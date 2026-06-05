use crate::crypter::CrypterInput;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::mpsc;
use std::time::Duration;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio_util::sync::CancellationToken;

use base64::engine::general_purpose::STANDARD as BASE64_STD;
use base64::Engine;
use debug_print::{debug_eprint, debug_eprintln, debug_print, debug_println};
use enet::{Address, BandwidthLimit, ChannelLimit, Enet, Event, Packet, PacketMode};
use rand::random;
use serde::Serialize;
use serde_json::Value;
use std::sync::OnceLock;

#[derive(Clone, Debug)]
pub struct PlayerMeta {
    pub port: u8,
    pub char: u8,
    pub color: u8,
    pub team: u8,
    pub cpu: bool,
}

impl PlayerMeta {
    pub fn new(port: u8, char: u8, color: u8, team: u8, cpu: bool) -> PlayerMeta {
        Self {
            port,
            char,
            color,
            team,
            cpu,
        }
    }
}

#[derive(Clone, Debug)]
pub struct GameMeta {
    pub stage: u8,
    pub is_teams: bool,
    pub players: Vec<PlayerMeta>,
    pub seed: u32,
    pub slp_version: [u8; 3],
}

impl GameMeta {
    pub fn new() -> GameMeta {
        Self {
            stage: u8::MAX,
            is_teams: false,
            players: Vec::new(),
            seed: 0,
            slp_version: [0, 0, 0],
        }
    }
}

#[derive(Clone, Debug)]
pub enum DolphinEvent {
    NewGame(GameMeta),
    GameEnd,
    Disconnected,
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum SLPEventType {
    GeckoCodes = 0x10,
    Payloads = 0x35,
    GameStart = 0x36,
    PreFrame = 0x37,
    PostFrame = 0x38,
    GameEnd = 0x39,
    FrameStart = 0x3a,
    ItemUpdate = 0x3b,
    FrameBookend = 0x3c,
}
enum SLPEvent {
    NewGame(GameMeta),
    GameEnd,
}

impl SLPEventType {
    fn from_byte(b: u8) -> Option<Self> {
        Some(match b {
            0x10 => SLPEventType::GeckoCodes,
            0x35 => SLPEventType::Payloads,
            0x36 => SLPEventType::GameStart,
            0x37 => SLPEventType::PreFrame,
            0x38 => SLPEventType::PostFrame,
            0x39 => SLPEventType::GameEnd,
            0x3a => SLPEventType::FrameStart,
            0x3b => SLPEventType::ItemUpdate,
            0x3c => SLPEventType::FrameBookend,
            _ => return None,
        })
    }
}

// Connects to Slippi port, parses game events, and
// forwards frame data and game events.
pub struct SLPreader {
    ip: String,
    port: u16,
    crypter_tx: Option<UnboundedSender<CrypterInput>>,
    event_tx: UnboundedSender<DolphinEvent>,
    cancel_token: CancellationToken,
}

#[derive(Serialize)]
struct UbjsonHandshakePayload {
    cursor: Vec<u8>,
    #[serde(rename = "clientToken")]
    client_token: Vec<u8>,
    #[serde(rename = "isRealtime")]
    is_realtime: bool,
}

#[derive(Serialize)]
struct UbjsonHandshakeMsg {
    #[serde(rename = "type")]
    msg_type: u8,
    payload: UbjsonHandshakePayload,
}

// Single frame of controller input
#[derive(Debug)]
pub struct InputFrame {
    pub frame: i64,
    pub last_finalized_frame: i64,
    pub data: Vec<u8>,
}
impl InputFrame {
    pub fn new(frame: i64, last_finalized_frame: i64, data: Vec<u8>) -> InputFrame {
        Self {
            frame,
            last_finalized_frame,
            data,
        }
    }
}

static CLIENT_TOKEN: OnceLock<u32> = OnceLock::new();
pub static ENET_INSTANCE: std::sync::OnceLock<Enet> = std::sync::OnceLock::new();

impl SLPreader {
    pub fn new(
        ip: &str,
        port: u16,
        crypter_tx: Option<UnboundedSender<CrypterInput>>,
        event_tx: UnboundedSender<DolphinEvent>,
        cancel_token: CancellationToken,
    ) -> Self {
        Self {
            ip: ip.to_string(),
            port,
            crypter_tx,
            event_tx,
            cancel_token,
        }
    }

    fn encode_ubjson_handshake(
        cursor_be: &[u8],
        client_token: u32,
        is_realtime: bool,
    ) -> Option<Vec<u8>> {
        let mut tok = [0u8; 4];
        tok.copy_from_slice(&client_token.to_be_bytes());
        let msg = UbjsonHandshakeMsg {
            msg_type: 0x01,
            payload: UbjsonHandshakePayload {
                cursor: cursor_be.to_vec(),
                client_token: tok.to_vec(),
                is_realtime,
            },
        };
        match serde_ubjson::to_vec(&msg) {
            Ok(mut body) => {
                let mut out = vec![0u8; 4];
                let len: u32 = body.len() as u32;
                out[0] = (len >> 24) as u8;
                out[1] = (len >> 16) as u8;
                out[2] = (len >> 8) as u8;
                out[3] = (len) as u8;
                out.append(&mut body);
                Some(out)
            }
            Err(_) => None,
        }
    }

    pub async fn start(self) {
        let _ = tokio::task::spawn_blocking(move || {
            let ip = self.ip.clone();
            let port = self.port;
            let client_token = *CLIENT_TOKEN.get_or_init(|| random::<u32>());

            let enet = ENET_INSTANCE.get_or_init(|| {
                Enet::new().expect("ENet initialization failed")
            });

            loop {
                if self.cancel_token.is_cancelled() {
                    return;
                }

                let mut host = match enet.create_host::<()>(None, 1, ChannelLimit::Limited(1), BandwidthLimit::Unlimited, BandwidthLimit::Unlimited) {
                    Ok(h) => h,
                    Err(e) => { debug_eprintln!("ENet host create failed: {e:?}"); std::thread::sleep(Duration::from_millis(1000)); continue; }
                };

                let ip4 = match Ipv4Addr::from_str(&ip) {
                    Ok(v) => v,
                    Err(e) => { debug_eprintln!("Invalid Slippi IP {ip}: {e}"); return; }
                };
                let address = Address::new(ip4, port);

                if let Err(e) = host.connect(&address, 1, 0) {
                    debug_eprintln!("ENet connect failed: {e:?}");
                    std::thread::sleep(Duration::from_millis(1000));
                    continue;
                }

                let mut meta = GameMeta::new();
                let mut sent_meta = false;
                let mut event_sizes: [usize; 256] = [0; 256];
                let mut frame_inputs: HashMap<(i32, u8), Vec<u8>> = HashMap::new();


                loop {
                    if self.cancel_token.is_cancelled() {
                        return;
                    }

                    match host.service(50) {
                        Ok(ev_opt) => {
                            if let Some(ev) = ev_opt {
                                match &ev {
                                    Event::Connect(p) => {
                                        debug_println!("Connected to {}:{}", ip, port);
                                        if let Ok(pkt) = Packet::new(r#"{"type":"connect_request","cursor":0}"#.as_bytes(), PacketMode::ReliableSequenced) {
                                            let _ = p.clone().send_packet(pkt, 0);
                                        }
                                    }
                                    Event::Receive { sender, channel_id: _, packet } => {
                                        let data = packet.data();
                                        if data.is_empty() { continue; }
                                        let val: Result<Value, _> = serde_json::from_slice(data);
                                        let val = match val { Ok(v) => v, Err(e) => { debug_eprintln!("Slippi Reader invalid JSON: {e}"); continue; } };
                                        let typ = val.get("type").and_then(|v| v.as_str()).unwrap_or("");
                                        let next_cursor = val.get("next_cursor").and_then(|v| v.as_u64());
                                        match typ {
                                            "START_GAME" | "start_game" => {
                                                frame_inputs.clear();
                                                meta = GameMeta::new();
                                                sent_meta = false;
                                            }
                                            "END_GAME" | "end_game" => {
                                                debug_println!("Game ended");
                                                let _ = self.event_tx.send(DolphinEvent::GameEnd);
                                            }
                                            "CONNECT_REPLY" | "connect_reply" => {}
                                            "GAME_EVENT" | "game_event" => {
                                                if let Some(payload) = val.get("payload").and_then(|v| v.as_str()) {
                                                    match BASE64_STD.decode(payload) {
                                                        Ok(bytes) => {
                                                            if !bytes.is_empty() {
                                                                let mut idx: usize = 0;
                                                                while idx < bytes.len() {
                                                                    let et = bytes[idx];
                                                                    if et == 0x00 { break; }

                                                                    let event_type = SLPEventType::from_byte(et);

                                                                    if let Some(SLPEventType::Payloads) = event_type {
                                                                        if idx + 1 >= bytes.len() { break; }
                                                                        let payload_size = bytes[idx + 1] as usize;
                                                                        if idx + 1 + payload_size >= bytes.len() + 1 { break; }
                                                                        let mut cursor = idx + 2;
                                                                        if payload_size >= 1 {
                                                                            let num_commands = (payload_size - 1) / 3;
                                                                            for _ in 0..num_commands { if cursor + 3 > idx + 1 + payload_size { break; }
                                                                                let command = bytes[cursor] as usize;
                                                                                let len_hi = bytes[cursor + 1] as usize; let len_lo = bytes[cursor + 2] as usize;
                                                                                event_sizes[command] = ((len_hi << 8) | len_lo) + 1; cursor += 3; }
                                                                        }
                                                                        idx += payload_size + 1;
                                                                        continue;
                                                                    }

                                                                    let esz = event_sizes[et as usize];
                                                                    if esz == 0 || idx + esz > bytes.len() { break; }
                                                                    let eb = &bytes[idx..idx+esz];
                                                                    match SLPEventType::from_byte(et) {
                                                                        Some(SLPEventType::GameStart) => {
                                                                            meta = GameMeta::new();
                                                                            sent_meta = false;
                                                                            if eb.len() > 0x80 {
                                                                                meta.slp_version = [
                                                                                    eb.get(0x1).copied().unwrap_or(0),
                                                                                    eb.get(0x2).copied().unwrap_or(0),
                                                                                    eb.get(0x3).copied().unwrap_or(0),
                                                                                ];

                                                                                if eb.len() >= 0x0F {
                                                                                    let t_hi = eb[0x0D] as u16;
                                                                                    let t_lo = eb[0x0E] as u16;
                                                                                    meta.is_teams = ((t_hi << 8) | t_lo) != 0;
                                                                                }

                                                                                if eb.len() > 0x14 {
                                                                                    let s_hi = eb[0x13] as u16;
                                                                                    let s_lo = eb[0x14] as u16;
                                                                                    meta.stage = ((s_hi << 8) | s_lo) as u8;
                                                                                }
                                                                                if eb.len() > 0x140 {
                                                                                    meta.seed = u32::from_be_bytes([eb[0x13d], eb[0x13e], eb[0x13f], eb[0x140]]);
                                                                                }

                                                                                for player_index in 0..4u8 {
                                                                                    let costume_off = 0x68 + 0x24 * (player_index as usize);
                                                                                    let team_off = 0x6E + 0x24 * (player_index as usize);
                                                                                    let type_off = 0x66 + 0x24 * (player_index as usize);

                                                                                    let color = eb.get(costume_off).copied();
                                                                                    let team = eb.get(team_off).copied();
                                                                                    let player_type = eb.get(type_off).copied();
                                                                                    let is_cpu = player_type.map(|v| v != 1);

                                                                                    meta.players.push(PlayerMeta::new(
                                                                                        player_index + 1,
                                                                                        u8::MAX,
                                                                                        color.unwrap_or(0),
                                                                                        team.unwrap_or(0),
                                                                                        is_cpu.unwrap_or(false),
                                                                                    ));
                                                                                }
                                                                            }
                                                                        }
                                                                        Some(SLPEventType::PreFrame) => {
                                                                            if eb.len() >= 6 {
                                                                                let frame = i32::from_be_bytes([eb[1], eb[2], eb[3], eb[4]]);
                                                                                let player = eb[5];

                                                                                let mut input_bytes: Vec<u8> = Vec::new();
                                                                                input_bytes.extend_from_slice(&eb[0x19 .. 0x3c]);
                                                                                frame_inputs.insert((frame, player), input_bytes);
                                                                            }
                                                                        }
                                                                        Some(SLPEventType::PostFrame) => {
                                                                            if !sent_meta {
                                                                                if eb.len() >= 8 {
                                                                                    let player_index = eb[5];
                                                                                    let internal_char = eb[7];
                                                                                    if let Some(p) = meta.players.iter_mut().find(|p| p.port == player_index+1) {
                                                                                        if p.char != u8::MAX {
                                                                                            meta.players = meta.players.iter().filter(|p| p.char != u8::MAX).cloned().collect();
                                                                                            // Send reset to crypter for new game
                                                                                            if let Some(ref tx) = self.crypter_tx {
                                                                                                let _ = tx.send(CrypterInput::Reset(meta.clone()));
                                                                                            }
                                                                                            let _ = self.event_tx.send(DolphinEvent::NewGame(meta.clone()));
                                                                                            sent_meta = true;
                                                                                        } else {
                                                                                            p.char = internal_char;
                                                                                        }
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                        Some(SLPEventType::GameEnd) => {
                                                                            frame_inputs.clear();
                                                                        }
                                                                        Some(SLPEventType::FrameBookend) => {
                                                                            if eb.len() >= 9 {
                                                                                let frame = i32::from_be_bytes([eb[1], eb[2], eb[3], eb[4]]);
                                                                                let last_finalized_frame = i32::from_be_bytes([eb[5], eb[6], eb[7], eb[8]]);
                                                                                if frame != last_finalized_frame {
                                                                                    // Rollback: frame -> last_finalized_frame)
                                                                                }
                                                                                let mut frame_bytes = vec![];
                                                                                for port in 1..4 {
                                                                                    if let Some(data) = frame_inputs.get(&(frame, port as u8)) {
                                                                                        frame_bytes.extend(data);
                                                                                    }
                                                                                }
                                                                                if !frame_bytes.is_empty() {
                                                                                    if let Some(ref tx) = self.crypter_tx {
                                                                                        let _ = tx.send(CrypterInput::Frame(InputFrame::new(frame.into(), last_finalized_frame.into(), frame_bytes)));
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                        Some(SLPEventType::GeckoCodes) => {}
                                                                        Some(SLPEventType::FrameStart) => {}
                                                                        _ => { }
                                                                    }
                                                                    idx += esz;
                                                                }
                                                            }
                                                        }
                                                        Err(_) => { debug_eprintln!("Slippi Reader invalid base64 payload") },
                                                    }
                                                } else { debug_eprintln!("missing payload in GAME_EVENT"); }
                                            }
                                            _ => {}
                                        }

                                        if let Some(nc) = next_cursor { let mut be = nc.to_be_bytes().to_vec(); while be.len() > 1 && be[0] == 0 { be.remove(0);} if let Some(buf) = Self::encode_ubjson_handshake(&be, client_token, false) { if let Ok(pkt) = Packet::new(&buf, PacketMode::ReliableSequenced) { let _ = sender.clone().send_packet(pkt, 0); }}}
                                    }
                                    Event::Disconnect(_, _) => {
                                        debug_println!("Slippi Reader Disconnected");
                                        break;
                                    }
                                }
                            }
                        }
                        Err(e) => { debug_eprintln!("service error: {e:?}"); break; }
                    }
                }
                if self.cancel_token.is_cancelled() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(500));
            }
        }).await;
    }
}
