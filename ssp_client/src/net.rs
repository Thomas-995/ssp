#![cfg_attr(not(debug_assertions), allow(unused_variables))]

use crate::crypter::CrypterUpdate;
use crate::dolphin::{DolphinEvent, GameMeta};
use crate::game::{
    ConnectionState, DiscoveryMode, SessionState, TimeoutConfig, DEFAULT_BOOTSTRAP_URL,
};
use crate::handshake::{
    self, HandshakeConfig, HandshakeGuard, HandshakeState, SSP_ALPN, SSP_VERSION,
};
use crate::msg::{Msg, MsgPayload, SLPMsg, SLPMsgData};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit};
use debug_print::{debug_eprintln, debug_println};
use iroh::{
    discovery::static_provider::StaticProvider, endpoint::Endpoint, EndpointAddr, EndpointId,
    RelayConfig,
};
use iroh_gossip::api::Event;
use iroh_gossip::api::{GossipReceiver, GossipSender};
use iroh_gossip::net::Gossip;
use iroh_gossip::proto::state::TopicId;
use rand::RngCore;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio::sync::Mutex;
use tokio_stream::StreamExt;
use tokio_util::sync::CancellationToken;

use distributed_topic_tracker::{RecordPublisher, TopicId as DttTopicId};
use ed25519_dalek::SigningKey;

struct ChunkAssembly {
    total: u16,
    parts: HashMap<u16, Vec<u8>>,
}

#[derive(serde::Deserialize)]
struct BootstrapResponse {
    session: String,
    peers: Vec<String>,
    #[serde(default)]
    peer_addrs: Vec<String>,
}

#[derive(Clone)]
struct DttReannounceState {
    session_hash: [u8; 32],
    signing_key: SigningKey,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct DhtRecordContent {
    id: [u8; 32],
    session_seed: [u8; 32],
}

#[derive(Clone)]
struct PeerCandidate {
    peer_addr: EndpointAddr,
    peer_id: EndpointId,
    #[cfg(debug_assertions)]
    via_bootstrap: bool,
    discovered_at: tokio::time::Instant,
}

fn get_hashed_seed(seed: &str) -> [u8; 32] {
    *blake3::keyed_hash(blake3::hash(b"ssp-topic").as_bytes(), seed.as_bytes()).as_bytes()
}

fn decode_nodeid_response(encoded: &str) -> Result<[u8; 32], String> {
    let data = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|e| format!("Base64 decode failed: {}", e))?;
    <[u8; 32]>::try_from(data.as_slice()).map_err(|_| "Invalid node ID length".to_string())
}

pub struct GameNet {
    session_state: Arc<Mutex<SessionState>>,
    connection_state: Arc<AtomicU8>,
    send_buf: Arc<Mutex<Vec<Vec<u8>>>>,
    incoming_msgs_tx: UnboundedSender<Msg>,
    consumer_msg_buf: Arc<Mutex<Vec<SLPMsg>>>,
    send: GossipSender,
    endpoint: Arc<Endpoint>,
    encryption_enabled: bool,
    secret_key: iroh::SecretKey,
    session_cancel_token: CancellationToken,
    current_seed_hash: Arc<Mutex<[u8; 32]>>,
    crypter_key_rx: Option<UnboundedReceiver<CrypterUpdate>>,
    previous_key: Option<[u8; 32]>,
    current_key: Option<[u8; 32]>,
    next_key: Option<[u8; 32]>,
    gameevent_rx: tokio::sync::mpsc::UnboundedReceiver<DolphinEvent>,
    discovery_mode: DiscoveryMode,
    bootstrap_url: String,
    dtt_reannounce: Option<DttReannounceState>,
    bootstrap_session_hash: [u8; 32],
    timeouts: TimeoutConfig,
    max_packet_length: usize,
    peer_seed_hash: Option<[u8; 32]>,
    local_in_game: bool,

    _router: iroh::protocol::Router,
}

impl GameNet {
    fn you(&self) -> EndpointId {
        self.endpoint.id()
    }

    fn peer_discovered(&self) -> bool {
        self.connection_state.load(Ordering::Relaxed) == ConnectionState::Discovered as u8
    }

    fn poll_keys(&mut self) {
        if let Some(ref mut crypter_key_rx) = self.crypter_key_rx {
            while let Ok(update) = crypter_key_rx.try_recv() {
                match update {
                    CrypterUpdate::Key(new_key) => {
                        self.next_key = Some(new_key.key);
                    }
                    CrypterUpdate::Rotate => {
                        if let Some(next) = self.next_key.take() {
                            self.previous_key = self.current_key.take();
                            self.current_key = Some(next);
                        }
                    }
                }
            }
        }
    }

    async fn poll_reannounces(&mut self) {
        while let Ok(event) = self.gameevent_rx.try_recv() {
            match event {
                DolphinEvent::NewGame(meta) => {
                    debug_println!("Received NewGame event");
                    let seed_str = format!("{:08x}", meta.seed);
                    let new_hash = get_hashed_seed(&seed_str);
                    {
                        let mut guard = self.current_seed_hash.lock().await;
                        *guard = new_hash;
                    }

                    // Reset keys for the new game
                    self.current_key = None;
                    self.previous_key = None;
                    self.next_key = None;
                    if self.peer_seed_hash != Some(new_hash) {
                        self.peer_seed_hash = None;
                    }
                    self.local_in_game = true;
                    *self.session_state.lock().await = SessionState::InGame;

                    let bootstrap_url = self.bootstrap_url.clone();
                    let my_addr = self.endpoint.addr();
                    let my_id = self.endpoint.id();
                    let discovery_mode = self.discovery_mode.clone();
                    let dtt_reannounce = self.dtt_reannounce.clone();
                    let bootstrap_session_hash = self.bootstrap_session_hash;
                    let session_cancel_token = self.session_cancel_token.clone();
                    let send_sender = self.send.clone();
                    let secret_key = self.secret_key.clone();
                    let http_timeout = self.timeouts.http_bootstrap_ms;

                    tokio::spawn(async move {
                        let signed_msg = SLPMsg::new_signed(
                            SLPMsgData::NewGame {
                                from: my_id,
                                newseed: new_hash,
                            },
                            &secret_key,
                        );
                        let _ = send_sender.broadcast(signed_msg.to_vec().into()).await;
                    });

                    if discovery_mode != DiscoveryMode::DhtOnly {
                        let bootstrap_url = bootstrap_url.clone();
                        let seed_str = seed_str.clone();
                        let session_cancel_token = session_cancel_token.clone();
                        tokio::spawn(async move {
                            if !session_cancel_token.is_cancelled() {
                                GameNet::reannounce(
                                    &bootstrap_url,
                                    &my_addr,
                                    &seed_str,
                                    Some(bootstrap_session_hash),
                                    http_timeout,
                                )
                                .await;
                            }
                        });
                    }

                    if let Some(dtt) = dtt_reannounce {
                        let session_cancel_token = session_cancel_token.clone();
                        tokio::spawn(async move {
                            if !session_cancel_token.is_cancelled() {
                                GameNet::reannounce_dtt(&my_id, &seed_str, &dtt).await;
                            }
                        });
                    }
                }
                DolphinEvent::GameEnd => {
                    self.local_in_game = false;
                    *self.session_state.lock().await = SessionState::Idle;
                    self.current_key = None;
                    self.previous_key = None;
                    self.next_key = None;
                }
            }
        }
    }

    fn encrypt_data(&self, plaintext: &[u8], nonce: &[u8; 12]) -> Option<Vec<u8>> {
        let key = self.current_key.as_ref()?;
        let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(key));
        cipher
            .encrypt(GenericArray::from_slice(nonce), plaintext)
            .ok()
    }

    fn decrypt_data(&self, ciphertext: &[u8], nonce: &[u8; 12]) -> Option<Vec<u8>> {
        for key in [&self.current_key, &self.previous_key, &self.next_key] {
            if let Some(k) = key {
                let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(k));
                if let Ok(pt) = cipher.decrypt(GenericArray::from_slice(nonce), ciphertext) {
                    return Some(pt);
                }
            }
        }
        None
    }

    pub async fn state_loop(mut self) {
        let mut last_newgame_time = tokio::time::Instant::now();
        let timeout = tokio::time::Duration::from_millis(self.timeouts.newgame_match_ms);

        loop {
            if *self.session_state.lock().await == SessionState::Ended {
                debug_println!("Session ended, cancelling tasks and exiting state loop");
                self.session_cancel_token.cancel();
                break;
            }

            if self.local_in_game {
                let current_hash = *self.current_seed_hash.lock().await;
                if Some(current_hash) != self.peer_seed_hash {
                    if last_newgame_time.elapsed() > timeout {
                        debug_println!("Timed out waiting for matching NewGame message from peers, ending session");
                        *self.session_state.lock().await = SessionState::Ended;
                        self.session_cancel_token.cancel();
                        break;
                    }
                } else {
                    last_newgame_time = tokio::time::Instant::now();
                }
            } else {
                last_newgame_time = tokio::time::Instant::now();
            }

            self.poll_keys();
            self.poll_reannounces().await;
            self.pipe_outgoing().await;
            self.pipe_incoming().await;
            tokio::task::yield_now().await;
        }
    }

    async fn pipe_outgoing(&mut self) {
        let current_hash = *self.current_seed_hash.lock().await;
        if self.peer_seed_hash != Some(current_hash) || !self.peer_discovered() {
            return;
        }

        let maybe_out = {
            let mut sb = self.send_buf.lock().await;
            if !sb.is_empty() {
                Some(sb.remove(0))
            } else {
                None
            }
        };

        if let Some(out) = maybe_out {
            debug_println!("Sending payload ({} bytes)", out.len());
            let nonce: [u8; 12] = rand::random();
            let plaintext = bincode::serialize(&MsgPayload {
                from: self.you(),
                data: out,
            })
            .expect("MsgPayload serialization must succeed");

            let final_bytes = if self.encryption_enabled {
                self.encrypt_data(&plaintext, &nonce).unwrap_or(plaintext)
            } else {
                plaintext
            };

            let send_clone = self.send.clone();
            let from_clone = self.you();
            let secret_key_clone = self.secret_key.clone();
            let max_packet_length = self.max_packet_length;

            tokio::spawn(async move {
                let msg = SLPMsgData::Data {
                    data: final_bytes,
                    nonce,
                };
                let signed_msg = SLPMsg::new_signed(msg, &secret_key_clone);
                let bytes = signed_msg.to_vec();

                if bytes.is_empty() {
                    return;
                }

                if bytes.len() <= max_packet_length {
                    debug_println!("SSP broadcasting Data message ({} bytes)", bytes.len());
                    let _ = send_clone.broadcast(bytes.into()).await;
                    return;
                }

                {
                    let id: u64 = rand::random();
                    let mut raw_chunk_size = max_packet_length.saturating_sub(512).max(1);
                    let mut sent_all = false;

                    loop {
                        let chunks: Vec<&[u8]> = bytes.chunks(raw_chunk_size).collect();
                        if chunks.len() > u16::MAX as usize {
                            debug_eprintln!(
                                "SSP Data message too large to chunk: {} bytes would need {} chunks",
                                bytes.len(),
                                chunks.len()
                            );
                            break;
                        }

                        let total = chunks.len() as u16;
                        let mut chunk_bytes = Vec::with_capacity(chunks.len());
                        let mut oversized = None;

                        for (index, chunk) in chunks.iter().enumerate() {
                            let chunk_msg = SLPMsg::new_signed(
                                SLPMsgData::Chunk {
                                    from: from_clone,
                                    id,
                                    index: index as u16,
                                    total,
                                    payload: chunk.to_vec(),
                                },
                                &secret_key_clone,
                            );
                            let serialized = chunk_msg.to_vec();
                            if serialized.len() > max_packet_length {
                                oversized = Some((index + 1, serialized.len()));
                                break;
                            }
                            chunk_bytes.push(serialized);
                        }

                        if let Some((index, len)) = oversized {
                            if raw_chunk_size == 1 {
                                debug_eprintln!(
                                    "SSP cannot create a valid chunk: chunk {} is {} bytes with 1 raw byte payload (max {})",
                                    index,
                                    len,
                                    max_packet_length
                                );
                                break;
                            }
                            raw_chunk_size = (raw_chunk_size / 2).max(1);
                            continue;
                        }

                        debug_println!(
                            "SSP chunking Data message into {} chunks of <= {} raw bytes ({} bytes total, max chunk {} bytes)",
                            total,
                            raw_chunk_size,
                            bytes.len(),
                            chunk_bytes.iter().map(Vec::len).max().unwrap_or(0)
                        );

                        sent_all = true;
                        for (index, chunk) in chunk_bytes.into_iter().enumerate() {
                            debug_assert!(chunk.len() <= max_packet_length);
                            if let Err(e) = send_clone.broadcast(chunk.into()).await {
                                debug_eprintln!(
                                    "SSP failed to broadcast chunk {} / {}: {}",
                                    index + 1,
                                    total,
                                    e
                                );
                                sent_all = false;
                                break;
                            }
                        }
                        break;
                    }
                    let _ = sent_all;
                }
            });
        }
    }

    async fn pipe_incoming(&mut self) {
        let discovered = self.peer_discovered();
        if let Some(msg) = self
            .pop_first_msg(|m| {
                matches!(m.body, SLPMsgData::NewGame { .. })
                    || (discovered && matches!(m.body, SLPMsgData::Data { .. }))
            })
            .await
        {
            match msg.body {
                SLPMsgData::Data { data, nonce } => {
                    debug_println!("SSP received Data message ({} bytes)", data.len());
                    let payload_bytes = if self.encryption_enabled {
                        self.decrypt_data(&data, &nonce).unwrap_or(data)
                    } else {
                        data
                    };
                    match bincode::deserialize::<MsgPayload>(&payload_bytes) {
                        Ok(payload) => {
                            debug_println!(
                                "SSP forwarding app payload from {:?} ({} bytes)",
                                payload.from,
                                payload.data.len()
                            );
                            let _ = self
                                .incoming_msgs_tx
                                .send(Msg::new(payload.data, payload.from));
                        }
                        Err(e) => {
                            debug_eprintln!("Failed to parse decrypted payload: {}", e);
                        }
                    }
                }
                SLPMsgData::NewGame { from: _, newseed } => {
                    debug_println!("Received peer NewGame");
                    let current_hash = *self.current_seed_hash.lock().await;
                    if newseed != current_hash {
                        debug_println!("Peer started a different game, ending session");
                        *self.session_state.lock().await = SessionState::Ended;
                        self.session_cancel_token.cancel();
                        return;
                    }

                    self.peer_seed_hash = Some(newseed);
                }
                _ => {}
            }
        }
    }

    pub async fn msg_consumer(mut recv: GossipReceiver, consumer_msg_buf: Arc<Mutex<Vec<SLPMsg>>>) {
        let mut assemblies: HashMap<(EndpointId, u64), ChunkAssembly> = HashMap::new();

        loop {
            match recv.next().await {
                Some(Ok(event)) => {
                    Self::handle_gossip_event(event, &mut assemblies, &consumer_msg_buf).await;
                }
                Some(Err(e)) => {
                    debug_eprintln!("Msg stream error: {:?}", e);
                }
                None => {
                    debug_println!("Msg stream ended");
                    return;
                }
            }
        }
    }

    async fn handle_gossip_event(
        event: Event,
        assemblies: &mut HashMap<(EndpointId, u64), ChunkAssembly>,
        consumer_msg_buf: &Arc<Mutex<Vec<SLPMsg>>>,
    ) {
        match event {
            Event::Received(raw) => match SLPMsg::from_bytes(&raw.content) {
                Ok(msg) => {
                    match &msg.body {
                        SLPMsgData::Data { .. } => {
                            // Data may be delivered by an intermediate gossip peer in
                            // multi-peer sessions, so raw.delivered_from is not necessarily
                            // the signer. The inner payload carries the sender identity.
                        }
                        SLPMsgData::Chunk { from, .. } | SLPMsgData::NewGame { from, .. } => {
                            if !msg.verify(from) {
                                debug_println!(
                                    "Received message with invalid signature from {:?}",
                                    from
                                );
                                return;
                            }
                        }
                    }

                    match msg.body {
                        SLPMsgData::Chunk {
                            from,
                            id,
                            index,
                            total,
                            payload,
                        } => {
                            let key = (from, id);
                            let asm = assemblies.entry(key).or_insert_with(|| ChunkAssembly {
                                total,
                                parts: HashMap::new(),
                            });
                            asm.parts.insert(index, payload);
                            if asm.parts.len() == asm.total as usize {
                                let mut full = Vec::new();
                                for i in 0..asm.total {
                                    if let Some(part) = asm.parts.get(&i) {
                                        full.extend_from_slice(part);
                                    }
                                }
                                assemblies.remove(&key);
                                match SLPMsg::from_bytes(&full) {
                                    Ok(reassembled) => {
                                        if !reassembled.verify(&from) {
                                            debug_println!("Received reassembled message with invalid signature from {:?}", from);
                                            return;
                                        }
                                        let mut buf = consumer_msg_buf.lock().await;
                                        buf.push(reassembled);
                                    }
                                    Err(e) => {
                                        debug_eprintln!(
                                            "Failed to parse reassembled message: {}",
                                            e
                                        );
                                    }
                                }
                            }
                        }
                        _ => {
                            let mut buf = consumer_msg_buf.lock().await;
                            buf.push(msg);
                        }
                    }
                }
                Err(_) => {
                    debug_eprintln!("Failed to parse SLPMsg");
                }
            },
            _ => {}
        }
    }

    async fn pop_first_msg<F>(&self, pred: F) -> Option<SLPMsg>
    where
        F: Fn(&SLPMsg) -> bool,
    {
        let mut buf = self.consumer_msg_buf.lock().await;
        if let Some(idx) = buf.iter().position(|e| pred(e)) {
            return Some(buf.remove(idx));
        }
        None
    }

    #[cfg(debug_assertions)]
    fn endpoint_addr_summary(addr: &EndpointAddr) -> String {
        format!("{:?}", addr)
    }

    fn encode_endpoint_addr(addr: &EndpointAddr) -> Option<String> {
        bincode::serialize(addr)
            .ok()
            .map(|bytes| URL_SAFE_NO_PAD.encode(bytes))
    }

    fn decode_endpoint_addr(encoded: &str) -> Option<EndpointAddr> {
        URL_SAFE_NO_PAD
            .decode(encoded)
            .ok()
            .and_then(|bytes| bincode::deserialize::<EndpointAddr>(&bytes).ok())
    }

    async fn fetch_bootstrap_peers(
        bootstrap_url: &str,
        seed: &str,
        my_addr: &EndpointAddr,
        http_timeout_ms: u64,
    ) -> Result<(String, Vec<EndpointAddr>), String> {
        let hashed_seed = get_hashed_seed(seed);
        let hashed_seed_hex = hex::encode(&hashed_seed);
        let encoded_node_id = URL_SAFE_NO_PAD.encode(my_addr.id.as_bytes());
        debug_println!(
            "Announcing bootstrap endpoint addr: {}",
            Self::endpoint_addr_summary(my_addr)
        );

        let url = if let Some(encoded_addr) = Self::encode_endpoint_addr(my_addr) {
            format!(
                "{}/games/{}?id={}&addr={}",
                bootstrap_url, hashed_seed_hex, encoded_node_id, encoded_addr
            )
        } else {
            format!(
                "{}/games/{}?id={}",
                bootstrap_url, hashed_seed_hex, encoded_node_id
            )
        };

        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_millis(http_timeout_ms))
            .timeout(std::time::Duration::from_millis(http_timeout_ms))
            .build()
            .map_err(|e| format!("HTTP client error: {}", e))?;

        let bootstrap_response = client
            .get(url)
            .send()
            .await
            .map_err(|e| format!("HTTP request failed: {}", e))?
            .json::<BootstrapResponse>()
            .await
            .map_err(|e| format!("JSON parse failed: {}", e))?;

        let mut peers = Vec::new();

        for addr_str in &bootstrap_response.peer_addrs {
            if let Some(peer_addr) = Self::decode_endpoint_addr(addr_str) {
                debug_println!(
                    "Bootstrap returned peer endpoint addr: {}",
                    Self::endpoint_addr_summary(&peer_addr)
                );
                if peer_addr.id != my_addr.id {
                    peers.push(peer_addr);
                }
            } else {
                debug_eprintln!("Failed to decode peer endpoint address");
            }
        }

        for peer_str in &bootstrap_response.peers {
            match decode_nodeid_response(peer_str) {
                Ok(arr) => match EndpointId::from_bytes(&arr) {
                    Ok(peer_id) => {
                        if peer_id == my_addr.id || peers.iter().any(|addr| addr.id == peer_id) {
                            continue;
                        }
                        peers.push(EndpointAddr::new(peer_id));
                    }
                    Err(e) => {
                        debug_eprintln!("EndpointId parse failed: {:?}", e)
                    }
                },
                Err(e) => {
                    debug_eprintln!("Failed to decode peer node ID: {}", e)
                }
            }
        }

        Ok((bootstrap_response.session, peers))
    }

    async fn reannounce(
        bootstrap_url: &str,
        endpoint_addr: &EndpointAddr,
        seed: &str,
        session_hash: Option<[u8; 32]>,
        http_timeout_ms: u64,
    ) {
        let hashed_seed = get_hashed_seed(seed);
        let hashed_seed_hex = hex::encode(&hashed_seed);
        debug_println!(
            "Re-announcing bootstrap endpoint addr: {}",
            Self::endpoint_addr_summary(endpoint_addr)
        );

        let encoded_node_id = URL_SAFE_NO_PAD.encode(endpoint_addr.id.as_bytes());
        let encoded_addr = Self::encode_endpoint_addr(endpoint_addr);

        let mut url = format!(
            "{}/games/{}?id={}",
            bootstrap_url, hashed_seed_hex, encoded_node_id
        );
        if let Some(session_hash) = session_hash {
            url.push_str("&session=");
            url.push_str(&hex::encode(session_hash));
        }
        if let Some(encoded_addr) = encoded_addr {
            url.push_str("&addr=");
            url.push_str(&encoded_addr);
        }

        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_millis(http_timeout_ms))
            .timeout(std::time::Duration::from_millis(http_timeout_ms))
            .build();

        match client {
            Ok(c) => match c.get(&url).send().await {
                Ok(_) => {
                    debug_println!("Re-announced for seed {}", seed);
                }
                Err(e) => {
                    debug_eprintln!("Re-announce failed: {}", e);
                }
            },
            Err(e) => {
                debug_eprintln!("Re-announce client error: {}", e);
            }
        }
    }

    async fn reannounce_dtt(endpoint_id: &EndpointId, seed: &str, dtt: &DttReannounceState) {
        let record_publisher = RecordPublisher::new(
            DttTopicId::new(seed.to_string()),
            dtt.signing_key.verifying_key(),
            dtt.signing_key.clone(),
            None,
            dtt.session_hash.to_vec(),
        );

        let content = DhtRecordContent {
            id: *endpoint_id.as_bytes(),
            session_seed: dtt.session_hash,
        };

        let unix_minute = distributed_topic_tracker::unix_minute(0);
        let record = match record_publisher.new_record(unix_minute, content) {
            Ok(r) => r,
            Err(e) => {
                debug_eprintln!("DHT reannounce record creation failed: {}", e);
                return;
            }
        };

        match record_publisher.publish_record(record).await {
            Ok(_) => {
                debug_println!("Re-announced discovery seed to DTT")
            }
            Err(e) => {
                debug_eprintln!("DTT re-announce failed: {}", e)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn setup_discovery(
        gametopicstr: &str,
        secret_seed: [u8; 32],
        endpoint: Arc<Endpoint>,
        gossip: Gossip,
        slp_version: [u8; 3],
        handshake_state: Arc<Mutex<HandshakeState>>,
        static_discovery: StaticProvider,
        discovery: DiscoveryMode,
        bootstrap_url: String,
        bootstrap_relay_url: Option<iroh::RelayUrl>,
        discovery_cancel: CancellationToken,
        timeouts: TimeoutConfig,
        peer_connected_tx: tokio::sync::watch::Sender<bool>,
    ) -> (
        GossipSender,
        GossipReceiver,
        Option<DttReannounceState>,
        [u8; 32],
    ) {
        let setup_started_at = tokio::time::Instant::now();
        let (candidate_tx, mut candidate_rx) =
            tokio::sync::mpsc::unbounded_channel::<PeerCandidate>();

        let my_id = endpoint.id();
        let my_addr = endpoint.addr();
        let mut session_hash = get_hashed_seed(gametopicstr);
        let mut initial_peers = Vec::new();
        let mut bootstrap_success = false;

        // Bootstrap Discovery
        if discovery != DiscoveryMode::DhtOnly {
            debug_println!(
                "[{:?}] Fetching peers from SSP server (initial)",
                setup_started_at.elapsed()
            );
            let fetch_started_at = tokio::time::Instant::now();
            match Self::fetch_bootstrap_peers(
                &bootstrap_url,
                gametopicstr,
                &my_addr,
                timeouts.http_bootstrap_ms,
            )
            .await
            {
                Ok((session_hex, peers)) => {
                    debug_println!(
                        "[{:?}] Initial SSP fetch returned {} peer(s) after {:?}",
                        setup_started_at.elapsed(),
                        peers.len(),
                        fetch_started_at.elapsed()
                    );
                    if let Ok(decoded) = hex::decode(&session_hex) {
                        if decoded.len() == 32 {
                            session_hash.copy_from_slice(&decoded);
                        }
                    }
                    for peer_addr in peers {
                        initial_peers.push((peer_addr, true));
                    }
                    bootstrap_success = true;
                }
                Err(e) => {
                    debug_eprintln!(
                        "[{:?}] Failed to fetch peers from bootstrap server after {:?}: {}",
                        setup_started_at.elapsed(),
                        fetch_started_at.elapsed(),
                        e
                    );
                }
            }
        }

        // DHT discovery
        let dht_topic = DttTopicId::new(gametopicstr.to_string());
        let signing_key = SigningKey::from_bytes(&secret_seed);

        let mut dht_rp = RecordPublisher::new(
            dht_topic.clone(),
            signing_key.verifying_key(),
            signing_key.clone(),
            None,
            session_hash.to_vec(),
        );

        if (!bootstrap_success || initial_peers.is_empty())
            && discovery != DiscoveryMode::BootstrapOnly
        {
            debug_println!(
                "[{:?}] Fetching peers from BitTorrent DHT",
                setup_started_at.elapsed()
            );
            let minute = distributed_topic_tracker::unix_minute(0);
            let content = DhtRecordContent {
                id: *my_id.as_bytes(),
                session_seed: session_hash,
            };

            // Publish our record so others can find us
            if let Ok(record) = dht_rp.new_record(minute, content) {
                if let Err(e) = dht_rp.publish_record(record).await {
                    debug_eprintln!("DTT initial publish failed: {}", e);
                }
            }
            debug_eprintln!("Published to DHT at minute={}", minute);

            // Scan for existing records to find the session seed
            let earliest_minute = minute.saturating_sub(8);
            debug_eprintln!("Scanning DHT on minutes={}-{}", earliest_minute, minute);

            let mut found_session_hash = None;
            for m in (earliest_minute..=minute).rev() {
                for record in dht_rp.get_records(m).await {
                    if let Ok(content) = record.content::<DhtRecordContent>() {
                        if let Ok(peer_id) = EndpointId::from_bytes(&content.id) {
                            if peer_id != my_id {
                                debug_eprintln!("Found peer {:?} on DHT at minute={}", peer_id, m);
                                initial_peers.push((EndpointAddr::new(peer_id), false));
                                if found_session_hash.is_none() {
                                    found_session_hash = Some(content.session_seed);
                                }
                            }
                        }
                    }
                }
            }

            if let Some(hash) = found_session_hash {
                session_hash = hash;
                dht_rp = RecordPublisher::new(
                    dht_topic.clone(),
                    signing_key.verifying_key(),
                    signing_key.clone(),
                    None,
                    session_hash.to_vec(),
                );
            }
        }

        // Subscribe to Gossip using the discovered session_seed
        let topic_id = TopicId::from_bytes(session_hash);
        let sub = gossip
            .subscribe(topic_id, vec![])
            .await
            .expect("Failed to subscribe to gossip");
        let (sender, receiver) = sub.split();
        let join_sender = sender.clone();

        // Feed initial peers into the candidate channel
        for (mut peer_addr, via_bootstrap) in initial_peers {
            let peer_id = peer_addr.id;
            if via_bootstrap {
                if peer_addr.is_empty() {
                    if let Some(ref relay) = bootstrap_relay_url {
                        peer_addr = peer_addr.with_relay_url(relay.clone());
                    }
                }
                debug_println!(
                    "Adding bootstrap endpoint info to static discovery: {}",
                    Self::endpoint_addr_summary(&peer_addr)
                );
                static_discovery.add_endpoint_info(peer_addr.clone());
            }
            debug_println!(
                "[{:?}] Queued initial peer candidate {:?} via {} with {} addr(s)",
                setup_started_at.elapsed(),
                peer_id,
                if via_bootstrap { "bootstrap" } else { "dht" },
                peer_addr.addrs.len()
            );
            let _ = candidate_tx.send(PeerCandidate {
                peer_addr,
                peer_id,
                #[cfg(debug_assertions)]
                via_bootstrap,
                discovered_at: tokio::time::Instant::now(),
            });
        }

        let failed_peers: Arc<Mutex<HashSet<EndpointId>>> = Arc::new(Mutex::new(HashSet::new()));

        // Start Background Discovery Tasks
        let dtt_reannounce = if discovery != DiscoveryMode::BootstrapOnly {
            Some(DttReannounceState {
                session_hash,
                signing_key: signing_key.clone(),
            })
        } else {
            None
        };

        if discovery != DiscoveryMode::DhtOnly {
            let tx_clone = candidate_tx.clone();
            let static_clone = static_discovery.clone();
            let bootstrap_url_clone = bootstrap_url.clone();
            let gametopic_clone = gametopicstr.to_string();
            let relay_clone = bootstrap_relay_url.clone();
            let my_addr_clone = my_addr.clone();
            let cancel_clone = discovery_cancel.clone();
            let failed_peers_clone = failed_peers.clone();
            let http_timeout = timeouts.http_bootstrap_ms;

            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = cancel_clone.cancelled() => {
                            debug_println!("Bootstrap peer fetch stopped (peer joined topic)");
                            return;
                        }
                        _ = tokio::time::sleep(tokio::time::Duration::from_secs(15)) => {
                            if let Ok((_, peers)) = Self::fetch_bootstrap_peers(&bootstrap_url_clone, &gametopic_clone, &my_addr_clone, http_timeout).await {
                                for mut peer_addr in peers {
                                    let peer_id = peer_addr.id;
                                    if failed_peers_clone.lock().await.contains(&peer_id) {
                                        continue;
                                    }
                                    if peer_addr.is_empty() {
                                        if let Some(ref relay) = relay_clone {
                                            peer_addr = peer_addr.with_relay_url(relay.clone());
                                        }
                                    }
                                    debug_println!(
                                        "Adding bootstrap endpoint info to static discovery: {}",
                                        Self::endpoint_addr_summary(&peer_addr)
                                    );
                                    static_clone.add_endpoint_info(peer_addr.clone());
                                    debug_println!(
                                        "Queued bootstrap peer candidate {:?} with {} addr(s)",
                                        peer_id,
                                        peer_addr.addrs.len()
                                    );
                                    let _ = tx_clone.send(PeerCandidate {
                                        peer_addr,
                                        peer_id,
                                        #[cfg(debug_assertions)]
                                        via_bootstrap: true,
                                        discovered_at: tokio::time::Instant::now(),
                                    });
                                }
                            }
                        }
                    }
                }
            });
        }

        if discovery != DiscoveryMode::BootstrapOnly {
            let tx_clone = candidate_tx.clone();
            let cancel_clone = discovery_cancel.clone();
            let failed_peers_clone = failed_peers.clone();
            let rp = dht_rp; // take ownership
            let session_hash_clone = session_hash;

            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = cancel_clone.cancelled() => {
                            debug_println!("DHT discovery stopped (peer joined topic)");
                            return;
                        }
                        _ = async {
                            let minute = distributed_topic_tracker::unix_minute(0);
                            let content = DhtRecordContent {
                                id: *my_id.as_bytes(),
                                session_seed: session_hash_clone,
                            };

                            if let Ok(record) = rp.new_record(minute, content) {
                                let _ = rp.publish_record(record).await;
                            }

                            let earliest_minute = minute.saturating_sub(8);
                            for m in (earliest_minute..=minute).rev() {
                                for record in rp.get_records(m).await {
                                    if let Ok(peer_id) = EndpointId::from_bytes(&record.node_id()) {
                                        if peer_id != my_id {
                                            if failed_peers_clone.lock().await.contains(&peer_id) {
                                                continue;
                                            }
                                            debug_println!("Queued DHT peer candidate {:?}", peer_id);
                                            let _ = tx_clone.send(PeerCandidate {
                                                peer_addr: EndpointAddr::new(peer_id),
                                                peer_id,
                                                #[cfg(debug_assertions)]
                                                via_bootstrap: false,
                                                discovered_at: tokio::time::Instant::now(),
                                            });
                                        }
                                    }
                                }
                            }
                        } => {}
                    }
                    tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
                }
            });
        }

        let endpoint_clone = endpoint.clone();
        let gossip_clone = gossip.clone();
        let hs_clone = handshake_state.clone();
        let relay_for_handshake = bootstrap_relay_url.clone();
        let cancel_on_connect = discovery_cancel.clone();
        let peer_connected_on_connect = peer_connected_tx.clone();

        tokio::spawn(async move {
            let active_peers: Arc<Mutex<HashSet<EndpointId>>> =
                Arc::new(Mutex::new(HashSet::new()));
            let mut handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();

            while let Some(candidate) = candidate_rx.recv().await {
                {
                    let mut active = active_peers.lock().await;
                    if !active.insert(candidate.peer_id) {
                        continue;
                    }
                }

                debug_println!(
                    "[{:?}] Received peer candidate {:?} via {} with {} addr(s) (candidate age {:?}); spawning handshake task",
                    setup_started_at.elapsed(),
                    candidate.peer_id,
                    if candidate.via_bootstrap { "bootstrap" } else { "dht" },
                    candidate.peer_addr.addrs.len(),
                    candidate.discovered_at.elapsed()
                );

                let endpoint_for_task = endpoint_clone.clone();
                let gossip_for_task = gossip_clone.clone();
                let hs_for_task = hs_clone.clone();
                let relay_task = relay_for_handshake.clone();
                let slp_version_task = slp_version;
                let peer_id = candidate.peer_id;
                let peer_addr = candidate.peer_addr.clone();
                let candidate_discovered_at = candidate.discovered_at;
                let join_sender_for_task = join_sender.clone();
                let cancel_task = cancel_on_connect.clone();
                let failed_peers_for_task = failed_peers.clone();
                let active_peers_for_task = active_peers.clone();
                let peer_connected_for_task = peer_connected_on_connect.clone();

                let handle = tokio::spawn(async move {
                    let handshake_started_at = tokio::time::Instant::now();
                    debug_println!(
                        "[{:?}] Starting handshake with {:?} addr {} (candidate age {:?})",
                        setup_started_at.elapsed(),
                        peer_id,
                        Self::endpoint_addr_summary(&peer_addr),
                        candidate_discovered_at.elapsed()
                    );

                    let mut peer = peer_addr;
                    if peer.is_empty() {
                        if let Some(ref relay) = relay_task {
                            peer = peer.with_relay_url(relay.clone());
                        }
                    }

                    match handshake::perform_handshake(
                        &endpoint_for_task,
                        peer.clone(),
                        hs_for_task.clone(),
                        slp_version_task,
                        SSP_VERSION,
                    )
                    .await
                    {
                        Ok(conn) => {
                            if let Err(e) = gossip_for_task.handle_connection(conn).await {
                                debug_eprintln!("Error handing connection to gossip: {e}");
                                active_peers_for_task.lock().await.remove(&peer_id);
                            } else {
                                if let Err(e) = join_sender_for_task.join_peers(vec![peer_id]).await
                                {
                                    debug_eprintln!(
                                        "Post-handshake join_peers failed for {:?}: {}",
                                        peer_id,
                                        e
                                    );
                                }
                                let _ = peer_connected_for_task.send(true);
                                debug_println!(
                                    "[{:?}] Connected to peer {:?} (handshake task {:?}, candidate age {:?})",
                                    setup_started_at.elapsed(),
                                    peer_id,
                                    handshake_started_at.elapsed(),
                                    candidate_discovered_at.elapsed()
                                );
                                cancel_task.cancel();
                                active_peers_for_task.lock().await.remove(&peer_id);
                            }
                        }
                        Err(e) => {
                            if relay_task.is_none() {
                                let _ = failed_peers_for_task;
                                debug_eprintln!(
                                    "Handshake failed for {:?}: {}; will retry future candidates for this peer",
                                    peer_id,
                                    e
                                );
                                active_peers_for_task.lock().await.remove(&peer_id);
                                return;
                            }

                            debug_eprintln!(
                                "Handshake with custom relay failed for {:?}: {}. Trying default n0 relays...",
                                peer_id,
                                e
                            );

                            let n0_relays =
                                iroh::defaults::prod::default_relay_map().urls::<Vec<_>>();
                            for n0_relay in n0_relays {
                                debug_println!(
                                    "Trying n0 fallback relay {} for {:?}",
                                    n0_relay,
                                    peer_id
                                );
                                let fallback_peer =
                                    EndpointAddr::new(peer_id).with_relay_url(n0_relay.clone());
                                match handshake::perform_handshake(
                                    &endpoint_for_task,
                                    fallback_peer,
                                    hs_for_task.clone(),
                                    slp_version_task,
                                    SSP_VERSION,
                                )
                                .await
                                {
                                    Ok(conn) => {
                                        if let Err(e) =
                                            gossip_for_task.handle_connection(conn).await
                                        {
                                            debug_eprintln!(
                                                "Error handing connection to gossip (fallback): {e}"
                                            );
                                        } else {
                                            if let Err(e) =
                                                join_sender_for_task.join_peers(vec![peer_id]).await
                                            {
                                                debug_eprintln!(
                                                    "Post-handshake join_peers failed for {:?} (fallback): {}",
                                                    peer_id,
                                                    e
                                                );
                                            }
                                            let _ = peer_connected_for_task.send(true);
                                            debug_println!(
                                                "[{:?}] Connected to peer {:?} via n0 fallback {} (handshake task {:?}, candidate age {:?})",
                                                setup_started_at.elapsed(),
                                                peer_id,
                                                n0_relay,
                                                handshake_started_at.elapsed(),
                                                candidate_discovered_at.elapsed()
                                            );
                                            cancel_task.cancel();
                                            active_peers_for_task.lock().await.remove(&peer_id);
                                            return;
                                        }
                                    }
                                    Err(fallback_err) => {
                                        debug_eprintln!(
                                            "n0 fallback relay {} failed for {:?}: {}",
                                            n0_relay,
                                            peer_id,
                                            fallback_err
                                        );
                                    }
                                }
                            }

                            let _ = failed_peers_for_task;
                            active_peers_for_task.lock().await.remove(&peer_id);
                            debug_eprintln!(
                                "All n0 fallback handshakes failed for {:?}; will retry future candidates",
                                peer_id,
                            );
                        }
                    }
                });

                handles.push(handle);
            }

            for h in handles {
                let _ = h.await;
            }
        });

        (sender, receiver, dtt_reannounce, session_hash)
    }

    pub async fn connect(
        meta: GameMeta,
        session_state: Arc<Mutex<SessionState>>,
        connection_state: Arc<AtomicU8>,
        encryption_enabled: bool,
        discovery_mode: DiscoveryMode,
        handshake_config: HandshakeConfig,
        bootstrap_url: Option<String>,
        bootstrap_relay_url: Option<iroh::RelayUrl>,
        send_buf: Arc<Mutex<Vec<Vec<u8>>>>,
        incoming_msgs_tx: UnboundedSender<Msg>,
        crypter_key_rx: Option<UnboundedReceiver<CrypterUpdate>>,
        gameevent_rx: UnboundedReceiver<DolphinEvent>,
        handshake_succ_tx: Option<UnboundedSender<(u64, u64)>>,
        session_cancel_token: CancellationToken,
        timeouts: TimeoutConfig,
        max_packet_length: usize,
    ) {
        let bootstrap_url = bootstrap_url.unwrap_or_else(|| DEFAULT_BOOTSTRAP_URL.to_string());

        let mut secret_seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret_seed);
        let secret_key = iroh::SecretKey::from_bytes(&secret_seed);

        let gametopicstr = format!("{:08x}", meta.seed);
        let current_seed_hash = Arc::new(Mutex::new(get_hashed_seed(&gametopicstr)));

        let relay_mode = if let Some(ref relay) = bootstrap_relay_url {
            let relay_map = iroh::defaults::prod::default_relay_map();
            let custom_config = RelayConfig::from(relay.clone());
            relay_map.insert(custom_config.url.clone(), Arc::new(custom_config));
            iroh::RelayMode::Custom(relay_map)
        } else {
            iroh::RelayMode::Default
        };

        let mut ep_builder = Endpoint::builder()
            .secret_key(secret_key.clone())
            .relay_mode(relay_mode);

        let static_discovery = StaticProvider::with_provenance("bootstrap");
        ep_builder = ep_builder.discovery(static_discovery.clone());

        let endpoint = Arc::new(ep_builder.bind().await.expect("Failed to bind endpoint"));

        // Setup initial gossip/discovery (non-blocking)
        let gossip = Gossip::builder()
            .alpn(SSP_ALPN)
            .max_message_size(max_packet_length)
            .spawn((*endpoint).clone());
        let slp_version = meta.slp_version;
        let discovery_cancel_token = CancellationToken::new();

        let handshake_state = Arc::new(Mutex::new(HandshakeState::new(
            handshake_config,
            slp_version,
            SSP_VERSION,
        )));
        let (peer_connected_tx, mut peer_connected_rx) = tokio::sync::watch::channel(false);

        // Setup Discovery
        let (gossip_send, gossip_recv, dtt_reannounce, bootstrap_session_hash) =
            Self::setup_discovery(
                &gametopicstr,
                secret_seed,
                endpoint.clone(),
                gossip.clone(),
                slp_version,
                handshake_state.clone(),
                static_discovery.clone(),
                discovery_mode.clone(),
                bootstrap_url.clone(),
                bootstrap_relay_url.clone(),
                discovery_cancel_token.clone(),
                timeouts.clone(),
                peer_connected_tx.clone(),
            )
            .await;

        let gossip_guard = HandshakeGuard::new(
            gossip.clone(),
            handshake_state.clone(),
            handshake_succ_tx,
            discovery_cancel_token.clone(),
            peer_connected_tx.clone(),
        );

        let router = iroh::protocol::Router::builder((*endpoint).clone())
            .accept(SSP_ALPN, gossip_guard)
            .spawn();

        debug_println!("Set connection up with {:?}", endpoint.id());

        let consumer_msg_buf = Arc::new(Mutex::new(Vec::new()));
        let consumer_msg_buf_for_task = consumer_msg_buf.clone();
        let (gossip_joined_tx, mut gossip_joined_rx) = tokio::sync::watch::channel(false);

        tokio::spawn(async move {
            let mut gossip_recv = gossip_recv;
            if let Err(e) = gossip_recv.joined().await {
                debug_eprintln!("Failed while waiting for gossip join: {:?}", e);
                return;
            }
            let _ = gossip_joined_tx.send(true);
            GameNet::msg_consumer(gossip_recv, consumer_msg_buf_for_task).await;
        });

        let connection_state_for_task = connection_state.clone();
        tokio::spawn(async move {
            loop {
                if *peer_connected_rx.borrow() && *gossip_joined_rx.borrow() {
                    connection_state_for_task
                        .store(ConnectionState::Discovered as u8, Ordering::Relaxed);
                    return;
                }

                tokio::select! {
                    changed = peer_connected_rx.changed() => {
                        if changed.is_err() {
                            return;
                        }
                    }
                    changed = gossip_joined_rx.changed() => {
                        if changed.is_err() {
                            return;
                        }
                    }
                }
            }
        });

        let initial_peer_seed_hash = *current_seed_hash.lock().await;
        *session_state.lock().await = SessionState::InGame;

        {
            let initial_sender = gossip_send.clone();
            let initial_secret_key = secret_key.clone();
            let initial_from = endpoint.id();
            tokio::spawn(async move {
                let signed_msg = SLPMsg::new_signed(
                    SLPMsgData::NewGame {
                        from: initial_from,
                        newseed: initial_peer_seed_hash,
                    },
                    &initial_secret_key,
                );
                let _ = initial_sender.broadcast(signed_msg.to_vec().into()).await;
            });
        }

        GameNet::state_loop(Self {
            session_state,
            connection_state,
            send_buf,
            incoming_msgs_tx,
            consumer_msg_buf,
            send: gossip_send,
            endpoint,
            encryption_enabled,
            secret_key,
            session_cancel_token,
            current_seed_hash: current_seed_hash.clone(),
            crypter_key_rx,
            previous_key: None,
            current_key: None,
            next_key: None,
            gameevent_rx,
            discovery_mode,
            bootstrap_url,
            dtt_reannounce,
            bootstrap_session_hash,
            timeouts,
            max_packet_length,
            peer_seed_hash: Some(initial_peer_seed_hash),
            local_in_game: true,
            _router: router,
        })
        .await;
    }
}
