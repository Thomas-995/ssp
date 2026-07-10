//! Session API

use crate::crypter::{CrypterInput, CrypterUpdate, SLPcrypter};
use crate::dolphin::{DolphinEvent, SLPreader};
use crate::handshake::{HandshakeConfig, ParamRange, SSP_VERSION};
use crate::msg::Msg;
use crate::net::GameNet;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc::error::TryRecvError;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

/// Peer discovery strategy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DiscoveryMode {
    /// Bootstrap server first, DTT fallback (default).
    BootstrapDhtFallback,
    /// Bootstrap server only.
    BootstrapOnly,
    /// Bootstrap using DTT (via bittorrent DHT) only.
    DhtOnly,
}

/// Pre-configured timeout profiles for different network environments.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum NetworkProfile {
    /// Designed for LAN or very stable, low-latency connections. Fails fast.
    Aggressive,
    /// The default. Balanced for typical internet play.
    #[default]
    Standard,
    /// High timeouts, lots of retries. Best for flaky WiFi or distant peers.
    Resilient,
}

/// Advanced configuration for network and state timeouts.
#[derive(Debug, Clone)]
pub struct TimeoutConfig {
    pub newgame_match_ms: u64,
    pub handshake_secs: u64,
    pub http_bootstrap_ms: u64,
}

impl From<NetworkProfile> for TimeoutConfig {
    fn from(profile: NetworkProfile) -> Self {
        match profile {
            NetworkProfile::Aggressive => Self {
                newgame_match_ms: 500,
                handshake_secs: 2,
                http_bootstrap_ms: 1000,
            },
            NetworkProfile::Standard => Self {
                newgame_match_ms: 2000,
                handshake_secs: 8,
                http_bootstrap_ms: 4000,
            },
            NetworkProfile::Resilient => Self {
                newgame_match_ms: 4000,
                handshake_secs: 16,
                http_bootstrap_ms: 8000,
            },
        }
    }
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        NetworkProfile::Standard.into()
    }
}

#[derive(Debug, Clone)]
pub enum SessionError {
    Disconnected,
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionError::Disconnected => write!(f, "Session has been disconnected"),
        }
    }
}

impl std::error::Error for SessionError {}

/// State of a Slippi play-session
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SessionState {
    /// A game is in progress.
    InGame,
    /// A game is not in progress
    Idle,
    /// The session has ended (you or peer joined different game)
    Ended,
}

/// Peer connection/discovery state for the current [`Session`].
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ConnectionState {
    /// Dolphin reported a game and networking/discovery is running, but no peer
    /// has completed the SSP handshake yet.
    Discovering = 0,
    /// At least one peer has completed the SSP handshake.
    Discovered = 1,
}

impl ConnectionState {
    fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Discovered,
            _ => Self::Discovering,
        }
    }
}

/// SSP session object of Slippi play-session (persistent across games)
pub struct Session {
    session_state: Arc<Mutex<SessionState>>,
    connection_state: Arc<AtomicU8>,
    // Buffer for outgoing messages, sent by GameNet
    send_buf: Arc<Mutex<Vec<Vec<u8>>>>,
    // Receiver for incoming messages, transmitted to by GameNet
    incoming_msgs_rx: UnboundedReceiver<Msg>,
}

impl Session {
    pub fn try_recv(&mut self) -> Result<Option<Msg>, SessionError> {
        match self.incoming_msgs_rx.try_recv() {
            Ok(m) => Ok(Some(m)),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => Err(SessionError::Disconnected),
        }
    }

    pub async fn send(&self, data: Vec<u8>) -> bool {
        let mut buf = self.send_buf.lock().await;
        buf.push(data);
        true
    }

    pub fn connection_state(&self) -> ConnectionState {
        ConnectionState::from_u8(self.connection_state.load(Ordering::Relaxed))
    }

    pub fn peer_discovered(&self) -> bool {
        self.connection_state() == ConnectionState::Discovered
    }

    pub async fn state(&self) -> SessionState {
        *self.session_state.lock().await
    }

    pub async fn in_game(&self) -> bool {
        self.state().await == SessionState::InGame
    }
}

pub(crate) const DEFAULT_RELAY_URL: &str = "http://slippi-ssp.net:11015";
pub(crate) const DEFAULT_BOOTSTRAP_URL: &str = "http://slippi-ssp.net:11008";

/// Builder for configuring and starting a [`Session`].
pub struct SessionBuilder {
    encryption_enabled: bool,
    handshake_config: HandshakeConfig,
    bootstrap_url: Option<String>,
    relay_url: Option<String>,
    discovery_mode: DiscoveryMode,
    timeouts: TimeoutConfig,
    max_packet_length: usize,
    dolphin_host: String,
    dolphin_port: u16,
}

impl Default for SessionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionBuilder {
    pub fn new() -> Self {
        Self {
            encryption_enabled: true,
            handshake_config: HandshakeConfig {
                rollover: ParamRange::new(60, 120, 240),
                offset: ParamRange::new(30, 60, 120),
                slp_version_min: [0, 0, 0],
                slp_version_max: [u8::MAX, u8::MAX, u8::MAX],
                ssp_version_min: SSP_VERSION,
                ssp_version_max: SSP_VERSION,
            },
            bootstrap_url: None,
            relay_url: None,
            discovery_mode: DiscoveryMode::BootstrapDhtFallback,
            timeouts: TimeoutConfig::default(),
            max_packet_length: 32768, // Default 32KB
            dolphin_host: "127.0.0.1".to_string(),
            dolphin_port: 51441,
        }
    }

    pub fn set_dolphin_host(mut self, host: &str) -> Self {
        self.dolphin_host = host.to_string();
        self
    }

    pub fn set_dolphin_port(mut self, port: u16) -> Self {
        self.dolphin_port = port;
        self
    }

    /// Enable or disable input-based encryption (default: enabled).
    pub fn set_encryption(mut self, enabled: bool) -> Self {
        self.encryption_enabled = enabled;
        self
    }

    /// Set URL for bootstrap server (if bootstrap [`DiscoveryMode`] enabled, default:
    /// http://slippi-ssp.net:11008)
    pub fn set_bootstrap_url(mut self, url: &str) -> Self {
        self.bootstrap_url = Some(url.trim_end_matches('/').to_string());
        self
    }

    /// Set URL for the iroh relay server (default: http://slippi-ssp.net:11015).
    pub fn set_relay_url(mut self, url: &str) -> Self {
        self.relay_url = Some(url.trim_end_matches('/').to_string());
        self
    }

    /// Configure peer discovery method(s).
    pub fn set_discovery_mode(mut self, mode: DiscoveryMode) -> Self {
        self.discovery_mode = mode;
        self
    }

    /// Set a predefined network profile for all internal timeouts.
    pub fn set_network_profile(mut self, profile: NetworkProfile) -> Self {
        self.timeouts = profile.into();
        self
    }

    /// Set timeouts manually.
    pub fn set_timeouts(mut self, timeouts: TimeoutConfig) -> Self {
        self.timeouts = timeouts;
        self
    }

    /// Set max packet size (corresponds to allocated buffer size)
    pub fn set_max_packet_length(mut self, len: usize) -> Self {
        self.max_packet_length = len;
        self
    }

    /// Filter peers by Slippi version during handshake.
    pub fn set_slp_version_filter(mut self, min: [u8; 3], max: [u8; 3]) -> Self {
        self.handshake_config.slp_version_min = min;
        self.handshake_config.slp_version_max = max;
        self
    }

    /// Set the acceptable SSP protocol version range (default: 0.0.0 to SSP_VERSION).
    /// Both sides must agree; handshake is rejected if versions don't overlap.
    pub fn set_ssp_version_range(mut self, min: [u8; 3], max: [u8; 3]) -> Self {
        self.handshake_config.ssp_version_min = min;
        self.handshake_config.ssp_version_max = max;
        self
    }

    /// Set input-based encryption-key rotation interval and rollback offset (if encryption enabled).
    pub fn set_key_rotation(mut self, interval: u64, rollback_offset: u64) -> Self {
        self.handshake_config.rollover = ParamRange::new(interval, interval, interval);
        self.handshake_config.offset =
            ParamRange::new(rollback_offset, rollback_offset, rollback_offset);
        self
    }

    /// Set negotiable range for the key rotation interval, used during handshake.
    pub fn set_rollover_range(mut self, min: u64, preferred: u64, max: u64) -> Self {
        self.handshake_config.rollover = ParamRange::new(min, preferred, max);
        self
    }

    /// Set negotiable range for the rollback offset, used during handshake.
    pub fn set_offset_range(mut self, min: u64, preferred: u64, max: u64) -> Self {
        self.handshake_config.offset = ParamRange::new(min, preferred, max);
        self
    }

    /// Start the session: wait for game, then connect to peers.
    pub async fn connect(self) -> Session {
        let send_buf = Arc::new(Mutex::new(Vec::new()));
        // Channel for receiving messages
        let (incoming_msgs_tx, incoming_msgs_rx) = unbounded_channel::<Msg>();

        let (gameevent_tx, mut gameevent_rx) = unbounded_channel::<DolphinEvent>();
        let session_cancel_token = CancellationToken::new();

        let handshake_config = self.handshake_config;

        // If encryption enabled, setup crypter with gameinfo (input) and key update (output) channels
        let (crypter_key_rx, crypter_input_tx, handshake_succ_tx) = if self.encryption_enabled {
            let (update_tx, update_rx) = unbounded_channel::<CrypterUpdate>();
            let (input_tx, input_rx) = unbounded_channel::<CrypterInput>();
            let (handshake_succ_tx, handshake_succ_rx) = unbounded_channel::<(u64, u64)>();

            let crypter = SLPcrypter::new(
                input_rx,
                update_tx,
                handshake_config.rollover.preferred,
                handshake_config.offset.preferred,
                Some(handshake_succ_rx),
            );
            tokio::spawn(crypter.start());

            (Some(update_rx), Some(input_tx), Some(handshake_succ_tx))
        } else {
            (None, None, None)
        };

        // Start listening for gamedata, transmitting input data and game events
        let reader = SLPreader::new(
            &self.dolphin_host,
            self.dolphin_port,
            crypter_input_tx,
            gameevent_tx,
            session_cancel_token.clone(),
        );
        tokio::spawn(async move {
            reader.start().await;
        });

        // Waiting for first gamestart event and metadata
        let meta = loop {
            match gameevent_rx.recv().await {
                Some(DolphinEvent::NewGame(meta)) => break meta,
                _ => continue,
            }
        };

        let send_buf_clone = send_buf.clone();
        let encryption_enabled = self.encryption_enabled;
        let bootstrap_url = Some(
            self.bootstrap_url
                .unwrap_or_else(|| DEFAULT_BOOTSTRAP_URL.to_string()),
        );
        let relay_url = self
            .relay_url
            .unwrap_or_else(|| DEFAULT_RELAY_URL.to_string());
        let discovery_mode = self.discovery_mode;
        let session_state = Arc::new(Mutex::new(SessionState::InGame));
        let net_session_state = session_state.clone();
        let connection_state = Arc::new(AtomicU8::new(ConnectionState::Discovering as u8));
        let net_connection_state = connection_state.clone();

        let timeouts = self.timeouts;
        let max_packet_length = self.max_packet_length;

        tokio::spawn(async move {
            let bootstrap_relay_url = match relay_url.parse::<iroh::RelayUrl>() {
                Ok(url) => Some(url),
                Err(e) => {
                    panic!("[net] invalid relay URL '{}': {}", relay_url, e);
                }
            };
            GameNet::connect(
                meta,
                net_session_state,
                net_connection_state,
                encryption_enabled,
                discovery_mode,
                handshake_config,
                bootstrap_url,
                bootstrap_relay_url,
                send_buf_clone,
                incoming_msgs_tx,
                crypter_key_rx,
                gameevent_rx,
                handshake_succ_tx,
                session_cancel_token,
                timeouts,
                max_packet_length,
            )
            .await;
        });

        // Return when Dolphin reports NewGame and the network task has spawned.
        // Outgoing messages are buffered until a peer connection is ready.
        Session {
            session_state,
            connection_state,
            send_buf,
            incoming_msgs_rx,
        }
    }
}
