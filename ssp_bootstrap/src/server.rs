use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

#[derive(Parser, Debug, Clone)]
#[command(name = "ssp-bootstrap", version)]
pub struct ServerConfig {
    #[arg(short, long, default_value_t = 5000, env = "SLP_PORT")]
    pub port: u16,

    #[arg(short, long, default_value = "0.0.0.0", env = "SLP_BIND")]
    pub bind: Ipv4Addr,

    #[arg(short, long, default_value_t = 20, env = "SLP_MAX_PEERS")]
    pub max_peers: usize,

    #[arg(short = 'g', long, default_value_t = 100_000, env = "SLP_MAX_GAMES")]
    pub max_games: usize,

    #[arg(short, long, default_value_t = 480, env = "SLP_TTL")]
    pub ttl: u64,

    #[arg(short, long, default_value_t = false, env = "SLP_VERBOSE")]
    pub verbose: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            port: 5000,
            bind: Ipv4Addr::UNSPECIFIED,
            max_peers: 20,
            max_games: 100_000,
            ttl: 480,
            verbose: false,
        }
    }
}

impl ServerConfig {
    pub fn peer_ttl(&self) -> Duration {
        Duration::from_secs(self.ttl)
    }

    pub fn socket_addr(&self) -> SocketAddr {
        SocketAddr::from((self.bind, self.port))
    }
}

pub struct BootstrapServerBuilder {
    config: ServerConfig,
}

impl Default for BootstrapServerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl BootstrapServerBuilder {
    pub fn new() -> Self {
        Self {
            config: ServerConfig::default(),
        }
    }

    pub fn config(mut self, config: ServerConfig) -> Self {
        self.config = config;
        self
    }

    pub fn port(mut self, port: u16) -> Self {
        self.config.port = port;
        self
    }

    pub fn bind(mut self, bind: Ipv4Addr) -> Self {
        self.config.bind = bind;
        self
    }

    pub fn max_peers(mut self, max_peers: usize) -> Self {
        self.config.max_peers = max_peers;
        self
    }

    pub fn max_games(mut self, max_games: usize) -> Self {
        self.config.max_games = max_games;
        self
    }

    pub fn ttl(mut self, ttl: u64) -> Self {
        self.config.ttl = ttl;
        self
    }

    pub fn verbose(mut self, verbose: bool) -> Self {
        self.config.verbose = verbose;
        self
    }

    pub fn build(self) -> BootstrapServer {
        BootstrapServer::new(self.config)
    }
}

struct PeerEntry {
    id: String,
    addr: Option<String>,
    last_seen: Instant,
}

pub struct BootstrapServer {
    state: Mutex<BootstrapState>,
    config: ServerConfig,
}

struct BootstrapState {
    games: HashMap<String, Vec<PeerEntry>>,
    peer_game: HashMap<String, String>,
    game_session: HashMap<String, String>,
    requests: u64,
    rejected: u64,
}

#[derive(Deserialize)]
struct Params {
    id: String,
    session: Option<String>,
    addr: Option<String>,
}

#[derive(Serialize)]
pub struct BootstrapResponse {
    pub session: String,
    pub peers: Vec<String>,
    pub peer_addrs: Vec<String>,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: &'static str,
}

#[derive(Serialize)]
struct StatsResponse {
    games: usize,
    peers: usize,
    requests: u64,
    rejected: u64,
}

impl BootstrapState {
    fn new() -> Self {
        Self {
            games: HashMap::new(),
            peer_game: HashMap::new(),
            game_session: HashMap::new(),
            requests: 0,
            rejected: 0,
        }
    }

    fn evict_game(&mut self, game: &str, ttl: Duration) {
        let now = Instant::now();
        let mut evicted = Vec::new();
        let mut remove_bucket = false;

        if let Some(peers) = self.games.get_mut(game) {
            peers.retain(|peer| {
                let keep = now.duration_since(peer.last_seen) < ttl;
                if !keep {
                    evicted.push(peer.id.clone());
                }
                keep
            });
            remove_bucket = peers.is_empty();
        }

        for peer in evicted {
            if self.peer_game.get(&peer).is_some_and(|g| g == game) {
                self.peer_game.remove(&peer);
            }
        }

        if remove_bucket {
            self.games.remove(game);
            self.game_session.remove(game);
        }
    }

    fn evict_expired(&mut self, ttl: Duration) {
        let games = self.games.keys().cloned().collect::<Vec<_>>();
        for game in games {
            self.evict_game(&game, ttl);
        }
    }

    fn remove_peer_from_previous_game(&mut self, peer: &str, game: &str) {
        let Some(previous_game) = self.peer_game.get(peer).cloned() else {
            return;
        };
        if previous_game == game {
            return;
        }

        let mut remove_bucket = false;
        if let Some(peers) = self.games.get_mut(&previous_game) {
            peers.retain(|entry| entry.id != peer);
            remove_bucket = peers.is_empty();
        }
        if remove_bucket {
            self.games.remove(&previous_game);
            self.game_session.remove(&previous_game);
        }
        self.peer_game.remove(peer);
    }

    fn peer_count(&self) -> usize {
        self.games.values().map(Vec::len).sum()
    }
}

impl BootstrapServer {
    pub fn new(config: ServerConfig) -> Self {
        Self {
            state: Mutex::new(BootstrapState::new()),
            config,
        }
    }

    pub fn builder() -> BootstrapServerBuilder {
        BootstrapServerBuilder::new()
    }

    pub async fn run(self) -> std::io::Result<()> {
        let _ = tracing_subscriber::fmt::try_init();

        let addr = self.config.socket_addr();
        let state = Arc::new(self);
        let app = Router::new()
            .route("/health", get(health))
            .route("/stats", get(stats))
            .route("/games/:game", get(handle_bootstrap))
            .with_state(state);

        let listener = tokio::net::TcpListener::bind(addr).await?;
        println!("SLPauth bootstrap server listening on http://{addr}");

        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_signal())
            .await
    }

    fn lock_state(&self) -> MutexGuard<'_, BootstrapState> {
        self.state.lock().unwrap_or_else(|err| err.into_inner())
    }
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

async fn health() -> &'static str {
    "ok"
}

async fn stats(State(server): State<Arc<BootstrapServer>>) -> Json<StatsResponse> {
    let state = server.lock_state();
    Json(StatsResponse {
        games: state.games.len(),
        peers: state.peer_count(),
        requests: state.requests,
        rejected: state.rejected,
    })
}

async fn handle_bootstrap(
    State(server): State<Arc<BootstrapServer>>,
    Path(game): Path<String>,
    Query(params): Query<Params>,
) -> impl IntoResponse {
    if !valid_hash(&game) || !valid_peer_id(&params.id) {
        let mut state = server.lock_state();
        state.rejected += 1;
        return bad_request("invalid request");
    }
    if params
        .session
        .as_ref()
        .is_some_and(|session| !valid_hash(session))
    {
        let mut state = server.lock_state();
        state.rejected += 1;
        return bad_request("invalid session");
    }
    if params.addr.as_ref().is_some_and(|addr| !valid_addr(addr)) {
        let mut state = server.lock_state();
        state.rejected += 1;
        return bad_request("invalid address");
    }

    let now = Instant::now();
    let ttl = server.config.peer_ttl();
    let capacity = server.config.max_peers;
    let max_games = server.config.max_games;
    let verbose = server.config.verbose;
    let peer_id = params.id;
    let peer_addr = params.addr;

    let mut state = server.lock_state();
    state.requests += 1;
    state.evict_game(&game, ttl);

    if !state.games.contains_key(&game) && state.games.len() >= max_games {
        state.evict_expired(ttl);
        if !state.games.contains_key(&game) && state.games.len() >= max_games {
            state.rejected += 1;
            return service_unavailable("server full");
        }
    }

    if let Some(session) = params.session {
        state.game_session.insert(game.clone(), session);
    }
    let session = state
        .game_session
        .get(&game)
        .cloned()
        .unwrap_or_else(|| game.clone());

    state.remove_peer_from_previous_game(&peer_id, &game);

    let mut upserted = false;
    let (peers, peer_addrs, registered) = {
        let peer_list = state.games.entry(game.clone()).or_default();

        if let Some(existing) = peer_list.iter_mut().find(|entry| entry.id == peer_id) {
            existing.addr = peer_addr.clone();
            existing.last_seen = now;
            upserted = true;
        } else if peer_list.len() < capacity {
            peer_list.push(PeerEntry {
                id: peer_id.clone(),
                addr: peer_addr.clone(),
                last_seen: now,
            });
            upserted = true;
        }

        let peers = peer_list
            .iter()
            .filter(|entry| entry.id != peer_id)
            .map(|entry| entry.id.clone())
            .collect::<Vec<_>>();
        let peer_addrs = peer_list
            .iter()
            .filter(|entry| entry.id != peer_id)
            .filter_map(|entry| entry.addr.clone())
            .collect::<Vec<_>>();
        (peers, peer_addrs, peer_list.len())
    };

    if upserted {
        state.peer_game.insert(peer_id.clone(), game.clone());
    }

    if verbose {
        println!(
            "[REQUEST] game_hash={} | peer_id={} | returning {} peer(s) ({} registered)",
            game,
            peer_id,
            peers.len(),
            registered,
        );
    }

    Json(BootstrapResponse {
        session,
        peers,
        peer_addrs,
    })
    .into_response()
}

fn valid_hash(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn valid_peer_id(value: &str) -> bool {
    value.len() <= 128
        && !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn valid_addr(value: &str) -> bool {
    value.len() <= 8192
        && !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn bad_request(error: &'static str) -> axum::response::Response {
    (StatusCode::BAD_REQUEST, Json(ErrorResponse { error })).into_response()
}

fn service_unavailable(error: &'static str) -> axum::response::Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(ErrorResponse { error }),
    )
        .into_response()
}
