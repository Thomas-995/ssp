use enet::{Address, BandwidthLimit, ChannelLimit, Enet, Event, Packet, PacketMode};
use serde_json::json;
use ssp_client::{DiscoveryMode, Session, SessionBuilder, SessionState, TimeoutConfig};
use tokio::sync::Mutex as TokioMutex;
use tokio::time::{sleep, Duration};

static DOLPHIN_MOCK_TEST_LOCK: TokioMutex<()> = TokioMutex::const_new(());

#[derive(Clone, Debug)]
struct PlayerMeta {
    port: u8,
    char: u8,
    color: u8,
    team: u8,
    cpu: bool,
}

impl PlayerMeta {
    fn new(port: u8, char: u8, color: u8, team: u8, cpu: bool) -> Self {
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
struct GameMeta {
    stage: u8,
    is_teams: bool,
    players: Vec<PlayerMeta>,
    seed: u32,
    slp_version: [u8; 3],
}

impl GameMeta {
    fn new() -> Self {
        Self {
            stage: u8::MAX,
            is_teams: false,
            players: Vec::new(),
            seed: 0,
            slp_version: [0, 0, 0],
        }
    }
}

fn free_tcp_port() -> u16 {
    std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .expect("bind ephemeral TCP port")
        .local_addr()
        .expect("read TCP local addr")
        .port()
}

fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .expect("bind ephemeral UDP port")
        .local_addr()
        .expect("read UDP local addr")
        .port()
}

fn mock_game_meta_with_seed(seed: u32) -> GameMeta {
    let mut meta = GameMeta::new();
    meta.seed = seed;
    meta.slp_version = [0, 0, 0];
    meta.stage = 0;
    meta.players.push(PlayerMeta::new(1, 0, 0, 0, false));
    meta
}

fn mock_new_game_payload(meta: &GameMeta) -> String {
    let mut slp_data = Vec::new();

    // 0x35 Payloads event: two command/length triples.
    slp_data.push(0x35);
    slp_data.push(7); // payload size: 1 + (2 commands * 3 bytes)

    // Define 0x36 GameStart with 0x140 bytes of data (+ event byte in reader).
    slp_data.push(0x36);
    slp_data.extend_from_slice(&0x0140u16.to_be_bytes());

    // Define 0x38 PostFrame with 7 bytes of data (+ event byte in reader).
    slp_data.push(0x38);
    slp_data.extend_from_slice(&0x0007u16.to_be_bytes());

    // 0x36 GameStart
    slp_data.push(0x36);
    let mut game_start = vec![0u8; 0x140];
    game_start[0..3].copy_from_slice(&meta.slp_version);
    game_start[(0x13d - 1)..0x140].copy_from_slice(&meta.seed.to_be_bytes());

    let teams = if meta.is_teams { 1u16 } else { 0u16 };
    game_start[(0x0d - 1)..0x0e].copy_from_slice(&teams.to_be_bytes());
    game_start[(0x13 - 1)..0x14].copy_from_slice(&(meta.stage as u16).to_be_bytes());

    if let Some(player) = meta.players.first() {
        let player_index = (player.port - 1) as usize;
        game_start[0x66 - 1 + 0x24 * player_index] = if player.cpu { 0 } else { 1 };
        game_start[0x68 - 1 + 0x24 * player_index] = player.color;
        game_start[0x6e - 1 + 0x24 * player_index] = player.team;
    }
    slp_data.extend(game_start);

    // The reader emits NewGame after it sees the same player's character on a
    // subsequent PostFrame, so send two PostFrame events for player index 0.
    for _ in 0..2 {
        slp_data.push(0x38);
        let mut post_frame = vec![0u8; 7];
        if let Some(player) = meta.players.first() {
            post_frame[4] = player.port - 1;
            post_frame[6] = player.char;
        }
        slp_data.extend(post_frame);
    }

    slp_data.push(0x00);

    use base64::{engine::general_purpose::STANDARD, Engine as _};
    STANDARD.encode(&slp_data)
}

#[derive(Clone, Debug)]
enum MockDolphinAction {
    StartGame(u32),
    EndGame,
    Delay(Duration),
}

async fn spawn_mock_dolphin_sequence(port: u16, actions: Vec<MockDolphinAction>) {
    std::thread::spawn(move || {
        let enet = ssp_client::ENET_INSTANCE.get_or_init(|| Enet::new().unwrap());
        let address = Address::new(std::net::Ipv4Addr::LOCALHOST, port);
        let mut host = enet
            .create_host::<()>(
                Some(&address),
                4,
                ChannelLimit::Maximum,
                BandwidthLimit::Unlimited,
                BandwidthLimit::Unlimited,
            )
            .unwrap();

        let mut connected = false;
        let mut next_action = 0usize;
        let mut delay_until: Option<std::time::Instant> = None;

        loop {
            if let Ok(Some(Event::Connect(_))) = host.service(20) {
                connected = true;
            }

            if !connected {
                continue;
            }

            if next_action >= actions.len() {
                for mut peer in host.peers() {
                    peer.disconnect(0);
                }
                host.flush();
                let deadline = std::time::Instant::now() + std::time::Duration::from_millis(500);
                while std::time::Instant::now() < deadline {
                    let _ = host.service(20);
                }
                return;
            }

            if let Some(deadline) = delay_until {
                if std::time::Instant::now() < deadline {
                    continue;
                }
                delay_until = None;
                next_action += 1;
                continue;
            }

            match &actions[next_action] {
                MockDolphinAction::StartGame(seed) => {
                    let game_payload = mock_new_game_payload(&mock_game_meta_with_seed(*seed));
                    let start_msg = json!({"type": "start_game"}).to_string();
                    let game_event = json!({
                        "type": "game_event",
                        "payload": game_payload,
                    })
                    .to_string();

                    for mut peer in host.peers() {
                        if let Ok(pkt) =
                            Packet::new(start_msg.as_bytes(), PacketMode::ReliableSequenced)
                        {
                            let _ = peer.send_packet(pkt, 0);
                        }
                        if let Ok(pkt) =
                            Packet::new(game_event.as_bytes(), PacketMode::ReliableSequenced)
                        {
                            let _ = peer.send_packet(pkt, 0);
                        }
                    }
                    host.flush();
                    next_action += 1;
                }
                MockDolphinAction::EndGame => {
                    let end_msg = json!({"type": "end_game"}).to_string();
                    for mut peer in host.peers() {
                        if let Ok(pkt) =
                            Packet::new(end_msg.as_bytes(), PacketMode::ReliableSequenced)
                        {
                            let _ = peer.send_packet(pkt, 0);
                        }
                    }
                    host.flush();
                    next_action += 1;
                }
                MockDolphinAction::Delay(delay) => {
                    delay_until = Some(std::time::Instant::now() + *delay);
                }
            }
        }
    });
}

async fn start_real_bootstrap_server(port: u16) {
    tokio::spawn(async move {
        let config = ssp_bootstrap::server::ServerConfig {
            port,
            bind: std::net::Ipv4Addr::LOCALHOST,
            max_peers: 20,
            max_games: 100_000,
            ttl: 480,
            verbose: true,
        };
        let server = ssp_bootstrap::server::BootstrapServer::new(config);
        server.run().await;
    });
}

async fn start_test_infra() -> (String, String) {
    let boot_port = free_tcp_port();
    let relay_port = free_tcp_port();

    tokio::spawn(async move {
        let http_bind_addr = std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
            std::net::Ipv4Addr::LOCALHOST,
            relay_port,
        ));
        let relay_config: iroh_relay::server::RelayConfig<(), ()> =
            iroh_relay::server::RelayConfig {
                http_bind_addr,
                tls: None,
                limits: iroh_relay::server::Limits::default(),
                key_cache_capacity: None,
                access: iroh_relay::server::AccessConfig::Everyone,
            };
        let config: iroh_relay::server::ServerConfig<(), ()> = iroh_relay::server::ServerConfig {
            relay: Some(relay_config),
            quic: None,
            metrics_addr: None,
        };
        match iroh_relay::server::Server::spawn(config).await {
            Ok(mut server) => {
                let _ = server.task_handle().await;
            }
            Err(err) => eprintln!("Failed to start iroh relay: {err}"),
        }
    });

    start_real_bootstrap_server(boot_port).await;
    sleep(Duration::from_millis(500)).await;

    (
        format!("http://127.0.0.1:{}", boot_port),
        format!("http://127.0.0.1:{}", relay_port),
    )
}

fn test_timeouts() -> TimeoutConfig {
    TimeoutConfig {
        newgame_match_ms: 8_000,
        handshake_secs: 6,
        http_bootstrap_ms: 1_500,
    }
}

async fn connect_ssp_session(
    bootstrap_url: &str,
    relay_url: &str,
    dolphin_port: u16,
) -> Result<Session, String> {
    tokio::time::timeout(
        Duration::from_secs(12),
        SessionBuilder::new()
            .set_bootstrap_url(bootstrap_url)
            .set_relay_url(relay_url)
            .set_discovery_mode(DiscoveryMode::BootstrapOnly)
            .set_timeouts(test_timeouts())
            .set_encryption(false)
            .set_dolphin_port(dolphin_port)
            .connect(),
    )
    .await
    .map_err(|_| format!("session did not connect to mock Dolphin on {dolphin_port} in time"))
}

async fn wait_for_state(
    session: &Session,
    expected: SessionState,
    timeout: Duration,
) -> Result<(), String> {
    let start = tokio::time::Instant::now();
    while start.elapsed() < timeout {
        if session.state().await == expected {
            return Ok(());
        }
        sleep(Duration::from_millis(50)).await;
    }
    let current = session.state().await;
    if current == expected {
        return Ok(());
    }
    Err(format!(
        "session did not reach state {:?} within {:?}; current state is {:?}",
        expected, timeout, current
    ))
}

async fn wait_for_next_game(session: &Session, timeout: Duration) -> Result<(), String> {
    wait_for_state(session, SessionState::InGame, timeout).await?;
    wait_for_state(session, SessionState::Idle, timeout).await?;
    wait_for_state(session, SessionState::InGame, timeout).await
}

async fn wait_for_message(
    session: &mut Session,
    expected: &str,
    timeout: Duration,
) -> Result<(), String> {
    let start = tokio::time::Instant::now();
    while start.elapsed() < timeout {
        while let Ok(Some(msg)) = session.try_recv() {
            let text = String::from_utf8(msg.data).map_err(|e| e.to_string())?;
            if text == expected {
                return Ok(());
            }
        }
        sleep(Duration::from_millis(50)).await;
    }
    Err(format!(
        "did not receive expected message '{expected}' within {:?}",
        timeout
    ))
}

async fn send_once_and_wait(
    sender: &Session,
    receiver: &mut Session,
    expected: &str,
    timeout: Duration,
) -> Result<(), String> {
    sender.send(expected.as_bytes().to_vec()).await;
    wait_for_message(receiver, expected, timeout).await
}

async fn run_games_then_leave() -> Result<(), String> {
    let _enet = ssp_client::ENET_INSTANCE.get_or_init(|| Enet::new().unwrap());
    let (bootstrap_url, relay_url) = start_test_infra().await;

    let port_a = free_udp_port();
    let mut port_b = free_udp_port();
    while port_b == port_a {
        port_b = free_udp_port();
    }

    let first = 0x0102_0304;
    let second = 0x0506_0708;
    let a_only = 0x0d0e_0f10;
    let b_only = 0x090a_0b0c;

    spawn_mock_dolphin_sequence(
        port_a,
        vec![
            MockDolphinAction::StartGame(first),
            MockDolphinAction::Delay(Duration::from_secs(4)),
            MockDolphinAction::EndGame,
            MockDolphinAction::Delay(Duration::from_millis(500)),
            MockDolphinAction::StartGame(second),
            MockDolphinAction::Delay(Duration::from_secs(2)),
            MockDolphinAction::EndGame,
            MockDolphinAction::Delay(Duration::from_millis(500)),
            MockDolphinAction::StartGame(a_only),
            MockDolphinAction::Delay(Duration::from_secs(2)),
        ],
    )
    .await;
    spawn_mock_dolphin_sequence(
        port_b,
        vec![
            MockDolphinAction::StartGame(first),
            MockDolphinAction::Delay(Duration::from_secs(4)),
            MockDolphinAction::EndGame,
            MockDolphinAction::Delay(Duration::from_millis(500)),
            MockDolphinAction::StartGame(second),
            MockDolphinAction::Delay(Duration::from_secs(2)),
            MockDolphinAction::EndGame,
            MockDolphinAction::Delay(Duration::from_millis(500)),
            MockDolphinAction::StartGame(b_only),
        ],
    )
    .await;

    sleep(Duration::from_millis(100)).await;
    let session_a = connect_ssp_session(&bootstrap_url, &relay_url, port_a).await?;
    let mut session_b = connect_ssp_session(&bootstrap_url, &relay_url, port_b).await?;

    wait_for_next_game(&session_a, Duration::from_secs(8)).await?;
    wait_for_state(&session_b, SessionState::InGame, Duration::from_secs(5)).await?;
    send_once_and_wait(
        &session_a,
        &mut session_b,
        "second game hello",
        Duration::from_secs(8),
    )
    .await?;

    wait_for_state(&session_a, SessionState::Ended, Duration::from_secs(8)).await?;
    wait_for_state(&session_b, SessionState::Ended, Duration::from_secs(8)).await?;
    Ok(())
}

async fn run_game_then_reconnect() -> Result<(), String> {
    let _enet = ssp_client::ENET_INSTANCE.get_or_init(|| Enet::new().unwrap());
    let (bootstrap_url, relay_url) = start_test_infra().await;

    let port_a1 = free_udp_port();
    let mut port_a2 = free_udp_port();
    while port_a2 == port_a1 {
        port_a2 = free_udp_port();
    }
    let mut port_b = free_udp_port();
    while port_b == port_a1 || port_b == port_a2 {
        port_b = free_udp_port();
    }

    let first = 0x1111_0001;
    let reconnect_seed = 0x1111_0002;
    let b_after = 0x1111_0003;
    let a2_after = 0x1111_0004;

    spawn_mock_dolphin_sequence(
        port_a1,
        vec![
            MockDolphinAction::StartGame(first),
            MockDolphinAction::Delay(Duration::from_secs(2)),
            MockDolphinAction::EndGame,
        ],
    )
    .await;
    spawn_mock_dolphin_sequence(
        port_b,
        vec![
            MockDolphinAction::StartGame(first),
            MockDolphinAction::Delay(Duration::from_secs(2)),
            MockDolphinAction::EndGame,
            MockDolphinAction::Delay(Duration::from_secs(2)),
            MockDolphinAction::StartGame(reconnect_seed),
            MockDolphinAction::Delay(Duration::from_secs(2)),
            MockDolphinAction::EndGame,
            MockDolphinAction::Delay(Duration::from_millis(500)),
            MockDolphinAction::StartGame(b_after),
            MockDolphinAction::Delay(Duration::from_secs(2)),
        ],
    )
    .await;
    spawn_mock_dolphin_sequence(
        port_a2,
        vec![
            MockDolphinAction::StartGame(reconnect_seed),
            MockDolphinAction::Delay(Duration::from_secs(2)),
            MockDolphinAction::StartGame(reconnect_seed),
            MockDolphinAction::Delay(Duration::from_secs(2)),
            MockDolphinAction::EndGame,
            MockDolphinAction::Delay(Duration::from_millis(500)),
            MockDolphinAction::StartGame(a2_after),
            MockDolphinAction::Delay(Duration::from_secs(2)),
        ],
    )
    .await;

    sleep(Duration::from_millis(100)).await;
    let session_a1 = connect_ssp_session(&bootstrap_url, &relay_url, port_a1).await?;
    let session_b = connect_ssp_session(&bootstrap_url, &relay_url, port_b).await?;

    wait_for_state(&session_a1, SessionState::Ended, Duration::from_secs(6)).await?;
    sleep(Duration::from_millis(250)).await;
    let mut session_a2 = connect_ssp_session(&bootstrap_url, &relay_url, port_a2).await?;

    wait_for_state(&session_a2, SessionState::InGame, Duration::from_secs(6)).await?;
    wait_for_state(&session_b, SessionState::InGame, Duration::from_secs(6)).await?;
    send_once_and_wait(
        &session_b,
        &mut session_a2,
        "after reconnect",
        Duration::from_secs(8),
    )
    .await?;

    wait_for_state(&session_a2, SessionState::Ended, Duration::from_secs(8)).await?;
    wait_for_state(&session_b, SessionState::Ended, Duration::from_secs(8)).await?;
    Ok(())
}

async fn run_games_then_new() -> Result<(), String> {
    let _enet = ssp_client::ENET_INSTANCE.get_or_init(|| Enet::new().unwrap());
    let (bootstrap_url, relay_url) = start_test_infra().await;

    let port_a = free_udp_port();
    let mut port_b = free_udp_port();
    while port_b == port_a {
        port_b = free_udp_port();
    }
    let mut port_c = free_udp_port();
    while port_c == port_a || port_c == port_b {
        port_c = free_udp_port();
    }

    let first = 0x2222_0001;
    let second = 0x2222_0002;
    let a_after = 0x2222_0003;
    let b_after = 0x2222_0004;
    let c_after = 0x2222_0005;
    let sequence_a = vec![
        MockDolphinAction::StartGame(first),
        MockDolphinAction::Delay(Duration::from_secs(4)),
        MockDolphinAction::EndGame,
        MockDolphinAction::Delay(Duration::from_millis(500)),
        MockDolphinAction::StartGame(second),
        MockDolphinAction::Delay(Duration::from_secs(2)),
        MockDolphinAction::EndGame,
        MockDolphinAction::Delay(Duration::from_millis(500)),
        MockDolphinAction::StartGame(a_after),
        MockDolphinAction::Delay(Duration::from_secs(2)),
    ];
    let sequence_b = vec![
        MockDolphinAction::StartGame(first),
        MockDolphinAction::Delay(Duration::from_secs(4)),
        MockDolphinAction::EndGame,
        MockDolphinAction::Delay(Duration::from_millis(500)),
        MockDolphinAction::StartGame(second),
        MockDolphinAction::Delay(Duration::from_secs(2)),
        MockDolphinAction::EndGame,
        MockDolphinAction::Delay(Duration::from_millis(500)),
        MockDolphinAction::StartGame(b_after),
        MockDolphinAction::Delay(Duration::from_secs(2)),
    ];

    spawn_mock_dolphin_sequence(port_a, sequence_a).await;
    spawn_mock_dolphin_sequence(port_b, sequence_b).await;
    spawn_mock_dolphin_sequence(
        port_c,
        vec![
            MockDolphinAction::StartGame(second),
            MockDolphinAction::Delay(Duration::from_secs(2)),
            MockDolphinAction::EndGame,
            MockDolphinAction::Delay(Duration::from_millis(500)),
            MockDolphinAction::StartGame(c_after),
            MockDolphinAction::Delay(Duration::from_secs(2)),
        ],
    )
    .await;

    sleep(Duration::from_millis(100)).await;
    let session_a = connect_ssp_session(&bootstrap_url, &relay_url, port_a).await?;
    let mut session_b = connect_ssp_session(&bootstrap_url, &relay_url, port_b).await?;

    wait_for_next_game(&session_a, Duration::from_secs(8)).await?;
    wait_for_state(&session_b, SessionState::InGame, Duration::from_secs(5)).await?;
    send_once_and_wait(
        &session_a,
        &mut session_b,
        "before c joins",
        Duration::from_secs(8),
    )
    .await?;

    let session_c = connect_ssp_session(&bootstrap_url, &relay_url, port_c).await?;
    wait_for_state(&session_a, SessionState::InGame, Duration::from_secs(6)).await?;
    wait_for_state(&session_c, SessionState::InGame, Duration::from_secs(12)).await?;
    wait_for_state(&session_a, SessionState::Ended, Duration::from_secs(12)).await?;
    wait_for_state(&session_b, SessionState::Ended, Duration::from_secs(12)).await?;
    wait_for_state(&session_c, SessionState::Ended, Duration::from_secs(12)).await?;
    Ok(())
}

async fn run_child_scenario<F>(test_name: &str, scenario: F, timeout: Duration)
where
    F: std::future::Future<Output = Result<(), String>>,
{
    println!("Testing {test_name}...");
    let result = tokio::time::timeout(timeout, scenario).await;

    match result {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            panic!("Test {test_name}: {err}");
        }
        Err(_) => {
            panic!("Test {test_name}: child scenario timed out");
        }
    }
}

#[tokio::test]
async fn test_games_then_leave() {
    let _guard = DOLPHIN_MOCK_TEST_LOCK.lock().await;
    run_child_scenario(
        "test_games_then_leave",
        run_games_then_leave(),
        Duration::from_secs(12),
    )
    .await;
}

#[tokio::test]
async fn test_game_then_leave_reconnect() {
    let _guard = DOLPHIN_MOCK_TEST_LOCK.lock().await;
    run_child_scenario(
        "test_game_then_leave_reconnect",
        run_game_then_reconnect(),
        Duration::from_secs(25),
    )
    .await;
}

#[tokio::test]
async fn test_games_then_new_peer() {
    let _guard = DOLPHIN_MOCK_TEST_LOCK.lock().await;
    run_child_scenario(
        "test_games_then_new_peer",
        run_games_then_new(),
        Duration::from_secs(35),
    )
    .await;
}
