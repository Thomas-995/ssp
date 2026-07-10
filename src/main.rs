use std::{env, net::Ipv4Addr};

use iroh_relay::server::{
    AccessConfig, RelayConfig, Server as RelayServer, ServerConfig as RelayServerConfig,
};
use ssp_bootstrap::server::{BootstrapServer, ServerConfig as BootstrapServerConfig};

fn env_u16(names: &[&str], default: u16) -> u16 {
    names
        .iter()
        .find_map(|name| env::var(name).ok()?.parse::<u16>().ok())
        .unwrap_or(default)
}

fn env_ipv4(names: &[&str], default: Ipv4Addr) -> Ipv4Addr {
    names
        .iter()
        .find_map(|name| env::var(name).ok()?.parse::<Ipv4Addr>().ok())
        .unwrap_or(default)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let bind = env_ipv4(&["SSP_DEV_BIND", "SLP_BIND"], Ipv4Addr::UNSPECIFIED);
    let bootstrap_port = env_u16(&["SSP_DEV_BOOTSTRAP_PORT", "SLP_PORT", "SERVER_PORT"], 5000);
    let relay_port = env_u16(&["SSP_DEV_RELAY_PORT", "SSP_RELAY_PORT"], 11015);

    let mut bootstrap_config = BootstrapServerConfig::default();
    bootstrap_config.bind = bind;
    bootstrap_config.port = bootstrap_port;
    bootstrap_config.verbose = true;

    println!("SLPauth bootstrap server");
    println!("  bind     : {}", bootstrap_config.socket_addr());
    println!("  ttl      : {}s", bootstrap_config.ttl);
    println!("  capacity : {} peers/game", bootstrap_config.max_peers);
    println!("  games    : {} max", bootstrap_config.max_games);
    println!("  verbose  : {}", bootstrap_config.verbose);

    let bootstrap_task =
        tokio::spawn(async move { BootstrapServer::new(bootstrap_config).run().await });

    let relay_addr = (bind, relay_port).into();
    let relay_config = RelayServerConfig::<(), ()> {
        relay: Some(RelayConfig {
            http_bind_addr: relay_addr,
            tls: None,
            limits: Default::default(),
            key_cache_capacity: Some(1024),
            access: AccessConfig::Everyone,
        }),
        quic: None,
        metrics_addr: None,
    };
    let _relay = RelayServer::spawn(relay_config).await?;

    println!("iroh relay listening on http://{relay_addr}");

    tokio::select! {
        result = bootstrap_task => {
            match result {
                Ok(Ok(())) => eprintln!("bootstrap server stopped"),
                Ok(Err(err)) => eprintln!("bootstrap server error: {err}"),
                Err(err) => eprintln!("bootstrap task failed: {err}"),
            }
        }
        result = tokio::signal::ctrl_c() => {
            result?;
            println!("shutting down");
        }
    }

    Ok(())
}
