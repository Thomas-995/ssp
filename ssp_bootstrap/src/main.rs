use clap::Parser;
use ssp_bootstrap::server::{BootstrapServer, ServerConfig};

#[tokio::main]
async fn main() {
    let config = ServerConfig::parse();

    println!("SLPauth bootstrap server");
    println!("  bind     : {}", config.socket_addr());
    println!("  ttl      : {}s", config.ttl);
    println!("  capacity : {} peers/game", config.max_peers);
    println!("  games    : {} max", config.max_games);
    println!("  verbose  : {}", config.verbose);

    if let Err(err) = BootstrapServer::new(config).run().await {
        eprintln!("server error: {err}");
        std::process::exit(1);
    }
}
