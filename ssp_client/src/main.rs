use ssp_client::SessionBuilder;
use tokio::io::{AsyncBufReadExt, BufReader};

#[tokio::main]
async fn main() {
    println!("Starting ssp_client...");

    #[cfg(debug_assertions)]
    let builder = {
        let dolphin_host =
            std::env::var("SSP_DOLPHIN_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
        let dolphin_port = std::env::var("SSP_DOLPHIN_PORT")
            .ok()
            .and_then(|port| port.parse::<u16>().ok())
            .unwrap_or(51441);
        let bootstrap_url = std::env::var("SSP_BOOTSTRAP_URL").ok();
        let relay_url = std::env::var("SSP_RELAY_URL").ok();

        println!(
            "Connecting to Slippi ENet at {dolphin_host}:{dolphin_port}; bootstrap={}; relay={}",
            bootstrap_url.as_deref().unwrap_or("default"),
            relay_url.as_deref().unwrap_or("default"),
        );

        let mut builder = SessionBuilder::new()
            .set_dolphin_host(&dolphin_host)
            .set_dolphin_port(dolphin_port);
        if let Some(url) = &bootstrap_url {
            builder = builder.set_bootstrap_url(url);
        }
        if let Some(url) = &relay_url {
            builder = builder.set_relay_url(url);
        }
        builder
    };

    #[cfg(not(debug_assertions))]
    let builder = {
        println!(
            "Connecting with SessionBuilder defaults: Slippi ENet 127.0.0.1:51441; default bootstrap/relay"
        );
        SessionBuilder::new()
    };

    let mut session = builder.connect().await;

    println!("SSP session connected. Type messages and press Enter to send.");

    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin).lines();

    loop {
        tokio::select! {
            _ = tokio::time::sleep(tokio::time::Duration::from_millis(10)) => {
                match session.try_recv() {
                    Ok(Some(msg)) => {
                        if let Ok(text) = String::from_utf8(msg.data.clone()) {
                            println!("[{:?}]: {}", msg.from, text);
                        }
                    }
                    Ok(None) => {}
                    Err(err) => {
                        eprintln!("Session error: {}", err);
                        break;
                    }
                }
            }

            line = reader.next_line() => {
                match line {
                    Ok(Some(input)) => {
                        if !input.is_empty() {
                            let data = input.into_bytes();
                            if !session.send(data).await {
                                println!("Failed to send message");
                            }
                        }
                    }
                    Ok(None) => {
                        println!("stdin closed, exiting...");
                        break;
                    }
                    Err(e) => {
                        eprintln!("Error reading stdin: {}", e);
                        break;
                    }
                }
            }
        }
    }
}
