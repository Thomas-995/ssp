# SSP (Slippi Session Protocol)

- `ssp-client` / crate `ssp_client`: connects to Slippi ENet port, establishes P2P connection with optional input-based encryption. Peer discovery falls back to BitTorrent Mainline DHT with n0 relays, if bootstrap server is unavailable.
- `ssp-bootstrap` / crate `ssp_bootstrap`: optional HTTP bootstrap peer discovery server.

## Run a bootstrap server

```bash
cargo run -p ssp-bootstrap -- --port 5000 --bind 0.0.0.0
```

options:

```bash
ssp-bootstrap --port 5000 --bind 0.0.0.0 --max-peers 20 --max-games 100000 --ttl 480
```

## Use client example binary

Run the following and start any local or online match using slippi:

```bash
cargo run -p ssp-client --bin ssp
```


## Use `ssp_client` as a library

```rust
use ssp_client::{ConnectionState, SessionBuilder};

#[tokio::main]
async fn main() {
    let mut session = SessionBuilder::new()
        .set_bootstrap_url("http://127.0.0.1:5000")
        .connect()
        .await;

    if session.connection_state() == ConnectionState::Discovering {
        println!("waiting for a peer handshake...");
    }

    session.send(b"hello".to_vec()).await;

    if let Ok(Some(msg)) = session.try_recv() {
        println!("from {:?}: {:?}", msg.from, msg.data);
    }
}
```

## Use `ssp_bootstrap` as a library

```rust
use ssp_bootstrap::server::{BootstrapServer, ServerConfig};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    BootstrapServer::new(ServerConfig::default()).run().await
}
```
