# ssp-client

Client library and test binary for SSP.

## Binary

```bash
cargo run -p ssp-client --bin ssp
```

Debug builds can override defaults with:

```bash
SSP_DOLPHIN_HOST=127.0.0.1 \
SSP_DOLPHIN_PORT=51441 \
SSP_BOOTSTRAP_URL=http://127.0.0.1:5000 \
SSP_RELAY_URL=http://127.0.0.1:3340 \
cargo run -p ssp-client --bin ssp
```

Release builds use `SessionBuilder::new()` defaults.

## Library

```rust
use ssp_client::{ConnectionState, SessionBuilder};

#[tokio::main]
async fn main() {
    let mut session = SessionBuilder::new()
        .set_bootstrap_url("http://127.0.0.1:5000")
        .connect()
        .await;

    println!("connection state: {:?}", session.connection_state());

    session.send(b"hello".to_vec()).await;

    while let Ok(Some(msg)) = session.try_recv() {
        println!("from {:?}: {:?}", msg.from, msg.data);
    }
}
```
