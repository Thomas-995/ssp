# ssp-bootstrap

HTTP bootstrap discovery server for SSP clients.

## Run

```bash
cargo run -p ssp-bootstrap -- --port 5000 --bind 0.0.0.0
```

Options:

```bash
ssp-bootstrap \
  --port 5000 \
  --bind 0.0.0.0 \
  --max-peers 20 \
  --max-games 100000 \
  --ttl 480
```
## Library

```rust
use ssp_bootstrap::server::{BootstrapServer, ServerConfig};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    BootstrapServer::new(ServerConfig::default()).run().await
}
```
