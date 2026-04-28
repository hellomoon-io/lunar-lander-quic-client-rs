# lunar-lander-quic-client

[![CI](https://github.com/hellomoon-io/lunar-lander-quic-client-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/hellomoon-io/lunar-lander-quic-client-rs/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/lunar-lander-quic-client.svg)](https://crates.io/crates/lunar-lander-quic-client)
[![docs.rs](https://img.shields.io/docsrs/lunar-lander-quic-client)](https://docs.rs/lunar-lander-quic-client)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](./LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](./Cargo.toml)

Official Rust QUIC client for Hello Moon Lunar Lander.

This crate is intentionally focused on a small surface area:
- connect to a Lunar Lander QUIC endpoint
- authenticate with a client certificate derived from your API key
- send one serialized Solana transaction per uni stream

## What it supports

- Lunar Lander QUIC submission
- in-code self-signed client certificate generation
- one connection reused across many sends

## What it does not do

- build or sign transactions for you
- simulate or preflight transactions
- provide JSON-RPC wrappers
- submit HTTP batches or bundles

## Install

```toml
[dependencies]
lunar-lander-quic-client = "0.3.0"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

## Quick start

```rust
use lunar_lander_quic_client::LunarLanderQuicClient;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let api_key = std::env::var("LUNAR_LANDER_API_KEY")?;
    let client = LunarLanderQuicClient::connect(
        "fra.lunar-lander.hellomoon.io:16888",
        api_key,
    )
    .await?;

    let tx_bytes = create_signed_transaction_somewhere()?;
    client.send_transaction(&tx_bytes).await?;

    Ok(())
}
```

## MEV Protection

Set `mev_protect: true` in `ClientOptions` to signal the server to enable MEV
protection for transactions sent over this connection. The flag embeds a custom
X.509 certificate extension (OID `2.999.1.1`) in the self-signed
client certificate. The extension is non-critical, so older servers that do not
understand it will simply ignore it.

```rust
use lunar_lander_quic_client::{ClientOptions, LunarLanderQuicClient};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let api_key = std::env::var("LUNAR_LANDER_API_KEY")?;
    let options = ClientOptions {
        mev_protect: true,
        ..ClientOptions::default()
    };

    let client = LunarLanderQuicClient::connect_with_options(
        "fra.lunar-lander.hellomoon.io:16888",
        api_key,
        options,
    )
    .await?;

    let tx_bytes = create_signed_transaction_somewhere()?;
    client.send_transaction(&tx_bytes).await?;

    Ok(())
}
```

## Examples

This repo includes:
- `send_transaction`: fetch a recent blockhash, build a tipped transaction, sign it, and send it over QUIC

Run the richer example with:

```bash
LUNAR_LANDER_API_KEY=your-api-key \
LUNAR_LANDER_QUIC_ENDPOINT=fra.lunar-lander.hellomoon.io:16888 \
KEYPAIR_PATH=~/.config/solana/id.json \
RPC_URL=https://api.mainnet-beta.solana.com \
cargo run --example send_transaction
```

The richer example:
- uses the Lunar Lander tip destination list
- randomly selects one destination on each run
- sends minimum tip threshold of `1_000_000` lamports

## Reconnect behavior

The client keeps the QUIC connection hot in two complementary layers:

- **`proactive_reconnect`** (default `true`): a background watchdog
  awaits `Connection::closed()` and re-handshakes as soon as the server
  closes (graceful shutdown, idle timeout, transport reset, …). The
  next `send_transaction` lands on the fresh connection without seeing
  a transient failure first. The watchdog uses a jittered exponential
  backoff bounded by `reconnect_max_backoff` so a fleet of clients
  doesn't herd the server on the way back up after a restart.
- **`auto_reconnect`** (default `true`): if a `send_transaction`
  observes a closed connection before the watchdog has finished
  reconnecting, the send transparently reconnects and retries once on
  the fresh connection. This closes the sub-second race window between
  close detection and the watchdog's reconnect.

Each flag is independent — disable `auto_reconnect` to opt out of
at-least-once resend semantics while keeping the connection hot, or
disable `proactive_reconnect` to keep the client passive and only
reconnect on demand.

Operators can poll `client.health() -> ConnectionHealth` for the
current state (`Healthy` / `Reconnecting` / `Disconnected`) and
`client.reconnects_total()` for cumulative reconnect count without
parsing tracing output.

## Notes

- Lunar Lander QUIC is tip-enforced.
- The client sends raw transaction bytes only.
- The client generates the client certificate in code from your API key.
- Lunar Lander QUIC is fire-and-forget and does not return a per-stream response body.
