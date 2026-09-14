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
- optionally send one serialized Solana transaction per bidi stream and read a compact admission response

## What it supports

- Lunar Lander QUIC submission
- in-code self-signed client certificate generation
- one connection reused across many sends
- response-capable bidi submits when you need admission status

## What it does not do

- build or sign transactions for you
- simulate or preflight transactions
- provide JSON-RPC wrappers
- submit HTTP batches or bundles

## Install

```toml
[dependencies]
lunar-lander-quic-client = "0.5.0"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

## Quick start

```rust
use lunar_lander_quic_client::LunarLanderQuicClient;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let api_key = std::env::var("LUNAR_LANDER_API_KEY")?;
    let client = LunarLanderQuicClient::connect(
        "lunar-lander.hellomoon.io:16888",
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
        "lunar-lander.hellomoon.io:16888",
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
- `send_transaction_with_response`: send a deliberately malformed payload over a bidi stream and assert the response

Run the richer example with:

```bash
LUNAR_LANDER_API_KEY=your-api-key \
LUNAR_LANDER_QUIC_ENDPOINT=lunar-lander.hellomoon.io:16888 \
KEYPAIR_PATH=~/.config/solana/id.json \
RPC_URL=https://api.mainnet-beta.solana.com \
cargo run --example send_transaction
```

The richer example:
- uses the Lunar Lander tip destination list
- randomly selects one destination on each run
- sends minimum tip threshold of `1_000_000` lamports

Run the response-capable smoke example with:

```bash
LUNAR_LANDER_API_KEY=your-api-key \
LUNAR_LANDER_QUIC_ENDPOINT=lunar-lander.hellomoon.io:16888 \
cargo run --example send_transaction_with_response
```

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

## Response-capable submits

`send_transaction` remains the unidirectional fire-and-forget path. Use
`send_transaction_with_response` when you need a compact admission response from
a bidi stream:

```rust
use lunar_lander_quic_client::{LunarLanderQuicClient, QuicSubmitCode};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let api_key = std::env::var("LUNAR_LANDER_API_KEY")?;
    let client = LunarLanderQuicClient::connect(
        "lunar-lander.hellomoon.io:16888",
        api_key,
    )
    .await?;

    let tx_bytes = create_signed_transaction_somewhere()?;
    let response = client.send_transaction_with_response(&tx_bytes).await?;

    match response.code {
        QuicSubmitCode::Accepted => println!("accepted"),
        QuicSubmitCode::InvalidPayload => println!("invalid payload: {:?}", response.message),
        QuicSubmitCode::TipRequired => println!("tip required: {:?}", response.message),
        QuicSubmitCode::RateLimited => println!("rate limited: {:?}", response.message),
        QuicSubmitCode::BlockedArbProgram => {
            println!("blocked arb program: {:?}", response.message)
        }
        QuicSubmitCode::Unavailable => println!("unavailable: {:?}", response.message),
        QuicSubmitCode::UnknownStatus(_) => println!("server returned {}", response.status),
    }

    Ok(())
}
```

## Notes

### Transaction versions and stream framing

Both submit methods accept serialized legacy/v0 transactions up to **1,232 bytes**
and v1 transactions up to **4,096 bytes**. V1 is identified by its first byte,
`0x81`. Oversized payloads return `ClientError::PayloadTooLarge` before opening a
stream. This is a size guard, not transaction decoding, signature verification,
or a guarantee that a server or cluster has activated v1.

`MAX_WIRE_TX_BYTES` is the largest supported size, not the limit for every
version. Use `MAX_LEGACY_V0_WIRE_TX_BYTES` and `MAX_V1_WIRE_TX_BYTES` when sizing
version-specific buffers. Transaction construction remains outside this crate;
the existing examples build legacy transactions.

Keep the entire signed transaction on **one stream**. QUIC segments it into UDP
datagrams and reassembles the ordered stream; do not split a large transaction
into multiple streams or add an HTTP batch length prefix. The client finishes
the request stream after writing all bytes. A successful uni submit only means
the local write completed; it does not confirm server admission or landing.
A successful bidi response confirms admission, not execution or confirmation.

For concurrent submissions, share one client (for example through `Arc`) and
call either submit method per transaction. These independent streams have no
cross-transaction ordering or atomicity guarantee. They are **not bundles**.
Ordered bundle submission and length-prefixed HTTP batches use separate HTTP
APIs and are not implemented by this QUIC-only client.

The offline tests exercise concurrent 4 KiB uni/bidi streams through a bounded
UDP fault injector that drops, reorders and duplicates datagrams, with a
1,232-byte datagram ceiling. They verify exact bytes, one delivery per stream,
response framing and rejection of oversized payloads before network submission.

- Lunar Lander QUIC is tip-enforced.
- The client sends raw transaction bytes only.
- The client generates the client certificate in code from your API key.
- `send_transaction` is fire-and-forget; `send_transaction_with_response` uses a bidi stream.
