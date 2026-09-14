//! Official Rust QUIC client for Hello Moon Lunar Lander.
//!
//! `lunar-lander-quic-client` is intentionally narrow:
//! - connect to a Lunar Lander QUIC endpoint
//! - generate the client certificate in code from your API key
//! - send one serialized Solana transaction payload per uni stream
//! - optionally send one serialized Solana transaction payload per bidi stream
//!   and read a compact admission response
//!
//! It does not perform simulation, preflight, or transaction construction.
//!
//! # What This Crate Does
//!
//! Use this crate when you already have serialized transaction bytes and want
//! to submit them over Lunar Lander's QUIC ingress path with a small, focused
//! client.
//!
//! The client:
//! - opens one QUIC connection and reuses it across many sends
//! - generates a self-signed client certificate in code from your API key
//! - writes each transaction payload to its own uni stream
//! - optionally writes transaction payloads to bidi streams and decodes compact
//!   response frames
//!
//! # What This Crate Does Not Do
//!
//! This crate intentionally does not:
//! - build or sign transactions
//! - wrap HTTP submission APIs
//! - provide JSON-RPC helpers
//! - simulate or preflight transactions
//!
//! # Example
//!
//! ```no_run
//! use lunar_lander_quic_client::LunarLanderQuicClient;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let api_key = std::env::var("LUNAR_LANDER_API_KEY")?;
//!     let client = LunarLanderQuicClient::connect(
//!         "lunar-lander.hellomoon.io:16888",
//!         api_key,
//!     )
//!     .await?;
//!
//!     let tx_bytes = create_signed_transaction_somewhere()?;
//!     client.send_transaction(&tx_bytes).await?;
//!     Ok(())
//! }
//!
//! fn create_signed_transaction_somewhere() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
//!     unimplemented!("build and serialize a signed Solana transaction")
//! }
//! ```
//!
//! # MEV Protection
//!
//! Enable MEV protection by setting `mev_protect: true` in [`ClientOptions`]:
//!
//! ```no_run
//! use lunar_lander_quic_client::{ClientOptions, LunarLanderQuicClient};
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let client = LunarLanderQuicClient::connect_with_options(
//!     "lunar-lander.hellomoon.io:16888",
//!     std::env::var("LUNAR_LANDER_API_KEY")?,
//!     ClientOptions {
//!         mev_protect: true,
//!         ..ClientOptions::default()
//!     },
//! )
//! .await?;
//! # Ok(())
//! # }
//! ```

use {
    quinn::{
        ClientConfig as QuinnClientConfig, ConnectError, Connection, ConnectionError, Endpoint,
        IdleTimeout, TransportConfig, VarInt, WriteError, crypto::rustls::QuicClientConfig,
    },
    rand::Rng,
    rcgen::{CertificateParams, CustomExtension, DistinguishedName, DnType, KeyPair},
    rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    rustls::{
        DigitallySignedStruct, SignatureScheme,
        client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        pki_types::{ServerName, UnixTime},
    },
    std::{
        fmt,
        net::{SocketAddr, ToSocketAddrs},
        sync::{
            Arc,
            atomic::{AtomicU8, AtomicU64, Ordering},
        },
        time::Duration,
    },
    thiserror::Error,
    tokio::{sync::Mutex, task::JoinHandle, time::timeout},
    tracing::{info, warn},
};

/// ALPN identifier used by the Lunar Lander QUIC endpoint.
pub const LUNAR_LANDER_TPU_PROTOCOL_ID: &[u8] = b"lunar-lander-tpu";

/// ITU-T experimental OID arc (2.999) for Lunar Lander QUIC extensions.
///
/// - `2.999.1` — Lunar Lander QUIC feature extensions
/// - `2.999.1.1` — MEV Protect
const OID_MEV_PROTECT: &[u64] = &[2, 999, 1, 1];
/// Default UDP port for Lunar Lander QUIC ingress.
pub const DEFAULT_PORT: u16 = 16_888;
/// Maximum serialized legacy or v0 transaction size.
pub const MAX_LEGACY_V0_WIRE_TX_BYTES: usize = 1232;
/// Maximum serialized v1 transaction size (SIMD-0385).
pub const MAX_V1_WIRE_TX_BYTES: usize = 4096;
/// Largest supported transaction size. Legacy/v0 still have a 1,232-byte limit.
pub const MAX_WIRE_TX_BYTES: usize = MAX_V1_WIRE_TX_BYTES;
const V1_TRANSACTION_PREFIX: u8 = 0x81;
/// Version byte used by Lunar Lander's compact QUIC submit response frame.
pub const QUIC_SUBMIT_RESPONSE_VERSION: u8 = 1;
/// Header length for the compact QUIC submit response frame.
pub const QUIC_SUBMIT_RESPONSE_HEADER_LEN: usize = 6;
/// Maximum response body size this client will accept from a bidi submit.
pub const MAX_QUIC_SUBMIT_RESPONSE_BODY_BYTES: usize = 1024;
/// Maximum full response frame size this client will read from a bidi submit.
pub const MAX_QUIC_SUBMIT_RESPONSE_FRAME_BYTES: usize =
    QUIC_SUBMIT_RESPONSE_HEADER_LEN + MAX_QUIC_SUBMIT_RESPONSE_BODY_BYTES;

/// Connection-level tuning for [`LunarLanderQuicClient`].
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ClientOptions {
    /// Maximum time allowed for the initial QUIC connect to complete.
    pub connect_timeout: Duration,
    /// Keepalive interval used on the QUIC connection. Must be strictly
    /// less than [`Self::idle_timeout`]; the constructor returns
    /// [`ClientError::InvalidTransport`] otherwise. The 2-second default
    /// is tight enough for the watchdog to detect silent drops within
    /// ~6 seconds, while leaving room for two missed pings before the
    /// connection is declared idle.
    pub keepalive_interval: Duration,
    /// Idle timeout advertised to Quinn for this client connection.
    /// Paired with the 2-second keepalive above, the 6-second default
    /// holds the 3:1 ratio that tolerates two dropped pings before
    /// Quinn declares the connection idle and the watchdog reconnects.
    /// A four-second contiguous-loss budget absorbs routine network
    /// jitter on cross-region paths and brief client-side scheduler
    /// stalls without flapping. A 1s/2s configuration would collapse
    /// the slack to a single missed ping, so a single transient blip
    /// or Lunar Lander ingress restart would force a reconnect and
    /// muddy [`LunarLanderQuicClient::reconnects_total`] as a
    /// real-outage signal.
    pub idle_timeout: Duration,
    /// When `true`, embeds a custom X.509 certificate extension that signals
    /// the server to enable MEV protection for transactions sent over this
    /// connection. The extension uses the ITU-T experimental OID arc
    /// `2.999.1.1` and is marked non-critical so older servers that do not
    /// understand it will simply ignore it.
    pub mev_protect: bool,
    /// When `true` (the default), [`LunarLanderQuicClient::send_transaction`]
    /// will transparently reconnect once if the current QUIC connection has
    /// been closed (by the server, an idle timeout, a transport reset, …)
    /// and retry the send on the fresh connection. Set to `false` to opt out
    /// and receive the original error from the first attempt.
    ///
    /// This is the at-least-once resend layer; it is independent of
    /// [`Self::proactive_reconnect`], which controls whether the connection
    /// is kept hot in the background.
    pub auto_reconnect: bool,
    /// Maximum time allowed for the response-capable bidi submit path to open
    /// a stream, write the transaction payload, finish the request side, and
    /// read the compact response frame.
    pub response_timeout: Duration,
    /// When `true` (the default), the client runs a background watchdog
    /// task that awaits [`Connection::closed`] and re-handshakes
    /// proactively. With this enabled, the next send after a server
    /// shutdown lands on a fresh connection without the caller seeing a
    /// transient failure first. Disable to keep the client passive: it
    /// will only reconnect on demand from
    /// [`LunarLanderQuicClient::send_transaction`] (when
    /// [`Self::auto_reconnect`] is also enabled) or an explicit
    /// [`LunarLanderQuicClient::reconnect`].
    pub proactive_reconnect: bool,
    /// Initial delay between watchdog reconnect attempts after the first
    /// failure. The watchdog doubles the wait on each subsequent failure,
    /// capped at [`Self::reconnect_max_backoff`], with full jitter
    /// applied to spread reconnects across clients after a server
    /// restart. Ignored when [`Self::proactive_reconnect`] is `false`.
    pub reconnect_initial_backoff: Duration,
    /// Upper bound on the watchdog reconnect delay. The exponential
    /// growth from [`Self::reconnect_initial_backoff`] is clamped here.
    /// Ignored when [`Self::proactive_reconnect`] is `false`.
    pub reconnect_max_backoff: Duration,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(5),
            keepalive_interval: Duration::from_secs(2),
            idle_timeout: Duration::from_secs(6),
            mev_protect: false,
            auto_reconnect: true,
            response_timeout: Duration::from_secs(5),
            proactive_reconnect: true,
            reconnect_initial_backoff: Duration::from_millis(250),
            reconnect_max_backoff: Duration::from_secs(30),
        }
    }
}

/// HTTP-like status category for a compact QUIC submit response.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum QuicSubmitCode {
    /// Request was accepted by the Lunar Lander send path.
    Accepted,
    /// Payload could not be read, decoded, or accepted as a transaction.
    InvalidPayload,
    /// Tip enforcement rejected the transaction.
    TipRequired,
    /// Global or key rate limiting rejected the request.
    RateLimited,
    /// Key policy rejected the transaction.
    BlockedArbProgram,
    /// Ingress is shutting down or otherwise unavailable.
    Unavailable,
    /// Response status is not known by this client version.
    UnknownStatus(u16),
}

impl QuicSubmitCode {
    fn from_status_and_body(status: u16, body: &str) -> Self {
        let body = body.to_ascii_lowercase();
        match status {
            200 => Self::Accepted,
            400 if body.contains("tip required") => Self::TipRequired,
            400 if body.contains("blocked arb program") => Self::BlockedArbProgram,
            400 => Self::InvalidPayload,
            403 => Self::BlockedArbProgram,
            429 => Self::RateLimited,
            503 => Self::Unavailable,
            _ => Self::UnknownStatus(status),
        }
    }
}

impl fmt::Display for QuicSubmitCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Accepted => f.write_str("accepted"),
            Self::InvalidPayload => f.write_str("invalid_payload"),
            Self::TipRequired => f.write_str("tip_required"),
            Self::RateLimited => f.write_str("rate_limited"),
            Self::BlockedArbProgram => f.write_str("blocked_arb_program"),
            Self::Unavailable => f.write_str("unavailable"),
            Self::UnknownStatus(status) => write!(f, "unknown_status_{status}"),
        }
    }
}

/// Typed response returned by [`LunarLanderQuicClient::send_transaction_with_response`].
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct QuicSubmitResponse {
    /// HTTP-like status from the compact response frame.
    pub status: u16,
    /// Client-friendly status category derived from `status` and the response
    /// body.
    pub code: QuicSubmitCode,
    /// Transaction signature returned on successful submissions, when the
    /// server includes one.
    pub signature: Option<String>,
    /// Short stable reason returned on rejected submissions, when the server
    /// includes one.
    pub message: Option<String>,
}

impl QuicSubmitResponse {
    /// Builds an accepted response, useful for tests and server-side fixtures.
    pub fn accepted(signature: impl Into<Option<String>>) -> Self {
        Self {
            status: 200,
            code: QuicSubmitCode::Accepted,
            signature: signature.into(),
            message: None,
        }
    }

    /// Builds an error response, useful for tests and server-side fixtures.
    pub fn error(status: u16, message: impl Into<String>) -> Self {
        let message = message.into();
        Self {
            status,
            code: QuicSubmitCode::from_status_and_body(status, &message),
            signature: None,
            message: Some(message),
        }
    }

    /// Decodes the compact Lunar Lander QUIC submit response frame.
    ///
    /// Frame layout:
    ///
    /// ```text
    /// version u8 | flags u8 | status u16 BE | body_len u16 BE | body bytes
    /// ```
    pub fn decode_frame(frame: &[u8]) -> std::result::Result<Self, QuicSubmitResponseFrameError> {
        if frame.len() < QUIC_SUBMIT_RESPONSE_HEADER_LEN {
            return Err(QuicSubmitResponseFrameError::TooShort { len: frame.len() });
        }

        let version = frame[0];
        if version != QUIC_SUBMIT_RESPONSE_VERSION {
            return Err(QuicSubmitResponseFrameError::UnsupportedVersion { version });
        }

        let flags = frame[1];
        if flags != 0 {
            return Err(QuicSubmitResponseFrameError::UnsupportedFlags { flags });
        }

        let status = u16::from_be_bytes([frame[2], frame[3]]);
        let body_len = u16::from_be_bytes([frame[4], frame[5]]) as usize;
        if body_len > MAX_QUIC_SUBMIT_RESPONSE_BODY_BYTES {
            return Err(QuicSubmitResponseFrameError::BodyTooLong {
                body_len,
                max: MAX_QUIC_SUBMIT_RESPONSE_BODY_BYTES,
            });
        }

        let actual_body_len = frame.len() - QUIC_SUBMIT_RESPONSE_HEADER_LEN;
        if body_len != actual_body_len {
            return Err(QuicSubmitResponseFrameError::BodyLengthMismatch {
                declared: body_len,
                actual: actual_body_len,
            });
        }

        let body = std::str::from_utf8(&frame[QUIC_SUBMIT_RESPONSE_HEADER_LEN..])?.to_owned();
        let code = QuicSubmitCode::from_status_and_body(status, &body);
        let (signature, message) = if status == 200 {
            (non_empty_string(body), None)
        } else {
            (None, non_empty_string(body))
        };

        Ok(Self {
            status,
            code,
            signature,
            message,
        })
    }

    /// Encodes this response as the compact Lunar Lander QUIC submit response
    /// frame.
    pub fn encode_frame(&self) -> std::result::Result<Vec<u8>, QuicSubmitResponseFrameError> {
        let body = if self.status == 200 {
            self.signature.as_deref().unwrap_or("")
        } else {
            self.message.as_deref().unwrap_or("")
        };
        encode_submit_response_frame(self.status, body.as_bytes())
    }

    /// Returns `true` when the response status is exactly `200`.
    pub fn is_accepted(&self) -> bool {
        self.status == 200
    }
}

/// Errors returned while decoding or encoding compact QUIC submit response
/// frames.
#[derive(Debug, Error)]
pub enum QuicSubmitResponseFrameError {
    #[error("frame is too short: {len} bytes")]
    TooShort { len: usize },
    #[error("unsupported response frame version {version}")]
    UnsupportedVersion { version: u8 },
    #[error("unsupported response frame flags 0x{flags:02x}")]
    UnsupportedFlags { flags: u8 },
    #[error("response body length {body_len} exceeds maximum {max}")]
    BodyTooLong { body_len: usize, max: usize },
    #[error("declared response body length {declared} does not match actual {actual}")]
    BodyLengthMismatch { declared: usize, actual: usize },
    #[error("response body is not valid UTF-8: {0}")]
    BodyUtf8(#[from] std::str::Utf8Error),
}

/// Reported reconnect state for a [`LunarLanderQuicClient`].
///
/// Returned by [`LunarLanderQuicClient::health`]. Operators can poll this
/// instead of inferring state from logs and the
/// [`LunarLanderQuicClient::reconnects_total`] counter.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ConnectionHealth {
    /// The current QUIC connection is open and ready to accept sends.
    Healthy,
    /// The connection has been observed closed and a reconnect attempt is
    /// in flight (either from the watchdog, the send-path retry, or an
    /// explicit [`LunarLanderQuicClient::reconnect`] call).
    Reconnecting,
    /// The connection is closed and no reconnect is being attempted. This
    /// is reachable when [`ClientOptions::proactive_reconnect`] is
    /// disabled and either reconnect attempts have failed or the
    /// send-path retry is also disabled.
    Disconnected,
}

const HEALTH_HEALTHY: u8 = 0;
const HEALTH_RECONNECTING: u8 = 1;
const HEALTH_DISCONNECTED: u8 = 2;

/// Error type returned by the client library.
#[derive(Debug, Error)]
pub enum ClientError {
    #[error("transaction payload is {len} bytes; maximum for this wire version is {max}")]
    PayloadTooLarge { len: usize, max: usize },
    #[error("api key must not be empty")]
    EmptyApiKey,
    #[error(
        "keepalive_interval ({keepalive:?}) must be strictly less than idle_timeout ({idle:?}); \
         otherwise the QUIC connection idles out before the next keepalive can refresh it"
    )]
    InvalidTransport { keepalive: Duration, idle: Duration },
    #[error("endpoint `{0}` must be host:port")]
    InvalidEndpoint(String),
    #[error("failed to resolve endpoint `{endpoint}`: {source}")]
    ResolveEndpoint {
        endpoint: String,
        #[source]
        source: std::io::Error,
    },
    #[error("endpoint `{0}` resolved to no socket addresses")]
    NoResolvedAddress(String),
    #[error("failed to generate client certificate: {0}")]
    ClientCertificate(String),
    #[error("failed to build QUIC client config: {0}")]
    ClientConfig(String),
    #[error("failed to bind local QUIC client endpoint: {0}")]
    ClientBind(#[source] std::io::Error),
    #[error("failed to start QUIC connect: {0}")]
    ConnectStart(#[from] ConnectError),
    #[error("timed out connecting after {0:?}")]
    ConnectTimeout(Duration),
    #[error("failed to establish QUIC connection: {0}")]
    Connect(String),
    #[error("failed to open uni stream: {0}")]
    OpenUni(String),
    #[error("failed to open bidi stream: {0}")]
    OpenBi(String),
    #[error("failed to write transaction payload: {0}")]
    Write(#[from] WriteError),
    #[error("failed to finish uni stream: {0}")]
    Finish(String),
    #[error("failed to finish bidi request stream: {0}")]
    FinishBi(String),
    #[error("timed out waiting for QUIC submit response after {0:?}")]
    ResponseTimeout(Duration),
    #[error("failed to read QUIC submit response: {0}")]
    ReadResponse(String),
    #[error("invalid QUIC submit response frame: {0}")]
    InvalidResponseFrame(#[from] QuicSubmitResponseFrameError),
}

impl ClientError {
    fn retry_safe_for_bidi_response(&self) -> bool {
        matches!(self, Self::OpenBi(_))
    }
}

pub type Result<T> = std::result::Result<T, ClientError>;

/// Connected Lunar Lander QUIC client.
///
/// Each instance owns one QUIC connection and reuses it across many transaction
/// sends. Transactions are written as fire-and-forget unidirectional streams.
///
/// By default (see [`ClientOptions::proactive_reconnect`]) the client runs a
/// background watchdog that watches the QUIC connection for closure (graceful
/// server shutdown, idle timeout, transport reset, …) and proactively
/// re-handshakes so the next [`LunarLanderQuicClient::send_transaction`] call
/// lands on a fresh connection. With [`ClientOptions::auto_reconnect`] also
/// enabled, [`LunarLanderQuicClient::send_transaction`] retries on the error
/// path as a race-closer if a send slips in before the watchdog has finished
/// reconnecting.
#[derive(Debug)]
pub struct LunarLanderQuicClient {
    inner: Arc<ClientInner>,
    watchdog: Option<JoinHandle<()>>,
}

#[derive(Debug)]
struct ClientInner {
    endpoint_label: String,
    server_addr: SocketAddr,
    server_name: String,
    options: ClientOptions,
    endpoint: Endpoint,
    // Guarded so `send_transaction(&self, …)` and the watchdog task can
    // replace the handle when a reconnect happens. Quinn's `Connection` is
    // a cheap Arc-handle, so we clone it out from under the lock before
    // doing I/O — concurrent sends don't serialize on this lock, only the
    // (rare) reconnect path does.
    connection: Mutex<Connection>,
    // Incremented every time a reconnect succeeds, regardless of whether the
    // watchdog or a failing send triggered it. Exposed via
    // [`LunarLanderQuicClient::reconnects_total`] so callers can monitor
    // connection churn without needing structured-log scraping.
    reconnects_total: AtomicU64,
    // One of `HEALTH_*`. Drives [`LunarLanderQuicClient::health`]. Updated
    // by every path that opens, observes-as-closed, or replaces the
    // connection: initial connect, watchdog, send-path retry, and manual
    // reconnect.
    health: AtomicU8,
}

impl LunarLanderQuicClient {
    /// Connects to a Lunar Lander QUIC endpoint with default client options.
    ///
    /// `endpoint` must be `host:port`, for example
    /// `lunar-lander.hellomoon.io:16888`.
    pub async fn connect(endpoint: impl Into<String>, api_key: impl Into<String>) -> Result<Self> {
        Self::connect_with_options(endpoint, api_key, ClientOptions::default()).await
    }

    /// Connects to a Lunar Lander QUIC endpoint with explicit client options.
    ///
    /// The client certificate is generated in code from the provided API key
    /// and sent as part of the QUIC/TLS handshake.
    pub async fn connect_with_options(
        endpoint: impl Into<String>,
        api_key: impl Into<String>,
        options: ClientOptions,
    ) -> Result<Self> {
        install_rustls_provider();

        let endpoint_label = endpoint.into();
        let api_key = api_key.into();
        if api_key.trim().is_empty() {
            return Err(ClientError::EmptyApiKey);
        }

        let (server_addr, server_name) = resolve_endpoint(&endpoint_label)?;

        let endpoint_socket = Endpoint::client("0.0.0.0:0".parse().expect("valid client bind"))
            .map_err(ClientError::ClientBind)?;
        let client_config = build_client_config(&api_key, &options)?;
        let mut endpoint = endpoint_socket;
        endpoint.set_default_client_config(client_config);

        let connection = connect_inner(
            &endpoint,
            server_addr,
            &server_name,
            options.connect_timeout,
        )
        .await?;

        let proactive_reconnect = options.proactive_reconnect;
        let inner = Arc::new(ClientInner {
            endpoint_label,
            server_addr,
            server_name,
            options,
            endpoint,
            connection: Mutex::new(connection),
            reconnects_total: AtomicU64::new(0),
            health: AtomicU8::new(HEALTH_HEALTHY),
        });

        let watchdog = if proactive_reconnect {
            Some(tokio::spawn(watchdog_loop(Arc::clone(&inner))))
        } else {
            None
        };

        Ok(Self { inner, watchdog })
    }

    /// Returns the endpoint string originally passed to [`Self::connect`] or
    /// [`Self::connect_with_options`].
    pub fn endpoint(&self) -> &str {
        &self.inner.endpoint_label
    }

    /// Returns the resolved remote socket address currently used by the client.
    pub fn remote_addr(&self) -> SocketAddr {
        self.inner.server_addr
    }

    /// Returns the TLS server name used for the connection handshake.
    pub fn server_name(&self) -> &str {
        &self.inner.server_name
    }

    /// Returns the total number of successful reconnects performed since
    /// this client was constructed, counting watchdog, send-path, and
    /// manual [`Self::reconnect`] paths.
    pub fn reconnects_total(&self) -> u64 {
        self.inner.reconnects_total.load(Ordering::Relaxed)
    }

    /// Returns the client's current reconnect state. See
    /// [`ConnectionHealth`] for the meaning of each variant.
    pub fn health(&self) -> ConnectionHealth {
        match self.inner.health.load(Ordering::Acquire) {
            HEALTH_HEALTHY => ConnectionHealth::Healthy,
            HEALTH_RECONNECTING => ConnectionHealth::Reconnecting,
            _ => ConnectionHealth::Disconnected,
        }
    }

    /// Tears down the current QUIC connection and establishes a new one.
    ///
    /// Takes `&mut self` for backward compatibility. Callers using
    /// [`Self::send_transaction`] typically don't need this: with the
    /// default [`ClientOptions::proactive_reconnect`] /
    /// [`ClientOptions::auto_reconnect`] settings the watchdog and
    /// send-path retry handle reconnects transparently.
    ///
    /// Closes the existing handle before re-handshaking. If the
    /// background watchdog is running, this also wakes it from
    /// [`Connection::closed`] on the old handle so it re-arms on the new
    /// one — without this close, a manual reconnect would leave the
    /// watchdog parked on a connection no caller is using.
    pub async fn reconnect(&mut self) -> Result<()> {
        // Hold the connection mutex across the close + connect. The
        // watchdog observes `closed()` on the old handle (woken by our
        // explicit close below), waits on the mutex, sees the stored
        // connection has been replaced, and re-arms on the fresh handle
        // without producing its own redundant handshake.
        let mut guard = self.inner.connection.lock().await;
        let old = guard.clone();
        old.close(VarInt::from_u32(0), b"manual_reconnect");

        self.inner
            .health
            .store(HEALTH_RECONNECTING, Ordering::Release);
        let fresh = match connect_inner(
            &self.inner.endpoint,
            self.inner.server_addr,
            &self.inner.server_name,
            self.inner.options.connect_timeout,
        )
        .await
        {
            Ok(connection) => connection,
            Err(error) => {
                self.inner
                    .health
                    .store(HEALTH_DISCONNECTED, Ordering::Release);
                return Err(error);
            }
        };

        *guard = fresh;
        self.inner.reconnects_total.fetch_add(1, Ordering::Relaxed);
        self.inner.health.store(HEALTH_HEALTHY, Ordering::Release);
        Ok(())
    }

    /// Sends one serialized transaction payload over a QUIC uni stream.
    ///
    /// The payload should already be fully prepared by the caller. This method
    /// only opens a stream, writes the bytes, and finishes the stream.
    ///
    /// If the current QUIC connection has been closed (server restart, idle
    /// timeout, transport reset, …) and [`ClientOptions::auto_reconnect`] is
    /// enabled (the default), this method transparently re-handshakes once
    /// and retries the send on the fresh connection. This retry also closes
    /// the race window where a send arrives before the background watchdog
    /// has finished replacing the dead connection handle.
    pub async fn send_transaction(&self, payload: &[u8]) -> Result<()> {
        validate_payload_size(payload)?;
        let connection = { self.inner.connection.lock().await.clone() };
        match send_on(&connection, payload).await {
            Ok(()) => Ok(()),
            Err(error) => {
                let Some(close_reason) = connection.close_reason() else {
                    // Connection is still alive — this is a per-stream or per-write
                    // error the caller should see verbatim.
                    return Err(error);
                };
                if !self.inner.options.auto_reconnect {
                    // Don't mask the close from observers polling `health()`;
                    // this caller is opting out of the resend, but the
                    // connection is genuinely dead.
                    if !self.inner.options.proactive_reconnect {
                        self.inner
                            .health
                            .store(HEALTH_DISCONNECTED, Ordering::Release);
                    }
                    return Err(error);
                }
                let new_connection = self
                    .inner
                    .reconnect_if_same(&connection, &close_reason)
                    .await?;
                send_on(&new_connection, payload).await
            }
        }
    }

    /// Sends one serialized transaction payload over a QUIC bidi stream and
    /// waits for the compact submit response frame.
    ///
    /// The request side is written immediately and finished before the client
    /// waits for the response, avoiding the QUIC bidi deadlock where a peer
    /// waits to read before it has sent stream data. This method is separate
    /// from [`Self::send_transaction`], which remains the uni-stream
    /// fire-and-forget path.
    ///
    /// If the current QUIC connection has been closed before a bidi stream can
    /// be opened and [`ClientOptions::auto_reconnect`] is enabled, this method
    /// reconnects once and retries. It does not retry after request bytes may
    /// have been written, because that could duplicate a submission.
    pub async fn send_transaction_with_response(
        &self,
        payload: &[u8],
    ) -> Result<QuicSubmitResponse> {
        validate_payload_size(payload)?;
        let connection = { self.inner.connection.lock().await.clone() };
        match send_with_response_on(&connection, payload, self.inner.options.response_timeout).await
        {
            Ok(response) => Ok(response),
            Err(error) => {
                if !self.inner.options.auto_reconnect || !error.retry_safe_for_bidi_response() {
                    return Err(error);
                }
                let Some(close_reason) = connection.close_reason() else {
                    return Err(error);
                };
                let new_connection = self
                    .inner
                    .reconnect_if_same(&connection, &close_reason)
                    .await?;
                send_with_response_on(
                    &new_connection,
                    payload,
                    self.inner.options.response_timeout,
                )
                .await
            }
        }
    }

    /// Closes the QUIC connection and waits for the endpoint to go idle.
    pub async fn close(mut self) {
        if let Some(watchdog) = self.watchdog.take() {
            watchdog.abort();
        }
        {
            let connection = self.inner.connection.lock().await;
            connection.close(0u32.into(), b"client_closed");
        }
        self.inner.endpoint.close(0u32.into(), b"client_closed");
        let _ = self.inner.endpoint.wait_idle().await;
    }
}

impl Drop for LunarLanderQuicClient {
    fn drop(&mut self) {
        if let Some(watchdog) = self.watchdog.take() {
            watchdog.abort();
        }
    }
}

impl ClientInner {
    /// Reconnects only if the stored connection handle is still the one the
    /// caller observed as dead. If another task (watchdog or another send)
    /// already replaced it, we reuse that fresh handle instead of creating
    /// yet another connection.
    async fn reconnect_if_same(
        self: &Arc<Self>,
        dead: &Connection,
        close_reason: &ConnectionError,
    ) -> Result<Connection> {
        let mut guard = self.connection.lock().await;
        if guard.stable_id() == dead.stable_id() {
            warn!(
                server = %self.endpoint_label,
                close_reason = %close_reason,
                "lunar-lander QUIC connection closed; reconnecting"
            );
            self.health.store(HEALTH_RECONNECTING, Ordering::Release);
            let fresh = match connect_inner(
                &self.endpoint,
                self.server_addr,
                &self.server_name,
                self.options.connect_timeout,
            )
            .await
            {
                Ok(connection) => connection,
                Err(error) => {
                    // Send-path retry doesn't loop on failure; surface the
                    // error and let the watchdog (if running) keep trying.
                    if !self.options.proactive_reconnect {
                        self.health.store(HEALTH_DISCONNECTED, Ordering::Release);
                    }
                    return Err(error);
                }
            };
            info!(
                server = %self.endpoint_label,
                "lunar-lander QUIC connection re-established"
            );
            *guard = fresh.clone();
            self.reconnects_total.fetch_add(1, Ordering::Relaxed);
            self.health.store(HEALTH_HEALTHY, Ordering::Release);
            Ok(fresh)
        } else {
            Ok(guard.clone())
        }
    }
}

/// Returns a duration uniformly distributed in `[0, base)` (full jitter).
/// Mixing in jitter on every reconnect attempt prevents a fleet of clients
/// from synchronously re-handshaking after a server restart.
fn jittered(base: Duration) -> Duration {
    let nanos = base.as_nanos();
    if nanos == 0 {
        return Duration::ZERO;
    }
    // Cap at u64; reconnect delays are seconds-scale, so this is safe.
    let bound = u64::try_from(nanos).unwrap_or(u64::MAX);
    let pick = rand::rng().random_range(0..bound);
    Duration::from_nanos(pick)
}

/// Background task: watch the current connection for closure, then
/// re-handshake and swap in a fresh handle. Retries on failure with a
/// jittered exponential backoff bounded by
/// [`ClientOptions::reconnect_max_backoff`], so a server outage doesn't
/// leave the client permanently stuck once the server returns and a
/// fleet of clients doesn't herd the server on the way back up.
async fn watchdog_loop(inner: Arc<ClientInner>) {
    loop {
        let connection = { inner.connection.lock().await.clone() };
        let close_reason = connection.closed().await;
        warn!(
            server = %inner.endpoint_label,
            close_reason = %close_reason,
            "lunar-lander QUIC watchdog observed connection close; reconnecting"
        );
        inner.health.store(HEALTH_RECONNECTING, Ordering::Release);

        let mut next_backoff = inner.options.reconnect_initial_backoff;
        loop {
            // If a concurrent path (manual reconnect or send-path retry)
            // already replaced the dead handle, skip the connect attempt
            // entirely and re-arm on the installed connection.
            {
                let guard = inner.connection.lock().await;
                if guard.stable_id() != connection.stable_id() {
                    inner.health.store(HEALTH_HEALTHY, Ordering::Release);
                    break;
                }
            }

            match connect_inner(
                &inner.endpoint,
                inner.server_addr,
                &inner.server_name,
                inner.options.connect_timeout,
            )
            .await
            {
                Ok(fresh) => {
                    let mut guard = inner.connection.lock().await;
                    if guard.stable_id() == connection.stable_id() {
                        *guard = fresh;
                        inner.reconnects_total.fetch_add(1, Ordering::Relaxed);
                        info!(
                            server = %inner.endpoint_label,
                            "lunar-lander QUIC watchdog re-established connection"
                        );
                    }
                    // If a concurrent send replaced the dead handle first, drop
                    // our newly-built connection; next iteration picks up the
                    // handle that send installed.
                    inner.health.store(HEALTH_HEALTHY, Ordering::Release);
                    break;
                }
                Err(error) => {
                    let sleep_for = jittered(next_backoff);
                    warn!(
                        server = %inner.endpoint_label,
                        error = %error,
                        backoff_ms = sleep_for.as_millis() as u64,
                        "lunar-lander QUIC watchdog reconnect attempt failed; retrying"
                    );
                    tokio::time::sleep(sleep_for).await;
                    next_backoff = (next_backoff * 2).min(inner.options.reconnect_max_backoff);
                }
            }
        }
    }
}

fn validate_payload_size(payload: &[u8]) -> Result<()> {
    // V1's discriminator is at byte zero. Legacy/v0 start with a compact
    // signature count. Full decoding and policy validation belong to ingress.
    let max = if payload.first() == Some(&V1_TRANSACTION_PREFIX) {
        MAX_V1_WIRE_TX_BYTES
    } else {
        MAX_LEGACY_V0_WIRE_TX_BYTES
    };
    if payload.len() > max {
        return Err(ClientError::PayloadTooLarge {
            len: payload.len(),
            max,
        });
    }
    Ok(())
}

async fn send_on(connection: &Connection, payload: &[u8]) -> Result<()> {
    let mut stream = connection
        .open_uni()
        .await
        .map_err(|error| ClientError::OpenUni(error.to_string()))?;
    stream.write_all(payload).await?;
    stream
        .finish()
        .map_err(|error| ClientError::Finish(error.to_string()))?;
    Ok(())
}

async fn send_with_response_on(
    connection: &Connection,
    payload: &[u8],
    response_timeout: Duration,
) -> Result<QuicSubmitResponse> {
    timeout(
        response_timeout,
        send_with_response_on_inner(connection, payload),
    )
    .await
    .map_err(|_| ClientError::ResponseTimeout(response_timeout))?
}

async fn send_with_response_on_inner(
    connection: &Connection,
    payload: &[u8],
) -> Result<QuicSubmitResponse> {
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(|error| ClientError::OpenBi(error.to_string()))?;
    send.write_all(payload).await?;
    send.finish()
        .map_err(|error| ClientError::FinishBi(error.to_string()))?;

    let frame = recv
        .read_to_end(MAX_QUIC_SUBMIT_RESPONSE_FRAME_BYTES)
        .await
        .map_err(|error| ClientError::ReadResponse(error.to_string()))?;
    Ok(QuicSubmitResponse::decode_frame(&frame)?)
}

fn encode_submit_response_frame(
    status: u16,
    body: &[u8],
) -> std::result::Result<Vec<u8>, QuicSubmitResponseFrameError> {
    if body.len() > MAX_QUIC_SUBMIT_RESPONSE_BODY_BYTES {
        return Err(QuicSubmitResponseFrameError::BodyTooLong {
            body_len: body.len(),
            max: MAX_QUIC_SUBMIT_RESPONSE_BODY_BYTES,
        });
    }

    let body_len = u16::try_from(body.len()).expect("max response body size fits in u16");
    let mut frame = Vec::with_capacity(QUIC_SUBMIT_RESPONSE_HEADER_LEN + body.len());
    frame.push(QUIC_SUBMIT_RESPONSE_VERSION);
    frame.push(0);
    frame.extend_from_slice(&status.to_be_bytes());
    frame.extend_from_slice(&body_len.to_be_bytes());
    frame.extend_from_slice(body);
    Ok(frame)
}

fn non_empty_string(value: String) -> Option<String> {
    if value.is_empty() { None } else { Some(value) }
}

fn install_rustls_provider() {
    if rustls::crypto::CryptoProvider::get_default().is_some() {
        return;
    }

    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

fn build_client_config(api_key: &str, options: &ClientOptions) -> Result<QuinnClientConfig> {
    // Quinn enforces nothing about the relationship between keepalive and
    // idle timeout, but if keepalive >= idle then the connection idles out
    // between pings and the watchdog flaps it. Catch the misconfiguration
    // at connect time rather than at the first silent drop.
    if options.keepalive_interval >= options.idle_timeout {
        return Err(ClientError::InvalidTransport {
            keepalive: options.keepalive_interval,
            idle: options.idle_timeout,
        });
    }

    let key_pair =
        KeyPair::generate().map_err(|error| ClientError::ClientCertificate(error.to_string()))?;
    let mut params = CertificateParams::new(Vec::new())
        .map_err(|error| ClientError::ClientCertificate(error.to_string()))?;
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, api_key);
    params.distinguished_name = distinguished_name;

    if options.mev_protect {
        // DER-encoded BOOLEAN TRUE (tag 0x01, length 0x01, value 0xFF).
        let ext = CustomExtension::from_oid_content(OID_MEV_PROTECT, vec![0x01, 0x01, 0xFF]);
        params.custom_extensions.push(ext);
    }

    let certificate = params
        .self_signed(&key_pair)
        .map_err(|error| ClientError::ClientCertificate(error.to_string()))?;

    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
    let no_verifier = Arc::new(NoServerCertificateVerification::new());
    let mut client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(no_verifier)
        .with_client_auth_cert(
            vec![CertificateDer::from(certificate.der().to_vec())],
            private_key,
        )
        .map_err(|error| ClientError::ClientConfig(error.to_string()))?;
    client_crypto.alpn_protocols = vec![LUNAR_LANDER_TPU_PROTOCOL_ID.to_vec()];

    let mut transport = TransportConfig::default();
    transport.keep_alive_interval(Some(options.keepalive_interval));
    transport.max_idle_timeout(Some(
        IdleTimeout::try_from(options.idle_timeout)
            .map_err(|error| ClientError::ClientConfig(error.to_string()))?,
    ));

    let mut client_config = QuinnClientConfig::new(Arc::new(
        QuicClientConfig::try_from(client_crypto)
            .map_err(|error| ClientError::ClientConfig(error.to_string()))?,
    ));
    client_config.transport_config(Arc::new(transport));
    Ok(client_config)
}

#[derive(Debug)]
struct NoServerCertificateVerification(Arc<rustls::crypto::CryptoProvider>);

impl NoServerCertificateVerification {
    fn new() -> Self {
        let provider = rustls::crypto::CryptoProvider::get_default()
            .expect("rustls crypto provider should be installed")
            .clone();
        Self(provider)
    }
}

impl ServerCertVerifier for NoServerCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

async fn connect_inner(
    endpoint: &Endpoint,
    server_addr: SocketAddr,
    server_name: &str,
    connect_timeout: Duration,
) -> Result<Connection> {
    let connecting = endpoint.connect(server_addr, server_name)?;
    let connection = timeout(connect_timeout, connecting)
        .await
        .map_err(|_| ClientError::ConnectTimeout(connect_timeout))?
        .map_err(|error: ConnectionError| ClientError::Connect(error.to_string()))?;
    Ok(connection)
}

fn resolve_endpoint(endpoint: &str) -> Result<(SocketAddr, String)> {
    let endpoint_host = host_from_endpoint(endpoint)?;
    let server_addr = endpoint
        .to_socket_addrs()
        .map_err(|source| ClientError::ResolveEndpoint {
            endpoint: endpoint.to_string(),
            source,
        })?
        .next()
        .ok_or_else(|| ClientError::NoResolvedAddress(endpoint.to_string()))?;
    Ok((server_addr, endpoint_host))
}

fn host_from_endpoint(endpoint: &str) -> Result<String> {
    if endpoint.starts_with('[') {
        let close = endpoint
            .find(']')
            .ok_or_else(|| ClientError::InvalidEndpoint(endpoint.to_string()))?;
        return Ok(endpoint[1..close].to_string());
    }

    endpoint
        .rsplit_once(':')
        .map(|(host, _)| host.to_string())
        .ok_or_else(|| ClientError::InvalidEndpoint(endpoint.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[path = "transport.rs"]
    mod transport;

    #[test]
    fn parses_host_from_domain_endpoint() {
        assert_eq!(
            host_from_endpoint("lunar-lander.hellomoon.io:16888").unwrap(),
            "lunar-lander.hellomoon.io"
        );
    }

    #[test]
    fn parses_host_from_ipv6_endpoint() {
        assert_eq!(host_from_endpoint("[::1]:16888").unwrap(), "::1");
    }

    #[test]
    fn default_options_have_mev_protect_disabled() {
        let options = ClientOptions::default();
        assert!(!options.mev_protect);
    }

    #[test]
    fn default_options_enable_auto_reconnect() {
        let options = ClientOptions::default();
        assert!(options.auto_reconnect);
    }

    #[test]
    fn default_options_set_response_timeout() {
        let options = ClientOptions::default();
        assert_eq!(options.response_timeout, Duration::from_secs(5));
    }

    #[test]
    fn default_options_enable_proactive_reconnect() {
        let options = ClientOptions::default();
        assert!(options.proactive_reconnect);
    }

    #[test]
    fn default_backoff_grows_to_max() {
        let options = ClientOptions::default();
        assert!(options.reconnect_initial_backoff < options.reconnect_max_backoff);
    }

    #[test]
    fn jittered_returns_zero_for_zero_base() {
        assert_eq!(jittered(Duration::ZERO), Duration::ZERO);
    }

    #[test]
    fn jittered_stays_below_base() {
        let base = Duration::from_millis(500);
        for _ in 0..32 {
            assert!(jittered(base) < base);
        }
    }

    #[test]
    fn bidi_response_retry_is_only_safe_before_stream_open() {
        assert!(ClientError::OpenBi("closed".to_string()).retry_safe_for_bidi_response());
        assert!(!ClientError::FinishBi("closed".to_string()).retry_safe_for_bidi_response());
        assert!(
            !ClientError::ResponseTimeout(Duration::from_millis(1)).retry_safe_for_bidi_response()
        );
        assert!(!ClientError::ReadResponse("reset".to_string()).retry_safe_for_bidi_response());
    }

    #[test]
    fn decodes_accepted_response_frame_with_signature() {
        let frame = [
            QUIC_SUBMIT_RESPONSE_VERSION,
            0,
            0,
            200,
            0,
            9,
            b's',
            b'i',
            b'g',
            b'n',
            b'a',
            b't',
            b'u',
            b'r',
            b'e',
        ];

        let response = QuicSubmitResponse::decode_frame(&frame).unwrap();

        assert!(response.is_accepted());
        assert_eq!(response.status, 200);
        assert_eq!(response.code, QuicSubmitCode::Accepted);
        assert_eq!(response.signature.as_deref(), Some("signature"));
        assert_eq!(response.message, None);
    }

    #[test]
    fn decodes_error_response_frame_with_message() {
        let frame = encode_submit_response_frame(429, b"rate limit exceeded").unwrap();

        let response = QuicSubmitResponse::decode_frame(&frame).unwrap();

        assert!(!response.is_accepted());
        assert_eq!(response.status, 429);
        assert_eq!(response.code, QuicSubmitCode::RateLimited);
        assert_eq!(response.signature, None);
        assert_eq!(response.message.as_deref(), Some("rate limit exceeded"));
    }

    #[test]
    fn classifies_tip_required_from_status_and_body() {
        let frame = encode_submit_response_frame(400, b"tip required").unwrap();

        let response = QuicSubmitResponse::decode_frame(&frame).unwrap();

        assert_eq!(response.code, QuicSubmitCode::TipRequired);
        assert_eq!(response.message.as_deref(), Some("tip required"));
    }

    #[test]
    fn classifies_blocked_arb_program_from_http_parity_body() {
        let frame =
            encode_submit_response_frame(400, b"transaction contains blocked arb program").unwrap();

        let response = QuicSubmitResponse::decode_frame(&frame).unwrap();

        assert_eq!(response.status, 400);
        assert_eq!(response.code, QuicSubmitCode::BlockedArbProgram);
        assert_eq!(
            response.message.as_deref(),
            Some("transaction contains blocked arb program")
        );
    }

    #[test]
    fn encodes_response_frame_big_endian_header() {
        let response = QuicSubmitResponse::accepted("abc".to_string());

        let frame = response.encode_frame().unwrap();

        assert_eq!(
            &frame[..QUIC_SUBMIT_RESPONSE_HEADER_LEN],
            &[QUIC_SUBMIT_RESPONSE_VERSION, 0, 0, 200, 0, 3]
        );
        assert_eq!(&frame[QUIC_SUBMIT_RESPONSE_HEADER_LEN..], b"abc");
    }

    #[test]
    fn round_trips_error_response_frame() {
        let response = QuicSubmitResponse::error(503, "unavailable");

        let decoded = QuicSubmitResponse::decode_frame(&response.encode_frame().unwrap()).unwrap();

        assert_eq!(decoded, response);
    }

    #[test]
    fn rejects_response_frame_with_wrong_version() {
        let frame = [2, 0, 0, 200, 0, 0];

        let error = QuicSubmitResponse::decode_frame(&frame).unwrap_err();

        assert!(matches!(
            error,
            QuicSubmitResponseFrameError::UnsupportedVersion { version: 2 }
        ));
    }

    #[test]
    fn rejects_response_frame_with_nonzero_flags() {
        let frame = [QUIC_SUBMIT_RESPONSE_VERSION, 1, 0, 200, 0, 0];

        let error = QuicSubmitResponse::decode_frame(&frame).unwrap_err();

        assert!(matches!(
            error,
            QuicSubmitResponseFrameError::UnsupportedFlags { flags: 1 }
        ));
    }

    #[test]
    fn rejects_response_frame_body_length_mismatch() {
        let frame = [QUIC_SUBMIT_RESPONSE_VERSION, 0, 0, 200, 0, 2, b'a'];

        let error = QuicSubmitResponse::decode_frame(&frame).unwrap_err();

        assert!(matches!(
            error,
            QuicSubmitResponseFrameError::BodyLengthMismatch {
                declared: 2,
                actual: 1
            }
        ));
    }

    #[test]
    fn rejects_response_frame_body_over_client_limit() {
        let oversized_body = vec![b'x'; MAX_QUIC_SUBMIT_RESPONSE_BODY_BYTES + 1];

        let error = encode_submit_response_frame(200, &oversized_body).unwrap_err();

        assert!(matches!(
            error,
            QuicSubmitResponseFrameError::BodyTooLong {
                body_len,
                max: MAX_QUIC_SUBMIT_RESPONSE_BODY_BYTES
            } if body_len == MAX_QUIC_SUBMIT_RESPONSE_BODY_BYTES + 1
        ));
    }

    #[test]
    fn build_client_config_without_mev_protect() {
        install_rustls_provider();
        let options = ClientOptions::default();
        // Should succeed and produce a valid QUIC client config.
        build_client_config("test-api-key", &options).unwrap();
    }

    #[test]
    fn build_client_config_with_mev_protect() {
        install_rustls_provider();
        let options = ClientOptions {
            mev_protect: true,
            ..ClientOptions::default()
        };
        // Should succeed — the custom extension must not break cert generation.
        build_client_config("test-api-key", &options).unwrap();
    }

    #[test]
    fn build_client_config_rejects_keepalive_at_or_above_idle() {
        install_rustls_provider();
        // Equal: idle expires at exactly the moment keepalive would fire,
        // which is unsafe.
        let options = ClientOptions {
            keepalive_interval: Duration::from_secs(5),
            idle_timeout: Duration::from_secs(5),
            ..ClientOptions::default()
        };
        assert!(matches!(
            build_client_config("test-api-key", &options),
            Err(ClientError::InvalidTransport { .. })
        ));
        // Greater: connection idles between every ping.
        let options = ClientOptions {
            keepalive_interval: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(5),
            ..ClientOptions::default()
        };
        assert!(matches!(
            build_client_config("test-api-key", &options),
            Err(ClientError::InvalidTransport { .. })
        ));
    }
}
