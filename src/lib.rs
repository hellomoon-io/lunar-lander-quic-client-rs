//! Official Rust QUIC client for Hello Moon Lunar Lander.
//!
//! `lunar-lander-quic-client` is intentionally narrow:
//! - connect to a Lunar Lander QUIC endpoint
//! - generate the client certificate in code from your API key
//! - send one serialized Solana transaction payload per uni stream
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
//!         "fra.lunar-lander.hellomoon.io:16888",
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
//!     "fra.lunar-lander.hellomoon.io:16888",
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
        IdleTimeout, TransportConfig, WriteError, crypto::rustls::QuicClientConfig,
    },
    rcgen::{CertificateParams, CustomExtension, DistinguishedName, DnType, KeyPair},
    rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    rustls::{
        DigitallySignedStruct, SignatureScheme,
        client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        pki_types::{ServerName, UnixTime},
    },
    std::{
        net::{SocketAddr, ToSocketAddrs},
        sync::Arc,
        time::Duration,
    },
    thiserror::Error,
    tokio::time::timeout,
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
/// Maximum serialized Solana transaction size accepted on the QUIC path.
pub const MAX_WIRE_TX_BYTES: usize = 1232;

/// Connection-level tuning for [`LunarLanderQuicClient`].
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ClientOptions {
    /// Maximum time allowed for the initial QUIC connect to complete.
    pub connect_timeout: Duration,
    /// Keepalive interval used on the QUIC connection.
    pub keepalive_interval: Duration,
    /// Idle timeout advertised to Quinn for this client connection.
    pub idle_timeout: Duration,
    /// When `true`, embeds a custom X.509 certificate extension that signals
    /// the server to enable MEV protection for transactions sent over this
    /// connection. The extension uses the ITU-T experimental OID arc
    /// `2.999.1.1` and is marked non-critical so older servers that do not
    /// understand it will simply ignore it.
    pub mev_protect: bool,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(5),
            keepalive_interval: Duration::from_secs(25),
            idle_timeout: Duration::from_secs(30),
            mev_protect: false,
        }
    }
}

/// Error type returned by the client library.
#[derive(Debug, Error)]
pub enum ClientError {
    #[error("api key must not be empty")]
    EmptyApiKey,
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
    #[error("failed to write transaction payload: {0}")]
    Write(#[from] WriteError),
    #[error("failed to finish uni stream: {0}")]
    Finish(String),
}

pub type Result<T> = std::result::Result<T, ClientError>;

/// Connected Lunar Lander QUIC client.
///
/// Each instance owns one QUIC connection and reuses it across many transaction
/// sends. Transactions are written as fire-and-forget unidirectional streams.
#[derive(Debug)]
pub struct LunarLanderQuicClient {
    endpoint_label: String,
    server_addr: SocketAddr,
    server_name: String,
    options: ClientOptions,
    endpoint: Endpoint,
    connection: Connection,
}

impl LunarLanderQuicClient {
    /// Connects to a Lunar Lander QUIC endpoint with default client options.
    ///
    /// `endpoint` must be `host:port`, for example
    /// `fra.lunar-lander.hellomoon.io:16888`.
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

        Ok(Self {
            endpoint_label,
            server_addr,
            server_name,
            options,
            endpoint,
            connection,
        })
    }

    /// Returns the endpoint string originally passed to [`Self::connect`] or
    /// [`Self::connect_with_options`].
    pub fn endpoint(&self) -> &str {
        &self.endpoint_label
    }

    /// Returns the resolved remote socket address currently used by the client.
    pub fn remote_addr(&self) -> SocketAddr {
        self.server_addr
    }

    /// Returns the TLS server name used for the connection handshake.
    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    /// Tears down the current QUIC connection and establishes a new one.
    pub async fn reconnect(&mut self) -> Result<()> {
        self.connection = connect_inner(
            &self.endpoint,
            self.server_addr,
            &self.server_name,
            self.options.connect_timeout,
        )
        .await?;
        Ok(())
    }

    /// Sends one serialized transaction payload over a QUIC uni stream.
    ///
    /// The payload should already be fully prepared by the caller. This method
    /// only opens a stream, writes the bytes, and finishes the stream.
    pub async fn send_transaction(&self, payload: &[u8]) -> Result<()> {
        let mut stream = self
            .connection
            .open_uni()
            .await
            .map_err(|error| ClientError::OpenUni(error.to_string()))?;
        stream.write_all(payload).await?;
        stream
            .finish()
            .map_err(|error| ClientError::Finish(error.to_string()))?;
        Ok(())
    }

    /// Closes the QUIC connection and waits for the endpoint to go idle.
    pub async fn close(self) {
        self.connection.close(0u32.into(), b"client_closed");
        self.endpoint.close(0u32.into(), b"client_closed");
        let _ = self.endpoint.wait_idle().await;
    }
}

fn install_rustls_provider() {
    if rustls::crypto::CryptoProvider::get_default().is_some() {
        return;
    }

    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

fn build_client_config(api_key: &str, options: &ClientOptions) -> Result<QuinnClientConfig> {
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

    #[test]
    fn parses_host_from_ipv4_endpoint() {
        assert_eq!(
            host_from_endpoint("fra.lunar-lander.hellomoon.io:16888").unwrap(),
            "fra.lunar-lander.hellomoon.io"
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
}
