//! Integration test for the background reconnect watchdog.
//!
//! Spins up a local Quinn server speaking the lunar-lander-tpu ALPN,
//! connects a [`LunarLanderQuicClient`], then closes the server-side
//! connection with an application close frame. The watchdog must observe
//! the close, re-handshake, and increment `reconnects_total` before the
//! next send is issued.

use {
    lunar_lander_quic_client::{
        ClientOptions, ConnectionHealth, LUNAR_LANDER_TPU_PROTOCOL_ID, LunarLanderQuicClient,
    },
    quinn::{Connection, Endpoint, ServerConfig, VarInt, crypto::rustls::QuicServerConfig},
    rcgen::{CertificateParams, DistinguishedName, KeyPair},
    rustls::{
        DigitallySignedStruct, DistinguishedName as RustlsDistinguishedName, SignatureScheme,
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, UnixTime},
        server::danger::{ClientCertVerified, ClientCertVerifier},
    },
    std::{net::SocketAddr, sync::Arc, time::Duration},
    tokio::{
        net::UdpSocket,
        sync::{mpsc, oneshot},
        task::JoinHandle,
    },
};

/// Owns the server endpoint's accept task. Calling [`kill`] aborts the
/// task; existing tests can ignore the handle.
struct TestServerHandle {
    #[allow(dead_code)]
    accept_task: JoinHandle<()>,
}

/// Bidirectional UDP relay between a client-facing socket and an
/// upstream Quinn server. Calling the returned `oneshot::Sender` makes
/// the relay stop forwarding in both directions, which is the closest
/// faithful simulation of a silent network drop available without
/// platform-specific firewall hooks: no application close frame, no
/// transport close, just the absence of packets that the keepalive +
/// idle-timeout path is supposed to detect.
fn start_silent_drop_proxy(upstream: SocketAddr) -> (SocketAddr, oneshot::Sender<()>) {
    let proxy_std = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind proxy");
    proxy_std.set_nonblocking(true).expect("nonblocking proxy");
    let proxy_addr = proxy_std.local_addr().expect("proxy local addr");
    let proxy = Arc::new(UdpSocket::from_std(proxy_std).expect("tokio proxy socket"));

    let upstream_std = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind upstream side");
    upstream_std
        .set_nonblocking(true)
        .expect("nonblocking upstream");
    let upstream_socket =
        Arc::new(UdpSocket::from_std(upstream_std).expect("tokio upstream socket"));

    let (kill_tx, mut kill_rx) = oneshot::channel();
    let proxy_loop = Arc::clone(&proxy);
    let upstream_loop = Arc::clone(&upstream_socket);
    tokio::spawn(async move {
        let mut last_client: Option<SocketAddr> = None;
        let mut buf_client = vec![0u8; 65536];
        let mut buf_server = vec![0u8; 65536];
        loop {
            tokio::select! {
                biased;
                _ = &mut kill_rx => return,
                Ok((n, src)) = proxy_loop.recv_from(&mut buf_client) => {
                    last_client = Some(src);
                    let _ = upstream_loop.send_to(&buf_client[..n], upstream).await;
                }
                Ok((n, _)) = upstream_loop.recv_from(&mut buf_server) => {
                    if let Some(addr) = last_client {
                        let _ = proxy_loop.send_to(&buf_server[..n], addr).await;
                    }
                }
            }
        }
    });

    (proxy_addr, kill_tx)
}

fn install_crypto_provider() {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }
}

#[derive(Debug)]
struct AcceptAnyClientCert(Arc<rustls::crypto::CryptoProvider>);

impl AcceptAnyClientCert {
    fn new() -> Arc<Self> {
        let provider = rustls::crypto::CryptoProvider::get_default()
            .expect("crypto provider installed")
            .clone();
        Arc::new(Self(provider))
    }
}

impl ClientCertVerifier for AcceptAnyClientCert {
    fn root_hint_subjects(&self) -> &[RustlsDistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> std::result::Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
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
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
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

/// Bring up a Quinn server bound to 127.0.0.1:0 that speaks the
/// lunar-lander-tpu ALPN and surfaces each accepted connection through
/// `conn_tx`. The test can then close individual server-side connections
/// to exercise the client's close-detection paths. The returned
/// [`TestServerHandle`] keeps the accept task alive for the duration
/// of the test; tests that don't need it can ignore the value.
fn start_test_server() -> (
    SocketAddr,
    mpsc::UnboundedReceiver<Connection>,
    TestServerHandle,
) {
    install_crypto_provider();

    let key_pair = KeyPair::generate().expect("keypair");
    let mut params = CertificateParams::new(vec!["localhost".to_string()]).expect("cert params");
    params.distinguished_name = DistinguishedName::new();
    let certificate = params.self_signed(&key_pair).expect("self-signed cert");
    let cert_der = CertificateDer::from(certificate.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_client_cert_verifier(AcceptAnyClientCert::new())
        .with_single_cert(vec![cert_der], key_der)
        .expect("server cert");
    server_crypto.alpn_protocols = vec![LUNAR_LANDER_TPU_PROTOCOL_ID.to_vec()];

    let quic_server_config = QuicServerConfig::try_from(server_crypto).expect("quic server config");
    let server_config = ServerConfig::with_crypto(Arc::new(quic_server_config));

    let endpoint =
        Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).expect("bind server");
    let addr = endpoint.local_addr().expect("local addr");

    let (conn_tx, conn_rx) = mpsc::unbounded_channel();
    let accept_task = tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let conn_tx = conn_tx.clone();
            tokio::spawn(async move {
                if let Ok(connection) = incoming.await {
                    let _ = conn_tx.send(connection.clone());
                    // Keep the server-side handle alive until the peer or the
                    // test tears it down so the stream accept half stays open.
                    let _ = connection.closed().await;
                }
            });
        }
    });

    (addr, conn_rx, TestServerHandle { accept_task })
}

async fn wait_for<F>(mut predicate: F, timeout: Duration) -> bool
where
    F: FnMut() -> bool,
{
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if predicate() {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

#[tokio::test]
async fn watchdog_reconnects_after_server_close() {
    let (addr, mut conn_rx, _server) = start_test_server();

    let options = ClientOptions {
        connect_timeout: Duration::from_secs(2),
        reconnect_initial_backoff: Duration::from_millis(50),
        reconnect_max_backoff: Duration::from_millis(200),
        ..ClientOptions::default()
    };
    let endpoint_label = format!("127.0.0.1:{}", addr.port());
    let client =
        LunarLanderQuicClient::connect_with_options(&endpoint_label, "watchdog-test-key", options)
            .await
            .expect("client connects");

    assert_eq!(client.reconnects_total(), 0);
    assert_eq!(client.health(), ConnectionHealth::Healthy);

    // The first server-side handle represents the initial handshake.
    let first_conn = tokio::time::timeout(Duration::from_secs(2), conn_rx.recv())
        .await
        .expect("server accepts initial connection within timeout")
        .expect("accept loop still alive");

    // Trigger the exact contract PR #165 exercises on the real server.
    first_conn.close(VarInt::from_u32(3), b"server_shutdown");

    // Watchdog should observe the close and re-handshake without any send
    // from the test driving it.
    let reconnected = wait_for(|| client.reconnects_total() >= 1, Duration::from_secs(5)).await;
    assert!(
        reconnected,
        "watchdog should increment reconnects_total after server-side close"
    );
    let healthy_again = wait_for(
        || client.health() == ConnectionHealth::Healthy,
        Duration::from_secs(2),
    )
    .await;
    assert!(
        healthy_again,
        "health() should return to Healthy after watchdog finishes reconnecting"
    );

    // The server accept loop should have admitted a new connection. Draining
    // it here gives a tight confirmation that reconnect produced a fresh
    // handshake rather than simply flipping the counter.
    let second_conn = tokio::time::timeout(Duration::from_secs(2), conn_rx.recv())
        .await
        .expect("server accepts reconnect within timeout")
        .expect("accept loop still alive");
    assert_ne!(
        first_conn.stable_id(),
        second_conn.stable_id(),
        "watchdog must replace the dead connection with a fresh handshake"
    );

    // Tear down cleanly so the watchdog task exits and no sockets leak.
    client.close().await;
}

#[tokio::test]
async fn watchdog_disabled_does_not_reconnect() {
    let (addr, mut conn_rx, _server) = start_test_server();

    let options = ClientOptions {
        connect_timeout: Duration::from_secs(2),
        proactive_reconnect: false,
        auto_reconnect: false,
        ..ClientOptions::default()
    };
    let endpoint_label = format!("127.0.0.1:{}", addr.port());
    let client = LunarLanderQuicClient::connect_with_options(
        &endpoint_label,
        "watchdog-disabled-key",
        options,
    )
    .await
    .expect("client connects");

    let first_conn = tokio::time::timeout(Duration::from_secs(2), conn_rx.recv())
        .await
        .expect("server accepts initial connection within timeout")
        .expect("accept loop still alive");
    first_conn.close(VarInt::from_u32(3), b"server_shutdown");

    // With proactive_reconnect disabled, the watchdog must not run and the
    // counter must remain at zero even after the close is observable.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(client.reconnects_total(), 0);

    // And the server must not see any further connection attempts.
    let no_reconnect = tokio::time::timeout(Duration::from_millis(200), conn_rx.recv()).await;
    assert!(
        no_reconnect.is_err(),
        "disabled watchdog must not trigger reconnect handshakes"
    );

    client.close().await;
}

#[tokio::test]
async fn manual_reconnect_rearms_watchdog() {
    let (addr, mut conn_rx, _server) = start_test_server();

    let options = ClientOptions {
        connect_timeout: Duration::from_secs(2),
        reconnect_initial_backoff: Duration::from_millis(50),
        reconnect_max_backoff: Duration::from_millis(200),
        ..ClientOptions::default()
    };
    let endpoint_label = format!("127.0.0.1:{}", addr.port());
    let mut client = LunarLanderQuicClient::connect_with_options(
        &endpoint_label,
        "manual-reconnect-test-key",
        options,
    )
    .await
    .expect("client connects");

    let first_conn = tokio::time::timeout(Duration::from_secs(2), conn_rx.recv())
        .await
        .expect("server accepts initial connection within timeout")
        .expect("accept loop still alive");

    // Drive a manual reconnect while the watchdog is running. The client
    // must close the existing connection (so the watchdog re-arms on the
    // fresh handle) and produce a new server-side handshake.
    client
        .reconnect()
        .await
        .expect("manual reconnect succeeds against the local server");

    let second_conn = tokio::time::timeout(Duration::from_secs(2), conn_rx.recv())
        .await
        .expect("server accepts manual reconnect within timeout")
        .expect("accept loop still alive");
    assert_ne!(
        first_conn.stable_id(),
        second_conn.stable_id(),
        "manual reconnect must replace the existing connection"
    );
    let after_manual = client.reconnects_total();
    assert!(
        after_manual >= 1,
        "manual reconnect should bump reconnects_total"
    );
    let healthy_after_manual = wait_for(
        || client.health() == ConnectionHealth::Healthy,
        Duration::from_secs(2),
    )
    .await;
    assert!(
        healthy_after_manual,
        "health() should return to Healthy after manual reconnect"
    );

    // Now close the post-manual-reconnect server handle. The watchdog must
    // have re-armed on the new handle; otherwise it would still be parked
    // on the orphaned first connection and never observe this close.
    second_conn.close(VarInt::from_u32(3), b"server_shutdown");

    let watchdog_recovered = wait_for(
        || client.reconnects_total() > after_manual,
        Duration::from_secs(5),
    )
    .await;
    assert!(
        watchdog_recovered,
        "watchdog must have re-armed on the post-manual-reconnect handle"
    );

    let third_conn = tokio::time::timeout(Duration::from_secs(2), conn_rx.recv())
        .await
        .expect("server accepts watchdog reconnect within timeout")
        .expect("accept loop still alive");
    assert_ne!(
        second_conn.stable_id(),
        third_conn.stable_id(),
        "watchdog must produce a fresh handshake after manual reconnect"
    );

    client.close().await;
}

#[tokio::test]
async fn watchdog_detects_silent_drop_via_idle_timeout() {
    // The Quinn server lives behind a UDP relay so we can break the
    // forwarding path without touching the server's connection state.
    // The point is to exercise the keepalive + idle_timeout path: the
    // peer never sends a close frame; the client must detect the dead
    // connection by absence of keepalive ACKs alone, the way it would
    // for a silent network drop in production.
    let (server_addr, mut conn_rx, _server) = start_test_server();
    let (proxy_addr, proxy_kill) = start_silent_drop_proxy(server_addr);

    // Tight enough that the test runs in well under a second.
    let options = ClientOptions {
        connect_timeout: Duration::from_secs(2),
        keepalive_interval: Duration::from_millis(50),
        idle_timeout: Duration::from_millis(200),
        reconnect_initial_backoff: Duration::from_millis(50),
        reconnect_max_backoff: Duration::from_millis(100),
        ..ClientOptions::default()
    };
    let endpoint_label = format!("127.0.0.1:{}", proxy_addr.port());
    let client = LunarLanderQuicClient::connect_with_options(
        &endpoint_label,
        "silent-drop-test-key",
        options,
    )
    .await
    .expect("client connects");

    let _first_conn = tokio::time::timeout(Duration::from_secs(2), conn_rx.recv())
        .await
        .expect("server accepts initial connection within timeout")
        .expect("accept loop still alive");

    // Stop the relay. From the client's perspective the peer simply
    // stops responding. The watchdog must observe the resulting close
    // through the keepalive path within roughly the configured
    // idle_timeout window.
    let _ = proxy_kill.send(());

    let observed = wait_for(
        || client.health() == ConnectionHealth::Reconnecting,
        Duration::from_secs(2),
    )
    .await;
    assert!(
        observed,
        "watchdog must observe a silent drop within ~idle_timeout via the keepalive path"
    );

    client.close().await;
}
