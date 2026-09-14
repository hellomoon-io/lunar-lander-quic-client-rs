use super::*;
#[path = "fault_proxy.rs"]
mod fault_proxy;
use fault_proxy::FaultProxy;

fn payload(seed: u8, size: usize) -> Vec<u8> {
    let mut bytes: Vec<u8> = (0..size).map(|i| (i as u8).wrapping_add(seed)).collect();
    bytes[0] = V1_TRANSACTION_PREFIX;
    bytes
}

#[test]
fn size_limits_are_version_aware() {
    for prefix in [0x01, 0x80, 0x81, 0x82] {
        for size in [1232, 1233, 4096, 4097] {
            let mut bytes = vec![0; size];
            bytes[0] = prefix;
            let max = if prefix == 0x81 { 4096 } else { 1232 };
            assert_eq!(validate_payload_size(&bytes).is_ok(), size <= max);
        }
    }
    // Keep malformed-payload diagnostics available; this is not a decoder.
    assert!(validate_payload_size(&[]).is_ok());
    assert!(validate_payload_size(&[0x81]).is_ok());
}

#[tokio::test]
async fn concurrent_v1_uni_bidi_survive_loss_reordering_and_duplication() {
    install_rustls_provider();
    let pair = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(vec!["localhost".to_owned()])
        .unwrap()
        .self_signed(&pair)
        .unwrap();
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            PrivatePkcs8KeyDer::from(pair.serialize_der()).into(),
        )
        .unwrap();
    tls.alpn_protocols = vec![LUNAR_LANDER_TPU_PROTOCOL_ID.to_vec()];
    let config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap(),
    ));
    let server = Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let proxy = FaultProxy::spawn(server.local_addr().unwrap())
        .await
        .unwrap();
    let (tx, mut rx) = tokio::sync::mpsc::channel(64);
    let accept = server.clone();
    let task = tokio::spawn(async move {
        let connection = accept.accept().await.unwrap().await.unwrap();
        loop {
            tokio::select! {
                uni = connection.accept_uni() => {
                    let Ok(mut recv) = uni else { break };
                    let tx = tx.clone();
                    tokio::spawn(async move {
                        tx.send(recv.read_to_end(4097).await.unwrap()).await.unwrap();
                    });
                }
                bidi = connection.accept_bi() => {
                    let Ok((mut send, mut recv)) = bidi else { break };
                    let tx = tx.clone();
                    tokio::spawn(async move {
                        let bytes = recv.read_to_end(4097).await.unwrap();
                        let response = QuicSubmitResponse::accepted(format!("fixture-{}", bytes[1]));
                        tx.send(bytes).await.unwrap();
                        for part in response.encode_frame().unwrap().chunks(3) {
                            send.write_all(part).await.unwrap();
                            tokio::task::yield_now().await;
                        }
                        send.finish().unwrap();
                    });
                }
            }
        }
    });
    let client = Arc::new(
        LunarLanderQuicClient::connect_with_options(
            proxy.addr.to_string(),
            "local-test-key",
            ClientOptions {
                response_timeout: Duration::from_secs(15),
                ..Default::default()
            },
        )
        .await
        .unwrap(),
    );
    proxy.arm();
    let mut sends = tokio::task::JoinSet::new();
    let mut cases: Vec<_> = (0..16).map(|i| payload(i, 4096)).collect();
    let legacy = vec![1; 1232];
    let mut v0 = legacy.clone();
    v0[65] = 0x80;
    cases.extend([legacy, v0, payload(30, 1232), payload(31, 1233)]);
    let expected: std::collections::HashSet<Vec<u8>> = cases.iter().cloned().collect();
    for (i, bytes) in cases.into_iter().enumerate() {
        let client = client.clone();
        sends.spawn(async move {
            if i % 2 == 0 {
                client.send_transaction(&bytes).await.unwrap();
            } else {
                let response = client.send_transaction_with_response(&bytes).await.unwrap();
                assert!(response.is_accepted());
                assert_eq!(response.signature, Some(format!("fixture-{}", bytes[1])));
            }
        });
    }
    timeout(Duration::from_secs(20), async {
        while let Some(result) = sends.join_next().await {
            result.unwrap();
        }
    })
    .await
    .unwrap();
    let mut received = std::collections::HashSet::new();
    for _ in 0..expected.len() {
        let bytes = timeout(Duration::from_secs(10), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(expected.contains(&bytes), "truncated or mixed stream");
        assert!(received.insert(bytes), "duplicate application submission");
    }
    assert_eq!(received, expected);
    for bytes in [payload(99, 4097), vec![1; 1233]] {
        assert!(matches!(
            client.send_transaction(&bytes).await,
            Err(ClientError::PayloadTooLarge { .. })
        ));
        assert!(matches!(
            client.send_transaction_with_response(&bytes).await,
            Err(ClientError::PayloadTooLarge { .. })
        ));
    }
    assert!(
        timeout(Duration::from_millis(100), rx.recv())
            .await
            .is_err(),
        "extra stream"
    );
    proxy.assert_exercised();
    drop(client);
    server.close(0u32.into(), b"test complete");
    task.abort();
}
