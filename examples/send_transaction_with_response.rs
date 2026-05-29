use {
    anyhow::{Context, Result},
    common::{DEFAULT_QUIC_ENDPOINT, LUNAR_LANDER_QUIC_ENDPOINT_ENV},
    lunar_lander_quic_client::{LunarLanderQuicClient, QuicSubmitCode},
    std::env,
};

mod common;

const MALFORMED_PAYLOAD: &[u8] = &[0xab, 0xcd];

#[tokio::main]
async fn main() -> Result<()> {
    let api_key =
        env::var("LUNAR_LANDER_API_KEY").context("LUNAR_LANDER_API_KEY env var is required")?;
    let endpoint = env::var(LUNAR_LANDER_QUIC_ENDPOINT_ENV)
        .unwrap_or_else(|_| DEFAULT_QUIC_ENDPOINT.to_string());

    let client = LunarLanderQuicClient::connect(&endpoint, api_key).await?;
    println!("connected to {}", client.endpoint());

    let response = client
        .send_transaction_with_response(MALFORMED_PAYLOAD)
        .await?;
    println!("response: {response:?}");

    assert_eq!(response.status, 400);
    assert_eq!(response.code, QuicSubmitCode::InvalidPayload);
    assert_eq!(
        response.message.as_deref(),
        Some("invalid transaction payload")
    );

    client.close().await;
    Ok(())
}
