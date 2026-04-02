use {
    anyhow::{Context, Result, bail},
    lunar_lander_quic_client::{ClientOptions, LunarLanderQuicClient},
    rand::seq::SliceRandom,
    solana_compute_budget_interface::ComputeBudgetInstruction,
    solana_sdk::{
        hash::Hash,
        message::Message,
        pubkey::Pubkey,
        signature::{EncodableKey, Keypair},
        signer::Signer,
        transaction::Transaction,
    },
    solana_system_interface::instruction as system_instruction,
    std::{env, str::FromStr},
};

const DEFAULT_ENDPOINT: &str = "fra.lunar-lander.hellomoon.io:16888";
const DEFAULT_RPC_URL: &str = "https://api.mainnet-beta.solana.com";
const TIP_THRESHOLD_LAMPORTS: u64 = 1_000_000;
const TIP_DESTINATIONS: &[&str] = &[
    "moon17L6BgxXRX5uHKudAmqVF96xia9h8ygcmG2sL3F",
    "moon26Sek222Md7ZydcAGxoKG832DK36CkLrS3PQY4c",
    "moon7fwyajcVstMoBnVy7UBcTx87SBtNoGGAaH2Cb8V",
    "moonBtH9HvLHjLqi9ivyrMVKgFUsSfrz9BwQ9khhn1u",
    "moonCJg8476LNFLptX1qrK8PdRsA1HD1R6XWyu9MB93",
    "moonF2sz7qwAtdETnrgxNbjonnhGGjd6r4W4UC9284s",
    "moonKfftMiGSak3cezvhEqvkPSzwrmQxQHXuspC96yj",
    "moonQBUKBpkifLcTd78bfxxt4PYLwmJ5admLW6cBBs8",
    "moonXwpKwoVkMegt5Bc776cSW793X1irL5hHV1vJ3JA",
    "moonZ6u9E2fgk6eWd82621eLPHt9zuJuYECXAYjMY1C",
];

async fn fetch_recent_blockhash(rpc_url: &str) -> Result<Hash> {
    let client = reqwest::Client::new();
    let request_body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getLatestBlockhash",
        "params": [{"commitment": "confirmed"}]
    });

    let response = client
        .post(rpc_url)
        .header("Content-Type", "application/json")
        .json(&request_body)
        .send()
        .await
        .context("failed to send RPC request")?;

    let status = response.status();
    let json: serde_json::Value = response
        .json()
        .await
        .context("failed to parse RPC response")?;

    if !status.is_success() {
        bail!("RPC returned {status}: {json}");
    }

    let blockhash = json["result"]["value"]["blockhash"]
        .as_str()
        .context("missing blockhash in RPC response")?;

    Hash::from_str(blockhash).context("failed to parse recent blockhash")
}

#[tokio::main]
async fn main() -> Result<()> {
    let api_key =
        env::var("LUNAR_LANDER_API_KEY").context("LUNAR_LANDER_API_KEY env var is required")?;
    let endpoint =
        env::var("LUNAR_LANDER_QUIC_ENDPOINT").unwrap_or_else(|_| DEFAULT_ENDPOINT.to_string());
    let rpc_url = env::var("RPC_URL").unwrap_or_else(|_| DEFAULT_RPC_URL.to_string());
    let keypair_path = env::var("KEYPAIR_PATH").context("KEYPAIR_PATH env var is required")?;

    let mut rng = rand::thread_rng();
    let tip_address = TIP_DESTINATIONS
        .choose(&mut rng)
        .context("tip destination list must not be empty")?;
    let tip_account = Pubkey::from_str(tip_address).context("failed to parse tip destination")?;
    let payer = Keypair::read_from_file(&keypair_path)
        .map_err(|error| anyhow::anyhow!("failed to read keypair from {keypair_path}: {error}"))?;

    println!("payer: {}", payer.pubkey());
    println!(
        "selected tip destination: {} (threshold {} lamports)",
        tip_account, TIP_THRESHOLD_LAMPORTS
    );
    println!("fetching recent blockhash from {rpc_url}...");
    let recent_blockhash = fetch_recent_blockhash(&rpc_url).await?;
    println!("recent blockhash: {recent_blockhash}");

    // Enable MEV protection via the LUNAR_LANDER_MEV_PROTECT env var.
    let mev_protect = env::var("LUNAR_LANDER_MEV_PROTECT")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let options = ClientOptions {
        mev_protect,
        ..ClientOptions::default()
    };

    let client = LunarLanderQuicClient::connect_with_options(&endpoint, &api_key, options).await?;
    println!(
        "connected to {} (mev_protect={})",
        client.endpoint(),
        mev_protect
    );

    let instructions = vec![
        ComputeBudgetInstruction::set_compute_unit_limit(20_000),
        ComputeBudgetInstruction::set_compute_unit_price(10_000),
        system_instruction::transfer(&payer.pubkey(), &tip_account, TIP_THRESHOLD_LAMPORTS),
    ];

    let message = Message::new(&instructions, Some(&payer.pubkey()));
    let mut transaction = Transaction::new_unsigned(message);
    transaction.sign(&[&payer], recent_blockhash);

    let signature = transaction.signatures[0];
    let payload = bincode::serialize(&transaction).context("failed to serialize transaction")?;

    println!(
        "sending transaction sig={} size={} bytes",
        signature,
        payload.len()
    );
    client.send_transaction(&payload).await?;

    // Give the server a moment to finish reading the stream before closing.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    client.close().await;

    println!("sent");
    Ok(())
}
