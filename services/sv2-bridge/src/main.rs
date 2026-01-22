use std::{
    env,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::sleep;

use rg_protocol::{PROTOCOL_VERSION, TemplatePropose};

#[derive(Clone)]
struct BridgeConfig {
    listen_addr: String,
    interval_secs: u64,
    start_height: u32,
    tx_count: u32,
    total_fees: u64,

    // Optional override. If set, used as the block subsidy (sats), independent of height.
    // Coinbase value will be subsidy + total_fees.
    subsidy_override_sats: Option<u64>,
}

impl BridgeConfig {
    fn from_env() -> Self {
        let listen_addr =
            env::var("VELDRA_BRIDGE_ADDR").unwrap_or_else(|_| "127.0.0.1:3333".to_string());

        let interval_secs = env::var("VELDRA_BRIDGE_INTERVAL_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(5);

        let start_height = env::var("VELDRA_BRIDGE_START_HEIGHT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(500);

        let tx_count = env::var("VELDRA_BRIDGE_TX_COUNT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(5);

        let total_fees = env::var("VELDRA_BRIDGE_TOTAL_FEES")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(100); // low on purpose so strict policy rejects

        // If you want “current mainnet-era” demo behavior, set:
        //   VELDRA_BRIDGE_SUBSIDY_SATS=312500000  (3.125 BTC)
        // Otherwise, we compute subsidy by height (regtest at height=500 -> 50 BTC).
        let subsidy_override_sats = env::var("VELDRA_BRIDGE_SUBSIDY_SATS")
            .ok()
            .and_then(|s| s.parse().ok());

        BridgeConfig {
            listen_addr,
            interval_secs,
            start_height,
            tx_count,
            total_fees,
            subsidy_override_sats,
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cfg = BridgeConfig::from_env();

    println!(
        "sv2-bridge listening on {} (interval={}s, start_height={}, tx_count={}, total_fees={}, subsidy_override_sats={})",
        cfg.listen_addr,
        cfg.interval_secs,
        cfg.start_height,
        cfg.tx_count,
        cfg.total_fees,
        cfg.subsidy_override_sats
            .map(|v| v.to_string())
            .unwrap_or_else(|| "none(height-derived)".to_string()),
    );

    let listener = TcpListener::bind(&cfg.listen_addr).await?;
    loop {
        let (stream, addr) = listener.accept().await?;
        println!("New template-manager connection from {}", addr);
        let cfg_clone = cfg.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_client(stream, cfg_clone).await {
                eprintln!("client handler error: {e:?}");
            }
        });
    }
}

async fn handle_client(mut stream: TcpStream, cfg: BridgeConfig) -> Result<()> {
    let mut id: u64 = 1;
    let mut height: u32 = cfg.start_height;

    let prev_hash = "0000000000000000000000000000000000000000000000000000000000000000".to_string();

    loop {
        let now_ms: u64 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX);

        let subsidy_sats = cfg
            .subsidy_override_sats
            .unwrap_or_else(|| block_subsidy_sats(height));

        // In Bitcoin Core getblocktemplate, coinbasevalue includes subsidy + fees.
        let coinbase_value: u64 = subsidy_sats.saturating_add(cfg.total_fees);

        let tpl = TemplatePropose {
            version: PROTOCOL_VERSION,
            id,
            block_height: height,
            prev_hash: prev_hash.clone(),
            coinbase_value,
            tx_count: cfg.tx_count,
            total_fees: cfg.total_fees,

            // v0.2.0 forward-compatible fields
            observed_weight: None,
            created_at_unix_ms: Some(now_ms),
        };

        let json = serde_json::to_string(&tpl)?;
        stream.write_all(json.as_bytes()).await?;
        stream.write_all(b"\n").await?;
        stream.flush().await?;

        println!(
            "[{}] sent template id={} height={} subsidy_sats={} total_fees={} coinbase_value={} tx_count={}",
            now_secs(),
            id,
            height,
            subsidy_sats,
            cfg.total_fees,
            coinbase_value,
            cfg.tx_count
        );

        id += 1;
        height = height.saturating_add(1);

        sleep(Duration::from_secs(cfg.interval_secs)).await;
    }
}

fn block_subsidy_sats(height: u32) -> u64 {
    // Mainnet schedule; regtest follows the same halving schedule unless chain params changed.
    // 50 BTC at height 0, halves every 210_000 blocks.
    let halvings = height / 210_000;
    if halvings >= 64 {
        return 0;
    }
    (50u64 * 100_000_000u64) >> halvings
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
