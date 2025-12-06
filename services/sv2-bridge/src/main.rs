use std::{
    env,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::sleep;

use rg_protocol::{TemplatePropose, PROTOCOL_VERSION};

#[derive(Clone)]
struct BridgeConfig {
    listen_addr: String,
    interval_secs: u64,
    start_height: u32,
    tx_count: u32,
    total_fees: u64,
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
            .unwrap_or(100); // low on purpose so current strict policy rejects

        BridgeConfig {
            listen_addr,
            interval_secs,
            start_height,
            tx_count,
            total_fees,
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cfg = BridgeConfig::from_env();

    println!(
        "sv2-bridge listening on {} (interval={}s, start_height={}, tx_count={}, total_fees={})",
        cfg.listen_addr, cfg.interval_secs, cfg.start_height, cfg.tx_count, cfg.total_fees
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
    let coinbase_value: u64 = 6_2500_0000; // 6.25 BTC in sats

    loop {
        let tpl = TemplatePropose {
            version: PROTOCOL_VERSION,
            id,
            block_height: height,
            prev_hash: prev_hash.clone(),
            coinbase_value,
            tx_count: cfg.tx_count,
            total_fees: cfg.total_fees,
        };

        let json = serde_json::to_string(&tpl)?;
        stream.write_all(json.as_bytes()).await?;
        stream.write_all(b"\n").await?;
        stream.flush().await?;

        println!(
            "[{}] sent template id={} height={} total_fees={} tx_count={}",
            now_secs(),
            id,
            height,
            cfg.total_fees,
            cfg.tx_count
        );

        id += 1;
        height += 1;

        sleep(Duration::from_secs(cfg.interval_secs)).await;
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
