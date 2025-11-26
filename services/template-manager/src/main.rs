use std::env;
use serde_json::{json, Value};

use anyhow::Result;
use bitcoincore_rpc::{Auth, Client, RpcApi};
use rg_protocol::{TemplatePropose, TemplateVerdict, PROTOCOL_VERSION};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

struct ManagerConfig {
    rpc_url: String,
    rpc_user: String,
    rpc_pass: String,
    verifier_addr: String,
}

impl ManagerConfig {
    fn from_env() -> Self {
        let rpc_url =
            env::var("VELDRA_RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:18443".to_string());
        let rpc_user = env::var("VELDRA_RPC_USER").unwrap_or_else(|_| "rguser".to_string());
        let rpc_pass = env::var("VELDRA_RPC_PASS").unwrap_or_else(|_| "rgpass".to_string());
        let verifier_addr =
            env::var("VELDRA_VERIFIER_ADDR").unwrap_or_else(|_| "127.0.0.1:4001".to_string());

        ManagerConfig {
            rpc_url,
            rpc_user,
            rpc_pass,
            verifier_addr,
        }
    }
}

async fn build_proposal(
    rpc: &Client,
    next_id: u64,
) -> anyhow::Result<TemplatePropose> {
    // get basic chain info
    let block_count = rpc.get_block_count()?;
    let tip_hash = rpc.get_block_hash(block_count)?;
    println!("Regtest tip: height = {}, hash = {}", block_count, tip_hash);

    // getblocktemplate with segwit rule
    let gbt_args = json!({ "rules": ["segwit"] });
    let gbt: Value = rpc.call("getblocktemplate", &[gbt_args])?;

    let tpl_height = gbt["height"]
        .as_u64()
        .ok_or_else(|| anyhow::anyhow!("missing height in getblocktemplate"))? as u32;

    let prev_hash_from_tpl = gbt["previousblockhash"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing previousblockhash in getblocktemplate"))?
        .to_string();

    let txs = gbt["transactions"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("missing transactions array in getblocktemplate"))?;

    let tx_count = txs.len() as u32;

    let mut total_fees: u64 = 0;
    for tx in txs {
        if let Some(fee) = tx["fee"].as_u64() {
            total_fees += fee;
        }
    }

    println!(
        "Template stats: height={}, prev_hash_len={}, tx_count={}, total_fees={}",
        tpl_height,
        prev_hash_from_tpl.len(),
        tx_count,
        total_fees
    );

    let propose = TemplatePropose {
        version: PROTOCOL_VERSION,
        id: next_id,
        block_height: tpl_height,
        prev_hash: prev_hash_from_tpl,
        coinbase_value: 6_2500_0000,
        tx_count,
        total_fees,
    };

    Ok(propose)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("Veldra Template Manager starting");

    // Load config from environment or use defaults
    let cfg = ManagerConfig::from_env();
    println!(
        "Using bitcoind RPC at {} with user {}",
        cfg.rpc_url, cfg.rpc_user
    );
    println!("Pool Verifier address: {}", cfg.verifier_addr);

    // Connect to local bitcoind on regtest to fetch the current chain tip
    let rpc_auth = Auth::UserPass(cfg.rpc_user.clone(), cfg.rpc_pass.clone());
    let rpc = Client::new(&cfg.rpc_url, rpc_auth)?;

    let block_count = rpc.get_block_count()?;
    let tip_hash = rpc.get_block_hash(block_count)?;
    println!("Regtest tip: height = {}, hash = {}", block_count, tip_hash);

    // ask bitcoind for a real block template
    // we keep it simple: default rules, no special params
    let gbt_args = json!({
    "rules": ["segwit"]
    });

    let gbt: Value = rpc.call("getblocktemplate", &[gbt_args])?;
    // height from template (should match block_count + 1 typically)
    let tpl_height = gbt["height"]
        .as_u64()
        .ok_or_else(|| anyhow::anyhow!("missing height in getblocktemplate"))? as u32;

    let prev_hash_from_tpl = gbt["previousblockhash"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing previousblockhash in getblocktemplate"))?
        .to_string();

    // transactions array; each entry has a "fee" field in sats
    let txs = gbt["transactions"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("missing transactions array in getblocktemplate"))?;

    let tx_count = txs.len() as u32;

    let mut total_fees: u64 = 0;
    for tx in txs {
        if let Some(fee) = tx["fee"].as_u64() {
            total_fees += fee;
        }
    }

    println!(
        "Template stats: height={}, prev_hash_len={}, tx_count={}, total_fees={}",
        tpl_height,
        prev_hash_from_tpl.len(),
        tx_count,
        total_fees
    );

    // connect to the Pool Verifier
    println!("Connecting to Pool Verifier at {}...", cfg.verifier_addr);
    let stream = TcpStream::connect(&cfg.verifier_addr).await?;
    println!("Connected to Pool Verifier");


    // split socket into reader and writer
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    let mut next_id: u64 = 1;

    loop {
        // build one proposal from current chain state
        let propose = build_proposal(&rpc, next_id).await?;
        next_id += 1;

        // send as JSON line
        let json = serde_json::to_string(&propose)?;
        println!("Sending TemplatePropose as JSON: {json}");
        writer.write_all(json.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;

        // read one verdict line back
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            anyhow::bail!("server closed connection before sending verdict");
        }

        println!("Raw verdict JSON received: {line}");

        let verdict: TemplateVerdict = serde_json::from_str(line.trim())?;
        println!(
            "Parsed verdict: id={}, accepted={}, reason={:?}",
            verdict.id, verdict.accepted, verdict.reason
        );

        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}
