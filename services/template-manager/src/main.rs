use std::{
    collections::hash_map::DefaultHasher,
    env,
    hash::{Hash, Hasher},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{RwLock, mpsc};
use tokio::time::{Duration, sleep, timeout};

use axum::{Extension, Json, Router, routing::get};
use bitcoincore_rpc::json::{
    GetBlockTemplateCapabilities, GetBlockTemplateModes, GetBlockTemplateRules,
};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use serde::Serialize;

use rg_protocol::{PROTOCOL_VERSION, TemplatePropose, TemplateVerdict};

mod config;
use config::TemplateManagerConfig;

use async_trait::async_trait;

/// Source of block templates.
#[async_trait]
trait TemplateSource: Send {
    async fn next_template(&mut self) -> Result<Option<TemplatePropose>>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TemplateFingerprint {
    height: u64,
    prev_hash: String,
    tx_count: u32,
    total_fees: u64,
    txids_hash: u64,
}

fn hash_txids(txids: &[String]) -> u64 {
    // Order-independent hash so reordering doesn’t create fake “new templates”.
    let mut v = txids.to_vec();
    v.sort();
    let mut h = DefaultHasher::new();
    for t in v {
        t.hash(&mut h);
    }
    h.finish()
}

fn block_subsidy_sats(height: u32) -> u64 {
    // Bitcoin mainnet schedule. Regtest uses same unless you changed params.
    // 50 BTC = 5_000_000_000 sats at height 0, halves every 210_000 blocks.
    let halvings = height / 210_000;
    if halvings >= 64 {
        return 0;
    }
    (50u64 * 100_000_000u64) >> halvings
}

fn stable_template_id(fp: &TemplateFingerprint) -> u64 {
    let mut h = DefaultHasher::new();
    fp.height.hash(&mut h);
    fp.prev_hash.hash(&mut h);
    fp.tx_count.hash(&mut h);
    fp.total_fees.hash(&mut h);
    fp.txids_hash.hash(&mut h);
    h.finish()
}

fn build_bitcoind_client(cfg: &TemplateManagerConfig) -> anyhow::Result<Arc<Client>> {
    let url = cfg
        .rpc_url
        .clone()
        .unwrap_or_else(|| "http://127.0.0.1:18443".to_string());
    let user = cfg.rpc_user.clone().unwrap_or_else(|| "veldra".to_string());
    let pass = cfg
        .rpc_pass
        .clone()
        .unwrap_or_else(|| "very_secure_password".to_string());

    let auth = Auth::UserPass(user, pass);
    let client = Client::new(&url, auth).context("failed to create bitcoind RPC client")?;
    Ok(Arc::new(client))
}

/// Bitcoind-backed template source using getblocktemplate.
struct BitcoindTemplateSource {
    client: Arc<Client>,
    last_fp: Option<TemplateFingerprint>,
    had_rpc_error: bool,
}

impl BitcoindTemplateSource {
    fn new(client: Arc<Client>) -> Self {
        Self {
            client,
            last_fp: None,
            had_rpc_error: false,
        }
    }
}

#[async_trait]
impl TemplateSource for BitcoindTemplateSource {
    async fn next_template(&mut self) -> Result<Option<TemplatePropose>> {
        let mut attempts = 0;

        let tpl_opt = loop {
            let client = self.client.clone();

            // blocking RPC inside spawn_blocking
            let res = tokio::task::spawn_blocking(move || {
                client.get_block_template(
                    GetBlockTemplateModes::Template,
                    &[GetBlockTemplateRules::SegWit],
                    &[] as &[GetBlockTemplateCapabilities],
                )
            })
            .await;

            match res {
                Ok(Ok(t)) => break Some(t),
                Ok(Err(e)) => {
                    attempts += 1;
                    eprintln!("[manager] get_block_template attempt {attempts} failed: {e:?}");

                    if attempts >= 3 {
                        eprintln!(
                            "[manager] get_block_template giving up for this poll after {attempts} attempts (will retry next tick)"
                        );
                        self.had_rpc_error = true;
                        break None;
                    }

                    sleep(Duration::from_millis(200)).await;
                }
                Err(join_err) => {
                    attempts += 1;
                    eprintln!(
                        "[manager] get_block_template spawn_blocking join error attempt {attempts}: {join_err:?}"
                    );

                    if attempts >= 3 {
                        self.had_rpc_error = true;
                        break None;
                    }

                    sleep(Duration::from_millis(200)).await;
                }
            }
        };

        let tpl = match tpl_opt {
            Some(t) => {
                if self.had_rpc_error {
                    eprintln!("[manager] get_block_template RPC recovered");
                    self.had_rpc_error = false;
                }
                t
            }
            None => return Ok(None),
        };

        let block_height = tpl.height as u32;
        let prev_hash = tpl.previous_block_hash.to_string();

        let tx_count = tpl.transactions.len() as u32;
        let total_fees: u64 = tpl.transactions.iter().map(|tx| tx.fee.to_sat()).sum();

        let coinbase_raw: u64 = tpl.coinbase_value.to_sat();
        let coinbase_value: u64 = if coinbase_raw == 0 {
            let fallback = block_subsidy_sats(block_height) + total_fees;
            eprintln!(
                "[manager] WARNING coinbase_value=0 from getblocktemplate at height={} tx_count={} total_fees={}; using fallback={}",
                block_height, tx_count, total_fees, fallback
            );
            fallback
        } else {
            coinbase_raw
        };

        let txids: Vec<String> = tpl
            .transactions
            .iter()
            .map(|tx| tx.txid.to_string())
            .collect();

        let fp = TemplateFingerprint {
            height: block_height as u64,
            prev_hash: prev_hash.clone(),
            tx_count,
            total_fees,
            txids_hash: hash_txids(&txids),
        };

        if self.last_fp.as_ref() == Some(&fp) {
            return Ok(None);
        }

        // stable id BEFORE moving fp
        let id: u64 = stable_template_id(&fp);
        self.last_fp = Some(fp);

        Ok(Some(TemplatePropose {
            version: PROTOCOL_VERSION,
            id,
            block_height,
            prev_hash,
            coinbase_value,
            tx_count,
            total_fees,
            observed_weight: None,
            created_at_unix_ms: Some(now_unix_ms()),
        }))
    }
}

/// Stratum-backed template source.
/// Expects a local bridge that sends TemplatePropose as newline-delimited JSON.
struct StratumTemplateSource {
    rx: mpsc::Receiver<TemplatePropose>,
}

impl StratumTemplateSource {
    fn from_config(cfg: &TemplateManagerConfig) -> Self {
        let addr = cfg
            .stratum_addr
            .clone()
            .unwrap_or_else(|| "127.0.0.1:3333".to_string());
        let auth = cfg.stratum_auth.clone();

        println!(
            "StratumTemplateSource connecting to Stratum V2 bridge at {} auth_set={}",
            addr,
            auth.is_some()
        );

        let (tx, rx) = mpsc::channel::<TemplatePropose>(16);

        tokio::spawn(async move {
            loop {
                match TcpStream::connect(&addr).await {
                    Ok(stream) => {
                        println!("Connected to Stratum V2 bridge at {}", addr);
                        let mut reader = BufReader::new(stream);
                        let mut line = String::new();

                        loop {
                            line.clear();
                            let n = match reader.read_line(&mut line).await {
                                Ok(n) => n,
                                Err(e) => {
                                    eprintln!("error reading from Stratum V2 bridge: {e:?}");
                                    break;
                                }
                            };

                            if n == 0 {
                                println!("Stratum V2 bridge closed connection");
                                break;
                            }

                            let s = line.trim();
                            if s.is_empty() {
                                continue;
                            }

                            match serde_json::from_str::<TemplatePropose>(s) {
                                Ok(tpl) => {
                                    if tx.send(tpl).await.is_err() {
                                        eprintln!(
                                            "template channel closed, stopping Stratum V2 reader task"
                                        );
                                        return;
                                    }
                                }
                                Err(e) => {
                                    eprintln!(
                                        "failed to parse TemplatePropose JSON from Stratum V2 bridge: {e:?} line={:?}",
                                        s
                                    );
                                }
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("failed to connect to Stratum V2 bridge {}: {e:?}", addr);
                    }
                }

                sleep(Duration::from_secs(3)).await;
            }
        });

        Self { rx }
    }
}

#[async_trait]
impl TemplateSource for StratumTemplateSource {
    async fn next_template(&mut self) -> Result<Option<TemplatePropose>> {
        match self.rx.recv().await {
            Some(tpl) => Ok(Some(tpl)),
            None => anyhow::bail!("Stratum V2 bridge template channel disconnected"),
        }
    }
}

/// What we show over HTTP for recent templates.
#[derive(Clone, Serialize)]
struct LoggedTemplate {
    id: u64,
    height: u32,
    total_fees: u64,
    backend: String,
    timestamp: u64,
}

#[derive(Clone, Serialize)]
struct MempoolStats {
    loaded_from: String,
    tx_count: u64,
    bytes: u64,
    usage: u64,
    max: u64,
    min_relay_fee: u64,
    timestamp: u64,
}

type TemplateLog = Arc<RwLock<Vec<LoggedTemplate>>>;
type MempoolLog = Arc<RwLock<Option<MempoolStats>>>;

const TEMPLATE_LOG_CAP: usize = 500;

#[tokio::main]
async fn main() -> Result<()> {
    let cfg_path =
        env::var("VELDRA_MANAGER_CONFIG").unwrap_or_else(|_| "config/manager.toml".to_string());

    let cfg = TemplateManagerConfig::from_path(&cfg_path)?;
    println!("Loaded manager config from {}: {:?}", cfg_path, cfg);

    let verifier_addr = env::var("VELDRA_VERIFIER_ADDR")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            cfg.verifier_tcp_addr
                .clone()
                .filter(|s| !s.trim().is_empty())
        })
        .unwrap_or_else(|| "127.0.0.1:5001".to_string());

    let poll_secs: u64 = cfg.poll_interval_secs.unwrap_or(5).max(1);

    let http_addr = env::var("VELDRA_MANAGER_HTTP_ADDR")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            cfg.http_listen_addr
                .clone()
                .filter(|s| !s.trim().is_empty())
        })
        .unwrap_or_else(|| "127.0.0.1:8081".to_string());

    println!(
        "Template manager backend={} polling every {}s, sending to verifier {}, HTTP at {}",
        cfg.backend, poll_secs, verifier_addr, http_addr
    );

    // ---- SINGLE-INSTANCE LOCK ----
    // Bind HTTP listener *before* starting the manager loop.
    // If this fails, we exit immediately, preventing zombie duplicate senders.
    let listener: TcpListener = TcpListener::bind(&http_addr).await.with_context(|| {
        format!("failed to bind manager HTTP at {http_addr} (already running?)")
    })?;
    println!("Template manager HTTP listening on {}", http_addr);

    // choose backend + build shared bitcoind RPC client once
    let (source, backend_name, bitcoind_arc): (
        Box<dyn TemplateSource>,
        String,
        Option<Arc<Client>>,
    ) = match cfg.backend.trim().to_ascii_lowercase().as_str() {
        "bitcoind" => {
            let client: Arc<Client> = build_bitcoind_client(&cfg)?; // NOTE the `?`

            (
                Box::new(BitcoindTemplateSource::new(client.clone())) as Box<dyn TemplateSource>,
                "bitcoind".to_string(),
                Some(client),
            )
        }
        "stratum" => (
            Box::new(StratumTemplateSource::from_config(&cfg)) as Box<dyn TemplateSource>,
            "stratum".to_string(),
            None,
        ),
        other => anyhow::bail!(
            "Unsupported backend {:?} (expected \"bitcoind\" or \"stratum\")",
            other
        ),
    };

    let template_log: TemplateLog = Arc::new(RwLock::new(Vec::new()));
    let mempool_log: MempoolLog = Arc::new(RwLock::new(None));

    // build router once
    let app = build_router(template_log.clone(), mempool_log.clone());

    // run HTTP server (if it dies, we stop)
    let http_task = tokio::spawn(async move { axum::serve(listener, app).await });

    // run manager loop (if it dies, we stop)
    let manager_task = tokio::spawn(run_manager_loop(
        source,
        verifier_addr,
        poll_secs,
        backend_name.clone(),
        template_log,
        mempool_log,
        bitcoind_arc,
    ));

    // If either task exits, fail loudly. In a demo product, silent partial failure is poison.
    tokio::select! {
        r = http_task => {
            let r = r.context("HTTP task join failed")?;
            r.context("HTTP server exited")?;
            anyhow::bail!("HTTP server exited");
        }
        r = manager_task => {
            r.context("manager task join failed")??;
            anyhow::bail!("manager loop exited");
        }
    }
}

fn build_router(template_log: TemplateLog, mempool_log: MempoolLog) -> Router {
    Router::new()
        .route("/health", get(health_check))
        .route("/templates", get(get_templates))
        .route("/mempool", get(get_mempool))
        .layer(Extension(template_log))
        .layer(Extension(mempool_log))
}

async fn fetch_mempool_info_with_retries(
    client: Arc<Client>,
    mempool_had_rpc_error: &mut bool,
) -> Option<bitcoincore_rpc::json::GetMempoolInfoResult> {
    let mut attempts = 0;

    loop {
        let client2 = client.clone();
        let res = tokio::task::spawn_blocking(move || client2.get_mempool_info()).await;

        match res {
            Ok(Ok(info)) => {
                if *mempool_had_rpc_error {
                    eprintln!("[manager] get_mempool_info RPC recovered");
                    *mempool_had_rpc_error = false;
                }
                return Some(info);
            }
            Ok(Err(e)) => {
                attempts += 1;
                eprintln!("[manager] get_mempool_info attempt {attempts} failed: {e:?}");
            }
            Err(join_err) => {
                attempts += 1;
                eprintln!(
                    "[manager] get_mempool_info spawn_blocking join error attempt {attempts}: {join_err:?}"
                );
            }
        }

        if attempts >= 3 {
            eprintln!(
                "[manager] get_mempool_info giving up for this poll after {attempts} attempts (will retry next tick)"
            );
            *mempool_had_rpc_error = true;
            return None;
        }

        sleep(Duration::from_millis(200)).await;
    }
}

async fn run_manager_loop(
    mut source: Box<dyn TemplateSource>,
    verifier_addr: String,
    poll_secs: u64,
    backend_name: String,
    template_log: TemplateLog,
    mempool_log: MempoolLog,
    bitcoind_client: Option<Arc<Client>>,
) -> Result<()> {
    let mut mempool_had_rpc_error = false;

    let connect_timeout = Duration::from_secs(2);
    let verdict_timeout = Duration::from_secs(4);

    loop {
        // ---- template handling ----
        match source.next_template().await {
            Ok(Some(propose)) => {
                println!(
                    "New template backend={} id={} height={} prev_hash={} coinbase_value={} total_fees={} tx_count={}",
                    backend_name,
                    propose.id,
                    propose.block_height,
                    propose.prev_hash,
                    propose.coinbase_value,
                    propose.total_fees,
                    propose.tx_count,
                );

                match timeout(connect_timeout, TcpStream::connect(&verifier_addr)).await {
                    Ok(Ok(stream)) => {
                        match timeout(verdict_timeout, send_and_receive(stream, &propose)).await {
                            Ok(Ok(())) => {}
                            Ok(Err(e)) => eprintln!(
                                "[manager] error sending template id={} to verifier {}: {e:?}",
                                propose.id, verifier_addr
                            ),
                            Err(_) => eprintln!(
                                "[manager] verifier timed out (send/recv) id={} addr={}",
                                propose.id, verifier_addr
                            ),
                        }
                    }
                    Ok(Err(e)) => eprintln!(
                        "[manager] failed to connect to verifier {}: {e:?}",
                        verifier_addr
                    ),
                    Err(_) => eprintln!("[manager] connect timeout to verifier {}", verifier_addr),
                }

                // store for /templates
                {
                    let mut log = template_log.write().await;
                    log.push(LoggedTemplate {
                        id: propose.id,
                        height: propose.block_height,
                        total_fees: propose.total_fees,
                        backend: backend_name.clone(),
                        timestamp: now_unix_secs(),
                    });
                    if log.len() > TEMPLATE_LOG_CAP {
                        let drain = log.len() - TEMPLATE_LOG_CAP;
                        log.drain(0..drain);
                    }
                }
            }
            Ok(None) => {}
            Err(e) => eprintln!("[manager] error getting template from source: {e:?}"),
        }

        // ---- mempool snapshot when backend == bitcoind ----
        if backend_name == "bitcoind" {
            if let Some(ref client) = bitcoind_client {
                if let Some(info) =
                    fetch_mempool_info_with_retries(client.clone(), &mut mempool_had_rpc_error)
                        .await
                {
                    let stats = MempoolStats {
                        loaded_from: "bitcoind".to_string(),
                        tx_count: info.size as u64,
                        bytes: info.bytes as u64,
                        usage: info.usage as u64,
                        max: info.max_mempool as u64,
                        min_relay_fee: info.mempool_min_fee.to_sat(),
                        timestamp: now_unix_secs(),
                    };

                    let mut slot = mempool_log.write().await;
                    *slot = Some(stats);
                }
            } else {
                eprintln!("[manager] bitcoind_client is None while backend_name=bitcoind");
            }
        }

        if backend_name == "bitcoind" {
            sleep(Duration::from_secs(poll_secs)).await;
        }
    }
}

async fn send_and_receive(mut stream: TcpStream, propose: &TemplatePropose) -> Result<()> {
    let (reader, mut writer) = stream.split();
    let mut reader = BufReader::new(reader);

    let json = serde_json::to_string(propose)?;
    timeout(Duration::from_secs(2), writer.write_all(json.as_bytes())).await??;
    timeout(Duration::from_secs(2), writer.write_all(b"\n")).await??;
    timeout(Duration::from_secs(2), writer.flush()).await??;

    let mut line = String::new();
    let bytes_read = timeout(Duration::from_secs(3), reader.read_line(&mut line)).await??;
    if bytes_read == 0 {
        anyhow::bail!("verifier closed connection without sending a verdict");
    }

    let verdict: TemplateVerdict = serde_json::from_str(line.trim())?;
    println!(
        "Received TemplateVerdict id={} accepted={} reason_code={:?} detail={:?}",
        verdict.id, verdict.accepted, verdict.reason_code, verdict.reason_detail,
    );

    Ok(())
}

// HTTP handlers

async fn health_check() -> &'static str {
    "ok"
}

async fn get_templates(Extension(log): Extension<TemplateLog>) -> Json<Vec<LoggedTemplate>> {
    let log = log.read().await;
    Json(log.clone())
}

async fn get_mempool(Extension(mem): Extension<MempoolLog>) -> Json<MempoolStats> {
    let mem = mem.read().await;

    let snapshot = mem.clone().unwrap_or_else(|| MempoolStats {
        loaded_from: "unknown".to_string(),
        tx_count: 0,
        bytes: 0,
        usage: 0,
        max: 0,
        min_relay_fee: 0,
        timestamp: now_unix_secs(),
    });

    Json(snapshot)
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}
