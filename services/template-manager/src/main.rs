use std::{env, sync::{Arc, Mutex}, time::{Duration, SystemTime, UNIX_EPOCH}};

use anyhow::Result;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::sleep;

use bitcoincore_rpc::{Auth, Client, RpcApi};
use bitcoincore_rpc::json::{
    GetBlockTemplateCapabilities,
    GetBlockTemplateModes,
    GetBlockTemplateRules,
};
use axum::{routing::get, Extension, Json, Router};
use serde::Serialize;

use rg_protocol::{TemplatePropose, TemplateVerdict, PROTOCOL_VERSION};

mod config;
use config::TemplateManagerConfig;

/// Source of block templates.
trait TemplateSource: Send {
    /// Returns Some(template) if there is a new template, or None if nothing changed.
    fn next_template(&mut self) -> Result<Option<TemplatePropose>>;
}

/// Bitcoind-backed template source using getblocktemplate.
struct BitcoindTemplateSource {
    client: Client,
    next_id: u64,
    last_key: Option<(u32, String)>, // (height, prev_hash)
    had_rpc_error: bool,
}

impl BitcoindTemplateSource {
    fn from_config(cfg: &TemplateManagerConfig) -> Self {
        let url = cfg
            .rpc_url
            .clone()
            .unwrap_or_else(|| "http://127.0.0.1:18443".to_string());
        let user = cfg
            .rpc_user
            .clone()
            .unwrap_or_else(|| "veldra".to_string());
        let pass = cfg
            .rpc_pass
            .clone()
            .unwrap_or_else(|| "very_secure_password".to_string());

        let auth = Auth::UserPass(user, pass);
        let client = Client::new(&url, auth).expect("failed to create bitcoind RPC client");

        BitcoindTemplateSource {
            client,
            next_id: 1,
            last_key: None,
            had_rpc_error: false,
        }
    }
}

impl TemplateSource for BitcoindTemplateSource {
    fn next_template(&mut self) -> Result<Option<TemplatePropose>> {
        let mut attempts = 0;
        let tpl_opt = loop {
            match self.client.get_block_template(
                GetBlockTemplateModes::Template,
                &[GetBlockTemplateRules::SegWit],
                &[] as &[GetBlockTemplateCapabilities],
            ) {
                Ok(t) => break Some(t),
                Err(e) => {
                    attempts += 1;
                    eprintln!(
                        "[manager] get_block_template attempt {attempts} failed: {e:?}"
                    );

                    if attempts >= 3 {
                        eprintln!(
                            "[manager] get_block_template giving up for this poll after {attempts} attempts (will retry next tick)"
                        );
                        self.had_rpc_error = true;   
                        break None;
                    }

                    // small backoff before retrying
                    std::thread::sleep(Duration::from_millis(200));
                }
            }
        };

        // if we still could not get a template, degrade gracefully: no new work
        let tpl = match tpl_opt {
            Some(t) => {
                if self.had_rpc_error {
                    eprintln!("[manager] get_block_template RPC recovered");
                    self.had_rpc_error = false;
                }
                t
            }
            None => {
                return Ok(None);
            }
        };

        let block_height = tpl.height as u32;
        let prev_hash = tpl.previous_block_hash.to_string();

        let key = (block_height, prev_hash.clone());
        if Some(key.clone()) == self.last_key {
            // same height + prev_hash as last time, skip
            return Ok(None);
        }

        self.last_key = Some(key);
        let id = self.next_id;
        self.next_id += 1;

        let coinbase_value: u64 = tpl.coinbase_value.to_sat();
        let tx_count = tpl.transactions.len() as u32;
        let total_fees: u64 = tpl
            .transactions
            .iter()
            .map(|tx| tx.fee.to_sat())
            .sum();

        let proposal = TemplatePropose {
            version: PROTOCOL_VERSION,
            id,
            block_height,
            prev_hash,
            coinbase_value,
            tx_count,
            total_fees,
        };

        Ok(Some(proposal))
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
            "StratumTemplateSource connecting to Stratum V2 bridge at {} auth={:?}",
            addr, auth
        );

        let (tx, rx) = mpsc::channel::<TemplatePropose>(16);

        tokio::spawn(async move {
            loop {
                match TcpStream::connect(&addr).await {
                    Ok(stream) => {
                        println!("Connected to Stratum V2 bridge at {}", addr);
                        // keep whole stream alive
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

                            match serde_json::from_str::<TemplatePropose>(&line) {
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
                                        "failed to parse TemplatePropose JSON from Stratum V2 bridge: {e:?}"
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

        StratumTemplateSource { rx }
    }
}

impl TemplateSource for StratumTemplateSource {
    fn next_template(&mut self) -> Result<Option<TemplatePropose>> {
        use tokio::sync::mpsc::error::TryRecvError;

        match self.rx.try_recv() {
            Ok(tpl) => Ok(Some(tpl)),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => {
                anyhow::bail!("Stratum V2 bridge template channel disconnected")
            }
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

type TemplateLog = Arc<Mutex<Vec<LoggedTemplate>>>;
type MempoolLog = Arc<Mutex<Option<MempoolStats>>>;

#[tokio::main]
async fn main() -> Result<()> {
    // manager config path
    let cfg_path = env::var("VELDRA_MANAGER_CONFIG")
        .unwrap_or_else(|_| "manager.toml".to_string());

    let cfg = TemplateManagerConfig::from_path(&cfg_path)?;
    println!("Loaded manager config from {}: {:?}", cfg_path, cfg);

    let verifier_addr =
        env::var("VELDRA_VERIFIER_ADDR").unwrap_or_else(|_| "127.0.0.1:5001".to_string());

    let poll_secs: u64 = cfg.poll_interval_secs.unwrap_or(5);

    let http_addr = env::var("VELDRA_MANAGER_HTTP_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8081".to_string());

    println!(
        "Template manager backend={} polling every {}s, sending to verifier {}, HTTP at {}",
        cfg.backend, poll_secs, verifier_addr, http_addr
    );

    // choose backend
    let source: Box<dyn TemplateSource> = match cfg.backend.as_str() {
        "bitcoind" => Box::new(BitcoindTemplateSource::from_config(&cfg)),
        "stratum" => Box::new(StratumTemplateSource::from_config(&cfg)),
        other => {
            panic!("Unsupported backend {:?} (expected \"bitcoind\" or \"stratum\")", other);
        }
    };

    let backend_name = cfg.backend.clone();

    let bitcoind_client = if backend_name == "bitcoind" {
        let url = cfg
            .rpc_url
            .clone()
            .unwrap_or_else(|| "http://127.0.0.1:18443".to_string());
        let user = cfg
            .rpc_user
            .clone()
            .unwrap_or_else(|| "veldra".to_string());
        let pass = cfg
            .rpc_pass
            .clone()
            .unwrap_or_else(|| "very_secure_password".to_string());

        let auth = Auth::UserPass(user, pass);
        Some(Client::new(&url, auth).expect("failed to create bitcoind RPC client for mempool"))
    } else {
        None
    };

    let template_log: TemplateLog = Arc::new(Mutex::new(Vec::new()));
    let mempool_log: MempoolLog = Arc::new(Mutex::new(None));

    // spawn HTTP server
    let http_tpl_log = template_log.clone();
    let http_mempool_log = mempool_log.clone();
    let http_task = tokio::spawn(async move {
        if let Err(e) = run_http_server(http_addr, http_tpl_log, http_mempool_log).await {
            eprintln!("manager HTTP server error: {e:?}");
        }
    });

    // spawn manager loop
    let manager_task = tokio::spawn(async move {
        if let Err(e) = run_manager_loop(
            source,
            verifier_addr,
            poll_secs,
            backend_name,
            template_log,
            mempool_log,
            bitcoind_client,
        )
        .await
        {
            eprintln!("manager loop error: {e:?}");
        }
    });


    let _ = tokio::join!(http_task, manager_task);

    Ok(())
}

async fn run_manager_loop(
    mut source: Box<dyn TemplateSource>,
    verifier_addr: String,
    poll_secs: u64,
    backend_name: String,
    template_log: TemplateLog,
    mempool_log: MempoolLog,
    bitcoind_client: Option<Client>,
) -> Result<()> {
    let mut mempool_had_rpc_error = false;
    loop {
        // template handling
        match source.next_template() {
            Ok(Some(mut propose)) => {
                println!(
                    "New template from backend={} id={} height={} total_fees={} tx_count={}",
                    backend_name,
                    propose.id,
                    propose.block_height,
                    propose.total_fees,
                    propose.tx_count,
                );

                // connect to verifier and send + receive verdict, but never kill the loop
                match TcpStream::connect(&verifier_addr).await {
                    Ok(stream) => {
                        if let Err(e) = send_and_receive(stream, &mut propose).await {
                            eprintln!(
                                "[manager] error sending template id={} to verifier {}: {e:?}",
                                propose.id, verifier_addr
                            );
                        }
                    }
                    Err(e) => {
                        eprintln!(
                            "[manager] failed to connect to verifier {}: {e:?}",
                            verifier_addr
                        );
                    }
                }

                // store in in-memory log for /templates
                {
                    let mut log = template_log.lock().unwrap();
                    log.push(LoggedTemplate {
                        id: propose.id,
                        height: propose.block_height,
                        total_fees: propose.total_fees,
                        backend: backend_name.clone(),
                        timestamp: current_timestamp(),
                    });
                }
            }
            Ok(None) => {
                // nothing new this tick
            }
            Err(e) => {
                eprintln!("[manager] error getting template from source: {e:?}");
            }
        }

        // mempool snapshot when backend == bitcoind
        if backend_name == "bitcoind" {
            if let Some(ref client) = bitcoind_client {
                let mut attempts = 0;
                let info_opt = loop {
                    match client.get_mempool_info() {
                        Ok(info) => break Some(info),
                        Err(e) => {
                            attempts += 1;
                            eprintln!(
                                "[manager] get_mempool_info attempt {attempts} failed: {e:?}"
                            );

                            if attempts >= 3 {
                                eprintln!(
                                    "[manager] get_mempool_info giving up for this poll after {attempts} attempts (will retry next tick)"
                                );
                                mempool_had_rpc_error = true;
                                break None;
                            }

                            std::thread::sleep(Duration::from_millis(200));
                        }
                    }
                };

                if let Some(info) = info_opt {
                    if mempool_had_rpc_error {
                        eprintln!("[manager] get_mempool_info RPC recovered");
                        mempool_had_rpc_error = false;
                    }

                    let stats = MempoolStats {
                        loaded_from: "bitcoind".to_string(),
                        tx_count: info.size as u64,
                        bytes: info.bytes as u64,
                        usage: info.usage as u64,
                        max: info.max_mempool as u64,
                        min_relay_fee: info.mempool_min_fee.to_sat(),
                        timestamp: current_timestamp(),
                    };
                    let mut slot = mempool_log.lock().unwrap();
                    *slot = Some(stats);
                }
            } else {
                eprintln!("[manager] bitcoind_client is None while backend_name=bitcoind");
            }

                sleep(Duration::from_secs(poll_secs)).await;
        }
    }
}




async fn send_and_receive(mut stream: TcpStream, propose: &mut TemplatePropose) -> Result<()> {
    let (reader, mut writer) = stream.split();
    let mut reader = BufReader::new(reader);

    let json = serde_json::to_string(&propose)?;
    writer.write_all(json.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;

    println!(
        "Sent TemplatePropose id={} height={}",
        propose.id, propose.block_height
    );

    let mut line = String::new();
    let bytes_read = reader.read_line(&mut line).await?;
    if bytes_read == 0 {
        println!("Verifier closed connection without sending a verdict");
        return Ok(());
    }

    let verdict: TemplateVerdict = serde_json::from_str(&line)?;
    println!(
        "Received TemplateVerdict id={} accepted={} reason={:?}",
        verdict.id, verdict.accepted, verdict.reason
    );

    Ok(())
}

// HTTP server

async fn run_http_server(
    bind_addr: String,
    template_log: TemplateLog,
    mempool_log: MempoolLog,
) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/health", get(health_check))
        .route("/templates", get(get_templates))
        .route("/mempool", get(get_mempool))
        .layer(Extension(template_log))
        .layer(Extension(mempool_log));

    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    println!("Template manager HTTP listening on {}", bind_addr);

    axum::serve(listener, app).await?;
    Ok(())
}

async fn health_check() -> &'static str {
    "ok"
}

async fn get_templates(
    Extension(log): Extension<TemplateLog>,
) -> Json<Vec<LoggedTemplate>> {
    let log = log.lock().unwrap();
    Json(log.clone())
}

async fn get_mempool(
    Extension(mem): Extension<MempoolLog>,
) -> Json<MempoolStats> {
    let mem = mem.lock().unwrap();

    let snapshot = mem.clone().unwrap_or_else(|| MempoolStats {
        loaded_from: "unknown".to_string(),
        tx_count: 0,
        bytes: 0,
        usage: 0,
        max: 0,
        min_relay_fee: 0,
        timestamp: current_timestamp(),
    });

    Json(snapshot)
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
