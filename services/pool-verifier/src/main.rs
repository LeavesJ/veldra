use std::env;
use std::sync::{Arc, Mutex};

use axum::{routing::get, Router};
use rg_protocol::{TemplatePropose, TemplateVerdict, PROTOCOL_VERSION};
use serde::Serialize;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

mod policy;
use policy::{PolicyConfig, VerdictReason};

#[derive(Clone, Serialize)]
struct LoggedVerdict {
    id: u64,
    height: u32,
    total_fees: u64,
    accepted: bool,
    reason: Option<String>,
    timestamp: u64,
}

type VerdictLog = Arc<Mutex<Vec<LoggedVerdict>>>;

async fn run_tcp_server(
    policy_cfg: PolicyConfig,
    listen_addr: String,
    verdict_log: VerdictLog,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(&listen_addr).await?;
    println!("Veldra ReserveGrid Pool Verifier listening on {}", listen_addr);

    loop {
        let (socket, addr) = listener.accept().await?;
        println!("New connection from {addr}");

        let policy_cfg_clone = policy_cfg.clone();
        let log_clone = verdict_log.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_connection(socket, policy_cfg_clone, log_clone).await {
                eprintln!("Connection error from {addr}: {e}");
            }
        });
    }
}

#[derive(Clone)]
struct HttpState {
    policy: PolicyConfig,
    verdict_log: VerdictLog,
}

type SharedState = Arc<HttpState>;

async fn health_handler() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({ "status": "ok" }))
}

async fn policy_handler(
    axum::extract::State(state): axum::extract::State<SharedState>,
) -> axum::Json<PolicyConfig> {
    axum::Json(state.policy.clone())
}

async fn verdicts_handler(
    axum::extract::State(state): axum::extract::State<SharedState>,
) -> axum::Json<Vec<LoggedVerdict>> {
    let snapshot = {
        let guard = state.verdict_log.lock().unwrap();
        guard.clone()
    };
    axum::Json(snapshot)
}

async fn run_http_server(
    policy_cfg: PolicyConfig,
    http_addr: String,
    verdict_log: VerdictLog,
) -> anyhow::Result<()> {
    use std::net::SocketAddr;

    let state = Arc::new(HttpState {
        policy: policy_cfg,
        verdict_log,
    });

    let app = Router::new()
        .route("/health", get(health_handler))
        .route("/policy", get(policy_handler))
        .route("/verdicts", get(verdicts_handler))
        .with_state(state);

    let addr: SocketAddr = http_addr.parse()?;
    println!("HTTP API listening on http://{}", addr);

    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // addresses from env, with defaults
    let tcp_addr =
        env::var("VELDRA_VERIFIER_ADDR").unwrap_or("127.0.0.1:5001".to_string());
    let http_addr =
        env::var("VELDRA_HTTP_ADDR").unwrap_or("127.0.0.1:8080".to_string());

    // load policy from file or default
    let policy_cfg = match env::var("VELDRA_POLICY_PATH") {
        Ok(path) => {
            println!("Loading policy from {}", &path);
            PolicyConfig::from_file(&path)?
        }
        Err(_) => {
            println!("VELDRA_POLICY_PATH not set, using built in defaults");
            PolicyConfig::default_with_protocol(PROTOCOL_VERSION)
        }
    };

    println!("Effective policy: {:?}", policy_cfg);

    let verdict_log: VerdictLog = Arc::new(Mutex::new(Vec::new()));

    let tcp_policy = policy_cfg.clone();
    let http_policy = policy_cfg.clone();
    let tcp_log = verdict_log.clone();
    let http_log = verdict_log.clone();

    tokio::select! {
        res = run_tcp_server(tcp_policy, tcp_addr, tcp_log) => {
            res?;
        }
        res = run_http_server(http_policy, http_addr, http_log) => {
            res?;
        }
    }

    Ok(())
}

async fn handle_connection(
    stream: TcpStream,
    policy_cfg: PolicyConfig,
    verdict_log: VerdictLog,
) -> anyhow::Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    loop {
        line.clear();

        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            println!("Client closed connection");
            break;
        }

        println!("Raw JSON received: {line}");

        let propose: TemplatePropose = match serde_json::from_str(line.trim()) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("Failed to parse TemplatePropose: {e}");
                continue;
            }
        };

        println!(
            "Parsed TemplatePropose: id={}, height={}, prev_hash_len={}, coinbase_value={}, tx_count={}, total_fees={}",
            propose.id,
            propose.block_height,
            propose.prev_hash.len(),
            propose.coinbase_value,
            propose.tx_count,
            propose.total_fees,
        );

        let reason = policy::evaluate(&propose, &policy_cfg);

        let (accepted, reason_str) = match reason {
            VerdictReason::Ok => (true, None),
            VerdictReason::UnsupportedVersion { got, expected } => (
                false,
                Some(format!(
                    "Unsupported protocol version {}, expected {}",
                    got, expected
                )),
            ),
            VerdictReason::PrevHashWrongLen { len, expected } => (
                false,
                Some(format!(
                    "prev_hash has length {}, expected {}",
                    len, expected
                )),
            ),
            VerdictReason::CoinbaseZero => (
                false,
                Some("coinbase_value cannot be zero".to_string()),
            ),
            VerdictReason::TotalFeesTooLow { total, min_required } => (
                false,
                Some(format!(
                    "total_fees {} below minimum required {}",
                    total, min_required
                )),
            ),
            VerdictReason::TooManyTransactions { count, max_allowed } => (
                false,
                Some(format!(
                    "tx_count {} exceeds max allowed {}",
                    count, max_allowed
                )),
            ),
        };

        let verdict = TemplateVerdict {
            version: policy_cfg.protocol_version,
            id: propose.id,
            accepted,
            reason: reason_str.clone(),
        };

        use std::time::{SystemTime, UNIX_EPOCH};

        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let log_entry = LoggedVerdict {
            id: propose.id,
            height: propose.block_height,
            total_fees: propose.total_fees,
            accepted: verdict.accepted,
            reason: verdict.reason.clone(),
            timestamp: ts,
        };

        if let Ok(mut v) = verdict_log.lock() {
            v.push(log_entry);
            if v.len() > 50 {
                v.remove(0);
            }
        }

        let verdict_json = serde_json::to_string(&verdict)?;
        writer.write_all(verdict_json.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
        println!("Sent verdict: {verdict_json}");
    }

    Ok(())
}
