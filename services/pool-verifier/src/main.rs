use std::collections::BTreeMap;
use std::env;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader as StdBufReader, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::state::{AppState, load_initial_policy};

use axum::{
    Json, Router,
    extract::{Extension, State},
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::{get, post},
};

use axum::body::Bytes;

use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

use pool_verifier::policy::{PolicyConfig, VerdictReason};
use rg_protocol::{PROTOCOL_VERSION, TemplatePropose, TemplateVerdict};

mod mempool_client;
mod state;
use mempool_client::{fetch_mempool_tx_count, mempool_url_from_env};

#[derive(Clone, Serialize, Deserialize)]
struct LoggedVerdict {
    pub log_id: u64,
    pub template_id: u64,
    pub height: u32,
    pub total_fees: u64,
    pub tx_count: u32,
    pub accepted: bool,
    pub reason: Option<String>,
    pub timestamp: u64,

    pub min_avg_fee_used: u64, // floor used for this decision
    pub fee_tier: String,      // "low" | "mid" | "high"

    pub avg_fee_sats_per_tx: u64,
}

#[derive(Serialize)]
struct StatsResponse {
    total: u64,
    accepted: u64,
    rejected: u64,
    by_reason: BTreeMap<String, u64>,
    by_tier: BTreeMap<String, u64>,
    last: Option<LoggedVerdict>,
}

#[derive(Deserialize)]
struct ApplyPolicyReq {
    low_mempool_tx: Option<u64>,
    high_mempool_tx: Option<u64>,
    min_avg_fee_lo: Option<u64>,
    min_avg_fee_mid: Option<u64>,
    min_avg_fee_hi: Option<u64>,
    min_total_fees: Option<u64>,
    max_tx_count: Option<u32>,
}

type VerdictLog = Arc<Mutex<Vec<LoggedVerdict>>>;
type LogIdCounter = Arc<AtomicU64>;

const VERDICT_LOG_PATH: &str = "data/verdicts.log";

fn load_verdict_log() -> (VerdictLog, LogIdCounter) {
    let mut list = Vec::new();
    let mut max_id = 0u64;

    if let Ok(file) = File::open(VERDICT_LOG_PATH) {
        let reader = StdBufReader::new(file);
        for line in reader.lines().map_while(Result::ok) {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Ok(v) = serde_json::from_str::<LoggedVerdict>(line) {
                if v.log_id > max_id {
                    max_id = v.log_id;
                }
                list.push(v);
            }
        }
    }

    let log = Arc::new(Mutex::new(list));
    let counter = Arc::new(AtomicU64::new(max_id + 1));
    (log, counter)
}

fn compute_avg_fee_sats_per_tx(t: &TemplatePropose) -> u64 {
    if t.tx_count == 0 {
        0
    } else {
        t.total_fees / t.tx_count as u64
    }
}

fn append_verdict_to_disk(v: &LoggedVerdict) {
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(VERDICT_LOG_PATH)
        && let Ok(line) = serde_json::to_string(v)
    {
        let _ = writeln!(file, "{}", line);
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // addresses from env, with defaults
    let tcp_addr =
        env::var("VELDRA_VERIFIER_ADDR").unwrap_or_else(|_| "127.0.0.1:5001".to_string());
    let http_addr = env::var("VELDRA_HTTP_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());

    // UI / mode label
    let ui_mode = env::var("VELDRA_DASH_MODE").unwrap_or_else(|_| "unknown".to_string());

    // load policy from file or default
    let policy_path =
        env::var("VELDRA_POLICY_FILE").unwrap_or_else(|_| "config/policy.toml".to_string());

    println!("Using policy file: {}", policy_path);

    let policy_holder =
        load_initial_policy(&policy_path).expect("Failed to load or construct initial policy");

    let app_state = AppState {
        policy: Arc::new(RwLock::new(policy_holder)),
    };

    // shared in-memory log
    let (verdict_log, log_id_counter) = load_verdict_log();
    println!(
        "Loaded {} verdicts from disk, next log_id={}",
        verdict_log.lock().unwrap().len(),
        log_id_counter.load(Ordering::Relaxed)
    );

    let tcp_state = app_state.clone();
    let tcp_log = verdict_log.clone();
    let tcp_log_counter = log_id_counter.clone();
    let http_log = verdict_log.clone();
    let http_ui_mode = ui_mode.clone();
    let http_state = app_state.clone();

    // read mempool url once (template-manager /mempool endpoint)
    let mempool_url = mempool_url_from_env();
    let tcp_mempool_url = mempool_url.clone();

    // TCP server task
    let tcp_task = tokio::spawn(async move {
        if let Err(e) = run_tcp_server(
            tcp_state,
            tcp_addr,
            tcp_log,
            tcp_mempool_url,
            tcp_log_counter,
        )
        .await
        {
            eprintln!("tcp server error: {e:?}");
        }
    });

    // HTTP server task
    let http_task = tokio::spawn(async move {
        if let Err(e) = run_http_server(http_addr, http_log, http_ui_mode, http_state).await {
            eprintln!("http server error: {e:?}");
        }
    });

    let _ = tokio::join!(tcp_task, http_task);

    Ok(())
}

async fn run_tcp_server(
    app_state: AppState,
    addr: String,
    verdict_log: VerdictLog,
    mempool_url: Option<String>,
    log_id_counter: LogIdCounter,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(&addr).await?;
    println!("TCP listening on {}", addr);

    loop {
        let (stream, _peer) = listener.accept().await?;
        let state_clone = app_state.clone();
        let log = verdict_log.clone();
        let url_clone = mempool_url.clone();
        let id_ctr = log_id_counter.clone();

        tokio::spawn(async move {
            let (reader, mut writer) = stream.into_split();
            let mut reader = BufReader::new(reader);
            let mut line = String::new();

            loop {
                line.clear();
                let _n = match reader.read_line(&mut line).await {
                    Ok(0) => break, // EOF
                    Ok(n) => n,
                    Err(e) => {
                        eprintln!("read error: {e:?}");
                        break;
                    }
                };

                let propose: TemplatePropose = match serde_json::from_str(&line) {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("parse error: {e:?}");
                        continue;
                    }
                };

                // fetch mempool tx_count from template-manager (if configured)
                let mempool_tx_count = if let Some(ref url) = url_clone {
                    fetch_mempool_tx_count(url).await
                } else {
                    None
                };

                // read live policy for each decision
                // Grab current policy snapshot
                let cfg = {
                    let holder = state_clone.policy.read().unwrap();
                    holder.config.clone()
                };

                let (min_avg_fee_used, fee_tier) =
                    cfg.effective_min_avg_fee_dynamic(mempool_tx_count);

                let avg_fee = compute_avg_fee_sats_per_tx(&propose);

                let mut accepted = true;
                let mut reason_enum = VerdictReason::Ok;

                // 0) reject empty templates if policy says so
                if accepted && cfg.reject_empty_templates && propose.tx_count == 0 {
                    accepted = false;
                    reason_enum = VerdictReason::EmptyTemplate;
                }

                // 0.5) real CoinbaseZero check
                if accepted && propose.coinbase_value == 0 {
                    accepted = false;
                    reason_enum = VerdictReason::CoinbaseZero;
                }

                // 1) Global min_total_fees
                if accepted && propose.total_fees < cfg.min_total_fees {
                    accepted = false;
                    reason_enum = VerdictReason::TotalFeesTooLow {
                        total: propose.total_fees,
                        min_required: cfg.min_total_fees,
                    };
                }

                // 2) Max tx count
                if accepted && (propose.tx_count as u32) > cfg.max_tx_count {
                    accepted = false;
                    reason_enum = VerdictReason::TooManyTransactions {
                        count: propose.tx_count,
                        max_allowed: cfg.max_tx_count,
                    };
                }

                // 3) Tiered fee floor
                if accepted && avg_fee < min_avg_fee_used {
                    accepted = false;
                    reason_enum = VerdictReason::AverageFeeTooLow {
                        avg: avg_fee,
                        min_required: min_avg_fee_used,
                    };
                }

                let reason_str = if matches!(reason_enum, VerdictReason::Ok) {
                    None
                } else {
                    Some(format!("{reason_enum:?}"))
                };

                let verdict = TemplateVerdict {
                    version: PROTOCOL_VERSION,
                    id: propose.id,
                    accepted,
                    reason: reason_str.clone(),
                };

                let log_id = id_ctr.fetch_add(1, Ordering::Relaxed);

                // build one LoggedVerdict
                let logged = LoggedVerdict {
                    log_id,
                    template_id: propose.id,
                    height: propose.block_height,
                    total_fees: propose.total_fees,
                    tx_count: propose.tx_count,
                    accepted,
                    reason: reason_str,
                    timestamp: current_timestamp(),
                    min_avg_fee_used,
                    fee_tier: fee_tier.as_str().to_string(),
                    avg_fee_sats_per_tx: avg_fee,
                };

                {
                    let mut guard = log.lock().unwrap();
                    guard.push(logged.clone());
                    const MAX_LOG: usize = 1000;
                    if guard.len() > MAX_LOG {
                        guard.remove(0);
                    }
                }

                append_verdict_to_disk(&logged);

                let json = match serde_json::to_string(&verdict) {
                    Ok(j) => j,
                    Err(e) => {
                        eprintln!("serialize verdict error: {e:?}");
                        break;
                    }
                };

                if let Err(e) = writer.write_all(json.as_bytes()).await {
                    eprintln!("write error: {e:?}");
                    break;
                }
                if let Err(e) = writer.write_all(b"\n").await {
                    eprintln!("write error: {e:?}");
                    break;
                }
                if let Err(e) = writer.flush().await {
                    eprintln!("flush error: {e:?}");
                    break;
                }
            }
        });
    }
}

// Simple HTML dashboard served at GET /
// Uses fetch to call /stats every 2 seconds and render the latest view.
static INDEX_HTML: &str = r##"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Veldra Pool Verifier</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    :root {
      color-scheme: dark;
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "SF Pro Text", sans-serif;
    }
      .recent-table td.num {
      text-align: right;
    }

    .recent-table td.mono {
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
    }

    .recent-table td.reason {
      max-width: 380px;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    body {
      margin: 0;
      padding: 0;
      background: #050712;
      color: #f5f5f5;
      display: flex;
      min-height: 100vh;
      justify-content: center;
      align-items: flex-start;
    }
    .page {
      width: 100%;
      max-width: 1040px;
      padding: 24px 16px 40px;
    }
    h1 {
      font-size: 24px;
      margin: 0 0 4px 0;
    }
    .subtitle {
      font-size: 13px;
      color: #9ba3b4;
      margin-bottom: 20px;
    }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 12px;
      margin-bottom: 20px;
    }
    .grid-wide {
      display: grid;
      grid-template-columns: minmax(0, 2.2fr) minmax(0, 1.5fr);
      gap: 12px;
      margin-top: 6px;
    }
    @media (max-width: 900px) {
      .grid-wide {
        grid-template-columns: minmax(0, 1fr);
      }
    }
    .card {
      background: radial-gradient(circle at top left, #1a2340, #0b0d1a);
      border-radius: 18px;
      padding: 14px 16px;
      box-shadow: 0 10px 30px rgba(0,0,0,0.55);
      border: 1px solid rgba(255,255,255,0.03);
    }
    .card h2 {
      font-size: 14px;
      margin: 0 0 8px 0;
      color: #c5d0ff;
    }
    .metric-main {
      font-size: 26px;
      font-weight: 600;
      margin-bottom: 2px;
    }
    .metric-sub {
      font-size: 13px;
      color: #9ba3b4;
    }
    .pill-row {
      display: flex;
      gap: 6px;
      flex-wrap: wrap;
      margin-top: 6px;
    }
    .pill {
      font-size: 11px;
      padding: 3px 8px;
      border-radius: 999px;
      border: 1px solid rgba(255,255,255,0.12);
      background: rgba(255,255,255,0.04);
      white-space: nowrap;
    }
    .pill.ok {
      border-color: #14b88f;
      color: #9ff6d7;
    }
    .pill.reject {
      border-color: #ff5370;
      color: #ffd3dd;
    }
    .pill.tier {
      border-color: #7c5cff;
      color: #d7c9ff;
    }
    .pill.id {
      border-color: rgba(255,255,255,0.12);
      color: #dfe3f0;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 12px;
      margin-top: 6px;
    }
    th, td {
      padding: 4px 0;
      text-align: left;
    }
    th {
      font-weight: 500;
      color: #9ba3b4;
    }
    tr + tr td {
      border-top: 1px solid rgba(255,255,255,0.04);
    }
    .reason-cell {
      max-width: 320px;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .muted {
      color: #737b8c;
    }
    .badge {
      display: inline-block;
      padding: 2px 7px;
      border-radius: 999px;
      font-size: 11px;
      border: 1px solid rgba(255,255,255,0.12);
      background: rgba(255,255,255,0.02);
      margin-left: 6px;
    }
    .status {
      font-size: 12px;
      margin-top: 4px;
      color: #818ba0;
    }
    .status span {
      font-weight: 500;
      color: #c5d0ff;
    }
    a.link {
      color: #7aa2ff;
      text-decoration: none;
      font-size: 12px;
    }
    a.link:hover {
      text-decoration: underline;
    }
    .tag-accepted {
      color: #9ff6d7;
    }
    .tag-rejected {
      color: #ffd3dd;
    }
    .tag-tier {
      color: #d7c9ff;
    }
    .mono {
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
    }
    .header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 16px;
    }
    .badge {
    font-size: 11px;
    padding: 4px 8px;
    border-radius: 999px;
    border: 1px solid #444;
    background: #151515;
    }
    .badge-click {
      cursor: pointer;
      user-select: none;
    }
    .badge-click:hover {
      background: rgba(255,255,255,0.08);
      border-color: rgba(255,255,255,0.18);
    }
    .badge-download {
      border-color: rgba(122, 162, 255, 0.9);
      color: #e0e7ff;
      background: radial-gradient(circle at top left,
                                  rgba(122, 162, 255, 0.26),
                                  rgba(122, 162, 255, 0.05));
      box-shadow: 0 0 0 1px rgba(122, 162, 255, 0.45);
    }

    .badge-download:hover {
      background: radial-gradient(circle at top left,
                                  rgba(122, 162, 255, 0.35),
                                  rgba(122, 162, 255, 0.10));
      box-shadow: 0 0 14px rgba(122, 162, 255, 0.60);
    }

    a.badge-download,
    a.badge-download:hover {
      text-decoration: none;
    }
    .badge-wizard {
      border-color: #ffb347;
      color: #ffe3b3;
      background: radial-gradient(circle at top left,
                                  rgba(255, 179, 71, 0.22),
                                  rgba(255, 179, 71, 0.04));
      box-shadow: 0 0 0 1px rgba(255, 179, 71, 0.35);
    }

    .badge-wizard:hover {
      background: radial-gradient(circle at top left,
                                  rgba(255, 179, 71, 0.30),
                                  rgba(255, 179, 71, 0.08));
      box-shadow: 0 0 14px rgba(255, 179, 71, 0.55);
    }
  
    #policy-debug {
      background: rgba(5, 10, 40, 0.9);
      border-radius: 10px;
      padding: 8px 10px;
      border: 1px solid rgba(255,255,255,0.06);
    }

    .wizard-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 8px 14px;
      margin-top: 6px;
      margin-bottom: 8px;
    }
    .wizard-label {
      font-size: 11px;
      color: #9ba3b4;
      margin-bottom: 2px;
    }
    .wizard-input {
      width: 100%;
      box-sizing: border-box;
      padding: 4px 6px;
      border-radius: 6px;
      border: 1px solid rgba(255,255,255,0.12);
      background: rgba(10,12,24,0.9);
      color: #f5f5f5;
      font-size: 12px;
    }
    .wizard-input:focus {
      outline: none;
      border-color: #7aa2ff;
      box-shadow: 0 0 0 1px rgba(122,162,255,0.5);
    }
    .wizard-output {
      width: 100%;
      margin-top: 8px;
      padding: 8px 10px;
      border-radius: 8px;
      border: 1px solid rgba(255,255,255,0.1);
      background: rgba(5,7,18,0.95);
      color: #dfe3f0;
      font-size: 11px;
      resize: vertical;
    }
  
  </style>
</head>
<body>
  <div class="page">
    <header class="header">
      <div>
        <h1>Veldra ReserveGrid OS</h1>
        <div class="subtitle">Pool verifier live view</div>
      </div>

      <div style="display:flex;align-items:center;gap:8px;">
        <a href="/verdicts/log"
          class="badge badge-download"
          id="download-log-link">download log</a>

        <a href="/verdicts.csv"
          class="badge badge-download"
          id="download-csv-link">download csv</a>

        <button class="badge badge-click badge-wizard"
                id="btn-open-wizard">open wizard</button>

        <div class="badge" id="badge-mode">mode: unknown</div>
        <div class="status" id="status-line">
          Last update: <span>never</span>
        </div>
      </div>
    </header>

    <div class="grid">
      <div class="card">
        <h2>Throughput</h2>
        <div class="metric-main" id="metric-total">0</div>
        <div class="metric-sub">
          <span id="metric-accepted">0</span> accepted,
          <span id="metric-rejected">0</span> rejected
        </div>
        <div class="pill-row">
          <div class="pill ok" id="pill-accept-rate">accept rate 0%</div>
        </div>
      </div>

      <div class="card">
        <h2>Fee tiers</h2>
        <div class="metric-main" id="metric-tier">none</div>
        <div class="metric-sub" id="metric-tier-detail">no verdicts yet</div>
        <div class="pill-row" id="pill-tiers"></div>
      </div>

      <div class="card">
        <h2>Latest verdict</h2>
        <div class="metric-main" id="metric-latest-result">n/a</div>
        <div class="metric-sub" id="metric-latest-fee">avg fee n/a</div>
        <div class="pill-row">
          <div class="pill id" id="pill-latest-id">id n/a</div>
          <div class="pill id" id="pill-latest-height">height n/a</div>
        </div>
      </div>

      <div class="card">
        <h2>Mempool</h2>
        <div class="metric-main" id="metric-mempool-tx">n/a</div>
        <div class="metric-sub" id="metric-mempool-bytes">bytes n/a</div>
        <div class="pill-row">
          <div class="pill" id="pill-mempool-tier">tier n/a</div>
        </div>
      </div>
    </div>

    <div class="grid-wide">
      <div class="card">
        <h2>
          Recent templates
          <span class="badge badge-click" id="badge-last">last 0</span>
          <span class="badge badge-click" id="badge-show-all">show all</span>
        </h2>
        <table>
          <thead>
            <tr>
              <th style="width: 90px;">time</th>
              <th style="width: 40px;">id</th>
              <th style="width: 60px;">height</th>
              <th style="width: 40px;">tier</th>
              <th style="width: 50px;">ratio</th>
              <th style="width: 70px;">decision</th>
              <th>reason</th>
            </tr>
          </thead>
          <tbody id="table-latest">
            <tr><td class="muted" colspan="7">no verdicts yet</td></tr>
          </tbody>
        </table>
      </div>

      <div class="card">
        <h2>Aggregates</h2>
        <table>
          <thead>
            <tr><th>reason</th><th style="width:60px;">count</th></tr>
          </thead>
          <tbody id="table-reasons">
            <tr><td class="muted" colspan="2">no data yet</td></tr>
          </tbody>
        </table>

        <table style="margin-top:14px;">
          <thead>
            <tr><th>tier</th><th style="width:60px;">count</th></tr>
          </thead>
          <tbody id="table-tiers">
            <tr><td class="muted" colspan="2">no tiers yet</td></tr>
          </tbody>
        </table>

        <div style="margin-top:10px;font-size:11px;">
          Mempool stats for regtest stay exposed as raw JSON at
          <a class="link" href="http://127.0.0.1:8081/mempool" target="_blank" rel="noreferrer">/mempool</a>.
        </div>

        <div style="margin-top:10px;font-size:11px;">
          Current policy:
          <pre id="policy-debug"
               class="mono muted"
               style="white-space:pre-wrap;font-size:11px;margin-top:4px;"></pre>
        </div>
      </div>
    </div>

        <div class="card" style="margin-top:16px;">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
            <h2 style="margin:0;">Policy wizard</h2>
            <button id="btn-open-wizard-footer" class="badge badge-click badge-wizard">
              open wizard
            </button>
          </div>

          <p class="metric-sub">
            Tweak fee tiers and mempool thresholds, then export a suggested
            <code>policy.toml</code> to paste into your config.
          </p>

          <div id="wizard-panel" style="display:none;margin-top:10px;">
            <div class="wizard-grid">
              <div>
                <div class="wizard-label">Low tier mempool &lt; tx</div>
                <input id="wiz-low-mempool" class="wizard-input" type="number" min="0" />
              </div>
              <div>
                <div class="wizard-label">High tier mempool ≥ tx</div>
                <input id="wiz-high-mempool" class="wizard-input" type="number" min="0" />
              </div>
              <div>
                <div class="wizard-label">Low tier floor sats/tx</div>
                <input id="wiz-fee-lo" class="wizard-input" type="number" min="0" />
              </div>
              <div>
                <div class="wizard-label">Mid tier floor sats/tx</div>
                <input id="wiz-fee-mid" class="wizard-input" type="number" min="0" />
              </div>
              <div>
                <div class="wizard-label">High tier floor sats/tx</div>
                <input id="wiz-fee-hi" class="wizard-input" type="number" min="0" />
              </div>
              <div>
                <div class="wizard-label">Min total fees sats</div>
                <input id="wiz-min-total" class="wizard-input" type="number" min="0" />
              </div>
              <div>
                <div class="wizard-label">Max tx count</div>
                <input id="wiz-max-tx" class="wizard-input" type="number" min="0" />
              </div>
            </div>

            <div style="margin-top:10px;display:flex;gap:8px;align-items:center;">
              <button id="btn-generate-toml" class="badge badge-click">
                generate policy.toml
              </button>
              <span class="metric-sub" id="wizard-status"></span>
            </div>

            <textarea id="wizard-output"
                      class="wizard-output mono"
                      rows="8"
                      readonly
                      placeholder="Generated policy.toml will appear here..."></textarea>
        </div>
      </div>
  </div>

  <script>
    const LATEST_LIMIT = 15;  // size of "last N" window
    let latestMode = "last";
    let showAllLog = false;
    let latestVerdicts = [];
    let wizardDirty = false;
    function setText(id, text) {
      var el = document.getElementById(id);
      if (el) el.textContent = text;
    }

    // shared wizard state for both buttons
    var wizardOpen = false;

    function setWizardOpen(open) {
      wizardOpen = !!open;

      var panel    = document.getElementById("wizard-panel");
      var btnTop   = document.getElementById("btn-open-wizard");
      var btnBottom = document.getElementById("btn-open-wizard-footer");

      if (panel) {
        panel.style.display = wizardOpen ? "block" : "none";
      }

      var label = wizardOpen ? "close wizard" : "open wizard";
      if (btnTop)    btnTop.textContent = label;
      if (btnBottom) btnBottom.textContent = label;
    }

    function setupWizard() {
      var btnTop    = document.getElementById("btn-open-wizard");
      var btnBottom = document.getElementById("btn-open-wizard-footer");
      var panel     = document.getElementById("wizard-panel");
      if (!panel) return;

      function toggle() {
        setWizardOpen(!wizardOpen);
      }

      if (btnTop) {
        btnTop.addEventListener("click", toggle);
      }
      if (btnBottom) {
        btnBottom.addEventListener("click", toggle);
      }

      var wizardIds = [
        "wiz-low-mempool",
        "wiz-high-mempool",
        "wiz-fee-lo",
        "wiz-fee-mid",
        "wiz-fee-hi",
        "wiz-min-total",
        "wiz-max-tx",
      ];

      wizardIds.forEach(function (id) {
        var el = document.getElementById(id);
        if (!el) return;
        el.addEventListener("input", function () {
          wizardDirty = true;
        });
      });

      // generate button stays as before
      var gen = document.getElementById("btn-generate-toml");
      if (gen) {
        gen.addEventListener("click", generateTomlFromWizard);
      }

      // start closed with consistent labels
      setWizardOpen(false);
    }

    function populateWizardFromPolicy(policy) {
      // once user touches the wizard, do not auto overwrite their inputs
      if (wizardDirty) return;
      if (!policy) return;

      function setVal(id, value) {
        var el = document.getElementById(id);
        if (el && value !== undefined && value !== null) {
          el.value = value;
        }
      }
      setVal("wiz-low-mempool", policy.low_mempool_tx);
      setVal("wiz-high-mempool", policy.high_mempool_tx);
      setVal("wiz-fee-lo",      policy.min_avg_fee_lo);
      setVal("wiz-fee-mid",     policy.min_avg_fee_mid);
      setVal("wiz-fee-hi",      policy.min_avg_fee_hi);
      setVal("wiz-min-total",   policy.min_total_fees);
      setVal("wiz-max-tx",      policy.max_tx_count);
    }

    function generateTomlFromWizard() {
      function getNum(id) {
        var el = document.getElementById(id);
        if (!el) return null;
        var v = el.value.trim();
        return v === "" ? null : Number(v);
      }

      var low   = getNum("wiz-low-mempool");
      var high  = getNum("wiz-high-mempool");
      var flo   = getNum("wiz-fee-lo");
      var fmid  = getNum("wiz-fee-mid");
      var fhi   = getNum("wiz-fee-hi");
      var minT  = getNum("wiz-min-total");
      var maxTx = getNum("wiz-max-tx");

      // Build TOML text just for display / copy
      var lines = [];
      lines.push("# Generated by Veldra dashboard wizard");
      lines.push("[policy]");
      if (low  != null)   lines.push("low_mempool_tx = "   + low);
      if (high != null)   lines.push("high_mempool_tx = "  + high);
      if (flo  != null)   lines.push("min_avg_fee_lo = "   + flo);
      if (fmid != null)   lines.push("min_avg_fee_mid = "  + fmid);
      if (fhi  != null)   lines.push("min_avg_fee_hi = "   + fhi);
      if (minT != null)   lines.push("min_total_fees = "   + minT);
      if (maxTx != null)  lines.push("max_tx_count = "     + maxTx);

      var toml = lines.join("\n");

      var out = document.getElementById("wizard-output");
      var status = document.getElementById("wizard-status");
      if (out) out.value = toml;
      if (status) status.textContent = "applying...";

      // Send JSON numbers to backend; backend mutates PolicyConfig directly
      fetch("/policy/apply", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          low_mempool_tx:   low,
          high_mempool_tx:  high,
          min_avg_fee_lo:   flo,
          min_avg_fee_mid:  fmid,
          min_avg_fee_hi:   fhi,
          min_total_fees:   minT,
          max_tx_count:     maxTx,
        }),
      })
        .then(function (res) {
          return res.text().then(function (text) {
            if (res.ok) {
              // backend accepted and validated the new config
              wizardDirty = false; // allow next /policy to repopulate debug, etc.
              if (status) status.textContent = "policy applied";
            } else {
              if (status) status.textContent = "error: " + text;
            }
          });
        })
        .catch(function (err) {
          console.error("apply policy failed", err);
          if (status) status.textContent = "network error";
        });
    }

    function renderTable(targetId, map, emptyText) {
      var tbody = document.getElementById(targetId);
      if (!tbody) return;
      while (tbody.firstChild) tbody.removeChild(tbody.firstChild);

      var keys = Object.keys(map || {});
      if (keys.length === 0) {
        var tr = document.createElement('tr');
        var td = document.createElement('td');
        td.colSpan = 2;
        td.textContent = emptyText;
        td.className = "muted";
        tr.appendChild(td);
        tbody.appendChild(tr);
        return;
      }

      keys.sort(function(a, b) { return map[b] - map[a]; });

      keys.forEach(function(k) {
        var tr = document.createElement('tr');
        var tdKey = document.createElement('td');
        var tdVal = document.createElement('td');
        tdKey.textContent = k;
        tdKey.className = targetId === "table-reasons" ? "reason-cell" : "";
        tdVal.textContent = map[k];
        tr.appendChild(tdKey);
        tr.appendChild(tdVal);
        tbody.appendChild(tr);
      });
    }

    function renderPillsForTiers(map) {
      var row = document.getElementById("pill-tiers");
      if (!row) return;
      while (row.firstChild) row.removeChild(row.firstChild);

      var keys = Object.keys(map || {});
      if (keys.length === 0) {
        var span = document.createElement("div");
        span.className = "pill tier";
        span.textContent = "no tier activity";
        row.appendChild(span);
        return;
      }

      keys.sort();
      keys.forEach(function(k) {
        var pill = document.createElement("div");
        pill.className = "pill tier";
        pill.textContent = k + " · " + map[k];
        row.appendChild(pill);
      });
    }

    function fmtPercent(num) {
      if (!isFinite(num)) return "0%";
      return num.toFixed(1).replace(/\.0$/, "") + "%";
    }

    function fmtTime(ts) {
      if (!ts && ts !== 0) return "";
      var d = new Date(ts * 1000);
      return d.toLocaleTimeString([], {hour: "2-digit", minute: "2-digit", second: "2-digit"});
    }

    function renderLatest(verdicts) {
      var tbody = document.getElementById("table-latest");
      if (!tbody) return;
      tbody.innerHTML = "";

      if (!Array.isArray(verdicts) || verdicts.length === 0) {
        var tr = document.createElement("tr");
        var td = document.createElement("td");
        td.colSpan = 7;
        td.textContent = "no verdicts yet";
        td.className = "muted";
        tr.appendChild(td);
        tbody.appendChild(tr);
        return;
      }

      verdicts.forEach(function (v) {
        var tr = document.createElement("tr");

        var tdTime = document.createElement("td");
        tdTime.textContent = fmtTime(v.timestamp);
        tdTime.className = "mono";

        var tdId = document.createElement("td");
        tdId.textContent = v.log_id ?? "";
        tdId.className = "mono";

        var tdHeight = document.createElement("td");
        tdHeight.textContent = v.height;
        tdHeight.className = "mono";

        var tdTier = document.createElement("td");
        tdTier.textContent = v.fee_tier || "";
        tdTier.className = "mono";

        var tdRatio = document.createElement("td");
        var ratioText;

        if (typeof v.min_avg_fee_used === "number" && v.min_avg_fee_used > 0) {
          var ratio = v.avg_fee_sats_per_tx / v.min_avg_fee_used;
          ratioText = ratio.toFixed(2);
        } else {
          ratioText = "n/a";  // or "∞", or leave blank
        }

        tdRatio.textContent = ratioText;
        tdRatio.className = "mono";

        var tdDecision = document.createElement("td");
        tdDecision.textContent = v.accepted ? "accepted" : "rejected";
        tdDecision.className = v.accepted ? "tag-accepted" : "tag-rejected";

        var tdReason = document.createElement("td");
        tdReason.textContent = v.reason || "Ok";
        tdReason.className = v.reason ? "" : "muted";

        tr.appendChild(tdTime);
        tr.appendChild(tdId);
        tr.appendChild(tdHeight);
        tr.appendChild(tdTier);
        tr.appendChild(tdRatio);
        tr.appendChild(tdDecision);
        tr.appendChild(tdReason);

        tbody.appendChild(tr);
      });
    }

    async function refresh() {
        try {
        // Fetch everything in parallel
        const [resStats, resVerdicts, resPolicy, resMempool, resMeta] = await Promise.all([
        fetch("/stats"),
        fetch("/verdicts"),
        fetch("/policy"),
        fetch("/mempool"),
        fetch("/meta"),
        ]);

        if (!resStats.ok)   throw new Error("stats HTTP "    + resStats.status);
        if (!resVerdicts.ok) throw new Error("verdicts HTTP " + resVerdicts.status);
        if (!resPolicy.ok)   throw new Error("policy HTTP "   + resPolicy.status);
        // mempool and meta are allowed to fail, we handle null below

        const data     = await resStats.json();
        const verdicts = await resVerdicts.json();
        latestVerdicts = Array.isArray(verdicts) ? verdicts.slice() : [];

        const slice = showAllLog
          ? latestVerdicts.slice().reverse()            // all
          : latestVerdicts.slice(-LATEST_LIMIT).reverse(); // last N

        // update the "last X" badge text on every refresh
        const lastBadge = document.getElementById("badge-last");
        if (lastBadge) {
          // cap at LATEST_LIMIT regardless of showAllLog
          const count = Math.min(LATEST_LIMIT, latestVerdicts.length);
          lastBadge.textContent = "last " + count;
        }

        // render the table rows
        renderLatest(slice);

        const policy   = await resPolicy.json();

        populateWizardFromPolicy(policy);

        let mempool = null;
        if (resMempool.ok) {
        try {
            mempool = await resMempool.json();
        } catch (_) {
            mempool = null;
        }
        }

        let meta = null;
        if (resMeta.ok) {
        try {
            meta = await resMeta.json();
        } catch (_) {
            meta = null;
        }
        }

        // ---------- basic stats ----------
        const total    = data.total    || 0;
        const accepted = data.accepted || 0;
        const rejected = data.rejected || 0;
        const byReason = data.by_reason || {};
        const byTier   = data.by_tier   || {};
        const last     = data.last      || null;

        setText("metric-total",    String(total));
        setText("metric-accepted", String(accepted));
        setText("metric-rejected", String(rejected));

        const rate = total > 0 ? (accepted * 100.0 / total) : 0;
        const pill = document.getElementById("pill-accept-rate");
        if (pill) pill.textContent = "accept rate " + fmtPercent(rate);

        renderTable("table-reasons", byReason, "no verdicts yet");
        renderTable("table-tiers",   byTier,   "no tiers yet");
        renderPillsForTiers(byTier);

    
        // ---------- latest verdict card ----------
        if (last) {
        const labelTier = last.fee_tier || "unknown";
        const labelFeeUsed =
            typeof last.min_avg_fee_used === "number"
            ? (last.min_avg_fee_used + " sats per tx")
            : "n/a";

        setText("metric-tier",        labelTier);
        setText("metric-tier-detail", "floor " + labelFeeUsed);

        const resultLabel = last.accepted ? "accepted" : "rejected";
        const resultElem  = document.getElementById("metric-latest-result");
        if (resultElem) {
            resultElem.textContent = resultLabel;
            resultElem.style.color = last.accepted ? "#9ff6d7" : "#ffd3dd";
        }

        setText("pill-latest-id", "id " + (last.log_id ?? ""));
        setText("pill-latest-height", "height " + last.height);

        const avgFeeLine =
            typeof last.avg_fee_sats_per_tx === "number"
            ? ("avg fee " + last.avg_fee_sats_per_tx + " sats/tx")
            : "avg fee n/a";
        setText("metric-latest-fee", avgFeeLine);
        } else {
        setText("metric-tier",             "none");
        setText("metric-tier-detail",      "no verdicts yet");
        setText("metric-latest-result",    "n/a");
        setText("metric-latest-fee",       "avg fee n/a");
        setText("pill-latest-id",          "id n/a");
        setText("pill-latest-height",      "height n/a");
        }

        // ---------- policy debug block ----------
        const pEl = document.getElementById("policy-debug");
        if (pEl) {
        if (policy) {
            const lo   = policy.low_mempool_tx;
            const hi   = policy.high_mempool_tx;
            const flo  = policy.min_avg_fee_lo;
            const fmid = policy.min_avg_fee_mid;
            const fhi  = policy.min_avg_fee_hi;

            const lines = [];

            if (typeof lo === "number" && typeof hi === "number") {
              const rows = [
                {
                  tier: "low",
                  window: "mempool < " + lo + " tx",
                  floor: "floor " + flo + " sats/tx",
                },
                {
                  tier: "mid",
                  window: lo + " ≤ mempool < " + hi + " tx",
                  floor: "floor " + fmid + " sats/tx",
                },
                {
                  tier: "high",
                  window: "mempool ≥ " + hi + " tx",
                  floor: "floor " + fhi + " sats/tx",
                },
              ];

              function pad(str, width) {
                return str + " ".repeat(Math.max(0, width - str.length));
              }

              const col1 = Math.max("tier".length, ...rows.map(r => r.tier.length));
              const col2 = Math.max("window".length, ...rows.map(r => r.window.length));
              const col3 = Math.max("floor".length, ...rows.map(r => r.floor.length));

              lines.push("Tier logic (by mempool tx count)");
              lines.push("");
              lines.push(
                "  " +
                  pad("tier", col1) +
                  "   " +
                  pad("window", col2) +
                  "   " +
                  pad("floor", col3)
              );
              lines.push(
                "  " +
                  "-".repeat(col1) +
                  "   " +
                  "-".repeat(col2) +
                  "   " +
                  "-".repeat(col3)
              );

              rows.forEach(r => {
                lines.push(
                  "  " +
                    pad(r.tier, col1) +
                    "   " +
                    pad(r.window, col2) +
                    "   " +
                    pad(r.floor, col3)
                );
              });
            }

            if (typeof policy.min_total_fees === "number") {
              lines.push("");
              lines.push("Other constraints");
              lines.push(
                "  min_total_fees = " +
                  policy.min_total_fees +
                  " sats"
              );
              lines.push(
                "  max_tx_count   = " +
                  policy.max_tx_count
              );
            }

            if (lines.length === 0 && typeof policy.debug === "string") {
            lines.push(policy.debug);
            }

            pEl.textContent = lines.join("\n");
        } else {
            pEl.textContent = "no policy info";
        }
        }

        // ---------- mempool card ----------
        const txEl    = document.getElementById("metric-mempool-tx");
        const bytesEl = document.getElementById("metric-mempool-bytes");
        const tierEl  = document.getElementById("pill-mempool-tier");

        if (mempool && !mempool.error && typeof mempool.tx_count === "number") {
          const tx     = mempool.tx_count;
          const usage  = mempool.usage;
          let usageStr = "";

          if (typeof usage === "number" && typeof mempool.max === "number" && mempool.max > 0) {
            const pct = (usage * 100.0 / mempool.max);
            usageStr = "usage " + pct.toFixed(1).replace(/\.0$/, "") + "%";
          } else if (typeof usage === "number") {
            usageStr = "usage " + usage + " bytes";
          } else if (typeof mempool.bytes === "number") {
            usageStr = "bytes " + mempool.bytes;
          } else {
            usageStr = "bytes n/a";
          }

          // staleness check
          let staleInfo = "";
          if (typeof mempool.timestamp === "number") {
            const nowSec = Date.now() / 1000;
            const ageSec = nowSec - mempool.timestamp;
            const ageText = ageSec.toFixed(0);
            if (ageSec > 30) {
              staleInfo = " • stale " + ageText + "s ago";
            } else {
              staleInfo = " • updated " + ageText + "s ago";
            }
          }

          if (txEl)    txEl.textContent    = String(tx);
          if (bytesEl) bytesEl.textContent = usageStr + staleInfo;

          let tierLabel = "n/a";
          if (policy) {
            const lo = policy.low_mempool_tx;
            const hi = policy.high_mempool_tx;
            if (typeof lo === "number" && typeof hi === "number") {
              if (tx < lo) tierLabel = "low";
              else if (tx < hi) tierLabel = "mid";
              else tierLabel = "high";
            }
          }

          if (tierEl) {
            tierEl.textContent = "expected tier " + tierLabel;
          }
        } else {
          if (txEl)    txEl.textContent    = "n/a";
          if (bytesEl) bytesEl.textContent = "no mempool backend";
          if (tierEl)  tierEl.textContent  = "tier n/a";
        }


        // ---------- mode badge ----------
        const badge = document.getElementById("badge-mode");
        if (badge && meta && meta.mode) {
        badge.textContent = "mode: " + meta.mode;
        }

        // ---------- status line ----------
        const status = document.getElementById("status-line");
        if (status) {
        const now = new Date();
        status.innerHTML = "Last update: <span>" +
            now.toLocaleTimeString() +
            "</span>";
        }
    } catch (err) {
        const status = document.getElementById("status-line");
        if (status) {
        status.innerHTML = "Last update: <span>error</span>";
        }
        console.error("refresh failed", err);
      }
  }

    function updateLogModeBadge() {
      const badge = document.getElementById("badge-log-mode");
      if (!badge) return;
      if (showAllLog) {
        badge.textContent = "showing all";
      } else {
        const n = latestVerdicts.length;
        const label = n <= 15 ? "last " + n : "last 15";
        badge.textContent = label;
      }
    }

    function toggleLogMode() {
      showAllLog = !showAllLog;
      const btn = document.getElementById("btn-toggle-log");
      if (btn) {
        btn.textContent = showAllLog ? "show last 15" : "show all";
      }

      const slice = showAllLog
        ? latestVerdicts.slice().reverse()
        : latestVerdicts.slice(-15).reverse();

      renderLatest(slice);
      updateLogModeBadge();
    }

    document.addEventListener("DOMContentLoaded", function () {
      const badgeLast     = document.getElementById("badge-last");
      const badgeShowAll  = document.getElementById("badge-show-all");

      if (badgeLast) {
        badgeLast.addEventListener("click", function () {
          showAllLog = false;
          refresh();
        });
      }

      if (badgeShowAll) {
        badgeShowAll.addEventListener("click", function () {
          showAllLog = true;
          refresh();
        });
      }

      setupWizard();
      refresh();
      setInterval(refresh, 3000);
    });

  </script>
</body>
</html>
"##;

async fn ui_index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

async fn run_http_server(
    bind_addr: String,
    verdict_log: VerdictLog,
    ui_mode: String,
    app_state: AppState,
) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/", get(ui_index))
        .route("/ui", get(ui_index))
        .route("/health", get(health_check))
        .route("/verdicts", get(get_verdicts))
        .route("/verdicts/log", get(get_verdict_log))
        .route("/verdicts.csv", get(get_verdicts_csv))
        .route("/stats", get(get_stats))
        .route("/policy", get(get_policy))
        .route("/policy/apply", post(apply_policy))
        .route("/policy/apply_toml", post(apply_policy_toml))
        .route("/mempool", get(get_mempool_proxy))
        .route("/meta", get(get_meta))
        .with_state(app_state.clone())
        .layer(Extension(verdict_log))
        .layer(Extension(ui_mode));

    let listener = TcpListener::bind(&bind_addr).await?;
    println!("HTTP listening on {}", bind_addr);
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health_check() -> &'static str {
    "ok"
}

async fn get_verdicts(Extension(log): Extension<VerdictLog>) -> Json<Vec<LoggedVerdict>> {
    let log = log.lock().unwrap();
    Json(log.clone())
}

async fn get_verdict_log() -> impl IntoResponse {
    let file = match File::open(VERDICT_LOG_PATH) {
        Ok(f) => f,
        Err(_) => {
            let body = "no verdicts yet\n".to_string();
            return (StatusCode::OK, [("Content-Type", "text/plain")], body);
        }
    };

    let reader = StdBufReader::new(file);

    let mut out = String::new();

    for line in reader.lines().map_while(Result::ok) {
        out.push_str(&line);
        out.push('\n');
    }

    (
        StatusCode::OK,
        [("Content-Type", "application/x-ndjson")],
        out,
    )
}

async fn get_verdicts_csv(Extension(log): Extension<VerdictLog>) -> impl IntoResponse {
    let log = log.lock().unwrap();

    let mut out = String::new();

    // header
    out.push_str("log_id,template_id,height,total_fees,tx_count,accepted,fee_tier,min_avg_fee_used,avg_fee_sats_per_tx,reason,timestamp\n");

    for v in log.iter() {
        let reason = v.reason.as_deref().unwrap_or("Ok");
        // escape double quotes in reason and wrap in quotes
        let escaped_reason = reason.replace('"', "\"\"");

        use std::fmt::Write as _;
        let _ = writeln!(
            out,
            "{},{},{},{},{},{},{},{},{},\"{}\",{}\n",
            v.log_id,
            v.template_id,
            v.height,
            v.total_fees,
            v.tx_count,
            v.accepted,
            v.fee_tier,
            v.min_avg_fee_used,
            v.avg_fee_sats_per_tx,
            escaped_reason,
            v.timestamp,
        );
    }

    (StatusCode::OK, [("Content-Type", "text/csv")], out)
}

async fn apply_policy(
    State(app_state): State<AppState>,
    Json(req): Json<ApplyPolicyReq>,
) -> impl IntoResponse {
    // Start from current config
    let base_cfg = {
        let holder = app_state.policy.read().unwrap();
        holder.config.clone()
    };

    // Apply changes to a local copy
    let mut cfg = base_cfg;
    if let Some(v) = req.low_mempool_tx {
        cfg.low_mempool_tx = v;
    }
    if let Some(v) = req.high_mempool_tx {
        cfg.high_mempool_tx = v;
    }
    if let Some(v) = req.min_avg_fee_lo {
        cfg.min_avg_fee_lo = v;
    }
    if let Some(v) = req.min_avg_fee_mid {
        cfg.min_avg_fee_mid = v;
    }
    if let Some(v) = req.min_avg_fee_hi {
        cfg.min_avg_fee_hi = v;
    }
    if let Some(v) = req.min_total_fees {
        cfg.min_total_fees = v;
    }
    if let Some(v) = req.max_tx_count {
        cfg.max_tx_count = v;
    }

    // Validate before committing
    if let Err(e) = cfg.validate() {
        return (
            StatusCode::BAD_REQUEST,
            format!("policy validation failed: {e:?}"),
        );
    }

    // Commit into AppState
    {
        let mut holder = app_state.policy.write().unwrap();
        holder.config = cfg;
        // Best effort debug text (you can improve this later if you care about exact TOML)
        holder.toml_text = format!("# updated via wizard\n# {:#?}", holder.config);
    }

    (StatusCode::OK, "ok".to_string())
}

async fn get_policy(State(app_state): State<AppState>) -> Json<serde_json::Value> {
    let holder = app_state.policy.read().unwrap();
    let policy = &holder.config;
    let dbg = format!("{policy:?}");

    let body = serde_json::json!({
        "protocol_version": policy.protocol_version,
        "required_prevhash_len": policy.required_prevhash_len,
        "min_total_fees": policy.min_total_fees,
        "max_tx_count": policy.max_tx_count,
        "min_avg_fee": policy.min_avg_fee,

        "low_mempool_tx": policy.low_mempool_tx,
        "high_mempool_tx": policy.high_mempool_tx,
        "min_avg_fee_lo": policy.min_avg_fee_lo,
        "min_avg_fee_mid": policy.min_avg_fee_mid,
        "min_avg_fee_hi": policy.min_avg_fee_hi,

        "max_weight_ratio": policy.max_weight_ratio,
        "reject_empty_templates": policy.reject_empty_templates,

        "debug": dbg
    });

    Json(body)
}

async fn get_meta(Extension(ui_mode): Extension<String>) -> Json<serde_json::Value> {
    let body = serde_json::json!({
        "mode": ui_mode,
    });
    Json(body)
}

async fn get_mempool_proxy() -> Json<serde_json::Value> {
    // reuse the same env source we use for fee hints
    let url_opt = mempool_url_from_env();
    let Some(url) = url_opt else {
        let body = serde_json::json!({
            "error": "VELDRA_MEMPOOL_URL not set"
        });
        return Json(body);
    };

    match reqwest::get(&url).await {
        Ok(resp) => match resp.json::<serde_json::Value>().await {
            Ok(json) => Json(json),
            Err(e) => {
                let body = serde_json::json!({
                    "error": format!("invalid mempool json: {e}")
                });
                Json(body)
            }
        },
        Err(e) => {
            let body = serde_json::json!({
                "error": format!("mempool fetch failed: {e}")
            });
            Json(body)
        }
    }
}

async fn get_stats(Extension(log): Extension<VerdictLog>) -> Json<StatsResponse> {
    let log = log.lock().unwrap();

    let mut total = 0_u64;
    let mut accepted = 0_u64;
    let mut rejected = 0_u64;
    let mut by_reason: BTreeMap<String, u64> = BTreeMap::new();
    let mut by_tier: BTreeMap<String, u64> = BTreeMap::new();

    for v in log.iter() {
        total += 1;

        if v.accepted {
            accepted += 1;
        } else {
            rejected += 1;
        }

        let reason_key = v
            .reason
            .as_ref()
            .cloned()
            .unwrap_or_else(|| "Ok".to_string());
        *by_reason.entry(reason_key).or_insert(0) += 1;

        *by_tier.entry(v.fee_tier.clone()).or_insert(0) += 1;
    }

    let last = log.last().cloned();

    Json(StatsResponse {
        total,
        accepted,
        rejected,
        by_reason,
        by_tier,
        last,
    })
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

async fn apply_policy_toml(State(app_state): State<AppState>, bytes: Bytes) -> impl IntoResponse {
    let body = match std::str::from_utf8(&bytes) {
        Ok(s) => s.to_string(),
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "ok": false,
                    "error": format!("body must be utf8 text: {}", e),
                })),
            );
        }
    };

    // Parse TOML into PolicyConfig the same way your file loader does:
    // the TOML shape is [policy] {...}
    #[derive(Deserialize)]
    struct Wrapper {
        policy: PolicyConfig,
    }

    let parsed: Wrapper = match toml::from_str(&body) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "ok": false,
                    "error": format!("toml parse failed: {}", e),
                })),
            );
        }
    };

    if let Err(e) = parsed.policy.validate() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "ok": false,
                "error": format!("policy validation failed: {:?}", e),
            })),
        );
    }

    {
        let mut holder = match app_state.policy.write() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };

        holder.config = parsed.policy;
        holder.toml_text = body;
    }

    (StatusCode::OK, Json(json!({ "ok": true })))
}
