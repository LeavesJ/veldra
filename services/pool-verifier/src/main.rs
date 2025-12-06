use std::collections::BTreeMap;
use std::env;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{extract::Extension, routing::get, Json, Router, response::Html};
use serde::Serialize;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

use pool_verifier::policy::{PolicyConfig, VerdictReason};
use rg_protocol::{TemplatePropose, TemplateVerdict, PROTOCOL_VERSION};

mod mempool_client;
use mempool_client::{fetch_mempool_tx_count, mempool_url_from_env};

#[derive(Clone, Serialize)]
struct LoggedVerdict {
    pub id: u64,
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

type VerdictLog = Arc<Mutex<Vec<LoggedVerdict>>>;

fn compute_avg_fee_sats_per_tx(t: &TemplatePropose) -> u64 {
    if t.tx_count == 0 {
        0
    } else {
        t.total_fees / t.tx_count as u64
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // addresses from env, with defaults
    let tcp_addr =
        env::var("VELDRA_VERIFIER_ADDR").unwrap_or_else(|_| "127.0.0.1:5001".to_string());
    let http_addr =
        env::var("VELDRA_HTTP_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());

    // UI / mode label
    let ui_mode = env::var("VELDRA_DASH_MODE").unwrap_or_else(|_| "unknown".to_string());

    // load policy from file or default
    let policy_path =
        env::var("VELDRA_POLICY_PATH").unwrap_or_else(|_| "policy.toml".to_string());

    println!("Using policy file: {}", policy_path);

    let policy_cfg = match PolicyConfig::from_file(&policy_path) {
        Ok(cfg) => {
            println!("Loaded policy: {:?}", cfg);
            if let Err(e) = cfg.validate() {
                panic!("Policy validation failed: {e:?}");
            }
            cfg
        }
        Err(e) => {
            println!(
                "Failed to load policy at {} (using default_with_protocol): {e:?}",
                policy_path
            );
            let cfg = PolicyConfig::default_with_protocol(PROTOCOL_VERSION);
            if let Err(e) = cfg.validate() {
                panic!("Default policy validation failed: {e:?}");
            }
            cfg
        }
    };

    println!("Effective policy: {:?}", policy_cfg);

    // shared in-memory log
    let verdict_log: VerdictLog = Arc::new(Mutex::new(Vec::new()));

    let tcp_policy = policy_cfg.clone();
    let tcp_log = verdict_log.clone();
    let http_log = verdict_log.clone();
    let http_policy = policy_cfg.clone();
    let http_ui_mode = ui_mode.clone();

    // read mempool url once (template-manager /mempool endpoint)
    let mempool_url = mempool_url_from_env();
    let tcp_mempool_url = mempool_url.clone();

    // TCP server task
    let tcp_task = tokio::spawn(async move {
    if let Err(e) = run_tcp_server(tcp_policy, tcp_addr, tcp_log, tcp_mempool_url).await {
        eprintln!("tcp server error: {e:?}");
        }
    });

    // HTTP server task
    let http_task = tokio::spawn(async move {
    if let Err(e) = run_http_server(http_addr, http_log, http_policy, http_ui_mode).await {
        eprintln!("http server error: {e:?}");
        }
    });
    
    let _ = tokio::join!(tcp_task, http_task);

    Ok(())
}

async fn run_tcp_server(
    policy_cfg: PolicyConfig,
    addr: String,
    verdict_log: VerdictLog,
    mempool_url: Option<String>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(&addr).await?;
    println!("TCP listening on {}", addr);

    loop {
        let (stream, _peer) = listener.accept().await?;
        let policy = policy_cfg.clone();
        let log = verdict_log.clone();
        let url_clone = mempool_url.clone();

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

                let (min_avg_fee_used, fee_tier) =
                    policy.effective_min_avg_fee_dynamic(mempool_tx_count);

                let avg_fee = compute_avg_fee_sats_per_tx(&propose);
                let accepted = avg_fee >= min_avg_fee_used;

                let reason_enum = if accepted {
                    VerdictReason::Ok
                } else {
                    VerdictReason::AverageFeeTooLow {
                        avg: avg_fee,
                        min_required: min_avg_fee_used,
                    }
                };

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

                {
                    let mut guard = log.lock().unwrap();
                    guard.push(LoggedVerdict {
                        id: propose.id,
                        height: propose.block_height,
                        total_fees: propose.total_fees,
                        tx_count: propose.tx_count,
                        accepted,
                        reason: reason_str,
                        timestamp: current_timestamp(),
                        min_avg_fee_used,
                        fee_tier: fee_tier.as_str().to_string(), // enum → "low"/"mid"/"high"
                        avg_fee_sats_per_tx: avg_fee,
                    });

                    const MAX_LOG: usize = 1000;
                    if guard.len() > MAX_LOG {
                        let excess = guard.len() - MAX_LOG;
                        guard.drain(0..excess);
                    }
                }

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
        <div class="badge" id="badge-mode">mode: unknown</div>
        <div class="status" id="status-line">Last update: <span>never</span></div>
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
        <h2>Recent templates <span class="badge">last 15</span></h2>
        <table>
          <thead>
            <tr>
              <th style="width:70px;">time</th>
              <th style="width:60px;">id</th>
              <th style="width:70px;">height</th>
              <th style="width:70px;">tier</th>
              <th style="width:80px;">decision</th>
              <th>reason</th>
            </tr>
          </thead>
          <tbody id="table-latest">
            <tr><td class="muted" colspan="6">no verdicts yet</td></tr>
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
  </div>

  <script>
    function setText(id, text) {
      var el = document.getElementById(id);
      if (el) el.textContent = text;
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
      while (tbody.firstChild) tbody.removeChild(tbody.firstChild);

      if (!Array.isArray(verdicts) || verdicts.length === 0) {
        var tr = document.createElement("tr");
        var td = document.createElement("td");
        td.colSpan = 6;
        td.textContent = "no verdicts yet";
        td.className = "muted";
        tr.appendChild(td);
        tbody.appendChild(tr);
        return;
      }

      verdicts.forEach(function(v) {
        var tr = document.createElement("tr");

        var tdTime = document.createElement("td");
        tdTime.textContent = fmtTime(v.timestamp);
        tdTime.className = "mono";

        var tdId = document.createElement("td");
        tdId.textContent = v.id;
        tdId.className = "mono";

        var tdHeight = document.createElement("td");
        tdHeight.textContent = v.height;
        tdHeight.className = "mono";

        var tdTier = document.createElement("td");
        tdTier.textContent = v.fee_tier || "";
        tdTier.className = "mono";

        var tdDecision = document.createElement("td");
        tdDecision.textContent = v.accepted ? "accepted" : "rejected";
        tdDecision.className = v.accepted ? "tag-accepted" : "tag-rejected";

        var tdReason = document.createElement("td");
        tdReason.textContent = v.reason || "Ok";
        tdReason.className = v.reason ? "reason-cell" : "muted";

        tr.appendChild(tdTime);
        tr.appendChild(tdId);
        tr.appendChild(tdHeight);
        tr.appendChild(tdTier);
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
        const policy   = await resPolicy.json();

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

        // recent 15 templates, newest first
        const latest = Array.isArray(verdicts) ? verdicts.slice(-15).reverse() : [];
        renderLatest(latest);  

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

        setText("pill-latest-id",     "id "     + last.id);
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
            lines.push("Tier logic (by mempool tx count):");
            lines.push("  low:  mempool < " + lo + " tx  → floor " + flo  + " sats/tx");
            lines.push("  mid:  " + lo + " ≤ mempool < " + hi + " tx  → floor " + fmid + " sats/tx");
            lines.push("  high: mempool ≥ " + hi + " tx  → floor " + fhi  + " sats/tx");
            }

            if (typeof policy.min_total_fees === "number") {
            lines.push("");
            lines.push(
                "Other constraints: min_total_fees = " + policy.min_total_fees +
                " sats, max_tx_count = " + policy.max_tx_count
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

    document.addEventListener("DOMContentLoaded", function() {
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
    policy_cfg: PolicyConfig,
    ui_mode: String,
) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/", get(ui_index))
        .route("/ui", get(ui_index))
        .route("/health", get(health_check))
        .route("/verdicts", get(get_verdicts))
        .route("/stats", get(get_stats))
        .route("/policy", get(get_policy))
        .route("/mempool", get(get_mempool_proxy))
        .route("/meta", get(get_meta))
        .layer(Extension(verdict_log))
        .layer(Extension(policy_cfg))
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

async fn get_policy(
    Extension(policy): Extension<PolicyConfig>,
) -> Json<serde_json::Value> {
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

        "debug": dbg
    });

    Json(body)
}

async fn get_meta(
    Extension(ui_mode): Extension<String>,
) -> Json<serde_json::Value> {
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
        Ok(resp) => {
            match resp.json::<serde_json::Value>().await {
                Ok(json) => Json(json),
                Err(e) => {
                    let body = serde_json::json!({
                        "error": format!("invalid mempool json: {e}")
                    });
                    Json(body)
                }
            }
        }
        Err(e) => {
            let body = serde_json::json!({
                "error": format!("mempool fetch failed: {e}")
            });
            Json(body)
        }
    }
}

async fn get_stats(
    Extension(log): Extension<VerdictLog>,
) -> Json<StatsResponse> {
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
