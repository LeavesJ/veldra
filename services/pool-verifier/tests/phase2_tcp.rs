//! v2.0 Invariant Shield Phase 2 #3 Tier 2 integration tests (ADR-003).
//!
//! Drives the full pool-verifier TCP listener via a subprocess plus
//! an in-process axum bitcoind JSON-RPC mock. The subprocess is the
//! real release binary picked up via `CARGO_BIN_EXE_pool-verifier`;
//! the mock answers `getrawmempool` against a controlled set of
//! txids. This complements the unit-level eval tests in
//! `phase2_eval.rs` by exercising every wire-format and config-load
//! surface that production deployments hit.
//!
//! Tests are `#[ignore]` so the default `cargo test --workspace`
//! stays fast for the pre-commit checklist. Run explicitly with
//! `cargo test -p pool-verifier --test phase2_tcp -- --ignored`.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::HashSet;
use std::io::Write as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::post;
use axum::{Json, Router};
use rg_protocol::gateway::{InternalMessage, msg_types};
use rg_protocol::{PROTOCOL_VERSION, TemplatePropose, TemplateVerdict, VerdictReason};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

const REGTEST_SEGWIT_BLOCK_HEX: &str = include_str!("fixtures/regtest_segwit_block.hex");

/// RAII guard for the integration test scratch directory. Composes
/// the path with pid plus nanos for collision safety, pre-cleans
/// before create, and tears down on `Drop` so a panicking test never
/// leaks the tree (R-160 pattern). Avoids pulling `tempfile` for
/// dependency-light tests.
struct ScratchDir {
    path: PathBuf,
}

impl ScratchDir {
    fn new(label: &str) -> std::io::Result<Self> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let pid = std::process::id();
        let path = std::env::temp_dir().join(format!("rg-{label}-{pid}-{nanos}"));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path)?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// `Drop` guard that kills the spawned pool-verifier subprocess so
/// a panicking test never leaks a process holding the listener port.
struct VerifierProcess {
    child: Child,
    _scratch: ScratchDir,
}

impl Drop for VerifierProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Shared state for the bitcoind JSON-RPC mock.
#[derive(Clone)]
struct MockState {
    /// Reversed-hex (display-order) txids returned in `getrawmempool`
    /// responses. The verifier's `bitcoind_rpc` reverses these back
    /// to internal byte order before installing into the view, so
    /// callers must pre-reverse from `compute_txid().to_byte_array()`
    /// when seeding this list.
    display_hex_txids: Arc<std::sync::RwLock<Vec<String>>>,
    request_count: Arc<AtomicU64>,
    /// Single-shot failure: returns one 500 then resets to healthy.
    fail_next: Arc<AtomicBool>,
    /// Sticky failure: every request returns 500 until cleared. Used
    /// by the kill-the-mock fail-stale Phase 2 #3.5 test to drive
    /// the verifier's mempool view from `Fresh` to `Degraded`
    /// without tearing down the axum task.
    always_fail: Arc<AtomicBool>,
    /// PB-40: the chain tip served to `getbestblockhash` / `getblock`.
    /// `None` makes both RPCs error, which is the state every test
    /// written before PB-40 runs in and which the second-chance block
    /// walk must tolerate.
    tip_block: Arc<std::sync::RwLock<Option<MockBlock>>>,
    /// PB-40: error code every batch probe replies with. `-5` is the
    /// normal "not in mempool"; anything else drives the unadjudicated
    /// path.
    probe_error_code: Arc<std::sync::atomic::AtomicI64>,
}

/// One block for the `getblock` mock. Always a chain of length one:
/// `previousblockhash` is null so the verifier's walk terminates
/// after it, which is the shape of the case being modelled (a single
/// block arriving between template construction and the check).
#[derive(Clone)]
struct MockBlock {
    hash: String,
    height: u32,
    /// Display-order hex, as Bitcoin Core emits in `getblock` verbosity 1.
    display_hex_txids: Vec<String>,
}

async fn rpc_handler(State(state): State<MockState>, Json(raw): Json<Value>) -> impl IntoResponse {
    state.request_count.fetch_add(1, Ordering::SeqCst);

    if state.always_fail.load(Ordering::SeqCst) || state.fail_next.swap(false, Ordering::SeqCst) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "result": null,
                "error": {"code": -32603, "message": "mock-induced failure"},
                "id": null,
            })),
        );
    }

    // PB-40 targeted probes arrive as a JSON-RPC batch. Answer from the
    // same txid set `getrawmempool` serves, so a test that seeds the
    // mempool sees the same answer through either path.
    if let Some(items) = raw.as_array() {
        let held: Vec<String> = state.display_hex_txids.read().expect("mock lock").clone();
        let replies: Vec<Value> = items
            .iter()
            .map(|item| {
                let wanted = item
                    .get("params")
                    .and_then(|p| p.get(0))
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let id = item.get("id").cloned().unwrap_or(Value::Null);
                if held.iter().any(|h| h == wanted) {
                    json!({"id": id, "result": {"vsize": 141}, "error": Value::Null})
                } else {
                    json!({
                        "id": id,
                        "result": Value::Null,
                        "error": {
                            "code": state.probe_error_code.load(Ordering::SeqCst),
                            "message": "Transaction not in mempool",
                        },
                    })
                }
            })
            .collect();
        return (StatusCode::OK, Json(Value::Array(replies)));
    }

    let method = raw.get("method").and_then(Value::as_str).unwrap_or("");
    let id = raw.get("id").cloned().unwrap_or(Value::Null);

    if method == "getmempoolinfo" {
        let size = state.display_hex_txids.read().expect("mock lock").len();
        return (
            StatusCode::OK,
            Json(json!({"result": {"size": size}, "error": null, "id": id})),
        );
    }

    // PB-40 second-chance block RPCs. A test that never seeds
    // `tip_block` gets the same error Bitcoin Core would give for an
    // unknown block, which is the path the block walk must survive.
    if method == "getbestblockhash" || method == "getblock" {
        let tip = state.tip_block.read().expect("mock lock").clone();
        let Some(tip) = tip else {
            return (
                StatusCode::OK,
                Json(json!({
                    "result": null,
                    "error": {"code": -5, "message": "Block not found"},
                    "id": id,
                })),
            );
        };
        if method == "getbestblockhash" {
            return (
                StatusCode::OK,
                Json(json!({"result": tip.hash, "error": null, "id": id})),
            );
        }
        return (
            StatusCode::OK,
            Json(json!({
                "result": {
                    "hash": tip.hash,
                    "height": tip.height,
                    "tx": tip.display_hex_txids,
                    // Null terminates the verifier's walk after this
                    // block, modelling a single block arriving between
                    // template construction and the Class M check.
                    "previousblockhash": Value::Null,
                },
                "error": null,
                "id": id,
            })),
        );
    }

    if method != "getrawmempool" {
        return (
            StatusCode::OK,
            Json(json!({
                "result": null,
                "error": {"code": -32601, "message": "method not supported"},
                "id": id,
            })),
        );
    }

    let txids = state.display_hex_txids.read().expect("mock lock");
    (
        StatusCode::OK,
        Json(json!({
            "result": *txids,
            "error": null,
            "id": id,
        })),
    )
}

/// Pre-bind to discover a free port, then immediately drop the
/// listener so the subprocess can bind it. Race window is small
/// enough to be reliable in CI; a bind-failed subprocess surfaces as
/// an explicit test failure rather than a silent skip.
async fn discover_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind 127.0.0.1:0");
    let port = listener.local_addr().expect("local_addr").port();
    drop(listener);
    port
}

async fn spawn_mock(state: MockState) -> SocketAddr {
    let app = Router::new()
        .route("/", post(rpc_handler))
        .with_state(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind mock");
    let addr = listener.local_addr().expect("mock addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    addr
}

/// Knobs the kill-the-mock fail-stale test needs to override
/// (smaller `max_stale_secs` so the view degrades within the test
/// timeout). All other policy fields stay permissive so Phase 1
/// gates never short-circuit Phase 2 behavior under test.
#[derive(Clone, Copy)]
struct PolicyOverrides {
    max_stale_secs: u64,
    /// PB-40 tests set this very high so the view is polled exactly
    /// once at boot and then frozen. That is what makes the
    /// stale-view false positive reproducible instead of a race
    /// against the next poll: the served view is pinned to the
    /// mempool as it was at T0 while the mock's mempool moves on,
    /// which is precisely the temporal skew the defect is made of.
    poll_interval_secs: u64,
}

impl Default for PolicyOverrides {
    fn default() -> Self {
        Self {
            max_stale_secs: 60,
            poll_interval_secs: 1,
        }
    }
}

fn write_policy_toml(scratch: &Path, mock_addr: SocketAddr, overrides: PolicyOverrides) -> PathBuf {
    let policy_path = scratch.join("policy.toml");
    let max_stale_secs = overrides.max_stale_secs;
    let poll_interval_secs = overrides.poll_interval_secs;
    let toml = format!(
        r#"[policy]
protocol_version = 2
required_prevhash_len = 64
min_total_fees = 0
max_tx_count = 4294967295
low_mempool_tx = 0
high_mempool_tx = 0
min_avg_fee_lo = 0
min_avg_fee_mid = 0
min_avg_fee_hi = 0
reject_empty_templates = false
reject_coinbase_zero = false
unknown_mempool_as_high = true

[policy.safety]
max_weight_ratio = 0.999
enforce_weight_ratio = false
enforce_template_age = false
warn_sigops_ratio = 0.95
warn_coinbase_sigops_max = 400

[policy.mempool]
enforce = true
tolerance_pct = 4.0
poll_interval_secs = {poll_interval_secs}
max_stale_secs = {max_stale_secs}
per_tx_detail = false
rpc_url = "http://{mock_addr}/"
rpc_user = "rg-test"
rpc_pass = "rg-test"
"#
    );
    let mut f = std::fs::File::create(&policy_path).expect("create policy.toml");
    f.write_all(toml.as_bytes()).expect("write policy.toml");
    policy_path
}

fn spawn_verifier(policy_path: &Path, tcp_port: u16, http_port: u16, scratch_dir: &Path) -> Child {
    let bin = env!("CARGO_BIN_EXE_pool-verifier");
    Command::new(bin)
        .env("VELDRA_POLICY_FILE", policy_path)
        .env("VELDRA_VERIFIER_ADDR", format!("127.0.0.1:{tcp_port}"))
        .env("VELDRA_HTTP_ADDR", format!("127.0.0.1:{http_port}"))
        .env("VELDRA_API_SECRET_OPTIONAL", "1")
        .env("VELDRA_VERIFIER_CONFIG", scratch_dir.join("verifier.toml"))
        .env("VELDRA_LOG_FILTER", "warn")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn pool-verifier")
}

async fn wait_for_listener(port: u16, deadline: Duration) {
    let start = Instant::now();
    while start.elapsed() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("verifier TCP listener on 127.0.0.1:{port} never came up within {deadline:?}");
}

async fn wait_for_first_refresh(state: &MockState, deadline: Duration) {
    let start = Instant::now();
    while start.elapsed() < deadline {
        if state.request_count.load(Ordering::SeqCst) >= 1 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("bitcoind mock never received a getrawmempool poll within {deadline:?}");
}

/// Send a `TemplatePropose` framed in a gateway-style
/// `InternalMessage` envelope, read one `TemplateVerdict` envelope
/// back. Returns the decoded verdict for assertions.
async fn round_trip_template(port: u16, template: TemplatePropose) -> TemplateVerdict {
    let stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect verifier TCP");
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    let propose_env = InternalMessage {
        msg_type: msg_types::TEMPLATE_PROPOSE.to_string(),
        version: PROTOCOL_VERSION,
        payload: serde_json::to_value(&template).expect("serialize template"),
    };
    let mut line = serde_json::to_string(&propose_env).expect("serialize envelope");
    line.push('\n');
    write_half
        .write_all(line.as_bytes())
        .await
        .expect("write template");
    write_half.flush().await.expect("flush");

    let mut buf = String::new();
    let n = reader.read_line(&mut buf).await.expect("read verdict line");
    assert!(n > 0, "expected verdict line, got EOF");

    let env: InternalMessage = serde_json::from_str(buf.trim()).expect("parse envelope");
    assert_eq!(
        env.msg_type,
        msg_types::TEMPLATE_VERDICT,
        "unexpected msg_type: {}",
        env.msg_type
    );
    serde_json::from_value(env.payload).expect("parse verdict payload")
}

/// Build a `TemplatePropose` against the regtest segwit fixture
/// plus the corresponding non-coinbase txid in display-order hex
/// (the shape bitcoind RPC emits).
fn regtest_segwit_template_and_display_hex() -> (TemplatePropose, Vec<String>) {
    let bytes =
        hex::decode(REGTEST_SEGWIT_BLOCK_HEX.trim()).expect("REGTEST_SEGWIT_BLOCK_HEX decodes");
    let parsed = rg_consensus::parse_block(&bytes).expect("regtest block parses");
    // PB-19 producer conventions: non-coinbase weight sum, sigops as
    // the legacy x4 cost floor, non-coinbase tx_count.
    let weight = rg_consensus::non_coinbase_tx_weight(&parsed);
    let total_sigops = u32::try_from(u64::from(rg_consensus::non_coinbase_sigops(&parsed)) * 4)
        .expect("fixture sigop cost fits u32");
    let coinbase_sigops = u32::try_from(u64::from(rg_consensus::coinbase_sigops(&parsed)) * 4)
        .expect("fixture coinbase sigop cost fits u32");
    let coinbase_value =
        rg_consensus::re_derive_coinbase_value(&bytes).expect("regtest coinbase value re-derives");
    let txids_internal = rg_consensus::template_txids(&parsed);

    let display_hex: Vec<String> = txids_internal
        .iter()
        .map(|t| {
            let mut bytes = *t;
            bytes.reverse();
            hex::encode(bytes)
        })
        .collect();

    let template = TemplatePropose {
        version: PROTOCOL_VERSION,
        id: 42,
        block_height: 102,
        prev_hash: "a".repeat(64),
        coinbase_value,
        tx_count: 1,
        total_fees: 0,
        observed_weight: None,
        created_at_unix_ms: None,
        total_sigops: Some(total_sigops),
        coinbase_sigops: Some(coinbase_sigops),
        template_weight: Some(weight),
        gateway_instance_id: None,
        raw_block_hex: Some(REGTEST_SEGWIT_BLOCK_HEX.trim().to_string()),
    };
    (template, display_hex)
}

fn make_mock_state(display_hex: Vec<String>) -> MockState {
    MockState {
        display_hex_txids: Arc::new(std::sync::RwLock::new(display_hex)),
        request_count: Arc::new(AtomicU64::new(0)),
        fail_next: Arc::new(AtomicBool::new(false)),
        always_fail: Arc::new(AtomicBool::new(false)),
        tip_block: Arc::new(std::sync::RwLock::new(None)),
        probe_error_code: Arc::new(std::sync::atomic::AtomicI64::new(-5)),
    }
}

/// Booted verifier handle. `verifier_port` carries the TCP listener
/// (`TemplatePropose` / `TemplateVerdict` envelopes); `http_port`
/// carries the public HTTP surface including `/metrics`. `_proc` is
/// only held for its `Drop` side effect (kills the subprocess and
/// removes the scratch dir); the field is intentionally unread.
struct Booted {
    _proc: VerifierProcess,
    verifier_port: u16,
    http_port: u16,
    mock: MockState,
}

/// A plausible non-empty mempool that contains none of the template's
/// transactions. This is what the fabrication scenario actually looks
/// like on a live node: tens of thousands of real txids, none of which
/// is the one the template invented.
///
/// Booting the mock with `vec![]` no longer produces a rejection: an
/// empty successful `getrawmempool` is refused as a view rather than
/// installed as Fresh, because a Fresh empty view scores 100% of every
/// template unknown and turns Class M into a false-positive storm.
fn decoy_display_hex_txids(count: u8) -> Vec<String> {
    (1..=count).map(|b| hex::encode([b; 32])).collect()
}

async fn boot_verifier_with_mock(display_hex_txids: Vec<String>) -> Booted {
    boot_verifier_with_mock_overrides(display_hex_txids, PolicyOverrides::default()).await
}

/// Serializes the boot sequence across parallel Tier 2 tests so the
/// pre-bind/drop port-discovery dance does not race. cargo test runs
/// integration tests on multiple threads by default and the kernel
/// can hand the same `127.0.0.1:0` port to two parallel
/// `discover_free_port` callers between their drop-and-spawn-verifier
/// windows; the second subprocess then fails to bind and its mock
/// never sees a `getrawmempool` poll, surfacing as a flaky
/// "bitcoind mock never received a poll within 30s" panic on a
/// different test each run. The lock covers only the racy section
/// (port discovery, mock spawn, verifier spawn, `wait_for_listener`);
/// the actual `TemplatePropose` / `TemplateVerdict` round-trips and
/// the post-boot verdict assertions run in parallel.
static BOOT_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn boot_verifier_with_mock_overrides(
    display_hex_txids: Vec<String>,
    overrides: PolicyOverrides,
) -> Booted {
    let _boot_guard = BOOT_MUTEX.lock().await;

    let mock_state = make_mock_state(display_hex_txids);
    let mock_addr = spawn_mock(mock_state.clone()).await;

    let verifier_port = discover_free_port().await;
    let http_port = discover_free_port().await;

    let scratch = ScratchDir::new("phase2-tcp").expect("create scratch dir");
    let policy_path = write_policy_toml(scratch.path(), mock_addr, overrides);
    let child = spawn_verifier(&policy_path, verifier_port, http_port, scratch.path());

    let proc = VerifierProcess {
        child,
        _scratch: scratch,
    };

    // Deadlines sized for parallel test execution. cargo test runs
    // integration tests on multiple threads by default; even with
    // BOOT_MUTEX serializing port discovery the wait_for_listener
    // probe still runs while later tests are queued behind the lock,
    // so the deadline must absorb both the verifier startup cost and
    // the queueing wait.
    wait_for_listener(verifier_port, Duration::from_secs(30)).await;
    wait_for_first_refresh(&mock_state, Duration::from_secs(30)).await;
    // Give the verifier one extra poll cycle to install the snapshot.
    tokio::time::sleep(Duration::from_millis(1_500)).await;

    // _boot_guard drops here on function exit, releasing BOOT_MUTEX
    // so the next test's boot can begin.
    Booted {
        _proc: proc,
        verifier_port,
        http_port,
        mock: mock_state,
    }
}

/// Issue a raw HTTP/1.1 GET against the verifier's public `/metrics`
/// endpoint and return the response body. Avoids pulling reqwest as
/// a dev-dep (one HTTP GET, no TLS, loopback only).
async fn fetch_metrics_text(http_port: u16) -> String {
    use tokio::io::AsyncReadExt;
    let mut stream = TcpStream::connect(("127.0.0.1", http_port))
        .await
        .expect("connect metrics");
    let req = "GET /metrics HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n".to_string();
    stream
        .write_all(req.as_bytes())
        .await
        .expect("write metrics req");
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.expect("read metrics");
    let text = String::from_utf8_lossy(&buf).into_owned();
    if let Some(idx) = text.find("\r\n\r\n") {
        text[idx + 4..].to_string()
    } else {
        text
    }
}

/// Parse a Prometheus counter line of shape `metric_name <number>`
/// out of the `OpenMetrics` text export. Returns 0 if absent so the
/// caller can assert "increased to >= N" without distinguishing
/// missing from zero.
fn parse_counter(text: &str, name: &str) -> u64 {
    for line in text.lines() {
        if line.starts_with('#') {
            continue;
        }
        // Match "name VALUE" or "name{labels} VALUE".
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix(name) {
            // Handle either bare metric or label set.
            let after_labels = rest.split_whitespace().last();
            if let Some(value) = after_labels
                && let Ok(parsed) = value.parse::<f64>()
            {
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                return parsed as u64;
            }
        }
    }
    0
}

#[tokio::test]
#[ignore = "Tier 2: spawns pool-verifier subprocess; run with --ignored"]
async fn phase2_tcp_happy_path_full_overlap_emits_accept() {
    let (template, display_hex) = regtest_segwit_template_and_display_hex();
    let booted = boot_verifier_with_mock(display_hex).await;

    let verdict = round_trip_template(booted.verifier_port, template).await;
    drop(booted);

    assert!(
        verdict.accepted,
        "expected accept, got reason={:?} detail={:?}",
        verdict.reason_code, verdict.reason_detail
    );
}

#[tokio::test]
#[ignore = "Tier 2: spawns pool-verifier subprocess; run with --ignored"]
async fn phase2_tcp_fabrication_path_emits_tolerance_exceeded() {
    let (template, _display_hex) = regtest_segwit_template_and_display_hex();
    // Populated mempool view that does not carry the template's 1
    // non-coinbase tx: 1/1 unknown, above the 4% tolerance.
    let booted = boot_verifier_with_mock(decoy_display_hex_txids(8)).await;

    // Seed a healthy tip so the block walk COMPLETES. Without this the
    // block RPCs error, coverage is Failed, and the verdict is
    // correctly reported `lookup_failed` rather than `upheld`. This
    // test asserts `upheld`, which is a claim that bitcoind held the
    // transactions in neither its mempool nor any recent block, so it
    // has to be a lookup that actually looked. The tip sits at 101
    // against a template building 102, so the walk terminates having
    // established there is nothing mined since the template was built.
    {
        let mut g = booted.mock.tip_block.write().expect("mock write lock");
        *g = Some(MockBlock {
            hash: "a".repeat(64),
            height: 101,
            display_hex_txids: vec![],
        });
    }

    let verdict = round_trip_template(booted.verifier_port, template).await;

    // PB-40: the second chance must not become a blanket amnesty.
    // bitcoind is reachable and genuinely does not have this
    // transaction, so the rejection is adjudicated and UPHELD, which
    // is the only outcome that can support a detection claim.
    let metrics = fetch_metrics_text(booted.http_port).await;
    let upheld = parse_counter(
        &metrics,
        "verifier_phase2_second_chance_total{outcome=\"upheld\"}",
    );
    let withdrawn = parse_counter(
        &metrics,
        "verifier_phase2_second_chance_total{outcome=\"withdrawn\"}",
    );
    drop(booted);

    assert!(!verdict.accepted, "expected reject, got accept");
    assert_eq!(
        verdict.reason_code,
        Some(VerdictReason::V2InvariantMempoolToleranceExceeded),
        "wrong reason_code: {:?}",
        verdict.reason_code
    );
    let detail = verdict.reason_detail.unwrap_or_default();
    assert!(
        detail.contains("mempool tolerance exceeded"),
        "detail must mention tolerance: {detail}"
    );
    assert_eq!(
        upheld, 1,
        "a genuinely absent transaction must be adjudicated and upheld\n\
         --- metrics ---\n{metrics}"
    );
    assert_eq!(
        withdrawn, 0,
        "nothing was recovered here\n--- metrics ---\n{metrics}"
    );
}

#[tokio::test]
#[ignore = "Tier 2: spawns pool-verifier subprocess; run with --ignored"]
async fn phase2_tcp_subsequent_template_uses_refreshed_view() {
    // Boot with a decoy mempool, replace the txid set, wait for poll,
    // assert the next template is accepted. Verifies the polling
    // task installs new snapshots without a process restart.
    let (template, display_hex) = regtest_segwit_template_and_display_hex();
    let booted = boot_verifier_with_mock(decoy_display_hex_txids(8)).await;

    // Confirm initial reject under the non-overlapping view.
    let verdict_a = round_trip_template(booted.verifier_port, template.clone()).await;
    assert!(!verdict_a.accepted);

    // Mutate the mock's view to include the template's tx.
    {
        let mut g = booted
            .mock
            .display_hex_txids
            .write()
            .expect("mock write lock");
        *g = display_hex;
    }

    // Wait two poll intervals plus install latency to make sure the
    // verifier picks up the new view.
    tokio::time::sleep(Duration::from_millis(2_500)).await;

    let verdict_b = round_trip_template(booted.verifier_port, template).await;
    drop(booted);
    assert!(
        verdict_b.accepted,
        "expected accept after refresh, got reason={:?}",
        verdict_b.reason_code
    );
}

/// Phase 2 #3.5 kill-the-mock fail-stale scenario.
///
/// Boot the verifier under a healthy view, send a `TemplatePropose`
/// (asserts accept under Fresh), flip the mock's `always_fail` toggle
/// so subsequent `getrawmempool` polls return 500, wait long enough
/// for the view to reach Degraded (`max_stale_secs * 2 + buffer`),
/// then send another `TemplatePropose`. The second verdict must still
/// accept because Class M skips on Degraded and Phase 1 falls
/// through unchanged. The HTTP `/metrics` surface must show
/// `verifier_phase2_degraded_total >= 1` confirming the operator
/// alert path fires.
#[tokio::test]
#[ignore = "Tier 2: spawns pool-verifier subprocess; run with --ignored"]
async fn phase2_tcp_kill_the_mock_drives_view_to_degraded() {
    let (template, display_hex) = regtest_segwit_template_and_display_hex();
    // 3-second fail-stale window so the view crosses Degraded
    // (2 * max_stale_secs = 6s) within the test budget.
    let overrides = PolicyOverrides {
        max_stale_secs: 3,
        ..PolicyOverrides::default()
    };
    let booted = boot_verifier_with_mock_overrides(display_hex, overrides).await;

    // Sanity: under Fresh, the template accepts.
    let v_fresh = round_trip_template(booted.verifier_port, template.clone()).await;
    assert!(
        v_fresh.accepted,
        "pre-kill: expected accept under Fresh, got reason={:?}",
        v_fresh.reason_code
    );

    // Flip the mock to always-fail. Polls now return 500; the polling
    // task logs and serves the last view, then transitions to Stale
    // and finally Degraded as the clock advances.
    booted.mock.always_fail.store(true, Ordering::SeqCst);

    // 2 * max_stale_secs (6s) + 2s buffer for the polling cycle to
    // observe failures across the Stale -> Degraded boundary.
    tokio::time::sleep(Duration::from_secs(8)).await;

    // Class M is now skipped (Degraded). Phase 1 still passes the
    // template, so the verdict accepts.
    let v_post = round_trip_template(booted.verifier_port, template).await;
    assert!(
        v_post.accepted,
        "post-kill: expected Phase 1 fall-through accept, got reason={:?}",
        v_post.reason_code
    );

    // /metrics must show the degraded counter incremented at least
    // once (one for each verdict served while view was Degraded).
    let metrics = fetch_metrics_text(booted.http_port).await;
    let degraded = parse_counter(&metrics, "verifier_phase2_degraded_total");
    drop(booted);
    assert!(
        degraded >= 1,
        "expected verifier_phase2_degraded_total >= 1 after kill, got {degraded}\n\
         --- metrics ---\n{metrics}"
    );
}

/// Class M soak hazard, at the wire.
///
/// A bitcoind that answers `getrawmempool` with `200 OK []` (still
/// loading `mempool.dat`, wrong chain, just restarted) must not be
/// installed as a Fresh view. If it were, every template on the
/// network would score 100% unknown and reject, and the launch-gate
/// soak would record a false-positive storm indistinguishable from a
/// real detection.
///
/// The template must therefore ACCEPT (Class M skipped on an unprimed
/// view, Phase 1 falls through) and `/metrics` must show the refusal.
#[tokio::test]
#[ignore = "Tier 2: spawns pool-verifier subprocess; run with --ignored"]
async fn phase2_tcp_empty_mempool_response_is_refused_not_served() {
    let (template, _display_hex) = regtest_segwit_template_and_display_hex();
    let booted = boot_verifier_with_mock(vec![]).await;

    let verdict = round_trip_template(booted.verifier_port, template).await;
    assert!(
        verdict.accepted,
        "an empty getrawmempool must skip Class M, not reject; reason={:?} detail={:?}",
        verdict.reason_code, verdict.reason_detail
    );

    let metrics = fetch_metrics_text(booted.http_port).await;
    let refused = parse_counter(&metrics, "verifier_mempool_empty_responses");
    let unprimed = parse_counter(
        &metrics,
        "verifier_phase2_checks_total{result=\"unprimed\"}",
    );
    drop(booted);
    assert!(
        refused >= 1,
        "expected verifier_mempool_empty_responses >= 1, got {refused}\n\
         --- metrics ---\n{metrics}"
    );
    assert!(
        unprimed >= 1,
        "an unprimed view must stay observable per template, got {unprimed}\n\
         --- metrics ---\n{metrics}"
    );
}

// ── PB-40: second-chance lookup at Class M rejection time ────────

/// Boot with the view pinned: one poll at startup, then never again,
/// so the served mempool view is frozen at T0 while the mock's
/// mempool moves on. That is the temporal skew the PB-40 defect is
/// made of, made deterministic instead of a race against the next
/// poll.
async fn boot_with_frozen_view(display_hex_txids: Vec<String>) -> Booted {
    boot_verifier_with_mock_overrides(
        display_hex_txids,
        PolicyOverrides {
            max_stale_secs: 3_600,
            poll_interval_secs: 3_600,
        },
    )
    .await
}

/// THE PB-40 CASE, at the wire.
///
/// Reproduces what was caught live on the Setup B node: `log_id=2952`
/// rejected with 187 of 2738 transactions "unknown to verifier view",
/// and 10 of 10 sampled txids were IN bitcoind's mempool when queried
/// seconds later. The verifier's view was stale; bitcoind was not.
///
/// Here the view is primed without the template's transaction, then
/// bitcoind's mempool gains it, then the template arrives. The first
/// pass rejects at 1/1 unknown, over the 4% tolerance. The template
/// must nonetheless be ACCEPTED, because the second-chance lookup
/// asks bitcoind and bitcoind has it.
///
/// Without the second-chance mechanism this verdict is a rejection,
/// which `phase2_tcp_fabrication_path_emits_tolerance_exceeded` pins
/// for the genuinely-absent case.
#[tokio::test]
#[ignore = "Tier 2: spawns pool-verifier subprocess; run with --ignored"]
async fn phase2_tcp_second_chance_withdraws_a_stale_view_false_positive() {
    let (template, display_hex) = regtest_segwit_template_and_display_hex();
    let booted = boot_with_frozen_view(decoy_display_hex_txids(8)).await;

    // The transaction arrives in bitcoind's mempool after the
    // verifier's view was taken. The view is frozen and still does
    // not carry it.
    {
        let mut g = booted
            .mock
            .display_hex_txids
            .write()
            .expect("mock write lock");
        g.extend(display_hex);
    }

    let verdict = round_trip_template(booted.verifier_port, template).await;

    let metrics = fetch_metrics_text(booted.http_port).await;
    let withdrawn = parse_counter(
        &metrics,
        "verifier_phase2_second_chance_total{outcome=\"withdrawn\"}",
    );
    let recovered = parse_counter(
        &metrics,
        "verifier_phase2_checks_total{result=\"recovered\"}",
    );
    let rejected = parse_counter(
        &metrics,
        "verifier_phase2_checks_total{result=\"rejected\"}",
    );
    drop(booted);

    assert!(
        verdict.accepted,
        "a template whose transactions bitcoind holds must not be rejected for a stale \
         view; reason={:?} detail={:?}",
        verdict.reason_code, verdict.reason_detail
    );
    assert_eq!(
        verdict.reason_code, None,
        "a withdrawn rejection must not leave a reason_code on an accepted verdict"
    );
    assert_eq!(
        withdrawn, 1,
        "expected exactly one withdrawn second chance\n--- metrics ---\n{metrics}"
    );
    assert_eq!(
        recovered, 1,
        "a withdrawn rejection must be observable as result=recovered, not folded into \
         agreed\n--- metrics ---\n{metrics}"
    );
    assert_eq!(
        rejected, 0,
        "no rejection was emitted, so result=rejected must not have incremented\n\
         --- metrics ---\n{metrics}"
    );
}

/// The mined case PB-40 names explicitly: a transaction selected into
/// the template and mined before the check is KNOWN, not absent.
///
/// bitcoind's mempool no longer holds it, because it is in the block
/// that just arrived. A second chance that only asked `getrawmempool`
/// would score it absent and uphold a false rejection, and this is the
/// worst shape of the defect: the whole template's transaction set
/// leaves the mempool at once, so the unknown ratio goes to 100%.
#[tokio::test]
#[ignore = "Tier 2: spawns pool-verifier subprocess; run with --ignored"]
async fn phase2_tcp_second_chance_counts_a_mined_tx_as_known() {
    let (template, display_hex) = regtest_segwit_template_and_display_hex();
    let booted = boot_with_frozen_view(decoy_display_hex_txids(8)).await;

    // The mempool never carries the transaction. The block that
    // arrived after the template was built does. `block_height` on
    // the fixture template is 102, so a tip at 102 is a block mined
    // since it was assembled.
    {
        let mut g = booted.mock.tip_block.write().expect("mock write lock");
        *g = Some(MockBlock {
            hash: "f".repeat(64),
            height: 102,
            display_hex_txids: display_hex,
        });
    }

    let verdict = round_trip_template(booted.verifier_port, template).await;

    let metrics = fetch_metrics_text(booted.http_port).await;
    let withdrawn = parse_counter(
        &metrics,
        "verifier_phase2_second_chance_total{outcome=\"withdrawn\"}",
    );
    drop(booted);

    assert!(
        verdict.accepted,
        "a template transaction mined between construction and the check is known to \
         bitcoind, not absent; reason={:?} detail={:?}",
        verdict.reason_code, verdict.reason_detail
    );
    assert_eq!(
        withdrawn, 1,
        "the mined transaction must be what withdrew the rejection\n--- metrics ---\n{metrics}"
    );
}

/// A lookup that could not run is NOT evidence of absence.
///
/// When bitcoind cannot be reached at rejection time the rejection
/// stands, but it must be recorded as `lookup_failed` rather than
/// `upheld`, because the two mean opposite things to a soak review:
/// `upheld` is a candidate detection, `lookup_failed` is a verdict
/// nobody adjudicated. Silently treating one as the other is the
/// mistake that made 68 rejections unadjudicable in the first place,
/// and it is also how a failing `bitcoin-cli` read as "genuinely
/// absent" for two full rounds of the investigation.
#[tokio::test]
#[ignore = "Tier 2: spawns pool-verifier subprocess; run with --ignored"]
async fn phase2_tcp_second_chance_failure_upholds_the_rejection_unadjudicated() {
    let (template, _display_hex) = regtest_segwit_template_and_display_hex();
    let booted = boot_with_frozen_view(decoy_display_hex_txids(8)).await;

    // bitcoind goes away after the view was primed. The view stays
    // Fresh (nothing re-polls it), so Class M still runs and still
    // rejects; only the adjudication is impossible.
    booted.mock.always_fail.store(true, Ordering::SeqCst);

    let verdict = round_trip_template(booted.verifier_port, template).await;

    let metrics = fetch_metrics_text(booted.http_port).await;
    let failed = parse_counter(
        &metrics,
        "verifier_phase2_second_chance_total{outcome=\"lookup_failed\"}",
    );
    let upheld = parse_counter(
        &metrics,
        "verifier_phase2_second_chance_total{outcome=\"upheld\"}",
    );
    let withdrawn = parse_counter(
        &metrics,
        "verifier_phase2_second_chance_total{outcome=\"withdrawn\"}",
    );
    drop(booted);

    assert!(
        !verdict.accepted,
        "an unreachable bitcoind must not turn a Class M rejection into an acceptance"
    );
    assert_eq!(
        verdict.reason_code,
        Some(VerdictReason::V2InvariantMempoolToleranceExceeded),
        "the original reason code must survive an unadjudicated rejection"
    );
    assert_eq!(
        failed, 1,
        "expected one lookup_failed\n--- metrics ---\n{metrics}"
    );
    assert_eq!(
        upheld, 0,
        "a lookup that never ran must NOT be recorded as upheld: upheld is a detection \
         claim and this is not one\n--- metrics ---\n{metrics}"
    );
    assert_eq!(withdrawn, 0, "--- metrics ---\n{metrics}");
}

/// A block walk that could not run must NOT be labelled `upheld`.
///
/// `upheld` asserts bitcoind held the transactions in neither its
/// mempool nor any block at or above the template's height, and the
/// soak runbook reads it as a genuine detection candidate. Before this
/// was fixed, an errored `getbestblockhash` produced
/// `blocks_scanned: 0, block_walk_truncated: false` — byte-identical to
/// a healthy walk with nothing to scan — and the verdict claimed a
/// completed adjudication the lookup never performed. The rejection
/// still stands either way; what must not stand is the evidence label.
#[tokio::test]
#[ignore = "Tier 2: spawns pool-verifier subprocess; run with --ignored"]
async fn phase2_tcp_failed_block_walk_is_unadjudicated_not_upheld() {
    let (template, _display_hex) = regtest_segwit_template_and_display_hex();
    // tip_block left unseeded, so getbestblockhash errors: the walk
    // cannot rule out the mined case.
    let booted = boot_with_frozen_view(decoy_display_hex_txids(8)).await;

    let verdict = round_trip_template(booted.verifier_port, template).await;

    let metrics = fetch_metrics_text(booted.http_port).await;
    let upheld = parse_counter(
        &metrics,
        "verifier_phase2_second_chance_total{outcome=\"upheld\"}",
    );
    let failed = parse_counter(
        &metrics,
        "verifier_phase2_second_chance_total{outcome=\"lookup_failed\"}",
    );
    drop(booted);

    assert!(
        !verdict.accepted,
        "an unadjudicated rejection must still be a rejection"
    );
    assert_eq!(
        upheld, 0,
        "a walk that never ran cannot support a detection claim\n--- metrics ---\n{metrics}"
    );
    assert_eq!(
        failed, 1,
        "expected the rejection to be recorded unadjudicated\n--- metrics ---\n{metrics}"
    );
}

/// An empty-but-successful `getrawmempool` at second-chance time is not
/// an answer.
///
/// It carries exactly the information content of an RPC error: it
/// cannot establish that any transaction is absent. Scoring every
/// unknown "absent" against it would uphold the rejection AND record it
/// as an adjudicated detection. The view install path already refuses
/// an empty set for the same reason
/// (`mempool_view::MIN_INSTALLABLE_MEMPOOL_SIZE`); the lookup now
/// refuses it too.
#[tokio::test]
#[ignore = "Tier 2: spawns pool-verifier subprocess; run with --ignored"]
async fn phase2_tcp_empty_fresh_mempool_is_unadjudicated_not_upheld() {
    let (template, _display_hex) = regtest_segwit_template_and_display_hex();
    let booted = boot_with_frozen_view(decoy_display_hex_txids(8)).await;

    // The view is already primed and frozen. bitcoind now answers
    // 200 OK [] to the second chance.
    {
        let mut g = booted
            .mock
            .display_hex_txids
            .write()
            .expect("mock write lock");
        g.clear();
    }

    let verdict = round_trip_template(booted.verifier_port, template).await;

    let metrics = fetch_metrics_text(booted.http_port).await;
    let upheld = parse_counter(
        &metrics,
        "verifier_phase2_second_chance_total{outcome=\"upheld\"}",
    );
    let failed = parse_counter(
        &metrics,
        "verifier_phase2_second_chance_total{outcome=\"lookup_failed\"}",
    );
    drop(booted);

    assert!(!verdict.accepted, "the rejection still stands");
    assert_eq!(
        upheld, 0,
        "an empty mempool cannot establish that anything is absent\n--- metrics ---\n{metrics}"
    );
    assert_eq!(
        failed, 1,
        "expected lookup_failed for the empty answer\n--- metrics ---\n{metrics}"
    );
}

/// A probe that cannot establish absence must not produce `upheld`.
///
/// The mempool is healthy and populated, so the degenerate-node guard
/// does not fire, but every probe answers with an unexpected error. The
/// rejection stands and is recorded unadjudicated.
#[tokio::test]
#[ignore = "Tier 2: spawns pool-verifier subprocess; run with --ignored"]
async fn phase2_tcp_unadjudicated_probe_is_not_upheld() {
    let (template, _display_hex) = regtest_segwit_template_and_display_hex();
    let booted = boot_with_frozen_view(decoy_display_hex_txids(8)).await;

    // A healthy tip so the block walk completes and cannot be the
    // reason for the unadjudicated outcome.
    {
        let mut g = booted.mock.tip_block.write().expect("mock write lock");
        *g = Some(MockBlock {
            hash: "a".repeat(64),
            height: 101,
            display_hex_txids: vec![],
        });
    }
    booted.mock.probe_error_code.store(-32603, Ordering::SeqCst);

    let verdict = round_trip_template(booted.verifier_port, template).await;

    let metrics = fetch_metrics_text(booted.http_port).await;
    let upheld = parse_counter(
        &metrics,
        "verifier_phase2_second_chance_total{outcome=\"upheld\"}",
    );
    let failed = parse_counter(
        &metrics,
        "verifier_phase2_second_chance_total{outcome=\"lookup_failed\"}",
    );
    drop(booted);

    assert!(!verdict.accepted, "the rejection still stands");
    assert_eq!(
        upheld, 0,
        "a probe that established nothing cannot support a detection claim\n\
         --- metrics ---\n{metrics}"
    );
    assert_eq!(failed, 1, "--- metrics ---\n{metrics}");
}

// Compile-time assertions that the test crate sees the symbols it
// imports. Catches a future visibility regression early without
// requiring the ignored Tier 2 tests to run.
#[allow(dead_code)]
fn _api_smoke() {
    let _ = HashSet::<[u8; 32]>::new();
    let _ = make_mock_state(vec![]);
}
