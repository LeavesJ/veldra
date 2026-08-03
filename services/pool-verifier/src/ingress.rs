use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use std::io::BufReader as StdBuf;
use subtle::ConstantTimeEq;
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};

use crate::mempool_client;
use crate::metrics::VerdictLabels;
use crate::state::AppState;
use crate::verdicts::{
    LAST_MEMPOOL_OK_UNIX, LogIdCounter, LoggedVerdict, VerdictLog, append_verdict_to_disk,
    current_timestamp, current_timestamp_ms,
};
use pool_verifier::policy::Phase2Attribution;
use rg_protocol::gateway::{InternalMessage, MAX_INTERNAL_LINE_BYTES, msg_types};
use rg_protocol::{
    PROTOCOL_VERSION, PolicyContext, TemplatePropose, TemplateVerdict, VerdictReason,
};
use std::sync::atomic::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time::{Duration, timeout};

/// Build an optional `TlsAcceptor` for the verifier TCP channel.
///
/// Env vars:
/// - `VELDRA_VERIFIER_TLS_CERT`: path to server certificate PEM
/// - `VELDRA_VERIFIER_TLS_KEY`: path to server private key PEM
/// - `VELDRA_VERIFIER_TLS_CLIENT_CA`: path to CA PEM for client certificate
///   verification (mTLS). When set, connecting clients must present a valid
///   certificate signed by this CA.
///
/// Returns `Ok(None)` when none of the env vars are set (plaintext mode).
pub(crate) fn build_tcp_tls_acceptor() -> Result<Option<TlsAcceptor>, String> {
    use std::env;
    use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use tokio_rustls::rustls::server::WebPkiClientVerifier;

    let cert_path = env::var("VELDRA_VERIFIER_TLS_CERT").ok();
    let key_path = env::var("VELDRA_VERIFIER_TLS_KEY").ok();

    let (Some(cert_path), Some(key_path)) = (&cert_path, &key_path) else {
        match (&cert_path, &key_path) {
            (None, None) => return Ok(None),
            (Some(_), None) | (None, Some(_)) => {
                return Err(
                    "VELDRA_VERIFIER_TLS_CERT and VELDRA_VERIFIER_TLS_KEY must both be set or \
                     both be unset"
                        .to_string(),
                );
            }
            _ => unreachable!(),
        }
    };
    let cert_path = cert_path.clone();
    let key_path = key_path.clone();

    // Load server certificate chain.
    let cert_pem = std::fs::read(&cert_path).map_err(|e| format!("read cert {cert_path}: {e}"))?;
    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut StdBuf::new(cert_pem.as_slice()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("parse server cert: {e}"))?;

    // Load server private key.
    let key_pem = std::fs::read(&key_path).map_err(|e| format!("read key {key_path}: {e}"))?;
    let key: PrivateKeyDer<'static> =
        rustls_pemfile::private_key(&mut StdBuf::new(key_pem.as_slice()))
            .map_err(|e| format!("parse server key: {e}"))?
            .ok_or_else(|| format!("no private key found in {key_path}"))?;

    // Optional: client CA for mTLS.
    let client_verifier = if let Ok(ca_path) = std::env::var("VELDRA_VERIFIER_TLS_CLIENT_CA") {
        let ca_pem = std::fs::read(&ca_path).map_err(|e| format!("read client CA: {e}"))?;
        let ca_certs: Vec<CertificateDer<'static>> =
            rustls_pemfile::certs(&mut StdBuf::new(ca_pem.as_slice()))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| format!("parse client CA: {e}"))?;

        let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
        for cert in &ca_certs {
            root_store
                .add(cert.clone())
                .map_err(|e| format!("add client CA: {e}"))?;
        }
        Some(
            WebPkiClientVerifier::builder(Arc::new(root_store))
                .build()
                .map_err(|e| format!("build client verifier: {e}"))?,
        )
    } else {
        None
    };

    let mut server_config = if let Some(verifier) = client_verifier {
        tokio_rustls::rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)
            .map_err(|e| format!("build server config (mTLS): {e}"))?
    } else {
        tokio_rustls::rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| format!("build server config (TLS): {e}"))?
    };
    server_config.alpn_protocols = vec![b"rg-ndjson".to_vec()];

    Ok(Some(TlsAcceptor::from(Arc::new(server_config))))
}

/// Generate a self-signed certificate for testing/development.
pub(crate) fn generate_self_signed_cert() -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let key_pair = rcgen::KeyPair::generate()?;
    let params = rcgen::CertificateParams::new(vec!["localhost".to_string()])?;
    let cert = params.self_signed(&key_pair)?;
    let cert_pem = cert.pem().into_bytes();
    let key_pem = key_pair.serialize_pem().into_bytes();
    Ok((cert_pem, key_pem))
}

/// System error boundary: reason codes not produced by policy evaluation.
///
/// `VerdictReason::PolicyLoadError`       — emitted when policy lock is poisoned
///                                          or policy state is unavailable.
/// `VerdictReason::MempoolBackendUnavailable` — reserved for future fail-closed
///                                          mode. Currently, missing mempool triggers
///                                          degraded-mode tier selection.
/// `VerdictReason::InternalError`         — emitted on unexpected handler failures
///                                          (e.g., serialize errors).
pub(crate) async fn run_tcp_server(
    app_state: AppState,
    addr: String,
    verdict_log: VerdictLog,
    mempool_url: Option<String>,
    log_id_counter: LogIdCounter,
    tls_acceptor: Option<TlsAcceptor>,
    metrics: Arc<crate::metrics::VerifierMetrics>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(&addr).await?;
    let tls_mode = if tls_acceptor.is_some() {
        "tls"
    } else {
        "plaintext"
    };
    info!(addr = %addr, tls = tls_mode, "TCP listening");
    if tls_acceptor.is_none() && !addr.starts_with("127.0.0.1") && !addr.starts_with("[::1]") {
        tracing::warn!(
            addr = %addr,
            "TCP verifier is running without TLS on a non-loopback address. \
             Templates and verdicts will be sent in plaintext. Set \
             VELDRA_VERIFIER_TLS_CERT and VELDRA_VERIFIER_TLS_KEY for production."
        );
    }

    loop {
        let (tcp_stream, _peer) = listener.accept().await?;
        let state_clone = app_state.clone();
        let log = verdict_log.clone();
        let url_clone = mempool_url.clone();
        let id_ctr = log_id_counter.clone();
        let acceptor = tls_acceptor.clone();
        let conn_metrics = metrics.clone();

        tokio::spawn(async move {
            // Upgrade to TLS if configured, then split into reader/writer.
            if let Some(acceptor) = acceptor {
                match acceptor.accept(tcp_stream).await {
                    Ok(tls_stream) => {
                        let (reader, writer) = tokio::io::split(tls_stream);
                        handle_tcp_connection(
                            reader,
                            writer,
                            state_clone,
                            log,
                            url_clone,
                            id_ctr,
                            conn_metrics,
                        )
                        .await;
                    }
                    Err(e) => {
                        warn!(error = %e, "TLS accept failed");
                    }
                }
            } else {
                let (reader, writer) = tcp_stream.into_split();
                handle_tcp_connection(
                    reader,
                    writer,
                    state_clone,
                    log,
                    url_clone,
                    id_ctr,
                    conn_metrics,
                )
                .await;
            }
        });
    }
}

/// Result of one bounded NDJSON line read (PB-18b).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BoundedLine {
    /// A complete line: newline-terminated within the budget, or a
    /// final unterminated line at EOF that stayed under the budget.
    Line,
    /// Clean EOF with no pending bytes.
    Eof,
    /// The peer sent `max_bytes` bytes without a newline. Protocol
    /// error: the caller drops the connection immediately, because a
    /// bounded reader cannot resync to the next newline. The gateway's
    /// read side does the same since PB-23; both sides share the same
    /// `MAX_INTERNAL_LINE_BYTES` budget (20 MiB).
    OverLimit,
}

/// Longest rendering of a rejected line that reaches the log.
///
/// Mirrors the gateway's `verifier_stream::LOG_SAMPLE_BYTES`, deliberately
/// duplicated rather than shared for the same reason `read_bounded_line`
/// is: each side owns its own ingress and neither should have to import
/// the other's I/O internals to bound a log field.
const LOG_SAMPLE_BYTES: usize = 512;

/// Bound a borrowed string before it reaches a log field, on a char
/// boundary so the output stays valid UTF-8, marking any truncation.
///
/// Used for the peer-supplied `msg_type`, which is a `String` bounded
/// only by `MAX_INTERNAL_LINE_BYTES` and reaches an unknown-type warning
/// that has no strike counter, so a peer can repeat it for the life of
/// the connection.
///
/// Mirrors the gateway's `verifier_stream::log_sample`.
fn log_sample(line: &str) -> std::borrow::Cow<'_, str> {
    if line.len() <= LOG_SAMPLE_BYTES {
        return std::borrow::Cow::Borrowed(line);
    }
    let mut end = LOG_SAMPLE_BYTES;
    while end > 0 && !line.is_char_boundary(end) {
        end -= 1;
    }
    std::borrow::Cow::Owned(format!(
        "{} (truncated, {} bytes total)",
        &line[..end],
        line.len()
    ))
}

/// Render `value` into at most `LOG_SAMPLE_BYTES`, marking any truncation
/// and keeping the true length.
///
/// This ingress never logged the offending line itself, so it did not
/// carry the gateway's original defect. It carried the other half of it:
/// `serde_json::Error`'s `Display` embeds the offending input verbatim,
/// so `error = %e` on a parse failure hands back whatever the peer sent.
/// A line is bounded only by `MAX_INTERNAL_LINE_BYTES` (20 MiB), and a
/// malformed line here is skipped rather than fatal, so a peer can spend
/// them one after another on a single connection. Measured against the
/// gateway's envelope type, a 1,000,042 byte line yields a 1,000,062 byte
/// error message.
///
/// Mirrors the gateway's `verifier_stream::log_display`.
fn log_display(value: impl std::fmt::Display) -> String {
    use std::fmt::Write as _;

    /// Keeps at most `LOG_SAMPLE_BYTES`, cut on a char boundary, while
    /// counting every byte offered so the true length survives.
    struct Capped {
        kept: String,
        offered: usize,
    }

    impl std::fmt::Write for Capped {
        fn write_str(&mut self, s: &str) -> std::fmt::Result {
            self.offered += s.len();
            let mut room = LOG_SAMPLE_BYTES
                .saturating_sub(self.kept.len())
                .min(s.len());
            // The cut point is attacker-chosen, so a naive slice at the
            // cap panics whenever it lands mid-codepoint.
            while room > 0 && !s.is_char_boundary(room) {
                room -= 1;
            }
            self.kept.push_str(&s[..room]);
            Ok(())
        }
    }

    let mut sink = Capped {
        kept: String::new(),
        offered: 0,
    };
    let _ = write!(sink, "{value}");
    let Capped { mut kept, offered } = sink;
    if offered > kept.len() {
        let _ = write!(kept, " (truncated, {offered} bytes total)");
    }
    kept
}

/// Read one newline-terminated line into `buf`, enforcing `max_bytes`
/// per line via `AsyncReadExt::take` so an endless newline-free
/// stream can never grow the line buffer without bound (PB-18b). The
/// `take` adaptor is re-created per call, so the budget resets for
/// every line.
async fn read_bounded_line<R>(
    reader: &mut R,
    buf: &mut String,
    max_bytes: u64,
) -> std::io::Result<BoundedLine>
where
    R: AsyncBufRead + Unpin,
{
    let n = (&mut *reader).take(max_bytes).read_line(buf).await?;
    if n == 0 {
        return Ok(BoundedLine::Eof);
    }
    if u64::try_from(n).unwrap_or(u64::MAX) >= max_bytes && !buf.ends_with('\n') {
        return Ok(BoundedLine::OverLimit);
    }
    Ok(BoundedLine::Line)
}

/// Handles a single TCP connection (plaintext or TLS) by reading NDJSON lines
/// and dispatching template proposals.
#[allow(clippy::too_many_lines)]
pub(crate) async fn handle_tcp_connection<R, W>(
    reader: R,
    mut writer: W,
    app_state: AppState,
    verdict_log: VerdictLog,
    mempool_url: Option<String>,
    log_id_counter: LogIdCounter,
    metrics: Arc<crate::metrics::VerifierMetrics>,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let max_log = crate::verdicts::verdict_log_max_entries();

    let state_clone = app_state;
    let url_clone = mempool_url;
    let id_ctr = log_id_counter;
    let log = verdict_log;
    {
        let mut reader = BufReader::new(reader);
        let mut line = String::new();

        // Track whether this client uses InternalMessage envelope format
        // (sv2-gateway) vs raw TemplatePropose (template-manager).
        // Auto-detected on the first successfully parsed line.
        let mut uses_envelope: Option<bool> = None;

        // PB-18(b): per-line byte budget shared with the gateway's
        // internal NDJSON protocol.
        let max_line_bytes = u64::try_from(MAX_INTERNAL_LINE_BYTES).unwrap_or(u64::MAX);

        loop {
            line.clear();
            match read_bounded_line(&mut reader, &mut line, max_line_bytes).await {
                Ok(BoundedLine::Line) => {}
                Ok(BoundedLine::Eof) => break,
                Ok(BoundedLine::OverLimit) => {
                    warn!(
                        max_bytes = MAX_INTERNAL_LINE_BYTES,
                        "ingress line exceeded MAX_INTERNAL_LINE_BYTES without a newline; \
                         dropping connection"
                    );
                    break;
                }
                Err(e) => {
                    warn!(error = ?e, "tcp read error");
                    break;
                }
            }

            let trimmed = line.trim();

            // Try InternalMessage envelope first (gateway protocol).
            let propose: TemplatePropose =
                if let Ok(env) = serde_json::from_str::<InternalMessage>(trimmed) {
                    if uses_envelope.is_none() {
                        uses_envelope = Some(true);
                    }
                    match env.msg_type.as_str() {
                        msg_types::TEMPLATE_PROPOSE => {
                            match serde_json::from_value::<TemplatePropose>(env.payload) {
                                Ok(p) => p,
                                Err(e) => {
                                    warn!(
                                        error = %log_display(&e),
                                        "template_propose payload parse error"
                                    );
                                    continue;
                                }
                            }
                        }
                        msg_types::HEARTBEAT => {
                            // Respond with heartbeat_ack in envelope format.
                            let ack = InternalMessage {
                                msg_type: msg_types::HEARTBEAT_ACK.to_string(),
                                version: PROTOCOL_VERSION,
                                payload: serde_json::json!({}),
                            };
                            if let Ok(json) = serde_json::to_string(&ack) {
                                if let Err(e) = writer.write_all(json.as_bytes()).await {
                                    warn!(error = %e, "heartbeat ack write failed");
                                    return;
                                }
                                if let Err(e) = writer.write_all(b"\n").await {
                                    warn!(error = %e, "heartbeat ack newline write failed");
                                    return;
                                }
                                if let Err(e) = writer.flush().await {
                                    warn!(error = %e, "heartbeat ack flush failed");
                                    return;
                                }
                            }
                            continue;
                        }
                        other => {
                            warn!(
                                msg_type = %log_sample(other),
                                "unknown internal message type; ignoring"
                            );
                            continue;
                        }
                    }
                } else {
                    // Fallback: try raw TemplatePropose (template-manager protocol).
                    match serde_json::from_str::<TemplatePropose>(trimmed) {
                        Ok(p) => {
                            if uses_envelope.is_none() {
                                uses_envelope = Some(false);
                            }
                            p
                        }
                        Err(e) => {
                            warn!(error = %log_display(&e), "template JSON parse error");
                            continue;
                        }
                    }
                };

            let mempool_tx_count: Option<u64> = if let Some(ref url) = url_clone {
                let result = timeout(
                    Duration::from_millis(600),
                    mempool_client::fetch_mempool_tx_count(url),
                )
                .await
                .ok() // Result<Option<u64>, Elapsed> -> Option<Option<u64>>
                .flatten(); // Option<Option<u64>> -> Option<u64>
                if result.is_some() {
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    LAST_MEMPOOL_OK_UNIX.store(now, Ordering::Relaxed);
                }
                result
            } else {
                None
            };

            // System error boundary: recover from poisoned lock.
            // Extract config synchronously so the RwLockReadGuard is
            // dropped before any .await (RwLockReadGuard is !Send).
            let (cfg_opt, is_poisoned) = match state_clone.policy.read() {
                Ok(holder) => (Some(holder.config.clone()), false),
                Err(_poisoned) => {
                    error!("policy lock poisoned, rejecting template (fail-closed)");
                    (None, true)
                }
            };

            if is_poisoned {
                // Emit PolicyLoadError verdict and skip normal evaluation.
                let verdict = TemplateVerdict {
                    version: PROTOCOL_VERSION,
                    id: propose.id,
                    accepted: false,
                    reason_code: Some(VerdictReason::PolicyLoadError),
                    reason_detail: Some("policy lock poisoned".to_string()),
                    policy_context: None,
                };
                let log_id: u64 = id_ctr.fetch_add(1, Ordering::Relaxed);
                let logged = LoggedVerdict {
                    log_id,
                    template_id: propose.id,
                    height: propose.block_height,
                    total_fees: propose.total_fees,
                    tx_count: propose.tx_count,
                    accepted: false,
                    reason: Some(VerdictReason::PolicyLoadError.as_str().to_string()),
                    reason_code: Some(VerdictReason::PolicyLoadError.as_str().to_string()),
                    reason_detail: Some("policy lock poisoned".to_string()),
                    timestamp: current_timestamp(),
                    min_avg_fee_used: 0,
                    fee_tier: "unknown".to_string(),
                    tier_source: "fallback".to_string(),
                    avg_fee_sats_per_tx: 0,
                    template_weight: None,
                    total_sigops: None,
                    coinbase_sigops: None,
                    created_at_unix_ms: None,
                    safety_warnings: vec![],
                };
                metrics.templates_evaluated_total.inc();
                metrics
                    .verdicts_total
                    .get_or_create(&VerdictLabels {
                        accepted: "false".into(),
                        reason_code: logged
                            .reason_code
                            .clone()
                            .unwrap_or_else(|| "unknown".into()),
                    })
                    .inc();
                {
                    let mut guard = log
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    guard.push(logged.clone());
                    if guard.len() > max_log {
                        let excess = guard.len() - max_log;
                        guard.drain(0..excess);
                    }
                }
                let logged_for_disk = logged.clone();
                tokio::task::spawn_blocking(move || {
                    append_verdict_to_disk(&logged_for_disk);
                });
                let json = if uses_envelope == Some(true) {
                    let env = InternalMessage {
                        msg_type: msg_types::TEMPLATE_VERDICT.to_string(),
                        version: PROTOCOL_VERSION,
                        payload: serde_json::to_value(&verdict).unwrap_or_default(),
                    };
                    serde_json::to_string(&env)
                } else {
                    serde_json::to_string(&verdict)
                };
                if let Ok(j) = json {
                    if let Err(e) = writer.write_all(j.as_bytes()).await {
                        warn!(error = %e, "verdict write failed");
                        return;
                    }
                    if let Err(e) = writer.write_all(b"\n").await {
                        warn!(error = %e, "verdict newline write failed");
                        return;
                    }
                    if let Err(e) = writer.flush().await {
                        warn!(error = %e, "verdict flush failed");
                        return;
                    }
                }
                continue;
            }

            // cfg_opt is always Some here because the is_poisoned branch
            // above hits `continue` before reaching this point.
            let Some(cfg) = cfg_opt else { continue };

            let tier_source = if mempool_tx_count.is_some() {
                "measured"
            } else {
                "fallback"
            };

            let now_ms = current_timestamp_ms();
            // Phase 2 path: if AppState carries a mempool view, snapshot
            // it once and evaluate with Class M wired; the same snapshot
            // refreshes the view gauges below. Phase 1 path otherwise.
            let mempool_snap = if let Some(view) = state_clone.mempool_view.as_ref() {
                Some(view.snapshot().await)
            } else {
                None
            };
            let eval = if let Some(snap) = mempool_snap.as_ref() {
                pool_verifier::policy::evaluate_dynamic_phase2(
                    &propose,
                    &cfg,
                    Some(snap),
                    mempool_tx_count,
                    now_ms,
                )
            } else {
                pool_verifier::policy::evaluate_dynamic(&propose, &cfg, mempool_tx_count, now_ms)
            };

            let accepted = eval.reason.is_none();

            // reason_code string comes from rg-protocol — single source of truth.
            let reason_code_str: Option<String> =
                eval.reason.as_ref().map(|r| r.as_str().to_string());

            // ── Phase 2 Class M observability (ADR-003, PB-18a) ──
            // The result label for verifier_phase2_checks_total comes
            // from eval.phase2, reported by the evaluation path itself,
            // so ingress cannot misattribute templates where Class M
            // never ran (no raw_block_hex, pre-shield rejection) and
            // cannot mislabel on a view-state flip between two snapshot
            // reads. NotRun increments nothing. Degraded, a primed view
            // that aged out, increments verifier_phase2_degraded_total;
            // Unprimed, the boot window before the first poll, does not
            // (PB-13). The gauges are view state rather than
            // per-template attribution, so the single snapshot taken
            // for evaluation refreshes them and dashboards see
            // freshness without an extra polling loop.
            if let Some(snap) = mempool_snap.as_ref() {
                metrics
                    .mempool_view_age_seconds
                    .set(i64::try_from(snap.age_secs).unwrap_or(i64::MAX));
                metrics
                    .mempool_view_size
                    .set(i64::try_from(snap.size).unwrap_or(i64::MAX));
                let result_label = match eval.phase2 {
                    Phase2Attribution::NotRun => None,
                    Phase2Attribution::Agreed => Some("agreed"),
                    Phase2Attribution::Stale => Some("stale"),
                    Phase2Attribution::SkippedDegraded => {
                        metrics.phase2_degraded_total.inc();
                        Some("skipped")
                    }
                    Phase2Attribution::SkippedUnprimed => Some("unprimed"),
                    Phase2Attribution::Rejected => Some("rejected"),
                };
                if let Some(result_label) = result_label {
                    metrics
                        .phase2_checks_total
                        .get_or_create(&crate::metrics::Phase2CheckLabels {
                            result: result_label.to_string(),
                        })
                        .inc();
                }
            }

            let reason_detail_str: Option<String> = eval.detail.clone();

            let avg_fee = crate::handlers::compute_avg_fee_sats_per_tx(&propose);

            // Emit structured warnings for observe only safety findings.
            let safety_warning_codes: Vec<String> = eval
                .warnings
                .iter()
                .map(|w| {
                    warn!(
                        template_id = propose.id,
                        height = propose.block_height,
                        warning = w.reason.as_str(),
                        detail = %w.detail,
                        "safety warning"
                    );
                    w.reason.as_str().to_string()
                })
                .collect();

            let policy_ctx = PolicyContext {
                fee_tier: Some(eval.fee_tier.as_str().to_string()),
                min_avg_fee_used: Some(eval.min_avg_fee_used),
                min_total_fees_used: Some(cfg.min_total_fees),
                reject_coinbase_zero: Some(cfg.reject_coinbase_zero),
                unknown_mempool_as_high: Some(cfg.unknown_mempool_as_high),
                max_weight_ratio: Some(cfg.safety.max_weight_ratio),
                max_template_age_ms: cfg.safety.max_template_age_ms,
            };

            let verdict = TemplateVerdict {
                version: PROTOCOL_VERSION,
                id: propose.id,
                accepted,
                reason_code: eval.reason,
                reason_detail: eval.detail.clone(),
                policy_context: Some(policy_ctx),
            };

            let log_id: u64 = id_ctr.fetch_add(1, Ordering::Relaxed);

            let logged = LoggedVerdict {
                log_id,
                template_id: propose.id,
                height: propose.block_height,
                total_fees: propose.total_fees,
                tx_count: propose.tx_count,
                accepted,

                // UI string: prefer reason_code; fallback to detail; fallback to ok.
                reason: reason_code_str
                    .clone()
                    .or_else(|| reason_detail_str.clone())
                    .or(Some("ok".to_string())),

                reason_code: reason_code_str,
                reason_detail: reason_detail_str,

                timestamp: current_timestamp(),

                min_avg_fee_used: eval.min_avg_fee_used,
                fee_tier: eval.fee_tier.as_str().to_string(),
                tier_source: tier_source.to_string(),
                avg_fee_sats_per_tx: avg_fee,

                template_weight: propose.template_weight.or(propose.observed_weight),
                total_sigops: propose.total_sigops,
                coinbase_sigops: propose.coinbase_sigops,
                created_at_unix_ms: propose.created_at_unix_ms,
                safety_warnings: safety_warning_codes,
            };

            metrics.templates_evaluated_total.inc();
            metrics
                .verdicts_total
                .get_or_create(&VerdictLabels {
                    accepted: accepted.to_string(),
                    reason_code: logged.reason_code.clone().unwrap_or_else(|| "ok".into()),
                })
                .inc();

            // ADR-002 Phase 1: count templates that reached the v2.0 Invariant
            // Shield pass but omitted `raw_block_hex`. Dashboards use this to
            // measure rollout coverage of gateways that ship raw block bytes.
            if eval.shield_skipped {
                metrics.shield_skipped_total.inc();
            }

            {
                let mut guard = log
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                guard.push(logged.clone());
                if guard.len() > max_log {
                    let excess = guard.len() - max_log;
                    guard.drain(0..excess);
                }
            }

            let logged_for_disk = logged.clone();
            tokio::task::spawn_blocking(move || {
                append_verdict_to_disk(&logged_for_disk);
            });

            let json = if uses_envelope == Some(true) {
                let env = InternalMessage {
                    msg_type: msg_types::TEMPLATE_VERDICT.to_string(),
                    version: PROTOCOL_VERSION,
                    payload: serde_json::to_value(&verdict).unwrap_or_default(),
                };
                serde_json::to_string(&env)
            } else {
                serde_json::to_string(&verdict)
            };
            let json = match json {
                Ok(j) => j,
                Err(e) => {
                    error!(error = ?e, "serialize verdict error");
                    break;
                }
            };

            if writer.write_all(json.as_bytes()).await.is_err() {
                break;
            }
            if writer.write_all(b"\n").await.is_err() {
                break;
            }
            if writer.flush().await.is_err() {
                break;
            }
        }
    }
}

/// API key middleware for protecting routes.
///
/// When `VELDRA_API_SECRET` is set (enforced at startup unless opted out),
/// every non-public request must carry `Authorization: Bearer <secret>`.
/// No localhost bypass: all callers are treated equally.
pub(crate) async fn api_key_middleware(
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    req: Request<Body>,
    next: Next,
) -> Response {
    use std::env;

    // If VELDRA_API_SECRET_OPTIONAL=1 was set and no secret exists, allow all.
    let expected = match env::var("VELDRA_API_SECRET") {
        Ok(k) if !k.is_empty() => k,
        _ => return next.run(req).await,
    };

    // Check Authorization header: "Bearer <key>" or raw key.
    let authorized = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            let stripped = v.strip_prefix("Bearer ").unwrap_or(v);
            stripped.as_bytes().ct_eq(expected.as_bytes()).into()
        });

    if authorized {
        next.run(req).await
    } else {
        tracing::warn!(
            peer = %addr,
            path = %req.uri().path(),
            "api_key_auth_failed"
        );
        (StatusCode::UNAUTHORIZED, "missing or invalid api key").into_response()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{BoundedLine, LOG_SAMPLE_BYTES, log_display, log_sample, read_bounded_line};
    use rg_protocol::TemplatePropose;
    use rg_protocol::gateway::MAX_INTERNAL_LINE_BYTES;
    use tokio::io::BufReader;

    // ── PB-23 parity: log write amplification through the error field ──
    //
    // This ingress never logged the offending line, so it did not carry
    // the gateway's original defect. It carried the other half: both
    // parse-failure sites render a `serde_json::Error`, whose Display
    // embeds the offending input verbatim. `TemplatePropose::id` is a
    // `u64`, so a giant string there is valid JSON that fails typing.

    fn hostile_propose_line(body: &str) -> String {
        format!(r#"{{"version":1,"id":"{body}"}}"#)
    }

    #[test]
    fn log_display_caps_the_raw_template_parse_error() {
        // The fallback site: `serde_json::from_str::<TemplatePropose>`.
        let line = hostile_propose_line(&"A".repeat(1_000_000));
        let e = serde_json::from_str::<TemplatePropose>(&line).unwrap_err();

        let uncapped = e.to_string().len();
        assert!(
            uncapped > 1_000_000,
            "expected the error to carry the line, got {uncapped} bytes"
        );

        let out = log_display(&e);
        assert!(
            out.len() < LOG_SAMPLE_BYTES + 64,
            "error field reached the log as {} bytes",
            out.len()
        );
        assert!(out.contains("truncated"), "truncation must be visible");
        assert!(
            out.contains(&uncapped.to_string()),
            "the real length must survive into the log"
        );
    }

    #[test]
    fn log_display_caps_the_envelope_payload_parse_error() {
        // The envelope site: `serde_json::from_value::<TemplatePropose>`
        // on `InternalMessage::payload`.
        let payload = serde_json::json!({ "version": 1, "id": "A".repeat(1_000_000) });
        let e = serde_json::from_value::<TemplatePropose>(payload).unwrap_err();

        assert!(e.to_string().len() > 1_000_000);
        let out = log_display(&e);
        assert!(out.len() < LOG_SAMPLE_BYTES + 64);
        assert!(out.contains("truncated"));
    }

    #[test]
    fn log_display_passes_short_errors_through_untouched() {
        let e = serde_json::from_str::<TemplatePropose>("{").unwrap_err();
        assert_eq!(log_display(&e), e.to_string());
    }

    #[test]
    fn log_sample_caps_a_hostile_msg_type() {
        // `InternalMessage::msg_type` is a peer-supplied String bounded
        // only by MAX_INTERNAL_LINE_BYTES, and the unknown-type warning
        // that logs it has no strike counter, so it repeats for the life
        // of the connection.
        let msg_type = "A".repeat(MAX_INTERNAL_LINE_BYTES);
        let out = log_sample(&msg_type);
        assert!(
            out.len() < LOG_SAMPLE_BYTES + 64,
            "msg_type reached the log as {} bytes",
            out.len()
        );
        assert!(out.contains("truncated"));
        assert!(out.contains(&MAX_INTERNAL_LINE_BYTES.to_string()));

        // Short types pass through borrowed, so the common path allocates
        // nothing.
        assert!(matches!(
            log_sample("template_verdict"),
            std::borrow::Cow::Borrowed(_)
        ));
    }

    /// Sink that collects everything a `tracing` subscriber writes, so a
    /// test can assert on the bytes that actually reach a log rather than
    /// on the capping helpers called in isolation.
    #[derive(Clone, Default)]
    struct CapturedLog(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for CapturedLog {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedLog {
        type Writer = Self;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    #[tokio::test]
    async fn hostile_inbound_lines_emit_bounded_log_records() {
        use crate::state::{AppState, PolicyHolder};
        use pool_verifier::policy::PolicyConfig;
        use rg_protocol::PROTOCOL_VERSION;

        // Asserted on the emitted records and through the real
        // `handle_tcp_connection`, so a future edit that drops a capping
        // call at a call site fails here rather than passing because the
        // helper is still correct in isolation.
        let big = "A".repeat(1_000_000);

        // 1. Envelope parses, `msg_type` itself is the hostile string.
        let unknown_type = format!(r#"{{"msg_type":"{big}","version":1,"payload":{{}}}}"#);
        // 2. Envelope parses, `TemplatePropose` typing fails on the payload.
        let bad_payload =
            format!(r#"{{"msg_type":"template_propose","version":1,"payload":{{"id":"{big}"}}}}"#);
        // 3. Not an envelope, so the raw `TemplatePropose` fallback runs
        //    and fails typing there.
        let bad_raw = format!(r#"{{"version":1,"id":"{big}"}}"#);

        let stream = format!("{unknown_type}\n{bad_payload}\n{bad_raw}\n");
        let sent = stream.len();

        let app_state = AppState {
            policy: std::sync::Arc::new(std::sync::RwLock::new(PolicyHolder {
                config: PolicyConfig::default_with_protocol(PROTOCOL_VERSION),
                toml_text: String::new(),
            })),
            mempool_view: None,
        };
        let mut registry = prometheus_client::registry::Registry::default();
        let metrics = std::sync::Arc::new(crate::metrics::VerifierMetrics::new_registered(
            &mut registry,
        ));

        let captured = CapturedLog::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(captured.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::DEBUG)
            .finish();

        {
            let _guard = tracing::subscriber::set_default(subscriber);
            super::handle_tcp_connection(
                stream.as_bytes(),
                tokio::io::sink(),
                app_state,
                std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
                None,
                std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
                metrics,
            )
            .await;
        }

        let emitted = captured.0.lock().unwrap().len();
        assert!(
            emitted < 8192,
            "{sent} bytes of hostile input produced {emitted} bytes of \
             log; every peer-controlled field must be capped at \
             {LOG_SAMPLE_BYTES}"
        );
    }

    #[test]
    fn log_display_truncates_on_a_char_boundary() {
        // 3-byte chars, so the 512 cap never lands on a boundary. A naive
        // slice here panics on input the peer chooses.
        let line = hostile_propose_line(&"\u{4e16}".repeat(400_000));
        let e = serde_json::from_str::<TemplatePropose>(&line).unwrap_err();
        let out = log_display(&e);
        assert!(out.contains("truncated"));
        assert!(out.len() < LOG_SAMPLE_BYTES + 64);
    }

    #[tokio::test]
    async fn read_bounded_line_reads_normal_lines_then_eof() {
        let data: &[u8] = b"hello world\nsecond\n";
        let mut reader = BufReader::new(data);
        let mut buf = String::new();

        let r = read_bounded_line(&mut reader, &mut buf, 64).await.unwrap();
        assert_eq!(r, BoundedLine::Line);
        assert_eq!(buf, "hello world\n");

        buf.clear();
        let r = read_bounded_line(&mut reader, &mut buf, 64).await.unwrap();
        assert_eq!(r, BoundedLine::Line);
        assert_eq!(buf, "second\n");

        buf.clear();
        let r = read_bounded_line(&mut reader, &mut buf, 64).await.unwrap();
        assert_eq!(r, BoundedLine::Eof);
        assert!(buf.is_empty());
    }

    #[tokio::test]
    async fn read_bounded_line_over_limit_without_newline_is_protocol_error() {
        // 64-byte budget, 200 newline-free bytes on the wire: the
        // PB-18(b) attack shape. The buffer must never grow past the
        // budget and the caller gets `OverLimit` to drop the
        // connection.
        let data = vec![b'a'; 200];
        let mut reader = BufReader::new(data.as_slice());
        let mut buf = String::new();
        let r = read_bounded_line(&mut reader, &mut buf, 64).await.unwrap();
        assert_eq!(r, BoundedLine::OverLimit);
        assert!(
            buf.len() <= 64,
            "buffer must stay within budget, got {} bytes",
            buf.len()
        );
    }

    #[tokio::test]
    async fn read_bounded_line_exact_budget_line_with_newline_is_ok() {
        // An 8-byte line whose final byte is the newline fits an
        // 8-byte budget exactly.
        let data: &[u8] = b"1234567\n";
        let mut reader = BufReader::new(data);
        let mut buf = String::new();
        let r = read_bounded_line(&mut reader, &mut buf, 8).await.unwrap();
        assert_eq!(r, BoundedLine::Line);
        assert_eq!(buf, "1234567\n");
    }

    #[tokio::test]
    async fn read_bounded_line_final_unterminated_line_at_eof_is_line() {
        // Matches plain read_line semantics: a trailing line without
        // a newline at EOF is still a line (the next call reports
        // Eof), as long as it is under the budget.
        let data: &[u8] = b"tail-no-newline";
        let mut reader = BufReader::new(data);
        let mut buf = String::new();
        let r = read_bounded_line(&mut reader, &mut buf, 64).await.unwrap();
        assert_eq!(r, BoundedLine::Line);
        assert_eq!(buf, "tail-no-newline");

        buf.clear();
        let r = read_bounded_line(&mut reader, &mut buf, 64).await.unwrap();
        assert_eq!(r, BoundedLine::Eof);
    }
}
