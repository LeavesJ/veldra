//! Verifier NDJSON TCP stream connection.
//!
//! Maintains a persistent TCP connection to the pool-verifier, sending
//! `template_propose` messages and receiving `template_verdict` responses.
//! `Heartbeat/heartbeat_ack` pairs keep the connection alive and drive the
//! readiness probe.
//!
//! When TLS is configured (`tls_config` present in `VerifierStreamConfig`),
//! the raw TCP stream is wrapped with `tokio_rustls::TlsConnector` using
//! mTLS client certificates. The NDJSON framing is unchanged.

use std::sync::Arc;
use std::time::Duration;

use reservegrid_common::reason::GatewayReason;
use rg_protocol::gateway::{InternalMessage, MAX_INTERNAL_LINE_BYTES, msg_types};
use rg_protocol::{PROTOCOL_VERSION, TemplatePropose, TemplateVerdict};
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
};
use tokio::net::TcpStream;
use tokio::sync::{broadcast, mpsc, watch};
use tracing::{debug, error, info, warn};

use crate::health::ReadinessState;

// ─────────────────────────────────────────────────────────────────────
// Message types flowing through the stream
// ─────────────────────────────────────────────────────────────────────

/// Outbound message to send to the verifier.
#[derive(Debug)]
pub enum VerifierOutbound {
    /// Propose a template for verification.
    TemplatePropose(TemplatePropose),
    /// Send a heartbeat.
    Heartbeat,
}

/// Inbound message received from the verifier.
#[derive(Debug, Clone)]
pub enum VerifierInbound {
    /// A verdict on a previously proposed template.
    TemplateVerdict(TemplateVerdict),
    /// Heartbeat acknowledgment (verifier is alive).
    HeartbeatAck,
}

// ─────────────────────────────────────────────────────────────────────
// Verifier connection task
// ─────────────────────────────────────────────────────────────────────

/// TLS configuration for the verifier channel (mTLS).
pub struct VerifierTlsConfig {
    /// TLS connector built from CA cert + client cert/key.
    pub connector: tokio_rustls::TlsConnector,
    /// Server name for SNI and certificate verification.
    pub server_name: tokio_rustls::rustls::pki_types::ServerName<'static>,
}

/// Configuration for the verifier connection.
pub struct VerifierStreamConfig {
    /// TCP address of the verifier.
    pub addr: String,
    /// Reconnect delay on disconnect.
    pub reconnect_delay: Duration,
    /// Heartbeat interval.
    pub heartbeat_interval: Duration,
    /// Health probe staleness threshold.
    pub health_probe_staleness_ms: u64,
    /// Optional TLS configuration. When `Some`, the TCP stream is wrapped
    /// with mTLS before NDJSON framing begins.
    pub tls_config: Option<VerifierTlsConfig>,
}

/// Run the verifier connection loop.
///
/// Connects to the verifier, reads NDJSON lines, dispatches verdicts
/// via the `verdict_tx` broadcast channel, and sends outbound messages
/// from `outbound_rx`. Reconnects automatically on failure.
///
/// Updates `readiness_state.verifier_connected` and `readiness_state.policy_loaded`.
#[allow(clippy::too_many_lines)] // Single async select loop; splitting obscures flow.
pub async fn run_verifier_stream(
    config: VerifierStreamConfig,
    outbound_rx: mpsc::Receiver<VerifierOutbound>,
    verdict_tx: broadcast::Sender<VerifierInbound>,
    readiness: Arc<ReadinessState>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut outbound_rx = outbound_rx;

    loop {
        // Check for shutdown.
        if *shutdown.borrow() {
            info!("verifier stream shutting down");
            return;
        }

        info!(addr = %config.addr, "connecting to verifier");
        readiness
            .verifier_connected
            .store(false, std::sync::atomic::Ordering::SeqCst);

        let tcp_stream = match TcpStream::connect(&config.addr).await {
            Ok(s) => {
                info!(addr = %config.addr, "TCP connected to verifier");
                s
            }
            Err(e) => {
                warn!(
                    addr = %config.addr,
                    error = %e,
                    "failed to connect to verifier; retrying"
                );
                tokio::select! {
                    () = tokio::time::sleep(config.reconnect_delay) => continue,
                    _ = shutdown.changed() => return,
                }
            }
        };

        // Wrap with TLS if configured, then run the I/O loop on the
        // resulting (reader, writer) pair. The NDJSON framing is identical
        // regardless of the transport layer.
        let io_result = if let Some(ref tls) = config.tls_config {
            match tls
                .connector
                .connect(tls.server_name.clone(), tcp_stream)
                .await
            {
                Ok(tls_stream) => {
                    info!(addr = %config.addr, "TLS handshake succeeded (mTLS)");
                    readiness
                        .verifier_connected
                        .store(true, std::sync::atomic::Ordering::SeqCst);
                    let (reader, writer) = tokio::io::split(tls_stream);
                    run_io_loop(
                        reader,
                        writer,
                        &mut outbound_rx,
                        &verdict_tx,
                        &readiness,
                        &config,
                        &mut shutdown,
                    )
                    .await
                }
                Err(e) => {
                    warn!(
                        addr = %config.addr,
                        error = %e,
                        "TLS handshake failed; retrying"
                    );
                    IoLoopOutcome::Disconnected
                }
            }
        } else {
            readiness
                .verifier_connected
                .store(true, std::sync::atomic::Ordering::SeqCst);
            let (reader, writer) = tcp_stream.into_split();
            run_io_loop(
                reader,
                writer,
                &mut outbound_rx,
                &verdict_tx,
                &readiness,
                &config,
                &mut shutdown,
            )
            .await
        };

        if matches!(io_result, IoLoopOutcome::Shutdown) {
            return;
        }

        // Disconnected; mark unhealthy and reconnect.
        readiness
            .verifier_connected
            .store(false, std::sync::atomic::Ordering::SeqCst);
        readiness
            .policy_loaded
            .store(false, std::sync::atomic::Ordering::SeqCst);

        // Add jitter (0..50% of base delay) to prevent thundering herd
        // when multiple gateways reconnect after a verifier restart.
        let jitter_ms = {
            use std::hash::{Hash, Hasher};
            let mut h = std::hash::DefaultHasher::new();
            std::time::Instant::now().hash(&mut h);
            let base_ms = config.reconnect_delay.as_millis() / 2;
            let half = u64::try_from(base_ms).unwrap_or(u64::MAX);
            h.finish() % half.max(1)
        };
        let delay = config.reconnect_delay + Duration::from_millis(jitter_ms);

        tokio::select! {
            () = tokio::time::sleep(delay) => {}
            _ = shutdown.changed() => return,
        }
    }
}

/// Outcome of a single connection's I/O loop.
enum IoLoopOutcome {
    /// Connection was lost (EOF, error, or TLS failure). Caller should reconnect.
    Disconnected,
    /// Graceful shutdown requested. Caller should exit.
    Shutdown,
}

/// Result of one bounded NDJSON line read (PB-23).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BoundedLine {
    /// A complete line: newline-terminated within the budget, or a final
    /// unterminated line at EOF that stayed under the budget.
    Line,
    /// Clean EOF with no pending bytes.
    Eof,
    /// The peer spent the whole budget without sending a newline. The
    /// caller drops the connection.
    OverLimit,
}

/// Longest prefix of a rejected line that reaches the log.
///
/// A malformed line is bounded by `MAX_INTERNAL_LINE_BYTES` but that
/// bound is 20 MiB, and the three-strike counter lets a peer spend
/// three of them before the connection drops. Logging the line whole
/// would hand a hostile verifier 60 MiB of log write amplification per
/// connection off 60 MiB of send, which is the same asymmetry PB-23
/// closed on the read side. PB-19 widened this 20x when it raised the
/// line budget from 1 MiB for `raw_block_hex`.
const LOG_SAMPLE_BYTES: usize = 512;

/// Bound a line before it reaches a log field, on a char boundary so
/// the output stays valid UTF-8, marking any truncation so a reader
/// never mistakes a sample for the whole message.
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

/// Read one newline-terminated line into `buf`, enforcing `max_bytes`
/// per line via `AsyncReadExt::take` so a verifier that never sends a
/// newline can never grow the gateway's line buffer without bound
/// (PB-23). The `take` adaptor is re-created per call, so the budget
/// resets for every line.
///
/// Mirrors `pool-verifier`'s `read_bounded_line` (PB-18b) with one
/// difference: the budget is charged against `buf.len()` rather than
/// applied flat, because this read is a `tokio::select!` branch and the
/// buffer outlives a single call. A cancelled `read_line` discards what
/// it had read (tokio moves the caller's `String` into the future and
/// drops it), so in practice `buf` is empty on entry, but the budget
/// must not silently become per-call if that ever changes.
async fn read_bounded_line<R>(
    reader: &mut R,
    buf: &mut String,
    max_bytes: u64,
) -> std::io::Result<BoundedLine>
where
    R: AsyncBufRead + Unpin,
{
    let already = u64::try_from(buf.len()).unwrap_or(u64::MAX);
    let remaining = max_bytes.saturating_sub(already);
    if remaining == 0 {
        // `take(0)` would report `Ok(0)`, indistinguishable from EOF.
        return Ok(BoundedLine::OverLimit);
    }
    let n = (&mut *reader).take(remaining).read_line(buf).await?;
    if n == 0 {
        return Ok(BoundedLine::Eof);
    }
    if u64::try_from(n).unwrap_or(u64::MAX) >= remaining && !buf.ends_with('\n') {
        return Ok(BoundedLine::OverLimit);
    }
    Ok(BoundedLine::Line)
}

/// Inner I/O loop that is transport-agnostic. Accepts any `AsyncRead + AsyncWrite`
/// pair, so the same logic serves both plaintext TCP and TLS streams.
async fn run_io_loop<R, W>(
    reader: R,
    mut writer: W,
    outbound_rx: &mut mpsc::Receiver<VerifierOutbound>,
    verdict_tx: &broadcast::Sender<VerifierInbound>,
    readiness: &ReadinessState,
    config: &VerifierStreamConfig,
    shutdown: &mut watch::Receiver<bool>,
) -> IoLoopOutcome
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut reader = BufReader::new(reader);
    let mut line_buf = String::new();
    let mut heartbeat_interval = tokio::time::interval(config.heartbeat_interval);
    let mut malformed_count: u32 = 0;
    // PB-23: per-line byte budget, shared with the verifier's ingress.
    let max_line_bytes = u64::try_from(MAX_INTERNAL_LINE_BYTES).unwrap_or(u64::MAX);

    loop {
        tokio::select! {
            result = read_bounded_line(&mut reader, &mut line_buf, max_line_bytes) => {
                match result {
                    Ok(BoundedLine::Eof) => {
                        warn!("verifier connection closed (EOF)");
                        return IoLoopOutcome::Disconnected;
                    }
                    Ok(BoundedLine::OverLimit) => {
                        // PB-23: the read stops at the budget, so the rest of
                        // this line is still unread on the wire. A bounded
                        // reader cannot resync to the next newline without
                        // consuming an unbounded tail, so the previous
                        // skip-then-three-strikes policy would now be a lie:
                        // the next read would return the middle of this line,
                        // not the next message. Drop the connection instead,
                        // matching the verifier ingress (PB-18b). The outer
                        // loop reconnects. The three-strike counter still
                        // governs malformed-but-bounded lines below, where
                        // framing is intact and resync is honest.
                        error!(
                            reason_code = GatewayReason::InternalLineTooLarge.as_str(),
                            max_bytes = MAX_INTERNAL_LINE_BYTES,
                            "verifier line exceeded MAX_INTERNAL_LINE_BYTES without a newline; disconnecting"
                        );
                        return IoLoopOutcome::Disconnected;
                    }
                    Ok(BoundedLine::Line) => {
                        match serde_json::from_str::<InternalMessage>(line_buf.trim()) {
                            Ok(msg) => {
                                dispatch_inbound(&msg, verdict_tx, readiness);
                            }
                            Err(e) => {
                                warn!(
                                    error = %e,
                                    line = %log_sample(line_buf.trim()),
                                    "malformed verifier message"
                                );
                                malformed_count += 1;
                                if malformed_count >= 3 {
                                    error!("3 malformed lines; disconnecting");
                                    return IoLoopOutcome::Disconnected;
                                }
                            }
                        }
                        line_buf.clear();
                    }
                    Err(e) => {
                        warn!(error = %e, "verifier read error");
                        return IoLoopOutcome::Disconnected;
                    }
                }
            }

            msg = outbound_rx.recv() => {
                if let Some(outbound) = msg {
                    let line = match serialize_outbound(&outbound) {
                        Ok(l) => l,
                        Err(e) => {
                            error!(error = %e, "failed to serialize outbound message");
                            continue;
                        }
                    };
                    if let Err(e) = writer.write_all(line.as_bytes()).await {
                        warn!(error = %e, "verifier write error");
                        return IoLoopOutcome::Disconnected;
                    }
                    if let Err(e) = writer.flush().await {
                        warn!(error = %e, "verifier flush error");
                        return IoLoopOutcome::Disconnected;
                    }
                } else {
                    info!("outbound channel closed; shutting down verifier stream");
                    return IoLoopOutcome::Shutdown;
                }
            }

            _ = heartbeat_interval.tick() => {
                let hb = match serialize_outbound(&VerifierOutbound::Heartbeat) {
                    Ok(line) => line,
                    Err(e) => {
                        error!(error = %e, "heartbeat serialization failed");
                        continue;
                    }
                };
                if let Err(e) = writer.write_all(hb.as_bytes()).await {
                    warn!(error = %e, "heartbeat write failed");
                    return IoLoopOutcome::Disconnected;
                }
                if let Err(e) = writer.flush().await {
                    warn!(error = %e, "heartbeat flush failed");
                    return IoLoopOutcome::Disconnected;
                }
                debug!("heartbeat sent");
            }

            _ = shutdown.changed() => {
                info!("shutdown signal received; closing verifier stream");
                return IoLoopOutcome::Shutdown;
            }
        }
    }
}

/// Dispatch an inbound message from the verifier.
fn dispatch_inbound(
    msg: &InternalMessage,
    verdict_tx: &broadcast::Sender<VerifierInbound>,
    readiness: &ReadinessState,
) {
    match msg.msg_type.as_str() {
        msg_types::TEMPLATE_VERDICT => {
            match serde_json::from_value::<TemplateVerdict>(msg.payload.clone()) {
                Ok(verdict) => {
                    debug!(
                        template_id = verdict.id,
                        accepted = verdict.accepted,
                        "received template verdict"
                    );
                    if verdict_tx
                        .send(VerifierInbound::TemplateVerdict(verdict))
                        .is_err()
                    {
                        warn!("verdict_tx has no receivers; template verdict dropped");
                    }
                }
                Err(e) => {
                    warn!(error = %e, "failed to parse template_verdict payload");
                }
            }
        }
        msg_types::HEARTBEAT_ACK => {
            debug!("received heartbeat_ack");
            readiness
                .policy_loaded
                .store(true, std::sync::atomic::Ordering::SeqCst);
            if verdict_tx.send(VerifierInbound::HeartbeatAck).is_err() {
                warn!("verdict_tx has no receivers; heartbeat ack dropped");
            }
        }
        other => {
            debug!(msg_type = other, "unknown verifier message type; ignoring");
        }
    }
}

/// Serialize an outbound message as an NDJSON line.
fn serialize_outbound(msg: &VerifierOutbound) -> Result<String, serde_json::Error> {
    let internal = match msg {
        VerifierOutbound::TemplatePropose(tp) => InternalMessage {
            msg_type: msg_types::TEMPLATE_PROPOSE.to_string(),
            version: PROTOCOL_VERSION,
            payload: serde_json::to_value(tp)?,
        },
        VerifierOutbound::Heartbeat => InternalMessage {
            msg_type: msg_types::HEARTBEAT.to_string(),
            version: PROTOCOL_VERSION,
            payload: serde_json::json!({}),
        },
    };
    let mut line = serde_json::to_string(&internal)?;
    line.push('\n');
    Ok(line)
}

// ─────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
    use std::task::{Context, Poll};
    use tokio::io::{AsyncReadExt, ReadBuf};

    // ── PB-23: log write amplification ──

    #[test]
    fn log_sample_passes_short_lines_through_untouched() {
        let line = r#"{"kind":"verdict","id":7}"#;
        assert_eq!(log_sample(line), line);
        // Borrowed, so the common path allocates nothing.
        assert!(matches!(log_sample(line), std::borrow::Cow::Borrowed(_)));
    }

    #[test]
    fn log_sample_caps_a_hostile_line_and_marks_it() {
        // A malformed line may be up to MAX_INTERNAL_LINE_BYTES, and
        // three of them land before the connection drops.
        let line = "x".repeat(MAX_INTERNAL_LINE_BYTES);
        let out = log_sample(&line);
        assert!(
            out.len() < LOG_SAMPLE_BYTES + 64,
            "20 MiB line reached the log as {} bytes",
            out.len()
        );
        assert!(out.contains("truncated"), "truncation must be visible");
        assert!(
            out.contains(&MAX_INTERNAL_LINE_BYTES.to_string()),
            "the real length must survive into the log"
        );
    }

    #[test]
    fn log_sample_truncates_on_a_char_boundary() {
        // A naive `&line[..LOG_SAMPLE_BYTES]` panics when the cap
        // lands mid-codepoint, which an attacker picks deliberately.
        // 3-byte chars mean 512 is never a boundary.
        let line = "\u{4e16}".repeat(MAX_INTERNAL_LINE_BYTES / 3);
        let out = log_sample(&line);
        assert!(out.contains("truncated"));
        assert!(out.len() < LOG_SAMPLE_BYTES + 64);
    }

    #[test]
    fn log_sample_boundary_is_exact() {
        let exact = "y".repeat(LOG_SAMPLE_BYTES);
        assert_eq!(log_sample(&exact), exact, "at the cap, pass through");
        let over = "y".repeat(LOG_SAMPLE_BYTES + 1);
        assert!(
            log_sample(&over).contains("truncated"),
            "one over, truncate"
        );
    }

    // ── PB-23 harness ──

    /// Reader that emits `remaining` newline-free bytes and then EOF,
    /// counting every byte it actually hands the caller. That counter is
    /// the PB-23 measurement: how much of a hostile line the gateway pulls
    /// into memory before the per-line budget stops it. Asserting on an
    /// eventual error would not distinguish "rejected the line" from
    /// "buffered 24 MiB and then rejected the line".
    struct CountingReader {
        remaining: usize,
        delivered: Arc<AtomicUsize>,
    }

    impl AsyncRead for CountingReader {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let me = self.get_mut();
            let chunk = [b'a'; 8192];
            let n = buf.remaining().min(me.remaining).min(chunk.len());
            if n == 0 {
                return Poll::Ready(Ok(())); // EOF
            }
            buf.put_slice(&chunk[..n]);
            me.remaining -= n;
            me.delivered.fetch_add(n, AtomicOrdering::SeqCst);
            Poll::Ready(Ok(()))
        }
    }

    /// Drive one connection's I/O loop over `reader` to completion and
    /// collect everything it dispatched. The heartbeat interval is set an
    /// hour out so the only traffic is what the test feeds in.
    async fn drive_io_loop<R>(reader: R) -> (IoLoopOutcome, Vec<VerifierInbound>)
    where
        R: AsyncRead + Unpin,
    {
        // Both senders must stay alive: dropping either would make the
        // loop exit through its shutdown path instead of the read path.
        let (_outbound_tx, mut outbound_rx) = mpsc::channel::<VerifierOutbound>(4);
        let (_shutdown_tx, mut shutdown) = watch::channel(false);
        let (verdict_tx, mut verdict_rx) = broadcast::channel(64);
        let readiness = ReadinessState::new();
        let config = VerifierStreamConfig {
            addr: "test".to_string(),
            reconnect_delay: Duration::from_millis(1),
            heartbeat_interval: Duration::from_secs(3600),
            health_probe_staleness_ms: 1000,
            tls_config: None,
        };

        let outcome = run_io_loop(
            reader,
            tokio::io::sink(),
            &mut outbound_rx,
            &verdict_tx,
            &readiness,
            &config,
            &mut shutdown,
        )
        .await;

        let mut received = Vec::new();
        while let Ok(msg) = verdict_rx.try_recv() {
            received.push(msg);
        }
        (outcome, received)
    }

    /// One NDJSON `heartbeat_ack` line.
    fn heartbeat_ack_line() -> String {
        let msg = InternalMessage {
            msg_type: msg_types::HEARTBEAT_ACK.to_string(),
            version: PROTOCOL_VERSION,
            payload: serde_json::json!({}),
        };
        format!("{}\n", serde_json::to_string(&msg).unwrap())
    }

    /// One NDJSON `template_verdict` line carrying `detail` bytes of
    /// human-readable detail.
    fn verdict_line(id: u64, detail: &str) -> String {
        let verdict = TemplateVerdict {
            version: PROTOCOL_VERSION,
            id,
            accepted: false,
            reason_code: None,
            reason_detail: Some(detail.to_string()),
            policy_context: None,
        };
        let msg = InternalMessage {
            msg_type: msg_types::TEMPLATE_VERDICT.to_string(),
            version: PROTOCOL_VERSION,
            payload: serde_json::to_value(&verdict).unwrap(),
        };
        format!("{}\n", serde_json::to_string(&msg).unwrap())
    }

    /// A `template_propose` line carrying a mainnet-sized `raw_block_hex`:
    /// 8 MiB of hex, the worst case a 4,000,000 WU block serializes to.
    /// This is the reason `MAX_INTERNAL_LINE_BYTES` is 20 MiB and not 1 MiB.
    fn mainnet_propose_line() -> String {
        let tp = TemplatePropose {
            version: PROTOCOL_VERSION,
            id: 1,
            block_height: 800_000,
            prev_hash: "aa".repeat(32),
            coinbase_value: 625_000_000,
            tx_count: 3000,
            total_fees: 50_000_000,
            observed_weight: Some(3_900_000),
            created_at_unix_ms: Some(1_700_000_000_000),
            total_sigops: Some(10000),
            coinbase_sigops: Some(4),
            template_weight: Some(3_950_000),
            gateway_instance_id: Some("test-gw-01".to_string()),
            raw_block_hex: Some("ab".repeat(4 * 1024 * 1024)),
        };
        serialize_outbound(&VerifierOutbound::TemplatePropose(tp)).unwrap()
    }

    // ── PB-23: the read must be bounded before the allocation, not after ──

    #[tokio::test]
    async fn oversize_line_is_not_pulled_past_the_budget() {
        // A verifier (hostile or broken) that never sends a newline. The
        // gateway must stop pulling at MAX_INTERNAL_LINE_BYTES. The old
        // read_line call pulled all 24 MiB and only then compared n to the
        // constant, so the bound was enforced after the allocation it
        // exists to prevent.
        let sent = MAX_INTERNAL_LINE_BYTES + 4 * 1024 * 1024;
        let delivered = Arc::new(AtomicUsize::new(0));
        let reader = CountingReader {
            remaining: sent,
            delivered: Arc::clone(&delivered),
        };

        let (outcome, received) = drive_io_loop(reader).await;
        let pulled = delivered.load(AtomicOrdering::SeqCst);

        // Slack of one BufReader refill (8 KiB capacity): `take` truncates
        // the slice it hands out, but the inner BufReader may already have
        // filled its buffer past the cut. 64 KiB covers that generously
        // and still fails loudly on a 24 MiB pull.
        assert!(
            pulled <= MAX_INTERNAL_LINE_BYTES + 64 * 1024,
            "pulled {pulled} bytes into memory for a single line; \
             budget is {MAX_INTERNAL_LINE_BYTES}, peer sent {sent}"
        );
        assert!(matches!(outcome, IoLoopOutcome::Disconnected));
        assert!(received.is_empty(), "nothing should have been dispatched");
    }

    #[tokio::test]
    async fn oversize_line_drops_the_connection_immediately() {
        // Deliberate policy change (PB-23). Once the read is bounded the
        // rest of the oversize line is still unread on the wire, so the old
        // "skip it and disconnect on the third" path could not honestly
        // resume at the next message. The connection drops on the first
        // oversize line, so the following well-formed heartbeat_ack is
        // never dispatched. Under the unbounded read it was.
        let tail = format!("\n{}", heartbeat_ack_line());
        let delivered = Arc::new(AtomicUsize::new(0));
        let reader = CountingReader {
            remaining: MAX_INTERNAL_LINE_BYTES + 4 * 1024 * 1024,
            delivered,
        }
        .chain(tail.as_bytes());

        let (outcome, received) = drive_io_loop(reader).await;

        assert!(matches!(outcome, IoLoopOutcome::Disconnected));
        assert!(
            received.is_empty(),
            "an oversize line must end the connection, not be skipped: got {received:?}"
        );
    }

    #[tokio::test]
    async fn read_bounded_line_keeps_the_buffer_within_budget() {
        // Unit-level mirror of the pool-verifier test: 200 newline-free
        // bytes against a 64-byte budget.
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
    async fn read_bounded_line_accepts_an_exact_budget_line() {
        // An 8-byte line whose final byte is the newline fits an 8-byte
        // budget exactly; the next call reports EOF.
        let data: &[u8] = b"1234567\n";
        let mut reader = BufReader::new(data);
        let mut buf = String::new();
        assert_eq!(
            read_bounded_line(&mut reader, &mut buf, 8).await.unwrap(),
            BoundedLine::Line
        );
        assert_eq!(buf, "1234567\n");
        buf.clear();
        assert_eq!(
            read_bounded_line(&mut reader, &mut buf, 8).await.unwrap(),
            BoundedLine::Eof
        );
    }

    #[tokio::test]
    async fn read_bounded_line_charges_the_budget_against_a_dirty_buffer() {
        // The budget covers the whole line, not one call: a buffer that
        // already holds the budget's worth of a newline-free line is over
        // the limit before any further read.
        let data: &[u8] = b"more bytes\n";
        let mut reader = BufReader::new(data);
        let mut buf = "a".repeat(8);
        assert_eq!(
            read_bounded_line(&mut reader, &mut buf, 8).await.unwrap(),
            BoundedLine::OverLimit
        );
        assert_eq!(buf.len(), 8, "no further bytes may be appended");
    }

    // ── PB-23: what must NOT regress ──

    #[tokio::test]
    async fn mainnet_sized_raw_block_hex_lines_round_trip() {
        // Three consecutive 8 MiB-payload lines prove the budget resets per
        // line rather than accumulating across the connection, and that a
        // legitimate mainnet block never trips the bound. The trailing
        // heartbeat_ack is the witness: it only arrives if all three big
        // lines were consumed whole.
        let big = mainnet_propose_line();
        assert!(
            big.len() < MAX_INTERNAL_LINE_BYTES,
            "mainnet propose line is {} bytes, budget is {MAX_INTERNAL_LINE_BYTES}",
            big.len()
        );
        let mut stream = String::new();
        for _ in 0..3 {
            stream.push_str(&big);
        }
        stream.push_str(&heartbeat_ack_line());

        let (outcome, received) = drive_io_loop(stream.as_bytes()).await;

        assert!(matches!(outcome, IoLoopOutcome::Disconnected)); // EOF
        assert_eq!(received.len(), 1, "expected the trailing heartbeat_ack");
        assert!(matches!(received[0], VerifierInbound::HeartbeatAck));
    }

    #[tokio::test]
    async fn multi_megabyte_verdict_line_survives_intact() {
        // Content preservation, not just "did not error": a 9 MiB verdict
        // line must arrive with every byte of its detail.
        let detail = "d".repeat(9 * 1024 * 1024);
        let stream = verdict_line(77, &detail);

        let (_outcome, received) = drive_io_loop(stream.as_bytes()).await;

        assert_eq!(received.len(), 1);
        match &received[0] {
            VerifierInbound::TemplateVerdict(v) => {
                assert_eq!(v.id, 77);
                assert_eq!(v.reason_detail.as_deref().map(str::len), Some(detail.len()));
            }
            VerifierInbound::HeartbeatAck => panic!("expected TemplateVerdict"),
        }
    }

    #[tokio::test]
    async fn two_malformed_lines_do_not_disconnect() {
        // The three-strike policy for malformed-but-bounded lines is
        // untouched by PB-23.
        let stream = format!("not json\n{{\"nope\":1}}\n{}", heartbeat_ack_line());

        let (_outcome, received) = drive_io_loop(stream.as_bytes()).await;

        assert_eq!(received.len(), 1, "the ack after two strikes must arrive");
        assert!(matches!(received[0], VerifierInbound::HeartbeatAck));
    }

    #[tokio::test]
    async fn three_malformed_lines_disconnect_on_the_third() {
        let stream = format!("not json\nstill not\nnope\n{}", heartbeat_ack_line());

        let (outcome, received) = drive_io_loop(stream.as_bytes()).await;

        assert!(matches!(outcome, IoLoopOutcome::Disconnected));
        assert!(
            received.is_empty(),
            "the third strike must disconnect before the ack is read"
        );
    }

    #[test]
    fn serialize_heartbeat() {
        let msg = VerifierOutbound::Heartbeat;
        let line = serialize_outbound(&msg).unwrap();
        assert!(line.contains("heartbeat"));
        assert!(line.ends_with('\n'));
    }

    #[test]
    fn serialize_template_propose() {
        let tp = TemplatePropose {
            version: PROTOCOL_VERSION,
            id: 42,
            block_height: 800_000,
            prev_hash: "aa".repeat(32),
            coinbase_value: 625_000_000,
            tx_count: 100,
            total_fees: 50_000_000,
            observed_weight: Some(3_900_000),
            created_at_unix_ms: Some(1_700_000_000_000),
            total_sigops: Some(10000),
            coinbase_sigops: Some(4),
            template_weight: Some(3_950_000),
            gateway_instance_id: Some("test-gw-01".to_string()),
            raw_block_hex: None,
        };
        let msg = VerifierOutbound::TemplatePropose(tp);
        let line = serialize_outbound(&msg).unwrap();
        assert!(line.contains("template_propose"));
        assert!(line.contains("800000"));
    }

    #[test]
    fn dispatch_verdict_parses_correctly() {
        let verdict = TemplateVerdict {
            version: PROTOCOL_VERSION,
            id: 42,
            accepted: true,
            reason_code: None,
            reason_detail: None,
            policy_context: None,
        };
        let msg = InternalMessage {
            msg_type: msg_types::TEMPLATE_VERDICT.to_string(),
            version: PROTOCOL_VERSION,
            payload: serde_json::to_value(&verdict).unwrap(),
        };

        let (tx, mut rx) = broadcast::channel(16);
        let readiness = ReadinessState::new();

        dispatch_inbound(&msg, &tx, &readiness);

        let received = rx.try_recv().unwrap();
        match received {
            VerifierInbound::TemplateVerdict(v) => {
                assert_eq!(v.id, 42);
                assert!(v.accepted);
            }
            VerifierInbound::HeartbeatAck => panic!("expected TemplateVerdict"),
        }
    }

    #[test]
    fn dispatch_heartbeat_ack_sets_policy_loaded() {
        let msg = InternalMessage {
            msg_type: msg_types::HEARTBEAT_ACK.to_string(),
            version: PROTOCOL_VERSION,
            payload: serde_json::json!({}),
        };

        let (tx, _rx) = broadcast::channel(16);
        let readiness = ReadinessState::new();
        assert!(
            !readiness
                .policy_loaded
                .load(std::sync::atomic::Ordering::SeqCst)
        );

        dispatch_inbound(&msg, &tx, &readiness);

        assert!(
            readiness
                .policy_loaded
                .load(std::sync::atomic::Ordering::SeqCst)
        );
    }
}
