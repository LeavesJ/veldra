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
use pool_verifier::second_chance::{self, SecondChance, SecondChanceError, SecondChanceOutcome};
use rg_protocol::gateway::{InternalMessage, MAX_INTERNAL_LINE_BYTES, msg_types};
use rg_protocol::{
    PROTOCOL_VERSION, PolicyContext, TemplatePropose, TemplateVerdict, VerdictReason,
};
use std::sync::atomic::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time::{Duration, timeout};

/// PB-40: put a Class M rejection to bitcoind before it stands.
///
/// Returns `None` when there is nothing to adjudicate: the template
/// was not rejected by Class M, or `[policy.mempool] enforce` is off
/// so there is no bitcoind to ask. Every other path returns a
/// [`SecondChanceOutcome`] that is both counted and durably recorded.
///
/// A failed lookup yields [`SecondChanceOutcome::LookupFailed`] and
/// the rejection stands. It deliberately does NOT fall through to
/// acceptance: a lookup that could not run is not evidence that the
/// transactions are present, and treating silence as a clean answer is
/// the exact mistake that made 68 rejections unadjudicable.
async fn run_second_chance(
    lookup: Option<&SecondChance>,
    phase2: &Phase2Attribution,
    template_height: u32,
    tolerance_pct: f64,
) -> Option<SecondChanceOutcome> {
    let (Phase2Attribution::Rejected { unknown, total }, Some(lookup)) = (phase2, lookup) else {
        return None;
    };
    let total = *total;
    let unknown_before = u32::try_from(unknown.len()).unwrap_or(u32::MAX);

    match lookup.ask(template_height, unknown).await {
        Ok(answer) => {
            let adjudication = second_chance::adjudicate(total, unknown, &answer);
            if !adjudication.still_exceeds(tolerance_pct) {
                // WITHDRAWN is safe under partial coverage. The walk can
                // only ever ADD transactions to the known set, so a
                // fuller answer could not have pushed the recomputed
                // count back over tolerance. Nothing is asserted here
                // that a complete walk would contradict.
                return Some(SecondChanceOutcome::Withdrawn(adjudication));
            }
            // An unadjudicated probe blocks an `upheld` for the same
            // reason an incomplete block walk does. `upheld` asserts
            // bitcoind held these transactions in neither its mempool
            // nor a recent block, and a transaction nobody could ask
            // about has established neither half of that. The rejection
            // still stands; only the evidence label changes.
            if adjudication.unadjudicated > 0 {
                warn!(
                    height = template_height,
                    unknown_before,
                    total,
                    still_absent = adjudication.still_absent,
                    unadjudicated = adjudication.unadjudicated,
                    "PB-40 second chance could not establish absence for every unknown; the \
                     Class M rejection stands UNADJUDICATED rather than as a confirmed detection"
                );
                let reason = SecondChanceError::MempoolProbeIncomplete(format!(
                    "{} of {unknown_before} unknown transactions had no usable probe answer",
                    adjudication.unadjudicated
                ));
                return Some(SecondChanceOutcome::LookupFailed {
                    total,
                    unknown_before,
                    // The real count, so a reviewer or a dashboard can
                    // key off it directly instead of parsing it back out
                    // of the free-text `reason` sentence above.
                    unadjudicated: adjudication.unadjudicated,
                    kind: reason.as_label().to_string(),
                    reason: reason.to_string(),
                });
            }
            // UPHELD is not safe under partial coverage. It asserts
            // bitcoind held the transactions in neither its mempool nor
            // any recent block, and the runbook reads it as a genuine
            // detection candidate. A walk that errored or truncated
            // never established the second half of that claim, so
            // absence from it is not evidence and the verdict is
            // reported unadjudicated instead. It still upholds the
            // rejection; only the evidence label changes, which is the
            // whole point.
            if let Some(shortfall) = answer.block_walk_shortfall.as_ref() {
                warn!(
                    height = template_height,
                    unknown_before,
                    total,
                    still_absent = adjudication.still_absent,
                    blocks_scanned = adjudication.blocks_scanned,
                    tip_height = adjudication.tip_height,
                    shortfall = %shortfall,
                    "PB-40 second chance could not rule out the mined case; the Class M rejection \
                     stands UNADJUDICATED rather than as a confirmed detection"
                );
                let reason = SecondChanceError::BlockWalkIncomplete(shortfall.clone());
                return Some(SecondChanceOutcome::LookupFailed {
                    total,
                    unknown_before,
                    // Verified zero: the `adjudication.unadjudicated > 0`
                    // branch above already returned if any probe came
                    // back unusable, so by construction nothing is
                    // unadjudicated on this path.
                    unadjudicated: adjudication.unadjudicated,
                    reason: reason.to_string(),
                    kind: reason.as_label().to_string(),
                });
            }
            Some(SecondChanceOutcome::Upheld(adjudication))
        }
        Err(e) => {
            warn!(
                error = %e,
                kind = e.as_label(),
                height = template_height,
                unknown_before,
                total,
                "PB-40 second chance could not reach bitcoind; the Class M rejection stands \
                 UNADJUDICATED and must not be read as a confirmed detection"
            );
            Some(SecondChanceOutcome::LookupFailed {
                total,
                unknown_before,
                // Genuinely unknown: no adjudication ran at all, so
                // there is no probed count to carry.
                unadjudicated: 0,
                reason: e.to_string(),
                kind: e.as_label().to_string(),
            })
        }
    }
}

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

    // The process-level rustls `CryptoProvider` that
    // `ServerConfig::builder()` below needs is installed by
    // `main::install_crypto_provider`, which runs before this function
    // is called. PB-28 installed it here instead, which put it behind
    // the `return Ok(None)` above: with the ingress TLS env vars unset,
    // which is the shipped default, the install never ran and the HTTPS
    // server took the very panic it was added to fix (PB-30).

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

/// Default ceiling on concurrent NDJSON ingress connections (PB-26),
/// used when `VELDRA_VERIFIER_MAX_CONNECTIONS` is unset.
///
/// Sized for a production mainnet pool, not for a load generator. The
/// ingress population is services, not miners, and the two services
/// use it differently. sv2-gateway holds one persistent stream and
/// reconnects it (`verifier_stream.rs`). template-manager does **not**:
/// it opens a fresh `TcpStream` per template and drops it once the
/// verdict comes back (`template-manager/src/main.rs:1697`, consumed
/// by `send_and_receive` at `:1816`), so at `poll_secs = 5` it wants a
/// free slot every few seconds and holds one for under its own 4 s
/// verdict timeout (`template-manager/src/main.rs:1679`). A pool
/// running a handful of each for HA sits in the single digits at any
/// instant, so 32 is several times the real steady-state peak and still
/// absorbs reconnect churn plus an operator's diagnostic connection.
///
/// The per-template reconnect is why PB-27 matters as much as PB-26:
/// squatting the cap does not merely degrade throughput, it starves
/// the manager of the slot it needs on the next poll and verdicts stop
/// entirely.
///
/// The number is also a memory bound. Every live connection can hold
/// a line buffer up to `MAX_INTERNAL_LINE_BYTES` (20 MiB since
/// PB-19), so the cap pins worst-case ingress buffer residency near
/// 640 MiB instead of leaving it unbounded. Deployments that drive
/// the ingress harder than production, such as the 100-connection
/// burst in `scripts/benchmark-release.sh`, raise it explicitly in
/// their compose file rather than lowering the shipped default.
pub(crate) const DEFAULT_MAX_INGRESS_CONNECTIONS: u32 = 32;

/// Default per-source-address ceiling (PB-27), used when
/// `VELDRA_VERIFIER_MAX_CONNECTIONS_PER_IP` is unset. `0` disables
/// per-IP enforcement.
///
/// The PB-26 cap is global, so one address could take every slot: the
/// reported probe locked out a legitimate peer with eight sockets from
/// one source. This bounds that. The size comes from the largest
/// legitimate single-address population, which is a NAT or L4 proxy
/// collapsing a deployment's whole egress onto one address:
///
/// ```text
/// per_ip >= 2G + M + 1
/// ```
///
/// `G` is gateway streams, and each costs two slots rather than one for
/// as long as a death takes to clear. A silently dead socket holds its
/// slot for the full idle budget: measured at 60.08 s against the 60 s
/// default below, and confirmed parametrically, with a 5 s budget
/// holding 5.10 s and a 15 s budget holding 15.05 s. A gateway
/// reconnects in 2 to 3 s, so for the ~58 s in between one egress
/// address carries two slots per gateway. TCP keepalive cannot shorten
/// that window. The ladder set below is 30 s idle and 10 s between
/// probes, and it leaves the probe count at the OS default, which is 8
/// on macOS and 9 on Linux, so the kill lands at 110 s and 120 s
/// respectively. Both are past the budget, so keepalive can never be
/// what reclaims the slot first at shipped defaults.
///
/// `M` is 1. A concurrent template-manager costs exactly one slot even
/// though it opens a fresh connection per template: measured peak
/// `verifier_connections_active` of 1 across twenty back-to-back
/// cycles. The trailing `+ 1` is an operator's diagnostic connection.
///
/// `G` is 8, the top of the single-digit gateway and template-manager
/// population `docker-compose.yml` documents as supported. That gives
/// 18, rounded to 20. PB-31 raised it from 8, which had been derived
/// from an HA pair at `G = 2` and so contradicted that documented
/// ceiling: at `G = 2` the number was right, but the supported topology
/// is single digits, and 8 broke at 7 gateways on one silent death, 6
/// with concurrent manager traffic, and 4 if they died together.
/// Refusing a real gateway is not a safe failure. It drives the
/// gateway's `auto_degrade` (default true), which suspends enforcement.
///
/// The cost of the raise is that 20 out of the 32-slot global cap lets
/// two addresses saturate the ingress where 8 needed four. That is
/// accepted because the per-IP ceiling was never what stops a squatter:
/// an attacker never needed a dead socket, only a quiet one, and the
/// idle budget below is what bounds those. Compose stacks also put
/// every service on its own container address, so in-cluster peers stay
/// one per IP and only host-published traffic collapses onto the bridge
/// address.
///
/// `0` stays supported, matching `sv2-gateway`, `rg-feed-server` and
/// `rg-demo-feed`, because a deployment whose every legitimate peer
/// arrives through a single L4 proxy address has no per-IP signal at
/// all and guessing a large number there is worse than an explicit off
/// switch. `docker-compose.yml` raises it to 256 instead, because
/// `scripts/benchmark-release.sh` scenario 6 opens 100 connections
/// from one host.
pub(crate) const DEFAULT_MAX_INGRESS_CONNECTIONS_PER_IP: u32 = 20;

/// Default no-progress budget for one ingress connection (PB-27), used
/// when `VELDRA_VERIFIER_IDLE_TIMEOUT_SECS` is unset.
///
/// Measured since the last byte that actually moved, never from the
/// connection's start; see `idle_stream`. 60 s is twelve times
/// sv2-gateway's default `heartbeat_interval_ms` of 5 000
/// (`sv2-gateway/src/config.rs:440`), so a scheduler stall, a policy
/// reload or a slow verdict can never look like silence, and
/// template-manager's per-template connections close long before it.
/// Against a squatter it bounds a stolen slot to one minute instead of
/// the process lifetime, which with the per-IP ceiling above is what
/// turns "32 sockets and the pool is down" back into a cost the
/// attacker has to keep paying.
pub(crate) const DEFAULT_INGRESS_IDLE_TIMEOUT_SECS: u64 = 60;

/// Total budget for the TLS handshake, from accept to negotiated
/// session.
///
/// PB-26 takes the ingress permit before the handshake on purpose, so a
/// peer that opens TCP and never sends a `ClientHello` holds a slot
/// without ever becoming a protocol peer. The idle budget already ends
/// that peer, but idle semantics let a hostile peer dribble one byte
/// per budget forever, and unlike a 20 MiB `raw_block_hex` line a TLS
/// handshake has no legitimate slow case: it is one or two round trips.
/// So this one is total elapsed time, not idleness.
///
/// Not configurable on purpose. Ten seconds is over an order of
/// magnitude more than any real handshake needs on any link a pool
/// operates over, and there is no deployment shape that wants it
/// larger or smaller, so it is a constant rather than a knob nobody
/// turns.
const TLS_HANDSHAKE_BUDGET: Duration = Duration::from_secs(10);

/// TCP keepalive idle period and probe interval for accepted ingress
/// sockets.
///
/// The no-progress deadline is a userspace budget, so it is the thing
/// that actually reclaims a squatted slot. Keepalive is the transport
/// backstop underneath it: it is what still reclaims a socket whose
/// peer host vanished without FIN when an operator has raised
/// `VELDRA_VERIFIER_IDLE_TIMEOUT_SECS` for a link with legitimately
/// long silences, and it makes the kernel surface `ETIMEDOUT` on a
/// parked write so the log names a dead path rather than an idle peer.
/// Before PB-27 nothing in `services/` set it at all, which is why a
/// vanished gateway host burned a slot permanently and ingress capacity
/// was monotonically non-increasing over process life.
///
/// 30 s before the first probe and 10 s between probes puts detection
/// inside a couple of minutes on both Linux and macOS defaults, well
/// under any plausible idle budget an operator would raise this above.
const TCP_KEEPALIVE_IDLE: Duration = Duration::from_secs(30);
const TCP_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);

/// System error boundary: reason codes not produced by policy evaluation.
///
/// `VerdictReason::PolicyLoadError`: emitted when policy lock is poisoned
///                                    or policy state is unavailable.
/// `VerdictReason::MempoolBackendUnavailable`: reserved for future fail-closed
///                                    mode. Currently, missing mempool triggers
///                                    degraded-mode tier selection.
/// `VerdictReason::InternalError`: emitted on unexpected handler failures
///                                    (e.g., serialize errors).
// Ten parameters is over the clippy threshold. Splitting them into a
// struct would only rename the same values at the one call site in
// main.rs, so the seam is not earned.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_tcp_server(
    app_state: AppState,
    addr: String,
    verdict_log: VerdictLog,
    mempool_url: Option<String>,
    log_id_counter: LogIdCounter,
    tls_acceptor: Option<TlsAcceptor>,
    metrics: Arc<crate::metrics::VerifierMetrics>,
    max_connections: u32,
    max_connections_per_ip: u32,
    idle_timeout_secs: u64,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(&addr).await?;
    let tls_mode = if tls_acceptor.is_some() {
        "tls"
    } else {
        "plaintext"
    };
    let idle_timeout = Duration::from_secs(idle_timeout_secs);
    info!(
        addr = %addr,
        tls = tls_mode,
        max_connections,
        max_connections_per_ip,
        idle_timeout_secs,
        "TCP listening"
    );
    if tls_acceptor.is_none() && !addr.starts_with("127.0.0.1") && !addr.starts_with("[::1]") {
        tracing::warn!(
            addr = %addr,
            "TCP verifier is running without TLS on a non-loopback address. \
             Templates and verdicts will be sent in plaintext. Set \
             VELDRA_VERIFIER_TLS_CERT and VELDRA_VERIFIER_TLS_KEY for production."
        );
    }

    // PB-26. Cap how many ingress connections are live at once.
    //
    // The listener takes unauthenticated peers (the TLS acceptor above
    // is built `.with_no_client_auth()`, and shadow/observe compose
    // bind it on 0.0.0.0:9090), and each admitted connection can hold
    // a line buffer up to `MAX_INTERNAL_LINE_BYTES`. PB-18's bounded
    // read caps one connection; nothing capped their number, so the
    // per-connection bound multiplied by an unbounded count is still
    // unbounded. Killing the verifier this way does not fail closed:
    // the gateway's `auto_degrade` (default true) sees the dead
    // verifier, suspends enforcement, and keeps shipping templates, so
    // this cap is protecting the Invariant Shield, not just the
    // process.
    //
    // Refuse rather than accept-then-wait. A peer parked on a permit
    // queue still owns an accepted socket and a slot in this process,
    // so a queue is the same exhaustion arriving more slowly, and a
    // legitimate gateway would rather get an immediate close and
    // retry through its existing reconnect loop than hang.
    //
    // A bare `Semaphore` rather than a wrapper type: this is one
    // `try_acquire_owned` call, the same shape `sv2-bridge`'s accept
    // loop already uses, and a struct around it would have exactly
    // one caller.
    let conn_permits = Arc::new(tokio::sync::Semaphore::new(
        usize::try_from(max_connections).unwrap_or(usize::MAX),
    ));

    // PB-27. The cap above is global, so one source address could hold
    // every slot; the reported probe did exactly that. The tracker is
    // `reservegrid-common`'s, shared with `sv2-gateway`'s miner
    // listener rather than copied here: it is the only one of the three
    // per-IP shapes already in the tree whose map is bounded and whose
    // decrement is an RAII `Drop`. It lives in `reservegrid-common`
    // and not in `sv2-gateway` because the verifier must not depend on
    // the service it verifies.
    let per_ip = reservegrid_common::per_ip::PerIpConnectionTracker::new(max_connections_per_ip);

    loop {
        let (tcp_stream, peer) = listener.accept().await?;

        let Ok(permit) = Arc::clone(&conn_permits).try_acquire_owned() else {
            metrics.connections_refused_total.inc();
            warn!(
                peer = %peer,
                max_connections,
                "ingress connection refused: concurrent connection cap reached"
            );
            drop(tcp_stream);
            continue;
        };

        let Some(ip_permit) = per_ip.try_accept(peer.ip()) else {
            metrics.connections_refused_per_ip_total.inc();
            warn!(
                peer = %peer,
                max_connections_per_ip,
                "ingress connection refused: per-IP connection limit reached"
            );
            drop(tcp_stream);
            continue;
        };

        // PB-27. Failure is logged rather than fatal: the no-progress
        // deadline below is the primary reclaim path and still applies,
        // and refusing an otherwise healthy connection because a socket
        // option did not take would be a worse outcome than running
        // without the transport backstop.
        if let Err(e) = enable_tcp_keepalive(&tcp_stream) {
            warn!(peer = %peer, error = %e, "failed to enable TCP keepalive on ingress socket");
        }

        metrics.connections_active.inc();

        tokio::spawn(serve_admitted_connection(
            AdmittedSlot {
                _permit: permit,
                _ip_permit: ip_permit,
                metrics: Arc::clone(&metrics),
            },
            tcp_stream,
            peer,
            tls_acceptor.clone(),
            IdleBudget {
                idle_timeout,
                idle_timeout_secs,
            },
            ConnectionDeps {
                app_state: app_state.clone(),
                verdict_log: verdict_log.clone(),
                mempool_url: mempool_url.clone(),
                log_id_counter: log_id_counter.clone(),
                metrics: Arc::clone(&metrics),
            },
        ));
    }
}

/// Turn on TCP keepalive for one accepted ingress socket (PB-27).
///
/// `tokio::net::TcpStream` exposes `set_nodelay` and `set_linger` but no
/// keepalive setter, so this goes through `socket2`, which tokio already
/// depends on. Separate from the accept loop so a test can read the
/// option back off a real socket rather than trusting the constants.
fn enable_tcp_keepalive(stream: &tokio::net::TcpStream) -> std::io::Result<()> {
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(TCP_KEEPALIVE_IDLE)
        .with_interval(TCP_KEEPALIVE_INTERVAL);
    socket2::SockRef::from(stream).set_tcp_keepalive(&keepalive)
}

/// The five service-wide handles one connection needs to evaluate a
/// template and record its verdict.
///
/// This exists because both branches of `serve_admitted_connection`, the
/// TLS one and the plaintext one, hand the same five values to
/// `handle_tcp_connection`, and the accept loop clones them once per
/// connection. Without it the accept loop carries five `let x = y.clone()`
/// lines and the task body threads five more parameters.
struct ConnectionDeps {
    app_state: AppState,
    verdict_log: VerdictLog,
    mempool_url: Option<String>,
    log_id_counter: LogIdCounter,
    metrics: Arc<crate::metrics::VerifierMetrics>,
}

/// The no-progress budget, and the same number in seconds for the log
/// line that reports a reap. Two representations of one setting rather
/// than a `Duration::as_secs()` call inside a warn field.
struct IdleBudget {
    idle_timeout: Duration,
    idle_timeout_secs: u64,
}

/// Serve one admitted ingress connection, from permit to close (PB-26,
/// PB-27).
async fn serve_admitted_connection(
    slot: AdmittedSlot,
    tcp_stream: tokio::net::TcpStream,
    peer: std::net::SocketAddr,
    acceptor: Option<TlsAcceptor>,
    budget: IdleBudget,
    deps: ConnectionDeps,
) {
    // The slot is held for the connection's whole lifetime, including
    // the TLS handshake (PB-26's ordering, preserved). Releasing the
    // permit, the per-IP count and the gauge together in one `Drop` is
    // what keeps the gauge honest on the early returns inside
    // `handle_tcp_connection` and on a panic in this task.
    let _slot = slot;

    let ConnectionDeps {
        app_state,
        verdict_log,
        mempool_url,
        log_id_counter,
        metrics,
    } = deps;

    // PB-27. Wrapped before the TLS acceptor, so a peer that opens TCP
    // and never sends a `ClientHello` is on the clock too.
    let reaped = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stream =
        crate::idle_stream::IdleTimeout::new(tcp_stream, budget.idle_timeout, Arc::clone(&reaped));

    // Upgrade to TLS if configured, then split into reader/writer.
    if let Some(acceptor) = acceptor {
        match timeout(TLS_HANDSHAKE_BUDGET, acceptor.accept(stream)).await {
            Ok(Ok(tls_stream)) => {
                let (reader, writer) = tokio::io::split(tls_stream);
                handle_tcp_connection(
                    reader,
                    writer,
                    app_state,
                    verdict_log,
                    mempool_url,
                    log_id_counter,
                    Arc::clone(&metrics),
                )
                .await;
            }
            Ok(Err(e)) => {
                warn!(peer = %peer, error = %e, "TLS accept failed");
            }
            Err(_elapsed) => {
                // PB-30 / I3. Counted apart from the idle reap on
                // purpose: `TLS_HANDSHAKE_BUDGET` is a constant, so an
                // operator who saw this on the idle counter would raise
                // `VELDRA_VERIFIER_IDLE_TIMEOUT_SECS` and change
                // nothing.
                metrics.connections_reaped_handshake_total.inc();
                warn!(
                    peer = %peer,
                    budget_secs = TLS_HANDSHAKE_BUDGET.as_secs(),
                    "ingress connection dropped: TLS handshake did not complete in time"
                );
                return;
            }
        }
    } else {
        let (reader, writer) = tokio::io::split(stream);
        handle_tcp_connection(
            reader,
            writer,
            app_state,
            verdict_log,
            mempool_url,
            log_id_counter,
            Arc::clone(&metrics),
        )
        .await;
    }

    if reaped.load(Ordering::Relaxed) {
        metrics.connections_reaped_idle_total.inc();
        warn!(
            peer = %peer,
            idle_timeout_secs = budget.idle_timeout_secs,
            "ingress connection reaped: no progress within the idle budget"
        );
    }
}

/// The three things one admitted ingress connection holds.
///
/// Exists because they must be released together on every exit path,
/// including the early `return`s inside `handle_tcp_connection` and a
/// panic in the connection task. Dropping them at the end of the task
/// body instead would leave the gauge reading high after either, which
/// is precisely the "slots are leaking" reading the gauge was added to
/// make legible.
struct AdmittedSlot {
    _permit: tokio::sync::OwnedSemaphorePermit,
    _ip_permit: reservegrid_common::per_ip::PerIpPermit,
    metrics: Arc<crate::metrics::VerifierMetrics>,
}

impl Drop for AdmittedSlot {
    fn drop(&mut self) {
        self.metrics.connections_active.dec();
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
                    // Class M never ran on this path, so there is
                    // nothing bitcoind could have been asked about.
                    mempool_adjudication: None,
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
                // Refused empty polls are view health rather than
                // per-template attribution, so they ride the same
                // mirror as the age and size gauges below.
                metrics
                    .mempool_empty_responses
                    .set(i64::try_from(view.empty_responses()).unwrap_or(i64::MAX));
                Some(view.snapshot().await)
            } else {
                None
            };
            let mut eval = if let Some(snap) = mempool_snap.as_ref() {
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

            // ── PB-40: second-chance lookup at Class M rejection time ──
            // The check above compared this template against a view up
            // to `poll_interval_secs` old, while `getblocktemplate`
            // preferentially selects transactions that arrived inside
            // exactly that window. Before a Class M rejection is
            // allowed to stand, ask bitcoind whether it holds the
            // transactions the polled view did not, and record what it
            // said: that answer is unrecoverable afterwards, because
            // the same transactions are RBF-replaced or evicted within
            // minutes and a later re-query would report them absent.
            let second_chance = run_second_chance(
                state_clone.second_chance.as_deref(),
                &eval.phase2,
                propose.block_height,
                cfg.mempool.tolerance_pct,
            )
            .await;
            if let Some(SecondChanceOutcome::Withdrawn(adj)) = second_chance.as_ref() {
                info!(
                    template_id = propose.id,
                    height = propose.block_height,
                    reason_code = VerdictReason::V2InvariantMempoolToleranceExceeded.as_str(),
                    total = adj.total,
                    unknown_before = adj.unknown_before,
                    in_mempool = adj.in_mempool,
                    mined = adj.mined,
                    still_absent = adj.still_absent,
                    blocks_scanned = adj.blocks_scanned,
                    tolerance_pct = cfg.mempool.tolerance_pct,
                    "PB-40 second chance withdrew a Class M rejection: bitcoind holds \
                     transactions the polled mempool view did not"
                );
                // The rejection is withdrawn on the recomputed count.
                // Detail is cleared with it so an accepted verdict can
                // never carry a rejection string; the adjudication
                // survives on the durable verdict record below.
                eval.reason = None;
                eval.detail = None;
            }

            let accepted = eval.reason.is_none();

            // reason_code string comes from rg-protocol, the single source of truth.
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
                let result_label = match (&eval.phase2, second_chance.as_ref()) {
                    (Phase2Attribution::NotRun, _) => None,
                    (Phase2Attribution::Agreed, _) => Some("agreed"),
                    (Phase2Attribution::Stale, _) => Some("stale"),
                    (Phase2Attribution::SkippedDegraded, _) => {
                        metrics.phase2_degraded_total.inc();
                        Some("skipped")
                    }
                    (Phase2Attribution::SkippedUnprimed, _) => Some("unprimed"),
                    // PB-40: a first-pass rejection that bitcoind
                    // overturned is neither "agreed" nor "rejected".
                    // Folding it into "agreed" would hide the defect
                    // this mechanism exists to measure, and leaving it
                    // in "rejected" would report a rejection that did
                    // not happen.
                    (
                        Phase2Attribution::Rejected { .. },
                        Some(SecondChanceOutcome::Withdrawn(_)),
                    ) => Some("recovered"),
                    (Phase2Attribution::Rejected { .. }, _) => Some("rejected"),
                };
                if let Some(outcome) = second_chance.as_ref() {
                    metrics
                        .phase2_second_chance_total
                        .get_or_create(&crate::metrics::SecondChanceLabels {
                            outcome: outcome.as_label().to_string(),
                        })
                        .inc();
                }
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
                mempool_adjudication: second_chance.as_ref().map(Into::into),
            };

            // PB-40: rejections were not logged at all. The Setup B
            // container emitted 8 lines in 7.5 hours, all startup,
            // while 68 templates were rejected, and `/verdicts` is a
            // capped 1000-entry ring that held only 23 of them. A
            // rejection that leaves no trace outside a ring buffer is
            // not evidence. Doctrine also requires every rejection to
            // be traceable through structured tracing carrying
            // `reason_code` plus policy context.
            if !accepted {
                warn!(
                    template_id = propose.id,
                    height = propose.block_height,
                    log_id,
                    reason_code = logged.reason_code.as_deref().unwrap_or("unknown"),
                    reason_detail = logged.reason_detail.as_deref().unwrap_or(""),
                    fee_tier = %eval.fee_tier.as_str(),
                    min_avg_fee_used = eval.min_avg_fee_used,
                    tx_count = propose.tx_count,
                    second_chance = logged
                        .mempool_adjudication
                        .as_ref()
                        .map_or("not_applicable", |a| a.outcome.as_str()),
                    "template rejected"
                );
            }

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
    use super::{
        BoundedLine, LOG_SAMPLE_BYTES, TCP_KEEPALIVE_IDLE, enable_tcp_keepalive, log_display,
        log_sample, read_bounded_line,
    };
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
            second_chance: None,
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

    /// PB-27. Before this, nothing in `services/` set `SO_KEEPALIVE`, so
    /// a gateway host that vanished without FIN held its ingress slot
    /// until the verifier restarted, and capacity was monotonically
    /// non-increasing over process life.
    ///
    /// The observable is the kernel's own state on a real accepted
    /// socket, read back through a separate `SockRef`, not a flag this
    /// code set for itself.
    #[tokio::test]
    async fn accepted_sockets_get_tcp_keepalive() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (accepted, _peer) = listener.accept().await.unwrap();

        let before = socket2::SockRef::from(&accepted).keepalive().unwrap();
        assert!(
            !before,
            "the OS default must be off, or this proves nothing"
        );

        enable_tcp_keepalive(&accepted).expect("enable keepalive");

        let sock = socket2::SockRef::from(&accepted);
        assert!(sock.keepalive().unwrap(), "SO_KEEPALIVE must be on");
        assert_eq!(
            sock.tcp_keepalive_time().unwrap(),
            TCP_KEEPALIVE_IDLE,
            "the idle period before the first probe must be the configured one"
        );
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
