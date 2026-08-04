use axum::{Extension, http::StatusCode, response::IntoResponse};
use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;
use std::sync::Arc;
use std::sync::atomic::AtomicI64;

/// Label set for verdict outcome counters.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub(crate) struct VerdictLabels {
    pub(crate) accepted: String,
    pub(crate) reason_code: String,
}

/// Label set for policy reload counters.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub(crate) struct PolicyReloadLabels {
    pub(crate) result: String,
}

/// Label set for v2.0 Invariant Shield Phase 2 Class M check
/// outcome counters. `result` ∈ {agreed, rejected, recovered, skipped,
/// stale, unprimed} (PB-13 added `unprimed`; PB-18 keys every label off
/// the evaluation path's `Phase2Attribution`, so templates where Class
/// M never ran increment nothing; PB-40 added `recovered` for a
/// first-pass rejection that the second-chance lookup withdrew, which
/// is neither an agreement nor a rejection).
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub(crate) struct Phase2CheckLabels {
    pub(crate) result: String,
}

/// Label set for the PB-40 second-chance lookup. `outcome` ∈
/// {`withdrawn`, `upheld`, `lookup_failed`}.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub(crate) struct SecondChanceLabels {
    pub(crate) outcome: String,
}

/// Prometheus metric families for the pool-verifier.
#[allow(clippy::struct_field_names)] // `_total` suffix is Prometheus naming convention
pub(crate) struct VerifierMetrics {
    pub(crate) verdicts_total: Family<VerdictLabels, Counter>,
    pub(crate) templates_evaluated_total: Counter,
    pub(crate) policy_reloads_total: Family<PolicyReloadLabels, Counter>,
    /// Count of templates where the v2.0 Invariant Shield pass was
    /// reached but the sender omitted `raw_block_hex`. Separate from
    /// `verdicts_total` because the shield skip is not a verdict
    /// outcome; dashboards use this to measure Phase 1 rollout
    /// coverage of gateways that ship raw block bytes.
    pub(crate) shield_skipped_total: Counter,

    /// v2.0 Invariant Shield Phase 2 (ADR-003) metrics.
    ///
    /// Count of templates where the Class M (mempool ground truth)
    /// check was skipped because the verifier's mempool view was in
    /// `Degraded` state. Increments per template that reaches the
    /// shield while bitcoind RPC is unreachable beyond the
    /// `mempool_max_stale_secs` window.
    pub(crate) phase2_degraded_total: Counter,

    /// Per-outcome counter for the Class M check. Allows dashboards
    /// to track agreed/rejected/skipped/stale rates over time
    /// without scraping verdict event logs.
    pub(crate) phase2_checks_total: Family<Phase2CheckLabels, Counter>,

    /// PB-40: what the second-chance lookup did to each Class M
    /// rejection. This is the soak's primary instrument. `withdrawn`
    /// counts false positives caught in the act; `upheld` counts the
    /// only rejections that can support a detection claim;
    /// `lookup_failed` counts rejections that stand UNADJUDICATED and
    /// must not be tallied as either.
    pub(crate) phase2_second_chance_total: Family<SecondChanceLabels, Counter>,

    /// Age of the verifier's most recently served mempool view in
    /// seconds. Tracks the D3 fail-stale state machine: above
    /// `mempool_max_stale_secs` the view is `Stale`, above 2x that
    /// threshold the view is `Degraded`.
    pub(crate) mempool_view_age_seconds: Gauge<i64, AtomicI64>,

    /// Number of distinct txids in the verifier's current mempool
    /// view. Healthy mainnet typically sits in the 30k-80k range;
    /// regtest and shadow-mode synthetic feeds report near zero.
    pub(crate) mempool_view_size: Gauge<i64, AtomicI64>,

    /// Successful `getrawmempool` responses that came back empty and
    /// were therefore refused as a view (`MIN_INSTALLABLE_MEMPOOL_SIZE`
    /// in `mempool_view.rs`), counted since process start.
    ///
    /// The `Unprimed` and `Degraded` states that follow a run of these
    /// are the symptom; this is the cause, and it separates "bitcoind
    /// is unreachable" from "bitcoind answers, with nothing in it",
    /// which need different operator responses. Nonzero on a mainnet
    /// node means the RPC endpoint is not the node it is supposed to
    /// be, or has not finished loading `mempool.dat`.
    ///
    /// Monotone but exported as a gauge, not a counter, because the
    /// value is mirrored from an atomic owned by the library crate's
    /// polling task at the same ingress call site that already mirrors
    /// `mempool_view_age_seconds` and `mempool_view_size`. `increase()`
    /// and `> 0` alert on it exactly as they would on a counter. Not a
    /// counter, so no `_total` suffix.
    pub(crate) mempool_empty_responses: Gauge<i64, AtomicI64>,

    /// PB-26. Inbound NDJSON ingress connections refused because the
    /// concurrent connection cap (`VELDRA_VERIFIER_MAX_CONNECTIONS`)
    /// was already saturated. A healthy pool never ticks this: the
    /// legitimate population is one persistent stream per gateway, plus
    /// one short-lived connection per template from each
    /// template-manager (`template-manager/src/main.rs:1697` opens a
    /// fresh `TcpStream` per template and drops it after the verdict).
    /// A nonzero rate means either the cap is set below the
    /// deployment's real service count, or an unauthenticated peer is
    /// holding slots, and both need an operator.
    pub(crate) connections_refused_total: Counter,

    /// PB-27. Ingress connections refused because the peer's source
    /// address already held `VELDRA_VERIFIER_MAX_CONNECTIONS_PER_IP`
    /// slots. Separate from `connections_refused_total` because the two
    /// call for opposite responses: the global counter means "the cap
    /// may be too low", this one means "one address is taking more than
    /// its share" and raising the global cap would not help.
    pub(crate) connections_refused_per_ip_total: Counter,

    /// PB-27. Ingress connections ended by the no-progress deadline
    /// (`VELDRA_VERIFIER_IDLE_TIMEOUT_SECS`) rather than by the peer
    /// closing. A steady rate with no attacker present means the budget
    /// is below the legitimate peer's heartbeat interval; a burst means
    /// sockets are being parked deliberately.
    ///
    /// PB-30: the TLS handshake kill is **not** counted here. See
    /// `connections_reaped_handshake_total`.
    pub(crate) connections_reaped_idle_total: Counter,

    /// PB-30. Ingress connections ended by `TLS_HANDSHAKE_BUDGET`
    /// (`ingress.rs`), the total elapsed time a peer gets to complete
    /// the TLS handshake after being admitted.
    ///
    /// Separate from `connections_reaped_idle_total` because the two
    /// point at different controls, and one of them is not a control at
    /// all: the handshake budget is a hardcoded constant, so raising
    /// `VELDRA_VERIFIER_IDLE_TIMEOUT_SECS`, which is what the idle
    /// counter's own documentation tells an operator to do, cannot move
    /// this number. A tick here means a peer took a slot and never
    /// started TLS, which is either a scanner or a client pointed at
    /// the wrong port, never a budget that needs widening.
    pub(crate) connections_reaped_handshake_total: Counter,

    /// PB-27. Ingress slots currently held. Without it, "the cap is too
    /// low", "slots are leaking" and "a squatter is present" are
    /// indistinguishable, and all three are only visible after capacity
    /// is already gone. Paired with the cap, this is the headroom an
    /// operator alerts on. Not a counter, so no `_total` suffix.
    pub(crate) connections_active: Gauge<i64, AtomicI64>,
}

impl VerifierMetrics {
    // A flat declaration list: one construction and one `register` call
    // per metric, no branching. Splitting it to satisfy a line count
    // would put half the registry in a helper with one caller and make
    // "is this metric registered?" a two-file question.
    #[allow(clippy::too_many_lines)]
    pub(crate) fn new_registered(registry: &mut Registry) -> Self {
        let m = Self {
            verdicts_total: Family::default(),
            templates_evaluated_total: Counter::default(),
            policy_reloads_total: Family::default(),
            shield_skipped_total: Counter::default(),
            phase2_degraded_total: Counter::default(),
            phase2_checks_total: Family::default(),
            phase2_second_chance_total: Family::default(),
            mempool_view_age_seconds: Gauge::default(),
            mempool_view_size: Gauge::default(),
            mempool_empty_responses: Gauge::default(),
            connections_refused_total: Counter::default(),
            connections_refused_per_ip_total: Counter::default(),
            connections_reaped_idle_total: Counter::default(),
            connections_reaped_handshake_total: Counter::default(),
            connections_active: Gauge::default(),
        };
        registry.register(
            "verifier_verdicts",
            "Total verdicts emitted by the verifier",
            m.verdicts_total.clone(),
        );
        registry.register(
            "verifier_templates_evaluated",
            "Total templates evaluated",
            m.templates_evaluated_total.clone(),
        );
        registry.register(
            "verifier_policy_reloads",
            "Total policy reload attempts",
            m.policy_reloads_total.clone(),
        );
        registry.register(
            "verifier_shield_skipped",
            "Phase 1 coverage gap: templates that reached the v2.0 Invariant Shield but \
             omitted raw_block_hex so the Class S and Class D check chain could not run. \
             Trends to zero as gateways are upgraded to ship raw block bytes. For Phase 2 \
             Class M (mempool ground truth) observability see verifier_phase2_checks_total, \
             verifier_phase2_degraded_total, verifier_mempool_view_age_seconds, and \
             verifier_mempool_view_size.",
            m.shield_skipped_total.clone(),
        );
        registry.register(
            "verifier_phase2_degraded",
            "Templates where the Phase 2 Class M check was skipped due to a Degraded mempool view",
            m.phase2_degraded_total.clone(),
        );
        registry.register(
            "verifier_phase2_checks",
            "Phase 2 Class M check outcomes by result label. result=recovered means the \
             first-pass check rejected the template against a stale mempool view and the \
             PB-40 second-chance lookup found bitcoind holding the transactions, so no \
             rejection was emitted",
            m.phase2_checks_total.clone(),
        );
        registry.register(
            "verifier_phase2_second_chance",
            "PB-40 second-chance lookups performed when the Phase 2 Class M check rejected a \
             template, by outcome. withdrawn = bitcoind held enough of the unknown \
             transactions to bring the recomputed ratio back within tolerance, so the \
             rejection was a false positive from mempool view staleness. upheld = bitcoind \
             knew neither the mempool nor recent blocks held them, the only outcome that can \
             support a detection claim. lookup_failed = bitcoind could not be asked and the \
             rejection stands UNADJUDICATED; it is not evidence either way and must be \
             excluded from any false-positive tally rather than counted as a true positive",
            m.phase2_second_chance_total.clone(),
        );
        registry.register(
            "verifier_mempool_view_age_seconds",
            "Age of the verifier's served mempool view in seconds",
            m.mempool_view_age_seconds.clone(),
        );
        registry.register(
            "verifier_mempool_view_size",
            "Number of distinct txids in the verifier's mempool view",
            m.mempool_view_size.clone(),
        );
        registry.register(
            "verifier_mempool_empty_responses",
            "Successful getrawmempool responses that returned an empty set and were refused \
             as a mempool view. A fresh empty view would score every template 100% unknown, \
             so the prior view is kept and ages toward Degraded instead. Nonzero on mainnet \
             means the RPC endpoint is wrong or bitcoind has not loaded mempool.dat",
            m.mempool_empty_responses.clone(),
        );
        registry.register(
            "verifier_connections_refused",
            "NDJSON ingress connections refused because the concurrent connection cap \
             (VELDRA_VERIFIER_MAX_CONNECTIONS) was saturated",
            m.connections_refused_total.clone(),
        );
        registry.register(
            "verifier_connections_refused_per_ip",
            "NDJSON ingress connections refused because the peer's source address already held \
             VELDRA_VERIFIER_MAX_CONNECTIONS_PER_IP slots. Raising the global cap does not \
             help this one",
            m.connections_refused_per_ip_total.clone(),
        );
        registry.register(
            "verifier_connections_reaped_idle",
            "NDJSON ingress connections ended by the no-progress deadline \
             (VELDRA_VERIFIER_IDLE_TIMEOUT_SECS) rather than by the peer closing. \
             Excludes TLS handshake kills; see verifier_connections_reaped_handshake_total",
            m.connections_reaped_idle_total.clone(),
        );
        registry.register(
            "verifier_connections_reaped_handshake",
            "NDJSON ingress connections ended because the TLS handshake did not complete \
             within the ingress handshake budget. That budget is a hardcoded constant, so \
             VELDRA_VERIFIER_IDLE_TIMEOUT_SECS does not affect this counter",
            m.connections_reaped_handshake_total.clone(),
        );
        registry.register(
            "verifier_connections_active",
            "NDJSON ingress slots currently held, out of VELDRA_VERIFIER_MAX_CONNECTIONS",
            m.connections_active.clone(),
        );
        m
    }
}

/// Shared metrics reference.
pub(crate) type SharedVerifierMetrics = Arc<VerifierMetrics>;

/// `GET /metrics` handler serving `OpenMetrics` text format.
pub(crate) async fn verifier_metrics_handler(
    Extension(registry): Extension<reservegrid_common::metrics::SharedRegistry>,
) -> impl IntoResponse {
    let (status, content_type, body) = reservegrid_common::metrics::render_metrics(&registry);
    (
        StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        [(axum::http::header::CONTENT_TYPE, content_type)],
        body,
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// PB-12 regression. `prometheus-client` appends a `_total` suffix
    /// to every counter on export, so a registered counter name must
    /// not already carry `_total` or it exports as `_total_total`.
    #[test]
    fn counters_export_single_total_suffix() {
        let mut registry = Registry::default();
        let m = VerifierMetrics::new_registered(&mut registry);

        // Emit a sample line per counter. Family counters print only
        // their metadata lines until a labeled child exists.
        m.templates_evaluated_total.inc();
        m.shield_skipped_total.inc();
        m.phase2_degraded_total.inc();
        m.connections_refused_total.inc();
        m.connections_refused_per_ip_total.inc();
        m.connections_reaped_idle_total.inc();
        m.connections_reaped_handshake_total.inc();
        m.verdicts_total
            .get_or_create(&VerdictLabels {
                accepted: "true".to_string(),
                reason_code: "ok".to_string(),
            })
            .inc();
        m.policy_reloads_total
            .get_or_create(&PolicyReloadLabels {
                result: "ok".to_string(),
            })
            .inc();
        m.phase2_checks_total
            .get_or_create(&Phase2CheckLabels {
                result: "agreed".to_string(),
            })
            .inc();

        let (status, _, body) = reservegrid_common::metrics::render_metrics(&registry);
        assert_eq!(status, 200);

        for name in [
            "verifier_verdicts_total",
            "verifier_templates_evaluated_total",
            "verifier_policy_reloads_total",
            "verifier_shield_skipped_total",
            "verifier_phase2_degraded_total",
            "verifier_phase2_checks_total",
            "verifier_connections_refused_total",
            "verifier_connections_refused_per_ip_total",
            "verifier_connections_reaped_idle_total",
            "verifier_connections_reaped_handshake_total",
        ] {
            assert!(body.contains(name), "missing exported counter `{name}`");
            let doubled = format!("{name}_total");
            assert!(!body.contains(&doubled), "double suffix on `{name}`");
        }

        // Gauges never take the `_total` suffix.
        assert!(body.contains("verifier_mempool_view_age_seconds"));
        assert!(body.contains("verifier_mempool_view_size"));
        assert!(!body.contains("verifier_mempool_view_size_total"));
        assert!(body.contains("verifier_mempool_empty_responses"));
        assert!(!body.contains("verifier_mempool_empty_responses_total"));
        assert!(body.contains("verifier_connections_active"));
        assert!(!body.contains("verifier_connections_active_total"));
    }
}
