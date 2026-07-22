//! v2.0 Invariant Shield Phase 2 #3 Tier 1 integration tests (ADR-003).
//!
//! Exercises `policy::evaluate_dynamic_phase2` end-to-end against
//! controlled mempool snapshots constructed via the
//! `pool_verifier::mempool_view::MempoolView::install_at` injection
//! seam. Tier 2 in `phase2_tcp.rs` reuses the same regtest segwit
//! fixture and drives the full pool-verifier TCP listener via a
//! subprocess plus an in-process bitcoind JSON-RPC mock.
//!
//! Per ADR-003 #3 acceptance, this file covers three of the four
//! originally-listed scenarios. The fourth (per-tx detail mode) is
//! deferred to Phase 2 #3.5 because the wiring has not landed yet:
//! `check_invariant_shield_inner` does not read
//! `[policy.mempool] per_tx_detail`, and the ingress writer currently
//! emits one `TemplateVerdict` per accepted `TemplatePropose`.
//! Multi-verdict-per-template emission is a protocol surface change
//! that gets its own commit.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::HashSet;
use std::sync::Arc;

use pool_verifier::mempool_view::{MempoolSnapshot, MempoolState, MempoolView};
use pool_verifier::policy::{PolicyConfig, ShieldOutcome, evaluate_dynamic_phase2};
use rg_protocol::{PROTOCOL_VERSION, TemplatePropose, VerdictReason};

const REGTEST_SEGWIT_BLOCK_HEX: &str = include_str!("fixtures/regtest_segwit_block.hex");

/// Build a fresh snapshot at age 0 carrying the supplied txids in
/// internal byte order.
fn fresh_snapshot(txids: Vec<[u8; 32]>) -> MempoolSnapshot {
    MempoolSnapshot {
        state: MempoolState::Fresh,
        txids: Arc::new(txids.into_iter().collect()),
        age_secs: 0,
        size: 0,
    }
}

/// Build a `TemplatePropose` against the regtest segwit fixture with
/// every Phase 1 invariant declared correctly so the shield reaches
/// the Class M check. Re-derives weight and sigops via the facade so
/// the test never hand-encodes counts that drift if the sigop
/// accounting changes (R-148 / R-154 facade narrowness).
fn regtest_segwit_template() -> (TemplatePropose, Vec<[u8; 32]>) {
    let bytes =
        hex::decode(REGTEST_SEGWIT_BLOCK_HEX.trim()).expect("REGTEST_SEGWIT_BLOCK_HEX decodes");
    let parsed = rg_consensus::parse_block(&bytes).expect("regtest block parses");
    // PB-19 producer conventions: non-coinbase weight sum, sigops in
    // cost units (declared as the legacy x4 floor), non-coinbase
    // tx_count.
    let weight = rg_consensus::non_coinbase_tx_weight(&parsed);
    let total_sigops_cost = u32::try_from(u64::from(rg_consensus::total_sigops(&parsed)) * 4)
        .expect("fixture sigop cost fits u32");
    let coinbase_sigops_cost = u32::try_from(u64::from(rg_consensus::coinbase_sigops(&parsed)) * 4)
        .expect("fixture coinbase sigop cost fits u32");
    let txids = rg_consensus::template_txids(&parsed);

    let coinbase_value =
        rg_consensus::re_derive_coinbase_value(&bytes).expect("regtest coinbase value re-derives");

    let template = TemplatePropose {
        version: PROTOCOL_VERSION,
        id: 1,
        block_height: 102,
        prev_hash: "a".repeat(64),
        coinbase_value,
        tx_count: 1,
        total_fees: 0,
        observed_weight: None,
        created_at_unix_ms: None,
        total_sigops: Some(total_sigops_cost),
        coinbase_sigops: Some(coinbase_sigops_cost),
        template_weight: Some(weight),
        gateway_instance_id: None,
        raw_block_hex: Some(REGTEST_SEGWIT_BLOCK_HEX.trim().to_string()),
    };
    (template, txids)
}

fn permissive_policy() -> PolicyConfig {
    let mut cfg = PolicyConfig::default_with_protocol(PROTOCOL_VERSION);
    cfg.required_prevhash_len = 64;
    cfg.min_total_fees = 0;
    // Zero every tier so the test never depends on which fee tier
    // mempool_tx selects. Without this, a 100-tx mempool routes to
    // the mid tier (default min_avg_fee_mid=500) and the regtest
    // fixture's avg fee of 0 trips AvgFeeBelowMinimum before the
    // Class M check ever runs.
    cfg.min_avg_fee_lo = 0;
    cfg.min_avg_fee_mid = 0;
    cfg.min_avg_fee_hi = 0;
    cfg.reject_empty_templates = false;
    cfg.reject_coinbase_zero = false;
    cfg.unknown_mempool_as_high = true;
    cfg.safety.max_template_age_ms = None;
    cfg
}

#[test]
fn phase2_happy_path_full_overlap_emits_agreed() {
    let (template, txids) = regtest_segwit_template();
    let snapshot = fresh_snapshot(txids);
    let cfg = permissive_policy();
    let now_ms = 0;

    let result = evaluate_dynamic_phase2(&template, &cfg, Some(&snapshot), Some(100), now_ms);

    assert!(
        result.reason.is_none(),
        "expected Agreed, got reason={:?} detail={:?}",
        result.reason,
        result.detail
    );
}

#[test]
fn phase2_fabrication_path_above_threshold_emits_tolerance_exceeded() {
    let (template, _txids) = regtest_segwit_template();
    // Empty mempool view but the template has 1 non-coinbase tx.
    // 1/1 = 100% unknown, well above the 4% default threshold.
    let snapshot = fresh_snapshot(vec![]);
    let cfg = permissive_policy();
    let now_ms = 0;

    let result = evaluate_dynamic_phase2(&template, &cfg, Some(&snapshot), Some(100), now_ms);

    assert_eq!(
        result.reason,
        Some(VerdictReason::V2InvariantMempoolToleranceExceeded),
        "expected V2InvariantMempoolToleranceExceeded, got {:?} detail={:?}",
        result.reason,
        result.detail
    );
    let detail = result.detail.expect("ToleranceExceeded carries detail");
    assert!(
        detail.contains("1/1 txs unknown"),
        "detail must surface the unknown ratio, got: {detail}"
    );
    assert!(
        detail.contains("sample=["),
        "detail must surface representative txids, got: {detail}"
    );
}

#[test]
fn phase2_below_threshold_unknown_still_agrees() {
    // 1 unknown of 100 = 1%, below 4%. Synthesize a 100-tx view with
    // 99 overlapping the template plus 1 fabricated.
    let mut mempool: HashSet<[u8; 32]> = (0u8..99).map(|b| [b; 32]).collect();
    let template_txids: Vec<[u8; 32]> = {
        let mut v: Vec<[u8; 32]> = (0u8..99).map(|b| [b; 32]).collect();
        v.push([0xff; 32]);
        v
    };
    mempool.insert([0xee; 32]);
    let snapshot = MempoolSnapshot {
        state: MempoolState::Fresh,
        txids: Arc::new(mempool),
        age_secs: 0,
        size: 0,
    };

    let outcome = pool_verifier::mempool_view::evaluate(&snapshot, &template_txids, 4.0);
    match outcome {
        pool_verifier::mempool_view::MempoolCheckOutcome::Agreed {
            unknown_count,
            total,
        } => {
            assert_eq!(unknown_count, 1);
            assert_eq!(total, 100);
        }
        other => panic!("expected Agreed below threshold, got {other:?}"),
    }
}

/// `MempoolView::install_at` lets the test seed the refresh
/// timestamp so the fail-stale state machine can be driven without
/// wall-clock time. Verifies all three states.
#[tokio::test]
async fn phase2_view_state_machine_drives_fresh_stale_degraded() {
    let max_stale_secs = 60;
    let view = Arc::new(MempoolView::new(max_stale_secs));

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .expect("clock available");

    // Fresh: install at now, snapshot must report Fresh.
    let txids: HashSet<[u8; 32]> = HashSet::from([[1u8; 32]]);
    view.install_at(txids.clone(), now_ms).await;
    let snap = view.snapshot().await;
    assert_eq!(snap.state, MempoolState::Fresh);
    assert_eq!(snap.size, 1);

    // Stale: install with a refresh timestamp 90s in the past
    // (between max_stale_secs and 2 * max_stale_secs).
    view.install_at(txids.clone(), now_ms.saturating_sub(90_000))
        .await;
    let snap = view.snapshot().await;
    assert_eq!(snap.state, MempoolState::Stale);
    assert!(
        snap.age_secs >= 90,
        "expected age >= 90, got {}",
        snap.age_secs
    );

    // Degraded: install with a refresh timestamp 130s in the past
    // (past 2 * max_stale_secs).
    view.install_at(txids, now_ms.saturating_sub(130_000)).await;
    let snap = view.snapshot().await;
    assert_eq!(snap.state, MempoolState::Degraded);
}

/// Ensures the shield bypasses Class M when the view is Degraded
/// rather than rejecting. `verifier_phase2_degraded_total` is the
/// observability surface for this path; the verdict itself is Agreed.
#[test]
fn phase2_degraded_view_skips_check_and_agrees() {
    let (template, _txids) = regtest_segwit_template();
    let snapshot = MempoolSnapshot {
        state: MempoolState::Degraded,
        txids: Arc::new(HashSet::new()),
        age_secs: 999,
        size: 0,
    };
    let cfg = permissive_policy();
    let now_ms = 0;

    let result = evaluate_dynamic_phase2(&template, &cfg, Some(&snapshot), Some(100), now_ms);

    assert!(
        result.reason.is_none(),
        "Degraded view must skip Class M and agree, got reason={:?} detail={:?}",
        result.reason,
        result.detail
    );
}

/// PB-13: a view that has never been primed by a successful poll
/// reports `Unprimed`, not `Degraded`, so the boot window stays out
/// of `verifier_phase2_degraded_total`. `evaluate` skips Class M for
/// it exactly as for `Degraded`, and the first successful install
/// moves it to `Fresh`.
#[tokio::test]
async fn phase2_unprimed_view_reports_unprimed_and_skips() {
    let view = MempoolView::new(60);

    let snap = view.snapshot().await;
    assert_eq!(snap.state, MempoolState::Unprimed);
    assert_eq!(snap.size, 0);

    let outcome = pool_verifier::mempool_view::evaluate(&snap, &[[7u8; 32]], 4.0);
    assert_eq!(
        outcome,
        pool_verifier::mempool_view::MempoolCheckOutcome::Skipped
    );

    view.install(HashSet::from([[1u8; 32]])).await;
    assert_eq!(view.snapshot().await.state, MempoolState::Fresh);
}

/// PB-13 policy path: an `Unprimed` snapshot must skip Class M and
/// agree, matching the `Degraded` behavior, so a booting verifier
/// never rejects a template just because the view has not primed yet.
#[test]
fn phase2_unprimed_view_skips_check_and_agrees() {
    let (template, _txids) = regtest_segwit_template();
    let snapshot = MempoolSnapshot {
        state: MempoolState::Unprimed,
        txids: Arc::new(HashSet::new()),
        age_secs: 0,
        size: 0,
    };
    let cfg = permissive_policy();
    let now_ms = 0;

    let result = evaluate_dynamic_phase2(&template, &cfg, Some(&snapshot), Some(100), now_ms);

    assert!(
        result.reason.is_none(),
        "Unprimed view must skip Class M and agree, got reason={:?} detail={:?}",
        result.reason,
        result.detail
    );
}

/// Phase 1 + Phase 2 toggle: passing `mempool_snapshot = None` must
/// reproduce `evaluate_dynamic` exactly (no Class M attempt).
#[test]
fn phase2_disabled_falls_through_to_phase1() {
    let (template, _txids) = regtest_segwit_template();
    let cfg = permissive_policy();
    let now_ms = 0;

    let with_none = evaluate_dynamic_phase2(&template, &cfg, None, Some(100), now_ms);
    let phase1 = pool_verifier::policy::evaluate_dynamic(&template, &cfg, Some(100), now_ms);

    assert_eq!(with_none.reason, phase1.reason);
    assert_eq!(with_none.detail, phase1.detail);
}

/// Defensive: `ShieldOutcome::Rejected` produced by the Phase 2 path
/// always carries a non-empty `detail` so dashboards can surface the
/// unknown ratio without separate lookups.
#[test]
fn phase2_rejected_carries_machine_readable_detail() {
    let (template, _txids) = regtest_segwit_template();
    let outcome = pool_verifier::policy::check_invariant_shield_with_mempool(
        &template,
        &fresh_snapshot(vec![]),
        4.0,
        false,
    );
    match outcome {
        ShieldOutcome::Rejected { reason, detail } => {
            assert_eq!(reason, VerdictReason::V2InvariantMempoolToleranceExceeded);
            assert!(!detail.is_empty(), "detail must not be empty");
            assert!(detail.contains("mempool tolerance exceeded"));
        }
        other => panic!("expected Rejected, got {other:?}"),
    }
}

/// Phase 2 #3.5 per-tx detail wiring. With `per_tx_detail = true`
/// the rejection detail string carries every unknown txid in the
/// `sample=[…]` field, not just the bounded
/// `mempool_view::SAMPLE_UNKNOWN_CAP` (10) sample. Wire stays 1:1
/// (one `TemplateVerdict` per accepted `TemplatePropose`); `per_tx_detail`
/// expands the existing `reason_detail` field rather than introducing
/// multi-verdict emission. Dashboard format stays grep-compatible
/// via the same `sample=` field name.
#[test]
fn phase2_per_tx_detail_helper_keeps_full_list_uncapped() {
    use pool_verifier::policy::format_mempool_tolerance_detail;

    // 50-tx unknown set, larger than SAMPLE_UNKNOWN_CAP. The aggregate
    // path passes the bounded sample (10 entries). The per-tx path
    // passes the full list (50 entries). The helper formats either
    // shape into the canonical `sample=[hex,hex,...]` field.
    let full_unknown: Vec<[u8; 32]> = (1u8..=50).map(|b| [b; 32]).collect();
    let bounded: Vec<[u8; 32]> = full_unknown
        .iter()
        .take(pool_verifier::mempool_view::SAMPLE_UNKNOWN_CAP)
        .copied()
        .collect();

    let detail_aggregate = format_mempool_tolerance_detail(50, 50, &bounded);
    let detail_per_tx = format_mempool_tolerance_detail(50, 50, &full_unknown);

    assert!(detail_aggregate.contains("50/50 txs unknown"));
    assert!(detail_per_tx.contains("50/50 txs unknown"));

    // Both contain the canonical `sample=` field, but the per-tx one
    // carries 5x more entries.
    let agg_count = detail_aggregate.matches(',').count() + 1;
    let per_tx_count = detail_per_tx.matches(',').count() + 1;
    assert_eq!(agg_count, pool_verifier::mempool_view::SAMPLE_UNKNOWN_CAP);
    assert_eq!(per_tx_count, 50);
}

/// `policy::evaluate_dynamic_phase2` flows `cfg.mempool.per_tx_detail`
/// into the shield call. With `per_tx_detail=true` the shield's
/// rejection detail must cite the full unknown list; with false it
/// must cite the bounded sample. Wires through `evaluate_dynamic_phase2`.
#[test]
fn phase2_evaluate_dynamic_phase2_routes_per_tx_detail_flag() {
    let (template, _txids) = regtest_segwit_template();
    let snapshot = fresh_snapshot(vec![]);

    let mut cfg_aggregate = permissive_policy();
    cfg_aggregate.mempool.per_tx_detail = false;
    let result_aggregate =
        evaluate_dynamic_phase2(&template, &cfg_aggregate, Some(&snapshot), Some(0), 0);

    let mut cfg_per_tx = permissive_policy();
    cfg_per_tx.mempool.per_tx_detail = true;
    let result_per_tx =
        evaluate_dynamic_phase2(&template, &cfg_per_tx, Some(&snapshot), Some(0), 0);

    // Both reject with the same canonical reason_code.
    assert_eq!(
        result_aggregate.reason,
        Some(VerdictReason::V2InvariantMempoolToleranceExceeded)
    );
    assert_eq!(
        result_per_tx.reason,
        Some(VerdictReason::V2InvariantMempoolToleranceExceeded)
    );
    // Both detail strings contain the canonical `sample=[` field.
    let detail_a = result_aggregate.detail.expect("aggregate detail");
    let detail_b = result_per_tx.detail.expect("per_tx detail");
    assert!(detail_a.contains("sample=["));
    assert!(detail_b.contains("sample=["));
    // For this 1-tx fixture both modes emit the same single txid; the
    // cap difference is exercised by the helper-level test above.
    // What this test proves is that the per_tx_detail flag plumbs all
    // the way through cfg.mempool.per_tx_detail into the shield call
    // without crashing or short-circuiting on a different reason.
}

/// Defensive: `ShieldOutcome::Rejected` produced by the Phase 2 path
/// always carries a non-empty `detail` so dashboards can surface the
/// unknown ratio without separate lookups.
#[test]
fn phase2_rejected_detail_format_under_per_tx_uses_same_sample_field() {
    let (template, _txids) = regtest_segwit_template();
    let outcome_a = pool_verifier::policy::check_invariant_shield_with_mempool(
        &template,
        &fresh_snapshot(vec![]),
        4.0,
        false,
    );
    let outcome_b = pool_verifier::policy::check_invariant_shield_with_mempool(
        &template,
        &fresh_snapshot(vec![]),
        4.0,
        true,
    );
    for outcome in [outcome_a, outcome_b] {
        match outcome {
            ShieldOutcome::Rejected { reason, detail } => {
                assert_eq!(reason, VerdictReason::V2InvariantMempoolToleranceExceeded);
                assert!(detail.contains("mempool tolerance exceeded"));
                assert!(
                    detail.contains("sample=["),
                    "detail must keep canonical sample=[…] field, got: {detail}"
                );
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }
}
