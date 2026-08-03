# ADR-003: v2.0 Invariant Shield Phase 2 — Mempool Ground Truth and Enforcement Policy

**Status:** Proposed
**Date:** 2026-04-29
**Deciders:** Jarron (Veldra, Inc.)
**Supersedes:** None
**Extends:** ADR-002 (v2.0 Invariant Shield Scope and Parser Choice)

## Context

ADR-002 Phase 1 introduced the v2.0 Invariant Shield as a re-derivation
pass inside `pool-verifier` that catches two attacker classes against
block templates: T1 internal `raw_block` tampering where the header,
coinbase, and body bytes are mutually inconsistent, and T2
`TemplatePropose` declared values disagreeing with what re-derivation
of the same `raw_block` bytes shows. Phase 1 #4b shipped on 2026-04-29
with 11 of 18 invariants wired and tested against genesis plus a
regtest segwit fixture, closing T1 and T2 to ~95% practical coverage.
Phase 1.5 shipped 2026-07-22 and wired the remaining 7 Tier 3
belt-and-suspenders checks, completing all 18 ADR-002 invariants.

Phase 1 cannot close one specific attacker class:

> **T3 consistent template-manager fabrication.** A malicious or
> compromised template-manager produces a `TemplatePropose` whose
> `raw_block_hex` carries a fabricated transaction set. The merkle
> root over the fabricated body matches the header, the witness
> commitment over the fabricated wtxids matches the coinbase
> `OP_RETURN`, the declared `coinbase_value` matches the fabricated
> coinbase outputs, every BIP-141 and BIP-34 check passes, and the
> shield emits `Agreed`. The fabrication is internally consistent
> by construction. The shield has no source of external truth to
> compare against.

T3 is real because template-managers are operational software with
network exposure. A template-manager is the smallest component an
attacker needs to compromise to siphon pool revenue: any operator
running a pool routes 100% of their revenue through template-manager
output. The attacker payload is not exotic, it is "include one of my
own outputs in every coinbase you produce". The shield as currently
shipped has no path to detect this.

Phase 2 closes T3 by introducing a second source of truth that the
verifier can cross-check the template's transaction set against. The
network mempool is the natural reference. A real Bitcoin block at
the time of mining must consist of the coinbase plus a subset of
transactions present in the operator's mempool at that block height.
A template with transactions absent from the mempool has either a
benign explanation (mempool propagation lag) or T3-class fabrication.
The verifier runs a tolerance-window check on the overlap and
rejects on excess divergence.

Phase 2 explicitly leaves two attacker classes open and documents
them as out of scope:

> **T4 compromised operator bitcoind.** If the bitcoind that backs
> the verifier's mempool view is itself the tampered source, no
> internal check can catch it. The operator owns the trust boundary
> at their bitcoind. Future mitigations (network-diverse second
> bitcoind, signed blockheader chain feed) are v3.x territory.

> **T5 selfish-mining or aggressive mempool-policy divergence.**
> Real Bitcoin mempools can legitimately differ across peers under
> selfish mining strategies or operator-side mempool policy
> divergence. The 4% tolerance window covers benign divergence;
> targeted selfish-mining-style attacks against template integrity
> are a different threat model that v2.0 does not address.

## Decision

**Add a Class M (Mempool) check to the v2.0 Invariant Shield that
runs after Class S and Class D checks. The verifier holds its own
bitcoind RPC client, maintains an in-memory mempool view as a
`HashSet<Txid>` refreshed on a configurable poll interval, and
checks every template's transaction set against the view with a
tolerance-window threshold defaulting to 4%. Failure modes use
fail-stale degradation up to 60 seconds, then fail-degraded to
Phase 1 behavior with a counter increment. Phase 2 rejection gates
the template only in inline mode; shadow and observe still emit
the verdict but do not gate template flow.**

This decision flows from six locked design forks documented in
EXECLOG D-18 on 2026-04-29. The full rationale per fork is in the
Options Considered section. Action item sequencing for
implementation lives in the Action Items section.

## Options Considered

### F1: Mempool source

**F1a (chosen): Verifier holds its own bitcoind RPC client.**
Pool-verifier gains a new RPC client. Polls `getrawmempool verbose=false`
every N seconds (configurable, default 10s). Maintains an in-memory
`HashSet<Txid>` plus a `last_refresh_unix_ms` timestamp. Per-template
checks are sub-microsecond hash lookups against the in-memory set.

**F1b (rejected): Template-manager pre-fetches mempool digest, ships
it inside `TemplatePropose`.** Trusting a possibly-tampered
template-manager to ship the ground truth defeats the point of
external cross-check. If template-manager is the attacker, it
controls the digest. Rejected on first principles.

**F1c (rejected): Verifier asks bitcoind on demand per template.**
N RPC calls per template at ~1ms each. For a 2000-tx template this
is ~2 seconds, brushing against `prevhash_verdict_timeout_ms = 2000`.
Latency budget too tight, and chatty RPC traffic adds operational
load on bitcoind.

### F2: Consistency check granularity

**F2a (rejected): Strict every-txid-must-be-in-mempool.** Every
template tx must be in the verifier's mempool view. Rejected on
false-positive risk. Mempool propagation lag between healthy peers
can transiently leave a 2-second gap during which a real tx is in
template-manager's mempool but not yet in verifier's. RBF transitions
and eviction events also produce legitimate divergence.

**F2b (chosen): Tolerance window with configurable threshold,
default 4%.** Templates pass when at most 4% of their transactions
are unknown to the verifier's mempool view. Reject with
`v2_invariant_mempool_tolerance_exceeded` otherwise. Threshold
lives in `policy.toml` as `mempool_tolerance_pct`.

The 4% default is operationally tunable, set per the criteria:

- Mainnet mempool propagation between healthy peers is typically
  under 2 seconds; measured tx-set divergence sits well under 1%
  during normal operation.
- 4% provides headroom for RBF transitions, eviction events, and
  peers-of-our-bitcoind disagreements without opening a meaningful
  tampering window.
- A T3-class fabrication cannot stay reliably under 4% of a
  multi-thousand-tx template without network-side coordination.
- **Tuning trigger:** false positive rate above 0.5% of templates
  in shadow observation raises threshold by 1% increments; if shield
  catches genuine attacks, consider lowering toward 2%.
- **Acceptance metric for default 4%:** zero false positives across
  one week of shadow-mode production observation against a real
  operator bitcoind.

**F2c (rejected): Coinbase-and-fee-only.** Verifier checks only that
the coinbase output sum is consistent with declared mempool fees plus
subsidy. Catches the most-revenue-impactful T3 attack but misses
fabrications that match the fee math but include fake non-coinbase
transactions (which can still alter the block's effective transaction
set and hide value-extraction patterns). Insufficient.

**F2d (rejected): Policy-driven mode selection.** Operator chooses
strict, tolerant, or coinbase-only via policy. Adds operational
complexity for v2.0 launch with no current customer demand for the
flexibility.

### F3: Enforcement policy

**F3a (chosen): Inline-only enforcement.** Phase 2 rejection blocks
the template only in inline mode, matching Phase 1 today. Shadow
and observe emit the verdict but do not gate template flow. Operators
graduate to F3b after production observation shows zero false
positives.

**F3b (rejected for v2.0, candidate for v2.1): Inline plus observe
enforcement.** Observe-mode operators run real miners against real
hashrate; arguably they want T3 protection too. Defer because
inline-only is the conservative default; promotion to F3b should
come from operator data, not a priori reasoning.

**F3c (rejected): Per-mode operator override.** Adds policy keys
and decision surface without obvious customer demand. Revisit in
v2.1 if observed need surfaces.

### D: Failure mode under bitcoind unavailability

**D1 (rejected): Fail-closed.** Bitcoind unreachable, every template
rejects with `v2_invariant_mempool_unavailable`. Creates an
availability cliff during normal bitcoind blips (restart, network
hiccup, restart-on-config-reload). Production hostility outweighs
security benefit.

**D2 (rejected as standalone): Fail-degraded.** Phase 2 check
skipped immediately on RPC unavailability, templates fall through to
Phase 1 with counter increment. Acceptable but loses the recently-fresh
mempool view that is still trustworthy for several seconds.

**D3 (chosen): Fail-stale with bounded staleness then fail-degraded.**
Verifier serves the last known mempool view up to 60 seconds old.
Beyond that, Phase 2 check is skipped, templates fall through to
Phase 1 behavior, and `verifier_phase2_degraded_total` increments.
60-second default lives in `policy.toml` as
`mempool_max_stale_secs`. Bitcoind blips under 60 seconds remain
fully covered; longer outages degrade gracefully with operator
alerting.

### Q6: ADR-003 vs extending ADR-002

**Chosen: ADR-003 dedicated.** ADR-002 is already substantial
(~400 lines covering Phase 1 scope, parser choice, facade design,
check set, and action items). Phase 2's threat model formalization
warrants its own document for reviewers and future-you. ADR-002
gains a short Phase 2 stub section that cross-links to ADR-003.

## Trade-off Analysis

The chosen design optimizes for three properties.

**Trust completeness for the v2.0 launch story.** With Phase 2 wired,
the shield closes T1, T2, and T3. T4 (compromised operator bitcoind)
is operator-side and explicitly named as out of scope. T5 (selfish
mining) is a different threat model. The trio T1+T2+T3 is what the
v2.0 marketing narrative needs and what a paying mainnet customer
needs to trust the inline-mode enforcement decision.

**Operational realism.** F1a verifier-owned RPC client matches how
operators already deploy: pool-verifier already has metrics endpoints
and a config file; adding a bitcoind client follows existing patterns.
D3 fail-stale behavior matches operational reality where bitcoind
blips happen under load and we cannot afford to convert every blip
into a production outage. F2b 4% threshold acknowledges that real
mempools diverge benignly and the shield must distinguish divergence
from attack.

**Forward compatibility with v3.x.** Per-tx detail mode lets dashboards
drill into specific missing transactions, which is the data shape v3.x
will need for selfish-mining detection or operator-side mempool policy
analytics. Adding the mode now keeps the export schema stable when
v3.x ships. The new reason codes follow the existing `v2_invariant_*`
prefix convention so canonical strings stay stable across protocol,
verifier, exports, and docs (R-118 / Tier 1 #3 pattern).

The chosen design accepts three costs.

**One new RPC client surface in pool-verifier.** Adds bitcoind RPC
config keys, error handling, retry policy, and metrics. Estimated
~200-300 lines of new code in pool-verifier across rpc client,
mempool view subscription, fail-stale state machine, and shield
integration.

**Operational complexity at deploy time.** Operators must point
pool-verifier at a bitcoind RPC endpoint. In observe and inline modes
this is the same bitcoind template-manager already consumes via
rg-feed-adapter; the verifier could in principle reuse the same
endpoint. Deployment runbook gains a Phase 2 section explaining the
shared bitcoind credential pattern.

**One additional latency dimension.** Per-template mempool checks are
sub-millisecond by design (HashSet lookup), but the polling loop
maintains the view in the background. Tuning the poll interval is
a trade-off between view freshness and bitcoind load. Default 10s
is a starting point; production observation will inform.

## Consequences

**What becomes easier.**

- The v2.0 marketing story acquires a concrete trust completeness
  claim ("the shield catches three of three template-manager attacker
  classes") tied to specific reason codes, not aspirational language.
- Operators running inline mode get protection against T3 without
  any per-template configuration; the shield runs by default once
  Phase 2 is wired and bitcoind RPC is configured.
- Selfish-mining detection (v3.x) and operator mempool analytics
  ride the same per-tx detail data shape Phase 2 introduces, so
  no schema break later.
- Public veldra-site redesign (task #43) gains a clear "Threat Model"
  page anchor that names T1 through T5 explicitly, which the
  competitive comparison matrix can reference.

**What becomes harder.**

- Pool-verifier deploy now requires bitcoind RPC creds; previously
  pool-verifier was bitcoind-agnostic. Documentation burden grows.
- Operators on observe mode using the Veldra-hosted feed must wire
  their own bitcoind for Phase 2 to work, or accept Phase 2 stays
  in degraded mode (Phase 1 only) on shadow-fed deployments.
- Test harness for Phase 2 needs a regtest bitcoind plus the ability
  to craft a tampered template that includes a fabricated tx. Phase
  2 #3 covers this.

**Trust boundary statement.** ReserveGrid OS v2.0 with Phase 1+2
shipped catches T1, T2, and T3 attacker classes. T4 compromised
operator bitcoind and T5 selfish mining are explicitly out of scope.
This is the canonical sentence that public docs, threat model page,
and customer conversations should converge on.

## Phase 2 Check Set and Reason Code Allocation

Phase 2 wires one Class M (Mempool) check that runs after Class S
and Class D in the existing shield short-circuit chain. The single
check produces four canonical reason codes covering the failure
modes:

| Reason code | When it fires |
| --- | --- |
| `v2_invariant_mempool_tx_unknown` | A specific template tx is not in the verifier's mempool view. Per-tx detail mode emits one record per missing tx; default mode emits one summary record listing first 10 and total count. |
| `v2_invariant_mempool_tolerance_exceeded` | Aggregate count of unknown txs exceeds the configured `mempool_tolerance_pct` (default 4%). Always emitted as one record per template. |
| `v2_invariant_mempool_unavailable` | Bitcoind RPC unreachable beyond the `mempool_max_stale_secs` (default 60s) fail-stale window. Phase 2 check skipped, template falls through to Phase 1 behavior; this code accompanies the verdict to record the degraded path. |
| `v2_invariant_mempool_view_stale` | Mempool view age exceeds the staleness threshold during a refresh attempt that did not yet trigger fail-stale; observability code, fires when a refresh is overdue but not yet over the limit. |

Total V2 invariant codes after Phase 2: 22 (18 Phase 1 + 4 Phase 2).
Total canonical reason codes after Phase 2: 95 (37 verdict + 59
gateway minus 1 shared `internal_error`). Public-surface count
refresh trigger when Phase 2 ships, gated on the website redesign
per task #43 and BIZLOG 2026-04-29.

**Per-tx detail mode** (`mempool_per_tx_detail` in `policy.toml`,
default `false`):

- false (default): one verdict record per template with `reason_code`
  set to the appropriate aggregate code and `reason_detail` listing
  up to 10 example txids plus the total unknown count. Bounded
  export volume.
- true: one verdict record per missing tx with `reason_code =
  v2_invariant_mempool_tx_unknown` and `reason_detail` carrying the
  txid. Plus one aggregate record per template if the threshold is
  also exceeded. Useful for forensic analysis but produces N records
  per template where N is the missing-tx count.

**New policy keys added to `[policy]` table in `policy.toml`:**

```
mempool_enforce              bool, default true   master enable for Phase 2
mempool_tolerance_pct        f64,  default 4.0    tolerance window threshold
mempool_poll_interval_secs   u64,  default 10     getrawmempool poll cadence
mempool_max_stale_secs       u64,  default 60     fail-stale window
mempool_per_tx_detail        bool, default false  forensic detail mode
mempool_rpc_url              str,  default ""     bitcoind RPC endpoint (required when mempool_enforce=true)
mempool_rpc_user             str,  default ""     bitcoind RPC user
mempool_rpc_pass             str,  default ""     bitcoind RPC pass (also via VELDRA_BITCOIND_RPC_PASS)
```

Eight new policy keys take the v1.1.0 `[policy]` count of 61 to
69 once Phase 2 ships. Bumping public docs and i18n entries follows
the Tier 1 #3 / R-167 pattern.

**New metrics:**

```
verifier_phase2_degraded_total       counter      bitcoind unavailable beyond fail-stale
verifier_mempool_view_age_seconds    gauge        seconds since last successful refresh
verifier_mempool_view_size           gauge        current HashSet<Txid> count
verifier_phase2_checks_total{result} counter vec  result in {agreed, rejected, skipped, stale, unprimed}
```

Four new metrics. Dashboards consume `verifier_mempool_view_age_seconds`
and `verifier_phase2_degraded_total` for operator alerting.

## Action Items

The Phase 2 implementation sequence mirrors Phase 1 #4b's bucketing
discipline. Each bucket lands as one or more commits with explicit
test gates and CI green requirements before the next bucket starts.

1. [x] **Phase 2 #1 rg-consensus** (cac223c, 2026-04-30) Added
   `MempoolDisagreement`, `MempoolToleranceExceeded`,
   `MempoolUnavailable`, and `MempoolViewStale` variants to
   `ConsensusViolation`. Mirrored as four new
   `VerdictReason::V2InvariantMempool*` and four new
   `ReasonCode::V2InvariantMempool*` variants with explicit
   `#[serde(rename)]` per R-155. `ALL_CODES` length assertions now
   read 22 / 37 / 95. Pure facade additions, no wiring or behavior.

2. [x] **Phase 2 #2 pool-verifier** (e422bd6, 2026-04-30) Landed
   `bitcoind_rpc` (reqwest JSON-RPC client with basic auth) and
   `mempool_view` (snapshot owning `HashSet<[u8; 32]>` plus
   `last_refresh_unix_ms` plus a tokio polling task) as new lib
   modules. `MempoolState` enum (`Fresh`, `Stale`, `Degraded`)
   wires the fail-stale state machine per D3. `policy::evaluate_dynamic`
   now routes through `check_invariant_shield_with_mempool` whenever
   `AppState::mempool_view` is `Some`; tolerance and unknown-tx
   checks emit the canonical `v2_invariant_mempool_tolerance_exceeded`
   and `v2_invariant_mempool_tx_unknown` reason codes. Eight policy
   keys parsed from `[policy.mempool]` (`enforce`, `tolerance_pct`,
   `poll_interval_secs`, `max_stale_secs`, `per_tx_detail`,
   `rpc_url`, `rpc_user`, `rpc_pass`). Four metrics emitted
   (`verifier_mempool_view_age_seconds`, `verifier_mempool_view_size`,
   `verifier_phase2_checks_total{result}`,
   `verifier_phase2_degraded_total`). `rg-consensus::template_txids`
   is the new Class M accessor that returns non-coinbase txids as
   `Vec<[u8; 32]>` so the verifier facade stays narrow (R-154).
   `cargo clippy --workspace --exclude rg-desktop --all-targets
   -- -D warnings` and `cargo test --workspace --exclude rg-desktop`
   green locally before push.

3. [x] **Phase 2 #3 pool-verifier integration tests** (this commit,
   2026-05-01) Two-tier integration test layout. Tier 1 in
   `services/pool-verifier/tests/phase2_eval.rs` exercises
   `policy::evaluate_dynamic_phase2` end-to-end against controlled
   `MempoolSnapshot` values built via the `MempoolView::install_at`
   injection seam. Tier 2 in `services/pool-verifier/tests/phase2_tcp.rs`
   spawns the real pool-verifier binary via `CARGO_BIN_EXE_pool-verifier`,
   stands up an in-process axum mock that answers `getrawmempool` over
   JSON-RPC, and round-trips `TemplatePropose` plus `TemplateVerdict`
   envelopes through the listener. Tier 2 tests are `#[ignore]` so the
   default `cargo test --workspace` stays fast for the pre-commit
   checklist; run with `cargo test -p pool-verifier --test phase2_tcp
   -- --ignored`. Three scenarios shipped: happy path full overlap
   emits Agreed, fabrication path above 4% emits
   `v2_invariant_mempool_tolerance_exceeded`, and the fail-stale
   state machine cycles `Fresh -> Stale -> Degraded` driven by
   `install_at` rather than `tokio::time::pause` because
   `mempool_view::unix_ms_now` reads `SystemTime::now` directly.
   Per-tx detail mode test plus the deeper bitcoind-RPC-unavailable
   end-to-end test fall to #3.5 below because both depend on wiring
   that has not landed yet.

3.5. [x] **Phase 2 #3.5 per-tx detail wiring plus fail-stale
   end-to-end** (this commit, 2026-05-01) Per-tx detail wired via
   the minimum-protocol-surface interpretation: `[policy.mempool]
   per_tx_detail = true` flips
   `check_invariant_shield_inner` from emitting up to
   `SAMPLE_UNKNOWN_CAP` (10) representative txids to emitting
   every unknown txid in the canonical `sample=[…]` field of
   the `V2InvariantMempoolToleranceExceeded` rejection detail
   string. Wire format stays 1:1 (one TemplateVerdict per
   accepted TemplatePropose); no new `ShieldOutcome` variant,
   no ingress writer change, no dashboard format change, no new
   metric. The original ADR text named multi-verdict-per-template
   as one option but landing the smaller-blast-radius path keeps
   the gateway-to-verifier protocol contract stable. New pure
   helper `policy::format_mempool_tolerance_detail` factors the
   detail-string formatting so Tier 1 tests can prove the cap
   bypass with synthetic data without a multi-tx fixture.

   Kill-the-mock fail-stale Tier 2 test wired in
   `tests/phase2_tcp.rs::phase2_tcp_kill_the_mock_drives_view_to_degraded`.
   `MockState` gains an `always_fail` `AtomicBool` companion to
   the existing single-shot `fail_next`. Test boots with
   `max_stale_secs = 3` for fast Degraded transition, sends a
   TemplatePropose under fresh view (asserts accept), flips
   `always_fail = true`, waits 8 seconds for the view to cross
   `2 * max_stale_secs` into Degraded, sends another
   TemplatePropose, asserts the verdict still accepts (Phase 1
   fall-through), then curls the public `/metrics` endpoint via
   raw HTTP/1.1 and asserts `verifier_phase2_degraded_total >= 1`
   confirming the operator alert path fires. Closes the
   bitcoind-RPC-unavailable scenario originally listed under
   Phase 2 #3.

4. [ ] **Phase 2 #4 documentation** Draft this ADR-003 (done as
   part of this design pass). Add a Phase 2 stub section to
   ADR-002 that cross-links here. Update
   `docs/three-mode-architecture.md` with a Phase 2 paragraph
   under the existing Invariant Shield section explaining the
   Class M check and the fail-stale state machine. Update
   `docs/deployment-runbook.md` with the eight new policy keys
   and the bitcoind RPC credential pattern. Update the
   `verifier_shield_skipped_total` metric description in the
   metrics export to mention the new `verifier_phase2_*`
   metrics. The public veldra-site reason code total 91 → 95
   sweep is gated on the website redesign per task #43.

5. [ ] **Phase 2 #5 lessons closure** Add R-168 (or next free
   number) to `docs/lessons.md` capturing any new patterns
   surfaced during Phase 2 implementation. Likely candidates:
   tokio polling-loop shutdown patterns, fail-stale state
   machine testing patterns, regtest bitcoind harness
   reuse pattern.

6. [x] **Phase 2 #6 production observation (Setup A axis closed)**
   Staged-validation plan: Setup A smoke against the local
   docker-compose shadow stack runs first to validate the wiring;
   Setup B/C real soak against an operator-controlled mainnet
   bitcoind earns the launch claim. **Setup A closeout: PASS,
   2026-05-28T03:34:06Z, 25-day cumulative window.** Counters
   delta from baseline (2026-05-02T10:52:28Z): 103,389 Class M
   checks evaluated, **0 rejections**, 471 degraded events at a
   steady 0.76 events per hour (rate stayed constant across the
   full window, environmental noise traced to macOS Power Nap
   DarkWake cycles per the T+3 diagnostic, see DEVLOG 2026-05-05).
   Skipped equals degraded (471), confirming the abstain-on-degraded
   design: every degraded window cleanly skipped Class M rather
   than emitting a false rejection. 28 stale templates (0.027% of
   total) within design tolerance. Earlier checkpoints: T+1 PASS
   2026-05-03 (3940 templates, 0 rejections, 10 degraded from a
   single startup race filed as PB-13); T+3 PASS 2026-05-05
   (10031 templates, 0 rejections, 67 degraded with Power Nap
   correlation diagnosed). T+5 and T+7 spot checks were never
   manually executed; the cumulative metric counters captured a
   stronger 25-day signal than the original 7-day plan called for.
   **Setup B is operational** (self-hosted VPS mainnet node, shadow
   soak T+0 2026-06-08T02:54:22Z, wraps 2026-06-15); **Setup C remains
   open** (runs once a design partner pool signs on). Both gate the
   launch claim until a clean week lands. Acceptance
   criteria for both remain: zero false positives at the 4% default
   threshold across the full week. If the bar is not met under
   real-bitcoind flow, tune the default threshold downward toward
   2% before any v2.0 launch announcement that names Phase 2 as
   live. See TESTLOG CL-38 closeout, BIZLOG 2026-05-27 setup-a-wrap
   entry, and DEVLOG 2026-05-27 for the 25-day cumulative summary.

7. [x] **Phase 2 #7 v3.x precursor markers** (this commit,
   2026-05-01) DEVLOG entry captures the v3.x upgrade path:
   `[policy.mempool] per_tx_detail = true` already emits the
   full unknown txid list per rejected template, providing
   per-tx granularity for downstream selfish-mining detection
   without any v3.x protocol change. The
   `verifier_mempool_view_size` and
   `verifier_phase2_checks_total{result}` metrics set up
   per-template aggregation that selfish-mining detection
   consumes as a time series. v3.x design begins from the
   shipped Phase 2 surface, no migration cost beyond enabling
   per-tx detail mode in operator policy.

## Notes

This ADR is the design output of EXECLOG D-18 (2026-04-29).
Implementation begins after this document is reviewed and accepted.
Phase 2 #1 through Phase 2 #4 are the next four engineering
bucket commits, sequenced to ship Phase 2 in 3 to 4 sessions.

R-118 reason code stability commitment: the four new
`v2_invariant_mempool_*` strings are canonical from the moment they
land in `rg-consensus` and propagate through `rg-protocol` and
`reservegrid-common`. No renames after Phase 2 #1 ships.

Cross-references:

- ADR-002 Invariant Shield scope and Phase 1 design.
- EXECLOG D-15 (parser choice), D-16 (Phase 1 #4b criticality
  tiering), D-17 (regtest fixture sourcing), D-18 (Phase 2
  architecture forks, this ADR's source).
- BIZLOG 2026-04-29 (post-Phase-2 website redesign reservation).
- Task #43 (veldra-site redesign trigger).
- PRODUCTION_BLOCKERS PB-9 (Independent Consensus Re-derivation;
  Phase 2 closes the trust maturity gap that PB-9 names).
