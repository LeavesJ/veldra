# Runbook: Phase 2 Shadow-Mode Soak (one week)

**Audience:** Veldra operator running the v2.0 launch gate (currently solo founder).
**Frequency:** One-time pre-launch gate per major release that ships changes to the Class M shield. Re-run on tolerance threshold tuning or after any reason-code-emitting change to `services/pool-verifier/src/policy.rs` Phase 2 path.
**Blast radius if botched:** The launch announcement names Phase 2 as live without the empirical backing the ADR-003 #6 acceptance criterion demands. Operators that adopt v2.0 may see false-positive rejections on real templates and lose blocks. Cost is reputational plus revenue. Mitigation is to delay the announcement, tune `[policy.mempool] tolerance_pct` downward, and re-soak.

## When to Run This Runbook

| Trigger | Severity | Window |
|---|---|---|
| Pre v2.0 launch announcement | Must run | One full week before the announcement date |
| `[policy.mempool] tolerance_pct` default change | Must run | Before the change ships in a release |
| Material change to the Class M code path (`check_invariant_shield_with_mempool`, `mempool_view::evaluate`, `bitcoind_rpc::get_raw_mempool`) | Must run | Before the next launch announcement |
| Operator deploys to a different bitcoind release (e.g. Core 27 → 28) | Should run | Within two weeks of the deploy |
| Routine quarterly health check | May run | Anytime, opportunistic |

## Acceptance Criterion (ADR-003 #6)

Zero false positives at the `tolerance_pct = 4.0` default across one full week of shadow-mode operation against an operator bitcoind. A false positive is any verdict where the shield emits `v2_invariant_mempool_tolerance_exceeded` against a template that downstream evidence shows was real.

**The evidence is captured at rejection time, not reconstructed afterwards (PB-40).** When the Class M check would reject, the verifier asks bitcoind directly about the specific unknown transactions and writes the answer to the verdict's `mempool_adjudication` field. Read that field. The intuitive procedure of re-querying the txids later is not merely weaker, it is **wrong in the dangerous direction**: the mempool tail churns within minutes, so week-old records return "absent" for transactions that were present all along, and the review concludes every rejection was a true positive. See the T+7 Wrap-Up and the PB-40 amendment in `docs/ADR-003-mempool-ground-truth.md`.

**What this criterion does and does not establish.** On a deployment where the template source and the verifier read the same bitcoind, which is Setup B, Class M is structurally incapable of a true positive. `FP_total == 0` is therefore exactly the right bar for that topology, but it validates *"the check does not cry wolf"*, NOT *"the check catches attacks"*. Detection evidence requires an independent bitcoind.

If the bar is not met, tune `tolerance_pct` downward toward `2.0` and re-soak before any v2.0 launch announcement names Phase 2 as live.

## Prerequisites

- **The template sender must ship `raw_block_hex` on every `TemplatePropose`.**
  Class M lives inside the Invariant Shield, which is skipped entirely when
  the field is absent (`verifier_shield_skipped_total` counts the skips). A
  soak whose senders omit the field validates the mempool view
  infrastructure but never runs a single tolerance comparison, making the
  false-positive criterion vacuous. Verify at T+0:
  `verifier_shield_skipped_total` must stay at zero while verdicts climb.
  (Template-manager ships the field from Phase 1b. Mainnet raw blocks run
  1.5 to 8 MB of hex; the internal line budget `MAX_INTERNAL_LINE_BYTES` was
  already raised protocol-wide to 20 MiB in PB-19, so no operator action is
  needed. Both the verifier ingress and the gateway read side enforce that
  budget before buffering and drop a peer that exceeds it.)
- **Metric semantics from the PB-18 build onward:** `phase2_checks_total`
  counts only templates whose evaluation actually reached Class M; templates
  that skip the shield increment nothing (older builds mislabeled them
  `agreed`). `phase2_degraded_total` likewise increments only when a
  template reaches Class M against a Degraded view. Do not mix baselines
  taken on a pre-PB-18 binary with deltas from a PB-18 binary.
- A pool-verifier instance running in **`VELDRA_MODE=observe`**, NOT `shadow`. Observe reports verdicts without enforcing, which is what this soak needs, and it persists them to disk. **`shadow` does NOT persist verdicts at all** (`DeployMode::persist_verdicts` is `Observe | Inline`, `services/reservegrid-common/src/mode.rs:46`), so `append_verdict_to_disk` returns early and `data/verdicts.log` is never written. Under shadow the entire PB-40 adjudication record — the authoritative and only durable evidence this soak's acceptance criterion reads — silently does not exist. `docker-compose.setup-b.yml` already defaults to `observe`; do not flip it to shadow for the soak despite this runbook's historical name.
- An operator-controlled bitcoind reachable from the verifier over JSON-RPC. Mainnet, not regtest.
- `[policy.mempool] enforce = true` plus `tolerance_pct = 4.0` plus `poll_interval_secs = 10` plus `max_stale_secs = 60` in the verifier's `policy.toml`.
- `VELDRA_BITCOIND_RPC_USER` plus `VELDRA_BITCOIND_RPC_PASS` set in the verifier's environment.
- Grafana or equivalent dashboard wired to the verifier's `/metrics` endpoint with the four Phase 2 metrics surfaced: `verifier_phase2_checks_total{result}`, `verifier_phase2_degraded_total`, `verifier_mempool_view_age_seconds`, `verifier_mempool_view_size`.
- Verdict log file (`./data/verdicts.log` by default) accessible for forensic spot checks.
- A way to cross-reference the pool's accepted blocks against the soak window (block explorer, pool's own block-found feed).

## Pre-Soak Setup (T minus 1 day)

1. Verify the verifier policy file is exactly the production-default Phase 2 config. Diff against `config/policy.toml` and `deploy/policy-prod.toml`. Any drift gets reconciled before T+0; a soak against a non-default config does not retire the launch gate.
2. Confirm bitcoind connectivity. From the verifier host:
   ```sh
   curl --user "$VELDRA_BITCOIND_RPC_USER:$VELDRA_BITCOIND_RPC_PASS" \
     -d '{"jsonrpc":"1.0","id":"soak","method":"getrawmempool","params":[false]}' \
     -H 'content-type: application/json' \
     "$VELDRA_BITCOIND_RPC_URL" | jq '.result | length'
   ```
   Expect a non-zero integer within a few hundred ms. If the call hangs, fix the bitcoind path before T+0.
3. Baseline the four Phase 2 counters and gauges. Run:
   ```sh
   scripts/phase2-baseline.sh
   ```
   The script captures `verifier_phase2_checks_total{result}` for each label, `verifier_phase2_degraded_total`, `verifier_mempool_view_age_seconds`, and `verifier_mempool_view_size` from the verifier's `/metrics` endpoint and writes them to `./data/phase2-baseline.json`. Override the metrics URL with `--metrics-url http://...` or set `VELDRA_PHASE2_METRICS_URL`; override the output path with `--out PATH`. Paste the script's stdout into DEVLOG so the T+7 deltas have an audit trail. Do not delete `phase2-baseline.json` mid-soak; doing so resets the soak math.
4. Confirm the verdict log file is rotating or is large enough to hold a week of records. Estimate: 200 templates per second peak times 86400 seconds per day times 7 days times 1 KB per record = ~120 GB upper bound. Most pools see far less; size the volume for the upper bound or wire log rotation.
5. Tail the verifier's stderr to make sure no startup warnings about the Phase 2 path are present:
   ```sh
   journalctl -u pool-verifier --since "5 min ago" | grep -iE 'phase2|mempool'
   ```
   Lines that say `Phase 2 mempool view polling task started` are healthy. Lines that say `Phase 2 Class M check disabled` mean the policy gate did not pass; fix before T+0.

## T+0 Start

1. Note the start timestamp in DEVLOG to the second. Soak window runs T+0 through T+7 days exactly.
2. Take a fresh metrics snapshot. Compare to the baseline; everything should still be at the baseline values plus normal incremental drift from the polling task.
3. Spot-check the dashboard once at T+0 plus 1 hour to make sure the verifier is consuming templates and emitting verdicts. `verifier_phase2_checks_total{result="agreed"}` should increment monotonically. If `result="rejected"` ticks above zero in the first hour, treat as Day 1 spot check (next section); the soak is already producing signal.

## T+1 / T+3 / T+5 Spot Checks

Three checks at days 1, 3, 5 plus the wrap-up at day 7. Each spot check follows the same procedure. At each, the operator records the four counter deltas since T+0 plus a hand-counted false-positive review.

1. Snapshot the four counters and list candidate FPs in one shot:
   ```sh
   scripts/phase2-spot-check.sh | tee -a docs/DEVLOG.md.spotchecks
   ```
   The script reads `./data/phase2-baseline.json`, fetches current values from `/metrics`, prints the five counter deltas plus the two live gauges, and dumps every Class M `v2_invariant_mempool_tolerance_exceeded` rejection from `./data/verdicts.log` (last 50 by default; bump with `--max-rejections N`). Output is human readable; pipe to a file so the DEVLOG entry inherits the same shape across all four spot checks. The script also flags a `delta_degraded > 0` warning so an operator-environment fault during the soak is impossible to miss.
2. For each rejection, read the `mempool_adjudication` object on its verdict record in `./data/verdicts.log`. **This is the authoritative evidence and it is the only evidence that survives.** Do not re-query the txids with `bitcoin-cli`; see the warning below. Three outcomes, keyed off `outcome`:
   - **`upheld`:** bitcoind was asked at rejection time, the block walk COMPLETED, and it held the transactions in neither its mempool nor any block at or above the template's height. This is a genuine candidate detection. Cross-reference against the pool's block-found feed for corroboration and log to DEVLOG with the `still_absent` count and `still_absent_sample`. An `upheld` can only be emitted when the walk was complete; an incomplete one is reported `lookup_failed` instead, so this label never over-claims.
   - **`lookup_failed`:** the lookup could not be completed, so this rejection is **UNADJUDICATED**. It is not a false positive and it is not a detection. Count it separately, read `lookup_error_kind`, and treat a nonzero total as a soak-validity problem (see T+7 step 4), never as a pass. Four kinds, all meaning "nobody established anything":
     - `rpc_error` — bitcoind answered badly. Fix the node.
     - `deadline` — bitcoind was too slow for the 2s budget. Measured headroom is comfortable at a 94k mempool and thin at 200k, so a run of these during a fee spike means the whole-mempool fetch is too expensive at that size.
     - `empty_mempool` — `getrawmempool` returned an empty set, which cannot establish that anything is absent.
     - `block_walk_incomplete` — the mempool half succeeded but the block walk errored or truncated, so the mined case could not be ruled out. Read `block_walk_shortfall`.
   - **`block_walk_shortfall` on any record:** `mined` is a FLOOR, not a count, and `still_absent` may include transactions that were in fact mined. Check `blocks_scanned` against the blocks the walk owed, which is `tip_height - height + 1`.
   - **`withdrawn` never appears here.** A rejection the second-chance lookup overturned is not emitted as a rejection at all; it lands as an accepted verdict with the adjudication attached, and it is counted by `verifier_phase2_second_chance_total{outcome="withdrawn"}`. A nonzero withdrawn count is the mempool-view staleness of PB-40 being caught in the act. It is expected and healthy, not a failure.

   > **Do NOT adjudicate a rejection by re-querying its txids afterwards.** PB-40 measured this directly: txids sampled from a rejection 35 minutes old came back 9 of 9 ABSENT from bitcoind, not because they were ever invalid but because they are the churny tail that gets RBF-replaced or evicted from a 93k mempool within minutes. A T+7 review that re-queries week-old records will find every transaction absent and conclude every rejection was a true positive. **The obvious procedure returns a confidently incorrect answer**, which is why the bitcoind answer is captured at rejection time and written to the verdict record instead.

   > If `data/verdicts.log` is stale or missing while rejections are climbing, the durability write is failing and the soak has no evidence. The verifier logs `verdict durability write FAILED` on every such attempt; on the Setup B node the file was root-owned and every append failed silently for weeks. Check ownership against the verifier's uid before trusting any wrap-up.
3. If the script reported a `delta_degraded > 0` warning, the bitcoind RPC went away at some point during the window. Check verifier logs for `mempool refresh failed` or `mempool refresh timed out`. Investigate the bitcoind side; this is operator-environment noise, not a Phase 2 bug. Resolve before continuing the soak; if the degraded counter grows beyond a few percent of the polling cadence, the soak window is invalid and resets to T+0 once bitcoind is healthy.
4. Watch `verifier_mempool_view_age_seconds` in the script's output. Should stay well under `max_stale_secs = 60` outside of degraded windows. Sustained values above 30 indicate bitcoind RPC latency growing; investigate.
5. Note the script output plus the FP count plus any anomalies in DEVLOG before the next spot check.

## T+7 Wrap-Up

1. Final counter snapshot. Run `scripts/phase2-spot-check.sh | tee -a docs/DEVLOG.md.spotchecks` one more time at T+7. The deltas at this run cover the full soak window.
2. `FP_total` is `delta_rejected` where the verdict's `mempool_adjudication.outcome` is `upheld`, corroborated against the block-found feed. It is read from the durable verdict records and the counters, NOT hand-counted from a fresh `bitcoin-cli` sweep.
3. Compute the false-positive rate against total Class M checks:
   ```
   total_classM_checks = delta_agreed + delta_recovered + delta_rejected + delta_stale + delta_skipped
   fp_rate = FP_total / total_classM_checks
   ```
   `delta_recovered` is `verifier_phase2_checks_total{result="recovered"}`: first-pass tolerance breaches that bitcoind overturned. They are Class M checks that ran, so they belong in the denominator, and they emitted no rejection, so they never belong in `FP_total`.
4. Apply the acceptance criterion:
   - `FP_total == 0` AND `delta_degraded` was zero or rapidly resolved each time AND `verifier_phase2_second_chance_total{outcome="lookup_failed"} == 0`: **PASS**. Phase 2 is launch-ready at the 4% default. Document in DEVLOG plus open a TESTLOG CL entry that closes the soak.
   - `FP_total > 0`: **FAIL**. Do not announce Phase 2 as live. Proceed to "If Fail" below.
   - `lookup_failed > 0`: **INVALID SOAK for those verdicts.** A rejection nobody could adjudicate is not evidence in either direction, so it can neither pass nor fail the gate. Fix the bitcoind reachability cause and re-run the window. Recording these as passes is the exact failure mode this soak exists to avoid.
   - Bitcoind degradation longer than a few hours total during the week: **INVALID SOAK**. Reset to T+0 once the operator-environment fault is fixed.
5. **State the scope of what passed.** On a single-bitcoind deployment such as Setup B, the template-manager and the verifier read the same node, so Class M is structurally incapable of a true positive and this soak validates *"the check does not cry wolf"*, NOT *"the check catches attacks"*. Write that sentence into the DEVLOG entry verbatim. A clean soak on this topology is not detection evidence and must never be cited as such. See the PB-40 amendment in `docs/ADR-003-mempool-ground-truth.md`.
6. On PASS, update `docs/PRODUCTION_BLOCKERS.md` PB-9 status to mark Phase 2 #6 as resolved with the soak result line. Update `docs/ADR-003-mempool-ground-truth.md` action item #6 from `[ ]` to `[x]` with the result and pointer at the DEVLOG entry.

## If Fail (FP_total > 0)

Open Phase 2 #6.5 as a new bucket. The bucket has three subtasks.

1. **Forensic review of every confirmed FP.** Goal is to find the common pattern. Two likely root causes:
   - The operator's bitcoind has slower transaction propagation than the network median, so templates legitimately reference txs the local mempool has not seen yet. Mitigation: tune `tolerance_pct` upward to absorb the propagation latency, or move bitcoind closer to the network (more peers, better transit).
   - The verifier's mempool view is stale at the moment of check (clock between `last_refresh_unix_ms` and `now`). Mitigation: drop `poll_interval_secs` from 10 to 5 so the view refreshes more often.
2. **Tune the default downward.** Bump `[policy.mempool] tolerance_pct` from 4.0 toward 2.0 in increments. Each tuning decision lands as its own commit on `services/pool-verifier/src/policy.rs` with the updated default plus an accompanying `docs/lessons.md` note covering the regtest-vs-mainnet tuning gap. R-154 governs: defaults must be safe for production mainnet day-one.
3. **Re-soak from T+0.** A tuned default starts the clock fresh. Soak runs another full week against the new threshold.

## Pass / Fail Criteria Summary

| Outcome | Action |
|---|---|
| Zero confirmed FPs across the week | Mark Phase 2 #6 done, ship the launch announcement |
| One or more confirmed FPs | Open Phase 2 #6.5, tune `tolerance_pct`, re-soak |
| Bitcoind degraded > few hours total | Soak is invalid, fix bitcoind, restart from T+0 |
| Verifier crashed or restarted during the soak | Soak is invalid, root-cause the crash, restart from T+0 |
| Operator changed `tolerance_pct` mid-soak | Soak is invalid, restart from T+0 with the chosen value |

## Where to Document

- **DEVLOG.md (private):** baseline counters at T-1, T+0 timestamp, every spot-check snapshot, every confirmed/ambiguous FP with sample reason_detail, T+7 final counters and FP rate, pass/fail decision.
- **TESTLOG.md (private):** new CL entry closing the soak with the four-counter delta table and the FP rate. Cross-link the DEVLOG session.
- **PRODUCTION_BLOCKERS.md (private):** on PASS, mark PB-9 Phase 2 #6 as resolved.
- **ADR-003-mempool-ground-truth.md (tracked):** on PASS, mark action item #6 as `[x]` with the result. On FAIL, leave `[ ]` and add a Phase 2 #6.5 line item.
- **lessons.md (private):** any new pattern that surfaced during the soak (e.g., a tuning-trigger threshold formalization, a bitcoind-latency rule, a verdict-log-rotation requirement) lands as the next free R-XXX rule.

## Cross-References

- ADR-003 Mempool Ground Truth and Enforcement Policy, action item #6.
- ADR-002 Invariant Shield, Phase 2 cross-reference section.
- `docs/three-mode-architecture.md` Phase 2 Class M check section.
- `docs/deployment-runbook.md` `[policy.mempool]` keys table.
- R-154 (defaults must be safe for production mainnet day-one), R-155 (canonical reason_code stability), R-167 (numeric-default refresh sweeps).
