# ReserveGrid OS v2.0.0-rc1 — Invariant

Release candidate for the Invariant chapter of ReserveGrid OS. Two architectural layers ship above the v1.1.0 policy plus gateway plus observability baseline: independent consensus re-derivation against raw block bytes, and mempool ground truth via direct bitcoind RPC. The verifier no longer trusts what the template declares about itself; it re-derives the consensus quantities and cross-references the tx set against the network mempool. 22 canonical `v2_invariant_*` reason codes formalize the new check classes. Final v2.0.0 ships once the production observation cycle completes cleanly.

## Independent consensus re-derivation

Phase 1 of the Invariant chapter introduces `rg-consensus`, a new workspace crate that wraps `rust-bitcoin` behind a narrow facade. Five public re-derivation functions cover the consensus quantities every template carries: `re_derive_coinbase_value`, `re_derive_template_weight`, `re_derive_merkle_root`, `re_derive_witness_commitment`, `count_sigops`. Plus class accessors over `ParsedBlock`: `template_txids`, `total_sigops`, `coinbase_sigops`, `bip34_height`, `parse_block`. The facade boundary is intentionally narrow so neither the gateway nor the verifier imports `rust-bitcoin` directly; every call goes through `rg-consensus`.

The pool-verifier's invariant shield runs the re-derivation chain against every template that ships `raw_block_hex`. Three check classes execute in order: Class S (structural validity, single-deserialize against `ParsedBlock`), Class D (declared-versus-derived consistency, comparing the template's stated values against what re-derivation produces), and the Phase 2 Class M check described below. The shield short-circuits on the first violation and emits a canonical `v2_invariant_*` reason code with full policy context.

18 canonical reason codes ship at this layer. 10 critical and high-criticality variants are wired and tested today (`v2_invariant_coinbase_value_mismatch`, `v2_invariant_coinbase_height_mismatch`, `v2_invariant_merkle_root_mismatch`, `v2_invariant_witness_commitment_missing`, `v2_invariant_witness_commitment_mismatch`, `v2_invariant_sigops_mismatch`, `v2_invariant_coinbase_sigops_mismatch`, `v2_invariant_template_weight_mismatch`, `v2_invariant_tx_count_mismatch`, `v2_invariant_coinbase_bip34_missing`, plus `v2_invariant_decode_failed` as the catch-all). 7 belt-and-suspenders Tier 3 reason codes (`v2_invariant_coinbase_script_length`, `v2_invariant_coinbase_output_count`, `v2_invariant_weight_exceeds_max`, `v2_invariant_sigops_exceed_max`, `v2_invariant_nontcb_null_prevout`, `v2_invariant_header_version_low`, `v2_invariant_duplicate_tx`) are reserved at the facade layer and ship wired in Phase 1.5 after the production observation cycle.

The shield ships against a regtest segwit block fixture for tampering tests. Every wired reason code has a corresponding tamper test that mutates the block bytes at a known offset, re-derives the merkle root via the test helper, and asserts the shield emits the expected reason code on the tampered template.

## Mempool ground truth

Phase 2 of the Invariant chapter adds Class M to the shield's check chain. The verifier holds its own bitcoind JSON-RPC client (`reqwest` over basic auth, configurable poll interval) and maintains a `MempoolView` populated by a tokio task that calls `getrawmempool` every `[policy.mempool] poll_interval_secs` seconds (default 10). Every template's non-coinbase txids are cross-referenced against the live view. When the unknown-tx ratio exceeds `[policy.mempool] tolerance_pct` (default 4.0, operator-tunable), the shield rejects with `v2_invariant_mempool_tolerance_exceeded` and an aggregate detail listing up to `SAMPLE_UNKNOWN_CAP = 10` representative txids. Per-tx detail mode (`[policy.mempool] per_tx_detail = true`) expands the sample list to every unknown txid for forensics; wire format stays 1:1 (one TemplateVerdict per accepted TemplatePropose).

The view runs a fail-stale state machine. `MempoolState::Fresh` while the last refresh is within `max_stale_secs` (default 60). `Stale` between `max_stale_secs` and `2 * max_stale_secs`. `Degraded` past `2 * max_stale_secs`, where the Class M check is skipped and templates fall through to Phase 1 behavior. Every verdict served while Degraded increments `verifier_phase2_degraded_total` so dashboards can alert on extended bitcoind RPC outages. The view also reads `Degraded` when not yet primed (before the first successful poll); operators should expect a small bounded number of degraded events at boot until the polling task installs the first snapshot.

4 canonical reason codes ship at this layer: `v2_invariant_mempool_disagreement`, `v2_invariant_mempool_tolerance_exceeded`, `v2_invariant_mempool_unavailable`, `v2_invariant_mempool_view_stale`. Plus `v2_invariant_mempool_tx_unknown` for the per-tx detail mode taxonomy. Cross-crate string parity is enforced by the `ALL_CODES` length assertion (22 in `rg-consensus::ConsensusViolation`, 37 in `rg-protocol::VerdictReason`, 95 in `reservegrid-common::ReasonCode` after dedup of the shared `internal_error`).

Config fields at `[policy.mempool]`: `enforce` (default false), `tolerance_pct`, `poll_interval_secs`, `max_stale_secs`, `per_tx_detail`, `rpc_url`, `rpc_user`, `rpc_pass`. All optional with defaults so older `policy.toml` files continue to load unchanged. Prometheus metrics: `verifier_phase2_checks_total{result}` (counter vec, result in agreed/rejected/skipped/stale), `verifier_phase2_degraded_total` (counter), `verifier_mempool_view_age_seconds` (gauge), `verifier_mempool_view_size` (gauge).

## Reason code taxonomy expansion

The canonical reason code surface grows from 91 to 95. The 22 new `v2_invariant_*` strings join the existing 73 non-shield codes (15 verdict reasons covering policy plus system plus advisory, and 59 gateway codes, with one `internal_error` shared between the verdict and gateway sides per the existing dedup convention). All 22 v2_invariant_* codes carry explicit `#[serde(rename = "v2_invariant_...")]` attributes per R-155 because the digit-to-uppercase boundary in `V2InvariantXxx` is exactly the case `rename_all = "snake_case"` does not reliably handle. The cross-crate string parity guard is the standard `grep -rE "v2_invariant_[a-z0-9_]+" services/rg-protocol services/reservegrid-common services/rg-consensus` plus the `ALL_CODES.len()` assertions in each crate's tests.

## Configuration surface expansion

The operator-tunable surface grows from 61 to 69 TOML keys. The eight new keys all live at `[policy.mempool]` and are listed under the Mempool ground truth section above. The pool-verifier reads `VELDRA_BITCOIND_RPC_PASS` first and falls back to `[policy.mempool] rpc_pass` only if the env var is unset, so production deploys can keep the bitcoind RPC password out of `policy.toml` on disk. Pool-verifier and template-manager share the same `VELDRA_BITCOIND_RPC_USER` plus `VELDRA_BITCOIND_RPC_PASS` env var pair when they share a bitcoind backend.

## Two-tier integration test layout

A new pair of integration test files in `services/pool-verifier/tests/` covers the Phase 2 Class M code paths. `phase2_eval.rs` is the Tier 1 file: synthesizes `MempoolSnapshot` values directly via the new `MempoolView::install_at` test seam and exercises `policy::evaluate_dynamic_phase2` end-to-end across happy path, fabrication path, below-threshold unknowns, view state machine cycling (Fresh / Stale / Degraded driven by `install_at` timestamps), Degraded view skip, Phase 2 disabled fall-through, and detail-format consistency. `phase2_tcp.rs` is the Tier 2 file: spawns the real `pool-verifier` binary via `CARGO_BIN_EXE_pool-verifier`, stands up an in-process axum mock that answers `getrawmempool` over JSON-RPC, and round-trips `TemplatePropose` plus `TemplateVerdict` envelopes through the listener. Three subprocess scenarios shipped: happy path, fabrication path, refresh-mid-flight, plus a kill-the-mock fail-stale scenario that flips an `always_fail` toggle on the mock and asserts `verifier_phase2_degraded_total` increments after the polling task crosses into Degraded.

The Tier 2 tests are `#[ignore]`d so the default `cargo test --workspace` stays fast for the pre-commit checklist. CI runs them via a dedicated step (`cargo test -p pool-verifier --test phase2_tcp -- --ignored`) so subprocess-spawned regressions are caught on every push and PR.

A static `BOOT_MUTEX: tokio::sync::Mutex<()>` serializes the racy port-discovery section across parallel Tier 2 tests because the kernel can hand the same `127.0.0.1:0` port to two parallel callers between drop-and-spawn-verifier windows; the mutex eliminates the resulting flakiness while keeping post-boot work parallel.

## Synthetic getrawmempool in rg-feed-adapter

The `docker-compose.shadow.yml` dev stack uses `rg-feed-adapter` to impersonate bitcoind. The adapter previously supported `getblocktemplate` and `getmempoolinfo` only; the verifier's Phase 2 polling task calls `getrawmempool`, which the adapter answered with `-32601 method not found`. The mempool view never primed and Class M was skipped on every template, breaking the demo of the full v2.0 product to first-time evaluators using the shadow stack.

The adapter now answers `getrawmempool` synthetically by extracting every `txid` field from the latest `blocktemplate.transactions` array and returning them as an array of hex strings matching bitcoind's `getrawmempool verbose=false` wire shape. The synthetic mempool is a superset of (or equal to) the latest template's tx set by construction, so the verifier's Phase 2 Class M check always Agrees against the shadow stack. Real mainnet mempool divergence is the production-soak concern; this is wiring smoke for the shadow product demo. `SUPPORTED_METHODS` test constant grows from 2 to 3 entries; CL-20 updated from 7 to 9 tests covering the txid extraction happy path plus the missing-transactions-field defensive path.

## Documentation

ADR-002 (Invariant Shield Phase 1) and ADR-003 (Mempool Ground Truth Phase 2) are tracked in `docs/`. The three-mode architecture document gains a Phase 2 paragraph covering the Class M check and the fail-stale state machine. The deployment runbook gains a `[policy.mempool]` configuration section with the eight new keys plus the bitcoind RPC credential pattern. A new operator runbook at `docs/runbooks/phase2-shadow-soak.md` covers the one-week production observation cycle: pre-soak setup, T+0 baseline capture, T+1/T+3/T+5 spot-check workflow including the FP cross-reference procedure against the pool's block-found feed, T+7 wrap-up with the FP rate computation and pass/fail decision, and the if-fail Phase 2 #6.5 forensic-review bucket. Two helper scripts at `scripts/phase2-baseline.sh` and `scripts/phase2-spot-check.sh` collapse the runbook's manual `curl` plus `jq` queries into one invocation per check, with a baseline JSON written to `./data/phase2-baseline.json` for delta computation.

A v3.x design sketch at `docs/v3-selfish-mining-design-sketch.md` captures the upgrade path the Phase 2 data shape (per-tx detail mode plus the four Phase 2 metrics) sets up for selfish-mining detection downstream. Preliminary, not an ADR; the formal v3.x design begins after v2.0 launches and at least one quarter of operator deployment data is available.

## What does not ship in this RC

This is a release candidate; the final v2.0.0 tag waits on the production observation cycle.

- Phase 1.5 Tier 3 belt-and-suspenders invariants (7 reason codes reserved at the rg-consensus facade layer, not yet wired into the shield's call chain). Ships in Phase 1.5 after the v2.0 production observation cycle completes cleanly.
- Per-tx detail mode emission as multi-verdict-per-template (current per_tx_detail mode expands the existing single TemplateVerdict's detail field; multi-verdict emission is a protocol surface change reserved for a later increment).
- Empirical zero-false-positive validation against real mainnet templates. Synthetic validation has shipped; real mainnet propagation-latency calibration on the 4% default `tolerance_pct` is the gap the production observation cycle closes. Final v2.0.0 ships post-cycle.

## Validation status

Setup A wiring smoke soak runs against the local docker-compose shadow stack. T+0 declared 2026-05-02; T+1 PASS captured 2026-05-03 (3940 templates Class-M-evaluated, zero rejections, ten degraded events attributable to a single startup race). T+3, T+5, T+7 wrap to follow on the runbook schedule. Setup B/C real-bitcoind soak runs once the mainnet bitcoind subscription opens; final v2.0.0 ships after a clean week of Setup B/C operation.

The desktop app version in `services/rg-desktop/tauri.conf.json` deliberately stays at `1.1.0` for this RC. Bumping the desktop version would auto-update existing v1.1.0 desktop installs to the release candidate via the Tauri updater; that auto-push happens with the final v2.0.0 tag, not the RC. RC consumers run `cargo build --release` from the tagged source or pull the GitHub Release prerelease artifact.

## Breaking changes

None at the RC layer. The 22 new `v2_invariant_*` reason codes are additive across rg-consensus, rg-protocol, and reservegrid-common; existing dashboards keying off the v1 reason codes continue to work. The 8 new `[policy.mempool]` keys are all optional with defaults, so older `policy.toml` files load unchanged with Phase 2 disabled (`[policy.mempool] enforce = false`). Operators opt in to Phase 2 by setting `enforce = true` and the bitcoind RPC credentials.

## Known limitations

- Production observation cycle in progress; final v2.0.0 launch claim ("validated against real mainnet templates over a multi-week observation window") gated on Setup B/C completion.
- Phase 1.5 Tier 3 invariants reserved at the facade layer but not yet wired into the shield's call chain. Phase 1.5 lands after the v2.0 production observation cycle.
- Verifier counter metrics export with a double `_total_total` suffix (`verifier_phase2_checks_total_total`, `verifier_phase2_degraded_total_total`, etc.) because the prometheus-client crate auto-appends `_total` to counter exports per OpenMetrics convention while the registration code already includes `_total` in the registered name. Filed as PB-12 for a workspace-wide fix on its own commit. Soak helper scripts at `scripts/phase2-baseline.sh` and `scripts/phase2-spot-check.sh` accept either single or double suffix to keep operator workflows working until PB-12 lands.
- Mempool view served as Degraded before the first install primes the view at boot. Bounded impact (single ~10-second window per stack restart). Filed as PB-13 for the post-launch cleanup pass; two resolution options on the table (compose `depends_on: ... condition: service_healthy` versus a verifier-side guard that holds verdicts until first install).
- Auto-update gating on the desktop app keeps the RC off the production updater channel; desktop installs continue to run v1.1.0 until the final v2.0.0 tag ships.

## Upgrade from v1.1.0

1. Pull the `v2.0.0-rc1` tag and rebuild: `cargo build --workspace --exclude rg-desktop --release`.
2. Verify the pre-commit gates: `cargo fmt --all --check && cargo clippy --workspace --exclude rg-desktop --all-targets -- -D warnings && cargo test --workspace --exclude rg-desktop`.
3. Add `[policy.mempool]` configuration to `config/policy.toml` if running observe or inline mode against a real bitcoind. Keep `[policy.mempool] enforce = false` to defer Phase 2 enablement until you are ready to point the verifier at a bitcoind RPC endpoint.
4. Set `VELDRA_BITCOIND_RPC_USER` plus `VELDRA_BITCOIND_RPC_PASS` env vars on the pool-verifier service when enabling Phase 2. The verifier prefers the env var to the on-disk `[policy.mempool] rpc_pass` value to keep secrets out of `policy.toml`.
5. Rebuild and deploy: `docker compose build && docker compose up -d`.
6. Verify Phase 2 health on the metrics endpoint: `curl -s http://localhost:8081/metrics | grep -E 'verifier_phase2|verifier_mempool_view'`. Expect `verifier_phase2_checks_total{result="agreed"}` to increment, `verifier_mempool_view_age_seconds` to stay under 60, and `verifier_mempool_view_size` to be non-zero.
7. Operators running the canonical one-week production observation cycle: capture the T-1 baseline via `scripts/phase2-baseline.sh` and follow the runbook at `docs/runbooks/phase2-shadow-soak.md`.

See [CHANGELOG.md](https://github.com/LeavesJ/ReserveGrid-OS/blob/main/CHANGELOG.md) for the complete list of changes.
