# ADR-002: v2.0 Invariant Shield Scope and Parser Choice

**Status:** Accepted, implemented (Phase 1 shipped 2026-04-21 through
2026-04-29; Phase 1.5 Tier 3 completion shipped 2026-07-22 — all 18
checks wired). **Amended 2026-08-02 by PB-20: the ratified table of 18
is widened to 19. Amended again 2026-08-03 by PB-21: widened to 20.**
See "Amendment 1" and "Amendment 2" below; the 18-count statements in
the sections underneath record what was originally ratified and are
left as written.
**Date:** 2026-04-21
**Deciders:** Jarron (Veldra, Inc.)

## Amendment 2 (2026-08-03, PB-21): a 20th invariant

No bound on coinbase value existed anywhere in the workspace. The
ratified table has a Class D check that the declared `coinbase_value`
equals the value re-derived from `raw_block_hex`, and Tier 3 ceilings
for weight and sigops, but nothing that asked whether the value itself
is a number Bitcoin can represent. `raw_block_hex` is fully attacker
controlled, so the coinbase output values are attacker chosen `u64`s,
and `re_derive_coinbase_value` added them with an unchecked `sum()`.

Added: `v2_invariant_coinbase_value_exceeds_max`, a Tier 3 ceiling
check asserting every coinbase output value and their total sit inside
Bitcoin `MoneyRange` of 0 through `MAX_MONEY` (2,100,000,000,000,000
sats). It is the third member of the ceiling family, beside
`check_weight_max` and `check_sigops_max`, and runs directly after
them. Core applies `MoneyRange` per output and again on the total, and
both halves are needed: one output above `MAX_MONEY` overflows nothing,
and a total above `MAX_MONEY` can be built from individually legal
outputs. This **widens** v2.0 rather than completing it.

**Severity, as executed.** Two distinct failures, both reproduced
before the fix on a template whose coinbase carries two outputs of
`0xC000_0000_0000_0000`.

Under the debug and CI profiles, where overflow checks are on, the
unchecked `sum()` panicked at `core/src/iter/traits/accum.rs:204` with
"attempt to add with overflow", inside `check_invariant_shield`. That
is a remote denial of service: a peer stops the verifier on demand
with one template.

Under release, where the same addition wraps, `re_derive_coinbase_value`
returned `Ok(9223372036854775808)`, exactly 2^63. An attacker who
declares that number matches the Class D re-derivation, and
`check_invariant_shield` returned `Agreed` on a block paying about
1.8e19 sats. The same `Agreed` was returned, in both profiles, for the
two non-overflowing shapes: a single output of `MAX_MONEY + 1`, and two
in-range outputs totalling above `MAX_MONEY`. Agreeing to a block that
causes consensus rejection is the harm class the Tier 1 table in
`docs/three-mode-architecture.md` labels CRITICAL.

What was NOT demonstrated, and is not claimed here: any path to stolen
funds. Real-world exposure stays bounded by Core rejecting such a block
outright, since `CheckTransaction` enforces the same `MoneyRange` this
check ports. That is a bound on blast radius, not a reason to grade the
defect low, and it does not bound the panic at all: the denial of
service lands on the verifier before any node sees the block.

**Where the arithmetic lives.** `re_derive_coinbase_value` now folds
with `checked_add` and reports a total that does not fit `u64` as this
same violation, since such a total is by construction far above
`MAX_MONEY`. It deliberately does not apply the `MoneyRange` ceiling
itself: that belongs to the Tier 3 check, which keeps the ceiling
reachable through the shield rather than shadowed by an earlier
rejection. Saturating instead of failing was considered and rejected,
because `u64::MAX` is a number the attacker can also declare, so the
Class D comparison would agree again. Reusing
`v2_invariant_decode_failed` was also rejected: the bytes decode fine,
and labelling a value overflow a decode failure lies to every dashboard
that keys off `reason_code`.

Count impact, superseding both the Phase 1 figures below and Amendment
1: `VerdictReason::ALL` 38 to 39, `ReasonCode::ALL` 96 to 97,
`ConsensusViolation::ALL_CODES` 23 to 24, `ConsensusViolation::ALL` 24
to 25, Tier 3 array 8 to 9, invariants wired 19 of 19 to 20 of 20.

## Amendment 1 (2026-08-02, PB-20): a 19th invariant

The ratified table below defines three accessors that derive a
"non-coinbase" set with `skip(1)`: `non_coinbase_sigops`,
`non_coinbase_tx_weight`, and `check_non_coinbase_null_prevout`, plus a
`tx_count`-minus-one convention in the verifier. `skip(1)` means "not
the first transaction". It means "not the coinbase" only if `txdata[0]`
is a coinbase, and no check in the ratified set asserted that.
`raw_block_hex` is fully attacker controlled on the wire, so all four
rested on an unchecked assumption.

Added: `v2_invariant_coinbase_prevout_not_null`, a Tier 3 structural
check asserting `txdata[0]` carries exactly one input whose previous
output is null. This **widens** v2.0 rather than completing it.

**Severity, corrected.** The first draft of this amendment called
exploit value "low" and said this was "not the closure of an urgent
hole". The T2 review falsified that by execution. With
`check_coinbase_null_prevout` removed from the Tier 3 array,
`check_invariant_shield` returns `Agreed` on a template whose
`txdata[0]` spends a real outpoint, which is a block Bitcoin Core
rejects in `CheckBlock` with `bad-cb-missing` because
`CTransaction::IsCoinBase` is exactly the one-input-with-null-prevout
predicate this check ports. Agreeing to a block that causes consensus
rejection is the harm class the Tier 1 table in
`docs/three-mode-architecture.md` labels CRITICAL, alongside
`v2_invariant_coinbase_height_mismatch`. "A validating node would
catch it" is not a mitigation for the shield, because catching what
would otherwise reach a node is the shield's whole purpose.

Two claims from that first draft survive and are kept, because both
are still true and both bound the damage. `total_sigops` is the
attacker's own field, so the sigop-accounting consequence in
particular hands him nothing he could not declare directly. The Tier 3
ceiling `check_sigops_max` measures the whole block against the
consensus limit and never depended on index 0 being labelled
correctly, so that ceiling was not blind.

What was NOT demonstrated, and is not claimed here: any path to stolen
funds, and any exploit that survives a validating node. Real-world
exposure stays bounded by Core rejecting such a block outright. That
is a bound on blast radius, not a reason to grade the defect low.

Count impact, superseding the Phase 1 figures below:
`VerdictReason::ALL` 37 to 38, `ReasonCode::ALL` 95 to 96,
`ConsensusViolation::ALL_CODES` 22 to 23, `ConsensusViolation::ALL` 23
to 24, Tier 3 array 7 to 8, invariants wired 18 of 18 to 19 of 19.

## Context

v1.x of ReserveGrid OS validates block templates at two layers. The gateway
enforces protocol invariants (Noise handshake, SV2 frame decode, share timing,
rate limits, WAL durability). The pool-verifier enforces policy invariants on
fields the template-manager already computed (`coinbase_value`, `total_fees`,
`tx_count`, `template_weight`, `total_sigops`, `coinbase_sigops`,
`max_weight_ratio`, `max_template_age_ms`). No layer independently re-derives
consensus critical values from the raw transaction data. The verifier trusts
the template-manager's arithmetic. If the template-manager or the miner
supplies a template with an incorrect `coinbase_value` or a malformed witness
commitment, v1.x has no defense. This is the scope of the v2.0 Invariant
Shield initiative advertised in our roadmap deck.

Invariant Shield means pool-verifier gains the ability to parse the raw block
template bytes, re-derive the consensus critical values, and reject any
template whose declared values disagree with the re-derived values. The
checks stay additive. Existing policy checks remain. The new checks are
expressed as new reason codes under a `v2_invariant_*` naming prefix so
dashboards and exports pick them up without schema migration.

The core engineering decision that blocks v2.0 is how pool-verifier parses
the consensus layer. Two paths are live:

1. Take a dependency on the `bitcoin` crate (rust-bitcoin) and use its
   `Block`, `Transaction`, `TxMerkleNode`, and `WitnessCommitment` types.
2. Build an in-tree parser sized to exactly the fields Invariant Shield
   needs, shipped as a new `rg-consensus` crate inside the workspace.

The workspace currently has zero rust-bitcoin exposure. `sha2 = "0.10"` is
used in five crates but no consensus or script parsing crate is present.
Adopting rust-bitcoin adds roughly 40 transitive crates, including
`secp256k1` (which links libsecp256k1 via FFI) and `bitcoin_hashes`. The
workspace has `unsafe_code = "deny"` at the Rust lint level. The deny
applies to in-tree code, not to transitive dependencies that compile with
their own lint config, so FFI in `secp256k1` would not trip the gate.
`deny.toml` already allows MIT, Apache-2.0, BSD, and ISC, which covers the
rust-bitcoin family.

R-148 in `docs/lessons.md` is compound and both halves apply here. The
Copy-to-non-Copy half says rust-bitcoin types like `Transaction` and `Txid`
are non-Copy and every use site must clone before ownership transfer if the
value is needed later. The Docker stub pattern half says any workspace crate
whose symbols become source-level dependencies for a service must be copied
with real source into every Dockerfile that selectively stubs `Cargo.toml`.
Adding a new `rg-consensus` crate or adding rust-bitcoin to pool-verifier
forces a full audit of the pool-verifier and rg-auth Dockerfiles.

The non-negotiable around reason codes applies here too. Every Invariant
Shield check must ship with a canonical snake_case `reason_code` string that
exists in `reservegrid-common::ReasonCode::ALL` and survives round-trip
across the gateway to verifier NDJSON, the Prometheus exports, the CSV
exports, the Grafana dashboards, and the public docs. The `ALL` length
assertion in `services/reservegrid-common/src/reason.rs` is the source of
truth that must advance with each new check.

## Decision

**Adopt rust-bitcoin behind a narrow facade in a new `rg-consensus` crate
scoped exclusively to pool-verifier. Keep rust-bitcoin types out of the
cross-service NDJSON wire, out of the shared `rg-protocol` crate, and out of
the gateway. Define 18 new consensus invariant checks in Phase 1 under a
`v2_invariant_*` reason code prefix, all additive.**

The facade design is the load-bearing constraint. `rg-consensus` exposes
plain Rust types (`u64`, `[u8; 32]`, `Vec<u8>`) and functions that return
`Result<(), ConsensusViolation>`. No rust-bitcoin type crosses the crate
boundary. The verifier sees exactly the same canonical data it sees today
plus a few extra precomputed checks. Dashboards and exports key off the new
reason codes without any schema migration.

Phase 1 ships the check set that closes the stated v1.x gaps. Later phases
may add probabilistic checks (fee bands, historical behavior) which are out
of scope for this ADR.

## Options Considered

### Option A: rust-bitcoin behind a facade in `rg-consensus` (proposed)

A new workspace crate `services/rg-consensus` owns the rust-bitcoin
dependency. It exposes a small, type-stable API:

```rust
pub fn re_derive_coinbase_value(raw_block: &[u8]) -> Result<u64, ConsensusViolation>;
pub fn re_derive_template_weight(raw_block: &[u8]) -> Result<u64, ConsensusViolation>;
pub fn re_derive_merkle_root(raw_block: &[u8]) -> Result<[u8; 32], ConsensusViolation>;
pub fn re_derive_witness_commitment(raw_block: &[u8]) -> Result<Option<[u8; 32]>, ConsensusViolation>;
pub fn count_sigops(raw_block: &[u8]) -> Result<u32, ConsensusViolation>;
```

pool-verifier calls these functions and compares the results to the
template-manager declared values. On mismatch it emits the matching
`v2_invariant_*` reason code.

| Dimension | Assessment |
|---|---|
| Complexity | Moderate. New crate, ~500 LOC of adapter code, tests against known vectors. |
| Cost | One dep (rust-bitcoin) plus ~40 transitive crates. Build time increase measurable but bounded. |
| Correctness | High. rust-bitcoin is the reference Rust implementation, widely audited and production tested across the ecosystem. |
| Team familiarity | Moderate. Jarron has touched rust-bitcoin for hashing utilities elsewhere, not for full parse. |
| Supply chain | Acceptable. MIT licensed, present in cargo-deny allowlist, `cargo vet` will need fresh audits for rust-bitcoin, bitcoin_hashes, secp256k1. |
| Customer impact | Zero. The facade keeps rust-bitcoin invisible to operators. |
| Time to Phase 1 ship | 3 to 5 weeks. |

**Pros**

- The consensus rules we re-derive are the same ones the Bitcoin Core and
  rust-bitcoin communities have stress tested for a decade. We do not want
  to be the 23rd team to reinvent varint parsing, segwit marker handling,
  or witness commitment derivation and shake out the edge cases in
  production.
- Upstream fixes for new soft forks land without engineering cost on our
  side. If a future soft fork changes witness commitment rules, we bump the
  rust-bitcoin version and our checks remain correct.
- The facade boundary preserves R-13 (reason codes canonical) and prevents
  rust-bitcoin types from leaking into the NDJSON wire. A later switch to a
  different parser costs only the `rg-consensus` implementation, not the
  verifier, gateway, dashboards, or docs.
- secp256k1 FFI is transitive and already in scope for other Bitcoin
  tooling. `unsafe_code = "deny"` still holds at the workspace level
  because the deny targets in-tree code. If a reviewer raises the
  transitive FFI surface, the answer is that libsecp256k1 has fewer known
  CVEs than any hand rolled replacement.

**Cons**

- Supply chain surface grows by ~40 transitive crates on pool-verifier.
  `cargo vet` exemptions need refreshing and a fresh audit pass is required
  before the v2.0 release.
- R-148 Docker stub pattern must be re-audited for pool-verifier and any
  service that compiles pool-verifier symbols transitively.
- Build time on cold cache goes up. Measured regression during Phase 1
  spike is acceptable budget (benchmark before merge).

### Option B: In-tree minimal parser in `rg-consensus`

Hand write a Bitcoin block parser covering only the fields Invariant Shield
needs. Parse the 80 byte header, iterate the transaction array, parse each
transaction with segwit marker and flag handling, track weight and sigops
as we go, hash the coinbase and non coinbase transactions to derive the
merkle root, locate the witness commitment in coinbase output scripts.

| Dimension | Assessment |
|---|---|
| Complexity | High. Consensus-critical parsing is well documented but historically error prone. BIP-141 segwit serialization, BIP-144 wtxid merkle, BIP-341 Taproot sighash, sigops legacy vs witness accounting. |
| Cost | Zero new dependencies. |
| Correctness | Medium initially, high after exhaustive test vectors. We would need to replicate rust-bitcoin's Bitcoin Core cross-check test vectors ourselves. |
| Supply chain | Minimal addition. |
| Customer impact | Zero. |
| Time to Phase 1 ship | 10 to 14 weeks including cross-check test harness. |

**Pros**

- Zero new transitive crates. `deny.toml` and `cargo vet` state is
  unchanged.
- `unsafe_code = "deny"` applies end to end. No FFI anywhere in the
  consensus path.
- Attack surface is bounded by our own code, which we audit continuously
  through CI clippy lints and `cargo deny`.
- Works offline for customers who run procurement review over the full
  dependency graph and find libsecp256k1 FFI unacceptable.

**Cons**

- Consensus parsing is a category of software where subtle bugs are
  expensive. The historical record of failed alternative implementations is
  not encouraging. Our reason to exist is verification integrity. Shipping
  a homegrown parser that silently disagrees with Bitcoin Core at an edge
  case is a brand ending event.
- Every future soft fork adds parsing work that rust-bitcoin's maintainers
  would absorb for free under Option A.
- The cross-check test harness (running our parser against rust-bitcoin's
  test vectors) effectively imports rust-bitcoin as a dev-dependency to
  validate ourselves. We gain no supply chain benefit there.
- Timeline is 2 to 3 times longer than Option A.

### Option C: Delegate to bitcoind via RPC

Have pool-verifier send the raw template to bitcoind's `getblocktemplate` or
`testblockvalidity` RPC and rely on bitcoind to answer.

| Dimension | Assessment |
|---|---|
| Complexity | Low in code, high in operations. |
| Cost | Operator must run bitcoind with template validation RPC enabled and expose it to pool-verifier. |
| Correctness | Maximum. bitcoind is Bitcoin. |
| Customer impact | Negative. Many pool operators run bitcoind without this RPC enabled. |
| Time to ship | 2 weeks. |

**Pros**

- Perfect consensus match with Bitcoin mainnet.
- Tiny code footprint.

**Cons**

- Makes pool-verifier dependent on operator-managed bitcoind reachability,
  which conflicts with the "pool-verifier is a standalone service" product
  promise.
- RPC round trip adds latency to the verdict budget which v1.x spent a
  release hardening to sub 100 ms.
- `testblockvalidity` is not always enabled on production pool nodes.
  Adoption friction.
- Does not solve the case where operators want shadow mode without
  bitcoind (S-1 promise).
- Does not give us in-process reason codes. Errors come back as bitcoind
  strings that we would still need to map to canonical reason codes.

### Option D: Defer Invariant Shield to v3.0

Keep v2.0 at a smaller scope and push consensus re-derivation to v3.0.

| Dimension | Assessment |
|---|---|
| Complexity | None. |
| Cost | Reputational. Invariant Shield is the v2.0 story on the pitch deck. |
| Customer impact | Negative for pilots who specifically cite consensus re-derivation as their evaluation criterion. |

**Cons**

- v2.0 becomes an incremental release with no new headline. Loss of sales
  narrative.
- Pushes the risk reduction deeper into the product roadmap.
- The v1.x verifier already tells customers what it does and does not
  check. Extending that frontier is the v2.0 purpose.

## Trade-off Analysis

Option A wins on every dimension that matters at our stage. Correctness is
the reason customers pay us. rust-bitcoin is the cheapest way to inherit a
decade of consensus correctness work done by the Bitcoin ecosystem. The
facade pattern isolates the dependency so we are never forced to leak
rust-bitcoin types into the gateway or the wire protocol, which keeps R-13
(canonical reason codes) intact and preserves our ability to swap
implementations later without a cross-service migration.

Option B buys us a smaller supply chain at the cost of 2 to 3 times longer
Phase 1 timeline and a higher risk of consensus divergence at the long
tail of edge cases. Our company is too small to absorb a consensus parsing
bug in production. The economics favor buying mature code.

Option C trades code complexity for operational complexity we cannot force
on operators. Shadow mode would stop working. Latency would regress. The
dependency on operator-managed bitcoind contradicts the standalone
verifier promise we sell today.

Option D abandons the roadmap narrative without solving any engineering
problem. It only delays the same decision.

## Consequences

**What becomes easier**

- Phase 1 development can start as soon as the crate scaffold and facade
  types are approved. rust-bitcoin has working examples for every check we
  plan.
- Adding Phase 2 checks (BIP specific rules, soft fork handling) becomes a
  matter of calling a new rust-bitcoin API, not parsing new bytes.
- Customer procurement teams recognize rust-bitcoin as a known quantity.
  The security review conversation is shorter.
- Brand promise tightens. We move from "policy verification" to "policy
  verification plus consensus re-derivation" without rewriting the
  marketing posture.

**What becomes harder**

- `cargo vet` must re-audit rust-bitcoin, bitcoin_hashes, secp256k1, hex,
  hashes_core, and the transitive set before v2.0 ships. Allocate one week
  for the audit pass.
- Docker builds that stub the workspace will break on cold build until
  R-148 is satisfied for pool-verifier and any transitively-affected
  service. The CI workflow needs an explicit matrix step that builds
  pool-verifier without stubs.
- Release notes and docs need a new section explaining Invariant Shield
  and the v2_invariant_* reason code family.

**What we will need to revisit**

- If libsecp256k1 FFI becomes a procurement blocker for a regulated
  customer, we revisit Option B for that customer as a feature-gated
  build.
- If rust-bitcoin breaks its public API in a major version bump, the
  facade absorbs the churn but `rg-consensus` needs version pinning
  discipline.
- If Phase 2 requires streaming parse of very large witness data, revisit
  the facade signature to accept `&mut dyn Read` instead of `&[u8]`.

## Phase 1 Check Set and Reason Code Allocation

Each check below ships as a new `GatewayReason` variant? No. These are
verifier-layer policy outcomes, so they land in `VerdictReason` and are
mirrored into `ReasonCode::ALL`. Count impact: 18 new verdict codes, which
advances `VerdictReason::ALL.len()` from 15 to 33 and `ReasonCode::ALL.len()`
from 73 to 91. The `internal_error` shared string dedup still applies.

Proposed canonical strings (snake_case, `v2_invariant_` prefix):

| Check | Canonical reason_code |
|---|---|
| Coinbase value disagrees with re-derived | `v2_invariant_coinbase_value_mismatch` |
| Declared `template_weight` disagrees with re-derived | `v2_invariant_template_weight_mismatch` |
| Merkle root does not match re-derived | `v2_invariant_merkle_root_mismatch` |
| Witness commitment missing when segwit txs present | `v2_invariant_witness_commitment_missing` |
| Witness commitment value does not match re-derived | `v2_invariant_witness_commitment_mismatch` |
| Total sigops disagrees with re-derived | `v2_invariant_sigops_mismatch` |
| Coinbase sigops disagrees with re-derived | `v2_invariant_coinbase_sigops_mismatch` |
| Transaction count disagrees with re-derived | `v2_invariant_tx_count_mismatch` |
| Coinbase script length outside BIP-34 constraints | `v2_invariant_coinbase_script_length` |
| Coinbase output count outside protocol constraints | `v2_invariant_coinbase_output_count` |
| Coinbase missing height push (BIP-34) | `v2_invariant_coinbase_bip34_missing` |
| Coinbase height push disagrees with header height | `v2_invariant_coinbase_height_mismatch` |
| Block weight exceeds consensus maximum | `v2_invariant_weight_exceeds_max` |
| Block sigops exceed consensus maximum | `v2_invariant_sigops_exceed_max` |
| Non coinbase transaction carries null prevout | `v2_invariant_nontcb_null_prevout` |
| `txdata[0]` is not a coinbase (Amendment 1, PB-20) | `v2_invariant_coinbase_prevout_not_null` |
| Coinbase output value or total outside MoneyRange (Amendment 2, PB-21) | `v2_invariant_coinbase_value_exceeds_max` |
| Block header version below active soft fork floor | `v2_invariant_header_version_low` |
| Duplicate transaction in block body | `v2_invariant_duplicate_tx` |
| Raw block bytes fail to deserialize | `v2_invariant_decode_failed` |

All 18 codes are additive. No existing code changes name. The
`reason_code_all_constant_length` test bumps from 73 to 91. The
`gateway_all_constant_covers_every_variant` test is unaffected (these are
verifier checks, not gateway checks). A new
`verdict_all_constant_covers_every_variant` style assertion is added to
`rg-protocol` if one is missing.

## Action Items

1. [x] Scaffold `services/rg-consensus` crate. Add to workspace members.
   MIT license header. Single public module (the crate root `lib.rs`).
   Landed 2026-04-21. Five facade functions return
   `ConsensusViolation::NotImplemented`. `ALL`, `ALL_CODES`,
   `as_reason_code()`, and six unit tests present.
2. [x] Add `bitcoin = "=0.32.x"` as a direct dep in
   `rg-consensus/Cargo.toml`. Exact pin per R-131. Blocked on action
   item 7 (`cargo vet` audit pass) so that the dep lands and the audit
   lands in the same patch set.
   Landed 2026-04-21. Pinned to `=0.32.8` with `default-features =
   false` and only `std` plus `rand-std` enabled. `cargo vet
   regenerate exemptions` absorbed the new graph; `cargo vet` exits
   0; `cargo deny check` advisories, licenses, sources all pass.
   Bans flags the expected `bitcoin` 0.31.3 plus 0.32.8 duplicate
   from the `bitcoincore-rpc 0.18` transitive, tracked under PB-11.
   Workspace `cargo clippy -- -D warnings` and `cargo test` remain
   green.
3. [x] Implement the five facade functions listed in Option A. Unit test
   each against rust-bitcoin's own test vectors plus at least two
   historical mainnet blocks. Blocked on action item 2.
   Landed 2026-04-21. `re_derive_coinbase_value`,
   `re_derive_template_weight`, `re_derive_merkle_root`,
   `re_derive_witness_commitment`, and `count_sigops` call through to
   rust-bitcoin 0.32.8 (`Block::weight().to_wu()`,
   `Block::compute_merkle_root`, `Block::witness_root`,
   `Script::count_sigops_legacy`) with no upstream type crossing the
   facade. Phase 1 ships legacy only sigop counting; accurate BIP-141
   sigop cost is carried as a `TODO` in the doc comment. Six unit
   tests cover garbage bytes surfacing `DecodeFailed` on every
   function, mainnet genesis 50 BTC coinbase, genesis weight and
   merkle root parity against `genesis_block(Network::Bitcoin)`, no
   witness commitment on pre segwit genesis, and a legacy sigop
   sanity bound. Historical mainnet block vectors (post segwit
   activation) are tracked as a test vector follow up under action
   item 11 (CL-28). `cargo build -p rg-consensus`,
   `cargo test -p rg-consensus`,
   `cargo clippy -p rg-consensus --all-targets -- -D warnings` all
   green on the landing machine.
4. [x] Wire `rg-consensus` into pool-verifier as a new policy layer that
   runs after the existing `check_basic_validity` pass. Emit the new
   reason codes on mismatch. Landed 2026-04-21. Wire schema decision:
   inline `raw_block_hex: Option<String>` on `TemplatePropose` over a
   sidecar channel, chosen for atomicity with the verdict, backward
   compatibility via `#[serde(default)]` matching the existing optional
   field pattern, and simpler failure semantics (no cross channel join).
   Senders that omit the field silently skip the shield and are counted
   in the new `verifier_shield_skipped_total` metric so dashboards can
   track Phase 1 rollout coverage. Phase 1 scope: coinbase value always,
   template weight when the sender supplied it. The remaining 16
   invariants (merkle root, witness commitment, per tx weight, sigops,
   target meet, header bind, coinbase script prefix, duplicate txid,
   BIP-34 height, witness reserved value, witness present without
   commitment, txid derivation, segwit marker) need follow up wire
   additions (`declared_merkle_root`, `declared_witness_commitment`,
   `declared_sigop_cost`) tracked under action item 4b. `ShieldOutcome`
   is decoupled from `VerdictReason` through
   `consensus_violation_to_verdict_reason`, exhaustive over every
   `ConsensusViolation` variant including the `NotImplemented` sentinel
   which maps to the internal error code so a facade gap never
   surfaces as an accept. Shield runs strictly after
   `check_basic_validity`, `check_template_constraints`, and
   `check_safety_constraints`, so earlier policy verdicts short
   circuit first and the shield never overrides an existing rejection.
   Thirteen unit tests cover round trip sanity, skipped path, bad hex,
   garbage bytes, coinbase mismatch, weight mismatch, happy path,
   template_weight=None path, ordering with safety warnings, the
   `shield_skipped` field wiring in `evaluate_dynamic`, reject emitted
   as `VerdictReason`, and mapping distinctness across all 18 variants.
   Tests use a hardcoded `GENESIS_RAW_HEX` constant rather than a
   `bitcoin` dev dependency so pool-verifier's dep graph stays narrow
   and exercises the facade during tests (R-154 precedent).
5. [x] Add the 18 `VerdictReason` variants to `rg-protocol` and mirror
   them into `reservegrid-common::ReasonCode`. Bump the `ALL` length
   assertions. Landed 2026-04-21. `VerdictReason::ALL.len()` is 33,
   `ReasonCode::ALL.len()` is 91, explicit `#[serde(rename)]` on every
   v2_invariant_* variant to pin canonical strings regardless of
   serde's snake_case algorithm.
6. [ ] Update pool-verifier Dockerfile and rg-auth Dockerfile per R-148
   to include pool-verifier source rather than a stub (audit transitive
   imports, do not guess).
7. [x] Add `cargo vet` audit entries for rust-bitcoin, bitcoin_hashes,
   secp256k1, hex, hex-conservative. Regenerate exemptions.
   Landed 2026-04-21 via `cargo vet regenerate exemptions`. Phase 1
   accepts exemptions in place of full audits per the ADR rationale;
   full audits tracked as a Phase 2 item.
8. [x] Add `cargo deny` check pass verifying no new banned-license
   transitives. Update `deny.toml` comment trail if a known advisory
   needs exemption with a version target.
   Landed 2026-04-21. Advisories, licenses, sources all pass. Bans
   surfaces one new expected duplicate (`bitcoin` 0.31.3 from
   `bitcoincore-rpc 0.18` plus the new direct 0.32.8 in
   `rg-consensus`), warn level only, zero denies. Filed under PB-11
   alongside the pre existing duplicate set.
9. [ ] Benchmark cold build time delta. Report in DEVLOG. If more than 3x
   current, open a tech debt item for workspace precompilation.
10. [x] Update `docs/three-mode-architecture.md` with the new v2.0
    Invariant Shield layer between template ingress and verdict emission.
    Landed with Phase 1 #4b; refreshed 2026-07-22 for the Phase 1.5
    Tier 3 completion (wired count 18 of 18).
11. [x] Update `docs/TESTLOG.md` with a new `CL-28: v2.0 Invariant
    Shield Re-derivation Agreement` claim covering all 18 checks against
    known mainnet blocks. CL-28 exists; historical mainnet vectors
    beyond genesis plus the regtest segwit fixture remain a follow up.
12. [x] Update `docs/PRODUCTION_BLOCKERS.md` with `PB-9: Consensus
    re-derivation parser` tracking Phase 1 delivery.
13. [ ] Public documentation refresh: add the 18 new codes to the docs
    site reason code table, add the `v2_invariant_*` prefix to the
    reason code conventions section, bump hardcoded counts across
    `POSITIONING.md`, `ReserveGrid-OS-Founders-Guide.md`, and the
    veldra-site HTML and i18n JSON (R-106 plus Tier 1 #3 pattern).
    Still open as of 2026-07-22: site i18n bundles claim 91 reason
    codes in four keys across three locales (canonical is 95), and
    the wired-count copy needs the 18 of 18 refresh.
14. [ ] If Phase 1 ships, add R-154 to `docs/lessons.md` capturing the
    facade discipline: "Consensus parsing library dependencies must enter
    the workspace through a single crate that exposes only plain Rust
    types across its API boundary. No upstream consensus types leak into
    wire schemas, NDJSON exports, or reason code definitions."
15. [x] Phase 1.5: implement and wire the seven Tier 3
    belt-and-suspenders checks (`coinbase_script_length`,
    `coinbase_output_count`, `weight_exceeds_max`,
    `sigops_exceed_max`, `nontcb_null_prevout`, `header_version_low`,
    `duplicate_tx`). Landed 2026-07-22: seven standalone check
    functions in `rg-consensus` (coinbase script-size bounds per
    Core's `bad-cb-length` rule, one-output floor, 4M WU ceiling,
    80k sigop-cost ceiling via the x4 legacy scale, null-prevout
    scan, BIP-65 version-4 floor, duplicate-txid set), wired into
    the shield after the Class D checks in ADR table order, first
    violation wins. Known residual Class S gap, false-negative
    direction only and pre-existing: Core's `bad-witness-nonce-size`
    rule is not fully mirrored (a commitment present with zero
    witnesses anywhere, or a coinbase witness stack that is not
    exactly one 32-byte element, can pass the shield while Core
    rejects). Tracked as a Phase 2 refinement. Seventeen new facade unit tests plus
    the pool-verifier wiring proof (genesis, a version-1 block, now
    rejects `v2_invariant_header_version_low`; happy path carried by
    the regtest segwit fixture). The same patch set fixed two shield
    fidelity gaps found in review: the witness commitment extractor
    now takes the highest-index match per BIP-141 (was first-match)
    and the commitment requirement scan counts coinbase witness data
    per Core's unexpected-witness rule (was non-coinbase only).

## Phase 2 (cross-reference)

Phase 2 closes the consistent-template-manager-tampering attacker class
(T3 in the formalized threat model) that Phase 1 leaves open. Phase 1's
shield catches internal raw_block tampering (T1) and TemplatePropose
versus bytes mismatches (T2) but cannot catch a tampered template that
is internally consistent by construction. Phase 2 adds an external view
of the network mempool that the verifier cross-checks every template's
transaction set against.

Full design including threat model formalization, four locked
architecture forks, four new `v2_invariant_mempool_*` reason codes,
eight new policy keys, four new metrics, and seven action items lives
in [ADR-003: Mempool Ground Truth and Enforcement
Policy](./ADR-003-mempool-ground-truth.md).

ADR-003 supersedes the open-ended Phase 2 mention in this document's
Context section. Implementation status as of 2026-04-30: Phase 2 #1
(four canonical reason codes) shipped in cac223c, and Phase 2 #2
(mempool view, bitcoind RPC client, polling task, Class M tolerance
check, four metrics, eight `[policy.mempool]` keys) shipped in e422bd6
plus the doc surface refresh in 5d1791e. Phase 2 #3 regtest
integration tests, Phase 2 #6 one-week shadow observation, and the
public veldra-site `91 → 95` reason code surface sweep remain open.
See ADR-003 Action Items for the live checkbox state.
