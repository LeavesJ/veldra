# PB-40 follow-up: make the second-chance lookup cost O(unknowns), not O(mempool)

Date: 2026-08-05
Status: APPROVED, not implemented
Surface: T2 (Class M reject decision + durable verdict evidence)
Depends on: `0caf6a1`, `7d891bc` on `claude/reservegrid-os-dev-c70b0d`

---

## Why

The PB-40 second-chance lookup asks bitcoind whether it holds the transactions
a stale mempool view did not, before a Class M rejection is allowed to stand.
It does that by fetching the **entire** mempool with `getrawmempool` and testing
set membership. That call was never measured before it shipped.

Measured 2026-08-05 against a synthetic mainnet-sized `getrawmempool`, three
runs each after a warm-up, over loopback:

| mempool size | `ask()` latency | headroom under the 2s deadline |
| ------------ | --------------- | ------------------------------ |
| 94,000       | 775-858 ms      | 58%                            |
| 200,000      | 1620-1648 ms    | 18%                            |
| 500,000      | exceeded        | fails                          |

94,000 is the live Setup B node today. These are **lower bounds**: the harness
is an in-process mock on loopback, so a real bitcoind's own work, the
concurrent 10-second poller fetching the same ~6 MB, and verifier CPU load all
eat further in.

Mainnet has exceeded 200k transactions during fee spikes. Those are exactly the
periods when `getblocktemplate` churns hardest and Class M rejections spike, so
the mechanism degrades to `lookup_failed` precisely when it is most needed. The
cost is tied to the wrong quantity: it scales with the mempool, when the work to
be done scales with the number of unknown transactions, which is typically a few
hundred and never depends on congestion.

## Goal and acceptance criterion

Make the lookup's cost proportional to the unknown set.

**Acceptance criterion, falsifiable:** lookup latency is flat across mempool
size. Re-run the same probe at 94k / 200k / 500k with a fixed N=187 unknowns
(the live `log_id=2952` case). Today that curve is 858 ms -> 1648 ms -> deadline
exceeded. After this change it must be approximately constant. Any residual
slope is a finding, not a rounding error.

Secondary: the change must not weaken any evidence property established by
`0caf6a1` and `7d891bc`. Specifically, it must remain impossible to emit
`upheld` on an incomplete answer.

## Non-goals

- The 10-second polling task is unchanged. It genuinely needs the whole set, and
  `bitcoind_rpc::get_raw_mempool` stays for it.
- `SECOND_CHANCE_DEADLINE` stays at 2s. It is derived from the
  template-manager's 4s verdict timeout
  (`services/template-manager/src/main.rs:1679`) and that has not changed.
- No fallback to the whole-mempool fetch if probing fails. That would be a
  second mechanism for one job; `getmempoolentry` has existed since Core 0.13.
- No new `[policy]` keys. The constants below are `const`, not knobs.

## Architecture

`SecondChance::ask()` changes signature. It currently takes only
`template_height` and returns two large sets for the caller to adjudicate.
Targeted probing requires it to know which transactions to ask about:

```rust
pub async fn ask(
    &self,
    template_height: u32,
    unknown: &[[u8; 32]],
) -> Result<BitcoindAnswer, SecondChanceError>
```

Four steps, in this order.

### 1. Degenerate-node guard

`getmempoolinfo` (~200 bytes). If `size < mempool_view::MIN_INSTALLABLE_MEMPOOL_SIZE`,
return `SecondChanceError::EmptyMempool`.

**This step is load-bearing and is the easiest thing in this design to lose.**
With per-txid probing, a bitcoind that is still loading `mempool.dat`, on the
wrong chain, or freshly restarted answers "not in mempool" for *every* txid,
which is byte-identical to "bitcoind genuinely knows none of them". That is the
empty-mempool false-evidence hazard, which the view install path closed at
`8a2a3c9` and the lookup closed at `7d891bc`, returning in a new costume.
Deleting the whole-mempool fetch silently deletes the existing floor check
unless this replaces it.

### 2. Block walk first

Unchanged from `7d891bc`: O(blocks), bounded by `template.block_height`,
producing `WalkCoverage::{Complete,Truncated,Failed}`. Subtract every txid it
found mined from the set still to be probed.

Running it first is a real optimisation, not just ordering. The worst case for N
is the **mined case**, where a block arrives between template construction and
the check and the template's entire transaction set leaves the mempool at once,
making N the whole template (~3000). The block walk resolves exactly that case
for the cost of one or two `getblock` calls, collapsing the probe set to near
zero. The common case (a few hundred freshly-arrived transactions) is unaffected
because the walk normally scans zero blocks.

One consequence to accept deliberately: a txid present in both a recent block
and the mempool now classifies as `Mined` rather than `InMempool`, where the
previous precedence was mempool-first. Both count as known, so the
withdraw/uphold decision is identical; only the evidence label differs. This can
only occur during a reorg.

### 3. Chunked `getmempoolentry`

Sequential JSON-RPC batches over the remaining unknowns, `MEMPOOL_PROBE_CHUNK`
per batch. Sequential rather than concurrent: Core's rpcworkqueue is shared with
the poller, and inducing "Work queue depth exceeded" is the documented trigger
for the block walk failing. This mechanism must not create the pressure that
breaks its own sibling.

### 4. Decide

Per the rule below.

## Per-txid probe semantics

Each batch item resolves three ways:

| Response                       | Verdict                    |
| ------------------------------ | -------------------------- |
| success (an entry object)      | `InMempool`                |
| error code `-5`                | definitively **absent**    |
| any other error, or no match   | `Unadjudicated` (new)      |

`-5` (`RPC_INVALID_ADDRESS_OR_KEY`, "Transaction not in mempool") is a genuine
negative answer and is better evidence than set membership in a snapshot,
because it is a direct per-transaction statement rather than an inference.

**Fail-safe against our own uncertainty.** The `-5` code is believed correct but
has NOT been verified against a real bitcoind from the development environment.
The design therefore treats only that exact code as absent and every unexpected
code as `Unadjudicated`. If the code is wrong, every probe becomes
`Unadjudicated`, which forces `lookup_failed` — loud and visible in
`verifier_phase2_second_chance_total`. It cannot degrade into "all absent",
which would fabricate detections. Verify the code against the node during
rollout and record the result; do not treat the belief as established.

## Decision rule

Generalising the rule from `7d891bc` rather than inventing a second one.

Two counts, kept **disjoint** so the durable record cannot be double-counted by
a reviewer:

- `still_absent` — probed and definitively **not** in the mempool, and not
  mined. Proven absent.
- `unadjudicated` — no usable answer. Proven nothing.

The decision uses their sum, named separately so the two ideas never get
conflated in code or in the record:

```
not_proven_known = still_absent + unadjudicated
```

Let `threshold` be the tolerance expressed in transactions.

- **Withdraw** when `not_proven_known <= threshold`. Safe under partial
  information: unadjudicated transactions are counted as absent, the pessimistic
  reading, so resolving them could only lower the count further. A fuller answer
  could never push a withdrawal back over the threshold.
- **`lookup_failed`** when `not_proven_known > threshold` **and** anything is
  incomplete: `unadjudicated > 0`, or a block walk that was `Truncated` or
  `Failed`. Upholding asserts bitcoind knew none of them, and an incomplete
  answer cannot support that assertion.
- **Uphold** only when `not_proven_known > threshold`, `unadjudicated == 0`,
  and the walk was `Complete`. In that case `not_proven_known == still_absent`
  by construction, so `upheld` is always reported against proven absences only.

Incompleteness can block an `upheld`; it can never block a `withdrawn`. This is
the same invariant `7d891bc` established for block-walk coverage, now covering
mempool probes too.

## Batch mechanics

**Match responses by `id`, never by position.** JSON-RPC permits a server to
return batch responses in any order. Core happens to preserve order, but relying
on that is the class of assumption that produced the three defects fixed in
`7d891bc`. Each request in a chunk carries a numeric `id`; results are resolved
through it. A missing or duplicated `id` makes that txid `Unadjudicated`.

A position-zip bug here would misattribute *every* verdict in the chunk by one
and would be invisible to any test whose mock replies in order, so the reordered
case is a required test, not an optional one.

Implementation notes:

- `JsonRpcResponse` does not currently deserialize `id`. Add it.
- Add `call_batch` beside the existing `call` in `bitcoind_rpc.rs`. The single
  `call` stays; three callers already depend on it.
- `MEMPOOL_PROBE_CHUNK = 250`, derived: a response stays near 150 KB, the worst
  realistic template (~3000 unknowns) bounds to 12 sequential round trips, and
  each chunk boundary is a deadline checkpoint. A `const`, not a config key.
- A JSON-RPC batch is a *single* HTTP request in Core and occupies one work
  queue slot regardless of size. Chunking buys bounded memory and deadline
  checkpoints, not queue relief.

## Data model

`BitcoindAnswer` keeps its shape to hold churn down; the existing pure
`adjudicate()` and most of its unit tests survive.

```rust
pub struct BitcoindAnswer {
    /// Unknowns bitcoind confirmed it holds RIGHT NOW. Populated by
    /// targeted probes, no longer a whole-mempool snapshot, hence the
    /// rename from `fresh_mempool`.
    pub present_in_mempool: HashSet<[u8; 32]>,
    /// Unknowns whose probe returned no usable answer.
    pub unadjudicated: HashSet<[u8; 32]>,
    pub recent_block_txids: HashSet<[u8; 32]>,
    pub blocks_scanned: u32,
    pub block_walk_truncated: bool,
    pub tip_height: Option<u32>,
    pub block_walk_shortfall: Option<String>,
}
```

`classify()` gains one arm, ordered: present -> mined -> unadjudicated -> absent.

`TxAdjudication` gains `Unadjudicated`. `Adjudication` gains `unadjudicated: u32`,
and `MempoolAdjudicationRecord` carries it into the durable NDJSON so a T+7
reviewer can see that a count was not fully established.

`still_absent` **narrows** in meaning: it was "not found", it becomes "proven
absent", with the unproven cases moving to `unadjudicated`. This is a deliberate
narrowing of an existing field rather than a new one, because the old meaning
was the thing that let an unestablished count read as evidence. The runbook's
outcome table says `still_absent` is what supports a detection claim, and after
this change that is true rather than approximately true. Records written before
this change carry the old, broader meaning; the field is only ever populated
alongside `outcome`, and a pre-change record is identifiable by the absence of
`unadjudicated`.

Deleted: the `get_raw_mempool` call inside `second_chance::gather` and the
94k-entry `HashSet` it built.

## Error taxonomy

`SecondChanceError` keeps `Rpc`, `Deadline`, `EmptyMempool`,
`BlockWalkIncomplete`, and gains `MempoolProbeIncomplete(String)` for the case
where probes came back unadjudicated and the decision would otherwise have been
`upheld`. Labels feed `verifier_phase2_second_chance_total{outcome="lookup_failed"}`
via `lookup_error_kind`, and the soak runbook's outcome table must list the new
kind.

## Testing

Every test below is mutation-proved: apply the inverse change, confirm the
intended test and only the intended test fails.

**Unit (`second_chance.rs`)**
- `classify()` precedence with the new arm, including a txid in more than one set.
- The decision rule directly: an `Unadjudicated` probe must block an `upheld`
  and must NOT block a `withdrawn`.
- `in_mempool + mined + unadjudicated + still_absent == unknown_before` for
  every constructible input, including duplicates in the unknown list. This is
  the test that pins the four counts as disjoint, so no reviewer or dashboard
  can double-count `unadjudicated` inside `still_absent`.

**Integration (extend `tests/pb40_walk_coverage.rs`)**
- Batch responses returned in REVERSED order resolve correctly.
- A response with a missing `id` yields `Unadjudicated` for that txid only.
- A duplicated `id` yields `Unadjudicated` rather than a double count.
- Error `-5` yields absent; any other error code yields `Unadjudicated`.
- Chunk boundaries at N = 249, 250, 251, 500.
- `getmempoolinfo` below the floor yields `EmptyMempool` before any probe is
  issued (assert the probe count is zero, not merely that the error is right).
- The mined case: block walk resolves the template, probe set is near zero.
  Assert the number of txids actually probed, so the optimisation is measured
  rather than assumed.

**Tier 2 (`tests/phase2_tcp.rs`)**
All 10 existing tests must keep passing, which requires teaching that mock
`getmempoolentry` and `getmempoolinfo`. The mock currently answers only
`getrawmempool`, `getbestblockhash`, `getblock`.

**Measurement**
Re-run the latency probe at 94k / 200k / 500k with N=187 and record the numbers
in DEVLOG. Flat is the pass condition.

## Risks

1. **The `-5` assumption.** Mitigated by construction, as above: wrong means
   loud, not silently wrong. Must still be verified on the node at rollout.
2. **Batch size limits in Core.** Not measurable here. Chunking at 250 is
   conservative; a rejected batch surfaces as an RPC error and therefore as
   `lookup_failed`, not as a false answer.
3. **N is large AND the block walk did not help**, e.g. a high unknown ratio
   with no block mined. 3000 unknowns is 12 sequential round trips; if that
   exceeds 2s the outcome is `Deadline`, which upholds the rejection
   unadjudicated. Acceptable and visible, but the soak should watch
   `lookup_failed{kind="deadline"}`.
4. **Reorg reclassification** of a txid from `InMempool` to `Mined`. Decision
   unaffected, evidence label differs. Documented above.

## Rollout

This lands as its own commit on top of `7d891bc`, with its own T2 review. It
does not change the merge order: the four review lenses that have never executed
(adjudication arithmetic, bitcoind answer integrity, evidence durability, blast
radius and doctrine) still gate the merge of the PB-40 branch as a whole.

Docs to update in the same change: the soak runbook's `lookup_error_kind` table
(new kind), and `docs/ADR-003-mempool-ground-truth.md` if the amendment's
description of the mechanism becomes inaccurate.
