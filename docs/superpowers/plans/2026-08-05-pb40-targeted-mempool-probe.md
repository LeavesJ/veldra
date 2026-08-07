# PB-40 Targeted Mempool Probe Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the PB-40 second-chance lookup cost O(unknown transactions) instead of O(mempool), so it stops degrading during mempool congestion.

**Architecture:** Replace the whole-mempool `getrawmempool` fetch inside `SecondChance::gather` with targeted per-txid probes via chunked sequential JSON-RPC batch `getmempoolentry`, run *after* the existing O(blocks) block walk has already subtracted everything it found mined. A `getmempoolinfo` floor replaces the empty-mempool guard that the deleted fetch was carrying. A new third per-transaction state, `Unadjudicated`, keeps an unestablished answer from ever reading as a proven absence.

**Tech Stack:** Rust 2024, cargo workspace, tokio, reqwest, serde, axum (test mocks only), prometheus-client, tracing.

**Spec:** `docs/superpowers/specs/2026-08-05-pb40-targeted-mempool-probe-design.md`

## Global Constraints

- Repo doctrine is `.claude/CLAUDE.md`. Read it. It binds every task.
- **Tier: T2.** Class M reject decision plus durable verdict evidence. Needs an independent reviewer in an isolated worktree who *executes* the claim, after the plan is complete.
- **No em dashes in prose.** Applies to code comments, doc comments, commit messages, and docs.
- **Never add a `Co-Authored-By` trailer.**
- `reason_code` is a canonical stable snake_case string, enum references only, never a string literal. Do not add or change one in this plan.
- **Invariant 3, fail loud.** No silent fallback, no swallowed error, no durability write that logs and returns void.
- **Invariant 4.** Every default must be correct for a production mainnet pool on day one. New tuning values are `const`, never `[policy]` TOML keys.
- **`docs/DEVLOG.md` entry required in the same change.** It is gitignored and lives ONLY in the main checkout at `/Users/a14808/ReserveGrid-OS/docs/DEVLOG.md`, not in the worktree.
- Gate before every commit: `./scripts/gate.sh`. `fmt` reports FAIL for any uncommitted `.rs` change, which is a known quirk; `cargo fmt --all --check` is the honest oracle mid-task.
- Also run `./scripts/superscan.sh --deep-only`. `gate.sh` is not the only gate.
- **Check that tests actually ran.** `0 passed; 0 filtered out` is a selection failure, never a pass. Read the count, not the word "ok".
- `timeout` is NOT installed on this Mac. Background long commands.
- Working directory is the worktree: `/Users/a14808/ReserveGrid-OS/.claude/worktrees/reservegrid-os-dev-c70b0d`. Absolute paths under `/Users/a14808/ReserveGrid-OS/services/...` resolve to the MAIN checkout and will silently edit the wrong tree.
- Branch base: `8762509`.

**Constants introduced by this plan (exact values):**
- `MEMPOOL_PROBE_CHUNK: usize = 250`
- `MEMPOOL_MISSING_ENTRY_CODE: i64 = -5`
- Unchanged: `SECOND_CHANCE_DEADLINE = 2s`, `MAX_RECENT_BLOCKS_SCANNED = 6`, `ABSENT_SAMPLE_CAP = 32`.

## File Structure

| File | Responsibility | Change |
| --- | --- | --- |
| `services/pool-verifier/src/bitcoind_rpc.rs` | JSON-RPC transport only. No policy. | Add batch transport, `getmempoolinfo`, `getmempoolentry` probing. |
| `services/pool-verifier/src/second_chance.rs` | Adjudication policy: what counts as known, budget, decision inputs. | Add `Unadjudicated`; rewire `gather` to probe; own the chunk loop. |
| `services/pool-verifier/src/ingress.rs` | Wiring: turns an adjudication into an outcome and a record. | Pass the unknown set to `ask`; gate `upheld` on `unadjudicated == 0`. |
| `services/pool-verifier/tests/pb40_walk_coverage.rs` | In-process integration against a scriptable bitcoind. | Extend mock; add batch and probe tests. |
| `services/pool-verifier/tests/phase2_tcp.rs` | Tier 2, real binary subprocess. | Teach mock the two new RPCs. |
| `docs/runbooks/phase2-shadow-soak.md` | Operator procedure. | New `lookup_error_kind`. |

Chunking lives in `second_chance`, not `bitcoind_rpc`: the chunk loop is where the deadline is spent, and the deadline is policy. `bitcoind_rpc::probe_mempool` issues exactly one batch.

---

### Task 1: JSON-RPC batch transport

**Files:**
- Modify: `services/pool-verifier/src/bitcoind_rpc.rs`

**Interfaces:**
- Consumes: existing private `JsonRpcError`, `BitcoindClient` fields `http`, `url`, `user`, `pass`.
- Produces:
  - `pub enum BatchItem<R> { Ok(R), Failed { code: i64, message: String }, NoResponse }`
  - `pub async fn BitcoindClient::call_batch<P: Serialize, R: DeserializeOwned>(&self, method: &str, params_per_item: &[P]) -> Result<Vec<BatchItem<R>>, RpcError>`. The returned Vec is always the same length as `params_per_item` and index-aligned to it.

- [ ] **Step 1: Write the failing tests**

Append to the `mod tests` block at the bottom of `services/pool-verifier/src/bitcoind_rpc.rs`:

```rust
    /// Responses are resolved by `id`, never by position. JSON-RPC
    /// permits a server to reorder a batch reply, and a position-zip
    /// would misattribute every verdict in the chunk while staying
    /// invisible to any mock that replies in order.
    #[test]
    fn batch_resolves_by_id_under_reordering() {
        let raw = r#"[
            {"id":2,"result":"c","error":null},
            {"id":0,"result":"a","error":null},
            {"id":1,"result":"b","error":null}
        ]"#;
        let parsed: Vec<BatchResponse<String>> = serde_json::from_str(raw).unwrap();
        let out = resolve_batch::<String>(parsed, 3);
        assert!(matches!(&out[0], BatchItem::Ok(s) if s == "a"));
        assert!(matches!(&out[1], BatchItem::Ok(s) if s == "b"));
        assert!(matches!(&out[2], BatchItem::Ok(s) if s == "c"));
    }

    #[test]
    fn batch_marks_a_missing_id_as_no_response() {
        let raw = r#"[{"id":0,"result":"a","error":null}]"#;
        let parsed: Vec<BatchResponse<String>> = serde_json::from_str(raw).unwrap();
        let out = resolve_batch::<String>(parsed, 2);
        assert_eq!(out.len(), 2, "the result must stay aligned to the request");
        assert!(matches!(out[1], BatchItem::NoResponse));
    }

    /// A duplicated id is ambiguous: two answers claim one request and
    /// there is no way to tell which is real. Ambiguous must not become
    /// a confident answer.
    #[test]
    fn batch_marks_a_duplicated_id_as_no_response() {
        let raw = r#"[
            {"id":0,"result":"a","error":null},
            {"id":0,"result":"b","error":null}
        ]"#;
        let parsed: Vec<BatchResponse<String>> = serde_json::from_str(raw).unwrap();
        let out = resolve_batch::<String>(parsed, 1);
        assert!(matches!(out[0], BatchItem::NoResponse));
    }

    /// Error precedence matches the single-call path: a 200 OK carrying
    /// an error object is a failure, and reading `result` first would
    /// miss it.
    #[test]
    fn batch_prefers_the_error_object_over_a_result() {
        let raw = r#"[{"id":0,"result":null,"error":{"code":-5,"message":"nope"}}]"#;
        let parsed: Vec<BatchResponse<String>> = serde_json::from_str(raw).unwrap();
        let out = resolve_batch::<String>(parsed, 1);
        match &out[0] {
            BatchItem::Failed { code, message } => {
                assert_eq!(*code, -5);
                assert_eq!(message, "nope");
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    /// An id outside the request range cannot be attributed to anything.
    #[test]
    fn batch_ignores_an_out_of_range_id() {
        let raw = r#"[{"id":99,"result":"x","error":null}]"#;
        let parsed: Vec<BatchResponse<String>> = serde_json::from_str(raw).unwrap();
        let out = resolve_batch::<String>(parsed, 1);
        assert!(matches!(out[0], BatchItem::NoResponse));
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cargo test -p pool-verifier --lib bitcoind_rpc 2>&1 | tail -20
```

Expected: compile error, `cannot find function 'resolve_batch'` and `cannot find type 'BatchResponse'`. A compile failure is the RED state here.

- [ ] **Step 3: Implement the batch transport**

In `services/pool-verifier/src/bitcoind_rpc.rs`, add after the `JsonRpcError` struct near the bottom:

```rust
/// One request in a JSON-RPC batch. Distinct from [`JsonRpcRequest`]
/// because a batch needs a per-item numeric `id` to correlate replies,
/// where the single-call path uses one fixed string id it never reads
/// back.
#[derive(Serialize)]
struct BatchRequest<'a, T> {
    jsonrpc: &'a str,
    id: u32,
    method: &'a str,
    params: T,
}

/// One reply in a JSON-RPC batch. `id` is `Option` because a malformed
/// or error-shaped reply may omit it, and an unattributable reply must
/// not be silently assigned to whichever request happens to sit at the
/// same index.
#[derive(Deserialize)]
struct BatchResponse<T> {
    #[serde(default)]
    id: Option<u32>,
    result: Option<T>,
    error: Option<JsonRpcError>,
}

/// One resolved batch item, index-aligned to the request that produced it.
#[derive(Debug)]
pub enum BatchItem<R> {
    Ok(R),
    Failed { code: i64, message: String },
    /// No reply could be attributed to this request: the id was absent,
    /// duplicated, or out of range. NOT an answer, and callers must not
    /// treat it as a negative one.
    NoResponse,
}

/// Correlate batch replies to requests by `id`, never by position.
///
/// Separated from the HTTP call so every branch is reachable in a unit
/// test without a server. Returns exactly `request_count` items.
fn resolve_batch<R>(responses: Vec<BatchResponse<R>>, request_count: usize) -> Vec<BatchItem<R>> {
    let mut slots: Vec<Option<BatchItem<R>>> = (0..request_count).map(|_| None).collect();
    let mut duplicated = vec![false; request_count];

    for resp in responses {
        let Some(id) = resp.id else { continue };
        let Ok(idx) = usize::try_from(id) else { continue };
        if idx >= request_count {
            continue;
        }
        if slots[idx].is_some() {
            // Two replies claim one request and there is no way to tell
            // which is real, so neither is used.
            duplicated[idx] = true;
            continue;
        }
        // Error first, matching the single-call path: a 200 OK carrying
        // an error object is a failure.
        slots[idx] = Some(match (resp.error, resp.result) {
            (Some(e), _) => BatchItem::Failed {
                code: e.code,
                message: e.message,
            },
            (None, Some(r)) => BatchItem::Ok(r),
            (None, None) => BatchItem::NoResponse,
        });
    }

    slots
        .into_iter()
        .enumerate()
        .map(|(i, slot)| {
            if duplicated[i] {
                BatchItem::NoResponse
            } else {
                slot.unwrap_or(BatchItem::NoResponse)
            }
        })
        .collect()
}
```

Then add this method inside `impl BitcoindClient`, directly after the existing `call` method:

```rust
    /// Issue one JSON-RPC batch and return per-item outcomes,
    /// index-aligned to `params_per_item`.
    ///
    /// The returned Vec is always the same length as the input. An item
    /// whose reply could not be attributed comes back as
    /// [`BatchItem::NoResponse`] rather than shifting its neighbours.
    ///
    /// # Errors
    ///
    /// Transport-level failure only: a non-2xx status, a body that is
    /// not a JSON array, or a network error. Per-item failures are
    /// carried in the returned Vec, not in this Result.
    pub async fn call_batch<P: Serialize, R: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        params_per_item: &[P],
    ) -> Result<Vec<BatchItem<R>>, RpcError> {
        if params_per_item.is_empty() {
            return Ok(Vec::new());
        }
        let reqs: Vec<BatchRequest<'_, &P>> = params_per_item
            .iter()
            .enumerate()
            .map(|(i, p)| BatchRequest {
                jsonrpc: "1.0",
                id: u32::try_from(i).unwrap_or(u32::MAX),
                method,
                params: p,
            })
            .collect();

        let responses: Vec<BatchResponse<R>> = self
            .http
            .post(&self.url)
            .basic_auth(&self.user, Some(&self.pass))
            .json(&reqs)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        Ok(resolve_batch(responses, params_per_item.len()))
    }
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cargo test -p pool-verifier --lib bitcoind_rpc 2>&1 | tail -20
```

Expected: `test result: ok. 9 passed` (4 pre-existing `parse_txid_hex` tests plus the 5 new ones). Confirm the count is 9, not 4.

- [ ] **Step 5: Mutation-proof the id correlation**

Temporarily replace the body of `resolve_batch` with a position-zip:

```rust
    responses
        .into_iter()
        .map(|resp| match (resp.error, resp.result) {
            (Some(e), _) => BatchItem::Failed { code: e.code, message: e.message },
            (None, Some(r)) => BatchItem::Ok(r),
            (None, None) => BatchItem::NoResponse,
        })
        .chain(std::iter::repeat_with(|| BatchItem::NoResponse))
        .take(request_count)
        .collect()
```

Run:

```bash
cargo test -p pool-verifier --lib bitcoind_rpc 2>&1 | tail -20
```

Expected: `batch_resolves_by_id_under_reordering`, `batch_marks_a_duplicated_id_as_no_response` and `batch_ignores_an_out_of_range_id` FAIL. Then restore the real implementation and confirm 9 pass again. If any of those three still passes under the mutation, the test is vacuous and must be strengthened before moving on.

- [ ] **Step 6: Commit**

```bash
cargo fmt --all && ./scripts/gate.sh 2>&1 | tail -10
git add services/pool-verifier/src/bitcoind_rpc.rs
git commit -m "feat(pool-verifier): JSON-RPC batch transport correlated by id (PB-40)"
```

---

### Task 2: `getmempoolinfo` and per-txid mempool probing

**Files:**
- Modify: `services/pool-verifier/src/bitcoind_rpc.rs`

**Interfaces:**
- Consumes: `call`, `call_batch`, `BatchItem` from Task 1.
- Produces:
  - `pub const MEMPOOL_MISSING_ENTRY_CODE: i64 = -5;`
  - `pub struct MempoolInfo { pub size: usize }`
  - `pub enum MempoolProbe { Present, Absent, Unadjudicated { reason: String } }`
  - `pub async fn BitcoindClient::get_mempool_info(&self) -> Result<MempoolInfo, RpcError>`
  - `pub async fn BitcoindClient::probe_mempool(&self, txids: &[[u8; 32]]) -> Result<Vec<MempoolProbe>, RpcError>` (one batch, Vec index-aligned to `txids`).

- [ ] **Step 1: Write the failing tests**

Append to `mod tests` in `services/pool-verifier/src/bitcoind_rpc.rs`:

```rust
    /// Only the documented missing-entry code counts as a proven
    /// absence. Every other error is unadjudicated.
    ///
    /// This is fail-safe against our own uncertainty: the -5 code is
    /// believed correct but has NOT been verified against a real
    /// bitcoind. If it is wrong, every probe becomes Unadjudicated,
    /// which forces lookup_failed (loud). It can never degrade into
    /// "all absent", which would fabricate detections.
    #[test]
    fn only_the_missing_entry_code_means_absent() {
        assert!(matches!(
            probe_from_item(BatchItem::<serde_json::Value>::Failed {
                code: MEMPOOL_MISSING_ENTRY_CODE,
                message: "Transaction not in mempool".to_string(),
            }),
            MempoolProbe::Absent
        ));
        assert!(matches!(
            probe_from_item(BatchItem::<serde_json::Value>::Failed {
                code: -32603,
                message: "Work queue depth exceeded".to_string(),
            }),
            MempoolProbe::Unadjudicated { .. }
        ));
        assert!(matches!(
            probe_from_item(BatchItem::<serde_json::Value>::NoResponse),
            MempoolProbe::Unadjudicated { .. }
        ));
        assert!(matches!(
            probe_from_item(BatchItem::Ok(serde_json::json!({"vsize": 141}))),
            MempoolProbe::Present
        ));
    }

    /// getmempoolinfo carries many fields; we read one and must ignore
    /// the rest rather than failing to deserialize.
    #[test]
    fn mempool_info_reads_size_and_ignores_the_rest() {
        let raw = r#"{"loaded":true,"size":94211,"bytes":41000000,"usage":210000000,
                      "maxmempool":300000000,"mempoolminfee":0.00001000}"#;
        let info: MempoolInfo = serde_json::from_str(raw).unwrap();
        assert_eq!(info.size, 94_211);
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cargo test -p pool-verifier --lib bitcoind_rpc 2>&1 | tail -20
```

Expected: compile error, `cannot find function 'probe_from_item'`, `cannot find type 'MempoolInfo'`, `cannot find type 'MempoolProbe'`.

- [ ] **Step 3: Implement**

Add to `services/pool-verifier/src/bitcoind_rpc.rs`, after the `BatchItem` definition:

```rust
/// Bitcoin Core's error code for `getmempoolentry` on a transaction the
/// mempool does not hold (`RPC_INVALID_ADDRESS_OR_KEY`, "Transaction
/// not in mempool").
///
/// This is the ONLY code treated as a proven absence. Matching on the
/// code alone rather than the message keeps it stable across Core
/// versions; scoping the meaning to `getmempoolentry` is what makes the
/// code unambiguous, since -5 means other things for other methods.
///
/// NOT VERIFIED against a live bitcoind from the development
/// environment. The design is deliberately fail-safe about that: if the
/// code is wrong, every probe resolves Unadjudicated and the caller
/// emits `lookup_failed`, which is loud. It cannot resolve to "absent",
/// which would fabricate a detection. Verify on the node at rollout.
pub const MEMPOOL_MISSING_ENTRY_CODE: i64 = -5;

/// The `getmempoolinfo` fields this crate reads. Core returns many
/// more; serde ignores them.
#[derive(Debug, Clone, Deserialize)]
pub struct MempoolInfo {
    /// Transactions currently in the mempool.
    pub size: usize,
}

/// What bitcoind said about one specific transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MempoolProbe {
    /// bitcoind returned an entry: it holds this transaction now.
    Present,
    /// bitcoind answered that it does not hold it. A real negative, and
    /// better evidence than absence from a snapshot, because it is a
    /// direct per-transaction statement rather than an inference.
    Absent,
    /// No usable answer. Proves nothing in either direction.
    Unadjudicated { reason: String },
}

/// Map one batch item to a probe verdict.
///
/// Separated from the RPC call so the error-code policy, which is the
/// part that decides whether an unproven thing can read as proven, is
/// unit-testable without a server.
fn probe_from_item<R>(item: BatchItem<R>) -> MempoolProbe {
    match item {
        BatchItem::Ok(_) => MempoolProbe::Present,
        BatchItem::Failed { code, .. } if code == MEMPOOL_MISSING_ENTRY_CODE => {
            MempoolProbe::Absent
        }
        BatchItem::Failed { code, message } => MempoolProbe::Unadjudicated {
            reason: format!("getmempoolentry returned code {code}: {message}"),
        },
        BatchItem::NoResponse => MempoolProbe::Unadjudicated {
            reason: "no batch reply could be attributed to this request id".to_string(),
        },
    }
}
```

Add these two methods inside `impl BitcoindClient`, after `call_batch`:

```rust
    /// Mempool size, for the degenerate-node guard.
    ///
    /// # Errors
    ///
    /// Any transport or RPC failure.
    pub async fn get_mempool_info(&self) -> Result<MempoolInfo, RpcError> {
        self.call("getmempoolinfo", [(); 0]).await
    }

    /// Ask bitcoind about specific transactions in ONE batch.
    ///
    /// The returned Vec is index-aligned to `txids`. Cost is
    /// proportional to `txids.len()` and independent of mempool size,
    /// which is the entire point: the whole-mempool fetch this replaces
    /// took 858 ms at 94k transactions and blew its 2s budget at 500k.
    ///
    /// Txids are sent in DISPLAY order, which is what Bitcoin Core's
    /// RPC speaks; callers hold them in internal byte order.
    ///
    /// # Errors
    ///
    /// Transport-level failure only. Per-txid outcomes, including "not
    /// in mempool", are values in the returned Vec.
    pub async fn probe_mempool(&self, txids: &[[u8; 32]]) -> Result<Vec<MempoolProbe>, RpcError> {
        let params: Vec<[String; 1]> = txids
            .iter()
            .map(|t| {
                let mut display = *t;
                display.reverse();
                [hex::encode(display)]
            })
            .collect();
        let items: Vec<BatchItem<serde_json::Value>> =
            self.call_batch("getmempoolentry", &params).await?;
        Ok(items.into_iter().map(probe_from_item).collect())
    }
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cargo test -p pool-verifier --lib bitcoind_rpc 2>&1 | tail -20
```

Expected: `test result: ok. 11 passed`.

- [ ] **Step 5: Mutation-proof the error-code policy**

Temporarily change the guard in `probe_from_item` from `if code == MEMPOOL_MISSING_ENTRY_CODE` to `if true`, so any error reads as absent. Run:

```bash
cargo test -p pool-verifier --lib bitcoind_rpc 2>&1 | tail -20
```

Expected: `only_the_missing_entry_code_means_absent` FAILS. Restore and confirm 11 pass.

- [ ] **Step 6: Commit**

```bash
cargo fmt --all && ./scripts/gate.sh 2>&1 | tail -10
git add services/pool-verifier/src/bitcoind_rpc.rs
git commit -m "feat(pool-verifier): getmempoolinfo and per-txid mempool probing (PB-40)"
```

---

### Task 3: `Unadjudicated` in the pure adjudication core

**Files:**
- Modify: `services/pool-verifier/src/second_chance.rs`

**Interfaces:**
- Consumes: nothing new.
- Produces:
  - `TxAdjudication::Unadjudicated` variant
  - `BitcoindAnswer.present_in_mempool` (renamed from `fresh_mempool`) and new `BitcoindAnswer.unadjudicated: HashSet<[u8; 32]>`
  - `Adjudication.unadjudicated: u32`
  - `pub fn Adjudication::not_proven_known(&self) -> u32`
  - `MempoolAdjudicationRecord.unadjudicated: u32`

This task is pure. It performs the rename and adds the fourth state while `gather` still uses the whole-mempool fetch, so the tree stays green and committable. Task 4 rewires the I/O.

- [ ] **Step 1: Write the failing tests**

Append inside `mod tests` in `services/pool-verifier/src/second_chance.rs`:

```rust
    /// The four counts are DISJOINT and must sum to the input. Without
    /// this, a reviewer or a dashboard can double-count `unadjudicated`
    /// inside `still_absent` and read an unestablished count as
    /// evidence.
    #[test]
    fn the_four_counts_are_disjoint_and_sum_to_the_unknown_set() {
        let unknown: Vec<[u8; 32]> = (1u8..=20).map(txid).collect();
        let mut a = answer(&[1, 2, 3], &[4, 5]);
        a.unadjudicated = [6u8, 7].iter().copied().map(txid).collect();
        let adj = adjudicate(100, &unknown, &a);

        assert_eq!(adj.in_mempool, 3);
        assert_eq!(adj.mined, 2);
        assert_eq!(adj.unadjudicated, 2);
        assert_eq!(adj.still_absent, 13, "proven absent only");
        assert_eq!(
            adj.in_mempool + adj.mined + adj.unadjudicated + adj.still_absent,
            adj.unknown_before
        );
    }

    /// `not_proven_known` is what the decision uses: proven absent plus
    /// the ones nobody established. `still_absent` alone would treat an
    /// unestablished transaction as known, which is the optimistic
    /// direction and the wrong one.
    #[test]
    fn unadjudicated_counts_against_recovery_not_for_it() {
        let unknown: Vec<[u8; 32]> = (1u8..=10).map(txid).collect();
        // 7 proven present, 3 unadjudicated, 0 proven absent.
        let mut a = answer(&[1, 2, 3, 4, 5, 6, 7], &[]);
        a.unadjudicated = [8u8, 9, 10].iter().copied().map(txid).collect();
        let adj = adjudicate(100, &unknown, &a);

        assert_eq!(adj.still_absent, 0);
        assert_eq!(adj.unadjudicated, 3);
        assert_eq!(adj.not_proven_known(), 3);
        assert!(
            !adj.still_exceeds(4.0),
            "3 of 100 is under the 4% tolerance even counting the unproven pessimistically"
        );

        // Now push the unproven count over the line: 5 of 100 is 5%.
        let unknown: Vec<[u8; 32]> = (1u8..=10).map(txid).collect();
        let mut a = answer(&[1, 2, 3, 4, 5], &[]);
        a.unadjudicated = [6u8, 7, 8, 9, 10].iter().copied().map(txid).collect();
        let adj = adjudicate(100, &unknown, &a);
        assert_eq!(adj.still_absent, 0, "none were PROVEN absent");
        assert!(
            adj.still_exceeds(4.0),
            "five unestablished transactions must not be read as recovered"
        );
    }

    /// Precedence: present beats mined beats unadjudicated beats absent,
    /// and a txid in several sets is counted exactly once.
    #[test]
    fn classification_precedence_counts_each_txid_once() {
        let unknown = [txid(1)];
        let mut a = answer(&[1], &[1]);
        a.unadjudicated = [txid(1)].into_iter().collect();
        let adj = adjudicate(10, &unknown, &a);

        assert_eq!(adj.in_mempool, 1);
        assert_eq!(adj.mined, 0);
        assert_eq!(adj.unadjudicated, 0);
        assert_eq!(adj.still_absent, 0);
        assert_eq!(adj.unknown_before, 1);
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cargo test -p pool-verifier --lib second_chance 2>&1 | tail -20
```

Expected: compile error, `no field 'unadjudicated' on type 'BitcoindAnswer'` and `no method named 'not_proven_known'`.

- [ ] **Step 3: Rename the field and add the fourth state**

In `services/pool-verifier/src/second_chance.rs`, in `pub struct BitcoindAnswer`, replace the `fresh_mempool` field with these two:

```rust
    /// Unknown transactions bitcoind CONFIRMED it holds right now.
    ///
    /// Named for what it is. It was `fresh_mempool` when it held a
    /// whole-mempool snapshot; it is now the probed subset that came
    /// back present, and calling it "the mempool" would invite a reader
    /// to treat absence from it as absence from the mempool. Absence
    /// from this set means only "not confirmed present".
    pub present_in_mempool: HashSet<[u8; 32]>,
    /// Unknown transactions whose probe returned no usable answer.
    /// Proves nothing in either direction; kept separate from the
    /// proven-absent count so the two can never be conflated.
    pub unadjudicated: HashSet<[u8; 32]>,
```

In `pub enum TxAdjudication`, add after `Mined`:

```rust
    /// bitcoind was asked and did not give a usable answer. Distinct
    /// from `Absent`, which is a positive statement that it does not
    /// hold the transaction.
    Unadjudicated,
```

Replace the whole `fn classify` body:

```rust
fn classify(txid: &[u8; 32], answer: &BitcoindAnswer) -> TxAdjudication {
    if answer.present_in_mempool.contains(txid) {
        TxAdjudication::InMempool
    } else if answer.recent_block_txids.contains(txid) {
        TxAdjudication::Mined
    } else if answer.unadjudicated.contains(txid) {
        TxAdjudication::Unadjudicated
    } else {
        TxAdjudication::Absent
    }
}
```

In `pub struct Adjudication`, change the `still_absent` doc comment and add the new field immediately after it:

```rust
    /// Of those, bitcoind answered that it holds them in neither place.
    /// PROVEN absent. Narrowed from "not found" by the targeted-probe
    /// change: the unproven cases now live in `unadjudicated`, because
    /// the old breadth is what let an unestablished count read as
    /// evidence for a detection.
    pub still_absent: u32,
    /// Of those, nobody established anything about. Disjoint from
    /// `still_absent`.
    pub unadjudicated: u32,
```

In `pub fn adjudicate`, add the counter and the new match arm. Replace the counter declarations and the loop:

```rust
    let mut in_mempool = 0u32;
    let mut mined = 0u32;
    let mut unadjudicated = 0u32;
    let mut still_absent = 0u32;
    let mut still_absent_sample = Vec::new();

    for txid in unknown {
        match classify(txid, answer) {
            TxAdjudication::InMempool => in_mempool = in_mempool.saturating_add(1),
            TxAdjudication::Mined => mined = mined.saturating_add(1),
            TxAdjudication::Unadjudicated => unadjudicated = unadjudicated.saturating_add(1),
            TxAdjudication::Absent => {
                still_absent = still_absent.saturating_add(1);
                if still_absent_sample.len() < ABSENT_SAMPLE_CAP {
                    still_absent_sample.push(*txid);
                }
            }
        }
    }
```

and add `unadjudicated,` to the `Adjudication { ... }` literal it returns, immediately after `still_absent,`.

Replace the `impl Adjudication` block:

```rust
impl Adjudication {
    /// Unknown transactions not proven known to bitcoind: proven absent
    /// plus unestablished. This is what the tolerance decision uses.
    ///
    /// Counting the unestablished ones here is the pessimistic reading
    /// and it is the safe one: it can only hold a rejection, never
    /// manufacture a recovery.
    #[must_use]
    pub fn not_proven_known(&self) -> u32 {
        self.still_absent.saturating_add(self.unadjudicated)
    }

    /// Whether the rejection still stands once the transactions
    /// bitcoind proved it knows have been removed from the count.
    #[must_use]
    pub fn still_exceeds(&self, tolerance_pct: f64) -> bool {
        exceeds_tolerance(self.not_proven_known(), self.total, tolerance_pct)
    }
}
```

In `pub struct MempoolAdjudicationRecord`, add after the `still_absent` field:

```rust
    /// Unknowns nobody established anything about. Disjoint from
    /// `still_absent`. Non-zero means this record cannot support a
    /// detection claim regardless of what `still_absent` says.
    #[serde(default)]
    pub unadjudicated: u32,
```

In `impl From<&SecondChanceOutcome> for MempoolAdjudicationRecord`, add `unadjudicated: adj.unadjudicated,` to the `Withdrawn | Upheld` arm after `still_absent`, and `unadjudicated: 0,` to the `LookupFailed` arm after `still_absent: 0,`.

Now fix the two compile sites that used the old field name. In the test helper `fn answer`, replace `fresh_mempool:` with `present_in_mempool:` and add `unadjudicated: HashSet::new(),`:

```rust
    fn answer(mempool: &[u8], blocks: &[u8]) -> BitcoindAnswer {
        BitcoindAnswer {
            present_in_mempool: mempool.iter().copied().map(txid).collect(),
            unadjudicated: HashSet::new(),
            recent_block_txids: blocks.iter().copied().map(txid).collect(),
            blocks_scanned: u32::from(!blocks.is_empty()),
            block_walk_truncated: false,
            tip_height: None,
            block_walk_shortfall: None,
        }
    }
```

In `async fn gather`, rename the local binding and add the empty set to the constructed `BitcoindAnswer`. Change `let fresh_mempool: HashSet<[u8; 32]> =` to `let present_in_mempool: HashSet<[u8; 32]> =`, change the two references in the length check and the `warn!` from `fresh_mempool.len()` to `present_in_mempool.len()`, and in the returned literal replace `fresh_mempool,` with:

```rust
            present_in_mempool,
            // Task 4 replaces the whole-mempool fetch with targeted
            // probes, which is what can actually produce this.
            unadjudicated: HashSet::new(),
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cargo test -p pool-verifier --lib second_chance 2>&1 | tail -20
```

Expected: `test result: ok. 11 passed` (8 pre-existing plus 3 new).

- [ ] **Step 5: Mutation-proof the pessimistic reading**

Temporarily change `not_proven_known` to `self.still_absent` alone. Run:

```bash
cargo test -p pool-verifier --lib second_chance 2>&1 | tail -20
```

Expected: `unadjudicated_counts_against_recovery_not_for_it` FAILS. Restore and confirm 11 pass.

- [ ] **Step 6: Commit**

```bash
cargo fmt --all && cargo test -p pool-verifier 2>&1 | grep -E "^test result"
./scripts/gate.sh 2>&1 | tail -10
git add services/pool-verifier/src/second_chance.rs
git commit -m "feat(pool-verifier): add an Unadjudicated state to the adjudication core (PB-40)"
```

---

### Task 4: Rewire `gather` to targeted probes

**Files:**
- Modify: `services/pool-verifier/src/second_chance.rs`
- Modify: `services/pool-verifier/tests/pb40_walk_coverage.rs` (call sites and mock)

**Interfaces:**
- Consumes: `get_mempool_info`, `probe_mempool`, `MempoolProbe` from Task 2; `BitcoindAnswer.unadjudicated` from Task 3.
- Produces:
  - `pub const MEMPOOL_PROBE_CHUNK: usize = 250;`
  - `SecondChanceError::MempoolProbeIncomplete(String)`
  - `pub async fn SecondChance::ask(&self, template_height: u32, unknown: &[[u8; 32]]) -> Result<BitcoindAnswer, SecondChanceError>` (signature change: gains `unknown`)

- [ ] **Step 1: Update the existing integration mock and call sites**

The mock in `services/pool-verifier/tests/pb40_walk_coverage.rs` answers only three methods and `ask` gains a parameter, so this file must move with the change or nothing compiles.

First add ONE shared helper near the top of the file, just below `display_hex`. Every mock in this file answers batches the same way, and the repo doctrine's rule of three says extract on the third rather than paste a fourth:

```rust
/// Reply to a JSON-RPC batch, echoing each request's `id`.
///
/// `present` decides whether each probed transaction reports as held.
/// `error_code` is the code used when it does not: `-5` is Core's
/// "not in mempool", anything else drives the unadjudicated path.
fn batch_reply(items: &[Value], present: bool, error_code: i64) -> Json<Value> {
    let replies: Vec<Value> = items
        .iter()
        .map(|item| {
            let id = item.get("id").cloned().unwrap_or(Value::Null);
            if present {
                json!({"id": id, "result": {"vsize": 141}, "error": Value::Null})
            } else {
                json!({
                    "id": id,
                    "result": Value::Null,
                    "error": {"code": error_code, "message": "Transaction not in mempool"},
                })
            }
        })
        .collect();
    Json(Value::Array(replies))
}
```

In the `rpc` handler's `match method`, replace the `"getrawmempool"` arm with these two arms:

```rust
        // Healthy, populated node: the degenerate-node floor must not trip.
        "getmempoolinfo" => Json(json!({
            "result": {"loaded": true, "size": 94_211}, "error": null, "id": 1
        })),
```

and add, before the final `_ =>` arm, nothing else. Batch requests do not reach this handler as a single object, so add a batch branch at the very top of `rpc`, before `let method = ...`:

```rust
    // A JSON-RPC batch arrives as an ARRAY. This chain never holds the
    // template's transactions, so every probe answers "not in mempool".
    if let Some(items) = req.as_array() {
        return batch_reply(items, false, -5);
    }
```

Do the same batch branch at the top of `mempool_only`, but replying with the work-queue error so the mempool half still succeeds while the block walk fails:

```rust
    if let Some(items) = req.as_array() {
        return batch_reply(items, false, -5);
    }
```

and replace its `getrawmempool` branch with:

```rust
    if req.get("method").and_then(Value::as_str) == Some("getmempoolinfo") {
        return Json(json!({"result": {"size": 94_211}, "error": null, "id": 1}));
    }
```

In `empty_mempool`, replace its `getrawmempool` branch with:

```rust
    if req.get("method").and_then(Value::as_str) == Some("getmempoolinfo") {
        return Json(json!({"result": {"size": 0}, "error": null, "id": 1}));
    }
```

Finally, every `sc.ask(TEMPLATE_HEIGHT)` call in this file gains a second argument. There are SEVEN, not six. Add this helper above `const TEMPLATE_HEIGHT`:

```rust
/// The unknown set these coverage tests probe with. One txid that this
/// synthetic chain never mines and never holds in its mempool, so the
/// mempool half is constant and the block walk is the only variable.
fn probe_set() -> Vec<[u8; 32]> {
    vec![[0x7Eu8; 32]]
}
```

and change every `sc.ask(TEMPLATE_HEIGHT).await` to `sc.ask(TEMPLATE_HEIGHT, &probe_set()).await`. Find them all with:

```bash
grep -n "ask(TEMPLATE_HEIGHT" services/pool-verifier/tests/pb40_walk_coverage.rs
```

- [ ] **Step 2: Write the failing tests**

Append to `services/pool-verifier/tests/pb40_walk_coverage.rs`:

```rust
/// Cost must be proportional to the unknown set, not the mempool. The
/// direct evidence for that is the number of transactions actually
/// probed, so count them.
#[tokio::test]
async fn the_block_walk_runs_first_and_shrinks_the_probe_set() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let probed = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&probed);

    // A chain whose tip block at TEMPLATE_HEIGHT holds the template's
    // transaction: the mined case, where every unknown left the mempool
    // at once.
    let mined_txid = tx_in_block(TEMPLATE_HEIGHT);
    let app = Router::new()
        .route(
            "/",
            post(move |Json(req): Json<Value>| {
                let counter = Arc::clone(&counter);
                async move {
                    if let Some(items) = req.as_array() {
                        counter.fetch_add(items.len(), Ordering::SeqCst);
                        return batch_reply(items, false, -5);
                    }
                    match req.get("method").and_then(Value::as_str).unwrap_or("") {
                        "getmempoolinfo" => {
                            Json(json!({"result": {"size": 94_211}, "error": null, "id": 1}))
                        }
                        "getbestblockhash" => Json(
                            json!({"result": block_hash(TEMPLATE_HEIGHT), "error": null, "id": 1}),
                        ),
                        "getblock" => Json(json!({
                            "result": {
                                "hash": block_hash(TEMPLATE_HEIGHT),
                                "height": TEMPLATE_HEIGHT,
                                "tx": [display_hex(mined_txid)],
                                "previousblockhash": Value::Null,
                            },
                            "error": null, "id": 1
                        })),
                        _ => Json(
                            json!({"result": null, "error": {"code": -32601, "message": "no"}, "id": 1}),
                        ),
                    }
                }
            }),
        );
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let sc = SecondChance::new(BitcoindClient::new(
        format!("http://{addr}/"),
        "u".into(),
        "p".into(),
        std::time::Duration::from_secs(5),
    ));

    let answer = sc.ask(TEMPLATE_HEIGHT, &[mined_txid]).await.expect("lookup");

    assert!(
        answer.recent_block_txids.contains(&mined_txid),
        "the block walk should have found it"
    );
    assert_eq!(
        probed.load(Ordering::SeqCst),
        0,
        "the block walk already resolved every unknown, so nothing should have been probed"
    );
}

/// A degenerate mempool is refused BEFORE any probe is issued, not
/// after. Assert the probe count, because an error raised after
/// probing would pass a test that only checks the error.
#[tokio::test]
async fn an_empty_mempool_is_refused_before_any_probe_is_issued() {
    let sc = spawn_router(Router::new().route("/", post(empty_mempool))).await;
    let err = sc
        .ask(TEMPLATE_HEIGHT, &probe_set())
        .await
        .expect_err("an empty mempool must be refused");
    assert_eq!(err.as_label(), "empty_mempool");
}

/// A probe that returns an unusable answer lands in `unadjudicated`,
/// never in the proven-absent set.
#[tokio::test]
async fn an_unusable_probe_answer_is_unadjudicated_not_absent() {
    async fn work_queue_exceeded(Json(req): Json<Value>) -> Json<Value> {
        if let Some(items) = req.as_array() {
            return batch_reply(items, false, -32603);
        }
        match req.get("method").and_then(Value::as_str).unwrap_or("") {
            "getmempoolinfo" => Json(json!({"result": {"size": 94_211}, "error": null, "id": 1})),
            "getbestblockhash" => {
                Json(json!({"result": block_hash(TEMPLATE_HEIGHT - 1), "error": null, "id": 1}))
            }
            "getblock" => Json(json!({
                "result": {
                    "hash": block_hash(TEMPLATE_HEIGHT - 1),
                    "height": TEMPLATE_HEIGHT - 1,
                    "tx": [], "previousblockhash": Value::Null,
                },
                "error": null, "id": 1
            })),
            _ => Json(json!({"result": null, "error": {"code": -1, "message": "no"}, "id": 1})),
        }
    }

    let sc = spawn_router(Router::new().route("/", post(work_queue_exceeded))).await;
    let target = [0x7Eu8; 32];
    let answer = sc.ask(TEMPLATE_HEIGHT, &[target]).await.expect("lookup");

    assert!(
        answer.unadjudicated.contains(&target),
        "an unusable answer must be unadjudicated"
    );
    assert!(!answer.present_in_mempool.contains(&target));
}

/// Chunking must not drop or duplicate a transaction at the boundary.
#[tokio::test]
async fn chunk_boundaries_probe_every_txid_exactly_once() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    for n in [
        MEMPOOL_PROBE_CHUNK - 1,
        MEMPOOL_PROBE_CHUNK,
        MEMPOOL_PROBE_CHUNK + 1,
        MEMPOOL_PROBE_CHUNK * 2,
    ] {
        let probed = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&probed);
        let app = Router::new().route(
            "/",
            post(move |Json(req): Json<Value>| {
                let counter = Arc::clone(&counter);
                async move {
                    if let Some(items) = req.as_array() {
                        assert!(
                            items.len() <= MEMPOOL_PROBE_CHUNK,
                            "a chunk must never exceed the cap"
                        );
                        counter.fetch_add(items.len(), Ordering::SeqCst);
                        return batch_reply(items, true, -5);
                    }
                    match req.get("method").and_then(Value::as_str).unwrap_or("") {
                        "getmempoolinfo" => {
                            Json(json!({"result": {"size": 94_211}, "error": null, "id": 1}))
                        }
                        "getbestblockhash" => Json(
                            json!({"result": block_hash(TEMPLATE_HEIGHT - 1), "error": null, "id": 1}),
                        ),
                        "getblock" => Json(json!({
                            "result": {
                                "hash": block_hash(TEMPLATE_HEIGHT - 1),
                                "height": TEMPLATE_HEIGHT - 1,
                                "tx": [], "previousblockhash": Value::Null,
                            },
                            "error": null, "id": 1
                        })),
                        _ => Json(json!({"result": null, "error": {"code": -1, "message": "x"}, "id": 1})),
                    }
                }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let sc = SecondChance::new(BitcoindClient::new(
            format!("http://{addr}/"),
            "u".into(),
            "p".into(),
            std::time::Duration::from_secs(5),
        ));

        let unknown: Vec<[u8; 32]> = (0..n)
            .map(|i| {
                let mut t = [0u8; 32];
                t[..8].copy_from_slice(&(i as u64).to_be_bytes());
                t
            })
            .collect();
        let answer = sc.ask(TEMPLATE_HEIGHT, &unknown).await.expect("lookup");

        assert_eq!(probed.load(Ordering::SeqCst), n, "n = {n}");
        assert_eq!(answer.present_in_mempool.len(), n, "n = {n}");
        assert!(answer.unadjudicated.is_empty(), "n = {n}");
    }
}
```

Add this helper above `const TEMPLATE_HEIGHT`, since three tests now need to spawn a server from a bare handler function:

```rust
/// Spawn a `SecondChance` against an already-built router.
///
/// Takes a `Router` rather than a bare handler on purpose: generic over
/// `axum::handler::Handler<T, S>` needs bounds that are easy to get
/// subtly wrong and produce inscrutable trait errors, and every caller
/// here already has a one-route router to hand.
async fn spawn_router(app: Router) -> SecondChance {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    SecondChance::new(BitcoindClient::new(
        format!("http://{addr}/"),
        "u".into(),
        "p".into(),
        std::time::Duration::from_secs(5),
    ))
}
```

and extend the import line to:

```rust
use pool_verifier::second_chance::{MAX_RECENT_BLOCKS_SCANNED, MEMPOOL_PROBE_CHUNK, SecondChance};
```

Rewrite the two pre-existing tests that build a router inline (`a_failed_walk_is_distinguishable_from_a_healthy_empty_one` and `an_empty_fresh_mempool_is_refused_not_treated_as_an_answer`) to call `spawn_router(Router::new().route("/", post(mempool_only)))` and `spawn_router(Router::new().route("/", post(empty_mempool)))` respectively, deleting their inline listener/serve blocks.

- [ ] **Step 3: Run the tests to verify they fail**

```bash
cargo test -p pool-verifier --test pb40_walk_coverage 2>&1 | tail -25
```

Expected: compile error, `this method takes 2 arguments but 1 argument was supplied` and `cannot find value 'MEMPOOL_PROBE_CHUNK'`.

**Note on scope, learned the hard way:** changing `ask`'s signature breaks
`services/pool-verifier/src/ingress.rs:57`, which calls `lookup.ask(template_height)`.
Task 4 MUST update that one call site to `lookup.ask(template_height, unknown).await`
(the binding is already in scope), or the package does not compile and the task
cannot end committable. Change nothing else in `ingress.rs`; Task 5 owns the
decision rule. Note also that `cargo test -p pool-verifier --test <name>` still
builds the package's `[[bin]]` target, so a broken binary blocks even a scoped
integration-test run.

- [ ] **Step 4: Implement the probe path**

In `services/pool-verifier/src/second_chance.rs`, add the constant after `MAX_RECENT_BLOCKS_SCANNED`:

```rust
/// Transactions probed per JSON-RPC batch.
///
/// Derived, not picked. At roughly 600 bytes per `getmempoolentry`
/// reply a chunk response stays near 150 KB; the worst realistic
/// template (~3000 unknowns) bounds to 12 sequential round trips; and
/// every chunk boundary is a point where the deadline is re-checked.
/// A `const` and not a `[policy]` key: Invariant 4 does not want a knob
/// with one caller and one value.
pub const MEMPOOL_PROBE_CHUNK: usize = 250;
```

Add the error variant to `pub enum SecondChanceError`, after `BlockWalkIncomplete`:

```rust
    /// Some transactions could not be probed, and the decision would
    /// otherwise have been `upheld`. Absence from an incomplete probe
    /// set is not evidence, so the verdict is reported unadjudicated.
    #[error("mempool probe incomplete, so absence could not be established: {0}")]
    MempoolProbeIncomplete(String),
```

and its label in `as_label`:

```rust
            SecondChanceError::MempoolProbeIncomplete(_) => "mempool_probe_incomplete",
```

Replace `ask` and `gather` entirely:

```rust
    /// Ask bitcoind about the specific transactions the polled view did
    /// not contain, within [`SECOND_CHANCE_DEADLINE`].
    ///
    /// Cost is proportional to `unknown.len()`, not to mempool size.
    /// The whole-mempool fetch this replaced took 858 ms against 94,000
    /// transactions and exceeded its 2 second budget at 500,000, which
    /// meant the mechanism degraded exactly during the fee spikes that
    /// produce the most Class M rejections.
    ///
    /// # Errors
    ///
    /// [`SecondChanceError::Rpc`] when bitcoind answered badly,
    /// [`SecondChanceError::Deadline`] when it did not answer in time,
    /// [`SecondChanceError::EmptyMempool`] when its mempool is too
    /// small to establish anything. Either way the caller must let the
    /// original rejection stand: a lookup that could not run is not
    /// evidence of absence, and this module exists because that exact
    /// distinction was lost once already, when silently failing
    /// `bitcoin-cli` calls read as "transaction genuinely absent" for
    /// two rounds of investigation.
    pub async fn ask(
        &self,
        template_height: u32,
        unknown: &[[u8; 32]],
    ) -> Result<BitcoindAnswer, SecondChanceError> {
        tokio::time::timeout(
            SECOND_CHANCE_DEADLINE,
            self.gather(template_height, unknown),
        )
        .await
        .map_err(|_| SecondChanceError::Deadline)?
    }

    async fn gather(
        &self,
        template_height: u32,
        unknown: &[[u8; 32]],
    ) -> Result<BitcoindAnswer, SecondChanceError> {
        // 1. Degenerate-node guard, BEFORE any probe.
        //
        // The same floor the view install path applies
        // (`mempool_view::MIN_INSTALLABLE_MEMPOOL_SIZE`), for the same
        // reason. A bitcoind still loading `mempool.dat`, on the wrong
        // chain, or freshly restarted answers "not in mempool" for
        // EVERY txid, which is byte-identical to "it holds none of
        // them". Without this the targeted-probe change would silently
        // delete the guard that the whole-mempool fetch was carrying,
        // and every rejection in that window would be recorded as a
        // confirmed detection.
        let info = self.client.get_mempool_info().await?;
        if info.size < crate::mempool_view::MIN_INSTALLABLE_MEMPOOL_SIZE {
            warn!(
                size = info.size,
                min = crate::mempool_view::MIN_INSTALLABLE_MEMPOOL_SIZE,
                "second chance: bitcoind's mempool is empty or too small to establish absence; \
                 refusing to adjudicate against it. Every unknown transaction would probe as \
                 absent and the rejection would be recorded as a confirmed detection"
            );
            return Err(SecondChanceError::EmptyMempool);
        }

        // 2. Block walk FIRST. It is O(blocks) and it resolves the
        // worst case for the probe set: the mined case, where a block
        // arrives between template construction and this check and the
        // template's entire transaction set leaves the mempool at once.
        // Subtracting what it found keeps the probe set small exactly
        // when it would otherwise be largest.
        let coverage = self.recent_blocks(template_height).await;
        let block_walk_shortfall = coverage.shortfall();
        let (recent_block_txids, blocks_scanned, tip_height, block_walk_truncated) =
            coverage.parts();

        // 3. Probe only what the walk did not resolve. Deduplicated,
        // because a duplicated txid in the template would otherwise be
        // paid for twice.
        let to_probe: Vec<[u8; 32]> = unknown
            .iter()
            .copied()
            .filter(|t| !recent_block_txids.contains(t))
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        let mut present_in_mempool = HashSet::new();
        let mut unadjudicated = HashSet::new();
        for chunk in to_probe.chunks(MEMPOOL_PROBE_CHUNK) {
            // Sequential, not concurrent. Core's rpcworkqueue is shared
            // with the polling task, and inducing "Work queue depth
            // exceeded" is the documented trigger for the block walk
            // failing. This mechanism must not create the pressure that
            // breaks its own sibling.
            let probes = self.client.probe_mempool(chunk).await?;
            // `probe_mempool` returns a Vec index-aligned to its input
            // by construction, resolved by JSON-RPC id rather than by
            // position, so this zip is safe.
            for (txid, probe) in chunk.iter().zip(probes) {
                match probe {
                    MempoolProbe::Present => {
                        present_in_mempool.insert(*txid);
                    }
                    MempoolProbe::Absent => {}
                    MempoolProbe::Unadjudicated { reason } => {
                        warn!(reason = %reason, "second chance: a mempool probe gave no usable answer");
                        unadjudicated.insert(*txid);
                    }
                }
            }
        }

        Ok(BitcoindAnswer {
            present_in_mempool,
            unadjudicated,
            recent_block_txids,
            blocks_scanned,
            block_walk_truncated,
            tip_height,
            block_walk_shortfall,
        })
    }
```

Update the import line at the top of the file:

```rust
use crate::bitcoind_rpc::{BitcoindClient, MempoolProbe, RpcError};
```

- [ ] **Step 5: Run the tests to verify they pass**

```bash
cargo test -p pool-verifier --test pb40_walk_coverage 2>&1 | tail -20
```

Expected: `test result: ok. 8 passed` (4 pre-existing plus 4 new). Confirm 8, not 4.

- [ ] **Step 6: Mutation-proof the ordering and the guard**

Two mutations, run separately, restoring between each.

Mutation A, move the block walk after the probe by changing the filter to `.filter(|_| true)`:

```bash
cargo test -p pool-verifier --test pb40_walk_coverage 2>&1 | tail -20
```

Expected: `the_block_walk_runs_first_and_shrinks_the_probe_set` FAILS on the probe count.

Mutation B, change the guard to `if false`:

```bash
cargo test -p pool-verifier --test pb40_walk_coverage 2>&1 | tail -20
```

Expected: `an_empty_mempool_is_refused_before_any_probe_is_issued` FAILS.

Restore both and confirm 8 pass.

- [ ] **Step 7: Commit**

```bash
cargo fmt --all && ./scripts/gate.sh 2>&1 | tail -10
git add services/pool-verifier/src/second_chance.rs services/pool-verifier/tests/pb40_walk_coverage.rs
git commit -m "feat(pool-verifier): probe only the unknown txids, after the block walk (PB-40)"
```

---

### Task 5: Gate `upheld` on a complete probe set

**Files:**
- Modify: `services/pool-verifier/src/ingress.rs:45-115` (`run_second_chance`)
- Modify: `services/pool-verifier/src/ingress.rs:1068` (call site)

**Interfaces:**
- Consumes: `Adjudication.unadjudicated`, `SecondChanceError::MempoolProbeIncomplete`, the two-argument `ask`.
- Produces: no new public API. `verifier_phase2_second_chance_total{outcome="lookup_failed"}` gains `lookup_error_kind = "mempool_probe_incomplete"`.

- [ ] **Step 1: Confirm the call site already passes the unknown set**

Task 4 had to make this change to leave the package compiling, so it should
already be present. Verify:

```bash
grep -n "lookup.ask(" services/pool-verifier/src/ingress.rs
```

Expected: `match lookup.ask(template_height, unknown).await {`. If it still
reads `lookup.ask(template_height)`, make that change now.

- [ ] **Step 2: Add the probe-completeness gate**

In `run_second_chance`, immediately after the `if !adjudication.still_exceeds(tolerance_pct) { ... return ... }` block and BEFORE the existing `if let Some(shortfall) = answer.block_walk_shortfall.as_ref()` block, insert:

```rust
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
                    kind: reason.as_label().to_string(),
                    reason: reason.to_string(),
                });
            }
```

- [ ] **Step 3: Build and run the whole suite**

```bash
cargo build -p pool-verifier 2>&1 | tail -20
cargo test -p pool-verifier 2>&1 | grep -E "^test result"
```

Expected: build clean; every suite `ok` with zero failures.

- [ ] **Step 4: Verify the new label is reachable**

Confirm the kind string is produced by exactly one place and matches the metric documentation:

```bash
grep -rn "mempool_probe_incomplete" services/pool-verifier/src/
```

Expected: two hits, the `as_label` arm in `second_chance.rs` and nothing hardcoded in `ingress.rs` (the insert above derives it from `as_label`, never a literal).

- [ ] **Step 5: Commit**

```bash
cargo fmt --all && ./scripts/gate.sh 2>&1 | tail -10
git add services/pool-verifier/src/ingress.rs
git commit -m "fix(pool-verifier): an unadjudicated probe cannot produce an upheld verdict (PB-40)"
```

---

### Task 6: Tier 2 mock and end-to-end verdicts

**Files:**
- Modify: `services/pool-verifier/tests/phase2_tcp.rs`

**Interfaces:**
- Consumes: everything above, through the real `pool-verifier` binary.
- Produces: no API. Proves the wiring end to end.

The Tier 2 mock answers only `getrawmempool`, `getbestblockhash`, `getblock`. The verifier now calls `getmempoolinfo` and batch `getmempoolentry`, so without this task every Tier 2 second-chance test degrades to `lookup_failed` and several will fail.

- [ ] **Step 1: Teach the mock the two new RPCs**

In `services/pool-verifier/tests/phase2_tcp.rs`, `rpc_handler` currently takes `Json(req): Json<RpcRequest>`. A batch arrives as an array and will not deserialize into `RpcRequest`, so change the extractor to `Json(raw): Json<Value>` and parse from there. Replace the function signature and add a batch branch at the very top:

```rust
async fn rpc_handler(State(state): State<MockState>, Json(raw): Json<Value>) -> impl IntoResponse {
    state.request_count.fetch_add(1, Ordering::SeqCst);

    if state.always_fail.load(Ordering::SeqCst) || state.fail_next.swap(false, Ordering::SeqCst) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "result": null,
                "error": {"code": -32603, "message": "mock-induced failure"},
                "id": null,
            })),
        );
    }

    // PB-40 targeted probes arrive as a JSON-RPC batch. Answer from the
    // same txid set `getrawmempool` serves, so a test that seeds the
    // mempool sees the same answer through either path.
    if let Some(items) = raw.as_array() {
        let held: Vec<String> = state.display_hex_txids.read().expect("mock lock").clone();
        let replies: Vec<Value> = items
            .iter()
            .map(|item| {
                let wanted = item
                    .get("params")
                    .and_then(|p| p.get(0))
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let id = item.get("id").cloned().unwrap_or(Value::Null);
                if held.iter().any(|h| h == wanted) {
                    json!({"id": id, "result": {"vsize": 141}, "error": Value::Null})
                } else {
                    json!({
                        "id": id,
                        "result": Value::Null,
                        "error": {"code": -5, "message": "Transaction not in mempool"},
                    })
                }
            })
            .collect();
        return (StatusCode::OK, Json(Value::Array(replies)));
    }

    let method = raw.get("method").and_then(Value::as_str).unwrap_or("");
    let id = raw.get("id").cloned().unwrap_or(Value::Null);

    if method == "getmempoolinfo" {
        let size = state.display_hex_txids.read().expect("mock lock").len();
        return (
            StatusCode::OK,
            Json(json!({"result": {"size": size}, "error": null, "id": id})),
        );
    }
```

Then replace the ENTIRE remainder of the function body, from the existing `if req.method == "getbestblockhash" || req.method == "getblock" {` line to the closing brace, with this. It is the same logic reading `method` and `id` instead of `req.method` and `req.id`:

```rust
    // PB-40 second-chance block RPCs. A test that never seeds
    // `tip_block` gets the same error Bitcoin Core would give for an
    // unknown block, which is the path the block walk must survive.
    if method == "getbestblockhash" || method == "getblock" {
        let tip = state.tip_block.read().expect("mock lock").clone();
        let Some(tip) = tip else {
            return (
                StatusCode::OK,
                Json(json!({
                    "result": null,
                    "error": {"code": -5, "message": "Block not found"},
                    "id": id,
                })),
            );
        };
        if method == "getbestblockhash" {
            return (
                StatusCode::OK,
                Json(json!({"result": tip.hash, "error": null, "id": id})),
            );
        }
        return (
            StatusCode::OK,
            Json(json!({
                "result": {
                    "hash": tip.hash,
                    "height": tip.height,
                    "tx": tip.display_hex_txids,
                    // Null terminates the verifier's walk after this
                    // block, modelling a single block arriving between
                    // template construction and the Class M check.
                    "previousblockhash": Value::Null,
                },
                "error": null,
                "id": id,
            })),
        );
    }

    if method != "getrawmempool" {
        return (
            StatusCode::OK,
            Json(json!({
                "result": null,
                "error": {"code": -32601, "message": "method not supported"},
                "id": id,
            })),
        );
    }

    let txids = state.display_hex_txids.read().expect("mock lock");
    (
        StatusCode::OK,
        Json(json!({
            "result": *txids,
            "error": null,
            "id": id,
        })),
    )
}
```

`getrawmempool` is kept in the mock because the verifier's 10-second POLLING task still calls it; only the second-chance path stopped.

The `RpcRequest` struct is now unused. Delete it, and delete `use serde::Deserialize;` if nothing else in the file needs it (check with `grep -n "Deserialize" services/pool-verifier/tests/phase2_tcp.rs` first).

- [ ] **Step 2: Run the Tier 2 suite**

```bash
cargo test -p pool-verifier --test phase2_tcp -- --ignored --test-threads=2 2>&1 | tail -20
```

Expected: `test result: ok. 10 passed`. Confirm the count is 10 and that `0 filtered out`.

If `phase2_tcp_second_chance_withdraws_a_stale_view_false_positive` fails, the batch branch is not reading the seeded txid set; check that the test seeds `display_hex_txids` before the template round-trip.

- [ ] **Step 3: Add a Tier 2 test for the new outcome**

Append to `services/pool-verifier/tests/phase2_tcp.rs`:

```rust
/// A probe that cannot establish absence must not produce `upheld`.
///
/// The mempool is healthy and populated, so the degenerate-node guard
/// does not fire, but every probe answers with an unexpected error. The
/// rejection stands and is recorded unadjudicated.
#[tokio::test]
#[ignore = "Tier 2: spawns pool-verifier subprocess; run with --ignored"]
async fn phase2_tcp_unadjudicated_probe_is_not_upheld() {
    let (template, _display_hex) = regtest_segwit_template_and_display_hex();
    let booted = boot_with_frozen_view(decoy_display_hex_txids(8)).await;

    // A healthy tip so the block walk completes and cannot be the
    // reason for the unadjudicated outcome.
    {
        let mut g = booted.mock.tip_block.write().expect("mock write lock");
        *g = Some(MockBlock {
            hash: "a".repeat(64),
            height: 101,
            display_hex_txids: vec![],
        });
    }
    booted.mock.probe_error_code.store(-32603, Ordering::SeqCst);

    let verdict = round_trip_template(booted.verifier_port, template).await;

    let metrics = fetch_metrics_text(booted.http_port).await;
    let upheld = parse_counter(
        &metrics,
        "verifier_phase2_second_chance_total{outcome=\"upheld\"}",
    );
    let failed = parse_counter(
        &metrics,
        "verifier_phase2_second_chance_total{outcome=\"lookup_failed\"}",
    );
    drop(booted);

    assert!(!verdict.accepted, "the rejection still stands");
    assert_eq!(
        upheld, 0,
        "a probe that established nothing cannot support a detection claim\n\
         --- metrics ---\n{metrics}"
    );
    assert_eq!(failed, 1, "--- metrics ---\n{metrics}");
}
```

Add the knob to `MockState`:

```rust
    /// PB-40: error code every batch probe replies with. `-5` is the
    /// normal "not in mempool"; anything else drives the unadjudicated
    /// path.
    probe_error_code: Arc<std::sync::atomic::AtomicI64>,
```

initialise it in `make_mock_state` with `probe_error_code: Arc::new(std::sync::atomic::AtomicI64::new(-5)),`, and in the batch branch replace the hardcoded `-5` with `state.probe_error_code.load(Ordering::SeqCst)`.

- [ ] **Step 4: Run Tier 2 again**

```bash
cargo test -p pool-verifier --test phase2_tcp -- --ignored --test-threads=2 2>&1 | tail -20
```

Expected: `test result: ok. 11 passed`.

- [ ] **Step 5: Mutation-proof the gate**

Temporarily change `if adjudication.unadjudicated > 0` in `ingress.rs` to `if false`. Run the Tier 2 suite. Expected: `phase2_tcp_unadjudicated_probe_is_not_upheld` FAILS. Restore and confirm 11 pass.

- [ ] **Step 6: Commit**

```bash
cargo fmt --all && ./scripts/gate.sh 2>&1 | tail -10
git add services/pool-verifier/tests/phase2_tcp.rs services/pool-verifier/src/ingress.rs
git commit -m "test(pool-verifier): Tier 2 coverage for targeted probes (PB-40)"
```

---

### Task 7: Prove the acceptance criterion, then document

**Files:**
- Create then delete: `services/pool-verifier/tests/zz_latency_probe.rs` (throwaway, never committed)
- Modify: `docs/runbooks/phase2-shadow-soak.md`
- Modify: `/Users/a14808/ReserveGrid-OS/docs/DEVLOG.md` (MAIN checkout, gitignored)

**Interfaces:** none. This task produces the measurement that justifies the change and the docs that keep the operator procedure true.

- [ ] **Step 1: Write the measurement probe**

Create `services/pool-verifier/tests/zz_latency_probe.rs`:

```rust
//! THROWAWAY measurement probe. Delete before committing.
//!
//! Acceptance criterion for the PB-40 targeted-probe change: lookup
//! latency must be FLAT across mempool size. Before the change it was
//! 858 ms at 94k, 1648 ms at 200k, and over the 2s deadline at 500k.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use axum::{Json, Router, routing::post};
use serde_json::{Value, json};
use std::time::Instant;
use tokio::net::TcpListener;

const N_UNKNOWN: usize = 187;

async fn handler(Json(req): Json<Value>) -> Json<Value> {
    if let Some(items) = req.as_array() {
        let replies: Vec<Value> = items
            .iter()
            .map(|item| {
                json!({
                    "id": item.get("id").cloned().unwrap_or(Value::Null),
                    "result": {"vsize": 141, "weight": 561, "time": 1,
                               "height": 1, "descendantcount": 1, "ancestorcount": 1},
                    "error": Value::Null,
                })
            })
            .collect();
        return Json(Value::Array(replies));
    }
    match req.get("method").and_then(Value::as_str).unwrap_or("") {
        // `size` is the ONLY mempool-size-dependent value the new path
        // reads, and it is one integer. That is the point.
        "getmempoolinfo" => Json(json!({"result": {"size": 94_211}, "error": null, "id": 1})),
        "getbestblockhash" => Json(json!({"result": "f".repeat(64), "error": null, "id": 1})),
        "getblock" => Json(json!({
            "result": {"hash": "f".repeat(64), "height": 899_999,
                       "tx": [], "previousblockhash": Value::Null},
            "error": null, "id": 1
        })),
        _ => Json(json!({"result": null, "error": {"code": -32601, "message": "no"}, "id": 1})),
    }
}

#[tokio::test]
#[ignore = "measurement probe"]
async fn measure_flat_across_mempool_size() {
    for declared_mempool in [94_000usize, 200_000, 500_000] {
        let app = Router::new().route("/", post(handler));
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(l, app).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let sc = pool_verifier::second_chance::SecondChance::new(
            pool_verifier::bitcoind_rpc::BitcoindClient::new(
                format!("http://{addr}/"),
                "u".into(),
                "p".into(),
                std::time::Duration::from_secs(5),
            ),
        );
        let unknown: Vec<[u8; 32]> = (0..N_UNKNOWN)
            .map(|i| {
                let mut t = [0u8; 32];
                t[..8].copy_from_slice(&(i as u64).to_be_bytes());
                t
            })
            .collect();

        let _ = sc.ask(900_000, &unknown).await;
        let mut worst = 0u128;
        for _ in 0..3 {
            let t = Instant::now();
            let r = sc.ask(900_000, &unknown).await;
            worst = worst.max(t.elapsed().as_millis());
            assert!(r.is_ok(), "declared {declared_mempool}: {:?}", r.err().map(|e| e.to_string()));
        }
        println!("DECLARED MEMPOOL {declared_mempool:>7} -> ask() worst {worst:>5}ms with N={N_UNKNOWN}");
    }
}
```

- [ ] **Step 2: Run the measurement**

```bash
cargo test -p pool-verifier --test zz_latency_probe -- --ignored --nocapture 2>&1 | grep -E "DECLARED|test result"
```

Expected: three `DECLARED MEMPOOL` lines whose worst-case milliseconds are approximately equal, all well under 2000. **If the three numbers differ by more than roughly 2x, the acceptance criterion has NOT been met** and something still scales with mempool size. Stop and investigate rather than proceeding.

Record the three numbers; they go in the DEVLOG in Step 5.

- [ ] **Step 3: Delete the probe**

```bash
rm services/pool-verifier/tests/zz_latency_probe.rs
```

- [ ] **Step 4: Update the runbook**

In `docs/runbooks/phase2-shadow-soak.md`, find the `lookup_failed` bullet list of four kinds and add a fifth entry after `block_walk_incomplete`:

```markdown
     - `mempool_probe_incomplete`: bitcoind was reachable but one or more transactions got no usable answer from `getmempoolentry`, so absence could not be established for all of them. Read `lookup_error` for the count.
```

In the same list, replace the `deadline` entry with:

```markdown
     - `deadline`: bitcoind was too slow for the 2s budget. The lookup's cost is proportional to the number of unknown transactions, not to mempool size, so a run of these means either a very large unknown set or a slow node, NOT congestion.
```

- [ ] **Step 5: Confirm ADR-003 did not go stale**

The spec flags ADR-003 as conditionally in scope. Check the PB-40 amendment's description of the mechanism against what now ships:

```bash
sed -n '168,180p' docs/ADR-003-mempool-ground-truth.md
```

Expected: it says the verifier "asks bitcoind directly about the specific unknown transactions", which this change makes MORE literally true rather than less, since it moves from set membership in a snapshot to a per-transaction query. **No edit required.** If the wording you find instead describes a whole-mempool fetch, correct it in this commit.

- [ ] **Step 6: Write the DEVLOG entry**

Prepend to `/Users/a14808/ReserveGrid-OS/docs/DEVLOG.md`, immediately after the line `Newest entries at top.` and its following `---`:

```markdown
## 2026-08-05 - PB-40: the second-chance lookup now costs O(unknowns)

T2. `services/pool-verifier/src/{bitcoind_rpc.rs,second_chance.rs,ingress.rs}`,
`services/pool-verifier/tests/{pb40_walk_coverage.rs,phase2_tcp.rs}`,
`docs/runbooks/phase2-shadow-soak.md`.

Implements `docs/superpowers/specs/2026-08-05-pb40-targeted-mempool-probe-design.md`.

The lookup fetched the whole mempool to test membership, so its cost scaled with
congestion rather than with the work to be done: 858 ms at 94k transactions,
1648 ms at 200k, over the 2s deadline at 500k. Mainnet passes 200k during fee
spikes, which is when Class M rejections spike, so the mechanism degraded
exactly when it was needed. It now probes only the unknown transactions, via
chunked sequential batch `getmempoolentry`, after the O(blocks) block walk has
subtracted everything it found mined.

**Acceptance criterion met.** Latency across declared mempool sizes of 94k /
200k / 500k with a fixed N=187: REPLACE_WITH_THE_THREE_MEASURED_NUMBERS. Flat,
against a curve that previously ended in a blown deadline.

Three things this had to not get wrong, each a way the change could have
silently reintroduced a hazard:

- A `getmempoolinfo` floor replaces the empty-mempool guard the deleted
  whole-mempool fetch was carrying. Without it, a bitcoind still loading
  `mempool.dat` answers "not in mempool" for every txid, byte-identical to
  "holds none of them". Same hazard as `8a2a3c9` and `7d891bc`, third costume.
  The test asserts the probe count is ZERO, not merely that the error is right,
  because a guard that fires after probing would pass the weaker test.
- Batch replies are correlated by `id`, never by position. A position-zip would
  misattribute every verdict in a chunk and would be invisible to any mock that
  replies in order, so reordered, missing, duplicated and out-of-range ids are
  all tested.
- Only error `-5` counts as a proven absence; every other code is
  `Unadjudicated`. The code is BELIEVED correct and remains UNVERIFIED against a
  real node. The design is fail-safe about that: if it is wrong, every probe
  becomes unadjudicated and the outcome is `lookup_failed`, which is loud. It
  cannot degrade into "all absent", which would fabricate detections.

`still_absent` narrows from "not found" to "proven absent", with the unproven
cases moving to a disjoint `unadjudicated` count. The old breadth is what let an
unestablished count read as evidence. An unadjudicated probe now blocks an
`upheld` for the same reason an incomplete block walk does, and blocks neither a
`withdrawn`, because counting the unproven pessimistically can only hold a
rejection, never manufacture a recovery.

**Still open:** the `-5` code needs verifying on the node at rollout, and four
T2 review lenses have never executed.

---
```

Replace `REPLACE_WITH_THE_THREE_MEASURED_NUMBERS` with the actual figures from Step 2.

- [ ] **Step 7: Full verification sweep**

```bash
cd /Users/a14808/ReserveGrid-OS/.claude/worktrees/reservegrid-os-dev-c70b0d
cargo fmt --all --check && echo "fmt oracle CLEAN"
cargo test --workspace 2>&1 | grep -cE "^test result: FAILED"
cargo test -p pool-verifier --test phase2_tcp -- --ignored --test-threads=2 2>&1 | grep -E "^test result"
cargo test -p pool-verifier --test pb40_walk_coverage 2>&1 | grep -E "^test result"
./scripts/superscan.sh --deep-only 2>&1 | tail -3
git status --short
```

Expected: fmt clean; `0` failed suites; Tier 2 `11 passed`; walk coverage `8 passed`; superscan all pass; `git status` shows only the runbook modification plus the two untracked entries `.claude-flow/` and `scripts/gate.sh`. **`zz_latency_probe.rs` must NOT appear.**

- [ ] **Step 8: Commit**

```bash
./scripts/gate.sh 2>&1 | tail -10
git add docs/runbooks/phase2-shadow-soak.md
git commit -m "docs(pool-verifier): record the O(unknowns) result and the new lookup_failed kind (PB-40)"
./scripts/gate.sh 2>&1 | tail -10
```

Expected on the second gate run: `gate: pass` with all six checks `ok`, including `fmt` and `inversion`.

---

## After the plan

This is a T2 surface. The plan is not finished when the tests pass. Hand the resulting commits to an independent reviewer in an isolated worktree who **executes** the claims rather than reading the diff, per `.claude/CLAUDE.md`. Copy `scripts/gate.sh` and `services/rg-dashboard/frontend/dist` into that worktree or the reviewer silently downgrades to a reader, and tell the reviewer to background cargo builds and poll: a cold build in a fresh worktree is silent for longer than the 180 second stall timeout, which killed three reviewers in an earlier round.

The four review lenses that have never executed against this branch still gate the merge: adjudication arithmetic, bitcoind answer integrity, evidence durability, and blast radius plus doctrine.
