//! PB-40: block-walk coverage, against a multi-block bitcoind.
//!
//! The Tier 2 mock in `phase2_tcp.rs` serves a chain of length one
//! (`previousblockhash: null`), so it cannot drive the walk past a
//! single block and no test there can reach the cap. These drive
//! `SecondChance::ask()` directly against a walkable chain, in-process,
//! so they run in the default suite rather than behind `--ignored`.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{Value, json};
use tokio::net::TcpListener;

use pool_verifier::bitcoind_rpc::BitcoindClient;
use pool_verifier::second_chance::{MAX_RECENT_BLOCKS_SCANNED, MEMPOOL_PROBE_CHUNK, SecondChance};

/// A walkable chain: block at height `h` has hash `hex(h)` and parent
/// `hex(h-1)`, and carries one distinctive txid so a caller can tell
/// which blocks were actually collected.
#[derive(Clone)]
struct Chain {
    tip_height: u32,
}

fn block_hash(height: u32) -> String {
    format!("{height:064x}")
}

/// The txid this synthetic chain puts in the block at `height`.
fn tx_in_block(height: u32) -> [u8; 32] {
    let mut t = [0u8; 32];
    t[..4].copy_from_slice(&height.to_be_bytes());
    t[31] = 0xAB;
    t
}

fn display_hex(txid: [u8; 32]) -> String {
    let mut d = txid;
    d.reverse();
    hex::encode(d)
}

/// Build one JSON-RPC batch reply entry for a single probed item.
///
/// `present` decides whether it reports as held. `error_code` is the
/// code used when it does not: `-5` is Core's "not in mempool",
/// anything else drives the unadjudicated path. Shared by [`batch_reply`]
/// (one answer for every item) and [`keyed_batch_reply`] (the answer
/// depends on which item it is), so the reply shape exists once.
fn reply_for(id: &Value, present: bool, error_code: i64) -> Value {
    if present {
        json!({"id": id, "result": {"vsize": 141}, "error": Value::Null})
    } else {
        json!({
            "id": id,
            "result": Value::Null,
            "error": {"code": error_code, "message": "Transaction not in mempool"},
        })
    }
}

/// Reply to a JSON-RPC batch, echoing each request's `id`.
///
/// `present` decides whether every probed transaction reports as held,
/// uniformly. `error_code` is the code used when it does not.
fn batch_reply(items: &[Value], present: bool, error_code: i64) -> Json<Value> {
    let replies: Vec<Value> = items
        .iter()
        .map(|item| {
            let id = item.get("id").cloned().unwrap_or(Value::Null);
            reply_for(&id, present, error_code)
        })
        .collect();
    Json(Value::Array(replies))
}

/// Reply to a JSON-RPC batch, deciding Present vs not-in-mempool PER
/// ITEM by reading the requested txid out of that item's own `params`.
///
/// A uniform answer cannot catch a misattribution bug: if a caller
/// lines up verdicts against the wrong request, every permutation of
/// the same uniform answer looks identical. Keying the answer to the
/// txid actually named in each request's `params` makes a swapped
/// pairing produce a different, checkable set of verdicts.
fn keyed_batch_reply(
    items: &[Value],
    present: impl Fn([u8; 32]) -> bool,
    error_code: i64,
) -> Json<Value> {
    let replies: Vec<Value> = items
        .iter()
        .map(|item| {
            let id = item.get("id").cloned().unwrap_or(Value::Null);
            let hex_str = item
                .get("params")
                .and_then(|p| p.get(0))
                .and_then(Value::as_str)
                .expect("getmempoolentry params carry the txid as a display-order hex string");
            let mut internal: [u8; 32] = hex::decode(hex_str)
                .expect("valid hex")
                .try_into()
                .expect("32-byte txid");
            internal.reverse(); // display order -> internal order
            reply_for(&id, present(internal), error_code)
        })
        .collect();
    Json(Value::Array(replies))
}

async fn rpc(State(chain): State<Chain>, Json(req): Json<Value>) -> Json<Value> {
    // A JSON-RPC batch arrives as an ARRAY. This chain never holds the
    // template's transactions, so every probe answers "not in mempool".
    if let Some(items) = req.as_array() {
        return batch_reply(items, false, -5);
    }
    let method = req.get("method").and_then(Value::as_str).unwrap_or("");
    match method {
        // Healthy, populated node: the degenerate-node floor must not trip.
        "getmempoolinfo" => Json(json!({
            "result": {"loaded": true, "size": 94_211}, "error": null, "id": 1
        })),
        "getbestblockhash" => Json(json!({
            "result": block_hash(chain.tip_height), "error": null, "id": 1
        })),
        "getblock" => {
            let hash = req
                .get("params")
                .and_then(|p| p.get(0))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let height = u32::from_str_radix(hash.trim_start_matches('0'), 16).unwrap_or(0);
            Json(json!({
                "result": {
                    "hash": hash,
                    "height": height,
                    "tx": [display_hex(tx_in_block(height))],
                    "previousblockhash": if height == 0 { Value::Null }
                                         else { json!(block_hash(height - 1)) },
                },
                "error": null, "id": 1
            }))
        }
        _ => Json(json!({"result": null, "error": {"code": -32601, "message": "no"}, "id": 1})),
    }
}

async fn spawn(tip_height: u32) -> SecondChance {
    let app = Router::new()
        .route("/", post(rpc))
        .with_state(Chain { tip_height });
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

/// A bitcoind that answers `getrawmempool` and errors on everything
/// else: the mempool half of the lookup succeeds, the block walk does not.
async fn mempool_only(Json(req): Json<Value>) -> Json<Value> {
    if let Some(items) = req.as_array() {
        return batch_reply(items, false, -5);
    }
    if req.get("method").and_then(Value::as_str) == Some("getmempoolinfo") {
        return Json(json!({"result": {"loaded": true, "size": 94_211}, "error": null, "id": 1}));
    }
    Json(json!({
        "result": null,
        "error": {"code": -5, "message": "Work queue depth exceeded"},
        "id": 1
    }))
}

/// A bitcoind whose mempool is successfully, uselessly empty. Reports
/// `loaded: true` so this exercises the size floor specifically, not
/// the separate `loaded` guard.
async fn empty_mempool(Json(req): Json<Value>) -> Json<Value> {
    if req.get("method").and_then(Value::as_str) == Some("getmempoolinfo") {
        return Json(json!({"result": {"loaded": true, "size": 0}, "error": null, "id": 1}));
    }
    Json(json!({"result": null, "error": {"code": -5, "message": "n/a"}, "id": 1}))
}

/// The unknown set these coverage tests probe with. One txid that this
/// synthetic chain never mines and never holds in its mempool, so the
/// mempool half is constant and the block walk is the only variable.
fn probe_set() -> Vec<[u8; 32]> {
    vec![[0x7Eu8; 32]]
}

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

const TEMPLATE_HEIGHT: u32 = 800_000;

/// Truncation must mean "blocks were lost", not "the cap number was
/// reached".
///
/// The cap check used to run BEFORE the terminator that stops at the
/// template's own height, so a walk that scanned exactly
/// `MAX_RECENT_BLOCKS_SCANNED` blocks and had nothing left to want
/// still reported `truncated`. The first thing that flag would have
/// shown an operator is a false alarm. Heights decrease by exactly one
/// per step, so once the block being collected IS the template height
/// there is provably nothing below it left to want.
#[tokio::test]
async fn truncation_reports_only_when_blocks_were_actually_lost() {
    // gap = tip - template_height. Blocks the walk owes = gap + 1.
    // With a cap of 6, gap 5 owes exactly 6: complete, not truncated.
    for gap in 0..=4u32 {
        let sc = spawn(TEMPLATE_HEIGHT + gap).await;
        let answer = sc.ask(TEMPLATE_HEIGHT, &probe_set()).await.expect("lookup");
        assert!(
            !answer.block_walk_truncated,
            "gap {gap} owes {} blocks, under the cap; must not report truncated",
            gap + 1
        );
        assert!(answer.block_walk_shortfall.is_none(), "gap {gap}");
        assert_eq!(answer.blocks_scanned, gap + 1, "gap {gap}");
    }

    // The boundary that used to be wrong.
    let sc = spawn(TEMPLATE_HEIGHT + MAX_RECENT_BLOCKS_SCANNED - 1).await;
    let answer = sc.ask(TEMPLATE_HEIGHT, &probe_set()).await.expect("lookup");
    assert_eq!(answer.blocks_scanned, MAX_RECENT_BLOCKS_SCANNED);
    assert!(
        !answer.block_walk_truncated,
        "a walk that scanned exactly the cap AND reached the template height lost nothing, \
         so it is complete, not truncated"
    );
    assert!(answer.block_walk_shortfall.is_none());
    // And it really did collect the block at the template's own height.
    assert!(
        answer
            .recent_block_txids
            .contains(&tx_in_block(TEMPLATE_HEIGHT)),
        "the last block the walk owed must actually be in the answer"
    );

    // One block further and the walk genuinely loses coverage.
    let sc = spawn(TEMPLATE_HEIGHT + MAX_RECENT_BLOCKS_SCANNED).await;
    let answer = sc.ask(TEMPLATE_HEIGHT, &probe_set()).await.expect("lookup");
    assert!(
        answer.block_walk_truncated,
        "owing {} blocks against a cap of {MAX_RECENT_BLOCKS_SCANNED} must report truncated",
        MAX_RECENT_BLOCKS_SCANNED + 1
    );
    assert!(answer.block_walk_shortfall.is_some());
    assert!(
        !answer
            .recent_block_txids
            .contains(&tx_in_block(TEMPLATE_HEIGHT)),
        "the block at the template height is exactly what a truncated walk failed to reach"
    );
}

/// The steady state: the tip has not advanced past the template's
/// parent, so nothing has been mined since it was built. Zero blocks
/// scanned is the CORRECT and COMPLETE answer here, which is precisely
/// why a failed walk reporting the same zero was indistinguishable.
#[tokio::test]
async fn tip_below_the_template_is_complete_coverage_not_a_shortfall() {
    let sc = spawn(TEMPLATE_HEIGHT - 1).await;
    let answer = sc.ask(TEMPLATE_HEIGHT, &probe_set()).await.expect("lookup");

    assert_eq!(answer.blocks_scanned, 0);
    assert!(!answer.block_walk_truncated);
    assert!(
        answer.block_walk_shortfall.is_none(),
        "nothing was owed, so nothing fell short"
    );
    assert_eq!(
        answer.tip_height,
        Some(TEMPLATE_HEIGHT - 1),
        "the tip must be recorded so a reader can check blocks_scanned against the gap owed"
    );
}

/// The record must carry enough to tell a healthy zero-block walk from
/// one that never ran. Both report `blocks_scanned: 0`.
#[tokio::test]
async fn a_failed_walk_is_distinguishable_from_a_healthy_empty_one() {
    let healthy = spawn(TEMPLATE_HEIGHT - 1)
        .await
        .ask(TEMPLATE_HEIGHT, &probe_set())
        .await
        .expect("healthy lookup");

    let broken = spawn_router(Router::new().route("/", post(mempool_only)))
        .await
        .ask(TEMPLATE_HEIGHT, &probe_set())
        .await
        .expect("mempool half still succeeds");

    assert_eq!(healthy.blocks_scanned, broken.blocks_scanned, "both are 0");
    assert_eq!(healthy.block_walk_truncated, broken.block_walk_truncated);
    assert!(
        healthy.block_walk_shortfall.is_none() && broken.block_walk_shortfall.is_some(),
        "the shortfall is the ONLY thing separating these two, and it is what stops a walk \
         that never ran from being recorded as a completed adjudication"
    );
}

/// An empty-but-successful getmempoolinfo cannot establish that any
/// transaction is absent, so it is refused rather than adjudicated.
#[tokio::test]
async fn an_empty_fresh_mempool_is_refused_not_treated_as_an_answer() {
    let sc = spawn_router(Router::new().route("/", post(empty_mempool))).await;

    let err = sc.ask(TEMPLATE_HEIGHT, &probe_set()).await.expect_err(
        "an empty mempool must be refused: scoring every unknown absent against it would \
         uphold the rejection and record it as a confirmed detection",
    );
    assert_eq!(err.as_label(), "empty_mempool");
}

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
    let app = Router::new().route(
        "/",
        post(move |Json(req): Json<Value>| {
            let counter = Arc::clone(&counter);
            async move {
                if let Some(items) = req.as_array() {
                    counter.fetch_add(items.len(), Ordering::SeqCst);
                    return batch_reply(items, false, -5);
                }
                match req.get("method").and_then(Value::as_str).unwrap_or("") {
                    "getmempoolinfo" => Json(
                        json!({"result": {"loaded": true, "size": 94_211}, "error": null, "id": 1}),
                    ),
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

    let answer = sc
        .ask(TEMPLATE_HEIGHT, &[mined_txid])
        .await
        .expect("lookup");

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
///
/// `empty_mempool` itself is not batch-aware, so a premature probe
/// against it would blow up on deserialization rather than fail this
/// assertion: the plain mock's fallback arm answers a batch array with
/// a bare object, which is a shape the client-side batch parser cannot
/// accept. That is an INCIDENTAL protection, not the one this test
/// claims to provide, so the router here is batch-aware and counts
/// every txid it is actually asked about, the same way
/// `the_block_walk_runs_first_and_shrinks_the_probe_set` does. If the
/// guard-before-probe ordering ever regresses, this fails on the
/// count, not on a parser panic that would also fire for unrelated
/// reasons.
#[tokio::test]
async fn an_empty_mempool_is_refused_before_any_probe_is_issued() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let probed = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&probed);

    let app = Router::new().route(
        "/",
        post(move |Json(req): Json<Value>| {
            let counter = Arc::clone(&counter);
            async move {
                if let Some(items) = req.as_array() {
                    counter.fetch_add(items.len(), Ordering::SeqCst);
                    return batch_reply(items, false, -5);
                }
                if req.get("method").and_then(Value::as_str) == Some("getmempoolinfo") {
                    // `loaded: true` so this drives the size floor
                    // specifically, not the separate `loaded` guard.
                    return Json(
                        json!({"result": {"loaded": true, "size": 0}, "error": null, "id": 1}),
                    );
                }
                Json(json!({"result": null, "error": {"code": -5, "message": "n/a"}, "id": 1}))
            }
        }),
    );
    let sc = spawn_router(app).await;

    let err = sc
        .ask(TEMPLATE_HEIGHT, &probe_set())
        .await
        .expect_err("an empty mempool must be refused");

    assert_eq!(err.as_label(), "empty_mempool");
    assert_eq!(
        probed.load(Ordering::SeqCst),
        0,
        "the degenerate-mempool guard must fire before any probe is issued"
    );
}

/// A bitcoind still loading `mempool.dat` is refused BEFORE any probe
/// is issued, even though its reported `size` is well above the
/// installable floor. This is the exact case a bare size check misses:
/// live peer relay can already have pushed `size` to a realistic value
/// while the node has not finished replaying its saved mempool, so
/// every probe would still answer "not in mempool" for a reason that
/// has nothing to do with absence.
#[tokio::test]
async fn a_mempool_still_loading_is_refused_before_any_probe_is_issued() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let probed = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&probed);

    let app = Router::new().route(
        "/",
        post(move |Json(req): Json<Value>| {
            let counter = Arc::clone(&counter);
            async move {
                if let Some(items) = req.as_array() {
                    counter.fetch_add(items.len(), Ordering::SeqCst);
                    return batch_reply(items, false, -5);
                }
                if req.get("method").and_then(Value::as_str) == Some("getmempoolinfo") {
                    // A realistic size, well above the installable
                    // floor, paired with `loaded: false`: the shape
                    // that only the `loaded` guard, not the size
                    // floor, can catch.
                    return Json(
                        json!({"result": {"loaded": false, "size": 94_211}, "error": null, "id": 1}),
                    );
                }
                Json(json!({"result": null, "error": {"code": -5, "message": "n/a"}, "id": 1}))
            }
        }),
    );
    let sc = spawn_router(app).await;

    let err = sc
        .ask(TEMPLATE_HEIGHT, &probe_set())
        .await
        .expect_err("a still-loading mempool must be refused");

    assert_eq!(err.as_label(), "mempool_loading");
    assert_eq!(
        probed.load(Ordering::SeqCst),
        0,
        "the loaded guard must fire before any probe is issued, exactly like the size guard"
    );
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
            "getmempoolinfo" => {
                Json(json!({"result": {"loaded": true, "size": 94_211}, "error": null, "id": 1}))
            }
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

/// Whether the synthetic txid built for index `i` in this test must
/// come back `Present`. Shared between the mock, which decides each
/// item's answer by decoding the txid out of its own request, and the
/// assertion, which computes the expected set the same way: any
/// mismatch (for example a probe verdict attached to the wrong
/// transaction) then changes WHICH txids land in `present_in_mempool`,
/// not just how many.
fn should_be_present(txid: [u8; 32]) -> bool {
    u64::from_be_bytes(txid[..8].try_into().expect("8 bytes")) % 2 == 0
}

/// Chunking must not drop, duplicate, or misattribute a transaction at
/// the boundary. The mock's answer is keyed to each txid's own identity
/// (`should_be_present`), not uniform, so a verdict attached to the
/// wrong transaction changes the specific membership of
/// `present_in_mempool` and is caught by the identity assertion below,
/// not just an aggregate count.
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
                        return keyed_batch_reply(items, should_be_present, -5);
                    }
                    match req.get("method").and_then(Value::as_str).unwrap_or("") {
                        "getmempoolinfo" => Json(json!({
                            "result": {"loaded": true, "size": 94_211}, "error": null, "id": 1
                        })),
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

        let expected_present: std::collections::HashSet<[u8; 32]> = unknown
            .iter()
            .copied()
            .filter(|t| should_be_present(*t))
            .collect();
        assert_eq!(
            answer.present_in_mempool, expected_present,
            "n = {n}: present_in_mempool must hold exactly the txids the mock marked \
             present, keyed by their own identity, not any other permutation of the \
             same count"
        );
        assert!(answer.unadjudicated.is_empty(), "n = {n}");
    }
}
