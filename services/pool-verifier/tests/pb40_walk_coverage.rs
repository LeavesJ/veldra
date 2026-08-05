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
use pool_verifier::second_chance::{MAX_RECENT_BLOCKS_SCANNED, SecondChance};

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

async fn rpc(State(chain): State<Chain>, Json(req): Json<Value>) -> Json<Value> {
    let method = req.get("method").and_then(Value::as_str).unwrap_or("");
    match method {
        // Non-empty so the second chance's empty-mempool floor does not
        // trip; deliberately holds none of the template's txids.
        "getrawmempool" => Json(json!({
            "result": ["11".repeat(32), "22".repeat(32)], "error": null, "id": 1
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
    if req.get("method").and_then(Value::as_str) == Some("getrawmempool") {
        return Json(json!({"result": ["11".repeat(32)], "error": null, "id": 1}));
    }
    Json(json!({
        "result": null,
        "error": {"code": -5, "message": "Work queue depth exceeded"},
        "id": 1
    }))
}

/// A bitcoind whose mempool is successfully, uselessly empty.
async fn empty_mempool(Json(req): Json<Value>) -> Json<Value> {
    if req.get("method").and_then(Value::as_str) == Some("getrawmempool") {
        return Json(json!({"result": [], "error": null, "id": 1}));
    }
    Json(json!({"result": null, "error": {"code": -5, "message": "n/a"}, "id": 1}))
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
        let answer = sc.ask(TEMPLATE_HEIGHT).await.expect("lookup");
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
    let answer = sc.ask(TEMPLATE_HEIGHT).await.expect("lookup");
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
    let answer = sc.ask(TEMPLATE_HEIGHT).await.expect("lookup");
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
    let answer = sc.ask(TEMPLATE_HEIGHT).await.expect("lookup");

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
        .ask(TEMPLATE_HEIGHT)
        .await
        .expect("healthy lookup");

    let app = Router::new().route("/", post(mempool_only));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let broken = SecondChance::new(BitcoindClient::new(
        format!("http://{addr}/"),
        "u".into(),
        "p".into(),
        std::time::Duration::from_secs(5),
    ))
    .ask(TEMPLATE_HEIGHT)
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

/// An empty-but-successful getrawmempool cannot establish that any
/// transaction is absent, so it is refused rather than adjudicated.
#[tokio::test]
async fn an_empty_fresh_mempool_is_refused_not_treated_as_an_answer() {
    let app = Router::new().route("/", post(empty_mempool));
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

    let err = sc.ask(TEMPLATE_HEIGHT).await.expect_err(
        "an empty mempool must be refused: scoring every unknown absent against it would \
         uphold the rejection and record it as a confirmed detection",
    );
    assert_eq!(err.as_label(), "empty_mempool");
}
