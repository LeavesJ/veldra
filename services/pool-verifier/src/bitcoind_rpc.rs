//! Direct bitcoind JSON-RPC client for the v2.0 Invariant Shield
//! Phase 2 Class M check (ADR-003).
//!
//! Distinct from `mempool_client.rs` which queries the
//! template-manager's `/mempool` HTTP endpoint for tx-count metadata
//! used in fee tier selection. This module talks JSON-RPC directly
//! to a bitcoind to fetch the full network mempool view.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::warn;

#[derive(Debug, Error)]
pub enum RpcError {
    #[error("bitcoind RPC HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("bitcoind RPC returned an error: code={code} message={message}")]
    Rpc { code: i64, message: String },

    #[error("bitcoind RPC response missing result field")]
    MissingResult,

    #[error("invalid txid hex returned by bitcoind: {0}")]
    InvalidTxidHex(String),
}

#[derive(Debug, Clone)]
pub struct BitcoindClient {
    http: reqwest::Client,
    url: String,
    user: String,
    pass: String,
}

impl BitcoindClient {
    /// Construct a new client. URL must be a full http(s) endpoint
    /// (e.g. `http://bitcoind:8332`). Basic auth credentials are
    /// loaded from caller-supplied strings; never logged.
    pub fn new(url: String, user: String, pass: String, timeout: Duration) -> Self {
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            http,
            url,
            user,
            pass,
        }
    }

    /// Issue one JSON-RPC call and return its `result`.
    ///
    /// Extracted on the third caller (`getrawmempool`,
    /// `getbestblockhash`, `getblock`), per the rule of three: the
    /// error precedence is the part worth having once rather than
    /// three times, because a `200 OK` carrying an `error` object is a
    /// failure and reading `result` first would miss it.
    async fn call<P: Serialize, R: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        params: P,
    ) -> Result<R, RpcError> {
        let req = JsonRpcRequest {
            jsonrpc: "1.0",
            id: "rg-pool-verifier",
            method,
            params,
        };
        let resp: JsonRpcResponse<R> = self
            .http
            .post(&self.url)
            .basic_auth(&self.user, Some(&self.pass))
            .json(&req)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        if let Some(err) = resp.error {
            return Err(RpcError::Rpc {
                code: err.code,
                message: err.message,
            });
        }
        resp.result.ok_or(RpcError::MissingResult)
    }

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
        let params = probe_params(txids);
        let items: Vec<BatchItem<serde_json::Value>> =
            self.call_batch("getmempoolentry", &params).await?;
        Ok(items.into_iter().map(probe_from_item).collect())
    }

    /// Fetch the current mempool as a list of transaction ids in
    /// internal byte order.
    ///
    /// Calls `getrawmempool verbose=false` per Bitcoin Core's
    /// JSON-RPC contract. The response is an array of hex-encoded
    /// txids in display order (which is internal byte order
    /// reversed); we reverse each to internal byte order so it
    /// matches `bitcoin::Transaction::compute_txid().to_byte_array()`
    /// from the facade.
    pub async fn get_raw_mempool(&self) -> Result<Vec<[u8; 32]>, RpcError> {
        let hex_txids: Vec<String> = self.call("getrawmempool", [false]).await?;
        txids_to_internal_order(hex_txids)
    }

    /// Hash of the current chain tip, as the display-order hex string
    /// Bitcoin Core returns.
    ///
    /// Left as a string on purpose: it is only ever handed straight
    /// back to [`BitcoindClient::get_block_txids`], so decoding it to
    /// bytes and re-encoding would add a conversion with no consumer.
    pub async fn get_best_block_hash(&self) -> Result<String, RpcError> {
        self.call("getbestblockhash", [(); 0]).await
    }

    /// Fetch one block's transaction ids, height, and parent hash via
    /// `getblock <hash> 1`.
    ///
    /// Verbosity 1 returns txids only, not full transactions: for a
    /// mainnet block that is roughly 200 KB against tens of megabytes
    /// at verbosity 2, and set membership is all the PB-40
    /// second-chance lookup asks of it.
    ///
    /// Txids come back in internal byte order to match
    /// `rg_consensus::template_txids`; the block and parent hashes
    /// stay in display order because they are only fed back into RPC.
    pub async fn get_block_txids(&self, block_hash: &str) -> Result<BlockTxids, RpcError> {
        let raw: GetBlockVerbosity1 = self.call("getblock", (block_hash, 1u8)).await?;
        Ok(BlockTxids {
            height: raw.height,
            txids: txids_to_internal_order(raw.tx)?,
            previous_block_hash: raw.previousblockhash,
        })
    }
}

/// One block, reduced to what the Class M second-chance lookup reads.
#[derive(Debug, Clone)]
pub struct BlockTxids {
    pub height: u32,
    /// Internal byte order, matching `rg_consensus::template_txids`.
    pub txids: Vec<[u8; 32]>,
    /// `None` at the genesis block, which ends any walk back.
    pub previous_block_hash: Option<String>,
}

/// Bitcoin Core returns txids in display order (RPC big endian).
/// Internal byte order is the reverse.
fn txids_to_internal_order(hex_txids: Vec<String>) -> Result<Vec<[u8; 32]>, RpcError> {
    let mut out = Vec::with_capacity(hex_txids.len());
    for hex_str in hex_txids {
        let mut bytes = parse_txid_hex(&hex_str)?;
        bytes.reverse();
        out.push(bytes);
    }
    Ok(out)
}

/// The `getblock` verbosity-1 fields this crate uses. Bitcoin Core
/// returns many more; serde ignores them.
#[derive(Deserialize)]
struct GetBlockVerbosity1 {
    height: u32,
    tx: Vec<String>,
    previousblockhash: Option<String>,
}

fn parse_txid_hex(hex_str: &str) -> Result<[u8; 32], RpcError> {
    if hex_str.len() != 64 {
        warn!(len = hex_str.len(), "unexpected txid hex length");
        return Err(RpcError::InvalidTxidHex(hex_str.to_string()));
    }
    // hex::decode walks bytes, never char boundaries, so a malformed
    // multi-byte UTF-8 string from a broken RPC endpoint surfaces as
    // an error instead of a slice panic inside the polling task.
    let decoded =
        hex::decode(hex_str).map_err(|_| RpcError::InvalidTxidHex(hex_str.to_string()))?;
    <[u8; 32]>::try_from(decoded).map_err(|_| RpcError::InvalidTxidHex(hex_str.to_string()))
}

#[derive(Serialize)]
struct JsonRpcRequest<'a, T> {
    jsonrpc: &'a str,
    id: &'a str,
    method: &'a str,
    params: T,
}

#[derive(Deserialize)]
struct JsonRpcResponse<T> {
    result: Option<T>,
    error: Option<JsonRpcError>,
}

#[derive(Deserialize)]
struct JsonRpcError {
    code: i64,
    message: String,
}

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
    Failed {
        code: i64,
        message: String,
    },
    /// No reply could be attributed to this request: the id was absent,
    /// duplicated, or out of range. NOT an answer, and callers must not
    /// treat it as a negative one.
    NoResponse,
}

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

/// Build the `getmempoolentry` batch params for a set of txids.
///
/// Each txid is converted from internal byte order, which callers hold,
/// to DISPLAY order, which is what Bitcoin Core's RPC speaks. Separated
/// from [`BitcoindClient::probe_mempool`] so the byte order conversion
/// is directly testable without a server: a wrong reversal here turns
/// every live probe into a lookup against a hash Core has never seen,
/// which resolves to Absent and fabricates a detection.
fn probe_params(txids: &[[u8; 32]]) -> Vec<[String; 1]> {
    txids
        .iter()
        .map(|t| {
            let mut display = *t;
            display.reverse();
            [hex::encode(display)]
        })
        .collect()
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

/// Correlate batch replies to requests by `id`, never by position.
///
/// Separated from the HTTP call so every branch is reachable in a unit
/// test without a server. Returns exactly `request_count` items.
fn resolve_batch<R>(responses: Vec<BatchResponse<R>>, request_count: usize) -> Vec<BatchItem<R>> {
    let mut slots: Vec<Option<BatchItem<R>>> = (0..request_count).map(|_| None).collect();
    let mut duplicated = vec![false; request_count];

    for resp in responses {
        let Some(id) = resp.id else { continue };
        let Ok(idx) = usize::try_from(id) else {
            continue;
        };
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_txid_hex_round_trips_a_known_value() {
        // Genesis coinbase tx id, display order (Bitcoin Core RPC).
        let display = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";
        let bytes = parse_txid_hex(display).unwrap();
        // Reverse to match internal byte order convention used by
        // `Transaction::compute_txid().to_byte_array()`.
        let mut internal = bytes;
        internal.reverse();
        // Internal byte order of genesis coinbase txid begins 0x3b 0xa3 ...
        assert_eq!(internal[0], 0x3b);
        assert_eq!(internal[1], 0xa3);
    }

    /// `probe_params` must send the exact display-order hex string Core
    /// expects, not merely something different from the input. Uses the
    /// same genesis coinbase txid as
    /// `parse_txid_hex_round_trips_a_known_value` so both tests agree on
    /// one ground truth: internal byte order begins 0x3b 0xa3, display
    /// order is the value below. A mutation that drops `.reverse()`, or
    /// reverses the wrong array, would send `internal`'s hex back out
    /// unchanged or double-reversed, and this assertion catches either.
    #[test]
    fn probe_params_sends_the_known_value_in_display_order() {
        let display = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";
        let mut internal = parse_txid_hex(display).unwrap();
        internal.reverse();
        assert_eq!(internal[0], 0x3b);
        assert_eq!(internal[1], 0xa3);

        let params = probe_params(&[internal]);
        assert_eq!(params, vec![[display.to_string()]]);
    }

    /// `probe_params` must preserve INPUT ORDER across multiple txids,
    /// not merely convert each one's byte order correctly. The test
    /// above cannot see a reordering: with a single input, `.rev()` on
    /// the iterator is a no-op. Three distinct txids, checked in order,
    /// is the direct evidence: a mutation that adds `.rev()` to
    /// `probe_params`'s iterator would return them last-to-first, and
    /// the assertion at index 0 would fail because `gather`'s
    /// `chunk.iter().zip(probes)` depends on this exact alignment.
    #[test]
    fn probe_params_preserves_input_order_across_three_txids() {
        fn display(t: [u8; 32]) -> String {
            let mut d = t;
            d.reverse();
            hex::encode(d)
        }

        let first = [0x11u8; 32];
        let mut second = [0x22u8; 32];
        second[0] = 0xBB;
        let mut third = [0x33u8; 32];
        third[0] = 0xCC;

        let params = probe_params(&[first, second, third]);
        assert_eq!(
            params,
            vec![[display(first)], [display(second)], [display(third)]],
            "each txid's display-order hex must land at its own input index, in order"
        );
    }

    #[test]
    fn parse_txid_hex_rejects_wrong_length() {
        assert!(parse_txid_hex("dead").is_err());
        assert!(parse_txid_hex("").is_err());
    }

    #[test]
    fn parse_txid_hex_rejects_non_hex() {
        let bad = "g".repeat(64);
        assert!(parse_txid_hex(&bad).is_err());
    }

    #[test]
    fn parse_txid_hex_rejects_multibyte_utf8_without_panic() {
        // 61 ASCII bytes + one 2-byte UTF-8 char + 1 ASCII byte is
        // exactly 64 bytes, passing the length gate, but a fixed
        // byte-offset slice at position 62 splits the char and
        // panics. A malformed txid string from a broken or hostile
        // RPC endpoint must surface as an error, not kill the
        // polling task.
        let mut s = "a".repeat(61);
        s.push('é');
        s.push('b');
        assert_eq!(s.len(), 64, "test string must be 64 bytes");
        assert!(parse_txid_hex(&s).is_err());
    }

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

    /// Only the documented missing-entry code counts as a proven
    /// absence. Every other error is unadjudicated.
    ///
    /// This is fail-safe against our own uncertainty: the -5 code is
    /// believed correct but has NOT been verified against a real
    /// bitcoind. If it is wrong, every probe becomes Unadjudicated,
    /// which forces `lookup_failed` (loud). It can never degrade into
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
}
