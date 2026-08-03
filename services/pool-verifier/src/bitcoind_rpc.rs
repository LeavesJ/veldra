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
        let req = JsonRpcRequest {
            jsonrpc: "1.0",
            id: "rg-pool-verifier",
            method: "getrawmempool",
            params: [false],
        };
        let resp: JsonRpcResponse<Vec<String>> = self
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
        let hex_txids = resp.result.ok_or(RpcError::MissingResult)?;
        let mut out = Vec::with_capacity(hex_txids.len());
        for hex_str in hex_txids {
            let mut bytes = parse_txid_hex(&hex_str)?;
            // Bitcoin Core returns txids in display order (RPC big
            // endian). Internal byte order is the reverse.
            bytes.reverse();
            out.push(bytes);
        }
        Ok(out)
    }
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
}
