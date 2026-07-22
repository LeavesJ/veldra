//! Upstream template polling and share relay.
//!
//! Two concerns in one module:
//! 1. Template polling: HTTP GET to template-manager `/latest`
//! 2. Share relay: HTTP POST of `ShareSubmission` to the pool backend

use std::sync::Arc;
use std::time::Duration;

use reqwest::Client;
use serde::Deserialize;
use tokio::sync::{mpsc, watch};
use tracing::{debug, error, info, warn};

use reservegrid_common::reason::GatewayReason;

use crate::health::ReadinessState;
use crate::shares::ShareSubmission;

// ─────────────────────────────────────────────────────────────────────
// Template polling
// ─────────────────────────────────────────────────────────────────────

/// Template response from `/latest`.
#[derive(Debug, Clone, Deserialize)]
pub struct TemplateResponse {
    pub template_id: u64,
    pub block_height: u32,
    pub block_version: u32,
    pub prev_hash: String,
    pub nbits: u32,
    pub min_ntime: u32,
    pub curtime: u32,
    pub coinbase_value: u64,
    pub coinbase_tx_prefix: String, // hex
    pub coinbase_tx_suffix: String, // hex
    pub merkle_path: Vec<String>,   // array of hex strings
    pub tx_count: u32,
    pub total_fees: u64,
    pub source_instance_id: String,
    #[serde(default)]
    pub observed_weight: Option<u64>,
    #[serde(default)]
    pub template_weight: Option<u64>,
    #[serde(default)]
    pub total_sigops: Option<u32>,
    #[serde(default)]
    pub coinbase_sigops: Option<u32>,
    /// PB-19 / Phase 1b: hex of the assembled raw template block,
    /// forwarded verbatim into `TemplatePropose` so the verifier's
    /// Invariant Shield has bytes to re-derive from. Optional for
    /// backward compatibility with older template-managers.
    #[serde(default)]
    pub raw_block_hex: Option<String>,
}

/// Configuration for the template poller.
pub struct TemplatePollerConfig {
    /// URL of the template-manager (e.g. "<http://localhost:8081>").
    pub base_url: String,
    /// Polling interval.
    pub poll_interval: Duration,
    /// Maximum template age before discarding.
    pub max_template_age_ms: u64,
}

/// Run the template polling loop.
///
/// Periodically fetches `/latest` and sends new templates
/// through `template_tx`.
pub async fn run_template_poller(
    config: TemplatePollerConfig,
    client: Client,
    template_tx: mpsc::Sender<TemplateResponse>,
    readiness: Arc<ReadinessState>,
    mut shutdown: watch::Receiver<bool>,
) {
    let url = format!("{}/latest", config.base_url.trim_end_matches('/'));
    let mut interval = tokio::time::interval(config.poll_interval);

    loop {
        tokio::select! {
            _ = interval.tick() => {
                match client.get(&url).send().await {
                    Ok(resp) if resp.status().is_success() => {
                        match resp.json::<TemplateResponse>().await {
                            Ok(template) => {
                                debug!(
                                    template_id = template.template_id,
                                    block_height = template.block_height,
                                    "polled template"
                                );
                                readiness.upstream_reachable.store(
                                    true,
                                    std::sync::atomic::Ordering::SeqCst,
                                );
                                if template_tx.send(template).await.is_err() {
                                    info!("template channel closed; stopping poller");
                                    return;
                                }
                            }
                            Err(e) => {
                                warn!(error = %e, "failed to parse template response");
                            }
                        }
                    }
                    Ok(resp) => {
                        warn!(status = %resp.status(), "template poll non-200");
                        readiness.upstream_reachable.store(
                            false,
                            std::sync::atomic::Ordering::SeqCst,
                        );
                    }
                    Err(e) => {
                        warn!(error = %e, "template poll failed");
                        readiness.upstream_reachable.store(
                            false,
                            std::sync::atomic::Ordering::SeqCst,
                        );
                    }
                }
            }
            _ = shutdown.changed() => {
                info!("template poller shutting down");
                return;
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// Share relay (HTTP adapter)
// ─────────────────────────────────────────────────────────────────────

/// Upstream response from the share endpoint.
#[derive(Debug, Deserialize)]
pub struct ShareUpstreamResponse {
    pub accepted: bool,
    #[serde(default)]
    pub reason: Option<String>,
}

/// Result of a share forward attempt.
#[derive(Debug, Clone)]
pub struct ShareForwardResult {
    pub share_id_hex: String,
    pub event_id_hex: String,
    pub forwarded: bool,
    pub upstream_accepted: Option<bool>,
    pub upstream_http_status: Option<u16>,
    pub upstream_error: Option<String>,
    pub reason_code: Option<String>,
}

/// Share forward error category for metrics labeling.
#[derive(Debug, Clone, Copy)]
pub enum ForwardErrorCategory {
    Timeout,
    Connect,
    Non200,
    Malformed,
}

impl ForwardErrorCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            ForwardErrorCategory::Timeout => "timeout",
            ForwardErrorCategory::Connect => "connect",
            ForwardErrorCategory::Non200 => "non_200",
            ForwardErrorCategory::Malformed => "malformed",
        }
    }
}

/// Configuration for the share relay worker.
pub struct ShareRelayConfig {
    pub url: String,
    pub secret: Vec<u8>,
    pub max_retries: u32,
    pub max_in_flight: usize,
}

/// Run the share relay worker.
///
/// Dequeues `ShareSubmission` entries from `share_rx`, POSTs them to
/// the upstream endpoint, and emits `ShareForwardResult` via `result_tx`.
pub async fn run_share_relay(
    config: ShareRelayConfig,
    client: Client,
    mut share_rx: mpsc::Receiver<ShareSubmission>,
    result_tx: mpsc::Sender<ShareForwardResult>,
    readiness: Arc<ReadinessState>,
    mut shutdown: watch::Receiver<bool>,
) {
    let semaphore = Arc::new(tokio::sync::Semaphore::new(config.max_in_flight));

    loop {
        tokio::select! {
            share = share_rx.recv() => {
                let Some(share) = share else {
                    info!("share relay channel closed");
                    return;
                };

                let Ok(permit) = semaphore.clone().acquire_owned().await else {
                    error!("share relay semaphore closed");
                    return;
                };

                let client = client.clone();
                let url = config.url.clone();
                let result_tx = result_tx.clone();
                let max_retries = config.max_retries;
                let readiness = readiness.clone();

                tokio::spawn(async move {
                    let result = forward_share_with_retries(
                        &client,
                        &url,
                        &share,
                        max_retries,
                    ).await;

                    // Update share_upstream_reachable based on HTTP reachability,
                    // not share acceptance. A rejected share still means the
                    // upstream is reachable.
                    readiness.share_upstream_reachable.store(
                        result.forwarded,
                        std::sync::atomic::Ordering::SeqCst,
                    );

                    let _ = result_tx.send(result).await;
                    drop(permit);
                });
            }
            _ = shutdown.changed() => {
                info!("share relay shutting down");
                return;
            }
        }
    }
}

/// Forward a single share with retry logic.
async fn forward_share_with_retries(
    client: &Client,
    url: &str,
    share: &ShareSubmission,
    max_retries: u32,
) -> ShareForwardResult {
    let mut last_error = None;
    let base_delay = Duration::from_millis(100);

    for attempt in 0..=max_retries {
        if attempt > 0 {
            let delay = base_delay * 2u32.saturating_pow(attempt - 1);
            tokio::time::sleep(delay).await;
        }

        match client.post(url).json(share).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let is_success = resp.status().is_success();
                let is_client_err = resp.status().is_client_error();

                if is_success {
                    match resp.json::<ShareUpstreamResponse>().await {
                        Ok(upstream_resp) => {
                            let reason = if upstream_resp.accepted {
                                None
                            } else {
                                upstream_resp.reason.clone()
                            };
                            return ShareForwardResult {
                                share_id_hex: share.share_id_hex.clone(),
                                event_id_hex: share.event_id_hex.clone(),
                                forwarded: true,
                                upstream_accepted: Some(upstream_resp.accepted),
                                upstream_http_status: Some(status),
                                upstream_error: reason.clone(),
                                reason_code: if upstream_resp.accepted {
                                    None
                                } else {
                                    Some(GatewayReason::ShareUpstreamRejected.as_str().to_string())
                                },
                            };
                        }
                        Err(e) => {
                            last_error = Some(format!("malformed response: {e}"));
                        }
                    }
                } else if is_client_err {
                    // 4xx errors are not retryable (bad request, not found, etc).
                    return ShareForwardResult {
                        share_id_hex: share.share_id_hex.clone(),
                        event_id_hex: share.event_id_hex.clone(),
                        forwarded: true,
                        upstream_accepted: Some(false),
                        upstream_http_status: Some(status),
                        upstream_error: Some(format!("HTTP {status} (non-retryable)")),
                        reason_code: Some(GatewayReason::ShareForwardFailed.as_str().to_string()),
                    };
                } else {
                    // 5xx or other: retryable.
                    last_error = Some(format!("HTTP {status}"));
                }
            }
            Err(e) => {
                if e.is_timeout() {
                    last_error = Some(format!("timeout: {e}"));
                } else if e.is_connect() {
                    last_error = Some(format!("connect: {e}"));
                } else {
                    last_error = Some(format!("request: {e}"));
                }
            }
        }
    }

    // All retries exhausted.
    warn!(
        share_id = %share.share_id_hex,
        retries = max_retries,
        error = ?last_error,
        "share forward failed after retries"
    );

    ShareForwardResult {
        share_id_hex: share.share_id_hex.clone(),
        event_id_hex: share.event_id_hex.clone(),
        forwarded: false,
        upstream_accepted: None,
        upstream_http_status: None,
        upstream_error: last_error,
        reason_code: Some(GatewayReason::ShareForwardFailed.as_str().to_string()),
    }
}

// ─────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn template_response_deserializes() {
        let json = serde_json::json!({
            "template_id": 42,
            "block_height": 800_000,
            "block_version": 536_870_912,
            "prev_hash": "aa".repeat(32),
            "nbits": 386_089_983,
            "min_ntime": 1_700_000_000,
            "curtime": 1_700_000_001,
            "coinbase_value": 625_000_000,
            "coinbase_tx_prefix": "0100",
            "coinbase_tx_suffix": "ffff",
            "merkle_path": [],
            "tx_count": 100,
            "total_fees": 50_000_000,
            "source_instance_id": "test-123"
        });
        let resp: TemplateResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.template_id, 42);
        assert_eq!(resp.block_height, 800_000);
    }

    #[test]
    fn upstream_response_accepted() {
        let json = serde_json::json!({"accepted": true});
        let resp: ShareUpstreamResponse = serde_json::from_value(json).unwrap();
        assert!(resp.accepted);
    }

    #[test]
    fn upstream_response_rejected() {
        let json = serde_json::json!({"accepted": false, "reason": "duplicate_share_id"});
        let resp: ShareUpstreamResponse = serde_json::from_value(json).unwrap();
        assert!(!resp.accepted);
        assert_eq!(resp.reason.as_deref(), Some("duplicate_share_id"));
    }

    #[test]
    fn forward_error_category_labels() {
        assert_eq!(ForwardErrorCategory::Timeout.as_str(), "timeout");
        assert_eq!(ForwardErrorCategory::Connect.as_str(), "connect");
        assert_eq!(ForwardErrorCategory::Non200.as_str(), "non_200");
        assert_eq!(ForwardErrorCategory::Malformed.as_str(), "malformed");
    }
}
