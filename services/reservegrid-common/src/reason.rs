//! Unified reason codes for the entire reservegrid-os stack.
//!
//! `ReasonCode` is the single enum that every API response, log line,
//! dashboard aggregate, and exporter metric keys off. It is a superset
//! of `rg_protocol::VerdictReason` (template verification) and
//! `GatewayReason` (gateway operational rejections).
//!
//! **Non-negotiable invariant:** canonical `snake_case` strings must never
//! drift between `ReasonCode`, `GatewayReason`, `VerdictReason`, exports,
//! and documentation. Tests enforce this at compile time.

use rg_protocol::VerdictReason;
use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────
// GatewayReason: operational rejection codes originating in the gateway
// ─────────────────────────────────────────────────────────────────────

/// Canonical machine-readable reason codes for gateway operational rejections.
///
/// These codes cover authentication, rate limiting, input validation, protocol
/// hardening, and runtime resilience. They do NOT overlap with
/// `rg_protocol::VerdictReason` which covers template verification decisions.
///
/// The `#[serde(rename_all = "snake_case")]` attribute and `as_str()` MUST agree,
/// enforced by tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GatewayReason {
    // ── Authentication ──
    /// Missing or invalid credentials
    AuthFailed,

    /// Algorithm in signed request not supported
    UnsupportedAlgorithm,

    // ── Rate limiting ──
    /// Token bucket exhausted for this client
    RateLimited,

    // ── Input validation ──
    /// Request body exceeds `max_request_body_bytes`
    PayloadTooLarge,

    /// `Content-Type` is not `application/json`
    InvalidContentType,

    /// JSON payload contains unrecognized fields
    PayloadUnknownField,

    /// Numeric or string field outside allowed range
    PayloadFieldOutOfRange,

    /// JSON is syntactically invalid or missing required fields
    PayloadMalformed,

    /// JSON nesting exceeds depth limit
    PayloadNestingExceeded,

    // ── Protocol hardening ──
    /// Signed request timestamp outside acceptance window
    RequestExpired,

    /// Nonce already seen within timestamp window
    RequestReplayed,

    // ── Runtime resilience ──
    /// Handler exceeded wall-clock deadline
    HandlerTimeout,

    /// Configuration file invalid or missing required fields
    ConfigInvalid,

    /// Catch-all for unexpected internal failures
    InternalError,

    // ── Internal framing (gateway <-> verifier TCP) ──
    /// Internal NDJSON line exceeds `MAX_INTERNAL_LINE_BYTES`
    InternalLineTooLarge,

    /// Internal NDJSON line missing `msg_type` or otherwise unparseable
    InternalFramingError,

    /// Internal `msg_type` recognized but version field mismatched
    InternalVersionMismatch,

    /// Too many unknown `msg_type` lines per minute from one peer
    InternalUnknownMsgFlood,

    // ── SV2 Transport (miner-facing boundary) ──
    /// Noise NX handshake failed (crypto error, malformed message)
    NoiseHandshakeFailed,

    /// Noise NX handshake did not complete within timeout
    NoiseHandshakeTimeout,

    /// Miner requested unsupported SV2 protocol version
    UnsupportedProtocolVersion,

    /// SV2 binary frame could not be decoded
    FrameDecodeError,

    /// SV2 frame exceeds maximum allowed size
    FrameTooLarge,

    /// Per-connection or per-IP rate limit hit on SV2 transport
    ConnectionRateLimited,

    /// Peer exceeded resource quota (connections, channels, bytes)
    PeerQuotaExceeded,

    // ── Miner authorization ──
    /// Miner identity not in allowlist or prefix map
    MinerUnauthorized,

    /// Identity prefix does not match any configured prefix mapping
    IdentityPrefixUnmatched,

    /// Worker identity exceeds `max_worker_id_bytes`
    IdentityTooLong,

    // ── Channel lifecycle ──
    /// Channel open rejected (no template available, cold start)
    ChannelOpenRejected,

    /// Maximum channels per connection exceeded
    ChannelLimitExceeded,

    /// Channel ID does not exist or was closed
    InvalidChannelId,

    /// Extended mining channels not supported in v1.0.0
    ExtendedChannelUnsupported,

    // ── Job path ──
    /// Verifier verdict did not arrive within `prevhash_verdict_timeout_ms`
    PrevhashSwitchTimeout,

    /// Verifier rejected the template for the new prevhash
    PrevhashVerdictRejected,

    /// Template referenced by a job is not in the dedup cache
    TemplateCacheMiss,

    /// Share references a job that is no longer active
    StaleJobSubmission,

    /// Upstream template source or share endpoint unreachable
    UpstreamUnavailable,

    // ── Share ingestion (gateway → template-manager HMAC validation) ──
    /// Share submission missing required `gateway_signature` field
    MissingGatewaySignature,

    /// `gateway_signature` field is not valid hex
    MalformedGatewaySignature,

    /// `event_id` field is not valid hex
    MalformedEventId,

    /// HMAC verification of `gateway_signature` failed
    InvalidGatewaySignature,

    // ── Share validation ──
    /// Duplicate `share_id` within dedup window (inline mode)
    ShareReplayDetected,

    /// Share hash does not meet channel `maximum_target`
    ShareDifficultyBelowTarget,

    /// Share references a `job_id` not in the job table
    ShareInvalidJobId,

    /// Share nonce produces invalid `PoW` candidate
    ShareInvalidNonce,

    /// Non-GP version bits differ from job version
    VersionBitViolation,

    /// Share ntime outside elapsed-time or absolute clamp bounds
    NtimeOutOfRange,

    /// Upstream HTTP POST failed (timeout, connect, non-200, malformed)
    ShareForwardFailed,

    /// Upstream returned `{"accepted": false}`
    ShareUpstreamRejected,

    /// Share forwarding queue or accepted queue is full
    ShareDroppedQueueFull,

    /// Share evicted from forward queue by `drop_old` policy
    ShareEvictedFromQueue,

    /// Per-connection share submission rate exceeded
    ShareRateLimited,

    // ── Crash recovery ──
    /// Synthetic forward result for shares orphaned by a process crash.
    /// Emitted during WAL reconciliation on startup.
    ProcessCrashRecovery,

    /// WAL append failed (disk full, fsync error, mutex poisoned, `spawn_blocking`
    /// join failure). Emitted as a structured log event immediately before the
    /// gateway begins graceful shutdown when `VELDRA_WAL_WRITE_FAILURE_MODE` is
    /// not set to `accept_silent`. Never reaches the SV2 wire.
    WalWriteFailure,

    // ── Connection lifecycle (disconnect telemetry) ──
    /// Peer TCP connection dropped or transport I/O error.
    PeerTransportError,

    /// Peer did not open any mining channel within the configured timeout.
    ChannelOpenTimeout,

    /// SV2 `SetupConnection` exchange failed (wrong message, bad flags, etc.).
    SetupConnectionRejected,

    // ── Health probe status ──
    /// Gateway is draining connections during graceful shutdown.
    ShutdownDrain,

    /// Gateway has not yet completed startup initialization.
    StartupPending,
}

impl GatewayReason {
    /// Every variant for exhaustive iteration in tests and mappings.
    pub const ALL: &[GatewayReason] = &[
        GatewayReason::AuthFailed,
        GatewayReason::UnsupportedAlgorithm,
        GatewayReason::RateLimited,
        GatewayReason::PayloadTooLarge,
        GatewayReason::InvalidContentType,
        GatewayReason::PayloadUnknownField,
        GatewayReason::PayloadFieldOutOfRange,
        GatewayReason::PayloadMalformed,
        GatewayReason::PayloadNestingExceeded,
        GatewayReason::RequestExpired,
        GatewayReason::RequestReplayed,
        GatewayReason::HandlerTimeout,
        GatewayReason::ConfigInvalid,
        GatewayReason::InternalError,
        GatewayReason::InternalLineTooLarge,
        GatewayReason::InternalFramingError,
        GatewayReason::InternalVersionMismatch,
        GatewayReason::InternalUnknownMsgFlood,
        // SV2 transport
        GatewayReason::NoiseHandshakeFailed,
        GatewayReason::NoiseHandshakeTimeout,
        GatewayReason::UnsupportedProtocolVersion,
        GatewayReason::FrameDecodeError,
        GatewayReason::FrameTooLarge,
        GatewayReason::ConnectionRateLimited,
        GatewayReason::PeerQuotaExceeded,
        // Miner authorization
        GatewayReason::MinerUnauthorized,
        GatewayReason::IdentityPrefixUnmatched,
        GatewayReason::IdentityTooLong,
        // Channel lifecycle
        GatewayReason::ChannelOpenRejected,
        GatewayReason::ChannelLimitExceeded,
        GatewayReason::InvalidChannelId,
        GatewayReason::ExtendedChannelUnsupported,
        // Job path
        GatewayReason::PrevhashSwitchTimeout,
        GatewayReason::PrevhashVerdictRejected,
        GatewayReason::TemplateCacheMiss,
        GatewayReason::StaleJobSubmission,
        GatewayReason::UpstreamUnavailable,
        // Share ingestion
        GatewayReason::MissingGatewaySignature,
        GatewayReason::MalformedGatewaySignature,
        GatewayReason::MalformedEventId,
        GatewayReason::InvalidGatewaySignature,
        // Share validation
        GatewayReason::ShareReplayDetected,
        GatewayReason::ShareDifficultyBelowTarget,
        GatewayReason::ShareInvalidJobId,
        GatewayReason::ShareInvalidNonce,
        GatewayReason::VersionBitViolation,
        GatewayReason::NtimeOutOfRange,
        GatewayReason::ShareForwardFailed,
        GatewayReason::ShareUpstreamRejected,
        GatewayReason::ShareDroppedQueueFull,
        GatewayReason::ShareEvictedFromQueue,
        GatewayReason::ShareRateLimited,
        GatewayReason::ProcessCrashRecovery,
        GatewayReason::WalWriteFailure,
        // Connection lifecycle
        GatewayReason::PeerTransportError,
        GatewayReason::ChannelOpenTimeout,
        GatewayReason::SetupConnectionRejected,
        // Health probe status
        GatewayReason::ShutdownDrain,
        GatewayReason::StartupPending,
    ];

    /// All canonical `snake_case` reason code strings. Order matches `ALL`.
    #[allow(clippy::too_many_lines)]
    pub const ALL_CODES: &[&str] = &[
        "auth_failed",
        "unsupported_algorithm",
        "rate_limited",
        "payload_too_large",
        "invalid_content_type",
        "payload_unknown_field",
        "payload_field_out_of_range",
        "payload_malformed",
        "payload_nesting_exceeded",
        "request_expired",
        "request_replayed",
        "handler_timeout",
        "config_invalid",
        "internal_error",
        "internal_line_too_large",
        "internal_framing_error",
        "internal_version_mismatch",
        "internal_unknown_msg_flood",
        // SV2 transport
        "noise_handshake_failed",
        "noise_handshake_timeout",
        "unsupported_protocol_version",
        "frame_decode_error",
        "frame_too_large",
        "connection_rate_limited",
        "peer_quota_exceeded",
        // Miner authorization
        "miner_unauthorized",
        "identity_prefix_unmatched",
        "identity_too_long",
        // Channel lifecycle
        "channel_open_rejected",
        "channel_limit_exceeded",
        "invalid_channel_id",
        "extended_channel_unsupported",
        // Job path
        "prevhash_switch_timeout",
        "prevhash_verdict_rejected",
        "template_cache_miss",
        "stale_job_submission",
        "upstream_unavailable",
        // Share ingestion (gateway → template-manager HMAC validation)
        "missing_gateway_signature",
        "malformed_gateway_signature",
        "malformed_event_id",
        "invalid_gateway_signature",
        // Share validation
        "share_replay_detected",
        "share_difficulty_below_target",
        "share_invalid_job_id",
        "share_invalid_nonce",
        "version_bit_violation",
        "ntime_out_of_range",
        "share_forward_failed",
        "share_upstream_rejected",
        "share_dropped_queue_full",
        "share_evicted_from_queue",
        "share_rate_limited",
        // Crash recovery
        "process_crash_recovery",
        "wal_write_failure",
        // Connection lifecycle
        "peer_transport_error",
        "channel_open_timeout",
        "setup_connection_rejected",
        // Health probe status
        "shutdown_drain",
        "startup_pending",
    ];

    /// Canonical `snake_case` string for this reason code.
    pub fn as_str(&self) -> &'static str {
        match self {
            GatewayReason::AuthFailed => "auth_failed",
            GatewayReason::UnsupportedAlgorithm => "unsupported_algorithm",
            GatewayReason::RateLimited => "rate_limited",
            GatewayReason::PayloadTooLarge => "payload_too_large",
            GatewayReason::InvalidContentType => "invalid_content_type",
            GatewayReason::PayloadUnknownField => "payload_unknown_field",
            GatewayReason::PayloadFieldOutOfRange => "payload_field_out_of_range",
            GatewayReason::PayloadMalformed => "payload_malformed",
            GatewayReason::PayloadNestingExceeded => "payload_nesting_exceeded",
            GatewayReason::RequestExpired => "request_expired",
            GatewayReason::RequestReplayed => "request_replayed",
            GatewayReason::HandlerTimeout => "handler_timeout",
            GatewayReason::ConfigInvalid => "config_invalid",
            GatewayReason::InternalError => "internal_error",
            GatewayReason::InternalLineTooLarge => "internal_line_too_large",
            GatewayReason::InternalFramingError => "internal_framing_error",
            GatewayReason::InternalVersionMismatch => "internal_version_mismatch",
            GatewayReason::InternalUnknownMsgFlood => "internal_unknown_msg_flood",
            // SV2 transport
            GatewayReason::NoiseHandshakeFailed => "noise_handshake_failed",
            GatewayReason::NoiseHandshakeTimeout => "noise_handshake_timeout",
            GatewayReason::UnsupportedProtocolVersion => "unsupported_protocol_version",
            GatewayReason::FrameDecodeError => "frame_decode_error",
            GatewayReason::FrameTooLarge => "frame_too_large",
            GatewayReason::ConnectionRateLimited => "connection_rate_limited",
            GatewayReason::PeerQuotaExceeded => "peer_quota_exceeded",
            // Miner authorization
            GatewayReason::MinerUnauthorized => "miner_unauthorized",
            GatewayReason::IdentityPrefixUnmatched => "identity_prefix_unmatched",
            GatewayReason::IdentityTooLong => "identity_too_long",
            // Channel lifecycle
            GatewayReason::ChannelOpenRejected => "channel_open_rejected",
            GatewayReason::ChannelLimitExceeded => "channel_limit_exceeded",
            GatewayReason::InvalidChannelId => "invalid_channel_id",
            GatewayReason::ExtendedChannelUnsupported => "extended_channel_unsupported",
            // Job path
            GatewayReason::PrevhashSwitchTimeout => "prevhash_switch_timeout",
            GatewayReason::PrevhashVerdictRejected => "prevhash_verdict_rejected",
            GatewayReason::TemplateCacheMiss => "template_cache_miss",
            GatewayReason::StaleJobSubmission => "stale_job_submission",
            GatewayReason::UpstreamUnavailable => "upstream_unavailable",
            // Share ingestion (gateway → template-manager HMAC validation)
            GatewayReason::MissingGatewaySignature => "missing_gateway_signature",
            GatewayReason::MalformedGatewaySignature => "malformed_gateway_signature",
            GatewayReason::MalformedEventId => "malformed_event_id",
            GatewayReason::InvalidGatewaySignature => "invalid_gateway_signature",
            // Share validation
            GatewayReason::ShareReplayDetected => "share_replay_detected",
            GatewayReason::ShareDifficultyBelowTarget => "share_difficulty_below_target",
            GatewayReason::ShareInvalidJobId => "share_invalid_job_id",
            GatewayReason::ShareInvalidNonce => "share_invalid_nonce",
            GatewayReason::VersionBitViolation => "version_bit_violation",
            GatewayReason::NtimeOutOfRange => "ntime_out_of_range",
            GatewayReason::ShareForwardFailed => "share_forward_failed",
            GatewayReason::ShareUpstreamRejected => "share_upstream_rejected",
            GatewayReason::ShareDroppedQueueFull => "share_dropped_queue_full",
            GatewayReason::ShareEvictedFromQueue => "share_evicted_from_queue",
            GatewayReason::ShareRateLimited => "share_rate_limited",
            GatewayReason::ProcessCrashRecovery => "process_crash_recovery",
            GatewayReason::WalWriteFailure => "wal_write_failure",
            // Connection lifecycle
            GatewayReason::PeerTransportError => "peer_transport_error",
            GatewayReason::ChannelOpenTimeout => "channel_open_timeout",
            GatewayReason::SetupConnectionRejected => "setup_connection_rejected",
            // Health probe status
            GatewayReason::ShutdownDrain => "shutdown_drain",
            GatewayReason::StartupPending => "startup_pending",
        }
    }

    // ── SV2 wire mapping (scope: SubmitShares.Error) ──

    /// SV2 `SubmitShares.Error` codes used by this gateway.
    pub const SV2_SHARE_ERROR_CODES: &[&str] = &[
        "stale-share",
        "difficulty-too-low",
        "invalid-job-id",
        "invalid-channel-id",
    ];

    /// Maps share-related `GatewayReason` to the SV2 `SubmitShares.Error` `error_code`.
    ///
    /// Only share-related and structural variants produce a wire code.
    /// Post-ACK internal telemetry variants (`ShareEvictedFromQueue`,
    /// `ShareForwardFailed`, `ShareUpstreamRejected`) never reach the SV2 wire
    /// and will panic if called through this method.
    pub fn to_sv2_error_code(&self) -> &'static str {
        match self {
            GatewayReason::InvalidChannelId => "invalid-channel-id",
            GatewayReason::ShareInvalidJobId => "invalid-job-id",
            GatewayReason::ShareDifficultyBelowTarget => "difficulty-too-low",
            GatewayReason::StaleJobSubmission
            | GatewayReason::ShareReplayDetected
            | GatewayReason::ShareInvalidNonce
            | GatewayReason::VersionBitViolation
            | GatewayReason::NtimeOutOfRange
            | GatewayReason::ShareDroppedQueueFull
            | GatewayReason::ShareRateLimited => "stale-share",
            // Post-ACK telemetry variants: unreachable on the wire path.
            GatewayReason::ShareEvictedFromQueue
            | GatewayReason::ShareForwardFailed
            | GatewayReason::ShareUpstreamRejected => {
                unreachable!(
                    "to_sv2_error_code called on post-ACK variant {:?}; \
                     this variant never reaches the SV2 wire",
                    self
                )
            }
            other => unreachable!("to_sv2_error_code called on non-share variant {:?}", other),
        }
    }

    /// SV2 `OpenMiningChannel.Error` codes used by this gateway.
    pub const SV2_OPEN_CHANNEL_ERROR_CODES: &[&str] = &["unknown-user", "max-target-out-of-range"];

    /// Maps channel-open `GatewayReason` to SV2 wire action.
    ///
    /// Returns `Some(code)` when the gateway should send `OpenMiningChannel.Error`
    /// with that code, or `None` when the gateway should close the connection
    /// without sending an error message (no spec-enumerated code applies).
    pub fn open_channel_wire_action(&self) -> Option<&'static str> {
        match self {
            GatewayReason::MinerUnauthorized
            | GatewayReason::IdentityPrefixUnmatched
            | GatewayReason::IdentityTooLong => Some("unknown-user"),
            _ => None,
        }
    }
}

impl std::fmt::Display for GatewayReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ─────────────────────────────────────────────────────────────────────
// ReasonCode: unified superset for API responses, logs, and dashboards
// ─────────────────────────────────────────────────────────────────────

/// Unified reason code enum spanning template verification and gateway
/// operational rejections.
///
/// Every API error response, structured log event, metrics label, and
/// exporter row uses this enum. The `reason_code` field is the stable
/// machine contract across all protocol boundaries.
///
/// Use `From<VerdictReason>` or `From<GatewayReason>` to construct.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasonCode {
    // ── Template verification (from rg_protocol::VerdictReason) ──
    ProtocolVersionMismatch,
    InvalidPrevHash,
    PrevHashLenMismatch,
    CoinbaseValueZeroRejected,
    EmptyTemplateRejected,
    TxCountExceeded,
    TotalFeesBelowMinimum,
    AvgFeeBelowMinimum,
    PolicyLoadError,
    MempoolBackendUnavailable,
    WeightRatioExceeded,
    TemplateStale,
    SigopsBudgetWarning,
    CoinbaseSigopsAbnormal,

    // ── v2.0 Invariant Shield (ADR-002 Phase 1, verifier-layer) ──
    //
    // Explicit `#[serde(rename)]` on every variant because serde's
    // automatic snake_case conversion does not guarantee an underscore
    // between a leading digit pair (`V2`) and the following uppercase
    // word. Pinning the string by hand keeps R-13 drift impossible by
    // construction.
    #[serde(rename = "v2_invariant_coinbase_value_mismatch")]
    V2InvariantCoinbaseValueMismatch,
    #[serde(rename = "v2_invariant_template_weight_mismatch")]
    V2InvariantTemplateWeightMismatch,
    #[serde(rename = "v2_invariant_merkle_root_mismatch")]
    V2InvariantMerkleRootMismatch,
    #[serde(rename = "v2_invariant_witness_commitment_missing")]
    V2InvariantWitnessCommitmentMissing,
    #[serde(rename = "v2_invariant_witness_commitment_mismatch")]
    V2InvariantWitnessCommitmentMismatch,
    #[serde(rename = "v2_invariant_sigops_mismatch")]
    V2InvariantSigopsMismatch,
    #[serde(rename = "v2_invariant_coinbase_sigops_mismatch")]
    V2InvariantCoinbaseSigopsMismatch,
    #[serde(rename = "v2_invariant_tx_count_mismatch")]
    V2InvariantTxCountMismatch,
    #[serde(rename = "v2_invariant_coinbase_script_length")]
    V2InvariantCoinbaseScriptLength,
    #[serde(rename = "v2_invariant_coinbase_output_count")]
    V2InvariantCoinbaseOutputCount,
    #[serde(rename = "v2_invariant_coinbase_bip34_missing")]
    V2InvariantCoinbaseBip34Missing,
    #[serde(rename = "v2_invariant_coinbase_height_mismatch")]
    V2InvariantCoinbaseHeightMismatch,
    #[serde(rename = "v2_invariant_weight_exceeds_max")]
    V2InvariantWeightExceedsMax,
    #[serde(rename = "v2_invariant_sigops_exceed_max")]
    V2InvariantSigopsExceedMax,
    #[serde(rename = "v2_invariant_nontcb_null_prevout")]
    V2InvariantNontcbNullPrevout,
    #[serde(rename = "v2_invariant_coinbase_prevout_not_null")]
    V2InvariantCoinbasePrevoutNotNull,
    #[serde(rename = "v2_invariant_header_version_low")]
    V2InvariantHeaderVersionLow,
    #[serde(rename = "v2_invariant_duplicate_tx")]
    V2InvariantDuplicateTx,
    #[serde(rename = "v2_invariant_decode_failed")]
    V2InvariantDecodeFailed,

    // ── v2.0 Invariant Shield Phase 2 (ADR-003) ──
    #[serde(rename = "v2_invariant_mempool_tx_unknown")]
    V2InvariantMempoolTxUnknown,
    #[serde(rename = "v2_invariant_mempool_tolerance_exceeded")]
    V2InvariantMempoolToleranceExceeded,
    #[serde(rename = "v2_invariant_mempool_unavailable")]
    V2InvariantMempoolUnavailable,
    #[serde(rename = "v2_invariant_mempool_view_stale")]
    V2InvariantMempoolViewStale,

    // ── Gateway operational (from GatewayReason) ──
    AuthFailed,
    UnsupportedAlgorithm,
    RateLimited,
    PayloadTooLarge,
    InvalidContentType,
    PayloadUnknownField,
    PayloadFieldOutOfRange,
    PayloadMalformed,
    PayloadNestingExceeded,
    RequestExpired,
    RequestReplayed,
    HandlerTimeout,
    ConfigInvalid,
    InternalLineTooLarge,
    InternalFramingError,
    InternalVersionMismatch,
    InternalUnknownMsgFlood,

    // ── SV2 transport ──
    NoiseHandshakeFailed,
    NoiseHandshakeTimeout,
    UnsupportedProtocolVersion,
    FrameDecodeError,
    FrameTooLarge,
    ConnectionRateLimited,
    PeerQuotaExceeded,

    // ── Miner authorization ──
    MinerUnauthorized,
    IdentityPrefixUnmatched,
    IdentityTooLong,

    // ── Channel lifecycle ──
    ChannelOpenRejected,
    ChannelLimitExceeded,
    InvalidChannelId,
    ExtendedChannelUnsupported,

    // ── Job path ──
    PrevhashSwitchTimeout,
    PrevhashVerdictRejected,
    TemplateCacheMiss,
    StaleJobSubmission,
    UpstreamUnavailable,

    // ── Share ingestion (gateway → template-manager HMAC validation) ──
    MissingGatewaySignature,
    MalformedGatewaySignature,
    MalformedEventId,
    InvalidGatewaySignature,

    // ── Share validation ──
    ShareReplayDetected,
    ShareDifficultyBelowTarget,
    ShareInvalidJobId,
    ShareInvalidNonce,
    VersionBitViolation,
    NtimeOutOfRange,
    ShareForwardFailed,
    ShareUpstreamRejected,
    ShareDroppedQueueFull,
    ShareEvictedFromQueue,
    ShareRateLimited,

    // ── Crash recovery ──
    /// Synthetic forward result for shares orphaned by a process crash
    ProcessCrashRecovery,
    /// WAL append failed; gateway is shutting down to preserve durability
    WalWriteFailure,

    // ── Connection lifecycle (disconnect telemetry) ──
    /// Peer TCP connection dropped or transport I/O error
    PeerTransportError,
    /// Peer did not open any mining channel within the configured timeout
    ChannelOpenTimeout,
    /// SV2 `SetupConnection` exchange failed
    SetupConnectionRejected,

    // ── Health probe status ──
    /// Gateway is draining connections during graceful shutdown
    ShutdownDrain,
    /// Gateway has not yet completed startup initialization
    StartupPending,

    // ── Shared ──
    /// Catch-all for unexpected internal failures (shared by both domains)
    InternalError,
}

impl ReasonCode {
    /// Every variant for exhaustive iteration in tests and mappings.
    pub const ALL: &[ReasonCode] = &[
        // Template verification
        ReasonCode::ProtocolVersionMismatch,
        ReasonCode::InvalidPrevHash,
        ReasonCode::PrevHashLenMismatch,
        ReasonCode::CoinbaseValueZeroRejected,
        ReasonCode::EmptyTemplateRejected,
        ReasonCode::TxCountExceeded,
        ReasonCode::TotalFeesBelowMinimum,
        ReasonCode::AvgFeeBelowMinimum,
        ReasonCode::PolicyLoadError,
        ReasonCode::MempoolBackendUnavailable,
        ReasonCode::WeightRatioExceeded,
        ReasonCode::TemplateStale,
        ReasonCode::SigopsBudgetWarning,
        ReasonCode::CoinbaseSigopsAbnormal,
        // v2.0 Invariant Shield (ADR-002)
        ReasonCode::V2InvariantCoinbaseValueMismatch,
        ReasonCode::V2InvariantTemplateWeightMismatch,
        ReasonCode::V2InvariantMerkleRootMismatch,
        ReasonCode::V2InvariantWitnessCommitmentMissing,
        ReasonCode::V2InvariantWitnessCommitmentMismatch,
        ReasonCode::V2InvariantSigopsMismatch,
        ReasonCode::V2InvariantCoinbaseSigopsMismatch,
        ReasonCode::V2InvariantTxCountMismatch,
        ReasonCode::V2InvariantCoinbaseScriptLength,
        ReasonCode::V2InvariantCoinbaseOutputCount,
        ReasonCode::V2InvariantCoinbaseBip34Missing,
        ReasonCode::V2InvariantCoinbaseHeightMismatch,
        ReasonCode::V2InvariantWeightExceedsMax,
        ReasonCode::V2InvariantSigopsExceedMax,
        ReasonCode::V2InvariantNontcbNullPrevout,
        ReasonCode::V2InvariantCoinbasePrevoutNotNull,
        ReasonCode::V2InvariantHeaderVersionLow,
        ReasonCode::V2InvariantDuplicateTx,
        ReasonCode::V2InvariantDecodeFailed,
        // v2.0 Invariant Shield Phase 2 (ADR-003)
        ReasonCode::V2InvariantMempoolTxUnknown,
        ReasonCode::V2InvariantMempoolToleranceExceeded,
        ReasonCode::V2InvariantMempoolUnavailable,
        ReasonCode::V2InvariantMempoolViewStale,
        // Gateway operational
        ReasonCode::AuthFailed,
        ReasonCode::UnsupportedAlgorithm,
        ReasonCode::RateLimited,
        ReasonCode::PayloadTooLarge,
        ReasonCode::InvalidContentType,
        ReasonCode::PayloadUnknownField,
        ReasonCode::PayloadFieldOutOfRange,
        ReasonCode::PayloadMalformed,
        ReasonCode::PayloadNestingExceeded,
        ReasonCode::RequestExpired,
        ReasonCode::RequestReplayed,
        ReasonCode::HandlerTimeout,
        ReasonCode::ConfigInvalid,
        ReasonCode::InternalLineTooLarge,
        ReasonCode::InternalFramingError,
        ReasonCode::InternalVersionMismatch,
        ReasonCode::InternalUnknownMsgFlood,
        // SV2 transport
        ReasonCode::NoiseHandshakeFailed,
        ReasonCode::NoiseHandshakeTimeout,
        ReasonCode::UnsupportedProtocolVersion,
        ReasonCode::FrameDecodeError,
        ReasonCode::FrameTooLarge,
        ReasonCode::ConnectionRateLimited,
        ReasonCode::PeerQuotaExceeded,
        // Miner authorization
        ReasonCode::MinerUnauthorized,
        ReasonCode::IdentityPrefixUnmatched,
        ReasonCode::IdentityTooLong,
        // Channel lifecycle
        ReasonCode::ChannelOpenRejected,
        ReasonCode::ChannelLimitExceeded,
        ReasonCode::InvalidChannelId,
        ReasonCode::ExtendedChannelUnsupported,
        // Job path
        ReasonCode::PrevhashSwitchTimeout,
        ReasonCode::PrevhashVerdictRejected,
        ReasonCode::TemplateCacheMiss,
        ReasonCode::StaleJobSubmission,
        ReasonCode::UpstreamUnavailable,
        // Share ingestion (gateway → template-manager HMAC validation)
        ReasonCode::MissingGatewaySignature,
        ReasonCode::MalformedGatewaySignature,
        ReasonCode::MalformedEventId,
        ReasonCode::InvalidGatewaySignature,
        // Share validation
        ReasonCode::ShareReplayDetected,
        ReasonCode::ShareDifficultyBelowTarget,
        ReasonCode::ShareInvalidJobId,
        ReasonCode::ShareInvalidNonce,
        ReasonCode::VersionBitViolation,
        ReasonCode::NtimeOutOfRange,
        ReasonCode::ShareForwardFailed,
        ReasonCode::ShareUpstreamRejected,
        ReasonCode::ShareDroppedQueueFull,
        ReasonCode::ShareEvictedFromQueue,
        ReasonCode::ShareRateLimited,
        // Crash recovery
        ReasonCode::ProcessCrashRecovery,
        ReasonCode::WalWriteFailure,
        // Connection lifecycle
        ReasonCode::PeerTransportError,
        ReasonCode::ChannelOpenTimeout,
        ReasonCode::SetupConnectionRejected,
        // Health probe status
        ReasonCode::ShutdownDrain,
        ReasonCode::StartupPending,
        // Shared
        ReasonCode::InternalError,
    ];

    /// All canonical `snake_case` reason code strings. Order matches `ALL`.
    pub const ALL_CODES: &[&str] = &[
        "protocol_version_mismatch",
        "invalid_prev_hash",
        "prev_hash_len_mismatch",
        "coinbase_value_zero_rejected",
        "empty_template_rejected",
        "tx_count_exceeded",
        "total_fees_below_minimum",
        "avg_fee_below_minimum",
        "policy_load_error",
        "mempool_backend_unavailable",
        "weight_ratio_exceeded",
        "template_stale",
        "sigops_budget_warning",
        "coinbase_sigops_abnormal",
        // v2.0 Invariant Shield (ADR-002)
        "v2_invariant_coinbase_value_mismatch",
        "v2_invariant_template_weight_mismatch",
        "v2_invariant_merkle_root_mismatch",
        "v2_invariant_witness_commitment_missing",
        "v2_invariant_witness_commitment_mismatch",
        "v2_invariant_sigops_mismatch",
        "v2_invariant_coinbase_sigops_mismatch",
        "v2_invariant_tx_count_mismatch",
        "v2_invariant_coinbase_script_length",
        "v2_invariant_coinbase_output_count",
        "v2_invariant_coinbase_bip34_missing",
        "v2_invariant_coinbase_height_mismatch",
        "v2_invariant_weight_exceeds_max",
        "v2_invariant_sigops_exceed_max",
        "v2_invariant_nontcb_null_prevout",
        "v2_invariant_coinbase_prevout_not_null",
        "v2_invariant_header_version_low",
        "v2_invariant_duplicate_tx",
        "v2_invariant_decode_failed",
        "v2_invariant_mempool_tx_unknown",
        "v2_invariant_mempool_tolerance_exceeded",
        "v2_invariant_mempool_unavailable",
        "v2_invariant_mempool_view_stale",
        "auth_failed",
        "unsupported_algorithm",
        "rate_limited",
        "payload_too_large",
        "invalid_content_type",
        "payload_unknown_field",
        "payload_field_out_of_range",
        "payload_malformed",
        "payload_nesting_exceeded",
        "request_expired",
        "request_replayed",
        "handler_timeout",
        "config_invalid",
        "internal_line_too_large",
        "internal_framing_error",
        "internal_version_mismatch",
        "internal_unknown_msg_flood",
        // SV2 transport
        "noise_handshake_failed",
        "noise_handshake_timeout",
        "unsupported_protocol_version",
        "frame_decode_error",
        "frame_too_large",
        "connection_rate_limited",
        "peer_quota_exceeded",
        // Miner authorization
        "miner_unauthorized",
        "identity_prefix_unmatched",
        "identity_too_long",
        // Channel lifecycle
        "channel_open_rejected",
        "channel_limit_exceeded",
        "invalid_channel_id",
        "extended_channel_unsupported",
        // Job path
        "prevhash_switch_timeout",
        "prevhash_verdict_rejected",
        "template_cache_miss",
        "stale_job_submission",
        "upstream_unavailable",
        // Share ingestion (gateway → template-manager HMAC validation)
        "missing_gateway_signature",
        "malformed_gateway_signature",
        "malformed_event_id",
        "invalid_gateway_signature",
        // Share validation
        "share_replay_detected",
        "share_difficulty_below_target",
        "share_invalid_job_id",
        "share_invalid_nonce",
        "version_bit_violation",
        "ntime_out_of_range",
        "share_forward_failed",
        "share_upstream_rejected",
        "share_dropped_queue_full",
        "share_evicted_from_queue",
        "share_rate_limited",
        // Crash recovery
        "process_crash_recovery",
        "wal_write_failure",
        // Connection lifecycle
        "peer_transport_error",
        "channel_open_timeout",
        "setup_connection_rejected",
        // Health probe status
        "shutdown_drain",
        "startup_pending",
        "internal_error",
    ];

    /// Canonical `snake_case` string for this reason code.
    #[allow(clippy::too_many_lines)]
    pub fn as_str(&self) -> &'static str {
        match self {
            // Template verification
            ReasonCode::ProtocolVersionMismatch => "protocol_version_mismatch",
            ReasonCode::InvalidPrevHash => "invalid_prev_hash",
            ReasonCode::PrevHashLenMismatch => "prev_hash_len_mismatch",
            ReasonCode::CoinbaseValueZeroRejected => "coinbase_value_zero_rejected",
            ReasonCode::EmptyTemplateRejected => "empty_template_rejected",
            ReasonCode::TxCountExceeded => "tx_count_exceeded",
            ReasonCode::TotalFeesBelowMinimum => "total_fees_below_minimum",
            ReasonCode::AvgFeeBelowMinimum => "avg_fee_below_minimum",
            ReasonCode::PolicyLoadError => "policy_load_error",
            ReasonCode::MempoolBackendUnavailable => "mempool_backend_unavailable",
            ReasonCode::WeightRatioExceeded => "weight_ratio_exceeded",
            ReasonCode::TemplateStale => "template_stale",
            ReasonCode::SigopsBudgetWarning => "sigops_budget_warning",
            ReasonCode::CoinbaseSigopsAbnormal => "coinbase_sigops_abnormal",
            // v2.0 Invariant Shield (ADR-002)
            ReasonCode::V2InvariantCoinbaseValueMismatch => "v2_invariant_coinbase_value_mismatch",
            ReasonCode::V2InvariantTemplateWeightMismatch => {
                "v2_invariant_template_weight_mismatch"
            }
            ReasonCode::V2InvariantMerkleRootMismatch => "v2_invariant_merkle_root_mismatch",
            ReasonCode::V2InvariantWitnessCommitmentMissing => {
                "v2_invariant_witness_commitment_missing"
            }
            ReasonCode::V2InvariantWitnessCommitmentMismatch => {
                "v2_invariant_witness_commitment_mismatch"
            }
            ReasonCode::V2InvariantSigopsMismatch => "v2_invariant_sigops_mismatch",
            ReasonCode::V2InvariantCoinbaseSigopsMismatch => {
                "v2_invariant_coinbase_sigops_mismatch"
            }
            ReasonCode::V2InvariantTxCountMismatch => "v2_invariant_tx_count_mismatch",
            ReasonCode::V2InvariantCoinbaseScriptLength => "v2_invariant_coinbase_script_length",
            ReasonCode::V2InvariantCoinbaseOutputCount => "v2_invariant_coinbase_output_count",
            ReasonCode::V2InvariantCoinbaseBip34Missing => "v2_invariant_coinbase_bip34_missing",
            ReasonCode::V2InvariantCoinbaseHeightMismatch => {
                "v2_invariant_coinbase_height_mismatch"
            }
            ReasonCode::V2InvariantWeightExceedsMax => "v2_invariant_weight_exceeds_max",
            ReasonCode::V2InvariantSigopsExceedMax => "v2_invariant_sigops_exceed_max",
            ReasonCode::V2InvariantNontcbNullPrevout => "v2_invariant_nontcb_null_prevout",
            ReasonCode::V2InvariantCoinbasePrevoutNotNull => {
                "v2_invariant_coinbase_prevout_not_null"
            }
            ReasonCode::V2InvariantHeaderVersionLow => "v2_invariant_header_version_low",
            ReasonCode::V2InvariantDuplicateTx => "v2_invariant_duplicate_tx",
            ReasonCode::V2InvariantDecodeFailed => "v2_invariant_decode_failed",
            // v2.0 Invariant Shield Phase 2 (ADR-003)
            ReasonCode::V2InvariantMempoolTxUnknown => "v2_invariant_mempool_tx_unknown",
            ReasonCode::V2InvariantMempoolToleranceExceeded => {
                "v2_invariant_mempool_tolerance_exceeded"
            }
            ReasonCode::V2InvariantMempoolUnavailable => "v2_invariant_mempool_unavailable",
            ReasonCode::V2InvariantMempoolViewStale => "v2_invariant_mempool_view_stale",
            // Gateway operational
            ReasonCode::AuthFailed => "auth_failed",
            ReasonCode::UnsupportedAlgorithm => "unsupported_algorithm",
            ReasonCode::RateLimited => "rate_limited",
            ReasonCode::PayloadTooLarge => "payload_too_large",
            ReasonCode::InvalidContentType => "invalid_content_type",
            ReasonCode::PayloadUnknownField => "payload_unknown_field",
            ReasonCode::PayloadFieldOutOfRange => "payload_field_out_of_range",
            ReasonCode::PayloadMalformed => "payload_malformed",
            ReasonCode::PayloadNestingExceeded => "payload_nesting_exceeded",
            ReasonCode::RequestExpired => "request_expired",
            ReasonCode::RequestReplayed => "request_replayed",
            ReasonCode::HandlerTimeout => "handler_timeout",
            ReasonCode::ConfigInvalid => "config_invalid",
            ReasonCode::InternalLineTooLarge => "internal_line_too_large",
            ReasonCode::InternalFramingError => "internal_framing_error",
            ReasonCode::InternalVersionMismatch => "internal_version_mismatch",
            ReasonCode::InternalUnknownMsgFlood => "internal_unknown_msg_flood",
            // SV2 transport
            ReasonCode::NoiseHandshakeFailed => "noise_handshake_failed",
            ReasonCode::NoiseHandshakeTimeout => "noise_handshake_timeout",
            ReasonCode::UnsupportedProtocolVersion => "unsupported_protocol_version",
            ReasonCode::FrameDecodeError => "frame_decode_error",
            ReasonCode::FrameTooLarge => "frame_too_large",
            ReasonCode::ConnectionRateLimited => "connection_rate_limited",
            ReasonCode::PeerQuotaExceeded => "peer_quota_exceeded",
            // Miner authorization
            ReasonCode::MinerUnauthorized => "miner_unauthorized",
            ReasonCode::IdentityPrefixUnmatched => "identity_prefix_unmatched",
            ReasonCode::IdentityTooLong => "identity_too_long",
            // Channel lifecycle
            ReasonCode::ChannelOpenRejected => "channel_open_rejected",
            ReasonCode::ChannelLimitExceeded => "channel_limit_exceeded",
            ReasonCode::InvalidChannelId => "invalid_channel_id",
            ReasonCode::ExtendedChannelUnsupported => "extended_channel_unsupported",
            // Job path
            ReasonCode::PrevhashSwitchTimeout => "prevhash_switch_timeout",
            ReasonCode::PrevhashVerdictRejected => "prevhash_verdict_rejected",
            ReasonCode::TemplateCacheMiss => "template_cache_miss",
            ReasonCode::StaleJobSubmission => "stale_job_submission",
            ReasonCode::UpstreamUnavailable => "upstream_unavailable",
            // Share ingestion (gateway → template-manager HMAC validation)
            ReasonCode::MissingGatewaySignature => "missing_gateway_signature",
            ReasonCode::MalformedGatewaySignature => "malformed_gateway_signature",
            ReasonCode::MalformedEventId => "malformed_event_id",
            ReasonCode::InvalidGatewaySignature => "invalid_gateway_signature",
            // Share validation
            ReasonCode::ShareReplayDetected => "share_replay_detected",
            ReasonCode::ShareDifficultyBelowTarget => "share_difficulty_below_target",
            ReasonCode::ShareInvalidJobId => "share_invalid_job_id",
            ReasonCode::ShareInvalidNonce => "share_invalid_nonce",
            ReasonCode::VersionBitViolation => "version_bit_violation",
            ReasonCode::NtimeOutOfRange => "ntime_out_of_range",
            ReasonCode::ShareForwardFailed => "share_forward_failed",
            ReasonCode::ShareUpstreamRejected => "share_upstream_rejected",
            ReasonCode::ShareDroppedQueueFull => "share_dropped_queue_full",
            ReasonCode::ShareEvictedFromQueue => "share_evicted_from_queue",
            ReasonCode::ShareRateLimited => "share_rate_limited",
            // Crash recovery
            ReasonCode::ProcessCrashRecovery => "process_crash_recovery",
            ReasonCode::WalWriteFailure => "wal_write_failure",
            // Connection lifecycle
            ReasonCode::PeerTransportError => "peer_transport_error",
            ReasonCode::ChannelOpenTimeout => "channel_open_timeout",
            ReasonCode::SetupConnectionRejected => "setup_connection_rejected",
            // Health probe status
            ReasonCode::ShutdownDrain => "shutdown_drain",
            ReasonCode::StartupPending => "startup_pending",
            // Shared
            ReasonCode::InternalError => "internal_error",
        }
    }
}

impl std::fmt::Display for ReasonCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── From conversions ────────────────────────────────────────────────

impl From<VerdictReason> for ReasonCode {
    fn from(v: VerdictReason) -> Self {
        match v {
            VerdictReason::ProtocolVersionMismatch => ReasonCode::ProtocolVersionMismatch,
            VerdictReason::InvalidPrevHash => ReasonCode::InvalidPrevHash,
            VerdictReason::PrevHashLenMismatch => ReasonCode::PrevHashLenMismatch,
            VerdictReason::CoinbaseValueZeroRejected => ReasonCode::CoinbaseValueZeroRejected,
            VerdictReason::EmptyTemplateRejected => ReasonCode::EmptyTemplateRejected,
            VerdictReason::TxCountExceeded => ReasonCode::TxCountExceeded,
            VerdictReason::TotalFeesBelowMinimum => ReasonCode::TotalFeesBelowMinimum,
            VerdictReason::AvgFeeBelowMinimum => ReasonCode::AvgFeeBelowMinimum,
            VerdictReason::PolicyLoadError => ReasonCode::PolicyLoadError,
            VerdictReason::MempoolBackendUnavailable => ReasonCode::MempoolBackendUnavailable,
            VerdictReason::InternalError => ReasonCode::InternalError,
            VerdictReason::WeightRatioExceeded => ReasonCode::WeightRatioExceeded,
            VerdictReason::TemplateStale => ReasonCode::TemplateStale,
            VerdictReason::SigopsBudgetWarning => ReasonCode::SigopsBudgetWarning,
            VerdictReason::CoinbaseSigopsAbnormal => ReasonCode::CoinbaseSigopsAbnormal,
            // v2.0 Invariant Shield (ADR-002)
            VerdictReason::V2InvariantCoinbaseValueMismatch => {
                ReasonCode::V2InvariantCoinbaseValueMismatch
            }
            VerdictReason::V2InvariantTemplateWeightMismatch => {
                ReasonCode::V2InvariantTemplateWeightMismatch
            }
            VerdictReason::V2InvariantMerkleRootMismatch => {
                ReasonCode::V2InvariantMerkleRootMismatch
            }
            VerdictReason::V2InvariantWitnessCommitmentMissing => {
                ReasonCode::V2InvariantWitnessCommitmentMissing
            }
            VerdictReason::V2InvariantWitnessCommitmentMismatch => {
                ReasonCode::V2InvariantWitnessCommitmentMismatch
            }
            VerdictReason::V2InvariantSigopsMismatch => ReasonCode::V2InvariantSigopsMismatch,
            VerdictReason::V2InvariantCoinbaseSigopsMismatch => {
                ReasonCode::V2InvariantCoinbaseSigopsMismatch
            }
            VerdictReason::V2InvariantTxCountMismatch => ReasonCode::V2InvariantTxCountMismatch,
            VerdictReason::V2InvariantCoinbaseScriptLength => {
                ReasonCode::V2InvariantCoinbaseScriptLength
            }
            VerdictReason::V2InvariantCoinbaseOutputCount => {
                ReasonCode::V2InvariantCoinbaseOutputCount
            }
            VerdictReason::V2InvariantCoinbaseBip34Missing => {
                ReasonCode::V2InvariantCoinbaseBip34Missing
            }
            VerdictReason::V2InvariantCoinbaseHeightMismatch => {
                ReasonCode::V2InvariantCoinbaseHeightMismatch
            }
            VerdictReason::V2InvariantWeightExceedsMax => ReasonCode::V2InvariantWeightExceedsMax,
            VerdictReason::V2InvariantSigopsExceedMax => ReasonCode::V2InvariantSigopsExceedMax,
            VerdictReason::V2InvariantNontcbNullPrevout => ReasonCode::V2InvariantNontcbNullPrevout,
            VerdictReason::V2InvariantCoinbasePrevoutNotNull => {
                ReasonCode::V2InvariantCoinbasePrevoutNotNull
            }
            VerdictReason::V2InvariantHeaderVersionLow => ReasonCode::V2InvariantHeaderVersionLow,
            VerdictReason::V2InvariantDuplicateTx => ReasonCode::V2InvariantDuplicateTx,
            VerdictReason::V2InvariantDecodeFailed => ReasonCode::V2InvariantDecodeFailed,
            // v2.0 Invariant Shield Phase 2 (ADR-003)
            VerdictReason::V2InvariantMempoolTxUnknown => ReasonCode::V2InvariantMempoolTxUnknown,
            VerdictReason::V2InvariantMempoolToleranceExceeded => {
                ReasonCode::V2InvariantMempoolToleranceExceeded
            }
            VerdictReason::V2InvariantMempoolUnavailable => {
                ReasonCode::V2InvariantMempoolUnavailable
            }
            VerdictReason::V2InvariantMempoolViewStale => ReasonCode::V2InvariantMempoolViewStale,
        }
    }
}

impl From<GatewayReason> for ReasonCode {
    fn from(g: GatewayReason) -> Self {
        match g {
            GatewayReason::AuthFailed => ReasonCode::AuthFailed,
            GatewayReason::UnsupportedAlgorithm => ReasonCode::UnsupportedAlgorithm,
            GatewayReason::RateLimited => ReasonCode::RateLimited,
            GatewayReason::PayloadTooLarge => ReasonCode::PayloadTooLarge,
            GatewayReason::InvalidContentType => ReasonCode::InvalidContentType,
            GatewayReason::PayloadUnknownField => ReasonCode::PayloadUnknownField,
            GatewayReason::PayloadFieldOutOfRange => ReasonCode::PayloadFieldOutOfRange,
            GatewayReason::PayloadMalformed => ReasonCode::PayloadMalformed,
            GatewayReason::PayloadNestingExceeded => ReasonCode::PayloadNestingExceeded,
            GatewayReason::RequestExpired => ReasonCode::RequestExpired,
            GatewayReason::RequestReplayed => ReasonCode::RequestReplayed,
            GatewayReason::HandlerTimeout => ReasonCode::HandlerTimeout,
            GatewayReason::ConfigInvalid => ReasonCode::ConfigInvalid,
            GatewayReason::InternalError => ReasonCode::InternalError,
            GatewayReason::InternalLineTooLarge => ReasonCode::InternalLineTooLarge,
            GatewayReason::InternalFramingError => ReasonCode::InternalFramingError,
            GatewayReason::InternalVersionMismatch => ReasonCode::InternalVersionMismatch,
            GatewayReason::InternalUnknownMsgFlood => ReasonCode::InternalUnknownMsgFlood,
            // SV2 transport
            GatewayReason::NoiseHandshakeFailed => ReasonCode::NoiseHandshakeFailed,
            GatewayReason::NoiseHandshakeTimeout => ReasonCode::NoiseHandshakeTimeout,
            GatewayReason::UnsupportedProtocolVersion => ReasonCode::UnsupportedProtocolVersion,
            GatewayReason::FrameDecodeError => ReasonCode::FrameDecodeError,
            GatewayReason::FrameTooLarge => ReasonCode::FrameTooLarge,
            GatewayReason::ConnectionRateLimited => ReasonCode::ConnectionRateLimited,
            GatewayReason::PeerQuotaExceeded => ReasonCode::PeerQuotaExceeded,
            // Miner authorization
            GatewayReason::MinerUnauthorized => ReasonCode::MinerUnauthorized,
            GatewayReason::IdentityPrefixUnmatched => ReasonCode::IdentityPrefixUnmatched,
            GatewayReason::IdentityTooLong => ReasonCode::IdentityTooLong,
            // Channel lifecycle
            GatewayReason::ChannelOpenRejected => ReasonCode::ChannelOpenRejected,
            GatewayReason::ChannelLimitExceeded => ReasonCode::ChannelLimitExceeded,
            GatewayReason::InvalidChannelId => ReasonCode::InvalidChannelId,
            GatewayReason::ExtendedChannelUnsupported => ReasonCode::ExtendedChannelUnsupported,
            // Job path
            GatewayReason::PrevhashSwitchTimeout => ReasonCode::PrevhashSwitchTimeout,
            GatewayReason::PrevhashVerdictRejected => ReasonCode::PrevhashVerdictRejected,
            GatewayReason::TemplateCacheMiss => ReasonCode::TemplateCacheMiss,
            GatewayReason::StaleJobSubmission => ReasonCode::StaleJobSubmission,
            GatewayReason::UpstreamUnavailable => ReasonCode::UpstreamUnavailable,
            // Share ingestion (gateway → template-manager HMAC validation)
            GatewayReason::MissingGatewaySignature => ReasonCode::MissingGatewaySignature,
            GatewayReason::MalformedGatewaySignature => ReasonCode::MalformedGatewaySignature,
            GatewayReason::MalformedEventId => ReasonCode::MalformedEventId,
            GatewayReason::InvalidGatewaySignature => ReasonCode::InvalidGatewaySignature,
            // Share validation
            GatewayReason::ShareReplayDetected => ReasonCode::ShareReplayDetected,
            GatewayReason::ShareDifficultyBelowTarget => ReasonCode::ShareDifficultyBelowTarget,
            GatewayReason::ShareInvalidJobId => ReasonCode::ShareInvalidJobId,
            GatewayReason::ShareInvalidNonce => ReasonCode::ShareInvalidNonce,
            GatewayReason::VersionBitViolation => ReasonCode::VersionBitViolation,
            GatewayReason::NtimeOutOfRange => ReasonCode::NtimeOutOfRange,
            GatewayReason::ShareForwardFailed => ReasonCode::ShareForwardFailed,
            GatewayReason::ShareUpstreamRejected => ReasonCode::ShareUpstreamRejected,
            GatewayReason::ShareDroppedQueueFull => ReasonCode::ShareDroppedQueueFull,
            GatewayReason::ShareEvictedFromQueue => ReasonCode::ShareEvictedFromQueue,
            GatewayReason::ShareRateLimited => ReasonCode::ShareRateLimited,
            // Crash recovery
            GatewayReason::ProcessCrashRecovery => ReasonCode::ProcessCrashRecovery,
            GatewayReason::WalWriteFailure => ReasonCode::WalWriteFailure,
            // Connection lifecycle
            GatewayReason::PeerTransportError => ReasonCode::PeerTransportError,
            GatewayReason::ChannelOpenTimeout => ReasonCode::ChannelOpenTimeout,
            GatewayReason::SetupConnectionRejected => ReasonCode::SetupConnectionRejected,
            // Health probe status
            GatewayReason::ShutdownDrain => ReasonCode::ShutdownDrain,
            GatewayReason::StartupPending => ReasonCode::StartupPending,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // ── GatewayReason tests ──

    #[test]
    fn gateway_as_str_matches_serde_for_all_variants() {
        for variant in GatewayReason::ALL {
            let serde_json = serde_json::to_string(variant).expect("serialize");
            let expected = format!("\"{}\"", variant.as_str());
            assert_eq!(
                serde_json, expected,
                "as_str() drift for {variant:?}: serde={serde_json} as_str={expected}",
            );
        }
    }

    #[test]
    fn gateway_all_constant_covers_every_variant() {
        assert_eq!(
            GatewayReason::ALL.len(),
            59,
            "GatewayReason::ALL length mismatch: did you add a variant?"
        );
    }

    #[test]
    fn gateway_serde_round_trip_all_variants() {
        for variant in GatewayReason::ALL {
            let json = serde_json::to_string(variant).expect("serialize");
            let back: GatewayReason = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*variant, back, "serde round-trip failed for {variant:?}");
        }
    }

    #[test]
    fn gateway_display_matches_as_str() {
        for variant in GatewayReason::ALL {
            assert_eq!(
                variant.to_string(),
                variant.as_str(),
                "Display drift for {variant:?}",
            );
        }
    }

    #[test]
    fn gateway_all_strings_are_snake_case() {
        for variant in GatewayReason::ALL {
            let s = variant.as_str();
            assert!(
                s.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "reason code {variant:?} is not snake_case: {s}",
            );
        }
    }

    #[test]
    fn gateway_all_codes_matches_all_variants() {
        assert_eq!(
            GatewayReason::ALL.len(),
            GatewayReason::ALL_CODES.len(),
            "ALL and ALL_CODES length mismatch"
        );
        for (variant, code) in GatewayReason::ALL
            .iter()
            .zip(GatewayReason::ALL_CODES.iter())
        {
            assert_eq!(variant.as_str(), *code, "ALL_CODES drift for {variant:?}");
        }
    }

    #[test]
    fn gateway_no_overlap_with_verdict_reason_codes() {
        // Uses rg_protocol::VerdictReason directly instead of hardcoded strings.
        for gw_code in GatewayReason::ALL_CODES {
            if *gw_code == "internal_error" {
                continue; // intentionally shared
            }
            for vr in VerdictReason::ALL {
                assert_ne!(
                    *gw_code,
                    vr.as_str(),
                    "GatewayReason code {gw_code} collides with VerdictReason::{vr:?}",
                );
            }
        }
    }

    // ── ReasonCode tests ──

    #[test]
    fn reason_code_all_constant_length() {
        // 32 verdict (excluding internal_error) + 58 gateway (excluding internal_error) + 1 shared
        // = 91 after ADR-002 Phase 1 mirrored the 18 v2_invariant_* codes from VerdictReason.
        // ADR-003 Phase 2 adds 4 v2_invariant_mempool_* codes, taking the total to 95.
        // PB-20 adds v2_invariant_coinbase_prevout_not_null, a 19th Phase 1
        // invariant that widens ADR-002's ratified table, taking it to 96.
        assert_eq!(
            ReasonCode::ALL.len(),
            96,
            "ReasonCode::ALL length mismatch: did you add a variant?"
        );
    }

    #[test]
    fn reason_code_as_str_matches_serde_for_all_variants() {
        for variant in ReasonCode::ALL {
            let serde_json = serde_json::to_string(variant).expect("serialize");
            let expected = format!("\"{}\"", variant.as_str());
            assert_eq!(
                serde_json, expected,
                "as_str() drift for {variant:?}: serde={serde_json} as_str={expected}",
            );
        }
    }

    #[test]
    fn reason_code_serde_round_trip_all_variants() {
        for variant in ReasonCode::ALL {
            let json = serde_json::to_string(variant).expect("serialize");
            let back: ReasonCode = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*variant, back, "serde round-trip failed for {variant:?}");
        }
    }

    #[test]
    fn reason_code_display_matches_as_str() {
        for variant in ReasonCode::ALL {
            assert_eq!(
                variant.to_string(),
                variant.as_str(),
                "Display drift for {variant:?}",
            );
        }
    }

    #[test]
    fn reason_code_all_strings_are_snake_case() {
        for variant in ReasonCode::ALL {
            let s = variant.as_str();
            assert!(
                s.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "reason code {variant:?} is not snake_case: {s}",
            );
        }
    }

    #[test]
    fn reason_code_all_codes_matches_all_variants() {
        assert_eq!(
            ReasonCode::ALL.len(),
            ReasonCode::ALL_CODES.len(),
            "ALL and ALL_CODES length mismatch"
        );
        for (variant, code) in ReasonCode::ALL.iter().zip(ReasonCode::ALL_CODES.iter()) {
            assert_eq!(variant.as_str(), *code, "ALL_CODES drift for {variant:?}");
        }
    }

    #[test]
    fn reason_code_no_duplicate_strings() {
        let mut seen = std::collections::HashSet::new();
        for variant in ReasonCode::ALL {
            assert!(
                seen.insert(variant.as_str()),
                "duplicate reason code string: {}",
                variant.as_str(),
            );
        }
    }

    // ── Cross-enum alignment: From conversions preserve strings ──

    #[test]
    fn verdict_reason_from_preserves_strings() {
        for vr in VerdictReason::ALL {
            let rc: ReasonCode = (*vr).into();
            assert_eq!(
                vr.as_str(),
                rc.as_str(),
                "From<VerdictReason> string drift for {vr:?}",
            );
        }
    }

    #[test]
    fn gateway_reason_from_preserves_strings() {
        for gr in GatewayReason::ALL {
            let rc: ReasonCode = (*gr).into();
            assert_eq!(
                gr.as_str(),
                rc.as_str(),
                "From<GatewayReason> string drift for {gr:?}",
            );
        }
    }

    #[test]
    fn reason_code_covers_all_verdict_reasons() {
        let rc_codes: std::collections::HashSet<&str> =
            ReasonCode::ALL.iter().map(ReasonCode::as_str).collect();
        for vr in VerdictReason::ALL {
            assert!(
                rc_codes.contains(vr.as_str()),
                "VerdictReason::{vr:?} ({}) missing from ReasonCode",
                vr.as_str(),
            );
        }
    }

    #[test]
    fn reason_code_covers_all_gateway_reasons() {
        let rc_codes: std::collections::HashSet<&str> =
            ReasonCode::ALL.iter().map(ReasonCode::as_str).collect();
        for gr in GatewayReason::ALL {
            assert!(
                rc_codes.contains(gr.as_str()),
                "GatewayReason::{gr:?} ({}) missing from ReasonCode",
                gr.as_str(),
            );
        }
    }

    // ── SV2 wire mapping tests ──

    /// Share-related variants that produce an SV2 wire error code.
    const SHARE_WIRE_VARIANTS: &[GatewayReason] = &[
        GatewayReason::InvalidChannelId,
        GatewayReason::ShareInvalidJobId,
        GatewayReason::StaleJobSubmission,
        GatewayReason::ShareDifficultyBelowTarget,
        GatewayReason::ShareReplayDetected,
        GatewayReason::ShareInvalidNonce,
        GatewayReason::VersionBitViolation,
        GatewayReason::NtimeOutOfRange,
        GatewayReason::ShareDroppedQueueFull,
        GatewayReason::ShareRateLimited,
    ];

    #[test]
    fn sv2_share_error_codes_are_spec_enumerated() {
        let allowed: std::collections::HashSet<&str> = GatewayReason::SV2_SHARE_ERROR_CODES
            .iter()
            .copied()
            .collect();
        for variant in SHARE_WIRE_VARIANTS {
            let code = variant.to_sv2_error_code();
            assert!(
                allowed.contains(code),
                "to_sv2_error_code({variant:?}) = {code:?} is not in SV2_SHARE_ERROR_CODES",
            );
        }
    }

    #[test]
    fn sv2_open_channel_codes_are_spec_enumerated() {
        let allowed: std::collections::HashSet<&str> = GatewayReason::SV2_OPEN_CHANNEL_ERROR_CODES
            .iter()
            .copied()
            .collect();
        let channel_variants = &[
            GatewayReason::MinerUnauthorized,
            GatewayReason::IdentityPrefixUnmatched,
            GatewayReason::IdentityTooLong,
            GatewayReason::ChannelOpenRejected,
            GatewayReason::ChannelLimitExceeded,
            GatewayReason::ExtendedChannelUnsupported,
        ];
        for variant in channel_variants {
            if let Some(code) = variant.open_channel_wire_action() {
                assert!(
                    allowed.contains(code),
                    "open_channel_wire_action({variant:?}) = {code:?} is not spec-enumerated",
                );
            }
            // None means close-without-error, which is valid
        }
    }

    #[test]
    fn auth_variants_map_to_unknown_user() {
        assert_eq!(
            GatewayReason::MinerUnauthorized.open_channel_wire_action(),
            Some("unknown-user"),
        );
        assert_eq!(
            GatewayReason::IdentityPrefixUnmatched.open_channel_wire_action(),
            Some("unknown-user"),
        );
        assert_eq!(
            GatewayReason::IdentityTooLong.open_channel_wire_action(),
            Some("unknown-user"),
        );
    }

    #[test]
    fn non_mappable_channel_reasons_close_without_error() {
        assert_eq!(
            GatewayReason::ChannelOpenRejected.open_channel_wire_action(),
            None
        );
        assert_eq!(
            GatewayReason::ChannelLimitExceeded.open_channel_wire_action(),
            None
        );
        assert_eq!(
            GatewayReason::ExtendedChannelUnsupported.open_channel_wire_action(),
            None,
        );
    }
}
