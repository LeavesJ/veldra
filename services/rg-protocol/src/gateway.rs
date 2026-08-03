//! Gateway types and constants shared across the reservegrid-os stack.
//!
//! These types are defined in `rg-protocol` because they appear in the
//! internal gateway-to-verifier wire format and in config schema that
//! both the gateway binary and shared libraries consume.

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────
// Gateway operating mode
// ─────────────────────────────────────────────────────────────────────

/// Deployment mode for the SV2 gateway.
///
/// Controlled by config, not recompilation. Each mode changes how
/// templates, jobs, and shares are handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GatewayMode {
    /// Full verification enforcement. Templates are verified before
    /// becoming jobs. Unverified templates never reach miners.
    Inline,

    /// Data-plane presence without verdict gating. Jobs are distributed
    /// immediately while verdicts run async for telemetry only.
    Observe,

    /// Pure out-of-band audit. No miner connections. Consumes templates,
    /// runs verifier, emits verdict telemetry.
    Shadow,
}

impl GatewayMode {
    /// Canonical `snake_case` string for serialization and config files.
    pub fn as_str(&self) -> &'static str {
        match self {
            GatewayMode::Inline => "inline",
            GatewayMode::Observe => "observe",
            GatewayMode::Shadow => "shadow",
        }
    }

    /// Whether this mode accepts miner SV2 connections.
    pub fn accepts_miners(&self) -> bool {
        matches!(self, GatewayMode::Inline | GatewayMode::Observe)
    }

    /// Whether this mode gates job distribution on verifier verdicts.
    pub fn enforces_verdicts(&self) -> bool {
        matches!(self, GatewayMode::Inline)
    }

    /// Whether this mode performs share replay detection.
    pub fn detects_replay(&self) -> bool {
        matches!(self, GatewayMode::Inline)
    }
}

impl std::fmt::Display for GatewayMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ─────────────────────────────────────────────────────────────────────
// BIP 320 version rolling constants
// ─────────────────────────────────────────────────────────────────────

/// BIP 320 general purpose mask: bits 13 through 28 (inclusive, zero-indexed).
///
/// Miners may freely manipulate bits within this range for version rolling.
/// SV2 Mining Protocol explicitly permits this. The mask value `0x1fffe000`
/// is derived from the BIP's specified bit range.
///
/// See: <https://github.com/bitcoin/bips/blob/master/bip-0320.mediawiki>
pub const BIP320_GP_MASK: u32 = 0x1fff_e000;

/// BIP 320 signaling mask: the bitwise complement of `BIP320_GP_MASK`.
///
/// These are the version bits that must match the job's version exactly.
/// A miner flipping non-GP bits produces a share that can never become
/// a valid block.
pub const BIP320_SIGNALING_MASK: u32 = !BIP320_GP_MASK;

// ─────────────────────────────────────────────────────────────────────
// Bitcoin consensus constants
// ─────────────────────────────────────────────────────────────────────

/// Maximum allowed gap between a block's timestamp and the node's adjusted
/// time, per Bitcoin consensus rules.
///
/// Defined in Bitcoin Core `src/chain.h` as `MAX_FUTURE_BLOCK_TIME`.
/// The SV2 Mining Protocol references this constant in its ntime validity
/// rules. Value is 2 hours (7200 seconds).
pub const MAX_FUTURE_BLOCK_TIME_SECONDS: u32 = 7200;

/// Bitcoin difficulty-1 target used for share difficulty calculation.
///
/// `DIFF1_TARGET / channel_target` produces the integer difficulty.
/// This is a 256-bit unsigned integer stored as big-endian bytes.
///
/// Value: `0x00000000FFFF0000000000000000000000000000000000000000000000000000`
pub const DIFF1_TARGET_BE: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

// ─────────────────────────────────────────────────────────────────────
// Internal message envelope (gateway <-> verifier NDJSON)
// ─────────────────────────────────────────────────────────────────────

/// Maximum size of a single NDJSON line on the internal gateway-to-verifier
/// TCP stream. Lines exceeding this limit are rejected with
/// `internal_line_too_large`.
// PB-19 / Phase 1b: sized for `raw_block_hex`. A mainnet block caps at
// 4,000,000 WU, so at most 4 MB serialized, 8 MB hex-encoded, plus the
// JSON envelope; 20 MiB leaves better than 2x headroom.
//
// Both sides now enforce this constant *before* buffering, with a
// `take()` that resets per line: the verifier ingress since PB-18(b),
// the gateway `verifier_stream` read side since PB-23 (before PB-23 it
// compared the byte count only after `read_line` had already buffered
// the whole line, so the bound did not bind). Both sides drop the
// connection when a peer spends the budget without sending a newline,
// because a bounded reader cannot resync to the next newline.
pub const MAX_INTERNAL_LINE_BYTES: usize = 20 * 1024 * 1024; // 20 MiB

/// NDJSON envelope for messages on the gateway-to-verifier TCP stream.
///
/// The `msg_type` field drives deserialization. Unknown `msg_type` values
/// are ignored (forward compatibility) but rate-limited per minute.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalMessage {
    /// Discriminator for the payload type.
    pub msg_type: String,

    /// Protocol version of this message.
    pub version: u16,

    /// Opaque payload. Deserialized based on `msg_type`.
    #[serde(default)]
    pub payload: serde_json::Value,
}

/// Known internal message types.
pub mod msg_types {
    /// Gateway proposes a template for verification.
    pub const TEMPLATE_PROPOSE: &str = "template_propose";

    /// Verifier returns a verdict on a proposed template.
    pub const TEMPLATE_VERDICT: &str = "template_verdict";

    /// Gateway sends a heartbeat to the verifier.
    pub const HEARTBEAT: &str = "heartbeat";

    /// Verifier acknowledges a heartbeat.
    pub const HEARTBEAT_ACK: &str = "heartbeat_ack";
}

// ─────────────────────────────────────────────────────────────────────
// Share validation level
// ─────────────────────────────────────────────────────────────────────

/// Validation level applied to a share before forwarding upstream.
///
/// Carried in every `ShareSubmission` and `share_accepted` event to
/// prevent payout disputes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationLevel {
    /// SV2 protocol checklist plus replay detection (inline mode).
    Full,

    /// SV2 protocol checklist only, no replay detection (observe mode).
    Sv2,
}

impl ValidationLevel {
    /// Canonical string for wire and event serialization.
    pub fn as_str(&self) -> &'static str {
        match self {
            ValidationLevel::Full => "full",
            ValidationLevel::Sv2 => "sv2",
        }
    }
}

impl std::fmt::Display for ValidationLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ─────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // ── BIP 320 test vectors ──

    #[test]
    fn bip320_gp_mask_value() {
        assert_eq!(BIP320_GP_MASK, 0x1fff_e000);
    }

    #[test]
    fn bip320_gp_mask_bits_13_through_28_set() {
        let mut expected: u32 = 0;
        for bit in 13..=28 {
            expected |= 1 << bit;
        }
        assert_eq!(
            BIP320_GP_MASK, expected,
            "GP mask bits 13..=28 mismatch: got {BIP320_GP_MASK:#010x}, expected {expected:#010x}"
        );
    }

    #[test]
    fn bip320_signaling_mask_is_complement() {
        assert_eq!(BIP320_SIGNALING_MASK, 0xe000_1fff);
    }

    #[test]
    fn bip320_masks_cover_all_bits() {
        assert_eq!(BIP320_GP_MASK | BIP320_SIGNALING_MASK, 0xffff_ffff);
        assert_eq!(BIP320_GP_MASK & BIP320_SIGNALING_MASK, 0);
    }

    // ── Bitcoin consensus ──

    #[test]
    fn max_future_block_time_is_two_hours() {
        assert_eq!(MAX_FUTURE_BLOCK_TIME_SECONDS, 2 * 60 * 60);
    }

    // ── GatewayMode ──

    #[test]
    fn gateway_mode_serde_round_trip() {
        for mode in &[
            GatewayMode::Inline,
            GatewayMode::Observe,
            GatewayMode::Shadow,
        ] {
            let json = serde_json::to_string(mode).unwrap();
            let back: GatewayMode = serde_json::from_str(&json).unwrap();
            assert_eq!(*mode, back);
        }
    }

    #[test]
    fn gateway_mode_as_str_matches_serde() {
        for mode in &[
            GatewayMode::Inline,
            GatewayMode::Observe,
            GatewayMode::Shadow,
        ] {
            let serde_json = serde_json::to_string(mode).unwrap();
            let expected = format!("\"{}\"", mode.as_str());
            assert_eq!(serde_json, expected);
        }
    }

    #[test]
    fn gateway_mode_accepts_miners() {
        assert!(GatewayMode::Inline.accepts_miners());
        assert!(GatewayMode::Observe.accepts_miners());
        assert!(!GatewayMode::Shadow.accepts_miners());
    }

    #[test]
    fn gateway_mode_enforces_verdicts() {
        assert!(GatewayMode::Inline.enforces_verdicts());
        assert!(!GatewayMode::Observe.enforces_verdicts());
        assert!(!GatewayMode::Shadow.enforces_verdicts());
    }

    #[test]
    fn gateway_mode_detects_replay() {
        assert!(GatewayMode::Inline.detects_replay());
        assert!(!GatewayMode::Observe.detects_replay());
        assert!(!GatewayMode::Shadow.detects_replay());
    }

    // ── ValidationLevel ──

    #[test]
    fn validation_level_serde_round_trip() {
        for level in &[ValidationLevel::Full, ValidationLevel::Sv2] {
            let json = serde_json::to_string(level).unwrap();
            let back: ValidationLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(*level, back);
        }
    }

    #[test]
    fn validation_level_as_str_matches_serde() {
        for level in &[ValidationLevel::Full, ValidationLevel::Sv2] {
            let serde_json = serde_json::to_string(level).unwrap();
            let expected = format!("\"{}\"", level.as_str());
            assert_eq!(serde_json, expected);
        }
    }

    // ── InternalMessage ──

    #[test]
    fn internal_message_round_trip() {
        let msg = InternalMessage {
            msg_type: msg_types::HEARTBEAT.to_string(),
            version: 2,
            payload: serde_json::json!({}),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let back: InternalMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(back.msg_type, msg_types::HEARTBEAT);
        assert_eq!(back.version, 2);
    }

    // ── DIFF1 target ──

    #[test]
    fn diff1_target_leading_zeros() {
        assert_eq!(DIFF1_TARGET_BE[0], 0x00);
        assert_eq!(DIFF1_TARGET_BE[1], 0x00);
        assert_eq!(DIFF1_TARGET_BE[2], 0x00);
        assert_eq!(DIFF1_TARGET_BE[3], 0x00);
        assert_eq!(DIFF1_TARGET_BE[4], 0xFF);
        assert_eq!(DIFF1_TARGET_BE[5], 0xFF);
        // Rest should be zero
        for byte in &DIFF1_TARGET_BE[6..] {
            assert_eq!(*byte, 0x00);
        }
    }
}
