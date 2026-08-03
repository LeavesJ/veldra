//! Per-peer connection state and lifecycle management.
//!
//! Each accepted TCP connection goes through:
//!   1. Noise NX handshake (managed by `transport::perform_handshake`)
//!   2. `SetupConnection` exchange (SV2 protocol negotiation)
//!   3. Authenticated session (channel open, job distribution, share handling)
//!   4. Graceful or abnormal disconnect with `GatewayReason`
//!
//! `PeerState` tracks per-connection telemetry and enforces rate limits.
//! `ConnectionManager` owns the listener loop and peer lifecycle.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use reservegrid_common::reason::GatewayReason;
use tokio::sync::Semaphore;
use tracing::{info, warn};
use uuid::Uuid;

// ─────────────────────────────────────────────────────────────────────
// PeerState
// ─────────────────────────────────────────────────────────────────────

/// Per-connection state tracked from handshake through disconnect.
#[derive(Debug)]
pub struct PeerState {
    /// Unique connection identifier (`UUIDv7`, monotonic).
    pub connection_id: Uuid,

    /// Remote socket address.
    pub peer_addr: SocketAddr,

    /// Wall-clock instant the TCP connection was accepted.
    pub connected_at: Instant,

    /// Cumulative bytes received from this peer (decrypted payload).
    pub bytes_in: AtomicU64,

    /// Cumulative bytes sent to this peer (before encryption).
    pub bytes_out: AtomicU64,

    /// Number of SV2 frames successfully decoded from this peer.
    pub frames_decoded: AtomicU64,

    /// Number of protocol or transport errors on this connection.
    pub error_count: AtomicU64,

    /// Instant of the last successfully decoded inbound frame.
    pub last_frame_at: std::sync::Mutex<Instant>,

    /// Reason the connection ended. `None` while still alive.
    pub disconnect_reason: std::sync::Mutex<Option<GatewayReason>>,

    /// Number of open standard mining channels on this connection.
    pub open_channels: AtomicU64,
}

impl PeerState {
    /// Create a new `PeerState` at connection acceptance time.
    pub fn new(peer_addr: SocketAddr) -> Self {
        let now = Instant::now();
        Self {
            connection_id: Uuid::now_v7(),
            peer_addr,
            connected_at: now,
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            frames_decoded: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
            last_frame_at: std::sync::Mutex::new(now),
            disconnect_reason: std::sync::Mutex::new(None),
            open_channels: AtomicU64::new(0),
        }
    }

    /// Record inbound bytes (after decryption).
    pub fn record_bytes_in(&self, n: u64) {
        self.bytes_in.fetch_add(n, Ordering::Relaxed);
    }

    /// Record outbound bytes (before encryption).
    pub fn record_bytes_out(&self, n: u64) {
        self.bytes_out.fetch_add(n, Ordering::Relaxed);
    }

    /// Record a successfully decoded frame.
    pub fn record_frame_decoded(&self) {
        self.frames_decoded.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut last) = self.last_frame_at.lock() {
            *last = Instant::now();
        }
    }

    /// Increment the error counter and return the new value.
    pub fn record_error(&self) -> u64 {
        self.error_count.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Mark this connection as disconnected with a reason.
    pub fn set_disconnect_reason(&self, reason: GatewayReason) {
        if let Ok(mut slot) = self.disconnect_reason.lock()
            && slot.is_none()
        {
            *slot = Some(reason);
        }
    }

    /// Elapsed time since the connection was accepted.
    pub fn uptime(&self) -> std::time::Duration {
        self.connected_at.elapsed()
    }

    /// Elapsed time since the last inbound frame.
    pub fn idle_duration(&self) -> std::time::Duration {
        self.last_frame_at
            .lock()
            .map(|last| last.elapsed())
            .unwrap_or_default()
    }
}

// ─────────────────────────────────────────────────────────────────────
// ConnectionLimiter
// ─────────────────────────────────────────────────────────────────────

/// Enforces the maximum concurrent connection limit using a semaphore.
///
/// Each accepted connection acquires a permit. When the connection drops,
/// the permit is released automatically through the `OwnedSemaphorePermit`.
#[derive(Clone)]
pub struct ConnectionLimiter {
    semaphore: Arc<Semaphore>,
    max: u32,
}

impl ConnectionLimiter {
    /// Create a new limiter with the given maximum concurrent connections.
    pub fn new(max_connections: u32) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(max_connections as usize)),
            max: max_connections,
        }
    }

    /// Try to acquire a connection permit. Returns `None` if the limit
    /// is reached (caller should reject the connection with
    /// `GatewayReason::ConnectionRateLimited`).
    pub fn try_acquire(&self) -> Option<tokio::sync::OwnedSemaphorePermit> {
        Arc::clone(&self.semaphore).try_acquire_owned().ok()
    }

    /// Number of currently active connections.
    pub fn active_count(&self) -> u32 {
        let available = self.semaphore.available_permits();
        // Semaphore permits are bounded by max (u32), so truncation is safe.
        #[allow(clippy::cast_possible_truncation)]
        let available_u32 = available as u32;
        self.max.saturating_sub(available_u32)
    }

    /// Maximum configured connections.
    pub fn max_connections(&self) -> u32 {
        self.max
    }
}

// ─────────────────────────────────────────────────────────────────────
// PerIpConnectionTracker
// ─────────────────────────────────────────────────────────────────────

// Moved to `reservegrid-common` by PB-27. This exists because both this
// listener and `pool-verifier`'s NDJSON ingress need per-source-address
// accounting, and the verifier must not depend on the service it
// verifies. Re-exported here so this module's surface is unchanged.
pub use reservegrid_common::per_ip::{PerIpConnectionTracker, PerIpPermit};

// ─────────────────────────────────────────────────────────────────────
// DisconnectEvent
// ─────────────────────────────────────────────────────────────────────

/// Structured disconnect event for logging and metrics.
#[derive(Debug)]
pub struct DisconnectEvent {
    pub connection_id: Uuid,
    pub peer_addr: SocketAddr,
    pub reason: GatewayReason,
    pub uptime_ms: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub frames_decoded: u64,
    pub error_count: u64,
}

impl DisconnectEvent {
    /// Build a disconnect event from a `PeerState` and reason.
    pub fn from_peer(peer: &PeerState, reason: GatewayReason) -> Self {
        Self {
            connection_id: peer.connection_id,
            peer_addr: peer.peer_addr,
            reason,
            // Connection uptime will not exceed u64::MAX milliseconds in practice.
            #[allow(clippy::cast_possible_truncation)]
            uptime_ms: peer.uptime().as_millis() as u64,
            bytes_in: peer.bytes_in.load(Ordering::Relaxed),
            bytes_out: peer.bytes_out.load(Ordering::Relaxed),
            frames_decoded: peer.frames_decoded.load(Ordering::Relaxed),
            error_count: peer.error_count.load(Ordering::Relaxed),
        }
    }

    /// Emit a structured tracing event for this disconnect.
    pub fn log(&self) {
        let reason_str = self.reason.as_str();
        if self.error_count > 0 {
            warn!(
                connection_id = %self.connection_id,
                peer = %self.peer_addr,
                reason_code = reason_str,
                uptime_ms = self.uptime_ms,
                bytes_in = self.bytes_in,
                bytes_out = self.bytes_out,
                frames_decoded = self.frames_decoded,
                error_count = self.error_count,
                "peer disconnected with errors"
            );
        } else {
            info!(
                connection_id = %self.connection_id,
                peer = %self.peer_addr,
                reason_code = reason_str,
                uptime_ms = self.uptime_ms,
                bytes_in = self.bytes_in,
                bytes_out = self.bytes_out,
                frames_decoded = self.frames_decoded,
                "peer disconnected"
            );
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
    use std::net::{IpAddr, Ipv4Addr};

    fn test_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345)
    }

    #[test]
    fn peer_state_new_has_zero_counters() {
        let peer = PeerState::new(test_addr());
        assert_eq!(peer.bytes_in.load(Ordering::Relaxed), 0);
        assert_eq!(peer.bytes_out.load(Ordering::Relaxed), 0);
        assert_eq!(peer.frames_decoded.load(Ordering::Relaxed), 0);
        assert_eq!(peer.error_count.load(Ordering::Relaxed), 0);
        assert_eq!(peer.open_channels.load(Ordering::Relaxed), 0);
        assert!(peer.disconnect_reason.lock().unwrap().is_none());
    }

    #[test]
    fn peer_state_records_bytes_and_frames() {
        let peer = PeerState::new(test_addr());
        peer.record_bytes_in(100);
        peer.record_bytes_in(50);
        peer.record_bytes_out(200);
        peer.record_frame_decoded();
        peer.record_frame_decoded();

        assert_eq!(peer.bytes_in.load(Ordering::Relaxed), 150);
        assert_eq!(peer.bytes_out.load(Ordering::Relaxed), 200);
        assert_eq!(peer.frames_decoded.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn peer_state_error_counter_returns_new_value() {
        let peer = PeerState::new(test_addr());
        assert_eq!(peer.record_error(), 1);
        assert_eq!(peer.record_error(), 2);
        assert_eq!(peer.record_error(), 3);
    }

    #[test]
    fn peer_state_disconnect_reason_set_once() {
        let peer = PeerState::new(test_addr());
        peer.set_disconnect_reason(GatewayReason::NoiseHandshakeTimeout);
        peer.set_disconnect_reason(GatewayReason::FrameDecodeError);
        // First reason wins.
        let reason = *peer.disconnect_reason.lock().unwrap();
        assert_eq!(reason, Some(GatewayReason::NoiseHandshakeTimeout));
    }

    #[test]
    fn connection_limiter_allows_up_to_max() {
        let limiter = ConnectionLimiter::new(2);
        assert_eq!(limiter.active_count(), 0);

        let _p1 = limiter.try_acquire().unwrap();
        assert_eq!(limiter.active_count(), 1);

        let _p2 = limiter.try_acquire().unwrap();
        assert_eq!(limiter.active_count(), 2);

        // Third should fail.
        assert!(limiter.try_acquire().is_none());
        assert_eq!(limiter.active_count(), 2);
    }

    #[test]
    fn connection_limiter_releases_on_drop() {
        let limiter = ConnectionLimiter::new(1);
        {
            let _permit = limiter.try_acquire().unwrap();
            assert_eq!(limiter.active_count(), 1);
        }
        // Permit dropped, slot freed.
        assert_eq!(limiter.active_count(), 0);
        assert!(limiter.try_acquire().is_some());
    }

    #[test]
    fn disconnect_event_from_peer_captures_state() {
        let peer = PeerState::new(test_addr());
        peer.record_bytes_in(1024);
        peer.record_bytes_out(2048);
        peer.record_frame_decoded();
        let _ = peer.record_error();

        let event = DisconnectEvent::from_peer(&peer, GatewayReason::NoiseHandshakeFailed);
        assert_eq!(event.connection_id, peer.connection_id);
        assert_eq!(event.peer_addr, test_addr());
        assert_eq!(event.bytes_in, 1024);
        assert_eq!(event.bytes_out, 2048);
        assert_eq!(event.frames_decoded, 1);
        assert_eq!(event.error_count, 1);
        assert_eq!(event.reason.as_str(), "noise_handshake_failed");
    }

    #[test]
    fn peer_uuid_is_v7() {
        let peer = PeerState::new(test_addr());
        assert_eq!(
            peer.connection_id.get_version(),
            Some(uuid::Version::SortRand)
        );
    }

    #[test]
    fn disconnect_event_log_does_not_panic() {
        let peer = PeerState::new(test_addr());
        let event = DisconnectEvent::from_peer(&peer, GatewayReason::NoiseHandshakeTimeout);
        // Just ensure it does not panic. Tracing subscriber not installed in tests.
        event.log();
    }
}
