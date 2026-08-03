//! Per-source-address connection accounting, shared across ingresses.
//!
//! This lives in `reservegrid-common` because `sv2-gateway`'s miner
//! listener (`connection.rs`) and `pool-verifier`'s NDJSON ingress
//! (`ingress.rs`) both need it, and the verifier must not depend on the
//! service it verifies. PB-27 is the second consumer; before it, the
//! repo already carried three per-IP shapes (this one plus the inline
//! maps in `rg-feed-server` and `rg-demo-feed`), and a fourth copy was
//! not worth the name recognition.
//!
//! Of the three, this is the only shape whose map is bounded and whose
//! decrement is an RAII `Drop` rather than a manual `fetch_sub` at the
//! end of a connection task, which is why it is the one that moved.
//! `rg-feed-server` and `rg-demo-feed` keep their inline copies: both
//! use a `tokio::sync::Mutex` inside an already-async accept loop, and
//! converting them is unrelated churn on services this change does not
//! otherwise touch.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use tracing::{debug, warn};

/// Tracks active connection counts per IP address.
///
/// When `max_per_ip` is nonzero, `try_accept` rejects IPs that already
/// hold that many active connections. The map is bounded to
/// `max_tracked_ips` entries with LRU eviction of IPs that have zero
/// active connections. If the map is full and no zero-count entry
/// exists, the request is allowed through (fail open for map capacity,
/// fail closed for per-IP enforcement).
///
/// Uses `std::sync::Mutex` rather than `tokio::sync::Mutex` because the
/// critical section is a single integer increment or decrement, and the
/// `Drop` impl on `PerIpPermit` must be synchronous.
#[derive(Clone)]
pub struct PerIpConnectionTracker {
    max_per_ip: u32,
    max_tracked_ips: usize,
    counts: Arc<std::sync::Mutex<HashMap<IpAddr, u32>>>,
}

/// RAII guard that decrements the per-IP count on drop.
pub struct PerIpPermit {
    ip: IpAddr,
    counts: Arc<std::sync::Mutex<HashMap<IpAddr, u32>>>,
}

impl Drop for PerIpPermit {
    fn drop(&mut self) {
        // Best effort decrement. If the lock is poisoned, we leak a count
        // entry, which is acceptable: the map has bounded capacity and the
        // entry will be evicted by LRU when the slot is needed.
        let Ok(mut map) = self.counts.lock() else {
            warn!("per-IP tracker mutex poisoned, failing open on drop");
            return;
        };
        if let Some(count) = map.get_mut(&self.ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                map.remove(&self.ip);
            }
        }
    }
}

/// Default maximum tracked IPs. Sized for a large mining pool gateway.
const DEFAULT_MAX_TRACKED_IPS: usize = 50_000;

impl PerIpConnectionTracker {
    /// Create a new tracker. `max_per_ip = 0` disables per-IP enforcement.
    pub fn new(max_per_ip: u32) -> Self {
        Self::with_capacity(max_per_ip, DEFAULT_MAX_TRACKED_IPS)
    }

    /// Create with explicit map capacity for testing.
    pub fn with_capacity(max_per_ip: u32, max_tracked_ips: usize) -> Self {
        Self {
            max_per_ip,
            max_tracked_ips,
            counts: Arc::new(std::sync::Mutex::new(HashMap::new())),
        }
    }

    /// Returns `true` when per-IP enforcement is disabled (`max_per_ip` == 0).
    pub fn is_disabled(&self) -> bool {
        self.max_per_ip == 0
    }

    /// Try to accept a connection from `ip`. Returns a permit guard on
    /// success that decrements the count when dropped. Returns `None` if
    /// the IP already holds `max_per_ip` connections.
    ///
    /// Fails closed on mutex poison: if the internal lock is poisoned,
    /// all connections are rejected.
    pub fn try_accept(&self, ip: IpAddr) -> Option<PerIpPermit> {
        if self.max_per_ip == 0 {
            return Some(PerIpPermit {
                ip,
                counts: Arc::clone(&self.counts),
            });
        }

        let Ok(mut map) = self.counts.lock() else {
            warn!("per-IP tracker mutex poisoned, failing closed");
            return None;
        };

        let current = map.get(&ip).copied().unwrap_or(0);

        if current >= self.max_per_ip {
            return None;
        }

        // Evict a zero-count entry if at capacity and the IP is new.
        if map.len() >= self.max_tracked_ips && !map.contains_key(&ip) {
            let evict_ip = map
                .iter()
                .filter(|(_, count)| **count == 0)
                .map(|(ip, _)| *ip)
                .next();
            if let Some(dead_ip) = evict_ip {
                debug!(evicted_ip = %dead_ip, map_size = map.len(), "per-IP tracker LRU eviction");
                map.remove(&dead_ip);
            }
            // If no zero-count entry exists and the map is full, allow the
            // connection anyway. The global connection cap still bounds
            // total concurrency. This avoids denying legitimate new IPs
            // when the map is saturated with active connections.
        }

        *map.entry(ip).or_insert(0) += 1;

        Some(PerIpPermit {
            ip,
            counts: Arc::clone(&self.counts),
        })
    }

    /// Current active connection count for an IP. For diagnostics only.
    pub fn count_for(&self, ip: IpAddr) -> u32 {
        let Ok(map) = self.counts.lock() else {
            return 0;
        };
        map.get(&ip).copied().unwrap_or(0)
    }

    /// Configured per-IP limit.
    pub fn max_per_ip(&self) -> u32 {
        self.max_per_ip
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::PerIpConnectionTracker;
    use std::net::{IpAddr, Ipv4Addr};

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
    }

    #[test]
    fn per_ip_disabled_always_accepts() {
        let tracker = PerIpConnectionTracker::new(0);
        assert!(tracker.is_disabled());
        let _p1 = tracker.try_accept(ip(1)).unwrap();
        let _p2 = tracker.try_accept(ip(1)).unwrap();
        let _p3 = tracker.try_accept(ip(1)).unwrap();
    }

    #[test]
    fn per_ip_rejects_at_limit() {
        let tracker = PerIpConnectionTracker::new(2);
        let _p1 = tracker.try_accept(ip(1)).unwrap();
        let _p2 = tracker.try_accept(ip(1)).unwrap();
        assert!(tracker.try_accept(ip(1)).is_none());
        let _p3 = tracker.try_accept(ip(2)).unwrap();
    }

    #[test]
    fn per_ip_permit_drop_frees_slot() {
        let tracker = PerIpConnectionTracker::new(1);
        {
            let _p = tracker.try_accept(ip(1)).unwrap();
            assert_eq!(tracker.count_for(ip(1)), 1);
        }
        assert_eq!(tracker.count_for(ip(1)), 0);
        let _p2 = tracker.try_accept(ip(1)).unwrap();
        assert_eq!(tracker.count_for(ip(1)), 1);
    }

    #[test]
    fn per_ip_different_ips_independent() {
        let tracker = PerIpConnectionTracker::new(1);
        let _p1 = tracker.try_accept(ip(1)).unwrap();
        let _p2 = tracker.try_accept(ip(2)).unwrap();
        let _p3 = tracker.try_accept(ip(3)).unwrap();
        assert_eq!(tracker.count_for(ip(1)), 1);
        assert_eq!(tracker.count_for(ip(2)), 1);
        assert_eq!(tracker.count_for(ip(3)), 1);
    }

    #[test]
    fn per_ip_map_evicts_zero_count_at_capacity() {
        let tracker = PerIpConnectionTracker::with_capacity(3, 2);
        let _p1 = tracker.try_accept(ip(1)).unwrap();
        let p2 = tracker.try_accept(ip(2)).unwrap();
        drop(p2);
        let _p3 = tracker.try_accept(ip(3)).unwrap();
        assert_eq!(tracker.count_for(ip(3)), 1);
    }

    /// IPv4-mapped IPv6 and plain IPv4 are distinct `IpAddr` values, so a
    /// dual-stack listener sees a v4 peer and a v6 peer as two sources.
    /// `pool-verifier`'s per-IP integration test depends on exactly this.
    #[test]
    fn mapped_v4_and_v6_loopback_are_distinct_sources() {
        let tracker = PerIpConnectionTracker::new(1);
        let mapped: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        let v6: IpAddr = "::1".parse().unwrap();
        let _p1 = tracker.try_accept(mapped).unwrap();
        assert!(tracker.try_accept(mapped).is_none());
        let _p2 = tracker.try_accept(v6).unwrap();
    }
}
