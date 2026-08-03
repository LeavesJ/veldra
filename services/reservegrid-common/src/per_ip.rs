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
//! Of the three, this is the only shape whose decrement is an RAII
//! `Drop` rather than a manual `fetch_sub` at the end of a connection
//! task, which is why it is the one that moved.
//! `rg-feed-server` and `rg-demo-feed` keep their inline copies: both
//! use a `tokio::sync::Mutex` inside an already-async accept loop, and
//! converting them is unrelated churn on services this change does not
//! otherwise touch.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use tracing::warn;

/// Tracks active connection counts per IP address.
///
/// When `max_per_ip` is nonzero, `try_accept` rejects IPs that already
/// hold that many active connections.
///
/// An entry exists only while its address holds at least one live
/// connection: `PerIpPermit::drop` removes it at zero. The map is
/// therefore bounded by the caller's own concurrent-connection ceiling,
/// which is `VELDRA_VERIFIER_MAX_CONNECTIONS` for the verifier ingress
/// (`pool-verifier/src/ingress.rs`) and `gateway.max_connections` for
/// the miner listener (`sv2-gateway/src/main.rs`). Nothing this type
/// owns bounds it, and both callers must keep enforcing a global cap
/// ahead of `try_accept` for that bound to mean anything.
///
/// PB-30. This used to claim a `max_tracked_ips` ceiling with LRU
/// eviction of zero-count entries. The claim was false and the eviction
/// branch was unreachable: a zero-count entry cannot exist, because
/// `Drop` removes the entry rather than leaving it at zero. Measured
/// before the removal, 64 live entries under a `max_tracked_ips` of 4,
/// and the test that covered eviction passed without ever entering the
/// branch. The doc now states the bound that does hold. Reintroducing an
/// internal cap means deciding what happens to a live connection whose
/// entry is evicted: its `Drop` would decrement an entry that no longer
/// exists, and the per-IP ceiling would stop binding for that address
/// until it went quiet, which is the opposite of what the ceiling is
/// for.
///
/// Uses `std::sync::Mutex` rather than `tokio::sync::Mutex` because the
/// critical section is a single integer increment or decrement, and the
/// `Drop` impl on `PerIpPermit` must be synchronous.
#[derive(Clone)]
pub struct PerIpConnectionTracker {
    max_per_ip: u32,
    counts: Arc<std::sync::Mutex<HashMap<IpAddr, u32>>>,
}

/// RAII guard that decrements the per-IP count on drop.
pub struct PerIpPermit {
    ip: IpAddr,
    counts: Arc<std::sync::Mutex<HashMap<IpAddr, u32>>>,
}

impl Drop for PerIpPermit {
    fn drop(&mut self) {
        // Best effort decrement. A poisoned lock leaks this entry, but
        // it leaks nothing further: `try_accept` fails closed on the
        // same poison, so the tracker admits nothing after that point
        // and the map cannot grow.
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

impl PerIpConnectionTracker {
    /// Create a new tracker. `max_per_ip = 0` disables per-IP enforcement.
    pub fn new(max_per_ip: u32) -> Self {
        Self {
            max_per_ip,
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

    /// The map's real bound (PB-30): one entry per address that holds a
    /// live connection, and nothing else.
    ///
    /// This replaces `per_ip_map_evicts_zero_count_at_capacity`, which
    /// asserted only `count_for(ip(3)) == 1` and passed whether or not
    /// the eviction branch it was named for ran. It could not have run:
    /// dropping a permit removes the entry, so the zero-count entry the
    /// branch looked for never existed.
    #[test]
    fn per_ip_map_holds_an_entry_only_while_a_connection_is_live() {
        let tracker = PerIpConnectionTracker::new(2);
        let permits: Vec<_> = (1..=4)
            .map(|i| tracker.try_accept(ip(i)).unwrap())
            .collect();
        assert_eq!(tracked_ips(&tracker), 4, "one entry per live source");

        // A second connection from an already-tracked address shares
        // the entry rather than adding one.
        let second_from_first = tracker.try_accept(ip(1)).unwrap();
        assert_eq!(tracked_ips(&tracker), 4);
        drop(second_from_first);
        assert_eq!(
            tracked_ips(&tracker),
            4,
            "ip(1) still holds one connection, so its entry must stay"
        );

        drop(permits);
        assert_eq!(
            tracked_ips(&tracker),
            0,
            "an address with no live connection must not keep an entry"
        );
    }

    /// Map size, which is the quantity the type's doc makes a claim
    /// about. Not exposed outside the module: the callers have no use
    /// for it, and `count_for` is the diagnostic they do use.
    fn tracked_ips(tracker: &PerIpConnectionTracker) -> usize {
        tracker.counts.lock().unwrap().len()
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
