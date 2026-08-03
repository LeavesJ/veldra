//! PB-31 regression: the shipped per-IP ingress ceiling must fit the
//! deployment topology this project documents as supported.
//!
//! PB-27 added the per-source-address ceiling and sized it from an HA
//! pair: two persistent gateway streams plus two in-flight
//! template-manager connections. `docker-compose.yml` documents
//! something larger, "single-digit gateway and template-manager
//! streams". Behind a NAT or an L4 proxy that whole population reaches
//! the verifier as one source address, so the two sites were sizing the
//! same number against different topologies and the smaller one shipped.
//!
//! What makes the HA-pair number too small is that a gateway stream
//! costs two slots, not one, for as long as a death takes to clear. A
//! silently dead socket holds its slot for the full no-progress budget,
//! reported at 60.08 s against the 60 s default and linear in the
//! budget, with a 15 s budget holding 15.05 s. The gateway behind it
//! reconnects in 2 to 3 s. For the ~58 s in between, one address
//! carries two slots per gateway. TCP keepalive cannot close that
//! window: its ladder fires at 110 s on macOS and 120 s on Linux, both
//! past the budget.
//!
//! At 8 that broke a documented topology, reportedly at 7 gateways on
//! one silent death, 6 with concurrent template-manager traffic, and 4
//! if they died together. Refusing a real gateway is not a safe
//! failure: the gateway's `auto_degrade` (default true) answers an
//! unreachable verifier by suspending enforcement.
//!
//! This test pins the derivation, `per_ip >= 2G + M + 1`, rather than
//! the number. It boots with the per-IP ceiling left at whatever the
//! binary ships and drives exactly that many concurrent streams from
//! one address, so lowering the shipped default back under the
//! documented topology fails here instead of in a pool.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::time::Duration;

mod common;

use common::{
    BootOptions, Conn, Outcome, boot_verifier, clean_template, connect, propose, sample_value,
    scrape_metrics, wait_for_sample,
};

/// `G`: gateway streams behind the one NAT address. Eight is the top of
/// the single-digit gateway and template-manager population
/// `docker-compose.yml` documents as supported.
const CEILING_GATEWAYS: u32 = 8;

/// `M`: concurrent template-manager connections. One, because the
/// manager opens a fresh connection per template and holds it for under
/// its own verdict timeout, so its measured peak
/// `verifier_connections_active` contribution is a single slot.
const MANAGER_CONNS: u32 = 1;

/// The trailing `+ 1`: an operator's diagnostic connection.
const DIAGNOSTIC_CONNS: u32 = 1;

/// `per_ip >= 2G + M + 1`. The `2G` is the doubling window: every
/// gateway's dead socket and its own reconnect held at the same time.
const REQUIRED_PER_IP: u32 = 2 * CEILING_GATEWAYS + MANAGER_CONNS + DIAGNOSTIC_CONNS;

/// PB-27's value, kept only to name the connection that used to be
/// refused. The first reconnecting gateway is stream number 9 from this
/// address, one past it.
const PB27_PER_IP: u32 = 8;

/// Global cap the verifier under test runs with: the shipped default,
/// which PB-31 does not change. Stated so a per-IP refusal cannot be
/// confused with the global cap binding at `REQUIRED_PER_IP`.
const SHIPPED_MAX_CONNECTIONS: u32 = 32;

/// No-progress budget under test. A quarter of the shipped 60 s, and
/// one of the budgets the hold time was measured at, so the dead
/// sockets here hold their slots the same way they do in production
/// without putting a minute into the default suite. Every connection
/// this test opens lands well inside it, and the live-slot assertion at
/// the end proves none of them were reaped underneath the claim.
const TEST_IDLE_SECS: u64 = 15;

/// How long a verdict may take before the ingress is considered hung.
const ANSWER: Duration = Duration::from_secs(10);

/// Open one more stream from the single NAT address and prove the
/// ingress admitted it by reading its verdict back.
///
/// A refused connection is not a failed `connect`: the accept loop
/// takes the socket off the backlog and drops it, so the peer sees the
/// TCP handshake succeed and then EOF, which `propose` reports as
/// `Outcome::Closed`.
async fn admit(addr: &str, id: u64, role: &str) -> Conn {
    let mut conn = connect(addr, Duration::from_secs(30)).await;
    assert_eq!(
        propose(&mut conn, &clean_template(id), ANSWER).await,
        Outcome::Verdict { id, accepted: true },
        "{role} was refused; the shipped per-IP ceiling must admit \
         2G + M + 1 = {REQUIRED_PER_IP} concurrent streams from one \
         source address, with G = {CEILING_GATEWAYS}"
    );
    conn
}

/// The full doubling window at the documented ceiling, from one source
/// address, against the ceiling the binary actually ships.
#[tokio::test]
async fn shipped_per_ip_default_admits_the_documented_topology_through_a_silent_death() {
    let booted = boot_verifier(BootOptions {
        label: "pb31-per-ip-sizing",
        max_connections: SHIPPED_MAX_CONNECTIONS,
        // The whole point: leave the per-IP ceiling at whatever the
        // binary ships. `None` is what makes this a pin on the shipped
        // default rather than on a value the test chose.
        max_connections_per_ip: None,
        idle_timeout_secs: Some(TEST_IDLE_SECS),
        ..BootOptions::default()
    })
    .await;
    let addr = booted.v4_addr();

    // Every connection below comes from 127.0.0.1, which is the point:
    // one NAT egress address carrying a whole deployment.
    let mut held: Vec<Conn> = Vec::new();

    // G persistent gateway streams, all admitted and serving.
    for g in 0..CEILING_GATEWAYS {
        held.push(admit(&addr, 3100 + u64::from(g), "a gateway stream").await);
    }

    // Every gateway host now dies silently: no FIN, no RST, nothing on
    // the wire. Holding the `Conn` and never writing again is that
    // socket from the verifier's side. Each keeps its slot until the
    // no-progress budget expires, which is what this test needs to
    // still be true when the last stream lands.

    // The gateways reconnect inside that window, so their dead sockets
    // and their new ones are held at the same time. The first reconnect
    // is where the reported topology broke.
    for g in 0..CEILING_GATEWAYS {
        let role = if g == 0 {
            format!(
                "the first reconnecting gateway, stream {} from this address \
                 and the first one PB-27's ceiling of {PB27_PER_IP} refused",
                PB27_PER_IP + 1
            )
        } else {
            "a reconnecting gateway inside the doubling window".to_owned()
        };
        held.push(admit(&addr, 3200 + u64::from(g), &role).await);
    }
    assert_eq!(
        u32::try_from(held.len()).expect("held fits u32"),
        2 * CEILING_GATEWAYS,
        "the doubling window must be 2G slots held at once"
    );

    // template-manager's per-template connection lands in the same
    // window. This is the M term, and the reported 6-gateway break.
    held.push(admit(&addr, 3300, "the concurrent template-manager connection").await);

    // And an operator opens a diagnostic connection while all of that
    // is live. This is the trailing + 1.
    held.push(admit(&addr, 3400, "an operator's diagnostic connection").await);

    assert_eq!(
        u32::try_from(held.len()).expect("held fits u32"),
        REQUIRED_PER_IP,
        "the test must have driven the whole derivation"
    );

    // Nothing was turned away, and the reason matters: a per-IP refusal
    // and a global-cap refusal send an operator to different knobs.
    let body = scrape_metrics(booted.http_port).await;
    assert_eq!(
        sample_value(&body, "verifier_connections_refused_per_ip_total"),
        0,
        "the shipped per-IP ceiling refused a stream inside the \
         documented topology:\n{body}"
    );
    assert_eq!(
        sample_value(&body, "verifier_connections_refused_total"),
        0,
        "the global cap of {SHIPPED_MAX_CONNECTIONS} must not be what \
         bound at {REQUIRED_PER_IP} streams:\n{body}"
    );

    // The premise, asserted rather than assumed: all of them were still
    // holding slots when the last one landed. Without this, a reap
    // firing mid-test would free room and turn the sizing claim into a
    // green test that proved nothing.
    wait_for_sample(
        booted.http_port,
        "verifier_connections_active",
        i64::from(REQUIRED_PER_IP),
        Duration::from_secs(5),
    )
    .await;
}
