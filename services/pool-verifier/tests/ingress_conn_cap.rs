//! PB-26 regression: the NDJSON ingress must cap concurrent TCP
//! connections.
//!
//! The ingress accepts unauthenticated peers (`ingress.rs` builds its
//! TLS acceptor `.with_no_client_auth()`, and shadow/observe compose
//! publish it on port 9090 for every interface), and every live
//! connection holds a line buffer up to `MAX_INTERNAL_LINE_BYTES`, which
//! PB-19 raised to 20 MiB so mainnet `raw_block_hex` fits. Without a cap
//! on how many connections are live at once, any reachable peer can
//! drive the verifier out of memory. That does not fail closed: the
//! gateway's `auto_degrade` (default true) observes the dead verifier,
//! suspends enforcement, and keeps shipping templates, which is exactly
//! what the Invariant Shield exists to prevent.
//!
//! These tests drive the real release binary over a real socket and
//! assert on wire behaviour (a verdict came back, or the peer was closed
//! without one), not on an internal counter. They are NOT `#[ignore]`d:
//! a Critical remote-DoS regression test that only runs when someone
//! remembers to pass `--ignored` is a test nobody runs.
//!
//! The scratch-dir, subprocess, connect and propose helpers moved to
//! `tests/common/mod.rs` when PB-27 became their third caller; see that
//! file's header. These tests deliberately leave the per-IP limit and
//! the idle budget at their shipped defaults, so PB-26's behaviour is
//! asserted against the configuration a production pool actually runs.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::time::{Duration, Instant};

mod common;

use common::{
    BootOptions, Outcome, boot_verifier, clean_template, connect, envelope_line, propose,
    sample_value, scrape_metrics,
};

/// Cap the verifier under test runs with. Two is enough to prove the cap
/// binds, that a connection under it still works, and that a permit
/// comes back on disconnect.
const TEST_CAP: u32 = 2;

fn cap_boot(label: &'static str) -> BootOptions {
    BootOptions {
        label,
        max_connections: TEST_CAP,
        ..BootOptions::default()
    }
}

/// PB-26 core regression. With the cap at 2, the third concurrent peer
/// must not be admitted, and the slot must come back when a held
/// connection goes away.
#[tokio::test]
async fn ingress_refuses_connections_beyond_the_cap() {
    let booted = boot_verifier(cap_boot("pb26-conn-cap")).await;
    let addr = booted.v4_addr();
    let answer = Duration::from_secs(10);

    // Two connections inside the cap: both must work normally. This is
    // the legitimate gateway path (one persistent NDJSON stream per
    // gateway), so it doubles as the "did not break the good case"
    // assertion.
    let mut first = connect(&addr, Duration::from_secs(30)).await;
    assert_eq!(
        propose(&mut first, &clean_template(1), answer).await,
        Outcome::Verdict {
            id: 1,
            accepted: true
        },
        "connection 1 of {TEST_CAP} must be served normally"
    );

    let mut second = connect(&addr, Duration::from_secs(5)).await;
    assert_eq!(
        propose(&mut second, &clean_template(2), answer).await,
        Outcome::Verdict {
            id: 2,
            accepted: true
        },
        "connection 2 of {TEST_CAP} must be served normally"
    );

    // Third concurrent peer, one past the cap. It must be closed without
    // a verdict rather than admitted and given a 20 MiB line buffer of
    // its own.
    let mut third = connect(&addr, Duration::from_secs(5)).await;
    assert_eq!(
        propose(&mut third, &clean_template(3), answer).await,
        Outcome::Closed,
        "connection {} exceeds the cap of {TEST_CAP} and must not be admitted",
        TEST_CAP + 1
    );

    // The refusal must be observable, not silent, and it must be
    // attributed to the global cap rather than to the per-IP limit.
    let body = scrape_metrics(booted.http_port).await;
    assert_eq!(
        sample_value(&body, "verifier_connections_refused_total"),
        1,
        "exactly one refusal expected in /metrics:\n{body}"
    );

    // The cap is on concurrency, not on lifetime totals: dropping a held
    // connection must return its slot.
    drop(first);
    let mut replacement = None;
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(15) {
        let mut candidate = connect(&addr, Duration::from_secs(5)).await;
        if let Outcome::Verdict { id, accepted } =
            propose(&mut candidate, &clean_template(4), answer).await
        {
            replacement = Some((id, accepted));
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        replacement,
        Some((4, true)),
        "the permit held by connection 1 must be released when it disconnects"
    );

    // `second` stays live to the end so the cap is genuinely saturated
    // for the whole test rather than by accident of GC.
    drop(second);
    drop(third);
}

/// The cap must not undo PB-19. A multi-megabyte `raw_block_hex` line,
/// the reason `MAX_INTERNAL_LINE_BYTES` is 20 MiB and the shape the
/// Class M mainnet soak sends, must still round-trip on an admitted
/// connection.
#[tokio::test]
async fn large_raw_block_hex_line_still_round_trips_under_the_cap() {
    let booted = boot_verifier(cap_boot("pb26-large-line")).await;
    let mut conn = connect(&booted.v4_addr(), Duration::from_secs(30)).await;

    // 2 MiB of block bytes, so 4 MiB of hex: four times the 1 MiB budget
    // that predated PB-19, and comfortably inside 20 MiB. The bytes are
    // not a real block, so the Invariant Shield rejects the template;
    // what is under test is that the line was read, parsed, evaluated,
    // and answered rather than truncated or dropped.
    let mut template = clean_template(7);
    template.raw_block_hex = Some("00".repeat(2 * 1024 * 1024));

    let line_len = envelope_line(&template).len();
    assert!(
        line_len > 4 * 1024 * 1024,
        "test is only meaningful past the pre-PB-19 1 MiB budget, line was {line_len} bytes"
    );

    let outcome = propose(&mut conn, &template, Duration::from_secs(30)).await;
    assert_eq!(
        outcome,
        Outcome::Verdict {
            id: 7,
            accepted: false
        },
        "a {line_len}-byte line must still reach the evaluator and get a verdict"
    );

    // The same connection stays usable afterwards: the oversize line
    // consumed its budget, not the stream.
    assert_eq!(
        propose(&mut conn, &clean_template(8), Duration::from_secs(10)).await,
        Outcome::Verdict {
            id: 8,
            accepted: true
        },
        "the connection must survive a multi-megabyte line"
    );
}
