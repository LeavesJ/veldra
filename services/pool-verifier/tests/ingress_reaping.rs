//! PB-27 regression: an ingress permit must not be holdable forever.
//! PB-28 regression: the ingress must be able to boot with TLS at all.
//!
//! PB-26 capped concurrent NDJSON ingress connections at 32 and released
//! a permit only when the peer's socket reported EOF or RST. Nothing
//! bounded how long a peer could hold one without speaking, so a peer
//! that connected and said nothing kept its slot for the life of the
//! process. That made one dimension of the PB-26 attack cheaper rather
//! than dearer: 32 silent sockets from one address, against a listener
//! that shadow and observe compose publish on port 9090 for every
//! interface with `.with_no_client_auth()`, are enough to lock out every
//! legitimate stream. Locking out the stream does not fail closed: the
//! gateway's `auto_degrade` (default true) sees the unreachable
//! verifier, suspends enforcement, and keeps shipping templates.
//!
//! It is not only an attack. `template-manager` opens a fresh
//! `TcpStream` per template (`template-manager/src/main.rs:1697`,
//! consumed by `send_and_receive` at `:1816`), so at `poll_secs = 5` the
//! ingress needs a free slot every few seconds. And a gateway host that
//! vanishes without sending FIN burned a slot permanently, which made
//! ingress capacity monotonically non-increasing over process life.
//!
//! Every assertion here is on wire behaviour or on a shipped `/metrics`
//! sample, never on an internal counter added for the test's
//! convenience. None of them are `#[ignore]`d, for the reason
//! `ingress_conn_cap.rs` gives.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::time::{Duration, Instant};

use tokio::io::AsyncWriteExt;

mod common;

use common::{
    BootOptions, Conn, Outcome, boot_verifier, clean_template, closed_within, connect,
    envelope_line, propose, sample_value, scrape_metrics, tls_connect, wait_for_sample,
};

/// Idle budget the verifier under test runs with. Short enough that a
/// test does not sit on the shipped 60 s default, long enough that
/// ordinary scheduler jitter on a loaded CI box cannot look like
/// silence.
const TEST_IDLE_SECS: u64 = 3;

/// How long a test will wait for a reap that should land in
/// `TEST_IDLE_SECS`. Generous on purpose: the failure this guards is
/// "never", not "late".
const REAP_DEADLINE: Duration = Duration::from_secs(25);

/// Keep trying a fresh connection until one is admitted and answered,
/// which is the observable a locked-out legitimate peer cares about.
/// Returns how long it took.
async fn wait_until_admitted(addr: &str, template_id: u64, deadline: Duration) -> Duration {
    let start = Instant::now();
    while start.elapsed() < deadline {
        let mut candidate = connect(addr, Duration::from_secs(5)).await;
        if let Outcome::Verdict { id, accepted } = propose(
            &mut candidate,
            &clean_template(template_id),
            Duration::from_secs(10),
        )
        .await
        {
            assert_eq!(id, template_id, "verdict came back for the wrong template");
            assert!(
                accepted,
                "the permissive test policy must accept template {id}"
            );
            return start.elapsed();
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("no connection was admitted within {deadline:?}");
}

/// (a) A peer that connects and never sends a byte must lose its slot.
///
/// This is the reported attack in miniature: silent sockets saturate the
/// cap, and a legitimate peer is locked out until they are reaped.
#[tokio::test]
async fn idle_peer_that_never_speaks_is_reaped_and_its_slot_returns() {
    let booted = boot_verifier(BootOptions {
        label: "pb27-idle",
        max_connections: 2,
        // Per-IP off: every socket here comes from 127.0.0.1, and this
        // test is about the idle budget, not about source addresses.
        max_connections_per_ip: Some(0),
        idle_timeout_secs: Some(TEST_IDLE_SECS),
        ..BootOptions::default()
    })
    .await;
    let addr = booted.v4_addr();

    // Two squatters, zero bytes sent, holding the whole cap.
    let mut squatter_a = connect(&addr, Duration::from_secs(30)).await;
    let mut squatter_b = connect(&addr, Duration::from_secs(5)).await;

    // The lockout is real: a third peer gets nothing while they hold.
    let mut victim = connect(&addr, Duration::from_secs(5)).await;
    assert_eq!(
        propose(&mut victim, &clean_template(1), Duration::from_secs(10)).await,
        Outcome::Closed,
        "the cap must be saturated by the two silent squatters"
    );
    drop(victim);

    // The slot must come back on its own, with no peer having closed.
    let took = wait_until_admitted(&addr, 2, REAP_DEADLINE).await;
    assert!(
        took < REAP_DEADLINE,
        "a legitimate peer waited {took:?} for a slot"
    );

    // And the squatters must be the ones that lost their sockets.
    assert!(
        closed_within(&mut squatter_a, Duration::from_secs(10)).await,
        "squatter A must have been closed by the ingress, not left holding a slot"
    );
    assert!(
        closed_within(&mut squatter_b, Duration::from_secs(10)).await,
        "squatter B must have been closed by the ingress, not left holding a slot"
    );

    // The reap must be visible to an operator, otherwise "capacity is
    // fine" and "we are being squatted continuously" look identical.
    let body = scrape_metrics(booted.http_port).await;
    assert!(
        sample_value(&body, "verifier_connections_reaped_idle_total") >= 2,
        "both squatters must be counted as reaped:\n{body}"
    );
}

/// (b) A peer that sends a partial line and then goes silent must also
/// be reaped. PB-18's bounded read caps how many bytes one line may
/// take, but a peer that stops one byte short of the newline never
/// trips it.
#[tokio::test]
async fn partial_line_then_silence_is_reaped() {
    let booted = boot_verifier(BootOptions {
        label: "pb27-partial",
        max_connections: 2,
        max_connections_per_ip: Some(0),
        idle_timeout_secs: Some(TEST_IDLE_SECS),
        ..BootOptions::default()
    })
    .await;
    let addr = booted.v4_addr();

    // A well-formed template line minus its trailing newline: the
    // verifier has a parseable prefix in hand and is still waiting.
    let partial = {
        let line = envelope_line(&clean_template(11));
        line.trim_end().to_string()
    };

    let mut a = connect(&addr, Duration::from_secs(30)).await;
    a.writer.write_all(partial.as_bytes()).await.unwrap();
    a.writer.flush().await.unwrap();

    let mut b = connect(&addr, Duration::from_secs(5)).await;
    b.writer.write_all(partial.as_bytes()).await.unwrap();
    b.writer.flush().await.unwrap();

    let mut victim = connect(&addr, Duration::from_secs(5)).await;
    assert_eq!(
        propose(&mut victim, &clean_template(12), Duration::from_secs(10)).await,
        Outcome::Closed,
        "the cap must be saturated by the two half-line squatters"
    );
    drop(victim);

    let took = wait_until_admitted(&addr, 13, REAP_DEADLINE).await;
    assert!(
        took < REAP_DEADLINE,
        "a legitimate peer waited {took:?} behind two half-line squatters"
    );
    assert!(
        closed_within(&mut a, Duration::from_secs(10)).await,
        "the half-line squatter must have been closed"
    );
}

/// The reported second attack shape: a peer that keeps sending but never
/// reads its verdicts. The read side sees progress, so a budget measured
/// only on reads would never fire; the verifier ends up parked in a
/// write that the peer's full receive window will never drain.
#[tokio::test]
async fn peer_that_never_reads_its_verdicts_is_reaped() {
    let booted = boot_verifier(BootOptions {
        label: "pb27-noread",
        max_connections: 1,
        max_connections_per_ip: Some(0),
        idle_timeout_secs: Some(TEST_IDLE_SECS),
        ..BootOptions::default()
    })
    .await;
    let addr = booted.v4_addr();

    let attacker = connect(&addr, Duration::from_secs(30)).await;
    let Conn {
        reader: _held_open,
        mut writer,
    } = attacker;

    // Push templates until the socket refuses more. The task is
    // detached: once the verifier stops draining, this write parks,
    // which is exactly the state under test.
    let flood = tokio::spawn(async move {
        let line = envelope_line(&clean_template(21));
        for _ in 0..200_000u32 {
            if writer.write_all(line.as_bytes()).await.is_err() {
                break;
            }
        }
        let _ = writer.flush().await;
        // Hold the write half so the socket stays open from the client
        // side; only the server may end this connection.
        tokio::time::sleep(Duration::from_secs(120)).await;
    });

    // Give the flood time to fill both socket buffers and park the
    // verifier in a write.
    tokio::time::sleep(Duration::from_secs(2)).await;

    let took = wait_until_admitted(&addr, 22, REAP_DEADLINE).await;
    assert!(
        took < REAP_DEADLINE,
        "a legitimate peer waited {took:?} behind a peer that never reads"
    );

    flood.abort();
}

/// (c) A peer that opens TCP against a TLS ingress and never sends a
/// `ClientHello`. PB-26 takes the permit before the handshake on purpose,
/// so such a peer holds a slot without ever becoming a protocol peer.
///
/// The idle budget here is set far above the handshake budget, so the
/// only thing that can end these connections is the handshake deadline
/// itself. That also means this test only compiles a result at all if
/// PB-28 is fixed: an ingress that panics on `CryptoProvider` never
/// binds the TLS listener.
#[tokio::test]
async fn tls_handshake_that_never_starts_is_reaped() {
    let booted = boot_verifier(BootOptions {
        label: "pb27-tls-squat",
        max_connections: 2,
        max_connections_per_ip: Some(0),
        // Deliberately longer than REAP_DEADLINE: if the handshake
        // deadline were removed, the idle budget could not rescue this
        // test inside its own deadline.
        idle_timeout_secs: Some(600),
        tls: true,
        ..BootOptions::default()
    })
    .await;
    let addr = booted.v4_addr();

    let mut squatter_a = connect(&addr, Duration::from_secs(30)).await;
    let mut squatter_b = connect(&addr, Duration::from_secs(5)).await;

    // Both were admitted: the third is refused by the cap, which is how
    // we know the first two are holding the slots.
    let mut third = connect(&addr, Duration::from_secs(5)).await;
    assert!(
        closed_within(&mut third, Duration::from_secs(5)).await,
        "the cap must be saturated by the two handshake squatters"
    );
    let body = scrape_metrics(booted.http_port).await;
    assert_eq!(
        sample_value(&body, "verifier_connections_refused_total"),
        1,
        "the over-cap peer must be counted refused:\n{body}"
    );

    // Neither squatter may keep its slot.
    assert!(
        closed_within(&mut squatter_a, REAP_DEADLINE).await,
        "a peer that never starts the TLS handshake must not hold a permit forever"
    );
    assert!(
        closed_within(&mut squatter_b, REAP_DEADLINE).await,
        "a peer that never starts the TLS handshake must not hold a permit forever"
    );
    wait_for_sample(
        booted.http_port,
        "verifier_connections_active",
        0,
        REAP_DEADLINE,
    )
    .await;
}

/// (d) One IP must not be able to take the whole ingress. The global cap
/// is per process, so before PB-27 a single source address could hold
/// every slot.
///
/// Two distinct peer IPs on one listener without root: bind dual-stack
/// and dial it both ways. The kernel reports the IPv4 client as
/// `::ffff:127.0.0.1` and the IPv6 client as `::1`, which are different
/// `IpAddr` values. macOS has no 127.0.0.2 to alias.
#[tokio::test]
async fn one_ip_cannot_occupy_more_than_the_per_ip_limit() {
    let booted = boot_verifier(BootOptions {
        label: "pb27-perip",
        // Four global slots, one per IP: any refusal below four live
        // connections can only have come from the per-IP limit.
        max_connections: 4,
        max_connections_per_ip: Some(1),
        idle_timeout_secs: Some(TEST_IDLE_SECS),
        bind_host: "[::]",
        ..BootOptions::default()
    })
    .await;

    let mut first = connect(&booted.v4_addr(), Duration::from_secs(30)).await;
    assert_eq!(
        propose(&mut first, &clean_template(31), Duration::from_secs(10)).await,
        Outcome::Verdict {
            id: 31,
            accepted: true
        },
        "the first connection from an IP must be served"
    );

    let mut second = connect(&booted.v4_addr(), Duration::from_secs(5)).await;
    assert_eq!(
        propose(&mut second, &clean_template(32), Duration::from_secs(10)).await,
        Outcome::Closed,
        "a second concurrent connection from the same IP must be refused"
    );

    let body = scrape_metrics(booted.http_port).await;
    assert_eq!(
        sample_value(&body, "verifier_connections_refused_per_ip_total"),
        1,
        "the per-IP refusal must be counted separately from the global cap:\n{body}"
    );
    assert_eq!(
        sample_value(&body, "verifier_connections_refused_total"),
        0,
        "the global cap must not have been the reason: it was nowhere near four:\n{body}"
    );

    // A different IP is unaffected.
    let mut other_ip = connect(&booted.v6_addr(), Duration::from_secs(5)).await;
    assert_eq!(
        propose(&mut other_ip, &clean_template(33), Duration::from_secs(10)).await,
        Outcome::Verdict {
            id: 33,
            accepted: true
        },
        "a different source IP must still be admitted while the first IP is at its limit"
    );
}

/// (e) The gauge must track slots actually held, so that "the cap is too
/// low", "slots are leaking" and "a squatter is present" stop being
/// indistinguishable until capacity is already gone.
#[tokio::test]
async fn live_connection_gauge_tracks_slots_actually_held() {
    let booted = boot_verifier(BootOptions {
        label: "pb27-gauge",
        max_connections: 2,
        max_connections_per_ip: Some(0),
        idle_timeout_secs: Some(TEST_IDLE_SECS),
        ..BootOptions::default()
    })
    .await;
    let addr = booted.v4_addr();

    let body = scrape_metrics(booted.http_port).await;
    assert_eq!(
        sample_value(&body, "verifier_connections_active"),
        0,
        "a verifier with no peers holds no slots:\n{body}"
    );

    let mut first = connect(&addr, Duration::from_secs(30)).await;
    assert!(matches!(
        propose(&mut first, &clean_template(41), Duration::from_secs(10)).await,
        Outcome::Verdict { .. }
    ));
    wait_for_sample(
        booted.http_port,
        "verifier_connections_active",
        1,
        Duration::from_secs(10),
    )
    .await;

    let mut second = connect(&addr, Duration::from_secs(5)).await;
    assert!(matches!(
        propose(&mut second, &clean_template(42), Duration::from_secs(10)).await,
        Outcome::Verdict { .. }
    ));
    wait_for_sample(
        booted.http_port,
        "verifier_connections_active",
        2,
        Duration::from_secs(10),
    )
    .await;

    // Both peers now stay silent, so both are reaped and the gauge
    // returns to zero with nobody having disconnected. That is the
    // "slots are actually held, and actually released" observable.
    wait_for_sample(
        booted.http_port,
        "verifier_connections_active",
        0,
        REAP_DEADLINE,
    )
    .await;
    drop(first);
    drop(second);
}

/// The launch-gate guard. A 20 MiB `raw_block_hex` line over a slow link
/// takes real time, and the mainnet Class M soak is the reason
/// `MAX_INTERNAL_LINE_BYTES` is 20 MiB at all. The budget must therefore
/// be idle-since-last-progress, never total connection age: this peer
/// stays connected for several multiples of the idle budget and must
/// still get its verdict.
#[tokio::test]
async fn slow_but_legitimate_transfer_is_not_reaped() {
    let booted = boot_verifier(BootOptions {
        label: "pb27-slow",
        max_connections: 2,
        max_connections_per_ip: Some(0),
        idle_timeout_secs: Some(TEST_IDLE_SECS),
        ..BootOptions::default()
    })
    .await;
    let mut conn = connect(&booted.v4_addr(), Duration::from_secs(30)).await;

    let mut template = clean_template(51);
    template.raw_block_hex = Some("00".repeat(128 * 1024));
    let line = envelope_line(&template);
    assert!(
        line.len() > 256 * 1024,
        "line was only {} bytes",
        line.len()
    );

    // Eight chunks at 60% of the idle budget apart. Total wall time is
    // more than four times the budget, and no single gap reaches it.
    let gap = Duration::from_millis(TEST_IDLE_SECS * 600);
    let chunk = line.len().div_ceil(8);
    let started = Instant::now();
    for piece in line.as_bytes().chunks(chunk) {
        conn.writer.write_all(piece).await.expect("slow write");
        conn.writer.flush().await.expect("slow flush");
        tokio::time::sleep(gap).await;
    }
    let spent = started.elapsed();
    assert!(
        spent > Duration::from_secs(TEST_IDLE_SECS * 3),
        "the drip must outlast the idle budget several times over, took {spent:?}"
    );

    // The bytes are not a real block, so the Invariant Shield rejects
    // the template. What is under test is that the line was read to
    // completion and answered.
    assert_eq!(
        common::read_outcome(&mut conn, Duration::from_secs(30)).await,
        Outcome::Verdict {
            id: 51,
            accepted: false
        },
        "a slow legitimate transfer must not be reaped mid-line"
    );

    let body = scrape_metrics(booted.http_port).await;
    assert_eq!(
        sample_value(&body, "verifier_connections_reaped_idle_total"),
        0,
        "nothing was idle here; a reap means the budget is measuring age, not idleness:\n{body}"
    );
}

/// (f) PB-28. Setting `VELDRA_VERIFIER_TLS_CERT` and
/// `VELDRA_VERIFIER_TLS_KEY` panicked the process on the rustls
/// `CryptoProvider`, so the ingress TLS path could not boot at all. No
/// test in the tree ever started the ingress in TLS mode, which is
/// exactly how that survived.
///
/// The observable is the whole path: the process is still alive, it
/// serves `/metrics`, it completes a real TLS handshake, and it answers
/// a template over the encrypted session. `PB-3` (mTLS on this channel,
/// marked Resolved) covered the gateway side and config validation, and
/// is not evidence that this end works.
#[tokio::test]
async fn tls_ingress_boots_and_serves_a_verdict_over_a_real_handshake() {
    let mut booted = boot_verifier(BootOptions {
        label: "pb28-tls-boot",
        max_connections: 4,
        max_connections_per_ip: Some(0),
        idle_timeout_secs: Some(60),
        tls: true,
        ..BootOptions::default()
    })
    .await;

    // Serving /metrics proves the process survived startup. A panicking
    // verifier never gets here.
    let body = scrape_metrics(booted.http_port).await;
    assert_eq!(
        sample_value(&body, "verifier_connections_active"),
        0,
        "the verifier is up but /metrics is not the verifier's:\n{body}"
    );
    assert_eq!(
        booted.exit_status(),
        None,
        "the verifier process exited after binding HTTP; TLS ingress startup killed it"
    );

    let mut conn = tls_connect(&booted.v4_addr(), Duration::from_secs(30)).await;
    assert_eq!(
        propose(&mut conn, &clean_template(61), Duration::from_secs(15)).await,
        Outcome::Verdict {
            id: 61,
            accepted: true
        },
        "a template must round-trip over the TLS ingress"
    );

    // The session stays usable, so the handshake produced a real
    // stream rather than a one-shot.
    assert_eq!(
        propose(&mut conn, &clean_template(62), Duration::from_secs(15)).await,
        Outcome::Verdict {
            id: 62,
            accepted: true
        },
        "the TLS session must survive past its first line"
    );
}
