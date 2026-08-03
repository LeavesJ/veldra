//! PB-30 regression: the verifier's HTTP surface must come up over
//! HTTPS in the configuration that ships by default.
//!
//! PB-28 installed the rustls `CryptoProvider` inside
//! `ingress::build_tcp_tls_acceptor`, after the early `return Ok(None)`
//! that fires when `VELDRA_VERIFIER_TLS_CERT` and
//! `VELDRA_VERIFIER_TLS_KEY` are unset. Unset is the shipped default, so
//! in the default configuration the install never ran and
//! `axum_server::tls_rustls::RustlsConfig` hit the same
//! "Could not automatically determine the process-level
//! `CryptoProvider`" panic that PB-28 was raised for.
//!
//! The failure mode is worse than a crash. The HTTP server runs in a
//! spawned task (`main.rs:351`), so the panic takes the task and leaves
//! the process alive with the ingress still accepting templates and no
//! `/health`, no `/metrics` and no dashboard. An operator sees a live
//! verifier that has gone blind, and every dashboard panel keyed off
//! `/metrics` reads "no data" rather than "down".
//!
//! The assertion is therefore on a real HTTPS response with a real
//! status code, not on the process still being alive: the process is
//! alive either way, which is the whole point.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::time::Duration;

mod common;

use common::{BootOptions, boot_verifier, https_get};

/// How long the HTTPS surface gets to bind. The failure this guards is
/// "never", not "late".
const SERVE_DEADLINE: Duration = Duration::from_secs(25);

/// HTTPS on, ingress TLS off: the shipped default shape.
///
/// `deploy/env.prod.example` sets no `VELDRA_VERIFIER_TLS_CERT` and no
/// `VELDRA_VERIFIER_TLS_KEY`, and `docker-compose` runs the verifier
/// with `VELDRA_TLS_SELF_SIGNED=1`, so this is not a corner: it is what
/// an operator gets by following the deployment docs.
#[tokio::test]
async fn metrics_serve_over_https_when_the_ingress_is_plaintext() {
    let mut booted = boot_verifier(BootOptions {
        label: "pb30-https",
        max_connections: 2,
        max_connections_per_ip: Some(0),
        idle_timeout_secs: Some(60),
        // The defect: TLS off here is what skipped the provider install.
        tls: false,
        https_self_signed: true,
        ..BootOptions::default()
    })
    .await;

    let (status, body) = https_get(booted.http_port, "/metrics", SERVE_DEADLINE).await;
    assert_eq!(
        status, 200,
        "/metrics over HTTPS answered {status}, body:\n{body}"
    );
    assert!(
        body.contains("verifier_connections_active"),
        "/metrics answered 200 but the body is not the verifier's:\n{body}"
    );

    // The process surviving is not the claim, but a verifier that died
    // for some unrelated reason would make the assertion above vacuous
    // in a future edit, so pin it.
    assert_eq!(
        booted.exit_status(),
        None,
        "the verifier process exited while serving HTTPS"
    );
}

/// The same surface over HTTPS, one route further in: `/health` is what
/// container orchestration polls, so a blind verifier that still holds
/// its ingress socket would otherwise keep passing its liveness probe.
#[tokio::test]
async fn health_serves_over_https_when_the_ingress_is_plaintext() {
    let booted = boot_verifier(BootOptions {
        label: "pb30-https-health",
        max_connections: 2,
        max_connections_per_ip: Some(0),
        idle_timeout_secs: Some(60),
        tls: false,
        https_self_signed: true,
        ..BootOptions::default()
    })
    .await;

    let (status, body) = https_get(booted.http_port, "/health", SERVE_DEADLINE).await;
    assert_eq!(
        status, 200,
        "/health over HTTPS answered {status}, body:\n{body}"
    );
}
