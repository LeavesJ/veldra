//! Process-level rustls `CryptoProvider` installation.
//!
//! This exists because `pool-verifier`, `sv2-gateway` and
//! `rg-feed-adapter` all need it. PB-28 wrote the first copy inside the
//! verifier's TLS ingress, PB-30 found that copy too narrowly scoped,
//! fixed the verifier's HTTPS surface and wrote a second copy in the
//! gateway, and recorded in that copy's doc comment that a third caller
//! is the trigger to extract. PB-32 is the third caller: the feed
//! adapter dials `wss://` in both shipped modes
//! (`rg-feed-adapter/config/observe.toml:7`,
//! `config/shadow.toml:6`) and panicked on the same lookup.
//!
//! `rustls` 0.23 picks a provider from its enabled crate features, and
//! only "exactly one" works. Zero candidates and two candidates fail the
//! same way, and both states existed in this workspace:
//! `rg-feed-adapter` had zero (`tokio-tungstenite`'s
//! `rustls-tls-webpki-roots` pulls `rustls` with neither provider
//! feature), while `pool-verifier` and `sv2-gateway` have two
//! (`aws-lc-rs` via `axum-server`/`tokio-rustls`, `ring` via `reqwest`).
//! Every `ClientConfig::builder` and `ServerConfig::builder` call then
//! panics with "Could not automatically determine the process-level
//! `CryptoProvider` from Rustls crate features".
//!
//! For the two-candidate callers this install is the only thing that
//! makes TLS start at all. For a one-candidate caller rustls would
//! auto-select correctly and the install changes nothing today; it is
//! there so the process does not depend on the transitive feature graph
//! continuing to resolve exactly one provider, which is the assumption
//! that broke in all three of PB-28, PB-30 and PB-32.
//!
//! `aws_lc_rs` is rustls' own default and the provider `axum-server`
//! builds against. All three callers install this same one, so no
//! channel between two `ReserveGrid` services can end up with a different
//! provider on each end.
//!
//! The module is behind the crate's `rustls-provider` feature, and that
//! gate is load bearing rather than tidiness: `rg-auth` links this crate
//! and resolves `rustls` with the `ring` feature alone
//! (`cargo tree -e features -p rg-auth`). An unconditional `rustls`
//! edge here would add `aws-lc-rs` to it, taking `rg-auth` from one
//! candidate to two and breaking it in exactly the way this module
//! exists to prevent. `template-manager` and `reservegrid-gateway` link
//! this crate too and carry no TLS surface of their own.

/// Install the process-level rustls `CryptoProvider`.
///
/// Call this before any TLS consumer in the process can reach a
/// builder. Doing it at the top of `main` rather than inside the first
/// TLS code path is deliberate: PB-28 put the install inside a function
/// that returned early when the TLS env vars were unset, which is the
/// shipped default, so in the shipped configuration the install never
/// ran and the next rustls consumer in the same process hit the
/// identical panic.
///
/// `install_default` returns `Err` only when a provider is already
/// installed, which is the state this wants, so that arm proceeds. The
/// post-condition is checked rather than assumed: no provider at this
/// point is a startup failure to surface, not a panic deferred to the
/// first handshake.
///
/// # Errors
///
/// Returns `Err` when no provider is installed after the attempt, which
/// means TLS in this process cannot start.
pub fn install_default() -> Result<(), String> {
    use rustls::crypto::{CryptoProvider, aws_lc_rs};

    if CryptoProvider::get_default().is_none()
        && aws_lc_rs::default_provider().install_default().is_err()
    {
        tracing::info!("rustls CryptoProvider was installed concurrently; using the installed one");
    }
    if CryptoProvider::get_default().is_none() {
        return Err(
            "no rustls CryptoProvider is installed after install_default; TLS cannot start"
                .to_string(),
        );
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::install_default;

    /// The post-condition holds, and the function is safe to call more
    /// than once in a process: the second call finds a provider already
    /// installed and proceeds rather than reporting failure. Three
    /// binaries call this and the test harness runs them in one
    /// process, so idempotence is a property, not a nicety.
    #[test]
    fn install_is_idempotent_and_leaves_a_provider() {
        install_default().expect("first install");
        install_default().expect("second install");
        assert!(rustls::crypto::CryptoProvider::get_default().is_some());
    }
}
