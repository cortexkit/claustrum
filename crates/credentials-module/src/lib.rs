//! The one library target in this package, and it exists only for tests.
//!
//! The daemon is a binary (`ck-claustrum`) and so is the admin CLI. The federation
//! test harness needs to drive the daemon's own outbound client, its federation home
//! (the ingress side) and its admin surface (the federation admin ops) in-process,
//! and a test binary can only link a library target, so this library re-exports
//! the federation, identity, secret, and admin surface helpers. Moving the
//! daemon's code into a library to satisfy that would rewrite every module declaration
//! in `main.rs` for no other reason, and would make the whole daemon a public API
//! surface.
#![forbid(unsafe_code)]

#[path = "federation/mod.rs"]
pub mod federation;
pub mod fleet_ops;
pub mod manifest_active_report;
pub mod manifest_identity;
#[cfg(not(test))]
pub mod manifest_propose;
mod plan_warnings;
pub mod secret_phone;
pub mod secret_use;

// Left out of this library's own unit-test build: the module's unit tests need the
// daemon's test helpers, and they already run in the daemon binary's test build.
#[cfg(not(test))]
#[path = "admin_surface.rs"]
pub mod admin_surface;

/// Expose only mapped member IDs to the external Callosum test harness.
#[cfg(feature = "test-support")]
pub async fn observe_hub_bindings_for_test(
    store: std::sync::Arc<credentials_core::store::EncryptedStore>,
    client: federation::OutboundClient,
    own_box: &str,
    observed: tokio::sync::watch::Sender<Option<Vec<String>>>,
) {
    use federation::{hub_binding::run_binding_feed, sharing::run_with_pairing_snapshots};
    let (paired_tx, paired_rx) = tokio::sync::watch::channel(None);
    let (joins_tx, mut joins_rx) = tokio::sync::watch::channel(None);
    tokio::select! {
        _ = run_with_pairing_snapshots(store, client.clone(), None, None, Some(paired_tx)) => {},
        _ = run_binding_feed(own_box, client, paired_rx, joins_tx) => {},
        _ = async {
            while joins_rx.changed().await.is_ok() {
                let mapped = joins_rx.borrow_and_update().as_ref().map(|joined| {
                    joined.bindings().map(|binding| binding.member_id.clone()).collect()
                });
                observed.send_replace(mapped);
            }
        } => {},
    }
}
