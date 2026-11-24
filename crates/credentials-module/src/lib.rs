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

#[cfg(not(test))]
mod account_token_mint;
pub mod error_class;
#[path = "federation/mod.rs"]
pub mod federation;
pub mod fleet_ops;
#[cfg(feature = "test-support")]
#[path = "federation/hub_tasks.rs"]
mod hub_tasks;
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
        _ = run_with_pairing_snapshots(store, client.clone(), None, Some(paired_tx)) => {},
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

/// Run the sharing loop and log the device fingerprints of every roster it
/// publishes to the hub workers (`None` while it has no valid roster).
#[cfg(feature = "test-support")]
pub async fn record_pairing_snapshots_for_test(
    store: std::sync::Arc<credentials_core::store::EncryptedStore>,
    client: federation::OutboundClient,
    log: std::sync::Arc<std::sync::Mutex<Vec<Option<Vec<String>>>>>,
) {
    use federation::sharing::run_with_pairing_snapshots;
    let (paired_tx, mut paired_rx) = tokio::sync::watch::channel(None);
    tokio::select! {
        _ = run_with_pairing_snapshots(store, client, None, Some(paired_tx)) => {},
        _ = async {
            while paired_rx.changed().await.is_ok() {
                let devices = paired_rx.borrow_and_update().as_ref().map(|snapshot| {
                    snapshot.devices.iter().map(|(fingerprint, _)| fingerprint.clone()).collect()
                });
                log.lock().unwrap().push(devices);
            }
        } => {},
    }
}

#[cfg(feature = "test-support")]
pub mod hub_test_support {
    use std::{future::ready, sync::Arc};

    use credentials_core::store::EncryptedStore;

    use crate::federation::{
        hub::{
            stand_in::{StandIn, StandInClient},
            Hub, SHARED_LOGINS,
        },
        OutboundClient,
    };
    use crate::hub_tasks::{self, AbortOnDrop};

    pub fn record_manifest_report(
        store: &EncryptedStore,
        member_id: &str,
        body: &serde_json::Value,
    ) -> serde_json::Value {
        let report = crate::manifest_active_report::parse_active_report(body).unwrap();
        crate::manifest_active_report::record_own_manifest_active_report(store, member_id, &report)
    }

    /// One shared hub, with a separate connection signal for each vault.
    pub struct HubFixture(StandIn);

    impl Default for HubFixture {
        fn default() -> Self {
            Self(StandIn::new())
        }
    }

    impl HubFixture {
        pub fn start_vault(
            &self,
            store: Arc<EncryptedStore>,
            outbound: OutboundClient,
            box_id: &str,
        ) -> RunningVault {
            let client = self.0.client(box_id);
            let hub: Arc<dyn Hub> = Arc::new(client.clone());
            let guards = hub_tasks::start(store, outbound, ready(Some(hub)), None);
            RunningVault {
                client,
                _guards: guards,
            }
        }

        /// Start a vault whose hub connection stays pending until the returned
        /// sender fires, the shape of a restart while the hub is unreachable.
        pub fn start_vault_pending(
            &self,
            store: Arc<EncryptedStore>,
            outbound: OutboundClient,
            box_id: &str,
        ) -> (RunningVault, tokio::sync::oneshot::Sender<()>) {
            let client = self.0.client(box_id);
            let hub: Arc<dyn Hub> = Arc::new(client.clone());
            let (release, released) = tokio::sync::oneshot::channel();
            let connected = async move { released.await.ok().map(|()| hub) };
            let guards = hub_tasks::start(store, outbound, connected, None);
            (
                RunningVault {
                    client,
                    _guards: guards,
                },
                release,
            )
        }

        pub fn set_online(&self, online: bool) {
            self.0.set_online(online);
        }

        pub fn reset_shared_logins(&self) {
            self.0.reset_bucket(SHARED_LOGINS, &[]);
        }

        pub fn has_login_list(&self, home_box: &str, member_box: &str) -> bool {
            self.0
                .entry(SHARED_LOGINS, &format!("{home_box}.{member_box}"))
                .unwrap()
                .is_some()
        }
    }

    pub struct RunningVault {
        client: StandInClient,
        _guards: [AbortOnDrop; 2],
    }

    impl RunningVault {
        pub fn replace_connection(&self) {
            self.client.replace_connection();
        }
    }
}
