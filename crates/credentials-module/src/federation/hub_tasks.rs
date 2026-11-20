//! Task ownership and pairing feeds for hub federation.

use std::{future::Future, sync::Arc};

use credentials_core::store::EncryptedStore;
use tokio::{sync::watch, task::JoinHandle};

use crate::federation::{
    hub::Hub, hub_binding, hub_home_writer, hub_manifest_collector, hub_manifest_reporter,
    hub_member_watcher, manifest_watch_ingress::ManifestWatchHub, sharing, OutboundClient,
};

/// Owns a task for the lifetime of the daemon's registration loop.
pub(crate) struct AbortOnDrop(pub(crate) JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub(crate) fn start(
    store: Arc<EncryptedStore>,
    outbound: OutboundClient,
    hub: impl Future<Output = Option<Arc<dyn Hub>>> + Send + 'static,
    manifest_watches: Option<Arc<ManifestWatchHub>>,
) -> [AbortOnDrop; 2] {
    // Callosum pairing reconciliation and local manifest watches also serve paths
    // that don't use the hub. Start them even while the hub connection is pending.
    let (pairings_tx, pairings_rx) = watch::channel(None);
    let sharing = tokio::spawn(sharing::run_with_pairing_snapshots(
        Arc::clone(&store),
        outbound.clone(),
        manifest_watches,
        Some(pairings_tx),
    ));
    let tasks = tokio::spawn(async move {
        let Some(hub) = hub.await else { return };
        let (joined_tx, joined_rx) = watch::channel(None);
        // The same Hub stays with all workers as its NATS connection changes.
        // In particular the home writer retains pending work across replacement.
        tokio::join!(
            hub_binding::run_binding_feed(hub.box_id(), outbound, pairings_rx.clone(), joined_tx),
            hub_home_writer::run(Arc::clone(&store), Arc::clone(&hub), joined_rx.clone()),
            hub_member_watcher::run(
                Arc::clone(&store),
                Arc::clone(&hub),
                joined_rx.clone(),
                pairings_rx.clone(),
            ),
            hub_manifest_reporter::run(Arc::clone(&store), Arc::clone(&hub)),
            hub_manifest_collector::run(store, Arc::clone(&hub), joined_rx, pairings_rx),
        );
    });
    [AbortOnDrop(sharing), AbortOnDrop(tasks)]
}
