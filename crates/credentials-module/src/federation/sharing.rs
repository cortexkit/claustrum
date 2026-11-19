//! Callosum's per-computer vault switch owns only switch-sourced member grants.
//! A failed lookup is not an empty inventory: no grant changes until a full snapshot
//! has decoded, and each snapshot's grant changes commit with their audits together.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use credentials_core::federation::{
    is_lower_hex_16_bytes, is_lower_hex_sha256, VaultSharingMember,
};
use credentials_core::fleet::FleetRemoval;
use credentials_core::store::EncryptedStore;
use serde::Deserialize;
use serde_json::{json, Value};

use super::outbound::{management_surface, OutboundClient, RouteCall, ADMIN_OP_BUDGET};

// Ignore additional Callosum metadata so a newer reply can still revoke a
// computer's grants when its vault-sharing switch turns off.
#[derive(Deserialize)]
struct Snapshot {
    devices: Vec<Device>,
    #[serde(rename = "self")]
    identity: Identity,
    #[serde(default)]
    tombstones: Vec<Tombstone>,
}

#[derive(Deserialize)]
struct Tombstone {
    fingerprint: String,
    removal_id: String,
}

#[derive(Deserialize)]
struct Identity {
    static_public_key_hex: String,
}

#[derive(Deserialize)]
struct Device {
    class: Class,
    fingerprint: String,
    pairing_id: String,
    shares: Vec<Share>,
}

#[derive(Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Class {
    Computer,
    Phone,
    Sim,
    #[serde(other)]
    Unknown,
}

#[derive(Deserialize)]
struct Share {
    share: String,
    enabled: bool,
}

/// An account removal, independent of the device roster and local pairing state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharingTombstone {
    pub member_id: String,
    pub removal_id: String,
}

/// A validated full snapshot, never a partial list salvaged from malformed data.
#[derive(Debug)]
pub struct VaultSharingSnapshot {
    pub members: Vec<VaultSharingMember>,
    pub enabled: bool,
    pub devices: Vec<(String, String)>,
    pub computers: Vec<(String, String)>,
    pub tombstones: Vec<SharingTombstone>,
}

pub fn decode_snapshot(body: &Value) -> Option<VaultSharingSnapshot> {
    let snapshot: Snapshot = serde_json::from_value(body.clone()).ok()?;
    if !is_lower_hex_sha256(&snapshot.identity.static_public_key_hex) {
        return None;
    }
    let mut fingerprints = BTreeSet::new();
    let mut members = Vec::new();
    let mut enabled = false;
    let mut devices = Vec::new();
    let mut computers = Vec::new();
    for device in snapshot.devices {
        if !is_lower_hex_16_bytes(&device.fingerprint)
            || device.pairing_id.is_empty()
            || !fingerprints.insert(device.fingerprint.clone())
        {
            return None;
        }
        let mut shares = BTreeSet::new();
        for share in device.shares {
            if share.share.is_empty() || !shares.insert(share.share.clone()) {
                return None;
            }
            if share.share == "vault" && share.enabled {
                enabled = true;
                if device.class == Class::Computer {
                    members.push(VaultSharingMember {
                        member_id: format!("fed-computer:{}", device.fingerprint),
                        pairing_id: device.pairing_id.clone(),
                    });
                }
            }
        }
        if device.class == Class::Computer {
            computers.push((device.fingerprint.clone(), device.pairing_id.clone()));
        }
        devices.push((device.fingerprint, device.pairing_id));
    }
    let mut tombstone_fingerprints = BTreeSet::new();
    let mut tombstones = Vec::new();
    for tombstone in snapshot.tombstones {
        if !is_lower_hex_16_bytes(&tombstone.fingerprint)
            || tombstone.removal_id.is_empty()
            || !tombstone_fingerprints.insert(tombstone.fingerprint.clone())
        {
            return None;
        }
        tombstones.push(SharingTombstone {
            member_id: format!("fed-computer:{}", tombstone.fingerprint),
            removal_id: tombstone.removal_id,
        });
    }
    tombstones.sort_by(|a, b| a.member_id.cmp(&b.member_id));
    Some(VaultSharingSnapshot {
        members,
        enabled,
        devices,
        computers,
        tombstones,
    })
}

fn request(method: &str) -> RouteCall {
    RouteCall {
        target: management_surface("callosum"),
        prelude: None,
        request: json!({"method": method, "params": {}}),
    }
}

async fn apply(
    store: Arc<EncryptedStore>,
    body: Value,
    retries: &mut RetryState,
    removals: &Arc<PendingRemovals>,
    home_watches: Option<&super::home_watch::RemoteWatchHub>,
    member_pairings: Option<&tokio::sync::watch::Sender<super::member_watch::PairedComputers>>,
) -> Result<(), String> {
    let snapshot =
        decode_snapshot(&body).ok_or_else(|| "invalid paired-device snapshot".to_string())?;
    if let Some(hub) = home_watches {
        hub.paired_devices(snapshot.devices);
    }
    if let Some(pairings) = member_pairings {
        pairings.send_replace(Some(snapshot.computers));
    }
    let removals = Arc::clone(removals);
    tokio::task::spawn_blocking(move || {
        removals.record(&store, snapshot.tombstones);
        if snapshot.enabled {
            super::transfer::ensure_transfer_key(&store, "vault")?;
        }
        store
            .reconcile_vault_sharing_audited(&snapshot.members)
            .map(|_| ())
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| e.to_string())?;
    if retries.applied() {
        tracing::info!(target: "federation", "vault sharing snapshot reconciliation recovered");
    }
    Ok(())
}

const MAX_SHARING_RETRY_SECONDS: u64 = 60;

/// Delay after consecutive failed attempts: 1, 2, 4, 8, 16, 32, then at most 60 seconds.
fn retry_delay(failures: u32) -> Duration {
    Duration::from_secs(
        1u64.checked_shl(failures.saturating_sub(1))
            .unwrap_or(u64::MAX)
            .min(MAX_SHARING_RETRY_SECONDS),
    )
}

#[derive(Default)]
struct RetryState {
    failures: u32,
    last_error: Option<String>,
}

impl RetryState {
    fn failed(&mut self, error: &str) -> (Duration, bool) {
        self.failures = self.failures.saturating_add(1);
        let warn = self.last_error.as_deref() != Some(error);
        if warn {
            self.last_error = Some(error.to_string());
        }
        (retry_delay(self.failures), warn)
    }

    fn applied(&mut self) -> bool {
        self.failures = 0;
        self.last_error.take().is_some()
    }
}

#[derive(Default)]
struct PendingRemovals {
    items: Mutex<BTreeSet<(String, String)>>,
    observed: tokio::sync::Notify,
}

impl PendingRemovals {
    fn record(&self, store: &EncryptedStore, tombstones: Vec<SharingTombstone>) {
        if tombstones.is_empty() {
            return;
        }
        let batch: Vec<_> = tombstones
            .into_iter()
            .map(|item| FleetRemoval {
                member_id: item.member_id,
                removal_id: item.removal_id,
            })
            .collect();
        if store
            .fleet_record_removals(&batch, super::transfer::wall_now_ms())
            .is_ok()
        {
            let mut pending = self.items.lock().expect("pending fleet removals");
            for item in batch {
                pending.remove(&(item.member_id, item.removal_id));
            }
        } else {
            let mut pending = self.items.lock().expect("pending fleet removals");
            pending.extend(
                batch
                    .into_iter()
                    .map(|item| (item.member_id, item.removal_id)),
            );
            self.observed.notify_one();
        }
    }

    async fn run(&self, store: Arc<EncryptedStore>) {
        let mut failures = 1u32;
        loop {
            if self
                .items
                .lock()
                .expect("pending fleet removals")
                .is_empty()
            {
                failures = 1;
                self.observed.notified().await;
                continue;
            }
            if failures == 1 {
                tracing::warn!(target: "federation", "fleet removals not recorded; retrying");
            }
            tokio::time::sleep(retry_delay(failures)).await;
            let pending = self.items.lock().expect("pending fleet removals").clone();
            if pending.is_empty() {
                continue;
            }
            let store = Arc::clone(&store);
            let result = tokio::task::spawn_blocking(move || {
                let batch: Vec<_> = pending
                    .iter()
                    .map(|(member_id, removal_id)| FleetRemoval {
                        member_id: member_id.clone(),
                        removal_id: removal_id.clone(),
                    })
                    .collect();
                store.fleet_record_removals(&batch, super::transfer::wall_now_ms())?;
                Ok::<_, credentials_core::fleet::FleetError>(pending)
            })
            .await;
            if let Ok(Ok(committed)) = result {
                let mut items = self.items.lock().expect("pending fleet removals");
                for item in committed {
                    items.remove(&item);
                }
                failures = 1;
            } else {
                failures = failures.saturating_add(1);
            }
        }
    }
}

/// Run until cancelled by the daemon's task guard. Every reopen starts with a full
/// read; the watch's initial snapshot closes the read/subscribe race.
pub async fn run(store: Arc<EncryptedStore>, client: OutboundClient) {
    run_with_home_watches(store, client, None).await;
}

pub async fn run_with_home_watches(
    store: Arc<EncryptedStore>,
    client: OutboundClient,
    home_watches: Option<Arc<super::home_watch::RemoteWatchHub>>,
) {
    run_with_reconcilers(store, client, home_watches, None).await;
}

pub async fn run_with_reconcilers(
    store: Arc<EncryptedStore>,
    client: OutboundClient,
    home_watches: Option<Arc<super::home_watch::RemoteWatchHub>>,
    member_pairings: Option<tokio::sync::watch::Sender<super::member_watch::PairedComputers>>,
) {
    let removals = Arc::new(PendingRemovals::default());
    // Keep the removal queue alive across reconnects and login-sharing changes.
    tokio::select! {
        _ = removals.run(Arc::clone(&store)) => {},
        _ = reconcile(store, client, home_watches, member_pairings, &removals) => {},
    }
}

async fn reconcile(
    store: Arc<EncryptedStore>,
    client: OutboundClient,
    home_watches: Option<Arc<super::home_watch::RemoteWatchHub>>,
    member_pairings: Option<tokio::sync::watch::Sender<super::member_watch::PairedComputers>>,
    removals: &Arc<PendingRemovals>,
) {
    let mut retries = RetryState::default();
    let mut writes = store.subscribe_writes();
    let mut enabled = store.login_sharing().unwrap_or(false);
    'watching: loop {
        let outcome = {
            let attempt = watch(
                Arc::clone(&store),
                &client,
                &mut retries,
                removals,
                home_watches.as_deref(),
                member_pairings.as_ref(),
            );
            tokio::pin!(attempt);
            loop {
                tokio::select! {
                    result = &mut attempt => break result,
                    changed = writes.changed() => {
                        if changed.is_err() { return; }
                        let current = store.login_sharing().unwrap_or(false);
                        let turned_on = !enabled && current;
                        enabled = current;
                        if turned_on { continue 'watching; }
                    }
                }
            }
        };
        let delay = match outcome {
            Err(error) => {
                let (delay, warn) = retries.failed(&error);
                if warn {
                    tracing::warn!(target: "federation", %error, "vault sharing unchanged until Callosum supplies a valid snapshot");
                }
                delay
            }
            Ok(()) => retry_delay(1),
        };
        tokio::time::sleep(delay).await;
    }
}

async fn watch(
    store: Arc<EncryptedStore>,
    client: &OutboundClient,
    retries: &mut RetryState,
    removals: &Arc<PendingRemovals>,
    home_watches: Option<&super::home_watch::RemoteWatchHub>,
    member_pairings: Option<&tokio::sync::watch::Sender<super::member_watch::PairedComputers>>,
) -> Result<(), String> {
    let snapshot = client
        .call(
            "callosum",
            request("callosum.paired_devices_read"),
            ADMIN_OP_BUDGET,
        )
        .await
        .map_err(|e| e.message().to_string())?;
    apply(
        Arc::clone(&store),
        snapshot,
        retries,
        removals,
        home_watches,
        member_pairings,
    )
    .await?;
    let mut subscription = client
        .subscribe(
            "callosum",
            request("callosum.paired_devices_watch"),
            ADMIN_OP_BUDGET,
        )
        .await
        .map_err(|e| e.message().to_string())?;
    while let Some(snapshot) = subscription
        .next()
        .await
        .map_err(|e| e.message().to_string())?
    {
        apply(
            Arc::clone(&store),
            snapshot,
            retries,
            removals,
            home_watches,
            member_pairings,
        )
        .await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sharing_retry_delay_doubles_until_the_sixty_second_cap() {
        for (failures, seconds) in [
            (0, 1),
            (1, 1),
            (2, 2),
            (3, 4),
            (4, 8),
            (5, 16),
            (6, 32),
            (7, 60),
            (8, 60),
            (u32::MAX, 60),
        ] {
            assert_eq!(retry_delay(failures), Duration::from_secs(seconds));
        }
    }

    #[test]
    fn sharing_retries_warn_only_on_first_or_changed_error_and_recover_once() {
        let mut state = RetryState::default();
        assert!(!state.applied());
        for (error, seconds, warn) in [
            ("offline", 1, true),
            ("offline", 2, false),
            ("different", 4, true),
            ("different", 8, false),
        ] {
            assert_eq!(state.failed(error), (Duration::from_secs(seconds), warn));
        }
        assert!(state.applied());
        assert!(!state.applied());
        assert_eq!(state.failed("different"), (Duration::from_secs(1), true));
        assert_eq!(state.failed("different"), (Duration::from_secs(2), false));
        state.failures = u32::MAX;
        assert_eq!(state.failed("different"), (Duration::from_secs(60), false));
    }
}
