//! Callosum's per-computer vault switch owns only switch-sourced member grants.
//! A failed lookup is not an empty inventory: no grant changes until a full snapshot
//! has decoded, and each snapshot's grant changes commit with their audits together.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use credentials_core::federation::{
    is_lower_hex_16_bytes, is_lower_hex_sha256, valid_pairing_id, VaultSharingMember,
};
use credentials_core::fleet::FleetRemoval;
use credentials_core::store::EncryptedStore;
use serde::Deserialize;
use serde_json::{json, Value};

use super::outbound::{management_surface, OutboundClient, RouteCall, ADMIN_OP_BUDGET};
use super::outbound::{Subscription, SubscriptionEvent};

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
    /// Fingerprints of devices whose class this build does not recognise. Such a
    /// device is unmapped: it is neither a computer nor proof that one went away.
    pub unrecognised: Vec<String>,
    pub tombstones: Vec<SharingTombstone>,
}

pub(crate) type PairingSnapshots = tokio::sync::watch::Sender<Option<Arc<VaultSharingSnapshot>>>;

pub fn decode_snapshot(body: &Value) -> Option<VaultSharingSnapshot> {
    check_snapshot(body).ok()
}

/// Decode a paired-device roster, or name the first check it failed. The reason is a
/// fixed code, never a value from the body, so it can go into a log line.
fn check_snapshot(body: &Value) -> Result<VaultSharingSnapshot, &'static str> {
    let snapshot: Snapshot = serde_json::from_value(body.clone()).map_err(|_| "shape")?;
    if !is_lower_hex_sha256(&snapshot.identity.static_public_key_hex) {
        return Err("identity_key");
    }
    let mut fingerprints = BTreeSet::new();
    let mut members = Vec::new();
    let mut enabled = false;
    let mut devices = Vec::new();
    let mut computers = Vec::new();
    let mut unrecognised = Vec::new();
    for device in snapshot.devices {
        // One pairing-id rule for the whole roster, the store's own: a roster the
        // store would refuse is never published to anyone as evidence of pairing.
        if !is_lower_hex_16_bytes(&device.fingerprint) {
            return Err("device_fingerprint");
        }
        if !valid_pairing_id(&device.pairing_id) {
            return Err("device_pairing_id");
        }
        if !fingerprints.insert(device.fingerprint.clone()) {
            return Err("duplicate_device");
        }
        let mut shares = BTreeSet::new();
        for share in device.shares {
            if share.share.is_empty() {
                return Err("share_name");
            }
            if !shares.insert(share.share.clone()) {
                return Err("duplicate_share");
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
        if device.class == Class::Unknown {
            unrecognised.push(device.fingerprint.clone());
        }
        devices.push((device.fingerprint, device.pairing_id));
    }
    let mut tombstone_fingerprints = BTreeSet::new();
    let mut tombstones = Vec::new();
    for tombstone in snapshot.tombstones {
        if !is_lower_hex_16_bytes(&tombstone.fingerprint) {
            return Err("tombstone_fingerprint");
        }
        if tombstone.removal_id.is_empty() {
            return Err("tombstone_removal_id");
        }
        if !tombstone_fingerprints.insert(tombstone.fingerprint.clone()) {
            return Err("duplicate_tombstone");
        }
        tombstones.push(SharingTombstone {
            member_id: format!("fed-computer:{}", tombstone.fingerprint),
            removal_id: tombstone.removal_id,
        });
    }
    tombstones.sort_by(|a, b| a.member_id.cmp(&b.member_id));
    Ok(VaultSharingSnapshot {
        members,
        enabled,
        devices,
        computers,
        unrecognised,
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

/// Validate the whole roster, commit its grant changes, and only then publish it.
/// Consumers therefore never act on a roster the store refused or on grants that
/// never committed; after a failure they keep the previous snapshot.
async fn apply(
    store: Arc<EncryptedStore>,
    body: Value,
    removals: &Arc<PendingRemovals>,
    manifest_watches: Option<&super::manifest_watch_ingress::ManifestWatchHub>,
    hub_pairings: Option<&PairingSnapshots>,
) -> Result<(), String> {
    let snapshot = Arc::new(
        check_snapshot(&body)
            .map_err(|reason| format!("invalid paired-device snapshot: {reason}"))?,
    );
    let removals = Arc::clone(removals);
    let reconciled = Arc::clone(&snapshot);
    tokio::task::spawn_blocking(move || {
        removals.record(&store, reconciled.tombstones.clone());
        if reconciled.enabled {
            super::transfer::ensure_transfer_key(&store, "vault")?;
        }
        store
            .reconcile_vault_sharing_audited(&reconciled.members)
            .map(|_| ())
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| e.to_string())?;
    if let Some(hub) = manifest_watches {
        hub.paired_devices(snapshot.devices.clone());
    }
    if let Some(pairings) = hub_pairings {
        pairings.send_replace(Some(snapshot));
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

    fn ended(&mut self) -> Duration {
        self.failures = self.failures.saturating_add(1);
        retry_delay(self.failures)
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
    run_with_manifest_watches(store, client, None).await;
}

pub async fn run_with_manifest_watches(
    store: Arc<EncryptedStore>,
    client: OutboundClient,
    manifest_watches: Option<Arc<super::manifest_watch_ingress::ManifestWatchHub>>,
) {
    run_with_pairing_snapshots(store, client, manifest_watches, None).await;
}

pub(crate) async fn run_with_pairing_snapshots(
    store: Arc<EncryptedStore>,
    client: OutboundClient,
    manifest_watches: Option<Arc<super::manifest_watch_ingress::ManifestWatchHub>>,
    hub_pairings: Option<PairingSnapshots>,
) {
    let removals = Arc::new(PendingRemovals::default());
    // Keep the removal queue alive across reconnects and login-sharing changes.
    tokio::select! {
        _ = removals.run(Arc::clone(&store)) => {},
        _ = reconcile(store, client, manifest_watches, hub_pairings, &removals) => {},
    }
}

async fn reconcile(
    store: Arc<EncryptedStore>,
    client: OutboundClient,
    manifest_watches: Option<Arc<super::manifest_watch_ingress::ManifestWatchHub>>,
    hub_pairings: Option<PairingSnapshots>,
    removals: &Arc<PendingRemovals>,
) {
    let mut retries = RetryState::default();
    let mut writes = store.subscribe_writes();
    let mut enables = store.login_sharing_enables();
    'watching: loop {
        let outcome = {
            let attempt = watch(
                Arc::clone(&store),
                &client,
                &mut retries,
                removals,
                manifest_watches.as_deref(),
                hub_pairings.as_ref(),
            );
            tokio::pin!(attempt);
            loop {
                tokio::select! {
                    result = &mut attempt => break result,
                    changed = writes.changed() => {
                        if changed.is_err() { return; }
                        // Write notices coalesce, so an off-then-on pair can look
                        // like no change at all. Every turn-on is counted instead,
                        // and any change that ends at on rereads the roster.
                        let current = store.login_sharing_enables();
                        if current != enables {
                            enables = current;
                            if store.login_sharing().unwrap_or(false) {
                                if let Some(pairings) = &hub_pairings {
                                    pairings.send_replace(None);
                                }
                                continue 'watching;
                            }
                        }
                    }
                }
            }
        };
        if let Some(pairings) = &hub_pairings {
            pairings.send_replace(None);
        }
        // Only an applied watch notice resets the backoff, so a Callosum that serves
        // the read but refuses or drops the watch is retried ever more slowly.
        let delay = match outcome {
            Err(error) => {
                let (delay, warn) = retries.failed(&error);
                if warn {
                    tracing::warn!(target: "federation", %error, "vault sharing unchanged until Callosum supplies a valid snapshot");
                }
                delay
            }
            Ok(()) => retries.ended(),
        };
        tokio::time::sleep(delay).await;
    }
}

/// Read the full roster, then hold the watch. The initial read alone is not proof
/// that the watch works, so only a notice applied from the watch counts as success.
async fn watch(
    store: Arc<EncryptedStore>,
    client: &OutboundClient,
    retries: &mut RetryState,
    removals: &Arc<PendingRemovals>,
    manifest_watches: Option<&super::manifest_watch_ingress::ManifestWatchHub>,
    hub_pairings: Option<&PairingSnapshots>,
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
        removals,
        manifest_watches,
        hub_pairings,
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
    let mut first = true;
    loop {
        let snapshot = match next_notice(&mut subscription, first, "paired-device").await? {
            Some(snapshot) => snapshot,
            None => return Ok(()),
        };
        first = false;
        apply(
            Arc::clone(&store),
            snapshot,
            removals,
            manifest_watches,
            hub_pairings,
        )
        .await?;
        if retries.applied() {
            tracing::info!(target: "federation", "vault sharing snapshot reconciliation recovered");
        }
    }
}

/// The next data notice of a Callosum watch, `None` at a clean end. A refusal or
/// a reply in place of the stream is a failure that names its code. The first
/// notice is bounded: a service that accepts the watch but never starts it would
/// otherwise hold the feed for ever.
pub(super) async fn next_notice(
    subscription: &mut Subscription,
    first: bool,
    feed: &str,
) -> Result<Option<Value>, String> {
    let event = if first {
        tokio::time::timeout(ADMIN_OP_BUDGET, subscription.next_event())
            .await
            .map_err(|_| format!("no first {feed} notice within the setup budget"))?
    } else {
        subscription.next_event().await
    };
    match event.map_err(|e| e.message().to_string())? {
        SubscriptionEvent::Data(body) => Ok(Some(body)),
        SubscriptionEvent::End => Ok(None),
        SubscriptionEvent::Error { code, .. } => Err(format!("{feed} watch refused: {code}")),
        SubscriptionEvent::Response(_) => {
            Err(format!("{feed} watch answered instead of streaming"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_invalid_roster_names_the_check_it_failed() {
        let key = "a".repeat(64);
        let device = |fingerprint: &str| {
            json!({"class": "computer", "fingerprint": fingerprint, "pairing_id": "pair-1",
                   "shares": [{"share": "vault", "enabled": true}]})
        };
        let roster = |key: &str, devices: Value| json!({"self": {"static_public_key_hex": key}, "devices": devices});
        let one = "0123456789abcdef0123456789abcdef";
        for (body, reason) in [
            (json!({"devices": []}), "shape"),
            (roster("", json!([])), "identity_key"),
            (
                roster(&key, json!([device("not-hex")])),
                "device_fingerprint",
            ),
            (
                roster(&key, json!([device(one), device(one)])),
                "duplicate_device",
            ),
        ] {
            assert_eq!(check_snapshot(&body).err(), Some(reason), "{body}");
        }
        assert!(check_snapshot(&roster(&key, json!([device(one)]))).is_ok());
    }

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
