//! Callosum's per-computer vault switch owns only switch-sourced member grants.
//! A failed lookup is not an empty inventory: no grant changes until a full snapshot
//! has decoded, and each snapshot's grant changes commit with their audits together.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use credentials_core::federation::{
    is_lower_hex_16_bytes, is_lower_hex_sha256, VaultSharingMember,
};
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

/// A validated full snapshot, never a partial list salvaged from malformed data.
#[derive(Debug)]
pub struct VaultSharingSnapshot {
    pub members: Vec<VaultSharingMember>,
    pub enabled: bool,
    pub devices: Vec<(String, String)>,
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
        devices.push((device.fingerprint, device.pairing_id));
    }
    Some(VaultSharingSnapshot {
        members,
        enabled,
        devices,
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
    home_watches: Option<&super::home_watch::RemoteWatchHub>,
) -> Result<(), String> {
    let snapshot =
        decode_snapshot(&body).ok_or_else(|| "invalid paired-device snapshot".to_string())?;
    if let Some(hub) = home_watches {
        hub.paired_devices(snapshot.devices);
    }
    tokio::task::spawn_blocking(move || {
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
    let mut retries = RetryState::default();
    loop {
        let delay = match watch(
            Arc::clone(&store),
            &client,
            &mut retries,
            home_watches.as_deref(),
        )
        .await
        {
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
    home_watches: Option<&super::home_watch::RemoteWatchHub>,
) -> Result<(), String> {
    let snapshot = client
        .call(
            "callosum",
            request("callosum.paired_devices_read"),
            ADMIN_OP_BUDGET,
        )
        .await
        .map_err(|e| e.message().to_string())?;
    apply(Arc::clone(&store), snapshot, retries, home_watches).await?;
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
        apply(Arc::clone(&store), snapshot, retries, home_watches).await?;
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
