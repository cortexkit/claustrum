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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    devices: Vec<Device>,
    #[serde(rename = "self")]
    identity: Identity,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    static_public_key_hex: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
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
    Unknown,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Share {
    share: String,
    enabled: bool,
}

/// A validated full snapshot, never a partial list salvaged from malformed data.
#[derive(Debug)]
pub struct VaultSharingSnapshot {
    pub members: Vec<VaultSharingMember>,
    pub enabled: bool,
}

pub fn decode_snapshot(body: &Value) -> Option<VaultSharingSnapshot> {
    let snapshot: Snapshot = serde_json::from_value(body.clone()).ok()?;
    if !is_lower_hex_sha256(&snapshot.identity.static_public_key_hex) {
        return None;
    }
    let mut fingerprints = BTreeSet::new();
    let mut members = Vec::new();
    let mut enabled = false;
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
    }
    Some(VaultSharingSnapshot { members, enabled })
}

fn request(method: &str) -> RouteCall {
    RouteCall {
        target: management_surface("callosum"),
        prelude: None,
        request: json!({"method": method, "params": {}}),
    }
}

async fn apply(store: Arc<EncryptedStore>, body: Value) -> Result<(), String> {
    let snapshot =
        decode_snapshot(&body).ok_or_else(|| "invalid paired-device snapshot".to_string())?;
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
    .map_err(|e| e.to_string())
}

/// Run until cancelled by the daemon's task guard. Every reopen starts with a full
/// read; the watch's initial snapshot closes the read/subscribe race.
pub async fn run(store: Arc<EncryptedStore>, client: OutboundClient) {
    loop {
        if let Err(error) = watch(Arc::clone(&store), &client).await {
            tracing::warn!(target: "federation", %error, "vault sharing unchanged until Callosum supplies a valid snapshot");
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

async fn watch(store: Arc<EncryptedStore>, client: &OutboundClient) -> Result<(), String> {
    let snapshot = client
        .call(
            "callosum",
            request("callosum.paired_devices_read"),
            ADMIN_OP_BUDGET,
        )
        .await
        .map_err(|e| e.message().to_string())?;
    apply(Arc::clone(&store), snapshot).await?;
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
        apply(Arc::clone(&store), snapshot).await?;
    }
    Ok(())
}
