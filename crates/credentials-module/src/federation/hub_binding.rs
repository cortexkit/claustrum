//! Join Callosum's two local views before using a computer's hub address or keys.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use credentials_core::federation::is_lower_hex_16_bytes;
use serde_json::{json, Value};
use tokio::sync::watch;

use super::{
    hub::Backoff,
    ingress::decode_public_key_hex,
    outbound::{management_surface, OutboundClient, RouteCall, ADMIN_OP_BUDGET},
    sharing::VaultSharingSnapshot,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HubBinding {
    pub(crate) member_id: String,
    pub(crate) box_id: String,
    pub(crate) pairing_id: String,
    pub(crate) vault_transfer_x25519: Option<[u8; 32]>,
    pub(crate) fleet_record_ed25519: Option<[u8; 32]>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum HubMember<'a> {
    Bound(&'a HubBinding),
    /// At least one view still lists the fingerprint, but it has no usable binding.
    Unmapped,
    /// Neither of the two available views lists the fingerprint.
    Absent,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HubBindings {
    present: BTreeSet<String>,
    by_fingerprint: BTreeMap<String, HubBinding>,
    by_box: BTreeMap<String, String>,
    ambiguous_boxes: BTreeSet<String>,
}

impl HubBindings {
    /// The peer-key read and watch both carry a full `peers` array. A refusal or
    /// malformed roster is not a successful, empty view and cannot prove unpairing.
    pub(crate) fn join(
        own_box: &str,
        paired: &VaultSharingSnapshot,
        peer_keys: &Value,
    ) -> Option<Self> {
        if !is_lower_hex_16_bytes(own_box) {
            return None;
        }
        let mut peers = BTreeMap::new();
        let mut boxes = BTreeMap::new();
        for peer in peer_keys.get("peers")?.as_array()? {
            let fingerprint = peer.get("fingerprint")?.as_str()?;
            if !is_lower_hex_16_bytes(fingerprint) || peers.insert(fingerprint, peer).is_some() {
                return None;
            }
            // A duplicate box is ambiguous even if the other claimant is not mappable.
            if let Some(box_id) = machine_id(peer) {
                *boxes.entry(box_id).or_insert(0usize) += 1;
            }
        }

        let mut joined = Self {
            present: paired
                .devices
                .iter()
                .map(|(fingerprint, _)| fingerprint.clone())
                .chain(peers.keys().map(|fp| (*fp).to_string()))
                .collect(),
            by_fingerprint: BTreeMap::new(),
            by_box: BTreeMap::new(),
            ambiguous_boxes: boxes
                .iter()
                .filter(|(_, count)| **count > 1)
                .map(|(box_id, _)| (*box_id).to_string())
                .collect(),
        };
        for (fingerprint, pairing_id) in &paired.computers {
            let Some(peer) = peers.get(fingerprint.as_str()) else {
                continue;
            };
            if peer.get("class").and_then(Value::as_str) != Some("computer")
                || peer.get("pairing_id").and_then(Value::as_str) != Some(pairing_id)
            {
                continue;
            }
            let Some(box_id) = machine_id(peer)
                .filter(|box_id| *box_id != own_box && boxes.get(box_id) == Some(&1))
            else {
                continue;
            };
            joined
                .by_box
                .insert(box_id.to_string(), fingerprint.clone());
            joined.by_fingerprint.insert(
                fingerprint.clone(),
                HubBinding {
                    member_id: format!("fed-computer:{fingerprint}"),
                    box_id: box_id.to_string(),
                    pairing_id: pairing_id.clone(),
                    vault_transfer_x25519: announced_key(peer, "vault_transfer_x25519"),
                    fleet_record_ed25519: announced_key(peer, "fleet_record_ed25519"),
                },
            );
        }
        Some(joined)
    }

    pub(crate) fn member(&self, member_id: &str) -> HubMember<'_> {
        let Some(fingerprint) = member_id
            .strip_prefix("fed-computer:")
            .filter(|fp| is_lower_hex_16_bytes(fp))
        else {
            return HubMember::Unmapped;
        };
        match self.by_fingerprint.get(fingerprint) {
            Some(binding) => HubMember::Bound(binding),
            None if self.present.contains(fingerprint) => HubMember::Unmapped,
            None => HubMember::Absent,
        }
    }

    pub(crate) fn by_box(&self, box_id: &str) -> Option<&HubBinding> {
        self.by_fingerprint.get(self.by_box.get(box_id)?)
    }

    pub(crate) fn bindings(&self) -> impl Iterator<Item = &HubBinding> {
        self.by_fingerprint.values()
    }

    pub(super) fn box_is_ambiguous(&self, box_id: &str) -> bool {
        self.ambiguous_boxes.contains(box_id)
    }
}

/// Join the sharing loop's paired-device snapshots with the full peer-key notices.
/// A terminated stream invalidates its half; it does not prove nobody is paired.
pub(crate) async fn run_binding_feed(
    own_box: &str,
    client: OutboundClient,
    mut pairings: watch::Receiver<Option<Arc<VaultSharingSnapshot>>>,
    joined: watch::Sender<Option<HubBindings>>,
) {
    let mut backoff = Backoff::default();
    loop {
        let request = RouteCall {
            target: management_surface("callosum"),
            prelude: None,
            request: json!({"method":"callosum.peer_keys_watch", "params":{}}),
        };
        let subscription = tokio::select! {
            _ = joined.closed() => return,
            result = client.subscribe("callosum", request, ADMIN_OP_BUDGET) => result,
        };
        if let Ok(mut subscription) = subscription {
            let mut peer_keys = None;
            // A watch that is accepted but never starts would otherwise hold the
            // feed for ever, so its first notice has the setup budget.
            let first_notice_by = tokio::time::Instant::now() + ADMIN_OP_BUDGET;
            loop {
                let current = pairings
                    .borrow_and_update()
                    .clone()
                    .and_then(|paired| HubBindings::join(own_box, &paired, peer_keys.as_ref()?));
                if current.is_some() {
                    backoff.reset();
                }
                replace_if_changed(&joined, current);
                tokio::select! {
                    _ = joined.closed() => return,
                    change = pairings.changed() => if change.is_err() {
                        replace_if_changed(&joined, None);
                        return;
                    },
                    result = subscription.next() => match result {
                        Ok(Some(value)) => peer_keys = Some(value),
                        _ => break,
                    },
                    _ = tokio::time::sleep_until(first_notice_by), if peer_keys.is_none() => break,
                }
            }
        }
        replace_if_changed(&joined, None);
        tokio::select! {
            _ = joined.closed() => return,
            _ = tokio::time::sleep(backoff.next_delay()) => {},
        }
    }
}

fn replace_if_changed(joined: &watch::Sender<Option<HubBindings>>, current: Option<HubBindings>) {
    joined.send_if_modified(|prior| {
        if *prior == current {
            return false;
        }
        *prior = current;
        true
    });
}

fn machine_id(peer: &Value) -> Option<&str> {
    peer.get("machine_id")?
        .as_str()
        .filter(|box_id| is_lower_hex_16_bytes(box_id))
}

fn announced_key(peer: &Value, kind: &str) -> Option<[u8; 32]> {
    decode_public_key_hex(
        peer.get("key_record")?
            .get("keys")?
            .get(kind)?
            .get("pub")?
            .as_str()?,
    )
}

#[cfg(test)]
mod tests {
    use super::{super::sharing::decode_snapshot, *};
    use serde_json::json;

    const OWN_BOX: &str = "00000000000000000000000000000000";
    const BOX: &str = "853ecdb6e1681c3dc8c1c578d14c23a2";
    const NEW_BOX: &str = "11111111111111111111111111111111";
    const FP: &str = "72cd6e8422c407fb6d098690f1130b7d";
    const OTHER_FP: &str = "22222222222222222222222222222222";
    const MEMBER: &str = "fed-computer:72cd6e8422c407fb6d098690f1130b7d";
    const PAIRING: &str = "9d3a2f6e-9a1d-4b42-8c56-cf6c6d3d4a9e:1";

    fn paired(devices: Value) -> VaultSharingSnapshot {
        decode_snapshot(&json!({
            "self": {"static_public_key_hex": "00".repeat(32)},
            "devices": devices
        }))
        .unwrap()
    }

    fn current_pairing() -> VaultSharingSnapshot {
        paired(json!([
            {"fingerprint": OTHER_FP, "pairing_id": "other:2", "class": "computer", "shares": []},
            {"fingerprint": FP, "pairing_id": PAIRING, "class": "computer", "shares": []}
        ]))
    }

    fn fixture_reply() -> Value {
        let file: Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/callosum/peer-keys-v3/cases.json"
        ))
        .unwrap();
        file["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["name"] == "vault_sees_bus_and_fleet_keys")
            .unwrap()["reply"]
            .clone()
    }

    #[test]
    fn joins_by_fingerprint_and_exposes_only_current_box_and_announced_keys() {
        let mut peers = fixture_reply();
        let keys = &mut peers["peers"][0]["key_record"]["keys"];
        keys["vault_transfer_x25519"]["pub"] = json!("22".repeat(32));
        keys["fleet_record_ed25519"]["pub"] = json!("33".repeat(32));
        let paired = current_pairing();
        let join = HubBindings::join(OWN_BOX, &paired, &peers).unwrap();
        let binding = join.by_box(BOX).unwrap();
        assert_eq!(join.bindings().count(), 1);
        assert_eq!(join.member(MEMBER), HubMember::Bound(binding));
        assert_eq!(binding.member_id, MEMBER);
        assert_eq!(binding.box_id, BOX);
        assert_eq!(binding.pairing_id, PAIRING);
        assert_eq!(binding.vault_transfer_x25519, Some([0x22; 32]));
        assert_eq!(binding.fleet_record_ed25519, Some([0x33; 32]));

        peers["peers"][0]["machine_id"] = json!(NEW_BOX);
        let join = HubBindings::join(OWN_BOX, &paired, &peers).unwrap();
        assert!(join.by_box(BOX).is_none());
        assert_eq!(join.by_box(NEW_BOX).unwrap().member_id, MEMBER);
    }

    #[test]
    fn disagreement_is_unmapped_not_unpaired() {
        let paired = current_pairing();
        let unpaired = self::paired(json!([]));
        let mut peer_keys = fixture_reply();
        let empty = json!({"peers": []});
        for (snapshot, peers) in [(&paired, &empty), (&unpaired, &peer_keys)] {
            let join = HubBindings::join(OWN_BOX, snapshot, peers).unwrap();
            assert_eq!(join.member(MEMBER), HubMember::Unmapped);
            assert!(join.by_box(BOX).is_none());
        }
        peer_keys["peers"][0]["pairing_id"] = json!("new-pairing:2");
        let join = HubBindings::join(OWN_BOX, &paired, &peer_keys).unwrap();
        assert_eq!(join.member(MEMBER), HubMember::Unmapped);
        assert!(join.by_box(BOX).is_none());
        assert_eq!(
            HubBindings::join(OWN_BOX, &unpaired, &empty)
                .unwrap()
                .member(MEMBER),
            HubMember::Absent
        );
        assert!(HubBindings::join(OWN_BOX, &unpaired, &json!({"code": "fed_not_ready"})).is_none());
        assert!(HubBindings::join(OWN_BOX, &unpaired, &json!({"peers": [{}]})).is_none());
    }

    #[test]
    fn only_unique_valid_boxes_of_other_computers_map() {
        let paired = current_pairing();
        let regular = fixture_reply();
        for (field, value) in [
            ("class", json!("phone")),
            ("class", Value::Null),
            ("machine_id", Value::Null),
            ("machine_id", json!("not-a-box")),
            ("machine_id", json!(OWN_BOX)),
        ] {
            let mut keys = regular.clone();
            keys["peers"][0][field] = value;
            let join = HubBindings::join(OWN_BOX, &paired, &keys).unwrap();
            assert_eq!(join.member(MEMBER), HubMember::Unmapped);
            assert_eq!(join.bindings().count(), 0);
        }
        let mut duplicate = regular;
        duplicate["peers"].as_array_mut().unwrap().push(json!({
            "class": "phone", "fingerprint": OTHER_FP, "machine_id": BOX
        }));
        let join = HubBindings::join(OWN_BOX, &paired, &duplicate).unwrap();
        assert_eq!(join.member(MEMBER), HubMember::Unmapped);
        assert!(join.by_box(BOX).is_none());
    }

    #[test]
    fn peer_key_watch_uses_the_same_join_as_the_read() {
        let file: Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/callosum/peer-keys-watch-v1/cases.json"
        ))
        .unwrap();
        let paired = current_pairing();
        assert_eq!(file["cases"].as_array().unwrap().len(), 5);
        for case in file["cases"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let notices = case["notices"].as_array().unwrap();
            match name {
                "vault_open" => {
                    assert_eq!(notices.len(), 1);
                    let join = HubBindings::join(OWN_BOX, &paired, &notices[0]).unwrap();
                    let binding = join.by_box(BOX).expect("vault notice has a current box");
                    assert_eq!(binding.member_id, MEMBER);
                    assert_eq!(binding.pairing_id, PAIRING);
                    assert_eq!(binding.vault_transfer_x25519, None, "short fixture key");
                    assert_eq!(binding.fleet_record_ed25519, None, "not announced");
                }
                "ordinary_open" | "visible_key_change" => {
                    assert_eq!(notices.len(), 1);
                    let join = HubBindings::join(OWN_BOX, &paired, &notices[0]).unwrap();
                    assert_eq!(join.member(MEMBER), HubMember::Unmapped, "{name}");
                }
                "invisible_key_change" => assert!(notices.is_empty()),
                "not_ready" => {
                    assert!(notices.is_empty());
                    assert!(HubBindings::join(OWN_BOX, &paired, &case["refusal"]).is_none());
                }
                _ => panic!("unknown watch case: {name}"),
            }
        }
    }
}
