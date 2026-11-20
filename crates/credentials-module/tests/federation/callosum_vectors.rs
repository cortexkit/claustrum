//! The vault's decoders for callosum's discovery replies, checked against callosum's
//! own published vectors (see `tests/fixtures/callosum/VENDORED.md`).
//!
//! The decoders in `federation::ingress` were written from callosum's described format.
//! These tests feed them bytes callosum's production code emitted, pinned at a callosum
//! tag. A change to the vault's decoders that breaks callosum's format fails here. A
//! change on callosum's side is caught when the vectors are refreshed from its next tag,
//! which is the point to copy them again rather than let a live home read "not paired".

use claustrum_module_probe::federation::ingress::{
    decode_paired_devices, decode_peer_transfer_key, decode_self_member, Lookup,
};
use claustrum_module_probe::federation::sharing::{decode_snapshot, SharingTombstone};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const PAIRED_DEVICES: &[u8] = include_bytes!("../fixtures/callosum/paired-devices/cases.json");
const PEER_KEYS: &[u8] = include_bytes!("../fixtures/callosum/peer-keys/cases.json");
const PAIRED_DEVICES_V2: &[u8] =
    include_bytes!("../fixtures/callosum/paired-devices-v2/cases.json");
const PEER_KEYS_V3: &[u8] = include_bytes!("../fixtures/callosum/peer-keys-v3/cases.json");
const PEER_KEYS_WATCH_V1: &[u8] =
    include_bytes!("../fixtures/callosum/peer-keys-watch-v1/cases.json");

/// The member id callosum's paired-devices README documents for the fixture's own key.
const FIXTURE_SELF_MEMBER: &str = "fed-computer:300c9c9603b92a4b39ed3958bf924011";

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// The reply of the named case, from a vector file's `cases` list.
fn reply(file: &[u8], name: &str) -> Value {
    let cases: Value = serde_json::from_slice(file).expect("vector file is JSON");
    cases["cases"]
        .as_array()
        .expect("vector file has a cases list")
        .iter()
        .find(|case| case["name"] == name)
        .unwrap_or_else(|| panic!("vector file has no case {name}"))["reply"]
        .clone()
}

#[test]
fn the_vendored_vectors_are_the_bytes_callosum_published() {
    assert_eq!(
        sha256_hex(PAIRED_DEVICES),
        "9bf5afa89ce776252e8a0e7bbadefe83799bda111da97748dce6349414f30901",
        "paired-devices vectors must match VENDORED.md"
    );
    assert_eq!(
        sha256_hex(include_bytes!(
            "../fixtures/callosum/paired-devices/README.md"
        )),
        "3e1e757f5676ec002ad5ce3cb12356d22da5c581ee7ef73c08928ae8c2743b06"
    );
    assert_eq!(
        sha256_hex(PEER_KEYS),
        "8b23d3ab3a9827e4d83584ca441ea84201979ca61cbcbf1560be0fca320ef805",
        "peer-keys vectors must match VENDORED.md"
    );
    assert_eq!(
        sha256_hex(include_bytes!(
            "../fixtures/callosum/fed-reexport-watch/local.json"
        )),
        "d235fcedee29caaf257c984edaa0c4883e19951585acd11a4a8a0991eb19d647",
        "fed-reexport-watch vectors must match VENDORED.md"
    );
    assert_eq!(
        sha256_hex(include_bytes!(
            "../fixtures/callosum/fed-reexport-watch/README.md"
        )),
        "322215e1f2c654fae79aed04468cbbe75e1176e5c9b3651da1b80761b0c4435b"
    );
}

#[test]
fn every_paired_devices_success_derives_the_documented_self_member() {
    for name in ["empty", "all_classes"] {
        assert_eq!(
            decode_self_member(&reply(PAIRED_DEVICES, name)),
            Lookup::Found(FIXTURE_SELF_MEMBER.to_string()),
            "case {name}"
        );
    }
}

#[test]
fn only_a_computer_class_device_maps_to_a_member_pairing() {
    let all = reply(PAIRED_DEVICES, "all_classes");
    assert_eq!(
        decode_paired_devices(&all, "fed-computer:648aa5c579fb30f38af744d97d6ec840"),
        Lookup::Found("11111111-2222-4333-8444-555555555555:3".to_string())
    );
    // The phone, sim and unknown devices are listed, but under their own class, so the
    // same fingerprints asked for as computers are not paired members.
    for fingerprint in [
        "72cd6e8422c407fb6d098690f1130b7d",
        "75877bb41d393b5fb8455ce60ecd8dda",
        "9f4fb68f3e1dac82202f9aa581ce0bbf",
    ] {
        assert_eq!(
            decode_paired_devices(&all, &format!("fed-computer:{fingerprint}")),
            Lookup::Absent,
            "{fingerprint}"
        );
    }
    assert_eq!(
        decode_paired_devices(
            &reply(PAIRED_DEVICES, "empty"),
            "fed-computer:648aa5c579fb30f38af744d97d6ec840"
        ),
        Lookup::Absent
    );
}

#[test]
fn paired_devices_refusals_never_read_as_a_pairing() {
    for name in ["wrong_caller", "nonempty_params", "missing_params"] {
        let refusal = reply(PAIRED_DEVICES, name);
        assert_eq!(
            decode_paired_devices(&refusal, "fed-computer:648aa5c579fb30f38af744d97d6ec840"),
            Lookup::Absent,
            "case {name}"
        );
        assert_eq!(
            decode_self_member(&refusal),
            Lookup::Unavailable,
            "case {name}"
        );
    }
}

#[test]
fn callosums_short_transfer_key_is_refused_and_a_64_hex_key_is_accepted() {
    let member = "fed-computer:72cd6e8422c407fb6d098690f1130b7d";
    // Callosum only bounds-checks `pub`, so its fixture announces a 4-hex key. The vault
    // must not treat that as a usable X25519 key.
    let mut full = reply(PEER_KEYS, "all_optional_fields");
    assert_eq!(
        full["peers"][0]["key_record"]["keys"]["vault_transfer_x25519"]["pub"],
        "cc03"
    );
    assert_eq!(decode_peer_transfer_key(&full, member), Lookup::Absent);

    // Control: the same reply with a real 64-hex key decodes, so the refusal above is the
    // length rule and not a decoder that can never answer.
    let key = "11".repeat(32);
    full["peers"][0]["key_record"]["keys"]["vault_transfer_x25519"]["pub"] = Value::from(key);
    match decode_peer_transfer_key(&full, member) {
        Lookup::Found(peer) => assert_eq!(peer.public, [0x11; 32]),
        other => panic!("a 64-hex transfer key must decode, got {other:?}"),
    }
}

#[test]
fn peer_keys_without_a_transfer_key_and_not_ready_are_classified() {
    let member = "fed-computer:72cd6e8422c407fb6d098690f1130b7d";
    for name in [
        "empty",
        "non_vault_filters_transfer",
        "non_vault_omits_empty_record",
        "no_optional_fields",
    ] {
        assert_eq!(
            decode_peer_transfer_key(&reply(PEER_KEYS, name), member),
            Lookup::Absent,
            "case {name}"
        );
    }
    assert_eq!(
        decode_peer_transfer_key(&reply(PEER_KEYS, "fed_not_ready"), member),
        Lookup::Unavailable
    );
}

macro_rules! sharing_fixture {
    ($name:ident, $members:expr, $enabled:expr) => {
        #[test]
        fn $name() {
            let body = reply(PAIRED_DEVICES, stringify!($name));
            let body = body.get("notices").map_or(&body, |notices| &notices[0]);
            let decoded = claustrum_module_probe::federation::sharing::decode_snapshot(body);
            match $members {
                Some(count) => {
                    let decoded = decoded.expect("published snapshot must decode");
                    assert_eq!(decoded.members.len(), count);
                    assert_eq!(decoded.enabled, $enabled);
                    if count != 0 {
                        assert_eq!(
                            decoded.members[0].member_id,
                            "fed-computer:648aa5c579fb30f38af744d97d6ec840"
                        );
                        assert_eq!(
                            decoded.members[0].pairing_id,
                            "11111111-2222-4333-8444-555555555555:3"
                        );
                    }
                }
                None => assert!(decoded.is_none(), "refusal is not an empty snapshot"),
            }
        }
    };
}

sharing_fixture!(empty, Some(0), false);
sharing_fixture!(all_classes, Some(1), true);
sharing_fixture!(occipital_caller, None::<usize>, false);
sharing_fixture!(wrong_caller, None::<usize>, false);
sharing_fixture!(nonempty_params, None::<usize>, false);
sharing_fixture!(missing_params, None::<usize>, false);
sharing_fixture!(watch_initial, Some(1), true);
sharing_fixture!(watch_wrong_caller, None::<usize>, false);
sharing_fixture!(watch_occipital, None::<usize>, false);
sharing_fixture!(watch_missing_caller, None::<usize>, false);
sharing_fixture!(watch_nonempty_params, None::<usize>, false);
sharing_fixture!(watch_missing_params, None::<usize>, false);
sharing_fixture!(watch_bad_params_before_caller, None::<usize>, false);
sharing_fixture!(watch_not_ready, None::<usize>, false);

#[test]
fn the_vendored_snapshot_and_peer_watch_vectors_are_the_bytes_callosum_published() {
    for (bytes, checksum) in [
        (
            PAIRED_DEVICES_V2,
            "118d4257915d6bbaa82c496e57f41dd84522f128ac406e2012d5dc14f7964102",
        ),
        (
            include_bytes!("../fixtures/callosum/paired-devices-v2/README.md").as_slice(),
            "e05047504fc4d4bdf8c83efbfe617261638621848cc82fd809232f17ef036522",
        ),
        (
            include_bytes!("../fixtures/callosum/paired-devices-v2/SHA256SUMS").as_slice(),
            "f8bd11a8ee65c2c214c7c8da28313245b040c010e58b2979839c6cd576109097",
        ),
        (
            PEER_KEYS_V3,
            "b5243386c46b0551c21f24f45dd696fb8edaa2dcb260b71e0d4f7da7e880979c",
        ),
        (
            include_bytes!("../fixtures/callosum/peer-keys-v3/README.md").as_slice(),
            "eaecef1ceec27a38bc542de7f17c71db7f368725dbc6b528f8107d985dfbd2ea",
        ),
        (
            include_bytes!("../fixtures/callosum/peer-keys-v3/SHA256SUMS").as_slice(),
            "d9a3774670b45e1a81f69b738564fa0a5496d6de0b145477a6aa799ebfc71d16",
        ),
        (
            PEER_KEYS_WATCH_V1,
            "11e987c87f461a3179ff096b1ccd457dab74ff2327e09eac6b754df762811ecd",
        ),
        (
            include_bytes!("../fixtures/callosum/peer-keys-watch-v1/README.md").as_slice(),
            "4e4e890b5a984a70e5ec72c7f5c565da1cfe4a981e20fd7bc2dbd77524d5ea28",
        ),
        (
            include_bytes!("../fixtures/callosum/peer-keys-watch-v1/SHA256SUMS").as_slice(),
            "9bd33a0c087a164505369b04d104e349d5b08739e7a678f6554f082edab522e5",
        ),
    ] {
        assert_eq!(sha256_hex(bytes), checksum, "must match VENDORED.md");
    }
}

fn expected_tombstones() -> Vec<SharingTombstone> {
    [
        (
            "fed-computer:72cd6e8422c407fb6d098690f1130b7d",
            "1000:permanent:2",
        ),
        ("fed-computer:75877bb41d393b5fb8455ce60ecd8dda", "2000:5:3"),
        ("fed-computer:f849d67325facf04177bc663b2dc5440", "3000:7:4"),
    ]
    .into_iter()
    .map(|(member_id, removal_id)| SharingTombstone {
        member_id: member_id.to_string(),
        removal_id: removal_id.to_string(),
    })
    .collect()
}

#[test]
fn every_paired_devices_v2_case_decodes_through_the_sharing_reader() {
    let file: Value = serde_json::from_slice(PAIRED_DEVICES_V2).unwrap();
    let cases = file["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 16);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let body = &case["reply"];
        let body = body.get("notices").map_or(body, |notices| {
            assert_eq!(notices.as_array().unwrap().len(), 1, "{name}");
            &notices[0]
        });
        let decoded = decode_snapshot(body);
        match name {
            "empty" | "all_classes" | "watch_initial" | "tombstones" | "watch_tombstones" => {
                let decoded = decoded.unwrap_or_else(|| panic!("snapshot {name} must decode"));
                assert_eq!(
                    decode_self_member(body),
                    Lookup::Found(FIXTURE_SELF_MEMBER.to_string())
                );
                assert_eq!(decoded.enabled, name != "empty", "{name}");
                assert_eq!(
                    decoded.members.len(),
                    usize::from(name != "empty"),
                    "{name}"
                );
                if name != "empty" {
                    assert_eq!(
                        decoded.members[0].member_id,
                        "fed-computer:648aa5c579fb30f38af744d97d6ec840"
                    );
                    assert_eq!(
                        decoded.members[0].pairing_id,
                        "11111111-2222-4333-8444-555555555555:3"
                    );
                }
                let tombstones = if matches!(name, "tombstones" | "watch_tombstones") {
                    expected_tombstones()
                } else {
                    Vec::new()
                };
                assert_eq!(decoded.tombstones, tombstones, "{name}");
            }
            _ => {
                assert!(body["code"].is_string(), "{name} must be a refusal");
                assert!(decoded.is_none(), "{name} is not an empty snapshot");
            }
        }
    }
}

#[test]
fn every_peer_keys_v3_case_decodes_through_the_transfer_reader() {
    let file: Value = serde_json::from_slice(PEER_KEYS_V3).unwrap();
    let cases = file["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 14);
    let member = "fed-computer:72cd6e8422c407fb6d098690f1130b7d";
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let body = &case["reply"];
        if name == "fed_not_ready" {
            assert_eq!(decode_peer_transfer_key(body, member), Lookup::Unavailable);
            continue;
        }
        // The published keys are deliberately too short for X25519, even when
        // the reply also carries fleet or bus keys. None is a usable transfer key.
        assert_eq!(
            decode_peer_transfer_key(body, member),
            Lookup::Absent,
            "{name}"
        );
        if matches!(
            name,
            "all_optional_fields"
                | "vault_sees_fleet_keys_and_pairing_identity"
                | "vault_sees_bus_and_fleet_keys"
        ) {
            let mut usable = body.clone();
            usable["peers"][0]["key_record"]["keys"]["vault_transfer_x25519"]["pub"] =
                json!("11".repeat(32));
            match decode_peer_transfer_key(&usable, member) {
                Lookup::Found(key) => assert_eq!(key.public, [0x11; 32], "{name}"),
                other => panic!(
                    "{name}: unrelated fleet/bus kinds must not hide the transfer key: {other:?}"
                ),
            }
        }
    }
}

#[test]
fn every_v1_5_snapshot_has_unchanged_sharing_without_tombstones() {
    let file: Value = serde_json::from_slice(PAIRED_DEVICES).unwrap();
    let mut successes = 0;
    for case in file["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let body = &case["reply"];
        let body = body.get("notices").map_or(body, |notices| &notices[0]);
        assert!(body.get("tombstones").is_none(), "{name}");
        let legacy = decode_snapshot(body);
        let mut explicit = body.clone();
        explicit["tombstones"] = json!([]);
        let explicit = decode_snapshot(&explicit);
        assert_eq!(legacy.is_some(), explicit.is_some(), "{name}");
        if let (Some(legacy), Some(explicit)) = (legacy, explicit) {
            successes += 1;
            assert!(legacy.tombstones.is_empty(), "{name}");
            assert!(explicit.tombstones.is_empty(), "{name}");
            assert_eq!(legacy.enabled, explicit.enabled, "{name}");
            assert_eq!(legacy.devices, explicit.devices, "{name}");
            assert_eq!(legacy.computers, explicit.computers, "{name}");
            let members =
                |snapshot: &claustrum_module_probe::federation::sharing::VaultSharingSnapshot| {
                    snapshot
                        .members
                        .iter()
                        .map(|m| (m.member_id.clone(), m.pairing_id.clone()))
                        .collect::<Vec<_>>()
                };
            assert_eq!(members(&legacy), members(&explicit), "{name}");
        }
    }
    assert_eq!(successes, 3);
}

#[test]
fn tombstones_are_sorted_and_removal_ids_are_opaque() {
    let mut body = reply(PAIRED_DEVICES_V2, "tombstones");
    body["tombstones"].as_array_mut().unwrap().reverse();
    body["tombstones"][2]["removal_id"] = json!(" opaque id:é\n");
    // A removed key may still be listed in the roster, regardless of its class.
    body["devices"][1]["fingerprint"] = json!("72cd6e8422c407fb6d098690f1130b7d");
    let decoded = decode_snapshot(&body).expect("opaque removal ids and roster overlap are valid");
    let mut expected = expected_tombstones();
    expected[0].removal_id = " opaque id:é\n".to_string();
    assert_eq!(decoded.tombstones, expected);
}

#[test]
fn malformed_tombstones_invalidate_the_entire_snapshot() {
    let valid = reply(PAIRED_DEVICES_V2, "tombstones");
    let tombstone = valid["tombstones"][0].clone();
    let mut cases = vec![
        Value::Null,
        json!({}),
        json!("not a list"),
        json!([null]),
        json!(["not an entry"]),
        json!([{}]),
        json!([{"fingerprint": tombstone["fingerprint"]}]),
        json!([{"removal_id": "present"}]),
    ];
    for fingerprint in [
        json!(null),
        json!(42),
        json!(""),
        json!("a".repeat(31)),
        json!("a".repeat(33)),
        json!("A".repeat(32)),
        json!("g".repeat(32)),
    ] {
        let mut entry = tombstone.clone();
        entry["fingerprint"] = fingerprint;
        cases.push(json!([entry]));
    }
    for removal_id in [
        json!(null),
        json!(false),
        json!(42),
        json!({}),
        json!([]),
        json!(""),
    ] {
        let mut entry = tombstone.clone();
        entry["removal_id"] = removal_id;
        cases.push(json!([entry]));
    }
    cases.push(json!([tombstone.clone(), tombstone.clone()]));
    let mut different_removal = tombstone.clone();
    different_removal["removal_id"] = json!("different");
    cases.push(json!([tombstone.clone(), different_removal]));
    cases.push(json!([tombstone, {"fingerprint": "invalid", "removal_id": "present"}]));
    for tombstones in cases {
        let mut body = valid.clone();
        body["tombstones"] = tombstones;
        assert!(
            decode_snapshot(&body).is_none(),
            "invalid tombstones must not yield a partial snapshot: {body}"
        );
    }
}
