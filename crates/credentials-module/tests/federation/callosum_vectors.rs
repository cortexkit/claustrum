//! The vault's decoders for callosum's two discovery replies, checked against callosum's
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
use serde_json::Value;
use sha2::{Digest, Sha256};

const PAIRED_DEVICES: &[u8] = include_bytes!("../fixtures/callosum/paired-devices/cases.json");
const PEER_KEYS: &[u8] = include_bytes!("../fixtures/callosum/peer-keys/cases.json");

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
        "9f0b260a7476c468f3816031073d18de1925c94c052bfc9083af845d56749a93",
        "paired-devices vectors must match VENDORED.md"
    );
    assert_eq!(
        sha256_hex(PEER_KEYS),
        "8b23d3ab3a9827e4d83584ca441ea84201979ca61cbcbf1560be0fca320ef805",
        "peer-keys vectors must match VENDORED.md"
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
