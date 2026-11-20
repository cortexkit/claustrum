use std::{fs, path::Path};

use base64::{engine::general_purpose::STANDARD, Engine};
use credentials_core::{
    hub_counters::{HubGeneration, HubReportSeq},
    kem,
    signing::{key_id_for_public, public_key_ed25519},
    store::{GhManifestVerdict, HubOwnReport},
};
use serde_json::{json, Value};

use super::{hub_logins, hub_manifest};

#[test]
fn hub_wire_samples_preserve_producer_bytes() {
    let home = "fed-computer:01010101010101010101010101010101";
    let member = "fed-computer:02020202020202020202020202020202";
    let home_box = "11111111111111111111111111111111";
    let member_box = "22222222222222222222222222222222";
    // Fixed test-only keys, deliberately unrelated to either machine id.
    let home_pem = kem::pem_from_scalar(&[17; 32]);
    let recipient_scalar = [23; 32];
    let recipient_pem = kem::pem_from_scalar(&recipient_scalar);
    let home_public: [u8; 32] = kem::public_half(&home_pem).unwrap().0.try_into().unwrap();
    let recipient_public: [u8; 32] = kem::public_half(&recipient_pem)
        .unwrap()
        .0
        .try_into()
        .unwrap();
    let aad = hub_logins::LoginAad {
        home: home.into(),
        member: member.into(),
        home_box: home_box.into(),
        member_box: member_box.into(),
        generation: HubGeneration::new(i64::MAX).unwrap(),
        sender_key_id: key_id_for_public(&home_public),
        recipient_key_id: key_id_for_public(&recipient_public),
    };
    let logins = json!({"kind":"snapshot","logins":[{
        "credential_id":"oauth:example", "state":"active", "refresh_adapter":"test",
        "identity":{}, "categories":[], "provider_ids":[], "detected_plan":null, "home_version":1,
    }]});
    let plaintext = serde_json::to_vec(&logins).unwrap();
    let new_seal: hub_logins::LoginEnvelope = serde_json::from_slice(
        &hub_logins::seal(&aad, &home_pem, &recipient_public, &plaintext).unwrap(),
    )
    .unwrap();

    // RFC 8410 PKCS#8 v1 wrapping a fixed, test-only Ed25519 seed.
    let mut der = vec![
        0x30, 0x2e, 2, 1, 0, 0x30, 5, 6, 3, 0x2b, 0x65, 0x70, 4, 0x22, 4, 0x20,
    ];
    der.extend_from_slice(&[19; 32]);
    let record_pem = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        STANDARD.encode(der)
    );
    let report = HubOwnReport {
        version: 29,
        payload_sha256: "a".repeat(64),
        verdict: GhManifestVerdict::Invalid,
        reason: Some("private test diagnosis, not on the hub".into()),
    };
    let signed = String::from_utf8(
        hub_manifest::seal(
            &report,
            home_box,
            home,
            HubReportSeq::new(9_007_199_254_740_991).unwrap(),
            &record_pem,
        )
        .unwrap(),
    )
    .unwrap();
    let record_public = public_key_ed25519(&record_pem).unwrap().public_key_hex;

    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/hub-wire-v1/samples.json");
    if std::env::var_os("CK_EMIT_HUB_WIRE_SAMPLES").as_deref() == Some("1".as_ref()) {
        let sample = json!({
            "login": {
                "key":format!("{home_box}.{member_box}"),
                "value":serde_json::to_string(&new_seal).unwrap(),
                "sender_public_b64":STANDARD.encode(home_public),
                "recipient_private_b64":STANDARD.encode(recipient_scalar),
                "plaintext":String::from_utf8(plaintext.clone()).unwrap(),
            },
            "manifest": {"key":home_box, "value":signed, "writer_public_hex":record_public},
        });
        fs::write(&path, serde_json::to_string_pretty(&sample).unwrap() + "\n").unwrap();
    }
    let sample: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    let login = &sample["login"];
    assert_eq!(login["key"], format!("{home_box}.{member_box}"));
    assert_eq!(login["sender_public_b64"], STANDARD.encode(home_public));
    assert_eq!(
        login["recipient_private_b64"],
        STANDARD.encode(recipient_scalar)
    );
    assert_eq!(login["plaintext"].as_str().unwrap().as_bytes(), plaintext);
    let envelope: hub_logins::LoginEnvelope =
        serde_json::from_str(login["value"].as_str().unwrap()).unwrap();
    assert_eq!(envelope.v, new_seal.v);
    assert_eq!(envelope.aad, new_seal.aad);
    assert_eq!(
        kem::open_hub_logins(
            &recipient_pem,
            &home_public,
            &STANDARD.decode(&envelope.enc_b64).unwrap(),
            &STANDARD.decode(&envelope.ciphertext_b64).unwrap(),
            envelope.aad.as_bytes(),
        )
        .unwrap(),
        plaintext
    );
    assert_eq!(
        sample["manifest"],
        json!({"key":home_box, "value":signed, "writer_public_hex":record_public})
    );
}
