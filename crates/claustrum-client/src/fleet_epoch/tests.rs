use super::*;
use serde_json::{json, Value};

#[derive(Deserialize)]
struct Samples<'a> {
    #[serde(borrow)]
    seal_open: SealOpenSample<'a>,
    #[serde(borrow)]
    batch: Exchange<'a>,
}

#[derive(Deserialize)]
struct SealOpenSample<'a> {
    #[serde(borrow)]
    response: &'a RawValue,
    #[serde(borrow)]
    open_response: &'a RawValue,
    #[serde(borrow)]
    cross_domain_open: RefusedOpen<'a>,
}

#[derive(Deserialize)]
struct RefusedOpen<'a> {
    #[serde(borrow)]
    response: &'a RawValue,
}

#[derive(Deserialize)]
struct Exchange<'a> {
    #[serde(borrow)]
    response: &'a RawValue,
    #[serde(borrow)]
    open_response: &'a RawValue,
}

fn vectors(caller: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../credentials-module/tests/fixtures")
        .join(format!("fleet-epoch-{caller}-v1/cases.json"));
    std::fs::read(path).expect("tagged fleet epoch vectors must be available in the checkout")
}

fn reply(body: &RawValue) -> Secret<Vec<u8>> {
    // The tagged fixtures store producer bodies; the daemon puts them under result.
    Secret::new([b"{\"result\":".as_slice(), body.get().as_bytes(), b"}"].concat())
}

#[test]
fn fleet_epoch_open_decodes_tagged_plaintext() {
    for (caller, expected) in [
        ("magic-context", b"first memory change".as_slice()),
        ("prefrontal", b"room event body".as_slice()),
    ] {
        let bytes = vectors(caller);
        let sample: Samples<'_> = serde_json::from_slice(&bytes).unwrap();
        let plaintext =
            decode_fleet_epoch_open_reply(reply(sample.seal_open.open_response).expose()).unwrap();
        assert_eq!(plaintext.expose(), expected);
    }
}

#[test]
fn fleet_epoch_seal_and_batch_decoders_read_both_tagged_samples() {
    fn assert_seal(sealed: &FleetEpochSeal, expected: &Value) {
        assert_eq!(sealed.epoch, 1);
        assert_eq!(URL_SAFE_NO_PAD.encode(sealed.nonce), expected["nonce"]);
        assert_eq!(
            URL_SAFE_NO_PAD.encode(&sealed.ciphertext),
            expected["ciphertext"]
        );
    }

    for caller in ["magic-context", "prefrontal"] {
        let bytes = vectors(caller);
        let sample: Samples<'_> = serde_json::from_slice(&bytes).unwrap();
        let body = sample.seal_open.response;
        let sealed = decode_fleet_epoch_seal_reply(reply(body).expose()).unwrap();
        assert_seal(&sealed, &serde_json::from_str(body.get()).unwrap());

        let batch =
            decode_fleet_epoch_seal_batch_reply(reply(sample.batch.response).expose()).unwrap();
        let expected: Value = serde_json::from_str(sample.batch.response.get()).unwrap();
        assert_eq!(batch.len(), 2);
        for (i, sealed) in batch.iter().enumerate() {
            assert_seal(sealed, &expected["items"][i]);
        }

        let opened =
            decode_fleet_epoch_open_batch_reply(reply(sample.batch.open_response).expose())
                .unwrap();
        assert_eq!(opened.len(), 2);
        if caller == "magic-context" {
            assert_eq!(opened[0].as_ref().unwrap().expose(), b"first memory change");
            assert_eq!(
                opened[1].as_ref().unwrap().expose(),
                b"second memory change"
            );
        } else {
            assert_eq!(opened[0].as_ref().unwrap().expose(), b"room event body");
            let error = opened[1].as_ref().unwrap_err();
            assert_eq!(error.code(), "fleet_epoch_open_failed");
            assert_eq!(error.class, CredentialErrorClass::Permanent);
        }
        let error = decode_fleet_epoch_open_reply(
            reply(sample.seal_open.cross_domain_open.response).expose(),
        )
        .unwrap_err();
        assert_eq!(error.code(), "fleet_epoch_open_failed");
        assert_eq!(error.class, CredentialErrorClass::Permanent);
    }
}

#[test]
fn fleet_epoch_refusals_keep_wire_code_and_class() {
    for (wire_class, class, codes) in [
        (
            "transient",
            CredentialErrorClass::Transient,
            &[
                "fleet_epoch_unavailable",
                "fleet_epoch_pending",
                "fleet_peer_keys_unavailable",
                "store_error",
            ][..],
        ),
        (
            "permanent",
            CredentialErrorClass::Permanent,
            &[
                "not_found",
                "fleet_members_mismatch",
                "fleet_epoch_not_pending",
                "fleet_epoch_open_failed",
                "fleet_wrap_refused",
                "fleet_epoch_capacity",
                "corrupt",
            ][..],
        ),
    ] {
        for code in codes {
            let refusal = json!({"error":{"code":code,"class":wire_class}});
            let bytes = serde_json::to_vec(&json!({"result":refusal})).unwrap();
            for error in [
                decode_fleet_epoch_seal_reply(&bytes).unwrap_err(),
                decode_fleet_epoch_open_reply(&bytes).unwrap_err(),
                decode_fleet_epoch_seal_batch_reply(&bytes).unwrap_err(),
                decode_fleet_epoch_open_batch_reply(&bytes).unwrap_err(),
            ] {
                assert_eq!(error.code(), *code);
                assert_eq!(error.class, class);
            }
            let mixed =
                serde_json::to_vec(&json!({"result":{"items":[refusal,{"plaintext":"_w"}]}}))
                    .unwrap();
            let items = decode_fleet_epoch_open_batch_reply(&mixed).unwrap();
            assert_eq!(items[0].as_ref().unwrap_err().code(), *code);
            assert_eq!(items[0].as_ref().unwrap_err().class, class);
            assert_eq!(items[1].as_ref().unwrap().expose(), &[255]);
        }
    }
    let invalid_params = crate::decode_established_route_wire_error(
        subc_protocol::Flags(0),
        br#"{"code":"invalid_params","message":"params not decodable: invalid fleet parameters"}"#,
    );
    assert_eq!(invalid_params.code(), "invalid_params");
    assert_eq!(invalid_params.class, CredentialErrorClass::Unclassified);
}

#[test]
fn fleet_epoch_open_rejects_malformed_item_without_returning_other_slots() {
    for item in [
        r#"{"plaintext":"/w"}"#,
        r#"{"plaintext":"_w=="}"#,
        r#"{"plaintext":"_x"}"#,
        r#"{"plaintext":"_\u0077"}"#,
        r#"{"plaintext":[255]}"#,
        r#"{"plaintext":"_w","error":{"code":"not_found","class":"permanent"}}"#,
        r#"{"error":{"code":"not_found"}}"#,
        r#"{"error":{"code":"not_found","class":"permanent","message":"unexpected"}}"#,
    ] {
        let bytes = format!(r#"{{"result":{{"items":[{{"plaintext":"_w"}},{item}]}}}}"#);
        let error = decode_fleet_epoch_open_batch_reply(bytes.as_bytes()).unwrap_err();
        assert_eq!(error.class, CredentialErrorClass::InvalidResponse);
    }
}

#[test]
fn fleet_epoch_batch_count_boundaries_match_the_vault() {
    let plaintext = Secret::new(Vec::new());
    let seal = FleetEpochSealRequest {
        aad: &[],
        plaintext: &plaintext,
    };
    let open = FleetEpochOpenRequest {
        epoch: 1,
        nonce: &[0; 24],
        ciphertext: &[0; 16],
        aad: &[],
    };
    for (count, accepted) in [(0, false), (1, true), (256, true), (257, false)] {
        for (method, encoded) in [
            (
                "fleet.epoch_seal_batch",
                request::seal_batch(&vec![seal; count]),
            ),
            (
                "fleet.epoch_open_batch",
                request::open_batch(&vec![open; count]),
            ),
        ] {
            if accepted {
                let bytes = encoded.unwrap();
                let value: Value = serde_json::from_slice(bytes.expose()).unwrap();
                assert_eq!(value["method"], method);
                assert_eq!(value["params"]["items"].as_array().unwrap().len(), count);
            } else {
                assert_eq!(encoded.unwrap_err().code(), "invalid_params");
            }
        }
        let bytes =
            serde_json::to_vec(&json!({"result":{"items":vec![json!({"plaintext":""}); count]}}))
                .unwrap();
        assert_eq!(
            decode_fleet_epoch_open_batch_reply(&bytes).is_ok(),
            accepted
        );
    }
}

#[test]
fn fleet_epoch_plaintext_is_absent_from_request_and_reply_debug() {
    let canary = b"fleet-plaintext-canary";
    let input = Secret::new(canary.to_vec());
    let seal = FleetEpochSealRequest {
        aad: b"record",
        plaintext: &input,
    };
    let wire = request::seal(seal).unwrap();
    let encoded = URL_SAFE_NO_PAD.encode(canary);
    let reply = Secret::new(
        serde_json::to_vec(&json!({"result":{"items":[{"plaintext":encoded}]}})).unwrap(),
    );
    let output = decode_fleet_epoch_open_batch_reply(reply.expose()).unwrap();
    assert_eq!(output[0].as_ref().unwrap().expose(), canary);
    for debug in [
        format!("{seal:?}"),
        format!("{wire:?}"),
        format!("{reply:?}"),
        format!("{output:?}"),
    ] {
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains(std::str::from_utf8(canary).unwrap()));
        assert!(!debug.contains(&encoded));
        assert!(!debug.contains(&format!("{canary:?}")));
    }
}

#[test]
fn fleet_epoch_single_requests_use_canonical_base64url() {
    let plaintext = Secret::new(vec![0xff, 0xff]);
    let seal = request::seal(FleetEpochSealRequest {
        aad: &[0xfb],
        plaintext: &plaintext,
    })
    .unwrap();
    let open = request::open(FleetEpochOpenRequest {
        epoch: 17,
        nonce: &[0xff; 24],
        ciphertext: &[0xfb],
        aad: &[],
    })
    .unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(seal.expose()).unwrap(),
        json!({"method":"fleet.epoch_seal","params":{"aad":"-w","plaintext":"__8"}})
    );
    assert_eq!(
        serde_json::from_slice::<Value>(open.expose()).unwrap(),
        json!({"method":"fleet.epoch_open","params":{"epoch":17,"nonce":"_".repeat(32),"ciphertext":"-w","aad":""}})
    );
}
