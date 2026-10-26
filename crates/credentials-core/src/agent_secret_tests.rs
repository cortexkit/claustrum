use super::*;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn api_scope() -> SecretScope {
    SecretScope::ApiKey {
        host: "x.test".into(),
        path_prefix: Some("/v1".into()),
        location: "header:X-Key".into(),
    }
}
fn api_material() -> SecretMaterial {
    SecretMaterial::ApiKey(Secret::new(b"key".to_vec()))
}

#[test]
fn names_accept_64_bytes_and_refuse_65_and_forbidden_bytes() {
    assert_eq!(validate_name(&"a".repeat(64)), Ok(()));
    assert_eq!(
        validate_name(&"a".repeat(65)),
        Err(ValidationError::LimitExceeded)
    );
    assert_eq!(ValidationError::LimitExceeded.wire_code(), "limit_exceeded");
    for name in [
        "",
        "a b",
        "a|b",
        "a\0",
        "a\n",
        "aé",
        "a\u{202e}",
        ".a",
        "_a",
        "-a",
    ] {
        assert_eq!(
            validate_name(name),
            Err(ValidationError::InvalidParams),
            "{name:?}"
        );
    }
    for byte in 0u8..=127 {
        let name = format!("a{}", char::from(byte));
        let valid = byte.is_ascii_alphanumeric() || b"._-".contains(&byte);
        assert_eq!(validate_name(&name).is_ok(), valid, "byte {byte}");
    }
    assert_eq!(validate_name("0Az._-"), Ok(()));
    assert_eq!(ValidationError::InvalidParams.wire_code(), "invalid_params");
}

#[test]
fn binary_layouts_binding_and_digest_are_known_answers() {
    let aad = deposit_aad(
        "01ARZ3NDEKTSV4RRFFQ69G5FAV",
        "fed-computer:00000000000000000000000000000000",
        "Example",
        &api_scope(),
    )
    .unwrap();
    assert_eq!(hex(&aad), "1800000000000000636b2d7365637265742d6465706f7369742d6161642f76311a00000000000000303141525a334e44454b545356345252464651363947354641562d000000000000006665642d636f6d70757465723a303030303030303030303030303030303030303030303030303030303030303007000000000000004578616d706c650d000000000000006167656e745f6170695f6b65790600000000000000782e7465737403000000000000002f76310c000000000000006865616465723a582d4b6579");
    assert_eq!(hex(deposit_plaintext(&api_material()).expose()), "1e00000000000000636b2d7365637265742d6465706f7369742d706c61696e746578742f763103000000000000006b6579");
    assert_eq!(hex(sealed_body(&api_scope(), &api_material()).unwrap().expose()), "1800000000000000636b2d7365637265742d7365616c65642d626f64792f76310d000000000000006167656e745f6170695f6b65790600000000000000782e7465737403000000000000002f76310c000000000000006865616465723a582d4b657903000000000000006b6579");
    assert_eq!(
        record_binding(
            "agent_api_key",
            "0123456789abcdef0123456789abcdef",
            "Example"
        )
        .unwrap(),
        "secret|agent_api_key|0123456789abcdef0123456789abcdef|Example"
    );
    assert_eq!(
        hex(&deposit_digest(
            "01ARZ3NDEKTSV4RRFFQ69G5FAV",
            b"enc",
            b"ciphertext",
            &aad
        )),
        "808f633951b48d3a328aafce1c556feb2f12f3921e4dd081416b642797aaada6"
    );

    let scope = SecretScope::SiteLogin {
        origin: format!("{}://x.test", "https"),
    };
    let material = SecretMaterial::SiteLogin {
        username: Secret::new("user".into()),
        password: Secret::new("pass".into()),
        otpauth: None,
    };
    let aad = deposit_aad(
        "01ARZ3NDEKTSV4RRFFQ69G5FAV",
        "fed-computer:00000000000000000000000000000000",
        "Example",
        &scope,
    )
    .unwrap();
    assert_eq!(hex(&aad), "1800000000000000636b2d7365637265742d6465706f7369742d6161642f76311a00000000000000303141525a334e44454b545356345252464651363947354641562d000000000000006665642d636f6d70757465723a303030303030303030303030303030303030303030303030303030303030303007000000000000004578616d706c650a00000000000000736974655f6c6f67696e0e0000000000000068747470733a2f2f782e74657374");
    assert_eq!(hex(deposit_plaintext(&material).expose()), "1e00000000000000636b2d7365637265742d6465706f7369742d706c61696e746578742f76310400000000000000757365720400000000000000706173730000000000000000");
    assert_eq!(hex(sealed_body(&scope, &material).unwrap().expose()), "1800000000000000636b2d7365637265742d7365616c65642d626f64792f76310a00000000000000736974655f6c6f67696e0e0000000000000068747470733a2f2f782e746573740400000000000000757365720400000000000000706173730000000000000000");
    assert_eq!(
        hex(&deposit_digest(
            "01ARZ3NDEKTSV4RRFFQ69G5FAV",
            b"enc",
            b"ciphertext",
            &aad
        )),
        "2c597816eda2b25fbcd4f92b3da643097e8218210cd8804a153edcd9a9e7b781"
    );
}

#[test]
fn sealing_binds_name_incarnation_kind_and_scope_before_material() {
    let key = MasterKey::from_bytes([12; 32]);
    let incarnation = "0123456789abcdef0123456789abcdef";
    let scope = api_scope();
    let material = api_material();
    let blob = seal(&key, incarnation, "Example", &scope, &material).unwrap();
    assert_eq!(
        open(&key, incarnation, "Example", &scope, &blob).unwrap(),
        material
    );
    assert!(open(&key, incarnation, "Other", &scope, &blob).is_err());
    assert!(
        open(
            &key,
            "1123456789abcdef0123456789abcdef",
            "Example",
            &scope,
            &blob
        )
        .is_err(),
        "a different incarnation must not open a sealed secret"
    );
    for altered in [
        SecretScope::ApiKey {
            host: "other.test".into(),
            path_prefix: Some("/v1".into()),
            location: "header:X-Key".into(),
        },
        SecretScope::ApiKey {
            host: "x.test".into(),
            path_prefix: None,
            location: "header:X-Key".into(),
        },
        SecretScope::ApiKey {
            host: "x.test".into(),
            path_prefix: Some("/v1".into()),
            location: "authorization_bearer".into(),
        },
        SecretScope::SiteLogin {
            origin: format!("{}://x.test", "https"),
        },
    ] {
        assert!(open(&key, incarnation, "Example", &altered, &blob).is_err());
    }
    let missing_location = SecretScope::ApiKey {
        host: "x.test".into(),
        path_prefix: None,
        location: String::new(),
    };
    assert!(seal(&key, incarnation, "Example", &missing_location, &material).is_err());
    assert!(deposit_aad("id", "member", "Example", &missing_location).is_err());
}

#[test]
fn plaintext_decoder_refuses_truncation_trailing_bytes_and_wrong_kind() {
    let encoded = deposit_plaintext(&api_material());
    assert_eq!(
        decode_deposit_plaintext("agent_api_key", &encoded).unwrap(),
        api_material()
    );
    for end in 0..encoded.expose().len() {
        assert!(decode_deposit_plaintext(
            "agent_api_key",
            &Secret::new(encoded.expose()[..end].to_vec())
        )
        .is_err());
    }
    let mut extra = encoded.expose().clone();
    extra.push(0);
    assert!(decode_deposit_plaintext("agent_api_key", &Secret::new(extra)).is_err());
    assert!(decode_deposit_plaintext("site_login", &encoded).is_err());
    assert_eq!(format!("{:?}", api_material()), "ApiKey(<redacted>)");
}

#[test]
fn the_deposit_namespace_excludes_the_secret_target_form() {
    // The operator's delete and put address `secret|<name>` targets, where a secret name
    // can never contain `|`. The reserved deposit key must therefore sit outside the
    // predicate, or an operator delete could reach the vault's own deposit key.
    asserting_deposit_namespace();
}

fn asserting_deposit_namespace() {
    assert!(is_deposit_key(DEPOSIT_KEY_ID));
    assert!(is_deposit_key("kem:secret-deposit:2"));
    assert!(!is_deposit_key("kem:secret-deposit:|ops-key"));
    assert!(!is_deposit_key("kem:vault-transfer:1"));
}
