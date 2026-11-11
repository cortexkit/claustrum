use super::*;
use serde_json::{json, Value};

// A synthetic payload with the live v28 top-level order and deliberately
// non-alphabetical nested objects; it is not a copy of the signed live payload.
const V28: &[u8] = include_bytes!("../tests/fixtures/gh-manifest-v28.json");

#[test]
fn v28_fixture_roundtrips_in_insertion_order_byte_identically() {
    let value: ManifestValue = serde_json::from_slice(V28).unwrap();
    let mut serialized = serde_json::to_vec_pretty(&value).unwrap();
    serialized.push(b'\n');
    assert_eq!(serialized, V28);
    let manifest = GhManifest::parse_reproducible(V28).unwrap();
    assert_eq!(manifest.to_bytes(), V28);
    let ManifestValue::Object(entries) = manifest.value() else {
        panic!("manifest must be an object");
    };
    assert_eq!(
        entries
            .iter()
            .map(|(key, _)| key.as_str())
            .collect::<Vec<_>>(),
        [
            "artifact_id",
            "manifest_version",
            "schema_floor",
            "issued_at_unix_secs",
            "detectors",
            "tiers",
            "api_rules",
            "canonicalization",
            "repository_sections",
            "bindings",
            "worker_reads"
        ]
    );
    assert_eq!(
        manifest
            .bindings()
            .map(|(repo, _)| repo)
            .collect::<Vec<_>>(),
        ["Zulu/Existing", "Alpha/Other", "cortexkit/opencode-sidebar"]
    );
    assert!(std::str::from_utf8(&serialized)
        .unwrap()
        .contains("café 🦀"));
    assert!(!serialized.ends_with(b"\n\n"));
}

#[test]
fn reproducibility_refuses_changed_formatting_and_escaping() {
    let text = std::str::from_utf8(V28).unwrap();
    let compact =
        serde_json::to_vec(&serde_json::from_slice::<ManifestValue>(V28).unwrap()).unwrap();
    for bytes in [
        V28[..V28.len() - 1].to_vec(),
        [V28, b"\n"].concat(),
        compact,
        text.replace("é", "\\u00e9").into_bytes(),
        text.replace("\n", "\r\n").into_bytes(),
        text.replace("  ", "    ").into_bytes(),
    ] {
        let result = GhManifest::parse_reproducible(&bytes);
        assert!(
            matches!(result, Err(ManifestError::NotReproducible)),
            "{result:?}"
        );
    }
    assert_eq!(
        ManifestError::NotReproducible.to_string(),
        "not_reproducible"
    );
}

#[test]
fn duplicate_object_keys_and_invalid_build_fields_are_refused() {
    for bytes in [
        br#"{"manifest_version":28,"manifest_version":29}"#.as_slice(),
        br#"{"bindings":{"Owner/Repo":"a","Owner/Repo":"b"}}"#.as_slice(),
    ] {
        assert!(matches!(
            GhManifest::parse_reproducible(bytes),
            Err(ManifestError::InvalidJson(_))
        ));
    }
    let text = std::str::from_utf8(V28).unwrap();
    for changed in [
        text.replace("\"manifest_version\": 28", "\"manifest_version\": 0"),
        text.replace("\"manifest_version\": 28", "\"manifest_version\": 28.0"),
        text.replace(
            "\"issued_at_unix_secs\": 1794355200",
            "\"issued_at_unix_secs\": null",
        ),
        text.replace(
            "\"Zulu/Existing\": \"agent_1111111111111111\"",
            "\"Zulu/Existing\": false",
        ),
    ] {
        assert!(matches!(
            GhManifest::parse_reproducible(changed.as_bytes()),
            Err(ManifestError::InvalidManifest(_))
        ));
    }
}

#[test]
fn build_next_changes_only_version_issue_time_and_one_last_binding() {
    let prior = GhManifest::parse_reproducible(V28).unwrap();
    // The installation lookup resolves a differently-cased proposal to full_name.
    let proposed_repo = "octo-owner/new-repo";
    let full_name = "Octo-Owner/New-Repo";
    assert_ne!(proposed_repo, full_name);
    assert!(proposed_repo.eq_ignore_ascii_case(full_name));
    let next = prior
        .build_next(full_name, "agent_4444444444444444", 1794355300)
        .unwrap();
    assert_eq!(next.version(), 29);
    assert_eq!(next.issued_at_unix_secs(), 1794355300);
    assert_eq!(
        next.bindings().last(),
        Some((full_name, "agent_4444444444444444"))
    );
    let before: Value = serde_json::from_slice(V28).unwrap();
    let after: Value = serde_json::from_slice(&next.to_bytes()).unwrap();
    let mut expected = before.clone();
    expected["manifest_version"] = json!(29);
    expected["issued_at_unix_secs"] = json!(1794355300);
    expected["bindings"][full_name] = json!("agent_4444444444444444");
    assert_eq!(after, expected);
    let expected_bytes = std::str::from_utf8(V28).unwrap()
        .replace("\"manifest_version\": 28", "\"manifest_version\": 29")
        .replace("\"issued_at_unix_secs\": 1794355200", "\"issued_at_unix_secs\": 1794355300")
        .replace("\"cortexkit/opencode-sidebar\": \"agent_3333333333333333\"\n",
            "\"cortexkit/opencode-sidebar\": \"agent_3333333333333333\",\n    \"Octo-Owner/New-Repo\": \"agent_4444444444444444\"\n");
    assert_eq!(next.to_bytes(), expected_bytes.as_bytes());
    assert_eq!(prior.to_bytes(), V28, "building does not mutate the base");
    let mut expected_bindings = prior.bindings().collect::<Vec<_>>();
    expected_bindings.push((full_name, "agent_4444444444444444"));
    assert_eq!(next.bindings().collect::<Vec<_>>(), expected_bindings);
    assert_eq!(
        GhManifest::parse_reproducible(&next.to_bytes()).unwrap(),
        next
    );
}

#[test]
fn build_next_never_overwrites_a_case_variant_binding_or_wraps_version() {
    let prior = GhManifest::parse_reproducible(V28).unwrap();
    assert!(matches!(
        prior.build_next("zulu/EXISTING", "other-agent", 1),
        Err(ManifestError::InvalidManifest(
            "repository is already bound"
        ))
    ));
    let maximum = std::str::from_utf8(V28).unwrap().replace(
        "\"manifest_version\": 28",
        &format!("\"manifest_version\": {}", i64::MAX),
    );
    let maximum = GhManifest::parse_reproducible(maximum.as_bytes()).unwrap();
    assert!(matches!(
        maximum.build_next("New/Repo", "agent", 1),
        Err(ManifestError::InvalidManifest("manifest_version overflow"))
    ));
}

fn sample_statement() -> ManifestBindingStatement {
    ManifestBindingStatement {
        v: MANIFEST_BINDING_STATEMENT_V1.to_owned(),
        proposal_id: "01JPROPOSAL".to_owned(),
        agent_id: "agent_4444444444444444".to_owned(),
        app_slug: "repo-bot".to_owned(),
        repo: "Octo-Owner/New-Repo".to_owned(),
        installation_permissions: BTreeMap::from([
            ("pull_requests".to_owned(), "write".to_owned()),
            ("metadata".to_owned(), "read".to_owned()),
            ("contents".to_owned(), "admin".to_owned()),
        ]),
        manifest_version: 29,
        manifest_sha256: "a".repeat(64),
        prior_version: 28,
        prior_sha256: "b".repeat(64),
        expires_at_ms: 1794441600000,
    }
}

#[test]
fn statement_pins_exact_key_set_sorted_permissions_bytes_and_hash() {
    assert_eq!(
        MANIFEST_BINDING_STATEMENT_V1.as_bytes(),
        MANIFEST_BINDING_STATEMENT_V1_TAG
    );
    let statement = sample_statement();
    let bytes = statement.canonical_bytes().unwrap();
    let expected = br#"{"agent_id":"agent_4444444444444444","app_slug":"repo-bot","expires_at_ms":1794441600000,"installation_permissions":{"contents":"admin","metadata":"read","pull_requests":"write"},"manifest_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","manifest_version":29,"prior_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","prior_version":28,"proposal_id":"01JPROPOSAL","repo":"Octo-Owner/New-Repo","v":"ck-manifest-binding-statement/v1"}"#;
    assert_eq!(bytes, expected);
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        [
            "agent_id",
            "app_slug",
            "expires_at_ms",
            "installation_permissions",
            "manifest_sha256",
            "manifest_version",
            "prior_sha256",
            "prior_version",
            "proposal_id",
            "repo",
            "v"
        ]
    );
    assert_eq!(
        value["installation_permissions"],
        json!({"contents":"admin", "metadata":"read", "pull_requests":"write"})
    );
    assert_eq!(
        serde_json::from_slice::<ManifestBindingStatement>(&bytes).unwrap(),
        statement
    );
    let hash = statement.statement_sha256().unwrap();
    assert_eq!(hash.len(), 64);
    assert!(hash
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
    assert_eq!(
        hash,
        "1dc5268ee9338a3571b33a13882eca47c24e51125b60e28fb129aa22f84d154b"
    );
}

#[test]
fn statement_builder_commits_the_built_and_prior_manifests() {
    let prior = GhManifest::parse_reproducible(V28).unwrap();
    let next = prior
        .build_next("Octo-Owner/New-Repo", "agent_4444444444444444", 1794355300)
        .unwrap();
    let sample = sample_statement();
    let statement = ManifestBindingStatement::new(
        sample.proposal_id,
        sample.agent_id,
        sample.app_slug,
        sample.repo,
        sample.installation_permissions.clone(),
        &next,
        &prior,
        sample.expires_at_ms,
    )
    .unwrap();
    assert_eq!(statement.v, MANIFEST_BINDING_STATEMENT_V1);
    assert_eq!(statement.repo, "Octo-Owner/New-Repo");
    assert_eq!(
        statement.installation_permissions,
        sample.installation_permissions
    );
    assert_eq!(statement.manifest_version, 29);
    assert_eq!(statement.prior_version, 28);
    assert_eq!(
        statement.manifest_sha256,
        format!("{:x}", Sha256::digest(next.to_bytes()))
    );
    assert_eq!(statement.prior_sha256, format!("{:x}", Sha256::digest(V28)));
}

#[test]
fn statement_sorts_valid_permission_keys_and_does_not_ascii_escape() {
    let mut statement = sample_statement();
    statement.app_slug = "café".to_owned();
    let bytes = statement.canonical_bytes().unwrap();
    let text = std::str::from_utf8(&bytes).unwrap();
    assert!(text.contains("\"app_slug\":\"café\""));
    assert!(text.contains(
        "\"installation_permissions\":{\"contents\":\"admin\",\"metadata\":\"read\",\"pull_requests\":\"write\"}"
    ));
}

fn statement_with_permissions(
    permissions: BTreeMap<String, String>,
) -> Result<ManifestBindingStatement, ManifestError> {
    let prior = GhManifest::parse_reproducible(V28).unwrap();
    let sample = sample_statement();
    ManifestBindingStatement::new(
        sample.proposal_id,
        sample.agent_id,
        sample.app_slug,
        sample.repo,
        permissions,
        &prior,
        &prior,
        sample.expires_at_ms,
    )
}

fn assert_invalid_permissions(permissions: BTreeMap<String, String>) {
    assert!(matches!(
        validate_installation_permissions(&permissions),
        Err(ManifestError::InvalidInstallationPermissions)
    ));
    assert!(matches!(
        statement_with_permissions(permissions.clone()),
        Err(ManifestError::InvalidInstallationPermissions)
    ));
    // Public fields and deserialization must not bypass the builder's validation.
    let mut statement = sample_statement();
    statement.installation_permissions = permissions;
    assert!(matches!(
        statement.canonical_bytes(),
        Err(ManifestError::InvalidInstallationPermissions)
    ));
    assert!(matches!(
        statement.statement_sha256(),
        Err(ManifestError::InvalidInstallationPermissions)
    ));
}

#[test]
fn installation_permissions_accept_real_names_and_all_three_levels() {
    let long_name = "organization_personal_access_token_requests";
    assert_eq!(long_name.len(), 43);
    let permissions = BTreeMap::from([
        (long_name.to_owned(), "admin".to_owned()),
        ("pull_requests".to_owned(), "write".to_owned()),
        ("metadata".to_owned(), "read".to_owned()),
    ]);
    validate_installation_permissions(&permissions).unwrap();
    let statement = statement_with_permissions(permissions.clone()).unwrap();
    assert_eq!(statement.installation_permissions, permissions);
    assert!(statement.canonical_bytes().is_ok());
}

#[test]
fn installation_permissions_count_accepts_1_and_64_refuses_0_and_65() {
    assert_eq!(MIN_MANIFEST_INSTALLATION_PERMISSIONS, 1);
    assert_eq!(MAX_MANIFEST_INSTALLATION_PERMISSIONS, 64);
    for count in [1, 64] {
        let permissions = (0..count)
            .map(|index| (format!("permission_{index}"), "read".to_owned()))
            .collect();
        let statement = statement_with_permissions(permissions).unwrap();
        assert_eq!(statement.installation_permissions.len(), count);
        assert!(statement.canonical_bytes().is_ok());
    }
    for count in [0, 65] {
        assert_invalid_permissions(
            (0..count)
                .map(|index| (format!("permission_{index}"), "read".to_owned()))
                .collect(),
        );
    }
}

#[test]
fn installation_permission_name_accepts_64_bytes_refuses_65() {
    assert_eq!(MAX_MANIFEST_PERMISSION_NAME_BYTES, 64);
    let statement =
        statement_with_permissions(BTreeMap::from([("a".repeat(64), "read".into())])).unwrap();
    assert!(statement.canonical_bytes().is_ok());
    assert_invalid_permissions(BTreeMap::from([("a".repeat(65), "read".into())]));
}

#[test]
fn statement_builder_refuses_u2028_permission_name() {
    assert!(matches!(
        statement_with_permissions(BTreeMap::from([("contents\u{2028}".into(), "read".into())])),
        Err(ManifestError::InvalidInstallationPermissions)
    ));
}

#[test]
fn installation_permissions_refuse_ambiguous_or_non_identifier_names() {
    for name in [
        "contents\u{2028}",
        "contents\u{2029}",
        "\u{202e}contents",
        "Contents",
        "pull-requests",
        "",
        "_contents",
        "1contents",
        "contents\nmetadata",
        "contents\0",
        "😀",
        "\u{e000}",
    ] {
        assert_invalid_permissions(BTreeMap::from([(name.to_owned(), "read".into())]));
    }
}

#[test]
fn installation_permissions_refuse_unknown_or_inexact_levels() {
    for level in ["unknown", "Read", "read ", "", "read\nwrite"] {
        assert_invalid_permissions(BTreeMap::from([("metadata".into(), level.to_owned())]));
    }
}

#[test]
fn manifest_statement_json_integers_accept_exact_limit_and_refuse_overflow() {
    assert_eq!(MAX_MANIFEST_JSON_INTEGER, 9_007_199_254_740_991);
    for field in ["manifest_version", "prior_version", "expires_at_ms"] {
        let mut statement = sample_statement();
        let set = |statement: &mut ManifestBindingStatement, value| match field {
            "manifest_version" => statement.manifest_version = value,
            "prior_version" => statement.prior_version = value,
            "expires_at_ms" => statement.expires_at_ms = value,
            _ => unreachable!(),
        };
        for accepted in [0, MAX_MANIFEST_JSON_INTEGER] {
            set(&mut statement, accepted);
            let bytes = statement.canonical_bytes().unwrap();
            let value: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(value[field].as_i64(), Some(accepted));
            assert_eq!(statement.statement_sha256().unwrap().len(), 64);
        }
        for refused in [-1, MAX_MANIFEST_JSON_INTEGER + 1, i64::MAX] {
            set(&mut statement, refused);
            assert!(matches!(statement.canonical_bytes(),
                Err(ManifestError::InvalidStatementInteger(name)) if name == field));
            assert!(matches!(statement.statement_sha256(),
                Err(ManifestError::InvalidStatementInteger(name)) if name == field));
        }
    }
}

#[test]
fn statement_builder_refuses_inexact_manifest_versions_and_expiry() {
    let prior = GhManifest::parse_reproducible(V28).unwrap();
    let inexact = std::str::from_utf8(V28).unwrap().replace(
        "\"manifest_version\": 28",
        &format!("\"manifest_version\": {}", MAX_MANIFEST_JSON_INTEGER + 1),
    );
    let inexact = GhManifest::parse_reproducible(inexact.as_bytes()).unwrap();
    for (manifest, prior, expiry, field) in [
        (&inexact, &prior, 1, "manifest_version"),
        (&prior, &inexact, 1, "prior_version"),
        (
            &prior,
            &prior,
            MAX_MANIFEST_JSON_INTEGER + 1,
            "expires_at_ms",
        ),
    ] {
        let sample = sample_statement();
        let result = ManifestBindingStatement::new(
            sample.proposal_id,
            sample.agent_id,
            sample.app_slug,
            sample.repo,
            sample.installation_permissions,
            manifest,
            prior,
            expiry,
        );
        assert!(
            matches!(result, Err(ManifestError::InvalidStatementInteger(name)) if name == field)
        );
    }
}
