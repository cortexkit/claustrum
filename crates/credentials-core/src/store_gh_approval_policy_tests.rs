use super::{
    approve, envelope, hash, propose_for, ready, ready_with_manifest, refuses, run, snapshot,
};
use super::{propose, FP, MEMBER, NOW, V28};
use crate::agent_policy::{
    github_default_rule_set, AgentPolicy, AGENT_POLICY_SCHEMA_V1, AGENT_POLICY_SEPARATOR,
    MAX_POLICY_DOCUMENT_BYTES,
};
use crate::agent_secret::SecretError;
use crate::audit::{AuditCtx, AuditOp};
use crate::gh_manifest::GhManifest;
use crate::signing::{key_id_for_public, MAX_SIGN_PAYLOAD};
use crate::store::{
    agent_policy::active_agent_policy_version_conn, EncryptedStore, GhManifestActivationReport,
    GhManifestSource, GhManifestVerdict, GhManifestVersion, GH_MANIFEST_ROOT_KEY_ID,
};
use serde_json::json;
use std::collections::BTreeMap;

const EXISTING_AGENT: &str = "agent_1111111111111111";
const FIRST_AGENT: &str = "agent_0000000000000000";
const BINDINGS_V28: &str = concat!(
    r#"[{"agent":"agent_1111111111111111","identity":"github_app:zulu-bot","resources":["zulu/existing"],"service":"github"},"#,
    r#"{"agent":"agent_2222222222222222","identity":"github_app:alpha-bot","resources":["alpha/other"],"service":"github"},"#,
    r#"{"agent":"agent_3333333333333333","identity":"github_app:sidebar-bot","resources":["cortexkit/opencode-sidebar"],"service":"github"}]"#,
);

fn initial_policy(public: &[u8]) -> AgentPolicy {
    AgentPolicy {
        schema: AGENT_POLICY_SCHEMA_V1.into(),
        version: 1,
        issued_at_unix_secs: 42,
        root_key_id: key_id_for_public(public),
        rule_sets: BTreeMap::new(),
        bindings: serde_json::from_str(BINDINGS_V28).unwrap(),
    }
}

fn sign_policy(store: &EncryptedStore, policy: &AgentPolicy, manifest: i64) -> String {
    let bytes = String::from_utf8(policy.canonical_bytes().unwrap()).unwrap();
    store
        .sign_agent_policy_admin(&bytes, manifest, "operator", "test")
        .unwrap();
    bytes
}

fn assert_pending(store: &EncryptedStore, proposal_id: &str) {
    store
        .with_raw_conn(|conn| {
            let state: String = conn.query_row(
                "SELECT state FROM gh_manifest_proposals WHERE proposal_id=?1",
                [proposal_id],
                |row| row.get(0),
            )?;
            assert_eq!(state, "pending");
            Ok(())
        })
        .unwrap();
}

#[test]
fn one_tap_policy_preserves_pending_ceremony_rules_in_p3_and_pairs_successive_approvals() {
    let (_dir, store, public) = ready("one-tap-policy-rules-witness");
    let mut policy = initial_policy(&public);
    policy
        .rule_sets
        .insert("github".into(), github_default_rule_set().unwrap());
    sign_policy(&store, &policy, 28);
    store
        .report_gh_manifest_active(
            &GhManifestActivationReport {
                member_id: MEMBER,
                version: 28,
                payload_sha256: &hash(V28),
                verdict: GhManifestVerdict::Valid,
                reason: None,
                reported_at_ms: NOW,
            },
            AuditCtx::admin(AuditOp::GhManifestActivation),
        )
        .unwrap();

    let v29 = std::str::from_utf8(V28)
        .unwrap()
        .replace("\"manifest_version\": 28", "\"manifest_version\": 29");
    store
        .sign_gh_manifest_admin(&v29, "operator", "test")
        .unwrap();
    policy.version = 2;
    let rules = policy.rule_sets.get_mut("github").unwrap();
    let removed = rules.actions.remove(0);
    assert!(!rules
        .actions
        .iter()
        .any(|action| action.action == removed.action));
    let p2 = sign_policy(&store, &policy, 29);
    assert_eq!(
        store
            .with_raw_conn(active_agent_policy_version_conn)
            .unwrap(),
        Some(1)
    );

    // Write the expected binding array independently of the successor builder and
    // copy the rules text from the just-signed P2 document.
    let (_, p2_tail) = p2.split_once(r#","rule_sets":"#).unwrap();
    let p2_rules = p2_tail
        .strip_suffix(r#","schema":"ck-agent-policy/v1","version":2}"#)
        .unwrap();
    let expected_p3_bindings =
        BINDINGS_V28.replace(r#"["zulu/existing"]"#, r#"["alpha/new","zulu/existing"]"#);
    let expected = |version, bindings: &str| {
        format!(
            r#"{{"bindings":{bindings},"issued_at_unix_secs":42,"root_key_id":"{}","rule_sets":{p2_rules},"schema":"ck-agent-policy/v1","version":{version}}}"#,
            key_id_for_public(&public),
        )
    };

    let p = propose_for(&store, EXISTING_AGENT, "zulu-bot", "Alpha/New", NOW);
    let sibling = propose(&store, "Octo/Sibling", NOW);
    let op = approve(&envelope(&p, NOW));
    let approved = run(&store, &op, NOW).unwrap();
    assert_eq!(
        approved,
        json!({"status":"approved","proposal_id":p.proposal_id,"version":30,"manifest_sha256":p.manifest_sha256})
    );
    assert_pair(
        &store,
        &p.manifest_sha256,
        &public,
        3,
        30,
        &expected(3, &expected_p3_bindings),
        true,
    );
    let after_p3 = snapshot(&store);
    assert_eq!(run(&store, &op, NOW).unwrap(), approved);
    assert_eq!(snapshot(&store), after_p3);
    refuses(
        &store,
        &approve(&envelope(&sibling, NOW)),
        NOW,
        SecretError::Superseded,
    );

    let p = propose_for(&store, FIRST_AGENT, "first-bot", "Bravo/Second", NOW + 1);
    assert_eq!(
        run(&store, &approve(&envelope(&p, NOW + 1)), NOW + 1).unwrap()["version"],
        31
    );
    let expected_p4_bindings = format!(
        "[{},{}",
        r#"{"agent":"agent_0000000000000000","identity":"github_app:first-bot","resources":["bravo/second"],"service":"github"}"#,
        &expected_p3_bindings[1..],
    );
    assert_pair(
        &store,
        &p.manifest_sha256,
        &public,
        4,
        31,
        &expected(4, &expected_p4_bindings),
        false,
    );
    assert_eq!(
        store
            .with_raw_conn(active_agent_policy_version_conn)
            .unwrap(),
        Some(1)
    );
    store.verify_audit_chain().unwrap();
}

fn assert_pair(
    store: &EncryptedStore,
    manifest_digest: &str,
    public: &[u8],
    version: i64,
    manifest_version: i64,
    expected_document: &str,
    swept_sibling: bool,
) {
    store.with_raw_conn(|conn| {
        let row: (Vec<u8>, String, Vec<u8>, i64, String, i64, i64) = conn.query_row(
            "SELECT policy_bytes, policy_sha256, p.signature, p.signed_at_ms, p.source, p.approval_seq, m.approval_audit_seq
             FROM agent_policies p JOIN gh_manifests m ON p.manifest_version=m.version
             WHERE p.version=?1 AND m.version=?2 AND m.source='one_tap'",
            [version, manifest_version], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?)),
        )?;
        let (bytes, digest, signature, signed_at, source, approval, manifest_approval) = row;
        assert_eq!(bytes, expected_document.as_bytes());
        assert_eq!(digest, hash(expected_document.as_bytes()));
        assert_eq!(signed_at, NOW + (version - 3));
        assert_eq!(source, "one_tap");
        assert_eq!(approval, manifest_approval);
        let input = [AGENT_POLICY_SEPARATOR, expected_document.as_bytes()].concat();
        let verifier = ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public);
        verifier.verify(&input, &signature).unwrap();
        assert!(verifier.verify(expected_document.as_bytes(), &signature).is_err());

        let mut expected_ops = vec!["approval", "gh_manifest_sign", "gh_manifest_proposal_state", "gh_manifest_store"];
        if swept_sibling {
            expected_ops.push("gh_manifest_proposal_state");
        }
        expected_ops.extend(["agent_policy_sign", "agent_policy_store"]);
        let mut stmt = conn.prepare("SELECT op, credential_id, payload_hash, actor FROM audit_log WHERE seq>=?1 ORDER BY seq")?;
        let audit = stmt.query_map([approval], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_,String>(3)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let sign = &audit[audit.len() - 2];
        let append = audit.last().unwrap();
        assert_eq!(audit.iter().map(|row| row.0.as_str()).collect::<Vec<_>>(), expected_ops);
        assert_eq!(audit[0].1, GH_MANIFEST_ROOT_KEY_ID);
        assert_eq!(audit[0].2, manifest_digest);
        assert_eq!(sign.1, GH_MANIFEST_ROOT_KEY_ID);
        assert_eq!(sign.2, digest);
        assert_eq!(append.1, format!("gh-manifest|{manifest_version}"));
        assert!(audit.iter().all(|row| row.3 == audit[0].3));
        assert!(audit[0].3.ends_with(&format!("approver:fed-phone:{FP}")));
        let mut framed = Vec::new();
        for field in [version.to_string().as_str(), manifest_version.to_string().as_str(), "one_tap", &digest] {
            framed.extend((field.len() as u64).to_le_bytes());
            framed.extend(field.as_bytes());
        }
        assert_eq!(append.2, hash(&framed));
        Ok(())
    }).unwrap();
}

#[test]
fn one_tap_policy_refuses_conflicting_identities_and_invalid_resources_without_writing() {
    let (_dir, store, public) = ready("one-tap-policy-identity-conflicts");
    sign_policy(&store, &initial_policy(&public), 28);
    for (agent, slug, repo) in [
        (EXISTING_AGENT, "different-bot", "Octo/Mismatch"),
        (FIRST_AGENT, "zulu-bot", "Octo/Shared"),
        (EXISTING_AGENT, "zulu-bot", "Octo/Contains Space"),
    ] {
        let p = propose_for(&store, agent, slug, repo, NOW);
        refuses(
            &store,
            &approve(&envelope(&p, NOW)),
            NOW,
            SecretError::PolicyBindingConflict,
        );
        assert_pending(&store, &p.proposal_id);
    }
}

#[test]
fn one_tap_policy_refuses_manifest_projection_mismatch_and_case_collision_without_writing() {
    for (label, repo) in [
        ("projection-mismatch", "Octo/Drift"),
        ("case-collision", "ZULU/EXISTING"),
    ] {
        let (_dir, store, public) = ready(label);
        sign_policy(&store, &initial_policy(&public), 28);
        // Insert directly because sign_gh_manifest_admin refuses manifests whose
        // bindings disagree with the policy head.
        let v29 = std::str::from_utf8(V28)
            .unwrap()
            .replace("\"manifest_version\": 28", "\"manifest_version\": 29")
            .replace(
                "  \"bindings\": {\n",
                &format!("  \"bindings\": {{\n    \"{repo}\": \"{EXISTING_AGENT}\",\n"),
            );
        GhManifest::parse_reproducible(v29.as_bytes()).unwrap();
        store
            .store_gh_manifest(
                &GhManifestVersion {
                    version: 29,
                    manifest_bytes: v29.as_bytes(),
                    manifest_sha256: &hash(v29.as_bytes()),
                    key_id: "0123456789abcdef",
                    signature: &[7; 64],
                    signed_at_ms: NOW,
                    source: GhManifestSource::Import,
                    approval_audit_seq: None,
                },
                AuditCtx::admin(AuditOp::GhManifestStore),
            )
            .unwrap();
        let p = propose_for(&store, EXISTING_AGENT, "zulu-bot", "Octo/New", NOW);
        refuses(
            &store,
            &approve(&envelope(&p, NOW)),
            NOW,
            SecretError::PolicyBindingConflict,
        );
        assert_pending(&store, &p.proposal_id);
    }
}

#[test]
fn one_tap_policy_refuses_both_size_layers_before_writing() {
    let document_len = MAX_SIGN_PAYLOAD - AGENT_POLICY_SEPARATOR.len();
    let base_len = initial_policy(&[0; 32]).canonical_bytes().unwrap().len();
    let mut remaining = document_len - base_len;
    let mut padding = Vec::new();
    let mut manifest_bindings = String::from("  \"bindings\": {\n");
    while remaining > 0 {
        use std::fmt::Write as _;
        let prefix = format!("pad/r{:05}", padding.len());
        let overhead = prefix.len() + 3; // quotes, comma, and the unique repository prefix
        let len = if remaining <= 80 {
            remaining
        } else {
            (remaining - overhead).min(80)
        };
        let repo = format!("{prefix}{}", "x".repeat(len - overhead));
        writeln!(manifest_bindings, "    \"{repo}\": \"{EXISTING_AGENT}\",").unwrap();
        padding.push(repo);
        remaining -= len;
    }
    let v28 = std::str::from_utf8(V28)
        .unwrap()
        .replace("  \"bindings\": {\n", &manifest_bindings);
    let (_dir, store, public) = ready_with_manifest("one-tap-policy-size-limits", v28.as_bytes());
    let mut policy = initial_policy(&public);
    policy.bindings[0].resources.splice(0..0, padding);
    let original = sign_policy(&store, &policy, 28);
    assert_eq!(original.len(), document_len);

    for (repo, app_slug, over_document_cap) in [
        ("A/B", "zulu-bot", false),
        (
            "Alpha/Long-Enough-To-Cross-The-Document-Limit",
            "zulu-bot",
            true,
        ),
        // The size refusal takes precedence over an identity mismatch.
        ("A/C", "different-bot", false),
    ] {
        // The ASCII repository contributes its bytes, two quotes and a comma.
        let successor_len = original.len() + repo.len() + 3;
        assert!(successor_len + AGENT_POLICY_SEPARATOR.len() > MAX_SIGN_PAYLOAD);
        assert_eq!(successor_len > MAX_POLICY_DOCUMENT_BYTES, over_document_cap);
        let p = propose_for(&store, EXISTING_AGENT, app_slug, repo, NOW);
        refuses(
            &store,
            &approve(&envelope(&p, NOW)),
            NOW,
            SecretError::PolicyTooLarge,
        );
        assert_pending(&store, &p.proposal_id);
    }
}

#[test]
fn one_tap_policy_insert_failure_aborts_manifest_and_sibling_changes() {
    let (_dir, store, public) = ready("one-tap-policy-insert-failure");
    sign_policy(&store, &initial_policy(&public), 28);
    let p = propose(&store, "Octo/New", NOW);
    let sibling = propose(&store, "Octo/Sibling", NOW);
    store
        .with_raw_conn(|conn| {
            conn.execute_batch(
                "CREATE TRIGGER fail_successor_policy BEFORE INSERT ON agent_policies
         BEGIN SELECT RAISE(ABORT, 'forced one-tap policy insert failure'); END;",
            )
        })
        .unwrap();
    let op = approve(&envelope(&p, NOW));
    refuses(&store, &op, NOW, SecretError::StoreError);
    assert_pending(&store, &p.proposal_id);
    assert_pending(&store, &sibling.proposal_id);
    store
        .with_raw_conn(|conn| conn.execute_batch("DROP TRIGGER fail_successor_policy"))
        .unwrap();
    assert_eq!(run(&store, &op, NOW).unwrap()["version"], 29);
    assert_eq!(
        store
            .with_raw_conn(|conn| conn.query_row(
                "SELECT MAX(version) FROM agent_policies",
                [],
                |row| row.get::<_, i64>(0)
            ))
            .unwrap(),
        2
    );
}

#[test]
fn one_tap_policy_refuses_a_replaced_manifest_root_without_writing() {
    let (_dir, store, public) = ready("one-tap-policy-root-replaced");
    let policy = initial_policy(&public);
    sign_policy(&store, &policy, 28);
    let p = propose(&store, "Octo/New", NOW);
    let (replacement, replacement_public) = super::root_key();
    assert_ne!(policy.root_key_id, key_id_for_public(&replacement_public));
    let unusable = crate::record::VaultRecord::new_static(
        crate::record::CredentialKind::SigningKey,
        "operator",
        b"not a PKCS#8 key".to_vec(),
        None,
    );
    let op = approve(&envelope(&p, NOW));
    for record in [replacement, unusable] {
        store
            .overwrite_unconditional_audited(
                GH_MANIFEST_ROOT_KEY_ID,
                &record,
                AuditCtx::admin(AuditOp::Overwrite),
            )
            .unwrap();
        refuses(&store, &op, NOW, SecretError::ManifestSetupIncomplete);
        assert_pending(&store, &p.proposal_id);
    }
}
