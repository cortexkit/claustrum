const CP_NOW: i64 = 1_800_000_000_000;
const CP_LONG_ID: &str = concat!(
    "apikey:provider-account-for-phone-permission-layout-",
    "a-single-long-credential-identifier-without-spaces-",
    "that-must-wrap-without-hiding-the-revoke-action"
);

type CpGrant = (
    &'static str,
    &'static str,
    SelectorKind,
    &'static str,
    GrantOperation,
);

fn cp_grants() -> Vec<CpGrant> {
    vec![
        (
            "reserved",
            "broca",
            SelectorKind::Category,
            "llm-provider",
            GrantOperation::Read,
        ),
        (
            "enrolled",
            "claustrum-auth-pi",
            SelectorKind::Category,
            "llm-provider",
            GrantOperation::List,
        ),
        (
            "reserved",
            "exact-reader",
            SelectorKind::Exact,
            CP_LONG_ID,
            GrantOperation::Read,
        ),
        (
            "reserved",
            "motor",
            SelectorKind::Audience,
            "cortexkit-runners",
            GrantOperation::AccountToken,
        ),
        (
            "reserved",
            "callosum",
            SelectorKind::Exact,
            "kem:phone-deposit",
            GrantOperation::Open,
        ),
        (
            "reserved",
            "subc",
            SelectorKind::Exact,
            "signing:bus",
            GrantOperation::Sign,
        ),
        (
            "reserved",
            "broca",
            SelectorKind::Exact,
            CP_RUNTIME_ID,
            GrantOperation::Read,
        ),
    ]
}

/// A stored secret its module needs in order to run, marked with the module-runtime
/// category, so its grant must stay out of the list like a vault-held key's.
const CP_RUNTIME_ID: &str = "opaque:broca-deployment:1";

fn cp_id(
    kind: &str,
    principal: &str,
    selector_kind: SelectorKind,
    selector: &str,
    op: GrantOperation,
) -> String {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(concat!("claustrum-credential-permission", "/v1\0").as_bytes());
    for column in [
        kind,
        principal,
        selector_kind.as_str(),
        selector,
        op.as_str(),
    ] {
        hash.update((column.len() as u64).to_be_bytes());
        hash.update(column.as_bytes());
    }
    format!("cg_{:x}", hash.finalize())
}

fn cp_rig(
    seed: u8,
) -> (
    Arc<ReadSurface>,
    Arc<admin_surface::AdminSurface>,
    DepositCookieTestStore,
) {
    let (surface, admin, store) = deposit_cookie_rig(seed);
    for id in ["apikey:zai", CP_LONG_ID] {
        store
            .create(
                id,
                &VaultRecord::new_static(
                    CredentialKind::ApiKey,
                    "test",
                    b"permission-secret-canary".to_vec(),
                    None,
                ),
            )
            .unwrap();
    }
    store
        .create(
            CP_RUNTIME_ID,
            &VaultRecord::new_static(
                CredentialKind::Opaque,
                "test",
                b"permission-secret-canary".to_vec(),
                None,
            ),
        )
        .unwrap();
    store
        .set_categories_audited(
            CP_RUNTIME_ID,
            credentials_core::store::SetCategoryMode::Set,
            &["module-runtime".to_owned()],
            AuditCtx::admin(AuditOp::SetCategory),
        )
        .unwrap();
    for (kind, principal, selector_kind, selector, op) in cp_grants() {
        store
            .create_read_grant_audited(
                kind,
                principal,
                selector_kind,
                selector,
                op,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .unwrap();
    }
    // Fixed metadata makes real dispatcher replies reproducible. The list never opens
    // the synthetic secret envelope, so no secret material is needed for these rows.
    store.with_raw_conn(|conn| {
        conn.execute("UPDATE read_grants SET created_at_ms=?1", [CP_NOW])?;
        conn.execute_batch(concat!(
            "INSERT INTO agent_secrets (name,kind,incarnation,state,origin,record_version,key_id,envelope,created_at_ms) ",
            "VALUES ('website','site_login','11111111111111111111111111111111','active','https://x.test',1,'test',X'00',1800000000000);",
            "INSERT INTO secret_grants (grant_id,secret_name,incarnation,scope_owner,scope_kind,scope_ref,coverage,duration,expires_at_ms,granted_at_ms,envelope_sha256,agent_id) ",
            "VALUES ('sg_sample','website','11111111111111111111111111111111','reserved:prefrontal-core','head','head-A','scope','permanent',0,1800000000000,'test','agent-A');",
            "INSERT INTO secret_flow_grants (grant_id,secret_name,incarnation,flow_id,flow_version,flow_code_hash,flow_install_id,granted_at_ms,envelope_sha256) ",
            "VALUES ('fg_sample','website','11111111111111111111111111111111','flow-A',3,'code-hash','install-A',1800000000000,'test');"
        ))
    }).unwrap();
    admin.record_bind_at(101, 1, reserved("cingulate"), "");
    (surface, admin, store)
}

async fn cp_reply(
    surface: &Arc<ReadSurface>,
    admin: &Arc<admin_surface::AdminSurface>,
    method: &str,
    params: serde_json::Value,
) -> Vec<u8> {
    let (kind, bytes) = routed_reply(surface, admin, 101, method, params).await;
    assert_eq!(kind, FrameType::Response);
    bytes
}

#[tokio::test]
async fn permissions_credential_grants_dispatcher_lists_and_pins_samples() {
    use base64::Engine as _;
    use sha2::{Digest, Sha256};
    let (surface, admin, store) = cp_rig(151);
    for (name, label) in [("approved-plugin", "Claude sign-in for Pi"), ("broca", "Not the module name")] {
        let request = store.propose_enrollment_with_display_name_by(None, name, &"a".repeat(64), Some(label)).unwrap();
        store.approve_enrollment(&request.request_id, name, "operator").unwrap();
    }
    store.create_read_grant_audited("enrolled", "approved-plugin", SelectorKind::Exact, CP_LONG_ID, GrantOperation::Read, AuditCtx::admin(AuditOp::GrantCreate)).unwrap();
    store.with_raw_conn(|conn| conn.execute("UPDATE read_grants SET created_at_ms=?1", [CP_NOW])).unwrap();
    let before = store.audit_tip().unwrap();
    let list = cp_reply(&surface, &admin, "permissions.list", json!({})).await;
    assert_eq!(store.audit_tip().unwrap(), before);
    let body: serde_json::Value = serde_json::from_slice(&list).unwrap();
    let rows = body["result"]["grants"].as_array().unwrap();
    assert_eq!(
        rows.len(),
        7,
        "five credential grants, one secret and one flow"
    );
    // The secret and flow rows keep the order they had before credential grants were
    // listed; the five credential rows follow them, sorted by id.
    assert_eq!(rows[0]["id"], "sg_sample");
    assert_eq!(rows[1]["id"], "fg_sample");
    assert!(rows[2..]
        .windows(2)
        .all(|pair| pair[0]["id"].as_str() < pair[1]["id"].as_str()));
    for (kind, principal, selector_kind, selector, op) in cp_grants().into_iter().take(4) {
        let id = cp_id(kind, principal, selector_kind, selector, op);
        let row = rows
            .iter()
            .find(|row| row["id"] == id)
            .expect("credential grant row");
        let holder = if kind == "reserved" {
            json!({"kind":"module","module_id":principal})
        } else {
            json!({"kind":"enrolled","name":principal})
        };
        let (subject, label) = match (selector_kind, op) {
            (SelectorKind::Category, GrantOperation::Read) => ("Model provider logins and keys", "can read the secrets of 1 credential in this group"),
            (SelectorKind::Category, GrantOperation::List) => ("Model provider logins and keys", "can see the accounts and plans of 1 credential in this group, but not their secrets"),
            (SelectorKind::Exact, _) => (CP_LONG_ID, "can read the secret of this credential"),
            _ => ("CortexKit account tokens for cortexkit-runners", "can get CortexKit account tokens for cortexkit-runners"),
        };
        assert_eq!(
            *row,
            json!({"id":id,"holder":holder,"module":"claustrum","subject_label":subject,"scope":op.as_str(),"scope_label":label,"granted_at_ms":CP_NOW})
        );
    }
    assert!(!String::from_utf8_lossy(&list).contains("canary"));
    let labelled = rows.iter().find(|row| row["holder"]["name"] == "approved-plugin").unwrap();
    assert_eq!(labelled["holder"], json!({"kind":"enrolled","name":"approved-plugin","label":"Claude sign-in for Pi"}));
    assert!(rows.iter().filter(|row| row["holder"]["kind"] == "module").all(|row| row["holder"].get("label").is_none()));
    let filtered = cp_reply(
        &surface,
        &admin,
        "permissions.list",
        json!({"agent_id":"agent-A"}),
    )
    .await;
    let filtered_body: serde_json::Value = serde_json::from_slice(&filtered).unwrap();
    assert_eq!(
        filtered_body["result"]["grants"],
        json!([rows.iter().find(|row| row["id"] == "sg_sample").unwrap()])
    );
    let id = cp_id(
        "reserved",
        "broca",
        SelectorKind::Category,
        "llm-provider",
        GrantOperation::Read,
    );
    let revoked = cp_reply(&surface, &admin, "permissions.revoke", json!({"id":id})).await;
    assert_eq!(revoked, br#"{"result":{"outcome":"revoked"}}"#);
    let not_found = cp_reply(&surface, &admin, "permissions.revoke", json!({"id":id})).await;
    assert_eq!(not_found, br#"{"result":{"outcome":"not_found"}}"#);
    let case = |name: &str, method: &str, params: serde_json::Value, bytes: Vec<u8>| {
        json!({
            "case":name,"request":{"method":method,"params":params},
            "reply_b64url":base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes),
            "reply_sha256":format!("{:x}",Sha256::digest(&bytes)),
            "reply":serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
        })
    };
    let emitted = serde_json::to_vec_pretty(&json!({
        "v":"ck-permissions-credential-grants-vectors/v1",
        "cases":[
            case("unfiltered_list", "permissions.list", json!({}), list),
            case("agent_filtered_list", "permissions.list", json!({"agent_id":"agent-A"}), filtered),
            case("revoke_success", "permissions.revoke", json!({"id":id}), revoked),
            case("revoke_not_found", "permissions.revoke", json!({"id":id}), not_found),
        ]
    })).unwrap();
    let pinned = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../credentials-core/tests/vectors/permissions-credential-grants-v1.json");
    if std::env::var("CK_EMIT_SECRET_VECTORS").as_deref() == Ok("1") {
        std::fs::write(pinned, emitted).unwrap();
        println!("emitted four permissions credential-grant vectors through the real dispatcher");
    } else {
        assert_eq!(
            emitted,
            std::fs::read(pinned).expect("pinned permissions credential-grant vectors")
        );
    }
}

#[tokio::test]
async fn permissions_credential_grants_revoke_matches_cli_audit_and_is_exact() {
    let (surface, admin, store) = cp_rig(152);
    let (_control_surface, _control_admin, control) = cp_rig(153);
    for (kind, principal, selector_kind, selector, op) in cp_grants().into_iter().take(4) {
        let id = cp_id(kind, principal, selector_kind, selector, op);
        let before = store.list_read_grants().unwrap();
        let generation = store.grants_generation().unwrap();
        let audit_count = store.read_audit(None).unwrap().len();
        assert_eq!(
            cp_reply(&surface, &admin, "permissions.revoke", json!({"id":id})).await,
            br#"{"result":{"outcome":"revoked"}}"#
        );
        let expected: Vec<_> = before
            .into_iter()
            .filter(|grant| {
                !(grant.principal_kind == kind
                    && grant.principal_id == principal
                    && grant.selector_kind == selector_kind
                    && grant.selector == selector
                    && grant.operation == op)
            })
            .collect();
        assert_eq!(store.list_read_grants().unwrap(), expected);
        assert_eq!(store.grants_generation().unwrap(), generation + 1);
        control
            .revoke_read_grant_audited(
                kind,
                principal,
                selector_kind,
                selector,
                op,
                AuditCtx {
                    op: AuditOp::GrantRevoke,
                    actor: "reserved:cingulate",
                    alarm: None,
                },
            )
            .unwrap();
        let audit = store.read_audit(None).unwrap();
        assert_eq!(audit.len(), audit_count + 1);
        let actual = audit.last().unwrap();
        let control_audit = control.read_audit(None).unwrap();
        let expected = control_audit.last().unwrap();
        assert_eq!(
            (
                &actual.op,
                &actual.credential_id,
                &actual.payload_hash,
                &actual.actor,
                actual.alarm,
                &actual.alarm_reason
            ),
            (
                &expected.op,
                &expected.credential_id,
                &expected.payload_hash,
                &expected.actor,
                expected.alarm,
                &expected.alarm_reason
            )
        );
        assert_eq!(actual.op, "grant_revoke");
        assert_eq!(
            actual.credential_id.as_deref(),
            Some(
                format!(
                    "grant:{}:{kind}:{principal}:{}|{selector}",
                    op.as_str(),
                    selector_kind.as_str()
                )
                .as_str()
            )
        );
        let listed: serde_json::Value = serde_json::from_slice(
            &cp_reply(&surface, &admin, "permissions.list", json!({})).await,
        )
        .unwrap();
        assert!(listed["result"]["grants"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| row["id"] != id));
        let tip = store.audit_tip().unwrap();
        assert_eq!(
            cp_reply(&surface, &admin, "permissions.revoke", json!({"id":id})).await,
            br#"{"result":{"outcome":"not_found"}}"#
        );
        assert_eq!(store.audit_tip().unwrap(), tip);
    }
    assert_eq!(store.verify_audit_chain().unwrap(), None);
    for id in ["sg_sample", "fg_sample"] {
        assert_eq!(
            cp_reply(&surface, &admin, "permissions.revoke", json!({"id":id})).await,
            br#"{"result":{"outcome":"revoked"}}"#
        );
        assert_eq!(
            cp_reply(&surface, &admin, "permissions.revoke", json!({"id":id})).await,
            br#"{"result":{"outcome":"not_found"}}"#
        );
    }
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(
            &cp_reply(&surface, &admin, "permissions.list", json!({})).await
        )
        .unwrap(),
        json!({"result":{"grants":[]}})
    );
}

#[tokio::test]
async fn permissions_credential_grants_exclude_runtime_keys_and_other_principals() {
    let (surface, admin, store) = cp_rig(154);
    // Simulate a principal kind added by a future schema: this provider must not
    // publish it as a module or an enrolled program just because it has a grant.
    store
        .with_raw_conn(|conn| {
            conn.execute_batch(
                "PRAGMA ignore_check_constraints=ON; INSERT INTO read_grants \
         (principal_kind,principal_id,selector_kind,selector,operation,created_at_ms) \
         VALUES ('agent','other-holder','exact','apikey:other','read',1800000000000);",
            )
        })
        .unwrap();
    let grants = store.list_read_grants().unwrap();
    let tip = store.audit_tip().unwrap();
    let generation = store.grants_generation().unwrap();
    let listed = cp_reply(&surface, &admin, "permissions.list", json!({})).await;
    for id in cp_grants()
        .into_iter()
        .skip(4)
        .map(|(kind, principal, sk, selector, op)| cp_id(kind, principal, sk, selector, op))
        .chain([
            "cg_made-up".into(),
            cp_id(
                "agent",
                "other-holder",
                SelectorKind::Exact,
                "apikey:other",
                GrantOperation::Read,
            ),
        ])
    {
        assert!(!String::from_utf8_lossy(&listed).contains(&id));
        assert_eq!(
            cp_reply(&surface, &admin, "permissions.revoke", json!({"id":id})).await,
            br#"{"result":{"outcome":"not_found"}}"#
        );
        assert_eq!(store.list_read_grants().unwrap(), grants);
        assert_eq!(store.audit_tip().unwrap(), tip);
        assert_eq!(store.grants_generation().unwrap(), generation);
    }
    assert_eq!(
        cp_reply(&surface, &admin, "permissions.list", json!({})).await,
        listed
    );
}

#[tokio::test]
async fn permissions_credential_grants_revoke_rolls_back_on_audit_failure() {
    let (surface, admin, store) = cp_rig(155);
    store
        .with_raw_conn(|conn| {
            conn.execute_batch(
                "CREATE TRIGGER refuse_grant_revoke_audit BEFORE INSERT ON audit_log \
         WHEN NEW.op='grant_revoke' BEGIN SELECT RAISE(ABORT,'test audit failure'); END;",
            )
        })
        .unwrap();
    let before = store.list_read_grants().unwrap();
    let tip = store.audit_tip().unwrap();
    let generation = store.grants_generation().unwrap();
    let id = cp_id(
        "reserved",
        "broca",
        SelectorKind::Category,
        "llm-provider",
        GrantOperation::Read,
    );
    let reply: serde_json::Value = serde_json::from_slice(
        &cp_reply(&surface, &admin, "permissions.revoke", json!({"id":id})).await,
    )
    .unwrap();
    assert!(reply["result"].get("error").is_some(), "{reply}");
    assert_eq!(store.list_read_grants().unwrap(), before);
    assert_eq!(store.audit_tip().unwrap(), tip);
    assert_eq!(store.grants_generation().unwrap(), generation);
}

#[tokio::test]
async fn permissions_credential_grants_reach_changes_without_changing_identity_or_subject() {
    let (surface, admin, store) = cp_rig(156);
    let before: serde_json::Value =
        serde_json::from_slice(&cp_reply(&surface, &admin, "permissions.list", json!({})).await)
            .unwrap();
    store
        .create(
            "apikey:openrouter",
            &VaultRecord::new_static(
                CredentialKind::ApiKey,
                "test",
                b"another-canary".to_vec(),
                None,
            ),
        )
        .unwrap();
    let after: serde_json::Value =
        serde_json::from_slice(&cp_reply(&surface, &admin, "permissions.list", json!({})).await)
            .unwrap();
    let id = cp_id(
        "reserved",
        "broca",
        SelectorKind::Category,
        "llm-provider",
        GrantOperation::Read,
    );
    let row = |value: &serde_json::Value| {
        value["result"]["grants"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["id"] == id)
            .unwrap()
            .clone()
    };
    let mut expected = row(&before);
    expected["scope_label"] = json!("can read the secrets of 2 credentials in this group");
    assert_eq!(row(&after), expected);
}
