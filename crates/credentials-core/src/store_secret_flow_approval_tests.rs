use super::*;
use agent_secret::{flow_approval_statement, ApprovalEnvelope, FlowIdentity, ValidationError};

const API: &str = "01HF7YAT000000000000000001";
const LOGIN: &str = "01HF7YAT000000000000000002";
const AGENT: &str = "01HF7YAT000000000000000003";

fn flow() -> FlowIdentity {
    FlowIdentity {
        flow_id: "daily-fetch".into(),
        version: 7,
        code_hash: "0123456789abcdef".repeat(4),
        install_id: "install-A".into(),
    }
}

fn verify(e: &Value) -> Result<ApprovalEnvelope, SecretError> {
    let bytes = serde_json::to_vec(e).unwrap();
    let signature: Signature = signer().sign(&bytes);
    ApprovalEnvelope::verify(
        &bytes,
        signature.to_der().as_bytes(),
        signer().verifying_key().to_encoded_point(false).as_bytes(),
        FP,
    )
}

#[test]
fn secret_flow_approval_statement_shape_methods_and_exact_integer_bound() {
    let api_scope = SecretScope::ApiKey {
        host: "api.example.com".into(),
        path_prefix: Some("/v1".into()),
        location: "authorization_bearer".into(),
    };
    let api = flow_approval_statement(
        API,
        MEMBER,
        "incarnation",
        "key",
        &flow(),
        &api_scope,
        Some(&["POST".into(), "GET".into()]),
        NOW + 600_000,
    )
    .unwrap();
    assert_eq!(
        api,
        json!({
            "v":"ck-secret-flow-statement/v1", "request_id":API, "member_id":MEMBER,
            "flow":{"flow_id":"daily-fetch","version":7,"code_hash":"0123456789abcdef".repeat(4),"install_id":"install-A"},
            "secret":{"name":"key","kind":"agent_api_key","incarnation":"incarnation"},
            "use":{"host":"api.example.com","path_prefix":"/v1","location":"authorization_bearer","methods":["GET","POST"]},
            "durations":["version"], "request_expires_at_ms":NOW+600_000
        })
    );
    let login_scope = SecretScope::SiteLogin {
        origin: "https://example.com".into(),
    };
    let login = flow_approval_statement(
        LOGIN,
        MEMBER,
        "incarnation",
        "login",
        &flow(),
        &login_scope,
        None,
        NOW + 600_000,
    )
    .unwrap();
    assert_eq!(login["use"], json!({"origin":"https://example.com"}));
    for s in [&api, &login] {
        assert!(s.get("scope").is_none());
        assert!(s.get("coverage").is_none());
        assert!(s.get("agent_id").is_none());
        assert_eq!(s["durations"], json!(["version"]));
    }
    for methods in [
        vec![],
        vec!["get".into()],
        vec!["".into()],
        vec!["GET".into(), "GET".into()],
        vec!["A".repeat(17)],
        vec!["GÉT".into()],
        vec!["GET-".into()],
    ] {
        assert!(flow_approval_statement(
            API,
            MEMBER,
            "incarnation",
            "key",
            &flow(),
            &scope(),
            Some(&methods),
            NOW + 600_000
        )
        .is_err());
    }
    assert!(flow_approval_statement(
        API,
        MEMBER,
        "incarnation",
        "key",
        &flow(),
        &scope(),
        None,
        NOW + 600_000
    )
    .is_err());
    assert!(flow_approval_statement(
        LOGIN,
        MEMBER,
        "incarnation",
        "login",
        &flow(),
        &login_scope,
        Some(&["GET".into()]),
        NOW + 600_000
    )
    .is_err());
    for version in [0, agent_secret::MAX_SECRET_JSON_INTEGER + 1, u64::MAX] {
        let mut identity = flow();
        identity.version = version;
        assert!(flow_approval_statement(
            LOGIN,
            MEMBER,
            "incarnation",
            "login",
            &identity,
            &login_scope,
            None,
            NOW + 600_000
        )
        .is_err());
    }
    let mut identity = flow();
    identity.version = agent_secret::MAX_SECRET_JSON_INTEGER;
    assert!(flow_approval_statement(
        LOGIN,
        MEMBER,
        "incarnation",
        "login",
        &identity,
        &login_scope,
        None,
        NOW + 600_000
    )
    .is_ok());
}

#[test]
fn secret_flow_approval_version_envelope_rules_and_closed_item_shape() {
    let valid = envelope(
        vec![json!({"request_id":API,"statement_sha256":"0".repeat(64)})],
        "version",
        NOW,
    );
    assert!(verify(&valid).is_ok());
    for (field, value) in [
        ("decision", json!("delete")),
        ("grant_expires_at_ms", json!(1)),
    ] {
        let mut invalid = valid.clone();
        invalid[field] = value;
        assert!(matches!(
            verify(&invalid),
            Err(SecretError::ApprovalInvalid)
        ));
    }
    let mut invalid = valid;
    invalid["items"][0]["duration"] = json!("version");
    assert!(matches!(
        verify(&invalid),
        Err(SecretError::ApprovalInvalid)
    ));
}

#[test]
fn secret_flow_statement_encoder_carries_every_identity_value_verbatim() {
    let api_scope = SecretScope::ApiKey {
        host: "x.test".into(),
        path_prefix: None,
        location: "authorization_bearer".into(),
    };
    let encode = |identity: &FlowIdentity| {
        flow_approval_statement(
            API,
            MEMBER,
            "incarnation",
            "key",
            identity,
            &api_scope,
            Some(&["GET".to_string()]),
            NOW,
        )
    };
    // A flow id equal to a statement tag would take the `v` key's place in the object.
    for tag in ["ck-secret-flow-statement/v1", "ck-secret-use-statement/v1"] {
        let mut identity = flow();
        identity.flow_id = tag.into();
        assert_eq!(
            encode(&identity),
            Err(ValidationError::InvalidParams),
            "{tag}"
        );
    }
    // An install id that is not 1-256 printable ASCII could not come back as the same
    // value at grant lookup, so such an identity is refused rather than stored.
    for install_id in ["".to_string(), "install\u{7f}".to_string(), "x".repeat(257)] {
        let mut identity = flow();
        identity.install_id = install_id;
        assert_eq!(encode(&identity), Err(ValidationError::InvalidParams));
    }
    // The identity a flow really carries encodes as itself, under the flow statement tag.
    let statement = encode(&flow()).unwrap();
    assert_eq!(statement["v"], "ck-secret-flow-statement/v1");
    assert_eq!(statement["flow"], json!(flow()));
}

fn pending(
    store: &EncryptedStore,
    id: &str,
    name: &str,
    scope: &SecretScope,
    is_flow: bool,
) -> Value {
    let incarnation: String = store
        .store
        .with_conn(|c| {
            c.query_row(
                "SELECT incarnation FROM agent_secrets WHERE name=?1",
                [name],
                |r| r.get(0),
            )
        })
        .unwrap();
    let methods = matches!(scope, SecretScope::ApiKey { .. }).then(|| vec!["GET".to_string()]);
    let identity = flow();
    let statement = if is_flow {
        flow_approval_statement(
            id,
            MEMBER,
            &incarnation,
            name,
            &identity,
            scope,
            methods.as_deref(),
            NOW + 600_000,
        )
        .unwrap()
    } else {
        agent_secret::approval_statement(id, MEMBER, &incarnation, &call(), scope, NOW + 600_000)
    };
    let bytes = serde_json::to_vec(&statement).unwrap();
    let digest = phone::hex(&payload_hash(&bytes));
    store.fenced_write(|tx| {
        tx.execute("INSERT INTO secret_pending_requests (request_id,request_kind,secret_name,incarnation,member_id,statement_bytes,statement_sha256,request_expires_at_ms) VALUES (?1,'approve',?2,?3,?4,?5,?6,?7)",rusqlite::params![id,name,incarnation,MEMBER,bytes,digest,NOW+600_000])?;
        if is_flow {
            tx.execute("UPDATE secret_pending_requests SET flow_id=?2,flow_version=?3,flow_code_hash=?4,flow_install_id=?5,methods=?6 WHERE request_id=?1",rusqlite::params![id,identity.flow_id,identity.version,identity.code_hash,identity.install_id,methods.as_ref().map(|m|serde_json::to_string(m).unwrap())])?;
        } else {
            tx.execute("UPDATE secret_pending_requests SET mapped_owner='reserved:prefrontal-core',mapped_kind='head',mapped_ref='H',mapped_epoch=7,coverage='scope',agent_id='agent-A' WHERE request_id=?1",[id])?;
        }
        Ok(())
    }).unwrap();
    json!({"request_id":id,"statement_b64url":URL_SAFE_NO_PAD.encode(&bytes),"statement_sha256":digest})
}

fn flow_setup(
    tag: &str,
) -> (
    crate::test_support::TestTempDir,
    Arc<EncryptedStore>,
    Vec<Value>,
) {
    let (root, store, _) = approval_setup(tag);
    sql(&store, "DELETE FROM secret_pending_requests");
    let login_scope = SecretScope::SiteLogin {
        origin: "https://x.test".into(),
    };
    seed(
        &store,
        "login",
        &login_scope,
        &SecretMaterial::SiteLogin {
            username: Secret::new("user".into()),
            password: Secret::new("password-canary".into()),
            otpauth: None,
        },
    );
    let requests = vec![
        pending(&store, API, "key", &scope(), true),
        pending(&store, LOGIN, "login", &login_scope, true),
        pending(&store, AGENT, "key", &scope(), false),
    ];
    (root, store, requests)
}

#[test]
fn secret_flow_approval_consumes_once_and_binds_grant_audit_to_exact_envelope() {
    use sha2::{Digest, Sha256};
    let (_root, store, requests) = flow_setup("flow-grant-audit");
    let e = envelope(vec![item(&requests[0]), item(&requests[1])], "version", NOW);
    let bytes = serde_json::to_vec(&e).unwrap();
    assert_eq!(
        phone(&store, &signed_bytes(bytes.clone(), false), NOW).unwrap(),
        json!({"results":[granted(&requests[0]),granted(&requests[1])]})
    );
    assert_eq!(count(&store, "SELECT COUNT(*) FROM secret_grants"), 0);
    let expected_hash: String = Sha256::digest(&bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let rows: Vec<(String, String, u64, String, String, Option<String>, String, String, i64, String)> = store.store.with_conn(|c| {
        let mut query = c.prepare("SELECT g.secret_name,g.flow_id,g.flow_version,g.flow_code_hash,g.flow_install_id,g.methods,g.envelope_sha256,a.payload_hash,g.granted_at_ms,g.card_ref FROM secret_flow_grants g JOIN audit_log a ON a.op='secret_grant_create' AND a.credential_id='secret|'||g.secret_name ORDER BY g.secret_name")?;
        let rows = query.query_map([], |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?,r.get(9)?)))?;
        rows.collect()
    }).unwrap();
    assert_eq!(
        rows,
        vec![
            (
                "key".into(),
                "daily-fetch".into(),
                7,
                flow().code_hash,
                "install-A".into(),
                Some("[\"GET\"]".into()),
                expected_hash.clone(),
                expected_hash.clone(),
                NOW,
                "card-1".into()
            ),
            (
                "login".into(),
                "daily-fetch".into(),
                7,
                flow().code_hash,
                "install-A".into(),
                None,
                expected_hash.clone(),
                expected_hash,
                NOW,
                "card-1".into()
            ),
        ]
    );
    assert_eq!(
        phone(&store, &signed(&e, false), NOW).unwrap(),
        json!({"results":[refused(&requests[0]),refused(&requests[1])]})
    );
    assert_eq!(count(&store, "SELECT COUNT(*) FROM secret_flow_grants"), 2);
    assert_eq!(
        count(
            &store,
            "SELECT COUNT(*) FROM audit_log WHERE op='secret_grant_create'"
        ),
        2
    );
    assert_eq!(store.verify_audit_chain().unwrap(), None);
}

#[test]
fn secret_flow_approval_pending_identity_methods_and_holder_cannot_cross() {
    for changes in [
        "flow_id='other'", "flow_version=8", "flow_code_hash=printf('%064d',0)",
        "flow_install_id='install-B'", "methods='[\"POST\"]'", "methods='[\"POST\",\"GET\"]'",
        "methods='[\"GET\",\"GET\"]'", "methods='bad-json'", "methods=NULL", "flow_id=NULL",
        "flow_version=NULL", "flow_code_hash=NULL", "flow_install_id=NULL",
        "mapped_owner='reserved:prefrontal-core'", "coverage='scope'", "agent_id='agent-A'",
        "flow_id=NULL,flow_version=NULL,flow_code_hash=NULL,flow_install_id=NULL,methods=NULL,mapped_owner='reserved:prefrontal-core',mapped_kind='head',mapped_ref='H',mapped_epoch=7,coverage='scope',agent_id='agent-A'",
    ] {
        let (_root, store, requests) = flow_setup("flow-binding");
        sql(&store, &format!("UPDATE secret_pending_requests SET {changes} WHERE request_id='{API}'"));
        let e = envelope(vec![item(&requests[0])], "version", NOW);
        assert_eq!(phone(&store, &signed(&e, false), NOW).unwrap(),json!({"results":[refused(&requests[0])]}),"{changes}");
        assert_eq!(count(&store, "SELECT COUNT(*) FROM secret_flow_grants"), 0);
        assert_eq!(count(&store, "SELECT COUNT(*) FROM secret_pending_requests WHERE consumed=1"), 0);
    }
    let (_root, store, requests) = flow_setup("agent-cannot-be-flow");
    sql(&store, &format!("UPDATE secret_pending_requests SET mapped_owner=NULL,mapped_kind=NULL,mapped_ref=NULL,mapped_epoch=NULL,coverage=NULL,agent_id=NULL,flow_id='daily-fetch',flow_version=7,flow_code_hash='{}',flow_install_id='install-A',methods='[\"GET\"]' WHERE request_id='{AGENT}'",flow().code_hash));
    let e = envelope(vec![item(&requests[2])], "version", NOW);
    assert_eq!(
        phone(&store, &signed(&e, false), NOW).unwrap(),
        json!({"results":[refused(&requests[2])]})
    );
    assert_eq!(count(&store, "SELECT COUNT(*) FROM secret_flow_grants"), 0);
}

#[test]
fn secret_flow_approval_offered_duration_is_checked_for_each_item() {
    for duration in ["once", "hour", "session", "permanent"] {
        let (_root, store, requests) = flow_setup("flow-duration");
        let e = envelope(vec![item(&requests[0]), item(&requests[2])], duration, NOW);
        assert_eq!(
            phone(&store, &signed(&e, false), NOW).unwrap(),
            json!({"results":[refused(&requests[0]),granted(&requests[2])]}),
            "{duration}"
        );
        assert_eq!(count(&store, "SELECT COUNT(*) FROM secret_flow_grants"), 0);
        assert_eq!(count(&store, "SELECT COUNT(*) FROM secret_grants"), 1);
    }
}

#[test]
fn secret_flow_approval_site_login_pending_methods_are_forbidden() {
    let (_root, store, requests) = flow_setup("login-has-no-methods");
    sql(
        &store,
        &format!(
            "UPDATE secret_pending_requests SET methods='[\"GET\"]' WHERE request_id='{LOGIN}'"
        ),
    );
    let e = envelope(vec![item(&requests[1])], "version", NOW);
    assert_eq!(
        phone(&store, &signed(&e, false), NOW).unwrap(),
        json!({"results":[refused(&requests[1])]})
    );
    assert_eq!(count(&store, "SELECT COUNT(*) FROM secret_flow_grants"), 0);
}

#[test]
fn secret_flow_approval_signed_statement_must_match_pending_and_sealed_scope() {
    for (pointer, value) in [
        ("/flow/flow_id", json!("other")),
        ("/flow/version", json!(8)),
        ("/flow/code_hash", json!("0".repeat(64))),
        ("/flow/install_id", json!("install-B")),
        ("/use/methods", json!(["POST"])),
        ("/use/host", json!("other.test")),
        ("/secret/incarnation", json!("0".repeat(32))),
        ("/v", json!("ck-secret-use-statement/v1")),
        ("/durations", json!(["version", "hour"])),
    ] {
        let (_root, store, requests) = flow_setup("flow-signed-binding");
        let mut statement: Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(requests[0]["statement_b64url"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        *statement.pointer_mut(pointer).unwrap() = value;
        let bytes = serde_json::to_vec(&statement).unwrap();
        let hash = phone::hex(&payload_hash(&bytes));
        store.fenced_write(|tx|tx.execute("UPDATE secret_pending_requests SET statement_bytes=?2,statement_sha256=?3 WHERE request_id=?1",rusqlite::params![API,bytes,hash]).map(|_|())).unwrap();
        let e = envelope(
            vec![json!({"request_id":API,"statement_sha256":hash})],
            "version",
            NOW,
        );
        assert_eq!(
            phone(&store, &signed(&e, false), NOW).unwrap(),
            json!({"results":[refused(&requests[0])]}),
            "{pointer}"
        );
        assert_eq!(count(&store, "SELECT COUNT(*) FROM secret_flow_grants"), 0);
    }
}

#[test]
fn secret_flow_approval_ckios_vectors_are_emitted_by_vault_code_and_pinned() {
    let mut vectors = Vec::new();
    for label in [
        "flow-version",
        "mixed-version",
        "mixed-hour",
        "item-duration",
    ] {
        let (_root, store, requests) = flow_setup("flow-ckios-vector");
        let selected = match label {
            "flow-version" => vec![requests[0].clone(), requests[1].clone()],
            "mixed-version" | "mixed-hour" => vec![requests[2].clone(), requests[0].clone()],
            _ => vec![requests[0].clone()],
        };
        let mut e = envelope(
            selected.iter().map(item).collect(),
            if label == "mixed-hour" {
                "hour"
            } else {
                "version"
            },
            NOW,
        );
        if label == "item-duration" {
            e["items"][0]["duration"] = json!("version");
        }
        let bytes = serde_json::to_vec(&e).unwrap();
        let signature: Signature = signer().sign(&bytes);
        let result = phone(&store, &signed_bytes(bytes.clone(), false), NOW);
        let outcome = if label == "item-duration" {
            assert_eq!(result, Err(SecretError::ApprovalInvalid));
            json!({"error":"approval_invalid"})
        } else {
            assert!(verify(&e).is_ok());
            let expected = match label {
                "flow-version" => vec![granted(&selected[0]), granted(&selected[1])],
                "mixed-version" => vec![refused(&selected[0]), granted(&selected[1])],
                "mixed-hour" => vec![granted(&selected[0]), refused(&selected[1])],
                _ => unreachable!(),
            };
            let result = result.unwrap();
            assert_eq!(result, json!({"results":expected}));
            result
        };
        let flow_count = if label == "flow-version" {
            2
        } else {
            i64::from(label == "mixed-version")
        };
        assert_eq!(
            count(&store, "SELECT COUNT(*) FROM secret_flow_grants"),
            flow_count
        );
        assert_eq!(
            count(&store, "SELECT COUNT(*) FROM secret_grants"),
            i64::from(label == "mixed-hour")
        );
        assert_eq!(
            count(
                &store,
                "SELECT COUNT(*) FROM secret_pending_requests WHERE consumed=1"
            ),
            flow_count + i64::from(label == "mixed-hour")
        );
        assert_eq!(store.verify_audit_chain().unwrap(), None);
        vectors.push(json!({"case":label,"statements":selected,"envelope_b64url":URL_SAFE_NO_PAD.encode(&bytes),"signature_b64url":URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes()),"envelope_sha256":phone::hex(&payload_hash(&bytes)),"result":outcome}));
    }
    let emitted = json!({"approval_private_key_hex":"07".repeat(32),"vectors":vectors});
    let pinned = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors/secret-flow-approval-v1.json");
    if std::env::var_os("CK_EMIT_SECRET_FLOW_VECTORS").is_some() {
        std::fs::write(&pinned, serde_json::to_vec_pretty(&emitted).unwrap()).unwrap();
        println!("emitted four flow approval vectors");
    } else {
        let expected: Value =
            serde_json::from_slice(&std::fs::read(pinned).expect("pinned flow approval vectors"))
                .unwrap();
        assert_eq!(
            emitted, expected,
            "vault-emitted flow approval vectors changed"
        );
    }
}
