use super::*;
use crate::{
    broker_action::{request_scope, OP_REQUEST_ACTION},
    secret_phone::OP_APPROVE_ACTION,
};
use base64::prelude::{Engine, BASE64_URL_SAFE_NO_PAD};
use credentials_core::{
    agent_policy::{policy_sha256, Consent},
    agent_secret::{SecretError, SECRET_ISSUE_SKEW_LIMIT_MS},
    broker_action::{check_statement, valid_ulid},
    store::{BrokerActionRequestError, BrokerActionRequestReply, PhoneOperation},
};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use sha2::{Digest, Sha256};

#[path = "broker_action_samples_tests.rs"]
mod broker_action_samples_tests;

const NOW: i64 = 1_800_000_000_000;
const TTL: i64 = 600_000;
const FIELD_CANARY: &str = "uniquely-sensitive-field-text";
const CONTEXT_CANARY: &str = "uniquely-sensitive-command-text";
const STAMP_CANARY: &str = "uniquely-sensitive-scope-ref";
const COMMENT: &str = "add_issue_comment";
const CLOSE: &str = "close_issue";
const APPROVING_PHONE: &str = "11111111111111111111111111111111";
const DEVELOPMENT_DESKTOP: &str = "00000000000000000000000000000000";

fn setup_actions() -> (Rig, Arc<Github>, String) {
    let rig = Rig::new();
    let key = root(&rig);
    rig.self_member();
    let digest = manifest_with_bindings(&rig, 41, json!({"org/r":"agent", "org/s":"agent"}));
    let mut rules = github_default_rule_set().unwrap();
    for (kind, fields) in [
        (COMMENT, ["number", "body"]),
        (CLOSE, ["number", "state_reason"]),
    ] {
        let kind = rules
            .kinds
            .iter_mut()
            .find(|entry| entry.kind == kind)
            .unwrap();
        kind.approval = Approval::Once;
        kind.consent = Some(Consent {
            fields: fields.map(str::to_owned).to_vec(),
        });
    }
    let policy: AgentPolicy = serde_json::from_value(json!({
        "schema":"ck-agent-policy/v1", "version":1, "issued_at_unix_secs":1,
        "root_key_id":key, "rule_sets":{"github":rules},
        "bindings":[{"service":"github", "agent":"agent", "identity":APP, "resources":["org/r", "org/s"]}],
    })).unwrap();
    // The shipped rules deliberately have no consent template. Insert a canonical
    // fixture policy so the reader can be tested without changing the signing rules.
    let bytes = policy.canonical_bytes().unwrap();
    Connection::open(&rig.path).unwrap().execute(
        "INSERT INTO agent_policies (version, policy_bytes, policy_sha256, key_id, signature, signed_at_ms, source, approval_seq, manifest_version)
         VALUES (1, ?1, ?2, ?3, zeroblob(64), 1, 'ceremony', 1, 41)",
        rusqlite::params![bytes, policy_sha256(&bytes), key],
    ).unwrap();
    ready(&rig, SELF, 41, &digest);
    rig.store.create(APP, &app_record(None)).unwrap();
    grant(&rig, "aft", APP, GrantOperation::PolicyToken);
    let github = Arc::new(Github::default());
    *rig.surface.policy_tokens.http.lock().unwrap() = Some(github.clone());
    (rig, github, digest)
}

fn one() -> Value {
    json!({
        "identity":APP,"service":"github","action":COMMENT,"kind":COMMENT,
        "method":"POST","host":"api.github.com","resource":"org/r","request_sha256":"1".repeat(64),
        "fields":[{"name":"body","value":{"text": FIELD_CANARY}}, {"name":"number","value":null}],
        "stamp": {"kind":"head","ref":STAMP_CANARY,"owner":{"kind":"reserved","module_id":"prefrontal"},
                  "scope_epoch":7,"owner_authorized":true,"attributes":{"agent_id":"agent"}},
        "context":CONTEXT_CANARY,
    })
}

fn template(body: &Value) -> Value {
    let mut request = body.clone();
    let obj = request.as_object_mut().unwrap();
    let first: serde_json::Map<_, _> = ["kind", "method", "resource", "request_sha256"]
        .into_iter()
        .map(|key| (key.to_owned(), obj.remove(key).unwrap()))
        .collect();
    request["action"] = json!("triage");
    request["legs"] = json!([first,{"kind":CLOSE,"method":"PATCH","resource":"org/s","request_sha256":"2".repeat(64)}]);
    request["fields"]
        .as_array_mut()
        .unwrap()
        .insert(0, json!({"name":"state_reason","value":0}));
    request
}

fn changed(mut request: Value, key: &str, value: Value) -> Value {
    request[key] = value;
    request
}

fn without(mut request: Value, key: &str) -> Value {
    request.as_object_mut().unwrap().remove(key).unwrap();
    request
}

fn map_stamp(mut request: Value, key: &str, value: Value) -> Value {
    request["stamp"][key] = value;
    request
}

fn state(rig: &Rig) -> (i64, i64, i64) {
    Connection::open(&rig.path).unwrap().query_row(
        "SELECT (SELECT COUNT(*) FROM broker_action_requests), (SELECT COUNT(*) FROM audit_log), (SELECT COUNT(*) FROM auth_events)",
        [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    ).unwrap()
}

async fn refuses(rig: &mut Rig, module: &str, params: Value, code: &str, class: &str) {
    let before = state(rig);
    let request: crate::ReadRequest =
        serde_json::from_value(json!({"method":OP_REQUEST_ACTION,"params":params})).unwrap();
    assert!(!format!("{request:?}").contains("params"));
    rig.request(caller(module), OP_REQUEST_ACTION, request.params, 1, 1)
        .await;
    let frame = frame(rig).await;
    let response = body(&frame);
    if code == "invalid_params" {
        assert_eq!(frame.header.ty, FrameType::Error);
        assert_eq!(response["code"], "invalid_params");
    } else {
        assert_eq!(frame.header.ty, FrameType::Response);
        assert_eq!(response["result"], refusal(code, class));
    }
    for canary in [FIELD_CANARY, CONTEXT_CANARY, STAMP_CANARY] {
        assert!(!response.to_string().contains(canary));
    }
    assert_eq!(state(rig), before);
}

async fn invalid(rig: &mut Rig, params: Value) {
    refuses(rig, "aft", params, "invalid_params", "").await;
}

#[tokio::test]
async fn broker_action_admission_precedes_shape_and_an_unmapped_stamp_is_not_a_shape_error() {
    let (mut rig, github, _) = setup_actions();
    grant(&rig, "other", APP, GrantOperation::PolicyToken);
    grant(&rig, "plexus", APP, GrantOperation::Read);
    for module in ["other", "plexus"] {
        refuses(
            &mut rig,
            module,
            changed(one(), "stamp", Value::Null),
            "not_found",
            "permanent",
        )
        .await;
    }
    for body in [
        without(one(), "identity"),
        changed(one(), "identity", json!(3)),
        changed(one(), "identity", json!("github_app:bad slug")),
        without(one(), "stamp"),
    ] {
        invalid(&mut rig, body).await;
    }
    refuses(
        &mut rig,
        "aft",
        without(
            changed(one(), "identity", json!("github_app:ungranted")),
            "stamp",
        ),
        "not_found",
        "permanent",
    )
    .await;
    let mut unmapped = changed(one(), "unexpected", json!(true));
    unmapped["stamp"]
        .as_object_mut()
        .unwrap()
        .remove("scope_epoch");
    for body in [
        unmapped,
        map_stamp(one(), "attributes", json!({})),
        map_stamp(one(), "kind", json!("worker")),
    ] {
        refuses(&mut rig, "aft", body, "not_found", "permanent").await;
    }
    use_remote_home(&rig);
    refuses(&mut rig, "aft", Value::Null, "not_found", "permanent").await;
    github.counts(0, 0);
}

#[tokio::test]
async fn broker_action_shape_precedes_active_policy_and_rejects_closed_member_defects() {
    let (mut rig, _, digest) = setup_actions();
    report_version(&rig, SELF, 41, &digest, GhManifestVerdict::Invalid);
    for (key, value) in [
        ("context", Value::Null),
        ("context", json!("")),
        ("context", json!("x".repeat(201))),
        ("context", json!("x\u{202e}")),
        ("service", json!("")),
        ("action", json!(CLOSE)),
        ("method", json!("Post")),
        ("host", json!("api.github.com:443")),
        ("host", json!("api.github.com:080")),
        ("request_sha256", json!("F".repeat(64))),
        (
            "fields",
            json!([{ "name":"number", "value": { "nested":[1.0] }}]),
        ),
        (
            "fields",
            json!([{ "name":"number", "value": -9_007_199_254_740_992_i64 }]),
        ),
        (
            "fields",
            json!(vec![json!({"name":"number","value":null}); 17]),
        ),
        ("fields", json!([["number", null]])),
        ("fields", json!([{"name":"number"}])),
        (
            "fields",
            json!([{"name":"number", "value":null, "extra":true}]),
        ),
        ("legs", json!([])),
        ("agent_id", json!("agent")),
        ("scope", json!({})),
    ] {
        invalid(&mut rig, changed(one(), key, value)).await;
    }
    let multi = template(&one());
    invalid(&mut rig, changed(multi.clone(), "resource", json!("org/r"))).await;
    invalid(
        &mut rig,
        changed(
            multi.clone(),
            "legs",
            json!(vec![multi["legs"][0].clone(); 17]),
        ),
    )
    .await;
    for stamp in [Value::Null, json!([]), json!("x")] {
        invalid(&mut rig, changed(one(), "stamp", stamp)).await;
    }
    for body in [
        map_stamp(one(), "scope_epoch", json!(9_007_199_254_740_992_u64)),
        map_stamp(
            one(),
            "parent",
            json!({"owner":{"kind":"direct"}, "ref":"p", "scope_epoch":9_007_199_254_740_992_u64}),
        ),
    ] {
        invalid(&mut rig, body).await;
    }
    // A well-shaped request with no ready policy refuses before service or policy binding checks.
    refuses(
        &mut rig,
        "aft",
        changed(one(), "service", json!("other")),
        "policy_absent",
        "permanent",
    )
    .await;
}

#[tokio::test]
async fn broker_action_policy_checks_precede_approval_template_and_statement_checks() {
    let (mut rig, github, _) = setup_actions();
    grant(
        &rig,
        "aft",
        "github_app:unbound",
        GrantOperation::PolicyToken,
    );
    let none = changed(
        changed(one(), "kind", json!("node_repository")),
        "action",
        json!("node_repository"),
    );
    for body in [
        changed(one(), "service", json!("other")),
        changed(one(), "identity", json!("github_app:unbound")),
        map_stamp(one(), "attributes", json!({"agent_id":"another-agent"})),
        changed(
            changed(one(), "kind", json!("unknown")),
            "action",
            json!("unknown"),
        ),
        changed(one(), "host", json!("api.github.com:8443")),
        changed(none.clone(), "resource", json!("org/nope")),
    ] {
        refuses(&mut rig, "aft", body, "not_found", "permanent").await;
    }
    let mut multi = template(&one());
    multi["legs"][1]["resource"] = json!("org/nope");
    refuses(&mut rig, "aft", multi, "not_found", "permanent").await;
    let mut multi = template(&one());
    multi["legs"][1]["kind"] = json!("node_repository");
    for body in [none, multi] {
        refuses(&mut rig, "aft", body, "approval_not_required", "permanent").await;
    }
    for fields in [
        json!([]),
        json!([{"name":"outside","value":null}]),
        json!([{"name":"number","value":null},{"name":"number","value":null}]),
        json!([{"name":"body","value":"x".repeat(524_288)}]),
    ] {
        refuses(
            &mut rig,
            "aft",
            changed(one(), "fields", fields),
            "consent_fields_invalid",
            "permanent",
        )
        .await;
    }
    let mut oversized = one();
    oversized["fields"][0]["value"] = json!("x".repeat(524_288));
    invalid(&mut rig, oversized).await;
    rig.sql(&format!(
        "UPDATE credentials SET github_app_agent = 'another', github_app_created_at_ms = 1 WHERE credential_id = '{APP}'"
    ));
    refuses(&mut rig, "aft", one(), "not_found", "permanent").await;
    rig.sql(&format!(
        "DELETE FROM credentials WHERE credential_id = '{APP}'"
    ));
    refuses(&mut rig, "aft", one(), "not_found", "permanent").await;
    github.counts(0, 0);
}

#[tokio::test]
async fn broker_action_mint_checks_the_statement_and_audits_exactly_its_digest() {
    let (mut rig, github, _) = setup_actions();
    grant(&rig, "plexus", APP, GrantOperation::PolicyToken);
    let (_, active) = rig.store.active_agent_policy().unwrap();
    let active = active.unwrap();
    let mut ids = std::collections::HashSet::new();
    let mut flow = map_stamp(one(), "kind", json!("ephemeral"));
    flow["stamp"]["attributes"] = json!({"agent_id":"agent", "flow_id":"flow", "run_id":"run"});
    flow["stamp"]["parent_state"] = json!("linked");
    flow["stamp"]["parent"] = json!({"owner":{"kind":"reserved","module_id":"prefrontal"}, "ref":"different-parent", "scope_epoch":7});
    for (module, request, fields, kind) in [
        ("aft", one(), vec!["number", "body"], "head"),
        (
            "plexus",
            map_stamp(
                map_stamp(template(&one()), "kind", json!("worker")),
                "attributes",
                json!({"agent_id":"other", "on_behalf_of_agent":"agent"}),
            ),
            vec!["number", "body", "state_reason"],
            "worker",
        ),
        ("plexus", flow, vec!["number", "body"], "ephemeral"),
    ] {
        let before = state(&rig);
        let ingress = Ingress::new(&rig);
        ingress.bind(&rig, 1, module);
        ingress
            .dispatch(
                &rig,
                super::request(OP_REQUEST_ACTION, request.clone(), 1, 1),
            )
            .await;
        let reply = super::reply(&mut rig, 1).await;
        let encoded = reply["statement_b64url"].as_str().unwrap();
        let checked = check_statement(encoded).unwrap();
        assert_eq!(
            reply,
            json!({
                "request_id": checked.statement().request_id,
                "statement_b64url": encoded,
                "statement_sha256": format!("{:x}", Sha256::digest(checked.bytes())),
                "expires_at_ms": checked.statement().expires_at_ms,
            })
        );
        let id = reply["request_id"].as_str().unwrap();
        assert!(valid_ulid(id));
        assert!(ids.insert(id.to_owned()));
        let statement: Value = serde_json::from_slice(checked.bytes()).unwrap();
        assert_eq!(statement["policy_sha256"], active.policy_sha256);
        assert_eq!(statement["policy_version"], active.version);
        assert_eq!(statement["agent_id"], "agent");
        assert_eq!(
            statement["scope"],
            json!({"owner":"reserved:prefrontal","kind": kind,"ref":STAMP_CANARY,"epoch":7})
        );
        assert_eq!(statement["resource"], "org/r");
        assert_eq!(statement["context"], CONTEXT_CANARY);
        assert_eq!(
            statement["fields"]
                .as_array()
                .unwrap()
                .iter()
                .map(|field| field["name"].as_str().unwrap())
                .collect::<Vec<_>>(),
            fields
        );
        if let Some(legs) = request.get("legs") {
            assert_eq!(statement["legs"], *legs);
            for absent in ["kind", "method", "request_sha256"] {
                assert!(statement.get(absent).is_none());
            }
        } else {
            assert_eq!(statement["action"], statement["kind"]);
            assert!(statement.get("legs").is_none());
        }
        let db = Connection::open(&rig.path).unwrap();
        let (principal, stored_bytes, stored_digest, created, expires): (String, Vec<u8>, String, i64, i64) = db.query_row(
            "SELECT principal, statement_bytes, statement_sha256, created_at_ms, expires_at_ms FROM broker_action_requests WHERE request_id = ?1", [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        ).unwrap();
        assert_eq!(principal, format!("reserved:{module}"));
        assert_eq!(stored_bytes, checked.bytes());
        assert_eq!(stored_digest, checked.sha256());
        assert_eq!(expires - created, TTL);
        assert_eq!(reply["expires_at_ms"], expires);
        assert_eq!(state(&rig), (before.0 + 1, before.1 + 1, before.2));
        let audit: (String, String, String, String, i64) = db.query_row(
            "SELECT op, credential_id, payload_hash, actor, alarm FROM audit_log ORDER BY seq DESC LIMIT 1", [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        ).unwrap();
        assert_eq!(
            audit,
            (
                "broker_action_request".into(),
                APP.into(),
                stored_digest,
                principal,
                0
            )
        );
        for canary in [
            FIELD_CANARY,
            CONTEXT_CANARY,
            STAMP_CANARY,
            encoded,
            std::str::from_utf8(checked.bytes()).unwrap(),
        ] {
            assert!(!format!("{audit:?} {checked:?} {:?}", checked.statement()).contains(canary));
        }
    }
    github.counts(0, 0);
}

fn mint_at(rig: &Rig, at: i64) -> Result<BrokerActionRequestReply, BrokerActionRequestError> {
    rig.store
        .request_broker_action(Some("aft"), one(), request_scope, || at)
}

fn envelope(request: &BrokerActionRequestReply, fingerprint: &str, issued: i64) -> Value {
    json!({"v":"ck-broker-action-envelope/v1","request_id":request.request_id,
        "statement_sha256":request.statement_sha256,"decision":"allow",
        "device_fingerprint":fingerprint,"issued_at_ms":issued})
}

fn sign(key: &SigningKey, bytes: &[u8]) -> Vec<u8> {
    let signature: Signature = key.sign(bytes);
    signature.to_der().as_bytes().to_vec()
}

fn register_approver(rig: &Rig, key: &SigningKey) {
    let operation = PhoneOperation::Register {
        deposit_pub: vec![46; 32],
        approval_pub: key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec(),
    };
    assert_eq!(
        rig.store
            .secret_phone_operation(
                APPROVING_PHONE,
                Some("pair-A"),
                1,
                &operation,
                || true,
                || 1,
            )
            .unwrap(),
        json!({"status":"stored"})
    );
}

fn approval_snapshot(rig: &Rig) -> Vec<Vec<Vec<rusqlite::types::Value>>> {
    let conn = Connection::open(&rig.path).unwrap();
    [
        "SELECT * FROM broker_action_requests ORDER BY request_id",
        "SELECT * FROM secret_phone_observations ORDER BY fingerprint",
        "SELECT * FROM audit_log ORDER BY rowid",
        "SELECT * FROM auth_events ORDER BY rowid",
    ]
    .into_iter()
    .map(|sql| {
        let mut stmt = conn.prepare(sql).unwrap();
        let count = stmt.column_count();
        stmt.query_map([], |row| {
            (0..count)
                .map(|i| row.get(i))
                .collect::<rusqlite::Result<_>>()
        })
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
    })
    .collect()
}

fn approval_reply(request: &BrokerActionRequestReply) -> Value {
    json!({"status":"approved","request_id":request.request_id,"statement_sha256":request.statement_sha256})
}

fn assert_recorded_approval(
    rig: &Rig,
    request: &BrokerActionRequestReply,
    fingerprint: &str,
    bytes: &[u8],
    actor: &str,
) {
    let conn = Connection::open(&rig.path).unwrap();
    let hash = format!("{:x}", Sha256::digest(bytes));
    let state: (i64, String, String, i64) = conn
        .query_row(
            "SELECT approved_at_ms, device_fingerprint, envelope_sha256, issued_legs
         FROM broker_action_requests WHERE request_id = ?1",
            [&request.request_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert!(state.0 < request.expires_at_ms as i64);
    assert_eq!(
        (state.1.as_str(), state.2.as_str(), state.3),
        (fingerprint, hash.as_str(), 0)
    );
    let audit: Vec<_> = rig
        .store
        .read_audit(None)
        .unwrap()
        .into_iter()
        .filter(|entry| entry.op == "broker_action_approve")
        .collect();
    assert_eq!(audit.len(), 1);
    let entry = &audit[0];
    assert_eq!(entry.credential_id.as_deref(), Some(APP));
    assert_eq!(entry.payload_hash.as_deref(), Some(hash.as_str()));
    assert_eq!(entry.actor, actor);
    assert!(!entry.alarm);
    assert_eq!(entry.alarm_reason, None);
}

fn approval_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

async fn approve_on_phone(
    rig: &Rig,
    params: Value,
    pairing: &str,
) -> crate::secret_phone::PhoneAnswer {
    crate::secret_phone::serve_with_lookup(
        Arc::clone(&rig.store), APPROVING_PHONE, Some("production"), OP_APPROVE_ACTION, &params,
        tokio::time::Instant::now() + crate::secret_phone::PHONE_OP_DEADLINE,
        async { Some(json!({"devices":[{"class":"phone","fingerprint":APPROVING_PHONE,"pairing_id":pairing}]})) },
    ).await
}

fn phone_approval_params(bytes: &[u8], key: &SigningKey) -> Value {
    json!({"envelope_b64url":BASE64_URL_SAFE_NO_PAD.encode(bytes),
        "signature_b64url":BASE64_URL_SAFE_NO_PAD.encode(sign(key, bytes))})
}

fn token_gate_clock(rig: &Rig) -> Arc<AtomicI64> {
    let clock = Arc::new(AtomicI64::new(NOW));
    let now = Arc::clone(&clock);
    *rig.surface.policy_tokens.clock.lock().unwrap() =
        Some(Arc::new(move || now.load(Ordering::SeqCst)));
    clock
}

fn approve_for_issue(rig: &Rig, request: &BrokerActionRequestReply) {
    let key = SigningKey::from_slice(&[51; 32]).unwrap();
    register_approver(rig, &key);
    let bytes = serde_json::to_vec(&envelope(request, APPROVING_PHONE, NOW)).unwrap();
    let signature = sign(&key, &bytes);
    assert_eq!(
        rig.store
            .secret_phone_operation(
                APPROVING_PHONE,
                Some("pair-A"),
                NOW,
                &PhoneOperation::BrokerActionApprove {
                    envelope: bytes,
                    signature
                },
                || true,
                || NOW,
            )
            .unwrap(),
        approval_reply(request),
    );
}

fn issue_params(request: &BrokerActionRequestReply) -> Value {
    let mut body = params();
    body["approval_request_id"] = json!(request.request_id);
    body["request_sha256"] = json!("1".repeat(64));
    body
}

fn issued_legs(rig: &Rig, request: &BrokerActionRequestReply) -> i64 {
    Connection::open(&rig.path)
        .unwrap()
        .query_row(
            "SELECT issued_legs FROM broker_action_requests WHERE request_id = ?1",
            [&request.request_id],
            |row| row.get(0),
        )
        .unwrap()
}

async fn invalid_issue_params(rig: &mut Rig, params: Value) {
    rig.request(caller("aft"), OP_POLICY_TOKEN, params, 1, 1)
        .await;
    let response = frame(rig).await;
    assert_eq!(response.header.ty, FrameType::Error);
    assert_eq!(body(&response)["code"], "invalid_params");
}

#[tokio::test]
async fn broker_action_token_shape_and_no_approval_precedence() {
    let (mut rig, github, _) = setup_actions();
    let request = mint_at(&rig, NOW).unwrap();
    let valid = issue_params(&request);
    let before = approval_snapshot(&rig);
    for malformed in [
        without(valid.clone(), "approval_request_id"),
        without(valid.clone(), "request_sha256"),
        changed(valid.clone(), "approval_request_id", json!("not-a-ulid")),
        changed(valid.clone(), "approval_request_id", json!(123)),
        changed(valid.clone(), "approval_request_id", Value::Null),
        changed(valid.clone(), "request_sha256", json!("a".repeat(63))),
        changed(valid.clone(), "request_sha256", json!("A".repeat(64))),
        changed(valid.clone(), "request_sha256", Value::Null),
        changed(params(), "request_sha256", Value::Null),
    ] {
        invalid_issue_params(&mut rig, malformed).await;
    }
    let malformed = changed(valid.clone(), "request_sha256", Value::Null);
    let not_found = refusal("not_found", "permanent");
    assert_eq!(
        rig.call("plexus", OP_POLICY_TOKEN, malformed.clone()).await,
        not_found
    );
    assert_eq!(
        rig.call(
            "aft",
            OP_POLICY_TOKEN,
            changed(malformed, "service", json!("other"))
        )
        .await,
        not_found
    );
    assert_eq!(
        rig.call(
            "aft",
            OP_POLICY_TOKEN,
            changed(params(), "resource", json!("org/unbound"))
        )
        .await,
        not_found
    );
    assert_eq!(
        rig.call("aft", OP_POLICY_TOKEN, params()).await,
        refusal("approval_required", "permanent")
    );
    // Even an unavailable approval table must not affect an active non-once kind.
    rig.sql("ALTER TABLE broker_action_requests RENAME TO unavailable_approvals");
    invalid_issue_params(
        &mut rig,
        changed(valid, "kind", json!("update_issue_comment")),
    )
    .await;
    rig.sql("ALTER TABLE unavailable_approvals RENAME TO broker_action_requests");
    assert_eq!(approval_snapshot(&rig), before);
    github.counts(0, 0);
}

#[tokio::test]
async fn broker_action_token_releases_only_the_next_approved_leg_and_audits_it() {
    let (mut rig, github, _) = setup_actions();
    let clock = token_gate_clock(&rig);
    grant(&rig, "plexus", APP, GrantOperation::PolicyToken);
    grant(&rig, "aft", "github_app:other", GrantOperation::PolicyToken);
    let request = rig
        .store
        .request_broker_action(Some("aft"), template(&one()), request_scope, || NOW)
        .unwrap();
    let first = issue_params(&request);
    let mut second = first.clone();
    second["request_sha256"] = json!("2".repeat(64));
    second["kind"] = json!(CLOSE);
    second["resource"] = json!("org/s");
    let invalid = refusal("approval_invalid", "permanent");
    let before = approval_snapshot(&rig);
    assert_eq!(
        rig.call("aft", OP_POLICY_TOKEN, first.clone()).await,
        invalid
    );
    assert_eq!(approval_snapshot(&rig), before);
    approve_for_issue(&rig, &request);

    let before = approval_snapshot(&rig);
    for (caller, bad) in [
        ("aft", second.clone()),
        (
            "aft",
            changed(first.clone(), "request_sha256", json!("3".repeat(64))),
        ),
        (
            "aft",
            changed(first.clone(), "identity", json!("github_app:other")),
        ),
        ("plexus", first.clone()),
    ] {
        assert_eq!(rig.call(caller, OP_POLICY_TOKEN, bad).await, invalid);
        assert_eq!(approval_snapshot(&rig), before);
    }
    github.counts(0, 0);
    clock.store(NOW + TTL - 1, Ordering::SeqCst);
    assert_eq!(
        rig.call("aft", OP_POLICY_TOKEN, first.clone()).await["token"],
        "fixture-token-1"
    );
    assert_eq!(issued_legs(&rig, &request), 1);
    let before = approval_snapshot(&rig);
    assert_eq!(rig.call("aft", OP_POLICY_TOKEN, first).await, invalid);
    assert_eq!(approval_snapshot(&rig), before);

    assert_eq!(
        rig.call("aft", OP_POLICY_TOKEN, second.clone()).await["token"],
        "fixture-token-2"
    );
    assert_eq!(issued_legs(&rig, &request), 2);
    let before = approval_snapshot(&rig);
    assert_eq!(rig.call("aft", OP_POLICY_TOKEN, second).await, invalid);
    assert_eq!(approval_snapshot(&rig), before);
    github.counts(2, 2);
    assert_eq!(first_uses(&rig), ["aft"]);
    let digest_order: Vec<_> = rig
        .store
        .read_audit(None)
        .unwrap()
        .into_iter()
        .filter_map(|entry| {
            if entry.op != "broker_action_issue" {
                return None;
            }
            assert_eq!(entry.credential_id.as_deref(), Some(APP));
            assert_eq!(entry.actor, "reserved:aft");
            assert!(!entry.alarm);
            assert_eq!(entry.alarm_reason, None);
            Some(entry.payload_hash.unwrap())
        })
        .collect();
    assert_eq!(digest_order, ["1".repeat(64), "2".repeat(64)]);
}

#[tokio::test]
async fn broker_action_token_two_prepared_calls_cannot_spend_the_same_leg() {
    let (mut rig, github, _) = setup_actions();
    token_gate_clock(&rig);
    let mut action = template(&one());
    action["legs"][1] = action["legs"][0].clone();
    action["fields"].as_array_mut().unwrap().remove(0);
    let approval = rig
        .store
        .request_broker_action(Some("aft"), action, request_scope, || NOW)
        .unwrap();
    approve_for_issue(&rig, &approval);
    let params = issue_params(&approval);
    let ingress = Ingress::new(&rig);
    ingress.bind(&rig, 1, "aft");
    let (posted, release) = github.stall_next_post();
    ingress
        .dispatch(&rig, request(OP_POLICY_TOKEN, params.clone(), 1, 10))
        .await;
    signal(posted).await;
    let (joined, waiting) = oneshot::channel();
    *rig.surface.policy_tokens.joined.lock().unwrap() = Some(joined);
    ingress
        .dispatch(&rig, request(OP_POLICY_TOKEN, params, 1, 11))
        .await;
    signal(waiting).await;
    assert_eq!(issued_legs(&rig, &approval), 0);
    release.send(()).unwrap();

    let first = frame(&mut rig).await;
    let second = frame(&mut rig).await;
    let mut correlations = [first.header.corr, second.header.corr];
    correlations.sort_unstable();
    assert_eq!(correlations, [10, 11]);
    let mut results = [
        body(&first)["result"].clone(),
        body(&second)["result"].clone(),
    ];
    results.sort_by_key(|reply| reply.get("token").is_some());
    assert_eq!(results[0], refusal("approval_invalid", "permanent"));
    assert_eq!(results[1]["token"], "fixture-token-1");
    assert_eq!(issued_legs(&rig, &approval), 1);
    github.counts(1, 1);
}

fn store_policy_without_approval(
    rig: &Rig,
    edit: impl FnOnce(&mut credentials_core::agent_policy::RuleSet),
) -> String {
    let mut policy = rollout_policy(rig);
    let mut rules = github_default_rule_set().unwrap();
    edit(&mut rules);
    policy.rule_sets.insert("github".into(), rules);
    let digest = manifest_with_bindings(rig, 42, json!({"org/r":"agent", "org/s":"agent"}));
    sign_rollout(rig, 42, &policy);
    digest
}

fn activate_policy_without_approval(rig: &Rig) {
    let digest = store_policy_without_approval(rig, |_| {});
    ready(rig, SELF, 42, &digest);
}

#[tokio::test]
async fn broker_action_token_rollout_keeps_approval_bound_to_ready_policy_when_newer_requires_less()
{
    let (mut rig, github, old) = setup_actions();
    admit_peer(&rig);
    ready(&rig, OTHER, 41, &old);
    let next = store_policy_without_approval(&rig, |_| {});
    ready(&rig, SELF, 42, &next);
    token_gate_clock(&rig);
    let approval = mint_at(&rig, NOW).unwrap();
    approve_for_issue(&rig, &approval);
    let params = issue_params(&approval);
    assert_eq!(params["policy_version"], 1);
    assert_eq!(
        rig.call("aft", OP_POLICY_TOKEN, params).await["token"],
        "fixture-token-1"
    );
    assert_eq!(issued_legs(&rig, &approval), 1);
    github.counts(1, 1);
}

#[tokio::test]
async fn broker_action_token_rollout_fences_an_approved_leg_removed_during_mint() {
    let (mut rig, github, _) = setup_actions();
    token_gate_clock(&rig);
    let approval = mint_at(&rig, NOW).unwrap();
    approve_for_issue(&rig, &approval);
    let ingress = Ingress::new(&rig);
    ingress.bind(&rig, 1, "aft");
    let (posted, release) = github.stall_next_post();
    let params = issue_params(&approval);
    ingress
        .dispatch(&rig, request(OP_POLICY_TOKEN, params.clone(), 1, 10))
        .await;
    signal(posted).await;
    store_policy_without_approval(&rig, |rules| {
        rules.kinds.retain(|kind| kind.kind != COMMENT);
        rules.actions.clear();
    });
    release.send(()).unwrap();
    assert_eq!(reply(&mut rig, 10).await, refusal("not_found", "permanent"));
    assert_eq!(
        rig.call("aft", OP_POLICY_TOKEN, params).await,
        refusal("not_found", "permanent")
    );
    assert_eq!(issued_legs(&rig, &approval), 0);
    assert!(first_uses(&rig).is_empty());
    github.counts(1, 1);
}

#[tokio::test]
async fn broker_action_token_policy_change_precedes_version_refusal_in_prepare_and_handoff() {
    let (mut rig, github, _) = setup_actions();
    token_gate_clock(&rig);
    let approval = mint_at(&rig, NOW).unwrap();
    approve_for_issue(&rig, &approval);
    let params = issue_params(&approval);
    let ingress = Ingress::new(&rig);
    ingress.bind(&rig, 1, "aft");
    let (posted, release) = github.stall_next_post();
    ingress
        .dispatch(&rig, request(OP_POLICY_TOKEN, params.clone(), 1, 10))
        .await;
    signal(posted).await;
    activate_policy_without_approval(&rig);
    let before = approval_snapshot(&rig);
    release.send(()).unwrap();
    let expected = refusal("approval_policy_changed", "permanent");
    assert_eq!(reply(&mut rig, 10).await, expected);
    assert_eq!(
        rig.call("aft", OP_POLICY_TOKEN, params.clone()).await,
        expected
    );
    invalid_issue_params(&mut rig, changed(params, "policy_version", json!(2))).await;
    assert_eq!(approval_snapshot(&rig), before);
    github.counts(1, 1);
}

#[tokio::test]
async fn broker_action_token_expiry_at_handoff_and_prepare_writes_nothing() {
    let (mut rig, github, _) = setup_actions();
    let clock = token_gate_clock(&rig);
    let approval = mint_at(&rig, NOW).unwrap();
    approve_for_issue(&rig, &approval);
    let params = issue_params(&approval);
    let ingress = Ingress::new(&rig);
    ingress.bind(&rig, 1, "aft");
    let (posted, release) = github.stall_next_post();
    ingress
        .dispatch(&rig, request(OP_POLICY_TOKEN, params.clone(), 1, 10))
        .await;
    signal(posted).await;
    clock.store(approval.expires_at_ms as i64, Ordering::SeqCst);
    let before = approval_snapshot(&rig);
    release.send(()).unwrap();
    let invalid = refusal("approval_invalid", "permanent");
    assert_eq!(reply(&mut rig, 10).await, invalid);
    assert_eq!(rig.call("aft", OP_POLICY_TOKEN, params).await, invalid);
    assert_eq!(approval_snapshot(&rig), before);
    github.counts(1, 1);
}

#[tokio::test]
async fn broker_action_token_record_change_and_provider_failure_leave_the_leg_unspent() {
    let (mut rig, github, _) = setup_actions();
    token_gate_clock(&rig);
    let approval = mint_at(&rig, NOW).unwrap();
    approve_for_issue(&rig, &approval);
    let params = issue_params(&approval);
    let ingress = Ingress::new(&rig);
    ingress.bind(&rig, 1, "aft");
    let (posted, release) = github.stall_next_post();
    let (retry_posted, retry_release) = github.stall_next_post();
    ingress
        .dispatch(&rig, request(OP_POLICY_TOKEN, params.clone(), 1, 10))
        .await;
    signal(posted).await;
    replace_record(&rig, false);
    let before = approval_snapshot(&rig);
    release.send(()).unwrap();
    signal(retry_posted).await;
    assert_eq!(approval_snapshot(&rig), before);
    github
        .exchange_faults
        .lock()
        .unwrap()
        .push_back((403, json!({"message":"provider refusal"})));
    retry_release.send(()).unwrap();
    assert_eq!(
        reply(&mut rig, 10).await,
        refusal("github_unavailable", "transient")
    );
    assert_eq!(approval_snapshot(&rig), before);
    assert_eq!(
        rig.call("aft", OP_POLICY_TOKEN, params).await["token"],
        "fixture-token-3"
    );
    assert_eq!(issued_legs(&rig, &approval), 1);
    github.counts(3, 3);
}

#[tokio::test]
async fn broker_action_token_failed_issue_audit_rolls_back_the_release() {
    let (mut rig, github, _) = setup_actions();
    token_gate_clock(&rig);
    let approval = mint_at(&rig, NOW).unwrap();
    approve_for_issue(&rig, &approval);
    let params = issue_params(&approval);
    rig.sql("CREATE TRIGGER fail_issue_audit BEFORE INSERT ON audit_log WHEN NEW.op = 'broker_action_issue' BEGIN SELECT RAISE(ABORT, 'test issue write failure'); END");
    let before = approval_snapshot(&rig);
    assert_eq!(
        rig.call("aft", OP_POLICY_TOKEN, params.clone()).await,
        refusal("store_error", "transient")
    );
    assert_eq!(approval_snapshot(&rig), before);
    rig.sql("DROP TRIGGER fail_issue_audit");
    assert_eq!(
        rig.call("aft", OP_POLICY_TOKEN, params).await["token"],
        "fixture-token-2"
    );
    assert_eq!(issued_legs(&rig, &approval), 1);
    github.counts(2, 2);
}

#[tokio::test]
async fn broker_action_phone_checks_registered_key_and_binding_and_records_only_once() {
    let (rig, _, _) = setup_actions();
    let key = SigningKey::from_slice(&[51; 32]).unwrap();
    let other_key = SigningKey::from_slice(&[52; 32]).unwrap();
    register_approver(&rig, &key);
    let created = approval_now();
    let request = mint_at(&rig, created).unwrap();
    let canonical = envelope(&request, APPROVING_PHONE, created);
    let bytes = serde_json::to_vec(&canonical).unwrap();
    let valid = phone_approval_params(&bytes, &key);
    let before = approval_snapshot(&rig);
    let invalid = SecretError::ApprovalInvalid.body();
    let check = |answer| match answer {
        crate::secret_phone::PhoneAnswer::Reply(value) => value,
        _ => panic!("expected a broker action approval result"),
    };

    assert_eq!(
        check(approve_on_phone(&rig, valid.clone(), "new-pair").await),
        invalid
    );
    assert_eq!(approval_snapshot(&rig), before);
    assert_eq!(
        check(approve_on_phone(&rig, phone_approval_params(&bytes, &other_key), "pair-A").await),
        invalid
    );
    assert_eq!(approval_snapshot(&rig), before);

    for (label, bad) in [
        (
            "wrong digest",
            changed(canonical.clone(), "statement_sha256", json!("a".repeat(64))),
        ),
        (
            "wrong fingerprint",
            changed(
                canonical.clone(),
                "device_fingerprint",
                json!(DEVELOPMENT_DESKTOP),
            ),
        ),
        (
            "wrong domain",
            changed(
                canonical.clone(),
                "v",
                json!("ck-manifest-binding-envelope/v1"),
            ),
        ),
        (
            "non-allow",
            changed(canonical.clone(), "decision", json!("decline")),
        ),
        (
            "bad request id",
            changed(
                canonical.clone(),
                "request_id",
                json!("81HF7YAT000000000000000004"),
            ),
        ),
        (
            "missing request",
            changed(
                canonical.clone(),
                "request_id",
                json!("01HF7YAT000000000000000004"),
            ),
        ),
        (
            "unknown member",
            changed(canonical.clone(), "proposal_id", json!(request.request_id)),
        ),
        (
            "before creation",
            changed(canonical.clone(), "issued_at_ms", json!(created - 1)),
        ),
    ] {
        let params = phone_approval_params(&serde_json::to_vec(&bad).unwrap(), &key);
        assert_eq!(
            check(approve_on_phone(&rig, params, "pair-A").await),
            invalid,
            "{label}"
        );
        assert_eq!(approval_snapshot(&rig), before, "{label}");
    }
    let mut duplicate = bytes.clone();
    duplicate.pop();
    duplicate.extend(br#", "decision":"allow"}"#);
    for bad_bytes in [serde_json::to_vec_pretty(&canonical).unwrap(), duplicate] {
        assert_eq!(
            check(approve_on_phone(&rig, phone_approval_params(&bad_bytes, &key), "pair-A").await),
            invalid
        );
        assert_eq!(approval_snapshot(&rig), before);
    }

    let reply = approval_reply(&request);
    assert_eq!(
        check(approve_on_phone(&rig, valid.clone(), "pair-A").await),
        reply
    );
    let recorded = approval_snapshot(&rig);
    let retry = changed(valid, "card_ref", json!("different-card-ref"));
    assert_eq!(check(approve_on_phone(&rig, retry, "pair-A").await), reply);
    let different = changed(canonical, "issued_at_ms", json!(created + 1));
    let params = phone_approval_params(&serde_json::to_vec(&different).unwrap(), &key);
    assert_eq!(
        check(approve_on_phone(&rig, params, "pair-A").await),
        invalid
    );
    assert_eq!(approval_snapshot(&rig), recorded);
    assert_recorded_approval(
        &rig,
        &request,
        APPROVING_PHONE,
        &bytes,
        &format!("fed-phone:{APPROVING_PHONE}/approver:fed-phone:{APPROVING_PHONE}"),
    );
}

#[test]
fn broker_action_approval_checks_expiry_and_both_edges_of_the_skew_window() {
    let (rig, _, _) = setup_actions();
    let key = SigningKey::from_slice(&[51; 32]).unwrap();
    register_approver(&rig, &key);
    let request = mint_at(&rig, NOW).unwrap();
    let expires = request.expires_at_ms as i64;
    let approve = |request, issued, now| {
        let bytes = serde_json::to_vec(&envelope(request, APPROVING_PHONE, issued)).unwrap();
        let signature = sign(&key, &bytes);
        rig.store.secret_phone_operation(
            APPROVING_PHONE,
            Some("pair-A"),
            now,
            &PhoneOperation::BrokerActionApprove {
                envelope: bytes,
                signature,
            },
            || true,
            || now,
        )
    };
    let skew = SECRET_ISSUE_SKEW_LIMIT_MS;
    let now = expires - 2 * skew;
    let before = approval_snapshot(&rig);
    for (signed_at, attempted_at) in [
        (expires - 1, expires),
        (expires, expires - 1),
        (now + skew + 1, now),
        (now - skew - 1, now),
    ] {
        assert_eq!(
            approve(&request, signed_at, attempted_at),
            Err(SecretError::ApprovalInvalid)
        );
        assert_eq!(approval_snapshot(&rig), before);
    }
    let other = mint_at(&rig, NOW).unwrap();
    assert_eq!(
        approve(&request, now - skew, now).unwrap(),
        approval_reply(&request)
    );
    assert_eq!(
        approve(&other, now + skew, now).unwrap(),
        approval_reply(&other)
    );

    let last = mint_at(&rig, NOW).unwrap();
    let reply = approval_reply(&last);
    assert_eq!(approve(&last, expires - 1, expires - 1).unwrap(), reply);
    let recorded = approval_snapshot(&rig);
    assert_eq!(approve(&last, expires - 1, expires).unwrap(), reply);
    assert_eq!(
        approve(&last, expires - 1, expires + skew),
        Err(SecretError::ApprovalInvalid)
    );
    assert_eq!(approval_snapshot(&rig), recorded);
}

async fn approve_on_route(rig: &Rig, params: Value) -> (FrameType, Value) {
    let (kind, bytes) =
        crate::tests::routed_reply(&rig.surface, &rig.admin, 77, OP_APPROVE_ACTION, params).await;
    (kind, serde_json::from_slice(&bytes).unwrap())
}

#[tokio::test]
async fn broker_action_approval_route_requires_production_phone_or_enabled_development_desktop() {
    let (rig, _, _) = setup_actions();
    let created = approval_now();
    let request = mint_at(&rig, created).unwrap();
    let bytes = serde_json::to_vec(&envelope(&request, DEVELOPMENT_DESKTOP, created)).unwrap();
    let params =
        json!({"envelope_b64url":BASE64_URL_SAFE_NO_PAD.encode(&bytes), "card_ref":"desktop-card"});
    let direct = subc_protocol::Principal::Direct;
    rig.admin.record_bind_at(77, 1, direct.clone(), "");
    let not_found = (FrameType::Response, crate::uniform_not_found());
    assert_eq!(approve_on_route(&rig, params.clone()).await, not_found);

    rig.store
        .set_secret_dev_desktop_approvals_audited(
            true,
            AuditCtx::admin(AuditOp::SecretDevDesktopApprovalsSet),
        )
        .unwrap();
    rig.store
        .set_federation_member_mapping_audited(true, AuditCtx::admin(AuditOp::FederationGateSet))
        .unwrap();
    rig.store
        .set_secret_phone_mapping_audited(true, AuditCtx::admin(AuditOp::SecretPhoneGateSet))
        .unwrap();
    let callosum = subc_protocol::Principal::Reserved {
        module_id: "callosum".into(),
    };
    let reserved = subc_protocol::Principal::Reserved {
        module_id: "aft".into(),
    };
    let harness = format!("fed-phone:{APPROVING_PHONE}");
    let scope = subc_protocol::scope::ScopeStamp::new(
        direct.clone(),
        "tool",
        1,
        subc_protocol::scope::ScopeKind::Head,
    );

    let before = approval_snapshot(&rig);
    for (principal, route, scope, build) in [
        (reserved, "", None, None),
        (direct.clone(), "", Some(&scope), None),
        (direct.clone(), harness.as_str(), None, Some("production")),
        (callosum.clone(), SELF, None, Some("production")),
        (callosum.clone(), harness.as_str(), None, None),
        (
            callosum.clone(),
            harness.as_str(),
            None,
            Some("development"),
        ),
    ] {
        rig.admin.record_connector_bind(
            77,
            1,
            principal,
            route,
            None,
            scope,
            None,
            build.map(str::to_owned),
        );
        assert_eq!(approve_on_route(&rig, Value::Null).await, not_found);
    }

    rig.admin.record_connector_bind(
        77,
        1,
        callosum,
        &harness,
        None,
        None,
        None,
        Some("production".into()),
    );
    let (kind, body) = approve_on_route(&rig, Value::Null).await;
    assert_eq!(kind, FrameType::Error);
    assert_eq!(body["code"], "invalid_params");

    rig.admin.record_bind_at(77, 1, direct, "");
    for signature in [Value::Null, json!(""), json!("AA")] {
        let (kind, body) =
            approve_on_route(&rig, changed(params.clone(), "signature_b64url", signature)).await;
        assert_eq!(kind, FrameType::Error);
        assert_eq!(body["code"], "invalid_params");
    }
    let wrong = serde_json::to_vec(&envelope(&request, APPROVING_PHONE, created)).unwrap();
    assert_eq!(
        approve_on_route(
            &rig,
            changed(
                params.clone(),
                "envelope_b64url",
                json!(BASE64_URL_SAFE_NO_PAD.encode(wrong))
            )
        )
        .await,
        (
            FrameType::Response,
            json!({"result":SecretError::ApprovalInvalid.body()})
        )
    );
    assert_eq!(approval_snapshot(&rig), before);

    let approved = (
        FrameType::Response,
        json!({"result":approval_reply(&request)}),
    );
    assert_eq!(approve_on_route(&rig, params.clone()).await, approved);
    let recorded = approval_snapshot(&rig);
    assert_eq!(approve_on_route(&rig, params).await, approved);
    assert_eq!(approval_snapshot(&rig), recorded);
    assert_recorded_approval(
        &rig,
        &request,
        DEVELOPMENT_DESKTOP,
        &bytes,
        "desktop-development",
    );
}

#[test]
fn broker_action_approval_is_rolled_back_if_the_audit_append_fails() {
    let (rig, _, _) = setup_actions();
    rig.store
        .set_secret_dev_desktop_approvals_audited(
            true,
            AuditCtx::admin(AuditOp::SecretDevDesktopApprovalsSet),
        )
        .unwrap();
    let request = mint_at(&rig, NOW).unwrap();
    let bytes = serde_json::to_vec(&envelope(&request, DEVELOPMENT_DESKTOP, NOW)).unwrap();
    let before = approval_snapshot(&rig);
    rig.sql("CREATE TRIGGER reject_approval BEFORE INSERT ON audit_log
        WHEN NEW.op = 'broker_action_approve' BEGIN SELECT RAISE(ABORT, 'blocked test insert'); END;");
    assert_eq!(
        rig.store.broker_action_dev_desktop_approval(&bytes, || NOW),
        Err(SecretError::ApprovalInvalid)
    );
    assert_eq!(approval_snapshot(&rig), before);
    rig.sql("DROP TRIGGER reject_approval");
    assert_eq!(
        rig.store
            .broker_action_dev_desktop_approval(&bytes, || NOW)
            .unwrap(),
        approval_reply(&request)
    );
    assert_recorded_approval(
        &rig,
        &request,
        DEVELOPMENT_DESKTOP,
        &bytes,
        "desktop-development",
    );
}

fn seed_pending(rig: &Rig, count: usize) {
    seed_pending_for(rig, count, None);
}

fn seed_pending_for(rig: &Rig, count: usize, agent: Option<&str>) {
    let mut db = Connection::open(&rig.path).unwrap();
    let tx = db.transaction().unwrap();
    for i in 0..count {
        tx.execute("INSERT INTO broker_action_requests (
                        request_id, principal, agent_id, scope_json, statement_bytes, statement_sha256,
                        policy_version, identity, legs_json, created_at_ms, expires_at_ms
                    ) VALUES (?1, 'reserved:plexus', ?2, '{}', X'00', 'digest', 1, ?3, '[{}]', ?4, ?5)",
            rusqlite::params![format!("{i:026}"), agent.map(str::to_owned).unwrap_or_else(|| format!("other-agent-{i}")), APP, NOW, NOW + TTL]).unwrap();
    }
    tx.commit().unwrap();
}

#[tokio::test]
async fn broker_action_mint_accepts_16_pending_per_agent_and_refuses_17() {
    let (mut rig, _, _) = setup_actions();
    let now = crate::read_surface::now_ms();
    let mut prior = String::new();
    for _ in 0..16 {
        let id = mint_at(&rig, now).unwrap().request_id;
        assert!(id > prior);
        prior = id;
    }
    refuses(
        &mut rig,
        "aft",
        one(),
        "approval_pending_limit",
        "transient",
    )
    .await;
    let mut oversized = one();
    oversized["fields"][0]["value"] = json!("x".repeat(524_288));
    invalid(&mut rig, oversized).await;
    // A completed single leg is not pending, even though its request has not expired.
    rig.sql("UPDATE broker_action_requests SET approved_at_ms = created_at_ms, device_fingerprint = 'phone',
             envelope_sha256 = 'envelope', issued_legs = 1 WHERE request_id = (SELECT MIN(request_id) FROM broker_action_requests)");
    assert!(mint_at(&rig, now).is_ok());
}

#[test]
fn broker_action_mint_accepts_256_pending_overall_and_refuses_257() {
    let (rig, _, _) = setup_actions();
    seed_pending(&rig, 255);
    assert!(mint_at(&rig, NOW).is_ok());
    let before = state(&rig);
    assert_eq!(
        mint_at(&rig, NOW).err(),
        Some(BrokerActionRequestError::PendingLimit)
    );
    assert_eq!(state(&rig), before);
}

#[test]
fn broker_action_pending_counts_until_but_not_at_the_ten_minute_deadline() {
    let (rig, _, _) = setup_actions();
    for _ in 0..16 {
        assert_eq!(
            mint_at(&rig, NOW).unwrap().expires_at_ms,
            (NOW + TTL) as u64
        );
    }
    // Approval without issuance is still pending.
    rig.sql("UPDATE broker_action_requests SET approved_at_ms = created_at_ms, device_fingerprint = 'phone', envelope_sha256 = 'envelope'");
    let before = state(&rig);
    assert_eq!(
        mint_at(&rig, NOW + TTL - 1).err(),
        Some(BrokerActionRequestError::PendingLimit)
    );
    assert_eq!(state(&rig), before);
    assert!(mint_at(&rig, NOW + TTL).is_ok());
}

#[test]
fn broker_action_mint_audit_failure_rolls_back_prune_and_insert_and_ids_do_not_go_backwards() {
    let (rig, _, _) = setup_actions();
    let old = mint_at(&rig, NOW).unwrap().request_id;
    let after_retention = NOW + TTL + 86_400_001;
    rig.sql("CREATE TRIGGER fail_broker_audit BEFORE INSERT ON audit_log WHEN NEW.op = 'broker_action_request'
             BEGIN SELECT RAISE(ABORT, 'test audit failure'); END;");
    let before = state(&rig);
    assert_eq!(
        mint_at(&rig, after_retention).err(),
        Some(BrokerActionRequestError::StoreError)
    );
    assert_eq!(state(&rig), before);
    let db = Connection::open(&rig.path).unwrap();
    let stored: String = db
        .query_row("SELECT request_id FROM broker_action_requests", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(stored, old);
    rig.sql("DROP TRIGGER fail_broker_audit");
    let new = mint_at(&rig, after_retention).unwrap().request_id;
    let after_rollback = mint_at(&rig, NOW).unwrap().request_id;
    assert!(old < new && new < after_rollback);
    let stored: u32 = db
        .query_row(
            "SELECT COUNT(*) FROM broker_action_requests WHERE request_id = ?1",
            [old],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(stored, 0);
}
