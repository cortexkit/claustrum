use super::*;
use crate::broker_action::{request_scope, OP_REQUEST_ACTION};
use credentials_core::{
    agent_policy::{policy_sha256, Consent},
    broker_action::{check_statement, valid_ulid},
    store::{BrokerActionRequestError, BrokerActionRequestReply},
};
use sha2::{Digest, Sha256};

const NOW: i64 = 1_800_000_000_000;
const TTL: i64 = 600_000;
const FIELD_CANARY: &str = "uniquely-sensitive-field-text";
const CONTEXT_CANARY: &str = "uniquely-sensitive-command-text";
const STAMP_CANARY: &str = "uniquely-sensitive-scope-ref";
const COMMENT: &str = "add_issue_comment";
const CLOSE: &str = "close_issue";

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

fn seed_pending(rig: &Rig, count: usize) {
    let mut db = Connection::open(&rig.path).unwrap();
    let tx = db.transaction().unwrap();
    for i in 0..count {
        tx.execute("INSERT INTO broker_action_requests (
                        request_id, principal, agent_id, scope_json, statement_bytes, statement_sha256,
                        policy_version, identity, legs_json, created_at_ms, expires_at_ms
                    ) VALUES (?1, 'reserved:plexus', ?2, '{}', X'00', 'digest', 1, ?3, '[{}]', ?4, ?5)",
            rusqlite::params![format!("{i:026}"), format!("other-agent-{i}"), APP, NOW, NOW + TTL]).unwrap();
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
