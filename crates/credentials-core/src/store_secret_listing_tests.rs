// Flow grants as the three listings render them: the provider's `permissions.list`, the
// phone's `secret.list` and the operator's `ck auth secret` reader.
use super::super::phone;
use super::*;
use crate::agent_secret::{self, SecretMaterial, SecretScope, SecretUse};
use crate::secret::Secret;
use crate::store::PhoneOperation;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};

const FP: &str = "11111111111111111111111111111111";
const MEMBER: &str = "fed-computer:22222222222222222222222222222222";
const INC: &str = "00000000000000000000000000000001";
const LOGIN_INC: &str = "00000000000000000000000000000002";
const NOW: i64 = 1_700_000_000_000;
const CODE_HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn signer() -> SigningKey {
    SigningKey::from_bytes((&[7u8; 32]).into()).unwrap()
}

/// A vault whose self member and registered phone let a real approval through.
fn list_setup(tag: &str) -> (crate::test_support::TestTempDir, Arc<EncryptedStore>) {
    let (root, store) = rig(tag, 94);
    store.ensure_secret_deposit_key().unwrap();
    store
        .set_federation_self_member_audited(MEMBER, AuditCtx::admin(AuditOp::FederationSelfSet))
        .unwrap();
    phone(
        &store,
        &PhoneOperation::Register {
            deposit_pub: vec![2; 32],
            approval_pub: signer()
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec(),
        },
        NOW,
    )
    .unwrap();
    (root, Arc::new(store))
}

fn phone(
    store: &EncryptedStore,
    op: &PhoneOperation,
    now: i64,
) -> Result<Value, agent_secret::SecretError> {
    store.secret_phone_operation(FP, Some("pair-A"), now, op, || true, || now)
}

fn envelope(items: Vec<Value>, duration: &str, issued: i64) -> Value {
    json!({"v":"ck-secret-use-envelope/v1","items":items,"decision":"allow","duration":duration,"grant_expires_at_ms":0,"device_fingerprint":FP,"issued_at_ms":issued})
}

fn signed(envelope: &Value, delete: bool) -> PhoneOperation {
    let bytes = serde_json::to_vec(envelope).unwrap();
    let signature: Signature = signer().sign(&bytes);
    let signature = signature.to_der().as_bytes().to_vec();
    if delete {
        PhoneOperation::DeleteCommit {
            envelope: bytes,
            signature,
        }
    } else {
        PhoneOperation::Approve {
            envelope: bytes,
            signature,
            card_ref: None,
        }
    }
}

fn scope() -> SecretScope {
    SecretScope::ApiKey {
        host: "x.test".into(),
        path_prefix: Some("/repos/a".into()),
        location: "header:X-Api-Key".into(),
    }
}

fn call() -> SecretUse {
    SecretUse {
        name: "key".into(),
        sender: agent_secret::SecretSender::Aft,
        scope: agent_secret::AskingScope {
            owner: "reserved:prefrontal-core".into(),
            kind: "head".into(),
            scope_ref: "H".into(),
            epoch: 7,
        },
        worker_parent: None,
        coverage: "scope".into(),
        agent_id: Some("agent-A".into()),
        target: agent_secret::UseTarget::ApiKey {
            scheme: "https".into(),
            host: "x.test".into(),
            port: 443,
            path: "/repos/a/canary-token".into(),
        },
    }
}

fn seed(store: &EncryptedStore, name: &str, scope: &SecretScope, material: &SecretMaterial) {
    let incarnation = incarnation(name);
    let blob = agent_secret::seal(&store.key, incarnation, name, scope, material).unwrap();
    let (host, prefix, location, origin) = phone::columns(scope);
    store
        .fenced_write(|tx| {
            tx.execute("INSERT INTO agent_secrets (name,kind,incarnation,state,host,path_prefix,location,origin,record_version,key_id,envelope,created_at_ms) VALUES (?1,?2,?3,'active',?4,?5,?6,?7,1,?8,?9,?10)", rusqlite::params![name, scope.kind(), incarnation, host, prefix, location, origin, store.key_id.to_hex(), blob, NOW]).map(|_| ())
        })
        .unwrap();
}

fn use_reply(store: &EncryptedStore, call: &SecretUse, now: i64) -> Value {
    store
        .secret_use(call, || now)
        .map_or_else(|e| e.body(), |o| o.reply)
}

fn seed_secret(store: &EncryptedStore, name: &str, incarnation: &str, login: bool) {
    store
        .store
        .with_conn(|conn| {
            if login {
                conn.execute(
                    "INSERT INTO agent_secrets (name,kind,incarnation,state,origin,record_version,key_id,envelope,created_at_ms) VALUES (?1,'site_login',?2,'active','https://x.test',1,'key',x'00',1)",
                    rusqlite::params![name, incarnation],
                )?;
            } else {
                conn.execute(
                    "INSERT INTO agent_secrets (name,kind,incarnation,state,host,path_prefix,location,record_version,key_id,envelope,created_at_ms) VALUES (?1,'agent_api_key',?2,'active','x.test','/repos/a','authorization_bearer',1,'key',x'00',1)",
                    rusqlite::params![name, incarnation],
                )?;
            }
            Ok(())
        })
        .unwrap();
}

/// One live flow grant, written directly: these listings are plaintext readers, and the
/// signed-envelope path that creates the same row in production is covered separately.
fn incarnation(name: &str) -> &'static str {
    if name == "key" {
        INC
    } else {
        LOGIN_INC
    }
}

fn seed_flow_grant(store: &EncryptedStore, grant_id: &str, name: &str, install: &str) {
    store
        .store
        .with_conn(|conn| {
            conn.execute(
                "INSERT INTO secret_flow_grants (grant_id,secret_name,incarnation,flow_id,flow_version,flow_code_hash,flow_install_id,methods,granted_at_ms,envelope_sha256,card_ref,last_use_ms) VALUES (?1,?2,?3,'daily-fetch',7,?4,?5,'[\"GET\"]',10,?6,'flow-card',12)",
                rusqlite::params![grant_id, name, incarnation(name), CODE_HASH, install, format!("{grant_id:0>64}")],
            )?;
            Ok(())
        })
        .unwrap();
}

fn seed_agent_grant(store: &EncryptedStore, grant_id: &str, name: &str, agent: Option<&str>) {
    store
        .store
        .with_conn(|conn| {
            conn.execute(
                "INSERT INTO secret_grants (grant_id,secret_name,incarnation,scope_owner,scope_kind,scope_ref,coverage,duration,expires_at_ms,granted_at_ms,envelope_sha256,agent_id) VALUES (?1,?2,?3,'reserved:prefrontal-core','head','H','scope','permanent',0,10,'digest',?4)",
                rusqlite::params![grant_id, name, incarnation(name), agent],
            )?;
            Ok(())
        })
        .unwrap();
}

/// permissions/v1 has a closed holder set and the phone decodes rows strictly, so a flow
/// row could drop the whole page. Until the contract gains a flow holder, flow grants
/// stay out of `permissions.list`, filtered or not, while agent grants keep their shape.
#[test]
fn permissions_list_leaves_flow_grants_out_until_the_contract_has_a_flow_holder() {
    let (_root, store) = rig("flow-permissions-list", 91);
    seed_secret(&store, "key", INC, false);
    seed_secret(&store, "login", LOGIN_INC, true);
    seed_agent_grant(&store, "agent-grant", "key", Some("agent-A"));
    seed_flow_grant(&store, "flow-a", "key", "install-A");
    seed_flow_grant(&store, "flow-b", "login", "install-B");
    for filter in [None, Some("agent-A")] {
        let listed = store.secret_permissions_list(filter, NOW).unwrap();
        let rows = listed["grants"].as_array().unwrap();
        assert_eq!(rows.len(), 1, "{listed}");
        assert_eq!(rows[0]["id"], "agent-grant");
        assert_eq!(rows[0]["holder"]["kind"], "agent");
    }
}

#[test]
fn secret_list_carries_an_agents_id_and_a_flows_identity() {
    let (_root, store) = rig("flow-secret-list", 93);
    seed_secret(&store, "key", INC, false);
    seed_secret(&store, "login", LOGIN_INC, true);
    seed_agent_grant(&store, "agent-grant", "key", Some("agent-A"));
    seed_agent_grant(&store, "anonymous-grant", "login", None);
    seed_flow_grant(&store, "flow-a", "key", "install-A");
    let listed = store.secret_phone_operation(
        FP,
        Some("pair-A"),
        NOW,
        &PhoneOperation::List,
        || true,
        || NOW,
    );
    // The phone preflight refuses an unregistered device, which is the only reason this
    // store answers without a registered key: check that too, then register and list.
    assert!(listed.is_err(), "{listed:?}");
    store
        .store
        .with_conn(|conn| {
            conn.execute(
                "INSERT INTO secret_phone_keys (fingerprint,pairing_id,deposit_pub,approval_pub,created_at_ms) VALUES (?1,'pair-A',zeroblob(32),zeroblob(65),1)",
                [FP],
            )?;
            Ok(())
        })
        .unwrap();
    let listed = store
        .secret_phone_operation(
            FP,
            Some("pair-A"),
            NOW,
            &PhoneOperation::List,
            || true,
            || NOW,
        )
        .unwrap();
    let secrets = listed["secrets"].as_array().unwrap();
    let key = secrets.iter().find(|s| s["name"] == "key").unwrap();
    let login = secrets.iter().find(|s| s["name"] == "login").unwrap();
    assert_eq!(key["grants"][0]["agent_id"], "agent-A");
    // An agent-less grant still names the key, as null, so the phone can render one shape.
    assert_eq!(login["grants"][0]["agent_id"], Value::Null);
    assert!(login["grants"][0].get("agent_id").is_some());
    let flow = &key["flow_grants"][0];
    assert_eq!(
        flow,
        &json!({
            "grant_id":"flow-a",
            "flow":{"flow_id":"daily-fetch","version":7,"install_id":"install-A"},
            "duration":"version",
            "methods":["GET"],
            "last_use_ms":12
        })
    );
    assert!(flow.get("scope").is_none() && flow.get("coverage").is_none());
    assert!(flow.get("expires_at_ms").is_none());
    assert!(login["flow_grants"].as_array().unwrap().is_empty());
}

#[test]
fn a_grant_approved_for_an_agent_lists_that_exact_agent_id() {
    // The seeded grants above exercise the reader; this one starts from the statement an
    // agent really asks for, so `secret.list` cannot drift from what the approval stored.
    let (_root, store) = list_setup("flow-agent-id");
    seed(
        &store,
        "key",
        &scope(),
        &SecretMaterial::ApiKey(Secret::new(b"material-canary".to_vec())),
    );
    let request = use_reply(&store, &call(), NOW);
    assert_eq!(request["status"], "approval_required", "{request}");
    let statement = URL_SAFE_NO_PAD
        .decode(request["statement_b64url"].as_str().unwrap())
        .unwrap();
    let envelope = envelope(
        vec![json!({
            "request_id":request["request_id"],
            "statement_sha256":phone::hex(&payload_hash(&statement)),
        })],
        "permanent",
        NOW,
    );
    let approved = phone(&store, &signed(&envelope, false), NOW).unwrap();
    assert_eq!(approved["results"][0]["outcome"], "granted", "{approved}");
    let stored_agent: Option<String> = store
        .store
        .with_conn(|conn| conn.query_row("SELECT agent_id FROM secret_grants", [], |r| r.get(0)))
        .unwrap();
    assert_eq!(stored_agent.as_deref(), Some("agent-A"));
    let listed = store
        .secret_phone_operation(
            FP,
            Some("pair-A"),
            NOW,
            &PhoneOperation::List,
            || true,
            || NOW,
        )
        .unwrap();
    assert_eq!(listed["secrets"][0]["grants"][0]["agent_id"], "agent-A");
}
