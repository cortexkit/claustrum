use super::*;
use crate::policy_token::OP_POLICY_TOKEN;
use async_trait::async_trait;
use credentials_core::{
    agent_policy::{github_default_rule_set, AgentPolicy, Approval, Class, Identity, Kind},
    federation::NewRemoteRecord,
    oauth::OAuthCredential,
    refresh_adapters::{github_app::INSTALLATIONS_URL, HttpResponse, HttpTransport, RefreshError},
    store::{GitHubAppCreation, GrantOperation, SelectorKind},
};
use std::{
    collections::VecDeque,
    sync::atomic::{AtomicI64, AtomicUsize, Ordering},
};

#[path = "broker_action_request_tests.rs"]
mod broker_action_request_tests;

const APP: &str = "github_app:plex-alfonso";
const INSTALLATIONS: &[u8] =
    include_bytes!("../../credentials-core/tests/fixtures/github_app/installations.json");
const EXPIRY_MS: i64 = 4_102_444_800_000;
type HeldPost = (oneshot::Sender<()>, oneshot::Receiver<()>);

#[derive(Default)]
struct Github {
    gets: AtomicUsize,
    posts: Mutex<Vec<Value>>,
    barriers: Mutex<VecDeque<HeldPost>>,
    exchange_faults: Mutex<VecDeque<(u16, Value)>>,
}

impl Github {
    fn stall_next_post(&self) -> (oneshot::Receiver<()>, oneshot::Sender<()>) {
        let (seen, arrived) = oneshot::channel();
        let (release, held) = oneshot::channel();
        self.barriers.lock().unwrap().push_back((seen, held));
        (arrived, release)
    }

    fn counts(&self, gets: usize, posts: usize) {
        assert_eq!(self.gets.load(Ordering::SeqCst), gets);
        assert_eq!(self.posts.lock().unwrap().len(), posts);
    }
}

#[async_trait]
impl HttpTransport for Github {
    async fn get(&self, url: &str, _: &[(&str, &str)]) -> Result<HttpResponse, RefreshError> {
        assert_eq!(url, INSTALLATIONS_URL);
        self.gets.fetch_add(1, Ordering::SeqCst);
        let mut reply: Value = serde_json::from_slice(INSTALLATIONS).unwrap();
        reply[0]["account"] = json!({"login":"Org"});
        Ok(HttpResponse {
            status: 200,
            body: serde_json::to_vec(&reply).unwrap(),
        })
    }

    async fn post(
        &self,
        url: &str,
        _: &[(&str, &str)],
        content_type: &str,
        body: Vec<u8>,
    ) -> Result<HttpResponse, RefreshError> {
        let installations: Value = serde_json::from_slice(INSTALLATIONS).unwrap();
        assert_eq!(url, installations[0]["access_tokens_url"].as_str().unwrap());
        assert_eq!(content_type, "application/json");
        let body: Value = serde_json::from_slice(&body).unwrap();
        let (sequence, barrier) = {
            let mut posts = self.posts.lock().unwrap();
            posts.push(body.clone());
            (posts.len(), self.barriers.lock().unwrap().pop_front())
        };
        if let Some((seen, held)) = barrier {
            seen.send(()).unwrap();
            held.await.unwrap();
        }
        if let Some((status, body)) = self.exchange_faults.lock().unwrap().pop_front() {
            return Ok(HttpResponse {
                status,
                body: serde_json::to_vec(&body).unwrap(),
            });
        }
        let repositories: Vec<_> = body["repositories"]
            .as_array()
            .unwrap()
            .iter()
            .map(|repo| json!({"full_name":format!("ORG/{}", repo.as_str().unwrap())}))
            .collect();
        let mut permissions = body["permissions"].clone();
        permissions["metadata"] = json!("read");
        let reply = json!({"token":format!("fixture-token-{sequence}"), "expires_at":"2100-01-01T00:00:00Z", "repositories":repositories, "permissions":permissions});
        Ok(HttpResponse {
            status: 201,
            body: serde_json::to_vec(&reply).unwrap(),
        })
    }
}

fn app_record(client_id: Option<&str>) -> VaultRecord {
    let installations: Value = serde_json::from_slice(INSTALLATIONS).unwrap();
    let oauth = OAuthCredential {
        access_token: "previous-broad-token".to_owned().into(),
        refresh_token: include_str!(
            "../../credentials-core/tests/fixtures/github_app/test_private_key.pem"
        )
        .to_owned()
        .into(),
        expires_at_ms: None,
        token_url: String::new(),
        client_id: Some(
            client_id
                .unwrap_or(installations[0]["client_id"].as_str().unwrap())
                .into(),
        ),
        client_secret: None,
        scopes: vec![],
    };
    VaultRecord::new_oauth(
        "test",
        "github_app",
        oauth,
        b"previous-broad-token".to_vec(),
    )
}

fn setup_with_resources(resources: Vec<String>) -> (Rig, Arc<Github>, String) {
    setup_for_agent(resources, "agent")
}

fn setup_for_agent(resources: Vec<String>, agent: &str) -> (Rig, Arc<Github>, String) {
    let rig = Rig::new();
    let key = root(&rig);
    rig.self_member();
    let manifest_bindings = resources
        .iter()
        .map(|resource| (resource.clone(), json!(agent)))
        .collect::<serde_json::Map<_, _>>();
    let digest = manifest_with_bindings(&rig, 41, Value::Object(manifest_bindings));
    let policy_text = json!({
        "schema":"ck-agent-policy/v1", "version":1, "issued_at_unix_secs":1,
        "root_key_id":key, "rule_sets":{"github":github_default_rule_set().unwrap()},
        "bindings":[{"service":"github","agent":agent,"identity":APP,"resources":resources}],
    })
    .to_string();
    apply(
        &rig.store,
        AdminOpBody::AgentPolicySign {
            v: ADMIN_OP_SCHEMA_V2,
            policy_bytes: policy_text,
            manifest_version: 41,
            approver: "operator".into(),
        },
        "test",
    )
    .unwrap();
    ready(&rig, SELF, 41, &digest);
    rig.store.create(APP, &app_record(None)).unwrap();
    grant(&rig, "aft", APP, GrantOperation::PolicyToken);
    let github = Arc::new(Github::default());
    *rig.surface.policy_tokens.http.lock().unwrap() = Some(github.clone());
    (rig, github, digest)
}

fn setup() -> (Rig, Arc<Github>, String) {
    setup_with_resources(vec!["org/r".into(), "org/s".into()])
}

fn params() -> Value {
    json!({"identity":APP,"service":"github","kind":"add_issue_comment","resource":"org/r","policy_version":1})
}

fn grant(rig: &Rig, module: &str, id: &str, op: GrantOperation) {
    rig.store
        .create_read_grant_audited(
            "reserved",
            module,
            SelectorKind::Exact,
            id,
            op,
            AuditCtx::admin(AuditOp::GrantCreate),
        )
        .unwrap();
}

fn revoke(rig: &Rig, module: &str) {
    rig.store
        .revoke_read_grant_audited(
            "reserved",
            module,
            SelectorKind::Exact,
            APP,
            GrantOperation::PolicyToken,
            AuditCtx::admin(AuditOp::GrantRevoke),
        )
        .unwrap();
}

fn first_uses(rig: &Rig) -> Vec<String> {
    Connection::open(&rig.path).unwrap().prepare(
        "SELECT principal_id FROM auth_events WHERE credential_id = ?1 AND kind = 'scoped_first_use' AND detail = 'policy_token' ORDER BY seq",
    ).unwrap().query_map([APP], |row| row.get(0)).unwrap().collect::<Result<_, _>>().unwrap()
}

async fn reply(rig: &mut Rig, corr: u64) -> Value {
    let received = frame(rig).await;
    assert_eq!(
        (received.header.ty, received.header.corr),
        (FrameType::Response, corr)
    );
    body(&received)["result"].clone()
}

async fn signal(signal: oneshot::Receiver<()>) {
    tokio::time::timeout(Duration::from_secs(5), signal)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn policy_token_local_refusals_do_not_call_github_or_record_first_use() {
    let (mut rig, github, digest) = setup();
    grant(&rig, "plexus", APP, GrantOperation::Read);
    grant(&rig, "other", APP, GrantOperation::PolicyToken);
    assert_eq!(
        rig.call("other", OP_POLICY_TOKEN, params()).await,
        refusal("not_found", "permanent")
    );
    assert_eq!(
        rig.call("plexus", OP_POLICY_TOKEN, params()).await,
        refusal("not_found", "permanent")
    );
    grant(
        &rig,
        "aft",
        "github_app:unbound",
        GrantOperation::PolicyToken,
    );
    for (field, value, code) in [
        ("service", json!("other"), "not_found"),
        ("policy_version", json!(2), "policy_version_not_active"),
        ("identity", json!("github_app:unbound"), "not_found"),
        ("kind", json!("absent"), "not_found"),
        ("resource", json!("Org/R"), "not_found"),
        ("resource", json!("org/unbound"), "not_found"),
        ("resource", json!("binding"), "not_found"),
    ] {
        let mut request = params();
        request[field] = value;
        assert_eq!(
            rig.call("aft", OP_POLICY_TOKEN, request).await,
            refusal(code, "permanent")
        );
    }
    report_version(&rig, SELF, 41, &digest, GhManifestVerdict::Invalid);
    assert_eq!(
        rig.call("aft", OP_POLICY_TOKEN, params()).await,
        refusal("policy_version_not_active", "permanent")
    );
    ready(&rig, SELF, 41, &digest);
    rig.sql("ALTER TABLE read_grants RENAME TO unavailable_grants");
    assert_eq!(
        rig.call("aft", OP_POLICY_TOKEN, params()).await,
        refusal("store_error", "transient")
    );
    rig.sql("ALTER TABLE unavailable_grants RENAME TO read_grants");
    assert_eq!(
        rig.call("aft", crate::OP_GET_SCOPED, json!({"credential_id": APP}))
            .await,
        refusal("not_found", "permanent")
    );
    for (state, code, class) in [
        ("needs_reauth", "needs_reauth", "auth_required"),
        ("retired", "needs_reauth", "auth_required"),
        ("corrupt", "corrupt", "permanent"),
    ] {
        rig.sql(&format!(
            "UPDATE credentials SET state = '{state}' WHERE credential_id = '{APP}'"
        ));
        let expected = refusal(code, class);
        assert_eq!(rig.call("aft", OP_POLICY_TOKEN, params()).await, expected);
        assert_eq!(
            rig.call(
                "plexus",
                crate::OP_GET_SCOPED,
                json!({"credential_id": APP})
            )
            .await,
            expected
        );
    }
    rig.sql(&format!(
        "DELETE FROM credentials WHERE credential_id = '{APP}'"
    ));
    assert_eq!(
        rig.call("aft", OP_POLICY_TOKEN, params()).await,
        refusal("not_installed", "permanent")
    );
    rig.store
        .remote_add_audited(&NewRemoteRecord {
            credential_id: APP.into(),
            home_member: OTHER.into(),
            refresh_adapter: Some("github_app".into()),
            detected_plan: None,
            identity: Default::default(),
            home_version: 1,
            categories: vec![],
        })
        .unwrap();
    assert_eq!(
        rig.call("aft", OP_POLICY_TOKEN, params()).await,
        refusal("not_installed", "permanent")
    );
    rig.store.remote_remove_audited(APP).unwrap();
    rig.store.create(APP, &app_record(Some(""))).unwrap();
    assert_eq!(
        rig.call("aft", OP_POLICY_TOKEN, params()).await,
        refusal("installation_unusable", "permanent")
    );
    rig.sql(&format!(
        "DELETE FROM credentials WHERE credential_id = '{APP}'"
    ));
    rig.store
        .create(
            APP,
            &VaultRecord::new_static(CredentialKind::ApiKey, "test", b"not-an-app".to_vec(), None),
        )
        .unwrap();
    assert_eq!(
        rig.call("aft", OP_POLICY_TOKEN, params()).await,
        refusal("installation_unusable", "permanent")
    );
    assert!(first_uses(&rig).is_empty());
    github.counts(0, 0);
}

#[tokio::test]
async fn policy_token_routes_hide_role_failures_and_never_relay() {
    let (mut rig, github, _) = setup();
    let ingress = Ingress::new(&rig);
    let not_found = refusal("not_found", "permanent");
    use_remote_home(&rig);
    for corr in [2, 3] {
        ingress.bind(&rig, 1, "aft");
        ingress
            .dispatch(&rig, request(OP_POLICY_TOKEN, params(), 1, corr))
            .await;
        assert_eq!(reply(&mut rig, corr).await, not_found);
        if corr == 2 {
            rig.sql(&format!(
                "DELETE FROM settings WHERE name = '{}'",
                credentials_core::federation::SELF_MEMBER_SETTING
            ));
        }
    }
    rig.sql(&format!(
        "UPDATE settings SET value = 'broken' WHERE name = '{}'",
        credentials_core::store::SECRET_HOME_SETTING
    ));
    for (corr, module, expected) in [
        (4, "other", not_found),
        (5, "aft", refusal("store_error", "transient")),
    ] {
        ingress.bind(&rig, 1, module);
        ingress
            .dispatch(&rig, request(OP_POLICY_TOKEN, json!({"bad":true}), 1, corr))
            .await;
        assert_eq!(reply(&mut rig, corr).await, expected);
    }
    assert!(first_uses(&rig).is_empty());
    github.counts(0, 0);
}

#[tokio::test]
async fn policy_token_returns_exact_scope_and_a_cache_hit_still_needs_a_grant() {
    let (mut rig, github, _) = setup();
    let expected_permissions = json!({"issues":"write", "pull_requests":"write"});
    rig.request(caller("aft"), OP_POLICY_TOKEN, params(), 1, 1)
        .await;
    let response = frame(&mut rig).await;
    assert_eq!(response.header.ty, FrameType::Response);
    assert_eq!(response.body.as_slice(), br#"{"result":{"expires_at_ms":4102444800000,"permissions":{"issues":"write","pull_requests":"write"},"repositories":["org/r"],"token":"fixture-token-1"}}"#);
    let first = body(&response)["result"].clone();
    assert_eq!(
        first,
        json!({"token":"fixture-token-1","expires_at_ms":EXPIRY_MS,"repositories":["org/r"],"permissions":expected_permissions})
    );
    assert_eq!(
        github.posts.lock().unwrap()[0],
        json!({"repositories":["r"],"permissions":expected_permissions})
    );
    assert_eq!(rig.call("aft", OP_POLICY_TOKEN, params()).await, first);
    let mut same_scope = params();
    same_scope["kind"] = json!("update_issue_comment");
    assert_eq!(rig.call("aft", OP_POLICY_TOKEN, same_scope).await, first);
    grant(&rig, "other", APP, GrantOperation::PolicyToken);
    for module in ["plexus", "other"] {
        assert_eq!(
            rig.call(module, OP_POLICY_TOKEN, params()).await,
            refusal("not_found", "permanent")
        );
    }
    let mut stale = params();
    stale["policy_version"] = json!(2);
    assert_eq!(
        rig.call("aft", OP_POLICY_TOKEN, stale).await,
        refusal("policy_version_not_active", "permanent")
    );
    assert_eq!(first_uses(&rig), ["aft"]);
    github.counts(1, 1);

    let mut whole = params();
    whole["kind"] = json!("node_repository");
    whole["resource"] = json!("binding");
    let result = rig.call("aft", OP_POLICY_TOKEN, whole).await;
    assert_eq!(result["repositories"], json!(["org/r", "org/s"]));
    assert_eq!(
        github.posts.lock().unwrap()[1]["repositories"],
        json!(["r", "s"])
    );
    assert_ne!(result["permissions"], expected_permissions);
    let mut other_repo = params();
    other_repo["resource"] = json!("org/s");
    let result = rig.call("aft", OP_POLICY_TOKEN, other_repo).await;
    assert_eq!(result["repositories"], json!(["org/s"]));
    assert_eq!(result["permissions"], expected_permissions);
    assert_eq!(
        github.posts.lock().unwrap()[2]["repositories"],
        json!(["s"])
    );
    let mut other_permissions = params();
    other_permissions["kind"] = json!("node_repository");
    let result = rig.call("aft", OP_POLICY_TOKEN, other_permissions).await;
    assert_eq!(result["repositories"], json!(["org/r"]));
    assert_ne!(result["permissions"], expected_permissions);
    assert_eq!(first_uses(&rig), ["aft"]);
    github.counts(4, 4);
}

#[tokio::test]
async fn policy_token_refuses_anonymous_and_denied_kinds_without_github() {
    let (mut rig, github, _) = setup();
    let active = rig.store.active_agent_policy().unwrap().1.unwrap();
    let mut policy = AgentPolicy::parse_canonical(active.policy_text.as_bytes()).unwrap();
    policy.version = 2;
    let rules = policy.rule_sets.get_mut("github").unwrap();
    let requests = serde_json::from_value(
        json!([{"rest":{"method":"GET","host":rules.hosts[0],"path":"/test-public-only"}}]),
    )
    .unwrap();
    let kinds = &mut rules.kinds;
    kinds.push(Kind {
        kind: "anonymous_read".into(),
        class: Class::Read,
        approval: Approval::None,
        identity: Identity::Anonymous,
        credential: None,
        ownership: None,
        requests,
        consent: None,
    });
    kinds.push(Kind {
        kind: "denied_read".into(),
        class: Class::Denied,
        approval: Approval::None,
        identity: Identity::Agent,
        credential: None,
        ownership: None,
        requests: vec![],
        consent: None,
    });
    let bytes = policy.canonical_bytes().unwrap();
    AgentPolicy::parse_canonical(&bytes).unwrap();
    let digest = manifest_with_bindings(&rig, 42, json!({"org/r":"agent", "org/s":"agent"}));
    // The policy signer only accepts kinds in the installed default. Insert the
    // model-valid fixture directly to exercise the read gates for these other kinds.
    Connection::open(&rig.path).unwrap().execute(
        "INSERT INTO agent_policies (version, policy_bytes, policy_sha256, key_id, signature, signed_at_ms, source, approval_seq, manifest_version) \
         SELECT 2, ?1, ?2, key_id, signature, signed_at_ms, source, approval_seq, 42 FROM agent_policies WHERE version = 1",
        rusqlite::params![bytes, credentials_core::agent_policy::policy_sha256(&bytes)],
    ).unwrap();
    ready(&rig, SELF, 42, &digest);
    for kind in ["anonymous_read", "denied_read"] {
        let mut request = params();
        request["policy_version"] = json!(2);
        request["kind"] = json!(kind);
        assert_eq!(
            rig.call("aft", OP_POLICY_TOKEN, request).await,
            refusal("not_found", "permanent")
        );
    }
    github.counts(0, 0);
    assert!(first_uses(&rig).is_empty());
}

#[tokio::test]
async fn policy_token_shared_mint_checks_each_recipient_and_uses_the_accepted_principal() {
    let (mut rig, github, _) = setup();
    grant(&rig, "plexus", APP, GrantOperation::PolicyToken);
    let ingress = Ingress::new(&rig);
    ingress.bind(&rig, 1, "aft");
    ingress.bind(&rig, 2, "plexus");
    let (posted, release) = github.stall_next_post();
    ingress
        .dispatch(&rig, request(OP_POLICY_TOKEN, params(), 1, 10))
        .await;
    signal(posted).await;
    let (joined, waiting) = oneshot::channel();
    *rig.surface.policy_tokens.joined.lock().unwrap() = Some(joined);
    ingress
        .dispatch(&rig, request(OP_POLICY_TOKEN, params(), 2, 11))
        .await;
    signal(waiting).await;
    revoke(&rig, "aft");
    ingress.bind(&rig, 1, "plexus");
    release.send(()).unwrap();
    let mut results = BTreeMap::new();
    for _ in 0..2 {
        let received = frame(&mut rig).await;
        assert_eq!(received.header.ty, FrameType::Response);
        results.insert(received.header.corr, body(&received)["result"].clone());
    }
    assert_eq!(results[&10], refusal("not_found", "permanent"));
    assert_eq!(results[&11]["token"], "fixture-token-1");
    assert_eq!(first_uses(&rig), ["plexus"]);
    github.counts(1, 1);
}

#[tokio::test]
async fn policy_token_rebind_does_not_lend_a_grant_or_record_first_use() {
    let (mut rig, github, _) = setup();
    grant(&rig, "plexus", APP, GrantOperation::PolicyToken);
    let ingress = Ingress::new(&rig);
    ingress.bind(&rig, 1, "aft");
    let (posted, release) = github.stall_next_post();
    ingress
        .dispatch(&rig, request(OP_POLICY_TOKEN, params(), 1, 10))
        .await;
    signal(posted).await;
    revoke(&rig, "aft");
    ingress.bind(&rig, 1, "plexus");
    release.send(()).unwrap();
    assert_eq!(reply(&mut rig, 10).await, refusal("not_found", "permanent"));
    assert!(first_uses(&rig).is_empty());
    github.counts(1, 1);
}

#[tokio::test]
async fn policy_token_handoff_rechecks_the_home_role_and_reports_grant_query_failure() {
    for role_changed in [false, true] {
        let (mut rig, github, _) = setup();
        rig.store
            .set_secret_home_audited(Some("self"), AuditCtx::admin(AuditOp::SecretHomeSet))
            .unwrap();
        let ingress = Ingress::new(&rig);
        ingress.bind(&rig, 1, "aft");
        let (posted, release) = github.stall_next_post();
        ingress
            .dispatch(&rig, request(OP_POLICY_TOKEN, params(), 1, 10))
            .await;
        signal(posted).await;
        let expected = if role_changed {
            use_remote_home(&rig);
            refusal("not_found", "permanent")
        } else {
            rig.sql("ALTER TABLE read_grants RENAME TO unavailable_grants");
            refusal("store_error", "transient")
        };
        release.send(()).unwrap();
        assert_eq!(reply(&mut rig, 10).await, expected);
        assert!(first_uses(&rig).is_empty());
        github.counts(1, 1);
    }
}

#[tokio::test]
async fn policy_token_failed_first_use_commit_withholds_fresh_and_cached_tokens() {
    let (mut rig, github, _) = setup();
    grant(&rig, "plexus", APP, GrantOperation::PolicyToken);
    rig.sql("CREATE TRIGGER fail_policy_first_use BEFORE INSERT ON auth_events WHEN NEW.kind = 'scoped_first_use' AND NEW.detail = 'policy_token' AND NEW.principal_id = 'plexus' BEGIN SELECT RAISE(ABORT, 'audit write failed'); END");
    let expected = refusal("store_error", "transient");
    assert_eq!(
        rig.call("plexus", OP_POLICY_TOKEN, params()).await,
        expected
    );
    assert!(first_uses(&rig).is_empty());
    github.counts(1, 1);
    assert_eq!(
        rig.call("aft", OP_POLICY_TOKEN, params()).await["token"],
        "fixture-token-2"
    );
    assert_eq!(
        rig.call("plexus", OP_POLICY_TOKEN, params()).await,
        expected
    );
    assert_eq!(first_uses(&rig), ["aft"]);
    github.counts(2, 2);
}

#[tokio::test]
async fn policy_token_mint_failures_are_opaque_and_never_cached() {
    let (mut rig, github, _) = setup();
    let invalid_scope = json!({"token":"must-not-leak", "expires_at":"2100-01-01T00:00:00Z", "repositories":[{"full_name":"org/other"}], "permissions":{"issues":"write","pull_requests":"write"}});
    let provider_error = json!({"message":"must-not-leak suspended"});
    for (status, body, code, class) in [
        (
            201,
            invalid_scope,
            "policy_token_scope_mismatch",
            "permanent",
        ),
        (
            422,
            provider_error.clone(),
            "policy_token_scope_unavailable",
            "permanent",
        ),
        (403, provider_error, "github_unavailable", "transient"),
    ] {
        github
            .exchange_faults
            .lock()
            .unwrap()
            .push_back((status, body));
        assert_eq!(
            rig.call("aft", OP_POLICY_TOKEN, params()).await,
            refusal(code, class)
        );
    }
    github.counts(3, 3);
    assert!(first_uses(&rig).is_empty());
    assert_eq!(
        rig.call("aft", OP_POLICY_TOKEN, params()).await["token"],
        "fixture-token-4"
    );
    assert_eq!(first_uses(&rig), ["aft"]);
}

#[tokio::test]
async fn policy_token_cache_uses_strict_five_minute_margin_and_handoff_checks_expiry() {
    let (mut rig, github, _) = setup();
    let clock = Arc::new(AtomicI64::new(EXPIRY_MS - 300_001));
    let now = Arc::clone(&clock);
    *rig.surface.policy_tokens.clock.lock().unwrap() =
        Some(Arc::new(move || now.load(Ordering::SeqCst)));
    let first = rig.call("aft", OP_POLICY_TOKEN, params()).await;
    assert_eq!(first["token"], "fixture-token-1");
    assert_eq!(rig.call("aft", OP_POLICY_TOKEN, params()).await, first);
    github.counts(1, 1);
    clock.store(EXPIRY_MS - 300_000, Ordering::SeqCst);
    assert_eq!(
        rig.call("aft", OP_POLICY_TOKEN, params()).await["token"],
        "fixture-token-2"
    );
    assert_eq!(
        rig.call("aft", OP_POLICY_TOKEN, params()).await["token"],
        "fixture-token-3"
    );
    github.counts(3, 3);

    grant(&rig, "plexus", APP, GrantOperation::PolicyToken);
    let ingress = Ingress::new(&rig);
    ingress.bind(&rig, 1, "plexus");
    let (posted, release) = github.stall_next_post();
    ingress
        .dispatch(&rig, request(OP_POLICY_TOKEN, params(), 1, 10))
        .await;
    signal(posted).await;
    clock.store(EXPIRY_MS, Ordering::SeqCst);
    release.send(()).unwrap();
    assert_eq!(
        reply(&mut rig, 10).await,
        refusal("github_unavailable", "transient")
    );
    assert_eq!(first_uses(&rig), ["aft"]);
    github.counts(4, 4);
}

fn replace_record(rig: &Rig, recreate: bool) {
    if recreate {
        rig.sql(&format!(
            "DELETE FROM credentials WHERE credential_id = '{APP}'"
        ));
        rig.store.create(APP, &app_record(None)).unwrap();
    } else {
        rig.store
            .overwrite_unconditional_audited(APP, &app_record(None), AuditCtx::admin(AuditOp::Put))
            .unwrap();
    }
}

#[tokio::test]
async fn policy_token_mints_for_a_vault_created_app_before_any_ordinary_refresh() {
    let agent = "agent_ab64ea0873bbee0c";
    let (mut rig, github, _) = setup_for_agent(vec!["org/r".into()], agent);
    let oauth = app_record(None).oauth.unwrap();
    rig.store
        .remove_audited(APP, AuditCtx::admin(AuditOp::Remove))
        .unwrap();
    rig.store
        .create_github_app_audited(
            GitHubAppCreation {
                slug: "plex-alfonso",
                agent,
                app_id: 20,
                pem: &oauth.refresh_token,
                client_id: oauth.client_id.as_deref().unwrap(),
                relay: None,
            },
            "test",
        )
        .unwrap();
    let before = rig.store.get(APP).unwrap();
    assert!(before.payload.expose().is_empty());
    let result = rig.call("aft", OP_POLICY_TOKEN, params()).await;
    assert!(
        result["token"] == "fixture-token-1",
        "first narrowed mint failed"
    );
    github.counts(1, 1);
    assert_eq!(
        github.posts.lock().unwrap()[0]["repositories"],
        json!(["r"])
    );
    let after = rig.store.get(APP).unwrap();
    assert_eq!(before.record_version, after.record_version);
    assert!(after.payload.expose().is_empty());
}

#[tokio::test]
async fn policy_token_retries_a_failed_mint_only_for_an_authorized_replacement() {
    for (replaced, revoked) in [(true, false), (false, false), (true, true)] {
        let (mut rig, github, _) = setup();
        let ingress = Ingress::new(&rig);
        ingress.bind(&rig, 1, "aft");
        let (posted, release) = github.stall_next_post();
        github
            .exchange_faults
            .lock()
            .unwrap()
            .push_back((503, json!({})));
        ingress
            .dispatch(&rig, request(OP_POLICY_TOKEN, params(), 1, 10))
            .await;
        signal(posted).await;
        if replaced {
            replace_record(&rig, false);
        }
        if revoked {
            revoke(&rig, "aft");
        }
        release.send(()).unwrap();
        let current = reply(&mut rig, 10).await;
        if replaced && !revoked {
            assert!(
                current["token"] == "fixture-token-2",
                "replacement mint failed"
            );
            github.counts(2, 2);
        } else {
            assert!(current.get("token").is_none());
            if !replaced {
                assert_eq!(current["error"]["code"], "github_unavailable");
            }
            github.counts(1, 1);
        }
    }
}

#[tokio::test(start_paused = true)]
async fn policy_token_shared_mint_accepts_29999_ms_and_times_out_at_30000_ms() {
    for timed_out in [false, true] {
        let (mut rig, github, _) = setup();
        let ingress = Ingress::new(&rig);
        ingress.bind(&rig, 1, "aft");
        let (posted, release) = github.stall_next_post();
        ingress
            .dispatch(&rig, request(OP_POLICY_TOKEN, params(), 1, 10))
            .await;
        posted.await.unwrap();
        tokio::time::advance(std::time::Duration::from_millis(if timed_out {
            30_000
        } else {
            29_999
        }))
        .await;
        if !timed_out {
            release.send(()).unwrap();
        }
        let result = tokio::time::timeout(std::time::Duration::from_secs(1), reply(&mut rig, 10))
            .await
            .expect("shared mint must resolve at its deadline");
        if timed_out {
            assert_eq!(result["error"]["code"], "github_unavailable");
        } else {
            assert!(result["token"] == "fixture-token-1");
        }
        github.counts(1, 1);
    }
}

#[tokio::test]
async fn policy_token_record_replacement_invalidates_warm_cache_and_held_mints() {
    for recreate in [false, true] {
        let (mut rig, github, _) = setup();
        assert_eq!(
            rig.call("aft", OP_POLICY_TOKEN, params()).await["token"],
            "fixture-token-1"
        );
        replace_record(&rig, recreate);
        assert_eq!(
            rig.call("aft", OP_POLICY_TOKEN, params()).await["token"],
            "fixture-token-2"
        );
        github.counts(2, 2);

        let (mut rig, github, _) = setup();
        let ingress = Ingress::new(&rig);
        ingress.bind(&rig, 1, "aft");
        let (posted, release) = github.stall_next_post();
        ingress
            .dispatch(&rig, request(OP_POLICY_TOKEN, params(), 1, 10))
            .await;
        signal(posted).await;
        replace_record(&rig, recreate);
        release.send(()).unwrap();
        let current = reply(&mut rig, 10).await;
        assert_eq!(current["token"], "fixture-token-2");
        assert_eq!(rig.call("aft", OP_POLICY_TOKEN, params()).await, current);
        github.counts(2, 2);
    }
}

fn reuse_slug_for_another_agent(rig: &Rig) {
    rig.store
        .remove_audited(APP, AuditCtx::admin(AuditOp::Remove))
        .unwrap();
    let refreshed = app_record(None);
    let oauth = refreshed.oauth.as_ref().unwrap();
    rig.store
        .create_github_app_audited(
            GitHubAppCreation {
                slug: APP.strip_prefix("github_app:").unwrap(),
                app_id: 20,
                agent: "agent_ab64ea0873bbee0c",
                pem: &oauth.refresh_token,
                client_id: oauth.client_id.as_deref().unwrap(),
                relay: None,
            },
            "test",
        )
        .unwrap();
    // Model an ordinary refresh so an empty access payload cannot be the thing
    // that prevents the replacement App from serving the old binding.
    let incarnation: String = Connection::open(&rig.path)
        .unwrap()
        .query_row(
            "SELECT incarnation FROM credentials WHERE credential_id = ?1",
            [APP],
            |row| row.get(0),
        )
        .unwrap();
    rig.store
        .commit_refresh(APP, 1, &incarnation, &refreshed, None)
        .unwrap();
    revoke(rig, "aft");
    grant(rig, "aft", APP, GrantOperation::PolicyToken);
}

#[tokio::test]
async fn policy_token_slug_reuse_for_another_agent_hides_mismatch_even_with_warm_cache() {
    let (mut rig, github, _) = setup();
    assert_eq!(
        rig.call("aft", OP_POLICY_TOKEN, params()).await["token"],
        "fixture-token-1"
    );
    reuse_slug_for_another_agent(&rig);
    let mut wrong_version = params();
    wrong_version["policy_version"] = json!(2);
    assert_eq!(
        rig.call("aft", OP_POLICY_TOKEN, wrong_version).await,
        refusal("policy_version_not_active", "permanent")
    );
    let before = first_uses(&rig);
    assert_eq!(
        rig.call("aft", OP_POLICY_TOKEN, params()).await,
        refusal("not_found", "permanent")
    );
    assert_eq!(first_uses(&rig), before);
    github.counts(1, 1);
}

#[tokio::test]
async fn policy_token_slug_reuse_for_another_agent_does_not_retry_an_inflight_mint() {
    let (mut rig, github, _) = setup();
    let ingress = Ingress::new(&rig);
    ingress.bind(&rig, 1, "aft");
    let (posted, release) = github.stall_next_post();
    ingress
        .dispatch(&rig, request(OP_POLICY_TOKEN, params(), 1, 10))
        .await;
    signal(posted).await;
    reuse_slug_for_another_agent(&rig);
    release.send(()).unwrap();
    assert_eq!(reply(&mut rig, 10).await, refusal("not_found", "permanent"));
    assert!(first_uses(&rig).is_empty());
    github.counts(1, 1);
}

#[tokio::test]
async fn policy_token_retries_a_changed_record_only_once() {
    let (mut rig, github, _) = setup();
    let ingress = Ingress::new(&rig);
    ingress.bind(&rig, 1, "aft");
    let (posted, release) = github.stall_next_post();
    let (posted_again, release_again) = github.stall_next_post();
    ingress
        .dispatch(&rig, request(OP_POLICY_TOKEN, params(), 1, 10))
        .await;
    signal(posted).await;
    replace_record(&rig, false);
    release.send(()).unwrap();
    signal(posted_again).await;
    replace_record(&rig, true);
    release_again.send(()).unwrap();
    assert_eq!(
        reply(&mut rig, 10).await,
        refusal("github_unavailable", "transient")
    );
    assert!(first_uses(&rig).is_empty());
    github.counts(2, 2);
}

#[tokio::test]
async fn policy_token_cache_checks_current_state_and_exact_sealed_bytes() {
    use credentials_core::envelope::{seal, RecordBinding};

    let (mut rig, github, _) = setup();
    let original = rig.call("aft", OP_POLICY_TOKEN, params()).await;
    assert_eq!(original["token"], "fixture-token-1");
    grant(&rig, "plexus", APP, GrantOperation::PolicyToken);
    for (state, code, class) in [
        ("needs_reauth", "needs_reauth", "auth_required"),
        ("corrupt", "corrupt", "permanent"),
    ] {
        rig.sql(&format!(
            "UPDATE credentials SET state = '{state}' WHERE credential_id = '{APP}'"
        ));
        assert_eq!(
            rig.call("plexus", OP_POLICY_TOKEN, params()).await,
            refusal(code, class)
        );
    }
    rig.sql(&format!(
        "UPDATE credentials SET state = 'active' WHERE credential_id = '{APP}'"
    ));
    assert_eq!(rig.call("aft", OP_POLICY_TOKEN, params()).await, original);
    rig.sql(&format!(
        "UPDATE credentials SET envelope = X'0011' WHERE credential_id = '{APP}'"
    ));
    assert_eq!(
        rig.call("plexus", OP_POLICY_TOKEN, params()).await,
        refusal("corrupt", "permanent")
    );
    let conn = Connection::open(&rig.path).unwrap();
    let (state, version): (String, u64) = conn
        .query_row(
            "SELECT state, record_version FROM credentials WHERE credential_id = ?1",
            [APP],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(state, "active", "policy_token must not quarantine the row");
    let other_key = MasterKey::from_bytes([203; MASTER_KEY_LEN]);
    let blob = seal(
        &other_key,
        &app_record(None).encode().unwrap(),
        &RecordBinding {
            credential_id: APP,
            record_version: version,
        },
    )
    .unwrap();
    conn.execute(
        "UPDATE credentials SET envelope = ?1 WHERE credential_id = ?2",
        rusqlite::params![blob, APP],
    )
    .unwrap();
    assert_eq!(
        rig.call("plexus", OP_POLICY_TOKEN, params()).await,
        refusal("vault_locked", "transient")
    );
    assert_eq!(first_uses(&rig), ["aft"]);
    github.counts(1, 1);
}

#[tokio::test]
async fn policy_token_oversized_binding_refuses_before_github() {
    let resources = (0..501).map(|i| format!("org/r{i:03}")).collect();
    let (mut rig, github, _) = setup_with_resources(resources);
    let mut request = params();
    request["kind"] = json!("node_repository");
    request["resource"] = json!("binding");
    assert_eq!(
        rig.call("aft", OP_POLICY_TOKEN, request).await,
        refusal("policy_token_scope_unavailable", "permanent")
    );
    assert!(first_uses(&rig).is_empty());
    github.counts(0, 0);
}
