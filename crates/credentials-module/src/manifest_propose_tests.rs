use super::*;

#[path = "manifest_binding_vectors_tests.rs"]
mod manifest_binding_vectors;
use crate::manifest_identity::{decode_identity_reply, IdentityCheckError, IdentityReply};
use async_trait::async_trait;
use credentials_core::{
    audit::{AuditCtx, AuditOp},
    oauth::OAuthCredential,
    record::{CredentialKind, VaultRecord},
    refresh_adapters::{HttpResponse, RefreshError},
    store::{GhManifestSource, GhManifestVersion, GH_MANIFEST_ROOT_KEY_ID},
};
use rusqlite::{types::Value as SqlValue, Connection};
use sha2::{Digest, Sha256};
use std::{
    collections::VecDeque,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    },
};

const INSTALLATIONS: &[u8] =
    include_bytes!("../../credentials-core/tests/fixtures/github_app/installations.json");
const TOKENS: &[u8] =
    include_bytes!("../../credentials-core/tests/fixtures/github_app/access_tokens.json");
const V28: &[u8] = include_bytes!("../../credentials-core/tests/fixtures/gh-manifest-v28.json");
const AGENT: &str = "agent_4444444444444444";
const REPO: &str = "Octo-Owner/New-Repo";
const NOW: i64 = 1_794_355_300_123;

struct Rig {
    store: Arc<EncryptedStore>,
    surface: Arc<crate::ReadSurface>,
    path: std::path::PathBuf,
    _root: credentials_core::test_support::TestTempDir,
}

impl Rig {
    fn with_raw_conn<T>(
        &self,
        f: impl FnOnce(&Connection) -> rusqlite::Result<T>,
    ) -> rusqlite::Result<T> {
        f(&Connection::open(&self.path)?)
    }
}

fn rig(missing: &str) -> Rig {
    let (surface, store, path, root) = crate::tests::tmp_surface_with_store(201);
    if missing != "root" {
        store
            .create(
                GH_MANIFEST_ROOT_KEY_ID,
                &VaultRecord::new_static(
                    CredentialKind::SigningKey,
                    "test",
                    b"unused root".to_vec(),
                    None,
                ),
            )
            .unwrap();
    }
    if missing != "member" {
        store
            .set_federation_self_member_audited(
                "fed-computer:22222222222222222222222222222222",
                AuditCtx::admin(AuditOp::FederationSelfSet),
            )
            .unwrap();
    }
    if missing != "version" {
        store_bytes(&store, 28, V28);
    }
    store
        .set_manifest_one_tap_audited(true, AuditCtx::admin(AuditOp::GhManifestOneTapSet))
        .unwrap();
    let installations: Value = serde_json::from_slice(INSTALLATIONS).unwrap();
    let credential = OAuthCredential {
        access_token: "previous-token".to_owned().into(),
        refresh_token: include_str!(
            "../../credentials-core/tests/fixtures/github_app/test_private_key.pem"
        )
        .to_owned()
        .into(),
        expires_at_ms: Some(0),
        token_url: String::new(),
        client_id: Some(installations[0]["client_id"].as_str().unwrap().into()),
        client_secret: None,
        scopes: vec![],
    };
    store
        .create(
            "github_app:plex-alfonso",
            &VaultRecord::new_oauth("test", "github_app", credential, b"previous-token".to_vec()),
        )
        .unwrap();
    Rig {
        store,
        surface,
        path,
        _root: root,
    }
}

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn store_bytes(store: &EncryptedStore, version: i64, bytes: &[u8]) {
    store
        .store_gh_manifest(
            &GhManifestVersion {
                version,
                manifest_bytes: bytes,
                manifest_sha256: &hash(bytes),
                key_id: "0123456789abcdef",
                signature: &[7; 64],
                signed_at_ms: NOW,
                source: GhManifestSource::Import,
                approval_audit_seq: None,
            },
            AuditCtx::admin(AuditOp::GhManifestStore),
        )
        .unwrap();
}

fn snapshot(rig: &Rig) -> Vec<Vec<Vec<SqlValue>>> {
    rig.with_raw_conn(|conn| {
        [
            "gh_manifests",
            "gh_manifest_proposals",
            "gh_manifest_activations",
            "gh_manifest_activation_audits",
            "audit_log",
            "credentials",
        ]
        .iter()
        .map(|table| {
            let mut stmt = conn.prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))?;
            let count = stmt.column_count();
            let rows = stmt
                .query_map([], |row| {
                    (0..count)
                        .map(|i| row.get(i))
                        .collect::<rusqlite::Result<Vec<_>>>()
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
        .collect()
    })
    .unwrap()
}

fn params() -> Value {
    json!({"agent_id":AGENT,"app_id":4617236,"app_slug":"plex-alfonso","repo":"octo-owner/new-repo"})
}
fn plexus() -> Principal {
    Principal::Reserved {
        module_id: "plexus".into(),
    }
}
fn identity_reply() -> Value {
    let vectors: Value = serde_json::from_slice(include_bytes!(
        "../tests/vectors/agent-github-identity-v1/github-identity.json"
    ))
    .unwrap();
    let mut reply = vectors[0]["reply"].clone();
    reply["result"]["github_identity"]["app_id"] = json!(4617236);
    reply["result"]["github_identity"]["app_slug"] = json!("plex-alfonso");
    reply["result"]["github_identity"]["credential_ref"] = json!("github_app:plex-alfonso");
    reply
}

struct IdentityStub {
    reply: Value,
    calls: AtomicUsize,
    hang: bool,
    exhaust: bool,
}
impl IdentityStub {
    fn new(reply: Value) -> Self {
        Self {
            reply,
            calls: AtomicUsize::new(0),
            hang: false,
            exhaust: false,
        }
    }
    fn good() -> Self {
        Self::new(identity_reply())
    }
}
#[async_trait]
impl GithubIdentitySource for IdentityStub {
    async fn github_identity(
        &self,
        agent: &str,
        budget: Duration,
    ) -> Result<IdentityReply, IdentityCheckError> {
        assert_eq!(agent, AGENT);
        assert!(budget <= PROPOSE_DEADLINE);
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.exhaust {
            tokio::time::advance(budget).await;
        }
        if self.hang {
            std::future::pending().await
        } else {
            decode_identity_reply(self.reply.clone()).map_err(|_| IdentityCheckError::Unavailable)
        }
    }
}

struct HttpStub {
    responses: Mutex<VecDeque<HttpResponse>>,
    calls: AtomicUsize,
    hang: bool,
    completed: Option<Arc<tokio::sync::Notify>>,
}
impl HttpStub {
    fn new(replies: Vec<(u16, Vec<u8>)>) -> Self {
        Self {
            responses: Mutex::new(
                replies
                    .into_iter()
                    .map(|(status, body)| HttpResponse { status, body })
                    .collect(),
            ),
            calls: AtomicUsize::new(0),
            hang: false,
            completed: None,
        }
    }
    fn good() -> Self {
        Self::new(vec![
            (200, INSTALLATIONS.to_vec()),
            (201, TOKENS.to_vec()),
            (200, page(1, &[REPO])),
        ])
    }
    async fn next(&self) -> Result<HttpResponse, RefreshError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.hang {
            std::future::pending().await
        } else {
            let mut responses = self.responses.lock().unwrap();
            let response = responses.pop_front().expect("unexpected outbound call");
            if responses.is_empty() {
                if let Some(done) = &self.completed {
                    done.notify_one();
                }
            }
            Ok(response)
        }
    }
}
#[async_trait]
impl HttpTransport for HttpStub {
    async fn get(
        &self,
        _url: &str,
        _headers: &[(&str, &str)],
    ) -> Result<HttpResponse, RefreshError> {
        self.next().await
    }
    async fn post(
        &self,
        _url: &str,
        _headers: &[(&str, &str)],
        _content_type: &str,
        _body: Vec<u8>,
    ) -> Result<HttpResponse, RefreshError> {
        self.next().await
    }
}
fn page(total: usize, names: &[&str]) -> Vec<u8> {
    serde_json::to_vec(&json!({"total_count":total,"repositories":names.iter().map(|name| json!({"full_name":name})).collect::<Vec<_>>()})).unwrap()
}

async fn propose(rig: &Rig, identity: &IdentityStub, http: &HttpStub) -> ProposeAnswer {
    let p = match preflight(&rig.store, Some(&plexus()), &params()) {
        Ok(p) => p,
        Err(answer) => return answer,
    };
    checked_proposal(
        Arc::clone(&rig.store),
        p,
        identity,
        Ok(http),
        Instant::now() + PROPOSE_DEADLINE,
        || NOW,
    )
    .await
}
fn reply(answer: ProposeAnswer) -> Value {
    match answer {
        ProposeAnswer::Reply(reply) => reply,
        ProposeAnswer::InvalidParams => panic!("unexpected invalid_params"),
    }
}
fn assert_refusal(answer: ProposeAnswer, code: &str, class: &str) {
    assert_eq!(reply(answer), json!({"error":{"code":code,"class":class}}));
}

#[tokio::test]
async fn manifest_propose_grammar_boundaries() {
    let rig = rig("");
    for (field, value) in [
        ("agent_id", json!("a".repeat(128))),
        ("app_slug", json!("a".repeat(100))),
        (
            "repo",
            json!(format!("{}/{}", "a".repeat(100), "b".repeat(100))),
        ),
        ("app_id", json!(i64::MAX)),
        ("agent_id", json!("A_0-z")),
        ("repo", json!("Owner_1./Repo-2")),
    ] {
        let mut p = params();
        p[field] = value;
        assert!(preflight(&rig.store, Some(&plexus()), &p).is_ok(), "{p}");
    }
    let before = snapshot(&rig);
    let mut bad = vec![
        json!({}),
        json!({"agent_id":AGENT,"app_id":1,"app_slug":"plex-alfonso","repo":REPO,"extra":true}),
    ];
    for (field, value) in [
        ("agent_id", json!("a".repeat(129))),
        ("agent_id", json!("")),
        ("agent_id", json!("bad/id")),
        ("agent_id", json!("à")),
        ("agent_id", json!("bad.id")),
        ("agent_id", json!(0)),
        ("app_slug", json!("a".repeat(101))),
        ("app_slug", json!("")),
        ("app_slug", json!("Upper")),
        ("app_slug", json!("under_score")),
        ("app_slug", json!("a:b")),
        ("app_slug", json!("é")),
        ("app_id", json!(0)),
        ("app_id", json!(-1)),
        ("app_id", json!(1.5)),
        ("app_id", json!("1")),
        ("repo", json!(format!("{}/b", "a".repeat(101)))),
        ("repo", json!(format!("a/{}", "b".repeat(101)))),
        ("repo", json!("./name")),
        ("repo", json!("../name")),
        ("repo", json!("owner/.")),
        ("repo", json!("owner/..")),
        ("repo", json!("a/b/c")),
        ("repo", json!("a/")),
        ("repo", json!("/b")),
        ("repo", json!("a/é")),
    ] {
        let mut p = params();
        p[field] = value;
        bad.push(p);
    }
    for p in bad {
        assert!(
            matches!(
                serve(Arc::clone(&rig.store), None, Some(&plexus()), &p).await,
                ProposeAnswer::InvalidParams
            ),
            "{p}"
        );
    }
    assert_eq!(snapshot(&rig), before);
}

#[tokio::test]
async fn manifest_propose_disabled_and_role_gates_never_call_out() {
    for setting in [None, Some("false"), Some("garbled"), Some("1")] {
        let rig = rig("");
        rig.with_raw_conn(|conn| {
            conn.execute("DELETE FROM settings WHERE name='manifest.one_tap'", [])?;
            if let Some(setting) = setting { conn.execute("INSERT INTO settings (name,value,updated_at_ms) VALUES ('manifest.one_tap',?1,0)", [setting])?; }
            Ok(())
        }).unwrap();
        let before = snapshot(&rig);
        let identity = IdentityStub::good();
        let http = HttpStub::new(vec![]);
        assert_refusal(
            propose(&rig, &identity, &http).await,
            "one_tap_disabled",
            "transient",
        );
        assert_refusal(
            serve(Arc::clone(&rig.store), None, None, &json!({})).await,
            "not_found",
            "permanent",
        );
        assert_eq!(identity.calls.load(Ordering::SeqCst), 0);
        assert_eq!(http.calls.load(Ordering::SeqCst), 0);
        assert_eq!(snapshot(&rig), before);
    }
    for (role, self_id, code, class) in [
        (
            "fed-computer:33333333333333333333333333333333",
            true,
            "not_found",
            "permanent",
        ),
        (
            "fed-computer:33333333333333333333333333333333",
            false,
            "not_found",
            "permanent",
        ),
        ("bad role", true, "store_error", "transient"),
    ] {
        let rig = rig("");
        rig.with_raw_conn(|conn| {
            if !self_id { conn.execute("DELETE FROM settings WHERE name='federation.self_member'", [])?; }
            conn.execute("INSERT OR REPLACE INTO settings (name,value,updated_at_ms) VALUES ('secrets.home_member',?1,0)", [role])?;
            Ok(())
        }).unwrap();
        let identity = IdentityStub::good();
        let http = HttpStub::new(vec![]);
        let before = snapshot(&rig);
        assert_refusal(propose(&rig, &identity, &http).await, code, class);
        assert_eq!(identity.calls.load(Ordering::SeqCst), 0);
        assert_eq!(http.calls.load(Ordering::SeqCst), 0);
        assert_eq!(snapshot(&rig), before);
    }
}

#[tokio::test]
async fn manifest_propose_setup_and_credential_refusals_write_nothing() {
    for missing in ["root", "version", "member"] {
        let rig = rig(missing);
        let identity = IdentityStub::good();
        let http = HttpStub::new(vec![]);
        let before = snapshot(&rig);
        assert_refusal(
            propose(&rig, &identity, &http).await,
            "manifest_setup_incomplete",
            "permanent",
        );
        assert_eq!(identity.calls.load(Ordering::SeqCst), 0);
        assert_eq!(http.calls.load(Ordering::SeqCst), 0);
        assert_eq!(snapshot(&rig), before);
    }
    for change in [
        "DELETE FROM credentials WHERE credential_id='github_app:plex-alfonso'",
        "UPDATE credentials SET state='needs_reauth' WHERE credential_id='github_app:plex-alfonso'",
        "UPDATE credentials SET envelope=x'00' WHERE credential_id='github_app:plex-alfonso'",
    ] {
        let rig = rig("");
        rig.with_raw_conn(|conn| conn.execute(change, [])).unwrap();
        let before = snapshot(&rig);
        let http = HttpStub::new(vec![]);
        assert_refusal(
            propose(&rig, &IdentityStub::good(), &http).await,
            if change.contains("envelope") {
                "store_error"
            } else {
                "not_installed"
            },
            if change.contains("envelope") {
                "transient"
            } else {
                "permanent"
            },
        );
        assert_eq!(http.calls.load(Ordering::SeqCst), 0);
        assert_eq!(snapshot(&rig), before);
    }
}

#[tokio::test]
async fn manifest_propose_identity_refusals_precede_installation() {
    let vectors: Value = serde_json::from_slice(include_bytes!(
        "../tests/vectors/agent-github-identity-v1/github-identity.json"
    ))
    .unwrap();
    let mut replies: Vec<(Value, &str)> = vectors.as_array().unwrap()[2..]
        .iter()
        .map(|record| (record["reply"].clone(), "identity_mismatch"))
        .collect();
    replies.push((
        json!({"code":"invalid_request","message":"invalid request"}),
        "identity_mismatch",
    ));
    replies.push((json!({"bad":"shape"}), "identity_unavailable"));
    for (field, value) in [
        ("app_id", json!(42)),
        ("app_slug", json!("other")),
        ("credential_ref", json!("github_app:other")),
    ] {
        let mut r = identity_reply();
        r["result"]["github_identity"][field] = value;
        replies.push((r, "identity_mismatch"));
    }
    for (body, code) in replies {
        let rig = rig("");
        let before = snapshot(&rig);
        let identity = IdentityStub::new(body);
        let http = HttpStub::new(vec![]);
        assert_refusal(
            propose(&rig, &identity, &http).await,
            code,
            if code == "identity_mismatch" {
                "permanent"
            } else {
                "transient"
            },
        );
        assert_eq!(identity.calls.load(Ordering::SeqCst), 1);
        assert_eq!(http.calls.load(Ordering::SeqCst), 0);
        assert_eq!(snapshot(&rig), before);
    }
}

#[tokio::test]
async fn manifest_propose_installation_refusals_use_typed_checker() {
    let installation: Value = serde_json::from_slice(INSTALLATIONS).unwrap();
    let mut several = installation.clone();
    several
        .as_array_mut()
        .unwrap()
        .push(installation[0].clone());
    let mut mismatch = installation.clone();
    mismatch[0]["app_slug"] = json!("other");
    let mut suspended = installation.clone();
    suspended[0]["suspended_at"] = json!("2026-01-01T00:00:00Z");
    let mut all = installation.clone();
    all[0]["repository_selection"] = json!("all");
    let mut cases = vec![
        (vec![(200, b"[]".to_vec())], "not_installed", "permanent"),
        (
            vec![(200, serde_json::to_vec(&several).unwrap())],
            "installation_unusable",
            "permanent",
        ),
        (
            vec![(200, serde_json::to_vec(&mismatch).unwrap())],
            "installation_unusable",
            "permanent",
        ),
        (
            vec![(200, serde_json::to_vec(&suspended).unwrap())],
            "installation_unusable",
            "permanent",
        ),
        (
            vec![
                (200, serde_json::to_vec(&all).unwrap()),
                (201, TOKENS.to_vec()),
                (200, page(1, &[REPO])),
            ],
            "installation_all",
            "permanent",
        ),
    ];
    for (pages, code, class) in [
        (
            vec![(200, page(1001, &[]))],
            "installation_too_large",
            "permanent",
        ),
        (
            vec![(200, page(1, &["Other/Repo"]))],
            "not_installed",
            "permanent",
        ),
        (
            vec![(403, b"{}".to_vec())],
            "github_unavailable",
            "transient",
        ),
        (
            vec![(429, b"{}".to_vec())],
            "github_unavailable",
            "transient",
        ),
        (
            vec![(200, page(2, &["Other/One"])), (500, b"{}".to_vec())],
            "github_unavailable",
            "transient",
        ),
        (
            vec![(200, page(2, &["Other/One"])), (200, page(2, &[]))],
            "github_unavailable",
            "transient",
        ),
        (
            vec![
                (200, page(2, &["Other/One"])),
                (200, page(3, &["Other/Two"])),
            ],
            "github_unavailable",
            "transient",
        ),
        (
            vec![(200, page(1, &["Other/One", "Other/Two"]))],
            "github_unavailable",
            "transient",
        ),
        (
            (0..10).map(|_| (200, page(20, &["Other/One"]))).collect(),
            "github_unavailable",
            "transient",
        ),
    ] {
        let mut replies = vec![(200, INSTALLATIONS.to_vec()), (201, TOKENS.to_vec())];
        replies.extend(pages);
        cases.push((replies, code, class));
    }
    for (responses, code, class) in cases {
        let rig = rig("");
        let before = snapshot(&rig);
        let http = HttpStub::new(responses);
        assert_refusal(
            propose(&rig, &IdentityStub::good(), &http).await,
            code,
            class,
        );
        assert_eq!(snapshot(&rig), before);
    }
}

#[tokio::test]
async fn manifest_propose_manifest_refusals_follow_both_outbound_checks() {
    for (case, code, class) in [
        ("same", "already_bound", "permanent"),
        ("other", "bound_to_other_agent", "permanent"),
        ("ahead", "stale_base", "transient"),
        ("format", "not_reproducible", "permanent"),
    ] {
        let rig = rig("");
        let mut manifest: Value = serde_json::from_slice(V28).unwrap();
        manifest["manifest_version"] = json!(30);
        if case == "same" || case == "other" {
            manifest["bindings"][REPO] = json!(if case == "same" { AGENT } else { "agent_other" });
        }
        let bytes = serde_json::to_vec(&manifest).unwrap();
        if case != "ahead" {
            store_bytes(&rig.store, 30, &bytes);
        }
        if case == "ahead" {
            rig.with_raw_conn(|conn| conn.execute("INSERT INTO gh_manifest_activations (member_id,version,payload_sha256,verdict,reason,reported_at_ms) VALUES ('fed-computer:33333333333333333333333333333333',31,?1,'valid',NULL,0)",["a".repeat(64)])).unwrap();
        }
        let before = snapshot(&rig);
        let identity = IdentityStub::good();
        let http = HttpStub::good();
        let answer = reply(propose(&rig, &identity, &http).await);
        if case == "same" {
            assert_eq!(
                answer,
                json!({"error":{"code":code,"class":class,"version":30,"manifest_sha256":hash(&bytes)}})
            );
        } else {
            assert_eq!(answer, json!({"error":{"code":code,"class":class}}));
        }
        assert_eq!(identity.calls.load(Ordering::SeqCst), 1);
        assert_eq!(http.calls.load(Ordering::SeqCst), 3);
        assert_eq!(snapshot(&rig), before);
    }
}

#[tokio::test]
async fn manifest_propose_success_preserves_build_and_installation_permissions() {
    let rig = rig("");
    let http = HttpStub::good();
    let answer = reply(propose(&rig, &IdentityStub::good(), &http).await);
    assert_eq!(answer["status"], "approval_required");
    assert_eq!(
        answer
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        vec![
            "expires_at_ms",
            "manifest_sha256",
            "manifest_version",
            "proposal_id",
            "statement_b64url",
            "status"
        ]
    );
    assert_eq!(answer["manifest_version"], 29);
    assert_eq!(answer["expires_at_ms"], NOW + 86_400_000);
    let statement = URL_SAFE_NO_PAD
        .decode(answer["statement_b64url"].as_str().unwrap())
        .unwrap();
    let decoded: Value = serde_json::from_slice(&statement).unwrap();
    let installations: Value = serde_json::from_slice(INSTALLATIONS).unwrap();
    assert_eq!(
        decoded["installation_permissions"],
        installations[0]["permissions"]
    );
    assert_eq!(decoded["repo"], REPO);
    assert_eq!(decoded["agent_id"], AGENT);
    assert_eq!(decoded["prior_version"], 28);
    assert_eq!(decoded["manifest_sha256"], answer["manifest_sha256"]);
    rig.with_raw_conn(|conn| {
        let (bytes,permissions,stored_statement):(Vec<u8>,Vec<u8>,Vec<u8>)=conn.query_row("SELECT manifest_bytes,installation_permissions,statement_bytes FROM gh_manifest_proposals",[],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?)))?;
        assert_eq!(stored_statement,statement);
        assert_eq!(permissions,br#"{"contents":"read","issues":"write","metadata":"read","pull_requests":"write"}"#);
        assert_eq!(hash(&bytes),answer["manifest_sha256"]);
        let expected=std::str::from_utf8(V28).unwrap()
            .replace("\"manifest_version\": 28","\"manifest_version\": 29")
            .replace("\"issued_at_unix_secs\": 1794355200","\"issued_at_unix_secs\": 1794355300")
            .replace("\"cortexkit/opencode-sidebar\": \"agent_3333333333333333\"\n", &format!("\"cortexkit/opencode-sidebar\": \"agent_3333333333333333\",\n    \"{REPO}\": \"{AGENT}\"\n"));
        assert_eq!(bytes,expected.as_bytes());
        let mut built:Value=serde_json::from_slice(&bytes).unwrap();
        let old:Value=serde_json::from_slice(V28).unwrap();
        assert_eq!(built["manifest_version"],29);assert_eq!(built["issued_at_unix_secs"],NOW/1000);
        assert_eq!(built["bindings"].as_object_mut().unwrap().remove(REPO),Some(json!(AGENT)));
        built["manifest_version"]=old["manifest_version"].clone();built["issued_at_unix_secs"]=old["issued_at_unix_secs"].clone();
        assert_eq!(built,old);
        Ok(())
    }).unwrap();
    let before = snapshot(&rig);
    assert_eq!(
        reply(propose(&rig, &IdentityStub::good(), &HttpStub::good()).await),
        answer
    );
    assert_eq!(snapshot(&rig), before);
}

#[tokio::test(start_paused = true)]
async fn manifest_propose_deadlines_classify_identity_and_installation() {
    for stage in ["identity", "installation"] {
        let rig = rig("");
        let before = snapshot(&rig);
        let mut identity = IdentityStub::good();
        let mut http = HttpStub::good();
        identity.hang = stage == "identity";
        http.hang = stage == "installation";
        assert_refusal(
            propose(&rig, &identity, &http).await,
            if stage == "identity" {
                "identity_unavailable"
            } else {
                "github_unavailable"
            },
            "transient",
        );
        assert_eq!(
            http.calls.load(Ordering::SeqCst),
            if stage == "identity" { 0 } else { 1 }
        );
        assert_eq!(snapshot(&rig), before);
    }
}

#[tokio::test(start_paused = true)]
async fn manifest_propose_identity_completing_at_deadline_is_still_identity_unavailable() {
    let rig = rig("");
    let before = snapshot(&rig);
    let mut identity = IdentityStub::good();
    identity.exhaust = true;
    let http = HttpStub::new(vec![]);
    assert_refusal(
        propose(&rig, &identity, &http).await,
        "identity_unavailable",
        "transient",
    );
    assert_eq!(http.calls.load(Ordering::SeqCst), 0);
    assert_eq!(snapshot(&rig), before);
}

#[tokio::test(start_paused = true)]
async fn manifest_propose_writer_lock_past_deadline_never_inserts_later() {
    let rig = rig("");
    let before = snapshot(&rig);
    let competing = Connection::open(&rig.path).unwrap();
    competing.execute_batch("BEGIN IMMEDIATE").unwrap();
    let completed = Arc::new(tokio::sync::Notify::new());
    let signal = Arc::clone(&completed);
    let store = Arc::clone(&rig.store);
    let job = tokio::spawn(async move {
        let identity = IdentityStub::good();
        let mut http = HttpStub::good();
        http.completed = Some(signal);
        let p = preflight(&store, Some(&plexus()), &params()).ok().unwrap();
        checked_proposal(
            store,
            p,
            &identity,
            Ok(&http),
            Instant::now() + PROPOSE_DEADLINE,
            || NOW,
        )
        .await
    });
    // On this current-thread runtime, the ready final HTTP response runs through
    // preparation and queues the blocking write before the task yields to us.
    completed.notified().await;
    tokio::time::advance(PROPOSE_DEADLINE).await;
    assert!(
        !job.is_finished(),
        "the blocking writer must be awaited, not detached at expiry"
    );
    competing.execute_batch("ROLLBACK").unwrap();
    assert_refusal(job.await.unwrap(), "github_unavailable", "transient");
    assert_eq!(snapshot(&rig), before);
}

#[tokio::test(start_paused = true)]
async fn manifest_propose_admitted_before_deadline_returns_committed_reply() {
    let rig = rig("");
    let deadline = Instant::now() + PROPOSE_DEADLINE;
    tokio::time::advance(PROPOSE_DEADLINE - Duration::from_millis(1)).await;
    let (admitted_tx, admitted_rx) = tokio::sync::oneshot::channel();
    let (finish_tx, finish_rx) = std::sync::mpsc::channel();
    let store = Arc::clone(&rig.store);
    let job = tokio::spawn(async move {
        let p = preflight(&store, Some(&plexus()), &params()).ok().unwrap();
        checked_proposal(
            store,
            p,
            &IdentityStub::good(),
            Ok(&HttpStub::good()),
            deadline,
            move || {
                admitted_tx.send(()).unwrap();
                finish_rx.recv().unwrap();
                NOW
            },
        )
        .await
    });
    admitted_rx.await.unwrap();
    tokio::time::advance(Duration::from_millis(1)).await;
    assert!(
        !job.is_finished(),
        "an admitted write must finish even when the budget expires"
    );
    finish_tx.send(()).unwrap();
    assert_eq!(reply(job.await.unwrap())["status"], "approval_required");
    assert_eq!(snapshot(&rig)[1].len(), 1);
}

async fn wire(
    rig: &Rig,
    caller: crate::federation::RouteCaller,
    method: &str,
    p: Value,
) -> (subc_protocol::FrameType, Vec<u8>) {
    use credentials_core::{
        engine::RefreshEngine,
        key::{MasterKey, MASTER_KEY_LEN},
    };
    use subc_protocol::{Flags, Frame, FrameType, Priority, PROTOCOL_VERSION};
    let key = MasterKey::from_bytes([201; MASTER_KEY_LEN]);
    let engine = Arc::new(RefreshEngine::new(
        Arc::clone(&rig.store),
        vec![],
        Arc::new(crate::test_support::NoHttp),
    ));
    let admin = Arc::new(crate::admin_surface::AdminSurface::new(
        engine,
        credentials_core::admin_auth::AdminMacKey::derive(&key),
        [0; 32],
        key.key_id(),
    ));
    let frame = Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        1,
        1,
        1,
        serde_json::to_vec(&json!({"method":method,"params":p})).unwrap(),
    )
    .unwrap();
    let (tx, mut rx) = tokio::sync::mpsc::channel(1);
    crate::dispatch_route_request(frame, &tx, &rig.surface, &admin, caller, None)
        .await
        .unwrap();
    let frame = rx.recv().await.unwrap();
    (frame.header.ty, frame.body)
}

#[tokio::test]
async fn manifest_propose_dispatch_pins_uniform_principals_and_transport_shape_errors() {
    use crate::federation::RouteCaller;
    use subc_protocol::FrameType;
    let rig = rig("");
    let before = snapshot(&rig);
    let unknown = wire(
        &rig,
        RouteCaller::Principal(None),
        "credential.get",
        json!({"handle":"unknown"}),
    )
    .await;
    assert_eq!(unknown.0, FrameType::Response);
    for caller in [
        RouteCaller::Principal(None),
        RouteCaller::Principal(Some(Principal::Reserved {
            module_id: "aft".into(),
        })),
        RouteCaller::Refused,
        RouteCaller::Phone("a".repeat(64)),
    ] {
        assert_eq!(
            wire(&rig, caller, OP_PROPOSE_BINDING, json!({"bad":"shape"})).await,
            unknown
        );
    }
    let (kind, body) = wire(
        &rig,
        RouteCaller::Principal(Some(plexus())),
        OP_PROPOSE_BINDING,
        json!({"agent_id":"bad/id"}),
    )
    .await;
    assert_eq!(kind, FrameType::Error);
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["code"], "invalid_params");
    assert!(body.get("class").is_none());
    let (kind, body) = wire(
        &rig,
        RouteCaller::Principal(Some(plexus())),
        OP_PROPOSE_BINDING,
        params(),
    )
    .await;
    assert_eq!(kind, FrameType::Response);
    assert_eq!(
        serde_json::from_slice::<Value>(&body).unwrap(),
        json!({"result":{"error":{"code":"identity_unavailable","class":"transient"}}})
    );
    assert_eq!(snapshot(&rig), before);
}
