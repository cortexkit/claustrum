use super::*;
use credentials_core::{
    audit::{AuditCtx, AuditOp},
    record::{CredentialKind, VaultRecord},
    refresh_adapters::{HttpResponse, RefreshError},
    store::{EncryptedStore, SelectorKind},
    test_support::TestTempDir,
};
use std::sync::Mutex as StdMutex;

const AUD: &str = "cortexkit-runners";
const ACCOUNT: &str = "01K00000000000000000000080";
const KEY: &str = "01MCC5RM006NDK01XD1WTB7Z1P";
const VAULT_KEY: &str = "signing:ck-account-machine:1";
fn vectors() -> Value {
    serde_json::from_str(include_str!(
        "../tests/fixtures/account-machine/vectors.json"
    ))
    .unwrap()
}
fn observation(name: &str, part: &str) -> Value {
    let v = vectors();
    let row = v["observations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == name)
        .unwrap();
    serde_json::from_str(row[part]["body"].as_str().unwrap()).unwrap()
}
fn challenge() -> Value {
    observation("worker:cortexkit-runners:challenge", "reply")
}
fn success() -> Value {
    observation("worker:cortexkit-runners:accepted", "reply")
}
fn reply(status: u16, body: Value) -> Result<HttpResponse, RefreshError> {
    Ok(HttpResponse {
        status,
        body: serde_json::to_vec(&body).unwrap(),
    })
}
fn exchange() -> Vec<Result<HttpResponse, RefreshError>> {
    vec![reply(200, challenge()), reply(200, success())]
}

// The same queued-response boundary used by refresh-adapter tests, with a yield
// so simultaneous requests overlap even on a single-threaded test runtime.
struct Server {
    replies: StdMutex<std::collections::VecDeque<Result<HttpResponse, RefreshError>>>,
    requests: StdMutex<Vec<(String, Value)>>,
}
impl Server {
    fn new(replies: Vec<Result<HttpResponse, RefreshError>>) -> Arc<Self> {
        Arc::new(Self {
            replies: StdMutex::new(replies.into()),
            requests: StdMutex::new(Vec::new()),
        })
    }
    fn requests(&self) -> Vec<(String, Value)> {
        self.requests.lock().unwrap().clone()
    }
}
#[async_trait::async_trait]
impl HttpTransport for Server {
    async fn post(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        content_type: &str,
        body: Vec<u8>,
    ) -> Result<HttpResponse, RefreshError> {
        assert!(headers.is_empty(), "exchange sends no bearer");
        assert_eq!(content_type, "application/json");
        self.requests
            .lock()
            .unwrap()
            .push((url.into(), serde_json::from_slice(&body).unwrap()));
        tokio::task::yield_now().await;
        self.replies
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| Err(RefreshError::Transport("stand-in exhausted".into())))
    }
    async fn get(&self, _: &str, _: &[(&str, &str)]) -> Result<HttpResponse, RefreshError> {
        panic!("exchange is POST only")
    }
}
fn principal() -> Principal {
    Principal::Reserved {
        module_id: "ck-motor".into(),
    }
}
fn params() -> AccountTokenParams {
    AccountTokenParams {
        audience: AUD.into(),
        enrollment_token: None,
        min_ttl_ms: None,
    }
}
struct Rig {
    surface: ReadSurface,
    store: Arc<EncryptedStore>,
    root: TestTempDir,
    http: Arc<Server>,
}
impl Rig {
    fn new(replies: Vec<Result<HttpResponse, RefreshError>>) -> Self {
        let (old, store, _, root) = crate::tests::tmp_surface_with_store(171);
        let http = Server::new(replies);
        let mut surface = ReadSurface::new(
            Arc::clone(&old.engine),
            crate::limiter::FetchLimiter::new(crate::limiter::Caps::default()),
        );
        surface.account_tokens.machine_path = Some(root.join("machine.json"));
        surface.account_tokens.transport = Some(http.clone());
        surface.account_tokens.clock = Some(1_800_000_000_000);
        let seed = unhex(vectors()["machine_private_seed_hex"].as_str().unwrap());
        let public = unhex(vectors()["machine_public_key_hex"].as_str().unwrap());
        // RFC 8410 PKCS#8 v1 for the corpus's public RFC 8032 seed.
        let mut der = unhex("302e020100300506032b657004220420");
        der.extend_from_slice(&seed);
        let pem = format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            base64::engine::general_purpose::STANDARD.encode(der)
        );
        assert_eq!(
            credentials_core::signing::public_key_ed25519(&pem)
                .unwrap()
                .public_key_hex,
            hex(&public)
        );
        let mut record = VaultRecord::new_static(
            CredentialKind::SigningKey,
            "public-vector",
            pem.into_bytes(),
            None,
        );
        record.audit_each_signature = true;
        store.create(VAULT_KEY, &record).unwrap();
        store
            .create_read_grant_audited(
                "reserved",
                "ck-motor",
                SelectorKind::Audience,
                AUD,
                GrantOperation::AccountToken,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .unwrap();
        let rig = Self {
            surface,
            store,
            root,
            http,
        };
        rig.write_machine(json!({"account":ACCOUNT,"key_id":KEY,"public_key_hex":vectors()["machine_public_key_hex"],"label":"Test Mac","vault_key_id":VAULT_KEY,"enrollment_jti":null}));
        rig
    }
    fn write_machine(&self, value: Value) {
        let path = self.root.join("machine.json");
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
    async fn call(&self) -> Mint {
        self.surface
            .account_token(Some(&principal()), &params())
            .await
    }
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|v| format!("{v:02x}")).collect()
}
fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|n| u8::from_str_radix(&s[n..n + 2], 16).unwrap())
        .collect()
}
fn error(outcome: Mint) -> AccountTokenError {
    match outcome {
        Err(e) => e,
        Ok(_) => panic!("expected refusal"),
    }
}

#[tokio::test]
async fn account_token_granted_vector_signature_and_audit() {
    let rig = Rig::new(exchange());
    let before = rig.store.audit_tip().unwrap();
    let token = rig.call().await.unwrap();
    assert_eq!(token.jwt.expose(), success()["jwt"].as_str().unwrap());
    assert_eq!(token.expires_at_ms, 1_800_000_900_000);
    let requests = rig.http.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(
        requests[0],
        (
            "https://account.cortexkit.io/v1/machine/token/challenge".into(),
            json!({"key_id":KEY,"aud":AUD})
        )
    );
    assert_eq!(
        requests[1].0,
        "https://account.cortexkit.io/v1/machine/token"
    );
    assert_eq!(
        requests[1].1,
        observation("worker:cortexkit-runners:accepted", "request")
    );
    let proof = vectors()["proofs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == "worker:cortexkit-runners")
        .unwrap()
        .clone();
    let transcript = worker_transcript(
        ACCOUNT,
        KEY,
        requests[1].1["challenge"].as_str().unwrap(),
        AUD,
    )
    .unwrap();
    assert_eq!(
        transcript.as_bytes(),
        unhex(proof["transcript_utf8_hex"].as_str().unwrap())
    );
    assert_eq!(transcript, proof["transcript"]);
    ring::signature::UnparsedPublicKey::new(
        &ring::signature::ED25519,
        unhex(vectors()["machine_public_key_hex"].as_str().unwrap()),
    )
    .verify(
        transcript.as_bytes(),
        &unhex(requests[1].1["sig_hex"].as_str().unwrap()),
    )
    .unwrap();
    rig.call().await.unwrap();
    assert_eq!(
        rig.store.audit_tip().unwrap(),
        before,
        "mints never append the HMAC chain, even for audit-each-signature keys"
    );
    let events = rig.store.recent_auth_events(64).unwrap();
    let first: Vec<_> = events
        .iter()
        .filter(|e| e.kind == "scoped_first_use" && e.credential_id == AUD)
        .collect();
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].detail.as_deref(), Some("account_token"));
    assert_eq!(first[0].principal_id.as_deref(), Some("ck-motor"));
}

#[tokio::test]
async fn account_token_challenge_binding_before_signing() {
    for (field, value) in [
        ("account", "01K00000000000000000000081"),
        ("key_id", "01MCC5RM006NDK01XD1WTB7Z1Q"),
        ("purpose", "machine_complete"),
        ("aud", "cortexkit-account"),
    ] {
        let raw = challenge()["challenge"].as_str().unwrap().to_owned();
        let (payload, mac) = raw.split_once('.').unwrap();
        let mut p: Value = serde_json::from_slice(&decode(payload).unwrap()).unwrap();
        p[field] = json!(value);
        let wrong = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&p).unwrap()),
            mac
        );
        let rig = Rig::new(vec![reply(
            200,
            json!({"challenge":wrong,"expires_at_ms":1800000300000_i64}),
        )]);
        assert_eq!(
            error(rig.call().await).class,
            ErrorClass::Permanent,
            "{field}"
        );
        assert_eq!(
            rig.http.requests().len(),
            1,
            "{field}: no proof leaves the vault"
        );
    }
}

#[tokio::test]
async fn account_token_audience_grant_is_not_signing_or_other_audience_authority() {
    let rig = Rig::new(vec![]);
    for audience in ["cortexkit-account", "unrecognized"] {
        let mut p = params();
        p.audience = audience.into();
        assert_eq!(
            error(rig.surface.account_token(Some(&principal()), &p).await).code,
            "not_found"
        );
    }
    for p in [
        None,
        Some(Principal::Direct),
        Some(Principal::Reserved {
            module_id: "other".into(),
        }),
    ] {
        assert_eq!(
            error(rig.surface.account_token(p.as_ref(), &params()).await).code,
            "not_found"
        );
    }
    assert!(!rig
        .store
        .read_grant_covers("reserved", "ck-motor", VAULT_KEY, GrantOperation::Sign)
        .unwrap());
    assert!(rig.http.requests().is_empty());
}

#[tokio::test]
async fn account_token_cache_window_and_minimum_ttl() {
    let mut rig = Rig::new(
        [exchange(), exchange(), exchange()]
            .into_iter()
            .flatten()
            .collect(),
    );
    rig.store
        .create_read_grant_audited(
            "reserved",
            "other-consumer",
            SelectorKind::Audience,
            AUD,
            GrantOperation::AccountToken,
            AuditCtx::admin(AuditOp::GrantCreate),
        )
        .unwrap();
    rig.call().await.unwrap();
    rig.surface
        .account_token(
            Some(&Principal::Reserved {
                module_id: "other-consumer".into(),
            }),
            &params(),
        )
        .await
        .unwrap();
    assert_eq!(rig.http.requests().len(), 2);
    let mut p = params();
    p.min_ttl_ms = Some(901_000);
    rig.surface
        .account_token(Some(&principal()), &p)
        .await
        .unwrap();
    assert_eq!(rig.http.requests().len(), 4);
    rig.surface.account_tokens.clock = Some(1_800_000_840_000);
    rig.call().await.unwrap();
    assert_eq!(
        rig.http.requests().len(),
        6,
        "exactly sixty seconds is not a cache hit"
    );
}

#[tokio::test]
async fn account_token_single_flight() {
    let rig = Arc::new(Rig::new(exchange()));
    let mut tasks = Vec::new();
    for _ in 0..24 {
        let rig = rig.clone();
        tasks.push(tokio::spawn(async move { rig.call().await }));
    }
    for task in tasks {
        task.await.unwrap().unwrap();
    }
    assert_eq!(rig.http.requests().len(), 2);
}

#[tokio::test]
async fn account_token_failed_flight_is_shared_and_audited_once() {
    let rig = Arc::new(Rig::new(vec![reply(
        503,
        json!({"error":"exchange_disabled","retry_after_s":5}),
    )]));
    let mut tasks = Vec::new();
    for _ in 0..24 {
        let rig = rig.clone();
        tasks.push(tokio::spawn(async move { rig.call().await }));
    }
    for task in tasks {
        assert_eq!(error(task.await.unwrap()).code, "exchange_disabled");
    }
    assert_eq!(rig.http.requests().len(), 1);
    assert_eq!(
        rig.store
            .recent_auth_events(64)
            .unwrap()
            .iter()
            .filter(|e| e.detail.as_deref() == Some("exchange_disabled"))
            .count(),
        1
    );
}

#[tokio::test]
async fn account_token_refusal_classes_retry_and_diagnostics() {
    let catalogue: Value = serde_json::from_str(include_str!(
        "../tests/fixtures/account-machine/refusals.json"
    ))
    .unwrap();
    for (code, status, class) in [
        ("invalid_request", 400, ErrorClass::Permanent),
        ("auth_failed", 401, ErrorClass::Permanent),
        ("signature_invalid", 401, ErrorClass::Permanent),
        ("machine_revoked", 401, ErrorClass::AuthRequired),
        ("machine_not_found", 401, ErrorClass::AuthRequired),
        ("account_not_active", 403, ErrorClass::AuthRequired),
        ("rate_limited", 429, ErrorClass::Transient),
        ("exchange_disabled", 503, ErrorClass::Transient),
        ("account_check_unavailable", 503, ErrorClass::Transient),
    ] {
        assert_eq!(catalogue[code], status);
        for on_token in [false, true] {
            let mut responses = Vec::new();
            if on_token {
                responses.push(reply(200, challenge()));
            }
            responses.push(reply(status, json!({"error":code,"retry_after_s":7})));
            let rig = Rig::new(responses);
            let e = error(rig.call().await);
            assert_eq!(e.code, code);
            assert_eq!(e.class, class, "{code}");
            assert_eq!(
                e.retry_after_ms,
                if matches!(status, 429 | 503) {
                    Some(7000)
                } else {
                    None
                }
            );
            assert_eq!(rig.http.requests().len(), if on_token { 2 } else { 1 });
            let events = rig.store.recent_auth_events(64).unwrap();
            assert_eq!(events.iter().filter(|e| e.kind=="scoped_read_refusal" && e.detail.as_deref()==Some(code)).count(),1);
        }
    }
    let rig = Rig::new(vec![Err(RefreshError::Transport("offline".into()))]);
    assert_eq!(error(rig.call().await).class, ErrorClass::Transient);
    for code in ["challenge_expired", "challenge_spent", "issuance_expired"] {
        assert_eq!(catalogue[code], 409);
        let rig = Rig::new(
            [
                vec![reply(200, challenge()), reply(409, json!({"error":code}))],
                exchange(),
            ]
            .into_iter()
            .flatten()
            .collect(),
        );
        rig.call().await.unwrap();
        assert_eq!(rig.http.requests().len(), 4);
        let rig = Rig::new(vec![
            reply(409, json!({"error":code})),
            reply(409, json!({"error":code})),
        ]);
        let e = error(rig.call().await);
        assert_eq!(e.code, code);
        assert_eq!(e.class, ErrorClass::Transient);
        assert_eq!(rig.http.requests().len(), 2, "exactly one retry");
    }
}

#[tokio::test]
async fn account_token_machine_file_shape_and_custody() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../tests/fixtures/account-machine/machine.json"
    ))
    .unwrap();
    assert!(serde_json::from_value::<Machine>(fixture.clone()).is_ok());
    for change in [
        "missing", "null", "public", "vault", "unknown", "symlink", "mode",
    ] {
        let rig = Rig::new(vec![]);
        let mut machine = fixture.clone();
        match change {
            "missing" => std::fs::remove_file(rig.root.join("machine.json")).unwrap(),
            "null" => {
                machine["key_id"] = Value::Null;
                rig.write_machine(machine);
            }
            "public" => {
                machine["public_key_hex"] = json!("00".repeat(32));
                rig.write_machine(machine);
            }
            "vault" => {
                machine["vault_key_id"] = json!("signing:ck-account-machine:2");
                rig.write_machine(machine);
            }
            "unknown" => {
                machine["unexpected"] = json!(true);
                rig.write_machine(machine);
            }
            #[cfg(unix)]
            "symlink" => {
                let path = rig.root.join("machine.json");
                std::fs::rename(&path, rig.root.join("real.json")).unwrap();
                std::os::unix::fs::symlink(rig.root.join("real.json"), path).unwrap();
            }
            #[cfg(unix)]
            "mode" => {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(
                    rig.root.join("machine.json"),
                    std::fs::Permissions::from_mode(0o644),
                )
                .unwrap();
            }
            _ => continue,
        }
        let e = error(rig.call().await);
        assert_eq!(e.code, "account_login_required", "{change}");
        assert_eq!(e.class, ErrorClass::AuthRequired, "{change}");
        assert!(rig.http.requests().is_empty(), "{change}");
    }
}

#[tokio::test]
async fn account_token_enrolled_token_uses_same_scoped_path() {
    let rig = Rig::new(exchange());
    let secret = "a".repeat(64);
    let hash = credentials_core::enrollment::enrollment_secret_hash(&secret).unwrap();
    let request = rig.store.propose_enrollment("motor-test", &hash).unwrap();
    rig.store
        .approve_enrollment(&request.request_id, "motor-test", "operator")
        .unwrap();
    let token = match rig
        .store
        .poll_enrollment(&request.request_id, &secret)
        .unwrap()
    {
        credentials_core::enrollment::EnrollmentPoll::Approved { token, .. } => token,
        other => panic!("expected enrollment token, got {other:?}"),
    };
    rig.store
        .create_read_grant_audited(
            "enrolled",
            "motor-test",
            SelectorKind::Audience,
            AUD,
            GrantOperation::AccountToken,
            AuditCtx::admin(AuditOp::GrantCreate),
        )
        .unwrap();
    let mut p = params();
    p.enrollment_token = Some(token);
    rig.surface
        .account_token(Some(&Principal::Direct), &p)
        .await
        .unwrap();
    p.enrollment_token = Some("bad-token".into());
    assert_eq!(
        error(rig.surface.account_token(Some(&principal()), &p).await).code,
        "not_found"
    );
}

#[tokio::test]
async fn account_token_wire_fixture_is_producer_generated() {
    let mut token = success();
    let claims: Value = serde_json::from_slice(
        &decode(token["jwt"].as_str().unwrap().split('.').nth(1).unwrap()).unwrap(),
    )
    .unwrap();
    token["jwt"] = json!(format!(
        "e30.{}.fake-signature",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
    ));
    let rig = Rig::new(vec![reply(200, challenge()), reply(200, token)]);
    let key = credentials_core::MasterKey::from_bytes([171; 32]);
    let admin = Arc::new(crate::admin_surface::AdminSurface::new(
        Arc::clone(&rig.surface.engine),
        credentials_core::admin_auth::AdminMacKey::derive(&key),
        [0; 32],
        key.key_id(),
    ));
    let surface = Arc::new(rig.surface);
    let p = params();
    let request = serde_json::to_value(&p).unwrap();
    let success = crate::tests::deposit_cookie_frame(
        &surface,
        &admin,
        Some(principal()),
        crate::OP_ACCOUNT_TOKEN,
        request.clone(),
    )
    .await;
    let refused = crate::tests::deposit_cookie_frame(
        &surface,
        &admin,
        Some(Principal::Direct),
        crate::OP_ACCOUNT_TOKEN,
        request,
    )
    .await;
    assert_eq!(success.header.ty, subc_protocol::FrameType::Response);
    let success_body: Value = serde_json::from_slice(&success.body).unwrap();
    assert!(success_body["result"]["jwt"]
        .as_str()
        .unwrap()
        .ends_with("fake-signature"));
    let refusal_body: Value = serde_json::from_slice(&refused.body).unwrap();
    assert_eq!(
        refusal_body,
        crate::wrap_result(json!({"error":{"code":"not_found","class":"permanent"}}))
    );
    let row = json!({"op":crate::OP_ACCOUNT_TOKEN,"request":serde_json::to_string(&p).unwrap(),"success":[String::from_utf8(success.body).unwrap()],"refusals":[String::from_utf8(refused.body).unwrap()]});
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/enrollment_wire_contract.json");
    let mut fixture: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let operations = fixture["operations"].as_array_mut().unwrap();
    if std::env::var_os("UPDATE_ENROLLMENT_WIRE_FIXTURE").is_some() {
        println!(
            "ACCOUNT_TOKEN_FIXTURE:{}",
            serde_json::to_string(&row).unwrap()
        );
        if let Some(old) = operations
            .iter_mut()
            .find(|r| r["op"] == crate::OP_ACCOUNT_TOKEN)
        {
            *old = row;
        } else {
            operations.push(row);
        }
        std::fs::write(
            path,
            format!("{}\n", serde_json::to_string_pretty(&fixture).unwrap()),
        )
        .unwrap();
    } else {
        assert_eq!(
            operations
                .iter()
                .find(|r| r["op"] == crate::OP_ACCOUNT_TOKEN),
            Some(&row),
            "regenerate with UPDATE_ENROLLMENT_WIRE_FIXTURE=1 and review producer samples"
        );
    }
}

#[test]
fn account_token_vendored_fixture_checksums() {
    for (bytes, expected) in [
        (
            include_bytes!("../tests/fixtures/account-machine/vectors.json").as_slice(),
            "1018385d6b632d74fe6c6d63ed1ec07554889483bbe628da6e7a1cf27b5380f1",
        ),
        (
            include_bytes!("../tests/fixtures/account-machine/refusals.json").as_slice(),
            "98041300fda819e6ffd526460ada9731140541b5c33780538a9e42dd4543c4ce",
        ),
        (
            include_bytes!("../tests/fixtures/account-machine/machine-key-contract.md").as_slice(),
            "1e7fc59c7546db464dc4b60d042f42d4ed129b37a30003377860c8e8fe3e4de8",
        ),
    ] {
        assert_eq!(
            hex(ring::digest::digest(&ring::digest::SHA256, bytes).as_ref()),
            expected
        );
    }
}

/// The vault must find the enrollment where `ck account` wrote it: a non-empty
/// `XDG_STATE_HOME` wins over `HOME`, and an empty one is ignored, as in the CLI.
#[test]
fn machine_state_path_resolves_like_the_account_cli() {
    let p = |xdg: Option<&str>, home: Option<&str>| {
        machine_state_path(xdg.map(Into::into), home.map(Into::into))
    };
    assert_eq!(
        p(Some("/state"), Some("/home/u")),
        Some(PathBuf::from("/state/cortexkit/account/machine.json"))
    );
    assert_eq!(
        p(Some(""), Some("/home/u")),
        Some(PathBuf::from(
            "/home/u/.local/state/cortexkit/account/machine.json"
        ))
    );
    assert_eq!(
        p(None, Some("/home/u")),
        Some(PathBuf::from(
            "/home/u/.local/state/cortexkit/account/machine.json"
        ))
    );
    assert_eq!(p(None, None), None);
}
