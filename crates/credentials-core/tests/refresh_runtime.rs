use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use async_trait::async_trait;
use cortexkit_store::{open_sqlite, Isolation, StorageBackend, StorageDescriptor};
use credentials_core::{
    engine::{EngineError, RefreshEngine},
    key::MasterKey,
    oauth::OAuthCredential,
    record::VaultRecord,
    refresh_adapters::{
        xai::XaiAdapter, HttpResponse, HttpTransport, RefreshAdapter, RefreshError, RefreshedTokens,
    },
    store::{EncryptedStore, StoreOpError},
    test_support::TestTempDir,
};

fn store() -> (TestTempDir, Arc<EncryptedStore>, rusqlite::Connection) {
    static SEQ: AtomicUsize = AtomicUsize::new(0);
    let dir = TestTempDir::new(format!(
        "refresh-runtime-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let path = dir.join("store.db");
    let raw = open_sqlite(&StorageDescriptor {
        module_id: "refresh-runtime".into(),
        storage_namespace: "default".into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: path.to_string_lossy().into_owned(),
        },
    })
    .unwrap();
    EncryptedStore::migrate(&raw).unwrap();
    let store = EncryptedStore::open(raw, MasterKey::from_bytes([23; 32])).unwrap();
    let conn = rusqlite::Connection::open(path).unwrap();
    (dir, Arc::new(store), conn)
}

fn record(adapter: &str, expires_at_ms: i64) -> VaultRecord {
    VaultRecord::new_oauth(
        "test",
        adapter,
        OAuthCredential {
            access_token: "old-access".to_string().into(),
            refresh_token: "old-refresh".to_string().into(),
            expires_at_ms: Some(expires_at_ms),
            token_url: credentials_core::refresh_adapters::xai::TOKEN_URL.into(),
            client_id: None,
            client_secret: None,
            scopes: vec![],
        },
        b"old-access".to_vec(),
    )
}

#[derive(Default)]
struct RotatingAdapter(AtomicUsize);

struct StatusTransport {
    status: u16,
    calls: AtomicUsize,
}

impl StatusTransport {
    fn new(status: u16) -> Self {
        Self {
            status,
            calls: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl HttpTransport for StatusTransport {
    async fn post(
        &self,
        _url: &str,
        _headers: &[(&str, &str)],
        _content_type: &str,
        _body: Vec<u8>,
    ) -> Result<HttpResponse, RefreshError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(HttpResponse {
            status: self.status,
            body: vec![],
        })
    }
}

#[async_trait]
impl RefreshAdapter for RotatingAdapter {
    fn name(&self) -> &str {
        "rotating-test"
    }

    async fn refresh(
        &self,
        cred: &OAuthCredential,
        _http: &dyn HttpTransport,
    ) -> Result<RefreshedTokens, RefreshError> {
        assert_eq!(cred.refresh_token.expose(), "old-refresh");
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(RefreshedTokens {
            access_token: "new-access".to_string().into(),
            refresh_token: "new-refresh".to_string().into(),
            expires_at_ms: Some(i64::MAX),
            github_app_permissions: None,
        })
    }
}

async fn failed_commit_blocks_next_read(expires_at_ms: i64) {
    let (_dir, store, conn) = store();
    store
        .create("oauth:test", &record("rotating-test", expires_at_ms))
        .unwrap();
    // Abort after the credential UPDATE but before the intent DELETE commits, so
    // the entire token transaction rolls back while txn1 remains durable.
    conn.execute_batch(
        "CREATE TRIGGER fail_refresh_commit BEFORE DELETE ON refresh_intent
         BEGIN SELECT RAISE(ABORT, 'injected commit failure'); END;",
    )
    .unwrap();
    let adapter = Arc::new(RotatingAdapter::default());
    let engine = RefreshEngine::new(
        store.clone(),
        vec![adapter.clone()],
        Arc::new(StatusTransport::new(500)),
    );
    let error = engine.get("oauth:test", None, true).await.unwrap_err();
    assert!(
        matches!(&error, EngineError::Store(StoreOpError::Store(message)) if message.contains("injected commit failure")),
        "{error:?}"
    );
    assert_eq!(adapter.0.load(Ordering::SeqCst), 1);
    assert_eq!(store.list_intents().unwrap().len(), 1);
    assert_eq!(store.get("oauth:test").unwrap().record_version, 1);
    conn.execute_batch("DROP TRIGGER fail_refresh_commit;")
        .unwrap();

    let next = engine.get("oauth:test", None, false).await;
    assert_eq!(
        adapter.0.load(Ordering::SeqCst),
        1,
        "must not replay a consumed refresh token"
    );
    assert!(
        matches!(next, Err(EngineError::Store(StoreOpError::NeedsReauth))),
        "{next:?}"
    );
    assert!(matches!(
        engine.get("oauth:test", None, true).await,
        Err(EngineError::Store(StoreOpError::NeedsReauth))
    ));
    assert_eq!(adapter.0.load(Ordering::SeqCst), 1);
    assert_eq!(store.list_intents().unwrap().len(), 1);
    engine.reconcile().await.unwrap();
    assert!(matches!(
        store.get("oauth:test"),
        Err(StoreOpError::NeedsReauth)
    ));
    assert!(store.list_intents().unwrap().is_empty());
    assert_eq!(adapter.0.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn failed_rotating_commit_blocks_fresh_read_until_reconciliation() {
    failed_commit_blocks_next_read(i64::MAX).await;
}

#[tokio::test]
async fn failed_rotating_commit_never_replays_expired_refresh_token() {
    failed_commit_blocks_next_read(0).await;
}

#[tokio::test]
async fn xai_subscription_denial_latches_but_server_failure_stays_retryable() {
    for status in [403, 503] {
        let (_dir, store, _conn) = store();
        store.create("oauth:xai", &record("xai", 0)).unwrap();
        let http = Arc::new(StatusTransport::new(status));
        let engine = RefreshEngine::new(
            store.clone(),
            vec![Arc::new(XaiAdapter::new())],
            http.clone(),
        );
        let error = engine.get("oauth:xai", None, false).await.unwrap_err();
        if status == 403 {
            assert!(
                matches!(
                    error,
                    EngineError::RefreshFailed(RefreshError::SubscriptionRequired)
                ),
                "{error:?}"
            );
            assert!(matches!(
                engine.get("oauth:xai", None, false).await,
                Err(EngineError::Store(StoreOpError::NeedsReauth))
            ));
            assert_eq!(http.calls.load(Ordering::SeqCst), 1);
            assert!(matches!(
                store.get("oauth:xai"),
                Err(StoreOpError::NeedsReauth)
            ));
        } else {
            assert!(
                matches!(
                    error,
                    EngineError::RefreshFailed(RefreshError::Status(503, _))
                ),
                "{error:?}"
            );
            assert!(store.get("oauth:xai").is_ok());
        }
        assert!(store.list_intents().unwrap().is_empty());
    }
}

#[test]
fn claude_plan_mappings_are_specific_to_the_source_field() {
    use credentials_core::plan_detection::anthropic_profile;
    for (field, raw, tier) in [
        ("rate_limit_tier", "default_claude_max_20x", Some("max_20x")),
        ("rate_limit_tier", "default_claude_max_5x", Some("max_5x")),
        ("rate_limit_tier", "default_claude_pro", Some("pro")),
        ("organization_type", "claude_pro", Some("pro")),
        ("rate_limit_tier", "claude_pro", None),
        ("organization_type", "default_claude_max_20x", None),
        ("organization_type", "default_claude_max_5x", None),
        ("organization_type", "default_claude_pro", None),
        ("rate_limit_tier", "unknown", None),
        ("organization_type", "unknown", None),
    ] {
        let profile = serde_json::json!({"organization": {(field): raw}});
        let plan = anthropic_profile(&serde_json::to_vec(&profile).unwrap()).unwrap();
        assert_eq!(plan.raw.as_deref(), Some(raw));
        assert_eq!(plan.tier.as_deref(), tier, "{field}={raw}");
    }
    let plan = anthropic_profile(
        br#"{"organization":{"rate_limit_tier":"unknown","organization_type":"claude_pro"}}"#,
    )
    .unwrap();
    assert_eq!(plan.raw.as_deref(), Some("unknown"));
    assert_eq!(plan.tier, None);
}

#[test]
fn callback_listener_docs_distinguish_provider_bind_policies() {
    for source in [
        include_str!("../src/refresh_adapters/openai.rs"),
        include_str!("../src/refresh_adapters/xai.rs"),
    ] {
        assert!(!source.contains("NO listener"));
        assert!(source.contains("--approve-on other"));
        assert!(source.contains("--no-listener"));
    }
    let runbook = include_str!("../../../docs/operator-runbook.md");
    assert!(runbook.contains("Google-family and DigitalOcean"));
    assert!(runbook.contains("stop before the authorization URL"));
}
