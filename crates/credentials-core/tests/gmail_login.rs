use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use cortexkit_store::{open_sqlite, Isolation, StorageBackend, StorageDescriptor};
use credentials_core::{
    catalog::{category_defaults, serves_for},
    engine::RefreshEngine,
    google_login::{
        gmail_login_record, GoogleLoginProvider, AUTHORIZE_EXTRA_PARAMS, AUTHORIZE_URL,
        GMAIL_REDIRECT_URI, GMAIL_SCOPES, TOKEN_URL,
    },
    key::MasterKey,
    oauth_login::{
        build_authorize_url_google, exchange_authorization_code_google, Callback, LoginTokens,
    },
    refresh_adapters::{google::GoogleAdapter, HttpResponse, HttpTransport, RefreshError},
    store::EncryptedStore,
    test_support::TestTempDir,
};

fn tokens() -> LoginTokens {
    LoginTokens {
        access_token: "test-access".into(),
        refresh_token: "test-refresh".into(),
        expires_at_ms: Some(0),
        id_token: None,
        account: None,
        organization: None,
    }
}

fn record(email: Option<String>) -> Result<credentials_core::record::VaultRecord, &'static str> {
    gmail_login_record(
        tokens(),
        "test-client-id".into(),
        "test-client-secret".to_string().into(),
        email,
    )
}

fn store(label: &str) -> (TestTempDir, Arc<EncryptedStore>) {
    let dir = TestTempDir::new(format!("gmail-{label}-{}", std::process::id()));
    let raw = open_sqlite(&StorageDescriptor {
        module_id: "gmail-tests".into(),
        storage_namespace: "vault".into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: dir.join("store.db").to_string_lossy().into_owned(),
        },
    })
    .unwrap();
    EncryptedStore::migrate(&raw).unwrap();
    (
        dir,
        Arc::new(EncryptedStore::open(raw, MasterKey::from_bytes([23; 32])).unwrap()),
    )
}

#[test]
fn gmail_categories_are_isolated_from_model_search_and_browser_grants() {
    for id in ["oauth:gmail", "oauth:gmail:work"] {
        let categories = category_defaults(id);
        for forbidden in ["llm-provider", "web-search", "browser-session"] {
            assert!(
                !categories.iter().any(|c| c == forbidden),
                "{id} must not get {forbidden}: {categories:?}"
            );
        }
        assert_eq!(categories, ["gmail-native"]);
        assert!(serves_for(id).is_empty());
    }
}

#[test]
fn gmail_authorize_url_has_exact_scopes_client_redirect_and_consent() {
    let wire = GoogleLoginProvider::parse("gmail").unwrap();
    let raw = build_authorize_url_google(
        AUTHORIZE_URL,
        "test-client-id",
        wire.redirect_uri(),
        wire.scopes(),
        "test-state",
        AUTHORIZE_EXTRA_PARAMS,
    )
    .unwrap();
    assert_eq!(raw, "https://accounts.google.com/o/oauth2/v2/auth?access_type=offline&prompt=consent&client_id=test-client-id&response_type=code&redirect_uri=http%3A%2F%2F127.0.0.1%3A8086%2Foauth2callback&scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fgmail.send+openid+email&state=test-state");
    assert_eq!(wire.default_id(), "oauth:gmail");
}

#[test]
fn gmail_missing_email_stores_nothing() {
    let (_dir, store) = store("missing-email");
    for email in [None, Some(String::new()), Some(" ".into())] {
        // This is the same fallible record builder called BEFORE the CLI's commit.
        let result = record(email).map(|record| {
            store.create("oauth:gmail", &record).unwrap();
        });
        assert_eq!(
            result.unwrap_err(),
            "Gmail userinfo omitted email; refusing to store a credential without account identity"
        );
        assert!(store.get("oauth:gmail").is_err());
    }
}

#[test]
fn gmail_record_requires_refresh_and_persists_identity_and_sealed_client() {
    let mut empty = tokens();
    empty.refresh_token.clear();
    assert_eq!(
        gmail_login_record(
            empty,
            "test-client-id".into(),
            "test-client-secret".to_string().into(),
            Some("operator@example.test".into())
        )
        .unwrap_err(),
        "Gmail token response omitted refresh_token; login again with consent"
    );
    let record = record(Some("operator@example.test".into())).unwrap();
    assert_eq!(
        record.identity.account_id.as_deref(),
        Some("operator@example.test")
    );
    assert_eq!(record.identity.email, record.identity.account_id);
    assert_eq!(record.payload.expose(), b"test-access");
    assert_eq!(record.refresh_adapter.as_deref(), Some("gmail"));
    let oauth = record.oauth.unwrap();
    assert_eq!(oauth.client_id.as_deref(), Some("test-client-id"));
    assert_eq!(oauth.client_secret.unwrap().expose(), "test-client-secret");
    assert_eq!(oauth.scopes, GMAIL_SCOPES);
}

struct Transport {
    bodies: Mutex<Vec<Vec<u8>>>,
    response: &'static [u8],
    status: u16,
}
impl Transport {
    fn success() -> Self {
        Self {
            bodies: Mutex::new(Vec::new()),
            response: br#"{"access_token":"test-refreshed-access","expires_in":0}"#,
            status: 200,
        }
    }
}
#[async_trait]
impl HttpTransport for Transport {
    async fn post(
        &self,
        url: &str,
        _headers: &[(&str, &str)],
        content_type: &str,
        body: Vec<u8>,
    ) -> Result<HttpResponse, RefreshError> {
        assert_eq!(url, "https://oauth2.googleapis.com/token");
        assert_eq!(content_type, "application/x-www-form-urlencoded");
        self.bodies.lock().unwrap().push(body);
        Ok(HttpResponse {
            status: self.status,
            body: self.response.to_vec(),
        })
    }
}

#[tokio::test]
async fn gmail_exchange_without_refresh_token_is_refused() {
    let http = Transport {
        response: br#"{"access_token":"test-access","expires_in":3600}"#,
        ..Transport::success()
    };
    let callback = Callback {
        code: "test-code".into(),
        state: "test-state".into(),
    };
    let error = exchange_authorization_code_google(
        &http,
        TOKEN_URL,
        "test-client-id",
        "test-client-secret",
        GMAIL_REDIRECT_URI,
        &callback,
        "test-state",
        0,
    )
    .await
    .unwrap_err();
    assert!(
        error.to_string().contains("missing field `refresh_token`"),
        "{error}"
    );
    assert_eq!(http.bodies.lock().unwrap()[0], b"client_id=test-client-id&client_secret=test-client-secret&code=test-code&grant_type=authorization_code&redirect_uri=http%3A%2F%2F127.0.0.1%3A8086%2Foauth2callback");
}

#[tokio::test]
async fn gmail_engine_two_refreshes_preserve_record_client_secret() {
    let (_dir, store) = store("two-refreshes");
    store
        .create(
            "oauth:gmail",
            &record(Some("operator@example.test".into())).unwrap(),
        )
        .unwrap();
    let http = Arc::new(Transport::success());
    let engine = RefreshEngine::new(
        store.clone(),
        vec![Arc::new(GoogleAdapter::gmail())],
        http.clone(),
    );
    for version in [2, 3] {
        let updated = engine.get("oauth:gmail", None, false).await.unwrap();
        assert_eq!(updated.record_version, version);
        assert_eq!(updated.payload.expose(), b"test-refreshed-access");
    }
    let bodies = http.bodies.lock().unwrap();
    assert_eq!(bodies.len(), 2);
    for body in bodies.iter() {
        assert_eq!(body, b"client_id=test-client-id&client_secret=test-client-secret&refresh_token=test-refresh&grant_type=refresh_token");
    }
    let persisted = store.get("oauth:gmail").unwrap();
    assert_eq!(
        persisted.oauth.unwrap().client_secret.unwrap().expose(),
        "test-client-secret"
    );
}
