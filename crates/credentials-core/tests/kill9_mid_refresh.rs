//! The kill-9 mid-refresh conformance test (a §13 ship-gate requirement).
//!
//! Spawns the `kill9_refresh_helper` process, waits until it has durably committed
//! a refresh intent and staged new tokens (parked at the engine's pre-commit seam),
//! sends a REAL SIGKILL, confirms it died by signal before committing, then opens
//! the same database and runs reconciliation. The interrupted refresh must resolve
//! to `needs_reauth`, and the staged token must NEVER be visible — proving a crash
//! between the provider response and the commit cannot brick a credential or serve
//! a token of unknown validity.
//!
//! Only built under the `kill9-test-seam` feature (the helper binary and the
//! engine's pre-commit seam both require it). Unix-only: it relies on SIGKILL and
//! on the OS advisory lease lock being released by the kernel on process death (so
//! the parent can re-open the database the killed child held).

#![cfg(all(unix, feature = "kill9-test-seam"))]

use std::os::unix::process::ExitStatusExt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use cortexkit_store::{open_sqlite, Isolation, StorageBackend, StorageDescriptor};
use credentials_core::engine::{ReauthReason, Reconciliation, RefreshEngine};
use credentials_core::key::{MasterKey, MASTER_KEY_LEN};
use credentials_core::oauth::OAuthCredential;
use credentials_core::refresh_adapters::{
    HttpResponse, HttpTransport, RefreshAdapter, RefreshError, RefreshedTokens,
};
use credentials_core::store::{EncryptedStore, StoreOpError};

struct StubAdapter;
#[async_trait]
impl RefreshAdapter for StubAdapter {
    fn name(&self) -> &str {
        "anthropic"
    }
    async fn refresh(
        &self,
        _cred: &OAuthCredential,
        _http: &dyn HttpTransport,
    ) -> Result<RefreshedTokens, RefreshError> {
        // Reconciliation never calls refresh(); present only to satisfy the registry.
        Err(RefreshError::Transport("recovery never refreshes".into()))
    }
}

struct NoHttp;
#[async_trait]
impl HttpTransport for NoHttp {
    async fn post(
        &self,
        _url: &str,
        _headers: &[(&str, &str)],
        _content_type: &str,
        _body: Vec<u8>,
    ) -> Result<HttpResponse, RefreshError> {
        Err(RefreshError::Transport("unused".into()))
    }
}

#[tokio::test]
async fn kill9_between_response_and_commit_resolves_to_needs_reauth() {
    let root = std::env::temp_dir().join(format!("ck-cred-kill9-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let db_path = root.join("store.db");
    let marker_path = root.join("ready.marker");

    // Spawn the helper: it seeds a stale credential, opens the intent, stages
    // refreshed tokens, writes the marker, and parks at the pre-commit seam.
    let helper = env!("CARGO_BIN_EXE_kill9_refresh_helper");
    let mut child = std::process::Command::new(helper)
        .arg(db_path.to_string_lossy().to_string())
        .arg(marker_path.to_string_lossy().to_string())
        .spawn()
        .expect("spawn kill9 helper");

    // Wait for the readiness marker (intent committed + tokens staged, parked).
    let deadline = Instant::now() + Duration::from_secs(30);
    while !marker_path.exists() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("helper never reached the pre-commit seam within 30s");
        }
        // Detect an early helper exit (it must NOT exit on its own).
        if let Ok(Some(status)) = child.try_wait() {
            panic!("helper exited early with {status:?} before parking");
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    // SIGKILL the parked child (std Child::kill is SIGKILL on Unix): uncatchable, no
    // destructors, no flush — a true "kill -9" between response and commit.
    child.kill().expect("SIGKILL helper");
    let status = child.wait().expect("reap helper");
    assert_eq!(
        status.signal(),
        Some(9),
        "helper must have died by SIGKILL (no graceful exit/commit), got {status:?}"
    );
    assert!(status.code().is_none(), "killed by signal => no exit code");

    // The kernel released the helper's lease lock on death, so we can now open the
    // same database as the "new owner" and reconcile the dangling intent.
    let descriptor = StorageDescriptor {
        module_id: "cortexkit-credentials".into(),
        storage_namespace: "vault".into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: db_path.to_string_lossy().into_owned(),
        },
    };
    let store = open_sqlite(&descriptor).expect("reopen after kill");
    EncryptedStore::migrate(&store).expect("migrate");
    let store = Arc::new(
        EncryptedStore::open(store, MasterKey::from_bytes([9u8; MASTER_KEY_LEN]))
            .expect("open vault"),
    );

    // Before reconciliation: the intent is dangling and the OLD token is still
    // stored (the staged token never reached disk).
    assert!(
        store.read_intent("anthropic").unwrap().is_some(),
        "the interrupted refresh left a dangling intent"
    );
    let before = store.get("anthropic").expect("old record present");
    assert_eq!(
        before.payload, b"old-access",
        "staged token never committed"
    );

    let engine = RefreshEngine::new(store, vec![Arc::new(StubAdapter)], Arc::new(NoHttp));
    let outcomes = engine.reconcile().await.expect("reconcile");

    // The interrupted refresh resolves to needs_reauth (no non-mutating check for
    // anthropic), never a silent dead token, never a re-exec of the rotation.
    assert_eq!(outcomes.len(), 1, "exactly one dangling intent");
    assert!(
        matches!(
            &outcomes[0],
            Reconciliation::NeedsReauth {
                reason: ReauthReason::NoValidityCheck,
                ..
            }
        ),
        "interrupted refresh => needs_reauth, got {:?}",
        outcomes[0]
    );
    match engine.store().get("anthropic") {
        Err(StoreOpError::NeedsReauth) => {}
        other => panic!("expected NeedsReauth after reconcile, got {other:?}"),
    }
    assert!(
        engine.store().read_intent("anthropic").unwrap().is_none(),
        "intent cleared by reconciliation"
    );

    let _ = std::fs::remove_dir_all(&root);
}
