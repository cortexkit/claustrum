//! Test-only helper process for the kill-9 mid-refresh conformance test.
//!
//! Only built under the `kill9-test-seam` feature (see Cargo.toml). The parent
//! integration test spawns this binary, waits for it to write a readiness marker
//! file (which means: the refresh intent is durably committed, the new tokens are
//! staged, and the engine is parked at the pre-commit seam), then sends a real
//! SIGKILL. Because the process is killed BEFORE the commit transaction runs, it
//! leaves exactly the interrupted-refresh state the parent then reconciles.
//!
//! Usage: `kill9_refresh_helper <db_path> <marker_path>`.
//! The process seeds a stale OAuth credential under `id = "anthropic"`, opens the
//! intent, stages refreshed tokens, writes the marker, and BLOCKS forever (the
//! parent kills it). It must never reach the commit.

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use cortexkit_store::{open_sqlite, Isolation, StorageBackend, StorageDescriptor};
use credentials_core::engine::RefreshEngine;
use credentials_core::key::{MasterKey, MASTER_KEY_LEN};
use credentials_core::oauth::OAuthCredential;
use credentials_core::record::VaultRecord;
use credentials_core::refresh_adapters::{
    HttpResponse, HttpTransport, RefreshAdapter, RefreshError, RefreshedTokens,
};
use credentials_core::store::EncryptedStore;

/// An adapter that always returns a fixed rotated token (no real network).
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
        Ok(RefreshedTokens {
            access_token: "STAGED-TOKEN-MUST-NEVER-BE-COMMITTED".into(),
            refresh_token: "STAGED-ROTATED-REFRESH".into(),
            expires_at_ms: Some(i64::MAX),
        })
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

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let mut args = std::env::args().skip(1);
    let db_path = args
        .next()
        .expect("usage: kill9_refresh_helper <db> <marker>");
    let marker_path = PathBuf::from(args.next().expect("missing marker path"));

    let descriptor = StorageDescriptor {
        module_id: "cortexkit-credentials".into(),
        storage_namespace: "vault".into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite { path: db_path },
    };
    let store = open_sqlite(&descriptor).expect("open store");
    EncryptedStore::migrate(&store).expect("migrate");
    let store = Arc::new(
        EncryptedStore::open(store, MasterKey::from_bytes([9u8; MASTER_KEY_LEN]))
            .expect("open vault"),
    );

    // Seed a stale (expired) OAuth credential so a get() triggers a refresh.
    let record = VaultRecord::new_oauth(
        "opencode",
        "anthropic",
        OAuthCredential {
            access_token: "old-access".into(),
            refresh_token: "old-refresh".into(),
            expires_at_ms: Some(0),
            token_url: "https://t.test/token".into(),
            client_id: Some("c".into()),
            scopes: vec![],
        },
        b"old-access".to_vec(),
    );
    store.create("anthropic", &record).expect("seed credential");

    let engine = RefreshEngine::new(store, vec![Arc::new(StubAdapter)], Arc::new(NoHttp));

    // Park at the pre-commit seam: the intent is committed + tokens staged, but the
    // commit transaction has not run. Write the readiness marker, then block
    // forever so the parent can SIGKILL us at exactly this point.
    let marker = marker_path.clone();
    engine.set_pre_commit_hook(Box::new(move || {
        std::fs::write(&marker, b"ready").expect("write readiness marker");
        // Block forever (uninterruptible by anything but a signal). The parent
        // sends SIGKILL once it sees the marker.
        loop {
            std::thread::sleep(std::time::Duration::from_secs(3600));
        }
    }));

    // This drives the refresh, which parks in the hook above and never returns.
    let _ = engine.get("anthropic", None, true).await;

    // Unreachable: the hook blocks forever and the parent SIGKILLs us first.
    eprintln!("kill9_refresh_helper: reached commit — THIS MUST NOT HAPPEN");
    std::process::exit(2);
}
