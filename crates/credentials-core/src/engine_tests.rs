//! Engine conformance tests: single-flight, refresh-on-read, the reconciliation
//! decision table, ADD-1 (admin clears intent), and the lease-handover convergence
//! property (a fenced commit leaves the same durable state as a kill-9, and
//! reconciliation resolves it to `needs_reauth` with the staged token never
//! visible). The REAL kill-9 SIGKILL harness lives in a separate, feature-gated
//! integration test; this file proves the logic deterministically in-process.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;

use crate::audit::{AuditCtx, AuditOp};
use crate::engine::{EngineError, ReauthReason, Reconciliation, RefreshEngine};
use crate::key::{MasterKey, MASTER_KEY_LEN};
use crate::oauth::OAuthCredential;
use crate::record::VaultRecord;
use crate::refresh_adapters::{
    HttpTransport, RefreshAdapter, RefreshError, RefreshedTokens, ValidityOutcome,
};
use crate::store::{AuthObservation, EncryptedStore, StoreOpError};
use cortexkit_store::{open_sqlite, Isolation, StorageBackend, StorageDescriptor};

/// A stub adapter that counts refresh calls and returns a fixed rotated token, with
/// a configurable non-mutating check outcome.
struct StubAdapter {
    name: String,
    calls: Arc<AtomicUsize>,
    check: Option<Result<ValidityOutcome, ()>>,
    fail: Option<&'static str>,
    access_token: &'static str,
    /// When set, every refresh waits here until the barrier's full party has
    /// arrived. Turns "did these overlap?" from a timing question into a
    /// structural one: if the engine serialises refreshes across credentials, the
    /// first arrival waits for a second that cannot start, and the test hangs
    /// rather than passing slowly.
    rendezvous: Option<Arc<tokio::sync::Barrier>>,
}

impl StubAdapter {
    fn new(name: &str) -> Self {
        StubAdapter {
            name: name.to_string(),
            calls: Arc::new(AtomicUsize::new(0)),
            check: None,
            fail: None,
            access_token: "refreshed-access",
            rendezvous: None,
        }
    }
}

#[async_trait]
impl RefreshAdapter for StubAdapter {
    fn name(&self) -> &str {
        &self.name
    }

    async fn refresh(
        &self,
        _cred: &OAuthCredential,
        _http: &dyn HttpTransport,
    ) -> Result<RefreshedTokens, RefreshError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        // A tiny await point so concurrent callers actually contend on the lock.
        tokio::task::yield_now().await;
        if let Some(barrier) = self.rendezvous.as_ref() {
            barrier.wait().await;
        }
        if let Some(reason) = self.fail {
            return match reason {
                "invalid_grant" => Err(RefreshError::InvalidGrant("dead".into())),
                _ => Err(RefreshError::Transport("boom".into())),
            };
        }
        Ok(RefreshedTokens {
            access_token: self.access_token.into(),
            refresh_token: "rotated-refresh".into(),
            expires_at_ms: Some(now_ms() + 3_600_000),
        })
    }

    async fn non_mutating_check(
        &self,
        _cred: &OAuthCredential,
        _http: &dyn HttpTransport,
    ) -> Option<Result<ValidityOutcome, RefreshError>> {
        self.check
            .map(|r| r.map_err(|_| RefreshError::Transport("probe failed".into())))
    }
}

/// A no-op transport (the stub adapter ignores it).
struct NoHttp;
#[async_trait]
impl HttpTransport for NoHttp {
    async fn post(
        &self,
        _url: &str,
        _headers: &[(&str, &str)],
        _content_type: &str,
        _body: Vec<u8>,
    ) -> Result<crate::refresh_adapters::HttpResponse, RefreshError> {
        Err(RefreshError::Transport("no http in this test".into()))
    }

    async fn get(
        &self,
        _url: &str,
        _headers: &[(&str, &str)],
    ) -> Result<crate::refresh_adapters::HttpResponse, RefreshError> {
        Err(RefreshError::Transport("no http in this test".into()))
    }
}

fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn tmp_descriptor() -> (std::path::PathBuf, StorageDescriptor) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let root = std::env::temp_dir().join(format!(
        "ck-cred-engine-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let db = root.join("store.db");
    let descriptor = StorageDescriptor {
        module_id: "cortexkit-credentials".into(),
        storage_namespace: "vault".into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: db.to_string_lossy().into_owned(),
        },
    };
    (root, descriptor)
}

fn open_store(descriptor: &StorageDescriptor, seed: u8) -> EncryptedStore {
    let store = open_sqlite(descriptor).expect("open");
    EncryptedStore::migrate(&store).expect("migrate");
    EncryptedStore::open(store, MasterKey::from_bytes([seed; MASTER_KEY_LEN])).expect("open vault")
}

fn stale_oauth_record() -> VaultRecord {
    VaultRecord::new_oauth(
        "opencode",
        "stub",
        OAuthCredential {
            access_token: "old-access".into(),
            refresh_token: "old-refresh".into(),
            // Already expired so a get() triggers a refresh.
            expires_at_ms: Some(0),
            token_url: "https://t.test/token".into(),
            client_id: Some("c".into()),
            scopes: vec![],
        },
        b"old-access".to_vec(),
    )
}

/// A refresh-only login artifact: an OAuth record imported with an EMPTY access
/// token and NO recorded expiry (the antigravity case — the account file stores only
/// the refresh token and lets the client mint the access token on first use).
fn refresh_only_oauth_record() -> VaultRecord {
    VaultRecord::new_oauth(
        "antigravity",
        "stub",
        OAuthCredential {
            access_token: String::new(),
            refresh_token: "live-refresh".into(),
            expires_at_ms: None,
            token_url: String::new(),
            client_id: None,
            scopes: vec![],
        },
        Vec::new(),
    )
}

fn engine(store: EncryptedStore, adapter: StubAdapter) -> (RefreshEngine, Arc<AtomicUsize>) {
    let calls = adapter.calls.clone();
    let eng = RefreshEngine::new(Arc::new(store), vec![Arc::new(adapter)], Arc::new(NoHttp));
    (eng, calls)
}

#[tokio::test]
async fn refresh_on_stale_commits_new_tokens_and_bumps_version() {
    let (root, d) = tmp_descriptor();
    let store = open_store(&d, 1);
    store.create("id", &stale_oauth_record()).unwrap();
    let (eng, calls) = engine(store, StubAdapter::new("stub"));

    let got = eng.get("id", None, false).await.expect("get");
    assert_eq!(got.payload, b"refreshed-access", "new access token served");
    assert_eq!(got.record_version, 2, "version bumped by refresh");
    assert_eq!(got.oauth.unwrap().refresh_token, "rotated-refresh");
    assert_eq!(calls.load(Ordering::SeqCst), 1, "exactly one upstream call");
    // The intent is cleared post-commit.
    assert!(eng.store().read_intent("id").unwrap().is_none());
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn empty_refresh_success_clears_intent_without_committing() {
    let (root, d) = tmp_descriptor();
    let store = open_store(&d, 41);
    store.create("id", &stale_oauth_record()).unwrap();
    let before = store.get("id").expect("record before refresh");
    let adapter = StubAdapter {
        access_token: "",
        ..StubAdapter::new("stub")
    };
    let (eng, calls) = engine(store, adapter);

    let error = eng
        .get("id", None, false)
        .await
        .expect_err("empty provider token must fail closed");
    assert!(matches!(
        error,
        EngineError::RefreshFailed(RefreshError::Decode(ref message))
            if message == "provider returned an empty access token"
    ));
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "provider path was exercised"
    );
    assert!(
        eng.store().read_intent("id").unwrap().is_none(),
        "txn1 must be cleared after the invalid provider success"
    );

    let after = eng.store().get("id").expect("record retained");
    assert_eq!(after.record_version, before.record_version);
    assert_eq!(after.payload, before.payload);
    assert_eq!(
        after.oauth.as_ref().map(|oauth| &oauth.refresh_token),
        before.oauth.as_ref().map(|oauth| &oauth.refresh_token)
    );
    assert!(
        eng.store()
            .read_audit(None)
            .expect("read audit")
            .iter()
            .all(|entry| entry.op != AuditOp::RefreshCommit.as_str()),
        "no refresh-commit audit may describe a rejected empty token"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn empty_access_token_refreshes_on_first_get_not_served_empty() {
    // A refresh-only record (empty access, no expiry) must REFRESH on the first
    // non-force get, not serve a zero-byte token. A zero-byte access token can never
    // be validly served.
    let (root, d) = tmp_descriptor();
    let store = open_store(&d, 9);
    store.create("id", &refresh_only_oauth_record()).unwrap();
    let (eng, calls) = engine(store, StubAdapter::new("stub"));

    // No force_refresh, and the min_ttl the consumer passes does not help (the record
    // has no expiry, so the ttl branch is never engaged).
    let got = eng.get("id", Some(600_000), false).await.expect("get");
    assert_eq!(
        got.payload, b"refreshed-access",
        "empty-access record refreshed on first get, not served empty"
    );
    assert!(!got.payload.is_empty(), "never serve a zero-byte token");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "exactly one upstream refresh"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn concurrent_gets_single_flight_one_upstream_call() {
    let (root, d) = tmp_descriptor();
    let store = open_store(&d, 2);
    store.create("id", &stale_oauth_record()).unwrap();
    let (eng, calls) = engine(store, StubAdapter::new("stub"));
    let eng = Arc::new(eng);

    // 8 concurrent gets all see the stale token; single-flight must collapse them
    // to exactly ONE upstream refresh.
    let mut handles = Vec::new();
    for _ in 0..8 {
        let e = eng.clone();
        handles.push(tokio::spawn(async move { e.get("id", None, false).await }));
    }
    for h in handles {
        let r = h.await.unwrap().expect("get ok");
        assert_eq!(r.payload, b"refreshed-access");
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "N concurrent gets => exactly ONE upstream refresh"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn refreshes_on_different_credentials_overlap_rather_than_serialising() {
    // The OTHER half of the manifest's ModuleManaged declaration.
    //
    // `concurrent_gets_single_flight_one_upstream_call` proves the module schedules
    // internally. It says nothing about whether unrelated credentials can proceed at
    // the same time -- a global lock would make this surface secretly Serial and that
    // test would still pass, because it only ever touches one credential.
    //
    // PROOF BY CONSTRUCTION RATHER THAN BY TIMING: the adapter blocks inside refresh
    // until a two-party barrier is satisfied. Overlapping refreshes both arrive and
    // release each other. A serialising engine holds the first one at the barrier
    // waiting for a second that cannot start until the first returns, and the test
    // hangs instead of passing slowly -- so it cannot be green for the wrong reason.
    let (root, d) = tmp_descriptor();
    let store = open_store(&d, 2);
    store.create("cred-a", &stale_oauth_record()).unwrap();
    store.create("cred-b", &stale_oauth_record()).unwrap();

    let mut adapter = StubAdapter::new("stub");
    adapter.rendezvous = Some(Arc::new(tokio::sync::Barrier::new(2)));
    let (eng, calls) = engine(store, adapter);
    let eng = Arc::new(eng);

    let a = {
        let e = eng.clone();
        tokio::spawn(async move { e.get("cred-a", None, false).await })
    };
    let b = {
        let e = eng.clone();
        tokio::spawn(async move { e.get("cred-b", None, false).await })
    };

    // The bound only has to exclude "hung": both refreshes are already in flight
    // before either can return, so a passing run completes immediately.
    let both = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        (a.await.unwrap(), b.await.unwrap())
    })
    .await
    .expect(
        "two refreshes on DIFFERENT credentials did not overlap: each blocked waiting \
         for the other, which is what a global lock looks like. The manifest declares \
         ModuleManaged, whose second half is that calls may proceed concurrently \
         across channels -- a surface that serialises unrelated credentials is Serial \
         and the manifest would be asserting something false.",
    );

    both.0.expect("cred-a get ok");
    both.1.expect("cred-b get ok");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "two distinct credentials must each refresh once -- single-flight is keyed \
         per credential, not global"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn a_refresh_commit_preserves_the_client_id_the_next_refresh_needs() {
    // client_id is an INPUT to the refresh exchange for anthropic, openai, xai and
    // github_app -- for github_app it is the App JWT's issuer, without which nothing
    // can be minted at all. commit_refresh rebuilds OAuthCredential field by field, so
    // dropping one line there loses it.
    //
    // THE FAILURE IS DELAYED, WHICH IS WHY THIS IS WORTH PINNING: the refresh that
    // drops client_id SUCCEEDS, because the adapter already read it from the old record.
    // Only the NEXT refresh fails, hours later, on a credential that worked once. A test
    // asserting one successful refresh cannot see it -- this asserts the committed
    // record still carries what a second exchange would need.
    let (root, d) = tmp_descriptor();
    let store = open_store(&d, 2);
    store.create("id", &stale_oauth_record()).unwrap();
    let (eng, _calls) = engine(store, StubAdapter::new("stub"));

    let served = eng.get("id", None, false).await.expect("get ok");
    assert_eq!(served.payload, b"refreshed-access");

    let after = eng.store().get("id").expect("record still readable");
    let oauth = after.oauth.as_ref().expect("still an oauth record");
    assert_eq!(
        oauth.client_id.as_deref(),
        Some("c"),
        "the committed record lost client_id, so the NEXT refresh has no issuer"
    );

    // The payload must also be filled from the new access token. Left empty, the read
    // surface quarantines the record as corrupt on the very next get -- which does not
    // merely fail, it POISONS a healthy credential.
    assert!(
        !after.payload.is_empty(),
        "a committed refresh left an empty payload, which the read surface quarantines"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// A reported but locally unexpired token must reach the real refresh failure path.
///
/// This begins with `stale_pending`, not expiry, so an implementation that ignores the
/// report marker serves the old token and never reaches the InvalidGrant transition.
#[tokio::test]
async fn report_stale_then_invalid_grant_latches_needs_reauth() {
    let (root, d) = tmp_descriptor();
    let store = open_store(&d, 83);
    let mut record = stale_oauth_record();
    record.oauth.as_mut().expect("oauth").expires_at_ms = Some(now_ms() + 3_600_000);
    store.create("id", &record).expect("create");
    store
        .mark_stale_if_version_reported(
            "id",
            1,
            AuditCtx::vault(AuditOp::ReportAuthFailure),
            AuthObservation {
                kind: "consumer_report_stale",
                provider_status: Some(401),
                detail: None,
            },
        )
        .expect("report marks the current token stale");
    let mut adapter = StubAdapter::new("stub");
    adapter.fail = Some("invalid_grant");
    let (eng, calls) = engine(store, adapter);

    let err = eng.get("id", None, false).await.expect_err("must fail");
    assert!(matches!(
        err,
        EngineError::RefreshFailed(RefreshError::InvalidGrant(_))
    ));
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the stale marker must force one refresh"
    );
    match eng.store().get("id") {
        Err(StoreOpError::NeedsReauth) => {}
        other => panic!("invalid_grant after a stale report must latch NeedsReauth, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(&root);
}

/// A successful forced refresh consumes the marker, otherwise every later get would
/// exchange an already-fresh token again.
#[tokio::test]
async fn stale_pending_clears_in_the_refresh_commit() {
    let (root, d) = tmp_descriptor();
    let store = open_store(&d, 84);
    let mut record = stale_oauth_record();
    record.oauth.as_mut().expect("oauth").expires_at_ms = Some(now_ms() + 3_600_000);
    store.create("id", &record).expect("create");
    store
        .mark_stale_if_version_reported(
            "id",
            1,
            AuditCtx::vault(AuditOp::ReportAuthFailure),
            AuthObservation {
                kind: "consumer_report_stale",
                provider_status: Some(401),
                detail: None,
            },
        )
        .expect("report marks the current token stale");
    let (eng, calls) = engine(store, StubAdapter::new("stub"));

    let refreshed = eng.get("id", None, false).await.expect("refresh succeeds");
    assert_eq!(refreshed.record_version, 2);
    assert!(!eng.store().meta("id").expect("meta").stale_pending);
    let served_again = eng.get("id", None, false).await.expect("fresh get");
    assert_eq!(served_again.record_version, 2);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the cleared marker must not re-refresh"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn invalid_grant_marks_needs_reauth() {
    let (root, d) = tmp_descriptor();
    let store = open_store(&d, 3);
    store.create("id", &stale_oauth_record()).unwrap();
    let mut adapter = StubAdapter::new("stub");
    adapter.fail = Some("invalid_grant");
    let (eng, _calls) = engine(store, adapter);

    let err = eng.get("id", None, false).await.expect_err("must fail");
    assert!(matches!(err, crate::engine::EngineError::RefreshFailed(_)));
    // The credential is now needs_reauth and the intent cleared.
    match eng.store().get("id") {
        Err(StoreOpError::NeedsReauth) => {}
        other => panic!("expected NeedsReauth, got {other:?}"),
    }
    assert!(eng.store().read_intent("id").unwrap().is_none());
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn reactivating_a_genuinely_dead_credential_returns_it_to_needs_reauth() {
    // THE SAFETY ARGUMENT FOR EXPOSING `reactivate` AT ALL, and until now it was prose.
    //
    // The verb lets an operator contradict a needs_reauth verdict without touching the
    // material, which is only defensible because a WRONG assertion is cheap: the vault
    // re-verifies on next use, so a credential that really is dead comes straight back
    // to needs_reauth and costs one failed request rather than serving a bad token.
    //
    // Nothing tested that. The store-level test covers the transition and the corrupt
    // refusal; the self-correction spans store AND engine, so it lives here. Without it,
    // an engine change that stopped marking on InvalidGrant would leave `reactivate` as
    // a way to keep a dead credential permanently "active" -- exactly the failure the
    // doc comment promises cannot happen.
    let (root, d) = tmp_descriptor();
    let store = open_store(&d, 9);
    store.create("id", &stale_oauth_record()).unwrap();
    let mut adapter = StubAdapter::new("stub");
    adapter.fail = Some("invalid_grant");
    let (eng, _calls) = engine(store, adapter);

    // First death: the provider says the grant is gone.
    let _ = eng.get("id", None, false).await.expect_err("must fail");
    match eng.store().get("id") {
        Err(StoreOpError::NeedsReauth) => {}
        other => panic!("expected NeedsReauth after invalid_grant, got {other:?}"),
    }

    // An operator asserts it was marked in error. The vault takes the assertion.
    let changed = eng
        .store()
        .reactivate_audited("id", AuditCtx::admin(AuditOp::Reactivate))
        .expect("reactivate");
    assert!(
        changed,
        "the reactivate must land, or the rest proves nothing"
    );

    // AND THE ASSERTION IS RE-TESTED AGAINST THE PROVIDER, not trusted. This is the
    // arm that makes a wrong assertion cheap instead of permanent.
    let err = eng
        .get("id", None, false)
        .await
        .expect_err("a dead credential must fail again");
    assert!(matches!(err, crate::engine::EngineError::RefreshFailed(_)));
    match eng.store().get("id") {
        Err(StoreOpError::NeedsReauth) => {}
        other => panic!(
            "a reactivated-but-dead credential must return to NeedsReauth on next use; \
             got {other:?} -- reactivate would otherwise pin a dead credential active"
        ),
    }
    assert!(eng.store().read_intent("id").unwrap().is_none());
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn reconcile_dangling_intent_no_check_is_needs_reauth() {
    // The kill-9 LOGIC equivalent: an intent that survived (txn1 committed, txn2
    // never ran). With no non-mutating check, reconciliation resolves needs_reauth
    // and the old token is never served.
    let (root, d) = tmp_descriptor();
    let store = open_store(&d, 4);
    let rec = stale_oauth_record();
    store.create("id", &rec).unwrap();
    // Open an intent and DON'T commit (simulates crash before txn2).
    let old_hash = crate::store::refresh_token_hash(&rec.oauth.unwrap().refresh_token);
    store.open_intent("id", 1, &old_hash).unwrap();
    let (eng, _calls) = engine(store, StubAdapter::new("stub"));

    let outcomes = eng.reconcile().await.expect("reconcile");
    assert_eq!(outcomes.len(), 1);
    assert!(matches!(
        &outcomes[0],
        Reconciliation::NeedsReauth {
            reason: ReauthReason::NoValidityCheck,
            ..
        }
    ));
    match eng.store().get("id") {
        Err(StoreOpError::NeedsReauth) => {}
        other => panic!("expected NeedsReauth after reconcile, got {other:?}"),
    }
    assert!(
        eng.store().read_intent("id").unwrap().is_none(),
        "intent cleared"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn reconcile_with_valid_check_clears_intent_and_keeps_active() {
    let (root, d) = tmp_descriptor();
    let store = open_store(&d, 5);
    let rec = stale_oauth_record();
    store.create("id", &rec).unwrap();
    let old_hash = crate::store::refresh_token_hash(&rec.oauth.unwrap().refresh_token);
    store.open_intent("id", 1, &old_hash).unwrap();
    let mut adapter = StubAdapter::new("stub");
    adapter.check = Some(Ok(ValidityOutcome::Valid));
    let (eng, _calls) = engine(store, adapter);

    let outcomes = eng.reconcile().await.expect("reconcile");
    assert!(matches!(&outcomes[0], Reconciliation::ClearedValid { .. }));
    // Record stays active (servable) since validity was proven; intent cleared.
    // (Token is expired so a get would refresh, but the STATE is active, not
    // needs_reauth — assert via meta.)
    assert_eq!(
        eng.store().meta("id").unwrap().state,
        crate::store::RecordState::Active
    );
    assert!(eng.store().read_intent("id").unwrap().is_none());
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn reconcile_hash_mismatch_is_needs_reauth() {
    // A stored refresh token whose hash != the intent's old_refresh_hash means a
    // write landed without clearing the intent: fail closed.
    let (root, d) = tmp_descriptor();
    let store = open_store(&d, 6);
    store.create("id", &stale_oauth_record()).unwrap();
    store
        .open_intent("id", 1, "a-hash-that-does-not-match")
        .unwrap();
    let (eng, _calls) = engine(store, StubAdapter::new("stub"));

    let outcomes = eng.reconcile().await.expect("reconcile");
    assert!(matches!(
        &outcomes[0],
        Reconciliation::NeedsReauth {
            reason: ReauthReason::HashMismatch,
            ..
        }
    ));
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn admin_overwrite_clears_dangling_intent() {
    // ADD-1: a re-login (admin overwrite with fresh tokens) must clear the dangling
    // intent, so a later reconcile does NOT undo it.
    let (root, d) = tmp_descriptor();
    let store = open_store(&d, 7);
    let rec = stale_oauth_record();
    store.create("id", &rec).unwrap();
    let old_hash = crate::store::refresh_token_hash(&rec.oauth.as_ref().unwrap().refresh_token);
    store.open_intent("id", 1, &old_hash).unwrap();
    // Admin overwrite with fresh tokens (CAS on current payload).
    let cur = store.get("id").unwrap();
    let expect = crate::store::payload_hash(&cur.payload);
    let mut fresh = stale_oauth_record();
    fresh.oauth.as_mut().unwrap().refresh_token = "freshly-relogged-in".into();
    fresh.payload = b"fresh-access".to_vec();
    store.overwrite_cas("id", &fresh, &expect).unwrap();
    // The intent must be gone.
    assert!(
        store.read_intent("id").unwrap().is_none(),
        "admin write cleared intent"
    );

    let (eng, _calls) = engine(store, StubAdapter::new("stub"));
    let outcomes = eng.reconcile().await.expect("reconcile");
    assert!(
        outcomes.is_empty(),
        "no dangling intent to reconcile after re-login"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn lease_handover_fences_commit_and_converges_to_needs_reauth() {
    // The convergence property, in-process: a refresh whose commit is fenced by a
    // newer lease holder leaves EXACTLY the same durable state as a kill-9 before
    // txn2 — a dangling intent + the OLD tokens — and reconciliation resolves it to
    // needs_reauth with the staged (refreshed) token NEVER visible.
    let (root, d) = tmp_descriptor();
    let store = open_store(&d, 8); // store holds epoch 1
    let rec = stale_oauth_record();
    store.create("id", &rec).unwrap();
    let old_hash = crate::store::refresh_token_hash(&rec.oauth.as_ref().unwrap().refresh_token);

    // Simulate a newer writer having claimed the database at a higher epoch: bump
    // the persisted fence epoch ABOVE this store's epoch. The next fenced write
    // (the refresh commit, txn2) will be rejected with Fenced — exactly the
    // lease-handover race, set up through the public connection.
    // Open the real intent (txn1) at epoch 1, BEFORE simulating the handover.
    store.open_intent("id", 1, &old_hash).expect("txn1 intent");

    // Simulate a newer writer having claimed the database at a higher epoch: bump
    // the persisted fence epoch ABOVE this store's epoch. The next fenced write
    // (the refresh commit, txn2) will be rejected with Fenced — exactly the
    // lease-handover race.
    store
        .with_raw_conn(|c| c.execute("UPDATE cortexkit_fence SET epoch = 999 WHERE id = 0", []))
        .expect("bump fence epoch above the holder");

    // Now attempt the refresh commit (txn2): it must be Fenced, NOT applied.
    let mut refreshed = stale_oauth_record();
    refreshed.oauth.as_mut().unwrap().access_token = "STAGED-must-never-be-served".into();
    refreshed.payload = b"STAGED-must-never-be-served".to_vec();
    match store.commit_refresh("id", 1, &refreshed) {
        Err(StoreOpError::Fenced {
            holder_epoch,
            db_epoch,
        }) => {
            assert_eq!(holder_epoch, 1);
            assert_eq!(db_epoch, 999);
        }
        other => panic!("expected Fenced commit, got {other:?}"),
    }

    // Durable state now == kill-9-before-txn2: dangling intent + old tokens at V=1.
    assert!(
        store.read_intent("id").unwrap().is_some(),
        "intent still dangling"
    );
    let still = store.get("id").unwrap();
    assert_eq!(still.record_version, 1, "old version retained");
    assert_eq!(still.payload, b"old-access", "staged token NOT visible");

    // Reconciliation resolves it identically to the crash case: needs_reauth, staged
    // token provably never served. (Reconcile writes go through the fence too, but
    // the resolution path uses invalidate which is fenced at epoch 999 here; model
    // the NEW owner by re-opening at the real next epoch.)
    drop(store);
    // Reset the fence to a sane value the reopened store's epoch will exceed: the
    // real lease bump gives epoch 2, but we left 999. Reopen and reconcile under a
    // store whose epoch we make current by clearing the synthetic fence.
    let reopened = open_sqlite(&d).expect("reopen");
    reopened
        .with_conn(|c| c.execute("UPDATE cortexkit_fence SET epoch = 0 WHERE id = 0", []))
        .expect("reset synthetic fence to let the new owner write");
    let new_store =
        EncryptedStore::open(reopened, MasterKey::from_bytes([8u8; MASTER_KEY_LEN])).expect("open");
    let (eng, _calls) = engine(new_store, StubAdapter::new("stub"));
    let outcomes = eng.reconcile().await.expect("reconcile");
    assert!(matches!(
        &outcomes[0],
        Reconciliation::NeedsReauth {
            reason: ReauthReason::NoValidityCheck,
            ..
        }
    ));
    match eng.store().get("id") {
        Err(StoreOpError::NeedsReauth) => {}
        other => panic!("expected NeedsReauth, got {other:?}"),
    }
    // The staged token was never, at any point, visible.
    let _ = std::fs::remove_dir_all(&root);
}
