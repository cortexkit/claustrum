use super::*;
use cortexkit_store::{open_sqlite, Isolation, StorageBackend, StorageDescriptor};
use credentials_core::federation::MemberGrantSource;
use credentials_core::key::MasterKey;
use credentials_core::oauth::OAuthCredential;
use credentials_core::refresh_adapters::{HttpResponse, HttpTransport};
use credentials_core::store::SetCategoryMode;
use credentials_core::test_support::TestTempDir;

const MEMBER: &str = "fed-computer:aa11bb22cc33dd44ee55ff6600112233";
const OTHER: &str = "fed-computer:00000000000000000000000000000001";
const PAIRING: &str = "current-pair";

struct NoHttp;

#[async_trait::async_trait]
impl HttpTransport for NoHttp {
    async fn post(
        &self,
        _: &str,
        _: &[(&str, &str)],
        _: &str,
        _: Vec<u8>,
    ) -> Result<HttpResponse, RefreshError> {
        panic!("an inventory projection must not contact a provider")
    }
}

fn rig() -> (TestTempDir, HomeVault, rusqlite::Connection) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let root = TestTempDir::new(format!(
        "home-watch-projection-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let path = root.join("store.db");
    let descriptor = StorageDescriptor {
        module_id: "claustrum".into(),
        storage_namespace: "vault".into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: path.to_string_lossy().into_owned(),
        },
    };
    let sqlite = open_sqlite(&descriptor).unwrap();
    EncryptedStore::migrate(&sqlite).unwrap();
    let store = EncryptedStore::open(sqlite, MasterKey::from_bytes([196; 32])).unwrap();
    let engine = RefreshEngine::new(Arc::new(store), vec![], Arc::new(NoHttp));
    let conn = rusqlite::Connection::open(path).unwrap();
    (root, HomeVault::new(Arc::new(engine)), conn)
}

fn login() -> VaultRecord {
    let mut record = VaultRecord::new_oauth(
        "test",
        "anthropic",
        OAuthCredential {
            access_token: "watch-private-access".to_string().into(),
            refresh_token: "watch-private-refresh".to_string().into(),
            expires_at_ms: Some(0),
            token_url: String::new(),
            client_id: None,
            client_secret: None,
            scopes: vec![],
        },
        b"watch-private-payload".to_vec(),
    )
    .with_identity(RecordIdentity {
        account_id: Some("account".into()),
        email: None,
        org_name: Some("workspace".into()),
    });
    record.detected_plan = Some(DetectedPlan {
        tier: Some("pro".into()),
        raw: Some("provider-pro".into()),
        observed_at_ms: 42,
    });
    record
}

fn category(store: &EncryptedStore, id: &str, name: &str) {
    store
        .set_categories_audited(
            id,
            SetCategoryMode::Set,
            &[name.into()],
            AuditCtx::admin(AuditOp::SetCategory),
        )
        .unwrap();
}

fn grant(store: &EncryptedStore, member: &str, pairing: &str, selector: MemberGrantSelector) {
    store
        .create_member_grant_audited(member, MemberGrantOperation::RemoteRead, &selector, pairing)
        .unwrap();
}

fn data_version(conn: &rusqlite::Connection) -> i64 {
    conn.query_row("PRAGMA data_version", [], |row| row.get(0))
        .unwrap()
}

#[test]
fn projection_lists_granted_needs_reauth_and_active_logins_without_writes() {
    let (_root, home, conn) = rig();
    let store = home.engine.store();
    let record = login();
    for id in [
        "oauth:z-active",
        "oauth:a-needs",
        "oauth:retired",
        "oauth:ungranted",
        "oauth:stale",
        "oauth:other",
        VAULT_TRANSFER_ID,
    ] {
        store.create(id, &record).unwrap();
    }
    store
        .overwrite_unconditional_audited("oauth:z-active", &record, AuditCtx::admin(AuditOp::Put))
        .unwrap();
    // Seed OAuth material under the reserved id to exercise the id fence separately
    // from the refreshability check that would already exclude a normal KEM key.
    for id in [
        "oauth:z-active",
        "oauth:a-needs",
        "oauth:retired",
        VAULT_TRANSFER_ID,
    ] {
        category(store, id, "llm-provider");
    }
    store.invalidate("oauth:a-needs").unwrap();
    store
        .retire_and_revoke_all_audited("oauth:retired", AuditCtx::admin(AuditOp::Invalidate))
        .unwrap();
    store
        .create(
            "apikey:static",
            &VaultRecord::new_static(
                CredentialKind::ApiKey,
                "test",
                b"watch-private-static".to_vec(),
                None,
            ),
        )
        .unwrap();
    grant(
        store,
        MEMBER,
        PAIRING,
        MemberGrantSelector::Category("llm-provider".into()),
    );
    grant(
        store,
        MEMBER,
        PAIRING,
        MemberGrantSelector::Exact("apikey:static".into()),
    );
    grant(
        store,
        MEMBER,
        "old-pair",
        MemberGrantSelector::Exact("oauth:stale".into()),
    );
    grant(
        store,
        OTHER,
        PAIRING,
        MemberGrantSelector::Exact("oauth:other".into()),
    );
    let mut no_oauth = record.clone();
    no_oauth.oauth = None;
    store.create("oauth:no-material", &no_oauth).unwrap();
    grant(
        store,
        MEMBER,
        PAIRING,
        MemberGrantSelector::Exact("oauth:no-material".into()),
    );
    let mut no_adapter = record.clone();
    no_adapter.refresh_adapter = None;
    store.create("oauth:no-adapter", &no_adapter).unwrap();
    grant(
        store,
        MEMBER,
        PAIRING,
        MemberGrantSelector::Exact("oauth:no-adapter".into()),
    );
    store.create("oauth:exact", &record).unwrap();
    category(store, "oauth:exact", "exact-only");
    grant(
        store,
        MEMBER,
        PAIRING,
        MemberGrantSelector::Exact("oauth:exact".into()),
    );

    let version = data_version(&conn);
    let audit = store.audit_tip().unwrap();
    let events = store.recent_auth_events(100).unwrap().len();
    let writes = store.subscribe_writes();
    let rows = home.remote_watch_projection(MEMBER, PAIRING).unwrap();
    assert_eq!(
        rows.iter()
            .map(|row| row.credential_id.as_str())
            .collect::<Vec<_>>(),
        ["oauth:a-needs", "oauth:exact", "oauth:z-active"]
    );
    assert_eq!(rows[0].state, RemoteHomeState::NeedsReauth);
    assert_eq!(rows[1].state, RemoteHomeState::Active);
    assert_eq!(rows[2].state, RemoteHomeState::Active);
    assert_eq!(rows[2].home_version, 2);
    for row in &rows {
        assert_eq!(
            row.home_version,
            store.meta(&row.credential_id).unwrap().record_version
        );
        assert_eq!(row.identity, record.identity);
        assert_eq!(row.detected_plan, record.detected_plan);
        assert_eq!(row.refresh_adapter.as_deref(), Some("anthropic"));
    }
    assert_eq!(rows[0].categories, ["llm-provider"]);
    assert_eq!(rows[1].categories, ["exact-only"]);
    assert_eq!(home.remote_watch_projection(MEMBER, PAIRING).unwrap(), rows);
    assert_eq!(data_version(&conn), version);
    assert_eq!(store.audit_tip().unwrap(), audit);
    assert_eq!(store.recent_auth_events(100).unwrap().len(), events);
    assert!(!writes.has_changed().unwrap());

    let incarnation = home
        .require_grant(MEMBER, PAIRING, "oauth:a-needs")
        .unwrap();
    let refusal = home
        .require_eligible(MEMBER, "oauth:a-needs", &incarnation)
        .unwrap_err();
    assert_eq!(
        refusal.body(),
        json!({"code":"needs_reauth", "class":"auth_required"})
    );
}

#[test]
fn projection_without_a_remote_read_grant_is_empty_and_quiet() {
    let (_root, home, conn) = rig();
    let store = home.engine.store();
    store.create("oauth:login", &login()).unwrap();
    category(store, "oauth:login", "llm-provider");
    store
        .create_member_grant_audited(
            MEMBER,
            MemberGrantOperation::SecretUse,
            &MemberGrantSelector::None,
            PAIRING,
        )
        .unwrap();
    let version = data_version(&conn);
    let writes = store.subscribe_writes();
    assert!(home
        .remote_watch_projection(MEMBER, PAIRING)
        .unwrap()
        .is_empty());
    assert!(store.recent_auth_events(100).unwrap().is_empty());
    assert_eq!(data_version(&conn), version);
    assert!(!writes.has_changed().unwrap());
}

fn watch_row() -> RemoteWatchRow {
    let record = login();
    RemoteWatchRow {
        credential_id: "oauth:login".into(),
        state: RemoteHomeState::Active,
        refresh_adapter: record.refresh_adapter,
        identity: record.identity,
        categories: vec!["llm-provider".into()],
        detected_plan: record.detected_plan,
        home_version: 7,
    }
}

#[test]
fn projection_wire_has_only_inventory_fields_with_token_identity_and_plan_shapes() {
    let row = watch_row();
    assert_eq!(
        remote_watch_logins_wire(std::slice::from_ref(&row)),
        [json!({
            "credential_id": "oauth:login",
            "state": "active",
            "refresh_adapter": "anthropic",
            "identity": {"account_id":"account", "org_name":"workspace"},
            "categories": ["llm-provider"],
            "detected_plan": {"tier":"pro", "raw":"provider-pro", "observed_at_ms":42},
            "home_version": 7,
        })]
    );
    let mut unknown = row;
    unknown.detected_plan = None;
    unknown.state = RemoteHomeState::NeedsReauth;
    let wire = remote_watch_logins_wire(&[unknown]);
    assert!(wire[0].as_object().unwrap().contains_key("detected_plan"));
    assert!(wire[0]["detected_plan"].is_null());
    assert_eq!(wire[0]["state"], "needs_reauth");
}

#[test]
fn projection_comparison_ignores_refresh_version_and_plan_observation_time_only() {
    let original = vec![watch_row()];
    let mut observed = original.clone();
    observed[0].detected_plan.as_mut().unwrap().observed_at_ms += 1;
    assert!(remote_watch_lists_equal(&original, &observed));
    let mut versioned = original.clone();
    versioned[0].home_version += 1;
    assert!(remote_watch_lists_equal(&original, &versioned));
    let mut refreshed = original.clone();
    refreshed[0].home_version += 1;
    refreshed[0].detected_plan.as_mut().unwrap().observed_at_ms += 1;
    assert!(remote_watch_lists_equal(&original, &refreshed));
    assert!(remote_watch_lists_equal(&refreshed, &original));
    assert!(remote_watch_lists_equal(&[], &[]));
    assert!(!remote_watch_lists_equal(&original, &[]));

    let mut tier = refreshed.clone();
    tier[0].detected_plan.as_mut().unwrap().tier = Some("max".into());
    let mut raw = refreshed.clone();
    raw[0].detected_plan.as_mut().unwrap().raw = Some("provider-max".into());
    let mut category = refreshed.clone();
    category[0].categories = vec!["other".into()];
    let mut adapter = refreshed.clone();
    adapter[0].refresh_adapter = Some("openai".into());
    let mut identity = refreshed.clone();
    identity[0].identity.account_id = Some("other".into());
    let mut state = refreshed.clone();
    state[0].state = RemoteHomeState::NeedsReauth;
    let mut id = refreshed.clone();
    id[0].credential_id = "oauth:other".into();
    let mut unknown = refreshed.clone();
    unknown[0].detected_plan = None;
    for changed in [tier, raw, category, adapter, identity, state, id, unknown] {
        assert!(!remote_watch_lists_equal(&original, &changed));
    }
}

#[test]
fn projection_omits_unreadable_rows_without_quarantining_and_propagates_query_errors() {
    let (_root, home, conn) = rig();
    let store = home.engine.store();
    for id in ["oauth:good", "oauth:broken"] {
        store.create(id, &login()).unwrap();
        grant(
            store,
            MEMBER,
            PAIRING,
            MemberGrantSelector::Exact(id.into()),
        );
    }
    conn.execute(
        "UPDATE credentials SET envelope = X'00' WHERE credential_id = 'oauth:broken'",
        [],
    )
    .unwrap();
    let version = data_version(&conn);
    let rows = home.remote_watch_projection(MEMBER, PAIRING).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].credential_id, "oauth:good");
    assert_eq!(
        store.meta("oauth:broken").unwrap().state,
        RecordState::Active
    );
    assert_eq!(data_version(&conn), version);
    let writes = store.subscribe_writes();
    conn.execute_batch("ALTER TABLE credential_categories RENAME COLUMN category TO unavailable")
        .unwrap();
    let version = data_version(&conn);
    assert!(home.remote_watch_projection(MEMBER, PAIRING).is_err());
    assert_eq!(data_version(&conn), version);
    assert!(!writes.has_changed().unwrap());
}

#[test]
fn shared_grant_coverage_requires_member_pairing_operation_and_selector() {
    let (_root, home, conn) = rig();
    let store = home.engine.store();
    store.create("oauth:login", &login()).unwrap();
    category(store, "oauth:login", "llm-provider");
    let exact = MemberGrant {
        member_id: MEMBER.into(),
        pairing_id: PAIRING.into(),
        operation: MemberGrantOperation::RemoteRead,
        selector: MemberGrantSelector::Exact("oauth:login".into()),
        created_at_ms: 1,
        source: MemberGrantSource::Operator,
    };
    let covers = |grant: &MemberGrant| {
        remote_read_grant_covers(
            store,
            std::slice::from_ref(grant),
            MEMBER,
            PAIRING,
            "oauth:login",
        )
        .unwrap()
    };
    assert!(covers(&exact));
    let mut categorical = exact.clone();
    categorical.selector = MemberGrantSelector::Category("llm-provider".into());
    assert!(covers(&categorical));
    let mut other = exact.clone();
    other.member_id = OTHER.into();
    let mut stale = exact.clone();
    stale.pairing_id = "old-pair".into();
    let mut wrong_op = exact.clone();
    wrong_op.operation = MemberGrantOperation::TransferDeliver;
    let mut wrong_id = exact.clone();
    wrong_id.selector = MemberGrantSelector::Exact("oauth:other".into());
    let mut wrong_category = categorical.clone();
    wrong_category.selector = MemberGrantSelector::Category("other".into());
    let mut no_selector = exact.clone();
    no_selector.selector = MemberGrantSelector::None;
    for grant in [
        other,
        stale,
        wrong_op,
        wrong_id,
        wrong_category,
        no_selector,
    ] {
        assert!(!covers(&grant));
    }
    conn.execute_batch("ALTER TABLE credential_categories RENAME COLUMN category TO unavailable")
        .unwrap();
    assert!(remote_read_grant_covers(
        store,
        &[exact, categorical.clone()],
        MEMBER,
        PAIRING,
        "oauth:login"
    )
    .unwrap());
    assert!(
        remote_read_grant_covers(store, &[categorical], MEMBER, PAIRING, "oauth:login").is_err()
    );
}
