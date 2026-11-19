use super::*;
use crate::{ConnectorInventory, ConnectorRecordMetadata, ConnectorRow};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};

/// The category an operator puts on a stored secret that a module needs in order to run
/// at all, such as Broca's session-storage key. Grants on such a record are left out of
/// the apps' permission list, like grants on vault-held keys: one tap there would stop
/// the module, and that's not something to offer next to ordinary access.
pub const MODULE_RUNTIME_CATEGORY: &str = "module-runtime";

fn visible_grants(conn: &rusqlite::Connection) -> rusqlite::Result<Vec<ReadGrant>> {
    let runtime = runtime_ids(conn)?;
    visible_grants_for_runtime(conn, &runtime)
}

fn visible_grants_for_runtime(
    conn: &rusqlite::Connection,
    runtime: &BTreeSet<String>,
) -> rusqlite::Result<Vec<ReadGrant>> {
    #[cfg(test)]
    tests::count_grant_load();
    Ok(
        read_grants_from_conn(conn, None, None, read_schema_version(conn)?)?
            .into_iter()
            .filter(|grant| {
                matches!(grant.principal_kind.as_str(), "reserved" | "enrolled")
                    && !(grant.selector_kind == SelectorKind::Exact
                        && (grant.selector.starts_with("signing:")
                            || grant.selector.starts_with("kem:")
                            || runtime.contains(&grant.selector)))
            })
            .collect(),
    )
}

#[derive(Default)]
struct PermissionIndex {
    exact: HashMap<String, Vec<String>>,
    category: HashMap<String, Vec<String>>,
}

impl PermissionIndex {
    fn new(grants: Vec<ReadGrant>) -> Self {
        let mut index = Self::default();
        for grant in grants {
            let bucket = match grant.selector_kind {
                SelectorKind::Exact => &mut index.exact,
                SelectorKind::Category => &mut index.category,
                SelectorKind::Audience => continue,
            };
            let id = grant_id(&grant);
            bucket.entry(grant.selector).or_default().push(id);
        }
        index
    }

    fn ids_for(&self, id: &str, categories: &[String]) -> Vec<String> {
        let mut ids: Vec<_> = self.exact.get(id).into_iter().flatten().cloned().collect();
        for category in categories {
            ids.extend(self.category.get(category).into_iter().flatten().cloned());
        }
        ids.sort_unstable();
        ids
    }
}

impl EncryptedStore {
    /// Newest existing diagnostic reason, without imposing a global event limit.
    pub fn connector_auth_reason(&self, id: &str) -> Result<Option<String>, StoreOpError> {
        self.store
            .with_conn(|conn| connector_auth_reason(conn, id))
            .map_err(StoreOpError::from)
    }

    /// Open display metadata even for non-active records. Each row, including its
    /// categories and incarnation, must come from the same snapshot as its envelope.
    pub fn connector_inventory(&self) -> Result<ConnectorInventory, StoreOpError> {
        self.store
            .with_conn(|conn| {
                let tx = conn.unchecked_transaction()?;
                let inventory = self.connector_inventory_in_snapshot(&tx)?;
                tx.commit()?;
                Ok(inventory)
            })
            .map_err(StoreOpError::from)
    }

    fn connector_inventory_in_snapshot(
        &self,
        conn: &rusqlite::Connection,
    ) -> rusqlite::Result<ConnectorInventory> {
        let runtime = runtime_ids(conn)?;
        #[cfg(test)]
        tests::after_first_read()?;
        let permissions = PermissionIndex::new(visible_grants_for_runtime(conn, &runtime)?);
        let mut local = Vec::new();
        let mut stmt = conn.prepare(
            "SELECT credential_id, record_version, envelope, incarnation, state,
                COALESCE((SELECT group_concat(category, ',') FROM (
                    SELECT category FROM credential_categories
                    WHERE credential_id=credentials.credential_id ORDER BY category
                )), ''),
                (SELECT plan_tier FROM credential_plan_tiers WHERE credential_id=credentials.credential_id)
             FROM credentials ORDER BY credential_id",
        )?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let id: String = row.get(0)?;
            if runtime.contains(&id) {
                continue;
            }
            let version = row.get(1)?;
            let bytes: Vec<u8> = row.get(2)?;
            let Ok(plaintext) = envelope::open(
                &self.key,
                &bytes,
                &RecordBinding {
                    credential_id: &id,
                    record_version: version,
                },
            ) else {
                continue;
            };
            // Undecodable records have no trustworthy kind for the connector list.
            let Ok(record) = VaultRecord::decode(&plaintext) else {
                continue;
            };
            let kind = match record.kind {
                CredentialKind::Oauth
                    if record.refresh_adapter.as_deref().is_some_and(|adapter| {
                        adapter != crate::refresh_adapters::github_app::ADAPTER_NAME
                    }) =>
                {
                    "account"
                }
                CredentialKind::Cookie => "account",
                CredentialKind::ApiKey if record.refresh_adapter.is_none() => "api_key",
                _ => continue,
            };
            let state = RecordState::from_str(&row.get::<_, String>(4)?);
            let categories = crate::store::metadata::split_categories(row.get(5)?);
            let incarnation: String = row.get(3)?;
            local.push(ConnectorRow {
                permissions: permissions.ids_for(&id, &categories),
                auth_reason: if state == RecordState::Active {
                    None
                } else {
                    connector_auth_reason(conn, &id)?
                },
                condition: conditions::local_condition_conn(conn, &id, &incarnation)?,
                record: ConnectorRecordMetadata {
                    id,
                    incarnation,
                    state,
                    categories,
                    kind,
                    identity: record.identity,
                    detected_plan: record.detected_plan,
                    plan_tier: row.get(6)?,
                },
            });
        }
        let mut remote = Vec::new();
        for entry in Self::remote_inventory_in_snapshot(conn)? {
            let id = &entry.record.credential_id;
            if !runtime.contains(id) {
                remote.push(ConnectorRow {
                    permissions: permissions.ids_for(id, &entry.categories),
                    auth_reason: connector_auth_reason(conn, id)?,
                    condition: conditions::remote_condition_conn(
                        conn,
                        id,
                        &entry.record.incarnation,
                    )?,
                    record: entry,
                });
            }
        }
        let computer =
            federation_store::read_setting(conn, crate::federation::SELF_MEMBER_SETTING)?;
        Ok(ConnectorInventory {
            local,
            remote,
            computer,
        })
    }
}

fn connector_auth_reason(
    conn: &rusqlite::Connection,
    id: &str,
) -> rusqlite::Result<Option<String>> {
    conn.query_row("SELECT detail FROM auth_events WHERE credential_id=?1 AND detail IS NOT NULL ORDER BY seq DESC LIMIT 1", [id], |row| row.get(0)).optional()
}

fn runtime_ids(conn: &rusqlite::Connection) -> rusqlite::Result<BTreeSet<String>> {
    conn.prepare("SELECT credential_id FROM credential_categories WHERE category=?1 UNION SELECT credential_id FROM remote_record_categories WHERE category=?1")?
        .query_map([MODULE_RUNTIME_CATEGORY], |row| row.get(0))?
        .collect()
}

fn grant_id(grant: &ReadGrant) -> String {
    credential_permission_id([
        &grant.principal_kind,
        &grant.principal_id,
        grant.selector_kind.as_str(),
        &grant.selector,
        grant.operation.as_str(),
    ])
}

pub(super) fn permission_rows(conn: &rusqlite::Connection) -> rusqlite::Result<Vec<Value>> {
    visible_grants(conn)?
        .into_iter()
        .map(|grant| {
            let mut holder = if grant.principal_kind == "reserved" {
                json!({"kind":"module", "module_id":grant.principal_id})
            } else {
                json!({"kind":"enrolled", "name":grant.principal_id})
            };
            if grant.principal_kind == "enrolled" {
                let label: Option<String> = conn
                    .query_row(
                        "SELECT display_name FROM enrolled_consumers WHERE name=?1 AND revoked_at_ms IS NULL",
                        [&grant.principal_id],
                        |row| {
                            let label: Option<String> = row.get(0)?;
                            Ok(crate::display_name::effective_enrollment_display_name(
                                &grant.principal_id,
                                label.as_deref(),
                            )
                            .map(str::to_owned))
                        },
                    )
                    .optional()?
                    .flatten();
                if let Some(label) = label {
                    holder["label"] = json!(label);
                }
            }
            let reach = if grant.selector_kind == SelectorKind::Category {
                conn.query_row(
                    "SELECT COUNT(*) FROM credential_categories cc JOIN credentials c \
                     ON c.credential_id=cc.credential_id WHERE cc.category=?1",
                    [&grant.selector],
                    |row| row.get::<_, usize>(0),
                )?
            } else {
                0
            };
            Ok(json!({
                "id":grant_id(&grant),
                "holder":holder,
                "module":"claustrum",
                "subject_label":credential_subject_label(grant.selector_kind.as_str(), &grant.selector),
                "scope":grant.operation.as_str(),
                "scope_label":credential_scope_label(grant.selector_kind.as_str(), &grant.selector, grant.operation.as_str(), reach),
                "granted_at_ms":grant.created_at_ms,
            }))
        })
        .collect()
}

pub(super) fn revoke(
    tx: &rusqlite::Transaction<'_>,
    key: &[u8; 32],
    id: &str,
    actor: &str,
) -> rusqlite::Result<Value> {
    let Some(grant) = visible_grants(tx)?
        .into_iter()
        .find(|grant| grant_id(grant) == id)
    else {
        return Ok(json!({"outcome":"not_found"}));
    };
    // Resolve the opaque id and remove the grant within the same transaction. The CLI
    // and provider share the deletion, audit record and grant-generation update.
    let changed = revoke_read_grant_audited_tx(
        tx,
        key,
        &grant.principal_kind,
        &grant.principal_id,
        grant.selector_kind,
        &grant.selector,
        grant.operation,
        AuditCtx {
            actor,
            op: AuditOp::GrantRevoke,
            alarm: None,
        },
    )?;
    Ok(json!({"outcome":if changed > 0 {"revoked"} else {"not_found"}}))
}

fn credential_permission_id(columns: [&str; 5]) -> String {
    let mut hash = Sha256::new();
    hash.update(b"claustrum-credential-permission/v1\0");
    for column in columns {
        hash.update((column.len() as u64).to_be_bytes());
        hash.update(column.as_bytes());
    }
    format!("cg_{:x}", hash.finalize())
}

fn credential_subject_label(selector_kind: &str, selector: &str) -> String {
    match selector_kind {
        "category" => match selector {
            "llm-provider" => "Model provider logins and keys".into(),
            "llm-gateway" => "Company AI gateway keys".into(),
            "web-search" => "Web search keys".into(),
            "media-provider" => "Speech and media keys".into(),
            "embedding-provider" => "Embedding model keys".into(),
            "browser-session" => "Browser sign-ins".into(),
            "github-app-native" => "GitHub App keys".into(),
            "anthropic-native" => "Claude logins".into(),
            "openai-native" => "ChatGPT logins".into(),
            "antigravity-native" => "Antigravity logins".into(),
            other => format!("Credentials in the {other} group"),
        },
        "audience" => format!("CortexKit account tokens for {selector}"),
        _ => selector.into(),
    }
}

fn credential_scope_label(
    selector_kind: &str,
    selector: &str,
    operation: &str,
    reach: usize,
) -> String {
    if selector_kind == "audience" {
        return format!("can get CortexKit account tokens for {selector}");
    }
    if selector_kind == "category" {
        let credentials = if reach == 1 {
            "1 credential".to_owned()
        } else {
            format!("{reach} credentials")
        };
        return match operation {
            "read" => format!("can read the secrets of {credentials} in this group"),
            "list" => format!(
                "can see the accounts and plans of {credentials} in this group, but not their secrets"
            ),
            "deposit" => format!(
                "can store browser sign-ins in this group, which currently contains {credentials}"
            ),
            "sign" => format!("can sign with {credentials} in this group"),
            "open" => format!("can decrypt messages with {credentials} in this group"),
            "seal" => format!("can encrypt messages with {credentials} in this group"),
            _ => format!("can get account tokens with {credentials} in this group"),
        };
    }
    match operation {
        "read" => "can read the secret of this credential",
        "list" => "can see this account and its plan, but not its secret",
        "deposit" => "can store browser sign-ins for this credential",
        "sign" => "can sign with this credential",
        "open" => "can decrypt messages with this credential",
        "seal" => "can encrypt messages with this credential",
        _ => "can get account tokens with this credential",
    }
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::taxonomy_tests::{api_record, rig};
    use std::cell::{Cell, RefCell};

    type BetweenReads = Box<dyn FnOnce() -> rusqlite::Result<()>>;
    thread_local! {
        static BETWEEN_READS: RefCell<Option<BetweenReads>> = const { RefCell::new(None) };
        static GRANT_LOADS: Cell<usize> = const { Cell::new(0) };
    }

    pub(super) fn after_first_read() -> rusqlite::Result<()> {
        BETWEEN_READS.with(|hook| hook.take().map_or(Ok(()), |hook| hook()))
    }

    pub(super) fn count_grant_load() {
        GRANT_LOADS.with(|count| count.set(count.get() + 1));
    }

    #[test]
    fn connector_inventory_keeps_coherent_rows_across_replacement_and_removal() {
        const REPLACED: &str = "apikey:zai";
        const REMOVED: &str = "apikey:to-remove";
        const NEXT: &str = "11111111111111111111111111111111";
        let (root, store) = rig("connector-snapshot", 95);
        let record_with_identity = |identity: &str| {
            api_record().with_identity(crate::record::RecordIdentity {
                account_id: Some(identity.into()),
                ..Default::default()
            })
        };
        store
            .create(REPLACED, &record_with_identity("old"))
            .unwrap();
        store.create(REMOVED, &api_record()).unwrap();
        let old = store.meta(REPLACED).unwrap();
        let replacement = store
            .seal_record(REPLACED, &record_with_identity("new"))
            .unwrap();
        let path = root.join("store.db");
        BETWEEN_READS.with(|slot| slot.replace(Some(Box::new(move || {
            let writer = rusqlite::Connection::open(path)?;
            let tx = writer.unchecked_transaction()?;
            tx.execute("UPDATE credentials SET envelope=?1,incarnation=?2,state='retired' WHERE credential_id=?3",
                rusqlite::params![replacement, NEXT, REPLACED])?;
            tx.execute("DELETE FROM credential_categories WHERE credential_id=?1", [REPLACED])?;
            tx.execute("INSERT INTO credential_categories(credential_id,category) VALUES (?1,'monitoring')", [REPLACED])?;
            tx.execute("DELETE FROM credentials WHERE credential_id=?1", [REMOVED])?;
            tx.commit()
        }))));
        let first = store.connector_inventory().unwrap();
        let snapshot = first
            .local
            .iter()
            .find(|row| row.record.id == REPLACED)
            .unwrap();
        assert_eq!(Some(&snapshot.record.incarnation), old.incarnation.as_ref());
        assert_eq!(snapshot.record.identity.account_id.as_deref(), Some("old"));
        assert_eq!(snapshot.record.state, RecordState::Active);
        assert_eq!(snapshot.record.categories, old.categories);
        assert!(first.local.iter().any(|row| row.record.id == REMOVED));

        let next = store.connector_inventory().unwrap();
        assert_eq!(next.local.len(), 1);
        let row = &next.local[0].record;
        assert_eq!(row.incarnation, NEXT);
        assert_eq!(row.identity.account_id.as_deref(), Some("new"));
        assert_eq!(row.state, RecordState::Retired);
        assert_eq!(row.categories, ["monitoring"]);
    }

    #[test]
    fn connector_inventory_loads_grants_once_for_many_rows() {
        let (_root, store) = rig("connector-permission-index", 96);
        let grant = |kind, selector: &str| {
            store
                .create_read_grant_audited(
                    "reserved",
                    "consumer",
                    kind,
                    selector,
                    GrantOperation::Read,
                    AuditCtx::admin(AuditOp::GrantCreate),
                )
                .unwrap();
        };
        grant(SelectorKind::Category, "monitoring");
        for n in 0..20 {
            let id = format!("apikey:test-{n}");
            store.create(&id, &api_record()).unwrap();
            grant(SelectorKind::Exact, &id);
        }
        store.with_raw_conn(|conn| {
            conn.execute("INSERT INTO credential_categories(credential_id,category) VALUES ('apikey:test-0','monitoring')", [])?;
            Ok(())
        }).unwrap();
        GRANT_LOADS.with(|count| count.set(0));
        let inventory = store.connector_inventory().unwrap();
        GRANT_LOADS.with(|count| assert_eq!(count.get(), 1));
        assert_eq!(inventory.local.len(), 20);
        for row in inventory.local {
            let mut expected = vec![credential_permission_id([
                "reserved",
                "consumer",
                "exact",
                &row.record.id,
                "read",
            ])];
            if row.record.id == "apikey:test-0" {
                expected.push(credential_permission_id([
                    "reserved",
                    "consumer",
                    "category",
                    "monitoring",
                    "read",
                ]));
            }
            expected.sort_unstable();
            assert_eq!(row.permissions, expected);
        }
    }

    #[test]
    fn credential_permission_ids_are_framed_and_stable() {
        assert_eq!(
            credential_permission_id(["reserved", "broca", "category", "llm-provider", "read"]),
            "cg_0b27e0d58a8329b15f72cc8765399faba1656d3b263a93cb2f567b3c3a2d9955"
        );
        assert_ne!(
            credential_permission_id(["ab", "c", "exact", "key", "read"]),
            credential_permission_id(["a", "bc", "exact", "key", "read"])
        );
        assert_ne!(
            credential_permission_id(["reserved", "broca", "category", "llm-provider", "read"]),
            credential_permission_id(["reserved", "broca", "category", "llm-provider", "list"])
        );
    }

    #[test]
    fn credential_permission_subject_labels_cover_every_catalog_category() {
        let labels = [
            ("llm-provider", "Model provider logins and keys"),
            ("llm-gateway", "Company AI gateway keys"),
            ("data-warehouse", "Credentials in the data-warehouse group"),
            (
                "cloud-infrastructure",
                "Credentials in the cloud-infrastructure group",
            ),
            ("web-search", "Web search keys"),
            ("media-provider", "Speech and media keys"),
            ("embedding-provider", "Embedding model keys"),
        ];
        assert_eq!(labels.len(), crate::catalog::CredentialCategory::ALL.len());
        for category in crate::catalog::CredentialCategory::ALL {
            let (_, expected) = labels
                .iter()
                .find(|(name, _)| *name == category.as_str())
                .expect("every catalog category has a pinned subject label");
            assert_eq!(
                credential_subject_label("category", category.as_str()),
                *expected
            );
        }
    }

    #[test]
    fn credential_permission_labels_cover_groups_and_operations() {
        for (category, expected) in [
            ("llm-provider", "Model provider logins and keys"),
            ("llm-gateway", "Company AI gateway keys"),
            ("web-search", "Web search keys"),
            ("media-provider", "Speech and media keys"),
            ("embedding-provider", "Embedding model keys"),
            ("browser-session", "Browser sign-ins"),
            ("github-app-native", "GitHub App keys"),
            ("anthropic-native", "Claude logins"),
            ("openai-native", "ChatGPT logins"),
            ("antigravity-native", "Antigravity logins"),
            ("custom", "Credentials in the custom group"),
        ] {
            assert_eq!(credential_subject_label("category", category), expected);
        }
        assert_eq!(credential_subject_label("exact", "key-1"), "key-1");
        assert_eq!(
            credential_subject_label("audience", "cortexkit-runners"),
            "CortexKit account tokens for cortexkit-runners"
        );
        for operation in [
            "read",
            "list",
            "sign",
            "open",
            "seal",
            "deposit",
            "account_token",
        ] {
            let empty = credential_scope_label("category", "custom", operation, 0);
            let populated = credential_scope_label("category", "custom", operation, 37);
            assert!(empty.contains("0 credentials"), "{empty}");
            assert!(populated.contains("37 credentials"), "{populated}");
            assert!(credential_scope_label("exact", "key-1", operation, 1).starts_with("can "));
        }
    }
}
