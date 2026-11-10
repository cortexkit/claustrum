//! Operator answers supply defaults only for API-key services outside the catalog.

use super::*;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RegisteredProvider {
    pub service: String,
    pub categories: Vec<String>,
    pub provider_ids: Vec<String>,
    pub created_at_ms: i64,
}

impl RegisteredProvider {
    pub fn service_for_id<'a>(rows: &'a [Self], id: &str) -> Option<&'a str> {
        crate::catalog::provider(id)
            .or_else(|| Self::for_id(rows, id).map(|row| row.service.as_str()))
    }

    pub fn for_id<'a>(rows: &'a [Self], id: &str) -> Option<&'a Self> {
        if crate::catalog::provider(id).is_some() {
            return None;
        }
        let service = api_key_service(id)?;
        rows.iter().find(|row| row.service == service)
    }
}

pub fn api_key_service(id: &str) -> Option<&str> {
    let mut segments = id.split(':');
    (segments.next()? == "apikey")
        .then(|| segments.next())
        .flatten()
        .filter(|service| !service.is_empty())
}

/// Validate before either CLI preflight or a store write, so both routes refuse alike.
pub fn validate_registered_provider_service(service: &str) -> Result<(), StoreOpError> {
    if !crate::credential_id::valid_api_key_service_name(service) {
        return Err(StoreOpError::InvalidServiceName {
            service: service.to_owned(),
        });
    }
    if crate::catalog::api_key_provider(service).is_some() {
        return Err(StoreOpError::ServiceInProviderCatalog {
            service: service.to_owned(),
        });
    }
    Ok(())
}

pub(super) fn from_conn(conn: &rusqlite::Connection) -> rusqlite::Result<Vec<RegisteredProvider>> {
    if read_schema_version(conn)? < REGISTERED_PROVIDERS_SCHEMA_VERSION {
        return Ok(Vec::new());
    }
    let mut stmt = conn.prepare(
        "SELECT service, categories_json, provider_ids_json, created_at_ms \
         FROM registered_providers ORDER BY service",
    )?;
    let rows = stmt.query_map([], |row| {
        let decode = |column| -> rusqlite::Result<Vec<String>> {
            serde_json::from_str(&row.get::<_, String>(column)?).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    column,
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            })
        };
        Ok(RegisteredProvider {
            service: row.get(0)?,
            categories: decode(1)?,
            provider_ids: decode(2)?,
            created_at_ms: row.get(3)?,
        })
    })?;
    rows.collect()
}

/// Read metadata without a master key, migration, or writer lease.
pub fn registered_providers_read_only(
    path: &std::path::Path,
) -> Result<Vec<RegisteredProvider>, StoreOpError> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let conn =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|error| StoreOpError::Store(error.to_string()))?;
    from_conn(&conn).map_err(|error| StoreOpError::Store(error.to_string()))
}

pub(super) fn category_defaults(
    conn: &rusqlite::Connection,
    id: &str,
) -> rusqlite::Result<Vec<String>> {
    if crate::catalog::provider(id).is_some() {
        return Ok(crate::catalog::category_defaults(id));
    }
    if let Some(service) = api_key_service(id) {
        if let Some(row) = from_conn(conn)?
            .into_iter()
            .find(|row| row.service == service)
        {
            return Ok(row.categories);
        }
    }
    Ok(crate::catalog::category_defaults(id))
}

impl EncryptedStore {
    pub fn registered_providers(&self) -> Result<Vec<RegisteredProvider>, StoreOpError> {
        self.store.with_conn(from_conn).map_err(StoreOpError::from)
    }

    /// Change defaults for future keys, never the categories or routes of existing keys.
    /// The answer and its audit entry commit together, and identical sets are a no-op.
    pub fn set_registered_provider_audited(
        &self,
        service: &str,
        categories: &[String],
        provider_ids: &[String],
        ctx: AuditCtx<'_>,
    ) -> Result<bool, StoreOpError> {
        validate_registered_provider_service(service)?;
        if categories.iter().any(|category| {
            !crate::catalog::CredentialCategory::ALL
                .iter()
                .any(|known| known.as_str() == category)
        }) {
            return Err(StoreOpError::InvalidCategoryName);
        }
        crate::provider_ids::check_provider_ids(provider_ids)?;
        if provider_ids.len() > crate::provider_ids::MAX_PROVIDER_IDS_PER_CREDENTIAL {
            return Err(StoreOpError::InvalidProviderId {
                rule: crate::provider_ids::ProviderIdRule::Count,
                value: provider_ids[crate::provider_ids::MAX_PROVIDER_IDS_PER_CREDENTIAL].clone(),
            });
        }
        let categories: Vec<_> = categories
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let provider_ids: Vec<_> = provider_ids
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let categories_json = serde_json::to_string(&categories)
            .map_err(|error| StoreOpError::Encode(error.to_string()))?;
        let provider_ids_json = serde_json::to_string(&provider_ids)
            .map_err(|error| StoreOpError::Encode(error.to_string()))?;
        self.fenced_write(|tx| {
            let changed = tx.execute(
                "INSERT INTO registered_providers (service, categories_json, provider_ids_json, created_at_ms) \
                 VALUES (?1, ?2, ?3, ?4) ON CONFLICT(service) DO UPDATE SET \
                 categories_json = excluded.categories_json, provider_ids_json = excluded.provider_ids_json \
                 WHERE categories_json != excluded.categories_json OR provider_ids_json != excluded.provider_ids_json",
                rusqlite::params![service, categories_json, provider_ids_json, now_ms()],
            )?;
            if changed > 0 {
                append_audit_tx(tx, &self.audit_key, &AuditRecord {
                    op: ctx.op,
                    credential_id: Some(format!("provider:{service}|{}|{}", categories.join(","), provider_ids.join(","))),
                    payload_hash: None,
                    actor: ctx.actor.to_owned(),
                    alarm: ctx.alarm,
                })?;
            }
            Ok(changed > 0)
        }).map_err(StoreOpError::from)
    }

    pub fn remove_registered_provider_audited(
        &self,
        service: &str,
        ctx: AuditCtx<'_>,
    ) -> Result<bool, StoreOpError> {
        self.fenced_write(|tx| {
            let changed = tx.execute(
                "DELETE FROM registered_providers WHERE service = ?1",
                [service],
            )?;
            if changed > 0 {
                append_audit_tx(
                    tx,
                    &self.audit_key,
                    &AuditRecord {
                        op: ctx.op,
                        credential_id: Some(format!("provider:{service}")),
                        payload_hash: None,
                        actor: ctx.actor.to_owned(),
                        alarm: ctx.alarm,
                    },
                )?;
            }
            Ok(changed > 0)
        })
        .map_err(StoreOpError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registered_provider_migration_preserves_records_and_behind_readers_are_lease_free() {
        let (root, sqlite) = taxonomy_tests::sqlite("registered-migration", 191);
        migrate_through_for_test(&sqlite, REGISTERED_PROVIDERS_SCHEMA_VERSION - 1).unwrap();
        let store = EncryptedStore::open(sqlite, MasterKey::from_bytes([191; 32])).unwrap();
        store
            .create("apikey:custom:existing", &taxonomy_tests::api_record())
            .unwrap();
        let meta = store.list_meta().unwrap();
        let audit = store.read_audit(None).unwrap();
        let path = root.join("store.db");
        assert!(registered_providers_read_only(&path).unwrap().is_empty());
        EncryptedStore::migrate(&store.store).unwrap();
        assert_eq!(store.list_meta().unwrap(), meta);
        assert_eq!(store.read_audit(None).unwrap(), audit);
        assert!(store.registered_providers().unwrap().is_empty());
        assert_eq!(newest_migration_version(), 38);
    }

    #[test]
    fn registered_provider_answer_and_audit_roll_back_together() {
        let (_root, store) = taxonomy_tests::rig("registered-atomic", 192);
        let set = |categories: &[String]| {
            store.set_registered_provider_audited(
                "custom",
                categories,
                &[],
                AuditCtx::admin(AuditOp::ProviderSet),
            )
        };
        let before = store.audit_tip().unwrap();
        store.store.with_conn(|conn| conn.execute_batch(
            "CREATE TRIGGER fail_provider_audit BEFORE INSERT ON audit_log BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END;",
        )).unwrap();
        assert!(set(&["web-search".into()]).is_err());
        assert!(store.registered_providers().unwrap().is_empty());
        assert_eq!(store.audit_tip().unwrap(), before);
        store
            .store
            .with_conn(|conn| conn.execute_batch("DROP TRIGGER fail_provider_audit;"))
            .unwrap();
        assert!(set(&["web-search".into()]).unwrap());
        let answer = store.registered_providers().unwrap();
        let before = store.audit_tip().unwrap();
        store.store.with_conn(|conn| conn.execute_batch(
            "CREATE TRIGGER fail_provider_audit BEFORE INSERT ON audit_log BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END;",
        )).unwrap();
        assert!(set(&["media-provider".into()]).is_err());
        assert!(store
            .remove_registered_provider_audited("custom", AuditCtx::admin(AuditOp::ProviderRemove))
            .is_err());
        assert_eq!(store.registered_providers().unwrap(), answer);
        assert_eq!(store.audit_tip().unwrap(), before);
        assert!(!set(&["web-search".into()]).unwrap());
    }

    #[test]
    fn registered_provider_validation_and_catalog_precedence_apply_before_writes() {
        let (_root, store) = taxonomy_tests::rig("registered-validation", 193);
        let set = |service, categories: &[String], ids: &[String]| {
            store.set_registered_provider_audited(
                service,
                categories,
                ids,
                AuditCtx::admin(AuditOp::ProviderSet),
            )
        };
        let before = store.audit_tip().unwrap();
        for service in [
            "",
            "has space",
            "has:colon",
            "has|separator",
            "has\nnewline",
            "has\u{1b}control",
        ] {
            let error = set(service, &[], &[]).unwrap_err();
            assert!(
                matches!(&error, StoreOpError::InvalidServiceName { service: invalid } if invalid == service)
            );
            assert_eq!(error.wire_code(), Some("invalid_service_name"));
            assert_eq!(error.wire_class(), Some("permanent"));
            assert!(error.to_string().contains(&format!("{service:?}")));
            assert!(!error.to_string().contains("storage error"));
        }
        for row in crate::catalog::API_KEY_PROVIDERS {
            let error = set(row.key, &[], &[]).unwrap_err();
            assert!(
                matches!(&error, StoreOpError::ServiceInProviderCatalog { service } if service == row.key)
            );
            assert_eq!(error.wire_code(), Some("service_in_provider_catalog"));
            assert_eq!(error.wire_class(), Some("permanent"));
            assert!(error.to_string().contains(row.key));
            assert!(!error.to_string().contains("storage error"));
        }
        assert!(set("custom", &["unknown-group".into()], &[]).is_err());
        assert!(set("custom", &[], &["BAD".into()]).is_err());
        assert!(store.registered_providers().unwrap().is_empty());
        assert_eq!(store.audit_tip().unwrap(), before);
        for service in ["CUSTOM", "custom.vendor", "éclair"] {
            assert!(set(service, &[], &[]).unwrap());
            let id = format!("apikey:{service}");
            store.create(&id, &taxonomy_tests::api_record()).unwrap();
            assert!(store.meta(&id).is_ok());
        }
        assert!(set("custom", &["web-search".into(), "llm-provider".into()], &[]).unwrap());
        let tip = store.audit_tip().unwrap();
        assert!(!set("custom", &["llm-provider".into(), "web-search".into()], &[]).unwrap());
        assert_eq!(store.audit_tip().unwrap(), tip);
        assert_eq!(store.verify_audit_chain().unwrap(), None);
    }
}
