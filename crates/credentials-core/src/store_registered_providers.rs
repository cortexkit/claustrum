//! Operator answers supply defaults only for API-key services outside the catalog.

use super::*;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RegisteredProvider {
    pub service: String,
    pub categories: Vec<String>,
    pub provider_ids: Vec<String>,
    pub created_at_ms: i64,
    pub hosts: Vec<String>,
    pub auth_header: Option<String>,
    pub auth_scheme: Option<String>,
    pub fusiform_provider_id: Option<String>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct RegisteredProviderSettings {
    pub hosts: Vec<String>,
    pub auth_header: Option<String>,
    pub auth_scheme: Option<String>,
    pub fusiform_provider_id: Option<String>,
}

pub const MAX_REGISTERED_PROVIDER_HOSTS: usize = 8;

/// Lowercase HTTP token grammar shared by registry and gateway auth headers.
pub fn valid_provider_header_name(header: &str) -> bool {
    !header.is_empty()
        && header.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || b"!#$%&'*+-.^_`|~".contains(&b)
        })
}

/// Shared by CLI preflight and store writes; the store never repairs signed input.
pub fn validate_registered_provider_settings(
    settings: &RegisteredProviderSettings,
) -> Result<(), StoreOpError> {
    let invalid = |field: &str, value: String| {
        StoreOpError::Encode(format!("invalid provider {field}: {value}"))
    };
    let hosts = &settings.hosts;
    if hosts.len() > MAX_REGISTERED_PROVIDER_HOSTS {
        return Err(invalid("hosts (at most 8)", format!("{hosts:?}")));
    }
    for host in hosts {
        if host.is_empty()
            || !host.split('.').all(|label| {
                !label.is_empty()
                    && label.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
                    && label.ends_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            })
        {
            return Err(invalid("host", format!("{host:?}")));
        }
    }
    if !hosts.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(invalid(
            "hosts (must be sorted and unique)",
            format!("{hosts:?}"),
        ));
    }
    match (
        hosts.is_empty(),
        &settings.auth_header,
        &settings.auth_scheme,
    ) {
        (true, None, None) => {}
        (false, Some(header), Some(scheme)) => {
            if !valid_provider_header_name(header) {
                return Err(invalid("auth_header", format!("{header:?}")));
            }
            if !matches!(scheme.as_str(), "bearer" | "raw") {
                return Err(invalid("auth_scheme", format!("{scheme:?}")));
            }
        }
        _ => {
            return Err(invalid(
                "hosts/auth (must be given together)",
                format!("{settings:?}"),
            ))
        }
    }
    if let Some(id) = &settings.fusiform_provider_id {
        if !crate::fusiform_providers::fusiform_providers()
            .iter()
            .any(|provider| provider.id == *id)
        {
            return Err(invalid("fusiform_provider_id", format!("{id:?}")));
        }
    }
    Ok(())
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
    if service.contains("-gw-") || !crate::credential_id::valid_api_key_service_name(service) {
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
    let descriptor_columns =
        if read_schema_version(conn)? >= REGISTERED_PROVIDER_DESCRIPTOR_SCHEMA_VERSION {
            "hosts_json, auth_header, auth_scheme, fusiform_provider_id"
        } else {
            "'[]', NULL, NULL, NULL"
        };
    let mut stmt = conn.prepare(&format!(
        "SELECT service, categories_json, provider_ids_json, created_at_ms, {descriptor_columns} \
         FROM registered_providers ORDER BY service",
    ))?;
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
            hosts: decode(4)?,
            auth_header: row.get(5)?,
            auth_scheme: row.get(6)?,
            fusiform_provider_id: row.get(7)?,
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

    /// Change category and routing defaults for future keys, preserving the descriptor.
    pub fn set_registered_provider_audited(
        &self,
        service: &str,
        categories: &[String],
        provider_ids: &[String],
        ctx: AuditCtx<'_>,
    ) -> Result<bool, StoreOpError> {
        self.set_registered_provider_settings_audited(service, categories, provider_ids, None, ctx)
    }

    /// Categories and routes are defaults for future keys only. Hosts, auth and the
    /// Fusiform id describe the provider for all its keys, projected at read time.
    /// Absent settings preserve the descriptor for legacy callers; present settings
    /// replace it completely. The registration and audit entry commit together.
    pub fn set_registered_provider_settings_audited(
        &self,
        service: &str,
        categories: &[String],
        provider_ids: &[String],
        settings: Option<&RegisteredProviderSettings>,
        ctx: AuditCtx<'_>,
    ) -> Result<bool, StoreOpError> {
        validate_registered_provider_service(service)?;
        let empty = RegisteredProviderSettings::default();
        validate_registered_provider_settings(settings.unwrap_or(&empty))?;
        if categories.iter().any(|category| {
            !crate::catalog::CredentialCategory::ALL
                .iter()
                .any(|known| known.as_str() == category)
        }) {
            return Err(StoreOpError::InvalidCategoryName);
        }
        crate::provider_ids::check_provider_ids(provider_ids)?;
        crate::provider_ids::check_reserved_provider_ids(provider_ids)?;
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
        let replacement = settings.unwrap_or(&empty);
        let hosts_json = serde_json::to_string(&replacement.hosts)
            .map_err(|error| StoreOpError::Encode(error.to_string()))?;
        self.fenced_write(|tx| {
            let changed = tx.execute(
                "INSERT INTO registered_providers (service, categories_json, provider_ids_json, created_at_ms, hosts_json, auth_header, auth_scheme, fusiform_provider_id) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) ON CONFLICT(service) DO UPDATE SET \
                 categories_json = excluded.categories_json, provider_ids_json = excluded.provider_ids_json, \
                 hosts_json = CASE WHEN ?9 THEN excluded.hosts_json ELSE hosts_json END, \
                 auth_header = CASE WHEN ?9 THEN excluded.auth_header ELSE auth_header END, \
                 auth_scheme = CASE WHEN ?9 THEN excluded.auth_scheme ELSE auth_scheme END, \
                 fusiform_provider_id = CASE WHEN ?9 THEN excluded.fusiform_provider_id ELSE fusiform_provider_id END \
                 WHERE categories_json != excluded.categories_json OR provider_ids_json != excluded.provider_ids_json \
                 OR (?9 AND (hosts_json != excluded.hosts_json OR auth_header IS NOT excluded.auth_header \
                     OR auth_scheme IS NOT excluded.auth_scheme OR fusiform_provider_id IS NOT excluded.fusiform_provider_id))",
                rusqlite::params![service, categories_json, provider_ids_json, now_ms(), hosts_json,
                    replacement.auth_header, replacement.auth_scheme, replacement.fusiform_provider_id, settings.is_some()],
            )?;
            if changed > 0 {
                let (hosts, header, scheme, fusiform): (String, Option<String>, Option<String>, Option<String>) = tx.query_row(
                    "SELECT hosts_json, auth_header, auth_scheme, fusiform_provider_id FROM registered_providers WHERE service = ?1",
                    [service], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )?;
                let hosts: Vec<String> = serde_json::from_str(&hosts).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(error))
                })?;
                append_audit_tx(tx, &self.audit_key, &AuditRecord {
                    op: ctx.op,
                    credential_id: Some(format!("provider:{service}|{}|{}|{}|{}|{}|{}", categories.join(","), provider_ids.join(","), hosts.join(","), header.unwrap_or_default(), scheme.unwrap_or_default(), fusiform.unwrap_or_default())),
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

    fn descriptor() -> RegisteredProviderSettings {
        RegisteredProviderSettings {
            hosts: vec!["api.example.com".into()],
            auth_header: Some("authorization".into()),
            auth_scheme: Some("bearer".into()),
            fusiform_provider_id: None,
        }
    }

    #[test]
    fn registered_provider_descriptor_migration_upgrades_existing_rows() {
        let (root, sqlite) = taxonomy_tests::sqlite("registered-descriptor-migration", 194);
        migrate_through_for_test(&sqlite, REGISTERED_PROVIDER_DESCRIPTOR_SCHEMA_VERSION - 1)
            .unwrap();
        sqlite.with_conn(|conn| conn.execute(
            "INSERT INTO registered_providers VALUES ('custom', '[\"web-search\"]', '[\"custom\"]', 123)", [],
        )).unwrap();
        let path = root.join("store.db");
        let before = registered_providers_read_only(&path).unwrap();
        assert_eq!(before.len(), 1);
        let store = EncryptedStore::open(sqlite, MasterKey::from_bytes([194; 32])).unwrap();
        EncryptedStore::migrate(&store.store).unwrap();
        let after = store.registered_providers().unwrap();
        assert_eq!(after, before);
        assert_eq!(after[0].categories, ["web-search"]);
        assert_eq!(after[0].provider_ids, ["custom"]);
        assert_eq!(after[0].created_at_ms, 123);
        assert!(after[0].hosts.is_empty());
        assert_eq!(after[0].auth_header, None);
        assert_eq!(after[0].auth_scheme, None);
        assert_eq!(after[0].fusiform_provider_id, None);
        assert_eq!(registered_providers_read_only(&path).unwrap(), after);
        let columns = store
            .store
            .with_conn(|conn| {
                let mut stmt = conn.prepare("PRAGMA table_info(registered_providers)")?;
                let columns = stmt
                    .query_map([], |row| {
                        Ok((
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, bool>(3)?,
                            row.get::<_, Option<String>>(4)?,
                        ))
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(columns)
            })
            .unwrap();
        assert_eq!(
            columns,
            vec![
                ("service".into(), "TEXT".into(), false, None),
                ("categories_json".into(), "TEXT".into(), true, None),
                ("provider_ids_json".into(), "TEXT".into(), true, None),
                ("created_at_ms".into(), "INTEGER".into(), true, None),
                (
                    "hosts_json".into(),
                    "TEXT".into(),
                    true,
                    Some("'[]'".into())
                ),
                (
                    "auth_header".into(),
                    "TEXT".into(),
                    false,
                    Some("NULL".into())
                ),
                (
                    "auth_scheme".into(),
                    "TEXT".into(),
                    false,
                    Some("NULL".into())
                ),
                (
                    "fusiform_provider_id".into(),
                    "TEXT".into(),
                    false,
                    Some("NULL".into())
                ),
            ]
        );
    }

    #[test]
    fn registered_provider_descriptor_changes_write_and_audit_every_column() {
        let (_root, store) = taxonomy_tests::rig("registered-descriptor-audit", 195);
        let mut settings = descriptor();
        let set = |settings: &RegisteredProviderSettings, categories: &[String], ids: &[String]| {
            store
                .set_registered_provider_settings_audited(
                    "custom",
                    categories,
                    ids,
                    Some(settings),
                    AuditCtx::admin(AuditOp::ProviderSet),
                )
                .unwrap()
        };
        assert!(set(&settings, &["web-search".into()], &["custom".into()]));
        settings.hosts = vec!["other.example.com".into()];
        assert!(set(&settings, &["web-search".into()], &["custom".into()]));
        assert_eq!(
            store
                .read_audit(None)
                .unwrap()
                .last()
                .unwrap()
                .credential_id
                .as_deref(),
            Some("provider:custom|web-search|custom|other.example.com|authorization|bearer|")
        );
        let tip = store.audit_tip().unwrap();
        assert!(!set(&settings, &["web-search".into()], &["custom".into()]));
        assert_eq!(store.audit_tip().unwrap(), tip);
        settings.auth_header = Some("x-api-key".into());
        assert!(set(&settings, &["web-search".into()], &["custom".into()]));
        settings.auth_scheme = Some("raw".into());
        assert!(set(&settings, &["web-search".into()], &["custom".into()]));
        assert!(set(
            &settings,
            &["media-provider".into()],
            &["custom".into()]
        ));
        assert!(set(
            &settings,
            &["media-provider".into()],
            &["other".into()]
        ));
        // A future binary may have stored an id; the legacy path must keep it,
        // and a complete replacement must be able to clear it.
        store
            .store
            .with_conn(|conn| {
                conn.execute(
                    "UPDATE registered_providers SET fusiform_provider_id = 'future'",
                    [],
                )
            })
            .unwrap();
        store
            .set_registered_provider_audited(
                "custom",
                &[],
                &[],
                AuditCtx::admin(AuditOp::ProviderSet),
            )
            .unwrap();
        assert_eq!(
            store.registered_providers().unwrap()[0]
                .fusiform_provider_id
                .as_deref(),
            Some("future")
        );
        assert!(set(&settings, &[], &[]));
        assert_eq!(
            store.registered_providers().unwrap()[0].fusiform_provider_id,
            None
        );
        assert!(set(&RegisteredProviderSettings::default(), &[], &[]));
        assert_eq!(
            store
                .read_audit(None)
                .unwrap()
                .last()
                .unwrap()
                .credential_id
                .as_deref(),
            Some("provider:custom||||||")
        );
        assert_eq!(store.verify_audit_chain().unwrap(), None);
    }

    #[test]
    fn registered_provider_hosts_accept_eight_and_refuse_nine() {
        let (_root, store) = taxonomy_tests::rig("registered-host-cap", 196);
        let mut settings = descriptor();
        settings.hosts = (0..8).map(|i| format!("h{i}.example.com")).collect();
        let set = |s: &RegisteredProviderSettings| {
            store.set_registered_provider_settings_audited(
                "custom",
                &[],
                &[],
                Some(s),
                AuditCtx::admin(AuditOp::ProviderSet),
            )
        };
        assert!(set(&settings).unwrap());
        let before = store.registered_providers().unwrap();
        let tip = store.audit_tip().unwrap();
        settings.hosts.push("h8.example.com".into());
        assert!(set(&settings)
            .unwrap_err()
            .to_string()
            .contains("h8.example.com"));
        assert_eq!(store.registered_providers().unwrap(), before);
        assert_eq!(store.audit_tip().unwrap(), tip);
    }

    #[test]
    fn registered_provider_descriptor_refusals_name_values_and_do_not_write() {
        let (_root, store) = taxonomy_tests::rig("registered-descriptor-invalid", 197);
        let set = |s: &RegisteredProviderSettings| {
            store.set_registered_provider_settings_audited(
                "custom",
                &[],
                &[],
                Some(s),
                AuditCtx::admin(AuditOp::ProviderSet),
            )
        };
        let mut bad = Vec::new();
        for host in [
            "",
            "API.example.com",
            "https://api.example.com",
            "api.example.com:443",
            "api.example.com/path",
            "*.example.com",
            "api.example.com.",
            "api..example.com",
            "-api.example.com",
            "api-.example.com",
            "é.example.com",
        ] {
            let mut s = descriptor();
            s.hosts = vec![host.into()];
            bad.push((s, format!("{host:?}")));
        }
        for hosts in [
            vec!["b.example.com", "a.example.com"],
            vec!["a.example.com", "a.example.com"],
        ] {
            let mut s = descriptor();
            s.hosts = hosts.into_iter().map(str::to_owned).collect();
            bad.push((s, "a.example.com".into()));
        }
        for header in [
            "",
            "Authorization",
            "x api key",
            "x-api-key:",
            "x-api-key\n",
        ] {
            let mut s = descriptor();
            s.auth_header = Some(header.into());
            bad.push((s, format!("{header:?}")));
        }
        for scheme in ["", "Bearer", "basic"] {
            let mut s = descriptor();
            s.auth_scheme = Some(scheme.into());
            bad.push((s, format!("{scheme:?}")));
        }
        for missing in 0..4 {
            let mut s = descriptor();
            match missing {
                0 => s.hosts.clear(),
                1 => s.auth_header = None,
                2 => s.auth_scheme = None,
                _ => {
                    s.auth_header = None;
                    s.auth_scheme = None;
                }
            }
            bad.push((
                s,
                if missing == 0 {
                    "authorization"
                } else {
                    "api.example.com"
                }
                .into(),
            ));
        }
        let tip = store.audit_tip().unwrap();
        for (s, value) in bad {
            let preflight = validate_registered_provider_settings(&s)
                .unwrap_err()
                .to_string();
            assert!(preflight.contains(&value), "{preflight} must name {value}");
            assert_eq!(set(&s).unwrap_err().to_string(), preflight);
        }
        assert!(store.registered_providers().unwrap().is_empty());
        assert_eq!(store.audit_tip().unwrap(), tip);
    }

    #[test]
    fn registered_provider_fusiform_ids_accept_published_values_and_refuse_unknown_unchanged() {
        let (_root, store) = taxonomy_tests::rig("registered-fusiform", 198);
        let set = |settings: &RegisteredProviderSettings| {
            store.set_registered_provider_settings_audited(
                "custom",
                &[],
                &[],
                Some(settings),
                AuditCtx::admin(AuditOp::ProviderSet),
            )
        };
        let mut settings = RegisteredProviderSettings::default();
        for provider in crate::fusiform_providers::fusiform_providers() {
            settings.fusiform_provider_id = Some(provider.id.clone());
            validate_registered_provider_settings(&settings).unwrap();
        }
        settings.fusiform_provider_id = Some("openai".into());
        assert!(set(&settings).unwrap());
        assert_eq!(
            store.registered_providers().unwrap()[0]
                .fusiform_provider_id
                .as_deref(),
            Some("openai")
        );
        assert!(!set(&settings).unwrap());
        settings.fusiform_provider_id = Some("anthropic".into());
        assert!(set(&settings).unwrap(), "an id-only change must write");
        let before = store.registered_providers().unwrap();
        let tip = store.audit_tip().unwrap();
        for id in ["unavailable-provider", "", "OpenAI", " openai "] {
            settings.fusiform_provider_id = Some(id.into());
            let preflight = validate_registered_provider_settings(&settings)
                .unwrap_err()
                .to_string();
            assert!(preflight.contains(&format!("{id:?}")), "{preflight}");
            assert_eq!(set(&settings).unwrap_err().to_string(), preflight);
            assert_eq!(store.registered_providers().unwrap(), before);
        }
        assert_eq!(store.audit_tip().unwrap(), tip);
        settings.fusiform_provider_id = None;
        assert!(set(&settings).unwrap());
        assert_eq!(
            store.registered_providers().unwrap()[0].fusiform_provider_id,
            None
        );
    }

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
        // The migrate above runs to the newest step, so it must cross the descriptor
        // step this module adds. Later steps may follow it.
        assert!(newest_migration_version() >= REGISTERED_PROVIDER_DESCRIPTOR_SCHEMA_VERSION);
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
