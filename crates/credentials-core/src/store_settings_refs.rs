//! An approved settings snapshot stays with its bind. The persisted list is inventory only.

use super::*;

const MAX_SETTINGS_REFS: usize = 32;
const MAX_SETTINGS_REF_BYTES: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingsRefSet {
    module_id: String,
    generation: u64,
    refs: Vec<String>,
}

impl SettingsRefSet {
    /// Reject a malformed member as a whole, including one that is too long before deduplication.
    pub fn new(module_id: &str, generation: u64, refs: &[String]) -> Option<Self> {
        if module_id.is_empty()
            || module_id.contains('|')
            || refs.len() > MAX_SETTINGS_REFS
            || refs.iter().any(|id| {
                !(1..=MAX_SETTINGS_REF_BYTES).contains(&id.len())
                    || !id.bytes().all(|byte| byte.is_ascii_graphic())
            })
        {
            return None;
        }
        let mut refs = refs.to_vec();
        refs.sort_unstable();
        refs.dedup();
        Some(Self {
            module_id: module_id.into(),
            generation,
            refs,
        })
    }

    pub fn module_id(&self) -> &str {
        &self.module_id
    }

    pub fn refs(&self) -> &[String] {
        &self.refs
    }

    fn refs_json(&self) -> String {
        serde_json::to_string(&self.refs).expect("a list of strings encodes as JSON")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingsRefRecord {
    pub set: SettingsRefSet,
    pub seen_at_ms: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SettingsRefListing {
    pub rows: Vec<SettingsRefRecord>,
    pub incomplete: bool,
}

/// The exact local record whose kind was checked for a settings-only read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingsReadPin {
    pub incarnation: String,
    pub record_version: u64,
}

impl SettingsReadPin {
    pub fn matches(&self, incarnation: &str, record_version: u64) -> bool {
        self.incarnation == incarnation && self.record_version == record_version
    }
}

impl EncryptedStore {
    pub(super) fn settings_read_pin(
        &self,
        conn: &rusqlite::Connection,
        credential_id: &str,
    ) -> rusqlite::Result<Option<SettingsReadPin>> {
        let row = conn.query_row(
            "SELECT incarnation, record_version, envelope FROM credentials WHERE credential_id = ?1",
            [credential_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, u64>(1)?, row.get::<_, Vec<u8>>(2)?)),
        ).optional()?;
        let Some((incarnation, record_version, blob)) = row else {
            return Ok(None);
        };
        // Kind is authenticated inside the envelope. Inspect it without changing record
        // state: the caller has not yet been authorized to use the record.
        let kind = open_credential_envelope(
            &self.key,
            &blob,
            &RecordBinding {
                credential_id,
                record_version,
            },
        )
        .ok()
        .and_then(|plaintext| VaultRecord::decode(&plaintext).ok())
        .map(|record| record.kind);
        Ok(
            (kind == Some(CredentialKind::ApiKey)).then_some(SettingsReadPin {
                incarnation,
                record_version,
            }),
        )
    }

    /// Persist a change and its audit row before making the admitted bind usable.
    pub fn record_settings_refs_seen(&self, set: &SettingsRefSet) -> Result<bool, StoreOpError> {
        // SQLite INTEGER is signed; decimal text preserves the full storage u64.
        let generation = set.generation.to_string();
        let refs_json = set.refs_json();
        let refs_sha256 = sha256_hex_of_bytes(refs_json.as_bytes());
        Ok(self.fenced_write(|tx| {
            let changed = tx.execute(
                "INSERT INTO settings_ref_sets (module_id, generation, refs_json, refs_sha256, seen_at_ms) \
                 VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT(module_id) DO UPDATE SET \
                 generation = excluded.generation, refs_json = excluded.refs_json, \
                 refs_sha256 = excluded.refs_sha256, seen_at_ms = excluded.seen_at_ms \
                 WHERE settings_ref_sets.generation != excluded.generation \
                    OR settings_ref_sets.refs_json != excluded.refs_json",
                rusqlite::params![set.module_id, generation, refs_json, refs_sha256, now_ms()],
            )?;
            if changed == 0 {
                return Ok(false);
            }
            append_audit_tx(tx, &self.audit_key, &AuditRecord {
                op: AuditOp::SettingsRefsSeen,
                credential_id: Some(format!("settings_refs|{generation}")),
                payload_hash: Some(refs_sha256),
                actor: format!("reserved:{}", set.module_id),
                alarm: None,
            })?;
            Ok(true)
        })?)
    }

    pub fn list_settings_ref_sets(&self) -> Result<SettingsRefListing, StoreOpError> {
        self.store
            .with_conn(settings_ref_sets_from_conn)
            .map_err(Into::into)
    }
}

fn settings_ref_sets_from_conn(
    conn: &rusqlite::Connection,
) -> rusqlite::Result<SettingsRefListing> {
    let mut listing = SettingsRefListing::default();
    if read_schema_version(conn)? < SETTINGS_REFS_SCHEMA_VERSION {
        return Ok(listing);
    }
    let mut stmt = conn.prepare(
        "SELECT module_id, generation, refs_json, refs_sha256, seen_at_ms FROM settings_ref_sets ORDER BY module_id",
    )?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let module_id: String = row.get(0)?;
        let generation: String = row.get(1)?;
        let refs_json: String = row.get(2)?;
        let refs_sha256: String = row.get(3)?;
        let (Ok(generation), Ok(refs)) = (
            generation.parse(),
            serde_json::from_str::<Vec<String>>(&refs_json),
        ) else {
            listing.incomplete = true;
            continue;
        };
        let Some(set) = SettingsRefSet::new(&module_id, generation, &refs) else {
            listing.incomplete = true;
            continue;
        };
        if set.refs_json() != refs_json || sha256_hex_of_bytes(refs_json.as_bytes()) != refs_sha256
        {
            listing.incomplete = true;
            continue;
        }
        listing.rows.push(SettingsRefRecord {
            set,
            seen_at_ms: row.get(4)?,
        });
    }
    Ok(listing)
}

/// Read the last-seen inventory without taking the daemon's writer lease.
pub fn settings_ref_sets_read_only(path: &std::path::Path) -> Result<SettingsRefListing, String> {
    if !path.exists() {
        return Ok(SettingsRefListing::default());
    }
    let conn =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|error| error.to_string())?;
    settings_ref_sets_from_conn(&conn).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::taxonomy_tests::rig;

    #[test]
    fn settings_refs_accept_boundary_counts_and_id_lengths() {
        let module = "test-module";
        let max_id = "~".repeat(256);
        let max = vec![max_id; 32];
        assert!(SettingsRefSet::new(module, 1, &max).is_some());
        assert!(SettingsRefSet::new(module, 1, &vec!["a".into(); 33]).is_none());
        assert!(SettingsRefSet::new(module, 1, &["!".into()]).is_some());
        for invalid in [
            String::new(),
            "a b".into(),
            "a\n".into(),
            "é".into(),
            "a".repeat(257),
        ] {
            assert!(SettingsRefSet::new(module, 1, &["valid".into(), invalid]).is_none());
        }
    }

    #[test]
    fn settings_refs_cover_only_current_api_keys_for_the_named_module_and_read() {
        let (_root, store) = rig("settings-refs-coverage", 222);
        let picked = "picked-key";
        let wrong_kind = "apikey:synthetic-signing";
        let uncovered = "uncovered-key";
        let api = VaultRecord::new_static(CredentialKind::ApiKey, "test", vec![1], None);
        let signing = VaultRecord::new_static(CredentialKind::SigningKey, "test", vec![2], None);
        store.create(picked, &api).unwrap();
        store.create(uncovered, &api).unwrap();
        store.create(wrong_kind, &signing).unwrap();
        let refs = [
            picked.to_owned(),
            wrong_kind.to_owned(),
            "no-row".to_owned(),
        ];
        let authority = DeclaredGrantSet::empty().with_settings_refs(SettingsRefSet::new(
            "test-module",
            1,
            &refs,
        ));
        let covers = |kind, principal, id, op| {
            store
                .read_grant_covers(kind, principal, id, op, &authority)
                .unwrap()
        };
        assert!(covers(
            "reserved",
            "test-module",
            picked,
            GrantOperation::Read
        ));
        for id in [wrong_kind, uncovered, "no-row"] {
            assert!(!covers("reserved", "test-module", id, GrantOperation::Read));
        }
        for (kind, principal) in [("reserved", "other-module"), ("enrolled", "test-module")] {
            assert!(!covers(kind, principal, picked, GrantOperation::Read));
        }
        for operation in [
            GrantOperation::List,
            GrantOperation::Sign,
            GrantOperation::Open,
            GrantOperation::Seal,
            GrantOperation::Deposit,
            GrantOperation::AccountToken,
            GrantOperation::PolicyToken,
        ] {
            assert!(!covers("reserved", "test-module", picked, operation));
        }
        store
            .overwrite_unconditional_audited(picked, &signing, AuditCtx::admin(AuditOp::Overwrite))
            .unwrap();
        assert!(!covers(
            "reserved",
            "test-module",
            picked,
            GrantOperation::Read
        ));
        store
            .create_read_grant_audited(
                "reserved",
                "test-module",
                SelectorKind::Exact,
                picked,
                GrantOperation::Read,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .unwrap();
        assert!(covers(
            "reserved",
            "test-module",
            picked,
            GrantOperation::Read
        ));
    }

    #[test]
    fn settings_refs_seen_audits_only_changes_and_rolls_back_with_the_audit() {
        let (_root, store) = rig("settings-refs-seen", 221);
        let one = "apikey:synthetic-one".to_owned();
        let two = "apikey:synthetic-two".to_owned();
        let record = |generation, refs: &[String]| {
            let set = SettingsRefSet::new("test-module", generation, refs).unwrap();
            store.record_settings_refs_seen(&set)
        };
        assert!(record(u64::MAX - 1, &[two.clone(), one.clone()]).unwrap());
        assert!(!record(u64::MAX - 1, &[one.clone(), two.clone()]).unwrap());
        assert!(record(u64::MAX, &[one.clone(), two]).unwrap());
        assert!(record(u64::MAX, std::slice::from_ref(&one)).unwrap());
        assert!(!record(u64::MAX, std::slice::from_ref(&one)).unwrap());

        let stored = || {
            store.with_raw_conn(|conn| {
                conn.query_row(
                    "SELECT generation, refs_json, refs_sha256, seen_at_ms FROM settings_ref_sets WHERE module_id = 'test-module'",
                    [],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, i64>(3)?)),
                )
            }).unwrap()
        };
        let before = stored();
        assert_eq!(before.0, u64::MAX.to_string());
        assert_eq!(before.1, r#"["apikey:synthetic-one"]"#);
        assert_eq!(
            before.2,
            format!("{:x}", Sha256::digest(before.1.as_bytes()))
        );
        assert!(before.3 > 0);
        let audit_rows = || {
            store.with_raw_conn(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT actor, payload_hash FROM audit_log WHERE op = 'settings_refs_seen' ORDER BY seq",
                )?;
                let rows = stmt.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))?;
                rows.collect::<rusqlite::Result<Vec<_>>>()
            }).unwrap()
        };
        let pair_hash = format!(
            "{:x}",
            Sha256::digest(br#"["apikey:synthetic-one","apikey:synthetic-two"]"#),
        );
        let expected_audit = vec![
            ("reserved:test-module".to_owned(), pair_hash.clone()),
            ("reserved:test-module".to_owned(), pair_hash),
            ("reserved:test-module".to_owned(), before.2.clone()),
        ];
        assert_eq!(audit_rows(), expected_audit);
        store
            .with_raw_conn(|conn| {
                conn.execute_batch(
                    "CREATE TRIGGER refuse_settings_audit BEFORE INSERT ON audit_log \
             WHEN NEW.op = 'settings_refs_seen' BEGIN SELECT RAISE(ABORT, 'test refusal'); END;",
                )
            })
            .unwrap();
        assert!(record(u64::MAX, &[]).is_err());
        assert_eq!(stored(), before);
        assert_eq!(audit_rows(), expected_audit);
        assert_eq!(store.verify_audit_chain().unwrap(), None);
    }
}
