//! Organization metadata learned for one version of a local API key.

use super::*;
use crate::secret::SecretBytes;

pub(super) const ORG_ID_COLUMN: &str = "(SELECT org_id FROM credential_orgs AS org \
    WHERE org.credential_id = credentials.credential_id \
      AND org.record_version = credentials.record_version \
      AND org.incarnation = credentials.incarnation)";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct OrgProbeTarget {
    pub credential_id: String,
    pub record_version: u64,
    pub incarnation: String,
}

impl EncryptedStore {
    /// List active candidates without opening their secrets. The daemon selects the
    /// candidates for which the catalog declares an organization probe.
    pub fn org_probe_targets(&self) -> Result<Vec<OrgProbeTarget>, StoreOpError> {
        Ok(self.store.with_conn(|conn| {
            let mut stmt = conn.prepare(&format!(
                "SELECT credential_id, record_version, incarnation FROM credentials \
                 WHERE state = 'active' AND {ORG_ID_COLUMN} IS NULL \
                   AND NOT EXISTS (SELECT 1 FROM credential_gateway_settings AS g \
                                   WHERE g.credential_id = credentials.credential_id) \
                 ORDER BY credential_id"
            ))?;
            let rows = stmt.query_map([], |row| {
                Ok(OrgProbeTarget {
                    credential_id: row.get(0)?,
                    record_version: row.get(1)?,
                    incarnation: row.get(2)?,
                })
            })?;
            rows.collect()
        })?)
    }

    /// Read only the key that the scan admitted. Never send gateway keys to a catalog
    /// endpoint, or quarantine a record as a side effect of learning its metadata.
    pub fn org_probe_key(
        &self,
        target: &OrgProbeTarget,
    ) -> Result<Option<SecretBytes>, StoreOpError> {
        let blob: Option<Vec<u8>> = self.store.with_conn(|conn| {
            conn.query_row(
                &format!(
                    "SELECT envelope FROM credentials WHERE credential_id = ?1 \
                       AND record_version = ?2 AND incarnation = ?3 AND state = 'active' \
                       AND {ORG_ID_COLUMN} IS NULL \
                       AND NOT EXISTS (SELECT 1 FROM credential_gateway_settings AS g \
                                       WHERE g.credential_id = credentials.credential_id)"
                ),
                rusqlite::params![
                    target.credential_id,
                    target.record_version,
                    target.incarnation
                ],
                |row| row.get(0),
            )
            .optional()
        })?;
        Ok(blob.and_then(|blob| {
            let binding = RecordBinding {
                credential_id: &target.credential_id,
                record_version: target.record_version,
            };
            let plaintext = envelope::open(&self.key, &blob, &binding).ok()?;
            let record = VaultRecord::decode(&plaintext).ok()?;
            (record.kind == CredentialKind::ApiKey).then_some(record.payload)
        }))
    }

    /// Commit the first observation only if the same active key still exists.
    /// The metadata and its audit row commit together, without writing the credential.
    pub fn learn_org(
        &self,
        target: &OrgProbeTarget,
        org_id: &str,
        observed_at_ms: i64,
    ) -> Result<bool, StoreOpError> {
        if !crate::record::is_valid_org_id(org_id) {
            return Ok(false);
        }
        Ok(self.fenced_write(|tx| {
            let inserted = tx.execute(
                "INSERT INTO credential_orgs (credential_id, record_version, incarnation, org_id, observed_at_ms) \
                 SELECT credential_id, record_version, incarnation, ?4, ?5 FROM credentials \
                 WHERE credential_id = ?1 AND record_version = ?2 AND incarnation = ?3 AND state = 'active' \
                 ON CONFLICT (credential_id) DO UPDATE SET record_version = excluded.record_version, \
                     incarnation = excluded.incarnation, org_id = excluded.org_id, observed_at_ms = excluded.observed_at_ms \
                 WHERE credential_orgs.record_version != excluded.record_version \
                    OR credential_orgs.incarnation != excluded.incarnation",
                rusqlite::params![target.credential_id, target.record_version, target.incarnation, org_id, observed_at_ms],
            )?;
            if inserted != 0 {
                append_audit_tx(tx, &self.audit_key, &AuditRecord {
                    op: AuditOp::LearnOrg,
                    credential_id: Some(target.credential_id.clone()),
                    payload_hash: Some(hex32(&audit::payload_fingerprint(&self.audit_key, org_id.as_bytes()))),
                    actor: "daemon".into(),
                    alarm: None,
                })?;
            }
            Ok(inserted != 0)
        })?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::taxonomy_tests::{api_record, rig};

    const ID: &str = "apikey:anthropic:work";

    fn target(store: &EncryptedStore) -> OrgProbeTarget {
        let targets = store.org_probe_targets().unwrap();
        assert_eq!(targets.len(), 1);
        targets.into_iter().next().unwrap()
    }

    fn side_rows(store: &EncryptedStore) -> Vec<(String, i64)> {
        store
            .with_raw_conn(|conn| {
                let mut stmt =
                    conn.prepare("SELECT org_id, observed_at_ms FROM credential_orgs")?;
                let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
                rows.collect()
            })
            .unwrap()
    }

    fn listed_org(store: &EncryptedStore, principal: &str) -> Option<String> {
        let snapshot = store
            .list_scoped_snapshot("reserved", principal, &DeclaredGrantSet::empty())
            .unwrap();
        assert_eq!(snapshot.rows.len(), 1);
        snapshot.rows[0].org_id.clone()
    }

    #[test]
    fn learned_org_is_one_audited_observation_and_only_identity_callers_see_it() {
        let (_root, store) = rig("learned-org", 72);
        store.create(ID, &api_record()).unwrap();
        for (principal, op) in [
            ("reader", GrantOperation::Read),
            ("list", GrantOperation::List),
            ("signer", GrantOperation::Sign),
        ] {
            store
                .create_read_grant_audited(
                    "reserved",
                    principal,
                    SelectorKind::Exact,
                    ID,
                    op,
                    AuditCtx::admin(AuditOp::GrantCreate),
                )
                .unwrap();
        }
        let key = target(&store);
        let before = store.get_with_stale_pending_and_digest(ID).unwrap();
        let audit = store.read_audit(None).unwrap();

        assert!(store.learn_org(&key, "org-a", 123).unwrap());
        assert!(!store.learn_org(&key, "org-b", 456).unwrap());
        assert_eq!(side_rows(&store), [("org-a".into(), 123)]);
        for principal in ["reader", "list"] {
            assert_eq!(listed_org(&store, principal).as_deref(), Some("org-a"));
        }
        assert_eq!(listed_org(&store, "signer"), None);
        let after = store.get_with_stale_pending_and_digest(ID).unwrap();
        assert_eq!(before.stored_digest_hex, after.stored_digest_hex);
        assert_eq!(before.record.record_version, after.record.record_version);
        let entries = store.read_audit(None).unwrap();
        assert_eq!(entries.len(), audit.len() + 1);
        assert_eq!(entries.last().unwrap().op, "learn_org");
        assert_eq!(entries[..audit.len()], audit);
        assert_eq!(store.verify_audit_chain().unwrap(), None);
    }

    #[test]
    fn replacement_and_removal_erase_learned_orgs() {
        let (_root, store) = rig("org-remove-replace", 73);
        let record = api_record();
        store.create(ID, &record).unwrap();
        store
            .create_read_grant_audited(
                "reserved",
                "reader",
                SelectorKind::Exact,
                ID,
                GrantOperation::List,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .unwrap();
        assert!(store.learn_org(&target(&store), "org-old", 123).unwrap());
        store
            .overwrite_unconditional_audited(ID, &record, AuditCtx::admin(AuditOp::Overwrite))
            .unwrap();
        assert!(side_rows(&store).is_empty());
        assert_eq!(listed_org(&store, "reader"), None);

        assert!(store
            .learn_org(&target(&store), "org-replacement", 456)
            .unwrap());
        store
            .remove_audited(ID, AuditCtx::admin(AuditOp::Remove))
            .unwrap();
        assert!(side_rows(&store).is_empty());
        store.create(ID, &record).unwrap();
        assert_eq!(listed_org(&store, "reader"), None);
    }

    #[test]
    fn stale_org_observation_does_not_write_or_audit() {
        let (_root, store) = rig("org-fence", 74);
        let record = api_record();
        store.create(ID, &record).unwrap();
        let old = target(&store);
        store
            .overwrite_unconditional_audited(ID, &record, AuditCtx::admin(AuditOp::Overwrite))
            .unwrap();
        assert!(target(&store).record_version > old.record_version);
        let audit = store.read_audit(None).unwrap();
        assert!(!store.learn_org(&old, "org-old", 123).unwrap());
        assert!(side_rows(&store).is_empty());
        assert_eq!(store.read_audit(None).unwrap(), audit);

        store
            .remove_audited(ID, AuditCtx::admin(AuditOp::Remove))
            .unwrap();
        store.create(ID, &record).unwrap();
        let new = target(&store);
        assert_eq!(new.record_version, old.record_version);
        assert_ne!(new.incarnation, old.incarnation);
        let audit = store.read_audit(None).unwrap();
        assert!(!store.learn_org(&old, "org-old", 456).unwrap());
        assert!(side_rows(&store).is_empty());
        assert_eq!(store.read_audit(None).unwrap(), audit);
    }
}
