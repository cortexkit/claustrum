use std::collections::HashMap;

use super::{conditions::local_condition_conn, EncryptedStore, HomeWatchCandidate, StoreOpError};
use crate::{envelope, envelope::RecordBinding, record::RecordState, record::VaultRecord};

/// Non-secret decoded fields from the last scan of this store. State and conditions
/// are read anew even when the envelope's incarnation and version are unchanged.
#[derive(Default)]
pub struct HomeWatchCache {
    rows: HashMap<String, Cached>,
    #[cfg(test)]
    opens: usize,
}

struct Cached {
    incarnation: String,
    version: u64,
    decoded: Option<HomeWatchCandidate>,
}

impl EncryptedStore {
    pub fn home_watch_candidates_cached(
        &self,
        cache: &mut HomeWatchCache,
    ) -> Result<Vec<HomeWatchCandidate>, StoreOpError> {
        Ok(self.store.with_read(|conn| {
            let mut stmt = conn.prepare(
                "SELECT credential_id, state, record_version, envelope, incarnation FROM credentials \
                 WHERE state IN ('active', 'needs_reauth') ORDER BY credential_id",
            )?;
            let mut rows = stmt.query([])?;
            let mut retained = HashMap::new();
            let mut candidates = Vec::new();
            while let Some(row) = rows.next()? {
                let id: String = row.get(0)?;
                let incarnation: String = row.get(4)?;
                let version = row.get::<_, i64>(2)? as u64;
                let state = RecordState::from_str(&row.get::<_, String>(1)?);
                let entry = match cache.rows.remove(&id) {
                    Some(entry) if entry.incarnation == incarnation && entry.version == version => entry,
                    _ => {
                        #[cfg(test)]
                        { cache.opens += 1; }
                        // Match home_watch_candidates_from_conn: skip unreadable envelopes and
                        // records without the quarantine side effect of a credential read.
                        let decoded = envelope::open(
                            &self.key,
                            &row.get::<_, Vec<u8>>(3)?,
                            &RecordBinding { credential_id: &id, record_version: version },
                        )
                        .ok()
                        .and_then(|plain| VaultRecord::decode(&plain).ok())
                        .map(|record| HomeWatchCandidate {
                            is_refreshable: record.is_refreshable(),
                            credential_id: id.clone(),
                            record_version: version,
                            state,
                            kind: record.kind,
                            refresh_adapter: record.refresh_adapter,
                            identity: record.identity,
                            detected_plan: record.detected_plan,
                            condition: None,
                        });
                        Cached { incarnation, version, decoded }
                    }
                };
                if let Some(mut candidate) = entry.decoded.clone() {
                    candidate.state = state;
                    candidate.condition = local_condition_conn(conn, &id, &entry.incarnation)?;
                    candidates.push(candidate);
                }
                retained.insert(id, entry);
            }
            cache.rows = retained;
            Ok(candidates)
        })?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{AuditCtx, AuditOp};
    use crate::{key::MasterKey, test_support::TestTempDir};
    use cortexkit_store::{open_sqlite, Isolation, StorageBackend, StorageDescriptor};

    #[test]
    fn cached_home_watch_matches_the_decoder_and_only_opens_changed_rows() {
        let root = TestTempDir::new(format!("home-watch-cache-{}", std::process::id()));
        let raw = open_sqlite(&StorageDescriptor {
            module_id: "claustrum".into(),
            storage_namespace: "vault".into(),
            isolation: Isolation::Module,
            backend: StorageBackend::Sqlite {
                path: root.join("store.db").to_string_lossy().into_owned(),
            },
        })
        .unwrap();
        EncryptedStore::migrate(&raw).unwrap();
        let store = EncryptedStore::open(raw, MasterKey::from_bytes([194; 32])).unwrap();
        let record = VaultRecord::new_static(
            crate::record::CredentialKind::ApiKey,
            "watch",
            b"payload".to_vec(),
            None,
        );
        for id in ["active", "needs", "broken"] {
            store.create(id, &record).unwrap();
        }
        store.invalidate("needs").unwrap();
        store
            .with_raw_conn(|conn| {
                conn.execute(
                    "UPDATE credentials SET envelope = X'00' WHERE credential_id = 'broken'",
                    [],
                )
            })
            .unwrap();

        let mut cache = HomeWatchCache::default();
        let first = store.home_watch_candidates_cached(&mut cache).unwrap();
        assert_eq!(first, store.home_watch_candidates().unwrap());
        assert_eq!(
            first
                .iter()
                .map(|row| (row.credential_id.as_str(), row.state))
                .collect::<Vec<_>>(),
            [
                ("active", RecordState::Active),
                ("needs", RecordState::NeedsReauth)
            ]
        );
        assert_eq!(store.meta("broken").unwrap().state, RecordState::Active);
        assert_eq!(cache.opens, 3);
        assert_eq!(
            store.home_watch_candidates_cached(&mut cache).unwrap(),
            first
        );
        assert_eq!(
            cache.opens, 3,
            "an unchanged scan must not open any envelopes"
        );

        store
            .overwrite_unconditional_audited("active", &record, AuditCtx::admin(AuditOp::Put))
            .unwrap();
        let updated = store.home_watch_candidates_cached(&mut cache).unwrap();
        assert_eq!(updated, store.home_watch_candidates().unwrap());
        assert_eq!(updated[0].record_version, first[0].record_version + 1);
        assert_eq!(cache.opens, 4);
    }
}
