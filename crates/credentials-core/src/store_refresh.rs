//! Refresh intents, held plans, and permission observations.

use super::*;
use crate::refresh_adapters::github_app::GithubAppIdentity;

/// Delete a credential's refresh intent within an open transaction. Returns the
/// number of rows removed (0 if there was no intent). Used both standalone and as
/// the intent-clearing step folded into admin writes and the refresh commit.
pub(super) fn clear_intent_tx(
    tx: &rusqlite::Transaction,
    credential_id: &str,
) -> rusqlite::Result<usize> {
    tx.execute(
        "DELETE FROM refresh_intent WHERE credential_id = ?1",
        rusqlite::params![credential_id],
    )
}

/// Render a changed GitHub installation grant as two ordered entitlement sets. A scope
/// whose level changed appears in both sets, so the direction is visible without asking
/// an operator to reconstruct it from whole JSON blobs.
fn github_app_permissions_change_detail(
    previous: &BTreeMap<String, String>,
    current: &BTreeMap<String, String>,
) -> String {
    let removed: BTreeSet<String> = previous
        .iter()
        .filter(|(scope, level)| current.get(*scope) != Some(*level))
        .map(|(scope, level)| format!("{scope}:{level}"))
        .collect();
    let added: BTreeSet<String> = current
        .iter()
        .filter(|(scope, level)| previous.get(*scope) != Some(*level))
        .map(|(scope, level)| format!("{scope}:{level}"))
        .collect();
    format!(
        "added=[{}]; removed=[{}]",
        added.into_iter().collect::<Vec<_>>().join(","),
        removed.into_iter().collect::<Vec<_>>().join(",")
    )
}

/// Build a [`RefreshIntent`] from a row of the standard intent column projection.
fn row_to_intent(row: &rusqlite::Row<'_>) -> rusqlite::Result<RefreshIntent> {
    Ok(RefreshIntent {
        credential_id: row.get(0)?,
        record_version: row.get::<_, i64>(1)? as u64,
        old_refresh_hash: row.get(2)?,
        lease_epoch: row.get::<_, i64>(3)? as u64,
        started_at_ms: row.get(4)?,
    })
}

impl EncryptedStore {
    // ---- refresh intent log (crash-safe rotation) -----------------------

    /// Durably open a refresh intent (txn1 of the refresh state machine): the
    /// fsynced marker written BEFORE the provider's rotating endpoint is called.
    ///
    /// Goes through the fenced path so a superseded writer cannot open an intent,
    /// and (with `synchronous=FULL`) the row is on disk before this returns —
    /// guaranteeing a crash during the subsequent network call leaves a recoverable
    /// intent. `record_version` is the version being refreshed from (the commit's
    /// CAS guard); `old_refresh_hash` is [`refresh_token_hash`] of the current
    /// refresh token. The engine must check for an unresolved intent under its
    /// per-credential lock before calling this method, not overwrite a surviving
    /// intent after an unsuccessful commit.
    pub fn open_intent(
        &self,
        credential_id: &str,
        record_version: u64,
        old_refresh_hash: &str,
    ) -> Result<(), StoreOpError> {
        let epoch = self.store.epoch();
        let now = now_ms();
        self.fenced_write(|tx| {
            tx.execute(
                "INSERT INTO refresh_intent \
                 (credential_id, record_version, old_refresh_hash, lease_epoch, started_at_ms) \
                 VALUES (?1, ?2, ?3, ?4, ?5) \
                 ON CONFLICT(credential_id) DO UPDATE SET \
                   record_version = excluded.record_version, \
                   old_refresh_hash = excluded.old_refresh_hash, \
                   lease_epoch = excluded.lease_epoch, \
                   started_at_ms = excluded.started_at_ms",
                rusqlite::params![
                    credential_id,
                    record_version as i64,
                    old_refresh_hash,
                    epoch as i64,
                    now
                ],
            )?;
            Ok(())
        })
        .map_err(StoreOpError::from)
    }

    /// Commit a completed refresh (txn2): seal the new record at
    /// `expected_version + 1`, write it, and clear the intent — in ONE fenced,
    /// fsynced transaction, so the new tokens become visible AND the intent clears
    /// atomically, or neither does.
    ///
    /// Fails [`StoreOpError::CasMismatch`] if the stored row is no longer active
    /// at `expected_version` in `expected_incarnation`, and
    /// [`StoreOpError::Fenced`] if a newer instance took the lease mid-commit (the
    /// lease-handover race) — in which case NOTHING is applied and the caller must
    /// discard the staged tokens and not retry (reconciliation on the new owner
    /// resolves the still-dangling intent). The new `record_version` is returned.
    pub fn commit_refresh(
        &self,
        credential_id: &str,
        expected_version: u64,
        expected_incarnation: &str,
        new_record: &VaultRecord,
        github_app: Option<&GithubAppIdentity>,
    ) -> Result<u64, StoreOpError> {
        let next_version = expected_version.saturating_add(1);
        let mut new_record = new_record.clone();
        // The sealed tier of the row this commit replaces decides whether the tier's
        // first-seen time carries over. Read it without `get`, which refuses
        // non-active rows and quarantines unreadable ones: this read must neither write
        // nor change the refusal. Use the same version, incarnation and state as the update
        // so the tier is retained only from the record being replaced.
        let previous = self
            .store
            .with_conn(|conn| {
                conn.query_row(
                    "SELECT envelope FROM credentials \
                     WHERE credential_id = ?1 AND record_version = ?2 AND state = 'active' \
                       AND incarnation = ?3",
                    rusqlite::params![credential_id, expected_version as i64, expected_incarnation],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .optional()
            })?
            .and_then(|sealed| {
                envelope::open(
                    &self.key,
                    &sealed,
                    &RecordBinding {
                        credential_id,
                        record_version: expected_version,
                    },
                )
                .ok()
            })
            .and_then(|plain| VaultRecord::decode(&plain).ok());
        retain_detected_plan(&mut new_record, previous.as_ref());
        new_record.record_version = next_version;
        let blob = self.seal_record(credential_id, &new_record)?;
        let key_id_hex = self.key_id.to_hex();
        let now = now_ms();
        let audit_key = self.audit_key.clone();
        let payload_hash_hex = hex32(&audit::payload_fingerprint(
            &audit_key,
            new_record.payload.expose(),
        ));

        let (app_id, app_slug) = github_app.map_or((None, None), |app| {
            (Some(app.app_id.as_str()), Some(app.slug.as_str()))
        });
        let changed = self.fenced_write(|tx| {
            let n = tx.execute(
                "UPDATE credentials \
                  SET record_version = ?2, key_id = ?3, state = 'active', stale_pending = 0, \
                      envelope = ?4, updated_at_ms = ?5, \
                      github_app_id = COALESCE(?8, github_app_id), \
                      github_app_slug = COALESCE(?9, github_app_slug) \
                 WHERE credential_id = ?1 AND record_version = ?6 AND state = 'active' \
                   AND incarnation = ?7",
                rusqlite::params![
                    credential_id,
                    next_version as i64,
                    key_id_hex,
                    blob,
                    now,
                    expected_version as i64,
                    expected_incarnation,
                    app_id,
                    app_slug,
                ],
            )?;
            // The new tokens, the intent-clear, and the audit entry commit together
            // or not at all — so the refresh's version bump is accounted for in the
            // chain (a vault-owned RefreshCommit).
            if n > 0 {
                clear_intent_tx(tx, credential_id)?;
                append_audit_tx(
                    tx,
                    &audit_key,
                    &AuditRecord {
                        op: AuditOp::RefreshCommit,
                        credential_id: Some(credential_id.to_string()),
                        payload_hash: Some(payload_hash_hex),
                        actor: "vault".to_string(),
                        alarm: None,
                    },
                )?;
            }
            Ok(n)
        })?;
        if changed == 0 {
            return Err(StoreOpError::CasMismatch);
        }
        Ok(next_version)
    }

    /// Hold a Claude profile until the next refresh, without writing the sealed record.
    pub(crate) fn hold_detected_plan(
        &self,
        credential_id: &str,
        record_version: u64,
        token_hash: &str,
        identity: &RecordIdentity,
        plan: &crate::plan_detection::DetectedPlan,
    ) -> Result<(), StoreOpError> {
        let identity =
            serde_json::to_string(identity).map_err(|e| StoreOpError::Encode(e.to_string()))?;
        // No lease fence: this disposable observation must not participate in token
        // commit ordering. The single statement checks the live version as well as
        // the held version, so a slow profile cannot resurrect a replaced row or
        // overwrite a newer observation. Only a one-way access-token hash is stored.
        self.store
            .with_conn(|conn| {
                conn.execute(
                    "INSERT INTO held_detected_plans \
                     (credential_id, record_version, token_hash, identity, tier, raw, observed_at_ms) \
                     SELECT credential_id, record_version, ?3, ?4, ?5, ?6, ?7 FROM credentials \
                     WHERE credential_id = ?1 AND record_version = ?2 \
                     ON CONFLICT(credential_id) DO UPDATE SET \
                         record_version = excluded.record_version, token_hash = excluded.token_hash, \
                         identity = excluded.identity, tier = excluded.tier, raw = excluded.raw, \
                         observed_at_ms = excluded.observed_at_ms \
                     WHERE held_detected_plans.record_version < excluded.record_version",
                    rusqlite::params![
                        credential_id,
                        record_version as i64,
                        token_hash,
                        identity,
                        plan.tier,
                        plan.raw,
                        plan.observed_at_ms,
                    ],
                )?;
                Ok(())
            })
            .map_err(StoreOpError::from)
    }

    /// Read a held profile only for the exact record and token it observed.
    pub(crate) fn held_detected_plan(
        &self,
        credential_id: &str,
        record: &VaultRecord,
    ) -> Result<Option<crate::plan_detection::DetectedPlan>, StoreOpError> {
        self.store
            .with_conn(|conn| {
                let tx = conn.unchecked_transaction()?;
                let held = tx
                    .query_row(
                        "SELECT record_version, token_hash, identity, tier, raw, observed_at_ms \
                         FROM held_detected_plans WHERE credential_id = ?1",
                        [credential_id],
                        |row| {
                            Ok((
                                row.get::<_, u64>(0)?,
                                row.get::<_, String>(1)?,
                                row.get::<_, String>(2)?,
                                crate::plan_detection::DetectedPlan {
                                    tier: row.get(3)?,
                                    raw: row.get(4)?,
                                    observed_at_ms: row.get(5)?,
                                },
                            ))
                        },
                    )
                    .optional()?;
                let mut result = None;
                if let Some((version, token_hash, identity, plan)) = held {
                    if version == record.record_version
                        && record.oauth.as_ref().is_some_and(|oauth| {
                            token_hash == refresh_token_hash(oauth.access_token.expose())
                        })
                        && serde_json::from_str::<RecordIdentity>(&identity)
                            .is_ok_and(|identity| identity == record.identity)
                    {
                        result = Some(plan);
                    } else {
                        // A refresh racing a replacement may still hold the old
                        // record. Discard invalid bindings for that version, but
                        // never let a stale reader erase the live version's plan.
                        tx.execute(
                            "DELETE FROM held_detected_plans WHERE credential_id = ?1 \
                             AND (record_version = ?2 OR NOT EXISTS (\
                                 SELECT 1 FROM credentials WHERE credential_id = ?1 \
                                 AND credentials.record_version = held_detected_plans.record_version))",
                            rusqlite::params![credential_id, record.record_version as i64],
                        )?;
                    }
                }
                // Valid observations remain until the refresh commit succeeds; the
                // version-change trigger then deletes them atomically with the tokens.
                tx.commit()?;
                Ok(result)
            })
            .map_err(StoreOpError::from)
    }

    /// Persist the last observed GitHub App installation grant after its token commit.
    ///
    /// This is deliberately best-effort inside the store rather than an error returned
    /// to the refresh engine: permission history explains a successful mint, but can
    /// never make that token unavailable. The post-commit version guard prevents an
    /// older owner from replacing a newer mint's observation after a lease handover.
    pub(crate) fn observe_github_app_permissions(
        &self,
        credential_id: &str,
        record_version: u64,
        permissions: &BTreeMap<String, String>,
    ) {
        let Ok(current_json) = serde_json::to_string(permissions) else {
            return;
        };
        let result = self.store.with_conn(|c| {
            let tx = c.unchecked_transaction()?;
            let previous_json: Option<Option<String>> = tx
                .query_row(
                    "SELECT last_github_app_permissions FROM credentials \
                     WHERE credential_id = ?1 AND record_version = ?2",
                    rusqlite::params![credential_id, record_version as i64],
                    |row| row.get(0),
                )
                .optional()?;
            let Some(previous_json) = previous_json else {
                tx.commit()?;
                return Ok(());
            };

            let updated = tx.execute(
                "UPDATE credentials SET last_github_app_permissions = ?3 \
                 WHERE credential_id = ?1 AND record_version = ?2",
                rusqlite::params![credential_id, record_version as i64, current_json],
            )?;
            if updated > 0 {
                if let Some(previous) = previous_json
                    .as_deref()
                    .and_then(|json| serde_json::from_str::<BTreeMap<String, String>>(json).ok())
                    .filter(|previous| previous != permissions)
                {
                    let detail = github_app_permissions_change_detail(&previous, permissions);
                    append_auth_event_tx(
                        &tx,
                        credential_id,
                        &AuthObservation {
                            kind: AuthEventKind::GithubAppPermissionsChanged.as_str(),
                            provider_status: None,
                            detail: Some(&detail),
                            reporter_source: None,
                            principal: None,
                        },
                        Some(record_version),
                        true,
                    )?;
                }
            }
            tx.commit()
        });
        self.signal_commit(&result);
    }

    /// Read the dangling intent for one credential, if any (reconciliation + the
    /// boot gate's never-serve-dangling check).
    pub fn read_intent(&self, credential_id: &str) -> Result<Option<RefreshIntent>, StoreOpError> {
        self.store
            .with_conn(|c| {
                c.query_row(
                    "SELECT credential_id, record_version, old_refresh_hash, lease_epoch, \
                            started_at_ms FROM refresh_intent WHERE credential_id = ?1",
                    rusqlite::params![credential_id],
                    row_to_intent,
                )
                .map(Some)
                .or_else(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => Ok(None),
                    other => Err(other),
                })
            })
            .map_err(StoreOpError::from)
    }

    /// List every dangling intent (the boot reconciliation scan).
    pub fn list_intents(&self) -> Result<Vec<RefreshIntent>, StoreOpError> {
        self.store
            .with_conn(|c| {
                let mut stmt = c.prepare(
                    "SELECT credential_id, record_version, old_refresh_hash, lease_epoch, \
                            started_at_ms FROM refresh_intent ORDER BY credential_id",
                )?;
                let rows = stmt.query_map([], row_to_intent)?;
                rows.collect::<rusqlite::Result<Vec<_>>>()
            })
            .map_err(StoreOpError::from)
    }

    /// Clear a dangling intent (reconciliation resolved it). Fenced.
    pub fn clear_intent(&self, credential_id: &str) -> Result<(), StoreOpError> {
        self.fenced_write(|tx| clear_intent_tx(tx, credential_id).map(|_| ()))
            .map_err(StoreOpError::from)
    }

    /// The current refresh token hash stored for a credential, read by decrypting
    /// the record. Used by reconciliation to compare against an intent's
    /// `old_refresh_hash`. `None` for a non-OAuth or absent record.
    pub fn stored_refresh_hash(&self, credential_id: &str) -> Result<Option<String>, StoreOpError> {
        match self.get(credential_id) {
            Ok(record) => Ok(record
                .oauth
                .as_ref()
                .map(|o| refresh_token_hash(o.refresh_token.expose()))),
            Err(StoreOpError::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }
}
