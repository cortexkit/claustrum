//! Credential handles and transfer-key mutation protection.

use super::*;

/// Whether the transfer-key fence holds, read on the connection a writer is about to
/// write on: true when a record under `kem:vault-transfer:` exists and is `Active`, so
/// no operation may change it.
///
/// On the caller's own connection on purpose. The public accessors open a fresh
/// connection, and a pre-check read there followed by a write elsewhere would leave a
/// window in which the key's state could change between the two; a writer that folds
/// this read into its own transaction has none. A store from before the transfer key
/// existed has no such row and answers false.
pub(super) fn vault_transfer_key_fence_holds_tx(
    conn: &rusqlite::Connection,
) -> rusqlite::Result<bool> {
    let active: Option<String> = conn
        .query_row(
            "SELECT state FROM credentials WHERE credential_id = ?1",
            [crate::federation::VAULT_TRANSFER_ID],
            |row| row.get(0),
        )
        .optional()?;
    Ok(active.as_deref() == Some(RecordState::Active.as_str()))
}

/// Hex SHA-256 of a raw capability handle — the only form of a handle the store
/// persists (a database leak yields no usable handle).
pub fn handle_hash(raw_handle: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"cortexkit-credentials/handle/v1");
    h.update(raw_handle.as_bytes());
    let digest = h.finalize();
    use std::fmt::Write;
    let mut s = String::with_capacity(64);
    for b in digest {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Mint a fresh capability handle: 256 CSPRNG bits as a `ckh_`-prefixed base64url
/// string. The raw value is returned once; only its hash is ever persisted.
pub fn mint_handle() -> Result<MintedHandle, getrandom::Error> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes)?;
    let value = format!("ckh_{}", base64url(&bytes));
    let hash = handle_hash(&value);
    Ok(MintedHandle { raw: value, hash })
}

/// The OTHER live handles on a credential, newest first, as (hash, minted-at-ms).
///
/// For the advisory `mint-handle` prints after a successful mint. The vault cannot tell
/// one holder from another -- there is no holder column and no last-use column -- so it
/// cannot know whether a fresh handle REPLACES one the operator already holds or joins a
/// set of live doors held by different consumers. Both are ordinary.
///
/// *** WHY THIS EXISTS AT ALL, because the alternative looks obviously better. ***
/// The tempting fix is `mint-handle --replace`, revoking the credential's other handles
/// in the same transaction. That is wrong here: on `oauth:anthropic` the other live
/// handle is a different consumer's default-resolution door, so a replace issued by one
/// holder would silently close another's. The vault has no way to tell them apart.
///
/// So the operator is asked instead, and the timing is the whole point: measured on this
/// vault 2026-09-19, four credentials carried 16 live handles and 12 had no identifiable
/// holder. Every orphan was created by a hand-edit that pasted a new handle over an old
/// one -- the consumer's config is a map keyed on credential id, so the displaced value
/// stops existing there the moment the editor saves while remaining live here. THE ONE
/// MOMENT BOTH VALUES COEXIST IS IN THE MINTING OPERATOR'S HANDS, and after that no
/// surface holds the predecessor. Asking later is a canvass; asking now is a question.
///
/// Read-only and lease-free, so it runs beside a serving daemon: every column is
/// plaintext and a handle hash is not spendable.
pub fn other_live_handles_read_only(
    store_path: &std::path::Path,
    credential_id: &str,
    exclude_hash: &str,
) -> Result<Vec<(String, i64)>, StoreOpError> {
    let map = |e: rusqlite::Error| StoreOpError::from(StoreError::Backend(e.to_string()));
    let conn = rusqlite::Connection::open_with_flags(
        store_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .map_err(map)?;
    let mut stmt = conn
        .prepare(
            "SELECT handle_hash, created_at_ms FROM handles \
             WHERE credential_id = ?1 AND revoked = 0 AND handle_hash <> ?2 \
             ORDER BY created_at_ms DESC",
        )
        .map_err(map)?;
    let rows = stmt
        .query_map(rusqlite::params![credential_id, exclude_hash], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })
        .map_err(map)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(map)?;
    Ok(rows)
}

impl EncryptedStore {
    // ---- capability handles ---------------------------------------------

    /// The lifecycle state of the vault transfer key (`kem:vault-transfer:*`), or
    /// `None` when this vault has no such record.
    ///
    /// Read WITHOUT decrypting: every fence below asks only whether the key is
    /// `Active`, and answering that must keep working on a key whose envelope is
    /// damaged -- the recovery path exists for exactly that state.
    pub fn vault_transfer_key_state(&self) -> Result<Option<RecordState>, StoreOpError> {
        self.store
            .with_conn(|conn| {
                let state: Option<String> = conn
                    .query_row(
                        "SELECT state FROM credentials WHERE credential_id = ?1",
                        [crate::federation::VAULT_TRANSFER_ID],
                        |row| row.get(0),
                    )
                    .optional()?;
                Ok(state.map(|state| RecordState::from_str(&state)))
            })
            .map_err(StoreOpError::from)
    }

    /// Whether the transfer key is present and `Active`: while it is, every operation
    /// that would change its record is refused with `transfer_key_protected`.
    pub(crate) fn refuses_vault_transfer_key_mutation(&self) -> Result<bool, StoreOpError> {
        Ok(self.vault_transfer_key_state()? == Some(RecordState::Active))
    }

    /// Refuse replacing, re-identifying, invalidating, retiring, reactivating or
    /// removing an id under the transfer-key prefix while the key is `Active`.
    ///
    /// The refusal compares the stored state rather than trusting the caller, and it
    /// admits everything else -- an id that is not a transfer key, and a transfer key
    /// found off `Active`, which is the state the recovery command repairs.
    pub(crate) fn check_vault_transfer_key_writable(
        &self,
        credential_id: &str,
    ) -> Result<(), StoreOpError> {
        if self
            .store
            .with_conn(|conn| store_agent_secrets::deposit_key_write_protected(conn, credential_id))
            .map_err(StoreOpError::from)?
        {
            return Err(StoreOpError::NotFound);
        }
        if crate::federation::is_vault_transfer_id(credential_id)
            && self.refuses_vault_transfer_key_mutation()?
        {
            return Err(StoreOpError::TransferKeyProtected);
        }
        Ok(())
    }

    /// Test-only: force the transfer key's stored state, bypassing every fence.
    ///
    /// The recovery path (`ck auth transfer init --replace`) is admitted only when the
    /// key is found off `Active`, and no production operation can produce that state --
    /// that is the point of the fences. A test therefore has no legitimate route to it,
    /// and this hook exists so one can stand in the damaged store an operator would
    /// find. It is compiled in only under the test-support feature, so a release binary
    /// has no way to move a transfer key's state without breaking the envelope it is
    /// supposed to seal. Returns whether a transfer-key row was updated.
    #[cfg(any(test, feature = "test-support"))]
    pub fn force_vault_transfer_key_state_for_test(
        &self,
        state: RecordState,
    ) -> Result<bool, StoreOpError> {
        let changed = self.store.with_conn(|conn| {
            conn.execute(
                "UPDATE credentials SET state = ?1 WHERE credential_id LIKE ?2",
                rusqlite::params![
                    state.as_str(),
                    format!("{}%", crate::federation::VAULT_TRANSFER_ID_PREFIX)
                ],
            )
        })?;
        Ok(changed > 0)
    }

    /// Resolve a raw capability handle to its credential id. Hashes the presented
    /// handle and looks up a NON-revoked row; returns [`StoreOpError::NotFound`]
    /// when the handle is unknown or revoked (the read surface maps that to a
    /// uniform not-found so a probe cannot tell "wrong handle" from "revoked").
    pub fn resolve_handle(&self, raw_handle: &str) -> Result<String, StoreOpError> {
        // Reads only the handles table. Callers that need the id alone, such as status,
        // must still name the credential when its row cannot be read; reads that act on
        // the row use `resolve_handle_with_incarnation`, which also pins the row identity.
        let h = handle_hash(raw_handle);
        self.store
            .with_conn(|c| {
                c.query_row(
                    "SELECT credential_id FROM handles \
                     WHERE handle_hash = ?1 AND revoked = 0",
                    rusqlite::params![h],
                    |r| r.get::<_, String>(0),
                )
                .map(Some)
                .or_else(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => Ok(None),
                    other => Err(other),
                })
            })
            .map_err(StoreOpError::from)?
            .filter(|id| {
                !crate::agent_secret::is_deposit_key(id) && !is_github_app_companion_id(id)
            })
            .ok_or(StoreOpError::NotFound)
    }

    /// Resolve authority and row identity in one read, before a lifecycle change can
    /// destroy the handle and reuse its credential id.
    pub fn resolve_handle_with_incarnation(
        &self,
        raw_handle: &str,
    ) -> Result<(String, String), StoreOpError> {
        let h = handle_hash(raw_handle);
        self.store
            .with_conn(|c| {
                c.query_row(
                    "SELECT h.credential_id, c.incarnation FROM handles h \
                     JOIN credentials c ON c.credential_id = h.credential_id \
                     WHERE handle_hash = ?1 AND revoked = 0",
                    rusqlite::params![h],
                    |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
                )
                .map(Some)
                .or_else(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => Ok(None),
                    other => Err(other),
                })
            })
            .map_err(StoreOpError::from)?
            .filter(|(id, _)| {
                !crate::agent_secret::is_deposit_key(id) && !is_github_app_companion_id(id)
            })
            .ok_or(StoreOpError::NotFound)
    }

    /// Lifetime identity of a local row, also exposed by scoped inventory.
    /// This is not a credential address or an access capability.
    pub fn credential_incarnation(&self, credential_id: &str) -> Result<String, StoreOpError> {
        self.store
            .with_conn(|c| {
                c.query_row(
                    "SELECT incarnation FROM credentials WHERE credential_id = ?1",
                    [credential_id],
                    |r| r.get(0),
                )
                .optional()
            })
            .map_err(StoreOpError::from)?
            .ok_or(StoreOpError::NotFound)
    }

    /// Fix storage identity before serializing deterministic test vectors.
    #[cfg(any(test, feature = "test-support"))]
    pub fn force_credential_incarnation_for_test(&self, id: &str, incarnation: &str) {
        assert_eq!(incarnation.len(), 32);
        assert!(incarnation.bytes().all(|byte| byte.is_ascii_hexdigit()));
        self.fenced_write(|tx| {
            tx.execute(
                "UPDATE credentials SET incarnation=?1 WHERE credential_id=?2",
                rusqlite::params![incarnation, id],
            )
        })
        .unwrap();
    }

    /// Record a freshly minted handle for a credential, storing only its hash, AND
    /// append a `MintHandle` audit entry — both in ONE fenced transaction, so a handle
    /// can never be minted without a tamper-evident audit record (the same atomicity
    /// every other durable mutation uses). Mint is admin-only; the caller's audit
    /// context records WHICH admin origin performed it (offline CLI vs the module's
    /// authenticated route admin surface) so the trail is truthful provenance.
    ///
    /// DELIBERATELY INDIFFERENT TO THE CREDENTIAL'S STATE: a handle is a grant to a
    /// credential, not an assertion that it currently works, so minting for a
    /// `needs_reauth` record succeeds. That is the shape production reaches on its own
    /// — a live consumer holds a handle across a credential dying and being repaired,
    /// and the same handle serves afterwards.
    ///
    /// Adding a state check here would look like a safety improvement and would break
    /// that: it would make a handle un-mintable exactly when an operator is repairing
    /// a dead credential.
    ///
    /// THE TRANSFER KEY IS THE ONE EXCEPTION, and it is a check on the ID rather than
    /// on the state: a handle on `kem:vault-transfer:*` would let its holder sign
    /// federation seals as this vault, so minting one is refused with
    /// `transfer_key_reserved` whatever the key's state.
    pub fn put_handle_hash(
        &self,
        handle_hash_hex: &str,
        credential_id: &str,
        ctx: AuditCtx<'_>,
    ) -> Result<(), StoreOpError> {
        check_github_app_companion_id(credential_id)?;
        if crate::federation::is_bus_key_id(credential_id) {
            return Err(StoreOpError::BusKeyReserved);
        }
        if crate::federation::is_fleet_key_id(credential_id) {
            return Err(StoreOpError::FleetKeyReserved);
        }
        if crate::agent_secret::is_deposit_key(credential_id) {
            return Err(StoreOpError::NotFound);
        }
        if crate::federation::is_vault_transfer_id(credential_id) {
            return Err(StoreOpError::TransferKeyReserved);
        }
        let now = now_ms();
        let audit_key = self.audit_key.clone();
        self.fenced_write(|tx| {
            tx.execute(
                "INSERT INTO handles (handle_hash, credential_id, created_at_ms, revoked) \
                 VALUES (?1, ?2, ?3, 0)",
                rusqlite::params![handle_hash_hex, credential_id, now],
            )?;
            append_audit_tx(
                tx,
                &audit_key,
                &AuditRecord {
                    op: AuditOp::MintHandle,
                    credential_id: Some(credential_id.to_string()),
                    // The handle hash, so a LIVE handle can be traced back to the mint
                    // that created it. Without it the chain records that a door was cut
                    // for a credential and not WHICH door, so a handle found live in the
                    // store has no minting actor and no minting time -- the exact
                    // question an audit of accumulated bearer material asks.
                    //
                    // This is the mirror of the gap the revoke path carried for two
                    // months (see `revoke_handle` below): there the caller's input named
                    // a handle and not a credential, here it names both and one was
                    // dropped. Measured on the live store when this was written: 205
                    // mint rows, ALL with a null payload hash, against 97 of 105 revoke
                    // rows carrying one and 87 still joining. So revocation was
                    // attributable and creation was not, which is backwards -- a
                    // revocation closes access and a mint opens it.
                    //
                    // No secrecy cost, by the same argument the revoke path already
                    // makes: the raw handle is never stored, the hash is what the
                    // `handles` table holds, and `credential_id` is here already.
                    //
                    // Historical rows stay null and are NOT backfilled: the chain is
                    // HMAC-linked, so rewriting an entry breaks verification from that
                    // point on. Attribution for handles minted before this is a
                    // timestamp correlation between `handles.created_at_ms` and this
                    // op's `ts_ms`, which is a correlation and not a join -- two mints
                    // in the same second are indistinguishable.
                    payload_hash: Some(handle_hash_hex.to_string()),
                    actor: ctx.actor.to_string(),
                    alarm: ctx.alarm,
                },
            )?;
            Ok(())
        })
        .map_err(StoreOpError::from)
    }

    /// Revoke a single handle by its raw value. Only revoking a live handle appends
    /// a `RevokeHandle` audit entry, in the same fenced transaction as the update.
    /// The entry names the owning credential and the handle hash, never the raw value.
    /// Repeats and unknown handles change nothing and append nothing.
    ///
    /// Returns the owning credential ID when a live handle was revoked, otherwise `None`.
    /// This operator-only result can distinguish a successful revocation from a no-op;
    /// consumer reads still answer identically for unknown and revoked handles.
    ///
    /// There is deliberately no un-revoke: the vault cannot know who retained a copy
    /// of a potentially leaked bearer token. Mint and distribute a new handle instead.
    /// Reactivating a credential restores trust in material the vault still holds;
    /// restoring a revoked handle would restore third-party access to an old capability.
    pub fn revoke_handle(
        &self,
        raw_handle: &str,
        ctx: AuditCtx<'_>,
    ) -> Result<Option<String>, StoreOpError> {
        self.revoke_handle_by_hash_audited(&handle_hash(raw_handle), ctx)
    }

    /// Revoke by the stored hash when the raw bearer is no longer available.
    pub fn revoke_handle_by_hash_audited(
        &self,
        handle_hash: &str,
        ctx: AuditCtx<'_>,
    ) -> Result<Option<String>, StoreOpError> {
        // Prefix expansion could revoke a different bearer as the table grows.
        if handle_hash.len() != 64
            || !handle_hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(StoreOpError::Encode(
                "expected 64 lowercase hex handle hash".into(),
            ));
        }
        let h = handle_hash.to_owned();
        let audit_key = self.audit_key.clone();
        self.fenced_write(|tx| {
            // Read the owner INSIDE the same transaction, before the update. One indexed
            // lookup on an admin-gated path, and it is what makes the entry attributable.
            let owner: Option<String> = tx
                .query_row(
                    "SELECT credential_id FROM handles WHERE handle_hash = ?1",
                    rusqlite::params![h],
                    |row| row.get(0),
                )
                .optional()?;
            let owner_for_return = owner.clone();
            let changed = tx.execute(
                "UPDATE handles SET revoked = 1 WHERE handle_hash = ?1 AND revoked = 0",
                rusqlite::params![h],
            )?;
            if changed == 0 {
                return Ok(None);
            }
            append_audit_tx(
                tx,
                &audit_key,
                &AuditRecord {
                    op: AuditOp::RevokeHandle,
                    credential_id: owner,
                    payload_hash: Some(h.clone()),
                    actor: ctx.actor.to_string(),
                    alarm: ctx.alarm,
                },
            )?;
            Ok(owner_for_return)
        })
        .map_err(StoreOpError::from)
    }

    /// Revoke ALL handles for a credential (e.g. on invalidate / suspected leak).
    /// Returns the number revoked. The update AND a `RevokeHandle` audit entry (naming
    /// the credential) commit in ONE fenced transaction.
    pub fn revoke_all_handles(
        &self,
        credential_id: &str,
        ctx: AuditCtx<'_>,
    ) -> Result<usize, StoreOpError> {
        let audit_key = self.audit_key.clone();
        self.fenced_write(|tx| {
            let n = tx.execute(
                "UPDATE handles SET revoked = 1 \
                 WHERE credential_id = ?1 AND revoked = 0",
                rusqlite::params![credential_id],
            )?;
            if n == 0 {
                return Ok(0);
            }
            append_audit_tx(
                tx,
                &audit_key,
                &AuditRecord {
                    op: AuditOp::RevokeHandle,
                    credential_id: Some(credential_id.to_string()),
                    payload_hash: None,
                    actor: ctx.actor.to_string(),
                    alarm: ctx.alarm,
                },
            )?;
            Ok(n)
        })
        .map_err(StoreOpError::from)
    }
}
