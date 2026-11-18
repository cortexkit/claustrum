//! Credential reads, writes, identity updates, and lifecycle transitions.

use super::*;

/// Refuse a static record whose payload is a short-term Amazon Bedrock API key. Applied at
/// every operator deposit sink (create, import, login and `put --replace` all reach one of
/// the two), so no door can store a key that dies within 12 hours.
pub(super) fn refuse_short_term_bedrock_key(record: &VaultRecord) -> Result<(), StoreOpError> {
    if record.kind == CredentialKind::Oauth {
        return Ok(());
    }
    match crate::bedrock::short_term_bedrock_key(record.payload.expose()) {
        Some(key) => Err(StoreOpError::ShortTermBedrockKey {
            expires_at_ms: key.expires_at_ms,
        }),
        None => Ok(()),
    }
}

pub(super) fn normalize_record_identity(mut record: VaultRecord) -> VaultRecord {
    let identity = record.identity.clone();
    record = record.with_identity(identity);
    record
}

pub(super) fn validate_record_identity(record: &VaultRecord) -> Result<(), StoreOpError> {
    record.identity.validate().map_err(StoreOpError::Encode)
}

pub(super) fn derived_account_id(record: &VaultRecord) -> Option<String> {
    let adapter = record.refresh_adapter.as_deref()?;
    crate::oauth_login::account_id_for_adapter(
        adapter,
        record.oauth.as_ref()?.access_token.expose(),
    )
}

pub(super) fn refuse_incoming_agent_ssh(record: &VaultRecord) -> Result<(), StoreOpError> {
    if record.agent_ssh.is_some() {
        return Err(StoreOpError::InvalidAgentSsh);
    }
    Ok(())
}

/// Use plaintext row identity, not the old envelope: replacing a damaged key must
/// revoke its authority too. Keep receipt nonces occupied until their normal expiry.
fn clear_agent_ssh_state_tx(tx: &rusqlite::Transaction, id: &str) -> rusqlite::Result<()> {
    if !id.starts_with("signing:") || read_schema_version(tx)? < AGENT_SECRET_SCHEMA_VERSION {
        return Ok(());
    }
    tx.execute("DELETE FROM secret_grants WHERE secret_name=?1", [id])?;
    tx.execute(
        "DELETE FROM secret_pending_requests WHERE secret_name=?1",
        [id],
    )?;
    if read_schema_version(tx)? >= SECRET_RELEASE_RECEIPT_SCHEMA_VERSION {
        tx.execute(
            "UPDATE secret_release_receipts SET aad_sha256='invalidated', enc=X'', ciphertext=X'' \
             WHERE incarnation=(SELECT incarnation FROM credentials WHERE credential_id=?1)",
            [id],
        )?;
    }
    Ok(())
}

fn clear_plan_on_account_change_tx(
    tx: &rusqlite::Transaction,
    audit_key: &[u8; 32],
    id: &str,
    old: Option<&RecordIdentity>,
    new: &RecordIdentity,
    ctx: AuditCtx<'_>,
) -> rusqlite::Result<()> {
    // An unreadable previous envelope cannot prove the account stayed the same.
    // Clearing its assertion is safer than pricing replacement material with a stale tier.
    if old.is_none_or(|old| old.clone().normalized().account_id != new.account_id) {
        write_plan_tier_tx(tx, audit_key, id, None, ctx)?;
    }
    Ok(())
}

pub(super) fn retain_detected_plan(incoming: &mut VaultRecord, old: Option<&VaultRecord>) {
    let same_account = old.is_some_and(|old| {
        old.identity.clone().normalized().account_id == incoming.identity.account_id
    });
    if let Some(old) = old {
        if !same_account && incoming.detected_plan == old.detected_plan {
            // A copied observation does not belong to a different account.
            incoming.detected_plan = None;
        } else if same_account && incoming.detected_plan.is_none() {
            incoming.detected_plan = old.detected_plan.clone();
        }
    }
    incoming.detected_plan_tier_observed_at_ms = incoming.detected_plan.as_ref().and_then(|plan| {
        let tier = plan.tier.as_ref()?;
        match old.filter(|old| {
            same_account && old.detected_plan.as_ref().and_then(|p| p.tier.as_ref()) == Some(tier)
        }) {
            // Preserve unknown for legacy records, even if a refresh sees the same tier.
            Some(old) => old.detected_plan_tier_observed_at_ms,
            None => Some(plan.observed_at_ms),
        }
    });
}

impl EncryptedStore {
    /// Inject an audit-append failure after the deposit data write, without affecting
    /// other store instances or operator writes.
    #[cfg(any(test, feature = "test-support"))]
    pub fn force_deposit_cookie_audit_append_error_for_test(&self, enabled: bool) {
        self.deposit_cookie_audit_fault
            .store(enabled, Ordering::Relaxed);
    }

    /// Store a cookie for an already-authorized reserved principal. Authorization and
    /// wire grammar checks belong to the route; creator ownership is enforced here.
    /// Mutation, intent clearing and audit append share one fenced transaction.
    pub fn deposit_cookie(
        &self,
        credential_id: &str,
        cookie: &crate::secret::Secret<String>,
        consent_ref: &str,
        email: Option<&str>,
        principal_str: &str,
    ) -> Result<DepositCookieOutcome, StoreOpError> {
        validate_deposit_credential_id(credential_id)?;
        if !crate::deposit_cookie::valid_deposit_cookie_id(credential_id) {
            return Err(StoreOpError::InvalidCredentialId);
        }
        if !principal_str
            .strip_prefix("reserved:")
            .is_some_and(|id| !id.is_empty() && !id.contains('|'))
        {
            return Err(StoreOpError::InvalidPrincipal);
        }
        let mut incoming =
            VaultRecord::new_cookie(principal_str, cookie.expose().as_bytes().to_vec());
        if let Some(email) = email {
            // Identity normalization discards email without an account id. Use the
            // email as both the account label and disclosed email, as imports do.
            incoming.identity.account_id = Some(email.to_owned());
            incoming.identity.email = Some(email.to_owned());
        }
        validate_record_identity(&incoming)?;
        let blob = self.seal_record(credential_id, &incoming)?;
        let key_id_hex = self.key_id.to_hex();
        let now = now_ms();
        let hash = crate::deposit_cookie::deposit_cookie_payload_hash(
            credential_id,
            consent_ref,
            cookie.expose().as_bytes(),
        );
        let hash = hex32(&audit::payload_fingerprint(
            &self.audit_key,
            hash.as_bytes(),
        ));
        let outcome = self.fenced_write(|tx| {
            let inserted = tx.execute(
                "INSERT INTO credentials (credential_id, record_version, key_id, state, envelope, updated_at_ms, created_at_ms, created_by) \
                 VALUES (?1, 1, ?2, 'active', ?3, ?4, ?4, ?5) ON CONFLICT(credential_id) DO NOTHING",
                rusqlite::params![credential_id, key_id_hex, blob, now, principal_str],
            )?;
            let (outcome, op) = if inserted > 0 {
                for category in crate::catalog::category_defaults(credential_id) {
                    tx.execute("INSERT INTO credential_categories (credential_id, category) VALUES (?1, ?2)", rusqlite::params![credential_id, category])?;
                    bump_grants_generation_tx(tx)?;
                }
                (DepositCookieOutcome::Created { record_version: 1 }, AuditOp::DepositCookieCreate)
            } else {
                let (version, creator, existing): (i64, Option<String>, Vec<u8>) = tx.query_row(
                    "SELECT record_version, created_by, envelope FROM credentials WHERE credential_id = ?1",
                    [credential_id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )?;
                if creator.as_deref() != Some(principal_str) {
                    return Ok(None);
                }
                let existing_record = envelope::open(&self.key, &existing, &RecordBinding {
                    credential_id, record_version: version as u64,
                }).ok().and_then(|plain| VaultRecord::decode(&plain).ok());
                let existing_identity = existing_record.as_ref()
                  .map(|record| record.identity.clone()).filter(|identity| identity.validate().is_ok())
                  .map(RecordIdentity::normalized);
                if email.is_none() {
                    incoming.identity = existing_identity.clone().unwrap_or_default();
                }
                retain_detected_plan(&mut incoming, existing_record.as_ref());
                let next = version.checked_add(1).ok_or(rusqlite::Error::InvalidQuery)?;
                incoming.record_version = next as u64;
                let blob = self.seal_record(credential_id, &incoming)
                    .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
                let changed = tx.execute(
                    "UPDATE credentials SET record_version = ?2, key_id = ?3, state = 'active', stale_pending = 0, envelope = ?4, updated_at_ms = ?5 \
                     WHERE credential_id = ?1 AND created_by = ?6 AND record_version = ?7",
                    rusqlite::params![credential_id, next, key_id_hex, blob, now, principal_str, version],
                )?;
                if changed != 1 { return Err(rusqlite::Error::InvalidQuery); }
                clear_plan_on_account_change_tx(tx, &self.audit_key, credential_id, existing_identity.as_ref(), &incoming.identity, AuditCtx::route_admin(AuditOp::SetPlan, principal_str))?;
                (DepositCookieOutcome::Replaced { record_version: next as u64 }, AuditOp::DepositCookieReplace)
            };
            clear_intent_tx(tx, credential_id)?;
            delete_local_condition_tx(tx, credential_id)?;
            #[cfg(any(test, feature = "test-support"))]
            if self.deposit_cookie_audit_fault.load(Ordering::Relaxed) {
                return Err(rusqlite::Error::InvalidQuery);
            }
            append_audit_tx(tx, &self.audit_key, &AuditRecord {
                op, credential_id: Some(credential_id.to_owned()), payload_hash: Some(hash),
                actor: principal_str.to_owned(), alarm: None,
            })?;
            Ok(Some(outcome))
        })?;
        outcome.ok_or(StoreOpError::DepositCookieNotPermitted)
    }

    /// Create a record (CREATE-ONLY) with an explicit audit context: fails
    /// [`StoreOpError::AlreadyExists`] if the id is already present. The record is
    /// sealed at `record_version = 1`, the row is written through the epoch-fenced
    /// path, any dangling refresh intent is cleared, AND an audit entry is appended
    /// — all in ONE transaction, so the mutation and its audit record commit
    /// atomically (the audit chain accounts for the new version, tamper-evidently).
    pub fn create_audited(
        &self,
        credential_id: &str,
        record: &VaultRecord,
        ctx: AuditCtx<'_>,
    ) -> Result<(), StoreOpError> {
        refuse_incoming_agent_ssh(record)?;
        validate_deposit_credential_id(credential_id)?;
        // A create for the transfer key's id must not slip past the replace fence by
        // failing first and being retried as a create.
        self.check_vault_transfer_key_writable(credential_id)?;
        refuse_short_term_bedrock_key(record)?;
        let mut record = normalize_record_identity(record.clone());
        if let Some(derived_account_id) = derived_account_id(&record) {
            match record.identity.account_id.as_deref() {
                Some(supplied_account_id) if supplied_account_id != derived_account_id => {
                    return Err(StoreOpError::SuppliedIdentityContradictsClaim {
                        credential_id: credential_id.to_string(),
                        supplied_account_id: supplied_account_id.to_string(),
                        derived_account_id,
                    });
                }
                None => record.identity.account_id = Some(derived_account_id),
                Some(_) => {}
            }
        }
        validate_record_identity(&record)?;
        record.record_version = 1;
        retain_detected_plan(&mut record, None);
        let blob = self.seal_record(credential_id, &record)?;
        let key_id_hex = self.key_id.to_hex();
        let now = now_ms();
        let audit_key = self.audit_key.clone();
        let payload_hash_hex = hex32(&audit::payload_fingerprint(
            &audit_key,
            record.payload.expose(),
        ));

        // Create-only via INSERT ... ON CONFLICT DO NOTHING inside the fenced
        // transaction: an existing id leaves zero rows changed (atomic, no separate
        // existence query, no error-string matching). Zero changed => AlreadyExists.
        let changed = self.fenced_write(|tx| {
            let n = tx.execute(
                // `created_at_ms` is written once, here, and never updated again:
                // every later write path sets `updated_at_ms` instead, so a refresh
                // that rewrites the envelope three times a day leaves the deposit
                // instant intact. Existing rows got theirs from their chain birth
                // entry when the column was added.
                "INSERT INTO credentials \
                 (credential_id, record_version, key_id, state, envelope, updated_at_ms, created_at_ms, created_by) \
                 VALUES (?1, ?2, ?3, 'active', ?4, ?5, ?5, 'operator') \
                 ON CONFLICT(credential_id) DO NOTHING",
                rusqlite::params![
                    credential_id,
                    record.record_version as i64,
                    key_id_hex,
                    blob,
                    now
                ],
            )?;
            // An admin write clears any dangling refresh intent for this id in the
            // SAME transaction: a fresh credential must never inherit a stale intent
            // from a prior id reuse (and on overwrite this is what stops a boot
            // reconciliation from undoing a legitimate re-login).
            //
            // THIS TAIL REPEATS IN THE REPLACE AND OVERWRITE PATHS AND IS NOT WORTH
            // EXTRACTING.
            //
            // The three sit under different write contracts -- unconditional insert,
            // version-guarded replace, unconditional overwrite -- each with its own SQL
            // and its own definition of what `n > 0` means. A shared helper would have
            // to decide, on its callers' behalf, when the intent may be cleared and
            // which audit op to append. Such a helper invites two failures: it enforces
            // an invariant on the way in while some caller writes around it, or a fix
            // constrains a type no reachable writer goes through. Three visible copies
            // under three contracts beat one helper hiding which contract it is serving.
            if n > 0 {
                for category in registered_providers::category_defaults(tx, credential_id)? {
                    tx.execute(
                        "INSERT INTO credential_categories (credential_id, category) VALUES (?1, ?2)",
                        rusqlite::params![credential_id, category],
                    )?;
                    bump_grants_generation_tx(tx)?;
                }
                clear_intent_tx(tx, credential_id)?;
                delete_local_condition_tx(tx, credential_id)?;
                append_audit_tx(
                    tx,
                    &audit_key,
                    &AuditRecord {
                        op: ctx.op,
                        credential_id: Some(credential_id.to_string()),
                        payload_hash: Some(payload_hash_hex),
                        actor: ctx.actor.to_string(),
                        alarm: ctx.alarm,
                    },
                )?;
            }
            Ok(n)
        })?;
        if changed == 0 {
            return Err(StoreOpError::AlreadyExists);
        }
        Ok(())
    }

    /// Replace or clear the complete SSH enrollment in the same transaction that
    /// revokes grants, pending requests and replayable replies for the old enrollment.
    pub fn set_agent_ssh_audited(
        &self,
        id: &str,
        enrollment: Option<crate::record::AgentSsh>,
        actor: &str,
    ) -> Result<Option<crate::record::AgentSsh>, StoreOpError> {
        if enrollment.is_some() {
            crate::agent_secret::validate_ssh_card_key_id(id)
                .map_err(|_| StoreOpError::InvalidAgentSsh)?;
        } else {
            // Revoking enrollment must remain possible even for an unreadable card id.
            if !id.starts_with("signing:") {
                return Err(StoreOpError::InvalidAgentSsh);
            }
            validate_deposit_credential_id(id)?;
        }
        let enrollment = enrollment
            .map(crate::record::AgentSsh::canonicalized)
            .transpose()
            .map_err(|_| StoreOpError::InvalidAgentSsh)?;
        self.fenced_write(|tx| {
            if enrollment.is_some() && !store_agent_secrets::local_programs_enabled(tx) {
                return Ok(Err(StoreOpError::SecretLocalProgramsDisabled));
            }
            let row: Option<(i64, Vec<u8>)> = tx.query_row(
                "SELECT record_version, envelope FROM credentials WHERE credential_id=?1",
                [id], |r| Ok((r.get(0)?, r.get(1)?)),
            ).optional()?;
            let Some((version, blob)) = row else {
                return Ok(Err(StoreOpError::NotFound));
            };
            let record = envelope::open(&self.key, &blob, &RecordBinding {
                credential_id: id, record_version: version as u64,
            }).ok().and_then(|bytes| VaultRecord::decode(&bytes).ok());
            let Some(mut record) = record else {
                return Ok(Err(StoreOpError::NotFound));
            };
            if record.kind != CredentialKind::SigningKey
                || std::str::from_utf8(record.payload.expose()).ok()
                    .and_then(|pem| crate::signing::public_key_ed25519(pem).ok()).is_none()
            {
                return Ok(Err(StoreOpError::InvalidAgentSsh));
            }
            if record.agent_ssh == enrollment {
                return Ok(Ok(enrollment));
            }
            record.agent_ssh = enrollment.clone();
            record.record_version = (version as u64).saturating_add(1);
            let blob = self.seal_record(id, &record)
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
            clear_agent_ssh_state_tx(tx, id)?;
            tx.execute(
                "UPDATE credentials SET record_version=?2, envelope=?3, updated_at_ms=?4 WHERE credential_id=?1",
                rusqlite::params![id, record.record_version as i64, blob, now_ms()],
            )?;
            append_audit_tx(tx, &self.audit_key, &AuditRecord {
                op: if enrollment.is_some() { AuditOp::SshKeyAgentAllow } else { AuditOp::SshKeyAgentDeny },
                credential_id: Some(id.to_owned()),
                payload_hash: Some(hex32(&audit::payload_fingerprint(&self.audit_key,
                    &serde_json::to_vec(&enrollment).expect("SSH enrollment JSON")))),
                actor: actor.to_owned(), alarm: None,
            })?;
            Ok(Ok(enrollment))
        })?
    }

    /// Create a record (CREATE-ONLY), auditing it as a vault-owned `Put`. Convenience
    /// wrapper over [`create_audited`] for callers (and tests) that do not need to
    /// specify the op/actor; production admin writes use `create_audited` with an
    /// admin context.
    pub fn create(&self, credential_id: &str, record: &VaultRecord) -> Result<(), StoreOpError> {
        self.create_audited(credential_id, record, AuditCtx::vault(AuditOp::Put))
    }

    /// Overwrite an existing record under a compare-and-set on its current payload
    /// hash, with an explicit audit context. Fails [`StoreOpError::NotFound`] if
    /// absent, [`StoreOpError::CasMismatch`] if `expected_payload_hash` does not
    /// match. On success the new record is sealed at `current_version + 1`, the
    /// dangling intent is cleared, and the audit entry is appended — all in ONE
    /// transaction.
    pub fn overwrite_cas_audited(
        &self,
        credential_id: &str,
        record: &VaultRecord,
        expected_payload_hash: &[u8; 32],
        ctx: AuditCtx<'_>,
    ) -> Result<(), StoreOpError> {
        refuse_incoming_agent_ssh(record)?;
        validate_deposit_credential_id(credential_id)?;
        // A CAS replace at the current version is still a replace: the transfer key's
        // active record cannot be overwritten under it.
        self.check_vault_transfer_key_writable(credential_id)?;
        // Read + decrypt the current record to verify the CAS precondition. A
        // decrypt failure here quarantines the id (handled by `get`).
        let current = self.get(credential_id)?;
        if &payload_hash(current.payload.expose()) != expected_payload_hash {
            return Err(StoreOpError::CasMismatch);
        }
        let next_version = current.record_version.saturating_add(1);
        let mut record = normalize_record_identity(record.clone());
        validate_record_identity(&record)?;
        retain_detected_plan(&mut record, Some(&current));
        record.record_version = next_version;
        let blob = self.seal_record(credential_id, &record)?;
        let key_id_hex = self.key_id.to_hex();
        let now = now_ms();
        let audit_key = self.audit_key.clone();
        let payload_hash_hex = hex32(&audit::payload_fingerprint(
            &audit_key,
            record.payload.expose(),
        ));

        // The version in the WHERE makes the UPDATE itself a compare-and-set on the
        // version we read, so a concurrent writer that already bumped it leaves zero
        // rows changed (no error-string matching). Zero changed => CasMismatch.
        let changed = self.fenced_write(|tx| {
            if (record.kind != CredentialKind::ApiKey || record.refresh_adapter.is_some())
                && gateway::has_settings(tx, credential_id)?
            {
                return Ok(None);
            }
            let n = tx.execute(
                "UPDATE credentials \
                  SET record_version = ?2, key_id = ?3, state = 'active', stale_pending = 0, \
                      envelope = ?4, updated_at_ms = ?5 \
                 WHERE credential_id = ?1 AND record_version = ?6",
                rusqlite::params![
                    credential_id,
                    next_version as i64,
                    key_id_hex,
                    blob,
                    now,
                    current.record_version as i64
                ],
            )?;
            // Clear any dangling intent in the same txn (see `create`): an admin
            // overwrite with fresh valid tokens must clear the old intent, or boot
            // reconciliation's hash-mismatch check would later undo this re-login.
            if n > 0 {
                clear_intent_tx(tx, credential_id)?;
                delete_local_condition_tx(tx, credential_id)?;
                clear_plan_on_account_change_tx(
                    tx,
                    &audit_key,
                    credential_id,
                    Some(&current.identity),
                    &record.identity,
                    ctx,
                )?;
                clear_agent_ssh_state_tx(tx, credential_id)?;
                append_audit_tx(
                    tx,
                    &audit_key,
                    &AuditRecord {
                        op: ctx.op,
                        credential_id: Some(credential_id.to_string()),
                        payload_hash: Some(payload_hash_hex),
                        actor: ctx.actor.to_string(),
                        alarm: ctx.alarm,
                    },
                )?;
            }
            Ok(Some(n))
        })?;
        match changed {
            None => Err(StoreOpError::GatewayFixed {
                rule: crate::gateway::GatewayFixedRule::Kind,
            }),
            Some(0) => Err(StoreOpError::CasMismatch),
            Some(_) => Ok(()),
        }
    }

    /// Overwrite an existing record UNCONDITIONALLY (no CAS), re-sealing it at
    /// `current_version + 1` and resetting its state to `active`, while preserving an
    /// existing identity when the replacement does not provide one. This is the normal
    /// token-rotation path; callers that intentionally clear identity use
    /// [`Self::overwrite_unconditional_with_identity_policy_audited`].
    pub fn overwrite_unconditional_audited(
        &self,
        credential_id: &str,
        record: &VaultRecord,
        ctx: AuditCtx<'_>,
    ) -> Result<(), StoreOpError> {
        self.overwrite_unconditional_with_identity_policy_audited(credential_id, record, true, ctx)
    }

    /// Overwrite an existing record UNCONDITIONALLY (no CAS), re-sealing it at
    /// `current_version + 1` and resetting its state to `active`, with an explicit
    /// audit context. Fails [`StoreOpError::NotFound`] if the id is absent.
    ///
    /// When `preserve_existing_identity` is true and `record` has no identity, carries
    /// the existing identity into the replacement. Identity describes the account rather
    /// than the token, so re-importing rotated tokens must not erase account labelling.
    /// This preservation assumes the incoming token belongs to the SAME ACCOUNT as the
    /// retained label; when the adapter can derive both account ids, a mismatch is refused.
    /// A derivation result of `None` preserves the label: an undecodable token cannot
    /// contradict it, while refusing would block every non-JWT OpenAI credential.
    /// An undecryptable existing envelope is treated as no identity so repair still
    /// replaces corrupted material. Passing false makes an empty incoming identity an
    /// explicit clear.
    ///
    /// Unlike [`overwrite_cas_audited`], this reads the current version via `meta`
    /// (plaintext columns, NO decrypt) rather than `get`, so it works even when the
    /// current record is `needs_reauth` or quarantined — which is exactly the
    /// re-import case: an operator imported a credential from the wrong source (its
    /// refresh token is dead → `needs_reauth`) and is replacing it with the correct
    /// one. The handles table is untouched, so existing handles keep resolving to this
    /// id (no re-mint). The version bump + state reset + intent clear + audit entry all
    /// commit in ONE fenced transaction.
    pub fn overwrite_unconditional_with_identity_policy_audited(
        &self,
        credential_id: &str,
        record: &VaultRecord,
        preserve_existing_identity: bool,
        ctx: AuditCtx<'_>,
    ) -> Result<(), StoreOpError> {
        refuse_incoming_agent_ssh(record)?;
        refuse_short_term_bedrock_key(record)?;
        self.check_vault_transfer_key_writable(credential_id)?;
        let incoming = normalize_record_identity(record.clone());
        if let (Some(supplied), Some(derived)) = (
            incoming.identity.account_id.as_ref(),
            derived_account_id(&incoming),
        ) {
            if supplied != &derived {
                return Err(StoreOpError::SuppliedIdentityContradictsClaim {
                    credential_id: credential_id.to_string(),
                    supplied_account_id: supplied.clone(),
                    derived_account_id: derived,
                });
            }
        }
        validate_record_identity(&incoming)?;
        let incoming_account_id = preserve_existing_identity
            .then_some(())
            .filter(|_| incoming.identity.is_empty())
            .and_then(|_| derived_account_id(&incoming));
        let key_id_hex = self.key_id.to_hex();
        let now = now_ms();
        let audit_key = self.audit_key.clone();
        let payload_hash_hex = hex32(&audit::payload_fingerprint(
            &audit_key,
            record.payload.expose(),
        ));

        // Read the current version, seal at version+1, and update — ALL inside the
        // one fenced transaction, gated on `WHERE record_version = <the version we
        // just read>`. On the single writer connection this is atomic: nothing can
        // move the version between the read and the guarded update, so the "+1" can
        // never alias a concurrent refresh's own +1 (the lost-update bug a
        // read-outside-the-txn version + unguarded update would allow). "State-
        // unconditional" (works on needs_reauth/quarantined via the plaintext
        // version read, no decrypt) is preserved; only lost-update tolerance is
        // removed. A CasMismatch here would mean the row vanished mid-txn (a
        // concurrent delete), which cannot happen under the single writer, so the
        // guard is belt-and-suspenders that also documents the invariant.
        let outcome = self.fenced_write(|tx| {
            let existing: Option<(i64, Vec<u8>)> = tx
                .query_row(
                    "SELECT record_version, envelope FROM credentials WHERE credential_id = ?1",
                    rusqlite::params![credential_id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let Some((current_version, existing_envelope)) = existing else {
                return Ok(IdentityPolicyOverwriteOutcome::NotFound);
            };
            if (incoming.kind != CredentialKind::ApiKey || incoming.refresh_adapter.is_some())
                && gateway::has_settings(tx, credential_id)?
            {
                return Ok(IdentityPolicyOverwriteOutcome::GatewayFixedKind);
            }
            let next_version = (current_version as u64).saturating_add(1);

            let existing_record = envelope::open(
                &self.key,
                &existing_envelope,
                &RecordBinding {
                    credential_id,
                    record_version: current_version as u64,
                },
            )
            .ok()
            .and_then(|plaintext| VaultRecord::decode(&plaintext).ok());
            let existing_identity = existing_record
                .as_ref()
                .map(|existing| existing.identity.clone())
                .filter(|identity| identity.validate().is_ok())
                .map(RecordIdentity::normalized);
            let mut sealed = incoming.clone();
            if preserve_existing_identity && sealed.identity.is_empty() {
                if let Some(identity) = existing_identity.clone() {
                    if let (Some(retained_account_id), Some(incoming_account_id)) =
                        (identity.account_id.as_ref(), incoming_account_id.as_ref())
                    {
                        if retained_account_id != incoming_account_id {
                            return Ok(IdentityPolicyOverwriteOutcome::AccountMismatch {
                                retained_account_id: retained_account_id.clone(),
                                incoming_account_id: incoming_account_id.clone(),
                            });
                        }
                    }
                    sealed.identity = identity;
                }
            }
            retain_detected_plan(&mut sealed, existing_record.as_ref());
            sealed.record_version = next_version;
            // seal_record is pure crypto (no DB), safe to call inside the txn.
            let blob = self
                .seal_record(credential_id, &sealed)
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;

            let n = tx.execute(
                "UPDATE credentials \
                  SET record_version = ?2, key_id = ?3, state = 'active', stale_pending = 0, \
                      envelope = ?4, updated_at_ms = ?5 \
                 WHERE credential_id = ?1 AND record_version = ?6",
                rusqlite::params![
                    credential_id,
                    next_version as i64,
                    key_id_hex,
                    blob,
                    now,
                    current_version
                ],
            )?;
            if n > 0 {
                clear_intent_tx(tx, credential_id)?;
                delete_local_condition_tx(tx, credential_id)?;
                clear_agent_ssh_state_tx(tx, credential_id)?;
                append_audit_tx(
                    tx,
                    &audit_key,
                    &AuditRecord {
                        op: ctx.op,
                        credential_id: Some(credential_id.to_string()),
                        payload_hash: Some(payload_hash_hex),
                        actor: ctx.actor.to_string(),
                        alarm: ctx.alarm,
                    },
                )?;
            }
            if n > 0 {
                clear_plan_on_account_change_tx(
                    tx,
                    &audit_key,
                    credential_id,
                    existing_identity.as_ref(),
                    &sealed.identity,
                    ctx,
                )?;
            }
            Ok(IdentityPolicyOverwriteOutcome::Updated(n))
        })?;
        match outcome {
            IdentityPolicyOverwriteOutcome::NotFound => Err(StoreOpError::NotFound),
            IdentityPolicyOverwriteOutcome::GatewayFixedKind => Err(StoreOpError::GatewayFixed {
                rule: crate::gateway::GatewayFixedRule::Kind,
            }),
            IdentityPolicyOverwriteOutcome::AccountMismatch {
                retained_account_id,
                incoming_account_id,
            } => Err(StoreOpError::AccountIdentityMismatch {
                credential_id: credential_id.to_string(),
                retained_account_id,
                incoming_account_id,
            }),
            IdentityPolicyOverwriteOutcome::Updated(0) => Err(StoreOpError::CasMismatch),
            IdentityPolicyOverwriteOutcome::Updated(_) => Ok(()),
        }
    }

    /// Replace only non-secret account identity, preserving every secret field and the
    /// record's lifecycle state. The envelope must be re-sealed, so `record_version`
    /// advances and lets consumers treat the identity update as fresh record metadata.
    /// This opens the envelope without the normal serving-state gate: identity is safe
    /// to correct on `needs_reauth` or `retired` records, but an undecryptable record
    /// cannot be labelled because there is no trustworthy material to preserve.
    pub fn set_identity_audited(
        &self,
        credential_id: &str,
        identity: crate::record::RecordIdentity,
        ctx: AuditCtx<'_>,
    ) -> Result<(), StoreOpError> {
        let identity = identity.normalized();
        identity.validate().map_err(StoreOpError::Encode)?;
        self.check_vault_transfer_key_writable(credential_id)?;
        let key_id_hex = self.key_id.to_hex();
        let now = now_ms();
        let audit_key = self.audit_key.clone();
        let typed_error = std::cell::RefCell::new(None);
        let outcome = self.fenced_write(|tx| {
            let existing: Option<(i64, Vec<u8>)> = tx
                .query_row(
                    "SELECT record_version, envelope FROM credentials WHERE credential_id = ?1",
                    rusqlite::params![credential_id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let Some((current_version, envelope)) = existing else {
                return Ok(None);
            };
            let plaintext = match envelope::open(
                &self.key,
                &envelope,
                &RecordBinding {
                    credential_id,
                    record_version: current_version as u64,
                },
            ) {
                Ok(plaintext) => plaintext,
                Err(error) => {
                    *typed_error.borrow_mut() = Some(StoreOpError::Decrypt(error));
                    return Err(rusqlite::Error::InvalidQuery);
                }
            };
            let record = match VaultRecord::decode(&plaintext) {
                Ok(record) => record,
                Err(error) => {
                    *typed_error.borrow_mut() = Some(StoreOpError::Corrupt(error.to_string()));
                    return Err(rusqlite::Error::InvalidQuery);
                }
            };
            let next_version = (current_version as u64).saturating_add(1);
            let mut updated = record.clone().with_identity(identity.clone());
            retain_detected_plan(&mut updated, Some(&record));
            updated.record_version = next_version;
            let payload_hash_hex = hex32(&audit::payload_fingerprint(
                &audit_key,
                updated.payload.expose(),
            ));
            let blob = self
                .seal_record(credential_id, &updated)
                .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
            let changed = tx.execute(
                "UPDATE credentials SET record_version = ?2, key_id = ?3, envelope = ?4, \
                     updated_at_ms = ?5 WHERE credential_id = ?1 AND record_version = ?6",
                rusqlite::params![
                    credential_id,
                    next_version as i64,
                    key_id_hex,
                    blob,
                    now,
                    current_version,
                ],
            )?;
            if changed > 0 {
                clear_plan_on_account_change_tx(
                    tx,
                    &audit_key,
                    credential_id,
                    Some(&record.identity),
                    &updated.identity,
                    ctx,
                )?;
                append_audit_tx(
                    tx,
                    &audit_key,
                    &AuditRecord {
                        op: AuditOp::SetIdentity,
                        credential_id: Some(credential_id.to_string()),
                        payload_hash: Some(payload_hash_hex),
                        actor: ctx.actor.to_string(),
                        alarm: ctx.alarm,
                    },
                )?;
            }
            Ok(Some(changed))
        });
        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(error) => match typed_error.into_inner() {
                Some(typed) => return Err(typed),
                None => return Err(StoreOpError::from(error)),
            },
        };
        match outcome {
            None => Err(StoreOpError::NotFound),
            Some(0) => Err(StoreOpError::CasMismatch),
            Some(_) => Ok(()),
        }
    }

    /// Overwrite under CAS, auditing as a vault-owned `Overwrite`. Convenience
    /// wrapper for callers/tests that do not specify an audit context.
    pub fn overwrite_cas(
        &self,
        credential_id: &str,
        record: &VaultRecord,
        expected_payload_hash: &[u8; 32],
    ) -> Result<(), StoreOpError> {
        self.overwrite_cas_audited(
            credential_id,
            record,
            expected_payload_hash,
            AuditCtx::vault(AuditOp::Overwrite),
        )
    }

    /// Read and decrypt a record. Fails closed: a quarantined (`corrupt`) row is
    /// [`StoreOpError::Quarantined`]; `needs_reauth` and `retired` rows are both
    /// [`StoreOpError::NeedsReauth`] so consumers need no new recovery branch; a row
    /// that fails to decrypt or parse is
    /// QUARANTINED (its state flipped to `corrupt`) and returned as a typed error.
    /// Never panics, never returns plaintext on failure.
    pub fn get(&self, credential_id: &str) -> Result<VaultRecord, StoreOpError> {
        self.get_with_stale_pending(credential_id)
            .map(|(record, _)| record)
    }

    /// Read a record with the local stale marker that was observed beside its state.
    ///
    /// This stays crate-private because `stale_pending` is a refresh instruction for
    /// the engine, not credential metadata for callers to interpret.
    pub(crate) fn get_with_stale_pending(
        &self,
        credential_id: &str,
    ) -> Result<(VaultRecord, StaleMark), StoreOpError> {
        let read = self.get_with_stale_pending_and_digest(credential_id)?;
        Ok((read.record, read.mark))
    }

    /// Read only the row lifetime admitted earlier. A removed-and-recreated id is
    /// indistinguishable from an unknown id, even if its version number is reused.
    pub fn get_snapshot(
        &self,
        credential_id: &str,
        incarnation: &str,
    ) -> Result<StoredRead, StoreOpError> {
        self.read_snapshot(credential_id, Some(incarnation))
    }

    /// The same read as [`Self::get_with_stale_pending`], plus the SHA-256 of the exact
    /// encrypted bytes it decrypted.
    ///
    /// The digest is taken from the blob this read already holds, so it describes the
    /// same row the record came from; nothing is read twice and nothing is recomputed
    /// from the decrypted record. A caller that must recognise "these stored bytes"
    /// across a delete and re-create (which restarts `record_version` at 1) can compare
    /// it, and one that records it as evidence names bytes rather than a number another
    /// write could reuse.
    pub(crate) fn get_with_stale_pending_and_digest(
        &self,
        credential_id: &str,
    ) -> Result<StoredRead, StoreOpError> {
        self.read_snapshot(credential_id, None)
    }

    fn read_snapshot(
        &self,
        credential_id: &str,
        expected_incarnation: Option<&str>,
    ) -> Result<StoredRead, StoreOpError> {
        let row = self
            .store
            .with_conn(|c| {
                c.query_row(
                    "SELECT record_version, state, stale_pending, envelope, updated_at_ms, incarnation \
                     FROM credentials WHERE credential_id = ?1",
                    rusqlite::params![credential_id],
                    |r| {
                        let version: i64 = r.get(0)?;
                        let state: String = r.get(1)?;
                        let stale_pending: i64 = r.get(2)?;
                        let blob: Vec<u8> = r.get(3)?;
                        let updated_at_ms: i64 = r.get(4)?;
                        let incarnation: String = r.get(5)?;
                        Ok((version, state, stale_pending, blob, updated_at_ms, incarnation))
                    },
                )
                .map(Some)
                .or_else(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => Ok(None),
                    other => Err(other),
                })
            })
            .map_err(StoreOpError::from)?;

        let (version, state, stale_pending, blob, updated_at_ms, incarnation) =
            row.ok_or(StoreOpError::NotFound)?;
        if expected_incarnation.is_some_and(|expected| expected != incarnation) {
            return Err(StoreOpError::NotFound);
        }
        let (record, pending) = self.decode_record_row(
            credential_id,
            (version, &incarnation),
            &state,
            stale_pending,
            &blob,
        )?;
        Ok(StoredRead {
            record,
            incarnation,
            mark: StaleMark {
                pending,
                record_written_at_ms: updated_at_ms,
            },
            stored_digest_hex: sha256_hex_of_bytes(&blob),
        })
    }

    pub(super) fn decode_record_row(
        &self,
        credential_id: &str,
        identity: (i64, &str),
        state: &str,
        stale_pending: i64,
        blob: &[u8],
    ) -> Result<(VaultRecord, bool), StoreOpError> {
        let (version, incarnation) = identity;
        match RecordState::from_str(state) {
            RecordState::Corrupt => return Err(StoreOpError::Quarantined),
            RecordState::NeedsReauth | RecordState::Retired => {
                return Err(StoreOpError::NeedsReauth)
            }
            RecordState::Active => {}
        }

        let binding = RecordBinding {
            credential_id,
            record_version: version as u64,
        };
        let plaintext = match envelope::open(&self.key, blob, &binding) {
            Ok(pt) => pt,
            Err(e) => {
                // Per-record quarantine: a single undecryptable row is isolated so
                // the rest of the vault keeps serving. Best-effort state flip — a
                // failure to mark must not itself panic the read path.
                if matches!(
                    self.quarantine_in_incarnation(credential_id, version as u64, incarnation),
                    Err(StoreOpError::NotFound)
                ) {
                    return Err(StoreOpError::NotFound);
                }
                return Err(StoreOpError::Decrypt(e));
            }
        };
        match VaultRecord::decode(&plaintext) {
            Ok(record) => Ok((record, stale_pending != 0)),
            Err(e) => {
                if matches!(
                    self.quarantine_in_incarnation(credential_id, version as u64, incarnation),
                    Err(StoreOpError::NotFound)
                ) {
                    return Err(StoreOpError::NotFound);
                }
                Err(StoreOpError::Corrupt(e.to_string()))
            }
        }
    }

    /// Mark a record `needs_reauth` (authoritative revoke / reported auth failure)
    /// and clear any dangling refresh intent for it, with an explicit audit context —
    /// the state flip, the intent clear, and the audit entry all commit atomically.
    /// A no-op (Ok) if the id is absent.
    ///
    /// Clears the intent because an authoritative revoke supersedes any in-flight
    /// refresh: leaving a stale intent would let boot reconciliation reason about a
    /// credential the operator has already invalidated.
    pub fn invalidate_audited(
        &self,
        credential_id: &str,
        ctx: AuditCtx<'_>,
    ) -> Result<(), StoreOpError> {
        self.set_state(credential_id, RecordState::NeedsReauth, true, Some(ctx))
    }

    /// Version-gated invalidate for a consumer-reported auth failure: mark the
    /// credential `needs_reauth` (and clear any dangling intent) ONLY if its current
    /// `record_version` still equals `expected_version` — the version the consumer was
    /// actually served. Returns `true` if it invalidated, `false` (a silent, successful
    /// no-op) if the version has since moved on.
    ///
    /// This closes a false-invalidation race: a consumer reports a 401 for the token it
    /// held at version N, but the vault has meanwhile refreshed to N+1 (a fresh, working
    /// token); the stale report must NOT kill the healthy N+1 credential. Because every
    /// durable mutation is serialized through the store's single writer connection, this
    /// CAS and a concurrent `commit_refresh` can never interleave: report-first flips
    /// state at version N and the refresh's `WHERE record_version = N` still overwrites it
    /// back to active N+1; refresh-first bumps to N+1 and this CAS matches 0 rows → no-op.
    /// Either ordering converges on the fresh token. It also neuters malicious
    /// invalidation: a consumer can only ever kill the exact version it was served.
    ///
    /// A no-op (Ok(false)) if the id is absent.
    pub fn invalidate_if_version_audited(
        &self,
        credential_id: &str,
        expected_version: u64,
        ctx: AuditCtx<'_>,
    ) -> Result<bool, StoreOpError> {
        self.invalidate_if_version_reported(credential_id, expected_version, ctx, None)
    }

    /// As [`Self::invalidate_if_version_audited`], additionally recording WHY.
    ///
    /// `observation` describes what the caller saw, and is written to `auth_events`
    /// in the same transaction WHETHER OR NOT the version matched. That is the point:
    /// a report naming a superseded version is deliberately a no-op on the credential,
    /// and previously left nothing behind, so the case where a consumer is acting on
    /// stale state -- the one worth investigating -- was the one with no record. The
    /// row's `applied` column distinguishes the two outcomes.
    pub fn invalidate_if_version_reported(
        &self,
        credential_id: &str,
        expected_version: u64,
        ctx: AuditCtx<'_>,
        observation: Option<AuthObservation<'_>>,
    ) -> Result<bool, StoreOpError> {
        let incarnation = self.credential_incarnation(credential_id)?;
        self.invalidate_in_incarnation(
            credential_id,
            expected_version,
            &incarnation,
            ctx,
            observation,
        )
    }

    /// Apply feedback only to the row lifetime that admitted the request.
    pub fn invalidate_in_incarnation(
        &self,
        credential_id: &str,
        expected_version: u64,
        incarnation: &str,
        ctx: AuditCtx<'_>,
        observation: Option<AuthObservation<'_>>,
    ) -> Result<bool, StoreOpError> {
        let now = now_ms();
        let audit_key = self.audit_key.clone();
        let changed = self.fenced_write_unless_transfer_key_protected(credential_id, |tx| {
            if !credential_incarnation_matches(tx, credential_id, incarnation)? {
                return Ok(None);
            }
            // `state = active` makes this a STATE TRANSITION rather than a
            // repeatable write, and that is what bounds the audit chain here.
            //
            // The version guard alone does not: invalidating does not bump
            // record_version, so a consumer reporting the same version twice
            // matched twice, and every match appends to a chain that is
            // append-only by design and must never be trimmed. Measured before
            // this guard existed: eight identical reports produced eight
            // `report_auth_failure` entries, seven of which changed nothing --
            // the credential was already `needs_reauth` after the first.
            //
            // With the clause, a repeat matches zero rows and audits nothing,
            // while the FIRST report still audits exactly as before. The
            // diagnostic record of the repeats is not lost: `auth_events` records
            // every report either way, which is what that table is for, and it is
            // bounded per credential where the chain cannot be.
            let n = tx.execute(
                "UPDATE credentials SET state = ?2, updated_at_ms = ?3 \
                 WHERE credential_id = ?1 AND record_version = ?4 AND state = 'active'",
                rusqlite::params![
                    credential_id,
                    RecordState::NeedsReauth.as_str(),
                    now,
                    expected_version as i64
                ],
            )?;
            if let Some(obs) = observation {
                append_auth_event_tx(tx, credential_id, &obs, Some(expected_version), n > 0)?;
            }
            if n > 0 {
                // Same version still current: this is an authoritative revoke, so clear
                // any dangling intent and audit it, exactly like invalidate_audited.
                clear_intent_tx(tx, credential_id)?;
                append_audit_tx(
                    tx,
                    &audit_key,
                    &AuditRecord {
                        op: ctx.op,
                        credential_id: Some(credential_id.to_string()),
                        payload_hash: None,
                        actor: ctx.actor.to_string(),
                        alarm: ctx.alarm,
                    },
                )?;
            }
            Ok(Some(n))
        })?;
        Ok(changed.ok_or(StoreOpError::NotFound)? > 0)
    }

    /// Mark only the current token stale after a consumer reports it refused.
    ///
    /// The version fence protects a token freshly replaced by a concurrent refresh:
    /// a report for version N cannot set the local marker on version N+1. The marker
    /// deliberately stays outside the envelope and does not advance `record_version`,
    /// because it is a local refresh instruction rather than a changed provider fact.
    pub fn mark_stale_if_version_reported(
        &self,
        credential_id: &str,
        expected_version: u64,
        ctx: AuditCtx<'_>,
        observation: AuthObservation<'_>,
    ) -> Result<bool, StoreOpError> {
        let incarnation = self.credential_incarnation(credential_id)?;
        self.mark_stale_in_incarnation(
            credential_id,
            expected_version,
            &incarnation,
            ctx,
            observation,
        )
    }

    /// Mark stale only within the row lifetime that admitted the request.
    pub fn mark_stale_in_incarnation(
        &self,
        credential_id: &str,
        expected_version: u64,
        incarnation: &str,
        ctx: AuditCtx<'_>,
        observation: AuthObservation<'_>,
    ) -> Result<bool, StoreOpError> {
        let audit_key = self.audit_key.clone();
        let changed = self.fenced_write_unless_transfer_key_protected(credential_id, |tx| {
            if !credential_incarnation_matches(tx, credential_id, incarnation)? {
                return Ok(None);
            }
            // A repeated report for the same version has already instructed the
            // next read to refresh. Treat it as no new state transition so the
            // append-only audit chain remains bounded; auth_events still records it.
            let n = tx.execute(
                "UPDATE credentials SET stale_pending = 1 \
                     WHERE credential_id = ?1 AND record_version = ?2 AND stale_pending = 0",
                rusqlite::params![credential_id, expected_version as i64],
            )?;
            append_auth_event_tx(
                tx,
                credential_id,
                &observation,
                Some(expected_version),
                n > 0,
            )?;
            if n > 0 {
                append_audit_tx(
                    tx,
                    &audit_key,
                    &AuditRecord {
                        op: ctx.op,
                        credential_id: Some(credential_id.to_string()),
                        payload_hash: None,
                        actor: ctx.actor.to_string(),
                        alarm: ctx.alarm,
                    },
                )?;
            }
            Ok(Some(n))
        })?;
        Ok(changed.ok_or(StoreOpError::NotFound)? > 0)
    }

    /// Invalidate, auditing as a vault-owned `Invalidate`. Convenience wrapper for
    /// callers/tests that do not specify an audit context.
    pub fn invalidate(&self, credential_id: &str) -> Result<(), StoreOpError> {
        self.invalidate_audited(credential_id, AuditCtx::vault(AuditOp::Invalidate))
    }

    /// Retire a credential only from the operator's logout path: mark an `active` or
    /// `needs_reauth` record `retired`, clear any dangling refresh intent, and revoke
    /// every live handle in one fenced transaction.
    ///
    /// A retirement is an operator acknowledgement, not a discovery of bad material.
    /// `Corrupt` is therefore deliberately excluded: clearing its health contribution
    /// would hide a vault-observed integrity failure. `Retired` is likewise a no-op so
    /// repeated logout requests do not grow the untrimmable audit chain.
    pub fn retire_and_revoke_all_audited(
        &self,
        credential_id: &str,
        ctx: AuditCtx<'_>,
    ) -> Result<InvalidateOutcome, StoreOpError> {
        self.check_vault_transfer_key_writable(credential_id)?;
        let now = now_ms();
        let audit_key = self.audit_key.clone();
        self.fenced_write(|tx| {
            let state_changed = tx.execute(
                "UPDATE credentials SET state = ?2, updated_at_ms = ?3 \
                 WHERE credential_id = ?1 AND state IN (?4, ?5)",
                rusqlite::params![
                    credential_id,
                    RecordState::Retired.as_str(),
                    now,
                    RecordState::Active.as_str(),
                    RecordState::NeedsReauth.as_str(),
                ],
            )? > 0;
            let intent_cleared = clear_intent_tx(tx, credential_id)? > 0;
            let revoked = tx.execute(
                "UPDATE handles SET revoked = 1 \
                 WHERE credential_id = ?1 AND revoked = 0",
                rusqlite::params![credential_id],
            )?;
            if state_changed || intent_cleared {
                append_audit_tx(
                    tx,
                    &audit_key,
                    &AuditRecord {
                        op: ctx.op,
                        credential_id: Some(credential_id.to_string()),
                        payload_hash: None,
                        actor: ctx.actor.to_string(),
                        alarm: ctx.alarm,
                    },
                )?;
            }
            if revoked > 0 {
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
            }
            Ok(InvalidateOutcome {
                state_changed,
                intent_cleared,
                handles_revoked: revoked,
            })
        })
        .map_err(StoreOpError::from)
    }

    /// The COMPOUND authoritative invalidate: mark `needs_reauth`, clear any
    /// dangling refresh intent, AND revoke every live handle for the credential —
    /// all in ONE fenced transaction, with both audit entries (`Invalidate` and,
    /// when any handles were live, `RevokeHandle`) inside it.
    ///
    /// This exists because invalidate-then-revoke as two calls is crash-partial: a
    /// crash between them leaves a dead credential still resolvable by handle. The
    /// offline CLI performs the same pair; the online admin surface additionally
    /// must not let a relay reorder or split the two halves, so the compound op is
    /// the only online shape.
    ///
    /// REPORTS WHAT IT ACTUALLY CHANGED, and the state flip is guarded so a repeat
    /// is a true no-op. Without the guard this always "succeeded": running it on an
    /// already-invalidated credential rewrote the same state, revoked nothing, and
    /// appended an `Invalidate` audit entry recording that nothing happened. An
    /// operator seeing an unchanged listing after a success message reasonably
    /// concludes the command is broken — observed live, three consecutive invalidations
    /// against one already-dead credential, three identical successes.
    ///
    /// Suppressing the no-op audit entry matters on its own: the chain is
    /// tamper-evident and therefore UNTRIMMABLE, so an operator (or a script)
    /// repeating an invalidation would grow it without bound with entries that record
    /// no mutation. The same guard was added to the consumer-driven path for the same
    /// reason; this is the operator-driven half of it.
    pub fn invalidate_and_revoke_all_audited(
        &self,
        credential_id: &str,
        ctx: AuditCtx<'_>,
    ) -> Result<InvalidateOutcome, StoreOpError> {
        self.check_vault_transfer_key_writable(credential_id)?;
        let now = now_ms();
        let audit_key = self.audit_key.clone();
        self.fenced_write(|tx| {
            // Excluding needs_reauth and corrupt makes this a transition rather than a write: the
            // rows-changed count is then the answer to "did this do anything",
            // which is what both the audit decision and the operator message need.
            let state_changed = tx.execute(
                "UPDATE credentials SET state = ?2, updated_at_ms = ?3 \
                 WHERE credential_id = ?1 AND state NOT IN (?2, 'corrupt')",
                rusqlite::params![credential_id, RecordState::NeedsReauth.as_str(), now],
            )? > 0;
            let intent_cleared = clear_intent_tx(tx, credential_id)? > 0;
            let revoked = tx.execute(
                "UPDATE handles SET revoked = 1 \
                 WHERE credential_id = ?1 AND revoked = 0",
                rusqlite::params![credential_id],
            )?;
            // Audit the mutation, not the request. An invalidation that finds the
            // credential already dead with no live handles mutated nothing, and an audit
            // entry claiming otherwise is a false record in a chain whose
            // whole value is that its entries are true.
            if state_changed || intent_cleared {
                append_audit_tx(
                    tx,
                    &audit_key,
                    &AuditRecord {
                        op: ctx.op,
                        credential_id: Some(credential_id.to_string()),
                        payload_hash: None,
                        actor: ctx.actor.to_string(),
                        alarm: ctx.alarm,
                    },
                )?;
            }
            if revoked > 0 {
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
            }
            Ok(InvalidateOutcome {
                state_changed,
                intent_cleared,
                handles_revoked: revoked,
            })
        })
        .map_err(StoreOpError::from)
    }

    /// PERMANENTLY remove a credential: delete the row, its refresh intent, and its
    /// handle rows, appending a `Remove` audit entry — all in ONE fenced transaction.
    /// The audit chain keeps the credential's full history (append-only; removal is
    /// itself an entry), so this deletes serving state, never forensics. For retiring
    /// an account or cleaning up a mistaken id; a temporary stop is `logout`
    /// (retire + revoke, reversible). Returns [`StoreOpError::NotFound`] when the
    /// id has no row, so a typo'd remove is loud instead of a silent no-op.
    /// Returns how many live handles were removed, because a consumer holding one
    /// cannot be told by the vault. Handles are bearer capabilities: nothing records
    /// WHO holds one, so removal cannot notify anybody, and a consumer's next fetch
    /// gets `not_found` with no explanation of why. Reporting the count gives the
    /// operator the one fact that says "go check your consumers" at the moment they
    /// can still act on it -- observed live, a removed credential left a stale entry
    /// in a consumer's handle file and blinded its sibling accounts until noticed.
    /// THERE IS NO UN-REMOVE, AND UNLIKE `reactivate` THAT IS IMPOSSIBLE RATHER THAN
    /// DECLINED. The distinction matters to a reader deciding whether to add one.
    ///
    /// `reactivate` exists because `needs_reauth` and `retired` only change a VERDICT
    /// while the sealed material stays on disk, so the verdict can be contradicted. This DELETEs the
    /// credentials row, and the sealed envelope is the only copy of the secret the vault
    /// ever had -- for a `github_app` key, the only copy anywhere, since the PEM is
    /// shredded after deposit by custody rule. After this commits there is nothing left
    /// to restore: the audit chain retains the HISTORY of the credential, never its bytes.
    ///
    /// So the repair for a mistaken `remove` is a fresh deposit of fresh material, which
    /// for a platform-issued key means an operator ceremony. That is the cost of the verb
    /// and it is why `logout` or `invalidate` is the reversible sibling an operator
    /// should reach for first -- stated here because now that ONE inverse exists in this file,
    /// an absent one stops looking deliberate.
    pub fn remove_audited(
        &self,
        credential_id: &str,
        ctx: AuditCtx<'_>,
    ) -> Result<usize, StoreOpError> {
        self.check_vault_transfer_key_writable(credential_id)?;
        let audit_key = self.audit_key.clone();
        let (removed, handles) = self.fenced_write(|tx| {
            // Count before deleting the parent: foreign-key cascades may remove the rows.
            let categories: usize = tx.query_row(
                "SELECT COUNT(*) FROM credential_categories WHERE credential_id = ?1",
                [credential_id],
                |row| row.get(0),
            )?;
            clear_agent_ssh_state_tx(tx, credential_id)?;
            let n = tx.execute(
                "DELETE FROM credentials WHERE credential_id = ?1",
                rusqlite::params![credential_id],
            )?;
            let mut handles = 0usize;
            if n > 0 {
                clear_intent_tx(tx, credential_id)?;
                // Handle rows are deleted outright (not just revoked): the credential
                // is gone, so retaining hash rows would only grow an unusable table.
                // The mint/revoke history stays in the audit chain.
                handles = tx.query_row(
                    "SELECT COUNT(*) FROM handles WHERE credential_id = ?1 AND revoked = 0",
                    [credential_id],
                    |row| row.get(0),
                )?;
                tx.execute(
                    "DELETE FROM handles WHERE credential_id = ?1",
                    rusqlite::params![credential_id],
                )?;
                // Do not depend on connection-level foreign-key enforcement: category
                // rows must not survive an id that can later be deposited again.
                tx.execute(
                    "DELETE FROM credential_categories WHERE credential_id = ?1",
                    rusqlite::params![credential_id],
                )?;
                for _ in 0..categories {
                    bump_grants_generation_tx(tx)?;
                }
                if read_schema_version(tx)? >= 16 {
                    tx.execute(
                        "DELETE FROM credential_plan_tiers WHERE credential_id = ?1",
                        [credential_id],
                    )?;
                }
                // The same holds for provider ids: a later deposit of this id must
                // start with none. Removal writes no `set_providers` entry; its own
                // audit row below records the whole credential going.
                if read_schema_version(tx)? >= PROVIDER_ID_SCHEMA_VERSION {
                    tx.execute(
                        "DELETE FROM credential_provider_ids WHERE credential_id = ?1",
                        rusqlite::params![credential_id],
                    )?;
                }
                // Explicit cleanup also covers connections with foreign keys disabled.
                if read_schema_version(tx)? >= GATEWAY_SETTINGS_SCHEMA_VERSION {
                    tx.execute(
                        "DELETE FROM credential_gateway_settings WHERE credential_id = ?1",
                        [credential_id],
                    )?;
                }
                delete_local_condition_tx(tx, credential_id)?;
                // Diagnostic events go WITH the credential, and this is the one
                // place they can go.
                //
                // `auth_events` is capped per credential, but the trim runs on
                // insert -- and a removed credential never gets another insert, so
                // without this its rows would be the one thing in the store nothing
                // can ever reclaim. Small per removal and driven by an operator
                // rather than by traffic, so this is tidiness rather than a bound,
                // but it is also the difference between `ck auth events` showing a
                // live vault and showing a graveyard.
                //
                // Nothing forensic is lost: the chain holds this credential's whole
                // history including the removal itself, and it is the chain that is
                // evidence -- these rows are explanation, and there is nothing left
                // to explain once the credential is gone. A removal ordered BECAUSE
                // a credential was failing is the case to think about, and there the
                // events were read before the removal, not after.
                tx.execute(
                    "DELETE FROM auth_events WHERE credential_id = ?1",
                    rusqlite::params![credential_id],
                )?;
                // The record of which materials were issued to members goes with the
                // material. A later credential under this id restarts at version 1, and
                // its first issue to a member must be audited, not matched against the
                // removed record's rows. The `remote_issue` audit rows themselves stay
                // in the chain. Migration 23 added the table.
                if read_schema_version(tx)? >= 23 {
                    tx.execute(
                        "DELETE FROM remote_issue_seen WHERE credential_id = ?1",
                        rusqlite::params![credential_id],
                    )?;
                }
                append_audit_tx(
                    tx,
                    &audit_key,
                    &AuditRecord {
                        op: ctx.op,
                        credential_id: Some(credential_id.to_string()),
                        payload_hash: None,
                        actor: ctx.actor.to_string(),
                        alarm: ctx.alarm,
                    },
                )?;
            }
            Ok((n, handles))
        })?;
        if removed == 0 {
            return Err(StoreOpError::NotFound);
        }
        Ok(handles)
    }

    /// Quarantine a record (`corrupt`). Used by the read path on a decrypt/parse
    /// failure; idempotent. Does NOT clear a refresh intent or audit — quarantine is
    /// an internal integrity flip, not a recorded mutation, and a corrupt record's
    /// intent (if any) is for reconciliation to resolve, not for this path to discard.
    /// ITS INVERSE EXISTS UNDER A DIFFERENT NAME, which is worth saying because a reader
    /// counting absences will otherwise reach the wrong conclusion in one of two ways.
    ///
    /// There is no un-quarantine, and `reactivate_audited` refuses `Corrupt` on purpose:
    /// this state means the sealed bytes failed their own integrity check, and no
    /// assertion makes an undecryptable envelope decrypt. But the record is NOT lost --
    /// `put --replace` (overwrite-unconditional) writes fresh material into the same id,
    /// clearing the state as a side effect and keeping the credential's audit lineage and
    /// its handles.
    ///
    /// THE EXPENSIVE MISREADING IS THE QUIET ONE. A reader who concludes a corrupt record
    /// is unrecoverable reaches for `remove`, which DELETEs the row and its handles -- so
    /// every consumer holding a handle loses it, and for a platform-issued key the repair
    /// becomes a fresh operator ceremony rather than one command. Replace repairs in
    /// place; remove escalates a fixable state into a ceremony.
    ///
    /// So the three shapes of a missing inverse each need their own note: DECLINED (an
    /// inverse that could be built but is refused on purpose, like the absent un-revoke
    /// for handles), IMPOSSIBLE (`remove` -- the bytes are gone), and RENAMED (this one
    /// -- it exists, under a name that does not look like an inverse).
    pub fn quarantine(&self, credential_id: &str) -> Result<(), StoreOpError> {
        self.set_state(credential_id, RecordState::Corrupt, false, None)
    }

    /// Quarantine only the exact record version the reader inspected. A concurrent
    /// refresh or admin replacement must not let a stale integrity decision poison the
    /// newly-written credential.
    pub fn quarantine_if_version(
        &self,
        credential_id: &str,
        expected_version: u64,
    ) -> Result<bool, StoreOpError> {
        let incarnation = self.credential_incarnation(credential_id)?;
        self.quarantine_in_incarnation(credential_id, expected_version, &incarnation)
    }

    /// Quarantine a snapshot without poisoning a removed-and-recreated credential.
    pub fn quarantine_in_incarnation(
        &self,
        credential_id: &str,
        expected_version: u64,
        incarnation: &str,
    ) -> Result<bool, StoreOpError> {
        let now = now_ms();
        let changed = self.fenced_write_unless_transfer_key_protected(credential_id, |tx| {
            if !credential_incarnation_matches(tx, credential_id, incarnation)? {
                return Ok(None);
            }
            tx.execute(
                "UPDATE credentials SET state = 'corrupt', updated_at_ms = ?1
                 WHERE credential_id = ?2 AND record_version = ?3",
                rusqlite::params![now, credential_id, expected_version],
            )
            .map(Some)
        })?;
        Ok(changed.ok_or(StoreOpError::NotFound)? == 1)
    }

    /// Mark a record `needs_reauth` but RETAIN its refresh intent. Used by
    /// reconciliation when a non-mutating validity check could not be run (transient
    /// network): the record fails closed now, but the surviving intent lets a later
    /// retry re-check and restore the credential without a forced re-login.
    pub fn mark_needs_reauth_retaining_intent(
        &self,
        credential_id: &str,
    ) -> Result<(), StoreOpError> {
        self.set_state(credential_id, RecordState::NeedsReauth, false, None)
    }

    /// Clear `needs_reauth` or `retired` back to active WITHOUT touching the stored
    /// material.
    ///
    /// THE REPAIR PATH FOR A VERDICT THAT WAS WRONG. `needs_reauth` is a claim about the
    /// OUTSIDE WORLD -- a provider rejected us, or a consumer said one did -- and the
    /// outside world can be misreported. On 2026-08-17 a consumer relayed GitHub's 403
    /// ("this token is valid and lacks one permission") as an auth failure, and a
    /// seconds-old, perfectly good App credential went dead.
    ///
    /// Without this verb that state was UNRECOVERABLE for the class it hit hardest.
    /// GitHub App keys are shredded after deposit by the vault's own custody rule, so
    /// the vault holds the only copy: `put --replace` needs a PEM nobody has, and no
    /// login flow exists to re-mint one. Repairing material the vault already held
    /// intact would have required a fresh key from GitHub and an operator at a browser.
    /// A consumer's mistaken report could force a human ceremony.
    ///
    /// ONLY FROM `NeedsReauth` OR `Retired`, never from `Corrupt`, and the distinction is
    /// the whole safety argument. Both allowed states are verdicts about serving, while
    /// Corrupt is a claim about OUR OWN BYTES -- they failed to decrypt,
    /// or the payload was empty -- which this vault verified itself and which clearing
    /// cannot fix; it would only put known-broken bytes back into service. Reactivating a
    /// corrupt record is refused rather than silently ignored.
    ///
    /// SELF-CORRECTING BY CONSTRUCTION, which is why it is safe to expose. The operator
    /// asserts the material is good; the vault verifies on next use. If the credential
    /// really is dead, a refreshable record's next `get` gets `InvalidGrant` from the
    /// provider and returns to `needs_reauth` on its own, and a static record's consumer
    /// reports again. The cost of a wrong assertion is one failed call, not a bad state
    /// that persists.
    ///
    /// Guarded as a TRANSITION: reactivating an already-active credential changes nothing
    /// and writes nothing, so a retry loop cannot append to the untrimmable audit chain.
    pub fn reactivate_audited(
        &self,
        credential_id: &str,
        ctx: AuditCtx<'_>,
    ) -> Result<bool, StoreOpError> {
        // Reactivation is the one state op that would put the transfer key back into
        // service, so it is refused by the fence even when the key is already `Active`
        // and the transition would change nothing: the answer to "reactivate the transfer
        // key" must be the named refusal, not a quiet success an operator could read as
        // their own repair. The off-`Active` recovery is `ck auth transfer init --replace`.
        self.check_vault_transfer_key_writable(credential_id)?;
        if crate::federation::is_vault_transfer_id(credential_id) {
            return Err(StoreOpError::TransferKeyProtected);
        }
        let now = now_ms();
        let audit_key = self.audit_key.clone();
        self.fenced_write(|tx| {
            // The state predicate is IN the UPDATE, so the guard cannot be defeated by a
            // concurrent writer between a read and a write.
            let n = tx.execute(
                "UPDATE credentials SET state = ?2, updated_at_ms = ?3 \
                 WHERE credential_id = ?1 AND state IN (?4, ?5)",
                rusqlite::params![
                    credential_id,
                    RecordState::Active.as_str(),
                    now,
                    RecordState::NeedsReauth.as_str(),
                    RecordState::Retired.as_str(),
                ],
            )?;
            if n > 0 {
                append_audit_tx(
                    tx,
                    &audit_key,
                    &AuditRecord {
                        op: ctx.op,
                        credential_id: Some(credential_id.to_string()),
                        payload_hash: None,
                        actor: ctx.actor.to_string(),
                        alarm: ctx.alarm,
                    },
                )?;
            }
            Ok(n > 0)
        })
        .map_err(StoreOpError::from)
    }

    fn set_state(
        &self,
        credential_id: &str,
        state: RecordState,
        clear_intent: bool,
        ctx: Option<AuditCtx<'_>>,
    ) -> Result<(), StoreOpError> {
        // The internal state writer is reachable from the read path (a quarantine), so
        // the fence sits here too: no path may move the active transfer key's record
        // off `Active`.
        let now = now_ms();
        let audit_key = self.audit_key.clone();
        self.fenced_write_unless_transfer_key_protected(credential_id, |tx| {
            let n = tx.execute(
                "UPDATE credentials SET state = ?2, updated_at_ms = ?3 \
                 WHERE credential_id = ?1 AND state <> ?2 AND state <> 'corrupt'",
                rusqlite::params![credential_id, state.as_str(), now],
            )?;
            if clear_intent {
                clear_intent_tx(tx, credential_id)?;
            }
            // Audit the state change only when it actually hit a row and a
            // context was supplied (quarantine/retain are internal, unaudited).
            if n > 0 {
                if let Some(ctx) = ctx {
                    append_audit_tx(
                        tx,
                        &audit_key,
                        &AuditRecord {
                            op: ctx.op,
                            credential_id: Some(credential_id.to_string()),
                            payload_hash: None,
                            actor: ctx.actor.to_string(),
                            alarm: ctx.alarm,
                        },
                    )?;
                }
            }
            Ok(())
        })
    }
}
