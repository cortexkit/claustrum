//! Enrollment proposals, approvals, polling, and lease-free listings.

use super::*;

fn append_enrollment_event_tx(
    tx: &rusqlite::Transaction,
    subject: &str,
    detail: &str,
    now: i64,
    principal: Option<AuthEventPrincipal<'_>>,
) -> rusqlite::Result<()> {
    debug_assert!(matches!(
        subject,
        ENROLL_PROPOSE_SUBJECT | ENROLL_POLL_SUBJECT | ENROLL_EXPIRE_SUBJECT
    ));
    tx.execute(
        "INSERT INTO auth_events \
         (ts_ms, credential_id, kind, provider_status, detail, record_version, applied, principal_kind, principal_id) \
         VALUES (?1, ?2, ?3, NULL, ?4, NULL, 0, ?5, ?6)",
        rusqlite::params![
            now,
            subject,
            AuthEventKind::Enrollment.as_str(),
            detail,
            principal.map(AuthEventPrincipal::kind),
            principal.and_then(AuthEventPrincipal::id),
        ],
    )?;
    trim_auth_events_tx(tx, subject)
}

fn sweep_pending_enrollments_tx(
    tx: &rusqlite::Transaction,
    now: i64,
    reserve_rows: i64,
) -> rusqlite::Result<()> {
    let expired = tx.execute(
        "UPDATE pending_enrollments SET state = 'expired' \
         WHERE state IN ('pending','approved') AND expires_at_ms <= ?1",
        [now],
    )?;
    if expired > 0 {
        append_enrollment_event_tx(tx, ENROLL_EXPIRE_SUBJECT, "expired", now, None)?;
    }

    let retention_cutoff = now.saturating_sub(ENROLLMENT_TERMINAL_RETENTION_MS);
    tx.execute(
        "DELETE FROM pending_enrollments \
         WHERE state IN ('denied','consumed','expired') AND created_at_ms < ?1",
        [retention_cutoff],
    )?;

    let count: i64 = tx.query_row("SELECT COUNT(*) FROM pending_enrollments", [], |row| {
        row.get(0)
    })?;
    let target = ENROLLMENT_TERMINAL_MAX_ROWS.saturating_sub(reserve_rows);
    let excess = count.saturating_sub(target);
    if excess > 0 {
        tx.execute(
            "DELETE FROM pending_enrollments WHERE request_id IN (\
                 SELECT request_id FROM pending_enrollments \
                 WHERE state IN ('denied','consumed','expired') \
                 ORDER BY created_at_ms ASC, request_id ASC LIMIT ?1\
             )",
            [excess],
        )?;
    }
    Ok(())
}

fn decode_requested_grants(json: &str) -> rusqlite::Result<Vec<crate::enrollment::RequestedGrant>> {
    let grants: Vec<crate::enrollment::RequestedGrant> =
        serde_json::from_str(json).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                0,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?;
    validate_requested_grants(&grants).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(error))
    })?;
    Ok(grants)
}

fn validate_requested_grants(
    grants: &[crate::enrollment::RequestedGrant],
) -> Result<(), StoreOpError> {
    if grants.is_empty()
        || grants.len() > crate::enrollment::REQUESTED_GRANTS_LIMIT
        || grants.iter().collect::<BTreeSet<_>>().len() != grants.len()
    {
        return Err(StoreOpError::InvalidCategoryName);
    }
    for grant in grants {
        if !matches!(grant.operation, GrantOperation::Read | GrantOperation::List) {
            return Err(StoreOpError::InvalidCategoryName);
        }
        let (kind, selector) = grant.selector.parts();
        validate_read_grant("enrolled", "proposal", kind, selector, grant.operation)?;
    }
    Ok(())
}

/// List pending requests and live enrollments WITHOUT a lease or a master key.
///
/// A thin wrapper over [`list_enrollments_read_only_with_schema`] for callers that want
/// only the rows.
pub fn list_enrollments_read_only(
    store_path: &std::path::Path,
) -> Result<Vec<EnrollmentRow>, StoreOpError> {
    list_enrollments_read_only_with_schema(store_path).map(|(rows, _)| rows)
}

/// List pending requests and live enrollments WITHOUT a lease or a master key, with the
/// store's recorded schema version.
///
/// A store below [`ENROLLMENT_PROPOSER_SCHEMA_VERSION`] has no proposer columns, so its
/// pending rows are read with no proposer; the version rides along so the caller can say
/// the proposer is missing because the store is behind, not because nobody proposed.
///
/// LEASE-FREE FOR THE SAME REASON EVERY OTHER READ VERB IS: the moment an operator asks
/// who is waiting for approval is the moment the vault is running, and a diagnostic that
/// needs an outage to read is useless exactly when it is needed. Nothing here is sealed —
/// request ids, names and states are plaintext columns by design, because an operator
/// approving an enrollment has to be able to see what they are approving.
///
/// TOKEN HASHES ARE NOT RETURNED and no caller should add them. They are not secrets, but
/// publishing them invites a reader to treat one as an identifier for a consumer, and the
/// only legitimate use of that column is the resolver's equality check.
pub fn list_enrollments_read_only_with_schema(
    store_path: &std::path::Path,
) -> Result<(Vec<EnrollmentRow>, u32), StoreOpError> {
    let map = |e: rusqlite::Error| StoreOpError::from(StoreError::Backend(e.to_string()));
    let conn = rusqlite::Connection::open_with_flags(
        format!("file:{}?mode=ro", store_path.display()),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
    )
    .map_err(map)?;
    let schema_version = read_schema_version(&conn).map_err(map)?;
    let mut rows: Vec<EnrollmentRow> = Vec::new();

    // Selecting NULL for the proposer below migration 12 keeps one row parser for both
    // shapes; selecting the real columns there would fail the whole listing.
    let proposer_columns = if schema_version >= ENROLLMENT_PROPOSER_SCHEMA_VERSION {
        "proposer_kind, proposer_id"
    } else {
        "NULL, NULL"
    };
    let display_name_column = if schema_version >= ENROLLMENT_DISPLAY_NAME_SCHEMA_VERSION {
        "display_name"
    } else {
        "NULL"
    };
    let requested_grants_column = if schema_version >= ENROLLMENT_REQUESTED_GRANTS_SCHEMA_VERSION {
        "requested_grants_json"
    } else {
        "NULL"
    };
    let mut pending = conn
        .prepare(&format!(
            "SELECT request_id, proposed_name, state, created_at_ms, {proposer_columns}, {display_name_column}, {requested_grants_column} \
             FROM pending_enrollments WHERE state = 'pending' ORDER BY created_at_ms"
        ))
        .map_err(map)?;
    let mapped = pending
        .query_map([], |row| {
            Ok(EnrollmentRow {
                key: row.get(0)?,
                name: row.get(1)?,
                state: row.get(2)?,
                created_at_ms: row.get(3)?,
                token_generation: 0,
                proposer_kind: row.get(4)?,
                proposer_id: row.get(5)?,
                display_name: row.get(6)?,
                requested_grants: row
                    .get::<_, Option<String>>(7)?
                    .as_deref()
                    .map(decode_requested_grants)
                    .transpose()?,
            })
        })
        .map_err(map)?;
    for row in mapped {
        rows.push(row.map_err(map)?);
    }

    let mut live = conn
        .prepare(&format!(
            "SELECT name, approved_at_ms, token_generation, token_hash, {display_name_column} FROM enrolled_consumers \
             WHERE revoked_at_ms IS NULL ORDER BY approved_at_ms",
        ))
        .map_err(map)?;
    let mapped = live
        .query_map([], |row| {
            let has_token: Option<String> = row.get(3)?;
            Ok(EnrollmentRow {
                key: row.get::<_, String>(0)?,
                name: row.get::<_, String>(0)?,
                // An approved enrollment that has never been polled holds no token, and
                // that is a state an operator needs to see: the consumer was admitted and
                // has not collected. Rendering it as `live` would hide a stalled handover.
                state: if has_token.is_some() {
                    "live".to_string()
                } else {
                    "awaiting-poll".to_string()
                },
                created_at_ms: row.get(1)?,
                token_generation: row.get(2)?,
                proposer_kind: None,
                proposer_id: None,
                display_name: row.get(4)?,
                requested_grants: None,
            })
        })
        .map_err(map)?;
    for row in mapped {
        rows.push(row.map_err(map)?);
    }
    Ok((rows, schema_version))
}

impl EncryptedStore {
    // ---- consumer enrollment ceremony ----------------------------------

    /// Propose one consumer name. The request id is returned once; only the caller's
    /// separately persisted request secret can resume the ceremony.
    ///
    /// `principal` is whoever the bus says sent it, recorded on the `auth_events` row and,
    /// for a new request, on the pending row itself so `ck auth enroll list` can show it. A
    /// proposal is anonymous by design, but anonymous is not the same as unattributed: a
    /// host-launched consumer arrives as `direct`, a supervised one as `reserved:<id>`, and
    /// that difference is what tells an operator whether a stray proposal came from a
    /// module or from something running beside it. Before this was recorded, seven
    /// proposals for an already-enrolled name arrived overnight and nothing could say from
    /// where.
    pub fn propose_enrollment_by(
        &self,
        principal: Option<AuthEventPrincipal<'_>>,
        proposed_name: &str,
        request_secret_hash: &str,
    ) -> Result<EnrollmentProposal, EnrollmentError> {
        self.propose_enrollment_with_display_name_by(
            principal,
            proposed_name,
            request_secret_hash,
            None,
        )
    }

    /// Propose a label for the operator to review; resuming never rewrites the request.
    pub fn propose_enrollment_with_display_name_by(
        &self,
        principal: Option<AuthEventPrincipal<'_>>,
        proposed_name: &str,
        request_secret_hash: &str,
        display_name: Option<&str>,
    ) -> Result<EnrollmentProposal, EnrollmentError> {
        self.propose_enrollment_with_requested_grants_by(
            principal,
            proposed_name,
            request_secret_hash,
            display_name,
            None,
        )
    }

    /// The first proposal fixes the permissions the operator will review, even on retry.
    pub fn propose_enrollment_with_requested_grants_by(
        &self,
        principal: Option<AuthEventPrincipal<'_>>,
        proposed_name: &str,
        request_secret_hash: &str,
        display_name: Option<&str>,
        requested_grants: Option<&[crate::enrollment::RequestedGrant]>,
    ) -> Result<EnrollmentProposal, EnrollmentError> {
        self.propose_enrollment_inner(
            proposed_name,
            request_secret_hash,
            now_ms(),
            principal,
            display_name,
            requested_grants,
        )
    }

    /// Test convenience: a proposal with no bus principal. Not compiled into the daemon,
    /// so a production call site cannot drop the caller's identity by picking the shorter
    /// name -- the shape that let three scoped surfaces ignore it for weeks.
    #[cfg(any(test, feature = "test-support"))]
    pub fn propose_enrollment(
        &self,
        proposed_name: &str,
        request_secret_hash: &str,
    ) -> Result<EnrollmentProposal, EnrollmentError> {
        self.propose_enrollment_inner(
            proposed_name,
            request_secret_hash,
            now_ms(),
            None,
            None,
            None,
        )
    }

    #[cfg(test)]
    pub(super) fn propose_enrollment_at(
        &self,
        proposed_name: &str,
        request_secret_hash: &str,
        now: i64,
    ) -> Result<EnrollmentProposal, EnrollmentError> {
        self.propose_enrollment_inner(proposed_name, request_secret_hash, now, None, None, None)
    }

    fn propose_enrollment_inner(
        &self,
        proposed_name: &str,
        request_secret_hash: &str,
        now: i64,
        principal: Option<AuthEventPrincipal<'_>>,
        display_name: Option<&str>,
        requested_grants: Option<&[crate::enrollment::RequestedGrant]>,
    ) -> Result<EnrollmentProposal, EnrollmentError> {
        if let Some(grants) = requested_grants {
            validate_requested_grants(grants)
                .map_err(|_| EnrollmentError::Refused(EnrollmentRefusal::InvalidParams))?;
        }
        let requested_grants_json = requested_grants
            .map(serde_json::to_string)
            .transpose()
            .map_err(|error| StoreOpError::Store(error.to_string()))?;
        let display_name = display_name
            .map(crate::display_name::validate_display_name)
            .transpose()
            .map_err(|_| EnrollmentError::Refused(EnrollmentRefusal::InvalidParams))?;
        if !valid_enrollment_name(proposed_name) || !is_lower_hex_32(request_secret_hash) {
            return Err(EnrollmentError::Refused(EnrollmentRefusal::InvalidParams));
        }
        let request_id = mint_hex_32()?;
        let expires_at_ms = now.saturating_add(ENROLLMENT_PENDING_TTL_MS);
        let outcome = self
            .fenced_write(|tx| {
                sweep_pending_enrollments_tx(tx, now, 1)?;

                // RESUME BEFORE REFUSING: the same secret means the same consumer.
                //
                // `request_id` is minted HERE and returned, so a consumer cannot persist it
                // before proposing -- which means a crash in the window between this INSERT
                // committing and the consumer writing the id down leaves it holding a secret
                // it cannot poll with, and the name held until TTL. The retry then hit
                // `pending_exists` and the consumer was wedged out of its own enrollment by
                // its own earlier attempt.
                //
                // The secret is the discriminator, and it is the right one: the consumer
                // mints it in-process and sends only its hash, so possession of the matching
                // hash proves this is the same caller resuming rather than a second one
                // colliding on a popular name. A squatter presenting a different secret
                // still gets `pending_exists`.
                //
                // Returns the ORIGINAL row rather than re-minting: a second id for one
                // pending enrollment would leave the first unreachable and still holding the
                // name, turning a resume into a second leak of the thing it was fixing.
                let resumable: Option<String> = tx
                    .query_row(
                        "SELECT request_id FROM pending_enrollments \
                 WHERE proposed_name = ?1 AND request_secret_hash = ?2 AND state = 'pending'",
                        rusqlite::params![proposed_name, request_secret_hash],
                        |row| row.get(0),
                    )
                    .optional()?;
                if let Some(existing_id) = resumable {
                    append_enrollment_event_tx(
                        tx,
                        ENROLL_PROPOSE_SUBJECT,
                        "resumed",
                        now,
                        principal,
                    )?;
                    return Ok(Ok(EnrollmentProposal {
                        request_id: existing_id,
                    }));
                }

                let name_in_use: bool = tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM pending_enrollments \
                 WHERE proposed_name = ?1 AND state IN ('pending','approved'))",
                    [proposed_name],
                    |row| row.get(0),
                )?;
                if name_in_use {
                    append_enrollment_event_tx(
                        tx,
                        ENROLL_PROPOSE_SUBJECT,
                        "pending_exists",
                        now,
                        principal,
                    )?;
                    return Ok(Err(EnrollmentRefusal::PendingExists));
                }

                let live_count: i64 = tx.query_row(
                    "SELECT COUNT(*) FROM pending_enrollments \
                 WHERE state IN ('pending','approved')",
                    [],
                    |row| row.get(0),
                )?;
                if live_count >= ENROLLMENT_LIVE_LIMIT {
                    append_enrollment_event_tx(
                        tx,
                        ENROLL_PROPOSE_SUBJECT,
                        "pending_queue_full",
                        now,
                        principal,
                    )?;
                    return Ok(Err(EnrollmentRefusal::PendingQueueFull));
                }

                // The proposer is written only here, on the INSERT. The resume path above
                // returns the original row untouched, so a later caller presenting the same
                // name and secret cannot rewrite who the operator sees as the proposer.
                tx.execute(
                    "INSERT INTO pending_enrollments \
                 (request_id, proposed_name, final_name, enrollment_id, request_secret_hash, \
                  state, approved_by, approved_at_ms, created_at_ms, expires_at_ms, \
                   proposer_kind, proposer_id, display_name, requested_grants_json) \
                 VALUES (?1, ?2, NULL, NULL, ?3, 'pending', NULL, NULL, ?4, ?5, ?6, ?7, ?8, ?9)",
                    rusqlite::params![
                        request_id,
                        proposed_name,
                        request_secret_hash,
                        now,
                        expires_at_ms,
                        principal.map(AuthEventPrincipal::kind),
                        principal.and_then(AuthEventPrincipal::id),
                        display_name,
                        requested_grants_json,
                    ],
                )?;
                append_enrollment_event_tx(tx, ENROLL_PROPOSE_SUBJECT, "accepted", now, principal)?;
                Ok(Ok(EnrollmentProposal {
                    request_id: request_id.clone(),
                }))
            })
            .map_err(StoreOpError::from)?;
        outcome.map_err(EnrollmentError::Refused)
    }

    /// Poll with exactly the request id and request secret. Unknown request ids and
    /// wrong well-formed secrets deliberately take the same constant-time comparison
    /// and return the same refusal.
    ///
    /// `principal` is recorded on every event the poll writes, for the same reason as on
    /// [`Self::propose_enrollment_by`]: a wrong-secret refusal is worth far more when it
    /// says which bus identity presented it.
    pub fn poll_enrollment_by(
        &self,
        principal: Option<AuthEventPrincipal<'_>>,
        request_id: &str,
        request_secret: &str,
    ) -> Result<EnrollmentPoll, EnrollmentError> {
        self.poll_enrollment_inner(request_id, request_secret, now_ms(), principal)
    }

    /// Test convenience with no bus principal; see [`Self::propose_enrollment`].
    #[cfg(any(test, feature = "test-support"))]
    pub fn poll_enrollment(
        &self,
        request_id: &str,
        request_secret: &str,
    ) -> Result<EnrollmentPoll, EnrollmentError> {
        self.poll_enrollment_inner(request_id, request_secret, now_ms(), None)
    }

    #[cfg(test)]
    pub(super) fn poll_enrollment_at(
        &self,
        request_id: &str,
        request_secret: &str,
        now: i64,
    ) -> Result<EnrollmentPoll, EnrollmentError> {
        self.poll_enrollment_inner(request_id, request_secret, now, None)
    }

    fn poll_enrollment_inner(
        &self,
        request_id: &str,
        request_secret: &str,
        now: i64,
        principal: Option<AuthEventPrincipal<'_>>,
    ) -> Result<EnrollmentPoll, EnrollmentError> {
        if !is_lower_hex_32(request_secret) {
            return Err(EnrollmentError::Refused(EnrollmentRefusal::InvalidParams));
        }
        let presented_hash = enrollment_secret_hash(request_secret)
            .ok_or(EnrollmentError::Refused(EnrollmentRefusal::InvalidParams))?;
        let outcome = self
            .fenced_write(|tx| {
                let row = tx
                .query_row(
                    "SELECT request_secret_hash, state, final_name, enrollment_id, expires_at_ms \
                     FROM pending_enrollments WHERE request_id = ?1",
                    [request_id],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, Option<String>>(2)?,
                            row.get::<_, Option<String>>(3)?,
                            row.get::<_, i64>(4)?,
                        ))
                    },
                )
                .optional()?;

                // Run one fixed-size comparison even for an unknown id. The row-existence bit
                // is applied only after it, so the two paths cannot diverge through `==`.
                let stored_hash = row
                    .as_ref()
                    .map(|values| values.0.as_str())
                    .unwrap_or("0000000000000000000000000000000000000000000000000000000000000000");
                let secret_matches = constant_time_hash_eq(&presented_hash, stored_hash);
                if row.is_none() || !secret_matches {
                    append_enrollment_event_tx(
                        tx,
                        ENROLL_POLL_SUBJECT,
                        "not_found",
                        now,
                        principal,
                    )?;
                    return Ok(Err(EnrollmentRefusal::NotFound));
                }

                let (_, state, final_name, enrollment_id, expires_at_ms) =
                    row.expect("checked above");
                if matches!(state.as_str(), "pending" | "approved") && expires_at_ms <= now {
                    tx.execute(
                        "UPDATE pending_enrollments SET state = 'expired' WHERE request_id = ?1",
                        [request_id],
                    )?;
                    append_enrollment_event_tx(
                        tx,
                        ENROLL_EXPIRE_SUBJECT,
                        "expired",
                        now,
                        principal,
                    )?;
                    append_enrollment_event_tx(
                        tx,
                        ENROLL_POLL_SUBJECT,
                        "superseded",
                        now,
                        principal,
                    )?;
                    return Ok(Err(EnrollmentRefusal::Superseded));
                }

                match state.as_str() {
                    // A PENDING POLL RECORDS NOTHING, because nothing happened.
                    //
                    // Consumers poll on a timer while they wait for the operator, and one
                    // was measured at ~2.2 polls a second. Every pending poll used to append
                    // an `auth_events` row, and that table keeps only the newest
                    // `AUTH_EVENTS_PER_CREDENTIAL` rows per subject, so the rows worth
                    // having under `auth.enroll_poll` -- a `not_found` from a wrong secret,
                    // a `superseded`, an `approved` -- were evicted within about half a
                    // minute by rows saying "still waiting". The ring is for diagnosis; an
                    // observation that nothing changed is not one.
                    //
                    // It also makes a pending poll write nothing at all: the fence row is
                    // only written when this writer claims the database, so the
                    // transaction commits empty instead of adding a commit per poll.
                    //
                    // Every other arm here is a transition or a refusal and still records.
                    "pending" => Ok(Ok(EnrollmentPoll::Pending)),
                    "denied" => {
                        append_enrollment_event_tx(
                            tx,
                            ENROLL_POLL_SUBJECT,
                            "denied",
                            now,
                            principal,
                        )?;
                        Ok(Ok(EnrollmentPoll::Denied))
                    }
                    "consumed" => {
                        append_enrollment_event_tx(
                            tx,
                            ENROLL_POLL_SUBJECT,
                            "already_consumed",
                            now,
                            principal,
                        )?;
                        Ok(Err(EnrollmentRefusal::AlreadyConsumed))
                    }
                    "expired" => {
                        append_enrollment_event_tx(
                            tx,
                            ENROLL_POLL_SUBJECT,
                            "superseded",
                            now,
                            principal,
                        )?;
                        Ok(Err(EnrollmentRefusal::Superseded))
                    }
                    "approved" => {
                        let Some(enrollment_id) = enrollment_id else {
                            append_enrollment_event_tx(
                                tx,
                                ENROLL_POLL_SUBJECT,
                                "superseded",
                                now,
                                principal,
                            )?;
                            return Ok(Err(EnrollmentRefusal::Superseded));
                        };
                        let incarnation = tx
                            .query_row(
                                "SELECT name, token_hash, token_generation, revoked_at_ms \
                             FROM enrolled_consumers WHERE enrollment_id = ?1",
                                [&enrollment_id],
                                |row| {
                                    Ok((
                                        row.get::<_, String>(0)?,
                                        row.get::<_, Option<String>>(1)?,
                                        row.get::<_, i64>(2)?,
                                        row.get::<_, Option<i64>>(3)?,
                                    ))
                                },
                            )
                            .optional()?;
                        let Some((name, token_hash, token_generation, revoked_at_ms)) = incarnation
                        else {
                            append_enrollment_event_tx(
                                tx,
                                ENROLL_POLL_SUBJECT,
                                "superseded",
                                now,
                                principal,
                            )?;
                            return Ok(Err(EnrollmentRefusal::Superseded));
                        };
                        if revoked_at_ms.is_some() || token_hash.is_some() || token_generation != 0
                        {
                            append_enrollment_event_tx(
                                tx,
                                ENROLL_POLL_SUBJECT,
                                "superseded",
                                now,
                                principal,
                            )?;
                            return Ok(Err(EnrollmentRefusal::Superseded));
                        }
                        if final_name.as_deref() != Some(name.as_str()) {
                            append_enrollment_event_tx(
                                tx,
                                ENROLL_POLL_SUBJECT,
                                "superseded",
                                now,
                                principal,
                            )?;
                            return Ok(Err(EnrollmentRefusal::Superseded));
                        }

                        let token = mint_hex_32_sqlite()?;
                        let token_hash = enrollment_secret_hash(&token)
                            .expect("a freshly minted 32-byte hex token is valid");
                        let changed = tx.execute(
                            "UPDATE enrolled_consumers SET token_hash = ?1, token_generation = 1 \
                         WHERE enrollment_id = ?2 AND token_hash IS NULL \
                           AND token_generation = 0 AND revoked_at_ms IS NULL",
                            rusqlite::params![token_hash, enrollment_id],
                        )?;
                        if changed != 1 {
                            append_enrollment_event_tx(
                                tx,
                                ENROLL_POLL_SUBJECT,
                                "superseded",
                                now,
                                principal,
                            )?;
                            return Ok(Err(EnrollmentRefusal::Superseded));
                        }
                        tx.execute(
                        "UPDATE pending_enrollments SET state = 'consumed' WHERE request_id = ?1",
                        [request_id],
                    )?;
                        append_enrollment_event_tx(
                            tx,
                            ENROLL_POLL_SUBJECT,
                            "approved",
                            now,
                            principal,
                        )?;
                        Ok(Ok(EnrollmentPoll::Approved {
                            name,
                            token,
                            token_generation: 1,
                        }))
                    }
                    _ => Err(rusqlite::Error::InvalidQuery),
                }
            })
            .map_err(StoreOpError::from)?;
        outcome.map_err(EnrollmentError::Refused)
    }

    /// Rotate a live token when its caller also holds the current generation.
    pub fn rotate_enrollment(
        &self,
        token: &str,
        expected_token_generation: u64,
    ) -> Result<EnrollmentRotation, EnrollmentError> {
        if !is_lower_hex_32(token) {
            return Err(EnrollmentError::Refused(EnrollmentRefusal::InvalidParams));
        }
        let presented_hash = enrollment_secret_hash(token)
            .ok_or(EnrollmentError::Refused(EnrollmentRefusal::InvalidParams))?;
        let audit_key = self.audit_key.clone();
        let outcome = self
            .fenced_write(|tx| {
                let mut stmt = tx.prepare(
                    "SELECT enrollment_id, name, token_hash, token_generation \
                 FROM enrolled_consumers WHERE revoked_at_ms IS NULL AND token_hash IS NOT NULL",
                )?;
                let candidates = stmt
                    .query_map([], |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, i64>(3)?,
                        ))
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                drop(stmt);

                let mut matched = None;
                for candidate in candidates {
                    if constant_time_hash_eq(&presented_hash, &candidate.2) {
                        matched = Some(candidate);
                    }
                }
                let Some((enrollment_id, name, old_hash, generation)) = matched else {
                    return Ok(Err(EnrollmentRefusal::NotFound));
                };
                if generation < 0 || generation as u64 != expected_token_generation {
                    return Ok(Err(EnrollmentRefusal::StaleGeneration));
                }

                let replacement = mint_hex_32_sqlite()?;
                let replacement_hash = enrollment_secret_hash(&replacement)
                    .expect("a freshly minted 32-byte hex token is valid");
                let next_generation = generation
                    .checked_add(1)
                    .ok_or(rusqlite::Error::IntegralValueOutOfRange(3, generation))?;
                let changed = tx.execute(
                    "UPDATE enrolled_consumers SET token_hash = ?1, token_generation = ?2 \
                 WHERE enrollment_id = ?3 AND token_hash = ?4 \
                   AND token_generation = ?5 AND revoked_at_ms IS NULL",
                    rusqlite::params![
                        replacement_hash,
                        next_generation,
                        enrollment_id,
                        old_hash,
                        generation
                    ],
                )?;
                if changed != 1 {
                    return Ok(Err(EnrollmentRefusal::NotFound));
                }
                append_audit_tx(
                    tx,
                    &audit_key,
                    &AuditRecord {
                        op: AuditOp::EnrollRotate,
                        credential_id: Some(enrollment_id),
                        payload_hash: None,
                        actor: format!("enrolled:{name}"),
                        alarm: None,
                    },
                )?;
                Ok(Ok(EnrollmentRotation {
                    token: replacement,
                    token_generation: next_generation as u64,
                }))
            })
            .map_err(StoreOpError::from)?;
        outcome.map_err(EnrollmentError::Refused)
    }

    /// Approve a pending request without minting its token. Callers that passed the admin
    /// plane's MAC check over the exact operation bytes provide the actor; the first
    /// successful poll remains the only consumer token-delivery path.
    pub fn approve_enrollment(
        &self,
        request_id: &str,
        final_name: &str,
        actor: &str,
    ) -> Result<String, StoreOpError> {
        self.approve_enrollment_with_grants(request_id, final_name, false, actor)
    }

    /// Existing name-bound grants require explicit consent before a new consumer can
    /// inherit them. Check inside the approval transaction so grant creation cannot race it.
    pub fn approve_enrollment_with_grants(
        &self,
        request_id: &str,
        final_name: &str,
        keep_grants: bool,
        actor: &str,
    ) -> Result<String, StoreOpError> {
        self.approve_enrollment_with_display_name(request_id, final_name, keep_grants, None, actor)
            .map(|(id, _)| id)
    }

    /// Change only a live enrollment's display name, auditing real changes atomically.
    pub fn label_enrollment(
        &self,
        name: &str,
        display_name: Option<&str>,
        actor: &str,
    ) -> Result<bool, StoreOpError> {
        let display_name = display_name
            .map(crate::display_name::validate_display_name)
            .transpose()
            .map_err(|_| StoreOpError::InvalidDisplayName)?;
        let audit_key = self.audit_key.clone();
        self.fenced_write(|tx| {
            let row = tx
                .query_row(
                    "SELECT enrollment_id, display_name FROM enrolled_consumers \
                 WHERE name = ?1 AND revoked_at_ms IS NULL",
                    [name],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
                )
                .optional()?;
            let Some((id, current)) = row else {
                return Ok(None);
            };
            if current == display_name {
                return Ok(Some(false));
            }
            tx.execute(
                "UPDATE enrolled_consumers SET display_name = ?1 WHERE enrollment_id = ?2",
                rusqlite::params![display_name, id],
            )?;
            append_audit_tx(
                tx,
                &audit_key,
                &AuditRecord {
                    op: AuditOp::EnrollLabel,
                    credential_id: Some(id),
                    payload_hash: None,
                    actor: actor.to_string(),
                    alarm: None,
                },
            )?;
            Ok(Some(true))
        })
        .map_err(StoreOpError::from)?
        .ok_or(StoreOpError::NotFound)
    }

    /// Approve the proposed label, or a validated operator replacement, atomically.
    pub fn approve_enrollment_with_display_name(
        &self,
        request_id: &str,
        final_name: &str,
        keep_grants: bool,
        display_name: Option<&str>,
        actor: &str,
    ) -> Result<(String, Option<String>), StoreOpError> {
        self.approve_enrollment_with_requested_grants(
            request_id,
            final_name,
            keep_grants,
            display_name,
            false,
            actor,
        )
    }

    /// Approve and, only on explicit operator consent, apply the stored permissions.
    pub fn approve_enrollment_with_requested_grants(
        &self,
        request_id: &str,
        final_name: &str,
        keep_grants: bool,
        display_name: Option<&str>,
        grant_requested: bool,
        actor: &str,
    ) -> Result<(String, Option<String>), StoreOpError> {
        let display_name = display_name
            .map(crate::display_name::validate_display_name)
            .transpose()
            .map_err(|_| StoreOpError::InvalidDisplayName)?;
        if !valid_enrollment_name(final_name) {
            return Err(StoreOpError::InvalidPrincipal);
        }
        let now = now_ms();
        let enrollment_id = mint_hex_32()?;
        let audit_key = self.audit_key.clone();
        self.fenced_write(|tx| {
            let state = tx
                .query_row(
                    "SELECT state, expires_at_ms, display_name, requested_grants_json FROM pending_enrollments WHERE request_id = ?1",
                    [request_id],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?, row.get::<_, Option<String>>(2)?, row.get::<_, Option<String>>(3)?)),
                )
                .optional()?;
            let Some((state, expires_at_ms, proposed_display_name, requested_grants_json)) = state else {
                return Ok(Ok(None));
            };
            if state != "pending" || expires_at_ms <= now {
                if state == "pending" && expires_at_ms <= now {
                    tx.execute(
                        "UPDATE pending_enrollments SET state = 'expired' WHERE request_id = ?1",
                        [request_id],
                    )?;
                    append_enrollment_event_tx(tx, ENROLL_EXPIRE_SUBJECT, "expired", now, None)?;
                }
                return Ok(Ok(None));
            }
            let live_name: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM enrolled_consumers \
                 WHERE name = ?1 AND revoked_at_ms IS NULL)",
                [final_name],
                |row| row.get(0),
            )?;
            if live_name {
                return Err(rusqlite::Error::SqliteFailure(
                    rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE),
                    Some("enrollment name already in use".into()),
                ));
            }
            let has_grants: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM read_grants \
                 WHERE principal_kind = 'enrolled' AND principal_id = ?1)",
                [final_name],
                |row| row.get(0),
            )?;
            if has_grants && !keep_grants {
                return Ok(Err(StoreOpError::EnrollmentNameHasGrants {
                    name: final_name.to_string(),
                }));
            }
            let grants = if grant_requested {
                requested_grants_json.as_deref().map(decode_requested_grants).transpose()?
            } else {
                None
            };
            let approved_display_name = display_name.clone().or(proposed_display_name);
            tx.execute(
                "INSERT INTO enrolled_consumers \
                 (enrollment_id, name, token_hash, token_generation, approved_at_ms, approved_by, revoked_at_ms, display_name) \
                 VALUES (?1, ?2, NULL, 0, ?3, ?4, NULL, ?5)",
                rusqlite::params![enrollment_id, final_name, now, actor, approved_display_name],
            )?;
            tx.execute(
                "UPDATE pending_enrollments SET state = 'approved', final_name = ?1, \
                 enrollment_id = ?2, approved_by = ?3, approved_at_ms = ?4 \
                 WHERE request_id = ?5",
                rusqlite::params![final_name, enrollment_id, actor, now, request_id],
            )?;
            append_audit_tx(
                tx,
                &audit_key,
                &AuditRecord {
                    op: AuditOp::EnrollApprove,
                    credential_id: Some(enrollment_id.clone()),
                    payload_hash: None,
                    actor: actor.to_string(),
                    alarm: None,
                },
            )?;
            for grant in grants.iter().flatten() {
                let (kind, selector) = grant.selector.parts();
                create_read_grant_audited_tx(
                    tx, &audit_key, "enrolled", final_name, kind, selector, grant.operation, now,
                    AuditCtx::route_admin(AuditOp::GrantCreate, actor),
                )?;
            }
            Ok(Ok(Some((enrollment_id.clone(), approved_display_name))))
        })
        .map_err(StoreOpError::from)??
        // Missing and expired requests are gone for approval purposes, not store faults.
        .ok_or(StoreOpError::NotFound)
    }

    /// Deny a live pending request and append exactly one audit row.
    /// An expired pending request is persisted as expired instead of denied.
    pub fn deny_enrollment(&self, request_id: &str, actor: &str) -> Result<(), StoreOpError> {
        let audit_key = self.audit_key.clone();
        let now = now_ms();
        self.fenced_write(|tx| {
            let expired = tx.execute(
                "UPDATE pending_enrollments SET state = 'expired' \
                 WHERE request_id = ?1 AND state = 'pending' AND expires_at_ms <= ?2",
                rusqlite::params![request_id, now],
            )?;
            if expired > 0 {
                append_enrollment_event_tx(tx, ENROLL_EXPIRE_SUBJECT, "expired", now, None)?;
                return Ok(false);
            }
            let changed = tx.execute(
                "UPDATE pending_enrollments SET state = 'denied' \
                 WHERE request_id = ?1 AND state = 'pending'",
                [request_id],
            )?;
            if changed != 1 {
                return Ok(false);
            }
            append_audit_tx(
                tx,
                &audit_key,
                &AuditRecord {
                    op: AuditOp::EnrollDeny,
                    credential_id: Some(request_id.to_string()),
                    payload_hash: None,
                    actor: actor.to_string(),
                    alarm: None,
                },
            )?;
            Ok(true)
        })
        .map_err(StoreOpError::from)
        .and_then(|denied| {
            if denied {
                Ok(())
            } else {
                // Missing and lapsed requests are NotFound, not store faults.
                Err(StoreOpError::NotFound)
            }
        })
    }

    /// Resolve a presented enrollment token to the live consumer name it names.
    ///
    /// This is the one function that makes an enrollment token SPENDABLE. Until it
    /// existed the ceremony could mint a token, the consumer could persist it, and no
    /// scoped operation would accept it — a credential that proved nothing, which is
    /// worse than no credential because it looks like access.
    ///
    /// CONSTANT-TIME IS NOT THE PROPERTY HERE AND CLAIMING IT WOULD BE WORSE THAN NOT
    /// HAVING IT. The lookup hashes the presented token and asks SQLite for a row, so
    /// timing varies with index structure and page cache. What defends the token is its
    /// entropy: 256 CSPRNG bits, the same as a capability handle, so guessing is not a
    /// timing question. The hash is domain-separated, so a token is not interchangeable
    /// with any other secret this store holds.
    ///
    /// `revoked_at_ms IS NULL` is part of the predicate rather than a check afterwards:
    /// a revoked enrollment must be indistinguishable from an unknown token, for the
    /// same reason a revoked capability handle answers like an unknown one. A caller who
    /// can tell them apart can enumerate which names ever existed.
    ///
    /// The generation is returned WITH the name because a rotated token must not be
    /// silently equivalent to its predecessor: the caller records which incarnation
    /// authorized an operation, so a forensic reader can tell a pre-rotation spend from
    /// a post-rotation one rather than seeing one undifferentiated name.
    pub fn resolve_enrollment_token(
        &self,
        token: &str,
    ) -> Result<Option<(String, i64)>, StoreOpError> {
        let Some(hash) = crate::enrollment::enrollment_secret_hash(token) else {
            // A malformed token is not an error the caller can act on differently from a
            // wrong one, and saying so would separate "badly shaped" from "unknown".
            return Ok(None);
        };
        self.store
            .with_conn(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT name, token_generation FROM enrolled_consumers \
                     WHERE token_hash = ?1 AND revoked_at_ms IS NULL",
                )?;
                let mut rows = stmt.query(rusqlite::params![hash])?;
                match rows.next()? {
                    Some(row) => Ok(Some((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))),
                    None => Ok(None),
                }
            })
            .map_err(StoreOpError::from)
    }

    /// Revoke the live incarnation and all of its name-bound grants atomically, so a
    /// different consumer later admitted under the name cannot inherit its reach.
    pub fn revoke_enrollment(
        &self,
        name: &str,
        actor: &str,
    ) -> Result<Vec<ReadGrant>, StoreOpError> {
        let now = now_ms();
        let audit_key = self.audit_key.clone();
        self.fenced_write(|tx| {
            let enrollment_id = tx
                .query_row(
                    "SELECT enrollment_id FROM enrolled_consumers \
                     WHERE name = ?1 AND revoked_at_ms IS NULL",
                    [name],
                    |row| row.get::<_, String>(0),
                )
                .optional()?;
            let Some(enrollment_id) = enrollment_id else {
                return Ok(None);
            };
            let removed_grants = read_grants_from_conn(
                tx,
                Some("enrolled"),
                Some(name),
                newest_migration_version(),
            )?;
            tx.execute(
                "DELETE FROM read_grants WHERE principal_kind = 'enrolled' AND principal_id = ?1",
                [name],
            )?;
            for grant in &removed_grants {
                append_audit_tx(
                    tx,
                    &audit_key,
                    &AuditRecord {
                        op: AuditOp::GrantRevoke,
                        credential_id: Some(format!(
                            "grant:{}:enrolled:{name}:{}|{}",
                            grant.operation.as_str(),
                            grant.selector_kind.as_str(),
                            grant.selector,
                        )),
                        payload_hash: None,
                        actor: actor.to_string(),
                        alarm: None,
                    },
                )?;
            }
            if !removed_grants.is_empty() {
                bump_grants_generation_tx(tx)?;
            }
            tx.execute(
                "UPDATE enrolled_consumers SET revoked_at_ms = ?1, display_name = NULL WHERE enrollment_id = ?2",
                rusqlite::params![now, enrollment_id],
            )?;
            append_audit_tx(
                tx,
                &audit_key,
                &AuditRecord {
                    op: AuditOp::EnrollRevoke,
                    credential_id: Some(enrollment_id),
                    payload_hash: None,
                    actor: actor.to_string(),
                    alarm: None,
                },
            )?;
            Ok(Some(removed_grants))
        })
        .map_err(StoreOpError::from)?
        .ok_or(StoreOpError::NotFound)
    }

    /// Repair for a lost poll response, for callers that passed the admin plane's MAC
    /// check over the exact operation bytes. It has no expected-generation argument.
    pub fn reissue_enrollment(
        &self,
        name: &str,
        actor: &str,
    ) -> Result<EnrollmentRotation, StoreOpError> {
        let audit_key = self.audit_key.clone();
        self.fenced_write(|tx| {
            let enrollment = tx
                .query_row(
                    "SELECT enrollment_id, token_generation FROM enrolled_consumers \
                     WHERE name = ?1 AND revoked_at_ms IS NULL",
                    [name],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
                )
                .optional()?;
            let Some((enrollment_id, generation)) = enrollment else {
                return Ok(None);
            };
            let token = mint_hex_32_sqlite()?;
            let token_hash = enrollment_secret_hash(&token)
                .expect("a freshly minted 32-byte hex token is valid");
            let next_generation = generation
                .checked_add(1)
                .ok_or(rusqlite::Error::IntegralValueOutOfRange(1, generation))?;
            tx.execute(
                "UPDATE enrolled_consumers SET token_hash = ?1, token_generation = ?2 \
                 WHERE enrollment_id = ?3",
                rusqlite::params![token_hash, next_generation, enrollment_id],
            )?;
            append_audit_tx(
                tx,
                &audit_key,
                &AuditRecord {
                    op: AuditOp::EnrollReissue,
                    credential_id: Some(enrollment_id),
                    payload_hash: None,
                    actor: actor.to_string(),
                    alarm: None,
                },
            )?;
            Ok(Some(EnrollmentRotation {
                token,
                token_generation: next_generation as u64,
            }))
        })
        .map_err(StoreOpError::from)?
        .ok_or(StoreOpError::NotFound)
    }

    pub(super) fn sweep_pending_enrollments_on_open(&self, now: i64) -> Result<(), StoreOpError> {
        match self
            .store
            .with_conn_fenced(|tx| sweep_pending_enrollments_tx(tx, now, 0))
        {
            Ok(()) => Ok(()),
            // An EncryptedStore is also used by lease-free diagnostics. A failed fence
            // proves this instance has no write authority, so opening it must stay a
            // pure read and leave expired rows for the next writer.
            Err(StoreError::Fenced { .. }) => Ok(()),
            Err(error) => Err(StoreOpError::from(error)),
        }
    }
}
