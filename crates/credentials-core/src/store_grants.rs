//! Read grants, scoped coverage, and credential taxonomy mutations.

use super::*;

pub(super) fn validate_read_grant(
    principal_kind: &str,
    principal_id: &str,
    selector_kind: SelectorKind,
    selector: &str,
    operation: GrantOperation,
) -> Result<(), StoreOpError> {
    if selector_kind == SelectorKind::Audience
        && selector == "cortexkit-hub"
        && operation == GrantOperation::AccountToken
        && (principal_kind != "reserved" || principal_id != "ckbus")
    {
        return Err(StoreOpError::HubAudienceReserved);
    }
    if crate::federation::is_bus_key_id(selector) {
        if selector_kind != SelectorKind::Exact {
            return Err(StoreOpError::BusKeyReserved);
        }
        crate::federation::bus_key_admits_grant(
            selector,
            &format!("{principal_kind}:{principal_id}"),
            operation,
        )
        .map_err(|_| StoreOpError::BusKeyReserved)?;
    }
    // The bus-seal allowlist already restricts exact grants to valid operations.
    // Let it name the reserved-key refusal even for an otherwise invalid operation.
    if selector_kind != SelectorKind::Exact || !crate::federation::is_bus_seal_key_id(selector) {
        selector_kind
            .validate_operation(operation)
            .map_err(StoreOpError::Store)?;
    }
    // The transfer key's one admissible grant is checked before every other grant
    // rule, so an id under its prefix is refused by that name rather than by
    // whichever unrelated rule it happens to trip first.
    if selector_kind == SelectorKind::Exact {
        if crate::agent_secret::is_deposit_key(selector) {
            return Err(StoreOpError::NotFound);
        }
        if operation == GrantOperation::Sign && selector == GH_MANIFEST_ROOT_KEY_ID {
            return Err(StoreOpError::NotFound);
        }
        crate::federation::transfer_key_admits_grant(
            selector,
            &format!("{principal_kind}:{principal_id}"),
            operation,
        )
        .map_err(|_| crate::federation::key_grant_refusal(selector))?;
    }
    // An enrolled name outside the approval grammar could never be held, so a grant
    // to it is unusable. Only creation checks this: revocation keeps the wider rule
    // so grants created before this check can still be removed.
    if !matches!(principal_kind, "reserved" | "enrolled")
        || principal_id.is_empty()
        || principal_id.contains('|')
        || (principal_kind == "enrolled" && !valid_enrollment_name(principal_id))
    {
        return Err(StoreOpError::InvalidPrincipal);
    }
    if operation == GrantOperation::Deposit
        && (principal_kind != "reserved"
            || selector_kind != SelectorKind::Category
            || selector != "browser-session")
    {
        return Err(StoreOpError::InvalidDepositGrant);
    }
    if selector.is_empty()
        || (selector_kind == SelectorKind::Category
            && !crate::catalog::valid_category_name(selector))
    {
        return Err(StoreOpError::InvalidCategoryName);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn create_read_grant_audited_tx(
    tx: &rusqlite::Transaction,
    audit_key: &[u8; 32],
    principal_kind: &str,
    principal_id: &str,
    selector_kind: SelectorKind,
    selector: &str,
    operation: GrantOperation,
    now: i64,
    ctx: AuditCtx<'_>,
) -> rusqlite::Result<usize> {
    let changed = tx.execute(
        "INSERT INTO read_grants \
         (principal_kind, principal_id, selector_kind, selector, operation, created_at_ms) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6) ON CONFLICT DO NOTHING",
        rusqlite::params![
            principal_kind,
            principal_id,
            selector_kind.as_str(),
            selector,
            operation.as_str(),
            now
        ],
    )?;
    if changed > 0 {
        append_audit_tx(
            tx,
            audit_key,
            &AuditRecord {
                op: ctx.op,
                credential_id: Some(format!(
                    "grant:{}:{principal_kind}:{principal_id}:{}|{selector}",
                    operation.as_str(),
                    selector_kind.as_str()
                )),
                payload_hash: None,
                actor: ctx.actor.to_string(),
                alarm: ctx.alarm,
            },
        )?;
        bump_grants_generation_tx(tx)?;
    }
    Ok(changed)
}

/// Advance the store-wide grant generation inside the caller's own transaction.
///
/// Grant and category mutations change what a principal reaches, and a consumer
/// enumerating its credentials reads the rows and this counter from one snapshot. The
/// bump therefore commits with the mutation that caused it: a counter advanced in a
/// separate transaction could be observed alongside the row set it predates, and a
/// consumer holding that pairing would record a high-water mark for state it never saw
/// and stop re-enumerating.
pub(super) fn bump_grants_generation_tx(tx: &rusqlite::Transaction) -> rusqlite::Result<()> {
    tx.execute(
        "UPDATE grants_generation SET value = value + 1 WHERE id = 1",
        [],
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn revoke_read_grant_audited_tx(
    tx: &rusqlite::Transaction<'_>,
    audit_key: &[u8; 32],
    principal_kind: &str,
    principal_id: &str,
    selector_kind: SelectorKind,
    selector: &str,
    operation: GrantOperation,
    ctx: AuditCtx<'_>,
) -> rusqlite::Result<usize> {
    let changed = tx.execute(
        "DELETE FROM read_grants \
         WHERE principal_kind = ?1 AND principal_id = ?2 \
         AND selector_kind = ?3 AND selector = ?4 AND operation = ?5",
        rusqlite::params![
            principal_kind,
            principal_id,
            selector_kind.as_str(),
            selector,
            operation.as_str()
        ],
    )?;
    if changed > 0 {
        append_audit_tx(
            tx,
            audit_key,
            &AuditRecord {
                op: ctx.op,
                credential_id: Some(format!(
                    "grant:{}:{principal_kind}:{principal_id}:{}|{selector}",
                    operation.as_str(),
                    selector_kind.as_str()
                )),
                payload_hash: None,
                actor: ctx.actor.to_string(),
                alarm: ctx.alarm,
            },
        )?;
        bump_grants_generation_tx(tx)?;
    }
    Ok(changed)
}

pub(super) fn read_grants_from_conn(
    conn: &rusqlite::Connection,
    principal_kind: Option<&str>,
    principal_id: Option<&str>,
    schema_version: u32,
) -> rusqlite::Result<Vec<ReadGrant>> {
    // Legacy prefix grants cannot be represented by the current exact/category model.
    // Refuse explicitly rather than understating the reach of a stored grant. A store
    // with no grants table at all (bootstrapped, never migrated) holds no grants, so it
    // reads as empty instead of being refused for a schema it never reached.
    if schema_version < SELECTOR_SCHEMA_VERSION {
        let has_grants_table: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'read_grants')",
            [],
            |row| row.get(0),
        )?;
        if !has_grants_table {
            return Ok(Vec::new());
        }
        return Err(rusqlite::Error::InvalidParameterName(format!(
            "store schema {schema_version}: current selector kinds arrive with migration 10; \
             restart the daemon on this build to migrate the store, or read it with the \
             ck-auth that matches the store"
        )));
    }
    let selector_kind_column = "selector_kind";
    let selector_column = "selector";
    let selector_order = "selector";
    let sql = if principal_kind.is_some() && principal_id.is_some() {
        format!(
            "SELECT principal_kind, principal_id, {selector_kind_column}, {selector_column}, operation, created_at_ms \
             FROM read_grants WHERE principal_kind = ?1 AND principal_id = ?2 \
             ORDER BY {selector_kind_column}, {selector_order}, operation"
        )
    } else {
        format!(
            "SELECT principal_kind, principal_id, {selector_kind_column}, {selector_column}, operation, created_at_ms \
             FROM read_grants ORDER BY principal_kind, principal_id, {selector_kind_column}, {selector_order}, operation"
        )
    };
    let mut stmt = conn.prepare(&sql)?;
    let parse = |row: &rusqlite::Row<'_>| {
        let selector_kind = row
            .get::<_, String>(2)?
            .parse()
            .map_err(|message: String| {
                rusqlite::Error::FromSqlConversionFailure(
                    2,
                    rusqlite::types::Type::Text,
                    Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        message,
                    )),
                )
            })?;
        let operation = row
            .get::<_, String>(4)?
            .parse()
            .map_err(|message: String| {
                rusqlite::Error::FromSqlConversionFailure(
                    4,
                    rusqlite::types::Type::Text,
                    Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        message,
                    )),
                )
            })?;
        Ok(ReadGrant {
            principal_kind: row.get(0)?,
            principal_id: row.get(1)?,
            selector_kind,
            selector: row.get(3)?,
            operation,
            created_at_ms: row.get(5)?,
        })
    };
    // The SQL ORDER BY is the listing's order, and it sorts on the stored TEXT. Do not
    // re-sort here by the enums: their declaration order (exact before category, open
    // after sign) is not the text order, and `ck auth grants` refuses a listing whose
    // text order is not strictly increasing, so a re-sort takes the operator's only
    // grant inventory down as soon as one principal holds both selector kinds.
    let grants = if let (Some(kind), Some(id)) = (principal_kind, principal_id) {
        stmt.query_map(rusqlite::params![kind, id], parse)?
            .collect::<rusqlite::Result<Vec<_>>>()?
    } else {
        stmt.query_map([], parse)?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    Ok(grants)
}

/// List operation grants from a store file WITHOUT a lease or a master key, with the
/// store's recorded schema version.
///
/// The version rides along for the same reason as the metadata reader: a store one
/// migration behind has no category grants yet, and a caller that renders the grant
/// set has to be able to say so rather than present a prefix-only view as complete.
pub fn list_read_grants_read_only_with_schema(
    store_path: &std::path::Path,
) -> Result<(Vec<ReadGrant>, u32), StoreOpError> {
    let map = |e: rusqlite::Error| StoreOpError::from(StoreError::Backend(e.to_string()));
    let conn = rusqlite::Connection::open_with_flags(
        format!("file:{}?mode=ro", store_path.display()),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
    )
    .map_err(map)?;
    let schema_version = read_schema_version(&conn).map_err(map)?;
    read_grants_from_conn(&conn, None, None, schema_version)
        .map(|grants| (grants, schema_version))
        .map_err(map)
        .map_err(|error| match error {
            StoreOpError::Store(message) if message.contains("no such table: read_grants") => {
                StoreOpError::NotFound
            }
            other => other,
        })
}

/// List operation grants from a store file WITHOUT a lease or a master key.
///
/// A thin wrapper over [`list_read_grants_read_only_with_schema`] for callers that want
/// only the rows. Reach for the version-aware reader when the caller has to say
/// anything about what the store is missing; do not add a third reader beside these two.
pub fn list_read_grants_read_only(
    store_path: &std::path::Path,
) -> Result<Vec<ReadGrant>, StoreOpError> {
    list_read_grants_read_only_with_schema(store_path).map(|(grants, _)| grants)
}

impl EncryptedStore {
    // ---- principal-scoped operation grants ------------------------------

    /// Create one operation grant and append its audit transition in one transaction so
    /// neither change can commit without the other.
    ///
    /// TWO PRINCIPAL KINDS, AND THE LIST IS CLOSED. `reserved` names a supervised module,
    /// attested by the supervisor's launch nonce. `enrolled` names a consumer this vault
    /// itself admitted through the enrollment ceremony. A grant may only name one of
    /// those two, and that closure is the reason `Principal::Direct` cannot be granted
    /// to: a grant to an unattested caller is a grant to every same-UID process on the
    /// machine, unrevocable in practice because there is nothing to revoke.
    ///
    /// `enrolled` is NOT validated against the live enrollment table here, deliberately.
    /// A grant may be created before its consumer enrolls — that is how an operator
    /// prepares reach for a module about to be installed — and coupling the two would
    /// make grant creation depend on ceremony ordering. What defends it is the resolver:
    /// a token only resolves to a name with a LIVE enrollment, so a grant naming a name
    /// that never enrolled, or one since revoked, reaches nothing.
    pub fn create_read_grant_audited(
        &self,
        principal_kind: &str,
        principal_id: &str,
        selector_kind: SelectorKind,
        selector: &str,
        operation: GrantOperation,
        ctx: AuditCtx<'_>,
    ) -> Result<(), StoreOpError> {
        validate_read_grant(
            principal_kind,
            principal_id,
            selector_kind,
            selector,
            operation,
        )?;
        let now = now_ms();
        let changed = self.fenced_write(|tx| {
            create_read_grant_audited_tx(
                tx,
                &self.audit_key,
                principal_kind,
                principal_id,
                selector_kind,
                selector,
                operation,
                now,
                ctx,
            )
        })?;
        if changed == 0 {
            return Err(StoreOpError::AlreadyExists);
        }
        Ok(())
    }

    /// Revoke exactly one selector-kind-specific grant and audit the transition.
    pub fn revoke_read_grant_audited(
        &self,
        principal_kind: &str,
        principal_id: &str,
        selector_kind: SelectorKind,
        selector: &str,
        operation: GrantOperation,
        ctx: AuditCtx<'_>,
    ) -> Result<(), StoreOpError> {
        selector_kind
            .validate_operation(operation)
            .map_err(StoreOpError::Store)?;
        // Before the closed kind list, it is the transfer key's own fence that answers:
        // an id under its prefix is refused by that name rather than by whichever
        // unrelated rule it happens to trip first. Revocation is fenced too, so the
        // vault and a caller cannot disagree about which grants the key may hold; the
        // admitted announce read can still be revoked.
        if matches!(selector_kind, SelectorKind::Exact) {
            crate::federation::transfer_key_admits_grant(
                selector,
                &format!("{principal_kind}:{principal_id}"),
                operation,
            )
            .map_err(|_| crate::federation::key_grant_refusal(selector))?;
        }
        // Same closed kind list as creation. If revocation accepted a NARROWER set than
        // creation, a grant could be created and never revocable through this API -- the
        // asymmetry that turns a reach mistake into a permanent one.
        if !matches!(principal_kind, "reserved" | "enrolled")
            || principal_id.is_empty()
            || principal_id.contains('|')
        {
            return Err(StoreOpError::InvalidPrincipal);
        }
        if selector.is_empty() {
            return Err(StoreOpError::InvalidCategoryName);
        }
        let changed = self.fenced_write(|tx| {
            revoke_read_grant_audited_tx(
                tx,
                &self.audit_key,
                principal_kind,
                principal_id,
                selector_kind,
                selector,
                operation,
                ctx,
            )
        })?;
        if changed == 0 {
            return Err(StoreOpError::NotFound);
        }
        Ok(())
    }

    /// Keep the boolean compatibility API by delegating to `evaluate_scoped_coverage`
    /// and returning only whether the requested operation is covered.
    pub fn read_grant_covers(
        &self,
        principal_kind: &str,
        principal_id: &str,
        credential_id: &str,
        operation: GrantOperation,
        declared: &DeclaredGrantSet,
    ) -> Result<bool, StoreOpError> {
        Ok(self
            .evaluate_scoped_coverage(
                principal_kind,
                principal_id,
                credential_id,
                operation,
                declared,
            )?
            .covered)
    }

    /// Evaluate all facts used by scoped authorization. Category rows are read only
    /// when no exact selector covered and this operation has a category selector.
    pub fn evaluate_scoped_coverage(
        &self,
        principal_kind: &str,
        principal_id: &str,
        credential_id: &str,
        operation: GrantOperation,
        declared: &DeclaredGrantSet,
    ) -> Result<ScopedCoverage, StoreOpError> {
        let bus_key = crate::federation::is_bus_key_id(credential_id);
        if bus_key {
            crate::federation::bus_key_admits_grant(
                credential_id,
                &format!("{principal_kind}:{principal_id}"),
                operation,
            )
            .map_err(|_| StoreOpError::BusKeyReserved)?;
        }
        if crate::agent_secret::is_deposit_key(credential_id) {
            return Err(StoreOpError::NotFound);
        }
        let exact_only = bus_key || crate::federation::is_bus_seal_key_id(credential_id);
        self.store
            .with_conn(|conn| {
                let mut grants = read_grants_from_conn(
                    conn,
                    Some(principal_kind),
                    Some(principal_id),
                    read_schema_version(conn)?,
                )?;
                declared.union_into(principal_kind, principal_id, &mut grants);
                let grants: Vec<_> = grants
                    .into_iter()
                    .filter(|grant| grant.operation == operation)
                    .filter(|grant| !exact_only || grant.selector_kind == SelectorKind::Exact)
                    .map(|grant| (grant.selector_kind.as_str().to_owned(), grant.selector))
                    .collect();
                let caller_active_grants = grants.len() as u32;
                if operation == GrantOperation::AccountToken {
                    return Ok(ScopedCoverage {
                        covered: grants.iter().any(|(kind, selector)| {
                            kind == SelectorKind::Audience.as_str() && credential_id == selector
                        }),
                        caller_active_grants,
                        holds_category_selector: false,
                        id_exists: false,
                        id_category_count: None,
                    });
                }
                if operation == GrantOperation::Deposit {
                    let categories = crate::catalog::category_defaults(credential_id);
                    return Ok(ScopedCoverage {
                        covered: grants.iter().any(|(kind, selector)| {
                            kind == SelectorKind::Category.as_str() && categories.contains(selector)
                        }),
                        caller_active_grants,
                        holds_category_selector: grants
                            .iter()
                            .any(|(kind, _)| kind == SelectorKind::Category.as_str()),
                        // A fresh id has no stored categories: authorize the vault-assigned
                        // defaults instead, without looking up any existing credential.
                        id_exists: false,
                        id_category_count: Some(categories.len() as u32),
                    });
                }
                // The stored kind text is compared through the enum rather than against a
                // literal spelled again here: this predicate reads raw columns, so a
                // vocabulary change that misses it would silently cover nothing.
                let holds_category_selector = grants
                    .iter()
                    .any(|(kind, _)| kind == SelectorKind::Category.as_str());
                let mut covered = grants.iter().any(|(kind, selector)| {
                    kind == SelectorKind::Exact.as_str() && credential_id == selector
                });
                // A remote record exists here as fully as a local one: local exact and
                // category grants reach it unchanged, with categories from this vault's
                // own remote-record set.
                let tables = metadata_tables_for(conn, credential_id)?;
                let id_exists = tables.is_some();

                let id_category_count = if !covered && holds_category_selector {
                    let mut categories_stmt = conn.prepare(&format!(
                        "SELECT category FROM {} WHERE credential_id = ?1 ORDER BY category",
                        tables.unwrap_or(MetadataTables::Local).categories()
                    ))?;
                    let categories = categories_stmt
                        .query_map(rusqlite::params![credential_id], |row| {
                            row.get::<_, String>(0)
                        })?
                        .collect::<rusqlite::Result<Vec<_>>>()?;
                    covered = grants.iter().any(|(kind, selector)| {
                        kind == SelectorKind::Category.as_str()
                            && categories.iter().any(|category| selector == category)
                    });
                    Some(categories.len() as u32)
                } else {
                    None
                };

                Ok(ScopedCoverage {
                    covered,
                    caller_active_grants,
                    holds_category_selector,
                    id_exists,
                    id_category_count,
                })
            })
            .map_err(StoreOpError::from)
    }

    /// The store-wide grant generation: every grant and category mutation advances it
    /// in its own transaction, so a consumer that observes a changed value knows the
    /// set of credentials it may reach has moved and re-enumerates.
    ///
    /// Seeded to 1 by the migration that creates the row, and a store row rather than
    /// a process counter, so it never regresses across a restart.
    pub fn grants_generation(&self) -> Result<u64, StoreOpError> {
        self.store
            .with_conn(|conn| {
                conn.query_row(
                    "SELECT value FROM grants_generation WHERE id = 1",
                    [],
                    |row| row.get::<_, i64>(0).map(|value| value as u64),
                )
            })
            .map_err(StoreOpError::from)
    }

    /// List every grant in deterministic principal/kind/selector/operation order.
    pub fn list_read_grants(&self) -> Result<Vec<ReadGrant>, StoreOpError> {
        self.store
            .with_conn(|conn| read_grants_from_conn(conn, None, None, read_schema_version(conn)?))
            .map_err(StoreOpError::from)
    }

    /// Enumerate one principal's visible rows and grants from one read snapshot.
    pub fn list_scoped_snapshot(
        &self,
        principal_kind: &str,
        principal_id: &str,
        declared: &DeclaredGrantSet,
    ) -> Result<ScopedListSnapshot, StoreOpError> {
        self.list_scoped_snapshot_inner(principal_kind, principal_id, declared, false, || Ok(()))
            .map(|(snapshot, _)| snapshot)
    }

    /// The list projection and held-key generations from the same SQLite snapshot.
    /// Key kind is sealed, so watch recomputation also opens sign/open-only rows
    /// internally. Neither their identity nor their material is disclosed by this API.
    pub fn watch_scoped_snapshot(
        &self,
        principal_kind: &str,
        principal_id: &str,
        declared: &DeclaredGrantSet,
    ) -> Result<(ScopedListSnapshot, Vec<(String, u64)>), StoreOpError> {
        self.list_scoped_snapshot_inner(principal_kind, principal_id, declared, true, || Ok(()))
    }

    #[cfg(test)]
    pub(super) fn list_scoped_snapshot_with_hook<F>(
        &self,
        principal_kind: &str,
        principal_id: &str,
        after_grants: F,
    ) -> Result<ScopedListSnapshot, StoreOpError>
    where
        F: FnOnce() -> rusqlite::Result<()>,
    {
        self.list_scoped_snapshot_inner(
            principal_kind,
            principal_id,
            &DeclaredGrantSet::empty(),
            false,
            after_grants,
        )
        .map(|(snapshot, _)| snapshot)
    }

    fn list_scoped_snapshot_inner<F>(
        &self,
        principal_kind: &str,
        principal_id: &str,
        declared: &DeclaredGrantSet,
        include_keys: bool,
        after_grants: F,
    ) -> Result<(ScopedListSnapshot, Vec<(String, u64)>), StoreOpError>
    where
        F: FnOnce() -> rusqlite::Result<()>,
    {
        self.store
            .with_conn(|conn| {
                let tx = conn.unchecked_transaction()?;
                let schema_version = read_schema_version(&tx)?;
                let registered_providers = registered_providers::from_conn(&tx)?;
                let mut grants = read_grants_from_conn(
                    &tx,
                    Some(principal_kind),
                    Some(principal_id),
                    schema_version,
                )?;
                declared.union_into(principal_kind, principal_id, &mut grants);
                grants.retain(|grant| grant.selector_kind != SelectorKind::Exact
                    || !crate::agent_secret::is_deposit_key(&grant.selector));
                after_grants()?;
                let mut stmt = tx.prepare(&format!(
                    "SELECT credential_id, record_version, state, envelope, \
                     COALESCE((SELECT group_concat(category, ',') FROM (\
                         SELECT category FROM credential_categories WHERE credential_id = credentials.credential_id ORDER BY category\
                      )), ''), {}, {}, {}, {}, {} FROM credentials ORDER BY credential_id",
                    provider_ids_column(schema_version), plan_tier_column(schema_version),
                    if schema_version >= 33 { "incarnation" } else { "''" },
                    plan_tier_observed_column(schema_version), plan_tier_since_column(schema_version)
                ))?;
                let candidates = stmt
                    .query_map([], |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, i64>(1)? as u64,
                            RecordState::from_str(&row.get::<_, String>(2)?),
                            row.get::<_, Vec<u8>>(3)?,
                            split_categories(row.get::<_, String>(4)?),
                            split_provider_ids(row.get::<_, String>(5)?),
                            row.get::<_, Option<String>>(6)?,
                            row.get::<_, String>(7)?,
                            row.get::<_, Option<i64>>(8)?,
                            row.get::<_, Option<i64>>(9)?,
                        ))
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                drop(stmt);

                let mut rows = Vec::new();
                let mut keys = Vec::new();
                for (id, record_version, state, envelope_bytes, categories, provider_ids, plan_tier, incarnation, operator_observed_at_ms, operator_since_ms) in
                    candidates
                {
                    if crate::agent_secret::is_deposit_key(&id) {
                        continue;
                    }
                    let operations: BTreeSet<GrantOperation> = grants
                        .iter()
                        .filter(|grant| grant.operation != GrantOperation::Deposit)
                        .filter(|grant| match grant.selector_kind {
                            SelectorKind::Exact => id == grant.selector,
                            SelectorKind::Audience => false,
                            SelectorKind::Category => categories
                                .iter()
                                .any(|category| grant.selector == category.as_str()),
                        })
                        .map(|grant| grant.operation)
                        .collect();
                    if operations.is_empty() {
                        continue;
                    }
                    // `read` and `list` both authorize the row's identity and adapter;
                    // a row reached only by `sign` or `open` stays sealed. Unsealing here
                    // serves metadata only, and no payload leaves this function.
                    //
                    // A row already quarantined as `corrupt` is listed sealed too, with
                    // state `corrupt` and no identity. The vault knows it can't be read,
                    // and unsealing it would fail this whole listing for every row the
                    // caller reaches. A row still stored as readable whose envelope fails
                    // to open does fail the snapshot below: that is corruption nothing has
                    // recorded yet, and it must not be listed as if it were healthy.
                    let disclose_identity = operations.contains(&GrantOperation::Read)
                        || operations.contains(&GrantOperation::List);
                    let is_gateway = disclose_identity && gateway::has_settings(&tx, &id)?;
                    let decoded_record = if state != RecordState::Corrupt
                        && (include_keys || disclose_identity)
                    {
                        let plaintext = envelope::open(
                            &self.key,
                            &envelope_bytes,
                            &RecordBinding {
                                credential_id: &id,
                                record_version,
                            },
                        )
                        .map_err(|error| {
                            rusqlite::Error::FromSqlConversionFailure(
                                3,
                                rusqlite::types::Type::Blob,
                                Box::new(error),
                            )
                        })?;
                        let record = VaultRecord::decode(&plaintext)
                                .map_err(|error| {
                                    rusqlite::Error::FromSqlConversionFailure(
                                        3,
                                        rusqlite::types::Type::Blob,
                                        Box::new(std::io::Error::new(
                                            std::io::ErrorKind::InvalidData,
                                            error.to_string(),
                                        )),
                                    )
                                })?;
                        let auth_method = crate::list_auth_method::list_auth_method_with_gateway(
                            record.kind,
                            record.refresh_adapter.as_deref(),
                            is_gateway,
                        );
                        if include_keys && record.kind.is_vault_held_key() {
                            keys.push((id.clone(), record_version));
                        }
                        disclose_identity.then_some((record.identity, record.refresh_adapter, auth_method, record.detected_plan, record.detected_plan_tier_observed_at_ms))
                    } else {
                        None
                    };
                    let (identity, refresh_adapter, auth_method, detected_plan, detected_observed_at_ms) = match decoded_record {
                        Some((identity, adapter, auth_method, detected_plan, observed)) => {
                            (Some(identity), adapter, auth_method, detected_plan, observed)
                        }
                        None => (None, None, is_gateway.then_some(crate::ListAuthMethod::Gateway), None, None),
                    };
                    let (plan_tier, plan_tier_source) = crate::plan_detection::effective_plan(
                        identity.as_ref().and(plan_tier), detected_plan.as_ref(),
                    );
                    rows.push(ScopedListRow {
                        plan_tier_since_ms: if plan_tier_source.as_deref() == Some("operator") { operator_since_ms } else { None },
                        provider: RegisteredProvider::service_for_id(&registered_providers, &id).map(str::to_owned),
                        incarnation,
                        plan_tier_observed_at_ms: match plan_tier_source.as_deref() {
                            Some("operator") => operator_observed_at_ms,
                            Some("detected") => detected_observed_at_ms,
                            _ => None,
                        },
                        id,
                        categories,
                        state,
                        record_version,
                        operations: operations.into_iter().collect(),
                        plan_tier,
                        plan_tier_source,
                        identity,
                        refresh_adapter,
                        provider_ids,
                        auth_method,
                    });
                }
                tx.commit()?;
                Ok((ScopedListSnapshot { rows, grants }, keys))
            })
            .map_err(StoreOpError::from)
    }

    /// Return one credential's sorted category set.
    ///
    /// For a remote record this is this vault's own set for it, kept in the remote
    /// tables.
    pub fn categories(&self, credential_id: &str) -> Result<Vec<String>, StoreOpError> {
        self.store
            .with_conn(|conn| {
                let tables =
                    metadata_tables_for(conn, credential_id)?.unwrap_or(MetadataTables::Local);
                let mut stmt = conn.prepare(&format!(
                    "SELECT category FROM {} WHERE credential_id = ?1 ORDER BY category",
                    tables.categories()
                ))?;
                let categories = stmt
                    .query_map(rusqlite::params![credential_id], |row| {
                        row.get::<_, String>(0)
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(categories)
            })
            .map_err(StoreOpError::from)
    }

    /// Apply a normalized category-set transition and append exactly one audit row.
    /// Returns false for a successful no-op.
    pub fn set_categories_audited(
        &self,
        credential_id: &str,
        mode: SetCategoryMode,
        categories: &[String],
        ctx: AuditCtx<'_>,
    ) -> Result<bool, StoreOpError> {
        if credential_id.contains('|') {
            return Err(StoreOpError::InvalidCredentialId);
        }
        let mut requested = BTreeSet::new();
        for category in categories {
            if !crate::catalog::valid_category_name(category) {
                return Err(StoreOpError::InvalidCategoryName);
            }
            requested.insert(category.clone());
        }
        let audit_key = self.audit_key.clone();
        self.fenced_write_or_refuse(|tx| {
            // Operator remote categories belong to this vault. A home-watch row's
            // categories are whatever the home computer last listed for it, so they
            // change only when the home changes its own record and the watch
            // delivers the new list.
            let Some(tables) = metadata_tables_for(tx, credential_id)? else {
                return Ok(Err(StoreOpError::NotFound));
            };
            if let MetadataTables::Remote = tables {
                let home_member = tx.query_row(
                    "SELECT home_member FROM remote_records WHERE credential_id = ?1 AND source = 'home_watch'",
                    [credential_id],
                    |row| row.get::<_, String>(0),
                ).optional()?;
                if let Some(home_member) = home_member {
                    return Ok(Err(StoreOpError::RemoteRecordHomeWatch {
                        credential_id: credential_id.to_string(),
                        home_member,
                    }));
                }
            }
            let mut stmt = tx.prepare(&format!(
                "SELECT category FROM {} WHERE credential_id = ?1 ORDER BY category",
                tables.categories()
            ))?;
            let current = stmt
                .query_map(rusqlite::params![credential_id], |row| {
                    row.get::<_, String>(0)
                })?
                .collect::<rusqlite::Result<BTreeSet<_>>>()?;
            drop(stmt);
            let resulting = match mode {
                SetCategoryMode::Set => requested.clone(),
                SetCategoryMode::Add => current.union(&requested).cloned().collect(),
                SetCategoryMode::Remove => current.difference(&requested).cloned().collect(),
            };
            if resulting == current {
                return Ok(Ok(false));
            }
            if tables == MetadataTables::Local && gateway::has_settings(tx, credential_id)? {
                return Ok(Err(StoreOpError::GatewayFixed {
                    rule: crate::gateway::GatewayFixedRule::Category,
                }));
            }
            tx.execute(
                &format!(
                    "DELETE FROM {} WHERE credential_id = ?1",
                    tables.categories()
                ),
                rusqlite::params![credential_id],
            )?;
            for category in &resulting {
                tx.execute(
                    &format!(
                        "INSERT INTO {} (credential_id, category) VALUES (?1, ?2)",
                        tables.categories()
                    ),
                    rusqlite::params![credential_id, category],
                )?;
            }
            append_audit_tx(
                tx,
                &audit_key,
                &AuditRecord {
                    op: ctx.op,
                    credential_id: Some(format!(
                        "category:{credential_id}|{}",
                        resulting.iter().cloned().collect::<Vec<_>>().join(",")
                    )),
                    payload_hash: None,
                    actor: ctx.actor.to_string(),
                    alarm: ctx.alarm,
                },
            )?;
            // An assignment changes what every category grant naming it reaches, so it
            // advances the same counter a grant mutation does.
            bump_grants_generation_tx(tx)?;
            Ok(Ok(true))
        })
    }

    /// One credential's provider ids in ascending byte order.
    /// Home-watch copies follow the home's ids; operator copies use this vault's ids.
    pub fn provider_ids(&self, credential_id: &str) -> Result<Vec<String>, StoreOpError> {
        self.store
            .with_conn(|conn| {
                if metadata_tables_for(conn, credential_id)? == Some(MetadataTables::Remote) {
                    let mut stmt = conn.prepare(
                        "SELECT provider_id FROM remote_record_provider_ids \
                         WHERE credential_id = ?1 ORDER BY provider_id",
                    )?;
                    let ids = stmt
                        .query_map([credential_id], |row| row.get::<_, String>(0))?
                        .collect::<rusqlite::Result<Vec<_>>>()?;
                    return Ok(ids);
                }
                provider_ids_from_conn(conn, credential_id, read_schema_version(conn)?)
            })
            .map_err(StoreOpError::from)
    }

    /// Apply a provider-id transition and return the resulting set in ascending byte
    /// order, also when it is unchanged or empty.
    ///
    /// Checks run in a fixed order and only the first failure is reported:
    /// `charset` then `length` for each requested id in request order, then
    /// `duplicate`, then the credential's existence, gateway restrictions, and `count`
    /// on the RESULTING set.
    /// The stored-state checks, the mapping write and the audit row share one
    /// transaction, so a refusal changes nothing.
    ///
    /// Only a change is audited, as `providers:<credential-id>|<sorted,list>`. The
    /// credential row and its sealed envelope are never read or written: provider ids
    /// live beside the record, so this succeeds on a retired or corrupt-envelope row
    /// and never moves `record_version`.
    pub fn set_providers_audited(
        &self,
        credential_id: &str,
        mode: SetProvidersMode,
        provider_ids: &[String],
        ctx: AuditCtx<'_>,
    ) -> Result<Vec<String>, StoreOpError> {
        crate::provider_ids::check_provider_ids(provider_ids)?;
        let audit_key = self.audit_key.clone();
        let outcome = self.fenced_write(|tx| {
            let Some(tables) = metadata_tables_for(tx, credential_id)? else {
                return Ok(Err(StoreOpError::NotFound));
            };
            let mut stmt = tx.prepare(&format!(
                "SELECT provider_id FROM {} WHERE credential_id = ?1",
                tables.provider_ids()
            ))?;
            let current = stmt
                .query_map(rusqlite::params![credential_id], |row| {
                    row.get::<_, String>(0)
                })?
                .collect::<rusqlite::Result<BTreeSet<_>>>()?;
            drop(stmt);
            let mut over_limit = None;
            let resulting = match mode {
                SetProvidersMode::Remove => {
                    let mut resulting = current.clone();
                    for id in provider_ids {
                        resulting.remove(id);
                    }
                    resulting
                }
                SetProvidersMode::Set | SetProvidersMode::Add => {
                    let mut resulting = match mode {
                        SetProvidersMode::Set => BTreeSet::new(),
                        _ => current.clone(),
                    };
                    // Grow the set in request order so the refusal names the first id
                    // whose addition crosses the cap (31 stored + `n1 n2` names `n2`).
                    for id in provider_ids {
                        resulting.insert(id.clone());
                        if over_limit.is_none()
                            && resulting.len()
                                > crate::provider_ids::MAX_PROVIDER_IDS_PER_CREDENTIAL
                        {
                            over_limit = Some(id.clone());
                        }
                    }
                    resulting
                }
            };
            if tables == MetadataTables::Local && gateway::has_settings(tx, credential_id)? {
                if resulting != current {
                    return Ok(Err(StoreOpError::GatewayFixed {
                        rule: crate::gateway::GatewayFixedRule::ProviderId,
                    }));
                }
            } else if mode != SetProvidersMode::Remove {
                if let Err(error) = crate::provider_ids::check_reserved_provider_ids(provider_ids) {
                    return Ok(Err(error));
                }
            }
            if let Some(value) = over_limit {
                return Ok(Err(StoreOpError::InvalidProviderId {
                    rule: crate::provider_ids::ProviderIdRule::Count,
                    value,
                }));
            }
            let resulting: Vec<String> = resulting.into_iter().collect();
            if resulting.iter().eq(current.iter()) {
                return Ok(Ok(resulting));
            }
            tx.execute(
                &format!(
                    "DELETE FROM {} WHERE credential_id = ?1",
                    tables.provider_ids()
                ),
                rusqlite::params![credential_id],
            )?;
            for id in &resulting {
                tx.execute(
                    &format!(
                        "INSERT INTO {} (credential_id, provider_id) VALUES (?1, ?2)",
                        tables.provider_ids()
                    ),
                    rusqlite::params![credential_id, id],
                )?;
            }
            // Split on the LAST `|` to parse: provider ids cannot contain one, while
            // the credential id before it is not constrained here.
            append_audit_tx(
                tx,
                &audit_key,
                &AuditRecord {
                    op: ctx.op,
                    credential_id: Some(format!(
                        "providers:{credential_id}|{}",
                        resulting.join(",")
                    )),
                    payload_hash: None,
                    actor: ctx.actor.to_string(),
                    alarm: ctx.alarm,
                },
            )?;
            Ok(Ok(resulting))
        })?;
        outcome
    }

    /// Set or clear a plaintext operator assertion without opening the envelope.
    /// Only a transition writes an audit row; the target records both old and new tiers.
    pub fn set_plan_audited(
        &self,
        credential_id: &str,
        plan_tier: Option<&str>,
        ctx: AuditCtx<'_>,
    ) -> Result<Option<String>, StoreOpError> {
        self.set_plan_since_audited(credential_id, plan_tier, None, ctx)
    }

    pub fn set_plan_since_audited(
        &self,
        credential_id: &str,
        plan_tier: Option<&str>,
        since_ms: Option<u64>,
        ctx: AuditCtx<'_>,
    ) -> Result<Option<String>, StoreOpError> {
        if plan_tier.is_some_and(|tier| !crate::plan_tier::valid_plan_tier(tier)) {
            return Err(StoreOpError::InvalidPlanTier);
        }
        if since_ms.is_some_and(|since| {
            plan_tier.is_none()
                || !crate::plan_tier::valid_plan_tier_since_ms(since, now_ms() as u64)
        }) {
            return Err(StoreOpError::InvalidPlanTier);
        }
        self.fenced_write(|tx| {
            let Some(tables) = metadata_tables_for(tx, credential_id)? else {
                return Ok(Err(StoreOpError::NotFound));
            };
            write_plan_tier_in_tx(
                tx,
                &self.audit_key,
                tables,
                credential_id,
                plan_tier,
                since_ms.map(|time| time as i64),
                ctx,
            )?;
            Ok(Ok(plan_tier.map(str::to_owned)))
        })?
    }

    pub fn detected_plans(&self) -> Result<DetectedPlanListing, StoreOpError> {
        self.store
            .with_conn(|conn| detected_plans_from_conn(conn, &self.key))
            .map_err(StoreOpError::from)
    }

    /// Open active and needs-reauth metadata without refreshing, quarantining, or
    /// recording use. Unreadable envelopes are omitted; database errors fail the read.
    pub fn home_watch_candidates(&self) -> Result<Vec<HomeWatchCandidate>, StoreOpError> {
        self.store
            .with_conn(|conn| home_watch_candidates_from_conn(conn, &self.key))
            .map_err(StoreOpError::from)
    }

    /// Refill empty category sets, or replace non-empty sets when forced. Enumeration,
    /// category writes, and all audit appends share one fenced transaction.
    pub fn reclassify_audited(
        &self,
        force: bool,
        ctx: AuditCtx<'_>,
    ) -> Result<usize, StoreOpError> {
        let audit_key = self.audit_key.clone();
        self.fenced_write(|tx| {
            let mut ids_stmt = tx.prepare("SELECT credential_id FROM credentials ORDER BY credential_id")?;
            let ids = ids_stmt
                .query_map([], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            drop(ids_stmt);
            // A CATEGORY AN ACTIVE GRANT SELECTS ON IS NOT THE REGISTRY'S TO REMOVE.
            //
            // `--force` deletes each credential's set and reinserts the registry's, so any
            // category the registry does not know is dropped. That includes every category
            // an operator assigned by hand AND every one a migration assigned: on this
            // vault `forge-identity` reaches 22 GitHub App credentials for a consumer that
            // mints tokens hourly, and it exists only as a migration-10 assignment list.
            // Running `--force` would have taken that grant to ZERO REACH, and the symptom
            // is `not_found` on credentials that plainly exist -- the anti-enumeration
            // answer, which by design says nothing about why.
            //
            // So the mass path refuses rather than warns. Collected BEFORE any write and
            // checked inside the same fenced transaction, so a grant created concurrently
            // cannot slip past. `set-category` on one credential is deliberately NOT
            // guarded this way: there the operator named the row and the category, and
            // this is the path that silently touches everything.
            //
            // A member grant selecting on a category is an active grant in the same sense:
            // stripping its category would silently cut another member's vault off.
            let granted_categories: BTreeSet<String> = {
                let mut sql = String::from(
                    "SELECT DISTINCT selector FROM read_grants WHERE selector_kind = 'category'",
                );
                if read_schema_version(tx)? >= MEMBER_GRANTS_SCHEMA_VERSION {
                    sql.push_str(
                        " UNION SELECT DISTINCT selector FROM member_grants \
                         WHERE selector_kind = 'category'",
                    );
                }
                let mut stmt = tx.prepare(&sql)?;
                let rows = stmt
                    .query_map([], |row| row.get::<_, String>(0))?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                drop(stmt);
                rows.into_iter().collect()
            };
            let mut changed = 0usize;
            for credential_id in ids {
                if gateway::has_settings(tx, &credential_id)? {
                    continue;
                }
                let defaults: BTreeSet<String> =
                    crate::catalog::category_defaults(&credential_id)
                        .into_iter()
                        .collect();
                if defaults.is_empty() || credential_id.contains('|') {
                    continue;
                }
                let mut categories_stmt = tx.prepare(
                    "SELECT category FROM credential_categories WHERE credential_id = ?1 ORDER BY category",
                )?;
                let current = categories_stmt
                    .query_map(rusqlite::params![&credential_id], |row| row.get::<_, String>(0))?
                    .collect::<rusqlite::Result<BTreeSet<_>>>()?;
                drop(categories_stmt);
                if (!force && !current.is_empty()) || current == defaults {
                    continue;
                }
                // Refuse before the first write if this would strip a category some grant
                // is selecting on. The whole call fails, so no credential is left half
                // reclassified and the operator gets one legible reason.
                let stripped: Vec<&String> = current
                    .difference(&defaults)
                    .filter(|category| granted_categories.contains(*category))
                    .collect();
                if let Some(category) = stripped.first() {
                    return Err(rusqlite::Error::SqliteFailure(
                        rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CONSTRAINT),
                        Some(format!(
                            "refusing: reclassify --force would remove category '{category}' \
                             from {credential_id}, and an active grant selects on it. That \
                             category is not in the registry, so --force cannot restore it \
                             and the grant would reach fewer credentials or none. Assign it \
                             with `ck auth set-category <id> --add {category}` or revoke the \
                             grant first."
                        )),
                    ));
                }
                tx.execute(
                    "DELETE FROM credential_categories WHERE credential_id = ?1",
                    rusqlite::params![&credential_id],
                )?;
                for category in &defaults {
                    tx.execute(
                        "INSERT INTO credential_categories (credential_id, category) VALUES (?1, ?2)",
                        rusqlite::params![&credential_id, category],
                    )?;
                }
                append_audit_tx(
                    tx,
                    &audit_key,
                    &AuditRecord {
                        op: ctx.op,
                        credential_id: Some(format!(
                            "category:{credential_id}|{}",
                            defaults.iter().cloned().collect::<Vec<_>>().join(",")
                        )),
                        payload_hash: None,
                        actor: ctx.actor.to_string(),
                        alarm: ctx.alarm,
                    },
                )?;
                changed += 1;
            }
            // One call is one mutation however many rows it refilled, and a call that
            // changed nothing is not a mutation at all.
            if changed > 0 {
                bump_grants_generation_tx(tx)?;
            }
            Ok(changed)
        })
        .map_err(StoreOpError::from)
    }
}
