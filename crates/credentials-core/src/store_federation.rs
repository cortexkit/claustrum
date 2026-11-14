//! Store APIs for home-vault federation: the settings that govern it, remote records
//! (rotating logins whose home is another member's vault) and member grants (what
//! another member's vault may do here).
//!
//! Every write here is a fenced transaction that commits its audit row with the
//! mutation, as everywhere else in the store. Settings are changed by audited admin
//! operations or by the daemon's config-file reader.

use super::*;
use crate::federation::{
    check_member_id, federation_gate_payload_hash, federation_self_payload_hash,
    is_lower_hex_16_bytes, member_grant_payload_hash, remote_membership_payload_hash,
    transfer_payload_hash, IncomingInsert, IncomingTransfer, IncomingTransferState, MemberGrant,
    MemberGrantOperation, MemberGrantSelector, MemberGrantSource, NewIncomingTransfer,
    NewOutgoingTransfer, NewRemoteRecord, OutgoingTransfer, OutgoingTransferState,
    PendingTransferCounts, RecoveredIncoming, RecoveredOutgoing, RemoteHomeState,
    RemoteHomeSuccess, RemoteInventoryRow, RemoteRecord, RemoteRecordSource, RemoteRecordWrite,
    SealedTransfer, TransferAcceptOutcome, TransferAcceptance, TransferKeyRecovery,
    VaultSharingMember, MEMBER_MAPPING_SETTING, REJECT_REMOTE_SEAL_INVALID,
    REJECT_SENDER_KEY_REPLACED, SELF_MEMBER_SETTING, TRANSFER_RETENTION_MS,
};
use crate::federation::{
    remote_watch_payload_hash, validate_remote_watch_row, RemoteWatchApplyMode,
    RemoteWatchApplyResult, RemoteWatchRow,
};

/// The longest fetch-outcome code stored. Outcomes are refusal codes this vault
/// chose (or `ok`), never text from a peer, so this bounds a column, not a format.
const MAX_FETCH_OUTCOME_LEN: usize = 64;

/// The longest pairing id stored. Callosum's pairing id is opaque and compared for
/// equality only, so this bounds a column, not a format.
const MAX_PAIRING_ID_LEN: usize = 128;

fn read_setting(conn: &rusqlite::Connection, name: &str) -> rusqlite::Result<Option<String>> {
    if read_schema_version(conn)? < SETTINGS_SCHEMA_VERSION {
        return Ok(None);
    }
    conn.query_row(
        "SELECT value FROM settings WHERE name = ?1",
        [name],
        |row| row.get(0),
    )
    .optional()
}

fn write_setting_tx(tx: &rusqlite::Transaction, name: &str, value: &str) -> rusqlite::Result<()> {
    tx.execute(
        "INSERT INTO settings (name, value, updated_at_ms) VALUES (?1, ?2, ?3) \
         ON CONFLICT(name) DO UPDATE SET value = excluded.value, updated_at_ms = excluded.updated_at_ms",
        rusqlite::params![name, value, now_ms()],
    )?;
    Ok(())
}

/// A stored gate value other than the two this code writes reads as off: the gate
/// fails closed, so damage can never switch member mapping on.
fn gate_from_stored(value: Option<&str>) -> bool {
    value == Some("true")
}

const LOGIN_SHARING_SETTING: &str = "federation.login_sharing";

fn login_sharing_conn(conn: &rusqlite::Connection) -> rusqlite::Result<bool> {
    Ok(matches!(
        read_setting(conn, LOGIN_SHARING_SETTING)?.as_deref(),
        None | Some("true")
    ))
}

fn mint_incarnation() -> Result<String, StoreOpError> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).map_err(|e| StoreOpError::Encode(format!("csprng: {e}")))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn remote_record_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RemoteRecord> {
    let detected_plan: Option<String> = row.get("detected_plan")?;
    let detected_plan = detected_plan
        .map(|json| {
            serde_json::from_str(&json).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            })
        })
        .transpose()?;
    let state: String = row.get("last_home_state")?;
    let last_home_state = RemoteHomeState::from_stored(&state).ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Text,
            format!("unknown remote home state {state:?}").into(),
        )
    })?;
    let source: String = match row.get("source") {
        Err(rusqlite::Error::InvalidColumnName(_)) => "operator".into(),
        value => value?,
    };
    let source = RemoteRecordSource::from_stored(&source).ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Text,
            format!("unknown remote record source {source:?}").into(),
        )
    })?;
    Ok(RemoteRecord {
        detected_plan_tier_observed_at_ms: match row.get("detected_plan_tier_observed_at_ms") {
            Err(rusqlite::Error::InvalidColumnName(_)) => None,
            value => value?,
        },
        credential_id: row.get("credential_id")?,
        home_member: row.get("home_member")?,
        source,
        home_pairing_id: match row.get("home_pairing_id") {
            Err(rusqlite::Error::InvalidColumnName(_)) => None,
            value => value?,
        },
        incarnation: row.get("incarnation")?,
        refresh_adapter: row.get("refresh_adapter")?,
        detected_plan,
        identity: RecordIdentity {
            account_id: row.get("account_id")?,
            email: row.get("email")?,
            org_name: row.get("org_name")?,
        },
        last_home_version: row.get::<_, i64>("last_home_version")? as u64,
        last_home_state,
        last_home_error: row.get("last_home_error")?,
        last_fetch_outcome: row.get("last_fetch_outcome")?,
        last_fetch_at_ms: row.get("last_fetch_at_ms")?,
        reported_version: row
            .get::<_, Option<i64>>("reported_version")?
            .map(|version| version as u64),
        created_at_ms: row.get("created_at_ms")?,
        updated_at_ms: row.get("updated_at_ms")?,
    })
}

fn check_member_grant_shape(
    operation: MemberGrantOperation,
    selector: &MemberGrantSelector,
) -> Result<(), StoreOpError> {
    match (operation, selector) {
        (MemberGrantOperation::RemoteRead, MemberGrantSelector::Exact(id)) => {
            if id.is_empty() {
                return Err(StoreOpError::InvalidCredentialId);
            }
            validate_deposit_credential_id(id)
        }
        (MemberGrantOperation::RemoteRead, MemberGrantSelector::Category(category)) => {
            if crate::catalog::valid_category_name(category) {
                Ok(())
            } else {
                Err(StoreOpError::InvalidCategoryName)
            }
        }
        (
            MemberGrantOperation::TransferDeliver | MemberGrantOperation::SecretUse,
            MemberGrantSelector::None,
        ) => Ok(()),
        (MemberGrantOperation::RemoteRead, MemberGrantSelector::None) => Err(StoreOpError::Encode(
            "remote_read needs an exact or category selector".into(),
        )),
        (MemberGrantOperation::TransferDeliver, _) => Err(StoreOpError::Encode(
            "transfer_deliver takes no selector".into(),
        )),
        (MemberGrantOperation::SecretUse, _) => {
            Err(StoreOpError::Encode("secret_use takes no selector".into()))
        }
    }
}

/// A fetch outcome or home error is a code: 1 to 64 characters of lowercase ASCII,
/// digits and `_`. Anything else is refused, so a peer's text can never reach a
/// plaintext column through these writes.
fn check_outcome_code(code: &str) -> Result<(), StoreOpError> {
    if code.is_empty()
        || code.len() > MAX_FETCH_OUTCOME_LEN
        || !code
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(StoreOpError::Encode(format!(
            "a remote outcome code must be 1 to {MAX_FETCH_OUTCOME_LEN} characters of a-z, 0-9 and _"
        )));
    }
    Ok(())
}

/// The row for (`credential_id`, `incarnation`), or `None` when the record is gone or
/// was added again under another incarnation.
fn remote_record_at_incarnation(
    tx: &rusqlite::Transaction,
    credential_id: &str,
    incarnation: &str,
) -> rusqlite::Result<Option<RemoteRecord>> {
    tx.query_row(
        "SELECT * FROM remote_records WHERE credential_id = ?1 AND incarnation = ?2",
        [credential_id, incarnation],
        remote_record_from_row,
    )
    .optional()
}

/// After an UPDATE conditioned on id and incarnation changed nothing: was that because
/// the row already held the values, or because the incarnation no longer matches?
fn unchanged_or_stale(
    tx: &rusqlite::Transaction,
    credential_id: &str,
    incarnation: &str,
) -> rusqlite::Result<RemoteRecordWrite> {
    let exists: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM remote_records WHERE credential_id = ?1 AND incarnation = ?2)",
        [credential_id, incarnation],
        |row| row.get(0),
    )?;
    Ok(if exists {
        RemoteRecordWrite::Unchanged
    } else {
        RemoteRecordWrite::StaleIncarnation
    })
}

fn check_pairing_id(pairing_id: &str) -> Result<(), StoreOpError> {
    if pairing_id.is_empty()
        || pairing_id.len() > MAX_PAIRING_ID_LEN
        || !pairing_id.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(StoreOpError::Encode(format!(
            "pairing_id must be 1 to {MAX_PAIRING_ID_LEN} printable ASCII characters"
        )));
    }
    Ok(())
}

#[derive(Default)]
struct RemoteWatchDiff<'a> {
    inserts: Vec<&'a RemoteWatchRow>,
    updates: Vec<(RemoteRecord, &'a RemoteWatchRow, bool)>,
    removals: Vec<RemoteRecord>,
    skipped: Vec<String>,
}

impl RemoteWatchDiff<'_> {
    fn result(&self) -> RemoteWatchApplyResult {
        RemoteWatchApplyResult {
            inserted: self.inserts.len(),
            updated: self.updates.len(),
            removed: self.removals.len(),
            skipped: self.skipped.clone(),
        }
    }

    fn is_empty(&self) -> bool {
        self.inserts.is_empty() && self.updates.is_empty() && self.removals.is_empty()
    }
}

fn remote_watch_records_conn(
    conn: &rusqlite::Connection,
    home: &str,
) -> rusqlite::Result<Vec<RemoteRecord>> {
    let mut stmt = conn.prepare(
        "SELECT * FROM remote_records WHERE source = 'home_watch' AND home_member = ?1 \
         ORDER BY credential_id",
    )?;
    let rows = stmt.query_map([home], remote_record_from_row)?.collect();
    rows
}

fn remote_categories_conn(
    conn: &rusqlite::Connection,
    id: &str,
) -> rusqlite::Result<BTreeSet<String>> {
    let mut stmt =
        conn.prepare("SELECT category FROM remote_record_categories WHERE credential_id = ?1")?;
    let rows = stmt.query_map([id], |row| row.get(0))?.collect();
    rows
}

fn remote_watch_diff_conn<'a>(
    conn: &rusqlite::Connection,
    home: &str,
    pairing: &str,
    rows: &'a [RemoteWatchRow],
    mode: RemoteWatchApplyMode,
    retained_ids: &[String],
) -> rusqlite::Result<RemoteWatchDiff<'a>> {
    let mut diff = RemoteWatchDiff::default();
    for row in rows {
        let id = &row.credential_id;
        if retained_ids.contains(id) {
            continue;
        }
        let current = conn
            .query_row(
                "SELECT * FROM remote_records WHERE credential_id = ?1",
                [id],
                remote_record_from_row,
            )
            .optional()?;
        match current {
            Some(current)
                if current.source == RemoteRecordSource::HomeWatch
                    && current.home_member == home
                    && current.home_pairing_id.as_deref() == Some(pairing) =>
            {
                if mode == RemoteWatchApplyMode::InsertOnly {
                    continue;
                }
                let categories_changed =
                    remote_categories_conn(conn, id)? != row.categories.iter().cloned().collect();
                let same_plan = current.detected_plan.as_ref().map(|p| (&p.tier, &p.raw))
                    == row.detected_plan.as_ref().map(|p| (&p.tier, &p.raw));
                if categories_changed
                    || !same_plan
                    || current.refresh_adapter != row.refresh_adapter
                    || current.identity != row.identity
                    || current.last_home_state != row.state
                {
                    diff.updates.push((current, row, categories_changed));
                }
            }
            Some(_) => diff.skipped.push(id.clone()),
            None => {
                let local: bool = conn.query_row(
                    "SELECT EXISTS(SELECT 1 FROM credentials WHERE credential_id = ?1)",
                    [id],
                    |r| r.get(0),
                )?;
                if local {
                    diff.skipped.push(id.clone());
                } else {
                    diff.inserts.push(row);
                }
            }
        }
    }
    if mode == RemoteWatchApplyMode::Full {
        for record in remote_watch_records_conn(conn, home)? {
            if record.home_pairing_id.as_deref() == Some(pairing)
                && !rows
                    .iter()
                    .any(|row| row.credential_id == record.credential_id)
                && !retained_ids.contains(&record.credential_id)
            {
                diff.removals.push(record);
            }
        }
    }
    Ok(diff)
}

fn audit_remote_watch_tx(
    tx: &rusqlite::Transaction,
    audit_key: &[u8; 32],
    home: &str,
    id: &str,
    incarnation: &str,
    op: AuditOp,
) -> rusqlite::Result<()> {
    let payload =
        remote_watch_payload_hash(home, incarnation).map_err(|e| bad_column(e.to_string()))?;
    append_audit_tx(
        tx,
        audit_key,
        &AuditRecord {
            op,
            credential_id: Some(id.into()),
            payload_hash: Some(payload),
            actor: "vault".into(),
            alarm: None,
        },
    )?;
    Ok(())
}

fn remove_remote_watch_tx(
    tx: &rusqlite::Transaction,
    audit_key: &[u8; 32],
    record: &RemoteRecord,
) -> rusqlite::Result<()> {
    let mut categories = 0;
    // Guard the metadata deletions too: a converted operator row owns all of its
    // metadata, even when foreign-key cascades are disabled on this connection.
    for table in [
        "remote_record_categories",
        "remote_record_provider_ids",
        "remote_record_plan_tiers",
        "auth_events",
    ] {
        let deleted = tx.execute(
            &format!(
                "DELETE FROM {table} WHERE credential_id = ?1 AND EXISTS (\
             SELECT 1 FROM remote_records WHERE credential_id = ?1 \
             AND source = 'home_watch' AND home_member = ?2 AND home_pairing_id = ?3)",
            ),
            rusqlite::params![
                record.credential_id,
                record.home_member,
                record.home_pairing_id
            ],
        )?;
        if table == "remote_record_categories" {
            categories = deleted;
        }
    }
    let deleted = tx.execute(
        "DELETE FROM remote_records WHERE credential_id = ?1 AND source = 'home_watch' \
         AND home_member = ?2 AND home_pairing_id = ?3",
        rusqlite::params![
            record.credential_id,
            record.home_member,
            record.home_pairing_id
        ],
    )?;
    if categories > 0 {
        bump_grants_generation_tx(tx)?;
    }
    if deleted > 0 {
        audit_remote_watch_tx(
            tx,
            audit_key,
            &record.home_member,
            &record.credential_id,
            &record.incarnation,
            AuditOp::RemoteRemove,
        )?;
    }
    Ok(())
}

impl EncryptedStore {
    pub fn login_sharing(&self) -> Result<bool, StoreOpError> {
        self.store
            .with_conn(login_sharing_conn)
            .map_err(StoreOpError::from)
    }

    /// Commit the setting and all automatic-state removals together. In-flight
    /// reconcilers recheck this setting in their own transaction before inserting.
    pub fn set_login_sharing_audited(
        &self,
        enabled: bool,
        actor: &str,
    ) -> Result<bool, StoreOpError> {
        let wanted = if enabled { "true" } else { "false" };
        if self
            .store
            .with_conn(|conn| read_setting(conn, LOGIN_SHARING_SETTING))?
            .as_deref()
            == Some(wanted)
        {
            return Ok(false);
        }
        self.fenced_write(|tx| {
            if read_setting(tx, LOGIN_SHARING_SETTING)?.as_deref() == Some(wanted) {
                return Ok(false);
            }
            write_setting_tx(tx, LOGIN_SHARING_SETTING, wanted)?;
            if !enabled {
                for grant in member_grants_conn(tx)?
                    .into_iter()
                    .filter(|g| g.source == MemberGrantSource::SharingSwitch)
                {
                    revoke_member_grant_tx(tx, &self.audit_key, &grant)?;
                }
                let homes = {
                    let mut stmt = tx.prepare(
                        "SELECT DISTINCT home_member FROM remote_records WHERE source='home_watch'",
                    )?;
                    let homes = stmt
                        .query_map([], |row| row.get::<_, String>(0))?
                        .collect::<rusqlite::Result<Vec<_>>>()?;
                    homes
                };
                for home in homes {
                    for record in remote_watch_records_conn(tx, &home)? {
                        remove_remote_watch_tx(tx, &self.audit_key, &record)?;
                    }
                }
            }
            append_audit_tx(
                tx,
                &self.audit_key,
                &AuditRecord {
                    op: AuditOp::LoginSharingSet,
                    credential_id: None,
                    payload_hash: Some(
                        payload_hash(wanted.as_bytes())
                            .iter()
                            .map(|b| format!("{b:02x}"))
                            .collect(),
                    ),
                    actor: actor.to_owned(),
                    alarm: None,
                },
            )?;
            Ok(true)
        })
        .map_err(StoreOpError::from)
    }

    /// Whether the federation member-mapping gate is on. Read from the store on every
    /// call, so a change made by the admin op takes effect without a restart. Unset,
    /// or a store from before federation, reads as off.
    pub fn federation_member_mapping(&self) -> Result<bool, StoreOpError> {
        self.store
            .with_conn(|conn| read_setting(conn, MEMBER_MAPPING_SETTING))
            .map(|value| gate_from_stored(value.as_deref()))
            .map_err(StoreOpError::from)
    }

    /// This vault's own member id, or `None` when it has not been set. Read from the
    /// store on every call, like the gate.
    pub fn federation_self_member(&self) -> Result<Option<String>, StoreOpError> {
        self.store
            .with_conn(|conn| read_setting(conn, SELF_MEMBER_SETTING))
            .map_err(StoreOpError::from)
    }

    /// Switch the member-mapping gate, auditing the change as `ctx.op` (the admin path
    /// passes `federation_gate_set`) with `payload_hash` over `{value}`. Setting the
    /// value it already has writes nothing and returns `false`.
    pub fn set_federation_member_mapping_audited(
        &self,
        enabled: bool,
        ctx: AuditCtx<'_>,
    ) -> Result<bool, StoreOpError> {
        let audit_key = self.audit_key.clone();
        let wanted = if enabled { "true" } else { "false" };
        self.fenced_write(|tx| {
            // Compared with the stored text, not the effective value: a damaged row
            // reads as off, and asking for off then rewrites it to exactly `false`.
            if read_setting(tx, MEMBER_MAPPING_SETTING)?.as_deref() == Some(wanted) {
                return Ok(false);
            }
            write_setting_tx(tx, MEMBER_MAPPING_SETTING, wanted)?;
            append_audit_tx(
                tx,
                &audit_key,
                &AuditRecord {
                    op: ctx.op,
                    credential_id: None,
                    payload_hash: Some(federation_gate_payload_hash(enabled)),
                    actor: ctx.actor.to_string(),
                    alarm: ctx.alarm,
                },
            )?;
            Ok(true)
        })
        .map_err(StoreOpError::from)
    }

    /// Set this vault's own member id, auditing the change as `ctx.op` (the admin path
    /// passes `federation_self_set`) with `payload_hash` over `{member}`. Setting the
    /// value it already has writes nothing and returns `false`.
    pub fn set_federation_self_member_audited(
        &self,
        member: &str,
        ctx: AuditCtx<'_>,
    ) -> Result<bool, StoreOpError> {
        check_member_id(member)?;
        let audit_key = self.audit_key.clone();
        self.fenced_write(|tx| {
            if read_setting(tx, SELF_MEMBER_SETTING)?.as_deref() == Some(member) {
                return Ok(false);
            }
            write_setting_tx(tx, SELF_MEMBER_SETTING, member)?;
            append_audit_tx(
                tx,
                &audit_key,
                &AuditRecord {
                    op: ctx.op,
                    credential_id: None,
                    payload_hash: Some(federation_self_payload_hash(member)),
                    actor: ctx.actor.to_string(),
                    alarm: ctx.alarm,
                },
            )?;
            Ok(true)
        })
        .map_err(StoreOpError::from)
    }

    /// Fix a remote row's incarnation, which `remote_add_audited` mints at random, so a
    /// wire fixture built from real replies is byte-identical on every run.
    #[cfg(any(test, feature = "test-support"))]
    pub fn force_remote_incarnation_for_test(&self, credential_id: &str, incarnation: &str) {
        assert_eq!(incarnation.len(), 32);
        assert!(incarnation.bytes().all(|byte| byte.is_ascii_hexdigit()));
        let changed = self
            .fenced_write(|tx| {
                tx.execute(
                    "UPDATE remote_records SET incarnation = ?1 WHERE credential_id = ?2",
                    rusqlite::params![incarnation, credential_id],
                )
            })
            .unwrap();
        assert_eq!(changed, 1, "no remote record {credential_id}");
    }

    /// Register a remote record from one validated home reply, with a fresh
    /// incarnation, and seed this vault's categories for it from that reply.
    ///
    /// Refuses an id that already holds a local record
    /// ([`StoreOpError::CredentialIdIsLocal`], from the id-uniqueness trigger) or a
    /// remote one ([`StoreOpError::AlreadyExists`]): re-homing is remove, then add.
    /// Audited `remote_add` with the home member as actor and `payload_hash` over
    /// `{incarnation}`, in the same transaction as the rows.
    pub fn remote_add_audited(&self, new: &NewRemoteRecord) -> Result<RemoteRecord, StoreOpError> {
        validate_remote_watch_row(
            &new.home_member,
            &RemoteWatchRow {
                credential_id: new.credential_id.clone(),
                state: RemoteHomeState::Active,
                refresh_adapter: new.refresh_adapter.clone(),
                identity: new.identity.clone(),
                categories: new.categories.clone(),
                detected_plan: new.detected_plan.clone(),
                home_version: new.home_version,
            },
        )?;
        let categories: BTreeSet<&String> = new.categories.iter().collect();
        let incarnation = mint_incarnation()?;
        let payload_hash = remote_membership_payload_hash(&incarnation)?;
        let detected_plan = new
            .detected_plan
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|e| StoreOpError::Encode(e.to_string()))?;
        let home_version = i64::try_from(new.home_version)
            .map_err(|_| StoreOpError::Encode("home record_version out of range".into()))?;
        let audit_key = self.audit_key.clone();
        let now = now_ms();
        let inserted = self.fenced_write(|tx| {
            let inserted = tx.execute(
                "INSERT INTO remote_records \
                 (credential_id, home_member, incarnation, kind, refresh_adapter, detected_plan, \
                  account_id, email, org_name, last_home_version, last_home_state, \
                  created_at_ms, updated_at_ms, detected_plan_tier_observed_at_ms) \
                 VALUES (?1, ?2, ?3, 'oauth', ?4, ?5, ?6, ?7, ?8, ?9, 'active', ?10, ?10, ?11) \
                 ON CONFLICT(credential_id) DO NOTHING",
                rusqlite::params![
                    new.credential_id,
                    new.home_member,
                    incarnation,
                    new.refresh_adapter,
                    detected_plan,
                    new.identity.account_id,
                    new.identity.email,
                    new.identity.org_name,
                    home_version,
                    now,
                    new.detected_plan.as_ref().filter(|p| p.tier.is_some()).map(|p| p.observed_at_ms),
                ],
            )?;
            if inserted == 0 {
                return Ok(false);
            }
            for category in &categories {
                tx.execute(
                    "INSERT INTO remote_record_categories (credential_id, category) VALUES (?1, ?2)",
                    rusqlite::params![new.credential_id, category],
                )?;
            }
            // New categories change what every category grant naming them reaches.
            if !categories.is_empty() {
                bump_grants_generation_tx(tx)?;
            }
            append_audit_tx(
                tx,
                &audit_key,
                &AuditRecord {
                    op: AuditOp::RemoteAdd,
                    credential_id: Some(new.credential_id.clone()),
                    payload_hash: Some(payload_hash.clone()),
                    actor: new.home_member.clone(),
                    alarm: Some(AlarmReason::AdminWrite),
                },
            )?;
            Ok(true)
        })?;
        if !inserted {
            return Err(StoreOpError::AlreadyExists);
        }
        self.remote_record(&new.credential_id)?
            .ok_or(StoreOpError::NotFound)
    }

    /// Convert a row created by the specified home's watch to operator ownership
    /// without fetching from the home.
    /// The incarnation and all metadata are retained. The source check, the update and
    /// a RemoteAdd audit row (the same row an operator `remote add` writes) commit in
    /// one fenced transaction, so a refusal leaves nothing behind.
    pub fn remote_convert_home_watch_audited(
        &self,
        credential_id: &str,
        home_member: &str,
    ) -> Result<RemoteRecord, StoreOpError> {
        check_member_id(home_member)?;
        self.fenced_write_or_refuse(|tx| {
            let Some(mut record) = tx
                .query_row(
                    "SELECT * FROM remote_records WHERE credential_id = ?1",
                    [credential_id],
                    remote_record_from_row,
                )
                .optional()?
            else {
                return Ok(Err(StoreOpError::NotFound));
            };
            if record.source == RemoteRecordSource::Operator {
                return Ok(Err(StoreOpError::AlreadyExists));
            }
            if record.home_member != home_member {
                return Ok(Err(StoreOpError::RemoteRecordHomeWatch {
                    credential_id: credential_id.to_string(),
                    home_member: record.home_member,
                }));
            }
            let payload_hash = remote_membership_payload_hash(&record.incarnation)
                .map_err(|e| bad_column(e.to_string()))?;
            tx.execute(
                "UPDATE remote_records SET source = 'operator', home_pairing_id = NULL \
                 WHERE credential_id = ?1 AND home_member = ?2 AND source = 'home_watch'",
                rusqlite::params![credential_id, home_member],
            )?;
            append_audit_tx(
                tx,
                &self.audit_key,
                &AuditRecord {
                    op: AuditOp::RemoteAdd,
                    credential_id: Some(credential_id.to_string()),
                    payload_hash: Some(payload_hash),
                    actor: home_member.to_string(),
                    alarm: Some(AlarmReason::AdminWrite),
                },
            )?;
            record.source = RemoteRecordSource::Operator;
            record.home_pairing_id = None;
            Ok(Ok(record))
        })
    }

    /// Remove an operator remote record and every row this vault keeps for it.
    /// Rows created by a home watch refuse removal until converted with a remote add
    /// for that same home.
    ///
    /// The category, provider-id and plan-tier rows are deleted explicitly rather than
    /// by the foreign-key cascade, because SQLite enforces foreign keys per connection
    /// and nothing guarantees the setting is on: a re-added id must start with no
    /// leftover metadata either way. Its `auth_events` rows go too, as for a local
    /// removal. Audited `remote_remove` with the home member as actor and
    /// `payload_hash` over the removed `{incarnation}`.
    pub fn remote_remove_audited(&self, credential_id: &str) -> Result<RemoteRecord, StoreOpError> {
        let audit_key = self.audit_key.clone();
        self.fenced_write_or_refuse(|tx| {
            let Some(record) = tx
                .query_row(
                    "SELECT * FROM remote_records WHERE credential_id = ?1",
                    [credential_id],
                    remote_record_from_row,
                )
                .optional()?
            else {
                return Ok(Err(StoreOpError::NotFound));
            };
            if record.source == RemoteRecordSource::HomeWatch {
                return Ok(Err(StoreOpError::RemoteRecordHomeWatch {
                    credential_id: credential_id.to_string(),
                    home_member: record.home_member,
                }));
            }
            let payload_hash =
                remote_membership_payload_hash(&record.incarnation).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Text,
                        e.to_string().into(),
                    )
                })?;
            let categories = tx.execute(
                "DELETE FROM remote_record_categories WHERE credential_id = ?1",
                [credential_id],
            )?;
            tx.execute(
                "DELETE FROM remote_record_provider_ids WHERE credential_id = ?1",
                [credential_id],
            )?;
            tx.execute(
                "DELETE FROM remote_record_plan_tiers WHERE credential_id = ?1",
                [credential_id],
            )?;
            tx.execute(
                "DELETE FROM remote_records WHERE credential_id = ?1",
                [credential_id],
            )?;
            tx.execute(
                "DELETE FROM auth_events WHERE credential_id = ?1",
                [credential_id],
            )?;
            if categories > 0 {
                bump_grants_generation_tx(tx)?;
            }
            append_audit_tx(
                tx,
                &audit_key,
                &AuditRecord {
                    op: AuditOp::RemoteRemove,
                    credential_id: Some(credential_id.to_string()),
                    payload_hash: Some(payload_hash),
                    actor: record.home_member.clone(),
                    alarm: Some(AlarmReason::AdminWrite),
                },
            )?;
            Ok(Ok(record))
        })
    }

    /// Apply a home's snapshot without touching operator, local or other homes'
    /// records. `retained_ids` names listed rows the caller rejected during validation:
    /// Full mode neither updates nor removes those ids, even if no valid row remains.
    /// Unknown or unparseable retained ids simply match nothing. InsertOnly retries
    /// collisions without replaying old metadata or deleting any row.
    ///
    /// A read-only preflight avoids a fenced commit (and its write signal) for an
    /// empty diff. A non-empty diff is recomputed inside one fenced transaction.
    pub fn remote_watch_apply_audited(
        &self,
        home_member: &str,
        pairing_id: &str,
        rows: &[RemoteWatchRow],
        mode: RemoteWatchApplyMode,
        retained_ids: &[String],
    ) -> Result<RemoteWatchApplyResult, StoreOpError> {
        check_member_id(home_member)?;
        check_pairing_id(pairing_id)?;
        let mut ids = BTreeSet::new();
        for row in rows {
            validate_remote_watch_row(home_member, row)?;
            if !ids.insert(&row.credential_id) {
                return Err(StoreOpError::Encode(
                    "duplicate home-watch credential id".into(),
                ));
            }
        }
        let preflight = self.store.with_conn(|conn| {
            if !login_sharing_conn(conn)? {
                return Ok((true, RemoteWatchApplyResult::default()));
            }
            let diff =
                remote_watch_diff_conn(conn, home_member, pairing_id, rows, mode, retained_ids)?;
            Ok((diff.is_empty(), diff.result()))
        })?;
        if preflight.0 {
            return Ok(preflight.1);
        }
        self.fenced_write(|tx| {
            let diff = remote_watch_diff_conn(tx, home_member, pairing_id, rows, mode, retained_ids)?;
            if !login_sharing_conn(tx)? {
                return Ok(RemoteWatchApplyResult::default());
            }
            let result = diff.result();
            let now = now_ms();
            for row in diff.inserts {
                let incarnation = mint_incarnation().map_err(|e| bad_column(e.to_string()))?;
                let plan = row.detected_plan.as_ref().map(serde_json::to_string).transpose()
                    .map_err(|e| bad_column(e.to_string()))?;
                tx.execute(
                    "INSERT INTO remote_records \
                     (credential_id, home_member, source, home_pairing_id, incarnation, kind, \
                      refresh_adapter, detected_plan, account_id, email, org_name, last_home_version, \
                      last_home_state, created_at_ms, updated_at_ms, detected_plan_tier_observed_at_ms) \
                     VALUES (?1, ?2, 'home_watch', ?3, ?4, 'oauth', ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?12, ?13)",
                    rusqlite::params![row.credential_id, home_member, pairing_id, incarnation,
                        row.refresh_adapter, plan, row.identity.account_id, row.identity.email,
                        row.identity.org_name, row.home_version as i64, row.state.as_str(), now,
                        row.detected_plan.as_ref().filter(|p| p.tier.is_some()).map(|p| p.observed_at_ms)],
                )?;
                let categories: BTreeSet<_> = row.categories.iter().collect();
                for category in &categories {
                    tx.execute("INSERT INTO remote_record_categories (credential_id, category) VALUES (?1, ?2)",
                        rusqlite::params![row.credential_id, category])?;
                }
                if !categories.is_empty() {
                    bump_grants_generation_tx(tx)?;
                }
                audit_remote_watch_tx(tx, &self.audit_key, home_member, &row.credential_id,
                    &incarnation, AuditOp::RemoteAdd)?;
            }
            for (current, row, categories_changed) in diff.updates {
                let plan = row.detected_plan.as_ref().map(serde_json::to_string).transpose()
                    .map_err(|e| bad_column(e.to_string()))?;
                let observed_at = row.detected_plan.as_ref().and_then(|plan| {
                    let tier = plan.tier.as_ref()?;
                    if current.identity.account_id == row.identity.account_id
                        && current.detected_plan.as_ref().and_then(|p| p.tier.as_ref()) == Some(tier) {
                        current.detected_plan_tier_observed_at_ms
                    } else {
                        Some(plan.observed_at_ms)
                    }
                });
                tx.execute(
                    "UPDATE remote_records SET refresh_adapter = ?4, detected_plan = ?5, \
                     account_id = ?6, email = ?7, org_name = ?8, last_home_state = ?9, \
                     last_home_error = CASE WHEN last_home_state != 'active' AND ?9 = 'active' \
                         THEN NULL ELSE last_home_error END, \
                     updated_at_ms = ?10, detected_plan_tier_observed_at_ms = ?11 \
                     WHERE credential_id = ?1 AND source = 'home_watch' \
                     AND home_member = ?2 AND home_pairing_id = ?3",
                    rusqlite::params![row.credential_id, home_member, pairing_id, row.refresh_adapter,
                        plan, row.identity.account_id, row.identity.email, row.identity.org_name,
                        row.state.as_str(), now, observed_at],
                )?;
                if categories_changed {
                    tx.execute(
                        "DELETE FROM remote_record_categories WHERE credential_id = ?1 AND EXISTS (\
                         SELECT 1 FROM remote_records WHERE credential_id = ?1 AND source = 'home_watch' \
                         AND home_member = ?2 AND home_pairing_id = ?3)",
                        rusqlite::params![row.credential_id, home_member, pairing_id],
                    )?;
                    let categories: BTreeSet<_> = row.categories.iter().collect();
                    for category in categories {
                        tx.execute("INSERT INTO remote_record_categories (credential_id, category) VALUES (?1, ?2)",
                            rusqlite::params![row.credential_id, category])?;
                    }
                    bump_grants_generation_tx(tx)?;
                }
                audit_remote_watch_tx(tx, &self.audit_key, home_member, &row.credential_id,
                    &current.incarnation, AuditOp::RemoteUpdate)?;
            }
            for record in diff.removals {
                remove_remote_watch_tx(tx, &self.audit_key, &record)?;
            }
            Ok(result)
        }).map_err(StoreOpError::from)
    }

    /// Remove a home's home-watch rows except those under `keep_pairing`, or all
    /// of them for `None`. Empty removals do not open a transaction or signal a write.
    pub fn remote_watch_remove_audited(
        &self,
        home_member: &str,
        keep_pairing: Option<&str>,
    ) -> Result<Vec<RemoteRecord>, StoreOpError> {
        check_member_id(home_member)?;
        if let Some(pairing) = keep_pairing {
            check_pairing_id(pairing)?;
        }
        let candidates = |conn: &rusqlite::Connection| -> rusqlite::Result<Vec<RemoteRecord>> {
            Ok(remote_watch_records_conn(conn, home_member)?
                .into_iter()
                .filter(|r| keep_pairing.is_none() || r.home_pairing_id.as_deref() != keep_pairing)
                .collect())
        };
        if self
            .store
            .with_conn(|conn| Ok(candidates(conn)?.is_empty()))?
        {
            return Ok(Vec::new());
        }
        self.fenced_write(|tx| {
            let records = candidates(tx)?;
            for record in &records {
                remove_remote_watch_tx(tx, &self.audit_key, record)?;
            }
            Ok(records)
        })
        .map_err(StoreOpError::from)
    }

    /// One remote record, or `None` when the id is not one (or the store predates
    /// federation).
    pub fn remote_record(&self, credential_id: &str) -> Result<Option<RemoteRecord>, StoreOpError> {
        self.store
            .with_conn(|conn| {
                if read_schema_version(conn)? < FEDERATION_SCHEMA_VERSION {
                    return Ok(None);
                }
                conn.query_row(
                    "SELECT * FROM remote_records WHERE credential_id = ?1",
                    [credential_id],
                    remote_record_from_row,
                )
                .optional()
            })
            .map_err(StoreOpError::from)
    }

    /// Every remote record, in id order.
    pub fn list_remote_records(&self) -> Result<Vec<RemoteRecord>, StoreOpError> {
        self.store
            .with_conn(|conn| {
                if read_schema_version(conn)? < FEDERATION_SCHEMA_VERSION {
                    return Ok(Vec::new());
                }
                let mut stmt =
                    conn.prepare("SELECT * FROM remote_records ORDER BY credential_id")?;
                let rows = stmt
                    .query_map([], remote_record_from_row)?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(rows)
            })
            .map_err(StoreOpError::from)
    }

    /// Every remote record with this vault's own categories, provider ids and operator
    /// plan tier for it, in id order, all read from one snapshot. This is what a scoped
    /// listing shows for remote ids: nothing in it came from a home call made now.
    pub fn remote_inventory(&self) -> Result<Vec<RemoteInventoryRow>, StoreOpError> {
        self.store
            .with_conn(|conn| {
                if read_schema_version(conn)? < REMOTE_METADATA_SCHEMA_VERSION {
                    return Ok(Vec::new());
                }
                let tx = conn.unchecked_transaction()?;
                let records = {
                    let mut stmt =
                        tx.prepare("SELECT * FROM remote_records ORDER BY credential_id")?;
                    let rows = stmt
                        .query_map([], remote_record_from_row)?
                        .collect::<rusqlite::Result<Vec<_>>>()?;
                    rows
                };
                let mut out = Vec::with_capacity(records.len());
                for record in records {
                    let id = record.credential_id.as_str();
                    let categories = {
                        let mut stmt = tx.prepare(
                            "SELECT category FROM remote_record_categories \
                             WHERE credential_id = ?1 ORDER BY category",
                        )?;
                        let rows = stmt
                            .query_map([id], |row| row.get::<_, String>(0))?
                            .collect::<rusqlite::Result<Vec<_>>>()?;
                        rows
                    };
                    let provider_ids = {
                        let mut stmt = tx.prepare(
                            "SELECT provider_id FROM remote_record_provider_ids \
                             WHERE credential_id = ?1 ORDER BY provider_id",
                        )?;
                        let rows = stmt
                            .query_map([id], |row| row.get::<_, String>(0))?
                            .collect::<rusqlite::Result<Vec<_>>>()?;
                        rows
                    };
                    let plan_tier = tx
                        .query_row(
                            "SELECT plan_tier FROM remote_record_plan_tiers WHERE credential_id = ?1",
                            [id],
                            |row| row.get::<_, String>(0),
                        )
                        .optional()?;
                    out.push(RemoteInventoryRow {
                        plan_tier_since_ms: if read_schema_version(&tx)? >= crate::store::PLAN_TIER_SINCE_SCHEMA_VERSION {
                            tx.query_row("SELECT since_ms FROM remote_record_plan_tiers WHERE credential_id = ?1", [id], |row| row.get(0)).optional()?.flatten()
                        } else { None },
                        plan_tier_observed_at_ms: if read_schema_version(&tx)? >= crate::store::PLAN_TIER_OBSERVED_SCHEMA_VERSION {
                            tx.query_row("SELECT observed_at_ms FROM remote_record_plan_tiers WHERE credential_id = ?1", [id], |row| row.get(0)).optional()?.flatten()
                        } else { None },
                        record,
                        categories,
                        provider_ids,
                        plan_tier,
                    });
                }
                tx.commit()?;
                Ok(out)
            })
            .map_err(StoreOpError::from)
    }

    /// Record the result of the latest fetch for a remote record: `outcome` is `ok` or
    /// the refusal code the fetch answered. Diagnostics only: this never touches
    /// `last_home_state` or `last_home_error`, so a transport failure cannot overwrite
    /// what the home last said authoritatively. Writes only when the outcome changes.
    pub fn remote_record_note_fetch_outcome(
        &self,
        credential_id: &str,
        incarnation: &str,
        outcome: &str,
    ) -> Result<RemoteRecordWrite, StoreOpError> {
        check_outcome_code(outcome)?;
        let now = now_ms();
        self.fenced_write(|tx| {
            let changed = tx.execute(
                "UPDATE remote_records \
                 SET last_fetch_outcome = ?3, last_fetch_at_ms = ?4, updated_at_ms = ?4 \
                 WHERE credential_id = ?1 AND incarnation = ?2 AND last_fetch_outcome IS NOT ?3",
                rusqlite::params![credential_id, incarnation, outcome, now],
            )?;
            if changed > 0 {
                return Ok(RemoteRecordWrite::Changed);
            }
            unchanged_or_stale(tx, credential_id, incarnation)
        })
        .map_err(StoreOpError::from)
    }

    /// Apply one validated home reply as authoritative: the home-owned fields and
    /// version from the reply, state `active`, no error.
    ///
    /// `reported_version` (a forwarded failure report not yet resolved) is kept only
    /// while the home is still holding that report back: the reply carries
    /// `recheck_in_ms`, is not a re-create (a version below the stored one means the
    /// home deleted and re-created the id), and its version is not above the reported
    /// one. Otherwise it is cleared. Writes only when a stored field changes.
    pub fn remote_record_apply_success(
        &self,
        credential_id: &str,
        incarnation: &str,
        success: &RemoteHomeSuccess,
    ) -> Result<RemoteRecordWrite, StoreOpError> {
        success.identity.validate().map_err(StoreOpError::Encode)?;
        if success
            .detected_plan
            .as_ref()
            .and_then(|plan| plan.tier.as_deref())
            .is_some_and(|tier| !crate::plan_tier::valid_plan_tier(tier))
        {
            return Err(StoreOpError::InvalidPlanTier);
        }
        let detected_plan = success
            .detected_plan
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|e| StoreOpError::Encode(e.to_string()))?;
        let home_version = i64::try_from(success.home_version)
            .map_err(|_| StoreOpError::Encode("home record_version out of range".into()))?;
        let now = now_ms();
        self.fenced_write(|tx| {
            let Some(current) = remote_record_at_incarnation(tx, credential_id, incarnation)?
            else {
                return Ok(RemoteRecordWrite::StaleIncarnation);
            };
            let recreated = success.home_version < current.last_home_version;
            let detected_observed_at_ms = success.detected_plan.as_ref().and_then(|plan| {
                let tier = plan.tier.as_ref()?;
                if !recreated
                    && current.identity.account_id == success.identity.account_id
                    && current.detected_plan.as_ref().and_then(|p| p.tier.as_ref()) == Some(tier)
                {
                    current.detected_plan_tier_observed_at_ms
                } else {
                    Some(plan.observed_at_ms)
                }
            });
            let reported_version = current.reported_version.filter(|reported| {
                success.recheck_pending && !recreated && success.home_version <= *reported
            });
            let unchanged = current.refresh_adapter == success.refresh_adapter
                && current.detected_plan == success.detected_plan
                && current.identity == success.identity
                && current.last_home_version == success.home_version
                && current.last_home_state == RemoteHomeState::Active
                && current.last_home_error.is_none()
                && current.reported_version == reported_version;
            if unchanged {
                return Ok(RemoteRecordWrite::Unchanged);
            }
            tx.execute(
                "UPDATE remote_records SET \
                     refresh_adapter = ?3, detected_plan = ?4, account_id = ?5, email = ?6, \
                     org_name = ?7, last_home_version = ?8, last_home_state = 'active', \
                     last_home_error = NULL, reported_version = ?9, updated_at_ms = ?10, \
                     detected_plan_tier_observed_at_ms = ?11 \
                 WHERE credential_id = ?1 AND incarnation = ?2",
                rusqlite::params![
                    credential_id,
                    incarnation,
                    success.refresh_adapter,
                    detected_plan,
                    success.identity.account_id,
                    success.identity.email,
                    success.identity.org_name,
                    home_version,
                    reported_version.map(|version| version as i64),
                    now,
                    detected_observed_at_ms,
                ],
            )?;
            Ok(RemoteRecordWrite::Changed)
        })
        .map_err(StoreOpError::from)
    }

    /// Apply an authoritative home answer that is not a success: the record's state
    /// becomes `state` (never `active`, which only a served token can establish) with
    /// `error` as the code behind it, and any unresolved forwarded report is cleared,
    /// because the home has now answered for the record as a whole. The home-owned
    /// description is kept. Writes only when a stored field changes.
    pub fn remote_record_apply_home_state(
        &self,
        credential_id: &str,
        incarnation: &str,
        state: RemoteHomeState,
        error: &str,
    ) -> Result<RemoteRecordWrite, StoreOpError> {
        if state == RemoteHomeState::Active {
            return Err(StoreOpError::Encode(
                "only a served token sets a remote record active".into(),
            ));
        }
        check_outcome_code(error)?;
        let now = now_ms();
        self.fenced_write(|tx| {
            let changed = tx.execute(
                "UPDATE remote_records \
                 SET last_home_state = ?3, last_home_error = ?4, reported_version = NULL, \
                     updated_at_ms = ?5 \
                 WHERE credential_id = ?1 AND incarnation = ?2 \
                   AND NOT (last_home_state = ?3 AND last_home_error IS ?4 \
                            AND reported_version IS NULL)",
                rusqlite::params![credential_id, incarnation, state.as_str(), error, now],
            )?;
            if changed > 0 {
                return Ok(RemoteRecordWrite::Changed);
            }
            unchanged_or_stale(tx, credential_id, incarnation)
        })
        .map_err(StoreOpError::from)
    }

    /// Raise the record's unresolved forwarded-report version to `version`. It never
    /// moves backwards: the `WHERE` guard leaves a stored version at or above `version`
    /// alone, so a report delayed in transit cannot lower it. Stored, so it survives a
    /// restart until a home answer resolves it.
    pub fn remote_record_raise_reported_version(
        &self,
        credential_id: &str,
        incarnation: &str,
        version: u64,
    ) -> Result<RemoteRecordWrite, StoreOpError> {
        let version = i64::try_from(version)
            .map_err(|_| StoreOpError::Encode("record_version out of range".into()))?;
        let now = now_ms();
        self.fenced_write(|tx| {
            let changed = tx.execute(
                "UPDATE remote_records SET reported_version = ?3, updated_at_ms = ?4 \
                 WHERE credential_id = ?1 AND incarnation = ?2 \
                   AND (reported_version IS NULL OR reported_version < ?3)",
                rusqlite::params![credential_id, incarnation, version, now],
            )?;
            if changed > 0 {
                return Ok(RemoteRecordWrite::Changed);
            }
            unchanged_or_stale(tx, credential_id, incarnation)
        })
        .map_err(StoreOpError::from)
    }

    /// Grant an operator-owned operation at the member's current pairing id.
    /// An explicit operator grant takes ownership of an existing switch grant.
    pub fn create_member_grant_audited(
        &self,
        member_id: &str,
        operation: MemberGrantOperation,
        selector: &MemberGrantSelector,
        pairing_id: &str,
    ) -> Result<bool, StoreOpError> {
        check_member_id(member_id)?;
        check_member_grant_shape(operation, selector)?;
        check_pairing_id(pairing_id)?;
        let grant = MemberGrant {
            member_id: member_id.to_string(),
            operation,
            selector: selector.clone(),
            pairing_id: pairing_id.to_string(),
            created_at_ms: now_ms(),
            source: MemberGrantSource::Operator,
        };
        self.fenced_write(|tx| create_member_grant_tx(tx, &self.audit_key, &grant))
            .map_err(StoreOpError::from)
    }

    /// Revoke an operator grant. Switch grants must be disabled in Callosum instead.
    pub fn revoke_member_grant_audited(
        &self,
        member_id: &str,
        operation: MemberGrantOperation,
        selector: &MemberGrantSelector,
    ) -> Result<(), StoreOpError> {
        check_member_id(member_id)?;
        check_member_grant_shape(operation, selector)?;
        self.fenced_write_or_refuse(|tx| {
            let Some(grant) = member_grants_conn(tx)?.into_iter().find(|grant| {
                grant.member_id == member_id
                    && grant.operation == operation
                    && &grant.selector == selector
            }) else {
                return Ok(Err(StoreOpError::NotFound));
            };
            if grant.source == MemberGrantSource::SharingSwitch {
                return Ok(Err(StoreOpError::MemberGrantSharingSwitch {
                    member_id: member_id.to_string(),
                }));
            }
            revoke_member_grant_tx(tx, &self.audit_key, &grant)?;
            Ok(Ok(()))
        })
    }

    /// Atomically make switch-owned grants match one fully decoded Callosum snapshot.
    /// Operator rows win even if their pairing is stale: only an operator may change them.
    pub fn reconcile_vault_sharing_audited(
        &self,
        members: &[VaultSharingMember],
    ) -> Result<(usize, usize), StoreOpError> {
        self.reconcile_vault_sharing_inner(members, || {})
    }

    pub(super) fn reconcile_vault_sharing_inner(
        &self,
        members: &[VaultSharingMember],
        after_write: impl FnMut(),
    ) -> Result<(usize, usize), StoreOpError> {
        self.reconcile_vault_sharing_before_write(members, after_write, || {})
    }

    pub(super) fn reconcile_vault_sharing_before_write(
        &self,
        members: &[VaultSharingMember],
        mut after_write: impl FnMut(),
        before_write: impl FnOnce(),
    ) -> Result<(usize, usize), StoreOpError> {
        let now = now_ms();
        let mut wanted = Vec::new();
        for member in members {
            check_member_id(&member.member_id)?;
            check_pairing_id(&member.pairing_id)?;
            for (operation, selector) in [
                (
                    MemberGrantOperation::RemoteRead,
                    MemberGrantSelector::Category("llm-provider".into()),
                ),
                (MemberGrantOperation::SecretUse, MemberGrantSelector::None),
            ] {
                wanted.push(MemberGrant {
                    member_id: member.member_id.clone(),
                    operation,
                    selector,
                    pairing_id: member.pairing_id.clone(),
                    created_at_ms: now,
                    source: MemberGrantSource::SharingSwitch,
                });
            }
        }
        // A no-op commit would wake inventory streams even though no grant changed.
        let unchanged = self.store.with_conn(|conn| {
            if !login_sharing_conn(conn)? {
                return Ok(true);
            }
            let existing = member_grants_conn(conn)?;
            let (created, revoked) = vault_sharing_diff(&existing, &wanted);
            Ok(created.is_empty() && revoked.is_empty())
        })?;
        if unchanged {
            return Ok((0, 0));
        }
        before_write();
        self.fenced_write(|tx| {
            // The Callosum snapshot may predate an opt-out committed after preflight.
            if !login_sharing_conn(tx)? {
                return Ok((0, 0));
            }
            let existing = member_grants_conn(tx)?;
            let (to_create, to_revoke) = vault_sharing_diff(&existing, &wanted);
            let mut revoked = 0;
            let mut created = 0;
            for grant in to_revoke {
                revoke_member_grant_tx(tx, &self.audit_key, grant)?;
                revoked += 1;
                after_write();
            }
            for grant in to_create {
                created += usize::from(create_member_grant_tx(tx, &self.audit_key, grant)?);
                after_write();
            }
            Ok((created, revoked))
        })
        .map_err(StoreOpError::from)
    }

    /// Record that this vault, as home, is about to release a token for `credential_id`
    /// to `member`, writing one `remote_issue` audit row per (member, credential, home
    /// `record_version`, material).
    ///
    /// `material_digest` is the SHA-256 of the stored encrypted bytes the serving read
    /// decrypted (`GetWithRefreshStatus::stored_digest_hex`). The transaction re-reads
    /// the row and requires both the version and the digest of its encrypted bytes to
    /// still match. If the record was deleted, re-created, rewritten or refreshed after
    /// the serving read, nothing is written and [`StoreOpError::CasMismatch`] is
    /// returned: the caller must not release the token it read, because the audit row
    /// would name material that is no longer the stored one.
    ///
    /// The seen row and the audit row commit together, so the audit row is written once
    /// per material, across restarts and retried fetches: returns `true` when this call
    /// wrote them, `false` when the tuple was already recorded. The digest is part of
    /// the key because a delete and re-create restarts `record_version` at 1, and the
    /// new material must be audited although its version number repeats.
    pub fn record_remote_issue_audited(
        &self,
        member_id: &str,
        credential_id: &str,
        record_version: u64,
        material_digest: &str,
    ) -> Result<bool, StoreOpError> {
        check_member_id(member_id)?;
        let version = i64::try_from(record_version)
            .map_err(|_| StoreOpError::Encode("record_version out of range".into()))?;
        let payload_hash =
            crate::federation::remote_issue_payload_hash(credential_id, record_version);
        let audit_key = self.audit_key.clone();
        let now = now_ms();
        let recorded = self.fenced_write(|tx| {
            let current = tx
                .query_row(
                    "SELECT record_version, envelope FROM credentials WHERE credential_id = ?1",
                    [credential_id],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
                )
                .optional()?;
            let unchanged = current.is_some_and(|(stored_version, envelope)| {
                stored_version == version && sha256_hex_of_bytes(&envelope) == material_digest
            });
            if !unchanged {
                return Ok(None);
            }
            let inserted = tx.execute(
                "INSERT INTO remote_issue_seen \
                 (member_id, credential_id, record_version, material_digest, seen_at_ms) \
                 VALUES (?1, ?2, ?3, ?4, ?5) \
                 ON CONFLICT(member_id, credential_id, record_version, material_digest) DO NOTHING",
                rusqlite::params![member_id, credential_id, version, material_digest, now],
            )?;
            if inserted == 0 {
                return Ok(Some(false));
            }
            append_audit_tx(
                tx,
                &audit_key,
                &AuditRecord {
                    op: AuditOp::RemoteIssue,
                    credential_id: Some(credential_id.to_string()),
                    payload_hash: Some(payload_hash.clone()),
                    actor: member_id.to_string(),
                    alarm: None,
                },
            )?;
            Ok(Some(true))
        })?;
        recorded.ok_or(StoreOpError::CasMismatch)
    }

    /// Every member grant, ordered by member, operation, selector kind and selector.
    pub fn list_member_grants(&self) -> Result<Vec<MemberGrant>, StoreOpError> {
        self.store
            .with_conn(member_grants_conn)
            .map_err(StoreOpError::from)
    }
}

// ---------------------------------------------------------------------------------
// Sealed static-key transfers
// ---------------------------------------------------------------------------------

/// The migration that creates `pending_transfers`.
const INCOMING_TRANSFERS_SCHEMA_VERSION: u32 = 24;

/// The migration that creates `outgoing_transfers`.
const OUTGOING_TRANSFERS_SCHEMA_VERSION: u32 = 25;

/// The longest reply code stored on an outgoing transfer. Codes come from the
/// receiver, so the column takes only the same safe shape as a fetch outcome.
const MAX_REPLY_CODE_LEN: usize = 64;

/// A typed refusal decided inside a transaction, carried out of it while the
/// transaction rolls back.
type InTx<T> = rusqlite::Result<Result<T, StoreOpError>>;

fn bad_column(what: String) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, what.into())
}

fn split_categories(stored: &str) -> Vec<String> {
    stored
        .split(',')
        .filter(|category| !category.is_empty())
        .map(str::to_string)
        .collect()
}

fn incoming_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<IncomingTransfer> {
    let state: String = row.get("state")?;
    let state = IncomingTransferState::from_stored(&state)
        .ok_or_else(|| bad_column(format!("unknown incoming transfer state {state:?}")))?;
    let enc: Option<Vec<u8>> = row.get("enc")?;
    let ciphertext: Option<Vec<u8>> = row.get("ciphertext")?;
    let aad: Option<Vec<u8>> = row.get("aad")?;
    let sealed = match (enc, ciphertext, aad) {
        (Some(enc), Some(ciphertext), Some(aad)) => Some(SealedTransfer {
            enc,
            ciphertext,
            aad,
        }),
        _ => None,
    };
    Ok(IncomingTransfer {
        sender_member: row.get("sender_member")?,
        transfer_id: row.get("transfer_id")?,
        body_hash: row.get("body_hash")?,
        state,
        credential_id: row.get("credential_id")?,
        kind: row.get("kind")?,
        categories: split_categories(&row.get::<_, String>("categories")?),
        size_bytes: row.get::<_, i64>("size_bytes")?.max(0) as u64,
        sealed,
        reject_reason: row.get("reject_reason")?,
        received_at_ms: row.get("received_at_ms")?,
        expires_at_ms: row.get("expires_at_ms")?,
        decided_at_ms: row.get("decided_at_ms")?,
    })
}

fn outgoing_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<OutgoingTransfer> {
    let state: String = row.get("state")?;
    let state = OutgoingTransferState::from_stored(&state)
        .ok_or_else(|| bad_column(format!("unknown outgoing transfer state {state:?}")))?;
    Ok(OutgoingTransfer {
        transfer_id: row.get("transfer_id")?,
        receiver_member: row.get("receiver_member")?,
        credential_id: row.get("credential_id")?,
        body_hash: row.get("body_hash")?,
        sealed: SealedTransfer {
            enc: row.get("enc")?,
            ciphertext: row.get("ciphertext")?,
            aad: row.get("aad")?,
        },
        state,
        last_reply_code: row.get("last_reply_code")?,
        created_at_ms: row.get("created_at_ms")?,
        expires_at_ms: row.get("expires_at_ms")?,
        last_attempt_at_ms: row.get("last_attempt_at_ms")?,
    })
}

fn pending_counts_tx(
    conn: &rusqlite::Connection,
    sender: &str,
) -> rusqlite::Result<PendingTransferCounts> {
    let (from_sender, total): (i64, i64) = conn.query_row(
        "SELECT COALESCE(SUM(sender_member = ?1), 0), COUNT(*) \
         FROM pending_transfers WHERE state = 'pending'",
        [sender],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    Ok(PendingTransferCounts {
        from_sender: u32::try_from(from_sender).unwrap_or(u32::MAX),
        total: u32::try_from(total).unwrap_or(u32::MAX),
    })
}

/// Append one `transfer_reject` row.
fn append_transfer_reject_tx(
    tx: &rusqlite::Transaction,
    audit_key: &[u8; 32],
    credential_id: &str,
    transfer_id: &str,
    reason: &str,
    actor: &str,
) -> rusqlite::Result<()> {
    let payload_hash = crate::federation::transfer_reject_payload_hash(transfer_id, reason)
        .map_err(|error| bad_column(error.to_string()))?;
    append_audit_tx(
        tx,
        audit_key,
        &AuditRecord {
            op: AuditOp::TransferReject,
            credential_id: Some(credential_id.to_string()),
            payload_hash: Some(payload_hash),
            actor: actor.to_string(),
            alarm: Some(AlarmReason::AdminWrite),
        },
    )?;
    Ok(())
}

/// Mark one pending transfer rejected: its sealed bytes are dropped, its id and hash
/// are kept, and one `transfer_reject` row names the sender. Returns false when the
/// row was not pending.
fn reject_incoming_tx(
    tx: &rusqlite::Transaction,
    audit_key: &[u8; 32],
    row: &IncomingTransfer,
    reason: &str,
    now: i64,
) -> rusqlite::Result<bool> {
    let changed = tx.execute(
        "UPDATE pending_transfers \
            SET state = 'rejected', enc = NULL, ciphertext = NULL, aad = NULL, \
                reject_reason = ?3, decided_at_ms = ?4 \
          WHERE sender_member = ?1 AND transfer_id = ?2 AND state = 'pending'",
        rusqlite::params![row.sender_member, row.transfer_id, reason, now],
    )?;
    if changed == 0 {
        return Ok(false);
    }
    append_transfer_reject_tx(
        tx,
        audit_key,
        &row.credential_id,
        &row.transfer_id,
        reason,
        &row.sender_member,
    )?;
    Ok(true)
}

fn check_transfer_kind(kind: &str) -> Result<(), StoreOpError> {
    // The receive side admits exactly the static kinds a transfer may carry; the column
    // records which one, so nothing else can be written there.
    match kind {
        "api_key" | "dsn" | "cookie" | "opaque" => Ok(()),
        _ => Err(StoreOpError::Encode(format!(
            "transfer kind {kind:?} is not a transferable kind"
        ))),
    }
}

/// The kinds a transfer may create or replace: the static kinds with no OAuth
/// material. Kept in step with the module's eligibility predicate, which is the one
/// that refuses a body; this is the store's own last line.
fn transferable_record(record: &VaultRecord) -> bool {
    matches!(
        record.kind,
        CredentialKind::ApiKey
            | CredentialKind::Dsn
            | CredentialKind::Cookie
            | CredentialKind::Opaque
    ) && record.oauth.is_none()
        && record.refresh_adapter.is_none()
}

impl EncryptedStore {
    /// [`Self::fenced_write`] where the work may refuse with a typed error. A refusal
    /// rolls the whole transaction back and is returned as itself.
    pub(super) fn fenced_write_or_refuse<T>(
        &self,
        work: impl FnOnce(&rusqlite::Transaction) -> InTx<T>,
    ) -> Result<T, StoreOpError> {
        let refused = std::cell::RefCell::new(None);
        let outcome = self.fenced_write(|tx| match work(tx)? {
            Ok(value) => Ok(value),
            Err(error) => {
                *refused.borrow_mut() = Some(error);
                Err(rusqlite::Error::InvalidQuery)
            }
        });
        match outcome {
            Ok(value) => Ok(value),
            Err(error) => match refused.into_inner() {
                Some(refusal) => Err(refusal),
                None => Err(StoreOpError::from(error)),
            },
        }
    }

    /// Commit an outgoing transfer: the row with its sealed envelope and the
    /// `transfer_out` audit row (actor: the receiver, `payload_hash` over
    /// `{transfer_id, body_hash}`), in ONE fenced transaction. The caller commits this
    /// before any delivery attempt, so a crash after it leaves a row `send --resume`
    /// redelivers byte for byte, and a failure here leaves neither row and sends
    /// nothing.
    pub fn commit_outgoing_transfer_audited(
        &self,
        new: &NewOutgoingTransfer,
    ) -> Result<OutgoingTransfer, StoreOpError> {
        self.commit_outgoing_transfer_inner(
            new,
            #[cfg(any(test, feature = "test-support"))]
            None,
        )
    }

    /// Fail between the row insert and audit write to check transaction rollback.
    #[cfg(any(test, feature = "test-support"))]
    pub fn commit_outgoing_transfer_with_fault(
        &self,
        new: &NewOutgoingTransfer,
        fault_after_insert: Option<&dyn Fn() -> bool>,
    ) -> Result<OutgoingTransfer, StoreOpError> {
        self.commit_outgoing_transfer_inner(new, fault_after_insert)
    }

    fn commit_outgoing_transfer_inner(
        &self,
        new: &NewOutgoingTransfer,
        #[cfg(any(test, feature = "test-support"))] fault_after_insert: Option<&dyn Fn() -> bool>,
    ) -> Result<OutgoingTransfer, StoreOpError> {
        check_member_id(&new.receiver_member)?;
        if new.credential_id.is_empty() {
            return Err(StoreOpError::InvalidCredentialId);
        }
        validate_deposit_credential_id(&new.credential_id)?;
        let body_hash = new.sealed.body_hash();
        let payload_hash = transfer_payload_hash(&new.transfer_id, &body_hash)?;
        let expires_at_ms = new.created_at_ms.saturating_add(TRANSFER_RETENTION_MS);
        let audit_key = self.audit_key.clone();
        self.fenced_write_or_refuse(|tx| {
            let inserted = tx.execute(
                "INSERT INTO outgoing_transfers \
                 (transfer_id, receiver_member, credential_id, body_hash, enc, ciphertext, aad, \
                  state, created_at_ms, expires_at_ms) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'pending', ?8, ?9) \
                 ON CONFLICT(transfer_id) DO NOTHING",
                rusqlite::params![
                    new.transfer_id,
                    new.receiver_member,
                    new.credential_id,
                    body_hash,
                    new.sealed.enc,
                    new.sealed.ciphertext,
                    new.sealed.aad,
                    new.created_at_ms,
                    expires_at_ms,
                ],
            )?;
            if inserted == 0 {
                return Ok(Err(StoreOpError::AlreadyExists));
            }
            #[cfg(any(test, feature = "test-support"))]
            if fault_after_insert.is_some_and(|fault| fault()) {
                return Ok(Err(StoreOpError::Encode(
                    "injected fault between the outgoing row and its audit row".into(),
                )));
            }
            append_audit_tx(
                tx,
                &audit_key,
                &AuditRecord {
                    op: AuditOp::TransferOut,
                    credential_id: Some(new.credential_id.clone()),
                    payload_hash: Some(payload_hash.clone()),
                    actor: new.receiver_member.clone(),
                    alarm: Some(AlarmReason::AdminWrite),
                },
            )?;
            Ok(Ok(OutgoingTransfer {
                transfer_id: new.transfer_id.clone(),
                receiver_member: new.receiver_member.clone(),
                credential_id: new.credential_id.clone(),
                body_hash: body_hash.clone(),
                sealed: new.sealed.clone(),
                state: OutgoingTransferState::Pending,
                last_reply_code: None,
                created_at_ms: new.created_at_ms,
                expires_at_ms,
                last_attempt_at_ms: None,
            }))
        })
    }

    /// One outgoing transfer, or `None` when it was never committed or was deleted.
    pub fn outgoing_transfer(
        &self,
        transfer_id: &str,
    ) -> Result<Option<OutgoingTransfer>, StoreOpError> {
        self.store
            .with_conn(|conn| {
                if read_schema_version(conn)? < OUTGOING_TRANSFERS_SCHEMA_VERSION {
                    return Ok(None);
                }
                conn.query_row(
                    "SELECT * FROM outgoing_transfers WHERE transfer_id = ?1",
                    [transfer_id],
                    outgoing_from_row,
                )
                .optional()
            })
            .map_err(StoreOpError::from)
    }

    /// Every outgoing transfer, oldest first.
    pub fn list_outgoing_transfers(&self) -> Result<Vec<OutgoingTransfer>, StoreOpError> {
        self.store
            .with_conn(|conn| {
                if read_schema_version(conn)? < OUTGOING_TRANSFERS_SCHEMA_VERSION {
                    return Ok(Vec::new());
                }
                let mut stmt = conn.prepare(
                    "SELECT * FROM outgoing_transfers ORDER BY created_at_ms, transfer_id",
                )?;
                let rows = stmt
                    .query_map([], outgoing_from_row)?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(rows)
            })
            .map_err(StoreOpError::from)
    }

    /// Record the receiver's reply to a delivery attempt that keeps the row. The code
    /// is a refusal code this vault chose, never peer text. Returns false when the row
    /// is gone.
    pub fn note_outgoing_transfer_attempt(
        &self,
        transfer_id: &str,
        reply_code: &str,
        now_ms: i64,
    ) -> Result<bool, StoreOpError> {
        if reply_code.is_empty()
            || reply_code.len() > MAX_REPLY_CODE_LEN
            || !reply_code
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(StoreOpError::Encode(
                "a transfer reply code must be a-z, 0-9 and _ only".into(),
            ));
        }
        let changed = self.fenced_write(|tx| {
            tx.execute(
                "UPDATE outgoing_transfers SET last_reply_code = ?2, last_attempt_at_ms = ?3 \
                 WHERE transfer_id = ?1",
                rusqlite::params![transfer_id, reply_code, now_ms],
            )
        })?;
        Ok(changed > 0)
    }

    /// Delete an outgoing transfer after a terminal reply. Returns false when it was
    /// already gone. The `transfer_out` row stays: it records that the send happened.
    pub fn delete_outgoing_transfer(&self, transfer_id: &str) -> Result<bool, StoreOpError> {
        let changed = self.fenced_write(|tx| {
            tx.execute(
                "DELETE FROM outgoing_transfers WHERE transfer_id = ?1",
                [transfer_id],
            )
        })?;
        Ok(changed > 0)
    }

    /// Delete every outgoing transfer older than its seven-day retention at `now_ms`.
    pub fn expire_outgoing_transfers(&self, now_ms: i64) -> Result<usize, StoreOpError> {
        self.fenced_write(|tx| {
            if read_schema_version(tx)? < OUTGOING_TRANSFERS_SCHEMA_VERSION {
                return Ok(0);
            }
            tx.execute(
                "DELETE FROM outgoing_transfers WHERE expires_at_ms <= ?1",
                [now_ms],
            )
        })
        .map_err(StoreOpError::from)
    }

    /// The transfer recorded for (`sender`, `body_hash`), whatever its state: the
    /// dedup lookup a delivery runs before it opens anything.
    pub fn incoming_transfer_by_hash(
        &self,
        sender: &str,
        body_hash: &str,
    ) -> Result<Option<IncomingTransfer>, StoreOpError> {
        self.store
            .with_conn(|conn| {
                if read_schema_version(conn)? < INCOMING_TRANSFERS_SCHEMA_VERSION {
                    return Ok(None);
                }
                conn.query_row(
                    "SELECT * FROM pending_transfers WHERE sender_member = ?1 AND body_hash = ?2",
                    [sender, body_hash],
                    incoming_from_row,
                )
                .optional()
            })
            .map_err(StoreOpError::from)
    }

    /// The transfer recorded for (`sender`, `transfer_id`), whatever its state.
    pub fn incoming_transfer(
        &self,
        sender: &str,
        transfer_id: &str,
    ) -> Result<Option<IncomingTransfer>, StoreOpError> {
        self.store
            .with_conn(|conn| {
                if read_schema_version(conn)? < INCOMING_TRANSFERS_SCHEMA_VERSION {
                    return Ok(None);
                }
                conn.query_row(
                    "SELECT * FROM pending_transfers WHERE sender_member = ?1 AND transfer_id = ?2",
                    [sender, transfer_id],
                    incoming_from_row,
                )
                .optional()
            })
            .map_err(StoreOpError::from)
    }

    /// Every received transfer, pending or decided, oldest first.
    pub fn list_incoming_transfers(&self) -> Result<Vec<IncomingTransfer>, StoreOpError> {
        self.store
            .with_conn(|conn| {
                if read_schema_version(conn)? < INCOMING_TRANSFERS_SCHEMA_VERSION {
                    return Ok(Vec::new());
                }
                let mut stmt = conn.prepare(
                    "SELECT * FROM pending_transfers \
                     ORDER BY received_at_ms, sender_member, transfer_id",
                )?;
                let rows = stmt
                    .query_map([], incoming_from_row)?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(rows)
            })
            .map_err(StoreOpError::from)
    }

    /// How many transfers are pending from `sender` and in total.
    pub fn pending_transfer_counts(
        &self,
        sender: &str,
    ) -> Result<PendingTransferCounts, StoreOpError> {
        self.store
            .with_conn(|conn| {
                if read_schema_version(conn)? < INCOMING_TRANSFERS_SCHEMA_VERSION {
                    return Ok(PendingTransferCounts {
                        from_sender: 0,
                        total: 0,
                    });
                }
                pending_counts_tx(conn, sender)
            })
            .map_err(StoreOpError::from)
    }

    /// Record a delivered transfer as pending, in ONE write transaction that first
    /// rechecks, in the delivery order: the dedup on (sender, body hash), whose stored
    /// state wins over every bound; then the queue bounds; then an existing entry under
    /// (sender, transfer id). So two concurrent identical deliveries record one row, and
    /// two concurrent distinct ones from a sender one short of its cap record one.
    ///
    /// Only sealed bytes and non-secret metadata are stored. No audit row is written:
    /// nothing has happened to any credential yet.
    pub fn insert_incoming_transfer(
        &self,
        new: &NewIncomingTransfer,
    ) -> Result<IncomingInsert, StoreOpError> {
        check_member_id(&new.sender_member)?;
        if !is_lower_hex_16_bytes(&new.transfer_id) {
            return Err(StoreOpError::Encode(
                "transfer_id must be 32 lowercase hex characters".into(),
            ));
        }
        if new.credential_id.is_empty() {
            return Err(StoreOpError::InvalidCredentialId);
        }
        validate_deposit_credential_id(&new.credential_id)?;
        check_transfer_kind(&new.kind)?;
        if new
            .categories
            .iter()
            .any(|category| !crate::catalog::valid_category_name(category))
        {
            return Err(StoreOpError::InvalidCategoryName);
        }
        let body_hash = new.sealed.body_hash();
        let categories = new.categories.join(",");
        let size = i64::try_from(new.size_bytes)
            .map_err(|_| StoreOpError::Encode("size out of range".into()))?;
        let expires_at_ms = new.received_at_ms.saturating_add(TRANSFER_RETENTION_MS);
        self.fenced_write(|tx| {
            let known: Option<String> = tx
                .query_row(
                    "SELECT state FROM pending_transfers WHERE sender_member = ?1 AND body_hash = ?2",
                    [&new.sender_member, &body_hash],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(state) = known {
                let state = IncomingTransferState::from_stored(&state)
                    .ok_or_else(|| bad_column(format!("unknown incoming transfer state {state:?}")))?;
                return Ok(IncomingInsert::Known(state));
            }
            if pending_counts_tx(tx, &new.sender_member)?.full() {
                return Ok(IncomingInsert::QueueFull);
            }
            let taken: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM pending_transfers \
                 WHERE sender_member = ?1 AND transfer_id = ?2)",
                [&new.sender_member, &new.transfer_id],
                |row| row.get(0),
            )?;
            if taken {
                return Ok(IncomingInsert::Conflict);
            }
            tx.execute(
                "INSERT INTO pending_transfers \
                 (sender_member, transfer_id, body_hash, state, credential_id, kind, categories, \
                  size_bytes, enc, ciphertext, aad, received_at_ms, expires_at_ms) \
                 VALUES (?1, ?2, ?3, 'pending', ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                rusqlite::params![
                    new.sender_member,
                    new.transfer_id,
                    body_hash,
                    new.credential_id,
                    new.kind,
                    categories,
                    size,
                    new.sealed.enc,
                    new.sealed.ciphertext,
                    new.sealed.aad,
                    new.received_at_ms,
                    expires_at_ms,
                ],
            )?;
            Ok(IncomingInsert::Inserted)
        })
        .map_err(StoreOpError::from)
    }

    /// Expire every pending transfer past its seven-day retention at `now_ms`: the
    /// sealed bytes are dropped and the id and hash are kept as `expired`, so a resend
    /// of the same bytes answers `transfer_expired` and never queues again.
    pub fn expire_incoming_transfers(&self, now_ms: i64) -> Result<usize, StoreOpError> {
        self.fenced_write(|tx| {
            if read_schema_version(tx)? < INCOMING_TRANSFERS_SCHEMA_VERSION {
                return Ok(0);
            }
            tx.execute(
                "UPDATE pending_transfers \
                    SET state = 'expired', enc = NULL, ciphertext = NULL, aad = NULL, \
                        decided_at_ms = ?1 \
                  WHERE state = 'pending' AND expires_at_ms <= ?1",
                [now_ms],
            )
        })
        .map_err(StoreOpError::from)
    }

    /// Reject one pending transfer: drop its sealed bytes, keep its id and hash as
    /// `rejected` with `reason`, and write one `transfer_reject` row naming the sender,
    /// in one transaction. Returns the state the transfer is in afterwards: `Rejected`
    /// when this call rejected it, or the terminal state it already had (nothing is
    /// written then). [`StoreOpError::NotFound`] when there is no such transfer.
    pub fn reject_incoming_transfer_audited(
        &self,
        sender: &str,
        transfer_id: &str,
        reason: &str,
    ) -> Result<IncomingTransferState, StoreOpError> {
        let audit_key = self.audit_key.clone();
        let now = now_ms();
        self.fenced_write_or_refuse(|tx| {
            let Some(row) = tx
                .query_row(
                    "SELECT * FROM pending_transfers WHERE sender_member = ?1 AND transfer_id = ?2",
                    [sender, transfer_id],
                    incoming_from_row,
                )
                .optional()?
            else {
                return Ok(Err(StoreOpError::NotFound));
            };
            if row.state != IncomingTransferState::Pending {
                return Ok(Ok(row.state));
            }
            reject_incoming_tx(tx, &audit_key, &row, reason, now)?;
            Ok(Ok(IncomingTransferState::Rejected))
        })
    }

    /// Accept one pending transfer. In ONE fenced transaction: the record (created, or
    /// with `replace` replacing an existing record of the same transferable kind), the
    /// body's categories in place of the catalog defaults, the body's provider ids
    /// through the provider-id rules, the pending row marked accepted with its sealed
    /// bytes dropped, and the `transfer_in` row (actor: the sender, `payload_hash` over
    /// `{transfer_id, body_hash}`). Any refusal part-way rolls all of it back.
    ///
    /// The record is stamped `created_by = 'operator'`, so no module's
    /// `deposit_cookie` can replace a transferred cookie. An id held by a remote record
    /// is refused by the id-uniqueness trigger.
    pub fn accept_incoming_transfer_audited(
        &self,
        acceptance: &TransferAcceptance,
    ) -> Result<TransferAcceptOutcome, StoreOpError> {
        let id = acceptance.credential_id.as_str();
        if id.is_empty() {
            return Err(StoreOpError::InvalidCredentialId);
        }
        validate_deposit_credential_id(id)?;
        if crate::agent_secret::is_deposit_key(id) {
            return Err(StoreOpError::NotFound);
        }
        if crate::federation::is_vault_transfer_id(id) {
            return Err(StoreOpError::TransferKeyReserved);
        }
        if !transferable_record(&acceptance.record) {
            return Err(StoreOpError::Encode(
                "a transfer creates only an api_key, dsn, cookie or opaque record".into(),
            ));
        }
        refuse_short_term_bedrock_key(&acceptance.record)?;
        let mut record = normalize_record_identity(acceptance.record.clone());
        validate_record_identity(&record)?;
        let mut categories = BTreeSet::new();
        for category in &acceptance.categories {
            if !crate::catalog::valid_category_name(category) {
                return Err(StoreOpError::InvalidCategoryName);
            }
            categories.insert(category.clone());
        }
        let payload_hash = transfer_payload_hash(&acceptance.transfer_id, &acceptance.body_hash)?;
        let key_id_hex = self.key_id.to_hex();
        let audit_key = self.audit_key.clone();
        let now = now_ms();
        self.fenced_write_or_refuse(|tx| {
            let Some(row) = tx
                .query_row(
                    "SELECT * FROM pending_transfers WHERE sender_member = ?1 AND transfer_id = ?2",
                    [&acceptance.sender_member, &acceptance.transfer_id],
                    incoming_from_row,
                )
                .optional()?
            else {
                return Ok(Err(StoreOpError::NotFound));
            };
            if row.state != IncomingTransferState::Pending {
                return Ok(Ok(TransferAcceptOutcome::AlreadyDecided(row.state)));
            }
            if row.body_hash != acceptance.body_hash || row.credential_id != id {
                return Ok(Err(StoreOpError::CasMismatch));
            }

            // 1. The record.
            let existing: Option<(i64, Vec<u8>)> = tx
                .query_row(
                    "SELECT record_version, envelope FROM credentials WHERE credential_id = ?1",
                    [id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let version = match existing {
                None => 1u64,
                Some(_) if !acceptance.replace => return Ok(Err(StoreOpError::AlreadyExists)),
                Some((current_version, envelope_bytes)) => {
                    // Only an eligible record of the same kind may be replaced, so a
                    // transfer can never turn a login or a vault-held key into a static
                    // key. An envelope that does not open cannot show its kind.
                    let current = envelope::open(
                        &self.key,
                        &envelope_bytes,
                        &RecordBinding {
                            credential_id: id,
                            record_version: current_version as u64,
                        },
                    )
                    .ok()
                    .and_then(|plaintext| VaultRecord::decode(&plaintext).ok());
                    match current {
                        Some(current)
                            if transferable_record(&current)
                                && current.kind == record.kind => {}
                        _ => {
                            return Ok(Err(StoreOpError::Encode(
                                "transfer_replace_refused: --replace only replaces an \
                                 eligible record of the same kind"
                                    .into(),
                            )))
                        }
                    }
                    (current_version as u64).saturating_add(1)
                }
            };
            record.record_version = version;
            let blob = match self.seal_record(id, &record) {
                Ok(blob) => blob,
                Err(error) => return Ok(Err(error)),
            };
            if version == 1 {
                tx.execute(
                    "INSERT INTO credentials \
                     (credential_id, record_version, key_id, state, envelope, updated_at_ms, \
                      created_at_ms, created_by) \
                     VALUES (?1, 1, ?2, 'active', ?3, ?4, ?4, 'operator')",
                    rusqlite::params![id, key_id_hex, blob, now],
                )?;
            } else {
                tx.execute(
                    "UPDATE credentials \
                        SET record_version = ?2, key_id = ?3, state = 'active', stale_pending = 0, \
                            envelope = ?4, updated_at_ms = ?5, created_by = 'operator' \
                      WHERE credential_id = ?1 AND record_version = ?6",
                    rusqlite::params![id, version as i64, key_id_hex, blob, now, version as i64 - 1],
                )?;
            }
            clear_intent_tx(tx, id)?;

            // 2. The body's categories, replacing the catalog defaults.
            tx.execute(
                "DELETE FROM credential_categories WHERE credential_id = ?1",
                [id],
            )?;
            for category in &categories {
                tx.execute(
                    "INSERT INTO credential_categories (credential_id, category) VALUES (?1, ?2)",
                    rusqlite::params![id, category],
                )?;
            }
            bump_grants_generation_tx(tx)?;

            // 3. The provider ids, under the same rules as `set-providers`. Checked
            // here, after the record is written, so a refusal is a refusal of the whole
            // accept and nothing above survives it.
            if let Err(error) = crate::provider_ids::check_provider_ids(&acceptance.provider_ids) {
                return Ok(Err(error));
            }
            let provider_ids: BTreeSet<&String> = acceptance.provider_ids.iter().collect();
            if provider_ids.len() != acceptance.provider_ids.len() {
                return Ok(Err(StoreOpError::InvalidProviderId {
                    rule: crate::provider_ids::ProviderIdRule::Duplicate,
                    value: String::new(),
                }));
            }
            if provider_ids.len() > crate::provider_ids::MAX_PROVIDER_IDS_PER_CREDENTIAL {
                return Ok(Err(StoreOpError::InvalidProviderId {
                    rule: crate::provider_ids::ProviderIdRule::Count,
                    value: String::new(),
                }));
            }
            tx.execute(
                "DELETE FROM credential_provider_ids WHERE credential_id = ?1",
                [id],
            )?;
            for provider_id in &provider_ids {
                tx.execute(
                    "INSERT INTO credential_provider_ids (credential_id, provider_id) VALUES (?1, ?2)",
                    rusqlite::params![id, provider_id],
                )?;
            }

            // 4. The accepted marker, and 5. the audit row.
            tx.execute(
                "UPDATE pending_transfers \
                    SET state = 'accepted', enc = NULL, ciphertext = NULL, aad = NULL, \
                        decided_at_ms = ?3 \
                  WHERE sender_member = ?1 AND transfer_id = ?2 AND state = 'pending'",
                rusqlite::params![acceptance.sender_member, acceptance.transfer_id, now],
            )?;
            append_audit_tx(
                tx,
                &audit_key,
                &AuditRecord {
                    op: AuditOp::TransferIn,
                    credential_id: Some(id.to_string()),
                    payload_hash: Some(payload_hash.clone()),
                    actor: acceptance.sender_member.clone(),
                    alarm: Some(AlarmReason::AdminWrite),
                },
            )?;
            Ok(Ok(TransferAcceptOutcome::Accepted {
                record_version: version,
            }))
        })
    }

    /// Transfer-key recovery (`ck auth transfer init --replace`): replace the vault
    /// transfer key, admitted ONLY while it is found off `Active`, and in the same
    /// transaction settle every transfer sealed under the old key:
    ///
    /// - every pending incoming transfer is marked rejected (`remote_seal_invalid`, one
    ///   `transfer_reject` row each naming its sender): its envelope was sealed to the
    ///   old key and can no longer open here;
    /// - every pending outgoing transfer is marked abandoned (`sender_key_replaced`, one
    ///   `transfer_reject` row each naming its receiver): it was Auth-sealed with the
    ///   old sender key and can only fail at the receiver.
    ///
    /// The key replace is audited under `ctx`. An `Active` key is refused with
    /// [`StoreOpError::TransferKeyProtected`]; a vault with no transfer key with
    /// [`StoreOpError::NotFound`] (`transfer init` creates one).
    pub fn recover_vault_transfer_key_audited(
        &self,
        new_key: &VaultRecord,
        ctx: AuditCtx<'_>,
    ) -> Result<TransferKeyRecovery, StoreOpError> {
        let id = crate::federation::VAULT_TRANSFER_ID;
        if new_key.kind != CredentialKind::KemKey || new_key.oauth.is_some() {
            return Err(StoreOpError::Encode(
                "the vault transfer key must be a KEM key".into(),
            ));
        }
        let key_id_hex = self.key_id.to_hex();
        let audit_key = self.audit_key.clone();
        let new_payload_hash = hex32(&audit::payload_fingerprint(
            &audit_key,
            new_key.payload.expose(),
        ));
        let now = now_ms();
        self.fenced_write_or_refuse(|tx| {
            let Some((current_version, state)) = tx
                .query_row(
                    "SELECT record_version, state FROM credentials WHERE credential_id = ?1",
                    [id],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
                )
                .optional()?
            else {
                return Ok(Err(StoreOpError::NotFound));
            };
            if state == RecordState::Active.as_str() {
                return Ok(Err(StoreOpError::TransferKeyProtected));
            }
            let version = (current_version as u64).saturating_add(1);
            let mut sealed = new_key.clone();
            sealed.record_version = version;
            let blob = match self.seal_record(id, &sealed) {
                Ok(blob) => blob,
                Err(error) => return Ok(Err(error)),
            };
            tx.execute(
                "UPDATE credentials \
                    SET record_version = ?2, key_id = ?3, state = 'active', stale_pending = 0, \
                        envelope = ?4, updated_at_ms = ?5 \
                  WHERE credential_id = ?1 AND record_version = ?6",
                rusqlite::params![id, version as i64, key_id_hex, blob, now, current_version],
            )?;
            clear_intent_tx(tx, id)?;
            append_audit_tx(
                tx,
                &audit_key,
                &AuditRecord {
                    op: ctx.op,
                    credential_id: Some(id.to_string()),
                    payload_hash: Some(new_payload_hash.clone()),
                    actor: ctx.actor.to_string(),
                    alarm: ctx.alarm,
                },
            )?;

            let mut recovery = TransferKeyRecovery::default();
            if read_schema_version(tx)? >= OUTGOING_TRANSFERS_SCHEMA_VERSION {
                let pending = {
                    let mut stmt = tx.prepare(
                        "SELECT * FROM pending_transfers WHERE state = 'pending' \
                         ORDER BY received_at_ms, sender_member, transfer_id",
                    )?;
                    let rows = stmt
                        .query_map([], incoming_from_row)?
                        .collect::<rusqlite::Result<Vec<_>>>()?;
                    rows
                };
                for row in pending {
                    if reject_incoming_tx(tx, &audit_key, &row, REJECT_REMOTE_SEAL_INVALID, now)? {
                        recovery.rejected_incoming.push(RecoveredIncoming {
                            sender_member: row.sender_member,
                            transfer_id: row.transfer_id,
                            credential_id: row.credential_id,
                        });
                    }
                }
                let outgoing = {
                    let mut stmt = tx.prepare(
                        "SELECT * FROM outgoing_transfers WHERE state = 'pending' \
                         ORDER BY created_at_ms, transfer_id",
                    )?;
                    let rows = stmt
                        .query_map([], outgoing_from_row)?
                        .collect::<rusqlite::Result<Vec<_>>>()?;
                    rows
                };
                for row in outgoing {
                    tx.execute(
                        "UPDATE outgoing_transfers SET state = 'abandoned' WHERE transfer_id = ?1",
                        [&row.transfer_id],
                    )?;
                    append_transfer_reject_tx(
                        tx,
                        &audit_key,
                        &row.credential_id,
                        &row.transfer_id,
                        REJECT_SENDER_KEY_REPLACED,
                        &row.receiver_member,
                    )?;
                    recovery.abandoned_outgoing.push(RecoveredOutgoing {
                        transfer_id: row.transfer_id,
                        credential_id: row.credential_id,
                        receiver_member: row.receiver_member,
                    });
                }
            }
            Ok(Ok(recovery))
        })
    }
}

/// The audit row's credential id for a member grant: the id an exact selector names,
/// else none (a category or no selector names no single credential).
fn member_grant_audit_target(selector: &MemberGrantSelector) -> Option<String> {
    match selector {
        MemberGrantSelector::Exact(id) => Some(id.clone()),
        MemberGrantSelector::Category(_) | MemberGrantSelector::None => None,
    }
}

fn same_member_grant(left: &MemberGrant, right: &MemberGrant) -> bool {
    left.member_id == right.member_id
        && left.operation == right.operation
        && left.selector == right.selector
}

fn vault_sharing_diff<'a>(
    existing: &'a [MemberGrant],
    wanted: &'a [MemberGrant],
) -> (Vec<&'a MemberGrant>, Vec<&'a MemberGrant>) {
    let revoked = existing
        .iter()
        .filter(|grant| {
            grant.source == MemberGrantSource::SharingSwitch
                && !wanted.iter().any(|want| {
                    same_member_grant(grant, want) && grant.pairing_id == want.pairing_id
                })
        })
        .collect();
    let created = wanted
        .iter()
        .filter(|grant| {
            !existing.iter().any(|old| {
                same_member_grant(old, grant)
                    && (old.source == MemberGrantSource::Operator
                        || old.pairing_id == grant.pairing_id)
            })
        })
        .collect();
    (created, revoked)
}

fn member_grants_conn(conn: &rusqlite::Connection) -> rusqlite::Result<Vec<MemberGrant>> {
    let version = read_schema_version(conn)?;
    if version < MEMBER_GRANTS_SCHEMA_VERSION {
        return Ok(Vec::new());
    }
    let source = if version < MEMBER_GRANT_SOURCE_SCHEMA_VERSION {
        "'operator'"
    } else {
        "source"
    };
    let mut stmt = conn.prepare(&format!(
        "SELECT member_id, operation, selector_kind, selector, pairing_id, created_at_ms, {source} FROM member_grants ORDER BY member_id, operation, selector_kind, selector"
    ))?;
    let rows = stmt
        .query_map([], |row| {
            let operation: String = row.get(1)?;
            let kind: String = row.get(2)?;
            let source: String = row.get(6)?;
            Ok(MemberGrant {
                member_id: row.get(0)?,
                operation: MemberGrantOperation::from_stored(&operation)
                    .ok_or_else(|| bad_column(format!("unknown member operation {operation}")))?,
                selector: MemberGrantSelector::from_stored(&kind, row.get(3)?)
                    .ok_or_else(|| bad_column(format!("unknown member selector {kind}")))?,
                pairing_id: row.get(4)?,
                created_at_ms: row.get(5)?,
                source: MemberGrantSource::from_stored(&source)
                    .ok_or_else(|| bad_column(format!("unknown member grant source {source}")))?,
            })
        })?
        .collect();
    rows
}

fn create_member_grant_tx(
    tx: &rusqlite::Transaction,
    audit_key: &[u8; 32],
    grant: &MemberGrant,
) -> rusqlite::Result<bool> {
    let sql = if read_schema_version(tx)? < MEMBER_GRANT_SOURCE_SCHEMA_VERSION {
        "INSERT INTO member_grants (member_id, operation, selector_kind, selector, pairing_id, created_at_ms) \
         SELECT ?1, ?2, ?3, ?4, ?5, ?6 WHERE ?7 = 'operator' \
         ON CONFLICT(member_id, operation, selector_kind, selector) DO UPDATE SET \
         pairing_id = excluded.pairing_id, created_at_ms = excluded.created_at_ms \
         WHERE member_grants.pairing_id <> excluded.pairing_id"
    } else {
        "INSERT INTO member_grants (member_id, operation, selector_kind, selector, pairing_id, created_at_ms, source) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) \
         ON CONFLICT(member_id, operation, selector_kind, selector) DO UPDATE SET \
         pairing_id = excluded.pairing_id, created_at_ms = excluded.created_at_ms, source = excluded.source \
         WHERE member_grants.pairing_id <> excluded.pairing_id OR member_grants.source <> excluded.source"
    };
    let changed = tx.execute(
        sql,
        rusqlite::params![
            grant.member_id,
            grant.operation.as_str(),
            grant.selector.kind_str(),
            grant.selector.selector_str(),
            grant.pairing_id,
            grant.created_at_ms,
            grant.source.as_str()
        ],
    )?;
    if changed == 0 {
        return Ok(false);
    }
    audit_member_grant_tx(tx, audit_key, grant, AuditOp::MemberGrantCreate)?;
    Ok(true)
}

fn revoke_member_grant_tx(
    tx: &rusqlite::Transaction,
    audit_key: &[u8; 32],
    grant: &MemberGrant,
) -> rusqlite::Result<()> {
    let source = if read_schema_version(tx)? < MEMBER_GRANT_SOURCE_SCHEMA_VERSION {
        "'operator'"
    } else {
        "source"
    };
    tx.execute(
        &format!("DELETE FROM member_grants WHERE member_id = ?1 AND operation = ?2 AND selector_kind = ?3 AND selector = ?4 AND {source} = ?5"),
        rusqlite::params![grant.member_id, grant.operation.as_str(), grant.selector.kind_str(), grant.selector.selector_str(), grant.source.as_str()],
    )?;
    audit_member_grant_tx(tx, audit_key, grant, AuditOp::MemberGrantRevoke)
}

fn audit_member_grant_tx(
    tx: &rusqlite::Transaction,
    audit_key: &[u8; 32],
    grant: &MemberGrant,
    op: AuditOp,
) -> rusqlite::Result<()> {
    // Preserve the operator audit encoding. Switch mutations name the member in the
    // payload because their actor is the vault, not the member.
    let (actor, alarm, payload_hash) = match grant.source {
        MemberGrantSource::Operator => (
            grant.member_id.as_str(),
            Some(AlarmReason::AdminWrite),
            member_grant_payload_hash(grant.operation, &grant.selector, &grant.pairing_id),
        ),
        MemberGrantSource::SharingSwitch => (
            "vault",
            None,
            crate::federation::sharing_switch_grant_payload_hash(grant),
        ),
    };
    append_audit_tx(
        tx,
        audit_key,
        &AuditRecord {
            op,
            credential_id: member_grant_audit_target(&grant.selector),
            payload_hash: Some(payload_hash),
            actor: actor.to_string(),
            alarm,
        },
    )?;
    Ok(())
}
