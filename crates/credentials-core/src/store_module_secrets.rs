//! Private, value-sealed storage that is deliberately separate from credential rows.

use super::*;
use crate::secret::Secret;

#[cfg(test)]
#[path = "store_module_secret_tests.rs"]
mod tests;

pub const MODULE_SECRET_MAX_ITEMS: usize = 64;
pub const MODULE_SECRET_MAX_VALUE_BYTES: usize = 65_536;
pub const MODULE_SECRET_MAX_NAME_BYTES: usize = 64;
pub const MODULE_SECRET_MAX_MODULE_ID_BYTES: usize = MODULE_SECRET_MAX_NAME_BYTES;

/// A module identity validated before it can select a private storage namespace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModuleSecretOwner(String);

impl ModuleSecretOwner {
    pub fn new(module_id: &str) -> Result<Self, ModuleSecretError> {
        validate_module_secret_name(module_id)?;
        Ok(Self(module_id.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn actor(&self) -> String {
        format!("reserved:{}", self.0)
    }
}

/// Names and module ids exclude `|`, the separator in their authenticated encryption binding.
pub fn validate_module_secret_name(name: &str) -> Result<(), ModuleSecretError> {
    let bytes = name.as_bytes();
    if bytes.is_empty()
        || bytes.len() > MODULE_SECRET_MAX_NAME_BYTES
        || !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit()
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(byte))
    {
        return Err(ModuleSecretError::InvalidParams);
    }
    Ok(())
}

/// Store refusals contain no underlying SQL, envelope or plaintext diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModuleSecretError {
    Protected,
    VersionConflict,
    Limit,
    InvalidParams,
    NotFound,
    Corrupt,
    VaultLocked,
    Store,
}

impl ModuleSecretError {
    /// The error code sent on the wire, the same for a module calling `module_secret.*`
    /// and for the operator's `ck auth module-secret` commands.
    pub fn code(self) -> &'static str {
        match self {
            Self::Protected => "module_secret_protected",
            Self::VersionConflict => "module_secret_version_conflict",
            Self::Limit => "module_secret_limit",
            Self::InvalidParams => "invalid_params",
            Self::NotFound => "not_found",
            Self::Corrupt => "corrupt",
            Self::VaultLocked => "vault_locked",
            Self::Store => "store_error",
        }
    }

    /// A locked vault or a store failure may pass on retry; every other refusal won't.
    pub fn class(self) -> &'static str {
        match self {
            Self::VaultLocked | Self::Store => "transient",
            Self::Protected
            | Self::VersionConflict
            | Self::Limit
            | Self::InvalidParams
            | Self::NotFound
            | Self::Corrupt => "permanent",
        }
    }
}

impl std::fmt::Display for ModuleSecretError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Protected => "module secret is protected",
            Self::VersionConflict => "module secret version conflict",
            Self::Limit => "module secret limit reached",
            Self::InvalidParams => "invalid module secret parameters",
            Self::NotFound => "module secret not found",
            Self::Corrupt => "module secret is corrupt",
            Self::VaultLocked => "vault is locked",
            Self::Store => "module secret store error",
        })
    }
}

impl std::error::Error for ModuleSecretError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModuleSecretState {
    Active,
    Corrupt,
}

impl ModuleSecretState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Corrupt => "corrupt",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModuleSecretWritten {
    pub name: String,
    pub version: u64,
    pub created: bool,
}

#[derive(Clone, Debug)]
pub struct ModuleSecret {
    pub name: String,
    pub version: u64,
    pub value: Secret<Vec<u8>>,
    pub protected: bool,
}

/// Metadata only: operator listings include the owner, but never an envelope or value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModuleSecretSummary {
    pub module_id: String,
    pub name: String,
    pub version: u64,
    pub protected: bool,
    pub state: ModuleSecretState,
    pub updated_at_ms: i64,
}

fn binding_id(module_id: &str, name: &str) -> String {
    format!("module-secret|{module_id}|{name}")
}

impl From<rusqlite::Error> for ModuleSecretError {
    fn from(_: rusqlite::Error) -> Self {
        Self::Store
    }
}

struct StoredModuleSecret {
    module_id: String,
    name: String,
    version: u64,
    protected: bool,
    state: ModuleSecretState,
    envelope: Vec<u8>,
    created_at_ms: i64,
    updated_at_ms: i64,
}

impl StoredModuleSecret {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        let version: i64 = row.get("version")?;
        let state: String = row.get("state")?;
        Ok(Self {
            module_id: row.get("module_id")?,
            name: row.get("name")?,
            version: u64::try_from(version).map_err(|_| rusqlite::Error::InvalidQuery)?,
            protected: row.get("protected")?,
            state: match state.as_str() {
                "active" => ModuleSecretState::Active,
                "corrupt" => ModuleSecretState::Corrupt,
                _ => return Err(rusqlite::Error::InvalidQuery),
            },
            envelope: row.get("envelope")?,
            created_at_ms: row.get("created_at_ms")?,
            updated_at_ms: row.get("updated_at_ms")?,
        })
    }

    fn open(&self, key: &MasterKey) -> Result<Zeroizing<Vec<u8>>, ModuleSecretError> {
        if self.state == ModuleSecretState::Corrupt {
            return Err(ModuleSecretError::Corrupt);
        }
        let id = binding_id(&self.module_id, &self.name);
        envelope::open(
            key,
            &self.envelope,
            &RecordBinding {
                credential_id: &id,
                record_version: self.version,
            },
        )
        .map_err(|error| match error {
            EnvelopeError::KeyMismatch { .. } => ModuleSecretError::VaultLocked,
            _ => ModuleSecretError::Corrupt,
        })
    }

    fn summary(self) -> ModuleSecretSummary {
        ModuleSecretSummary {
            module_id: self.module_id,
            name: self.name,
            version: self.version,
            protected: self.protected,
            state: self.state,
            updated_at_ms: self.updated_at_ms,
        }
    }
}

fn read_item(
    conn: &rusqlite::Connection,
    owner: &ModuleSecretOwner,
    name: &str,
) -> rusqlite::Result<Option<StoredModuleSecret>> {
    conn.query_row(
        "SELECT * FROM module_secrets WHERE module_id = ?1 AND name = ?2",
        rusqlite::params![owner.as_str(), name],
        StoredModuleSecret::from_row,
    )
    .optional()
}

fn validate_expected_version(version: Option<u64>) -> Result<(), ModuleSecretError> {
    if version == Some(0) {
        return Err(ModuleSecretError::InvalidParams);
    }
    Ok(())
}

impl EncryptedStore {
    // Convert domain refusals into rollback, not a successful no-op commit. Neither
    // SQL diagnostics nor cryptographic errors become part of the public error.
    fn module_secret_write<T>(
        &self,
        work: impl FnOnce(&rusqlite::Transaction<'_>) -> Result<T, ModuleSecretError>,
    ) -> Result<T, ModuleSecretError> {
        let mut refusal = None;
        let result = self.fenced_write(|tx| {
            work(tx).map_err(|error| {
                refusal = Some(error);
                rusqlite::Error::InvalidQuery
            })
        });
        result.map_err(|_| refusal.unwrap_or(ModuleSecretError::Store))
    }

    pub fn put_module_secret(
        &self,
        owner: &ModuleSecretOwner,
        name: &str,
        value: &[u8],
        expected_version: Option<u64>,
        protected: Option<bool>,
    ) -> Result<ModuleSecretWritten, ModuleSecretError> {
        validate_module_secret_name(name)?;
        validate_expected_version(expected_version)?;
        if value.is_empty() || value.len() > MODULE_SECRET_MAX_VALUE_BYTES {
            return Err(ModuleSecretError::InvalidParams);
        }
        self.module_secret_write(|tx| {
            let existing = read_item(tx, owner, name)?;
            let (version, protected, created_at_ms, created) = match existing {
                Some(row) => {
                    if row.protected {
                        return Err(ModuleSecretError::Protected);
                    }
                    if expected_version.is_some_and(|expected| expected != row.version) {
                        return Err(ModuleSecretError::VersionConflict);
                    }
                    if protected == Some(true) {
                        return Err(ModuleSecretError::InvalidParams);
                    }
                    let version = row.version.checked_add(1).filter(|v| *v <= i64::MAX as u64)
                        .ok_or(ModuleSecretError::Store)?;
                    (version, row.protected, row.created_at_ms, false)
                }
                None => {
                    if expected_version.is_some() {
                        return Err(ModuleSecretError::VersionConflict);
                    }
                    let count: i64 = tx.query_row(
                        "SELECT count(*) FROM module_secrets WHERE module_id = ?1",
                        [owner.as_str()],
                        |r| r.get(0),
                    )?;
                    if count >= MODULE_SECRET_MAX_ITEMS as i64 {
                        return Err(ModuleSecretError::Limit);
                    }
                    (1, protected.unwrap_or(false), now_ms(), true)
                }
            };
            let id = binding_id(owner.as_str(), name);
            let sealed = envelope::seal(&self.key, value, &RecordBinding {
                credential_id: &id,
                record_version: version,
            }).map_err(|_| ModuleSecretError::Store)?;
            tx.execute(
                "INSERT INTO module_secrets
                 (module_id, name, version, protected, state, key_id, envelope, created_at_ms, updated_at_ms)
                 VALUES (?1, ?2, ?3, ?4, 'active', ?5, ?6, ?7, ?8)
                 ON CONFLICT(module_id, name) DO UPDATE SET
                 version = excluded.version, state = 'active', key_id = excluded.key_id,
                 envelope = excluded.envelope, updated_at_ms = excluded.updated_at_ms",
                rusqlite::params![owner.as_str(), name, version as i64, protected,
                    self.key_id.to_hex(), sealed, created_at_ms, now_ms()],
            )?;
            append_audit_tx(tx, &self.audit_key, &AuditRecord {
                op: if created { AuditOp::ModuleSecretCreate } else { AuditOp::ModuleSecretReplace },
                credential_id: Some(id),
                payload_hash: Some(hex32(&audit::payload_fingerprint(&self.audit_key, value))),
                actor: owner.actor(),
                alarm: None,
            })?;
            Ok(ModuleSecretWritten { name: name.to_owned(), version, created })
        })
    }

    pub fn get_module_secret(
        &self,
        owner: &ModuleSecretOwner,
        name: &str,
    ) -> Result<ModuleSecret, ModuleSecretError> {
        validate_module_secret_name(name)?;
        let row = self
            .store
            .with_conn(|conn| read_item(conn, owner, name))
            .map_err(|_| ModuleSecretError::Store)?
            .ok_or(ModuleSecretError::NotFound)?;
        match row.open(&self.key) {
            Ok(value) => Ok(ModuleSecret {
                name: row.name,
                version: row.version,
                value: Secret::new(value.to_vec()),
                protected: row.protected,
            }),
            Err(ModuleSecretError::Corrupt) if row.state == ModuleSecretState::Active => {
                self.quarantine_module_secret(&row)?;
                Err(ModuleSecretError::Corrupt)
            }
            Err(error) => Err(error),
        }
    }

    fn quarantine_module_secret(&self, row: &StoredModuleSecret) -> Result<(), ModuleSecretError> {
        self.module_secret_write(|tx| {
            tx.execute(
                "UPDATE module_secrets SET state = 'corrupt'
                 WHERE module_id = ?1 AND name = ?2 AND version = ?3
                 AND envelope = ?4 AND state = 'active'",
                rusqlite::params![row.module_id, row.name, row.version as i64, row.envelope],
            )?;
            Ok(())
        })
    }

    pub fn list_module_secrets(
        &self,
        owner: &ModuleSecretOwner,
    ) -> Result<Vec<ModuleSecretSummary>, ModuleSecretError> {
        self.list_module_secret_metadata(Some(owner))
    }

    pub fn list_all_module_secrets(&self) -> Result<Vec<ModuleSecretSummary>, ModuleSecretError> {
        self.list_module_secret_metadata(None)
    }

    fn list_module_secret_metadata(
        &self,
        owner: Option<&ModuleSecretOwner>,
    ) -> Result<Vec<ModuleSecretSummary>, ModuleSecretError> {
        self.store
            .with_conn(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT * FROM module_secrets WHERE (?1 IS NULL OR module_id = ?1)
                 ORDER BY module_id, name",
                )?;
                let rows = stmt.query_map([owner.map(ModuleSecretOwner::as_str)], |row| {
                    StoredModuleSecret::from_row(row).map(StoredModuleSecret::summary)
                })?;
                rows.collect()
            })
            .map_err(|_| ModuleSecretError::Store)
    }

    pub fn delete_module_secret(
        &self,
        owner: &ModuleSecretOwner,
        name: &str,
        expected_version: Option<u64>,
    ) -> Result<(), ModuleSecretError> {
        validate_module_secret_name(name)?;
        validate_expected_version(expected_version)?;
        self.module_secret_write(|tx| {
            let row = read_item(tx, owner, name)?.ok_or(ModuleSecretError::NotFound)?;
            if row.protected {
                return Err(ModuleSecretError::Protected);
            }
            if expected_version.is_some_and(|expected| expected != row.version) {
                return Err(ModuleSecretError::VersionConflict);
            }
            self.delete_module_secret_tx(tx, owner, name, &owner.actor(), None)
        })
    }

    pub fn delete_module_secret_as_operator(
        &self,
        owner: &ModuleSecretOwner,
        name: &str,
        ctx: AuditCtx<'_>,
    ) -> Result<(), ModuleSecretError> {
        validate_module_secret_name(name)?;
        self.module_secret_write(|tx| {
            if read_item(tx, owner, name)?.is_none() {
                return Err(ModuleSecretError::NotFound);
            }
            self.delete_module_secret_tx(tx, owner, name, ctx.actor, Some(AlarmReason::AdminWrite))
        })
    }

    fn delete_module_secret_tx(
        &self,
        tx: &rusqlite::Transaction<'_>,
        owner: &ModuleSecretOwner,
        name: &str,
        actor: &str,
        alarm: Option<AlarmReason>,
    ) -> Result<(), ModuleSecretError> {
        tx.execute(
            "DELETE FROM module_secrets WHERE module_id = ?1 AND name = ?2",
            rusqlite::params![owner.as_str(), name],
        )?;
        append_audit_tx(
            tx,
            &self.audit_key,
            &AuditRecord {
                op: AuditOp::ModuleSecretDelete,
                credential_id: Some(binding_id(owner.as_str(), name)),
                payload_hash: None,
                actor: actor.to_owned(),
                alarm,
            },
        )?;
        Ok(())
    }

    pub fn move_module_secrets(
        &self,
        from: &ModuleSecretOwner,
        to: &ModuleSecretOwner,
        ctx: AuditCtx<'_>,
    ) -> Result<usize, ModuleSecretError> {
        self.module_secret_write(|tx| {
            if from == to {
                return Err(ModuleSecretError::InvalidParams);
            }
            let occupied: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM module_secrets WHERE module_id = ?1)",
                [to.as_str()],
                |r| r.get(0),
            )?;
            if occupied {
                return Err(ModuleSecretError::InvalidParams);
            }
            let rows = {
                let mut stmt =
                    tx.prepare("SELECT * FROM module_secrets WHERE module_id = ?1 ORDER BY name")?;
                let mapped = stmt.query_map([from.as_str()], StoredModuleSecret::from_row)?;
                mapped.collect::<rusqlite::Result<Vec<_>>>()?
            };
            if rows.is_empty() {
                return Err(ModuleSecretError::NotFound);
            }
            for row in &rows {
                let value = row.open(&self.key)?;
                let id = binding_id(to.as_str(), &row.name);
                let sealed = envelope::seal(
                    &self.key,
                    &value,
                    &RecordBinding {
                        credential_id: &id,
                        record_version: row.version,
                    },
                )
                .map_err(|_| ModuleSecretError::Store)?;
                tx.execute(
                    "UPDATE module_secrets SET module_id = ?3, key_id = ?4, envelope = ?5,
                     updated_at_ms = ?6 WHERE module_id = ?1 AND name = ?2",
                    rusqlite::params![
                        from.as_str(),
                        row.name,
                        to.as_str(),
                        self.key_id.to_hex(),
                        sealed,
                        now_ms()
                    ],
                )?;
                append_audit_tx(
                    tx,
                    &self.audit_key,
                    &AuditRecord {
                        op: AuditOp::ModuleSecretMove,
                        credential_id: Some(id),
                        payload_hash: Some(hex32(&audit::payload_fingerprint(
                            &self.audit_key,
                            &value,
                        ))),
                        actor: ctx.actor.to_owned(),
                        alarm: Some(AlarmReason::AdminWrite),
                    },
                )?;
            }
            Ok(rows.len())
        })
    }
}

/// Called only from master-key rotation, inside the single write transaction that
/// `fenced_write` opens for the whole rotation. That transaction is refused if a newer
/// writer has taken the store's single-writer lease, and the re-sealed rows commit
/// together with the rest of the rotation or not at all.
pub(super) fn rotate_module_secrets_tx(
    tx: &rusqlite::Transaction<'_>,
    old_key: &MasterKey,
    new_key: &MasterKey,
) -> rusqlite::Result<Vec<String>> {
    let rows = {
        let mut stmt = tx.prepare("SELECT * FROM module_secrets ORDER BY module_id, name")?;
        let mapped = stmt.query_map([], StoredModuleSecret::from_row)?;
        mapped.collect::<rusqlite::Result<Vec<_>>>()?
    };
    let mut quarantined = Vec::new();
    for row in rows {
        let id = binding_id(&row.module_id, &row.name);
        let value = match row.open(old_key) {
            Ok(value) => value,
            Err(_) => {
                tx.execute(
                    "UPDATE module_secrets SET state = 'corrupt' WHERE module_id = ?1 AND name = ?2",
                    rusqlite::params![row.module_id, row.name],
                )?;
                quarantined.push(id);
                continue;
            }
        };
        let sealed = envelope::seal(
            new_key,
            &value,
            &RecordBinding {
                credential_id: &id,
                record_version: row.version,
            },
        )
        .map_err(|_| rusqlite_err("module secret re-seal failed"))?;
        tx.execute(
            "UPDATE module_secrets SET envelope = ?3, key_id = ?4 WHERE module_id = ?1 AND name = ?2",
            rusqlite::params![row.module_id, row.name, sealed, new_key.key_id().to_hex()],
        )?;
    }
    Ok(quarantined)
}
