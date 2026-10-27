//! Operator writes for agent secrets and the lease-free listing `ck auth secret` uses.
//!
//! The write half runs through the shared admin applier, so the online path (master-key
//! admin MAC through the daemon) and the offline path (single-writer lease) execute the
//! same code and cannot drift in what they store. The read half opens the store file
//! read-only, because an operator asking what secrets exist is usually asking while the
//! vault is serving.
//!
//! THREE RULES HOLD EVERY WRITE HERE TOGETHER:
//!
//! 1. The material never leaves this module. It enters as a `SecretPut`, is decoded to
//!    the same framed plaintext a phone deposit carries, and is sealed straight into the
//!    `envelope` column. It is never formatted, hashed into an audit field, put in a
//!    reply, or echoed in an error.
//! 2. The invariants are the phone channel's. A put uses one incarnation, one record
//!    binding (`secret|<kind>|<incarnation>|<name>`) and the same sealed-scope body, so a
//!    secret the operator puts releases to an agent exactly like one a phone deposited —
//!    and the same scope/corrupt checks fire on the way out.
//! 3. Names stay create-only. A live or corrupt row under the name refuses the put, so a
//!    mistake cannot be repaired by silently overwriting what an agent was granted access
//!    to; the operator deletes first, which is a separate audited act.

use super::*;
use crate::agent_secret::{self, SecretError, SecretPut, SecretScope};

impl EncryptedStore {
    /// Create one agent secret from operator-supplied material.
    ///
    /// Checks run in this order: name grammar (so a bad name is reported before any
    /// other field), scope and material validation, then the create-only name check
    /// inside the write transaction so it cannot race a concurrent deposit or put.
    pub fn secret_put_audited(
        &self,
        put: &SecretPut,
        actor: &str,
    ) -> Result<serde_json::Value, StoreOpError> {
        agent_secret::validate_name(&put.name).map_err(secret_validation_error)?;
        let (scope, material) = put.scope_and_material().map_err(secret_validation_error)?;
        let audit_key = self.audit_key.clone();
        self.fenced_write(|tx| {
            let exists: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM agent_secrets WHERE name=?1)",
                [&put.name],
                |r| r.get(0),
            )?;
            if exists {
                return Ok(Err(SecretError::NameExists));
            }
            let mut random = [0u8; 16];
            getrandom::getrandom(&mut random)
                .map_err(|_| rusqlite_err("secret incarnation generation failed"))?;
            let incarnation = hex_of(&random);
            let blob = agent_secret::seal(&self.key, &incarnation, &put.name, &scope, &material)
                .map_err(|_| rusqlite_err("secret seal failed"))?;
            let (host, prefix, location, origin) = super::phone::columns(&scope);
            tx.execute("INSERT INTO agent_secrets (name,kind,incarnation,state,host,path_prefix,location,origin,record_version,key_id,envelope,created_at_ms) VALUES (?1,?2,?3,'active',?4,?5,?6,?7,1,?8,?9,?10)",
                rusqlite::params![put.name,scope.kind(),incarnation,host,prefix,location,origin,self.key_id.to_hex(),blob,now_ms()])?;
            // The payload names the same fields a phone store does, minus the deposit id
            // an operator put never had. Material and any digest of it stay out.
            let mut fields: Vec<&[u8]> = vec![scope.kind().as_bytes(), incarnation.as_bytes()];
            match &scope {
                SecretScope::ApiKey {
                    host,
                    path_prefix,
                    location,
                } => fields.extend([
                    host.as_bytes(),
                    path_prefix.as_deref().unwrap_or("").as_bytes(),
                    location.as_bytes(),
                ]),
                SecretScope::SiteLogin { origin } => fields.push(origin.as_bytes()),
            }
            super::phone::audit(
                tx,
                &audit_key,
                AuditOp::SecretStore,
                Some(format!("secret|{}", put.name)),
                actor,
                &fields,
            )?;
            Ok(Ok(serde_json::json!({"status":"stored","incarnation":incarnation})))
        })
        .map_err(StoreOpError::from)?
        .map_err(secret_store_error)
    }

    /// Remove a secret, its grants and its pending requests.
    ///
    /// The row is located by name only and never opened, so a `corrupt` row can be
    /// removed — which is the case the operator most often needs, because a corrupt row
    /// still refuses its own name to any deposit or put.
    pub fn secret_operator_delete_audited(
        &self,
        name: &str,
        actor: &str,
    ) -> Result<serde_json::Value, StoreOpError> {
        agent_secret::validate_name(name).map_err(secret_validation_error)?;
        let audit_key = self.audit_key.clone();
        let target = format!("secret|{name}");
        self.fenced_write(|tx| {
            let row: Option<(String, String)> = tx
                .query_row(
                    "SELECT kind,incarnation FROM agent_secrets WHERE name=?1",
                    [name],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let Some((kind, incarnation)) = row else {
                return Ok(Err(SecretError::NotFound));
            };
            for table in [
                "secret_grants",
                "secret_flow_grants",
                "secret_pending_requests",
            ] {
                tx.execute(
                    &format!("DELETE FROM {table} WHERE incarnation=?1"),
                    [&incarnation],
                )?;
            }
            tx.execute(
                "DELETE FROM agent_secrets WHERE incarnation=?1",
                [&incarnation],
            )?;
            // Diagnostics belong to the secret's own subject; nothing else is touched
            // (a credential of the same name keeps its rows).
            tx.execute("DELETE FROM auth_events WHERE credential_id=?1", [&target])?;
            let request_id = agent_secret::request_id(now_ms())
                .map_err(|_| rusqlite_err("request id generation failed"))?;
            super::phone::audit(
                tx,
                &audit_key,
                AuditOp::SecretDelete,
                Some(target),
                actor,
                &[
                    kind.as_bytes(),
                    incarnation.as_bytes(),
                    request_id.as_bytes(),
                ],
            )?;
            Ok(Ok(serde_json::json!({"status":"deleted"})))
        })
        .map_err(StoreOpError::from)?
        .map_err(secret_store_error)
    }

    /// Remove one grant by id, keeping the secret it covered.
    ///
    /// Expired grants are swept by the vault rather than by this op, so an id that names
    /// nothing live answers `not_found` exactly like an unknown one.
    pub fn secret_operator_revoke_audited(
        &self,
        grant_id: &str,
        actor: &str,
    ) -> Result<serde_json::Value, StoreOpError> {
        self.fenced_write(|tx| {
            super::approval::revoke(tx, &self.audit_key, grant_id, actor, now_ms())
        })
        .map_err(StoreOpError::from)
    }
}

/// Grammar and limit refusals at the operator door reuse the store's existing
/// `invalid_credential_id` taxonomy rather than growing a third vocabulary: an operator
/// already reads that code from every other write verb, and a length overflow keeps its
/// own sentence so it is not mistaken for a character the grammar forbade.
fn secret_validation_error(error: agent_secret::ValidationError) -> StoreOpError {
    match error {
        agent_secret::ValidationError::InvalidParams => StoreOpError::InvalidCredentialId,
        agent_secret::ValidationError::LimitExceeded => {
            StoreOpError::Store("limit_exceeded: field over its length limit".into())
        }
    }
}

/// Turn a store refusal into the taxonomy code an operator can act on, so the CLI prints
/// `name_exists` rather than a sentence it has to string-match.
fn secret_store_error(error: SecretError) -> StoreOpError {
    match error {
        SecretError::NameExists => StoreOpError::SecretNameExists,
        SecretError::NotFound => StoreOpError::NotFound,
        // Validation ran before the transaction, so reaching here means the request and
        // its transaction disagree; report a storage error rather than inventing a code.
        _ => StoreOpError::Store("secret write refused".into()),
    }
}

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Every live grant as id, secret name and expiry, for the operator who needs a grant id
/// to revoke. Plaintext columns only, so no master key is involved.
pub fn list_agent_secret_grants_read_only(
    store_path: &std::path::Path,
) -> Result<Vec<(String, String, i64)>, StoreOpError> {
    let Some(listing) = list_agent_secrets_read_only(store_path)? else {
        return Ok(Vec::new());
    };
    Ok(listing
        .secrets
        .into_iter()
        .flat_map(|secret| {
            secret
                .grants
                .into_iter()
                .map(|grant| (grant.grant_id, grant.expires_at_ms.unwrap_or(0)))
                .chain(
                    secret
                        .flow_grants
                        .into_iter()
                        .map(|grant| (grant.grant_id, 0)),
                )
                .map(move |(id, expiry)| (id, secret.name.clone(), expiry))
        })
        .collect())
}

/// One agent secret as the read-only listing renders it.
///
/// Deliberately holds no material, no digest of it and no requested target path: every
/// field is a scope column or an id that is already plaintext in the store file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperatorSecretRow {
    pub name: String,
    pub kind: String,
    pub incarnation: String,
    /// `active` or `corrupt`.
    pub state: String,
    pub host: Option<String>,
    pub path_prefix: Option<String>,
    pub location: Option<String>,
    pub origin: Option<String>,
    pub grants: Vec<OperatorGrantRow>,
    /// Flow holders are separate because they have no agent scope or coverage.
    pub flow_grants: Vec<OperatorFlowGrantRow>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperatorGrantRow {
    pub grant_id: String,
    pub scope_owner: String,
    pub scope_kind: String,
    pub scope_ref: String,
    pub coverage: String,
    pub duration: String,
    /// Absent for a permanent grant, which has no expiry to report.
    pub expires_at_ms: Option<i64>,
    pub last_use_ms: Option<i64>,
    /// The paired computer whose agent this grant serves; `None` for this vault's own.
    pub asking_member_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperatorFlowGrantRow {
    pub grant_id: String,
    pub flow_id: String,
    pub flow_version: u64,
    pub flow_code_hash: String,
    pub flow_install_id: String,
    /// Sorted HTTP methods for an API key; absent for a site login.
    pub methods: Option<Vec<String>>,
    pub granted_at_ms: i64,
    pub last_use_ms: Option<i64>,
    pub card_ref: Option<String>,
    /// The paired computer whose flow this grant serves; `None` for this vault's own.
    pub asking_member_id: Option<String>,
}

/// One registered phone and how current its keys are.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperatorPhoneRow {
    pub fingerprint: String,
    pub pairing_id: String,
    /// `Some(observed_at_ms)` when the last pairing lookup saw this very pairing, `None`
    /// when a lookup saw a different pairing or the device absent.
    pub current_since_ms: Option<i64>,
    /// No lookup has happened for this fingerprint yet.
    pub unobserved: bool,
    pub observed_pairing_id: Option<String>,
}

/// Everything `ck auth secret list` prints, read without a lease or the master key.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OperatorSecretListing {
    pub secrets: Vec<OperatorSecretRow>,
    pub phones: Vec<OperatorPhoneRow>,
}

/// Read the agent-secret tables from a store file with no lease and no master key.
///
/// `Ok(None)` means the store predates the agent-secret migration, which is a different
/// fact from an empty vault: the CLI says "no agent-secret tables yet" for the first and
/// lists nothing for the second.
///
/// `mode=ro` rather than `immutable=1`, like every other lease-free reader here: the
/// table may be brand new and still sitting in the write-ahead log, and skipping the WAL
/// would report a secret the vault has already stored as missing.
pub fn list_agent_secrets_read_only(
    store_path: &std::path::Path,
) -> Result<Option<OperatorSecretListing>, StoreOpError> {
    let map = |e: rusqlite::Error| StoreOpError::from(StoreError::Backend(e.to_string()));
    let conn = rusqlite::Connection::open_with_flags(
        format!("file:{}?mode=ro", store_path.display()),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
    )
    .map_err(map)?;
    let schema_version = read_schema_version(&conn).map_err(map)?;
    if schema_version < AGENT_SECRET_SCHEMA_VERSION {
        return Ok(None);
    }
    let mut secrets = conn
        .prepare("SELECT name,kind,incarnation,state,host,path_prefix,location,origin FROM agent_secrets ORDER BY name")
        .map_err(map)?
        .query_map([], |r| {
            Ok(OperatorSecretRow {
                name: r.get(0)?,
                kind: r.get(1)?,
                incarnation: r.get(2)?,
                state: r.get(3)?,
                host: r.get(4)?,
                path_prefix: r.get(5)?,
                location: r.get(6)?,
                origin: r.get(7)?,
                grants: Vec::new(),
                flow_grants: Vec::new(),
            })
        })
        .map_err(map)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(map)?;
    // A store the daemon has not yet migrated has no `asking_member_id` column; every
    // grant in it was made on this vault, which `''` stands for.
    let asking_member = if schema_version >= SECRET_ASKING_MEMBER_SCHEMA_VERSION {
        "asking_member_id"
    } else {
        "''"
    };
    let asking = |id: String| (!id.is_empty()).then_some(id);
    for secret in &mut secrets {
        secret.grants = conn
            .prepare(&format!("SELECT grant_id,scope_owner,scope_kind,scope_ref,coverage,duration,expires_at_ms,last_use_ms,{asking_member} FROM secret_grants WHERE incarnation=?1 ORDER BY grant_id"))
            .map_err(map)?
            .query_map([&secret.incarnation], |r| {
                let duration: String = r.get(5)?;
                Ok(OperatorGrantRow {
                    grant_id: r.get(0)?,
                    scope_owner: r.get(1)?,
                    scope_kind: r.get(2)?,
                    scope_ref: r.get(3)?,
                    coverage: r.get(4)?,
                    expires_at_ms: (duration != "permanent").then(|| r.get(6)).transpose()?,
                    duration,
                    last_use_ms: r.get(7)?,
                    asking_member_id: asking(r.get(8)?),
                })
            })
            .map_err(map)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(map)?;
        if schema_version >= FLOW_SECRET_SCHEMA_VERSION {
            secret.flow_grants = conn
                .prepare(&format!("SELECT grant_id,flow_id,flow_version,flow_code_hash,flow_install_id,methods,granted_at_ms,last_use_ms,card_ref,{asking_member} FROM secret_flow_grants WHERE incarnation=?1 ORDER BY grant_id"))
                .map_err(map)?
                .query_map([&secret.incarnation], |r| {
                    let methods: Option<String> = r.get(5)?;
                    let methods = methods
                        .map(|json| serde_json::from_str(&json).map_err(|e| {
                            rusqlite::Error::FromSqlConversionFailure(5, rusqlite::types::Type::Text, Box::new(e))
                        }))
                        .transpose()?;
                    Ok(OperatorFlowGrantRow {
                        grant_id: r.get(0)?,
                        flow_id: r.get(1)?,
                        flow_version: r.get(2)?,
                        flow_code_hash: r.get(3)?,
                        flow_install_id: r.get(4)?,
                        methods,
                        granted_at_ms: r.get(6)?,
                        last_use_ms: r.get(7)?,
                        card_ref: r.get(8)?,
                        asking_member_id: asking(r.get(9)?),
                    })
                })
                .map_err(map)?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(map)?;
        }
    }
    let phones = conn
        .prepare(
            "SELECT k.fingerprint, k.pairing_id, o.pairing_id, o.observed_at_ms \
             FROM secret_phone_keys k LEFT JOIN secret_phone_observations o \
             ON o.fingerprint = k.fingerprint ORDER BY k.fingerprint, k.pairing_id",
        )
        .map_err(map)?
        .query_map([], |r| {
            let pairing_id: String = r.get(1)?;
            let observed: Option<String> = r.get(2)?;
            let observed_at: Option<i64> = r.get(3)?;
            // Comparing against the STORED observation is the whole point: this verb
            // makes no network call, so it can only report what the last lookup saw.
            let current_since_ms = if observed.as_deref() == Some(pairing_id.as_str()) {
                observed_at
            } else {
                None
            };
            // A row exists in `secret_phone_observations` for any lookup that happened,
            // including one that found the device absent. So `observed_at` alone cannot
            // say whether anything was ever seen: the left join's missing row is what an
            // unobserved fingerprint looks like.
            let unobserved = observed_at.is_none();
            Ok(OperatorPhoneRow {
                fingerprint: r.get(0)?,
                pairing_id,
                current_since_ms,
                unobserved,
                observed_pairing_id: observed,
            })
        })
        .map_err(map)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(map)?;
    Ok(Some(OperatorSecretListing { secrets, phones }))
}
