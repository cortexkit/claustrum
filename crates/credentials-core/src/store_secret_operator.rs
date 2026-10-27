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
use crate::federation::{valid_member_id, SELF_MEMBER_SETTING};

/// The vault setting naming which member's vault holds this account's agent secrets.
/// Absent means this vault serves its own secrets, as a single computer always has.
pub const SECRET_HOME_SETTING: &str = "secrets.home_member";

/// The stored value meaning "this vault is the home". It is kept symbolic, never a copy
/// of the self id, so a later change of the federation self id cannot turn a home into a
/// remote.
pub const SECRET_HOME_SELF: &str = "self";

/// Where this vault stands for agent secrets, resolved from `secrets.home_member` and
/// the live federation self id on every call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SecretHomeRole {
    /// The setting is unset: every secret op is served locally, exactly as before the
    /// setting existed.
    Single,
    /// The setting is `self`. `self_member` is the live self id, when one is set.
    Home { self_member: Option<String> },
    /// The setting names another member, whose vault holds the secrets.
    Remote { home_member: String },
    /// The setting names a member while the self id is unset or equal to it, so this
    /// vault cannot tell whether it is the home. Permanent until an operator fixes it.
    RemoteSetupIncomplete { self_member: Option<String> },
    /// The setting or the self id could not be read, or the setting holds a value that
    /// is neither `self` nor a member id. Transient: nothing is decided from it.
    StoreError,
}

impl SecretHomeRole {
    /// The role's name as `ck auth secret home show` prints it: the role for a usable
    /// setting, or the refusal code a secret op answers when the setting is unusable.
    pub fn as_str(&self) -> &'static str {
        match self {
            SecretHomeRole::Single => "single",
            SecretHomeRole::Home { .. } => "home",
            SecretHomeRole::Remote { .. } => "remote",
            SecretHomeRole::RemoteSetupIncomplete { .. } => "remote_setup_incomplete",
            SecretHomeRole::StoreError => "store_error",
        }
    }

    /// Whether a new agent secret may be created on this vault, and the refusal when it
    /// may not. Only a vault that serves secrets itself (single or home) may hold them.
    fn local_create_allowed(&self) -> Result<(), StoreOpError> {
        match self {
            SecretHomeRole::Single | SecretHomeRole::Home { .. } => Ok(()),
            SecretHomeRole::Remote { home_member } => Err(StoreOpError::SecretHomeElsewhere {
                home_member: home_member.clone(),
            }),
            SecretHomeRole::RemoteSetupIncomplete { self_member } => {
                Err(StoreOpError::SecretRemoteSetupIncomplete {
                    remedy_member: self_member.clone(),
                })
            }
            SecretHomeRole::StoreError => Err(StoreOpError::Store(
                "store_error: the secrets.home_member setting could not be read".into(),
            )),
        }
    }

    /// The phone channel's refusal body for a deposit on a vault that may not hold
    /// secrets, or `None` when the deposit may go ahead. The body has the same
    /// `{"error":{code,class,remedy_member?}}` shape as every other phone refusal.
    pub(super) fn phone_deposit_refusal(&self) -> Option<Result<serde_json::Value, SecretError>> {
        match self {
            SecretHomeRole::Single | SecretHomeRole::Home { .. } => None,
            SecretHomeRole::Remote { home_member } => Some(Ok(serde_json::json!({"error":{
                "code":"secret_home_elsewhere","class":"permanent","remedy_member":home_member,
            }}))),
            SecretHomeRole::RemoteSetupIncomplete { self_member } => {
                let mut error =
                    serde_json::json!({"code":"remote_setup_incomplete","class":"permanent"});
                if let Some(member) = self_member {
                    error["remedy_member"] = serde_json::json!(member);
                }
                Some(Ok(serde_json::json!({ "error": error })))
            }
            SecretHomeRole::StoreError => Some(Err(SecretError::StoreError)),
        }
    }
}

/// Resolve the role from the stored setting and the stored self id. A self id that is
/// not a valid member id counts as unset, which can only make the answer a refusal.
pub fn resolve_secret_home_role(
    setting: Option<&str>,
    self_member: Option<&str>,
) -> SecretHomeRole {
    let self_member = self_member
        .filter(|m| valid_member_id(m))
        .map(str::to_owned);
    match setting {
        None => SecretHomeRole::Single,
        Some(SECRET_HOME_SELF) => SecretHomeRole::Home { self_member },
        Some(home) if valid_member_id(home) => match self_member {
            Some(me) if me != home => SecretHomeRole::Remote {
                home_member: home.to_owned(),
            },
            other => SecretHomeRole::RemoteSetupIncomplete { self_member: other },
        },
        Some(_) => SecretHomeRole::StoreError,
    }
}

/// One setting, or `None` on a store from before the settings table existed.
fn read_setting_conn(conn: &rusqlite::Connection, name: &str) -> rusqlite::Result<Option<String>> {
    if read_schema_version(conn)? < SETTINGS_SCHEMA_VERSION {
        return Ok(None);
    }
    conn.query_row("SELECT value FROM settings WHERE name=?1", [name], |r| {
        r.get(0)
    })
    .optional()
}

/// The stored setting and the stored self id, read through one connection. Inside a
/// write transaction both come from the same snapshot as the write that depends on them.
fn secret_home_settings_conn(
    conn: &rusqlite::Connection,
) -> rusqlite::Result<(Option<String>, Option<String>)> {
    Ok((
        read_setting_conn(conn, SECRET_HOME_SETTING)?,
        read_setting_conn(conn, SELF_MEMBER_SETTING)?,
    ))
}

/// The role as seen by `conn`. A read failure is [`SecretHomeRole::StoreError`].
pub(super) fn secret_home_role_conn(conn: &rusqlite::Connection) -> SecretHomeRole {
    match secret_home_settings_conn(conn) {
        Ok((setting, self_member)) => {
            resolve_secret_home_role(setting.as_deref(), self_member.as_deref())
        }
        Err(_) => SecretHomeRole::StoreError,
    }
}

/// What `ck auth secret home show` prints: the stored setting and the role it resolves to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretHomeStatus {
    /// The stored value: `self`, a member id, or `None` when unset.
    pub setting: Option<String>,
    pub role: SecretHomeRole,
}

/// Read the setting without the writer lease, like `ck auth secret list`, so it works
/// while the vault is serving. A store from before the settings table reads as unset.
pub fn secret_home_read_only(path: &std::path::Path) -> Result<SecretHomeStatus, StoreOpError> {
    let conn =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|e| StoreOpError::Store(e.to_string()))?;
    let (setting, self_member) =
        secret_home_settings_conn(&conn).map_err(|e| StoreOpError::Store(e.to_string()))?;
    let role = resolve_secret_home_role(setting.as_deref(), self_member.as_deref());
    Ok(SecretHomeStatus { setting, role })
}

/// The result of `home set`: what is stored now, and whether the call changed it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretHomeChange {
    pub stored: Option<String>,
    pub changed: bool,
}

impl EncryptedStore {
    /// This vault's role for agent secrets, from one read of the store.
    pub fn secret_home_role(&self) -> SecretHomeRole {
        self.store
            .with_conn(|conn| Ok(secret_home_role_conn(conn)))
            .unwrap_or(SecretHomeRole::StoreError)
    }

    /// Set `secrets.home_member` to `self` or a member id, or clear it with `None`.
    ///
    /// A member id equal to the stored self id is stored as `self`. Naming another
    /// member is refused while this vault holds any agent secret, grant, flow grant or
    /// pending request, so the secrets cannot be stranded on a vault that stops serving
    /// them. The count and the write share one transaction: a concurrent put either
    /// commits first, and is counted, or runs after and is refused by the new setting.
    /// Setting `self` or clearing is always allowed. The caller checks a member id
    /// against callosum's pairing first; this method only checks its grammar.
    pub fn set_secret_home_audited(
        &self,
        home: Option<&str>,
        ctx: AuditCtx<'_>,
    ) -> Result<SecretHomeChange, StoreOpError> {
        if let Some(home) = home {
            if home != SECRET_HOME_SELF && !valid_member_id(home) {
                return Err(StoreOpError::InvalidMemberId);
            }
        }
        let audit_key = self.audit_key.clone();
        self.fenced_write(|tx| {
            let (current, self_member) = secret_home_settings_conn(tx)?;
            let wanted = match home {
                Some(member) if self_member.as_deref() == Some(member) => Some(SECRET_HOME_SELF),
                other => other,
            };
            if current.as_deref() == wanted {
                return Ok(Ok(SecretHomeChange {
                    stored: current,
                    changed: false,
                }));
            }
            if wanted.is_some_and(|value| value != SECRET_HOME_SELF) {
                let count = |table: &str| -> rusqlite::Result<u64> {
                    tx.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
                };
                let agent_secrets = count("agent_secrets")?;
                let grants = count("secret_grants")?;
                let flow_grants = count("secret_flow_grants")?;
                let pending_requests = count("secret_pending_requests")?;
                if agent_secrets + grants + flow_grants + pending_requests > 0 {
                    return Ok(Err(StoreOpError::SecretHomeNotEmpty {
                        agent_secrets,
                        grants,
                        flow_grants,
                        pending_requests,
                    }));
                }
            }
            match wanted {
                Some(value) => {
                    tx.execute(
                        "INSERT INTO settings (name, value, updated_at_ms) VALUES (?1, ?2, ?3) \
                         ON CONFLICT(name) DO UPDATE SET value=excluded.value, \
                         updated_at_ms=excluded.updated_at_ms",
                        rusqlite::params![SECRET_HOME_SETTING, value, now_ms()],
                    )?;
                }
                None => {
                    tx.execute("DELETE FROM settings WHERE name=?1", [SECRET_HOME_SETTING])?;
                }
            }
            let mut payload = Vec::new();
            agent_secret::push_field(&mut payload, wanted.unwrap_or("").as_bytes());
            append_audit_tx(
                tx,
                &audit_key,
                &AuditRecord {
                    op: ctx.op,
                    credential_id: None,
                    payload_hash: Some(hex_of(&payload_hash(&payload))),
                    actor: ctx.actor.to_string(),
                    alarm: ctx.alarm,
                },
            )?;
            Ok(Ok(SecretHomeChange {
                stored: wanted.map(str::to_owned),
                changed: true,
            }))
        })
        .map_err(StoreOpError::from)?
    }

    /// Create one agent secret from operator-supplied material.
    ///
    /// Checks run in this order: name grammar (so a bad name is reported before any
    /// other field), scope and material validation, then, inside the write transaction
    /// so neither can race a concurrent deposit, put or `home set`, the vault's secret
    /// home role and the create-only name check.
    pub fn secret_put_audited(
        &self,
        put: &SecretPut,
        actor: &str,
    ) -> Result<serde_json::Value, StoreOpError> {
        self.secret_put_inner(put, actor, &|| {})
    }

    /// [`Self::secret_put_audited`], calling `gate` inside the write transaction after
    /// the role check and before the insert, so a test can hold a put at that point.
    #[cfg(any(test, feature = "test-support"))]
    pub fn secret_put_audited_with_gate(
        &self,
        put: &SecretPut,
        actor: &str,
        gate: &dyn Fn(),
    ) -> Result<serde_json::Value, StoreOpError> {
        self.secret_put_inner(put, actor, gate)
    }

    fn secret_put_inner(
        &self,
        put: &SecretPut,
        actor: &str,
        gate: &dyn Fn(),
    ) -> Result<serde_json::Value, StoreOpError> {
        agent_secret::validate_name(&put.name).map_err(secret_validation_error)?;
        let (scope, material) = put.scope_and_material().map_err(secret_validation_error)?;
        let audit_key = self.audit_key.clone();
        self.fenced_write(|tx| {
            if let Err(refusal) = secret_home_role_conn(tx).local_create_allowed() {
                return Ok(Err(refusal));
            }
            gate();
            let exists: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM agent_secrets WHERE name=?1)",
                [&put.name],
                |r| r.get(0),
            )?;
            if exists {
                return Ok(Err(secret_store_error(SecretError::NameExists)));
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
