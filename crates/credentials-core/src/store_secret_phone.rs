use super::*;
use crate::agent_secret::{SecretError, SecretScope};
use serde_json::{json, Value};

pub const PHONE_MAPPING_SETTING: &str = "secret.phone_mapping";

/// Read persisted gates without taking the writer lease or loading any secret material.
pub fn secret_phone_gate_status_read_only(
    path: &std::path::Path,
) -> Result<[String; 2], StoreOpError> {
    let conn =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|e| StoreOpError::Store(e.to_string()))?;
    let has_settings: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='settings')",
            [],
            |r| r.get(0),
        )
        .map_err(|e| StoreOpError::Store(e.to_string()))?;
    if !has_settings {
        return Ok(["off".to_owned(), "off".to_owned()]);
    }
    Ok(
        ["federation.member_mapping", PHONE_MAPPING_SETTING].map(|name| {
            match conn
                .query_row("SELECT value FROM settings WHERE name=?1", [name], |r| {
                    r.get::<_, String>(0)
                })
                .optional()
            {
                Ok(None) => "off".to_owned(),
                Ok(Some(v)) if v == "true" => "on".to_owned(),
                Ok(Some(v)) if v == "false" => "off".to_owned(),
                _ => "unreadable".to_owned(),
            }
        }),
    )
}

#[derive(Clone)]
pub struct PhoneDeposit {
    pub deposit_id: String,
    pub member_id: String,
    pub name: String,
    pub scope: SecretScope,
    pub enc: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// Grammar has already been checked by the transport before the pairing lookup.
pub enum PhoneOperation {
    Register {
        deposit_pub: Vec<u8>,
        approval_pub: Vec<u8>,
    },
    DepositKeys,
    Deposit(PhoneDeposit),
    List,
    Approve {
        envelope: Vec<u8>,
        signature: Vec<u8>,
        card_ref: Option<String>,
    },
    DeleteRequest {
        name: String,
    },
    DeleteCommit {
        envelope: Vec<u8>,
        signature: Vec<u8>,
    },
    Revoke {
        grant_id: String,
    },
}

impl EncryptedStore {
    /// Both mapping gates come from one SQLite snapshot, so concurrent gate changes
    /// cannot combine a past member setting with a later phone setting.
    pub fn secret_phone_mapping_gates(&self) -> Result<(bool, Option<bool>), StoreOpError> {
        self.store.with_conn(|conn| {
            let (member,phone):(Option<String>,Option<String>)=conn.query_row(
                "SELECT (SELECT value FROM settings WHERE name='federation.member_mapping'), (SELECT value FROM settings WHERE name='secret.phone_mapping')",[],|r|Ok((r.get(0)?,r.get(1)?)))?;
            let phone=match phone.as_deref() {None|Some("false")=>Some(false),Some("true")=>Some(true),_=>None};
            Ok((member.as_deref()==Some("true"),phone))
        }).map_err(StoreOpError::from)
    }

    pub fn secret_phone_mapping(&self) -> Result<bool, StoreOpError> {
        self.store
            .with_conn(|conn| {
                let value: Option<String> = conn
                    .query_row(
                        "SELECT value FROM settings WHERE name = ?1",
                        [PHONE_MAPPING_SETTING],
                        |r| r.get(0),
                    )
                    .optional()?;
                match value.as_deref() {
                    None | Some("false") => Ok(false),
                    Some("true") => Ok(true),
                    _ => Err(rusqlite_err("unreadable phone mapping setting")),
                }
            })
            .map_err(StoreOpError::from)
    }

    pub fn set_secret_phone_mapping_audited(
        &self,
        enabled: bool,
        ctx: AuditCtx<'_>,
    ) -> Result<bool, StoreOpError> {
        self.fenced_write(|tx| {
            let wanted = if enabled { "true" } else { "false" };
            let old: Option<String> = tx.query_row("SELECT value FROM settings WHERE name = ?1", [PHONE_MAPPING_SETTING], |r| r.get(0)).optional()?;
            if old.as_deref() == Some(wanted) { return Ok(false); }
            tx.execute("INSERT INTO settings (name, value, updated_at_ms) VALUES (?1, ?2, ?3) ON CONFLICT(name) DO UPDATE SET value=excluded.value,updated_at_ms=excluded.updated_at_ms", rusqlite::params![PHONE_MAPPING_SETTING, wanted, now_ms()])?;
            let mut payload=Vec::new();
            agent_secret::push_field(&mut payload,wanted.as_bytes());
            append_audit_tx(tx,&self.audit_key,&AuditRecord {op:AuditOp::SecretPhoneGateSet,credential_id:None,payload_hash:Some(hex(&payload_hash(&payload))),actor:ctx.actor.to_string(),alarm:ctx.alarm})?;
            Ok(true)
        }).map_err(StoreOpError::from)
    }

    pub fn observe_secret_phone(
        &self,
        fingerprint: &str,
        pairing: Option<&str>,
        observed_at_ms: i64,
    ) -> Result<(), StoreOpError> {
        self.fenced_write(|tx| observation(tx, fingerprint, pairing, observed_at_ms))
            .map_err(StoreOpError::from)
    }

    /// The admission predicate is checked after obtaining the serializing write transaction.
    /// Once admitted, no asynchronous deadline can cancel a partially committed operation.
    pub fn secret_phone_operation(
        &self,
        fingerprint: &str,
        pairing: Option<&str>,
        observed_at_ms: i64,
        op: &PhoneOperation,
        before_deadline: impl FnOnce() -> bool,
        clock: impl FnOnce() -> i64,
    ) -> Result<Value, SecretError> {
        let answer = self.fenced_write(|tx| {
            let admitted = before_deadline();
            if !matches!(op, PhoneOperation::DepositKeys) {
                observation(tx, fingerprint, pairing, observed_at_ms)?;
            }
            if !admitted { return Ok(Err(SecretError::PairingUnavailable)); }
            let op_now = clock();
            if matches!(op, PhoneOperation::DepositKeys) {
                return Ok(self.deposit_keys_tx(tx));
            }
            let Some(pairing) = pairing else { return Ok(Err(SecretError::PhoneNotRegistered)); };
            let keys: Option<(Vec<u8>, Vec<u8>)> = tx.query_row(
                "SELECT deposit_pub, approval_pub FROM secret_phone_keys WHERE fingerprint=?1 AND pairing_id=?2",
                rusqlite::params![fingerprint, pairing], |r| Ok((r.get(0)?, r.get(1)?)),
            ).optional()?;
            if let PhoneOperation::Register { deposit_pub, approval_pub } = op {
                if let Some((deposit, approval)) = keys {
                    return Ok(if deposit == *deposit_pub && approval == *approval_pub {
                        Ok(json!({"status":"already_stored"}))
                    } else { Err(SecretError::PhoneKeyConflict) });
                }
                tx.execute("INSERT INTO secret_phone_keys (fingerprint,pairing_id,deposit_pub,approval_pub,created_at_ms) VALUES (?1,?2,?3,?4,?5)",
                    rusqlite::params![fingerprint,pairing,deposit_pub,approval_pub,op_now])?;
                let actor = format!("fed-phone:{fingerprint}");
                audit(tx, &self.audit_key, AuditOp::SecretPhoneRegister, Some(format!("secret-phone|{fingerprint}")), &actor,
                    &[pairing.as_bytes(),deposit_pub,approval_pub])?;
                return Ok(Ok(json!({"status":"stored"})));
            }
            let Some((deposit_pub, approval_pub)) = keys else { return Ok(Err(SecretError::PhoneNotRegistered)); };
            match op {
                PhoneOperation::Deposit(deposit) => self.deposit_tx(tx, fingerprint, &deposit_pub, deposit, op_now),
                PhoneOperation::List => {
                    sweep(tx, &self.audit_key, op_now)?;
                    list(tx).map(Ok)
                }
                PhoneOperation::Approve { envelope, signature, card_ref } => self.secret_approval_tx(tx, fingerprint, &approval_pub, envelope, signature, card_ref.as_deref(), false, op_now),
                PhoneOperation::DeleteCommit { envelope, signature } => self.secret_approval_tx(tx, fingerprint, &approval_pub, envelope, signature, None, true, op_now),
                PhoneOperation::DeleteRequest { name } => self.secret_delete_request_tx(tx, name, op_now),
                PhoneOperation::Revoke { grant_id } => super::approval::revoke(tx, &self.audit_key, grant_id, &format!("fed-phone:{fingerprint}"), op_now).map(Ok),
                PhoneOperation::Register { .. } | PhoneOperation::DepositKeys => unreachable!(),
            }
        }).map_err(|_| SecretError::StoreError)?;
        if answer == Err(SecretError::PhoneKeyConflict) {
            // Diagnostics cannot turn the stable conflict reply into a storage error.
            let actor = format!("fed-phone:{fingerprint}");
            let _ = self.fenced_write(|tx| {
                append_secret_auth_event_tx(
                    tx,
                    &format!("secret-phone|{fingerprint}"),
                    &AuthObservation {
                        kind: crate::audit::AuthEventKind::SecretUseRefusal.as_str(),
                        provider_status: None,
                        detail: Some("phone_key_conflict"),
                        reporter_source: None,
                        principal: Some(AuthEventPrincipal::Phone(&actor)),
                    },
                    None,
                    false,
                )
            });
        }
        answer
    }

    fn deposit_keys_tx(&self, tx: &rusqlite::Transaction<'_>) -> Result<Value, SecretError> {
        let member = self_member(tx)?;
        let record = self
            .secret_deposit_record_conn(tx)
            .map_err(deposit_key_error)?;
        let pem = std::str::from_utf8(record.payload.expose())
            .map_err(|_| SecretError::SecretSetupIncomplete)?;
        let (public, key_id) =
            crate::kem::public_half(pem).map_err(|_| SecretError::SecretSetupIncomplete)?;
        Ok(
            json!({"member_id":member,"keys":[{"state":"current","key_id":key_id,"pub":hex(&public)}]}),
        )
    }

    fn deposit_tx(
        &self,
        tx: &rusqlite::Transaction<'_>,
        fingerprint: &str,
        sender: &[u8],
        d: &PhoneDeposit,
        now: i64,
    ) -> rusqlite::Result<Result<Value, SecretError>> {
        // A vault whose secrets live on another member's vault stores nothing, so the
        // deposit is refused before any other check, with a refusal that names the home. The role is read in this transaction,
        // so a concurrent `home set` either sees this deposit's row or refuses it here.
        // `SecretError` names a code only, while this refusal must also name the home, so
        // the full refusal body is returned as the reply; the transport passes it through
        // unchanged, exactly as it would `SecretError::body()`.
        if let Some(refusal) = super::operator::secret_home_role_conn(tx).phone_deposit_refusal() {
            return Ok(refusal);
        }
        // All deposit checks use this transaction, including key and member reads. Reading
        // either through a public store method would reacquire the connection lock.
        let prepared = (|| {
            let record = self
                .secret_deposit_record_conn(tx)
                .map_err(deposit_key_error)?;
            let pem = std::str::from_utf8(record.payload.expose())
                .map_err(|_| SecretError::SecretSetupIncomplete)?;
            crate::kem::parse_pkcs8_pem(pem).map_err(|_| SecretError::SecretSetupIncomplete)?;
            let member = self_member(tx)?;
            let aad = agent_secret::deposit_aad(&d.deposit_id, &d.member_id, &d.name, &d.scope)?;
            let digest = hex(&agent_secret::deposit_digest(
                &d.deposit_id,
                &d.enc,
                &d.ciphertext,
                &aad,
            ));
            Ok::<_, SecretError>((record, member, aad, digest))
        })();
        let (record, member, aad, digest) = match prepared {
            Ok(p) => p,
            Err(e) => return Ok(Err(e)),
        };
        let tombstone: Option<(String,String,String)> = tx.query_row("SELECT digest,member_id,incarnation FROM secret_deposit_tombstones WHERE deposit_id=?1", [&d.deposit_id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
        if let Some((old_digest, old_member, incarnation)) = tombstone {
            let live: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM agent_secrets WHERE incarnation=?1)",
                [&incarnation],
                |r| r.get(0),
            )?;
            return Ok(if old_digest == digest && old_member == member && live {
                Ok(json!({"status":"already_stored"}))
            } else {
                Err(SecretError::DepositConflict)
            });
        }
        if d.member_id != member {
            return Ok(Err(SecretError::NotFound));
        }
        let pem = std::str::from_utf8(record.payload.expose()).expect("validated stored key");
        let opened = match crate::kem::open_auth(
            pem,
            sender,
            &d.enc,
            &d.ciphertext,
            agent_secret::DEPOSIT_INFO,
            &aad,
        ) {
            Ok(bytes) => crate::secret::Secret::new(bytes),
            Err(_) => return Ok(Err(SecretError::NotFound)),
        };
        let material = match agent_secret::decode_deposit_plaintext(d.scope.kind(), &opened)
            .and_then(|material| {
                agent_secret::validate_material(&material)?;
                Ok(material)
            }) {
            Ok(m) => m,
            Err(e) => return Ok(Err(e.into())),
        };
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM agent_secrets WHERE name=?1)",
            [&d.name],
            |r| r.get(0),
        )?;
        if exists {
            return Ok(Err(SecretError::NameExists));
        }
        let mut random = [0u8; 16];
        getrandom::getrandom(&mut random)
            .map_err(|_| rusqlite_err("secret incarnation generation failed"))?;
        let incarnation = hex(&random);
        let blob = agent_secret::seal(&self.key, &incarnation, &d.name, &d.scope, &material)
            .map_err(|_| rusqlite_err("secret seal failed"))?;
        let (host, prefix, location, origin) = columns(&d.scope);
        tx.execute("INSERT INTO agent_secrets (name,kind,incarnation,state,host,path_prefix,location,origin,record_version,key_id,envelope,created_at_ms) VALUES (?1,?2,?3,'active',?4,?5,?6,?7,1,?8,?9,?10)",
            rusqlite::params![d.name,d.scope.kind(),incarnation,host,prefix,location,origin,self.key_id.to_hex(),blob,now])?;
        tx.execute("INSERT INTO secret_deposit_tombstones (deposit_id,digest,member_id,incarnation) VALUES (?1,?2,?3,?4)", rusqlite::params![d.deposit_id,digest,member,incarnation])?;
        let mut fields = vec![d.scope.kind().as_bytes(), incarnation.as_bytes()];
        match &d.scope {
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
        fields.push(d.deposit_id.as_bytes());
        audit(
            tx,
            &self.audit_key,
            AuditOp::SecretStore,
            Some(format!("secret|{}", d.name)),
            &format!("fed-phone:{fingerprint}"),
            &fields,
        )?;
        Ok(Ok(json!({"status":"stored","incarnation":incarnation})))
    }
}

fn deposit_key_error(error: StoreOpError) -> SecretError {
    match error {
        StoreOpError::SecretSetupIncomplete => SecretError::SecretSetupIncomplete,
        _ => SecretError::StoreError,
    }
}

pub(super) fn self_member(tx: &rusqlite::Transaction<'_>) -> Result<String, SecretError> {
    tx.query_row(
        "SELECT value FROM settings WHERE name='federation.self_member'",
        [],
        |r| r.get::<_, String>(0),
    )
    .optional()
    .map_err(|_| SecretError::StoreError)?
    .filter(|m| crate::federation::valid_member_id(m))
    .ok_or(SecretError::SecretSetupIncomplete)
}

fn observation(
    tx: &rusqlite::Transaction<'_>,
    fp: &str,
    pairing: Option<&str>,
    now: i64,
) -> rusqlite::Result<()> {
    tx.execute("INSERT INTO secret_phone_observations (fingerprint,pairing_id,observed_at_ms) VALUES (?1,?2,?3) ON CONFLICT(fingerprint) DO UPDATE SET pairing_id=excluded.pairing_id,observed_at_ms=excluded.observed_at_ms", rusqlite::params![fp,pairing,now])?;
    Ok(())
}

pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub(super) fn columns(
    scope: &SecretScope,
) -> (Option<&str>, Option<&str>, Option<&str>, Option<&str>) {
    match scope {
        SecretScope::ApiKey {
            host,
            path_prefix,
            location,
        } => (Some(host), path_prefix.as_deref(), Some(location), None),
        SecretScope::SiteLogin { origin } => (None, None, None, Some(origin)),
    }
}

pub(super) fn audit(
    tx: &rusqlite::Transaction<'_>,
    key: &[u8; 32],
    op: AuditOp,
    target: Option<String>,
    actor: &str,
    fields: &[&[u8]],
) -> rusqlite::Result<()> {
    let mut payload = Vec::new();
    for field in fields {
        agent_secret::push_field(&mut payload, field);
    }
    append_audit_tx(
        tx,
        key,
        &AuditRecord {
            op,
            credential_id: target,
            payload_hash: Some(hex(&payload_hash(&payload))),
            actor: actor.to_owned(),
            alarm: None,
        },
    )?;
    Ok(())
}

pub(super) fn sweep(
    tx: &rusqlite::Transaction<'_>,
    key: &[u8; 32],
    now: i64,
) -> rusqlite::Result<()> {
    let expired = tx.prepare("SELECT grant_id,secret_name,incarnation,expires_at_ms FROM secret_grants WHERE duration != 'permanent' AND expires_at_ms <= ?1")?.query_map([now], |r| Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,u64>(3)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
    for (id, name, incarnation, expiry) in expired {
        tx.execute("DELETE FROM secret_grants WHERE grant_id=?1", [&id])?;
        audit(
            tx,
            key,
            AuditOp::SecretGrantExpire,
            Some(format!("secret|{name}")),
            "vault",
            &[id.as_bytes(), incarnation.as_bytes(), &expiry.to_le_bytes()],
        )?;
    }
    sweep_release_receipts(tx, now)
}

/// Delete release receipts that can no longer answer a retry. This only reclaims
/// space: a receipt lookup compares `expires_at_ms` with its own clock and never
/// relies on this having run.
pub(super) fn sweep_release_receipts(
    tx: &rusqlite::Transaction<'_>,
    now: i64,
) -> rusqlite::Result<()> {
    tx.execute(
        "DELETE FROM secret_release_receipts WHERE expires_at_ms <= ?1",
        [now],
    )?;
    Ok(())
}

fn list(tx: &rusqlite::Transaction<'_>) -> rusqlite::Result<Value> {
    let mut stmt = tx.prepare("SELECT name,kind,incarnation,state,host,path_prefix,location,origin FROM agent_secrets ORDER BY name")?;
    let mut secrets = stmt.query_map([], |r| {
        let mut value = json!({"name":r.get::<_,String>(0)?,"kind":r.get::<_,String>(1)?,"incarnation":r.get::<_,String>(2)?,"state":r.get::<_,String>(3)?});
        for (index,key) in [(4,"host"),(5,"path_prefix"),(6,"location"),(7,"origin")] {
            if let Some(text) = r.get::<_,Option<String>>(index)? { value[key]=json!(text); }
        }
        Ok(value)
    })?.collect::<rusqlite::Result<Vec<_>>>()?;
    for secret in &mut secrets {
        let mut grants = tx.prepare("SELECT grant_id,scope_owner,scope_kind,scope_ref,coverage,duration,expires_at_ms,last_use_ms,agent_id FROM secret_grants WHERE incarnation=?1 ORDER BY grant_id")?;
        secret["grants"] = Value::Array(grants.query_map([secret["incarnation"].as_str().expect("incarnation")], |r| {
            let duration: String=r.get(5)?;
            // `agent_id` is always present so the phone never has to tell a missing key
            // from an agent-less grant: it is null when the grant named no agent.
            let mut grant = json!({"grant_id":r.get::<_,String>(0)?,"scope":{"owner":r.get::<_,String>(1)?,"kind":r.get::<_,String>(2)?,"ref":r.get::<_,String>(3)?},"coverage":r.get::<_,String>(4)?,"duration":duration,"agent_id":r.get::<_,Option<String>>(8)?});
            if duration != "permanent" { grant["expires_at_ms"]=json!(r.get::<_,i64>(6)?); }
            if let Some(last)=r.get::<_,Option<i64>>(7)? { grant["last_use_ms"]=json!(last); }
            Ok(grant)
        })?.collect::<rusqlite::Result<Vec<_>>>()?);
        // A flow grant answers a different question: "which installed flow version may
        // use this?" It therefore names its flow instead of an asking scope, has no
        // coverage and never expires, and carries `methods` only for an API key.
        let mut flows = tx.prepare("SELECT grant_id,flow_id,flow_version,flow_install_id,methods,last_use_ms FROM secret_flow_grants WHERE incarnation=?1 ORDER BY grant_id")?;
        let flow_grants = flows.query_map([secret["incarnation"].as_str().expect("incarnation")], |r| {
            let methods: Option<String> = r.get(4)?;
            let mut grant = json!({"grant_id":r.get::<_,String>(0)?,"flow":{"flow_id":r.get::<_,String>(1)?,"version":r.get::<_,u64>(2)?,"install_id":r.get::<_,String>(3)?},"duration":"version"});
            if let Some(methods) = methods {
                grant["methods"] = serde_json::from_str(&methods).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(4, rusqlite::types::Type::Text, Box::new(e))
                })?;
            }
            if let Some(last)=r.get::<_,Option<i64>>(5)? { grant["last_use_ms"]=json!(last); }
            Ok(grant)
        })?.collect::<rusqlite::Result<Vec<_>>>()?;
        secret["flow_grants"] = Value::Array(flow_grants);
    }
    Ok(json!({"secrets":secrets}))
}

#[cfg(test)]
#[path = "store_secret_phone_tests.rs"]
mod tests;
