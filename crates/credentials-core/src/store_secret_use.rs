use super::*;
use crate::agent_secret::{
    AskingScope, SecretError, SecretMaterial, SecretScope, SecretSender, SecretUse,
    MAX_SECRET_PENDING_PER_SCOPE, MAX_SECRET_PENDING_TOTAL, SECRET_PENDING_LIFETIME_LIMIT_MS,
};
use base64::Engine;
use serde_json::{json, Value};

#[path = "store_secret_flow.rs"]
mod flow;

pub struct SecretUseOutcome {
    pub reply: Value,
    /// The module schedules `secret_use_last_use` without awaiting it, so updating
    /// `last_use_ms` cannot delay or fail a repeat release.
    pub last_use: Option<(String, i64)>,
}

struct Record {
    incarnation: String,
    scope: SecretScope,
    material: SecretMaterial,
}

struct Refusal {
    detail: &'static str,
    addressed: bool,
}
struct Grant {
    id: String,
    first: bool,
    duration: String,
}

impl EncryptedStore {
    /// Diagnostics are separate from release/quarantine transactions and cannot change replies.
    pub fn record_secret_use_refusal(
        &self,
        sender: SecretSender,
        name: Option<&str>,
        detail: &'static str,
    ) {
        let subject = name.map_or_else(
            || "secret-use|unaddressed".to_owned(),
            |n| format!("secret|{n}"),
        );
        let _ = self.store.with_conn(|conn| {
            let tx = conn.unchecked_transaction()?;
            append_secret_auth_event_tx(
                &tx,
                &subject,
                &AuthObservation {
                    kind: AuthEventKind::SecretUseRefusal.as_str(),
                    provider_status: None,
                    detail: Some(detail),
                    reporter_source: None,
                    principal: Some(AuthEventPrincipal::Reserved(
                        sender
                            .actor()
                            .strip_prefix("reserved:")
                            .expect("sender module"),
                    )),
                },
                None,
                false,
            )?;
            tx.commit()
        });
    }

    /// Ordinary repeat releases do not need an audit transition or a writer-fence wakeup.
    pub fn secret_use_last_use(&self, id: &str, now: i64) {
        let _ = self.store.with_conn(|conn| {
            let tx = conn.unchecked_transaction()?;
            for table in ["secret_grants", "secret_flow_grants"] {
                tx.execute(&format!("UPDATE {table} SET last_use_ms=MAX(COALESCE(last_use_ms,0),?2) WHERE grant_id=?1"), rusqlite::params![id,now])?;
            }
            tx.commit()
        });
    }

    pub fn secret_use(
        &self,
        call: &SecretUse,
        clock: impl Fn() -> i64,
    ) -> Result<SecretUseOutcome, SecretError> {
        if call.sender == SecretSender::Basal {
            return self.use_refused(
                call,
                Refusal {
                    detail: "flow_identity",
                    addressed: false,
                },
            );
        }
        let now = clock();
        let snapshot = self.store.with_conn(|conn| {
            let record = self.check_secret_use(conn, call)?;
            let Ok(record) = record else { return Ok(Err(record.err().expect("refusal"))); };
            let grant = choose_grant(conn, call, &record.incarnation, now)?;
            let expired: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM secret_grants WHERE duration != 'permanent' AND expires_at_ms<=?1)", [now], |r|r.get(0))?;
            Ok(Ok((record, grant, expired)))
        }).map_err(|_|SecretError::StoreError)?;
        match snapshot {
            Err(refusal) => return self.use_refused(call, refusal),
            Ok((record, Some(grant), false)) if grant.first && grant.duration != "once" => {
                let reply = release(&record, now)?;
                return Ok(SecretUseOutcome {
                    reply,
                    last_use: Some((grant.id, now)),
                });
            }
            _ => {}
        }
        // Recheck after acquiring the write transaction: concurrent once uses must not share a snapshot.
        let answer = self.fenced_write(|tx| {
            let now = clock();
            let record = match self.check_secret_use(tx, call)? { Ok(r)=>r, Err(r)=>return Ok(Err(r)) };
            phone::sweep(tx, &self.audit_key, now)?;
            if let Some(grant) = choose_grant(tx, call, &record.incarnation, now)? {
                let reply = release(&record, now).map_err(|_|rusqlite_err("secret release failed"))?;
                if !grant.first || grant.duration == "once" {
                    phone::audit(tx, &self.audit_key, AuditOp::SecretFirstRelease, Some(format!("secret|{}",call.name)), call.sender.actor(), &[grant.id.as_bytes(),record.incarnation.as_bytes()])?;
                }
                if grant.duration == "once" { tx.execute("DELETE FROM secret_grants WHERE grant_id=?1",[&grant.id])?; }
                else { tx.execute("UPDATE secret_grants SET first_released=1,last_use_ms=?2 WHERE grant_id=?1",rusqlite::params![grant.id,now])?; }
                return Ok(Ok(Ok(SecretUseOutcome { reply, last_use:None })));
            }
            pending(tx, call, &record, now).map(Ok)
        }).map_err(|_|SecretError::StoreError)?;
        match answer {
            Err(refusal) => self.use_refused(call, refusal),
            Ok(answer) => answer,
        }
    }

    fn use_refused(
        &self,
        call: &SecretUse,
        refusal: Refusal,
    ) -> Result<SecretUseOutcome, SecretError> {
        Err(self.refuse_secret_target(&call.name, call.sender, &call.target, refusal))
    }

    fn refuse_secret_target(
        &self,
        name: &str,
        sender: SecretSender,
        target: &agent_secret::UseTarget,
        refusal: Refusal,
    ) -> SecretError {
        if refusal.detail == "sealed_scope" {
            // The flip is compare-and-set and audited in one transaction. Failure remains opaque.
            let _ = self.fenced_write(|tx| {
                let incarnation: Option<String> = tx.query_row("SELECT incarnation FROM agent_secrets WHERE name=?1 AND state='active'",[name],|r|r.get(0)).optional()?;
                if let Some(incarnation) = incarnation {
                    // Another writer may have repaired/replaced the row while this call waited.
                    if self.check_secret_target(tx,name,sender,target)?.is_err_and(|r|r.detail=="sealed_scope") {
                        tx.execute("UPDATE agent_secrets SET state='corrupt' WHERE name=?1 AND incarnation=?2 AND state='active'",rusqlite::params![name,incarnation])?;
                        phone::audit(tx,&self.audit_key,AuditOp::SecretQuarantine,Some(format!("secret|{name}")),"vault",&[incarnation.as_bytes()])?;
                    }
                }
                Ok(())
            });
        }
        self.record_secret_use_refusal(sender, refusal.addressed.then_some(name), refusal.detail);
        SecretError::NotFound
    }

    fn check_secret_use(
        &self,
        conn: &rusqlite::Connection,
        call: &SecretUse,
    ) -> rusqlite::Result<Result<Record, Refusal>> {
        self.check_secret_target(conn, &call.name, call.sender, &call.target)
    }

    fn check_secret_target(
        &self,
        conn: &rusqlite::Connection,
        name: &str,
        sender: SecretSender,
        target: &agent_secret::UseTarget,
    ) -> rusqlite::Result<Result<Record, Refusal>> {
        let row = conn.query_row("SELECT incarnation,state,kind,host,path_prefix,location,origin,envelope FROM agent_secrets WHERE name=?1",[name], |r| Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,Option<String>>(3)?,r.get::<_,Option<String>>(4)?,r.get::<_,Option<String>>(5)?,r.get::<_,Option<String>>(6)?,r.get::<_,Vec<u8>>(7)?))).optional()?;
        let Some((incarnation, state, kind, host, path_prefix, location, origin, blob)) = row
        else {
            return Ok(Err(Refusal {
                detail: "unknown_name",
                addressed: false,
            }));
        };
        let refused = |detail| {
            Ok(Err(Refusal {
                detail,
                addressed: true,
            }))
        };
        if state != "active" {
            return refused("corrupt");
        }
        let scope = match (kind.as_str(), host, location, origin) {
            ("agent_api_key", Some(host), Some(location), None) => SecretScope::ApiKey {
                host,
                path_prefix,
                location,
            },
            ("site_login", None, None, Some(origin)) => SecretScope::SiteLogin { origin },
            _ => return refused("sealed_scope"),
        };
        let material = match agent_secret::open(&self.key, &incarnation, name, &scope, &blob) {
            Ok(material) => material,
            Err(_) => return refused("sealed_scope"),
        };
        if !sender.admits(&scope) {
            return refused("kind");
        }
        if !target.matches(&scope) {
            return refused("target");
        }
        Ok(Ok(Record {
            incarnation,
            scope,
            material,
        }))
    }
}

fn choose_grant(
    conn: &rusqlite::Connection,
    call: &SecretUse,
    incarnation: &str,
    now: i64,
) -> rusqlite::Result<Option<Grant>> {
    let mut stmt=conn.prepare("SELECT grant_id,scope_owner,scope_kind,scope_ref,coverage,duration,first_released FROM secret_grants WHERE incarnation=?1 AND secret_name=?2 AND (duration='permanent' OR expires_at_ms>?3) ORDER BY (duration='once'), (duration='permanent') DESC, CASE WHEN duration!='once' THEN expires_at_ms ELSE 0 END DESC, granted_at_ms, grant_id")?;
    let rows = stmt.query_map(rusqlite::params![incarnation, call.name, now], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, String>(4)?,
            r.get::<_, String>(5)?,
            r.get::<_, bool>(6)?,
        ))
    })?;
    for row in rows {
        let (id, owner, kind, scope_ref, coverage, duration, first) = row?;
        let equal = |scope: &AskingScope| {
            scope.owner == owner && scope.kind == kind && scope.scope_ref == scope_ref
        };
        if (coverage == "scope" && equal(&call.scope))
            || (coverage == "agent_and_workers"
                && kind == "head"
                && (equal(&call.scope) || call.worker_parent.as_ref().is_some_and(equal)))
        {
            return Ok(Some(Grant {
                id,
                first,
                duration,
            }));
        }
    }
    Ok(None)
}

fn release(record: &Record, now: i64) -> Result<Value, SecretError> {
    match (&record.scope, &record.material) {
        (SecretScope::ApiKey { location, .. }, SecretMaterial::ApiKey(key)) => Ok(
            json!({"status":"released","kind":"agent_api_key","key_b64url":base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.expose()),"location":location}),
        ),
        (
            SecretScope::SiteLogin { .. },
            SecretMaterial::SiteLogin {
                username,
                password,
                otpauth,
            },
        ) => {
            let mut reply = json!({"status":"released","kind":"site_login","username":username.expose(),"password":password.expose()});
            if let Some(uri) = otpauth {
                let code =
                    agent_secret::totp(uri.expose(), now).map_err(|_| SecretError::StoreError)?;
                reply["totp"] = json!(code.expose());
            }
            Ok(reply)
        }
        _ => Err(SecretError::StoreError),
    }
}

fn approval_reply(id: &str, statement: &[u8], expiry: i64) -> SecretUseOutcome {
    SecretUseOutcome {
        reply: json!({"status":"approval_required","request_id":id,"statement_b64url":base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(statement),"expires_at_ms":expiry}),
        last_use: None,
    }
}

fn pending(
    tx: &rusqlite::Transaction<'_>,
    call: &SecretUse,
    record: &Record,
    now: i64,
) -> rusqlite::Result<Result<SecretUseOutcome, SecretError>> {
    let member = match phone::self_member(tx) {
        Ok(member) => member,
        Err(SecretError::StoreError) => return Err(rusqlite_err("member lookup failed")),
        Err(error) => return Ok(Err(error)),
    };
    let run = || -> rusqlite::Result<Result<SecretUseOutcome, SecretError>> {
        tx.execute("DELETE FROM secret_pending_requests WHERE consumed!=0 OR request_expires_at_ms<=?1 OR member_id!=?2",rusqlite::params![now,member])?;
        let prior=tx.query_row("SELECT request_id,statement_bytes,request_expires_at_ms FROM secret_pending_requests WHERE request_kind='approve' AND flow_id IS NULL AND incarnation=?1 AND mapped_owner=?2 AND mapped_kind=?3 AND mapped_ref=?4 AND coverage=?5",rusqlite::params![record.incarnation,call.scope.owner,call.scope.kind,call.scope.scope_ref,call.coverage],|r|Ok((r.get::<_,String>(0)?,r.get::<_,Vec<u8>>(1)?,r.get::<_,i64>(2)?))).optional()?;
        if let Some((id, bytes, expiry)) = prior {
            return Ok(Ok(approval_reply(&id, &bytes, expiry)));
        }
        let (total,scope):(usize,usize)=tx.query_row("SELECT COUNT(*),COALESCE(SUM(mapped_owner=?1 AND mapped_kind=?2 AND mapped_ref=?3),0) FROM secret_pending_requests WHERE request_kind='approve'",rusqlite::params![call.scope.owner,call.scope.kind,call.scope.scope_ref],|r|Ok((r.get(0)?,r.get(1)?)))?;
        if total >= MAX_SECRET_PENDING_TOTAL || scope >= MAX_SECRET_PENDING_PER_SCOPE {
            return Ok(Err(SecretError::PendingLimit));
        }
        let id = agent_secret::request_id(now)
            .map_err(|_| rusqlite_err("request id generation failed"))?;
        let expiry = now + SECRET_PENDING_LIFETIME_LIMIT_MS;
        // The statement has fixed ASCII keys, no floats, and integers in JSON's exact range.
        // Sorted serde_json maps therefore use JCS key ordering; string values such as
        // `agent` and `scope.ref` retain their UTF-8 bytes without normalization.
        let statement = agent_secret::approval_statement(
            &id,
            &member,
            &record.incarnation,
            call,
            &record.scope,
            expiry,
        );
        let bytes = serde_json::to_vec(&statement)
            .map_err(|_| rusqlite_err("statement encoding failed"))?;
        let digest = phone::hex(&payload_hash(&bytes));
        tx.execute("INSERT INTO secret_pending_requests (request_id,request_kind,secret_name,incarnation,member_id,mapped_owner,mapped_kind,mapped_ref,mapped_epoch,coverage,agent_id,statement_bytes,statement_sha256,request_expires_at_ms) VALUES (?1,'approve',?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",rusqlite::params![id,call.name,record.incarnation,member,call.scope.owner,call.scope.kind,call.scope.scope_ref,call.scope.epoch,call.coverage,call.agent_id,bytes,digest,expiry])?;
        Ok(Ok(approval_reply(&id, &bytes, expiry)))
    };
    run()
}

#[cfg(test)]
#[path = "store_secret_use_tests.rs"]
mod tests;
