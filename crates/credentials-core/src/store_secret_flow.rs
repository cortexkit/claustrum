use super::*;
use agent_secret::{
    SecretFlowApproval, SecretFlowUse, FLOW_SECRET_PENDING_LIFETIME_LIMIT_MS,
    MAX_FLOW_SECRET_PENDING_PER_INSTALL, MAX_FLOW_SECRET_PENDING_TOTAL,
};

impl EncryptedStore {
    pub fn secret_request_flow_approval(
        &self,
        call: &SecretFlowApproval,
        clock: impl Fn() -> i64,
    ) -> Result<SecretUseOutcome, SecretError> {
        agent_secret::validate_name(&call.name)?;
        call.flow.validate()?;
        call.target.validate()?;
        let methods = agent_secret::validate_flow_methods(&call.target, call.methods.as_deref())?;
        let methods = methods
            .map(|m| serde_json::to_string(&m))
            .transpose()
            .map_err(|_| SecretError::StoreError)?;
        let answer = self
            .fenced_write(|tx| {
                let record = match self.check_secret_target(
                    tx,
                    &call.name,
                    SecretSender::Basal,
                    &call.target,
                )? {
                    Ok(record) => record,
                    Err(refusal) => return Ok(Err(refusal)),
                };
                let now = clock();
                flow_pending(tx, call, &record, methods.as_deref(), now).map(Ok)
            })
            .map_err(|_| SecretError::StoreError)?;
        match answer {
            Ok(answer) => answer,
            Err(refusal) => Err(self.refuse_secret_target(
                &call.name,
                SecretSender::Basal,
                &call.target,
                refusal,
            )),
        }
    }

    pub fn secret_flow_use(
        &self,
        call: &SecretFlowUse,
        clock: impl Fn() -> i64,
    ) -> Result<SecretUseOutcome, SecretError> {
        agent_secret::validate_name(&call.name)?;
        call.target.validate()?;
        let method = call.method.as_ref().map(std::slice::from_ref);
        agent_secret::validate_flow_methods(&call.target, method)?;
        if call.flow.validate().is_err() {
            self.record_secret_use_refusal(SecretSender::Basal, None, "flow_identity");
            return Err(SecretError::NotFound);
        }
        let snapshot = self
            .store
            .with_conn(|conn| {
                let record = match self.check_secret_target(
                    conn,
                    &call.name,
                    SecretSender::Basal,
                    &call.target,
                )? {
                    Ok(record) => record,
                    Err(refusal) => return Ok(Err(refusal)),
                };
                match choose_flow_grant(conn, call, &record.incarnation)? {
                    Ok(grant) => Ok(Ok((record, grant))),
                    Err(refusal) => Ok(Err(refusal)),
                }
            })
            .map_err(|_| SecretError::StoreError)?;
        match snapshot {
            Err(refusal) => {
                return Err(self.refuse_secret_target(
                    &call.name,
                    SecretSender::Basal,
                    &call.target,
                    refusal,
                ))
            }
            Ok((record, grant)) if grant.first => {
                let now = clock();
                return Ok(SecretUseOutcome {
                    reply: release(&record, now)?,
                    last_use: Some((grant.id, now)),
                });
            }
            _ => {}
        }
        // Recheck under the writer fence so concurrent first releases audit only once.
        let answer = self.fenced_write(|tx| {
            let record = match self.check_secret_target(tx, &call.name, SecretSender::Basal, &call.target)? {
                Ok(record) => record,
                Err(refusal) => return Ok(Err(refusal)),
            };
            let grant = match choose_flow_grant(tx, call, &record.incarnation)? {
                Ok(grant) => grant,
                Err(refusal) => return Ok(Err(refusal)),
            };
            let now = clock();
            let reply = release(&record, now).map_err(|_| rusqlite_err("secret release failed"))?;
            if !grant.first {
                phone::audit(tx, &self.audit_key, AuditOp::SecretFirstRelease, Some(format!("secret|{}", call.name)), SecretSender::Basal.actor(),
                    &[grant.id.as_bytes(), record.incarnation.as_bytes(), call.flow.flow_id.as_bytes(), call.flow.version.to_string().as_bytes()])?;
            }
            tx.execute("UPDATE secret_flow_grants SET first_released=1,last_use_ms=?2 WHERE grant_id=?1", rusqlite::params![grant.id, now])?;
            Ok(Ok(SecretUseOutcome { reply, last_use: None }))
        }).map_err(|_| SecretError::StoreError)?;
        answer.map_err(|refusal| {
            self.refuse_secret_target(&call.name, SecretSender::Basal, &call.target, refusal)
        })
    }

    pub fn revoke_flow_grants(
        &self,
        install_id: &str,
        version: Option<u64>,
    ) -> Result<usize, SecretError> {
        if !(1..=256).contains(&install_id.len())
            || !install_id.bytes().all(|b| (0x20..=0x7e).contains(&b))
            || version.is_some_and(|v| v == 0 || v > agent_secret::MAX_SECRET_JSON_INTEGER)
        {
            return Err(SecretError::InvalidParams);
        }
        self.fenced_write(|tx| {
            let mut stmt = tx.prepare("SELECT grant_id,secret_name,incarnation,flow_id,flow_version FROM secret_flow_grants WHERE flow_install_id=?1 AND (?2 IS NULL OR flow_version=?2) ORDER BY grant_id")?;
            let grants = stmt.query_map(rusqlite::params![install_id, version], |r| Ok((r.get::<_,String>(0)?, r.get::<_,String>(1)?, r.get::<_,String>(2)?, r.get::<_,String>(3)?, r.get::<_,u64>(4)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
            for (id, name, incarnation, flow_id, flow_version) in &grants {
                tx.execute("DELETE FROM secret_flow_grants WHERE grant_id=?1", [id])?;
                phone::audit(tx, &self.audit_key, AuditOp::SecretGrantRevoke, Some(format!("secret|{name}")), SecretSender::Basal.actor(),
                    &[id.as_bytes(), incarnation.as_bytes(), flow_id.as_bytes(), flow_version.to_string().as_bytes()])?;
            }
            tx.execute("DELETE FROM secret_pending_requests WHERE consumed=0 AND flow_install_id=?1 AND (?2 IS NULL OR flow_version=?2)", rusqlite::params![install_id, version])?;
            phone::audit(tx, &self.audit_key, AuditOp::SecretGrantRevoke, Some(format!("secret-flow|{install_id}")), SecretSender::Basal.actor(),
                &[install_id.as_bytes(), version.map(|v| v.to_string()).unwrap_or_default().as_bytes(), grants.len().to_string().as_bytes()])?;
            Ok(grants.len())
        }).map_err(|_| SecretError::StoreError)
    }
}

fn flow_pending(
    tx: &rusqlite::Transaction<'_>,
    call: &SecretFlowApproval,
    record: &Record,
    methods: Option<&str>,
    now: i64,
) -> rusqlite::Result<Result<SecretUseOutcome, SecretError>> {
    let member = match phone::self_member(tx) {
        Ok(member) => member,
        Err(SecretError::StoreError) => return Err(rusqlite_err("member lookup failed")),
        Err(error) => return Ok(Err(error)),
    };
    tx.execute("DELETE FROM secret_pending_requests WHERE consumed!=0 OR request_expires_at_ms<=?1 OR member_id!=?2", rusqlite::params![now, member])?;
    let prior = tx.query_row("SELECT request_id,statement_bytes,request_expires_at_ms FROM secret_pending_requests WHERE request_kind='approve' AND incarnation=?1 AND flow_id=?2 AND flow_version=?3 AND flow_code_hash=?4 AND flow_install_id=?5 AND methods IS ?6 AND mapped_owner IS NULL AND mapped_kind IS NULL AND mapped_ref IS NULL AND mapped_epoch IS NULL AND coverage IS NULL AND agent_id IS NULL", rusqlite::params![record.incarnation, call.flow.flow_id, call.flow.version, call.flow.code_hash, call.flow.install_id, methods], |r| Ok((r.get::<_,String>(0)?, r.get::<_,Vec<u8>>(1)?, r.get::<_,i64>(2)?))).optional()?;
    if let Some((id, bytes, expiry)) = prior {
        return Ok(Ok(approval_reply(&id, &bytes, expiry)));
    }
    let (total, install): (usize,usize) = tx.query_row("SELECT COUNT(*),COALESCE(SUM(flow_install_id=?1),0) FROM secret_pending_requests WHERE request_kind='approve' AND flow_id IS NOT NULL", [&call.flow.install_id], |r| Ok((r.get(0)?, r.get(1)?)))?;
    if total >= MAX_FLOW_SECRET_PENDING_TOTAL || install >= MAX_FLOW_SECRET_PENDING_PER_INSTALL {
        return Ok(Err(SecretError::PendingLimit));
    }
    let id =
        agent_secret::request_id(now).map_err(|_| rusqlite_err("request id generation failed"))?;
    let expiry = now + FLOW_SECRET_PENDING_LIFETIME_LIMIT_MS;
    let statement = agent_secret::flow_approval_statement(
        &id,
        &member,
        &record.incarnation,
        &call.name,
        &call.flow,
        &record.scope,
        call.methods.as_deref(),
        expiry,
    )
    .map_err(|_| rusqlite_err("statement encoding failed"))?;
    let bytes =
        serde_json::to_vec(&statement).map_err(|_| rusqlite_err("statement encoding failed"))?;
    let digest = phone::hex(&payload_hash(&bytes));
    tx.execute("INSERT INTO secret_pending_requests (request_id,request_kind,secret_name,incarnation,member_id,flow_id,flow_version,flow_code_hash,flow_install_id,methods,statement_bytes,statement_sha256,request_expires_at_ms) VALUES (?1,'approve',?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)", rusqlite::params![id, call.name, record.incarnation, member, call.flow.flow_id, call.flow.version, call.flow.code_hash, call.flow.install_id, methods, bytes, digest, expiry])?;
    Ok(Ok(approval_reply(&id, &bytes, expiry)))
}

fn choose_flow_grant(
    conn: &rusqlite::Connection,
    call: &SecretFlowUse,
    incarnation: &str,
) -> rusqlite::Result<Result<Grant, Refusal>> {
    let mut stmt = conn.prepare("SELECT grant_id,first_released,methods FROM secret_flow_grants WHERE secret_name=?1 AND incarnation=?2 AND flow_id=?3 AND flow_version=?4 AND flow_code_hash=?5 AND flow_install_id=?6 ORDER BY granted_at_ms,grant_id")?;
    let rows = stmt.query_map(
        rusqlite::params![
            call.name,
            incarnation,
            call.flow.flow_id,
            call.flow.version,
            call.flow.code_hash,
            call.flow.install_id
        ],
        |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, bool>(1)?,
                r.get::<_, Option<String>>(2)?,
            ))
        },
    )?;
    let mut detail = "flow_no_grant";
    for row in rows {
        let (id, first, methods) = row?;
        let matches = match (&call.method, methods) {
            (Some(method), Some(methods)) => serde_json::from_str::<Vec<String>>(&methods)
                .map_err(|_| rusqlite_err("invalid stored flow methods"))?
                .contains(method),
            (None, None) => true,
            _ => false,
        };
        if matches {
            return Ok(Ok(Grant {
                id,
                first,
                duration: "version".into(),
            }));
        }
        detail = "flow_method";
    }
    Ok(Err(Refusal {
        detail,
        addressed: true,
    }))
}
