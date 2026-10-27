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
        self.secret_request_flow_approval_from(call, LOCAL_ASKING_MEMBER, clock)
    }

    /// [`Self::secret_request_flow_approval`] for a request that `asking_member`
    /// forwarded to this vault. The pending request records that asker, so its approval
    /// grants that computer's flow and nobody else's. The caller must have
    /// authenticated `asking_member`.
    pub fn secret_request_flow_approval_from(
        &self,
        call: &SecretFlowApproval,
        asking_member: &str,
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
                flow_pending(tx, call, asking_member, &record, methods.as_deref(), now).map(Ok)
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
        self.secret_flow_use_from(call, LOCAL_ASKING_MEMBER, clock)
    }

    /// [`Self::secret_flow_use`] for a flow run that `asking_member` forwarded to this
    /// vault. Only flow grants recorded for that same asker release. The caller must
    /// have authenticated `asking_member`.
    pub fn secret_flow_use_from(
        &self,
        call: &SecretFlowUse,
        asking_member: &str,
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
                match choose_flow_grant(conn, call, asking_member, &record.incarnation)? {
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
                let grant = match choose_flow_grant(tx, call, asking_member, &record.incarnation)? {
                    Ok(grant) => grant,
                    Err(refusal) => return Ok(Err(refusal)),
                };
                let now = clock();
                let reply =
                    release(&record, now).map_err(|_| rusqlite_err("secret release failed"))?;
                self.commit_flow_release(tx, call, &grant, &record, now)?;
                Ok(Ok(SecretUseOutcome {
                    reply,
                    last_use: None,
                }))
            })
            .map_err(|_| SecretError::StoreError)?;
        answer.map_err(|refusal| {
            self.refuse_secret_target(&call.name, SecretSender::Basal, &call.target, refusal)
        })
    }

    /// Mark a flow grant released, and write the release audit the first time it releases.
    fn commit_flow_release(
        &self,
        tx: &rusqlite::Transaction<'_>,
        call: &SecretFlowUse,
        grant: &Grant,
        record: &Record,
        now: i64,
    ) -> rusqlite::Result<()> {
        if !grant.first {
            phone::audit(
                tx,
                &self.audit_key,
                AuditOp::SecretFirstRelease,
                Some(format!("secret|{}", call.name)),
                SecretSender::Basal.actor(),
                &[
                    grant.id.as_bytes(),
                    record.incarnation.as_bytes(),
                    call.flow.flow_id.as_bytes(),
                    call.flow.version.to_string().as_bytes(),
                ],
            )?;
        }
        tx.execute(
            "UPDATE secret_flow_grants SET first_released=1,last_use_ms=?2 WHERE grant_id=?1",
            rusqlite::params![grant.id, now],
        )?;
        Ok(())
    }

    /// [`Self::secret_flow_use_from`] for a flow run a paired computer forwarded, whose
    /// release must cross to that computer sealed. `seal`, the release receipt and the
    /// caller's duties are exactly as for [`Self::secret_use_sealed`]; a flow grant
    /// counts as live while its row exists, since flow grants never expire.
    pub fn secret_flow_use_sealed<E>(
        &self,
        call: &SecretFlowUse,
        request: &ReleaseRequest<'_>,
        seal: impl FnOnce(&Value) -> Result<SealedRelease, E>,
        clock: impl Fn() -> i64,
    ) -> Result<Result<ForwardedUse, E>, SecretError> {
        request.validate()?;
        agent_secret::validate_name(&call.name)?;
        call.target.validate()?;
        let method = call.method.as_ref().map(std::slice::from_ref);
        agent_secret::validate_flow_methods(&call.target, method)?;
        if call.flow.validate().is_err() {
            self.record_secret_use_refusal(SecretSender::Basal, None, "flow_identity");
            return Err(SecretError::NotFound);
        }
        let aad_sha256 = phone::hex(&payload_hash(request.aad));
        let mut seal_failure = None;
        let answer = self.fenced_write(|tx| {
            let now = clock();
            let record = match self.check_secret_target(
                tx,
                &call.name,
                SecretSender::Basal,
                &call.target,
            )? {
                Ok(record) => record,
                Err(refusal) => return Ok(Forwarded::Refused(refusal)),
            };
            if let Some(replay) = replay(
                tx,
                request,
                &aad_sha256,
                &record.incarnation,
                &[ReceiptGrant::Flow],
                now,
            )? {
                return Ok(replay);
            }
            phone::sweep_release_receipts(tx, now)?;
            let grant = match choose_flow_grant(tx, call, request.requester, &record.incarnation)? {
                Ok(grant) => grant,
                Err(refusal) => return Ok(Forwarded::Refused(refusal)),
            };
            let reply = release(&record, now).map_err(|_| rusqlite_err("secret release failed"))?;
            let sealed = match seal(&reply) {
                Ok(sealed) => sealed,
                Err(error) => {
                    seal_failure = Some(error);
                    return Err(rusqlite_err("secret release seal failed"));
                }
            };
            self.commit_flow_release(tx, call, &grant, &record, now)?;
            write_receipt(
                tx,
                request,
                &aad_sha256,
                &record.incarnation,
                ReceiptGrant::Flow,
                &grant.id,
                &sealed,
                now,
            )?;
            Ok(Forwarded::Answer(Ok(ForwardedUse::Sealed(sealed))))
        });
        if let Some(error) = seal_failure {
            return Ok(Err(error));
        }
        match answer.map_err(|_| SecretError::StoreError)? {
            Forwarded::Answer(answer) => answer.map(Ok),
            Forwarded::Refused(refusal) => Err(self.refuse_secret_target(
                &call.name,
                SecretSender::Basal,
                &call.target,
                refusal,
            )),
        }
    }

    pub fn revoke_flow_grants(
        &self,
        install_id: &str,
        version: Option<u64>,
    ) -> Result<usize, SecretError> {
        self.revoke_flow_grants_from(install_id, version, LOCAL_ASKING_MEMBER)
    }

    /// [`Self::revoke_flow_grants`] for a revoke that `asking_member` forwarded to this
    /// vault. It removes only that asker's flow grants and unconsumed requests, so one
    /// computer uninstalling a flow leaves the same flow identity's grants on other
    /// computers, and on this vault itself, in place. The caller must have
    /// authenticated `asking_member`.
    pub fn revoke_flow_grants_from(
        &self,
        install_id: &str,
        version: Option<u64>,
        asking_member: &str,
    ) -> Result<usize, SecretError> {
        if !(1..=256).contains(&install_id.len())
            || !install_id.bytes().all(|b| (0x20..=0x7e).contains(&b))
            || version.is_some_and(|v| v == 0 || v > agent_secret::MAX_SECRET_JSON_INTEGER)
        {
            return Err(SecretError::InvalidParams);
        }
        self.fenced_write(|tx| {
            let mut stmt = tx.prepare("SELECT grant_id,secret_name,incarnation,flow_id,flow_version FROM secret_flow_grants WHERE flow_install_id=?1 AND (?2 IS NULL OR flow_version=?2) AND asking_member_id=?3 ORDER BY grant_id")?;
            let grants = stmt.query_map(rusqlite::params![install_id, version, asking_member], |r| Ok((r.get::<_,String>(0)?, r.get::<_,String>(1)?, r.get::<_,String>(2)?, r.get::<_,String>(3)?, r.get::<_,u64>(4)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
            for (id, name, incarnation, flow_id, flow_version) in &grants {
                tx.execute("DELETE FROM secret_flow_grants WHERE grant_id=?1", [id])?;
                phone::audit(tx, &self.audit_key, AuditOp::SecretGrantRevoke, Some(format!("secret|{name}")), SecretSender::Basal.actor(),
                    &[id.as_bytes(), incarnation.as_bytes(), flow_id.as_bytes(), flow_version.to_string().as_bytes()])?;
            }
            tx.execute("DELETE FROM secret_pending_requests WHERE consumed=0 AND flow_install_id=?1 AND (?2 IS NULL OR flow_version=?2) AND asking_member_id=?3", rusqlite::params![install_id, version, asking_member])?;
            phone::audit(tx, &self.audit_key, AuditOp::SecretGrantRevoke, Some(format!("secret-flow|{install_id}")), SecretSender::Basal.actor(),
                &[install_id.as_bytes(), version.map(|v| v.to_string()).unwrap_or_default().as_bytes(), grants.len().to_string().as_bytes()])?;
            Ok(grants.len())
        }).map_err(|_| SecretError::StoreError)
    }
}

fn flow_pending(
    tx: &rusqlite::Transaction<'_>,
    call: &SecretFlowApproval,
    asking_member: &str,
    record: &Record,
    methods: Option<&str>,
    now: i64,
) -> rusqlite::Result<Result<SecretUseOutcome, SecretError>> {
    let member = match phone::self_member(tx) {
        Ok(member) => member,
        Err(SecretError::StoreError) => return Err(rusqlite_err("member lookup failed")),
        Err(error) => return Ok(Err(error)),
    };
    // Housekeeping only: drop consumed and expired requests, and requests whose serving
    // member id is no longer this vault's. Live requests from any asker stay.
    tx.execute("DELETE FROM secret_pending_requests WHERE consumed!=0 OR request_expires_at_ms<=?1 OR member_id!=?2", rusqlite::params![now, member])?;
    // Reused only for the same asker: the same flow identity on another computer gets
    // its own approval request.
    let prior = tx.query_row("SELECT request_id,statement_bytes,request_expires_at_ms FROM secret_pending_requests WHERE request_kind='approve' AND incarnation=?1 AND flow_id=?2 AND flow_version=?3 AND flow_code_hash=?4 AND flow_install_id=?5 AND methods IS ?6 AND mapped_owner IS NULL AND mapped_kind IS NULL AND mapped_ref IS NULL AND mapped_epoch IS NULL AND coverage IS NULL AND agent_id IS NULL AND asking_member_id=?7", rusqlite::params![record.incarnation, call.flow.flow_id, call.flow.version, call.flow.code_hash, call.flow.install_id, methods, asking_member], |r| Ok((r.get::<_,String>(0)?, r.get::<_,Vec<u8>>(1)?, r.get::<_,i64>(2)?))).optional()?;
    if let Some((id, bytes, expiry)) = prior {
        return Ok(Ok(approval_reply(&id, &bytes, expiry)));
    }
    // The per-install limit counts this asker's requests only, like the agent path's
    // per-scope limit.
    let (total, install): (usize,usize) = tx.query_row("SELECT COUNT(*),COALESCE(SUM(flow_install_id=?1 AND asking_member_id=?2),0) FROM secret_pending_requests WHERE request_kind='approve' AND flow_id IS NOT NULL", rusqlite::params![call.flow.install_id, asking_member], |r| Ok((r.get(0)?, r.get(1)?)))?;
    if total >= MAX_FLOW_SECRET_PENDING_TOTAL || install >= MAX_FLOW_SECRET_PENDING_PER_INSTALL {
        return Ok(Err(SecretError::PendingLimit));
    }
    let id =
        agent_secret::request_id(now).map_err(|_| rusqlite_err("request id generation failed"))?;
    let expiry = now + FLOW_SECRET_PENDING_LIFETIME_LIMIT_MS;
    // Only a forwarded request refuses a flow id equal to a v2 tag: the local
    // sender boundary stays v1-only, so a local flow id holding a v2 tag is
    // still accepted and still encodes as a v1 statement.
    if !asking_member.is_empty() && agent_secret::flow_id_is_v2_statement_tag(&call.flow.flow_id) {
        return Ok(Err(SecretError::InvalidParams));
    }
    // A forwarded request carries the v1 object plus `asking_member_id` under a
    // v2 tag; a local one stays v1 byte for byte.
    let statement = agent_secret::flow_approval_statement_for_asker(
        &id,
        &member,
        &record.incarnation,
        &call.name,
        &call.flow,
        &record.scope,
        call.methods.as_deref(),
        expiry,
        asking_member,
    )
    .map_err(|_| rusqlite_err("statement encoding failed"))?;
    let bytes =
        serde_json::to_vec(&statement).map_err(|_| rusqlite_err("statement encoding failed"))?;
    let digest = phone::hex(&payload_hash(&bytes));
    tx.execute("INSERT INTO secret_pending_requests (request_id,request_kind,secret_name,incarnation,member_id,flow_id,flow_version,flow_code_hash,flow_install_id,methods,statement_bytes,statement_sha256,request_expires_at_ms,asking_member_id) VALUES (?1,'approve',?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)", rusqlite::params![id, call.name, record.incarnation, member, call.flow.flow_id, call.flow.version, call.flow.code_hash, call.flow.install_id, methods, bytes, digest, expiry, asking_member])?;
    Ok(Ok(approval_reply(&id, &bytes, expiry)))
}

fn choose_flow_grant(
    conn: &rusqlite::Connection,
    call: &SecretFlowUse,
    asking_member: &str,
    incarnation: &str,
) -> rusqlite::Result<Result<Grant, Refusal>> {
    let mut stmt = conn.prepare("SELECT grant_id,first_released,methods FROM secret_flow_grants WHERE secret_name=?1 AND incarnation=?2 AND flow_id=?3 AND flow_version=?4 AND flow_code_hash=?5 AND flow_install_id=?6 AND asking_member_id=?7 ORDER BY granted_at_ms,grant_id")?;
    let rows = stmt.query_map(
        rusqlite::params![
            call.name,
            incarnation,
            call.flow.flow_id,
            call.flow.version,
            call.flow.code_hash,
            call.flow.install_id,
            asking_member
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
#[cfg(test)]
mod v2_flow_tests {
    use super::super::*;
    use crate::{secret::Secret, store::taxonomy_tests::rig};
    use std::sync::Arc;

    const V2_MEMBER: &str = "fed-computer:22222222222222222222222222222222";
    const V2_ASKER: &str = "fed-computer:11111111111111111111111111111111";
    const V2_NOW: i64 = 1_700_000_000_000;

    fn v2_scope() -> agent_secret::SecretScope {
        agent_secret::SecretScope::ApiKey {
            host: "x.test".into(),
            path_prefix: Some("/repos/a".into()),
            location: "header:X-Api-Key".into(),
        }
    }

    fn v2_flow() -> agent_secret::FlowIdentity {
        agent_secret::FlowIdentity {
            flow_id: "daily-fetch".into(),
            version: 7,
            code_hash: "0123456789abcdef".repeat(4),
            install_id: "install-A".into(),
        }
    }

    fn v2_approval_call() -> agent_secret::SecretFlowApproval {
        agent_secret::SecretFlowApproval {
            name: "key".into(),
            flow: v2_flow(),
            target: agent_secret::UseTarget::ApiKey {
                scheme: "https".into(),
                host: "x.test".into(),
                port: 443,
                path: "/repos/a".into(),
            },
            methods: Some(vec!["GET".to_string()]),
        }
    }

    fn v2_setup(tag: &str) -> (crate::test_support::TestTempDir, Arc<EncryptedStore>) {
        let (root, store) = rig(tag, 66);
        store
            .set_federation_self_member_audited(
                V2_MEMBER,
                crate::audit::AuditCtx::admin(crate::audit::AuditOp::FederationSelfSet),
            )
            .unwrap();
        let incarnation = format!(
            "{:032x}",
            b"key".iter().copied().map(u64::from).sum::<u64>()
        );
        let blob = agent_secret::seal(
            &store.key,
            &incarnation,
            "key",
            &v2_scope(),
            &agent_secret::SecretMaterial::ApiKey(Secret::new(b"material-canary".to_vec())),
        )
        .unwrap();
        let scope = v2_scope();
        let (host, prefix, location, origin) = phone::columns(&scope);
        store
            .fenced_write(|tx| {
                tx.execute(
                    "INSERT INTO agent_secrets (name,kind,incarnation,state,host,path_prefix,location,origin,record_version,key_id,envelope,created_at_ms) VALUES ('key',?1,?2,'active',?3,?4,?5,?6,1,?7,?8,?9)",
                    rusqlite::params![
                        v2_scope().kind(),
                        incarnation,
                        host,
                        prefix,
                        location,
                        origin,
                        store.key_id.to_hex(),
                        blob,
                        V2_NOW
                    ],
                )
                .map(|_| ())
            })
            .unwrap();
        (root, Arc::new(store))
    }

    #[test]
    fn forwarded_flow_pending_carries_v2_statement_with_asker() {
        let (_root, store) = v2_setup("v2-flow-forwarded");
        let outcome = store
            .secret_request_flow_approval_from(&v2_approval_call(), V2_ASKER, || V2_NOW)
            .unwrap();
        assert_eq!(outcome.reply["status"], "approval_required");
        let request_id = outcome.reply["request_id"].as_str().unwrap().to_owned();
        let (bytes, asker): (Vec<u8>, String) = store
            .store
            .with_conn(|c| {
                c.query_row(
                    "SELECT statement_bytes,asking_member_id FROM secret_pending_requests WHERE request_id=?1",
                    [&request_id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
            })
            .unwrap();
        assert_eq!(asker, V2_ASKER);
        let statement: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(statement["v"], "ck-secret-flow-statement/v2");
        assert_eq!(statement["asking_member_id"], V2_ASKER);
        assert_eq!(statement["member_id"], V2_MEMBER);
        assert_eq!(serde_json::to_vec(&statement).unwrap(), bytes);
    }

    #[test]
    fn local_flow_pending_stays_v1_without_asker() {
        let (_root, store) = v2_setup("v2-flow-local");
        let outcome = store
            .secret_request_flow_approval(&v2_approval_call(), || V2_NOW)
            .unwrap();
        let request_id = outcome.reply["request_id"].as_str().unwrap().to_owned();
        let (bytes, asker): (Vec<u8>, String) = store
            .store
            .with_conn(|c| {
                c.query_row(
                    "SELECT statement_bytes,asking_member_id FROM secret_pending_requests WHERE request_id=?1",
                    [&request_id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
            })
            .unwrap();
        assert_eq!(asker, "");
        let statement: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(statement["v"], "ck-secret-flow-statement/v1");
        assert!(statement.get("asking_member_id").is_none());
    }

    #[test]
    fn only_forwarded_flow_refuses_a_v2_tag_flow_id() {
        let (_root, store) = v2_setup("v2-flow-tag");
        for tag in ["ck-secret-use-statement/v2", "ck-secret-flow-statement/v2"] {
            let mut call = v2_approval_call();
            call.flow.flow_id = tag.into();
            // Local still accepts it: the sender boundary stays v1-only.
            let local = store
                .secret_request_flow_approval(&call, || V2_NOW)
                .unwrap();
            assert_eq!(local.reply["status"], "approval_required");
            // Forwarded refuses it with invalid_params.
            assert!(matches!(
                store.secret_request_flow_approval_from(&call, V2_ASKER, || V2_NOW),
                Err(agent_secret::SecretError::InvalidParams)
            ));
        }
    }
}
