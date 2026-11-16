use super::*;
use crate::agent_secret::{
    ApprovalEnvelope, ApprovalItem, SecretError, SecretScope,
    FLOW_SECRET_PENDING_LIFETIME_LIMIT_MS, SECRET_ISSUE_SKEW_LIMIT_MS,
    SECRET_PENDING_LIFETIME_LIMIT_MS,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::{json, Value};

struct Pending {
    kind: String,
    name: String,
    incarnation: String,
    member: String,
    owner: Option<String>,
    scope_kind: Option<String>,
    scope_ref: Option<String>,
    epoch: Option<u64>,
    coverage: Option<String>,
    agent_id: Option<String>,
    bytes: Vec<u8>,
    digest: String,
    expiry: i64,
    consumed: bool,
    flow_id: Option<String>,
    flow_version: Option<u64>,
    flow_code_hash: Option<String>,
    flow_install_id: Option<String>,
    methods: Option<String>,
    /// The computer whose request this is, `''` for this vault's own. Each grant the
    /// request's approval creates records the same asker.
    asking_member: String,
    local_use: Option<String>,
}

impl EncryptedStore {
    /// The caller must enforce provider admission; this method reads metadata only.
    pub fn secret_permissions_list(
        &self,
        agent_id: Option<&str>,
        now: i64,
    ) -> Result<Value, SecretError> {
        self.store.with_conn(|conn| {
            let mut stmt = conn.prepare("SELECT g.grant_id,g.agent_id,g.scope_kind,g.scope_ref,s.name,s.kind,s.host,s.path_prefix,s.origin,g.duration,g.expires_at_ms,g.granted_at_ms,g.card_ref,s.location,s.scope_json FROM secret_grants g JOIN agent_secrets s ON s.incarnation=g.incarnation AND s.name=g.secret_name WHERE g.local_use IS NULL AND (g.duration='permanent' OR g.expires_at_ms>?1) AND (?2 IS NULL OR g.agent_id=?2) ORDER BY g.grant_id")?;
            let rows = stmt.query_map(rusqlite::params![now,agent_id],|r| {
                let name: String = r.get(4)?;
                let kind: String = r.get(5)?;
                let label = if let Some(raw) = r.get::<_,Option<String>>(14)? {
                    let location: Option<String> = r.get(13)?;
                    extended_permission_scope_label(&name, &kind, location.as_deref(), &raw)?
                } else if kind == "agent_api_key" {
                    format!("use {name} on {}{}",r.get::<_,String>(6)?,r.get::<_,Option<String>>(7)?.unwrap_or_default())
                } else {
                    format!("fill {name} on {}",r.get::<_,String>(8)?)
                };
                let scope_kind: String = r.get(2)?;
                let mut row = json!({"id":r.get::<_,String>(0)?,"holder":{"kind":if scope_kind=="head" {"agent"}else{"worker"},"scope_ref":r.get::<_,String>(3)?},"module":"claustrum","subject_label":name,"scope":if kind=="agent_api_key" {"api_key"}else{"site_login"},"scope_label":label,"granted_at_ms":r.get::<_,i64>(11)?});
                if let Some(agent) = r.get::<_,Option<String>>(1)? { row["agent_id"]=json!(agent);row["holder"]["agent_id"]=json!(agent); }
                if r.get::<_,String>(9)? != "permanent" { row["expires_at_ms"]=json!(r.get::<_,i64>(10)?); }
                if let Some(card) = r.get::<_,Option<String>>(12)? { row["card_ref"]=json!(card); }
                Ok(row)
            })?.collect::<rusqlite::Result<Vec<_>>>()?;
            let mut grants = rows;
            // Flow grants belong to an installed flow version, not to an agent, so an
            // agent-filtered listing never contains one (permissions-v1.1).
            if agent_id.is_none() {
                grants.extend(flow_permission_rows(conn)?);
                // Credential grants are appended after the secret and flow rows and
                // sorted by id among themselves, so the secret and flow rows keep the
                // order they had before credential grants were listed.
                let mut credential_rows = credential_permissions::permission_rows(conn)?;
                credential_rows.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
                grants.extend(credential_rows);
            }
            Ok(json!({"grants":grants}))
        }).map_err(|_|SecretError::StoreError)
    }

    /// Shared sink for admitted provider callers; the actor is supplied by the route boundary.
    pub fn secret_permissions_revoke(
        &self,
        id: &str,
        actor: &str,
        now: i64,
    ) -> Result<Value, SecretError> {
        self.fenced_write(|tx| revoke(tx, &self.audit_key, id, actor, now))
            .map_err(|_| SecretError::StoreError)
    }

    pub(super) fn secret_delete_request_tx(
        &self,
        tx: &rusqlite::Transaction<'_>,
        name: &str,
        now: i64,
    ) -> rusqlite::Result<Result<Value, SecretError>> {
        let member = match phone::self_member(tx) {
            Ok(m) => m,
            Err(SecretError::StoreError) => return Err(rusqlite_err("member lookup failed")),
            Err(e) => return Ok(Err(e)),
        };
        let secret: Option<(String, String)> = tx
            .query_row(
                "SELECT kind,incarnation FROM agent_secrets WHERE name=?1",
                [name],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((kind, incarnation)) = secret else {
            return Ok(Err(SecretError::NotFound));
        };
        tx.execute("DELETE FROM secret_pending_requests WHERE consumed!=0 OR request_expires_at_ms<=?1 OR member_id!=?2",rusqlite::params![now,member])?;
        let prior: Option<(String,Vec<u8>,i64)> = tx.query_row("SELECT request_id,statement_bytes,request_expires_at_ms FROM secret_pending_requests WHERE request_kind='delete' AND incarnation=?1",[&incarnation],|r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
        let (id, bytes, expiry) = if let Some(prior) = prior {
            prior
        } else {
            let id = agent_secret::request_id(now)
                .map_err(|_| rusqlite_err("request id generation failed"))?;
            let expiry = now + SECRET_PENDING_LIFETIME_LIMIT_MS;
            let statement =
                agent_secret::delete_statement(&id, &member, name, &kind, &incarnation, expiry);
            let bytes = serde_json::to_vec(&statement)
                .map_err(|_| rusqlite_err("statement encoding failed"))?;
            let digest = phone::hex(&payload_hash(&bytes));
            tx.execute("INSERT INTO secret_pending_requests (request_id,request_kind,secret_name,incarnation,member_id,statement_bytes,statement_sha256,request_expires_at_ms) VALUES (?1,'delete',?2,?3,?4,?5,?6,?7)",rusqlite::params![id,name,incarnation,member,bytes,digest,expiry])?;
            (id, bytes, expiry)
        };
        Ok(Ok(
            json!({"status":"approval_required","request_id":id,"statement_b64url":URL_SAFE_NO_PAD.encode(bytes),"expires_at_ms":expiry}),
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn secret_approval_tx(
        &self,
        tx: &rusqlite::Transaction<'_>,
        fingerprint: &str,
        public_key: &[u8],
        bytes: &[u8],
        signature: &[u8],
        card_ref: Option<&str>,
        delete: bool,
        now: i64,
    ) -> rusqlite::Result<Result<Value, SecretError>> {
        let envelope = match ApprovalEnvelope::verify(bytes, signature, public_key, fingerprint) {
            Ok(e) => e,
            Err(e) => return Ok(Err(e)),
        };
        let member = match phone::self_member(tx) {
            Ok(m) => Some(m),
            Err(SecretError::StoreError) => return Err(rusqlite_err("member lookup failed")),
            Err(_) => None,
        };
        let hash = phone::hex(&payload_hash(bytes));
        // A resend of an envelope this phone already had applied answers with the reply
        // the first call produced. Its requests are consumed by then, so re-running the
        // items would report every one as refused and hide a grant that exists. The
        // signature was verified above, so only the phone can reach a stored reply.
        tx.execute(
            "DELETE FROM secret_approval_replies WHERE expires_at_ms<=?1",
            [now],
        )?;
        let stored: Option<String> = tx
            .query_row(
                "SELECT reply FROM secret_approval_replies WHERE envelope_sha256=?1 AND fingerprint=?2 AND delete_op=?3",
                rusqlite::params![hash, fingerprint, delete],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(stored) = stored {
            return match serde_json::from_str(&stored) {
                Ok(reply) => Ok(Ok(reply)),
                Err(_) => Err(rusqlite_err("stored approval reply is unreadable")),
            };
        }
        let mut results = Vec::with_capacity(envelope.items.len());
        for item in &envelope.items {
            let local_item: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM secret_pending_requests WHERE request_id=?1 AND local_use IS NOT NULL)", [&item.request_id], |r| r.get(0))?;
            if local_item && !phone::local_programs_enabled(tx) {
                results.push(json!({"request_id":item.request_id,"outcome":"refused","code":"secret_local_programs_disabled"}));
                continue;
            }
            let accepted = self.secret_approval_item_tx(
                tx,
                item,
                &envelope,
                member.as_deref(),
                &hash,
                fingerprint,
                card_ref,
                delete,
                now,
            )?;
            results.push(if accepted {
                json!({"request_id":item.request_id,"outcome":"granted"})
            } else {
                json!({"request_id":item.request_id,"outcome":"refused","code":"approval_invalid"})
            });
        }
        let reply = json!({"results":results});
        // Stored for as long as the envelope's issue time stays inside the skew window,
        // which is the longest a resend of these bytes could still be applied.
        let expires_at_ms =
            (envelope.issued_at_ms as i64).saturating_add(SECRET_ISSUE_SKEW_LIMIT_MS);
        tx.execute(
            "INSERT INTO secret_approval_replies (envelope_sha256,fingerprint,delete_op,reply,expires_at_ms) VALUES (?1,?2,?3,?4,?5)",
            rusqlite::params![hash, fingerprint, delete, reply.to_string(), expires_at_ms],
        )?;
        Ok(Ok(reply))
    }

    #[allow(clippy::too_many_arguments)]
    fn secret_approval_item_tx(
        &self,
        tx: &rusqlite::Transaction<'_>,
        item: &ApprovalItem,
        e: &ApprovalEnvelope,
        member: Option<&str>,
        envelope_hash: &str,
        fingerprint: &str,
        card_ref: Option<&str>,
        delete: bool,
        now: i64,
    ) -> rusqlite::Result<bool> {
        let pending = tx.query_row("SELECT request_kind,secret_name,incarnation,member_id,mapped_owner,mapped_kind,mapped_ref,mapped_epoch,coverage,agent_id,statement_bytes,statement_sha256,request_expires_at_ms,consumed,flow_id,flow_version,flow_code_hash,flow_install_id,methods,asking_member_id,local_use FROM secret_pending_requests WHERE request_id=?1",[&item.request_id],|r| Ok(Pending {kind:r.get(0)?,name:r.get(1)?,incarnation:r.get(2)?,member:r.get(3)?,owner:r.get(4)?,scope_kind:r.get(5)?,scope_ref:r.get(6)?,epoch:r.get(7)?,coverage:r.get(8)?,agent_id:r.get(9)?,bytes:r.get(10)?,digest:r.get(11)?,expiry:r.get(12)?,consumed:r.get(13)?,flow_id:r.get(14)?,flow_version:r.get(15)?,flow_code_hash:r.get(16)?,flow_install_id:r.get(17)?,methods:r.get(18)?,asking_member:r.get(19)?,local_use:r.get(20)?})).optional()?;
        let Some(p) = pending else {
            return Ok(false);
        };
        let issued = e.issued_at_ms as i64;
        let pending_lifetime = if p.flow_id.is_some() {
            FLOW_SECRET_PENDING_LIFETIME_LIMIT_MS
        } else {
            SECRET_PENDING_LIFETIME_LIMIT_MS
        };
        let statement: Value = match serde_json::from_slice(&p.bytes) {
            Ok(v) => v,
            Err(_) => return Ok(false),
        };
        if p.consumed
            || now >= p.expiry
            || p.digest != item.statement_sha256
            || phone::hex(&payload_hash(&p.bytes)) != p.digest
            || issued < p.expiry - pending_lifetime
            || issued >= p.expiry
            || now.abs_diff(issued) > SECRET_ISSUE_SKEW_LIMIT_MS as u64
            || member != Some(p.member.as_str())
            || statement["member_id"] != p.member
            || statement["request_id"] != item.request_id
            || statement["request_expires_at_ms"] != p.expiry
            || (p.local_use.is_none()
                && (statement["secret"]["name"] != p.name
                    || statement["secret"]["incarnation"] != p.incarnation))
            || p.kind != if delete { "delete" } else { "approve" }
            || e.decision != if delete { "delete" } else { "allow" }
        {
            return Ok(false);
        }
        // The statement names an asker exactly when the pending request was forwarded.
        // Each branch below checks its exact version after loading the secret's scope.
        {
            let asker_ok = if p.asking_member.is_empty() {
                statement.get("asking_member_id").is_none()
            } else {
                statement.get("asking_member_id").and_then(|v| v.as_str())
                    == Some(p.asking_member.as_str())
            };
            if !asker_ok {
                return Ok(false);
            }
        }
        let expected_expiry = match e.duration.as_str() {
            "once" => issued.checked_add(600_000),
            "hour" => issued.checked_add(3_600_000),
            "session" => issued.checked_add(86_400_000),
            "permanent" | "version" => Some(0),
            "none" if delete => Some(p.expiry),
            _ => None,
        };
        if expected_expiry != Some(e.grant_expires_at_ms as i64) {
            return Ok(false);
        }
        if p.local_use.is_some() {
            return self.secret_local_approval_item_tx(
                tx,
                item,
                e,
                &p,
                &statement,
                fingerprint,
                envelope_hash,
                card_ref,
                now,
            );
        }
        let row = tx.query_row("SELECT kind,state,host,path_prefix,location,origin,envelope,scope_json FROM agent_secrets WHERE name=?1 AND incarnation=?2",rusqlite::params![p.name,p.incarnation], |r| Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,Option<String>>(2)?,r.get::<_,Option<String>>(3)?,r.get::<_,Option<String>>(4)?,r.get::<_,Option<String>>(5)?,r.get::<_,Vec<u8>>(6)?,r.get::<_,Option<String>>(7)?))).optional()?;
        let Some((kind, state, host, path_prefix, location, origin, blob, scope_json)) = row else {
            return Ok(false);
        };
        let actor = format!("fed-phone:{fingerprint}");
        if delete {
            if e.duration != "none"
                || statement["v"] != "ck-secret-delete-statement/v1"
                || statement.get("asking_member_id").is_some()
            {
                return Ok(false);
            }
            for table in [
                "secret_grants",
                "secret_flow_grants",
                "secret_pending_requests",
            ] {
                tx.execute(
                    &format!("DELETE FROM {table} WHERE incarnation=?1"),
                    [&p.incarnation],
                )?;
            }
            tx.execute(
                "DELETE FROM agent_secrets WHERE incarnation=?1",
                [&p.incarnation],
            )?;
            tx.execute(
                "DELETE FROM auth_events WHERE credential_id=?1",
                [format!("secret|{}", p.name)],
            )?;
            envelope_audit(
                tx,
                &self.audit_key,
                AuditOp::SecretDelete,
                &p.name,
                &actor,
                envelope_hash,
            )?;
            return Ok(true);
        }
        if state != "active"
            || !statement["durations"]
                .as_array()
                .is_some_and(|d| d.iter().any(|v| v == &e.duration))
        {
            return Ok(false);
        }
        let flow_item = p.flow_id.is_some()
            || p.flow_version.is_some()
            || p.flow_code_hash.is_some()
            || p.flow_install_id.is_some()
            || p.methods.is_some();
        if !flow_item
            && (e.duration == "version"
                || statement["v"]
                    != if scope_json.is_some() {
                        agent_secret::USE_STATEMENT_V3
                    } else if p.asking_member.is_empty() {
                        "ck-secret-use-statement/v1"
                    } else {
                        "ck-secret-use-statement/v2"
                    }
                || statement["scope"]
                    != json!({"owner":p.owner,"kind":p.scope_kind,"ref":p.scope_ref,"epoch":p.epoch})
                || statement["coverage"] != json!(p.coverage)
                || !matches!(p.scope_kind.as_deref(), Some("head" | "worker"))
                || !matches!(p.coverage.as_deref(), Some("scope" | "agent_and_workers"))
                || (p.coverage.as_deref() == Some("agent_and_workers")
                    && (e.duration != "permanent" || p.scope_kind.as_deref() != Some("head"))))
        {
            return Ok(false);
        }
        let scope = match agent_secret::SecretScope::from_columns(
            &kind,
            host.as_deref(),
            path_prefix.as_deref(),
            location.as_deref(),
            origin.as_deref(),
            scope_json.as_deref(),
        ) {
            Ok(scope) => scope,
            Err(_) => {
                self.approval_quarantine(tx, &p)?;
                return Ok(false);
            }
        };
        if agent_secret::open(&self.key, &p.incarnation, &p.name, &scope, &blob).is_err() {
            self.approval_quarantine(tx, &p)?;
            return Ok(false);
        }
        if flow_item {
            return self.secret_flow_approval_item_tx(
                tx,
                item,
                e,
                &p,
                &scope,
                &actor,
                envelope_hash,
                card_ref,
                now,
            );
        }
        let sealed_use = scope.use_fields();
        if statement["secret"]["kind"] != scope.kind() || statement["use"] != sealed_use {
            return Ok(false);
        }
        let id = agent_secret::request_id(now)
            .map_err(|_| rusqlite_err("grant id generation failed"))?;
        tx.execute(
            "UPDATE secret_pending_requests SET consumed=1 WHERE request_id=?1",
            [&item.request_id],
        )?;
        tx.execute("INSERT INTO secret_grants (grant_id,secret_name,incarnation,scope_owner,scope_kind,scope_ref,coverage,duration,expires_at_ms,granted_at_ms,envelope_sha256,agent_id,card_ref,asking_member_id) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",rusqlite::params![id,p.name,p.incarnation,p.owner,p.scope_kind,p.scope_ref,p.coverage,e.duration,e.grant_expires_at_ms,now,envelope_hash,p.agent_id,card_ref,p.asking_member])?;
        envelope_audit(
            tx,
            &self.audit_key,
            AuditOp::SecretGrantCreate,
            &p.name,
            &actor,
            envelope_hash,
        )?;
        Ok(true)
    }

    #[allow(clippy::too_many_arguments)]
    fn secret_local_approval_item_tx(
        &self,
        tx: &rusqlite::Transaction<'_>,
        item: &ApprovalItem,
        e: &ApprovalEnvelope,
        p: &Pending,
        statement: &Value,
        fingerprint: &str,
        envelope_hash: &str,
        card_ref: Option<&str>,
        now: i64,
    ) -> rusqlite::Result<bool> {
        if !phone::local_programs_enabled(tx)
            || e.decision != "allow"
            || p.coverage.as_deref() != Some("scope")
            || !matches!(p.scope_kind.as_deref(), Some("head" | "worker"))
            || p.flow_id.is_some()
        {
            return Ok(false);
        }
        let mut members: Value =
            match serde_json::from_str(p.local_use.as_deref().expect("local pending")) {
                Ok(v) => v,
                Err(_) => return Ok(false),
            };
        let saved_key = members.as_object_mut().and_then(|v| v.remove("key"));
        let local = match agent_secret::LocalUse::from_value(&members) {
            Ok(v) => v,
            Err(_) => return Ok(false),
        };
        if !local.durations().contains(&e.duration.as_str()) {
            return Ok(false);
        }
        let (Some(owner), Some(kind), Some(scope_ref), Some(epoch)) =
            (&p.owner, &p.scope_kind, &p.scope_ref, p.epoch)
        else {
            return Ok(false);
        };
        let call = agent_secret::SecretUse {
            name: p.name.clone(),
            sender: agent_secret::SecretSender::Aft,
            scope: agent_secret::AskingScope {
                owner: owner.clone(),
                kind: kind.clone(),
                scope_ref: scope_ref.clone(),
                epoch,
            },
            worker_parent: None,
            coverage: "scope".into(),
            agent_id: p.agent_id.clone(),
            target: agent_secret::UseTarget::LocalProgram(local.clone()),
        };
        let key_fp = if local.is_ssh() {
            let Some(record) = self.enrolled_ssh(tx, &p.name, &local, None)? else {
                return Ok(false);
            };
            if record.incarnation != p.incarnation
                || saved_key
                    != Some(json!({"credential_id":p.name,"fingerprint":record.fingerprint}))
            {
                return Ok(false);
            }
            Some(record.fingerprint)
        } else {
            if saved_key.is_some() {
                return Ok(false);
            }
            let record = match self.check_secret_use(tx, &call)? {
                Ok(r) => r,
                Err(_) => return Ok(false),
            };
            if record.incarnation != p.incarnation {
                return Ok(false);
            }
            None
        };
        let expected = match agent_secret::local_approval_statement(
            &item.request_id,
            &p.member,
            &p.incarnation,
            &call,
            &local,
            key_fp.as_deref(),
            p.expiry,
            &p.asking_member,
        ) {
            Ok(statement) => statement,
            Err(_) => return Ok(false),
        };
        if *statement != expected {
            return Ok(false);
        }
        let mut granted = if e.duration == "once" {
            local.members()
        } else {
            local.triple()
        };
        if let Some(fp) = key_fp {
            granted["key"] = json!({"credential_id":p.name,"fingerprint":fp});
        }
        let id = agent_secret::request_id(now)
            .map_err(|_| rusqlite_err("grant id generation failed"))?;
        tx.execute(
            "UPDATE secret_pending_requests SET consumed=1 WHERE request_id=?1",
            [&item.request_id],
        )?;
        tx.execute("INSERT INTO secret_grants (grant_id,secret_name,incarnation,scope_owner,scope_kind,scope_ref,coverage,duration,expires_at_ms,granted_at_ms,envelope_sha256,agent_id,card_ref,asking_member_id,local_use) VALUES (?1,?2,?3,?4,?5,?6,'scope',?7,?8,?9,?10,?11,?12,?13,?14)", rusqlite::params![id,p.name,p.incarnation,p.owner,p.scope_kind,p.scope_ref,e.duration,e.grant_expires_at_ms,now,envelope_hash,p.agent_id,card_ref,p.asking_member,granted.to_string()])?;
        envelope_audit(
            tx,
            &self.audit_key,
            AuditOp::SecretGrantCreate,
            &p.name,
            &format!("fed-phone:{fingerprint}"),
            envelope_hash,
        )?;
        Ok(true)
    }

    #[allow(clippy::too_many_arguments)]
    fn secret_flow_approval_item_tx(
        &self,
        tx: &rusqlite::Transaction<'_>,
        item: &ApprovalItem,
        e: &ApprovalEnvelope,
        p: &Pending,
        scope: &agent_secret::SecretScope,
        actor: &str,
        envelope_hash: &str,
        card_ref: Option<&str>,
        now: i64,
    ) -> rusqlite::Result<bool> {
        if e.duration != "version"
            || p.owner.is_some()
            || p.scope_kind.is_some()
            || p.scope_ref.is_some()
            || p.epoch.is_some()
            || p.coverage.is_some()
            || p.agent_id.is_some()
        {
            return Ok(false);
        }
        let (Some(flow_id), Some(version), Some(code_hash), Some(install_id)) = (
            &p.flow_id,
            p.flow_version,
            &p.flow_code_hash,
            &p.flow_install_id,
        ) else {
            return Ok(false);
        };
        let flow = agent_secret::FlowIdentity {
            flow_id: flow_id.clone(),
            version,
            code_hash: code_hash.clone(),
            install_id: install_id.clone(),
        };
        // Extended statements reserve both v3 tags. Forwarded requests also retain
        // the v2 reservations; local requests may still use a v2 tag as their flow id.
        if (scope.is_extended() && agent_secret::flow_id_is_v3_statement_tag(&flow.flow_id))
            || (!p.asking_member.is_empty()
                && agent_secret::flow_id_is_v2_statement_tag(&flow.flow_id))
        {
            return Ok(false);
        }
        let methods: Option<Vec<String>> =
            match p.methods.as_deref().map(serde_json::from_str).transpose() {
                Ok(methods) => methods,
                Err(_) => return Ok(false),
            };
        if let Some(methods) = &methods {
            if agent_secret::sorted_flow_methods(methods).as_ref() != Ok(methods) {
                return Ok(false);
            }
        }
        let expected = match agent_secret::flow_approval_statement_for_asker(
            &item.request_id,
            &p.member,
            &p.incarnation,
            &p.name,
            &flow,
            scope,
            methods.as_deref(),
            p.expiry,
            &p.asking_member,
        ) {
            Ok(statement) => statement,
            Err(_) => return Ok(false),
        };
        // Rebuild from the pending identity and sealed secret scope, never from signed claims.
        if serde_json::to_vec(&expected).ok().as_deref() != Some(p.bytes.as_slice()) {
            return Ok(false);
        }
        let id = agent_secret::request_id(now)
            .map_err(|_| rusqlite_err("grant id generation failed"))?;
        tx.execute(
            "UPDATE secret_pending_requests SET consumed=1 WHERE request_id=?1",
            [&item.request_id],
        )?;
        tx.execute("INSERT INTO secret_flow_grants (grant_id,secret_name,incarnation,flow_id,flow_version,flow_code_hash,flow_install_id,methods,granted_at_ms,envelope_sha256,card_ref,asking_member_id) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",rusqlite::params![id,p.name,p.incarnation,flow.flow_id,flow.version,flow.code_hash,flow.install_id,p.methods,now,envelope_hash,card_ref,p.asking_member])?;
        envelope_audit(
            tx,
            &self.audit_key,
            AuditOp::SecretGrantCreate,
            &p.name,
            actor,
            envelope_hash,
        )?;
        Ok(true)
    }

    fn approval_quarantine(
        &self,
        tx: &rusqlite::Transaction<'_>,
        p: &Pending,
    ) -> rusqlite::Result<()> {
        // A failed quarantine audit must undo only the flip, not change an item's opaque refusal.
        tx.execute_batch("SAVEPOINT secret_quarantine")?;
        let result = (|| {
            tx.execute(
                "UPDATE agent_secrets SET state='corrupt' WHERE incarnation=?1 AND state='active'",
                [&p.incarnation],
            )?;
            phone::audit(
                tx,
                &self.audit_key,
                AuditOp::SecretQuarantine,
                Some(format!("secret|{}", p.name)),
                "vault",
                &[p.incarnation.as_bytes()],
            )
        })();
        if result.is_err() {
            tx.execute_batch("ROLLBACK TO secret_quarantine")?;
        }
        tx.execute_batch("RELEASE secret_quarantine")
    }
}

fn envelope_audit(
    tx: &rusqlite::Transaction<'_>,
    key: &[u8; 32],
    op: AuditOp,
    name: &str,
    actor: &str,
    hash: &str,
) -> rusqlite::Result<()> {
    append_audit_tx(
        tx,
        key,
        &AuditRecord {
            op,
            credential_id: Some(use_secret::secret_subject(name)),
            payload_hash: Some(hash.to_owned()),
            actor: actor.to_owned(),
            alarm: None,
        },
    )
    .map(|_| ())
}

fn extended_permission_scope_label(
    name: &str,
    kind: &str,
    location: Option<&str>,
    raw: &str,
) -> rusqlite::Result<String> {
    let scope = SecretScope::from_scope_json(kind, location, raw)
        .map_err(|_| rusqlite_err("invalid stored secret scope"))?;
    match scope {
        SecretScope::ApiKeyRules { rules, .. } => {
            let targets = rules
                .iter()
                .map(|rule| format!("{}{}", rule.host, rule.path_prefix.as_deref().unwrap_or("")))
                .collect::<Vec<_>>()
                .join(", ");
            Ok(format!("use {name} on {targets}"))
        }
        SecretScope::SiteLoginOrigins { origins } => {
            Ok(format!("fill {name} on {}", origins.join(", ")))
        }
        _ => Err(rusqlite_err("expected extended secret scope")),
    }
}

/// One `permissions.list` row per live flow grant.
///
/// A flow grant has no wall-clock expiry and no agent, so it carries no `expires_at_ms`
/// and no `agent_id`. Its holder is the installed flow version that owns it, which the
/// phone and desktop permission pages render from these three fields plus the secret's
/// name and kind. `methods` describes how an API key may be used, so a site login, which
/// has no method at all, omits the key rather than sending an empty list.
fn flow_permission_rows(conn: &rusqlite::Connection) -> rusqlite::Result<Vec<Value>> {
    conn.prepare("SELECT g.grant_id,g.flow_id,g.flow_version,g.flow_install_id,s.name,s.kind,s.host,s.path_prefix,COALESCE(s.origin,''),g.methods,g.granted_at_ms,g.card_ref,s.location,s.scope_json FROM secret_flow_grants g JOIN agent_secrets s ON s.incarnation=g.incarnation AND s.name=g.secret_name ORDER BY g.grant_id")?
        .query_map([], |r| {
            let name: String = r.get(4)?;
            let kind: String = r.get(5)?;
            let api_key = kind == "agent_api_key";
            let label = if let Some(raw) = r.get::<_,Option<String>>(13)? {
                let location: Option<String> = r.get(12)?;
                extended_permission_scope_label(&name, &kind, location.as_deref(), &raw)?
            } else if api_key {
                format!("use {name} on {}{}", r.get::<_,String>(6)?, r.get::<_,Option<String>>(7)?.unwrap_or_default())
            } else {
                format!("fill {name} on {}", r.get::<_,String>(8)?)
            };
            let version: u64 = r.get(2)?;
            let mut row = json!({
                "id":r.get::<_,String>(0)?,
                "holder":{"kind":"flow", "flow_id":r.get::<_,String>(1)?, "flow_version":version, "flow_install_id":r.get::<_,String>(3)?},
                "module":"claustrum",
                "subject_label":name,
                "scope":if api_key {"api_key"} else {"site_login"},
                "scope_label":label,
                "granted_at_ms":r.get::<_,i64>(10)?,
            });
            if api_key {
                let methods: Option<String> = r.get(9)?;
                match methods {
                    Some(methods) => {
                        row["methods"] = serde_json::from_str(&methods).map_err(|e| {
                            rusqlite::Error::FromSqlConversionFailure(9, rusqlite::types::Type::Text, Box::new(e))
                        })?;
                    }
                    // A stored API-key grant always records the methods it was approved
                    // for; a missing list cannot be shown as "any method", so it is an error.
                    None => return Err(rusqlite_err("api key flow grant without methods")),
                }
            }
            if let Some(card) = r.get::<_,Option<String>>(11)? {
                row["card_ref"] = json!(card);
            }
            Ok(row)
        })?
        .collect()
}

pub(super) fn revoke(
    tx: &rusqlite::Transaction<'_>,
    key: &[u8; 32],
    id: &str,
    actor: &str,
    now: i64,
) -> rusqlite::Result<Value> {
    let row: Option<(String,String)> = tx.query_row("SELECT secret_name,incarnation FROM secret_grants WHERE grant_id=?1 AND (duration='permanent' OR expires_at_ms>?2)",rusqlite::params![id,now],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
    let Some((name, incarnation)) = row else {
        let flow: Option<(String, String, String, u64)> = tx
            .query_row(
                "SELECT secret_name,incarnation,flow_id,flow_version FROM secret_flow_grants WHERE grant_id=?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;
        let Some((name, incarnation, flow_id, flow_version)) = flow else {
            return credential_permissions::revoke(tx, key, id, actor);
        };
        let flow_version = flow_version.to_string();
        tx.execute("DELETE FROM secret_flow_grants WHERE grant_id=?1", [id])?;
        phone::audit(
            tx,
            key,
            AuditOp::SecretGrantRevoke,
            Some(use_secret::secret_subject(&name)),
            actor,
            &[
                id.as_bytes(),
                incarnation.as_bytes(),
                flow_id.as_bytes(),
                flow_version.as_bytes(),
            ],
        )?;
        return Ok(json!({"outcome":"revoked"}));
    };
    tx.execute("DELETE FROM secret_grants WHERE grant_id=?1", [id])?;
    phone::audit(
        tx,
        key,
        AuditOp::SecretGrantRevoke,
        Some(use_secret::secret_subject(&name)),
        actor,
        &[id.as_bytes(), incarnation.as_bytes()],
    )?;
    Ok(json!({"outcome":"revoked"}))
}
#[cfg(test)]
mod v2_approval_tests {
    use super::*;
    use crate::{secret::Secret, store::taxonomy_tests::rig};
    use p256::ecdsa::{signature::Signer, SigningKey};
    use std::sync::Arc;

    mod local_use_tests {
        use super::*;
        use agent_secret::{LocalUse, SecretSshSign, SshUserauth, UseTarget};
        const KEY: &str = "signing:local-login";

        fn setup(tag: &str) -> (crate::test_support::TestTempDir, Arc<EncryptedStore>) {
            let (root, store) = v2_setup(tag);
            store
                .set_secret_local_programs_audited(
                    true,
                    AuditCtx::admin(AuditOp::SecretLocalProgramsSet),
                )
                .unwrap();
            let scope = SecretScope::from_input(
                "local_program",
                &json!({"program":"sudo","use":"sudo_password","targets":[{"user":"root"}]}),
                None,
            )
            .unwrap();
            let incarnation = "000000000000000000000000000000ab";
            let blob = agent_secret::seal(
                &store.key,
                incarnation,
                "sudo-pw",
                &scope,
                &agent_secret::SecretMaterial::LocalProgram(Secret::new("pässwörd".into())),
            )
            .unwrap();
            store.fenced_write(|tx| tx.execute("INSERT INTO agent_secrets (name,kind,incarnation,state,record_version,key_id,envelope,created_at_ms,scope_json) VALUES ('sudo-pw','local_program',?1,'active',1,?2,?3,?4,?5)", rusqlite::params![incarnation,store.key_id.to_hex(),blob,V2_NOW,scope.scope_json().unwrap()]).map(|_| ())).unwrap();
            let der =
                ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
                    .unwrap();
            let pem = format!(
                "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
                base64::engine::general_purpose::STANDARD.encode(der.as_ref())
            );
            store
                .create(
                    KEY,
                    &VaultRecord::new_static(
                        CredentialKind::SigningKey,
                        "test",
                        pem.into_bytes(),
                        None,
                    ),
                )
                .unwrap();
            allow(&store);
            (root, store)
        }

        fn allow(store: &EncryptedStore) {
            store
                .set_agent_ssh_audited(
                    KEY,
                    Some(crate::record::AgentSsh {
                        targets: vec![crate::record::AgentSshTarget {
                            user: None,
                            host: "ssh.test".into(),
                            port: None,
                        }],
                    }),
                    "admin",
                )
                .unwrap();
        }

        fn sudo(command: &str) -> agent_secret::SecretUse {
            let mut call = v2_call();
            call.name = "sudo-pw".into();
            call.target = UseTarget::LocalProgram(LocalUse::from_value(&json!({"program":"sudo","use":"sudo_password","target":{"user":"root"},"command":command,"workdir":"/home/u","purpose":"update","expects":"password prompt","undoable":"no"})).unwrap());
            call
        }

        fn ssh(
            store: &EncryptedStore,
            command: &str,
            user: &str,
            host: &str,
            port: u16,
        ) -> SecretSshSign {
            let public = crate::signing::public_key_ed25519(
                std::str::from_utf8(store.get(KEY).unwrap().payload.expose()).unwrap(),
            )
            .unwrap();
            let mut blob = b"\0\0\0\x0bssh-ed25519\0\0\0\x20".to_vec();
            for pair in public.public_key_hex.as_bytes().as_chunks::<2>().0 {
                blob.push(u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap());
            }
            fn push(out: &mut Vec<u8>, b: &[u8]) {
                out.extend_from_slice(&(b.len() as u32).to_be_bytes());
                out.extend_from_slice(b);
            }
            let mut data = vec![];
            push(&mut data, b"session");
            data.push(50);
            for b in [user.as_bytes(), b"ssh-connection", b"publickey"] {
                push(&mut data, b);
            }
            data.push(1);
            push(&mut data, b"ssh-ed25519");
            push(&mut data, &blob);
            let call = v2_call();
            SecretSshSign { key:KEY.into(), sender:agent_secret::SecretSender::Aft, scope:call.scope, worker_parent:None, coverage:"scope".into(), agent_id:call.agent_id, local_use:LocalUse::from_value(&json!({"program":"ssh","use":"ssh_sign","target":{"user":user,"host":host,"port":port},"command":command,"workdir":"/home/u","purpose":"login"})).unwrap(), data:SshUserauth::parse(data).unwrap() }
        }

        fn count(store: &EncryptedStore, query: &str) -> i64 {
            store
                .store
                .with_conn(|c| c.query_row(query, [], |r| r.get(0)))
                .unwrap()
        }
        fn request(store: &EncryptedStore, call: &SecretSshSign) -> Value {
            store.secret_ssh_sign(call, || V2_NOW).unwrap().reply
        }
        fn signed_envelope(requests: &[Value], duration: &str) -> (Vec<u8>, Vec<u8>) {
            let envelope = v2_envelope(requests.iter().map(v2_item).collect(), duration, V2_NOW);
            let bytes = serde_json::to_vec(&envelope).unwrap();
            let sig: p256::ecdsa::Signature = v2_signer().sign(&bytes);
            (bytes, sig.to_der().as_bytes().to_vec())
        }
        fn submit(store: &EncryptedStore, bytes: Vec<u8>, signature: Vec<u8>) -> Value {
            store
                .secret_phone_operation(
                    V2_FP,
                    Some("pair-A"),
                    V2_NOW,
                    &crate::store::store_agent_secrets::PhoneOperation::Approve {
                        envelope: bytes,
                        signature,
                        card_ref: Some("local-card".into()),
                    },
                    || true,
                    || V2_NOW,
                )
                .unwrap()
        }

        #[test]
        fn sudo_cards_bind_full_members_and_release_once_with_audit() {
            let (_root, store) = setup("local-sudo-cards");
            let a = store
                .secret_use(&sudo("apt upgrade"), || V2_NOW)
                .unwrap()
                .reply;
            assert_eq!(
                store
                    .secret_use(&sudo("apt upgrade"), || V2_NOW)
                    .unwrap()
                    .reply,
                a
            );
            let b = store
                .secret_use(&sudo("apt remove"), || V2_NOW)
                .unwrap()
                .reply;
            assert_ne!(a["request_id"], b["request_id"]);
            assert_eq!(
                v2_approve(&store, &a, "hour")["results"][0]["code"],
                "approval_invalid"
            );
            assert_eq!(
                v2_approve(&store, &a, "once")["results"][0]["outcome"],
                "granted"
            );
            assert_eq!(
                store
                    .secret_use(&sudo("apt remove"), || V2_NOW)
                    .unwrap()
                    .reply,
                b
            );
            let outcome = store.secret_use(&sudo("apt upgrade"), || V2_NOW).unwrap();
            assert!(outcome.last_use.is_none());
            assert_eq!(
                outcome.reply,
                json!({"status":"released","kind":"local_program","use":"sudo_password","value":"pässwörd"})
            );
            let fresh = store
                .secret_use(&sudo("apt upgrade"), || V2_NOW)
                .unwrap()
                .reply;
            assert_eq!(fresh["status"], "approval_required");
            assert_ne!(fresh["request_id"], a["request_id"]);
            assert_eq!(count(&store, "SELECT count(*) FROM audit_log WHERE op='secret_local_release' AND credential_id='secret|sudo-pw'"), 1);
            assert_eq!(count(&store, "SELECT count(*) FROM audit_log WHERE op='secret_first_release' AND credential_id='secret|sudo-pw'"), 0);
            assert_eq!(
                store.secret_permissions_list(None, V2_NOW).unwrap()["grants"],
                json!([])
            );
        }

        #[test]
        fn ssh_once_binds_members_and_remembered_grants_bind_triple_and_asker() {
            for duration in ["once", "hour", "session"] {
                let (_root, store) = setup(&format!("local-ssh-{duration}"));
                let call = ssh(&store, "ssh first", "u", "ssh.test", 22);
                let pending = request(&store, &call);
                assert_eq!(
                    v2_approve(&store, &pending, duration)["results"][0]["outcome"],
                    "granted"
                );
                let changed = ssh(&store, "ssh changed", "u", "ssh.test", 22);
                let changed_reply = request(&store, &changed);
                if duration == "once" {
                    assert_eq!(changed_reply["status"], "approval_required");
                } else {
                    assert_eq!(changed_reply["status"], "signed");
                }
                let signed = request(&store, &call);
                assert_eq!(signed["status"], "signed");
                let signature = URL_SAFE_NO_PAD
                    .decode(signed["signature_b64url"].as_str().unwrap())
                    .unwrap();
                assert_eq!(signature.len(), 64);
                ring::signature::UnparsedPublicKey::new(
                    &ring::signature::ED25519,
                    &call.data.public_key()[19..],
                )
                .verify(call.data.as_bytes(), &signature)
                .unwrap();
                assert_eq!(
                    request(&store, &ssh(&store, "ssh first", "other", "ssh.test", 22))["status"],
                    "approval_required"
                );
                assert_eq!(
                    request(&store, &ssh(&store, "ssh first", "u", "ssh.test", 23))["status"],
                    "approval_required"
                );
                assert_eq!(
                    store
                        .secret_ssh_sign_from(&call, V2_ASKER, || V2_NOW)
                        .unwrap()
                        .reply["status"],
                    "approval_required"
                );
                assert_eq!(
                    count(
                        &store,
                        "SELECT count(*) FROM audit_log WHERE op='secret_ssh_sign'"
                    ),
                    if duration == "once" { 1 } else { 2 }
                );
                assert_eq!(count(&store, "SELECT count(*) FROM audit_log WHERE op='secret_grant_create' AND credential_id='signing:local-login'"), 1);
                assert_eq!(
                    store.secret_permissions_list(None, V2_NOW).unwrap()["grants"],
                    json!([])
                );
                let raw: String = store
                    .store
                    .with_conn(|c| {
                        c.query_row(
                            "SELECT local_use FROM secret_grants WHERE secret_name=?1",
                            [KEY],
                            |r| r.get(0),
                        )
                    })
                    .unwrap_or_default();
                if duration != "once" {
                    let value: Value = serde_json::from_str(&raw).unwrap();
                    assert!(value.get("command").is_none());
                    assert_eq!(value["key"]["credential_id"], KEY);
                }
            }
        }

        #[test]
        fn ssh_approval_after_deny_is_refused_without_grant() {
            let (_root, store) = setup("local-ssh-approve-denied");
            let pending = request(&store, &ssh(&store, "ssh", "u", "ssh.test", 22));
            let (bytes, signature) = signed_envelope(&[pending], "once");
            store.set_agent_ssh_audited(KEY, None, "admin").unwrap();
            let reply = submit(&store, bytes, signature);
            assert_eq!(reply["results"][0]["outcome"], "refused");
            assert_eq!(reply["results"][0]["code"], "approval_invalid");
            assert_eq!(count(&store, "SELECT count(*) FROM secret_grants"), 0);
            assert_eq!(
                count(
                    &store,
                    "SELECT count(*) FROM audit_log WHERE op='secret_grant_create'"
                ),
                0
            );
        }

        #[test]
        fn local_ssh_signature_verifies_under_node_and_tampering_fails() {
            let (_root, store) = setup("local-ssh-node-verify");
            let call = ssh(&store, "ssh", "u", "ssh.test", 22);
            let pending = request(&store, &call);
            assert_eq!(
                v2_approve(&store, &pending, "once")["results"][0]["outcome"],
                "granted"
            );
            let signed = request(&store, &call);
            let script = r#"
const {createPublicKey, verify} = require('node:crypto');
const input = JSON.parse(process.argv[1]);
const raw = Buffer.from(input.public_key, 'base64url');
const spki = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), raw]);
const key = createPublicKey({key: spki, format: 'der', type: 'spki'});
const data = Buffer.from(input.data, 'base64url');
const signature = Buffer.from(input.signature, 'base64url');
if (!verify(null, data, key, signature)) throw new Error('vault signature did not verify');
data[0] ^= 1;
if (verify(null, data, key, signature)) throw new Error('tampered userauth verified');
console.log('2 Node Ed25519 verification checks passed');
"#;
            let input = json!({"public_key":URL_SAFE_NO_PAD.encode(&call.data.public_key()[19..]),"data":URL_SAFE_NO_PAD.encode(call.data.as_bytes()),"signature":signed["signature_b64url"]});
            let result = std::process::Command::new("node")
                .args(["-e", script, &input.to_string()])
                .output()
                .expect("Node is required for independent SSH-signature verification");
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            assert_eq!(
                String::from_utf8(result.stdout).unwrap().trim(),
                "2 Node Ed25519 verification checks passed"
            );
        }

        #[test]
        fn mixed_approval_while_off_refuses_only_local_item_and_replays_reply() {
            let (_root, store) = setup("local-approval-off");
            let https = store.secret_use(&v2_call(), || V2_NOW).unwrap().reply;
            let local = store
                .secret_use(&sudo("apt upgrade"), || V2_NOW)
                .unwrap()
                .reply;
            let (bytes, sig) = signed_envelope(&[https, local], "once");
            store
                .set_secret_local_programs_audited(
                    false,
                    AuditCtx::admin(AuditOp::SecretLocalProgramsSet),
                )
                .unwrap();
            let reply = submit(&store, bytes.clone(), sig.clone());
            assert_eq!(reply["results"][0]["outcome"], "granted");
            assert_eq!(
                reply["results"][1]["code"],
                "secret_local_programs_disabled"
            );
            assert_eq!(
                count(
                    &store,
                    "SELECT count(*) FROM secret_grants WHERE secret_name='sudo-pw'"
                ),
                0
            );
            assert_eq!(submit(&store, bytes, sig), reply);
            assert!(matches!(
                store.secret_use(&sudo("apt upgrade"), || V2_NOW),
                Err(SecretError::SecretLocalProgramsDisabled)
            ));
        }

        #[test]
        fn lost_once_signature_after_deny_and_reallow_cannot_consume_new_grant() {
            let (_root, store) = setup("local-ssh-lost-once");
            let call = ssh(&store, "ssh", "u", "ssh.test", 22);
            let aad = b"authenticated-signature-aad";
            let receipt = use_secret::ReleaseRequest {
                requester: V2_ASKER,
                nonce: "0123456789abcdef0123456789abcdef",
                aad,
            };
            let seal = |v: &Value| {
                Ok::<_, ()>(use_secret::SealedRelease {
                    enc: vec![1],
                    ciphertext: serde_json::to_vec(v).unwrap(),
                })
            };
            let pending = store
                .secret_ssh_sign_from(&call, V2_ASKER, || V2_NOW)
                .unwrap()
                .reply;
            v2_approve(&store, &pending, "once");
            let first = store
                .secret_ssh_sign_sealed(&call, &receipt, seal, || V2_NOW)
                .unwrap()
                .unwrap();
            assert_eq!(
                store
                    .secret_ssh_sign_sealed(
                        &call,
                        &receipt,
                        |_| -> Result<_, ()> { panic!("retry must replay") },
                        || V2_NOW
                    )
                    .unwrap()
                    .unwrap(),
                first
            );
            store.set_agent_ssh_audited(KEY, None, "admin").unwrap();
            allow(&store);
            let fresh = store
                .secret_ssh_sign_from(&call, V2_ASKER, || V2_NOW)
                .unwrap()
                .reply;
            assert_eq!(
                v2_approve(&store, &fresh, "once")["results"][0]["outcome"],
                "granted"
            );
            let before = count(&store, "SELECT count(*) FROM secret_pending_requests");
            assert!(matches!(
                store.secret_ssh_sign_sealed(&call, &receipt, seal, || V2_NOW),
                Err(SecretError::NotFound)
            ));
            assert_eq!(
                count(
                    &store,
                    "SELECT count(*) FROM secret_grants WHERE secret_name='signing:local-login'"
                ),
                1
            );
            assert_eq!(
                count(&store, "SELECT count(*) FROM secret_pending_requests"),
                before
            );
            assert_eq!(
                count(
                    &store,
                    "SELECT count(*) FROM audit_log WHERE op='secret_ssh_sign'"
                ),
                1
            );
            let tombstone: (String, Vec<u8>, Vec<u8>) = store
                .store
                .with_conn(|c| {
                    c.query_row(
                        "SELECT aad_sha256,enc,ciphertext FROM secret_release_receipts",
                        [],
                        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                    )
                })
                .unwrap();
            assert_eq!(tombstone, ("invalidated".into(), vec![], vec![]));
            let fresh_receipt = use_secret::ReleaseRequest {
                nonce: "1123456789abcdef0123456789abcdef",
                ..receipt
            };
            assert!(matches!(
                store
                    .secret_ssh_sign_sealed(&call, &fresh_receipt, seal, || V2_NOW)
                    .unwrap()
                    .unwrap(),
                use_secret::ForwardedUse::Sealed(_)
            ));
        }

        #[test]
        fn ssh_revoke_and_expire_audit_bare_credential_ids() {
            let (_root, store) = setup("local-ssh-lifecycle-audit");
            let call = ssh(&store, "ssh", "u", "ssh.test", 22);
            let pending = request(&store, &call);
            v2_approve(&store, &pending, "hour");
            let id: String = store
                .store
                .with_conn(|c| c.query_row("SELECT grant_id FROM secret_grants", [], |r| r.get(0)))
                .unwrap();
            store
                .secret_permissions_revoke(&id, "admin", V2_NOW)
                .unwrap();
            let pending = request(&store, &call);
            v2_approve(&store, &pending, "hour");
            store
                .fenced_write(|tx| phone::sweep(tx, &store.audit_key, V2_NOW + 3_600_000))
                .unwrap();
            for op in [
                "secret_grant_create",
                "secret_grant_revoke",
                "secret_grant_expire",
            ] {
                let subjects: Vec<String> = store
                    .store
                    .with_conn(|c| {
                        c.prepare("SELECT credential_id FROM audit_log WHERE op=?1")?
                            .query_map([op], |r| r.get(0))?
                            .collect()
                    })
                    .unwrap();
                assert!(!subjects.is_empty());
                assert!(subjects.iter().all(|s| s == KEY), "{op}: {subjects:?}");
            }
        }

        #[test]
        fn local_targets_are_disjoint_and_flows_refuse_them() {
            let (_root, store) = setup("local-target-disjoint");
            let mut local = sudo("apt upgrade");
            local.name = "key".into();
            assert!(matches!(
                store.secret_use(&local, || V2_NOW),
                Err(SecretError::NotFound)
            ));
            let mut https = v2_call();
            https.name = "sudo-pw".into();
            assert!(matches!(
                store.secret_use(&https, || V2_NOW),
                Err(SecretError::NotFound)
            ));
            assert!(agent_secret::validate_flow_methods(&sudo("apt").target, None).is_err());
            let approval = agent_secret::SecretFlowApproval {
                name: "sudo-pw".into(),
                flow: v2_flow(),
                target: sudo("apt").target,
                methods: None,
            };
            assert!(matches!(
                store.secret_request_flow_approval(&approval, || V2_NOW),
                Err(SecretError::InvalidParams)
            ));
            let call = agent_secret::SecretFlowUse {
                name: "sudo-pw".into(),
                flow: v2_flow(),
                target: sudo("apt").target,
                method: None,
            };
            assert!(matches!(
                store.secret_flow_use(&call, || V2_NOW),
                Err(SecretError::InvalidParams)
            ));
        }

        #[test]
        fn local_approval_rechecks_secret_and_key_incarnations() {
            for ssh_key in [false, true] {
                let (_root, store) = setup(&format!("local-incarnation-{ssh_key}"));
                let pending = if ssh_key {
                    request(&store, &ssh(&store, "ssh", "u", "ssh.test", 22))
                } else {
                    store
                        .secret_use(&sudo("apt upgrade"), || V2_NOW)
                        .unwrap()
                        .reply
                };
                let (bytes, signature) = signed_envelope(&[pending], "once");
                store.fenced_write(|tx| {
                    if ssh_key { tx.execute("UPDATE credentials SET incarnation='ffffffffffffffffffffffffffffffff' WHERE credential_id=?1", [KEY])?; }
                    else { tx.execute("UPDATE agent_secrets SET incarnation='ffffffffffffffffffffffffffffffff' WHERE name='sudo-pw'", [])?; }
                    Ok(())
                }).unwrap();
                let reply = submit(&store, bytes, signature);
                assert_eq!(reply["results"][0]["code"], "approval_invalid");
                assert_eq!(count(&store, "SELECT count(*) FROM secret_grants"), 0);
            }
        }

        #[test]
        fn ssh_userauth_user_mismatch_with_grant_is_refused_without_consumption() {
            assert_ssh_userauth_mismatch_is_refused(true, UserauthMismatch::User);
        }

        #[test]
        fn ssh_userauth_user_mismatch_without_grant_is_refused_without_pending() {
            assert_ssh_userauth_mismatch_is_refused(false, UserauthMismatch::User);
        }

        #[test]
        fn ssh_userauth_public_key_mismatch_with_grant_is_refused_without_consumption() {
            assert_ssh_userauth_mismatch_is_refused(true, UserauthMismatch::PublicKey);
        }

        #[test]
        fn ssh_userauth_public_key_mismatch_without_grant_is_refused_without_pending() {
            assert_ssh_userauth_mismatch_is_refused(false, UserauthMismatch::PublicKey);
        }

        enum UserauthMismatch {
            User,
            PublicKey,
        }

        fn assert_ssh_userauth_mismatch_is_refused(with_grant: bool, mismatch: UserauthMismatch) {
            let mismatch_name = match &mismatch {
                UserauthMismatch::User => "user",
                UserauthMismatch::PublicKey => "public-key",
            };
            let (_root, store) = setup(&format!("ssh-userauth-{mismatch_name}-{with_grant}"));
            let mut call = ssh(&store, "ssh deploy@ssh.test", "deploy", "ssh.test", 22);
            if with_grant {
                let pending = request(&store, &call);
                assert_eq!(
                    v2_approve(&store, &pending, "once")["results"][0]["outcome"],
                    "granted"
                );
            }
            let expected_error = match mismatch {
                UserauthMismatch::User => {
                    call.data =
                        ssh(&store, "ssh deploy@ssh.test", "other-user", "ssh.test", 22).data;
                    assert_eq!(call.local_use.user(), "deploy");
                    assert_eq!(call.data.user(), "other-user");
                    SecretError::InvalidParams
                }
                UserauthMismatch::PublicKey => {
                    let original_key = call.data.public_key().to_vec();
                    let mut bytes = call.data.as_bytes().to_vec();
                    *bytes.last_mut().unwrap() ^= 1;
                    call.data = SshUserauth::parse(bytes).unwrap();
                    assert_ne!(call.data.public_key(), original_key);
                    assert_eq!(call.data.user(), call.local_use.user());
                    SecretError::NotFound
                }
            };
            let pending_before = count(&store, "SELECT count(*) FROM secret_pending_requests");
            let audit_before = count(&store, "SELECT count(*) FROM audit_log");
            let grant_snapshot = || {
                store.store.with_conn(|conn| {
                    conn.query_row(
                        "SELECT grant_id,first_released,last_use_ms FROM secret_grants WHERE secret_name=?1",
                        [KEY],
                        |r| Ok((r.get::<_, String>(0)?, r.get::<_, bool>(1)?, r.get::<_, Option<i64>>(2)?)),
                    ).optional()
                }).unwrap()
            };
            let grant_before = grant_snapshot();
            assert_eq!(grant_before.is_some(), with_grant);
            let result = store
                .secret_ssh_sign(&call, || V2_NOW)
                .map(|outcome| outcome.reply);
            assert_eq!(result, Err(expected_error));
            assert_eq!(grant_snapshot(), grant_before);
            assert_eq!(
                count(&store, "SELECT count(*) FROM secret_pending_requests"),
                pending_before
            );
            assert_eq!(
                count(&store, "SELECT count(*) FROM audit_log"),
                audit_before
            );
            assert_eq!(count(&store, "SELECT count(*) FROM audit_log WHERE op IN ('secret_ssh_sign','secret_local_release','secret_first_release')"), 0);
            let valid = ssh(&store, "ssh deploy@ssh.test", "deploy", "ssh.test", 22);
            if with_grant {
                assert_eq!(request(&store, &valid)["status"], "signed");
                assert!(grant_snapshot().is_none());
            } else {
                assert_eq!(pending_before, 0);
                assert_eq!(request(&store, &valid)["status"], "approval_required");
            }
        }

        #[test]
        fn local_ssh_invisibility_refusals_do_not_create_pending_or_release_audits() {
            let (_root, store) = setup("local-ssh-invisible");
            let mut call = ssh(&store, "ssh", "u", "ssh.test", 22);
            let mut replies = vec![];
            call.key = "signing:absent".into();
            replies.push(
                store
                    .secret_ssh_sign(&call, || V2_NOW)
                    .err()
                    .unwrap()
                    .body(),
            );
            call.key = KEY.into();
            call.local_use = ssh(&store, "ssh", "u", "other.test", 22).local_use;
            replies.push(
                store
                    .secret_ssh_sign(&call, || V2_NOW)
                    .err()
                    .unwrap()
                    .body(),
            );
            call.local_use = ssh(&store, "ssh", "u", "ssh.test", 22).local_use;
            let mut wrong_blob = call.data.as_bytes().to_vec();
            *wrong_blob.last_mut().unwrap() ^= 1;
            call.data = SshUserauth::parse(wrong_blob).unwrap();
            replies.push(
                store
                    .secret_ssh_sign(&call, || V2_NOW)
                    .err()
                    .unwrap()
                    .body(),
            );
            call = ssh(&store, "ssh", "u", "ssh.test", 22);
            store.set_agent_ssh_audited(KEY, None, "admin").unwrap();
            replies.push(
                store
                    .secret_ssh_sign(&call, || V2_NOW)
                    .err()
                    .unwrap()
                    .body(),
            );
            assert!(replies.iter().all(|r| r == &SecretError::NotFound.body()));
            assert_eq!(
                count(&store, "SELECT count(*) FROM secret_pending_requests"),
                0
            );
            assert_eq!(
                count(
                    &store,
                    "SELECT count(*) FROM audit_log WHERE op='secret_ssh_sign'"
                ),
                0
            );
            assert_eq!(count(&store, "SELECT count(*) FROM auth_events WHERE credential_id='signing:local-login' AND detail='ssh_key'"), 3);
            let events = count(&store, "SELECT count(*) FROM auth_events");
            store
                .set_secret_local_programs_audited(
                    false,
                    AuditCtx::admin(AuditOp::SecretLocalProgramsSet),
                )
                .unwrap();
            assert!(matches!(
                store.secret_ssh_sign(&call, || V2_NOW),
                Err(SecretError::SecretLocalProgramsDisabled)
            ));
            call.sender = agent_secret::SecretSender::Cerebellum;
            assert!(matches!(
                store.secret_ssh_sign(&call, || V2_NOW),
                Err(SecretError::NotFound)
            ));
            assert_eq!(count(&store, "SELECT count(*) FROM auth_events"), events);
        }

        #[test]
        fn local_audit_fields_and_sealing_failure_are_transactional() {
            let (_root, store) = setup("local-audit-fields");
            let call = ssh(&store, "ssh", "u", "ssh.test", 22);
            let pending = store
                .secret_ssh_sign_from(&call, V2_ASKER, || V2_NOW)
                .unwrap()
                .reply;
            v2_approve(&store, &pending, "hour");
            let (id, incarnation): (String, String) = store
                .store
                .with_conn(|c| {
                    c.query_row("SELECT grant_id,incarnation FROM secret_grants", [], |r| {
                        Ok((r.get(0)?, r.get(1)?))
                    })
                })
                .unwrap();
            let receipt = use_secret::ReleaseRequest {
                requester: V2_ASKER,
                nonce: "0123456789abcdef0123456789abcdef",
                aad: b"signed-aad",
            };
            assert_eq!(
                store
                    .secret_ssh_sign_sealed(
                        &call,
                        &receipt,
                        |_| Err::<use_secret::SealedRelease, _>("seal failed"),
                        || V2_NOW
                    )
                    .unwrap(),
                Err("seal failed")
            );
            assert_eq!(
                count(
                    &store,
                    "SELECT count(*) FROM audit_log WHERE op='secret_ssh_sign'"
                ),
                0
            );
            assert_eq!(
                count(&store, "SELECT count(*) FROM secret_release_receipts"),
                0
            );
            assert_eq!(count(&store, "SELECT first_released FROM secret_grants"), 0);
            store
                .secret_ssh_sign_from(&call, V2_ASKER, || V2_NOW)
                .unwrap();
            let triple = r#"{"program":"ssh","target":{"host":"ssh.test","port":22,"user":"u"},"use":"ssh_sign"}"#;
            let keyed_data = phone::hex(&audit::payload_fingerprint(
                &store.audit_key,
                call.data.as_bytes(),
            ));
            let mut payload = vec![];
            for field in [
                id.as_bytes(),
                incarnation.as_bytes(),
                triple.as_bytes(),
                keyed_data.as_bytes(),
                V2_ASKER.as_bytes(),
            ] {
                payload.extend_from_slice(&(field.len() as u64).to_le_bytes());
                payload.extend_from_slice(field);
            }
            let hash: String = store
                .store
                .with_conn(|c| {
                    c.query_row(
                        "SELECT payload_hash FROM audit_log WHERE op='secret_ssh_sign'",
                        [],
                        |r| r.get(0),
                    )
                })
                .unwrap();
            assert_eq!(hash, phone::hex(&payload_hash(&payload)));
            let pending = store
                .secret_use_from(&sudo("apt upgrade"), V2_ASKER, || V2_NOW)
                .unwrap()
                .reply;
            v2_approve(&store, &pending, "once");
            let (id, incarnation): (String, String) = store.store.with_conn(|c| c.query_row("SELECT grant_id,incarnation FROM secret_grants WHERE secret_name='sudo-pw'", [], |r| Ok((r.get(0)?, r.get(1)?)))).unwrap();
            store
                .secret_use_from(&sudo("apt upgrade"), V2_ASKER, || V2_NOW)
                .unwrap();
            let triple = r#"{"program":"sudo","target":{"user":"root"},"use":"sudo_password"}"#;
            let mut payload = vec![];
            for field in [
                id.as_bytes(),
                incarnation.as_bytes(),
                triple.as_bytes(),
                V2_ASKER.as_bytes(),
            ] {
                payload.extend_from_slice(&(field.len() as u64).to_le_bytes());
                payload.extend_from_slice(field);
            }
            let hash: String = store
                .store
                .with_conn(|c| {
                    c.query_row(
                        "SELECT payload_hash FROM audit_log WHERE op='secret_local_release'",
                        [],
                        |r| r.get(0),
                    )
                })
                .unwrap();
            assert_eq!(hash, phone::hex(&payload_hash(&payload)));
        }
    }

    const V2_HOME: &str = "fed-computer:22222222222222222222222222222222";
    const V2_ASKER: &str = "fed-computer:11111111111111111111111111111111";
    const V2_OTHER_ASKER: &str = "fed-computer:33333333333333333333333333333333";
    const V2_FP: &str = "11111111111111111111111111111111";
    const V2_NOW: i64 = 1_700_000_000_000;

    fn v2_signer() -> SigningKey {
        SigningKey::from_bytes((&[7u8; 32]).into()).unwrap()
    }

    fn v2_scope() -> agent_secret::SecretScope {
        agent_secret::SecretScope::ApiKey {
            host: "x.test".into(),
            path_prefix: Some("/repos/a".into()),
            location: "header:X-Api-Key".into(),
        }
    }

    fn v2_call() -> agent_secret::SecretUse {
        agent_secret::SecretUse {
            name: "key".into(),
            sender: agent_secret::SecretSender::Aft,
            scope: agent_secret::AskingScope {
                owner: "reserved:prefrontal-core".into(),
                kind: "head".into(),
                scope_ref: "H".into(),
                epoch: 7,
            },
            worker_parent: None,
            coverage: "scope".into(),
            agent_id: Some("agent-A".into()),
            target: agent_secret::UseTarget::ApiKey {
                scheme: "https".into(),
                host: "x.test".into(),
                port: 443,
                path: "/repos/a/canary-token".into(),
            },
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

    fn v2_flow_call() -> agent_secret::SecretFlowApproval {
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
        let (root, store) = rig(tag, 67);
        store
            .set_federation_self_member_audited(
                V2_HOME,
                crate::audit::AuditCtx::admin(crate::audit::AuditOp::FederationSelfSet),
            )
            .unwrap();
        let scope = v2_scope();
        let incarnation = format!(
            "{:032x}",
            b"key".iter().copied().map(u64::from).sum::<u64>()
        );
        let blob = agent_secret::seal(
            &store.key,
            &incarnation,
            "key",
            &scope,
            &agent_secret::SecretMaterial::ApiKey(Secret::new(b"material-canary".to_vec())),
        )
        .unwrap();
        let (host, prefix, location, origin) = phone::columns(&scope);
        store
            .fenced_write(|tx| {
                tx.execute(
                    "INSERT INTO agent_secrets (name,kind,incarnation,state,host,path_prefix,location,origin,record_version,key_id,envelope,created_at_ms) VALUES ('key',?1,?2,'active',?3,?4,?5,?6,1,?7,?8,?9)",
                    rusqlite::params![
                        scope.kind(),
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
        let approval_pub = v2_signer()
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        store
            .secret_phone_operation(
                V2_FP,
                Some("pair-A"),
                V2_NOW,
                &crate::store::store_agent_secrets::PhoneOperation::Register {
                    deposit_pub: vec![2; 32],
                    approval_pub,
                },
                || true,
                || V2_NOW,
            )
            .unwrap();
        (root, Arc::new(store))
    }

    fn v2_item(request: &Value) -> Value {
        let bytes = URL_SAFE_NO_PAD
            .decode(request["statement_b64url"].as_str().unwrap())
            .unwrap();
        json!({"request_id":request["request_id"],"statement_sha256":phone::hex(&payload_hash(&bytes))})
    }

    fn v2_envelope(items: Vec<Value>, duration: &str, issued: i64) -> Value {
        let expiry = match duration {
            "once" => issued + 600_000,
            "hour" => issued + 3_600_000,
            "session" => issued + 86_400_000,
            "permanent" | "version" => 0,
            _ => 0,
        };
        json!({"v":"ck-secret-use-envelope/v1","items":items,"decision":"allow","duration":duration,"grant_expires_at_ms":expiry,"device_fingerprint":V2_FP,"issued_at_ms":issued})
    }

    fn v2_approve(store: &EncryptedStore, request: &Value, duration: &str) -> Value {
        let e = v2_envelope(vec![v2_item(request)], duration, V2_NOW);
        let bytes = serde_json::to_vec(&e).unwrap();
        let signature: p256::ecdsa::Signature = v2_signer().sign(&bytes);
        store
            .secret_phone_operation(
                V2_FP,
                Some("pair-A"),
                V2_NOW,
                &crate::store::store_agent_secrets::PhoneOperation::Approve {
                    envelope: bytes,
                    signature: signature.to_der().as_bytes().to_vec(),
                    card_ref: Some("card-1".into()),
                },
                || true,
                || V2_NOW,
            )
            .unwrap()
    }

    fn v2_grant_asker(store: &EncryptedStore, table: &str) -> String {
        store
            .store
            .with_conn(|c| {
                c.query_row(&format!("SELECT asking_member_id FROM {table}"), [], |r| {
                    r.get(0)
                })
            })
            .unwrap()
    }

    #[test]
    fn forwarded_use_approval_grants_and_inherits_the_asker() {
        let (_root, store) = v2_setup("v2-appr-use-fwd");
        let request = store
            .secret_use_from(&v2_call(), V2_ASKER, || V2_NOW)
            .unwrap()
            .reply;
        assert_eq!(request["status"], "approval_required");
        let reply = v2_approve(&store, &request, "hour");
        assert_eq!(
            reply,
            json!({"results":[{"request_id":request["request_id"],"outcome":"granted"}]})
        );
        assert_eq!(v2_grant_asker(&store, "secret_grants"), V2_ASKER);
        // The grant releases for its asker.
        let released = store
            .secret_use_from(&v2_call(), V2_ASKER, || V2_NOW)
            .unwrap()
            .reply;
        assert_eq!(released["status"], "released");
    }

    #[test]
    fn local_use_approval_still_grants_a_v1_statement() {
        let (_root, store) = v2_setup("v2-appr-use-local");
        let request = store.secret_use(&v2_call(), || V2_NOW).unwrap().reply;
        let reply = v2_approve(&store, &request, "hour");
        assert_eq!(
            reply,
            json!({"results":[{"request_id":request["request_id"],"outcome":"granted"}]})
        );
        assert_eq!(v2_grant_asker(&store, "secret_grants"), "");
    }

    #[test]
    fn use_approval_refuses_asker_or_version_mismatch() {
        // Forwarded row carrying a v1 statement: version is v1 but the row is not local.
        let (_root, store) = v2_setup("v2-appr-mismatch-v1");
        let forwarded = store
            .secret_use_from(&v2_call(), V2_ASKER, || V2_NOW)
            .unwrap()
            .reply;
        let request_id = forwarded["request_id"].as_str().unwrap().to_owned();
        let v1 = agent_secret::approval_statement(
            &request_id,
            V2_HOME,
            "00000000000000000000000000000149",
            &v2_call(),
            &v2_scope(),
            V2_NOW + 600_000,
        );
        let v1_bytes = serde_json::to_vec(&v1).unwrap();
        let v1_digest = phone::hex(&payload_hash(&v1_bytes));
        store
            .store
            .with_conn(|c| {
                c.execute(
                    "UPDATE secret_pending_requests SET statement_bytes=?1,statement_sha256=?2 WHERE request_id=?3",
                    rusqlite::params![v1_bytes, v1_digest, request_id],
                )
            })
            .unwrap();
        let tampered = json!({"request_id":request_id,"statement_b64url":URL_SAFE_NO_PAD.encode(&v1_bytes),"statement_sha256":v1_digest,"status":"approval_required","expires_at_ms":V2_NOW+600_000});
        assert_eq!(
            v2_approve(&store, &tampered, "hour"),
            json!({"results":[{"request_id":request_id,"outcome":"refused","code":"approval_invalid"}]})
        );
        assert_eq!(
            store
                .store
                .with_conn(
                    |c| c.query_row("SELECT COUNT(*) FROM secret_grants", [], |r| r
                        .get::<_, i64>(0))
                )
                .unwrap(),
            0
        );

        // Forwarded row whose statement names another asker.
        let (_root, store) = v2_setup("v2-appr-mismatch-asker");
        let forwarded = store
            .secret_use_from(&v2_call(), V2_ASKER, || V2_NOW)
            .unwrap()
            .reply;
        let request_id = forwarded["request_id"].as_str().unwrap().to_owned();
        store
            .store
            .with_conn(|c| {
                c.execute(
                    "UPDATE secret_pending_requests SET asking_member_id=?1 WHERE request_id=?2",
                    rusqlite::params![V2_OTHER_ASKER, request_id],
                )
            })
            .unwrap();
        assert_eq!(
            v2_approve(&store, &forwarded, "hour"),
            json!({"results":[{"request_id":request_id,"outcome":"refused","code":"approval_invalid"}]})
        );

        // Local row carrying a v2 statement: version is v2 but the row is local.
        let (_root, store) = v2_setup("v2-appr-mismatch-v2");
        let local = store.secret_use(&v2_call(), || V2_NOW).unwrap().reply;
        let request_id = local["request_id"].as_str().unwrap().to_owned();
        let v2 = agent_secret::approval_statement_for_asker(
            &request_id,
            V2_HOME,
            "00000000000000000000000000000149",
            &v2_call(),
            &v2_scope(),
            V2_NOW + 600_000,
            V2_ASKER,
        );
        let v2_bytes = serde_json::to_vec(&v2).unwrap();
        let v2_digest = phone::hex(&payload_hash(&v2_bytes));
        store
            .store
            .with_conn(|c| {
                c.execute(
                    "UPDATE secret_pending_requests SET statement_bytes=?1,statement_sha256=?2 WHERE request_id=?3",
                    rusqlite::params![v2_bytes, v2_digest, request_id],
                )
            })
            .unwrap();
        let tampered = json!({"request_id":request_id,"statement_b64url":URL_SAFE_NO_PAD.encode(&v2_bytes),"statement_sha256":v2_digest,"status":"approval_required","expires_at_ms":V2_NOW+600_000});
        assert_eq!(
            v2_approve(&store, &tampered, "hour"),
            json!({"results":[{"request_id":request_id,"outcome":"refused","code":"approval_invalid"}]})
        );

        // Local v1 statement carrying an explicit empty asker key is not the v1 object.
        let (_root, store) = v2_setup("v2-appr-mismatch-empty");
        let local = store.secret_use(&v2_call(), || V2_NOW).unwrap().reply;
        let request_id = local["request_id"].as_str().unwrap().to_owned();
        let mut v1_with_empty_asker: Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(local["statement_b64url"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        v1_with_empty_asker["asking_member_id"] = json!("");
        let bytes = serde_json::to_vec(&v1_with_empty_asker).unwrap();
        let digest = phone::hex(&payload_hash(&bytes));
        store
            .store
            .with_conn(|c| {
                c.execute(
                    "UPDATE secret_pending_requests SET statement_bytes=?1,statement_sha256=?2 WHERE request_id=?3",
                    rusqlite::params![bytes, digest, request_id],
                )
            })
            .unwrap();
        let tampered = json!({"request_id":request_id,"statement_b64url":URL_SAFE_NO_PAD.encode(&bytes),"statement_sha256":digest,"status":"approval_required","expires_at_ms":V2_NOW+600_000});
        assert_eq!(
            v2_approve(&store, &tampered, "hour"),
            json!({"results":[{"request_id":request_id,"outcome":"refused","code":"approval_invalid"}]})
        );
    }

    #[test]
    fn forwarded_flow_approval_grants_v2_and_inherits_the_asker() {
        let (_root, store) = v2_setup("v2-appr-flow-fwd");
        let request = store
            .secret_request_flow_approval_from(&v2_flow_call(), V2_ASKER, || V2_NOW)
            .unwrap()
            .reply;
        let reply = v2_approve(&store, &request, "version");
        assert_eq!(
            reply,
            json!({"results":[{"request_id":request["request_id"],"outcome":"granted"}]})
        );
        assert_eq!(v2_grant_asker(&store, "secret_flow_grants"), V2_ASKER);
    }

    #[test]
    fn only_forwarded_flow_approval_refuses_a_v2_tag_flow_id() {
        // Local still accepts it: the request encodes as v1 and the approval grants.
        let (_root, store) = v2_setup("v2-appr-flow-tag-local");
        let mut local_call = v2_flow_call();
        local_call.flow.flow_id = agent_secret::FLOW_STATEMENT_V2.into();
        let local = store
            .secret_request_flow_approval(&local_call, || V2_NOW)
            .unwrap()
            .reply;
        assert_eq!(
            v2_approve(&store, &local, "version"),
            json!({"results":[{"request_id":local["request_id"],"outcome":"granted"}]})
        );
        // Forwarded refuses it at the request boundary.
        assert!(matches!(
            store.secret_request_flow_approval_from(&local_call, V2_ASKER, || V2_NOW),
            Err(agent_secret::SecretError::InvalidParams)
        ));
        // And at the approval boundary, a smuggled row with that flow id is refused.
        let (_root, store) = v2_setup("v2-appr-flow-tag-fwd");
        let request = store
            .secret_request_flow_approval_from(&v2_flow_call(), V2_ASKER, || V2_NOW)
            .unwrap()
            .reply;
        let request_id = request["request_id"].as_str().unwrap().to_owned();
        store
            .store
            .with_conn(|c| {
                c.execute(
                    "UPDATE secret_pending_requests SET flow_id=?1 WHERE request_id=?2",
                    rusqlite::params![agent_secret::FLOW_STATEMENT_V2, request_id],
                )
            })
            .unwrap();
        assert_eq!(
            v2_approve(&store, &request, "version"),
            json!({"results":[{"request_id":request_id,"outcome":"refused","code":"approval_invalid"}]})
        );
        assert_eq!(
            store
                .store
                .with_conn(
                    |c| c.query_row("SELECT COUNT(*) FROM secret_flow_grants", [], |r| r
                        .get::<_, i64>(0))
                )
                .unwrap(),
            0
        );
    }

    mod v3_approval_tests {
        use super::*;

        fn setup(login: bool) -> (crate::test_support::TestTempDir, Arc<EncryptedStore>) {
            static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            let tag = format!(
                "v3-approval-{}",
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            );
            let (root, store) = v2_setup(&tag);
            let scope = if login {
                agent_secret::SecretScope::SiteLoginOrigins {
                    origins: vec!["https://x.test".into(), "https://y.test".into()],
                }
            } else {
                agent_secret::SecretScope::ApiKeyRules {
                    rules: vec![
                        agent_secret::SecretRule {
                            host: "x.test".into(),
                            path_prefix: Some("/repos/a".into()),
                        },
                        agent_secret::SecretRule {
                            host: "y.test".into(),
                            path_prefix: None,
                        },
                    ],
                    location: "header:X-Api-Key".into(),
                }
            };
            let material = if login {
                agent_secret::SecretMaterial::SiteLogin {
                    username: Secret::new("test-user".into()),
                    password: Secret::new("test-password".into()),
                    otpauth: None,
                }
            } else {
                agent_secret::SecretMaterial::ApiKey(Secret::new(b"material-canary".to_vec()))
            };
            store.store.with_conn(|c| {
                let incarnation: String = c.query_row("SELECT incarnation FROM agent_secrets", [], |r| r.get(0))?;
                let blob = agent_secret::seal(&store.key, &incarnation, "key", &scope, &material).unwrap();
                c.execute("UPDATE agent_secrets SET kind=?1,host=NULL,path_prefix=NULL,location=?2,origin=NULL,scope_json=?3,envelope=?4", rusqlite::params![scope.kind(), if login { None } else { Some("header:X-Api-Key") }, scope.scope_json().unwrap(), blob])?;
                Ok(())
            }).unwrap();
            (root, store)
        }

        fn call(login: bool) -> agent_secret::SecretUse {
            let mut call = v2_call();
            if login {
                call.sender = agent_secret::SecretSender::Cerebellum;
                call.target = agent_secret::UseTarget::SiteLogin {
                    origin: "https://x.test".into(),
                };
            }
            call
        }

        fn flow_call(login: bool) -> agent_secret::SecretFlowApproval {
            let mut call = v2_flow_call();
            if login {
                call.target = agent_secret::UseTarget::SiteLogin {
                    origin: "https://x.test".into(),
                };
                call.methods = None;
            }
            call
        }

        fn pending(store: &EncryptedStore, login: bool, flow: bool, asker: &str) -> Value {
            let result = if flow {
                store.secret_request_flow_approval_from(&flow_call(login), asker, || V2_NOW)
            } else {
                store.secret_use_from(&call(login), asker, || V2_NOW)
            };
            let request = result.unwrap().reply;
            assert_eq!(request["status"], "approval_required");
            request
        }

        fn statement(request: &Value) -> Value {
            serde_json::from_slice(
                &URL_SAFE_NO_PAD
                    .decode(request["statement_b64url"].as_str().unwrap())
                    .unwrap(),
            )
            .unwrap()
        }

        fn rewrite(store: &EncryptedStore, request: &Value, statement: &Value) -> Value {
            let bytes = serde_json::to_vec(statement).unwrap();
            let digest = phone::hex(&payload_hash(&bytes));
            store.store.with_conn(|c| c.execute(
                "UPDATE secret_pending_requests SET statement_bytes=?1,statement_sha256=?2 WHERE request_id=?3",
                rusqlite::params![bytes, digest, request["request_id"].as_str().unwrap()],
            )).unwrap();
            let mut request = request.clone();
            request["statement_b64url"] = json!(URL_SAFE_NO_PAD.encode(bytes));
            request
        }

        fn assert_refused(store: &EncryptedStore, request: &Value, flow: bool) {
            assert_eq!(
                v2_approve(store, request, if flow { "version" } else { "hour" }),
                json!({"results":[{"request_id":request["request_id"],"outcome":"refused","code":"approval_invalid"}]})
            );
            assert_eq!(count(store, "secret_grants"), 0);
            assert_eq!(count(store, "secret_flow_grants"), 0);
        }

        fn count(store: &EncryptedStore, table: &str) -> i64 {
            store
                .store
                .with_conn(|c| {
                    c.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
                })
                .unwrap()
        }

        #[test]
        fn v3_agent_and_flow_approvals_release_both_kinds_for_local_and_forwarded_askers() {
            for login in [false, true] {
                for flow in [false, true] {
                    for asker in ["", V2_ASKER] {
                        let (_root, store) = setup(login);
                        let request = pending(&store, login, flow, asker);
                        let signed = statement(&request);
                        assert_eq!(
                            signed["v"],
                            if flow {
                                agent_secret::FLOW_STATEMENT_V3
                            } else {
                                agent_secret::USE_STATEMENT_V3
                            }
                        );
                        assert_eq!(
                            signed.get("asking_member_id").cloned(),
                            if asker.is_empty() {
                                None
                            } else {
                                Some(json!(asker))
                            }
                        );
                        assert_eq!(
                            v2_approve(&store, &request, if flow { "version" } else { "hour" }),
                            json!({"results":[{"request_id":request["request_id"],"outcome":"granted"}]})
                        );
                        assert_eq!(
                            v2_grant_asker(
                                &store,
                                if flow {
                                    "secret_flow_grants"
                                } else {
                                    "secret_grants"
                                }
                            ),
                            asker
                        );
                        let released = if flow {
                            let call = flow_call(login);
                            store.secret_flow_use_from(
                                &agent_secret::SecretFlowUse {
                                    name: call.name,
                                    flow: call.flow,
                                    target: call.target,
                                    method: if login { None } else { Some("GET".into()) },
                                },
                                asker,
                                || V2_NOW,
                            )
                        } else {
                            store.secret_use_from(&call(login), asker, || V2_NOW)
                        }
                        .unwrap()
                        .reply;
                        assert_eq!(released["status"], "released");
                    }
                }
            }
        }

        #[test]
        fn v3_approvals_refuse_asker_presence_and_value_mismatches() {
            for login in [false, true] {
                for flow in [false, true] {
                    for asker in ["", V2_ASKER] {
                        for replacement in [None, Some(""), Some(V2_ASKER), Some(V2_OTHER_ASKER)] {
                            if replacement == if asker.is_empty() { None } else { Some(asker) } {
                                continue;
                            }
                            let (_root, store) = setup(login);
                            let request = pending(&store, login, flow, asker);
                            let mut signed = statement(&request);
                            match replacement {
                                None => {
                                    signed.as_object_mut().unwrap().remove("asking_member_id");
                                }
                                Some(value) => signed["asking_member_id"] = json!(value),
                            }
                            let request = rewrite(&store, &request, &signed);
                            assert_refused(&store, &request, flow);
                        }
                    }
                }
            }
        }

        #[test]
        fn approvals_require_the_exact_tag_for_the_stored_scope_and_asker() {
            for extended in [false, true] {
                for flow in [false, true] {
                    for asker in ["", V2_ASKER] {
                        for tag in [
                            "ck-secret-use-statement/v1",
                            "ck-secret-use-statement/v2",
                            agent_secret::USE_STATEMENT_V3,
                            "ck-secret-flow-statement/v1",
                            agent_secret::FLOW_STATEMENT_V2,
                            agent_secret::FLOW_STATEMENT_V3,
                            "unknown/v2",
                        ] {
                            let (_root, store) = if extended {
                                setup(false)
                            } else {
                                v2_setup("exact-tag")
                            };
                            let request = pending(&store, false, flow, asker);
                            let mut signed = statement(&request);
                            if signed["v"] == tag {
                                continue;
                            }
                            signed["v"] = json!(tag);
                            let request = rewrite(&store, &request, &signed);
                            assert_refused(&store, &request, flow);
                        }
                    }
                }
            }
        }

        #[test]
        fn v3_approvals_compare_stored_use_and_the_whole_flow_statement() {
            for login in [false, true] {
                for flow in [false, true] {
                    for asker in ["", V2_ASKER] {
                        for extra_field in [false, true] {
                            if extra_field && !flow {
                                continue;
                            }
                            let (_root, store) = setup(login);
                            let request = pending(&store, login, flow, asker);
                            let mut signed = statement(&request);
                            if extra_field {
                                signed["unsigned_extension"] = json!(true);
                            } else if login {
                                signed["use"]["origins"][1] = json!("https://z.test");
                            } else {
                                signed["use"]["rules"][1]["host"] = json!("z.test");
                            }
                            let request = rewrite(&store, &request, &signed);
                            assert_refused(&store, &request, flow);
                        }
                    }
                }
            }
        }

        #[test]
        fn extended_flow_reserved_tags_are_invalid_params_without_pending_rows() {
            for login in [false, true] {
                for asker in ["", V2_ASKER] {
                    for tag in [
                        agent_secret::USE_STATEMENT_V3,
                        agent_secret::FLOW_STATEMENT_V3,
                        agent_secret::USE_STATEMENT_V2,
                        agent_secret::FLOW_STATEMENT_V2,
                    ] {
                        let (_root, store) = setup(login);
                        let mut call = flow_call(login);
                        call.flow.flow_id = tag.into();
                        let result =
                            store.secret_request_flow_approval_from(&call, asker, || V2_NOW);
                        if tag.ends_with("/v2") && asker.is_empty() {
                            let request = result.unwrap().reply;
                            assert_eq!(statement(&request)["v"], agent_secret::FLOW_STATEMENT_V3);
                            assert_eq!(
                                v2_approve(&store, &request, "version")["results"][0]["outcome"],
                                "granted"
                            );
                        } else {
                            assert_eq!(
                                result.err(),
                                Some(agent_secret::SecretError::InvalidParams),
                                "{login} {asker} {tag}"
                            );
                            assert_eq!(count(&store, "secret_pending_requests"), 0);
                        }
                    }
                }
            }
        }

        #[test]
        fn extended_flow_commit_refuses_reserved_tags_in_pending_rows() {
            for login in [false, true] {
                for asker in ["", V2_ASKER] {
                    for tag in [
                        agent_secret::USE_STATEMENT_V3,
                        agent_secret::FLOW_STATEMENT_V3,
                        agent_secret::USE_STATEMENT_V2,
                        agent_secret::FLOW_STATEMENT_V2,
                    ] {
                        if asker.is_empty() && tag.ends_with("/v2") {
                            continue;
                        }
                        let (_root, store) = setup(login);
                        let request = pending(&store, login, true, asker);
                        let mut signed = statement(&request);
                        signed["flow"]["flow_id"] = json!(tag);
                        let request = rewrite(&store, &request, &signed);
                        store
                            .store
                            .with_conn(|c| {
                                c.execute(
                            "UPDATE secret_pending_requests SET flow_id=?1 WHERE request_id=?2",
                            rusqlite::params![tag, request["request_id"].as_str().unwrap()],
                        )
                            })
                            .unwrap();
                        assert_refused(&store, &request, true);
                    }
                }
            }
        }

        #[test]
        fn corrupt_stored_scopes_quarantine_approve_items_once() {
            for login in [false, true] {
                for asker in ["", V2_ASKER] {
                    for corruption in 0..7 {
                        let (_root, store) = setup(login);
                        let agent = pending(&store, login, false, asker);
                        let flow = pending(&store, login, true, asker);
                        let use_scope = statement(&agent)["use"].clone();
                        let entries = use_scope[if login { "origins" } else { "rules" }]
                            .as_array()
                            .unwrap();
                        let corrupt = match corruption {
                            0 => "[".into(),
                            1 => format!("{} ", json!(entries)),
                            2 => "[]".into(),
                            3 => json!([entries[0]]).to_string(),
                            4 => json!([entries[0], entries[0]]).to_string(),
                            5 => json!(vec![entries[0].clone(); if login { 5 } else { 9 }])
                                .to_string(),
                            6 => json!([entries[1], entries[0]]).to_string(),
                            _ => unreachable!(),
                        };
                        store
                            .store
                            .with_conn(|c| {
                                c.execute("UPDATE agent_secrets SET scope_json=?1", [&corrupt])
                            })
                            .unwrap();
                        // Either approval branch must perform the stored decode before granting.
                        let first_flow = corruption % 2 == 0;
                        let (first, second) = if first_flow {
                            (&flow, &agent)
                        } else {
                            (&agent, &flow)
                        };
                        assert_refused(&store, first, first_flow);
                        assert_refused(&store, second, !first_flow);
                        store
                            .store
                            .with_conn(|c| {
                                let state: String =
                                    c.query_row("SELECT state FROM agent_secrets", [], |r| {
                                        r.get(0)
                                    })?;
                                let audits: i64 = c.query_row(
                                    "SELECT COUNT(*) FROM audit_log WHERE op='secret_quarantine'",
                                    [],
                                    |r| r.get(0),
                                )?;
                                assert_eq!(state, "corrupt");
                                assert_eq!(audits, 1);
                                Ok(())
                            })
                            .unwrap();
                    }
                }
            }
        }

        fn phone_operation(store: &EncryptedStore, op: &super::super::PhoneOperation) -> Value {
            store
                .secret_phone_operation(V2_FP, Some("pair-A"), V2_NOW, op, || true, || V2_NOW)
                .unwrap()
        }

        fn delete_commit(store: &EncryptedStore, request: &Value) -> Value {
            let bytes = serde_json::to_vec(&json!({
                "v":"ck-secret-use-envelope/v1", "items":[v2_item(request)],
                "decision":"delete", "duration":"none",
                "grant_expires_at_ms":request["expires_at_ms"],
                "device_fingerprint":V2_FP, "issued_at_ms":V2_NOW,
            }))
            .unwrap();
            let signature: p256::ecdsa::Signature = v2_signer().sign(&bytes);
            phone_operation(
                store,
                &super::super::PhoneOperation::DeleteCommit {
                    envelope: bytes,
                    signature: signature.to_der().as_bytes().to_vec(),
                },
            )
        }

        #[test]
        fn phone_v1_delete_removes_extended_rows_grants_and_pending_even_with_corrupt_scope() {
            for login in [false, true] {
                for corrupt in [false, true] {
                    let (_root, store) = setup(login);
                    for flow in [false, true] {
                        for asker in ["", V2_ASKER] {
                            let request = pending(&store, login, flow, asker);
                            assert_eq!(
                                v2_approve(&store, &request, if flow { "version" } else { "hour" })
                                    ["results"][0]["outcome"],
                                "granted"
                            );
                        }
                        pending(&store, login, flow, V2_OTHER_ASKER);
                    }
                    assert_eq!(count(&store, "secret_grants"), 2);
                    assert_eq!(count(&store, "secret_flow_grants"), 2);
                    if corrupt {
                        store
                            .store
                            .with_conn(|c| c.execute("UPDATE agent_secrets SET scope_json='['", []))
                            .unwrap();
                    }
                    let request = phone_operation(
                        &store,
                        &super::super::PhoneOperation::DeleteRequest { name: "key".into() },
                    );
                    let signed = statement(&request);
                    assert_eq!(signed["v"], "ck-secret-delete-statement/v1");
                    assert!(signed.get("asking_member_id").is_none());
                    assert!(count(&store, "secret_pending_requests") >= 3);
                    assert_eq!(
                        delete_commit(&store, &request),
                        json!({"results":[{"request_id":request["request_id"],"outcome":"granted"}]})
                    );
                    for table in [
                        "agent_secrets",
                        "secret_grants",
                        "secret_flow_grants",
                        "secret_pending_requests",
                    ] {
                        assert_eq!(count(&store, table), 0, "{table}");
                    }
                }
            }
        }

        #[test]
        fn phone_delete_keeps_its_exact_v1_tag_and_absent_asker_contract() {
            for tag in [
                "ck-secret-delete-statement/v2",
                agent_secret::USE_STATEMENT_V3,
                "ck-secret-delete-statement/v1",
            ] {
                let (_root, store) = setup(false);
                let request = phone_operation(
                    &store,
                    &super::super::PhoneOperation::DeleteRequest { name: "key".into() },
                );
                let mut signed = statement(&request);
                signed["v"] = json!(tag);
                if tag == "ck-secret-delete-statement/v1" {
                    signed["asking_member_id"] = json!(V2_ASKER);
                    store
                        .store
                        .with_conn(|c| {
                            c.execute(
                                "UPDATE secret_pending_requests SET asking_member_id=?1",
                                [V2_ASKER],
                            )
                        })
                        .unwrap();
                }
                let request = rewrite(&store, &request, &signed);
                assert_eq!(
                    delete_commit(&store, &request),
                    json!({"results":[{"request_id":request["request_id"],"outcome":"refused","code":"approval_invalid"}]})
                );
                assert_eq!(count(&store, "agent_secrets"), 1);
            }
        }
    }
}
