use super::*;
use crate::agent_secret::{
    ApprovalEnvelope, ApprovalItem, SecretError, SECRET_ISSUE_SKEW_LIMIT_MS,
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
}

impl EncryptedStore {
    /// The caller must enforce provider admission; this method reads metadata only.
    pub fn secret_permissions_list(
        &self,
        agent_id: Option<&str>,
        now: i64,
    ) -> Result<Value, SecretError> {
        self.store.with_conn(|conn| {
            let mut stmt = conn.prepare("SELECT g.grant_id,g.agent_id,g.scope_kind,g.scope_ref,s.name,s.kind,s.host,s.path_prefix,s.origin,g.duration,g.expires_at_ms,g.granted_at_ms,g.card_ref FROM secret_grants g JOIN agent_secrets s ON s.incarnation=g.incarnation AND s.name=g.secret_name WHERE (g.duration='permanent' OR g.expires_at_ms>?1) AND (?2 IS NULL OR g.agent_id=?2) ORDER BY g.grant_id")?;
            let rows = stmt.query_map(rusqlite::params![now,agent_id],|r| {
                let name: String = r.get(4)?;
                let kind: String = r.get(5)?;
                let label = if kind == "agent_api_key" { format!("use {name} on {}{}",r.get::<_,String>(6)?,r.get::<_,Option<String>>(7)?.unwrap_or_default()) } else { format!("fill {name} on {}",r.get::<_,String>(8)?) };
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
        let pending = tx.query_row("SELECT request_kind,secret_name,incarnation,member_id,mapped_owner,mapped_kind,mapped_ref,mapped_epoch,coverage,agent_id,statement_bytes,statement_sha256,request_expires_at_ms,consumed,flow_id,flow_version,flow_code_hash,flow_install_id,methods FROM secret_pending_requests WHERE request_id=?1",[&item.request_id],|r| Ok(Pending {kind:r.get(0)?,name:r.get(1)?,incarnation:r.get(2)?,member:r.get(3)?,owner:r.get(4)?,scope_kind:r.get(5)?,scope_ref:r.get(6)?,epoch:r.get(7)?,coverage:r.get(8)?,agent_id:r.get(9)?,bytes:r.get(10)?,digest:r.get(11)?,expiry:r.get(12)?,consumed:r.get(13)?,flow_id:r.get(14)?,flow_version:r.get(15)?,flow_code_hash:r.get(16)?,flow_install_id:r.get(17)?,methods:r.get(18)?})).optional()?;
        let Some(p) = pending else {
            return Ok(false);
        };
        let issued = e.issued_at_ms as i64;
        let statement: Value = match serde_json::from_slice(&p.bytes) {
            Ok(v) => v,
            Err(_) => return Ok(false),
        };
        if p.consumed
            || now >= p.expiry
            || p.digest != item.statement_sha256
            || phone::hex(&payload_hash(&p.bytes)) != p.digest
            || issued < p.expiry - SECRET_PENDING_LIFETIME_LIMIT_MS
            || issued >= p.expiry
            || now.abs_diff(issued) > SECRET_ISSUE_SKEW_LIMIT_MS as u64
            || member != Some(p.member.as_str())
            || statement["member_id"] != p.member
            || statement["request_id"] != item.request_id
            || statement["request_expires_at_ms"] != p.expiry
            || statement["secret"]["name"] != p.name
            || statement["secret"]["incarnation"] != p.incarnation
            || p.kind != if delete { "delete" } else { "approve" }
            || e.decision != if delete { "delete" } else { "allow" }
        {
            return Ok(false);
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
        let row = tx.query_row("SELECT kind,state,host,path_prefix,location,origin,envelope FROM agent_secrets WHERE name=?1 AND incarnation=?2",rusqlite::params![p.name,p.incarnation], |r| Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,Option<String>>(2)?,r.get::<_,Option<String>>(3)?,r.get::<_,Option<String>>(4)?,r.get::<_,Option<String>>(5)?,r.get::<_,Vec<u8>>(6)?))).optional()?;
        let Some((kind, state, host, path_prefix, location, origin, blob)) = row else {
            return Ok(false);
        };
        let actor = format!("fed-phone:{fingerprint}");
        if delete {
            if e.duration != "none" || statement["v"] != "ck-secret-delete-statement/v1" {
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
                || statement["v"] != "ck-secret-use-statement/v1"
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
        let scope = match (kind.as_str(), host, location, origin) {
            ("agent_api_key", Some(host), Some(location), None) => {
                agent_secret::SecretScope::ApiKey {
                    host,
                    path_prefix,
                    location,
                }
            }
            ("site_login", None, None, Some(origin)) => {
                agent_secret::SecretScope::SiteLogin { origin }
            }
            _ => {
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
        let sealed_use = match &scope {
            agent_secret::SecretScope::ApiKey {
                host,
                path_prefix,
                location,
            } => {
                json!({"host":host,"path_prefix":path_prefix.as_deref().unwrap_or(""),"location":location})
            }
            agent_secret::SecretScope::SiteLogin { origin } => json!({"origin":origin}),
        };
        if statement["secret"]["kind"] != scope.kind() || statement["use"] != sealed_use {
            return Ok(false);
        }
        let id = agent_secret::request_id(now)
            .map_err(|_| rusqlite_err("grant id generation failed"))?;
        tx.execute(
            "UPDATE secret_pending_requests SET consumed=1 WHERE request_id=?1",
            [&item.request_id],
        )?;
        tx.execute("INSERT INTO secret_grants (grant_id,secret_name,incarnation,scope_owner,scope_kind,scope_ref,coverage,duration,expires_at_ms,granted_at_ms,envelope_sha256,agent_id,card_ref) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",rusqlite::params![id,p.name,p.incarnation,p.owner,p.scope_kind,p.scope_ref,p.coverage,e.duration,e.grant_expires_at_ms,now,envelope_hash,p.agent_id,card_ref])?;
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
        let expected = match agent_secret::flow_approval_statement(
            &item.request_id,
            &p.member,
            &p.incarnation,
            &p.name,
            &flow,
            scope,
            methods.as_deref(),
            p.expiry,
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
        tx.execute("INSERT INTO secret_flow_grants (grant_id,secret_name,incarnation,flow_id,flow_version,flow_code_hash,flow_install_id,methods,granted_at_ms,envelope_sha256,card_ref) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",rusqlite::params![id,p.name,p.incarnation,flow.flow_id,flow.version,flow.code_hash,flow.install_id,p.methods,now,envelope_hash,card_ref])?;
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
            credential_id: Some(format!("secret|{name}")),
            payload_hash: Some(hash.to_owned()),
            actor: actor.to_owned(),
            alarm: None,
        },
    )
    .map(|_| ())
}

/// One `permissions.list` row per live flow grant.
///
/// A flow grant has no wall-clock expiry and no agent, so it carries no `expires_at_ms`
/// and no `agent_id`. Its holder is the installed flow version that owns it, which the
/// phone and desktop permission pages render from these three fields plus the secret's
/// name and kind. `methods` describes how an API key may be used, so a site login, which
/// has no method at all, omits the key rather than sending an empty list.
fn flow_permission_rows(conn: &rusqlite::Connection) -> rusqlite::Result<Vec<Value>> {
    conn.prepare("SELECT g.grant_id,g.flow_id,g.flow_version,g.flow_install_id,s.name,s.kind,s.host,s.path_prefix,COALESCE(s.origin,''),g.methods,g.granted_at_ms,g.card_ref FROM secret_flow_grants g JOIN agent_secrets s ON s.incarnation=g.incarnation AND s.name=g.secret_name ORDER BY g.grant_id")?
        .query_map([], |r| {
            let name: String = r.get(4)?;
            let kind: String = r.get(5)?;
            let api_key = kind == "agent_api_key";
            let label = if api_key {
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
            return Ok(json!({"outcome":"not_found"}));
        };
        let flow_version = flow_version.to_string();
        tx.execute("DELETE FROM secret_flow_grants WHERE grant_id=?1", [id])?;
        phone::audit(
            tx,
            key,
            AuditOp::SecretGrantRevoke,
            Some(format!("secret|{name}")),
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
        Some(format!("secret|{name}")),
        actor,
        &[id.as_bytes(), incarnation.as_bytes()],
    )?;
    Ok(json!({"outcome":"revoked"}))
}
