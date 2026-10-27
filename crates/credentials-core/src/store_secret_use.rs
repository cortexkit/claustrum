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
/// The `asking_member_id` of a grant or pending request made on this vault itself.
///
/// A call forwarded here by a paired computer carries that computer's member id
/// instead, so a grant approved for one computer's agent or flow never answers another
/// computer's request, nor this vault's own, for the same scope stamp or flow identity.
const LOCAL_ASKING_MEMBER: &str = "";

struct Grant {
    id: String,
    first: bool,
    duration: String,
}

/// How long the home answers a same-nonce retry of a forwarded release with the reply
/// it already sealed. A paired computer gives up retrying one sender call well before
/// this, so a nonce is never answered afresh after its receipt has been deleted.
pub const SECRET_RELEASE_RECEIPT_LIFETIME_MS: i64 = 10 * 60 * 1000;

/// The `detail` of the refusal audit written when a same-nonce retry is denied.
const RECEIPT_DENIED: &str = "release_receipt";

/// One forwarded release request as the home received it.
///
/// A paired computer sends one AAD (one nonce) for every transport retry of a single
/// sender call. The home answers a retry with exactly the same AAD bytes from its
/// release receipt instead of releasing again.
pub struct ReleaseRequest<'a> {
    /// The paired computer that asked (`fed-computer:<fp>`). The caller must have
    /// authenticated it; it is also the asking member every grant is matched against.
    pub requester: &'a str,
    /// The AAD's `nonce`: 16 random bytes in lower hex.
    pub nonce: &'a str,
    /// The exact AAD bytes received. Only a retry with identical bytes, not merely an
    /// equal JSON object, is answered from the receipt.
    pub aad: &'a [u8],
}

impl ReleaseRequest<'_> {
    fn validate(&self) -> Result<(), SecretError> {
        if crate::federation::valid_member_id(self.requester)
            && crate::federation::is_lower_hex_16_bytes(self.nonce)
            && !self.aad.is_empty()
        {
            Ok(())
        } else {
            Err(SecretError::InvalidParams)
        }
    }
}

/// A released secret sealed to the requesting computer's key. It holds no plaintext.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedRelease {
    pub enc: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// The home's answer to a forwarded `secret.use` or flow run.
#[derive(Debug, PartialEq)]
pub enum ForwardedUse {
    /// The secret was released: sealed just now, or the stored bytes for a retry.
    Sealed(SealedRelease),
    /// Any other reply, such as `approval_required`. It never holds material.
    Reply(Value),
}

/// What a forwarded release did inside its transaction, before the caller maps it.
enum Forwarded {
    Answer(Result<ForwardedUse, SecretError>),
    Refused(Refusal),
}

/// The kind of grant a receipt was released under, which decides how a retry checks
/// that the grant is still live.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ReceiptGrant {
    /// An agent grant that stays after release (hour, session or permanent).
    Agent,
    /// The `once` agent grant the release consumed. It is gone by design, so a retry
    /// does not look for it.
    Once,
    /// A flow grant.
    Flow,
}

impl ReceiptGrant {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::Once => "once",
            Self::Flow => "flow",
        }
    }
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

    /// Record one secret call this vault forwarded to its secret home, under the local
    /// `sender`, with `outcome`, the code the sender was answered with. The subject is
    /// `secret|<name>`, or `secret-use|unaddressed` when the call named no valid secret.
    ///
    /// A `released` outcome is written only when the subject holds no `released` row for
    /// this sender yet: the table keeps 64 rows per subject, and a row per release would
    /// evict the refusal rows that explain why a call stopped working. Every other
    /// outcome is written each time. Best effort, like the refusal diagnostics: a
    /// failure here changes no reply.
    pub fn record_secret_forward(
        &self,
        sender: SecretSender,
        name: Option<&str>,
        outcome: &'static str,
    ) {
        let subject = name.map_or_else(
            || "secret-use|unaddressed".to_owned(),
            |n| format!("secret|{n}"),
        );
        let module = sender
            .actor()
            .strip_prefix("reserved:")
            .expect("sender module");
        let principal = AuthEventPrincipal::Reserved(module);
        let _ = self.store.with_conn(|conn| {
            let tx = conn.unchecked_transaction()?;
            if outcome == "released" {
                tx.execute(
                    "INSERT INTO auth_events \
                     (ts_ms, credential_id, kind, provider_status, detail, record_version, applied, principal_kind, principal_id) \
                     SELECT ?1, ?2, ?3, NULL, ?4, NULL, 0, ?5, ?6 \
                     WHERE NOT EXISTS ( \
                       SELECT 1 FROM auth_events \
                       WHERE credential_id = ?2 AND kind = ?3 AND detail = ?4 \
                         AND principal_kind = ?5 AND (principal_id IS ?6) \
                     )",
                    rusqlite::params![
                        now_ms(),
                        subject,
                        AuthEventKind::SecretForward.as_str(),
                        outcome,
                        principal.kind(),
                        principal.id(),
                    ],
                )?;
                trim_auth_events_tx(&tx, &subject)?;
            } else {
                append_secret_auth_event_tx(
                    &tx,
                    &subject,
                    &AuthObservation {
                        kind: AuthEventKind::SecretForward.as_str(),
                        provider_status: None,
                        detail: Some(outcome),
                        reporter_source: None,
                        principal: Some(principal),
                    },
                    None,
                    false,
                )?;
            }
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
        self.secret_use_from(call, LOCAL_ASKING_MEMBER, clock)
    }

    /// [`Self::secret_use`] for a call that `asking_member` forwarded to this vault.
    ///
    /// Only grants recorded for that same asking member can release, and a request
    /// with no such grant gets its own pending approval, never one another asker made.
    /// The caller must have authenticated `asking_member`; this method trusts it.
    pub fn secret_use_from(
        &self,
        call: &SecretUse,
        asking_member: &str,
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
            let grant = choose_grant(conn, call, asking_member, &record.incarnation, now)?;
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
        let answer = self
            .fenced_write(|tx| {
                let now = clock();
                let record = match self.check_secret_use(tx, call)? {
                    Ok(r) => r,
                    Err(r) => return Ok(Err(r)),
                };
                phone::sweep(tx, &self.audit_key, now)?;
                if let Some(grant) =
                    choose_grant(tx, call, asking_member, &record.incarnation, now)?
                {
                    let reply =
                        release(&record, now).map_err(|_| rusqlite_err("secret release failed"))?;
                    self.commit_agent_release(tx, call, asking_member, &grant, &record, now)?;
                    return Ok(Ok(Ok(SecretUseOutcome {
                        reply,
                        last_use: None,
                    })));
                }
                pending(tx, call, asking_member, &record, now).map(Ok)
            })
            .map_err(|_| SecretError::StoreError)?;
        match answer {
            Err(refusal) => self.use_refused(call, refusal),
            Ok(answer) => answer,
        }
    }

    /// Consume a `once` grant or mark a grant released, and write the release audit the
    /// first time a grant releases.
    ///
    /// A release forwarded by a paired computer (a non-empty `asking_member`) adds that
    /// member id as the last audited field, so the audit chain records which computer the
    /// secret went to. A local release audits exactly the fields it always has.
    fn commit_agent_release(
        &self,
        tx: &rusqlite::Transaction<'_>,
        call: &SecretUse,
        asking_member: &str,
        grant: &Grant,
        record: &Record,
        now: i64,
    ) -> rusqlite::Result<()> {
        if !grant.first || grant.duration == "once" {
            let mut fields: Vec<&[u8]> = vec![grant.id.as_bytes(), record.incarnation.as_bytes()];
            if asking_member != LOCAL_ASKING_MEMBER {
                fields.push(asking_member.as_bytes());
            }
            phone::audit(
                tx,
                &self.audit_key,
                AuditOp::SecretFirstRelease,
                Some(format!("secret|{}", call.name)),
                call.sender.actor(),
                &fields,
            )?;
        }
        if grant.duration == "once" {
            tx.execute("DELETE FROM secret_grants WHERE grant_id=?1", [&grant.id])?;
        } else {
            tx.execute(
                "UPDATE secret_grants SET first_released=1,last_use_ms=?2 WHERE grant_id=?1",
                rusqlite::params![grant.id, now],
            )?;
        }
        Ok(())
    }

    /// [`Self::secret_use_from`] for a call a paired computer forwarded, whose release
    /// must cross to that computer sealed.
    ///
    /// `seal` turns the released object into the bytes sent back; it runs inside the
    /// write transaction, and if it fails nothing is consumed, audited or stored and its
    /// error is returned as `Ok(Err(_))`.
    ///
    /// Every release writes a receipt keyed by `(requester, nonce)` in the same
    /// transaction that consumes a `once` grant or marks the first release and writes
    /// its audit. A later request with the same key is answered only from that receipt,
    /// before any grant is chosen: it gets the stored bytes unchanged, with no second
    /// consumption or audit, while the receipt is unexpired, the AAD bytes are identical,
    /// the secret has the same incarnation and the grant used is still live (a consumed
    /// `once` grant excepted). Otherwise it is refused `not_found` with a refusal audit
    /// and is never released afresh. Every one of these is compared against `clock` on
    /// each request, so a receipt or grant past its expiry is refused even before the
    /// sweep deletes it.
    ///
    /// The caller must have authenticated `request.requester` and checked its pairing,
    /// its `secret_use` member grant and its announced key, on the first request and on
    /// every retry alike.
    pub fn secret_use_sealed<E>(
        &self,
        call: &SecretUse,
        request: &ReleaseRequest<'_>,
        seal: impl FnOnce(&Value) -> Result<SealedRelease, E>,
        clock: impl Fn() -> i64,
    ) -> Result<Result<ForwardedUse, E>, SecretError> {
        request.validate()?;
        if call.sender == SecretSender::Basal {
            return Err(self.refuse_secret_target(
                &call.name,
                call.sender,
                &call.target,
                Refusal {
                    detail: "flow_identity",
                    addressed: false,
                },
            ));
        }
        let aad_sha256 = phone::hex(&payload_hash(request.aad));
        let mut seal_failure = None;
        let answer = self.fenced_write(|tx| {
            let now = clock();
            let record = match self.check_secret_use(tx, call)? {
                Ok(record) => record,
                Err(refusal) => return Ok(Forwarded::Refused(refusal)),
            };
            let kinds = [ReceiptGrant::Agent, ReceiptGrant::Once];
            if let Some(replay) =
                replay(tx, request, &aad_sha256, &record.incarnation, &kinds, now)?
            {
                return Ok(replay);
            }
            phone::sweep(tx, &self.audit_key, now)?;
            let Some(grant) = choose_grant(tx, call, request.requester, &record.incarnation, now)?
            else {
                return Ok(Forwarded::Answer(
                    pending(tx, call, request.requester, &record, now)?
                        .map(|outcome| ForwardedUse::Reply(outcome.reply)),
                ));
            };
            let reply = release(&record, now).map_err(|_| rusqlite_err("secret release failed"))?;
            let sealed = match seal(&reply) {
                Ok(sealed) => sealed,
                Err(error) => {
                    seal_failure = Some(error);
                    return Err(rusqlite_err("secret release seal failed"));
                }
            };
            self.commit_agent_release(tx, call, request.requester, &grant, &record, now)?;
            let kind = if grant.duration == "once" {
                ReceiptGrant::Once
            } else {
                ReceiptGrant::Agent
            };
            write_receipt(
                tx,
                request,
                &aad_sha256,
                &record.incarnation,
                kind,
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
            Forwarded::Refused(refusal) => {
                Err(self.refuse_secret_target(&call.name, call.sender, &call.target, refusal))
            }
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
    asking_member: &str,
    incarnation: &str,
    now: i64,
) -> rusqlite::Result<Option<Grant>> {
    let mut stmt=conn.prepare("SELECT grant_id,scope_owner,scope_kind,scope_ref,coverage,duration,first_released FROM secret_grants WHERE incarnation=?1 AND secret_name=?2 AND (duration='permanent' OR expires_at_ms>?3) AND asking_member_id=?4 ORDER BY (duration='once'), (duration='permanent') DESC, CASE WHEN duration!='once' THEN expires_at_ms ELSE 0 END DESC, granted_at_ms, grant_id")?;
    let rows = stmt.query_map(
        rusqlite::params![incarnation, call.name, now, asking_member],
        |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, bool>(6)?,
            ))
        },
    )?;
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

/// Answer a forwarded release from its receipt, if `(requester, nonce)` has one.
///
/// `None` means no release was made for this nonce yet. Otherwise the stored sealed
/// bytes come back only if every condition still holds now; any failed condition
/// refuses the request rather than letting it fall through to a fresh release.
/// `kinds` names the receipt kinds the calling path can have written, so an agent
/// call never replays a flow release or the reverse.
fn replay(
    tx: &rusqlite::Transaction<'_>,
    request: &ReleaseRequest<'_>,
    aad_sha256: &str,
    incarnation: &str,
    kinds: &[ReceiptGrant],
    now: i64,
) -> rusqlite::Result<Option<Forwarded>> {
    let row = tx
        .query_row(
            "SELECT aad_sha256,incarnation,grant_kind,grant_id,enc,ciphertext,expires_at_ms FROM secret_release_receipts WHERE requester=?1 AND nonce=?2",
            [request.requester, request.nonce],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, Vec<u8>>(4)?,
                    r.get::<_, Vec<u8>>(5)?,
                    r.get::<_, i64>(6)?,
                ))
            },
        )
        .optional()?;
    let Some((stored_aad, stored_incarnation, kind, grant_id, enc, ciphertext, expires_at_ms)) =
        row
    else {
        return Ok(None);
    };
    let denied = Some(Forwarded::Refused(Refusal {
        detail: RECEIPT_DENIED,
        addressed: true,
    }));
    let kind = [ReceiptGrant::Agent, ReceiptGrant::Once, ReceiptGrant::Flow]
        .into_iter()
        .find(|k| k.as_str() == kind)
        .ok_or_else(|| rusqlite_err("invalid release receipt grant kind"))?;
    if expires_at_ms <= now
        || stored_aad != aad_sha256
        || stored_incarnation != incarnation
        || !kinds.contains(&kind)
    {
        return Ok(denied);
    }
    // The same liveness test grant selection applies, so revoking the grant, its
    // timed expiry, or a flow revoke ends replay at once, swept or not.
    let live = match kind {
        ReceiptGrant::Once => true,
        ReceiptGrant::Agent => tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM secret_grants WHERE grant_id=?1 AND incarnation=?2 AND asking_member_id=?3 AND (duration='permanent' OR expires_at_ms>?4))",
            rusqlite::params![grant_id, incarnation, request.requester, now],
            |r| r.get::<_, bool>(0),
        )?,
        ReceiptGrant::Flow => tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM secret_flow_grants WHERE grant_id=?1 AND incarnation=?2 AND asking_member_id=?3)",
            rusqlite::params![grant_id, incarnation, request.requester],
            |r| r.get::<_, bool>(0),
        )?,
    };
    if !live {
        return Ok(denied);
    }
    Ok(Some(Forwarded::Answer(Ok(ForwardedUse::Sealed(
        SealedRelease { enc, ciphertext },
    )))))
}

#[allow(clippy::too_many_arguments)]
fn write_receipt(
    tx: &rusqlite::Transaction<'_>,
    request: &ReleaseRequest<'_>,
    aad_sha256: &str,
    incarnation: &str,
    kind: ReceiptGrant,
    grant_id: &str,
    sealed: &SealedRelease,
    now: i64,
) -> rusqlite::Result<()> {
    tx.execute(
        "INSERT INTO secret_release_receipts (requester,nonce,aad_sha256,incarnation,grant_kind,grant_id,enc,ciphertext,expires_at_ms) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        rusqlite::params![
            request.requester,
            request.nonce,
            aad_sha256,
            incarnation,
            kind.as_str(),
            grant_id,
            sealed.enc,
            sealed.ciphertext,
            now + SECRET_RELEASE_RECEIPT_LIFETIME_MS
        ],
    )?;
    Ok(())
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
    asking_member: &str,
    record: &Record,
    now: i64,
) -> rusqlite::Result<Result<SecretUseOutcome, SecretError>> {
    let member = match phone::self_member(tx) {
        Ok(member) => member,
        Err(SecretError::StoreError) => return Err(rusqlite_err("member lookup failed")),
        Err(error) => return Ok(Err(error)),
    };
    let run = || -> rusqlite::Result<Result<SecretUseOutcome, SecretError>> {
        // Housekeeping only: drop consumed and expired requests, and requests
        // whose serving member id is no longer this vault's. Live requests from any
        // asker stay.
        tx.execute("DELETE FROM secret_pending_requests WHERE consumed!=0 OR request_expires_at_ms<=?1 OR member_id!=?2",rusqlite::params![now,member])?;
        // A request is reused only for the same asker, so two computers whose agents carry
        // the same scope stamp each get their own approval, never a shared one.
        let prior=tx.query_row("SELECT request_id,statement_bytes,request_expires_at_ms FROM secret_pending_requests WHERE request_kind='approve' AND flow_id IS NULL AND incarnation=?1 AND mapped_owner=?2 AND mapped_kind=?3 AND mapped_ref=?4 AND coverage=?5 AND asking_member_id=?6",rusqlite::params![record.incarnation,call.scope.owner,call.scope.kind,call.scope.scope_ref,call.coverage,asking_member],|r|Ok((r.get::<_,String>(0)?,r.get::<_,Vec<u8>>(1)?,r.get::<_,i64>(2)?))).optional()?;
        if let Some((id, bytes, expiry)) = prior {
            return Ok(Ok(approval_reply(&id, &bytes, expiry)));
        }
        // The per-scope limit counts this asker's requests only, so another computer
        // cannot use up the quota of a scope stamp it happens to share.
        let (total,scope):(usize,usize)=tx.query_row("SELECT COUNT(*),COALESCE(SUM(mapped_owner=?1 AND mapped_kind=?2 AND mapped_ref=?3 AND asking_member_id=?4),0) FROM secret_pending_requests WHERE request_kind='approve' AND flow_id IS NULL",rusqlite::params![call.scope.owner,call.scope.kind,call.scope.scope_ref,asking_member],|r|Ok((r.get(0)?,r.get(1)?)))?;
        if total >= MAX_SECRET_PENDING_TOTAL || scope >= MAX_SECRET_PENDING_PER_SCOPE {
            return Ok(Err(SecretError::PendingLimit));
        }
        let id = agent_secret::request_id(now)
            .map_err(|_| rusqlite_err("request id generation failed"))?;
        let expiry = now + SECRET_PENDING_LIFETIME_LIMIT_MS;
        // The statement has fixed ASCII keys, no floats, and integers in JSON's exact range.
        // Sorted serde_json maps therefore use JCS key ordering; string values such as
        // `agent` and `scope.ref` retain their UTF-8 bytes without normalization.
        // A forwarded request carries the v1 object plus `asking_member_id` under a
        // v2 tag; a local one stays v1 byte for byte.
        let statement = agent_secret::approval_statement_for_asker(
            &id,
            &member,
            &record.incarnation,
            call,
            &record.scope,
            expiry,
            asking_member,
        );
        let bytes = serde_json::to_vec(&statement)
            .map_err(|_| rusqlite_err("statement encoding failed"))?;
        let digest = phone::hex(&payload_hash(&bytes));
        tx.execute("INSERT INTO secret_pending_requests (request_id,request_kind,secret_name,incarnation,member_id,mapped_owner,mapped_kind,mapped_ref,mapped_epoch,coverage,agent_id,statement_bytes,statement_sha256,request_expires_at_ms,asking_member_id) VALUES (?1,'approve',?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",rusqlite::params![id,call.name,record.incarnation,member,call.scope.owner,call.scope.kind,call.scope.scope_ref,call.scope.epoch,call.coverage,call.agent_id,bytes,digest,expiry,asking_member])?;
        Ok(Ok(approval_reply(&id, &bytes, expiry)))
    };
    run()
}

#[cfg(test)]
#[path = "store_secret_use_tests.rs"]
mod tests;
#[cfg(test)]
mod v2_use_tests {
    use super::*;
    use crate::{secret::Secret, store::taxonomy_tests::rig};
    use std::sync::Arc;

    const V2_MEMBER: &str = "fed-computer:22222222222222222222222222222222";
    const V2_ASKER: &str = "fed-computer:11111111111111111111111111111111";
    const V2_NOW: i64 = 1_700_000_000_000;

    fn v2_scope() -> SecretScope {
        SecretScope::ApiKey {
            host: "x.test".into(),
            path_prefix: Some("/repos/a".into()),
            location: "header:X-Api-Key".into(),
        }
    }

    fn v2_call() -> SecretUse {
        SecretUse {
            name: "key".into(),
            sender: SecretSender::Aft,
            scope: AskingScope {
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

    fn v2_setup(tag: &str) -> (crate::test_support::TestTempDir, Arc<EncryptedStore>) {
        let (root, store) = rig(tag, 65);
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
            &SecretMaterial::ApiKey(Secret::new(b"material-canary".to_vec())),
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
    fn forwarded_use_pending_carries_v2_statement_with_asker() {
        let (_root, store) = v2_setup("v2-use-forwarded");
        let outcome = store
            .secret_use_from(&v2_call(), V2_ASKER, || V2_NOW)
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
        let statement: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(statement["v"], "ck-secret-use-statement/v2");
        assert_eq!(statement["asking_member_id"], V2_ASKER);
        assert_eq!(statement["member_id"], V2_MEMBER);
        assert_eq!(serde_json::to_vec(&statement).unwrap(), bytes);
    }

    #[test]
    fn local_use_pending_stays_v1_without_asker() {
        let (_root, store) = v2_setup("v2-use-local");
        let outcome = store.secret_use(&v2_call(), || V2_NOW).unwrap();
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
        let statement: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(statement["v"], "ck-secret-use-statement/v1");
        assert!(statement.get("asking_member_id").is_none());
        assert_eq!(serde_json::to_vec(&statement).unwrap(), bytes);
    }
}

/// Release receipts: a forwarded release is answered again, byte for byte, only while
/// its receipt, its AAD, the secret's incarnation and the grant it used all still hold.
#[cfg(test)]
mod receipt_tests {
    use super::*;
    use crate::{secret::Secret, store::taxonomy_tests::rig};
    use agent_secret::{FlowIdentity, SecretFlowUse};
    use std::cell::Cell;

    const SEED: u8 = 67;
    const MEMBER: &str = "fed-computer:22222222222222222222222222222222";
    const ASKER: &str = "fed-computer:11111111111111111111111111111111";
    const NONCE: &str = "0123456789abcdef0123456789abcdef";
    const FIRST: &str = "00000000000000000000000000000001";
    const SECOND: &str = "00000000000000000000000000000002";
    const NOW: i64 = 1_700_000_000_000;
    const LIFETIME: i64 = SECRET_RELEASE_RECEIPT_LIFETIME_MS;

    fn aad() -> Vec<u8> {
        format!(
            r#"{{"secret_name":"key","requester":"{ASKER}","home":"{MEMBER}","nonce":"{NONCE}","recipient_key_id":"kem-1","call_sha256":"{}"}}"#,
            "ab".repeat(32)
        )
        .into_bytes()
    }

    fn scope() -> SecretScope {
        SecretScope::ApiKey {
            host: "x.test".into(),
            path_prefix: Some("/repos/a".into()),
            location: "header:X-Api-Key".into(),
        }
    }

    fn call() -> SecretUse {
        SecretUse {
            name: "key".into(),
            sender: SecretSender::Aft,
            scope: AskingScope {
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

    fn flow_call() -> SecretFlowUse {
        SecretFlowUse {
            name: "key".into(),
            flow: FlowIdentity {
                flow_id: "daily-fetch".into(),
                version: 7,
                code_hash: "0123456789abcdef".repeat(4),
                install_id: "install-A".into(),
            },
            target: call().target,
            method: Some("GET".into()),
        }
    }

    fn seed(store: &EncryptedStore, incarnation: &str) {
        let blob = agent_secret::seal(
            &store.key,
            incarnation,
            "key",
            &scope(),
            &SecretMaterial::ApiKey(Secret::new(b"material-canary".to_vec())),
        )
        .unwrap();
        let scope = scope();
        let (host, prefix, location, origin) = phone::columns(&scope);
        store
            .fenced_write(|tx| {
                tx.execute(
                    "INSERT INTO agent_secrets (name,kind,incarnation,state,host,path_prefix,location,origin,record_version,key_id,envelope,created_at_ms) VALUES ('key',?1,?2,'active',?3,?4,?5,?6,1,?7,?8,?9)",
                    rusqlite::params![scope.kind(), incarnation, host, prefix, location, origin, store.key_id.to_hex(), blob, NOW],
                )
                .map(|_| ())
            })
            .unwrap();
    }

    fn setup(tag: &str) -> (crate::test_support::TestTempDir, EncryptedStore) {
        let (root, store) = rig(tag, SEED);
        store
            .set_federation_self_member_audited(
                MEMBER,
                crate::audit::AuditCtx::admin(AuditOp::FederationSelfSet),
            )
            .unwrap();
        seed(&store, FIRST);
        (root, store)
    }

    fn reopen(root: &crate::test_support::TestTempDir, tag: &str) -> EncryptedStore {
        let descriptor = cortexkit_store::StorageDescriptor {
            module_id: "claustrum".into(),
            storage_namespace: format!("taxonomy-{tag}"),
            isolation: cortexkit_store::Isolation::Module,
            backend: cortexkit_store::StorageBackend::Sqlite {
                path: root.join("store.db").to_string_lossy().into_owned(),
            },
        };
        let sqlite = cortexkit_store::open_sqlite(&descriptor).unwrap();
        EncryptedStore::open(sqlite, MasterKey::from_bytes([SEED; 32])).unwrap()
    }

    /// An agent grant for [`ASKER`] on the secret's current incarnation.
    fn agent_grant(store: &EncryptedStore, id: &str, duration: &str, expiry: i64) {
        store.fenced_write(|tx| tx.execute("INSERT INTO secret_grants (grant_id,secret_name,incarnation,scope_owner,scope_kind,scope_ref,coverage,duration,expires_at_ms,granted_at_ms,envelope_sha256,asking_member_id) SELECT ?1,name,incarnation,'reserved:prefrontal-core','head','H','scope',?2,?3,?4,'envelope-hash',?5 FROM agent_secrets WHERE name='key'", rusqlite::params![id, duration, expiry, NOW, ASKER]).map(|_| ())).unwrap();
    }

    /// A flow grant for [`ASKER`] matching [`flow_call`].
    fn flow_grant(store: &EncryptedStore, id: &str) {
        let flow = flow_call().flow;
        store.fenced_write(|tx| tx.execute("INSERT INTO secret_flow_grants (grant_id,secret_name,incarnation,flow_id,flow_version,flow_code_hash,flow_install_id,methods,granted_at_ms,envelope_sha256,asking_member_id) SELECT ?1,name,incarnation,?2,?3,?4,?5,'[\"GET\"]',?6,'envelope-hash',?7 FROM agent_secrets WHERE name='key'", rusqlite::params![id, flow.flow_id, flow.version, flow.code_hash, flow.install_id, NOW, ASKER]).map(|_| ())).unwrap();
    }

    fn count(store: &EncryptedStore, query: &str) -> i64 {
        store
            .store
            .with_conn(|c| c.query_row(query, [], |r| r.get(0)))
            .unwrap()
    }

    fn releases(store: &EncryptedStore) -> i64 {
        count(
            store,
            "SELECT COUNT(*) FROM audit_log WHERE op='secret_first_release'",
        )
    }

    fn refusals(store: &EncryptedStore) -> i64 {
        count(
            store,
            "SELECT COUNT(*) FROM auth_events WHERE credential_id='secret|key' AND detail='release_receipt'",
        )
    }

    /// The `n`th fresh seal. Every seal produces new bytes, so a reply equal to an
    /// earlier one can only have come from the receipt.
    fn sealed(n: u32) -> ForwardedUse {
        ForwardedUse::Sealed(SealedRelease {
            enc: format!("enc-{n}").into_bytes(),
            ciphertext: format!("ciphertext-{n}").into_bytes(),
        })
    }

    fn request(aad: &[u8]) -> ReleaseRequest<'_> {
        ReleaseRequest {
            requester: ASKER,
            nonce: NONCE,
            aad,
        }
    }

    /// Forward [`call`] with `aad` at `now`, counting fresh seals in `seals`.
    fn forward(
        store: &EncryptedStore,
        aad: &[u8],
        now: i64,
        seals: &Cell<u32>,
    ) -> Result<ForwardedUse, SecretError> {
        let seal = |reply: &Value| -> Result<SealedRelease, ()> {
            assert_eq!(reply["status"], "released", "{reply}");
            seals.set(seals.get() + 1);
            let ForwardedUse::Sealed(sealed) = sealed(seals.get()) else {
                unreachable!()
            };
            Ok(sealed)
        };
        store
            .secret_use_sealed(&call(), &request(aad), seal, || now)
            .map(|sealed| sealed.expect("seal"))
    }

    fn forward_flow(
        store: &EncryptedStore,
        aad: &[u8],
        now: i64,
        seals: &Cell<u32>,
    ) -> Result<ForwardedUse, SecretError> {
        let seal = |_: &Value| -> Result<SealedRelease, ()> {
            seals.set(seals.get() + 1);
            let ForwardedUse::Sealed(sealed) = sealed(seals.get()) else {
                unreachable!()
            };
            Ok(sealed)
        };
        store
            .secret_flow_use_sealed(&flow_call(), &request(aad), seal, || now)
            .map(|sealed| sealed.expect("seal"))
    }

    #[test]
    fn a_once_release_is_replayed_until_one_tick_before_expiry_and_refused_at_it() {
        let (_root, store) = setup("receipt-once");
        agent_grant(&store, "once-1", "once", NOW + LIFETIME * 2);
        let seals = Cell::new(0);
        assert_eq!(forward(&store, &aad(), NOW, &seals), Ok(sealed(1)));
        assert_eq!(
            count(&store, "SELECT COUNT(*) FROM secret_grants"),
            0,
            "the once grant is consumed"
        );
        assert_eq!(releases(&store), 1);
        let row: (String, String, String, String, Vec<u8>, Vec<u8>, i64) = store
            .store
            .with_conn(|c| {
                c.query_row(
                    "SELECT aad_sha256,incarnation,grant_kind,grant_id,enc,ciphertext,expires_at_ms FROM secret_release_receipts WHERE requester=?1 AND nonce=?2",
                    [ASKER, NONCE],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?)),
                )
            })
            .unwrap();
        assert_eq!(
            row,
            (
                phone::hex(&payload_hash(&aad())),
                FIRST.to_owned(),
                "once".to_owned(),
                "once-1".to_owned(),
                b"enc-1".to_vec(),
                b"ciphertext-1".to_vec(),
                NOW + LIFETIME
            )
        );

        // A dropped reply's retry gets the stored bytes, with no second release.
        assert_eq!(
            forward(&store, &aad(), NOW + LIFETIME - 1, &seals),
            Ok(sealed(1))
        );
        assert_eq!(seals.get(), 1);
        assert_eq!(releases(&store), 1);
        assert_eq!(refusals(&store), 0);

        // At expiry the retry is refused even though a fresh grant could release, and
        // even though no sweep has deleted the receipt.
        agent_grant(&store, "once-2", "once", NOW + LIFETIME * 2);
        assert_eq!(
            forward(&store, &aad(), NOW + LIFETIME, &seals),
            Err(SecretError::NotFound)
        );
        assert_eq!(seals.get(), 1);
        assert_eq!(releases(&store), 1);
        assert_eq!(refusals(&store), 1);
        assert_eq!(
            count(
                &store,
                "SELECT COUNT(*) FROM secret_grants WHERE grant_id='once-2'"
            ),
            1,
            "nothing is consumed"
        );
        assert_eq!(
            count(&store, "SELECT COUNT(*) FROM secret_pending_requests"),
            0
        );
        assert_eq!(
            count(&store, "SELECT COUNT(*) FROM secret_release_receipts"),
            1
        );
    }

    #[test]
    fn other_aad_bytes_for_the_same_nonce_are_refused_and_leave_the_receipt() {
        let (_root, store) = setup("receipt-aad");
        agent_grant(&store, "always", "permanent", 0);
        let seals = Cell::new(0);
        assert_eq!(forward(&store, &aad(), NOW, &seals), Ok(sealed(1)));
        let respaced = String::from_utf8(aad()).unwrap().replace("\",\"", "\", \"");
        let other_key = String::from_utf8(aad()).unwrap().replace("kem-1", "kem-2");
        for (n, other) in [respaced, other_key].iter().enumerate() {
            assert_eq!(
                forward(&store, other.as_bytes(), NOW + 1, &seals),
                Err(SecretError::NotFound)
            );
            assert_eq!(refusals(&store), n as i64 + 1);
        }
        assert_eq!(seals.get(), 1);
        assert_eq!(releases(&store), 1);
        // The exact bytes still replay.
        assert_eq!(forward(&store, &aad(), NOW + 2, &seals), Ok(sealed(1)));
    }

    #[test]
    fn an_expired_hour_or_session_grant_ends_replay_before_its_receipt_expires() {
        for duration in ["hour", "session"] {
            let (_root, store) = setup(&format!("receipt-timed-{duration}"));
            agent_grant(&store, "timed", duration, NOW + 1_000);
            let seals = Cell::new(0);
            assert_eq!(forward(&store, &aad(), NOW, &seals), Ok(sealed(1)));
            assert_eq!(forward(&store, &aad(), NOW + 999, &seals), Ok(sealed(1)));
            assert_eq!(
                forward(&store, &aad(), NOW + 1_000, &seals),
                Err(SecretError::NotFound)
            );
            assert_eq!(refusals(&store), 1);
            assert_eq!(seals.get(), 1);
            // Refused by its own expiry check: the grant has not been swept.
            assert_eq!(count(&store, "SELECT COUNT(*) FROM secret_grants"), 1);
        }
    }

    #[test]
    fn revoking_the_grant_ends_replay() {
        let (_root, store) = setup("receipt-revoke");
        agent_grant(&store, "always", "permanent", 0);
        let seals = Cell::new(0);
        assert_eq!(forward(&store, &aad(), NOW, &seals), Ok(sealed(1)));
        store
            .secret_operator_revoke_audited("always", "operator")
            .unwrap();
        assert_eq!(
            forward(&store, &aad(), NOW + 1, &seals),
            Err(SecretError::NotFound)
        );
        assert_eq!(refusals(&store), 1);
        assert_eq!(seals.get(), 1);
    }

    #[test]
    fn deleting_and_recreating_the_secret_ends_replay() {
        let (_root, store) = setup("receipt-recreate");
        agent_grant(&store, "always", "permanent", 0);
        let seals = Cell::new(0);
        assert_eq!(forward(&store, &aad(), NOW, &seals), Ok(sealed(1)));
        store
            .secret_operator_delete_audited("key", "operator")
            .unwrap();
        seed(&store, SECOND);
        // A live grant on the new incarnation must not let the old nonce through.
        agent_grant(&store, "again", "permanent", 0);
        assert_eq!(
            forward(&store, &aad(), NOW + 1, &seals),
            Err(SecretError::NotFound)
        );
        assert_eq!(refusals(&store), 1);
        assert_eq!(seals.get(), 1);
        assert_eq!(releases(&store), 1);
    }

    #[test]
    fn a_flow_release_replays_until_its_flow_grants_are_revoked() {
        let (_root, store) = setup("receipt-flow");
        flow_grant(&store, "flow-1");
        let seals = Cell::new(0);
        assert_eq!(forward_flow(&store, &aad(), NOW, &seals), Ok(sealed(1)));
        assert_eq!(releases(&store), 1);
        assert_eq!(forward_flow(&store, &aad(), NOW + 1, &seals), Ok(sealed(1)));
        // An agent call can never be answered by a flow release's receipt.
        agent_grant(&store, "always", "permanent", 0);
        assert_eq!(
            forward(&store, &aad(), NOW + 1, &seals),
            Err(SecretError::NotFound)
        );
        assert_eq!(
            store
                .revoke_flow_grants_from("install-A", None, ASKER)
                .unwrap(),
            1
        );
        assert_eq!(
            forward_flow(&store, &aad(), NOW + 2, &seals),
            Err(SecretError::NotFound)
        );
        assert_eq!(refusals(&store), 2);
        assert_eq!(seals.get(), 1);
        assert_eq!(releases(&store), 1);
    }

    #[test]
    fn receipts_survive_restart_and_are_swept_after_expiry() {
        let tag = "receipt-restart";
        let (root, store) = setup(tag);
        agent_grant(&store, "once-1", "once", NOW + LIFETIME * 2);
        let seals = Cell::new(0);
        assert_eq!(forward(&store, &aad(), NOW, &seals), Ok(sealed(1)));
        drop(store);
        let store = reopen(&root, tag);
        assert_eq!(forward(&store, &aad(), NOW + 1, &seals), Ok(sealed(1)));
        assert_eq!(releases(&store), 1);
        // A local call that reaches the write path sweeps; before expiry it keeps the
        // receipt, at expiry it deletes it.
        for (now, left) in [(NOW + LIFETIME - 1, 1), (NOW + LIFETIME, 0)] {
            let _ = store.secret_use(&call(), || now);
            assert_eq!(
                count(&store, "SELECT COUNT(*) FROM secret_release_receipts"),
                left
            );
        }
    }

    #[test]
    fn a_failed_lookup_or_seal_decides_nothing() {
        let (_root, store) = setup("receipt-transient");
        agent_grant(&store, "once-1", "once", NOW + LIFETIME * 2);
        let seals = Cell::new(0);
        // A seal failure rolls the release back: the grant stays, nothing is audited.
        assert_eq!(
            store.secret_use_sealed(&call(), &request(&aad()), |_| Err("no key"), || NOW),
            Ok(Err("no key"))
        );
        assert_eq!(count(&store, "SELECT COUNT(*) FROM secret_grants"), 1);
        assert_eq!(releases(&store), 0);
        assert_eq!(
            count(&store, "SELECT COUNT(*) FROM secret_release_receipts"),
            0
        );
        assert_eq!(forward(&store, &aad(), NOW, &seals), Ok(sealed(1)));
        // A receipt lookup that fails keeps its transient code, audits no refusal and
        // leaves the receipt for the next retry to judge afresh.
        let hide = "ALTER TABLE secret_release_receipts RENAME TO hidden_receipts";
        let restore = "ALTER TABLE hidden_receipts RENAME TO secret_release_receipts";
        store.store.with_conn(|c| c.execute_batch(hide)).unwrap();
        assert_eq!(
            forward(&store, &aad(), NOW + 1, &seals),
            Err(SecretError::StoreError)
        );
        store.store.with_conn(|c| c.execute_batch(restore)).unwrap();
        assert_eq!(refusals(&store), 0);
        assert_eq!(forward(&store, &aad(), NOW + 2, &seals), Ok(sealed(1)));
        assert_eq!(seals.get(), 1);
        assert_eq!(releases(&store), 1);
    }

    #[test]
    fn concurrent_duplicates_consume_and_audit_once() {
        let (_root, store) = setup("receipt-concurrent");
        agent_grant(&store, "once-1", "once", NOW + LIFETIME * 2);
        let store = std::sync::Arc::new(store);
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let replies: Vec<_> = (0..2)
            .map(|_| {
                let (store, barrier) = (store.clone(), barrier.clone());
                std::thread::spawn(move || {
                    barrier.wait();
                    let seals = Cell::new(0);
                    let reply = forward(&store, &aad(), NOW, &seals);
                    (reply, seals.get())
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|t| t.join().unwrap())
            .collect();
        assert_eq!(replies[0].0, Ok(sealed(1)));
        assert_eq!(replies[1].0, Ok(sealed(1)));
        assert_eq!(replies[0].1 + replies[1].1, 1, "exactly one fresh seal");
        assert_eq!(releases(&store), 1);
        assert_eq!(count(&store, "SELECT COUNT(*) FROM secret_grants"), 0);
    }

    #[test]
    fn a_local_asker_or_malformed_nonce_is_refused_before_any_lookup() {
        let (_root, store) = setup("receipt-params");
        let aad = aad();
        let upper = NONCE.to_uppercase();
        for (requester, nonce) in [("", NONCE), (ASKER, "0123"), (ASKER, upper.as_str())] {
            let request = ReleaseRequest {
                requester,
                nonce,
                aad: &aad,
            };
            assert_eq!(
                store.secret_use_sealed(
                    &call(),
                    &request,
                    |_| Ok::<_, ()>(SealedRelease {
                        enc: vec![],
                        ciphertext: vec![]
                    }),
                    || NOW
                ),
                Err(SecretError::InvalidParams)
            );
        }
    }

    /// The `payload_hash` an audit row holds for `fields`, computed the way
    /// `phone::audit` computes it.
    fn audited(fields: &[&[u8]]) -> String {
        let mut payload = Vec::new();
        for field in fields {
            agent_secret::push_field(&mut payload, field);
        }
        phone::hex(&payload_hash(&payload))
    }

    fn release_audit_hashes(store: &EncryptedStore) -> Vec<String> {
        store
            .store
            .with_conn(|c| {
                c.prepare("SELECT payload_hash FROM audit_log WHERE op='secret_first_release' ORDER BY seq")?
                    .query_map([], |r| r.get(0))?
                    .collect()
            })
            .unwrap()
    }

    #[test]
    fn a_forwarded_release_audits_its_asker_and_a_local_release_audits_what_it_always_did() {
        let (_root, store) = setup("receipt-audit-asker");
        // A local permanent grant (asker '') and a forwarded permanent grant for ASKER.
        store.fenced_write(|tx| tx.execute("INSERT INTO secret_grants (grant_id,secret_name,incarnation,scope_owner,scope_kind,scope_ref,coverage,duration,expires_at_ms,granted_at_ms,envelope_sha256,asking_member_id) SELECT 'local-1',name,incarnation,'reserved:prefrontal-core','head','H','scope','permanent',0,?1,'envelope-hash','' FROM agent_secrets WHERE name='key'", [NOW]).map(|_| ())).unwrap();
        agent_grant(&store, "forwarded-1", "permanent", 0);
        store.secret_use(&call(), || NOW).unwrap();
        let seals = Cell::new(0);
        assert_eq!(forward(&store, &aad(), NOW, &seals), Ok(sealed(1)));
        assert_eq!(
            release_audit_hashes(&store),
            vec![
                // Local: the grant id and incarnation only, byte for byte as before.
                audited(&[b"local-1", FIRST.as_bytes()]),
                // Forwarded: the same fields, then the asking member.
                audited(&[b"forwarded-1", FIRST.as_bytes(), ASKER.as_bytes()]),
            ]
        );

        // Flow releases follow the same rule.
        let flow = flow_call().flow;
        store.fenced_write(|tx| tx.execute("INSERT INTO secret_flow_grants (grant_id,secret_name,incarnation,flow_id,flow_version,flow_code_hash,flow_install_id,methods,granted_at_ms,envelope_sha256,asking_member_id) SELECT 'local-flow',name,incarnation,?1,?2,?3,?4,'[\"GET\"]',?5,'envelope-hash','' FROM agent_secrets WHERE name='key'", rusqlite::params![flow.flow_id, flow.version, flow.code_hash, flow.install_id, NOW]).map(|_| ())).unwrap();
        flow_grant(&store, "forwarded-flow");
        store.secret_flow_use(&flow_call(), || NOW).unwrap();
        let flow_aad = aad().iter().rev().copied().collect::<Vec<_>>();
        let flow_request = ReleaseRequest {
            requester: ASKER,
            nonce: SECOND,
            aad: &flow_aad,
        };
        store
            .secret_flow_use_sealed(
                &flow_call(),
                &flow_request,
                |_| {
                    Ok::<_, ()>(SealedRelease {
                        enc: vec![1],
                        ciphertext: vec![2],
                    })
                },
                || NOW,
            )
            .unwrap()
            .unwrap();
        let version = flow.version.to_string();
        let hashes = release_audit_hashes(&store);
        assert_eq!(
            hashes[2..],
            [
                audited(&[
                    b"local-flow",
                    FIRST.as_bytes(),
                    flow.flow_id.as_bytes(),
                    version.as_bytes()
                ]),
                audited(&[
                    b"forwarded-flow",
                    FIRST.as_bytes(),
                    flow.flow_id.as_bytes(),
                    version.as_bytes(),
                    ASKER.as_bytes()
                ]),
            ]
        );
    }
}

/// The diagnostic rows a vault whose secret home is elsewhere writes for the calls it
/// forwards: one per outcome, except a release, which is written once per sender and
/// secret so releases never push refusal rows out of the trimmed table.
#[cfg(test)]
mod forward_audit_tests {
    use super::*;
    use crate::store::taxonomy_tests::rig;

    fn forward_rows(store: &EncryptedStore) -> Vec<(String, String, String, String)> {
        let mut rows: Vec<_> = store
            .recent_auth_events(1_000)
            .unwrap()
            .into_iter()
            .filter(|row| row.kind == "secret_forward")
            .map(|row| {
                (
                    row.credential_id,
                    row.detail.unwrap_or_default(),
                    row.principal_kind.unwrap_or_default(),
                    row.principal_id.unwrap_or_default(),
                )
            })
            .collect();
        rows.sort();
        rows
    }

    #[test]
    fn every_outcome_but_a_release_writes_a_row_and_a_release_writes_one_per_sender() {
        let (_root, store) = rig("secret-forward-audit", 68);
        store.record_secret_forward(SecretSender::Aft, Some("key"), "approval_required");
        store.record_secret_forward(SecretSender::Aft, Some("key"), "not_found");
        store.record_secret_forward(SecretSender::Aft, Some("key"), "not_found");
        for _ in 0..3 {
            store.record_secret_forward(SecretSender::Aft, Some("key"), "released");
        }
        // Another sender's first release of the same secret is its own row.
        store.record_secret_forward(SecretSender::Cerebellum, Some("key"), "released");
        store.record_secret_forward(SecretSender::Basal, None, "revoked");
        let row = |subject: &str, detail: &str, module: &str| {
            (
                subject.to_owned(),
                detail.to_owned(),
                "reserved".to_owned(),
                module.to_owned(),
            )
        };
        assert_eq!(
            forward_rows(&store),
            vec![
                row("secret-use|unaddressed", "revoked", "basal"),
                row("secret|key", "approval_required", "aft"),
                row("secret|key", "not_found", "aft"),
                row("secret|key", "not_found", "aft"),
                row("secret|key", "released", "aft"),
                row("secret|key", "released", "cerebellum"),
            ]
        );
    }
}
