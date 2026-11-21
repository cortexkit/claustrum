//! Admission and atomic minting of pending broker action approvals.

use std::collections::{HashMap, HashSet};

use ring::rand::{SecureRandom, SystemRandom};
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::{
    agent_policy::{valid_app_slug, AgentPolicy, Approval, Class, Identity, Kind},
    audit::{AuditOp, AuditRecord},
    broker_action::{
        valid_context, valid_method, valid_statement_host, valid_ulid, BrokerActionField,
        BrokerActionLeg, BrokerActionScope, BrokerActionShape, BrokerActionStatement, FieldValue,
        MAX_STATEMENT_FIELDS, MAX_STATEMENT_LEGS,
    },
    federation::is_lower_hex_sha256,
};

use super::{
    agent_policy::active_agent_policy_conn,
    append_audit_tx,
    policy_token::{has_exact_grant, serving_role, PolicyTokenError},
    EncryptedStore,
};

const BROKER_ACTION_LIFETIME_LIMIT_MS: i64 = 10 * 60 * 1000;
const MAX_PENDING_BROKER_ACTIONS_PER_AGENT: i64 = 16;
const MAX_PENDING_BROKER_ACTIONS: i64 = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BrokerActionRequestError {
    NotFound,
    InvalidParams,
    PolicyAbsent,
    ApprovalNotRequired,
    ConsentFieldsInvalid,
    PendingLimit,
    StoreError,
}

use BrokerActionRequestError as Error;

#[derive(Serialize)]
pub struct BrokerActionRequestReply {
    pub request_id: String,
    pub statement_b64url: String,
    pub statement_sha256: String,
    pub expires_at_ms: u64,
}

struct Request {
    service: String,
    action: String,
    host: String,
    legs: Vec<BrokerActionLeg>,
    multi_leg: bool,
    fields: Vec<BrokerActionField>,
    context: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawField {
    name: String,
    value: Value,
}

impl Request {
    // A grant and an agent mapping are checked before validating the rest of the body.
    fn parse(mut body: Map<String, Value>) -> Option<Self> {
        let service = nonempty_text(body.remove("service")?)?;
        let action = nonempty_text(body.remove("action")?)?;
        let host = nonempty_text(body.remove("host")?)?;
        if !valid_statement_host(&host) {
            return None;
        }
        let context = match body.remove("context") {
            Some(value) => {
                let text = nonempty_text(value)?;
                if !valid_context(&text) {
                    return None;
                }
                Some(text)
            }
            None => None,
        };
        let Value::Array(fields) = body.remove("fields")? else {
            return None;
        };
        if fields.len() > MAX_STATEMENT_FIELDS {
            return None;
        }
        let fields = fields
            .into_iter()
            .map(|value| {
                if !value.is_object() {
                    return None;
                }
                let field: RawField = serde_json::from_value(value).ok()?;
                Some(BrokerActionField {
                    name: field.name,
                    value: FieldValue::try_from(field.value).ok()?,
                })
            })
            .collect::<Option<_>>()?;
        let (legs, multi_leg) = if let Some(legs) = body.remove("legs") {
            let entries = legs.as_array()?;
            if !body.is_empty()
                || !(1..=MAX_STATEMENT_LEGS).contains(&entries.len())
                || entries.iter().any(|leg| !leg.is_object())
            {
                return None;
            }
            (serde_json::from_value(legs).ok()?, true)
        } else {
            // The only members remaining are the four required members of a single leg.
            let leg: BrokerActionLeg = serde_json::from_value(Value::Object(body)).ok()?;
            if leg.kind != action {
                return None;
            }
            (vec![leg], false)
        };
        if !legs
            .iter()
            .all(|leg| valid_method(&leg.method) && is_lower_hex_sha256(&leg.request_sha256))
        {
            return None;
        }
        Some(Self {
            service,
            action,
            host,
            legs,
            multi_leg,
            fields,
            context,
        })
    }
}

fn nonempty_text(value: Value) -> Option<String> {
    match value {
        Value::String(text) if !text.is_empty() => Some(text),
        _ => None,
    }
}

impl EncryptedStore {
    /// Check and mint in one writer snapshot so a role, grant or policy change
    /// cannot race the insert. Stamp decoding belongs to the route protocol.
    pub fn request_broker_action(
        &self,
        module_id: Option<&str>,
        body: Value,
        decode_stamp: impl FnOnce(Value) -> Result<(String, BrokerActionScope), Error>,
        clock: impl FnOnce() -> i64,
    ) -> Result<BrokerActionRequestReply, Error> {
        self.fenced_write(|tx| {
            self.request_broker_action_tx(tx, module_id, body, decode_stamp, clock)
        })
        .map_err(|_| Error::StoreError)?
    }

    fn request_broker_action_tx(
        &self,
        tx: &Transaction<'_>,
        module_id: Option<&str>,
        body: Value,
        decode_stamp: impl FnOnce(Value) -> Result<(String, BrokerActionScope), Error>,
        clock: impl FnOnce() -> i64,
    ) -> rusqlite::Result<Result<BrokerActionRequestReply, Error>> {
        match serving_role(tx) {
            Ok(()) => (),
            Err(PolicyTokenError::NotFound) => return Ok(Err(Error::NotFound)),
            Err(_) => return Ok(Err(Error::StoreError)),
        }
        let Some(module_id @ ("aft" | "plexus")) = module_id else {
            return Ok(Err(Error::NotFound));
        };
        let Value::Object(mut body) = body else {
            return Ok(Err(Error::InvalidParams));
        };
        let Some(identity) = body
            .remove("identity")
            .and_then(nonempty_text)
            .filter(|id| id.strip_prefix("github_app:").is_some_and(valid_app_slug))
        else {
            return Ok(Err(Error::InvalidParams));
        };
        if !has_exact_grant(tx, module_id, &identity)? {
            return Ok(Err(Error::NotFound));
        }
        let Some(stamp) = body.remove("stamp") else {
            return Ok(Err(Error::InvalidParams));
        };
        let (agent_id, scope) = match decode_stamp(stamp) {
            Ok(mapped) => mapped,
            Err(error) => return Ok(Err(error)),
        };
        let Some(request) = Request::parse(body) else {
            return Ok(Err(Error::InvalidParams));
        };

        let Some(active) = active_agent_policy_conn(tx)? else {
            return Ok(Err(Error::PolicyAbsent));
        };
        let Ok(policy) = AgentPolicy::parse_canonical(active.policy_text.as_bytes()) else {
            return Ok(Err(Error::StoreError));
        };
        let Some(kinds) = authorized_kinds(&policy, &request, &identity, &agent_id) else {
            return Ok(Err(Error::NotFound));
        };
        let agent: Option<Option<String>> = tx
            .query_row(
                "SELECT github_app_agent FROM credentials WHERE credential_id = ?1",
                [&identity],
                |row| row.get(0),
            )
            .optional()?;
        if !agent.is_some_and(|attested| attested.as_ref().is_none_or(|agent| agent == &agent_id)) {
            return Ok(Err(Error::NotFound));
        }
        if kinds.iter().any(|kind| kind.approval != Approval::Once) {
            return Ok(Err(Error::ApprovalNotRequired));
        }
        let Some(fields) = order_fields(kinds, request.fields) else {
            return Ok(Err(Error::ConsentFieldsInvalid));
        };

        let created_at_ms = clock();
        let Some(expires_at_ms) = created_at_ms
            .checked_add(BROKER_ACTION_LIFETIME_LIMIT_MS)
            .filter(|_| created_at_ms >= 0)
            .map(|expiry| expiry as u64)
        else {
            return Ok(Err(Error::InvalidParams));
        };
        let request_id = next_request_id(tx, created_at_ms as u64)?;
        let first_leg = &request.legs[0];
        let shape = if request.multi_leg {
            BrokerActionShape::Legs(request.legs.clone())
        } else {
            BrokerActionShape::OneLeg {
                kind: first_leg.kind.clone(),
                method: first_leg.method.clone(),
                request_sha256: first_leg.request_sha256.clone(),
            }
        };
        let statement = BrokerActionStatement {
            request_id,
            agent_id,
            scope,
            service: request.service,
            identity,
            action: request.action,
            host: request.host,
            resource: first_leg.resource.clone(),
            policy_version: active.version as u64,
            policy_sha256: active.policy_sha256,
            fields,
            shape,
            context: request.context,
            expires_at_ms,
        };
        let Ok(checked) = statement.encode() else {
            return Ok(Err(Error::InvalidParams));
        };
        if pending_limit_reached(tx, &statement.agent_id, created_at_ms)? {
            return Ok(Err(Error::PendingLimit));
        }

        let scope_json = serde_json::to_string(&statement.scope).map_err(sql_encode_error)?;
        let legs_json = serde_json::to_string(&request.legs).map_err(sql_encode_error)?;
        let principal = format!("reserved:{module_id}");
        tx.execute(
            "INSERT INTO broker_action_requests (
                 request_id, principal, agent_id, scope_json, statement_bytes, statement_sha256,
                 policy_version, identity, legs_json, created_at_ms, expires_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                statement.request_id,
                principal,
                statement.agent_id,
                scope_json,
                checked.bytes(),
                checked.sha256(),
                active.version,
                statement.identity,
                legs_json,
                created_at_ms,
                expires_at_ms
            ],
        )?;
        append_audit_tx(
            tx,
            &self.audit_key,
            &AuditRecord {
                op: AuditOp::BrokerActionRequest,
                credential_id: Some(statement.identity),
                payload_hash: Some(checked.sha256().to_owned()),
                actor: principal,
                alarm: None,
            },
        )?;
        Ok(Ok(BrokerActionRequestReply {
            request_id: statement.request_id,
            statement_b64url: checked.b64url().to_owned(),
            statement_sha256: checked.sha256().to_owned(),
            expires_at_ms,
        }))
    }
}

fn authorized_kinds<'a>(
    policy: &'a AgentPolicy,
    request: &Request,
    identity: &str,
    agent_id: &str,
) -> Option<Vec<&'a Kind>> {
    if request.service != "github" {
        return None;
    }
    let rules = policy.rule_sets.get(&request.service)?;
    let binding = policy.bindings.iter().find(|binding| {
        binding.service == request.service
            && binding.identity == identity
            && binding.agent == agent_id
    })?;
    if !rules.hosts.contains(&request.host) {
        return None;
    }
    request
        .legs
        .iter()
        .map(|leg| {
            binding.resources.binary_search(&leg.resource).ok()?;
            rules.kinds.iter().find(|kind| {
                kind.kind == leg.kind
                    && kind.class != Class::Denied
                    && kind.identity == Identity::Agent
            })
        })
        .collect()
}

fn order_fields(
    kinds: Vec<&Kind>,
    fields: Vec<BrokerActionField>,
) -> Option<Vec<BrokerActionField>> {
    let count = fields.len();
    let mut by_name: HashMap<_, _> = fields
        .into_iter()
        .map(|field| (field.name, field.value))
        .collect();
    if by_name.len() != count {
        return None;
    }
    let mut seen = HashSet::new();
    let ordered = kinds
        .into_iter()
        .filter_map(|kind| kind.consent.as_ref())
        .flat_map(|consent| &consent.fields)
        .filter(|name| seen.insert(*name))
        .map(|name| {
            Some(BrokerActionField {
                name: name.clone(),
                value: by_name.remove(name)?,
            })
        })
        .collect::<Option<Vec<_>>>()?;
    by_name.is_empty().then_some(ordered)
}

fn pending_limit_reached(conn: &Connection, agent_id: &str, now_ms: i64) -> rusqlite::Result<bool> {
    let (agent, all): (i64, i64) = conn.query_row(
        "SELECT COUNT(CASE WHEN agent_id = ?1 THEN 1 END), COUNT(*)
         FROM broker_action_requests WHERE expires_at_ms > ?2 AND issued_legs < json_array_length(legs_json)",
        params![agent_id, now_ms],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    Ok(agent >= MAX_PENDING_BROKER_ACTIONS_PER_AGENT || all >= MAX_PENDING_BROKER_ACTIONS)
}

fn sql_encode_error(error: serde_json::Error) -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(error))
}

const CROCKFORD: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

fn next_request_id(conn: &Connection, now_ms: u64) -> rusqlite::Result<String> {
    let mut bytes = [0; 16];
    bytes[..6].copy_from_slice(&now_ms.min((1_u64 << 48) - 1).to_be_bytes()[2..]);
    SystemRandom::new()
        .fill(&mut bytes[6..])
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    let mut value = u128::from_be_bytes(bytes);
    // Every successful insert advances the largest id. The retention trigger
    // only removes rows during an insert, so a clock rollback cannot reuse an id,
    // even one from a row that's already been pruned or across a daemon restart.
    let last_id: Option<String> = conn.query_row(
        "SELECT MAX(request_id) FROM broker_action_requests",
        [],
        |row| row.get(0),
    )?;
    if let Some(last_id) = last_id {
        if !valid_ulid(&last_id) {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let last = last_id.bytes().try_fold(0_u128, |value, ch| {
            let digit = CROCKFORD.iter().position(|&digit| digit == ch)?;
            Some((value << 5) | digit as u128)
        });
        let Some(last) = last else {
            return Err(rusqlite::Error::InvalidQuery);
        };
        if value <= last {
            value = last.checked_add(1).ok_or(rusqlite::Error::InvalidQuery)?;
        }
    }
    Ok((0..26)
        .rev()
        .map(|i| char::from(CROCKFORD[((value >> (5 * i)) & 31) as usize]))
        .collect())
}
