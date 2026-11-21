//! Daemon-only GitHub App operations. The admin surface authenticates the exact
//! request before reaching any code here.

use std::{path::PathBuf, sync::Arc, time::Duration};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use credentials_core::{
    engine::RefreshEngine,
    http::ReqwestTransport,
    refresh_adapters::{HttpResponse, HttpTransport},
    secret::Secret,
    store::{SecretHomeRole, StoreOpError},
};
use serde::{Deserialize, Serialize};
use tokio::time::{timeout_at, Instant};

use super::{store_err, AdminOutcome, ROUTE_ADMIN_ACTOR};
use crate::account_token_mint::{canonical_id, mint_relay_token, RelayTokenError};

const RELAY_OPEN_URL: &str = "https://hooks.cortexkit.io/v1/relay/github-apps/slots";
const RELAY_WEBHOOK_BASE: &str = "https://hooks.cortexkit.io/v1/github/apps";
const MAX_RELAY_REPLY_BYTES: usize = 8 * 1024;

pub(super) struct GitHubAppAdmin {
    budget: Duration,
    transport: Option<Arc<dyn HttpTransport>>,
    machine_path: Option<PathBuf>,
    clock: Option<i64>,
}

impl Default for GitHubAppAdmin {
    fn default() -> Self {
        Self {
            budget: crate::federation::ADMIN_OP_BUDGET,
            transport: None,
            machine_path: None,
            clock: None,
        }
    }
}

impl GitHubAppAdmin {
    /// Check serving admission within the same deadline as the operation's
    /// lock waits, token mint and HTTP work.
    async fn admit(&self, engine: &RefreshEngine) -> Result<Instant, AdminOutcome> {
        let deadline = Instant::now() + self.budget;
        let store = Arc::clone(engine.store());
        let role = timeout_at(
            deadline,
            tokio::task::spawn_blocking(move || store.secret_home_role()),
        )
        .await
        .ok()
        .and_then(Result::ok)
        .ok_or_else(|| RelayFailure::Unavailable.refusal())?;
        match role {
            SecretHomeRole::Single | SecretHomeRole::Home { .. } => Ok(deadline),
            SecretHomeRole::Remote { home_member } => {
                Err(store_err(StoreOpError::SecretHomeElsewhere { home_member }))
            }
            SecretHomeRole::RemoteSetupIncomplete { self_member } => {
                Err(store_err(StoreOpError::SecretRemoteSetupIncomplete {
                    remedy_member: self_member,
                }))
            }
            SecretHomeRole::StoreError => Err(RelayFailure::Unavailable.refusal()),
        }
    }

    pub(super) async fn relay_slot_open(&self, engine: &Arc<RefreshEngine>) -> AdminOutcome {
        let deadline = match self.admit(engine).await {
            Ok(deadline) => deadline,
            Err(refusal) => return refusal,
        };
        let reply = match timeout_at(deadline, self.request_slot(engine, deadline)).await {
            Ok(Ok(reply)) => reply,
            Ok(Err(failure)) => return failure.refusal(),
            Err(_) => return RelayFailure::Unavailable.refusal(),
        };

        // There is no local slot record to roll back. If audit fails, don't hand
        // out the URL; the pending slot will expire at the relay.
        if engine
            .store()
            .audit_github_app_relay_slot_open(&reply.slot, ROUTE_ADMIN_ACTOR)
            .is_err()
        {
            return AdminOutcome::Refused(
                "audit_write_failed/permanent: could not record the confirmed relay slot".into(),
            );
        }
        AdminOutcome::Ok(serde_json::json!(reply))
    }

    async fn request_slot(
        &self,
        engine: &Arc<RefreshEngine>,
        deadline: Instant,
    ) -> Result<SlotOpenReply, RelayFailure> {
        let transport;
        let http = match &self.transport {
            Some(http) => http.as_ref(),
            None => {
                // The shared transport never follows redirects, including on requests
                // carrying a bearer token or machine proof.
                transport = ReqwestTransport::new().map_err(|_| RelayFailure::Unavailable)?;
                &transport
            }
        };
        let token = mint_relay_token(engine, http, self.machine_path.clone(), self.clock)
            .await
            .map_err(|error| match error {
                RelayTokenError::NoMachineKey => RelayFailure::UnavailableForAccount,
                RelayTokenError::MintFailed => RelayFailure::Unavailable,
            })?;
        if Instant::now() >= deadline {
            return Err(RelayFailure::Unavailable);
        }
        let authorization = Secret::new(format!("Bearer {}", token.jwt.expose()));
        let reply = http
            .post(
                RELAY_OPEN_URL,
                &[("Authorization", authorization.expose().as_str())],
                "application/json",
                Vec::new(),
            )
            .await
            .map_err(|_| RelayFailure::Unavailable)?;
        confirmed_slot(reply)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RelayFailure {
    UnavailableForAccount,
    SlotLimit,
    Unavailable,
    RequestRefused,
    ReplyInvalid,
}

impl RelayFailure {
    fn refusal(self) -> AdminOutcome {
        let message = match self {
            Self::UnavailableForAccount => {
                "relay_unavailable_for_account/permanent: the relay is unavailable for this account"
            }
            Self::SlotLimit => "relay_slot_limit/permanent: the account's relay slots are full",
            Self::Unavailable => "relay_unavailable/transient: could not open a relay slot",
            Self::RequestRefused => {
                "relay_request_refused/permanent: the relay refused the request"
            }
            Self::ReplyInvalid => {
                "relay_reply_invalid/permanent: the relay did not return a valid slot"
            }
        };
        AdminOutcome::Refused(message.into())
    }
}

#[derive(Deserialize, Serialize)]
struct SlotOpenReply {
    slot: String,
    webhook_url: String,
    expires_at: String,
}

fn confirmed_slot(reply: HttpResponse) -> Result<SlotOpenReply, RelayFailure> {
    match reply.status {
        201 => {}
        401 | 403 | 404 => return Err(RelayFailure::UnavailableForAccount),
        409 => return Err(RelayFailure::SlotLimit),
        300..=399 | 429 | 500..=599 => return Err(RelayFailure::Unavailable),
        400..=499 => return Err(RelayFailure::RequestRefused),
        _ => return Err(RelayFailure::ReplyInvalid),
    }
    if reply.body.len() > MAX_RELAY_REPLY_BYTES {
        return Err(RelayFailure::ReplyInvalid);
    }
    let slot: SlotOpenReply =
        serde_json::from_slice(&reply.body).map_err(|_| RelayFailure::ReplyInvalid)?;
    if !valid_relay_slot(&slot.slot)
        || slot.webhook_url != format!("{RELAY_WEBHOOK_BASE}/{}/webhook", slot.slot)
        || chrono::DateTime::parse_from_rfc3339(&slot.expires_at).is_err()
    {
        return Err(RelayFailure::ReplyInvalid);
    }
    Ok(slot)
}

pub(super) fn valid_relay_slot(slot: &str) -> bool {
    slot.split_once('.').is_some_and(|(id, tag)| {
        canonical_id(id) && tag.len() == 22 && URL_SAFE_NO_PAD.decode(tag).is_ok()
    })
}

#[cfg(test)]
#[path = "github_app_admin_tests.rs"]
mod tests;
