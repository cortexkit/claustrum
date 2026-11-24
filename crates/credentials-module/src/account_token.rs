//! Grant-gated, audience-scoped account tokens with an identity-bound cache.

use super::{ErrorClass, ReadSurface};
use crate::account_token_mint::{
    candidate, machine_state_path, mint, observe_refusal, signer, AccountTokenError,
    AccountTokenResult, Mint,
};
#[cfg(test)]
use crate::account_token_mint::{decode, worker_transcript, Machine, RELAY_TOKEN_AUDIENCE};
#[cfg(test)]
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use credentials_core::{
    refresh_adapters::HttpTransport,
    store::{AuthEventPrincipal, GrantOperation, ACCOUNT_TOKEN_AUDIENCES as AUDIENCES},
};
use serde::{Deserialize, Serialize};
#[cfg(test)]
use serde_json::{json, Value};
use std::{collections::HashMap, path::PathBuf, sync::Arc};
#[cfg(test)]
use subc_protocol::Principal;
use tokio::sync::{watch, Mutex};

pub(super) fn audience_admits(audience: &str, kind: &str, id: &str) -> bool {
    AUDIENCES.contains(&audience)
        && (audience != "cortexkit-hub" || (kind == "reserved" && id == "ckbus"))
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AccountTokenParams {
    pub audience: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrollment_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_ttl_ms: Option<u64>,
}

type Flight = watch::Receiver<Option<Mint>>;
#[derive(Default)]
struct Entry {
    identity: String,
    cached: Option<AccountTokenResult>,
    flight: Option<Flight>,
}

impl Entry {
    fn token(&self, now: i64, minimum: u64) -> Option<AccountTokenResult> {
        self.cached
            .as_ref()
            .filter(|token| token.expires_at_ms.saturating_sub(now) as i128 > minimum as i128)
            .cloned()
    }
}

pub(super) struct AccountTokens {
    entries: Arc<Mutex<HashMap<String, Entry>>>,
    machine_path: Option<PathBuf>,
    transport: Option<Arc<dyn HttpTransport>>,
    clock: Option<i64>,
    #[cfg(test)]
    signer_opens: std::sync::atomic::AtomicUsize,
}

impl AccountTokens {
    pub(super) fn new() -> Self {
        Self {
            entries: Arc::default(),
            machine_path: None,
            transport: None,
            clock: None,
            #[cfg(test)]
            signer_opens: 0.into(),
        }
    }
    fn now(&self) -> i64 {
        if let Some(now) = self.clock {
            return now;
        }
        super::now_ms()
    }
    fn path(&self) -> Result<PathBuf, AccountTokenError> {
        if let Some(path) = &self.machine_path {
            return Ok(path.clone());
        }
        machine_state_path(cfg!(windows), |name| std::env::var_os(name))
            .ok_or_else(AccountTokenError::login)
    }
}

async fn wait_for_flight(mut flight: Flight) -> Mint {
    loop {
        if let Some(outcome) = flight.borrow().clone() {
            return outcome;
        }
        flight
            .changed()
            .await
            .map_err(|_| AccountTokenError::network())?;
    }
}

impl ReadSurface {
    pub async fn account_token(
        self: &Arc<Self>,
        caller: &crate::federation::ingress::ScopedCaller,
        params: &AccountTokenParams,
    ) -> Mint {
        let config = &self.account_tokens;
        // Queue preflights ahead of exchange completion, so requests already
        // checking the same key can share even a failed exchange. Release the
        // guard before waiting on HTTP or on another request's result.
        let mut entries = config.entries.lock().await;
        let surface = Arc::clone(self);
        let caller = caller.clone();
        let audience = params.audience.clone();
        let enrollment_token = params.enrollment_token.clone();
        let (kind, id, candidate) = tokio::task::spawn_blocking(move || {
            let (kind, id) = surface
                .authorize_scoped_as(
                    &caller,
                    enrollment_token.as_deref(),
                    &audience,
                    GrantOperation::AccountToken,
                )
                .map_err(|_| AccountTokenError::new("not_found", ErrorClass::Permanent))?
                .principal;
            let key = candidate(&surface.engine, &surface.account_tokens.path()?)
                .map_err(|_| AccountTokenError::login())?;
            Ok((kind, id, key))
        })
        .await
        .map_err(|_| AccountTokenError::network())??;
        let minimum = params.min_ttl_ms.unwrap_or(0).max(60_000);
        if let Some(entry) = entries
            .get(&params.audience)
            .filter(|entry| entry.identity == candidate.identity)
        {
            if let Some(token) = entry.token(config.now(), minimum) {
                return Ok(token);
            }
            if let Some(flight) = entry.flight.clone() {
                drop(entries);
                return wait_for_flight(flight).await;
            }
        }
        let identity = candidate.identity.clone();
        let surface = Arc::clone(self);
        let signer = tokio::task::spawn_blocking(move || {
            #[cfg(test)]
            surface
                .account_tokens
                .signer_opens
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            signer(&surface.engine, candidate)
        })
        .await
        .map_err(|_| AccountTokenError::network())??;

        let flight = {
            let (sender, receiver) = watch::channel(None);
            let entry = entries.entry(params.audience.clone()).or_default();
            if entry.identity != identity {
                *entry = Entry {
                    identity: identity.clone(),
                    ..Entry::default()
                };
            }
            entry.flight = Some(receiver.clone());
            let audience = params.audience.clone();
            let engine = Arc::clone(&self.engine);
            let entries = Arc::clone(&config.entries);
            let transport = config.transport.clone();
            let clock = config.clock;
            // Detached from the request so cancellation cannot strand waiters or
            // start a second mint while the first is still spending its challenge.
            tokio::spawn(async move {
                let principal = if kind == "reserved" {
                    AuthEventPrincipal::Reserved(&id)
                } else {
                    AuthEventPrincipal::Enrolled(&id)
                };
                let outcome = match transport {
                    Some(http) => {
                        mint(http.as_ref(), &signer, &audience, &engine, principal, clock).await
                    }
                    None => match credentials_core::http::ReqwestTransport::new() {
                        Ok(http) => {
                            mint(&http, &signer, &audience, &engine, principal, clock).await
                        }
                        Err(_) => {
                            let error = AccountTokenError::network();
                            observe_refusal(&engine, &audience, principal, 0, error.code).await;
                            Err(error)
                        }
                    },
                };
                let mut entries = entries.lock().await;
                if let Some(entry) = entries.get_mut(&audience) {
                    // A re-login can replace the identity while an older exchange is
                    // in flight; its result belongs only to the original waiters.
                    if entry.identity == identity {
                        if let Ok(token) = &outcome {
                            entry.cached = Some(token.clone());
                        }
                        entry.flight = None;
                    }
                }
                sender.send_replace(Some(outcome));
            });
            receiver
        };
        drop(entries);
        wait_for_flight(flight).await
    }
}

#[cfg(test)]
#[path = "account_token_tests.rs"]
mod tests;
