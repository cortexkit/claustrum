//! Partner-only GitHub token minting. The cache shares provider work, never authorization.

use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Mutex, OnceLock, Weak},
    time::Duration,
};

use credentials_core::{
    refresh_adapters::{
        github_app::{mint_narrowed_installation_token, GithubNarrowedInstallationError},
        HttpTransport,
    },
    secret::SecretString,
    store::{
        EncryptedStore, PolicyTokenError, PolicyTokenHandoff, PolicyTokenPlan, PolicyTokenRecord,
        PolicyTokenRecordKey, PolicyTokenRequest,
    },
    ReqwestTransport,
};
use serde::Serialize;
use serde_json::{json, Value};
use subc_protocol::{EnvelopeHeader, Frame};
use tokio::sync::{mpsc, watch};

use crate::{
    read_surface::{ErrorClass, ReadError},
    ModuleError,
};

pub(crate) const OP_POLICY_TOKEN: &str = "credential.policy_token";
const MIN_POLICY_TOKEN_CACHE_TTL_MS: i64 = 5 * 60 * 1_000 + 1;
const POLICY_TOKEN_MINT_TIME_LIMIT: Duration = Duration::from_secs(30);

#[derive(PartialEq, Eq, Hash)]
struct Key {
    identity: String,
    record: PolicyTokenRecordKey,
    repositories: Vec<String>,
    permissions: BTreeMap<String, String>,
}

#[derive(Serialize)]
struct Token {
    token: SecretString,
    expires_at_ms: i64,
    repositories: Vec<String>,
    permissions: BTreeMap<String, String>,
}

impl Token {
    fn cacheable(&self, now: i64) -> bool {
        self.expires_at_ms.saturating_sub(now) >= MIN_POLICY_TOKEN_CACHE_TTL_MS
    }
}

#[derive(Clone, Copy, Serialize)]
struct Refusal {
    code: &'static str,
    class: ErrorClass,
}

impl Refusal {
    const GITHUB_UNAVAILABLE: Self = Self::transient("github_unavailable");
    const STORE_ERROR: Self = Self::transient("store_error");

    const fn permanent(code: &'static str) -> Self {
        Self {
            code,
            class: ErrorClass::Permanent,
        }
    }

    const fn transient(code: &'static str) -> Self {
        Self {
            code,
            class: ErrorClass::Transient,
        }
    }

    fn read(code: &'static str, error: ReadError) -> Self {
        Self {
            code,
            class: error.class(),
        }
    }
}

impl From<PolicyTokenError> for Refusal {
    fn from(error: PolicyTokenError) -> Self {
        use PolicyTokenError::*;
        match error {
            NotFound => Self::read("not_found", ReadError::NotFound),
            StoreError => Self::STORE_ERROR,
            // Only prepare can produce this; its caller sends a transport error.
            InvalidParams => Self::permanent("invalid_params"),
            VersionNotActive => Self::permanent("policy_version_not_active"),
            ApprovalRequired => Self::permanent("approval_required"),
            ApprovalInvalid => Self::permanent("approval_invalid"),
            ApprovalPolicyChanged => Self::permanent("approval_policy_changed"),
            ScopeUnavailable => Self::permanent("policy_token_scope_unavailable"),
            NotInstalled => Self::permanent("not_installed"),
            NeedsReauth => Self::read("needs_reauth", ReadError::NeedsReauth),
            Corrupt => Self::read("corrupt", ReadError::Corrupt),
            VaultLocked => Self::read("vault_locked", ReadError::VaultLocked),
            InstallationUnusable => Self::permanent("installation_unusable"),
            Expired => Self::GITHUB_UNAVAILABLE,
        }
    }
}

impl From<GithubNarrowedInstallationError> for Refusal {
    fn from(error: GithubNarrowedInstallationError) -> Self {
        use GithubNarrowedInstallationError::*;
        match error {
            GithubUnavailable => Self::GITHUB_UNAVAILABLE,
            ScopeUnavailable => Self::permanent("policy_token_scope_unavailable"),
            ScopeMismatch => Self::permanent("policy_token_scope_mismatch"),
            InstallationUnusable => Self::permanent("installation_unusable"),
            InstallationSuspended => Self::permanent("installation_suspended"),
        }
    }
}

type Mint = Result<Arc<Token>, Refusal>;
type Flight = watch::Receiver<Option<Mint>>;
#[cfg(test)]
type TestClock = Arc<dyn Fn() -> i64 + Send + Sync>;

#[derive(Default)]
struct Entry {
    cached: Option<Arc<Token>>,
    flight: Weak<Flight>,
}

#[derive(Default)]
pub(crate) struct PolicyTokens {
    entries: Mutex<HashMap<Arc<Key>, Entry>>,
    live_http: OnceLock<Result<ReqwestTransport, Refusal>>,
    #[cfg(test)]
    pub(crate) http: Mutex<Option<Arc<dyn HttpTransport>>>,
    #[cfg(test)]
    pub(crate) clock: Mutex<Option<TestClock>>,
    #[cfg(test)]
    pub(crate) joined: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
}

impl PolicyTokens {
    fn now(&self) -> i64 {
        #[cfg(test)]
        if let Some(clock) = self.clock.lock().unwrap().clone() {
            return clock();
        }
        crate::read_surface::now_ms()
    }

    /// Keep a completed mint available while recipients finish their release checks.
    /// A refused recipient neither publishes a cached token nor cuts other waiters off.
    async fn candidate(
        self: &Arc<Self>,
        store: Arc<EncryptedStore>,
        key: Arc<Key>,
        record: PolicyTokenRecord,
    ) -> Result<(Arc<Token>, Option<Arc<Flight>>), Refusal> {
        let flight = {
            let now = self.now();
            let mut entries = self.entries.lock().unwrap();
            entries.retain(|_, entry| {
                if entry
                    .cached
                    .as_ref()
                    .is_some_and(|token| !token.cacheable(now))
                {
                    entry.cached = None;
                }
                entry.cached.is_some() || entry.flight.strong_count() != 0
            });
            let entry = entries.entry(Arc::clone(&key)).or_default();
            if let Some(token) = &entry.cached {
                return Ok((Arc::clone(token), None));
            }
            if let Some(flight) = entry.flight.upgrade() {
                #[cfg(test)]
                if let Some(signal) = self.joined.lock().unwrap().take() {
                    let _ = signal.send(());
                }
                flight
            } else {
                let (publish, flight) = watch::channel(None);
                let flight = Arc::new(flight);
                entry.flight = Arc::downgrade(&flight);
                let keep_alive = Arc::clone(&flight);
                let cache = Arc::clone(self);
                tokio::spawn(async move {
                    let deadline = tokio::time::Instant::now() + POLICY_TOKEN_MINT_TIME_LIMIT;
                    let minted =
                        tokio::time::timeout_at(deadline, cache.mint(store, key, record)).await;
                    let minted = if tokio::time::Instant::now() >= deadline {
                        Err(Refusal::GITHUB_UNAVAILABLE)
                    } else {
                        minted.unwrap_or(Err(Refusal::GITHUB_UNAVAILABLE))
                    };
                    publish.send_replace(Some(minted));
                    drop(keep_alive);
                });
                flight
            }
        };
        let mut result = Flight::clone(&flight);
        let token = result
            .wait_for(Option::is_some)
            .await
            .map_err(|_| Refusal::GITHUB_UNAVAILABLE)?
            .clone()
            .ok_or(Refusal::GITHUB_UNAVAILABLE)??;
        Ok((token, Some(flight)))
    }

    async fn mint(
        &self,
        store: Arc<EncryptedStore>,
        key: Arc<Key>,
        record: PolicyTokenRecord,
    ) -> Mint {
        let id = Arc::clone(&key);
        let material = tokio::task::spawn_blocking(move || {
            store.open_policy_token_material(&id.identity, record)
        })
        .await
        .map_err(|_| Refusal::STORE_ERROR)??;
        #[cfg(test)]
        let available = self.http.lock().unwrap().clone();
        #[cfg(test)]
        let injected = available.as_deref();
        #[cfg(not(test))]
        let injected = None;
        let http: &dyn HttpTransport = match injected {
            Some(http) => http,
            None => self
                .live_http
                .get_or_init(|| ReqwestTransport::new().map_err(|_| Refusal::GITHUB_UNAVAILABLE))
                .as_ref()
                .map_err(|error| *error)?,
        };
        let token = mint_narrowed_installation_token(
            &key.identity,
            &material,
            &key.repositories,
            &key.permissions,
            http,
        )
        .await?;
        Ok(Arc::new(Token {
            token: token.access_token,
            expires_at_ms: token.expires_at_ms,
            repositories: token.repositories,
            permissions: token.permissions,
        }))
    }

    async fn issue(
        self: &Arc<Self>,
        store: &Arc<EncryptedStore>,
        module_id: Arc<str>,
        request: Arc<PolicyTokenRequest>,
        plan: PolicyTokenPlan,
    ) -> Mint {
        let PolicyTokenPlan {
            mut record,
            repositories,
            permissions,
            approval_leg,
        } = plan;
        for retry in [false, true] {
            let key = Arc::new(Key {
                identity: request.identity.clone(),
                record: record.key.clone(),
                repositories: repositories.clone(),
                permissions: permissions.clone(),
            });
            let (token, flight) = match self
                .candidate(Arc::clone(store), Arc::clone(&key), record)
                .await
            {
                Ok(candidate) => candidate,
                Err(error) if !retry => {
                    let store = Arc::clone(store);
                    let module_id = Arc::clone(&module_id);
                    let request = Arc::clone(&request);
                    let cache = Arc::clone(self);
                    // Reuse the read-only gates without advancing the approval or
                    // following a replacement for a caller whose grant was revoked.
                    let current = tokio::task::spawn_blocking(move || {
                        store.prepare_policy_token(&module_id, Some(&request), || cache.now())
                    })
                    .await;
                    match current {
                        Ok(Ok(current))
                            if current.record.key != key.record
                                && current.approval_leg == approval_leg =>
                        {
                            record = current.record;
                            continue;
                        }
                        _ => return Err(error),
                    }
                }
                Err(error) => return Err(error),
            };
            let decision = {
                let store = Arc::clone(store);
                let module_id = Arc::clone(&module_id);
                let request = Arc::clone(&request);
                let key = Arc::clone(&key);
                let cache = Arc::clone(self);
                let expires_at_ms = token.expires_at_ms;
                tokio::task::spawn_blocking(move || {
                    store.handoff_policy_token(
                        &module_id,
                        &request,
                        &key.record,
                        expires_at_ms,
                        approval_leg,
                        || cache.now(),
                    )
                })
                .await
                .map_err(|_| Refusal::STORE_ERROR)??
            };
            match decision {
                PolicyTokenHandoff::Released => {
                    if let Some(flight) = flight.filter(|_| token.cacheable(self.now())) {
                        let mut entries = self.entries.lock().unwrap();
                        if let Some(entry) = entries
                            .get_mut(&key)
                            .filter(|entry| entry.flight.ptr_eq(&Arc::downgrade(&flight)))
                        {
                            entry.cached = Some(Arc::clone(&token));
                        }
                    }
                    return Ok(token);
                }
                PolicyTokenHandoff::RecordChanged(current) => {
                    self.entries.lock().unwrap().remove(&key);
                    if retry {
                        break;
                    }
                    record = current;
                }
            }
        }
        Err(Refusal::GITHUB_UNAVAILABLE)
    }
}

pub(crate) async fn serve(
    header: EnvelopeHeader,
    writer: &mpsc::Sender<Frame>,
    store: &Arc<EncryptedStore>,
    cache: &Arc<PolicyTokens>,
    module_id: &str,
    params: &Value,
) -> Result<(), ModuleError> {
    let module_id: Arc<str> = module_id.into();
    let params = params.clone();
    let prepared = {
        let store = Arc::clone(store);
        let module_id = Arc::clone(&module_id);
        let cache = Arc::clone(cache);
        tokio::task::spawn_blocking(move || {
            let request = params
                .is_object()
                .then(|| serde_json::from_value(params).ok())
                .flatten();
            let plan = store.prepare_policy_token(&module_id, request.as_ref(), || cache.now())?;
            Ok((request.ok_or(PolicyTokenError::InvalidParams)?, plan))
        })
        .await
        .unwrap_or(Err(PolicyTokenError::StoreError))
    };
    let result = match prepared {
        Ok((request, plan)) => cache.issue(store, module_id, Arc::new(request), plan).await,
        Err(PolicyTokenError::InvalidParams) => {
            return crate::invalid_params(
                writer,
                header.ver,
                header.channel,
                header.epoch,
                header.corr,
                "invalid credential.policy_token parameters",
            )
            .await;
        }
        Err(error) => Err(error.into()),
    };
    let body = match result {
        Ok(token) => json!(token.as_ref()),
        Err(error) => json!({"error":error}),
    };
    crate::send_route_result(writer, header, crate::wrap_result(body)).await
}
