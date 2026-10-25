//! The module-driven admin surface: authenticated write ops on the RUNNING module.
//!
//! Overview: docs/architecture.md, section 3 ("Writing"). Admin ops ride the
//! same route plane as reads, dual-gated:
//!
//! - Gate 1 (provenance pre-filter): the bind's daemon-stamped principal must be
//!   `direct`. `Reserved`, `Unverified`, and ABSENT all refuse. This removes the
//!   honest/accidental consumer class; it is NOT the adversarial boundary.
//! - Gate 2 (THE authority root): a master-key challenge-response per op. The
//!   caller MACs the exact op-body bytes with a key derived from the master key
//!   (`credentials_core::admin_auth`); the module verifies with the key it already
//!   holds, then — only after verification — parses and executes.
//!
//! Guarantee: at-most-once acceptance of an individually key-authorized operation.
//! A hostile relay can drop/delay/reorder ops and fabricate responses; it cannot
//! create or alter one, and a captured (nonce, tag) cannot authorize a second
//! execution (atomic nonce claim) or a different op (op-body binding).
//!
//! Serialization: every credential-scoped admin mutation runs under the engine's
//! per-credential single-flight lock (`RefreshEngine::with_admin_lock`) — the same
//! lock a refresh holds across its provider call and commit — so an admin write
//! can never interleave with a refresh for the same credential.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use credentials_core::admin_auth::{AdminMacKey, TranscriptParts, ADMIN_NONCE_LEN, VAULT_ID_LEN};
use credentials_core::admin_ops::AdminOpBody;
#[cfg(test)]
use credentials_core::admin_ops::ADMIN_OP_SCHEMA_V1;
use credentials_core::audit::{AuditCtx, AuditOp};
use credentials_core::engine::RefreshEngine;
use credentials_core::federation::{
    valid_member_id, MemberGrantOperation, MemberGrantSelector, VAULT_TRANSFER_ID,
};
use credentials_core::key::KeyId;
use credentials_core::record::{CredentialKind, VaultRecord};
use credentials_core::store::{EncryptedStore, GrantOperation, SelectorKind, StoreOpError};
use subc_protocol::Principal;

/// Challenge TTL. Long enough for a CLI to resolve the keychain key and MAC the op;
/// short enough that a captured nonce is stale quickly (an attacker also needs the
/// master key, so this is defense-in-depth over the authority boundary).
const NONCE_TTL: Duration = Duration::from_secs(30);

/// Hard cap on outstanding challenges across all binds. Bounds the nonce table so a
/// challenge flood cannot exhaust memory. When full, a new challenge is refused
/// (never evict another bind's live nonce — that would let a flooder cancel a real
/// admin flow). Small: admin is a human-driven, low-rate operation.
const MAX_OUTSTANDING_NONCES: usize = 128;

/// Max authenticated op-body size. Bounds MAC work and decode cost per op.
const MAX_OP_BODY_LEN: usize = 1 << 20; // 1 MiB

/// The outcome the surface hands back to the wire layer. `Refused` carries a
/// non-secret reason string; the wire maps it to a route error.
pub enum AdminOutcome {
    /// A `admin.challenge` reply.
    Challenge {
        nonce_hex: String,
        vault_id_hex: String,
        key_id_hex: String,
    },
    /// A successful op with a JSON result body.
    Ok(serde_json::Value),
    /// A refused op (gate failure, bad MAC, expired/used nonce, oversize, decode).
    Refused(String),
}

/// A single-use challenge nonce with its issue instant (for TTL).
struct Nonce {
    bytes: [u8; ADMIN_NONCE_LEN],
    issued: Instant,
}

/// Per-bind admin state, keyed by route channel. Replaced wholesale on rebind so a
/// stale epoch cannot reuse a prior bind's principal or nonce.
struct BindState {
    epoch: u32,
    principal: Principal,
    /// The opener's `BindIdentity.harness` for this bind. Read only on callosum's routes
    /// and only by the federation ingress mapping (`federation::map_route_caller`).
    /// Lives in the same record as the principal, so a rebind or route Goodbye replaces
    /// or drops both together.
    harness: String,
    /// At most one outstanding nonce per bind (issuing a new challenge replaces it).
    nonce: Option<Nonce>,
}

/// The module admin surface. Holds the engine (for the store + per-id lock), the
/// admin MAC key (derived from the master key), and the vault identity — plus the
/// per-bind registry, a global outstanding-nonce counter, and this vault's federation
/// home, which answers the calls a federation channel carries.
pub struct AdminSurface {
    engine: Arc<RefreshEngine>,
    mac_key: AdminMacKey,
    vault_id: [u8; VAULT_ID_LEN],
    key_id: KeyId,
    binds: Mutex<HashMap<u16, BindState>>,
    outstanding_nonces: AtomicU64,
    home: crate::federation::HomeVault,
    /// This vault's transfer admin ops (send, resume, accept). They share the home's
    /// outbound client, attached at startup.
    transfers: crate::federation::Transfers,
    /// The daemon's own remote reader, so `remote add` fetches and validates exactly as
    /// a consumer read does (same adapter set, same reply type). Attached at startup.
    remote: OnceLock<Arc<crate::federation::RemoteReader>>,
    /// The one budget each federation admin op's outbound calls share. Only tests
    /// shorten it.
    federation_budget: Duration,
}

/// The actor recorded in the audit trail for a route-driven admin write.
const ROUTE_ADMIN_ACTOR: &str = "route-admin";

impl AdminSurface {
    pub fn new(
        engine: Arc<RefreshEngine>,
        mac_key: AdminMacKey,
        vault_id: [u8; VAULT_ID_LEN],
        key_id: KeyId,
    ) -> Self {
        AdminSurface {
            home: crate::federation::HomeVault::new(Arc::clone(&engine)),
            transfers: crate::federation::Transfers::new(Arc::clone(engine.store())),
            remote: OnceLock::new(),
            federation_budget: crate::federation::ADMIN_OP_BUDGET,
            engine,
            mac_key,
            vault_id,
            key_id,
            binds: Mutex::new(HashMap::new()),
            outstanding_nonces: AtomicU64::new(0),
        }
    }

    /// Replace a channel's principal, harness and nonce on rebind. The wire epoch lets an
    /// in-flight request prove it still belongs to this binding before claiming a nonce.
    pub fn record_bind_at(&self, channel: u16, epoch: u32, principal: Principal, harness: &str) {
        let mut binds = self.binds.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(prev) = binds.get(&channel) {
            // Draining the replaced bind's nonce keeps the global counter honest.
            if prev.nonce.is_some() {
                self.outstanding_nonces.fetch_sub(1, Ordering::SeqCst);
            }
        }
        binds.insert(
            channel,
            BindState {
                epoch,
                principal,
                harness: harness.to_string(),
                nonce: None,
            },
        );
    }

    #[cfg(test)]
    pub fn record_bind(&self, channel: u16, principal: Principal) {
        self.record_bind_at(channel, 0, principal, "");
    }

    /// Test seam: backdate this channel's outstanding nonce so the TTL check sees it
    /// as expired, without sleeping through the real window.
    #[cfg(test)]
    fn backdate_nonce_for_test(&self, channel: u16, by: Duration) {
        let mut binds = self.binds.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(state) = binds.get_mut(&channel) {
            if let Some(nonce) = state.nonce.as_mut() {
                nonce.issued = Instant::now() - by;
            }
        }
    }

    /// Snapshot who a route bind speaks for, through the federation ingress mapping
    /// (`federation::map_route_caller`). This is the one place the request path reads a
    /// channel's principal and harness, so the mapping covers every operation. With the
    /// member-mapping gate off the answer is vault release 1's: callosum relaying
    /// another computer's call (a `fed-` harness) gets no principal. The gate is read
    /// from the store on each call, and only for callosum's routes, so turning it on or
    /// off takes effect without a restart.
    ///
    /// The route dispatcher captures this before spawning a request so a later channel
    /// rebind cannot change which caller authorized an already-accepted frame. An
    /// unbound channel speaks for no one.
    pub fn route_caller(&self, channel: u16) -> crate::federation::RouteCaller {
        let bound = {
            let binds = self.binds.lock().unwrap_or_else(|p| p.into_inner());
            binds
                .get(&channel)
                .map(|state| (state.principal.clone(), state.harness.clone()))
        };
        let Some((principal, harness)) = bound else {
            return crate::federation::RouteCaller::Principal(None);
        };
        let gate = if crate::federation::ingress::is_callosum(&principal) {
            crate::federation::MappingGate::from_store(
                self.engine.store().federation_member_mapping(),
            )
        } else {
            // Not read for anyone else: their harness is ignored in every gate state.
            crate::federation::MappingGate::Off
        };
        crate::federation::map_route_caller(&principal, &harness, gate)
    }

    /// The EFFECTIVE principal of a route bind: what [`Self::route_caller`] lends the
    /// read surface and the admin plane. `None` is what an unbound or unknown caller
    /// has, so the scoped surface answers the uniform `not_found` and the admin plane
    /// refuses; a federation or refused channel also has `None`. The request path takes
    /// the whole [`Self::route_caller`] instead, so only tests read this projection.
    #[cfg(test)]
    pub fn principal(&self, channel: u16) -> Option<Principal> {
        self.route_caller(channel).principal()
    }

    /// This vault as a federation home: what a federation channel's calls reach.
    pub fn home(&self) -> &crate::federation::HomeVault {
        &self.home
    }

    /// Attach the daemon's remote reader, which `remote add` fetches through. Only the
    /// first call takes effect; returns whether this one did.
    pub fn attach_remote_reader(&self, reader: Arc<crate::federation::RemoteReader>) -> bool {
        self.remote.set(reader).is_ok()
    }

    /// Give every federation admin op `budget` for its outbound calls instead of
    /// [`crate::federation::ADMIN_OP_BUDGET`]. A test seam with no production caller,
    /// reached by the integration tests through the test-only library, so the daemon
    /// binary itself never calls it.
    #[allow(dead_code)]
    pub fn with_federation_budget(mut self, budget: Duration) -> Self {
        self.transfers =
            crate::federation::Transfers::new(Arc::clone(self.engine.store())).with_budget(budget);
        self.federation_budget = budget;
        self
    }

    /// Forget a channel's admin state on route Goodbye. Idempotent.
    pub fn drop_bind(&self, channel: u16) {
        let mut binds = self.binds.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(prev) = binds.remove(&channel) {
            if prev.nonce.is_some() {
                self.outstanding_nonces.fetch_sub(1, Ordering::SeqCst);
            }
        }
    }

    #[cfg(test)]
    pub fn challenge(&self, channel: u16) -> AdminOutcome {
        self.challenge_as(channel, 0, self.principal(channel).as_ref())
    }

    #[cfg(test)]
    pub async fn execute(&self, channel: u16, body: &[u8], tag: &str) -> AdminOutcome {
        self.execute_as(channel, 0, self.principal(channel).as_ref(), body, tag)
            .await
    }

    /// Issue a fresh challenge nonce for a bind. Gate 1 enforced. Replaces any prior
    /// nonce on this bind (at most one outstanding per bind). Refused if the global
    /// outstanding cap is reached (never evicts another bind's nonce).
    pub fn challenge_as(
        &self,
        channel: u16,
        epoch: u32,
        principal: Option<&Principal>,
    ) -> AdminOutcome {
        if !matches!(principal, Some(Principal::Direct)) {
            return AdminOutcome::Refused("admin ops require a direct bind".into());
        }
        let nonce_bytes = match credentials_core::admin_auth::generate_admin_nonce() {
            Ok(n) => n,
            Err(e) => return AdminOutcome::Refused(format!("csprng: {e}")),
        };

        let mut binds = self.binds.lock().unwrap_or_else(|p| p.into_inner());
        // Sweep only expired challenges: a quiet peer must not hold a capacity slot
        // forever, and a flood must never evict another peer's live challenge.
        for state in binds.values_mut() {
            if state
                .nonce
                .as_ref()
                .is_some_and(|nonce| nonce.issued.elapsed() > NONCE_TTL)
            {
                state.nonce = None;
                self.outstanding_nonces.fetch_sub(1, Ordering::SeqCst);
            }
        }
        let Some(state) = binds.get_mut(&channel) else {
            return AdminOutcome::Refused("admin ops require a direct bind".into());
        };
        if state.epoch != epoch || !matches!(state.principal, Principal::Direct) {
            return AdminOutcome::Refused("admin ops require the same direct bind".into());
        }
        // Reissuing replaces this bind's own nonce (net-zero on the counter); a fresh
        // nonce needs a global slot only when this bind had none.
        if state.nonce.is_none() {
            // Reserve a global slot; refuse if full (never evict a peer's live nonce).
            let prior = self.outstanding_nonces.fetch_add(1, Ordering::SeqCst);
            if prior as usize >= MAX_OUTSTANDING_NONCES {
                self.outstanding_nonces.fetch_sub(1, Ordering::SeqCst);
                return AdminOutcome::Refused("admin challenge capacity reached".into());
            }
        }
        state.nonce = Some(Nonce {
            bytes: nonce_bytes,
            issued: Instant::now(),
        });

        AdminOutcome::Challenge {
            nonce_hex: hex(&nonce_bytes),
            vault_id_hex: hex(&self.vault_id),
            key_id_hex: self.key_id.to_hex(),
        }
    }

    /// Execute an admin op. `op_body` is the EXACT authenticated bytes; `tag_hex` is
    /// the caller's MAC over the transcript. Verify-then-claim-then-parse-then-execute:
    /// the nonce is claimed atomically only after the MAC verifies, and the body is
    /// parsed only after the nonce is claimed.
    pub async fn execute_as(
        &self,
        channel: u16,
        epoch: u32,
        principal: Option<&Principal>,
        op_body: &[u8],
        tag_hex: &str,
    ) -> AdminOutcome {
        // Gate 1 uses the principal captured when the request was accepted.
        if !matches!(principal, Some(Principal::Direct)) {
            return AdminOutcome::Refused("admin ops require a direct bind".into());
        }
        if op_body.len() > MAX_OP_BODY_LEN {
            return AdminOutcome::Refused("admin op body too large".into());
        }
        let Some(tag) = decode_hex(tag_hex) else {
            return AdminOutcome::Refused("malformed auth tag".into());
        };

        // Gate 2 + atomic nonce claim. Hold the bind lock across verify+claim so two
        // concurrent replays of the same (nonce, tag) cannot both pass — exactly one
        // claims the nonce; the other sees it already taken.
        let claimed_nonce = {
            let mut binds = self.binds.lock().unwrap_or_else(|p| p.into_inner());
            let Some(state) = binds.get_mut(&channel) else {
                return AdminOutcome::Refused("admin ops require a direct bind".into());
            };
            if state.epoch != epoch || !matches!(state.principal, Principal::Direct) {
                return AdminOutcome::Refused("admin ops require the same direct bind".into());
            }
            let Some(nonce) = state.nonce.as_ref() else {
                return AdminOutcome::Refused("no outstanding challenge".into());
            };
            if nonce.issued.elapsed() > NONCE_TTL {
                state.nonce = None;
                self.outstanding_nonces.fetch_sub(1, Ordering::SeqCst);
                return AdminOutcome::Refused("challenge expired".into());
            }
            // Verify the MAC over the exact op bytes BEFORE consuming the nonce, so a
            // wrong guess cannot burn a caller's outstanding challenge.
            let parts = TranscriptParts {
                vault_id: &self.vault_id,
                key_id: self.key_id,
                nonce: &nonce.bytes,
                op_body,
            };
            if !self.mac_key.verify(&parts, &tag) {
                return AdminOutcome::Refused("auth failed".into());
            }
            // Verified: claim the nonce (single-use). The next replay finds none.
            let claimed = state.nonce.take().expect("checked Some above");
            self.outstanding_nonces.fetch_sub(1, Ordering::SeqCst);
            claimed.bytes
        };
        let _ = claimed_nonce; // (kept for clarity; the claim is the side effect above)

        // Parse-AFTER-verify: the body is opaque until the MAC proves possession.
        let op: AdminOpBody = match serde_json::from_slice(op_body) {
            Ok(op) => op,
            Err(e) => return AdminOutcome::Refused(format!("admin op body not decodable: {e}")),
        };
        self.dispatch(op).await
    }

    async fn dispatch(&self, op: AdminOpBody) -> AdminOutcome {
        // Every op carries a schema version `v`; this module speaks exactly v1. An
        // unknown version is refused (never best-effort-parsed) so a future field
        // addition can't be silently dropped by an old module — the caller learns
        // the module is too old rather than getting a partial write.
        if !op.has_valid_schema_version() {
            return AdminOutcome::Refused(format!(
                "unsupported admin op schema version/variant pairing {} (module accepts v1 and v2 only for their declared variants)",
                op.schema_version()
            ));
        }
        // The federation ops that await outbound calls never reach `apply`, which is
        // synchronous and refuses them; the asynchronous federation dispatch below runs
        // them instead.
        if op.requires_daemon() {
            return self.dispatch_federation(op).await;
        }
        // Apply through the SHARED core applier so the online and offline admin paths
        // can never diverge in what an op does. A credential-scoped op runs under the
        // engine's per-credential single-flight lock (same lock a refresh holds), so
        // an admin write and a refresh for one credential are strictly serialized;
        // revoke-by-handle names no credential, so it commits directly.
        let result = match op.lock_id() {
            Some(_) => {
                let lock_id = op.lock_id().expect("Some checked").to_string();
                self.engine
                    .with_admin_lock(&lock_id, move |store| {
                        credentials_core::admin_ops::apply(store, op, ROUTE_ADMIN_ACTOR)
                    })
                    .await
            }
            None => credentials_core::admin_ops::apply(self.engine.store(), op, ROUTE_ADMIN_ACTOR),
        };
        match result {
            Ok(v) => AdminOutcome::Ok(v),
            Err(e) => store_err(e),
        }
    }
}

// ---------------------------------------------------------------------------------
// The federation admin hook
// ---------------------------------------------------------------------------------

/// The callosum method whose reply names this computer (`self`) and every paired
/// member's current pairing id.
const PAIRED_DEVICES_READ: &str = "callosum.paired_devices_read";

impl AdminSurface {
    /// The transfer ops, with the outbound client the home was given at startup. The
    /// attach takes effect once; later calls find it already set.
    fn transfers(&self) -> &crate::federation::Transfers {
        if let Some(client) = self.home.outbound() {
            let _ = self.transfers.attach_outbound(client.clone());
        }
        &self.transfers
    }

    /// Run `commit` under `credential_id`'s admin lock, the lock a refresh of that
    /// record holds. `commit` is synchronous, so no lock is ever held across an
    /// outbound await. Waiting for the lock counts against the op's `budget`: a lock
    /// not obtained in time commits nothing and answers `admin_lock_busy` (transient).
    async fn locked<T>(
        &self,
        credential_id: &str,
        budget: tokio::time::Instant,
        commit: impl FnOnce(&EncryptedStore) -> Result<T, StoreOpError>,
    ) -> Result<T, AdminOutcome> {
        match tokio::time::timeout_at(budget, self.engine.with_admin_lock(credential_id, commit))
            .await
        {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(error)) => Err(store_err(error)),
            Err(_) => Err(refused("admin_lock_busy", "transient", None)),
        }
    }

    /// The admin ops that await outbound calls. Each runs only the stages it needs, in
    /// this order: an outbound pre-step (a key or pairing lookup, a home fetch), then one
    /// synchronous store commit, under the record's admin lock where the op writes a
    /// record, then an outbound post-step (a send's delivery, only after its commit). A
    /// send has all three; a resume only redelivers. Every outbound call of one op
    /// shares one budget, so the CLI, which waits 15 s for this reply, always gets a
    /// definite answer.
    async fn dispatch_federation(&self, op: AdminOpBody) -> AdminOutcome {
        let budget = tokio::time::Instant::now() + self.federation_budget;
        let store = self.engine.store();
        match op {
            AdminOpBody::FederationSelfSet { member, .. } => {
                if let Err(refusal) = self.check_self_member(&member, budget).await {
                    return refusal;
                }
                match store.set_federation_self_member_audited(
                    &member,
                    AuditCtx::route_admin(AuditOp::FederationSelfSet, ROUTE_ADMIN_ACTOR),
                ) {
                    Ok(changed) => AdminOutcome::Ok(
                        serde_json::json!({ "self_member": member, "changed": changed }),
                    ),
                    Err(error) => store_err(error),
                }
            }
            AdminOpBody::TransferInit { self_member, .. } => {
                if let Err(refusal) = self.check_self_member(&self_member, budget).await {
                    return refusal;
                }
                match self
                    .locked(VAULT_TRANSFER_ID, budget, |store| {
                        init_transfer_key(store, &self_member, ROUTE_ADMIN_ACTOR)
                    })
                    .await
                {
                    Ok(reply) => AdminOutcome::Ok(reply),
                    Err(refusal) => refusal,
                }
            }
            AdminOpBody::TransferSend {
                credential_id, to, ..
            } => {
                let transfers = self.transfers();
                let plan = match transfers.send_prepare(&credential_id, &to).await {
                    Ok(plan) => plan,
                    Err(refusal) => return transfer_refused(&refusal),
                };
                let row = match self
                    .locked(plan.credential_id(), plan.budget(), |_| {
                        Ok(transfers.send_commit(&plan))
                    })
                    .await
                {
                    Ok(Ok(row)) => row,
                    Ok(Err(refusal)) => return transfer_refused(&refusal),
                    Err(refusal) => return refusal,
                };
                AdminOutcome::Ok(send_report(&transfers.send_deliver(&row, &plan).await))
            }
            AdminOpBody::TransferResume { transfer_id, .. } => {
                match self.transfers().resume(&transfer_id).await {
                    Ok(report) => AdminOutcome::Ok(send_report(&report)),
                    Err(refusal) => transfer_refused(&refusal),
                }
            }
            AdminOpBody::TransferAccept {
                transfer_id,
                from,
                replace,
                ..
            } => {
                let transfers = self.transfers();
                let plan = match transfers.accept_prepare(&transfer_id, &from, replace).await {
                    Ok(crate::federation::AcceptStep::Decided(report)) => {
                        return AdminOutcome::Ok(accept_report(&report))
                    }
                    Ok(crate::federation::AcceptStep::Ready(plan)) => plan,
                    Err(refusal) => return transfer_refused(&refusal),
                };
                match self
                    .locked(plan.credential_id(), budget, |_| {
                        Ok(transfers.accept_commit(&plan))
                    })
                    .await
                {
                    Ok(Ok(report)) => AdminOutcome::Ok(accept_report(&report)),
                    Ok(Err(refusal)) => transfer_refused(&refusal),
                    Err(refusal) => refusal,
                }
            }
            AdminOpBody::RemoteAdd {
                credential_id,
                home,
                ..
            } => {
                if !valid_member_id(&home) {
                    return store_err(StoreOpError::InvalidMemberId);
                }
                // Refused before the home fetch, so a conflicting id costs no outbound
                // call. The store's id-uniqueness triggers decide again at the commit.
                match store.meta(&credential_id) {
                    Ok(_) => return store_err(StoreOpError::CredentialIdIsLocal),
                    Err(StoreOpError::NotFound) => {}
                    Err(error) => return store_err(error),
                }
                match store.remote_record(&credential_id) {
                    Ok(None) => {}
                    Ok(Some(_)) => return store_err(StoreOpError::AlreadyExists),
                    Err(error) => return store_err(error),
                }
                let Some(reader) = self.remote.get() else {
                    return refused("home_unreachable", "transient", None);
                };
                let new = match reader.fetch_for_add(&credential_id, &home, budget).await {
                    Ok(new) => new,
                    Err(refusal) => {
                        return refused(
                            refusal.code,
                            refusal.class,
                            refusal.remedy_member.as_deref(),
                        )
                    }
                };
                match self
                    .locked(&credential_id, budget, |store| {
                        store.remote_add_audited(&new)
                    })
                    .await
                {
                    Ok(record) => AdminOutcome::Ok(serde_json::json!({
                        "credential_id": record.credential_id,
                        "home": record.home_member,
                        "incarnation": record.incarnation,
                        "last_home_version": record.last_home_version,
                        "refresh_adapter": record.refresh_adapter,
                        "categories": new.categories,
                    })),
                    Err(refusal) => refusal,
                }
            }
            AdminOpBody::MemberGrant {
                member,
                operation,
                selector,
                ..
            } => {
                if !valid_member_id(&member) {
                    return store_err(StoreOpError::InvalidMemberId);
                }
                if let Err(why) = member_grant_shape(operation, &selector) {
                    return refused("invalid_params", "permanent", None).with_detail(why);
                }
                let body = crate::federation::callosum_lookup(
                    self.home.outbound(),
                    PAIRED_DEVICES_READ,
                    budget,
                )
                .await;
                let pairing_id = match body
                    .map(|body| crate::federation::decode_paired_devices(&body, &member))
                {
                    Some(crate::federation::Lookup::Found(pairing_id)) => pairing_id,
                    Some(crate::federation::Lookup::Absent) => {
                        return refused("member_not_paired", "permanent", Some(&member))
                    }
                    Some(crate::federation::Lookup::Unavailable) | None => {
                        return refused("callosum_unavailable", "transient", None)
                    }
                };
                match store.create_member_grant_audited(&member, operation, &selector, &pairing_id)
                {
                    Ok(changed) => AdminOutcome::Ok(serde_json::json!({
                        "member": member,
                        "operation": operation.as_str(),
                        "selector_kind": selector.kind_str(),
                        "selector": selector.selector_str(),
                        "pairing_id": pairing_id,
                        "changed": changed,
                    })),
                    Err(error) => store_err(error),
                }
            }
            // `requires_daemon` sent only the ops above here; anything else is a
            // mismatch between that table and this match, and is refused unrun.
            other => AdminOutcome::Refused(format!(
                "internal: {} has no federation admin path",
                other.op_name()
            )),
        }
    }

    /// Refuse `typed` unless it is the member id callosum computes for this computer
    /// from its own static key. An id that cannot be checked (a callosum older than
    /// 1.3 sends no `self`) is refused too, never accepted unchecked.
    async fn check_self_member(
        &self,
        typed: &str,
        budget: tokio::time::Instant,
    ) -> Result<(), AdminOutcome> {
        if !valid_member_id(typed) {
            return Err(store_err(StoreOpError::InvalidMemberId));
        }
        let body =
            crate::federation::callosum_lookup(self.home.outbound(), PAIRED_DEVICES_READ, budget)
                .await;
        match body.map(|body| crate::federation::decode_self_member(&body)) {
            Some(crate::federation::Lookup::Found(actual)) if actual == typed => Ok(()),
            Some(crate::federation::Lookup::Found(actual)) => Err(AdminOutcome::Refused(format!(
                "self_member_mismatch/permanent: the id given is {typed}, but callosum computes \
                 {actual} for this computer from its own static key"
            ))),
            Some(crate::federation::Lookup::Absent) => Err(AdminOutcome::Refused(
                "self_member_unchecked/permanent: callosum's paired_devices_read reply has no \
                 `self` key (callosum is older than 1.3), so this computer's member id cannot \
                 be checked; upgrade callosum and run the command again"
                    .to_string(),
            )),
            Some(crate::federation::Lookup::Unavailable) | None => {
                Err(refused("callosum_unavailable", "transient", None))
            }
        }
    }
}

/// `transfer init --self`: create the transfer key when this vault has none, grant
/// callosum the one announce read on it (so callosum can publish its public half), and
/// set the self id. An existing key is kept: replacing it is `transfer init --replace`.
fn init_transfer_key(
    store: &EncryptedStore,
    self_member: &str,
    actor: &str,
) -> Result<serde_json::Value, StoreOpError> {
    let created = match store.meta(VAULT_TRANSFER_ID) {
        Ok(_) => false,
        Err(StoreOpError::NotFound) => {
            let pem = credentials_core::kem::generate_key().map_err(|e| {
                StoreOpError::Encode(format!("transfer key generation failed: {e}"))
            })?;
            store.create_audited(
                VAULT_TRANSFER_ID,
                &VaultRecord::new_static(
                    CredentialKind::KemKey,
                    "operator",
                    pem.into_bytes(),
                    None,
                ),
                AuditCtx::route_admin(AuditOp::Put, actor),
            )?;
            true
        }
        Err(error) => return Err(error),
    };
    match store.create_read_grant_audited(
        "reserved",
        "callosum",
        SelectorKind::Exact,
        VAULT_TRANSFER_ID,
        GrantOperation::Read,
        AuditCtx::route_admin(AuditOp::GrantCreate, actor),
    ) {
        Ok(()) | Err(StoreOpError::AlreadyExists) => {}
        Err(error) => return Err(error),
    }
    let changed = store.set_federation_self_member_audited(
        self_member,
        AuditCtx::route_admin(AuditOp::FederationSelfSet, actor),
    )?;
    Ok(serde_json::json!({
        "transfer_key": if created { "created" } else { "existing" },
        "self_member": self_member,
        "self_changed": changed,
    }))
}

/// The selector a member grant operation takes: `remote_read` an exact id or a valid
/// category, `transfer_deliver` none. Checked before the pairing lookup, so a
/// malformed grant costs no outbound call; the store checks again when it writes.
fn member_grant_shape(
    operation: MemberGrantOperation,
    selector: &MemberGrantSelector,
) -> Result<(), &'static str> {
    match (operation, selector) {
        (MemberGrantOperation::RemoteRead, MemberGrantSelector::Exact(id)) if !id.is_empty() => {
            Ok(())
        }
        (MemberGrantOperation::RemoteRead, MemberGrantSelector::Category(category))
            if credentials_core::catalog::valid_category_name(category) =>
        {
            Ok(())
        }
        (MemberGrantOperation::RemoteRead, _) => {
            Err("remote_read needs an exact credential id or a valid category")
        }
        (MemberGrantOperation::TransferDeliver, MemberGrantSelector::None) => Ok(()),
        (MemberGrantOperation::TransferDeliver, _) => Err("transfer_deliver takes no selector"),
    }
}

/// A refusal in the `code/class` shape the admin route answers with, naming the member
/// whose operator must fix it when there is one.
fn refused(code: &str, class: &str, remedy_member: Option<&str>) -> AdminOutcome {
    match remedy_member {
        Some(member) => AdminOutcome::Refused(format!("{code}/{class}: remedy_member={member}")),
        None => AdminOutcome::Refused(format!("{code}/{class}")),
    }
}

impl AdminOutcome {
    /// Append `detail` to a refusal's text; any other outcome is returned unchanged.
    fn with_detail(self, detail: &str) -> Self {
        match self {
            AdminOutcome::Refused(text) => AdminOutcome::Refused(format!("{text}: {detail}")),
            other => other,
        }
    }
}

fn transfer_refused(refusal: &crate::federation::TransferRefusal) -> AdminOutcome {
    let outcome = refused(
        refusal.code,
        refusal.class,
        refusal.remedy_member.as_deref(),
    );
    match refusal.reason {
        Some(reason) => outcome.with_detail(&format!("reason={reason}")),
        None => outcome,
    }
}

/// A send's or resume's report: the committed row and the receiver's reply to this
/// attempt. A transient reply keeps the row for `--resume`.
fn send_report(report: &crate::federation::SendReport) -> serde_json::Value {
    let class = match &report.reply {
        crate::federation::DeliveryReply::Refused { class, .. } => Some(class.as_str()),
        crate::federation::DeliveryReply::State(_) => None,
    };
    serde_json::json!({
        "transfer_id": report.transfer_id,
        "credential_id": report.credential_id,
        "receiver": report.receiver,
        "reply": report.reply.code(),
        "reply_class": class,
        "row_kept": report.row_kept,
    })
}

fn accept_report(report: &crate::federation::AcceptReport) -> serde_json::Value {
    match report {
        crate::federation::AcceptReport::Accepted {
            credential_id,
            record_version,
        } => serde_json::json!({
            "state": "accepted",
            "credential_id": credential_id,
            "record_version": record_version,
        }),
        crate::federation::AcceptReport::AlreadyDecided(state) => serde_json::json!({
            "state": state.as_str(),
            "already_decided": true,
        }),
    }
}

/// Map a store error to a non-secret refusal. Admin ops are authenticated, so a bit
/// more detail than the anonymous read surface is acceptable (the caller holds the
/// master key), but never secret material.
fn store_err(e: StoreOpError) -> AdminOutcome {
    // Refusals `apply` names with their own code (`<code>: <why>`) keep it in front,
    // as `<code>/permanent: <why>`, instead of reading as an encoding failure.
    if let StoreOpError::Encode(message) = &e {
        for code in [
            credentials_core::admin_ops::FEDERATION_REQUIRES_DAEMON,
            credentials_core::admin_ops::REMOTE_RECORD_CODE,
            "invalid_params",
        ] {
            if let Some(why) = message.strip_prefix(code).and_then(|m| m.strip_prefix(':')) {
                return AdminOutcome::Refused(format!("{code}/permanent:{why}"));
            }
        }
    }
    // A provider-id refusal keeps its labelled rule and value. The bare `code/class` below
    // would drop them, and the operator then could not tell which id broke which rule. The
    // full Display is the same string the CLI's offline path prints, so both paths agree.
    if let StoreOpError::InvalidProviderId { .. } = e {
        return AdminOutcome::Refused(e.to_string());
    }
    if let (Some(code), Some(class)) = (e.wire_code(), e.wire_class()) {
        return AdminOutcome::Refused(format!("{code}/{class}"));
    }
    let reason = match e {
        StoreOpError::NotFound => "credential not found".to_string(),
        StoreOpError::CasMismatch => "version/hash mismatch (concurrent change)".to_string(),
        StoreOpError::AlreadyExists => "credential already exists".to_string(),
        StoreOpError::Fenced { .. } => "fenced out by a newer writer".to_string(),
        e @ (StoreOpError::AccountIdentityMismatch { .. }
        | StoreOpError::SuppliedIdentityContradictsClaim { .. }) => e.to_string(),
        other => format!("store error: {other}"),
    };
    AdminOutcome::Refused(reason)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.is_ascii() || !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use cortexkit_store::{open_sqlite, Isolation, StorageBackend, StorageDescriptor};
    use credentials_core::audit::{AuditCtx, AuditOp};
    use credentials_core::key::{MasterKey, MASTER_KEY_LEN};
    use credentials_core::record::{CredentialKind, RecordIdentity, VaultRecord};
    use credentials_core::store::{mint_handle, EncryptedStore};
    use credentials_core::test_support::TestTempDir;
    use credentials_core::vault_id_for;

    /// A test rig: the AdminSurface plus everything a caller-side signer needs
    /// (the same MAC key derivation the CLI would perform from the keychain key).
    struct Rig {
        _root: TestTempDir,
        admin: AdminSurface,
        store: Arc<EncryptedStore>,
        caller_mac: AdminMacKey,
        vault_id: [u8; VAULT_ID_LEN],
        key_id: KeyId,
    }

    fn rig(seed: u8) -> Rig {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let root = TestTempDir::new(format!(
            "ck-admin-surface-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let descriptor = StorageDescriptor {
            module_id: "cortexkit-credentials".into(),
            storage_namespace: "default".into(),
            isolation: Isolation::Module,
            backend: StorageBackend::Sqlite {
                path: root.join("store.db").to_string_lossy().into_owned(),
            },
        };
        let store = open_sqlite(&descriptor).expect("open");
        EncryptedStore::migrate(&store).expect("migrate");
        let key = MasterKey::from_bytes([seed; MASTER_KEY_LEN]);
        let mac_key = AdminMacKey::derive(&key);
        let caller_mac = AdminMacKey::derive(&MasterKey::from_bytes([seed; MASTER_KEY_LEN]));
        let key_id = key.key_id();
        let vault_id = vault_id_for(&root).expect("vault id");
        let store = Arc::new(EncryptedStore::open(store, key).expect("open vault"));
        let http = Arc::new(crate::test_support::NoHttp);
        let engine = Arc::new(RefreshEngine::new(Arc::clone(&store), Vec::new(), http));
        Rig {
            _root: root,
            admin: AdminSurface::new(engine, mac_key, vault_id, key_id),
            store,
            caller_mac,
            vault_id,
            key_id,
        }
    }

    /// Caller side: fetch a challenge and sign the op body exactly as the CLI would.
    fn challenge_and_sign(rig: &Rig, channel: u16, op_body: &str) -> (String, String) {
        let AdminOutcome::Challenge { nonce_hex, .. } = rig.admin.challenge(channel) else {
            panic!("challenge refused");
        };
        let nonce_vec = decode_hex(&nonce_hex).expect("nonce hex");
        let nonce: [u8; ADMIN_NONCE_LEN] = nonce_vec.as_slice().try_into().expect("nonce len");
        let parts = TranscriptParts {
            vault_id: &rig.vault_id,
            key_id: rig.key_id,
            nonce: &nonce,
            op_body: op_body.as_bytes(),
        };
        (hex(&rig.caller_mac.sign(&parts)), nonce_hex)
    }

    fn store_op_body(id: &str) -> String {
        let record =
            VaultRecord::new_static(CredentialKind::ApiKey, "test", b"sk-1".to_vec(), None);
        serde_json::json!({
            "v": 1,
            "op": "admin.store",
            "id": id,
            "record": record,
            "audit_op": "put",
            "mode": { "kind": "create" },
        })
        .to_string()
    }

    fn openai_record(account_id: &str, payload: &[u8]) -> VaultRecord {
        use base64::Engine as _;

        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"alg":"none","typ":"JWT"}"#);
        let claims = serde_json::json!({
            "https://api.openai.com/auth": { "chatgpt_account_id": account_id },
        });
        let claims =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());
        let access_token = format!("{header}.{claims}.sig");
        VaultRecord::new_oauth(
            "opencode",
            "openai",
            credentials_core::oauth::OAuthCredential {
                access_token: access_token.into(),
                refresh_token: format!("refresh-{account_id}").into(),
                expires_at_ms: Some(4_102_444_800_000),
                token_url: "https://example.invalid/token".to_string(),
                client_id: Some("identity-test-client".to_string()),
                client_secret: None,
                scopes: vec!["scope-a".to_string(), "scope-b".to_string()],
            },
            payload.to_vec(),
        )
    }

    #[tokio::test]
    async fn operator_sign_uses_both_admin_gates_and_route_admin_audit() {
        use base64::Engine;
        let r = rig(0x62);
        let der = ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
            .unwrap();
        let pem = format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            base64::engine::general_purpose::STANDARD.encode(der.as_ref())
        );
        let mut record = VaultRecord::new_static(
            CredentialKind::SigningKey,
            "operator",
            pem.into_bytes(),
            None,
        );
        record.operator_sign = true;
        r.store
            .create_audited(
                "signing:machine:1",
                &record,
                AuditCtx::route_admin(AuditOp::Put, "test"),
            )
            .unwrap();
        let body = serde_json::json!({"v": 1, "op": "admin.operator_sign", "id": "signing:machine:1", "payload_b64": "Y2hhbGxlbmdl"}).to_string();
        r.admin.record_bind(5, Principal::Direct);
        let (tag, _) = challenge_and_sign(&r, 5, &body);
        let refused = r.admin.execute_as(5, 0, None, body.as_bytes(), &tag).await;
        assert!(matches!(refused, AdminOutcome::Refused(_)));
        let refused = r.admin.execute(5, body.as_bytes(), &"00".repeat(32)).await;
        assert!(matches!(refused, AdminOutcome::Refused(_)));
        assert_eq!(
            r.store
                .read_audit(None)
                .unwrap()
                .iter()
                .filter(|row| row.op == "sign")
                .count(),
            0
        );
        let AdminOutcome::Ok(result) = r.admin.execute(5, body.as_bytes(), &tag).await else {
            panic!("authenticated operator signing must dispatch");
        };
        assert_eq!(result["signature_hex"].as_str().unwrap().len(), 128);
        let rows = r.store.read_audit(None).unwrap();
        let row = rows.last().unwrap();
        assert_eq!(row.op, "sign");
        assert_eq!(row.actor, "route-admin");
    }

    #[tokio::test]
    async fn direct_bind_full_round_trip_stores_a_credential() {
        let r = rig(1);
        r.admin.record_bind(5, Principal::Direct);
        let body = store_op_body("apikey:new");
        let (tag, _) = challenge_and_sign(&r, 5, &body);

        let out = r.admin.execute(5, body.as_bytes(), &tag).await;
        assert!(matches!(out, AdminOutcome::Ok(_)), "store should succeed");
        // The write is REAL: the record is in the store, audited as route-admin.
        let rec = r.store.get("apikey:new").expect("stored");
        assert_eq!(rec.payload.expose(), b"sk-1");
        let entries = r.store.read_audit(None).expect("audit");
        let last = entries.last().expect("an entry");
        assert_eq!(last.actor, "route-admin");
        assert_eq!(last.op, "put");
    }

    #[tokio::test]
    async fn direct_bind_set_identity_reseals_an_oauth_record_without_replacing_its_secret() {
        let r = rig(11);
        r.admin.record_bind(5, Principal::Direct);
        let record = VaultRecord::new_oauth(
            "test",
            "anthropic",
            credentials_core::oauth::OAuthCredential {
                access_token: "opaque-access".to_string().into(),
                refresh_token: "refresh-secret".to_string().into(),
                expires_at_ms: Some(4_102_444_800_000),
                token_url: "https://example.invalid/token".to_string(),
                client_id: Some("identity-test-client".to_string()),
                client_secret: None,
                scopes: vec!["scope-a".to_string(), "scope-b".to_string()],
            },
            b"opaque-access".to_vec(),
        );
        r.store
            .create("oauth:anthropic", &record)
            .expect("seed OAuth record");
        let before = r.store.get("oauth:anthropic").expect("before");
        let op = AdminOpBody::SetIdentity {
            v: ADMIN_OP_SCHEMA_V1,
            id: "oauth:anthropic".to_string(),
            identity: RecordIdentity {
                account_id: Some("acct-routed".to_string()),
                email: Some("routed@example.com".to_string()),
                org_name: None,
            },
        };
        let body = String::from_utf8(op.to_bytes().expect("encode op")).expect("UTF-8 JSON");
        let (tag, _) = challenge_and_sign(&r, 5, &body);

        let outcome = r.admin.execute(5, body.as_bytes(), &tag).await;
        assert!(
            matches!(outcome, AdminOutcome::Ok(_)),
            "set identity must route"
        );
        let after = r.store.get("oauth:anthropic").expect("after");
        assert_eq!(
            after.payload, before.payload,
            "route op must preserve payload bytes"
        );
        assert_eq!(
            after.oauth, before.oauth,
            "route op must preserve OAuth material"
        );
        assert_eq!(after.identity.account_id.as_deref(), Some("acct-routed"));
        assert_eq!(
            r.store
                .read_audit(None)
                .expect("audit")
                .last()
                .expect("entry")
                .op,
            "set_identity"
        );
    }

    #[tokio::test]
    async fn direct_bind_set_identity_refuses_an_empty_account_id_at_the_store_sink() {
        let r = rig(12);
        r.admin.record_bind(5, Principal::Direct);
        r.store
            .create(
                "oauth:anthropic",
                &VaultRecord::new_oauth(
                    "test",
                    "anthropic",
                    credentials_core::oauth::OAuthCredential {
                        access_token: "opaque-access".to_string().into(),
                        refresh_token: "refresh-secret".to_string().into(),
                        expires_at_ms: Some(4_102_444_800_000),
                        token_url: "https://example.invalid/token".to_string(),
                        client_id: Some("identity-test-client".to_string()),
                        client_secret: None,
                        scopes: vec!["scope-a".to_string(), "scope-b".to_string()],
                    },
                    b"opaque-access".to_vec(),
                ),
            )
            .expect("seed OAuth record");
        let op = AdminOpBody::SetIdentity {
            v: ADMIN_OP_SCHEMA_V1,
            id: "oauth:anthropic".to_string(),
            identity: RecordIdentity {
                account_id: Some(String::new()),
                email: None,
                org_name: None,
            },
        };
        let body = String::from_utf8(op.to_bytes().expect("encode op")).expect("UTF-8 JSON");
        let (tag, _) = challenge_and_sign(&r, 5, &body);

        let outcome = r.admin.execute(5, body.as_bytes(), &tag).await;
        assert!(
            matches!(outcome, AdminOutcome::Refused(ref message) if message.contains("account_id")),
            "a MAC-authenticated op must still be refused for invalid identity"
        );
        assert!(
            r.store
                .get("oauth:anthropic")
                .expect("record remains readable")
                .identity
                .is_empty(),
            "the rejected operation must not persist any metadata"
        );
    }

    #[tokio::test]
    async fn direct_bind_store_refuses_an_invalid_import_identity() {
        let r = rig(13);
        r.admin.record_bind(5, Principal::Direct);
        let record = VaultRecord::new_oauth(
            "import",
            "anthropic",
            credentials_core::oauth::OAuthCredential {
                access_token: "opaque-access".to_string().into(),
                refresh_token: "refresh-secret".to_string().into(),
                expires_at_ms: Some(4_102_444_800_000),
                token_url: "https://example.invalid/token".to_string(),
                client_id: Some("identity-test-client".to_string()),
                client_secret: None,
                scopes: vec!["scope-a".to_string(), "scope-b".to_string()],
            },
            b"opaque-access".to_vec(),
        )
        .with_identity(RecordIdentity {
            account_id: Some("acct-good".to_string()),
            email: Some("invalid\u{0007}email@example.com".to_string()),
            org_name: None,
        });
        let op = AdminOpBody::Store {
            v: ADMIN_OP_SCHEMA_V1,
            id: "oauth:anthropic".to_string(),
            record: Box::new(record),
            audit_op: credentials_core::admin_ops::AdminAuditOp::Import,
            mode: credentials_core::admin_ops::StoreMode::Create,
        };
        let body = String::from_utf8(op.to_bytes().expect("encode op")).expect("UTF-8 JSON");
        let (tag, _) = challenge_and_sign(&r, 5, &body);

        let outcome = r.admin.execute(5, body.as_bytes(), &tag).await;
        assert!(
            matches!(outcome, AdminOutcome::Refused(ref message) if message.contains("email")),
            "authenticated imports must enforce the same store identity boundary"
        );
        assert!(r.store.get("oauth:anthropic").is_err());
    }

    #[tokio::test]
    async fn connected_identity_mismatch_refusal_renders_both_accounts_and_remedies() {
        let r = rig(14);
        r.admin.record_bind(5, Principal::Direct);
        let existing = openai_record("acct-retained", b"old-token").with_identity(RecordIdentity {
            account_id: Some("acct-retained".to_string()),
            email: Some("retained@example.com".to_string()),
            org_name: None,
        });
        r.store
            .create("oauth:openai", &existing)
            .expect("seed OAuth record");
        let op = AdminOpBody::StoreWithIdentityPolicy {
            v: ADMIN_OP_SCHEMA_V1,
            id: "oauth:openai".to_string(),
            record: Box::new(openai_record("acct-incoming", b"new-token")),
            audit_op: credentials_core::admin_ops::AdminAuditOp::Import,
            clear_identity: false,
        };
        let body = String::from_utf8(op.to_bytes().expect("encode op")).expect("UTF-8 JSON");
        let (tag, _) = challenge_and_sign(&r, 5, &body);

        let AdminOutcome::Refused(message) = r.admin.execute(5, body.as_bytes(), &tag).await else {
            panic!("account mismatch must surface as admin_refused");
        };
        assert_eq!(
            message,
            "incoming material names account 'acct-incoming', but identity preservation would retain account 'acct-retained'; pass `--account-id <new>` with 'acct-incoming' or `--clear-identity`; or afterwards: ck auth set-identity oauth:openai --account-id acct-incoming"
        );
    }

    #[tokio::test]
    async fn connected_create_identity_claim_refusal_renders_as_admin_refused() {
        let r = rig(15);
        r.admin.record_bind(5, Principal::Direct);
        let op = AdminOpBody::Store {
            v: ADMIN_OP_SCHEMA_V1,
            id: "oauth:openai".to_string(),
            record: Box::new(openai_record("acct-derived", b"new-token").with_identity(
                RecordIdentity {
                    account_id: Some("acct-supplied".to_string()),
                    email: Some("supplied@example.com".to_string()),
                    org_name: None,
                },
            )),
            audit_op: credentials_core::admin_ops::AdminAuditOp::Import,
            mode: credentials_core::admin_ops::StoreMode::Create,
        };
        let body = String::from_utf8(op.to_bytes().expect("encode op")).expect("UTF-8 JSON");
        let (tag, _) = challenge_and_sign(&r, 5, &body);

        let AdminOutcome::Refused(message) = r.admin.execute(5, body.as_bytes(), &tag).await else {
            panic!("a contradictory create identity must surface as admin_refused");
        };
        assert_eq!(
            message,
            "supplied identity names account 'acct-supplied', but incoming material names account 'acct-derived'; drop `--account-id`, or fix the export; the token's own claim is authoritative"
        );
        assert!(matches!(
            r.store.get("oauth:openai"),
            Err(credentials_core::store::StoreOpError::NotFound)
        ));
    }

    #[tokio::test]
    async fn non_direct_principals_never_reach_admin() {
        let r = rig(2);
        let body = store_op_body("apikey:x");

        // Each arm asserts the refusal REASON, not merely that a refusal happened: a
        // non-direct caller has no outstanding challenge either, so a wildcard match is
        // satisfied by the missing-nonce refusal and would still pass with Gate 1
        // deleted. Naming the reason is what makes these tests about Gate 1.
        const GATE_1: &str = "require a direct bind";

        // Reserved bind: challenge refused.
        r.admin.record_bind(
            3,
            Principal::Reserved {
                module_id: "llm-runner".into(),
            },
        );
        assert!(matches!(r.admin.challenge(3), AdminOutcome::Refused(ref m) if m.contains(GATE_1)));
        // Unverified bind (absent stamp records as this): refused.
        r.admin.record_bind(4, Principal::Unverified);
        assert!(matches!(r.admin.challenge(4), AdminOutcome::Refused(ref m) if m.contains(GATE_1)));
        // Never-bound channel: refused.
        assert!(matches!(r.admin.challenge(9), AdminOutcome::Refused(ref m) if m.contains(GATE_1)));
        // Execute without a direct bind is refused even with a (meaningless) tag.
        let out = r.admin.execute(3, body.as_bytes(), "00").await;
        assert!(
            matches!(out, AdminOutcome::Refused(ref m) if m.contains(GATE_1)),
            "execute must refuse on Gate 1, not on the absent challenge behind it"
        );
        // Nothing was written.
        assert!(r.store.get("apikey:x").is_err());
    }

    #[tokio::test]
    async fn replay_of_a_valid_tag_is_refused_nonce_claimed() {
        let r = rig(3);
        r.admin.record_bind(5, Principal::Direct);
        let body = store_op_body("apikey:once");
        let (tag, _) = challenge_and_sign(&r, 5, &body);

        let first = r.admin.execute(5, body.as_bytes(), &tag).await;
        assert!(matches!(first, AdminOutcome::Ok(_)));
        // The exact same (body, tag) again: the nonce is consumed — refused.
        let replay = r.admin.execute(5, body.as_bytes(), &tag).await;
        assert!(
            matches!(replay, AdminOutcome::Refused(ref m) if m.contains("challenge")),
            "replay must be refused for lack of an outstanding challenge"
        );
    }

    #[tokio::test]
    async fn a_tag_for_op_a_cannot_authorize_op_b() {
        let r = rig(4);
        r.admin.record_bind(5, Principal::Direct);
        let body_a = store_op_body("apikey:a");
        let body_b = store_op_body("apikey:b");
        let (tag_a, _) = challenge_and_sign(&r, 5, &body_a);

        // Splice: op B with A's tag — MAC covers the exact bytes, so refused, and
        // the failed attempt does NOT burn the outstanding nonce...
        let out = r.admin.execute(5, body_b.as_bytes(), &tag_a).await;
        assert!(matches!(out, AdminOutcome::Refused(ref m) if m.contains("auth failed")));
        assert!(
            r.store.get("apikey:b").is_err(),
            "spliced op must not execute"
        );
        // ...so the legitimate op A still goes through on the same challenge.
        let ok = r.admin.execute(5, body_a.as_bytes(), &tag_a).await;
        assert!(
            matches!(ok, AdminOutcome::Ok(_)),
            "original op survives a failed splice"
        );
    }

    #[tokio::test]
    async fn wrong_master_key_tag_is_refused() {
        let r = rig(5);
        r.admin.record_bind(5, Principal::Direct);
        let body = store_op_body("apikey:wrongkey");
        // Sign with a DIFFERENT master key's derived MAC.
        let AdminOutcome::Challenge { nonce_hex, .. } = r.admin.challenge(5) else {
            panic!("challenge refused");
        };
        let nonce: [u8; ADMIN_NONCE_LEN] = decode_hex(&nonce_hex)
            .unwrap()
            .as_slice()
            .try_into()
            .unwrap();
        let wrong = AdminMacKey::derive(&MasterKey::from_bytes([99; MASTER_KEY_LEN]));
        let tag = hex(&wrong.sign(&TranscriptParts {
            vault_id: &r.vault_id,
            key_id: r.key_id,
            nonce: &nonce,
            op_body: body.as_bytes(),
        }));

        let out = r.admin.execute(5, body.as_bytes(), &tag).await;
        assert!(matches!(out, AdminOutcome::Refused(ref m) if m.contains("auth failed")));
        assert!(r.store.get("apikey:wrongkey").is_err());
    }

    #[tokio::test]
    async fn expired_nonce_is_refused() {
        let r = rig(6);
        r.admin.record_bind(5, Principal::Direct);
        let body = store_op_body("apikey:late");
        let (tag, _) = challenge_and_sign(&r, 5, &body);
        r.admin
            .backdate_nonce_for_test(5, NONCE_TTL + Duration::from_secs(1));

        let out = r.admin.execute(5, body.as_bytes(), &tag).await;
        assert!(matches!(out, AdminOutcome::Refused(ref m) if m.contains("expired")));
        assert!(r.store.get("apikey:late").is_err());
    }

    #[tokio::test]
    async fn rebind_invalidates_an_outstanding_challenge() {
        let r = rig(7);
        r.admin.record_bind(5, Principal::Direct);
        let body = store_op_body("apikey:rebind");
        let (tag, _) = challenge_and_sign(&r, 5, &body);

        // A rebind of the same channel (lost-Goodbye self-heal): fresh generation,
        // no nonce — the old challenge cannot authorize anything.
        r.admin.record_bind(5, Principal::Direct);
        let out = r.admin.execute(5, body.as_bytes(), &tag).await;
        assert!(matches!(out, AdminOutcome::Refused(ref m) if m.contains("challenge")));
        assert!(r.store.get("apikey:rebind").is_err());
    }

    #[tokio::test]
    async fn set_plan_requires_gate_2_and_dispatches_set_clear_and_refusals() {
        let r = rig(23);
        r.admin.record_bind(5, Principal::Direct);
        seed_provider_ids(&r, "apikey:zai", &["aa"]);
        let body = |id: &str, tier: Option<&str>| {
            String::from_utf8(
                AdminOpBody::SetPlan {
                    v: credentials_core::admin_ops::ADMIN_OP_SCHEMA_V2,
                    credential_id: id.to_owned(),
                    plan_tier: tier.map(str::to_owned),
                }
                .to_bytes()
                .unwrap(),
            )
            .unwrap()
        };
        let set = body("apikey:zai", Some("pro_200"));
        let AdminOutcome::Challenge { nonce_hex, .. } = r.admin.challenge(5) else {
            panic!("challenge refused");
        };
        let nonce: [u8; ADMIN_NONCE_LEN] = decode_hex(&nonce_hex)
            .unwrap()
            .as_slice()
            .try_into()
            .unwrap();
        let wrong = AdminMacKey::derive(&MasterKey::from_bytes([99; MASTER_KEY_LEN]));
        let wrong_tag = hex(&wrong.sign(&TranscriptParts {
            vault_id: &r.vault_id,
            key_id: r.key_id,
            nonce: &nonce,
            op_body: set.as_bytes(),
        }));
        let before = r.store.read_audit(None).unwrap().len();
        assert!(
            matches!(r.admin.execute(5, set.as_bytes(), &wrong_tag).await, AdminOutcome::Refused(ref m) if m.contains("auth failed"))
        );
        assert_eq!(r.store.meta("apikey:zai").unwrap().plan_tier, None);
        assert_eq!(r.store.read_audit(None).unwrap().len(), before);
        for (id, tier, expected) in [
            (
                "apikey:zai",
                Some("pro_200"),
                Some(serde_json::json!({"plan_tier":"pro_200"})),
            ),
            (
                "apikey:zai",
                None,
                Some(serde_json::json!({"plan_tier":null})),
            ),
            ("apikey:zai", Some("Pro"), None),
            ("missing", Some("max_5x"), None),
        ] {
            let body = body(id, tier);
            let (tag, _) = challenge_and_sign(&r, 5, &body);
            let outcome = r.admin.execute(5, body.as_bytes(), &tag).await;
            if let Some(expected) = expected {
                assert!(matches!(outcome, AdminOutcome::Ok(value) if value == expected));
            } else {
                assert!(
                    matches!(outcome, AdminOutcome::Refused(ref message) if message == if id == "missing" { "credential not found" } else { "invalid_plan_tier/permanent" })
                );
            }
        }
        assert_eq!(r.store.read_audit(None).unwrap().len(), before + 2);
        assert_eq!(r.store.verify_audit_chain().unwrap(), None);
    }

    fn set_providers_body(credential_id: &str, provider_ids: &[&str]) -> String {
        let op = AdminOpBody::SetProviders {
            v: credentials_core::admin_ops::ADMIN_OP_SCHEMA_V2,
            credential_id: credential_id.to_string(),
            mode: credentials_core::store::SetProvidersMode::Add,
            provider_ids: provider_ids.iter().map(|id| (*id).to_string()).collect(),
        };
        String::from_utf8(op.to_bytes().expect("encode op")).expect("UTF-8 JSON")
    }

    fn seed_provider_ids(r: &Rig, id: &str, provider_ids: &[&str]) {
        r.store
            .create(
                id,
                &VaultRecord::new_static(CredentialKind::ApiKey, "test", b"k".to_vec(), None),
            )
            .expect("seed credential");
        let ids: Vec<String> = provider_ids.iter().map(|id| (*id).to_string()).collect();
        r.store
            .set_providers_audited(
                id,
                credentials_core::store::SetProvidersMode::Set,
                &ids,
                AuditCtx::admin(AuditOp::SetProviders),
            )
            .expect("seed provider ids");
    }

    /// `admin.set_providers` is an admin op like any other: signed with a master key
    /// other than this vault's, it is refused by the master-key MAC check (Gate 2) and
    /// neither the provider-id table nor the audit log moves. The same body signed with
    /// this vault's key then succeeds, so the refusal is the MAC's and not a malformed
    /// op's.
    #[tokio::test]
    async fn set_providers_without_a_valid_gate_2_mac_changes_neither_the_table_nor_the_audit() {
        let r = rig(21);
        r.admin.record_bind(5, Principal::Direct);
        seed_provider_ids(&r, "apikey:zai", &["aa"]);
        let audit_before = r.store.read_audit(None).expect("audit").len();
        let body = set_providers_body("apikey:zai", &["zai-coding-plan"]);

        let AdminOutcome::Challenge { nonce_hex, .. } = r.admin.challenge(5) else {
            panic!("challenge refused");
        };
        let nonce: [u8; ADMIN_NONCE_LEN] = decode_hex(&nonce_hex)
            .unwrap()
            .as_slice()
            .try_into()
            .unwrap();
        let wrong = AdminMacKey::derive(&MasterKey::from_bytes([99; MASTER_KEY_LEN]));
        let wrong_tag = hex(&wrong.sign(&TranscriptParts {
            vault_id: &r.vault_id,
            key_id: r.key_id,
            nonce: &nonce,
            op_body: body.as_bytes(),
        }));
        let out = r.admin.execute(5, body.as_bytes(), &wrong_tag).await;
        assert!(
            matches!(out, AdminOutcome::Refused(ref m) if m.contains("auth failed")),
            "a wrong-key tag must be refused at Gate 2"
        );
        // An authentication tag that is not hex at all is refused too.
        let out = r.admin.execute(5, body.as_bytes(), "not-a-tag").await;
        assert!(matches!(out, AdminOutcome::Refused(_)));
        assert_eq!(r.store.provider_ids("apikey:zai").unwrap(), ["aa"]);
        assert_eq!(r.store.read_audit(None).expect("audit").len(), audit_before);

        // The same body signed with this vault's MAC succeeds, so the refusals above
        // were about the tag.
        let (tag, _) = challenge_and_sign(&r, 5, &body);
        let out = r.admin.execute(5, body.as_bytes(), &tag).await;
        assert!(
            matches!(out, AdminOutcome::Ok(ref v) if *v == serde_json::json!({"provider_ids": ["aa", "zai-coding-plan"]})),
            "the correctly signed op must succeed"
        );
        assert_eq!(
            r.store.read_audit(None).expect("audit").len(),
            audit_before + 1
        );
    }

    /// A provider-id refusal reaches the caller as the labelled Display, the same string
    /// the offline path prints, rather than the bare `invalid_provider_id/permanent` code
    /// that every other coded store error renders as.
    #[tokio::test]
    async fn a_provider_id_refusal_renders_its_rule_and_value() {
        let r = rig(22);
        r.admin.record_bind(5, Principal::Direct);
        seed_provider_ids(&r, "apikey:zai", &["aa"]);
        for (provider_ids, expected) in [
            (
                vec!["1a"],
                "invalid_provider_id/permanent: rule=charset value=1a",
            ),
            (
                vec!["a"],
                "invalid_provider_id/permanent: rule=length value=a",
            ),
            (
                vec!["bb", "bb"],
                "invalid_provider_id/permanent: rule=duplicate value=bb",
            ),
        ] {
            let body = set_providers_body("apikey:zai", &provider_ids);
            let (tag, _) = challenge_and_sign(&r, 5, &body);
            let AdminOutcome::Refused(message) = r.admin.execute(5, body.as_bytes(), &tag).await
            else {
                panic!("{provider_ids:?} must be refused");
            };
            assert_eq!(message, expected, "{provider_ids:?}");
        }
        assert_eq!(r.store.provider_ids("apikey:zai").unwrap(), ["aa"]);

        // Other coded store errors keep the bare code/class rendering.
        assert!(matches!(
            store_err(StoreOpError::InvalidCategoryName),
            AdminOutcome::Refused(ref m) if m == "invalid_category_name/permanent"
        ));
    }

    #[tokio::test]
    async fn unsupported_schema_version_is_refused_after_auth() {
        let r = rig(8);
        r.admin.record_bind(5, Principal::Direct);
        let record = VaultRecord::new_static(CredentialKind::ApiKey, "test", b"sk".to_vec(), None);
        let body = serde_json::json!({
            "v": 2,
            "op": "admin.invalidate",
            "id": "apikey:v2",
            "record": record,
        })
        .to_string();
        let (tag, _) = challenge_and_sign(&r, 5, &body);
        let out = r.admin.execute(5, body.as_bytes(), &tag).await;
        assert!(
            matches!(out, AdminOutcome::Refused(ref m) if m.contains("schema version")),
            "v=2 must be refused, not best-effort parsed"
        );
    }

    #[tokio::test]
    async fn oversize_body_is_refused_before_mac_work() {
        let r = rig(9);
        r.admin.record_bind(5, Principal::Direct);
        let body = "x".repeat(MAX_OP_BODY_LEN + 1);
        let out = r.admin.execute(5, body.as_bytes(), "00").await;
        assert!(matches!(out, AdminOutcome::Refused(ref m) if m.contains("too large")));
    }

    /// A correctly signed op body of exactly `MAX_OP_BODY_LEN` bytes executes, and the
    /// same op one byte longer is refused for its size alone. Both bodies are real,
    /// signed store ops (JSON padded with trailing whitespace, which the parser
    /// accepts), so the only difference between the two outcomes is the length.
    #[tokio::test]
    async fn op_body_at_the_cap_executes_and_one_byte_over_is_refused() {
        let r = rig(12);
        r.admin.record_bind(5, Principal::Direct);
        let padded = |id: &str, len: usize| {
            let mut body = store_op_body(id);
            assert!(body.len() < len, "the op must fit before padding");
            body.extend(std::iter::repeat_n(' ', len - body.len()));
            body
        };

        let at_cap = padded("apikey:at-cap", MAX_OP_BODY_LEN);
        let (tag, _) = challenge_and_sign(&r, 5, &at_cap);
        let out = r.admin.execute(5, at_cap.as_bytes(), &tag).await;
        assert!(
            matches!(out, AdminOutcome::Ok(_)),
            "a body exactly at the cap must execute"
        );
        assert!(r.store.get("apikey:at-cap").is_ok());

        let over_cap = padded("apikey:over-cap", MAX_OP_BODY_LEN + 1);
        let (tag, _) = challenge_and_sign(&r, 5, &over_cap);
        let out = r.admin.execute(5, over_cap.as_bytes(), &tag).await;
        assert!(
            matches!(out, AdminOutcome::Refused(ref m) if m.contains("too large")),
            "a body one byte over the cap must be refused for its size"
        );
        assert!(r.store.get("apikey:over-cap").is_err());
    }

    #[tokio::test]
    async fn compound_invalidate_revokes_handles_atomically() {
        let r = rig(10);
        r.admin.record_bind(5, Principal::Direct);

        // Seed a credential with two live handles.
        r.store
            .create(
                "apikey:dead",
                &VaultRecord::new_static(CredentialKind::ApiKey, "t", b"k".to_vec(), None),
            )
            .unwrap();
        let h1 = mint_handle().unwrap();
        let h2 = mint_handle().unwrap();
        let ctx = AuditCtx::admin(AuditOp::MintHandle);
        r.store
            .put_handle_hash(&h1.hash, "apikey:dead", ctx)
            .unwrap();
        r.store
            .put_handle_hash(&h2.hash, "apikey:dead", ctx)
            .unwrap();

        let body = serde_json::json!({
            "v": 1,
            "op": "admin.invalidate",
            "id": "apikey:dead",
        })
        .to_string();
        let (tag, _) = challenge_and_sign(&r, 5, &body);
        let out = r.admin.execute(5, body.as_bytes(), &tag).await;
        let AdminOutcome::Ok(v) = out else {
            panic!("invalidate refused");
        };
        assert_eq!(v["handles_revoked"], 2);
        // The credential is needs_reauth AND both handles are dead.
        assert!(matches!(
            r.store.get("apikey:dead"),
            Err(StoreOpError::NeedsReauth)
        ));
        // resolve_handle returns NotFound for a revoked handle (uniform not-found).
        assert!(matches!(
            r.store.resolve_handle(&h1.raw),
            Err(StoreOpError::NotFound)
        ));
        assert!(matches!(
            r.store.resolve_handle(&h2.raw),
            Err(StoreOpError::NotFound)
        ));
    }

    #[tokio::test]
    async fn mint_handle_returns_a_resolvable_handle() {
        let r = rig(11);
        r.admin.record_bind(5, Principal::Direct);
        r.store
            .create(
                "apikey:h",
                &VaultRecord::new_static(CredentialKind::ApiKey, "t", b"k".to_vec(), None),
            )
            .unwrap();

        let body =
            serde_json::json!({ "v": 1, "op": "admin.mint_handle", "id": "apikey:h" }).to_string();
        let (tag, _) = challenge_and_sign(&r, 5, &body);
        let AdminOutcome::Ok(v) = r.admin.execute(5, body.as_bytes(), &tag).await else {
            panic!("mint refused");
        };
        let raw = v["handle"].as_str().expect("handle string");
        assert!(raw.starts_with("ckh_"));
        assert_eq!(r.store.resolve_handle(raw).expect("resolve"), "apikey:h");
    }

    #[tokio::test]
    async fn admin_requests_require_the_captured_principal_and_current_epoch() {
        let r = rig(201);
        r.admin.record_bind_at(5, 1, Principal::Direct, "");
        assert!(matches!(
            r.admin.challenge_as(5, 1, None),
            AdminOutcome::Refused(_)
        ));
        assert_eq!(r.admin.outstanding_nonces.load(Ordering::SeqCst), 0);
        assert!(matches!(
            r.admin.challenge_as(5, 1, Some(&Principal::Direct)),
            AdminOutcome::Challenge { .. }
        ));
        r.admin.record_bind_at(5, 2, Principal::Direct, "");
        assert!(matches!(
            r.admin.challenge_as(5, 1, Some(&Principal::Direct)),
            AdminOutcome::Refused(_)
        ));
        assert_eq!(r.admin.outstanding_nonces.load(Ordering::SeqCst), 0);
        r.admin.record_bind(5, Principal::Direct);
        let body = store_op_body("apikey:snapshot");
        let (tag, _) = challenge_and_sign(&r, 5, &body);
        assert!(matches!(
            r.admin
                .execute_as(5, 0, Some(&Principal::Unverified), body.as_bytes(), &tag)
                .await,
            AdminOutcome::Refused(_)
        ));
        assert_eq!(r.admin.outstanding_nonces.load(Ordering::SeqCst), 1);
        assert!(matches!(
            r.admin.execute(5, body.as_bytes(), &tag).await,
            AdminOutcome::Ok(_)
        ));
        r.admin.record_bind_at(5, 3, Principal::Unverified, "");
        assert!(matches!(
            r.admin.challenge_as(5, 3, Some(&Principal::Direct)),
            AdminOutcome::Refused(_)
        ));
        assert_eq!(r.admin.outstanding_nonces.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn non_ascii_auth_tags_refuse_without_consuming_the_nonce() {
        let r = rig(202);
        r.admin.record_bind(5, Principal::Direct);
        let body = store_op_body("apikey:ascii-tag");
        let (tag, _) = challenge_and_sign(&r, 5, &body);
        for malformed in ["aéb", "é", "💡", "gg", "a"] {
            assert!(
                matches!(r.admin.execute(5, body.as_bytes(), malformed).await, AdminOutcome::Refused(ref reason) if reason == "malformed auth tag")
            );
        }
        assert!(matches!(
            r.admin.execute(5, body.as_bytes(), &tag).await,
            AdminOutcome::Ok(_)
        ));
    }

    #[test]
    fn expired_challenges_release_capacity_without_evicting_live_nonces() {
        let r = rig(203);
        for channel in 0..MAX_OUTSTANDING_NONCES as u16 {
            r.admin.record_bind(channel, Principal::Direct);
            assert!(matches!(
                r.admin.challenge(channel),
                AdminOutcome::Challenge { .. }
            ));
        }
        let overflow = MAX_OUTSTANDING_NONCES as u16;
        r.admin.record_bind(overflow, Principal::Direct);
        assert!(matches!(
            r.admin.challenge(overflow),
            AdminOutcome::Refused(_)
        ));
        r.admin.backdate_nonce_for_test(0, NONCE_TTL * 2);
        assert!(matches!(
            r.admin.challenge(overflow),
            AdminOutcome::Challenge { .. }
        ));
        assert_eq!(
            r.admin.outstanding_nonces.load(Ordering::SeqCst),
            MAX_OUTSTANDING_NONCES as u64
        );
        let binds = r.admin.binds.lock().unwrap();
        assert!(binds[&0].nonce.is_none());
        assert!(binds[&1].nonce.is_some());
    }

    #[tokio::test]
    async fn challenge_capacity_is_bounded_and_never_evicts() {
        let r = rig(12);
        // Fill the global nonce table from distinct binds.
        for ch in 0..MAX_OUTSTANDING_NONCES as u16 {
            r.admin.record_bind(ch, Principal::Direct);
            assert!(matches!(
                r.admin.challenge(ch),
                AdminOutcome::Challenge { .. }
            ));
        }
        // The next NEW bind's challenge is refused (no eviction of live nonces).
        let overflow_ch = MAX_OUTSTANDING_NONCES as u16;
        r.admin.record_bind(overflow_ch, Principal::Direct);
        assert!(matches!(
            r.admin.challenge(overflow_ch),
            AdminOutcome::Refused(ref m) if m.contains("capacity")
        ));
        // But an EXISTING bind reissuing its own challenge still works (replace, not add).
        assert!(matches!(
            r.admin.challenge(0),
            AdminOutcome::Challenge { .. }
        ));
        // And dropping a bind frees capacity for the newcomer.
        r.admin.drop_bind(0);
        assert!(matches!(
            r.admin.challenge(overflow_ch),
            AdminOutcome::Challenge { .. }
        ));
    }
}
