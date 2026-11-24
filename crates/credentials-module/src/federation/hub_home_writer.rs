//! One decision and publication task per login-list recipient.

use std::{collections::BTreeSet, future::Future, pin::Pin, sync::Arc};

use credentials_core::{
    federation::{MemberGrantOperation, RemoteWatchRow},
    hub_counters::HubGeneration,
    kem::MAX_HUB_LOGINS_PLAINTEXT,
    signing::key_id_for_public,
    store::{EncryptedStore, HubLoginKind, HubLoginRecipient, HubLoginTarget, StoreOpError},
};
use serde_json::json;
use tokio::{
    sync::{broadcast, watch},
    task::JoinSet,
    time::{sleep, sleep_until, Instant},
};

use super::{
    hub::{Backoff, Hub, HubEntry, HubError, HubEvent, HubOperation, SHARED_LOGINS},
    hub_binding::{HubBindings, HubMember},
    hub_logins::{self, LoginAad, LoginEnvelope},
    ingress::{remote_watch_lists_equal, remote_watch_logins_wire, HomeVault},
    transfer::{own_key, OwnKey},
};

type Bindings = watch::Receiver<Option<HubBindings>>;

#[derive(Clone)]
enum Repair {
    All,
    Entry(Arc<HubEntry>),
}

pub(crate) async fn run(store: Arc<EncryptedStore>, hub: Arc<dyn Hub>, bindings: Bindings) {
    run_inner(
        store,
        hub,
        bindings,
        #[cfg(test)]
        TestHooks::default(),
    )
    .await;
}

async fn run_inner(
    store: Arc<EncryptedStore>,
    hub: Arc<dyn Hub>,
    bindings: Bindings,
    #[cfg(test)] hooks: TestHooks,
) {
    let (repairs, _) = broadcast::channel(64);
    tokio::select! {
        _ = supervise(store, &hub, bindings, &repairs, #[cfg(test)] hooks) => {},
        _ = watch_keys(hub.as_ref(), &repairs) => {},
    }
}

async fn supervise(
    store: Arc<EncryptedStore>,
    hub: &Arc<dyn Hub>,
    mut bindings: Bindings,
    repairs: &broadcast::Sender<Repair>,
    #[cfg(test)] hooks: TestHooks,
) {
    let mut backoff = Backoff::default();
    let mut stored = loop {
        let store = Arc::clone(&store);
        match tokio::task::spawn_blocking(move || store.list_hub_login_targets()).await {
            Ok(Ok(targets)) => {
                break targets
                    .into_iter()
                    .map(|row| row.member_id)
                    .collect::<Vec<_>>()
            }
            _ => sleep(backoff.next_delay()).await,
        }
    };
    let mut started = BTreeSet::new();
    let mut members = std::collections::HashMap::new();
    let mut tasks = JoinSet::new();
    loop {
        if let Some(current) = bindings.borrow_and_update().as_ref() {
            stored.extend(current.bindings().map(|binding| binding.member_id.clone()));
        }
        for member_id in stored.drain(..) {
            if started.insert(member_id.clone()) {
                let task = tasks.spawn(
                    MemberTask {
                        member_id: member_id.clone(),
                        hub: Arc::clone(hub),
                        writes: store.subscribe_writes(),
                        store: Arc::clone(&store),
                        bindings: bindings.clone(),
                        repairs: repairs.subscribe(),
                        #[cfg(test)]
                        hooks: hooks.clone(),
                    }
                    .run(),
                );
                members.insert(task.id(), member_id);
            }
        }
        tokio::select! {
            change = bindings.changed() => if change.is_err() { return; },
            // A recipient is never left without a writer: one that ends for any
            // reason is logged and started again.
            ended = tasks.join_next_with_id(), if !tasks.is_empty() => {
                let id = match &ended {
                    Some(Ok((id, ()))) => *id,
                    Some(Err(error)) => error.id(),
                    None => continue,
                };
                if let Some(member) = members.remove(&id) {
                    tracing::error!(target: "federation", %member, "hub login writer for a recipient stopped; restarting it");
                    started.remove(&member);
                    stored.push(member);
                }
            }
        }
    }
}

async fn watch_keys(hub: &dyn Hub, repairs: &broadcast::Sender<Repair>) {
    let mut backoff = Backoff::default();
    let mut connections = hub.connection_changes();
    let prefix = format!("{}.", hub.box_id());
    loop {
        let opened = tokio::select! {
            biased;
            change = connections.changed() => if change.is_ok() { continue } else { return },
            opened = hub.watch_bucket(SHARED_LOGINS) => opened,
        };
        if let Ok(mut watch) = opened {
            let _ = repairs.send(Repair::All);
            loop {
                let event = tokio::select! {
                    biased;
                    change = connections.changed() => if change.is_ok() { break } else { return },
                    event = watch.next() => event,
                };
                let Some(Ok(event)) = event else { break };
                backoff.reset();
                let repair = match event {
                    HubEvent::BucketReset { bucket } if bucket == SHARED_LOGINS => Repair::All,
                    HubEvent::Entry(entry) if entry.key.starts_with(&prefix) => {
                        Repair::Entry(Arc::new(entry))
                    }
                    _ => continue,
                };
                let _ = repairs.send(repair);
            }
        }
        tokio::select! {
            change = connections.changed() => if change.is_err() { return; },
            _ = sleep(backoff.next_delay()) => {},
        }
    }
}

struct MemberTask {
    member_id: String,
    hub: Arc<dyn Hub>,
    store: Arc<EncryptedStore>,
    writes: watch::Receiver<()>,
    bindings: Bindings,
    repairs: broadcast::Receiver<Repair>,
    #[cfg(test)]
    hooks: TestHooks,
}

#[cfg(test)]
#[derive(Clone, Default)]
struct TestHooks {
    project: Option<super::ingress::IssueAuditGate>,
    decided: Option<Arc<tokio::sync::Notify>>,
    failed: Option<Arc<tokio::sync::Notify>>,
    /// Makes the next member task end at once, as an unexpected exit would.
    exit_once: Option<Arc<std::sync::atomic::AtomicBool>>,
    /// Counts refusal warnings this writer logs.
    refusals: Option<Arc<std::sync::atomic::AtomicUsize>>,
}

struct Recipient {
    box_id: String,
    pairing_id: String,
    key: [u8; 32],
}

enum Inventory {
    Eligible(Vec<RemoteWatchRow>),
    Ended,
}

impl Inventory {
    fn kind(&self) -> HubLoginKind {
        match self {
            Self::Eligible(_) => HubLoginKind::Snapshot,
            Self::Ended => HubLoginKind::Ended,
        }
    }
}

enum Decision {
    Unknown,
    Discard(HubLoginTarget),
    Known {
        target: Option<HubLoginTarget>,
        recipient: Recipient,
        sender: OwnKey,
        inventory: Inventory,
    },
}

fn decide(
    store: &EncryptedStore,
    member: &str,
    bindings: &HubBindings,
) -> Result<Decision, StoreOpError> {
    let Ok(sender) = own_key(store)? else {
        return Ok(Decision::Unknown);
    };
    let targets = store.list_hub_login_targets()?;
    let target = targets.iter().find(|row| row.member_id == member);
    let binding = bindings.member(member);
    if let Some(row) = target.filter(|row| row.sealed_bytes.is_some()) {
        let reassigned = bindings
            .by_box(&row.box_id)
            .is_some_and(|owner| owner.member_id != member);
        let moved = matches!(binding, HubMember::Bound(current) if current.box_id != row.box_id);
        if reassigned || moved {
            return Ok(Decision::Discard(row.clone()));
        }
    }
    let (recipient, inventory) = match binding {
        HubMember::Unmapped => return Ok(Decision::Unknown),
        HubMember::Absent => {
            // Discarding sealed bytes preserves the generation, not box ownership.
            // Without a current binding the former owner cannot reclaim the box.
            let Some(row) = target.filter(|row| row.sealed_bytes.is_some()) else {
                return Ok(Decision::Unknown);
            };
            if bindings.box_is_ambiguous(&row.box_id)
                || targets.iter().any(|other| {
                    other.member_id != member
                        && other.box_id == row.box_id
                        && other.sealed_bytes.is_some()
                })
            {
                return Ok(Decision::Unknown);
            }
            (
                Recipient {
                    box_id: row.box_id.clone(),
                    pairing_id: row.pairing_id.clone(),
                    key: row.transfer_public_key,
                },
                Inventory::Ended,
            )
        }
        HubMember::Bound(binding) => {
            let Some(key) = binding.vault_transfer_x25519 else {
                return Ok(Decision::Unknown);
            };
            let eligible = store.federation_member_mapping()?
                && store.login_sharing()?
                && store.list_member_grants()?.iter().any(|grant| {
                    grant.member_id == member
                        && grant.pairing_id == binding.pairing_id
                        && grant.operation == MemberGrantOperation::RemoteRead
                });
            let inventory = if eligible {
                Inventory::Eligible(HomeVault::project_remote_watch(
                    store,
                    member,
                    &binding.pairing_id,
                )?)
            } else {
                Inventory::Ended
            };
            (
                Recipient {
                    box_id: binding.box_id.clone(),
                    pairing_id: binding.pairing_id.clone(),
                    key,
                },
                inventory,
            )
        }
    };
    Ok(Decision::Known {
        target: target.cloned(),
        recipient,
        sender,
        inventory,
    })
}

struct MemberState {
    starting: bool,
    last_kind: Option<HubLoginKind>,
    last_rows: Vec<RemoteWatchRow>,
    resumed: bool,
    /// The refusal last logged for this recipient. A refusal repeats on every
    /// store write until its cause changes, so it is logged once per change.
    refused: Option<&'static str>,
    #[cfg(test)]
    refusals: Option<Arc<std::sync::atomic::AtomicUsize>>,
}

impl Default for MemberState {
    fn default() -> Self {
        Self {
            starting: true,
            last_kind: None,
            last_rows: Vec::new(),
            resumed: true,
            refused: None,
            #[cfg(test)]
            refusals: None,
        }
    }
}

impl MemberState {
    fn refuse(&mut self, reason: &'static str, member: &str, at_max: bool) {
        if self.refused != Some(reason) {
            tracing::warn!(target: "federation", member, at_max, "{reason}");
            #[cfg(test)]
            if let Some(count) = &self.refusals {
                count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        }
        self.refused = Some(reason);
    }

    fn commit(
        &mut self,
        store: &EncryptedStore,
        member: &str,
        home_box: &str,
        decision: Decision,
        floor: Option<HubGeneration>,
    ) -> Result<Option<HubLoginTarget>, StoreOpError> {
        let (target, recipient, sender, inventory) = match decision {
            Decision::Unknown => {
                self.resumed = true;
                return Ok(None);
            }
            Decision::Discard(row) => {
                store.discard_hub_login_target_bytes(member, row.generation)?;
                self.resumed = true;
                return Ok(None);
            }
            Decision::Known {
                target,
                recipient,
                sender,
                inventory,
            } => (target, recipient, sender, inventory),
        };
        let kind = inventory.kind();
        // The hub holds a value this home published at or above the local row's
        // generation (a restored backup): only a new, higher generation can replace it.
        let behind =
            floor.is_some_and(|floor| target.as_ref().is_none_or(|row| row.generation <= floor));
        let seal = behind
            || target.as_ref().is_none_or(|row| {
                row.kind != kind
                    || row.box_id != recipient.box_id
                    || row.pairing_id != recipient.pairing_id
                    || row.transfer_public_key != recipient.key
                    || !matches_sender(row, &sender, home_box)
            })
            || match &inventory {
                Inventory::Eligible(rows) => {
                    self.starting
                        || target.as_ref().is_some_and(|row| row.stale)
                        || !remote_watch_lists_equal(&self.last_rows, rows)
                }
                Inventory::Ended => self.last_kind == Some(HubLoginKind::Snapshot),
            };
        let mut current = target;
        if seal {
            let plaintext = match &inventory {
                Inventory::Eligible(rows) => serde_json::to_vec(&json!({
                    "kind": "snapshot", "logins": remote_watch_logins_wire(rows)
                }))
                .map_err(|_| StoreOpError::Encode("hub login plaintext".into()))?,
                Inventory::Ended => br#"{"kind":"ended"}"#.to_vec(),
            };
            let at_max = current
                .as_ref()
                .is_some_and(|row| row.generation.checked_next().is_none());
            // The hub refuses values over 256 KiB. At the plaintext cap, the
            // base64 ciphertext and tag still leave room in that limit for the
            // encapsulated key and the escaped `LoginAad` (the authenticated but
            // unencrypted header that names sender, recipient and generation).
            if plaintext.len() > MAX_HUB_LOGINS_PLAINTEXT || at_max {
                if let Some(row) = current.as_ref().filter(|row| !row.stale) {
                    store.mark_hub_login_target_stale(member, row.generation)?;
                }
                self.refuse(
                    "hub login value exceeds size or generation limit",
                    member,
                    at_max,
                );
                current = None;
            } else {
                let recipient_id = key_id_for_public(&recipient.key);
                let mut bytes = Vec::new();
                let generation = store.commit_hub_login_target_above(
                    &HubLoginRecipient {
                        member_id: member,
                        box_id: &recipient.box_id,
                        transfer_public_key: &recipient.key,
                        pairing_id: &recipient.pairing_id,
                    },
                    kind,
                    floor,
                    |generation| {
                        bytes = hub_logins::seal(
                            &LoginAad {
                                home: sender.self_id,
                                member: member.into(),
                                home_box: home_box.into(),
                                member_box: recipient.box_id.clone(),
                                generation,
                                sender_key_id: sender.key_id,
                                recipient_key_id: recipient_id,
                            },
                            sender.pem.expose(),
                            &recipient.key,
                            &plaintext,
                        )?;
                        Ok(bytes.clone())
                    },
                );
                let generation = match generation {
                    Ok(generation) => generation,
                    Err(StoreOpError::Encode(_)) => {
                        // Invalid announced key or unusable local encoding: never repair
                        // an older value while the requested one cannot be sealed.
                        if let Some(row) = current.as_ref().filter(|row| !row.stale) {
                            store.mark_hub_login_target_stale(member, row.generation)?;
                        }
                        self.refuse("cannot seal hub login value", member, false);
                        self.resumed = true;
                        return Ok(None);
                    }
                    Err(error) => return Err(error),
                };
                self.refused = None;
                current = Some(HubLoginTarget {
                    member_id: member.into(),
                    box_id: recipient.box_id,
                    transfer_public_key: recipient.key,
                    pairing_id: recipient.pairing_id,
                    generation,
                    kind,
                    sealed_bytes: Some(bytes),
                    stale: false,
                    delivered: false,
                });
                if let Inventory::Eligible(rows) = inventory {
                    self.last_rows = rows;
                }
            }
        }
        self.last_kind = Some(kind);
        self.starting = false;
        Ok(current.filter(|row| !row.stale && row.sealed_bytes.is_some()))
    }
}

fn matches_sender(row: &HubLoginTarget, sender: &OwnKey, home_box: &str) -> bool {
    let aad = row
        .sealed_bytes
        .as_ref()
        .and_then(|bytes| serde_json::from_slice::<LoginEnvelope>(bytes).ok())
        .filter(|envelope| envelope.v == 1)
        .and_then(|envelope| serde_json::from_str::<LoginAad>(&envelope.aad).ok());
    aad.is_some_and(|aad| {
        aad.home == sender.self_id && aad.home_box == home_box && aad.sender_key_id == sender.key_id
    })
}

/// `Ok(Some(generation))` when the hub already holds a value from this home at a
/// higher generation, so writing the local row would move it backwards. A different
/// value at the same generation is a damaged copy and is repaired with the same bytes.
type HubAttempt = Pin<Box<dyn Future<Output = Result<Option<HubGeneration>, HubError>> + Send>>;

fn attempt(hub: Arc<dyn Hub>, row: Arc<HubLoginTarget>, at: Instant) -> HubAttempt {
    Box::pin(async move {
        sleep_until(at).await;
        let Some(bytes) = &row.sealed_bytes else {
            return Ok(None);
        };
        let key = format!("{}.{}", hub.box_id(), row.box_id);
        match hub.entry(SHARED_LOGINS, &key).await? {
            Some(entry) if entry.operation == HubOperation::Put && entry.value == *bytes => {
                Ok(None)
            }
            Some(entry)
                if published_generation(&entry, hub.box_id(), &row.box_id)
                    .is_some_and(|published| published > row.generation) =>
            {
                Ok(published_generation(&entry, hub.box_id(), &row.box_id))
            }
            Some(entry) => hub
                .update(SHARED_LOGINS, &key, bytes.clone(), entry.revision)
                .await
                .map(|_| None),
            None => hub
                .create(SHARED_LOGINS, &key, bytes.clone())
                .await
                .map(|_| None),
        }
    })
}

/// The generation in a hub value's readable header, when it names this home's box
/// and the recipient's box.
fn published_generation(
    entry: &HubEntry,
    home_box: &str,
    member_box: &str,
) -> Option<HubGeneration> {
    if entry.operation != HubOperation::Put {
        return None;
    }
    let envelope: LoginEnvelope = serde_json::from_slice(&entry.value).ok()?;
    let aad: LoginAad = serde_json::from_str(&envelope.aad).ok()?;
    (envelope.v == 1 && aad.home_box == home_box && aad.member_box == member_box)
        .then_some(aad.generation)
}

async fn repair_needed(
    repairs: &mut broadcast::Receiver<Repair>,
    hub: &dyn Hub,
    row: Option<&HubLoginTarget>,
) {
    loop {
        match repairs.recv().await {
            Ok(Repair::All) | Err(broadcast::error::RecvError::Lagged(_)) => return,
            Ok(Repair::Entry(entry)) => {
                if row.is_some_and(|row| {
                    entry.key.split_once('.') == Some((hub.box_id(), row.box_id.as_str()))
                        && (entry.operation != HubOperation::Put
                            || row.sealed_bytes.as_ref() != Some(&entry.value))
                }) {
                    return;
                }
            }
            Err(broadcast::error::RecvError::Closed) => std::future::pending().await,
        }
    }
}

impl MemberTask {
    async fn evaluate(
        &mut self,
        mut state: MemberState,
        floor: Option<HubGeneration>,
    ) -> (
        MemberState,
        Option<Result<Option<HubLoginTarget>, StoreOpError>>,
    ) {
        self.writes.borrow_and_update();
        let bindings = self.bindings.borrow_and_update().clone();
        let versions = (self.writes.clone(), self.bindings.clone());
        let store = Arc::clone(&self.store);
        let member = self.member_id.clone();
        let home_box = self.hub.box_id().to_owned();
        #[cfg(test)]
        let project_gate = self.hooks.project.clone();
        tokio::task::spawn_blocking(move || {
            let decision = bindings.as_ref().map_or(Ok(Decision::Unknown), |bindings| {
                decide(&store, &member, bindings)
            });
            #[cfg(test)]
            if let Some(gate) = project_gate {
                tokio::runtime::Handle::current().block_on(gate());
            }
            // Do not seal a projection that may predate a revoke or re-pair.
            if versions.0.has_changed().unwrap_or(true) || versions.1.has_changed().unwrap_or(true)
            {
                return (state, None);
            }
            let next = decision
                .and_then(|decision| state.commit(&store, &member, &home_box, decision, floor));
            (state, Some(next))
        })
        .await
        .unwrap_or_else(|_| {
            (
                MemberState::default(),
                Some(Err(StoreOpError::Encode(
                    "hub login projection task".into(),
                ))),
            )
        })
    }

    async fn run(mut self) {
        #[cfg(test)]
        if self
            .hooks
            .exit_once
            .as_ref()
            .is_some_and(|exit| exit.swap(false, std::sync::atomic::Ordering::SeqCst))
        {
            return;
        }
        let mut state = MemberState::default();
        #[cfg(test)]
        {
            state.refusals = self.hooks.refusals.clone();
        }
        let mut local_backoff = Backoff::default();
        let mut hub_backoff = Backoff::default();
        let mut decide_at = Some(Instant::now());
        let mut current: Option<Arc<HubLoginTarget>> = None;
        let mut publishing: Option<HubAttempt> = None;
        let mut repair_again = false;
        // The highest generation found on the hub for this recipient that the local
        // row had not reached. Kept for the task's life; the store row passes it once
        // the next value is sealed.
        let mut floor: Option<HubGeneration> = None;
        loop {
            tokio::select! {
                biased;
                changed = self.bindings.changed() => {
                    if changed.is_err() { return; }
                    decide_at = Some(Instant::now());
                }
                changed = self.writes.changed() => {
                    if changed.is_err() { return; }
                    decide_at = Some(Instant::now());
                }
                _ = async { sleep_until(decide_at.expect("a decision is queued")).await }, if decide_at.is_some() => {
                    let (new_state, next) = self.evaluate(state, floor).await;
                    state = new_state;
                    let Some(next) = next else { continue };
                    #[cfg(test)]
                    if let Some(decided) = &self.hooks.decided { decided.notify_one(); }
                    match next {
                        Ok(next) => {
                            decide_at = None;
                            local_backoff.reset();
                            if next.as_ref() != current.as_deref() || (state.resumed && next.is_some()) {
                                current = next.map(Arc::new);
                                publishing = current.as_ref().map(|row| attempt(Arc::clone(&self.hub), Arc::clone(row), Instant::now()));
                                hub_backoff.reset();
                                repair_again = false;
                            }
                            if current.is_some() { state.resumed = false; }
                        }
                        Err(_) => {
                            #[cfg(test)]
                            if let Some(failed) = &self.hooks.failed { failed.notify_one(); }
                            // A failed decision blocks every send, including repairs of
                            // the previous row. Retry without needing another input.
                            current = None;
                            publishing = None;
                            state.resumed = true;
                            repair_again = false;
                            decide_at = Some(Instant::now() + local_backoff.next_delay());
                        }
                    }
                }
                _ = repair_needed(&mut self.repairs, self.hub.as_ref(), current.as_deref()) => {
                    if publishing.is_some() {
                        repair_again = true;
                    } else if let Some(row) = &current {
                        publishing = Some(attempt(Arc::clone(&self.hub), Arc::clone(row), Instant::now()));
                    }
                }
                result = async { publishing.as_mut().expect("an attempt is queued").await }, if publishing.is_some() && decide_at.is_none() => {
                    if let Ok(Some(published)) = result {
                        // Never overwrite a newer value: seal again above it.
                        tracing::warn!(target: "federation", member = %self.member_id, published = published.get(), "hub holds a newer login list from this home than the local store; sealing above it");
                        floor = floor.max(Some(published));
                        current = None;
                        publishing = None;
                        state.resumed = true;
                        decide_at = Some(Instant::now());
                        continue;
                    }
                    let row = current.as_ref().expect("attempt has a committed target");
                    let delivered = result.is_ok() && (row.delivered || self.store.mark_hub_login_target_delivered(
                        &self.member_id, row.generation, row.sealed_bytes.as_deref().expect("attempt has bytes"),
                    ).is_ok());
                    publishing = if !delivered {
                        Some(attempt(Arc::clone(&self.hub), Arc::clone(row), Instant::now() + hub_backoff.next_delay()))
                    } else if std::mem::take(&mut repair_again) {
                        hub_backoff.reset();
                        Some(attempt(Arc::clone(&self.hub), Arc::clone(row), Instant::now()))
                    } else {
                        hub_backoff.reset();
                        None
                    };
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "hub_home_writer_tests.rs"]
mod tests;
