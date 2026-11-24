//! Apply authenticated login inventories without letting hub availability remove copies.

use std::{
    collections::{BTreeMap, BTreeSet},
    future::pending,
    sync::Arc,
};

use credentials_core::{
    federation::{is_lower_hex_16_bytes, RemoteRecordSource},
    signing::key_id_for_public,
    store::{EncryptedStore, HubLoginApply, HubLoginApplyMode, HubLoginHomeState, StoreOpError},
};
use credentials_core::hub_counters::HubGeneration;
use tokio::{
    sync::{mpsc, watch},
    task::{AbortHandle, JoinSet},
    time::{sleep, sleep_until, Instant},
};

use super::{
    hub::{Backoff, Hub, HubEntry, HubError, HubEvent, HubOperation, SHARED_LOGINS},
    hub_binding::{HubBinding, HubBindings},
    hub_logins::{decode_rows, LoginAad, LoginBody, LoginEnvelope, Snapshot},
    sharing::VaultSharingSnapshot,
    transfer::{TransferKey, TransferKeyCache},
};

type Pairings = watch::Receiver<Option<Arc<VaultSharingSnapshot>>>;
type Bindings = watch::Receiver<Option<HubBindings>>;
type PointRead = (String, String, Result<Option<HubEntry>, HubError>);

pub(crate) async fn run(
    store: Arc<EncryptedStore>,
    hub: Arc<dyn Hub>,
    bindings: Bindings,
    pairings: Pairings,
) {
    run_inner(
        store,
        hub,
        bindings,
        pairings,
        #[cfg(test)]
        TestHooks::default(),
    )
    .await;
}

async fn run_inner(
    store: Arc<EncryptedStore>,
    hub: Arc<dyn Hub>,
    bindings: Bindings,
    pairings: Pairings,
    #[cfg(test)] hooks: TestHooks,
) {
    let (events, mut deliveries) = mpsc::channel(1);
    let writes = store.subscribe_writes();
    let watcher = MemberWatcher {
        store,
        hub: Arc::clone(&hub),
        bindings,
        pairings,
        writes,
        homes: BTreeMap::new(),
        local: Local::default(),
        bound: BTreeMap::new(),
        reads: JoinSet::new(),
        refresh: Retry::default(),
        last_scanned: None,
        keys: Arc::default(),
        #[cfg(test)]
        hooks,
    };
    tokio::select! {
        _ = watch_values(hub.as_ref(), &events) => {},
        _ = watcher.serve(&mut deliveries) => {},
    }
}

async fn watch_values(hub: &dyn Hub, events: &mpsc::Sender<HubEvent>) {
    let mut connections = hub.connection_changes();
    let mut backoff = Backoff::default();
    loop {
        let opened = tokio::select! {
            biased;
            change = connections.changed() => if change.is_ok() { continue } else { return },
            opened = hub.watch_bucket(SHARED_LOGINS) => opened,
        };
        if let Ok(mut watch) = opened {
            loop {
                let event = tokio::select! {
                    biased;
                    change = connections.changed() => if change.is_ok() { break } else { return },
                    event = watch.next() => event,
                };
                let Some(Ok(event)) = event else { break };
                backoff.reset();
                let forward = match &event {
                    HubEvent::Entry(entry) => home_box(&entry.key, hub.box_id()).is_some(),
                    HubEvent::BucketReset { bucket } => bucket == SHARED_LOGINS,
                    HubEvent::CaughtUp => false,
                };
                if forward && events.send(event).await.is_err() {
                    return;
                }
            }
        }
        tokio::select! {
            change = connections.changed() => if change.is_err() { return; },
            _ = sleep(backoff.next_delay()) => {},
        }
    }
}

fn home_box<'a>(key: &'a str, own_box: &str) -> Option<&'a str> {
    let (home, member) = key.split_once('.')?;
    (member == own_box && home != own_box && is_lower_hex_16_bytes(home)).then_some(home)
}

fn pairing_for<'a>(view: &'a VaultSharingSnapshot, home: &str) -> Option<&'a str> {
    let fp = home.strip_prefix("fed-computer:")?;
    view.computers
        .iter()
        .find_map(|(id, pair)| (id == fp).then_some(pair.as_str()))
}

/// A device of a class this build does not recognise is unmapped: it is not a
/// computer, but it is no evidence that the computer went away either.
fn unmapped(view: &VaultSharingSnapshot, home: &str) -> bool {
    home.strip_prefix("fed-computer:")
        .is_some_and(|fp| view.unrecognised.iter().any(|id| id == fp))
}

/// Whether a validated roster proves that copies made under `old` lost their
/// pairing: the home is gone or re-paired. An unmapped home proves nothing.
fn pairing_lost(view: &VaultSharingSnapshot, home: &str, old: Option<&str>) -> bool {
    !unmapped(view, home) && (old.is_none() || old != pairing_for(view, home))
}

/// Acts on a confirmed unpair while no member watcher exists: before the hub
/// connects, or for good when this registration has no hub. It removes only
/// what [`MemberWatcher`] would remove for the same roster, and it is stopped
/// before a member watcher starts, so its removals never race a hub apply.
pub(crate) struct PairingLossRemover {
    store: Arc<EncryptedStore>,
    pairings: Pairings,
    retry: Retry,
}

impl PairingLossRemover {
    pub(crate) fn new(store: Arc<EncryptedStore>, pairings: Pairings) -> Self {
        Self {
            store,
            pairings,
            retry: Retry::default(),
        }
    }

    /// Remove lost pairings until `other` completes. A removal that has started
    /// always finishes before `other`'s output is returned.
    pub(crate) async fn until<T>(&mut self, other: impl std::future::Future<Output = T>) -> T {
        tokio::pin!(other);
        loop {
            tokio::select! {
                biased;
                output = &mut other => return output,
                changed = self.pairings.changed() => {
                    if changed.is_err() {
                        return other.await;
                    }
                    self.retry.wake();
                }
                _ = deadline(self.retry.at) => {
                    self.retry.at = None;
                    if self.remove_lost().await {
                        self.retry.delay.reset();
                    } else {
                        tracing::warn!(target: "federation", "hub login pairing removal failed; retrying");
                        self.retry.failed();
                    }
                }
            }
        }
    }

    async fn remove_lost(&mut self) -> bool {
        // No roster (an unavailable or refused feed) is not evidence of anything.
        let Some(view) = self.pairings.borrow_and_update().clone() else {
            return true;
        };
        let store = Arc::clone(&self.store);
        let removed = tokio::task::spawn_blocking(move || -> Result<(), StoreOpError> {
            let copies = store
                .list_remote_records()?
                .into_iter()
                .filter(|row| row.source == RemoteRecordSource::HomeWatch)
                .map(|row| (row.home_member, row.home_pairing_id));
            let accepted: Vec<_> = store
                .list_hub_login_homes()?
                .into_iter()
                .filter_map(|state| state.pairing_id.map(|pairing| (state.home_member, Some(pairing))))
                .collect();
            let lost: BTreeSet<String> = copies
                .chain(accepted)
                .filter(|(home, old)| pairing_lost(&view, home, old.as_deref()))
                .map(|(home, _)| home)
                .collect();
            for home in lost {
                store.remove_hub_login_home_audited(&home, pairing_for(&view, &home))?;
            }
            Ok(())
        })
        .await;
        matches!(removed, Ok(Ok(())))
    }
}

struct Recipient {
    member: String,
    key_id: String,
    incarnation: String,
    key: Arc<TransferKey>,
}

impl Recipient {
    fn read(
        store: &EncryptedStore,
        keys: &mut TransferKeyCache,
    ) -> Result<Option<Self>, StoreOpError> {
        let Some(member) = store.federation_self_member()? else {
            return Ok(None);
        };
        let Some(key) = keys.read(store)? else {
            return Ok(None);
        };
        Ok(Some(Self {
            member,
            key_id: key.key_id.clone(),
            incarnation: key.incarnation.clone(),
            key,
        }))
    }

    fn stamp(&self) -> (&str, &str, &str, u64) {
        (
            &self.member,
            &self.key_id,
            &self.incarnation,
            self.key.record_version,
        )
    }
}

enum Inventory {
    Snapshot(Snapshot),
    Ended,
}

struct Opened {
    aad: LoginAad,
    pairing: String,
    inventory: Inventory,
}

impl Opened {
    fn open(
        entry: &HubEntry,
        binding: &HubBinding,
        own_box: &str,
        recipient: &Recipient,
    ) -> Option<Self> {
        let envelope: LoginEnvelope = serde_json::from_slice(&entry.value).ok()?;
        let aad: LoginAad = serde_json::from_str(&envelope.aad).ok()?;
        if envelope.v != 1
            || aad.home_box != home_box(&entry.key, own_box)?
            || aad.member_box != own_box
            || !matches_recipient(&aad, recipient)
            || !matches_home(&aad, binding)
        {
            return None;
        }
        let pem = recipient.key.pem.expose();
        let inventory = match envelope.open(pem, binding.vault_transfer_x25519.as_ref()?)? {
            LoginBody::Ended {} => Inventory::Ended,
            LoginBody::Snapshot { logins } => {
                Inventory::Snapshot(decode_rows(&aad.home, logins, |id, _| {
                    tracing::debug!(target: "federation", home = %aad.home, %id, "hub login row rejected; existing row unchanged");
                })?)
            }
        };
        Some(Self {
            aad,
            pairing: binding.pairing_id.clone(),
            inventory,
        })
    }
}

fn matches_recipient(aad: &LoginAad, recipient: &Recipient) -> bool {
    aad.member == recipient.member && aad.recipient_key_id == recipient.key_id
}

fn matches_home(aad: &LoginAad, binding: &HubBinding) -> bool {
    aad.home == binding.member_id
        && aad.home_box == binding.box_id
        && binding
            .vault_transfer_x25519
            .as_ref()
            .is_some_and(|key| aad.sender_key_id == key_id_for_public(key))
}

#[derive(Default)]
struct Local {
    enabled: bool,
    recipient: Option<Arc<Recipient>>,
    accepted: BTreeMap<String, HubLoginHomeState>,
    free_collisions: BTreeMap<String, BTreeSet<String>>,
}

type AutomaticCopies = Vec<(String, Option<String>)>;

impl Local {
    fn read(
        store: &EncryptedStore,
        scan_records: bool,
        keys: &mut TransferKeyCache,
    ) -> Result<(Self, AutomaticCopies), StoreOpError> {
        let enabled = store.login_sharing()?;
        let mut free_collisions = BTreeMap::new();
        let mut accepted = BTreeMap::new();
        for home in store.list_hub_login_homes()? {
            if enabled && !home.reapply {
                for id in &home.skipped_ids {
                    match store.meta(id) {
                        Ok(_) => continue,
                        Err(StoreOpError::NotFound) => {}
                        Err(error) => return Err(error),
                    }
                    if store.remote_record(id)?.is_none() {
                        free_collisions
                            .entry(home.home_member.clone())
                            .or_insert_with(BTreeSet::new)
                            .insert(id.clone());
                    }
                }
            }
            accepted.insert(home.home_member.clone(), home);
        }
        // Automatic copies carry no generation of their own; a pairing scan reads
        // each copy's home and pairing to find those a roster proves lost.
        let copies = if scan_records {
            store
                .list_remote_records()?
                .into_iter()
                .filter(|row| row.source == RemoteRecordSource::HomeWatch)
                .map(|row| (row.home_member, row.home_pairing_id))
                .collect()
        } else {
            Vec::new()
        };
        Ok((
            Self {
                enabled,
                recipient: Recipient::read(store, keys)?.map(Arc::new),
                accepted,
                free_collisions,
            },
            copies,
        ))
    }
}

#[derive(Default)]
struct Retry {
    at: Option<Instant>,
    delay: Backoff,
}

impl Retry {
    fn wake(&mut self) {
        self.at = Some(Instant::now());
        self.delay.reset();
    }

    fn failed(&mut self) {
        self.at = Some(Instant::now() + self.delay.next_delay());
    }

    fn take_due(&mut self) -> bool {
        if self.at.is_some_and(|at| at <= Instant::now()) {
            self.at = None;
            true
        } else {
            false
        }
    }
}

#[derive(Default)]
struct HomeWork {
    pending: Option<Arc<Opened>>,
    apply: Retry,
    read: Retry,
    reading: Option<AbortHandle>,
    removal: Option<(Option<String>, Retry)>,
    /// The older generation last logged as dropped, so a replay logs once.
    warned_older: Option<HubGeneration>,
}

impl HomeWork {
    fn cancel_read(&mut self) -> bool {
        let running = self.reading.take().map(|job| job.abort()).is_some();
        self.read.at.take().is_some() || running
    }

    fn forget_pending(&mut self) {
        self.pending = None;
        self.apply = Retry::default();
    }
}

struct MemberWatcher {
    store: Arc<EncryptedStore>,
    hub: Arc<dyn Hub>,
    bindings: Bindings,
    pairings: Pairings,
    writes: watch::Receiver<()>,
    local: Local,
    bound: BTreeMap<String, HubBinding>,
    homes: BTreeMap<String, HomeWork>,
    reads: JoinSet<PointRead>,
    refresh: Retry,
    last_scanned: Option<Arc<VaultSharingSnapshot>>,
    keys: Arc<std::sync::Mutex<TransferKeyCache>>,
    #[cfg(test)]
    hooks: TestHooks,
}

#[derive(Clone, Copy)]
enum Apply {
    New,
    Restore,
    Fill,
}

#[cfg(test)]
#[derive(Default)]
struct TestHooks {
    before_apply: Option<super::ingress::IssueAuditGate>,
    apply_attempted: Option<Arc<tokio::sync::Notify>>,
    handled: Option<mpsc::UnboundedSender<HubEvent>>,
    /// Receives the homes with a queued removal after each roster is reconciled.
    reconciled: Option<mpsc::UnboundedSender<Vec<String>>>,
    /// Receives the transfer-key decrypt count and the number of homes with held
    /// state after each local refresh.
    refreshed: Option<mpsc::UnboundedSender<(usize, usize)>>,
}

impl MemberWatcher {
    async fn serve(mut self, deliveries: &mut mpsc::Receiver<HubEvent>) {
        self.refresh.wake();
        loop {
            let next_work = self
                .homes
                .values()
                .filter_map(|work| {
                    if let Some((_, removal)) = &work.removal {
                        removal.at
                    } else {
                        work.apply.at.into_iter().chain(work.read.at).min()
                    }
                })
                .min();
            tokio::select! {
                biased;
                change = self.pairings.changed() => {
                    if change.is_err() { return; }
                    self.refresh.wake();
                }
                change = self.bindings.changed() => {
                    if change.is_err() { return; }
                    self.refresh.wake();
                }
                change = self.writes.changed() => {
                    if change.is_err() { return; }
                    if self.refresh.at.is_none() { self.refresh.wake(); }
                }
                _ = deadline(self.refresh.at) => self.refresh_local().await,
                event = deliveries.recv() => match event {
                    None => return,
                    Some(event) => {
                        #[cfg(test)] let observed = self.hooks.handled.as_ref().map(|sink| (sink.clone(), event.clone()));
                        match event {
                            HubEvent::Entry(entry) => { self.receive(entry, false).await; },
                            HubEvent::BucketReset { .. } => self.reset_pending(),
                            HubEvent::CaughtUp => {},
                        }
                        #[cfg(test)] if let Some((sink, event)) = observed { let _ = sink.send(event); }
                    }
                },
                result = self.reads.join_next_with_id(), if !self.reads.is_empty() => {
                    if let Some(Ok((id, (home, key, result)))) = result {
                        self.read_completed(id, home, key, result).await;
                    }
                }
                _ = deadline(next_work) => self.work().await,
            }
        }
    }

    async fn refresh_local(&mut self) {
        let pairings = self.pairings.borrow_and_update().clone();
        let bindings = self.bindings.borrow_and_update().clone();
        let store = Arc::clone(&self.store);
        let scan = pairings.as_ref().is_some_and(|current| {
            self.last_scanned
                .as_ref()
                .is_none_or(|prior| !Arc::ptr_eq(prior, current))
        });
        let keys = Arc::clone(&self.keys);
        let Ok(Ok((local, copies))) = tokio::task::spawn_blocking(move || {
            let mut keys = keys.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            Local::read(&store, scan, &mut keys)
        })
        .await
        else {
            self.refresh.failed();
            return;
        };
        self.refresh = Retry::default();
        if let Some(pairings) = &pairings {
            if scan {
                self.reconcile_pairings(pairings, &local, copies);
                self.last_scanned = Some(Arc::clone(pairings));
                #[cfg(test)]
                if let Some(sink) = &self.hooks.reconciled {
                    let queued = self
                        .homes
                        .iter()
                        .filter(|(_, work)| work.removal.is_some())
                        .map(|(home, _)| home.clone())
                        .collect();
                    let _ = sink.send(queued);
                }
            }
        }
        let bound: BTreeMap<_, _> = bindings
            .iter()
            .flat_map(HubBindings::bindings)
            .filter(|binding| {
                binding.vault_transfer_x25519.is_some()
                    && pairings.as_ref().is_some_and(|pairs| {
                        pairing_for(pairs, &binding.member_id) == Some(&binding.pairing_id)
                    })
            })
            .map(|binding| (binding.member_id.clone(), binding.clone()))
            .collect();
        let setup_changed = local.enabled != self.local.enabled
            || local.recipient.as_deref().map(Recipient::stamp)
                != self.local.recipient.as_deref().map(Recipient::stamp);

        for (home, work) in &mut self.homes {
            if !bound.contains_key(home) || local.recipient.is_none() {
                work.cancel_read();
                work.apply.at = None;
            }
            // A decrypted inventory is not held for a home that is not bound; the
            // point read that follows a rebind fetches it again.
            if !bound.contains_key(home) {
                work.forget_pending();
            }
            if work.pending.as_ref().is_some_and(|pending| {
                local
                    .accepted
                    .get(home)
                    .is_some_and(|state| state.generation >= pending.aad.generation)
            }) {
                work.forget_pending();
            }
        }
        for (home, binding) in &bound {
            let work = self.homes.entry(home.clone()).or_default();
            if local.recipient.is_none() {
                continue;
            }
            if setup_changed || self.bound.get(home) != Some(binding) {
                work.cancel_read();
                work.read.wake();
                if work.pending.is_some() && local.enabled {
                    work.apply.wake();
                } else {
                    work.apply.at = None;
                }
            } else if local.enabled
                && work.pending.is_none()
                && work.reading.is_none()
                && work.read.at.is_none()
            {
                let restore = needs_restore(&local, binding);
                let released = local
                    .free_collisions
                    .get(home)
                    .is_some_and(|free| self.local.free_collisions.get(home) != Some(free));
                if restore || released {
                    work.read.wake();
                }
            }
        }
        // Forget homes with nothing left to do, so state does not accumulate for
        // every home this vault was ever bound to.
        self.homes.retain(|home, work| {
            bound.contains_key(home)
                || work.pending.is_some()
                || work.removal.is_some()
                || work.reading.is_some()
        });
        self.bound = bound;
        self.local = local;
        #[cfg(test)]
        if let Some(sink) = &self.hooks.refreshed {
            let _ = sink.send((self.keys.lock().unwrap().decrypts, self.homes.len()));
        }
    }

    fn reconcile_pairings(
        &mut self,
        pairs: &VaultSharingSnapshot,
        local: &Local,
        copies: AutomaticCopies,
    ) {
        let changed = local.accepted.values().filter_map(|state| {
            state
                .pairing_id
                .as_ref()
                .map(|pairing| (state.home_member.clone(), Some(pairing.clone())))
        });
        for (home, old_pair) in copies.into_iter().chain(changed) {
            if pairing_lost(pairs, &home, old_pair.as_deref()) {
                let work = self.homes.entry(home).or_default();
                // Convert an observed loss to a removal before admitting any hub value.
                work.removal.get_or_insert_with(|| (None, Retry::default()));
            }
        }
        for (home, work) in &mut self.homes {
            let current = pairing_for(pairs, home);
            if work
                .pending
                .as_ref()
                .is_some_and(|pending| Some(pending.pairing.as_str()) != current)
            {
                work.forget_pending();
            }
            if let Some((keep, retry)) = &mut work.removal {
                // An unmapped home leaves a queued removal exactly as it was.
                if !unmapped(pairs, home) {
                    if keep.as_deref() != current || retry.at.is_none() {
                        retry.wake();
                    }
                    *keep = current.map(str::to_owned);
                }
                work.forget_pending();
                work.cancel_read();
            }
        }
    }

    fn reset_pending(&mut self) {
        for (home, work) in &mut self.homes {
            work.forget_pending();
            // A point read begun before the bucket reset may still carry the old bucket's value.
            let interrupted = work.cancel_read();
            if let Some(binding) = self.bound.get(home) {
                if interrupted
                    || needs_restore(&self.local, binding)
                    || self.local.free_collisions.contains_key(home)
                {
                    work.read.wake();
                }
            }
        }
    }

    async fn work(&mut self) {
        for (home, work) in &mut self.homes {
            if let Some((keep, retry)) = &mut work.removal {
                if !retry.take_due() {
                    continue;
                }
                let store = Arc::clone(&self.store);
                let home_id = home.clone();
                let keep = keep.clone();
                let result = tokio::task::spawn_blocking(move || {
                    store.remove_hub_login_home_audited(&home_id, keep.as_deref())
                })
                .await;
                if matches!(result, Ok(Ok(_))) {
                    work.removal = None;
                    if self.bound.contains_key(home) {
                        work.read.wake();
                    }
                } else {
                    tracing::warn!(target: "federation", %home, "hub login pairing removal failed; retrying");
                    retry.failed();
                }
                return;
            }
            if work.apply.take_due() {
                let home = home.clone();
                self.apply_pending(&home).await;
                return;
            }
            if work.read.take_due() {
                if let Some(binding) = self.bound.get(home) {
                    let hub = Arc::clone(&self.hub);
                    let key = format!("{}.{}", binding.box_id, hub.box_id());
                    let home = home.clone();
                    work.reading = Some(self.reads.spawn(async move {
                        let result = hub.entry(SHARED_LOGINS, &key).await;
                        (home, key, result)
                    }));
                }
                return;
            }
        }
    }

    async fn read_completed(
        &mut self,
        id: tokio::task::Id,
        home: String,
        key: String,
        result: Result<Option<HubEntry>, HubError>,
    ) {
        let Some(work) = self.homes.get_mut(&home) else {
            return;
        };
        if !work.reading.as_ref().is_some_and(|job| job.id() == id) {
            return;
        }
        work.reading = None;
        let retry = match result {
            Err(_) => true,
            Ok(Some(entry)) if entry.key == key => self.receive(entry, true).await,
            _ => false,
        };
        let work = self.homes.get_mut(&home).expect("point read's home");
        let restoring = work.pending.is_none()
            && self
                .bound
                .get(&home)
                .is_some_and(|binding| needs_restore(&self.local, binding));
        if retry || restoring {
            work.read.failed();
        } else {
            work.read.delay.reset();
        }
    }

    /// Returns whether a point read needs to be retried after an equal-generation failure.
    async fn receive(&mut self, entry: HubEntry, point_read: bool) -> bool {
        if entry.operation != HubOperation::Put {
            return false;
        }
        let Some(box_id) = home_box(&entry.key, self.hub.box_id()) else {
            return false;
        };
        let Some(binding) = self.bound.values().find(|binding| binding.box_id == box_id) else {
            return false;
        };
        let home = binding.member_id.clone();
        let Some(recipient) = self.local.recipient.as_deref() else {
            return false;
        };
        let work = self.homes.entry(home.clone()).or_default();
        if work.removal.is_some() {
            return false;
        }
        let Some(value) = Opened::open(&entry, binding, self.hub.box_id(), recipient) else {
            return false;
        };
        let generation = value.aad.generation;
        if work
            .pending
            .as_ref()
            .is_some_and(|pending| generation <= pending.aad.generation)
        {
            return false;
        }
        let accepted = self.local.accepted.get(&home);
        if accepted.is_none_or(|state| generation > state.generation) {
            work.pending = Some(Arc::new(value));
            work.apply = Retry::default();
            self.apply_pending(&home).await;
            return false;
        }
        if let Some(state) = accepted.filter(|state| generation < state.generation) {
            // Authenticated but older than what this vault accepted: a restored home
            // republishing from a rewound counter. Logged once per value.
            if work.warned_older != Some(generation) {
                tracing::warn!(target: "federation", %home, generation = generation.get(), accepted = state.generation.get(), "hub login list older than the accepted one; dropped");
                work.warned_older = Some(generation);
            }
        }
        let Some(accepted) = accepted.filter(|state| {
            point_read
                && self.local.enabled
                && work.pending.is_none()
                && state.generation == generation
                && state.pairing_id.as_deref() == Some(&value.pairing)
        }) else {
            return false;
        };
        let mode = if accepted.reapply {
            Apply::Restore
        } else if !accepted.skipped_ids.is_empty()
            && matches!(value.inventory, Inventory::Snapshot(_))
        {
            Apply::Fill
        } else {
            return false;
        };
        !self.commit(Arc::new(value), mode).await
    }

    async fn apply_pending(&mut self, home: &str) {
        if !self.local.enabled || !self.bound.contains_key(home) {
            return;
        }
        let Some(value) = self.homes.get(home).and_then(|work| work.pending.clone()) else {
            return;
        };
        let committed = self.commit(value, Apply::New).await;
        let work = self.homes.get_mut(home).expect("pending value's home");
        if committed {
            work.forget_pending();
        } else {
            work.apply.failed();
        }
    }

    async fn commit(&mut self, value: Arc<Opened>, mode: Apply) -> bool {
        let Some(recipient) = self.local.recipient.clone() else {
            return false;
        };
        if !matches_recipient(&value.aad, &recipient)
            || !self.bound.get(&value.aad.home).is_some_and(|binding| {
                binding.pairing_id == value.pairing && matches_home(&value.aad, binding)
            })
        {
            return false;
        }
        let bindings = self.bindings.clone();
        let pairings = self.pairings.clone();
        let store = Arc::clone(&self.store);
        let home = value.aad.home.clone();
        let pairing = value.pairing.clone();
        let generation = value.aad.generation;
        #[cfg(test)]
        if let Some(gate) = &self.hooks.before_apply {
            gate().await;
        }
        let result = tokio::task::spawn_blocking(move || {
            let apply = HubLoginApply {
                home_member: &value.aad.home,
                recipient_member: &value.aad.member,
                pairing_id: &value.pairing,
                generation,
                recipient_key_incarnation: &recipient.incarnation,
                recipient_key_record_version: recipient.key.record_version,
            };
            let mode = match (mode, &value.inventory) {
                (Apply::New, Inventory::Snapshot(snapshot)) => HubLoginApplyMode::NewSnapshot {
                    rows: &snapshot.rows,
                    retained_ids: &snapshot.retained_ids,
                },
                (Apply::New, Inventory::Ended) => HubLoginApplyMode::Ended,
                (Apply::Restore, Inventory::Snapshot(snapshot)) => {
                    HubLoginApplyMode::RestoreSnapshot {
                        rows: &snapshot.rows,
                        retained_ids: &snapshot.retained_ids,
                    }
                }
                (Apply::Restore, Inventory::Ended) => HubLoginApplyMode::RestoreEnded,
                (Apply::Fill, Inventory::Snapshot(snapshot)) => HubLoginApplyMode::FillCollisions {
                    rows: &snapshot.rows,
                },
                (Apply::Fill, Inventory::Ended) => return Ok(None),
            };
            // Read the latest views after the write transaction begins and keep
            // them stable through commit, not while waiting for a previous writer.
            let mut views = None;
            store.apply_hub_login_audited(&apply, mode, || {
                let paired = pairings.borrow();
                let joined = bindings.borrow();
                let current = paired.as_ref().is_some_and(|pairs| {
                    pairing_for(pairs, &value.aad.home) == Some(&value.pairing)
                }) && joined
                    .as_ref()
                    .and_then(|view| view.by_box(&value.aad.home_box))
                    .is_some_and(|binding| {
                        binding.pairing_id == value.pairing && matches_home(&value.aad, binding)
                    });
                views = Some((paired, joined));
                current
            })
        })
        .await;
        #[cfg(test)]
        if let Some(attempted) = &self.hooks.apply_attempted {
            attempted.notify_one();
        }
        match result {
            Ok(Ok(Some(result))) => {
                self.local.accepted.insert(
                    home.clone(),
                    HubLoginHomeState {
                        home_member: home,
                        pairing_id: Some(pairing),
                        generation,
                        skipped_ids: result.skipped,
                        reapply: false,
                    },
                );
                true
            }
            Ok(Ok(None)) => false,
            _ => {
                tracing::warn!(target: "federation", %home, "hub login apply failed; retrying");
                false
            }
        }
    }
}

fn needs_restore(local: &Local, binding: &HubBinding) -> bool {
    local.enabled
        && local.recipient.is_some()
        && local.accepted.get(&binding.member_id).is_some_and(|state| {
            state.reapply && state.pairing_id.as_deref() == Some(&binding.pairing_id)
        })
}

async fn deadline(at: Option<Instant>) {
    match at {
        Some(at) if at > Instant::now() => sleep_until(at).await,
        Some(_) => {}
        None => pending().await,
    }
}

#[cfg(test)]
#[path = "hub_member_watcher_tests.rs"]
mod tests;
