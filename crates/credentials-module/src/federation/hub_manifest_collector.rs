//! Readiness derives from authenticated hub reports and the Home's current local admission.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::Arc,
};

use credentials_core::{
    audit::{AuditCtx, AuditOp},
    federation::{MemberGrantOperation, MemberGrantSelector},
    store::{EncryptedStore, GhManifestActivationReport, SecretHomeRole, StoreOpError},
};
use tokio::{
    sync::{mpsc, watch},
    task::{AbortHandle, Id, JoinSet},
    time::{sleep, Instant},
};

use super::{
    hub::{Backoff, Hub, HubEntry, HubError, HubOperation, MANIFEST_ACTIVE},
    hub_binding::{HubBinding, HubBindings},
    hub_manifest,
    hub_manifest_reporter::{store_work, until, watch_reports, Delivery},
    sharing::VaultSharingSnapshot,
};
use crate::manifest_active_report::{report_time_ms, warn_on_downgrade};

type Bindings = watch::Receiver<Option<HubBindings>>;
type Pairings = watch::Receiver<Option<Arc<VaultSharingSnapshot>>>;

enum Role {
    Home,
    Other,
    Unavailable,
}

async fn role(store: &Arc<EncryptedStore>) -> Role {
    let store = Arc::clone(store);
    match store_work(move || Ok(store.secret_home_role())).await {
        Ok(SecretHomeRole::Home { .. }) => Role::Home,
        Ok(SecretHomeRole::StoreError) | Err(_) => Role::Unavailable,
        Ok(_) => Role::Other,
    }
}

pub(crate) async fn run(
    store: Arc<EncryptedStore>,
    hub: Arc<dyn Hub>,
    bindings: Bindings,
    pairings: Pairings,
) {
    let mut writes = store.subscribe_writes();
    let mut backoff = Backoff::default();
    loop {
        writes.borrow_and_update();
        match role(&store).await {
            Role::Home => {
                backoff.reset();
                let active = collect(
                    Arc::clone(&store),
                    Arc::clone(&hub),
                    bindings.clone(),
                    pairings.clone(),
                );
                tokio::pin!(active);
                let mut retry = None;
                loop {
                    tokio::select! {
                        biased;
                        changed = writes.changed() => if changed.is_err() { return; },
                        _ = until(retry) => {},
                        _ = &mut active => return,
                    }
                    match role(&store).await {
                        Role::Home => {
                            backoff.reset();
                            retry = None;
                        }
                        Role::Other => break,
                        Role::Unavailable => retry = Some(Instant::now() + backoff.next_delay()),
                    }
                }
            }
            Role::Other => {
                if writes.changed().await.is_err() {
                    return;
                }
            }
            Role::Unavailable => {
                tokio::select! {
                    changed = writes.changed() => if changed.is_err() { return; },
                    _ = sleep(backoff.next_delay()) => {},
                }
            }
        }
    }
}

async fn collect(
    store: Arc<EncryptedStore>,
    hub: Arc<dyn Hub>,
    bindings: Bindings,
    pairings: Pairings,
) {
    let writes = store.subscribe_writes();
    let mut backoff = Backoff::default();
    loop {
        let store = Arc::clone(&store);
        if store_work(move || store.clear_ungranted_hub_manifest_reports())
            .await
            .is_ok()
        {
            break;
        }
        sleep(backoff.next_delay()).await;
    }
    let (tx, mut rx) = mpsc::channel(1);
    let mut collector = Collector {
        store,
        hub: Arc::clone(&hub),
        bindings,
        pairings,
        writes,
        members: BTreeMap::new(),
        marks: BTreeMap::new(),
        reads: JoinSet::new(),
        local_refresh: Retry::now(),
        reset: Retry::default(),
    };
    // Check pairing and persisted box provenance before the first hub read.
    while collector.local_refresh.at.is_some() {
        until(collector.local_refresh.at).await;
        collector.refresh().await;
    }
    tokio::select! {
        _ = watch_reports(hub.as_ref(), false, tx) => {},
        _ = collector.serve(&mut rx) => {},
    }
}

#[derive(Default)]
struct Retry {
    at: Option<Instant>,
    backoff: Backoff,
}

impl Retry {
    fn now() -> Self {
        Self {
            at: Some(Instant::now()),
            ..Self::default()
        }
    }

    fn later(&mut self) {
        self.at = Some(Instant::now() + self.backoff.next_delay());
    }
}

fn pairing_for<'a>(snapshot: &'a VaultSharingSnapshot, member: &str) -> Option<&'a str> {
    let fingerprint = member.strip_prefix("fed-computer:")?;
    snapshot
        .computers
        .iter()
        .find_map(|(id, pairing)| (id == fingerprint).then_some(pairing.as_str()))
}

fn same_binding(joined: &HubBindings, binding: &HubBinding) -> bool {
    joined.by_box(&binding.box_id).is_some_and(|current| {
        current.member_id == binding.member_id
            && current.pairing_id == binding.pairing_id
            && current.fleet_record_ed25519 == binding.fleet_record_ed25519
    })
}

#[derive(Clone)]
struct Queued {
    entry: HubEntry,
    from_watch: bool,
}

struct Member {
    binding: HubBinding,
    queue: VecDeque<Queued>,
    store_retry: Retry,
    reread: Retry,
    reading: Option<AbortHandle>,
}

impl Member {
    fn new(binding: HubBinding) -> Self {
        Self {
            binding,
            queue: VecDeque::new(),
            store_retry: Retry::default(),
            reread: Retry::now(),
            reading: None,
        }
    }

    fn next_at(&self) -> Option<Instant> {
        if !self.queue.is_empty() && self.reading.is_none() {
            Some(self.store_retry.at.unwrap_or_else(Instant::now))
        } else if self.reading.is_none() {
            self.reread.at
        } else {
            None
        }
    }
}

impl Drop for Member {
    fn drop(&mut self) {
        if let Some(read) = &self.reading {
            read.abort();
        }
    }
}

type ReadDone = (HubBinding, Result<Option<HubEntry>, HubError>);

struct Collector {
    store: Arc<EncryptedStore>,
    hub: Arc<dyn Hub>,
    bindings: Bindings,
    pairings: Pairings,
    writes: watch::Receiver<()>,
    members: BTreeMap<String, Member>,
    marks: BTreeMap<String, u64>,
    reads: JoinSet<ReadDone>,
    local_refresh: Retry,
    reset: Retry,
}

impl Collector {
    async fn refresh(&mut self) {
        let paired = self.pairings.borrow_and_update().clone();
        let joined = self.bindings.borrow_and_update().clone();
        let (store, pairings, bindings) = (
            Arc::clone(&self.store),
            self.pairings.clone(),
            self.bindings.clone(),
        );
        let prior: BTreeSet<_> = self
            .members
            .values()
            .map(|m| (m.binding.member_id.clone(), m.binding.box_id.clone()))
            .collect();
        let result = store_work(move || {
            if let Some(paired) = paired.as_ref() {
                // The roster alone can prove unpair or re-pair even while peer keys lag.
                let mut reconciled = BTreeSet::new();
                for old in store.list_hub_manifest_high_waters()? {
                    let current = pairing_for(paired, &old.member_id);
                    if current != Some(old.pairing_id.as_str())
                        && reconciled.insert(old.member_id.clone())
                    {
                        let mut view = None;
                        store.reconcile_hub_manifest_pairing(&old.member_id, current, || {
                            let latest = pairings.borrow();
                            let unchanged = latest
                                .as_ref()
                                .is_some_and(|p| pairing_for(p, &old.member_id) == current);
                            view = Some(latest);
                            unchanged
                        })?;
                    }
                }
            }
            let mut targets = BTreeMap::new();
            let (Some(paired), Some(joined)) = (&paired, &joined) else {
                return Ok(targets);
            };
            let grants = store.list_member_grants()?;
            let self_member = store.federation_self_member()?;
            for binding in joined.bindings() {
                if self_member.as_ref() == Some(&binding.member_id)
                    || pairing_for(paired, &binding.member_id) != Some(binding.pairing_id.as_str())
                    || !grants.iter().any(|grant| {
                        grant.member_id == binding.member_id
                            && grant.pairing_id == binding.pairing_id
                            && grant.operation == MemberGrantOperation::SecretUse
                            && grant.selector == MemberGrantSelector::None
                    })
                {
                    continue;
                }
                if !prior.contains(&(binding.member_id.clone(), binding.box_id.clone())) {
                    let mut views = None;
                    store.reconcile_hub_manifest_box(
                        &binding.member_id,
                        Some(&binding.box_id),
                        || hold_binding(&mut views, &pairings, &bindings, binding),
                    )?;
                }
                targets.insert(binding.member_id.clone(), binding.clone());
            }
            Ok(targets)
        })
        .await;
        match result {
            Ok(current) => {
                self.members
                    .retain(|member, _| current.contains_key(member));
                for (id, binding) in current {
                    let existing = self
                        .members
                        .entry(id)
                        .or_insert_with(|| Member::new(binding.clone()));
                    if !same_report_binding(&existing.binding, &binding) {
                        *existing = Member::new(binding);
                    }
                }
                self.local_refresh = Retry::default();
            }
            Err(_) => {
                tracing::warn!("could not reconcile local hub manifest admission");
                self.local_refresh.later();
            }
        }
    }

    async fn serve(&mut self, rx: &mut mpsc::Receiver<Delivery>) {
        loop {
            let next = if self.reset.at.is_none() && self.local_refresh.at.is_none() {
                self.members
                    .iter()
                    .filter_map(|(id, m)| Some((m.next_at()?, id.clone())))
                    .min()
            } else {
                None
            };
            tokio::select! {
                biased;
                changed = self.pairings.changed() => {
                    if changed.is_err() { return; }
                    self.local_refresh = Retry::now();
                }
                changed = self.bindings.changed() => {
                    if changed.is_err() { return; }
                    self.local_refresh = Retry::now();
                }
                changed = self.writes.changed() => {
                    if changed.is_err() { return; }
                    self.local_refresh.at.get_or_insert_with(Instant::now);
                }
                _ = until(self.reset.at) => self.clear_reset().await,
                _ = until(self.local_refresh.at) => self.refresh().await,
                _ = until(next.as_ref().map(|(at, _)| *at)) => {
                    if let Some((_, id)) = next { self.step(&id).await; }
                }
                done = self.reads.join_next_with_id(), if !self.reads.is_empty() => {
                    if let Some(Ok((id, (binding, entry)))) = done { self.read_done(id, &binding, entry); }
                }
                delivery = rx.recv(), if self.reset.at.is_none() && self.local_refresh.at.is_none() => match delivery {
                    Some(Delivery::Opened) => {},
                    Some(Delivery::Entry(entry)) => self.on_entry(entry),
                    Some(Delivery::Reset) => {
                        // Old work belongs to the old bucket, even if it has not committed.
                        self.reads.abort_all();
                        self.marks.clear();
                        for member in self.members.values_mut() {
                            member.queue.clear();
                            member.reading = None;
                            member.store_retry = Retry::default();
                            member.reread = Retry::default();
                        }
                        self.reset = Retry::now();
                    }
                    None => return,
                }
            }
        }
    }

    async fn clear_reset(&mut self) {
        let store = Arc::clone(&self.store);
        if store_work(move || store.clear_peer_hub_manifest_reports())
            .await
            .is_ok()
        {
            self.reset = Retry::default();
        } else {
            self.reset.later();
        }
    }

    fn on_entry(&mut self, entry: HubEntry) {
        let joined = self.bindings.borrow();
        if let Some(binding) = joined.as_ref().and_then(|j| j.by_box(&entry.key)) {
            if let Some(member) = self.members.get_mut(&binding.member_id) {
                member.queue.push_back(Queued {
                    entry,
                    from_watch: true,
                });
            }
        }
    }

    fn read_done(
        &mut self,
        id: Id,
        binding: &HubBinding,
        entry: Result<Option<HubEntry>, HubError>,
    ) {
        let Some(member) = self
            .members
            .get_mut(&binding.member_id)
            .filter(|m| m.reading.as_ref().is_some_and(|read| read.id() == id))
        else {
            return;
        };
        member.reading = None;
        match entry {
            Ok(entry) => {
                member.reread = Retry::default();
                if let Some(entry) = entry {
                    member.queue.push_front(Queued {
                        entry,
                        from_watch: false,
                    });
                }
            }
            Err(_) => member.reread.later(),
        }
    }

    async fn step(&mut self, id: &str) {
        let member = self.members.get_mut(id).expect("scheduled member");
        if let Some(work) = member.queue.front().cloned() {
            let binding = member.binding.clone();
            let mark = self.marks.get(&work.entry.key).copied().unwrap_or(0);
            let obsolete = work.entry.key != binding.box_id
                || (work.from_watch && work.entry.revision <= mark);
            let result = if obsolete {
                Ok(false)
            } else {
                let (store, pairings, bindings, entry) = (
                    Arc::clone(&self.store),
                    self.pairings.clone(),
                    self.bindings.clone(),
                    work.entry.clone(),
                );
                store_work(move || apply(&store, &pairings, &bindings, &binding, &entry)).await
            };
            let member = self.members.get_mut(id).expect("scheduled member");
            match result {
                Ok(acted) => {
                    if acted {
                        self.marks
                            .insert(work.entry.key, mark.max(work.entry.revision));
                    }
                    member.queue.pop_front();
                    member.store_retry = Retry::default();
                }
                Err(_) => {
                    tracing::warn!(
                        member_id = id,
                        "hub manifest activation write failed; retrying"
                    );
                    member.store_retry.later();
                }
            }
        } else {
            let binding = member.binding.clone();
            let hub = Arc::clone(&self.hub);
            member.reread.at = None;
            member.reading = Some(self.reads.spawn(async move {
                let entry = hub.entry(MANIFEST_ACTIVE, &binding.box_id).await;
                (binding, entry)
            }));
        }
    }
}

fn same_report_binding(left: &HubBinding, right: &HubBinding) -> bool {
    left.member_id == right.member_id
        && left.box_id == right.box_id
        && left.pairing_id == right.pairing_id
        && left.fleet_record_ed25519 == right.fleet_record_ed25519
}

type Views<'a> = (
    watch::Ref<'a, Option<Arc<VaultSharingSnapshot>>>,
    watch::Ref<'a, Option<HubBindings>>,
);

fn hold_binding<'a>(
    views: &mut Option<Views<'a>>,
    pairings: &'a Pairings,
    bindings: &'a Bindings,
    binding: &HubBinding,
) -> bool {
    // Borrow after the write fence is acquired, and hold through commit. A stale
    // pairing or key must not record anything or consume a sequence number.
    let paired = pairings.borrow();
    let joined = bindings.borrow();
    let current = paired
        .as_ref()
        .is_some_and(|p| pairing_for(p, &binding.member_id) == Some(binding.pairing_id.as_str()))
        && joined.as_ref().is_some_and(|j| same_binding(j, binding));
    *views = Some((paired, joined));
    current
}

fn apply(
    store: &EncryptedStore,
    pairings: &Pairings,
    bindings: &Bindings,
    binding: &HubBinding,
    entry: &HubEntry,
) -> Result<bool, StoreOpError> {
    let mut views = None;
    let Some(body) = (match entry.operation {
        HubOperation::Put if binding.fleet_record_ed25519.is_none() => return Ok(false),
        HubOperation::Put => hub_manifest::verify(&entry.value, binding),
        HubOperation::Delete | HubOperation::Purge => None,
    }) else {
        let mut current = false;
        store.reconcile_hub_manifest_box(&binding.member_id, None, || {
            current = hold_binding(&mut views, pairings, bindings, binding);
            current
        })?;
        return Ok(current);
    };
    let report = GhManifestActivationReport {
        member_id: &binding.member_id,
        version: body.version,
        payload_sha256: &body.manifest_sha256,
        verdict: body.verdict,
        reason: body.reason.as_str(),
        reported_at_ms: report_time_ms(),
    };
    let mut current = false;
    if let Some(outcome) = store.record_hub_manifest_report(
        &report,
        &binding.box_id,
        &binding.pairing_id,
        body.seq,
        || {
            current = hold_binding(&mut views, pairings, bindings, binding);
            current
        },
        AuditCtx {
            actor: &binding.member_id,
            op: AuditOp::GhManifestActivation,
            alarm: None,
        },
    )? {
        warn_on_downgrade(&binding.member_id, outcome);
    }
    Ok(current)
}
