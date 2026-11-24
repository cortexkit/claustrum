//! One publisher signs and repairs this vault's report. The local request only commits it.

use std::{
    future::{pending, Future},
    pin::Pin,
    sync::Arc,
};

use credentials_core::{
    federation::{is_lower_hex_16_bytes, valid_member_id},
    fleet::RECORD_KEY_ID,
    hub_counters::HubReportSeq,
    record::{CredentialKind, RecordState, VaultRecord},
    signing::public_key_ed25519,
    store::{EncryptedStore, HubOwnReport, HubReportTaskState, StoreOpError},
};
use tokio::{
    sync::mpsc,
    time::{sleep, sleep_until, Instant},
};

use super::{
    hub::{Backoff, Hub, HubEntry, HubError, HubEvent, HubOperation, MANIFEST_ACTIVE},
    hub_manifest::{matches_report, published_seq, seal},
};

pub(super) enum Delivery {
    Opened,
    Entry(HubEntry),
    Reset,
}

pub(super) async fn watch_reports(hub: &dyn Hub, own_only: bool, tx: mpsc::Sender<Delivery>) {
    let mut connections = hub.connection_changes();
    let mut backoff = Backoff::default();
    'reopen: loop {
        let opened = tokio::select! {
            biased;
            change = connections.changed() => if change.is_ok() { continue } else { return },
            opened = hub.watch_bucket(MANIFEST_ACTIVE) => opened,
        };
        if let Ok(mut watch) = opened {
            if tx.send(Delivery::Opened).await.is_err() {
                return;
            }
            loop {
                let event = tokio::select! {
                    biased;
                    change = connections.changed() => if change.is_ok() { continue 'reopen } else { return },
                    event = watch.next() => event,
                };
                let Some(Ok(event)) = event else { break };
                backoff.reset();
                let delivery = match event {
                    HubEvent::Entry(entry) if (entry.key == hub.box_id()) == own_only => {
                        Delivery::Entry(entry)
                    }
                    HubEvent::BucketReset { bucket } if bucket == MANIFEST_ACTIVE => {
                        Delivery::Reset
                    }
                    _ => continue,
                };
                if tx.send(delivery).await.is_err() {
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

pub(crate) async fn run(store: Arc<EncryptedStore>, hub: Arc<dyn Hub>) {
    run_inner(
        store,
        hub,
        #[cfg(test)]
        None,
    )
    .await;
}

pub(super) async fn run_inner(
    store: Arc<EncryptedStore>,
    hub: Arc<dyn Hub>,
    #[cfg(test)] sign_failed: Option<Arc<tokio::sync::Notify>>,
) {
    if !is_lower_hex_16_bytes(hub.box_id()) {
        return;
    }
    let (tx, rx) = mpsc::channel(1);
    tokio::select! {
        _ = watch_reports(hub.as_ref(), true, tx) => {},
        _ = publish(store, Arc::clone(&hub), rx, #[cfg(test)] sign_failed) => {},
    }
}

struct Input {
    own: HubOwnReport,
    member: String,
    key: VaultRecord,
    key_id: String,
}

impl Input {
    fn read(store: &EncryptedStore) -> Result<Option<Self>, StoreOpError> {
        let Some(own) = store.hub_own_report()? else {
            return Ok(None);
        };
        let Some(member) = store
            .federation_self_member()?
            .filter(|id| valid_member_id(id))
        else {
            return Ok(None);
        };
        let meta = match store.meta(RECORD_KEY_ID) {
            Ok(meta) if meta.state == RecordState::Active => meta,
            Ok(_) | Err(StoreOpError::NotFound) => return Ok(None),
            Err(error) => return Err(error),
        };
        let Some(incarnation) = meta.incarnation else {
            return Ok(None);
        };
        let key = match store.get_snapshot(RECORD_KEY_ID, &incarnation) {
            Ok(read) if read.record.kind == CredentialKind::SigningKey => read.record,
            Ok(_)
            | Err(StoreOpError::NotFound | StoreOpError::NeedsReauth | StoreOpError::Quarantined) => {
                return Ok(None)
            }
            Err(error) => return Err(error),
        };
        let key_id = public_key_ed25519(pem(&key)?)
            .map_err(|_| StoreOpError::Encode("hub manifest signing key".into()))?
            .key_id;
        Ok(Some(Self {
            own,
            member,
            key,
            key_id,
        }))
    }

    fn same_as(&self, other: &Self) -> bool {
        self.own == other.own && self.member == other.member && self.key_id == other.key_id
    }
}

fn pem(key: &VaultRecord) -> Result<&str, StoreOpError> {
    std::str::from_utf8(key.payload.expose())
        .map_err(|_| StoreOpError::Encode("hub manifest signing key".into()))
}

pub(super) async fn store_work<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, StoreOpError> + Send + 'static,
) -> Result<T, StoreOpError> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|_| StoreOpError::Store("hub manifest store job stopped".into()))?
}

async fn sign(
    store: &Arc<EncryptedStore>,
    input: &Arc<Input>,
    box_id: &str,
    floor: Option<HubReportSeq>,
) -> Result<Option<HubReportTaskState>, StoreOpError> {
    let (store, input, box_id) = (Arc::clone(store), Arc::clone(input), box_id.to_owned());
    store_work(move || {
        let mut state = None;
        store.commit_hub_report_bytes_above(&input.own, floor, |seq| {
            let signed_bytes = seal(&input.own, &box_id, &input.member, seq, pem(&input.key)?)?;
            state = Some(HubReportTaskState {
                seq,
                signed_bytes: signed_bytes.clone(),
                sent: false,
            });
            Ok(signed_bytes)
        })?;
        Ok(state)
    })
    .await
}

async fn mark_sent(
    store: &Arc<EncryptedStore>,
    input: &Arc<Input>,
    state: &HubReportTaskState,
) -> Result<bool, StoreOpError> {
    let (store, input, state) = (Arc::clone(store), Arc::clone(input), state.clone());
    store_work(move || {
        if !Input::read(&store)?.is_some_and(|current| current.same_as(&input)) {
            return Ok(false);
        }
        store.mark_hub_report_sent(&input.own, state.seq, &state.signed_bytes)
    })
    .await
}

enum Finished {
    Read(Result<Option<HubEntry>, HubError>),
    Put(Result<u64, HubError>),
}

type Attempt = Pin<Box<dyn Future<Output = Finished> + Send>>;

fn point_read(hub: Arc<dyn Hub>, at: Instant) -> Attempt {
    Box::pin(async move {
        until(Some(at)).await;
        Finished::Read(hub.entry(MANIFEST_ACTIVE, hub.box_id()).await)
    })
}

fn put(hub: Arc<dyn Hub>, previous: Option<HubEntry>, bytes: Vec<u8>) -> Attempt {
    Box::pin(async move {
        Finished::Put(match previous {
            Some(entry) => {
                hub.update(MANIFEST_ACTIVE, hub.box_id(), bytes, entry.revision)
                    .await
            }
            None => hub.create(MANIFEST_ACTIVE, hub.box_id(), bytes).await,
        })
    })
}

async fn finish(attempt: &mut Option<Attempt>) -> Finished {
    match attempt {
        Some(attempt) => attempt.await,
        None => pending().await,
    }
}

async fn publish(
    store: Arc<EncryptedStore>,
    hub: Arc<dyn Hub>,
    mut rx: mpsc::Receiver<Delivery>,
    #[cfg(test)] sign_failed: Option<Arc<tokio::sync::Notify>>,
) {
    let mut writes = store.subscribe_writes();
    let mut input: Option<Arc<Input>> = None;
    let mut state: Option<HubReportTaskState> = None;
    let mut attempt = None;
    let mut putting = false;
    let mut backoff = Backoff::default();
    let mut refresh_at = Some(Instant::now());
    let mut force_sign = false;
    let mut repair = false;
    // The highest sequence found on the hub that the local row had not reached.
    let mut floor: Option<HubReportSeq> = None;
    let mut records = store.hub_own_report_records();
    loop {
        tokio::select! {
            biased;
            change = writes.changed() => {
                if change.is_err() { return; }
                // An explicit local report, even an unchanged one, is signed afresh.
                let recorded = store.hub_own_report_records();
                if recorded != records {
                    records = recorded;
                    force_sign = true;
                }
                if !force_sign || refresh_at.is_none() {
                    refresh_at = Some(Instant::now());
                }
            }
            _ = until(refresh_at) => {
                refresh_at = None;
                let read = {
                    let store = Arc::clone(&store);
                    store_work(move || Ok((Input::read(&store)?, store.hub_report_task_state()?))).await
                };
                match read {
                    Ok((Some(next), saved)) => {
                        let changed = input.as_ref().is_none_or(|last| !last.same_as(&next));
                        let same_bytes = saved.as_ref().is_some_and(|saved| matches_report(
                            &saved.signed_bytes, &next.own, hub.box_id(), &next.member, &next.key_id,
                        ));
                        if changed || force_sign || !same_bytes || state != saved || (attempt.is_none() && repair) {
                            if changed || force_sign {
                                attempt = None;
                            }
                            if changed {
                                backoff.reset();
                            }
                            let next = Arc::new(next);
                            input = Some(Arc::clone(&next));
                            if !same_bytes || force_sign {
                                match sign(&store, &next, hub.box_id(), floor).await {
                                    Ok(Some(new)) => {
                                        state = Some(new);
                                        force_sign = false;
                                    }
                                    Ok(None) => { refresh_at = Some(Instant::now()); continue; }
                                    Err(_) => {
                                        tracing::warn!("could not persist signed hub manifest report");
                                        refresh_at = Some(Instant::now() + backoff.next_delay());
                                        #[cfg(test)]
                                        if let Some(signal) = &sign_failed {
                                            signal.notify_one();
                                        }
                                        continue;
                                    }
                                }
                            } else {
                                state = saved;
                            }
                            repair = false;
                            putting = false;
                            attempt = Some(point_read(Arc::clone(&hub), Instant::now()));
                        }
                    }
                    Ok((None, _)) => { input = None; state = None; attempt = None; }
                    Err(_) => {
                        attempt = None;
                        refresh_at = Some(Instant::now() + backoff.next_delay());
                    }
                }
            }
            delivery = rx.recv() => {
                match delivery {
                    Some(Delivery::Reset) => {
                        force_sign = true;
                        backoff.reset();
                        attempt = None;
                        refresh_at = Some(Instant::now());
                    }
                    Some(Delivery::Opened) => {
                        repair = true;
                        if !putting { attempt = None; }
                    }
                    Some(Delivery::Entry(entry)) => {
                        repair |= state.as_ref().is_some_and(|state| !holds_bytes(&entry, state));
                    }
                    None => return,
                }
                if repair && attempt.is_none() && refresh_at.is_none() {
                    refresh_at = Some(Instant::now());
                }
            }
            done = finish(&mut attempt) => {
                attempt = None;
                putting = false;
                let (Some(input), Some(latest)) = (&input, &mut state) else { continue };
                match done {
                    Finished::Read(Ok(Some(entry))) if holds_bytes(&entry, latest) => backoff.reset(),
                    Finished::Read(Ok(entry)) => {
                        let published = entry
                            .as_ref()
                            .filter(|entry| entry.operation == HubOperation::Put)
                            .and_then(|entry| published_seq(&entry.value, hub.box_id(), &input.member, &input.key_id))
                            .filter(|published| *published > latest.seq);
                        if let Some(published) = published {
                            // Never replace a value above the local sequence (a
                            // restored backup): sign again above it.
                            tracing::warn!(target: "federation", published = published.get(), "hub holds a newer manifest report from this vault than the local store; signing above it");
                            floor = floor.max(Some(published));
                            force_sign = true;
                            refresh_at = Some(Instant::now());
                            continue;
                        }
                        if latest.sent {
                            // The Home may already have consumed this sequence before the key changed.
                            force_sign = true;
                            refresh_at = Some(Instant::now());
                            continue;
                        }
                        match mark_sent(&store, input, latest).await {
                            Ok(true) => {
                                latest.sent = true;
                                putting = true;
                                attempt = Some(put(Arc::clone(&hub), entry, latest.signed_bytes.clone()));
                            }
                            Ok(false) => refresh_at = Some(Instant::now()),
                            Err(_) => attempt = Some(point_read(Arc::clone(&hub), Instant::now() + backoff.next_delay())),
                        }
                    }
                    Finished::Put(Ok(_)) => backoff.reset(),
                    Finished::Put(Err(_)) | Finished::Read(Err(_)) => {
                        attempt = Some(point_read(Arc::clone(&hub), Instant::now() + backoff.next_delay()));
                    }
                }
                if repair && attempt.is_none() {
                    refresh_at = Some(Instant::now());
                }
            }
        }
    }
}

fn holds_bytes(entry: &HubEntry, state: &HubReportTaskState) -> bool {
    entry.operation == HubOperation::Put && entry.value == state.signed_bytes
}

pub(super) async fn until(at: Option<Instant>) {
    match at {
        Some(at) if at <= Instant::now() => {}
        Some(at) => sleep_until(at).await,
        None => pending().await,
    }
}
