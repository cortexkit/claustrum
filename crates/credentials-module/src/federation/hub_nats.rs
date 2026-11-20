//! Production JetStream transport for the vault's shared hub buckets.

use std::{future::Future, sync::Arc};

use async_nats::jetstream::kv::{self, CreateErrorKind, UpdateErrorKind};
use async_trait::async_trait;
use cortexkit_bus_client::{BucketItem, BucketWatch, BusClientOptions, Error, HubClient};
use subc_client_rs::{ConsumerOptions, SubcConsumer};
use tokio::sync::watch;

use crate::federation::hub::{Backoff, Hub, HubEntry, HubError, HubEvent, HubOperation, HubWatch};

pub(crate) async fn connect_with_retry<F>(mut connect: impl FnMut() -> F) -> Option<Arc<dyn Hub>>
where
    F: Future<Output = Result<Arc<dyn Hub>, Error>>,
{
    let mut backoff = Backoff::default();
    let mut reported_unavailable = false;
    loop {
        match connect().await {
            Ok(hub) => return Some(hub),
            Err(Error::HubNotGranted) => {
                tracing::warn!(target: "federation", "hub sharing disabled: missing ck-bus hub grant for claustrum");
                return None;
            }
            Err(_) => {
                if !reported_unavailable {
                    reported_unavailable = true;
                    tracing::info!(target: "federation", "hub unavailable; retrying in the background");
                }
                tokio::time::sleep(backoff.next_delay()).await;
            }
        }
    }
}

pub(crate) async fn connect() -> Result<Arc<dyn Hub>, Error> {
    let subc = SubcConsumer::connect_default(ConsumerOptions::default())
        .await
        .map_err(|_| Error::HubUnavailable)?;
    let client = HubClient::connect(Arc::new(subc), BusClientOptions::new("claustrum")?).await?;
    let box_id = hub_box_id(&client)?;
    Ok(Arc::new(NatsHub {
        client: Arc::new(client),
        box_id,
    }))
}

fn hub_box_id(client: &HubClient) -> Result<String, Error> {
    // The box id comes only from the hub credential ck-bus issued; a module must
    // never derive it. A valid hub credential always carries one, so `None` means
    // there is no usable hub credential yet: retry like an unavailable hub.
    client
        .box_id()
        .map(|box_id| box_id.as_str().to_owned())
        .ok_or(Error::HubUnavailable)
}

struct NatsHub {
    client: Arc<HubClient>,
    box_id: String,
}

impl NatsHub {
    async fn bucket(&self, bucket: &str) -> Result<kv::Store, HubError> {
        // A context is bound to one NATS client, not to the credential manager.
        // Reopen it for every operation so we follow credential replacement.
        self.client
            .jetstream()
            .map_err(|_| HubError::Unavailable)?
            .get_key_value(bucket)
            .await
            .map_err(|_| HubError::Unavailable)
    }
}

#[async_trait]
impl Hub for NatsHub {
    fn box_id(&self) -> &str {
        &self.box_id
    }

    fn connection_changes(&self) -> watch::Receiver<u64> {
        self.client.connection_changes()
    }

    async fn watch_bucket(&self, bucket: &str) -> Result<Box<dyn HubWatch>, HubError> {
        let watch = self
            .client
            .watch_bucket(bucket)
            .await
            .map_err(|_| HubError::Unavailable)?;
        Ok(Box::new(NatsWatch(Some(watch))))
    }

    async fn entry(&self, bucket: &str, key: &str) -> Result<Option<HubEntry>, HubError> {
        // KV get hides tombstones; entry retains their revisions for compare-and-swap updates.
        self.bucket(bucket)
            .await?
            .entry(key)
            .await
            .map(|entry| entry.map(map_entry))
            .map_err(|_| HubError::Unavailable)
    }

    async fn create(&self, bucket: &str, key: &str, value: Vec<u8>) -> Result<u64, HubError> {
        self.bucket(bucket)
            .await?
            .create(key, value.into())
            .await
            .map_err(|error| map_create_error(error.kind()))
    }

    async fn update(
        &self,
        bucket: &str,
        key: &str,
        value: Vec<u8>,
        revision: u64,
    ) -> Result<u64, HubError> {
        self.bucket(bucket)
            .await?
            .update(key, value.into(), revision)
            .await
            .map_err(|error| map_update_error(error.kind()))
    }
}

struct NatsWatch(Option<BucketWatch>);

#[async_trait]
impl HubWatch for NatsWatch {
    async fn next(&mut self) -> Option<Result<HubEvent, HubError>> {
        let event = map_watch_item(self.0.as_mut()?.next().await);
        if event.is_err() {
            self.0 = None;
        }
        Some(event)
    }
}

fn map_watch_item(item: Result<BucketItem, Error>) -> Result<HubEvent, HubError> {
    match item {
        Ok(BucketItem::Put {
            key,
            revision,
            value,
        }) => Ok(HubEvent::Entry(HubEntry {
            key,
            value: value.to_vec(),
            revision,
            operation: HubOperation::Put,
        })),
        // bus-client reports both delete and purge as this tombstone.
        Ok(BucketItem::Delete { key, revision }) => Ok(HubEvent::Entry(HubEntry {
            key,
            value: Vec::new(),
            revision,
            operation: HubOperation::Delete,
        })),
        Ok(BucketItem::CaughtUp) => Ok(HubEvent::CaughtUp),
        Err(Error::BucketReset { bucket }) => Ok(HubEvent::BucketReset { bucket }),
        _ => Err(HubError::Unavailable),
    }
}

fn map_entry(entry: kv::Entry) -> HubEntry {
    HubEntry {
        key: entry.key,
        value: entry.value.to_vec(),
        revision: entry.revision,
        operation: match entry.operation {
            kv::Operation::Put => HubOperation::Put,
            kv::Operation::Delete => HubOperation::Delete,
            kv::Operation::Purge => HubOperation::Purge,
        },
    }
}

fn map_create_error(kind: CreateErrorKind) -> HubError {
    match kind {
        CreateErrorKind::AlreadyExists => HubError::Conflict,
        _ => HubError::Unavailable,
    }
}

fn map_update_error(kind: UpdateErrorKind) -> HubError {
    match kind {
        UpdateErrorKind::WrongLastRevision => HubError::Conflict,
        _ => HubError::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watch_maps_put_tombstone_caught_up_reset_and_transient_error() {
        let event = map_watch_item(Ok(BucketItem::Put {
            key: "key".into(),
            revision: 17,
            value: b"sealed".as_slice().into(),
        }))
        .unwrap();
        assert_eq!(
            event,
            HubEvent::Entry(HubEntry {
                key: "key".into(),
                revision: 17,
                value: b"sealed".to_vec(),
                operation: HubOperation::Put,
            })
        );
        assert!(!format!("{event:?}").contains("value"));
        assert_eq!(
            map_watch_item(Ok(BucketItem::Delete {
                key: "key".into(),
                revision: 19
            })),
            Ok(HubEvent::Entry(HubEntry {
                key: "key".into(),
                revision: 19,
                value: Vec::new(),
                operation: HubOperation::Delete,
            }))
        );
        assert_eq!(
            map_watch_item(Ok(BucketItem::CaughtUp)),
            Ok(HubEvent::CaughtUp)
        );
        assert_eq!(
            map_watch_item(Err(Error::BucketReset {
                bucket: "bucket".into()
            })),
            Ok(HubEvent::BucketReset {
                bucket: "bucket".into()
            })
        );
        assert_eq!(
            map_watch_item(Err(Error::HubUnavailable)),
            Err(HubError::Unavailable)
        );
    }

    #[test]
    fn point_read_keeps_delete_and_purge_revisions() {
        for (operation, expected) in [
            (kv::Operation::Delete, HubOperation::Delete),
            (kv::Operation::Purge, HubOperation::Purge),
        ] {
            let entry = map_entry(kv::Entry {
                bucket: "bucket".into(),
                key: "key".into(),
                value: Default::default(),
                revision: 42,
                delta: 0,
                created: std::time::UNIX_EPOCH.into(),
                operation,
                seen_current: true,
            });
            assert_eq!(
                entry,
                HubEntry {
                    key: "key".into(),
                    value: Vec::new(),
                    revision: 42,
                    operation: expected,
                }
            );
        }
    }

    #[test]
    fn kv_only_maps_cas_failures_to_conflict() {
        for kind in [
            CreateErrorKind::InvalidKey,
            CreateErrorKind::Publish,
            CreateErrorKind::Ack,
            CreateErrorKind::Other,
        ] {
            assert_eq!(map_create_error(kind), HubError::Unavailable);
        }
        for kind in [
            UpdateErrorKind::InvalidKey,
            UpdateErrorKind::TimedOut,
            UpdateErrorKind::Other,
        ] {
            assert_eq!(map_update_error(kind), HubError::Unavailable);
        }
        assert_eq!(
            map_create_error(CreateErrorKind::AlreadyExists),
            HubError::Conflict
        );
        assert_eq!(
            map_update_error(UpdateErrorKind::WrongLastRevision),
            HubError::Conflict
        );
    }
}
