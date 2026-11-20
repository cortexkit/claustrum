//! The shared hub transport for login lists and manifest reports.

use std::{fmt, time::Duration};

use async_trait::async_trait;
use tokio::sync::watch;

#[cfg(any(test, feature = "test-support"))]
#[path = "hub_stand_in.rs"]
pub(crate) mod stand_in;

pub(crate) const SHARED_LOGINS: &str = "vault-shared-logins";
pub(crate) const MANIFEST_ACTIVE: &str = "vault-manifest-active";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HubOperation {
    Put,
    Delete,
    Purge,
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct HubEntry {
    pub(crate) key: String,
    pub(crate) value: Vec<u8>,
    pub(crate) revision: u64,
    pub(crate) operation: HubOperation,
}

impl fmt::Debug for HubEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HubEntry")
            .field("key", &self.key)
            .field("revision", &self.revision)
            .field("operation", &self.operation)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum HubEvent {
    Entry(HubEntry),
    CaughtUp,
    /// The recreated bucket's entries and a fresh CaughtUp follow on this watch.
    BucketReset {
        bucket: String,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HubError {
    Unavailable,
    Conflict,
}

impl fmt::Display for HubError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unavailable => "hub unavailable",
            Self::Conflict => "hub revision conflict",
        })
    }
}

impl std::error::Error for HubError {}

#[async_trait]
pub(crate) trait HubWatch: Send {
    /// `None` or an error ends the watch; a reset is a normal event on it.
    async fn next(&mut self) -> Option<Result<HubEvent, HubError>>;
}

#[async_trait]
pub(crate) trait Hub: Send + Sync {
    fn box_id(&self) -> &str;
    fn connection_changes(&self) -> watch::Receiver<u64>;
    async fn watch_bucket(&self, bucket: &str) -> Result<Box<dyn HubWatch>, HubError>;
    async fn entry(&self, bucket: &str, key: &str) -> Result<Option<HubEntry>, HubError>;
    async fn create(&self, bucket: &str, key: &str, value: Vec<u8>) -> Result<u64, HubError>;
    async fn update(
        &self,
        bucket: &str,
        key: &str,
        value: Vec<u8>,
        revision: u64,
    ) -> Result<u64, HubError>;
}

#[derive(Default)]
pub(crate) struct Backoff(u64);

impl Backoff {
    /// Callers schedule the delay so newer input can interrupt an old retry.
    pub(crate) fn next_delay(&mut self) -> Duration {
        const MAX_SECONDS: u64 = 600;
        let delay = self.0.max(1);
        self.0 = (delay * 2).min(MAX_SECONDS);
        Duration::from_secs(delay)
    }

    pub(crate) fn reset(&mut self) {
        *self = Self::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hub_backoff_caps_at_ten_minutes_and_resets() {
        let mut backoff = Backoff::default();
        for seconds in [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 600, 600] {
            assert_eq!(backoff.next_delay(), Duration::from_secs(seconds));
        }
        backoff.reset();
        assert_eq!(backoff.next_delay(), Duration::from_secs(1));
    }
}
