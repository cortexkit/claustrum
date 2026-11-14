//! Startup and live application of the shared config-file resolver.

use std::{collections::HashSet, path::PathBuf, sync::Arc, time::Duration};

use credentials_core::{
    login_sharing::{read_input, resolve, Input, Resolution},
    EncryptedStore, StoreOpError,
};

pub struct ConfigPoll {
    path: PathBuf,
    store: Arc<EncryptedStore>,
    previous: Option<Input>,
    resolution: Resolution,
    applied: Option<bool>,
    warned: HashSet<[u8; 32]>,
}

impl ConfigPoll {
    pub fn new(path: PathBuf, store: Arc<EncryptedStore>) -> Self {
        Self {
            path,
            store,
            previous: None,
            resolution: Resolution::Default,
            applied: None,
            warned: HashSet::new(),
        }
    }

    pub async fn poll(&mut self) -> Result<(), StoreOpError> {
        let path = self.path.clone();
        let input = tokio::task::spawn_blocking(move || read_input(&path))
            .await
            .map_err(|_| StoreOpError::Encode("config reader stopped".into()))?;
        if self.previous.as_ref() != Some(&input) {
            self.resolution = resolve(&input);
            if let Resolution::Invalid(reason) = &self.resolution {
                let digest: [u8; 32] = match &input {
                    Input::Bytes(bytes) => credentials_core::payload_hash(bytes),
                    other => credentials_core::payload_hash(format!("{other:?}").as_bytes()),
                };
                if self.warned.insert(digest) {
                    tracing::warn!(target: "federation", path = %self.path.display(), %reason, "invalid login sharing configuration; applied value retained or off at startup");
                }
            }
            self.previous = Some(input);
        }
        let wanted = self
            .resolution
            .value()
            .unwrap_or(self.applied.unwrap_or(false));
        if self.applied != Some(wanted) {
            let store = Arc::clone(&self.store);
            let actor = format!("config:{}", self.path.display());
            tokio::task::spawn_blocking(move || store.set_login_sharing_audited(wanted, &actor))
                .await
                .map_err(|_| StoreOpError::Encode("config apply stopped".into()))??;
            self.applied = Some(wanted);
        }
        Ok(())
    }

    pub async fn run(mut self) {
        let period = Duration::from_secs(2);
        let mut timer = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            timer.tick().await;
            if self.poll().await.is_err() {
                tracing::warn!(target: "federation", path = %self.path.display(), "login sharing configuration apply failed; retrying");
            }
        }
    }
}
