//! Learn organization ids without changing the credentials used to probe them.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use credentials_core::catalog::{api_key_provider_for_credential, ApiKeyProvider};
use credentials_core::record::is_valid_org_id;
use credentials_core::refresh_adapters::HttpTransport;
use credentials_core::store::{EncryptedStore, OrgProbeTarget};
use tokio::time::{sleep_until, Instant};

const INITIAL_RETRY: Duration = Duration::from_secs(60);
const MAX_ORG_PROBE_RETRY: Duration = Duration::from_secs(6 * 60 * 60);

pub(crate) struct Learner {
    store: Arc<EncryptedStore>,
    http: Arc<dyn HttpTransport>,
    retries: BTreeMap<OrgProbeTarget, Retry>,
}

#[derive(Clone, Copy)]
struct Retry {
    at: Instant,
    delay: Duration,
}

impl Retry {
    fn after(previous: Option<Self>, now: Instant) -> Self {
        let delay = previous.map_or(INITIAL_RETRY, |previous| {
            (previous.delay * 2).min(MAX_ORG_PROBE_RETRY)
        });
        Self {
            at: now + delay,
            delay,
        }
    }
}

impl Learner {
    pub(crate) fn new(store: Arc<EncryptedStore>, http: Arc<dyn HttpTransport>) -> Self {
        Self {
            store,
            http,
            retries: BTreeMap::new(),
        }
    }

    pub(crate) async fn run(mut self) {
        let mut writes = self.store.subscribe_writes();
        loop {
            // A write during the pass must cause another scan, including one made
            // while a stale version's HTTP request was still in flight.
            writes.borrow_and_update();
            let wake = match self.pass().await {
                Some(at) => tokio::select! {
                    result = writes.changed() => result,
                    () = sleep_until(at) => continue,
                },
                None => writes.changed().await,
            };
            if wake.is_err() {
                return;
            }
        }
    }

    async fn pass(&mut self) -> Option<Instant> {
        let Ok(targets) = self.store.org_probe_targets() else {
            return Some(Instant::now() + INITIAL_RETRY);
        };
        // Keep backoff only for candidates still missing an org at the same version
        // and incarnation. A replaced or re-created key starts at once.
        let mut previous = std::mem::take(&mut self.retries);
        for target in targets {
            let Some(provider) = api_key_provider_for_credential(&target.credential_id) else {
                continue;
            };
            let Some(header) = provider.org_id_header else {
                continue;
            };
            let retry = previous.remove(&target);
            if let Some(retry) = retry.filter(|retry| Instant::now() < retry.at) {
                self.retries.insert(target, retry);
                continue;
            }
            if let Err((status, reason)) = self.probe(&target, provider, header).await {
                let credential_id: String = target.credential_id.escape_debug().take(128).collect();
                tracing::warn!(
                    target: "claustrum.org",
                    credential_id = %credential_id,
                    status = ?status,
                    reason,
                    "API-key organization probe failed"
                );
                self.retries
                    .insert(target, Retry::after(retry, Instant::now()));
            }
        }
        self.retries.values().map(|retry| retry.at).min()
    }

    async fn probe(
        &self,
        target: &OrgProbeTarget,
        provider: &ApiKeyProvider,
        header: &str,
    ) -> Result<(), (Option<u16>, &'static str)> {
        let Some(key) = self
            .store
            .org_probe_key(target)
            .map_err(|_| (None, "store_read"))?
        else {
            return Ok(());
        };
        let value =
            std::str::from_utf8(key.expose()).map_err(|_| (None, "invalid_key_encoding"))?;
        let response = provider
            .probe_get(self.http.as_ref(), value, Some(header))
            .await
            .map_err(|_| (None, "transport"))?;
        let status = Some(response.status);
        if !(200..=299).contains(&response.status) {
            return Err((status, "http_status"));
        }
        let header = response
            .header
            .as_deref()
            .ok_or((status, "missing_header"))?;
        let org_id = std::str::from_utf8(header)
            .ok()
            .filter(|value| is_valid_org_id(value))
            .ok_or((status, "invalid_header"))?;
        self.store
            .learn_org(target, org_id, crate::read_surface::now_ms())
            .map_err(|_| (status, "store_write"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use credentials_core::audit::{AuditCtx, AuditOp};
    use credentials_core::record::{CredentialKind, VaultRecord};
    use credentials_core::refresh_adapters::{HttpProbeResponse, HttpResponse, RefreshError};
    use std::collections::VecDeque;
    use std::sync::Mutex;

    const ID: &str = "apikey:anthropic:test";

    struct Fixture {
        responses: Mutex<VecDeque<Result<HttpProbeResponse, RefreshError>>>,
        calls: Mutex<Vec<String>>,
    }

    impl Fixture {
        fn with(
            responses: impl IntoIterator<Item = Result<HttpProbeResponse, RefreshError>>,
        ) -> Arc<Self> {
            Arc::new(Self {
                responses: Mutex::new(responses.into_iter().collect()),
                calls: Mutex::new(Vec::new()),
            })
        }
    }

    #[async_trait::async_trait]
    impl HttpTransport for Fixture {
        async fn post(
            &self,
            _: &str,
            _: &[(&str, &str)],
            _: &str,
            _: Vec<u8>,
        ) -> Result<HttpResponse, RefreshError> {
            panic!("learner must use the GET probe");
        }

        async fn probe_get(
            &self,
            url: &str,
            headers: &[(&str, &str)],
            response_header: Option<&str>,
        ) -> Result<HttpProbeResponse, RefreshError> {
            assert_eq!(url, "https://api.anthropic.com/v1/models");
            assert_eq!(response_header, Some("anthropic-organization-id"));
            assert_eq!(headers.len(), 2);
            assert!(headers.contains(&("anthropic-version", "2023-06-01")));
            let key = headers
                .iter()
                .find(|(name, _)| *name == "x-api-key")
                .unwrap()
                .1;
            self.calls.lock().unwrap().push(key.to_owned());
            self.responses
                .lock()
                .unwrap()
                .pop_front()
                .expect("unexpected network probe")
        }
    }

    fn key(bytes: &[u8]) -> VaultRecord {
        VaultRecord::new_static(CredentialKind::ApiKey, "test", bytes.to_vec(), None)
    }

    #[tokio::test]
    async fn learner_scans_at_startup_and_on_credential_commits() {
        let (_surface, store, _, _root) = crate::tests::tmp_surface_with_store(153);
        store.create(ID, &key(b"fixture-existing")).unwrap();
        let fixture = Fixture::with(["org-existing", "org-new"].map(|org| {
            Ok(HttpProbeResponse {
                status: 200,
                header: Some(org.as_bytes().to_vec()),
            })
        }));
        let mut writes = store.subscribe_writes();
        let task = tokio::spawn(Learner::new(store.clone(), fixture.clone()).run());
        for expected in [
            ["fixture-existing"].as_slice(),
            &["fixture-existing", "fixture-new"],
        ] {
            tokio::time::timeout(Duration::from_secs(3), writes.changed())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(fixture.calls.lock().unwrap().as_slice(), expected);
            assert!(!store
                .org_probe_targets()
                .unwrap()
                .iter()
                .any(|target| target.credential_id.starts_with("apikey:anthropic")));
            if expected.len() == 1 {
                store
                    .create("apikey:anthropic:new", &key(b"fixture-new"))
                    .unwrap();
                writes.borrow_and_update();
            }
        }
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
    }

    #[tokio::test]
    async fn learner_ignores_keys_without_an_org_header_and_oauth() {
        let (_surface, store, _, _root) = crate::tests::tmp_surface_with_store(151);
        store.create(ID, &key(b"fixture-anthropic")).unwrap();
        store
            .create("apikey:openai:test", &key(b"fixture-openai"))
            .unwrap();
        let oauth = crate::tests::roster_oauth_record();
        store.create("oauth:anthropic:test", &oauth).unwrap();
        store.create("apikey:anthropic:wrong-kind", &oauth).unwrap();
        store
            .create("apikey:anthropic:inactive", &key(b"fixture-inactive"))
            .unwrap();
        store
            .invalidate_audited(
                "apikey:anthropic:inactive",
                AuditCtx::admin(AuditOp::Invalidate),
            )
            .unwrap();
        let fixture = Fixture::with([Ok(HttpProbeResponse {
            status: 200,
            header: Some(b"org-allowed".to_vec()),
        })]);
        let before = store.read_audit(None).unwrap();
        let mut learner = Learner::new(store.clone(), fixture.clone());

        assert!(learner.pass().await.is_none());
        assert!(learner.pass().await.is_none());
        assert_eq!(
            fixture.calls.lock().unwrap().as_slice(),
            ["fixture-anthropic"]
        );
        let audit = store.read_audit(None).unwrap();
        assert_eq!(audit.len(), before.len() + 1);
        let learned = audit.last().unwrap();
        assert_eq!(learned.credential_id.as_deref(), Some(ID));
        assert_eq!(learned.op, "learn_org");
    }

    #[tokio::test]
    async fn failed_org_probes_leave_state_version_and_audit_unchanged() {
        use credentials_core::store::RecordState;

        let (_surface, store, db, _root) = crate::tests::tmp_surface_with_store(152);
        store.create(ID, &key(b"fixture-anthropic")).unwrap();
        let before = store.meta(ID).unwrap();
        let audit = store.read_audit(None).unwrap();
        let fixture = Fixture::with([
            Ok(HttpProbeResponse {
                status: 200,
                header: None,
            }),
            Ok(HttpProbeResponse {
                status: 200,
                header: Some(b"not valid".to_vec()),
            }),
            Ok(HttpProbeResponse {
                status: 401,
                header: Some(b"org-ignore".to_vec()),
            }),
            Ok(HttpProbeResponse {
                status: 403,
                header: Some(b"org-ignore".to_vec()),
            }),
            Err(RefreshError::Transport("untrusted fixture error".into())),
        ]);
        let mut learner = Learner::new(store.clone(), fixture.clone());
        let conn = rusqlite::Connection::open(db).unwrap();
        for (index, retry_secs) in [60, 120, 240, 480, 960].into_iter().enumerate() {
            assert!(learner.pass().await.is_some());
            let retry = learner.retries.values_mut().next().unwrap();
            assert_eq!(retry.delay, Duration::from_secs(retry_secs));
            // Passes triggered by unrelated store writes cannot advance the retry.
            assert!(learner.pass().await.is_some());
            assert_eq!(fixture.calls.lock().unwrap().len(), index + 1);
            let count: usize = conn
                .query_row("SELECT COUNT(*) FROM credential_orgs", [], |row| row.get(0))
                .unwrap();
            assert_eq!(count, 0);
            let after = store.meta(ID).unwrap();
            assert_eq!(after.state, RecordState::Active);
            assert_eq!(after.record_version, before.record_version);
            assert_eq!(store.read_audit(None).unwrap(), audit);
            learner.retries.values_mut().next().unwrap().at = Instant::now();
        }
        // A replacement skips the old backoff, even when it is not yet due.
        learner.retries.values_mut().next().unwrap().at = Instant::now() + MAX_ORG_PROBE_RETRY;
        store
            .overwrite_unconditional_audited(
                ID,
                &key(b"fixture-replacement"),
                AuditCtx::admin(AuditOp::Overwrite),
            )
            .unwrap();
        fixture
            .responses
            .lock()
            .unwrap()
            .push_back(Ok(HttpProbeResponse {
                status: 200,
                header: Some(b"org-new".to_vec()),
            }));
        assert!(learner.pass().await.is_none());
        assert_eq!(
            fixture.calls.lock().unwrap().last().map(String::as_str),
            Some("fixture-replacement")
        );
    }

    #[test]
    fn org_probe_retry_doubles_to_six_hours_and_clamps_above_it() {
        let now = Instant::now();
        for (previous_ms, next_ms) in [
            (10_799_999, 21_599_998),
            (10_800_000, 21_600_000),
            (10_800_001, 21_600_000),
        ] {
            let previous = Retry {
                at: now,
                delay: Duration::from_millis(previous_ms),
            };
            let next = Retry::after(Some(previous), now);
            assert_eq!(next.at - now, Duration::from_millis(next_ms));
        }
    }
}
