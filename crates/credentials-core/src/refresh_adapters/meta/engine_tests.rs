//! Use the real adapter, encrypted store, and refresh engine with reconstructed
//! fixtures to prove consumers receive the inference key, not its minting token.

use super::*;
use crate::device_flow::DeviceTokens;
use crate::refresh_adapters::fixture::FixtureTransport;
use crate::refresh_adapters::meta::{fixtures, login_record, MetaAdapter};
use crate::refresh_adapters::HttpResponse;

async fn setup(status: u16, body: &str) -> (TestTempDir, RefreshEngine, Arc<FixtureTransport>) {
    let (root, descriptor) = tmp_descriptor();
    let store = open_store(&descriptor, 91);
    let (record, _) = login_record(
        DeviceTokens {
            access_token: "meta-identity-token".into(),
            refresh_token: Some("meta-refresh-token".into()),
            expires_at_ms: None,
            expiry_field_present: false,
        },
        &FixtureTransport::ok(200, fixtures::KEY),
    )
    .await
    .unwrap();
    store.create("oauth:meta", &record).unwrap();
    let http = Arc::new(FixtureTransport::new(
        (0..4)
            .map(|_| {
                Ok(HttpResponse {
                    status,
                    body: body.as_bytes().to_vec(),
                })
            })
            .collect(),
    ));
    let engine = RefreshEngine::new(Arc::new(store), vec![Arc::new(MetaAdapter)], http.clone());
    (root, engine, http)
}

#[tokio::test]
async fn meta_protection_no_per_read_mint() {
    let (_root, engine, http) = setup(200, fixtures::KEY).await;
    for _ in 0..3 {
        engine.get("oauth:meta", None, false).await.unwrap();
    }
    assert_eq!(
        http.requests().len(),
        0,
        "fresh reads must not hit the rate-limited mint endpoint"
    );
}

#[tokio::test]
async fn meta_protection_401_latches_needs_reauth() {
    let (_root, engine, http) = setup(401, fixtures::UNAUTHORIZED).await;
    assert!(engine.get("oauth:meta", None, true).await.is_err());
    assert_eq!(http.requests().len(), 1);
    assert!(matches!(
        engine.store().get("oauth:meta"),
        Err(StoreOpError::NeedsReauth)
    ));
}

#[tokio::test]
async fn meta_protection_429_does_not_latch_needs_reauth() {
    let (_root, engine, http) = setup(429, fixtures::TRANSIENT).await;
    assert!(engine.get("oauth:meta", None, true).await.is_err());
    assert_eq!(http.requests().len(), 1);
    let retained = engine
        .store()
        .get("oauth:meta")
        .expect("rate limiting must remain retryable");
    assert_eq!(retained.record_version, 1);
    assert_eq!(retained.payload.expose(), b"muse-inference-key");
    assert!(engine.store().list_intents().unwrap().is_empty());
}

#[tokio::test]
async fn meta_protection_served_secret_is_inference_key_never_identity_token() {
    let (_root, engine, http) = setup(200, fixtures::KEY_JWT).await;
    let initial = engine.store().get("oauth:meta").unwrap();
    assert_eq!(initial.payload.expose(), b"muse-inference-key");
    let served = engine.get("oauth:meta", None, true).await.unwrap();
    assert_eq!(http.requests().len(), 1);
    assert_eq!(served.payload.expose(), b"e30.eyJleHAiOjIwMDAwMDAwMDB9.sig");
    assert_ne!(served.payload.expose(), b"meta-identity-token");
    assert_eq!(
        served.oauth.as_ref().unwrap().refresh_token,
        initial.oauth.unwrap().refresh_token
    );
}

#[tokio::test]
async fn meta_403_subscription_and_outage_dispositions_reach_the_store() {
    for (status, body, terminal) in [
        (403, fixtures::FORBIDDEN, true),
        (200, fixtures::INACTIVE, true),
        (200, fixtures::PAYMENT, true),
        (402, fixtures::PAYMENT, true),
        (503, fixtures::TRANSIENT, false),
    ] {
        let (_root, engine, http) = setup(status, body).await;
        let error = engine.get("oauth:meta", None, true).await.unwrap_err();
        if body == fixtures::INACTIVE || body == fixtures::PAYMENT {
            assert!(matches!(
                error,
                EngineError::RefreshFailed(RefreshError::SubscriptionRequired)
            ));
        }
        assert_eq!(http.requests().len(), 1);
        assert_eq!(
            matches!(
                engine.store().get("oauth:meta"),
                Err(StoreOpError::NeedsReauth)
            ),
            terminal
        );
    }
}

#[tokio::test]
async fn meta_refresh_uses_engine_expiry_min_ttl_and_stale_report_policy() {
    for cause in ["expiry", "min_ttl", "report"] {
        let (_root, engine, http) = setup(200, fixtures::KEY).await;
        // Read from past the report cooldown: the record was just created, and the
        // "report" cause is about the stale mark forcing a refresh once the window
        // no longer holds it back. The cooldown clock does not affect the other causes.
        let engine = engine.with_clock(clock_past_report_cooldown());
        let mut min_ttl = None;
        match cause {
            "expiry" => {
                let mut record = engine.store().get("oauth:meta").unwrap();
                record.expires_at_ms = Some(0);
                record.oauth.as_mut().unwrap().expires_at_ms = Some(0);
                engine
                    .store()
                    .overwrite_cas(
                        "oauth:meta",
                        &record,
                        &crate::store::payload_hash(record.payload.expose()),
                    )
                    .unwrap();
            }
            "min_ttl" => min_ttl = Some(86_400_001),
            _ => {
                engine
                    .store()
                    .mark_stale_if_version_reported(
                        "oauth:meta",
                        1,
                        AuditCtx::vault(AuditOp::ReportAuthFailure),
                        AuthObservation {
                            kind: "consumer_report_stale",
                            provider_status: Some(401),
                            detail: None,
                            reporter_source: None,
                            principal: None,
                        },
                    )
                    .unwrap();
            }
        }
        let refreshed = engine.get("oauth:meta", min_ttl, false).await.unwrap();
        assert_eq!(refreshed.payload.expose(), b"muse-inference-key");
        engine.get("oauth:meta", None, false).await.unwrap();
        assert_eq!(http.requests().len(), 1, "{cause}");
    }
}
