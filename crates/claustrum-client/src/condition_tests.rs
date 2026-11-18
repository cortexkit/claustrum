use super::*;
use std::path::Path;

fn producer_samples(file: &str) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../credentials-module/tests/fixtures/login-conditions-v1")
        .join(file);
    serde_json::from_slice(&std::fs::read(path).expect("producer fixture in the checkout"))
        .expect("producer fixture is JSON")
}

#[tokio::test]
async fn condition_methods_default_to_unavailable_for_an_existing_resolver() {
    let resolver: &dyn CredentialResolver = &UnavailableCredentialResolver;
    let unavailable = CredentialResolverError::unavailable();
    assert_eq!(
        resolver
            .report_condition("id", 1, "provider_ineligible", 403, None, None)
            .await,
        Err(unavailable.clone())
    );
    assert_eq!(
        resolver.clear_condition("id", 1, None).await,
        Err(unavailable)
    );
}

#[test]
fn condition_reply_decoders_use_producer_samples() {
    let samples = producer_samples("consumer-ops.json");
    for case in [
        "report_verification_required",
        "report_ineligible",
        "report_identical",
        "report_new_link",
        "report_reason_replacement",
        "report_version_mismatch",
    ] {
        assert_eq!(
            decode_report_condition_reply(samples[case].clone()),
            Ok(true),
            "{case}"
        );
    }
    for (case, code) in [
        ("report_link_refused", "condition_link_refused"),
        ("report_status_refused", "condition_status_refused"),
        ("report_unknown_reason", "condition_not_admitted"),
    ] {
        let error = decode_report_condition_reply(samples[case].clone()).unwrap_err();
        assert_eq!(error.class, CredentialErrorClass::Permanent);
        assert_eq!(error.code(), "credential_permanent");
        assert!(error.to_string().contains(code));
    }
    for (case, cleared) in [
        ("clear_applied", true),
        ("clear_unset", false),
        ("clear_version_mismatch", false),
    ] {
        assert_eq!(
            decode_clear_condition_reply(samples[case].clone()),
            Ok(cleared),
            "{case}"
        );
    }
    for error in [
        decode_report_condition_reply(samples["report_not_found"].clone()).unwrap_err(),
        decode_clear_condition_reply(samples["clear_not_found"].clone()).unwrap_err(),
    ] {
        assert_eq!(error.class, CredentialErrorClass::CredentialAbsent);
        assert!(error.to_string().contains("not_found"));
    }
}

#[test]
fn condition_reply_decoders_require_boolean_outcomes() {
    for (case, decode) in [
        (
            json!({"result": {"accepted": "true"}}),
            decode_report_condition_reply as fn(_) -> _,
        ),
        (
            json!({"result": {"accepted": true}}),
            decode_clear_condition_reply,
        ),
    ] {
        let error: CredentialResolverError = decode(case).unwrap_err();
        assert_eq!(error.class, CredentialErrorClass::InvalidResponse);
    }
}

#[test]
fn scoped_condition_listing_decodes_producer_samples() {
    let samples = producer_samples("surfaces.json");
    for (case, condition_present, tier) in [
        ("listing_condition", true, None),
        ("listing_condition_with_plan_tier", true, Some("pro")),
        ("listing_unconditioned", false, None),
        ("listing_sign_only", false, None),
    ] {
        let listing = decode_list_scoped_reply(samples[case].clone()).unwrap();
        assert!(listing.undecodable_credentials.is_empty(), "{case}");
        let [row] = listing.credentials.as_slice() else {
            panic!("expected one row in {case}")
        };
        assert_eq!(
            row.condition,
            condition_present.then(|| ListedCredentialCondition {
                reason: "provider_verification_required".into(),
                since_ms: 7,
            }),
            "{case}"
        );
        assert_eq!(row.plan_tier.as_deref(), tier, "{case}");
    }
}

#[test]
fn scoped_condition_since_ms_accepts_the_largest_safe_integer_and_refuses_the_next() {
    let samples = producer_samples("surfaces.json");
    let mut reply = samples["listing_condition"].clone();
    let row = &mut reply["result"]["credentials"][0];
    row["condition"]["reason"] = json!("future_provider_reason");
    row["condition"]["since_ms"] = json!(9_007_199_254_740_991_u64);
    let listing = decode_list_scoped_reply(reply.clone()).unwrap();
    assert!(listing.undecodable_credentials.is_empty());
    assert_eq!(
        listing.credentials[0].condition,
        Some(ListedCredentialCondition {
            reason: "future_provider_reason".into(),
            since_ms: 9_007_199_254_740_991,
        })
    );

    let rows = reply["result"]["credentials"].as_array_mut().unwrap();
    rows[0]["condition"]["since_ms"] = json!(9_007_199_254_740_992_u64);
    let mut sibling = samples["listing_unconditioned"]["result"]["credentials"][0].clone();
    sibling["id"] = json!("usable-sibling");
    rows.push(sibling);
    let listing = decode_list_scoped_reply(reply).unwrap();
    assert_eq!(listing.undecodable_credentials, [
        "oauth:antigravity:condition-fixture: condition.since_ms is not a non-negative safe integer"
    ]);
    assert_eq!(listing.credentials.len(), 1);
    assert_eq!(listing.credentials[0].id, "usable-sibling");
}

#[test]
fn scoped_condition_rejects_malformed_members_without_exposing_the_link() {
    let samples = producer_samples("surfaces.json");
    for (condition, problem) in [
        (json!([]), "condition is not an object"),
        (
            json!({"reason": 4, "since_ms": 0}),
            "condition.reason is not a string",
        ),
        (
            json!({"reason": "reason", "since_ms": -1, "action_url": "private-query-value"}),
            "condition.since_ms is not a non-negative safe integer",
        ),
        (
            json!({"reason": "reason", "since_ms": "7"}),
            "condition.since_ms is not a non-negative safe integer",
        ),
        (
            json!({"reason": "reason", "since_ms": 0.5}),
            "condition.since_ms is not a non-negative safe integer",
        ),
    ] {
        let mut reply = samples["listing_condition"].clone();
        reply["result"]["credentials"][0]["condition"] = condition;
        let listing = decode_list_scoped_reply(reply).unwrap();
        assert!(listing.credentials.is_empty());
        assert_eq!(
            listing.undecodable_credentials,
            [format!("oauth:antigravity:condition-fixture: {problem}")]
        );
    }
}

#[cfg(feature = "transport")]
mod dispatch {
    use super::*;
    use tokio::net::TcpListener;

    struct ConditionConnector(std::net::SocketAddr);

    impl CredentialConsumerConnector for ConditionConnector {
        fn connect(
            &self,
        ) -> CredentialResolverFuture<
            '_,
            Result<Box<dyn CredentialConsumerConnection>, CredentialResolverError>,
        > {
            Box::pin(async move {
                let stream = TcpStream::connect(self.0).await.unwrap();
                Ok(Box::new(ClaustrumConsumer {
                    stream,
                    route_channel: 7,
                    route_epoch: 9,
                    next_corr: 1,
                }) as Box<dyn CredentialConsumerConnection>)
            })
        }
    }

    async fn rig() -> (TcpListener, ClaustrumCredentialResolver) {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let target = Arc::new(LiveCredentialGetTarget::new(
            Arc::new(ConditionConnector(listener.local_addr().unwrap())),
            CREDENTIAL_CALL_DEADLINE,
        ));
        // The resolver has a usable second connection and a nonzero retry budget.
        (
            listener,
            ClaustrumCredentialResolver::with_target(target, 2),
        )
    }

    async fn request(stream: &mut TcpStream) -> (Frame, Value) {
        let frame = tokio::time::timeout(CREDENTIAL_CALL_DEADLINE, read_frame(stream))
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(frame.header.ty, FrameType::Request);
        let body = serde_json::from_slice(&frame.body).unwrap();
        (frame, body)
    }

    async fn reply(stream: &mut TcpStream, request: &Frame, ty: FrameType, body: &Value) {
        let frame = Frame::build(
            ty,
            Flags::new(false, Priority::Interactive, false),
            request.header.channel,
            request.header.epoch,
            request.header.corr,
            serde_json::to_vec(body).unwrap(),
        )
        .unwrap();
        write_frame(stream, &frame).await.unwrap();
    }

    #[tokio::test]
    async fn condition_calls_forward_enrollment_and_leave_status_and_link_checks_to_the_vault() {
        const LINK: &str = "not an absolute URL?account=private-query-value";
        let (listener, resolver) = rig().await;
        let samples = producer_samples("consumer-ops.json");
        let calls = async {
            let resolver: &dyn CredentialResolver = &resolver;
            let error = resolver
                .report_condition(
                    "id",
                    9,
                    "provider_verification_required",
                    403,
                    Some(LINK),
                    Some("token"),
                )
                .await
                .unwrap_err();
            assert_eq!(error.class, CredentialErrorClass::Permanent);
            assert!(error.to_string().contains("condition_link_refused"));
            assert!(!error.to_string().contains("private-query-value"));
            assert!(!format!("{error:?}").contains("private-query-value"));

            let error = resolver
                .report_condition("id", 9, "provider_ineligible", 422, None, None)
                .await
                .unwrap_err();
            assert_eq!(error.class, CredentialErrorClass::Permanent);
            assert!(error.to_string().contains("condition_status_refused"));

            assert!(resolver
                .clear_condition("id", 9, Some("token"))
                .await
                .unwrap());
            let error = resolver.clear_condition("id", 9, None).await.unwrap_err();
            assert_eq!(error.code(), "unknown_method");
        };
        let server = async {
            let (mut stream, _) = listener.accept().await.unwrap();
            for (expected, ty, response) in [
                (
                    json!({"method": "credential.report_condition", "params": {
                        "credential_id": "id", "record_version": 9, "reason": "provider_verification_required",
                        "provider_status": 403, "action_url": LINK, "enrollment_token": "token"
                    }}),
                    FrameType::Response,
                    samples["report_link_refused"].clone(),
                ),
                (
                    json!({"method": "credential.report_condition", "params": {
                        "credential_id": "id", "record_version": 9, "reason": "provider_ineligible", "provider_status": 422
                    }}),
                    FrameType::Response,
                    samples["report_status_refused"].clone(),
                ),
                (
                    json!({"method": "credential.clear_condition", "params": {
                        "credential_id": "id", "record_version": 9, "enrollment_token": "token"
                    }}),
                    FrameType::Response,
                    samples["clear_applied"].clone(),
                ),
                (
                    json!({"method": "credential.clear_condition", "params": {
                        "credential_id": "id", "record_version": 9
                    }}),
                    FrameType::Error,
                    json!({"code": "unknown_method", "message": "not supported"}),
                ),
            ] {
                let (frame, body) = request(&mut stream).await;
                assert_eq!(body, expected);
                reply(&mut stream, &frame, ty, &response).await;
            }
        };
        tokio::join!(calls, server);
    }

    #[tokio::test]
    async fn condition_mutations_are_dispatched_once_when_the_committed_reply_is_lost() {
        for (method, expected_reason) in [
            ("credential.report_condition", "provider_ineligible"),
            (
                "credential.clear_condition",
                "provider_verification_required",
            ),
        ] {
            let (listener, resolver) = rig().await;
            let calls = async {
                let result = if method == "credential.report_condition" {
                    resolver
                        .report_condition("id", 9, "provider_ineligible", 403, None, Some("token"))
                        .await
                } else {
                    resolver.clear_condition("id", 9, Some("token")).await
                };
                let error = result.unwrap_err();
                assert_eq!(error.class, CredentialErrorClass::Transport);
                assert!(error.to_string().contains("closed before replying"));
                let listing = resolver.list_scoped().await.unwrap();
                assert_eq!(
                    listing.credentials[0].condition.as_ref().unwrap().reason,
                    expected_reason
                );
            };
            let server = async {
                let (mut stream, _) = listener.accept().await.unwrap();
                let (_, body) = request(&mut stream).await;
                assert_eq!(body["method"], method);
                // The stand-in vault commits before closing the socket, without sending a reply.
                let mut condition = Some("old_condition".to_owned());
                match method {
                    "credential.report_condition" => {
                        condition = Some(body["params"]["reason"].as_str().unwrap().to_owned());
                    }
                    "credential.clear_condition" => {
                        assert_eq!(condition.take().as_deref(), Some("old_condition"))
                    }
                    _ => unreachable!(),
                }
                drop(stream);
                if condition.is_none() {
                    // Another reader's report lands after the clear whose reply was lost.
                    condition = Some("provider_verification_required".to_owned());
                }
                let (mut stream, _) = listener.accept().await.unwrap();
                let (frame, body) = request(&mut stream).await;
                // A replay would be received before the caller's next operation.
                assert_eq!(body["method"], "credential.list_scoped");
                let mut listing = producer_samples("surfaces.json")["listing_condition"].clone();
                listing["result"]["credentials"][0]["condition"]["reason"] =
                    json!(condition.unwrap());
                reply(&mut stream, &frame, FrameType::Response, &listing).await;
            };
            tokio::join!(calls, server);
        }
    }
}
