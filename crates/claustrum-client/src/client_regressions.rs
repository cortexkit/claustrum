use super::*;

#[test]
fn error_frames_never_infer_credential_state_from_a_class() {
    for (code, class) in [
        ("not_found", "permanent"),
        ("auth_required", "auth_required"),
    ] {
        let error = decode_wire_error(
            &serde_json::to_vec(&json!({
                "code": code, "class": class, "message": "route failure"
            }))
            .unwrap(),
        );
        assert_eq!(error.class, CredentialErrorClass::Transport);
        assert!(error.retryable());
        let response = decode_credential_reply(json!({"result": {"error": {
            "code": code, "class": class
        }}}))
        .unwrap_err();
        assert!(!response.retryable());
    }
}

#[test]
fn get_rejects_malformed_metadata_and_non_wire_payloads() {
    for (field, invalid_values) in [
        (
            "record_version",
            vec![json!(null), json!({}), json!(1.5), json!(-1), json!("7")],
        ),
        ("expires_at_ms", vec![json!("soon"), json!(1.5), json!({})]),
        ("account_id", vec![json!(7), json!({})]),
        ("email", vec![json!(false), json!([])]),
        ("org_name", vec![json!(7), json!({})]),
        ("payload", vec![json!("A"), json!([256]), json!([1.5])]),
    ] {
        for invalid in invalid_values {
            let mut reply = json!({"result": {"payload": [65], "record_version": 7}});
            reply["result"][field] = invalid.clone();
            let error = decode_credential_reply(reply)
                .expect_err(&format!("must reject {field}={invalid}"));
            assert_eq!(error.class, CredentialErrorClass::InvalidResponse);
        }
    }
}

#[test]
fn get_accepts_unsigned_versions_and_absent_or_null_optional_metadata() {
    for version in [0, u64::MAX] {
        for optional in [
            json!({}),
            json!({
                "expires_at_ms": null, "account_id": null, "email": null, "org_name": null
            }),
        ] {
            let mut result = optional;
            result["payload"] = json!([65]);
            result["record_version"] = json!(version);
            let credential = decode_credential_reply(json!({"result": result})).unwrap();
            assert_eq!(credential.expose(), b"A");
            assert_eq!(credential.record_version, version.to_string());
            assert_eq!(credential.expires_at_ms, None);
            assert_eq!(credential.account_id, None);
            assert_eq!(credential.email, None);
            assert_eq!(credential.org_name, None);
        }
    }
}

#[test]
fn status_rejects_malformed_present_metadata() {
    for (field, invalid_values) in [
        (
            "record_version",
            vec![json!(null), json!({}), json!(1.5), json!(-1), json!("7")],
        ),
        ("stale_pending", vec![json!(null), json!("false"), json!(0)]),
        ("last_error_code", vec![json!(7), json!({})]),
    ] {
        for invalid in invalid_values {
            let mut reply = json!({"result": {"ready": false}});
            reply["result"][field] = invalid.clone();
            let error = decode_credential_status_reply(reply)
                .expect_err(&format!("must reject {field}={invalid}"));
            assert_eq!(error.class, CredentialErrorClass::InvalidResponse);
        }
    }
    let absent = decode_credential_status_reply(json!({"result": {"ready": false}})).unwrap();
    assert_eq!(absent.record_version, None);
    assert!(!absent.stale_pending);
    assert_eq!(absent.last_error_code, None);
}

#[test]
fn grant_tuple_envelope_rejects_wrong_containers_but_keeps_row_diagnostics() {
    for invalid in [json!(null), json!("grants"), json!({}), json!(false)] {
        let error = decode_list_scoped_reply(json!({"result": {
            "view": "view", "credentials": [], "grant_tuples": invalid
        }}))
        .expect_err("a present grant_tuples container must be an array");
        assert_eq!(error.class, CredentialErrorClass::InvalidResponse);
    }
    for result in [
        json!({"view": "view", "credentials": []}),
        json!({"view": "view", "credentials": [], "grant_tuples": []}),
    ] {
        let listing = decode_list_scoped_reply(json!({"result": result})).unwrap();
        assert!(listing.grant_tuples.is_empty());
        assert!(listing.undecodable_grants.is_empty());
    }
    let listing = decode_list_scoped_reply(json!({"result": {
        "view": "view", "credentials": [], "grant_tuples": [null, {
            "selector_kind": "id", "selector": "credential", "operation": "get"
        }]
    }}))
    .unwrap();
    assert_eq!(listing.grant_tuples.len(), 1);
    assert_eq!(listing.undecodable_grants.len(), 1);
}

#[cfg(feature = "transport")]
mod retry {
    use super::*;
    use std::{future::Future, task::Poll};

    #[derive(Clone, Copy, Debug)]
    enum Operation {
        Get,
        Sign,
        PublicKey,
        Scoped,
        Seal,
    }

    struct ScriptedTarget {
        replies: Mutex<VecDeque<Value>>,
        calls: Mutex<Vec<Operation>>,
    }

    impl ScriptedTarget {
        fn reply(&self, operation: Operation) -> Result<Value, CredentialResolverError> {
            self.calls.lock().unwrap().push(operation);
            Ok(self
                .replies
                .lock()
                .unwrap()
                .pop_front()
                .expect("script exhausted"))
        }
    }

    impl CredentialGetTarget for ScriptedTarget {
        fn credential_get<'a>(
            &'a self,
            _: &'a str,
            _: Option<u64>,
            _: bool,
        ) -> CredentialResolverFuture<'a, Result<Value, CredentialResolverError>> {
            Box::pin(async move { self.reply(Operation::Get) })
        }

        fn credential_sign<'a>(
            &'a self,
            _: &'a str,
            _: &'a [u8],
        ) -> CredentialResolverFuture<'a, Result<Value, CredentialResolverError>> {
            Box::pin(async move { self.reply(Operation::Sign) })
        }

        fn credential_public_key<'a>(
            &'a self,
            _: &'a str,
        ) -> CredentialResolverFuture<'a, Result<Value, CredentialResolverError>> {
            Box::pin(async move { self.reply(Operation::PublicKey) })
        }

        fn credential_get_scoped<'a>(
            &'a self,
            _: &'a str,
        ) -> CredentialResolverFuture<'a, Result<Value, CredentialResolverError>> {
            Box::pin(async move { self.reply(Operation::Scoped) })
        }

        fn credential_seal<'a>(
            &'a self,
            _: SealRequest<'a>,
        ) -> CredentialResolverFuture<'a, Result<Value, CredentialResolverError>> {
            Box::pin(async move { self.reply(Operation::Seal) })
        }
    }

    fn scripted(replies: Vec<Value>) -> (Arc<ScriptedTarget>, ClaustrumCredentialResolver) {
        let target = Arc::new(ScriptedTarget {
            replies: Mutex::new(replies.into()),
            calls: Mutex::new(Vec::new()),
        });
        let resolver = ClaustrumCredentialResolver::with_target(target.clone(), 2);
        (target, resolver)
    }

    fn success(operation: Operation) -> Value {
        match operation {
            Operation::Get => json!({"result": {"payload": [65], "record_version": 7}}),
            Operation::Sign => json!({"result": {
                "signature_b64": base64::engine::general_purpose::STANDARD.encode([1; 64]),
                "key_id": "0123456789abcdef"
            }}),
            Operation::PublicKey => json!({"result": {
                "public_key_hex": hex_bytes(&[1; 32]),
                "key_id": hex_bytes(&Sha256::digest([1; 32])[..8]),
                "algorithm": "ed25519"
            }}),
            _ => unreachable!(),
        }
    }

    async fn invoke(
        resolver: &ClaustrumCredentialResolver,
        operation: Operation,
    ) -> Result<(), CredentialResolverError> {
        match operation {
            Operation::Get => resolver.resolve("handle", Some(7), true).await.map(|_| ()),
            Operation::Sign => resolver.sign("id", b"A").await.map(|_| ()),
            Operation::PublicKey => resolver.public_key("id").await.map(|_| ()),
            Operation::Scoped => resolver.get_scoped("id").await.map(|_| ()),
            Operation::Seal => resolver
                .seal(SealRequest {
                    credential_id: "id",
                    recipient_public_key: &[1; 32],
                    info: b"",
                    aad: b"",
                    plaintext: b"A",
                })
                .await
                .map(|_| ()),
        }
    }

    fn transient() -> Value {
        json!({"result": {"error": {"class": "transient", "code": "vault_locked"}}})
    }

    #[tokio::test(start_paused = true)]
    async fn response_refusals_retry_after_backoff_for_handle_sign_and_public_key() {
        for operation in [Operation::Get, Operation::Sign, Operation::PublicKey] {
            let (target, resolver) = scripted(vec![transient(), success(operation)]);
            let mut call = Box::pin(invoke(&resolver, operation));
            let first = std::future::poll_fn(|cx| Poll::Ready(call.as_mut().poll(cx))).await;
            assert!(
                first.is_pending(),
                "{operation:?} must back off before retrying: {first:?}"
            );
            assert_eq!(target.calls.lock().unwrap().len(), 1);
            tokio::time::advance(Duration::from_secs(1)).await;
            call.await.expect("the next Response succeeds");
            assert_eq!(target.calls.lock().unwrap().len(), 2);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn response_retry_budget_and_single_attempt_operations_are_preserved() {
        for operation in [Operation::Get, Operation::Sign, Operation::PublicKey] {
            let (target, resolver) = scripted(vec![transient(); 3]);
            let error = invoke(&resolver, operation).await.unwrap_err();
            assert_eq!(error.class, CredentialErrorClass::Transient);
            assert_eq!(target.calls.lock().unwrap().len(), 3);
            for class in [
                "permanent",
                "auth_required",
                "context_overflow",
                "future_class",
            ] {
                let (target, resolver) = scripted(vec![json!({"result": {"error": {
                    "class": class, "code": "refused"
                }}})]);
                invoke(&resolver, operation).await.unwrap_err();
                assert_eq!(target.calls.lock().unwrap().len(), 1);
            }
        }
        for operation in [Operation::Scoped, Operation::Seal] {
            let (target, resolver) = scripted(vec![transient()]);
            let error = invoke(&resolver, operation).await.unwrap_err();
            assert_eq!(error.class, CredentialErrorClass::Transient);
            assert_eq!(target.calls.lock().unwrap().len(), 1);
        }
    }

    struct ErrorConnector {
        code: &'static str,
        dials: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl CredentialConsumerConnector for ErrorConnector {
        fn connect<'a>(
            &'a self,
        ) -> CredentialResolverFuture<
            'a,
            Result<Box<dyn CredentialConsumerConnection>, CredentialResolverError>,
        > {
            Box::pin(async move {
                let first = self.dials.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0;
                Ok(Box::new(ErrorConsumer {
                    code: first.then_some(self.code),
                }) as Box<dyn CredentialConsumerConnection>)
            })
        }
    }

    struct ErrorConsumer {
        code: Option<&'static str>,
    }

    impl CredentialConsumerConnection for ErrorConsumer {
        fn credential_get<'a>(
            &'a mut self,
            _: &'a str,
            _: Option<u64>,
            _: bool,
        ) -> CredentialResolverFuture<'a, Result<Value, CredentialResolverError>> {
            Box::pin(async move {
                match self.code {
                    Some(code) => Err(decode_wire_error(
                        &serde_json::to_vec(&json!({
                            "code": code, "message": "route refused"
                        }))
                        .unwrap(),
                    )),
                    None => Ok(success(Operation::Get)),
                }
            })
        }

        fn credential_get_scoped<'a>(
            &'a mut self,
            id: &'a str,
            min_ttl_ms: Option<u64>,
        ) -> CredentialResolverFuture<'a, Result<Value, CredentialResolverError>> {
            self.credential_get(id, min_ttl_ms, false)
        }

        fn credential_sign<'a>(
            &'a mut self,
            _: &'a str,
            _: &'a [u8],
        ) -> CredentialResolverFuture<'a, Result<Value, CredentialResolverError>> {
            Box::pin(async { unreachable!() })
        }

        fn credential_public_key<'a>(
            &'a mut self,
            _: &'a str,
        ) -> CredentialResolverFuture<'a, Result<Value, CredentialResolverError>> {
            Box::pin(async { unreachable!() })
        }
    }

    #[tokio::test(start_paused = true)]
    async fn unknown_unary_error_codes_retry_and_redial_the_cached_connection() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        for code in ["route_closed", "future_transport_code", "unknown_module"] {
            let dials = Arc::new(AtomicUsize::new(0));
            let target = Arc::new(LiveCredentialGetTarget::new(
                Arc::new(ErrorConnector {
                    code,
                    dials: dials.clone(),
                }),
                Duration::from_secs(1),
            ));
            let resolver = ClaustrumCredentialResolver::with_target(target, 1);
            let credential = resolver
                .resolve("handle", None, false)
                .await
                .expect("unknown Error codes must retry on a fresh connection");
            assert_eq!(credential.expose(), b"A");
            assert_eq!(dials.load(Ordering::SeqCst), 2, "{code}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn definitive_unary_error_codes_are_terminal_and_keep_the_binding() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        for code in [
            "unknown_method",
            "invalid_params",
            "invalid_request",
            "flow_scopes_unsupported",
            "invalid_control_body",
        ] {
            let dials = Arc::new(AtomicUsize::new(0));
            let target = Arc::new(LiveCredentialGetTarget::new(
                Arc::new(ErrorConnector {
                    code,
                    dials: dials.clone(),
                }),
                Duration::from_secs(1),
            ));
            let resolver = ClaustrumCredentialResolver::with_target(target, 2);
            for _ in 0..2 {
                let error = resolver.resolve("handle", None, false).await.unwrap_err();
                assert_eq!(error.class, CredentialErrorClass::Unclassified);
                assert_eq!(error.code(), code);
                assert!(!error.retryable());
            }
            assert_eq!(dials.load(Ordering::SeqCst), 1, "{code}");
        }
    }
}
