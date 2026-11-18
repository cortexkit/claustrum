use super::*;
use crate::sensitive_wire::Request;

#[test]
fn module_secret_decodes_the_real_daemon_wire_fixture() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../credentials-module/tests/fixtures/module_secret_wire_contract.json");
    let fixture: Value =
        serde_json::from_slice(&std::fs::read(path).expect("daemon wire fixture")).unwrap();
    let bytes = |case: &str| Secret::new(serde_json::to_vec(&fixture["success"][case]).unwrap());
    let written: ModuleSecretWritten = decode(&bytes("replace")).unwrap();
    assert_eq!(
        written,
        ModuleSecretWritten {
            name: "key".into(),
            version: 2,
            created: false
        }
    );
    let get_bytes = bytes("get");
    let got: Got<'_> = decode(&get_bytes).unwrap();
    assert_eq!(got.name, "key");
    assert_eq!(got.value.0, "BAU=");
    assert_eq!(got.version, 2);
    assert!(!got.protected);
    let list: Listed = decode(&bytes("list_corrupt")).unwrap();
    assert_eq!(list.items.len(), 2);
    assert_eq!(list.items[0].state, ModuleSecretState::Corrupt);
    assert!(list.items[1].protected);
    assert!(decode::<Deleted>(&bytes("delete")).unwrap().deleted);
    for (code, body) in fixture["refusals"].as_object().unwrap() {
        let error = decode::<Deleted>(&Secret::new(serde_json::to_vec(body).unwrap())).unwrap_err();
        match code.as_str() {
            "module_secret_version_conflict" => {
                assert_eq!(error, ModuleSecretError::VersionConflict)
            }
            "module_secret_protected" => assert_eq!(error, ModuleSecretError::Protected),
            "module_secret_limit" => assert_eq!(error, ModuleSecretError::Limit),
            _ => assert!(matches!(error, ModuleSecretError::Other(_))),
        }
    }
}

#[test]
fn module_secret_value_buffers_and_wire_types_have_redacted_debug() {
    const TEXT: &str = "client-owned-value-canary";
    const ENCODED: &str = "Y2xpZW50LW93bmVkLXZhbHVlLWNhbmFyeQ==";
    let request = Request {
        method: "module_secret.put",
        params: Put {
            name: "key",
            value: Secret::new(ENCODED.to_owned()),
            expected_version: Some(2),
            protected: Some(false),
        },
    };
    let reply = Secret::new(
        format!(
            r#"{{"result":{{"name":"key","version":3,"value":"{ENCODED}","protected":false}}}}"#
        )
        .into_bytes(),
    );
    let got: Got<'_> = decode(&reply).unwrap();
    let values = [
        format!("{:?}", Secret::new(TEXT.to_owned())),
        format!("{:?}", Secret::new(TEXT.as_bytes().to_vec())),
        format!("{request:?}"),
        format!("{:?}", encode(request.params, "module_secret.put").unwrap()),
        format!("{reply:?}"),
        format!("{got:?}"),
        format!("{:?}", Reply { result: got }),
        format!(
            "{:?}",
            ModuleSecret {
                name: "key".into(),
                version: 3,
                value: Secret::new(TEXT.as_bytes().to_vec()),
                protected: false
            }
        ),
        format!(
            "{:?}",
            Request {
                method: "module_secret.get",
                params: Named {
                    name: "key",
                    expected_version: None
                }
            }
        ),
        format!(
            "{:?}",
            Request {
                method: "module_secret.delete",
                params: Named {
                    name: "key",
                    expected_version: Some(3)
                }
            }
        ),
        format!(
            "{:?}",
            Request {
                method: "module_secret.list",
                params: Empty {}
            }
        ),
        format!(
            "{:?}",
            ModuleSecretWritten {
                name: "key".into(),
                version: 3,
                created: false
            }
        ),
        format!("{:?}", Deleted { deleted: true }),
        format!(
            "{:?}",
            Listed {
                items: vec![ModuleSecretSummary {
                    name: "key".into(),
                    version: 3,
                    protected: false,
                    state: ModuleSecretState::Active,
                    updated_at_ms: 123
                }]
            }
        ),
        format!(
            "{:?}",
            MaybeError {
                error: Some(WireError {
                    code: "not_found",
                    class: Some("permanent")
                })
            }
        ),
    ];
    for debug in values {
        assert!(!debug.contains(TEXT));
        assert!(!debug.contains(ENCODED));
        assert!(!debug.contains(&format!("{:?}", TEXT.as_bytes())));
    }
    assert_eq!(format!("{:?}", Secret::new(TEXT.to_owned())), "<redacted>");
    assert_eq!(
        format!("{:?}", Secret::new(TEXT.as_bytes().to_vec())),
        "<redacted>"
    );
}

#[test]
fn module_secret_secret_scrubs_its_owned_buffer_on_drop() {
    struct Probe(std::sync::Arc<std::sync::atomic::AtomicBool>);
    impl Zeroize for Probe {
        fn zeroize(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }
    let scrubbed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let secret = Secret::new(Probe(scrubbed.clone()));
    assert!(!scrubbed.load(std::sync::atomic::Ordering::SeqCst));
    drop(secret);
    assert!(scrubbed.load(std::sync::atomic::Ordering::SeqCst));
}

#[test]
fn module_secret_errors_map_before_the_unchanged_generic_classifier() {
    for (code, expected) in [
        (
            "module_secret_version_conflict",
            ModuleSecretError::VersionConflict,
        ),
        ("module_secret_protected", ModuleSecretError::Protected),
        ("module_secret_limit", ModuleSecretError::Limit),
    ] {
        let bytes = Secret::new(
            format!(r#"{{"result":{{"error":{{"code":"{code}","class":"permanent"}}}}}}"#)
                .into_bytes(),
        );
        assert_eq!(decode::<Deleted>(&bytes).unwrap_err(), expected);
        let generic =
            classify_error_value(&serde_json::json!({"code": code, "class": "permanent"}));
        assert_eq!(generic.class, CredentialErrorClass::Permanent);
        assert_eq!(generic.code(), "credential_permanent");
    }
    for (code, class, expected) in [
        (
            "not_found",
            "permanent",
            CredentialErrorClass::CredentialAbsent,
        ),
        ("corrupt", "permanent", CredentialErrorClass::Permanent),
        (
            "invalid_params",
            "permanent",
            CredentialErrorClass::Permanent,
        ),
        ("vault_locked", "transient", CredentialErrorClass::Transient),
        ("store_error", "transient", CredentialErrorClass::Transient),
        ("route_busy", "transient", CredentialErrorClass::Transient),
    ] {
        let bytes = Secret::new(format!(r#"{{"result":{{"error":{{"code":"{code}","class":"{class}","message":"do-not-echo"}}}}}}"#).into_bytes());
        let ModuleSecretError::Other(error) = decode::<Deleted>(&bytes).unwrap_err() else {
            panic!("generic error expected")
        };
        assert_eq!(error.class, expected);
        assert!(!format!("{error:?}").contains("do-not-echo"));
    }
}

#[test]
fn module_secret_wire_decode_rejects_malformed_bodies_without_echoing_values() {
    for bytes in [
        br#"not-json-canary"#.as_slice(),
        br#"{"result":{"name":"key","value":"canary"}}"#,
    ] {
        let error = decode::<Got<'_>>(&Secret::new(bytes.to_vec())).unwrap_err();
        assert!(matches!(
            error,
            ModuleSecretError::Other(CredentialResolverError {
                class: CredentialErrorClass::InvalidResponse,
                ..
            })
        ));
        assert!(!format!("{error:?}").contains("canary"));
    }
    let reply = Secret::new(br#"{"result":{"items":[{"name":"broken","version":1,"protected":true,"state":"corrupt","updated_at_ms":-1}]}}"#.to_vec());
    assert_eq!(
        decode::<Listed>(&reply).unwrap().items[0].state,
        ModuleSecretState::Corrupt
    );
}

#[cfg(feature = "transport")]
mod live {
    use super::*;

    struct Script {
        replies: Mutex<VecDeque<Result<Secret<Vec<u8>>, CredentialResolverError>>>,
        requests: Mutex<Vec<Secret<Vec<u8>>>>,
    }
    struct Connection(Arc<Script>);
    impl CredentialConsumerConnection for Connection {
        fn sensitive_request(
            &mut self,
            request: Secret<Vec<u8>>,
        ) -> CredentialResolverFuture<'_, Result<Secret<Vec<u8>>, CredentialResolverError>>
        {
            self.0.requests.lock().unwrap().push(request);
            let reply = self
                .0
                .replies
                .lock()
                .unwrap()
                .pop_front()
                .expect("one scripted attempt");
            Box::pin(async move { reply })
        }
    }
    struct Connector(Arc<Script>);
    impl CredentialConsumerConnector for Connector {
        fn connect(
            &self,
        ) -> CredentialResolverFuture<
            '_,
            Result<Box<dyn CredentialConsumerConnection>, CredentialResolverError>,
        > {
            let connection = Connection(self.0.clone());
            Box::pin(
                async move { Ok(Box::new(connection) as Box<dyn CredentialConsumerConnection>) },
            )
        }
    }
    fn resolver(
        replies: Vec<Result<Secret<Vec<u8>>, CredentialResolverError>>,
    ) -> (ClaustrumCredentialResolver, Arc<Script>) {
        let script = Arc::new(Script {
            replies: Mutex::new(replies.into()),
            requests: Mutex::new(Vec::new()),
        });
        let target = Arc::new(LiveCredentialGetTarget::new(
            Arc::new(Connector(script.clone())),
            CREDENTIAL_CALL_DEADLINE,
        ));
        (
            ClaustrumCredentialResolver {
                live_target: None,
                target: target.clone(),
                module_secret_target: Some(target),
                transient_retries: 99,
            },
            script,
        )
    }
    fn ok(bytes: &[u8]) -> Result<Secret<Vec<u8>>, CredentialResolverError> {
        Ok(Secret::new(bytes.to_vec()))
    }

    #[tokio::test]
    async fn module_secret_operations_share_typed_single_shot_wire_layer() {
        let (resolver, script) = resolver(vec![
            ok(br#"{"result":{"name":"key","version":1,"created":true}}"#),
            ok(br#"{"result":{"name":"key","version":1,"value":"AAH/","protected":false}}"#),
            ok(br#"{"result":{"items":[{"name":"key","version":1,"protected":false,"state":"active","updated_at_ms":123}]}}"#),
            ok(br#"{"result":{"deleted":true}}"#),
        ]);
        assert!(
            resolver
                .module_secret_put("key", Secret::new(vec![0, 1, 255]), None, Some(false))
                .await
                .unwrap()
                .created
        );
        let got = resolver.module_secret_get("key").await.unwrap();
        assert_eq!(got.name, "key");
        assert_eq!(got.version, 1);
        assert!(!got.protected);
        assert_eq!(got.value.expose(), &[0, 1, 255]);
        assert_eq!(
            resolver.module_secret_list().await.unwrap()[0].updated_at_ms,
            123
        );
        resolver.module_secret_delete("key", Some(1)).await.unwrap();
        let requests: Vec<Value> = script
            .requests
            .lock()
            .unwrap()
            .iter()
            .map(|request| serde_json::from_slice(request.expose()).unwrap())
            .collect();
        assert_eq!(
            requests,
            vec![
                serde_json::json!({"method":"module_secret.put","params":{"name":"key","value":"AAH/","protected":false}}),
                serde_json::json!({"method":"module_secret.get","params":{"name":"key"}}),
                serde_json::json!({"method":"module_secret.list","params":{}}),
                serde_json::json!({"method":"module_secret.delete","params":{"name":"key","expected_version":1}}),
            ]
        );
    }

    #[tokio::test]
    async fn module_secret_no_operation_retries_transient_or_transport_failures() {
        for transport_error in [false, true] {
            for operation in 0..4 {
                let reply = if transport_error {
                    Err(CredentialResolverError::transport("lost reply"))
                } else {
                    ok(br#"{"result":{"error":{"code":"route_busy","class":"transient"}}}"#)
                };
                let (resolver, script) = resolver(vec![reply]);
                let error = match operation {
                    0 => resolver
                        .module_secret_put("key", Secret::new(vec![1]), Some(1), None)
                        .await
                        .unwrap_err(),
                    1 => resolver.module_secret_get("key").await.unwrap_err(),
                    2 => resolver
                        .module_secret_delete("key", None)
                        .await
                        .unwrap_err(),
                    _ => resolver.module_secret_list().await.unwrap_err(),
                };
                assert!(matches!(
                    error,
                    ModuleSecretError::Other(CredentialResolverError {
                        class: CredentialErrorClass::Transient | CredentialErrorClass::Transport,
                        ..
                    })
                ));
                assert_eq!(script.requests.lock().unwrap().len(), 1);
            }
        }
    }

    #[tokio::test]
    async fn module_secret_get_refuses_bad_base64_and_delete_requires_true() {
        let (resolver, _) = resolver(vec![
            ok(br#"{"result":{"name":"key","version":1,"value":"bad!","protected":false}}"#),
            ok(br#"{"result":{"deleted":false}}"#),
        ]);
        for error in [
            resolver.module_secret_get("key").await.unwrap_err(),
            resolver
                .module_secret_delete("key", None)
                .await
                .unwrap_err(),
        ] {
            assert!(matches!(
                error,
                ModuleSecretError::Other(CredentialResolverError {
                    class: CredentialErrorClass::InvalidResponse,
                    ..
                })
            ));
        }
    }
}
