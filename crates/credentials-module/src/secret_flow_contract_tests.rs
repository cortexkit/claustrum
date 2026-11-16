// Flow boundary tests share the registered-phone and deposit harness with the
// agent contract tests, without changing the existing agent golden requests.

fn phone_attestation_snapshot(root: &TestTempDir) -> Vec<Vec<Vec<rusqlite::types::Value>>> {
    let conn = rusqlite::Connection::open(root.join("store.db")).unwrap();
    let tables = conn
        .prepare("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    tables
        .iter()
        .map(|table| {
            let mut query = conn
                .prepare(&format!("SELECT * FROM \"{}\"", table.replace('"', "\"\"")))
                .unwrap();
            let columns = query.column_count();
            query
                .query_map([], |row| (0..columns).map(|i| row.get(i)).collect())
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap()
        })
        .collect()
}

#[tokio::test]
async fn phone_attestation_guards_registration_agent_flow_and_both_delete_stages_without_writes() {
    let flow = SecretFlow::new(231).await;
    let key = MasterKey::from_bytes([231; MASTER_KEY_LEN]);
    let admin = Arc::new(admin_surface::AdminSurface::new(
        Arc::new(RefreshEngine::new(
            Arc::clone(&flow.store),
            Vec::new(),
            Arc::new(crate::test_support::NoHttp),
        )),
        credentials_core::admin_auth::AdminMacKey::derive(&key),
        credentials_core::vault_id_for(flow._root.join("store.db").parent().unwrap()).unwrap(),
        key.key_id(),
    ));
    set_member_mapping(&flow.store, true);
    flow.store
        .set_secret_phone_mapping_audited(true, AuditCtx::admin(AuditOp::SecretPhoneGateSet))
        .unwrap();
    let routes = Arc::new(RouteEpochs::default());
    phone_attestation_bind(
        &flow.surface,
        &admin,
        &routes,
        17,
        1,
        Some(json!("production")),
    )
    .await;
    phone_attestation_bind(&flow.surface, &admin, &routes, 18, 1, None).await;
    let federation::RouteCaller::Phone(production) = admin.route_caller(17) else {
        panic!("not a phone")
    };
    flow.deposit_both().await;
    let agent = flow.use_secret("aft", &secret_golden("use.request.api_key"));
    let install = sf_request(&flow, &sf_install(true));
    let delete = flow.phone("secret.delete", json!({"name":"key"})).await;
    let signed = |statement: &serde_json::Value, duration: &str| {
        flow.signed(
            if duration == "none" { "delete.request.signed" } else { "approve.request" },
            json!([{"request_id":statement["request_id"], "statement_sha256":sc_sha256_hex(&sc_unb64(statement["statement_b64url"].as_str().unwrap()))}]),
            duration, if duration == "none" { statement["expires_at_ms"].as_i64().unwrap() } else { 0 }, sc_now_ms(),
        )
    };
    let cases = [
        (
            "secret.phone_keys_register",
            flow.register_request(),
            "already_stored",
        ),
        ("secret.approve", signed(&agent, "permanent"), "granted"),
        ("secret.approve", signed(&install, "version"), "granted"),
        ("secret.delete", json!({"name":"key"}), "approval_required"),
        ("secret.delete", signed(&delete, "none"), "granted"),
    ];
    for (method, params, expected) in cases {
        let before = phone_attestation_snapshot(&flow._root);
        let (ty, bytes) = sc_dispatch(
            &flow.surface,
            &admin,
            admin.route_caller(18),
            method,
            params.clone(),
        )
        .await;
        assert_eq!(ty, FrameType::Response);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
            json!({"result":{"error":{"code":"phone_not_attested","class":"permanent"}}})
        );
        assert_eq!(phone_attestation_snapshot(&flow._root), before);
        for build in [None, Some("development"), Some("Production"), Some("")] {
            let before = phone_attestation_snapshot(&flow._root);
            for request in [
                &params,
                &json!({"envelope_b64url":"not base64", "signature_b64url":null}),
                &json!(null),
            ] {
                let reply = crate::secret_phone::serve_with_lookup(
                    Arc::clone(&flow.store),
                    SC_FP,
                    build,
                    method,
                    request,
                    tokio::time::Instant::now() + crate::secret_phone::PHONE_OP_DEADLINE,
                    async { panic!("unattested requests must not look up pairing") },
                )
                .await;
                assert_eq!(
                    sc_answer(reply),
                    json!({"error":{"code":"phone_not_attested","class":"permanent"}}),
                    "{method} {build:?}"
                );
                assert_eq!(
                    phone_attestation_snapshot(&flow._root),
                    before,
                    "{method} wrote state"
                );
            }
        }
        // Use the real bind's captured mark with the normal phone pipeline; only
        // Callosum's pairing lookup is injected, as in the other phone contract tests.
        let reply = flow
            .phone_on_build(method, params, production.peer_build.as_deref())
            .await;
        let outcome = reply["status"]
            .as_str()
            .or_else(|| reply["results"][0]["outcome"].as_str());
        assert_eq!(outcome, Some(expected), "{method}: {reply}");
    }
}

#[tokio::test]
async fn phone_attestation_leaves_unmarked_reads_deposit_and_revocation_available() {
    let flow = SecretFlow::new(232).await;
    assert_eq!(
        flow.phone_on_build("secret.home", json!({}), None).await,
        json!({"home":true,"home_member_id":null})
    );
    assert_eq!(
        flow.phone_on_build("secret.deposit_keys", json!({}), None)
            .await,
        flow.deposit_keys_reply
    );
    let request = flow.deposit_request(
        "deposit.request.api_key",
        &credentials_core::agent_secret::SecretMaterial::ApiKey(
            credentials_core::secret::Secret::new(b"test-only-key".to_vec()),
        ),
    );
    assert_eq!(
        flow.phone_on_build("secret.deposit", request, None).await["status"],
        "stored"
    );
    let listed = flow.phone_on_build("secret.list", json!({}), None).await;
    assert_eq!(listed["secrets"][0]["name"], "key");
    assert_eq!(
        flow.phone_on_build(
            "secret.revoke_grant",
            secret_golden("revoke_grant.request"),
            None
        )
        .await,
        json!({"outcome":"not_found"})
    );
}

async fn phone_attestation_bind(
    surface: &Arc<ReadSurface>,
    admin: &Arc<admin_surface::AdminSurface>,
    routes: &Arc<RouteEpochs>,
    channel: u16,
    epoch: u32,
    peer_build: Option<serde_json::Value>,
) {
    let mut body = serde_json::to_value(ModuleControlRequest::RouteBind {
        route_channel: channel,
        epoch,
        target: subc_protocol::RouteTarget::ToolProvider {
            module_id: "claustrum".into(),
        },
        identity: subc_protocol::BindIdentity::new(format!("fed-phone:{SC_FP}"), "s"),
        principal: Some(reserved("callosum")),
        consumer_capabilities: None,
        role_versions: None,
        admission_facts: None,
        scope: None,
        call_mode: None,
    })
    .unwrap();
    if let Some(build) = peer_build {
        body["peer_build"] = build;
    }
    let frame = Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        control_flags(),
        0,
        0,
        1,
        serde_json::to_vec(&body).unwrap(),
    )
    .unwrap();
    let (tx, mut rx) = mpsc::channel(1);
    handle_control_request(frame, &tx, surface, admin, routes)
        .await
        .unwrap();
    assert_eq!(rx.try_recv().unwrap().header.ty, FrameType::Response);
}

#[tokio::test]
async fn phone_attestation_is_normalized_per_route_and_captured_before_rebind() {
    #[derive(Clone, Default)]
    struct BindEvents(
        Arc<std::sync::atomic::AtomicUsize>,
        Arc<std::sync::Mutex<Vec<std::collections::BTreeMap<String, String>>>>,
    );
    impl tracing::Subscriber for BindEvents {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            if event.metadata().target() == "routes" {
                if *event.metadata().level() == tracing::Level::WARN {
                    self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                } else {
                    assert_eq!(*event.metadata().level(), tracing::Level::INFO);
                    struct Fields(std::collections::BTreeMap<String, String>);
                    impl tracing::field::Visit for Fields {
                        fn record_debug(
                            &mut self,
                            field: &tracing::field::Field,
                            value: &dyn std::fmt::Debug,
                        ) {
                            self.0.insert(field.name().into(), format!("{value:?}"));
                        }
                        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                            self.0.insert(field.name().into(), value.into());
                        }
                    }
                    let mut fields = Fields(std::collections::BTreeMap::new());
                    event.record(&mut fields);
                    assert!(
                        !format!("{:?}", fields.0).contains(SC_FP),
                        "bind logs must not contain the phone fingerprint"
                    );
                    self.1.lock().unwrap().push(fields.0);
                }
            }
        }
    }
    let (surface, admin, store) = scoped_rig(233);
    set_member_mapping(&store, true);
    store
        .set_secret_phone_mapping_audited(true, AuditCtx::admin(AuditOp::SecretPhoneGateSet))
        .unwrap();
    let routes = Arc::new(RouteEpochs::default());
    let warnings = BindEvents::default();
    let _capture = tracing::subscriber::set_default(warnings.clone());
    phone_attestation_bind(&surface, &admin, &routes, 17, 1, Some(json!("production"))).await;
    assert_eq!(warnings.0.load(std::sync::atomic::Ordering::SeqCst), 0);
    let bind_line = |channel: &str, production: &str| {
        std::collections::BTreeMap::from([
            ("message".into(), "phone route bound".into()),
            ("production_build".into(), production.into()),
            ("route_channel".into(), channel.into()),
        ])
    };
    assert_eq!(*warnings.1.lock().unwrap(), vec![bind_line("17", "true")]);
    let captured = admin.route_caller(17);
    let federation::RouteCaller::Phone(phone) = &captured else {
        panic!("not a phone route")
    };
    assert_eq!(phone.fingerprint, SC_FP);
    assert_eq!(phone.peer_build.as_deref(), Some("production"));
    for build in [
        None,
        Some(json!(null)),
        Some(json!("development")),
        Some(json!("Production")),
        Some(json!("")),
        Some(json!(false)),
        Some(json!(17)),
        Some(json!({"build":"production"})),
    ] {
        let before = warnings.0.load(std::sync::atomic::Ordering::SeqCst);
        let bind_lines_before = warnings.1.lock().unwrap().len();
        phone_attestation_bind(&surface, &admin, &routes, 18, 1, build.clone()).await;
        assert_eq!(warnings.1.lock().unwrap().len(), bind_lines_before + 1);
        assert_eq!(
            warnings.1.lock().unwrap().last(),
            Some(&bind_line("18", "false"))
        );
        assert_eq!(
            warnings.0.load(std::sync::atomic::Ordering::SeqCst),
            before + usize::from(build.is_some()),
            "each invalid present mark warns once"
        );
        let caller = admin.route_caller(18);
        let federation::RouteCaller::Phone(phone) = &caller else {
            panic!("not a phone route")
        };
        assert_eq!(phone.fingerprint, SC_FP);
        assert_eq!(phone.peer_build, None, "{build:?}");
        assert_eq!(admin.route_caller(17), captured);
        for method in [
            "secret.phone_keys_register",
            "secret.approve",
            "secret.delete",
            "manifest.approve",
        ] {
            let (ty, bytes) =
                sc_dispatch(&surface, &admin, caller.clone(), method, json!(null)).await;
            assert_eq!(ty, FrameType::Response);
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
                json!({"result":{"error":{"code":"phone_not_attested","class":"permanent"}}})
            );
            let (ty, bytes) =
                sc_dispatch(&surface, &admin, captured.clone(), method, json!(null)).await;
            assert_eq!(ty, FrameType::Error);
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["code"],
                "invalid_params"
            );
        }
        assert_eq!(
            warnings.0.load(std::sync::atomic::Ordering::SeqCst),
            before + usize::from(build.is_some()),
            "requests do not repeat bind warnings"
        );
        assert_eq!(
            warnings.1.lock().unwrap().len(),
            bind_lines_before + 1,
            "requests do not repeat bind info lines"
        );
    }
    phone_attestation_bind(&surface, &admin, &routes, 17, 2, None).await;
    assert_eq!(
        warnings.1.lock().unwrap().last(),
        Some(&bind_line("17", "false"))
    );
    assert_ne!(admin.route_caller(17), captured);
    let (ty, _) = sc_dispatch(&surface, &admin, captured, "secret.approve", json!(null)).await;
    assert_eq!(
        ty,
        FrameType::Error,
        "rebind must not change already captured authority"
    );
    admin.drop_bind(17);
    assert!(matches!(
        admin.route_caller(17),
        federation::RouteCaller::Principal(_)
    ));
    let before = warnings.1.lock().unwrap().len();
    bind_reserved_route(
        &surface,
        &admin,
        &routes,
        19,
        1,
        "callosum",
        "callosum-self",
    )
    .await;
    assert_eq!(
        warnings.1.lock().unwrap().len(),
        before,
        "non-phone binds do not emit phone bind info lines"
    );
}

fn sf_identity() -> serde_json::Value {
    json!({"flow_id":"daily-fetch", "version":7, "code_hash":"0123456789abcdef".repeat(4), "install_id":"install-A"})
}

fn sf_run(login: bool) -> serde_json::Value {
    let mut request = secret_golden(if login {
        "use.request.site_login"
    } else {
        "use.request.api_key"
    });
    request.as_object_mut().unwrap().remove("coverage");
    let flow = sf_identity();
    for (attribute, field) in [
        ("flow_id", "flow_id"),
        ("flow_version", "version"),
        ("flow_code_hash", "code_hash"),
        ("flow_install_id", "install_id"),
    ] {
        request["stamp"]["attributes"][attribute] = flow[field].clone();
    }
    if !login {
        request["method"] = json!("GET");
    }
    request
}

fn sf_install(login: bool) -> serde_json::Value {
    let run = sf_run(login);
    let mut request = json!({"name":run["name"], "flow":sf_identity(), "target":run["target"]});
    if !login {
        request["methods"] = json!(["GET"]);
    }
    request
}

fn sf_request(flow: &SecretFlow, params: &serde_json::Value) -> serde_json::Value {
    sc_use_answer(crate::secret_use::serve_flow_approval(
        &flow.store,
        Some(&reserved("basal")),
        params,
        sc_now_ms,
    ))
}

fn sf_revoke(flow: &SecretFlow, params: &serde_json::Value) -> serde_json::Value {
    sc_use_answer(crate::secret_use::serve_revoke_flow_grants(
        &flow.store,
        Some(&reserved("basal")),
        params,
    ))
}

fn sf_pending(flow: &SecretFlow) -> i64 {
    rusqlite::Connection::open_with_flags(
        flow._root.join("store.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap()
    .query_row("SELECT COUNT(*) FROM secret_pending_requests", [], |r| {
        r.get(0)
    })
    .unwrap()
}

fn sf_refusal(flow: &SecretFlow, request: &serde_json::Value, detail: &str) {
    let reply = flow.use_secret("basal", request);
    assert_eq!(
        serde_json::to_vec(&reply).unwrap(),
        serde_json::to_vec(&json!({"error":{"code":"not_found", "class":"permanent"}})).unwrap()
    );
    let events = flow.store.recent_auth_events(1).unwrap();
    assert_eq!(events[0].detail.as_deref(), Some(detail));
    assert_eq!(events[0].principal_id.as_deref(), Some("basal"));
}

#[tokio::test]
async fn secret_flow_sender_admission_precedes_parsing_and_diagnostics() {
    let flow = SecretFlow::new(216).await;
    for principal in [
        None,
        Some(subc_protocol::Principal::Direct),
        Some(subc_protocol::Principal::Unverified),
        Some(reserved("aft")),
        Some(reserved("cerebellum")),
        Some(reserved("callosum")),
        Some(reserved("prefrontal-core")),
        Some(reserved("cingulate")),
        Some(reserved("harness:basal")),
    ] {
        for params in [json!({}), sf_install(false)] {
            assert_eq!(
                sc_use_answer(crate::secret_use::serve_flow_approval(
                    &flow.store,
                    principal.as_ref(),
                    &params,
                    sc_now_ms
                )),
                json!({"error":{"code":"not_found", "class":"permanent"}})
            );
        }
        for params in [json!({}), json!({"flow_install_id":"install-A"})] {
            assert_eq!(
                sc_use_answer(crate::secret_use::serve_revoke_flow_grants(
                    &flow.store,
                    principal.as_ref(),
                    &params
                )),
                json!({"error":{"code":"not_found", "class":"permanent"}})
            );
        }
    }
    assert_eq!(sf_pending(&flow), 0);
    assert!(flow.store.recent_auth_events(100).unwrap().is_empty());
}

#[tokio::test]
async fn secret_flow_methods_are_validated_against_target_before_lookup() {
    let flow = SecretFlow::new(217).await;
    flow.deposit_both().await;
    let invalid = json!({"transport":"invalid_params"});
    for name in [sf_run(false)["name"].as_str().unwrap(), "unknown"] {
        for method in [
            None,
            Some(json!(null)),
            Some(json!("get")),
            Some(json!("")),
            Some(json!("A".repeat(17))),
            Some(json!(["GET"])),
        ] {
            let mut request = sf_run(false);
            request["name"] = json!(name);
            match method {
                Some(value) => {
                    request["method"] = value;
                }
                None => {
                    request.as_object_mut().unwrap().remove("method");
                }
            }
            assert_eq!(flow.use_secret("basal", &request), invalid, "{request}");
        }
        for methods in [
            None,
            Some(json!(null)),
            Some(json!([])),
            Some(json!(["GET", "GET"])),
            Some(json!(["get"])),
            Some(json!([""])),
            Some(json!(["A".repeat(17)])),
            Some(json!("GET")),
        ] {
            let mut request = sf_install(false);
            request["name"] = json!(name);
            match methods {
                Some(value) => {
                    request["methods"] = value;
                }
                None => {
                    request.as_object_mut().unwrap().remove("methods");
                }
            }
            assert_eq!(sf_request(&flow, &request), invalid, "{request}");
        }
        for value in [json!(null), json!([]), json!(["GET"]), json!("GET")] {
            let mut request = sf_install(true);
            request["name"] = json!(name);
            request["methods"] = value.clone();
            assert_eq!(sf_request(&flow, &request), invalid);
            let mut request = sf_run(true);
            request["name"] = json!(name);
            request["method"] = value;
            assert_eq!(flow.use_secret("basal", &request), invalid);
        }
        let mut request = sf_install(true);
        request["name"] = json!(name);
        assert_eq!(
            sf_request(&flow, &request),
            json!({"error":{"code":"not_found", "class":"permanent"}})
        );
        let mut request = sf_run(true);
        request["name"] = json!(name);
        assert_eq!(
            flow.use_secret("basal", &request),
            json!({"error":{"code":"not_found", "class":"permanent"}})
        );
    }
    for (operation, key) in [
        ("request", "method"),
        ("use", "methods"),
        ("use", "coverage"),
        ("use", "flow"),
    ] {
        let mut request = if operation == "request" {
            sf_install(false)
        } else {
            sf_run(false)
        };
        request[key] = json!("scope");
        assert_eq!(
            if operation == "request" {
                sf_request(&flow, &request)
            } else {
                flow.use_secret("basal", &request)
            },
            invalid
        );
    }
    for version in [
        json!(0),
        json!(9_007_199_254_740_992u64),
        json!(-1),
        json!(1.5),
        json!("7"),
    ] {
        let mut request = sf_install(false);
        request["flow"]["version"] = version;
        assert_eq!(sf_request(&flow, &request), invalid);
    }
    let mut request = sf_run(false);
    request["stamp"]["attributes"]["flow_version"] = json!(9_007_199_254_740_992u64);
    assert_eq!(flow.use_secret("basal", &request), invalid);
    assert_eq!(sf_pending(&flow), 0);
}

#[tokio::test]
async fn secret_flow_release_refusals_are_uniform_and_never_create_pending_rows() {
    let flow = SecretFlow::new(218).await;
    flow.deposit_both().await;
    sf_refusal(&flow, &sf_run(false), "flow_no_grant");
    sf_refusal(&flow, &sf_run(true), "flow_no_grant");
    assert_eq!(sf_pending(&flow), 0);
    for login in [false, true] {
        let request = sf_request(&flow, &sf_install(login));
        assert_eq!(request["status"], "approval_required");
        assert_eq!(sf_request(&flow, &sf_install(login)), request);
        let approved = flow.approve(&request, "version", false).await;
        assert_eq!(approved["results"][0]["outcome"], "granted");
    }
    let pending = sf_pending(&flow);
    for _ in 0..3 {
        for login in [false, true] {
            let released = flow.use_secret("basal", &sf_run(login));
            assert_eq!(released["status"], "released", "{released}");
            assert_secret_reply_matches(
                if login {
                    "use.result.released.site_login"
                } else {
                    "use.result.released.api_key"
                },
                &released,
            );
        }
    }
    let mut request = sf_run(false);
    request["method"] = json!("POST");
    sf_refusal(&flow, &request, "flow_method");
    for (key, value) in [
        ("flow_id", json!("another-flow")),
        ("flow_version", json!(8)),
        ("flow_code_hash", json!("f".repeat(64))),
        ("flow_install_id", json!("another-install")),
    ] {
        let mut request = sf_run(false);
        request["stamp"]["attributes"][key] = value;
        sf_refusal(&flow, &request, "flow_no_grant");
    }
    for key in [
        "flow_id",
        "flow_version",
        "flow_code_hash",
        "flow_install_id",
    ] {
        let mut request = sf_run(false);
        request["stamp"]["attributes"]
            .as_object_mut()
            .unwrap()
            .remove(key);
        sf_refusal(&flow, &request, "flow_identity");
        let events = flow.store.recent_auth_events(1).unwrap();
        assert_eq!(events[0].credential_id, "secret-use|unaddressed");
        assert!(!format!("{events:?}").contains("daily-fetch"));
        assert!(!format!("{events:?}").contains("install-A"));
    }
    let mut request = sf_run(false);
    request["stamp"] = secret_golden("use.request.api_key")["stamp"].clone();
    sf_refusal(&flow, &request, "flow_identity");
    let mut request = sf_run(false);
    request["name"] = json!("unknown");
    sf_refusal(&flow, &request, "unknown_name");
    let mut request = sf_run(true);
    request["name"] = sf_run(false)["name"].clone();
    sf_refusal(&flow, &request, "target");
    let mut request = sf_run(false);
    request["target"]["host"] = json!("wrong.example");
    sf_refusal(&flow, &request, "target");
    let mut request = sf_run(false);
    request["stamp"]["attributes"]["flow_install_id"] = json!("");
    sf_refusal(&flow, &request, "flow_identity");
    let mut request = sf_run(false);
    request["target"]["path"] = json!(format!(
        "{}/second",
        request["target"]["path"]
            .as_str()
            .unwrap()
            .trim_end_matches('/')
    ));
    assert_eq!(flow.use_secret("basal", &request)["status"], "released");
    assert_eq!(sf_pending(&flow), pending);
}

#[tokio::test]
async fn secret_flow_and_agent_grants_never_satisfy_each_other() {
    let flow = SecretFlow::new(219).await;
    flow.deposit_both().await;
    let request = sf_request(&flow, &sf_install(false));
    assert_eq!(
        flow.approve(&request, "version", false).await["results"][0]["outcome"],
        "granted"
    );
    let agent = secret_golden("use.request.api_key");
    let agent_request = flow.use_secret("aft", &agent);
    assert_eq!(agent_request["status"], "approval_required");
    assert_ne!(agent_request["request_id"], request["request_id"]);
    assert_eq!(
        flow.approve(&agent_request, "permanent", false).await["results"][0]["outcome"],
        "granted"
    );
    assert_eq!(
        sf_revoke(
            &flow,
            &json!({"flow_install_id":"install-A", "flow_version":8})
        ),
        json!({"status":"revoked", "grants":0})
    );
    assert_eq!(
        flow.use_secret("basal", &sf_run(false))["status"],
        "released"
    );
    assert_eq!(
        sf_revoke(
            &flow,
            &json!({"flow_install_id":"install-A", "flow_version":7})
        ),
        json!({"status":"revoked", "grants":1})
    );
    let pending = sf_pending(&flow);
    sf_refusal(&flow, &sf_run(false), "flow_no_grant");
    assert_eq!(flow.use_secret("aft", &agent)["status"], "released");
    let mut head = sf_run(false);
    head["stamp"] = agent["stamp"].clone();
    sf_refusal(&flow, &head, "flow_identity");
    assert_eq!(sf_pending(&flow), pending);
    let request = sf_request(&flow, &sf_install(false));
    assert_eq!(
        flow.approve(&request, "version", false).await["results"][0]["outcome"],
        "granted"
    );
    assert_eq!(
        sf_revoke(&flow, &json!({"flow_install_id":"install-A"})),
        json!({"status":"revoked", "grants":1})
    );
    assert_eq!(
        sf_revoke(&flow, &json!({"flow_install_id":"install-A"})),
        json!({"status":"revoked", "grants":0})
    );
}

#[tokio::test]
async fn secret_flow_stamps_preserve_the_agent_closed_key_set_and_goldens() {
    let flow = SecretFlow::new(220).await;
    flow.deposit_both().await;
    for (sender, login) in [("aft", false), ("cerebellum", true)] {
        let golden = secret_golden(if login {
            "use.request.site_login"
        } else {
            "use.request.api_key"
        });
        let request = flow.use_secret(sender, &golden);
        assert_eq!(request["status"], "approval_required");
        assert_eq!(
            flow.approve(&request, "permanent", false).await["results"][0]["outcome"],
            "granted"
        );
        assert_eq!(flow.use_secret(sender, &golden)["status"], "released");
        let mut stamped = golden.clone();
        stamped["stamp"] = sf_run(login)["stamp"].clone();
        let pending = sf_pending(&flow);
        assert_eq!(
            flow.use_secret(sender, &stamped),
            json!({"error":{"code":"not_found", "class":"permanent"}})
        );
        stamped["method"] = json!("GET");
        assert_eq!(
            flow.use_secret(sender, &stamped),
            json!({"transport":"invalid_params"})
        );
        let mut with_method = golden.clone();
        with_method["method"] = json!("GET");
        assert_eq!(
            flow.use_secret(sender, &with_method),
            json!({"transport":"invalid_params"})
        );
        assert_eq!(sf_pending(&flow), pending);
    }
}

#[tokio::test]
async fn secret_flow_ops_dispatch_only_for_basal_and_revoke_params_are_closed() {
    use federation::RouteCaller;
    let seed = 221;
    let (surface, store, db_path, _root) = tmp_surface_with_store(seed);
    let key = MasterKey::from_bytes([seed; MASTER_KEY_LEN]);
    let engine = Arc::new(RefreshEngine::new(
        Arc::clone(&store),
        Vec::new(),
        Arc::new(crate::test_support::NoHttp),
    ));
    let admin = Arc::new(admin_surface::AdminSurface::new(
        engine,
        credentials_core::admin_auth::AdminMacKey::derive(&key),
        credentials_core::vault_id_for(db_path.parent().unwrap()).unwrap(),
        key.key_id(),
    ));
    let expected = serde_json::to_vec(&uniform_not_found()).unwrap();
    for caller in [
        RouteCaller::Principal(crate::federation::ingress::ScopedCaller::hand_only(None)),
        RouteCaller::Principal(crate::federation::ingress::ScopedCaller::hand_only(Some(
            subc_protocol::Principal::Direct,
        ))),
        RouteCaller::Principal(crate::federation::ingress::ScopedCaller::hand_only(Some(
            subc_protocol::Principal::Unverified,
        ))),
        RouteCaller::Principal(crate::federation::ingress::ScopedCaller::hand_only(Some(
            reserved("aft"),
        ))),
        RouteCaller::Principal(crate::federation::ingress::ScopedCaller::hand_only(Some(
            reserved("cerebellum"),
        ))),
        RouteCaller::Principal(crate::federation::ingress::ScopedCaller::hand_only(Some(
            reserved("cingulate"),
        ))),
        RouteCaller::Principal(crate::federation::ingress::ScopedCaller::hand_only(Some(
            reserved("callosum"),
        ))),
        RouteCaller::Principal(crate::federation::ingress::ScopedCaller::hand_only(Some(
            reserved("prefrontal-core"),
        ))),
        RouteCaller::Phone(SC_FP.into()),
        RouteCaller::Member(SC_MEMBER.into()),
        RouteCaller::Refused,
    ] {
        for method in ["secret.request_flow_approval", "secret.revoke_flow_grants"] {
            let reply = sc_dispatch(&surface, &admin, caller.clone(), method, json!({})).await;
            assert_eq!(
                reply,
                (FrameType::Response, expected.clone()),
                "{caller:?} {method}"
            );
        }
    }
    assert!(store.recent_auth_events(100).unwrap().is_empty());
    let basal = RouteCaller::Principal(crate::federation::ingress::ScopedCaller::hand_only(Some(
        reserved("basal"),
    )));
    for method in [
        "secret.use",
        "secret.request_flow_approval",
        "secret.revoke_flow_grants",
    ] {
        let (kind, bytes) = sc_dispatch(&surface, &admin, basal.clone(), method, json!({})).await;
        assert_eq!(kind, FrameType::Error);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["code"],
            "invalid_params"
        );
    }
    let reply = sc_dispatch(
        &surface,
        &admin,
        basal.clone(),
        "secret.request_flow_approval",
        sf_install(false),
    )
    .await;
    assert_eq!(reply, (FrameType::Response, expected));
    assert_eq!(
        store.recent_auth_events(1).unwrap()[0].detail.as_deref(),
        Some("unknown_name")
    );
    for params in [
        json!({"flow_install_id":"install-A"}),
        json!({"flow_install_id":"install-A", "flow_version":7}),
    ] {
        let (kind, bytes) = sc_dispatch(
            &surface,
            &admin,
            basal.clone(),
            "secret.revoke_flow_grants",
            params,
        )
        .await;
        assert_eq!(kind, FrameType::Response);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
            wrap_result(json!({"status":"revoked", "grants":0}))
        );
    }
    for params in [
        json!({}),
        json!({"flow_install_id":""}),
        json!({"flow_install_id":"x".repeat(257)}),
        json!({"flow_install_id":"bad\n"}),
        json!({"flow_install_id":"é"}),
        json!({"flow_install_id":"install-A", "flow_version":null}),
        json!({"flow_install_id":"install-A", "flow_version":0}),
        json!({"flow_install_id":"install-A", "flow_version":9_007_199_254_740_992u64}),
        json!({"flow_install_id":"install-A", "flow_version":"7"}),
        json!({"flow_install_id":"install-A", "extra":true}),
        json!({"flow_install_id":"install-A", "flow":{}}),
    ] {
        let (kind, bytes) = sc_dispatch(
            &surface,
            &admin,
            basal.clone(),
            "secret.revoke_flow_grants",
            params.clone(),
        )
        .await;
        assert_eq!(kind, FrameType::Error, "{params}");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["code"],
            "invalid_params"
        );
    }
}

#[tokio::test]
async fn secret_flow_install_errors_and_closed_shapes_do_not_create_pending_rows() {
    let flow = SecretFlow::new(222).await;
    flow.deposit_both().await;
    let invalid = json!({"transport":"invalid_params"});
    for key in ["name", "flow", "target", "methods"] {
        let mut request = sf_install(false);
        request.as_object_mut().unwrap().remove(key);
        assert_eq!(sf_request(&flow, &request), invalid);
    }
    // Name-less flow calls are uniformly refused rather than entering the Basic
    // sign-in selector or revealing which flow fields are required.
    let mut nameless = sf_run(false);
    nameless.as_object_mut().unwrap().remove("name");
    assert_eq!(flow.use_secret("basal", &nameless), credentials_core::agent_secret::SecretError::NotFound.body());
    for key in ["stamp", "target", "method"] {
        let mut request = sf_run(false);
        request.as_object_mut().unwrap().remove(key);
        assert_eq!(flow.use_secret("basal", &request), invalid);
    }
    for key in ["flow_id", "version", "code_hash", "install_id"] {
        let mut request = sf_install(false);
        request["flow"].as_object_mut().unwrap().remove(key);
        assert_eq!(sf_request(&flow, &request), invalid);
    }
    let mut request = sf_install(false);
    request["flow"]["extra"] = json!(true);
    assert_eq!(sf_request(&flow, &request), invalid);
    // A flow id equal to a statement tag cannot be carried in the signed statement, whose
    // own `v` key holds that value.
    for tag in ["ck-secret-flow-statement/v1", "ck-secret-use-statement/v1"] {
        let mut request = sf_install(false);
        request["flow"]["flow_id"] = json!(tag);
        assert_eq!(sf_request(&flow, &request), invalid, "{tag}");
    }
    for key in ["extra", "stamp", "coverage"] {
        let mut request = sf_install(false);
        request[key] = json!(true);
        assert_eq!(sf_request(&flow, &request), invalid);
    }
    let mut request = sf_install(false);
    request["name"] = json!("a".repeat(65));
    assert_eq!(
        sf_request(&flow, &request),
        json!({"error":{"code":"limit_exceeded", "class":"context_overflow"}})
    );
    let conn = rusqlite::Connection::open(flow._root.join("store.db")).unwrap();
    conn.execute(
        "DELETE FROM settings WHERE name='federation.self_member'",
        [],
    )
    .unwrap();
    assert_eq!(
        sf_request(&flow, &sf_install(false)),
        json!({"error":{"code":"secret_setup_incomplete", "class":"permanent"}})
    );
    assert_eq!(sf_pending(&flow), 0);
    flow.store
        .set_federation_self_member_audited(SC_MEMBER, AuditCtx::admin(AuditOp::FederationSelfSet))
        .unwrap();
    conn.execute_batch("CREATE TRIGGER fail_flow_pending BEFORE INSERT ON secret_pending_requests BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
    assert_eq!(
        sf_request(&flow, &sf_install(false)),
        json!({"error":{"code":"store_error", "class":"transient"}})
    );
    assert_eq!(sf_pending(&flow), 0);
    conn.execute_batch("DROP TRIGGER fail_flow_pending")
        .unwrap();
    let mut request = sf_install(false);
    request["methods"] = json!(["POST", "GET"]);
    let pending = sf_request(&flow, &request);
    assert_eq!(pending["status"], "approval_required");
    let statement: serde_json::Value =
        serde_json::from_slice(&sc_unb64(pending["statement_b64url"].as_str().unwrap())).unwrap();
    assert_eq!(statement["use"]["methods"], json!(["GET", "POST"]));
    request["methods"] = json!(["GET", "POST"]);
    assert_eq!(sf_request(&flow, &request), pending);
}

/// A second install of the same flow version: its grants differ only in `install_id`.
fn sf_other_install() -> serde_json::Value {
    let mut install = sf_install(false);
    install["flow"]["install_id"] = json!("install-B");
    install
}

async fn sf_approve(flow: &SecretFlow, request: &serde_json::Value) {
    let reply = sf_request(flow, request);
    assert_eq!(reply["status"], "approval_required", "{reply}");
    let approved = flow.approve(&reply, "version", false).await;
    assert_eq!(approved["results"][0]["outcome"], "granted", "{approved}");
}

#[tokio::test]
async fn secret_flow_grants_list_on_the_phone_and_revoke_one_at_a_time() {
    let seed = 223;
    let flow = SecretFlow::new(seed).await;
    flow.deposit_both().await;
    sf_approve(&flow, &sf_install(false)).await;
    sf_approve(&flow, &sf_other_install()).await;
    sf_approve(&flow, &sf_install(true)).await;
    let key = MasterKey::from_bytes([seed; MASTER_KEY_LEN]);
    let mac = credentials_core::admin_auth::AdminMacKey::derive(&key);
    let engine = Arc::new(RefreshEngine::new(
        Arc::clone(&flow.store),
        Vec::new(),
        Arc::new(crate::test_support::NoHttp),
    ));
    let db = flow._root.join("store.db");
    let vault_id = credentials_core::vault_id_for(db.parent().unwrap()).unwrap();
    let admin = admin_surface::AdminSurface::new(engine, mac, vault_id, key.key_id());

    // The provider surface lists one row per flow grant, under its installed flow version,
    // with no expiry and no agent, in the shape Cingulate's permissions-v1.1 vectors pin as grt_06 (an API key
    // limited by method) and grt_07 (a site login, so no methods).
    let vectors: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/vectors/permissions-v1/provider-list.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let pinned = |id: &str| -> serde_json::Value {
        vectors["reply"]["grants"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["id"] == id)
            .cloned()
            .unwrap_or_else(|| panic!("{id} is missing from the vendored vectors"))
    };
    let keys = |row: &serde_json::Value| -> std::collections::BTreeSet<String> {
        row.as_object().unwrap().keys().cloned().collect()
    };
    let (api_shape, login_shape) = (pinned("grt_06"), pinned("grt_07"));
    let listed = admin
        .serve_permissions("permissions.list", &json!({}), "test")
        .unwrap();
    let rows = listed["grants"].as_array().unwrap();
    assert_eq!(rows.len(), 3, "{listed}");
    for row in rows {
        let shape = if row["scope"] == "api_key" {
            &api_shape
        } else {
            &login_shape
        };
        assert_eq!(keys(row), keys(shape), "{row}");
        assert_eq!(keys(&row["holder"]), keys(&shape["holder"]), "{row}");
        assert_eq!(row["holder"]["kind"], "flow");
        assert_eq!(row["holder"]["flow_id"], "daily-fetch");
        assert_eq!(row["holder"]["flow_version"], 7);
        if row["scope"] == "api_key" {
            assert_eq!(row["methods"], json!(["GET"]), "{row}");
        }
    }
    // A flow row names no agent, so an agent-filtered listing carries none.
    assert_eq!(
        admin
            .serve_permissions("permissions.list", &json!({"agent_id":"agent-A"}), "test")
            .unwrap(),
        json!({"grants":[]})
    );

    // The phone surface lists the grants under each secret, with `flow` and duration
    // `version` in place of an asking scope and coverage.
    let phone = flow.phone("secret.list", json!({})).await;
    let key_secret = phone["secrets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|secret| secret["kind"] == "agent_api_key")
        .unwrap();
    let flow_rows = key_secret["flow_grants"].as_array().unwrap();
    assert_eq!(flow_rows.len(), 2, "{phone}");
    for row in flow_rows {
        assert_eq!(row["duration"], "version");
        assert_eq!(row["flow"]["flow_id"], "daily-fetch");
        assert_eq!(row["flow"]["version"], 7);
        assert_eq!(row["methods"], json!(["GET"]), "{row}");
        assert!(
            row.get("scope").is_none() && row.get("coverage").is_none(),
            "{row}"
        );
        assert!(row.get("expires_at_ms").is_none(), "{row}");
        assert!(row.get("agent_id").is_none(), "{row}");
    }
    let login_secret = phone["secrets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|secret| secret["kind"] == "site_login")
        .unwrap();
    let login_row = &login_secret["flow_grants"][0];
    assert_eq!(login_row["duration"], "version");
    assert_eq!(login_row["flow"]["install_id"], "install-A");
    assert!(login_row.get("methods").is_none(), "{login_row}");

    // Revoking one of two grants that share flow id and version leaves the other install
    // releasing, and the login's own grant untouched. Both revokes go through the
    // operator's single-grant delete by id.
    let id_of = |install: &str, kind: &str| -> String {
        phone["secrets"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|secret| secret["kind"] == kind)
            .flat_map(|secret| secret["flow_grants"].as_array().unwrap())
            .find(|row| row["flow"]["install_id"] == install)
            .map(|row| row["grant_id"].as_str().unwrap().to_owned())
            .unwrap_or_else(|| panic!("no {kind} grant for {install}"))
    };
    let (api_a, api_b, login_a) = (
        id_of("install-A", "agent_api_key"),
        id_of("install-B", "agent_api_key"),
        id_of("install-A", "site_login"),
    );
    assert_eq!(
        [&api_a, &api_b, &login_a]
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        3
    );
    // Revoke over a bind whose principal is the operator: only a direct bind may run an
    // admin op, and the path is the same MAC-authenticated one `ck auth secret revoke`
    // takes through the daemon.
    admin.record_bind(7, subc_protocol::Principal::Direct);
    let revoke = |id: String| {
        let body = serde_json::to_vec(&json!({"op":"permissions.revoke","v":1,"id":id})).unwrap();
        let admin_surface::AdminOutcome::Challenge { nonce_hex, .. } = admin.challenge(7) else {
            panic!("challenge refused");
        };
        let nonce: [u8; credentials_core::admin_auth::ADMIN_NONCE_LEN] =
            sc_unhex(&nonce_hex).try_into().expect("nonce length");
        let tag = sc_hex(
            &credentials_core::admin_auth::AdminMacKey::derive(&key).sign(
                &credentials_core::admin_auth::TranscriptParts {
                    vault_id: &vault_id,
                    key_id: key.key_id(),
                    nonce: &nonce,
                    op_body: &body,
                },
            ),
        );
        (body, tag)
    };
    let (body, tag) = revoke(api_a);
    assert!(
        matches!(
            admin.execute(7, &body, &tag).await,
            admin_surface::AdminOutcome::Ok(_)
        ),
        "the operator's MAC-authenticated revoke is served"
    );
    // Only the other install's grant survives, so a run stamped with it still releases
    // while one stamped with the revoked install is refused.
    let mut other_install = sf_run(false);
    other_install["stamp"]["attributes"]["flow_install_id"] = json!("install-B");
    assert_eq!(
        flow.use_secret("basal", &other_install)["status"],
        "released"
    );
    sf_refusal(&flow, &sf_run(false), "flow_no_grant");
    // The same single-grant delete, this time for the login's grant.
    let (body, tag) = revoke(login_a);
    assert!(
        matches!(
            admin.execute(7, &body, &tag).await,
            admin_surface::AdminOutcome::Ok(_)
        ),
        "the operator's MAC-authenticated revoke is served"
    );
    sf_refusal(&flow, &sf_run(true), "flow_no_grant");
    // The other install's API-key grant is the only one left, and revoking the login's
    // never touched it.
    assert_eq!(
        flow.use_secret("basal", &other_install)["status"],
        "released"
    );
    let remaining = flow.phone("secret.list", json!({})).await;
    let left: Vec<&str> = remaining["secrets"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|secret| secret["flow_grants"].as_array().unwrap())
        .map(|row| row["grant_id"].as_str().unwrap())
        .collect();
    assert_eq!(left, [api_b.as_str()], "{remaining}");
}
