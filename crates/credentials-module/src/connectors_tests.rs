mod connectors_contract {
    use super::*;
    use credentials_core::{federation::NewRemoteRecord, record::RecordIdentity};
    use sha2::{Digest, Sha256};

    fn rig(
        seed: u8,
    ) -> (
        Arc<ReadSurface>,
        Arc<admin_surface::AdminSurface>,
        Arc<EncryptedStore>,
        std::path::PathBuf,
        TestTempDir,
    ) {
        let (surface, store, db, root) = tmp_surface_with_store(seed);
        for id in ["apikey:active", "apikey:dead"] {
            store
                .remove_audited(id, AuditCtx::admin(AuditOp::Remove))
                .unwrap();
        }
        let engine = Arc::new(RefreshEngine::new(
            Arc::clone(&store),
            Vec::new(),
            Arc::new(crate::test_support::NoHttp),
        ));
        let key = MasterKey::from_bytes([seed; MASTER_KEY_LEN]);
        let admin = Arc::new(admin_surface::AdminSurface::new(
            engine,
            credentials_core::admin_auth::AdminMacKey::derive(&key),
            credentials_core::vault_id_for(db.parent().unwrap()).unwrap(),
            key.key_id(),
        ));
        admin.record_bind_at(77, 1, reserved("cingulate"), "");
        (surface, admin, store, db, root)
    }

    async fn reply(
        surface: &Arc<ReadSurface>,
        admin: &Arc<admin_surface::AdminSurface>,
    ) -> serde_json::Value {
        let (ty, bytes) = routed_reply(surface, admin, 77, "connectors.list", json!({})).await;
        assert_eq!(ty, FrameType::Response);
        serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["result"].clone()
    }

    fn seed(store: &EncryptedStore, db: &std::path::Path) -> Vec<String> {
        let mut payloads = vec!["opaque-access".to_owned(), "opaque-refresh".to_owned()];
        let mut account = oauth_record_with_adapter("anthropic");
        account.identity = RecordIdentity {
            account_id: Some("account-1".into()),
            email: Some("person@example.invalid".into()),
            org_name: Some("Workspace".into()),
        };
        account.detected_plan = Some(credentials_core::plan_detection::DetectedPlan {
            tier: Some("pro".into()),
            raw: None,
            observed_at_ms: 1,
        });
        store.create("oauth:anthropic", &account).unwrap();
        for (id, kind, state) in [
            ("apikey:openai", CredentialKind::ApiKey, "needs_reauth"),
            ("cookie:signed-out", CredentialKind::Cookie, "retired"),
            ("cookie:damaged", CredentialKind::Cookie, "corrupt"),
            ("oauth:id-is-not-kind", CredentialKind::Opaque, "active"),
            ("opaque:id-is-not-kind", CredentialKind::ApiKey, "active"),
            ("apikey:runtime", CredentialKind::ApiKey, "active"),
            ("signing:excluded", CredentialKind::SigningKey, "active"),
            ("kem:excluded", CredentialKind::KemKey, "active"),
            ("dsn:excluded", CredentialKind::Dsn, "active"),
        ] {
            let payload = format!("payload-canary-{id}");
            payloads.push(payload.clone());
            store
                .create(
                    id,
                    &VaultRecord::new_static(kind, "test", payload.into_bytes(), None),
                )
                .unwrap();
            rusqlite::Connection::open(db)
                .unwrap()
                .execute(
                    "UPDATE credentials SET state=?2 WHERE credential_id=?1",
                    rusqlite::params![id, state],
                )
                .unwrap();
        }
        let mut no_adapter = oauth_record_with_adapter("anthropic");
        store
            .create(
                "oauth:bot-excluded",
                &oauth_record_with_adapter("github_app"),
            )
            .unwrap();
        no_adapter.refresh_adapter = None;
        store.create("oauth:no-adapter", &no_adapter).unwrap();
        store
            .remote_add_audited(&NewRemoteRecord {
                credential_id: "oauth:anthropic:copy".into(),
                home_member: "fed-computer:22222222222222222222222222222222".into(),
                refresh_adapter: Some("anthropic".into()),
                detected_plan: None,
                identity: RecordIdentity::default(),
                home_version: 1,
                categories: vec!["llm-provider".into()],
            })
            .unwrap();
        store
            .remote_add_audited(&NewRemoteRecord {
                credential_id: "oauth:runtime-copy".into(),
                home_member: "fed-computer:22222222222222222222222222222222".into(),
                refresh_adapter: Some("anthropic".into()),
                detected_plan: None,
                identity: RecordIdentity::default(),
                home_version: 1,
                categories: vec!["module-runtime".into()],
            })
            .unwrap();
        store
            .set_federation_self_member_audited(
                "fed-computer:11111111111111111111111111111111",
                AuditCtx::admin(AuditOp::FederationSelfSet),
            )
            .unwrap();
        let conn = rusqlite::Connection::open(db).unwrap();
        conn.execute("INSERT OR IGNORE INTO credential_categories (credential_id,category) VALUES ('apikey:runtime','module-runtime')", []).unwrap();
        conn.execute("INSERT INTO auth_events (ts_ms,credential_id,kind,detail,applied) VALUES (1,'apikey:openai','needs_reauth','invalid_api_key',1)", []).unwrap();
        conn.execute(
            "UPDATE credentials SET incarnation='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'",
            [],
        )
        .unwrap();
        conn.execute(
            "UPDATE remote_records SET incarnation='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'",
            [],
        )
        .unwrap();
        payloads
    }

    #[tokio::test]
    async fn connectors_rows_exclude_internal_kinds_and_payloads_and_map_states() {
        let (surface, admin, store, db, _root) = rig(219);
        let payloads = seed(&store, &db);
        let body = reply(&surface, &admin).await;
        assert_eq!(
            body["computer"],
            "fed-computer:11111111111111111111111111111111"
        );
        assert_eq!(body["watch"], true);
        let rows = body["rows"].as_array().unwrap();
        assert_eq!(
            rows.iter()
                .map(|row| row["id"].as_str().unwrap())
                .collect::<Vec<_>>(),
            vec![
                "apikey:openai",
                "cookie:damaged",
                "cookie:signed-out",
                "oauth:anthropic",
                "oauth:anthropic:copy",
                "opaque:id-is-not-kind"
            ]
        );
        let by_id = |id: &str| rows.iter().find(|row| row["id"] == id).unwrap();
        assert_eq!(by_id("oauth:anthropic")["name"], "Claude");
        assert_eq!(by_id("oauth:anthropic")["kind"], "account");
        assert_eq!(
            by_id("oauth:anthropic")["plan"],
            json!({"tier":"pro","source":"detected"})
        );
        assert_eq!(
            by_id("oauth:anthropic")["identity"],
            "person@example.invalid"
        );
        assert_eq!(by_id("apikey:openai")["kind"], "api_key");
        assert_eq!(
            by_id("apikey:openai")["status"],
            json!({"state":"key_refused","reason":"invalid_api_key"})
        );
        assert_eq!(
            by_id("apikey:openai")["setup"],
            json!([{"step":"key","state":"needed","remedy":"replace_key","where":"computer"}])
        );
        assert_eq!(
            by_id("cookie:signed-out")["status"],
            json!({"state":"signed_out"})
        );
        assert_eq!(
            by_id("cookie:damaged")["status"],
            json!({"state":"damaged"})
        );
        assert_eq!(
            by_id("oauth:anthropic")["setup"],
            json!([{"step":"sign_in","state":"done","where":"computer"}])
        );
        assert_eq!(
            by_id("oauth:anthropic:copy")["setup"][1],
            json!({"step":"home","state":"unknown","where":"computer"})
        );
        assert_eq!(
            by_id("opaque:id-is-not-kind")["name"],
            "opaque:id-is-not-kind"
        );
        for row in rows {
            for absent in [
                "description",
                "can",
                "usedBy",
                "settings",
                "counts",
                "payload",
                "token",
                "handle",
            ] {
                assert!(row.get(absent).is_none(), "{absent}");
            }
        }
        let encoded = serde_json::to_string(&body).unwrap();
        for payload in payloads {
            assert!(!encoded.contains(&payload), "payload leaked");
        }
        assert_eq!(
            body["version"],
            format!("{:x}", Sha256::digest(serde_json::to_vec(rows).unwrap()))
        );
        let conn = rusqlite::Connection::open(db).unwrap();
        conn.execute("UPDATE credentials SET envelope=x'010203', state='corrupt' WHERE credential_id='opaque:id-is-not-kind'", []).unwrap();
        assert_eq!(
            reply(&surface, &admin).await["rows"]
                .as_array()
                .unwrap()
                .len(),
            5
        );
    }

    #[tokio::test]
    async fn connectors_categories_identity_plan_and_permission_ids_match_permission_list() {
        let (surface, admin, store, db, _root) = rig(220);
        let mut record = oauth_record_with_adapter("gmail");
        record.identity = RecordIdentity {
            account_id: Some("account-1".into()),
            email: Some("é".repeat(127)),
            org_name: Some("Org".into()),
        };
        store.create("oauth:gmail", &record).unwrap();
        let conn = rusqlite::Connection::open(db).unwrap();
        assert_eq!(
            reply(&surface, &admin).await["rows"][0]["category"],
            "communication"
        );
        assert_eq!(
            reply(&surface, &admin).await["rows"][0]["identity"]
                .as_str()
                .unwrap()
                .len(),
            254
        );
        for (groups, expected) in [
            (vec!["cloud-infrastructure"], "infrastructure"),
            (vec!["cloud-infrastructure", "web-search"], "search"),
            (
                vec!["cloud-infrastructure", "web-search", "media-provider"],
                "ai_models",
            ),
            (vec!["llm-provider"], "ai_models"),
        ] {
            conn.execute(
                "DELETE FROM credential_categories WHERE credential_id='oauth:gmail'",
                [],
            )
            .unwrap();
            for group in groups {
                conn.execute("INSERT INTO credential_categories (credential_id,category) VALUES ('oauth:gmail',?1)", [group]).unwrap();
            }
            assert_eq!(
                reply(&surface, &admin).await["rows"][0]["category"],
                expected
            );
        }
        for (selector, kind) in [
            ("oauth:gmail", SelectorKind::Exact),
            ("llm-provider", SelectorKind::Category),
        ] {
            store
                .create_read_grant_audited(
                    "reserved",
                    "plexus",
                    kind,
                    selector,
                    GrantOperation::Read,
                    AuditCtx::admin(AuditOp::GrantCreate),
                )
                .unwrap();
        }
        let (_, bytes) = routed_reply(&surface, &admin, 77, "permissions.list", json!({})).await;
        let permission_reply: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let mut ids: Vec<_> = permission_reply["result"]["grants"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["id"].clone())
            .collect();
        ids.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
        assert_eq!(ids.len(), 2);
        assert_eq!(
            reply(&surface, &admin).await["rows"][0]["permissions"],
            json!(ids)
        );
        record.identity.email = Some("a".repeat(255));
        store.commit_refresh("oauth:gmail", 1, &record).unwrap();
        assert!(reply(&surface, &admin).await["rows"][0]
            .get("identity")
            .is_none());
        store.invalidate("oauth:gmail").unwrap();
        let needed = reply(&surface, &admin).await;
        assert_eq!(needed["rows"][0]["status"]["state"], "needs_sign_in");
        assert_eq!(
            needed["rows"][0]["setup"],
            json!([{"step":"sign_in","state":"needed","remedy":"sign_in_again","where":"computer"}])
        );
    }
    #[derive(Clone, Copy, Debug, PartialEq)]
    enum BindScope {
        Plain,
        Agent,
        Flow,
        Federated,
    }

    impl BindScope {
        fn stamp(self) -> Option<subc_protocol::scope::ScopeStamp> {
            use subc_protocol::scope::{ScopeAttributes, ScopeKind, ScopeStamp};
            let attributes = ScopeAttributes::new().with_agent_id(Some("connector-agent".into()));
            match self {
                Self::Plain => None,
                Self::Agent => Some(
                    ScopeStamp::new(reserved("prefrontal-core"), "agent", 1, ScopeKind::Head)
                        .with_attributes(attributes),
                ),
                Self::Flow => Some(
                    ScopeStamp::new(reserved("prefrontal-core"), "flow", 1, ScopeKind::Worker)
                        .with_attributes(attributes.with_flow_id(Some("connector-flow".into()))),
                ),
                Self::Federated => Some(ScopeStamp::new(
                    reserved("callosum"),
                    "phone",
                    1,
                    ScopeKind::Federated,
                )),
            }
        }
    }

    async fn bind(
        surface: &Arc<ReadSurface>,
        admin: &Arc<admin_surface::AdminSurface>,
        principal: Option<subc_protocol::Principal>,
        harness: &str,
        app: Option<&str>,
        scope: BindScope,
    ) {
        let request = ModuleControlRequest::RouteBind {
            route_channel: 77,
            epoch: 1,
            target: subc_protocol::RouteTarget::ToolProvider {
                module_id: credentials_core::contract::MODULE_ID.into(),
            },
            identity: subc_protocol::BindIdentity::new(harness, "s"),
            principal,
            consumer_capabilities: None,
            role_versions: None,
            admission_facts: None,
            scope: scope.stamp(),
            call_mode: None,
        };
        let mut body = serde_json::to_value(request).unwrap();
        let peer = subc_protocol::peer::RouteBindPeer::new()
            .with_operator_app(app.map(|app| subc_protocol::peer::OperatorApp::new(app, 1)));
        body.as_object_mut().unwrap().extend(
            serde_json::to_value(peer)
                .unwrap()
                .as_object()
                .unwrap()
                .clone(),
        );
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
        handle_control_request(
            frame,
            &tx,
            surface,
            admin,
            &Arc::new(RouteEpochs::default()),
        )
        .await
        .unwrap();
        let reply = rx.recv().await.unwrap();
        if scope == BindScope::Flow {
            assert_eq!(reply.header.ty, FrameType::Error);
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&reply.body).unwrap()["code"],
                "flow_scopes_unsupported"
            );
            assert!(
                admin.principal(77).is_none(),
                "refused flow bind installs no caller"
            );
        } else {
            assert_eq!(reply.header.ty, FrameType::Response);
        }
    }

    #[tokio::test]
    async fn connectors_admission_matrix_uses_real_binds_and_route_dispatch() {
        let (surface, admin, _store, db, _root) = rig(221);
        let conn = rusqlite::Connection::open(db).unwrap();
        let rows = [
            (
                Some(subc_protocol::Principal::Direct),
                "",
                None,
                BindScope::Plain,
                "desktop-dev",
            ),
            (
                Some(subc_protocol::Principal::Direct),
                "",
                None,
                BindScope::Agent,
                "denied",
            ),
            (
                Some(subc_protocol::Principal::Direct),
                "",
                None,
                BindScope::Flow,
                "denied",
            ),
            (
                Some(subc_protocol::Principal::Direct),
                "",
                None,
                BindScope::Federated,
                "denied",
            ),
            (
                Some(subc_protocol::Principal::Unverified),
                "",
                Some("alfonso-desktop"),
                BindScope::Plain,
                "desktop-release",
            ),
            (
                Some(subc_protocol::Principal::Unverified),
                "",
                Some("alfonso-desktop"),
                BindScope::Agent,
                "desktop-release",
            ),
            (
                Some(subc_protocol::Principal::Unverified),
                "",
                Some("other-app"),
                BindScope::Plain,
                "denied",
            ),
            (
                Some(subc_protocol::Principal::Direct),
                "",
                Some("other-app"),
                BindScope::Plain,
                "denied",
            ),
            (
                Some(reserved("cingulate")),
                "",
                None,
                BindScope::Plain,
                "cingulate",
            ),
            (
                Some(reserved("cingulate")),
                "",
                None,
                BindScope::Agent,
                "cingulate",
            ),
            (
                Some(reserved("callosum")),
                "fed-phone:11111111111111111111111111111111",
                None,
                BindScope::Plain,
                "phone",
            ),
            (
                Some(reserved("callosum")),
                "fed-phone:11111111111111111111111111111111",
                None,
                BindScope::Federated,
                "denied",
            ),
            (
                Some(reserved("callosum")),
                "fed-phone:1111111111111111111111111111111A",
                None,
                BindScope::Plain,
                "denied",
            ),
            (
                Some(reserved("callosum")),
                "fed-phone:short",
                None,
                BindScope::Plain,
                "denied",
            ),
            (
                Some(reserved("callosum")),
                "fed-sim:11111111111111111111111111111111",
                None,
                BindScope::Plain,
                "denied",
            ),
            (
                Some(reserved("callosum")),
                "fed-computer:11111111111111111111111111111111",
                None,
                BindScope::Plain,
                "denied",
            ),
            (
                Some(reserved("callosum")),
                "callosum-self",
                None,
                BindScope::Plain,
                "denied",
            ),
            (
                Some(reserved("aft")),
                "fed-phone:11111111111111111111111111111111",
                None,
                BindScope::Plain,
                "denied",
            ),
            (
                Some(reserved("cerebellum")),
                "",
                None,
                BindScope::Plain,
                "denied",
            ),
            (
                Some(subc_protocol::Principal::Unverified),
                "",
                None,
                BindScope::Plain,
                "denied",
            ),
            (None, "", None, BindScope::Plain, "denied"),
        ];
        let mut cells = 0;
        for (principal, harness, app, scope, expected) in rows {
            for member in ["true", "false", "unreadable"] {
                for phone in ["true", "false", "unreadable"] {
                    conn.execute("INSERT OR REPLACE INTO settings (name,value,updated_at_ms) VALUES ('federation.member_mapping',?1,1)",[member]).unwrap();
                    conn.execute("INSERT OR REPLACE INTO settings (name,value,updated_at_ms) VALUES ('secret.phone_mapping',?1,1)",[phone]).unwrap();
                    if scope == BindScope::Flow {
                        admin.drop_bind(77);
                    }
                    bind(&surface, &admin, principal.clone(), harness, app, scope).await;
                    if scope == BindScope::Flow {
                        // The real binder refuses flows before any operation can run.
                        // Seed the same stamp to test the dispatcher's independent fence.
                        let stamp = scope.stamp();
                        admin.record_connector_bind(
                            77,
                            1,
                            principal.clone().unwrap(),
                            harness,
                            app.map(str::to_owned),
                            stamp.as_ref(),
                        );
                    }
                    for op in ["connectors.list", "connectors.watch"] {
                        let (ty, bytes) = routed_reply(&surface, &admin, 77, op, json!({})).await;
                        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                        let at = format!("{expected} {scope:?} {harness} {member}/{phone} {op}");
                        if expected == "phone" && (member != "true" || phone == "unreadable") {
                            assert_eq!(ty, FrameType::Response, "{at}");
                            assert_eq!(body, uniform_not_found(), "{at}");
                        } else if expected == "phone" && phone == "false" {
                            assert_eq!(ty, FrameType::Response, "{at}");
                            assert_eq!(
                                body,
                                wrap_result(
                                    json!({"error":{"code":"phone_access_off","class":"permanent"}})
                                ),
                                "{at}"
                            );
                        } else if expected == "denied" {
                            assert_eq!(ty, FrameType::Error, "{at}");
                            assert_eq!(body["code"], "permissions_operator_required", "{at}");
                            let (_, permission_bytes) =
                                routed_reply(&surface, &admin, 77, "permissions.list", json!({}))
                                    .await;
                            assert_eq!(bytes, permission_bytes, "{at}");
                        } else if op == "connectors.watch" {
                            assert_eq!(ty, FrameType::StreamData, "{at}");
                            assert_eq!(body["seq"], 1, "{at}");
                            surface.watches.close(77);
                        } else {
                            assert_eq!(ty, FrameType::Response, "{at}");
                            assert_eq!(body["result"]["rows"], json!([]), "{at}");
                        }
                        cells += 1;
                    }
                }
            }
        }
        assert_eq!(cells, 378);
    }

    #[tokio::test]
    async fn connectors_watch_ignores_token_refresh_then_notices_logout_and_ends_on_drain() {
        let (surface, admin, store, _db, _root) = rig(222);
        let mut record = oauth_record_with_adapter("anthropic");
        store.create("oauth:anthropic", &record).unwrap();
        let before = reply(&surface, &admin).await;
        let mut completed = surface.watches.completed.subscribe();
        let (tx, mut rx) = mpsc::channel(8);
        let frame = Frame::build_with_version(
            PROTOCOL_VERSION,
            FrameType::Request,
            Flags::new(false, Priority::Interactive, false),
            77,
            1,
            1,
            serde_json::to_vec(&json!({"method":"connectors.watch","params":{}})).unwrap(),
        )
        .unwrap();
        dispatch_route_request(frame, &tx, &surface, &admin, admin.route_caller(77), None)
            .await
            .unwrap();
        let first: serde_json::Value =
            serde_json::from_slice(&rx.recv().await.unwrap().body).unwrap();
        completed.changed().await.unwrap();
        assert_eq!(first["seq"], 1);
        assert_eq!(first["version"], before["version"]);
        assert_eq!(first.as_object().unwrap().len(), 4);
        record.payload = b"refreshed-payload-canary".to_vec().into();
        record.oauth.as_mut().unwrap().access_token = "refreshed-token-canary".to_owned().into();
        store.commit_refresh("oauth:anthropic", 1, &record).unwrap();
        completed.changed().await.unwrap();
        assert!(rx.try_recv().is_err(), "refresh published a notice");
        assert_eq!(reply(&surface, &admin).await["version"], before["version"]);
        store
            .retire_and_revoke_all_audited("oauth:anthropic", AuditCtx::admin(AuditOp::Remove))
            .unwrap();
        let notice: serde_json::Value =
            serde_json::from_slice(&rx.recv().await.unwrap().body).unwrap();
        assert_eq!(notice["seq"], 2);
        assert_ne!(notice["version"], before["version"]);
        assert_eq!(notice["version"], reply(&surface, &admin).await["version"]);
        assert_eq!(notice["epoch"], first["epoch"]);
        surface.watches.finish_all().await.unwrap();
        assert_eq!(rx.recv().await.unwrap().header.ty, FrameType::StreamEnd);
        assert!(rx.try_recv().is_err());
    }
    #[derive(Clone)]
    struct Logs(Arc<std::sync::Mutex<Vec<String>>>);

    impl tracing::Subscriber for Logs {
        fn register_callsite(
            &self,
            _: &'static tracing::Metadata<'static>,
        ) -> tracing::subscriber::Interest {
            tracing::subscriber::Interest::always()
        }
        fn max_level_hint(&self) -> Option<tracing::metadata::LevelFilter> {
            Some(tracing::metadata::LevelFilter::TRACE)
        }
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
            struct Message(String);
            impl tracing::field::Visit for Message {
                fn record_debug(&mut self, _: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                    self.0.push_str(&format!("{value:?}"));
                }
            }
            let mut message = Message(String::new());
            event.record(&mut message);
            self.0.lock().unwrap().push(message.0);
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn connectors_development_admission_logs_each_call_and_no_other_direct_op() {
        const CHILD: &str = "CK_CONNECTOR_LOG_CAPTURE_CHILD";
        const TEST: &str = "tests::connectors_contract::connectors_development_admission_logs_each_call_and_no_other_direct_op";
        if std::env::var(CHILD).as_deref() != Ok("1") {
            // Isolate the subscriber from parallel tests exercising the same log site.
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", TEST, "--nocapture", "--test-threads=1"])
                .env(CHILD, "1")
                .output()
                .unwrap();
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(output.status.success(), "{stdout}\n{stderr}");
            assert!(
                stdout.contains("1 passed;"),
                "child must execute the capture test: {stdout}"
            );
            return;
        }
        let (surface, admin, _store, _db, _root) = rig(223);
        admin.record_bind_at(77, 1, subc_protocol::Principal::Direct, "");
        let logs = Logs(Arc::default());
        let _subscriber = tracing::subscriber::set_default(logs.clone());
        for method in ["connectors.list", "connectors.watch"] {
            routed_reply(&surface, &admin, 77, method, json!({})).await;
            surface.watches.close(77);
        }
        assert_eq!(
            *logs.0.lock().unwrap(),
            vec!["unsigned_desktop_development_admission admitted connectors read"; 2]
        );
        let manifest = manifest("claustrum", None);
        let ProviderRole::ManagementSurface { operations, .. } = &manifest.provides[0] else {
            panic!("management")
        };
        for op in operations.iter().filter(|op| !connectors::is_op(&op.name)) {
            routed_reply(&surface, &admin, 77, &op.name, json!({})).await;
        }
        assert_eq!(
            logs.0.lock().unwrap().len(),
            2,
            "non-connectors direct calls gained a log line"
        );
    }

    #[tokio::test]
    async fn connectors_vectors_are_generated_by_handler_and_pinned_to_sha256sums() {
        let (surface, admin, store, db, _root) = rig(224);
        let mut samples = std::collections::BTreeMap::new();
        let (_, empty) = routed_reply(&surface, &admin, 77, "connectors.list", json!({})).await;
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&empty).unwrap()["result"]["rows"],
            json!([])
        );
        samples.insert(
            "empty.json",
            serde_json::from_slice::<serde_json::Value>(&empty).unwrap(),
        );
        let _ = seed(&store, &db);
        let (_, inventory) = routed_reply(&surface, &admin, 77, "connectors.list", json!({})).await;
        samples.insert(
            "inventory.json",
            serde_json::from_slice::<serde_json::Value>(&inventory).unwrap(),
        );
        let (ty, notice) = routed_reply(&surface, &admin, 77, "connectors.watch", json!({})).await;
        assert_eq!(ty, FrameType::StreamData);
        surface.watches.close(77);
        let mut notice: serde_json::Value = serde_json::from_slice(&notice).unwrap();
        // The process epoch is random; only that field is normalized for the sample.
        assert_eq!(notice["epoch"].as_str().unwrap().len(), 32);
        notice["epoch"] = json!("cccccccccccccccccccccccccccccccc");
        samples.insert("watch.json", notice);
        store
            .set_federation_member_mapping_audited(
                true,
                AuditCtx::admin(AuditOp::FederationGateSet),
            )
            .unwrap();
        store
            .set_secret_phone_mapping_audited(false, AuditCtx::admin(AuditOp::SecretPhoneGateSet))
            .unwrap();
        bind(
            &surface,
            &admin,
            Some(reserved("callosum")),
            "fed-phone:11111111111111111111111111111111",
            None,
            BindScope::Plain,
        )
        .await;
        let (_, off) = routed_reply(&surface, &admin, 77, "connectors.list", json!({})).await;
        samples.insert(
            "phone-access-off.json",
            serde_json::from_slice::<serde_json::Value>(&off).unwrap(),
        );
        let dir =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/connectors-v1");
        let emit = std::env::var_os("CK_EMIT_CONNECTOR_VECTORS").is_some();
        if emit {
            std::fs::create_dir_all(&dir).unwrap();
        }
        let mut sums = String::new();
        for (name, value) in samples {
            let bytes = format!("{}\n", serde_json::to_string_pretty(&value).unwrap()).into_bytes();
            sums.push_str(&format!("{:x}  {name}\n", Sha256::digest(&bytes)));
            if emit {
                std::fs::write(dir.join(name), &bytes).unwrap();
            } else {
                assert_eq!(std::fs::read(dir.join(name)).unwrap(), bytes, "{name}");
            }
        }
        if emit {
            std::fs::write(dir.join("SHA256SUMS"), &sums).unwrap();
        } else {
            assert_eq!(
                std::fs::read_to_string(dir.join("SHA256SUMS")).unwrap(),
                sums
            );
        }
    }
    #[tokio::test]
    async fn connectors_name_accepts_80_chars_and_caps_81() {
        let (surface, admin, store, _db, _root) = rig(225);
        for len in [80, 81] {
            let id = format!("opaque:{}", "a".repeat(len - 7));
            store
                .create(
                    &id,
                    &VaultRecord::new_static(
                        CredentialKind::ApiKey,
                        "test",
                        b"name-test-canary".to_vec(),
                        None,
                    ),
                )
                .unwrap();
        }
        let body = reply(&surface, &admin).await;
        for row in body["rows"].as_array().unwrap() {
            assert_eq!(row["name"].as_str().unwrap().chars().count(), 80);
            assert!(row.get("category").is_none());
        }
        for login in credentials_core::LOGIN_PROVIDERS {
            let (name, _) = credentials_core::catalog::connector_metadata(login.default_id);
            assert!(
                name.is_some_and(|name| name != login.default_id && name.chars().count() <= 80),
                "{}",
                login.key
            );
        }
    }
    #[tokio::test]
    async fn connectors_copies_map_home_states_fetch_outcomes_and_recheck_phone_gate() {
        let (surface, admin, store, db, _root) = rig(226);
        let _ = seed(&store, &db);
        let conn = rusqlite::Connection::open(db).unwrap();
        for (state, status, outcome, home) in [
            ("active", "ok", Some("ok"), "done"),
            (
                "needs_reauth",
                "needs_sign_in",
                Some("home_unpaired"),
                "needed",
            ),
            ("active", "ok", None, "unknown"),
            ("corrupt", "damaged", Some("store_error"), "needed"),
        ] {
            conn.execute("UPDATE remote_records SET last_home_state=?1,last_fetch_outcome=?2 WHERE credential_id='oauth:anthropic:copy'",rusqlite::params![state,outcome]).unwrap();
            let body = reply(&surface, &admin).await;
            let row = body["rows"]
                .as_array()
                .unwrap()
                .iter()
                .find(|row| row["id"] == "oauth:anthropic:copy")
                .unwrap();
            assert_eq!(row["status"]["state"], status);
            assert_eq!(row["setup"][1]["state"], home);
        }
        store
            .set_federation_member_mapping_audited(
                true,
                AuditCtx::admin(AuditOp::FederationGateSet),
            )
            .unwrap();
        store
            .set_secret_phone_mapping_audited(true, AuditCtx::admin(AuditOp::SecretPhoneGateSet))
            .unwrap();
        bind(
            &surface,
            &admin,
            Some(reserved("callosum")),
            "fed-phone:11111111111111111111111111111111",
            None,
            BindScope::Plain,
        )
        .await;
        let (tx, mut rx) = mpsc::channel(4);
        let frame = Frame::build_with_version(
            PROTOCOL_VERSION,
            FrameType::Request,
            Flags::new(false, Priority::Interactive, false),
            77,
            1,
            1,
            serde_json::to_vec(&json!({"method":"connectors.watch","params":{}})).unwrap(),
        )
        .unwrap();
        dispatch_route_request(frame, &tx, &surface, &admin, admin.route_caller(77), None)
            .await
            .unwrap();
        assert_eq!(rx.recv().await.unwrap().header.ty, FrameType::StreamData);
        store
            .set_secret_phone_mapping_audited(false, AuditCtx::admin(AuditOp::SecretPhoneGateSet))
            .unwrap();
        let refusal = rx.recv().await.unwrap();
        assert_eq!(refusal.header.ty, FrameType::Response);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&refusal.body).unwrap(),
            wrap_result(json!({"error":{"code":"phone_access_off","class":"permanent"}}))
        );
    }
    #[tokio::test]
    async fn connectors_watch_registers_before_following_cancel_and_route_close() {
        let (surface, admin, _store, _db, _root) = rig(227);
        let routes = Arc::new(RouteEpochs::default());
        routes.install(77, 1);
        let (control, _control_rx) = mpsc::channel(4);
        let (route, mut rx) = mpsc::channel(4);
        let egress = Egress { control, route };
        for (corr, ending) in [(1, FrameType::Cancel), (2, FrameType::Goodbye)] {
            let open = Frame::build_with_version(
                PROTOCOL_VERSION,
                FrameType::Request,
                Flags::new(false, Priority::Interactive, false),
                77,
                1,
                corr,
                serde_json::to_vec(&json!({"method":"connectors.watch","params":{}})).unwrap(),
            )
            .unwrap();
            handle_frame(open, &egress, &surface, &admin, &routes)
                .await
                .unwrap();
            assert!(
                surface.watches.contains(77),
                "watch registration was deferred past the next ingress frame"
            );
            let end = Frame::build_with_version(
                PROTOCOL_VERSION,
                ending,
                Flags::new(false, Priority::Interactive, false),
                77,
                1,
                corr,
                Vec::new(),
            )
            .unwrap();
            handle_frame(end, &egress, &surface, &admin, &routes)
                .await
                .unwrap();
            assert!(!surface.watches.contains(77));
        }
        assert!(rx.try_recv().is_err());
    }
}
