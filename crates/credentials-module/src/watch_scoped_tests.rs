mod scoped_watch {
    use super::*;
    use credentials_core::store::{SetCategoryMode, SetProvidersMode};
    use std::time::Duration;
    use subc_protocol::{AdmissionClass, FLAG_SUBSCRIPTION};
    include!("list_scoped_vectors_tests.rs");

    struct Rig {
        surface: Arc<ReadSurface>,
        admin: Arc<admin_surface::AdminSurface>,
        store: Arc<EncryptedStore>,
        db_path: std::path::PathBuf,
        _root: TestTempDir,
        routes: Arc<RouteEpochs>,
        egress: Egress,
        rx: mpsc::Receiver<Frame>,
        _control: mpsc::Receiver<Frame>,
    }

    impl Rig {
        fn new() -> Self {
            let (surface, admin, store, db_path, root) = scoped_rig_with_db(149);
            let (control, control_rx) = mpsc::channel(8);
            let (route, rx) = mpsc::channel(256);
            Self {
                surface,
                admin,
                store,
                db_path,
                _root: root,
                routes: Arc::new(RouteEpochs::default()),
                egress: Egress { control, route },
                rx,
                _control: control_rx,
            }
        }

        fn bind(&self, channel: u16, principal: subc_protocol::Principal) {
            self.routes.install(channel, 1);
            self.admin.record_bind_at(channel, 1, principal, "");
        }

        async fn dispatch(
            &self,
            channel: u16,
            corr: u64,
            ty: FrameType,
            method: &str,
            params: serde_json::Value,
        ) {
            let mut flags = Flags::new(false, Priority::Interactive, false);
            if method == OP_WATCH_SCOPED {
                flags.0 |= FLAG_SUBSCRIPTION;
            }
            let frame = Frame::build_with_version(
                PROTOCOL_VERSION,
                ty,
                flags,
                channel,
                1,
                corr,
                if matches!(ty, FrameType::Cancel | FrameType::Goodbye) {
                    Vec::new()
                } else {
                    serde_json::to_vec(&json!({ "method":method, "params":params })).unwrap()
                },
            )
            .unwrap();
            assert!(handle_frame(
                frame,
                &self.egress,
                &self.surface,
                &self.admin,
                &self.routes
            )
            .await
            .unwrap());
        }

        async fn open(&self, channel: u16, corr: u64, params: serde_json::Value) {
            self.dispatch(channel, corr, FrameType::Request, OP_WATCH_SCOPED, params)
                .await;
        }

        async fn next(&mut self) -> Frame {
            tokio::time::timeout(Duration::from_secs(3), self.rx.recv())
                .await
                .expect("notice deadline")
                .expect("egress open")
        }

        async fn notice(&mut self, channel: u16, corr: u64, seq: u64) -> serde_json::Value {
            let frame = self.next().await;
            assert_eq!(frame.header.ty, FrameType::StreamData);
            assert_eq!(
                (frame.header.channel, frame.header.epoch, frame.header.corr),
                (channel, 1, corr)
            );
            assert_eq!(
                frame.header.flags.admission_class(),
                Some(AdmissionClass::Sheddable)
            );
            let body: serde_json::Value = serde_json::from_slice(&frame.body).unwrap();
            assert_eq!(body["kind"], "changed");
            assert_eq!(body["seq"], seq);
            assert_eq!(body.as_object().unwrap().len(), 5);
            let epoch = body["epoch"].as_str().unwrap();
            assert_eq!(epoch.len(), 32);
            assert!(epoch.bytes().all(|byte| byte.is_ascii_hexdigit()));
            body
        }

        async fn quiet(&mut self) {
            assert!(
                tokio::time::timeout(Duration::from_millis(400), self.rx.recv())
                    .await
                    .is_err(),
                "unexpected extra notice"
            );
        }

        fn grant(&self, caller: &str, id: &str) {
            grant_for(&self.store, caller, id, GrantOperation::List);
        }
    }

    impl Drop for Rig {
        fn drop(&mut self) {
            self.surface.watches.close_all();
        }
    }

    async fn scoped_login_result(method: &str, id: &str, adapter: &str) -> serde_json::Value {
        let mut rig = Rig::new();
        let mut record = roster_oauth_record();
        record.refresh_adapter = Some(adapter.to_owned());
        rig.store.create(id, &record).unwrap();
        for operation in [GrantOperation::Read, GrantOperation::List] {
            grant_for(&rig.store, "login-reader", id, operation);
        }
        rig.bind(1, reserved("login-reader"));
        let params = if method == OP_GET_SCOPED {
            json!({"credential_id": id})
        } else {
            json!({})
        };
        rig.dispatch(1, 11, FrameType::Request, method, params).await;
        let frame = rig.next().await;
        assert_eq!(frame.header.ty, FrameType::Response);
        let mut body: serde_json::Value = serde_json::from_slice(&frame.body).unwrap();
        if method == OP_GET_SCOPED {
            assert_eq!(body["result"]["credential_id"], id);
            assert_eq!(body["result"]["payload"], json!(record.payload.expose()));
            body["result"].take()
        } else {
            let rows = body["result"]["credentials"].as_array_mut().unwrap();
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0]["id"], id);
            assert_eq!(rows[0]["refresh_adapter"], adapter);
            rows[0].take()
        }
    }

    macro_rules! login_hosts_tests {
        ($get:ident, $list:ident, $adapter:literal, $($host:literal),+) => {
            #[tokio::test]
            async fn $get() {
                let get = scoped_login_result(OP_GET_SCOPED, "oauth:scoped-login", $adapter).await;
                assert_eq!(get["hosts"], json!([$($host),+]));
                assert!(get.get("auth").is_none());
                assert!(get.get("invalid_key").is_none());
            }

            #[tokio::test]
            async fn $list() {
                let row = scoped_login_result(OP_LIST_SCOPED, "oauth:scoped-login", $adapter).await;
                assert_eq!(row["hosts"], json!([$($host),+]));
                assert!(row.get("auth").is_none());
                assert!(row.get("invalid_key").is_none());
            }
        };
    }

    login_hosts_tests!(login_hosts_anthropic_get, login_hosts_anthropic_list, "anthropic", "api.anthropic.com");
    login_hosts_tests!(login_hosts_chatgpt_get, login_hosts_chatgpt_list, "openai", "chatgpt.com");
    login_hosts_tests!(login_hosts_antigravity_get, login_hosts_antigravity_list, "antigravity", "cloudcode-pa.googleapis.com", "daily-cloudcode-pa.googleapis.com");
    login_hosts_tests!(login_hosts_xai_get, login_hosts_xai_list, "xai", "api.x.ai");
    login_hosts_tests!(login_hosts_meta_get, login_hosts_meta_list, "meta", "api.meta.ai");

    #[tokio::test]
    async fn login_hosts_absent_for_other_adapters_even_with_a_known_id() {
        for method in [OP_GET_SCOPED, OP_LIST_SCOPED] {
            let result = scoped_login_result(method, "oauth:anthropic", "google").await;
            for field in ["hosts", "auth", "invalid_key"] {
                assert!(result.get(field).is_none(), "{method} must omit {field}");
            }
        }
    }

    #[tokio::test]
    async fn watch_scoped_refusal_backpressure_does_not_block_control() {
        for params in [json!({}), json!({"unknown_param":true})] {
            let mut rig = Rig::new();
            let (route, rx) = mpsc::channel(1);
            rig.egress.route = route;
            rig.rx = rx;
            rig.bind(1, reserved("watcher"));
            rig.surface.watches.finish_all().await.unwrap();
            let filler = Frame::build_with_version(
                PROTOCOL_VERSION,
                FrameType::Response,
                Flags::new(false, Priority::Interactive, false),
                1,
                1,
                77,
                Vec::new(),
            )
            .unwrap();
            rig.egress.route.try_send(filler).unwrap();
            tokio::time::timeout(Duration::from_millis(100), rig.open(1, 11, params.clone()))
                .await
                .expect("watch refusal must not block ingress on route backpressure");
            let ping = Frame::build_with_version(
                PROTOCOL_VERSION,
                FrameType::Ping,
                control_flags(),
                0,
                0,
                88,
                Vec::new(),
            )
            .unwrap();
            handle_frame(ping, &rig.egress, &rig.surface, &rig.admin, &rig.routes)
                .await
                .unwrap();
            assert_eq!(rig._control.try_recv().unwrap().header.ty, FrameType::Pong);
            assert_eq!(rig.rx.try_recv().unwrap().header.corr, 77);
            let refusal = rig.next().await;
            assert_eq!(refusal.header.corr, 11);
            if params == json!({}) {
                assert_eq!(refusal.header.ty, FrameType::Response);
                assert_scoped_not_found(&serde_json::from_slice(&refusal.body).unwrap());
            } else {
                assert_eq!(refusal.header.ty, FrameType::Error);
                assert_eq!(
                    serde_json::from_slice::<serde_json::Value>(&refusal.body).unwrap()["code"],
                    "invalid_params"
                );
            }
        }
    }

    #[tokio::test]
    async fn watch_scoped_accepts_request_without_subscription_flag() {
        let mut rig = Rig::new();
        rig.bind(1, reserved("watcher"));
        let frame = Frame::build_with_version(
            PROTOCOL_VERSION,
            FrameType::Request,
            Flags::new(false, Priority::Interactive, false),
            1,
            1,
            11,
            serde_json::to_vec(&json!({"method":OP_WATCH_SCOPED,"params":{}})).unwrap(),
        )
        .unwrap();
        assert!(!frame.header.flags.is_subscription());
        handle_frame(frame, &rig.egress, &rig.surface, &rig.admin, &rig.routes)
            .await
            .unwrap();
        rig.notice(1, 11, 1).await;
    }

    #[tokio::test]
    async fn watch_scoped_accepts_request_with_subscription_flag() {
        let mut rig = Rig::new();
        rig.bind(1, reserved("watcher"));
        rig.open(1, 11, json!({})).await;
        rig.notice(1, 11, 1).await;
    }

    #[tokio::test]
    async fn draining_keeps_ping_live_while_watch_end_waits_for_route_capacity() {
        use std::{future::Future, task::Poll};

        let mut rig = Rig::new();
        let (route, rx) = mpsc::channel(1);
        rig.egress.route = route;
        rig.rx = rx;
        rig.bind(1, reserved("watcher"));
        rig.open(1, 11, json!({})).await;
        rig.notice(1, 11, 1).await;
        let filler = Frame::build_with_version(PROTOCOL_VERSION, FrameType::Response,
            control_flags(), 1, 1, 77, Vec::new()).unwrap();
        rig.egress.route.try_send(filler).unwrap();
        let body = serde_json::to_vec(&subc_protocol::session::ModuleControlCommand::Draining {
            reason: subc_protocol::RouteCloseReason::Reload, deadline_ms: 4_102_444_800_000,
        }).unwrap();
        let control = |ty, corr, body| Frame::build_with_version(PROTOCOL_VERSION, ty,
            control_flags(), 0, 0, corr, body).unwrap();
        {
            let mut handling = std::pin::pin!(handle_frame(control(FrameType::Push, 0, body),
                &rig.egress, &rig.surface, &rig.admin, &rig.routes));
            let keep_reading = std::future::poll_fn(|cx| Poll::Ready(handling.as_mut().poll(cx))).await;
            assert!(matches!(keep_reading, Poll::Ready(Ok(true))), "route capacity blocked the frame loop");
        }
        handle_frame(control(FrameType::Ping, 88, Vec::new()),
            &rig.egress, &rig.surface, &rig.admin, &rig.routes).await.unwrap();
        assert_eq!(rig._control.try_recv().unwrap().header.ty, FrameType::Pong);
        assert_eq!(rig.rx.try_recv().unwrap().header.corr, 77);
        let end = rig.next().await;
        assert_eq!((end.header.ty, end.header.corr), (FrameType::StreamEnd, 11));
        assert!(rig.rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn watch_scoped_drain_and_shutdown_end_before_closing() {
        for ty in [FrameType::Push, FrameType::Goodbye] {
            let mut rig = Rig::new();
            for channel in 1..=2 {
                rig.bind(channel, reserved("watcher"));
                rig.open(channel, u64::from(channel) + 10, json!({})).await;
                rig.notice(channel, u64::from(channel) + 10, 1).await;
            }
            let frame = Frame::build_with_version(
                PROTOCOL_VERSION,
                ty,
                control_flags(),
                0,
                0,
                0,
                if ty == FrameType::Goodbye {
                    Vec::new()
                } else {
                    serde_json::to_vec(&subc_protocol::session::ModuleControlCommand::Draining {
                        reason: subc_protocol::RouteCloseReason::Reload,
                        deadline_ms: 4102444800000,
                    })
                    .unwrap()
                },
            )
            .unwrap();
            let keep_open = handle_frame(frame, &rig.egress, &rig.surface, &rig.admin, &rig.routes)
                .await
                .unwrap();
            assert_eq!(keep_open, ty != FrameType::Goodbye);
            let mut frames = if keep_open {
                [rig.next().await, rig.next().await]
            } else {
                [
                    rig.rx.try_recv().expect("first STREAM_END queued before closing"),
                    rig.rx.try_recv().expect("second STREAM_END queued before closing"),
                ]
            };
            frames.sort_by_key(|frame| frame.header.channel);
            for (index, frame) in frames.iter().enumerate() {
                assert_eq!(frame.header.ty, FrameType::StreamEnd);
                assert_eq!(frame.header.corr, index as u64 + 11);
                assert_eq!(frame.header.epoch, 1);
            }
            rig.open(1, 99, json!({})).await;
            let refusal = rig.next().await;
            assert_eq!(refusal.header.ty, FrameType::Response);
            assert_scoped_not_found(&serde_json::from_slice(&refusal.body).unwrap());
            rig.quiet().await;
        }
    }

    #[tokio::test]
    async fn watch_scoped_wire_fixture_is_producer_generated() {
        let mut rig = Rig::new();
        rig.store.force_credential_incarnation_for_test(
            "apikey:active",
            "0123456789abcdef0123456789abcdef",
        );
        rig.grant("watcher", "apikey:active");
        rig.bind(1, reserved("watcher"));
        rig.open(1, 11, json!({})).await;
        let first = rig.notice(1, 11, 1).await;
        rig.store.invalidate("apikey:active").unwrap();
        let second = rig.notice(1, 11, 2).await;
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/enrollment_wire_contract.json");
        let mut text = std::fs::read_to_string(&path).unwrap();
        let fixture: serde_json::Value = serde_json::from_str(&text).unwrap();
        let row = fixture["operations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["op"] == OP_WATCH_SCOPED)
            .unwrap();
        assert_eq!(
            row["request"],
            serde_json::to_string(&ListScopedParams {
                enrollment_token: None
            })
            .unwrap()
        );
        assert_eq!(row["success_cases"].as_array().unwrap().len(), 2);
        assert_eq!(row["success"].as_array().unwrap().len(), 2);
        for (index, mut notice) in [first, second].into_iter().enumerate() {
            // Only the boot nonce is nondeterministic; every other byte is emitted
            // by the daemon request path, not re-created by the fixture test.
            notice["epoch"] = json!("00000000000000000000000000000000");
            let produced = serde_json::to_string(&notice).unwrap();
            if std::env::var_os("UPDATE_ENROLLMENT_WIRE_FIXTURE").is_some() {
                let old = serde_json::to_string(&row["success"][index]).unwrap();
                assert_eq!(
                    text.matches(&old).count(),
                    1,
                    "fixture value must be unique"
                );
                text = text.replacen(&old, &serde_json::to_string(&produced).unwrap(), 1);
            } else {
                assert_eq!(row["success"][index], produced, "producer watch notice drifted; regenerate with UPDATE_ENROLLMENT_WIRE_FIXTURE=1");
            }
        }
        if std::env::var_os("UPDATE_ENROLLMENT_WIRE_FIXTURE").is_some() {
            std::fs::write(path, text).unwrap();
        }
    }

    #[tokio::test]
    async fn watch_scoped_home_watch_provider_ids_reach_listing_and_move_view() {
        use credentials_core::federation::{RemoteHomeState, RemoteWatchApplyMode, RemoteWatchRow};
        let mut rig = Rig::new();
        let home = "fed-computer:aa11bb22cc33dd44ee55ff6600112233";
        let mut row = RemoteWatchRow {
            credential_id: "oauth:shared".into(),
            state: RemoteHomeState::Active,
            refresh_adapter: Some("anthropic".into()),
            identity: Default::default(),
            categories: vec!["llm-provider".into()],
            provider_ids: Some(vec!["anthropic".into()]),
            detected_plan: None,
            home_version: 1,
            condition: None,
        };
        assert_eq!(
            rig.store
                .remote_watch_apply_audited(
                    home, "pair", std::slice::from_ref(&row), RemoteWatchApplyMode::Full, &[],
                )
                .unwrap()
                .inserted,
            1
        );
        rig.grant("watcher", &row.credential_id);
        rig.bind(1, reserved("watcher"));
        rig.open(1, 11, json!({})).await;
        let initial = rig.notice(1, 11, 1).await;
        let listing =
            scoped_route_request(&rig.surface, &rig.admin, 1, OP_LIST_SCOPED, json!({})).await;
        assert_eq!(
            listing["result"]["credentials"][0]["provider_ids"], json!(["anthropic"])
        );
        assert_eq!(listing["result"]["credentials"][0]["hosts"], json!(["api.anthropic.com"]));
        assert_eq!(listing["result"]["view"], initial["view"]);
        let writes = rig.store.subscribe_writes();
        row.provider_ids = Some(vec!["openai".into()]);
        assert_eq!(
            rig.store
                .remote_watch_apply_audited(home, "pair", &[row], RemoteWatchApplyMode::Full, &[])
                .unwrap()
                .updated,
            1
        );
        assert!(writes.has_changed().unwrap());
        let changed = rig.notice(1, 11, 2).await;
        assert_ne!(changed["view"], initial["view"]);
        assert_eq!(changed["keys"], initial["keys"]);
        let listing =
            scoped_route_request(&rig.surface, &rig.admin, 1, OP_LIST_SCOPED, json!({})).await;
        assert_eq!(listing["result"]["credentials"][0]["provider_ids"], json!(["openai"]));
        assert_eq!(listing["result"]["view"], changed["view"]);
    }

    #[tokio::test]
    async fn watch_scoped_metadata_changes_each_emit_once() {
        let mut rig = Rig::new();
        rig.bind(1, reserved("watcher"));
        rig.open(1, 11, json!({})).await;
        let mut previous = rig.notice(1, 11, 1).await;
        for (index, mutation) in [
            "grant",
            "category",
            "provider",
            "plan",
            "plan-since",
            "plan-since-clear",
            "state",
        ]
        .iter()
        .enumerate()
        {
            match *mutation {
                "grant" => rig.grant("watcher", "apikey:active"),
                "category" => {
                    rig.store
                        .set_categories_audited(
                            "apikey:active",
                            SetCategoryMode::Add,
                            &["watch-test".into()],
                            AuditCtx::admin(AuditOp::SetCategory),
                        )
                        .unwrap();
                }
                "provider" => {
                    rig.store
                        .set_providers_audited(
                            "apikey:active",
                            SetProvidersMode::Set,
                            &["anthropic".into()],
                            AuditCtx::admin(AuditOp::SetProviders),
                        )
                        .unwrap();
                }
                "plan" => {
                    rig.store
                        .set_plan_audited(
                            "apikey:active",
                            Some("pro"),
                            AuditCtx::admin(AuditOp::SetPlan),
                        )
                        .unwrap();
                }
                "plan-since" | "plan-since-clear" => {
                    rig.store
                        .set_plan_since_audited(
                            "apikey:active",
                            Some("pro"),
                            (*mutation == "plan-since").then_some(1),
                            AuditCtx::admin(AuditOp::SetPlan),
                        )
                        .unwrap();
                }
                "state" => rig.store.invalidate("apikey:active").unwrap(),
                _ => unreachable!(),
            }
            let notice = rig.notice(1, 11, index as u64 + 2).await;
            assert_ne!(previous["view"], notice["view"], "{mutation}");
            assert_eq!(previous["epoch"], notice["epoch"]);
            previous = notice;
            rig.quiet().await;
        }
    }

    #[tokio::test]
    async fn list_scoped_hosts_use_local_descriptors_for_local_and_remote_rows() {
        let rig = Rig::new();
        rig.store
            .set_registered_provider_settings_audited(
                "customdescriptor",
                &[],
                &[],
                Some(&credentials_core::store::RegisteredProviderSettings {
                    hosts: vec!["api.example.com".into()],
                    auth_header: Some("x-api-key".into()),
                    auth_scheme: Some("raw".into()),
                    fusiform_provider_id: None,
                }),
                AuditCtx::admin(AuditOp::ProviderSet),
            )
            .unwrap();
        rig.store
            .set_registered_provider_audited(
                "nodescriptor",
                &[],
                &[],
                AuditCtx::admin(AuditOp::ProviderSet),
            )
            .unwrap();
        for remote in [false, true] {
            for (id, hosts) in [
                ("apikey:openai", Some(json!(["api.openai.com"]))),
                (
                    "apikey:nanogpt",
                    Some(json!(["api.nano-gpt.com", "nano-gpt.com"])),
                ),
                ("apikey:customdescriptor", Some(json!(["api.example.com"]))),
                ("apikey:nodescriptor", None),
                ("apikey:searxng", None),
                ("apikey:typesafe", Some(json!(["api.typesafe.ai"]))),
                ("apikey:kagi", None),
                ("oauth:anthropic", None),
                ("cookie:openai", None),
                ("manual:openai", None),
            ] {
                let id = format!("{id}:{}", if remote { "remote" } else { "local" });
                if remote {
                    rig.store
                        .remote_add_audited(&credentials_core::federation::NewRemoteRecord {
                            credential_id: id.clone(),
                            home_member: "fed-computer:aa11bb22cc33dd44ee55ff6600112233".into(),
                            refresh_adapter: None,
                            detected_plan: None,
                            identity: Default::default(),
                            home_version: 3,
                            categories: Vec::new(),
                        })
                        .unwrap();
                } else {
                    rig.store
                        .create(
                            &id,
                            &VaultRecord::new_static(
                                CredentialKind::ApiKey,
                                "test",
                                b"test-key".to_vec(),
                                None,
                            ),
                        )
                        .unwrap();
                }
                rig.grant("watcher", &id);
                let listing = rig
                    .surface
                    .list_scoped(
                        &crate::federation::ingress::ScopedCaller::hand_only(
                            (Some(&reserved("watcher"))).cloned(),
                        ),
                        &read_surface::ListScopedParams {
                            enrollment_token: None,
                        },
                    )
                    .unwrap();
                let row = listing.credentials.iter().find(|row| row.id == id).unwrap();
                let wire = serde_json::to_value(row).unwrap();
                assert_eq!(wire.get("hosts"), hosts.as_ref(), "{id}");
                let fusiform_id = match id.split(':').nth(1) {
                    Some("openai") if id.starts_with("apikey:") => Some("openai"),
                    Some("nanogpt") => Some("nano-gpt"),
                    Some("typesafe") => Some("typesafe"),
                    Some("searxng") => Some("searxng"),
                    Some("kagi") => Some("kagi"),
                    _ => None,
                };
                assert_eq!(
                    wire.get("fusiform_provider_id")
                        .and_then(serde_json::Value::as_str),
                    fusiform_id,
                    "{id}"
                );
            }
        }
    }

    #[tokio::test]
    async fn scoped_inventory_keeps_registry_and_conditions_with_the_admitted_row_version() {
        use credentials_core::store::{AuthEventPrincipal, ConditionReport, RegisteredProviderSettings};

        let rig = Rig::new();
        let id = "oauth:antigravity:snapshot";
        let record = oauth_record_with_adapter("antigravity");
        rig.store.create(id, &record).unwrap();
        rig.grant("watcher", id);
        let incarnation = rig.store.credential_incarnation(id).unwrap();
        let link = super::consumer_condition_tests::verification_link();
        assert!(rig.store.report_condition_in_incarnation(id, 1, &incarnation,
            ConditionReport { reason: "provider_verification_required", provider_status: 403, action_url: Some(link.as_str()) },
            AuditCtx::route_admin(AuditOp::ReportCondition, "condition-reporter"),
            AuthEventPrincipal::Reserved("condition-reporter")).unwrap());
        let replace_registry = |store: &EncryptedStore, host: &str| {
            assert!(store.set_registered_provider_settings_audited("antigravity", &[], &[],
                Some(&RegisteredProviderSettings {
                    hosts: vec![host.into()], auth_header: Some("x-api-key".into()),
                    auth_scheme: Some("raw".into()), fusiform_provider_id: None,
                }), AuditCtx::admin(AuditOp::ProviderSet)).unwrap());
        };
        replace_registry(&rig.store, "api.example.com");
        let caller = federation::ingress::ScopedCaller::hand_only(Some(reserved("watcher")));
        let params = read_surface::ListScopedParams { enrollment_token: None };
        let before = rig.surface.list_scoped(&caller, &params).unwrap();
        let row = serde_json::to_value(&before.credentials[0]).unwrap();
        assert!(row.get("condition").is_some());
        let store = rig.store.clone();
        rig.surface.set_incarnation_hook("inventory-projection", move || {
            store.overwrite_unconditional_audited(id, &record, AuditCtx::admin(AuditOp::Overwrite)).unwrap();
            replace_registry(&store, "other.example.com");
        });
        let during = rig.surface.watch_scoped(&caller, &params).unwrap();
        assert_eq!(during.0, before.view);
        let after = rig.surface.list_scoped(&caller, &params).unwrap();
        assert_ne!(after.view, before.view);
        assert!(serde_json::to_value(&after.credentials[0]).unwrap().get("condition").is_none());
    }

    #[tokio::test]
    async fn watch_scoped_registry_hosts_change_emits_through_committed_write() {
        let mut rig = Rig::new();
        let settings = |host: &str| credentials_core::store::RegisteredProviderSettings {
            hosts: vec![host.into()],
            auth_header: Some("x-api-key".into()),
            auth_scheme: Some("raw".into()),
            fusiform_provider_id: None,
        };
        assert!(rig
            .store
            .set_registered_provider_settings_audited(
                "active",
                &[],
                &[],
                Some(&settings("api.example.com")),
                AuditCtx::admin(AuditOp::ProviderSet),
            )
            .unwrap());
        rig.grant("watcher", "apikey:active");
        rig.bind(1, reserved("watcher"));
        rig.open(1, 11, json!({})).await;
        let initial = rig.notice(1, 11, 1).await;
        let version = rig.store.meta("apikey:active").unwrap().record_version;
        assert!(rig
            .store
            .set_registered_provider_settings_audited(
                "active",
                &[],
                &[],
                Some(&settings("other.example.com")),
                AuditCtx::admin(AuditOp::ProviderSet),
            )
            .unwrap());
        let changed = rig.notice(1, 11, 2).await;
        assert_ne!(initial["view"], changed["view"]);
        assert_eq!(initial["keys"], changed["keys"]);
        assert_eq!(initial["epoch"], changed["epoch"]);
        assert_eq!(
            rig.store.meta("apikey:active").unwrap().record_version,
            version,
        );
    }

    #[tokio::test]
    async fn watch_scoped_condition_link_replacement_notifies_only_connectors() {
        use credentials_core::store::{AuthEventPrincipal, ConditionReport};

        let mut rig = Rig::new();
        let id = "oauth:antigravity:watch";
        rig.store
            .create(id, &oauth_record_with_adapter("antigravity"))
            .unwrap();
        rig.grant("condition-list", id);
        rig.bind(1, reserved("condition-list"));
        rig.bind(2, reserved("cingulate"));
        routed_json(&rig.surface, &rig.admin, 1, OP_LIST_SCOPED, json!({})).await;
        let mut completed = rig.surface.watches.completed.subscribe();
        rig.open(1, 1, json!({})).await;
        let base = rig.notice(1, 1, 1).await;
        rig.dispatch(2, 2, FrameType::Request, "connectors.watch", json!({}))
            .await;
        let initial_connector = rig.next().await;
        assert_eq!(initial_connector.header.ty, FrameType::StreamData);
        assert_eq!(initial_connector.header.corr, 2);
        let initial_connector: serde_json::Value =
            serde_json::from_slice(&initial_connector.body).unwrap();
        assert_eq!(initial_connector["seq"], 1);

        let incarnation = rig.store.credential_incarnation(id).unwrap();
        let report = |store: &EncryptedStore, link| {
            assert!(store
                .report_condition_in_incarnation(
                    id,
                    1,
                    &incarnation,
                    ConditionReport {
                        reason: "provider_verification_required",
                        provider_status: 403,
                        action_url: Some(link)
                    },
                    AuditCtx::route_admin(AuditOp::ReportCondition, "condition-reporter"),
                    AuthEventPrincipal::Reserved("condition-reporter"),
                )
                .unwrap());
        };
        async fn wait_for_snapshots(completed: &mut tokio::sync::watch::Receiver<u64>, count: u64) {
            tokio::time::timeout(
                Duration::from_secs(3),
                completed.wait_for(|seen| *seen >= count),
            )
            .await
            .unwrap()
            .unwrap();
        }
        let first_link = super::consumer_condition_tests::verification_link();
        wait_for_snapshots(&mut completed, 2).await;
        report(&rig.store, first_link.as_str());
        wait_for_snapshots(&mut completed, 4).await;
        let mut notices = std::collections::BTreeMap::new();
        while let Ok(frame) = rig.rx.try_recv() {
            assert_eq!(frame.header.ty, FrameType::StreamData);
            let notice: serde_json::Value = serde_json::from_slice(&frame.body).unwrap();
            assert_eq!(notice["seq"], 2);
            assert!(notices.insert(frame.header.corr, notice).is_none());
        }
        assert_eq!(notices.len(), 2);
        assert_ne!(notices[&1]["view"], base["view"]);
        assert_eq!(notices[&1]["keys"], base["keys"]);
        assert_eq!(notices[&1].as_object().unwrap().len(), 5);
        assert_ne!(notices[&2]["version"], initial_connector["version"]);
        let before = routed_reply(&rig.surface, &rig.admin, 1, OP_LIST_SCOPED, json!({})).await;

        let next_link = format!("{first_link}&next=1");
        report(&rig.store, next_link.as_str());
        wait_for_snapshots(&mut completed, 6).await;
        let frame = rig.rx.try_recv().unwrap();
        assert_eq!(frame.header.ty, FrameType::StreamData);
        assert_eq!(frame.header.corr, 2);
        let notice: serde_json::Value = serde_json::from_slice(&frame.body).unwrap();
        assert_eq!(notice["seq"], 3);
        assert_eq!(notice.as_object().unwrap().len(), 4);
        assert_ne!(notice["version"], notices[&2]["version"]);
        assert!(
            rig.rx.try_recv().is_err(),
            "link-only change sent a scoped notice"
        );
        assert_eq!(
            routed_reply(&rig.surface, &rig.admin, 1, OP_LIST_SCOPED, json!({})).await,
            before
        );
        let list = routed_json(&rig.surface, &rig.admin, 2, "connectors.list", json!({})).await;
        assert_eq!(notice["version"], list["result"]["version"]);
        assert_eq!(
            list["result"]["rows"]
                .as_array()
                .unwrap()
                .iter()
                .find(|row| row["id"] == id)
                .unwrap()["condition"]["action_url"],
            next_link
        );
    }

    #[tokio::test]
    async fn watch_scoped_token_refresh_is_quiet() {
        let mut rig = Rig::new();
        let record = roster_oauth_record();
        rig.store.create("oauth:watch-refresh", &record).unwrap();
        rig.store
            .set_plan_since_audited(
                "oauth:watch-refresh",
                Some("pro"),
                Some(1),
                AuditCtx::admin(AuditOp::SetPlan),
            )
            .unwrap();
        rig.grant("watcher", "oauth:watch-refresh");
        rig.bind(1, reserved("watcher"));
        let mut completed = rig.surface.watches.completed.subscribe();
        rig.open(1, 11, json!({})).await;
        let initial = rig.notice(1, 11, 1).await;
        completed.changed().await.unwrap();
        let list = || {
            rig.surface
                .list_scoped(
                    &crate::federation::ingress::ScopedCaller::hand_only(Some(reserved("watcher"))),
                    &ListScopedParams { enrollment_token: None },
                )
                .unwrap()
        };
        let mut listing = list();
        assert_eq!(listing.credentials.len(), 1);
        assert_eq!(initial["view"], listing.view);
        // Compare with the same view input except for the receiving host fact.
        listing.credentials[0].hosts = Some(vec!["api.anthropic.com".into()]);
        assert_eq!(
            initial["view"],
            crate::read_surface::list_scoped_view(&listing.credentials, &listing.grant_tuples),
        );
        listing.credentials[0].hosts = None;
        assert_ne!(
            initial["view"],
            crate::read_surface::list_scoped_view(&listing.credentials, &listing.grant_tuples),
        );
        let mut refreshed = record.clone();
        refreshed.payload = b"fresh-token".to_vec().into();
        rig.store
            .commit_refresh("oauth:watch-refresh", 1, &rig.store.credential_incarnation("oauth:watch-refresh").unwrap(), &refreshed, None)
            .unwrap();
        assert_eq!(
            rig.store
                .meta("oauth:watch-refresh")
                .unwrap()
                .record_version,
            2
        );
        assert_eq!(initial["view"], list().view);
        completed.changed().await.unwrap();
        assert!(rig.rx.try_recv().is_err(), "refresh published a notice");
        rig.dispatch(1, 11, FrameType::Cancel, "", json!({})).await;
        rig.open(1, 12, json!({})).await;
        assert_eq!(initial, rig.notice(1, 12, 1).await);
    }

    /// Callosum re-reads the transfer key to announce it only when its watch's held-key
    /// digest moves, so granting it the key must move that digest. Any other watcher's
    /// digest stays blind to the transfer key.
    #[tokio::test]
    async fn bus_purpose_keys_need_exact_grants_in_inventory_and_watch() {
        let rig = Rig::new();
        let id = credentials_core::signing::BUS_SIGNING_KEY_IDS[0];
        rig.store.create(id, &VaultRecord::new_static(CredentialKind::SigningKey, "test",
            test_ed25519_pem().into_bytes(), None)).unwrap();
        rig.store.set_categories_audited(id, SetCategoryMode::Set, &["bus-purpose".into()],
            AuditCtx::admin(AuditOp::SetCategory)).unwrap();
        rig.store.create_read_grant_audited("reserved", "ckbus", SelectorKind::Category, "bus-purpose",
            GrantOperation::Sign, AuditCtx::admin(AuditOp::GrantCreate)).unwrap();
        let caller = federation::ingress::ScopedCaller::hand_only(Some(reserved("ckbus")));
        let params = read_surface::ListScopedParams { enrollment_token: None };
        assert!(!rig.store.evaluate_scoped_coverage("reserved", "ckbus", id, GrantOperation::Sign,
            &credentials_core::store::DeclaredGrantSet::empty()).unwrap().covered);
        let before = rig.surface.watch_scoped(&caller, &params).unwrap();
        assert!(rig.surface.list_scoped(&caller, &params).unwrap().credentials.is_empty());
        grant_for(&rig.store, "ckbus", id, GrantOperation::Read);
        let listing = rig.surface.list_scoped(&caller, &params).unwrap();
        let row = serde_json::to_value(&listing.credentials[0]).unwrap();
        assert_eq!(row["operations"], json!(["read"]));
        assert_ne!(before.1, rig.surface.watch_scoped(&caller, &params).unwrap().1);
    }

    #[tokio::test]
    async fn the_transfer_key_moves_callosums_keys_and_no_one_elses() {
        use credentials_core::federation::VAULT_TRANSFER_ID;
        let mut rig = Rig::new();
        let pem = credentials_core::kem::generate_key().expect("transfer key");
        rig.store
            .create_audited(
                VAULT_TRANSFER_ID,
                &VaultRecord::new_static(
                    CredentialKind::KemKey,
                    "operator",
                    pem.into_bytes(),
                    None,
                ),
                AuditCtx::admin(AuditOp::Put),
            )
            .expect("transfer init");
        rig.bind(1, reserved("callosum"));
        rig.bind(2, reserved("broca"));
        rig.open(1, 11, json!({})).await;
        let callosum_before = rig.notice(1, 11, 1).await;
        rig.open(2, 21, json!({})).await;
        let broca_before = rig.notice(2, 21, 1).await;

        grant_for(
            &rig.store,
            "callosum",
            VAULT_TRANSFER_ID,
            GrantOperation::Read,
        );
        // The view moves too, because callosum's grant list gained a row. The held-key
        // digest is what callosum acts on, so that digest must move.
        let callosum_after = rig.notice(1, 11, 2).await;
        assert_ne!(callosum_before["keys"], callosum_after["keys"]);
        rig.quiet().await;
        assert_eq!(broca_before["seq"], 1);
    }

    #[tokio::test]
    async fn watch_scoped_identical_signing_replacement_moves_keys() {
        let mut rig = Rig::new();
        // The id deliberately does not advertise the kind: keys follow the sealed
        // record kind, not a naming convention. Sign-only grants withhold identity.
        let record = VaultRecord::new_static(
            CredentialKind::SigningKey,
            "test",
            test_ed25519_pem().into_bytes(),
            None,
        );
        let id = "apikey:not-a-token";
        rig.store.create(id, &record).unwrap();
        grant_for(&rig.store, "watcher", id, GrantOperation::Sign);
        rig.bind(1, reserved("watcher"));
        rig.open(1, 11, json!({})).await;
        let initial = rig.notice(1, 11, 1).await;
        rig.store
            .overwrite_unconditional_audited(id, &record, AuditCtx::admin(AuditOp::Overwrite))
            .unwrap();
        let changed = rig.notice(1, 11, 2).await;
        assert_eq!(initial["view"], changed["view"]);
        assert_ne!(initial["keys"], changed["keys"]);
        rig.quiet().await;
    }

    #[tokio::test]
    async fn watch_scoped_burst_coalesces() {
        let mut rig = Rig::new();
        rig.grant("watcher", "apikey:active");
        rig.bind(1, reserved("watcher"));
        rig.open(1, 11, json!({})).await;
        let initial = rig.notice(1, 11, 1).await;
        rig.store
            .set_categories_audited(
                "apikey:active",
                SetCategoryMode::Add,
                &["watch-test".into()],
                AuditCtx::admin(AuditOp::SetCategory),
            )
            .unwrap();
        // Leave time for a watcher to run between commits. Without its 250 ms
        // coalescing window, it would publish the intermediate category-only view.
        tokio::time::sleep(Duration::from_millis(75)).await;
        rig.store
            .set_plan_audited(
                "apikey:active",
                Some("pro"),
                AuditCtx::admin(AuditOp::SetPlan),
            )
            .unwrap();
        let changed = rig.notice(1, 11, 2).await;
        assert_ne!(initial["view"], changed["view"]);
        let listing =
            scoped_route_request(&rig.surface, &rig.admin, 1, OP_LIST_SCOPED, json!({})).await;
        assert_eq!(changed["view"], listing["result"]["view"]);
        rig.quiet().await;
    }

    #[tokio::test]
    async fn watch_scoped_only_visible_caller_is_notified() {
        let mut rig = Rig::new();
        rig.grant("first", "apikey:active");
        rig.grant("second", "apikey:dead");
        rig.bind(1, reserved("first"));
        rig.bind(2, reserved("second"));
        rig.open(1, 11, json!({})).await;
        let first = rig.notice(1, 11, 1).await;
        rig.open(2, 22, json!({})).await;
        let second = rig.notice(2, 22, 1).await;
        assert_ne!(first["view"], second["view"]);
        assert_eq!(first["epoch"], second["epoch"]);
        rig.store.invalidate("apikey:active").unwrap();
        rig.notice(1, 11, 2).await;
        rig.quiet().await;
    }

    #[tokio::test]
    async fn watch_scoped_refusal_matches_list_bytes() {
        let mut rig = Rig::new();
        rig.bind(1, subc_protocol::Principal::Direct);
        for params in [json!({}), json!({"enrollment_token":"invalid"})] {
            rig.dispatch(1, 10, FrameType::Request, OP_LIST_SCOPED, params.clone())
                .await;
            let listing = rig.next().await;
            assert_eq!(listing.header.ty, FrameType::Response);
            assert_scoped_not_found(&serde_json::from_slice(&listing.body).unwrap());
            rig.open(1, 11, params).await;
            let refusal = rig.next().await;
            assert_eq!(refusal.header.ty, FrameType::Response);
            assert_eq!(refusal.body, listing.body);
        }
    }

    #[tokio::test]
    async fn an_enrollment_token_never_inherits_a_replacement_enrollments_grants() {
        for method in [OP_GET_SCOPED, OP_LIST_SCOPED, OP_WATCH_SCOPED] {
            let mut rig = Rig::new();
            let secret = "a1".repeat(32);
            let hash = credentials_core::enrollment::enrollment_secret_hash(&secret).unwrap();
            let request = rig.store.propose_enrollment("watcher", &hash).unwrap();
            rig.store.approve_enrollment(&request.request_id, "watcher", "test").unwrap();
            let credentials_core::enrollment::EnrollmentPoll::Approved { token, .. } =
                rig.store.poll_enrollment(&request.request_id, &secret).unwrap() else { panic!("approved") };
            let replacement = "b2".repeat(32);
            let replacement_hash = credentials_core::enrollment::enrollment_secret_hash(&replacement).unwrap();
            let db = rig.db_path.clone();
            rig.surface.set_incarnation_hook("before-enrollment-admission", move || {
                let writer = rusqlite::Connection::open(db).unwrap();
                let tx = writer.unchecked_transaction().unwrap();
                tx.execute("UPDATE enrolled_consumers SET revoked_at_ms=1 WHERE name='watcher'", []).unwrap();
                tx.execute(
                    "INSERT INTO enrolled_consumers (enrollment_id,name,token_hash,approved_at_ms,approved_by) \
                     VALUES ('replacement','watcher',?1,2,'test')", [&replacement_hash],
                ).unwrap();
                tx.execute(
                    "INSERT INTO read_grants (principal_kind,principal_id,selector_kind,selector,operation,created_at_ms) \
                     VALUES ('enrolled','watcher','exact','apikey:active','read',2)", [],
                ).unwrap();
                tx.commit().unwrap();
            });
            rig.bind(1, reserved("ambient"));
            rig.grant("ambient", "apikey:active");
            let params = if method == OP_GET_SCOPED {
                json!({"enrollment_token":token, "credential_id":"apikey:active"})
            } else {
                json!({"enrollment_token":token})
            };
            rig.dispatch(1, 11, FrameType::Request, method, params).await;
            let reply = rig.next().await;
            assert_eq!(reply.header.ty, FrameType::Response, "{method}");
            let body: serde_json::Value = serde_json::from_slice(&reply.body).unwrap();
            assert_eq!(body["result"]["error"]["code"], "not_found", "{method}");

            let valid = scoped_route_request(&rig.surface, &rig.admin, 1, OP_LIST_SCOPED,
                json!({"enrollment_token":replacement})).await;
            assert_eq!(valid["result"]["credentials"][0]["id"], "apikey:active");
        }
    }

    #[tokio::test]
    async fn watch_scoped_enrollment_revocation_ends_with_refusal_response() {
        let mut rig = Rig::new();
        let secret = "a1".repeat(32);
        let hash = credentials_core::enrollment::enrollment_secret_hash(&secret).unwrap();
        let request = rig.store.propose_enrollment("watcher", &hash).unwrap();
        rig.store
            .approve_enrollment(&request.request_id, "watcher", "test")
            .unwrap();
        let credentials_core::enrollment::EnrollmentPoll::Approved { token, .. } = rig
            .store
            .poll_enrollment(&request.request_id, &secret)
            .unwrap()
        else {
            panic!("approved");
        };
        rig.store
            .create_read_grant_audited(
                "enrolled",
                "watcher",
                SelectorKind::Exact,
                "apikey:active",
                GrantOperation::List,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .unwrap();
        // The ambient principal is valid but has different grants. Token precedence
        // must remain in force both at open and after the enrollment is revoked.
        rig.bind(1, reserved("ambient"));
        rig.grant("ambient", "apikey:dead");
        let params = json!({"enrollment_token":token});
        rig.open(1, 11, params.clone()).await;
        let initial = rig.notice(1, 11, 1).await;
        let listing =
            scoped_route_request(&rig.surface, &rig.admin, 1, OP_LIST_SCOPED, params.clone()).await;
        assert_eq!(initial["view"], listing["result"]["view"]);
        rig.store.revoke_enrollment("watcher", "test").unwrap();
        let refusal = rig.next().await;
        assert_eq!(refusal.header.ty, FrameType::Response);
        assert_eq!(refusal.header.corr, 11);
        rig.dispatch(1, 12, FrameType::Request, OP_LIST_SCOPED, params)
            .await;
        assert_eq!(refusal.body, rig.next().await.body);
        assert_scoped_not_found(&serde_json::from_slice(&refusal.body).unwrap());
        rig.quiet().await;
    }

    #[tokio::test]
    async fn github_app_companion_is_not_found_through_grants_and_old_handles() {
        use credentials_core::store::StoreOpError;

        const ID: &str = "opaque:github-app-webhook:protected";
        let mut rig = Rig::new();
        rig.store.put_legacy_github_app_companion_for_tests(
            ID,
            &VaultRecord::new_static(CredentialKind::Opaque, "test", b"hidden".to_vec(), None),
        ).unwrap();
        rig.store.set_categories_audited(
            ID, SetCategoryMode::Add, &["watch-test".into()], AuditCtx::admin(AuditOp::SetCategory),
        ).unwrap();
        for operation in [GrantOperation::Read, GrantOperation::List, GrantOperation::Sign] {
            for selector_kind in [SelectorKind::Exact, SelectorKind::Category] {
                assert!(matches!(rig.store.create_read_grant_audited(
                    "reserved", "app-reader", selector_kind, ID, operation,
                    AuditCtx::admin(AuditOp::GrantCreate),
                ), Err(StoreOpError::NotFound)));
            }
            rig.store.create_read_grant_audited(
                "reserved", "app-reader", SelectorKind::Category, "watch-test", operation,
                AuditCtx::admin(AuditOp::GrantCreate),
            ).unwrap();
        }
        let handle = credentials_core::store::mint_handle().unwrap();
        {
            let conn = rusqlite::Connection::open(&rig.db_path).unwrap();
            conn.execute(
                "INSERT INTO handles (handle_hash, credential_id, created_at_ms, revoked) VALUES (?1, ?2, 0, 0)",
                rusqlite::params![handle.hash, ID],
            ).unwrap();
        }
        rig.bind(1, reserved("app-reader"));
        for (method, params) in [
            (OP_GET_SCOPED, json!({"credential_id":ID})),
            (OP_GET, json!({"handle":handle.raw})),
            (OP_SIGN, json!({"credential_id":ID,"payload_b64":"eA=="})),
            (OP_SIGN, json!({"handle":handle.raw,"payload_b64":"eA=="})),
        ] {
            rig.dispatch(1, 61, FrameType::Request, method, params).await;
            let frame = rig.next().await;
            assert_scoped_not_found(&serde_json::from_slice(&frame.body).unwrap());
        }
        rig.dispatch(1, 62, FrameType::Request, OP_LIST_SCOPED, json!({})).await;
        let listing: serde_json::Value = serde_json::from_slice(&rig.next().await.body).unwrap();
        assert_eq!(listing["result"]["credentials"], json!([]));
        assert!(!rig.store.list_meta().unwrap().iter().any(|(id, _)| id == ID));
        assert!(!credentials_core::store::list_meta_read_only(&rig.db_path).unwrap().iter().any(|(id, _)| id == ID));
    }

    #[tokio::test]
    async fn watch_scoped_initial_is_immediate_and_matches_list() {
        let mut rig = Rig::new();
        rig.grant("watcher", "apikey:active");
        rig.bind(1, reserved("watcher"));
        let listing =
            scoped_route_request(&rig.surface, &rig.admin, 1, OP_LIST_SCOPED, json!({})).await;
        rig.open(1, 11, json!({})).await;
        let initial = tokio::time::timeout(Duration::from_millis(200), rig.notice(1, 11, 1))
            .await
            .expect("initial notice must not wait for the coalescing window");
        assert_eq!(initial["view"], listing["result"]["view"]);
        rig.dispatch(1, 11, FrameType::Cancel, "", json!({})).await;
        rig.store.invalidate("apikey:active").unwrap();
        rig.open(1, 12, json!({})).await;
        let reopened = rig.notice(1, 12, 1).await;
        assert_ne!(initial["view"], reopened["view"]);
        assert_eq!(initial["epoch"], reopened["epoch"]);
    }

    #[tokio::test]
    async fn watch_scoped_cap_cancel_and_route_close() {
        let mut rig = Rig::new();
        for channel in 1..=65 {
            rig.bind(channel, reserved("watcher"));
            rig.open(channel, u64::from(channel), json!({})).await;
            if channel <= 64 {
                rig.notice(channel, u64::from(channel), 1).await;
            }
        }
        let refusal = rig.next().await;
        assert_eq!(refusal.header.ty, FrameType::Response);
        assert_scoped_not_found(&serde_json::from_slice(&refusal.body).unwrap());
        assert_eq!(refusal.header.channel, 65);
        rig.dispatch(1, 999, FrameType::Cancel, "", json!({})).await;
        rig.open(65, 65, json!({})).await;
        assert_scoped_not_found(&serde_json::from_slice(&rig.next().await.body).unwrap());
        rig.dispatch(1, 1, FrameType::Cancel, "", json!({})).await;
        rig.open(65, 65, json!({})).await;
        rig.notice(65, 65, 1).await;
        rig.dispatch(2, 0, FrameType::Goodbye, "", json!({})).await;
        rig.bind(66, reserved("watcher"));
        rig.open(66, 66, json!({})).await;
        rig.notice(66, 66, 1).await;
    }

    #[tokio::test]
    async fn watch_scoped_replacement_ends_old_and_grant_loss_keeps_new_open() {
        let mut rig = Rig::new();
        rig.grant("watcher", "apikey:active");
        rig.bind(1, reserved("watcher"));
        rig.open(1, 11, json!({})).await;
        let initial = rig.notice(1, 11, 1).await;
        rig.open(1, 12, json!({})).await;
        let mut frames = [rig.next().await, rig.next().await];
        frames.sort_by_key(|frame| frame.header.corr);
        assert_eq!(frames[0].header.corr, 11);
        assert_eq!(frames[0].header.ty, FrameType::StreamEnd);
        assert_eq!(frames[1].header.corr, 12);
        assert_eq!(frames[1].header.ty, FrameType::StreamData);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&frames[1].body).unwrap()["seq"],
            1
        );
        rig.store
            .revoke_read_grant_audited(
                "reserved",
                "watcher",
                SelectorKind::Exact,
                "apikey:active",
                GrantOperation::List,
                AuditCtx::admin(AuditOp::GrantRevoke),
            )
            .unwrap();
        let empty = rig.notice(1, 12, 2).await;
        assert_ne!(empty["view"], initial["view"]);
        let listing =
            scoped_route_request(&rig.surface, &rig.admin, 1, OP_LIST_SCOPED, json!({})).await;
        assert_eq!(listing["result"]["credentials"], json!([]));
        assert_eq!(empty["view"], listing["result"]["view"]);
        rig.quiet().await;
    }
}
