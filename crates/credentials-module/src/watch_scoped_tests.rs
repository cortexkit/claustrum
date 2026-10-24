mod scoped_watch {
    use super::*;
    use credentials_core::store::{SetCategoryMode, SetProvidersMode};
    use std::time::Duration;
    use subc_protocol::{AdmissionClass, FLAG_SUBSCRIPTION};

    struct Rig {
        surface: Arc<ReadSurface>,
        admin: Arc<admin_surface::AdminSurface>,
        store: Arc<EncryptedStore>,
        routes: Arc<RouteEpochs>,
        egress: Egress,
        rx: mpsc::Receiver<Frame>,
        _control: mpsc::Receiver<Frame>,
    }

    impl Rig {
        fn new() -> Self {
            let (surface, admin, store) = scoped_rig(149);
            let (control, control_rx) = mpsc::channel(8);
            let (route, rx) = mpsc::channel(256);
            Self {
                surface,
                admin,
                store,
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
            let mut frames = [
                rig.rx
                    .try_recv()
                    .expect("first STREAM_END queued before closing"),
                rig.rx
                    .try_recv()
                    .expect("second STREAM_END queued before closing"),
            ];
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
    async fn watch_scoped_metadata_changes_each_emit_once() {
        let mut rig = Rig::new();
        rig.bind(1, reserved("watcher"));
        rig.open(1, 11, json!({})).await;
        let mut previous = rig.notice(1, 11, 1).await;
        for (index, mutation) in ["grant", "category", "provider", "plan", "state"]
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
    async fn watch_scoped_token_refresh_is_quiet() {
        let mut rig = Rig::new();
        let record = roster_oauth_record();
        rig.store.create("oauth:watch-refresh", &record).unwrap();
        rig.grant("watcher", "oauth:watch-refresh");
        rig.bind(1, reserved("watcher"));
        rig.open(1, 11, json!({})).await;
        rig.notice(1, 11, 1).await;
        let mut refreshed = record.clone();
        refreshed.payload = b"fresh-token".to_vec().into();
        rig.store
            .commit_refresh("oauth:watch-refresh", 1, &refreshed)
            .unwrap();
        assert_eq!(
            rig.store
                .meta("oauth:watch-refresh")
                .unwrap()
                .record_version,
            2
        );
        rig.quiet().await;
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
