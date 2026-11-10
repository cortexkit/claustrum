mod home_watch_routes {
    use super::*;
    use tokio::sync::Notify;

    type Rig = (
        Arc<ReadSurface>,
        Arc<admin_surface::AdminSurface>,
        Arc<RouteEpochs>,
        Egress,
    );

    fn hold_checks(home: &federation::HomeVault) -> (Arc<Notify>, Arc<Notify>) {
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let (started, released) = (entered.clone(), release.clone());
        let gate: federation::ingress::IssueAuditGate = Arc::new(move || {
            let (started, released) = (started.clone(), released.clone());
            Box::pin(async move {
                started.notify_one();
                released.notified().await;
            })
        });
        assert!(home.remote_watches.before_checks.set(gate).is_ok());
        (entered, release)
    }

    async fn lifecycle(rig: &Rig, ty: FrameType, channel: u16, corr: u64) {
        let (surface, admin, routes, egress) = rig;
        let request = Frame::build_with_version(
            PROTOCOL_VERSION,
            ty,
            Flags::new(false, Priority::Interactive, false),
            channel,
            if channel == 0 { 0 } else { 1 },
            corr,
            if ty == FrameType::Request {
                serde_json::to_vec(
                    &json!({"method":federation::ingress::OP_REMOTE_WATCH,"params":{}}),
                )
                .unwrap()
            } else if ty == FrameType::Push {
                serde_json::to_vec(&subc_protocol::session::ModuleControlCommand::Draining {
                    reason: subc_protocol::RouteCloseReason::Reload,
                    deadline_ms: 1000,
                })
                .unwrap()
            } else {
                Vec::new()
            },
        )
        .unwrap();
        handle_frame(request, egress, surface, admin, routes)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn remote_watch_pending_cancel_and_route_goodbye_send_nothing() {
        for ty in [FrameType::Cancel, FrameType::Goodbye] {
            let (surface, admin, store, routes) = granted_scoped_rig(216, "callosum");
            set_member_mapping(&store, true);
            bind_reserved_route(
                &surface,
                &admin,
                &routes,
                119,
                1,
                "callosum",
                MEMBER_HARNESS,
            )
            .await;
            let (control, _control) = mpsc::channel(8);
            let (route, mut rx) = mpsc::channel(8);
            let rig = (surface, admin, routes, Egress { control, route });
            let (entered, release) = hold_checks(rig.1.home());
            lifecycle(&rig, FrameType::Request, 119, 41).await;
            // This assertion runs before the spawned open can be polled.
            assert_eq!(rig.1.home().remote_watches.entry_count(), 1);
            entered.notified().await;
            lifecycle(&rig, ty, 119, 41).await;
            assert_eq!(rig.1.home().remote_watches.entry_count(), 0);
            release.notify_one();
            rig.1.home().remote_watches.completed.notified().await;
            assert_eq!(rig.1.home().remote_watches.entry_count(), 0);
            assert!(matches!(
                rx.try_recv(),
                Err(mpsc::error::TryRecvError::Empty)
            ));
        }
    }

    #[tokio::test]
    async fn remote_watch_pending_drain_and_goodbye_are_transient() {
        for ty in [FrameType::Push, FrameType::Goodbye] {
            let (surface, admin, store, routes) = granted_scoped_rig(217, "callosum");
            set_member_mapping(&store, true);
            bind_reserved_route(
                &surface,
                &admin,
                &routes,
                120,
                1,
                "callosum",
                MEMBER_HARNESS,
            )
            .await;
            let (control, _control) = mpsc::channel(8);
            let (route, mut rx) = mpsc::channel(8);
            let rig = (surface, admin, routes, Egress { control, route });
            let (entered, release) = hold_checks(rig.1.home());
            lifecycle(&rig, FrameType::Request, 120, 42).await;
            entered.notified().await;
            lifecycle(&rig, ty, 0, 0).await;
            release.notify_one();
            rig.1.home().remote_watches.completed.notified().await;
            let answer = rx.try_recv().expect("draining open refusal");
            assert_eq!(answer.header.ty, FrameType::Error);
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&answer.body).unwrap(),
                json!({"code":"home_unavailable","message":"home unavailable","detail":{"class":"transient"}})
            );
            assert_eq!(rig.1.home().remote_watches.entry_count(), 0);
            if ty == FrameType::Push {
                lifecycle(&rig, FrameType::Request, 120, 43).await;
                rig.1.home().remote_watches.completed.notified().await;
                let answer = rx.try_recv().expect("new open after drain");
                assert_eq!(body_code(&answer), "home_unavailable");
            }
        }
    }

    fn body_code(answer: &Frame) -> String {
        assert_eq!(answer.header.ty, FrameType::Error);
        serde_json::from_slice::<serde_json::Value>(&answer.body).unwrap()["code"]
            .as_str()
            .unwrap()
            .to_owned()
    }
}
