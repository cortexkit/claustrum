fn regression_frame(channel: u16, epoch: u32, method: &str, params: serde_json::Value) -> Frame {
    Frame::build_with_version(
        subc_protocol::PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        channel,
        epoch,
        1,
        serde_json::to_vec(&json!({"method": method, "params": params})).unwrap(),
    )
    .unwrap()
}

async fn regression_reply(
    surface: &Arc<ReadSurface>,
    admin: &Arc<admin_surface::AdminSurface>,
    frame: Frame,
    principal: Option<subc_protocol::Principal>,
) -> Frame {
    let (tx, mut rx) = mpsc::channel(1);
    handle_read_request(frame, &tx, surface, admin, principal)
        .await
        .unwrap();
    rx.recv().await.unwrap()
}

#[tokio::test]
async fn status_store_failures_are_transient_on_handle_resolution_and_metadata() {
    let (surface, store, db, _root) = tmp_surface_with_store(204);
    let conn = rusqlite::Connection::open(db).unwrap();
    let (admin, _admin_store, _admin_root) = tmp_admin(204);
    let handle = credentials_core::store::mint_handle().unwrap();
    store
        .put_handle_hash(
            &handle.hash,
            "apikey:active",
            AuditCtx::admin(AuditOp::MintHandle),
        )
        .unwrap();
    conn.execute_batch("ALTER TABLE handles RENAME TO unavailable_handles")
        .unwrap();
    let failed = surface
        .status(
            1,
            None,
            &read_surface::StatusParams {
                handle: Some(handle.raw.clone()),
                credential_id: None,
                enrollment_token: None,
            },
        )
        .await;
    assert_eq!(
        failed.last_error_code,
        Some(read_surface::ReadError::RefreshFailed)
    );
    assert_eq!(
        failed.last_error_code.unwrap().class(),
        read_surface::ErrorClass::Transient
    );
    assert!(failed.credential_id.is_none());
    let reply = regression_reply(
        &surface,
        &admin,
        regression_frame(1, 0, OP_STATUS, json!({"handle": handle.raw})),
        None,
    )
    .await;
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&reply.body).unwrap()["result"]
            ["last_error_code"],
        "refresh_failed"
    );
    conn.execute_batch("ALTER TABLE unavailable_handles RENAME TO handles; ALTER TABLE credentials RENAME TO unavailable_credentials").unwrap();
    let failed = surface
        .status(
            1,
            None,
            &read_surface::StatusParams {
                handle: Some(handle.raw),
                credential_id: None,
                enrollment_token: None,
            },
        )
        .await;
    assert_eq!(
        failed.last_error_code,
        Some(read_surface::ReadError::RefreshFailed)
    );
    assert_eq!(
        failed.last_error_code.unwrap().class(),
        read_surface::ErrorClass::Transient
    );
    assert_eq!(failed.credential_id.as_deref(), Some("apikey:active"));
}

#[tokio::test]
async fn unknown_and_revoked_status_handles_have_identical_reply_bytes() {
    let (surface, store, _db, _root) = tmp_surface_with_store(205);
    let (admin, _admin_store, _admin_root) = tmp_admin(205);
    let handle = credentials_core::store::mint_handle().unwrap();
    store
        .put_handle_hash(
            &handle.hash,
            "apikey:active",
            AuditCtx::admin(AuditOp::MintHandle),
        )
        .unwrap();
    store
        .revoke_handle(&handle.raw, AuditCtx::admin(AuditOp::RevokeHandle))
        .unwrap();
    let unknown = regression_reply(
        &surface,
        &admin,
        regression_frame(1, 0, OP_STATUS, json!({"handle":"unknown"})),
        None,
    )
    .await;
    let revoked = regression_reply(
        &surface,
        &admin,
        regression_frame(1, 0, OP_STATUS, json!({"handle":handle.raw})),
        None,
    )
    .await;
    assert_eq!(unknown.body, revoked.body);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&unknown.body).unwrap()["result"]
            ["last_error_code"],
        "not_found"
    );
}

#[tokio::test]
async fn malformed_sign_base64_is_a_permanent_encoding_error() {
    let (surface, store, _db, _root) = tmp_surface_with_store(206);
    let (admin, _admin_store, _admin_root) = tmp_admin(206);
    store
        .create(
            "signing:encoding",
            &VaultRecord::new_static(
                CredentialKind::SigningKey,
                "test",
                test_ed25519_pem().into_bytes(),
                None,
            ),
        )
        .unwrap();
    let handle = credentials_core::store::mint_handle().unwrap();
    store
        .put_handle_hash(
            &handle.hash,
            "signing:encoding",
            AuditCtx::admin(AuditOp::MintHandle),
        )
        .unwrap();
    let reply = regression_reply(
        &surface,
        &admin,
        regression_frame(
            1,
            0,
            OP_SIGN,
            json!({"handle":handle.raw,"payload_b64":"!!!"}),
        ),
        None,
    )
    .await;
    assert_eq!(reply.header.ty, FrameType::Response);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&reply.body).unwrap(),
        json!({"result":{"error":{"code":"malformed_encoding","class":"permanent"}}})
    );
}

#[tokio::test]
async fn malformed_control_requests_do_not_stop_dispatch_or_goodbye() {
    let (surface, _surface_root) = tmp_surface(207);
    let (admin, _store, _root) = tmp_admin(207);
    let routes = Arc::new(RouteEpochs::default());
    let (control, mut replies) = mpsc::channel(8);
    let (route, _route_rx) = mpsc::channel(8);
    let egress = Egress { control, route };
    for body in [b"{".to_vec(), br#"{"type":"future.control"}"#.to_vec()] {
        let frame = Frame::build_with_version(
            subc_protocol::PROTOCOL_VERSION,
            FrameType::Request,
            control_flags(),
            0,
            0,
            1,
            body,
        )
        .unwrap();
        assert!(handle_frame(frame, &egress, &surface, &admin, &routes)
            .await
            .unwrap());
        assert!(replies.try_recv().is_err());
    }
    let health = Frame::build_with_version(
        subc_protocol::PROTOCOL_VERSION,
        FrameType::Request,
        control_flags(),
        0,
        0,
        2,
        serde_json::to_vec(&ModuleControlRequest::HealthCheck {}).unwrap(),
    )
    .unwrap();
    assert!(handle_frame(health, &egress, &surface, &admin, &routes)
        .await
        .unwrap());
    assert_eq!(replies.recv().await.unwrap().header.ty, FrameType::Response);
    let goodbye = Frame::build_with_version(
        subc_protocol::PROTOCOL_VERSION,
        FrameType::Goodbye,
        control_flags(),
        0,
        0,
        3,
        Vec::new(),
    )
    .unwrap();
    assert!(!handle_frame(goodbye, &egress, &surface, &admin, &routes)
        .await
        .unwrap());
}

#[test]
fn health_liveness_uses_no_wall_clock() {
    let source = include_str!("../../src/read_surface.rs");
    let health_methods = source
        .split("pub fn health_snapshot")
        .nth(1)
        .unwrap()
        .split("fn compute_health")
        .next()
        .unwrap();
    assert!(
        !health_methods.contains("now_ms()"),
        "refresher liveness must not read wall time"
    );
    assert!(
        health_methods.contains(".elapsed()"),
        "the monotonic timestamp must be checked live"
    );
}

#[tokio::test]
async fn shutdown_bounds_writer_wait_with_an_inflight_sender() {
    let (control, control_rx) = mpsc::channel(1);
    let (route, route_rx) = mpsc::channel(1);
    let writer = tokio::spawn(drain_writer(tokio::io::sink(), control_rx, route_rx));
    drop(control);
    // Keeping `route` open models a request still waiting on a provider when the loop exits.
    let result = tokio::time::timeout(std::time::Duration::from_secs(3), finish_writer(writer))
        .await
        .expect("shutdown must not wait for an in-flight route sender");
    result.unwrap().unwrap();
    assert!(route.is_closed());
}

#[test]
fn epoch_drop_history_is_pruned_on_install_and_remove() {
    let routes = RouteEpochs::default();
    assert!(routes.note_drop(4, 1));
    assert!(!routes.note_drop(4, 1));
    assert!(routes.note_drop(5, 1));
    routes.install(4, 2);
    assert_eq!(routes.1.lock().unwrap().len(), 1);
    assert!(routes.note_drop(4, 1));
    routes.remove(4);
    assert_eq!(routes.1.lock().unwrap().len(), 1);
    assert!(routes.note_drop(4, 1));
}

#[tokio::test]
async fn concurrent_open_probes_cannot_overshoot_the_refusal_threshold() {
    let (surface, _surface_root) = tmp_surface(208);
    let mut requests = Vec::new();
    for _ in 0..32 {
        let surface = Arc::clone(&surface);
        requests.push(tokio::spawn(async move {
            surface
                .open(
                    88,
                    None,
                    &read_surface::OpenParams {
                        credential_id: "kem:unknown".into(),
                        enrollment_token: None,
                        enc_b64: String::new(),
                        ciphertext_b64: String::new(),
                        info_b64: String::new(),
                        aad_b64: String::new(),
                    },
                )
                .await
                .err()
                .unwrap()
        }));
    }
    let mut not_found = 0;
    let mut limited = 0;
    for request in requests {
        match request.await.unwrap() {
            read_surface::ReadError::NotFound => not_found += 1,
            read_surface::ReadError::OpenRateLimited => limited += 1,
            other => panic!("unexpected refusal: {other:?}"),
        }
    }
    assert_eq!((not_found, limited), (16, 16));
}

#[test]
fn relative_sqlite_filenames_use_the_current_directory() {
    let descriptor = StorageDescriptor {
        module_id: "claustrum".into(),
        storage_namespace: "default".into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: "store.db".into(),
        },
    };
    assert_eq!(sqlite_data_dir(&descriptor).unwrap(), PathBuf::from("."));
}

#[test]
fn manifest_advertises_both_operator_entrypoints() {
    let m = manifest("claustrum", None);
    let ProviderRole::ManagementSurface { operations, .. } = &m.provides[0] else {
        panic!("management surface required")
    };
    for name in [OP_ADMIN_CHALLENGE, OP_ADMIN_OP] {
        let op = operations
            .iter()
            .find(|op| op.name == name)
            .expect("operator entrypoint must be discoverable");
        assert_eq!(op.kind, ManagementOperationKind::Mutate);
    }
}

#[tokio::test]
async fn admin_route_uses_the_principal_captured_for_the_request() {
    let (surface, _surface_root) = tmp_surface(209);
    let (admin, _store, _root) = tmp_admin(209);
    admin.record_bind_at(5, 1, subc_protocol::Principal::Direct);
    let denied = regression_reply(
        &surface,
        &admin,
        regression_frame(5, 1, OP_ADMIN_CHALLENGE, json!({})),
        Some(subc_protocol::Principal::Unverified),
    )
    .await;
    assert_eq!(denied.header.ty, FrameType::Error);
    let allowed = regression_reply(
        &surface,
        &admin,
        regression_frame(5, 1, OP_ADMIN_CHALLENGE, json!({})),
        Some(subc_protocol::Principal::Direct),
    )
    .await;
    assert_eq!(allowed.header.ty, FrameType::Response);
}

#[tokio::test]
async fn rebind_resets_counters_and_late_old_epoch_requests_are_isolated() {
    assert_rebind_counter_isolation(false).await;
}

#[tokio::test]
async fn goodbye_racing_a_late_request_cannot_contaminate_the_next_epoch() {
    assert_rebind_counter_isolation(true).await;
}

async fn assert_rebind_counter_isolation(goodbye: bool) {
    let (surface, store, _db, _root) = tmp_surface_with_store(210);
    let (admin, _admin_store, _admin_root) = tmp_admin(210);
    let routes = Arc::new(RouteEpochs::default());
    let (control, mut control_rx) = mpsc::channel(8);
    let (route, _route_rx) = mpsc::channel(8);
    let egress = Egress { control, route };
    let params = json!({"credential_id":"kem:unknown", "enc_b64":"", "ciphertext_b64":"", "info_b64":"", "aad_b64":""});
    for _ in 0..16 {
        regression_reply(
            &surface,
            &admin,
            regression_frame(7, 1, OP_OPEN, params.clone()),
            None,
        )
        .await;
    }
    for index in 0..17 {
        regression_reply(
            &surface,
            &admin,
            regression_frame(7, 1, OP_STATUS, json!({"handle":format!("probe-{index}")})),
            None,
        )
        .await;
    }
    if goodbye {
        routes.install(7, 1);
        let goodbye = Frame::build_with_version(
            subc_protocol::PROTOCOL_VERSION,
            FrameType::Goodbye,
            control_flags(),
            7,
            1,
            1,
            Vec::new(),
        )
        .unwrap();
        handle_frame(goodbye, &egress, &surface, &admin, &routes)
            .await
            .unwrap();
    }
    let bind = Frame::build_with_version(subc_protocol::PROTOCOL_VERSION, FrameType::Request, control_flags(), 0, 0, 1,
        serde_json::to_vec(&json!({"op":"route.bind", "route_channel":7, "epoch":2, "target":{"kind":"management_surface","module_id":"claustrum"}, "identity":{"project_root":".","harness":"test","session":"test"}, "principal":subc_protocol::Principal::Direct})).unwrap()).unwrap();
    handle_frame(bind, &egress, &surface, &admin, &routes)
        .await
        .unwrap();
    control_rx.recv().await.unwrap();
    // An old spawned task may recreate its state after Goodbye or the bind reset.
    let late = regression_reply(
        &surface,
        &admin,
        regression_frame(7, 1, OP_OPEN, params.clone()),
        None,
    )
    .await;
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&late.body).unwrap()["result"]["error"]["code"],
        "not_found"
    );
    for _ in 0..15 {
        regression_reply(
            &surface,
            &admin,
            regression_frame(7, 1, OP_OPEN, params.clone()),
            None,
        )
        .await;
    }
    let fresh = regression_reply(
        &surface,
        &admin,
        regression_frame(7, 2, OP_OPEN, params),
        None,
    )
    .await;
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&fresh.body).unwrap()["result"]["error"]
            ["code"],
        "not_found"
    );
    for index in 0..17 {
        regression_reply(
            &surface,
            &admin,
            regression_frame(
                7,
                2,
                OP_STATUS,
                json!({"handle":format!("new-probe-{index}")}),
            ),
            None,
        )
        .await;
    }
    assert_eq!(
        store
            .read_audit(None)
            .unwrap()
            .iter()
            .filter(|entry| entry.op == "fetch_anomaly")
            .count(),
        2
    );
}
