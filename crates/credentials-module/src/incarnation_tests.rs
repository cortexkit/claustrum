use super::*;

fn recreate_on(
    surface: &ReadSurface,
    store: &Arc<EncryptedStore>,
    point: &'static str,
    id: &'static str,
    record: VaultRecord,
) {
    let writer = Arc::clone(store);
    surface.set_incarnation_hook(point, move || {
        writer
            .remove_audited(id, AuditCtx::admin(AuditOp::Remove))
            .unwrap();
        writer
            .create_audited(id, &record, AuditCtx::admin(AuditOp::Put))
            .unwrap();
        assert_eq!(writer.get(id).unwrap().record_version, 1);
    });
}

fn dummy_record() -> VaultRecord {
    VaultRecord::new_static(
        CredentialKind::ApiKey,
        "operator",
        b"replacement".to_vec(),
        None,
    )
}

fn handle_for(store: &EncryptedStore, id: &str) -> String {
    let handle = credentials_core::store::mint_handle().unwrap();
    store
        .put_handle_hash(&handle.hash, id, AuditCtx::admin(AuditOp::MintHandle))
        .unwrap();
    handle.raw
}

fn assert_not_found(answer: read_surface::GetOutcome) {
    let read_surface::GetOutcome::Err { error } = answer else {
        panic!("a pending request served a recreated credential");
    };
    assert_eq!(error.code, read_surface::ReadError::NotFound);
}

#[tokio::test]
async fn open_resolution_does_not_hold_another_connections_refusal_counter() {
    use std::future::{poll_fn, Future};
    use std::task::Poll;

    let (surface, _admin, _store) = scoped_rig(188);
    let caller = federation::ingress::ScopedCaller::hand_only(None);
    let params = read_surface::OpenParams {
        credential_id: "kem:missing".into(),
        enc_b64: String::new(),
        ciphertext_b64: String::new(),
        info_b64: String::new(),
        aad_b64: String::new(),
        enrollment_token: None,
    };
    let mut resolving = std::pin::pin!(surface.open(1, &caller, &params));
    let mut same_connection = std::pin::pin!(surface.open(1, &caller, &params));
    let mut other_connection = std::pin::pin!(surface.open(2, &caller, &params));
    poll_fn(|cx| {
        // In tests, open yields with its counter locked before resolving the key.
        assert!(resolving.as_mut().poll(cx).is_pending());
        assert!(same_connection.as_mut().poll(cx).is_pending());
        assert!(same_connection.as_mut().poll(cx).is_pending());
        assert!(other_connection.as_mut().poll(cx).is_pending());
        assert!(matches!(
            other_connection.as_mut().poll(cx),
            Poll::Ready(Err(read_surface::ReadError::NotFound))
        ), "a held refusal counter blocked another connection");
        Poll::Ready(())
    }).await;
}

#[tokio::test]
async fn closed_route_cannot_grow_counters_when_its_requests_resume() {
    let (surface, _admin, _store) = scoped_rig(188);
    let connection = route_connection_id(7, 1);
    let routes = Arc::new(RouteEpochs::default());
    routes.install(7, 1);
    surface.set_live_routes(routes.clone());
    let fetch = read_surface::GetParams { handle: "missing".into(), min_ttl_ms: None, force_refresh: false };
    let caller = federation::ingress::ScopedCaller::hand_only(Some(reserved("late")));
    let open = read_surface::OpenParams {
        credential_id: "kem:missing".into(), enc_b64: String::new(), ciphertext_b64: String::new(),
        info_b64: String::new(), aad_b64: String::new(), enrollment_token: None,
    };
    let pending_fetch = surface.get(connection, &fetch);
    let pending_open = surface.open(connection, &caller, &open);
    routes.remove(7);
    surface.drop_connection(connection).await;
    assert_not_found(pending_fetch.await);
    assert_eq!(pending_open.await.err(), Some(read_surface::ReadError::NotFound));
    assert_eq!(surface.route_counter_presence(connection).await, (false, false));
    routes.install(7, 2);
    let new_connection = route_connection_id(7, 2);
    assert_not_found(surface.get(new_connection, &fetch).await);
    assert_eq!(surface.open(new_connection, &caller, &open).await.err(), Some(read_surface::ReadError::NotFound));
    assert_eq!(surface.route_counter_presence(new_connection).await, (true, true));
}

#[tokio::test]
async fn status_refuses_recreated_record_for_old_handle_and_category() {
    const ID: &str = "apikey:status:lifetime";
    for by_handle in [true, false] {
        let (surface, _admin, store) = scoped_rig(188);
        store.create(ID, &dummy_record()).unwrap();
        store.set_categories_audited(ID, credentials_core::store::SetCategoryMode::Set,
            &["status-lifetime".into()], AuditCtx::admin(AuditOp::SetCategory)).unwrap();
        store.create_read_grant_audited("reserved", "status-reader", SelectorKind::Category,
            "status-lifetime", GrantOperation::Read, AuditCtx::admin(AuditOp::GrantCreate)).unwrap();
        let caller = federation::ingress::ScopedCaller::hand_only(Some(reserved("status-reader")));
        let params = read_surface::StatusParams {
            handle: by_handle.then(|| handle_for(&store, ID)),
            credential_id: (!by_handle).then(|| ID.into()),
            enrollment_token: None,
        };
        assert!(surface.status(77, &caller, &params).await.ready);
        recreate_on(&surface, &store, "status-admitted", ID, dummy_record());
        let status = surface.status(77, &caller, &params).await;
        assert_eq!(status.last_error_code, Some(read_surface::ReadError::NotFound), "by_handle={by_handle}");
        assert!(!status.ready);
        assert_eq!(status.credential_id, None);
        assert_eq!(status.record_version, None);
        assert_eq!(status.stale_pending, None);
    }
}

#[tokio::test]
async fn incarnation_open_refuses_recreated_key_outside_authorized_category() {
    use base64::Engine as _;
    let (surface, _admin, store) = scoped_rig(188);
    const ID: &str = "kem:open:lifetime";
    let original = credentials_core::kem::generate_key().unwrap();
    let replacement = credentials_core::kem::generate_key().unwrap();
    let (public, _) = credentials_core::kem::public_half(&replacement).unwrap();
    store
        .create(
            ID,
            &VaultRecord::new_static(CredentialKind::KemKey, "test", original.into_bytes(), None),
        )
        .unwrap();
    store
        .set_categories_audited(
            ID,
            credentials_core::store::SetCategoryMode::Set,
            &["key-lifetime".into()],
            AuditCtx::admin(AuditOp::SetCategory),
        )
        .unwrap();
    store
        .create_read_grant_audited(
            "reserved",
            "entorhinal",
            SelectorKind::Category,
            "key-lifetime",
            GrantOperation::Open,
            AuditCtx::admin(AuditOp::GrantCreate),
        )
        .unwrap();
    let principal = reserved("entorhinal");
    let (enc, ciphertext) =
        credentials_core::kem::seal_base(&public, b"replacement plaintext", b"info", b"aad")
            .unwrap();
    assert_eq!(
        credentials_core::kem::open_base(&replacement, &enc, &ciphertext, b"info", b"aad").unwrap(),
        b"replacement plaintext"
    );
    let encode = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
    let params = read_surface::OpenParams {
        credential_id: ID.into(),
        enc_b64: encode(&enc),
        ciphertext_b64: encode(&ciphertext),
        info_b64: encode(b"info"),
        aad_b64: encode(b"aad"),
        enrollment_token: None,
    };
    recreate_on(
        &surface,
        &store,
        "admitted",
        ID,
        VaultRecord::new_static(
            CredentialKind::KemKey,
            "test",
            replacement.into_bytes(),
            None,
        ),
    );
    assert_eq!(
        surface
            .open(
                77,
                &crate::federation::ingress::ScopedCaller::hand_only((Some(&principal)).cloned()),
                &params
            )
            .await
            .err(),
        Some(read_surface::ReadError::NotFound)
    );
    assert!(store.meta(ID).unwrap().categories.is_empty());
    assert_eq!(
        surface
            .open(
                77,
                &crate::federation::ingress::ScopedCaller::hand_only((Some(&principal)).cloned()),
                &params
            )
            .await
            .err(),
        Some(read_surface::ReadError::NotFound)
    );
}

#[tokio::test]
async fn incarnation_public_key_handle_refuses_recreated_key_after_resolution() {
    let (surface, store, _db, _root) = tmp_surface_with_store(20);
    const ID: &str = "signing:lifetime:1";
    store
        .create(
            ID,
            &VaultRecord::new_static(
                CredentialKind::SigningKey,
                "test",
                test_ed25519_pem().into_bytes(),
                None,
            ),
        )
        .unwrap();
    let params = read_surface::PublicKeyParams {
        handle: Some(handle_for(&store, ID)),
        credential_id: None,
        enrollment_token: None,
    };
    let original = surface
        .public_key(
            77,
            &crate::federation::ingress::ScopedCaller::hand_only(None),
            &params,
        )
        .await
        .unwrap();
    let pem = test_ed25519_pem();
    let replacement = credentials_core::signing::public_key_ed25519(&pem).unwrap();
    assert_ne!(original.key_id, replacement.key_id);
    recreate_on(
        &surface,
        &store,
        "admitted",
        ID,
        VaultRecord::new_static(CredentialKind::SigningKey, "test", pem.into_bytes(), None),
    );
    assert_eq!(
        surface
            .public_key(
                77,
                &crate::federation::ingress::ScopedCaller::hand_only(None),
                &params
            )
            .await
            .err(),
        Some(read_surface::ReadError::NotFound)
    );
    assert_eq!(
        surface
            .public_key(
                77,
                &crate::federation::ingress::ScopedCaller::hand_only(None),
                &params
            )
            .await
            .err(),
        Some(read_surface::ReadError::NotFound)
    );
    assert_eq!(
        credentials_core::signing::public_key_ed25519(
            std::str::from_utf8(store.get(ID).unwrap().payload.expose()).unwrap()
        )
        .unwrap()
        .key_id,
        replacement.key_id
    );
}

#[tokio::test]
async fn incarnation_handle_get_refuses_recreated_id_after_resolution() {
    let (surface, store, _db, _root) = tmp_surface_with_store(20);
    const ID: &str = "apikey:openrouter";
    store.create(ID, &dummy_record()).unwrap();
    let handle = handle_for(&store, ID);
    recreate_on(&surface, &store, "admitted", ID, dummy_record());
    let params = read_surface::GetParams {
        handle,
        min_ttl_ms: None,
        force_refresh: false,
    };
    assert_not_found(surface.get(77, &params).await);
    assert_not_found(surface.get(77, &params).await);
    assert_eq!(store.get(ID).unwrap().payload.expose(), b"replacement");
}

#[tokio::test]
async fn incarnation_static_report_does_not_mutate_recreated_version_one() {
    report_does_not_mutate_recreated_version_one("apikey:openrouter").await;
}

#[tokio::test]
async fn incarnation_refreshable_report_does_not_mutate_recreated_version_one() {
    report_does_not_mutate_recreated_version_one("oauth:anthropic").await;
}

async fn report_does_not_mutate_recreated_version_one(id: &'static str) {
    let (surface, store, _db, _root) = tmp_surface_with_store(20);
    store.create(id, &dummy_record()).unwrap();
    let handle = handle_for(&store, id);
    recreate_on(&surface, &store, "admitted", id, dummy_record());
    let params = serde_json::from_value(json!({
        "handle": handle, "record_version": 1, "provider_status": 401
    }))
    .unwrap();
    assert_eq!(
        surface
            .report_auth_failure(
                77,
                &crate::federation::ingress::ScopedCaller::hand_only(None),
                &params
            )
            .await,
        Err(read_surface::ReadError::NotFound)
    );
    assert_eq!(
        store.meta(id).unwrap().state,
        credentials_core::store::RecordState::Active
    );
    assert!(!store.meta(id).unwrap().stale_pending);
    assert!(store
        .read_audit(None)
        .unwrap()
        .iter()
        .all(|row| row.op != "report_auth_failure"));
}

#[tokio::test]
async fn incarnation_empty_read_does_not_quarantine_recreated_version_one() {
    let (surface, store, _db, _root) = tmp_surface_with_store(20);
    const ID: &str = "oauth:legacy-empty";
    let mut empty = dummy_record();
    empty.kind = CredentialKind::Oauth;
    empty.payload = Vec::new().into();
    store.create(ID, &empty).unwrap();
    let handle = handle_for(&store, ID);
    recreate_on(&surface, &store, "quarantine", ID, dummy_record());
    assert_not_found(
        surface
            .get(
                77,
                &read_surface::GetParams {
                    handle,
                    min_ttl_ms: None,
                    force_refresh: false,
                },
            )
            .await,
    );
    assert_eq!(
        store.meta(ID).unwrap().state,
        credentials_core::store::RecordState::Active
    );
}

#[tokio::test]
async fn incarnation_signature_refuses_recreation_before_audit() {
    let (surface, admin, store) = signature_audit_rig(true);
    const ID: &str = "signing:publish:1";
    let replacement = store.get(ID).unwrap();
    recreate_on(&surface, &store, "sign_audit", ID, replacement);
    let reply = scoped_route_request(
        &surface,
        &admin,
        188,
        OP_SIGN,
        json!({
            "credential_id": ID, "payload_b64": "cGF5bG9hZA=="
        }),
    )
    .await;
    assert_eq!(
        reply["result"],
        json!({"error": {"code": "not_found", "class": "permanent"}})
    );
    assert!(store
        .read_audit(None)
        .unwrap()
        .iter()
        .all(|row| row.op != "sign"));
    store.verify_audit_chain().unwrap();
}

#[tokio::test]
async fn incarnation_seal_refuses_recreation_before_audit() {
    let (surface, admin, store, recipient, _, _) = seal_rig();
    let writer = Arc::clone(&store);
    let replacement = store.get("kem:push").unwrap();
    surface.run_before_next_seal_audit_for_test(Box::new(move || {
        writer
            .remove_audited("kem:push", AuditCtx::admin(AuditOp::Remove))
            .unwrap();
        writer
            .create_audited("kem:push", &replacement, AuditCtx::admin(AuditOp::Put))
            .unwrap();
    }));
    let reply = scoped_route_request(
        &surface,
        &admin,
        193,
        OP_SEAL,
        seal_params("kem:push", &recipient_public(&recipient), b"push"),
    )
    .await;
    assert_eq!(
        reply["result"],
        json!({"error": {"code": "not_found", "class": "permanent"}})
    );
    assert!(seal_rows(&store).is_empty());
    assert_eq!(store.get("kem:push").unwrap().record_version, 1);
    store.verify_audit_chain().unwrap();
}

#[tokio::test]
async fn incarnation_scoped_get_refuses_recreated_id_after_authorization() {
    let (surface, _admin, store) = scoped_rig(188);
    const ID: &str = "apikey:openrouter";
    store.create(ID, &dummy_record()).unwrap();
    store
        .create_read_grant_audited(
            "reserved",
            "entorhinal",
            SelectorKind::Exact,
            ID,
            GrantOperation::Read,
            AuditCtx::admin(AuditOp::GrantCreate),
        )
        .unwrap();
    let principal = reserved("entorhinal");
    recreate_on(&surface, &store, "admitted", ID, dummy_record());
    let params = serde_json::from_value(json!({"credential_id": ID})).unwrap();
    assert_not_found(
        surface
            .get_scoped(
                &crate::federation::ingress::ScopedCaller::hand_only((Some(&principal)).cloned()),
                &params,
            )
            .await,
    );
    // An exact-id grant deliberately survives removal; only the pending read is stale.
    assert!(matches!(
        surface
            .get_scoped(
                &crate::federation::ingress::ScopedCaller::hand_only((Some(&principal)).cloned()),
                &params
            )
            .await,
        read_surface::GetOutcome::Ok(_)
    ));
}

#[tokio::test]
async fn incarnation_scoped_report_refuses_recreation_after_authorization() {
    let (surface, _admin, store) = scoped_rig(188);
    const ID: &str = "apikey:openrouter";
    store.create(ID, &dummy_record()).unwrap();
    store
        .create_read_grant_audited(
            "reserved",
            "entorhinal",
            SelectorKind::Exact,
            ID,
            GrantOperation::Read,
            AuditCtx::admin(AuditOp::GrantCreate),
        )
        .unwrap();
    let principal = reserved("entorhinal");
    recreate_on(&surface, &store, "admitted", ID, dummy_record());
    let params = serde_json::from_value(json!({
        "credential_id": ID, "record_version": 1, "provider_status": 401
    }))
    .unwrap();
    assert_eq!(
        surface
            .report_auth_failure(
                77,
                &crate::federation::ingress::ScopedCaller::hand_only((Some(&principal)).cloned()),
                &params
            )
            .await,
        Err(read_surface::ReadError::NotFound)
    );
    assert_eq!(
        store.meta(ID).unwrap().state,
        credentials_core::store::RecordState::Active
    );
}
