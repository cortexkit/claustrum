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
        surface.report_auth_failure(77, None, &params).await,
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
    assert_not_found(surface.get_scoped(Some(&principal), &params).await);
    // An exact-id grant deliberately survives removal; only the pending read is stale.
    assert!(matches!(
        surface.get_scoped(Some(&principal), &params).await,
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
            .report_auth_failure(77, Some(&principal), &params)
            .await,
        Err(read_surface::ReadError::NotFound)
    );
    assert_eq!(
        store.meta(ID).unwrap().state,
        credentials_core::store::RecordState::Active
    );
}
