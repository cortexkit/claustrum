#[path = "../federation/support.rs"]
mod federation_fixture_support;

mod federation_read_fixture {
    use super::federation_fixture_support as support;
    use super::*;
    use credentials_core::federation::NewRemoteRecord;
    use credentials_core::record::RecordIdentity;

    fn fixture() -> serde_json::Value {
        serde_json::from_str(include_str!("federation_wire_contract.json")).unwrap()
    }

    #[tokio::test]
    async fn remote_client_fixtures_match_the_read_surface_producer() {
        use claustrum_module_probe::federation::{HomeAnswer, HomeVault};
        use credentials_core::federation::{
            MemberGrantOperation, MemberGrantSelector, VAULT_TRANSFER_ID,
        };
        use support::{HomeStore, Reply, Responder, TwoVaults};
        let root = support::temp_root("remote-client-wire-producer");
        let vaults = TwoVaults::new(&root).await;
        let a = HomeStore::open(&vaults.a.data_dir);
        let b = HomeStore::open(&vaults.b.data_dir);
        let home = vaults.home_member();
        let requester = vaults.requester_member();
        for (store, scalar, member) in [(&a.store, 1, home), (&b.store, 2, requester)] {
            let pem = credentials_core::kem::pem_from_scalar(&[scalar; 32]);
            let public = credentials_core::kem::public_half(&pem).unwrap().0;
            let hex: String = public.iter().map(|byte| format!("{byte:02x}")).collect();
            vaults.callosum.announce_peer_key(member, &hex);
            vaults.callosum.set_pairing(member, Some("fixture-pair"));
            store
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
                .unwrap();
            store
                .set_federation_self_member_audited(
                    member,
                    AuditCtx::admin(AuditOp::FederationSelfSet),
                )
                .unwrap();
        }
        let home_vault = Arc::new(HomeVault::new(Arc::clone(&a.engine)));
        assert!(home_vault.attach_outbound(vaults.a.outbound.clone()));
        for method in [
            crate::federation::ingress::OP_REMOTE_TOKEN,
            crate::federation::ingress::OP_REPORT_AUTH_FAILURE,
        ] {
            let home_vault = Arc::clone(&home_vault);
            let requester = requester.to_string();
            vaults.callosum.answer(
                support::TARGET_MODULE,
                method,
                Reply::Handler(Responder(Arc::new(move |params| {
                    let home_vault = Arc::clone(&home_vault);
                    let requester = requester.clone();
                    Box::pin(async move {
                        match home_vault.serve(&requester, method, &params).await {
                            HomeAnswer::Reply(body) => Reply::Ok(body),
                            HomeAnswer::InvalidParams(detail) => {
                                panic!("unexpected invalid_params: {detail}")
                            }
                        }
                    })
                }))),
            );
        }
        let surface = Arc::new(
            ReadSurface::new(Arc::clone(&b.engine), FetchLimiter::new(Caps::default()))
                .with_refresh_adapter_names(["anthropic".to_string(), "antigravity".to_string()]),
        );
        assert!(surface
            .remote()
            .attach_outbound(crate::federation::OutboundClient::for_daemon(
                vaults.b.connection_file.clone(),
                "claustrum",
                Some("harness-launch-nonce")
            )));
        let key = MasterKey::from_bytes([42; MASTER_KEY_LEN]);
        let admin = Arc::new(admin_surface::AdminSurface::new(
            Arc::clone(&b.engine),
            credentials_core::admin_auth::AdminMacKey::derive(&key),
            credentials_core::vault_id_for(&vaults.b.data_dir).unwrap(),
            key.key_id(),
        ));
        let routes = Arc::new(RouteEpochs::default());
        bind_reserved_route(&surface, &admin, &routes, 100, 1, "broca", "").await;
        let mut cases = Vec::new();
        for adapter in ["anthropic", "antigravity"] {
            let id = format!("oauth:{adapter}:fixture");
            let identity = RecordIdentity {
                account_id: Some(format!("fixture-{adapter}-account")),
                email: Some("fixture@example.invalid".into()),
                org_name: Some("Fixture Team".into()),
            };
            let access = format!("fixture-{adapter}-access-not-a-secret");
            let mut record = VaultRecord::new_oauth(
                "operator",
                adapter,
                OAuthCredential {
                    access_token: access.clone().into(),
                    refresh_token: "fixture-refresh|fixture-project|fixture-managed-project"
                        .to_string()
                        .into(),
                    expires_at_ms: None,
                    token_url: "https://fixture.invalid/token".into(),
                    client_id: None,
                    client_secret: None,
                    scopes: vec![],
                },
                access.into_bytes(),
            );
            record.identity = identity.clone();
            a.store.create(&id, &record).unwrap();
            a.store
                .set_categories_audited(
                    &id,
                    credentials_core::store::SetCategoryMode::Set,
                    &["llm-provider".into()],
                    AuditCtx::admin(AuditOp::SetCategory),
                )
                .unwrap();
            a.store
                .create_member_grant_audited(
                    requester,
                    MemberGrantOperation::RemoteRead,
                    &MemberGrantSelector::Exact(id.clone()),
                    "fixture-pair",
                )
                .unwrap();
            b.store
                .remote_add_audited(&NewRemoteRecord {
                    credential_id: id.clone(),
                    home_member: home.into(),
                    refresh_adapter: Some(adapter.into()),
                    detected_plan: None,
                    identity,
                    home_version: 1,
                    categories: vec!["llm-provider".into()],
                })
                .unwrap();
            b.store
                .create_read_grant_audited(
                    "reserved",
                    "broca",
                    SelectorKind::Exact,
                    &id,
                    GrantOperation::Read,
                    AuditCtx::admin(AuditOp::GrantCreate),
                )
                .unwrap();
            let get = routed_json(
                &surface,
                &admin,
                100,
                OP_GET_SCOPED,
                json!({"credential_id": id}),
            )
            .await;
            let status = routed_json(
                &surface,
                &admin,
                100,
                OP_STATUS,
                json!({"credential_id": id}),
            )
            .await;
            cases.push(json!({"adapter": adapter, "get": get, "status": status}));
        }
        let inventory = routed_json(&surface, &admin, 100, OP_LIST_SCOPED, json!({})).await;
        let requests: Vec<_> = vaults
            .callosum
            .ledger()
            .into_iter()
            .filter_map(|entry| match entry {
                support::Ledger::Request { method, params, .. }
                    if method == crate::federation::ingress::OP_REMOTE_TOKEN =>
                {
                    Some(params)
                }
                _ => None,
            })
            .collect();
        assert_eq!(requests.len(), 2);
        for (mut params, expected) in requests
            .into_iter()
            .zip(fixture()["home"]["cases"].as_array().unwrap())
        {
            let aad = params["aad"].as_str().unwrap();
            let parsed: serde_json::Value = serde_json::from_str(aad).unwrap();
            let nonce = parsed["nonce"].as_str().unwrap();
            assert_eq!(nonce.len(), 32);
            assert!(nonce
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
            // Replace only randomness in the actual transmitted bytes: rebuilding JSON
            // here would hide an accidental change to the authenticated field order.
            params["aad"] = json!(aad.replace(nonce, "00112233445566778899aabbccddeeff"));
            assert_eq!(
                params, expected["request"]["params"],
                "requester aad byte or params drift"
            );
        }
        let report = routed_json(&surface, &admin, 100, OP_REPORT_AUTH_FAILURE,
            json!({"credential_id": "oauth:anthropic:fixture", "record_version": 1, "provider_status": 401})).await;
        assert_eq!(report["result"]["accepted"], true);
        vaults.callosum.announce_peer_key(home, "");
        let refusal = routed_json(
            &surface,
            &admin,
            100,
            OP_GET_SCOPED,
            json!({"credential_id": "oauth:anthropic:fixture"}),
        )
        .await;
        let actual = json!({"cases": cases, "inventory": inventory, "refusal": refusal});
        println!("CLIENT_FIXTURE={actual}");
        assert_eq!(
            actual,
            fixture()["clients"],
            "read surface producer wire drift"
        );
    }

    #[tokio::test]
    async fn a_forced_open_grant_cannot_open_a_real_federation_token_reply() {
        use base64::Engine as _;
        use credentials_core::federation::VAULT_TRANSFER_ID;
        let (surface, store, db, _root) = tmp_surface_with_store(212);
        let pem = credentials_core::kem::pem_from_scalar(&[2; 32]);
        store
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
            .unwrap();
        let conn = rusqlite::Connection::open(db).unwrap();
        conn.execute("INSERT INTO read_grants (principal_kind,principal_id,selector_kind,selector,operation,created_at_ms) VALUES ('reserved','broca','exact',?1,'open',1)", [VAULT_TRANSFER_ID]).unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM read_grants WHERE selector=?1 AND operation='open'",
                [VAULT_TRANSFER_ID],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            1
        );
        let fixture = fixture();
        let sealed = &fixture["sealed_sample"]["result"];
        let aad = fixture["home"]["cases"][0]["request"]["params"]["aad"]
            .as_str()
            .unwrap();
        let b64 = base64::engine::general_purpose::STANDARD;
        let enc = b64.decode(sealed["enc"].as_str().unwrap()).unwrap();
        let ciphertext = b64.decode(sealed["ciphertext"].as_str().unwrap()).unwrap();
        let sender = credentials_core::kem::pem_from_scalar(&[1; 32]);
        let public = credentials_core::kem::public_half(&sender).unwrap().0;
        assert!(
            credentials_core::kem::open_auth(
                &credentials_core::kem::pem_from_scalar(&[2; 32]),
                &public,
                &enc,
                &ciphertext,
                crate::federation::ingress::REMOTE_TOKEN_INFO,
                aad.as_bytes()
            )
            .is_ok(),
            "the input must be a real, openable Auth-mode token reply"
        );
        let params: read_surface::OpenParams = serde_json::from_value(json!({
            "credential_id": VAULT_TRANSFER_ID, "enc_b64": sealed["enc"], "ciphertext_b64": sealed["ciphertext"],
            "info_b64": b64.encode(crate::federation::ingress::REMOTE_TOKEN_INFO), "aad_b64": b64.encode(aad),
        })).unwrap();
        let principal = subc_protocol::Principal::Reserved {
            module_id: "broca".into(),
        };
        let result = surface.open(1, Some(&principal), &params).await;
        assert!(
            matches!(result, Err(read_surface::ReadError::NotFound)),
            "the transfer-key fence must refuse before attempting an open: {result:?}"
        );
    }
}
