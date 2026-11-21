mod connectors_contract {
    use super::*;
    use credentials_core::{federation::NewRemoteRecord, record::RecordIdentity};
    use sha2::{Digest, Sha256};

    fn declaration(entries: serde_json::Value) -> serde_json::Value {
        use subc_protocol::peer::{CallerAttestation, CallerClaim, CallerOrigin};
        serde_json::to_value(
            CallerAttestation::new(
                "declared-test",
                1,
                1,
                CallerClaim::Own,
                true,
                CallerOrigin::Release,
                "approved",
            )
            .unwrap()
            .with_declaration(
                json!({"v":1,"grants":entries}).as_object().unwrap().clone(),
                "digest",
            ),
        )
        .unwrap()
    }

    async fn declared_bind(
        surface: &Arc<ReadSurface>,
        admin: &Arc<admin_surface::AdminSurface>,
        channel: u16,
        principal: Option<subc_protocol::Principal>,
        harness: &str,
        caller: Option<serde_json::Value>,
    ) {
        let request = ModuleControlRequest::RouteBind {
            route_channel: channel,
            epoch: 1,
            target: subc_protocol::RouteTarget::ToolProvider {
                module_id: "claustrum".into(),
            },
            identity: subc_protocol::BindIdentity::new(harness, "s"),
            principal,
            consumer_capabilities: None,
            role_versions: None,
            admission_facts: None,
            scope: None,
            call_mode: None,
        };
        let mut body = serde_json::to_value(request).unwrap();
        if let Some(caller) = caller {
            let peer = subc_protocol::peer::RouteBindPeer::new()
                .with_caller(Some(serde_json::from_value(caller).unwrap()));
            body.as_object_mut().unwrap().extend(
                serde_json::to_value(peer)
                    .unwrap()
                    .as_object()
                    .unwrap()
                    .clone(),
            );
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
        handle_control_request(
            frame,
            &tx,
            surface,
            admin,
            &Arc::new(RouteEpochs::default()),
        )
        .await
        .unwrap();
        assert_eq!(rx.recv().await.unwrap().header.ty, FrameType::Response);
    }

    fn declared_set(
        admin: &admin_surface::AdminSurface,
        channel: u16,
    ) -> Arc<credentials_core::store::DeclaredGrantSet> {
        match admin.route_caller(channel) {
            federation::RouteCaller::Principal(caller) => caller.declared,
            _ => Arc::new(credentials_core::store::DeclaredGrantSet::empty()),
        }
    }

    fn declaration_audits(store: &EncryptedStore) -> usize {
        store
            .read_audit(None)
            .unwrap()
            .iter()
            .filter(|row| row.op == "declaration_seen")
            .count()
    }

    #[tokio::test]
    async fn declared_admission_requires_every_attestation_and_route_condition() {
        let valid = declaration(json!([{"category":"llm-provider","operation":"read"}]));
        for condition in [
            "valid",
            "principal_absent",
            "direct",
            "unverified",
            "caller_absent",
            "first_party",
            "brokered",
            "relay",
            "legacy",
            "unknown_claim",
            "declaration_absent",
            "digest_absent",
            "digest_empty",
            "fed_gate_off",
            "member",
            "phone",
            "refused",
        ] {
            let (surface, admin, store, _db, _root) = rig(224);
            let mut principal = Some(reserved("striatum"));
            let mut caller = Some(valid.clone());
            let mut harness = "self";
            match condition {
                "principal_absent" => principal = None,
                "direct" => principal = Some(subc_protocol::Principal::Direct),
                "unverified" => principal = Some(subc_protocol::Principal::Unverified),
                "caller_absent" => caller = None,
                "first_party" => caller.as_mut().unwrap()["first_party"] = json!(false),
                "brokered" | "relay" | "legacy" => {
                    caller.as_mut().unwrap()["claim"] = json!(condition)
                }
                "unknown_claim" => caller.as_mut().unwrap()["claim"] = json!("new_claim"),
                "declaration_absent" => {
                    caller
                        .as_mut()
                        .unwrap()
                        .as_object_mut()
                        .unwrap()
                        .remove("declaration");
                }
                "digest_absent" => {
                    caller
                        .as_mut()
                        .unwrap()
                        .as_object_mut()
                        .unwrap()
                        .remove("declaration_digest");
                }
                "digest_empty" => caller.as_mut().unwrap()["declaration_digest"] = json!(""),
                "fed_gate_off" | "member" | "phone" | "refused" => {
                    principal = Some(reserved("callosum"));
                    harness = match condition {
                        "phone" => "fed-phone:22222222222222222222222222222222",
                        "refused" => "not-self",
                        _ => "fed-computer:22222222222222222222222222222222",
                    };
                    if condition != "fed_gate_off" {
                        store
                            .set_federation_member_mapping_audited(
                                true,
                                AuditCtx::admin(AuditOp::FederationGateSet),
                            )
                            .unwrap();
                        if condition == "phone" {
                            store
                                .set_secret_phone_mapping_audited(
                                    true,
                                    AuditCtx::admin(AuditOp::SecretPhoneGateSet),
                                )
                                .unwrap();
                        }
                    }
                }
                "valid" => {}
                _ => unreachable!(),
            }
            declared_bind(&surface, &admin, 77, principal, harness, caller).await;
            let accepted = condition == "valid";
            assert_eq!(
                declared_set(&admin, 77).grants().len(),
                usize::from(accepted),
                "{condition}"
            );
            assert_eq!(
                store.list_declared_grant_sets().unwrap().rows.len(),
                usize::from(accepted),
                "{condition}"
            );
            assert_eq!(
                declaration_audits(&store),
                usize::from(accepted),
                "{condition}"
            );
            assert!(store.list_read_grants().unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn declared_rebind_row_is_inventory_not_live_authority_and_origin_does_not_gate() {
        let (surface, admin, store, _db, _root) = rig(225);
        let valid = declaration(json!([{"category":"llm-provider","operation":"read"}]));
        for origin in ["release", "development", "other"] {
            let mut caller = valid.clone();
            caller["origin"] = json!(origin);
            declared_bind(
                &surface,
                &admin,
                77,
                Some(reserved("striatum")),
                "self",
                Some(caller),
            )
            .await;
            assert_eq!(declared_set(&admin, 77).grants().len(), 1);
        }
        let first = store.list_declared_grant_sets().unwrap().rows.remove(0);
        assert_eq!(first.origin.as_deref(), Some("release"));
        assert_eq!(declaration_audits(&store), 1);
        for key in ["declaration", "declaration_digest", "first_party"] {
            let mut caller = valid.clone();
            if key == "first_party" {
                caller[key] = json!(false);
            } else {
                caller.as_object_mut().unwrap().remove(key);
            }
            declared_bind(
                &surface,
                &admin,
                77,
                Some(reserved("striatum")),
                "self",
                Some(caller),
            )
            .await;
            assert!(declared_set(&admin, 77).grants().is_empty());
            assert_eq!(store.list_declared_grant_sets().unwrap().rows[0], first);
            assert_eq!(declaration_audits(&store), 1);
        }
        let mut absent = valid.clone();
        absent.as_object_mut().unwrap().remove("declaration");
        absent.as_object_mut().unwrap().remove("declaration_digest");
        for expected in [2, 2] {
            declared_bind(
                &surface,
                &admin,
                77,
                Some(reserved("striatum")),
                "self",
                Some(absent.clone()),
            )
            .await;
            assert!(declared_set(&admin, 77).grants().is_empty());
            assert_eq!(declaration_audits(&store), expected);
            assert!(store.list_declared_grant_sets().unwrap().rows[0]
                .grants
                .grants()
                .is_empty());
        }
    }

    #[tokio::test]
    async fn declared_row_read_and_write_failures_bind_without_declared_authority() {
        for fault in ["read", "write"] {
            let (surface, admin, store, db, _root) = rig(226);
            let conn = rusqlite::Connection::open(db).unwrap();
            if fault == "read" {
                conn.execute_batch("DROP TABLE declared_grant_sets")
                    .unwrap();
            } else {
                conn.execute_batch("CREATE TRIGGER refuse_declaration BEFORE INSERT ON declared_grant_sets BEGIN SELECT RAISE(ABORT, 'test write failure'); END").unwrap();
            }
            declared_bind(
                &surface,
                &admin,
                77,
                Some(reserved("striatum")),
                "self",
                Some(declaration(json!([
                    {"category":"llm-provider","operation":"read"}
                ]))),
            )
            .await;
            assert!(declared_set(&admin, 77).grants().is_empty(), "{fault}");
            assert_eq!(declaration_audits(&store), 0, "{fault}");
        }
    }

    fn declared_category(store: &EncryptedStore, id: &str) {
        store
            .set_categories_audited(
                id,
                credentials_core::store::SetCategoryMode::Set,
                &["llm-provider".into()],
                AuditCtx::admin(AuditOp::SetCategory),
            )
            .unwrap();
    }

    fn declared_hand_grant(
        store: &EncryptedStore,
        module: &str,
        kind: SelectorKind,
        selector: &str,
        operation: GrantOperation,
    ) {
        store
            .create_read_grant_audited(
                "reserved",
                module,
                kind,
                selector,
                operation,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .unwrap();
    }

    #[tokio::test]
    async fn declared_policy_token_is_skipped_and_hand_grant_operations_stay_independent() {
        let (surface, admin, store, _db, _root) = rig(233);
        let id = "github_app:sample";
        declared_bind(
            &surface,
            &admin,
            77,
            Some(reserved("aft")),
            "self",
            Some(declaration(json!([
                {"category":"github-app-native","operation":"read"},
                {"category":"github-app-native","operation":"policy_token"},
                {"category":"github-app-native","operation":"list"}
            ]))),
        )
        .await;
        let declared = declared_set(&admin, 77);
        assert_eq!(
            declared
                .grants()
                .iter()
                .map(|grant| (grant.selector.as_str(), grant.operation))
                .collect::<Vec<_>>(),
            [
                ("github-app-native", GrantOperation::List),
                ("github-app-native", GrantOperation::Read),
            ]
        );
        assert!(store.list_read_grants().unwrap().is_empty());
        let covers = |module, op, grants: &credentials_core::store::DeclaredGrantSet| {
            store
                .read_grant_covers("reserved", module, id, op, grants)
                .unwrap()
        };
        assert!(!covers("aft", GrantOperation::PolicyToken, &declared));

        declared_hand_grant(&store, "aft", SelectorKind::Exact, id, GrantOperation::Read);
        assert!(covers("aft", GrantOperation::Read, &declared));
        assert!(!covers("aft", GrantOperation::PolicyToken, &declared));

        declared_hand_grant(
            &store,
            "plexus",
            SelectorKind::Exact,
            id,
            GrantOperation::PolicyToken,
        );
        let empty = credentials_core::store::DeclaredGrantSet::empty();
        assert!(covers("plexus", GrantOperation::PolicyToken, &empty));
        assert!(!covers("plexus", GrantOperation::Read, &empty));
    }

    #[tokio::test]
    async fn declared_scoped_union_matches_hand_grants_in_local_remote_and_audience_paths() {
        let (surface, admin, store, _db, _root) = rig(227);
        store
            .create(
                "apikey:declared",
                &VaultRecord::new_static(
                    CredentialKind::ApiKey,
                    "test",
                    b"declared-value".to_vec(),
                    None,
                ),
            )
            .unwrap();
        declared_category(&store, "apikey:declared");
        store
            .remote_add_audited(&NewRemoteRecord {
                credential_id: "oauth:declared-copy".into(),
                home_member: "fed-computer:22222222222222222222222222222222".into(),
                refresh_adapter: Some("anthropic".into()),
                detected_plan: None,
                identity: RecordIdentity::default(),
                home_version: 1,
                categories: vec!["llm-provider".into()],
            })
            .unwrap();
        let audience = credentials_core::store::ACCOUNT_TOKEN_AUDIENCES[0];
        declared_bind(
            &surface,
            &admin,
            77,
            Some(reserved("striatum")),
            "self",
            Some(declaration(json!([
                {"category":"llm-provider","operation":"read"},
                {"category":"llm-provider","operation":"list"},
                {"audience":audience,"operation":"account_token"},
                {"audience":"not-an-account-audience","operation":"account_token"}
            ]))),
        )
        .await;
        assert_eq!(declared_set(&admin, 77).grants().len(), 3);
        declared_bind(
            &surface,
            &admin,
            78,
            Some(reserved("hand-reader")),
            "self",
            None,
        )
        .await;
        let empty = routed_json(&surface, &admin, 78, OP_LIST_SCOPED, json!({})).await;
        for op in [GrantOperation::Read, GrantOperation::List] {
            declared_hand_grant(
                &store,
                "hand-reader",
                SelectorKind::Category,
                "llm-provider",
                op,
            );
        }
        declared_hand_grant(
            &store,
            "hand-reader",
            SelectorKind::Audience,
            audience,
            GrantOperation::AccountToken,
        );
        for (op, params) in [
            (OP_GET_SCOPED, json!({"credential_id":"apikey:declared"})),
            (OP_STATUS, json!({"credential_id":"apikey:declared"})),
            (OP_STATUS, json!({"credential_id":"oauth:declared-copy"})),
            (OP_LIST_SCOPED, json!({})),
            (OP_ACCOUNT_TOKEN, json!({"audience":audience})),
            (
                OP_USAGE_REPORT_SCOPED,
                json!({"credential_id":"apikey:declared", "reading":{"observedAtMs":12,"provider":"claude","headers":{}}}),
            ),
            (
                OP_REPORT_AUTH_FAILURE,
                json!({"credential_id":"apikey:declared", "record_version":1, "provider_status":401}),
            ),
        ] {
            let declared = routed_json(&surface, &admin, 77, op, params.clone()).await;
            let hand = routed_json(&surface, &admin, 78, op, params).await;
            assert_eq!(declared, hand, "{op}");
            assert_ne!(
                declared["result"]["error"]["code"],
                json!("not_found"),
                "{op}"
            );
        }
        let list = routed_json(&surface, &admin, 77, OP_LIST_SCOPED, json!({})).await;
        assert_ne!(list["result"]["view"], empty["result"]["view"]);
        assert_eq!(
            list["result"]["grants"],
            list["result"]["grant_tuples"].as_array().unwrap().len()
        );
        let rows = list["result"]["credentials"].as_array().unwrap();
        assert!(
            rows.iter().any(|r| r["id"] == "oauth:declared-copy"),
            "remote projection must use the union"
        );
        assert!(rows.iter().any(|r| r["id"] == "apikey:declared"));
        assert!(!store
            .list_read_grants()
            .unwrap()
            .iter()
            .any(|g| g.principal_id == "striatum"));
    }

    #[tokio::test]
    async fn declared_deposit_matches_hand_and_duplicate_projection_and_transfer_fence_wins() {
        let (surface, admin, store, _db, _root) = rig(228);
        declared_bind(
            &surface,
            &admin,
            77,
            Some(reserved("striatum")),
            "self",
            None,
        )
        .await;
        deposit_cookie_grant(&store, "striatum", GrantOperation::Deposit);
        let hand = routed_json(&surface, &admin, 77, OP_LIST_SCOPED, json!({})).await;
        store
            .revoke_read_grant_audited(
                "reserved",
                "striatum",
                SelectorKind::Category,
                "browser-session",
                GrantOperation::Deposit,
                AuditCtx::admin(AuditOp::GrantRevoke),
            )
            .unwrap();
        declared_bind(
            &surface,
            &admin,
            77,
            Some(reserved("striatum")),
            "self",
            Some(declaration(json!([
                {"category":"browser-session","operation":"deposit"},
                {"category":"llm-provider","operation":"deposit"},
                {"exact":"apikey:declared","operation":"read"}
            ]))),
        )
        .await;
        assert_eq!(declared_set(&admin, 77).grants().len(), 1);
        assert_eq!(
            routed_json(&surface, &admin, 77, OP_LIST_SCOPED, json!({})).await,
            hand
        );
        let deposited = routed_json(
            &surface,
            &admin,
            77,
            OP_DEPOSIT_COOKIE,
            deposit_cookie_params(),
        )
        .await;
        assert!(deposited["result"]["error"].is_null(), "{deposited}");
        deposit_cookie_grant(&store, "striatum", GrantOperation::Deposit);
        assert_eq!(
            routed_json(&surface, &admin, 77, OP_LIST_SCOPED, json!({})).await,
            hand
        );
        let transfer = credentials_core::federation::VAULT_TRANSFER_ID;
        store
            .create(
                transfer,
                &VaultRecord::new_static(
                    CredentialKind::KemKey,
                    "test",
                    credentials_core::kem::generate_key().unwrap().into_bytes(),
                    None,
                ),
            )
            .unwrap();
        declared_category(&store, transfer);
        declared_bind(
            &surface,
            &admin,
            77,
            Some(reserved("striatum")),
            "self",
            Some(declaration(json!([
                {"category":"llm-provider","operation":"read"}
            ]))),
        )
        .await;
        let refused = routed_json(
            &surface,
            &admin,
            77,
            OP_PUBLIC_KEY,
            json!({"credential_id":transfer}),
        )
        .await;
        assert_eq!(refused["result"]["error"]["code"], "not_found");
        let list = routed_json(&surface, &admin, 77, OP_LIST_SCOPED, json!({})).await;
        assert!(!list["result"]["credentials"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["id"] == transfer));
    }

    #[tokio::test]
    async fn declared_read_does_not_authorize_sign_open_or_seal_but_hand_grants_do() {
        use base64::Engine as _;
        let (surface, admin, store, _db, _root) = rig(229);
        store
            .create(
                "signing:declared",
                &VaultRecord::new_static(
                    CredentialKind::SigningKey,
                    "test",
                    test_ed25519_pem().into_bytes(),
                    None,
                ),
            )
            .unwrap();
        let pem = credentials_core::kem::generate_key().unwrap();
        let public = credentials_core::kem::public_half(&pem).unwrap().0;
        store
            .create(
                "kem:declared",
                &VaultRecord::new_static(CredentialKind::KemKey, "test", pem.into_bytes(), None),
            )
            .unwrap();
        for id in ["signing:declared", "kem:declared"] {
            declared_category(&store, id);
        }
        declared_bind(
            &surface,
            &admin,
            77,
            Some(reserved("striatum")),
            "self",
            Some(declaration(json!([
                {"category":"llm-provider","operation":"read"},
                {"category":"llm-provider","operation":"list"},
                {"category":"llm-provider","operation":"sign"},
                {"category":"llm-provider","operation":"open"},
                {"category":"llm-provider","operation":"seal"}
            ]))),
        )
        .await;
        assert_eq!(declared_set(&admin, 77).grants().len(), 2);
        let (enc, ciphertext) =
            credentials_core::kem::seal_base(&public, b"plaintext", b"info", b"aad").unwrap();
        let encode = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
        let cases = [
            (
                OP_SIGN,
                json!({"credential_id":"signing:declared", "payload_b64":encode(b"payload")}),
                SelectorKind::Category,
                "llm-provider",
                GrantOperation::Sign,
            ),
            (
                OP_OPEN,
                json!({"credential_id":"kem:declared", "enc_b64":encode(&enc), "ciphertext_b64":encode(&ciphertext), "info_b64":encode(b"info"), "aad_b64":encode(b"aad")}),
                SelectorKind::Category,
                "llm-provider",
                GrantOperation::Open,
            ),
            (
                OP_SEAL,
                seal_params("kem:declared", &public, b"plaintext"),
                SelectorKind::Exact,
                "kem:declared",
                GrantOperation::Seal,
            ),
        ];
        let published = routed_json(
            &surface,
            &admin,
            77,
            OP_PUBLIC_KEY,
            json!({"credential_id":"signing:declared"}),
        )
        .await;
        assert!(published["result"]["public_key_hex"].is_string());
        for (op, params, kind, selector, grant_op) in cases {
            let refused = routed_json(&surface, &admin, 77, op, params.clone()).await;
            assert_eq!(refused["result"]["error"]["code"], "not_found", "{op}");
            declared_hand_grant(&store, "striatum", kind, selector, grant_op);
            let allowed = routed_json(&surface, &admin, 77, op, params).await;
            assert!(allowed["result"]["error"].is_null(), "{op}: {allowed}");
        }
    }

    fn declared_request(channel: u16, method: &str, params: serde_json::Value) -> Frame {
        Frame::build_with_version(
            PROTOCOL_VERSION,
            FrameType::Request,
            Flags::new(false, Priority::Interactive, false),
            channel,
            1,
            1,
            serde_json::to_vec(&json!({"method":method,"params":params})).unwrap(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn declared_dispatch_snapshots_the_set_before_same_principal_rebind_and_goodbye_drops_it()
    {
        let (surface, admin, store, _db, _root) = rig(230);
        store
            .create(
                "apikey:declared",
                &VaultRecord::new_static(
                    CredentialKind::ApiKey,
                    "test",
                    b"declared-value".to_vec(),
                    None,
                ),
            )
            .unwrap();
        declared_category(&store, "apikey:declared");
        let original = declaration(json!([{"category":"llm-provider","operation":"read"}]));
        declared_bind(
            &surface,
            &admin,
            77,
            Some(reserved("striatum")),
            "self",
            Some(original.clone()),
        )
        .await;
        let routes = Arc::new(RouteEpochs::default());
        routes.install(77, 1);
        let (control, _controls) = mpsc::channel(1);
        let (route, mut replies) = mpsc::channel(1);
        let egress = Egress { control, route };
        handle_frame(
            declared_request(
                77,
                OP_GET_SCOPED,
                json!({"credential_id":"apikey:declared"}),
            ),
            &egress,
            &surface,
            &admin,
            &routes,
        )
        .await
        .unwrap();
        let mut replacement = declaration(json!([]));
        replacement["declaration_digest"] = json!("replacement");
        declared_bind(
            &surface,
            &admin,
            77,
            Some(reserved("striatum")),
            "self",
            Some(replacement),
        )
        .await;
        assert!(declared_set(&admin, 77).grants().is_empty());
        let reply: serde_json::Value =
            serde_json::from_slice(&replies.recv().await.unwrap().body).unwrap();
        assert_eq!(
            reply["result"]["payload"],
            json!(b"declared-value"),
            "accepted frame lost its captured set: {reply}"
        );
        let refused = routed_json(
            &surface,
            &admin,
            77,
            OP_GET_SCOPED,
            json!({"credential_id":"apikey:declared"}),
        )
        .await;
        assert_eq!(refused["result"]["error"]["code"], "not_found");
        declared_bind(
            &surface,
            &admin,
            78,
            Some(reserved("striatum")),
            "self",
            Some(original),
        )
        .await;
        assert_eq!(declared_set(&admin, 78).grants().len(), 1);
        assert!(
            declared_set(&admin, 77).grants().is_empty(),
            "two live routes must not share authority"
        );
        let without = routed_json(&surface, &admin, 77, OP_LIST_SCOPED, json!({})).await;
        let with = routed_json(&surface, &admin, 78, OP_LIST_SCOPED, json!({})).await;
        assert_ne!(without["result"]["view"], with["result"]["view"]);
        routes.install(78, 1);
        let goodbye = Frame::build_with_version(
            PROTOCOL_VERSION,
            FrameType::Goodbye,
            Flags::new(false, Priority::Interactive, false),
            78,
            1,
            0,
            Vec::new(),
        )
        .unwrap();
        handle_frame(goodbye, &egress, &surface, &admin, &routes)
            .await
            .unwrap();
        assert!(declared_set(&admin, 78).grants().is_empty());
    }

    #[tokio::test]
    async fn declared_watch_captures_union_and_enrollment_tokens_never_see_it() {
        let (surface, admin, store, db, _root) = rig(231);
        for id in ["apikey:declared", "apikey:enrolled-only"] {
            store
                .create(
                    id,
                    &VaultRecord::new_static(
                        CredentialKind::ApiKey,
                        "test",
                        b"test-value".to_vec(),
                        None,
                    ),
                )
                .unwrap();
        }
        declared_bind(
            &surface,
            &admin,
            77,
            Some(reserved("striatum")),
            "self",
            Some(declaration(json!([
                {"category":"llm-provider","operation":"read"}
            ]))),
        )
        .await;
        let secret = "ad".repeat(32);
        let hash = credentials_core::enrollment::enrollment_secret_hash(&secret).unwrap();
        let proposed = store
            .propose_enrollment("declared-consumer", &hash)
            .unwrap();
        store
            .approve_enrollment(&proposed.request_id, "declared-consumer", "operator")
            .unwrap();
        let token = match store
            .poll_enrollment(&proposed.request_id, &secret)
            .unwrap()
        {
            credentials_core::enrollment::EnrollmentPoll::Approved { token, .. } => token,
            other => panic!("expected token: {other:?}"),
        };
        store
            .create_read_grant_audited(
                "enrolled",
                "declared-consumer",
                SelectorKind::Exact,
                "apikey:enrolled-only",
                GrantOperation::Read,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .unwrap();
        let (tx, mut rx) = mpsc::channel(8);
        dispatch_route_request(
            declared_request(77, OP_WATCH_SCOPED, json!({})),
            &tx,
            &surface,
            &admin,
            admin.route_caller(77),
            None,
        )
        .await
        .unwrap();
        let first: serde_json::Value =
            serde_json::from_slice(&rx.recv().await.unwrap().body).unwrap();
        let initial = routed_json(&surface, &admin, 77, OP_LIST_SCOPED, json!({})).await;
        assert_eq!(first["view"], initial["result"]["view"]);
        declared_category(&store, "apikey:declared");
        let changed: serde_json::Value =
            serde_json::from_slice(&rx.recv().await.unwrap().body).unwrap();
        assert_eq!(changed["seq"], 2);
        assert_ne!(changed["view"], first["view"]);
        surface.watches.close(77);
        let list = routed_json(
            &surface,
            &admin,
            77,
            OP_LIST_SCOPED,
            json!({"enrollment_token":token}),
        )
        .await;
        let rows = list["result"]["credentials"].as_array().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["id"], "apikey:enrolled-only");
        assert_eq!(list["result"]["grant_tuples"].as_array().unwrap().len(), 1);
        assert_eq!(list["result"]["grant_tuples"][0]["selector_kind"], "exact");
        for (id, allowed) in [("apikey:declared", false), ("apikey:enrolled-only", true)] {
            let result = routed_json(
                &surface,
                &admin,
                77,
                OP_GET_SCOPED,
                json!({"credential_id":id, "enrollment_token":token}),
            )
            .await;
            assert_eq!(
                result["result"]["payload"].is_array(),
                allowed,
                "{id}: {result}"
            );
        }
        let observed: String = rusqlite::Connection::open(&db).unwrap().query_row(
            "SELECT principal_kind || ':' || principal_id FROM auth_events WHERE credential_id='apikey:enrolled-only' AND kind='scoped_first_use' LIMIT 1", [], |row| row.get(0),
        ).unwrap();
        assert_eq!(observed, "enrolled:declared-consumer");
        let (tx, mut rx) = mpsc::channel(8);
        let mut completed = surface.watches.completed.subscribe();
        let caller = match admin.route_caller(77) {
            federation::RouteCaller::Principal(caller) => caller,
            _ => unreachable!(),
        };
        let token_params = read_surface::ListScopedParams {
            enrollment_token: Some(token.clone()),
        };
        assert_eq!(
            surface.watch_scoped(&caller, &token_params).unwrap().0,
            list["result"]["view"]
        );
        dispatch_route_request(
            declared_request(77, OP_WATCH_SCOPED, json!({"enrollment_token":token})),
            &tx,
            &surface,
            &admin,
            admin.route_caller(77),
            None,
        )
        .await
        .unwrap();
        let subscribed: serde_json::Value =
            serde_json::from_slice(&rx.recv().await.unwrap().body).unwrap();
        assert_eq!(subscribed["view"], list["result"]["view"]);
        completed.changed().await.unwrap();
        store
            .set_categories_audited(
                "apikey:declared",
                credentials_core::store::SetCategoryMode::Set,
                &[],
                AuditCtx::admin(AuditOp::SetCategory),
            )
            .unwrap();
        completed.changed().await.unwrap();
        assert!(
            rx.try_recv().is_err(),
            "token watch borrowed the bind declaration"
        );
        declared_category(&store, "apikey:enrolled-only");
        let changed: serde_json::Value =
            serde_json::from_slice(&rx.recv().await.unwrap().body).unwrap();
        assert_eq!(changed["seq"], 2);
        surface.watches.close(77);
        for op in [OP_GET_SCOPED, OP_LIST_SCOPED, OP_WATCH_SCOPED] {
            let params = if op == OP_GET_SCOPED {
                json!({"credential_id":"apikey:declared", "enrollment_token":"invalid"})
            } else {
                json!({"enrollment_token":"invalid"})
            };
            if op == OP_WATCH_SCOPED {
                let (tx, mut rx) = mpsc::channel(2);
                dispatch_route_request(
                    declared_request(77, op, params),
                    &tx,
                    &surface,
                    &admin,
                    admin.route_caller(77),
                    None,
                )
                .await
                .unwrap();
                let refused: serde_json::Value =
                    serde_json::from_slice(&rx.recv().await.unwrap().body).unwrap();
                assert_eq!(refused["result"]["error"]["code"], "not_found");
            } else {
                assert_eq!(
                    routed_json(&surface, &admin, 77, op, params).await["result"]["error"]["code"],
                    "not_found"
                );
            }
        }
        surface.watches.finish_all().await.unwrap();
    }

    #[test]
    fn declared_manifest_classifies_every_operation_and_addressing_form() {
        let manifest = manifest("claustrum", None);
        let ProviderRole::ManagementSurface { operations, .. } = &manifest.provides[0] else {
            panic!("management surface")
        };
        let mut scoped = Vec::new();
        for op in operations {
            let classification = match op.name.as_str() {
                OP_GET_SCOPED | OP_USAGE_REPORT_SCOPED => {
                    Some((GrantOperation::Read, "credential_id", true))
                }
                OP_PUBLIC_KEY | OP_STATUS | OP_REPORT_AUTH_FAILURE | OP_REPORT_CONDITION
                | OP_CLEAR_CONDITION => {
                    Some((GrantOperation::Read, "credential_id (not handle)", true))
                }
                OP_LIST_SCOPED | OP_WATCH_SCOPED => Some((GrantOperation::List, "inventory", true)),
                OP_DEPOSIT_COOKIE => {
                    Some((GrantOperation::Deposit, "category browser-session", true))
                }
                OP_ACCOUNT_TOKEN => Some((GrantOperation::AccountToken, "audience", true)),
                "credential.policy_token" | "policy.request_action" => {
                    Some((GrantOperation::PolicyToken, "exact identity (not handle)", false))
                }
                // An approval is authorized by the approving device's registered key on its
                // route, not by any grant, so it has no grant selector.
                "policy.approve_action" => None,
                OP_SIGN => Some((GrantOperation::Sign, "credential_id (not handle)", false)),
                OP_OPEN => Some((GrantOperation::Open, "credential_id", false)),
                OP_SEAL => Some((GrantOperation::Seal, "exact credential_id", false)),
                "secret.phone_keys_register"
                | "secret.deposit_keys"
                | "secret.deposit"
                | "secret.approve"
                | "manifest.approve"
                | "secret.list"
                | "secret.delete"
                | "secret.revoke_grant"
                | "secret.home"
                | "secret.use"
                | "secret.ssh_sign"
                | "manifest.propose_binding"
                | "manifest.latest"
                | "manifest.watch"
                | "manifest.report_active"
                | "manifest.active_status"
                | "policy.active"
                | "policy.watch"
                | "federation.manifest_latest"
                | "federation.manifest_watch"
                | "secret.request_flow_approval"
                | "secret.revoke_flow_grants"
                | "permissions.list"
                | "permissions.revoke"
                | "connectors.list"
                | "connectors.watch"
                | OP_ADMIN_CHALLENGE
                | OP_ADMIN_OP
                | OP_ENROLL_PROPOSE
                | OP_ENROLL_POLL
                | OP_ENROLL_ROTATE
                | OP_GET
                | OP_GET_MANY
                | federation::ingress::OP_REMOTE_TOKEN
                | federation::ingress::OP_REPORT_AUTH_FAILURE
                | federation::ingress::OP_REPORT_CONDITION
                | federation::ingress::OP_CLEAR_CONDITION
                | federation::ingress::OP_TRANSFER_DELIVER
                | federation::ingress::OP_SECRET_USE
                | federation::ingress::OP_SECRET_SSH_SIGN
                | federation::ingress::OP_SECRET_REQUEST_FLOW_APPROVAL
                | federation::ingress::OP_SECRET_REVOKE_FLOW_GRANTS => None,
                // Fleet admission uses the attested caller and method, not a grant selector.
                name if crate::fleet_ops::OPS.contains(&name) => None,
                // Owner-only: a module reaches its own space by its attested identity,
                // and no grant selector can reach another module's.
                name if crate::module_secret::is_op(name) => None,
                name => panic!("unclassified operation: {name}"),
            };
            if let Some(classification) = classification {
                scoped.push((op.name.as_str(), classification));
            }
        }
        assert_eq!(scoped.len(), 16);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn declared_bind_warns_once_per_digest_with_safe_indices_and_operation_reasons() {
        const CHILD: &str = "CK_DECLARATION_LOG_CAPTURE_CHILD";
        const TEST: &str = "tests::connectors_contract::declared_bind_warns_once_per_digest_with_safe_indices_and_operation_reasons";
        if std::env::var(CHILD).as_deref() != Ok("1") {
            // A child process gives the process-wide warning cache and tracing callsite a clean start.
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", TEST, "--nocapture", "--test-threads=1"])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed;"));
            return;
        }
        let (surface, admin, _store, _db, _root) = rig(232);
        let logs = Logs(Arc::default());
        let _subscriber = tracing::subscriber::set_default(logs.clone());
        let caller = declaration(json!([
            {"category":"llm-provider","operation":"read"},
            {"category":"llm-provider","operation":"sign"},
            {"category":"llm-provider","operation":"open"},
            {"category":"llm-provider","operation":"seal"},
            {"category":"llm-provider","operation":"read","only":"narrowing-canary"}
        ]));
        for _ in 0..2 {
            declared_bind(
                &surface,
                &admin,
                77,
                Some(reserved("declared-diagnostics")),
                "self",
                Some(caller.clone()),
            )
            .await;
        }
        assert_eq!(declared_set(&admin, 77).grants().len(), 1);
        let logs = logs.0.lock().unwrap();
        let warnings: Vec<_> = logs
            .iter()
            .filter(|line| line.contains("declaration entries skipped"))
            .collect();
        assert_eq!(warnings.len(), 1, "{logs:?}");
        let warning = warnings[0];
        assert!(warning.contains("declared-diagnostics") && warning.contains("digest"));
        for index in 1..=3 {
            assert!(
                warning.contains(&format!("index: {index}, reason: \"operation\"")),
                "{warning}"
            );
        }
        assert!(!warning.contains("narrowing-canary"));
    }

    #[tokio::test]
    async fn declared_read_and_list_are_independent_and_a_different_resolved_principal_gets_neither(
    ) {
        for operation in [GrantOperation::Read, GrantOperation::List] {
            let (surface, admin, store, _db, _root) = rig(233);
            store
                .create(
                    "apikey:declared",
                    &VaultRecord::new_static(
                        CredentialKind::ApiKey,
                        "test",
                        b"test-value".to_vec(),
                        None,
                    ),
                )
                .unwrap();
            declared_category(&store, "apikey:declared");
            declared_bind(
                &surface,
                &admin,
                77,
                Some(reserved("striatum")),
                "self",
                Some(declaration(json!([
                    {"category":"llm-provider","operation":operation.as_str()}
                ]))),
            )
            .await;
            declared_bind(
                &surface,
                &admin,
                78,
                Some(reserved("hand-reader")),
                "self",
                None,
            )
            .await;
            declared_hand_grant(
                &store,
                "hand-reader",
                SelectorKind::Category,
                "llm-provider",
                operation,
            );
            let list = routed_json(&surface, &admin, 77, OP_LIST_SCOPED, json!({})).await;
            assert_eq!(
                list,
                routed_json(&surface, &admin, 78, OP_LIST_SCOPED, json!({})).await
            );
            assert_eq!(
                list["result"]["credentials"][0]["operations"],
                json!([operation.as_str()])
            );
            let get = routed_json(
                &surface,
                &admin,
                77,
                OP_GET_SCOPED,
                json!({"credential_id":"apikey:declared"}),
            )
            .await;
            assert_eq!(
                get["result"]["payload"].is_array(),
                operation == GrantOperation::Read
            );
            let wrong = federation::ingress::ScopedCaller {
                principal: Some(reserved("another-module")),
                attestation: None,
                declared: declared_set(&admin, 77),
            };
            let params = read_surface::ListScopedParams {
                enrollment_token: None,
            };
            let wrong = surface.list_scoped(&wrong, &params).unwrap();
            assert!(wrong.credentials.is_empty() && wrong.grant_tuples.is_empty());
        }
    }

    type Rig = (
        Arc<ReadSurface>,
        Arc<admin_surface::AdminSurface>,
        Arc<EncryptedStore>,
        std::path::PathBuf,
        TestTempDir,
    );

    fn rig(seed: u8) -> Rig {
        rig_with_settings(seed, |_| {})
    }

    fn rig_with_settings(seed: u8, seed_settings: impl FnOnce(&std::path::Path)) -> Rig {
        let (surface, store, db, root) = tmp_surface_with_seeded_store(seed, seed_settings);
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
            (vec!["embedding-provider"], "ai_models"),
            (
                vec!["cloud-infrastructure", "web-search", "embedding-provider"],
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
        store.commit_refresh("oauth:gmail", 1, &store.credential_incarnation("oauth:gmail").unwrap(), &record, None).unwrap();
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
        for member in ["true", "false", "unreadable"] {
            for phone in ["true", "false", "unreadable"] {
                let (surface, admin, _store, _db, _root) = rig_with_settings(221, |db| {
                    let conn = rusqlite::Connection::open(db).unwrap();
                    conn.execute("INSERT OR REPLACE INTO settings (name,value,updated_at_ms) VALUES ('federation.member_mapping',?1,1)",[member]).unwrap();
                    conn.execute("INSERT OR REPLACE INTO settings (name,value,updated_at_ms) VALUES ('secret.phone_mapping',?1,1)",[phone]).unwrap();
                });
                for (principal, harness, app, scope, expected) in rows.iter().cloned() {
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
                            None,
                            None,
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
        store.commit_refresh("oauth:anthropic", 1, &store.credential_incarnation("oauth:anthropic").unwrap(), &record, None).unwrap();
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
