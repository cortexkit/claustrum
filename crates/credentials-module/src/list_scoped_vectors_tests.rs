fn list_vector_case(label: &str, method: &str, frame: Frame) -> serde_json::Value {
    use base64::Engine as _;
    let mut reply: serde_json::Value = serde_json::from_slice(&frame.body).unwrap();
    // The boot nonce identifies a process, not a wire variant. All row identities
    // are fixed in storage below; normalize only this process-local watch nonce.
    if frame.header.ty == FrameType::StreamData {
        reply["epoch"] = json!("00000000000000000000000000000000");
    }
    let bytes = serde_json::to_vec(&reply).unwrap();
    json!({
        "case": label,
        "request": {"method": method, "params": {}},
        "frame_type": format!("{:?}", frame.header.ty),
        "reply": reply,
        "reply_b64url": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes),
        "reply_sha256": hex_digest(&bytes),
    })
}

fn hex_digest(bytes: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

include!("../tests/support/gateway_vector_pin.rs");

#[tokio::test]
async fn gateway_scoped_vectors_are_producer_generated_and_pinned() {
    use credentials_core::{GatewayAuth, GatewayHeader, GatewaySettings};

    let (surface, store, db, root) = tmp_surface_with_store(149);
    let engine = Arc::new(RefreshEngine::new(
        Arc::clone(&store),
        Vec::new(),
        Arc::new(crate::test_support::NoHttp),
    ));
    let key = MasterKey::from_bytes([149; MASTER_KEY_LEN]);
    let admin = Arc::new(admin_surface::AdminSurface::new(
        engine,
        credentials_core::admin_auth::AdminMacKey::derive(&key),
        credentials_core::vault_id_for(db.parent().unwrap()).unwrap(),
        key.key_id(),
    ));
    let (control, control_rx) = mpsc::channel(8);
    let (route, rx) = mpsc::channel(16);
    let mut rig = Rig {
        surface,
        admin,
        store,
        db_path: db,
        _root: root,
        routes: Arc::new(RouteEpochs::default()),
        egress: Egress { control, route },
        rx,
        _control: control_rx,
    };
    rig.bind(1, reserved("gateway-vector-reader"));
    for operation in [GrantOperation::Read, GrantOperation::List] {
        rig.store.create_read_grant_audited(
            "reserved", "gateway-vector-reader", SelectorKind::Category,
            "llm-gateway", operation, AuditCtx::admin(AuditOp::GrantCreate),
        ).unwrap();
    }
    let mut produced = Vec::new();
    let settings = GatewaySettings {
        base_url: "http://[::1]:4000/v1".into(),
        auth: GatewayAuth { header: "authorization".into(), scheme: "bearer".into() },
        headers: vec![
            GatewayHeader { name: "x-a".into(), value: "a\"b\\c".into() },
            GatewayHeader { name: "x-z".into(), value: "engineering".into() },
        ],
    };
    for (index, (id, filename, with_headers)) in [
        ("apikey:anthropic-gw-acme", "gateway-get-scoped-v1.json", true),
        ("apikey:anthropic-gw-acme:empty", "gateway-get-scoped-empty-headers-v1.json", false),
    ].into_iter().enumerate() {
        let mut input = settings.clone();
        if !with_headers { input.headers.clear(); }
        rig.store.gateway_create_audited(
            id,
            &VaultRecord::new_static(CredentialKind::ApiKey, "vector", b"vector-test-key".to_vec(), None),
            &input, &["anthropic-gw-acme".into()], AuditCtx::admin(AuditOp::Put),
        ).unwrap();
        let incarnation = format!("{:032x}", index + 1);
        rig.store.force_credential_incarnation_for_test(id, &incarnation);
        // Both rows describe one incarnation; fix both identities before producing bytes.
        rusqlite::Connection::open(&rig.db_path).unwrap().execute(
            "UPDATE credential_gateway_settings SET incarnation = ?1 WHERE credential_id = ?2",
            [&incarnation, id],
        ).unwrap();
        rig.dispatch(1, 1 + index as u64, FrameType::Request, OP_GET_SCOPED, json!({"credential_id": id})).await;
        let frame = rig.next().await;
        assert_eq!(frame.header.ty, FrameType::Response);
        let reply: serde_json::Value = serde_json::from_slice(&frame.body).unwrap();
        let result = &reply["result"];
        assert_eq!(result["credential_id"], id);
        assert_eq!(result["payload"], json!(b"vector-test-key".to_vec()));
        assert_eq!(result["base_url"], input.base_url);
        assert_eq!(result["auth"], json!({"header":"authorization","scheme":"bearer"}));
        assert_eq!(result["hosts"], json!(["[::1]"]));
        assert_eq!(result.get("invalid_key"), Some(&serde_json::Value::Null));
        assert_eq!(result["headers"], if with_headers {
            json!({"x-a":"a\"b\\c", "x-z":"engineering"})
        } else { json!({}) });
        produced.push((filename, frame.body));
    }
    rig.dispatch(1, 3, FrameType::Request, OP_LIST_SCOPED, json!({})).await;
    let frame = rig.next().await;
    assert_eq!(frame.header.ty, FrameType::Response);
    let reply: serde_json::Value = serde_json::from_slice(&frame.body).unwrap();
    let rows = reply["result"]["credentials"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    for row in rows {
        assert_eq!(row["auth_method"], "gateway");
        assert_eq!(row["categories"], json!(["llm-gateway"]));
        assert_eq!(row["provider_ids"], json!(["anthropic-gw-acme"]));
        assert_eq!(row["serves"], json!(["anthropic"]));
        assert_eq!(row["hosts"], json!(["[::1]"]));
        assert!(row.get("fusiform_provider_id").is_none());
    }
    produced.push(("gateway-list-scoped-v1.json", frame.body));
    let digest = credentials_core::gateway::gateway_settings_digest(&settings);
    let compact = r#"{"base_url":"http://[::1]:4000/v1","auth":{"header":"authorization","scheme":"bearer"},"headers":{"x-a":"a\"b\\c","x-z":"engineering"}}"#;
    assert_eq!(digest, hex_digest(compact.as_bytes()));
    produced.push(("gateway-settings-digest-v1.json", serde_json::to_vec_pretty(&json!({
        "settings": settings, "digest_input_utf8": compact, "sha256": digest,
    })).unwrap()));
    for (name, bytes) in non_gateway_scoped_baseline_vectors().await {
        // Emission must not bless a changed ordinary reply as a new baseline.
        assert_eq!(bytes, std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors").join(name)).unwrap(), "non-gateway baseline changed: {name}");
        produced.push((name, bytes));
    }
    pin_gateway_vectors(&produced);
}

async fn non_gateway_scoped_baseline_vectors() -> [(&'static str, Vec<u8>); 2] {
    let mut rig = Rig::new();
    let id = "apikey:openai";
    let record = VaultRecord::new_static(
        CredentialKind::ApiKey,
        "vector",
        b"vector-test-key".to_vec(),
        None,
    );
    rig.store.create(id, &record).unwrap();
    rig.store
        .force_credential_incarnation_for_test(id, "00000000000000000000000000000001");
    rig.store
        .set_providers_audited(
            id,
            SetProvidersMode::Set,
            &["openai".into()],
            AuditCtx::admin(AuditOp::SetProviders),
        )
        .unwrap();
    rig.bind(1, reserved("baseline-reader"));
    for operation in [GrantOperation::Read, GrantOperation::List] {
        grant_for(&rig.store, "baseline-reader", id, operation);
    }

    rig.dispatch(
        1,
        1,
        FrameType::Request,
        OP_GET_SCOPED,
        json!({"credential_id": id}),
    )
    .await;
    let get = rig.next().await;
    assert_eq!(get.header.ty, FrameType::Response);
    let reply: serde_json::Value = serde_json::from_slice(&get.body).unwrap();
    let result = &reply["result"];
    assert_eq!(result["credential_id"], id);
    assert_eq!(result["payload"], json!(b"vector-test-key".to_vec()));
    assert_eq!(result["record_version"], 1);
    assert_eq!(result["auth"]["header"], "authorization");
    assert_eq!(result["auth"]["scheme"], "bearer");
    assert_eq!(result["hosts"], json!(["api.openai.com"]));
    for field in ["base_url", "headers"] {
        assert!(result.get(field).is_none(), "non-gateway must omit {field}");
    }

    rig.dispatch(1, 2, FrameType::Request, OP_LIST_SCOPED, json!({}))
        .await;
    let list = rig.next().await;
    assert_eq!(list.header.ty, FrameType::Response);
    let reply: serde_json::Value = serde_json::from_slice(&list.body).unwrap();
    let rows = reply["result"]["credentials"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["id"], id);
    assert_eq!(rows[0]["auth_method"], "apikey");
    assert_eq!(rows[0]["provider_ids"], json!(["openai"]));
    assert_eq!(rows[0]["hosts"], json!(["api.openai.com"]));

    // Preserve the dispatched bytes, including field order and whitespace. A JSON
    // round-trip would hide serialization changes from the non-gateway baseline.
    [
        ("get-scoped-non-gateway-baseline-v1.json", get.body),
        ("list-scoped-non-gateway-baseline-v1.json", list.body),
    ]
}

#[tokio::test]
async fn list_scoped_v2_vectors_are_emitted_by_real_handlers_and_pinned() {
    let mut rig = Rig::new();
    let secret = "a1".repeat(32);
    let hash = credentials_core::enrollment::enrollment_secret_hash(&secret).unwrap();
    let request = rig
        .store
        .propose_enrollment("catalog-watcher", &hash)
        .unwrap();
    rig.store
        .approve_enrollment(&request.request_id, "catalog-watcher", "test")
        .unwrap();
    let credentials_core::enrollment::EnrollmentPoll::Approved { token, .. } = rig
        .store
        .poll_enrollment(&request.request_id, &secret)
        .unwrap()
    else {
        panic!("approved");
    };
    for (index, id) in [
        "apikey:exa",
        "apikey:kimi-for-coding",
        "apikey:brave",
        "apikey:tavily",
        "apikey:hidden",
    ]
    .iter()
    .enumerate()
    {
        let mut record = VaultRecord::new_static(
            CredentialKind::ApiKey,
            "vector",
            b"vector-test-key".to_vec(),
            None,
        );
        if *id == "apikey:kimi-for-coding" {
            record.detected_plan = Some(credentials_core::plan_detection::DetectedPlan {
                tier: Some("pro".into()),
                raw: Some("pro".into()),
                observed_at_ms: 1_700_000_000_000,
            });
        }
        rig.store.create(id, &record).unwrap();
        rig.store
            .force_credential_incarnation_for_test(id, &format!("{:032x}", index + 1));
    }
    rig.store
        .set_categories_audited(
            "apikey:hidden",
            SetCategoryMode::Set,
            &["private-key".into()],
            AuditCtx::admin(AuditOp::SetCategory),
        )
        .unwrap();
    rig.store.invalidate("apikey:brave").unwrap();
    rig.store
        .retire_and_revoke_all_audited("apikey:tavily", AuditCtx::admin(AuditOp::Invalidate))
        .unwrap();
    rig.store
        .create_read_grant_audited(
            "enrolled",
            "catalog-watcher",
            SelectorKind::Category,
            "web-search",
            GrantOperation::List,
            AuditCtx::admin(AuditOp::GrantCreate),
        )
        .unwrap();
    rig.bind(1, reserved("ambient"));
    let params = json!({"enrollment_token": token});
    rig.dispatch(1, 10, FrameType::Request, OP_LIST_SCOPED, params.clone())
        .await;
    let listing = rig.next().await;
    assert_eq!(listing.header.ty, FrameType::Response);
    let reply: serde_json::Value = serde_json::from_slice(&listing.body).unwrap();
    let rows = reply["result"]["credentials"].as_array().unwrap();
    assert_eq!(
        rows.iter()
            .map(|row| row["id"].as_str().unwrap())
            .collect::<Vec<_>>(),
        [
            "apikey:brave",
            "apikey:exa",
            "apikey:kimi-for-coding",
            "apikey:tavily"
        ]
    );
    assert_eq!(rows[0]["state"], "needs_reauth");
    assert_eq!(rows[1]["provider"], "exa");
    assert_eq!(rows[1]["incarnation"], "00000000000000000000000000000001");
    assert_eq!(rows[2]["provider"], "kimi-for-coding");
    assert_eq!(rows[2]["categories"], json!(["llm-provider", "web-search"]));
    assert_eq!(rows[2]["plan_tier_observed_at_ms"], 1_700_000_000_000_i64);
    assert_eq!(rows[3]["state"], "retired");
    assert_eq!(rows[1]["hosts"], json!(["api.exa.ai"]));
    assert!(rows.iter().all(|row| row.get("hosts").is_some()));
    assert_eq!(rows[2]["fusiform_provider_id"], "kimi-code-plan-global");
    for (index, expected) in [(0, "brave"), (1, "exa"), (3, "tavily")] {
        assert_eq!(rows[index]["fusiform_provider_id"], expected);
    }
    let mut cases = vec![list_vector_case(
        "catalog_and_lifecycle",
        OP_LIST_SCOPED,
        listing,
    )];
    rig.open(1, 11, params.clone()).await;
    let opening = rig.next().await;
    let opening_json: serde_json::Value = serde_json::from_slice(&opening.body).unwrap();
    assert_eq!(opening_json["seq"], 1);
    cases.push(list_vector_case("watch_opening", OP_WATCH_SCOPED, opening));
    rig.store
        .set_categories_audited(
            "apikey:exa",
            SetCategoryMode::Add,
            &["search-vector".into()],
            AuditCtx::admin(AuditOp::SetCategory),
        )
        .unwrap();
    let changed = rig.next().await;
    let changed_json: serde_json::Value = serde_json::from_slice(&changed.body).unwrap();
    assert_eq!(changed_json["seq"], 2);
    assert_ne!(changed_json["view"], opening_json["view"]);
    cases.push(list_vector_case(
        "watch_category_changed",
        OP_WATCH_SCOPED,
        changed,
    ));
    rig.store
        .revoke_enrollment("catalog-watcher", "test")
        .unwrap();
    let terminal = rig.next().await;
    assert_eq!(terminal.header.ty, FrameType::Response);
    assert_scoped_not_found(&serde_json::from_slice(&terminal.body).unwrap());
    cases.push(list_vector_case("watch_revoked", OP_WATCH_SCOPED, terminal));
    rig.dispatch(
        1,
        12,
        FrameType::Request,
        "auth.watch_scoped.unsupported",
        json!({}),
    )
    .await;
    let unknown = rig.next().await;
    assert_eq!(unknown.header.ty, FrameType::Error);
    let error: serde_json::Value = serde_json::from_slice(&unknown.body).unwrap();
    assert_eq!(error["code"], "unknown_method");
    cases.push(list_vector_case(
        "older_vault_unknown_method",
        "auth.watch_scoped.unsupported",
        unknown,
    ));

    rig.bind(2, reserved("descriptor-reader"));
    let mut get_cases = Vec::new();
    for (index, (label, id)) in [
        ("catalog_with_evidence", "apikey:openai"),
        ("catalog_without_evidence", "apikey:nanogpt"),
        ("oauth_hosts_only", "oauth:anthropic"),
    ].iter().enumerate() {
        let record = if *id == "oauth:anthropic" {
            VaultRecord::new_oauth(
                "vector",
                "anthropic",
                credentials_core::oauth::OAuthCredential {
                    access_token: "vector-test-access".to_owned().into(),
                    refresh_token: "vector-test-refresh".to_owned().into(),
                    expires_at_ms: None,
                    token_url: String::new(),
                    client_id: None,
                    client_secret: None,
                    scopes: Vec::new(),
                },
                b"vector-test-key".to_vec(),
            )
        } else {
            VaultRecord::new_static(CredentialKind::ApiKey, "vector", b"vector-test-key".to_vec(), None)
        };
        rig.store.create(id, &record).unwrap();
        rig.store.force_credential_incarnation_for_test(id, &format!("{:032x}", index + 101));
        rig.store.create_read_grant_audited(
            "reserved", "descriptor-reader", SelectorKind::Exact, id,
            GrantOperation::Read, AuditCtx::admin(AuditOp::GrantCreate),
        ).unwrap();
        let params = json!({"credential_id": id});
        rig.dispatch(2, 20 + index as u64, FrameType::Request, OP_GET_SCOPED, params.clone()).await;
        let frame = rig.next().await;
        assert_eq!(frame.header.ty, FrameType::Response);
        let mut case = list_vector_case(label, OP_GET_SCOPED, frame);
        case["request"]["params"] = params;
        let reply = &case["reply"]["result"];
        assert_eq!(reply["credential_id"], *id);
        match *label {
            "catalog_with_evidence" => {
                assert_eq!(reply["invalid_key"]["status"], 401);
                assert_eq!(reply["invalid_key"]["error_code"], "invalid_api_key");
            }
            "catalog_without_evidence" => {
                assert!(reply.get("auth").is_some());
                assert_eq!(reply.get("invalid_key"), Some(&serde_json::Value::Null));
            }
            _ => {
                assert_eq!(reply["hosts"], json!(["api.anthropic.com"]));
                for field in ["auth", "invalid_key"] {
                    assert!(reply.get(field).is_none(), "OAuth must omit {field}");
                }
            }
        }
        get_cases.push(case);
    }
    rig.dispatch(2, 30, FrameType::Request, OP_LIST_SCOPED, json!({})).await;
    let listing = rig.next().await;
    assert_eq!(listing.header.ty, FrameType::Response);
    let reply: serde_json::Value = serde_json::from_slice(&listing.body).unwrap();
    let rows = reply["result"]["credentials"].as_array().unwrap();
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0]["hosts"], json!(["api.nano-gpt.com", "nano-gpt.com"]));
    assert_eq!(rows[1]["hosts"], json!(["api.openai.com"]));
    assert_eq!(rows[0]["fusiform_provider_id"], "nano-gpt");
    assert_eq!(rows[1]["fusiform_provider_id"], "openai");
    assert_eq!(rows[2]["hosts"], json!(["api.anthropic.com"]));
    assert!(rows[2].get("fusiform_provider_id").is_none());
    cases.push(list_vector_case("descriptor_presence", OP_LIST_SCOPED, listing));
    cases.push(github_app_identity_listing_vector().await);
    cases.push(github_app_attestation_listing_vector().await);
    let emitted =
        serde_json::to_vec_pretty(&json!({"v":"ck-list-scoped-vectors/v2", "cases":cases}))
            .unwrap();
    let get_emitted =
        serde_json::to_vec_pretty(&json!({"v":"ck-get-scoped-vectors/v1", "cases":get_cases}))
            .unwrap();
    let baselines = non_gateway_scoped_baseline_vectors().await;
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors");
    // SHA256SUMS lists every vector file in the directory, one line each. This test
    // owns only the lines for the files it produces (the two vector files and the
    // non-gateway baselines), so other files' entries must not affect it.
    let mut produced: Vec<(&str, &[u8])> = vec![
        ("get-scoped-v1.json", get_emitted.as_slice()),
        ("list-scoped-v2.json", emitted.as_slice()),
    ];
    for (name, bytes) in &baselines {
        produced.push((*name, bytes.as_slice()));
    }
    produced.sort_by(|a, b| a.0.cmp(b.0));
    let owned_by_us = |entry: &str| {
        produced
            .iter()
            .any(|(name, _)| entry.ends_with(&format!("  {name}")))
    };
    let lines: Vec<String> = produced
        .iter()
        .map(|(name, bytes)| format!("{}  {name}", hex_digest(bytes)))
        .collect();
    let ours = |text: &str| -> Vec<String> {
        text.lines()
            .filter(|entry| owned_by_us(entry))
            .map(str::to_owned)
            .collect()
    };
    let sums_path = directory.join("SHA256SUMS");
    let sums = std::fs::read_to_string(&sums_path).expect("pinned vector hash");
    if std::env::var("CK_EMIT_LIST_SCOPED_VECTORS").as_deref() == Ok("1")
        || std::env::var("CK_EMIT_SECRET_VECTORS").as_deref() == Ok("1")
    {
        std::fs::write(directory.join("list-scoped-v2.json"), &emitted).unwrap();
        std::fs::write(directory.join("get-scoped-v1.json"), &get_emitted).unwrap();
        for (name, bytes) in &baselines {
            std::fs::write(directory.join(name), bytes).unwrap();
        }
        let mut all: Vec<String> = sums
            .lines()
            .filter(|entry| !owned_by_us(entry))
            .map(str::to_owned)
            .chain(lines.iter().cloned())
            .collect();
        all.sort_by(|a, b| a.split_once("  ").unwrap().1.cmp(b.split_once("  ").unwrap().1));
        std::fs::write(&sums_path, format!("{}\n", all.join("\n"))).unwrap();
        println!(
            "emitted {} list-scoped v2 cases, three get-scoped v1 cases, two non-gateway baselines and their SHA256SUMS lines",
            cases.len(),
        );
    } else {
        assert_eq!(
            emitted,
            std::fs::read(directory.join("list-scoped-v2.json"))
                .expect("pinned list-scoped vectors")
        );
        assert_eq!(
            get_emitted,
            std::fs::read(directory.join("get-scoped-v1.json"))
                .expect("pinned get-scoped vectors")
        );
        for (name, bytes) in &baselines {
            assert_eq!(
                bytes,
                &std::fs::read(directory.join(name)).expect("pinned non-gateway baseline"),
                "non-gateway wire bytes changed: {name}",
            );
        }
        assert_eq!(
            ours(&sums),
            lines,
            "SHA256SUMS must list each file this test produces once, with these hashes"
        );
    }
}

async fn github_app_identity_listing_vector() -> serde_json::Value {
    use credentials_core::refresh_adapters::github_app::GithubAppIdentity;

    const ID: &str = "github_app:listing-vector";
    let mut rig = Rig::new();
    let mut record = roster_oauth_record();
    record.refresh_adapter = Some("github_app".into());
    rig.store.create(ID, &record).unwrap();
    let incarnation = "0123456789abcdef0123456789abcdef";
    rig.store.force_credential_incarnation_for_test(ID, incarnation);
    rig.grant("app-list", ID);
    grant_for(&rig.store, "app-read", ID, GrantOperation::Read);
    grant_for(&rig.store, "app-policy", ID, GrantOperation::PolicyToken);
    rig.bind(1, reserved("app-list"));
    rig.bind(2, reserved("app-read"));
    rig.bind(3, reserved("app-policy"));

    let list = |caller: &str| {
        rig.surface
            .list_scoped(
                &crate::federation::ingress::ScopedCaller::hand_only(Some(reserved(caller))),
                &ListScopedParams { enrollment_token: None },
            )
            .unwrap()
    };
    for caller in ["app-list", "app-read", "app-policy"] {
        let listing = list(caller);
        assert_eq!(listing.credentials.len(), 1);
        assert!(listing.credentials[0].github_app.is_none());
    }
    let policy_only_before = list("app-policy").view;
    let mut completed = rig.surface.watches.completed.subscribe();
    rig.open(1, 41, json!({})).await;
    let before = rig.notice(1, 41, 1).await;
    completed.changed().await.unwrap();

    let app = GithubAppIdentity { app_id: "9007199254740993".into(), slug: "listing-vector".into() };
    rig.store.commit_refresh(ID, 1, incarnation, &record, Some(&app)).unwrap();
    let changed = rig.notice(1, 41, 2).await;
    completed.changed().await.unwrap();
    assert_ne!(before["view"], changed["view"]);
    assert_eq!(before["keys"], changed["keys"]);

    let pinned = rig.surface.list_scoped(
        &crate::federation::ingress::ScopedCaller::hand_only(Some(reserved("app-policy"))),
        &ListScopedParams { enrollment_token: None },
    ).unwrap();
    assert_eq!(pinned.view, policy_only_before);
    assert!(pinned.credentials[0].github_app.is_none());
    let expected_member = json!({"app_id": "9007199254740993", "slug": "listing-vector"});
    rig.dispatch(2, 42, FrameType::Request, OP_LIST_SCOPED, json!({})).await;
    let read = rig.next().await;
    assert_eq!(serde_json::from_slice::<serde_json::Value>(&read.body).unwrap()["result"]["credentials"][0]["github_app"], expected_member);
    rig.dispatch(1, 43, FrameType::Request, OP_LIST_SCOPED, json!({})).await;
    let listing = rig.next().await;
    let golden = list_vector_case("github_app_identity", OP_LIST_SCOPED, listing);
    assert_eq!(golden["reply"]["result"]["view"], changed["view"]);
    assert_eq!(golden["reply"]["result"]["credentials"][0]["github_app"], expected_member);

    rig.store.commit_refresh(ID, 2, incarnation, &record, Some(&app)).unwrap();
    completed.changed().await.unwrap();
    assert!(rig.rx.try_recv().is_err(), "same App identity published a notice");
    golden
}

async fn github_app_attestation_listing_vector() -> serde_json::Value {
    use credentials_core::store::GitHubAppCreation;

    const ID: &str = "github_app:attested-vector";
    const COMPANION: &str = "opaque:github-app-webhook:attested-vector";
    const AGENT: &str = "agent_0123456789abcdef";
    let mut rig = Rig::new();
    rig.grant("app-list", ID);
    grant_for(&rig.store, "app-policy", "github_app:policy-baseline", GrantOperation::PolicyToken);
    rig.store.create("github_app:policy-baseline", &roster_oauth_record()).unwrap();
    // A grant that predates the reservation must not expose the companion in either
    // the grant list or the row set, even when it could otherwise resolve by exact id.
    {
        let conn = rusqlite::Connection::open(&rig.db_path).unwrap();
        for caller in ["app-list", "app-policy"] {
            conn.execute(
                "INSERT INTO read_grants (principal_kind, principal_id, selector_kind, selector, operation, created_at_ms) \
                 VALUES ('reserved', ?1, 'exact', ?2, 'read', 0)",
                [caller, COMPANION],
            ).unwrap();
        }
    }
    rig.bind(1, reserved("app-list"));
    rig.bind(2, reserved("app-policy"));
    let policy = |rig: &Rig| {
        let caller = crate::federation::ingress::ScopedCaller::hand_only(Some(reserved("app-policy")));
        rig.surface.list_scoped(&caller, &ListScopedParams { enrollment_token: None }).unwrap()
    };
    let policy_before = serde_json::to_value(policy(&rig)).unwrap();
    assert_eq!(policy_before["credentials"].as_array().unwrap().len(), 1);
    assert!(policy_before["credentials"][0].get("github_app").is_none());
    let mut completed = rig.surface.watches.completed.subscribe();
    let initial_count = *completed.borrow();
    rig.open(1, 51, json!({})).await;
    let before = rig.notice(1, 51, 1).await;
    rig.open(2, 52, json!({})).await;
    let policy_initial = rig.notice(2, 52, 1).await;
    assert_eq!(policy_initial["view"], policy_before["view"]);
    tokio::time::timeout(Duration::from_secs(3), completed.wait_for(|count| *count >= initial_count + 2))
        .await.expect("both initial snapshots finish").unwrap();

    rig.store.create_github_app_audited(GitHubAppCreation {
        slug: "attested-vector",
        app_id: 9007199254740993,
        agent: AGENT,
        pem: &"test-pem".to_owned().into(),
        client_id: "test-client",
        relay: Some(("test-slot", &"test-webhook-secret".to_owned().into())),
    }, "test").unwrap();
    let changed = rig.notice(1, 51, 2).await;
    tokio::time::timeout(Duration::from_secs(3), completed.wait_for(|count| *count >= initial_count + 4))
        .await.expect("both watches recompute after create").unwrap();
    assert_ne!(before["view"], changed["view"]);
    assert_eq!(before["keys"], changed["keys"]);
    assert_eq!(serde_json::to_value(policy(&rig)).unwrap(), policy_before);
    assert!(rig.rx.try_recv().is_err(), "PolicyToken-only watch changed at create");

    rig.dispatch(1, 51, FrameType::Cancel, "", json!({})).await;
    rig.dispatch(2, 52, FrameType::Cancel, "", json!({})).await;
    const CREATED_AT: i64 = 1_700_000_000_000;
    rusqlite::Connection::open(&rig.db_path).unwrap().execute(
        "UPDATE credentials SET github_app_created_at_ms=?1 WHERE credential_id=?2",
        rusqlite::params![CREATED_AT, ID],
    ).unwrap();
    let read_pinned_metadata = rig.surface.list_scoped(
        &crate::federation::ingress::ScopedCaller::hand_only(Some(reserved("app-list"))),
        &ListScopedParams { enrollment_token: None },
    ).unwrap();
    assert_eq!(read_pinned_metadata.credentials.len(), 1);
    assert_eq!(read_pinned_metadata.credentials[0].id, ID);
    assert_ne!(json!(read_pinned_metadata.view), changed["view"]);
    rig.store.force_credential_incarnation_for_test(ID, "0123456789abcdef0123456789abcdef");
    rig.dispatch(1, 53, FrameType::Request, OP_LIST_SCOPED, json!({})).await;
    let listing = rig.next().await;
    let golden = list_vector_case("github_app_attestation", OP_LIST_SCOPED, listing);
    let result = &golden["reply"]["result"];
    assert_eq!(result["credentials"].as_array().unwrap().len(), 1);
    assert_eq!(result["credentials"][0]["id"], ID);
    assert_eq!(result["grants"], 1);
    assert_eq!(result["grant_tuples"][0]["selector"], ID);
    assert_eq!(result["credentials"][0]["github_app"], json!({
        "app_id": "9007199254740993", "slug": "attested-vector", "created_by": "vault",
        "created_at_ms": CREATED_AT, "agent": AGENT,
    }));
    golden
}
