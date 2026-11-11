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
    for index in [0, 1, 3] {
        assert!(rows[index].get("fusiform_provider_id").is_none());
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
        ("oauth_without_descriptor", "oauth:anthropic"),
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
                for field in ["auth", "hosts", "invalid_key"] {
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
    assert!(rows[2].get("hosts").is_none());
    assert!(rows[2].get("fusiform_provider_id").is_none());
    cases.push(list_vector_case("descriptor_presence", OP_LIST_SCOPED, listing));
    let emitted =
        serde_json::to_vec_pretty(&json!({"v":"ck-list-scoped-vectors/v2", "cases":cases}))
            .unwrap();
    let get_emitted =
        serde_json::to_vec_pretty(&json!({"v":"ck-get-scoped-vectors/v1", "cases":get_cases}))
            .unwrap();
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors");
    // SHA256SUMS lists every vector file in the directory, one line each. This test
    // owns only the lines for the two files it produces, so other files' entries must
    // not affect it.
    const OWNED: [&str; 2] = ["get-scoped-v1.json", "list-scoped-v2.json"];
    let owned_by_us = |entry: &str| {
        OWNED
            .iter()
            .any(|name| entry.ends_with(&format!("  {name}")))
    };
    let lines = vec![
        format!("{}  get-scoped-v1.json", hex_digest(&get_emitted)),
        format!("{}  list-scoped-v2.json", hex_digest(&emitted)),
    ];
    let ours = |text: &str| -> Vec<String> {
        text.lines()
            .filter(|entry| owned_by_us(entry))
            .map(str::to_owned)
            .collect()
    };
    let sums_path = directory.join("SHA256SUMS");
    let sums = std::fs::read_to_string(&sums_path).expect("pinned vector hash");
    if std::env::var("CK_EMIT_LIST_SCOPED_VECTORS").as_deref() == Ok("1") {
        std::fs::write(directory.join("list-scoped-v2.json"), &emitted).unwrap();
        std::fs::write(directory.join("get-scoped-v1.json"), &get_emitted).unwrap();
        let mut all: Vec<String> = sums
            .lines()
            .filter(|entry| !owned_by_us(entry))
            .map(str::to_owned)
            .chain(lines)
            .collect();
        all.sort_by(|a, b| a.split_once("  ").unwrap().1.cmp(b.split_once("  ").unwrap().1));
        std::fs::write(&sums_path, format!("{}\n", all.join("\n"))).unwrap();
        println!(
            "emitted six list-scoped v2 cases, three get-scoped v1 cases and their SHA256SUMS lines"
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
        assert_eq!(
            ours(&sums),
            lines,
            "SHA256SUMS must list get-scoped-v1.json and list-scoped-v2.json once each, with these hashes"
        );
    }
}
