use super::*;
use credentials_core::fleet::{BUS_KEY_ID, RECORD_KEY_ID, WRAP_KEY_ID};

#[tokio::test]
async fn fleet_magic_context_routes_admit_only_single_and_batch_crypto() {
    let (surface, admin, _) = scoped_rig(227);
    admin.record_bind_at(120, 1, reserved("magic-context"), "");
    admin.record_bind_at(122, 1, reserved("unknown"), "");
    for op in [
        "fleet.epoch_status", "fleet.epoch_mint", "fleet.epoch_commit",
        "fleet.epoch_discard", "fleet.epoch_import", "fleet.epoch_wrap_for",
    ] {
        let unknown = routed_reply(&surface, &admin, 122, op, json!(null)).await;
        assert_eq!(unknown.0, FrameType::Response);
        assert_eq!(serde_json::from_slice::<serde_json::Value>(&unknown.1).unwrap(), uniform_not_found());
        let actual = routed_reply(&surface, &admin, 120, op, json!(null)).await;
        assert_eq!(actual, unknown, "magic-context {op}");
    }
    for op in [
        "fleet.epoch_seal", "fleet.epoch_open", "fleet.epoch_seal_batch", "fleet.epoch_open_batch",
    ] {
        let actual = routed_reply(&surface, &admin, 120, op, json!(null)).await;
        assert_eq!(actual.0, FrameType::Error, "admitted malformed {op}");
    }
}

#[tokio::test]
async fn fleet_prefrontal_routes_admit_only_single_and_batch_crypto() {
    let (surface, admin, _) = scoped_rig(227);
    admin.record_bind_at(120, 1, reserved("prefrontal"), "");
    admin.record_bind_at(121, 1, reserved("prefrontal-core"), "");
    admin.record_bind_at(122, 1, reserved("unknown"), "");
    let crypto = [
        "fleet.epoch_seal", "fleet.epoch_open",
        "fleet.epoch_seal_batch", "fleet.epoch_open_batch",
    ];
    for op in crypto.into_iter().chain([
        "fleet.epoch_status", "fleet.epoch_mint", "fleet.epoch_commit",
        "fleet.epoch_discard", "fleet.epoch_import", "fleet.epoch_wrap_for",
    ]) {
        let unknown = routed_reply(&surface, &admin, 122, op, json!(null)).await;
        assert_eq!(unknown.0, FrameType::Response);
        assert_eq!(serde_json::from_slice::<serde_json::Value>(&unknown.1).unwrap(), uniform_not_found());
        let alias = routed_reply(&surface, &admin, 121, op, json!(null)).await;
        assert_eq!(alias, unknown, "prefrontal-core {op}");
        let actual = routed_reply(&surface, &admin, 120, op, json!(null)).await;
        if crypto.contains(&op) {
            assert_eq!(actual.0, FrameType::Error, "admitted malformed {op}");
        } else {
            assert_eq!(actual, unknown, "prefrontal {op}");
        }
    }
}

#[test]
fn fleet_manifest_pins_all_ten_kinds_and_contract_names() {
    let manifest = manifest(credentials_core::MODULE_ID, None);
    let ProviderRole::ManagementSurface { operations, .. } = &manifest.provides[0] else {
        panic!("management surface")
    };
    let contract = include_str!("../../../docs/wire-contract-v1.md");
    for (index, op) in fleet_ops::OPS.into_iter().enumerate() {
        let declarations: Vec<_> = operations.iter().filter(|entry| entry.name == op).collect();
        assert_eq!(declarations.len(), 1, "{op}");
        assert_eq!(
            declarations[0].kind,
            if index < 5 {
                ManagementOperationKind::Query
            } else {
                ManagementOperationKind::Mutate
            }
        );
        assert!(contract.contains(&format!("`{op}`")), "undocumented {op}");
    }
}

#[tokio::test]
async fn fleet_routes_hide_all_ops_before_parameter_parsing_from_other_identities() {
    let (surface, admin, _) = scoped_rig(223);
    for (channel, principal) in [
        (120, subc_protocol::Principal::Direct),
        (121, subc_protocol::Principal::Unverified),
        (122, reserved("callosum")),
        (123, reserved("aft")),
        (124, reserved("entorhinal")),
    ] {
        admin.record_bind_at(channel, 1, principal, "");
    }
    for op in fleet_ops::OPS {
        for channel in [119, 120, 121, 122, 123] {
            let (ty, bytes) = routed_reply(&surface, &admin, channel, op, json!(null)).await;
            assert_eq!(ty, FrameType::Response, "{op} {channel}");
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
                uniform_not_found()
            );
        }
        let (ty, _) = routed_reply(
            &surface,
            &admin,
            124,
            op,
            json!({"unexpected":"never echo"}),
        )
        .await;
        assert_eq!(ty, FrameType::Error, "admitted malformed {op}");
    }
    assert_eq!(
        routed_json(&surface, &admin, 124, "fleet.epoch_status", json!({})).await,
        json!({"result":{"current":null,"held":[],"pending":null,"sealing_blocked_by":[]}})
    );
    assert_eq!(
        routed_json(
            &surface,
            &admin,
            124,
            "fleet.epoch_seal",
            json!({"aad":"","plaintext":""})
        )
        .await,
        json!({"result":{"error":{"code":"fleet_epoch_unavailable","class":"transient"}}})
    );
    assert_eq!(
        routed_json(
            &surface,
            &admin,
            124,
            "fleet.epoch_mint",
            json!({"members":[]})
        )
        .await,
        json!({"result":{"error":{"code":"fleet_peer_keys_unavailable","class":"transient"}}})
    );
}

#[tokio::test]
async fn fleet_read_fence_allows_only_announce_and_entorhinal_signing_even_with_persisted_authority(
) {
    use base64::Engine as _;
    let (surface, store, db_path, _root) = tmp_surface_with_store(224);
    let engine = Arc::new(RefreshEngine::new(
        Arc::clone(&store),
        Vec::new(),
        Arc::new(crate::test_support::NoHttp),
    ));
    let key = MasterKey::from_bytes([224; MASTER_KEY_LEN]);
    let admin = Arc::new(admin_surface::AdminSurface::new(
        engine,
        credentials_core::admin_auth::AdminMacKey::derive(&key),
        credentials_core::vault_id_for(db_path.parent().unwrap()).unwrap(),
        key.key_id(),
    ));
    let conn = rusqlite::Connection::open(db_path).unwrap();
    for module in ["callosum", "entorhinal", "broca"] {
        for id in [RECORD_KEY_ID, WRAP_KEY_ID] {
            for operation in ["read", "list", "sign", "open", "seal"] {
                conn.execute("INSERT INTO read_grants (principal_kind, principal_id, selector_kind, selector, operation, created_at_ms) VALUES ('reserved', ?1, 'exact', ?2, ?3, 0)", rusqlite::params![module,id,operation]).unwrap();
            }
        }
    }
    let callosum = federation::ingress::ScopedCaller::hand_only(Some(reserved("callosum")));
    let entorhinal = federation::ingress::ScopedCaller::hand_only(Some(reserved("entorhinal")));
    let watch = serde_json::from_value(json!({})).unwrap();
    let callosum_before = surface.watch_scoped(&callosum, &watch).unwrap();
    let entorhinal_before = surface.watch_scoped(&entorhinal, &watch).unwrap();
    store.ensure_fleet_keys(1).unwrap();
    assert_eq!(
        surface.watch_scoped(&entorhinal, &watch).unwrap(),
        entorhinal_before
    );
    assert_ne!(
        surface.watch_scoped(&callosum, &watch).unwrap(),
        callosum_before
    );
    let b64 = base64::engine::general_purpose::STANDARD;
    let recipient =
        credentials_core::kem::public_half(&credentials_core::kem::generate_key().unwrap())
            .unwrap()
            .0;
    for (channel, module) in [(120, "callosum"), (121, "entorhinal"), (122, "broca")] {
        admin.record_bind_at(channel, 1, reserved(module), "");
        for id in [RECORD_KEY_ID, WRAP_KEY_ID] {
            for (method, params, allowed) in [
                (
                    OP_PUBLIC_KEY,
                    json!({"credential_id":id}),
                    module == "callosum" || (module == "entorhinal" && id == RECORD_KEY_ID),
                ),
                (
                    OP_SIGN,
                    json!({"credential_id":id,"payload_b64":b64.encode(b"record")}),
                    module == "entorhinal" && id == RECORD_KEY_ID,
                ),
                (OP_STATUS, json!({"credential_id":id}), module == "callosum"),
                (OP_GET_SCOPED, json!({"credential_id":id}), false),
                (
                    OP_OPEN,
                    json!({"credential_id":id,"enc_b64":b64.encode([0;32]),"ciphertext_b64":b64.encode([0;16]),"info_b64":"","aad_b64":""}),
                    false,
                ),
                (
                    OP_SEAL,
                    json!({"credential_id":id,"recipient_public_key_b64":b64.encode(&recipient),"plaintext_b64":b64.encode(b"x"),"info_b64":"","aad_b64":""}),
                    false,
                ),
                (
                    OP_REPORT_AUTH_FAILURE,
                    json!({"credential_id":id,"provider_status":401,"record_version":1}),
                    false,
                ),
            ] {
                let mut unknown = params.clone();
                unknown["credential_id"] = json!("unknown:fleet-control");
                let reply = routed_json(&surface, &admin, channel, method, params).await;
                if allowed {
                    assert!(
                        reply["result"].get("error").is_none(),
                        "{module} {id} {method}: {reply}"
                    );
                    if method == OP_STATUS {
                        assert_eq!(reply["result"]["ready"], true);
                        assert_eq!(reply["result"]["record_version"], 1);
                    }
                } else {
                    let expected = routed_json(&surface, &admin, channel, method, unknown).await;
                    assert_eq!(reply, expected, "{module} {id} {method}");
                }
            }
        }
        let listed = routed_json(&surface, &admin, channel, OP_LIST_SCOPED, json!({})).await;
        assert!(!listed["result"]["credentials"]
            .to_string()
            .contains(RECORD_KEY_ID));
        assert!(!listed["result"]["credentials"]
            .to_string()
            .contains(WRAP_KEY_ID));
    }
    for id in [RECORD_KEY_ID, WRAP_KEY_ID] {
        let handle = credentials_core::store::mint_handle().unwrap();
        conn.execute("INSERT INTO handles (handle_hash, credential_id, created_at_ms, revoked) VALUES (?1, ?2, 0, 0)", rusqlite::params![handle.hash, id]).unwrap();
        for (method, params) in [
            (OP_GET, json!({"handle":handle.raw})),
            (OP_STATUS, json!({"handle":handle.raw})),
            (OP_PUBLIC_KEY, json!({"handle":handle.raw})),
            (
                OP_SIGN,
                json!({"handle":handle.raw,"payload_b64":b64.encode(b"record")}),
            ),
        ] {
            let mut unknown = params.clone();
            unknown["handle"] = json!(credentials_core::store::mint_handle().unwrap().raw);
            let expected = routed_json(&surface, &admin, 121, method, unknown).await;
            assert_eq!(
                routed_json(&surface, &admin, 121, method, params).await,
                expected,
                "{id} {method}"
            );
        }
    }
}

#[tokio::test]
async fn fleet_daemon_start_creates_missing_keys_once_and_preserves_existing_envelopes() {
    let root = TestTempDir::new(format!("fleet-daemon-start-{}", std::process::id()));
    let data_dir = root.join("vault");
    credentials_core::resolver::bootstrap(&credentials_core::resolver::ResolverConfig {
        data_dir: data_dir.clone(),
        source: credentials_core::resolver::KeySource::OperatorPath {
            path: root.join("master.key"),
        },
    })
    .unwrap();
    let db_path = data_dir.join("store.db");
    let descriptor = StorageDescriptor {
        module_id: credentials_core::MODULE_ID.into(),
        storage_namespace: credentials_core::STORAGE_NAMESPACE.into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: db_path.to_string_lossy().into_owned(),
        },
    };
    let ack: ModuleHelloAckBody = serde_json::from_value(json!({
        "negotiated_ver": PROTOCOL_VERSION, "subc_ops": [], "subc_capabilities": [],
        "storage": serde_json::to_value(descriptor).unwrap(),
    }))
    .unwrap();
    let mut originals = std::collections::BTreeMap::new();
    for _ in 0..2 {
        let (surface, admin, poll) = build_surface(
            &ack,
            credentials_core::MODULE_ID,
            root.join("claustrum.jsonc"),
        )
        .await
        .unwrap();
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        for id in [
            RECORD_KEY_ID,
            WRAP_KEY_ID,
            BUS_KEY_ID,
            "signing:bus-federation-account:1",
        ] {
            let blob: Vec<u8> = conn.query_row("SELECT envelope FROM credentials WHERE credential_id = ?1 AND state = 'active'", [id], |r| r.get(0)).unwrap();
            if let Some(original) = originals.get(id) {
                assert_eq!(&blob, original);
            } else {
                originals.insert(id, blob);
            }
            assert_eq!(conn.query_row("SELECT count(*) FROM audit_log WHERE op = 'fleet_key_create' AND actor = 'vault' AND credential_id = ?1", [id], |r| r.get::<_, i64>(0)).unwrap(), 1);
        }
        drop((conn, surface, admin, poll));
    }
}

#[tokio::test]
async fn fleet_wire_grammar_checks_canonical_bytes_and_epoch_width_before_store_access() {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    let (surface, admin, _) = scoped_rig(225);
    admin.record_bind_at(120, 1, reserved("entorhinal"), "");
    let valid_open = json!({"epoch":1,"nonce":URL_SAFE_NO_PAD.encode([0;24]),
        "ciphertext":URL_SAFE_NO_PAD.encode([0;16]),"aad":""});
    let mut cases = vec![
        ("fleet.epoch_seal", json!({"aad":"","plaintext":"Zg=="})),
        ("fleet.epoch_seal", json!({"aad":"+w","plaintext":""})),
        ("fleet.epoch_seal", json!({"plaintext":""})),
        (
            "fleet.epoch_seal",
            json!({"aad":"","plaintext":URL_SAFE_NO_PAD.encode(vec![0;credentials_core::fleet::MAX_BYTES+1])}),
        ),
        (
            "fleet.epoch_seal",
            json!({"aad":URL_SAFE_NO_PAD.encode(vec![0;credentials_core::fleet::MAX_BYTES+1]),"plaintext":""}),
        ),
        (
            "fleet.epoch_commit",
            json!({"epoch":1,"mint_id":URL_SAFE_NO_PAD.encode([0;15])}),
        ),
        (
            "fleet.epoch_discard",
            json!({"epoch":1,"mint_id":format!("{}=",URL_SAFE_NO_PAD.encode([0;16]))}),
        ),
        ("fleet.epoch_mint", json!({"members":["not-a-member"]})),
        ("fleet.epoch_wrap_for", json!({"member_id":"not-a-member"})),
        (
            "fleet.epoch_import",
            json!({"wrap":{"enc":URL_SAFE_NO_PAD.encode([0;31]),"ct":"","from":"x","to":"y","v":"ck-fleet-epoch-wrap/v1"}}),
        ),
    ];
    for epoch in [
        json!(0),
        json!(-1),
        json!(1.5),
        json!(4294967296u64),
        json!("1"),
    ] {
        let mut p = valid_open.clone();
        p["epoch"] = epoch;
        cases.push(("fleet.epoch_open", p));
    }
    for (field, value) in [
        ("nonce", URL_SAFE_NO_PAD.encode([0; 23])),
        ("nonce", URL_SAFE_NO_PAD.encode([0; 25])),
        ("ciphertext", URL_SAFE_NO_PAD.encode([0; 15])),
    ] {
        let mut p = valid_open.clone();
        p[field] = json!(value);
        cases.push(("fleet.epoch_open", p));
    }
    for (op, params) in cases {
        let (ty, bytes) = routed_reply(&surface, &admin, 120, op, params).await;
        assert_eq!(ty, FrameType::Error, "{op}");
        let reply: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(reply["code"], "invalid_params");
        assert_eq!(
            reply["message"],
            "params not decodable: invalid fleet parameters"
        );
    }
    let accepted = routed_json(
        &surface,
        &admin,
        120,
        "fleet.epoch_seal",
        json!({
            "aad":URL_SAFE_NO_PAD.encode(vec![0;credentials_core::fleet::MAX_BYTES]),
            "plaintext":URL_SAFE_NO_PAD.encode(vec![0;credentials_core::fleet::MAX_BYTES]),
        }),
    )
    .await;
    assert_eq!(
        accepted["result"]["error"]["code"],
        "fleet_epoch_unavailable"
    );
}

#[tokio::test]
async fn fleet_member_phone_and_refused_routes_cannot_borrow_entorhinal_identity() {
    let (surface, admin, _) = scoped_rig(226);
    for op in fleet_ops::OPS {
        for caller in [
            federation::RouteCaller::Member("reserved:entorhinal".into()),
            federation::RouteCaller::Phone("entorhinal".into()),
            federation::RouteCaller::Refused,
        ] {
            let (writer, mut receiver) = mpsc::channel(1);
            let frame = Frame::build_with_version(
                PROTOCOL_VERSION,
                FrameType::Request,
                Flags::new(false, Priority::Interactive, false),
                120,
                1,
                1,
                serde_json::to_vec(&json!({"method":op,"params":null})).unwrap(),
            )
            .unwrap();
            dispatch_route_request(frame, &writer, &surface, &admin, caller, None)
                .await
                .unwrap();
            let reply = receiver.recv().await.unwrap();
            assert_eq!(reply.header.ty, FrameType::Response);
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&reply.body).unwrap(),
                uniform_not_found()
            );
        }
    }
}
