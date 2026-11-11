use super::*;

const ID: &str = "apikey:anthropic-gw-acme";
const PROVIDER: &str = "anthropic-gw-acme";

fn put_args<'a>(id: &'a str, file: &'a str) -> Vec<&'a str> {
    vec![
        "put",
        "--id",
        id,
        "--payload-file",
        file,
        "--gateway-base-url",
        "HTTP://LOCALHOST:4000/v1///",
        "--gateway-auth-header",
        "Authorization",
        "--gateway-auth-scheme",
        "bearer",
        "--provider-id",
        PROVIDER,
    ]
}

fn run(
    vault: &GrantCliVault,
    peer: Option<&ProviderRoutePeer>,
    args: &[&str],
) -> std::process::Output {
    let mut command = cli();
    isolated_cli::assert_isolated(&command);
    command
        .args(args)
        .arg("--data-dir")
        .arg(&vault.data_dir)
        .arg("--key-path")
        .arg(&vault.key_path);
    if let Some(peer) = peer {
        command.arg("--subc").arg(&peer.connection);
    }
    command.output().unwrap()
}

fn succeeded(output: std::process::Output) {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn gateway_put_online_and_offline_create_normalized_settings_with_sorted_headers() {
    for online in [false, true] {
        for with_headers in [false, true] {
            let vault = GrantCliVault::new("gateway-normal-form");
            vault.bootstrap();
            let (audit_count, generation, fingerprint) = {
                use credentials_core::audit::{AuditCtx, AuditOp};
                use credentials_core::store::{GrantOperation, SelectorKind};
                let store = open_leased_store(&vault.data_dir, &vault.key_path);
                // Creating an audited ordinary record for the same API key supplies
                // its fingerprint without exposing the audit key or copying crypto.
                store
                    .create_audited(
                        "apikey:fingerprint-control",
                        &credentials_core::VaultRecord::new_static(
                            CredentialKind::ApiKey,
                            "test",
                            b"gateway-key-canary".to_vec(),
                            None,
                        ),
                        AuditCtx::admin(AuditOp::Put),
                    )
                    .unwrap();
                let fingerprint = store
                    .read_audit(None)
                    .unwrap()
                    .last()
                    .unwrap()
                    .payload_hash
                    .clone()
                    .unwrap();
                for (principal, category) in [
                    ("gateway-reader", "llm-gateway"),
                    ("provider-reader", "llm-provider"),
                ] {
                    for operation in [GrantOperation::Read, GrantOperation::List] {
                        store
                            .create_read_grant_audited(
                                "reserved",
                                principal,
                                SelectorKind::Category,
                                category,
                                operation,
                                AuditCtx::admin(AuditOp::GrantCreate),
                            )
                            .unwrap();
                    }
                }
                store.open_intent(ID, 7, "old-refresh-hash").unwrap();
                assert!(store.read_intent(ID).unwrap().is_some());
                (
                    store.read_audit(None).unwrap().len(),
                    store.grants_generation().unwrap(),
                    fingerprint,
                )
            };
            let peer = online.then(|| ProviderRoutePeer::start(&vault));
            let file = payload_file("gateway-key-canary");
            let mut args = put_args(ID, &file);
            if with_headers {
                args.extend([
                    "--gateway-header",
                    "X-Zone=  eu=west  ",
                    "--gateway-header",
                    "X-Route= team ",
                ]);
            }
            succeeded(run(&vault, peer.as_ref(), &args));
            if let Some(peer) = &peer {
                let ops = peer.observed.lock().unwrap();
                assert_eq!(ops.len(), 1, "{ops:?}");
                assert_eq!(ops[0]["op"], "admin.gateway_create");
                assert_eq!(ops[0]["v"], 2);
                assert_eq!(ops[0]["base_url"], "http://localhost:4000/v1");
                assert_eq!(ops[0]["auth_header"], "authorization");
                assert_eq!(ops[0]["provider_ids"], serde_json::json!([PROVIDER]));
                assert!(ops[0].get("mode").is_none());
            }
            drop(peer);
            let store = open_leased_store(&vault.data_dir, &vault.key_path);
            let stored = store.gateway_settings(ID).unwrap().unwrap();
            let settings = &stored.settings;
            assert_eq!(settings.base_url, "http://localhost:4000/v1");
            assert_eq!(settings.auth.header, "authorization");
            assert_eq!(settings.auth.scheme, "bearer");
            let headers: Vec<_> = settings
                .headers
                .iter()
                .map(|h| (h.name.as_str(), h.value.as_str()))
                .collect();
            assert_eq!(
                headers,
                if with_headers {
                    vec![("x-route", "team"), ("x-zone", "eu=west")]
                } else {
                    vec![]
                }
            );
            assert_eq!(
                store.get(ID).unwrap().payload.expose(),
                b"gateway-key-canary"
            );
            assert_eq!(store.get(ID).unwrap().kind, CredentialKind::ApiKey);
            assert!(store.get(ID).unwrap().refresh_adapter.is_none());
            let meta = store.meta(ID).unwrap();
            assert_eq!(meta.record_version, 1);
            assert_eq!(meta.categories, ["llm-gateway"]);
            assert_eq!(meta.provider_ids, [PROVIDER]);
            assert_eq!(
                meta.incarnation.as_deref(),
                Some(stored.incarnation.as_str())
            );
            assert_eq!(store.grants_generation().unwrap(), generation + 1);
            assert!(store.read_intent(ID).unwrap().is_none());
            for operation in [
                credentials_core::store::GrantOperation::Read,
                credentials_core::store::GrantOperation::List,
            ] {
                assert!(store
                    .read_grant_covers("reserved", "gateway-reader", ID, operation)
                    .unwrap());
                assert!(!store
                    .read_grant_covers("reserved", "provider-reader", ID, operation)
                    .unwrap());
            }
            let audit = store.read_audit(None).unwrap();
            let rows = &audit[audit_count..];
            assert_eq!(rows.len(), 2);
            assert_eq!(rows[0].op, "put");
            assert_eq!(rows[0].credential_id.as_deref(), Some(ID));
            assert_eq!(rows[0].payload_hash.as_deref(), Some(fingerprint.as_str()));
            assert_eq!(rows[1].op, "gateway_create");
            let encoded = if with_headers {
                br#"{"base_url":"http://localhost:4000/v1","auth":{"header":"authorization","scheme":"bearer"},"headers":{"x-route":"team","x-zone":"eu=west"}}"#.as_slice()
            } else {
                br#"{"base_url":"http://localhost:4000/v1","auth":{"header":"authorization","scheme":"bearer"},"headers":{}}"#.as_slice()
            };
            let digest = ring::digest::digest(&ring::digest::SHA256, encoded);
            let digest: String = digest
                .as_ref()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            assert_eq!(
                rows[1].credential_id.as_deref(),
                Some(format!("gateway:{ID}|{digest}").as_str())
            );
            assert!(rows[1].payload_hash.is_none());
            assert_eq!(store.verify_audit_chain().unwrap(), None);
        }
    }
}

#[test]
fn gateway_put_refused_discriminator_never_falls_back_or_stores() {
    let vault = GrantCliVault::new("gateway-refused-op");
    vault.bootstrap();
    let tip = open_leased_store(&vault.data_dir, &vault.key_path)
        .audit_tip()
        .unwrap();
    let peer = ProviderRoutePeer::start_with_gateway_refusal(&vault, true);
    let output = run(
        &vault,
        Some(&peer),
        &put_args(ID, &payload_file("gateway-key-canary")),
    );
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unsupported admin.gateway_create"));
    {
        let ops = peer.observed.lock().unwrap();
        assert_eq!(ops.len(), 1, "{ops:?}");
        assert_eq!(ops[0]["op"], "admin.gateway_create");
    }
    drop(peer);
    let store = open_leased_store(&vault.data_dir, &vault.key_path);
    assert!(store.list_meta().unwrap().is_empty());
    assert!(store.gateway_settings(ID).unwrap().is_none());
    assert_eq!(store.audit_tip().unwrap(), tip);
}

#[test]
fn gateway_put_invalid_settings_are_preflighted_before_any_op() {
    for online in [false, true] {
        let vault = GrantCliVault::new("gateway-preflight");
        vault.bootstrap();
        let tip = open_leased_store(&vault.data_dir, &vault.key_path)
            .audit_tip()
            .unwrap();
        let peer = online.then(|| ProviderRoutePeer::start(&vault));
        let file = payload_file("gateway-key-canary");
        for (flag, value, rule) in [
            ("--gateway-base-url", "http://remote.invalid", "base_url"),
            (
                "--gateway-base-url",
                "https://localhost/a/../v1",
                "base_url",
            ),
            (
                "--gateway-base-url",
                "https://localhost/v1/Messages/",
                "base_url_path",
            ),
            ("--gateway-auth-header", "bad header", "auth"),
            ("--gateway-auth-scheme", "Bearer", "auth"),
            ("--provider-id", "openai", "provider_id"),
            ("--provider-id", "Bad", "provider_id"),
            ("--id", "apikey:anthropic-gw-other", "provider_id"),
        ] {
            let mut args = put_args(ID, &file);
            let index = args.iter().position(|arg| *arg == flag).unwrap();
            args[index + 1] = value;
            let output = run(&vault, peer.as_ref(), &args);
            assert!(!output.status.success(), "{flag}");
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                stderr.contains("invalid_gateway_settings")
                    && stderr.contains(&format!("rule={rule}")),
                "{stderr}"
            );
        }
        for (extras, reason) in [
            (
                vec![
                    "--gateway-header",
                    "X-Route=one",
                    "--gateway-header",
                    "x-route=two",
                ],
                "rule=header_name",
            ),
            (
                vec!["--gateway-header", "authorization=never-echo-canary"],
                "rule=header_name",
            ),
            (
                vec![
                    "--gateway-header",
                    "x-route={\"secret\":\"never-echo-canary\"}",
                ],
                "rule=header_value",
            ),
            (
                vec!["--gateway-header", "missing-equals-never-echo-canary"],
                "--gateway-header needs name=value",
            ),
            (vec!["--provider-id", "openai-gw-other"], "rule=provider_id"),
            (vec!["--provider-id", PROVIDER], "rule=provider_id"),
        ] {
            let mut args = put_args(ID, &file);
            args.extend(extras);
            let output = run(&vault, peer.as_ref(), &args);
            assert!(!output.status.success());
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(stderr.contains(reason), "{stderr}");
            assert!(!stderr.contains("never-echo-canary"));
        }
        let mut args = put_args(ID, &file);
        args.truncate(args.len() - 2);
        let output = run(&vault, peer.as_ref(), &args);
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("rule=provider_id"));
        for required in [
            "--gateway-base-url",
            "--gateway-auth-header",
            "--gateway-auth-scheme",
        ] {
            let mut args = put_args(ID, &file);
            let index = args.iter().position(|arg| *arg == required).unwrap();
            args.drain(index..index + 2);
            let output = run(&vault, peer.as_ref(), &args);
            assert_eq!(output.status.code(), Some(1));
            assert!(String::from_utf8_lossy(&output.stderr).contains(required));
        }
        if let Some(peer) = &peer {
            assert!(peer.observed.lock().unwrap().is_empty());
        }
        drop(peer);
        let store = open_leased_store(&vault.data_dir, &vault.key_path);
        assert!(store.list_meta().unwrap().is_empty());
        assert_eq!(store.audit_tip().unwrap(), tip);
    }
}

#[test]
fn gateway_put_usage_errors_leave_gateway_and_ordinary_records_unchanged() {
    for online in [false, true] {
        let vault = GrantCliVault::new("gateway-usage");
        vault.bootstrap();
        let file = payload_file("gateway-key-canary");
        succeeded(vault.run(&put_args(ID, &file)));
        let ordinary = "apikey:ordinary";
        succeeded(vault.run(&["put", "--id", ordinary, "--payload-file", &file]));
        let before = {
            let store = open_leased_store(&vault.data_dir, &vault.key_path);
            (
                store.audit_tip().unwrap(),
                store.gateway_settings(ID).unwrap(),
            )
        };
        let peer = online.then(|| ProviderRoutePeer::start(&vault));
        for id in [ID, ordinary] {
            for flags in [
                vec!["--gateway-auth-header", "authorization"],
                vec!["--gateway-auth-scheme", "bearer"],
                vec!["--gateway-header", "x-route=team"],
            ] {
                let mut args = vec!["put", "--id", id, "--payload-file", &file];
                args.extend(flags);
                let output = run(&vault, peer.as_ref(), &args);
                assert_eq!(output.status.code(), Some(1));
                assert!(String::from_utf8_lossy(&output.stderr).contains("--gateway-base-url"));
            }
            for gateway_flag in [
                "--gateway-base-url",
                "--gateway-auth-header",
                "--gateway-auth-scheme",
                "--gateway-header",
            ] {
                for mode in [vec!["--replace"], vec!["--expected-hash", "00"]] {
                    let mut args = vec![
                        "put",
                        "--id",
                        id,
                        "--payload-file",
                        &file,
                        gateway_flag,
                        "placeholder",
                    ];
                    args.extend(mode);
                    let output = run(&vault, peer.as_ref(), &args);
                    assert_eq!(output.status.code(), Some(1));
                    assert!(String::from_utf8_lossy(&output.stderr)
                        .contains("gateway flags cannot be used"));
                }
            }
        }
        if let Some(peer) = &peer {
            assert!(peer.observed.lock().unwrap().is_empty());
        }
        drop(peer);
        let store = open_leased_store(&vault.data_dir, &vault.key_path);
        assert_eq!(store.audit_tip().unwrap(), before.0);
        assert_eq!(store.gateway_settings(ID).unwrap(), before.1);
        for id in [ID, ordinary] {
            assert_eq!(
                store.get(id).unwrap().payload.expose(),
                b"gateway-key-canary"
            );
            assert_eq!(store.meta(id).unwrap().record_version, 1);
        }
    }
}

#[test]
fn gateway_put_replace_keeps_settings_kind_refusals_are_atomic_and_recreation_drops_them() {
    for online in [false, true] {
        let vault = GrantCliVault::new("gateway-replace");
        vault.bootstrap();
        succeeded(vault.run(&put_args(ID, &payload_file("original-key"))));
        let settings = open_leased_store(&vault.data_dir, &vault.key_path)
            .gateway_settings(ID)
            .unwrap();
        let peer = online.then(|| ProviderRoutePeer::start(&vault));
        let file = payload_file("rotated-key");
        succeeded(run(
            &vault,
            peer.as_ref(),
            &["put", "--id", ID, "--payload-file", &file, "--replace"],
        ));
        drop(peer);
        let (tip, hash, incarnation) = {
            let store = open_leased_store(&vault.data_dir, &vault.key_path);
            assert_eq!(store.gateway_settings(ID).unwrap(), settings);
            assert_eq!(store.get(ID).unwrap().payload.expose(), b"rotated-key");
            let meta = store.meta(ID).unwrap();
            assert_eq!(meta.record_version, 2);
            assert_eq!(meta.categories, ["llm-gateway"]);
            assert_eq!(meta.provider_ids, [PROVIDER]);
            (
                store.audit_tip().unwrap(),
                credentials_core::store::payload_hash(b"rotated-key"),
                meta.incarnation,
            )
        };
        let peer = online.then(|| ProviderRoutePeer::start(&vault));
        let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
        for mode in [vec!["--replace"], vec!["--expected-hash", &hex]] {
            let mut args = vec!["put", "--id", ID, "--payload-file", &file, "--kind", "dsn"];
            args.extend(mode);
            let output = run(&vault, peer.as_ref(), &args);
            assert!(!output.status.success());
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                stderr.contains("gateway_fixed") && stderr.contains("rule=kind"),
                "{stderr}"
            );
        }
        drop(peer);
        {
            let store = open_leased_store(&vault.data_dir, &vault.key_path);
            assert_eq!(store.audit_tip().unwrap(), tip);
            assert_eq!(store.gateway_settings(ID).unwrap(), settings);
            assert_eq!(store.get(ID).unwrap().payload.expose(), b"rotated-key");
            assert_eq!(store.meta(ID).unwrap().record_version, 2);
        }
        succeeded(vault.run(&["remove", "--id", ID]));
        succeeded(vault.run(&["put", "--id", ID, "--payload-file", &file]));
        let store = open_leased_store(&vault.data_dir, &vault.key_path);
        assert!(store.gateway_settings(ID).unwrap().is_none());
        let meta = store.meta(ID).unwrap();
        assert_ne!(meta.incarnation, incarnation);
        assert!(meta.provider_ids.is_empty());
        assert!(!meta.categories.contains(&"llm-gateway".to_string()));
    }
}

#[test]
fn gateway_put_help_lists_settings_and_keeps_lines_under_eighty_columns() {
    let output = cli().args(["help", "put"]).output().unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    for flag in [
        "--gateway-base-url",
        "--gateway-auth-header",
        "--gateway-auth-scheme",
        "--gateway-header",
    ] {
        assert!(help.contains(flag), "{help}");
    }
    assert!(
        help.lines().all(|line| line.chars().count() <= 80),
        "{help}"
    );
}
