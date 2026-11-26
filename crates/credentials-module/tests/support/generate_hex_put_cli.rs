use super::*;

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

fn assert_no_payload(output: &std::process::Output, payload: &[u8]) {
    assert!(
        !output.stdout.windows(payload.len()).any(|w| w == payload),
        "payload appeared on stdout"
    );
    assert!(
        !output.stderr.windows(payload.len()).any(|w| w == payload),
        "payload appeared on stderr"
    );
}

#[test]
fn generate_hex_put_creates_distinct_unprinted_payloads_online_and_offline() {
    let first = "opaque:broca-deployment:1";
    let second = "opaque:broca-deployment:2";
    for online in [false, true] {
        let vault = GrantCliVault::new("generate-hex-put");
        vault.bootstrap();
        let peer = online.then(|| ProviderRoutePeer::start(&vault));
        let put = |id| {
            run(
                &vault,
                peer.as_ref(),
                &[
                    "put",
                    "--id",
                    id,
                    "--kind",
                    "opaque",
                    "--generate-hex",
                    "32",
                ],
            )
        };
        let a = put(first);
        let b = put(second);
        for (out, id) in [(&a, first), (&b, second)] {
            assert!(
                out.status.success(),
                "generated put failed (online={online})"
            );
            assert!(out.stdout == format!("created {id}\n").as_bytes());
        }
        let duplicate = put(first);
        let file = payload_file("unused-replacement-canary");
        let ordinary_duplicate = run(
            &vault,
            peer.as_ref(),
            &[
                "put",
                "--id",
                first,
                "--kind",
                "opaque",
                "--payload-file",
                &file,
            ],
        );
        assert_eq!(duplicate.status.code(), Some(1));
        assert_eq!(duplicate.status, ordinary_duplicate.status);
        assert!(duplicate.stdout.is_empty());
        assert!(duplicate.stderr == ordinary_duplicate.stderr);
        assert!(String::from_utf8_lossy(&duplicate.stderr).contains("already exists"));

        if let Some(peer) = &peer {
            let ops = peer.observed.lock().unwrap();
            assert_eq!(ops.iter().filter(|op| op["op"] == "admin.store").count(), 4);
        }
        drop(peer);
        let store = open_leased_store(&vault.data_dir, &vault.key_path);
        let a_record = store.get(first).unwrap();
        let b_record = store.get(second).unwrap();
        let audit = vault.run(&["audit"]);
        assert!(audit.status.success());
        assert_eq!(
            store
                .read_audit(None)
                .unwrap()
                .iter()
                .filter(|row| row.op == "put")
                .count(),
            2
        );
        for (out, record) in [(&a, &a_record), (&b, &b_record)] {
            let value = record.payload.expose();
            assert_eq!(record.kind, CredentialKind::Opaque);
            assert_eq!(record.record_version, 1);
            assert_hex(value, 32);
            assert_no_payload(out, value);
            assert_no_payload(&duplicate, value);
            assert_no_payload(&audit, value);
        }
        assert!(a_record.payload != b_record.payload);
    }
}

fn assert_hex(value: &[u8], random_bytes: usize) {
    assert_eq!(value.len(), 2 * random_bytes);
    assert!(value.iter().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
}

#[test]
fn generate_hex_put_accepts_16_through_256_bytes_only() {
    let vault = GrantCliVault::new("generate-hex-bounds");
    vault.bootstrap();
    for (id, size, accepted) in [
        ("apikey:openai:below-min", "15", false),
        ("apikey:openai:at-min", "16", true),
        ("apikey:openai:at-max", "256", true),
        ("apikey:openai:above-max", "257", false),
    ] {
        let out = vault.run(&[
            "put",
            "--id",
            id,
            "--kind",
            "api_key",
            "--generate-hex",
            size,
        ]);
        let store = open_leased_store(&vault.data_dir, &vault.key_path);
        if accepted {
            assert!(out.status.success(), "size {size} should be accepted");
            let record = store.get(id).unwrap();
            assert_eq!(record.kind, CredentialKind::ApiKey);
            assert_hex(record.payload.expose(), size.parse().unwrap());
            assert_no_payload(&out, record.payload.expose());
        } else {
            assert_eq!(out.status.code(), Some(1));
            assert!(String::from_utf8_lossy(&out.stderr).contains("16 to 256"));
            assert!(matches!(
                store.get(id),
                Err(credentials_core::store::StoreOpError::NotFound)
            ));
        }
    }
}

#[test]
fn generate_hex_put_refuses_incompatible_options_without_writing() {
    let vault = GrantCliVault::new("generate-hex-conflicts");
    vault.bootstrap();
    let before = open_leased_store(&vault.data_dir, &vault.key_path)
        .audit_tip()
        .unwrap();
    let file = payload_file("unused-input-canary");
    let hash = "0".repeat(64);
    for (flags, reason) in [
        (&["--id", "opaque:conflict", "--replace"][..], "--replace"),
        (
            &["--id", "opaque:conflict", "--expected-hash", &hash],
            "--expected-hash",
        ),
        (
            &["--id", "opaque:conflict", "--payload-file", &file],
            "--payload-file",
        ),
        (&["--id", "opaque:conflict", "--kind", "dsn"], "api_key"),
        (&["--id", "cookie:localhost:fixture"], "cookie"),
        (
            &["--id", "github_app:fixture", "--client-id", "fixture"],
            "github_app",
        ),
        (
            &["--id", "opaque:conflict", "--gateway-auth-scheme", "raw"],
            "gateway",
        ),
        (&["--kind", "opaque"], "--id"),
    ] {
        let mut args = vec!["put", "--generate-hex", "32"];
        args.extend_from_slice(flags);
        let out = vault.run(&args);
        assert_eq!(out.status.code(), Some(1));
        assert!(out.stdout.is_empty());
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("--generate-hex") && err.contains(reason));
    }
    let store = open_leased_store(&vault.data_dir, &vault.key_path);
    assert_eq!(store.audit_tip().unwrap(), before);
}

#[test]
fn put_with_categories_replaces_defaults_and_is_reached_by_a_grant() {
    let generated = "opaque:broca-deployment:1";
    let from_file = "apikey:openrouter:explicit";
    let plain = "apikey:openrouter:default";
    let file = payload_file("categorized-file-canary");
    for online in [false, true] {
        let vault = GrantCliVault::new("put-explicit-categories");
        vault.bootstrap();
        let peer = online.then(|| ProviderRoutePeer::start(&vault));
        for (args, id) in [
            (
                &[
                    "put",
                    "--id",
                    generated,
                    "--kind",
                    "opaque",
                    "--generate-hex",
                    "32",
                    "--category",
                    "broca-deployment",
                ][..],
                generated,
            ),
            (
                &[
                    "put",
                    "--id",
                    from_file,
                    "--payload-file",
                    &file,
                    "--category",
                    "zulu",
                    "--category",
                    "alpha",
                    "--category",
                    "alpha",
                ],
                from_file,
            ),
            (&["put", "--id", plain, "--payload-file", &file], plain),
        ] {
            let out = run(&vault, peer.as_ref(), args);
            assert!(out.status.success(), "put {id} failed (online={online})");
            assert!(out.stdout == format!("created {id}\n").as_bytes());
        }
        if let Some(peer) = &peer {
            let ops = peer.observed.lock().unwrap();
            assert_eq!(
                ops.iter()
                    .filter(|op| op["op"] == "admin.store_with_categories")
                    .count(),
                2
            );
            assert_eq!(ops.iter().filter(|op| op["op"] == "admin.store").count(), 1);
            assert!(!ops.iter().any(|op| op["op"] == "admin.set_category"));
        }
        drop(peer);
        {
            let store = open_leased_store(&vault.data_dir, &vault.key_path);
            assert_eq!(
                store.meta(generated).unwrap().categories,
                ["broca-deployment"]
            );
            assert_eq!(store.meta(from_file).unwrap().categories, ["alpha", "zulu"]);
            assert_eq!(store.meta(plain).unwrap().categories, ["llm-provider"]);
            let generated = store.get(generated).unwrap();
            assert_hex(generated.payload.expose(), 32);
            assert!(store.get(from_file).unwrap().payload.expose() == b"categorized-file-canary");
            let audit = store.read_audit(None).unwrap();
            let rows: Vec<_> = audit
                .iter()
                .filter(|row| row.op == "put" || row.op == "set_category")
                .map(|row| (row.op.as_str(), row.credential_id.as_deref().unwrap()))
                .collect();
            assert_eq!(
                rows,
                [
                    ("put", "opaque:broca-deployment:1"),
                    (
                        "set_category",
                        "category:opaque:broca-deployment:1|broca-deployment"
                    ),
                    ("put", from_file),
                    (
                        "set_category",
                        "category:apikey:openrouter:explicit|alpha,zulu"
                    ),
                    ("put", plain),
                ]
            );
        }
        let (ok, _, _) = grant_on(
            &vault,
            "reserved:broca",
            "category",
            "broca-deployment",
            "read",
        );
        assert!(ok);
        let grants = vault.run(&["grants"]);
        assert!(grants.status.success());
        let grants = String::from_utf8(grants.stdout).unwrap();
        assert!(
            grants.lines().any(|row| {
                row.split_whitespace().skip(1).take(5).eq([
                    "broca",
                    "category",
                    "broca-deployment",
                    "read",
                    "1",
                ])
            }),
            "missing one-credential reach in grants table: {grants}"
        );
    }
}

#[test]
fn put_with_categories_refuses_bad_names_and_incompatible_options_without_writing() {
    let vault = GrantCliVault::new("put-category-refused");
    vault.bootstrap();
    let before = open_leased_store(&vault.data_dir, &vault.key_path)
        .audit_tip()
        .unwrap();
    let file = payload_file("refused-category-canary");
    let hash = "0".repeat(64);
    for (flags, reason) in [
        (&["--id", "opaque:conflict", "--category", "Bad"][..], "Bad"),
        (&["--id", "opaque:conflict", "--replace"], "--replace"),
        (
            &["--id", "opaque:conflict", "--expected-hash", &hash],
            "--expected-hash",
        ),
        (&["--id", "cookie:localhost:fixture"], "cookie"),
        (
            &["--id", "github_app:fixture", "--client-id", "fixture"],
            "github_app",
        ),
        (
            &["--id", "opaque:conflict", "--gateway-auth-scheme", "raw"],
            "gateway",
        ),
    ] {
        let mut args = vec![
            "put",
            "--payload-file",
            &file,
            "--category",
            "broca-deployment",
        ];
        args.extend_from_slice(flags);
        let out = vault.run(&args);
        assert_eq!(out.status.code(), Some(1));
        assert!(out.stdout.is_empty());
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains(reason), "unexpected refusal: {err}");
    }
    let store = open_leased_store(&vault.data_dir, &vault.key_path);
    assert!(store.list_meta().unwrap().is_empty());
    assert_eq!(store.audit_tip().unwrap(), before);
}
