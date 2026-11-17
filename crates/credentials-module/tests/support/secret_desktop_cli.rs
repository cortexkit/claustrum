use super::*;

#[test]
fn dev_desktop_approvals_cli_setting_is_persisted_and_audited() {
    let vault = GrantCliVault::new("desktop-approvals-setting");
    let ok = |args: &[&str]| {
        let out = vault.run(args);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    };
    assert_eq!(
        ok(&["secret", "dev-desktop-approvals", "status"]),
        "dev-desktop-approvals setting off\n"
    );
    vault.bootstrap();
    for action in ["off", "on", "on", "off", "off"] {
        assert_eq!(
            ok(&["secret", "dev-desktop-approvals", action]),
            format!("dev-desktop-approvals setting {action}\n")
        );
        assert_eq!(
            ok(&["secret", "dev-desktop-approvals", "status"]),
            format!("dev-desktop-approvals setting {action}\n")
        );
    }
    let conn = rusqlite::Connection::open(vault.data_dir.join("store.db")).unwrap();
    let changes: i64 = conn
        .query_row(
            "SELECT count(*) FROM audit_log WHERE op='secret_dev_desktop_approvals_set'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(changes, 2);
    if std::env::var_os(CLI_BIN_ENV).is_none() {
        let peer = ProviderRoutePeer::start(&vault);
        let out = cli()
            .args(["secret", "dev-desktop-approvals", "on", "--data-dir"])
            .arg(&vault.data_dir)
            .arg("--key-path")
            .arg(&vault.key_path)
            .arg("--subc")
            .arg(&peer.connection)
            .env("CORTEXKIT_TEST_BYPASS_VALIDATION", "1")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            ok(&["secret", "dev-desktop-approvals", "status"]),
            "dev-desktop-approvals setting on\n"
        );
        assert_eq!(
            peer.observed
                .lock()
                .unwrap()
                .iter()
                .filter(|v| v["op"] == "admin.secret_dev_desktop_approvals_set")
                .count(),
            1
        );
    }
    assert!(!vault
        .run(&["secret", "dev-desktop-approvals", "bogus"])
        .status
        .success());
}
