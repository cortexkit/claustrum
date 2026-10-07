use credentials_core::test_support::ckdev_command;

fn login(args: &[&str]) -> std::process::Output {
    ckdev_command(env!("CARGO_BIN_EXE_ck-auth"))
        .arg("login")
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap()
}

#[test]
fn gmail_client_flags_are_required_before_vault_or_network_access() {
    for (args, missing) in [
        (vec!["--provider", "gmail"], "--client-id"),
        (
            vec!["--provider", "gmail", "--client-id", "test-client-id"],
            "--client-secret-file",
        ),
        (
            vec!["--provider", "gmail", "--client-secret-file", "not-read"],
            "--client-id",
        ),
    ] {
        let out = login(&args);
        assert_eq!(out.status.code(), Some(1)); // the CLI's usage status
        let error = String::from_utf8_lossy(&out.stderr);
        assert!(
            error.contains(&format!("gmail requires {missing}")),
            "{error}"
        );
        assert!(
            error.contains(
                "ck auth login --provider gmail --client-id <id> --client-secret-file <path>"
            ),
            "{error}"
        );
        assert!(out.stdout.is_empty(), "must not start a browser login");
    }
}

#[test]
fn non_gmail_providers_refuse_either_client_flag_before_any_login() {
    for provider in credentials_core::catalog::LOGIN_PROVIDERS
        .iter()
        .map(|p| p.key)
        .chain(
            credentials_core::catalog::API_KEY_PROVIDERS
                .iter()
                .map(|p| p.key),
        )
        .filter(|p| *p != "gmail")
    {
        for flag in ["--client-id", "--client-secret-file"] {
            let out = login(&["--provider", provider, flag, "test-value"]);
            assert_eq!(out.status.code(), Some(1), "{provider} {flag}");
            let error = String::from_utf8_lossy(&out.stderr);
            assert!(
                error.contains(
                    "--client-id and --client-secret-file are only supported for --provider gmail"
                ),
                "{provider} {flag}: {error}"
            );
            assert!(out.stdout.is_empty());
        }
    }
}
