#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
#[path = "support/isolated_cli.rs"]
mod isolated_cli;

#[cfg(target_os = "linux")]
mod linux {
    use cortexkit_test_support::{ckdev_binary, dev_command};
    use std::io::{BufRead, BufReader};
    use std::process::{Child, Command, Stdio};
    use std::time::Duration;

    struct ReapedChild(Child);

    impl Drop for ReapedChild {
        fn drop(&mut self) {
            // Also reap children when an assertion fails, rather than leaving a
            // login process blocked on stdin or a control process running.
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    pub(super) fn ck_auth_process_is_non_dumpable() {
        let mut command = dev_command(ckdev_binary(env!("CARGO_BIN_EXE_ck-auth")));
        super::isolated_cli::isolate(&mut command);
        super::isolated_cli::assert_isolated(&command);

        // With no account, Snowflake login prompts before accessing the vault or
        // opening a callback listener. An empty EOF is invalid, so closing stdin
        // ends the command without entering the network or vault paths.
        let mut auth = ReapedChild(
            command
                .args(["login", "--provider", "snowflake"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn isolated ck-auth"),
        );
        let stdout = auth.0.stdout.take().unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut line = String::new();
            let result = BufReader::new(stdout).read_line(&mut line).map(|_| line);
            let _ = sender.send(result);
        });
        let prompt = receiver
            .recv_timeout(Duration::from_secs(10))
            .expect("ck-auth must reach the stdin prompt")
            .expect("read ck-auth prompt");
        assert_eq!(prompt.trim(), "Snowflake account identifier:");
        assert!(auth.0.try_wait().unwrap().is_none(), "ck-auth exited early");

        let control = ReapedChild(
            Command::new("sleep")
                .arg("30")
                .spawn()
                .expect("spawn dumpable control"),
        );
        assert!(
            std::fs::read_link(format!("/proc/{}/exe", control.0.id())).is_ok(),
            "the same-user control image must be readable",
        );
        let mountinfo =
            std::fs::read_to_string("/proc/self/mountinfo").expect("read procfs mount options");
        let super_options = mountinfo
            .lines()
            .find_map(|line| {
                let (mount, filesystem) = line.split_once(" - ")?;
                let mut filesystem = filesystem.split_whitespace();
                if mount.split_whitespace().nth(4)? != "/proc" || filesystem.next()? != "proc" {
                    return None;
                }
                filesystem.next()?;
                filesystem.next()
            })
            .expect("find /proc super options");
        let hides_non_dumpable = super_options
            .split(',')
            .any(|option| matches!(option, "hidepid=invisible" | "hidepid=2"));
        let image = std::fs::read_link(format!("/proc/{}/exe", auth.0.id()));
        assert!(
            auth.0.try_wait().unwrap().is_none(),
            "ck-auth must still be alive when its image is read (procfs: {super_options})",
        );

        drop(auth.0.stdin.take());
        let status = auth.0.wait().expect("reap ck-auth after EOF");
        assert!(!status.success(), "empty Snowflake account must be refused");
        let error = image.expect_err(&format!(
            "a non-dumpable ck-auth image must be unreadable (procfs: {super_options})"
        ));
        // hidepid=2 hides the whole non-dumpable process directory; ordinary
        // procfs exposes the directory but refuses access to its image link.
        assert!(
            error.kind() == std::io::ErrorKind::PermissionDenied
                || (hides_non_dumpable && error.kind() == std::io::ErrorKind::NotFound),
            "unexpected image error {error:?} (procfs: {super_options})",
        );
    }
}

#[test]
fn ck_auth_process_is_non_dumpable() {
    #[cfg(target_os = "linux")]
    linux::ck_auth_process_is_non_dumpable();
    #[cfg(not(target_os = "linux"))]
    eprintln!("SKIPPING: process dumpability is Linux-only");
}

/// The text after a `main` signature. Source scans run on every OS: the hardening
/// call is platform-specific, but the order of statements in `main` is not.
fn main_body<'a>(source: &'a str, signature: &str) -> &'a str {
    let (_, body) = source.split_once(signature).expect("main signature exists");
    body.trim_start()
}

#[test]
fn ck_auth_hardens_before_any_other_main_statement() {
    assert!(
        main_body(
            include_str!("../src/bin/credentials_cli.rs"),
            "fn main() -> ExitCode {",
        )
        .starts_with("if let Err(error) = credentials_core::harden_process() {"),
        "ck-auth must fail closed on process hardening as main's first statement",
    );
}

#[test]
fn ck_claustrum_hardens_before_any_other_main_statement() {
    assert!(
        main_body(
            include_str!("../src/main.rs"),
            "async fn main() -> Result<(), ModuleError> {",
        )
        .starts_with("credentials_core::harden_process()"),
        "ck-claustrum must harden the process as main's first statement",
    );
}

/// `harden_process` must apply each platform's protection and propagate its error,
/// so dropping either line, or swallowing a failure with `.ok()`, fails here.
#[test]
fn harden_process_applies_the_linux_and_windows_protections() {
    // A Windows checkout may have CRLF line endings, so compare on LF.
    let source =
        include_str!("../../credentials-core/src/process_hardening.rs").replace("\r\n", "\n");
    let (_, body) = source
        .split_once("pub fn harden_process() -> std::io::Result<()> {")
        .expect("harden_process exists");
    let body = &body[..body.find("\n}\n").expect("harden_process ends")];
    for (platform, call) in [
        (
            "linux",
            "#[cfg(target_os = \"linux\")]\n    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)?;",
        ),
        (
            "windows",
            "#[cfg(windows)]\n    subc_os::windows_acl::restrict_current_process()?;",
        ),
    ] {
        assert!(body.contains(call), "harden_process must apply the {platform} protection and propagate its error");
    }
}
