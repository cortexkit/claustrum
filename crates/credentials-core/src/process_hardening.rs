/// Prevent same-user ptrace attachment, `/proc/<pid>/mem` reads, and core dumps
/// on Linux. On other operating systems this is a no-op.
///
/// Linux also makes `/proc/<pid>/exe`, `fd/`, `environ`, and `maps` unreadable to
/// same-user processes. This side effect is accepted: the supervisor handles
/// non-dumpable modules without reading those paths.
pub fn harden_process() -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn linux_process_becomes_non_dumpable() {
        #[cfg(target_os = "linux")]
        {
            const CHILD_ENV: &str = "CK_TEST_PROCESS_HARDENING_CHILD";
            const TEST_NAME: &str = "process_hardening::tests::linux_process_becomes_non_dumpable";
            if std::env::var_os(CHILD_ENV).is_some() {
                super::harden_process().expect("process hardening succeeds");
                assert_eq!(
                    rustix::process::dumpable_behavior().expect("read dumpable behavior"),
                    rustix::process::DumpableBehavior::NotDumpable,
                );
                return;
            }

            // Re-exec only this test so hardening cannot change the shared test
            // harness's dumpability or affect any other test's subprocesses.
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", TEST_NAME, "--nocapture"])
                .env(CHILD_ENV, "1")
                .output()
                .expect("spawn isolated hardening test");
            assert!(
                output.status.success()
                    && String::from_utf8_lossy(&output.stdout)
                        .contains("test result: ok. 1 passed;"),
                "isolated hardening test failed:\n{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
        }
        #[cfg(not(target_os = "linux"))]
        eprintln!("SKIPPING: process dumpability is Linux-only");
    }
}
