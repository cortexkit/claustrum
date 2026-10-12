/// Stop other processes running as the same user from reading or altering the
/// vault's memory. Called first in `main` of both binaries, before any secret is
/// read; a failure stops startup, so the vault never runs unprotected by accident.
///
/// Linux: the process becomes non-dumpable, which refuses same-user ptrace attach,
/// `/proc/<pid>/mem` reads and core dumps. It also makes `/proc/<pid>/exe`, `fd/`,
/// `environ` and `maps` unreadable to same-user processes; the supervisor handles
/// non-dumpable modules without reading those paths.
///
/// Windows: the process replaces its own DACL with one granting the user only
/// query-limited information, synchronize and terminate, which are the rights the
/// supervisor uses. Memory read and write, thread creation, handle duplication and
/// DACL changes are refused, including to the vault's own user. A process with
/// `SeDebugPrivilege` enabled, such as an elevated administrator, still gets in.
///
/// macOS: nothing here; the hardened runtime signature does this job.
pub fn harden_process() -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)?;
    #[cfg(windows)]
    subc_os::windows_acl::restrict_current_process()?;
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
