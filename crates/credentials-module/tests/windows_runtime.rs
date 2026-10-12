//! Real Windows operator workflows, including open SQLite/WAL handles beside a
//! writer. The explicit CI arm enables the debug-only rendezvous seams; wrappers
//! remain registered on every OS so the workspace test floor is platform-neutral.
#![forbid(unsafe_code)]

#[cfg(all(windows, feature = "windows-runtime-test-seam"))]
#[path = "support/isolated_cli.rs"]
mod isolated_cli;

#[cfg(all(windows, feature = "windows-runtime-test-seam"))]
mod native {
    use cortexkit_test_support::{ckdev_binary, dev_command};
    use std::{
        io::{BufRead, BufReader, Read, Write},
        path::{Path, PathBuf},
        process::{Child, Command, Output, Stdio},
        sync::mpsc::{self, Receiver},
        thread::{self, JoinHandle},
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };
    use subc_os::windows_acl::{self, test_support::assert_dacl_owner_only};

    const TIMEOUT: Duration = Duration::from_secs(60);
    const PAUSE_ENV: &str = "CK_AUTH_WINDOWS_RUNTIME_TEST_PAUSE";

    struct Vault {
        root: PathBuf,
        data: PathBuf,
        key: PathBuf,
    }

    impl Vault {
        fn new(tag: &str) -> Self {
            if !cfg!(debug_assertions) {
                panic!("Windows runtime seams require a debug binary");
            }
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let root = super::isolated_cli::scratch_home().join(format!(
                "windows-runtime-{tag}-{}-{nonce}",
                std::process::id()
            ));
            windows_acl::create_private_dir(&root).expect("create private test parent");
            Self {
                data: root.join("vault"),
                key: root.join("master.key"),
                root,
            }
        }

        fn command(&self, args: &[&str]) -> Command {
            let mut command = dev_command(ckdev_binary(env!("CARGO_BIN_EXE_ck-auth")));
            super::isolated_cli::isolate(&mut command);
            command
                .env_remove(PAUSE_ENV)
                .args(args)
                .arg("--data-dir")
                .arg(&self.data)
                .arg("--key-path")
                .arg(&self.key);
            super::isolated_cli::assert_isolated(&command);
            command
        }

        fn run(&self, args: &[&str]) -> Output {
            Running::spawn(self.command(args), None).finish()
        }

        fn ok(&self, args: &[&str]) -> String {
            let out = self.run(args);
            assert!(out.status.success(), "ck-auth {args:?}: {}", describe(&out));
            self.assert_custody();
            String::from_utf8(out.stdout).unwrap()
        }

        fn paused(&self, args: &[&str], point: &str) -> Running {
            let mut command = self.command(args);
            command.env(PAUSE_ENV, point);
            let mut running = Running::spawn(command, Some(point));
            if let Err(error) = running.ready.recv_timeout(TIMEOUT) {
                let _ = running.child.kill();
                let out = running.finish();
                panic!(
                    "ck-auth never reached {point}: {error}; operation {args:?}: {}",
                    describe(&out)
                );
            }
            assert!(
                self.data.join("store.db-wal").is_file(),
                "the writer must really be in WAL mode"
            );
            assert!(
                self.data.join("store.db-shm").is_file(),
                "the shared-memory sibling must exist"
            );
            self.assert_custody();
            running
        }

        fn bootstrap(&self) {
            assert!(self
                .ok(&["bootstrap"])
                .contains("provisioned a new master key"));
            for path in [
                &self.key,
                &self.data.join("key-source"),
                &self.data.join("store.db"),
            ] {
                assert!(
                    path.is_file(),
                    "bootstrap did not create {}",
                    path.display()
                );
            }
        }

        fn put(&self, id: &str, value: &str) {
            assert_eq!(
                self.ok(&["put", "--id", id, "--payload", value]).trim(),
                format!("created {id}")
            );
        }

        fn replace_key(&self, bytes: &[u8]) {
            let temporary = self.root.join("test-key-replacement");
            let mut file = windows_acl::create_private_file(&temporary).unwrap();
            file.write_all(bytes).unwrap();
            file.sync_all().unwrap();
            drop(file);
            std::fs::rename(&temporary, &self.key)
                .expect("replace the operator key at the same recorded path");
        }

        fn assert_custody(&self) {
            fn walk(path: &Path, paths: &mut Vec<(PathBuf, bool)>) {
                let kind = std::fs::symlink_metadata(path).unwrap().file_type();
                assert!(
                    kind.is_file() || kind.is_dir(),
                    "unexpected vault path: {}",
                    path.display()
                );
                paths.push((path.to_owned(), kind.is_dir()));
                if kind.is_dir() {
                    for entry in std::fs::read_dir(path).unwrap() {
                        walk(&entry.unwrap().path(), paths);
                    }
                }
            }
            let mut paths = Vec::new();
            walk(&self.root, &mut paths);

            // SQLite may create inherited, owner-only WAL/SHM DACLs on a read-only
            // open, whereas the shared store explicitly protects existing siblings.
            // Read only the protection bit here; the independent native assertion
            // below still checks every ACE against the current user's SID.
            let script = "$ErrorActionPreference='Stop'; $paths = [Console]::In.ReadToEnd() | ConvertFrom-Json; @($paths | ForEach-Object { (Get-Acl -LiteralPath $_).AreAccessRulesProtected }) | ConvertTo-Json -Compress";
            let mut command = Command::new("powershell.exe");
            command.args(["-NoProfile", "-NonInteractive", "-Command", script]);
            let mut probe = Running::spawn(command, None);
            let names: Vec<_> = paths.iter().map(|(path, _)| path).collect();
            probe
                .child
                .stdin
                .as_mut()
                .unwrap()
                .write_all(&serde_json::to_vec(&names).unwrap())
                .unwrap();
            drop(probe.child.stdin.take());
            let out = probe.finish();
            assert!(
                out.status.success(),
                "read DACL protection flags: {}",
                describe(&out)
            );
            let protected: Vec<bool> =
                serde_json::from_slice(&out.stdout).expect("DACL protection flags");
            assert_eq!(protected.len(), paths.len());
            for ((path, directory), protected) in paths.iter().zip(protected) {
                eprintln!("checking owner-only DACL: {}", path.display());
                assert_dacl_owner_only(path, *directory, protected);
            }
            for path in [
                &self.root,
                &self.data,
                &self.key,
                &self.data.join("key-source"),
            ] {
                if path.exists() {
                    assert_dacl_owner_only(path, path.is_dir(), true);
                }
            }
        }
    }

    impl Drop for Vault {
        fn drop(&mut self) {
            if let Err(error) = std::fs::remove_dir_all(&self.root) {
                eprintln!("Windows vault cleanup {}: {error}", self.root.display());
                assert!(
                    std::thread::panicking(),
                    "vault files could not be deleted after all CLI handles closed"
                );
            }
        }
    }

    fn describe(out: &Output) -> String {
        format!(
            "status={}\nstdout={}\nstderr={}",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    }

    // Drain both pipes while the child is running, bound all waits, and kill/reap
    // on unwind so a sharing/locking failure cannot hang CI or leak an open vault.
    struct Running {
        child: Child,
        ready: Receiver<()>,
        stdout: Option<JoinHandle<Vec<u8>>>,
        stderr: Option<JoinHandle<Vec<u8>>>,
    }

    impl Running {
        fn spawn(mut command: Command, point: Option<&str>) -> Self {
            command
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let mut child = command.spawn().expect("spawn Windows workflow process");
            let stdout = child.stdout.take().unwrap();
            let mut stderr = child.stderr.take().unwrap();
            let (tx, ready) = mpsc::channel();
            let marker = point.map(|p| format!("ck-auth Windows runtime test ready: {p}"));
            let stdout = thread::spawn(move || {
                let mut reader = BufReader::new(stdout);
                let mut bytes = Vec::new();
                loop {
                    let mut line = Vec::new();
                    if reader.read_until(b'\n', &mut line).unwrap() == 0 {
                        break;
                    }
                    if marker.as_deref() == Some(String::from_utf8_lossy(&line).trim()) {
                        let _ = tx.send(());
                    }
                    bytes.extend(line);
                }
                bytes
            });
            let stderr = thread::spawn(move || {
                let mut bytes = Vec::new();
                stderr.read_to_end(&mut bytes).unwrap();
                bytes
            });
            Self {
                child,
                ready,
                stdout: Some(stdout),
                stderr: Some(stderr),
            }
        }

        fn release(&mut self) {
            self.child
                .stdin
                .as_mut()
                .unwrap()
                .write_all(b"continue\n")
                .unwrap();
            drop(self.child.stdin.take());
        }

        fn finish(mut self) -> Output {
            let deadline = Instant::now() + TIMEOUT;
            let status = loop {
                if let Some(status) = self.child.try_wait().unwrap() {
                    break status;
                }
                if Instant::now() >= deadline {
                    self.child.kill().expect("kill timed-out CLI");
                    let status = self.child.wait().unwrap();
                    let out = Output {
                        status,
                        stdout: self.stdout.take().unwrap().join().unwrap(),
                        stderr: self.stderr.take().unwrap().join().unwrap(),
                    };
                    panic!(
                        "Windows operation timed out (possible sharing/locking failure): {}",
                        describe(&out)
                    );
                }
                thread::sleep(Duration::from_millis(10));
            };
            Output {
                status,
                stdout: self.stdout.take().unwrap().join().unwrap(),
                stderr: self.stderr.take().unwrap().join().unwrap(),
            }
        }
    }

    impl Drop for Running {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    pub fn bootstrap_put_remove() {
        let vault = Vault::new("bootstrap-remove");
        vault.bootstrap();
        vault.put("apikey:kept", "windows-static-secret");
        vault.put("apikey:removed", "remove-me");
        let before = vault.ok(&["list"]);
        assert!(
            before.contains("apikey:kept") && before.contains("apikey:removed"),
            "{before}"
        );
        assert!(
            !before.contains("windows-static-secret"),
            "list must not expose payloads"
        );
        assert!(vault
            .ok(&["remove", "--id", "apikey:removed"])
            .contains("removed apikey:removed"));
        let after = vault.ok(&["list"]);
        assert!(
            after.contains("apikey:kept") && !after.contains("apikey:removed"),
            "{after}"
        );
    }

    pub fn rotation() {
        let vault = Vault::new("rotation");
        vault.bootstrap();
        for (id, value) in [
            ("apikey:first", "first-secret"),
            ("apikey:second", "second-secret"),
            ("apikey:third", "third-secret"),
        ] {
            vault.put(id, value);
        }
        let old = std::fs::read(&vault.key).unwrap();
        let mut rotation = vault.paused(&["rotate-master-key"], "rotation-staged");
        let next = vault.root.join("master.key.next");
        assert_eq!(
            std::fs::read(&vault.key).unwrap(),
            old,
            "stage must not replace the current key"
        );
        let staged = std::fs::read(&next).expect("rotation must stage the next key file");
        assert_ne!(staged, old);
        rotation.release();
        let out = rotation.finish();
        assert!(
            out.status.success(),
            "rotation/promotion/rename failed: {}",
            describe(&out)
        );
        assert!(String::from_utf8_lossy(&out.stdout).contains("rotated master key to key_id"));
        assert!(
            !String::from_utf8_lossy(&out.stderr).contains("quarantined"),
            "{}",
            describe(&out)
        );
        assert_eq!(
            std::fs::read(&vault.key).unwrap(),
            staged,
            "promotion must publish the staged bytes"
        );
        assert!(!next.exists(), "promotion must delete the next slot");
        vault.assert_custody();

        // Keep the recorded key path unchanged: selecting another path would test
        // the key-source policy, not refusal of the old cryptographic key.
        vault.replace_key(&old);
        let refused = vault.run(&[
            "put",
            "--id",
            "apikey:old-key-must-not-write",
            "--payload",
            "must-not-land",
        ]);
        assert_eq!(
            refused.status.code(),
            Some(4),
            "old key was not refused: {}",
            describe(&refused)
        );
        assert!(
            String::from_utf8_lossy(&refused.stderr)
                .contains("no master key slot holds the key this vault is sealed under"),
            "{}",
            describe(&refused)
        );
        vault.replace_key(&staged);
        let usable = vault.ok(&["usable"]);
        assert!(
            usable.contains("serviceable: 3")
                && usable.contains("stranded: 0")
                && usable.contains("unreadable: 0"),
            "the new key must decrypt every envelope: {usable}"
        );
        let listed = vault.ok(&["list"]);
        for id in ["apikey:first", "apikey:second", "apikey:third"] {
            assert!(listed.contains(id), "rotation lost {id}: {listed}");
        }
        assert!(!listed.contains("apikey:old-key-must-not-write"));
        assert!(vault.ok(&["verify-audit"]).contains("intact"));
    }

    pub fn reader_and_writer() {
        let vault = Vault::new("reader-writer");
        vault.bootstrap();
        vault.put("apikey:before", "before-secret");
        let before = vault.ok(&["list"]);
        let mut writer = vault.paused(
            &["put", "--id", "apikey:after", "--payload", "after-secret"],
            "writer",
        );
        // This is the CLI's actual mode=ro connection, opened while the writer
        // owns the lease and WAL/SHM handles, not an in-process stand-in reader.
        let mut reader = vault.paused(&["list"], "reader");
        writer.release();
        let write = writer.finish();
        assert!(
            write.status.success(),
            "put beside mode=ro list was refused: {}",
            describe(&write)
        );
        assert!(String::from_utf8_lossy(&write.stdout).contains("created apikey:after"));
        vault.assert_custody();
        reader.release();
        let read = reader.finish();
        assert!(
            read.status.success(),
            "mode=ro list beside put was refused: {}",
            describe(&read)
        );
        let listed = String::from_utf8_lossy(&read.stdout);
        assert!(
            listed.contains("apikey:before"),
            "reader lost the old state: {listed}"
        );
        let snapshot = listed
            .lines()
            .filter(|line| *line != "ck-auth Windows runtime test ready: reader")
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        let after = vault.ok(&["list"]);
        assert!(after.contains("apikey:after"));
        assert!(
            snapshot == before || snapshot == after,
            "reader must see a complete old or new inventory, never a mixed state: {snapshot}"
        );
        assert!(!listed.contains("before-secret") && !listed.contains("after-secret"));
        vault.assert_custody();
    }

    pub fn second_writer() {
        let vault = Vault::new("second-writer");
        vault.bootstrap();
        vault.put("apikey:before", "before-secret");
        let mut first = vault.paused(
            &["put", "--id", "apikey:winner", "--payload", "winner-secret"],
            "writer",
        );
        let refused = vault.run(&["put", "--id", "apikey:loser", "--payload", "must-not-land"]);
        assert_eq!(
            refused.status.code(),
            Some(3),
            "second put must fail at the lease, not SQLite or file sharing: {}",
            describe(&refused)
        );
        assert!(
            String::from_utf8_lossy(&refused.stderr).contains("holds the single-writer lease"),
            "{}",
            describe(&refused)
        );
        assert!(
            !String::from_utf8_lossy(&refused.stderr).contains("panicked"),
            "{}",
            describe(&refused)
        );
        assert!(
            refused.stdout.is_empty(),
            "refused put must not report a commit: {}",
            describe(&refused)
        );
        eprintln!("concurrent put refusal: {}", describe(&refused));
        first.release();
        let committed = first.finish();
        assert!(
            committed.status.success(),
            "first put failed: {}",
            describe(&committed)
        );
        let listed = vault.ok(&["list"]);
        assert!(
            listed.contains("apikey:before")
                && listed.contains("apikey:winner")
                && !listed.contains("apikey:loser"),
            "{listed}"
        );
        let usable = vault.ok(&["usable"]);
        assert!(
            usable.contains("serviceable: 2") && usable.contains("unreadable: 0"),
            "{usable}"
        );
        assert!(vault.ok(&["verify-audit"]).contains("intact"));
    }
}

#[test]
fn windows_cli_bootstrap_put_remove_have_owner_only_custody() {
    #[cfg(all(windows, feature = "windows-runtime-test-seam"))]
    native::bootstrap_put_remove();
    #[cfg(not(all(windows, feature = "windows-runtime-test-seam")))]
    eprintln!("SKIPPING windows_cli_bootstrap_put_remove_have_owner_only_custody: requires Windows and windows-runtime-test-seam");
}

#[test]
fn windows_cli_rotation_promotes_key_file_and_rewraps_every_record() {
    #[cfg(all(windows, feature = "windows-runtime-test-seam"))]
    native::rotation();
    #[cfg(not(all(windows, feature = "windows-runtime-test-seam")))]
    eprintln!("SKIPPING windows_cli_rotation_promotes_key_file_and_rewraps_every_record: requires Windows and windows-runtime-test-seam");
}

#[test]
fn windows_cli_mode_ro_list_overlaps_a_real_put() {
    #[cfg(all(windows, feature = "windows-runtime-test-seam"))]
    native::reader_and_writer();
    #[cfg(not(all(windows, feature = "windows-runtime-test-seam")))]
    eprintln!("SKIPPING windows_cli_mode_ro_list_overlaps_a_real_put: requires Windows and windows-runtime-test-seam");
}

#[test]
fn windows_cli_second_put_is_refused_cleanly_by_the_writer_lease() {
    #[cfg(all(windows, feature = "windows-runtime-test-seam"))]
    native::second_writer();
    #[cfg(not(all(windows, feature = "windows-runtime-test-seam")))]
    eprintln!("SKIPPING windows_cli_second_put_is_refused_cleanly_by_the_writer_lease: requires Windows and windows-runtime-test-seam");
}
