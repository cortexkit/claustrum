use std::{
    collections::HashMap,
    ops::Deref,
    path::{Path, PathBuf},
    process::Command,
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex,
    },
};

use sha2::{Digest, Sha256};

/// Execute test artifacts under a development-only filename, without changing the
/// built or staged artifact.
///
/// The development name is a COPY, not a hard link. On a loaded macOS host, a
/// fresh hard link to cargo's binary was SIGKILLed at exec often enough to fail
/// one `cli_admin` run in three (signal 9, empty stderr), while copies were not
/// killed. The copy is content-addressed and published once by atomic rename, so
/// every later call, in this process or another, executes the same settled file
/// instead of creating a new path per spawn.
///
/// The copy lives in a `ckdev-exec` directory beside the artifact, inside cargo's
/// target directory, so cleaning the target removes it; a copy in the system temp
/// directory would outlive every rebuild.
pub fn ckdev_binary(src: &Path) -> PathBuf {
    /// Source artifact -> (length, mtime, published copy) for the build last copied.
    type Published = HashMap<PathBuf, (u64, std::time::SystemTime, PathBuf)>;
    static PUBLISHED: Mutex<Option<Published>> = Mutex::new(None);
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);

    let meta = std::fs::metadata(src)
        .unwrap_or_else(|e| panic!("stat test binary {}: {e}", src.display()));
    let modified = meta.modified().expect("test binary mtime");
    let mut published = PUBLISHED.lock().unwrap_or_else(|e| e.into_inner());
    let published = published.get_or_insert_with(HashMap::new);
    // A rebuild changes length or mtime, so the memo never serves a stale copy.
    if let Some((len, at, dst)) = published.get(src) {
        if *len == meta.len() && *at == modified && dst.exists() {
            return dst.clone();
        }
    }

    let name = src
        .file_name()
        .expect("binary filename")
        .to_str()
        .expect("UTF-8 binary name");
    let name = name
        .strip_prefix("ck-")
        .or_else(|| name.strip_prefix("ckdev-"))
        .unwrap_or(name);
    let bytes =
        std::fs::read(src).unwrap_or_else(|e| panic!("read test binary {}: {e}", src.display()));
    let digest = Sha256::digest(&bytes);
    let hash: String = digest[..8].iter().map(|b| format!("{b:02x}")).collect();
    let dir = src
        .parent()
        .expect("binary parent directory")
        .join("ckdev-exec")
        .join(hash);
    std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("create {}: {e}", dir.display()));
    let dst = dir.join(format!("ckdev-{name}"));
    if !dst.exists() {
        let tmp = dir.join(format!(
            ".ckdev-{name}.{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        // fs::copy carries the permission bits; the ad-hoc signature is in the file.
        std::fs::copy(src, &tmp)
            .unwrap_or_else(|e| panic!("copy test binary {}: {e}", src.display()));
        // Another process may publish the same content first; replacing it with
        // identical bytes is harmless, and the rename keeps the path whole either way.
        std::fs::rename(&tmp, &dst)
            .unwrap_or_else(|e| panic!("publish test binary {}: {e}", dst.display()));
    }
    published.insert(src.to_path_buf(), (meta.len(), modified, dst.clone()));
    dst
}

/// A `Command` for a test artifact, run under its development name.
pub fn ckdev_command(src: impl AsRef<Path>) -> Command {
    Command::new(ckdev_binary(src.as_ref()))
}

/// A test-owned directory that is removed when its owner leaves scope.
#[derive(Debug)]
pub struct TestTempDir {
    path: Option<PathBuf>,
}

impl TestTempDir {
    pub fn new(name: impl AsRef<str>) -> Self {
        let path = std::env::temp_dir().join(name.as_ref());
        Self::from_path(path)
    }

    pub fn from_path(path: PathBuf) -> Self {
        // A reused PID can collide with an orphaned test directory; refuse rather than
        // silently inherit a vault whose store and key material may not belong together.
        std::fs::create_dir(&path)
            .unwrap_or_else(|e| panic!("create test temp directory {}: {e}", path.display()));
        Self { path: Some(path) }
    }

    pub fn path(&self) -> &Path {
        self.path.as_deref().expect("test temp directory was kept")
    }

    /// Preserve evidence only when it must outlive this guard; current crash-cut tests do not.
    pub fn keep(mut self) -> PathBuf {
        self.path
            .take()
            .expect("test temp directory was already kept")
    }
}

impl Deref for TestTempDir {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        self.path()
    }
}

impl AsRef<Path> for TestTempDir {
    fn as_ref(&self) -> &Path {
        self.path()
    }
}

impl Drop for TestTempDir {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = std::fs::remove_dir_all(path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ckdev_binary, TestTempDir};

    #[test]
    fn development_copies_keep_names_and_artifacts_separate_and_are_reused() {
        let dir = TestTempDir::new(format!("ckdev-copy-test-{}", std::process::id()));
        let src = dir.join("ck-auth.exe");
        std::fs::write(&src, b"first artifact").unwrap();
        let first = ckdev_binary(&src);
        assert_eq!(first.file_name().unwrap(), "ckdev-auth.exe");
        assert_eq!(std::fs::read(&first).unwrap(), b"first artifact");
        // A copy, never a hard link: a fresh link to cargo's binary is what got
        // SIGKILLed at exec under load.
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_ne!(
                std::fs::metadata(&src).unwrap().ino(),
                std::fs::metadata(&first).unwrap().ino()
            );
        }
        // The same artifact is executed from one settled path, not a new one per call.
        assert_eq!(ckdev_binary(&src), first);

        let other = dir.join("other");
        std::fs::create_dir(&other).unwrap();
        let src2 = other.join("ck-auth.exe");
        std::fs::write(&src2, b"second artifact").unwrap();
        let second = ckdev_binary(&src2);
        assert_ne!(first, second);
        assert_eq!(std::fs::read(&second).unwrap(), b"second artifact");
        assert_eq!(std::fs::read(&first).unwrap(), b"first artifact");

        // A rebuild in place must not be served the previous build's copy.
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(&src, b"rebuilt artifact").unwrap();
        let rebuilt = ckdev_binary(&src);
        assert_ne!(rebuilt, first);
        assert_eq!(std::fs::read(&rebuilt).unwrap(), b"rebuilt artifact");
    }

    #[test]
    fn keep_disarms_removal() {
        // The crash-cut suites still pass if keep() is broken because they inspect before
        // their guards drop. This focused test is the only coverage that detects a clone
        // here instead of take(), which would leave Drop armed and erase kept evidence.
        let path = TestTempDir::new("ck-cred-test-support-keep").keep();
        assert!(path.exists(), "keep must leave crash-cut evidence behind");
        std::fs::remove_dir_all(path).expect("remove kept test directory");
    }

    #[test]
    fn drop_removes_directory() {
        let path = {
            let dir = TestTempDir::new("ck-cred-test-support-drop");
            dir.path().to_path_buf()
        };
        assert!(!path.exists(), "drop must remove the test directory");
    }
}
