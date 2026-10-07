use std::{
    ops::Deref,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

/// Execute test artifacts under a development-only filename, without changing the
/// built or staged artifact. A hard link preserves the signed inode on macOS; a
/// copy also works when the scratch directory is on another filesystem.
pub fn ckdev_binary(src: &Path, scratch: &Path) -> PathBuf {
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let name = src
        .file_name()
        .expect("binary filename")
        .to_str()
        .expect("UTF-8 binary name");
    let name = name
        .strip_prefix("ck-")
        .or_else(|| name.strip_prefix("ckdev-"))
        .unwrap_or(name);
    // Separate calls may test different artifacts with the same basename (for
    // example the shipped CLI and a seam-enabled CLI). Never reuse a stale link.
    let dir = scratch.join(format!(
        "ckdev-bin-{}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&dir).expect("create binary scratch directory");
    let dst = dir.join(format!("ckdev-{name}"));
    if std::fs::hard_link(src, &dst).is_err() {
        std::fs::copy(src, &dst)
            .unwrap_or_else(|e| panic!("copy test binary {}: {e}", src.display()));
    }
    dst
}

/// Command factories that run before vault setup still need an owned scratch
/// directory. Rust's test threads retain it until exit, including async tests and
/// commands whose child outlives the factory call; no production directory is used.
pub fn ckdev_command(src: impl AsRef<Path>) -> Command {
    thread_local! {
        static SCRATCH: TestTempDir = TestTempDir::new(format!(
            "ckdev-commands-{}-{:?}", std::process::id(), std::thread::current().id()
        ));
    }
    SCRATCH.with(|scratch| Command::new(ckdev_binary(src.as_ref(), scratch)))
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
    fn development_links_keep_names_and_artifacts_separate() {
        let dir = TestTempDir::new(format!("ckdev-link-test-{}", std::process::id()));
        let src = dir.join("ck-auth.exe");
        std::fs::write(&src, b"first artifact").unwrap();
        let first = ckdev_binary(&src, &dir);
        assert_eq!(first.file_name().unwrap(), "ckdev-auth.exe");
        assert_eq!(std::fs::read(&first).unwrap(), b"first artifact");
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(
                std::fs::metadata(&src).unwrap().ino(),
                std::fs::metadata(&first).unwrap().ino()
            );
        }
        let other = dir.join("other");
        std::fs::create_dir(&other).unwrap();
        let src2 = other.join("ck-auth.exe");
        std::fs::write(&src2, b"second artifact").unwrap();
        let second = ckdev_binary(&src2, &dir);
        assert_ne!(first, second);
        assert_eq!(std::fs::read(&second).unwrap(), b"second artifact");
        assert_eq!(std::fs::read(&first).unwrap(), b"first artifact");
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
