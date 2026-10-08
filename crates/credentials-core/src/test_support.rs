use std::{
    ops::Deref,
    path::{Path, PathBuf},
};

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
    use super::TestTempDir;

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
