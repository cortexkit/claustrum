use std::{
    ops::Deref,
    path::{Path, PathBuf},
};

/// Park a real Windows CLI with its database handle still open. The parent test
/// waits for the ready line before starting a competing operation, then releases
/// the process through stdin. No timing assumption is needed to establish overlap.
#[cfg(all(windows, debug_assertions))]
pub fn windows_runtime_pause(point: &str) -> std::io::Result<()> {
    use std::io::Write;

    if std::env::var("CK_AUTH_WINDOWS_RUNTIME_TEST_PAUSE").as_deref() != Ok(point) {
        return Ok(());
    }
    println!("ck-auth Windows runtime test ready: {point}");
    std::io::stdout().flush()?;
    let mut release = String::new();
    std::io::stdin().read_line(&mut release)?;
    if release.trim() != "continue" {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "Windows runtime test did not release the CLI",
        ));
    }
    Ok(())
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

/// Protocol examples shared by the core, consumer and operator signing tests.
pub fn bus_signing_inputs(id: &str) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    match id {
        "signing:bus-leaf:1" => {
            let good = b"Az09-_abcdefghI".to_vec();
            let mut bad = vec![vec![b'A'; 14], vec![b'A'; 16]];
            for byte in [b'=', b'/', b'+', b'.', 0, 0xff] {
                let mut input = good.clone();
                input[0] = byte;
                bad.push(input);
            }
            (vec![good], bad)
        }
        "signing:bus-hub-tls:1" => {
            let prefix = [
                vec![0x20; 64],
                b"TLS 1.3, server CertificateVerify\0".to_vec(),
            ]
            .concat();
            let input = |len| [prefix.clone(), vec![0x41; len]].concat();
            let mut bad: Vec<_> = [31, 33, 47, 49].into_iter().map(input).collect();
            for padding in [63, 65] {
                bad.push(
                    [
                        vec![0x20; padding],
                        b"TLS 1.3, server CertificateVerify\0".to_vec(),
                        vec![0x41; 32],
                    ]
                    .concat(),
                );
            }
            let mut missing_zero = prefix.clone();
            missing_zero.pop();
            bad.push([missing_zero, vec![0x41; 32]].concat());
            let mut wrong_context = input(32);
            wrong_context[64] = b't';
            bad.push(wrong_context);
            let mut wrong_padding = input(32);
            wrong_padding[0] = 0x21;
            bad.push(wrong_padding);
            (vec![input(32), input(48)], bad)
        }
        "signing:bus-hub-operator:1" | "signing:bus-hub-account:1" => {
            let header = br#"{"alg":"ed25519-nkey","typ":"JWT","extra":true}"#;
            let jwt = |header: &[u8], claims: &str| {
                format!("{}.{}", URL_SAFE_NO_PAD.encode(header), claims).into_bytes()
            };
            let at_size = |header: &[u8], len: usize| {
                let encoded = URL_SAFE_NO_PAD.encode(header);
                format!("{encoded}.{}", "A".repeat(len - encoded.len() - 1)).into_bytes()
            };
            let good = jwt(header, "e30");
            let mut bad = vec![
                at_size(&[header.as_slice(), b" "].concat(), 65537),
                jwt(br#"{"alg":"EdDSA","typ":"JWT"}"#, "e30"),
                jwt(br#"{"alg":"ed25519-nkey","typ":"jwt"}"#, "e30"),
                jwt(br#"{"alg":"ed25519-nkey"}"#, "e30"),
                jwt(br#"{"typ":"JWT"}"#, "e30"),
                jwt(br#"[]"#, "e30"),
                jwt(b"not json", "e30"),
                jwt(&[0xff], "e30"),
                jwt(header, ""),
                jwt(header, "A"),
                jwt(header, "e30="),
                jwt(header, "e3/"),
                jwt(header, "e3+"),
                jwt(header, "e30.e30"),
                b".e30".to_vec(),
                b"A.e30".to_vec(),
                b"!.e30".to_vec(),
                URL_SAFE_NO_PAD.encode(header).into_bytes(),
            ];
            let mut padded_header = URL_SAFE_NO_PAD.encode(header);
            padded_header.push_str("=.e30");
            bad.push(padded_header.into_bytes());
            (
                vec![
                    good,
                    jwt(header, "AA"),
                    at_size(header, 65535),
                    at_size(header, 65536),
                ],
                bad,
            )
        }
        _ => panic!("unknown bus signing test purpose"),
    }
}

/// Regenerate or byte-compare one development approval sample produced by a real
/// vault operation. These fixtures contain no production keys or secret material.
pub fn desktop_dev_vector(name: &str, value: &serde_json::Value) {
    let folder = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors/desktop-dev-approval-vectors-v1");
    let bytes = serde_json::to_vec_pretty(value).unwrap();
    let path = folder.join(name);
    if std::env::var_os("CK_EMIT_SECRET_VECTORS").is_some() {
        std::fs::create_dir_all(&folder).unwrap();
        std::fs::write(path, bytes).unwrap();
    } else {
        assert_eq!(
            std::fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display())),
            bytes,
            "development approval vector changed: {name}"
        );
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
