//! Master-key resolution: where the vault's 32-byte master key comes from, and
//! the fail-closed rules around it.
//!
//! ## Pluggable backends
//!
//! Custody is a pluggable [`MasterKeyStore`] backend trait so new mechanisms slot
//! in without restructuring the resolver. Two backends ship in v1:
//! - [`KeychainCli`] (desktop): a macOS Keychain generic password, addressed by a
//!   fixed service/account read via the `security` CLI. A locked keychain fails
//!   closed as `vault_locked` rather than blocking on an interactive unlock prompt.
//! - [`OperatorPathStore`] (headless/server): an operator-provisioned key file that
//!   MUST live OUTSIDE the vault data tree. Co-locating the key beside `store.db` is
//!   forbidden — a single backup that captured both the ciphertext and its key would
//!   defeat at-rest encryption entirely — so resolution fails closed if the key file
//!   resolves to a directory under the data dir.
//!
//! Future backends (a signed-app key delivery, Windows DPAPI, Linux Secret Service)
//! implement the same trait and add a [`KeySource`] variant; the orchestration below
//! is backend-agnostic, so they need no resolver changes.
//!
//! First-run [`bootstrap`] mints a CSPRNG key into the active backend, failing
//! closed if the store is not writable. The vault directory is created `0700`.
//!
//! ## Wrong-key fast-fail (above the backend)
//!
//! [`resolve`] takes an optional expected [`KeyId`] (the fingerprint the vault
//! recorded for the key its records are sealed under). If the loaded key's
//! fingerprint does not match, resolution fails with [`MasterKeyError::KeyMismatch`]
//! BEFORE any record is decrypted — so supplying the wrong or a rotated key is a
//! single clean `vault_locked`, not a flood of per-record decrypt failures. This
//! check lives in the resolver, ABOVE the backend, so it applies uniformly to every
//! backend.
//!
//! ## Testability
//!
//! The impure keychain command execution is kept thin and separated from a PURE
//! classifier ([`classify_keychain_find`]) that maps a `security` invocation's
//! exit/output to an outcome, so the locked/not-found/found decision is unit-
//! tested without macOS. The operator-path logic is plain filesystem work and is
//! tested directly.

use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::key::{KeyId, MasterKey, MASTER_KEY_LEN};

/// How the master key is stored for this vault.
#[derive(Debug, Clone)]
pub enum KeySource {
    /// macOS Keychain generic password (the desktop default).
    Keychain {
        /// Keychain service string (the item's "where").
        service: String,
        /// Keychain account string (the item's "name").
        account: String,
    },
    /// An operator-provisioned key file (the headless default). Must live OUTSIDE
    /// the vault data tree (enforced at resolve/bootstrap time).
    OperatorPath {
        /// Absolute path to the key file (64 hex chars = 32 bytes).
        path: PathBuf,
    },
}

/// Inputs that locate the vault's key and data directory.
#[derive(Debug, Clone)]
pub struct ResolverConfig {
    /// The vault data directory (holds `store.db`). Created `0700` if absent;
    /// also the root the operator key path must NOT live under.
    pub data_dir: PathBuf,
    /// Where the master key lives.
    pub source: KeySource,
}

/// A master-key resolution failure. Every variant is fail-closed and typed — the
/// resolver never panics and never surfaces key bytes.
#[derive(Debug)]
pub enum MasterKeyError {
    /// The key store is present but locked / unavailable without interaction
    /// (keychain locked, pre-login). Maps to the wire `vault_locked`.
    VaultLocked,
    /// No key has been provisioned yet (first run): caller may [`bootstrap`].
    NotBootstrapped,
    /// The loaded key's fingerprint does not match the vault's recorded key_id —
    /// the wrong or a rotated key. Maps to the wire `vault_locked`.
    KeyMismatch { loaded: KeyId, expected: KeyId },
    /// The operator key path resolves to a directory under the data tree, which
    /// is forbidden (a single backup would leak both ciphertext and key).
    KeyPathUnderDataDir { key_dir: PathBuf, data_dir: PathBuf },
    /// The operator key path is structurally unusable (no parent, parent dir
    /// absent). The operator must provision the directory out-of-band.
    KeyPathInvalid(String),
    /// Bootstrap could not write the new key to the chosen store.
    KeyStoreUnwritable(String),
    /// Stored key material is not a valid 32-byte hex key.
    InvalidKeyMaterial(String),
    /// Bootstrap was attempted but a master key is ALREADY provisioned in this
    /// backend. Bootstrap is strictly first-run; refusing to clobber an existing
    /// key is what stops a stray second bootstrap from replacing the key every
    /// existing record is sealed under (which would brick the whole vault). Both
    /// v1 backends raise this symmetrically.
    KeyAlreadyProvisioned(String),
    /// Running the keychain CLI failed (spawn error, non-macOS host, ...).
    KeychainExec(String),
    /// A filesystem error preparing the vault dir or reading/writing the key.
    Io(std::io::Error),
    /// The OS CSPRNG failed during bootstrap.
    Csprng,
}

impl MasterKeyError {
    /// Whether this failure should surface to consumers as `vault_locked` (a
    /// clean back-off signal) rather than a hard error. A locked store and a
    /// wrong/rotated key are both "the vault cannot be opened right now."
    pub fn is_vault_locked(&self) -> bool {
        matches!(
            self,
            MasterKeyError::VaultLocked | MasterKeyError::KeyMismatch { .. }
        )
    }
}

impl std::fmt::Display for MasterKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MasterKeyError::VaultLocked => f.write_str("vault is locked (key store unavailable)"),
            MasterKeyError::NotBootstrapped => f.write_str("no master key has been provisioned"),
            MasterKeyError::KeyMismatch { loaded, expected } => write!(
                f,
                "loaded master key {} does not match the vault's key {}",
                loaded.to_hex(),
                expected.to_hex()
            ),
            MasterKeyError::KeyPathUnderDataDir { key_dir, data_dir } => write!(
                f,
                "operator key directory {} is inside the vault data dir {} (forbidden co-location)",
                key_dir.display(),
                data_dir.display()
            ),
            MasterKeyError::KeyPathInvalid(m) => write!(f, "operator key path is unusable: {m}"),
            MasterKeyError::KeyAlreadyProvisioned(m) => {
                write!(f, "a master key is already provisioned: {m}")
            }
            MasterKeyError::KeyStoreUnwritable(m) => write!(f, "key store is not writable: {m}"),
            MasterKeyError::InvalidKeyMaterial(m) => {
                write!(f, "stored key material is invalid: {m}")
            }
            MasterKeyError::KeychainExec(m) => write!(f, "keychain command failed: {m}"),
            MasterKeyError::Io(e) => write!(f, "key resolution io: {e}"),
            MasterKeyError::Csprng => f.write_str("OS CSPRNG failed generating a master key"),
        }
    }
}

impl std::error::Error for MasterKeyError {}

/// A master-key custody backend: the mechanism that holds the 32-byte key (a
/// keychain item, an operator file, a future signed-app delivery, ...).
///
/// A backend does exactly two things — load the existing key and store a freshly
/// generated one on first-run bootstrap — and is handed the vault `data_dir` so a
/// backend that lives on the filesystem can enforce its placement rules (the
/// operator-path backend forbids co-location under the data tree). Everything
/// shared across backends — directory `0700` setup, the CSPRNG key generation, and
/// the `key_id` wrong-key check — lives ABOVE the backend in [`resolve`] /
/// [`bootstrap`], so a new backend implements only its own load/store and inherits
/// all of it. Adding a backend is a new `impl` plus a [`KeySource`] variant; no
/// orchestration changes.
pub trait MasterKeyStore {
    /// Load the existing master key. A backend with no key provisioned yet returns
    /// [`MasterKeyError::NotBootstrapped`]; an unavailable/locked store returns
    /// [`MasterKeyError::VaultLocked`].
    fn load(&self, data_dir: &Path) -> Result<MasterKey, MasterKeyError>;

    /// Persist a freshly generated key (first-run only). Implementations must fail
    /// closed rather than overwrite an existing key.
    fn store(&self, data_dir: &Path, key: &MasterKey) -> Result<(), MasterKeyError>;
}

/// The macOS Keychain backend (v1, desktop): a generic password addressed by a
/// fixed service/account, read/written via the `security` CLI. The key never
/// touches the data dir, so it ignores `data_dir`.
pub struct KeychainCli {
    /// Keychain service string (the item's "where").
    pub service: String,
    /// Keychain account string (the item's "name").
    pub account: String,
}

impl MasterKeyStore for KeychainCli {
    fn load(&self, _data_dir: &Path) -> Result<MasterKey, MasterKeyError> {
        load_from_keychain(&self.service, &self.account)
    }

    fn store(&self, _data_dir: &Path, key: &MasterKey) -> Result<(), MasterKeyError> {
        store_in_keychain(&self.service, &self.account, key)
    }
}

/// The operator-path backend (v1, headless/server): a key file that MUST live
/// outside the vault data tree. Both load and store enforce the no-co-location
/// rule against `data_dir` before touching the file.
pub struct OperatorPathStore {
    /// Absolute path to the key file (64 hex chars = 32 bytes), outside the data dir.
    pub path: PathBuf,
}

impl MasterKeyStore for OperatorPathStore {
    fn load(&self, data_dir: &Path) -> Result<MasterKey, MasterKeyError> {
        ensure_outside_data_dir(&self.path, data_dir)?;
        load_from_operator_path(&self.path)
    }

    fn store(&self, data_dir: &Path, key: &MasterKey) -> Result<(), MasterKeyError> {
        ensure_outside_data_dir(&self.path, data_dir)?;
        store_at_operator_path(&self.path, key)
    }
}

impl KeySource {
    /// Build the [`MasterKeyStore`] backend this source names. The one place that
    /// maps config to a backend instance — a new backend adds a match arm here.
    pub fn backend(&self) -> Box<dyn MasterKeyStore> {
        match self {
            KeySource::Keychain { service, account } => Box::new(KeychainCli {
                service: service.clone(),
                account: account.clone(),
            }),
            KeySource::OperatorPath { path } => Box::new(OperatorPathStore { path: path.clone() }),
        }
    }
}

/// Load the existing master key, optionally checking it against the vault's
/// recorded fingerprint. Fails closed on a locked store, a missing key, a
/// fingerprint mismatch, or a forbidden key/data co-location.
///
/// Backend-agnostic: it prepares the vault dir, delegates the actual load to the
/// configured [`MasterKeyStore`], then applies the `key_id` wrong-key check above
/// the backend so every backend gets it uniformly.
pub fn resolve(
    config: &ResolverConfig,
    expected_key_id: Option<KeyId>,
) -> Result<MasterKey, MasterKeyError> {
    ensure_vault_dir(&config.data_dir)?;
    let key = config.source.backend().load(&config.data_dir)?;
    if let Some(expected) = expected_key_id {
        let loaded = key.key_id();
        if loaded != expected {
            return Err(MasterKeyError::KeyMismatch { loaded, expected });
        }
    }
    Ok(key)
}

/// First-run provisioning: generate a CSPRNG master key and persist it to the
/// configured backend, failing closed if the store is not writable. Returns the
/// new key (its [`KeyId`] is what the vault records for future wrong-key checks).
///
/// Backend-agnostic: the CSPRNG generation lives here, above the backend, so every
/// backend bootstraps the same way and only implements its own persistence.
pub fn bootstrap(config: &ResolverConfig) -> Result<MasterKey, MasterKeyError> {
    ensure_vault_dir(&config.data_dir)?;
    let key = MasterKey::generate().map_err(|_| MasterKeyError::Csprng)?;
    config.source.backend().store(&config.data_dir, &key)?;
    Ok(key)
}

/// Create the vault data directory if absent and tighten it to `0700` on unix
/// (owner-only). On non-unix the directory is created without a mode change.
fn ensure_vault_dir(data_dir: &Path) -> Result<(), MasterKeyError> {
    std::fs::create_dir_all(data_dir).map_err(MasterKeyError::Io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o700);
        std::fs::set_permissions(data_dir, perms).map_err(MasterKeyError::Io)?;
    }
    Ok(())
}

/// Enforce that the operator key file does NOT live in or under the data tree.
/// Both directories are canonicalized (so a symlink cannot smuggle the key back
/// inside the data dir); the key file's parent must already exist (the operator
/// provisions it out-of-band, e.g. `/run/secrets`).
fn ensure_outside_data_dir(key_path: &Path, data_dir: &Path) -> Result<(), MasterKeyError> {
    let data_canon = data_dir.canonicalize().map_err(MasterKeyError::Io)?;
    let parent = key_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| MasterKeyError::KeyPathInvalid("key path has no parent directory".into()))?;
    let parent_canon = parent.canonicalize().map_err(|e| {
        MasterKeyError::KeyPathInvalid(format!(
            "operator key directory {} must exist: {e}",
            parent.display()
        ))
    })?;
    if parent_canon.starts_with(&data_canon) {
        return Err(MasterKeyError::KeyPathUnderDataDir {
            key_dir: parent_canon,
            data_dir: data_canon,
        });
    }
    Ok(())
}

// ---- operator-path store -------------------------------------------------

/// Read and decode the key from an operator-provisioned file. The file holds the
/// 32-byte key as 64 hex characters (trailing whitespace tolerated). A missing
/// file is [`MasterKeyError::NotBootstrapped`]; malformed contents are
/// [`MasterKeyError::InvalidKeyMaterial`]. The raw file bytes are scrubbed after
/// decoding.
fn load_from_operator_path(path: &Path) -> Result<MasterKey, MasterKeyError> {
    let raw = match std::fs::read(path) {
        Ok(bytes) => Zeroizing::new(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(MasterKeyError::NotBootstrapped)
        }
        Err(e) => return Err(MasterKeyError::Io(e)),
    };
    let key_bytes = decode_hex_key(&raw)?;
    Ok(MasterKey::from_bytes(*key_bytes))
}

/// Write the key to the operator path as hex, `0600` on unix. Refuses to clobber
/// an existing key file (bootstrap is first-run only): an existing file is a
/// distinct "already provisioned" outcome, symmetric with the keychain backend's
/// duplicate-item rejection.
fn store_at_operator_path(path: &Path, key: &MasterKey) -> Result<(), MasterKeyError> {
    if path.exists() {
        return Err(MasterKeyError::KeyAlreadyProvisioned(format!(
            "key file {} already exists; refusing to overwrite",
            path.display()
        )));
    }
    let hex = encode_hex_key(key);
    write_key_file(path, hex.as_bytes())
}

/// Map an open failure: an existing file is the "already provisioned" outcome
/// (`create_new` is atomic, so this also closes the check-then-write race the
/// `path.exists()` pre-check leaves open); anything else is unwritable.
fn map_create_new_err(path: &Path, e: std::io::Error) -> MasterKeyError {
    if e.kind() == std::io::ErrorKind::AlreadyExists {
        MasterKeyError::KeyAlreadyProvisioned(format!(
            "key file {} already exists; refusing to overwrite",
            path.display()
        ))
    } else {
        MasterKeyError::KeyStoreUnwritable(e.to_string())
    }
}

#[cfg(unix)]
fn write_key_file(path: &Path, bytes: &[u8]) -> Result<(), MasterKeyError> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| map_create_new_err(path, e))?;
    f.write_all(bytes)
        .map_err(|e| MasterKeyError::KeyStoreUnwritable(e.to_string()))?;
    f.flush().map_err(MasterKeyError::Io)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_key_file(path: &Path, bytes: &[u8]) -> Result<(), MasterKeyError> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| map_create_new_err(path, e))?;
    f.write_all(bytes)
        .map_err(|e| MasterKeyError::KeyStoreUnwritable(e.to_string()))?;
    f.flush().map_err(MasterKeyError::Io)?;
    Ok(())
}

// ---- keychain store (macOS) ----------------------------------------------

/// The outcome of a keychain `find-generic-password` invocation, classified from
/// its raw exit/output by the PURE [`classify_keychain_find`].
#[derive(Debug, PartialEq, Eq)]
enum KeychainFind {
    /// The `-w` password line (expected to be the hex key).
    Found(String),
    /// The keychain is locked / interaction is not allowed → fail closed.
    Locked,
    /// No such item → not provisioned yet.
    NotFound,
    /// An unclassified failure.
    Error(String),
}

/// Map a `security find-generic-password` invocation to an outcome. Pure (no I/O),
/// so the locked/not-found/found decision is unit-tested without macOS.
///
/// Residual: the locked-vs-other decision leans on stderr substring matching,
/// which is locale/format-fragile and cannot be validated in CI (no macOS keychain
/// runner). Exit codes are used where stable (44 = not-found). When dogfooding on a
/// real Mac, capture the actual `security` exit/stderr for the locked and
/// duplicate cases and pin the classifiers against those real strings rather than
/// guessing the wire format.
fn classify_keychain_find(code: Option<i32>, stdout: &str, stderr: &str) -> KeychainFind {
    if code == Some(0) {
        return KeychainFind::Found(stdout.trim().to_string());
    }
    let haystack = stderr.to_ascii_lowercase();
    // A locked keychain (or any non-interactive denial) must fail closed.
    if haystack.contains("interaction")
        || haystack.contains("locked")
        || haystack.contains("not allowed")
        || haystack.contains("-25308")
    {
        return KeychainFind::Locked;
    }
    // errSecItemNotFound is exit 44 and/or the "could not be found" message.
    if code == Some(44) || haystack.contains("could not be found") {
        return KeychainFind::NotFound;
    }
    KeychainFind::Error(format!("security exited with {code:?}: {}", stderr.trim()))
}

fn load_from_keychain(service: &str, account: &str) -> Result<MasterKey, MasterKeyError> {
    let output = std::process::Command::new("security")
        .args(["find-generic-password", "-s", service, "-a", account, "-w"])
        .output()
        .map_err(|e| MasterKeyError::KeychainExec(e.to_string()))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    match classify_keychain_find(output.status.code(), &stdout, &stderr) {
        KeychainFind::Found(hex) => {
            let hex = Zeroizing::new(hex.into_bytes());
            let key_bytes = decode_hex_key(&hex)?;
            Ok(MasterKey::from_bytes(*key_bytes))
        }
        KeychainFind::Locked => Err(MasterKeyError::VaultLocked),
        KeychainFind::NotFound => Err(MasterKeyError::NotBootstrapped),
        KeychainFind::Error(m) => Err(MasterKeyError::KeychainExec(m)),
    }
}

/// The outcome of a keychain `add-generic-password` invocation, classified from
/// its raw exit/output by the PURE [`classify_keychain_add`].
#[derive(Debug, PartialEq, Eq)]
enum KeychainAdd {
    /// The item was created (first-run success).
    Stored,
    /// An item already exists for this service/account (errSecDuplicateItem):
    /// bootstrap must NOT overwrite it (that would brick the vault).
    AlreadyProvisioned,
    /// An unclassified failure.
    Error(String),
}

/// Map a `security add-generic-password` invocation to an outcome. Pure (no I/O),
/// so the created/duplicate decision is unit-tested without macOS.
fn classify_keychain_add(code: Option<i32>, stderr: &str) -> KeychainAdd {
    if code == Some(0) {
        return KeychainAdd::Stored;
    }
    let haystack = stderr.to_ascii_lowercase();
    // errSecDuplicateItem is exit 45 and/or the "already exists" message. Without
    // -U, `security` refuses to replace an existing item, so this is the
    // first-run-only guard surfacing as a distinct, recoverable signal.
    if code == Some(45) || haystack.contains("already exists") || haystack.contains("-25299") {
        return KeychainAdd::AlreadyProvisioned;
    }
    KeychainAdd::Error(format!(
        "security add exited with {code:?}: {}",
        stderr.trim()
    ))
}

/// Store the key as a keychain generic password — FIRST-RUN ONLY.
///
/// Deliberately omits `-U`: with `-U`, a stray second bootstrap would silently
/// REPLACE the existing master key, after which every record sealed under the old
/// key fails the key_id check and the whole vault is bricked. Without `-U`,
/// `security` returns errSecDuplicateItem if the item exists, which we surface as
/// [`MasterKeyError::KeyAlreadyProvisioned`] — symmetric with the operator-path
/// backend's refuse-to-clobber, so bootstrap is safe-by-construction on both.
///
/// Documented residuals of this `security`-CLI write path (accepted for v1; the
/// signed-app custodian is the hardened future target — see the contract's
/// master-key model):
///   1. The key hex is passed as an argv (`-w <hex>`), so it is briefly visible in
///      the process table to same-user processes during the one-time bootstrap.
///      This is within the accepted same-user residual (a same-user attacker can
///      read the item via the CLI anyway), but the Security-framework/signed-app
///      path avoids even this transient argv exposure.
///   2. The item is created with the broad default ACL (no `-T`/partition
///      restriction). The tight code-signature ACL that makes another app's read
///      prompt the user is only achievable from the signed CK app, not the
///      unsigned CLI.
fn store_in_keychain(service: &str, account: &str, key: &MasterKey) -> Result<(), MasterKeyError> {
    let hex = encode_hex_key(key);
    let output = std::process::Command::new("security")
        .args([
            "add-generic-password",
            "-s",
            service,
            "-a",
            account,
            "-w",
            hex.as_str(),
        ])
        .output()
        .map_err(|e| MasterKeyError::KeychainExec(e.to_string()))?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    match classify_keychain_add(output.status.code(), &stderr) {
        KeychainAdd::Stored => Ok(()),
        KeychainAdd::AlreadyProvisioned => Err(MasterKeyError::KeyAlreadyProvisioned(format!(
            "keychain item {service}/{account} already exists; refusing to overwrite"
        ))),
        KeychainAdd::Error(m) => Err(MasterKeyError::KeyStoreUnwritable(m)),
    }
}

// ---- hex helpers ---------------------------------------------------------

/// Encode the master key as 64 lowercase hex characters, in a scrubbed buffer.
fn encode_hex_key(key: &MasterKey) -> Zeroizing<String> {
    use std::fmt::Write;
    let mut s = String::with_capacity(MASTER_KEY_LEN * 2);
    for b in key.as_bytes() {
        let _ = write!(s, "{b:02x}");
    }
    Zeroizing::new(s)
}

/// Decode exactly 64 hex characters (trailing/leading ASCII whitespace tolerated)
/// into a scrubbed 32-byte key. Any other length or a non-hex digit is invalid.
fn decode_hex_key(raw: &[u8]) -> Result<Zeroizing<[u8; MASTER_KEY_LEN]>, MasterKeyError> {
    let trimmed: &[u8] = {
        let start = raw
            .iter()
            .position(|b| !b.is_ascii_whitespace())
            .unwrap_or(raw.len());
        let end = raw
            .iter()
            .rposition(|b| !b.is_ascii_whitespace())
            .map(|i| i + 1)
            .unwrap_or(start);
        &raw[start..end]
    };
    if trimmed.len() != MASTER_KEY_LEN * 2 {
        return Err(MasterKeyError::InvalidKeyMaterial(format!(
            "expected {} hex chars, got {}",
            MASTER_KEY_LEN * 2,
            trimmed.len()
        )));
    }
    let mut out = Zeroizing::new([0u8; MASTER_KEY_LEN]);
    for (i, chunk) in trimmed.chunks_exact(2).enumerate() {
        let hi = hex_val(chunk[0])?;
        let lo = hex_val(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_val(c: u8) -> Result<u8, MasterKeyError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        other => Err(MasterKeyError::InvalidKeyMaterial(format!(
            "non-hex byte 0x{other:02x}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let d = std::env::temp_dir().join(format!(
            "ck-cred-resolver-{}-{}-{}",
            std::process::id(),
            tag,
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn operator_path_bootstrap_then_resolve_round_trips() {
        let root = tmp_dir("rt");
        let data_dir = root.join("data");
        let key_dir = root.join("secrets");
        std::fs::create_dir_all(&key_dir).unwrap();
        let config = ResolverConfig {
            data_dir: data_dir.clone(),
            source: KeySource::OperatorPath {
                path: key_dir.join("master.key"),
            },
        };
        let created = bootstrap(&config).expect("bootstrap");
        let loaded = resolve(&config, Some(created.key_id())).expect("resolve");
        assert_eq!(created.key_id(), loaded.key_id(), "same key round-trips");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn vault_dir_is_created_0700_on_unix() {
        let root = tmp_dir("perm");
        let data_dir = root.join("data");
        ensure_vault_dir(&data_dir).expect("mkdir");
        assert!(data_dir.is_dir());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&data_dir).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700, "vault dir is owner-only");
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn key_under_data_dir_is_rejected() {
        let root = tmp_dir("coloc");
        let data_dir = root.join("data");
        std::fs::create_dir_all(&data_dir).unwrap();
        // The forbidden case: key file beside store.db, inside the data tree.
        let config = ResolverConfig {
            data_dir: data_dir.clone(),
            source: KeySource::OperatorPath {
                path: data_dir.join("master.key"),
            },
        };
        match bootstrap(&config) {
            Err(MasterKeyError::KeyPathUnderDataDir { .. }) => {}
            other => panic!("expected KeyPathUnderDataDir, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn key_in_nested_data_subdir_is_rejected() {
        let root = tmp_dir("coloc-nested");
        let data_dir = root.join("data");
        let nested = data_dir.join("keys");
        std::fs::create_dir_all(&nested).unwrap();
        let config = ResolverConfig {
            data_dir: data_dir.clone(),
            source: KeySource::OperatorPath {
                path: nested.join("master.key"),
            },
        };
        match resolve(&config, None) {
            Err(MasterKeyError::KeyPathUnderDataDir { .. }) => {}
            other => panic!("expected KeyPathUnderDataDir, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn missing_operator_key_is_not_bootstrapped() {
        let root = tmp_dir("absent");
        let data_dir = root.join("data");
        let key_dir = root.join("secrets");
        std::fs::create_dir_all(&key_dir).unwrap();
        let config = ResolverConfig {
            data_dir,
            source: KeySource::OperatorPath {
                path: key_dir.join("master.key"),
            },
        };
        match resolve(&config, None) {
            Err(MasterKeyError::NotBootstrapped) => {}
            other => panic!("expected NotBootstrapped, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn wrong_key_id_is_mismatch_and_vault_locked() {
        let root = tmp_dir("mismatch");
        let data_dir = root.join("data");
        let key_dir = root.join("secrets");
        std::fs::create_dir_all(&key_dir).unwrap();
        let config = ResolverConfig {
            data_dir,
            source: KeySource::OperatorPath {
                path: key_dir.join("master.key"),
            },
        };
        bootstrap(&config).expect("bootstrap");
        // Expect a fingerprint that is NOT the stored key's.
        let wrong = MasterKey::from_bytes([0xFE; MASTER_KEY_LEN]).key_id();
        match resolve(&config, Some(wrong)) {
            Err(e @ MasterKeyError::KeyMismatch { .. }) => assert!(e.is_vault_locked()),
            other => panic!("expected KeyMismatch, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn corrupt_operator_key_is_invalid_material() {
        let root = tmp_dir("corrupt");
        let data_dir = root.join("data");
        let key_dir = root.join("secrets");
        std::fs::create_dir_all(&key_dir).unwrap();
        let key_path = key_dir.join("master.key");
        std::fs::write(&key_path, b"not-a-valid-hex-key").unwrap();
        let config = ResolverConfig {
            data_dir,
            source: KeySource::OperatorPath { path: key_path },
        };
        match resolve(&config, None) {
            Err(MasterKeyError::InvalidKeyMaterial(_)) => {}
            other => panic!("expected InvalidKeyMaterial, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn bootstrap_refuses_to_clobber_existing_key() {
        let root = tmp_dir("noclobber");
        let data_dir = root.join("data");
        let key_dir = root.join("secrets");
        std::fs::create_dir_all(&key_dir).unwrap();
        let config = ResolverConfig {
            data_dir,
            source: KeySource::OperatorPath {
                path: key_dir.join("master.key"),
            },
        };
        bootstrap(&config).expect("first bootstrap");
        // A second bootstrap must refuse to clobber the existing key (which would
        // brick every record sealed under it), surfacing the distinct
        // already-provisioned signal — symmetric with the keychain backend.
        match bootstrap(&config) {
            Err(MasterKeyError::KeyAlreadyProvisioned(_)) => {}
            other => panic!("expected KeyAlreadyProvisioned on re-bootstrap, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn operator_key_file_is_0600_on_unix() {
        let root = tmp_dir("mode");
        let data_dir = root.join("data");
        let key_dir = root.join("secrets");
        std::fs::create_dir_all(&key_dir).unwrap();
        let key_path = key_dir.join("master.key");
        let config = ResolverConfig {
            data_dir,
            source: KeySource::OperatorPath {
                path: key_path.clone(),
            },
        };
        bootstrap(&config).expect("bootstrap");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&key_path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "key file is owner-only");
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn hex_round_trips() {
        let key = MasterKey::from_bytes([0x5A; MASTER_KEY_LEN]);
        let hex = encode_hex_key(&key);
        assert_eq!(hex.len(), MASTER_KEY_LEN * 2);
        let decoded = decode_hex_key(hex.as_bytes()).expect("decode");
        assert_eq!(*decoded, [0x5A; MASTER_KEY_LEN]);
    }

    #[test]
    fn hex_decode_tolerates_trailing_newline() {
        let key = MasterKey::from_bytes([0x11; MASTER_KEY_LEN]);
        let mut hex = encode_hex_key(&key).to_string();
        hex.push('\n');
        let decoded = decode_hex_key(hex.as_bytes()).expect("decode with newline");
        assert_eq!(*decoded, [0x11; MASTER_KEY_LEN]);
    }

    #[test]
    fn hex_decode_rejects_wrong_length_and_non_hex() {
        assert!(matches!(
            decode_hex_key(b"abcd"),
            Err(MasterKeyError::InvalidKeyMaterial(_))
        ));
        let bad = vec![b'z'; MASTER_KEY_LEN * 2];
        assert!(matches!(
            decode_hex_key(&bad),
            Err(MasterKeyError::InvalidKeyMaterial(_))
        ));
    }

    // The keychain classifier (pure) — exercised without macOS.
    #[test]
    fn keychain_classifier_maps_outcomes() {
        assert_eq!(
            classify_keychain_find(Some(0), "deadbeef\n", ""),
            KeychainFind::Found("deadbeef".to_string())
        );
        assert_eq!(
            classify_keychain_find(Some(44), "", "security: ... could not be found ..."),
            KeychainFind::NotFound
        );
        assert_eq!(
            classify_keychain_find(
                Some(36),
                "",
                "SecKeychainSearchCopyNext: User interaction is not allowed."
            ),
            KeychainFind::Locked
        );
        assert_eq!(
            classify_keychain_find(Some(36), "", "errSecInteractionNotAllowed (-25308)"),
            KeychainFind::Locked
        );
        match classify_keychain_find(Some(1), "", "some other failure") {
            KeychainFind::Error(_) => {}
            other => panic!("expected Error, got {other:?}"),
        }
    }

    // The keychain ADD classifier (pure) — the first-run-only / no-clobber guard.
    #[test]
    fn keychain_add_classifier_maps_outcomes() {
        assert_eq!(classify_keychain_add(Some(0), ""), KeychainAdd::Stored);
        assert_eq!(
            classify_keychain_add(Some(45), "security: ... already exists ..."),
            KeychainAdd::AlreadyProvisioned
        );
        assert_eq!(
            classify_keychain_add(Some(45), ""),
            KeychainAdd::AlreadyProvisioned,
            "duplicate-item exit alone is enough"
        );
        match classify_keychain_add(Some(1), "some other add failure") {
            KeychainAdd::Error(_) => {}
            other => panic!("expected Error, got {other:?}"),
        }
    }
}
