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
    /// Load the key in `slot`, or `None` when that slot is empty. An
    /// unavailable/locked store is [`MasterKeyError::VaultLocked`].
    ///
    /// A master-key store holds TWO slots — `Current` and `Next` — so a key
    /// rotation is crash-safe: the new key is staged in `Next` before the database
    /// is re-wrapped, and only promoted to `Current` after. At any crash point the
    /// resolver can find the slot whose key matches the database's recorded
    /// fingerprint (see [`resolve`]), so the vault never bricks. The common case
    /// (no rotation in flight) just uses `Current`.
    fn load_slot(
        &self,
        data_dir: &Path,
        slot: KeySlot,
    ) -> Result<Option<MasterKey>, MasterKeyError>;

    /// Persist `key` to `slot`, REPLACING whatever is there. Replace (not
    /// create-only) is required because a rotation writes `Next` over any stale key
    /// an aborted prior rotation may have left. First-run clobber-safety is enforced
    /// ABOVE the backend (in [`bootstrap`]), not here.
    fn store_slot(
        &self,
        data_dir: &Path,
        slot: KeySlot,
        key: &MasterKey,
    ) -> Result<(), MasterKeyError>;

    /// Clear `slot` (idempotent — clearing an empty slot is a no-op success).
    fn clear_slot(&self, data_dir: &Path, slot: KeySlot) -> Result<(), MasterKeyError>;
}

/// Which of a master-key store's two slots a key lives in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySlot {
    /// The active key the vault is normally opened under.
    Current,
    /// The staged key during a rotation handover (the new key, before promotion).
    Next,
}

/// The macOS Keychain backend (v1, desktop): generic passwords addressed by a fixed
/// service + a per-slot account, read/written via the `security` CLI. The key never
/// touches the data dir, so it ignores `data_dir`.
pub struct KeychainCli {
    /// Keychain service string (the item's "where").
    pub service: String,
    /// Keychain account string for the `Current` slot (the item's "name").
    pub account: String,
}

impl KeychainCli {
    /// The keychain account string for a slot: the configured account for
    /// `Current`, that account with a `-next` suffix for `Next`.
    fn account_for(&self, slot: KeySlot) -> String {
        match slot {
            KeySlot::Current => self.account.clone(),
            KeySlot::Next => format!("{}-next", self.account),
        }
    }
}

impl MasterKeyStore for KeychainCli {
    fn load_slot(
        &self,
        _data_dir: &Path,
        slot: KeySlot,
    ) -> Result<Option<MasterKey>, MasterKeyError> {
        match load_from_keychain(&self.service, &self.account_for(slot)) {
            Ok(key) => Ok(Some(key)),
            Err(MasterKeyError::NotBootstrapped) => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn store_slot(
        &self,
        _data_dir: &Path,
        slot: KeySlot,
        key: &MasterKey,
    ) -> Result<(), MasterKeyError> {
        replace_in_keychain(&self.service, &self.account_for(slot), key)
    }

    fn clear_slot(&self, _data_dir: &Path, slot: KeySlot) -> Result<(), MasterKeyError> {
        delete_from_keychain(&self.service, &self.account_for(slot))
    }
}

/// The operator-path backend (v1, headless/server): per-slot key files that MUST
/// live outside the vault data tree. Every op enforces the no-co-location rule
/// against `data_dir` before touching a file.
pub struct OperatorPathStore {
    /// Absolute path to the `Current` key file (64 hex chars = 32 bytes), outside
    /// the data dir. The `Next` slot is the same path with a `.next` suffix.
    pub path: PathBuf,
}

impl OperatorPathStore {
    fn path_for(&self, slot: KeySlot) -> PathBuf {
        match slot {
            KeySlot::Current => self.path.clone(),
            KeySlot::Next => {
                let mut s = self.path.clone().into_os_string();
                s.push(".next");
                PathBuf::from(s)
            }
        }
    }
}

impl MasterKeyStore for OperatorPathStore {
    fn load_slot(
        &self,
        data_dir: &Path,
        slot: KeySlot,
    ) -> Result<Option<MasterKey>, MasterKeyError> {
        let path = self.path_for(slot);
        ensure_outside_data_dir(&path, data_dir)?;
        match load_from_operator_path(&path) {
            Ok(key) => Ok(Some(key)),
            Err(MasterKeyError::NotBootstrapped) => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn store_slot(
        &self,
        data_dir: &Path,
        slot: KeySlot,
        key: &MasterKey,
    ) -> Result<(), MasterKeyError> {
        let path = self.path_for(slot);
        ensure_outside_data_dir(&path, data_dir)?;
        replace_at_operator_path(&path, key)
    }

    fn clear_slot(&self, data_dir: &Path, slot: KeySlot) -> Result<(), MasterKeyError> {
        let path = self.path_for(slot);
        ensure_outside_data_dir(&path, data_dir)?;
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(MasterKeyError::Io(e)),
        }
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

/// Load the master key, optionally checking it against the vault's recorded
/// fingerprint. Fails closed on a locked store, a missing key, a fingerprint
/// mismatch, or a forbidden key/data co-location.
///
/// This is the simple form used before the database is open (so its key_id is not
/// yet known): it loads the `Current` slot and checks `expected_key_id` if given.
/// Once the database is open, [`resolve_for_db`] is the crash-safe form that picks
/// whichever slot matches the database's recorded fingerprint (so a rotation that
/// crashed mid-handover still resolves).
pub fn resolve(
    config: &ResolverConfig,
    expected_key_id: Option<KeyId>,
) -> Result<MasterKey, MasterKeyError> {
    ensure_vault_dir(&config.data_dir)?;
    let key = config
        .source
        .backend()
        .load_slot(&config.data_dir, KeySlot::Current)?
        .ok_or(MasterKeyError::NotBootstrapped)?;
    if let Some(expected) = expected_key_id {
        let loaded = key.key_id();
        if loaded != expected {
            return Err(MasterKeyError::KeyMismatch { loaded, expected });
        }
    }
    Ok(key)
}

/// Crash-safe resolve against an OPEN database's recorded key fingerprint.
///
/// The database stores its master key's fingerprint in plaintext (the sealed
/// audit-key row's `key_id`), so the resolver can tell which key the database is
/// actually sealed under WITHOUT decrypting anything, and pick the matching slot.
/// This is what makes a rotation crash-safe: at any handover crash point the
/// database's fingerprint matches EXACTLY ONE of the two slots, and this returns
/// that key. If NEITHER slot matches, that is a genuine wrong-key/corrupt state
/// ([`MasterKeyError::KeyMismatch`]), not a recoverable handover — fail-closed.
///
/// Tries `Current` first (the common, no-rotation-in-flight case), then `Next`.
pub fn resolve_for_db(
    config: &ResolverConfig,
    db_key_id: KeyId,
) -> Result<MasterKey, MasterKeyError> {
    ensure_vault_dir(&config.data_dir)?;
    let backend = config.source.backend();
    for slot in [KeySlot::Current, KeySlot::Next] {
        if let Some(key) = backend.load_slot(&config.data_dir, slot)? {
            if key.key_id() == db_key_id {
                return Ok(key);
            }
        }
    }
    // No slot's key matches the database's recorded fingerprint: a real wrong-key /
    // corrupt state, distinct from a recoverable mid-rotation handover.
    Err(MasterKeyError::KeyMismatch {
        loaded: db_key_id,
        expected: db_key_id,
    })
}

/// First-run provisioning: generate a CSPRNG master key and persist it to the
/// `Current` slot, failing closed if the slot already holds a key (first-run only)
/// or the store is not writable. Returns the new key.
///
/// Clobber-safety is enforced HERE (above the backend), since the slot store ops are
/// replace-not-create: a `Current` slot that already holds a key means the vault is
/// already bootstrapped, so this refuses rather than overwrite.
pub fn bootstrap(config: &ResolverConfig) -> Result<MasterKey, MasterKeyError> {
    ensure_vault_dir(&config.data_dir)?;
    let backend = config.source.backend();
    if backend
        .load_slot(&config.data_dir, KeySlot::Current)?
        .is_some()
    {
        return Err(MasterKeyError::KeyAlreadyProvisioned(
            "current key slot is already provisioned".to_string(),
        ));
    }
    let key = MasterKey::generate().map_err(|_| MasterKeyError::Csprng)?;
    backend.store_slot(&config.data_dir, KeySlot::Current, &key)?;
    Ok(key)
}

/// Stage a rotation's new key into the `Next` slot (rotation step 1), REPLACING any
/// stale key a prior aborted rotation left there. The `Current` slot is untouched,
/// so the vault still opens under the current key until the database is re-wrapped.
pub fn stage_next(config: &ResolverConfig, new_key: &MasterKey) -> Result<(), MasterKeyError> {
    ensure_vault_dir(&config.data_dir)?;
    config
        .source
        .backend()
        .store_slot(&config.data_dir, KeySlot::Next, new_key)
}

/// Promote the `Next` slot to `Current` and clear `Next` (rotation's final step).
/// Reads `Next` and copies it into `Current` within the key store (no key handle
/// needed — the rotation already consumed the new key value). Off the brick-path and
/// idempotent: a crash before promotion still resolves to `Next` (which matches the
/// re-wrapped database); a `Next` already cleared (already promoted) is a no-op.
pub fn promote_next(config: &ResolverConfig) -> Result<(), MasterKeyError> {
    ensure_vault_dir(&config.data_dir)?;
    let backend = config.source.backend();
    let Some(next) = backend.load_slot(&config.data_dir, KeySlot::Next)? else {
        // Already promoted (next is empty): nothing to do.
        return Ok(());
    };
    backend.store_slot(&config.data_dir, KeySlot::Current, &next)?;
    backend.clear_slot(&config.data_dir, KeySlot::Next)?;
    Ok(())
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

/// Replace (create-or-update) a keychain slot's key, via `add-generic-password -U`.
///
/// Unlike [`store_in_keychain`] (first-run-only, no `-U`), a SLOT write must REPLACE
/// whatever is there: a rotation overwrites the `Next` slot's stale key, and the
/// first-run clobber-safety is enforced above the backend in [`bootstrap`]. So `-U`
/// is correct here. (Same argv-exposure residual as the bootstrap write.)
fn replace_in_keychain(
    service: &str,
    account: &str,
    key: &MasterKey,
) -> Result<(), MasterKeyError> {
    let hex = encode_hex_key(key);
    let output = std::process::Command::new("security")
        .args([
            "add-generic-password",
            "-U",
            "-s",
            service,
            "-a",
            account,
            "-w",
            hex.as_str(),
        ])
        .output()
        .map_err(|e| MasterKeyError::KeychainExec(e.to_string()))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(MasterKeyError::KeyStoreUnwritable(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ))
    }
}

/// Delete a keychain slot's item (idempotent — a missing item is success).
fn delete_from_keychain(service: &str, account: &str) -> Result<(), MasterKeyError> {
    let output = std::process::Command::new("security")
        .args(["delete-generic-password", "-s", service, "-a", account])
        .output()
        .map_err(|e| MasterKeyError::KeychainExec(e.to_string()))?;
    if output.status.success() {
        return Ok(());
    }
    // errSecItemNotFound (exit 44 / "could not be found") = already absent = success.
    let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
    if output.status.code() == Some(44) || stderr.contains("could not be found") {
        Ok(())
    } else {
        Err(MasterKeyError::KeyStoreUnwritable(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ))
    }
}

/// Write a key file, REPLACING any existing file, `0600` on unix, atomically (write
/// a temp sibling then rename). Used for a slot write (rotation overwrites `Next`).
fn replace_at_operator_path(path: &Path, key: &MasterKey) -> Result<(), MasterKeyError> {
    let hex = encode_hex_key(key);
    let mut tmp = path.to_path_buf().into_os_string();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    // create_new the temp so a stale temp from a crashed prior write doesn't get
    // appended to; remove any leftover temp first.
    let _ = std::fs::remove_file(&tmp);
    write_key_file(&tmp, hex.as_bytes())?;
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        MasterKeyError::KeyStoreUnwritable(e.to_string())
    })?;
    Ok(())
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

    fn op_config(root: &std::path::Path) -> ResolverConfig {
        let key_dir = root.join("secrets");
        std::fs::create_dir_all(&key_dir).unwrap();
        ResolverConfig {
            data_dir: root.join("data"),
            source: KeySource::OperatorPath {
                path: key_dir.join("master.key"),
            },
        }
    }

    // The two-slot handover's brick-free invariant: at EVERY handover state the
    // database's recorded key_id matches exactly one slot, and resolve_for_db
    // returns that key. These simulate each crash point by leaving the slots in the
    // state a crash at that point would leave them.

    #[test]
    fn resolve_for_db_picks_current_before_rotation() {
        let root = tmp_dir("slot-current");
        let config = op_config(&root);
        let k1 = bootstrap(&config).expect("bootstrap");
        // No rotation in flight: db is under k1, only current is set.
        let got = resolve_for_db(&config, k1.key_id()).expect("resolve");
        assert_eq!(got.key_id(), k1.key_id());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn resolve_for_db_after_stage_next_still_picks_current() {
        // Crash point 1: next written, db NOT yet rewrapped (still under k1).
        let root = tmp_dir("slot-staged");
        let config = op_config(&root);
        let k1 = bootstrap(&config).expect("bootstrap");
        let k2 = MasterKey::generate().unwrap();
        stage_next(&config, &k2).expect("stage");
        // db key_id is still k1 → resolve must pick current (k1), ignoring next.
        let got = resolve_for_db(&config, k1.key_id()).expect("resolve");
        assert_eq!(
            got.key_id(),
            k1.key_id(),
            "current matches the un-rewrapped db"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn resolve_for_db_after_db_rewrap_picks_next() {
        // Crash point 2: db rewrapped to k2, both slots present, NOT yet promoted.
        let root = tmp_dir("slot-rewrapped");
        let config = op_config(&root);
        let _k1 = bootstrap(&config).expect("bootstrap");
        let k2 = MasterKey::generate().unwrap();
        stage_next(&config, &k2).expect("stage");
        // db is now under k2 (simulated) → resolve must pick next (k2).
        let got = resolve_for_db(&config, k2.key_id()).expect("resolve");
        assert_eq!(got.key_id(), k2.key_id(), "next matches the rewrapped db");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn resolve_for_db_after_promote_picks_current() {
        // Crash point 3: promoted (current=k2, next cleared), db under k2.
        let root = tmp_dir("slot-promoted");
        let config = op_config(&root);
        let _k1 = bootstrap(&config).expect("bootstrap");
        let k2 = MasterKey::generate().unwrap();
        stage_next(&config, &k2).expect("stage");
        promote_next(&config).expect("promote");
        let got = resolve_for_db(&config, k2.key_id()).expect("resolve");
        assert_eq!(got.key_id(), k2.key_id());
        // next is cleared after promote.
        assert!(config
            .source
            .backend()
            .load_slot(&config.data_dir, KeySlot::Next)
            .unwrap()
            .is_none());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn resolve_for_db_no_matching_slot_fails_closed() {
        // A db key_id matching NEITHER slot is a genuine wrong-key/corrupt state,
        // distinct from a recoverable handover — fail closed, do not brick-loop.
        let root = tmp_dir("slot-nomatch");
        let config = op_config(&root);
        let _k1 = bootstrap(&config).expect("bootstrap");
        let stranger = MasterKey::generate().unwrap();
        match resolve_for_db(&config, stranger.key_id()) {
            Err(MasterKeyError::KeyMismatch { .. }) => {}
            other => panic!("expected KeyMismatch on no-matching-slot, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn promote_is_idempotent() {
        let root = tmp_dir("slot-promote-idem");
        let config = op_config(&root);
        let _k1 = bootstrap(&config).expect("bootstrap");
        let k2 = MasterKey::generate().unwrap();
        stage_next(&config, &k2).expect("stage");
        promote_next(&config).expect("promote 1");
        // Promoting again (next already cleared) is a no-op success.
        promote_next(&config).expect("promote 2 idempotent");
        let got = resolve_for_db(&config, k2.key_id()).expect("resolve");
        assert_eq!(got.key_id(), k2.key_id());
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
}
