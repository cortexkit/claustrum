use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc, Arc,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use serde_json::Value;

static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);
const AUTH_FILE_MAX_BYTES: u64 = 1024 * 1024;
const HANDLE_FILE_MAX_BYTES: u64 = 256 * 1024;
const MANIFEST_LOCK_TTL_MS: u64 = 30_000;
const MANIFEST_LOCK_RENEW_EVERY_MS: u64 = 10_000;
// The claim deadline bounds when the last stale-lock rename is issued, not when it lands:
// a rename issued at deadline-1ms can complete afterwards, by tens to hundreds of ms on a
// loaded host. The retry deadline and staleness window both read `ttl` today; if they split,
// this bound must keep their max so reclamation still covers the longer role.
const MANIFEST_LOCK_QUARANTINE_RECLAIM_MARGIN: Duration = Duration::from_millis(5_000);
const MANIFEST_LOCK_OWNER_KEYS: [&str; 4] = ["tenant", "pid", "claimed_at_ms", "nonce"];
const MANIFEST_LOCK_STALE_TARGET_PATTERN: &str = r"^\.lock\.stale-\d+-[A-Za-z0-9_-]+$";
const OPENCODE_CLAUSTRUM_TENANT: &str = "opencode-claustrum";
type BeforeManifestRename = Arc<dyn Fn(&Path) + Send + Sync>;

#[cfg(test)]
static LEASE_LOST_WARNINGS: AtomicU64 = AtomicU64::new(0);

#[derive(Clone)]
struct ManifestLockOptions {
    ttl: Duration,
    renew_every: Duration,
    retry_min: Duration,
    retry_max: Duration,
    after_claim: Option<Arc<dyn Fn() + Send + Sync>>,
    before_evict: Option<Arc<dyn Fn() + Send + Sync>>,
    #[cfg(test)]
    after_evict_rename_attempt: Option<Arc<dyn Fn() + Send + Sync>>,
    after_evict: Option<Arc<dyn Fn() + Send + Sync>>,
    before_manifest_rename: Option<BeforeManifestRename>,
    // Manifest lock staleness is judged against the contender's clock at each observation (not at claim start); claim deadline expiry remains monotonic so the production bound is still exercised.
    now_override_ms: Option<u64>,
    #[cfg(test)]
    now_sequence_ms: Option<Arc<AtomicU64>>,
}

impl Default for ManifestLockOptions {
    fn default() -> Self {
        Self {
            ttl: Duration::from_millis(MANIFEST_LOCK_TTL_MS),
            renew_every: Duration::from_millis(MANIFEST_LOCK_RENEW_EVERY_MS),
            retry_min: Duration::from_millis(25),
            retry_max: Duration::from_millis(75),
            after_claim: None,
            before_evict: None,
            #[cfg(test)]
            after_evict_rename_attempt: None,
            after_evict: None,
            before_manifest_rename: None,
            now_override_ms: None,
            #[cfg(test)]
            now_sequence_ms: None,
        }
    }
}

struct ManifestLease {
    lock: PathBuf,
    nonce: String,
    ttl: Duration,
    clock: LockClock,
    renewal_failed: Arc<AtomicBool>,
    stop_tx: Option<mpsc::Sender<()>>,
    renewal: Option<thread::JoinHandle<()>>,
}

impl ManifestLease {
    fn stop_renewal(&mut self) {
        if let Some(stop_tx) = self.stop_tx.take() {
            let _ = stop_tx.send(());
        }
        if let Some(renewal) = self.renewal.take() {
            let _ = renewal.join();
        }
    }

    fn commit(&mut self) -> Result<(), OpenCodeFilesError> {
        self.stop_renewal();
        let owner = read_lock_owner(&self.lock.join("owner")).ok();
        let ours_and_fresh = owner.is_some_and(|owner| {
            owner.nonce == self.nonce
                && self.clock.now_ms().is_ok_and(|now| {
                    now.saturating_sub(owner.claimed_at_ms) < self.ttl.as_millis() as u64
                })
        });
        if self.renewal_failed.load(Ordering::SeqCst) || !ours_and_fresh {
            return Err(OpenCodeFilesError::Invalid(
                "manifest lock renewal failed; write aborted".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct ManifestLockOwner {
    #[serde(default)]
    tenant: Value,
    #[serde(default)]
    pid: Value,
    claimed_at_ms: u64,
    nonce: String,
}

#[derive(Debug)]
pub enum OpenCodeFilesError {
    Io {
        action: &'static str,
        source: std::io::Error,
    },
    Json(serde_json::Error),
    InsecureParent {
        path: PathBuf,
        reason: &'static str,
    },
    Invalid(String),
}

impl fmt::Display for OpenCodeFilesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { action, source } => write!(f, "{action}: {source}"),
            Self::Json(source) => write!(f, "JSON: {source}"),
            Self::InsecureParent { path, reason } => {
                write!(
                    f,
                    "parent directory {} is insecure: {reason}",
                    path.display()
                )
            }
            Self::Invalid(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for OpenCodeFilesError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TombstoneFixture {
    pub provider: String,
    pub entry: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TombstoneFixtures {
    pub api: TombstoneFixture,
    pub oauth: TombstoneFixture,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandleFile {
    pub version: u64,
    pub providers: Vec<HandleProvider>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandleProvider {
    pub provider: String,
    pub shape: HandleShape,
    #[serde(default)]
    pub serve: String,
    pub accounts: Vec<HandleAccount>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HandleShape {
    Api,
    Oauth,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandleAccount {
    pub label: String,
    pub handle: String,
    pub credential_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub superseded: Vec<String>,
}

impl fmt::Debug for HandleFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HandleFile")
            .field("version", &self.version)
            .field("providers", &self.providers)
            .finish()
    }
}

impl fmt::Debug for HandleProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HandleProvider")
            .field("provider", &self.provider)
            .field("shape", &self.shape)
            .field("serve", &self.serve)
            .field("accounts", &self.accounts)
            .finish()
    }
}

impl fmt::Debug for HandleAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HandleAccount")
            .field("label", &self.label)
            .field("handle", &"ckh_[redacted]")
            .field("credential_id", &self.credential_id)
            .field(
                "superseded",
                &format_args!("<{} ckh_[redacted]>", self.superseded.len()),
            )
            .finish()
    }
}

pub fn default_auth_path() -> PathBuf {
    let data_home = std::env::var_os("XDG_DATA_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .filter(|value| !value.is_empty())
                .map(|home| PathBuf::from(home).join(".local/share"))
        })
        .unwrap_or_else(|| PathBuf::from(".local/share"));
    data_home.join("opencode").join("auth.json")
}

pub fn default_handle_path() -> PathBuf {
    let config_home = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .filter(|value| !value.is_empty())
                .map(|home| PathBuf::from(home).join(".config"))
        })
        .unwrap_or_else(|| PathBuf::from(".config"));
    config_home.join("cortexkit").join("opencode-handles.json")
}

pub fn golden_tombstone_fixtures() -> Result<TombstoneFixtures, OpenCodeFilesError> {
    let golden: Value = serde_json::from_str(include_str!(
        "../../../../../packages/opencode/golden/tombstone.json"
    ))
    .map_err(OpenCodeFilesError::Json)?;
    let fixture = |shape: &str| -> Result<TombstoneFixture, OpenCodeFilesError> {
        let item = &golden["fixtures"][shape];
        let provider = item["provider"]
            .as_str()
            .filter(|provider| !provider.is_empty())
            .ok_or_else(|| {
                OpenCodeFilesError::Invalid(format!("golden {shape} provider is invalid"))
            })?
            .to_string();
        let entry = item["entry"].clone();
        validate_auth_entry(&entry)?;
        Ok(TombstoneFixture { provider, entry })
    };
    Ok(TombstoneFixtures {
        api: fixture("api")?,
        oauth: fixture("oauth")?,
    })
}

pub fn read_auth_entries(path: &Path) -> Result<BTreeMap<String, Value>, OpenCodeFilesError> {
    validate_secure_file(path)?;
    let bytes = read_limited(path, AUTH_FILE_MAX_BYTES, "auth file")?;
    let entries: BTreeMap<String, Value> =
        serde_json::from_slice(&bytes).map_err(OpenCodeFilesError::Json)?;
    for (provider, entry) in &entries {
        validate_identifier(provider, "provider")?;
        validate_auth_entry(entry)?;
    }
    Ok(entries)
}

pub fn write_auth_entry(
    path: &Path,
    provider: &str,
    entry: Value,
) -> Result<(), OpenCodeFilesError> {
    validate_identifier(provider, "provider")?;
    validate_auth_entry(&entry)?;
    let mut entries = if path.exists() {
        read_auth_entries(path)?
    } else {
        BTreeMap::new()
    };
    entries.insert(provider.to_string(), entry);
    let bytes = serde_json::to_vec(&entries).map_err(OpenCodeFilesError::Json)?;
    write_atomic(path, &bytes, false)
}

pub fn verify_auth_written(
    path: &Path,
    provider: &str,
    expected: &Value,
) -> Result<(), OpenCodeFilesError> {
    let entries = read_auth_entries(path)?;
    if entries.get(provider) != Some(expected) {
        return Err(OpenCodeFilesError::Invalid(
            "auth entry did not persist exactly".into(),
        ));
    }
    Ok(())
}

pub fn read_handle_file(path: &Path) -> Result<HandleFile, OpenCodeFilesError> {
    validate_secure_file(path)?;
    let bytes = read_limited(path, HANDLE_FILE_MAX_BYTES, "handle file")?;
    let file: HandleFile = serde_json::from_slice(&bytes).map_err(OpenCodeFilesError::Json)?;
    validate_handle_file(&file)?;
    Ok(file)
}

pub fn write_handle_file(path: &Path, file: &HandleFile) -> Result<(), OpenCodeFilesError> {
    write_handle_file_for_tenant(
        path,
        OPENCODE_CLAUSTRUM_TENANT,
        file,
        ManifestLockOptions::default(),
    )
}

pub fn verify_handle_written(path: &Path, expected: &HandleFile) -> Result<(), OpenCodeFilesError> {
    validate_handle_file(expected)?;
    let written = read_handle_file(path)?;
    let expected_owned: Vec<_> = expected
        .providers
        .iter()
        .filter(|provider| provider.serve == OPENCODE_CLAUSTRUM_TENANT)
        .cloned()
        .collect();
    let written_owned: Vec<_> = written
        .providers
        .iter()
        .filter(|provider| provider.serve == OPENCODE_CLAUSTRUM_TENANT)
        .cloned()
        .collect();
    if written_owned != expected_owned {
        return Err(OpenCodeFilesError::Invalid(
            "handle file tenant block did not persist exactly".into(),
        ));
    }
    Ok(())
}

fn write_handle_file_for_tenant(
    path: &Path,
    tenant: &str,
    desired: &HandleFile,
    options: ManifestLockOptions,
) -> Result<(), OpenCodeFilesError> {
    validate_handle_file(desired)?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| OpenCodeFilesError::Invalid("file path has no parent".into()))?;
    fs::create_dir_all(parent).map_err(|source| io_error("create parent directory", source))?;
    validate_secure_parent(parent)?;
    set_mode(parent, 0o700)?;
    let before_manifest_rename = options.before_manifest_rename.clone();
    with_manifest_lock_with_options(path, tenant, options, |lease| {
        let current = match fs::symlink_metadata(path) {
            Ok(_) => read_handle_file(path)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => HandleFile {
                version: 1,
                providers: Vec::new(),
            },
            Err(error) => return Err(io_error("stat handle file", error)),
        };
        let before_foreign: Vec<Vec<u8>> = current
            .providers
            .iter()
            .filter(|provider| provider.serve != tenant)
            .map(serde_json::to_vec)
            .collect::<Result<_, _>>()
            .map_err(OpenCodeFilesError::Json)?;
        let mut providers: Vec<_> = current
            .providers
            .into_iter()
            .filter(|provider| provider.serve != tenant)
            .collect();
        providers.extend(
            desired
                .providers
                .iter()
                .filter(|provider| provider.serve == tenant)
                .cloned(),
        );
        let next = HandleFile {
            version: 1,
            providers,
        };
        validate_handle_file(&next)?;
        let bytes = serde_json::to_vec(&next).map_err(OpenCodeFilesError::Json)?;
        write_atomic_guarded(path, &bytes, true, || {
            if let Some(before_manifest_rename) = &before_manifest_rename {
                before_manifest_rename(&lock_path(path));
            }
            lease.commit()
        })?;
        let readback = read_handle_file(path)?;
        if readback != next {
            return Err(OpenCodeFilesError::Invalid(
                "handle file readback did not persist exactly".into(),
            ));
        }
        let after_foreign: Vec<Vec<u8>> = readback
            .providers
            .iter()
            .filter(|provider| provider.serve != tenant)
            .map(serde_json::to_vec)
            .collect::<Result<_, _>>()
            .map_err(OpenCodeFilesError::Json)?;
        if after_foreign != before_foreign {
            return Err(OpenCodeFilesError::Invalid(
                "handle file readback changed another tenant block".into(),
            ));
        }
        Ok(())
    })
}

fn lock_path(path: &Path) -> PathBuf {
    let mut lock = path.as_os_str().to_os_string();
    lock.push(".lock");
    PathBuf::from(lock)
}

fn current_time_ms() -> Result<u64, OpenCodeFilesError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .map_err(|_| OpenCodeFilesError::Invalid("system clock is before UNIX epoch".into()))
}

/// The single clock every `claimed_at_ms` comparison reads through.
///
/// The owner stamp is written from this clock, so any consumer that calls
/// `current_time_ms()` instead measures real elapsed time against an injected
/// stamp -- under test that difference is the injected offset, and on a loaded
/// machine it silently crosses the TTL and skips the release. Not
/// hypothetical: it made `owner_that_becomes_stale_during_retry_window_is_evicted`
/// fail 1 in 8 runs at load 41.
///
/// The invariant that now holds: every comparison against `claimed_at_ms` reads
/// the lease's clock (`LockClock::now_ms`), because the stamp is written from
/// it. `commit` and the renewal thread carry a clone of the same clock the
/// claim used, so they cannot disagree with the stamp under test or under load.
#[derive(Clone)]
enum LockClock {
    Real,
    Fixed(u64),
    #[cfg(test)]
    Sequence(Arc<AtomicU64>),
}

impl LockClock {
    fn now_ms(&self) -> Result<u64, OpenCodeFilesError> {
        match self {
            LockClock::Real => current_time_ms(),
            LockClock::Fixed(ms) => Ok(*ms),
            #[cfg(test)]
            LockClock::Sequence(clock) => Ok(clock.load(Ordering::SeqCst)),
        }
    }
}

fn clock_from_options(options: &ManifestLockOptions) -> LockClock {
    #[cfg(test)]
    if let Some(clock) = &options.now_sequence_ms {
        return LockClock::Sequence(Arc::clone(clock));
    }
    match options.now_override_ms {
        Some(fixed) => LockClock::Fixed(fixed),
        None => LockClock::Real,
    }
}

fn resolve_now_ms(options: &ManifestLockOptions) -> Result<u64, OpenCodeFilesError> {
    clock_from_options(options).now_ms()
}

fn random_nonce() -> Result<String, OpenCodeFilesError> {
    // 16 CSPRNG bytes from ring: a collision needs both the same millisecond and the same
    // nonce. Do not simplify this to a counter, pid+timestamp, or a short token.
    let mut bytes = [0_u8; 16];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| OpenCodeFilesError::Invalid("generate manifest lock nonce failed".into()))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn io_error(action: &'static str, source: std::io::Error) -> OpenCodeFilesError {
    OpenCodeFilesError::Io { action, source }
}

fn read_lock_owner(path: &Path) -> Result<ManifestLockOwner, OpenCodeFilesError> {
    let source =
        fs::read_to_string(path).map_err(|source| io_error("read manifest lock owner", source))?;
    let owner: ManifestLockOwner = serde_json::from_str(&source)
        .map_err(|_| OpenCodeFilesError::Invalid("manifest lock owner invalid".into()))?;
    let stale_target = format!(".lock.stale-{}-{}", owner.claimed_at_ms, owner.nonce);
    if !stale_target_matches(&stale_target) {
        return Err(OpenCodeFilesError::Invalid(
            "manifest lock owner invalid".into(),
        ));
    }
    Ok(owner)
}

fn write_lock_owner(lock: &Path, owner: &ManifestLockOwner) -> Result<(), OpenCodeFilesError> {
    let owner_path = lock.join("owner");
    let temporary = lock.join(format!(
        "owner.{}.{}.tmp",
        std::process::id(),
        random_nonce()?
    ));
    let result = (|| -> Result<(), OpenCodeFilesError> {
        #[cfg(unix)]
        let mut file = {
            use std::os::unix::fs::OpenOptionsExt;
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temporary)
                .map_err(|source| io_error("create manifest lock owner", source))?
        };
        #[cfg(not(unix))]
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|source| io_error("create manifest lock owner", source))?;
        set_mode(&temporary, 0o600)?;
        serde_json::to_writer(&mut file, owner).map_err(OpenCodeFilesError::Json)?;
        file.write_all(b"\n")
            .map_err(|source| io_error("write manifest lock owner", source))?;
        file.sync_all()
            .map_err(|source| io_error("sync manifest lock owner", source))?;
        drop(file);
        fs::rename(&temporary, &owner_path)
            .map_err(|source| io_error("rename manifest lock owner", source))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn stale_target_matches(value: &str) -> bool {
    let Some(rest) = value.strip_prefix(".lock.stale-") else {
        return false;
    };
    let Some((claimed, random)) = rest.split_once('-') else {
        return false;
    };
    !claimed.is_empty()
        && claimed.bytes().all(|byte| byte.is_ascii_digit())
        && !random.is_empty()
        && random
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

/// RECLAIM READS THE SAME CLOCK THE LOCK READS.
///
/// This used `SystemTime::now()` directly while every other staleness decision in this
/// module goes through `resolve_now_ms`, which honours the injected clock. That is the
/// two-clock split PR #33 fixed for the LOCK's own staleness -- the same defect, one
/// directory over, and it survived because the two paths are read at different times.
///
/// The cost was not theoretical. Fixtures seed a quarantine mtime relative to the wall
/// clock and then assert a reclaim verdict, so the answer depended on how long the test
/// body took: under full-gate parallelism the fixture aged past its own threshold before
/// the assertion ran, and DIFFERENT members failed on different runs. Three sightings
/// across two contributor PRs that touched none of this code (issue #51).
///
/// Raising the TTL only moves the load at which it happens, which is what makes the class
/// persistent: each failure looks like a flake worth re-running, and a green re-run at
/// idle looks like a fix.
///
/// Milliseconds rather than `Duration` on both sides, because the injected clock is a
/// `u64` epoch value and mixing it with a `SystemTime` is how the two clocks got apart.
fn reclaim_stale_manifest_lock_quarantines(
    path: &Path,
    ttl: Duration,
    claim_deadline: Duration,
    options: &ManifestLockOptions,
) {
    let reclaim_age_ms = ttl
        .max(claim_deadline)
        .saturating_add(MANIFEST_LOCK_QUARANTINE_RECLAIM_MARGIN)
        .as_millis() as u64;
    let Ok(now_ms) = resolve_now_ms(options) else {
        return;
    };
    let Some(parent) = path.parent() else {
        return;
    };
    let Some(basename) = path.file_name().and_then(|name| name.to_str()) else {
        return;
    };
    let Ok(entries) = fs::read_dir(parent) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some(stale_target) = name.strip_prefix(basename) else {
            continue;
        };
        if !stale_target_matches(stale_target) {
            continue;
        }
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_dir() {
            continue;
        }
        let Ok(modified) = entry.metadata().and_then(|metadata| metadata.modified()) else {
            continue;
        };
        let Ok(modified_ms) = modified
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
        else {
            continue;
        };
        // A directory whose mtime is in the FUTURE relative to this clock reads as age 0
        // and is retained. That is the safe direction: reclaiming on a clock disagreement
        // would delete another process's live quarantine.
        if now_ms.saturating_sub(modified_ms) >= reclaim_age_ms {
            let _ = fs::remove_dir_all(entry.path());
        }
    }
}

fn warn_lease_lost(path: &Path) {
    #[cfg(test)]
    LEASE_LOST_WARNINGS.fetch_add(1, Ordering::SeqCst);
    eprintln!(
        "manifest lock lease lost, not releasing: {}",
        path.display()
    );
}

fn jitter(options: &ManifestLockOptions) -> Duration {
    let min = options.retry_min.as_millis() as u64;
    let max = options.retry_max.as_millis() as u64;
    if max <= min {
        return Duration::from_millis(min);
    }
    let mut bytes = [0_u8; 8];
    if SystemRandom::new().fill(&mut bytes).is_err() {
        return Duration::from_millis(min);
    }
    Duration::from_millis(min + u64::from_le_bytes(bytes) % (max - min + 1))
}

fn release_manifest_lock(
    path: &Path,
    lock: &Path,
    nonce: &str,
    options: &ManifestLockOptions,
    ttl: Duration,
) -> Result<(), OpenCodeFilesError> {
    let owner = match read_lock_owner(&lock.join("owner")) {
        Ok(owner) => owner,
        Err(_) => {
            warn_lease_lost(path);
            return Ok(());
        }
    };
    let now = resolve_now_ms(options)?;
    if owner.nonce != nonce || now.saturating_sub(owner.claimed_at_ms) >= ttl.as_millis() as u64 {
        warn_lease_lost(path);
        return Ok(());
    }
    let release = PathBuf::from(format!("{}.release-{nonce}", lock.display()));
    if fs::rename(lock, &release).is_err() {
        warn_lease_lost(path);
        return Ok(());
    }
    let moved = read_lock_owner(&release.join("owner")).ok();
    let moved_is_ours = moved.is_some_and(|owner| {
        owner.nonce == nonce
            && resolve_now_ms(options)
                .is_ok_and(|now| now.saturating_sub(owner.claimed_at_ms) < ttl.as_millis() as u64)
    });
    if !moved_is_ours {
        let _ = fs::rename(&release, lock);
        warn_lease_lost(path);
        return Ok(());
    }
    fs::remove_dir_all(&release).map_err(|source| io_error("remove manifest lock", source))
}

fn with_manifest_lock_with_options<T, F>(
    path: &Path,
    tenant: &str,
    options: ManifestLockOptions,
    operation: F,
) -> Result<T, OpenCodeFilesError>
where
    F: FnOnce(&mut ManifestLease) -> Result<T, OpenCodeFilesError>,
{
    let lock = lock_path(path);
    let owner_path = lock.join("owner");
    let nonce = random_nonce()?;
    let deadline = Instant::now() + options.ttl;
    loop {
        match fs::create_dir(&lock) {
            Ok(()) => {
                set_mode(&lock, 0o700)?;
                let owner = ManifestLockOwner {
                    tenant: Value::String(tenant.into()),
                    pid: Value::from(std::process::id()),
                    claimed_at_ms: resolve_now_ms(&options)?,
                    nonce: nonce.clone(),
                };
                if let Err(error) = write_lock_owner(&lock, &owner) {
                    let _ = fs::remove_dir_all(&lock);
                    return Err(error);
                }
                if let Some(after_claim) = &options.after_claim {
                    after_claim();
                }
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(io_error("create manifest lock", error)),
        }

        let owner_read_error = match read_lock_owner(&owner_path) {
            Ok(observed) => {
                if resolve_now_ms(&options)?.saturating_sub(observed.claimed_at_ms)
                    >= options.ttl.as_millis() as u64
                {
                    if let Some(before_evict) = &options.before_evict {
                        before_evict();
                    }
                    // The owner record remains because the quarantine is the ABA guard, not
                    // an audit log; bounded reclamation below is what makes that retention finite.
                    let stale = PathBuf::from(format!(
                        "{}.stale-{}-{}",
                        lock.display(),
                        observed.claimed_at_ms,
                        observed.nonce
                    ));
                    let rename_result = fs::rename(&lock, &stale);
                    #[cfg(test)]
                    if let Some(after_evict_rename_attempt) = &options.after_evict_rename_attempt {
                        after_evict_rename_attempt();
                    }
                    match rename_result {
                        Ok(()) => {
                            let moved = read_lock_owner(&stale.join("owner")).ok();
                            if moved.is_some_and(|owner| {
                                owner.nonce == observed.nonce
                                    && owner.claimed_at_ms == observed.claimed_at_ms
                            }) {
                                if let Some(after_evict) = &options.after_evict {
                                    after_evict();
                                }
                                continue;
                            }
                            let _ = fs::rename(&stale, &lock);
                        }
                        Err(error)
                            if matches!(
                                error.kind(),
                                std::io::ErrorKind::NotFound
                                    | std::io::ErrorKind::AlreadyExists
                                    | std::io::ErrorKind::DirectoryNotEmpty
                            ) => {}
                        Err(error) => return Err(io_error("rename stale manifest lock", error)),
                    }
                }
                None
            }
            Err(error) => Some(error),
        };
        if Instant::now() >= deadline {
            if matches!(owner_read_error, Some(OpenCodeFilesError::Invalid(_))) {
                return Err(OpenCodeFilesError::Invalid(
                    "manifest lock owner invalid".into(),
                ));
            }
            return Err(OpenCodeFilesError::Invalid("manifest lock busy".into()));
        }
        thread::sleep(jitter(&options).min(deadline.saturating_duration_since(Instant::now())));
    }

    reclaim_stale_manifest_lock_quarantines(path, options.ttl, options.ttl, &options);

    let (stop_tx, stop_rx) = mpsc::channel::<()>();
    let renewal_lock = lock.clone();
    let renewal_nonce = nonce.clone();
    let renewal_ttl = options.ttl;
    let renewal_every = options.renew_every;
    let renewal_clock = clock_from_options(&options);
    let renewal_failed = Arc::new(AtomicBool::new(false));
    let renewal_failed_thread = Arc::clone(&renewal_failed);
    let renewal = thread::spawn(move || loop {
        match stop_rx.recv_timeout(renewal_every) {
            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let owner_path = renewal_lock.join("owner");
                let Ok(mut owner) = read_lock_owner(&owner_path) else {
                    renewal_failed_thread.store(true, Ordering::SeqCst);
                    break;
                };
                let Ok(now) = renewal_clock.now_ms() else {
                    renewal_failed_thread.store(true, Ordering::SeqCst);
                    break;
                };
                if owner.nonce != renewal_nonce
                    || now.saturating_sub(owner.claimed_at_ms) >= renewal_ttl.as_millis() as u64
                {
                    renewal_failed_thread.store(true, Ordering::SeqCst);
                    break;
                }
                owner.claimed_at_ms = now;
                if write_lock_owner(&renewal_lock, &owner).is_err() {
                    renewal_failed_thread.store(true, Ordering::SeqCst);
                    break;
                }
            }
        }
    });
    let mut lease = ManifestLease {
        lock: lock.clone(),
        nonce: nonce.clone(),
        ttl: options.ttl,
        clock: clock_from_options(&options),
        renewal_failed,
        stop_tx: Some(stop_tx),
        renewal: Some(renewal),
    };
    let result = operation(&mut lease);
    lease.stop_renewal();
    let result = match result {
        Ok(_) if lease.renewal_failed.load(Ordering::SeqCst) => Err(OpenCodeFilesError::Invalid(
            "manifest lock renewal failed; write aborted".into(),
        )),
        other => other,
    };
    let release = release_manifest_lock(path, &lock, &nonce, &options, options.ttl);
    match (result, release) {
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Ok(value), Ok(())) => Ok(value),
    }
}

fn validate_auth_entry(entry: &Value) -> Result<(), OpenCodeFilesError> {
    let object = entry
        .as_object()
        .ok_or_else(|| OpenCodeFilesError::Invalid("auth entry must be an object".into()))?;
    match object.get("type").and_then(Value::as_str) {
        Some("api") | Some("oauth") | Some("wellknown") => Ok(()),
        _ => Err(OpenCodeFilesError::Invalid("unknown auth shape".into())),
    }
}

fn validate_handle_file(file: &HandleFile) -> Result<(), OpenCodeFilesError> {
    if file.version != 1 {
        return Err(OpenCodeFilesError::Invalid(
            "handle file must have version 1".into(),
        ));
    }
    let mut provider_ids = BTreeSet::new();
    for (index, provider) in file.providers.iter().enumerate() {
        if !identifier_is_valid(&provider.provider) {
            return Err(OpenCodeFilesError::Invalid(format!(
                "provider {index} has invalid provider"
            )));
        }
        if !provider_ids.insert(&provider.provider) {
            return Err(OpenCodeFilesError::Invalid(format!(
                "provider {index} duplicates provider {}",
                provider.provider
            )));
        }
        match provider.shape {
            HandleShape::Api | HandleShape::Oauth => {}
        }
        if provider.serve.is_empty() {
            return Err(OpenCodeFilesError::Invalid(format!(
                "provider {index} requires serve"
            )));
        }
        let mut labels = BTreeSet::new();
        for account in &provider.accounts {
            if !identifier_is_valid(&account.label) {
                return Err(OpenCodeFilesError::Invalid(format!(
                    "provider {index} has an invalid account label"
                )));
            }
            if !labels.insert(&account.label) {
                return Err(OpenCodeFilesError::Invalid(format!(
                    "provider {index} duplicates account label {}",
                    account.label
                )));
            }
            if !valid_handle(&account.handle) {
                return Err(OpenCodeFilesError::Invalid(format!(
                    "provider {index} account {} has invalid handle",
                    account.label
                )));
            }
            // Must match `parseHandleFile` in packages/client/src/handles.ts. THIS IS A
            // WRITER: `validate_handle_file` runs from `write_handle_file_for_tenant` and
            // `verify_handle_written`, so a rule missing here lets `ck auth` ORIGINATE a
            // row the TypeScript reader refuses -- and that reader refuses the whole
            // document, so one bad row written here denies every tenant in the file.
            //
            // Until this commit the check was emptiness only, which let `ck auth` write
            // `oauth:openai` into an `anthropic` block: the exact cross-provider smuggle
            // the TypeScript side was tightened to reject. Two implementations of one
            // predicate in one repo, diverging because the fix landed on the reader.
            //
            // Segment 2 must BE the provider block; NO segment may be empty. Segment 1
            // (kind) is an open set -- oauth, chatgpt, antigravity, apikey are all live --
            // and segment 3+ (label) is operator-chosen and optional, so neither is
            // constrained beyond non-emptiness. `:anthropic:x` and `oauth:anthropic:`
            // satisfy the provider rule literally while naming ids that cannot exist.
            let segments: Vec<&str> = account.credential_id.split(':').collect();
            if account.credential_id.is_empty()
                || segments.get(1) != Some(&provider.provider.as_str())
                || segments.iter().any(|segment| segment.is_empty())
            {
                return Err(OpenCodeFilesError::Invalid(format!(
                    "provider {index} account {} has invalid credential id",
                    account.label
                )));
            }
            if account
                .superseded
                .iter()
                .any(|handle| !valid_handle(handle))
            {
                return Err(OpenCodeFilesError::Invalid(format!(
                    "provider {index} account {} has invalid superseded handle",
                    account.label
                )));
            }
        }
    }
    Ok(())
}

fn valid_handle(handle: &str) -> bool {
    handle.starts_with("ckh_") && handle.len() == 47
}

fn identifier_is_valid(value: &str) -> bool {
    !matches!(value, "__proto__" | "constructor" | "prototype")
        && !value.is_empty()
        && value.len() <= 64
        && value.bytes().enumerate().all(|(index, byte)| match byte {
            b'a'..=b'z' | b'0'..=b'9' => true,
            b'.' | b'_' | b'-' => index > 0,
            _ => false,
        })
}

fn validate_identifier(value: &str, kind: &str) -> Result<(), OpenCodeFilesError> {
    if identifier_is_valid(value) {
        Ok(())
    } else {
        Err(OpenCodeFilesError::Invalid(format!(
            "{kind} must match [a-z0-9][a-z0-9._-]{{0,63}}"
        )))
    }
}

fn write_atomic(path: &Path, bytes: &[u8], secure_parent: bool) -> Result<(), OpenCodeFilesError> {
    write_atomic_guarded(path, bytes, secure_parent, || Ok(()))
}

fn write_atomic_guarded<F>(
    path: &Path,
    bytes: &[u8],
    secure_parent: bool,
    before_rename: F,
) -> Result<(), OpenCodeFilesError>
where
    F: FnOnce() -> Result<(), OpenCodeFilesError>,
{
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| OpenCodeFilesError::Invalid("file path has no parent".into()))?;
    fs::create_dir_all(parent).map_err(|source| OpenCodeFilesError::Io {
        action: "create parent directory",
        source,
    })?;
    validate_secure_parent(parent)?;
    if secure_parent {
        set_mode(parent, 0o700)?;
    }
    let name = path
        .file_name()
        .ok_or_else(|| OpenCodeFilesError::Invalid("file path has no filename".into()))?;
    let temp = parent.join(format!(
        ".{}.{}.{}.tmp",
        name.to_string_lossy(),
        std::process::id(),
        TEMP_SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| -> Result<(), OpenCodeFilesError> {
        #[cfg(unix)]
        let mut file = {
            use std::os::unix::fs::OpenOptionsExt;
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temp)
                .map_err(|source| OpenCodeFilesError::Io {
                    action: "create temporary file",
                    source,
                })?
        };
        #[cfg(not(unix))]
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
            .map_err(|source| OpenCodeFilesError::Io {
                action: "create temporary file",
                source,
            })?;
        set_mode(&temp, 0o600)?;
        file.write_all(bytes)
            .map_err(|source| OpenCodeFilesError::Io {
                action: "write temporary file",
                source,
            })?;
        file.sync_all().map_err(|source| OpenCodeFilesError::Io {
            action: "sync temporary file",
            source,
        })?;
        before_rename()?;
        fs::rename(&temp, path).map_err(|source| OpenCodeFilesError::Io {
            action: "rename temporary file",
            source,
        })?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|source| OpenCodeFilesError::Io {
                action: "sync parent directory",
                source,
            })?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

fn validate_secure_file(path: &Path) -> Result<(), OpenCodeFilesError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| OpenCodeFilesError::Io {
        action: "stat file",
        source,
    })?;
    if !metadata.file_type().is_file() {
        return Err(OpenCodeFilesError::Invalid(
            "file must be a regular file".into(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != current_uid()? {
            return Err(OpenCodeFilesError::Invalid(
                "file is not owned by the current uid".into(),
            ));
        }
        if metadata.permissions().mode() & 0o777 != 0o600 {
            return Err(OpenCodeFilesError::Invalid(
                "file mode must be exactly 0600".into(),
            ));
        }
    }
    Ok(())
}

fn read_limited(path: &Path, max_bytes: u64, kind: &str) -> Result<Vec<u8>, OpenCodeFilesError> {
    let metadata = fs::metadata(path).map_err(|source| OpenCodeFilesError::Io {
        action: "stat file for read limit",
        source,
    })?;
    if metadata.len() > max_bytes {
        let limit = if max_bytes == AUTH_FILE_MAX_BYTES {
            "1 MiB".into()
        } else {
            format!("{} KiB", max_bytes / 1024)
        };
        return Err(OpenCodeFilesError::Invalid(format!(
            "{kind} exceeds {limit}",
        )));
    }
    fs::read(path).map_err(|source| OpenCodeFilesError::Io {
        action: "read file",
        source,
    })
}

/// Refuse when any ancestor of `parent` is group- or world-writable without sticky.
///
/// CANONICALISE FIRST, THEN WALK THE CANONICAL COMPONENTS. An unresolved walk is defeated
/// by a symlink component pointing somewhere permissive: every individual stat passes, the
/// loop visibly covers every component, and the whole thing is about a path we do not
/// write through. A guard returning true about the wrong subject, and the nastiest member
/// of that family because it LOOKS exhaustive.
///
/// STICKY EXEMPTS. `/tmp` and `/Users/Shared` are 1777, so without the exemption this
/// refuses on correctly-configured systems -- and a lint that fires on healthy
/// configuration gets disabled, after which the real signal reaches nobody. Load-bearing
/// rather than a courtesy.
///
/// A parent that cannot be canonicalised returns Ok: the operation that follows reports the
/// real errno, and refusing here would replace a precise "no such file" with a permissions
/// verdict about a path we could not resolve.
#[cfg(unix)]
fn refuse_writable_ancestor(parent: &Path) -> Result<(), OpenCodeFilesError> {
    use std::os::unix::fs::PermissionsExt;

    let Ok(resolved) = fs::canonicalize(parent) else {
        return Ok(());
    };

    let mut component = resolved.as_path();
    loop {
        // An unreadable component is skipped rather than refused. Canonicalising already
        // required traverse permission on every component, so a metadata failure here is
        // close to unreachable -- and refusing on it would convert a transient io error
        // into a permissions verdict, the same trade the canonicalise arm declines.
        if let Ok(metadata) = fs::metadata(component) {
            let mode = metadata.permissions().mode();
            if mode & 0o022 != 0 && mode & 0o1000 == 0 {
                return Err(OpenCodeFilesError::InsecureParent {
                    path: component.to_path_buf(),
                    reason: "an ancestor is group- or world-writable without sticky bit",
                });
            }
        }
        match component.parent() {
            Some(next) => component = next,
            None => return Ok(()),
        }
    }
}

#[cfg(not(unix))]
fn refuse_writable_ancestor(_parent: &Path) -> Result<(), OpenCodeFilesError> {
    // Windows ACLs are not a mode bitmask and the Unix reasoning does not carry. Stated
    // rather than silently skipped, so the absence is a decision.
    Ok(())
}

fn validate_secure_parent(path: &Path) -> Result<(), OpenCodeFilesError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| OpenCodeFilesError::Io {
        action: "stat parent directory",
        source,
    })?;
    if !metadata.file_type().is_dir() {
        return Err(OpenCodeFilesError::Invalid(
            "parent directory must be a directory".into(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != current_uid()? {
            return Err(OpenCodeFilesError::InsecureParent {
                path: path.into(),
                reason: "not owned by the current uid",
            });
        }
        // GROUP-WRITABLE COUNTS, NOT ONLY WORLD-WRITABLE. Directory write permission
        // governs unlink and create, so anyone who can write the parent can replace a
        // mode-0600 file wholesale no matter how tightly the file itself is locked.
        // The owner check above does not close this: a directory I own can still be
        // group-writable (0770), and then any other uid in that group can swap the
        // handle file for one of theirs.
        //
        // That matters more than the file's own mode, because a cross-uid attacker is
        // NOT conceded by this threat model the way a same-uid one is. Latent here --
        // the real directories are 0700/0755 -- which is exactly why a guard against
        // misconfiguration must cover the misconfiguration.
        //
        // The sticky exemption applies to both bits for the same reason it applies to
        // one: with it set, a writer may only unlink files they own.
        let mode = metadata.permissions().mode();
        if mode & 0o022 != 0 && mode & 0o1000 == 0 {
            return Err(OpenCodeFilesError::InsecureParent {
                path: path.into(),
                reason: "group- or world-writable without sticky bit",
            });
        }
        // EVERY ANCESTOR, NOT JUST THIS ONE, OR THE GUARANTEE DOES NOT COMPOSE.
        //
        // Checking the immediate parent alone leaves a live hole rather than merely being
        // incomplete: anyone who can create and unlink in ANY ancestor renames an
        // intermediate directory aside and substitutes their own tree. With `~/.local` at
        // 0777, this directory being 0700 protects nothing.
        //
        // Walk to `/` rather than $HOME or an XDG base. A stopping point read from the
        // environment is attacker-influenceable and undefined when unset, which is the
        // shape a security bound must not have.
        //
        // Shape agreed with SUBC 2026-09-18 and mirrored from subc-transport 0.7.0
        // (refuse_writable_ancestor), read at source rather than from their description.
        refuse_writable_ancestor(path)?;
    }
    Ok(())
}

fn set_mode(path: &Path, mode: u32) -> Result<(), OpenCodeFilesError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|source| {
            OpenCodeFilesError::Io {
                action: "set file mode",
                source,
            }
        })?;
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }
    Ok(())
}

#[cfg(unix)]
fn current_uid() -> Result<u32, OpenCodeFilesError> {
    std::process::Command::new("/usr/bin/id")
        .arg("-u")
        .output()
        .map_err(|source| OpenCodeFilesError::Io {
            action: "determine current uid",
            source,
        })
        .and_then(|output| {
            if !output.status.success() {
                return Err(OpenCodeFilesError::Invalid(
                    "determine current uid failed".into(),
                ));
            }
            String::from_utf8(output.stdout)
                .map_err(|_| OpenCodeFilesError::Invalid("current uid was not UTF-8".into()))?
                .trim()
                .parse()
                .map_err(|_| OpenCodeFilesError::Invalid("current uid was invalid".into()))
        })
}

// UNIX ONLY, like every other custody test in this file. The module imports
// std::os::unix::fs::PermissionsExt and asserts 0600 publication, parent modes, and
// symlink refusal -- none of which exist on Windows, where the import alone is E0433.
//
// The function under test is already #[cfg(unix)] at line 1100, so an ungated test module
// for it cannot compile on Windows at all. Caught by CI rather than locally: a macOS gate
// compiles every one of these happily, and the branch's own checks are the fork-safe
// subset that never builds Rust.
#[cfg(all(test, unix))]
mod manifest_lock_aba_regression {
    use super::*;
    use std::{
        os::unix::fs::PermissionsExt,
        sync::{Arc, Barrier},
        thread,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    #[test]
    fn aba_observation_cannot_rename_a_replacement_lock() {
        let root = std::env::temp_dir().join(format!(
            "claustrum-manifest-lock-aba-{}-{}",
            std::process::id(),
            TEMP_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("opencode-handles.json");
        let lock = lock_path(&path);
        let now = now_ms();
        fs::create_dir(&lock).unwrap();
        fs::set_permissions(&lock, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(
            lock.join("owner"),
            format!(
                "{{\"tenant\":\"other-tenant\",\"pid\":41,\"claimed_at_ms\":{},\"nonce\":\"0123456789abcdef0123456789abcdef\"}}\n",
                now - 501
            ),
        )
        .unwrap();
        fs::set_permissions(lock.join("owner"), fs::Permissions::from_mode(0o600)).unwrap();

        let loser_observed = Arc::new(Barrier::new(2));
        let allow_loser_rename = Arc::new(Barrier::new(2));
        let replacement_claimed = Arc::new(Barrier::new(2));
        let allow_replacement_release = Arc::new(Barrier::new(2));
        let rename_attempted = Arc::new(Barrier::new(2));
        let allow_attempt_completion = Arc::new(Barrier::new(2));

        let loser_path = path.clone();
        let loser = thread::spawn({
            let loser_observed = Arc::clone(&loser_observed);
            let allow_loser_rename = Arc::clone(&allow_loser_rename);
            let rename_attempted = Arc::clone(&rename_attempted);
            let allow_attempt_completion = Arc::clone(&allow_attempt_completion);
            move || {
                with_manifest_lock_with_options(
                    &loser_path,
                    "loser",
                    ManifestLockOptions {
                        ttl: Duration::from_millis(500),
                        renew_every: Duration::from_secs(1),
                        retry_min: Duration::from_millis(2),
                        retry_max: Duration::from_millis(3),
                        before_evict: Some(Arc::new(move || {
                            loser_observed.wait();
                            allow_loser_rename.wait();
                        })),
                        after_evict_rename_attempt: Some(Arc::new(move || {
                            rename_attempted.wait();
                            allow_attempt_completion.wait();
                        })),
                        now_override_ms: Some(now),
                        ..ManifestLockOptions::default()
                    },
                    |_| Ok(()),
                )
            }
        });

        loser_observed.wait();
        let replacement_path = path.clone();
        let replacement = thread::spawn({
            let replacement_claimed = Arc::clone(&replacement_claimed);
            let allow_replacement_release = Arc::clone(&allow_replacement_release);
            move || {
                with_manifest_lock_with_options(
                    &replacement_path,
                    "replacement",
                    ManifestLockOptions {
                        ttl: Duration::from_millis(500),
                        renew_every: Duration::from_secs(1),
                        retry_min: Duration::from_millis(2),
                        retry_max: Duration::from_millis(3),
                        after_claim: Some(Arc::new(move || {
                            replacement_claimed.wait();
                            allow_replacement_release.wait();
                        })),
                        now_override_ms: Some(now),
                        ..ManifestLockOptions::default()
                    },
                    |_| Ok(()),
                )
            }
        });

        replacement_claimed.wait();
        allow_loser_rename.wait();
        rename_attempted.wait();
        allow_replacement_release.wait();
        replacement.join().unwrap().unwrap();
        allow_attempt_completion.wait();
        loser.join().unwrap().unwrap();
        assert!(!lock.exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn two_stale_evictors_create_exactly_one_quarantine_directory() {
        let root = std::env::temp_dir().join(format!(
            "claustrum-manifest-lock-quarantine-{}-{}",
            std::process::id(),
            TEMP_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("opencode-handles.json");
        let lock = lock_path(&path);
        let now = now_ms();
        fs::create_dir(&lock).unwrap();
        fs::set_permissions(&lock, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(
            lock.join("owner"),
            format!(
                "{{\"tenant\":\"other-tenant\",\"pid\":41,\"claimed_at_ms\":{},\"nonce\":\"0123456789abcdef0123456789abcdef\"}}\n",
                now - 501
            ),
        )
        .unwrap();
        fs::set_permissions(lock.join("owner"), fs::Permissions::from_mode(0o600)).unwrap();
        let ready = Arc::new(Barrier::new(2));
        let evictions = Arc::new(AtomicU64::new(0));
        let mut joins = Vec::new();
        for tenant in ["anthropic-auth", "openai-auth"] {
            let path = path.clone();
            let ready = Arc::clone(&ready);
            let evictions = Arc::clone(&evictions);
            joins.push(thread::spawn(move || {
                with_manifest_lock_with_options(
                    &path,
                    tenant,
                    ManifestLockOptions {
                        ttl: Duration::from_millis(500),
                        renew_every: Duration::from_secs(1),
                        retry_min: Duration::from_millis(2),
                        retry_max: Duration::from_millis(3),
                        before_evict: Some(Arc::new(move || {
                            ready.wait();
                        })),
                        after_evict: Some(Arc::new(move || {
                            evictions.fetch_add(1, Ordering::SeqCst);
                        })),
                        now_override_ms: Some(now),
                        ..ManifestLockOptions::default()
                    },
                    |_| Ok(()),
                )
            }));
        }
        for join in joins {
            join.join().unwrap().unwrap();
        }
        let stale = fs::read_dir(&root)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().contains(".lock.stale-"))
            .count();
        assert_eq!(evictions.load(Ordering::SeqCst), 1);
        assert_eq!(stale, 1);
        let _ = fs::remove_dir_all(root);
    }

    fn seed_owner(path: &Path, owner: &str) -> PathBuf {
        let lock = lock_path(path);
        fs::create_dir(&lock).unwrap();
        fs::set_permissions(&lock, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(lock.join("owner"), owner).unwrap();
        fs::set_permissions(lock.join("owner"), fs::Permissions::from_mode(0o600)).unwrap();
        lock
    }

    fn seed_quarantine(path: &Path, claimed_at_ms: u64, nonce: &str) -> PathBuf {
        let quarantine = path.with_file_name(format!(
            "{}.lock.stale-{claimed_at_ms}-{nonce}",
            path.file_name().unwrap().to_string_lossy()
        ));
        fs::create_dir(&quarantine).unwrap();
        fs::set_permissions(&quarantine, fs::Permissions::from_mode(0o700)).unwrap();
        quarantine
    }

    /// Stamp a directory's mtime, and on failure SAY WHAT THE DISK LOOKED LIKE.
    ///
    /// This open has failed with `NotFound` on a path the same thread created two
    /// statements earlier, under a loaded full gate, repeatedly since 2026-09-18 — and
    /// every occurrence has been a bare `Os { code: 2 }` with nothing to reason from.
    /// Two explanations fit it and they need different fixes: the directory was created
    /// and then REMOVED by something, or the create returned success without the entry
    /// being visible to the next syscall. A bare NotFound cannot tell them apart.
    ///
    /// So the failure now reports whether the path exists on a re-stat and what its
    /// parent actually contains. A deleter leaves an empty or differently-populated
    /// parent; a visibility problem leaves the entry sitting there while the open that
    /// just failed says it does not. Deliberately NOT a retry: retrying would make the
    /// flake disappear and take the evidence with it, and I do not yet know which
    /// failure I would be papering over.
    fn set_directory_mtime(path: &Path, modified_at_ms: u64) {
        fs::File::open(path)
            .unwrap_or_else(|error| {
                let exists = path.exists();
                let siblings: Vec<String> = path
                    .parent()
                    .and_then(|parent| fs::read_dir(parent).ok())
                    .map(|entries| {
                        entries
                            .flatten()
                            .map(|entry| entry.file_name().to_string_lossy().into_owned())
                            .collect()
                    })
                    .unwrap_or_default();
                panic!(
                    "opening {path:?} to stamp its mtime failed with {error:?}; \
                     re-stat says exists={exists}; parent holds {siblings:?}. \
                     exists=true means the entry is there and the open disagreed \
                     (a visibility problem); exists=false with a populated parent \
                     means something removed this one specifically; an empty parent \
                     means the whole fixture directory went."
                )
            })
            .set_times(
                fs::FileTimes::new()
                    .set_modified(UNIX_EPOCH + Duration::from_millis(modified_at_ms)),
            )
            .unwrap();
    }

    /// PIN THE RECLAIM CLOCK, so a fixture's verdict is arithmetic rather than a race.
    ///
    /// *** THERE IS DELIBERATELY NO UNPINNED SIBLING. *** One existed, `reclaim_options(ttl)`,
    /// which called this with `now_ms()`, and it reintroduced the exact race this helper was
    /// written to remove: the FIXTURE reads the clock to seed an mtime and the helper then
    /// reads it AGAIN, so the age under test is `101ms + however long the test body took`. A
    /// retention fixture ages past its own threshold under load and the verdict flips. It
    /// survived the first pass at this bug because the three tests it was added for were
    /// converted and the three calling it were not.
    ///
    /// Measured when that was found: `quarantine_past_ttl_but_inside_margin_is_retained` seeds
    /// `now - 101` against a 100ms ttl, so its whole budget is the reclaim margin minus one
    /// millisecond. It passed in isolation every time and failed inside a loaded full gate.
    /// `quarantine_younger_than_reclaim_age_is_retained` has the same defect with ~900ms of
    /// slack, which buys a lower failure rate rather than correctness.
    ///
    /// Requiring an explicit instant at every call site makes the double read impossible
    /// rather than merely discouraged: a caller must hold ONE `at` and use it for both the
    /// mtime and the verdict, which is the property these fixtures need.
    ///
    /// Without this the reclaim path reads the wall clock while the fixture seeds an mtime
    /// relative to its own earlier reading of that clock, so the answer depends on how long
    /// the test body takes. Under full-gate parallelism the fixture ages past its own
    /// threshold before the assertion runs, and WHICH member fails is a function of
    /// scheduling rather than of the member -- which is why three different members tripped
    /// across three runs (issue #51).
    ///
    /// Raising the TTL would only move the load at which it happens. Every failure in this
    /// class looks like a flake worth re-running, and a green re-run at idle looks like a
    /// fix, so the defect survives being noticed.
    ///
    /// Seed mtimes from the SAME `at_ms` this returns. Mixing a pinned reclaim clock with a
    /// wall-clock mtime reintroduces the split one level down.
    fn reclaim_options_at(ttl: Duration, at_ms: u64) -> ManifestLockOptions {
        ManifestLockOptions {
            ttl,
            renew_every: Duration::from_secs(1),
            retry_min: Duration::from_millis(1),
            retry_max: Duration::from_millis(1),
            now_override_ms: Some(at_ms),
            ..ManifestLockOptions::default()
        }
    }

    // A SLOW LOCK BODY MUST NOT CHANGE A RECLAIM VERDICT.
    //
    // This is the property behind issue #51. The reclaim used to read `SystemTime::now()`
    // deep inside the lock call, after retries and sleeps, while the fixture seeded an
    // mtime from its own earlier reading -- so the verdict depended on elapsed wall time
    // and DIFFERENT members failed on different runs under gate parallelism.
    //
    // 350ms of delay against a fixture seeded 4.1s into a 5.1s threshold: 900ms of slack,
    // so this passes either way UNLESS the delay is counted. Under the old wall-clock read
    // the same shape at higher load is what deleted the directory.
    //
    // Mutation-checked in both directions: reverting the reclaim to `SystemTime::now()`
    // and raising this delay past the slack deletes the quarantine and fails here.
    #[test]
    fn a_slow_lock_body_does_not_age_a_quarantine_into_reclamation() {
        let root = std::env::temp_dir().join(format!(
            "claustrum-manifest-lock-reclaim-slow-{}-{}",
            std::process::id(),
            TEMP_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("opencode-handles.json");
        let at = now_ms();
        let quarantine = seed_quarantine(&path, 1, "slow_body_nonce");
        set_directory_mtime(&quarantine, at - 4_100);

        let mut options = reclaim_options_at(Duration::from_millis(100), at);
        options.after_claim = Some(Arc::new(|| thread::sleep(Duration::from_millis(350))));

        with_manifest_lock_with_options(&path, "claimant", options, |_| Ok(())).unwrap();

        assert!(
            quarantine.exists(),
            "a quarantine inside the reclaim threshold was deleted because the lock body \
             took time -- the verdict is reading elapsed wall time rather than the clock \
             the fixture pinned"
        );
        let _ = fs::remove_dir_all(root);
    }

    // THE WRITER REFUSES A GROUP-WRITABLE PARENT, NOT ONLY A WORLD-WRITABLE ONE.
    //
    // Directory write permission governs unlink and create, so anyone who can write the
    // parent replaces a mode-0600 handle file wholesale however tightly the file itself is
    // locked. The uid check above does not close it: a directory the user owns can still
    // be 0770, and then any other uid in that group can swap the file for one of theirs.
    // A cross-uid attacker is not conceded by this threat model the way a same-uid one is.
    //
    // Latent on the machines we run today -- the real directories are 0700 and 0755 --
    // which is precisely why a guard that exists to catch a misconfiguration has to cover
    // the misconfiguration rather than the configuration we happen to have.
    //
    // The 0700 arm is the control: it proves the refusal came from the group bit rather
    // than from anything else about the fixture.
    // THE STICKY EXEMPTION IS EXERCISED, AND WITHOUT THIS TEST IT IS NOT.
    //
    // Found by mutation: dropping the exemption changed no result in either suite. The
    // reason is that fixtures live under the per-user TMPDIR (/private/var/folders/.../T
    // on macOS), whose entire chain is 0700/0755 -- so no fixture path contains a
    // group- or world-writable directory and the exemption branch is never taken. The
    // 1777 directories that motivate it, /tmp and /Users/Shared, are nowhere on it.
    //
    // This builds its own 1777 ancestor so the walk MUST take that branch. Hermetic and
    // rootless: chmod 1777 on a directory we own needs no privilege, and it avoids
    // writing fixtures into a shared world-writable directory where another process
    // could interfere.
    //
    // Mutation-checked: removing `mode & 0o1000 == 0` from the walk fails this by name
    // while every other member stays green.
    #[test]
    #[cfg(unix)]
    fn a_sticky_group_writable_ancestor_is_allowed_through() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!(
            "claustrum-sticky-{}-{}",
            std::process::id(),
            TEMP_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let shared = root.join("shared-like-tmp");
        let leaf = shared.join("leaf");
        fs::create_dir_all(&leaf).unwrap();
        fs::set_permissions(&leaf, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();

        // 1777, exactly the shape of /tmp: group- and world-writable, sticky set.
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o1777)).unwrap();
        assert_eq!(
            fs::metadata(&shared).unwrap().permissions().mode() & 0o7777,
            0o1777,
            "the fixture must actually be 1777 or this test proves nothing"
        );

        assert!(
            validate_secure_parent(&leaf).is_ok(),
            "a sticky group+world-writable ancestor must be allowed -- /tmp is 1777, and a \
             lint that refuses a correctly-configured system gets disabled"
        );

        // Without sticky the same directory must refuse, proving the exemption is what
        // allowed it rather than something else about the fixture.
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(
            validate_secure_parent(&leaf).is_err(),
            "the same ancestor without sticky must be refused"
        );

        fs::set_permissions(&shared, fs::Permissions::from_mode(0o700)).unwrap();
        let _ = fs::remove_dir_all(root);
    }

    // AN ANCESTOR IS REFUSED, NOT ONLY THE IMMEDIATE PARENT.
    //
    // The immediate parent being 0700 protects nothing if a directory above it is
    // group-writable: anyone who can create and unlink there renames it aside and
    // substitutes their own tree. This fixture is exactly that shape -- a locked-down
    // leaf under a permissive grandparent -- and it PASSES the immediate-parent check,
    // which is what makes it the discriminating case.
    #[test]
    #[cfg(unix)]
    fn a_group_writable_ancestor_is_refused_even_when_the_immediate_parent_is_0700() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!(
            "claustrum-ancestor-{}-{}",
            std::process::id(),
            TEMP_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let leaf = root.join("mid").join("leaf");
        fs::create_dir_all(&leaf).unwrap();
        fs::set_permissions(&leaf, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(root.join("mid"), fs::Permissions::from_mode(0o700)).unwrap();

        // Control: the whole chain tight, so a later refusal is attributable to the bit
        // this test sets and not to anything else about the fixture.
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            validate_secure_parent(&leaf).is_ok(),
            "a fully locked-down chain must pass, or the refusal below proves nothing"
        );

        fs::set_permissions(&root, fs::Permissions::from_mode(0o770)).unwrap();
        let refused = match validate_secure_parent(&leaf) {
            Err(e) => e.to_string(),
            Ok(()) => panic!(
                "a group-writable ANCESTOR must be refused; the immediate \
                              parent being 0700 does not make the path safe"
            ),
        };
        assert!(
            refused.contains("ancestor"),
            "refused for the wrong reason: {refused}"
        );

        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    #[cfg(unix)]
    fn a_group_writable_parent_is_refused_even_when_the_file_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!(
            "claustrum-parent-group-{}-{}",
            std::process::id(),
            TEMP_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("opencode-handles.json");
        fs::write(&path, b"{}").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        fs::set_permissions(&root, fs::Permissions::from_mode(0o770)).unwrap();
        let refused = validate_secure_parent(&root);
        let refused_message = match refused {
            Err(e) => e.to_string(),
            Ok(()) => panic!("a group-writable parent must be refused, but it passed"),
        };
        assert!(
            refused_message.contains("group- or world-writable"),
            "refused for the wrong reason: {refused_message}"
        );

        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            validate_secure_parent(&root).is_ok(),
            "the same fixture without the group bit must pass, or the refusal proves nothing"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn quarantine_younger_than_reclaim_age_is_retained() {
        let root = std::env::temp_dir().join(format!(
            "claustrum-manifest-lock-reclaim-young-{}-{}",
            std::process::id(),
            TEMP_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("opencode-handles.json");
        let ttl = Duration::from_millis(100);
        let quarantine = seed_quarantine(&path, 1, "young_nonce");
        let at = now_ms();
        set_directory_mtime(&quarantine, at - 4_100);

        with_manifest_lock_with_options(&path, "claimant", reclaim_options_at(ttl, at), |_| Ok(()))
            .unwrap();

        assert!(quarantine.exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn quarantine_older_than_reclaim_age_is_reclaimed() {
        let root = std::env::temp_dir().join(format!(
            "claustrum-manifest-lock-reclaim-old-{}-{}",
            std::process::id(),
            TEMP_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("opencode-handles.json");
        let ttl = Duration::from_millis(100);
        let quarantine = seed_quarantine(&path, 1, "old_nonce");
        let at = now_ms();
        set_directory_mtime(&quarantine, at - 5_101);

        with_manifest_lock_with_options(&path, "claimant", reclaim_options_at(ttl, at), |_| Ok(()))
            .unwrap();

        assert!(!quarantine.exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn quarantine_past_ttl_but_inside_margin_is_retained() {
        let root = std::env::temp_dir().join(format!(
            "claustrum-manifest-lock-reclaim-margin-{}-{}",
            std::process::id(),
            TEMP_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("opencode-handles.json");
        let ttl = Duration::from_millis(100);
        let quarantine = seed_quarantine(&path, 1, "margin_nonce");
        let at = now_ms();
        set_directory_mtime(&quarantine, at - 101);

        with_manifest_lock_with_options(&path, "claimant", reclaim_options_at(ttl, at), |_| Ok(()))
            .unwrap();

        assert!(quarantine.exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn old_quarantine_name_with_recent_mtime_is_retained() {
        let root = std::env::temp_dir().join(format!(
            "claustrum-manifest-lock-reclaim-mtime-{}-{}",
            std::process::id(),
            TEMP_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("opencode-handles.json");
        let quarantine = seed_quarantine(&path, 1, "recent_mtime_nonce");
        let at = now_ms();
        set_directory_mtime(&quarantine, at);

        with_manifest_lock_with_options(
            &path,
            "claimant",
            reclaim_options_at(Duration::from_millis(100), at),
            |_| Ok(()),
        )
        .unwrap();

        assert!(quarantine.exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn reclaim_leaves_nonmatching_siblings_live_lock_and_other_manifest_quarantine() {
        let root = std::env::temp_dir().join(format!(
            "claustrum-manifest-lock-reclaim-scope-{}-{}",
            std::process::id(),
            TEMP_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("opencode-handles.json");
        let nonmatching = root.join("opencode-handles.json.lock.stale-not-a-timestamp-nonce");
        let unrelated_file = root.join("unrelated");
        let other_path = root.join("another-manifest.json");
        let other_quarantine = seed_quarantine(&other_path, 1, "other_nonce");
        fs::create_dir(&nonmatching).unwrap();
        fs::write(&unrelated_file, "untouched").unwrap();
        let at = now_ms();
        set_directory_mtime(&nonmatching, at - 5_101);
        set_directory_mtime(&other_quarantine, at - 5_101);

        with_manifest_lock_with_options(
            &path,
            "claimant",
            reclaim_options_at(Duration::from_millis(100), at),
            |_| {
                assert!(lock_path(&path).is_dir());
                Ok(())
            },
        )
        .unwrap();

        assert!(nonmatching.exists());
        assert_eq!(fs::read_to_string(&unrelated_file).unwrap(), "untouched");
        assert!(other_quarantine.exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn reclaim_failure_does_not_fail_acquisition() {
        let root = std::env::temp_dir().join(format!(
            "claustrum-manifest-lock-reclaim-failure-{}-{}",
            std::process::id(),
            TEMP_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("opencode-handles.json");
        let quarantine = seed_quarantine(&path, 1, "unreadable_nonce");
        let at = now_ms();
        set_directory_mtime(&quarantine, at - 5_101);
        fs::set_permissions(&root, fs::Permissions::from_mode(0o300)).unwrap();

        let result = with_manifest_lock_with_options(
            &path,
            "claimant",
            reclaim_options_at(Duration::from_millis(100), at),
            |_| Ok(()),
        );

        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(result.is_ok());
        assert!(quarantine.exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn unknown_owner_keys_are_tolerated_and_evictable_once_stale() {
        let root = std::env::temp_dir().join(format!(
            "claustrum-manifest-lock-unknown-key-{}-{}",
            std::process::id(),
            TEMP_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("opencode-handles.json");
        let now = now_ms();
        seed_owner(
            &path,
            &format!(
                "{{\"tenant\":\"other\",\"pid\":41,\"claimed_at_ms\":{},\"nonce\":\"0123456789abcdef0123456789abcdef\",\"host\":\"x\"}}\n",
                now - 501
            ),
        );
        let result = with_manifest_lock_with_options(
            &path,
            "claimant",
            ManifestLockOptions {
                ttl: Duration::from_millis(500),
                now_override_ms: Some(now),
                ..ManifestLockOptions::default()
            },
            |_| Ok(()),
        );
        assert!(result.is_ok());
        assert!(!lock_path(&path).exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn malformed_diagnostic_owner_fields_are_tolerated_and_evictable_once_stale() {
        let root = std::env::temp_dir().join(format!(
            "claustrum-manifest-lock-malformed-diagnostic-{}-{}",
            std::process::id(),
            TEMP_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("opencode-handles.json");
        let now = now_ms();
        seed_owner(
            &path,
            &format!(
                "{{\"pid\":\"not-a-number\",\"claimed_at_ms\":{},\"nonce\":\"0123456789abcdef0123456789abcdef\"}}\n",
                now - 501
            ),
        );
        let result = with_manifest_lock_with_options(
            &path,
            "claimant",
            ManifestLockOptions {
                ttl: Duration::from_millis(500),
                now_override_ms: Some(now),
                ..ManifestLockOptions::default()
            },
            |_| Ok(()),
        );
        assert!(result.is_ok());
        assert!(!lock_path(&path).exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn missing_owner_nonce_fails_with_owner_invalid_at_deadline() {
        let root = std::env::temp_dir().join(format!(
            "claustrum-manifest-lock-owner-invalid-{}-{}",
            std::process::id(),
            TEMP_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("opencode-handles.json");
        let now = now_ms();
        seed_owner(
            &path,
            &format!(
                "{{\"tenant\":\"other\",\"pid\":41,\"claimed_at_ms\":{}}}\n",
                now - 501
            ),
        );
        let result = with_manifest_lock_with_options(
            &path,
            "claimant",
            ManifestLockOptions {
                ttl: Duration::from_millis(20),
                retry_min: Duration::from_millis(2),
                retry_max: Duration::from_millis(3),
                now_override_ms: Some(now),
                ..ManifestLockOptions::default()
            },
            |_| Ok(()),
        );
        assert_eq!(
            result.unwrap_err().to_string(),
            "manifest lock owner invalid"
        );
        let _ = fs::remove_dir_all(root);
    }

    /// The release path must read the clock the claim was stamped from.
    ///
    /// Pins the disagreement directly rather than waiting for a loaded machine to expose
    /// it. `owner_that_becomes_stale_during_retry_window_is_evicted` can catch the same
    /// defect, but only when real elapsed time happens to exceed the injected offset plus
    /// the TTL -- which is a property of the machine, not of the code. Here the work
    /// inside the lock outlasts the TTL by construction, so a release reading the real
    /// clock ALWAYS sees `real_elapsed - injected_offset >= ttl`, concludes its lease is
    /// lost, and leaves the directory behind. The injected clock never moves, so a
    /// release reading it always computes age 0 and removes the directory.
    ///
    /// The sleep is what makes the arithmetic deterministic. It is not a widened window:
    /// raising the TTL would hide the disagreement, and this exposes it on every run.
    #[test]
    fn lock_release_reads_the_clock_the_claim_was_stamped_from() {
        let root = std::env::temp_dir().join(format!(
            "claustrum-manifest-lock-release-clock-{}-{}",
            std::process::id(),
            TEMP_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("opencode-handles.json");
        let ttl = Duration::from_millis(100);
        let clock = Arc::new(AtomicU64::new(now_ms()));
        let result = with_manifest_lock_with_options(
            &path,
            "claimant",
            ManifestLockOptions {
                ttl,
                now_sequence_ms: Some(clock),
                ..ManifestLockOptions::default()
            },
            |_| {
                thread::sleep(ttl * 3);
                Ok(())
            },
        );
        assert!(
            result.is_ok(),
            "holding the lock past its TTL is not an error"
        );
        assert!(
            !lock_path(&path).exists(),
            "release read the real clock against an injected claim stamp and skipped cleanup"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn owner_that_becomes_stale_during_retry_window_is_evicted() {
        let root = std::env::temp_dir().join(format!(
            "claustrum-manifest-lock-observation-clock-{}-{}",
            std::process::id(),
            TEMP_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("opencode-handles.json");
        let now = now_ms();
        seed_owner(
            &path,
            &format!(
                "{{\"tenant\":\"other\",\"pid\":41,\"claimed_at_ms\":{},\"nonce\":\"0123456789abcdef0123456789abcdef\"}}\n",
                now - 80
            ),
        );
        let clock = Arc::new(AtomicU64::new(now));
        let advancing_clock = Arc::clone(&clock);
        let advance = thread::spawn(move || {
            thread::sleep(Duration::from_millis(20));
            advancing_clock.store(now + 100, Ordering::SeqCst);
        });
        let result = with_manifest_lock_with_options(
            &path,
            "claimant",
            ManifestLockOptions {
                ttl: Duration::from_millis(100),
                retry_min: Duration::from_millis(50),
                retry_max: Duration::from_millis(50),
                now_sequence_ms: Some(clock),
                ..ManifestLockOptions::default()
            },
            |_| Ok(()),
        );
        advance.join().unwrap();
        assert!(result.is_ok());
        assert!(!lock_path(&path).exists());
        let _ = fs::remove_dir_all(root);
    }

    /// `commit` must read the lease's clock, not the wall clock.
    ///
    /// The claim stamps `claimed_at_ms` from the injected clock (which never
    /// moves), then the critical section sleeps 300ms of REAL time -- longer
    /// than the 200ms TTL. If `commit` reads the real clock it computes
    /// `real_now - injected_stamp >= ttl`, concludes the lease is stale, and
    /// returns `Err`. If it reads the lease's clock the age is 0 and it returns
    /// `Ok`. The sleep makes the arithmetic deterministic on every run, not
    /// just under load.
    #[test]
    fn commit_measures_the_lease_clock_not_the_wall_clock() {
        let root = std::env::temp_dir().join(format!(
            "claustrum-manifest-lock-commit-clock-{}-{}",
            std::process::id(),
            TEMP_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("opencode-handles.json");
        let now = now_ms();
        let result = with_manifest_lock_with_options(
            &path,
            "claimant",
            ManifestLockOptions {
                ttl: Duration::from_millis(200),
                renew_every: Duration::from_secs(10),
                now_override_ms: Some(now),
                ..ManifestLockOptions::default()
            },
            |lease| {
                thread::sleep(Duration::from_millis(300));
                lease.commit()
            },
        );
        assert!(
            result.is_ok(),
            "commit read the wall clock against an injected claim stamp and refused a lease \
             whose injected age is 0"
        );
        let _ = fs::remove_dir_all(root);
    }

    /// The renewal thread must read the lease's clock, not the wall clock.
    ///
    /// The renewal interval is longer than the TTL, so the first renewal fires
    /// after the TTL has expired in real time. If the renewal thread reads the
    /// real clock it computes `real_now - injected_stamp >= ttl`, concludes the
    /// lease is stale, sets `renewal_failed`, and `commit` refuses. If it reads
    /// the lease's clock the age is 0, the stamp is refreshed, and the call
    /// succeeds. The sleep keeps the critical section open long enough for the
    /// renewal to fire.
    #[test]
    fn renewal_thread_measures_the_lease_clock_not_the_wall_clock() {
        let root = std::env::temp_dir().join(format!(
            "claustrum-manifest-lock-renewal-clock-{}-{}",
            std::process::id(),
            TEMP_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("opencode-handles.json");
        let now = now_ms();
        let result = with_manifest_lock_with_options(
            &path,
            "claimant",
            ManifestLockOptions {
                ttl: Duration::from_millis(200),
                renew_every: Duration::from_millis(250),
                now_override_ms: Some(now),
                ..ManifestLockOptions::default()
            },
            |lease| {
                thread::sleep(Duration::from_millis(400));
                lease.commit()
            },
        );
        assert!(
            result.is_ok(),
            "the renewal thread read the wall clock against an injected claim stamp, flagged the \
             lease as expired, and commit refused"
        );
        let _ = fs::remove_dir_all(root);
    }
}
