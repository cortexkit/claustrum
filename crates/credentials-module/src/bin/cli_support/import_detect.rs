//! Pure discovery and id derivation for interactive credential import.
//!
//! Discovery deliberately stops before prompting or writing. Each row keeps its
//! renderable metadata separate from an opaque payload that may contain credentials.

use std::collections::{BTreeMap, HashMap};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use credentials_core::credential_id::{default_refresh_adapter, AuthMethod};
use credentials_core::record::VaultRecord;
use serde_json::Value;

/// Environment access used by default-path resolution.
///
/// Tests pass a map; production passes [`std::env::var_os`]. Keeping the lookup
/// explicit prevents process-global environment races in the default test harness.
pub trait EnvLookup {
    fn get(&self, name: &str) -> Option<OsString>;
}

impl<F> EnvLookup for F
where
    F: Fn(&str) -> Option<OsString>,
{
    fn get(&self, name: &str) -> Option<OsString> {
        self(name)
    }
}

impl EnvLookup for BTreeMap<String, OsString> {
    fn get(&self, name: &str) -> Option<OsString> {
        BTreeMap::get(self, name).cloned()
    }
}

impl EnvLookup for HashMap<String, OsString> {
    fn get(&self, name: &str) -> Option<OsString> {
        HashMap::get(self, name).cloned()
    }
}

fn non_empty_env(env: &(impl EnvLookup + ?Sized), name: &str) -> Option<PathBuf> {
    env.get(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn home_relative(env: &(impl EnvLookup + ?Sized), suffix: &str) -> PathBuf {
    non_empty_env(env, "HOME").unwrap_or_default().join(suffix)
}

/// Resolve opencode's auth file with the same XDG/HOME fallback as the existing
/// `opencode_files::default_auth_path()` function, whose zero-argument API remains
/// unchanged for its existing callers.
pub fn opencode_default_auth_path(env: &(impl EnvLookup + ?Sized)) -> PathBuf {
    non_empty_env(env, "XDG_DATA_HOME")
        .or_else(|| non_empty_env(env, "HOME").map(|home| home.join(".local/share")))
        .unwrap_or_else(|| PathBuf::from(".local/share"))
        .join("opencode")
        .join("auth.json")
}

/// Resolve pi's HOME-relative auth file. Pi does not consult XDG directories.
pub fn pi_default_auth_path(env: &(impl EnvLookup + ?Sized)) -> PathBuf {
    home_relative(env, ".pi/agent/auth.json")
}

/// Resolve gemini-cli's HOME-relative OAuth file. Gemini CLI does not consult XDG directories.
pub fn gemini_cli_default_auth_path(env: &(impl EnvLookup + ?Sized)) -> PathBuf {
    home_relative(env, ".gemini/oauth_creds.json")
}

/// Resolve the antigravity plugin's XDG config file.
pub fn antigravity_default_auth_path(env: &(impl EnvLookup + ?Sized)) -> PathBuf {
    non_empty_env(env, "XDG_CONFIG_HOME")
        .or_else(|| non_empty_env(env, "HOME").map(|home| home.join(".config")))
        .unwrap_or_else(|| PathBuf::from(".config"))
        .join("opencode")
        .join("antigravity-accounts.json")
}

/// The four source files scanned when import runs without an explicit source file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportPaths {
    pub opencode: PathBuf,
    pub pi: PathBuf,
    pub gemini_cli: PathBuf,
    pub antigravity: PathBuf,
}

impl ImportPaths {
    pub fn from_env(env: &(impl EnvLookup + ?Sized)) -> Self {
        Self {
            opencode: opencode_default_auth_path(env),
            pi: pi_default_auth_path(env),
            gemini_cli: gemini_cli_default_auth_path(env),
            antigravity: antigravity_default_auth_path(env),
        }
    }

    pub fn from_process_env() -> Self {
        Self::from_env(&|name: &str| std::env::var_os(name))
    }
}

/// A supported installed application that provides an auth file for import.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ImportSource {
    Opencode,
    Pi,
    GeminiCli,
    Antigravity,
}

impl ImportSource {
    pub const fn token(self) -> &'static str {
        match self {
            Self::Opencode => "opencode",
            Self::Pi => "pi",
            Self::GeminiCli => "gemini-cli",
            Self::Antigravity => "antigravity",
        }
    }
}

/// Classification of an individual source entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    ApiKey,
    Oauth,
}

impl EntryKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::ApiKey => "api-key",
            Self::Oauth => "oauth",
        }
    }
}

/// The selection value passed to the existing source reader.
///
/// It is intentionally independent of the provider token embedded in the id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntrySelection {
    ProviderKey(String),
    AntigravityAccount(usize),
    None,
}

/// A non-secret position within a source document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryPosition {
    File,
    Provider(String),
    Account(usize),
    Entry(usize),
}

impl EntryPosition {
    fn render(&self) -> String {
        match self {
            Self::File => "file".to_string(),
            Self::Provider(key) => format!("provider '{key}'"),
            Self::Account(index) => format!("account {index}"),
            Self::Entry(index) => format!("entry {index}"),
        }
    }
}

/// The fixed, non-secret vocabulary for a row that cannot be imported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetectionFailure {
    ReadFailure,
    ParseFailure,
    MissingField(&'static str),
    UnsupportedEntryKind,
    MissingAdapter(String),
}

impl DetectionFailure {
    fn render(&self) -> String {
        match self {
            Self::ReadFailure => "read failure".to_string(),
            Self::ParseFailure => "parse failure".to_string(),
            Self::MissingField(field) => format!("missing field '{field}'"),
            Self::UnsupportedEntryKind => "unsupported entry kind".to_string(),
            Self::MissingAdapter(adapter) => format!(
                "missing adapter '{adapter}'; use flag-driven `ck auth import --adapter {adapter}`"
            ),
        }
    }
}

/// Renderable, non-secret facts about one detected entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RowMetadata {
    pub source: ImportSource,
    pub file_path: PathBuf,
    pub harness_provider_key: Option<String>,
    pub entry_kind: Option<EntryKind>,
    pub account: Option<String>,
    pub original_account_index: Option<usize>,
    pub entry_position: EntryPosition,
    pub base_id: Option<String>,
    pub proposed_id: Option<String>,
    pub refresh_adapter: Option<String>,
    pub entry_selection: EntrySelection,
}

/// Secret-bearing bytes for exactly one source entry.
///
/// This type intentionally implements neither `Debug` nor `Display`; callers can only
/// hand its bytes to the existing record builder/reader boundary.
pub struct EntryPayload(Vec<u8>);

impl EntryPayload {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

/// One detected entry. Metadata and payload remain separate values.
pub struct DetectedRow {
    pub metadata: RowMetadata,
    payload: Option<EntryPayload>,
    pub failure: Option<DetectionFailure>,
}

impl DetectedRow {
    pub fn is_selectable(&self) -> bool {
        self.payload.is_some() && self.failure.is_none()
    }

    pub fn payload(&self) -> Option<&EntryPayload> {
        self.payload.as_ref()
    }

    /// Render a refusal without forwarding a filesystem, serde, or source-reader error.
    pub fn non_selectable_text(&self) -> Option<String> {
        let failure = self.failure.as_ref()?;
        Some(format!(
            "{} file '{}' {}: {}",
            self.metadata.source.token(),
            self.metadata.file_path.display(),
            self.metadata.entry_position.render(),
            failure.render()
        ))
    }
}

/// Id and reader-selection values derived before whole-set labels are applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedEntry {
    pub base_id: String,
    pub refresh_adapter: Option<String>,
    pub entry_selection: EntrySelection,
}

/// Derive the fixed method/provider/adapter table for one valid entry.
pub fn derive_entry(
    source: ImportSource,
    kind: EntryKind,
    harness_provider_key: Option<&str>,
) -> Option<DerivedEntry> {
    match source {
        ImportSource::Opencode | ImportSource::Pi => {
            let key = harness_provider_key?;
            let (base_id, method) = match kind {
                EntryKind::ApiKey => (format!("apikey:{key}"), Some(AuthMethod::ApiKey)),
                EntryKind::Oauth if key == "openai" => {
                    ("chatgpt:openai".to_string(), Some(AuthMethod::Chatgpt))
                }
                EntryKind::Oauth if key == "github-copilot" => {
                    ("copilot:github".to_string(), Some(AuthMethod::Copilot))
                }
                EntryKind::Oauth => (format!("oauth:{key}"), Some(AuthMethod::Oauth)),
            };
            let provider = base_id.split(':').nth(1).unwrap_or_default();
            Some(DerivedEntry {
                refresh_adapter: default_refresh_adapter(method, provider),
                base_id,
                entry_selection: EntrySelection::ProviderKey(key.to_string()),
            })
        }
        ImportSource::GeminiCli if kind == EntryKind::Oauth => Some(DerivedEntry {
            base_id: "oauth:google".to_string(),
            refresh_adapter: default_refresh_adapter(Some(AuthMethod::Oauth), "google"),
            entry_selection: EntrySelection::None,
        }),
        ImportSource::Antigravity if kind == EntryKind::Oauth => Some(DerivedEntry {
            base_id: "antigravity:google".to_string(),
            refresh_adapter: default_refresh_adapter(Some(AuthMethod::Antigravity), "google"),
            entry_selection: EntrySelection::AntigravityAccount(0),
        }),
        ImportSource::GeminiCli | ImportSource::Antigravity => None,
    }
}

/// Adapter names that `build_surface` registers and import derivation may use for refresh.
pub const REGISTERED_REFRESH_ADAPTERS: &[&str] = &[
    "anthropic",
    "cursor",
    "devin",
    "digitalocean",
    "openai",
    "google",
    "snowflake",
    "xai",
    "github-copilot",
    "github_app",
    "kimi",
    "antigravity",
];

pub fn adapter_is_registered(name: &str) -> bool {
    REGISTERED_REFRESH_ADAPTERS.contains(&name)
}

/// Enumerate explicit source paths in stable source order.
pub fn enumerate(paths: &ImportPaths) -> Vec<DetectedRow> {
    enumerate_with_registry(paths, adapter_is_registered)
}

/// Testable form that supplies the adapter-registration check explicitly, keeping id
/// derivation independent from adapter availability.
pub fn enumerate_with_registry(
    paths: &ImportPaths,
    registered: impl Fn(&str) -> bool,
) -> Vec<DetectedRow> {
    let mut rows = Vec::new();
    enumerate_provider_file(
        ImportSource::Opencode,
        &paths.opencode,
        &registered,
        &mut rows,
    );
    enumerate_provider_file(ImportSource::Pi, &paths.pi, &registered, &mut rows);
    enumerate_gemini(&paths.gemini_cli, &registered, &mut rows);
    enumerate_antigravity(&paths.antigravity, &registered, &mut rows);
    apply_labels(&mut rows);
    rows
}

fn read_source(path: &Path) -> Result<Option<Vec<u8>>, DetectionFailure> {
    match std::fs::read(path) {
        Ok(raw) => Ok(Some(raw)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(DetectionFailure::ReadFailure),
    }
}

fn blank_metadata(source: ImportSource, path: &Path, position: EntryPosition) -> RowMetadata {
    RowMetadata {
        source,
        file_path: path.to_path_buf(),
        harness_provider_key: None,
        entry_kind: None,
        account: None,
        original_account_index: None,
        entry_position: position,
        base_id: None,
        proposed_id: None,
        refresh_adapter: None,
        entry_selection: EntrySelection::None,
    }
}

fn file_failure(source: ImportSource, path: &Path, failure: DetectionFailure) -> DetectedRow {
    DetectedRow {
        metadata: blank_metadata(source, path, EntryPosition::File),
        payload: None,
        failure: Some(failure),
    }
}

fn parse_root(raw: &[u8]) -> Result<Value, DetectionFailure> {
    serde_json::from_slice(raw).map_err(|_| DetectionFailure::ParseFailure)
}

fn enumerate_provider_file(
    source: ImportSource,
    path: &Path,
    registered: &impl Fn(&str) -> bool,
    rows: &mut Vec<DetectedRow>,
) {
    let raw = match read_source(path) {
        Ok(Some(raw)) => raw,
        Ok(None) => return,
        Err(failure) => {
            rows.push(file_failure(source, path, failure));
            return;
        }
    };
    let root = match parse_root(&raw) {
        Ok(root) => root,
        Err(failure) => {
            rows.push(file_failure(source, path, failure));
            return;
        }
    };
    let Some(entries) = root.as_object() else {
        rows.push(file_failure(source, path, DetectionFailure::ParseFailure));
        return;
    };

    for (provider, entry) in entries {
        let mut metadata =
            blank_metadata(source, path, EntryPosition::Provider(provider.to_string()));
        metadata.harness_provider_key = Some(provider.to_string());
        metadata.account = entry
            .get("email")
            .and_then(Value::as_str)
            .filter(|email| !email.is_empty())
            .map(str::to_string);

        let kind = if entry.get("type").and_then(Value::as_str) == Some("api") {
            Some(EntryKind::ApiKey)
        } else if entry
            .get("refresh")
            .and_then(Value::as_str)
            .is_some_and(|refresh| !refresh.is_empty())
        {
            Some(EntryKind::Oauth)
        } else {
            None
        };
        metadata.entry_kind = kind;

        let mut failure = match kind {
            Some(EntryKind::ApiKey)
                if !entry
                    .get("key")
                    .and_then(Value::as_str)
                    .is_some_and(|key| !key.is_empty()) =>
            {
                Some(DetectionFailure::MissingField("key"))
            }
            Some(_) => None,
            None if entry.get("type").is_some() => Some(DetectionFailure::UnsupportedEntryKind),
            None => Some(DetectionFailure::MissingField("refresh or type=api")),
        };

        let payload = kind.and_then(|kind| {
            let derived = derive_entry(source, kind, Some(provider))?;
            metadata.base_id = Some(derived.base_id.clone());
            metadata.proposed_id = Some(derived.base_id);
            metadata.refresh_adapter = derived.refresh_adapter;
            metadata.entry_selection = derived.entry_selection;
            if failure.is_none() {
                if let Some(adapter) = metadata.refresh_adapter.as_deref() {
                    if !registered(adapter) {
                        failure = Some(DetectionFailure::MissingAdapter(adapter.to_string()));
                    }
                }
            }
            wrap_provider_entry(provider, entry).map(EntryPayload)
        });

        rows.push(DetectedRow {
            metadata,
            payload,
            failure,
        });
    }
}

fn wrap_provider_entry(provider: &str, entry: &Value) -> Option<Vec<u8>> {
    let provider = serde_json::to_vec(provider).ok()?;
    let entry = serde_json::to_vec(entry).ok()?;
    let mut payload = Vec::with_capacity(provider.len() + entry.len() + 3);
    payload.push(b'{');
    payload.extend_from_slice(&provider);
    payload.push(b':');
    payload.extend_from_slice(&entry);
    payload.push(b'}');
    Some(payload)
}

fn enumerate_gemini(path: &Path, registered: &impl Fn(&str) -> bool, rows: &mut Vec<DetectedRow>) {
    let raw = match read_source(path) {
        Ok(Some(raw)) => raw,
        Ok(None) => return,
        Err(failure) => {
            rows.push(file_failure(ImportSource::GeminiCli, path, failure));
            return;
        }
    };
    let root = match parse_root(&raw) {
        Ok(root) => root,
        Err(failure) => {
            rows.push(file_failure(ImportSource::GeminiCli, path, failure));
            return;
        }
    };
    let mut metadata = blank_metadata(ImportSource::GeminiCli, path, EntryPosition::Entry(0));
    metadata.entry_kind = Some(EntryKind::Oauth);
    metadata.account = root
        .get("email")
        .and_then(Value::as_str)
        .filter(|email| !email.is_empty())
        .map(str::to_string);
    let derived = derive_entry(ImportSource::GeminiCli, EntryKind::Oauth, None)
        .expect("gemini derivation is fixed");
    metadata.base_id = Some(derived.base_id.clone());
    metadata.proposed_id = Some(derived.base_id);
    metadata.refresh_adapter = derived.refresh_adapter;
    metadata.entry_selection = derived.entry_selection;

    let mut failure = if root
        .get("refresh_token")
        .and_then(Value::as_str)
        .is_some_and(|refresh| !refresh.is_empty())
    {
        None
    } else {
        Some(DetectionFailure::MissingField("refresh_token"))
    };
    if failure.is_none() {
        if let Some(adapter) = metadata.refresh_adapter.as_deref() {
            if !registered(adapter) {
                failure = Some(DetectionFailure::MissingAdapter(adapter.to_string()));
            }
        }
    }
    rows.push(DetectedRow {
        metadata,
        payload: Some(EntryPayload(raw)),
        failure,
    });
}

fn enumerate_antigravity(
    path: &Path,
    registered: &impl Fn(&str) -> bool,
    rows: &mut Vec<DetectedRow>,
) {
    let raw = match read_source(path) {
        Ok(Some(raw)) => raw,
        Ok(None) => return,
        Err(failure) => {
            rows.push(file_failure(ImportSource::Antigravity, path, failure));
            return;
        }
    };
    let root = match parse_root(&raw) {
        Ok(root) => root,
        Err(failure) => {
            rows.push(file_failure(ImportSource::Antigravity, path, failure));
            return;
        }
    };
    let Some(accounts) = root.get("accounts").and_then(Value::as_array) else {
        rows.push(file_failure(
            ImportSource::Antigravity,
            path,
            DetectionFailure::MissingField("accounts"),
        ));
        return;
    };

    for (index, account) in accounts.iter().enumerate() {
        let mut metadata = blank_metadata(
            ImportSource::Antigravity,
            path,
            EntryPosition::Account(index),
        );
        metadata.entry_kind = Some(EntryKind::Oauth);
        metadata.original_account_index = Some(index);
        metadata.account = account
            .get("email")
            .and_then(Value::as_str)
            .filter(|email| !email.is_empty())
            .map(str::to_string)
            .or_else(|| Some(index.to_string()));
        let derived = derive_entry(ImportSource::Antigravity, EntryKind::Oauth, None)
            .expect("antigravity derivation is fixed");
        metadata.base_id = Some(derived.base_id.clone());
        metadata.proposed_id = Some(derived.base_id);
        metadata.refresh_adapter = derived.refresh_adapter;
        metadata.entry_selection = derived.entry_selection;

        let mut failure = if account
            .get("refreshToken")
            .and_then(Value::as_str)
            .is_some_and(|refresh| !refresh.is_empty())
        {
            None
        } else {
            Some(DetectionFailure::MissingField("refreshToken"))
        };
        if failure.is_none() {
            if let Some(adapter) = metadata.refresh_adapter.as_deref() {
                if !registered(adapter) {
                    failure = Some(DetectionFailure::MissingAdapter(adapter.to_string()));
                }
            }
        }
        rows.push(DetectedRow {
            metadata,
            payload: wrap_antigravity_account(account).map(EntryPayload),
            failure,
        });
    }
}

fn wrap_antigravity_account(account: &Value) -> Option<Vec<u8>> {
    let account = serde_json::to_vec(account).ok()?;
    let mut payload = Vec::with_capacity(account.len() + 33);
    payload.extend_from_slice(b"{\"accounts\":[");
    payload.extend_from_slice(&account);
    payload.extend_from_slice(b"],\"activeIndex\":0}");
    Some(payload)
}

fn apply_labels(rows: &mut [DetectedRow]) {
    let mut counts = HashMap::<String, usize>::new();
    for base in rows.iter().filter_map(|row| row.metadata.base_id.as_ref()) {
        *counts.entry(base.clone()).or_default() += 1;
    }

    for row in rows {
        let Some(base) = row.metadata.base_id.as_ref() else {
            continue;
        };
        if counts.get(base).copied().unwrap_or_default() <= 1 {
            row.metadata.proposed_id = Some(base.clone());
            continue;
        }
        let label = row
            .metadata
            .account
            .as_deref()
            .and_then(email_local_part)
            .map(str::to_string)
            .or_else(|| {
                (row.metadata.source == ImportSource::Antigravity)
                    .then(|| {
                        row.metadata
                            .original_account_index
                            .map(|index| index.to_string())
                    })
                    .flatten()
            })
            .unwrap_or_else(|| row.metadata.source.token().to_string());
        row.metadata.proposed_id = Some(format!("{base}:{label}"));
    }
}

fn email_local_part(value: &str) -> Option<&str> {
    let (local, _) = value.split_once('@')?;
    (!local.is_empty()).then_some(local)
}

/// The picker reserves rendered indices 0 and 1 for `[all]` and `[none]`, so detected
/// entries are offset by two.
pub fn first_selectable_rendered_index(rows: &[DetectedRow]) -> Option<usize> {
    rows.iter()
        .position(DetectedRow::is_selectable)
        .map(|index| index + 2)
}

/// `(state, record_version, id)`, matching the existing CLI parser at the re-verified HEAD.
pub type InventoryTuple = (String, u64, String);

/// Parse the `admin.status` inventory without allowing the two string fields to trade places.
pub fn parse_inventory(result: &Value) -> Result<Vec<InventoryTuple>, &'static str> {
    let rows = result
        .get("credentials")
        .and_then(Value::as_array)
        .ok_or("admin.status omitted credential inventory")?;
    rows.iter()
        .map(|row| {
            let state = row
                .get("state")
                .and_then(Value::as_str)
                .filter(|state| matches!(*state, "active" | "needs_reauth" | "retired" | "corrupt"))
                .ok_or("admin.status returned an invalid state")?;
            let record_version = row
                .get("record_version")
                .and_then(Value::as_u64)
                .filter(|version| *version > 0)
                .ok_or("admin.status returned an invalid version")?;
            let id = row
                .get("id")
                .and_then(Value::as_str)
                .filter(|id| !id.is_empty())
                .ok_or("admin.status returned an invalid id")?;
            Ok((state.to_string(), record_version, id.to_string()))
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportAction {
    Create,
    Replace { record_version: u64 },
}

pub fn classify_inventory_row(inventory: &[InventoryTuple], proposed_id: &str) -> ImportAction {
    inventory
        .iter()
        .find_map(|(state, record_version, id)| {
            let _state = state;
            (id == proposed_id).then_some(ImportAction::Replace {
                record_version: *record_version,
            })
        })
        .unwrap_or(ImportAction::Create)
}

/// Test-only prompt and commit seam definitions used by `import_picker`.
///
/// Keeping environment names, ordered-response types, and the prompt limit together
/// ensures scripted tests and the terminal picker implement the same protocol.
pub mod slice2_contract {
    use super::*;

    pub const FEATURE_NAME: &str = "import-prompt-seam";
    pub const PROMPT_SCRIPT_ENV: &str = "CK_AUTH_IMPORT_PROMPT_SCRIPT";
    pub const COMMIT_SCRIPT_ENV: &str = "CK_AUTH_IMPORT_COMMIT_SCRIPT";
    pub const SHIPPED_BINARY_ENV: &str = "CK_AUTH_IMPORT_SHIPPED_BINARY";
    pub const ID_PROMPT_OPEN_LIMIT_PER_ROW: usize = 3;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum PromptRequest {
        PickRows,
        EditId { row: usize, initial: String },
        ConfirmSummary,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum PromptResponse {
        Picked(Vec<String>),
        Id(String),
        Confirm(bool),
        Cancel,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ScriptExhausted {
        pub seam: &'static str,
    }

    impl std::fmt::Display for ScriptExhausted {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                f,
                "{0} script exhausted before the next ordered response",
                self.seam
            )
        }
    }

    impl std::error::Error for ScriptExhausted {}

    /// One ordered response is consumed for every prompt invocation.
    pub trait PromptSeam {
        type Error;

        fn prompt(&mut self, request: PromptRequest) -> Result<PromptResponse, Self::Error>;
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum CommitAction {
        Create,
        Replace,
    }

    /// One ordered outcome is consumed for every attempted row commit.
    pub trait CommitSeam {
        type Error;

        fn commit(
            &mut self,
            final_id: &str,
            record: VaultRecord,
            action: CommitAction,
        ) -> Result<Value, Self::Error>;
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum PromptSource {
        InjectedScript,
        Terminal,
        RefuseNoTty,
    }

    /// Injected scripts outrank terminal checks. A default-feature binary passes
    /// `seam_compiled = false`, so it ignores the script environment variable.
    pub fn prompt_source(
        seam_compiled: bool,
        script_env_is_set: bool,
        stdin_is_tty: bool,
        stdout_is_tty: bool,
    ) -> PromptSource {
        if seam_compiled && script_env_is_set {
            PromptSource::InjectedScript
        } else if stdin_is_tty && stdout_is_tty {
            PromptSource::Terminal
        } else {
            PromptSource::RefuseNoTty
        }
    }
}

/// Verified implementation facts the import flow relies on: inventory tuple order,
/// version visibility, online test reach, argument handling, replacement identity,
/// refusal rendering, and reachability reads.
///
/// Commit identifiers and line anchors are included so later changes can distinguish
/// intentional behavior changes from source drift.
pub const SLICE_1_AMENDMENT: &str = r#"Slice 1 amendment (re-verified against 1686f53ca295; implementation baseline 6a53dd54b7b02353c58be69a0289c1a99636e03e):
G1 — parse_inventory still returns (state, record_version, id), now at credentials_cli.rs:2949-2989. The 6c9de1795ba4 anchor drifted +4 lines; behavior did not drift.
G2 — take the version-present branch. list_meta_read_only returns (String, RecordMeta), and RecordMeta.record_version is public (store.rs:284-297,3096-3137), so offline reads expose each id's version. The earlier no-version evidence was incomplete, not a product limitation.
G3 — take the online-harness branch. real_daemon_e2e::start_vault_with_seed starts subc-core plus ck-claustrum over a temp store, and real_daemon_admin_op_over_route_while_offline_refused drives ck-auth with --subc through admin.status and an admin write. The harness is ignored outside its explicit gate because it builds ../subconscious and binds loopback ports.
G4 — take the stripped-leading-global branch. run calls hoist_leading_global_flags, removes the verb, then parse_global removes globals before passing &args to cmd_import (credentials_cli.rs:270-315,344-367); a pre-import --data-dir does not enter cmd_import's tail. The cited cmd_import anchor drifted +4 lines to 1422-1531.
G5 — take the no-refusal-for-this-row branch. The check is EncryptedStore::overwrite_unconditional_with_identity_policy_audited (store.rs:1205-1349), reached from admin_ops::apply with preserve_existing_identity = !clear_identity. Its exact AccountIdentityMismatch Display format is: incoming material names account '{incoming_account_id}', but identity preservation would retain account '{retained_account_id}'; pass `--account-id <new>` with '{incoming_account_id}' or `--clear-identity`; or afterwards: ck auth set-identity {credential_id} --account-id {incoming_account_id}. It does not fire for the specified picker antigravity replacement: the shared identity step puts imported_email into the incoming record, so incoming.identity is not empty, and antigravity's opaque access token has no derivable account claim. That row commits as an ordinary replace.
G6 — take the fixed-refusal-vocabulary branch. The shared commit path returns Result<serde_json::Value, CliError>; offline store failures are CliError::Store(StoreOpError), while route refusals are free-form CliError::RouteRefused(String). Display can carry serde or other unconstrained text through StoreOpError::Corrupt/Encode/Store and the route refusal string. No inspected branch formats record bytes, and no inspected branch formats a token, but serde text is possible; slice 2 therefore must not reproduce this unconstrained Display per row.
G7 — created_id_is_already_reachable reads request_admin_status: with --subc it reads authenticated admin.status over the route plane and otherwise falls back to list_meta_read_only/list_read_grants_read_only. The online G3 driver can reach the guard's route plane. The cited create-arm anchor drifted +4 lines; the guard is now credentials_cli.rs:2825-2886.
Anchor drift — opencode_files::default_auth_path remains 233-244; oauth.rs import_provider, antigravity, and api-key readers remain 96-120, 210-288, and 309-342. credentials_cli::cmd_import and its construction/identity subranges moved +4 to 1422-1531, 1435-1487, and 1489-1505; parse_inventory moved +4 to 2949-2989; the create advisory call moved +4 to 1310 and its guard is 2825-2886. preflight_login is now 934-971 (its cited key-resolution body moved +4 to 943-955); login_id_is_valid is 1838-1847; the Input validation example is at 1989-1993; and import help is 608-632. dialoguer remains Cargo.toml:45-47, credential_id default_refresh_adapter remains 172-180, and store identity policy is 1205-1349. No cited behavior was silently adapted.
Dialoguer capability — compile checks under the crate's existing features prove MultiSelect and its cancellable interact_opt method are reachable. Input has no interact_text_opt-shaped cancellable method in dialoguer 0.12; the id prompt therefore exits only through an accepted id or the shared per-row bound of three opens. No disabled-item API is assumed.
Slice 2 seam contract — module import_picker implements slice2_contract::PromptSeam and CommitSeam behind non-default feature import-prompt-seam. CK_AUTH_IMPORT_PROMPT_SCRIPT and CK_AUTH_IMPORT_COMMIT_SCRIPT name ordered scripts; one response/outcome is consumed per prompt/attempted row, in order, and exhaustion returns ScriptExhausted. An injected prompt script wins before TTY checks; without the feature its env var is ignored. CK_AUTH_IMPORT_SHIPPED_BINARY names the default-feature binary gate builds. ID prompts have three opens per row across every trigger."#;
