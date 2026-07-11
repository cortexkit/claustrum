#![forbid(unsafe_code)]

//! The cortexkit-credentials offline admin CLI.
//!
//! This is the ONLY write surface. It is master-key-gated by STRUCTURE, not a
//! separate handshake, via two stacked gates. FIRST, it must RESOLVE the master key
//! (keychain / operator path) to open the encrypted store — and producing a valid
//! sealed record IS the proof of master-key possession (a caller without the key
//! cannot seal a record). SECOND, it takes the single-writer LEASE via
//! `open_sqlite`: if the daemon is running it holds the lease, so the CLI's acquire
//! fails and the operator is told to stop the daemon, making "while the daemon is
//! stopped" a structural precondition rather than an honor-system one. A plain route
//! consumer (transport key only, no master key, no lease) cannot reach this path at
//! all — there is no running-vault admin surface.
//!
//! Every write goes through the epoch-fenced path and appends an audit-chain entry
//! (flagged as an admin write) atomically with the mutation. Bootstrap (first run)
//! mints a CSPRNG master key into the configured store.
//!
//! Commands:
//!   bootstrap                                  provision a new master key
//!   put       --id <id> --payload <bytes> [--kind api_key|dsn|opaque] [--expires-ms N]
//!   import    --source opencode|pi|antigravity --id <id> --json <file>
//!   invalidate --id <id>
//!   rotate-master-key
//!   mint-handle --id <id>                      print a fresh handle (once)
//!   revoke-handle --handle <ckh_...>
//!   revoke-all-handles --id <id>
//!   audit [--limit N] | verify-audit
//!
//! Storage location is resolved the same way the daemon resolves it; for the CLI
//! it is taken from `--data-dir` (the vault directory holding `store.db`).

use std::path::PathBuf;
use std::process::ExitCode;

#[path = "cli_support/admin_client.rs"]
mod admin_client;
#[path = "cli_support/login_listener.rs"]
mod login_listener;

use cortexkit_store::{open_sqlite, Isolation, StorageBackend, StorageDescriptor, StoreError};
use credentials_core::admin_ops::{AdminAuditOp, AdminOpBody, StoreMode, ADMIN_OP_SCHEMA_V1};
use credentials_core::contract::{MODULE_ID, STORAGE_NAMESPACE};
use credentials_core::credential_id::{default_refresh_adapter, parse_credential_id, AuthMethod};
use credentials_core::key::MasterKey;
use credentials_core::record::{CredentialKind, VaultRecord};
use credentials_core::resolver::{self, KeySource, MasterKeyError, ResolverConfig};
use credentials_core::store::{EncryptedStore, RecordState, StoreOpError};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            e.exit_code()
        }
    }
}

/// A CLI error with a meaningful process exit code so scripting can distinguish
/// "daemon is running" (try again later) from a usage/IO error.
#[derive(Debug)]
enum CliError {
    Usage(String),
    /// The daemon holds the lease — the operator must stop it first.
    DaemonRunning,
    /// The master key could not be resolved (locked / absent / wrong).
    MasterKey(MasterKeyError),
    Store(StoreOpError),
    StoreOpen(StoreError),
    Io(String),
    /// The running module refused an admin op (auth/gate/store error). Terminal.
    RouteRefused(String),
    /// An admin op was dispatched to the running module but its outcome is unknown
    /// (connection dropped after send). The op may have committed.
    RouteIndeterminate(String),
}

impl CliError {
    fn exit_code(&self) -> ExitCode {
        match self {
            CliError::DaemonRunning => ExitCode::from(3),
            CliError::MasterKey(_) => ExitCode::from(4),
            // A dispatched-but-unknown outcome gets its own code so a script does not
            // treat it as a clean failure and blindly retry a possibly-committed op.
            CliError::RouteIndeterminate(_) => ExitCode::from(5),
            _ => ExitCode::FAILURE,
        }
    }
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CliError::Usage(m) => write!(f, "{m}"),
            CliError::DaemonRunning => f.write_str(
                "the credentials daemon is running (holds the single-writer lease); \
                 stop it before running an admin command",
            ),
            CliError::MasterKey(e) => write!(f, "master key: {e}"),
            CliError::Store(e) => write!(f, "{e}"),
            CliError::StoreOpen(e) => write!(f, "{e}"),
            CliError::Io(m) => write!(f, "{m}"),
            CliError::RouteRefused(m) => write!(f, "the running module refused the op: {m}"),
            CliError::RouteIndeterminate(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for CliError {}

struct GlobalArgs {
    data_dir: PathBuf,
    key_source: KeySource,
    /// The subc connection file, from `--subc`. When present, an admin WRITE is
    /// committed through the RUNNING module over the route plane (zero-downtime,
    /// master-key challenge-response); when absent, writes take the offline lease
    /// path (daemon must be stopped). Read commands ignore it.
    subc_conn: Option<PathBuf>,
}

fn run() -> Result<(), CliError> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        return Err(CliError::Usage(usage()));
    }
    let command = args.remove(0);

    // A `--help`/`-h` ANYWHERE prints usage and exits WITHOUT running the command.
    // This is load-bearing safety, not a convenience: the arg parser pulls the flags
    // it knows and (before this) silently ignored the rest, so `bootstrap --help`
    // ignored `--help` and RAN bootstrap — provisioning stray key material on a typo.
    // Intercepting here, before parse_global / any open-for-admin, makes help a no-op.
    if command == "help"
        || command == "--help"
        || command == "-h"
        || args.iter().any(|a| a == "--help" || a == "-h")
    {
        println!("{}", usage());
        return Ok(());
    }

    // Pull the global flags (--data-dir, and the key source) out of the arg list.
    let global = parse_global(&mut args)?;

    // Every remaining arg must be an accepted flag for this command (or its value);
    // an unknown or misspelled flag is a HARD error, never silently ignored. Runs
    // before dispatch, so a bad invocation never reaches the keychain or the lease.
    reject_unknown_args(&command, &args)?;

    match command.as_str() {
        "bootstrap" => cmd_bootstrap(&global),
        "put" => cmd_put(&global, &args),
        "import" => cmd_import(&global, &args),
        "login" => cmd_login(&global, &args),
        "invalidate" => cmd_invalidate(&global, &args),
        "logout" => cmd_logout(&global, &args),
        "status" => cmd_status(&global),
        "rotate-master-key" => cmd_rotate_master_key(&global),
        "mint-handle" => cmd_mint_handle(&global, &args),
        "revoke-handle" => cmd_revoke_handle(&global, &args),
        "revoke-all-handles" => cmd_revoke_all_handles(&global, &args),
        "list" => cmd_list(&global),
        "audit" => cmd_audit(&global, &args),
        "verify-audit" => cmd_verify_audit(&global),
        other => Err(CliError::Usage(format!(
            "unknown command '{other}'\n{}",
            usage()
        ))),
    }
}

/// Reject any leftover arg that is not an accepted flag (or a flag's value) for the
/// command, AFTER the global flags have been pulled. The arg parser consumes the
/// flags it knows and ignores the rest, so without this a misspelled or stray flag is
/// silently dropped. For a command that takes no required flag (such as `bootstrap`),
/// that silent drop means a typo'd invocation runs the real mutation. This makes a
/// bad flag a hard usage error before any keychain or lease access.
fn reject_unknown_args(command: &str, args: &[String]) -> Result<(), CliError> {
    // The per-command flags that TAKE a value. `--data-dir` / `--key-path` are global
    // and already removed by parse_global before this runs.
    let value_flags: &[&str] = match command {
        "put" => &[
            "--id",
            "--payload",
            "--payload-file",
            "--kind",
            "--expires-ms",
            "--expected-hash",
        ],
        "import" => &["--source", "--provider", "--id", "--json", "--adapter"],
        "login" => &["--provider", "--id"],
        "invalidate" | "mint-handle" | "revoke-all-handles" => &["--id"],
        "logout" => &["--provider", "--id"],
        "revoke-handle" => &["--handle"],
        "audit" => &["--limit"],
        // bootstrap / rotate-master-key / verify-audit take no per-command flags.
        _ => &[],
    };
    // Boolean (valueless) flags accepted per command.
    let bool_flags: &[&str] = match command {
        "import" => &["--replace"],
        "login" => &["--replace", "--no-listener"],
        _ => &[],
    };
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if bool_flags.contains(&arg.as_str()) {
            i += 1;
            continue;
        }
        if value_flags.contains(&arg.as_str()) {
            // Skip the flag AND its value (the value may look like anything).
            i += 2;
            continue;
        }
        return Err(CliError::Usage(format!(
            "unexpected argument '{arg}' for '{command}'\n{}",
            usage()
        )));
    }
    Ok(())
}

fn usage() -> String {
    "ck auth — CortexKit provider-credential vault\n\
     \n\
     On a standard install, commands need NO flags: the vault location and the\n\
     running daemon are auto-discovered. Just:\n\
       ck auth status                              show vault health + inventory\n\
       ck auth login --provider xai --replace      (re-)login a provider\n\
       ck auth logout --provider xai               stop serving a provider\n\
     \n\
     Commands: login | logout | status | list | import | put | audit | verify-audit\n\
               mint-handle | revoke-handle | revoke-all-handles | invalidate\n\
               rotate-master-key | bootstrap\n\
     \n\
      login: --provider <anthropic|openai|xai> [--id <id>] [--replace] [--no-listener]\n\
            vault-native first-party OAuth login — mints an INDEPENDENT refresh token\n\
            the vault solely custodies (no dual-custody rotation race). Opens a\n\
            browser URL. openai/xai: a one-shot CLI-local listener on the loopback\n\
            redirect completes the flow automatically (--no-listener, a busy port, or\n\
            a timeout falls back to pasting the address-bar URL). anthropic: paste\n\
            the shown code#state (its callback page is remote, no listener).\n\
            --replace swaps an existing credential (keeps its handle).\n\
            Default id: oauth:anthropic / chatgpt:openai / oauth:xai.\n\
     logout: --provider <p> | --id <id> — stop serving a credential REVERSIBLY\n\
            (invalidate + revoke its handles; keeps the record and audit chain;\n\
            `login --provider <p> --replace` restores it). Never a delete.\n\
     status: vault health + per-credential inventory (no secrets) — run this when\n\
            the health table says degraded. Reads the RUNNING daemon when one is up,\n\
            else the offline store.\n\
      list: print each credential's id + lifecycle state + version (no secrets),\n\
            e.g. to find which credential a health probe flagged needs_reauth.\n\
     import: --source <opencode|pi|gemini-cli|antigravity> --id <id> --json <file>\n\
             [--provider <key>] [--adapter <name>] [--replace]\n\
       opencode/pi read auth.json (--provider selects one entry; an apikey:<p> id\n\
         imports a {type:api,key} entry as a static key, an oauth id imports tokens);\n\
       gemini-cli reads ~/.gemini/oauth_creds.json (single credential, no --provider);\n\
       antigravity reads ~/.config/opencode/antigravity-accounts.json (accounts array;\n\
         --provider selects an account by email/index, default activeIndex);\n\
       --adapter overrides the method-derived refresh adapter;\n\
       --replace overwrites an existing id (fix a wrong-source import; keeps handles).\n\
     \n\
     Overrides (rarely needed):\n\
       [--data-dir <dir>]  vault location; defaults to the standard per-user path\n\
                           (<data_home>/cortexkit/cortexkit-credentials). An explicit\n\
                           dir targets THAT vault and stays offline unless --subc is\n\
                           also given.\n\
       [--subc <file>]     subc connection file; auto-discovered on a standard\n\
                           install. Present ⇒ writes commit through the running module\n\
                           (zero downtime); absent/no daemon ⇒ offline single-writer\n\
                           lease (daemon must be stopped). rotate-master-key and\n\
                           bootstrap are always offline.\n\
       [--key-path <file>] operator key file instead of the OS keychain."
        .to_string()
}

/// Commit one admin op, choosing the backend by `--subc`:
///
/// - `--subc <connection-file>` present: commit through the RUNNING module over the
///   route plane (admin.challenge → master-key MAC → admin.op). Zero downtime; the
///   module is the single writer, serializing the op against live refreshes. If no
///   live module is reachable, fall back to the offline lease path (nothing was
///   dispatched, so the fallback cannot double-execute).
/// - absent: the offline lease path exactly as before (daemon must be stopped).
///
/// A REFUSAL from a live module is terminal (never falls back — the module is alive
/// and said no); a DISPATCHED op with a lost response is indeterminate (never falls
/// back or retries — it may have committed; the operator verifies first).
fn commit_admin(
    global: &GlobalArgs,
    op: credentials_core::admin_ops::AdminOpBody,
) -> Result<serde_json::Value, CliError> {
    if let Some(conn_path) = &global.subc_conn {
        match admin_client::commit(&global.data_dir, &resolver_config(global), conn_path, &op) {
            admin_client::RouteCommit::Committed(v) => return Ok(v),
            admin_client::RouteCommit::Refused(m) => return Err(CliError::RouteRefused(m)),
            admin_client::RouteCommit::Indeterminate(m) => {
                return Err(CliError::RouteIndeterminate(m))
            }
            admin_client::RouteCommit::NoLiveModule(m) => {
                // Nothing was dispatched; the offline path below is safe.
                eprintln!("(no live module: {m}; using the offline lease path)");
            }
        }
    }
    let store = open_for_admin(global)?;
    credentials_core::admin_ops::apply(&store, op, "offline-cli").map_err(CliError::Store)
}

/// Open the vault for an admin write: resolve the master key (proof of possession)
/// and take the single-writer lease (proof the daemon is stopped). Either failing
/// is a clean, typed refusal.
fn open_for_admin(global: &GlobalArgs) -> Result<EncryptedStore, CliError> {
    let store = open_sqlite(&descriptor(global)).map_err(|e| match e {
        // A held lease means the daemon is up — the structural "while stopped" gate.
        StoreError::Lease(_) => CliError::DaemonRunning,
        other => CliError::StoreOpen(other),
    })?;
    EncryptedStore::migrate(&store).map_err(CliError::StoreOpen)?;
    // Crash-safe resolve: pick the key-store slot matching the database's recorded
    // fingerprint (so a vault left mid-rotation still opens under the right key).
    let key = match EncryptedStore::read_db_key_id(&store).map_err(CliError::StoreOpen)? {
        Some(db_key_id) => resolver::resolve_for_db(&resolver_config(global), db_key_id)
            .map_err(CliError::MasterKey)?,
        None => resolver::resolve(&resolver_config(global), None).map_err(CliError::MasterKey)?,
    };
    EncryptedStore::open(store, key).map_err(CliError::Store)
}

fn cmd_bootstrap(global: &GlobalArgs) -> Result<(), CliError> {
    // Bootstrap must also take the lease (the daemon must be stopped) and must not
    // clobber an existing key.
    let _store = open_sqlite(&descriptor(global)).map_err(|e| match e {
        StoreError::Lease(_) => CliError::DaemonRunning,
        other => CliError::StoreOpen(other),
    })?;
    let key = resolver::bootstrap(&resolver_config(global)).map_err(CliError::MasterKey)?;
    println!(
        "provisioned a new master key (key_id {})",
        key.key_id().to_hex()
    );
    Ok(())
}

fn cmd_put(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    let id = required(args, "--id")?;
    // Payload from EITHER --payload <value> (exact bytes) OR --payload-file <path>
    // (the file's bytes, trailing whitespace stripped). --payload-file keeps a real
    // secret OUT of argv (process list / shell history) — the right way to ingest a
    // bare key file like ~/.config/openai.key.
    let payload = match (
        optional(args, "--payload"),
        optional(args, "--payload-file"),
    ) {
        (Some(_), Some(_)) => {
            return Err(CliError::Usage(
                "pass only one of --payload or --payload-file".to_string(),
            ))
        }
        (Some(p), None) => p.into_bytes(),
        (None, Some(path)) => {
            let raw = std::fs::read_to_string(&path)
                .map_err(|e| CliError::Io(format!("reading {path}: {e}")))?;
            raw.trim_end().as_bytes().to_vec()
        }
        (None, None) => {
            return Err(CliError::Usage(
                "--payload <value> or --payload-file <path> is required".to_string(),
            ))
        }
    };
    let kind = match optional(args, "--kind").as_deref() {
        None | Some("api_key") => CredentialKind::ApiKey,
        Some("dsn") => CredentialKind::Dsn,
        Some("opaque") => CredentialKind::Opaque,
        Some(other) => {
            return Err(CliError::Usage(format!(
                "--kind must be api_key|dsn|opaque (oauth records come via import), got '{other}'"
            )))
        }
    };
    let expires_at_ms = optional(args, "--expires-ms")
        .map(|s| s.parse::<i64>())
        .transpose()
        .map_err(|e| CliError::Usage(format!("--expires-ms not an integer: {e}")))?;

    let record = VaultRecord::new_static(kind, "operator", payload, expires_at_ms);
    // CREATE-ONLY by default. An overwrite requires an explicit --expected-hash CAS.
    match optional(args, "--expected-hash") {
        Some(hex) => {
            let expected = decode_hash(&hex)?;
            commit_admin(
                global,
                store_op(
                    &id,
                    record,
                    AdminAuditOp::Overwrite,
                    StoreMode::ReplaceCas {
                        expected_hash_hex: hex_lower(&expected),
                    },
                ),
            )?;
            println!("overwrote {id} (CAS ok)");
        }
        None => {
            commit_admin(
                global,
                store_op(&id, record, AdminAuditOp::Put, StoreMode::Create),
            )?;
            println!("created {id}");
        }
    }
    Ok(())
}

/// Build an `admin.store` op body.
fn store_op(id: &str, record: VaultRecord, audit_op: AdminAuditOp, mode: StoreMode) -> AdminOpBody {
    AdminOpBody::Store {
        v: ADMIN_OP_SCHEMA_V1,
        id: id.to_string(),
        record: Box::new(record),
        audit_op,
        mode,
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn cmd_import(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    let source = required(args, "--source")?;
    let id = required(args, "--id")?;
    let json_path = required(args, "--json")?;
    let raw =
        std::fs::read(&json_path).map_err(|e| CliError::Io(format!("reading {json_path}: {e}")))?;
    let provider_sel = optional(args, "--provider");

    // The credential id (<method>:<provider>[:<account>], or legacy <provider>...)
    // determines whether this is an api-key (static) or an oauth import, and which
    // refresh adapter to STORE. The adapter is set EXPLICITLY here, never parsed from
    // the id suffix — `--adapter` overrides the method's default.
    let parsed = parse_credential_id(&id);
    let record = if matches!(parsed.method, Some(AuthMethod::ApiKey)) {
        // API key → a static record (no adapter, no refresh). `--provider` selects the
        // entry from a multi-provider auth.json; default to the parsed provider.
        let provider = provider_sel
            .clone()
            .unwrap_or_else(|| parsed.provider.clone());
        let key = credentials_core::oauth::import_api_key(&source, &raw, &provider)
            .map_err(|e| CliError::Usage(format!("api-key import: {e}")))?;
        VaultRecord::new_static(CredentialKind::ApiKey, source, key, None)
    } else {
        // OAuth (incl. antigravity / chatgpt / legacy) → a refreshable record. The
        // stored adapter is the method's default, overridable with --adapter.
        let oauth = if source == "antigravity" {
            // For antigravity the credentials live in the plugin's accounts-array
            // store instead of the normal provider auth.json file — read the selected
            // account and pack its refresh.
            credentials_core::oauth::import_antigravity_account(&raw, provider_sel.as_deref())
        } else {
            match &provider_sel {
                Some(provider) => credentials_core::oauth::OAuthCredential::import_provider(
                    &source, &raw, provider,
                ),
                None => credentials_core::oauth::OAuthCredential::import(&source, &raw),
            }
        }
        .map_err(|e| CliError::Usage(format!("import parse: {e}")))?;
        let adapter = optional(args, "--adapter")
            .or_else(|| default_refresh_adapter(parsed.method, &parsed.provider))
            .ok_or_else(|| {
                CliError::Usage(format!(
                    "no refresh adapter for id '{id}'; pass --adapter <name>"
                ))
            })?;
        let payload = oauth.access_token.clone().into_bytes();
        VaultRecord::new_oauth(source, adapter, oauth, payload)
    };

    // `--replace` overwrites an existing credential UNCONDITIONALLY (re-seal at
    // version+1, reset to active, keep the handle), for fixing a credential imported
    // from the wrong source. Without it, import is CREATE-ONLY (an existing id is an
    // error), so a fresh credential can never be silently clobbered.
    if has_flag(args, "--replace") {
        commit_admin(
            global,
            store_op(
                &id,
                record,
                AdminAuditOp::Import,
                StoreMode::ReplaceUnconditional,
            ),
        )?;
        println!("replaced {id}");
    } else {
        commit_admin(
            global,
            store_op(&id, record, AdminAuditOp::Import, StoreMode::Create),
        )?;
        println!("imported {id}");
    }
    Ok(())
}

/// Vault-native first-party OAuth login: drive an interactive authorization-code +
/// PKCE flow so the vault mints and SOLELY custodies an INDEPENDENT refresh token,
/// eliminating the dual-custody rotation race by construction. The operator opens a
/// printed URL, approves in the browser, and pastes the resulting `code#state` back;
/// the vault exchanges it and stores the tokens as a normal oauth record (which the
/// existing refresh adapter then refreshes with no per-record client override).
///
/// This is an admin write — same offline-CLI-while-daemon-stopped discipline as every
/// other mutation. The daemon opens no browser and runs no listener; the manual
/// code-paste redirect means there is no inbound network surface here at all.
/// The per-provider login wire: everything `cmd_login` needs to drive one provider's
/// authorization-code flow. Each provider's values are pinned in its adapter module;
/// adding a login provider = adding one row to `login_provider()`.
struct LoginProvider {
    authorize_url: &'static str,
    token_url: &'static str,
    client_id: &'static str,
    redirect_uri: &'static str,
    scopes: &'static [&'static str],
    extra_authorize_params: &'static [(&'static str, &'static str)],
    adapter_name: &'static str,
    /// The default credential id (the method-scoped id consumers key on).
    default_id: &'static str,
    /// Which token-exchange wire the provider speaks: Anthropic's JSON body with an
    /// embedded state, or the standard RFC form-encoded body (OpenAI / xAI).
    exchange: ExchangeWire,
    /// Whether to append a fresh per-flow OIDC `nonce` to the authorize URL. Required
    /// by providers whose scope set includes `openid` (xAI); the nonce is CSPRNG per
    /// request. We do not verify it (the vault does not consume the id_token) — it is
    /// sent only to satisfy the provider's OIDC authorize contract.
    needs_oidc_nonce: bool,
    /// Whether the RFC form token exchange must echo `code_challenge` +
    /// `code_challenge_method` alongside `code_verifier`. xAI's public-client token
    /// endpoint expects it (matching the Grok CLI / Hermes flow); OpenAI does not.
    exchange_echoes_challenge: bool,
    /// The operator instruction for capturing the callback (the flows present the code
    /// differently).
    paste_prompt: &'static str,
}

enum ExchangeWire {
    AnthropicJson,
    RfcForm,
}

fn login_provider(provider: &str) -> Option<LoginProvider> {
    use credentials_core::refresh_adapters::{anthropic, openai, xai};
    match provider {
        "anthropic" => Some(LoginProvider {
            authorize_url: anthropic::AUTHORIZE_URL,
            token_url: anthropic::TOKEN_URL,
            client_id: anthropic::CLAUDE_CODE_CLIENT_ID,
            redirect_uri: anthropic::CODE_CALLBACK_URL,
            scopes: anthropic::LOGIN_SCOPES,
            extra_authorize_params: anthropic::LOGIN_EXTRA_AUTHORIZE_PARAMS,
            adapter_name: anthropic::ADAPTER_NAME,
            default_id: "oauth:anthropic",
            exchange: ExchangeWire::AnthropicJson,
            needs_oidc_nonce: false,
            exchange_echoes_challenge: false,
            paste_prompt: "After approving, paste the authorization code shown (code#state), then Enter:",
        }),
        "openai" => Some(LoginProvider {
            authorize_url: openai::AUTHORIZE_URL,
            token_url: openai::TOKEN_URL,
            client_id: openai::CODEX_CLIENT_ID,
            redirect_uri: openai::LOGIN_REDIRECT_URI,
            scopes: openai::LOGIN_SCOPES,
            extra_authorize_params: openai::LOGIN_EXTRA_AUTHORIZE_PARAMS,
            adapter_name: openai::ADAPTER_NAME,
            // The ChatGPT-subscription credential: method `chatgpt` (the id the
            // llm-runner chatgpt wire family consumes; the prod handle points here).
            default_id: "chatgpt:openai",
            exchange: ExchangeWire::RfcForm,
            needs_oidc_nonce: false,
            exchange_echoes_challenge: false,
            // No listener runs on the registered localhost redirect, so the browser
            // lands on a connection-refused page whose ADDRESS BAR carries the code.
            paste_prompt: "After approving, the browser will fail to connect to localhost:1455 \
                           — that is expected (nothing listens there).\n\
                           Copy the FULL URL from the browser's address bar and paste it here, then Enter:",
        }),
        "xai" => Some(LoginProvider {
            authorize_url: xai::AUTHORIZE_URL,
            token_url: xai::TOKEN_URL,
            client_id: xai::GROK_CLI_CLIENT_ID,
            redirect_uri: xai::LOGIN_REDIRECT_URI,
            scopes: xai::LOGIN_SCOPES,
            extra_authorize_params: xai::LOGIN_EXTRA_AUTHORIZE_PARAMS,
            adapter_name: xai::ADAPTER_NAME,
            default_id: "oauth:xai",
            exchange: ExchangeWire::RfcForm,
            // xAI's scope set includes `openid`, so its authorize contract wants a
            // per-flow nonce, and its public-client token endpoint echoes the PKCE
            // challenge in the exchange (matching the Grok CLI / Hermes flow).
            needs_oidc_nonce: true,
            exchange_echoes_challenge: true,
            // Same zero-listener posture as OpenAI: the loopback redirect refuses the
            // connection and the address bar carries the code.
            paste_prompt: "After approving, the browser will fail to connect to 127.0.0.1:56121 \
                           — that is expected (nothing listens there).\n\
                           Copy the FULL URL from the browser's address bar and paste it here, then Enter:",
        }),
        _ => None,
    }
}

fn cmd_login(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    use credentials_core::oauth_login::{
        build_authorize_url, decode_jwt_claims, exchange_authorization_code,
        exchange_authorization_code_form, extract_chatgpt_account_id, generate_pkce,
        generate_state, parse_callback,
    };

    let provider = required(args, "--provider")?;
    // Each provider's auth-code wire gets its own grounded research before it is
    // added to login_provider().
    let Some(wire) = login_provider(&provider) else {
        return Err(CliError::Usage(format!(
            "login supports --provider anthropic|openai|xai (got '{provider}')"
        )));
    };
    let id = optional(args, "--id").unwrap_or_else(|| wire.default_id.to_string());

    // Generate the PKCE pair and the CSPRNG state (state is independent of the
    // verifier), build the authorize URL, and present it to the operator.
    let pkce = generate_pkce().map_err(|e| CliError::Io(format!("csprng: {e}")))?;
    let state = generate_state().map_err(|e| CliError::Io(format!("csprng: {e}")))?;
    // An OIDC provider (xAI) requires a fresh per-flow nonce in the authorize request;
    // it is CSPRNG per login and appended as an extra authorize param. The vault does
    // not consume the id_token, so the nonce is not verified — it only satisfies the
    // provider's authorize contract.
    let nonce = if wire.needs_oidc_nonce {
        Some(generate_state().map_err(|e| CliError::Io(format!("csprng: {e}")))?)
    } else {
        None
    };
    let mut authorize_params: Vec<(&str, &str)> = wire.extra_authorize_params.to_vec();
    if let Some(nonce) = nonce.as_deref() {
        authorize_params.push(("nonce", nonce));
    }
    let authorize_url = build_authorize_url(
        wire.authorize_url,
        wire.client_id,
        wire.redirect_uri,
        wire.scopes,
        &pkce.challenge,
        &state,
        &authorize_params,
    )
    .map_err(|e| CliError::Io(format!("building authorize url: {e}")))?;

    // For a loopback-redirect provider (openai/xai), bind a one-shot CLI-local
    // listener on the EXACT redirect address BEFORE opening the browser, so the
    // redirect can't race an unbound socket. `--no-listener` forces the paste path.
    // The listener is a pure convenience over paste; the daemon never listens.
    let listener = if has_flag(args, "--no-listener") {
        None
    } else {
        login_listener::loopback_bind_addr(wire.redirect_uri)
            .and_then(|addr| login_listener::capture_callback(&addr))
    };

    println!("Open this URL in a browser signed into the account to custody:");
    println!();
    println!("  {authorize_url}");
    println!();
    // Best-effort browser open; the printed URL is the source of truth if it fails.
    let _ = open_in_browser(&authorize_url);

    // Prefer the listener: if it captured the redirect, use it; otherwise (bind
    // failed, timed out, or a non-loopback redirect) fall back to paste. The pasted
    // value never touches argv — it is a secret-grade code read from stdin only.
    let captured = match listener {
        Some(l) => {
            println!(
                "Waiting for the browser redirect on {} (or paste the URL if it does not complete)...",
                wire.redirect_uri
            );
            l.wait()
        }
        None => None,
    };
    let raw_callback = match captured {
        Some(query) => query,
        None => {
            println!("{}", wire.paste_prompt);
            let mut pasted = String::new();
            std::io::stdin()
                .read_line(&mut pasted)
                .map_err(|e| CliError::Io(format!("reading pasted code: {e}")))?;
            pasted
        }
    };
    let callback = parse_callback(&raw_callback)
        .ok_or_else(|| CliError::Usage("could not parse the login callback".to_string()))?;

    // Exchange the code for tokens over the provider's wire. State is validated
    // inside (before any network call), so a forged/stale callback is refused up
    // front.
    let http =
        credentials_core::http::ReqwestTransport::new().map_err(|e| CliError::Io(e.to_string()))?;
    let now_ms = chrono::Utc::now().timestamp_millis();
    let tokens = match wire.exchange {
        ExchangeWire::AnthropicJson => tokio_block_on(exchange_authorization_code(
            &http,
            wire.token_url,
            wire.client_id,
            wire.redirect_uri,
            &callback,
            &state,
            &pkce.verifier,
            now_ms,
        )),
        ExchangeWire::RfcForm => {
            // xAI's public-client token endpoint echoes the PKCE challenge in the
            // exchange body (alongside the verifier); OpenAI sends none.
            let extra_body: &[(&str, &str)] = if wire.exchange_echoes_challenge {
                &[
                    ("code_challenge", &pkce.challenge),
                    ("code_challenge_method", "S256"),
                ]
            } else {
                &[]
            };
            tokio_block_on(exchange_authorization_code_form(
                &http,
                wire.token_url,
                wire.client_id,
                wire.redirect_uri,
                &callback,
                &state,
                &pkce.verifier,
                extra_body,
                now_ms,
            ))
        }
    }
    .map_err(|e| CliError::Io(e.to_string()))?;

    // The OpenAI browser-flow exchange returns no expires_in; the access token is a
    // JWT carrying its own `exp` (seconds). Fall back to it so the refresh engine
    // sees the real expiry instead of never-expires (the official codex CLI reads
    // the same claim).
    let expires_at_ms = tokens.expires_at_ms.or_else(|| {
        decode_jwt_claims(&tokens.access_token)
            .and_then(|c| c.get("exp")?.as_i64())
            .map(|exp_s| exp_s.saturating_mul(1000))
    });

    // Non-secret identity sanity check for the ChatGPT wire: llm-runner derives the
    // ChatGPT-Account-Id header from the access token's claims and fails loud when
    // absent — surface that at mint time rather than at first read.
    if provider == "openai" {
        match extract_chatgpt_account_id(&tokens) {
            Some(account) => println!("chatgpt account id: {account}"),
            None => println!(
                "WARNING: the minted token carries no chatgpt_account_id claim; \
                 the ChatGPT wire family will refuse it — is this a ChatGPT-subscription account?"
            ),
        }
    }

    // Build the canonical oauth credential + record. token_url and client_id are
    // stored on the record so the refresh path uses the same endpoint/client that
    // minted this token.
    let oauth = credentials_core::oauth::OAuthCredential {
        access_token: tokens.access_token.clone(),
        refresh_token: tokens.refresh_token.clone(),
        expires_at_ms,
        token_url: wire.token_url.to_string(),
        client_id: Some(wire.client_id.to_string()),
        scopes: wire.scopes.iter().map(|s| s.to_string()).collect(),
    };
    let payload = tokens.access_token.clone().into_bytes();
    let record = VaultRecord::new_oauth("login", wire.adapter_name, oauth, payload);

    // Login records a distinct `Login` audit op (not `Import`) so forensics can tell
    // a native mint from a foreign import. `--replace` overwrites an existing id (the
    // dual-custody migration: swap the imported token for the vault-minted one; the
    // handle survives). With `--subc` the commit rides the RUNNING module, so a
    // re-login needs no daemon stop at all (the zero-downtime path).
    if has_flag(args, "--replace") {
        commit_admin(
            global,
            store_op(
                &id,
                record,
                AdminAuditOp::Login,
                StoreMode::ReplaceUnconditional,
            ),
        )?;
        println!("logged in and replaced {id}");
    } else {
        commit_admin(
            global,
            store_op(&id, record, AdminAuditOp::Login, StoreMode::Create),
        )?;
        println!("logged in and stored {id}");
    }
    Ok(())
}

fn cmd_invalidate(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    let id = required(args, "--id")?;
    // The compound invalidate is atomic: needs_reauth + clear intent + revoke all
    // handles in one fenced transaction (so a live relay can't split the halves).
    let result = commit_admin(
        global,
        AdminOpBody::Invalidate {
            v: ADMIN_OP_SCHEMA_V1,
            id: id.clone(),
        },
    )?;
    let revoked = result["handles_revoked"].as_u64().unwrap_or(0);
    println!("invalidated {id}; revoked {revoked} handle(s)");
    Ok(())
}

/// `logout` = stop serving a credential, reversibly: invalidate + revoke all its
/// handles (the compound atomic op), keeping the row and its audit chain. Re-login
/// restores it (`login --provider <p> --replace`). Deliberately NOT a delete — a
/// logout must never destroy an audit trail. `--provider <p>` resolves to the same
/// default id `login --provider <p>` writes; `--id` names any credential directly.
fn cmd_logout(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    let id = match (optional(args, "--id"), optional(args, "--provider")) {
        (Some(_), Some(_)) => {
            return Err(CliError::Usage(
                "pass only one of --id or --provider".to_string(),
            ))
        }
        (Some(id), None) => id,
        (None, Some(provider)) => login_provider(&provider)
            .map(|wire| wire.default_id.to_string())
            .ok_or_else(|| {
                CliError::Usage(format!(
                    "unknown login provider '{provider}'; pass --id <id> for other credentials"
                ))
            })?,
        (None, None) => {
            return Err(CliError::Usage(
                "--provider <p> or --id <id> is required".to_string(),
            ))
        }
    };
    let result = commit_admin(
        global,
        AdminOpBody::Invalidate {
            v: ADMIN_OP_SCHEMA_V1,
            id: id.clone(),
        },
    )?;
    let revoked = result["handles_revoked"].as_u64().unwrap_or(0);
    println!("logged out {id}: stopped serving, revoked {revoked} handle(s)");
    println!("(reversible: `login --provider <p> --replace` restores it; the record and audit chain are kept)");
    Ok(())
}

/// `status` = the one command for "why does the health table say degraded": the
/// no-decrypt credential inventory + the same fail-closed health ladder the live
/// probe computes. An authenticated admin READ — with --subc it reads the RUNNING
/// module (master-key challenge-response, works exactly when the probe shows
/// degraded); offline it takes the lease like `list`.
fn cmd_status(global: &GlobalArgs) -> Result<(), CliError> {
    let result = commit_admin(
        global,
        AdminOpBody::Status {
            v: ADMIN_OP_SCHEMA_V1,
        },
    )?;

    let status = result["status"].as_str().unwrap_or("unknown");
    let total = result["credentials_total"].as_u64().unwrap_or(0);
    let active = result["active"].as_u64().unwrap_or(0);
    println!("vault: {status} ({active}/{total} serving)");
    if result["fenced_out"].as_bool() == Some(true) {
        println!("FENCED OUT: this writer lost the single-writer lease to a newer instance");
    }
    let open_intents = result["open_intents"].as_u64().unwrap_or(0);
    if open_intents > 0 {
        println!("open refresh intents: {open_intents}");
    }
    println!();
    if let Some(rows) = result["credentials"].as_array() {
        for row in rows {
            let state = row["state"].as_str().unwrap_or("?");
            let version = row["record_version"].as_u64().unwrap_or(0);
            let id = row["id"].as_str().unwrap_or("?");
            println!("{state:<14} v{version:<4} {id}");
        }
    }
    // Actionable tail: name what needs the operator, like the health probe does.
    let needs: Vec<&str> = result["needs_reauth_ids"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    if !needs.is_empty() {
        println!();
        println!(
            "needs re-login: {} (fix: `login --provider <p> --replace`, or `import --replace`)",
            needs.join(", ")
        );
    }
    Ok(())
}

fn cmd_rotate_master_key(global: &GlobalArgs) -> Result<(), CliError> {
    // Crash-safe two-slot handover. The key store holds two slots (current/next);
    // the database's plaintext key_id is the authority for which key it is sealed
    // under. Order — brick-free at every crash point:
    //   0. HEAL any prior crashed-mid-rotation state (a `next` the database is already
    //      sealed under, from a rotation that crashed before promotion): promote it to
    //      `current` and clear `next`, so staging below cannot overwrite a key the
    //      database depends on. Without this, a second rotation staging into `next`
    //      followed by a crash before its own rewrap would leave the database matching
    //      NEITHER slot — the scheme's one bricking window.
    //   1. open under the current key (proves possession + takes the lease),
    //   2. STAGE the new key into `next` (current still opens the vault),
    //   3. DB rewrap under the new key in ONE atomic fenced txn (now the db's key_id
    //      matches `next`),
    //   4. PROMOTE `next` to `current` and clear `next` (hygiene; off the brick-path).
    // A crash after (2) resolves via current (db still old); after (3) via next (db
    // now new); after (4) via current. No state matches neither slot.
    let mut store = open_for_admin(global)?;
    let new_key = MasterKey::generate().map_err(|_| CliError::Io("csprng".to_string()))?;
    let new_key_id = new_key.key_id();
    let config = resolver_config(global);

    // Heal before staging: `store.key_id()` is the fingerprint the database is sealed
    // under (open_for_admin resolved the matching slot and opened under it), so a pending
    // un-promoted `next` from a crashed prior rotation is promoted to `current` and
    // `next` freed before we stage the new key into it.
    resolver::heal_pending_rotation(&config, store.key_id()).map_err(CliError::MasterKey)?;

    resolver::stage_next(&config, &new_key).map_err(CliError::MasterKey)?;
    let quarantined = store.rotate_master_key(new_key).map_err(CliError::Store)?;
    // Promote copies `next` to `current` and clears `next` within the key store, so
    // it needs no key handle (the new key was consumed by the rewrap above).
    resolver::promote_next(&config).map_err(CliError::MasterKey)?;
    println!("rotated master key to key_id {}", new_key_id.to_hex());
    if !quarantined.is_empty() {
        // Records that could not decrypt under the OLD key were already corrupt; the
        // rotation quarantined them (state = corrupt) rather than leaving stale-key rows.
        // Surface them so the operator re-imports/re-logs them in.
        eprintln!(
            "warning: {} record(s) could not be re-wrapped and were quarantined as corrupt \
             (re-import or re-login these): {}",
            quarantined.len(),
            quarantined.join(", ")
        );
    }
    Ok(())
}

fn cmd_mint_handle(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    let id = required(args, "--id")?;
    let result = commit_admin(
        global,
        AdminOpBody::MintHandle {
            v: ADMIN_OP_SCHEMA_V1,
            id: id.clone(),
        },
    )?;
    let handle = result["handle"]
        .as_str()
        .ok_or_else(|| CliError::Io("mint did not return a handle".into()))?;
    // The raw handle is printed ONCE; write it into the consumer's 0600 config.
    println!("{handle}");
    eprintln!("(minted handle for {id}; store it now — it is not recoverable)");
    Ok(())
}

fn cmd_revoke_handle(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    let handle = required(args, "--handle")?;
    commit_admin(
        global,
        AdminOpBody::RevokeHandle {
            v: ADMIN_OP_SCHEMA_V1,
            handle,
        },
    )?;
    println!("revoked handle");
    Ok(())
}

fn cmd_revoke_all_handles(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    let id = required(args, "--id")?;
    let result = commit_admin(
        global,
        AdminOpBody::RevokeAllHandles {
            v: ADMIN_OP_SCHEMA_V1,
            id: id.clone(),
        },
    )?;
    let n = result["handles_revoked"].as_u64().unwrap_or(0);
    println!("revoked {n} handle(s) for {id}");
    Ok(())
}

fn cmd_audit(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    let limit = optional(args, "--limit")
        .map(|s| s.parse::<usize>())
        .transpose()
        .map_err(|e| CliError::Usage(format!("--limit not an integer: {e}")))?;
    let store = open_for_admin(global)?;
    let entries = store.read_audit(limit).map_err(CliError::Store)?;
    for e in entries {
        let alarm = if e.alarm { " ALARM" } else { "" };
        println!(
            "{:>5} {} {} {}{}",
            e.seq,
            e.op,
            e.credential_id.as_deref().unwrap_or("-"),
            e.actor,
            alarm
        );
    }
    Ok(())
}

fn cmd_list(global: &GlobalArgs) -> Result<(), CliError> {
    // Read-only: id + lifecycle state + version, WITHOUT decrypting any record
    // (list_meta reads only plaintext columns). This is the operator's offline
    // "which credential needs action?" view — the counterpart to the live health
    // probe's needs_reauth ids — so re-importing a stale credential does not
    // require reading the audit log and inferring.
    let store = open_for_admin(global)?;
    let rows = store.list_meta().map_err(CliError::Store)?;
    for (id, meta) in rows {
        let state = match meta.state {
            RecordState::Active => "active",
            RecordState::NeedsReauth => "needs_reauth",
            RecordState::Corrupt => "corrupt",
        };
        println!("{:<14} v{:<4} {}", state, meta.record_version, id);
    }
    Ok(())
}

fn cmd_verify_audit(global: &GlobalArgs) -> Result<(), CliError> {
    let store = open_for_admin(global)?;
    match store.verify_audit_chain().map_err(CliError::Store)? {
        None => {
            println!("audit chain verified: intact");
            Ok(())
        }
        Some(seq) => Err(CliError::Io(format!(
            "audit chain BROKEN at seq {seq} (tamper detected)"
        ))),
    }
}

// ---- arg parsing helpers -------------------------------------------------

fn parse_global(args: &mut Vec<String>) -> Result<GlobalArgs, CliError> {
    // ZERO-FLAG default: on a standard install every flag below is derivable, so a
    // top-level command (`ck auth login --provider xai --replace`, `ck auth status`)
    // works with no path arguments at all. Flags are OVERRIDES for non-standard
    // installs, never requirements.
    let (data_dir, data_dir_explicit) = match take_flag(args, "--data-dir") {
        Some(dir) => (PathBuf::from(dir), true),
        // The daemon's storage path is fixed by convention to
        // <data_home>/cortexkit/<module_id> (subc daemon_config); module_id is a
        // known constant, and data_home follows the same platform default subc
        // uses. So the default IS the directory the supervised vault serves.
        None => (default_data_home().join("cortexkit").join(MODULE_ID), false),
    };
    let key_source = match take_flag(args, "--key-path") {
        Some(path) => KeySource::OperatorPath {
            path: PathBuf::from(path),
        },
        // Fieldless: the keychain item is scoped per-vault by the data dir inside the
        // backend (contract::keychain_service_for), so there is no service/account
        // here for the CLI and daemon to set differently.
        None => KeySource::Keychain,
    };
    // --subc resolution:
    // - explicit --subc: use it verbatim (the operator named a specific daemon).
    // - no --subc AND default data-dir: DISCOVER the connection file the way `ck`
    //   does, so the standard-install zero-flag path routes through the running
    //   daemon automatically.
    // - no --subc AND EXPLICIT --data-dir: do NOT auto-discover. An explicit vault
    //   dir means "this specific vault"; the discovered daemon may serve a
    //   DIFFERENT vault, so silently routing there would be wrong. Use the offline
    //   lease path (or the operator adds --subc to route deliberately). This keeps
    //   auto-routing scoped to exactly the vault the default derivation targets.
    let subc_conn = match take_flag(args, "--subc") {
        Some(path) => Some(PathBuf::from(path)),
        None if data_dir_explicit => None,
        None => discover_subc_connection_file(),
    };
    Ok(GlobalArgs {
        data_dir,
        key_source,
        subc_conn,
    })
}

/// Platform data home, matching subc's `default_data_home` byte-for-byte so the
/// derived vault directory is exactly the one the supervised daemon serves:
/// `$XDG_DATA_HOME`, else the Windows roaming profile, else `~/.local/share`.
fn default_data_home() -> PathBuf {
    if let Some(v) = non_empty_env("XDG_DATA_HOME") {
        return PathBuf::from(v);
    }
    #[cfg(windows)]
    {
        if let Some(v) = non_empty_env("APPDATA") {
            return PathBuf::from(v);
        }
        if let Some(v) = non_empty_env("USERPROFILE") {
            return PathBuf::from(v).join("AppData").join("Roaming");
        }
    }
    if let Some(v) = non_empty_env("HOME") {
        return PathBuf::from(v).join(".local").join("share");
    }
    PathBuf::from(".local").join("share")
}

/// Discover the subc connection file the way the `ck` dispatcher does:
/// `$XDG_RUNTIME_DIR/subc-connection.json`, else the production location
/// `~/.local/share/cortexkit/run/subc-connection.json`. Only an EXISTING file is
/// returned — no daemon means the offline lease path, which is the correct
/// fallback, not an error.
fn discover_subc_connection_file() -> Option<PathBuf> {
    const CONNECTION_FILE_NAME: &str = "subc-connection.json";
    if let Some(runtime_dir) = non_empty_env("XDG_RUNTIME_DIR") {
        let p = PathBuf::from(runtime_dir).join(CONNECTION_FILE_NAME);
        if p.is_file() {
            return Some(p);
        }
    }
    if let Some(home) = non_empty_env("HOME") {
        let p = PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("cortexkit")
            .join("run")
            .join(CONNECTION_FILE_NAME);
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

fn non_empty_env(key: &str) -> Option<std::ffi::OsString> {
    let v = std::env::var_os(key)?;
    if v.is_empty() {
        None
    } else {
        Some(v)
    }
}

/// Remove `--flag <value>` from the arg list and return the value (a global flag
/// may appear anywhere).
fn take_flag(args: &mut Vec<String>, flag: &str) -> Option<String> {
    let pos = args.iter().position(|a| a == flag)?;
    if pos + 1 >= args.len() {
        return None;
    }
    let value = args.remove(pos + 1);
    args.remove(pos);
    Some(value)
}

fn required(args: &[String], flag: &str) -> Result<String, CliError> {
    optional(args, flag).ok_or_else(|| CliError::Usage(format!("{flag} is required")))
}

fn optional(args: &[String], flag: &str) -> Option<String> {
    let pos = args.iter().position(|a| a == flag)?;
    args.get(pos + 1).cloned()
}

/// Whether a boolean (valueless) flag is present.
fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|a| a == flag)
}

/// Run one async future to completion on a temporary current-thread runtime. The CLI
/// is otherwise synchronous; the only async work is the single login token exchange,
/// so a full multi-thread runtime is unwarranted.
fn tokio_block_on<F: std::future::Future>(fut: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("building a current-thread runtime never fails")
        .block_on(fut)
}

/// Best-effort open of a URL in the operator's default browser. A failure is ignored
/// by the caller — the URL is also printed, so the login still works if this no-ops
/// (e.g. a headless box). Never passes the URL through a shell (no injection surface).
fn open_in_browser(url: &str) -> std::io::Result<()> {
    #[cfg(target_os = "macos")]
    let mut cmd = {
        let mut c = std::process::Command::new("open");
        c.arg(url);
        c
    };
    #[cfg(target_os = "linux")]
    let mut cmd = {
        let mut c = std::process::Command::new("xdg-open");
        c.arg(url);
        c
    };
    #[cfg(target_os = "windows")]
    let mut cmd = {
        // `cmd /c start "" <url>` — the empty title arg avoids start treating the URL
        // as a window title. The URL is a single arg, not shell-interpolated.
        let mut c = std::process::Command::new("cmd");
        c.args(["/C", "start", "", url]);
        c
    };
    cmd.stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|_| ())
}

fn decode_hash(hex: &str) -> Result<[u8; 32], CliError> {
    if hex.len() != 64 {
        return Err(CliError::Usage(
            "--expected-hash must be 64 hex chars".to_string(),
        ));
    }
    let mut out = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        let s = std::str::from_utf8(chunk).map_err(|_| CliError::Usage("bad hex".into()))?;
        out[i] = u8::from_str_radix(s, 16).map_err(|_| CliError::Usage("bad hex".into()))?;
    }
    Ok(out)
}

fn descriptor(global: &GlobalArgs) -> StorageDescriptor {
    let path = global.data_dir.join("store.db");
    StorageDescriptor {
        module_id: MODULE_ID.to_string(),
        storage_namespace: STORAGE_NAMESPACE.to_string(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: path.to_string_lossy().into_owned(),
        },
    }
}

fn resolver_config(global: &GlobalArgs) -> ResolverConfig {
    ResolverConfig {
        data_dir: global.data_dir.clone(),
        source: global.key_source.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn accepts_known_flags_with_values() {
        // import's real flags (global --data-dir/--key-path are already pulled before
        // this runs, so they are not in the slice here).
        assert!(reject_unknown_args(
            "import",
            &v(&[
                "--source",
                "opencode",
                "--provider",
                "google",
                "--id",
                "opencode:google",
                "--json",
                "/p/auth.json"
            ])
        )
        .is_ok());
        // A flag value that happens to look like a flag name is still a value, not a
        // leftover (consumed by the preceding flag).
        assert!(reject_unknown_args("invalidate", &v(&["--id", "--weird-but-valid-id"])).is_ok());
        // Commands that take no per-command flags accept an empty arg slice.
        assert!(reject_unknown_args("bootstrap", &v(&[])).is_ok());
        assert!(reject_unknown_args("verify-audit", &v(&[])).is_ok());
    }

    #[test]
    fn rejects_unknown_and_typoed_flags() {
        // A stray unknown flag is a hard error (not silently ignored).
        assert!(reject_unknown_args("mint-handle", &v(&["--id", "x", "--bogus"])).is_err());
        // A typo'd flag name (--it for --id) is rejected — without this it would be
        // dropped and the command would run with a MISSING id.
        assert!(reject_unknown_args("invalidate", &v(&["--it", "opencode:anthropic"])).is_err());
        // A bare positional (no leading flag) is rejected for a no-flag command — this
        // is the `bootstrap somearg` / `bootstrap --help` class that previously RAN.
        assert!(reject_unknown_args("bootstrap", &v(&["--help"])).is_err());
        assert!(reject_unknown_args("bootstrap", &v(&["stray"])).is_err());
    }
}
