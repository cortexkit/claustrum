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

use cortexkit_store::{open_sqlite, Isolation, StorageBackend, StorageDescriptor, StoreError};
use credentials_core::audit::{AuditCtx, AuditOp};
use credentials_core::contract::{MODULE_ID, STORAGE_NAMESPACE};
use credentials_core::key::MasterKey;
use credentials_core::record::{CredentialKind, VaultRecord};
use credentials_core::resolver::{self, KeySource, MasterKeyError, ResolverConfig};
use credentials_core::store::{mint_handle, EncryptedStore, StoreOpError};

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
}

impl CliError {
    fn exit_code(&self) -> ExitCode {
        match self {
            CliError::DaemonRunning => ExitCode::from(3),
            CliError::MasterKey(_) => ExitCode::from(4),
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
        }
    }
}

impl std::error::Error for CliError {}

struct GlobalArgs {
    data_dir: PathBuf,
    key_source: KeySource,
}

fn run() -> Result<(), CliError> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        return Err(CliError::Usage(usage()));
    }
    let command = args.remove(0);

    // Pull the global flags (--data-dir, and the key source) out of the arg list.
    let global = parse_global(&mut args)?;

    match command.as_str() {
        "bootstrap" => cmd_bootstrap(&global),
        "put" => cmd_put(&global, &args),
        "import" => cmd_import(&global, &args),
        "invalidate" => cmd_invalidate(&global, &args),
        "rotate-master-key" => cmd_rotate_master_key(&global),
        "mint-handle" => cmd_mint_handle(&global, &args),
        "revoke-handle" => cmd_revoke_handle(&global, &args),
        "revoke-all-handles" => cmd_revoke_all_handles(&global, &args),
        "audit" => cmd_audit(&global, &args),
        "verify-audit" => cmd_verify_audit(&global),
        "help" | "--help" | "-h" => {
            println!("{}", usage());
            Ok(())
        }
        other => Err(CliError::Usage(format!(
            "unknown command '{other}'\n{}",
            usage()
        ))),
    }
}

fn usage() -> String {
    "cortexkit-credentials admin CLI (run while the daemon is STOPPED)\n\
     \n\
     Global: --data-dir <dir> (required) [--key-path <file> | keychain default]\n\
     Commands: bootstrap | put | import | invalidate | rotate-master-key |\n\
               mint-handle | revoke-handle | revoke-all-handles | audit | verify-audit"
        .to_string()
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
    let payload = required(args, "--payload")?.into_bytes();
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

    let store = open_for_admin(global)?;
    let record = VaultRecord::new_static(kind, "operator", payload, expires_at_ms);
    // CREATE-ONLY by default. An overwrite requires an explicit --expected-hash CAS.
    match optional(args, "--expected-hash") {
        Some(hex) => {
            let expected = decode_hash(&hex)?;
            store
                .overwrite_cas_audited(&id, &record, &expected, AuditCtx::admin(AuditOp::Overwrite))
                .map_err(CliError::Store)?;
            println!("overwrote {id} (CAS ok)");
        }
        None => {
            store
                .create_audited(&id, &record, AuditCtx::admin(AuditOp::Put))
                .map_err(CliError::Store)?;
            println!("created {id}");
        }
    }
    Ok(())
}

fn cmd_import(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    let source = required(args, "--source")?;
    let id = required(args, "--id")?;
    let json_path = required(args, "--json")?;
    let raw =
        std::fs::read(&json_path).map_err(|e| CliError::Io(format!("reading {json_path}: {e}")))?;
    // `--provider <key>` selects one provider's entry from a multi-provider auth.json
    // (the real on-disk shape); without it, --json must be a single provider's entry.
    let oauth = match optional(args, "--provider") {
        Some(provider) => {
            credentials_core::oauth::OAuthCredential::import_provider(&source, &raw, &provider)
        }
        None => credentials_core::oauth::OAuthCredential::import(&source, &raw),
    }
    .map_err(|e| CliError::Usage(format!("import parse: {e}")))?;
    let payload = oauth.access_token.clone().into_bytes();
    let record = VaultRecord::new_oauth(source, adapter_for(&id), oauth, payload);

    let store = open_for_admin(global)?;
    store
        .create_audited(&id, &record, AuditCtx::admin(AuditOp::Import))
        .map_err(CliError::Store)?;
    println!("imported {id}");
    Ok(())
}

fn cmd_invalidate(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    let id = required(args, "--id")?;
    let store = open_for_admin(global)?;
    store
        .invalidate_audited(&id, AuditCtx::admin(AuditOp::Invalidate))
        .map_err(CliError::Store)?;
    // Revoke the credential's handles too: an invalidated credential's handles must
    // not keep resolving.
    let revoked = store.revoke_all_handles(&id).map_err(CliError::Store)?;
    println!("invalidated {id}; revoked {revoked} handle(s)");
    Ok(())
}

fn cmd_rotate_master_key(global: &GlobalArgs) -> Result<(), CliError> {
    // Crash-safe two-slot handover. The key store holds two slots (current/next);
    // the database's plaintext key_id is the authority for which key it is sealed
    // under. Order — brick-free at every crash point:
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

    resolver::stage_next(&config, &new_key).map_err(CliError::MasterKey)?;
    store.rotate_master_key(new_key).map_err(CliError::Store)?;
    // Promote copies `next` to `current` and clears `next` within the key store, so
    // it needs no key handle (the new key was consumed by the rewrap above).
    resolver::promote_next(&config).map_err(CliError::MasterKey)?;
    println!("rotated master key to key_id {}", new_key_id.to_hex());
    Ok(())
}

fn cmd_mint_handle(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    let id = required(args, "--id")?;
    let store = open_for_admin(global)?;
    // The credential must exist before a handle is minted for it.
    store.meta(&id).map_err(CliError::Store)?;
    let handle = mint_handle().map_err(|e| CliError::Io(format!("csprng: {e}")))?;
    // put_handle_hash folds the MintHandle audit entry into the same fenced txn, so
    // the mint and its audit record commit atomically (no error-swallowed append).
    store
        .put_handle_hash(&handle.hash, &id)
        .map_err(CliError::Store)?;
    // The raw handle is printed ONCE; write it into the consumer's 0600 config.
    println!("{}", handle.raw);
    eprintln!("(minted handle for {id}; store it now — it is not recoverable)");
    Ok(())
}

fn cmd_revoke_handle(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    let handle = required(args, "--handle")?;
    let store = open_for_admin(global)?;
    store.revoke_handle(&handle).map_err(CliError::Store)?;
    println!("revoked handle");
    Ok(())
}

fn cmd_revoke_all_handles(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    let id = required(args, "--id")?;
    let store = open_for_admin(global)?;
    let n = store.revoke_all_handles(&id).map_err(CliError::Store)?;
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
    let data_dir = take_flag(args, "--data-dir")
        .ok_or_else(|| CliError::Usage("--data-dir <dir> is required".to_string()))?;
    let key_source = match take_flag(args, "--key-path") {
        Some(path) => KeySource::OperatorPath {
            path: PathBuf::from(path),
        },
        // Fieldless: the keychain item is scoped per-vault by the data dir inside the
        // backend (contract::keychain_service_for), so there is no service/account
        // here for the CLI and daemon to set differently.
        None => KeySource::Keychain,
    };
    Ok(GlobalArgs {
        data_dir: PathBuf::from(data_dir),
        key_source,
    })
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

/// Default the refresh adapter from the credential id prefix (e.g.
/// `opencode:anthropic` -> `anthropic`). Falls back to the id itself.
fn adapter_for(id: &str) -> String {
    id.rsplit(':').next().unwrap_or(id).to_string()
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
