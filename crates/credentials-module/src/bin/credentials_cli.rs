#![forbid(unsafe_code)]

//! The claustrum admin CLI (`ck auth`).
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
//!   put       --id <id> --payload <bytes> [--kind api_key|dsn|opaque] [--expires-ms N] [--replace]
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
#[path = "cli_support/api_key_login.rs"]
mod api_key_login;
#[path = "cli_support/google_login.rs"]
mod google_login;
#[path = "cli_support/login_listener.rs"]
mod login_listener;
#[path = "cli_support/provider_login.rs"]
mod provider_login;

use cortexkit_store::{open_sqlite, Isolation, StorageBackend, StorageDescriptor, StoreError};
use credentials_core::admin_ops::{AdminAuditOp, AdminOpBody, StoreMode, ADMIN_OP_SCHEMA_V1};
use credentials_core::contract::{MODULE_ID, STORAGE_NAMESPACE};
use credentials_core::credential_id::{default_refresh_adapter, parse_credential_id, AuthMethod};
use credentials_core::key::MasterKey;
use credentials_core::record::{CredentialKind, VaultRecord};
use credentials_core::resolver::{self, KeySource, MasterKeyError, ResolverConfig};
use credentials_core::store::{EncryptedStore, StoreOpError};

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
    /// The daemon holds the lease. The payload says whether a route path EXISTS for
    /// the refused verb, because the remedy differs and a wrong one is worse than
    /// none: an operator told to retry with `--subc` on a verb that has no admin op
    /// gets the identical error again and reasonably concludes the vault is broken.
    /// For `rotate-master-key` that happens during a key compromise, which is the
    /// worst possible moment to be sent through a door that is not there.
    DaemonRunning {
        route_path_exists: bool,
    },
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
            CliError::DaemonRunning { .. } => ExitCode::from(3),
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
            // NAME THE FIX, not just the cause. This refusal is the one moment a
            // caller is guaranteed to be reading, and the old text offered only
            // "stop the daemon" -- which is the WORSE of the two remedies and the
            // only one it mentioned. Routing through the running module needs no
            // downtime and is what an operator almost always wants; it was documented
            // under `help overrides`, i.e. exactly where someone who does not yet know
            // the flag exists will not look.
            CliError::DaemonRunning {
                route_path_exists: true,
            } => f.write_str(
                "the credentials daemon is running (holds the single-writer lease). \
                 Either commit through it with --subc <connection-file> (no downtime), \
                 or stop the daemon to use the offline path.",
            ),
            CliError::DaemonRunning {
                route_path_exists: false,
            } => f.write_str(
                "the credentials daemon is running (holds the single-writer lease), and \
                 this verb has no route path — it can only run offline. Stop the daemon \
                 (ck module stop claustrum), run it, then start the daemon again. \
                 --subc will NOT help here.",
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
    // Bare `ck auth` prints the short verb table to stdout and exits 0 — showing
    // usage is not an error (no `error:` prefix, no stderr).
    if args.is_empty() {
        println!("{}", usage_short());
        return Ok(());
    }
    if args.as_slice() == ["--version"] || args.as_slice() == ["-V"] {
        // The package version alone cannot identify a build -- it is a constant that
        // has not moved in the project's lifetime. The revision is what answers "which
        // ck-auth", and it is `unknown` unless this came from the release script.
        println!(
            "ck-auth {} ({})",
            env!("CARGO_PKG_VERSION"),
            credentials_core::contract::BUILD_REV
        );
        return Ok(());
    }
    // The verb is positional and is taken FIRST, so a global flag written before it
    // would be read as the verb itself. Rather than let that surface as "unexpected
    // argument '<path>' for '--data-dir'" -- which names the flag as a verb and tells
    // the reader nothing about what to do -- accept the leading-flag form by moving
    // any leading global flags (and their values) after the verb.
    //
    // Both orders are documented as working and an operator has no way to know the
    // parser is positional, so refusing one of them would be a rule with no reason a
    // caller could see.
    hoist_leading_global_flags(&mut args);
    let command = args.remove(0);

    // A `--help`/`-h` ANYWHERE prints help and exits WITHOUT running the command.
    // This is load-bearing safety, not a convenience: the arg parser pulls the flags
    // it knows and (before this) silently ignored the rest, so `bootstrap --help`
    // ignored `--help` and RAN bootstrap — provisioning stray key material on a typo.
    // Intercepting here, before parse_global / any open-for-admin, makes help a no-op.
    // `ck auth help [<verb>]` and `ck auth <verb> --help` both land here: with a verb
    // we print that verb's detail page, otherwise the short table.
    if command == "help" || command == "--help" || command == "-h" {
        // `help <verb>` → the verb's page; bare `help` → the short table.
        match args.first() {
            Some(verb) => println!("{}", help_verb(verb)),
            None => println!("{}", usage_short()),
        }
        return Ok(());
    }
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("{}", help_verb(&command));
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
        "remove" => cmd_remove(&global, &args),
        "status" => cmd_status(&global),
        "rotate-master-key" => cmd_rotate_master_key(&global),
        "mint-handle" => cmd_mint_handle(&global, &args),
        "revoke-handle" => cmd_revoke_handle(&global, &args),
        "revoke-all-handles" => cmd_revoke_all_handles(&global, &args),
        "list" => cmd_list(&global),
        "audit" => cmd_audit(&global, &args),
        "events" => cmd_events(&global, &args),
        "usable" => cmd_usable(&global),
        "verify-audit" => cmd_verify_audit(&global),
        other => Err(CliError::Usage(format!(
            "unknown verb '{other}'\n\n{}",
            usage_short()
        ))),
    }
}

/// Move any global flags that appear BEFORE the verb to after it, so both orders work.
///
/// Each global flag takes a value, so the flag and the token following it move
/// together. Stops at the first token that is not a leading global flag, which is the
/// verb -- so flags written after the verb are untouched, and a bare `--data-dir` with
/// no value is left in place to be reported by the normal flag parser rather than
/// silently swallowed here.
fn hoist_leading_global_flags(args: &mut Vec<String>) {
    const GLOBAL_WITH_VALUE: [&str; 3] = ["--data-dir", "--subc", "--key-path"];
    let mut hoisted: Vec<String> = Vec::new();
    while args
        .first()
        .is_some_and(|a| GLOBAL_WITH_VALUE.contains(&a.as_str()))
    {
        // Only move the pair when a value is actually present; a trailing flag with
        // no value is left for the parser to refuse with its own message.
        if args.len() < 2 {
            break;
        }
        hoisted.push(args.remove(0));
        hoisted.push(args.remove(0));
    }
    args.extend(hoisted);
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
        "login" => &["--provider", "--id", "--payload-file", "--account"],
        "invalidate" | "mint-handle" | "revoke-all-handles" | "remove" => &["--id"],
        "logout" => &["--provider", "--id"],
        "revoke-handle" => &["--handle"],
        "audit" => &["--limit"],
        "events" => &["--limit"],
        // bootstrap / rotate-master-key / verify-audit take no per-command flags.
        _ => &[],
    };
    // Boolean (valueless) flags accepted per command.
    let bool_flags: &[&str] = match command {
        "put" => &["--replace"],
        "import" => &["--replace"],
        "login" => &["--replace", "--no-listener", "--device"],
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
            "unexpected argument '{arg}' for '{command}'\n\n{}",
            help_verb(command)
        )));
    }
    Ok(())
}

/// The short verb table shown for bare `ck auth`, `ck auth help`, and an unknown
/// verb. Matches the `ck` dispatcher house style (compact verb + one-line
/// description); per-verb flags and semantics live in `help_verb`, reached via
/// `ck auth help <verb>`, so a bare invocation never dumps the full man page.
fn usage_short() -> String {
    "ck auth — CortexKit provider-credential vault\n\
     \n\
     usage: ck auth <verb> [flags]\n\
     \n\
     verbs:\n\
       login               OAuth/device/api-key login (interactive with no flags)\n\
       logout              stop serving a credential (reversible)\n\
       remove              permanently delete a credential\n\
       status              vault health + credential inventory (no secrets)\n\
       list                credential ids + lifecycle state (no secrets)\n\
       put                 ingest an api key / opaque secret\n\
       import              import from opencode/pi/gemini-cli/antigravity\n\
       mint-handle         mint a capability handle for a credential\n\
       revoke-handle       revoke one capability handle\n\
       revoke-all-handles  revoke every handle for a credential\n\
       invalidate          mark a credential needs-reauth\n\
       audit               print the audit chain\n\
       events              why credentials failed to authenticate\n\
       usable              which credentials can still serve or refresh\n\
       verify-audit        verify the audit-chain integrity\n\
       rotate-master-key   rotate the vault master key (offline)\n\
       bootstrap           initialize a new vault (offline)\n\
     \n\
     On a standard install commands need no flags — the vault location and the\n\
     running daemon auto-discover. Run 'ck auth help <verb>' for flags and details."
        .to_string()
}

/// Per-verb detail page for `ck auth help <verb>` (and `ck auth <verb> --help`).
/// This is where the long-form semantics live — login listener fallback,
/// multi-account labeled ids, logout-vs-remove, import sources, offline-lease
/// overrides — so they stay discoverable without dumping on every invocation.
/// An unknown verb falls back to the short table.
fn help_verb(verb: &str) -> String {
    let body = match verb {
        "login" => {
            "ck auth login [--provider <name>] [--id <id>] [--account <id>] \
             [--replace] [--no-listener] [--device]\n\
             \n\
             Vault-native first-party login — mints an INDEPENDENT credential the vault\n\
             solely custodies (no dual-custody rotation race). Run with NO --provider for\n\
             an interactive picker of every provider.\n\
             \n\
             OAuth providers open a browser URL; a one-shot CLI-local listener on the\n\
             loopback redirect completes the flow automatically (--no-listener, a busy\n\
             port, or a timeout falls back to pasting the address-bar URL). --device\n\
             selects headless device authorization for openai/xai; github-copilot and\n\
             kimi always use device authorization. api-key providers prompt for a key\n\
             (validated before storing).\n\
             \n\
             --replace swaps an existing credential (keeps its handle).\n\
             \n\
             Providers: anthropic, openai, xai, google, antigravity, github-copilot,\n\
             kimi, cursor, devin, snowflake, digitalocean, plus api-key providers\n\
             (zai, openrouter, deepseek, groq, ...). Snowflake requires --account\n\
             (id oauth:snowflake:<account>).\n\
             \n\
             MULTIPLE ACCOUNTS per provider — give each its own labeled id:\n\
               ck auth login --provider anthropic --id oauth:anthropic:work\n\
             (label freely chosen; each labeled id is an independent credential with\n\
             its own refresh chain and handles)."
        }
        "logout" => {
            "ck auth logout --provider <p> | --id <id>\n\
             \n\
             Stop serving a credential REVERSIBLY: invalidate it and revoke its handles,\n\
             keeping the record and audit chain. `ck auth login --provider <p> --replace`\n\
             restores it. Never a delete — use `remove` for that."
        }
        "remove" => {
            "ck auth remove --id <id>\n\
             \n\
             PERMANENTLY delete a credential row and revoke its handles (audited; the\n\
             audit chain keeps the history). For retiring an account or cleaning up a\n\
             mistaken id. For a temporary stop use `logout` instead."
        }
        "status" => {
            "ck auth status\n\
             \n\
             Vault health + per-credential inventory (no secrets) — run this when the\n\
             health table says degraded. Reads the RUNNING daemon when one is up, else\n\
             the offline store."
        }
        "list" => {
            "ck auth list\n\
             \n\
             Print each credential's id + lifecycle state + version (no secrets), e.g.\n\
             to find which credential a health probe flagged needs_reauth."
        }
        "put" => {
            "ck auth put --id <id> --payload <v> | --payload-file <path>\n\
             \x20            [--kind api_key|dsn|opaque] [--expires-ms N]\n\
             \x20            [--replace | --expected-hash <hex>]\n\
             \n\
             Ingest a non-OAuth secret (an api_key, dsn, or opaque blob). Create-only by\n\
             default; --replace rotates it unconditionally (bumps record_version so\n\
             consumers re-fetch; keeps handles); --expected-hash is a concurrency-safe\n\
             CAS overwrite. --payload-file keeps the secret out of argv."
        }
        "import" => {
            "ck auth import --source <opencode|pi|gemini-cli|antigravity> --id <id> \
             --json <file>\n\
             \x20             [--provider <key>] [--adapter <name>] [--replace]\n\
             \n\
             opencode/pi read auth.json (--provider selects one entry; an apikey:<p> id\n\
               imports a {type:api,key} entry as a static key, an oauth id imports tokens);\n\
             gemini-cli reads ~/.gemini/oauth_creds.json (single credential, no --provider);\n\
             antigravity reads ~/.config/opencode/antigravity-accounts.json (accounts array;\n\
               --provider selects an account by email/index, default activeIndex);\n\
             --adapter overrides the method-derived refresh adapter;\n\
             --replace overwrites an existing id (fix a wrong-source import; keeps handles)."
        }
        "mint-handle" => {
            "ck auth mint-handle --id <id>\n\
             \n\
             Mint an unguessable capability handle for a credential — the token a\n\
             consumer presents to `credential.get`. A credential can have many handles."
        }
        "revoke-handle" => {
            "ck auth revoke-handle --handle <raw>\n\
             \n\
             Revoke one capability handle (audited). The credential and its other\n\
             handles keep serving."
        }
        "revoke-all-handles" => {
            "ck auth revoke-all-handles --id <id>\n\
             \n\
             Revoke every capability handle for a credential in one audited step. The\n\
             record itself is untouched (still refreshable; mint new handles later)."
        }
        "invalidate" => {
            "ck auth invalidate --id <id>\n\
             \n\
             Mark a credential needs-reauth (stops serving until re-login) without\n\
             revoking handles. `logout` is the usual operator verb; this is the lower-\n\
             level primitive."
        }
        "audit" => {
            "ck auth audit [--limit N]\n\
             \n\
             Print the tamper-evident HMAC audit chain (offline-only; stop the daemon\n\
             to release the lease first)."
        }
        "events" => {
            "ck auth events [--limit N]\n\
             \n\
             Print recent authentication events: why a credential stopped working.\n\
             Records a consumer's reported provider status (401 vs 403) and refresh\n\
             failures, neither of which the audit chain can carry.\n\
             \n\
             `applied` says whether the event changed the credential. A report naming\n\
             a record_version the vault had already replaced is a deliberate no-op --\n\
             shown here as applied=no, because a consumer acting on stale state is\n\
             worth seeing and leaves no other trace.\n\
             \n\
             Reads the store read-only and takes no lease, so it works against a\n\
             RUNNING vault. These rows are diagnostics, not evidence: unlike the audit\n\
             chain they are not tamper-evident and may be pruned. For what authoritatively\n\
             happened, use `audit`."
        }
        "usable" => {
            "ck auth usable\n\
             \n\
             Open every credential's envelope and report what its contents imply.\n\
             \n\
             The only command that decrypts. 'status' and 'list' read plaintext\n\
             metadata, so neither can see a record that decrypts to nothing usable.\n\
             \n\
             Scores STRANDED: a record holding neither a usable access token nor any\n\
             refresh material, so it can never serve again without an operator login.\n\
             Expiry is printed but never scored -- an expired access token beside live\n\
             refresh material is the routine state of a healthy credential, and it\n\
             refreshes on the next read.\n\
             \n\
             Safe while the daemon runs: read-only, takes no lease, writes nothing.\n\
             \n\
             'stranded: 0' is the expected reading."
        }
        "verify-audit" => {
            "ck auth verify-audit\n\
             \n\
             Verify the audit-chain integrity end to end (offline-only). Fails if any\n\
             entry was edited, reordered, or inserted."
        }
        "rotate-master-key" => {
            "ck auth rotate-master-key\n\
             \n\
             Crash-safe two-slot rotation of the vault master key (ALWAYS offline; stop\n\
             the daemon first). Re-seals every record under the new key."
        }
        "bootstrap" => {
            "ck auth bootstrap\n\
             \n\
             Initialize a new vault: provision the master key and seal the audit key\n\
             (ALWAYS offline). Refuses if the vault already exists."
        }
        "overrides" => {
            "Global flags (rarely needed; apply to any verb):\n\
             \n\
             \x20 --data-dir <dir>   vault location; defaults to the standard per-user path\n\
             \x20                    (<data_home>/cortexkit/claustrum). An\n\
             \x20                    explicit dir targets THAT vault and stays offline\n\
             \x20                    unless --subc is also given.\n\
             \x20 --subc <file>      subc connection file; auto-discovered on a standard\n\
             \x20                    install. Present => writes commit through the running\n\
             \x20                    module (zero downtime); absent/no daemon => offline\n\
             \x20                    single-writer lease (daemon must be stopped).\n\
             \x20                    rotate-master-key and bootstrap are always offline.\n\
             \x20 --key-path <file>  operator key file instead of the OS keychain."
        }
        _ => return format!("no help for '{verb}'\n\n{}", usage_short()),
    };
    format!(
        "{body}\n\nGlobal flags: --data-dir / --subc / --key-path — run 'ck auth help overrides'."
    )
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
    let store = open_for_admin(global, true)?;
    credentials_core::admin_ops::apply(&store, op, "offline-cli").map_err(CliError::Store)
}

/// Open the vault for an admin write: resolve the master key (proof of possession)
/// and take the single-writer lease (proof the daemon is stopped). Either failing
/// is a clean, typed refusal.
/// `route_path_exists` is the CALLER's answer, not this function's: the same lease
/// failure means different things to its two callers. A mutation can be committed
/// through the running daemon, so `--subc` is a real remedy; `rotate-master-key` has no
/// admin op and can only run offline, so the same advice sends an operator through a
/// door that is not there -- during a key compromise, when they can least afford it.
fn open_for_admin(
    global: &GlobalArgs,
    route_path_exists: bool,
) -> Result<EncryptedStore, CliError> {
    let store = open_sqlite(&descriptor(global)).map_err(|e| match e {
        // A held lease means the daemon is up — the structural "while stopped" gate.
        StoreError::Lease(_) => CliError::DaemonRunning { route_path_exists },
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
        // No admin op bootstraps a vault: there is no daemon to ask yet.
        StoreError::Lease(_) => CliError::DaemonRunning {
            route_path_exists: false,
        },
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
    // CREATE-ONLY by default. An overwrite is either an explicit --expected-hash CAS
    // (concurrency-safe: fails if the record changed under you) or --replace
    // (unconditional: bumps record_version, keeps existing handles). --replace is the
    // routine rotation path for a static key — the operator pastes the new key from
    // the provider console and the record_version bump invalidates every consumer's
    // cache. The two are mutually exclusive: a CAS is a targeted overwrite, --replace
    // is a deliberate blind one.
    let replace = has_flag(args, "--replace");
    match (optional(args, "--expected-hash"), replace) {
        (Some(_), true) => {
            return Err(CliError::Usage(
                "pass only one of --expected-hash (CAS) or --replace (unconditional)".to_string(),
            ));
        }
        (Some(hex), false) => {
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
        (None, true) => {
            commit_admin(
                global,
                store_op(
                    &id,
                    record,
                    AdminAuditOp::Overwrite,
                    StoreMode::ReplaceUnconditional,
                ),
            )?;
            println!("replaced {id} (unconditional)");
        }
        (None, false) => {
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
        // Antigravity carries an identity the other import sources do not: its access
        // tokens are opaque, so the email in the plugin store is the only thing that
        // can distinguish two accounts downstream.
        let mut identity_email: Option<String> = None;
        let oauth = if source == "antigravity" {
            // For antigravity the credentials live in the plugin's accounts-array
            // store instead of the normal provider auth.json file — read the selected
            // account and pack its refresh.
            credentials_core::oauth::import_antigravity_account(&raw, provider_sel.as_deref()).map(
                |imported| {
                    identity_email = imported.email;
                    imported.oauth
                },
            )
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
        let record = VaultRecord::new_oauth(source, adapter, oauth, payload);
        match identity_email {
            // Only attach an identity when one was actually read. An unconditional
            // `with_identity` would stamp an all-None identity onto every other import
            // source, which reads as "captured, and empty" rather than "never captured".
            //
            // THE EMAIL GOES IN BOTH FIELDS, and `account_id` is the load-bearing one.
            // The read surface serves `account_id` as the identity consumers join on,
            // and treats `email` as display metadata; a record carrying only `email`
            // renders a value while still resolving no identity, so a consumer
            // labelling per account keeps collapsing and the wire looks unchanged.
            // The read surface already states this as an invariant -- email never
            // ships without account_id -- and populating one field alone breaks it.
            //
            // An email is a legitimate account_id here: consumers treat it as an opaque
            // stable string, and antigravity has no other per-account identifier,
            // since its access tokens are opaque rather than JWTs.
            Some(email) => record.with_identity(credentials_core::record::RecordIdentity {
                account_id: Some(email.clone()),
                email: Some(email),
                org_name: None,
            }),
            None => record,
        }
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
/// authorization-code or device flow. Each provider's values are pinned in its adapter
/// module; adding a login provider = adding one row to `login_provider()`.
#[derive(Debug, Clone, Copy)]
enum DeviceKind {
    Xai,
    OpenAi,
    GithubCopilot,
    Kimi,
}

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
    /// Device wire, when the provider supports headless authorization.
    device: Option<DeviceKind>,
}

enum ExchangeWire {
    AnthropicJson,
    RfcForm,
}

fn login_provider(provider: &str) -> Option<LoginProvider> {
    use credentials_core::google_login as google;
    use credentials_core::refresh_adapters::{
        anthropic, cursor, devin, digitalocean, github_copilot, kimi, openai, snowflake, xai,
    };
    match provider {
        "anthropic" => Some(LoginProvider {
            authorize_url: anthropic::AUTHORIZE_URL,
            token_url: anthropic::LOGIN_TOKEN_URL,
            client_id: anthropic::CLAUDE_CODE_CLIENT_ID,
            // The Claude Code loopback redirect: the CLI's one-shot listener captures
            // the code automatically (same flow as openai/xai). Paste stays the
            // fallback when the port is busy.
            redirect_uri: anthropic::LOGIN_REDIRECT_URI,
            scopes: anthropic::LOGIN_SCOPES,
            extra_authorize_params: anthropic::LOGIN_EXTRA_AUTHORIZE_PARAMS,
            adapter_name: anthropic::ADAPTER_NAME,
            default_id: "oauth:anthropic",
            exchange: ExchangeWire::AnthropicJson,
            needs_oidc_nonce: false,
            exchange_echoes_challenge: false,
            paste_prompt: "After approving, the browser will fail to connect to localhost:54545 \
                            — that is expected (nothing listens there).\n\
                            Copy the FULL URL from the browser's address bar (or the code#state if \
                            shown) and paste it here, then Enter:",
            device: None,
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
            device: Some(DeviceKind::OpenAi),
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
            device: Some(DeviceKind::Xai),
        }),
        "github-copilot" => Some(LoginProvider {
            authorize_url: "",
            token_url: github_copilot::DEVICE_TOKEN_URL,
            client_id: github_copilot::CLIENT_ID,
            redirect_uri: "",
            scopes: &["read:user"],
            extra_authorize_params: &[],
            adapter_name: github_copilot::ADAPTER_NAME,
            default_id: "copilot:github",
            exchange: ExchangeWire::RfcForm,
            needs_oidc_nonce: false,
            exchange_echoes_challenge: false,
            paste_prompt: "",
            device: Some(DeviceKind::GithubCopilot),
        }),
        "kimi" => Some(LoginProvider {
            authorize_url: "",
            token_url: kimi::TOKEN_URL,
            client_id: kimi::CLIENT_ID,
            redirect_uri: "",
            scopes: &[],
            extra_authorize_params: &[],
            adapter_name: kimi::ADAPTER_NAME,
            default_id: "oauth:kimi",
            exchange: ExchangeWire::RfcForm,
            needs_oidc_nonce: false,
            exchange_echoes_challenge: false,
            paste_prompt: "",
            device: Some(DeviceKind::Kimi),
        }),
        // The Google-family driver handles these entries before the generic PKCE
        // path, but keeping their metadata in the provider table makes picker,
        // logout, and direct provider lookups describe the same credential ids.
        "google" => Some(LoginProvider {
            authorize_url: google::AUTHORIZE_URL,
            token_url: google::TOKEN_URL,
            client_id: "681255809395-oo8ft2oprdrnp9e3aqf6av3hmdib135j.apps.googleusercontent.com",
            redirect_uri: google::GEMINI_REDIRECT_URI,
            scopes: google::SCOPES,
            extra_authorize_params: google::AUTHORIZE_EXTRA_PARAMS,
            adapter_name: "google",
            default_id: "oauth:google",
            exchange: ExchangeWire::RfcForm,
            needs_oidc_nonce: false,
            exchange_echoes_challenge: false,
            paste_prompt: "After approving, the browser may fail to connect to 127.0.0.1:8085 — that is expected. Copy the FULL URL from the address bar and paste it here, then Enter:",
            device: None,
        }),
        "antigravity" => Some(LoginProvider {
            authorize_url: google::AUTHORIZE_URL,
            token_url: google::TOKEN_URL,
            client_id: "1071006060591-tmhssin2h21lcre235vtolojh4g403ep.apps.googleusercontent.com",
            redirect_uri: google::ANTIGRAVITY_REDIRECT_URI,
            scopes: google::SCOPES,
            extra_authorize_params: google::AUTHORIZE_EXTRA_PARAMS,
            adapter_name: "antigravity",
            default_id: "antigravity:google",
            exchange: ExchangeWire::RfcForm,
            needs_oidc_nonce: false,
            exchange_echoes_challenge: false,
            paste_prompt: "After approving, the browser may fail to connect to 127.0.0.1:51121 — that is expected. Copy the FULL URL from the address bar and paste it here, then Enter:",
            device: None,
        }),
        "cursor" => Some(LoginProvider {
            authorize_url: cursor::LOGIN_URL,
            token_url: cursor::TOKEN_URL,
            client_id: "",
            redirect_uri: "",
            scopes: &[],
            extra_authorize_params: &[],
            adapter_name: cursor::ADAPTER_NAME,
            default_id: cursor::DEFAULT_ID,
            exchange: ExchangeWire::RfcForm,
            needs_oidc_nonce: false,
            exchange_echoes_challenge: false,
            paste_prompt: "Cursor login is completed by browser polling.",
            device: None,
        }),
        "devin" => Some(LoginProvider {
            authorize_url: devin::AUTHORIZE_URL,
            token_url: devin::TOKEN_URL,
            client_id: "",
            redirect_uri: devin::LOGIN_REDIRECT_URI,
            scopes: &[],
            extra_authorize_params: &[],
            adapter_name: devin::ADAPTER_NAME,
            default_id: devin::DEFAULT_ID,
            exchange: ExchangeWire::RfcForm,
            needs_oidc_nonce: false,
            exchange_echoes_challenge: false,
            paste_prompt: "After approving Devin, paste the callback URL.",
            device: None,
        }),
        "snowflake" => Some(LoginProvider {
            authorize_url: snowflake::TOKEN_URL_BASE,
            token_url: snowflake::TOKEN_URL_BASE,
            client_id: snowflake::CLIENT_ID,
            redirect_uri: "http://127.0.0.1:0/",
            scopes: &[],
            extra_authorize_params: &[],
            adapter_name: snowflake::ADAPTER_NAME,
            default_id: "oauth:snowflake",
            exchange: ExchangeWire::RfcForm,
            needs_oidc_nonce: false,
            exchange_echoes_challenge: false,
            paste_prompt: "After approving Snowflake, paste the callback URL.",
            device: None,
        }),
        "digitalocean" => Some(LoginProvider {
            authorize_url: digitalocean::AUTHORIZE_URL,
            token_url: digitalocean::AUTHORIZE_URL,
            client_id: digitalocean::CLIENT_ID,
            redirect_uri: digitalocean::REDIRECT_URI,
            scopes: digitalocean::SCOPES,
            extra_authorize_params: &[],
            adapter_name: digitalocean::ADAPTER_NAME,
            default_id: digitalocean::DEFAULT_ID,
            exchange: ExchangeWire::RfcForm,
            needs_oidc_nonce: false,
            exchange_echoes_challenge: false,
            paste_prompt: "After approving DigitalOcean, paste the full callback URL including its fragment.",
            device: None,
        }),
        _ => None,
    }
}

/// The default credential id for a bare `--provider <name>` login (no `--id`, no
/// interactive pick). OAuth/subscription logins WIN for the three names that also
/// have an api-key row (openai → chatgpt:openai, xai → oauth:xai, google →
/// oauth:google): a bare `login --provider <name>` means the subscription login,
/// and that name's api-key credential is reached with an explicit `--id apikey:<name>`.
fn default_login_id(provider: &str) -> String {
    if let Some(wire) = login_provider(provider) {
        return wire.default_id.to_string();
    }
    if let Some(id) = google_login::default_id(provider) {
        return id.to_string();
    }
    if let Some(p) = api_key_login::API_KEY_PROVIDERS
        .iter()
        .find(|p| p.key == provider)
    {
        return p.default_id.to_string();
    }
    // Unknown provider: return it unchanged so the dispatch's final login_provider
    // lookup produces the proper "unknown provider" error.
    provider.to_string()
}

/// Whether a login `--id` is the provider's default id or a labeled sub-account of
/// it (`<default_id>:<label>`, one non-empty label segment). Anything else would
/// mint a mis-keyed credential.
fn login_id_is_valid(default_id: &str, id: &str) -> bool {
    id == default_id
        || id
            .strip_prefix(default_id)
            .and_then(|rest| rest.strip_prefix(':'))
            .is_some_and(|label| !label.is_empty() && !label.contains(':'))
}

/// The login providers offered by the interactive picker, in display order. The
/// display name is the subscription the operator recognizes; the key is what
/// `login_provider()` resolves.
const LOGIN_PICKER_ROWS: &[(&str, &str)] = &[
    ("anthropic", "Anthropic (Claude Pro/Max)"),
    ("openai", "ChatGPT (Codex subscription)"),
    ("xai", "xAI (Grok)"),
    ("github-copilot", "GitHub Copilot"),
    ("kimi", "Kimi Code"),
    ("google", "Google Gemini CLI (Code Assist)"),
    ("antigravity", "Antigravity (Gemini 3)"),
    ("cursor", "Cursor"),
    ("devin", "Devin"),
    ("snowflake", "Snowflake Cortex"),
    ("digitalocean", "DigitalOcean GenAI"),
];

/// What the interactive flow decided beyond the provider: an id override (labeled
/// account) and/or replace mode.
struct InteractiveChoice {
    provider: String,
    id_override: Option<String>,
    replace: bool,
}

/// Best-effort credential inventory for the picker's "logged in" indicators and the
/// add-vs-replace prompt: the authenticated `admin.status` read (running daemon or
/// offline lease). `None` when unavailable (unbootstrapped vault, locked keychain) —
/// the picker then simply shows no indicators; login itself will surface real errors.
fn inventory_for_picker(global: &GlobalArgs) -> Option<Vec<(String, String)>> {
    let result = commit_admin(
        global,
        AdminOpBody::Status {
            v: ADMIN_OP_SCHEMA_V1,
        },
    )
    .ok()?;
    Some(
        result["credentials"]
            .as_array()?
            .iter()
            .filter_map(|row| {
                Some((
                    row["id"].as_str()?.to_string(),
                    row["state"].as_str()?.to_string(),
                ))
            })
            .collect(),
    )
}

/// The ids belonging to one login provider: the default id and its labeled accounts.
fn provider_ids<'a>(inventory: &'a [(String, String)], default_id: &str) -> Vec<&'a str> {
    inventory
        .iter()
        .map(|(id, _)| id.as_str())
        .filter(|id| *id == default_id || id.starts_with(&format!("{default_id}:")))
        .collect()
}

fn pick_login_interactively(global: &GlobalArgs) -> Result<InteractiveChoice, CliError> {
    use dialoguer::{theme::ColorfulTheme, FuzzySelect, Input, Select};

    let inventory = inventory_for_picker(global).unwrap_or_default();
    let mut combined_rows = Vec::new();
    for &(key, name) in LOGIN_PICKER_ROWS {
        let wire = login_provider(key).expect("picker rows are valid providers");
        combined_rows.push((
            key.to_string(),
            name.to_string(),
            wire.default_id.to_string(),
        ));
    }
    for provider in api_key_login::API_KEY_PROVIDERS {
        combined_rows.push((
            provider.key.to_string(),
            provider.display_name.to_string(),
            provider.default_id.to_string(),
        ));
    }

    let items: Vec<String> = combined_rows
        .iter()
        .map(|(_key, name, default_id)| {
            let ids = provider_ids(&inventory, default_id);
            match ids.len() {
                0 => name.to_string(),
                1 => format!("{name}  ● logged in"),
                n => format!("{name}  ● {n} accounts"),
            }
        })
        .collect();

    let theme = ColorfulTheme::default();
    let pick = FuzzySelect::with_theme(&theme)
        .with_prompt("Select provider to login (type to search)")
        .items(&items)
        .default(0)
        .interact()
        .map_err(|e| {
            CliError::Usage(format!(
                "interactive login needs a terminal ({e}); run `ck auth login` with a TTY, \
                 or pass --provider <name>"
            ))
        })?;
    let (provider, _, default_id) = &combined_rows[pick];
    let default_id = default_id.as_str();
    let existing = provider_ids(&inventory, default_id);

    if existing.is_empty() {
        // Carry the picked row's default id so the dispatch keys on the credential
        // METHOD, not the provider name: openai/xai/google each name BOTH an OAuth
        // login (chatgpt:openai / oauth:xai / oauth:google) and an api-key row
        // (apikey:*), so the provider string alone cannot say which the operator
        // picked — the resolved id can.
        return Ok(InteractiveChoice {
            provider: provider.clone(),
            id_override: Some(default_id.to_string()),
            replace: false,
        });
    }

    // The account already exists: make the multi-account path a menu, not a flag.
    let mut actions = vec![format!(
        "Add another account (a new labeled id like {}:work)",
        default_id
    )];
    for id in &existing {
        actions.push(format!("Replace {id} (re-login; keeps its handles)"));
    }
    let action = Select::with_theme(&theme)
        .with_prompt("This provider already has a credential")
        .items(&actions)
        .default(0)
        .interact()
        .map_err(|e| CliError::Usage(format!("interactive login cancelled: {e}")))?;

    if action == 0 {
        let label: String = Input::with_theme(&theme)
            .with_prompt("Label for the new account (e.g. work, personal, gmail)")
            .validate_with(|s: &String| {
                if s.is_empty() || s.contains(':') || s.contains(char::is_whitespace) {
                    Err("label must be non-empty, without ':' or spaces")
                } else {
                    Ok(())
                }
            })
            .interact_text()
            .map_err(|e| CliError::Usage(format!("interactive login cancelled: {e}")))?;
        Ok(InteractiveChoice {
            id_override: Some(format!("{default_id}:{label}")),
            provider: provider.clone(),
            replace: false,
        })
    } else {
        Ok(InteractiveChoice {
            id_override: Some(existing[action - 1].to_string()),
            provider: provider.clone(),
            replace: true,
        })
    }
}

fn cmd_device_login(
    global: &GlobalArgs,
    args: &[String],
    provider: &str,
    id: &str,
    wire: &LoginProvider,
) -> Result<(), CliError> {
    use credentials_core::device_flow::{
        run_device_flow, run_openai_device_flow, DeviceBodyEncoding, DeviceFlowConfig,
    };
    use credentials_core::refresh_adapters::{github_copilot, kimi, xai, RefreshAdapter};

    let http =
        credentials_core::http::ReqwestTransport::new().map_err(|e| CliError::Io(e.to_string()))?;
    let print_device_instructions = |auth: &credentials_core::DeviceAuthorization| {
        println!("Enter this code: {}", auth.user_code);
        println!("Verification URL: {}", auth.verification_uri);
        if let Some(complete) = auth.verification_uri_complete.as_deref() {
            println!("Direct verification URL: {complete}");
        }
    };

    let tokens = match wire.device {
        Some(DeviceKind::GithubCopilot) => {
            let mut cfg = DeviceFlowConfig::new(
                github_copilot::DEVICE_CODE_URL,
                github_copilot::DEVICE_TOKEN_URL,
                github_copilot::CLIENT_ID,
                DeviceBodyEncoding::Json,
            );
            cfg.scope = Some("read:user".into());
            cfg.extra_headers = vec![("Accept".into(), "application/json".into())];
            tokio_block_on(run_device_flow(&http, &cfg, print_device_instructions))
                .map_err(|e| CliError::Io(e.to_string()))?
        }
        Some(DeviceKind::Kimi) => {
            let path = kimi::device_id_path(&global.data_dir);
            let device_id = kimi::ensure_device_id(&path)
                .map_err(|e| CliError::Io(format!("Kimi device id: {e}")))?;
            let mut cfg = DeviceFlowConfig::new(
                kimi::DEVICE_AUTH_URL,
                kimi::TOKEN_URL,
                kimi::CLIENT_ID,
                DeviceBodyEncoding::Form,
            );
            cfg.extra_headers = vec![
                ("Accept".into(), "application/json".into()),
                ("User-Agent".into(), kimi::USER_AGENT.into()),
                ("X-Msh-Platform".into(), kimi::PLATFORM.into()),
                ("X-Msh-Device-Id".into(), device_id),
            ];
            tokio_block_on(run_device_flow(&http, &cfg, print_device_instructions))
                .map_err(|e| CliError::Io(e.to_string()))?
        }
        Some(DeviceKind::Xai) => {
            let mut cfg = DeviceFlowConfig::new(
                xai::DEVICE_CODE_URL,
                xai::DEVICE_TOKEN_URL,
                xai::GROK_CLI_CLIENT_ID,
                DeviceBodyEncoding::Form,
            );
            cfg.scope = Some(xai::DEVICE_SCOPE.into());
            cfg.extra_headers = vec![("Accept".into(), "application/json".into())];
            tokio_block_on(run_device_flow(&http, &cfg, print_device_instructions))
                .map_err(|e| CliError::Io(e.to_string()))?
        }
        Some(DeviceKind::OpenAi) => tokio_block_on(run_openai_device_flow(
            &http,
            credentials_core::refresh_adapters::openai::CODEX_CLIENT_ID,
            print_device_instructions,
        ))
        .map_err(|e| CliError::Io(e.to_string()))?,
        None => {
            return Err(CliError::Usage(format!(
                "provider '{provider}' does not support device login"
            )))
        }
    };

    let (oauth, payload) = if matches!(wire.device, Some(DeviceKind::GithubCopilot)) {
        let github_credential = credentials_core::oauth::OAuthCredential {
            access_token: String::new(),
            refresh_token: tokens.access_token,
            expires_at_ms: None,
            token_url: github_copilot::TOKEN_URL.into(),
            client_id: Some(github_copilot::CLIENT_ID.into()),
            scopes: vec!["read:user".into()],
        };
        let exchanged = tokio_block_on(
            github_copilot::GithubCopilotAdapter::new().refresh(&github_credential, &http),
        )
        .map_err(|e| CliError::Io(e.to_string()))?;
        let oauth = credentials_core::oauth::OAuthCredential {
            access_token: exchanged.access_token.clone(),
            refresh_token: exchanged.refresh_token,
            expires_at_ms: exchanged.expires_at_ms,
            token_url: github_copilot::TOKEN_URL.into(),
            client_id: Some(github_copilot::CLIENT_ID.into()),
            scopes: vec!["read:user".into()],
        };
        let payload = oauth.access_token.clone().into_bytes();
        (oauth, payload)
    } else {
        let refresh_token = tokens.refresh_token.ok_or_else(|| {
            CliError::Io(format!("{provider} device flow returned no refresh token"))
        })?;
        let oauth = credentials_core::oauth::OAuthCredential {
            access_token: tokens.access_token.clone(),
            refresh_token,
            expires_at_ms: tokens.expires_at_ms,
            token_url: wire.token_url.to_string(),
            client_id: Some(wire.client_id.to_string()),
            scopes: wire.scopes.iter().map(|scope| scope.to_string()).collect(),
        };
        let payload = oauth.access_token.clone().into_bytes();
        (oauth, payload)
    };

    // Device-flow providers do not disclose an account identity in the response, so
    // leave RecordIdentity empty rather than making an extra account lookup.
    let record = VaultRecord::new_oauth("login", wire.adapter_name, oauth, payload);
    let replace = has_flag(args, "--replace");
    if replace {
        commit_admin(
            global,
            store_op(
                id,
                record,
                AdminAuditOp::Login,
                StoreMode::ReplaceUnconditional,
            ),
        )?;
        println!("logged in and replaced {id}");
    } else {
        let result = commit_admin(
            global,
            store_op(id, record, AdminAuditOp::Login, StoreMode::Create),
        );
        if matches!(&result, Err(CliError::Store(StoreOpError::AlreadyExists)))
            || matches!(&result, Err(CliError::RouteRefused(message)) if message.contains("already exists"))
        {
            return Err(CliError::Usage(format!(
                "'{id}' already holds a credential; use --replace or a labeled id"
            )));
        }
        result?;
        println!("logged in and stored {id}");
    }
    Ok(())
}

fn cmd_login(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    use credentials_core::oauth_login::{
        build_authorize_url, decode_jwt_claims, exchange_authorization_code,
        exchange_authorization_code_form, extract_chatgpt_account_id, generate_pkce,
        generate_state, parse_callback,
    };

    // With --provider the flow is fully flag-driven (scriptable); without it, the
    // interactive picker owns provider + id + replace selection.
    let interactive = match optional(args, "--provider") {
        Some(provider) => InteractiveChoice {
            provider,
            id_override: None,
            replace: false,
        },
        None => pick_login_interactively(global)?,
    };
    let provider = interactive.provider.clone();

    // Resolve the target credential id BEFORE routing so the dispatch can key on the
    // credential METHOD, not the bare provider name. openai/xai/google each name both
    // an OAuth login (chatgpt:openai / oauth:xai / oauth:google) and an api-key row
    // (apikey:*). Precedence: explicit --id > the interactive picker's chosen id > the
    // provider's default. Route to the api-key branch when the provider has ONLY an
    // api-key login, OR it has both AND the resolved id is explicitly an `apikey:` id.
    // (Gating purely on the id's method would send a malformed `--id zai` for an
    // api-key-only provider to the "unknown provider" path instead of the helpful
    // id-rail error.)
    let target_id = optional(args, "--id")
        .or_else(|| interactive.id_override.clone())
        .unwrap_or_else(|| default_login_id(&provider));
    let has_oauth_login =
        login_provider(&provider).is_some() || google_login::is_provider(&provider);
    let apikey_row = api_key_login::API_KEY_PROVIDERS
        .iter()
        .find(|p| p.key == provider);
    let route_api_key =
        apikey_row.is_some() && (!has_oauth_login || target_id.starts_with("apikey:"));

    if !route_api_key && google_login::is_provider(&provider) {
        return google_login::cmd_login(
            global,
            args,
            &provider,
            interactive.id_override,
            interactive.replace,
        );
    }

    if route_api_key {
        let p = apikey_row.expect("route_api_key implies an api-key row");
        let id = target_id.clone();
        if !login_id_is_valid(p.default_id, &id) {
            return Err(CliError::Usage(format!(
                "login --id must be '{d}' or '{d}:<label>' (a labeled account of the same \
                 provider, e.g. '{d}:work') — got '{id}'",
                d = p.default_id
            )));
        }

        let key = if let Some(path) = optional(args, "--payload-file") {
            let raw = std::fs::read_to_string(&path)
                .map_err(|e| CliError::Io(format!("reading {path}: {e}")))?;
            raw.trim().to_string()
        } else {
            use dialoguer::Password;
            let prompt = format!(
                "Enter API key for {} (dashboard: {})",
                p.display_name, p.dashboard_url
            );
            Password::new()
                .with_prompt(prompt)
                .interact()
                .map_err(|e| CliError::Io(format!("reading API key: {e}")))?
                .trim()
                .to_string()
        };

        println!("Validating API key...");
        let http = credentials_core::http::ReqwestTransport::new()
            .map_err(|e| CliError::Io(e.to_string()))?;
        let outcome = tokio_block_on(api_key_login::validate_key(&http, &p.validation, &key));
        match outcome {
            api_key_login::ValidationOutcome::Valid => {
                println!("API key is valid.");
            }
            api_key_login::ValidationOutcome::Invalid(err) => {
                return Err(CliError::Usage(format!("API key validation failed: {err}")));
            }
            api_key_login::ValidationOutcome::Warning(warn) => {
                println!("WARNING: API key validation could not be completed: {warn}. Storing the key anyway.");
            }
        }

        let record =
            VaultRecord::new_static(CredentialKind::ApiKey, "login", key.into_bytes(), None);

        let replace = has_flag(args, "--replace") || interactive.replace;
        let (audit_op, store_mode) = if replace {
            (AdminAuditOp::Overwrite, StoreMode::ReplaceUnconditional)
        } else {
            (AdminAuditOp::Put, StoreMode::Create)
        };

        if replace {
            commit_admin(global, store_op(&id, record, audit_op, store_mode))?;
            println!("logged in and replaced {id}");
        } else {
            let result = commit_admin(global, store_op(&id, record, audit_op, store_mode));
            let already_exists = match &result {
                Err(CliError::Store(StoreOpError::AlreadyExists)) => true,
                Err(CliError::RouteRefused(m)) => m.contains("already exists"),
                _ => false,
            };
            if already_exists {
                return Err(CliError::Usage(format!(
                    "'{id}' already holds a credential.\n\
                     To add ANOTHER account for this provider:  login --provider {p} --id {d}:<label>\n\
                     (e.g. --id {d}:work — each labeled id is an independent credential)\n\
                     To REPLACE the existing credential:        login --provider {p} --replace\n\
                     (keeps the id, its handles, and bumps record_version)",
                    p = provider,
                    d = p.default_id
                )));
            }
            result?;
            println!("logged in and stored {id}");
        }

        println!(
            "To mint a capability handle for this credential, run: ck-auth mint-handle --id {}",
            id
        );
        return Ok(());
    }

    // The proprietary browser-poll / callback flows (Cursor, Devin, Snowflake,
    // DigitalOcean) run their own driver, which returns None for any other provider.
    if let Some(special) = provider_login::run(
        &provider,
        args,
        interactive.id_override.as_deref(),
        interactive.replace,
    )
    .map_err(CliError::Io)?
    {
        let mode = if special.replace {
            StoreMode::ReplaceUnconditional
        } else {
            StoreMode::Create
        };
        commit_admin(
            global,
            store_op(&special.id, special.record, AdminAuditOp::Login, mode),
        )?;
        println!("logged in and stored {}", special.id);
        return Ok(());
    }

    // Each provider's auth-code wire gets its own grounded research before it is
    // added to login_provider().
    let Some(wire) = login_provider(&provider) else {
        return Err(CliError::Usage(format!(
            "unknown --provider '{provider}'; run `ck auth login` with no flags \
             to pick from the full provider list"
        )));
    };
    // The method-resolved target id (same precedence as the api-key branch).
    let id = target_id;
    // Multi-account rail: --id must be the provider's default id or a labeled
    // sub-account of it (`<default_id>:<label>`). A free-form id here would silently
    // create a mis-keyed credential (wrong method segment ⇒ wrong adapter routing,
    // ugly inventory) — the exact footgun this validation exists to close.
    if !login_id_is_valid(wire.default_id, &id) {
        return Err(CliError::Usage(format!(
            "login --id must be '{d}' or '{d}:<label>' (a labeled account of the same \
             provider, e.g. '{d}:work') — got '{id}'",
            d = wire.default_id
        )));
    }

    let requested_device = has_flag(args, "--device");
    if requested_device && wire.device.is_none() {
        return Err(CliError::Usage(format!(
            "provider '{provider}' has no device login; omit --device"
        )));
    }
    if requested_device
        || matches!(
            wire.device,
            Some(DeviceKind::GithubCopilot | DeviceKind::Kimi)
        )
    {
        return cmd_device_login(global, args, &provider, &id, &wire);
    }

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

    // Every login provider registers a loopback redirect, so bind a one-shot
    // CLI-local listener on the EXACT redirect address BEFORE opening the browser
    // (the redirect can't race an unbound socket). `--no-listener` forces the paste
    // path. The listener is a pure convenience over paste; the daemon never listens.
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
            println!("Approve in the browser — the login completes here automatically.");
            println!(
                "(The provider's page may show a code or tell you to paste something: \
                 IGNORE that, it is the no-listener fallback. Paste only if this \
                 command asks you to.)"
            );
            let got = l.wait();
            if got.is_some() {
                // Say the capture happened, so the operator is never left matching
                // the browser's "paste this code" instruction against a CLI that
                // (correctly) shows no paste prompt.
                println!("Browser redirect received — completing the login, nothing to paste.");
            }
            got
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

    // Capture NON-secret account identity while we have the login artifacts in hand:
    // Anthropic inlines account/organization blocks in the exchange response (its
    // access tokens are opaque, so login is the only capture point); OIDC providers
    // carry email in id_token claims. Stored on the record as display/routing
    // metadata (ck-quota's per-account usage labels), never used for authorization.
    let identity = credentials_core::record::RecordIdentity {
        account_id: tokens
            .account
            .as_ref()
            .and_then(|a| a.uuid.clone())
            .or_else(|| extract_chatgpt_account_id(&tokens)),
        email: tokens
            .account
            .as_ref()
            .and_then(|a| a.email_address.clone())
            .or_else(|| {
                tokens.id_token.as_deref().and_then(|t| {
                    decode_jwt_claims(t)?
                        .get("email")?
                        .as_str()
                        .map(str::to_string)
                })
            }),
        org_name: tokens.organization.as_ref().and_then(|o| o.name.clone()),
    };
    if let Some(email) = identity.email.as_deref() {
        match identity.org_name.as_deref() {
            Some(org) => println!("account: {email} · {org}"),
            None => println!("account: {email}"),
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
    let record =
        VaultRecord::new_oauth("login", wire.adapter_name, oauth, payload).with_identity(identity);

    // Login records a distinct `Login` audit op (not `Import`) so forensics can tell
    // a native mint from a foreign import. `--replace` overwrites an existing id (the
    // dual-custody migration: swap the imported token for the vault-minted one; the
    // handle survives). With `--subc` the commit rides the RUNNING module, so a
    // re-login needs no daemon stop at all (the zero-downtime path).
    if has_flag(args, "--replace") || interactive.replace {
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
        let result = commit_admin(
            global,
            store_op(&id, record, AdminAuditOp::Login, StoreMode::Create),
        );
        // The create-only refusal must not be a dead end: name both ways forward
        // (another account under a label, or swapping this credential). The route
        // path surfaces the same refusal as a RouteRefused string, so match both.
        let already_exists = match &result {
            Err(CliError::Store(StoreOpError::AlreadyExists)) => true,
            // The route path's refusal string for StoreOpError::AlreadyExists
            // (admin_surface::store_err).
            Err(CliError::RouteRefused(m)) => m.contains("already exists"),
            _ => false,
        };
        if already_exists {
            return Err(CliError::Usage(format!(
                "'{id}' already holds a credential.\n\
                 To add ANOTHER account for this provider:  login --provider {p} --id {d}:<label>\n\
                 (e.g. --id {d}:work — each labeled id is an independent credential)\n\
                 To REPLACE the existing credential:        login --provider {p} --replace\n\
                 (keeps the id, its handles, and bumps record_version)",
                p = provider,
                d = wire.default_id
            )));
        }
        result?;
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
        // Resolve the same way `login` does (OAuth/subscription wins for openai/
        // xai/google, which each also have an api-key row): `logout --provider openai`
        // targets the ChatGPT subscription credential, and the api-key one is reached
        // with `logout --id apikey:openai`. A provider with no known login is rejected.
        (None, Some(provider)) => {
            let id = default_login_id(&provider);
            if id == provider {
                return Err(CliError::Usage(format!(
                    "unknown login provider '{provider}'; pass --id <id> for other credentials"
                )));
            }
            id
        }
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
    // Absent on a daemon older than the field: treat that as "changed", which keeps
    // the pre-existing message rather than claiming a no-op we cannot observe.
    let state_changed = result["state_changed"].as_bool().unwrap_or(true);
    let intent_cleared = result["intent_cleared"].as_bool().unwrap_or(false);

    if state_changed || intent_cleared || revoked > 0 {
        println!("logged out {id}: stopped serving, revoked {revoked} handle(s)");
        println!("(reversible: `login --provider <p> --replace` restores it; the record and audit chain are kept)");
    } else {
        // SAY THAT NOTHING CHANGED, and name the verb that does what the operator is
        // probably after. Reporting plain success here is what makes logout read as
        // broken: the credential was already dead, the listing is identical
        // afterwards, and running it again produces the same success. Observed live
        // -- three consecutive logouts, three identical successes, no change.
        println!("{id} was already logged out: nothing changed");
        println!("  state was already needs_reauth and no live handles remained.");
        println!("  it stays listed because logout is REVERSIBLE and keeps the record;");
        println!("  to delete it for good: `ck auth remove --id {id}`");
    }
    Ok(())
}

/// `remove` = PERMANENTLY delete a credential row (+ its intent and handle rows) in
/// one audited fenced transaction. The audit chain keeps the full history — removal
/// deletes serving state, never forensics. The permanent sibling of `logout`: use it
/// to retire an account or clean up a mistakenly created id. Takes `--id` only (no
/// `--provider` shorthand: a permanent delete should name its exact target).
fn cmd_remove(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    let id = required(args, "--id")?;
    let result = commit_admin(
        global,
        AdminOpBody::Remove {
            v: ADMIN_OP_SCHEMA_V1,
            id: id.clone(),
        },
    )?;
    // Absent on a daemon older than the field: print the old line rather than
    // claiming a count we did not get.
    let handles = result["handles_deleted"].as_u64();
    match handles {
        Some(n) => println!(
            "removed {id}: row, refresh intent, and {n} handle(s) deleted (audit history kept)"
        ),
        None => {
            println!("removed {id}: row, refresh intent, and handles deleted (audit history kept)")
        }
    }
    // NAME THE CONSEQUENCE THE VAULT CANNOT ACT ON. Handles are bearer
    // capabilities: nothing records who holds one, so removal cannot notify the
    // holder and their next fetch gets a bare `not_found`. The operator is the only
    // party who knows which consumers were given one, and this is the last moment
    // that knowledge is actionable. Observed live: a removed credential left a
    // stale entry in a consumer's handle file, and that one dangling entry blinded
    // its three healthy sibling accounts until the consumer noticed independently.
    if handles.is_some_and(|n| n > 0) {
        println!("  those handle(s) no longer resolve for whoever holds them.");
        println!("  the vault cannot tell them: a handle records no holder. if you gave");
        println!("  one to a consumer, drop it from that consumer's config now.");
    }
    Ok(())
}

/// `status` = the one command for "why does the health table say degraded": the
/// no-decrypt credential inventory + the same fail-closed health ladder the live
/// probe computes. An authenticated admin READ — with --subc it reads the RUNNING
/// module (master-key challenge-response, works exactly when the probe shows
/// degraded); offline it takes the lease like `list`.
fn request_admin_status(global: &GlobalArgs) -> Result<serde_json::Value, CliError> {
    commit_admin(
        global,
        AdminOpBody::Status {
            v: ADMIN_OP_SCHEMA_V1,
        },
    )
}

fn parse_inventory(result: &serde_json::Value) -> Result<Vec<(String, u64, String)>, CliError> {
    let rows = result
        .get("credentials")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            CliError::RouteRefused("admin.status omitted credential inventory".into())
        })?;
    rows.iter()
        .enumerate()
        .map(|(index, row)| {
            let state = row
                .get("state")
                .and_then(serde_json::Value::as_str)
                .filter(|state| matches!(*state, "active" | "needs_reauth" | "corrupt"))
                .ok_or_else(|| {
                    CliError::RouteRefused(format!(
                        "admin.status returned an invalid state at credential row {index}"
                    ))
                })?;
            let version = row
                .get("record_version")
                .and_then(serde_json::Value::as_u64)
                .filter(|version| *version > 0)
                .ok_or_else(|| {
                    CliError::RouteRefused(format!(
                        "admin.status returned an invalid version at credential row {index}"
                    ))
                })?;
            let id = row
                .get("id")
                .and_then(serde_json::Value::as_str)
                .filter(|id| !id.is_empty())
                .ok_or_else(|| {
                    CliError::RouteRefused(format!(
                        "admin.status returned an invalid id at credential row {index}"
                    ))
                })?;
            Ok((state.to_string(), version, id.to_string()))
        })
        .collect()
}

fn print_inventory(rows: &[(String, u64, String)]) {
    for (state, version, id) in rows {
        println!("{state:<14} v{version:<4} {id}");
    }
}

fn cmd_status(global: &GlobalArgs) -> Result<(), CliError> {
    let result = request_admin_status(global)?;
    let inventory = parse_inventory(&result)?;

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
    print_inventory(&inventory);
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
    let mut store = open_for_admin(global, false)?;
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
    // Lease-free, like `verify-audit` and `events`: the audit_log columns are all
    // plaintext, so this needs neither the lease nor a master key. It used to take the
    // lease, which meant the forensic log was unreadable while the vault ran -- i.e.
    // whenever anyone actually wanted it.
    let db = global.data_dir.join("store.db");
    if !db.exists() {
        return Err(CliError::Usage(format!(
            "no vault at {} (run 'ck auth bootstrap' first)",
            global.data_dir.display()
        )));
    }
    let entries =
        credentials_core::store::read_audit_read_only(&db, limit).map_err(CliError::Store)?;
    for e in entries {
        // PRINT THE REASON, NOT A BARE "ALARM".
        //
        // The alarm column is set on every admin write by design, so admin activity is
        // loud -- 169 of the 172 flagged rows in this vault are ordinary mints and
        // revokes, and 3 are the real detection signal (fetch_rate_anomaly). Rendering
        // both as the same word makes the routine 98% look like faults and buries the
        // one thing an operator scans for. The reason already distinguishes them; the
        // renderer was discarding it.
        let alarm = match (e.alarm, e.alarm_reason.as_deref()) {
            (true, Some(reason)) => format!(" [{reason}]"),
            // Flagged with no reason recorded: say so rather than printing nothing,
            // because a silent flag is indistinguishable from an unflagged row.
            (true, None) => " [alarm: reason not recorded]".to_string(),
            (false, _) => String::new(),
        };
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

/// Print recent authentication events.
///
/// Deliberately does NOT go through `open_for_admin`, which takes the single-writer
/// lease and therefore requires the daemon stopped. These rows exist to explain a
/// credential that just stopped working, and the moment an operator wants them is the
/// moment the vault is running -- a diagnostic that requires an outage to read would
/// be useless exactly when it is needed.
///
/// Every column is plaintext (no envelope, no master key), so a read-only connection
/// is sufficient and takes nothing the daemon holds.
fn cmd_events(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    let limit: u32 = optional(args, "--limit")
        .map(|s| s.parse::<u32>())
        .transpose()
        .map_err(|e| CliError::Usage(format!("--limit not an integer: {e}")))?
        .unwrap_or(20);

    let db = global.data_dir.join("store.db");
    if !db.exists() {
        return Err(CliError::Usage(format!(
            "no vault at {} (run 'ck auth bootstrap' first)",
            global.data_dir.display()
        )));
    }

    let events = match credentials_core::store::read_auth_events_read_only(&db, limit) {
        Ok(events) => events,
        // The table is absent, not empty: this store predates the migration that adds
        // it. Distinguished because "no events" would claim nothing has gone wrong,
        // when in fact nothing CAN be recorded until the daemon restarts and migrates.
        Err(credentials_core::store::StoreOpError::NotFound) => {
            println!("this vault has no authentication-event table yet");
            println!("  (it arrives with a schema migration the daemon applies on restart;");
            println!("   until then no events can be recorded, which is not the same as none)");
            return Ok(());
        }
        Err(e) => return Err(CliError::Store(e)),
    };

    for e in &events {
        let when = format_ts_ms(e.ts_ms);
        let what = match (e.provider_status, e.detail.as_deref()) {
            (Some(s), Some(d)) => format!("{s} {d}"),
            (Some(s), None) => s.to_string(),
            (None, Some(d)) => d.to_string(),
            (None, None) => "-".to_string(),
        };
        let version = e
            .record_version
            .map(|v| format!("v{v}"))
            .unwrap_or_else(|| "-".into());
        println!(
            "{when}  {:34} {:16} {what:22} {version:6} applied={}",
            e.credential_id,
            e.kind,
            if e.applied { "yes" } else { "no" }
        );
    }
    // DISCLOSE THE TRIM. The per-credential cap is enforced by a silent DELETE, so a
    // reader cannot otherwise distinguish "this is everything that happened" from "this
    // is what survived" -- and those close an investigation in opposite directions.
    match credentials_core::store::auth_events_at_cap_read_only(&db) {
        Ok(ids) if !ids.is_empty() => {
            println!();
            println!(
                "note: {} credential(s) are at the {}-event retention cap, so older events",
                ids.len(),
                credentials_core::store::AUTH_EVENTS_PER_CREDENTIAL
            );
            println!("      for them have been discarded:");
            for id in &ids {
                println!("        {id}");
            }
        }
        // Absent table or a read problem is not worth failing the command over: the
        // events themselves already printed, and this is a footnote about them.
        Ok(_) | Err(_) => {}
    }

    if events.is_empty() {
        // Say what an empty table MEANS, because "nothing here" reads as either "no
        // failures" or "the recorder is broken", and those need different responses.
        println!("no authentication events recorded");
        println!("  (no consumer has reported a provider rejection and no refresh has failed");
        println!("   since this vault's store was created or last pruned)");
    }
    Ok(())
}

/// Render a millisecond timestamp as local `YYYY-MM-DD HH:MM:SS`.
///
/// Hand-rolled because the crate takes no date dependency and this is the only place
/// that needs one; the arithmetic is the civil-from-days algorithm.
fn format_ts_ms(ts_ms: i64) -> String {
    let secs = ts_ms.div_euclid(1000);
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (h, m, s) = (tod / 3600, (tod % 3600) / 60, tod % 60);

    // Civil date from a days-since-epoch count (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };
    format!("{year:04}-{month:02}-{d:02} {h:02}:{m:02}:{s:02}")
}

fn cmd_list(global: &GlobalArgs) -> Result<(), CliError> {
    // `admin.status` builds this no-decrypt inventory from plaintext metadata. Using
    // the shared admin path keeps `list --subc` available while the daemon owns the
    // lease; without a live module `commit_admin` retains the offline lease fallback.
    let result = request_admin_status(global)?;
    let rows = parse_inventory(&result)?;
    print_inventory(&rows);
    Ok(())
}

/// Report whether each credential still holds material the engine can work with.
///
/// The only command that OPENS EVERY ENVELOPE. `status` and `list` read plaintext
/// metadata, so neither can see a record that decrypts to nothing usable -- the one
/// state that needs an operator login and that no gauge can infer from the outside.
///
/// Lease-free like `events`, and for the same reason: the moment an operator asks is
/// the moment the vault is running, and a diagnostic that needs an outage to read is
/// useless exactly when it is needed. Unlike `events` this needs the master key, so it
/// resolves one WITHOUT opening an `EncryptedStore` (which would take the lease).
fn cmd_usable(global: &GlobalArgs) -> Result<(), CliError> {
    use credentials_core::usable::{self, ScanError, Usability};

    let db = global.data_dir.join("store.db");
    if !db.exists() {
        return Err(CliError::Usage(format!(
            "no vault at {} (run 'ck auth bootstrap' first)",
            global.data_dir.display()
        )));
    }
    let conn = usable::open_store_read_only(&db).map_err(|e| CliError::Io(e.to_string()))?;

    // Resolve the slot the STORE names, exactly as the daemon does. A rotation that
    // crashed after the rewrap and before the promote leaves the store sealed under
    // `next`; loading `current` would report every record unreadable on a vault that is
    // serving perfectly well.
    let cfg = resolver_config(global);
    let key = match usable::read_db_key_id_read_only(&conn) {
        Some(db_key_id) => resolver::resolve_for_db(&cfg, db_key_id),
        None => resolver::resolve(&cfg, None),
    }
    .map_err(CliError::MasterKey)?;

    let rows = match usable::scan(&conn, &key) {
        Ok(rows) => rows,
        // Bootstrapped but never written: the schema arrives with the first write, not
        // with `bootstrap`. Said plainly, because the raw sqlite error reads as a
        // corrupt store when the store is merely empty.
        Err(ScanError::NoSchema) => {
            println!("{} holds no credentials yet", global.data_dir.display());
            println!("  (the vault is bootstrapped; its schema is created by the first write)");
            return Ok(());
        }
        Err(e) => return Err(CliError::Io(e.to_string())),
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    let (mut serviceable, mut stranded, mut unreadable, mut bad_identity) = (0, 0, 0, 0);
    for row in &rows {
        let id = &row.credential_id;
        if row.unservable_identity {
            println!(
                "  {id:34} IDENTITY    email with no account_id: serves a label that \
                 resolves nothing (re-login or re-import to repair)"
            );
            bad_identity += 1;
        }
        match &row.usability {
            Usability::Unreadable { why } => {
                println!("  {id:34} UNREADABLE  {why}");
                unreadable += 1;
            }
            Usability::Stranded => {
                println!(
                    "  {id:34} oauth   {}  STRANDED: no access token and no refresh token",
                    row.state
                );
                stranded += 1;
            }
            Usability::Static => {
                println!("  {id:34} static  {}", row.state);
                serviceable += 1;
            }
            Usability::Serviceable { expires_at_ms } => {
                // Expiry is printed as context and never scored: an expired access
                // token is the routine state of a healthy credential, so counting it
                // would report normal operation as a problem.
                // "refreshes on next get" is TRUE OF THE MATERIAL AND FALSE OF THE
                // RECORD once the state is needs_reauth. EncryptedStore::get refuses at
                // the state check, before decrypting and long before the engine could
                // attempt a refresh -- so there is no next get, and the phrase invites
                // an operator to wait for a recovery that cannot arrive.
                //
                // Live instance: oauth:anthropic:ufuk3 sat needs_reauth for five hours
                // reading "refreshes on next get", while three sibling anthropic
                // accounts refreshed normally around it.
                let refresh_reachable = row.state != "needs_reauth";
                let ttl = match expires_at_ms {
                    Some(exp) => {
                        let mins = (exp - now) / 60_000;
                        if mins >= 0 {
                            format!("access good for {mins}m")
                        } else if refresh_reachable {
                            format!("access expired {}m ago, refreshes on next get", -mins)
                        } else {
                            format!(
                                "access expired {}m ago; refresh material is intact but \
                                 UNREACHABLE while the state is {} -- only a login clears it",
                                -mins, row.state
                            )
                        }
                    }
                    None => "no expiry recorded".to_string(),
                };
                println!("  {id:34} oauth   {}  {ttl}", row.state);
                serviceable += 1;
            }
        }
    }

    println!();
    println!(
        "  serviceable: {serviceable}   stranded: {stranded}   unreadable: {unreadable}   \
         unservable identity: {bad_identity}"
    );
    println!();
    println!("  Serviceable means the record decrypts under the current master key and");
    println!("  holds material the engine can either serve or refresh from. It is NOT a");
    println!("  claim that the provider will still honour it: only spending a token");
    println!("  answers that, and for rotating providers spending it invalidates the copy");
    println!("  we hold, so no dry run exists even in principle. The authoritative signal");
    println!("  for a provider-rejected credential is the `needs_reauth` state, which a");
    println!("  consumer sets via report_auth_failure and the health gauge already counts.");
    Ok(())
}

/// Verify the tamper-evidence chain, WITHOUT stopping the daemon.
///
/// This used to go through `open_for_admin`, which takes the single-writer lease and
/// therefore required the vault offline. That made it unrunnable in practice: nobody
/// takes the credential vault down to run an integrity check, so the check that
/// justifies the whole HMAC chain had never once run against the live store. A
/// tamper-evidence mechanism nobody can afford to invoke provides evidence of nothing.
///
/// The verification is a pure read -- fetch the entries, recompute each MAC over its
/// predecessor -- and needs the master key only to unseal the stored audit key. So it
/// resolves the key the way the daemon does (matching the slot the store's own
/// fingerprint names, so a vault left mid-rotation still verifies) and reads through a
/// lease-free connection, exactly like `events` and `usable`.
fn cmd_verify_audit(global: &GlobalArgs) -> Result<(), CliError> {
    let db = global.data_dir.join("store.db");
    if !db.exists() {
        return Err(CliError::Usage(format!(
            "no vault at {} (run 'ck auth bootstrap' first)",
            global.data_dir.display()
        )));
    }

    let conn = credentials_core::usable::open_store_read_only(&db)
        .map_err(|e| CliError::Io(e.to_string()))?;
    let cfg = resolver_config(global);
    let key = match credentials_core::usable::read_db_key_id_read_only(&conn) {
        Some(db_key_id) => resolver::resolve_for_db(&cfg, db_key_id),
        None => resolver::resolve(&cfg, None),
    }
    .map_err(CliError::MasterKey)?;
    drop(conn);

    match credentials_core::store::verify_audit_chain_read_only(&db, &key) {
        Ok(None) => {
            println!("audit chain verified: intact");
            Ok(())
        }
        Ok(Some(seq)) => Err(CliError::Io(format!(
            "audit chain BROKEN at seq {seq} (tamper detected)"
        ))),
        // An absent audit key is not an empty chain. Reporting "intact" for a store
        // whose key cannot be found would be the exact false green the chain exists to
        // prevent.
        Err(credentials_core::store::StoreOpError::NotFound) => Err(CliError::Io(
            "this vault has no audit key, so the chain cannot be verified \
             (it predates the sealed-audit-key scheme, or the row was removed)"
                .to_string(),
        )),
        Err(e) => Err(CliError::Store(e)),
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
    fn a_global_flag_before_the_verb_lands_where_one_after_it_would() {
        // The verb is positional and read before the flags, so a leading global flag
        // would otherwise BE the verb. Both orders are documented and a caller cannot
        // see that the parser is positional.
        let mut leading: Vec<String> = ["--data-dir", "/tmp/v", "list"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        hoist_leading_global_flags(&mut leading);
        assert_eq!(leading, vec!["list", "--data-dir", "/tmp/v"]);

        // Two of them, and each flag must stay next to its own value.
        let mut two: Vec<String> = ["--data-dir", "/tmp/v", "--key-path", "/tmp/k", "status"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        hoist_leading_global_flags(&mut two);
        assert_eq!(
            two,
            vec!["status", "--data-dir", "/tmp/v", "--key-path", "/tmp/k"]
        );

        // A flag already after the verb is untouched: the hoist must not reorder an
        // invocation that already worked.
        let mut trailing: Vec<String> = ["list", "--data-dir", "/tmp/v"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let before = trailing.clone();
        hoist_leading_global_flags(&mut trailing);
        assert_eq!(trailing, before);

        // A flag with no value is left in place so the normal parser reports it,
        // rather than this function consuming the arg and producing a stranger error.
        let mut valueless: Vec<String> = vec!["--data-dir".to_string()];
        hoist_leading_global_flags(&mut valueless);
        assert_eq!(valueless, vec!["--data-dir"]);
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
        assert!(reject_unknown_args("login", &v(&["--provider", "xai", "--device"])).is_ok());
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

    /// The multi-account rail: a login id is the provider default or one labeled
    /// sub-account — any free-form id (e.g. a bare account name) would create a
    /// mis-keyed credential, so it is refused before any browser or network work.
    #[test]
    fn login_id_validation_accepts_default_and_labels_only() {
        // The default id and labeled accounts pass.
        assert!(login_id_is_valid("oauth:anthropic", "oauth:anthropic"));
        assert!(login_id_is_valid("oauth:anthropic", "oauth:anthropic:work"));
        assert!(login_id_is_valid("chatgpt:openai", "chatgpt:openai:gmail"));
        assert!(login_id_is_valid("copilot:github", "copilot:github:work"));
        assert!(login_id_is_valid("oauth:kimi", "oauth:kimi:personal"));
        // Free-form ids are refused (a bare label is not a credential id).
        assert!(!login_id_is_valid("oauth:anthropic", "wwaxpoetic"));
        assert!(!login_id_is_valid("oauth:anthropic", "oauth:xai"));
        // Empty or nested labels are refused.
        assert!(!login_id_is_valid("oauth:anthropic", "oauth:anthropic:"));
        assert!(!login_id_is_valid("oauth:anthropic", "oauth:anthropic:a:b"));
        // A prefix without the separator is refused (not a label).
        assert!(!login_id_is_valid("oauth:anthropic", "oauth:anthropicx"));
    }

    #[test]
    fn google_login_provider_rows_pin_ids_redirects_and_fallback_ports() {
        let gemini = login_provider("google").expect("Gemini CLI row");
        assert_eq!(gemini.default_id, "oauth:google");
        assert_eq!(gemini.redirect_uri, "http://127.0.0.1:8085/oauth2callback");
        assert!(gemini.paste_prompt.contains("8085"));
        assert_eq!(gemini.scopes, credentials_core::google_login::SCOPES);

        let antigravity = login_provider("antigravity").expect("Antigravity row");
        assert_eq!(antigravity.default_id, "antigravity:google");
        assert_eq!(antigravity.redirect_uri, "http://127.0.0.1:51121/callback");
        assert!(antigravity.paste_prompt.contains("51121"));
        assert!(LOGIN_PICKER_ROWS.contains(&("google", "Google Gemini CLI (Code Assist)")));
        assert!(LOGIN_PICKER_ROWS.contains(&("antigravity", "Antigravity (Gemini 3)")));
    }

    /// `remove` takes --id and is registered in the arg-rejection table (a typo'd
    /// flag cannot silently target the wrong credential for a PERMANENT delete).
    #[test]
    fn remove_flags_are_validated() {
        assert!(reject_unknown_args("remove", &v(&["--id", "oauth:anthropic:old"])).is_ok());
        assert!(reject_unknown_args("remove", &v(&["--provider", "anthropic"])).is_err());
    }

    #[test]
    fn test_api_key_registration_and_id_rail() {
        // apikey:zai:work passes the id rail for zai (default_id = apikey:zai)
        assert!(login_id_is_valid("apikey:zai", "apikey:zai:work"));
        // --id zai fails it
        assert!(!login_id_is_valid("apikey:zai", "zai"));

        // Check that zai is in API_KEY_PROVIDERS
        let zai_provider = api_key_login::API_KEY_PROVIDERS
            .iter()
            .find(|p| p.key == "zai");
        assert!(zai_provider.is_some());
        let zai = zai_provider.unwrap();
        assert_eq!(zai.default_id, "apikey:zai");
    }

    #[test]
    fn inventory_parser_accepts_exact_rows_and_rejects_malformed_status() {
        let valid = serde_json::json!({
            "credentials": [
                {"id": "apikey:test", "state": "active", "record_version": 7}
            ]
        });
        assert_eq!(
            parse_inventory(&valid).expect("valid inventory"),
            vec![("active".to_string(), 7, "apikey:test".to_string())]
        );

        for malformed in [
            serde_json::json!({}),
            serde_json::json!({"credentials": [{"id": "apikey:test", "state": "unknown", "record_version": 7}]}),
            serde_json::json!({"credentials": [{"id": "apikey:test", "state": "active", "record_version": 0}]}),
            serde_json::json!({"credentials": [{"id": "", "state": "active", "record_version": 7}]}),
        ] {
            assert!(
                parse_inventory(&malformed).is_err(),
                "malformed admin status must fail closed: {malformed}"
            );
        }
    }

    #[test]
    fn collision_provider_names_default_to_the_oauth_login() {
        // openai / xai / google each name BOTH an OAuth login and an api-key row.
        // A bare `--provider <name>` login must resolve to the OAuth/subscription
        // credential (the "login" semantic), NOT the api-key row — the regression
        // that shadowed the ChatGPT login behind apikey:openai.
        assert_eq!(default_login_id("openai"), "chatgpt:openai");
        assert_eq!(default_login_id("xai"), "oauth:xai");
        assert_eq!(default_login_id("google"), "oauth:google");
        assert_eq!(default_login_id("antigravity"), "antigravity:google");
        // api-key-only providers resolve to their apikey: id.
        assert_eq!(default_login_id("zai"), "apikey:zai");
        assert_eq!(default_login_id("openrouter"), "apikey:openrouter");
        // The routing discriminator: the OAuth defaults are NOT api-key ids, so the
        // dispatch sends them to the OAuth path; the api-key-only ones ARE.
        assert!(!default_login_id("openai").starts_with("apikey:"));
        assert!(!default_login_id("xai").starts_with("apikey:"));
        assert!(default_login_id("zai").starts_with("apikey:"));
        // An unknown provider returns itself unchanged (so the dispatch surfaces the
        // proper "unknown provider" error rather than mis-routing).
        assert_eq!(
            default_login_id("nope-not-a-provider"),
            "nope-not-a-provider"
        );
    }
}
