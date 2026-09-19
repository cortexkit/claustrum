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
//! consumer (transport key only, no master key, no lease) cannot reach these writes;
//! secret reads remain capability-gated on the consumer route.
//!
//! Every write goes through the epoch-fenced path and appends an audit-chain entry
//! (flagged as an admin write) atomically with the mutation. Bootstrap (first run)
//! mints a CSPRNG master key into the configured store.
//!
//! Commands:
//!   bootstrap                                  provision a new master key
//!   put       --id <id> --payload <bytes> [--kind api_key|dsn|opaque] [--expires-ms N] [--replace]
//!             cookie:<domain> records are always `CredentialKind::Cookie`, preserve
//!             `--payload-file` bytes exactly, and do not accept `--expires-ms`.
//!   mint-signing-key --id signing:<provider>[:<generation>] [--replace]
//!   import    --source opencode|pi|antigravity --id <id> --json <file>
//!   set-identity <id> --account-id <id> [--email <email>] [--org-name <name>] | --clear
//!   migrate-opencode [--dry-run] [--replace] [--force-shape] [--restore <provider>]
//!   invalidate --id <id>
//!   rotate-master-key
//!   mint-handle --id <id>                      print a fresh handle (once)
//!   revoke-handle --handle <ckh_...> | --hash <hex>
//!   revoke-all-handles --id <id>
//!   grant --principal <module-id> --prefix <credential-prefix> --operation <read|sign>
//!   revoke-grant --principal <module-id> --prefix <credential-prefix> --operation <read|sign>
//!   grants
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
#[allow(dead_code)]
mod cli_support;
#[allow(dead_code)]
#[path = "cli_support/credential_client.rs"]
mod credential_client;
#[path = "cli_support/google_login.rs"]
mod google_login;
#[path = "cli_support/import_picker.rs"]
mod import_picker;
#[path = "cli_support/login_listener.rs"]
mod login_listener;
#[path = "cli_support/login_wire.rs"]
mod login_wire;
#[path = "cli_support/opencode_accounts.rs"]
mod opencode_accounts;
#[allow(dead_code)]
#[path = "cli_support/opencode_files.rs"]
mod opencode_files;
#[path = "cli_support/opencode_migration.rs"]
mod opencode_migration;
#[path = "cli_support/provider_login.rs"]
mod provider_login;
#[path = "cli_support/route_client.rs"]
mod route_client;

use base64::Engine;
use cortexkit_store::{open_sqlite, Isolation, StorageBackend, StorageDescriptor, StoreError};
use credentials_core::admin_ops::{
    AdminAuditOp, AdminOpBody, StoreMode, ADMIN_OP_SCHEMA_V1, ADMIN_OP_SCHEMA_V2,
};
use credentials_core::catalog::{login_provider, DeviceKind, ExchangeWire, LoginProvider};
use credentials_core::contract::{MODULE_ID, STORAGE_NAMESPACE};
use credentials_core::credential_id::{default_refresh_adapter, parse_credential_id, AuthMethod};
use credentials_core::key::MasterKey;
use credentials_core::record::{CredentialKind, RecordIdentity, VaultRecord};
use credentials_core::resolver::{self, KeySource, MasterKeyError, ResolverConfig};
use credentials_core::store::{
    EncryptedStore, GrantOperation, SelectorKind, SetCategoryMode, StoreOpError,
};
use ring::rand::SystemRandom;
use ring::signature::Ed25519KeyPair;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            // RESTATE A USAGE REFUSAL AFTER THE HELP PAGE, because the help page is
            // longer than the refusal and buries it.
            //
            // A usage error prints `error: <what was wrong>` and then the verb's whole
            // help text, so the LAST thing on screen is a global-flags footer that looks
            // like ordinary help output. Transcripts are routinely captured with `tail`,
            // and a reader seeing only the tail cannot tell a refusal from a successful
            // run followed by a hint.
            //
            // Measured 2026-08-25: the supervisor seat ran two wrong flag shapes during a
            // deploy probe (`logout <id>` positionally, and `remove --id <id> --yes` with
            // a flag that does not exist). Both correctly exited 1 with the error on
            // stderr and nothing on stdout -- the CLI fails closed and that part is
            // right. What caught them was asserting on the EFFECT (list state, serving
            // count) rather than the command output, and they said plainly they could not
            // tell from their transcript whether the commands had run.
            //
            // So the exit code was always honest and the rendering was not. One line at
            // the end costs nothing and makes a tailed transcript self-describing.
            // ONLY WHEN SOMETHING CAME BETWEEN, measured 2026-09-17. The restatement was
            // unconditional, so a one-line refusal printed the same sentence twice with a
            // blank line between:
            //
            //     error: --id is required
            //
            //     error: --id is required — nothing ran, nothing changed.
            //
            // The reasoning above is about a refusal BURIED by a help page. When the error
            // body is a single line there is nothing to bury it, the reader has the first
            // line in view, and the echo reads as a second, different failure. Every verb
            // with a required flag renders this way, so the noise is the common case and
            // the case the restatement was written for is the rare one.
            if let CliError::Usage(m) = &e {
                let mut lines = m.lines();
                let first = lines.next().unwrap_or("invalid usage");
                if lines.next().is_some() {
                    eprintln!("\nerror: {first} — nothing ran, nothing changed.");
                }
            }
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
    /// THIS CLIENT could not prepare the op: nothing was dispatched, and the module
    /// was never asked. Terminal for the same reason as `RouteRefused` (the offline
    /// path needs the same master key), but the operator's next move is local.
    LocalFailure(String),
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
            CliError::MasterKey(MasterKeyError::NotBootstrapped) => write!(
                f,
                "master key: no master key has been provisioned; run `ck auth bootstrap`, or \
                 verify --key-path points to an existing operator key file"
            ),
            CliError::MasterKey(e) => write!(f, "master key: {e}"),
            CliError::Store(e) => write!(f, "{e}"),
            CliError::StoreOpen(e) => write!(f, "{e}"),
            CliError::Io(m) => write!(f, "{m}"),
            CliError::RouteRefused(m) => write!(f, "the running module refused the op: {m}"),
            // NAMES THIS SIDE, because the operator's next move depends on which machine
            // is at fault and the old wording sent them to the wrong one. Nothing was
            // dispatched, so there is no module state to inspect and no wire error to
            // look up -- the fix is here.
            CliError::LocalFailure(m) => write!(
                f,
                "could not prepare the op on this side (nothing was sent): {m}"
            ),
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
    // THE `ck` DISPATCHER'S OPT-IN PROBE. Until this answers, `ck auth …` refuses as
    // "not a command" and this binary is absent from `ck --help`.
    //
    // The dispatcher used to exec ANY `ck-*` on PATH, which broke once `ck setup` began
    // placing module programs into the same directory: `ck aft` exec'd the AFT module
    // itself, which started in stdio mode and waited on a pipe. Opting in is the right
    // shape — a binary that happens to be named `ck-something` is not thereby a command.
    //
    // CONTRACT, and every clause is load-bearing because the dispatcher enforces it:
    // exit 0, within 2 seconds, EXACTLY ONE non-empty line on stdout. Answered here as
    // the very first thing `run` does, before argument parsing, config or any file
    // touch, so the deadline cannot be missed on a slow or misconfigured host — a
    // headline that needed the vault to be readable would fail the probe on exactly the
    // machines where an operator most needs `ck auth` to exist.
    if args.as_slice() == ["--ck-domain"] {
        println!("provider-credential vault: login, list, put, grants");
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
        "mint-signing-key" => cmd_mint_signing_key(&global, &args),
        "import" => cmd_import(&global, &args),
        "set-identity" => cmd_set_identity(&global, &args),
        "set-category" => cmd_set_category(&global, &args),
        "reclassify" => cmd_reclassify(&global, &args),
        "migrate-opencode" => opencode_migration::cmd_migrate_opencode(&global, &args),
        "opencode-account" => opencode_accounts::cmd_opencode_account(&global, &args),
        "login" => cmd_login(&global, &args),
        "invalidate" => cmd_invalidate(&global, &args),
        "reactivate" => cmd_reactivate(&global, &args),
        "logout" => cmd_logout(&global, &args),
        "remove" => cmd_remove(&global, &args),
        "status" => cmd_status(&global),
        "rotate-master-key" => cmd_rotate_master_key(&global),
        "mint-handle" => cmd_mint_handle(&global, &args),
        "revoke-handle" => cmd_revoke_handle(&global, &args),
        "revoke-all-handles" => cmd_revoke_all_handles(&global, &args),
        "grant" => cmd_grant(&global, &args),
        "revoke-grant" => cmd_revoke_grant(&global, &args),
        "approve" => cmd_approve(&global, &args),
        "list" => cmd_list(&global),
        "grants" => cmd_grants(&global),
        "categories" => cmd_categories(&global),
        "enroll" => cmd_enroll(&global, &args),
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
            // github_app deposits only: the App JWT issuer. A flag handled in cmd_put
            // but missing HERE is rejected before cmd_put ever runs, so this list and
            // that handler have to move together.
            "--client-id",
        ],
        "mint-signing-key" => &["--id"],
        "import" => &[
            "--source",
            "--provider",
            "--id",
            "--json",
            "--adapter",
            "--account-id",
            "--email",
            "--org-name",
        ],
        "set-identity" => &["--account-id", "--email", "--org-name"],
        "set-category" => &["--set", "--add", "--remove"],
        "migrate-opencode" => &[
            "--restore",
            "--auth-file",
            "--handle-file",
            "--provider",
            "--serve-by",
        ],
        "opencode-account" => &[
            "--provider",
            "--label",
            "--key-file",
            "--before",
            "--handle-file",
        ],
        "login" => &["--provider", "--id", "--payload-file", "--account"],
        "invalidate" | "reactivate" | "mint-handle" | "revoke-all-handles" | "remove" => &["--id"],
        "logout" => &["--provider", "--id"],
        "revoke-handle" => &["--handle", "--hash"],
        "enroll" => &["--request-id", "--name"],
        "approve" => &["--id", "--file", "--approver"],
        // `--prefix` stays in this table DELIBERATELY although it is refused. Removing it
        // would make an operator who types the old flag hit the generic
        // unknown-argument error, which says nothing about what replaced it. Listed
        // here, it reaches `parse_grant_selector`'s refusal, which names the successor
        // and explains why a former prefix is a category rather than an exact selector.
        "grant" | "revoke-grant" => &[
            "--principal",
            "--prefix",
            "--selector-kind",
            "--selector",
            "--operation",
        ],
        "audit" => &["--limit"],
        "events" => &["--limit"],
        // bootstrap / rotate-master-key / verify-audit take no per-command flags.
        _ => &[],
    };
    // Boolean (valueless) flags accepted per command.
    let bool_flags: &[&str] = match command {
        "put" => &["--replace"],
        "mint-signing-key" => &["--replace"],
        "import" => &["--replace", "--clear-identity"],
        "set-identity" => &["--clear"],
        "reclassify" => &["--from-registry", "--force"],
        "login" => &["--replace", "--no-listener", "--no-browser", "--device"],
        "migrate-opencode" => &["--dry-run", "--replace", "--force-shape"],
        _ => &[],
    };
    let mut i = if matches!(command, "set-identity" | "set-category")
        && args.first().is_some_and(|arg| !arg.starts_with("--"))
    {
        1
    } else {
        0
    };
    while i < args.len() {
        let arg = &args[i];
        // VERBS WITH POSITIONAL SUBCOMMANDS must name them here, or this check eats the
        // subcommand before dispatch and the verb is unusable.
        //
        // `enroll` shipped that way and the whole suite stayed green: every help and
        // flag test drives FLAGS, and no test invoked `ck auth enroll list`. It failed
        // on the live daemon at the first probe, during a migration window, which is the
        // most expensive place to find it. A table rather than a second `command ==`
        // chain because there are two now and the next one should only have to add a row.
        let subcommands: &[&str] = match command {
            "opencode-account" => &["add", "remove", "list"],
            "enroll" => &["list", "approve", "deny", "revoke", "reissue"],
            _ => &[],
        };
        if subcommands.contains(&arg.as_str()) {
            i += 1;
            continue;
        }
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
       grants              principal-scoped grants (no secrets)\n\
       enroll              admit, revoke or reissue a consumer enrollment\n\
       categories          which categories exist and what they cover\n\
       approve             record a master-key approval before a signing window\n\
         put                 ingest an api key, session cookie, or opaque secret\n\
         mint-signing-key    generate and custody a new Ed25519 signing key\n\
         import              import from opencode/pi/gemini-cli/antigravity\n\
         set-identity        attach non-secret account metadata to one credential\n\
         set-category        replace/add/remove authorization categories\n\
         reclassify          apply registry category defaults atomically\n\
         migrate-opencode    custody OpenCode api auth entries idempotently\n\
         opencode-account    add/remove/list labeled OpenCode api accounts\n\
        mint-handle         mint a capability handle for a credential\n\
        revoke-handle       revoke one capability handle\n\
        revoke-all-handles  revoke every handle for a credential\n\
        grant               grant a reserved module a prefix or category selector\n\
        revoke-grant        revoke a reserved module's prefix or category selector\n\
       invalidate          mark a credential needs-reauth\n\
       reactivate          clear needs-reauth without replacing the secret\n\
       audit               print the audit chain\n\
       events              why credentials failed to authenticate\n\
       usable              which credentials can still serve or refresh\n\
       verify-audit        verify the audit-chain integrity\n\
       rotate-master-key   rotate the vault master key (offline)\n\
       bootstrap           initialize a new vault (offline)\n\
     \n\
     GLOBAL FLAGS\n\
     \x20 --data-dir <dir>   vault location (default: <data_home>/cortexkit/claustrum)\n\
     \x20 --subc <file>      connection file; auto-discovered on a standard install\n\
     \x20 --key-path <file>  operator key file instead of the OS keychain\n\
     \x20 --version          print the build version and exit\n\
     \n\
     NOTES\n\
     On a standard install commands need no flags — the vault location and the\n\
     running daemon auto-discover. Run 'ck auth help <verb>' for flags and details.\n\
     \n\
     Global flags are rarely needed and apply to any verb. An explicit vault\n\
     directory targets THAT vault and stays offline unless a connection file is\n\
     also given. With a connection file, writes commit through the running module\n\
     (zero downtime); absent/no daemon, they take the offline single-writer lease\n\
     (daemon must be stopped). rotate-master-key and bootstrap are always offline."
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
            "ck auth login [--provider <name>] [--id <id>] [--account <id>] [--replace]\n\
             \x20             [--no-listener] [--no-browser] [--device] [--payload-file <path>]\n\
             \n\
             \x20 --provider <name>      pick a provider; omit for an interactive picker of\n\
             \x20                        every provider\n\
             \x20 --id <id>              use the provider default id or its own freely chosen\n\
             \x20                        labeled id\n\
             \x20 --account <id>         required for Snowflake (id oauth:snowflake:<account>)\n\
             \x20 --replace              swap an existing credential (keeps its handle)\n\
             \x20 --no-listener          paste the address-bar URL instead of using the loopback\n\
             \x20                        listener\n\
             \x20 --no-browser           only print the browser URL for headless or SSH sessions\n\
             \x20 --device               select headless device authorization for openai/xai\n\
             \x20 --payload-file <path>  api-key logins: read the key from a file instead of\n\
             \x20                        prompting\n\
             \n\
             NOTES\n\
             Vault-native first-party login — mints an INDEPENDENT credential the vault\n\
             solely custodies (no dual-custody rotation race).\n\
             \n\
             OAuth providers open a browser URL. A one-shot CLI-local listener on the\n\
             loopback redirect completes the flow automatically; a busy port or a timeout\n\
             falls back to pasting the address-bar URL. github-copilot and kimi always use\n\
             device authorization. api-key providers prompt for a key (validated before\n\
             storing).\n\
             \n\
             Providers: anthropic, openai, xai, google, antigravity, github-copilot, kimi,\n\
             cursor, devin, snowflake, digitalocean, plus api-key providers (zai, openrouter,\n\
             deepseek, groq, ...).\n\
             \n\
             MULTIPLE ACCOUNTS per provider — give each its own labeled id: ck auth login\n\
             --provider anthropic --id oauth:anthropic:work (label freely chosen; each\n\
             labeled id is an independent credential with its own refresh chain and handles)."
        }
        "logout" => {
            "ck auth logout --provider <p> | --id <id>\n\
             \n\
             \x20 --provider <p>  select the provider credential to stop serving\n\
             \x20 --id <id>       select an explicit credential id instead\n\
             \n\
             NOTES\n\
             Stop serving a credential REVERSIBLY: invalidate it and revoke its handles,\n\
             keeping the record and audit chain. `ck auth login --provider <p> --replace`\n\
             restores it. Never a delete — use `remove` for that."
        }
        "remove" => {
            "ck auth remove --id <id>\n\
             \n\
             \x20 --id <id>  credential to permanently delete\n\
             \n\
             NOTES\n\
             PERMANENTLY delete a credential row and revoke its handles (audited; the audit\n\
             chain keeps the history). For retiring an account or cleaning up a mistaken id.\n\
             For a temporary stop use `logout` instead."
        }
        "status" => {
            "ck auth status\n\
             \n\
             NOTES\n\
             Vault health + per-credential inventory (no secrets) — run this when the health\n\
             table says degraded. Reads the RUNNING daemon when one is up, else the offline\n\
             store."
        }
        "list" => {
            "ck auth list\n\
             \n\
             NOTES\n\
             Print each credential's id + lifecycle state + version (no secrets), e.g. to\n\
             find which credential a health probe flagged needs_reauth."
        }
        "grants" => {
            "ck auth grants\n\
             \n\
             NOTES\n\
             Print every principal-scoped grant as one stable row: principal kind, principal\n\
             id, credential prefix, operation, and creation time. Read-only; it uses the\n\
             authenticated admin.status path, reading the running daemon when available and\n\
             the offline lease path otherwise. An empty grant table prints `no grants`."
        }
        "categories" => {
            "ck auth categories\n\
             \n\
             NOTES\n\
             Print every category that exists, how many credentials carry it, and which\n\
             principals hold a grant naming it. Read-only; it takes no lease and uses the\n\
             same authenticated admin.status path as `grants`.\n\
             A category NAMED BY A GRANT but carried by no credential is listed at zero\n\
             rather than omitted: that row is why a grant reaches nothing, and hiding it\n\
             would leave the operator with a correct-looking grant and no explanation.\n\
             `(uncategorized)` counts credentials carrying no category at all. Some are\n\
             deliberate, so the count is information rather than an error."
        }
        "approve" => {
            "ck auth approve --id <signing-credential-id> --file <path> --approver <name>\n\
             \n\
             \x20 --id <id>                     signing credential the window will use\n\
             \x20 --file <path>                 artifact being approved; its sha256 is recorded\n\
             \x20 --approver <name>             who is approving, recorded in the chain\n\
             \n\
             NOTES\n\
             Record a master-key approval in the audit chain before opening a signing\n\
             window. The chain entry binds the approver, the artifact's exact sha256, and\n\
             the signing credential, so a later reader can prove WHICH bytes were approved\n\
             rather than that an approval happened.\n\
             It signs nothing. Approval and signature are separate acts on purpose: a\n\
             recorded approval that is never exercised leaves a chain entry with no\n\
             signature beside it, which is the state an auditor needs to be able to see."
        }
        "enroll" => {
            "ck auth enroll list\n\
             \x20             approve --request-id <id> [--name <name>]\n\
             \x20             deny --request-id <id>\n\
             \x20             revoke --name <name>\n\
             \x20             reissue --name <name>\n\
             \n\
             \x20 --request-id <id>             pending request, from `enroll list`\n\
             \x20 --name <name>                 consumer name to admit, revoke or reissue\n\
             \n\
             NOTES\n\
             The operator half of consumer enrollment. A consumer proposes a name over the\n\
             read plane and waits; only the master key can admit it.\n\
             approve admits a NAME and mints no token: the consumer's own poll mints it,\n\
             authenticated by the request secret it generated, so neither an operator nor a\n\
             squatter can collect a token for a name they do not hold. --name overrides the\n\
             proposed spelling, which is a stranger's claim rather than a fact.\n\
             revoke keeps the consumer's grants: they record what reach existed and they\n\
             block re-enrolling the name, so a later consumer cannot inherit that reach.\n\
             reissue prints the new token on stdout ALONE so it can be piped into a 0600\n\
             file; the previous token stops working the moment it is minted.\n\
             list is read-only and takes no lease. awaiting-poll means admitted but never\n\
             collected, which is a stalled handover rather than a live consumer."
        }
        "mint-signing-key" => {
            "ck auth mint-signing-key --id signing:<provider>[:<generation>] [--replace]\n\
             \n\
             \x20 --id <id>  signing:<provider>[:<generation>] credential to create\n\
             \x20 --replace  explicit destructive rotation of an existing id; keeps its handles\n\
             \n\
             NOTES\n\
             Generate a fresh Ed25519 key pair in this process and seal its PKCS#8 private\n\
             half directly into the vault. The private key is never written to a file, argv,\n\
             environment variable, or command output. Prints the public key hex and its\n\
             derived key_id for handoff to verifiers.\n\
             \n\
             Create-only by default: use a new generation id for normal rotation."
        }
        "put" => {
            "ck auth put --id <id> --payload <v> | --payload-file <path>\n\
             \x20           [--kind <api_key|dsn|opaque>] [--expires-ms <N>]\n\
             \x20           [--replace | --expected-hash <hex>] [--client-id <id>]\n\
             \n\
             \x20 --id <id>                    vault credential id to create or rotate\n\
             \x20 --payload <v>                secret bytes from argv, instead of a file\n\
             \x20 --payload-file <path>        keep the secret out of argv; cookie bytes are\n\
             \x20                              preserved exactly; for every other kind strip\n\
             \x20                              TRAILING whitespace (any amount: newlines, CR,\n\
             \x20                              spaces, tabs), keeping LEADING whitespace\n\
             \x20 --kind <api_key|dsn|opaque>  record kind; defaults to api_key; refused for\n\
             \x20                              cookie ids\n\
             \x20 --expires-ms <N>             expiry timestamp in milliseconds; refused for\n\
             \x20                              cookie ids\n\
             \x20 --replace                    rotate unconditionally; bumps record_version so\n\
             \x20                              consumers re-fetch, keeping handles\n\
             \x20 --expected-hash <hex>        concurrency-safe CAS overwrite\n\
             \x20 --client-id <id>             required App JWT issuer for a github_app: deposit\n\
             \n\
             NOTES\n\
             Ingest a non-OAuth secret (an api_key, dsn, or opaque blob). Create-only by\n\
             default. A cookie:<domain> id always creates a session-cookie record.\n\
             \n\
             A one-line secret file gives the same bytes as $(cat file). A value that must\n\
             END in whitespace cannot come from a file; use a cookie: id, whose bytes are\n\
             taken verbatim."
        }
        "import" => {
            "ck auth import --source <opencode|pi|gemini-cli|antigravity> --id <id>\n\
             ck auth import  pick detected accounts to import (no flags)\n\
             \x20              [--json <file>] [--provider <entry>] [--adapter <adapter>]\n\
             \x20              [--replace]\n\
             \x20              [--account-id <id>] [--email <email>] [--org-name <name>]\n\
             \x20              [--clear-identity]\n\
             \n\
             \x20 --source <source>    which harness to read\n\
             \x20 --id <id>            vault credential id to create\n\
             \x20 --json <file>        read that file instead of the source's default path\n\
             \x20 --provider <entry>   opencode/pi: pick one auth.json entry; antigravity: pick\n\
             \x20                      an account by email or index; not used for gemini-cli\n\
             \x20 --adapter <adapter>  override the refresh adapter the method implies\n\
             \x20 --replace            overwrite an existing id, keeping its handles; keeps\n\
             \x20                      prior identity only when the incoming token belongs to\n\
             \x20                      the same account\n\
             \x20 --account-id <id>    attach non-secret account metadata; required with email\n\
             \x20                      or org-name\n\
             \x20 --email <email>      account email metadata\n\
             \x20 --org-name <name>    account organization metadata\n\
             \x20 --clear-identity     remove non-secret account metadata\n\
             \n\
             SOURCES\n\
             \x20 opencode, pi    auth.json. An apikey:<p> id imports a {type:api,key}\n\
             \x20                 entry as a static key; an oauth id imports tokens.\n\
             \x20 gemini-cli      ~/.gemini/oauth_creds.json, one credential\n\
             \x20 antigravity     antigravity-accounts.json, defaults to activeIndex\n\
             \n\
             NOTES\n\
             A detectable account mismatch refuses until you pass identity flags to override\n\
             or clear it."
        }
        "set-identity" => {
            "ck auth set-identity <credential-id> --account-id <id> [--email <email>]\n\
             \x20                    [--org-name <name>] | --clear\n\
             \n\
             \x20 --account-id <id>  account identity to attach, instead of clearing metadata\n\
             \x20 --email <email>    account email; requires account-id\n\
             \x20 --org-name <name>  account organization; requires account-id\n\
             \x20 --clear            remove the account metadata instead of setting it\n\
             \n\
             NOTES\n\
             Update only non-secret account metadata. The vault decrypts and re-seals the\n\
             existing record without replacing token material, keeps its lifecycle state, and\n\
             bumps record_version because the encrypted envelope changed. Works for any\n\
             decryptable record, including needs-reauth or retired records."
        }
        "set-category" => {
            "ck auth set-category <credential-id>\n\
             \x20             (--set <csv> | --add <csv> | --remove <csv>)\n\
             \n\
             \x20 --set <csv>     replace the category set; an empty value clears it\n\
             \x20 --add <csv>     add normalized category names\n\
             \x20 --remove <csv>  remove category names\n\
             \n\
             NOTES\n\
             Names match ^[a-z][a-z0-9-]{1,31}$. A transition appends one set_category\n\
             audit row; a no-op is silent."
        }
        "reclassify" => {
            "ck auth reclassify --from-registry [--force]\n\
             \n\
             \x20 --from-registry  required acknowledgement of the catalog source\n\
             \x20 --force          replace non-empty differing sets; without it only empty\n\
             \x20                  sets are refilled\n\
             \n\
             NOTES\n\
             Enumeration and all category transitions use one fenced transaction."
        }
        "migrate-opencode" => {
            "ck auth migrate-opencode [--dry-run] [--replace] [--force-shape]\n\
             \x20                        [--restore <provider>] [--auth-file <path>]\n\
             \x20                        [--handle-file <path>]\n\
             \x20                        [--provider <id>]... [--serve-by <plugin-id>]\n\
             \n\
             \x20 --dry-run               print non-secret compare verdicts and stop before\n\
             \x20                         every write\n\
             \x20 --replace               explicitly allow replacement when material differs\n\
             \x20 --force-shape           override the availability-only refusal for unsafe\n\
             \x20                         provider shapes and print the concrete sentinel\n\
             \x20                         consequence\n\
             \x20 --restore <provider>    safely write an api entry back, revoke recorded\n\
             \x20                         handles, and remove that provider from the handle\n\
             \x20                         file; cannot combine with dry-run, replace,\n\
             \x20                         force-shape, or provider\n\
             \x20 --auth-file <path>      OpenCode auth file; defaults to\n\
             \x20                         <data_home>/opencode/auth.json\n\
             \x20 --handle-file <path>    handle file; defaults to\n\
             \x20                         <config_home>/cortexkit/opencode-handles.json\n\
             \x20 --provider <id>         select a provider; repeatable, preserving requested\n\
             \x20                         order\n\
             \x20 --serve-by <plugin-id>  serving plugin; defaults to opencode-claustrum\n\
             \n\
             NOTES\n\
             Move OpenCode api entries into the vault as apikey:<provider>:main, write a\n\
             capability handle file, then replace the auth entry with a provider tombstone.\n\
             Re-running identical material is a no-op. OAuth and wellknown entries are\n\
             skipped by default.\n\
             \n\
             Providers whose api key leaves the generic fetch seam are refused with source\n\
             citations."
        }
        "opencode-account" => {
            "ck auth opencode-account add --provider <id> --label <label> --key-file <path|->\n\
             \x20                        [--before <label>] [--handle-file <path>]\n\
             \n\
             \x20 --provider <id>       provider already migrated; required for add/remove,\n\
             \x20                       optional for list\n\
             \x20 --label <label>       account label to add or remove\n\
             \x20 --key-file <path|->   add: key from a file or stdin (-), never argv; stdin\n\
             \x20                       trims one terminal LF or CRLF\n\
             \x20 --before <label>      add: insert before an existing account label\n\
             \x20 --handle-file <path>  handle file; defaults to\n\
             \x20                       <config_home>/cortexkit/opencode-handles.json\n\
             \n\
             NOTES\n\
             Add, remove, or list labeled api accounts in a provider already migrated by\n\
             migrate-opencode. List prints labels, credential ids, lifecycle state, and\n\
             record versions only.\n\
             \n\
             ck auth opencode-account remove --provider <id> --label <label>\n\
             \x20                        [--handle-file <path>]\n\
             \n\
             ck auth opencode-account list [--provider <id>] [--handle-file <path>]"
        }
        "mint-handle" => {
            "ck auth mint-handle --id <id>\n\
             \n\
             \x20 --id <id>  credential for which to mint a capability handle\n\
             \n\
             NOTES\n\
             Mint an unguessable capability handle for a credential — the token a consumer\n\
             presents to `credential.get`. A credential can have many handles."
        }
        "revoke-handle" => {
            "ck auth revoke-handle --handle <raw> | --hash <hex>\n\
             \n\
             \x20 --handle <raw>  the raw ckh_ bearer token\n\
             \x20 --hash <hex>    64 lowercase hex; when the raw value is gone, use the\n\
             \x20                 handle_hash column. Mint rows carry it too from the\n\
             \x20                 2026-09-19 build on; older mints name only the\n\
             \x20                 credential and the time (ck auth audit)\n\
             \n\
             NOTES\n\
             Revoke one capability handle (audited). The credential and its other handles\n\
             keep serving. Supply exactly one form."
        }
        "revoke-all-handles" => {
            "ck auth revoke-all-handles --id <id>\n\
             \n\
             \x20 --id <id>  credential whose capability handles should all be revoked\n\
             \n\
             NOTES\n\
             Revoke every capability handle for a credential in one audited step. The record\n\
             itself is untouched (still refreshable; mint new handles later)."
        }
        "grant" => {
            "ck auth grant --principal <id|reserved:id>\n\
             \x20             --selector-kind <exact|category> --selector <value>\n\
             \x20             --operation <read|sign>\n\
             \n\
             \x20 --principal <id|reserved:id>  reserved module principal\n\
             \x20 --selector-kind <kind>        exact or category (required, no default)\n\
             \x20 --selector <value>            credential id text or bare category name\n\
             \x20 --operation <read|sign>       authority to grant (`--op` is accepted)\n\
             \n\
             NOTES\n\
             exact matches one credential id byte for byte. category matches every\n\
             credential carrying that category, so the set moves as categories are\n\
             assigned. Both are stored as bare text; neither carries a kind marker.\n\
             --prefix is gone: its reach changed whenever someone named a new\n\
             credential. A former prefix that named a family is a category now.\n\
             Read and sign are separate authorities; neither implies the other."
        }
        "revoke-grant" => {
            "ck auth revoke-grant --principal <id|reserved:id>\n\
             \x20                    --selector-kind <exact|category> --selector <value>\n\
             \x20                    --operation <read|sign>\n\
             \n\
             \x20 --principal <id|reserved:id>  reserved module principal\n\
             \x20 --selector-kind <kind>        exact or category (required, no default)\n\
             \x20 --selector <value>            credential id text or bare category name\n\
             \x20 --operation <read|sign>       authority to revoke (`--op` is accepted)\n\
             \n\
             NOTES\n\
             Revocation is exact over principal, selector kind, selector, and operation."
        }
        "reactivate" => {
            "ck auth reactivate --id <id>\n\
             \n\
             \x20 --id <id>  credential to clear from needs-reauth\n\
             \n\
             NOTES\n\
             Clear needs-reauth WITHOUT replacing the secret: the operator asserting the\n\
             credential was marked dead in error (a consumer can misreport a provider's\n\
             refusal). The stored material is untouched, so this is not a re-login.\n\
             \n\
             Self-correcting: the next use verifies it, and a credential that really is dead\n\
             returns to needs-reauth on its own. Refused for `corrupt` records — those failed\n\
             our own integrity check and only a re-deposit fixes them."
        }
        "invalidate" => {
            "ck auth invalidate --id <id>\n\
             \n\
             \x20 --id <id>  credential to mark needs-reauth\n\
             \n\
             NOTES\n\
             Mark a credential needs-reauth (stops serving until re-login) without revoking\n\
             handles. `logout` is the usual operator verb; this is the lower-level primitive."
        }
        "audit" => {
            "ck auth audit [--limit <N>]\n\
             \n\
             \x20 --limit <N>  maximum audit entries to print; defaults to all entries\n\
             \n\
             NOTES\n\
             Print the tamper-evident HMAC audit chain. Reads LEASE-FREE, so it is safe\n\
             against a running daemon -- do not stop the vault for this.\n\
             \n\
             This is where a SUCCESSFUL refresh appears, as refresh_commit. 'ck auth events'\n\
             records failures only, so read the chain to answer whether a credential is being\n\
             refreshed at all."
        }
        "events" => {
            "ck auth events [--limit <N>]\n\
             \n\
             \x20 --limit <N>  maximum recent events to print; defaults to 20\n\
             \n\
             NOTES\n\
             Print recent authentication events: why a credential stopped working. Records a\n\
             consumer's reported provider status (401 vs 403) and refresh failures, neither\n\
             of which the audit chain can carry.\n\
             \n\
             `applied` says whether the event changed the credential. A report naming a\n\
             record_version the vault had already replaced is a deliberate no-op -- shown\n\
             here as applied=no, because a consumer acting on stale state is worth seeing and\n\
             leaves no other trace.\n\
             \n\
             Reads the store read-only and takes no lease, so it works against a RUNNING\n\
             vault. These rows are diagnostics, not evidence: unlike the audit chain they are\n\
             not tamper-evident and may be pruned. For what authoritatively happened, use\n\
             `audit`."
        }
        "usable" => {
            "ck auth usable\n\
             \n\
             NOTES\n\
             Open every credential's envelope and report what its contents imply.\n\
             \n\
             The only command that decrypts. 'status' and 'list' read plaintext metadata, so\n\
             neither can see a record that decrypts to nothing usable.\n\
             \n\
             Scores STRANDED: a record holding neither a usable access token nor any refresh\n\
             material, so it can never serve again without an operator login. Expiry is\n\
             printed but never scored -- an expired access token beside live refresh material\n\
             is the routine state of a healthy credential, and it refreshes on the next read.\n\
             \n\
             Safe while the daemon runs: read-only, takes no lease, writes nothing.\n\
             \n\
             'stranded: 0' is the expected reading."
        }
        "verify-audit" => {
            "ck auth verify-audit\n\
             \n\
             NOTES\n\
             Verify the audit-chain integrity end to end. Reads LEASE-FREE, so it is safe\n\
             against a running daemon -- do not stop the vault for this. Fails if any entry\n\
             was edited, reordered, or inserted.\n\
             \n\
             DOES NOT DETECT TRUNCATION OF THE NEWEST ENTRIES, at any depth. Every entry\n\
             binds its predecessor, so a chain with its tail removed is a SHORTER VALID CHAIN\n\
             and verifies clean -- there is no in-band record of expected length. Forging an\n\
             entry still needs the audit key; deleting a suffix does not. So 'intact' means\n\
             the recorded history was not ALTERED, never that it is ALL of the history.\n\
             \n\
             Consequence worth knowing before you rely on it: absence of rows is not\n\
             evidence. 'The vault wrote nothing' reads identically to 'the vault's rows were\n\
             deleted', so it cannot separate a credential the vault never adjudicated from\n\
             one whose verdict was erased. Detecting that needs a tip (last seq + entry_mac)\n\
             recorded OUTSIDE this database and compared for monotonicity -- see\n\
             docs/operator-runbook.md.\n\
             \n\
             The running daemon publishes that tip in its health body as auditSeq and\n\
             auditTipMac, so a witness can record it without database access. The check is\n\
             NOT 'the sequence never decreases': a truncation followed by fresh legitimate\n\
             appends returns the sequence to its old value, and only the mac at that sequence\n\
             differs. The mac observed at a given sequence must be stable forever."
        }
        "rotate-master-key" => {
            "ck auth rotate-master-key\n\
             \n\
             NOTES\n\
             Crash-safe two-slot rotation of the vault master key (ALWAYS offline; stop the\n\
             daemon first). Re-seals every record under the new key."
        }
        "bootstrap" => {
            "ck auth bootstrap\n\
             \n\
             NOTES\n\
             Initialize a new vault: provision the master key and seal the audit key (ALWAYS\n\
             offline). Refuses if the vault already exists."
        }
        "overrides" => return usage_short(),
        _ => return format!("no help for '{verb}'\n\n{}", usage_short()),
    };
    body.to_string()
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
    commit_admin_with_key(global, op, None)
}

fn commit_login_admin(
    global: &GlobalArgs,
    op: credentials_core::admin_ops::AdminOpBody,
    preflighted_key: MasterKey,
) -> Result<serde_json::Value, CliError> {
    commit_admin_with_key(global, op, Some(preflighted_key))
}

fn commit_admin_with_key(
    global: &GlobalArgs,
    op: credentials_core::admin_ops::AdminOpBody,
    mut preflighted_key: Option<MasterKey>,
) -> Result<serde_json::Value, CliError> {
    if let Some(conn_path) = &global.subc_conn {
        match admin_client::commit(
            &global.data_dir,
            &resolver_config(global),
            conn_path,
            &op,
            preflighted_key.as_ref(),
        ) {
            admin_client::RouteCommit::Committed(v) => return Ok(v),
            admin_client::RouteCommit::Refused(m) => return Err(CliError::RouteRefused(m)),
            admin_client::RouteCommit::LocalFailure(m) => return Err(CliError::LocalFailure(m)),
            admin_client::RouteCommit::Indeterminate(m) => {
                return Err(CliError::RouteIndeterminate(m))
            }
            admin_client::RouteCommit::NoLiveModule(m) => {
                // Nothing was dispatched; the offline path below is safe.
                eprintln!("(no live module: {m}; using the offline lease path)");
            }
        }
    }
    let store = open_for_admin_with_key(global, true, preflighted_key.take())?;
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
    open_for_admin_with_key(global, route_path_exists, None)
}

fn open_for_admin_with_key(
    global: &GlobalArgs,
    route_path_exists: bool,
    preflighted_key: Option<MasterKey>,
) -> Result<EncryptedStore, CliError> {
    let store = open_sqlite(&descriptor(global)).map_err(|e| match e {
        // A held lease means the daemon is up — the structural "while stopped" gate.
        StoreError::Lease(_) => CliError::DaemonRunning { route_path_exists },
        other => CliError::StoreOpen(other),
    })?;
    // Crash-safe resolve happens before migration because migration 10 must decrypt
    // the existing audit-chain key before it writes category assignments.
    let db_key_id = EncryptedStore::read_db_key_id(&store).map_err(CliError::StoreOpen)?;
    let key = match (db_key_id, preflighted_key) {
        (Some(db_key_id), Some(key)) if key.key_id() == db_key_id => key,
        (Some(db_key_id), _) => resolver::resolve_for_db(&resolver_config(global), db_key_id)
            .map_err(CliError::MasterKey)?,
        (None, Some(key)) => key,
        (None, None) => {
            resolver::resolve(&resolver_config(global), None).map_err(CliError::MasterKey)?
        }
    };
    EncryptedStore::migrate_with_key(&store, &key).map_err(CliError::StoreOpen)?;
    EncryptedStore::open(store, key).map_err(CliError::Store)
}

/// Resolve the key for the destination store before an interactive flow opens a prompt.
/// A missing store uses the configured current key, while an existing store selects the
/// key whose fingerprint the database records.
fn resolve_store_key(global: &GlobalArgs) -> Result<MasterKey, CliError> {
    let path = store_path(global);
    let db_key_id = if path.exists() {
        let conn = credentials_core::usable::open_store_read_only(&path)
            .map_err(|error| CliError::Io(error.to_string()))?;
        credentials_core::usable::read_db_key_id_read_only(&conn)
    } else {
        None
    };
    match db_key_id {
        Some(key_id) => resolver::resolve_for_db(&resolver_config(global), key_id),
        None => resolver::resolve(&resolver_config(global), None),
    }
    .map_err(CliError::MasterKey)
}

/// Refuse login failures that are knowable before an authorization code or device
/// code is spent. The read-only probes take no writer lease, so this stays compatible
/// with both the online commit path and the daemon-stopped fallback.
fn preflight_login(
    global: &GlobalArgs,
    id: &str,
    replace: bool,
    already_exists_message: String,
) -> Result<MasterKey, CliError> {
    let path = store_path(global);
    let key = resolve_store_key(global)?;

    let exists = if path.exists() {
        // The version-aware reader, so the CLI has ONE lease-free metadata reader rather
        // than two that could drift. This caller only needs existence, so the version is
        // discarded here; the verbs that render a reduced view are the ones that use it.
        match credentials_core::store::list_meta_read_only_with_schema(&path) {
            Ok((rows, _)) => rows.iter().any(|(stored_id, _)| stored_id == id),
            Err(StoreOpError::NotFound) => false,
            Err(error) => return Err(CliError::Store(error)),
        }
    } else {
        false
    };
    match (replace, exists) {
        (false, true) => Err(CliError::Usage(already_exists_message)),
        (true, false) => Err(CliError::Store(StoreOpError::NotFound)),
        _ => Ok(key),
    }
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
    // IDEMPOTENT ON PURPOSE: an already-provisioned vault is bootstrap's POSTCONDITION,
    // not a failure. Returning an error for a state that satisfies the goal is what made
    // this dangerous -- `CliError::MasterKey(_)` maps every one of MasterKeyError's 13
    // variants to exit 4, so "a key already exists" and "the keychain is locked and I
    // cannot tell" are indistinguishable to a caller reading the code.
    //
    // MEASURED NEAR-MISS, 2026-09-03, on a fresh macOS VM over SSH: `ck setup claustrum`
    // hit exit 4 from a LOCKED LOGIN KEYCHAIN ("User interaction is not allowed"), and a
    // repair proposal then read exit 4 as "already provisioned" and moved on -- which
    // would have enabled the module with NO KEY. The conflation did that, not the
    // proposal: both readings of 4 were defensible.
    //
    // So the installer can now always run bootstrap: success means a key exists, and a
    // non-zero exit means one does not. The key_id is printed either way, which is what
    // lets an operator tell a fresh provision from a pre-existing vault -- the honest
    // difference between the two cases, rather than an exit code carrying it.
    match resolver::bootstrap(&resolver_config(global)) {
        Ok(key) => {
            println!(
                "provisioned a new master key (key_id {})",
                key.key_id().to_hex()
            );
            Ok(())
        }
        Err(MasterKeyError::KeyAlreadyProvisioned(_)) => {
            // Read the existing key back so the line names WHICH key is in place. If that
            // read fails we still exit 0: `KeyAlreadyProvisioned` already proved a key
            // exists, which is the whole postcondition, and downgrading to a failure here
            // would reintroduce the conflation this arm exists to remove.
            match resolver::resolve(&resolver_config(global), None) {
                Ok(key) => println!(
                    "already provisioned (key_id {}); nothing to do",
                    key.key_id().to_hex()
                ),
                Err(e) => println!(
                    "already provisioned; nothing to do (the key is present but could not \
                     be read back to name it: {e})"
                ),
            }
            Ok(())
        }
        Err(other) => Err(CliError::MasterKey(other)),
    }
}

/// Generate and store an Ed25519 signing key without creating a second copy outside
/// the vault. The public half is derived before the record is committed so it can be
/// printed only after the admin write succeeds; no private material reaches output.
fn cmd_mint_signing_key(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    let id = required(args, "--id")?;
    let parsed = parse_credential_id(&id);
    if !matches!(parsed.method, Some(AuthMethod::Signing)) {
        return Err(CliError::Usage(
            "mint-signing-key requires an id beginning with signing:".to_string(),
        ));
    }

    // `ring` generates PKCS#8 in memory. The only copy after this function returns is
    // the encrypted record; neither the key bytes nor this PEM are sent to disk or a
    // process boundary before the vault seals them.
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
        .map_err(|_| CliError::Io("generating Ed25519 key failed".to_string()))?;
    let private_pem = pem_wrap_private_key(pkcs8.as_ref());
    let public = credentials_core::signing::public_key_ed25519(&private_pem)
        .map_err(|_| CliError::Io("generated Ed25519 key was unusable".to_string()))?;
    let record = VaultRecord::new_static(
        AuthMethod::Signing.credential_kind(),
        "operator",
        private_pem.into_bytes(),
        None,
    );

    let replace = has_flag(args, "--replace");
    let (audit_op, mode, success) = if replace {
        (
            AdminAuditOp::Overwrite,
            StoreMode::ReplaceUnconditional,
            "replaced",
        )
    } else {
        (AdminAuditOp::Put, StoreMode::Create, "created")
    };
    commit_admin(global, store_op(&id, record, audit_op, mode))?;

    // Public material is the intentional output of this ceremony. The private PEM
    // stays inside the sealed record and is never interpolated into a success message.
    println!("{success} {id}");
    println!("public_key_hex {}", public.public_key_hex);
    println!("key_id {}", public.key_id);
    Ok(())
}

/// Wrap ring's in-memory PKCS#8 bytes in the only PEM armour the signing parser accepts.
fn pem_wrap_private_key(pkcs8: &[u8]) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(pkcs8);
    let mut pem = String::from("-----BEGIN PRIVATE KEY-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).expect("base64 output is ASCII"));
        pem.push('\n');
    }
    pem.push_str("-----END PRIVATE KEY-----");
    pem
}

fn cmd_put(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    let id = required(args, "--id")?;
    let parsed = parse_credential_id(&id);
    if matches!(parsed.method, Some(AuthMethod::Signing)) {
        return Err(CliError::Usage(
            "signing keys must be generated with mint-signing-key, not put".to_string(),
        ));
    }
    // Payload from EITHER --payload <value> (exact bytes) OR --payload-file <path>.
    // Ordinary key files drop their terminal line ending, but a cookie header is sent
    // verbatim upstream, so its file bytes cannot be trimmed or normalized.
    // --payload-file keeps a real secret OUT of argv (process list / shell history).
    //
    // AND THERE IS DELIBERATELY NO ADVISORY WHEN --payload IS USED, which looks like an
    // omission next to the reachability advisory ~200 lines below. The difference is that
    // THAT condition is structural -- no handle AND no covering grant is a fact the vault
    // can read -- while "this value is a secret" is a guess. Every discriminator available
    // here is a heuristic on the bytes, and both of its failure modes are worse than
    // silence: a false positive fires on probe deposits (`--payload
    // 'claustrum-tombstone:v1:probe'` is a real invocation from this week's testing) and
    // teaches the operator to skip the line, after which the true positives are invisible
    // too; a false negative is worse still, because a warning that did not fire reads as
    // clearance.
    //
    // So the exposure is real and the vault cannot close it at this seam. It is closed
    // upstream instead, by whoever ASKS for a key naming a file path rather than
    // prohibiting a paste -- a prohibition leaves the person holding a secret with no next
    // step, and under time pressure they paste it anyway. Recorded 2026-09-13 after a peer
    // routed a key through an ask row for exactly that reason.
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
        (None, Some(path)) if matches!(parsed.method, Some(AuthMethod::Cookie)) => {
            std::fs::read(&path).map_err(|e| CliError::Io(format!("reading {path}: {e}")))?
        }
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
    // A GitHub App deposit is the one `put` that must NOT produce a static record.
    //
    // The App private key is a DURABLE credential that mints short-lived installation
    // tokens -- structurally the refresh-token/access-token relationship, so it belongs
    // in the OAuth shape where the engine's single-flight, expiry and version-CAS
    // machinery already lives. Stored static instead, `credential.get` serves the PEM
    // verbatim; a consumer then puts newline-laden key material into an HTTP header and
    // fails before the wire. That is not hypothetical -- it is what plexus hit on
    // 2026-08-17, and the reason this branch exists.
    //
    // `--client-id` is what selects the shape, because the adapter cannot mint without
    // it: it is the App JWT's `iss`. Requiring it here means a github_app record cannot
    // be created in a state that can never serve.
    let client_id = optional(args, "--client-id");
    let is_github_app = id.starts_with("github_app:");
    match (&client_id, is_github_app) {
        (Some(_), false) => {
            return Err(CliError::Usage(
                "--client-id applies only to a github_app:<slug> id".to_string(),
            ))
        }
        (None, true) => {
            return Err(CliError::Usage(
                "a github_app deposit needs --client-id <app client id> (the App JWT issuer); \
                 without it the record can never mint a token"
                    .to_string(),
            ))
        }
        _ => {}
    }

    let kind = if matches!(parsed.method, Some(AuthMethod::Cookie)) {
        if optional(args, "--kind").is_some() {
            return Err(CliError::Usage(
                "cookie:<domain> determines the cookie kind; do not pass --kind".to_string(),
            ));
        }
        CredentialKind::Cookie
    } else {
        match optional(args, "--kind").as_deref() {
            None | Some("api_key") => CredentialKind::ApiKey,
            Some("dsn") => CredentialKind::Dsn,
            Some("opaque") => CredentialKind::Opaque,
            Some(other) => {
                return Err(CliError::Usage(format!(
                "--kind must be api_key|dsn|opaque (oauth records come via import), got '{other}'"
            )))
            }
        }
    };
    let expires_at_ms = if matches!(parsed.method, Some(AuthMethod::Cookie)) {
        if optional(args, "--expires-ms").is_some() {
            return Err(CliError::Usage(
                "cookie credentials do not carry an expiry; omit --expires-ms".to_string(),
            ));
        }
        None
    } else {
        optional(args, "--expires-ms")
            .map(|s| s.parse::<i64>())
            .transpose()
            .map_err(|e| CliError::Usage(format!("--expires-ms not an integer: {e}")))?
    };

    let record = match client_id {
        Some(client_id) => {
            // Empty access_token on purpose: `is_stale` short-circuits an empty access
            // token to stale, so the FIRST get mints rather than serving nothing. The
            // empty payload is legal here for the same reason it is legal for a
            // refresh-only OAuth import -- the non-empty-payload invariant guards
            // records that have no way to fill themselves, and this one refreshes.
            //
            // token_url stays empty because this adapter pins GitHub's endpoints as
            // constants rather than reading them off the record.
            let oauth = credentials_core::oauth::OAuthCredential {
                access_token: String::new().into(),
                refresh_token: String::from_utf8(payload)
                    .map_err(|_| {
                        CliError::Usage("the App private key must be UTF-8 PEM text".to_string())
                    })?
                    .into(),
                expires_at_ms: None,
                token_url: String::new(),
                client_id: Some(client_id),
                scopes: Vec::new(),
            };
            VaultRecord::new_oauth("operator", "github_app", oauth, Vec::new())
        }
        None if kind == CredentialKind::Cookie => VaultRecord::new_cookie("operator", payload),
        None => VaultRecord::new_static(kind, "operator", payload, expires_at_ms),
    };
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
            // SAID ONLY ON THE CREATE ARM, and only when nothing already reaches the id.
            //
            // A deposit is not a delivery. The vault now holds the material and no
            // consumer can ask for it: a handle must be minted AND placed in whatever
            // file that consumer reads, and the vault must never write that file --
            // it does not own the path or the schema, and a credential store that edits
            // its callers' config is a worse object than one that leaves a gap.
            //
            // So the operator is the only party who can close it, and this is the one
            // moment they are standing in the flow.
            //
            // WHY A LINE HERE RATHER THAN A GAUGE IN `list` OR HEALTH: measured on the
            // live vault, 4 of 4 credentials with no handle and no covering grant are
            // DELIBERATELY unreachable -- a signing root whose handle exists only inside
            // a ceremony window, and three deploy-time sources of record consumed by
            // `wrangler secret put` and never over the route plane. A standing alarm
            // would be wrong every time it fired, and the first thing anyone would do is
            // stop reading it. A statement at the moment of the act is honest for those
            // too: depositing the manifest root DOES leave it unreachable until a
            // ceremony mints one.
            //
            // Create-only by construction: `StoreMode::Create` fails if the id exists,
            // so there cannot be a surviving handle from a previous deposit. On the
            // replace arms handles are deliberately kept, and printing this there would
            // be false.
            // ADVICE ON STDERR, VERDICT ON STDOUT -- this file's existing convention,
            // most closely the mint advisory ("(minted handle for …)"), which puts the
            // datum on stdout and the note beside it on stderr.
            //
            // This was on stdout, so the LAST line of a successful put was advice and a
            // caller had to tail past it to find `created <id>`. An operator reads both
            // either way; a script capturing stdout now gets the verdict alone.
            if !created_id_is_already_reachable(global, &id) {
                // STATE THE FACT, AND MAKE THE STEP CONDITIONAL ON A CONSUMER EXISTING.
                //
                // This used to read "mint one with ...", which assumes the operator
                // deposited FOR a consumer that is already waiting. Depositing AHEAD of
                // one is equally legitimate, and there the advice is wrong: a capability
                // handle is bearer material, so minting it early creates a live
                // credential surface whose only property is that nobody can use it yet.
                //
                // Corrected 2026-09-06 after an operator declined the advice with better
                // reasoning than the advice had -- they deposited a key whose consumer
                // could not select it until a field ships, and minting would have left a
                // reachable secret with no reader in the meantime.
                eprintln!(
                    "(not reachable by any consumer yet: no capability handle and no \
                     covering grant. When a consumer needs it, mint a handle with \
                     `ck auth mint-handle --id {id}` and place it where that consumer \
                     reads handles — the vault cannot write that file. A handle is bearer \
                     material, so it is worth minting when there is a reader rather than \
                     ahead of one.)"
                );
            }
        }
    }
    Ok(())
}

/// Build an admin store op, upgrading unconditional replacement to the identity-policy
/// discriminator so an older daemon refuses semantics it cannot preserve.
fn store_op(id: &str, record: VaultRecord, audit_op: AdminAuditOp, mode: StoreMode) -> AdminOpBody {
    match mode {
        StoreMode::ReplaceUnconditional => AdminOpBody::StoreWithIdentityPolicy {
            v: ADMIN_OP_SCHEMA_V1,
            id: id.to_string(),
            record: Box::new(record),
            audit_op,
            clear_identity: false,
        },
        mode => AdminOpBody::Store {
            v: ADMIN_OP_SCHEMA_V1,
            id: id.to_string(),
            record: Box::new(record),
            audit_op,
            mode,
        },
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

#[derive(Default)]
struct IdentityFlags {
    clear: bool,
    account_id: Option<String>,
    email: Option<String>,
    org_name: Option<String>,
}

fn identity_flags(
    args: &[String],
    clear_flag: &str,
    require_account_id: bool,
) -> Result<IdentityFlags, CliError> {
    let flags = IdentityFlags {
        clear: has_flag(args, clear_flag),
        account_id: optional(args, "--account-id"),
        email: optional(args, "--email"),
        org_name: optional(args, "--org-name"),
    };
    let has_identity_fields =
        flags.account_id.is_some() || flags.email.is_some() || flags.org_name.is_some();
    if flags.clear && has_identity_fields {
        return Err(CliError::Usage(format!(
            "{clear_flag} is mutually exclusive with --account-id, --email, and --org-name"
        )));
    }
    if flags.clear {
        return Ok(flags);
    }
    let Some(account_id) = flags.account_id.as_deref() else {
        if has_identity_fields || require_account_id {
            return Err(CliError::Usage(
                "--account-id is required when setting identity metadata".to_string(),
            ));
        }
        return Ok(flags);
    };
    if account_id.trim().is_empty() {
        return Err(CliError::Usage(
            "--account-id must not be empty".to_string(),
        ));
    }
    if account_id.chars().any(char::is_control) {
        return Err(CliError::Usage(
            "--account-id must not contain control characters".to_string(),
        ));
    }
    if account_id.len() > 256 {
        return Err(CliError::Usage(
            "--account-id must be at most 256 bytes".to_string(),
        ));
    }
    Ok(flags)
}

/// Convert one isolated harness entry into the vault record used by both import forms.
/// Identity is deliberately returned as metadata so attachment remains a separate step.
fn build_import_record(
    source: &str,
    entry_payload: &[u8],
    id: &str,
    provider_selection: Option<&str>,
    adapter_override: Option<String>,
) -> Result<(VaultRecord, Option<String>), CliError> {
    let parsed = parse_credential_id(id);
    if matches!(parsed.method, Some(AuthMethod::Signing)) {
        return Err(CliError::Usage(
            "signing keys must be generated with mint-signing-key, not imported".to_string(),
        ));
    }
    if matches!(parsed.method, Some(AuthMethod::ApiKey)) {
        let provider = provider_selection.unwrap_or(&parsed.provider);
        let key = credentials_core::oauth::import_api_key(source, entry_payload, provider)
            .map_err(|error| CliError::Usage(format!("api-key import: {error}")))?;
        return Ok((
            VaultRecord::new_static(CredentialKind::ApiKey, source, key, None),
            None,
        ));
    }

    let mut imported_email = None;
    let oauth = if source == "antigravity" {
        credentials_core::oauth::import_antigravity_account(entry_payload, provider_selection).map(
            |imported| {
                imported_email = imported.email;
                imported.oauth
            },
        )
    } else {
        match provider_selection {
            Some(provider) => credentials_core::oauth::OAuthCredential::import_provider(
                source,
                entry_payload,
                provider,
            ),
            None => credentials_core::oauth::OAuthCredential::import(source, entry_payload),
        }
    }
    .map_err(|error| CliError::Usage(format!("import parse: {error}")))?;
    let adapter = adapter_override
        .or_else(|| default_refresh_adapter(parsed.method, &parsed.provider))
        .ok_or_else(|| {
            CliError::Usage(format!(
                "no refresh adapter for id '{id}'; pass --adapter <name>"
            ))
        })?;
    let payload =
        credentials_core::secret::SecretBytes::new(oauth.access_token.expose().as_bytes().to_vec());
    Ok((
        VaultRecord::new_oauth(source, adapter, oauth, payload),
        imported_email,
    ))
}

/// Apply the import identity policy after record construction. Keeping this separate
/// ensures the picker and flag form attach antigravity identity in the same order.
fn attach_import_identity(
    record: VaultRecord,
    requested_identity: IdentityFlags,
    imported_email: Option<String>,
) -> VaultRecord {
    if requested_identity.clear {
        return record;
    }
    match requested_identity.account_id {
        Some(account_id) => record.with_identity(RecordIdentity {
            account_id: Some(account_id),
            email: requested_identity.email.or(imported_email),
            org_name: requested_identity.org_name,
        }),
        None => match imported_email {
            Some(email) => record.with_identity(RecordIdentity {
                account_id: Some(email.clone()),
                email: Some(email),
                org_name: None,
            }),
            None => record,
        },
    }
}

fn cmd_import(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    if args.is_empty() {
        return import_picker::run(global);
    }

    let source = required(args, "--source")?;
    let id = required(args, "--id")?;
    let json_path = required(args, "--json")?;
    let requested_identity = identity_flags(args, "--clear-identity", false)?;
    let clear_identity = requested_identity.clear;
    let raw =
        std::fs::read(&json_path).map_err(|e| CliError::Io(format!("reading {json_path}: {e}")))?;
    let provider_selection = optional(args, "--provider");
    let (record, imported_email) = build_import_record(
        &source,
        &raw,
        &id,
        provider_selection.as_deref(),
        optional(args, "--adapter"),
    )?;
    let record = attach_import_identity(record, requested_identity, imported_email);

    // `--replace` overwrites an existing credential UNCONDITIONALLY (re-seal at
    // version+1, reset to active, keep the handle), for fixing a credential imported
    // from the wrong source. Without it, import is CREATE-ONLY (an existing id is an
    // error), so a fresh credential can never be silently clobbered.
    if has_flag(args, "--replace") {
        commit_admin(
            global,
            AdminOpBody::StoreWithIdentityPolicy {
                v: ADMIN_OP_SCHEMA_V1,
                id: id.clone(),
                record: Box::new(record),
                audit_op: AdminAuditOp::Import,
                clear_identity,
            },
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

fn cmd_set_identity(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    let id = args
        .first()
        .filter(|arg| !arg.starts_with("--"))
        .cloned()
        .ok_or_else(|| {
            CliError::Usage("set-identity requires a positional <credential-id>".to_string())
        })?;
    let requested = identity_flags(args, "--clear", true)?;
    let identity = if requested.clear {
        RecordIdentity::default()
    } else {
        RecordIdentity {
            account_id: requested.account_id,
            email: requested.email,
            org_name: requested.org_name,
        }
    };
    commit_admin(
        global,
        AdminOpBody::SetIdentity {
            v: ADMIN_OP_SCHEMA_V1,
            id: id.clone(),
            identity,
        },
    )?;
    println!("updated identity for {id}");
    Ok(())
}

fn cmd_set_category(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    let credential_id = args
        .first()
        .filter(|value| !value.starts_with("--"))
        .ok_or_else(|| {
            CliError::Usage("set-category requires a positional <credential-id>".into())
        })?
        .clone();
    let modes = [
        ("--set", SetCategoryMode::Set),
        ("--add", SetCategoryMode::Add),
        ("--remove", SetCategoryMode::Remove),
    ];
    let mode_count = args
        .iter()
        .filter(|value| modes.iter().any(|(flag, _)| value == flag))
        .count();
    let selected: Vec<_> = modes
        .iter()
        .filter_map(|(flag, mode)| optional(args, flag).map(|value| (*mode, value)))
        .collect();
    if mode_count != 1 || selected.len() != 1 {
        return Err(CliError::Usage(
            "set-category requires exactly one of --set, --add, or --remove".into(),
        ));
    }
    let (mode, raw) = &selected[0];
    let categories = if raw.is_empty() {
        Vec::new()
    } else {
        raw.split(',').map(str::to_string).collect()
    };
    commit_admin(
        global,
        AdminOpBody::SetCategory {
            v: ADMIN_OP_SCHEMA_V2,
            credential_id: credential_id.clone(),
            mode: *mode,
            categories,
        },
    )?;
    println!("updated categories for {credential_id}");
    Ok(())
}

fn cmd_reclassify(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    if !has_flag(args, "--from-registry") {
        return Err(CliError::Usage(
            "reclassify requires --from-registry".into(),
        ));
    }
    let result = commit_admin(
        global,
        AdminOpBody::Reclassify {
            v: ADMIN_OP_SCHEMA_V2,
            force: has_flag(args, "--force"),
        },
    )?;
    let changed = result
        .get("credentials_reclassified")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    println!("reclassified {changed} credential(s)");
    Ok(())
}

// Vault-native first-party OAuth login uses the shared core catalog so the CLI,
// creation defaults, reclassification, and scoped listings resolve the same entries.

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

    let replace = has_flag(args, "--replace");
    let preflighted_key = preflight_login(
        global,
        id,
        replace,
        format!("'{id}' already holds a credential; use --replace or a labeled id"),
    )?;

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
            access_token: String::new().into(),
            refresh_token: tokens.access_token.into(),
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
        let payload = credentials_core::secret::SecretBytes::new(
            oauth.access_token.expose().as_bytes().to_vec(),
        );
        (oauth, payload)
    } else {
        let refresh_token = tokens.refresh_token.ok_or_else(|| {
            CliError::Io(format!("{provider} device flow returned no refresh token"))
        })?;
        let oauth = credentials_core::oauth::OAuthCredential {
            access_token: tokens.access_token.clone().into(),
            refresh_token: refresh_token.into(),
            expires_at_ms: tokens.expires_at_ms,
            token_url: wire.token_url.to_string(),
            client_id: Some(wire.client_id.to_string()),
            scopes: wire.scopes.iter().map(|scope| scope.to_string()).collect(),
        };
        let payload = credentials_core::secret::SecretBytes::new(
            oauth.access_token.expose().as_bytes().to_vec(),
        );
        (oauth, payload)
    };

    // Device-flow providers do not disclose an account identity in the response, so
    // leave RecordIdentity empty rather than making an extra account lookup.
    let record = VaultRecord::new_oauth("login", wire.adapter_name, oauth, payload);
    if replace {
        commit_login_admin(
            global,
            store_op(
                id,
                record,
                AdminAuditOp::Login,
                StoreMode::ReplaceUnconditional,
            ),
            preflighted_key,
        )?;
        println!("logged in and replaced {id}");
    } else {
        let result = commit_login_admin(
            global,
            store_op(id, record, AdminAuditOp::Login, StoreMode::Create),
            preflighted_key,
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
        decode_jwt_claims, exchange_authorization_code, exchange_authorization_code_form,
        extract_chatgpt_account_id, generate_pkce, generate_state, parse_callback,
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

        let replace = has_flag(args, "--replace") || interactive.replace;
        let preflighted_key = preflight_login(
            global,
            &id,
            replace,
            format!(
                "'{id}' already holds a credential.\n\
                 To add ANOTHER account for this provider:  login --provider {provider} --id {d}:<label>\n\
                 (e.g. --id {d}:work — each labeled id is an independent credential)\n\
                 To REPLACE the existing credential:        login --provider {provider} --replace\n\
                 (keeps the id, its handles, and bumps record_version)",
                d = p.default_id
            ),
        )?;

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

        let (audit_op, store_mode) = if replace {
            (AdminAuditOp::Overwrite, StoreMode::ReplaceUnconditional)
        } else {
            (AdminAuditOp::Put, StoreMode::Create)
        };

        if replace {
            commit_login_admin(
                global,
                store_op(&id, record, audit_op, store_mode),
                preflighted_key,
            )?;
            println!("logged in and replaced {id}");
        } else {
            let result = commit_login_admin(
                global,
                store_op(&id, record, audit_op, store_mode),
                preflighted_key,
            );
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
        return cmd_device_login(global, args, &provider, &id, wire);
    }

    let replace = has_flag(args, "--replace") || interactive.replace;
    let preflighted_key = preflight_login(
        global,
        &id,
        replace,
        format!(
            "'{id}' already holds a credential.\n\
             To add ANOTHER account for this provider:  login --provider {provider} --id {d}:<label>\n\
             (e.g. --id {d}:work — each labeled id is an independent credential)\n\
             To REPLACE the existing credential:        login --provider {provider} --replace\n\
             (keeps the id, its handles, and bumps record_version)",
            d = wire.default_id
        ),
    )?;

    // Generate the PKCE pair and the CSPRNG state (state is independent of the
    // verifier), pick the wire, build the authorize URL, and present it to the
    // operator.
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

    // Every login provider registers a loopback redirect, so bind a one-shot
    // CLI-local listener on the EXACT redirect address BEFORE opening the browser
    // (the redirect can't race an unbound socket). `--no-listener` forces the paste
    // path. The listener is a pure convenience over paste; the daemon never listens.
    //
    // THE BIND COMES BEFORE THE URL IS BUILT because the URL depends on its outcome:
    // with no socket holding the loopback address, a redirect there can only land on
    // a connection error, so a provider that also registers a code-display redirect
    // is sent to that one instead. Bind-before-browser-open is preserved — the open
    // is still below.
    let listener = if has_flag(args, "--no-listener") {
        None
    } else {
        login_listener::loopback_bind_addr(wire.redirect_uri)
            .and_then(|addr| login_listener::capture_callback(&addr))
    };

    // ONE redirect for the whole flow. The token exchange replays the redirect, and
    // the provider refuses the exchange unless it byte-matches the one in the
    // authorize URL — a refusal that lands AFTER the operator has already approved in
    // the browser, which is the most expensive place to fail. So the authorize URL
    // and both exchange arms below read this plan, and nothing past here works out a
    // redirect of its own.
    let plan = login_wire::plan_login_wire(
        wire,
        listener.is_some(),
        &pkce.challenge,
        &state,
        &authorize_params,
    )
    .map_err(|e| CliError::Io(format!("building authorize url: {e}")))?;

    println!("Open this URL in a browser signed into the account to custody:");
    println!();
    println!("  {}", plan.authorize_url);
    println!();
    // Best-effort browser open; the printed URL is the source of truth if it fails.
    let _ = open_in_browser(args, &plan.authorize_url);

    // Prefer the listener: if it captured the redirect, use it; otherwise (bind
    // failed, timed out, or a non-loopback redirect) fall back to paste. The pasted
    // value never touches argv — it is a secret-grade code read from stdin only.
    let captured = match listener {
        Some(l) => {
            // A bound listener completes the login automatically only for a browser on
            // THIS machine, so the banner states that condition and names the wait an
            // operator on another machine is about to sit through before being asked to
            // paste.
            println!(
                "{}",
                login_wire::listener_wait_banner(login_listener::LISTEN_TIMEOUT)
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
            println!("{}", plan.paste_prompt);
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
            plan.redirect_uri,
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
                plan.redirect_uri,
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
        access_token: tokens.access_token.clone().into(),
        refresh_token: tokens.refresh_token.clone().into(),
        expires_at_ms,
        token_url: wire.token_url.to_string(),
        client_id: Some(wire.client_id.to_string()),
        scopes: wire.scopes.iter().map(|s| s.to_string()).collect(),
    };
    let payload =
        credentials_core::secret::SecretBytes::new(oauth.access_token.expose().as_bytes().to_vec());
    let record =
        VaultRecord::new_oauth("login", wire.adapter_name, oauth, payload).with_identity(identity);

    // Login records a distinct `Login` audit op (not `Import`) so forensics can tell
    // a native mint from a foreign import. `--replace` overwrites an existing id (the
    // dual-custody migration: swap the imported token for the vault-minted one; the
    // handle survives). With `--subc` the commit rides the RUNNING module, so a
    // re-login needs no daemon stop at all (the zero-downtime path).
    if replace {
        commit_login_admin(
            global,
            store_op(
                &id,
                record,
                AdminAuditOp::Login,
                StoreMode::ReplaceUnconditional,
            ),
            preflighted_key,
        )?;
        println!("logged in and replaced {id}");
    } else {
        let result = commit_login_admin(
            global,
            store_op(&id, record, AdminAuditOp::Login, StoreMode::Create),
            preflighted_key,
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
    // READ `state_changed`, WHICH THE ADMIN OP SENDS FOR EXACTLY THIS. Without it the
    // line claimed "invalidated <id>" for an id that does not exist, is already
    // needs_reauth, or is retired -- and `handles_revoked` cannot stand in, because a
    // credential with no handles reports zero whether it was live or already dead.
    //
    // Same false-assurance shape as revoke-handle: the operator is told a credential was
    // stopped when nothing was. `logout` already reports this correctly; this is the
    // sibling that did not.
    //
    // Absent (older daemon) falls back to the previous wording rather than claiming
    // nothing changed -- absent and false mean different things.
    match result.get("state_changed") {
        Some(serde_json::Value::Bool(false)) => println!(
            "{id} was already needs_reauth, retired, absent, or corrupt: nothing changed\n  \
             revoked {revoked} handle(s) regardless — revocation is idempotent."
        ),
        _ => println!("invalidated {id}; revoked {revoked} handle(s)"),
    }
    Ok(())
}

/// `reactivate` = clear `needs_reauth` or `retired` back to active WITHOUT replacing
/// the secret.
///
/// The repair is for a wrong lifecycle verdict, not for a credential whose stored
/// material is damaged. It exists because that state was otherwise unrecoverable for
/// material the vault holds
/// the only copy of: a GitHub App key is shredded after deposit by custody rule, so
/// `put --replace` has no PEM to read and no login flow can re-mint one, and a mistaken
/// consumer report could force an operator back to a browser to repair bytes that were
/// never damaged.
///
/// Refuses from `corrupt` by design -- that is a claim about our own bytes, which this
/// vault verified itself, and clearing it would return known-broken material to service.
fn cmd_reactivate(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    let id = required(args, "--id")?;
    let result = commit_admin(
        global,
        AdminOpBody::Reactivate {
            v: ADMIN_OP_SCHEMA_V1,
            id: id.clone(),
        },
    )?;
    if result["state_changed"].as_bool().unwrap_or(false) {
        println!("reactivated {id}: serving verdict cleared, material untouched");
        println!("  the next use verifies it; if the credential really is dead it returns to");
        println!("  needs_reauth on its own, so a wrong call costs one failed request.");
    } else {
        // A no-op has two causes and the operator needs to know WHICH, because one is
        // benign and the other means they reached for the wrong verb.
        println!("reactivated nothing: {id} was not in needs_reauth or retired");
        println!("  already active, unknown, or corrupt. Corrupt is refused here because the");
        println!("  bytes themselves failed, and only a re-deposit fixes that.");
    }
    Ok(())
}

/// `logout` = stop serving a credential, reversibly: retire + revoke all its handles
/// (the compound atomic op), keeping the row and its audit chain. Re-login
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
        AdminOpBody::Logout {
            v: ADMIN_OP_SCHEMA_V1,
            id: id.clone(),
        },
    )?;
    let revoked = result["handles_revoked"].as_u64().unwrap_or(0);
    let state_changed = result["state_changed"].as_bool().unwrap_or(true);
    let intent_cleared = result["intent_cleared"].as_bool().unwrap_or(false);

    if state_changed {
        println!("logged out {id}: retired, stopped serving, revoked {revoked} handle(s)");
        println!(
            "  reversible: `login --provider <p> --replace` or `reactivate --id {id}` restores it."
        );
        println!("  it stays listed as retired, but is not counted as a degraded health signal.");
    } else if intent_cleared || revoked > 0 {
        println!("logged out {id}: stopped serving, revoked {revoked} handle(s)");
        println!("  its lifecycle state did not change; inspect `ck auth status` for the recorded state.");
    } else {
        println!("{id} was already retired, absent, or corrupt: nothing changed");
        println!(
            "  retired rows stay listed because logout is reversible; remove deletes the row."
        );
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
/// Can any consumer reach a NEWLY CREATED `id`, by capability handle or covering grant?
///
/// *** SOUND ONLY ON THE CREATE ARM, AND THAT IS A PROPERTY OF THE CALLER RATHER THAN
/// OF THIS FUNCTION. *** It reads the grant set and does NOT read handles: it concludes
/// "no handle" structurally, because `StoreMode::Create` refuses an existing id, so a
/// freshly created row cannot carry one from a previous deposit.
///
/// Call it from a replace arm and the handle half is silently wrong in the expensive
/// direction: a credential WITH a live handle would be reported unreachable, and the
/// caller would print exactly the false hint the fail-open design below exists to
/// prevent -- telling an operator to mint and place a handle for a credential that is
/// already reachable. Hence the name says CREATED, and the create-only precondition is
/// stated rather than implied by where it happens to be called from today.
///
/// Found by applying a peer's refinement to this file (2026-09-03): reading a remedy
/// string is not "is the remedy wrong" but "can it be reached from a state where
/// following it changes nothing", which requires enumerating the paths that REACH the
/// refusal rather than reading its text. Doing that here showed the doc comment claimed
/// a general answer the body does not compute. One call site today; the claim was the
/// defect, not the behaviour.
///
/// FAILS OPEN, DELIBERATELY: every uncertain path returns `true` ("assume reachable"),
/// so the caller stays silent. This function exists only to decide whether to print an
/// advisory line, and the two errors are not symmetric — a missing hint costs an
/// operator one puzzled minute, while a WRONG hint tells them to mint a handle for a
/// credential that a grant already covers, which is a real instruction to widen access
/// for no reason.
///
/// So an old daemon, an absent field, a refused read, or a shape this build does not
/// understand all resolve to silence rather than to a claim.
///
/// `admin.status` carries the grant set with each grant's covered credential ids
/// already computed by the store, so the grant half is a lookup rather than a
/// re-implementation of prefix matching here — the store's own answer, not a second
/// opinion that could drift from it.
fn created_id_is_already_reachable(global: &GlobalArgs, id: &str) -> bool {
    let Ok(status) = request_admin_status(global) else {
        return true; // unreadable: say nothing
    };
    let Some(grants) = status["read_grants"].as_array() else {
        return true; // field absent on this daemon: say nothing
    };
    let covered_by_grant = grants.iter().any(|g| {
        g["covered_credential_ids"]
            .as_array()
            .map(|ids| ids.iter().any(|c| c.as_str() == Some(id)))
            .unwrap_or(false)
    });
    if covered_by_grant {
        return true;
    }
    // A freshly CREATED id cannot carry a handle from a previous deposit: `Create`
    // refuses an existing id. Status does not publish per-credential handle counts, and
    // this is the one call site where their absence costs nothing, because the create
    // arm has already established the answer structurally.
    false
}

fn request_admin_status(global: &GlobalArgs) -> Result<serde_json::Value, CliError> {
    request_admin_status_with_schema(global).map(|(result, _)| result)
}

/// The store's recorded schema version when the report came from the lease-free
/// readers, or `None` when a live module answered.
///
/// A live module has already migrated on boot, so there is nothing behind to report;
/// only the offline path can meet a store the binary is ahead of.
type StoreSchemaVersion = Option<u32>;

/// Build the status report, and say which schema the store was read at.
///
/// The version is threaded out rather than printed here because the note belongs AFTER
/// the verb's own output: a caller that printed it first would put a diagnostic above
/// the inventory an operator is reading, and a script capturing stdout would still be
/// fine but a human tailing the transcript would not.
fn request_admin_status_with_schema(
    global: &GlobalArgs,
) -> Result<(serde_json::Value, StoreSchemaVersion), CliError> {
    let op = AdminOpBody::Status {
        v: ADMIN_OP_SCHEMA_V1,
    };
    if let Some(conn_path) = &global.subc_conn {
        match admin_client::commit(
            &global.data_dir,
            &resolver_config(global),
            conn_path,
            &op,
            None,
        ) {
            admin_client::RouteCommit::Committed(v) => return Ok((v, None)),
            admin_client::RouteCommit::Refused(m) => return Err(CliError::RouteRefused(m)),
            admin_client::RouteCommit::LocalFailure(m) => return Err(CliError::LocalFailure(m)),
            admin_client::RouteCommit::Indeterminate(m) => {
                return Err(CliError::RouteIndeterminate(m))
            }
            admin_client::RouteCommit::NoLiveModule(m) => {
                // NOT the lease path, which is what this said until the read verbs stopped
                // taking the writer lease. The wording survived the change because the
                // test pins stdout AND stderr byte-for-byte against the online run, so a
                // now-false sentence was the price of that pin -- worth naming, because a
                // diagnostic that describes the mechanism it no longer uses is how an
                // operator concludes a read is unsafe to run beside a live daemon. Which
                // is the exact belief this change exists to remove.
                eprintln!("(no live module: {m}; reading plaintext metadata directly)");
            }
        }
    }

    let db = store_path(global);
    if !db.exists() {
        return Err(CliError::Usage(format!(
            "no vault at {} (run 'ck auth bootstrap' first)",
            global.data_dir.display()
        )));
    }
    let (metas, meta_schema) = match credentials_core::store::list_meta_read_only_with_schema(&db) {
        Ok((metas, schema)) => (metas, Some(schema)),
        Err(StoreOpError::NotFound) => (Vec::new(), None),
        Err(error) => return Err(CliError::Store(error)),
    };
    let (grants, grant_schema) =
        match credentials_core::store::list_read_grants_read_only_with_schema(&db) {
            Ok((grants, schema)) => (grants, Some(schema)),
            Err(StoreOpError::NotFound) => (Vec::new(), None),
            Err(error) => return Err(CliError::Store(error)),
        };
    let open_intents = match credentials_core::store::count_refresh_intents_read_only(&db) {
        Ok(count) => count,
        Err(StoreOpError::NotFound) => 0,
        Err(error) => return Err(CliError::Store(error)),
    };
    Ok((
        credentials_core::admin_ops::status_result(&metas, &grants, open_intents, false),
        meta_schema.or(grant_schema),
    ))
}

/// Say, once, that the store this read met is behind the binary.
///
/// *** THE WINDOW THIS DESCRIBES IS THE PLACEMENT WINDOW. *** A CLI-only change is
/// placed first and the daemon, which migrates on boot, is restarted later. Between the
/// two the offline readers meet a store one migration behind, and they read it
/// truthfully: no categories exist yet, and every grant is a prefix grant. Without this
/// line the reduced view is indistinguishable from a vault that genuinely has no
/// categories, which is the reading that would send an operator looking for a bug in
/// their classification rather than at the restart they have not done yet.
///
/// STDERR, and stdout is untouched, so a script parsing the inventory keeps working.
fn print_store_behind_note(store_schema: StoreSchemaVersion) {
    let Some(store_schema) = store_schema else {
        return;
    };
    let binary_schema = credentials_core::store::newest_migration_version();
    if store_schema >= binary_schema {
        return;
    }
    eprintln!(
        "note: store schema {store_schema} is behind this binary's {binary_schema}; \
         categories and category grants appear after the daemon restarts (migration {})",
        credentials_core::store::CATEGORY_SCHEMA_VERSION
    );
}

type InventoryRow = (String, u64, String, Vec<String>);

fn parse_inventory(result: &serde_json::Value) -> Result<Vec<InventoryRow>, CliError> {
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
                .filter(|state| matches!(*state, "active" | "needs_reauth" | "retired" | "corrupt"))
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
            let categories = row
                .get("categories")
                .and_then(serde_json::Value::as_array)
                .and_then(|values| {
                    values
                        .iter()
                        .map(|value| value.as_str().map(str::to_string))
                        .collect::<Option<Vec<_>>>()
                })
                .unwrap_or_default();
            Ok((state.to_string(), version, id.to_string(), categories))
        })
        .collect()
}

fn print_inventory(rows: &[InventoryRow]) {
    println!("STATE          VER   CREDENTIAL  CATEGORIES");
    for (state, version, id, categories) in rows {
        let categories = if categories.is_empty() {
            "-".to_string()
        } else {
            categories.join(",")
        };
        println!("{state:<14} v{version:<4} {id}  {categories}");
    }

    // SAY WHAT `active` DOES NOT MEAN, because the word claims more than the column
    // knows. This inventory is built from plaintext metadata with no decrypt and no
    // provider call, so `active` means ONLY "nothing has reported this dead". A
    // credential nobody has called in a month and one serving perfectly render as the
    // same row, and the vault cannot tell them apart -- it learns a credential is dead
    // when a refresh is refused or a consumer reports it, and neither happens to a
    // credential nobody uses.
    //
    // An external operator reached the adjacent conclusion on 2026-08-24 while reading
    // elapsed time as evidence of durability, and named the general form better than
    // this comment could: UNTESTED IS NOT THE SAME AS PROVEN. A credential that has not
    // been exercised has demonstrated nothing, and no gauge computed from metadata can
    // close that gap -- only a call can.
    //
    // One line, unconditional. A caveat that only prints in the interesting case is one
    // an operator has never seen when they need it.
    if !rows.is_empty() {
        println!(
            "\n(`active` = nothing has reported it dead. Not a check that the provider \
             still accepts it;\n that costs a real call. `ck auth usable` opens the \
             envelopes; only a get proves service.)"
        );
    }
}

#[derive(Debug)]
struct GrantRow {
    principal_kind: String,
    principal_id: String,
    selector_kind: String,
    credential_prefix: String,
    operation: String,
    created_at_ms: i64,
}

/// Credential id -> its assigned categories, read from the same `admin.status` reply
/// the grant table is rendered from.
///
/// Tolerant by design: a reply without the inventory yields an empty map and every grant
/// renders `reaches 0`. That is honest rather than silent -- an operator seeing every row
/// at zero will question the reading, where a missing column would just be absent.
fn parse_credential_categories(
    result: &serde_json::Value,
) -> std::collections::BTreeMap<String, Vec<String>> {
    let mut map = std::collections::BTreeMap::new();
    let Some(rows) = result
        .get("credentials")
        .and_then(serde_json::Value::as_array)
    else {
        return map;
    };
    for row in rows {
        let Some(id) = row.get("id").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let categories = row
            .get("categories")
            .and_then(serde_json::Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        map.insert(id.to_owned(), categories);
    }
    map
}

fn parse_grants(result: &serde_json::Value) -> Result<Vec<GrantRow>, CliError> {
    let rows = result
        .get("read_grants")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| CliError::RouteRefused("admin.status omitted grant inventory".into()))?;
    let mut grants = Vec::with_capacity(rows.len());
    for (index, grant) in rows.iter().enumerate() {
        let principal_kind = grant
            .get("principal_kind")
            .and_then(serde_json::Value::as_str)
            .filter(|kind| *kind == "reserved")
            .ok_or_else(|| {
                CliError::RouteRefused(format!(
                    "admin.status returned an invalid grant principal kind at row {index}"
                ))
            })?;
        let principal_id = grant
            .get("principal_id")
            .and_then(serde_json::Value::as_str)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| {
                CliError::RouteRefused(format!(
                    "admin.status returned an invalid grant principal at row {index}"
                ))
            })?;
        let selector_kind = grant
            .get("selector_kind")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("exact");
        if !matches!(selector_kind, "exact" | "category") {
            return Err(CliError::RouteRefused(format!(
                "admin.status returned an invalid selector kind at row {index}"
            )));
        }
        let credential_prefix = grant
            .get("credential_prefix")
            .and_then(serde_json::Value::as_str)
            .filter(|prefix| !prefix.is_empty())
            .ok_or_else(|| {
                CliError::RouteRefused(format!(
                    "admin.status returned an invalid grant prefix at row {index}"
                ))
            })?;
        let operation = grant
            .get("operation")
            .and_then(serde_json::Value::as_str)
            .filter(|operation| matches!(*operation, "read" | "sign"))
            .ok_or_else(|| {
                CliError::RouteRefused(format!(
                    "admin.status returned an invalid grant operation at row {index}"
                ))
            })?;
        let created_at_ms = grant
            .get("created_at_ms")
            .and_then(serde_json::Value::as_i64)
            .ok_or_else(|| {
                CliError::RouteRefused(format!(
                    "admin.status returned an invalid grant creation time at row {index}"
                ))
            })?;
        grants.push(GrantRow {
            principal_kind: principal_kind.to_string(),
            principal_id: principal_id.to_string(),
            selector_kind: selector_kind.to_string(),
            credential_prefix: credential_prefix.to_string(),
            operation: operation.to_string(),
            created_at_ms,
        });
    }

    let mut prior: Option<(String, String, String, String, String)> = None;
    for grant in &grants {
        let order_key = (
            grant.principal_kind.clone(),
            grant.principal_id.clone(),
            grant.selector_kind.clone(),
            grant.credential_prefix.clone(),
            grant.operation.clone(),
        );
        if prior
            .as_ref()
            .is_some_and(|previous| previous >= &order_key)
        {
            return Err(CliError::RouteRefused(
                "admin.status returned grants out of stable order".into(),
            ));
        }
        prior = Some(order_key);
    }
    Ok(grants)
}

/// Print one stable row per principal-scoped grant, including the creation time.
///
/// WIDTHS ARE MEASURED FROM THE ROWS, NOT FIXED. The fixed `{:<24}` this replaced was
/// narrower than a measured 26-character selector, so that row pushed its last two
/// columns right while every other row stayed aligned. A table where one row is offset
/// reads as a rendering fault in the VALUE -- I misread a correct selector as truncated
/// output on the strength of it, and only the store settled it.
///
/// The header is here for the same reason. Without it the operation column (`read` /
/// `sign`) and the principal kind are both short lowercase words, and nothing on screen
/// says which is which.
fn render_grants(result: &serde_json::Value) -> Result<Vec<String>, CliError> {
    let grants = parse_grants(result)?;
    if grants.is_empty() {
        return Ok(vec!["no grants".to_owned()]);
    }
    // Include the header in the width so a long heading cannot overrun its own column.
    let w = |head: &str, f: &dyn Fn(&GrantRow) -> &str| {
        grants
            .iter()
            .map(|g| f(g).chars().count())
            .chain(std::iter::once(head.chars().count()))
            .max()
            .unwrap_or(head.len())
    };
    let wk = w("KIND", &|g| g.principal_kind.as_str());
    let wp = w("PRINCIPAL", &|g| g.principal_id.as_str());
    let ws = w("SELECTOR KIND", &|g| g.selector_kind.as_str());
    let wc = w("SELECTOR", &|g| g.credential_prefix.as_str());
    let wo = w("OP", &|g| g.operation.as_str());

    // REACH IS THE COLUMN THAT MAKES A WRONG GRANT VISIBLE.
    //
    // Every other column renders what the operator TYPED, so a grant that authorizes
    // nothing looks identical to one that works. That is not hypothetical: a
    // `category:llm-provider` grant was created on this vault while no credential
    // carried that category, because registry defaults apply at CREATION and every
    // credential predated the migration that introduced categories. It was
    // syntactically valid, accepted without complaint, reached zero credentials, and
    // read as correct in this exact table. A consumer asking me to double-check a
    // selector is the only reason it was caught.
    //
    // `reaches 0` stays LEGAL rather than a refusal: granting an empty category is how
    // an operator prepares reach for a module about to be installed. The column is what
    // keeps that honest -- a permanent visible statement rather than a one-time warning
    // that scrolls past.
    //
    // Computed from the SAME `admin.status` reply, which already carries per-credential
    // categories. No new admin op and no new wire field, which is why this is a
    // rendering change rather than a protocol one.
    let inventory = parse_credential_categories(result);
    let reach = |g: &GrantRow| -> usize {
        let selector = g
            .credential_prefix
            .strip_prefix("category:")
            .filter(|_| g.selector_kind == "category")
            .unwrap_or(&g.credential_prefix);
        match g.selector_kind.as_str() {
            "category" => inventory
                .values()
                .filter(|categories| categories.iter().any(|c| c == selector))
                .count(),
            // `exact` is byte equality, deliberately: a grant whose reach can grow when
            // someone else names a credential is not a grant anyone can reason about.
            _ => inventory.contains_key(selector) as usize,
        }
    };

    let mut lines = vec![format!(
        "{:<wk$}  {:<wp$}  {:<ws$}  {:<wc$}  {:<wo$}  {:>7}  GRANTED",
        "KIND", "PRINCIPAL", "SELECTOR KIND", "SELECTOR", "OP", "REACHES"
    )];
    for grant in grants {
        lines.push(format!(
            "{:<wk$}  {:<wp$}  {:<ws$}  {:<wc$}  {:<wo$}  {:>7}  {}",
            grant.principal_kind,
            grant.principal_id,
            grant.selector_kind,
            grant
                .credential_prefix
                .strip_prefix("category:")
                .filter(|_| grant.selector_kind == "category")
                .unwrap_or(&grant.credential_prefix),
            grant.operation,
            reach(&grant),
            format_ts_ms(grant.created_at_ms)
        ));
    }
    Ok(lines)
}

/// Print what `render_grants` produced.
///
/// The split exists so a test can drive the REAL formatter rather than a copy of it. A
/// test that rebuilt these rows by hand would assert its own arithmetic and pass with the
/// production renderer deleted.
fn print_grants(result: &serde_json::Value) -> Result<(), CliError> {
    for line in render_grants(result)? {
        println!("{line}");
    }
    Ok(())
}

/// Render the server's sorted grant set instead of asking an operator to mentally
/// expand prefixes. A newly covered id is a security-relevant status diff.
fn print_read_grants(result: &serde_json::Value) -> Result<(), CliError> {
    let Some(raw_grants) = result.get("read_grants") else {
        // An older daemon cannot have created a grant, so there is no access set to
        // hide while a newly upgraded CLI is still talking to it.
        return Ok(());
    };
    let raw_grants = raw_grants.as_array().ok_or_else(|| {
        CliError::RouteRefused("admin.status returned malformed read grants".into())
    })?;
    let grants = parse_grants(result)?;
    println!();
    if grants.is_empty() {
        println!("read grants: none");
        return Ok(());
    }
    println!("read grants:");
    for (index, grant) in grants.iter().enumerate() {
        let raw_grant = &raw_grants[index];
        let covered = raw_grant
            .get("covered_credential_ids")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| {
                CliError::RouteRefused(format!(
                    "admin.status omitted covered credentials at grant row {index}"
                ))
            })?;
        println!(
            "  {}:{} {} {} {}",
            grant.principal_kind,
            grant.principal_id,
            grant.operation,
            grant.selector_kind,
            grant
                .credential_prefix
                .strip_prefix("category:")
                .filter(|_| grant.selector_kind == "category")
                .unwrap_or(&grant.credential_prefix)
        );
        let mut prior_id: Option<&str> = None;
        for (covered_index, id) in covered.iter().enumerate() {
            let id = id.as_str().filter(|id| !id.is_empty()).ok_or_else(|| {
                CliError::RouteRefused(format!(
                    "admin.status returned an invalid covered credential at grant row {index}, row {covered_index}"
                ))
            })?;
            if grant.selector_kind == "exact" && !id.starts_with(&grant.credential_prefix) {
                return Err(CliError::RouteRefused(format!(
                    "admin.status listed a credential outside its grant selector at grant row {index}"
                )));
            }
            if prior_id.is_some_and(|prior| prior >= id) {
                return Err(CliError::RouteRefused(format!(
                    "admin.status returned covered credentials out of stable order at grant row {index}"
                )));
            }
            prior_id = Some(id);
            println!("    {id}");
        }
    }
    Ok(())
}

fn cmd_status(global: &GlobalArgs) -> Result<(), CliError> {
    let (result, store_schema) = request_admin_status_with_schema(global)?;
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
    print_read_grants(&result)?;
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
    let retired: Vec<&str> = result["retired_ids"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    if !retired.is_empty() {
        println!();
        println!(
            "retired: {} (intentionally not serving; not counted as degraded)",
            retired.join(", ")
        );
    }
    print_store_behind_note(store_schema);
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
    // Keep stdout machine-readable for consumers capturing the bearer token.
    println!("{handle}");
    eprintln!("revoke with: ck auth revoke-handle --handle {handle}");
    eprintln!("(minted handle for {id}; store it now — it is not recoverable)");
    warn_about_predecessors(global, &id, handle);
    Ok(())
}

/// Ask the operator about a predecessor, because this is the only moment anyone can.
///
/// A fresh handle either REPLACES one the operator already holds or joins a set held by
/// different consumers, and the vault cannot tell which: there is no holder column. What
/// it can do is say that other live doors exist and name them by hash, while the person
/// who knows whether one of them is theirs is still standing here holding both values.
///
/// After this returns, nothing holds the predecessor. A consumer config keyed on
/// credential id loses it on the next save; the audit chain records that a handle was
/// minted and (only since 2026-09-19) which one. That asymmetry is how this vault reached
/// 16 live handles on four credentials with 12 unattributable to any holder -- resolved
/// by canvassing three seats, which is an hour of work this advisory would have saved.
///
/// FAILS OPEN AND SILENT. The mint already succeeded and its handle is on stdout; an
/// advisory that turned a completed mint into a visible error would teach operators that
/// minting is unreliable. A hash is not spendable, so naming them costs nothing.
fn warn_about_predecessors(global: &GlobalArgs, id: &str, handle: &str) {
    let hash = credentials_core::handle_hash(handle);
    let Ok(others) =
        credentials_core::store::other_live_handles_read_only(&store_path(global), id, &hash)
    else {
        return;
    };
    if others.is_empty() {
        return;
    }
    eprintln!(
        "note: {id} now has {} live handles. The vault cannot tell holders apart, so if\n\
         \x20     this one REPLACES a handle you already hold, revoke that one now:",
        others.len() + 1
    );
    for (other, minted_at) in &others {
        eprintln!(
            "  ck auth revoke-handle --hash {other}   (minted {})",
            format_ts_ms(*minted_at)
        );
    }
}

fn cmd_revoke_handle(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    let usage =
        "revoke-handle requires exactly one of --handle <raw> or --hash <hex> (64 lowercase hex)";
    let (op, form) = match (optional(args, "--handle"), optional(args, "--hash")) {
        (Some(handle), None) => (
            AdminOpBody::RevokeHandle {
                v: ADMIN_OP_SCHEMA_V1,
                handle,
            },
            "--handle",
        ),
        (None, Some(handle_hash)) => {
            if handle_hash.len() != 64
                || !handle_hash
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(CliError::Usage(usage.into()));
            }
            (
                AdminOpBody::RevokeHandleByHash {
                    v: ADMIN_OP_SCHEMA_V1,
                    handle_hash,
                },
                "--hash",
            )
        }
        _ => return Err(CliError::Usage(usage.into())),
    };
    let result = commit_admin(global, op)?;
    // NAME WHAT WAS REVOKED, OR SAY NOTHING MATCHED. The old line said "revoked handle"
    // for a live handle, an already-revoked one, AND one that never existed -- so an
    // operator who pasted a truncated value was told a bearer credential was dead while
    // it kept serving. That is the one direction this tool must never be wrong in.
    //
    // Falls back to the old wording against a daemon too old to send the field, rather
    // than claiming nothing matched: absent and null mean different things here.
    match result.get("credential_id") {
        Some(serde_json::Value::String(id)) => println!("revoked handle for {id} via {form}"),
        Some(serde_json::Value::Null) => println!(
            "no live handle matched that value; nothing changed.\n  \
             check for a truncated paste — a handle is one unbroken ckh_ token."
        ),
        _ => println!("revoked handle"),
    }
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

/// Parse a grant principal into its `(kind, id)` pair.
///
/// TWO KINDS, AND THE BARE SPELLING MEANS `reserved` FOR COMPATIBILITY. `reserved:<id>`
/// names a supervised module, attested by the supervisor's launch nonce. `enrolled:<name>`
/// names a consumer this vault admitted through the enrollment ceremony. A bare `<id>`
/// with no colon is read as `reserved`, because that was the only kind when the flag was
/// introduced and every existing script spells it that way.
///
/// The bare default is deliberately the NARROWER of the two to fail safe: a typo that
/// drops the prefix grants to a module principal that probably does not exist, reaching
/// nothing, rather than to an enrolled name that might.
fn parse_grant_principal(principal: &str) -> Result<(String, String), CliError> {
    if principal.contains('|') {
        return Err(CliError::Usage("invalid_principal: '|' is reserved".into()));
    }
    match principal.split_once(':') {
        None if !principal.is_empty() => Ok(("reserved".to_string(), principal.to_string())),
        Some(("reserved", id)) if !id.is_empty() && !id.contains(':') => {
            Ok(("reserved".to_string(), id.to_string()))
        }
        Some(("enrolled", name)) if !name.is_empty() && !name.contains(':') => {
            Ok(("enrolled".to_string(), name.to_string()))
        }
        Some((kind, _)) => Err(CliError::Usage(format!(
            "invalid_principal: expected reserved:<module> or enrolled:<name> (got {kind})"
        ))),
        None => Err(CliError::Usage("invalid_principal: empty principal".into())),
    }
}

fn parse_grant_selector(args: &[String]) -> Result<(SelectorKind, String), CliError> {
    // `--prefix` IS REFUSED RATHER THAN ALIASED, and `--selector-kind` has no default.
    //
    // The tempting version of this migration keeps `--prefix` as a deprecated alias for
    // `exact`. That is worse than removing it, and the reason is the same one the whole
    // selector change exists for: it SUCCEEDS while silently changing what the operator
    // granted. `--prefix apikey:` used to reach every credential under `apikey:` — on my
    // vault, seventeen of them. Aliased to `exact` it reaches the credential LITERALLY
    // NAMED `apikey:`, which does not exist, so the command prints success and creates a
    // grant covering nothing while the operator believes they granted a family.
    //
    // `ck auth grants` would eventually show `reaches 0`, but that is a different command
    // read at a different time. A refusal at the point of creation is the only version
    // where the operator's belief and the stored row cannot diverge.
    //
    // Defaulting `--selector-kind` to `exact` has the same defect in a quieter form: an
    // operator who omits it gets a decision made for them about reach. Requiring it makes
    // them state the intent, which is cheap exactly once per grant.
    if optional(args, "--prefix").is_some() {
        return Err(CliError::Usage(
            "--prefix is gone: a prefix grant's reach changed whenever someone named a \
             new credential. Use --selector-kind exact --selector <credential-id> for one \
             credential, or --selector-kind category --selector <category> for a set that \
             moves deliberately. A former --prefix that named a family is a category now, \
             not an exact selector."
                .into(),
        ));
    }
    let selector_kind = optional(args, "--selector-kind")
        .ok_or_else(|| {
            CliError::Usage(
                "grant requires --selector-kind exact|category (no default: the kind \
                 decides whether this grant's reach can change without you)"
                    .into(),
            )
        })?
        .parse::<SelectorKind>()
        .map_err(CliError::Usage)?;
    let selector = optional(args, "--selector")
        .ok_or_else(|| CliError::Usage("grant requires --selector".into()))?;
    Ok((selector_kind, selector))
}

fn cmd_grant(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    let (principal_kind, principal_id) = parse_grant_principal(&required(args, "--principal")?)?;
    let (selector_kind, selector) = parse_grant_selector(args)?;
    let operation = required(args, "--operation")?
        .parse::<GrantOperation>()
        .map_err(CliError::Usage)?;
    commit_admin(
        global,
        AdminOpBody::GrantCreateV2 {
            v: ADMIN_OP_SCHEMA_V2,
            principal_kind: principal_kind.clone(),
            principal_id: principal_id.clone(),
            selector_kind,
            selector: selector.clone(),
            operation,
        },
    )?;
    println!(
        "granted {principal_kind}:{principal_id} {} {}:{selector}",
        operation.as_str(),
        selector_kind.as_str()
    );
    Ok(())
}

fn cmd_revoke_grant(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    let (principal_kind, principal_id) = parse_grant_principal(&required(args, "--principal")?)?;
    let (selector_kind, selector) = parse_grant_selector(args)?;
    let operation = required(args, "--operation")?
        .parse::<GrantOperation>()
        .map_err(CliError::Usage)?;
    commit_admin(
        global,
        AdminOpBody::GrantRevokeV2 {
            v: ADMIN_OP_SCHEMA_V2,
            principal_kind: principal_kind.clone(),
            principal_id: principal_id.clone(),
            selector_kind,
            selector: selector.clone(),
            operation,
        },
    )?;
    println!(
        "revoked {principal_kind}:{principal_id} {} {}:{selector}",
        operation.as_str(),
        selector_kind.as_str()
    );
    Ok(())
}

/// Record that a named approver approved an artifact's EXACT BYTES, before a signing
/// window is opened for it.
///
/// THE HASH IS COMPUTED HERE, FROM THE FILE, and is never taken as an argument. An
/// operator-supplied hash would let the approval name bytes nobody read: the entry would
/// look identical while binding a different artifact, which is the one failure this
/// record exists to make impossible.
///
/// Prints the chain sequence so the approval can be cited by the party who publishes the
/// signature. They meet at the hash: the chain proves who approved bytes H before the
/// key was reachable, the signature proves the key signed bytes H.
fn cmd_approve(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    let id = required(args, "--id")?;
    let path = required(args, "--file")?;
    let approver = required(args, "--approver")?;

    let bytes =
        std::fs::read(&path).map_err(|e| CliError::Io(format!("read artifact {path}: {e}")))?;
    if bytes.is_empty() {
        return Err(CliError::Usage(format!(
            "artifact {path} is empty: approving zero bytes would bind a hash no \
             meaningful artifact can have"
        )));
    }
    // `ring` is already a dependency of this binary (Ed25519 key minting), so the hash
    // costs no new crate. Lowercase hex, which is what every consumer of this value
    // compares against.
    let artifact_sha256 = ring::digest::digest(&ring::digest::SHA256, &bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();

    commit_admin(
        global,
        AdminOpBody::Approval {
            v: ADMIN_OP_SCHEMA_V1,
            credential_id: id.clone(),
            artifact_sha256: artifact_sha256.clone(),
            approver: approver.clone(),
        },
    )?;
    println!("approved {artifact_sha256}");
    println!("  artifact  {path} ({} bytes)", bytes.len());
    println!("  key       {id}");
    println!("  approver  {approver}");
    println!(
        "\nRecorded BEFORE the signing window. Verify this hash matches what the \
         publisher\n signs; if they differ, the approval and the signature bind \
         different artifacts."
    );
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
    let db = store_path(global);
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
///
/// *** AN EMPTY RESULT IS AMBIGUOUS, AND IT READS LIKE GOOD NEWS. ***
///
/// This table fills only when a consumer calls `credential.report_auth_failure`. So
/// "no rows for this credential" is equally consistent with:
///
///   - the credential works and no consumer has ever been refused, and
///   - the credential is dead and its consumer does not report.
///
/// The vault cannot tell those apart from here. It never observes a provider's verdict
/// -- it hands over bytes, and only the consumer that spends them learns whether they
/// were honoured. Nothing readable in the store distinguishes a live credential from
/// one revoked an hour ago.
///
/// So an empty result establishes something about a credential ONLY for consumers
/// KNOWN to report. Establishing that is a question for the consumer's source, not for
/// this table: the reporting hook is a trait method that a consumer can leave
/// unimplemented and still compile and run, which fails silently in exactly this
/// direction. When it matters, ask the consumer and get the answer from their call
/// site rather than inferring from this table's silence.
///
/// Recorded because I nearly made that inference myself while investigating whether a
/// credential was behind a downstream failure: the empty table was the first thing I
/// reached for, and reading it as "fine" would have been wrong for a reason invisible
/// in the output.
fn cmd_events(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    let limit: u32 = optional(args, "--limit")
        .map(|s| s.parse::<u32>())
        .transpose()
        .map_err(|e| CliError::Usage(format!("--limit not an integer: {e}")))?
        .unwrap_or(20);

    let db = store_path(global);
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

    // AN EMPTY TABLE READS AS GOOD NEWS AND IS NOT. It fills only when a consumer
    // calls report_auth_failure, so silence here is equally consistent with a working
    // credential and with a dead one whose consumer does not report -- and the vault
    // cannot tell those apart, because it never sees a provider's verdict. Said in the
    // OUTPUT rather than only in the source, since an operator reads this at the
    // moment they are deciding whether a credential is the cause of something.
    if events.is_empty() {
        println!("no authentication events recorded");
        println!();
        println!("  This is NOT evidence that every credential is being honoured. Rows");
        println!("  appear only when a consumer reports a refusal, so an empty table");
        println!("  also describes a dead credential whose consumer never reports. The");
        println!("  vault hands over bytes and never learns the provider's verdict.");
        println!();
        println!("  To rule a credential in or out, ask the consumer that spends it");
        println!("  whether it calls credential.report_auth_failure -- the hook can be");
        println!("  left unimplemented and still compile and run.");
        return Ok(());
    }

    // *** THIS TABLE RECORDS FAILURES. A SUCCESSFUL REFRESH IS INVISIBLE HERE. ***
    //
    // Said in the OUTPUT because the empty-table caveats above do not cover it, and a
    // NON-empty table is the more misleading case: rows are present, so the reader
    // trusts the view, and then reasons from which kinds are absent.
    //
    // That is not hypothetical. An external operator ran this verb on my advice, saw
    // consumer_report rows and no refresh_failed rows for a credential, and concluded
    // the vault had never attempted a refresh -- a claim this table cannot support. A
    // refresh that SUCCEEDS writes `refresh_commit` to the audit chain and nothing
    // here. Absence of refresh rows means "no refresh FAILED", never "no refresh ran".
    //
    // The fault was mine: I handed over an instrument without saying what it cannot
    // contain, which is the half of a recommendation that decides what conclusions it
    // licenses.
    println!("these are FAILURES and state transitions only -- a refresh that succeeded");
    println!("writes refresh_commit to the audit chain and appears nowhere below, so the");
    println!("absence of a refresh row means 'none failed', not 'none was attempted'.");
    println!();

    type EventRow = (
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
    );
    let mut rows: Vec<EventRow> = Vec::with_capacity(events.len());
    for e in &events {
        let when = format_ts_ms(e.ts_ms);
        let what = match (e.provider_status, e.detail.as_deref()) {
            (Some(s), Some(d)) => format!("{s} {d}"),
            (Some(s), None) => s.to_string(),
            (None, Some(d)) => d.to_string(),
            (None, None) => "-".to_string(),
        };
        let principal = match (e.principal_kind.as_deref(), e.principal_id.as_deref()) {
            (Some(kind), Some(id)) => format!("{kind}:{id}"),
            (Some(kind), None) => kind.to_string(),
            (None, _) => "-".to_string(),
        };
        let version = e
            .record_version
            .map(|v| format!("v{v}"))
            .unwrap_or_else(|| "-".into());
        // The consumer-asserted source rides at the end and only when present, so
        // legacy NULL rows render exactly as before this column existed.
        let source = e
            .reporter_source
            .as_deref()
            .map(|s| format!(" src={s}"))
            .unwrap_or_default();
        rows.push((
            when,
            e.credential_id.clone(),
            e.kind.clone(),
            principal,
            what,
            version,
            if e.applied { "yes" } else { "no" }.to_string(),
            source,
        ));
    }

    // MEASURED WIDTHS, for the same reason as `grants`. The fixed `{:34} {:16} {:24} {:22}`
    // this replaced rendered every row at 155 columns against 90 of actual content -- 65
    // columns of padding for values that are never that wide. At 155 the row wraps on any
    // ordinary terminal, and a wrapped table is harder to read than an unaligned one.
    let w = |f: &dyn Fn(&EventRow) -> &str, head: &str| {
        rows.iter()
            .map(|r| f(r).chars().count())
            .chain(std::iter::once(head.chars().count()))
            .max()
            .unwrap_or(head.len())
    };
    let wc = w(&|r| r.1.as_str(), "CREDENTIAL");
    let wk = w(&|r| r.2.as_str(), "KIND");
    let wp = w(&|r| r.3.as_str(), "PRINCIPAL");
    let ww = w(&|r| r.4.as_str(), "DETAIL");
    let wv = w(&|r| r.5.as_str(), "VER");
    println!(
        "{:19}  {:wc$} {:wk$} {:wp$} {:ww$} {:wv$} APPLIED",
        "WHEN", "CREDENTIAL", "KIND", "PRINCIPAL", "DETAIL", "VER"
    );
    for (when, cred, kind, principal, what, version, applied, source) in &rows {
        println!(
            "{when}  {cred:wc$} {kind:wk$} {principal:wp$} {what:ww$} {version:wv$} applied={applied}{source}"
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

    // To see whether refreshes are happening at all, read the chain rather than this
    // table -- named here because the reader asking that question is looking at this
    // output, not at a runbook.
    println!();
    println!("to see whether a credential is being REFRESHED (as opposed to failing),");
    println!("read the audit chain for refresh_commit rows:");
    println!("  ck auth audit --limit 100     (lease-free; safe against a running vault)");

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
    // A discovered daemon still supplies authenticated `admin.status`; when none is
    // reachable, the same report is built from lease-free plaintext metadata readers.
    let (result, store_schema) = request_admin_status_with_schema(global)?;
    let rows = parse_inventory(&result)?;
    print_inventory(&rows);
    print_store_behind_note(store_schema);
    Ok(())
}

/// `ck auth enroll <list|approve|deny|revoke|reissue>` — the operator half of consumer
/// enrollment.
///
/// WITHOUT THIS THE CEREMONY IS UNREACHABLE. A consumer can propose, and the store can
/// approve, deny, revoke and reissue — but nothing could CALL those, so a pending
/// request sat in the queue forever and the vault admitted nobody. The consumer-facing
/// routes shipped first because they are what a plugin builds against; this is the half
/// that makes them mean something.
///
/// Every mutating subcommand is master-key gated (Gate 2) through `commit_admin`.
/// `list` is not: it reads the pending queue and the live roster, both plaintext, so it
/// works against a running daemon without the key and without taking the write lease.
fn cmd_enroll(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    let sub = args
        .first()
        .filter(|value| !value.starts_with("--"))
        .ok_or_else(|| {
            CliError::Usage("enroll requires a subcommand: list|approve|deny|revoke|reissue".into())
        })?
        .clone();
    let rest = &args[1..];
    match sub.as_str() {
        "list" => cmd_enroll_list(global),
        "approve" => {
            let request_id = required(rest, "--request-id")?;
            // The name defaults to what was proposed, and `--name` is how an operator
            // corrects it. A name a stranger chose is a claim, not a fact.
            let final_name = match optional(rest, "--name") {
                Some(name) => name,
                None => pending_proposed_name(global, &request_id)?,
            };
            commit_admin(
                global,
                AdminOpBody::EnrollApprove {
                    v: ADMIN_OP_SCHEMA_V2,
                    request_id: request_id.clone(),
                    final_name: final_name.clone(),
                },
            )?;
            println!("approved {request_id} as enrolled:{final_name}");
            eprintln!(
                "(no token was minted here: the consumer's own poll mints it, \
                 authenticated by the request secret it holds)"
            );
            Ok(())
        }
        "deny" => {
            let request_id = required(rest, "--request-id")?;
            commit_admin(
                global,
                AdminOpBody::EnrollDeny {
                    v: ADMIN_OP_SCHEMA_V2,
                    request_id: request_id.clone(),
                },
            )?;
            println!("denied {request_id}");
            Ok(())
        }
        "revoke" => {
            let name = required(rest, "--name")?;
            commit_admin(
                global,
                AdminOpBody::EnrollRevoke {
                    v: ADMIN_OP_SCHEMA_V2,
                    name: name.clone(),
                },
            )?;
            println!("revoked enrolled:{name}");
            eprintln!(
                "(its grants are kept and still name this principal; revoke them too \
                 before re-enrolling the name, or a different consumer inherits its reach)"
            );
            Ok(())
        }
        "reissue" => {
            let name = required(rest, "--name")?;
            let reply = commit_admin(
                global,
                AdminOpBody::EnrollReissue {
                    v: ADMIN_OP_SCHEMA_V2,
                    name: name.clone(),
                },
            )?;
            let token = reply
                .get("token")
                .and_then(|value| value.as_str())
                .ok_or_else(|| CliError::Usage("reissue returned no token".into()))?;
            // Stdout carries the token ALONE so it can be piped into a 0600 file
            // without a shell dance; everything else goes to stderr.
            println!("{token}");
            eprintln!(
                "reissued enrolled:{name} at generation {}. The previous token stopped \
                 working the moment this one was minted.",
                reply
                    .get("token_generation")
                    .and_then(|value| value.as_u64())
                    .unwrap_or_default()
            );
            Ok(())
        }
        other => Err(CliError::Usage(format!(
            "unknown enroll subcommand {other}: expected list|approve|deny|revoke|reissue"
        ))),
    }
}

/// Render pending requests and live enrollments, lease-free.
fn cmd_enroll_list(global: &GlobalArgs) -> Result<(), CliError> {
    let db = store_path(global);
    if !db.exists() {
        return Err(CliError::Usage(format!(
            "no vault at {} (run `ck auth bootstrap` first)",
            db.display()
        )));
    }
    let rows = credentials_core::store::list_enrollments_read_only(&db)
        .map_err(|error| CliError::Usage(format!("read enrollments: {error}")))?;
    if rows.is_empty() {
        println!("no pending requests and no live enrollments");
        return Ok(());
    }
    let width = rows
        .iter()
        .map(|row| row.key.chars().count())
        .max()
        .unwrap_or(3)
        .max(3);
    println!("{:<width$}  {:<13}  NAME", "KEY", "STATE", width = width);
    for row in &rows {
        let suffix = if row.token_generation > 0 {
            format!("  (generation {})", row.token_generation)
        } else {
            String::new()
        };
        println!(
            "{:<width$}  {:<13}  {}{suffix}",
            row.key,
            row.state,
            row.name,
            width = width
        );
    }
    Ok(())
}

/// Read the proposed name for a pending request so `approve` can default to it.
///
/// Reading it here rather than defaulting inside the store keeps the DECISION visible:
/// the operator sees the name in the success line and can override it with `--name`.
/// A store-side default would admit whatever a stranger proposed with nothing printed.
fn pending_proposed_name(global: &GlobalArgs, request_id: &str) -> Result<String, CliError> {
    let db = store_path(global);
    let rows = credentials_core::store::list_enrollments_read_only(&db)
        .map_err(|error| CliError::Usage(format!("read enrollments: {error}")))?;
    rows.into_iter()
        .find(|row| row.key == request_id && row.state == "pending")
        .map(|row| row.name)
        .ok_or_else(|| {
            CliError::Usage(format!(
                "no pending request {request_id} (list them with `ck auth enroll list`)"
            ))
        })
}

/// Render every category that exists, what it covers, and which grants name it.
///
/// THE OTHER HALF OF THE REACH COLUMN. That column tells an operator a grant reaches
/// nothing AFTER they create it; this tells them what is there BEFORE. Both exist because
/// a category selector fails CLOSED and SILENTLY: a grant naming a category nothing
/// carries is syntactically valid, accepted without complaint, and authorizes zero
/// credentials, which is indistinguishable from a working grant by reading it.
///
/// Not hypothetical. On 2026-09-19 a `category:llm-provider` grant was created on the live
/// vault while the only category in the store was `forge-identity` -- registry defaults
/// apply at CREATION and every credential predated the migration that introduced
/// categories. Nothing on either side said so; a consumer asking me to double-check a
/// selector is the only reason it surfaced.
///
/// UNCATEGORIZED IS A ROW, not an omission. Some credentials carry no category
/// deliberately, so hiding the count would make a FORGOTTEN assignment indistinguishable
/// from an INTENDED one -- the same silence one level up.
///
/// Lease-free, like every other read verb, and for the same reason: the moment an operator
/// asks is the moment the vault is running.
fn cmd_categories(global: &GlobalArgs) -> Result<(), CliError> {
    let (result, store_schema) = request_admin_status_with_schema(global)?;
    for line in render_categories(&result)? {
        println!("{line}");
    }
    print_store_behind_note(store_schema);
    Ok(())
}

/// Build the category table. Split from printing so a test drives the real formatter
/// rather than a hand-built copy of its arithmetic.
fn render_categories(result: &serde_json::Value) -> Result<Vec<String>, CliError> {
    let inventory = parse_credential_categories(result);
    if inventory.is_empty() {
        return Ok(vec!["no credentials".to_owned()]);
    }
    let grants = parse_grants(result)?;

    let mut counts: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    let mut uncategorized = 0usize;
    for categories in inventory.values() {
        if categories.is_empty() {
            uncategorized += 1;
            continue;
        }
        for category in categories {
            *counts.entry(category.clone()).or_default() += 1;
        }
    }

    // A category NAMED BY A GRANT but carried by no credential must appear, at zero.
    // Omitting it hides exactly the row an operator is looking for: the reach column says
    // a grant reaches nothing, and this is where they come to find out why.
    for grant in &grants {
        if grant.selector_kind == "category" {
            let name = grant
                .credential_prefix
                .strip_prefix("category:")
                .unwrap_or(&grant.credential_prefix);
            counts.entry(name.to_owned()).or_insert(0);
        }
    }

    let namers = |category: &str| -> String {
        let mut who: Vec<String> = grants
            .iter()
            .filter(|g| {
                g.selector_kind == "category"
                    && g.credential_prefix
                        .strip_prefix("category:")
                        .unwrap_or(&g.credential_prefix)
                        == category
            })
            .map(|g| format!("{}:{}", g.principal_kind, g.principal_id))
            .collect();
        who.sort();
        who.dedup();
        if who.is_empty() {
            "-".to_owned()
        } else {
            who.join(" ")
        }
    };

    let wn = counts
        .keys()
        .map(|c| c.chars().count())
        .chain(std::iter::once("CATEGORY".len()))
        .chain(std::iter::once("(uncategorized)".len()))
        .max()
        .unwrap_or(8);
    let mut lines = vec![format!(
        "{:<wn$}  {:>11}  GRANTED TO",
        "CATEGORY", "CREDENTIALS"
    )];
    for (category, count) in &counts {
        lines.push(format!(
            "{:<wn$}  {:>11}  {}",
            category,
            count,
            namers(category)
        ));
    }
    if uncategorized > 0 {
        lines.push(format!(
            "{:<wn$}  {:>11}  {}",
            "(uncategorized)", uncategorized, "-"
        ));
    }
    Ok(lines)
}

fn cmd_grants(global: &GlobalArgs) -> Result<(), CliError> {
    // Grant inventory is part of the same authenticated admin.status response as the
    // credential inventory. A discovered daemon is queried online; otherwise the same
    // sorted rows come from the lease-free plaintext reader.
    let (result, store_schema) = request_admin_status_with_schema(global)?;
    print_grants(&result)?;
    print_store_behind_note(store_schema);
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

    let db = store_path(global);
    if !db.exists() {
        return Err(CliError::Usage(format!(
            "no vault at {} (run 'ck auth bootstrap' first)",
            global.data_dir.display()
        )));
    }
    warn_unsafe_opencode_tombstones();
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
    let mut declared_expired = 0;
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
                    "  {id:34} oauth   {}  account={}  STRANDED: no access token and no refresh token",
                    row.state,
                    row.account_id.as_deref().unwrap_or("none")
                );
                stranded += 1;
            }
            Usability::Static {
                expires_at_ms,
                written_at_ms,
            } => {
                // AGE, not a lifetime claim. For a static record nothing but an
                // operator write moves this column -- no refresh touches the row -- so
                // elapsed time since it is exactly "how long since a human last put
                // this". It says nothing about whether the provider still honours the
                // credential, and deliberately does not try to.
                let age_days = (now - written_at_ms) / 86_400_000;
                // A declared expiry is the ONLY forward-looking signal a
                // non-refreshable credential can carry, and it is the operator's own
                // statement rather than the provider's -- so a key past it is called
                // out as DECLARED dead, not proven dead. Counted separately from
                // serviceable because an audit that folds it in tells an operator
                // everything is fine while a credential they themselves marked
                // short-lived sits a day past its date.
                if credentials_core::usable::static_past_declared_expiry(*expires_at_ms, now) {
                    let mins = (now - expires_at_ms.unwrap_or(now)) / 60_000;
                    println!(
                        "  {id:34} static  {}  DECLARED EXPIRED {mins}m ago: no refresh \
                         path, so only a re-put replaces it",
                        row.state
                    );
                    declared_expired += 1;
                } else {
                    let ttl = match expires_at_ms {
                        Some(exp) => format!("declared good for {}m", (exp - now) / 60_000),
                        None => "no expiry declared".to_string(),
                    };
                    println!(
                        "  {id:34} static  {}  written {age_days}d ago, {ttl}",
                        row.state
                    );
                    serviceable += 1;
                }
            }
            Usability::Cookie { written_at_ms } => {
                let age_days = (now - written_at_ms) / 86_400_000;
                println!(
                    "  {id:34} cookie  {}  session cookie captured {age_days}d ago; \
                     age is a staleness signal, re-capture after provider rejection",
                    row.state
                );
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
                println!(
                    "  {id:34} oauth   {}  account={}{}  {ttl}",
                    row.state,
                    row.account_id.as_deref().unwrap_or("none"),
                    // Only when it says something the account id does not -- the scan
                    // suppresses an email equal to it, so this appends exactly where a
                    // provider uuid would otherwise leave five accounts indistinguishable.
                    row.email
                        .as_deref()
                        .map(|email| format!(" ({email})"))
                        .unwrap_or_default()
                );
                serviceable += 1;
            }
        }
    }

    println!();
    println!(
        "  serviceable: {serviceable}   declared expired: {declared_expired}   \
         stranded: {stranded}   unreadable: {unreadable}   \
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

fn warn_unsafe_opencode_tombstones() {
    let auth_path = opencode_files::default_auth_path();
    if !auth_path.exists() {
        return;
    }
    let entries = match opencode_files::read_auth_entries(&auth_path) {
        Ok(entries) => entries,
        Err(error) => {
            println!(
                "WARN: OpenCode auth file {} could not be inspected for unsafe custody tombstones: {error}",
                auth_path.display()
            );
            return;
        }
    };
    for (provider, entry) in entries {
        if !opencode_migration::is_api_tombstone(&entry, &provider) {
            continue;
        }
        match opencode_migration::unsafe_provider_shape(&provider) {
            Ok(Some(shape)) => println!(
                "WARN: OpenCode tombstone provider={provider} shape={} why={} source={}; run ck auth migrate-opencode --restore {provider}",
                shape.shape_names(),
                shape.why(),
                shape.sites(),
            ),
            Ok(None) => {}
            Err(error) => println!(
                "WARN: OpenCode provider shape table could not classify {provider}: {error}"
            ),
        }
    }
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
    let db = store_path(global);
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
///
/// THAT BYTE-FOR-BYTE CLAIM IS NOW FENCED, and it was not before. It spans two
/// repositories, so no test's natural scope reached it -- the exact shape that
/// survives review because it reads as reasoning rather than as a property. The
/// daemon publishes a golden fixture for its own rule; this repo vendors it and
/// asserts against it (see `tests/fixtures/data_home` and the test below).
///
/// Why a duplicate at all, rather than calling a shared crate: `cortexkit-store-types`
/// offers `resolve_data_home()`, and on 2026-08-21 its rules DIFFERED from the
/// daemon's -- no Windows branch, and relative `XDG_DATA_HOME` rejected. Adopting the
/// shared implementation would have broken a correct alignment. It has since been
/// corrected to mirror the daemon, but the lesson stands: THE SHARED IMPLEMENTATION
/// IS NOT AUTOMATICALLY THE AUTHORITATIVE ONE. What matters is tracking whoever
/// actually builds the storage descriptor, which is the daemon.
fn default_data_home() -> PathBuf {
    resolve_data_home_from(
        non_empty_env("XDG_DATA_HOME"),
        non_empty_env("APPDATA"),
        non_empty_env("USERPROFILE"),
        non_empty_env("HOME"),
    )
}

/// The resolution rule itself, with the environment passed in.
///
/// Split out so the golden fixture can drive it directly. Driving it through real
/// environment variables would mutate process-global state, which races every other
/// test in the binary -- and a test that must run alone is one that quietly stops
/// running.
///
/// Takes RAW values rather than pre-filtered ones so that empty-means-unset is under
/// test: the fixture pins `XDG_DATA_HOME=""` falling through to `HOME`, and a caller
/// that filtered first would assert nothing about it.
fn resolve_data_home_from(
    xdg: Option<std::ffi::OsString>,
    appdata: Option<std::ffi::OsString>,
    userprofile: Option<std::ffi::OsString>,
    home: Option<std::ffi::OsString>,
) -> PathBuf {
    let present = |v: Option<std::ffi::OsString>| v.filter(|s| !s.is_empty());
    if let Some(v) = present(xdg) {
        return PathBuf::from(v);
    }
    #[cfg(windows)]
    {
        if let Some(v) = present(appdata) {
            return PathBuf::from(v);
        }
        if let Some(v) = present(userprofile) {
            return PathBuf::from(v).join("AppData").join("Roaming");
        }
    }
    #[cfg(not(windows))]
    {
        let _ = (&appdata, &userprofile);
    }
    if let Some(v) = present(home) {
        return PathBuf::from(v).join(".local").join("share");
    }
    PathBuf::from(".local").join("share")
}

/// Discover the subc connection file the way the `ck` dispatcher does:
/// `$XDG_RUNTIME_DIR/subc-connection.json`, else the production location
/// `~/.local/share/cortexkit/run/subc-connection.json`. Only an EXISTING file is
/// returned — no daemon means the offline lease path, which is the correct
/// fallback, not an error.
/// The vault store's path under a data directory.
///
/// One site rather than five identical `join("store.db")` calls. The filename is not
/// this CLI's to choose -- the daemon opens it through `cortexkit-store` from the same
/// data dir -- so a literal repeated per read verb is five places for a rename to land
/// in four. Unlike the connection-file rung above, there is no second authority here
/// that would make the duplication correct.
fn store_path(global: &GlobalArgs) -> PathBuf {
    global.data_dir.join("store.db")
}

fn discover_subc_connection_file() -> Option<PathBuf> {
    const CONNECTION_FILE_NAME: &str = "subc-connection.json";

    // SUBC_CONNECTION_FILE NAMES THE DAEMON THE CALLER MEANS, SO IT IS EXCLUSIVE RATHER
    // THAN FIRST-IN-A-LIST -- matching `ck`'s own reader, re-derived at source
    // 2026-09-05 from subc-core's `connection_file_candidates_with` in bin/ck.rs.
    //
    // This ladder is a COPY of that one and cannot be a call: subc-core exposes the
    // WRITER's helper, which resolves to the temp fallback rather than searching, so
    // calling it would answer about a path the daemon would write rather than the one it
    // wrote. A copied ladder diverges SILENTLY -- nothing links the two, no test can
    // compare them, and the failure is that this CLI looks where `ck` does not.
    //
    // IT HAD ALREADY DIVERGED. This arm was absent until 2026-09-05: an operator who set
    // SUBC_CONNECTION_FILE to name a rig fell through to discovery and reached whichever
    // daemon was found -- in practice production. For a read verb that is a true answer
    // about the wrong machine; for `put`, `login` or `invalidate` it is a credential
    // written into the wrong vault, with both stores looking healthy afterwards.
    //
    // Exclusive, not first-tried, for the reason subc gives: a value that is set and
    // wrong must FAIL rather than fall back, or honouring it is indistinguishable from
    // ignoring it. Returning it unconditionally keeps the existing not-found path, which
    // names the file it could not read.
    if let Some(named) = non_empty_env("SUBC_CONNECTION_FILE") {
        return Some(PathBuf::from(named));
    }

    if let Some(runtime_dir) = non_empty_env("XDG_RUNTIME_DIR") {
        let p = PathBuf::from(runtime_dir).join(CONNECTION_FILE_NAME);
        if p.is_file() {
            return Some(p);
        }
    }
    // *** THIS REBUILDS THE PREFIX `default_data_home()` DERIVES TWELVE LINES ABOVE, AND
    // THAT DUPLICATION IS CORRECT. DO NOT COLLAPSE THEM. ***
    //
    // They look like one behaviour written twice and they answer different questions:
    //
    //   default_data_home()   where THIS MODULE's data lives -- XDG_DATA_HOME first,
    //                         then the Windows AppData rungs, then HOME/.local/share
    //   this rung             where `ck` LOOKS for a connection file -- HOME only,
    //                         matching subc-core's PROD_CONNECTION_RELATIVE_PATH
    //
    // `ck`'s reader consults HOME and does NOT consult XDG_DATA_HOME for this rung
    // (bin/ck.rs, `connection_file_candidates_with`, re-derived at source 2026-09-05).
    // So routing this through `default_data_home()` would make the CLI look somewhere
    // `ck` never looks the moment an operator sets XDG_DATA_HOME -- reintroducing the
    // looks-where-ck-does-not class that the SUBC_CONNECTION_FILE rung above was added
    // to close, in the same function, by way of tidying.
    //
    // Recorded because a duplicate-value audit REPORTS THIS PAIR, and the obvious
    // remedy is the defect. A reported duplicate is a candidate until it is resolved
    // against the other side's authority; these two have different authorities.
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
    temp_dir_connection_file()
}

/// The daemon's LAST-RESORT location: when `XDG_RUNTIME_DIR` is unset, subc writes
/// `<temp>/subc-<user-token>.connection.json` (bootstrap.rs `connection_file_path`).
///
/// This arm exists because a CLI that misses it does not fail loudly -- it silently
/// concludes no daemon is running, takes the offline path, hits the single-writer
/// lease, and tells the operator to STOP THE DAEMON. The remedy it names is the one
/// thing they should not do, and the `--subc` route that would have worked is never
/// mentioned. Reported from a real box, and STOCK MACOS sets no `XDG_RUNTIME_DIR`,
/// so it is the default there rather than an edge case; this machine only avoids it
/// because something sets that variable explicitly.
///
/// It GLOBS rather than recomputing the name. The token comes from
/// `user_connection_token()`, whose unix arm derives a uid by WRITING A PROBE FILE --
/// side-effecting, several fallbacks deep, and silently wrong if reimplemented a
/// little differently. Asking the filesystem what exists needs none of that and
/// survives any future change to the naming scheme.
///
/// Ambiguity REFUSES rather than guessing: on a shared temp dir the token exists
/// precisely so different OS users do not collide, so more than one match means the
/// files belong to different users and picking one could point an admin op at
/// another user's daemon.
fn temp_dir_connection_file() -> Option<PathBuf> {
    let dir = std::env::temp_dir();

    // THE EXACT PATH FIRST, FROM THE SIBLING'S OWN DERIVATION. `user_connection_token`
    // is the token the daemon uses when it writes this file (subc-transport 0.6.0), so
    // calling it names the file rather than searching for something shaped like it.
    // This rung is a CALL and therefore needs no date: if subc changes the token, this
    // stops compiling or stops matching loudly rather than quietly finding the wrong
    // file.
    let exact = dir.join(format!(
        "subc-{}.connection.json",
        subc_transport::user_connection_token()
    ));
    if exact.is_file() {
        return Some(exact);
    }

    // THE GLOB STAYS AS A FALLBACK, AND IT IS NOT REDUNDANT. It exists for the states
    // an exact lookup cannot describe: an unreadable temp directory, and MORE THAN ONE
    // connection file, where guessing picks a daemon at random. Those were built for a
    // real report -- a CLI that concluded "no daemon" from an I/O error took the offline
    // path and told the operator to stop a daemon that was serving. An exact miss is
    // silent by construction, so dropping this would trade a diagnostic for a shrug.
    match connection_file_in(&dir) {
        ConnectionSearch::Found(p) => Some(p),
        // The ordinary answer: no daemon, take the offline path silently.
        ConnectionSearch::NotPresent => None,
        ConnectionSearch::Unreadable(e) => {
            eprintln!(
                "note: could not read {} while looking for a running daemon ({e}). \
                 Proceeding as if none is running; if one IS running, pass \
                 --subc <connection-file> rather than stopping it.",
                dir.display()
            );
            None
        }
        ConnectionSearch::Ambiguous(found) => {
            eprintln!(
                "note: {} subc connection files in {} -- not guessing which daemon is \
                 yours. Pass --subc <connection-file> to choose:",
                found.len(),
                dir.display()
            );
            for p in &found {
                eprintln!("  {}", p.display());
            }
            None
        }
    }
}

/// What a search of one directory found. An ENUM rather than `Option` because the
/// three outcomes need different operator responses and `None` erases the difference:
/// "nothing here" is the ordinary no-daemon case, while "could not look" and "several
/// candidates" both mean a running daemon may be reachable and the offline path is
/// about to give bad advice.
///
/// The distinction lives in the TYPE, not in an eprintln, for a reason measured on
/// this very function: with both arms returning `None`, a test asserting `None`
/// passes whether the error is reported or discarded -- I wrote exactly that test,
/// claimed it was mutation-proof in its own comment, and the mutation survived.
/// A difference only visible on stderr is a difference no test can hold.
#[derive(Debug, PartialEq)]
enum ConnectionSearch {
    Found(PathBuf),
    /// Directory readable, no candidate present. The ordinary "no daemon" answer.
    NotPresent,
    /// The directory could not be read. NOT the same as absent: an inability to get
    /// an answer is not an answer, and treating it as one sends the caller offline
    /// into a lease refusal whose advice is to stop a daemon that may be serving.
    Unreadable(String),
    /// Several candidates. The per-user token exists so different OS users do not
    /// collide, so more than one means they belong to different users and picking
    /// one could point an admin op at someone else's daemon.
    Ambiguous(Vec<PathBuf>),
}

/// The searchable half, split out so every arm can be TESTED.
///
/// Driving this through the CLI cannot reach it: auto-discovery is gated on
/// `--data-dir` being defaulted, so any invocation that pins a data dir -- which a
/// test must, to avoid touching the operator's vault -- skips discovery entirely.
/// Three probes read as clean before I noticed the gate was mine.
fn connection_file_in(dir: &std::path::Path) -> ConnectionSearch {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => return ConnectionSearch::Unreadable(e.to_string()),
    };
    let mut found: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("subc-") && n.ends_with(".connection.json"))
                && p.is_file()
        })
        .collect();
    match found.len() {
        1 => ConnectionSearch::Found(found.pop().expect("len checked")),
        0 => ConnectionSearch::NotPresent,
        _ => {
            found.sort();
            ConnectionSearch::Ambiguous(found)
        }
    }
}

#[cfg(test)]
mod discovery_tests {
    /// SERIALISES THE TESTS THAT MUTATE PROCESS-GLOBAL ENVIRONMENT.
    ///
    /// `set_var`/`remove_var` are process-wide and cargo runs unit tests on parallel
    /// threads, so two tests in this module touching `SUBC_CONNECTION_FILE` interleave:
    /// one clears the variable the other just set, the cleared side falls through to
    /// discovery, and it fails claiming a fallback happened. The failure is TRUE about
    /// what the function did and FALSE about why, which is what makes it expensive --
    /// it reads as a defect in the exclusivity rung rather than as a racing neighbour.
    ///
    /// *** OBSERVED, NOT ANTICIPATED. *** The same commit passed on its train branch and
    /// failed on master minutes later -- identical sha, opposite outcomes, which is the
    /// signature of a race rather than a platform difference. The duplicate master run I
    /// had just called "buying nothing" is what surfaced it.
    ///
    /// A mutex rather than `--test-threads=1`: the flag is invisible at the call site and
    /// a future runner without it silently reintroduces the race.
    static ENV_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Take the environment guard, surviving a poisoned lock.
    ///
    /// A panicking test poisons the mutex; without this, every later test in the module
    /// fails on the poison rather than on its own subject, turning one real failure into
    /// a wall of misattributed ones.
    fn env_guard() -> std::sync::MutexGuard<'static, ()> {
        ENV_GUARD.lock().unwrap_or_else(|e| e.into_inner())
    }

    use super::{
        connection_file_in, discover_subc_connection_file, temp_dir_connection_file,
        ConnectionSearch,
    };

    /// An unreadable directory must not read as "no daemon is running".
    ///
    /// The arm this covers was `.ok()?` -- a real I/O error discarded and returned as
    /// the same `None` an empty directory produces, so the caller took the offline
    /// path, hit the single-writer lease, and told the operator to STOP THE DAEMON.
    ///
    /// This assertion discriminates because the outcomes are different VARIANTS.
    /// Mutation-verified: collapsing the error arm back to a not-present result reds
    /// this by name. The earlier `Option`-returning version of this same test survived
    /// that mutation, which is why the enum exists.
    #[test]
    fn an_unreadable_search_dir_is_not_reported_as_absent() {
        let missing = std::path::Path::new("/definitely/not/a/real/dir/ckcred-probe");
        assert!(
            !missing.exists(),
            "probe path must not exist or this proves nothing"
        );
        assert!(
            matches!(connection_file_in(missing), ConnectionSearch::Unreadable(_)),
            "an unreadable directory must be distinguishable from an empty one"
        );
    }

    /// The temp rung names the daemon's file rather than searching for its shape.
    ///
    /// TWO matching files, deliberately. With one file this test PASSES WITH THE EXACT
    /// RUNG DELETED, because the glob below finds the same path -- I wrote that version
    /// first and mutation caught it, which is the silent-success the rung exists to
    /// avoid, pointed at its own test. With two, the glob refuses as Ambiguous rather
    /// than guessing a daemon, so only subc's own derivation can answer and the
    /// assertion is about the CALL.
    #[test]
    fn the_temp_rung_finds_subcs_derived_name_where_the_glob_cannot() {
        let _env = env_guard();
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "ck-tmprung-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).expect("root");

        let derived = root.join(format!(
            "subc-{}.connection.json",
            subc_transport::user_connection_token()
        ));
        std::fs::write(&derived, "{}").expect("the daemon-shaped file");
        // A second daemon's file: same shape, different token. The glob sees two.
        std::fs::write(root.join("subc-otheruser.connection.json"), "{}").expect("second");

        // ALL THREE, because `env::temp_dir()` reads TMPDIR on unix and TMP/TEMP on
        // windows. Setting only TMPDIR redirects on macOS and linux and SILENTLY DOES
        // NOT on windows, so the test would pass here and assert nothing there -- which
        // is exactly what it did until CI said so. Third instance of this class today.
        let prev: Vec<(&str, Option<std::ffi::OsString>)> = ["TMPDIR", "TMP", "TEMP"]
            .iter()
            .map(|k| (*k, std::env::var_os(k)))
            .collect();
        let prev_named = std::env::var_os("SUBC_CONNECTION_FILE");
        for (k, _) in &prev {
            std::env::set_var(k, &root);
        }
        std::env::remove_var("SUBC_CONNECTION_FILE");

        let got = temp_dir_connection_file();

        for (k, v) in prev {
            match v {
                Some(v) => std::env::set_var(k, v),
                None => std::env::remove_var(k),
            }
        }
        if let Some(v) = prev_named {
            std::env::set_var("SUBC_CONNECTION_FILE", v);
        }
        let _ = std::fs::remove_dir_all(&root);

        assert_eq!(
            got.as_deref(),
            Some(derived.as_path()),
            "with two candidates the glob refuses, so only subc's derived name can answer; \
             a miss means the token derivation drifted"
        );
    }

    /// `SUBC_CONNECTION_FILE` must be EXCLUSIVE, matching `ck`'s own reader.
    ///
    /// The hazard is not that the variable is ignored -- it is that ignoring it looks
    /// like honouring it. A caller who names a rig and silently reaches production gets
    /// a true answer about the wrong machine, and for a write verb a credential in the
    /// wrong vault. So the assertion is that the named path is returned even when it
    /// does NOT exist and a discoverable file DOES: falling back on a set-and-wrong
    /// value is the defect, not a convenience.
    #[test]
    fn subc_connection_file_is_exclusive_and_does_not_fall_back() {
        let _env = env_guard();
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "ck-conn-excl-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let runtime = root.join("runtime");
        std::fs::create_dir_all(&runtime).expect("runtime dir");
        let discoverable = runtime.join("subc-connection.json");
        std::fs::write(&discoverable, "{}").expect("discoverable file");

        let named = root.join("rig").join("subc-connection.json");

        let prev_named = std::env::var_os("SUBC_CONNECTION_FILE");
        let prev_runtime = std::env::var_os("XDG_RUNTIME_DIR");
        std::env::set_var("SUBC_CONNECTION_FILE", &named);
        std::env::set_var("XDG_RUNTIME_DIR", &runtime);

        let got = discover_subc_connection_file();

        match prev_named {
            Some(v) => std::env::set_var("SUBC_CONNECTION_FILE", v),
            None => std::env::remove_var("SUBC_CONNECTION_FILE"),
        }
        match prev_runtime {
            Some(v) => std::env::set_var("XDG_RUNTIME_DIR", v),
            None => std::env::remove_var("XDG_RUNTIME_DIR"),
        }
        let _ = std::fs::remove_dir_all(&root);

        assert_eq!(
            got.as_deref(),
            Some(named.as_path()),
            "a named connection file must win outright; falling back to the discoverable \
             one at {} would answer about a different daemon",
            discoverable.display()
        );
    }

    /// POSITIVE CONTROL for the test above: a readable directory with no candidates
    /// must be NotPresent, so the Unreadable assertion cannot pass by everything
    /// returning the same variant.
    #[test]
    fn a_readable_dir_without_candidates_is_not_present() {
        let empty = std::env::temp_dir().join(format!("ckcred-empty-{}", std::process::id()));
        std::fs::create_dir_all(&empty).unwrap();
        let got = connection_file_in(&empty);
        let _ = std::fs::remove_dir_all(&empty);
        assert_eq!(got, ConnectionSearch::NotPresent);
    }
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

fn browser_open_allowed(args: &[String]) -> bool {
    !has_flag(args, "--no-browser")
}

/// Best-effort open of a URL in the operator's default browser. A failure is ignored
/// by the caller — the URL is also printed, so the login still works if this no-ops.
/// Headless sessions can refuse the spawn before any platform command is constructed.
/// Never passes the URL through a shell (no injection surface).
fn open_in_browser(args: &[String], url: &str) -> std::io::Result<()> {
    if !browser_open_allowed(args) {
        return Ok(());
    }
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
    // `as_chunks` over `chunks_exact` so the pair is a `[u8; 2]`. The remainder is
    // provably empty: the length guard above requires exactly 64 bytes.
    let (pairs, _remainder) = hex.as_bytes().as_chunks::<2>();
    for (i, chunk) in pairs.iter().enumerate() {
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
    #[test]
    fn no_browser_flag_refuses_the_platform_browser_spawn() {
        assert!(super::browser_open_allowed(&[]));
        assert!(!super::browser_open_allowed(&["--no-browser".to_string()]));
    }

    /// A client-side failure must not speak in the module's voice.
    ///
    /// DRIVES THE PRODUCTION DECISION, not a hand-built variant. The first version of
    /// this test constructed `CliError::LocalFailure` itself and asserted its Display --
    /// which verifies the test's own copy of the classification. Mutation proved it
    /// worthless: putting the key-resolution failure back on `RouteCommit::Refused`, the
    /// exact defect, left all 26 tests green.
    ///
    /// So it calls `resolve_signing_key` with a key path that cannot resolve, which is
    /// the real arm an operator hits when the login keychain is locked.
    ///
    /// BOTH DIRECTIONS. A change making every refusal sound local would pass a one-armed
    /// test and lose the distinction the other way, so a genuine module refusal must
    /// still name the module.
    #[test]
    fn a_local_failure_does_not_claim_the_module_refused_and_a_real_refusal_still_does() {
        let config = credentials_core::resolver::ResolverConfig {
            source: credentials_core::resolver::KeySource::OperatorPath {
                path: std::path::PathBuf::from("/nonexistent/claustrum-test/master.key"),
            },
            data_dir: std::path::PathBuf::from("/nonexistent/claustrum-test"),
        };
        let key_id = credentials_core::key::KeyId::from_hex("0123456789abcdef")
            .expect("a well-formed key id");

        let rendered = match admin_client::resolve_signing_key(&config, key_id) {
            Err(admin_client::RouteCommit::LocalFailure(m)) => {
                CliError::LocalFailure(m).to_string()
            }
            Err(other) => panic!(
                "an unresolvable key is a LOCAL failure; classifying it as anything else \
                 puts words in the daemon's mouth (got {})",
                match other {
                    admin_client::RouteCommit::Refused(m) => format!("Refused({m})"),
                    admin_client::RouteCommit::NoLiveModule(m) => format!("NoLiveModule({m})"),
                    admin_client::RouteCommit::Indeterminate(m) => format!("Indeterminate({m})"),
                    _ => "Committed".to_string(),
                }
            ),
            Ok(_) => panic!("a key path that does not exist must not resolve"),
        };
        assert!(
            !rendered.contains("module refused"),
            "a failure that never left this machine must not blame the daemon: {rendered}"
        );
        assert!(
            rendered.contains("nothing was sent"),
            "and it must say the op was never dispatched, since that decides whether \
             there is any module state to inspect: {rendered}"
        );

        let remote = CliError::RouteRefused("gate 1: principal is not direct".into()).to_string();
        assert!(
            remote.contains("module refused"),
            "a real refusal must still name the module, or the distinction is lost the \
             other way: {remote}"
        );
    }

    /// This CLI's data-home rule conforms to the daemon's own golden fixture.
    ///
    /// The doc comment on `default_data_home` has always claimed byte-for-byte
    /// equivalence with subc's resolver. Nothing tested it: the claim spans two
    /// repositories, so no test's natural scope contained it, and it would have gone
    /// on reading as true for as long as nobody re-derived it. If it were ever false
    /// the CLI would compute a different vault directory than the daemon serves --
    /// and because that directory derives the keychain service name and the admin
    /// transcript id, the visible symptom is `vault_locked` on an intact store, not
    /// a wrong path.
    ///
    /// The fixture is AUTHORED BY THE DAEMON and vendored here (see
    /// `tests/fixtures/data_home/VENDORED.md`). A conformance fixture written on this
    /// side would agree with whatever this side expects, which is the failure this
    /// repo has already paid for three times in key-container parsing.
    ///
    /// Platform rows are split by `cfg` rather than parameterised: that keeps the test
    /// on the REAL production path with real `PathBuf` join semantics, and CI runs
    /// both Ubuntu and Windows on every push, so every row executes on every push.
    /// Refuses on an empty selection, because a filter that silently matches nothing
    /// passes exactly like a conforming implementation.
    #[test]
    fn the_data_home_rule_conforms_to_the_daemons_golden_fixture() {
        let raw = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/data_home/data_home_resolution.json"),
        )
        .expect("vendored golden fixture");
        let doc: serde_json::Value = serde_json::from_str(&raw).expect("fixture parses");

        let mut ran = 0usize;
        for case in doc["cases"].as_array().expect("cases array") {
            let platform = case["platform"].as_str().expect("platform");
            let applies = match platform {
                "any" => true,
                "windows" => cfg!(windows),
                "unix" => !cfg!(windows),
                other => panic!("unknown platform in fixture: {other}"),
            };
            if !applies {
                continue;
            }
            ran += 1;

            let env = &case["env"];
            let var = |k: &str| {
                env.get(k)
                    .and_then(|v| v.as_str())
                    .map(std::ffi::OsString::from)
            };

            let got = super::resolve_data_home_from(
                var("XDG_DATA_HOME"),
                var("APPDATA"),
                var("USERPROFILE"),
                var("HOME"),
            );
            assert_eq!(
                got.to_string_lossy(),
                case["expect"].as_str().expect("expect"),
                "case {}: this CLI diverges from the daemon's rule, which means it \
                 would derive a different vault directory than the daemon serves",
                case["name"].as_str().unwrap_or("?")
            );
        }

        assert!(
            ran > 0,
            "no fixture rows applied to this platform -- a conformance test that \
             matches nothing passes exactly like a conforming implementation"
        );
    }

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
        assert!(reject_unknown_args(
            "grant",
            &v(&[
                "--principal",
                "prefrontal-core",
                "--prefix",
                "github_app:",
                "--operation",
                "read",
            ])
        )
        .is_ok());
        assert!(reject_unknown_args(
            "revoke-grant",
            &v(&[
                "--principal",
                "prefrontal-core",
                "--prefix",
                "github_app:",
                "--operation",
                "sign",
            ])
        )
        .is_ok());
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
        assert!(reject_unknown_args(
            "grant",
            &v(&[
                "--principal",
                "prefrontal-core",
                "--prefix",
                "github_app:",
                "--op",
                "read"
            ])
        )
        .is_err());
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
            vec![(
                "active".to_string(),
                7,
                "apikey:test".to_string(),
                Vec::new(),
            )]
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

#[cfg(test)]
mod taxonomy_cli_tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    /// A GRANT THAT REACHES NOTHING SAYS SO.
    ///
    /// Written because it happened on the live vault: a `category:llm-provider` grant was
    /// created while NO credential carried that category, because registry defaults apply
    /// at creation and every credential predated the migration that introduced
    /// categories. It was syntactically valid, accepted without complaint, authorized
    /// nothing, and rendered identically to a working grant — every other column shows
    /// what the operator TYPED. A consumer asking me to double-check a selector is the
    /// only reason it was caught.
    ///
    /// Both arms matter and they fail differently. Without the zero arm, a renderer that
    /// hardcoded a plausible count passes. Without the non-zero arm, a renderer that
    /// printed 0 for everything passes — and that is the likelier defect, because a reach
    /// computation that silently matches nothing is what a selector-format change would
    /// produce.
    #[test]
    fn the_grant_table_reports_what_each_row_actually_reaches() {
        let reply = serde_json::json!({
            "credentials": [
                { "id": "apikey:one", "state": "active", "categories": ["llm-provider"] },
                { "id": "apikey:two", "state": "active", "categories": ["llm-provider"] },
                { "id": "signing:x:1", "state": "active", "categories": [] },
            ],
            "read_grants": [
                { "principal_kind": "reserved", "principal_id": "m", "selector_kind": "category",
                  "credential_prefix": "llm-provider", "operation": "read", "created_at_ms": 0 },
                { "principal_kind": "reserved", "principal_id": "m", "selector_kind": "category",
                  "credential_prefix": "no-such-category", "operation": "read", "created_at_ms": 0 },
                // Sorted, because an existing guard refuses an unsorted grant set: the
                // order is the operator's reach audit and a shuffled one hides a diff.
                { "principal_kind": "reserved", "principal_id": "m", "selector_kind": "exact",
                  "credential_prefix": "signing:x", "operation": "sign", "created_at_ms": 0 },
                { "principal_kind": "reserved", "principal_id": "m", "selector_kind": "exact",
                  "credential_prefix": "signing:x:1", "operation": "sign", "created_at_ms": 0 },
            ],
        });
        let lines = render_grants(&reply).expect("render");
        let reaches = |selector: &str| -> String {
            let line = lines
                .iter()
                .find(|l| l.split_whitespace().nth(3) == Some(selector) && !l.starts_with("KIND"))
                .unwrap_or_else(|| panic!("no row for {selector:?} in:\n{}", lines.join("\n")));
            line.split_whitespace()
                .nth(5)
                .unwrap_or_default()
                .to_owned()
        };
        assert_eq!(reaches("llm-provider"), "2", "two credentials carry it");
        assert_eq!(
            reaches("no-such-category"),
            "0",
            "the defect this exists for: valid, accepted, authorizes nothing"
        );
        assert_eq!(reaches("signing:x:1"), "1");
        assert_eq!(
            reaches("signing:x"),
            "0",
            "exact is byte equality: a prefix of a real id reaches nothing, which is the \
             narrowing the selector vocabulary exists to make visible"
        );
    }

    #[test]
    fn grant_principal_and_selector_parsers_pin_legacy_and_v2_forms() {
        // A BARE ID MEANS `reserved`, which is the narrower of the two kinds. A typo
        // that drops the prefix must not silently grant to an enrolled consumer.
        assert_eq!(
            parse_grant_principal("agent").unwrap(),
            ("reserved".to_string(), "agent".to_string())
        );
        assert_eq!(
            parse_grant_principal("reserved:agent").unwrap(),
            ("reserved".to_string(), "agent".to_string())
        );
        assert_eq!(
            parse_grant_principal("enrolled:anthropic-auth").unwrap(),
            ("enrolled".to_string(), "anthropic-auth".to_string())
        );
        // `direct` is refused rather than merely unknown: a grant to an unattested
        // caller is a grant to every same-UID process, with nothing to revoke.
        for invalid in [
            "direct:agent",
            "reserved:a|b",
            "enrolled:a|b",
            "enrolled:",
            "",
        ] {
            assert!(parse_grant_principal(invalid).is_err(), "{invalid:?}");
        }

        // `--prefix` is REFUSED, not aliased to exact. Aliasing would succeed while
        // granting nothing: `apikey:` reached seventeen credentials as a prefix and
        // names none of them exactly, so the operator would believe they granted a
        // family and hold a row covering zero.
        let legacy = args(&["--prefix", "apikey:"]);
        let refusal = parse_grant_selector(&legacy).expect_err("--prefix must refuse");
        assert!(
            format!("{refusal}").contains("--prefix is gone"),
            "the refusal must name the flag and route to the replacement, not fail \
             generically: got {refusal}"
        );

        let category = args(&["--selector-kind", "category", "--selector", "llm-provider"]);
        assert_eq!(
            parse_grant_selector(&category).unwrap(),
            (SelectorKind::Category, "llm-provider".to_string())
        );
        let exact = args(&["--selector-kind", "exact", "--selector", "apikey:exa"]);
        assert_eq!(
            parse_grant_selector(&exact).unwrap(),
            (SelectorKind::Exact, "apikey:exa".to_string())
        );

        // No default: omitting the kind must refuse rather than choose reach for the
        // operator.
        let no_kind = args(&["--selector", "apikey:exa"]);
        let kind_refusal = parse_grant_selector(&no_kind)
            .expect_err("--selector-kind is required with no default");
        assert!(
            format!("{kind_refusal}").contains("--selector-kind"),
            "got {kind_refusal}"
        );
        assert!(parse_grant_selector(&args(&["--selector-kind", "exact"])).is_err());
    }

    #[test]
    fn grant_rows_accept_v1_without_selector_kind_and_v2_with_it() {
        let v1 = serde_json::json!({
            "read_grants": [{
                "principal_kind": "reserved",
                "principal_id": "agent",
                "credential_prefix": "apikey:",
                "operation": "read",
                "created_at_ms": 1,
                "covered_credential_ids": []
            }]
        });
        assert_eq!(parse_grants(&v1).unwrap()[0].selector_kind, "exact");
        let v2 = serde_json::json!({
            "read_grants": [{
                "principal_kind": "reserved",
                "principal_id": "agent",
                "selector_kind": "category",
                "credential_prefix": "llm-provider",
                "operation": "read",
                "created_at_ms": 1,
                "covered_credential_ids": []
            }]
        });
        assert_eq!(parse_grants(&v2).unwrap()[0].selector_kind, "category");
    }
}
