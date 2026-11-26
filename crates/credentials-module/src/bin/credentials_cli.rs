#![forbid(unsafe_code)]

//! The claustrum admin CLI (`ck auth`).
//!
//! This operator write surface is master-key-gated by STRUCTURE, not a
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
//! mints a master key from the operating system's secure random generator into the
//! configured store.
//!
//! Commands:
//!
//! ```text
//!   bootstrap                                  provision a new master key
//!   put       --id <id> [--payload-file <path> | --generate-hex <n>]
//!             [--kind api_key|dsn|opaque] [--expires-ms N] [--category <name>]... [--replace]
//!             cookie:<domain> records are always `CredentialKind::Cookie`, preserve
//!             `--payload-file` bytes exactly, and do not accept `--expires-ms`.
//!   mint-signing-key --id signing:<provider>[:<generation>] [--replace] [--audit-each-signature] [--operator-sign]
//!   sign --id <id> --payload-file <path|->
//!   import    --source opencode|pi|antigravity --id <id> --json <file>
//!   set-identity <id> --account-id <id> [--email <email>] [--org-name <name>] | --clear
//!   invalidate --id <id>
//!   rotate-master-key
//!   mint-handle --id <id>                      print a fresh handle (once)
//!   revoke-handle --handle <ckh_...> | --hash <hex>
//!   revoke-all-handles --id <id>
//!   grant --principal <id> --selector-kind <exact|category|audience> --selector <value>
//!       --operation <read|sign|open|list|deposit|account_token|seal|policy_token>
//!   revoke-grant --principal <id> --selector-kind <exact|category|audience> --selector <value>
//!       --operation <read|sign|open|list|deposit|account_token|seal|policy_token>
//!   grants
//!   audit [--limit N] | verify-audit
//! ```
//!
//! Storage location is resolved the same way the daemon resolves it; for the CLI
//! it is taken from `--data-dir` (the vault directory holding `store.db`).

use std::path::PathBuf;
use std::process::ExitCode;

#[path = "cli_support/module_secret_cli.rs"]
mod module_secret_cli;
#[path = "cli_support/provider_cli.rs"]
mod provider_cli;

use provider_cli::{
    cmd_clear_condition, cmd_provider, cmd_provider_report, cmd_set_plan, cmd_set_providers,
    finish_provider_deposit, print_missing_provider_note, provider_set_op,
};

#[cfg(test)]
use provider_cli::parse_plan_since;

#[path = "cli_support/keys_cli.rs"]
mod keys_cli;

use keys_cli::{
    cmd_approve, cmd_bootstrap, cmd_mint_kem_key, cmd_mint_signing_key, cmd_rotate_master_key,
    cmd_sign,
};

#[path = "cli_support/credential_cli.rs"]
mod credential_cli;

use credential_cli::{
    attach_import_identity, build_import_record, cmd_import, cmd_invalidate, cmd_put,
    cmd_reactivate, cmd_reclassify, cmd_remove, cmd_set_category, cmd_set_identity,
    has_gateway_flags, normalize_gateway_base_url, parse_gateway_header, IdentityFlags,
};

#[path = "cli_support/login_cli.rs"]
mod login_cli;

use login_cli::{cmd_login, cmd_logout, login_id_is_valid};

#[path = "cli_support/status_cli.rs"]
mod status_cli;

use status_cli::{
    cmd_audit, cmd_events, cmd_list, cmd_status, cmd_usable, cmd_verify_audit, format_ts_ms,
    parse_inventory, print_store_behind_note, request_admin_status,
    request_admin_status_with_schema,
};

#[cfg(test)]
use status_cli::{
    attach_inventory_creators, provider_store_behind_note, render_inventory_row, store_behind_note,
};

#[path = "cli_support/handles_cli.rs"]
mod handles_cli;

use handles_cli::{cmd_mint_handle, cmd_revoke_all_handles, cmd_revoke_handle};

#[path = "cli_support/grants_cli.rs"]
mod grants_cli;

use grants_cli::{
    cmd_categories, cmd_grant, cmd_grants, cmd_revoke_grant, parse_grants, print_read_grants,
    render_grant_reach,
};

#[path = "cli_support/enrollment_cli.rs"]
mod enrollment_cli;

use enrollment_cli::{cmd_enroll, live_enrollment_named, missing_pending_request};

#[path = "cli_support/admin_client.rs"]
mod admin_client;
#[path = "cli_support/api_key_login.rs"]
mod api_key_login;
#[path = "cli_support/browser_login.rs"]
mod browser_login;
#[allow(dead_code)]
mod cli_support;
#[path = "cli_support/github_app_cli.rs"]
mod github_app_cli;
#[path = "cli_support/github_apps.rs"]
mod github_apps;
#[path = "cli_support/google_login.rs"]
mod google_login;
#[path = "cli_support/import_picker.rs"]
mod import_picker;
#[path = "cli_support/login_listener.rs"]
mod login_listener;
#[path = "cli_support/login_wire.rs"]
mod login_wire;
#[path = "cli_support/provider_login.rs"]
mod provider_login;
#[path = "cli_support/put_prompt.rs"]
mod put_prompt;
#[path = "cli_support/route_client.rs"]
mod route_client;

use cortexkit_store::{open_sqlite, Isolation, StorageBackend, StorageDescriptor, StoreError};
use credentials_core::admin_ops::{
    AdminAuditOp, AdminOpBody, StoreMode, ADMIN_OP_SCHEMA_V1, ADMIN_OP_SCHEMA_V2,
    ADMIN_OP_SCHEMA_V3,
};
use credentials_core::catalog::{
    default_provider_ids as catalog_default_provider_ids, login_provider, DeviceKind, ExchangeWire,
    LoginProvider,
};
use credentials_core::contract::{MODULE_ID, STORAGE_NAMESPACE};
use credentials_core::credential_id::{default_refresh_adapter, parse_credential_id, AuthMethod};
use credentials_core::key::MasterKey;
use credentials_core::record::{CredentialKind, RecordIdentity, VaultRecord};
use credentials_core::resolver::{self, KeySource, MasterKeyError, ResolverConfig};
use credentials_core::store::{
    EncryptedStore, GrantOperation, SelectorKind, SetCategoryMode, SetProvidersMode, StoreOpError,
};
use ring::rand::SystemRandom;
use ring::signature::Ed25519KeyPair;

fn main() -> ExitCode {
    if let Err(error) = credentials_core::harden_process() {
        return finish(Err(CliError::Io(format!(
            "process hardening failed: {error}"
        ))));
    }
    finish(run())
}

fn finish(result: Result<(), CliError>) -> ExitCode {
    match result {
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
            // The exit code alone does not settle it: a wrong flag shape exits 1 with the
            // error on stderr and nothing on stdout, so the CLI fails closed, but a reader
            // of a tailed transcript sees only the help footer and cannot tell whether the
            // command ran.
            //
            // So the exit code was always honest and the rendering was not. One line at
            // the end costs nothing and makes a tailed transcript self-describing.
            // ONLY WHEN SOMETHING CAME BETWEEN. An unconditional restatement would print
            // a one-line refusal twice with a blank line between:
            //
            //     error: --id is required
            //
            //     error: --id is required — nothing ran, nothing changed.
            //
            // The reasoning above is about a refusal BURIED by a help page. When the error
            // body is a single line there is nothing to bury it, the reader has the first
            // line in view, and the echo reads as a second, different failure. Every verb
            // with a required flag renders this way, so the noise would be the common case
            // and the case the restatement is for is the rare one.
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
    /// A status report (from the running module or from this CLI's own lease-free read)
    /// failed this CLI's shape or ordering check. Nobody refused anything: the report
    /// arrived and this side would not trust it, so the wording must not blame the module.
    StatusReportInvalid(String),
    /// THIS CLIENT could not prepare the op: nothing was dispatched, and the module
    /// was never asked. Terminal for the same reason as `RouteRefused` (the offline
    /// path needs the same master key), but the operator's next move is local.
    LocalFailure(String),
    /// An admin op was dispatched to the running module but its outcome is unknown
    /// (connection dropped after send). The op may have committed.
    RouteIndeterminate(String),
    /// A revoke found nothing live to revoke. It changed nothing, so a script must not
    /// carry on as if access had been removed: a mistyped value leaves the handle it
    /// meant serving. It has its own exit code so a script that revokes the same value
    /// twice on purpose can accept exactly this case.
    NothingRevoked(String),
}

impl CliError {
    fn is_already_exists(&self) -> bool {
        match self {
            Self::Store(StoreOpError::AlreadyExists) => true,
            Self::RouteRefused(message) => *message == StoreOpError::AlreadyExists.to_string(),
            _ => false,
        }
    }

    fn exit_code(&self) -> ExitCode {
        match self {
            CliError::DaemonRunning { .. } => ExitCode::from(3),
            CliError::MasterKey(_) => ExitCode::from(4),
            // A dispatched-but-unknown outcome gets its own code so a script does not
            // treat it as a clean failure and blindly retry a possibly-committed op.
            CliError::RouteIndeterminate(_) => ExitCode::from(5),
            CliError::NothingRevoked(_) => ExitCode::from(6),
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
            CliError::Store(StoreOpError::ConditionHomeOwned) => {
                f.write_str("condition_home_owned/permanent")
            }
            CliError::Store(e) => write!(f, "{e}"),
            CliError::StoreOpen(e) => write!(f, "{e}"),
            CliError::Io(m) => write!(f, "{m}"),
            CliError::RouteRefused(m) => write!(f, "the running module refused the op: {m}"),
            CliError::StatusReportInvalid(m) => {
                write!(f, "the status report failed this CLI's check: {m}")
            }
            // NAMES THIS SIDE, because the operator's next move depends on which machine
            // is at fault and the old wording sent them to the wrong one. Nothing was
            // dispatched, so there is no module state to inspect and no wire error to
            // look up -- the fix is here.
            CliError::LocalFailure(m) => write!(
                f,
                "could not prepare the op on this side (nothing was sent): {m}"
            ),
            CliError::RouteIndeterminate(m) => write!(f, "{m}"),
            CliError::NothingRevoked(m) => write!(f, "{m}"),
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
    let args = std::env::args_os()
        .skip(1)
        .map(|arg| {
            arg.into_string()
                .map_err(|_| CliError::Usage("arguments must be valid UTF-8".into()))
        })
        .collect::<Result<_, _>>()?;
    run_args(args)
}

fn run_args(args: Vec<String>) -> Result<(), CliError> {
    // Bare `ck auth` prints the short verb table to stdout and exits 0 — showing
    // usage is not an error (no `error:` prefix, no stderr).
    if args.is_empty() {
        println!("{}", usage_short());
        return Ok(());
    }
    // THE `ck` DISPATCHER'S OPT-IN PROBE. Until this answers, `ck auth …` refuses as
    // "not a command" and this binary is absent from `ck --help`.
    //
    // Opting in is needed because `ck setup` places module programs in the same PATH
    // directory: a dispatcher that exec'd ANY `ck-*` would run, say, a module program
    // that starts in stdio mode and waits on a pipe. Opting in is the right
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
    let Invocation {
        command,
        args,
        globals,
        options,
        help,
    } = parse_invocation(args)?;

    if command == "help" || command == "--help" || command == "-h" {
        // `help <verb>` → the verb's page; bare `help` → the short table.
        match args.first() {
            Some(verb) if verb == "federation" && args.get(1).is_some_and(|a| a == "sharing") => {
                println!("{}", help_verb("federation sharing status"))
            }
            Some(verb) if verb == "github" => println!("{}", help_verb(&args.join(" "))),
            Some(verb)
                if (verb == "provider"
                    && args
                        .get(1)
                        .is_some_and(|arg| matches!(arg.as_str(), "list" | "set" | "remove")))
                    || (matches!(
                        verb.as_str(),
                        "manifest" | "policy" | "policy-root" | "module-secret" | "github-app"
                    ) && args.get(1).is_some()) =>
            {
                println!("{}", help_verb(&args[..2].join(" ")))
            }
            Some(verb) => println!("{}", help_verb(verb)),
            None => println!("{}", usage_short()),
        }
        return Ok(());
    }
    if help {
        if command == "federation" && args.first().is_some_and(|a| a == "sharing") {
            println!("{}", help_verb("federation sharing status"));
            return Ok(());
        }
        let page = if command == "github" {
            std::iter::once(command.as_str())
                .chain(args.iter().take(2).map(String::as_str))
                .collect::<Vec<_>>()
                .join(" ")
        } else if (command == "provider"
            && args
                .first()
                .is_some_and(|arg| matches!(arg.as_str(), "list" | "set" | "remove")))
            || (matches!(
                command.as_str(),
                "manifest" | "policy" | "policy-root" | "module-secret" | "github-app"
            ) && args.first().is_some_and(|arg| !arg.starts_with('-')))
        {
            format!("{command} {}", args[0])
        } else {
            command.clone()
        };
        println!("{}", help_verb(&page));
        return Ok(());
    }

    let global = resolve_globals(&globals)?;

    match command.as_str() {
        "bootstrap" => cmd_bootstrap(&global),
        "put" => cmd_put(&global, &args, options),
        "mint-signing-key" => cmd_mint_signing_key(&global, &args),
        "ssh-key" => cli_support::ssh_key::cmd_ssh_key(&global, &args),
        "sign" => cmd_sign(&global, &args),
        "mint-kem-key" => cmd_mint_kem_key(&global, &args),
        "import" => cmd_import(&global, &args),
        "set-identity" => cmd_set_identity(&global, &args),
        "set-category" => cmd_set_category(&global, &args),
        "set-providers" => cmd_set_providers(&global, &args),
        "provider" => cmd_provider(&global, &args, options),
        "set-plan" => cmd_set_plan(&global, &args),
        "clear-condition" => cmd_clear_condition(&global, &args),
        "reclassify" => cmd_reclassify(&global, &args),
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
        "list" => cmd_list(&global, &args),
        "provider-report" => cmd_provider_report(&global, options),
        "grants" => cmd_grants(&global, &args),
        "categories" => cmd_categories(&global),
        "enroll" => cmd_enroll(&global, &args),
        "audit" => cmd_audit(&global, &args),
        "events" => cmd_events(&global, &args),
        "usable" => cmd_usable(&global),
        "verify-audit" => cmd_verify_audit(&global),
        "verify-github-apps" => github_apps::cmd_verify(&global),
        "github-app" => github_app_cli::cmd(&global, &args),
        "github" => cli_support::github_bindings_cli::cmd_github(&global, &args),
        "transfer" => cli_support::federation_cli::cmd_transfer(&global, &args),
        "remote" => cli_support::federation_cli::cmd_remote(&global, &args),
        "member" => cli_support::federation_cli::cmd_member(&global, &args),
        "federation" => cli_support::federation_cli::cmd_federation(&global, &args),
        "secret" => cli_support::secret_cli::cmd_secret(&global, &args),
        "module-secret" => module_secret_cli::cmd_module_secret(&global, &args),
        "manifest" => cli_support::manifest_cli::cmd_manifest(&global, &args),
        "policy" => cli_support::policy_cli::cmd_policy(&global, &args),
        "policy-root" => keys_cli::cmd_policy_root(&global, &args),
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
#[derive(Debug, Default)]
struct ParsedOptions {
    values: std::collections::BTreeMap<String, String>,
    bools: std::collections::BTreeSet<String>,
}

impl ParsedOptions {
    fn optional(&self, flag: &str) -> Option<String> {
        self.values.get(flag).cloned()
    }

    fn required(&self, flag: &str) -> Result<String, CliError> {
        self.optional(flag)
            .ok_or_else(|| CliError::Usage(format!("{flag} is required")))
    }

    fn has_flag(&self, flag: &str) -> bool {
        self.bools.contains(flag)
    }
}

type FlagSpec = (&'static [&'static str], &'static [&'static str]);

fn verb_flags(command: &str, subcommand: &str) -> FlagSpec {
    match command {
        "github-app" => return github_app_cli::flag_spec(subcommand),
        "module-secret" => {
            return (
                module_secret_cli::value_flags(subcommand).unwrap_or(&[]),
                &[],
            )
        }
        "manifest" => return (cli_support::manifest_cli::value_flags(subcommand), &[]),
        "policy" => {
            return (
                cli_support::policy_cli::value_flags(subcommand).unwrap_or(&[]),
                &[],
            )
        }
        "secret" => {
            return (
                cli_support::secret_cli::flag_spec(subcommand)
                    .map_or(&[][..], |(values, _)| values),
                &[],
            )
        }
        "ssh-key" if subcommand == "allow" => return (&["--target"], &[]),
        _ => (),
    }
    let value_flags: &[&str] = match command {
        "put" => &[
            "--id",
            "--payload-file",
            "--generate-hex",
            "--category",
            "--kind",
            "--expires-ms",
            "--expected-hash",
            // github_app deposits only: the App JWT issuer. A flag handled in cmd_put
            // but missing HERE is rejected before cmd_put ever runs, so this list and
            // that handler have to move together.
            "--client-id",
            "--provider-id",
            "--gateway-base-url",
            "--gateway-auth-header",
            "--gateway-auth-scheme",
            "--gateway-header",
        ],
        "provider" => &[
            "--service",
            "--category",
            "--provider-id",
            "--host",
            "--auth-header",
            "--auth-scheme",
            "--fusiform-id",
        ],
        "github" => &["--repo", "--to", "--agent", "--app"],
        "mint-signing-key" | "mint-kem-key" => &["--id"],
        "sign" => &["--id", "--payload-file"],
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
        "set-providers" => &["--id"],
        "set-plan" => &["--id", "--tier", "--since"],
        "clear-condition" => &["--id"],
        "login" => &[
            "--provider",
            "--approve-on",
            "--browser",
            "--id",
            "--client-id",
            "--client-secret-file",
            "--payload-file",
            "--account",
            "--account-id",
            "--provider-id",
        ],
        "invalidate" | "reactivate" | "mint-handle" | "revoke-all-handles" | "remove" => &["--id"],
        "logout" => &["--provider", "--id"],
        "revoke-handle" => &["--handle", "--hash"],
        "enroll" => &["--request-id", "--name", "--display-name"],
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
        "transfer" => &["--self", "--id", "--to", "--resume", "--from"],
        "remote" => &["--id", "--home"],
        "member" => &["--member", "--operation", "--id", "--category"],
        // bootstrap / rotate-master-key / verify-audit take no per-command flags.
        _ => &[],
    };
    // Boolean (valueless) flags accepted per command.
    let bool_flags: &[&str] = match command {
        "set-providers" => &["--set", "--add", "--remove"],
        "put" => &["--replace"],
        "mint-signing-key" => &["--replace", "--audit-each-signature", "--operator-sign"],
        "mint-kem-key" => &["--replace"],
        "import" => &["--replace", "--clear-identity"],
        "set-identity" | "set-plan" => &["--clear"],
        "reclassify" => &["--from-registry", "--force"],
        "login" => &["--replace", "--no-listener", "--no-browser", "--device"],
        "transfer" => &["--replace"],
        "list" => &["--json"],
        "grants" => &["--declared"],
        "provider-report" => &["--missing"],
        "enroll" => &[
            "--keep-grants",
            "--clear",
            "--grant-requested",
            "--no-grants",
        ],
        _ => &[],
    };
    (value_flags, bool_flags)
}

const GLOBAL_FLAGS: &[&str] = &["--data-dir", "--subc", "--key-path"];
const HELP_FLAGS: &[&str] = &["--help", "-h"];

#[derive(Debug)]
struct Invocation {
    command: String,
    args: Vec<String>,
    globals: ParsedOptions,
    options: ParsedOptions,
    help: bool,
}

fn parse_invocation(args: Vec<String>) -> Result<Invocation, CliError> {
    let mut args = args.into_iter();
    let mut globals = ParsedOptions::default();
    let command = loop {
        let arg = args
            .next()
            .ok_or_else(|| CliError::Usage("a command is required".into()))?;
        if !GLOBAL_FLAGS.contains(&arg.as_str()) {
            break arg;
        }
        let value = flag_value(&arg, &mut args, |next| {
            next.starts_with("--") || HELP_FLAGS.contains(&next)
        })?;
        insert_global(&mut globals, arg, value)?;
    };
    scan_verb_args(command, args, globals, true)
}

fn flag_value(
    flag: &str,
    args: &mut impl Iterator<Item = String>,
    is_flag: impl FnOnce(&str) -> bool,
) -> Result<String, CliError> {
    args.next()
        .filter(|value| !is_flag(value))
        .ok_or_else(|| CliError::Usage(format!("{flag} requires a value")))
}

fn insert_global(globals: &mut ParsedOptions, flag: String, value: String) -> Result<(), CliError> {
    if globals.values.contains_key(&flag) {
        return Err(CliError::Usage(format!(
            "unexpected repeated argument '{flag}'"
        )));
    }
    globals.values.insert(flag, value);
    Ok(())
}

fn scan_verb_args(
    command: String,
    mut input: impl Iterator<Item = String>,
    mut globals: ParsedOptions,
    allow_help: bool,
) -> Result<Invocation, CliError> {
    let mut options = ParsedOptions::default();
    let mut args = Vec::<String>::new();
    let help_command = matches!(command.as_str(), "help" | "--help" | "-h");
    let delegated = matches!(
        command.as_str(),
        "github-app"
            | "github"
            | "module-secret"
            | "ssh-key"
            | "manifest"
            | "policy"
            | "policy-root"
            | "secret"
    );
    let subcommands: &[&str] = match command.as_str() {
        "enroll" => &["list", "approve", "label", "deny", "revoke", "reissue"],
        "transfer" => &["init", "send", "receive", "accept", "reject"],
        "remote" => &["add", "remove", "list"],
        "member" => &["grant", "revoke", "list"],
        "provider" => &["list", "set", "remove"],
        "federation" => &["self", "mapping", "sharing", "status"],
        _ => &[],
    };
    let mut help = false;
    let mut unexpected = None;
    while let Some(arg) = input.next() {
        let subcommand = args.first().map(String::as_str).unwrap_or_default();
        let (value_flags, bool_flags) = verb_flags(&command, subcommand);
        if GLOBAL_FLAGS.contains(&arg.as_str()) {
            let value = flag_value(&arg, &mut input, |next| {
                next.starts_with("--") || HELP_FLAGS.contains(&next)
            })?;
            insert_global(&mut globals, arg, value)?;
            continue;
        }
        if allow_help && HELP_FLAGS.contains(&arg.as_str()) {
            help = true;
            continue;
        }
        if value_flags.contains(&arg.as_str()) {
            // A put payload path is documented to accept a literal flag-shaped filename.
            let literal_path = command == "put" && arg == "--payload-file";
            let value = flag_value(&arg, &mut input, |next| {
                !literal_path
                    && (GLOBAL_FLAGS.contains(&next)
                        || HELP_FLAGS.contains(&next)
                        || value_flags.contains(&next)
                        || bool_flags.contains(&next))
            })?;
            options
                .values
                .entry(arg.clone())
                .or_insert_with(|| value.clone());
            args.extend([arg, value]);
            continue;
        }
        if bool_flags.contains(&arg.as_str()) {
            options.bools.insert(arg.clone());
        } else if !delegated
            && !help_command
            && !subcommands.contains(&arg.as_str())
            && !(matches!(
                command.as_str(),
                "set-providers" | "transfer" | "federation"
            ) && !arg.starts_with("--"))
            && !(matches!(command.as_str(), "set-identity" | "set-category")
                && args.is_empty()
                && !arg.starts_with("--"))
        {
            unexpected.get_or_insert_with(|| {
                if command == "put" && (arg == "--payload" || arg.starts_with("--payload=")) {
                    CliError::Usage("--payload is no longer accepted: use --payload-file <path> or omit it for the hidden interactive prompt".into())
                } else {
                    CliError::Usage(format!("unexpected argument '{arg}' for '{command}'\n\n{}", help_verb(&command)))
                }
            });
        }
        args.push(arg);
    }
    if !help && !help_command {
        if let Some(error) = unexpected {
            return Err(error);
        }
        match command.as_str() {
            "module-secret" => module_secret_cli::guard_args(&args)?,
            "ssh-key" => {
                parse_ssh_key_op(&args)?;
            }
            "manifest" => cli_support::manifest_cli::guard_args(&args)?,
            "github" => cli_support::github_bindings_cli::guard_args(&args)?,
            "policy" => cli_support::policy_cli::guard_args(&args)?,
            "policy-root" => keys_cli::guard_policy_root_args(&args)?,
            "secret" => cli_support::secret_cli::guard_args(&args)?,
            _ => (),
        }
    }
    Ok(Invocation {
        command,
        args,
        globals,
        options,
        help,
    })
}

#[cfg(test)]
fn reject_unknown_args(command: &str, args: &[String]) -> Result<ParsedOptions, CliError> {
    scan_verb_args(
        command.to_owned(),
        args.iter().cloned(),
        ParsedOptions::default(),
        false,
    )
    .map(|invocation| invocation.options)
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
           login               OAuth/device/API-key login; picker also enrolls gateways\n\
       logout              stop serving (picker with no flags at a terminal)\n\
       remove              permanently delete a credential\n\
       status              vault health + credential inventory (no secrets)\n\
        list                credential inventory + gateway settings (no secrets)\n\
       provider-report     compare routing ids or list uncovered providers\n\
       provider            list, set or remove operator provider defaults\n\
       grants [--declared]  hand-made or declared grants (no secrets)\n\
       enroll              approve, label, list or revoke consumer enrollments\n\
       categories          which categories exist and what they cover\n\
       approve             record a master-key approval before a signing window\n\
        manifest            import, sign and track GitHub routing manifests\n\
         policy              derive, sign, list and export fleet agent policies\n\
         policy-root         initialize or show the policy signing root\n\
            put                 store or generate a secret; enroll gateway keys\n\
           mint-signing-key    generate and custody a new Ed25519 signing key\n\
           ssh-key             allow or deny agent SSH use of a signing key\n\
           sign                sign payload bytes with an operator-enabled key\n\
          mint-kem-key        generate and custody a new X25519 recipient key\n\
         import              import from opencode/pi/gemini-cli/antigravity\n\
         set-identity        attach non-secret account metadata to one credential\n\
         set-category        replace/add/remove authorization categories\n\
           set-providers       replace/add/remove catalog provider ids\n\
           set-plan            set/clear a subscription tier and optional start date\n\
           clear-condition     clear a provider login condition\n\
          reclassify          apply registry category defaults atomically\n\
        mint-handle         mint a capability handle for a credential\n\
        revoke-handle       revoke one capability handle\n\
        revoke-all-handles  revoke every handle for a credential\n\
        grant               grant a module or consumer an explicit selector\n\
        revoke-grant        revoke an exact/category/audience grant\n\
       invalidate          mark a credential needs-reauth\n\
       reactivate          clear needs-reauth without replacing the secret\n\
       audit               print the audit chain\n\
       events              why credentials failed to authenticate\n\
       usable              check which credentials can serve or refresh\n\
       verify-audit        verify the audit-chain integrity\n\
       verify-github-apps  check GitHub App record ids against GitHub's slugs\n\
       github-app          create Apps or manage their webhook relay\n\
       github              change and sign GitHub repository and App bindings\n\
       transfer            send, receive, accept or reject a sealed key transfer\n\
       remote              add or remove a login homed in another vault\n\
       member              grant another vault remote reads or deliveries\n\
         federation          member setup and config-file sharing status\n\
           secret              agent secrets; phone, multi-host, basic-auth gates\n\
           module-secret       list, delete or move module-owned secrets\n\
       rotate-master-key   rotate the master key and report corrupt rows (offline)\n\
       bootstrap           initialize a new vault (offline)\n\
     \n\
     GLOBAL FLAGS\n\
     \x20 --data-dir <dir>   vault location (default: <data_home>/cortexkit/claustrum)\n\
     \x20 --subc <file>      connection file; auto-discovered on a standard install\n\
     \x20 --key-path <file>  operator key file instead of the OS keychain\n\
     \n\
     STANDALONE\n\
     \x20 ck auth --version (or -V)  print the build version and exit\n\
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
    if verb == "github" || verb.starts_with("github ") {
        return cli_support::github_bindings_cli::help_text(verb.strip_prefix("github bindings "));
    }
    if verb == "github-app" || verb.starts_with("github-app ") {
        return github_app_cli::help(verb).into();
    }
    if verb == "module-secret" || verb.starts_with("module-secret ") {
        return module_secret_cli::help_text(verb.strip_prefix("module-secret "));
    }
    if verb == "manifest" || verb.starts_with("manifest ") {
        return cli_support::manifest_cli::help_text(verb.strip_prefix("manifest "));
    }
    if verb == "policy" || verb.starts_with("policy ") {
        return cli_support::policy_cli::help_text(verb.strip_prefix("policy "));
    }
    if verb == "policy-root" || verb.starts_with("policy-root ") {
        return keys_cli::policy_root_help(verb).to_string();
    }
    let body = match verb {
        "ssh-key" => {
            "ck auth ssh-key allow <id> --target [user@]host[:port]...\n\
             ck auth ssh-key deny <id>\n\
             \n\
             \x20 --target <target>  allowed destination (allow; repeatable)\n\
             \n\
             NOTES\n\
             allow replaces the whole target set and requires local-programs on.\n\
             Repeat --target for each destination. Bracket IPv6 even without a port:\n\
             [2001:db8::1] or user@[2001:db8::1]:22. Hosts must be canonical.\n\
             deny clears enrollment and works even with local-programs off.\n\
             Both print the resulting targets; changed enrollment revokes old grants."
        }
        "provider" => {
            "ck auth provider list\n\
             ck auth provider set --service <name> [--category <c>]...\n\
             \x20                    [--provider-id <id>]...\n\
             \x20                    [--host <host>]...\n\
             \x20                    [--auth-header <header> --auth-scheme <scheme>]\n\
             \x20                    [--fusiform-id <id>]\n\
             ck auth provider remove --service <name>\n\
             \n\
             \x20 --service <name>    API-key service name (set and remove)\n\
             \x20 --category <c>      default group for future keys (set; repeatable)\n\
             \x20 --provider-id <id>  default routing id (set; repeatable)\n\
             \x20 --host <host>       allowed key destination (set; repeatable)\n\
             \x20 --auth-header <h>   key header, for example authorization (set)\n\
             \x20 --auth-scheme <s>   bearer or raw (set)\n\
             \x20 --fusiform-id <id>  provider id in the embedded Fusiform list (set)\n\
             \n\
             NOTES\n\
             list is read-only and lease-free; descriptor fields are JSON columns.\n\
             set states the whole registration; omitted optional settings are cleared.\n\
             Groups and routing ids are defaults for future keys. Hosts and auth\n\
             describe every key for this service, including existing keys.\n\
             Choose groups from ck auth categories; no groups or routing ids is valid.\n\
             A fixed catalog service cannot be registered. Repeating a set is a no-op.\n\
             Use set-category or set-providers to edit existing keys' groups or ids.\n\
             Routing ids tell routing which models a key\n\
             may serve; a wrong id sends work to a key that refuses it. Empty is safe."
        }
        "provider list" => {
            "ck auth provider list\n\
             \n\
             NOTES\n\
             Columns: SERVICE, GROUPS, PROVIDER IDS, HOSTS, AUTH, FUSIFORM ID.\n\
             All but SERVICE are JSON: arrays, an auth object or null, an id or null.\n\
             Read-only and lease-free; no master key is needed."
        }
        "provider set" => {
            "ck auth provider set --service <name> [--category <c>]...\n\
             \x20                    [--provider-id <id>]...\n\
             \x20                    [--host <host>]...\n\
             \x20                    [--auth-header <header> --auth-scheme <scheme>]\n\
             \x20                    [--fusiform-id <id>]\n\
             \n\
             \x20 --service <name>    API-key service absent from the fixed catalog\n\
             \x20 --category <c>      default group for future keys (repeatable)\n\
             \x20 --provider-id <id>  default routing id (repeatable)\n\
             \x20 --host <host>       allowed key destination (repeatable; commas OK)\n\
             \x20 --auth-header <h>   key header, for example authorization\n\
             \x20 --auth-scheme <s>   bearer (Bearer <key>) or raw (the key alone)\n\
             \x20 --fusiform-id <id>  provider id in the embedded Fusiform list\n\
             \n\
             NOTES\n\
             No groups or routing ids is valid. Groups are from ck auth categories.\n\
             set states the whole registration; omitted optional settings are cleared.\n\
             Give hosts and auth together, or neither. Hosts are exact names only,\n\
             with no scheme, port, path or pattern (at most 8). Hosts and the header\n\
             are lowercased; hosts are trimmed, sorted and deduplicated.\n\
             Groups and routing ids apply to future keys only. Hosts and auth also\n\
             describe existing keys; an identical set writes nothing.\n\
             Routing ids tell routing which models a key may serve. A wrong id sends\n\
             work to a key that refuses it; empty is the safe answer."
        }
        "provider remove" => {
            "ck auth provider remove --service <name>\n\
             \n\
             \x20 --service <name>    registered API-key service to forget\n\
             \n\
             NOTES\n\
             Remove future defaults only; existing records keep their groups and ids.\n\
             The next interactive put for this service asks again."
        }
        "provider-report" => {
            "ck auth provider-report [--missing]\n\
             \n\
             \x20 --missing    list uncovered embedded provider ids, then reviewed skips\n\
             \n\
             NOTES\n\
             List catalog-matched credentials whose stored routing provider ids differ\n\
             from the table, with ID, STORED and TABLE columns (JSON arrays of ids).\n\
             Unmapped rows with no stored ids are not differences. Unknown services\n\
             are not compared. Read-only and lease-free: no records are changed.\n\
             With --missing, no vault or key is needed. Print ids in provider-id order\n\
             when no API-key row carries them and no reviewed skip holds them, then\n\
             print skipped ids and reasons under 'Skipped:'."
        }
        "secret" => cli_support::secret_cli::help_text(),
        "set-plan" => {
            "ck auth set-plan --id <credential-id> (--tier <id> [--since <date>] | --clear)\n\
             \n\
             \x20 --id <credential-id>  credential whose subscription tier is edited\n\
             \x20 --tier <id>           operator assertion of the plan tier\n\
             \x20 --since <date>        effective start: YYYY-MM-DD, RFC 3339 or epoch ms\n\
             \x20 --clear               remove the override (detected tier reappears)\n\
             \n\
             NOTES\n\
             Choose exactly one of --tier and --clear. Tiers start with a lowercase\n\
             letter, contain only lowercase ASCII letters, digits and _, and are\n\
             1-32 characters. Pricing owns the override vocabulary. Automatic detection\n\
             cannot verify an operator override; clear it to use the detected tier.\n\
             A bare date means midnight UTC. The start must be positive and not future.\n\
             --since requires --tier; omitting it clears any previous start date."
        }
        "clear-condition" => {
            "ck auth clear-condition --id <credential-id>\n\
             \n\
             \x20 --id <credential-id>  login whose condition is cleared\n\
             \n\
             Prints cleared=true if a condition was removed, or cleared=false if none\n\
             was set. Clear a shared copy's condition at its home vault."
        }
        "set-providers" => {
            "ck auth set-providers --id <credential-id> (--add | --remove | --set)\n\
             \x20                     <provider-id>...\n\
             \n\
             \x20 --id <credential-id>  credential whose provider ids are edited\n\
             \x20 --add                 union ids with the stored set\n\
             \x20 --remove              remove ids from the stored set\n\
             \x20 --set                 replace the set; no ids clears it\n\
             \n\
             NOTES\n\
             Choose exactly one mode. --add and --remove need at least one id.\n\
             Provider ids are lowercase catalog ids, not authorization categories."
        }
        "login" => {
            "ck auth login [--provider <name>] [--id <id>] [--account <id>] [--replace]\n\
             \x20             [--no-listener] [--no-browser] [--device] [--payload-file <path>]\n\
             \x20             [--account-id <id>] [--approve-on this|other]\n\
             \x20             [--browser open|copy|show]\n\
             \n\
             \x20 --provider <name>      pick a provider; omit for an interactive picker of\n\
             \x20                        every provider\n\
             \x20 --id <id>              use the provider default id or a labeled id; must\n\
             \x20                        match any id chosen in the interactive picker\n\
             \x20 --account <id>         required for Snowflake (id oauth:snowflake:<account>)\n\
             \x20 --provider-id <id>     add a catalog provider id after deposit (repeatable)\n\
             \x20 --client-id <id>       gmail only: your Google Cloud Desktop OAuth client id\n\
             \x20 --client-secret-file <path>  gmail only: read your client secret from a file\n\
             \x20 --replace              swap an existing credential (keeps its handle)\n\
             \x20 --approve-on this|other  choose where to approve a browser OAuth login;\n\
             \x20                        default: this, or other on Linux with no display\n\
             \x20 --browser open|copy|show  open the browser, copy the link, or just show it;\n\
             \x20                        default without a terminal: show\n\
             \x20 --no-listener          disable the loopback listener and paste the callback\n\
             \x20 --no-browser           skip the browser action picker and just show the URL\n\
             \x20 --device               select headless device authorization for openai/xai\n\
             \x20 --payload-file <path>  api-key logins: read the key from a file instead of\n\
             \x20                        prompting\n\
             \x20 --account-id <id>      cloudflare-workers-ai only: the Cloudflare account id\n\
             \x20                        (32 lowercase hex characters) instead of prompting\n\
             \n\
             NOTES\n\
             Vault-native first-party login — mints an INDEPENDENT credential the vault\n\
             solely custodies (no dual-custody rotation race).\n\
             \n\
             Anthropic, OpenAI, xAI and Google-family browser OAuth ask where you will\n\
             approve before showing the URL. On this computer, a CLI-local loopback\n\
             listener and pasted input work at the same time. On another device, paste\n\
             the result here immediately; no listener is bound. Cursor, Devin, Snowflake\n\
             and DigitalOcean keep their provider-specific callback or polling flow.\n\
             No browser login opens a browser unless you choose it. Without a terminal,\n\
             pass --provider and optionally --approve-on and --browser; nothing is\n\
             prompted. github-copilot and kimi always use device authorization.\n\
             api-key providers prompt for a key, validated before\n\
             storing where the provider offers a check; otherwise login says the key\n\
             was stored unchecked, and why.\n\
             After API-key providers, Company AI gateway enrolls a LiteLLM, Portkey,\n\
             Cloudflare or custom gateway. It asks for settings and a hidden key,\n\
             never replaces, and confirms with default No. It does not check the key.\n\
             Gateway enrollment is picker-only; scripts use ck auth put with\n\
             --gateway-base-url, --gateway-auth-header and --gateway-auth-scheme.\n\
             The picker ends with Other API key provider… for a named API key.\n\
             Enter a provider name or provider:label; existing ids ask Replace it?\n\
             with default No before provider settings or the hidden key prompt.\n\
             Unknown providers reuse the groups and routing ids chosen on first use.\n\
              Catalog API-key and subscription logins store their table's routing\n\
              provider ids when no --provider-id is given. An explicit\n\
             --provider-id replaces the default; --replace keeps an existing\n\
             set and only fills a credential that holds none.\n\
             Provider ids containing -gw- are reserved for gateway creation. If a\n\
             registered default contains it, login refuses before storing; repair\n\
             the default with ck auth provider set --service <service>.\n\
             \n\
             Providers: anthropic, openai, xai, google, gmail, antigravity, github-copilot,\n\
             kimi, cursor, devin, snowflake, digitalocean, plus api-key providers\n\
             (zai, openrouter, deepseek, groq, cloudflare-workers-ai, ...) and web-search\n\
             keys (tavily, kagi, exa, parallel, brave, firecrawl, jina, tinyfish, searxng).\n\
             SearXNG keys are optional: store one only if your instance requires an API key.\n\
             cloudflare-workers-ai also asks for the account id; use an API token scoped to\n\
             Workers AI (Read and Edit), never the Global API Key.\n\
             \n\
             MULTIPLE ACCOUNTS per provider — give each its own labeled id: ck auth login\n\
             --provider anthropic --id oauth:anthropic:work (label freely chosen; each\n\
             labeled id is an independent credential with its own refresh chain and handles)."
        }
        "logout" => {
            "ck auth logout [--provider <p> | --id <id>]\n\
             \n\
             \x20 --provider <p>  select the provider credential to stop serving\n\
             \x20 --id <id>       select an explicit credential id instead\n\
             \n\
             NOTES\n\
             With no flags at a terminal, pick one active or needs_reauth credential,\n\
             then confirm (default No). Retired, corrupt, signing and KEM keys are\n\
             excluded from the picker. Use --id to log out a vault-held key.\n\
             --id or --provider never prompts; one is required without a terminal.\n\
             Stop serving now: retire the credential and revoke all its capability\n\
             handles, keeping the record and audit chain. `ck auth reactivate --id <id>`\n\
             or logging in again restores the credential, but revoked handles stay\n\
             revoked. Never a delete — use `remove` for that."
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
             table says degraded. Shows provider login conditions and links when set.\n\
             Reads the running daemon when one is up, otherwise the offline store."
        }
        "list" => {
            "ck auth list [--json]\n\
             \n\
             \x20 --json               print a stable JSON inventory for scripts\n\
             \n\
             NOTES\n\
             Print each credential's id + lifecycle state + version (no secrets), e.g. to\n\
             find which credential a health probe flagged needs_reauth. The human table\n\
             is not a stable format; scripts must use --json. --json prints one JSON\n\
             document on stdout: {\"v\":1,\"credentials\":[...]} with rows sorted by id.\n\
             Each row carries id, state, record_version, categories,\n\
              provider_ids, auth_method, plan_tier, plan_tier_source and creator.\n\
              Rows also carry provider (service name), incarnation and\n\
              plan_tier_observed_at_ms and plan_tier_since_ms (null when unknown).\n\
             JSON lists local rows only. A login with a condition also carries\n\
             condition: an object with reason, since_ms and, when there is one,\n\
             action_url; other rows omit it. The human table also shows conditions\n\
             on shared copies.\n\
             auth_method is apikey, chatgpt, antigravity, oauth or gateway, and null when the\n\
             credential has no subscription or API plane. plan_tier and plan_tier_source\n\
             are null when unset; creator is null when none. No payloads, tokens,\n\
             handles or emails are ever printed. Gateway rows also carry base_url and\n\
             headers (a name-to-value object, empty when unset). The human table shows\n\
             gateway's base URL and header names only, never header values."
        }
        "grants" => {
            "ck auth grants [--declared]\n\
             \n\
             \x20 --declared  show last-seen declaration and settings grants\n\
             \n\
             NOTES\n\
             Print every principal-scoped grant as one stable row: principal kind, principal\n\
             id, selector kind (exact, category or audience), selector, operation, reach,\n\
             and creation time. Read-only; it uses the authenticated admin.status\n\
             path when the daemon is available, otherwise a lease-free, read-only\n\
             local metadata read. An empty grant table prints `no grants`.\n\
             Plain output stays hand-made only; stderr points to --declared when needed.\n\
             --declared shows what each module last presented, not live route authority.\n\
             Empty inventory prints nothing. For settings grants, remove the key from\n\
             the module's approved setting. For declared grants, change the module's\n\
             approved declaration in the daemon configuration, then restart the module\n\
             so it re-binds; a route bound earlier may still hold an older set."
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
             \x20             approve --request-id <id> [--name <name>] [--keep-grants]\n\
             \x20                     [--grant-requested | --no-grants]\n\
             \x20                     [--display-name <text>]\n\
             \x20             label --name <name> (--display-name <text> | --clear)\n\
             \x20             deny --request-id <id>\n\
             \x20             revoke --name <name>\n\
             \x20             reissue --name <name>\n\
             \n\
             \x20 --request-id <id>             pending request, from `enroll list`\n\
             \x20 --name <name>                 consumer name to admit or manage\n\
             \x20 --display-name <text>         set or replace the display name\n\
             \x20 --clear                       clear an approved label (label only)\n\
             \x20 --keep-grants                 explicitly inherit existing name grants\n\
             \x20 --grant-requested             approve with the stored requested grants\n\
             \x20 --no-grants                   approve without the requested grants\n\
             \n\
             NOTES\n\
             The operator half of consumer enrollment. A consumer proposes a name over the\n\
             read plane and waits; only the master key can admit it.\n\
             approve admits a NAME and mints no token: the consumer's own poll mints it,\n\
             authenticated by the request secret it generated, so neither an operator nor a\n\
             squatter can collect a token for a name they do not hold. --name overrides the\n\
             proposed spelling, which is a stranger's claim rather than a fact.\n\
             list shows proposed display names; approve prints the approved name.\n\
             --display-name replaces the proposal: trimmed, 1-40 Unicode characters,\n\
             no controls, separators, bidi controls or zero-width characters; never cut.\n\
             Empty labels refuse. Rotation keeps the label; revocation removes it.\n\
             label changes an approved name without changing grants or tokens. Choose\n\
             exactly one of --display-name or --clear. An identical label is a no-op.\n\
             Requests are short-lived and stay on the vault on the computer\n\
             where the consumer ran setup. Approve there; `enroll list` shows pending ones.\n\
             revoke removes all the consumer's grants and lists them, auditing each one.\n\
             approve lists existing grants on an unused name and refuses unless you revoke\n\
             them first or pass --keep-grants to explicitly give them to the new consumer.\n\
             Token rotation keeps the same consumer and preserves its grants.\n\
             reissue prints the new token on stdout ALONE so it can be piped into a 0600\n\
             file; the previous token stops working the moment it is minted.\n\
             list is read-only and takes no lease. awaiting-poll means admitted but never\n\
             collected, which is a stalled handover rather than a live consumer."
        }
        "transfer" => {
            "ck auth transfer init --self <member> | --replace\n\
             \x20             send --id <credential> --to <member> | --resume <transfer-id>\n\
             \x20             receive\n\
             \x20             accept <transfer-id> --from <member> [--replace]\n\
             \x20             reject <transfer-id> --from <member>\n\
             \n\
             \x20 --self <member>      this vault's own member id (fed-computer:<32 hex>)\n\
             \x20 --replace            init: replace a transfer key found off active;\n\
             \x20                      accept: replace an existing record of the same kind\n\
             \x20 --id <credential>    the static key to send\n\
             \x20 --to <member>        the receiving member\n\
             \x20 --resume <id>        deliver a stored transfer again, byte for byte\n\
             \x20 --from <member>      the sending member (transfer ids are per sender)\n\
             \n\
             NOTES\n\
             Moves an api key, DSN, cookie or opaque secret to another member's vault,\n\
             sealed to a key only that vault holds. Rotating logins never move this way.\n\
             init --self creates the transfer key and records the self id; callosum must\n\
             agree that the id is this computer's. send, --resume, accept and init --self\n\
             need the running daemon (they make outbound calls) and are refused offline\n\
             with federation_requires_daemon. init --replace can recover offline: the\n\
             existing key must be off active; missing or active keys are refused. Recovery\n\
             rejects pending incoming transfers and abandons outgoing transfers.\n\
             A send that cannot be delivered is kept for\n\
             --resume. Nothing is created on the receiver until its operator accepts."
        }
        "remote" => {
            "ck auth remote add --id <credential> --home <member>\n\
             \x20           remove --id <credential>\n\
             \x20           list\n\
             \n\
             \x20 --id <credential>    the login's id, the same on both vaults\n\
             \x20 --home <member>      the member whose vault holds the login\n\
             \n\
             NOTES\n\
             A remote record serves a rotating login held by another member's vault: this\n\
             vault fetches short-lived access tokens from it and never stores a token.\n\
             add fetches once from the home (it needs the running daemon) and copies the\n\
             account identity, adapter and plan. It refuses an id held by a local record.\n\
             Re-homing is remove, then add."
        }
        "member" => {
            "ck auth member grant|revoke --member <member> --operation remote_read\n\
             \x20                    (--id <credential> | --category <name>)\n\
             \x20 member grant|revoke --member <member> --operation transfer_deliver|secret_use\n\
             \x20 member list\n\
             \n\
             \x20 --member <member>    the other member (fed-computer:<32 hex>)\n\
             \x20 --operation <op>     remote_read (fetch access tokens for a login homed\n\
             \x20                      here), transfer_deliver (send transfers here) or\n\
             \x20                      secret_use (forward agent-secret calls here)\n\
             \x20 --id <credential>    remote_read on one credential\n\
             \x20 --category <name>    remote_read on every credential in a category\n\
             \n\
             NOTES\n\
             A grant records the member's current pairing id and counts only while that\n\
             pairing lasts: after a re-pair, grant again. grant needs the running daemon\n\
             (it asks callosum for the pairing) and is refused for an unpaired member\n\
             (member_not_paired). revoke needs no lookup."
        }
        "federation" => {
            "ck auth federation self <member>\n\
             \x20 federation mapping on|off\n\
             \x20 federation sharing status\n\
             \n\
             NOTES\n\
             self changes this vault's member id. It needs the running daemon: callosum\n\
             computes this computer's id from its own key, and an id that differs, or one\n\
             that cannot be checked, is refused. mapping switches the member-mapping gate;\n\
             it takes effect at once, without a restart.\n\
             sharing status reads claustrum.jsonc without a daemon; edit that file to\n\
             change login_sharing. Run ck auth help federation sharing status for details."
        }
        "federation sharing status" => {
            "ck auth federation sharing status\n\
             \n\
             Read-only; no daemon or vault key needed. Prints path, on/off/invalid and\n\
             source (default, file or invalid reason). Edit the JSONC file to change it:\n\
             <config home>/cortexkit/claustrum.jsonc\n\
             {\"login_sharing\": false}\n\
             Missing file or field defaults on. The daemon polls every 2 seconds.\n\
             Invalid config never turns sharing on: startup applies off, and an invalid\n\
             edit keeps the applied value. There are no sharing on/off commands."
        }
        "mint-kem-key" => {
            "ck auth mint-kem-key --id kem:<name> [--replace]\n\
             \n\
             \x20 --id <id>   KEM credential id to create\n\
             \x20 --replace   explicitly replace an existing id\n\
             \n\
             NOTES\n\
             Generate a fresh X25519 recipient key and store its private half in the vault.\n\
             Only the created id, public_key_hex and key_id are printed."
        }
        "mint-signing-key" => {
            "ck auth mint-signing-key --id signing:<provider>[:<generation>] [--replace]\n\
              \x20                        [--audit-each-signature] [--operator-sign]\n\
             \n\
             \x20 --id <id>  signing:<provider>[:<generation>] credential to create\n\
              \x20 --replace  explicit destructive rotation of an existing id; keeps its handles\n\
               \x20 --audit-each-signature  require a chained payload-hash audit before signing\n\
               \x20 --operator-sign         allow ck auth sign; implies --audit-each-signature\n\
             \n\
             NOTES\n\
             Generate a fresh Ed25519 key pair in this process and seal its PKCS#8 private\n\
             half directly into the vault. The private key is never written to a file, argv,\n\
             environment variable, or command output. Prints the public key hex and its\n\
             derived key_id for handoff to verifiers.\n\
             \n\
              Create-only by default: use a new generation id for normal rotation.\n\
              Signature auditing is off by default. Opt in for publish keys whose complete\n\
              signing history must survive compromise; the audit chain cannot be trimmed.\n\
               A replacement is a fresh key: pass the policy flags again to keep them.\n\
               Operator signing is for machine account keys. Root keys must never carry it."
        }
        "sign" => {
            "ck auth sign --id <id> --payload-file <path>\n\
             \n\
             \x20 --id <id>              signing key minted with --operator-sign\n\
             \x20 --payload-file <path>  exact payload bytes to sign; - reads stdin\n\
             \n\
             NOTES\n\
             Uses authenticated operator admin access, not a capability or grant.\n\
             Every signature commits the payload's plain SHA-256 before signing.\n\
             Signed bytes are published with the signature, so anyone can check the row.\n\
             Payloads are limited to 64 KiB. Prints exactly one JSON line with key_id,\n\
             public_key_hex and signature_hex (lowercase hex). Root keys must never\n\
             be enabled for this path."
        }
        "verify-github-apps" => {
            "ck auth verify-github-apps\n\
             \n\
             NOTES\n\
             Check every github_app: record against GitHub's installations list.\n\
             Prints id, observed slug (or -), and ok, mismatch, not installed,\n\
             several installations, or unreachable. Exit 0 only if every App is ok.\n\
             \n\
             Requires the operator master key and network access to GitHub. Opens\n\
             the store read-only, without a lease; works while the daemon runs.\n\
             Never stores, refreshes, or prints keys, JWTs, or installation tokens."
        }
        "put" => {
            "ck auth put [--id <id>] [--payload-file <path> | --generate-hex <n>]\n\
             \x20           [--kind <api_key|dsn|opaque>] [--expires-ms <N>]\n\
             \x20           [--category <name>]...\n\
             \x20           [--replace | --expected-hash <hex>] [--client-id <id>]\n\
             \x20           [--gateway-base-url <url> --gateway-auth-header <name>\n\
             \x20            --gateway-auth-scheme <bearer|raw> --provider-id <id>]\n\
             \x20           [--gateway-header <name=value>]...\n\
             \n\
             \x20 --id <id>                    vault credential id to create or rotate\n\
             \x20 --payload-file <path>        keep the secret out of argv; cookie bytes are\n\
             \x20                              preserved exactly; for every other kind strip\n\
             \x20                              TRAILING whitespace (any amount: newlines, CR,\n\
             \x20                              spaces, tabs), keeping LEADING whitespace\n\
             \x20 --generate-hex <n>           generate 16 to 256 random bytes and store\n\
             \x20                              them as lowercase hex without printing them\n\
             \x20 --category <name>            set a category at creation (repeatable);\n\
             \x20                              the given set replaces catalog defaults\n\
             \x20 --kind <api_key|dsn|opaque>  record kind; defaults to api_key; refused for\n\
             \x20                              cookie ids\n\
             \x20 --expires-ms <N>             expiry timestamp in milliseconds; refused for\n\
             \x20                              cookie ids\n\
             \x20 --replace                    rotate unconditionally; bumps record_version so\n\
             \x20                              consumers re-fetch, keeping handles\n\
             \x20 --expected-hash <hex>        concurrency-safe CAS overwrite\n\
             \x20 --client-id <id>             required App JWT issuer for a github_app: deposit\n\
             \x20 --provider-id <id>           add a catalog provider id after deposit\n\
             \x20                              (repeatable)\n\
             \x20 --gateway-base-url <url>     company AI gateway API root, not /messages\n\
             \x20 --gateway-auth-header <name> header carrying the gateway key\n\
             \x20 --gateway-auth-scheme <s>    bearer or raw\n\
             \x20 --gateway-header <name=value>  fixed non-secret header (repeatable)\n\
             \n\
             NOTES\n\
             Ingest a non-OAuth secret (an api_key, dsn, or opaque blob). Create-only by\n\
              default. A cookie:<domain> id always creates a session-cookie record.\n\
              Catalog ids store the table's routing provider ids by default. Explicit\n\
               --provider-id wins; --replace keeps a stored set, as login does.\n\
               Without gateway flags, provider ids containing -gw- refuse before\n\
               storing. Repair a registered default with ck auth provider set.\n\
               If the id's service contains -gw-, no defaults are inherited and\n\
               --provider-id is a usage error; use ck auth set-providers instead.\n\
              Use ck auth login to add a provider key, with a check where available.\n\
              Unknown API-key providers ask once for groups and routing ids before\n\
              reading the value. No groups or routing ids is valid; confirmation\n\
              defaults to No. Later keys reuse the answer. Without a terminal, put\n\
              stores the key and names ck auth provider set for future defaults.\n\
              Use ck auth set-category to change one key's groups afterwards.\n\
             \n\
             --generate-hex needs --id and never prompts or replaces a record. Use it\n\
             only for api_key or opaque records, without --payload-file, --replace,\n\
             --expected-hash or gateway flags. Cookie and github_app: ids are refused.\n\
             \n\
             --category is create-only; use ck auth set-category for existing records.\n\
             Names match ^[a-z][a-z0-9-]{1,31}$. Do not combine with --replace,\n\
             --expected-hash, gateway flags, cookie ids, or github_app: deposits.\n\
             \n\
             Gateway creation needs all three settings flags and exactly one routing\n\
             id, matching the service in apikey:<vendor>-gw-<name>[:<label>].\n\
             URL scheme, host and header names are lowercased; trailing URL slashes\n\
             and surrounding header-value whitespace are stripped. Fixed headers are\n\
             sorted by name; repeated names refuse. Values must not contain secrets.\n\
             Gateway flags cannot be used with --replace or --expected-hash. Settings\n\
             are fixed: replace without gateway flags rotates only the key; remove\n\
             and re-create to change settings. Existing gateway ids never prompt to\n\
             replace when gateway flags are present.\n\
             \n\
             At a terminal, omit flags to pick API key, cookie, DSN or opaque secret,\n\
             then name it and paste a hidden value. API keys use apikey:<provider>\n\
             or apikey:<provider>:<label>; cookies use cookie:<domain>:<account>.\n\
             DSN and opaque ids have no required prefix. An explicit --id skips naming\n\
             and kind selection; without --kind it keeps the api_key default (except\n\
             cookie ids). Existing ids ask Replace it? with default No unless --replace\n\
             or --expected-hash is given. The hidden value is trimmed at both ends,\n\
             must not be empty, and never enters argv or a temporary file.\n\
             Known API-key providers suggest ck auth login --provider <name> instead\n\
             of storing unchecked; declining unchecked storage writes nothing.\n\
              Without a terminal, --id and a payload source are required.\n\
             Generated keys: ck auth mint-signing-key / ck auth mint-kem-key.\n\
             OAuth logins: ck auth login.\n\
             GitHub App ids must be github_app:<GitHub slug>. The App JWT checks\n\
             the slug with GitHub before storing; an unavailable check refuses.\n\
             \n\
             Unlike shell command substitution, non-cookie file input also trims trailing\n\
             spaces and tabs. A value that must END in whitespace cannot come from a file;\n\
             cookie: ids take file bytes verbatim."
        }
        "import" => {
            "ck auth import --source <opencode|pi|gemini-cli|antigravity> --id <id>\n\
             ck auth import  pick detected accounts to import (no flags)\n\
             \x20              --json <file> [--provider <entry>] [--adapter <adapter>]\n\
             \x20              [--replace]\n\
             \x20              [--account-id <id>] [--email <email>] [--org-name <name>]\n\
             \x20              [--clear-identity]\n\
             \n\
             \x20 --source <source>    which harness to read\n\
             \x20 --id <id>            vault credential id to create\n\
             \x20 --json <file>        required in the flag form: source file to read\n\
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
             \x20                  sets are refilled. REFUSES if it would remove a\n\
             \x20                  category an active grant selects on: --force puts\n\
             \x20                  back the REGISTRY set, so a hand-assigned or\n\
             \x20                  migration-assigned category is dropped and that\n\
             \x20                  grant reaches fewer credentials, or none\n\
             \n\
             NOTES\n\
             Enumeration and all category transitions use one fenced transaction."
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
             keep serving. Supply exactly one form. When no live handle matches (a\n\
             mistyped value, or one already revoked), nothing changes and the command\n\
             exits 6."
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
            "ck auth grant --principal <id|reserved:id|enrolled:name>\n\
             \x20             --selector-kind <exact|category|audience> --selector <value>\n\
             \x20   --operation <read|sign|open|list|deposit|account_token|seal|policy_token>\n\
             \n\
             \x20 --principal <principal>       reserved module or enrolled consumer name\n\
             \x20 --selector-kind <kind>        required: exact, category or audience\n\
             \x20 --selector <value>            credential id, category name or audience string\n\
             \x20 --operation <operation>        grant authority (no `--op` alias)\n\
             \n\
             NOTES\n\
             exact matches one credential id byte for byte. category matches every\n\
             credential carrying that category, so the set moves as categories are\n\
             assigned. Both are stored as bare text; neither carries a kind marker.\n\
             --prefix is gone: its reach changed whenever someone named a new\n\
             credential. A former prefix that named a family is a category now.\n\
             Each operation is a separate authority; none implies another.\n\
             read: fetch the token (get_scoped), status, public_key, report_auth_failure.\n\
             sign: sign with a signing key. open: open with a KEM key.\n\
             list: see the row in list_scoped with its identity and refresh adapter,\n\
             and nothing else. It never returns a token or exercises a key.\n\
             deposit: cerebellum-style module write access for cookie: records only.\n\
             Requires a reserved principal and category browser-session selector; it\n\
             grants no read access. A module can replace only rows it created.\n\
             account_token: exchange a machine proof for one audience's worker token.\n\
             It requires selector-kind audience; audience permits only account_token.\n\
             Audience grants show token in REACHES, not a credential count.\n\
             seal: seal messages in HPKE auth mode under one KEM key, which recipients\n\
             then attribute to that key. Exact selector only: a category grant would\n\
             extend that to keys added later. Every seal is audited. It grants no read,\n\
             open, sign or list access, and no other grant implies it.\n\
             policy_token: get a GitHub token limited by the signed policy for one\n\
             GitHub App credential. Exact selector only; it grants no read access.\n\
             On success a second line says how many credentials the grant reaches\n\
             now (`reaches N credentials`), counted as `ck auth grants` counts it. A\n\
             grant that reaches nothing still succeeds, with a warning on stderr\n\
             listing the categories that exist and the fix (deposit grants are not\n\
             warned). A category grant also names uncategorized credentials whose\n\
             registry defaults include it, and points at\n\
             `ck auth reclassify --from-registry`.\n\
             An enrolled name with no live enrollment still gets the grant, with a\n\
             warning: nothing can use it now; whoever is later approved under exactly\n\
             that name gets it. Revoke the grant if granting ahead was a mistake."
        }
        "revoke-grant" => {
            "ck auth revoke-grant --principal <id|reserved:id|enrolled:name>\n\
             \x20             --selector-kind <exact|category|audience> --selector <value>\n\
             \x20   --operation <read|sign|open|list|deposit|account_token|seal|policy_token>\n\
             \n\
             \x20 --principal <id|reserved:id|enrolled:name>\n\
             \x20                               module or enrolled consumer principal\n\
             \x20 --selector-kind <kind>        required: exact, category or audience\n\
             \x20 --selector <value>            credential id, category name or audience string\n\
             \x20 --operation <operation>        revoke authority (no `--op` alias)\n\
             \n\
             NOTES\n\
             Revocation is exact over principal, selector kind, selector, and operation.\n\
             Revoking list leaves any read grant on the same selector in place.\n\
             seal and policy_token grants require --selector-kind exact."
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
             Mark a credential needs-reauth (stops serving until re-login) and revoke all\n\
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
             STRANDED means neither a usable access token nor refresh material remains.\n\
             Expiry alone is normal for an active record that can refresh on the next read.\n\
             If a record needs a refresh but its adapter cannot use the stored material,\n\
             the report says 'unsupported refresh configuration'.\n\
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
             Rotate the vault master key using two crash-safe slots. Stop the daemon first.\n\
             Re-seal readable rows under the new key. Rows newly marked corrupt are listed\n\
             separately from rows already marked corrupt before rotation."
        }
        "bootstrap" => {
            "ck auth bootstrap\n\
             \n\
             NOTES\n\
             Initialize a new vault: provision the master key and seal the audit key (ALWAYS\n\
             offline). An existing vault is left unchanged (idempotent)."
        }
        "overrides" => return usage_short(),
        _ => return format!("no help for '{verb}'\n\n{}", usage_short()),
    };
    body.to_string()
}

/// Commit one admin op, choosing the backend by `--subc`:
///
/// - `--subc <connection-file>` present: commit through the RUNNING module over the
///   route plane (admin.challenge → master-key message authentication code (MAC) →
///   admin.op). Zero downtime; the
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
    let not_found = match &op {
        AdminOpBody::EnrollApprove { request_id, .. }
        | AdminOpBody::EnrollDeny { request_id, .. } => Some(missing_pending_request(request_id)),
        AdminOpBody::EnrollRevoke { name, .. }
        | AdminOpBody::EnrollLabel { name, .. }
        | AdminOpBody::EnrollReissue { name, .. } => Some(format!(
            "no live enrollment named {name} (list them with `ck auth enroll list`)"
        )),
        _ => None,
    };
    commit_admin_with_key(global, op, None)
        .map_err(|error| enrollment_admin_error(error, not_found))
}

fn enrollment_admin_error(error: CliError, not_found: Option<String>) -> CliError {
    // The route carries NotFound as its existing display text, not a typed error code.
    // Limit the translation to enrollment ops so other missing records keep their meaning.
    let missing = matches!(&error, CliError::Store(StoreOpError::NotFound))
        || matches!(&error, CliError::RouteRefused(reason) if reason == &StoreOpError::NotFound.to_string());
    match not_found {
        Some(message) if missing => CliError::Usage(message),
        _ => error,
    }
}

fn commit_login_admin(
    global: &GlobalArgs,
    op: AdminOpBody,
    preflighted_key: MasterKey,
    args: &[String],
) -> Result<serde_json::Value, CliError> {
    let explicit = provider_id_flags(args)?;
    let id = match &op {
        AdminOpBody::Store { id, .. } | AdminOpBody::StoreWithIdentityPolicy { id, .. } => {
            id.clone()
        }
        _ => return Err(CliError::Usage("login requires a deposit op".into())),
    };
    // A catalog deposit stores its default provider ids when the operator
    // passes no `--provider-id`, through the same audited admin path an explicit
    // flag takes (so the recovery below for a deposit whose provider-id write
    // fails still applies). An explicit flag always wins; a `--replace` that
    // already carries provider ids keeps
    // them, and the default lands only on a credential that holds none.
    let ids = deposit_provider_ids(global, &id, explicit)?;
    let result = commit_login_deposit(global, op, preflighted_key, &id, &ids)?;
    if ids.is_empty() {
        print_missing_provider_note(global, &id);
    }
    Ok(result)
}

fn check_deposit_provider_flags(id: Option<&str>, ids: &[String]) -> Result<(), CliError> {
    if !ids.is_empty() && id.is_some_and(|id| parse_credential_id(id).provider.contains("-gw-")) {
        return Err(CliError::Usage(
            "without gateway flags, an id whose service contains -gw- cannot take --provider-id; use ck auth set-providers instead".into(),
        ));
    }
    if let Some(value) = ids.iter().find(|id| id.contains("-gw-")) {
        return Err(CliError::Usage(
            StoreOpError::InvalidProviderId {
                rule: credentials_core::provider_ids::ProviderIdRule::Reserved,
                value: value.clone(),
            }
            .to_string(),
        ));
    }
    Ok(())
}

fn deposit_provider_ids(
    global: &GlobalArgs,
    id: &str,
    explicit: Vec<String>,
) -> Result<Vec<String>, CliError> {
    check_deposit_provider_flags(Some(id), &explicit)?;
    // A marker in the service does not prove the record has gateway settings.
    // Leave all provider-id changes for these records to the atomic store check.
    if parse_credential_id(id).provider.contains("-gw-") {
        return Ok(Vec::new());
    }
    if explicit.is_empty() {
        let registered =
            credentials_core::store::registered_providers_read_only(&store_path(global))
                .unwrap_or_default();
        let defaults: Vec<String> =
            credentials_core::store::RegisteredProvider::for_id(&registered, id)
                .map(|row| row.provider_ids.clone())
                .unwrap_or_else(|| {
                    catalog_default_provider_ids(id)
                        .iter()
                        .map(|id| id.to_string())
                        .collect()
                });
        if defaults.is_empty() || !stored_login_provider_ids(global, id).is_empty() {
            Ok(Vec::new())
        } else {
            if let Some(value) = defaults.iter().find(|id| id.contains("-gw-")) {
                let service = parse_credential_id(id).provider;
                let error = StoreOpError::InvalidProviderId {
                    rule: credentials_core::provider_ids::ProviderIdRule::Reserved,
                    value: value.clone(),
                };
                return Err(CliError::Usage(format!(
                    "{error}; registered service {service} has a reserved default provider id; repair it with ck auth provider set --service {service} before depositing"
                )));
            }
            Ok(defaults)
        }
    } else {
        Ok(explicit)
    }
}

/// The provider ids already stored for `id`, without a lease or a master key.
/// A read failure or a missing row reads as none, so a fresh credential gets
/// its catalog default; a replace that already carries ids keeps them.
fn stored_login_provider_ids(global: &GlobalArgs, id: &str) -> Vec<String> {
    let path = store_path(global);
    if !path.exists() {
        return Vec::new();
    }
    match credentials_core::store::list_meta_read_only(&path) {
        Ok(rows) => rows
            .into_iter()
            .find(|(stored_id, _)| stored_id == id)
            .map(|(_, meta)| meta.provider_ids)
            .unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

/// Keep the preflighted key and offline lease for both writes: a successful login
/// must not ask for the master key again merely to attach non-secret metadata.
fn commit_login_deposit(
    global: &GlobalArgs,
    op: AdminOpBody,
    key: MasterKey,
    id: &str,
    ids: &[String],
) -> Result<serde_json::Value, CliError> {
    if ids.is_empty() {
        return commit_admin_with_key(global, op, Some(key));
    }
    let add = set_providers_op(id, SetProvidersMode::Add, ids);
    if let Some(conn) = &global.subc_conn {
        match admin_client::commit(
            &global.data_dir,
            &resolver_config(global),
            conn,
            &op,
            Some(&key),
        ) {
            admin_client::RouteCommit::Committed(result) => {
                // The live vault already owns the deposit. Keep the metadata write on
                // that route rather than attempting to acquire its offline writer lease.
                let second = provider_route_result(admin_client::commit(
                    &global.data_dir,
                    &resolver_config(global),
                    conn,
                    &add,
                    Some(&key),
                ));
                second.map_err(|error| provider_deposit_error(id, ids, error))?;
                return Ok(result);
            }
            admin_client::RouteCommit::Refused(m) => return Err(CliError::RouteRefused(m)),
            admin_client::RouteCommit::LocalFailure(m) => return Err(CliError::LocalFailure(m)),
            admin_client::RouteCommit::Indeterminate(m) => {
                return Err(CliError::RouteIndeterminate(m))
            }
            admin_client::RouteCommit::NoLiveModule(m) => {
                if non_empty_env("SUBC_CONNECTION_FILE")
                    .map(PathBuf::from)
                    .as_ref()
                    == Some(conn)
                {
                    return Err(CliError::LocalFailure(m));
                }
                eprintln!("(no live module: {m}; using the offline lease path)");
            }
        }
    }
    let store = open_for_admin_with_key(global, true, Some(key))?;
    let result =
        credentials_core::admin_ops::apply(&store, op, "offline-cli").map_err(CliError::Store)?;
    credentials_core::admin_ops::apply(&store, add, "offline-cli")
        .map_err(CliError::Store)
        .map_err(|error| provider_deposit_error(id, ids, error))?;
    Ok(result)
}

fn provider_route_result(outcome: admin_client::RouteCommit) -> Result<(), CliError> {
    match outcome {
        admin_client::RouteCommit::Committed(_) => Ok(()),
        admin_client::RouteCommit::Refused(m) => Err(CliError::RouteRefused(m)),
        admin_client::RouteCommit::Indeterminate(m) => Err(CliError::RouteIndeterminate(m)),
        admin_client::RouteCommit::LocalFailure(m) | admin_client::RouteCommit::NoLiveModule(m) => {
            Err(CliError::LocalFailure(m))
        }
    }
}

fn provider_deposit_error(id: &str, ids: &[String], error: CliError) -> CliError {
    for line in provider_deposit_error_lines(id, ids, &error) {
        eprintln!("{line}");
    }
    error
}

fn provider_deposit_error_lines(id: &str, ids: &[String], error: &CliError) -> [String; 2] {
    [
        format!("note: deposit of {id} stood; provider ids were not confirmed: {error}"),
        format!(
            "retry: ck auth set-providers --id {id} --add {}",
            ids.join(" ")
        ),
    ]
}

fn set_providers_op(id: &str, mode: SetProvidersMode, ids: &[String]) -> AdminOpBody {
    AdminOpBody::SetProviders {
        v: ADMIN_OP_SCHEMA_V2,
        credential_id: id.into(),
        mode,
        provider_ids: ids.to_vec(),
    }
}

fn check_cli_provider_ids(ids: &[String], cap: bool) -> Result<(), CliError> {
    credentials_core::provider_ids::check_provider_ids(ids).map_err(CliError::Store)?;
    let max = credentials_core::provider_ids::MAX_PROVIDER_IDS_PER_CREDENTIAL;
    if cap && ids.len() > max {
        return Err(CliError::Store(StoreOpError::InvalidProviderId {
            rule: credentials_core::provider_ids::ProviderIdRule::Count,
            value: ids[max].clone(),
        }));
    }
    Ok(())
}

fn provider_id_flags(args: &[String]) -> Result<Vec<String>, CliError> {
    let ids = provider_id_values(args)?;
    check_cli_provider_ids(&ids, true)?;
    Ok(ids)
}

fn provider_id_values(args: &[String]) -> Result<Vec<String>, CliError> {
    let mut ids = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--provider-id" {
            let value = args
                .get(i + 1)
                .filter(|s| !s.starts_with("--"))
                .ok_or_else(|| CliError::Usage("--provider-id needs a value".into()))?;
            ids.push(value.clone());
            i += 2;
        } else if matches!(
            args[i].as_str(),
            "--id"
                | "--payload-file"
                | "--generate-hex"
                | "--category"
                | "--kind"
                | "--expires-ms"
                | "--expected-hash"
                | "--client-id"
                | "--gateway-base-url"
                | "--gateway-auth-header"
                | "--gateway-auth-scheme"
                | "--gateway-header"
                | "--provider"
                | "--account"
        ) {
            i += 2;
        } else {
            i += 1;
        }
    }
    Ok(ids)
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
                if non_empty_env("SUBC_CONNECTION_FILE")
                    .map(PathBuf::from)
                    .as_ref()
                    == Some(conn_path)
                {
                    return Err(CliError::LocalFailure(m));
                }
                // Nothing was dispatched; the offline path below is safe.
                eprintln!("(no live module: {m}; using the offline lease path)");
            }
        }
    }
    let store = open_for_admin_with_key(global, true, preflighted_key.take())?;
    #[cfg(all(windows, debug_assertions, feature = "windows-runtime-test-seam"))]
    credentials_core::test_support::windows_runtime_pause("writer")
        .map_err(|e| CliError::Io(e.to_string()))?;
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

fn parse_ssh_key_op(args: &[String]) -> Result<AdminOpBody, CliError> {
    let usage =
        || CliError::Usage("ssh-key allow <id> --target <target>... | ssh-key deny <id>".into());
    let verb = args.first().ok_or_else(usage)?;
    let id = args
        .get(1)
        .filter(|id| !id.starts_with('-'))
        .ok_or_else(usage)?;
    if !id.starts_with("signing:") {
        return Err(CliError::Usage(
            "ssh-key requires a signing: credential id".into(),
        ));
    }
    match verb.as_str() {
        "deny" if args.len() == 2 => Ok(AdminOpBody::SshKeyAgentDeny {
            v: ADMIN_OP_SCHEMA_V2,
            id: id.clone(),
        }),
        "allow" => {
            let mut targets = Vec::new();
            let (pairs, remainder) = args[2..].as_chunks::<2>();
            for pair in pairs {
                if pair[0] != "--target" {
                    return Err(usage());
                }
                targets.push(parse_ssh_key_target(&pair[1])?);
            }
            if !remainder.is_empty() {
                return Err(usage());
            }
            let enrollment = credentials_core::record::AgentSsh { targets }
                .canonicalized()
                .map_err(|_| usage())?;
            Ok(AdminOpBody::SshKeyAgentAllow {
                v: ADMIN_OP_SCHEMA_V2,
                id: id.clone(),
                targets: enrollment.targets,
            })
        }
        _ => Err(usage()),
    }
}

fn parse_ssh_key_target(input: &str) -> Result<credentials_core::record::AgentSshTarget, CliError> {
    let invalid = || {
        CliError::Usage("invalid SSH target; bracket IPv6 hosts, including without a port".into())
    };
    let (user, address) = match input.split_once('@') {
        Some((user, address)) => (Some(user.to_owned()), address),
        None => (None, input),
    };
    let (host, port) = if let Some(rest) = address.strip_prefix('[') {
        let (host, suffix) = rest.split_once(']').ok_or_else(invalid)?;
        host.parse::<std::net::Ipv6Addr>().map_err(|_| invalid())?;
        let port = if suffix.is_empty() {
            None
        } else {
            Some(suffix.strip_prefix(':').ok_or_else(invalid)?)
        };
        (host, port)
    } else {
        if address.matches(':').count() > 1 {
            return Err(invalid());
        }
        match address.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (address, None),
        }
    };
    let port = port
        .map(|p| {
            if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
                return Err(invalid());
            }
            p.parse::<u16>().map_err(|_| invalid())
        })
        .transpose()?;
    let target = credentials_core::record::AgentSshTarget {
        user,
        host: host.to_owned(),
        port,
    };
    target.validate().map_err(|_| invalid())?;
    Ok(target)
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

/// The note `put` and `import` print on stderr after creating a credential that no
/// grant covers yet.
///
/// It points at `ck auth grant`, because modules and enrolled consumers read under a
/// grant. It does not suggest a capability handle: a handle is bearer material that
/// has to be copied to its reader, while a grant names the reader and needs nothing
/// copied. It states the gap as a fact and does not urge a grant: depositing
/// ahead of any consumer is legitimate, and a grant made before a reader exists only
/// widens access early.
///
/// Only print it where `created_id_is_already_reachable` returned false, so the
/// "no covering grant" claim has been checked against the vault's grant set.
fn no_covering_grant_note(id: &str) -> String {
    format!(
        "(no grant covers this credential yet, so no consumer can read it. When a module \
         or an enrolled consumer needs it, grant access with `ck auth grant --principal \
         <principal> --selector-kind exact --selector {id} --operation read`.)"
    )
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

// ---- arg parsing helpers -------------------------------------------------

fn resolve_globals(options: &ParsedOptions) -> Result<GlobalArgs, CliError> {
    // ZERO-FLAG default: on a standard install every flag below is derivable, so a
    // top-level command (`ck auth login --provider xai --replace`, `ck auth status`)
    // works with no path arguments at all. Flags are OVERRIDES for non-standard
    // installs, never requirements.
    let (data_dir, data_dir_explicit) = match options.optional("--data-dir") {
        Some(dir) => (PathBuf::from(dir), true),
        // The daemon's storage path is fixed by convention to
        // <data_home>/cortexkit/<module_id> (subc daemon_config); module_id is a
        // known constant, and data_home follows the same platform default subc
        // uses. So the default IS the directory the supervised vault serves.
        None => (default_data_home().join("cortexkit").join(MODULE_ID), false),
    };
    let key_path = options.optional("--key-path").map(PathBuf::from);
    let key_source =
        resolver::key_source(&data_dir, key_path.as_deref()).map_err(CliError::MasterKey)?;
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
    let subc_conn = match options.optional("--subc") {
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
/// THAT BYTE-FOR-BYTE CLAIM IS TESTED. It spans two repositories, so no test's
/// natural scope reaches it -- the exact shape that survives review because it reads
/// as reasoning rather than as a property. The
/// daemon publishes a golden fixture for its own rule; this repo vendors it and
/// asserts against it (see `tests/fixtures/data_home` and the test below).
///
/// Why a duplicate at all, rather than calling a shared crate: `cortexkit-store-types`
/// offers `resolve_data_home()`, but THE SHARED IMPLEMENTATION IS NOT AUTOMATICALLY
/// THE AUTHORITATIVE ONE, and its rules have differed from the daemon's (no Windows
/// branch, relative `XDG_DATA_HOME` rejected). What matters is tracking whoever
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
    // THAN FIRST-IN-A-LIST -- matching `ck`'s own reader, subc-core's
    // `connection_file_candidates_with` in bin/ck.rs.
    //
    // This ladder is a COPY of that one and cannot be a call: subc-core exposes the
    // WRITER's helper, which resolves to the temp fallback rather than searching, so
    // calling it would answer about a path the daemon would write rather than the one it
    // wrote. A copied ladder diverges SILENTLY -- nothing links the two, no test can
    // compare them, and the failure is that this CLI looks where `ck` does not.
    //
    // WITHOUT THIS ARM, an operator who sets SUBC_CONNECTION_FILE to name a rig falls
    // through to discovery and reaches whichever daemon is found -- in practice
    // production. For a read verb that is a true answer
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
    // (bin/ck.rs, `connection_file_candidates_with`).
    // So routing this through `default_data_home()` would make the CLI look somewhere
    // `ck` never looks the moment an operator sets XDG_DATA_HOME -- reintroducing the
    // looks-where-ck-does-not class that the SUBC_CONNECTION_FILE rung above was added
    // to close, in the same function, by way of tidying.
    //
    // A tool that flags duplicated values will flag this pair, and the obvious remedy is
    // the defect. A flagged duplicate is a candidate until it is resolved
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
/// mentioned. STOCK MACOS sets no `XDG_RUNTIME_DIR`, so this is the default there
/// rather than an edge case.
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
    temp_dir_connection_file_in(std::env::temp_dir())
}

/// The rule itself, with the directory passed in.
///
/// SPLIT OUT BECAUSE DRIVING IT THROUGH `TMPDIR` RACES EVERY OTHER TEST IN THE BINARY.
/// The Rust harness runs tests as threads in ONE process, so while one test points
/// TMPDIR/TMP/TEMP at a scratch root, any concurrent test calling `env::temp_dir()`
/// reads that root, creates a directory inside it, and then has it deleted underneath
/// by the first test's cleanup.
///
/// THE VICTIMS touch no environment variable at all (the manifest-lock tests, for
/// example) and have no way to know. That is why a mutex over the MUTATORS -- which
/// is how the `SUBC_CONNECTION_FILE` tests are serialised -- does not solve this one: it
/// protects mutators from each other and leaves every innocent reader exposed. The only
/// fix that covers a reader that does not participate is not to mutate the variable.
///
/// Both error codes such a race produces fall out of one cause, which makes it hard to
/// read: ENOENT (no such file) when the scratch root was already deleted, and EINVAL
/// (invalid argument) from a torn `getenv` during a concurrent `setenv` (the reason
/// `set_var` is unsafe in edition 2024). Two different-looking failures, two different
/// tests, one race.
///
/// The pattern is already in this file: `resolve_data_home_from` takes its inputs as
/// parameters for exactly this reason, two hundred lines away.
fn temp_dir_connection_file_in(dir: PathBuf) -> Option<PathBuf> {
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
    // connection file, where guessing picks a daemon at random. Without it, a CLI that
    // concludes "no daemon" from an I/O error takes the offline path and tells the
    // operator to stop a daemon that is serving. An exact miss is
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
/// The distinction lives in the TYPE, not in an eprintln: with both arms returning
/// `None`, a test asserting `None` passes whether the error is reported or discarded.
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
    /// A race like this can make one commit pass on one run and fail on the next, which
    /// is the signature of a race rather than a platform difference.
    ///
    /// A mutex rather than `--test-threads=1`: the flag is invisible at the call site and
    /// a future runner without it silently reintroduces the race.
    static ENV_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Take the environment guard, surviving a poisoned lock.
    ///
    /// A panicking test poisons the mutex; without this, every later test in the module
    /// fails on the poison rather than on its own subject, turning one real failure into
    /// a wall of misattributed ones.
    pub(super) fn env_guard() -> std::sync::MutexGuard<'static, ()> {
        ENV_GUARD.lock().unwrap_or_else(|e| e.into_inner())
    }

    use super::{
        connection_file_in, discover_subc_connection_file, temp_dir_connection_file_in,
        ConnectionSearch,
    };

    /// An unreadable directory must not read as "no daemon is running".
    ///
    /// The failure this guards against: a real I/O error discarded (`.ok()?`) and
    /// returned as the same `None` an empty directory produces, so the caller takes the
    /// offline path, hits the single-writer lease, and tells the operator to STOP THE
    /// DAEMON.
    ///
    /// This assertion discriminates because the outcomes are different VARIANTS:
    /// collapsing the error arm back to a not-present result reds this by name, which
    /// an `Option`-returning version of this test could not do.
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
    /// RUNG DELETED, because the glob below finds the same path -- the silent success
    /// the rung exists to avoid, pointed at its own test. With two, the glob refuses as
    /// Ambiguous rather than guessing a daemon, so only subc's own derivation can answer
    /// and the assertion is about the CALL.
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

        // THE DIRECTORY IS PASSED IN, NOT SET IN THE ENVIRONMENT.
        //
        // Setting TMPDIR/TMP/TEMP to `root` and restoring them afterwards would BREAK
        // OTHER TESTS: the harness runs tests as threads in one process, so during that
        // window any concurrent test calling `env::temp_dir()` -- such as the
        // manifest-lock suite, which touches no environment variable and has no way to
        // know -- would read this scratch root, create a directory in it, and have it
        // deleted underneath by the cleanup below.
        //
        // That presents as two unrelated flakes with different error codes: ENOENT
        // where the root was already gone, EINVAL from a torn `getenv` racing a
        // `setenv`. One cause, two symptoms, neither in this file.
        //
        // A mutex over the mutators would NOT fix it, which is the part worth keeping:
        // it protects mutators from each other (that is how the `SUBC_CONNECTION_FILE`
        // tests are serialised) while leaving every innocent reader exposed. The only
        // fix that reaches a victim who does not participate is to stop mutating the
        // variable.
        let got = temp_dir_connection_file_in(root.clone());
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

/// True on Linux when no graphical session is present (neither `DISPLAY` nor
/// `WAYLAND_DISPLAY` is set), as on a headless server or a plain SSH login. No
/// browser is likely to work there, and another device cannot reach this machine's
/// loopback listener. Auth-code login defaults to approving on another device;
/// the provider-specific callback drivers use this to disable their listener.
fn no_local_display() -> bool {
    no_local_display_from(
        cfg!(target_os = "linux"),
        std::env::var_os("DISPLAY"),
        std::env::var_os("WAYLAND_DISPLAY"),
    )
}

fn no_local_display_from(
    linux: bool,
    display: Option<std::ffi::OsString>,
    wayland: Option<std::ffi::OsString>,
) -> bool {
    let unset = |v: Option<std::ffi::OsString>| v.is_none_or(|v| v.is_empty());
    linux && unset(display) && unset(wayland)
}

/// Use only the paste flow: asked for with `--no-listener`, or forced because this
/// machine has no display.
fn paste_only(args: &[String]) -> bool {
    has_flag(args, "--no-listener") || no_local_display()
}

/// Open only after an explicit browser action has been selected.
/// Never passes the URL through a shell (no injection surface).
fn open_in_browser(action: browser_login::BrowserAction, url: &str) -> std::io::Result<()> {
    if action != browser_login::BrowserAction::Open {
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
    let mut cmd = windows_browser_command(url);
    spawn_browser(&mut cmd).map(|_| ())
}

#[cfg(any(windows, test))]
fn windows_browser_command(url: &str) -> std::process::Command {
    let mut command = std::process::Command::new("rundll32");
    command.args(["url.dll,FileProtocolHandler", url]);
    command
}

fn spawn_browser(command: &mut std::process::Command) -> std::io::Result<std::process::Child> {
    command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
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
        assert_eq!(
            super::browser_login::browser_action(
                &["--no-browser".to_string()],
                super::browser_login::ApproveOn::This,
            )
            .unwrap(),
            super::browser_login::BrowserAction::Show,
        );
    }

    #[test]
    fn only_linux_without_any_display_counts_as_headless() {
        use super::no_local_display_from as headless;
        let set = |v: &str| Some(std::ffi::OsString::from(v));
        assert!(headless(true, None, None));
        assert!(headless(true, set(""), set("")));
        assert!(!headless(true, set(":0"), None));
        assert!(!headless(true, None, set("wayland-0")));
        // macOS and Windows always have a way to open a browser for the signed-in user.
        assert!(!headless(false, None, None));
    }

    #[test]
    fn no_listener_flag_forces_the_paste_flow() {
        assert!(super::paste_only(&["--no-listener".to_string()]));
        assert_eq!(super::paste_only(&[]), super::no_local_display());
    }

    /// A client-side failure must not speak in the module's voice.
    ///
    /// DRIVES THE PRODUCTION DECISION, not a hand-built variant. A test that constructed
    /// `CliError::LocalFailure` itself and asserted its Display would verify only the
    /// test's own copy of the classification, and would stay green with the
    /// key-resolution failure put back on `RouteCommit::Refused`, the exact defect.
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
    /// The doc comment on `default_data_home` claims byte-for-byte equivalence with
    /// subc's resolver. The claim spans two repositories, so no test's natural scope
    /// contains it, and untested it would go on reading as true for as long as nobody
    /// re-derived it. If it were ever false
    /// the CLI would compute a different vault directory than the daemon serves --
    /// and because that directory derives the keychain service name and the admin
    /// transcript id, the visible symptom is `vault_locked` on an intact store, not
    /// a wrong path.
    ///
    /// The fixture is AUTHORED BY THE DAEMON and vendored here (see
    /// `tests/fixtures/data_home/VENDORED.md`). A conformance fixture written on this
    /// side would agree with whatever this side expects, so it could never catch a
    /// mismatch.
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

    #[test]
    fn deposit_already_exists_requires_the_exact_store_error() {
        assert!(CliError::Store(StoreOpError::AlreadyExists).is_already_exists());
        let message = StoreOpError::AlreadyExists.to_string();
        assert!(CliError::RouteRefused(message.clone()).is_already_exists());
        assert!(!CliError::RouteRefused(format!("invalid label: {message}")).is_already_exists());
    }

    fn v(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn a_global_flag_before_the_verb_lands_where_one_after_it_would() {
        for args in [
            ["--data-dir", "/tmp/v", "--key-path", "/tmp/k", "status"],
            ["status", "--data-dir", "/tmp/v", "--key-path", "/tmp/k"],
            ["--data-dir", "/tmp/v", "status", "--key-path", "/tmp/k"],
        ] {
            let parsed = parse_invocation(v(&args)).unwrap();
            assert_eq!(parsed.command, "status");
            assert!(parsed.args.is_empty());
            assert_eq!(
                parsed.globals.optional("--data-dir").as_deref(),
                Some("/tmp/v")
            );
            assert_eq!(
                parsed.globals.optional("--key-path").as_deref(),
                Some("/tmp/k")
            );
        }
        assert!(
            matches!(parse_invocation(v(&["--data-dir"])), Err(CliError::Usage(message)) if message == "--data-dir requires a value")
        );
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

    /// `remove` takes --id and is registered in the arg-rejection table (a typo'd
    /// flag cannot silently target the wrong credential for a PERMANENT delete).
    #[test]
    fn remove_flags_are_validated() {
        assert!(reject_unknown_args("remove", &v(&["--id", "oauth:anthropic:old"])).is_ok());
        assert!(reject_unknown_args("remove", &v(&["--provider", "anthropic"])).is_err());
    }
}

#[cfg(test)]
mod deposit_cli_tests {
    use super::*;
    use std::process::{Command, Output};

    // A child test process runs the production argv parser and exit/stderr handler,
    // so CLI tests can live beside the binary without requiring a prebuilt artifact.
    #[test]
    #[ignore = "subprocess argv-parser helper; invoked by deposit CLI tests"]
    fn cli_child() {
        let raw = std::env::var("CK_AUTH_TEST_ARGV").expect("child helper needs CK_AUTH_TEST_ARGV");
        let args: Vec<String> = serde_json::from_str(&raw).unwrap();
        let code = finish(run_args(args));
        let value = (0..=255u8)
            .find(|value| ExitCode::from(*value) == code)
            .unwrap();
        std::process::exit(i32::from(value));
    }

    fn invoke(root: &std::path::Path, args: &[&str]) -> Output {
        let mut argv: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        argv.extend([
            "--data-dir".into(),
            root.join("vault").display().to_string(),
            "--key-path".into(),
            root.join("master.key").display().to_string(),
        ]);
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "deposit_cli_tests::cli_child",
                "--nocapture",
            ])
            .env("CK_AUTH_TEST_ARGV", serde_json::to_string(&argv).unwrap())
            .output()
            .unwrap()
    }

    fn success(root: &std::path::Path, args: &[&str]) -> String {
        let output = invoke(root, args);
        assert!(
            output.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    }

    fn root(label: &str) -> PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("ck-auth-{label}-{}-{nonce}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        success(&root, &["bootstrap"]);
        root
    }

    fn global(root: &std::path::Path) -> GlobalArgs {
        GlobalArgs {
            data_dir: root.join("vault"),
            key_source: KeySource::OperatorPath {
                path: root.join("master.key"),
            },
            subc_conn: None,
        }
    }

    #[test]
    fn policy_root_cli_prints_the_public_identity_and_protects_mint_and_put() {
        let root = root("policy-root-cli");
        let global = global(&root);
        let absent = invoke(&root, &["policy-root", "show"]);
        assert!(!absent.status.success());
        assert!(String::from_utf8_lossy(&absent.stderr).contains("policy_root_absent/permanent:"));
        let init = success(&root, &["policy-root", "init"]);
        assert_eq!(init, success(&root, &["policy-root", "show"]));
        let id = "signing:policy-root:1";
        let store = open_for_admin(&global, false).unwrap();
        let tip = store.audit_tip().unwrap();
        let record = store.get(id).unwrap();
        let public = credentials_core::signing::public_key_ed25519(
            std::str::from_utf8(record.payload.expose()).unwrap(),
        )
        .unwrap();
        let raw = (0..64)
            .step_by(2)
            .map(|i| u8::from_str_radix(&public.public_key_hex[i..i + 2], 16).unwrap())
            .collect::<Vec<_>>();
        let digest = ring::digest::digest(&ring::digest::SHA256, &raw);
        let fingerprint = digest.as_ref()[..16]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|group| format!("{:02x}{:02x}", group[0], group[1]))
            .collect::<Vec<_>>()
            .join(" ");
        assert!(init.ends_with(&format!(
            "credential_id {id}\nkey_id {}\npublic_key_hex {}\nfingerprint {fingerprint}\n",
            public.key_id, public.public_key_hex,
        )));
        drop(store);
        for id in [id, "signing:policy-root:foo"] {
            for replace in [false, true] {
                let mut args = vec!["mint-signing-key", "--id", id];
                if replace {
                    args.push("--replace");
                }
                let mint = invoke(&root, &args);
                assert!(!mint.status.success());
                assert!(String::from_utf8_lossy(&mint.stderr)
                    .contains("policy_root_protected/permanent:"));
            }
        }
        let put = invoke(&root, &["put", "--id", id, "--kind", "opaque"]);
        assert!(!put.status.success());
        assert!(String::from_utf8_lossy(&put.stderr)
            .contains("signing keys must be generated with mint-signing-key, not put"));
        assert_eq!(
            open_for_admin(&global, false).unwrap().audit_tip().unwrap(),
            tip
        );
        for verb in ["init", "show"] {
            let help = success(&root, &["help", "policy-root", verb]);
            assert!(help.contains(&format!("ck auth policy-root {verb}")));
            assert!(help.lines().all(|line| line.len() <= 80));
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    /// Deposits the fleet's legacy root and names it as the policy signing root, as
    /// migration 52 does on a vault that already held it. Minting the id through
    /// `mint-signing-key` alone leaves the root setting unset, so signing refuses.
    fn put_legacy_policy_root(global: &GlobalArgs) {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        open_for_admin(global, false)
            .unwrap()
            .put_legacy_manifest_root_for_tests(
                &VaultRecord::new_static(
                    AuthMethod::Signing.credential_kind(),
                    "operator",
                    keys_cli::pem_wrap_private_key(pkcs8.as_ref()).into_bytes(),
                    None,
                ),
                credentials_core::audit::AuditCtx::admin(credentials_core::audit::AuditOp::Put),
            )
            .unwrap();
    }

    fn put_policy_test_identity(global: &GlobalArgs) {
        use credentials_core::oauth::OAuthCredential;

        open_for_admin(global, false)
            .unwrap()
            .create(
                "github_app:sample",
                &VaultRecord::new_oauth(
                    "operator",
                    "github_app",
                    OAuthCredential {
                        access_token: "sample".to_string().into(),
                        // Policy signing opens the App's real signing material, so the
                        // identity needs a key that parses, not a placeholder string.
                        refresh_token: include_str!(
                            "../../../credentials-core/tests/fixtures/github_app/test_private_key_pkcs1.pem"
                        )
                        .to_string()
                        .into(),
                        expires_at_ms: None,
                        token_url: String::new(),
                        client_id: Some("sample".into()),
                        client_secret: None,
                        scopes: Vec::new(),
                    },
                    Vec::new(),
                ),
            )
            .unwrap();
    }

    #[test]
    fn policy_cli_oversized_derivation_leaves_the_output_untouched() {
        use credentials_core::signing::MAX_SIGN_PAYLOAD;
        use serde_json::json;

        let root = root("policy-derive-size");
        let global = global(&root);
        put_legacy_policy_root(&global);
        put_policy_test_identity(&global);
        // The manifest fits the signer; including the seeded rules pushes the policy over.
        let agent = "x".repeat(MAX_SIGN_PAYLOAD - 1_000);
        let manifest = serde_json::to_string_pretty(&json!({
            "manifest_version": 42, "issued_at_unix_secs": 1, "bindings": {"Org/R": &agent},
        }))
        .unwrap()
            + "\n";
        let manifest_path = root.join("manifest.json");
        let identities_path = root.join("identities.json");
        let out = root.join("policy.json");
        std::fs::write(&manifest_path, manifest).unwrap();
        std::fs::write(
            &identities_path,
            serde_json::to_vec(&json!({(agent): "github_app:sample"})).unwrap(),
        )
        .unwrap();
        std::fs::write(&out, "existing file").unwrap();
        success(
            &root,
            &[
                "manifest",
                "sign",
                "--file",
                manifest_path.to_str().unwrap(),
                "--approver",
                "owner",
            ],
        );
        let tip = || open_for_admin(&global, false).unwrap().audit_tip().unwrap();
        let before = tip();
        let result = invoke(
            &root,
            &[
                "policy",
                "derive",
                "--manifest-version",
                "42",
                "--identities",
                identities_path.to_str().unwrap(),
                "--out",
                out.to_str().unwrap(),
            ],
        );
        assert!(!result.status.success());
        assert!(String::from_utf8_lossy(&result.stderr).contains("policy_too_large"));
        assert_eq!(std::fs::read_to_string(&out).unwrap(), "existing file");
        assert_eq!(tip(), before);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn policy_cli_derives_signs_lists_and_recovers_an_inactive_envelope() {
        use credentials_core::agent_policy::AgentPolicy;
        use serde_json::{json, Value};

        let root = root("policy-cli");
        let global = global(&root);
        let json_output = |args: &[&str]| {
            success(&root, args)
                .lines()
                .find_map(|line| serde_json::from_str::<Value>(line).ok())
                .unwrap()
        };
        assert_eq!(
            json_output(&["policy", "list"]),
            json!({"policies": [], "head": null, "active": null})
        );
        put_legacy_policy_root(&global);
        let path = |file: &str| root.join(file).to_str().unwrap().to_owned();
        let manifest_file = path("manifest.json");
        let identities_file = path("identities.json");
        let policy_file = path("policy.json");
        let initial_manifest = |version| {
            serde_json::to_string_pretty(&json!({
            "manifest_version": version, "issued_at_unix_secs": 1, "bindings": {"Org/R": "agent"},
        })).unwrap() + "\n"
        };
        let manifest_sign = |version| {
            std::fs::write(&manifest_file, initial_manifest(version)).unwrap();
            success(
                &root,
                &[
                    "manifest",
                    "sign",
                    "--file",
                    &manifest_file,
                    "--approver",
                    "owner",
                ],
            );
        };
        manifest_sign(41);
        manifest_sign(42);
        let derive = |version| {
            invoke(
                &root,
                &[
                    "policy",
                    "derive",
                    "--manifest-version",
                    version,
                    "--identities",
                    &identities_file,
                    "--out",
                    &policy_file,
                ],
            )
        };
        let sign = |version| {
            json_output(&[
                "policy",
                "sign",
                "--file",
                &policy_file,
                "--manifest-version",
                version,
                "--approver",
                "owner",
            ])
        };
        std::fs::write(&identities_file, r#"{"agent":"github_app:sample"}"#).unwrap();
        std::fs::write(&policy_file, "leave this alone").unwrap();
        assert!(!derive("41").status.success());
        assert!(!derive("42").status.success());
        assert_eq!(
            std::fs::read_to_string(&policy_file).unwrap(),
            "leave this alone"
        );
        put_policy_test_identity(&global);
        let derived = derive("42");
        assert!(
            derived.status.success(),
            "{}",
            String::from_utf8_lossy(&derived.stderr)
        );
        let policy = std::fs::read_to_string(&policy_file).unwrap();
        assert!(!policy.ends_with('\n'));
        assert_eq!(
            AgentPolicy::parse_canonical(policy.as_bytes())
                .unwrap()
                .bindings[0]
                .resources,
            ["org/r"]
        );
        let first = sign("42");
        assert_eq!(first["envelope"]["policy"], policy);
        let published = global.data_dir.join("signed-policies/v1-envelope.json");
        let original = std::fs::read(&published).unwrap();
        let check_mode = || {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                assert_eq!(
                    std::fs::metadata(&published).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
        };
        check_mode();
        assert!(!derive("42").status.success());
        assert_eq!(std::fs::read_to_string(&policy_file).unwrap(), policy);
        manifest_sign(43);
        let derived = derive("43");
        assert!(
            derived.status.success(),
            "{}",
            String::from_utf8_lossy(&derived.stderr)
        );
        assert_eq!(sign("43")["version"], 2);
        let tip = || open_for_admin(&global, false).unwrap().audit_tip().unwrap();
        let before = tip();
        let list = json_output(&["policy", "list"]);
        assert_eq!(list["head"], 2);
        assert_eq!(list["active"], Value::Null);
        assert_eq!(
            list["policies"]
                .as_array()
                .unwrap()
                .iter()
                .map(|row| row["version"].as_i64().unwrap())
                .collect::<Vec<_>>(),
            [1, 2]
        );
        std::fs::remove_file(&published).unwrap();
        assert_eq!(
            json_output(&["policy", "export", "--version", "1"]),
            first["envelope"]
        );
        assert_eq!(std::fs::read(&published).unwrap(), original);
        check_mode();
        let missing = invoke(&root, &["policy", "export", "--version", "9"]);
        assert!(!missing.status.success());
        assert!(String::from_utf8_lossy(&missing.stderr).contains("not found"));
        assert_eq!(tip(), before);
        assert_eq!(
            std::fs::read_dir(published.parent().unwrap())
                .unwrap()
                .count(),
            2
        );
        for verb in ["sign", "list", "export", "derive"] {
            let help = success(&root, &["help", "policy", verb]);
            assert!(help.contains(&format!("ck auth policy {verb}")));
            assert!(help.lines().all(|line| line.chars().count() <= 80));
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn account_token_cli_grant_pairs_and_inventory() {
        let root = root("account-token-grants");
        let args = [
            "grant",
            "--principal",
            "reserved:ck-motor",
            "--selector-kind",
            "audience",
            "--selector",
            "cortexkit-runners",
            "--operation",
            "account_token",
        ];
        success(&root, &args);
        let table = success(&root, &["grants"]);
        assert!(
            table.lines().any(|row| row.contains("ck-motor")
                && row.contains("audience")
                && row.contains("cortexkit-runners")
                && row.contains("account_token")),
            "{table}"
        );
        for (kind, operation) in [
            ("exact", "account_token"),
            ("category", "account_token"),
            ("audience", "read"),
            ("audience", "sign"),
            ("audience", "open"),
            ("audience", "list"),
            ("audience", "deposit"),
        ] {
            let args: Vec<String> = [
                "--principal",
                "reserved:ck-motor",
                "--selector-kind",
                kind,
                "--selector",
                "cortexkit-runners",
                "--operation",
                operation,
            ]
            .into_iter()
            .map(str::to_owned)
            .collect();
            assert!(
                matches!(cmd_grant(&global(&root), &args), Err(CliError::Usage(_))),
                "{kind}/{operation} grant must refuse before touching the store"
            );
            assert!(
                matches!(
                    cmd_revoke_grant(&global(&root), &args),
                    Err(CliError::Usage(_))
                ),
                "{kind}/{operation} revoke must refuse before touching the store"
            );
        }
        let mut revoke = args;
        revoke[0] = "revoke-grant";
        success(&root, &revoke);
        assert!(success(&root, &["grants"]).contains("no grants"));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn policy_token_cli_grants_require_an_exact_selector() {
        let root = root("policy-token-grants");
        for (kind, selector, reason) in [
            (
                "category",
                "github-app-native",
                "policy_token requires selector-kind exact",
            ),
            (
                "audience",
                "cortexkit-runners",
                "audience requires operation account_token",
            ),
        ] {
            for verb in ["grant", "revoke-grant"] {
                let output = invoke(
                    &root,
                    &[
                        verb,
                        "--principal",
                        "reserved:aft",
                        "--selector-kind",
                        kind,
                        "--selector",
                        selector,
                        "--operation",
                        "policy_token",
                    ],
                );
                let stderr = String::from_utf8(output.stderr).unwrap();
                assert!(
                    !output.status.success() && stderr.contains(reason),
                    "{verb} {kind}: {stderr}"
                );
            }
        }
        assert!(success(&root, &["grants"]).contains("no grants"));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn seal_cli_grants_are_exact_only_listed_and_revocable() {
        let root = root("seal-grants");
        let grant = [
            "grant",
            "--principal",
            "reserved:prefrontal-core",
            "--selector-kind",
            "exact",
            "--selector",
            "kem:push",
            "--operation",
            "seal",
        ];
        let granted = success(&root, &grant);
        assert!(
            granted.contains("granted reserved:prefrontal-core seal exact:kem:push"),
            "{granted}"
        );
        // Match the grant row, never a bare word: the child's stdout also carries
        // libtest's own lines.
        let has_row = |table: &str| {
            table.lines().any(|line| {
                line.contains("prefrontal-core")
                    && line.contains("exact")
                    && line.contains("kem:push")
                    && line.contains("seal")
            })
        };
        let table = success(&root, &["grants"]);
        assert!(has_row(&table), "granted row missing:\n{table}");
        for kind in ["category", "audience"] {
            for verb in ["grant", "revoke-grant"] {
                let output = invoke(
                    &root,
                    &[
                        verb,
                        "--principal",
                        "reserved:prefrontal-core",
                        "--selector-kind",
                        kind,
                        "--selector",
                        "push-keys",
                        "--operation",
                        "seal",
                    ],
                );
                assert!(!output.status.success(), "{verb} {kind}");
                let stderr = String::from_utf8(output.stderr).unwrap();
                let expected = if kind == "audience" {
                    "error: account_token requires selector-kind audience, and audience requires operation account_token\n"
                } else {
                    "error: seal requires selector-kind exact: it names one KEM key, never a category\n"
                };
                assert_eq!(stderr, expected, "{verb} {kind}");
            }
        }
        assert!(
            has_row(&success(&root, &["grants"])),
            "a refused verb changed nothing"
        );
        let mut revoke = grant;
        revoke[0] = "revoke-grant";
        success(&root, &revoke);
        let after = success(&root, &["grants"]);
        assert!(!has_row(&after), "row still listed after revoke:\n{after}");
        assert!(after.contains("no grants"), "{after}");
        assert!(
            help_verb("grant").contains("seal: seal messages in HPKE auth mode under one KEM key")
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn deposit_grant_round_trip_and_invalid_deposit_grant_stderr_are_pinned() {
        let root = root("deposit-grants");
        let grant = [
            "grant",
            "--principal",
            "reserved:cerebellum",
            "--selector-kind",
            "category",
            "--selector",
            "browser-session",
            "--operation",
            "deposit",
        ];
        // Match the grant row, never a bare word: the child is this test binary, so its
        // stdout also carries libtest's own lines. Run single-threaded, libtest prints
        // `test deposit_cli_tests::cli_child ...` before the child exits, and a check
        // for "deposit" alone matched that line in both directions.
        let has_row = |table: &str| {
            table.lines().any(|line| {
                line.contains("cerebellum")
                    && line.contains("browser-session")
                    && line.contains("deposit")
            })
        };
        success(&root, &grant);
        let table = success(&root, &["grants"]);
        assert!(has_row(&table), "granted row missing:\n{table}");
        let mut revoke = grant;
        revoke[0] = "revoke-grant";
        success(&root, &revoke);
        let after = success(&root, &["grants"]);
        assert!(!has_row(&after), "row still listed after revoke:\n{after}");
        assert!(after.contains("no grants"), "{after}");
        for (principal, kind, selector) in [
            ("reserved:cerebellum", "exact", "cookie:example.com:me"),
            ("reserved:cerebellum", "category", "llm-provider"),
            ("enrolled:consumer", "category", "browser-session"),
        ] {
            let output = invoke(
                &root,
                &[
                    "grant",
                    "--principal",
                    principal,
                    "--selector-kind",
                    kind,
                    "--selector",
                    selector,
                    "--operation",
                    "deposit",
                ],
            );
            assert!(!output.status.success());
            assert_eq!(String::from_utf8(output.stderr).unwrap(), "error: deposit requires a reserved principal and category browser-session selector\n");
        }
        for verb in ["grant", "revoke-grant"] {
            assert!(help_verb(verb)
                .contains("<read|sign|open|list|deposit|account_token|seal|policy_token>"));
        }
        assert!(help_verb("grant")
            .contains("cerebellum-style module write access for cookie: records only"));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cookie_put_categories_and_list_creator_display_cover_operator_null_and_schema_13() {
        let root = root("cookie-list");
        let payload = root.join("payload.txt");
        std::fs::write(&payload, "session=operator").unwrap();
        success(
            &root,
            &[
                "put",
                "--id",
                "cookie:example.com:me",
                "--payload-file",
                payload.to_str().unwrap(),
            ],
        );
        let cfg = global(&root);
        {
            let store = open_for_admin(&cfg, false).unwrap();
            let meta = store.meta("cookie:example.com:me").unwrap();
            assert_eq!(meta.categories, ["browser-session"]);
            assert_eq!(meta.created_by.as_deref(), Some("operator"));
            store
                .deposit_cookie(
                    "cookie:example.com:module",
                    &credentials_core::secret::Secret::new("session=module".to_string()),
                    "consent-1",
                    None,
                    "reserved:cerebellum",
                )
                .unwrap();
            store
                .create(
                    "cookie:example.com:legacy",
                    &VaultRecord::new_cookie("operator", b"legacy".to_vec()),
                )
                .unwrap();
            let conn = rusqlite::Connection::open(root.join("vault/store.db")).unwrap();
            conn.execute("UPDATE credentials SET created_by = NULL WHERE credential_id = 'cookie:example.com:legacy'", []).unwrap();
            let text = success(&root, &["list"]);
            let module = text
                .lines()
                .find(|line| line.contains("cookie:example.com:module"))
                .unwrap();
            assert!(module.contains("by=reserved:cerebellum"), "{text}");
            for id in ["cookie:example.com:me", "cookie:example.com:legacy"] {
                assert!(
                    !text
                        .lines()
                        .find(|line| line.contains(id))
                        .unwrap()
                        .contains("by="),
                    "{text}"
                );
            }
            assert!(success(&root, &["categories"]).contains("browser-session"));
        }
        std::fs::remove_dir_all(root).unwrap();

        let root = root_schema_13();
        let cfg = global(&root);
        // Hold the writer lease throughout both child reads to prove they are lease-free.
        let _lease = open_sqlite(&descriptor(&cfg)).unwrap();
        let text = success(&root, &["list"]);
        assert!(text.contains("cookie:example.com:old"), "{text}");
        assert!(!text.contains("by="), "{text}");
        assert_eq!(
            credentials_core::store::list_meta_read_only_with_schema(&root.join("vault/store.db"))
                .unwrap()
                .1,
            13
        );
        let usable = success(&root, &["usable"]);
        assert!(usable.contains("serviceable: 1"), "{usable}");
        drop(_lease);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn missing_or_malformed_creator_metadata_never_hides_inventory() {
        let mut report = serde_json::json!({"credentials": [
            {"id": "cookie:example.com:one", "state": "active", "record_version": 1, "created_by": 17},
            {"id": "cookie:example.com:two", "state": "active", "record_version": 1}
        ]});
        let rows = parse_inventory(&report).unwrap();
        assert_eq!(rows.len(), 2);
        for row in &rows {
            assert!(!render_inventory_row(row, &report).contains("by="));
        }
        attach_inventory_creators(&mut report, &[]);
        assert_eq!(parse_inventory(&report).unwrap(), rows);
    }

    fn root_schema_13() -> PathBuf {
        let root = root("schema-13");
        let cfg = global(&root);
        let sqlite = open_sqlite(&descriptor(&cfg)).unwrap();
        credentials_core::store::migrate_through_for_test(&sqlite, 13).unwrap();
        let key = resolve_store_key(&cfg).unwrap();
        let key_id = key.key_id().to_hex();
        let record = VaultRecord::new_cookie("operator", b"session=old".to_vec());
        let envelope = credentials_core::envelope::seal(
            &key,
            &serde_json::to_vec(&record).unwrap(),
            &credentials_core::envelope::RecordBinding {
                credential_id: "cookie:example.com:old",
                record_version: 1,
            },
        )
        .unwrap();
        sqlite.with_conn(|conn| {
            conn.execute("INSERT INTO credentials (credential_id, record_version, key_id, state, envelope, updated_at_ms, created_at_ms) VALUES ('cookie:example.com:old', 1, ?1, 'active', ?2, 7, 7)", rusqlite::params![key_id, envelope])?;
            Ok(())
        }).unwrap();
        drop(sqlite);
        root
    }
}

#[cfg(test)]
mod explicit_route_regressions {
    use super::*;

    #[test]
    fn a_wrong_named_connection_refuses_instead_of_opening_offline_store() {
        let _env = discovery_tests::env_guard();
        let root = std::env::temp_dir().join(format!("ck-named-refusal-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let named = root.join("missing-connection.json");
        let previous = std::env::var_os("SUBC_CONNECTION_FILE");
        std::env::set_var("SUBC_CONNECTION_FILE", &named);
        let global = GlobalArgs {
            data_dir: root.clone(),
            key_source: KeySource::OperatorPath {
                path: root.join("missing.key"),
            },
            subc_conn: Some(named),
        };
        let result = commit_admin(
            &global,
            AdminOpBody::Status {
                v: ADMIN_OP_SCHEMA_V1,
            },
        );
        match previous {
            Some(value) => std::env::set_var("SUBC_CONNECTION_FILE", value),
            None => std::env::remove_var("SUBC_CONNECTION_FILE"),
        }
        assert!(matches!(result, Err(CliError::LocalFailure(_))));
        assert!(!root.join("store.db").exists());
        std::fs::remove_dir_all(root).unwrap();
    }
}
