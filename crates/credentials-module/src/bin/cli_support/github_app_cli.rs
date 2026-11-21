use std::collections::{BTreeMap, BTreeSet};

use credentials_core::{
    admin_ops::AdminOpBody,
    agent_policy::{valid_app_slug, valid_github_app_agent},
    oauth_login::generate_state,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    admin_client::{self, RouteCommit},
    browser_login::{self, ApproveOn, BrowserAction},
    login_listener::ManifestListener,
    CliError, GlobalArgs,
};

const MAX_APP_NAME_CHARS: usize = 34;
const MAX_GITHUB_ORG_CHARS: usize = 39;
const GITHUB_ORIGIN: &str = "https://github.com";
const MANIFEST_APP_URL: &str = "https://cortexkit.io";

struct CreateArgs {
    agent: String,
    org: Option<String>,
    name: Option<String>,
    no_relay: bool,
    browser: BrowserAction,
}

fn valid_name(name: &str) -> bool {
    (1..=MAX_APP_NAME_CHARS).contains(&name.chars().count()) && !name.chars().any(char::is_control)
}

fn valid_org(org: &str) -> bool {
    (1..=MAX_GITHUB_ORG_CHARS).contains(&org.len())
        && org.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

fn create_args(args: &[String]) -> Result<CreateArgs, CliError> {
    let mut values = BTreeMap::new();
    let mut switches = BTreeSet::new();
    let mut args = args.iter().map(String::as_str);
    while let Some(flag) = args.next() {
        match flag {
            "--agent" | "--org" | "--name" | "--approve-on" | "--browser" => {
                let value = args
                    .next()
                    .ok_or_else(|| usage(format!("{flag} requires a value")))?;
                if values.insert(flag, value).is_some() {
                    return Err(usage(format!("{flag} must not be repeated")));
                }
            }
            "--no-relay" | "--no-browser" => {
                if !switches.insert(flag) {
                    return Err(usage(format!("{flag} must not be repeated")));
                }
            }
            _ => return Err(usage("unexpected argument for github-app create")),
        }
    }
    match values.get("--approve-on").copied() {
        None | Some("this") => {}
        Some("other") => return Err(usage("GitHub App creation requires a browser on this computer; --approve-on other is not supported")),
        Some(_) => return Err(usage("--approve-on must be this")),
    }
    let agent = values
        .get("--agent")
        .copied()
        .ok_or_else(|| usage("--agent is required"))?;
    if !valid_github_app_agent(agent) {
        return Err(usage(
            "--agent must be agent_ followed by 16 lowercase hex digits",
        ));
    }
    let org = values.get("--org").copied();
    if org.is_some_and(|org| !valid_org(org)) {
        return Err(usage("--org must be 1–39 ASCII letters, digits or hyphens"));
    }
    let name = values.get("--name").copied();
    if name.is_some_and(|name| !valid_name(name)) {
        return Err(usage(
            "--name must be 1–34 characters and contain no control characters",
        ));
    }
    let mut browser_flags = Vec::new();
    if let Some(value) = values.get("--browser") {
        browser_flags.extend(["--browser".into(), (*value).into()]);
    }
    if switches.contains("--no-browser") {
        browser_flags.push("--no-browser".into());
    }
    Ok(CreateArgs {
        agent: agent.into(),
        org: org.map(str::to_owned),
        name: name.map(str::to_owned),
        no_relay: switches.contains("--no-relay"),
        browser: browser_login::browser_action(&browser_flags, ApproveOn::This)?,
    })
}

fn usage(message: impl Into<String>) -> CliError {
    CliError::Usage(message.into())
}

pub(super) fn cmd(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    let commit = |op: AdminOpBody| {
        let Some(path) = &global.subc_conn else {
            return RouteCommit::NoLiveModule(String::new());
        };
        admin_client::commit(
            &global.data_dir,
            &crate::resolver_config(global),
            path,
            &op,
            None,
        )
    };
    let (verb, args) = args
        .split_first()
        .ok_or_else(|| usage(help("github-app")))?;
    let verb = verb.as_str();
    match verb {
        "create" => run_create(
            create_args(args)?,
            commit,
            browser_login::pasted_lines,
            |action, url| {
                browser_login::present(
                    action,
                    url,
                    |url| crate::open_in_browser(action, url),
                    browser_login::copy_link,
                )
            },
            |line| println!("{line}"),
        ),
        "relay-retry" | "rotate-webhook-secret" => {
            let [flag, slug] = args else {
                return Err(usage("expected --slug <slug>"));
            };
            if flag != "--slug" || !valid_app_slug(slug) {
                return Err(usage("expected --slug with a valid GitHub App slug"));
            }
            run_maintenance(verb, slug, commit, |line| println!("{line}"))
        }
        _ => Err(usage(help("github-app"))),
    }
}

fn run_maintenance(
    verb: &str,
    slug: &str,
    commit: impl FnOnce(AdminOpBody) -> RouteCommit,
    mut emit: impl FnMut(&str),
) -> Result<(), CliError> {
    let rotate = verb == "rotate-webhook-secret";
    let result = result(commit(if rotate {
        AdminOpBody::GitHubAppWebhookRotate {
            v: 1,
            slug: slug.into(),
        }
    } else {
        AdminOpBody::GitHubAppRelayRetry {
            v: 1,
            slug: slug.into(),
        }
    }))?;
    if result["slug"].as_str() != Some(slug) {
        return Err(bad_reply());
    }
    if rotate && result["repeated_put"].as_bool().ok_or_else(bad_reply)? {
        emit("Warning: the relay accepts the old secret for only 10 minutes from its first acceptance of the candidate.");
        emit("The relay does not promise to preserve that grace period across a repeated PUT.");
    }
    emit(slug);
    Ok(())
}

#[derive(Deserialize)]
struct Prepared {
    name: String,
    default_permissions: BTreeMap<String, String>,
    default_events: Vec<String>,
}

#[derive(Deserialize)]
struct RelaySlot {
    slot: String,
    webhook_url: String,
}

fn run_create(
    args: CreateArgs,
    mut commit: impl FnMut(AdminOpBody) -> RouteCommit,
    pasted: impl FnOnce() -> tokio::sync::mpsc::Receiver<std::io::Result<String>>,
    present: impl FnOnce(BrowserAction, &str),
    mut emit: impl FnMut(&str),
) -> Result<(), CliError> {
    let prepare = || AdminOpBody::GitHubAppManifestPrepare {
        v: 1,
        agent: args.agent.clone(),
    };
    let prepared: Prepared =
        serde_json::from_value(result(commit(prepare()))?).map_err(|_| bad_reply())?;
    let name = args.name.unwrap_or(prepared.name);
    if !valid_name(&name) {
        return Err(bad_reply());
    }
    let relay = if args.no_relay {
        None
    } else {
        match commit(AdminOpBody::GitHubAppRelaySlotOpen { v: 1 }) {
            RouteCommit::Refused(message) if code(&message) == "relay_unavailable_for_account" => {
                None
            }
            reply => {
                Some(serde_json::from_value::<RelaySlot>(result(reply)?).map_err(|_| bad_reply())?)
            }
        }
    };
    if relay.is_none() {
        emit("Warning: this App has no relay; GitHub webhook events will not reach this vault.");
    }

    let listener = ManifestListener::bind()
        .ok_or_else(|| CliError::Io("Could not bind a loopback listener.".into()))?;
    let start = listener
        .start_url()
        .map_err(|_| CliError::Io("Could not read the loopback address.".into()))?;
    let redirect = listener
        .redirect_url()
        .map_err(|_| CliError::Io("Could not read the loopback address.".into()))?;
    let state = generate_state()
        .map_err(|_| CliError::Io("Could not generate a GitHub App callback state.".into()))?;
    let org_path = args
        .org
        .as_deref()
        .map(|org| format!("/organizations/{org}"))
        .unwrap_or_default();
    let action = format!("{GITHUB_ORIGIN}{org_path}/settings/apps/new?state={state}");
    let mut manifest = json!({
        "name": name,
        "url": MANIFEST_APP_URL,
        "redirect_url": redirect,
        "public": false,
        "default_permissions": prepared.default_permissions,
        "default_events": prepared.default_events,
    });
    if let Some(relay) = &relay {
        manifest["hook_attributes"] = json!({"url": relay.webhook_url, "active": true});
    }
    if args.browser != BrowserAction::Open {
        emit(&start);
    }
    present(args.browser, &start);
    let callback = crate::tokio_block_on(listener.wait(&action, &manifest, &state, pasted()))
        .map_err(|message| CliError::Io(message.into()))?;
    let completion = commit(AdminOpBody::GitHubAppCreateComplete {
        v: 1,
        code: callback,
        agent: args.agent.clone(),
        slot: relay.map(|slot| slot.slot),
    });
    // A lost transport reply is not a refusal. The first op may have consumed the
    // code and saved the App, so only the read-only agent check is safe here.
    if matches!(completion, RouteCommit::Indeterminate(_)) {
        let guidance = match commit(prepare()) {
            RouteCommit::Refused(message) if code(&message) == "github_app_agent_exists" => {
                "The App may be saved. Check `ck auth list`; if listed, run `ck auth github-app relay-retry --slug <slug>`.".into()
            }
            _ => format!("github_app_conversion_unknown: Check GitHub for the App named {name:?}; the vault could not confirm conversion."),
        };
        return Err(CliError::RouteIndeterminate(guidance));
    }
    if let RouteCommit::Refused(message) = &completion {
        let guidance = match code(message) {
            "github_app_agent_exists" => Some(format!("github_app_agent_exists: The App was created on GitHub but not converted. Delete the App named {name:?}.")),
            "github_app_code_invalid" => Some(format!("github_app_code_invalid: Delete the App named {name:?} if it exists, then rerun creation.")),
            "github_app_conversion_unknown" => Some(format!("github_app_conversion_unknown: Check GitHub for the App named {name:?}, delete it if present, then rerun creation.")),
            _ => None,
        };
        if let Some(guidance) = guidance {
            return Err(CliError::RouteRefused(guidance));
        }
    }
    report_creation(result(completion)?, &name, emit)
}

fn report_creation(reply: Value, name: &str, mut emit: impl FnMut(&str)) -> Result<(), CliError> {
    let slug = reply["slug"].as_str().filter(|slug| valid_app_slug(slug));
    let app_id = reply["app_id"].as_str().filter(|id| {
        id.parse::<u64>()
            .is_ok_and(|n| n > 0 && n.to_string() == *id)
    });
    let outcome = reply["outcome"].as_str();
    if outcome == Some("github_app_unsaved") {
        let target = match slug {
            Some(slug) => format!("with slug {slug}"),
            None => format!("named {name:?}"),
        };
        return Err(CliError::Io(format!(
            "github_app_unsaved: Delete the GitHub App {target}; the vault could not save it."
        )));
    }
    if !matches!(outcome, Some("created" | "relay_registration_failed")) {
        return Err(bad_reply());
    }
    let (Some(slug), Some(app_id)) = (slug, app_id) else {
        return Err(bad_reply());
    };
    let install_url = format!("{GITHUB_ORIGIN}/apps/{slug}/installations/new");
    if reply["install_url"].as_str() != Some(&install_url) {
        return Err(bad_reply());
    }
    emit(&format!("Slug: {slug}"));
    emit(&format!("App id: {app_id}"));
    emit(&format!("Install: {install_url}"));
    emit("Choose \"Only select repositories\" when installing the App.");
    if outcome == Some("relay_registration_failed") {
        let mut message = "relay_registration_failed: The App is saved, but webhook events will not arrive without relay registration.".to_owned();
        if reply["cause"].as_str() == Some("relay_unavailable") {
            message.push_str(&format!(
                " Try `ck auth github-app relay-retry --slug {slug}`."
            ));
        }
        return Err(CliError::Io(message));
    }
    Ok(())
}

fn code(reason: &str) -> &str {
    reason.split_once('/').map_or("", |(code, _)| code)
}

fn bad_reply() -> CliError {
    CliError::Io("The daemon returned an invalid GitHub App reply. Check `ck auth list`.".into())
}

fn result(reply: RouteCommit) -> Result<Value, CliError> {
    match reply {
        RouteCommit::Committed(value) => Ok(value),
        RouteCommit::NoLiveModule(_) => Err(CliError::LocalFailure("GitHub App commands require the running vault daemon on this computer".into())),
        RouteCommit::LocalFailure(_) => Err(CliError::LocalFailure("could not authorize the GitHub App request; check the local vault key".into())),
        RouteCommit::Indeterminate(_) => Err(CliError::RouteIndeterminate("The daemon did not confirm the GitHub App operation. Check the vault before repeating it.".into())),
        // Relay and GitHub can return arbitrary text. Only render the daemon's
        // known codes, never raw refusal messages or transport errors.
        RouteCommit::Refused(message) => Err(CliError::RouteRefused(match code(&message) {
            known @ ("agent_invalid" | "github_app_agent_exists" | "policy_unavailable"
                | "invalid_params" | "not_found" | "github_app_inactive" | "github_app_no_relay"
                | "relay_slot_limit" | "relay_unavailable" | "relay_unavailable_for_account"
                | "relay_request_refused" | "relay_reply_invalid" | "relay_slot_expired"
                | "relay_app_mismatch" | "audit_write_failed") => known.into(),
            "github_app_rotation_pending" => "github_app_rotation_pending: Run `rotate-webhook-secret` for this App to resume rotation.".into(),
            "github_app_hook_update_failed" => "github_app_hook_update_failed: Rerun `rotate-webhook-secret` to resume this rotation.".into(),
            _ => "the GitHub App operation was not admitted".into(),
        })),
    }
}

pub(super) fn help(verb: &str) -> &'static str {
    match verb {
        "github-app create" => {
            "ck auth github-app create --agent <id> [--org <login>] [--name <name>]\n\
            \x20 [--no-relay] [--browser open|copy|show] [--no-browser] [--approve-on this]\n\n\
            \x20 --agent <id>        agent registry id\n\
            \x20 --org <login>       register the App in a GitHub organization\n\
            \x20 --name <name>       override the generated App name\n\
            \x20 --no-relay          create without webhook relay delivery\n\
            \x20 --browser <action>  open, copy or show the loopback start URL\n\
            \x20 --no-browser        show the URL without opening a browser\n\
            \x20 --approve-on this   approve on this computer (the only supported place)\n\n\
            NOTES\n\
            Create a private GitHub App for the agent. Approve the form in a browser\n\
            on this computer. You may paste the full callback URL in the terminal.\n\
            The running daemon stores the App key and registers its webhook with the\n\
            relay unless you use --no-relay. The CLI sees neither secret."
        }
        "github-app relay-retry" => {
            "ck auth github-app relay-retry --slug <slug>\n\n\
            \x20 --slug <slug>  GitHub App slug\n\n\
            NOTES\n\
            Complete an existing slot using the saved App and its current secret.\n\
            No new slot is opened. Resume a pending rotation before retrying."
        }
        "github-app rotate-webhook-secret" => {
            "ck auth github-app rotate-webhook-secret --slug <slug>\n\n\
            \x20 --slug <slug>  GitHub App slug\n\n\
            NOTES\n\
            Update the relay first, then GitHub. If interrupted, run the same command\n\
            again to resume the pending rotation without generating another secret."
        }
        _ => {
            "ck auth github-app <command> [flags]\n\n\
            \x20 create                 Create a private GitHub App for an agent.\n\
            \x20 relay-retry            Retry registration of a saved App's relay slot.\n\
            \x20 rotate-webhook-secret  Rotate or resume rotation of the webhook secret.\n\n\
            Run `ck auth help github-app <command>` for details."
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        net::TcpStream,
        thread,
        time::Duration,
    };

    use super::*;

    const AGENT: &str = "agent_ab64ea0873bbee0c";
    const CODE: &str = "manifest-code-redaction-canary";
    const NAME: &str = "agent \"quoted\" <name> & more";
    const MARKERS: [&str; 5] = [
        "-----BEGIN armour-marker-----",
        "webhook-marker",
        "client-marker",
        "machine-marker",
        CODE,
    ];

    fn no_paste() -> tokio::sync::mpsc::Receiver<std::io::Result<String>> {
        tokio::sync::mpsc::channel(1).1
    }

    fn strings(args: &[&str]) -> Vec<String> {
        args.iter().map(|arg| (*arg).into()).collect()
    }

    fn get(url: &str) -> String {
        let (address, path) = url
            .strip_prefix("http://")
            .unwrap()
            .split_once('/')
            .unwrap();
        let mut socket = TcpStream::connect(address).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        write!(socket, "GET /{path} HTTP/1.1\r\nHost: {address}\r\n\r\n").unwrap();
        let mut body = String::new();
        socket.read_to_string(&mut body).unwrap();
        body
    }

    fn start_form(start: &str, wrong_state: bool, relay: bool) {
        assert!(start.starts_with("http://127.0.0.1:"));
        assert!(get(&start.replace("/start", "/favicon.ico")).starts_with("HTTP/1.1 404"));
        let page = get(start);
        assert!(page.starts_with("HTTP/1.1 200"));
        assert!(page.contains("document.forms[0].submit()"));
        let action = page
            .split_once("action=\"")
            .unwrap()
            .1
            .split('"')
            .next()
            .unwrap();
        let state = action
            .strip_prefix("https://github.com/organizations/example-org/settings/apps/new?state=")
            .unwrap();
        assert!(!state.is_empty() && state != "wrong");
        let encoded = page
            .split_once("name=\"manifest\" value=\"")
            .unwrap()
            .1
            .split('"')
            .next()
            .unwrap();
        assert!(encoded.contains("&lt;name&gt;") && !encoded.contains("<name>"));
        let decoded = encoded
            .replace("&quot;", "\"")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&amp;", "&");
        let manifest: Value = serde_json::from_str(&decoded).unwrap();
        assert_eq!(manifest["name"], NAME);
        assert_eq!(manifest["url"], "https://cortexkit.io");
        assert_eq!(manifest["public"], false);
        assert_eq!(manifest["default_permissions"], json!({"issues":"read"}));
        assert_eq!(manifest["default_events"], json!(["issues"]));
        let hook = relay.then(|| json!({"url":"https://hooks.cortexkit.io/v1/github/apps/slot/webhook", "active": true}));
        assert_eq!(manifest.get("hook_attributes"), hook.as_ref());
        let target = manifest["redirect_url"].as_str().unwrap();
        assert_eq!(target, start.replace("/start", "/auth/github-app/callback"));
        let state = if wrong_state { "wrong" } else { state };
        let response = get(&format!("{target}?code={CODE}&state={state}"));
        assert!(response.starts_with(if wrong_state {
            "HTTP/1.1 400"
        } else {
            "HTTP/1.1 200"
        }));
        assert!(MARKERS
            .iter()
            .all(|marker| !page.contains(marker) && !response.contains(marker)));
    }

    fn prepared() -> RouteCommit {
        RouteCommit::Committed(
            json!({"name":"ck-agent_ab64ea0873bbee0c-cafeee", "default_permissions":{"issues":"read"}, "default_events":["issues"]}),
        )
    }

    fn completion(outcome: &str, cause: &str) -> RouteCommit {
        RouteCommit::Committed(json!({
            "outcome":outcome, "cause":cause, "slug":"created-app", "app_id":"9007199254740993",
            "install_url":"https://github.com/apps/created-app/installations/new", "ignored":MARKERS,
        }))
    }

    fn exercise_create(
        wrong_state: bool,
        relay: bool,
        responses: Vec<RouteCommit>,
    ) -> (Vec<&'static str>, String, Result<(), CliError>) {
        let mut args = strings(&[
            "--agent",
            AGENT,
            "--org",
            "example-org",
            "--name",
            NAME,
            "--browser",
            "open",
        ]);
        if !relay {
            args.push("--no-relay".into());
        }
        let mut calls = Vec::new();
        let mut stdout = String::new();
        let mut responses = responses.into_iter();
        let mut browser = None;
        let result = run_create(
            create_args(&args).unwrap(),
            |op| {
                calls.push(op.op_name());
                if let AdminOpBody::GitHubAppCreateComplete {
                    code, agent, slot, ..
                } = op
                {
                    assert!(code == CODE);
                    assert_eq!(agent, AGENT);
                    assert_eq!(slot.as_deref(), relay.then_some("slot"));
                }
                responses.next().expect("unexpected admin call")
            },
            no_paste,
            |action, start| {
                assert_eq!(action, BrowserAction::Open);
                let start = start.to_owned();
                browser = Some(thread::spawn(move || {
                    start_form(&start, wrong_state, relay)
                }));
            },
            |line| {
                stdout.push_str(line);
                stdout.push('\n');
            },
        );
        browser.unwrap().join().unwrap();
        assert!(responses.next().is_none());
        let output = format!(
            "{stdout}{}",
            result
                .as_ref()
                .err()
                .map(ToString::to_string)
                .unwrap_or_default()
        );
        assert!(
            MARKERS.iter().all(|marker| !output.contains(marker)),
            "secret appeared in CLI output"
        );
        (calls, stdout, result)
    }

    #[test]
    fn github_app_name_accepts_34_characters_and_refuses_35() {
        assert!(create_args(&strings(&[
            "--agent",
            AGENT,
            "--name",
            &"é".repeat(34),
            "--no-browser"
        ]))
        .is_ok());
        assert!(create_args(&strings(&[
            "--agent",
            AGENT,
            "--name",
            &"é".repeat(35),
            "--no-browser"
        ]))
        .is_err());
    }

    #[test]
    fn github_app_org_accepts_39_characters_and_refuses_40() {
        assert!(create_args(&strings(&[
            "--agent",
            AGENT,
            "--org",
            &"a".repeat(39),
            "--no-browser"
        ]))
        .is_ok());
        assert!(create_args(&strings(&[
            "--agent",
            AGENT,
            "--org",
            &"a".repeat(40),
            "--no-browser"
        ]))
        .is_err());
        assert!(!valid_org("org/other"));
    }

    #[test]
    fn github_app_cli_posts_a_private_manifest_and_checks_the_loopback_state() {
        let slot = RouteCommit::Committed(
            json!({"slot":"slot", "webhook_url":"https://hooks.cortexkit.io/v1/github/apps/slot/webhook"}),
        );
        let (calls, output, result) = exercise_create(
            false,
            true,
            vec![prepared(), slot, completion("created", "")],
        );
        result.unwrap();
        assert_eq!(
            calls,
            [
                "admin.github_app_manifest_prepare",
                "admin.github_app_relay_slot_open",
                "admin.github_app_create_complete"
            ]
        );
        assert!(output.contains("App id: 9007199254740993"));
        assert!(output.contains("Only select repositories"));

        let (calls, _, result) = exercise_create(true, false, vec![prepared()]);
        assert_eq!(calls, ["admin.github_app_manifest_prepare"]);
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("state did not match"));
    }

    #[test]
    fn github_app_cli_reconciles_a_lost_reply_without_replaying_the_code_or_advising_deletion() {
        for saved in [true, false] {
            let reconcile = if saved {
                RouteCommit::Refused(format!(
                    "github_app_agent_exists/permanent: {}",
                    MARKERS.join(" ")
                ))
            } else {
                prepared()
            };
            let (calls, _, result) = exercise_create(
                false,
                false,
                vec![
                    prepared(),
                    RouteCommit::Indeterminate(MARKERS.join(" ")),
                    reconcile,
                ],
            );
            assert_eq!(
                calls,
                [
                    "admin.github_app_manifest_prepare",
                    "admin.github_app_create_complete",
                    "admin.github_app_manifest_prepare"
                ]
            );
            let error = result.unwrap_err().to_string();
            assert!(!error.to_ascii_lowercase().contains("delete"));
            if saved {
                assert!(error.contains("ck auth list") && error.contains("relay-retry"));
            } else {
                assert!(error.contains("github_app_conversion_unknown"));
            }
        }
    }

    #[test]
    fn github_app_cli_only_offers_same_slot_retry_for_transient_relay_failure() {
        for cause in [
            "relay_unavailable",
            "relay_reply_invalid",
            "relay_slot_expired",
            "relay_app_mismatch",
            "relay_unavailable_for_account",
            "relay_request_refused",
        ] {
            let (_, _, result) = exercise_create(
                false,
                false,
                vec![prepared(), completion("relay_registration_failed", cause)],
            );
            let error = result.unwrap_err().to_string();
            assert!(error.contains("The App is saved"));
            assert_eq!(
                error.contains("relay-retry --slug created-app"),
                cause == "relay_unavailable"
            );
        }
    }

    #[test]
    fn github_app_cli_uses_fixed_creation_guidance_instead_of_remote_error_text() {
        for code in [
            "github_app_agent_exists",
            "github_app_code_invalid",
            "github_app_conversion_unknown",
            "relay_unavailable",
            "invalid_params",
        ] {
            let (_, _, result) = exercise_create(
                false,
                false,
                vec![
                    prepared(),
                    RouteCommit::Refused(format!("{code}/permanent: {}", MARKERS.join(" "))),
                ],
            );
            assert!(result.unwrap_err().to_string().contains(code));
        }
        for (slug, target) in [
            (json!("created-app"), "with slug created-app"),
            (json!(null), "named"),
        ] {
            let reply = RouteCommit::Committed(json!({
                "outcome":"github_app_unsaved", "slug":slug,
                "cause":MARKERS.join(" "), "ignored":MARKERS,
            }));
            let (_, stdout, result) = exercise_create(false, false, vec![prepared(), reply]);
            assert!(!stdout.contains("Install:"));
            assert!(result.unwrap_err().to_string().contains(target));
        }
    }

    #[tokio::test]
    async fn github_app_pasted_callback_checks_the_same_state() {
        for matches in [false, true] {
            let (sender, receiver) = tokio::sync::mpsc::channel(1);
            let state = if matches { "expected" } else { "wrong" };
            sender
                .send(Ok(format!("code={CODE}&state={state}")))
                .await
                .unwrap();
            let result = ManifestListener::bind()
                .unwrap()
                .wait("", &json!({}), "expected", receiver)
                .await;
            if matches {
                assert!(result.unwrap() == CODE);
            } else {
                assert!(result.unwrap_err().contains("state did not match"));
            }
        }
    }

    #[test]
    fn github_app_cli_warns_about_grace_only_for_a_repeated_put() {
        for repeated_put in [false, true] {
            let mut lines = Vec::new();
            run_maintenance(
                "rotate-webhook-secret",
                "created-app",
                |op| {
                    assert!(matches!(
                        op,
                        AdminOpBody::GitHubAppWebhookRotate { v: 1, .. }
                    ));
                    RouteCommit::Committed(
                        json!({"slug":"created-app", "repeated_put":repeated_put}),
                    )
                },
                |line| lines.push(line.to_owned()),
            )
            .unwrap();
            let output = lines.join("\n");
            assert_eq!(
                output.contains("10 minutes from its first acceptance"),
                repeated_put
            );
            assert_eq!(
                output.contains("does not promise to preserve"),
                repeated_put
            );
        }
    }
}
