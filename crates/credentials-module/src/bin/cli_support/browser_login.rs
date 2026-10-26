//! Presentation and concurrent callback input for authorization-code logins.

use std::io::{IsTerminal, Write};
use std::process::{Command, Stdio};

use credentials_core::oauth_login::{parse_callback, Callback};

use crate::{has_flag, login_listener, no_local_display, optional, CliError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApproveOn {
    This,
    Other,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BrowserAction {
    Open,
    Copy,
    Show,
}

/// Local fake endpoints for process-level tests. Release builds cannot redirect
/// authorization or token exchange through an environment variable.
#[cfg(all(debug_assertions, feature = "test-support"))]
pub fn test_endpoint(field: &str, default: &'static str) -> &'static str {
    let Some(value) = std::env::var("CK_AUTH_TEST_LOGIN_WIRE")
        .ok()
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok())
        .and_then(|config| config.get(field)?.as_str().map(str::to_string))
    else {
        return default;
    };
    assert!(
        value.starts_with("http://127.0.0.1:"),
        "fake OAuth must stay on numeric loopback"
    );
    Box::leak(value.into_boxed_str())
}

#[cfg(all(debug_assertions, feature = "test-support"))]
pub fn test_wire(
    wire: &credentials_core::catalog::LoginProvider,
) -> credentials_core::catalog::LoginProvider {
    credentials_core::catalog::LoginProvider {
        authorize_url: test_endpoint("authorize_url", wire.authorize_url),
        token_url: test_endpoint("token_url", wire.token_url),
        redirect_uri: test_endpoint("redirect_uri", wire.redirect_uri),
        code_redirect_uri: wire
            .code_redirect_uri
            .map(|uri| test_endpoint("code_redirect_uri", uri)),
        ..*wire
    }
}

fn pick(prompt: &str, items: &[&str], default: usize) -> Result<usize, CliError> {
    dialoguer::Select::with_theme(&dialoguer::theme::ColorfulTheme::default())
        .with_prompt(prompt)
        .items(items)
        .default(default)
        .interact()
        .map_err(|e| CliError::Io(format!("reading login choice: {e}")))
}

fn choice_flag(args: &[String], flag: &str) -> Result<Option<String>, CliError> {
    match optional(args, flag) {
        Some(value) if !value.starts_with("--") => Ok(Some(value)),
        None if !has_flag(args, flag) => Ok(None),
        _ => Err(CliError::Usage(format!("{flag} needs a value"))),
    }
}

pub fn approve_on(args: &[String]) -> Result<ApproveOn, CliError> {
    let default = if no_local_display() {
        ApproveOn::Other
    } else {
        ApproveOn::This
    };
    match choice_flag(args, "--approve-on")?.as_deref() {
        Some("this") => Ok(ApproveOn::This),
        Some("other") => Ok(ApproveOn::Other),
        Some(_) => Err(CliError::Usage("--approve-on must be this or other".into())),
        None if !std::io::stdin().is_terminal() => Ok(default),
        None => Ok(
            if pick(
                "Where will you approve this login?",
                &[
                    "In a browser on this computer",
                    "On another device (paste the result back here)",
                ],
                usize::from(default == ApproveOn::Other),
            )? == 0
            {
                ApproveOn::This
            } else {
                ApproveOn::Other
            },
        ),
    }
}

pub fn browser_action(args: &[String], location: ApproveOn) -> Result<BrowserAction, CliError> {
    if has_flag(args, "--no-browser")
        && choice_flag(args, "--browser")?.is_some_and(|value| value != "show")
    {
        return Err(CliError::Usage(
            "--no-browser cannot be combined with --browser open or copy".into(),
        ));
    }
    let action = match choice_flag(args, "--browser")?.as_deref() {
        Some("open") => BrowserAction::Open,
        Some("copy") => BrowserAction::Copy,
        Some("show") => BrowserAction::Show,
        Some(_) => {
            return Err(CliError::Usage(
                "--browser must be open, copy or show".into(),
            ))
        }
        None if has_flag(args, "--no-browser") || !std::io::stdin().is_terminal() => {
            BrowserAction::Show
        }
        None if location == ApproveOn::This => match pick(
            "Open it in your browser, or copy the link?",
            &["Open in browser", "Copy link to clipboard", "Just show it"],
            0,
        )? {
            0 => BrowserAction::Open,
            1 => BrowserAction::Copy,
            _ => BrowserAction::Show,
        },
        None => match pick(
            "Copy the link, or just show it?",
            &["Copy link to clipboard", "Just show it"],
            0,
        )? {
            0 => BrowserAction::Copy,
            _ => BrowserAction::Show,
        },
    };
    if location == ApproveOn::Other && action == BrowserAction::Open {
        return Err(CliError::Usage(
            "--browser open requires --approve-on this".into(),
        ));
    }
    Ok(action)
}

pub fn choose_and_present(args: &[String], location: ApproveOn, url: &str) -> Result<(), CliError> {
    let action = browser_action(args, location)?;
    present(
        action,
        url,
        |url| crate::open_in_browser(action, url),
        copy_link,
    );
    Ok(())
}

/// Keep presentation side effects injectable, so showing a link cannot silently
/// start a browser or clipboard helper.
pub fn present(
    action: BrowserAction,
    url: &str,
    mut open: impl FnMut(&str) -> std::io::Result<()>,
    mut copy: impl FnMut(&str) -> std::io::Result<()>,
) {
    let result = match action {
        BrowserAction::Open => open(url),
        BrowserAction::Copy => copy(url),
        BrowserAction::Show => return,
    };
    if let Err(error) = result {
        println!(
            "Could not {}: {error}. Use the URL below instead.",
            match action {
                BrowserAction::Open => "open the browser",
                _ => "copy the link to the clipboard",
            }
        );
        println!("  {url}");
    }
}

fn pipe_url(program: &str, args: &[&str], url: &str) -> std::io::Result<()> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let written = child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(url.as_bytes());
    let status = child.wait()?;
    written?;
    if status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other(format!(
            "{program} exited with {status}"
        )))
    }
}

pub fn copy_link(url: &str) -> std::io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        pipe_url("pbcopy", &[], url)
    }
    #[cfg(target_os = "windows")]
    {
        pipe_url("clip.exe", &[], url)
    }
    #[cfg(target_os = "linux")]
    {
        if std::env::var_os("WAYLAND_DISPLAY").is_some() && pipe_url("wl-copy", &[], url).is_ok() {
            return Ok(());
        }
        pipe_url("xclip", &["-selection", "clipboard"], url)
            .or_else(|_| pipe_url("xsel", &["--clipboard", "--input"], url))
    }
}

/// Read stdin outside Tokio's blocking pool: an idle terminal must not hold up
/// runtime shutdown after the browser wins. Closing the receiver stops further
/// reads; an already blocked OS read is left to end with this CLI process.
fn pasted_lines() -> tokio::sync::mpsc::Receiver<std::io::Result<String>> {
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    std::thread::spawn(move || loop {
        if tx.is_closed() {
            break;
        }
        let mut line = String::new();
        let read = std::io::stdin().read_line(&mut line);
        if matches!(read, Ok(0)) {
            break;
        }
        let line = read.map(|_| line);
        let failed = line.is_err();
        if tx.blocking_send(line).is_err() || failed {
            break;
        }
    });
    rx
}

fn validated_callback(raw: &str, expected_state: &str) -> Result<Callback, &'static str> {
    match parse_callback(raw) {
        Some(callback) if callback.state == expected_state => Ok(callback),
        Some(_) => Err("The callback state does not match this login. Paste the callback from the URL above."),
        None => Err("Could not parse the login callback. Paste the complete callback URL or code and state."),
    }
}

pub async fn read_callback(
    listener: Option<login_listener::CallbackListener>,
    prompt: &str,
    expected_state: &str,
) -> Result<Callback, CliError> {
    let listener = listener
        .map(login_listener::CallbackListener::into_async)
        .transpose()
        .map_err(|e| CliError::Io(format!("listening for login callback: {e}")))?;
    if listener.is_some() {
        println!(
            "Approve in the browser on this computer, or paste the callback here at any time."
        );
    }
    let prompt = if listener.is_some() {
        "Copy the full callback URL (or code#state if shown) and paste it here, then Enter:"
    } else {
        prompt
    }
    .replace(" — ", ", ");
    println!("{prompt}");
    let mut listening = listener.is_some();
    // Keep the browser future alive across rejected pastes. A bad line must not
    // cancel an HTTP callback that is still arriving in several TCP packets.
    let browser = async {
        let listener = listener?;
        tokio::time::timeout(login_listener::LISTEN_TIMEOUT, async {
            loop {
                if let Some(raw) = login_listener::receive_code(&listener).await {
                    match validated_callback(&raw, expected_state) {
                        Ok(callback) => return callback,
                        Err(reason) => println!("{reason}\n{prompt}"),
                    }
                }
            }
        })
        .await
        .ok()
    };
    tokio::pin!(browser);
    let mut lines = pasted_lines();
    let mut stdin_closed = false;
    loop {
        let raw = tokio::select! {
            line = lines.recv(), if !stdin_closed => match line {
                Some(line) => line.map_err(|e| CliError::Io(format!("reading pasted code: {e}")))?,
                None => {
                    stdin_closed = true;
                    if !listening {
                        return Err(CliError::Usage("stdin closed before a valid login callback was received".into()));
                    }
                    continue;
                }
            },
            callback = &mut browser, if listening => {
                if let Some(callback) = callback {
                    return Ok(callback);
                }
                listening = false;
                if stdin_closed {
                    return Err(CliError::Usage("no login callback received before the listener timed out".into()));
                }
                println!("The browser listener timed out. You can still paste the callback here.");
                continue;
            }
        };
        match validated_callback(&raw, expected_state) {
            Ok(callback) => return Ok(callback),
            Err(reason) => println!("{reason}"),
        }
        println!("{prompt}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn showing_the_link_has_no_side_effects_and_actions_run_exactly_once() {
        for action in [
            BrowserAction::Show,
            BrowserAction::Open,
            BrowserAction::Copy,
        ] {
            let mut opened = Vec::new();
            let mut copied = Vec::new();
            present(
                action,
                "https://example.test/authorize?state=public",
                |url| {
                    opened.push(url.to_string());
                    Ok(())
                },
                |url| {
                    copied.push(url.to_string());
                    Ok(())
                },
            );
            assert_eq!(opened.len(), usize::from(action == BrowserAction::Open));
            assert_eq!(copied.len(), usize::from(action == BrowserAction::Copy));
            for url in opened.iter().chain(copied.iter()) {
                assert_eq!(url, "https://example.test/authorize?state=public");
            }
        }
    }

    #[test]
    fn invalid_or_missing_choices_are_usage_errors() {
        for args in [vec!["--approve-on"], vec!["--approve-on", "elsewhere"]] {
            let args: Vec<_> = args.into_iter().map(str::to_string).collect();
            assert!(approve_on(&args).is_err());
        }
        for args in [
            vec!["--browser"],
            vec!["--browser", "automatically"],
            vec!["--browser", "open"],
        ] {
            let args: Vec<_> = args.into_iter().map(str::to_string).collect();
            assert!(browser_action(&args, ApproveOn::Other).is_err());
        }
    }
}
