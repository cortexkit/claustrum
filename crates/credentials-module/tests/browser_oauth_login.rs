//! Process-level browser OAuth regression tests. All CLI runs use an isolated home.
#![cfg(all(unix, debug_assertions, feature = "test-support"))]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

use cortexkit_test_support::{ckdev_binary, dev_command};
use credentials_core::test_support::TestTempDir;
use serde_json::{json, Value};

#[path = "support/isolated_cli.rs"]
mod isolated_cli;

fn cli() -> Command {
    let mut command = dev_command(ckdev_binary(env!("CARGO_BIN_EXE_ck-auth")));
    isolated_cli::isolate(&mut command);
    command
}

#[test]
fn every_browser_oauth_command_uses_an_isolated_home() {
    isolated_cli::assert_isolated(&cli());
}

struct Fixture {
    root: TestTempDir,
    callback: String,
    origin: String,
    token_server: TcpListener,
}

impl Fixture {
    fn new() -> Self {
        let root = TestTempDir::new(format!(
            "browser-login-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(root.join("vault")).unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(root.join("master.key"))
            .unwrap()
            .write_all("17".repeat(32).as_bytes())
            .unwrap();
        let callback = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = callback.local_addr().unwrap().to_string();
        drop(callback);
        let token_server = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}", token_server.local_addr().unwrap());
        Self {
            root,
            callback: address,
            origin,
            token_server,
        }
    }

    fn command(&self, provider: &str, flags: &[&str]) -> Command {
        let mut command = cli();
        command
            .args(["login", "--provider", provider])
            .args(flags)
            .args(["--data-dir"])
            .arg(self.root.join("vault"))
            .arg("--key-path")
            .arg(self.root.join("master.key"))
            .env("DISPLAY", ":0")
            .env_remove("WAYLAND_DISPLAY")
            .env(
                "CK_AUTH_TEST_LOGIN_WIRE",
                json!({
                    "authorize_url": format!("{}/authorize", self.origin),
                    "token_url": format!("{}/token", self.origin),
                    "redirect_uri": format!("http://{}/callback", self.callback),
                    "code_redirect_uri": format!("{}/code", self.origin),
                })
                .to_string(),
            );
        command
    }

    fn exchange(&self, success: bool) -> thread::JoinHandle<Value> {
        let listener = self.token_server.try_clone().unwrap();
        listener.set_nonblocking(true).unwrap();
        thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(12);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        thread::sleep(Duration::from_millis(10))
                    }
                    other => panic!("token exchange was not reached: {other:?}"),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut first = String::new();
            reader.read_line(&mut first).unwrap();
            assert!(first.starts_with("POST /token "), "{first}");
            let mut length = None;
            let mut is_json = false;
            loop {
                let mut header = String::new();
                reader.read_line(&mut header).unwrap();
                if header == "\r\n" {
                    break;
                }
                if let Some(value) = header.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = Some(value.trim().parse::<usize>().unwrap());
                }
                is_json |= header.contains("application/json");
            }
            let mut body = vec![0; length.unwrap()];
            reader.read_exact(&mut body).unwrap();
            let request = if is_json {
                serde_json::from_slice(&body).unwrap()
            } else {
                let text = String::from_utf8(body).unwrap();
                let mut value = serde_json::Map::new();
                for pair in text.split('&') {
                    let (key, raw) = pair.split_once('=').unwrap();
                    value.insert(key.to_string(), Value::String(decode(raw)));
                }
                Value::Object(value)
            };
            let (status, response) = if success {
                (
                    "200 OK",
                    json!({"access_token":"fake-access", "refresh_token":"fake-refresh", "expires_in":3600}),
                )
            } else {
                ("400 Bad Request", json!({"error":"fake_exchange_reached"}))
            };
            let response = response.to_string();
            write!(stream, "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}", response.len()).unwrap();
            request
        })
    }

    fn helper_tools(&self, command: &mut Command, fail: bool) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let dir = self.root.join("tools");
        std::fs::create_dir_all(&dir).unwrap();
        let log = self.root.join("helper.log");
        for tool in ["xdg-open", "open", "pbcopy", "wl-copy", "xclip", "xsel"] {
            let script = format!("#!/bin/sh\nprintf '%s %s\\n' '{tool}' \"$*\" >> \"$CK_AUTH_TEST_HELPER_LOG\"\n{}\nexit {}\n", if tool == "open" || tool == "xdg-open" { ":" } else { "/bin/cat > \"$CK_AUTH_TEST_HELPER_INPUT\"" }, u8::from(fail));
            let path = dir.join(tool);
            std::fs::write(&path, script).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        command
            .env("PATH", dir)
            .env("CK_AUTH_TEST_HELPER_LOG", &log)
            .env("CK_AUTH_TEST_HELPER_INPUT", self.root.join("clipboard"));
        log
    }
}

fn decode(raw: &str) -> String {
    let mut bytes = Vec::new();
    let mut input = raw.bytes();
    while let Some(byte) = input.next() {
        bytes.push(match byte {
            b'+' => b' ',
            b'%' => u8::from_str_radix(
                &String::from_utf8(vec![input.next().unwrap(), input.next().unwrap()]).unwrap(),
                16,
            )
            .unwrap(),
            other => other,
        });
    }
    String::from_utf8(bytes).unwrap()
}

fn param(url: &str, name: &str) -> String {
    url.split_once('?')
        .unwrap()
        .1
        .split('&')
        .find_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            (key == name).then(|| decode(value))
        })
        .unwrap()
}

struct Login {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: Receiver<String>,
    output: String,
    stderr: thread::JoinHandle<String>,
}

impl Login {
    fn start(mut command: Command) -> Self {
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take();
        let stdout = child.stdout.take().unwrap();
        let mut stderr = child.stderr.take().unwrap();
        let stderr = thread::spawn(move || {
            let mut out = String::new();
            stderr.read_to_string(&mut out).unwrap();
            out
        });
        let (tx, lines) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                if tx.send(line.unwrap() + "\n").is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            stdin,
            lines,
            output: String::new(),
            stderr,
        }
    }

    fn until(&mut self, needle: &str) {
        let deadline = Instant::now() + Duration::from_secs(8);
        while !self.output.contains(needle) {
            match self
                .lines
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            {
                Ok(line) => self.output.push_str(&line),
                Err(error) => {
                    let _ = self.child.kill();
                    panic!("waiting for {needle}: {error}; stdout: {}", self.output);
                }
            }
        }
    }

    fn authorize_url(&mut self) -> String {
        self.until("/authorize?");
        self.output
            .lines()
            .find(|line| line.starts_with("  http://"))
            .unwrap()
            .trim()
            .to_string()
    }

    fn paste(&mut self, value: &str) {
        writeln!(self.stdin.as_mut().unwrap(), "{value}").unwrap();
    }

    fn finish(mut self, success: bool) -> String {
        let deadline = Instant::now() + Duration::from_secs(8);
        let status = loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = self.child.kill();
                panic!("login did not complete promptly: {}", self.output);
            }
            thread::sleep(Duration::from_millis(10));
        };
        for line in self.lines {
            self.output.push_str(&line);
        }
        let stderr = self.stderr.join().unwrap();
        assert_eq!(
            status.success(),
            success,
            "stdout: {}\nstderr: {stderr}",
            self.output
        );
        self.output + &stderr
    }
}

#[test]
fn paste_while_listening_completes_without_waiting_and_show_spawns_nothing() {
    let fixture = Fixture::new();
    let server = fixture.exchange(true);
    let mut command = fixture.command("xai", &["--approve-on", "this", "--browser", "show"]);
    let helpers = fixture.helper_tools(&mut command, false);
    let mut login = Login::start(command);
    let url = login.authorize_url();
    assert!(
        TcpListener::bind(&fixture.callback).is_err(),
        "this computer must hold the callback socket"
    );
    // An incomplete browser request must not monopolize callback input either.
    let mut partial = TcpStream::connect(&fixture.callback).unwrap();
    partial.write_all(b"GET /callback?code=unfinished").unwrap();
    login.paste(&format!(
        "http://{}/callback?code=pasted-now&state={}",
        fixture.callback,
        param(&url, "state")
    ));
    let output = login.finish(true);
    assert!(
        output.contains("logged in and stored oauth:xai"),
        "{output}"
    );
    assert!(
        !output.contains("Where will you approve") && !output.contains("Open it in your browser")
    );
    assert!(!helpers.exists(), "show must not spawn either helper");
    let exchange = server.join().unwrap();
    assert_eq!(exchange["code"], "pasted-now");
    assert_eq!(
        exchange["redirect_uri"],
        format!("http://{}/callback", fixture.callback)
    );
    use base64::Engine;
    let verifier = exchange["code_verifier"].as_str().unwrap();
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(ring::digest::digest(&ring::digest::SHA256, verifier.as_bytes()).as_ref());
    assert_eq!(param(&url, "code_challenge"), challenge);
    assert_eq!(exchange["code_challenge"], challenge);
    assert!(
        !url.contains(verifier),
        "the PKCE verifier must stay in-process"
    );
    assert!(
        TcpStream::connect(&fixture.callback).is_err(),
        "pasting must close the losing listener"
    );
}

#[test]
fn browser_callback_wins_without_waiting_for_stdin_to_close() {
    let fixture = Fixture::new();
    let server = fixture.exchange(true);
    let mut login =
        Login::start(fixture.command("xai", &["--approve-on", "this", "--browser", "show"]));
    let url = login.authorize_url();
    let mut browser = TcpStream::connect(&fixture.callback).unwrap();
    write!(
        browser,
        "GET /callback?code=from-browser&state={} HTTP/1.1\r\nHost: localhost\r\n\r\n",
        param(&url, "state")
    )
    .unwrap();
    browser
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut page = String::new();
    browser.read_to_string(&mut page).unwrap();
    assert!(page.contains("Authentication successful"));
    // Keep the stdin writer alive until the child exits. EOF cannot rescue the race.
    assert!(login.stdin.is_some());
    login.finish(true);
    assert_eq!(server.join().unwrap()["code"], "from-browser");
}

#[test]
fn another_device_binds_nothing_and_bad_pastes_let_the_user_retry() {
    let fixture = Fixture::new();
    let server = fixture.exchange(true);
    let mut login =
        Login::start(fixture.command("xai", &["--approve-on", "other", "--browser", "show"]));
    let url = login.authorize_url();
    let _available =
        TcpListener::bind(&fixture.callback).expect("another device must not bind a listener");
    login.paste("not a callback");
    login.until("Could not parse the login callback");
    login.paste("old-code#wrong-state");
    login.until("callback state does not match");
    login.paste(&format!("fresh-code#{}", param(&url, "state")));
    let output = login.finish(true);
    assert!(
        output.matches("paste it here, then Enter:").count() >= 3,
        "{output}"
    );
    assert!(!output.contains("at any time"));
    assert_eq!(server.join().unwrap()["code"], "fresh-code");
}

#[test]
fn non_tty_defaults_show_and_headless_defaults_to_another_device() {
    for headless in [false, true] {
        let fixture = Fixture::new();
        let server = fixture.exchange(true);
        let mut command = fixture.command("xai", &[]);
        if headless {
            command.env_remove("DISPLAY");
        }
        let helpers = fixture.helper_tools(&mut command, false);
        let mut login = Login::start(command);
        let url = login.authorize_url();
        assert_eq!(
            TcpListener::bind(&fixture.callback).is_ok(),
            cfg!(target_os = "linux") && headless
        );
        login.paste(&format!("code#{}", param(&url, "state")));
        let output = login.finish(true);
        assert!(
            !output.contains("Where will you approve") && !output.contains("or copy the link?")
        );
        assert!(!helpers.exists());
        server.join().unwrap();
    }
    let output = cli().arg("login").stdin(Stdio::null()).output().unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("needs --provider"));
}

#[test]
fn clipboard_gets_the_url_once_on_stdin_and_not_in_argv() {
    let fixture = Fixture::new();
    let server = fixture.exchange(true);
    let mut command = fixture.command("xai", &["--approve-on", "other", "--browser", "copy"]);
    let helpers = fixture.helper_tools(&mut command, false);
    let mut login = Login::start(command);
    let url = login.authorize_url();
    login.until("paste it here, then Enter:");
    assert_eq!(
        std::fs::read_to_string(fixture.root.join("clipboard")).unwrap(),
        url
    );
    let expected = if cfg!(target_os = "macos") {
        "pbcopy \n"
    } else {
        "xclip -selection clipboard\n"
    };
    assert_eq!(std::fs::read_to_string(helpers).unwrap(), expected);
    login.paste(&format!("code#{}", param(&url, "state")));
    login.finish(true);
    server.join().unwrap();
}

#[test]
fn explicit_open_runs_the_opener_once() {
    let fixture = Fixture::new();
    let server = fixture.exchange(true);
    let mut command = fixture.command("xai", &["--approve-on", "this", "--browser", "open"]);
    let helpers = fixture.helper_tools(&mut command, false);
    let mut login = Login::start(command);
    let url = login.authorize_url();
    login.paste(&format!("code#{}", param(&url, "state")));
    login.finish(true);
    server.join().unwrap();
    let tool = if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    };
    assert_eq!(
        std::fs::read_to_string(helpers).unwrap(),
        format!("{tool} {url}\n")
    );
    assert!(!fixture.root.join("clipboard").exists());
}

#[test]
fn clipboard_failure_shows_the_url_and_still_accepts_a_callback() {
    let fixture = Fixture::new();
    let server = fixture.exchange(true);
    let mut command = fixture.command("xai", &["--approve-on", "other", "--browser", "copy"]);
    fixture.helper_tools(&mut command, true);
    let mut login = Login::start(command);
    let url = login.authorize_url();
    login.until("Could not copy the link to the clipboard");
    login.paste(&format!("code#{}", param(&url, "state")));
    let output = login.finish(true);
    assert!(output.matches(&url).count() >= 2, "{output}");
    server.join().unwrap();
}

#[test]
fn google_reuses_concurrent_paste_and_other_device_listener_policy() {
    for location in ["this", "other"] {
        let fixture = Fixture::new();
        // An exchange refusal proves the real Google driver reached the fake token
        // server without proceeding to its unrelated userinfo/project APIs.
        let server = fixture.exchange(false);
        let mut login = Login::start(
            fixture.command("google", &["--approve-on", location, "--browser", "show"]),
        );
        let url = login.authorize_url();
        let _available = if location == "other" {
            Some(TcpListener::bind(&fixture.callback).expect("Google other must not bind"))
        } else {
            assert!(TcpListener::bind(&fixture.callback).is_err());
            None
        };
        login.paste("broken");
        login.until("Could not parse the login callback");
        login.paste(&format!("google-code#{}", param(&url, "state")));
        let output = login.finish(false);
        assert!(
            output.contains("Google token endpoint rejected the authorization code"),
            "{output}"
        );
        let exchange = server.join().unwrap();
        assert_eq!(exchange["code"], "google-code");
        assert_eq!(
            exchange["redirect_uri"],
            format!("http://{}/callback", fixture.callback)
        );
    }
}

#[test]
fn proprietary_browser_flow_uses_the_action_choice_instead_of_auto_opening() {
    let fixture = Fixture::new();
    let mut command = fixture.command("digitalocean", &["--no-listener", "--browser", "show"]);
    let helpers = fixture.helper_tools(&mut command, false);
    command.stdin(Stdio::piped());
    let mut login = Login::start(command);
    login.until("paste it here:");
    login.paste("invalid-fragment");
    login.finish(false);
    assert!(!helpers.exists());
}

/// Run explicitly to capture both real dialoguer menus against a local fake provider.
#[test]
#[ignore = "manual terminal transcript; run with --ignored --nocapture"]
fn manual_this_computer_and_another_device_transcripts() {
    use std::fs::File;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::process::CommandExt;

    for other in [false, true] {
        let fixture = Fixture::new();
        let server = fixture.exchange(true);
        let mut command = fixture.command("xai", &[]);
        let helpers = fixture.helper_tools(&mut command, false);
        let (mut master_fd, mut slave_fd) = (-1, -1);
        // openpty initializes both owned descriptors; no Rust references cross exec.
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master_fd,
                    &mut slave_fd,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            },
            0
        );
        let mut master = unsafe { File::from_raw_fd(master_fd) };
        let slave = unsafe { File::from_raw_fd(slave_fd) };
        unsafe {
            assert_ne!(
                libc::fcntl(master.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC),
                -1
            );
            assert_ne!(
                libc::fcntl(slave.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC),
                -1
            );
            assert_ne!(
                libc::fcntl(master.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK),
                -1
            );
        }
        command
            .env("TERM", "xterm-256color")
            .stdin(Stdio::from(slave.try_clone().unwrap()))
            .stdout(Stdio::from(slave.try_clone().unwrap()))
            .stderr(Stdio::from(slave));
        // Give dialoguer the same controlling terminal and session as a shell login.
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() == -1
                    || libc::ioctl(libc::STDIN_FILENO, libc::TIOCSCTTY as _, 0) == -1
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command.spawn().unwrap();
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut output = String::new();
        let mut stage = 0;
        let mut inputs = Vec::new();
        loop {
            let mut buffer = [0; 8192];
            match master.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => output.push_str(&String::from_utf8_lossy(&buffer[..n])),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) if error.raw_os_error() == Some(libc::EIO) => break,
                Err(error) => panic!("reading terminal: {error}"),
            }
            let next = match stage {
                0 if output.contains("Where will you approve this login?") => Some(if other {
                    "\x1b[B\r".to_string()
                } else {
                    "\r".to_string()
                }),
                1 if output.contains(if other {
                    "Copy the link, or just show it?"
                } else {
                    "Open it in your browser, or copy the link?"
                }) =>
                {
                    Some(if other {
                        "\x1b[B\r".to_string()
                    } else {
                        "\x1b[B\x1b[B\r".to_string()
                    })
                }
                2 if output.contains("paste it here, then Enter:") => {
                    let url = output
                        .lines()
                        .find(|line| line.starts_with("  http://"))
                        .unwrap()
                        .trim();
                    assert_eq!(TcpListener::bind(&fixture.callback).is_ok(), other);
                    Some(format!("manual-code#{}\r", param(url, "state")))
                }
                _ => None,
            };
            if let Some(input) = next {
                master.write_all(input.as_bytes()).unwrap();
                inputs.push(input);
                stage += 1;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                panic!("terminal login timed out: {output}");
            }
            thread::sleep(Duration::from_millis(10));
        }
        let status = child.wait().unwrap();
        assert!(status.success(), "{output}");
        assert_eq!(stage, 3);
        assert!(
            output.contains("logged in and stored oauth:xai"),
            "{output}"
        );
        assert!(!helpers.exists());
        assert_eq!(server.join().unwrap()["code"], "manual-code");
        println!(
            "TRANSCRIPT_JSON {}",
            json!({
                "approval": if other { "another device" } else { "this computer" },
                "command": format!("ck auth login --provider xai --data-dir {} --key-path {}", fixture.root.join("vault").display(), fixture.root.join("master.key").display()),
                "terminal_output": output,
                "input_bytes": inputs,
                "exit_code": status.code(),
            })
        );
    }
}

#[test]
fn a_bad_paste_does_not_cancel_a_browser_callback_in_progress() {
    let fixture = Fixture::new();
    let server = fixture.exchange(true);
    let mut login =
        Login::start(fixture.command("xai", &["--approve-on", "this", "--browser", "show"]));
    let url = login.authorize_url();
    let mut browser = TcpStream::connect(&fixture.callback).unwrap();
    write!(
        browser,
        "GET /callback?code=fragmented-browser&state={}",
        param(&url, "state")
    )
    .unwrap();
    // Leave a request unfinished while the terminal rejects a pasted line.
    thread::sleep(Duration::from_millis(100));
    login.paste("not a callback");
    login.until("Could not parse the login callback");
    browser
        .write_all(b" HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .unwrap();
    login.finish(true);
    assert_eq!(server.join().unwrap()["code"], "fragmented-browser");
}
