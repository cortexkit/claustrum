//! A one-shot localhost callback listener for the interactive login flow.
//!
//! For a provider whose OAuth redirect is a loopback URL (OpenAI `localhost:1455`,
//! xAI `127.0.0.1:56121`), the CLI can bind that exact address and capture the
//! authorization-code redirect directly — so the operator just approves in the
//! browser and the flow completes, no copy-paste.
//!
//! Boundaries:
//! - CLI-PROCESS-ONLY. The daemon never runs a listener; this lives in the CLI, the
//!   same process that owns the interactive half of login. The vault stays headless
//!   and zero-inbound.
//! - The redirect STRING sent to the provider is UNCHANGED — we bind the exact
//!   host:port the registered redirect already uses, so the provider's exact-match
//!   still holds. We do not invent a new redirect.
//! - It closes after accepting one valid callback or reaching its deadline.
//! - Paste-back remains available while listening. A browser on another device
//!   cannot reach this socket, so the listener is a convenience, not a requirement.
//! - State is checked before acknowledging receipt. The terminal reports the
//!   outcome of the exchange and the deposit.

use credentials_core::oauth_login::{parse_callback, states_equal, Callback};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

/// How long to keep the browser callback socket open. Pasting need not wait for it.
pub const LISTEN_TIMEOUT: Duration = Duration::from_secs(300);

/// The loopback bind address for a provider's redirect URI, if the redirect is a
/// loopback URL this CLI can listen on. `None` for a remote redirect (e.g.
/// Anthropic's platform.claude.com callback), which stays paste-only.
///
/// Parsed WITHOUT a URL crate (the module binary has no `url` dep): pull the scheme
/// authority (`host:port`) out of `scheme://<authority>/...` and require a
/// loopback host with an explicit port.
pub fn loopback_bind_addr(redirect_uri: &str) -> Option<String> {
    let after_scheme = redirect_uri.split_once("://")?.1;
    // The authority is everything up to the first '/', '?', or '#'.
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .filter(|a| !a.is_empty())?;
    // Reject userinfo (`user@host`) — a real redirect never carries it, and it would
    // let a crafted string smuggle a non-loopback host past the check.
    if authority.contains('@') {
        return None;
    }
    let (host, port_str) = authority.rsplit_once(':')?;
    let port: u16 = port_str.parse().ok()?;
    let is_loopback = host == "localhost"
        || host
            .trim_matches(['[', ']'])
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false);
    if !is_loopback {
        return None;
    }
    // A literal loopback address (`[::1]`, `127.0.0.2`) is bound exactly as written, since
    // that is the address the browser will connect to. The name `localhost` still binds
    // numeric 127.0.0.1: resolving it here could pick `::1` on its own, and a browser
    // that then tries 127.0.0.1 would never reach the listener.
    if host == "localhost" {
        return Some(format!("127.0.0.1:{port}"));
    }
    Some(format!("{host}:{port}"))
}

/// Try to capture the OAuth callback by listening on the redirect's loopback
/// address. Returns the captured callback string (a `code=..&state=..` querystring,
/// which `parse_callback` accepts) on success, or `None` to signal the caller to
/// fall back to paste (bind failed, timed out, or the request carried no query).
///
/// `bind_addr` comes from [`loopback_bind_addr`]. This binds BEFORE the browser is
/// opened (the caller sequences it that way), so the redirect can never race a
/// not-yet-listening socket.
pub fn capture_callback(bind_addr: &str) -> Option<CallbackListener> {
    capture_with_mode(bind_addr, CaptureMode::Code)
}

/// Bind a one-shot listener that serves a fragment bootstrap page and accepts the
/// token POSTed back by that page. This mode is explicit so normal code callbacks
/// never interpret a browser fragment as a credential.
pub fn capture_fragment_callback(bind_addr: &str) -> Option<CallbackListener> {
    capture_with_mode(bind_addr, CaptureMode::Fragment)
}

pub fn port_in_use_message(redirect_uri: &str) -> String {
    format!(
        "callback port is in use or unavailable ({redirect_uri}); retry after freeing the port or choose another device (--approve-on other, paste-only with no local listener)"
    )
}

/// Bind an ephemeral numeric loopback port for providers that register a random
/// callback port. The caller reads [`CallbackListener::local_addr`] before opening
/// the browser.
pub fn capture_dynamic_callback() -> Option<CallbackListener> {
    capture_with_mode("127.0.0.1:0", CaptureMode::Code)
}

fn capture_with_mode(bind_addr: &str, mode: CaptureMode) -> Option<CallbackListener> {
    let listener = TcpListener::bind(bind_addr).ok()?;
    listener.set_nonblocking(false).ok()?;
    Some(CallbackListener { listener, mode })
}

/// A bound one-shot listener, handed back so the caller can open the browser and
/// THEN block for the redirect (bind-before-open removes the race).
#[derive(Clone, Copy)]
enum CaptureMode {
    Code,
    Fragment,
}

pub struct CallbackListener {
    listener: TcpListener,
    mode: CaptureMode,
}

impl CallbackListener {
    /// Convert the code listener for cancellation-safe concurrent callback input.
    /// Dropping the async listener closes the socket without waiting for a browser.
    pub fn into_async(self) -> std::io::Result<tokio::net::TcpListener> {
        self.listener.set_nonblocking(true)?;
        tokio::net::TcpListener::from_std(self.listener)
    }

    /// Return the actual bound address, including an ephemeral port when requested.
    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }

    /// Block for the browser callback, up to [`LISTEN_TIMEOUT`]. Code mode returns a
    /// `code=..&state=..` querystring; fragment mode returns the form posted by the
    /// bootstrap page.
    pub fn wait(self, redirect_uri: &str, expected_state: &str) -> Option<String> {
        let deadline = Instant::now() + LISTEN_TIMEOUT;
        let path = callback_path(redirect_uri);
        match self.mode {
            CaptureMode::Code => {
                while let Some(mut stream) = accept_until(&self.listener, deadline) {
                    let Some((method, target, _)) = read_http_request(&mut stream, deadline) else {
                        continue;
                    };
                    let query = callback_query(&method, &target, path, expected_state)
                        .and_then(Result::ok)
                        .map(|(query, _)| query.to_owned());
                    write_browser_response(&mut stream, query.is_some());
                    if query.is_some() {
                        return query;
                    }
                }
                None
            }
            CaptureMode::Fragment => {
                wait_for_fragment(&self.listener, deadline, path, expected_state)
            }
        }
    }
}

/// Receive and validate one callback without blocking pasted input.
pub async fn receive_code(
    listener: &tokio::net::TcpListener,
    path: &str,
    expected_state: &str,
) -> Result<Option<Callback>, &'static str> {
    let Ok((mut stream, _)) = listener.accept().await else {
        return Ok(None);
    };
    let query = read_request_target(&mut stream)
        .await
        .and_then(|(method, target)| {
            callback_query(&method, &target, path, expected_state)
                .map(|result| result.map(|(_, callback)| callback))
        })
        .transpose();
    write_response_async(
        &mut stream,
        &browser_response(matches!(&query, Ok(Some(_)))),
    )
    .await;
    query
}

async fn read_request_target(stream: &mut tokio::net::TcpStream) -> Option<(String, String)> {
    use tokio::io::AsyncReadExt;

    tokio::time::timeout(Duration::from_secs(5), async {
        let mut request = Vec::new();
        let mut chunk = [0; 1024];
        loop {
            let n = stream.read(&mut chunk).await.ok()?;
            if n == 0 {
                return None;
            }
            request.extend_from_slice(&chunk[..n]);
            if request.len() > 16 * 1024 {
                return None;
            }
            if request.windows(4).any(|w| w == b"\r\n\r\n") {
                let text = std::str::from_utf8(&request).ok()?;
                let mut parts = text.lines().next()?.split_whitespace();
                return Some((parts.next()?.into(), parts.next()?.into()));
            }
        }
    })
    .await
    .ok()
    .flatten()
}

async fn write_response_async(stream: &mut tokio::net::TcpStream, response: &str) {
    use tokio::io::AsyncWriteExt;
    let _ = tokio::time::timeout(
        Duration::from_secs(1),
        stream.write_all(response.as_bytes()),
    )
    .await;
}

const MANIFEST_CALLBACK_PATH: &str = "/auth/github-app/callback";

/// A loopback server for the manifest form and its one GitHub callback.
pub(super) struct ManifestListener(CallbackListener);

impl ManifestListener {
    pub(super) fn bind() -> Option<Self> {
        capture_dynamic_callback().map(Self)
    }

    pub(super) fn start_url(&self) -> std::io::Result<String> {
        Ok(format!("http://{}/start", self.0.local_addr()?))
    }

    pub(super) fn redirect_url(&self) -> std::io::Result<String> {
        Ok(format!(
            "http://{}{MANIFEST_CALLBACK_PATH}",
            self.0.local_addr()?
        ))
    }

    pub(super) async fn wait(
        self,
        action: &str,
        manifest: &serde_json::Value,
        expected_state: &str,
        mut pasted: tokio::sync::mpsc::Receiver<std::io::Result<String>>,
    ) -> Result<String, &'static str> {
        let listener = self
            .0
            .into_async()
            .map_err(|_| "Could not start the loopback listener.")?;
        let page = manifest_page(action, manifest);
        let receive = async {
            loop {
                let (mut stream, _) = listener
                    .accept()
                    .await
                    .map_err(|_| "Could not accept the loopback callback.")?;
                let target = read_request_target(&mut stream).await;
                let target = target
                    .as_ref()
                    .filter(|(method, _)| method == "GET")
                    .map(|(_, target)| target.as_str());
                let (path, query) = target
                    .unwrap_or_default()
                    .split_once('?')
                    .unwrap_or((target.unwrap_or_default(), ""));
                match path {
                    "/start" => write_response_async(&mut stream, &page).await,
                    MANIFEST_CALLBACK_PATH => {
                        let result = manifest_callback_code(query, expected_state);
                        let (status, body) = if result.is_ok() {
                            ("200 OK", "Callback received. Return to the terminal.")
                        } else {
                            (
                                "400 Bad Request",
                                "Callback refused. Return to the terminal.",
                            )
                        };
                        write_response_async(&mut stream, &manifest_http_response(status, body))
                            .await;
                        return result;
                    }
                    _ => {
                        write_response_async(
                            &mut stream,
                            &manifest_http_response("404 Not Found", "Not found"),
                        )
                        .await
                    }
                }
            }
        };
        let browser = tokio::time::timeout(LISTEN_TIMEOUT, receive);
        tokio::pin!(browser);
        tokio::select! {
            result = &mut browser => result.map_err(|_| "Timed out waiting for the GitHub App callback.")?,
            line = pasted.recv() => match line {
                Some(Ok(line)) => manifest_callback_code(&line, expected_state),
                Some(Err(_)) => Err("Could not read the pasted GitHub App callback."),
                None => browser.await.map_err(|_| "Timed out waiting for the GitHub App callback.")?,
            },
        }
    }
}

fn manifest_callback_code(input: &str, expected_state: &str) -> Result<String, &'static str> {
    let callback = credentials_core::oauth_login::parse_callback(input)
        .ok_or("The GitHub App callback did not contain a code and state.")?;
    if callback.state != expected_state {
        return Err("The GitHub App callback state did not match. No code was exchanged.");
    }
    Ok(callback.code)
}

fn manifest_page(action: &str, manifest: &serde_json::Value) -> String {
    fn escape(text: &str) -> String {
        text.replace('&', "&amp;")
            .replace('"', "&quot;")
            .replace('\'', "&#39;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    }
    let body = format!(
        "<!doctype html><meta charset=utf-8><title>Create a GitHub App</title>\
         <form method=\"post\" action=\"{}\"><input type=\"hidden\" name=\"manifest\" value=\"{}\">\
         <button type=\"submit\">Continue to GitHub</button></form>\
         <script>document.forms[0].submit();</script>",
        escape(action),
        escape(&manifest.to_string()),
    );
    manifest_http_response("200 OK", &body)
}

fn manifest_http_response(status: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n\
        Connection: close\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\n\
        X-Frame-Options: DENY\r\n\r\n{body}",
        body.len()
    )
}

/// Fragment mode needs two browser connections: the first GET receives a page that
/// can read `location.hash`, and the second POST carries the fragment fields.
fn wait_for_fragment(
    listener: &TcpListener,
    deadline: Instant,
    path: &str,
    expected_state: &str,
) -> Option<String> {
    while let Some(mut stream) = accept_until(listener, deadline) {
        let Some((method, target, body)) = read_http_request(&mut stream, deadline) else {
            continue;
        };
        if method == "GET" && target.split(['?', '#']).next() == Some(path) {
            write_fragment_bootstrap(&mut stream);
            continue;
        }
        if method == "POST" && target == "/auth/token" {
            if let Ok(form) = String::from_utf8(body) {
                if credentials_core::refresh_adapters::digitalocean::parse_fragment_capture(
                    &form,
                    expected_state,
                    0,
                )
                .is_ok()
                {
                    write_token_response(&mut stream, true);
                    return Some(form);
                }
            }
        }
        write_token_response(&mut stream, false);
    }
    None
}

/// Serve only local JavaScript: the browser owns the fragment and posts it back to
/// the same loopback listener, so the access token never appears in a GET request.
fn write_fragment_bootstrap(stream: &mut TcpStream) {
    let body = "<!doctype html><meta charset=\"utf-8\"><title>CortexKit · login</title><script>\
const fields=new URLSearchParams(location.hash.slice(1));\
fetch('/auth/token',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fields.toString()})\
 .then(r=>{if(!r.ok)throw Error();document.body.textContent='Callback received. Return to the terminal.';})\
.catch(()=>document.body.textContent='Return to the terminal and paste the URL from the address bar.');</script>\
<p>Completing authentication…</p>";
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

fn write_token_response(stream: &mut TcpStream, ok: bool) {
    let (status, body) = if ok {
        ("200 OK", "Callback received. Return to the terminal.")
    } else {
        ("400 Bad Request", "bad request")
    };
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

/// Read a bounded HTTP request, including a form body when Content-Length is present.
fn read_http_request(
    stream: &mut TcpStream,
    deadline: Instant,
) -> Option<(String, String, Vec<u8>)> {
    let read = |stream: &mut TcpStream, chunk: &mut [u8]| {
        let remaining = deadline.checked_duration_since(Instant::now())?;
        stream
            .set_read_timeout(Some(remaining.min(Duration::from_secs(5))))
            .ok()?;
        stream.read(chunk).ok()
    };
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        let n = read(stream, &mut chunk)?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break end + 4;
        }
        if buf.len() > 16 * 1024 {
            return None;
        }
    };
    let header_text = std::str::from_utf8(&buf[..header_end]).ok()?;
    let request_line = header_text.lines().next()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();
    let content_length = header_text
        .lines()
        .find_map(|line| {
            line.strip_prefix("Content-Length:")
                .or_else(|| line.strip_prefix("content-length:"))
        })
        .and_then(|n| n.trim().parse::<usize>().ok())
        .unwrap_or(0);
    if content_length > 16 * 1024 {
        return None;
    }
    while buf.len() - header_end < content_length {
        let n = read(stream, &mut chunk)?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    Some((
        method,
        target,
        buf[header_end..header_end + content_length].to_vec(),
    ))
}

/// Accept one connection, honoring a wall-clock timeout by polling the listener's
/// accept in short nonblocking windows (std has no accept-with-deadline).
fn accept_until(listener: &TcpListener, deadline: Instant) -> Option<TcpStream> {
    listener.set_nonblocking(true).ok()?;
    while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false).ok()?;
                stream
                    .set_write_timeout(Some(remaining.min(Duration::from_secs(1))))
                    .ok()?;
                return Some(stream);
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(remaining.min(Duration::from_millis(50)));
            }
            Err(_) => return None,
        }
    }
    None
}

pub fn callback_path(redirect_uri: &str) -> &str {
    let authority_and_path = redirect_uri
        .split_once("://")
        .map_or(redirect_uri, |(_, tail)| tail);
    authority_and_path
        .find('/')
        .map_or("/", |start| &authority_and_path[start..])
        .split(['?', '#'])
        .next()
        .unwrap_or("/")
}

fn callback_query<'a>(
    method: &str,
    target: &'a str,
    path: &str,
    expected_state: &str,
) -> Option<Result<(&'a str, Callback), &'static str>> {
    let (request_path, query) = target.split_once('?').unwrap_or((target, ""));
    (method == "GET" && request_path == path)
        .then(|| validated_callback(query, expected_state).map(|callback| (query, callback)))
}

pub fn validated_callback(raw: &str, expected_state: &str) -> Result<Callback, &'static str> {
    match parse_callback(raw) {
        Some(callback) if !callback.code.is_empty() && states_equal(&callback.state, expected_state) => Ok(callback),
        Some(callback) if !states_equal(&callback.state, expected_state) => Err("The callback state does not match this login. Paste the callback from the URL above."),
        _ => Err("Could not parse the login callback. Paste the complete callback URL or code and state."),
    }
}

/// Write a small self-contained success/failure page so the browser shows a clean
/// result instead of a raw connection or a hanging request. Styled (dark, centered
/// card) because this page is the visible end of every login; no external loads.
fn write_browser_response(stream: &mut TcpStream, ok: bool) {
    let _ = stream.write_all(browser_response(ok).as_bytes());
    let _ = stream.flush();
}

fn browser_response(ok: bool) -> String {
    let status = if ok { "200 OK" } else { "400 Bad Request" };
    let (title, detail, mark) = if ok {
        (
            "Callback received",
            "Return to the terminal to see whether the login completed.",
            "\u{2713}",
        )
    } else {
        (
            "Could not read the login response",
            "Return to the terminal and paste the URL from the address bar instead.",
            "!",
        )
    };
    let body = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>CortexKit \u{b7} login</title>\
         <style>body{{margin:0;display:flex;align-items:center;justify-content:center;\
         min-height:100vh;background:#101014;color:#e8e8ea;font-family:-apple-system,system-ui,sans-serif}}\
         .card{{text-align:center;padding:48px 56px;border:1px solid #2a2a31;border-radius:12px;background:#17171c}}\
         .mark{{width:64px;height:64px;line-height:64px;margin:0 auto 24px;border-radius:50%;\
         background:#1e2b1e;color:#7fbf7f;font-size:32px}}h1{{font-size:22px;font-weight:600;margin:0 0 12px}}\
         p{{margin:0;color:#9a9aa2;font-size:15px}}</style></head><body>\
         <div class=\"card\"><div class=\"mark\">{mark}</div><h1>{title}</h1><p>{detail}</p></div>\
         </body></html>"
    );
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n{}",
        body.len(),
        body
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_redirects_bind_the_redirect_host() {
        assert_eq!(
            loopback_bind_addr("http://localhost:1455/auth/callback").as_deref(),
            Some("127.0.0.1:1455"),
            "localhost must bind the numeric address, not whatever the resolver picks"
        );
        assert_eq!(
            loopback_bind_addr("http://127.0.0.1:56121/callback").as_deref(),
            Some("127.0.0.1:56121")
        );
    }

    #[test]
    fn remote_redirect_is_not_bindable() {
        // Anthropic's real callback is remote — must stay paste-only.
        assert_eq!(
            loopback_bind_addr("https://platform.claude.com/oauth/code/callback"),
            None
        );
        // A public host is never bound even if it parses.
        assert_eq!(loopback_bind_addr("http://93.184.216.34:80/cb"), None);
    }

    #[test]
    fn redirect_without_port_is_not_bindable() {
        assert_eq!(loopback_bind_addr("http://localhost/callback"), None);
    }

    /// End-to-end on loopback: bind, connect as a fake browser issuing the redirect
    /// GET, and confirm the listener returns the exact query and answers the browser.
    #[test]
    fn captures_a_loopback_redirect_query() {
        let listener = capture_callback("127.0.0.1:0").expect("bind ephemeral");
        let addr = listener.listener.local_addr().unwrap();

        let client = std::thread::spawn(move || {
            let mut s = TcpStream::connect(addr).expect("connect");
            s.write_all(
                b"GET /auth/callback?code=abc123&state=xyz789 HTTP/1.1\r\nHost: localhost\r\n\r\n",
            )
            .unwrap();
            let mut resp = String::new();
            let _ = s.read_to_string(&mut resp);
            resp
        });

        let query = listener
            .wait("http://localhost/auth/callback", "xyz789")
            .expect("captured query");
        assert_eq!(query, "code=abc123&state=xyz789");
        let resp = client.join().unwrap();
        assert!(resp.contains("200 OK"), "browser got a page: {resp}");
        assert!(resp.contains("Callback received"));
    }

    #[test]
    fn unrelated_connection_does_not_end_callback_capture() {
        let listener = capture_callback("127.0.0.1:0").expect("bind ephemeral");
        let addr = listener.listener.local_addr().unwrap();
        let mut unrelated = TcpStream::connect(addr).unwrap();
        unrelated
            .write_all(b"GET /favicon.ico HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .unwrap();
        let mut callback = TcpStream::connect(addr).unwrap();
        callback
            .write_all(
                b"GET /auth/callback?code=fixture&state=valid HTTP/1.1\r\nHost: localhost\r\n\r\n",
            )
            .unwrap();
        assert!(listener
            .wait("http://localhost/auth/callback", "valid")
            .is_some());
    }

    #[tokio::test]
    async fn stale_callback_does_not_claim_sign_in_and_valid_callback_only_acknowledges_receipt() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = capture_callback("127.0.0.1:0")
            .unwrap()
            .into_async()
            .unwrap();
        for (state, accepted) in [("stale", false), ("current", true)] {
            let mut browser = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
                .await
                .unwrap();
            browser.write_all(format!("GET /auth/callback?code=fixture&state={state} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes()).await.unwrap();
            let result = receive_code(&listener, "/auth/callback", "current").await;
            let mut page = String::new();
            browser.read_to_string(&mut page).await.unwrap();
            assert!(!page.contains("Authentication successful"));
            assert_eq!(matches!(result, Ok(Some(_))), accepted);
            assert_eq!(page.contains("Callback received"), accepted);
        }
    }

    #[test]
    fn fragment_mode_serves_javascript_and_accepts_token_post() {
        let listener = capture_fragment_callback("127.0.0.1:0").expect("bind ephemeral");
        let addr = listener.listener.local_addr().unwrap();
        let client = std::thread::spawn(move || {
            let mut get = TcpStream::connect(addr).expect("connect GET");
            get.write_all(
                b"GET /auth/callback#access_token=secret HTTP/1.1\r\nHost: localhost\r\n\r\n",
            )
            .unwrap();
            let mut page = String::new();
            get.read_to_string(&mut page).unwrap();
            assert!(page.contains("location.hash"));
            assert!(page.contains("/auth/token"));

            let mut favicon = TcpStream::connect(addr).unwrap();
            favicon
                .write_all(b"GET /favicon.ico HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .unwrap();
            let body = "access_token=secret&expires_in=3600&state=state";
            let mut post = TcpStream::connect(addr).expect("connect POST");
            write!(
                post,
                "POST /auth/token HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
            let mut response = String::new();
            post.read_to_string(&mut response).unwrap();
            assert!(response.contains("200 OK"));
        });
        let posted = listener
            .wait("http://localhost/auth/callback", "state")
            .expect("fragment POST captured");
        assert_eq!(posted, "access_token=secret&expires_in=3600&state=state");
        client.join().unwrap();
    }
}

#[cfg(test)]
mod streaming_tests {
    use super::*;

    #[test]
    fn loopback_binding_keeps_ipv6_and_alternate_ipv4_hosts() {
        assert_eq!(
            loopback_bind_addr("http://[::1]:1234/cb").as_deref(),
            Some("[::1]:1234")
        );
        assert_eq!(
            loopback_bind_addr("http://127.0.0.2:1234/cb").as_deref(),
            Some("127.0.0.2:1234")
        );
    }

    #[test]
    fn callback_capture_reads_fragmented_headers_to_completion() {
        let listener = capture_callback("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = std::thread::spawn(move || {
            let mut stream = TcpStream::connect(addr).unwrap();
            stream.write_all(b"GET /cb?code=").unwrap();
            std::thread::sleep(Duration::from_millis(100));
            // Split the request across TCP writes to require a complete-header read.
            let _ = stream.write_all(b"abc&state=xyz HTTP/1.1\r\nHost: localhost\r\n\r\n");
            let mut response = String::new();
            let _ = stream.read_to_string(&mut response);
        });
        let captured = listener.wait("http://localhost/cb", "xyz");
        client.join().unwrap();
        assert_eq!(captured.as_deref(), Some("code=abc&state=xyz"));
    }
}
