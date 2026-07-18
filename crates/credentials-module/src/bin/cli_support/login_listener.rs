//! A one-shot localhost callback listener for the interactive login flow.
//!
//! For a provider whose OAuth redirect is a loopback URL (OpenAI `localhost:1455`,
//! xAI `127.0.0.1:56121`), the CLI can bind that exact address and capture the
//! authorization-code redirect directly — so the operator just approves in the
//! browser and the flow completes, no copy-paste.
//!
//! Boundaries (the approved envelope):
//! - CLI-PROCESS-ONLY. The daemon never runs a listener; this lives in the CLI, the
//!   same process that owns the interactive half of login. The vault stays headless
//!   and zero-inbound.
//! - The redirect STRING sent to the provider is UNCHANGED — we bind the exact
//!   host:port the registered redirect already uses, so the provider's exact-match
//!   still holds. We do not invent a new redirect.
//! - One-shot: it accepts exactly one request, then closes. Bound to loopback only.
//! - Paste-back stays the fallback: if the bind fails (port busy, headless, a
//!   non-loopback redirect) or no request arrives before the timeout, the caller
//!   falls back to reading the pasted callback from stdin. So this is a convenience
//!   over the paste path, never a new requirement.
//! - State is validated by the SAME downstream code that validates a pasted
//!   callback (the exchange checks `state` before any network call); this listener
//!   only transports the callback, it does not authorize anything.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

/// How long to wait for the browser redirect before giving up and falling back to
/// paste. Generous: the operator may need to sign in and approve.
const LISTEN_TIMEOUT: Duration = Duration::from_secs(300);

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
    // Bind the numeric loopback even when the redirect host is "localhost", so we do
    // not depend on the resolver mapping localhost → 127.0.0.1.
    Some(format!("127.0.0.1:{port}"))
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
    let listener = TcpListener::bind(bind_addr).ok()?;
    listener.set_nonblocking(false).ok()?;
    Some(CallbackListener { listener })
}

/// A bound one-shot listener, handed back so the caller can open the browser and
/// THEN block for the redirect (bind-before-open removes the race).
pub struct CallbackListener {
    listener: TcpListener,
}

impl CallbackListener {
    /// Block for the single browser redirect, up to [`LISTEN_TIMEOUT`]. Returns the
    /// captured `code=..&state=..` querystring, or `None` to fall back to paste.
    pub fn wait(self) -> Option<String> {
        self.listener
            .set_nonblocking(false)
            .ok()
            .and_then(|()| accept_with_timeout(&self.listener, LISTEN_TIMEOUT))
            .and_then(|mut stream| {
                let query = read_callback_query(&mut stream);
                // Always answer the browser so the operator sees a clean page, even
                // if we could not parse a query (then we fall back to paste).
                write_browser_response(&mut stream, query.is_some());
                query
            })
    }
}

/// Accept one connection, honoring a wall-clock timeout by polling the listener's
/// accept in short nonblocking windows (std has no accept-with-deadline).
fn accept_with_timeout(listener: &TcpListener, timeout: Duration) -> Option<TcpStream> {
    let deadline = std::time::Instant::now() + timeout;
    listener.set_nonblocking(true).ok()?;
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false).ok()?;
                return Some(stream);
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if std::time::Instant::now() >= deadline {
                    return None;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => return None,
        }
    }
}

/// Read the HTTP request line and extract the `code=..&state=..` query. We only need
/// the request line (`GET /path?query HTTP/1.1`), so we read a bounded prefix.
fn read_callback_query(stream: &mut TcpStream) -> Option<String> {
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    let mut buf = [0u8; 4096];
    let n = stream.read(&mut buf).ok()?;
    let request = std::str::from_utf8(&buf[..n]).ok()?;
    // First line: METHOD SP request-target SP HTTP/x.y
    let request_line = request.lines().next()?;
    let target = request_line.split_whitespace().nth(1)?;
    // Extract the query after the first '?'. The target is a path like
    // `/auth/callback?code=..&state=..`.
    let (_, query) = target.split_once('?')?;
    if query.contains("code=") && query.contains("state=") {
        Some(query.to_string())
    } else {
        None
    }
}

/// Write a small self-contained success/failure page so the browser shows a clean
/// result instead of a raw connection or a hanging request. Styled (dark, centered
/// card) because this page is the visible end of every login; no external loads.
fn write_browser_response(stream: &mut TcpStream, ok: bool) {
    let (title, detail, mark) = if ok {
        (
            "Authentication successful",
            "You are logged in. You can close this tab and return to the terminal.",
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
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_redirects_bind_numeric_localhost() {
        assert_eq!(
            loopback_bind_addr("http://localhost:1455/auth/callback").as_deref(),
            Some("127.0.0.1:1455")
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

        let query = listener.wait().expect("captured query");
        assert_eq!(query, "code=abc123&state=xyz789");
        let resp = client.join().unwrap();
        assert!(resp.contains("200 OK"), "browser got a page: {resp}");
        assert!(resp.contains("Authentication successful"));
    }

    #[test]
    fn a_request_without_code_state_falls_back() {
        let listener = capture_callback("127.0.0.1:0").expect("bind ephemeral");
        let addr = listener.listener.local_addr().unwrap();
        let client = std::thread::spawn(move || {
            let mut s = TcpStream::connect(addr).expect("connect");
            let _ = s.write_all(b"GET /favicon.ico HTTP/1.1\r\nHost: localhost\r\n\r\n");
            let mut resp = String::new();
            let _ = s.read_to_string(&mut resp);
        });
        assert!(
            listener.wait().is_none(),
            "a non-callback request yields None so the caller falls back to paste"
        );
        client.join().unwrap();
    }
}
