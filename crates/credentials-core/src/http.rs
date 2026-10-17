//! The production HTTP transport for refresh adapters: a thin reqwest-backed
//! implementation of [`HttpTransport`].
//!
//! Adapters are wire-agnostic and test against a recorded-fixture transport; this
//! is the real one the daemon wires in. rustls only (no native-tls), matching the
//! workspace's reqwest features.

use async_trait::async_trait;

use crate::refresh_adapters::{HttpResponse, HttpTransport, RefreshError};

/// A reqwest-backed [`HttpTransport`]. Holds one shared client (connection pooling).
pub struct ReqwestTransport {
    client: reqwest::Client,
}

impl ReqwestTransport {
    /// Build a transport with a default client and a sane request timeout.
    ///
    /// HTTP/1.1 is pinned rather than left to negotiation, and the reason is about
    /// how the alternative would arrive rather than about which protocol is better.
    ///
    /// This workspace enables reqwest's `http2` feature for an unrelated caller, and
    /// cargo unions features across the graph, so without this line the client offers
    /// h2 here too. When the pin was added, every provider token endpoint the probe
    /// then covered accepted h2 (re-measure with `cargo run -p credentials-core
    /// --example negotiated_protocol`, which probes each refresh adapter's endpoint),
    /// so the next release build would have moved every
    /// credential refresh in the vault onto a different transport as a side effect of
    /// a feature added for something else. Nobody would have decided that.
    ///
    /// The pin is not a claim that h2 is worse. It is very likely fine, and moving to
    /// it may well be an improvement. The point is that the currently deployed daemon
    /// refreshes over 1.1 and has done so for the vault's whole operating history, so
    /// that is the behaviour with evidence behind it — and a change to the
    /// credential-serving path should be a commit that says so, testable on its own,
    /// rather than an invisible consequence of a dependency edit.
    ///
    /// TO MOVE TO h2 DELIBERATELY: delete this call. The risk that argues for doing so
    /// eventually is the mirror of the one it guards: a provider that someday drops
    /// HTTP/1.1 would break refresh while this pin stands.
    pub fn new() -> Result<Self, RefreshError> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            // Token-exchange bodies contain secrets; redirects must be surfaced, never followed.
            .redirect(reqwest::redirect::Policy::none())
            .http1_only()
            .build()
            .map_err(|e| RefreshError::Transport(e.to_string()))?;
        Ok(ReqwestTransport { client })
    }
}

#[async_trait]
impl HttpTransport for ReqwestTransport {
    async fn post(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        content_type: &str,
        body: Vec<u8>,
    ) -> Result<HttpResponse, RefreshError> {
        let mut req = self
            .client
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, content_type)
            .body(body);
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| RefreshError::Transport(e.to_string()))?;
        let status = resp.status().as_u16();
        let body = resp
            .bytes()
            .await
            .map_err(|e| RefreshError::Transport(e.to_string()))?
            .to_vec();
        Ok(HttpResponse { status, body })
    }

    async fn get(&self, url: &str, headers: &[(&str, &str)]) -> Result<HttpResponse, RefreshError> {
        let mut req = self.client.get(url);
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| RefreshError::Transport(e.to_string()))?;
        let status = resp.status().as_u16();
        let body = resp
            .bytes()
            .await
            .map_err(|e| RefreshError::Transport(e.to_string()))?
            .to_vec();
        Ok(HttpResponse { status, body })
    }
}

#[cfg(test)]
mod tests {
    /// The HTTP/1.1 pin is present in the shipped transport.
    ///
    /// Asserted against this file's own source, which is unusual and is the only
    /// option available: `reqwest::ClientBuilder` offers the pin as a setter with no
    /// corresponding getter, and a built `Client` exposes nothing about its protocol
    /// policy. A constructed client cannot be interrogated, and the alternative -- a
    /// live request against a server that offers h2 -- would put a network dependency
    /// in the unit suite and fail for reasons unrelated to the pin.
    ///
    /// Without this, removing the call is a SILENT no-op: every test still passes,
    /// the behaviour changes only against servers that offer h2, and nothing reports
    /// it until someone reads the negotiated protocol on a live connection.
    ///
    /// The same silence is how this module gained the h2 capability to begin with. It
    /// was never edited: another crate in the workspace enabled reqwest's `http2`
    /// feature for its own use, cargo unions features across the graph, and this
    /// transport acquired the capability without any change to the file.
    #[test]
    fn the_transport_pins_http1() {
        let source = include_str!("http.rs");

        // The needle is built rather than written literally, so this assertion cannot
        // be satisfied by the needle's own appearance in a comment or message inside
        // the same file. A substring test that can match its own text proves nothing.
        let needle = format!(".{}{}()", "http1", "_only");
        assert!(
            source.contains(&needle),
            "the production transport must pin HTTP/1.1. The workspace enables \
             reqwest's h2 feature for an unrelated caller, and without the pin every \
             provider token refresh moves to a different transport with nothing \
             reporting it. If the pin was removed deliberately, remove this test in \
             the same commit so the decision appears in review."
        );

        // The disambiguator: prove the assertion is reading THIS module rather than
        // passing because some file was read successfully.
        assert!(
            source.contains("impl HttpTransport for ReqwestTransport"),
            "the included source must be this module; if this fails the include path \
             is wrong and the assertion above proves nothing"
        );
    }

    /// The HTTP-version probe example reaches every refresh adapter through the
    /// adapter's own URL constants, never through a typed URL.
    ///
    /// The probe is how anyone deciding about the HTTP/1.1 pin above learns what each
    /// provider would negotiate. Its list was once hand-typed, and it drifted: it
    /// probed `api.x.ai` while the xai adapter refreshes at `auth.x.ai`, probed
    /// GitHub's device-login URL for github-copilot, and missed six adapters. Nothing
    /// failed, because an example is only compiled, never checked against the tree.
    #[test]
    fn the_protocol_probe_covers_every_refresh_adapter_through_its_constants() {
        let example = include_str!("../examples/negotiated_protocol.rs");
        let code: String = example
            .lines()
            .map(|line| line.split("//").next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !code.contains("\"https:"),
            "the probe must take its URLs from the adapters' constants, not literals"
        );

        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/refresh_adapters");
        let mut adapters: Vec<String> = std::fs::read_dir(&dir)
            .expect("read refresh_adapters/")
            .filter_map(|entry| {
                let name = entry.ok()?.file_name().to_string_lossy().to_string();
                name.strip_suffix(".rs").map(str::to_string)
            })
            // `mod` and `fixture` are not adapters; `digitalocean` has no refresh
            // exchange (its tokens are re-login-only), so there is nothing to probe.
            .filter(|stem| !matches!(stem.as_str(), "mod" | "fixture" | "digitalocean"))
            .collect();
        adapters.sort();
        assert!(
            adapters.len() >= 12,
            "the adapter scan must find the adapter modules (found {adapters:?})"
        );
        let missing: Vec<&String> = adapters
            .iter()
            .filter(|stem| !code.contains(&format!("{stem}::")))
            .collect();
        assert!(
            missing.is_empty(),
            "examples/negotiated_protocol.rs does not probe these refresh adapters \
             through their URL constants: {missing:?}"
        );
    }
}

#[cfg(test)]
mod redirect_rules {
    use super::*;
    #[tokio::test]
    async fn token_post_surfaces_redirect_without_forwarding_body() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut buffer = [0; 4096];
            let _ = stream.read(&mut buffer).unwrap();
            write!(stream, "HTTP/1.1 307 Temporary Redirect\r\nLocation: http://{address}/target\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
            drop(stream);
            listener.set_nonblocking(true).unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_millis(500);
            while std::time::Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut forwarded, _)) => {
                        forwarded
                            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                            .unwrap();
                        let _ = forwarded.read(&mut buffer).unwrap();
                        forwarded.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
                        return true;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(5))
                    }
                    Err(e) => panic!("accept failed: {e}"),
                }
            }
            false
        });
        let response = ReqwestTransport::new()
            .unwrap()
            .post(
                &format!("http://{address}/token"),
                &[],
                "application/json",
                b"refresh-token-fixture".to_vec(),
            )
            .await
            .unwrap();
        let forwarded = server.join().unwrap();
        assert_eq!(response.status, 307);
        assert!(
            !forwarded,
            "a token body must never reach a redirect target"
        );
    }
}
