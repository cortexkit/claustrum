//! The production HTTP transport for refresh adapters: a thin reqwest-backed
//! implementation of [`HttpTransport`].
//!
//! Adapters are wire-agnostic and test against a recorded-fixture transport; this
//! is the real one the daemon wires in. rustls only (no native-tls), matching the
//! workspace's reqwest features.

use async_trait::async_trait;

use crate::refresh_adapters::{HttpResponse, HttpTransport, RefreshError};

// Token/profile replies are small JSON objects; GitHub installation discovery is
// the larger, list-shaped reply. One MiB leaves headroom for token strings and
// installation metadata, not downloads, and also bounds error and chunked bodies.
const MAX_RESPONSE_BODY_BYTES: usize = 1024 * 1024;

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
        read_response(resp).await
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
        read_response(resp).await
    }
}

async fn read_response(mut response: reqwest::Response) -> Result<HttpResponse, RefreshError> {
    let status = response.status().as_u16();
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| RefreshError::Transport(e.to_string()))?
    {
        if chunk.len() > MAX_RESPONSE_BODY_BYTES - body.len() {
            return Err(RefreshError::Transport(
                "provider response body exceeds one MiB".into(),
            ));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(HttpResponse { status, body })
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

#[cfg(test)]
mod response_limits {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn response_body_accepts_one_mib_and_refuses_one_byte_more() {
        assert_eq!(MAX_RESPONSE_BODY_BYTES, 1_048_576);
        let transport = ReqwestTransport::new().unwrap();
        for post in [false, true] {
            for chunked in [false, true] {
                for status in [200, 503] {
                    for size in [1_048_576, 1_048_577] {
                        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                        let address = listener.local_addr().unwrap();
                        let server = tokio::spawn(async move {
                            let (mut socket, _) = listener.accept().await.unwrap();
                            let mut request = Vec::new();
                            let mut byte = [0];
                            while !request.ends_with(b"\r\n\r\n") {
                                socket.read_exact(&mut byte).await.unwrap();
                                request.push(byte[0]);
                            }
                            let framing = if chunked {
                                "Transfer-Encoding: chunked".to_owned()
                            } else {
                                format!("Content-Length: {size}")
                            };
                            let head = format!(
                                "HTTP/1.1 {status} Test\r\n{framing}\r\nConnection: close\r\n\r\n"
                            );
                            socket.write_all(head.as_bytes()).await.unwrap();
                            // Separate chunks make the cumulative limit matter, not
                            // just the length of any one chunk or a declared length.
                            let bytes = [b'x'; 8192];
                            let mut remaining = size;
                            while remaining > 0 {
                                let len = remaining.min(bytes.len());
                                if chunked
                                    && socket
                                        .write_all(format!("{len:x}\r\n").as_bytes())
                                        .await
                                        .is_err()
                                {
                                    return;
                                }
                                if socket.write_all(&bytes[..len]).await.is_err() {
                                    return;
                                }
                                if chunked && socket.write_all(b"\r\n").await.is_err() {
                                    return;
                                }
                                remaining -= len;
                            }
                            if chunked {
                                let _ = socket.write_all(b"0\r\n\r\n").await;
                            }
                        });
                        let url = format!("http://{address}/provider");
                        let response = if post {
                            transport
                                .post(&url, &[], "application/json", Vec::new())
                                .await
                        } else {
                            transport.get(&url, &[]).await
                        };
                        server.await.unwrap();
                        if size == 1_048_576 {
                            let response = response.unwrap();
                            assert_eq!(response.status, status);
                            assert_eq!(response.body, vec![b'x'; size]);
                        } else {
                            assert!(matches!(response, Err(RefreshError::Transport(ref why)) if why == "provider response body exceeds one MiB"), "oversized reply must be retryable for post={post}, chunked={chunked}, status={status}");
                        }
                    }
                }
            }
        }
    }
}
