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
    /// h2 here too. Measured against the five provider token endpoints this transport
    /// posts to: ALL FIVE accept h2, so the next release build would move every
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
}
