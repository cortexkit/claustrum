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
    pub fn new() -> Result<Self, RefreshError> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
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
}
