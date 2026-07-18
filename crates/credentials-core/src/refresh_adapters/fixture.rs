//! A recorded-response HTTP transport for adapter conformance tests.
//!
//! Adapters are tested against RECORDED provider responses (the fidelity rule —
//! never invent a provider response string). [`FixtureTransport`] returns a queued
//! [`HttpResponse`] per call and records the requests it received so a test can
//! assert the exact URL, headers, content type, and body an adapter sent.

use std::sync::Mutex;

use async_trait::async_trait;

use super::{HttpResponse, HttpTransport, RefreshError};

/// A request an adapter made, captured for assertions.
#[derive(Debug, Clone)]
pub struct RecordedRequest {
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub content_type: String,
    pub body: Vec<u8>,
}

/// A transport that replays queued responses and records requests. A queued
/// `Err` models a transport failure; an empty queue panics (a test bug).
pub struct FixtureTransport {
    responses: Mutex<std::collections::VecDeque<Result<HttpResponse, RefreshError>>>,
    requests: Mutex<Vec<RecordedRequest>>,
}

impl FixtureTransport {
    /// Build a transport that returns `responses` in order.
    pub fn new(responses: Vec<Result<HttpResponse, RefreshError>>) -> Self {
        FixtureTransport {
            responses: Mutex::new(responses.into_iter().collect()),
            requests: Mutex::new(Vec::new()),
        }
    }

    /// A transport that returns one successful response.
    pub fn ok(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Self::new(vec![Ok(HttpResponse {
            status,
            body: body.into(),
        })])
    }

    /// The requests the adapter made, in order.
    pub fn requests(&self) -> Vec<RecordedRequest> {
        self.requests.lock().unwrap().clone()
    }
}

#[async_trait]
impl HttpTransport for FixtureTransport {
    async fn post(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        content_type: &str,
        body: Vec<u8>,
    ) -> Result<HttpResponse, RefreshError> {
        self.requests.lock().unwrap().push(RecordedRequest {
            url: url.to_string(),
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            content_type: content_type.to_string(),
            body,
        });
        self.responses
            .lock()
            .unwrap()
            .pop_front()
            .expect("FixtureTransport: no queued response for request")
    }

    async fn get(&self, url: &str, headers: &[(&str, &str)]) -> Result<HttpResponse, RefreshError> {
        self.requests.lock().unwrap().push(RecordedRequest {
            url: url.to_string(),
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            content_type: "".to_string(),
            body: Vec::new(),
        });
        self.responses
            .lock()
            .unwrap()
            .pop_front()
            .expect("FixtureTransport: no queued response for request")
    }
}
