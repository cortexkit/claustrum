/// A transport that cannot reach the network, preventing test fixtures from silently
/// acquiring live provider behavior if an adapter is added later.
pub(crate) struct NoHttp;

#[async_trait::async_trait]
impl credentials_core::refresh_adapters::HttpTransport for NoHttp {
    async fn post(
        &self,
        _url: &str,
        _headers: &[(&str, &str)],
        _content_type: &str,
        _body: Vec<u8>,
    ) -> Result<
        credentials_core::refresh_adapters::HttpResponse,
        credentials_core::refresh_adapters::RefreshError,
    > {
        Err(credentials_core::refresh_adapters::RefreshError::Transport(
            "credentials-module tests do not make network calls".into(),
        ))
    }

    async fn get(
        &self,
        _url: &str,
        _headers: &[(&str, &str)],
    ) -> Result<
        credentials_core::refresh_adapters::HttpResponse,
        credentials_core::refresh_adapters::RefreshError,
    > {
        Err(credentials_core::refresh_adapters::RefreshError::Transport(
            "credentials-module tests do not make network calls".into(),
        ))
    }
}
