//! Operator GitHub App identity checks. No installation tokens are requested here.

use credentials_core::http::ReqwestTransport;
use credentials_core::oauth::OAuthCredential;
use credentials_core::refresh_adapters::github_app::check_github_app;

use crate::{tokio_block_on, CliError, GlobalArgs};

fn http() -> Result<impl credentials_core::refresh_adapters::HttpTransport, CliError> {
    let http = ReqwestTransport::new().map_err(|e| CliError::Io(e.to_string()))?;
    #[cfg(all(debug_assertions, feature = "test-support"))]
    let http = TestHttp(http);
    Ok(http)
}

pub fn check_deposit(id: &str, oauth: &OAuthCredential) -> Result<(), CliError> {
    let http =
        http().map_err(|_| CliError::Io("the App's GitHub slug couldn't be checked".into()))?;
    let check = tokio_block_on(check_github_app(id, oauth, &http))
        .map_err(|_| CliError::Io("the App's GitHub slug couldn't be checked".into()))?;
    check
        .require_match()
        .map_err(|e| CliError::Usage(e.to_string()))?;
    Ok(())
}

pub fn cmd_verify(global: &GlobalArgs) -> Result<(), CliError> {
    use credentials_core::envelope::{open as envelope_open, RecordBinding};
    use credentials_core::record::VaultRecord;
    use credentials_core::{resolver, usable};

    let db = crate::store_path(global);
    if !db.exists() {
        return Err(CliError::Usage(
            "no vault (run 'ck auth bootstrap' first)".into(),
        ));
    }
    // A read transaction pins the key slot and envelopes to the same snapshot even
    // if the running daemon rotates the master key during the network checks.
    let mut conn = usable::open_store_read_only(&db).map_err(|e| CliError::Io(e.to_string()))?;
    let conn = conn
        .transaction()
        .map_err(|e| CliError::Io(e.to_string()))?;
    let cfg = crate::resolver_config(global);
    let key = match usable::read_db_key_id_read_only(&conn) {
        Some(id) => resolver::resolve_for_db(&cfg, id),
        None => resolver::resolve(&cfg, None),
    }
    .map_err(CliError::MasterKey)?;
    let has_credentials: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='credentials')",
            [],
            |r| r.get(0),
        )
        .map_err(|e| CliError::Io(e.to_string()))?;
    if !has_credentials {
        return Ok(());
    }
    let mut stmt = conn
        .prepare(
            "SELECT credential_id, record_version, envelope FROM credentials \
                  WHERE credential_id GLOB 'github_app:*' ORDER BY credential_id",
        )
        .map_err(|e| CliError::Io(e.to_string()))?;
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, Vec<u8>>(2)?,
            ))
        })
        .map_err(|e| CliError::Io(e.to_string()))?;
    let http = http().ok();
    let mut all_ok = true;
    for row in rows {
        let (id, version, blob) = row.map_err(|e| CliError::Io(e.to_string()))?;
        let binding = RecordBinding {
            credential_id: &id,
            record_version: version as u64,
        };
        let record = envelope_open(&key, &blob, &binding)
            .ok()
            .and_then(|plain| serde_json::from_slice::<VaultRecord>(&plain).ok());
        let observation = record
            .as_ref()
            .and_then(|r| r.oauth.as_ref())
            .and_then(|oauth| tokio_block_on(check_github_app(&id, oauth, http.as_ref()?)).ok());
        let (slug, status) = observation
            .as_ref()
            .map(|check| (check.observed_slug().unwrap_or("-"), check.status()))
            .unwrap_or(("-", "unreachable"));
        println!("{}\t{}\t{status}", id.escape_debug(), slug.escape_debug());
        all_ok &= status == "ok";
    }
    if all_ok {
        Ok(())
    } else {
        Err(CliError::Io(
            "some GitHub App records did not verify".into(),
        ))
    }
}

/// Only debug test builds can redirect the authenticated check to a loopback fixture.
#[cfg(all(debug_assertions, feature = "test-support"))]
struct TestHttp(ReqwestTransport);

#[cfg(all(debug_assertions, feature = "test-support"))]
#[async_trait::async_trait]
impl credentials_core::refresh_adapters::HttpTransport for TestHttp {
    async fn get(
        &self,
        url: &str,
        headers: &[(&str, &str)],
    ) -> Result<
        credentials_core::refresh_adapters::HttpResponse,
        credentials_core::refresh_adapters::RefreshError,
    > {
        use credentials_core::refresh_adapters::github_app::INSTALLATIONS_URL;
        assert_eq!(url, INSTALLATIONS_URL);
        self.0
            .get(
                crate::browser_login::test_endpoint(
                    "github_app_installations_url",
                    INSTALLATIONS_URL,
                ),
                headers,
            )
            .await
    }

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
            "identity checks must not mint installation tokens".into(),
        ))
    }
}
