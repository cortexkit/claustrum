use crate::oauth::{import_antigravity_account, ImportError};

#[test]
fn imports_antigravity_accounts_store_and_packs_managed_project() {
    // The version:4 accounts-array store the antigravity plugin writes.
    let raw = br#"{
            "version": 4,
            "activeIndex": 1,
            "accounts": [
                {"email":"a@x.com","refreshToken":"1//0-aaa","managedProjectId":"proj-a"},
                {"email":"b@x.com","refreshToken":"1//0-bbb","managedProjectId":"encouraging-env-qwp21"}
            ]
        }"#;
    // activeIndex picks account[1].
    let c = import_antigravity_account(raw, None).expect("active account");
    assert_eq!(
        c.oauth.refresh_token.expose(),
        "1//0-bbb||encouraging-env-qwp21",
        "packs <refresh>||<managed> (empty plain project segment)"
    );
    assert!(
        c.oauth.access_token.expose().is_empty(),
        "antigravity store carries no access token"
    );
    // effective_project_id returns the managed id.
    assert_eq!(
        crate::refresh_adapters::antigravity::effective_project_id(c.oauth.refresh_token.expose())
            .as_deref(),
        Some("encouraging-env-qwp21")
    );
    // THE IDENTITY COMES BACK WITH THE SELECTED ACCOUNT, and it must be the
    // selected one rather than the first: antigravity access tokens are opaque, so
    // this email is the only thing that can tell two accounts apart downstream, and
    // returning the wrong account's email is worse than returning none.
    assert_eq!(
        c.email.as_deref(),
        Some("b@x.com"),
        "the active account's email, not the store's first"
    );
    // Select a specific account by email (forward-compat multi-account).
    let a = import_antigravity_account(raw, Some("a@x.com")).expect("by email");
    assert_eq!(a.oauth.refresh_token.expose(), "1//0-aaa||proj-a");
    assert_eq!(a.email.as_deref(), Some("a@x.com"), "tracks the selection");
    // Select by numeric index.
    let byidx = import_antigravity_account(raw, Some("0")).expect("by index");
    assert_eq!(byidx.oauth.refresh_token.expose(), "1//0-aaa||proj-a");
    assert_eq!(byidx.email.as_deref(), Some("a@x.com"));
    // An account with NO email is None rather than an empty string, which would
    // present downstream as an account labelled with nothing.
    let no_email = import_antigravity_account(
        br#"{"version":4,"activeIndex":0,"accounts":[{"refreshToken":"1//0-ccc"}]}"#,
        None,
    )
    .expect("account without an email");
    assert_eq!(no_email.email, None);
    assert_eq!(no_email.oauth.refresh_token.expose(), "1//0-ccc|");
    // An unknown selector is a typed error; an empty store is rejected.
    assert!(matches!(
        import_antigravity_account(raw, Some("nope@x.com")),
        Err(ImportError::ProviderNotFound(_))
    ));
    assert!(matches!(
        import_antigravity_account(br#"{"version":4,"accounts":[]}"#, None),
        Err(ImportError::Malformed(_))
    ));
}
