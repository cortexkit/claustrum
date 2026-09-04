//! Test-only helper for the vault-native-login crash-cut conformance test.
//!
//! Only built under the `login-test-seam` feature. Like the rotate helper it compiles
//! NO seam into the library: the login write is a SINGLE atomic fenced transaction
//! (`overwrite_unconditional_audited`), so there is no mid-operation durable state to
//! catch — the helper simply brackets that one public store call with park points.
//!
//! The scenario models `login --provider anthropic --replace`: an OLD dual-custody
//! oauth:anthropic credential already exists (with its own handle), and login mints an
//! INDEPENDENT new token that replaces it. The network exchange is elided (it writes
//! nothing durable); the helper jumps straight to the only durable step — the store
//! overwrite — and parks before or after it.
//!
//! Usage: `login_cut_helper <db_path> <key_dir> <marker_path> <cut>`
//!   cut ∈ { before-write, after-write }
//!     before-write = crash after the (elided) network exchange, BEFORE the store
//!                    commit -> the OLD credential must be fully intact + refreshable
//!                    (the never-strand guard).
//!     after-write  = crash just AFTER the store commit -> the NEW credential is
//!                    present at version+1, the handle survived, the chain verifies.
//!
//! Uses the operator-path key store so it runs in CI without a keychain.

use std::path::PathBuf;

use cortexkit_store::{open_sqlite, Isolation, StorageBackend, StorageDescriptor};
use credentials_core::audit::{AuditCtx, AuditOp};
use credentials_core::oauth::OAuthCredential;
use credentials_core::record::VaultRecord;
use credentials_core::resolver::{self, KeySource, ResolverConfig};
use credentials_core::store::{mint_handle, EncryptedStore};

fn park(marker: &PathBuf) -> ! {
    std::fs::write(marker, b"ready").expect("write readiness marker");
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}

/// The old credential's refresh token — the parent asserts this exact value survives
/// a before-write crash (proving the original grant chain is untouched).
const OLD_REFRESH: &str = "OLD-REFRESH-TOKEN-do-not-lose";
/// The new credential's refresh token — present only after an after-write crash.
const NEW_REFRESH: &str = "NEW-INDEPENDENT-REFRESH-TOKEN";

fn oauth_record(refresh: &str, access: &str) -> VaultRecord {
    let oauth = OAuthCredential {
        access_token: access.to_string().into(),
        refresh_token: refresh.to_string().into(),
        expires_at_ms: Some(1),
        token_url: "https://platform.claude.com/v1/oauth/token".to_string(),
        client_id: Some("9d1c250a-e61b-44d9-88ed-5944d1962f5e".to_string()),
        scopes: vec!["user:inference".to_string()],
    };
    VaultRecord::new_oauth("login", "anthropic", oauth, access.as_bytes().to_vec())
}

fn main() {
    let mut args = std::env::args().skip(1);
    let db_path = args.next().expect("usage: <db> <key_dir> <marker> <cut>");
    let key_dir = PathBuf::from(args.next().expect("missing key_dir"));
    let marker = PathBuf::from(args.next().expect("missing marker"));
    let cut = args.next().expect("missing cut point");

    let data_dir = PathBuf::from(&db_path)
        .parent()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    let config = ResolverConfig {
        data_dir,
        source: KeySource::OperatorPath {
            path: key_dir.join("master.key"),
        },
    };

    let key = resolver::bootstrap(&config).expect("bootstrap");
    let descriptor = StorageDescriptor {
        module_id: "cortexkit-credentials".into(),
        storage_namespace: "vault".into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: db_path.clone(),
        },
    };
    let store = open_sqlite(&descriptor).expect("open store");
    EncryptedStore::migrate(&store).expect("migrate");
    let store = EncryptedStore::open(store, key).expect("open vault");

    // Seed the OLD dual-custody credential and mint a handle for it (the handle the
    // parent asserts survives the replace).
    store
        .create_audited(
            "oauth:anthropic",
            &oauth_record(OLD_REFRESH, "OLD-ACCESS"),
            AuditCtx::admin(AuditOp::Import),
        )
        .expect("seed old credential");
    let handle = mint_handle().expect("mint handle");
    store
        .put_handle_hash(
            &handle.hash,
            "oauth:anthropic",
            AuditCtx::admin(AuditOp::MintHandle),
        )
        .expect("mint handle for old cred");
    // Persist the raw handle next to the rig so the parent test can prove it still
    // RESOLVES (via the real public resolve_handle API) after the crash — a genuine
    // survival check, not a row count.
    let handle_file = PathBuf::from(&db_path)
        .parent()
        .map(|p| p.join("handle.txt"))
        .expect("handle file path");
    std::fs::write(&handle_file, &handle.raw).expect("write handle file");

    // The login write models a successful exchange producing NEW_REFRESH. The only
    // durable step is this overwrite; park BEFORE it to model a crash after the
    // (elided) network exchange but before commit.
    if cut == "before-write" {
        park(&marker);
    }

    store
        .overwrite_unconditional_audited(
            "oauth:anthropic",
            &oauth_record(NEW_REFRESH, "NEW-ACCESS"),
            AuditCtx::admin(AuditOp::Login),
        )
        .expect("login overwrite");

    if cut == "after-write" {
        park(&marker);
    }

    eprintln!("login_cut_helper: completed without parking — unexpected cut '{cut}'");
    std::process::exit(2);
}
