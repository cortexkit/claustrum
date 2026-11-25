// The vault's fleet-log crate policy (`vault_log_crates` in main.rs).

use super::super::{async_nats_ceilings, VAULT_LOG_CRATES};

/// The Rust name of a workspace crate's library: `[lib] name` when the manifest
/// sets one, otherwise the package name with hyphens as underscores. Read as text,
/// because the manifests are plain and the test should not need a TOML parser.
fn library_name(manifest: &str) -> Option<String> {
    let section_name = |section: &str| {
        let body = manifest.split(section).nth(1)?;
        let body = body.split("\n[").next()?;
        body.lines().find_map(|line| {
            let value = line.trim().strip_prefix("name")?.trim().strip_prefix('=')?;
            Some(value.trim().trim_matches('"').to_owned())
        })
    };
    section_name("\n[lib]")
        .or_else(|| section_name("[package]").map(|name| name.replace('-', "_")))
}

#[test]
fn every_workspace_library_and_the_daemon_binary_log_as_the_vault() {
    let crates_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates directory");
    let mut libraries = Vec::new();
    for entry in std::fs::read_dir(crates_dir).expect("read crates directory") {
        let manifest = entry.expect("crates entry").path().join("Cargo.toml");
        let Ok(text) = std::fs::read_to_string(&manifest) else {
            continue;
        };
        libraries.push(library_name(&text).expect("crate manifest names its package"));
    }
    // The anchor: if the scan stops finding crates, it must fail rather than pass empty.
    assert!(
        libraries.iter().any(|name| name == "credentials_core"),
        "scan found {libraries:?}"
    );
    assert!(
        libraries.iter().any(|name| name == "claustrum_module_probe"),
        "the [lib] name override was not read: {libraries:?}"
    );
    for name in libraries.iter().map(String::as_str).chain(["ck_claustrum"]) {
        assert!(
            VAULT_LOG_CRATES.contains(&name),
            "{name} is not in VAULT_LOG_CRATES, so its INFO lines would be capped at WARN"
        );
    }
}

#[test]
fn every_piece_of_the_bus_client_directive_becomes_a_ceiling() {
    let pieces = cortexkit_bus_client::ASYNC_NATS_LOG_DIRECTIVE.split(',').count();
    let ceilings = async_nats_ceilings();
    assert_eq!(ceilings.len(), pieces, "a piece was skipped: {ceilings:?}");
    assert!(
        ceilings.contains(&("async_nats::connector", cortexkit_log::LevelFilter::OFF)),
        "the reconnect lines must be dropped: {ceilings:?}"
    );
}
