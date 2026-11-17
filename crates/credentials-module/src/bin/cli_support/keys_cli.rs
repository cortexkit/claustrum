//! Vault bootstrap, signing, key minting, rotation, and approval commands.

use super::{
    commit_admin, descriptor, has_flag, open_for_admin, open_sqlite, parse_credential_id, required,
    resolver, resolver_config, store_op, AdminAuditOp, AdminOpBody, AuthMethod, CliError,
    Ed25519KeyPair, GlobalArgs, MasterKey, MasterKeyError, StoreError, StoreMode, SystemRandom,
    VaultRecord, ADMIN_OP_SCHEMA_V1,
};
use base64::Engine;

pub(super) fn cmd_bootstrap(global: &GlobalArgs) -> Result<(), CliError> {
    // Bootstrap must also take the lease (the daemon must be stopped) and must not
    // clobber an existing key.
    let _store = open_sqlite(&descriptor(global)).map_err(|e| match e {
        // No admin op bootstraps a vault: there is no daemon to ask yet.
        StoreError::Lease(_) => CliError::DaemonRunning {
            route_path_exists: false,
        },
        other => CliError::StoreOpen(other),
    })?;
    // IDEMPOTENT ON PURPOSE: an already-provisioned vault is bootstrap's POSTCONDITION,
    // not a failure. Returning an error for a state that satisfies the goal is what made
    // this dangerous -- `CliError::MasterKey(_)` maps every one of MasterKeyError's 13
    // variants to exit 4, so "a key already exists" and "the keychain is locked and I
    // cannot tell" are indistinguishable to a caller reading the code.
    //
    // A LOCKED LOGIN KEYCHAIN ("User interaction is not allowed", common over SSH) also
    // exits 4, so a caller reading 4 as "already provisioned" would move on and enable
    // the module with NO KEY. Both readings of 4 are defensible; the conflation is the
    // defect.
    //
    // So the installer can now always run bootstrap: success means a key exists, and a
    // non-zero exit means one does not. The key_id is printed either way, which is what
    // lets an operator tell a fresh provision from a pre-existing vault -- the honest
    // difference between the two cases, rather than an exit code carrying it.
    match resolver::bootstrap(&resolver_config(global)) {
        Ok(key) => {
            println!(
                "provisioned a new master key (key_id {})",
                key.key_id().to_hex()
            );
            Ok(())
        }
        Err(MasterKeyError::KeyAlreadyProvisioned(_)) => {
            // Read the existing key back so the line names WHICH key is in place. If that
            // read fails we still exit 0: `KeyAlreadyProvisioned` already proved a key
            // exists, which is the whole postcondition, and downgrading to a failure here
            // would reintroduce the conflation this arm exists to remove.
            match resolver::resolve(&resolver_config(global), None) {
                Ok(key) => println!(
                    "already provisioned (key_id {}); nothing to do",
                    key.key_id().to_hex()
                ),
                Err(e) => println!(
                    "already provisioned; nothing to do (the key is present but could not \
                     be read back to name it: {e})"
                ),
            }
            Ok(())
        }
        Err(other) => Err(CliError::MasterKey(other)),
    }
}

/// Generate and store an Ed25519 signing key without creating a second copy outside
/// the vault. The public half is derived before the record is committed so it can be
/// printed only after the admin write succeeds; no private material reaches output.
pub(super) fn cmd_mint_signing_key(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    let id = required(args, "--id")?;
    let parsed = parse_credential_id(&id);
    if !matches!(parsed.method, Some(AuthMethod::Signing)) {
        return Err(CliError::Usage(
            "mint-signing-key requires an id beginning with signing:".to_string(),
        ));
    }

    // `ring` generates PKCS#8 in memory. The only copy after this function returns is
    // the encrypted record; neither the key bytes nor this PEM are sent to disk or a
    // process boundary before the vault seals them.
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
        .map_err(|_| CliError::Io("generating Ed25519 key failed".to_string()))?;
    let private_pem = pem_wrap_private_key(pkcs8.as_ref());
    let public = credentials_core::signing::public_key_ed25519(&private_pem)
        .map_err(|_| CliError::Io("generated Ed25519 key was unusable".to_string()))?;
    let mut record = VaultRecord::new_static(
        AuthMethod::Signing.credential_kind(),
        "operator",
        private_pem.into_bytes(),
        None,
    );
    record.operator_sign = has_flag(args, "--operator-sign");
    record.audit_each_signature = record.operator_sign || has_flag(args, "--audit-each-signature");

    let replace = has_flag(args, "--replace");
    let (audit_op, mode, success) = if replace {
        (
            AdminAuditOp::Overwrite,
            StoreMode::ReplaceUnconditional,
            "replaced",
        )
    } else {
        (AdminAuditOp::Put, StoreMode::Create, "created")
    };
    commit_admin(global, store_op(&id, record, audit_op, mode))?;

    // Public material is the intentional output of this ceremony. The private PEM
    // stays inside the sealed record and is never interpolated into a success message.
    println!("{success} {id}");
    println!("public_key_hex {}", public.public_key_hex);
    println!("key_id {}", public.key_id);
    Ok(())
}

pub(super) fn cmd_sign(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    use std::io::Read;

    let id = required(args, "--id")?;
    let path = required(args, "--payload-file")?;
    let input: Box<dyn Read> = if path == "-" {
        Box::new(std::io::stdin())
    } else {
        Box::new(std::fs::File::open(&path).map_err(|e| CliError::Io(e.to_string()))?)
    };
    let mut payload = Vec::new();
    input
        .take(credentials_core::admin_ops::MAX_OPERATOR_SIGN_PAYLOAD as u64 + 1)
        .read_to_end(&mut payload)
        .map_err(|e| CliError::Io(e.to_string()))?;
    if payload.len() > credentials_core::admin_ops::MAX_OPERATOR_SIGN_PAYLOAD {
        return Err(CliError::Io(
            "payload exceeds the 64 KiB signing cap".into(),
        ));
    }
    let result = commit_admin(
        global,
        AdminOpBody::OperatorSign {
            v: ADMIN_OP_SCHEMA_V1,
            id,
            payload_b64: base64::engine::general_purpose::STANDARD.encode(&payload),
        },
    )?;
    println!("{}", serde_json::to_string(&result).expect("JSON result"));
    Ok(())
}

/// Generate a KEM key and publish its public half for enrollment.
pub(super) fn cmd_mint_kem_key(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    let id = required(args, "--id")?;
    if !matches!(parse_credential_id(&id).method, Some(AuthMethod::Kem)) {
        return Err(CliError::Usage("mint-kem-key requires a kem: id".into()));
    }
    let private_pem = credentials_core::kem::generate_key().map_err(CliError::Io)?;
    let (public, key_id) =
        credentials_core::kem::public_half(&private_pem).map_err(CliError::Io)?;
    let record = VaultRecord::new_static(
        AuthMethod::Kem.credential_kind(),
        "operator",
        private_pem.into_bytes(),
        None,
    );
    let mode = if has_flag(args, "--replace") {
        StoreMode::ReplaceUnconditional
    } else {
        StoreMode::Create
    };
    let audit_op = if has_flag(args, "--replace") {
        AdminAuditOp::Overwrite
    } else {
        AdminAuditOp::Put
    };
    commit_admin(global, store_op(&id, record, audit_op, mode))?;
    println!(
        "{} {id}",
        if has_flag(args, "--replace") {
            "replaced"
        } else {
            "created"
        }
    );
    println!(
        "public_key_hex {}",
        public
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    println!("key_id {key_id}");
    Ok(())
}

fn pem_wrap_private_key(pkcs8: &[u8]) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(pkcs8);
    let mut pem = String::from("-----BEGIN PRIVATE KEY-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).expect("base64 output is ASCII"));
        pem.push('\n');
    }
    pem.push_str("-----END PRIVATE KEY-----");
    pem
}

pub(super) fn cmd_rotate_master_key(global: &GlobalArgs) -> Result<(), CliError> {
    // Crash-safe two-slot handover. The key store holds two slots (current/next);
    // the database's plaintext key_id is the authority for which key it is sealed
    // under. Order — brick-free at every crash point:
    //   0. HEAL any prior crashed-mid-rotation state (a `next` the database is already
    //      sealed under, from a rotation that crashed before promotion): promote it to
    //      `current` and clear `next`, so staging below cannot overwrite a key the
    //      database depends on. Without this, a second rotation staging into `next`
    //      followed by a crash before its own rewrap would leave the database matching
    //      NEITHER slot — the scheme's one bricking window.
    //   1. open under the current key (proves possession + takes the lease),
    //   2. STAGE the new key into `next` (current still opens the vault),
    //   3. DB rewrap under the new key in ONE atomic fenced txn (now the db's key_id
    //      matches `next`),
    //   4. PROMOTE `next` to `current` and clear `next` (hygiene; off the brick-path).
    // A crash after (2) resolves via current (db still old); after (3) via next (db
    // now new); after (4) via current. No state matches neither slot.
    let mut store = open_for_admin(global, false)?;
    let new_key = MasterKey::generate().map_err(|_| CliError::Io("csprng".to_string()))?;
    let new_key_id = new_key.key_id();
    let config = resolver_config(global);

    // Heal before staging: `store.key_id()` is the fingerprint the database is sealed
    // under (open_for_admin resolved the matching slot and opened under it), so a pending
    // un-promoted `next` from a crashed prior rotation is promoted to `current` and
    // `next` freed before we stage the new key into it.
    resolver::heal_pending_rotation(&config, store.key_id()).map_err(CliError::MasterKey)?;

    resolver::stage_next(&config, &new_key).map_err(CliError::MasterKey)?;
    #[cfg(all(windows, debug_assertions, feature = "windows-runtime-test-seam"))]
    credentials_core::test_support::windows_runtime_pause("rotation-staged")
        .map_err(|e| CliError::Io(e.to_string()))?;
    let quarantined = store.rotate_master_key(new_key).map_err(CliError::Store)?;
    // Promote copies `next` to `current` and clears `next` within the key store, so
    // it needs no key handle (the new key was consumed by the rewrap above).
    resolver::promote_next(&config).map_err(CliError::MasterKey)?;
    println!("rotated master key to key_id {}", new_key_id.to_hex());
    if !quarantined.is_empty() {
        // Records that could not decrypt under the OLD key were already corrupt; the
        // rotation quarantined them (state = corrupt) rather than leaving stale-key rows.
        // Surface them so the operator re-imports/re-logs them in.
        eprintln!(
            "warning: {} record(s) could not be re-wrapped and were quarantined as corrupt \
             (re-import or re-login these): {}",
            quarantined.len(),
            quarantined.join(", ")
        );
    }
    Ok(())
}

/// Record that a named approver approved an artifact's EXACT BYTES, before a signing
/// window is opened for it.
///
/// THE HASH IS COMPUTED HERE, FROM THE FILE, and is never taken as an argument. An
/// operator-supplied hash would let the approval name bytes nobody read: the entry would
/// look identical while binding a different artifact, which is the one failure this
/// record exists to make impossible.
///
/// Prints the chain sequence so the approval can be cited by the party who publishes the
/// signature. They meet at the hash: the chain proves who approved bytes H before the
/// key was reachable, the signature proves the key signed bytes H.
pub(super) fn cmd_approve(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    let id = required(args, "--id")?;
    let path = required(args, "--file")?;
    let approver = required(args, "--approver")?;

    let bytes =
        std::fs::read(&path).map_err(|e| CliError::Io(format!("read artifact {path}: {e}")))?;
    if bytes.is_empty() {
        return Err(CliError::Usage(format!(
            "artifact {path} is empty: approving zero bytes would bind a hash no \
             meaningful artifact can have"
        )));
    }
    // `ring` is already a dependency of this binary (Ed25519 key minting), so the hash
    // costs no new crate. Lowercase hex, which is what every consumer of this value
    // compares against.
    let artifact_sha256 = ring::digest::digest(&ring::digest::SHA256, &bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();

    commit_admin(
        global,
        AdminOpBody::Approval {
            v: ADMIN_OP_SCHEMA_V1,
            credential_id: id.clone(),
            artifact_sha256: artifact_sha256.clone(),
            approver: approver.clone(),
        },
    )?;
    println!("approved {artifact_sha256}");
    println!("  artifact  {path} ({} bytes)", bytes.len());
    println!("  key       {id}");
    println!("  approver  {approver}");
    println!(
        "\nRecorded BEFORE the signing window. Verify this hash matches what the \
         publisher\n signs; if they differ, the approval and the signature bind \
         different artifacts."
    );
    Ok(())
}
