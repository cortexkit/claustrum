# Windows filesystem custody inventory

This inventory covers claustrum's own Rust filesystem writes and permission checks.
Unix protection is unchanged. Windows secret files are create-new with a protected
current-user-only DACL from first visibility; replacement writes use private
temporary files and rename. Readers verify the opened handle before reading bytes.
The verifier permits only the current user, SYSTEM and Administrators as owners
and grant recipients, and fails closed on null DACLs or unknown grant types.

| Rust path / site | File kind | Unix protection today | Windows protection after |
| --- | --- | --- | --- |
| `credentials-core/src/resolver.rs`, `ensure_vault_dir` | Vault data directory | `create_dir_all`, then `0700` | `create_private_dir` creates or tightens, then `verify_private_dir`; foreign owners / reparse points refused |
| Same, `open_checked_key_file` | Operator master key, current and `.next` slots | Regular, effective-uid owner, no group/other mode bits; no-follow on Linux/macOS; opened device/inode matches lstat | Open, then `verify_owner_only` on that handle; refusal names the file and ACL remedy, never repairs the file |
| Same, `write_key_file`, `replace_at_operator_path` | Bootstrap key and rotation temporary / slot files | Create-new `0600`; fsync; replacement via temporary sibling and rename | `create_private_file`; parent verified before creation and publication; existing file never truncated |
| `credentials-core/src/resolver/source_record.rs`, `record_source` | `key-source` version/backend/absolute key path | Shared `0600` writer; create-only hard-link publication under `0700` vault dir | Shared private writer and verified publication directory; non-secret metadata, so its plain record reader remains unchanged |
| `credentials-module/src/bin/cli_support/opencode_files.rs`, credential and handle readers | OpenCode `auth.json` tokens / API keys and `opencode-handles.json` capabilities | Regular file, current uid, exactly `0600`; size-limited read | `verify_owner_only` on the opened file; size and bytes read from the verified handle, not a reopened path |
| Same, `write_atomic_guarded` | Credential / handle file temporary and replacement | Create-new `0600`, explicit chmod, file fsync and rename; handle parent tightened to `0700`; auth parent is validated but not chmodded | Parent created/tightened with `create_private_dir`, checked with `verify_private_dir`; temporary uses `create_private_file`; directory checked again before rename |
| Same, manifest lock acquisition / `write_lock_owner` / `read_lock_owner` | Empty lock claim directory and non-secret lease-owner metadata (tenant, PID, timestamp, ABA nonce) | Exclusive mkdir, `0700`; atomic create-new `0600` owner temporary, chmod, rename | Empty mkdir remains the exclusive claim: `create_private_dir` succeeds on an existing directory, so it cannot distinguish a new claim from a competitor's lock. After exclusive mkdir, the directory is tightened with `create_private_dir` before owner bytes are published, then verified. Owner files use private create / opened-handle verify |
| `credentials-module/src/main.rs`, `place_engram_catalog` | Static `engram-catalog.json` backup descriptor | `0600` temporary, fsync, rename | Unchanged: descriptor embeds public backup paths and policy, no key, token or capability |
| `credentials-core/src/refresh_adapters/kimi.rs`, device ID helpers | `kimi-device-id` local metadata | Create-new `0600`; ordinary reads | Unchanged: random device identifier is explicitly not a token or credential; not secret-bearing |
| `credentials-core/src/signing.rs`, `envelope.rs`, `store.rs` | Signatures / encrypted credential envelopes | Values / SQLite BLOBs, not separate files | No claustrum file site: database / WAL / SHM protection belongs to `cortexkit-store` |
| `signed-payloads/` described in the signing procedure | Operator-saved signed approval envelopes | Procedure specifies `0600`; no Rust creator/loader | No Rust site: approval signatures and payloads are public data, not private signing keys |
| `cortexkit-lease`, `cortexkit-store`, `cortexkit-log` consumers | Lease, database and log files | Filesystem policy owned by the named shared crates | Out of scope: shared crates already own their Windows DACL handling |

Paths in the table are relative to `crates/`. TypeScript client and OpenCode plugin
filesystem helpers are outside this change.

## Dependency and launch nonce compatibility

The workspace requirement moves from `subc-os = "0.1.6"` (lockfile resolved 0.1.10)
to 0.1.14. `cortexkit-test-support` must also move from 0.1.0 to 0.1.3 because 0.1.0
pins `subc-os = "=0.1.10"`. No claustrum launch-nonce call signature changes:
`launch_nonce()` still returns `Result<Option<LaunchNonce>, LaunchNonceError>` and
`value()` / `source()` remain available; Unix inherited-fd and caching behaviour
is unchanged.

Compared with 0.1.10, 0.1.14 adds Windows named-pipe handoff, a `Pipe` provenance
value (`"pipe"`), pipe environment constants and pipe-specific errors. When
`SUBC_LAUNCH_NONCE_PIPE` names a handoff, errors refuse launch unless
`SUBC_LAUNCH_NONCE_PIPE_FALLBACK=env` explicitly permits the environment copy.
An absent pipe still uses the environment. The daemon already maps unknown
source variants through `from_wire_name(other.as_str())`, so `Pipe` provenance is
preserved without changing that call site. The Rust client reads only the nonce
value and still propagates errors. These are launch-key delivery changes, not
operator master-key file changes.

## Verification boundary

`credentials-core/tests/windows_acl.rs` tests unsafe key-file refusal, protected
key / key-source / rotation creation, and tightening broad inherited directory
grants. CLI wrappers also test protected credential / handle / lock publications
and unsafe credential / handle refusal. All five tests are registered on every
OS; non-Windows bodies print explicit skip lines.

`scripts/prove-windows-acl.py` runs in CI's Windows job against the real OS. It
first requires all three core tests green, then independently skips key-file
verification and bypasses private key creation. Each mutant must redden exactly
its named test and leave the other two green. It stages the live source before
mutation, records the non-empty diff, restores from that index and records the
empty restored diff. CI uploads `gate-evidence/windows-acl-mutations.json` outside
the Cargo build directory. Local Windows GNU clippy proves compilation only:
Windows behaviour and both red mutation observations are proven only by CI's
Windows job. On macOS and Linux, the registered tests only print skip lines and
return successfully without executing their Windows bodies; those passes do not
demonstrate DACL behaviour.
