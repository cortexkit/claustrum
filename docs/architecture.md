# Architecture

claustrum is a credential vault that runs as a module under the CortexKit supervisor
(`subc`). It holds OAuth tokens, API keys, session cookies, DSNs and private keys
encrypted at rest, refreshes OAuth credentials before they expire, and serves each
consumer only what it is entitled to. One custody home means one refresher per OAuth
grant, so two processes can never race each other into a provider's token-reuse
detection.

This document describes the parts, how data moves between them, and the rules that
are easy to break. The consumer-facing wire surface is specified in
[the wire contract](wire-contract-v1.md); day-to-day operation is in
[the operator runbook](operator-runbook.md).

## 1. The parts

| part | path | what it is |
|---|---|---|
| `credentials-core` | `crates/credentials-core` | Custody logic, wire-agnostic: records, the encryption envelope, master-key resolution, the encrypted store and its migrations, refresh adapters, the refresh engine, the audit chain, enrollment, Ed25519 signing, X25519 KEM keys, APNs provider-token minting. It never speaks the supervisor protocol. |
| `ck-claustrum` | `crates/credentials-module/src/main.rs` | The daemon. Registers with the supervisor as the reserved `claustrum` management surface and serves the read surface (`read_surface.rs`), the authenticated admin surface (`admin_surface.rs`) and the health probe. Per-connection rate limits live in `limiter.rs`. |
| `ck-auth` | `crates/credentials-module/src/bin/credentials_cli.rs` | The operator CLI, run as `ck auth <verb>`. It is the only write surface an operator uses: login, import, put, grants, handles, enrollment, audit. Helpers live in `src/bin/cli_support/`. |
| `cortexkit-claustrum-client` | `crates/claustrum-client` | The Rust client for supervised modules. |
| `@cortexkit/claustrum-client` | `packages/client` | The TypeScript client. Both clients live here so their decoders are tested against the producer's own serialized replies. |
| `ck_key_verify`, `ck_key_move` | `crates/credentials-core/src/bin/` | Feature-gated operator tools for checking and moving the master key. |

The two programs share one data directory, `<data_home>/cortexkit/claustrum/`, which
holds `store.db` (SQLite, WAL mode), the lease file, the non-secret `key-source`
record, and the backup descriptor `engram-catalog.json`.

The supervisor only routes: it carries request and reply bytes on a route channel and
never holds, opens, decrypts or parses a credential. Credentials are pulled on demand by
consumers and are never pushed at module registration.

## 2. Records

A credential is a `VaultRecord` keyed by an operator-chosen id of the form
`<method>:<provider>[:<label>]`, for example `oauth:anthropic` or `apikey:deepseek:work`.
The id is a label: nothing routes on it, and the record's kind and refresh adapter are
stored fields rather than parsed from it.

Kinds (`CredentialKind` in `crates/credentials-core/src/record.rs`) are a closed set:
`Oauth`, `ApiKey`, `Dsn`, `Cookie`, `Opaque`, `SigningKey`, `KemKey`. The consumer-facing
payload is opaque bytes; the rest of the record (canonical OAuth fields, refresh
adapter, expiry, identity) is vault-internal.

Lifecycle states (`RecordState`) are a closed set:

| state | meaning | health effect |
|---|---|---|
| `active` | served | none |
| `needs_reauth` | the provider refused the credential, or a report latched it | `degraded` |
| `corrupt` | the record failed to decrypt or parse and is quarantined | `degraded` |
| `retired` | an operator stopped it on purpose with `ck auth logout` | none |

`needs_reauth` and `retired` refuse reads identically (`needs_reauth`, class
`auth_required`): to a consumer both mean "not served until an operator acts". Only the
health arithmetic and the operator's `list`/`status` output tell them apart.
Transitions: `logout` moves `active` or `needs_reauth` to `retired`; `login --replace` and
`reactivate` move `needs_reauth` or `retired` back to `active`; `reactivate` refuses
`corrupt`; `remove` deletes the row.

`record_version` increases on every write and every refresh of one row. It is the
change cursor consumers join on, and it is bound into the encryption (section 4).

## 3. Data flow

### Boot

The daemon's boot is a gate, in this order: resolve the master key, open and migrate
the encrypted store, reconcile any refresh intents a crash left behind, and only then
accept reads. A `get` is never served while a crash-left intent is unresolved.

The daemon never bootstraps. Only `ck auth bootstrap` creates a key, so a vault whose
data directory moved finds no key for its new scope and refuses to serve rather than
coming up empty.

A binary refuses to open a store whose schema is newer than its own migration chain
(`store::tests::a_store_ahead_of_this_binary_refuses_to_migrate`). The current chain
ends at migration 18.

### Reading a credential

```
consumer ──route.open(ManagementSurface, "claustrum")──▶ subc ──route.bind(principal)──▶ ck-claustrum
         ──credential.get { handle }─────────────────────────────────────────────────▶ resolve handle
                                                                                         refresh if stale
         ◀─{ payload, expires_at_ms, record_version, identity… }──────────────────────── serve
```

A consumer authorizes in one of three ways, described in full in
[the wire contract, section 2](wire-contract-v1.md#2-addressing):

- **A capability handle** (`ckh_…`), a bearer token minted by `ck auth mint-handle`. The
  vault stores only its hash.
- **A supervised module principal**, `reserved:<module>`, stamped by the supervisor at
  route bind when the module presents the launch nonce it was spawned with.
- **An enrollment token**, `enrolled:<name>`, minted by the vault to a host-launched
  consumer after an operator approves its name.

Principals reach credentials through grants. A grant names a principal, a selector
(`exact` id, `category`, or `audience`), and one operation: `read`, `sign`, `open`,
`list`, `deposit`, `account_token` or `seal`. No operation implies another. `seal`
takes an exact selector only.

### Refreshing a credential

Refresh is owned by the vault; consumers never refresh or write back. The refresh
engine (`crates/credentials-core/src/engine.rs`) runs this state machine:

1. Durably write a `refresh_intent` (credential id, hash of the old refresh token,
   lease epoch) before calling the provider.
2. Call the provider through the record's refresh adapter and stage the result in
   memory.
3. In one fenced transaction, write the new tokens, bump `record_version`, and clear
   the intent.
4. Only after that commit does a `get` see the new payload.

Concurrent `get`s needing a refresh of the same credential share one upstream call
(single-flight per credential id, `concurrent_gets_single_flight_one_upstream_call`).

On boot, a surviving intent means the process died mid-exchange and the provider may
or may not have rotated the token. Reconciliation resolves it to `needs_reauth` unless a
non-mutating provider check proves the stored refresh state is still valid; it never
calls a rotating refresh endpoint during recovery
(`engine_tests::reconcile_dangling_intent_no_check_is_needs_reauth`,
`kill9_between_response_and_commit_resolves_to_needs_reauth`, which SIGKILLs the real
helper process between the provider response and the commit). The old access token still
working is not evidence, because it can outlive a rotated refresh token. The residual cost
is stated rather than hidden: a crash in that narrow window costs one re-login, never a
silently dead token.

There are 13 adapters, one per provider family the vault can refresh: `anthropic`,
`antigravity`, `cursor`, `devin`, `digitalocean`, `github_app`, `github_copilot`,
`google` (which also serves Gmail logins), `kimi`, `meta`, `openai`, `snowflake` and
`xai`, each in `crates/credentials-core/src/refresh_adapters/` with conformance tests
over recorded HTTP fixtures. Adding an adapter is a contract change: the count in this
paragraph is checked against the tree by
`refresh_adapters::documented_count_tests::the_documented_adapter_count_matches_the_tree`.
Every provider host an adapter or catalog entry contacts is listed in
[`endpoint-hosts.txt`](endpoint-hosts.txt), which `scripts/endpoint-hosts.py` regenerates
and diffs.

### Writing

There is exactly one writer at a time, enforced by an epoch-checked single-writer lease.
Every durable write runs inside a transaction that re-reads the store's fence epoch and
refuses if a newer writer has taken the lease. A writer that loses the fence latches
permanently (`store::tests::fenced_out_never_clears_on_a_later_successful_write`): having
lost it once means another writer holds authority.

While the daemon runs it holds the lease, so `ck auth` sends write operations to it over
the route plane. Each admin operation is authorized by two gates
(`crates/credentials-module/src/admin_surface.rs`):

- **Gate 1, provenance:** the bind's supervisor-stamped principal must be `direct`. This
  removes the accidental consumer class; it is not the security boundary.
- **Gate 2, the authority:** the caller MACs the exact operation bytes with a key derived
  from the master key, over a single-use nonce. The daemon verifies before it parses or
  executes. A captured tag cannot authorize a second execution
  (`replay_of_a_valid_tag_is_refused_nonce_claimed`) or a different operation.

When no daemon is reachable, `ck auth` takes the lease itself and writes directly, with
the same audit chain and the same master-key requirement. `bootstrap` and
`rotate-master-key` are always offline.

Every deposit is create-only unless the caller asks to replace: a blind write to an
existing id is refused, a compare-and-set write with the wrong expected hash is refused
and changes nothing, and any overwrite of an existing id raises an audit alarm
(`create_only_rejects_blind_overwrite`, `cas_mismatch_rejected_and_record_unchanged`,
`admin_overwrite_raises_audit_alarm_row`, all in
`crates/credentials-core/tests/security_conformance.rs`).

## 4. Encryption and the master key

Each record is sealed individually with XChaCha20-Poly1305 under the 32-byte master key,
with a fresh 192-bit random nonce per seal. The additional authenticated data binds the
key id, the credential id and the `record_version`, so a record cannot be moved to
another id or rolled back to an earlier version of itself
(`envelope::tests::wrong_binding_record_version_fails_decrypt`,
`envelope::tests::wrong_binding_credential_id_fails_decrypt`). The decoder bounds-checks
every field and never panics on arbitrary bytes
(`envelope::tests::decoder_never_panics_on_arbitrary_bytes`, a property test).

The cryptographic domain separators are listed in
[`domain-separators.txt`](domain-separators.txt). They keep the pre-rename
`cortexkit-credentials` spelling on purpose: they are hashed or authenticated into stored
data, so changing one makes every existing vault unreadable. `scripts/endpoint-hosts.py`
refuses an unreviewed change to that list.

The master key lives in one recorded backend, named in `<data_dir>/key-source`:
`keychain` (macOS), `credential-manager` (Windows), `secret-service` (Linux), or
`file:<absolute path>` for an operator-held key file outside the data directory. A key
file inside the data directory is refused (`resolver::tests::key_under_data_dir_is_rejected`).
Native stores keep a current and a next slot, so rotation re-wraps every record and the
sealed audit key in one transaction and a crash at any cut point reopens under whichever
key matches (`crash_after_rewrap_resolves_to_next_and_never_bricks` and its siblings in
`crates/credentials-core/tests/rotate_crash_cut.rs`).

A corrupt or undecryptable record is quarantined alone and the vault keeps serving every
other credential (`fail_closed_corrupt_envelope_quarantines_not_panics`). A missing or
locked master key is the typed `vault_locked` error, never a panic. The resolver checks the
resolved key's fingerprint against the store's expected `key_id` before any record is
decrypted, for every backend, so a wrong key fails closed as `vault_locked`
(`resolver::tests::wrong_key_id_is_mismatch_and_vault_locked`) rather than as a cascade of
decrypt failures.

Secret bytes are never logged or printed. Token, key and payload types render as redacted
placeholders (`secret::tests::a_secret_is_unprintable_and_serialises_transparently`,
`oauth::tests::debug_redacts_tokens`), and every output site in the daemon is enumerated by a
test, so a new one that could emit credential bytes must be reviewed
(`tests::every_daemon_output_site_is_enumerated`).

## 5. Audit and diagnostics

Every durable mutation appends an entry to `audit_log`, an HMAC chain keyed by an audit
key that is itself sealed under the master key. Each entry binds its predecessor, so an
interior edit, reorder or insert fails verification (`audit::tests::tampered_entry_breaks_chain`).

The chain does not detect truncation on its own: deleting a suffix leaves a shorter chain
that still verifies. The daemon therefore publishes the global chain tip (`auditSeq` and
`auditTipMac`) in its health snapshot so an external witness can record it. The MAC
matters as much as the sequence: a truncation followed by fresh appends returns the
sequence to an old value, and only the MAC at that sequence differs
(`store::tests::audit_tip_pair_exposes_tail_truncation_with_reused_sequence`).

The chain takes transitions only. Observations (provider refusals, consumer reports,
scoped refusals, first use of a grant) go to `auth_events`, a separate table that is not
tamper-evident and keeps the newest 64 rows per credential. The vocabularies of both
tables are listed in [the operator runbook](operator-runbook.md#the-four-diagnostic-string-vocabularies).

## 6. Health

The supervisor probes the daemon's health, which reports a snapshot recomputed every
5 seconds off the probe path:

| status | meaning |
|---|---|
| `ok` | the store is readable, the lease is held, and every record is `active` or `retired` |
| `degraded` | serving, but at least one credential is `needs_reauth` or `corrupt` |
| `failing` | the store is unreadable, this daemon lost write authority to a newer instance, or the health refresher stalled |

A degraded vault still serves every healthy credential. When the store is unreadable the
snapshot omits its counts rather than reporting zeros, so an outage cannot be plotted as
an empty vault.

## 7. Process hardening

On Linux both binaries make themselves non-dumpable before reading arguments or
credentials, which blocks same-user ptrace, `/proc/<pid>/mem` reads and core dumps. On
Windows both replace their process DACL so same-user processes get only query, synchronize
and terminate rights. On macOS the hardened-runtime signature does this job. Each binary
refuses to start if hardening fails (`crates/credentials-module/tests/process_hardening.rs`).
A process holding `SeDebugPrivilege` or root still gets in; this is defence in depth, not
a boundary.

Windows file custody (owner-only DACLs on every secret file the vault writes) is
inventoried in [Windows file custody](windows-file-custody.md).

## 8. Rules that bite

- **An unknown handle and a revoked handle are one answer.** Both return `not_found`,
  class `permanent`, with no credential id
  (`tests::unknown_and_revoked_get_handles_refuse_without_disclosing_a_credential_id`).
  Scoped refusals are uniform the same way
  (`tests::scoped_get_uncovered_and_unknown_ids_have_identical_wire_bodies`,
  `tests::scoped_status_unknown_and_no_grant_are_indistinguishable_on_the_wire`). So no
  refusal licenses a consumer to destroy its own configuration.
- **Reads are bounded per connection.** A handle is at least 128 bits of randomness, so it
  cannot be guessed. `credential.get_many` takes at most 8 handles (`GET_MANY_MAX` in
  `crates/credentials-module/src/limiter.rs`). A connection that reaches 64 fetches in 60
  seconds, or 16 distinct handles, raises a durable
  `fetch_rate_anomaly` alarm; the requests are still served, so the alarm detects a sweep
  rather than blocking it.
- **Handles survive repair.** `login --replace` and `put --replace` bump `record_version`
  without touching the handles table, so a held handle keeps resolving to the new secret.
  `invalidate`, `logout` and explicit revocation are the only ways a handle stops working.
- **A consumer report marks a token stale; it does not kill the credential.** A 401 at the
  current version on a refreshable credential forces a refresh on the next `get`; only the
  provider's `invalid_grant` latches `needs_reauth`
  (`engine_tests::report_stale_then_invalid_grant_latches_needs_reauth`). A report naming a
  superseded version is a no-op. Static credentials latch immediately.
- **`status` is a cursor and `get` is the authority.** `ready` tracks the state verdict and
  `record_version` tracks material; `reactivate` moves the first without the second.
- **A restart of this daemon is silent on the route plane.** A consumer reusing a binding
  from before the restart has its frames dropped without an error, so every long-lived
  consumer must impose a per-call deadline and rebind on expiry
  ([wire contract, section 9](wire-contract-v1.md#9-a-daemon-restart-is-silent-so-impose-a-per-call-deadline)).
- **The private half of a signing or KEM key never leaves the vault.** `get` refuses those
  kinds; `credential.sign`, `credential.open` and `credential.seal` exercise them in place
  (`tests::scoped_get_reveals_signing_kind_only_after_read_grant`). `credential.seal`
  returns only HPKE output and writes one audit row per call before replying; no
  operation returns a raw Diffie-Hellman value or a derived key.
- **Copy the data directory, never `store.db` alone, and never beside the live one.** See
  [the operator runbook](operator-runbook.md#reading-the-store-directly).

## 9. What this does not defend against

The threat model, including what is out of scope, is in [SECURITY.md](../SECURITY.md).
