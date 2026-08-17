# cortexkit-credentials — build charter

You own the `cortexkit-credentials` repo: a subc-supervised module that holds
credentials (OAuth tokens, API keys, DSNs) **encrypted at rest** and serves each
consumer the credential it needs, **kept fresh** via vault-owned OAuth refresh. It
replaces the scattered per-consumer credential acquisition across the system with
one custody home.

This is a **security boundary**. The full normative spec is
[`docs/cortexkit-credentials-contract.md`](./cortexkit-credentials-contract.md) —
it survived three adversarial review passes (Oracle → Athena council NO-GO → v2
rewrite closing all blockers → Oracle confirm GO-WITH-CHANGES with T1/T2/T3). The
contract is the source of truth; this charter is the build plan and the ground
rules. **Do not deviate from the contract without raising it** — if something in it
looks wrong or impossible, ask (peer message to the driving Alfonso) before coding
around it.

## What is already done (the foundation you build on)

**Build-sequence step 1 is COMPLETE** (do not rebuild it):
- **`cortexkit-store::SqliteStore::with_conn_fenced`** (commons, committed) — the
  epoch-CAS fenced write path the vault's refresh-commit requires. It runs your
  write inside an IMMEDIATE transaction, reads the database's persisted fence
  epoch, and rejects (`StoreError::Fenced`) if a newer writer has taken the lease
  (the supervisor-reload / lease-handover race). **Use `with_conn_fenced` for every
  durable vault write** (refresh commit, put, invalidate, rotate). `with_conn` is
  the unfenced path — fine for reads, never for a credential mutation.
- **subc-core launch-nonce-bound reserved module_id** (subconscious, committed) —
  a module marked `reserved: true` in `subc.jsonc` can only be registered by the
  process subc spawned (it injects `SUBC_LAUNCH_NONCE`, the child echoes it in its
  HELLO `launch_nonce` field, subc constant-time-checks it). **Your module reads
  `SUBC_LAUNCH_NONCE` from the environment and echoes it in its HELLO**, and the
  daemon config that supervises it sets `reserved: true`. This closes the
  vault-impersonation hole (#13 / T3). The `@cortexkit/subc-client` and the Rust
  modules already have the echo wired as precedent — mirror the Rust module path.

## Your scope: contract build-sequence steps 2 + 3

### Step 2 — `credentials-core` (the lib): custody logic, wire-agnostic
- **Typed `VaultRecord`** (contract §5): `schema_version`, `kind`
  (oauth|api_key|dsn|opaque), `source`, `record_version` (monotonic, bumped every
  write/refresh), `expires_at`, `refresh_adapter`, `oauth: Option<OAuthCredential>`,
  `payload: Vec<u8>` (the opaque bytes the consumer gets — the rest never leaks to
  a read).
- **Canonical `OAuthCredential`** (§8): importers parse each source format
  (opencode/pi/antigravity) into ONE canonical type (token URLs, client_id, grant
  shape); refresh adapters operate on the canonical type, NEVER raw provider JSON.
- **Value-level encryption envelope** (§9): each `VaultRecord` encrypted as one
  atomic unit. Envelope carries `cipher_version`, `key_id`, per-record nonce.
  AES-256-GCM (scaffolded) with a 32-byte master key — confirm the AEAD choice in
  your first design note before the envelope lands. NEVER log/persist plaintext
  payload, token, or key bytes. Use `zeroize` to scrub key material.
- **Master-key resolution** (§9): desktop = OS keychain (macOS `security` CLI,
  service/account string, locked-keychain ⇒ fail-closed `vault_locked`); headless =
  operator-supplied key path **OUTSIDE the data tree** (co-location with `store.db`
  is FORBIDDEN — fail-closed if the key path resolves under the data dir). Bootstrap
  = CSPRNG 32-byte key, fail-closed if neither store is writable. Vault dir `0700`.
- **Bounded refresh adapters** (§8): 12 adapters, one per provider CortexKit can
  log in to, in a `refresh_adapters/` submodule with
  **per-adapter conformance tests over recorded HTTP fixtures** (never invented
  response strings — the fidelity rule). Adding an adapter is a contract amendment.
- **Crash-safe refresh state machine** (§8, the B2 closure — get this exactly
  right): (1) fsync a `refresh_intent {credential_id, old_refresh_hash, started_at,
  lease_epoch}` BEFORE calling the provider; (2) call, stage in memory; (3) commit
  new tokens + bump `record_version` + clear intent in ONE `synchronous=FULL`
  transaction via `with_conn_fenced` (epoch-fenced); (4) only post-commit is the new
  payload visible to a `get`. **Single-flight per credential_id** (in-process async
  lock — N concurrent gets needing refresh ⇒ exactly ONE upstream call).
- **Startup reconciliation (T1 — safety-critical)**: a pending intent =
  INDETERMINATE ⇒ default `needs_reauth`. Clear it ONLY via a **non-mutating**
  provider validity check (read-only introspection/userinfo that does NOT rotate).
  The old access token still working is NOT sufficient. NEVER call a rotating
  refresh endpoint during recovery. No non-mutating check ⇒ `needs_reauth`, full stop.

### Step 3 — `credentials-module` (the binary): the two surfaces + resilience
- **Read surface** (anonymous, over the route channel — §4): `credential.get
  {handle, min_ttl_ms?, force_refresh?}`, `get_many` (CAPPED ≤ 8 handles/call),
  `credential.status {handle?}` (non-secret health, never bytes),
  `credential.report_auth_failure {handle, provider_status}` (rate-limited
  revocation feedback). READ-ONLY — no write op on this channel.
- **Admin surface** (master-key-gated, OFF the runtime channel — §4 + T2):
  `credential.put` (CREATE-ONLY by default; overwrite needs `expected_payload_hash`
  CAS + raises an audit ALARM), `credential.import {source}`, `credential.invalidate`,
  `credential.rotate_master_key`. An unlocked vault must NOT itself authorize a
  write — require an explicit caller-held master-key PROOF: offline CLI while the
  daemon is stopped, OR a master-key challenge/HMAC against the live vault.
- **Capability handles** (§6, B3): a credential is read by an unguessable ≥128-bit
  random handle minted at import (written into the consumer's 0600 config), NOT by
  its public alias. Per-credential revocable. `get_many` capped. Per-connection
  fetch ceiling + per-credential rate-anomaly ALARM (track `connection_id`).
- **Fault isolation** (§10): NEVER panic on decrypt/parse — a corrupt/undecryptable
  record marks THAT id `corrupt`/`needs_reauth` and is quarantined; the vault keeps
  serving every other credential (per-record quarantine, NOT whole-DB reset). Distinct
  `vault_locked` error code. A decrypt/lock failure is a clean fail-closed error,
  never a panic (no launchd crash-loop).
- **Write-audit hash-chain** (§11): audit every WRITE (import/put/invalidate/rotate)
  with `payload_hash` + `connection_id` in a separate append-only table under the
  lease, each entry carrying `prev_hash` (tamper-evident). ALARM (not just log) on
  overwrite-without-CAS, fetch-rate anomaly, any admin write. Never log secret bytes.

### The ship gate (contract §13) — non-negotiable
A real-daemon e2e harness (build subc-core from the sibling checkout, write a
`subc.jsonc` with your module `reserved: true` + a storage section, spawn the real
daemon, drive the surfaces) AND the **security-conformance suite**: envelope fuzz
(malformed ciphertext never panics), **kill -9 mid-refresh** (between mock-upstream
response and commit ⇒ reconciliation resolves to `needs_reauth`, never a bricked
silent-dead token, never a re-exec), **lease-handover mid-write** (epoch-CAS rejects
the superseded writer), fail-closed matrix (key absent / keychain locked / corrupt
envelope / lease lost ⇒ typed error, never panic, never plaintext), overwrite-CAS
(create-only rejects blind overwrite; CAS mismatch rejected; overwrite raises the
alarm), invalidate-then-get + concurrent import+get visibility, and a
malicious-local-client harness driving the real connection file. **The vault does
not ship until this suite is green.**

## Ground rules

- **The contract is law.** Build to `docs/cortexkit-credentials-contract.md`. If a
  requirement is ambiguous or looks wrong, ASK (peer message to the driving Alfonso)
  before coding around it — especially for the refresh state machine, the surface
  split, master-key handling, and the epoch-CAS write path. These are the pieces
  that get close review.
- **Template = ai-provider-quota** (`../ai-provider-quota`): the 2-crate split, the
  module connect→HELLO→frame-loop→dispatch shape, the real-daemon e2e rig
  (`tests/real_daemon_e2e.rs`), and the manifest shape are all proven there. Mirror
  it; don't reinvent the wire plumbing.
- **Storage = the commons libs.** `open_sqlite(descriptor)` → `migrate(namespace,
  MIGRATIONS)` → `with_conn`/`with_conn_fenced`. The module reads its storage
  descriptor from `HELLO_ACK.storage` (subc delivers it; the daemon config sets a
  `storage` section). `owns_schema: true`. NEVER pull a raw DB driver into the
  module — the lib owns DB mechanics.
- **Green build before every turn boundary.** The codebase must compile (stubs if
  needed) when you end a turn. Never leave it red.
- **Self-contained comments.** No opaque cross-reference tags (`[B2]`, `§8`,
  `finding #13`, `T1`). Explain the rationale inline in plain language; a trailing
  doc pointer is fine only as a secondary reference. Domain vocab (vault, handle,
  refresh intent, lease epoch) is fine.
- **Cross-platform.** Before pushing, cross-check Windows:
  `cargo clippy --workspace --all-targets --target x86_64-pc-windows-gnu` (CI runs
  `-D warnings`; a param used only under `#[cfg(unix)]` is an unused-var error on
  Windows — bind it to `_` under `#[cfg(not(unix))]`). Run `cargo fmt --all` before
  pushing (CI format-checks).
- **CI is Blacksmith** (this is a private repo; the org free-plan blocks
  GitHub-hosted private-repo runners). The workflow uses
  `blacksmith-2vcpu-ubuntu-2404` + `blacksmith-4vcpu-windows-2025` (macOS dropped),
  and checks out BOTH sibling repos (`subconscious`, `commons`) because cargo loads
  the whole workspace manifest before resolving any package. You own your CI loop:
  watch runs, diagnose, fix to green without being told.
- **Commit + push autonomously** (private repo). crates.io/npm publishes and public
  comms stay gated on Ufuk.

## Build order (de-risk incrementally)
1. Confirm the AEAD/envelope design in a short note → land the encryption envelope
   + master-key resolution in `credentials-core` with unit + fuzz tests.
2. Typed `VaultRecord` + canonical `OAuthCredential` + the encrypted store
   (open/migrate/fenced-write) + per-record quarantine on decrypt failure.
3. The crash-safe refresh state machine + startup reconciliation + single-flight +
   ONE bounded refresh adapter (anthropic) with recorded fixtures + the kill-9 and
   lease-handover conformance tests (prove the hardest thing early).
4. The remaining 3 adapters; the module's read surface + capability handles; the
   admin surface + master-key proof + audit hash-chain; fault isolation + status.
5. Real-daemon e2e + the full §13 security-conformance suite = the ship gate.
6. Hand back for review; first consumer (llm-runner) is a later step, driven separately.
