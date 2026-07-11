# Module-Driven Admin Ops — Design Note

Status: AMENDED after Oracle adversarial review (verdict: GO-WITH-CHANGES; all 13
findings resolved below). Transport settled with SUBCONSCIOUS (route-plane Option
A-plus). One item pending the daemon owner: the Gate-1 provenance guarantee (§Gate 1).
Finding 8 (control-lane starvation) was a live bug in shipped code and is already
fixed and regression-tested (commit a1d2904), independent of this design.

## Problem

Every admin write today (`login`, `put`, `import`, `invalidate`, `mint-handle`,
`revoke`, `rotate-master-key`) is offline-CLI-while-module-stopped: the CLI takes the
single-writer lease (its acquisition IS the structural proof the daemon is stopped),
resolves the master key, writes through a fenced transaction, and exits. In prod the
vault is supervised, so any admin op is a drain: stop the module → run the CLI →
restart → bounce the dependent consumer (broca) for the stale-route hazard.

This was a deliberate v1 scope cut (contract §4 "mechanism 2" — the running-vault admin
surface — was explicitly deferred). But the end-state was always module-driven writes,
and the module ALREADY writes while running (refresh rotation commits through the same
fenced path). Ufuk hit the dance restoring `oauth:xai` and called it out: "isn't this
wrong?" It is. Each `needs_reauth` event costs an operator dance the design says
shouldn't exist, and the CK app cannot stop the vault to log a user in.

## What this reverses, and why it is safe now

Reversed: admin writes no longer require the module stopped. The module — which already
holds the lease and is already the live writer — becomes the writer for admin ops too,
authorized by an authenticated admin channel instead of by lease-acquisition.

Safe now because the machinery this needs already exists and is proven:
- The module is already the single live writer (refresh rotation).
- Admin-write and refresh-commit already serialize correctly through the store's single
  `Mutex<Connection>` + `with_conn_fenced` (verified for the `report_auth_failure`
  version-CAS round). Moving admin writes INTO the module makes this an in-process
  contention (two async tasks, one store mutex) — strictly simpler than the current
  cross-process lease model, with no lease handoff.
- `record_version` CAS already resolves the login-replace-during-refresh interleave (a
  replace bumps the version; a concurrent refresh commit's CAS then no-ops or the
  replace re-points and refresh no-ops — both orderings converge safely).

## Non-negotiables preserved

1. **Custody boundary unchanged (memory 7622, locked).** The CLI/app owns the
   INTERACTIVE half (browser, one-shot localhost callback, PKCE, the auth-code dance
   including the code→token exchange) and hands the module the resulting credential. The
   module owns CUSTODY — an authenticated "store this record" op. The module never
   spawns a browser and never runs a redirect listener.
2. **subc never AUTHORIZES a vault mutation.** The master key is the sole admin
   authority root; subc attests process provenance (principal stamps) but a
   hypothetically-compromised daemon must not be able to forge an admin op. (An earlier
   draft also demanded subc never SEE a provider token — that constraint was already
   untrue of the serve path: every `credential.get` response carries the decrypted
   credential through the daemon relay. The same-host trust model bounds
   confidentiality; authorization is the invariant worth holding.)
3. **Single-writer stays.** The module is THE writer. No second writer, no lease
   handoff, zero downtime.
4. **Reserved modules stay locked out of admin authority.** Reads are
   anonymous-capability-handle; `report_auth_failure` is version-gated. A reserved
   consumer (broca) or route consumer must NEVER acquire admin authority. The
   authority boundary is Gate 2 (master-key proof); Gate 1 (principal filter) is a
   provenance pre-filter whose strength depends on the daemon's stamping model (see
   Gate 1 below — honest scoping after Oracle review).
5. **Master key stays the single root of admin authority.** You cannot administer a
   vault without it today (the CLI must resolve it to write); that stays true.

## Transport decision: route-plane admin ops, dual-gated ("Option A-plus")

Admin ops ride the EXISTING route plane — the CLI/app opens the module's
`ManagementSurface` exactly as read consumers do — with two independent gates in front
of every admin op:

- **Gate 1 — principal filter (provenance pre-filter, NOT the authority boundary).**
  subc stamps every relayed `route.bind` with a `Principal`: `reserved:<module_id>`
  (daemon-spawned, spawn-nonce-attested) vs `direct` (a client-key holder). The vault
  records the principal per bind and refuses admin ops on any non-`direct` bind
  (`Reserved`, `Unverified`, and ABSENT all refuse — fail closed).

  ORACLE FINDING (verified at source, subc-core control.rs `route_open_principal`):
  `Direct` is stamped whenever `consumer_identity` is ABSENT — it is proven-key-holder,
  not proven-not-a-module. A supervised module receives the shared connection file/key
  and could open a SECOND client connection omitting its identity, getting stamped
  `Direct`. So under the current daemon model Gate 1 is a COOPERATIVE provenance filter
  (an honest module never reaches admin ops; a compromised one is stopped by Gate 2,
  not Gate 1). Raised with the daemon owner whether direct-stamping can be hardened to
  connection provenance a supervised child cannot imitate; until then the design
  claims only: Gate 2 is the sole ADVERSARIAL authorization boundary, Gate 1 removes
  the accidental/honest-consumer class.
- **Gate 2 — THE authority root: in-band master-key challenge-response.** Contract §4
  "mechanism 2", now un-deferred. `admin.challenge` returns a single-use, short-TTL
  CSPRNG nonce; the caller proves master-key possession by MACing the EXACT operation
  bytes (transcript below). Possession proven; key never transmitted; the op body is
  bound into the MAC so a captured response cannot authorize a DIFFERENT op (no
  splice), and the daemon in the relay path cannot modify the op it carries. Challenge
  and op must ride the SAME bind generation (no cross-route answer, no post-rebind
  reuse).

### The authenticated transcript (exact bytes — Oracle finding 1)

JSON is not canonical, so the MAC covers an EXACT opaque byte string, parsed only
AFTER verification — never reconstructed fields:

```text
K_admin    = HMAC-SHA256(master_key, "cortexkit-credentials/admin-mac-key/v1")
transcript = "cortexkit-credentials/admin-op/v1\0"
             || vault_id[32]          # sha256(canonical data_dir), full width
             || key_id[8]             # the master key fingerprint in use
             || nonce[32]             # the claimed challenge nonce
             || u32_be(len(op_body))
             || op_body               # exact bytes as sent, opaque
tag        = HMAC-SHA256(K_admin, transcript)
```

Rules: `op_body` is the exact byte string the caller sends and MUST contain `v` (op
schema version) and `op` (method discriminator) plus every semantic field; the module
dispatches ONLY from the authenticated `op`, never from any outer envelope. DTOs are
strict (`deny_unknown_fields`, no serde defaults for version/mode/auth fields). The tag
is decoded as exactly 32 bytes and verified with `hmac::Mac::verify_slice`
(constant-time), never a manual compare. Signing/verification lives in
`credentials-core`; `MasterKey::as_bytes` stays private — the core exposes
`admin_mac_key()` derivation, not raw key bytes.

### Nonce lifecycle (atomic claim — Oracle finding 2)

A nonce is CLAIMED atomically (single winner) AFTER constant-time verification succeeds
and BEFORE the op is parsed or executed — verify-then-claim-then-execute. Concurrent
replays of the same valid response race the claim; exactly one wins, the rest are
refused as used. A failed MAC does NOT consume the nonce (an attacker cannot burn a
caller's outstanding challenge by guessing), but each bind holds at most ONE
outstanding nonce (issuing a new challenge replaces it). TTL 30s, monotonic clock.
Nonce state lives inside the bind-generation object (below), so bind teardown or
replacement invalidates outstanding challenges structurally.

### Bind-generation state (Oracle finding 4)

The current bind arm ACKs and discards bind data; route Goodbye can be DROPPED under
daemon backpressure, and route tasks are spawned async — so channel-number-keyed state
is unsafe (a stale task could act on, or answer into, a REBOUND channel). Before
ACKing `route.bind`, the module atomically replaces
`channel → Arc<BindState { generation, principal, nonce_slot, limiter }>`; a duplicate
bind for a live channel REPLACES and invalidates the old generation (lost-Goodbye
self-heal). Request dispatch captures the `Arc` at arrival; a task whose generation is
no longer current has its response suppressed (never delivered into a later consumer's
channel). Principal is immutable per generation.

### Admin admission bounds (Oracle finding 9)

The existing fetch limiter is anomaly-detection (it still serves); admin needs HARD
bounds, non-auditing on the refuse path: one outstanding nonce per bind; ≤128
outstanding nonces globally (never evict another bind's live nonce to make room —
refuse the new challenge); per-bind challenge token bucket; op body ≤ 1 MiB; ≤4
concurrent admin executions. Refusals are cheap wire errors (`class: transient`), not
audit rows — a probe must not be able to bloat the audit chain.

Why this beats the earlier-draft private 0600 unix socket (SUBCONSCIOUS counter-analysis,
accepted):
- The UDS hands the vault an INBOUND listener — inverting the vault's own zero-inbound
  posture on the most sensitive module in the fleet.
- Windows has no UDS-with-0600 semantics (subc removed UDS for exactly this); named-pipe
  ACLs are a different security model we would have to own. We ship Windows CI.
- It forks the transport; modules never roll their own channels under subc.
- It buys nothing: OS-perms-as-auth ≈ same-user trust, which is exactly what `direct` +
  the HMAC already encode with a STRONGER root.
- Confidentiality is unchanged either way: the route plane already carries decrypted
  credentials outbound on every `credential.get`; an inbound token in an admin op is the
  same exposure class under the same-host trust model.

What subc deliberately does NOT provide (and must not): operator-vs-other-direct-client
granularity. Under the same-host trust model every direct client IS the user; subc
attests provenance and never becomes an authorization authority for module-domain
mutations. The HMAC is the authority.

## The module admin surface (provider-agnostic)

The elegance: from the module's side, `login`/`import`/`put` all reduce to "store this
record." Everything provider-specific (browser flow, file parsing, exchange wire) is
CLI-side and produces a fully-formed `VaultRecord`. So the module admin surface is small
and provider-agnostic:

- `admin.challenge {}` → `{ nonce, vault_id, key_id }`. Returning the module's
  non-secret `vault_id` + `key_id` lets the CLI (a) confirm it is talking to the
  intended vault and (b) resolve the SAME key via `resolve_for_db(key_id)` from the
  keychain WITHOUT opening SQLite or touching the lease (Oracle finding 10 — the
  offline opener acquires the lease first, which necessarily fails while the module
  runs; key resolution for the MAC must not go through it).
- `admin.store { v, op, id, record, audit_op, mode, tag }` — mode ∈ {create,
  replace-unconditional, replace-cas(expected_hash)}. Covers login (audit=Login),
  import (audit=Import), put (audit=Put/Overwrite). Commits through the module's held
  lease + fenced txn, audited atomically exactly as the offline path does today.
- `admin.invalidate { v, op, id, tag }` — set `needs_reauth`, clear intent, AND revoke
  all handles for the id, in ONE fenced transaction with its audit entries (Oracle
  finding 7: the offline CLI's invalidate-then-revoke is two calls and crash-partial;
  the online op is the compound action, atomic — compound-by-construction also keeps
  the authorization non-splittable under a reordering daemon, finding 12).
- `admin.mint_handle { v, op, id, tag }` → returns the minted handle.
- `admin.revoke_handle { v, op, handle, tag }`.
- `admin.revoke_all_handles { v, op, id, tag }` (exists offline today; carried over so
  the online surface is not silently weaker).

Each admin op is preceded by its challenge on the same bind generation (one nonce per
op, single-use). Handle/store ops take an `AuditCtx` whose actor is derived from an
authenticated-origin enum ("route-admin" + bind generation) — the store's handle
methods grow audited variants accepting the ctx instead of hard-coding "offline-cli"
(Oracle finding 11): the audit trail must say who actually wrote.

### Concurrency: per-ID serialization, not just the store mutex (Oracle findings 5, 6)

The store's `Mutex<Connection>` serializes individual transactions, NOT the
read-modify-write sequences around them. Verified unsafe interleavings if admin ops
went straight to the store: unconditional-replace reads version N outside its txn and
updates WITHOUT a version predicate (version aliasing with a concurrent refresh);
refresh-commit can resurrect an invalidated credential to active; a stale refresh's
`invalid_grant` error path invalidates unconditionally and can kill a fresh admin
replacement. Resolution, all three layers:
1. Every online ID-scoped admin op acquires the ENGINE's existing per-ID single-flight
   lock (the same lock refresh holds) — admin and refresh for one credential are
   strictly serialized end-to-end, not just per-transaction.
2. `overwrite_unconditional_audited` gains an internal `WHERE record_version = N` guard
   (retry-on-conflict loop) so "unconditional" means state-unconditional, never
   lost-update-tolerant.
3. The engine's `invalid_grant` invalidation becomes version-gated (reuses
   `invalidate_if_version_audited`) so a stale refresh error cannot kill a newer
   record it did not observe.
ADD-2 (finding 6): the engine's fast path returns a non-stale record without the
per-ID lock, so a get CAN serve while a concurrent force-refresh holds an open intent
— acceptable for reads (single-flight governs runtime intents by design) but NOT for
admin writes; the per-ID lock in (1) is what closes it for the writer class. Every
interleaving above ships with a deterministic test.

### CLI fallback semantics (Oracle finding 10)

The offline lease path remains for disaster recovery (module can't boot) and
bootstrap. Fallback is permitted ONLY before the mutation request has been handed to
transport: once an admin op is dispatched and the response is lost, the outcome is
INDETERMINATE (it may have committed) — the CLI reports that honestly and requires
inspection (`list` / `verify-audit`) before any retry; it never auto-falls-back into a
possible double-execution (mint-handle and unconditional-replace are not idempotent).
Module-start vs CLI-lease races are already safe: lease acquisition precedes DB open
on both sides.

### Exchange stays CLI-side (v1)

The CLI does the code→token exchange and hands the module the minted `VaultRecord`
(option A, matching the locked boundary literally). Alternative considered — the module
does the exchange from an auth-code+verifier (option B), so the refresh token is minted
module-side and never transits the channel. B is marginally better for custody but makes
the module admin op provider-aware (it would need the per-provider exchange wire) and is
a larger delta. RECOMMENDATION: A for v1 (smallest delta, provider-agnostic module
surface, literal boundary match); revisit B only if the channel-transits-refresh-token
exposure is judged material (it is bounded by the same-uid socket argument above).

## What stays offline-only

- **rotate-master-key.** Rewraps both key slots + every record; rare; making it
  concurrency-safe against live refresh is a needless hazard. Stop-rotate-restart stays
  the discipline. It keeps the lease-acquisition gate.
- **bootstrap.** Creates the vault before any module supervises it — inherently
  pre-module, stays offline.
- **verify-audit** stays offline, but honestly: it opens via the admin opener, which
  acquires the WRITER lease — so "read-only" still means module-stopped today (Oracle
  finding 13). Fine for a forensics op; not sold as zero-downtime.

So the model splits cleanly: offline-lease-gate for rotate+bootstrap; authenticated
admin channel for login/import/put/invalidate/handles.

## The one-shot localhost callback listener (approved separately) folds in here

Approved envelope: CLI-process-only (never the module), bind 127.0.0.1 one-shot, redirect
STRING unchanged so the provider's exact-match holds, state validated before accepting
the code, paste-back retained as headless fallback. It belongs to the CLI/app interactive
half, orthogonal to who-commits. Per SUBCONSCIOUS's sequencing hint it is built into the
module-driven CLI shape (not the offline shape then moved): module-driven store + local
callback = one-click provider login with zero downtime = the CK-app onboarding flow.

## What the protocol guarantees (precise — Oracle finding 12)

AT-MOST-ONCE ACCEPTANCE OF AN INDIVIDUALLY KEY-AUTHORIZED OPERATION. Nothing stronger.
A compromised daemon can still: drop an op, delay it to near-TTL, reorder separately
authorized ops, or fabricate a RESPONSE (claim success for a dropped op). It cannot
create or alter an operation. Consequences: any action whose parts must not be
reordered/split ships as ONE compound authenticated op (e.g. invalidate+revoke-all);
the CLI treats an unconfirmed response as indeterminate (see fallback semantics), and
response authenticity under a compromised daemon is explicitly NOT claimed — if a
future product need requires trustworthy results over a hostile relay, add response
MACs then.

## Oracle review — disposition

Verdict GO-WITH-CHANGES; all 13 findings incorporated: (1) exact MAC transcript
defined; (2) atomic nonce claim state machine; (3) Gate-1 claim downgraded to
cooperative filter, hardening question routed to daemon owner; (4) bind-generation
state + stale-response suppression; (5) per-ID single-flight for admin ops +
version-guarded unconditional replace + version-gated invalid_grant invalidation;
(6) ADD-2 scoped honestly (reads by single-flight design; writers closed by the per-ID
lock); (7) admin.invalidate is compound invalidate+revoke-all, atomic;
(8) control-lane starvation — FIXED IN SHIPPED CODE already (a1d2904, one route frame
per drain iteration + regression test proven against the old code); (9) hard admin
admission bounds; (10) challenge returns vault_id+key_id for lease-free key
resolution, fallback only-before-dispatch; (11) parameterized AuditCtx for handle
ops; (12) precise at-most-once guarantee wording; (13) verify-audit wording fixed.

## Transport question: RESOLVED with SUBCONSCIOUS

Answered by the transport owner: subc's route plane already stamps daemon-verified
principals (`reserved:<module_id>` vs `direct`) on every relayed bind — this is on the
wire in the protocol version we build against today (`RouteBind.principal:
Option<Principal>`, currently ignored by our bind arm). There is no operator-principal
granularity beyond `direct`, deliberately: subc attests provenance, it does not
authorize module-domain mutations. Their recommendation (route-plane + in-band
master-key proof) is adopted above; the earlier private-socket draft is retired.

## Rollout

1. Design gate: this note → Oracle adversarial review → build.
2. Module: record principal per bind; `admin.challenge` + `admin.store`/`invalidate`/
   handle ops on the read surface, dual-gated; fenced+audited commits exactly as the
   offline path today.
3. CLI: thin front (route backend when module up, offline lease fallback when down).
4. One-shot localhost callback into the CLI login flow (approved envelope; built
   directly into this shape, per the sequencing hint).
5. Then: `login --provider google` (clean next provider), and the antigravity
   project-resolution boundary question (separate design decision).
6. CK app path composes for free: the Swift client is already a direct consumer.
