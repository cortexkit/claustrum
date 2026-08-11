# Operator runbook — claustrum (the credential vault)

How an operator provisions the credential vault and wires a consumer to it. The
vault is a subc-supervised daemon plus an admin CLI; this is the end-to-end flow
from an empty machine to a consumer reading a credential.

There are two programs:

- **`ck-claustrum`** — the daemon. subc supervises it; it serves the
  read surface (`credential.get` / `get_many` / `status` / `report_auth_failure`)
  over the route channel, and the authenticated admin surface described below.
  (Built from the `credentials-module` crate; the module id remains
  `claustrum`.)
- **`ck-auth`** — the admin tool, invoked as `ck auth <verb>`. The **only** write
  surface (login, import, invalidate, rotate, mint/revoke handles, audit). Most
  verbs commit through the **running** daemon with no downtime; a few are
  offline-only (see "The single-writer rule" below).

> On a standard install, admin commands need **no flags at all** — both the vault
> data directory and the running daemon's connection file are auto-discovered.
> The flags below matter only for a non-default location (a test vault, a second
> vault on the same machine, or a key held outside the keychain).
>
> All admin commands accept `--data-dir <dir>` (the vault's data directory, holding
> `store.db`) and a key source: `--key-path <file>` for an operator-path key, or
> nothing for the macOS keychain default.
>
> **`--data-dir` must be `<data_home>/cortexkit/<module_id>`**, where `<module_id>`
> is the subc.jsonc module key — **`claustrum`**, NOT a shortened
> `credentials`. The supervised daemon derives its store path from the module id
> verbatim, so the CLI must use the same full id or it opens a *different*
> (empty) vault under a different keychain scope. On a default desktop:
>
> ```sh
> DATA_DIR=~/.local/share/cortexkit/claustrum
> ```

---

## The single-writer rule (read this first)

There is exactly one writer at a time, always. What changes is **who** it is.

When the daemon is running it holds the vault's single-writer lease, so the CLI
cannot open the store directly. Instead the CLI sends the operation **to** the
daemon over the route plane, and the daemon — the lease holder — performs the
write, serialized against any in-flight token refresh. This is the normal path and
it needs no downtime: re-logging in a provider while agents are actively reading
credentials is safe and expected.

The daemon does not take the operator's word for it. Each op is authenticated by a
challenge-response MAC over the exact operation bytes, keyed by the **master key** —
so the caller proves possession of the key that the vault's contents are sealed
under, per operation, with a single-use nonce. A compromised daemon cannot
authorize a mutation it was not given, and a caller without the master key cannot
mutate anything.

When the daemon is **not** running, the CLI takes the lease itself and writes
directly. Same operations, same audit chain, same master-key requirement.

**Offline-only verbs.** Four commands always require the daemon stopped, because
they operate on the store as a whole rather than on one credential:

| verb | why it is offline-only |
|------|------------------------|
| `bootstrap` | creates the vault; there is no daemon yet |
| `rotate-master-key` | re-wraps every record and the sealed audit key in one transaction |
| `audit` / `verify-audit` | reads the whole chain under the lease |

Run these with the daemon stopped. Every other write verb — `login`, `logout`,
`remove`, `put`, `import`, `invalidate`, `mint-handle`, `revoke-handle`,
`revoke-all-handles` — commits through the running daemon, and falls back to the
offline lease path automatically when no daemon is reachable.

Exit codes:

| code | meaning | what to do |
|-----:|---------|------------|
| 0 | success | — |
| 3 | the daemon holds the lease and this verb is offline-only | stop the daemon, retry |
| 4 | master key could not be resolved (locked keychain / absent / wrong) | unlock the keychain, or check `--key-path` |
| 5 | **indeterminate** — the op reached the daemon but the reply was lost | see below |
| 1 | usage / IO / other error | read the message |

**Exit code 5 is the one that needs care.** It means the operation was sent to the
running daemon and the connection dropped before the outcome came back, so it may
or may not have committed. Do **not** blindly retry — check first with `ck auth
list` (did the credential's version change?) or `ck auth audit` (is there an entry
for it?), then act on what you find.

The other two outcomes are unambiguous by construction. A **refusal** from a live
daemon is terminal and safe — the daemon was alive and said no, so nothing was
written and the CLI never falls back. **No reachable daemon** means nothing was
dispatched at all, which is why falling back to the offline path cannot
double-execute.

---

## 1. Bootstrap the master key (once per machine)

The master key encrypts every credential at rest. Provision it once. It is created
once and never regenerated; a second bootstrap is refused rather than clobbering
the existing key (which would brick the vault).

**Keychain (desktop default, macOS):**

```sh
ck auth bootstrap --data-dir "$DATA_DIR"
```

**Operator-path (headless / server):** the key file **must live outside the data
directory** (co-locating the key with the ciphertext defeats at-rest encryption);
the CLI refuses a key path inside `--data-dir`.

```sh
ck auth bootstrap --data-dir "$DATA_DIR" --key-path /etc/cortexkit/master.key
```

`$DATA_DIR` is the vault's data directory. Under subc supervision the daemon
resolves it to `<data_home>/cortexkit/claustrum/` — the admin CLI must
point `--data-dir` at that **same** directory so both operate on one vault.

---

## 2. Import or put a credential

**Import an existing OAuth login** (e.g. an opencode `auth.json` entry — the shared
`{ refresh, access, expires }` shape):

```sh
ck auth import \
  --source opencode \
  --provider anthropic \
  --id oauth:anthropic \
  --json /path/to/auth.json
```

`--source` is one of `opencode | pi | gemini-cli | antigravity`. The provider's
token URL and client id are supplied by the refresh adapter, not the file.

**The credential `--id` is `<method>:<provider>[:<account>]`** (e.g. `oauth:anthropic`,
`apikey:deepseek`, `antigravity:google`). The `<method>` selects the credential kind
and the refresh adapter the record stores — `oauth`→the provider-named adapter,
`antigravity`→the `antigravity` adapter, `apikey`→a static key (no adapter). It is
NOT derived from the id by position (no positional rule is uniform — `oauth:anthropic`
wants the provider segment, `antigravity:google` the method segment); pass
`--adapter <name>` to override the method default. A legacy `<provider>[:<account>]`
id (first segment not a known method) defaults to the provider's oauth adapter.

Source-specific notes:

- **API keys:** an `apikey:<provider>` id imports a `{ "type": "api", "key": "..." }`
  entry as a static key. The real `auth.json` is a map keyed by provider, so
  `--provider <key>` selects the entry (`--source opencode --provider deepseek
  --id apikey:deepseek`). `credential.get` returns the key bytes verbatim.
- **OAuth (auth.json):** `--provider <key>` selects one provider's
  `{ refresh, access, expires }` entry from the map. Without it, `--json` must point
  at a single provider's object.
- **Google must be imported from `gemini-cli` or `antigravity`, not opencode.** A
  Google refresh token only refreshes against the OAuth client that minted it.
  `--source gemini-cli` reads `~/.gemini/oauth_creds.json` (the gemini-cli Code-Assist
  login, single credential, no `--provider`). `--source antigravity` reads
  `~/.config/opencode/antigravity-accounts.json` (the antigravity plugin's accounts
  array; `--provider` selects an account by email or index, default the active one)
  and is the source for an `antigravity:google` id. An opencode-minted google token
  cannot be refreshed by either and fails closed to `needs_reauth`.
- `--replace` overwrites an existing id unconditionally (re-seal at version+1,
  reset to active), for fixing a credential imported from the wrong source. Existing
  handles keep resolving to the id — **no re-mint needed**. Without `--replace`,
  `import` is create-only and an existing id is refused.

**Put a static credential** (API key / DSN / opaque). Use `--payload-file <path>`
for a secret so it never appears in the process list or shell history; `--payload
<value>` passes the exact bytes inline. A bare key file (e.g. `~/.config/openai.key`)
is read with trailing whitespace stripped:

```sh
ck auth put \
  --id apikey:openai \
  --payload-file ~/.config/openai.key \
  --kind api_key
```

`put` is create-only; an existing id is refused. To rotate a static key in place,
pass `--replace` (unconditional, keeps existing handles) or `--expected-hash <hex>`
(a compare-and-set guard, for when you know the current value).

**Vault-native login — the preferred path, and the one to reach for first.** Import
exists for bootstrapping from another tool's files; `login` mints a NEW, independent
credential that the vault solely custodies, so there is no dual-custody rotation race
with a tool that holds the same provider login.

Run it with no flags at all for an interactive picker over every provider, showing
which already have a credential:

```sh
ck auth login
```

The picker covers OAuth (`anthropic`, `openai`, `xai`, `google`, `antigravity`),
device-flow (`github-copilot`, `kimi`, and `--device` for openai/xai), custom
browser flows (`cursor`, `devin`, `snowflake`, `digitalocean`), and API-key
providers (`zai`, `openrouter`, `deepseek`, `groq`, …), which are validated against
the provider before being stored.

OAuth logins open a browser and complete automatically: a one-shot CLI-local
listener on the loopback redirect captures the code, so **when the browser shows a
paste code, ignore it — the CLI has already finished.** If the port is busy, the
listen fails, or you pass `--no-listener`, the flow falls back to pasting the
address-bar URL. Pasted values are read from stdin only — never argv, never logged.

```sh
ck auth login --provider xai --replace
```

**Multiple accounts per provider** each get their own labeled id, with an
independent refresh chain and its own handles:

```sh
ck auth login --provider anthropic --id oauth:anthropic:work
```

Default ids are `oauth:anthropic`, `chatgpt:openai`, `oauth:xai` (note: a bare
`--provider openai` means the ChatGPT subscription login, not `apikey:openai`).
`--replace` swaps the credential on an existing id and **keeps its handles** — the
usual recovery for a `needs_reauth` credential, and the reason a re-login never
requires re-distributing handles. Without it, `login` is create-only. A native login
records a distinct `Login` audit entry (not `Import`).

---

## 3. Mint a handle and give it to the consumer

A consumer never names a credential directly; it presents a **capability handle**.
Mint one per consumer:

```sh
ck auth mint-handle --id oauth:anthropic
```

The command prints the raw handle (`ckh_...`) to **stdout exactly once** — only its
hash is stored, so it cannot be recovered later. Write it into the consumer's
config (a `0600` file). To rotate a consumer's access, `revoke-handle --handle
<ckh_...>` (or `revoke-all-handles --id <id>`) and mint a fresh one — no re-login.

Mint a **separate handle per consumer** rather than sharing one. Handles are the
revocation unit: with one each, cutting off a single consumer is one `revoke-handle`
and nobody else notices. Handles also survive `login --replace`, so re-authenticating
a provider never means re-distributing them.

---

## 4. Start the daemon; the consumer reads over the route channel

subc supervises the daemon from its `subc.jsonc` (the vault module marked
`reserved: true`, with a `sqlite` storage section). Once it is up, a consumer reads
a credential over the route channel:

```
catalog.list
  → route.open(ManagementSurface, module_id = "claustrum")
  → credential.get { handle: "ckh_..." }   // returns the opaque payload
```

The daemon resolves the handle, refreshes the token if stale (vault-owned OAuth
refresh, single-flight), and returns the credential payload. An unknown or revoked
handle is a uniform `not_found` (no enumeration).

A consumer that observes a 401/403 should call `credential.report_auth_failure
{ handle, provider_status, record_version }` so the vault marks the credential
`needs_reauth` rather than serving a dead token. **`record_version` is required and
is the version the consumer was served.** If the vault has since refreshed to a newer
version, the report is a silent no-op — which is what stops a stale 401 from
invalidating a credential that has already been repaired.

---

## 5. See what the vault holds, and what needs action

```sh
ck auth status   # health ladder + inventory
ck auth list     # one row per credential: <state> v<version> <credential_id>
```

Neither prints a secret. Both read the running daemon when one is up and fall back
to the store directly when it is not.

`status` is the one to run when something is wrong. It reports the same health the
supervisor probes:

| status | meaning | what to do |
|--------|---------|------------|
| `ok` | store readable, lease held, every credential active | — |
| `degraded` | serving, but ≥1 credential is `needs_reauth` or `corrupt` | re-login the named credential |
| `failing` | the store is unreadable, **or** this daemon lost write authority to a newer instance, **or** its background health refresher has stalled | check disk and lease; a stalled refresher means restart the module |

**A degraded vault is still serving every healthy credential** — it names the broken
ones rather than failing whole, which is why a single dead credential never takes the
vault down.

To repair a flagged credential, re-login it and keep its handles:

```sh
ck auth login --provider <name> --replace
```

Two verbs express intent that `--replace` does not:

- **`logout`** — stop serving a credential, reversibly. It marks the credential
  `needs_reauth` and revokes every handle in one atomic operation, keeping the record
  and its audit history. A later `login --replace` restores it, though consumers need
  freshly minted handles since the old ones are gone.
- **`remove`** — permanently delete the credential, its refresh intent and its
  handles. Audited, but not undoable.

## 6. Verify the audit chain

Every durable mutation is recorded in a tamper-evident, HMAC-keyed audit chain.
Both verbs are offline-only — stop the daemon first:

```sh
ck auth verify-audit
ck auth audit
```

`verify-audit` reports the chain intact or names the first broken entry.
`audit` lists the entries (seq, op, credential, actor, and any alarm). An alarm row
(e.g. `fetch_rate_anomaly`) is a durable detection signal surfaced here on demand,
not a live notification.

### Reading the chain directly

The verbs above need the daemon stopped. To inspect a **running** vault — or to answer
"did that write actually commit?" from outside — read the store read-only. This takes no
lease and cannot disturb the daemon:

```sh
DB="$HOME/.local/share/cortexkit/claustrum/store.db"

# Recent events. `actor` distinguishes who caused them: `vault` is the refresh engine
# acting on its own, `route-admin` an operator through the running daemon, `offline-cli`
# an operator holding the lease directly.
#
# `conn-<N>` is NOT a consumer identity. N is the route channel number, assigned to a
# route binding and reused as bindings come and go: two rows sharing `conn-1` are not
# evidence of the same reporter, and one reporter across reconnects may appear under
# several numbers. The read surface is anonymous by design -- a capability handle
# authorizes a read without identifying who presented it -- so the vault has no caller
# identity to record. For a CONSUMER-REPORTED invalidation (op `report_auth_failure`)
# the chain gives you the credential and the instant, never the reporter; correlate
# that timestamp against sources outside this record, such as consumer or route-layer
# logs. Operator and vault-owned actions are attributable as usual.
sqlite3 "file:$DB?mode=ro" "SELECT seq, op, credential_id, actor,
  datetime(ts_ms/1000,'unixepoch','localtime') FROM audit_log ORDER BY seq DESC LIMIT 20;"

# When each credential last completed a real provider token exchange.
sqlite3 "file:$DB?mode=ro" "SELECT credential_id, MAX(datetime(ts_ms/1000,'unixepoch','localtime'))
  FROM audit_log WHERE op='refresh_commit' GROUP BY credential_id;"

# Write authority: the store's fence epoch against the daemon's lease.
sqlite3 "file:$DB?mode=ro" "SELECT epoch FROM cortexkit_fence WHERE id = 0;"
cat "$HOME/.local/share/cortexkit/claustrum"/*.lease
```

Three things that make these read wrong:

- **Use `mode=ro`, never `immutable=1`.** An immutable open tells SQLite the file cannot
  change, so it skips the write-ahead log — on a live vault that silently returns a
  pre-WAL snapshot, answering confidently about the past. `immutable=1` is for a store
  nobody is writing, such as a copy kept as a rollback target.

  **A `store.db` with no `store.db-wal` beside it is the dangerous case, and the
  danger is that it usually does NOT announce itself.** A WAL database keeps recent
  commits in the `-wal`; the main file alone holds only what was checkpointed. What
  happens when you open one depends entirely on which SQLite you are holding —
  measured here on one identical file:

  ```
  system sqlite3 (Apple 3.51.0)   Error: unable to open database file (14)
  the daemon's build (3.46.0)     opens, answers from pre-WAL state, integrity ok
  ```

  So the error-14 refusal is a property of the tool, not of the file. **Through the
  daemon's own build the same store opens without complaint and silently under-reports
  — in a probe here, a live copy taken with 50 rows committed answered as though the
  table did not exist.** It is missing data, it says nothing, and `PRAGMA
  integrity_check` returns `ok`, because the file it has is internally consistent.

  **`-wal` is the load-bearing companion; `-shm` is a rebuildable index over it.**
  Measured: `main+wal+shm` and `main+wal` both read correctly; `main+shm` and `main`
  alone both read stale.

  ```
  ls store.db-wal          # the check that matters, before opening anything
  ```

  **What a companion-less main file contains is exactly what had been CHECKPOINTED,
  and nothing else.** That is the whole rule, and every case follows from it:

  ```
  closed cleanly          everything was checkpointed      complete
  copied mid-write        nothing was checkpointed         reads as empty
  copied mid-write        a checkpoint had partly run      AN ARBITRARY PREFIX
  ```

  **The third is the dangerous one, because it is the only outcome that looks like a
  working database.** It opens, it answers, `integrity_check` says `ok`, and it is
  short by an amount nothing on the file can tell you — a probe here produced one row
  of fifty. Checkpoint timing leaves no trace in the file, so **completeness is not
  merely hard to infer from a store, it is absent from it.** The audit chain is not a
  fallback for answering this: `MAX(seq)` against what the vault should have is the
  only source that exists.

  **If you are copying a store, copy the directory, never the file.** The main file on
  its own is a partial artefact whose losses are silent.
- **`mode=ro` is also what makes the read INERT, and dropping it is not harmless just
  because the SQL is a `SELECT`.** SQLite checkpoints on close when the closing connection
  is the last one attached to the database, and that is a property of the CONNECTION, not
  of the statements run through it. Measured both ways on this platform, same database,
  same query, only the open mode differing: a read-write last closer truncated the WAL and
  removed it; a read-only last closer left it byte-for-byte intact. So a plain
  `sqlite3 store.db "SELECT ..."` against a **stopped** vault rewrites the main database
  file and deletes the WAL — an operator looking for evidence, modifying the evidence.
  Nothing is corrupted and nothing warns, which is exactly why it is worth a line here:
  the next reader sees a store whose file timestamps and WAL state were changed by the
  investigation. Against a *running* vault the daemon holds a connection, so a stray
  read-write visitor is not the last closer and this does not fire — meaning the dangerous
  case is the careful one, where the operator stopped the daemon first.
- **The table is `audit_log`, and its timestamp column is `ts_ms`.** A misspelled table
  errors, but a wrong *column* in a `WHERE` clause returns zero rows — indistinguishable
  from "nothing happened". Check the schema before believing an empty result.
- **The audit chain answers "what happened"; the fence epoch only answers "what is true
  now".** The fence row is rewritten only when a writer's epoch *exceeds* it, so an
  unchanged row is equally consistent with a rejected write and with a healthy writer that
  had nothing to claim. To ask whether a write committed, read the chain.

One honest limit: the chain is **tamper-evident, not truncation-proof**. No interior
edit, reorder or insertion survives verification without the audit key — but an
attacker with write access to the database file can delete a suffix of recent
entries, and the surviving prefix still verifies. Detecting that needs an external
monotonic anchor (periodically recording the tip `(last_seq, entry_mac)` off-box),
which is out of scope for the in-database chain.

---

## Rotating the master key

`ck auth rotate-master-key` performs a crash-safe two-slot handover: it stages a new
key, re-wraps every record and the sealed audit key under it in one atomic
transaction, then promotes the new key. A crash at any point reopens cleanly under
whichever key matches the database — the vault never bricks, including when a
previous rotation was itself interrupted (a staged-but-unpromoted rotation is healed
before a new one is staged). Offline-only: stop the daemon first.

---

## Deploying a new vault binary

The daemon and CLI are installed at `~/.local/share/cortexkit/bin/`, with `ck-auth`
also symlinked into `~/.local/bin/` for the `ck` dispatcher.

### Before building a release: the full gate

`cargo test --workspace` is **not** the gate. It silently skips the two suites that
cover the properties a credential vault exists to guarantee — the real-daemon
end-to-end tests are `#[ignore]` by default, and the crash-safety proofs sit behind
feature flags. Run all four:

```sh
cargo test --workspace
CRED_REQUIRE_DAEMON=1 cargo test -p credentials-module --test real_daemon_e2e -- --ignored
cargo test -p credentials-core --features kill9-test-seam  --test kill9_mid_refresh
cargo test -p credentials-core --features rotate-test-seam --test rotate_crash_cut
cargo test -p credentials-core --features login-test-seam  --test login_crash_cut
```

`CRED_REQUIRE_DAEMON=1` is an anti-masking switch: without it, the end-to-end suite
is allowed to skip when it cannot build or reach the sibling `ck-subc`, which reads
as a pass. With it, an unreachable daemon is a failure.

**Read the counts, not the word `ok`.** Each of these lines is a passing run that
proved nothing:

```
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 4 filtered out
```

`0 passed` with a non-zero `filtered out` means the filter excluded everything —
usually a mistyped target name, or `--ignored` applied to tests that are not marked
ignored (that flag runs **only** ignored tests, so adding it to a normal suite runs
nothing). Expected counts at the time of writing: 7 end-to-end, 1 kill9, 4 rotate,
2 login. If a number drops, find out why before shipping; a suite that shrank is
indistinguishable from one that passed.

**Read the listing, not only the totals** — a test can leave the suite without the
total falling. A `#[test]` attribute binds to whatever function follows it, so
inserting a new test between an existing attribute and its function hands the
attribute to the newcomer and silently unregisters the original. Both counts stay
plausible (one test replaces another) and nothing fails. Measured here: a run
reported nine tests with one name printed twice and another absent, all green.

The cheap check is that every name appears exactly once, which the per-test lines
already show. To verify a whole target, compare the attributes against what the
runner registers:

```sh
grep -cE '^#\[(tokio::)?test(\(.*\))?\]' crates/credentials-module/tests/cli_admin.rs
cargo test -p credentials-module --test cli_admin -- --list | grep -c ': test'
```

Match the attribute pattern loosely: `#[tokio::test(flavor = "multi_thread")]` is a
test and an exact-string search for `#[tokio::test]` misses it, which reports a
mismatch in the file rather than in the search.

**Sign with a pinned identifier at build time, then place with a plain copy:**

```sh
codesign --force --sign - --identifier ck-claustrum   target/release/ck-claustrum
codesign --force --sign - --identifier ck-auth        target/release/ck-auth
```

This is not cosmetic. macOS's default ad-hoc identifier embeds the binary's
link-time UUID, so it **changes on every build** — and because macOS binds privacy
grants to that identifier and attributes them to the responsible process (the
supervisor), every unpinned release silently revokes those grants with no prompt and
no error. Pinning also makes the published hash equal the placed hash, so a plain
`shasum` comparison is a valid deployment check.

**Acceptance, after restarting the module.** Each leg must be able to fail:

| check | why it discriminates |
|-------|----------------------|
| deployed hash equals the **new** build's hash, and differs from the **old** one | publish both values — comparing the system to itself passes trivially |
| running process's image inode equals the deploy path's inode | proves the process is not still executing an unlinked predecessor |
| `ck auth status` reports every credential serving | a daemon whose master key was unavailable at boot is alive and serving nothing |
| mint a throwaway handle, then revoke it | exercises the fenced write path and its atomic audit append |

The last two are the ones that matter. A restarted daemon can be running, answering,
and serving nothing — so the acceptance assertion is **"N/N serving"**, never "the
process is up". And a read-only check cannot prove the vault can still write; the
mint/revoke pair can.

If a hash comparison fails after someone re-signed the binary, re-sign a **copy** of
the known build with the known identifier and compare that — a legitimate re-sign and
a substituted binary are otherwise indistinguishable. `dwarfdump --uuid` (invariant
under signing) and a signature-stripped `shasum` also settle it.
