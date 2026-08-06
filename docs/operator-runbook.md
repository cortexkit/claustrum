# Operator runbook — cortexkit-credentials

How an operator provisions the credential vault and wires a consumer to it. The
vault is a subc-supervised daemon plus an admin CLI; this is the end-to-end flow
from an empty machine to a consumer reading a credential.

There are two programs:

- **`ck-credentials`** — the daemon. subc supervises it; it serves the
  read surface (`credential.get` / `get_many` / `status` / `report_auth_failure`)
  over the route channel, and the authenticated admin surface described below.
  (Built from the `credentials-module` crate; the module id remains
  `cortexkit-credentials`.)
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
> is the subc.jsonc module key — **`cortexkit-credentials`**, NOT a shortened
> `credentials`. The supervised daemon derives its store path from the module id
> verbatim, so the CLI must use the same full id or it opens a *different*
> (empty) vault under a different keychain scope. On a default desktop:
>
> ```sh
> DATA_DIR=~/.local/share/cortexkit/cortexkit-credentials
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
resolves it to `<data_home>/cortexkit/cortexkit-credentials/` — the admin CLI must
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
  → route.open(ManagementSurface, module_id = "cortexkit-credentials")
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

**Sign with a pinned identifier at build time, then place with a plain copy:**

```sh
codesign --force --sign - --identifier ck-credentials target/release/ck-credentials
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
