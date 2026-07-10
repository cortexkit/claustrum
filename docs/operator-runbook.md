# Operator runbook — cortexkit-credentials

How an operator provisions the credential vault and wires a consumer to it. The
vault is a subc-supervised daemon plus an offline admin CLI; this is the
end-to-end flow from an empty machine to a consumer reading a credential.

There are two programs:

- **`ck-credentials`** — the daemon. subc supervises it; it serves the
  read surface (`credential.get` / `get_many` / `status` / `report_auth_failure`)
  over the route channel. It never writes credentials on the wire. (Built from the
  `credentials-module` crate; the module id remains `cortexkit-credentials`.)
- **`credentials-cli`** — the offline admin tool. The **only** write surface
  (provision, import, invalidate, rotate, mint/revoke handles, audit). It runs
  **only while the daemon is stopped** (see "The single-writer rule" below).

> All admin commands take `--data-dir <dir>` (the vault's data directory, holding
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

Every admin write goes through the vault's single-writer lease. **The daemon holds
that lease while it runs.** So an admin command run while the daemon is up is
refused with **exit code 3** ("daemon running") — stop the daemon first. This is
structural, not advisory: the CLI and daemon contend for the same OS lease, so
there is no way for an admin write to slip in alongside a live daemon.

Exit codes:

| code | meaning | what to do |
|-----:|---------|------------|
| 0 | success | — |
| 3 | the daemon is running (holds the lease) | stop the daemon, retry |
| 4 | master key could not be resolved (locked keychain / absent / wrong) | unlock the keychain, or check `--key-path` |
| 1 | usage / IO / other error | read the message |

---

## 1. Bootstrap the master key (once per machine)

The master key encrypts every credential at rest. Provision it once. It is created
once and never regenerated; a second bootstrap is refused rather than clobbering
the existing key (which would brick the vault).

**Keychain (desktop default, macOS):**

```sh
credentials-cli bootstrap --data-dir "$DATA_DIR"
```

**Operator-path (headless / server):** the key file **must live outside the data
directory** (co-locating the key with the ciphertext defeats at-rest encryption);
the CLI refuses a key path inside `--data-dir`.

```sh
credentials-cli bootstrap --data-dir "$DATA_DIR" --key-path /etc/cortexkit/master.key
```

`$DATA_DIR` is the vault's data directory. Under subc supervision the daemon
resolves it to `<data_home>/cortexkit/cortexkit-credentials/` — the admin CLI must
point `--data-dir` at that **same** directory so both operate on one vault.

---

## 2. Import or put a credential

**Import an existing OAuth login** (e.g. an opencode `auth.json` entry — the shared
`{ refresh, access, expires }` shape):

```sh
credentials-cli import \
  --source opencode \
  --id opencode:anthropic \
  --json /path/to/auth.json \
  --data-dir "$DATA_DIR" --key-path /etc/cortexkit/master.key
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
credentials-cli put \
  --id apikey:openai \
  --payload-file ~/.config/openai.key \
  --kind api_key \
  --data-dir "$DATA_DIR" --key-path /etc/cortexkit/master.key
```

`put` is create-only; an existing id is refused. To replace an existing
credential, pass `--expected-hash <hex>` (a compare-and-set guard).

**Vault-native OAuth login** (preferred over import for the providers that support
it). `login --provider <anthropic|openai|xai>` mints a NEW, independent refresh token
that the vault solely custodies — so there is no dual-custody rotation race with
another tool that also holds the same login. It drives an interactive
authorization-code + PKCE flow: the CLI prints (and opens) an authorize URL, you
approve in the browser, and paste the result back. There is no inbound listener — for
`openai`/`xai` the browser lands on a connection-refused page and you copy the full
URL from the address bar; for `anthropic` you copy the displayed `code#state`.

```sh
credentials-cli login \
  --provider xai \
  --replace \
  --data-dir "$DATA_DIR" --key-path /etc/cortexkit/master.key
```

The default id is `oauth:anthropic` / `chatgpt:openai` / `oauth:xai` (override with
`--id`). `--replace` swaps the token on an existing id and keeps the handle (the usual
recovery for a `needs_reauth` credential); without it, `login` is create-only. The
pasted code is read from stdin only — never argv, never logged. A native login records
a distinct `Login` audit entry (not `Import`).

---

## 3. Mint a handle and give it to the consumer

A consumer never names a credential directly; it presents a **capability handle**.
Mint one per consumer:

```sh
credentials-cli mint-handle \
  --id opencode:anthropic \
  --data-dir "$DATA_DIR" --key-path /etc/cortexkit/master.key
```

The command prints the raw handle (`ckh_...`) to **stdout exactly once** — only its
hash is stored, so it cannot be recovered later. Write it into the consumer's
config (a `0600` file). To rotate a consumer's access, `revoke-handle --handle
<ckh_...>` (or `revoke-all-handles --id <id>`) and mint a fresh one — no re-login.

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
handle is a uniform `not_found` (no enumeration). A consumer that observes a 401/403
should call `credential.report_auth_failure { handle, provider_status }` so the
vault marks the credential `needs_reauth` rather than serving a dead token.

---

## 5. List credentials (which one needs action?)

To see what the vault holds without decrypting anything (daemon stopped):

```sh
credentials-cli list --data-dir "$DATA_DIR" --key-path /etc/cortexkit/master.key
```

Each row is `<state> v<version> <credential_id>` — no secrets. Use it to find
which credential a health probe flagged: if the daemon's health report says a
credential is `needs_reauth`, `list` (or the health metrics' `needsReauthIds`)
names it, and you re-import it with `import ... --replace` (§2).

## 6. Verify the audit chain

Every durable mutation is recorded in a tamper-evident, HMAC-keyed audit chain.
Check it (daemon stopped):

```sh
credentials-cli verify-audit --data-dir "$DATA_DIR" --key-path /etc/cortexkit/master.key
credentials-cli audit        --data-dir "$DATA_DIR" --key-path /etc/cortexkit/master.key
```

`verify-audit` reports the chain intact or names the first broken entry.
`audit` lists the entries (seq, op, credential, actor, and any alarm). An alarm row
(e.g. `fetch_rate_anomaly`) is a durable detection signal surfaced here on demand,
not a live notification.

---

## Rotating the master key

`credentials-cli rotate-master-key` performs a crash-safe two-slot handover: it
stages a new key, re-wraps every record and the sealed audit key under it in one
atomic transaction, then promotes the new key. A crash at any point reopens cleanly
under whichever key matches the database — the vault never bricks. Run it with the
daemon stopped, like any admin write.
