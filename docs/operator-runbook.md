# Operator runbook — cortexkit-credentials

How an operator provisions the credential vault and wires a consumer to it. The
vault is a subc-supervised daemon plus an offline admin CLI; this is the
end-to-end flow from an empty machine to a consumer reading a credential.

There are two programs:

- **`credentials-module`** — the daemon. subc supervises it; it serves the
  read surface (`credential.get` / `get_many` / `status` / `report_auth_failure`)
  over the route channel. It never writes credentials on the wire.
- **`credentials-cli`** — the offline admin tool. The **only** write surface
  (provision, import, invalidate, rotate, mint/revoke handles, audit). It runs
  **only while the daemon is stopped** (see "The single-writer rule" below).

> All admin commands take `--data-dir <dir>` (the vault's data directory, holding
> `store.db`) and a key source: `--key-path <file>` for an operator-path key, or
> nothing for the macOS keychain default.

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

`--source` is one of `opencode | pi | antigravity`. The provider's token URL and
client id are supplied by the refresh adapter, not the file. The credential `--id`
is the consumer-facing name; the adapter is inferred from its suffix
(`opencode:anthropic` → the `anthropic` refresh adapter).

**Put a static credential** (API key / DSN / opaque):

```sh
credentials-cli put \
  --id operator:my-api-key \
  --payload "sk-..." \
  --kind api_key \
  --data-dir "$DATA_DIR" --key-path /etc/cortexkit/master.key
```

`put` is create-only; an existing id is refused. To replace an existing
credential, pass `--expected-hash <hex>` (a compare-and-set guard).

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

## 5. Verify the audit chain

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
