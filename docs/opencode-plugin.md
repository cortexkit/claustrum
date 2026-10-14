# OpenCode plugin

`@cortexkit/opencode-claustrum` (`packages/opencode`) serves OpenCode provider slots from the
vault instead of from OpenCode's `auth.json`, on a stock OpenCode build, through the
documented plugin API only.

**Status: parked.** The plugin works as described here, but it is parked pending a redesign
into a shared custody library. Do not treat it as the supported path for a new provider or a
new consumer; ask before building on it.

The package README covers its configuration and environment variables:
[`packages/opencode/README.md`](../packages/opencode/README.md).

## 1. How it works

The plugin is an in-process auth proxy on OpenCode's `fetch` seam. OpenCode's SDK builds every
request believing the credential is a sentinel; the plugin intercepts each outbound request for
a provider it owns, exchanges the sentinel for live material from the vault at that moment,
forwards the request, and observes the response. The vault performs every refresh and every
latch; the plugin only asks for current material and reports what it saw. The plugin knows
nothing about providers: it acts on the **shape** of an `auth.json` entry (`api` or `oauth`)
and on a handle file the CLI writes.

Registration uses OpenCode's `config` hook, which injects `options = { apiKey: SENTINEL(p),
fetch }` for each owned provider. Config provider options are re-applied after every
`auth.loader` has run, so an injected `fetch` replaces a shipped plugin's loader-set `fetch`.
That makes a provider reachable only when its live credential path is the generic AI SDK fetch
seam. Provider-specific loaders, model discovery, environment credentials and native runtime
paths can bypass it, so reachability is never inferred for a provider without a per-provider
proof.

## 2. Ownership: tombstone plus handle file

Two independent signals decide every slot, and no slot is served on one of them alone:

- **The tombstone** in `auth.json` is the sole source of truth that no local credential exists.
- **The handle file** (`opencode-handles.json`) is the sole source of truth for which plugin
  owns the provider, through its `serve` field.

A tombstone carries a non-secret, versioned, provider-bound sentinel,
`claustrum-tombstone:v1:<provider>`:

```json
"deepseek":  { "type": "api",   "key": "claustrum-tombstone:v1:deepseek" }
"anthropic": { "type": "oauth", "access":  "claustrum-tombstone:v1:anthropic",
                                 "refresh": "claustrum-tombstone:v1:anthropic",
                                 "expires": 0 }
```

For `oauth`, `refresh` is the sentinel and non-empty (OpenCode drops entries with a missing
refresh, and then no loader runs), and `expires: 0` makes any reader that forgets its guard
take the refresh path, where the owning plugin's guard lives. `isTombstone(entry, provider)` is
an exact match on `type` and every sentinel-bearing field, so a sentinel copied onto another
provider fails it. `packages/opencode/golden/tombstone.json` holds the canonical instance of
every shape; the Rust CLI includes it with `include_str!` and the plugin imports it.

The handle file is an ordered list (array position is priority order) with `serve` required on
every provider block:

```json
{ "version": 1,
  "providers": [
    { "provider": "deepseek",  "shape": "api",   "serve": "opencode-claustrum",
      "accounts": [ { "label": "main", "handle": "ckh_…", "credential_id": "apikey:deepseek:main" },
                    { "label": "alt",  "handle": "ckh_…", "credential_id": "apikey:deepseek:alt" } ] } ] }
```

An account may carry `superseded: ["ckh_…"]`: old handles awaiting revocation during a
`--replace`, written before the tombstone step and cleared after revocation, so a crash in
between leaves them recoverable. Readers must ignore the field and never serve a superseded
handle.

The decision table, evaluated once per OpenCode start:

| `auth.json` entry | handle file `serve` | action |
|---|---|---|
| tombstone | `opencode-claustrum` | inject the sentinel and the vault-backed `fetch` |
| tombstone | absent, or unreadable handle file | `CustodyOrphan`: log, inject a refusing `fetch` |
| tombstone | another owner | not ours; inject nothing |
| real credential | `opencode-claustrum` | `SplitCustody`: log, inject a refusing `fetch` (the request is refused before it leaves the process) |
| real credential | absent or another owner | not ours; untouched |
| any | any, with `CLAUSTRUM_CUSTODY_DISABLE=1` | fail-open by operator instruction; tombstoned providers fail with 401 until restored or re-enabled |

Ownership is the seam: any `serve` value other than `opencode-claustrum` leaves the entry
entirely alone for its named owner. The `config` hook never throws, because that would take down
every provider rather than the split one.

### Handle-manifest credential-id scope

The handle manifest is shared by several tenant plugins; each owns only its own provider
blocks. Within a block for provider `P`, `credential_id.split(':')[1] === P` is the whole
id-level scope check. Segment 1 is the credential kind and is an **open set** (`antigravity`,
`apikey`, `chatgpt` and `oauth` exist, and new kinds are expected): do not allowlist or infer
it. Segment 3 and later are a label convention and are never consulted.

| expectation | provider | account label | `credential_id` | reason |
|---|---|---|---|---|
| MUST RESOLVE | `openai` | `main` | `chatgpt:openai` | A kind-prefix rule would reject this real OpenAI shape. |
| MUST RESOLVE | `google` | `main` | `antigravity:google` | A kind-prefix rule would reject this real Google shape. |
| MUST RESOLVE | `anthropic` | `work-alt` | `oauth:anthropic:something-else` | The label must not be derived or consulted. |
| MUST REJECT | `anthropic` | `main` | `chatgpt:openai` | A real cross-tenant id must not parse in another provider's block. |

This is a shape check, not an existence check. Only a runtime comparison of `credential_id`
with what `credential.get` returns for the bound handle proves a binding names a real record,
and only a tenant whose transport exposes the served `credential_id` can make that comparison.
Tenant fixtures must use the real credential-id shapes: credential ids are operator-chosen
and cannot be derived from the provider, label or record kind.

### When the auth source cannot be read

When the selected auth source cannot be fully read, parsed or validated, the plugin scans its
raw bytes in bounded chunks for `claustrum-tombstone:v1:<provider>` and refuses those providers,
together with any providers the readable handle file assigns to `opencode-claustrum`. No scan
hit and no owned handle leaves a never-migrated user alone on purpose.

Two limits are coupled. A JSON-escaped sentinel (`\u0063laustrum-…`) is not found, and a
sentinel under the wrong key refuses the provider it **names**, not the entry that carries it.
Both are tolerable only because the sentinel is non-secret: the worst case is availability loss,
never exposure. Closing the escape hole by refusing every configured provider would break the
never-migrated case, so a change to either requires deciding both.

## 3. Serving a request

The vault connection is lazy: the `config` hook only reads files, and the first request that
needs a credential connects. Per request, the plugin re-reads the auth entry (a real credential
present means split custody, and the request is refused), then walks the provider's accounts in
priority order:

```
material = cached(account) ?? await credential.get(account)
substitute SENTINEL(p) -> material in every header value and URL query parameter
res = forward(request)
2xx / other -> return res
401         -> report_auth_failure(handle, 401, served record_version, "direct"); mark unusable; next
429         -> cooldown = Retry-After ?? 60 s; next
402         -> cooldown 1 h; next
exhausted   -> throw naming the provider, per-account state and the fix
```

Only 401 is reported. The report carries the `record_version` of the material actually sent on
that response. Failover completes before any body streams to the caller. Per-account state is
in memory only. Freshness is by shape: `api` re-observes the served credential on the next
request after 10 minutes; `oauth` runs a 60-second unref'd tick calling `get` with a minimum TTL,
so idle accounts stay fresh with no traffic. Handles, material and substituted values are never
logged.

## 4. CLI verbs

```sh
ck auth migrate-opencode [--dry-run] [--replace] [--force-shape] [--provider <id>]... \
                         [--auth-file <path>] [--handle-file <path>] [--serve-by opencode-claustrum]
ck auth migrate-opencode --restore <provider>
ck auth opencode-account add --provider <id> --label <label> --key-file <path|-> [--before <label>]
ck auth opencode-account remove --provider <id> --label <label>
ck auth opencode-account list [--provider <id>]
```

`migrate-opencode` moves `api` entries into the vault as `apikey:<provider>:main`, then for each
provider, each step idempotent so a crash anywhere converges on re-run:

1. **Import** the material. An identical existing record is reused; a different one aborts
   unless `--replace`.
2. **Mint** a handle and write the handle file (temporary file, fsync, rename, mode `0600`). An
   old handle for the same account is revoked only after the new file has been re-read and
   matches.
3. **Tombstone** the `auth.json` entry, atomically and only after step 2's re-read succeeded.
4. **Report.** `--dry-run` prints non-secret compare verdicts and stops before every write.

It refuses an `auth.json` that is not mode `0600`, a shape with no mapping, and a tombstone that
does not round-trip `isTombstone`. OAuth entries are skipped by default.

Before migrating, the CLI reads its provider-shape table,
`crates/credentials-module/src/bin/cli_support/opencode-provider-shapes.json`, maintained from
OpenCode source. A provider whose API key leaves the generic fetch seam is refused with the
shape, the reason and the source site:

| shape | why |
| --- | --- |
| `api-env` | OpenCode copies the key into `process.env` at provider load, so material would enter the environment. |
| `api-discovery` | Model discovery or a loader closure uses the key outside `options.fetch`. |
| `api-metadata` | The provider reads API auth metadata that a metadata-less tombstone does not carry. |

`--force-shape` overrides this, and the consequence is availability only, because the sentinel is
non-secret. Unlisted providers default to fetch-seam eligibility.

`--restore <provider>` refuses if the vault record is `needs_reauth` (writing a dead key back is a
silent failure). Otherwise it writes the live key back to `auth.json`, revokes the provider's
handles and drops it from the handle file; vault records are kept.

`opencode-account add` imports `apikey:<provider>:<label>`, mints a handle and inserts it in
priority order; `remove` revokes and drops the entry (the record is kept); `list` prints labels,
credential ids, state and record versions, never material.

## 5. xAI enrolment

xAI is served through a dedicated enrolment command in `packages/opencode`, not through
`migrate-opencode` or `import`.

**Roll back before changing login state.** To return xAI to OpenCode:

```sh
cd packages/opencode
bun run enroll -- --provider xai --id oauth:xai --main --remove
```

Only after that succeeds, run `/login` for xAI in OpenCode, then reload OpenCode. The plugin
refuses to serve while a tombstone remains in `auth.json` after the manifest entry is gone, until
`/login` replaces it; running `/login` first while the manifest entry remains produces
`SplitCustody` and also refuses. Do not delete the tombstone to repair either state. Removing the
manifest entry does not unload fetch closures from a running process, so reload is required.

**Enrol:**

1. Build the plugin bundle and install it (the default location is
   `~/.local/share/cortexkit/opencode-plugin/opencode-plugin.js`), restart OpenCode, and confirm
   the installed revision with `head -1 ~/.local/share/cortexkit/opencode-plugin/SOURCE.txt`
   before writing the manifest.
2. Create the vault record with `ck auth login --provider xai --id oauth:xai` (create-only; do not
   add `--replace` on a first login). Paste the whole callback URL if a manual paste is needed.
3. Mint a handle into a caller-owned `0600` file holding exactly one handle (`ckh_` followed by 43
   base64url characters). Symlinks, directories, looser modes, files over 256 bytes, two handles
   and anything else are refused.
4. Measure the provider's access-token lifetime, choose a minimum-TTL floor below it, and enrol:

   ```sh
   cd packages/opencode
   CLAUSTRUM_CUSTODY_LOG=off bun run enroll -- --provider xai --id oauth:xai --main \
     --min-ttl-ms "$MIN_TTL_MS" --token-lifetime-ms "$TOKEN_LIFETIME_MS"
   ```

   The tool refuses a floor greater than or equal to the lifetime, but cannot check that the
   lifetime is truthful. Use exactly one `--` separator. Other options: `--handle-file`,
   `--manifest-path`, `--auth-path`, `--remove`, `--help`.

The command writes the manifest first and the OAuth tombstone second. Preflight refusals, a
failed vault read and a failed manifest write all write nothing. If the tombstone write fails
after the manifest write, the command says so; run the rollback command above, then `/login`.
Never restore a stale `auth.json` snapshot: it may overwrite newer material from another
provider's rotation.

xAI does not revoke a predecessor refresh token on rotation, so enrolment moves serving into the
vault without retiring the old local lineage: any copy of the old `auth.json` entry (a backup, the
`OPENCODE_AUTH_CONTENT` of a still-running child) stays valid until its own expiry.

Any other consumer that reads xAI from the local `auth.json` entry loses it when the tombstone
lands. Give such a consumer its own capability handle **before** enrolling.

**Verify the serve.** A request through the plugin writes one `served` row per provider per
process to the custody log; leave `CLAUSTRUM_CUSTODY_LOG` unset while probing. The negative
control: the same request with `CLAUSTRUM_CUSTODY_DISABLE=1` fails, because the shipped loader can
only try the sentinel.

## 6. Verification

`bun test packages/opencode` runs the plugin's suites in `packages/opencode/src/tests/`: the
`config` hook decision table (`config-hook.test.ts`), the serve state machine against a stubbed
upstream (`serve.test.ts`), freshness policy (`freshness.test.ts`), the enrolment writers
(`enroll*.test.ts`), and log-leak checks asserting no handle or material is emitted
(`log-leak.test.ts`). The client's wire codec and identity handling are tested in
`packages/client/src/tests/`. The Rust side is covered by
`crates/credentials-module/tests/cli_opencode.rs` and the opencode crash-cut arms in
`scripts/gate.sh`.
