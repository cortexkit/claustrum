# Operator runbook

How to install, provision, operate, back up and upgrade the claustrum credential vault.
The parts and the rules behind each step are in [the architecture](architecture.md); the
consumer-facing wire surface is in [the wire contract](wire-contract-v1.md).

There are two programs:

- **`ck-claustrum`**, the daemon. The CortexKit supervisor (`subc`) runs it; it serves the
  read surface (`credential.get`, `get_many`, `status`, `report_auth_failure` and the
  scoped operations) over the route channel, and the authenticated admin surface. It is
  built from the `credentials-module` crate, and its module id is `claustrum`.
- **`ck-auth`**, the operator CLI, invoked as `ck auth <verb>`. It is the only write
  surface an operator uses. Most verbs commit through the **running** daemon with no
  downtime; two are offline-only (see [the single-writer rule](#the-single-writer-rule)).
  `ck auth help <verb>` prints each verb's flags and semantics.

## Locations, flags and environment

On a standard install admin commands need **no flags**: the vault data directory and the
running daemon's connection file are both auto-discovered. The flags matter only for a
non-default location (a test vault, a second vault on one machine, or a key held outside
the OS store).

All admin commands accept `--data-dir <dir>` (the directory holding `store.db`),
`--subc <file>` (the supervisor connection file) and `--key-path <file>` (an operator key
file instead of the OS store). An explicit `--data-dir` targets that vault and stays
offline unless a connection file is also given.

**`--data-dir` must be `<data_home>/cortexkit/<module_id>`**, where `<module_id>` is the
`subc.jsonc` module key, `claustrum`. The supervised daemon derives its store path from the
module id verbatim, so a CLI pointed elsewhere opens a *different*, empty vault under a
different key scope. On a default desktop:

```sh
DATA_DIR=~/.local/share/cortexkit/claustrum
```

**The daemon has no `--key-path` flag; it reads `CK_MASTER_KEY_PATH` from its
environment**, set in `subc.jsonc`. The two must agree. In practice the recorded
`key-source` (see [section 2](#2-bootstrap-the-master-key)) makes overrides unnecessary.

The supervisor supplies the other environment the vault is sensitive to:
`XDG_DATA_HOME` and `XDG_RUNTIME_DIR` (which move the data directory and the connection
file) and `SUBC_MODULE_ID` / `SUBC_LAUNCH_NONCE` (identity, echoed at registration).
**Moving the data directory does not start a fresh vault**: the daemon never bootstraps,
so a relocated vault finds no key for its new scope and refuses to serve rather than
coming up empty.

`CK_GOOGLE_OAUTH_CLIENT_ID` / `CK_GOOGLE_OAUTH_CLIENT_SECRET` and the `CK_ANTIGRAVITY_*`
pair override the embedded public OAuth clients. A wrong value fails loudly at the
provider, so no procedure below uses them.

## The single-writer rule

There is exactly one writer at a time, always. What changes is **who** it is.

When the daemon is running it holds the vault's single-writer lease, so the CLI cannot
open the store directly. Instead the CLI sends the operation **to** the daemon over the
route plane, and the daemon performs the write, serialized against any in-flight token
refresh. This needs no downtime: re-logging in a provider while agents are reading
credentials is safe.

Each operation is authenticated by a challenge-response MAC over the exact operation
bytes, keyed from the **master key**, with a single-use nonce. A caller without the master
key cannot mutate anything, and a compromised daemon cannot authorize a mutation it was
not given.

When the daemon is **not** running, the CLI takes the lease itself and writes directly.
Same operations, same audit chain, same master-key requirement.

**Offline-only verbs.** Two commands always require the daemon stopped, because they
operate on the store as a whole:

| verb | why it is offline-only |
|------|------------------------|
| `bootstrap` | creates the vault; there is no daemon yet |
| `rotate-master-key` | re-wraps every record and the sealed audit key in one transaction |

Every other write verb commits through the running daemon, and falls back to the offline
lease path automatically when no daemon is reachable.

Exit codes:

| code | meaning | what to do |
|-----:|---------|------------|
| 0 | success | — |
| 3 | the daemon holds the lease and this verb is offline-only | stop the daemon, retry |
| 4 | master key could not be resolved (OS credential store locked, key absent, or wrong) | unlock the OS credential store (Keychain on macOS, Secret Service on Linux, Credential Manager on Windows), or check `--key-path` |
| 5 | **indeterminate**: the op reached the daemon but the reply was lost | see below |
| 1 | usage, IO or other error | read the message |

**Exit code 5 needs care.** The operation was sent to the running daemon and the
connection dropped before the outcome came back, so it may or may not have committed. Do
**not** blindly retry: check with `ck auth list` (did the credential's version change?)
or `ck auth audit` (is there an entry for it?), then act on what you find.

The other outcomes are unambiguous. A **refusal** from a live daemon is terminal and safe:
nothing was written and the CLI never falls back. **No reachable daemon** means nothing
was dispatched, which is why falling back to the offline path cannot double-execute.

---

## 1. Install

`ck setup claustrum` installs the vault through the CortexKit dispatcher, installing the
supervisor core first by construction. The binaries live in
`~/.local/share/cortexkit/bin/`, with `ck-auth` also symlinked into `~/.local/bin/` for the
`ck` dispatcher.

**Claustrum releases require subc-core (the supervisor core), version 0.20.83 or newer.**
Upgrade the supervisor before installing from the release page; `ck setup claustrum` installs it first.

The supervisor runs the daemon from its `subc.jsonc`, with the vault module marked
`reserved: true` and a `sqlite` storage section. `reserved: true` means only the process
the supervisor spawned, echoing its launch nonce, can register as `claustrum`.

Verify the install:

```sh
ck-auth --version          # prints the build revision
ck auth status             # after bootstrap: health ladder + inventory
```

## 2. Bootstrap the master key

The master key encrypts every credential at rest. It is created once and never
regenerated; a second bootstrap is refused rather than clobbering the existing key.

**Native OS store (default for a new vault):**

| OS | Master-key storage | Requirements |
| --- | --- | --- |
| macOS | Keychain generic passwords | An accessible login keychain |
| Windows | Credential Manager per-user generic credentials, protected by DPAPI | Run as the vault owner with access to their credential store. The item uses enterprise persistence, so on a domain account with a roaming profile it roams with that profile. Use a key file on such machines if the key must stay on one host |
| Linux | Secret Service default collection (GNOME Keyring or KWallet) over the D-Bus session bus | A reachable service and an already-unlocked collection |

```sh
ck auth bootstrap --data-dir "$DATA_DIR"
```

All native stores keep independent current and next slots for crash-safe rotation,
scoped by the canonical vault directory. They never request an interactive unlock. If
the Linux keyring is locked, unlock it in your desktop keyring manager before starting or
retrying the daemon. For an unattended session, arrange an unlocked keyring and its D-Bus
session bus before launching the daemon. A missing bus, absent default collection, or
refused Credential Manager access is a refusal, not permission to choose another backend.

On macOS the keychain write needs the owner's login session, not just their user id. A
bootstrap run from a plain `sudo` shell or a remote command channel (SSH, a VM tool) fails
with `SecKeychainItemCreateFromContent ... Write permissions error`. Run it inside that
user's session instead, for example
`sudo launchctl asuser "$(id -u <user>)" sudo -u <user> ck auth bootstrap --data-dir "$DATA_DIR"`.

**Operator key file (headless or server):** the key file **must live outside the data
directory** (co-locating the key with the ciphertext defeats at-rest encryption); the CLI
refuses a key path inside `--data-dir`.

```sh
ck auth bootstrap --data-dir "$DATA_DIR" --key-path /etc/cortexkit/master.key
```

On headless Linux without an unlocked Secret Service, explicitly choose `--key-path <file>`
or `CK_MASTER_KEY_PATH=<file>` when bootstrapping. Use a directory outside the vault tree
that the daemon user owns (for example `~/.config/cortexkit/secrets/master.key`), with
the parent directory at mode `0700`, created beforehand; bootstrap creates the key file.
There is no automatic fallback from a missing or locked native store.

On Unix every load checks that the key file is a regular file, not a symlink, owned by
the current effective user, with no group or other permission bits. Use `chmod 600 <file>`
and, if needed, `chown <uid> <file>`. On Windows every load verifies the **opened handle's
owner and DACL**: only the current user, SYSTEM and Administrators may own it or hold
grants; null DACLs, unknown grant types and grants to other users or groups are refused.
Bootstrap creates the key with a protected current-user-only DACL from first visibility,
and rotation writes a similarly protected temporary file and renames it. Provision the
key's parent directory with an owner-only DACL too.

A loosened key file is refused as `unsafe operator key file: <path> failed owner-only
Windows ACL verification: ...; restore a regular key file owned by the current user,
SYSTEM or Administrators, remove inherited and explicit grants to all other users/groups,
and retry (do not regenerate the key)`. Use the file's Security / Advanced settings to
disable inheritance and remove broad grants, including Everyone or Users, and preserve the
existing key bytes. Claustrum does not repair an untrusted key file while reading it.

The vault data directory is created or tightened to a protected owner-only DACL on
Windows; foreign owners and reparse points are refused. See
[Windows file custody](windows-file-custody.md) for every file the vault writes.

Bootstrap also writes `$DATA_DIR/key-source`, a non-secret, versioned custody record. Its
two lines are `version:1` and one of `keychain`, `credential-manager`, `secret-service`,
or `file:<absolute path>`. Keep it with the vault metadata, not with the secret key. Both
the daemon and `ck auth` read this choice, so later commands need no key-path override.
Unknown versions or backend names are refused, not guessed.

Both programs honour `--key-path` and `CK_MASTER_KEY_PATH`. An override must agree with the
recorded choice; a different file, or a file override for a native-store vault, is refused
with both choices named. If both override names are set they must name the same file.
Remove conflicting overrides rather than editing the record to redirect a live vault.

A vault with `store.db` but no `key-source` is migrated on its first successful key
resolution: an explicit file override records that path, otherwise the existing keychain
source is recorded. A failed load or fingerprint mismatch writes nothing, and no key
material is moved.

---

## 3. Log in, import or put a credential

### Credential ids

**A credential id is `<method>:<provider>[:<label>]`** (for example `oauth:anthropic`,
`apikey:deepseek`, `antigravity:google`, `oauth:anthropic:work`). The `<method>` selects the
credential kind and the refresh adapter stored with the record: `oauth` → the
provider-named adapter, `antigravity` → the `antigravity` adapter, `apikey` → a static key
with no adapter. `--adapter <name>` overrides the method default. A legacy
`<provider>[:<label>]` id (first segment not a known method) defaults to the provider's
OAuth adapter. Ids beginning with `category:` or containing `|` are refused.

### Vault-native login: the preferred path

`login` mints a NEW, independent credential that the vault solely custodies, so there is
no rotation race with another tool holding the same provider login. Run it with no flags
for an interactive picker over every provider, showing which already have a credential:

```sh
ck auth login
```

The picker covers OAuth (`anthropic`, `openai`, `xai`, `google`, `antigravity`),
device-flow (`github-copilot`, `kimi`, `meta`, and `--device` for openai and xai), custom
browser flows (`cursor`, `devin`, `snowflake`, `digitalocean`), and API-key providers
(`zai`, `openrouter`, `kiro`, `deepseek`, `groq`, `cloudflare-workers-ai`, …), which are
validated against the provider before being stored. A few API-key providers have no probe
that can tell a bad key from a good one (for example `opencode-go`, `vercel-ai-gateway`,
`cline-pass`); for those, login prints a `NOTE:` line saying the key was stored without
being checked.

OAuth logins open a browser and complete automatically: a one-shot listener on the
loopback redirect captures the code, so **when the browser shows a paste code, ignore it;
the CLI has already finished.** If the port is busy, the listen fails, or you pass
`--no-listener`, the flow falls back to pasting the address-bar URL. Pasted values are read
from stdin only, never argv, and never logged.

```sh
ck auth login --provider xai --replace
ck auth login --provider anthropic --id oauth:anthropic:work   # a second, labeled account
```

Default ids include `oauth:anthropic`, `chatgpt:openai`, `oauth:xai` and `oauth:meta`. A
bare `--provider openai` means the ChatGPT subscription login, not `apikey:openai`. Each
labeled account has its own refresh chain and its own handles. `--replace` swaps the
credential on an existing id and **keeps its handles**; it is the usual repair for a
`needs_reauth` credential. Without it, `login` is create-only. A native login records a
`login` audit entry, distinct from `import`.

**Kiro.** Create a long-lived `ksk_` key at https://app.kiro.dev under Account → Settings →
API Keys, then run `ck auth login --provider kiro` to store it as `apikey:kiro` (or a
labeled account). Login checks the key against Amazon Q's model catalog using bearer auth
and `TokenType: API_KEY`; a successful response verifies it, the 403 auth refusal rejects
it, and other statuses or network errors produce a warning. No profile ARN is stored or
served.

**Cloudflare Workers AI.** At https://dash.cloudflare.com/profile/api-tokens create an API
token scoped to **Workers AI** with the Read and Edit permissions. Never use the Global API
Key: it grants the whole account and does not authenticate as a bearer token. Run
`ck auth login --provider cloudflare-workers-ai`; after the token, login asks for the
Cloudflare account id (32 lowercase hex characters, shown on the dashboard's account home
and in the Workers AI "Use REST API" panel). For a non-interactive login pass
`--payload-file <token-file> --account-id <id>`. A malformed account id is refused before any
request is sent. Login then checks both values together with Cloudflare's free Workers AI
model search for that account: a 401 or an unreadable token is refused as a bad token, a
403 is refused as a token that lacks the Workers AI permissions or belongs to another
account, and other statuses or network errors produce a warning and store the token anyway.
The token is stored as `apikey:cloudflare-workers-ai` (`llm-provider`). The account id is
not secret: it is stored as the record's `account_id` identity and served to consumers on
`credential.get_scoped` and `credential.list_scoped`. `--account-id` is refused for every
other provider.

**Meta Muse subscription.** Run `ck auth login --provider meta` (or add
`--id oauth:meta:work`). The device flow prints a verification URL and code, then the
vault mints an inference key. Only that key is served; the Meta identity token and any
optional OAuth refresh token stay sealed in the vault. No live exchange has confirmed a
Meta refresh-token grant, so the vault does not use one. Login prints only whether a
refresh token and expiry fields were present, never their values. Key expiry uses a
response expiry, then the JWT `exp`, and only otherwise an **assumed 24-hour lifetime**.
The HTTP fixtures for this adapter are reconstructed from client source rather than
captured from Meta. A mint 401/403 requires re-login. An inactive or payment-required
subscription also latches `needs_reauth`, but its `subscription_required` event means
**repair the subscription first**; re-login alone cannot fix payment. A 429 or server
outage is transient.

**Gmail send.** Gmail uses **your own Google Cloud OAuth client**, not the public Gemini or
Antigravity clients. Create an OAuth client of type **Desktop app** in your Google Cloud
project and enable the **Gmail API**. Configure the consent screen for exactly these
scopes: `https://www.googleapis.com/auth/gmail.send`, `openid` and `email`, and publish the
app **In production**. Per
[Google's OAuth documentation](https://developers.google.com/identity/protocols/oauth2#expiration),
an external-user app in **Testing** gets refresh tokens that expire after 7 days unless it
requests only basic identity scopes, and `gmail.send` is not exempt. Keep the client secret
in a `0600` file, never a command argument:

```sh
chmod 600 /secure/path/gmail-client-secret
ck auth login --provider gmail --client-id YOUR_DESKTOP_CLIENT_ID --client-secret-file /secure/path/gmail-client-secret
rm /secure/path/gmail-client-secret
ck auth grant --principal reserved:<module> --selector-kind exact --selector oauth:gmail --operation read
```

The file holds only the secret value (not the downloaded client JSON); trailing whitespace
is stripped. The refresh token and client secret are sealed together. The flow requests
offline access and consent, listens on `http://127.0.0.1:8086/oauth2callback`, and supports
`--no-browser` / `--no-listener` with the full-URL paste fallback. Login refuses a missing
refresh token or a missing userinfo email. Use `--id oauth:gmail:<label>` for a labeled
account and grant that **exact** id. A Gmail record carries only the `gmail-native`
category and no `serves` vendors: never grant a model category to a mailbox consumer or add
`llm-provider` to a Gmail record. Reads return the short-lived access token only; the
refresh token and client secret never leave the vault.

### Import an existing login

`import` bootstraps from another tool's files. Run it with no flags to pick from detected
accounts, or name the source:

```sh
ck auth import --source opencode --provider anthropic --id oauth:anthropic --json /path/to/auth.json
```

`--source` is one of `opencode | pi | gemini-cli | antigravity`. The provider's token URL and
client id come from the refresh adapter, not the file.

- **API keys:** an `apikey:<provider>` id imports a `{ "type": "api", "key": "..." }` entry
  as a static key; `--provider <key>` selects the entry from the `auth.json` map.
- **OAuth (`auth.json`):** `--provider <key>` selects one provider's
  `{ refresh, access, expires }` entry. Without it, `--json` must point at a single
  provider's object.
- **Google must be imported from `gemini-cli` or `antigravity`, not opencode.** A Google
  refresh token only refreshes against the OAuth client that minted it. `--source
  gemini-cli` reads `~/.gemini/oauth_creds.json`. `--source antigravity` reads
  `~/.config/opencode/antigravity-accounts.json` (`--provider` selects an account by email
  or index, default the active one) and is the source for an `antigravity:google` id. An
  opencode-minted Google token cannot be refreshed by either and fails closed to
  `needs_reauth`.
- **Claustrum tombstones are not importable.** After `migrate-opencode`, a tombstoned entry
  is an ownership marker. Re-run `ck auth migrate-opencode` to converge, or use
  `ck auth migrate-opencode --restore <provider>` to return the credential to OpenCode
  (see [the OpenCode plugin](opencode-plugin.md)).
- `--replace` overwrites an existing id unconditionally (re-seal at version+1, reset to
  `active`) and keeps its handles. Without it, `import` is create-only.
- `--account-id <id>` attaches non-secret account metadata; `--email` and `--org-name`
  require it; `--clear-identity` is exclusive with all three. A token-only
  `import --replace` keeps the existing identity, which assumes the replacement token
  belongs to the same account. After a re-login into a different account, run
  `ck auth set-identity <id> --account-id <id>`.

`ck auth set-identity <credential-id> --account-id <id> [--email <email>] [--org-name <name>]`
(or `--clear`) relabels a credential without replacing its token: it re-seals unchanged
material, keeps the lifecycle state, and bumps `record_version`.

### Put a static credential

For an API key, DSN, opaque secret or session cookie. Use `--payload-file <path>` so the
secret never appears in the process list or shell history; trailing whitespace is stripped
(cookie bytes are kept exactly):

```sh
ck auth put --id apikey:openai --payload-file ~/.config/openai.key --kind api_key
```

`put` is create-only. To rotate a static key in place, pass `--replace` (unconditional,
keeps handles) or `--expected-hash <hex>` (compare-and-set). A `cookie:<domain>:<label>` id
always creates a session-cookie record. A `github_app` deposit requires `--client-id`, the
App JWT issuer.

### Agent secrets: keys an agent uses without seeing them

Agent secrets are a separate record kind that no credential id, handle, grant or transfer
can reach. An agent (AFT for an API key, Cerebellum for a login) asks the vault to *use*
one; the vault hands back the key with the header, query or JSON-pointer location to put
it in, or the username, password and TOTP code for a login. Material is released only to
those two senders, and only under a grant.

```sh
ck auth secret put ops-github --kind api-key --host api.github.com \
  --path-prefix /repos --location header:X-Api-Key --material-file ~/.config/gh.key
ck auth secret put ops-board --kind site-login --origin https://board.example.com \
  --material-file ~/.config/board.login
ck auth secret list
ck auth secret grants
ck auth secret revoke --grant-id <grant-id>
ck auth secret delete ops-github
```

**Material never comes from a flag.** `--material-file` must be mode `0600`, and its
content is the deposit plaintext: the key bytes for an API key, or three lines (username,
password, optional `otpauth://totp/...`) for a login — the same layout a phone deposit
carries, checked by the same validator. Without the flag, `put` prompts on stdin instead.
A refusal names the path and the rule that failed and never echoes the content, an error
message or the audit payload.

`--location` defaults to `authorization_bearer`. It is scope metadata, not a target: it
tells the sending module where to put the key (`authorization_bearer`, `header:<name>`,
`query:<name>`, `json_pointer:<pointer>`) and it takes no part in matching the call.

Names are 1 to 64 bytes of `A-Z a-z 0-9 . _ -`, starting with a letter or digit, and they
are **create-only**: a second `put` of a name is refused, whether the existing row is
active or `corrupt`, because silently replacing a record an agent already holds a grant to
is not a repair. Delete first, which is a separate audited act that also removes the
record's grants and its pending approval requests.

`put`, `delete` and `revoke` are ordinary operator writes: through the master-key admin MAC
when the daemon is running (`admin.secret_put`, `admin.secret_delete`,
`admin.secret_revoke_grant`) and under the single-writer lease when it is stopped. `list`
and `grants` never touch the daemon: they open the store read-only, so they work with the
vault serving and need no key. On a store whose schema predates the agent-secret migration
they print `no agent-secret tables yet` and exit 0.

`list` also prints each registered phone's keys as `current as of <time>`, `superseded` or
`unobserved`. That is the **last observed** pairing — when a lookup saw a different pairing,
or the device absent, the keys read `superseded` — and never a validity checked now, because
`list` makes no callosum call.

### Secret home: which vault holds the agent secrets

One vault holds every agent secret, every grant and every flow grant for the account.
Other computers hold none. Each vault names that vault once:

```sh
ck auth secret home show     # secrets.home_member <value> + role <role>
ck auth secret home set self               # this vault is the home
ck auth secret home set fed-computer:<fp>  # another member's vault is the home
ck auth secret home unset                  # back to serving locally
```

`show` reads the store without the daemon or the lease, like `list`. The stored value is
`self`, a member id, or unset; the role is what that value resolves to with the live
federation self id: `single` (unset: served locally, exactly as before), `home`, `remote`,
or the refusal a secret op would answer when the setting is unusable
(`remote_setup_incomplete`, `store_error`). On a remote-role vault nothing local is
created: phone operations and `ck auth secret put` refuse
`secret_home_elsewhere/permanent: remedy_member=<home id>`, so a stray phone profile
cannot split the Secrets page. `delete`, `revoke-grant`, `list` and `grants` stay allowed,
so leftover state can be inspected and cleaned up.

`set <member-id>` needs the running daemon. A member id equal to this vault's live self
id is stored as `self` without a pairing lookup; any other member is checked against
callosum's pairing first, the same way `ck auth federation self` checks the self member.
A member callosum does not
know is refused `member_not_paired`, and a lookup that fails is refused
`callosum_unavailable`; an id is never stored unchecked. `set self` and `unset` are local
writes and run offline. Setting another member is refused while this vault still holds
any agent secret, grant, flow grant or pending request — the refusal names the counts
(`secret_home_not_empty/permanent: agent_secrets=<n> grants=<n> flow_grants=<n>
pending_requests=<n>; delete the secrets on this vault before naming another member as the
home`). Delete the secrets first, which also removes their grants and pending requests;
a concurrent put either commits first and is counted, or runs after the set and is itself
refused `secret_home_elsewhere`.

A member computer forwards only with the home's permission. On the home, grant it a
selector-free forwarding grant:

```sh
ck auth member grant --member fed-computer:<fp> --operation secret_use
```

Like `transfer_deliver`, `secret_use` takes no `--id` or `--category`: an exact or
category selector is refused. The grant records the member's current pairing id and counts
only while that pairing lasts, so after a re-pair the member's forwarded calls refuse
with the uniform `not_found` until the grant is made again. Revoking the grant, or
re-pairing, makes a retry with the same nonce fail with `not_found`. The grant needs the running daemon (it asks callosum for
the pairing); revocation needs no lookup.

### Operator-terminal signing keys

For machine account authentication from the operator's own terminal, generate a
dedicated Ed25519 key inside the vault and opt it into the admin signing path:

```sh
ck auth mint-signing-key --id signing:account-machine:1 --operator-sign
ck auth sign --id signing:account-machine:1 --payload-file challenge.bin
# Or pipe exact challenge bytes to: ck auth sign --id signing:account-machine:1 --payload-file -
```

The private key never leaves the vault in plaintext. `--operator-sign` seals the
permission with the key and implies `--audit-each-signature`. Every operator
signature commits a chained `sign` audit row with the payload SHA-256 before
signing; an audit failure returns no signature. Only the hash is audited, not the
challenge bytes. The actor is `route-admin` online and `offline-cli` offline.

`sign` uses the same operator master-key authentication as other `ck auth` admin
commands, or the offline single-writer lease when the daemon is stopped. It needs
no capability handle or enrollment token. Success prints one JSON line with
`key_id`, `public_key_hex` and `signature_hex`; the signature is 128 lowercase hex
characters. Refusal exits 1 and prints no signature. The 64 KiB decoded payload cap and
exact-byte signing apply to both files and stdin.

Keys minted without the flag cannot use this path. **Root keys
`signing:cortexkit-root:1` and `signing:gh-manifest-root:1` must never carry
`operator_sign`.** Use a separate machine key, not a root key. Replacement is a
fresh key and requires `--operator-sign` again. Older binaries can read the sealed
record but drop operator permission if they rewrite it. Consumer bus signing,
grants and capability handles otherwise retain their existing behavior.

### Which providers rotate refresh tokens

Whether a second holder of the same login is a hazard depends on the provider, not on the
arrangement. Read the adapter's refresh-token handling:

```
ROTATES  -> one custodian only; a second holder is a live revocation hazard
OMITS    -> a second holder is redundancy, not a race
```

Anthropic rotates and revokes the whole token family when a rotated-away refresh token is
presented, so keep one custodian. Google's installed-app OAuth omits the refresh token from
the response and the old one stays valid (`antigravity.rs` keeps the stored token when the
response omits one). xAI rotates but does not revoke the predecessor.

Anthropic subscription logins are also revoked by the provider roughly a month after login,
independent of how often they refresh. The vault discovers this as `invalid_grant`, latches
`needs_reauth`, and the repair is `ck auth login --provider anthropic --id <id> --replace`.
`ck auth reactivate` does not fix it: that clears a wrong verdict, and this one is right.

---

## 4. Categories and routing metadata

### Categories

A category is a bare name matching `^[a-z][a-z0-9-]{1,31}$`. Grants can select on a
category, so a category assignment changes what a grant reaches; assigning one requires the
master key.

The catalog seeds five categories: `llm-provider`, `data-warehouse`, `cloud-infrastructure`,
`web-search` and `browser-session`. The set is not closed: an operator can assign any valid
name. The seeds are what a new credential is stamped with at creation:

- Search-only API-key entries are Tavily, Kagi, Exa, Parallel, Brave, Firecrawl, Jina, TinyFish
  and SearXNG; they are `web-search` and never `llm-provider`. Many SearXNG instances need no key;
  store `apikey:searxng` only if your instance requires an API key. SearXNG is self-hosted, so
  login stores the key unchecked; a wrong key shows up on first use.
  DeepSeek, Ollama Cloud, Perplexity, Synthetic and Z.AI are dual-use API keys, so new records
  receive both `llm-provider` and `web-search`.
  Kimi for Coding (`apikey:kimi-for-coding`) is a separately managed live credential with no
  catalog row; its categories must be assigned explicitly rather than inferred from the catalog.
- Login entries are `llm-provider`, except Snowflake (`data-warehouse`), DigitalOcean
  (`cloud-infrastructure`), Devin (uncategorized) and Gmail (`gmail-native` only).
- A credential that speaks a provider's OAuth protocol is also stamped `<adapter>-native`.
- Every new `cookie:` record is stamped only `browser-session`.

The assignments are literal per-entry catalog fields in `crates/credentials-core/src/catalog.rs`;
no fallback derives them from the id. `ModelVendor` (`serves`) is a separate, advisory
vocabulary that never authorizes.

```sh
ck auth categories                                   # every category, its count, and the grants naming it
ck auth set-category <id> --add llm-provider         # or --set <csv> / --remove <csv>
ck auth reclassify --from-registry                   # refill EMPTY sets from the catalog
ck auth reclassify --from-registry --force           # also replace differing non-empty sets
```

`reclassify --force` refuses if it would remove a category an active grant selects on. A
category set an operator deliberately cleared is refilled by a later `reclassify`, so keep it
empty by not rerunning reclassify, or clear it again afterward. A transition writes one
`set_category` audit row; a no-op is silent.

### Provider ids and subscription tier

Provider ids are operator-written catalog mappings, not authorization categories. Neither
provider ids nor plan tiers are inferred from the credential's name:

```sh
ck auth set-providers --id oauth:anthropic --set anthropic claude-code
ck auth set-plan --id oauth:anthropic --tier max_20x
ck auth set-plan --id oauth:anthropic --clear
ck auth list
```

`set-plan` needs exactly one of `--tier` or `--clear`. A tier is a lowercase ASCII letter
followed by lowercase letters, digits or underscores, 1–32 characters. The pricing service
owns the vocabulary; current tiers include Anthropic `pro`, `max_5x`, `max_20x` and OpenAI
`plus`, `pro_100`, `pro_200`, `pro_500`. `--tier` always wins over automatic detection;
`--clear` removes only the override and reveals the detected tier. **An absent tier means
unknown, not a default plan.** Replacements into a different account and `set-identity`
clear both the old override and the old detection.

Automatic detection reads ChatGPT's access-token JWT at login and every refresh, and makes
one bearer profile request for Claude at login and after each successful refresh; unknown
plan strings give no tier rather than a guess. The exact mapping, timing and staleness
bounds are in [the wire contract](wire-contract-v1.md#operator-asserted-plan_tier-migration-16).
Overrides do not update automatically: reassert or clear one after an out-of-band plan change.

**Table layout:** when any row has a tier, `ck auth list` and the inventory in `status` add a
sixth header word, `PLAN_TIER`, after `PROVIDERS`, and every row has a sixth field (the tier
or `-`). Detected tiers carry a `*` suffix, e.g. `max_20x*`, explained in a footnote. An
optional `by=<principal>` follows as a trailing annotation with no header word. With no
tiers, the five-word `STATE VER CREDENTIAL CATEGORIES PROVIDERS` header is unchanged. Parsers
must accept both layouts; no field value contains whitespace.

---

## 5. Give a consumer access

There are three ways a consumer reaches a credential. Pick by what the consumer is.

| consumer | mechanism | operator command |
|---|---|---|
| anything that can keep a `0600` file | capability handle | `ck auth mint-handle` |
| a module the supervisor spawns | grant to `reserved:<module>` | `ck auth grant` |
| a host-launched process with no supervisor identity | enrollment, then grant to `enrolled:<name>` | `ck auth enroll approve`, `ck auth grant` |

### Capability handles

Handles and enrollment tokens are vault-local bearer secrets: never pass them to a peer
vault. With federation mapping on, a federation channel rejects either parameter before
resolving it. Turning mapping off restores release-1 bearer-scoped reads, even when the
forwarded `fed-` principal itself is refused; those reads do not apply the access-token
projection. Gate-off rollback therefore does not make leaked local handles or tokens safe.
Remote records have no handles; local consumers use their own vault's scoped grants.

```sh
ck auth mint-handle --id oauth:anthropic
```

The command prints the raw handle (`ckh_...`) to **stdout exactly once**; only its hash is
stored. Write it into the consumer's config as a `0600` file. Mint a **separate handle per
consumer**: handles are the revocation unit, so cutting off one consumer is one
`revoke-handle` and nobody else notices. Handles survive `login --replace`.

```sh
ck auth revoke-handle --handle <ckh_...>      # or --hash <64 hex> when the raw value is gone
ck auth revoke-all-handles --id <id>          # the record stays refreshable
```

To verify, the consumer's next `credential.get` succeeds; after a revoke it answers
`not_found` (indistinguishable from an unknown handle, by design).

### Grants

```sh
ck auth grant --principal reserved:<module> --selector-kind exact --selector <credential-id> --operation read
ck auth grant --principal enrolled:<name>   --selector-kind category --selector <category> --operation read
ck auth grants          # the complete authority set, read-only
ck auth revoke-grant --principal reserved:<module> --selector-kind exact --selector <credential-id> --operation read
```

`exact` matches one credential id byte for byte; `category` matches every credential carrying
that category, and moves as categories are assigned. Each operation is a separate authority
and none implies another:

| operation | authorizes |
|---|---|
| `read` | `credential.get_scoped` (the token itself), and scoped `status`, `public_key` and `report_auth_failure` |
| `sign` | `credential.sign` with a signing key |
| `open` | `credential.open` with a KEM key |
| `list` | the row in `credential.list_scoped`, with its identity (`account_id`, `email`, `org_name`) and `refresh_adapter`, and nothing else |
| `deposit` | `credential.deposit_cookie` for `cookie:` records only; requires a reserved principal and the `browser-session` category; grants no read access |

`list` is the account roster without the tokens: grant it to a module that chooses between
accounts but must never fetch one. A `list`-only principal is refused by every other scoped
operation with the same `not_found` as a principal with no grant.

`grants` rows contain the principal kind and id, selector kind, selector, operation and
creation time, sorted by principal, selector, then operation. An empty table prints
`no grants`. Revocation is exact over all four fields: revoking `list` leaves a `read` grant
on the same selector in place.

To verify a grant took effect, the module's next scoped call succeeds, and `ck auth events`
shows one `scoped_first_use` row for the (credential, principal, operation) tuple.

### Enrollments

A host-launched consumer (for example an editor plugin) has no supervisor launch nonce. It
proposes a name over the read plane and waits; only the master key can admit it.

```sh
ck auth enroll list                                       # pending requests and live enrollments
ck auth enroll approve --request-id <id> [--name <name>]  # admit a NAME; mints no token
ck auth enroll deny --request-id <id>
ck auth enroll revoke --name <name>
ck auth enroll reissue --name <name> > token-file          # prints the new token alone
```

Approval admits a name and mints nothing: the consumer's own poll mints the token,
authenticated by a request secret only it holds, so neither an operator nor a squatter can
collect a token for a name they do not hold. `--name` overrides the proposed spelling, which
is a stranger's claim rather than a fact. After approval, grant `enrolled:<name>` what it
needs. In `enroll list`, `awaiting-poll` means admitted but never collected: a stalled
handover, not a live consumer.

`revoke` stops the token from resolving immediately; a revoked enrollment answers like an
unknown token. It keeps the consumer's grants, which record what reach existed and block
re-enrolling the name, so a later consumer cannot inherit that reach. Revoke the grants
before re-enrolling a name. `reissue` writes a new token; the previous one stops working the
moment the new one is minted. The consumer-side ceremony is in
[the wire contract](wire-contract-v1.md#21-enrollment-for-a-consumer-with-no-supervised-identity).

---

## 6. Start the daemon; consumers read over the route channel

The supervisor runs the daemon. Once it is up, a consumer reads a credential:

```
catalog.list
  → route.open(ManagementSurface, module_id = "claustrum")
  → credential.get { handle: "ckh_..." }   // returns the opaque payload
```

The daemon resolves the handle, refreshes the token if stale, and returns the payload. An
unknown or revoked handle is a uniform `not_found`.

On Linux, both `ck-claustrum` and `ck-auth` make themselves non-dumpable before processing
arguments or loading credentials, and refuse to start if that fails. This also makes
`/proc/<pid>/exe`, `fd/`, `environ` and `maps` unreadable to same-user processes, so
`ck module status` reports the running image as `not readable (non-dumpable)`; that is
expected, not a failed deployment. On Windows both binaries replace their process DACL at
the same point. On macOS the hardened-runtime signature does this job.

A consumer that observes a 401/403 should call `credential.report_auth_failure { handle,
provider_status, record_version }` with the version it was served. If the vault has since
refreshed to a newer version, the report is a silent no-op.

---

## 7. See what the vault holds, and what needs action

```sh
ck auth status       # health ladder + inventory
ck auth list         # one row per credential: <state> v<version> <credential_id> …
ck auth grants       # one row per principal-scoped grant
ck auth categories   # categories, counts, and the grants naming them
ck auth usable       # which credentials can still serve or refresh
```

None of these prints a secret. They read the running daemon when one is up and fall back to
the store directly when it is not.

`status` reports the same health the supervisor probes:

| status | meaning | what to do |
|--------|---------|------------|
| `ok` | store readable, lease held, every credential active or retired | — |
| `degraded` | serving, but ≥1 credential is `needs_reauth` or `corrupt` | repair the named credential ([section 8](#8-repair-or-retire-a-credential)) |
| `failing` | the store is unreadable, **or** this daemon lost write authority to a newer instance, **or** its background health refresher stalled | check disk and lease; a stalled refresher means restart the module |

**A degraded vault still serves every healthy credential.** Retired credentials are listed
separately and do not degrade health.

The supervisor logs every non-ok probe. **Strip the colour escapes before searching that
log**, or field-name patterns match nothing and return a confident zero:

```sh
sed -E 's/\x1b\[[0-9;]*m//g' ~/.local/share/cortexkit/run/subc.log \
  | grep 'module reported non-ok health' | grep 'module_id=claustrum'
```

Without the `sed`, `status=` never appears as literal bytes (on disk it is
`status\e[0m\e[2m=\e[0m`). The log is shared and interleaved across every supervised module,
so require both terms on one line.

### Is anything unrecoverable?

The health probe and `ck auth list` read metadata only; they never open an envelope. One tool
answers whether every record can still serve, by decrypting each record in memory:

```sh
ck auth usable
ck auth usable --data-dir /srv/vault --key-path /etc/cortexkit/master.key
```

It is safe against a running vault: a read-only connection, no lease, nothing written. It
scores **stranded**: a record holding neither a usable access token nor refresh material, so
no `get` can recover it without a re-login. It deliberately does not score access-token
expiry, which is the routine state of a healthy credential. It also flags an identity that
renders a value while resolving nothing (an email with no account id). `stranded: 0` is the
expected reading.

---

## 8. Repair or retire a credential

| situation | command | effect |
|---|---|---|
| a credential is `needs_reauth` and the provider really refused it | `ck auth login --provider <name> [--id <id>] --replace` | new material, same id, **handles kept** |
| a consumer report latched it but the refresh token may be alive | `ck auth reactivate --id <id>` | clears `needs_reauth`; the secret is untouched |
| stop serving, reversibly | `ck auth logout --id <id>` | state `retired`, every handle revoked, record and audit history kept |
| delete permanently | `ck auth remove --id <id>` | the record, its refresh intent and its handles are gone; audited, not undoable |
| take out of service (lower-level) | `ck auth invalidate --id <id>` | `needs_reauth` and every handle revoked |

A retired credential does not degrade health. `login --replace` or `reactivate` brings it
back; consumers need freshly minted handles because `logout` revoked theirs.

### A consumer report put a credential in `needs_reauth`: try `reactivate` first

A consumer report is a claim about a served token; it says nothing about the refresh
material, and the two die independently. The vault also cannot interpret a provider
status: GitHub returns 403 both for a missing permission and for a rate limit, and other
providers use 403 for an entitlement lapse. So a report can kill a working credential.
Check whether the vault's own refreshes were healthy:

```sh
sqlite3 "file:$DATA_DIR/store.db?mode=ro" \
  "SELECT datetime(ts_ms/1000,'unixepoch','localtime'), op
     FROM audit_log WHERE credential_id='<id>' ORDER BY seq DESC LIMIT 8;"
```

A `refresh_commit` shortly before the report means the refresh token was alive then, and a
re-login is the expensive repair for a verdict that may be wrong:

```sh
ck auth reactivate --id <id>     # clears needs_reauth, does NOT touch the secret
```

This is self-correcting: the vault re-verifies on next use, so a credential that really is
dead returns to `needs_reauth` on its own and the wrong guess costs one failed request. It is
refused for `corrupt` records, where the vault checked its own bytes. If `reactivate` is
followed within minutes by another report at the new version, the credential is genuinely
dead and `login --replace` is the repair.

A 401 report at the **current** `record_version` against a **refreshable** credential does
not latch anything: it marks the token stale and the next `get` refreshes it. Only the
provider's `invalid_grant` latches `needs_reauth`. Static credentials have no recovery path,
so a report latches them immediately.

---

## 9. Audit and diagnostics

### Verify the audit chain

Every durable mutation is recorded in a tamper-evident, HMAC-keyed audit chain.

```sh
ck auth verify-audit    # safe while the daemon runs
ck auth audit           # safe while the daemon runs
```

`verify-audit` takes no lease, so it runs against a live vault. Four outcomes, deliberately
distinct; the middle two are configuration problems, not tampering:

| outcome | meaning |
|---------|---------|
| `audit chain verified: intact` | every MAC chains to its predecessor |
| `audit chain BROKEN at seq N` | the chain fails at N; inspect from there |
| `no master key slot holds the key this vault is sealed under` | wrong key or wrong vault, not tampering |
| `this vault has no audit key` | nothing to verify against; not an empty chain |

The chain is tamper-evident against edits, reorders and inserts, but not against
TRUNCATION: an attacker with write access can delete a suffix and the prefix still verifies.
Detecting that needs an external anchor. The running daemon publishes the global tip in its
health body as `auditSeq` and `auditTipMac`; a witness that records the pair over time
detects truncation. The check is not "the sequence never decreases": a truncation followed by
fresh appends returns the sequence to an old value, and only the MAC at that sequence differs.
The MAC observed at a given sequence must be stable forever.

`audit` lists entries (seq, op, credential, actor, and any alarm), lease-free. A flagged row
prints its reason in brackets. Every admin write is flagged `[admin_write]` by design, so
scan for the reason, not the flag: `[fetch_rate_anomaly]` and `[overwrite_without_cas]` are
the detection signals. An alarm row is a durable record surfaced on demand, not a live
notification.

### Why a credential stopped working

The chain records mutations, not reasons. `ck auth events` answers why:

```sh
ck auth events              # most recent first, 20 by default
ck auth events --limit 100
```

```
WHEN                 CREDENTIAL      KIND                   PRINCIPAL DETAIL     VER  APPLIED
2026-01-01 07:58:09  apikey:openai   consumer_report_latch  -         401        v3   applied=yes
2026-01-01 07:57:50  chatgpt:openai  consumer_report_stale  -         401        v5   applied=no
2026-01-01 06:12:03  oauth:xai       refresh_failed         -         503 status v2   applied=no
```

Column widths are measured from the rows, so the header is the only stable way to read a
column. `PRINCIPAL` is `-` on consumer reports because the read surface does not record one.

- A **consumer report** means a consumer spent the token and the provider refused it. The
  status distinguishes a rejected token (401) from a forbidden request (403). The reporter is
  whoever saw the refusal, not whoever caused it.
- **`refresh_failed`** means the vault's own exchange failed. On a transient failure the
  record stays active, so without this row nothing would show the attempt happened.
- **`applied`** says whether the event changed the credential. `no` on a report means the
  version it named had already been replaced, so the report was correctly ignored; a run of
  those is a consumer working from stale state.

Unlike `audit`, these rows are not evidence: they are not tamper-evident, and only the newest
64 events per credential are kept, so a flood against one credential cannot evict another's
history. A credential showing exactly 64 events has had at least that many. For what
authoritatively happened, read the chain. Two empty results mean different things:
`no authentication events recorded` (nothing has failed) versus `no authentication-event table
yet` (the store predates the migration; the daemon creates it on its next start).

### The four diagnostic string vocabularies

The vault has four separate string vocabularies that are easy to confuse. They live in
**different tables and columns**. Each list below is checked against the code's enum by the
tests in `crates/credentials-core/src/audit.rs` (`vocabulary_documentation_tests`).

#### `audit_log.op`

**Table:** `audit_log`

**Column:** `op` (TEXT)

These values come from the closed `AuditOp` enum and name the mutation or chain event:

| Value | Meaning |
| --- | --- |
| `put` | Create a new credential without replacing an existing row. |
| `import` | Import a credential from an external source format. |
| `login` | Mint a vault-native first-party OAuth credential. |
| `overwrite` | Replace a credential under an unconditional or compare-and-set write path. |
| `set_identity` | Re-seal unchanged credential material with updated non-secret account identity. |
| `set_plan` | Change an operator tier assertion, or clear it atomically when a replacement changes accounts. |
| `invalidate` | Mark a credential as needing re-authentication. |
| `rotate_master_key` | Re-wrap the vault under a new master key. |
| `refresh_commit` | Commit new tokens from a vault-owned refresh. |
| `report_auth_failure` | Record a consumer report that changes credential state. |
| `remove` | Permanently remove a credential row while retaining its audit history. |
| `reactivate` | Clear `needs_reauth` without changing the stored secret. |
| `mint_handle` | Mint a capability handle for a credential. |
| `revoke_handle` | Revoke one or all capability handles for a credential. |
| `fetch_anomaly` | Record a read-surface fetch-rate or enumeration anomaly. |
| `grant_create` | Create a principal-scoped exact or category operation grant. |
| `grant_revoke` | Revoke a principal-scoped exact or category operation grant. |
| `enroll.approve` | Approve a pending enrolled-consumer incarnation. |
| `enroll.deny` | Deny a pending enrollment request. |
| `enroll.revoke` | Revoke one enrolled-consumer incarnation. |
| `enroll.rotate` | Rotate a live enrollment token at its current generation. |
| `enroll.reissue` | Operator-reissue a replacement enrollment token. |
| `category.migrate` | Record migration 10's audited category backfill. |
| `approval` | Record an approver's approval of the exact artifact bytes identified by a hash. |
| `seal` | Record one `credential.seal` (auth-mode HPKE under a vault-held KEM key) before its ciphertext is returned; `payload_hash` is the SHA-256 of the plaintext. |
| `remote_issue` | The home issued an access token to a member; durable dedup bounds this to one row per member, credential, home version and encrypted material. |
| `transfer_out` | Commit a sealed outgoing transfer before delivery; resuming it adds no second row. |
| `transfer_in` | Accept a sealed transfer and create or replace the local static credential atomically. |
| `transfer_reject` | Reject a pending transfer, or abandon an outgoing envelope after replacing its sender key. |
| `member_grant_create` | Grant `remote_read` or `transfer_deliver` to a member at its current pairing id. |
| `member_grant_revoke` | Revoke a member grant. |
| `remote_add` | Create a remote record with a new incarnation, without persisting its access token. |
| `remote_remove` | Remove a remote record and its local metadata. |
| `federation_gate_set` | Change the live federation member-mapping setting. |
| `federation_self_set` | Set the vault's own canonical member id. |
| `secret_deposit_key_create` | Vault bootstrap creates the dedicated deposit key; target `kem:secret-deposit:1`, payload fields: key id. |
| `secret_phone_gate_set` | Operator changes the phone mapping gate; no target, payload fields: enabled. |
| `secret_home_set` | Operator sets or clears `secrets.home_member`, the vault that holds agent secrets; no target, payload fields: the stored value (`self` or a member id), or empty when cleared. |
| `secret_phone_register` | Phone registers create-only keys for the current pairing; target `secret-phone\|<fp>`, payload fields: pairing id, deposit public key, approval public key. |
| `secret_store` | Phone or operator stores a secret; target `secret\|<name>`, payload fields: kind, incarnation, sealed scope fields, and the deposit id for a phone deposit. The operator's `ck auth secret put` payload omits the deposit id, because there is none. |
| `secret_grant_create` | Phone approves a grant; target `secret\|<name>`, payload hash is the SHA-256 of the exact accepted envelope bytes. |
| `secret_delete` | Phone or operator deletes a secret; target `secret\|<name>`, payload hash is the phone envelope SHA-256, or framed incarnation and request id for the operator. |
| `secret_grant_revoke` | Phone, Cingulate or operator removes a grant; target `secret\|<name>`, payload fields: grant id, incarnation. |
| `secret_grant_expire` | Vault sweeps an expired grant after an admitted use or phone list; target `secret\|<name>`, payload fields: grant id, incarnation, expiry as u64 LE. |
| `secret_first_release` | Sender module first exercises a grant; target `secret\|<name>`, payload fields: grant id, incarnation. The grant's `first_released` marker, not prunable diagnostics, deduplicates this transition. |
| `secret_quarantine` | Vault flips an active secret to corrupt after an authenticated-scope mismatch; target `secret\|<name>`, payload fields: incarnation. Failed flips remain opaque. Master-key rotation records corrupt secrets under `rotate_master_key`, with no separate quarantine row. |

Secret grants are also visible through the `permissions/v1` provider. Cingulate uses
`permissions.list` and `permissions.revoke`; the local operator uses those operation
names inside the existing MAC-authenticated `admin.op` body with `v: 1`. A plain Direct
permissions call is refused. Listing returns live grant metadata only, never usernames
or material. Revocation removes access without a phone signature and records the
calling actor (`fed-phone:<fingerprint>`, `reserved:cingulate`, or `route-admin`).

The `set_category`, `set_providers`, `deposit_cookie_create` and `deposit_cookie_replace` ops
and their target formats are specified in [the wire contract](wire-contract-v1.md).

Federation chain rows keep the existing HMAC-chain format. Their actors and payload hashes
are specified in [the federation wire contract](wire-contract-v1.md#14-federation-between-computer-vaults).
For `remote_issue` and forwarded `report_auth_failure`, the actor is the authenticated
member (`fed-computer:<32 lowercase hex>`), never `reserved:callosum`. Transfer actors name
the counterpart: receiver on `transfer_out`, sender on `transfer_in`, and sender on a
receiver-side rejection or receiver on an abandoned outgoing row.

#### `audit_log.alarm`

**Table:** `audit_log`

**Column:** `alarm_reason` (TEXT), paired with the `alarm` (INTEGER 0/1) flag

`op` says what the entry records; an alarm reason says why that entry was flagged. The
`alarm` column is only the presence flag; the strings below are stored in `alarm_reason` and
come from the closed `AlarmReason` enum. Do not combine this list with the `op` list:

| Value | Meaning |
| --- | --- |
| `overwrite_without_cas` | An existing credential was overwritten without a compare-and-set guard. |
| `fetch_rate_anomaly` | A connection's credential-fetch rate or spread crossed the anomaly threshold. |
| `admin_write` | An administrative write occurred; admin activity is always flagged. |
| `reconcile_hash_mismatch` | Startup reconciliation found a stored refresh token hash that disagreed with its dangling intent. |

#### `auth_events.kind`

**Table:** `auth_events`

**Column:** `kind` (TEXT)

These values come from the `AuthEventKind` enum. This table is a separate, prunable
diagnostics table, not the tamper-evident audit chain:

| Value | Meaning |
| --- | --- |
| `refresh_failed` | A provider refresh attempt failed without producing a committed replacement. |
| `stale_nonrefreshable_latch` | A stale report on a non-refreshable credential was latched as `needs_reauth`. |
| `consumer_report_stale` | A consumer report marked a refreshable credential stale for its next read. |
| `consumer_report_latch` | A consumer report immediately latched a non-refreshable credential. |
| `scoped_read_refusal` | A principal-scoped read was refused; `detail` names the internal refusal reason. |
| `scoped_first_use` | The first time a principal successfully exercised a grant over a credential. Written once per (principal, credential, operation) and never again, so its absence shows a grant that has never been exercised. |
| `reconcile_needs_reauth` | Startup reconciliation forced a credential to `needs_reauth`. |
| `github_app_permissions_changed` | A successful GitHub App mint observed changed installation permissions. |
| `stale_refresh_deferred` | A read found a consumer's stale mark but served the current token without refreshing, because that version was written less than `REPORT_REFRESH_COOLDOWN_MS` (60 s) ago. Written at most once per credential version, so one row stands for every held-back read in that window; `record_version` names the version that kept serving. The mark stays set and the first read after the window refreshes. |
| `enrollment` | A bounded enrollment proposal, poll, or expiry diagnostic under a fixed `auth.enroll_*` subject. |
| `secret_forward` | On a vault whose secret home is another member: one secret call (`secret.use`, `secret.request_flow_approval` or `secret.revoke_flow_grants`) this vault forwarded to the home. `detail` is the outcome code the local sender got (`approval_required`, `revoked`, `invalid_params`, a §15 refusal code, or a forwarding fault such as `home_unreachable` or `remote_seal_invalid`), never material and never the home's own text. A `released` outcome is written once per (sender, secret), so repeated releases do not keep displacing the rows that explain a failure. The principal is the local sender. The subject is `secret\|<name>` for a call naming a valid secret name, else `secret-use\|unaddressed` (always for `secret.revoke_flow_grants`). |
| `secret_use_refusal` | AFT/Cerebellum refusal during secret-use grammar, scope mapping, or secret/target authorization, or create-only phone-key conflict. Best-effort and never part of a release transaction; failure changes no reply. Details are `grammar`, `limit`, `unmapped`, `coverage`, `unknown_name`, `corrupt`, `sealed_scope`, `kind`, `target`, or `phone_key_conflict`, never a requested path. |

Secret refusal subjects are `secret\|<name>` for an existing secret during secret/target authorization,
`secret-use\|unaddressed` for grammar, scope mapping and unknown names, and `secret-phone\|<fp>`
for a phone-key conflict. Each subject retains at most `AUTH_EVENTS_PER_CREDENTIAL`
(64) rows independently. Deleting a secret removes only `secret\|<name>` rows;
unaddressed and credential diagnostics survive. Credential writers reroute every
caller-derived id containing `|` to `credential.invalid_id`, so they cannot trim a
secret's diagnostics. Non-sender caller admission failures and invalid approval
replies (`approval_invalid`) write no refusal diagnostic.
The sender principal kind is `reserved`, id `aft` or `cerebellum`. Phone conflicts
use principal kind `phone`, id `fed-phone:<fp>`; this identifies the authenticated
phone, not the callosum transport.

**Retired values you may still meet in the data.** The table above lists what the code
writes; the table on disk also holds what older binaries wrote, and it is never rewritten:

| Retired value | What it was |
| --- | --- |
| `consumer_report` | The single kind that preceded the stale/latch split: a consumer report of an auth failure, before the vault distinguished "mark stale so the next read refreshes" from "latch immediately". Superseded by `consumer_report_stale` and `consumer_report_latch`. |

Other unknown kinds may appear (a future retirement, a test-harness fixture). Treat them as
diagnostics, never as audit operations or alarm reasons.

**Before reading a missing row as evidence, ask whether the path could have completed without
writing it.**

```
CAN THE PATH THAT WOULD HAVE WRITTEN THIS ROW COMPLETE WITHOUT WRITING IT?
  no   -> absence is a STATEMENT
  yes  -> absence is a SILENCE
```

`auth_events` is written unconditionally on a consumer report, so a missing row there is a
statement: the report did not arrive. The attributed `audit_log` row is written only when the
version gate passes, so its absence is a silence: it is missing for every `applied=no`
report, which are exactly the reports worth tracing. Local consumer reports record the
observed principal when present (`direct`, `reserved`, `unverified` or `enrolled`), or NULL
when none is observed; home-side forwarded reports identify their member. A write-on-success path makes absence meaningful; a
write-on-transition path does not, and no row count tells you which you are looking at.

**Member principal.** Federation diagnostics use principal kind `member` and the canonical
`fed-computer:<32 lowercase hex>` id for member refusals and forwarded reports.
Do not attribute those rows to the `reserved:callosum` transport principal. Requester-side
diagnostics can name remote credential ids even though those ids have no local credential
row; `auth_events` has no credential foreign key.

#### `auth_events.reporter_source`

**Table:** `auth_events`

**Column:** `reporter_source` (TEXT, nullable)

A consumer-asserted, unverified claim about where the reported failure was observed. It is
separate from `detail`, which records what the vault observed. The vault accepts only this
closed vocabulary; any other wire string becomes `unrecognised`, and the original string is
never stored:

| Value | Meaning |
| --- | --- |
| `direct` | The consumer saw the provider status on a direct response. |
| `relay_status_field` | The consumer read a structured status field from a relay error event. |
| `relay_message_parse` | The consumer recovered the status by parsing relay message text. |
| `unrecognised` | The consumer supplied a source outside the vault's named vocabulary. |

`NULL` means the report predates this column or the consumer omitted the optional field; it
is normal, not invalid data, and differs from `unrecognised`.

### Reading the store directly

To inspect a running vault, or to answer "did that write commit?" from outside, read the
store read-only. This takes no lease and cannot disturb the daemon:

```sh
DB="$DATA_DIR/store.db"

# Recent events. `actor` distinguishes who caused them: `vault` is the refresh engine,
# `route-admin` an operator through the running daemon, `offline-cli` an operator holding
# the lease directly.
sqlite3 "file:$DB?mode=ro" "SELECT seq, op, credential_id, actor,
  datetime(ts_ms/1000,'unixepoch','localtime') FROM audit_log ORDER BY seq DESC LIMIT 20;"

# When each credential last completed a real provider token exchange.
sqlite3 "file:$DB?mode=ro" "SELECT credential_id, MAX(datetime(ts_ms/1000,'unixepoch','localtime'))
  FROM audit_log WHERE op='refresh_commit' GROUP BY credential_id;"

# Write authority: the store's fence epoch against the daemon's lease.
sqlite3 "file:$DB?mode=ro" "SELECT epoch FROM cortexkit_fence WHERE id = 0;"
cat "$DATA_DIR"/*.lease
```

`conn-<N>` in the `actor` or `source` columns is a route channel number, reused as bindings
come and go: it is not a consumer identity. For a consumer-reported invalidation the chain
gives you the credential and the instant, never the reporter; correlate the timestamp
against consumer or supervisor logs.

When filtering invalidations, split on `actor`: `actor = vault` is the provider refusing a
refresh, while `route-admin` or `offline-cli` is an operator stopping the credential on
purpose. They share a row shape.

Rules that keep these reads honest:

- **Use `mode=ro`, never `immutable=1`.** An immutable open skips the write-ahead log, so on
  a live vault it returns a pre-WAL snapshot. `immutable=1` is only for a store nobody is
  writing.
- **`mode=ro` is also what makes the read inert.** SQLite checkpoints on close when the
  closing connection is the last one attached, whatever statements it ran. A plain
  read-write `sqlite3 store.db "SELECT …"` against a **stopped** vault rewrites the main file
  and deletes the WAL.
- **`store.db` without its `store.db-wal` is incomplete, and usually silently so.** The main
  file holds only what was checkpointed. Depending on the SQLite build it either refuses to
  open or opens and answers from an arbitrary checkpointed prefix, and `PRAGMA
  integrity_check` still says `ok`. `-wal` is the load-bearing companion; `-shm` is a
  rebuildable index. Check `ls store.db-wal` before opening a copy.
- **Copy the directory, never the file. And put the copy outside
  `~/.local/share/cortexkit`**, for example in `~/.local/state/claustrum-snapshots/` (mode
  `0700`). A directory copy carries `engram-catalog.json`, the lease file and the
  signed-payloads tree. The backup module discovers stores by reading
  `<data_home>/<child>/engram-catalog.json` one level deep and fails closed fleet-wide on a
  descriptor it cannot match to an enrolled module, so a copy beside the live directory
  stops every module's backup until it is moved.
- **The table is `audit_log` and its timestamp column is `ts_ms`.** A wrong column in a
  `WHERE` clause returns zero rows, indistinguishable from "nothing happened". Check the
  schema before believing an empty result.
- **The chain answers "what happened"; the fence epoch answers only "what is true now".** An
  unchanged fence row is consistent with both a rejected write and a healthy writer that had
  nothing to claim. To ask whether a write committed, read the chain.

### Reading anomalies

- **A lane's silence is only anomalous against its own fetch rate.** `credential.get` is
  demand-driven, so token lifetime says when a token expires, not when a consumer asks.
  Compare a credential's quiet period with its own history of mint intervals, not with the
  token lifetime or with busier credentials. The direct evidence needs no timing: a provider
  call that was made and refused writes an `auth_events` row on both failure arms, so zero
  rows means no call was refused, provided the store was writable in that window.
- **A refresh rate far above the token lifetime** is the signature of a consumer whose
  `min_ttl_ms` demand is close to that lifetime. The vault records refreshes but not reads,
  so the ratio that names this (refreshes per read) is not computable here. Ask the consumer
  for its per-credential read count rather than adding read recording to the hot path. A
  tight demand drives the ratio toward 1.0.

---

## 10. Backups and restore

The store is enrolled with engram, the fleet's backup module, and captured whole through an
online backup over a `mode=ro` connection, so committed WAL frames are included. The daemon
writes the backup descriptor, `<data_dir>/engram-catalog.json`, at every start from the
constant `ENGRAM_CATALOG_JSON` in `crates/credentials-module/src/main.rs`; it covers
`store.db`, `signed-payloads/` and `signed-envelopes/`. A new directory kept in the data
directory needs an entry there, or it is not backed up and nothing warns.

**Restoring needs TWO things, and one is not in the backup:**

```
restored store.db          from the backup generation
+ the matching master key   from the recorded OS store, or the recorded operator key file
= a vault that opens
```

The backup holds the audit key sealed under the master key, never the master key itself. That
is deliberate: a backup that carried the key would be enough to decrypt every credential. So
a machine restoring this vault must carry the key across separately.

**Restore one without the other and the failure does not say "missing key".** The store opens,
the migrations apply, and unsealing the audit key fails, which surfaces as an open error on an
intact file. Before concluding anything about the data, compare what the store wants with what
this machine can resolve:

```sh
sqlite3 "file:$DATA_DIR/store.db?mode=ro" "SELECT key_id FROM vault_secrets LIMIT 1;"
ck_key_verify --data-dir "$DATA_DIR"     # feature-gated tool, takes no lease
```

`KeyMismatch` names both fingerprints: the store is fine and the key is wrong.
`NoSlotMatchesDb` means no slot in the recorded backend matches: a native-store item may be
absent or scoped to a different canonical data directory, or the operator file holds the
wrong key.

After a restore, verify:

```sh
ck auth verify-audit       # intact
ck auth status             # every credential serving (N/N), or the expected degraded set
ck auth usable             # stranded: 0
```

A whole-store restore brings back the snapshot's state wholesale: every capability handle
that was live then (including ones revoked since, because revocation lives in the same
table), its open refresh intents, and older key versions. Revoke the handles that should stay
dead rather than deleting rows, and re-check keys other machines remember
([section 11](#keys-other-machines-see-rotate-with---replace)).

**Never run a restored copy alongside the live home vault.** The matching master key makes
the backup a complete credential copy, including rotating refresh tokens and federation
settings; concurrent refreshes can revoke the login on both copies.

**Other backup tools reach this data too.** On macOS, Time Machine includes
`~/.local/share/cortexkit/claustrum` unless excluded, and a Time Machine restore of the data
directory is the same whole-store restore. Handle files and enrollment tokens that consumers
write under `~/.config` or `~/.local/state` are also copied into every snapshot whatever their
mode, and those copies outlive a revoke (the live vault still refuses them, until a store
restore brings the old handle back). Check with `tmutil isexcluded <dir>`: the question is not
whether one backup entry covers a path, but whether any backup tool reaches it.

---

## 11. Key rotation

### The master key

```sh
ck auth rotate-master-key     # offline: stop the daemon first
```

This is a crash-safe two-slot handover: it stages a new key, re-wraps every record and the
sealed audit key in one transaction, then promotes the new key. A crash at any point reopens
cleanly under whichever key matches the database, including when a previous rotation was
itself interrupted (a staged-but-unpromoted rotation is healed before a new one is staged).
Verify with `ck auth verify-audit` and `ck auth status` after restarting the daemon.

### Signing and KEM keys

```sh
ck auth mint-signing-key --id signing:<name>[:<generation>]   # prints public key hex and key_id
ck auth mint-kem-key --id kem:<name>                           # prints public_key_hex and key_id
```

Both generate the key pair in the CLI process and seal the private half directly into the
vault; it is never written to a file, argv, environment variable or output. Both are
create-only by default; normal rotation of a key that verifiers pin by id is a new
`<generation>` id.

### Keys other machines see: rotate with `--replace`

Some signing keys have their public half announced to other machines, which remember it
together with the key's `record_version` (for example the per-machine message-signing key
`signing:msgsig`). For these, a rotation must keep the credential id and move the version
forward:

```sh
ck auth mint-signing-key --id signing:msgsig --replace
```

`record_version` only increases within one row's life. `ck auth remove` deletes the row, and
minting the same id again starts at version 1; a whole-store restore also brings back an older
key at its older version. In both cases peers remember a higher version than this machine
serves, keep the key they hold, and raise an alarm naming the version to beat ("rotate above
N"). Run the `--replace` above until `record_version` (see `ck auth status`) is higher than N.

A key rotated to a new generation id instead (for example a bus account key
`signing:<name>:<generation>`) needs its consumers re-granted on the new id.

The `gh` routing-manifest root follows its own ceremony: see
[manifest signing](gh-manifest-signing.md).

---

## 12. Deploy and roll back

### Build

For local daemon/`ck auth` iteration, the order is **fast check → build/sign → place →
live acceptance → full gate and CI**. A local fix need not wait for integration CI or landing on master.
Migrations still require the pre-migration snapshot procedure first; the faster build
path does not change the backup or rollback requirements below.

```sh
# While iterating (includes committed, staged, unstaged and untracked changes):
./scripts/fast-check.sh
# Commit the final source before building; --fast reruns the check on that clean commit:
PROBE='<command> should print <X> against the live daemon' ./scripts/release-build.sh --fast
```

`fast-check.sh` compares against `origin/master` (or an explicit `--base <ref>`), checks workspace formatting,
workspace, and lints/tests changed crates. It always runs consumer wire-contract tests,
authorization/uniform-refusal/anti-enumeration tests, the no-secret-output and direct-nonce
source scans, and migration safety tests. It names the exact filters and skipped full-gate
arms in its output. Release signing is still checked by the builder, not by the fast check.

`release-build.sh --fast` permits a clean, committed local revision even before it reaches
`origin/master`. It runs the fast check itself and refuses if checks change the source or
HEAD. It skips `real_daemon_e2e` and `cli_admin` tests against the staged binaries, so live acceptance is mandatory, not an
optional substitute for a source test. `build-info.txt` records `fast_path`,
`on_origin_master`, the observed `origin_master` SHA, and whether the fetch succeeded. An
unresolved remote is recorded as `unknown`, not as an ancestry pass. Without `--fast`, the
existing branch/ancestry guards and staged-artifact suites remain. Published
releases still use the guarded release workflow; the fast lane is not a public release path.

Default and fast builds refuse on a dirty tree, stamp the source revision into both binaries, sign each with its
pinned identifier and the hardened runtime, and prints the revision and sha256 it produced. It
builds with `CARGO_TARGET_DIR=target/stamped` and copies the artifacts to
`target/staged/<rev>/`, where a later cargo build cannot overwrite them. A stage is safe from
overwrite but not from `cargo clean`, which removes everything under `target/`; do not run it
between staging and placement.

**Every build carries a reachability probe**: `release-build.sh` refuses without `PROBE`. The
probe names the behaviour that proves the change is LIVE rather than merely placed; only the
requester knows it. `none: <reason>` is a valid answer for a build with no observable change.

Signing uses pinned identifiers:

```sh
codesign --force --sign - --options runtime --identifier ck-claustrum target/staged/<rev>/ck-claustrum
codesign --force --sign - --options runtime --identifier ck-auth target/staged/<rev>/ck-auth
```

macOS's default ad-hoc identifier embeds the binary's link-time UUID, so it changes on every
build, and macOS binds privacy grants to that identifier; an unpinned release silently revokes
them. Pinning also makes the published hash equal the placed hash. **Do not re-sign at the
destination**: one `codesign --force --sign -` there reverts the identifier.

### Place

Place by **rename**, never by a plain `cp` over the destination:

```sh
cp target/staged/<rev>/ck-claustrum ~/.local/share/cortexkit/bin/.ck-claustrum.incoming
mv -f ~/.local/share/cortexkit/bin/.ck-claustrum.incoming ~/.local/share/cortexkit/bin/ck-claustrum
```

`cp` rewrites the destination in place, keeping its inode. Overwriting pages under a mapped,
code-signed image invalidates the signature: the placed binary is killed with SIGKILL
(`rc=137`, no output) the next time it executes, while the running daemon keeps serving from
its old mapping, so a restart in that window takes the vault down. Rename allocates a new inode
and leaves the running process's mapping intact. It also keeps the inode acceptance leg
meaningful: after a `cp`, "running inode equals disk inode" passes for the wrong reason.

### Accept

Restart the module, then run the acceptance ladder:

```sh
scripts/accept-deploy.sh <rev> target/staged/<rev>
```

Run the script rather than retyping its legs. Each leg is able to fail:

| check | why it discriminates |
|-------|----------------------|
| deployed hash equals the **new** build's hash and differs from the **old** one | publish both values; comparing the system to itself passes trivially |
| `<dest> --version` reports the revision you built | the only check that asks the binary what it is |
| the running process's image inode equals the deploy path's inode | proves the process is not still executing an unlinked predecessor |
| the open `store.db` is the one you expect | every other check answers "is it healthy", not "is it the right vault" |
| `ck auth status` reports every credential serving | a daemon whose master key was unavailable at boot is alive and serving nothing |
| mint a throwaway handle, then revoke it | exercises the fenced write path and its atomic audit append |

The store check asks the kernel rather than the process:

```sh
lsof -p "$(pgrep -a -x ck-claustrum)" | awk '$NF ~ /store\.db$/ {print $NF}'
```

Use `pgrep -x`, never `pgrep -f`: `-f` matches the whole command line, including any shell
whose script text contains the name. And by default `pgrep` excludes its own ancestors, so from
a shell running under the supervisor `pgrep -x ck-subc` returns nothing while the supervisor is
alive. `pgrep -a` includes ancestors; `ps -axo pid=,comm= | awk '$2 ~ /ck-subc$/'` needs no
flag. An empty `pgrep` is not evidence a process is down. Do not use `pgrep -v` as an inverse:
an excluded ancestor lands on the non-matching side.

**What the ladder does not cover: whether the behaviour you shipped is reachable.** Every leg
asks whether the right bytes are in the right place. A CLI change whose logic runs inside the
daemon is not live until the daemon half is placed and restarted. Exercise the build's probe end
to end, and if it does not show, check which binary owns the behaviour before assuming the
deploy failed.

After `accept-deploy.sh` and the live probe pass, run the full checks and fix forward on any failure:

```sh
./scripts/gate.sh
# Land through the train so the Linux and Windows CI legs run too.
./scripts/train-push.sh
```

`scripts/gate.sh` is post-deploy feedback for local iteration, not permission to omit CI.

If a hash comparison fails after someone re-signed the binary, re-sign a **copy** of the known
build with the known identifier and compare that; `dwarfdump --uuid` (invariant under signing)
and a signature-stripped `shasum` also settle it. `LC_UUID` identifies a (commit, path,
toolchain) triple, not a commit: the same commit built in two checkouts gives two UUIDs. To
name the commit a running binary came from, ask `--version`.

### When to cut a build

At the behavioural boundary, not on a timer. CLI-only commits accumulate freely. The moment a
commit touches daemon-linked source (`credentials-core/src`, or anything under
`credentials-module/src` outside `bin/`), that is the cut point and the pair ships together.

### KEM open probe

After deploying a vault that serves `credential.open`, mint a disposable recipient with
`ck auth mint-kem-key --id kem:probe` (save the printed `public_key_hex` and `key_id`). Grant
`open` on the exact `kem:probe` selector to a test module with `ck auth grant --principal
reserved:<module-id> --selector-kind exact --selector kem:probe --operation open`. Seal a
message with `cargo run -p credentials-module --example kem_seal_probe -- <public_key_hex>
<plaintext> > /tmp/kem-fields.json`, then run `cargo run -p credentials-module --example
vault_read_probe -- --subc <connection-file> --as-module <module-id> --scoped-id kem:probe
--open-fields /tmp/kem-fields.json`. The probe opens twice on the same bound connection: verify
identical `plaintext_b64` values and a `key_id` matching the minted value. Check for exactly one
`scoped_first_use` event for `(kem:probe, <module-id>, open)`, then revoke the grant with
`ck auth revoke-grant` using the same selector and operation, and remove the key with
`ck auth remove --id kem:probe`. The disposable probe does not exercise a real consumer's
principal, so a real consumer's first open still needs its own verification.

### Roll back

Keep the two most recent rollback copies of each binary
(`~/.local/share/cortexkit/bin/ck-auth.pre-<rev>-<ts>`) and delete the rest; every one is
reproducible by re-running `release-build.sh` at its rev. A bin directory full of
similarly-named binaries is where somebody eventually runs the wrong one. Delete on sight any
copy named for an event rather than a rev. `release-build.sh` prunes staged trees itself,
keeping the three newest and, whatever its age, the stage matching the deployed binary.

**A daemon rollback copy stops being a rollback target at the next migration.** Rolling the
daemon back is safe only while the target's migration chain is at least as new as the store's.
A binary refuses to open a store ahead of its chain, naming both versions, but that refusal
lives in the binary you roll back TO: a target that predates the refusal migrates and serves a
schema it cannot reason about, and fails at the first write of the wrong shape. Check the
target against the store:

```sh
sqlite3 "file:$DATA_DIR/store.db?mode=ro" \
  "SELECT MAX(version) FROM cortexkit_schema_version WHERE namespace='credentials';"
git merge-base --is-ancestor <newest-migration-commit> <target-rev> \
  && echo "target carries that migration" || echo "STALE: not a rollback target"
```

A stale target is not a rollback. Restore the store alongside the binary from a backup taken
before the migration (with its master key, [section 10](#10-backups-and-restore)), or roll
forward.

To roll back a binary: place the rollback copy by rename exactly as above, restart the module,
and run `scripts/accept-deploy.sh` against the rev you rolled back to.

### Federation setup and recovery

Keep each rotating login on one home vault A. On each computer, obtain its own canonical
member id from callosum (`fed-computer:<32 lowercase hex>`), pair the computers and run
`ck auth transfer init --self <own-member>`. Callosum announces that vault's transfer
public key. A mistaken self id is repaired with `ck auth federation self <own-member>`;
do not replace a healthy transfer key to change the self id.

Deploy in producer-first order: release-1 harness recording, callosum's `callosum-self`,
then release 2 with a pre-migration snapshot and mapping off. Only after the deployed
supervisor guarantees the authenticated harness and callosum derives it from the computer
peer should the operator run `ck auth federation mapping on`, then expose claustrum to
computer peers. Gate changes take effect without restart. Gate-off rollback restores the
bearer-secret boundary described under capability handles, not a safe way to share tokens.
An older binary cannot open the migrated store; roll forward or restore the snapshot
with the older binary, losing subsequent writes.

On A, authorize B with
`ck auth member grant --member <B> --operation remote_read --id <login-id>` (or
`--category <category>`). On B, run `ck auth remote add --id <login-id> --home <A>`.
B's modules need their own local read grants. `ck auth remote list` shows home/version/
fetch outcome; `remote remove --id <id>` removes it. Re-homing is remove then add.
After a re-pair or trust-backup restore, re-grant: old pairing-bound grants do not apply.
Repair a home login on A, then poll B's `get_scoped`; remote status alone cannot observe
the repair. A cached access token can remain usable for at most 300 s after grant revocation.

For agent secrets, one vault is the home for the whole account. On each vault run
`ck auth secret home show` to see the stored setting and the role it resolves to, and on
every non-home vault run `ck auth secret home set <home-member>` (or `self` on the home).
`set <member>` needs the running daemon and is refused for an unpaired member; it is
refused with the blocking counts while the vault still holds agent secrets, grants, flow
grants or pending requests, and refused `secret_home_elsewhere` is what that vault's phone
operations and `ck auth secret put` answer until the setting points at the home. On the
home, each member computer needs `ck auth member grant --member <m> --operation
secret_use` (selector-free, pairing-bound like `transfer_deliver`); without it the home
refuses that member's forwarded calls with the uniform `not_found`. After a re-pair,
re-grant. A remote-role vault forwards `secret.use` and the two flow ops and relays the
home's answer; a vault that is not the home-role vault answers an inbound forward with
`not_found` and never re-forwards, so a misconfigured two-way pairing ends after one hop.
The phone finds the home through `secret.home`, and only after the forwarded approval
statements (`ck-secret-use-statement/v2` and `ck-secret-flow-statement/v2`) and
`secret_home_elsewhere` are deployed to every vault does an operator set the member
setting on any non-home vault.

For a static credential, B grants A `transfer_deliver` without a selector. A runs
`ck auth transfer send --id <id> --to <B>`. B inspects `ck auth transfer receive` and runs
`ck auth transfer accept <transfer-id> --from <A>` or `reject <transfer-id> --from <A>`.
Nothing becomes a credential on B before accept. A uses
`ck auth transfer send --resume <transfer-id>` after uncertainty or to learn acceptance;
it resends identical sealed bytes. Do not create a new send merely because an acknowledgement
was lost. Transfers are operator-approved copies, not ongoing synchronization.

Outbound admin operations require the running daemon (`federation_requires_daemon` offline).
If a transfer key is damaged and found off `active`, use `ck auth transfer init --replace`.
An active key is protected. Recovery rejects pending rows and abandons that vault's outgoing
rows, printing their ids; abandoned rows cannot resume. Use fresh sends with fresh transfer
ids. An already accepted identical envelope still deduplicates after either key changes.

### Account worker-token grants

`ck auth grant` and `revoke-grant` accept `--selector-kind audience --selector
cortexkit-runners --operation account_token` for reserved or enrolled principals.
`account_token` is valid only with `audience`; `audience` is valid only with
`account_token`. Selectors are exact, never wildcard or category coverage. For the
first consumer:

```sh
ck auth grant --principal reserved:ck-motor --selector-kind audience --selector cortexkit-runners --operation account_token
```

`ck auth grants` renders these rows with `token` in REACHES rather than a credential
count. The grant authorizes `credential.account_token`, not arbitrary signing or
retrieval of the machine key. The machine must already be enrolled by `ck account
login`; an `account_login_required` refusal means re-run that command. Service
`machine_revoked`, `machine_not_found`, and `account_not_active` also require
operator re-login. Periodic mints are in-memory only; first uses and mint refusals
are trimmable `auth_events`, not repeated HMAC-chain appends. Full wire and retry
semantics are in [the account-token wire contract](wire-contract-v1.md#12-account-worker-token-credentialaccount_token).
