# OpenCode xAI enrolment runbook

Status: RUNBOOK v1 · commands verified against branch feat/oauth-half-xai and deployed ck-auth 90b69a3 on 2026-09-19 · live enrolment RUN 2026-09-19T09:53:24Z on this host (receipt `~/.local/share/cortexkit/claustrum-instruments/2026-09-19-xai-live-enrolment.json`)

## Roll back before changing login state

Run this first:

```sh
cd packages/opencode
bun run enroll -- --provider xai --id oauth:xai --main --remove
```

Only after that succeeds, run `/login` for xAI in OpenCode, then reload the OpenCode process. The plugin refuses to serve when a tombstone remains in `auth.json` after the manifest entry is gone. That orphan refusal is intentional and lasts until `/login`; nothing else is required. Running `/login` first while the manifest entry remains produces `SplitCustody` and also refuses. Do not delete the tombstone to repair either state. Removing the manifest entry does not hot-unload fetch closures from a running process. Reload is required.

The remove command prints:

```text
Manifest entry removed. Run /login for xai in OpenCode, then reload OpenCode; local serving is not restored until both complete.
```

## Enrolment command

The deployed command surface is:

```text
Usage: bun run enroll -- --provider xai --id oauth:xai --main --min-ttl-ms <ms> --token-lifetime-ms <ms>

v1 supports only --provider xai --id oauth:xai. The manifest records local serving; --remove removes it before /login.

Options: --handle-file <path>, --manifest-path <path>, --auth-path <path>, --remove, --help
```

The documented command form has exactly one separator, as shown. Bun consumes it before argv reaches the script; the parser tolerates one more if a wrapper adds it, and refuses beyond that. Do not add separators.

Set the values from the measurement receipt, then enrol:

```sh
cd packages/opencode
MIN_TTL_MS=7200000
TOKEN_LIFETIME_MS=21599663
CLAUSTRUM_CUSTODY_LOG=off bun run enroll -- --provider xai --id oauth:xai --main --min-ttl-ms "$MIN_TTL_MS" --token-lifetime-ms "$TOKEN_LIFETIME_MS"
```

`TOKEN_LIFETIME_MS` must come from the receipt field `measured_lifetime_ms`. The tool refuses a floor greater than or equal to the supplied lifetime, but it cannot verify that the lifetime is truthful. The receipt is the evidence. The operator-ratified floor is 120 minutes, which gives a four-hour rotation period from the measured six-hour lifetime. The plugin default of 270 minutes would give a 90-minute period.

The handle file is caller-owned, regular, mode `0600`, and contains one handle: 47 characters, `ckh_` followed by 43 base64url characters, with at most one surrounding whitespace region. Symlinks, directories, mode `0644`, files over 256 bytes, two handles, and garbage are refused.

The enrolment script writes the manifest first and the OAuth tombstone second. The two writers are independently tested on purpose. When the maintainer's category-grant direction lands, retire only the manifest half. Keep the tombstone half.

## Build and install the plugin before writing the manifest

Source landing on this branch is not deployment. Complete these checks in order:

1. Build the bundle from this branch, or from master after merge.
2. Install it at `~/.local/share/cortexkit/opencode-plugin/opencode-plugin.js`.
3. Restart OpenCode.
4. Confirm the installed bundle carries the change before writing the manifest:

   ```sh
   head -1 ~/.local/share/cortexkit/opencode-plugin/SOURCE.txt
   ```

The installed `SOURCE.txt` currently says `rev=568333d built=2026-09-18T22:46:23Z`. That bundle predates the per-account `minTtlMs` change and falls back to the global 270-minute floor, producing a 90-minute period. The installed revision must be at least `78a8d9f` before enrolment.

## Create the vault record

The deployed vault/CLI is `ck-auth 0.1.2`, built from master `90b69a3` on 2026-09-07. On this host it is not on PATH: the deployed binary is the build-is-deploy checkout's `~/projects/cortexkit/claustrum/target/release/ck-auth` (the same file the running daemon's `ck-claustrum` sits beside); every `ck-auth` below means that path. Do not build in that checkout — it would rebuild the running daemon's binary in place. It lacks `mint-handle --out`, so capture the handle printed to stdout into a caller-owned file with `umask 077` and a redirect. It also lacks `remove --yes`; remove without that flag. Check `ck-auth mint-handle --help` on the deployed binary before relying on either interface, because master newer than `90b69a3` has `--out`.

For xAI on this host, pass the master key explicitly:

```sh
~/projects/cortexkit/claustrum/target/release/ck-auth login --provider xai --id oauth:xai --key-path /etc/cortexkit/master.key
```

Default keychain resolution resolves the master key after the browser callback and burns the one-time authorization code. If manual paste is needed, paste the whole callback URL from the address bar. Pasting only the code is refused harmlessly. A loopback listener may complete the callback instead.

`oauth:xai` does not exist on this host yet. The normal first login is create-only. A second login against an existing id refuses unless `--replace` is supplied. Do not add `--replace` to the first-login command.

## Measurement and revocation

The xAI access-token lifetime measured on 2026-09-19 was 6.00 hours. Three independent samples agreed: vault login lower bound 5.9999 hours, live-slot `expires − mtime` 6.0000 hours, and provider literal `expires_in: 21600`. The receipt is `~/.local/share/cortexkit/claustrum-instruments/2026-09-19T063923Z-xai-oauth-measurements.json`, with sha256 prefix `991273ec281f6778`.

Revocation measured as `predecessor_survives`: replaying a rotated-away refresh token returned HTTP 200 and a third distinct family. xAI does not revoke a predecessor refresh token on rotation. A fresh vault login therefore does not burn an older local or backed-up xAI lineage. Provider-side revocation, if wanted, is a separate operator action in the xAI console. There is no CLI for it here.

This applies to the local family in `auth.json` too: the tombstone overwrites the entry, but the refresh token it held stays valid until its own expiry in any copy that exists (backups, the pre-flip `OPENCODE_AUTH_CONTENT` of a still-running workspace child). Enrolment moves serving into the vault; it does not retire the old lineage.

To repeat the labelled measurement after a binary or provider change:

1. Log in to `oauth:xai:measure-<UTC stamp>`, never the main id.
2. Mint the handle into a 0600 scratch file. On this deployed binary, capture stdout with `umask 077` and a redirect.
3. Run refresh-free `credential.get(handle, 0)` to measure lifetime.
4. Use isolated XDG state for `/login` to create a discardable local family.
5. Rotate once, then replay R0 once to measure predecessor revocation.
6. Remove the measurement record with `~/projects/cortexkit/claustrum/target/release/ck-auth remove --id <measurement id> --key-path /etc/cortexkit/master.key`. Do not use `logout`: it leaves `needs_reauth`, which the latch monitor alarms on every 30 minutes.

The scripts are host-local at `~/.local/share/cortexkit/claustrum-instruments/xai-measure/`. They are not in this repository.

## Loader evidence

On the installed OpenCode `1.18.31`, `scripts/spikes/opencode-config-fetch.sh` measured `custom_fetch=1 shipped_refresh=0` for xAI against the canonical empty-access tombstone. The coverage arm fired first: `coverage=fired fixture=empty-access count=1`. This result is bound to OpenCode `1.18.31`. A binary update invalidates it until the spike is rerun and reports `0 fail`.

## Shared manifest acknowledgement

The manifest is shared with `anthropic-auth` and `openai-auth`. This branch adds the optional account key `minTtlMs`, a non-negative safe integer in milliseconds, only in the `xai` block. Both readers must tolerate an unknown account key in a foreign block under the PR #33 rule.

| tenant | ack | file:line checked |
| --- | --- | --- |
| anthropic-auth | ACK 2026-09-19T08:35Z, probed with a positive control (their control B fails per-row, never whole-file); writer round-trips the key; 48 h waived | reader `packages/core/src/claustrum.ts:482` (`readCustodyHandles`, provider filter at :501-506 runs before account parsing); writer `:1119` |
| openai-auth | pending at flip time; their reader skips foreign blocks before account parsing, checked by the operator side | `packages/core/src/custody-manifest.ts:255-257` @ 77c2be9 |

Fill in the acknowledgements and checked locations before enrolment.

## Consumers that read the local entry

Any monitor that reads a provider's quota from the local `auth.json` entry loses that lane when the tombstone lands. On this host Insula reads xAI quota that way. Mint it its own capability handle (a distinct handle, so revoking either side never cuts the other) and install it in its handle file BEFORE the tombstone; done in that order on 2026-09-19 (handle 09:31Z, tombstone 09:53Z) Insula's grok row flipped to `source=vault` within a second and never sampled degraded. In the reverse order the lane is dark for the gap.

Do NOT label the vault record (`set-identity --account-id`) while the local entry is a tombstone. A dedup consumer keys on the account label: with both slots unlabelled the tombstoned local lane and the vault lane collapse to one row and the serving lane wins; labelling only the vault twin splits them, publishes the dead local lane as a second row, and moves the provider out of completeness. Learned live on 2026-09-19 (seq 1674, reverted 4 minutes later at seq 1675). The unlabelled state matches deepseek and synthetic, which publish one clean row each. Labelling becomes safe only once the consumer stops enumerating a tombstoned local entry.

A custody flip logs nothing on either side: the wire is the only witness. Capture a before/after quota snapshot on purpose if the flip is to be verifiable afterwards.

## Verifying the serve

`credential.get` through the plugin writes one `served` row per provider per process to the custody log. When probing, leave `CLAUSTRUM_CUSTODY_LOG` UNSET — an empty value is treated as a file path today (claustrum#62) and the row goes nowhere. Negative control that proves the plugin is the serving path: the same request with `CLAUSTRUM_CUSTODY_DISABLE=1` fails with `xAI token refresh failed (400) invalid_grant`, because the shipped loader can only try the sentinel.

## Partial failures

Preflight refusals write nothing. A failed vault read closes the client and writes nothing. A manifest write failure writes nothing. If the tombstone write fails after the manifest write, the command prints:

```text
tombstone write failed after manifest write; manifest entry remains — run --remove before /login
```

Run the rollback command at the top of this document, then `/login`. Never restore a stale `auth.json` snapshot. It may overwrite newer material from another provider's rotation.

## Gate caveat

On Linux, `bash scripts/gate.sh` is red on one arm of master's own: `interactive import picker + real-terminal smoke` (`cortexkit/claustrum#61`). The master's test passes the command to `script(1)` positionally, which util-linux rejects. Before live enrolment, every other line must be green: floor `696 >= 696`, hermetic, and e2e `9/9`. That single red arm is #61, not a failure in this branch. This document does not claim the full gate is green.
