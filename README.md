# cortexkit-credentials

A subc-supervised module that holds credentials (OAuth tokens, API keys, DSNs)
**encrypted at rest** and serves each consumer the credential it needs, **kept
fresh** via vault-owned OAuth refresh. One custody home replacing scattered
per-consumer credential acquisition (llm-runner's `auth.json` read,
ai-provider-quota's bespoke OAuth paths, the future CortexKit app's login/import).

This is a **security boundary**. See:
- [`docs/cortexkit-credentials-contract.md`](docs/cortexkit-credentials-contract.md)
  — the normative security contract (three adversarial review passes).
- [`docs/charter.md`](docs/charter.md) — the build plan and ground rules.

## Layout

- `crates/credentials-core` — custody logic, wire-agnostic: typed `VaultRecord`,
  canonical `OAuthCredential`, value-level encryption envelope, bounded refresh
  adapters, crash-safe refresh state machine, master-key resolution.
- `crates/credentials-module` — the thin subc-wire binary: anonymous read surface,
  master-key-gated admin surface, capability handles, fault isolation, write-audit.

## Development

Path-deps two sibling repos checked out alongside this one:
`../subconscious` (subc wire + daemon) and `../commons` (storage libs). Build with
`cargo check --workspace` from the repo root.
