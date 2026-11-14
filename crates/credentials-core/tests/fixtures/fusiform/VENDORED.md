# Vendored provider list: Fusiform

Copied byte-for-byte from `cortexkit/fusiform`'s published provider list. Release binaries
embed these exact bytes; the vault reads only provider ids and display facts, never
authorization, hosts or credential groups. The `models.dev` entries originate from the
MIT-licensed models.dev catalog; Fusiform also supplies manually maintained `hand_kept`
entries.

Never edit or reformat `providers-v1.json`. To refresh it, copy the published file from a
reviewed Fusiform commit and update this table. The embedded-byte hash test in
`src/fusiform_providers.rs` checks the sha256 pin below.

| file | source URL | commit | sha256 | fetched (UTC) |
|---|---|---|---|---|
| `providers-v1.json` | <https://raw.githubusercontent.com/cortexkit/fusiform/638a4064e120332f9fe9d038eeb24eb92b3daeee/test-vectors/providers-v1.json> | `638a4064e120332f9fe9d038eeb24eb92b3daeee` | `6a8b8e086e7c14eafdfec8eb4a6294b511859ab59fedd70126236091432a20bb` | 2026-11-14 |

The initial pin, `6ee693a6b093b0d488cfb06ec2ca3bf57bbe4925`, had no provider
entry for these existing API-key rows: `kiro`, `qianfan`, `qwen-portal`,
`singularityapi-dev`, `singularityapi-tech`, `typesafe`, `yolo-auto`, `tavily`,
`kagi`, `exa`, `parallel`, `brave`, `firecrawl`, `jina`, `tinyfish`, and `searxng`.

Fusiform's revision `a1983387bd35aa56530994e837727a364aa69110` published six
additional manually maintained (`hand_kept`) identities: `kiro`, `qianfan`, `typesafe`,
`yolo-auto`, `singularityapi` (the `singularityapi-dev` row), and
`singularityapi-reserved` (the `singularityapi-tech` row).

This refresh copies 64,486 bytes unmodified and contains 244 providers. It adds
`qwen-portal` and the separate Fire Pass offering, `fireworks-fire-pass`, as
`hand_kept` identities. Fire Pass is distinct from `fireworks-ai`, with its own
key, routes and billing.

The nine search rows still await a ruling on whether Fusiform covers search
services. They have no fabricated identity;
`PENDING_FUSIFORM_PROVIDER_IDS` in `src/catalog.rs` records the pending reasons.
