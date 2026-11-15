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
| `providers-v1.json` | <https://raw.githubusercontent.com/cortexkit/fusiform/2b875148e286d14c2747cf29ddcf1ec7ebebd63a/test-vectors/providers-v1.json> | `2b875148e286d14c2747cf29ddcf1ec7ebebd63a` | `3db86c16575e35ff7d54fdc81416f36c4fd71b581bc36b9c79e1a76ff42461ed` | 2026-11-15 |

The initial pin, `6ee693a6b093b0d488cfb06ec2ca3bf57bbe4925`, had no provider
entry for these existing API-key rows: `kiro`, `qianfan`, `qwen-portal`,
`singularityapi-dev`, `singularityapi-tech`, `typesafe`, `yolo-auto`, `tavily`,
`kagi`, `exa`, `parallel`, `brave`, `firecrawl`, `jina`, `tinyfish`, and `searxng`.

Fusiform's revision `a1983387bd35aa56530994e837727a364aa69110` published six
additional manually maintained (`hand_kept`) identities: `kiro`, `qianfan`, `typesafe`,
`yolo-auto`, `singularityapi` (the `singularityapi-dev` row), and
`singularityapi-reserved` (the `singularityapi-tech` row).

An earlier refresh copied 64,486 bytes unmodified and contained 244 providers. It added
`qwen-portal` and the separate Fire Pass offering, `fireworks-fire-pass`, as
`hand_kept` identities. Fire Pass is distinct from `fireworks-ai`, with its own
key, routes and billing.

Revision `638a4064e120332f9fe9d038eeb24eb92b3daeee` published the nine search
identities and BytePlus, bringing the list to 254 providers.

The current refresh copies 66,976 bytes unmodified and contains 255 providers.
Its only entry change is the addition of the manually maintained `kimi-for-coding`
web-search offering, "Kimi Code". The existing Kimi Code key keeps its
`kimi-code-plan-global` model identity and routing defaults. The search offering is
recorded in `FUSIFORM_PROVIDER_SKIPS` in `src/catalog.rs`. Search routing does not
select credentials by provider id, so the key does not need the search offering id.
