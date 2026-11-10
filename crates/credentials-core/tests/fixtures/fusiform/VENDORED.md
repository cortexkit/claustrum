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
| `providers-v1.json` | <https://raw.githubusercontent.com/cortexkit/fusiform/a1983387bd35aa56530994e837727a364aa69110/test-vectors/providers-v1.json> | `a1983387bd35aa56530994e837727a364aa69110` | `72939beb21129c8f60aa53123677a957fa0d8aef99c4777638bda59d4d2cc0ed` | 2026-11-10 |

The previous pin, `6ee693a6b093b0d488cfb06ec2ca3bf57bbe4925`, had no provider
entry for these existing API-key rows: `kiro`, `qianfan`, `qwen-portal`,
`singularityapi-dev`, `singularityapi-tech`, `typesafe`, `yolo-auto`, `tavily`,
`kagi`, `exa`, `parallel`, `brave`, `firecrawl`, `jina`, `tinyfish`, and `searxng`.

This refresh copies 64,032 bytes unmodified and contains 242 providers. Fusiform
published six additional `hand_kept` identities: `kiro`, `qianfan`, `typesafe`,
`yolo-auto`, `singularityapi` (the `singularityapi-dev` row), and
`singularityapi-reserved` (the `singularityapi-tech` row).

`qwen-portal` still has no published Fusiform identity. The nine search rows await
a ruling on whether Fusiform covers search services. They have no fabricated identity;
`PENDING_FUSIFORM_PROVIDER_IDS` in `src/catalog.rs` records the pending reasons.
