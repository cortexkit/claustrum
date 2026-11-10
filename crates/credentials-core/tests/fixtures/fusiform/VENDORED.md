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
| `providers-v1.json` | <https://raw.githubusercontent.com/cortexkit/fusiform/6ee693a6b093b0d488cfb06ec2ca3bf57bbe4925/test-vectors/providers-v1.json> | `6ee693a6b093b0d488cfb06ec2ca3bf57bbe4925` | `7bd2e5f088732c140d5d7b0402b168b13a329edb0b763f7fb155db91bf628739` | 2026-11-10 |
