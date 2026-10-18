# Vendored account machine exchange

Copied byte-for-byte from `cortexkit-account` commit
`ad8e471590a71f626dde236818c8b6229a122a7f`, source directory
`crates/account-cli/tests/fixtures/machine-key/` (2026-10-18).
`SOURCE` preserves its upstream cloud commit provenance. Tests read only these
local copies; no sibling checkout is needed. All cryptographic material is public
RFC 8032 test material, not deployment credentials.

| File | SHA-256 |
| --- | --- |
| README.md | 725ac9bdcf20af7e4016e34f3dba5a5d4edaf4e291da9b0ba65a27b7d0065151 |
| SOURCE | 708abadbb974ea820586b235295bdf0f2a96589d282c9cf4526df3955fc56cc6 |
| machine-key-contract.md | 1e7fc59c7546db464dc4b60d042f42d4ed129b37a30003377860c8e8fe3e4de8 |
| vectors.json | 1018385d6b632d74fe6c6d63ed1ec07554889483bbe628da6e7a1cf27b5380f1 |
| refusals.json | 98041300fda819e6ffd526460ada9731140541b5c33780538a9e42dd4543c4ce |

`machine.json` is a local synthetic fixture pinning the account CLI's `Machine`
shape (`crates/account-cli/src/machine.rs` at the same commit, SHA-256
`6c803075b28921fc73c3270208cf6ad54954b9015396a88e0c63b337a8661132`).
The signer reference (`src/machine_signer.rs`) had SHA-256
`afd7f9f9aea9c0dd5faa3b5c51fb66443fb151b78c36c32cd0232bbab14c79af`.

The contract and vectors include `cortexkit-runners`; the CLI's
`worker_transcript` audience allowlist still contains only `cortexkit-account`
and `cortexkit-webhook-relay`. The vault follows the normative contract and vectors,
including runners, while retaining the CLI's pre-signing challenge binding checks.
