# Vendored catalog record signing vectors

`record.json` is an unmodified copy of the producer's published byte-level
contract vectors. Do not edit or reserialize it: re-copy from the source when
intentionally updating the contract pin.

| file | source repository and path | commit | SHA-256 |
|---|---|---|---|
| `record.json` | `cortexkit/prefrontal`, `test-vectors/ck-catalog-v1/record.json` | `10cc9ebb68446305d1451cf9ff3ef3bc98f49f99` | `279ba8405e45141ccf2edaaee2c615b0405061dc0e564b7d11f1d6d9e82b2c2f` |

The fixture's authors label its keys **TEST-ONLY**: the seeds are public and must
never be trusted outside these vectors. Test code reads the seed from this file;
no seed or private-key literal is duplicated in another source file.

`helpers.rs` adapts the fixture's trusted seed into PKCS#8 PEM for the vault's
existing Ed25519 signer. It is included only by tests. The core tests pin the
entire file hash and compare every valid vector's deterministic signature bytes.
The daemon test exercises one vector through the real `credential.sign` request
dispatcher with per-signature auditing enabled. These tests exercise signing,
not catalog parsing, canonicalization, trust selection, or archive validation.
