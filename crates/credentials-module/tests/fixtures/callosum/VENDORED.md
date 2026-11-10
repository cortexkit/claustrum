# Vendored fixtures: callosum's reply vectors

Copied byte-for-byte from `cortexkit/callosum`, so the vault's decoders for callosum's
replies are tested against the bytes callosum's production code emits. Fixtures written
on this side would only agree with this side's own reading of the format. Never edit
these files: to refresh them, copy again from a new callosum tag and update the table and
the pins in `tests/federation/callosum_vectors.rs`.

| file | source | tag | commit | sha256 |
|---|---|---|---|---|
| `paired-devices/cases.json` | `test-vectors/paired-devices/cases.json` | `paired-devices-vectors-v1.5` | `e1dd0eb8` | `9bf5afa89ce776252e8a0e7bbadefe83799bda111da97748dce6349414f30901` |
| `paired-devices/README.md` | `test-vectors/paired-devices/README.md` | `paired-devices-vectors-v1.5` | `e1dd0eb8` | `3e1e757f5676ec002ad5ce3cb12356d22da5c581ee7ef73c08928ae8c2743b06` |
| `peer-keys/cases.json` | `test-vectors/peer-keys/cases.json` | `peer-keys-vectors-v1.0` | `48f2198f` | `8b23d3ab3a9827e4d83584ca441ea84201979ca61cbcbf1560be0fca320ef805` |

The paired-devices fixture's own static key is `8520f009…4e6a`, and its documented
member id is `fed-computer:300c9c9603b92a4b39ed3958bf924011` (the first 16 bytes of
SHA-256 over the decoded 32-byte key). The peer-keys fixture's transfer key `pub` is
deliberately short (`cc03`): callosum only bounds-checks it, and the vault must refuse
anything but exactly 64 lowercase hex.
