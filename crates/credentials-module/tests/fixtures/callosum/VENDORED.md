# Vendored fixtures: callosum's reply vectors

Copied byte-for-byte from `cortexkit/callosum`, so the vault's decoders for callosum's
replies are tested against the bytes callosum's production code emits. Fixtures written
on this side would only agree with this side's own reading of the format. Never edit
these files: to refresh them, copy again from a new callosum tag and update the table and
the pins in `tests/federation/callosum_vectors.rs`.

| file | source | tag | commit | sha256 |
|---|---|---|---|---|
| `paired-devices/cases.json` | `test-vectors/paired-devices/cases.json` | `paired-devices-vectors-v1.3` | `48f2198f` | `9f0b260a7476c468f3816031073d18de1925c94c052bfc9083af845d56749a93` |
| `peer-keys/cases.json` | `test-vectors/peer-keys/cases.json` | `peer-keys-vectors-v1.0` | `48f2198f` | `8b23d3ab3a9827e4d83584ca441ea84201979ca61cbcbf1560be0fca320ef805` |

The paired-devices fixture's own static key is `8520f009…4e6a`, and its documented
member id is `fed-computer:300c9c9603b92a4b39ed3958bf924011` (the first 16 bytes of
SHA-256 over the decoded 32-byte key). The peer-keys fixture's transfer key `pub` is
deliberately short (`cc03`): callosum only bounds-checks it, and the vault must refuse
anything but exactly 64 lowercase hex.
