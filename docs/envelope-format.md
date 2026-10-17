# Vault envelope format parameters

Every vault record, and the sealed audit key, is stored as one cipher envelope
(`crates/credentials-core/src/envelope.rs`). The values below are written into stored
data or recomputed when it is read. Changing any of them makes every existing vault
unreadable, and there is no migration path short of a deliberate, versioned format bump.

They are pinned by the known-answer tests in `envelope.rs` (`mod known_answer`), which
open an envelope written by an earlier build and assert the AAD and key-id bytes
literally. If one of those tests fails, the change under test breaks existing vaults:
undo it. Do not regenerate the fixture.

The domain-separator STRINGS (`cortexkit-credentials/envelope-aad/v1`,
`cortexkit-credentials/key-id/v1`, and the rest) are listed separately in
`docs/domain-separators.txt`, which `scripts/endpoint-hosts.py` derives from source.

## Envelope blob

| bytes | field | value |
|---|---|---|
| 0 | magic | `0xC7` (`MAGIC`) |
| 1 | cipher_version | `0x01` = XChaCha20-Poly1305 (`CIPHER_VERSION_XCHACHA20POLY1305`) |
| 2..10 | key_id | 8-byte master-key fingerprint (`KEY_ID_LEN`) |
| 10..34 | nonce | 24 random bytes, fresh per seal (`NONCE_LEN`) |
| 34.. | ciphertext + tag | the AEAD output; the last 16 bytes are the Poly1305 tag (`TAG_LEN`) |

## Additional authenticated data

```text
AAD = LP(domain) || LP(cipher_version) || LP(key_id) || LP(credential_id) || LP(record_version)
```

- `LP(x)` is the length of `x` as a **u32, little-endian**, followed by the bytes of `x`.
- The fields appear in exactly this order.
- `domain` is `cortexkit-credentials/envelope-aad/v1`.
- `cipher_version` is the single byte `0x01`.
- `credential_id` is the record id's UTF-8 bytes.
- `record_version` is the record's version as a **u64, little-endian** (8 bytes).

## Key id

```text
key_id = SHA-256(domain || master_key)[0..8]
```

- The domain label is hashed **first**, then the 32 key bytes. `domain` is
  `cortexkit-credentials/key-id/v1`.
- Stored columns render it as 16 **lowercase** hex characters (`KeyId::to_hex`).
