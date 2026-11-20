# Vault hub wire samples, v1

`samples.json` contains one `vault-shared-logins` value and one
`vault-manifest-active` value. Each `value` string is the exact UTF-8 JSON that
would be stored at the corresponding `key`. The fixture also carries the raw
X25519 sender public key and recipient private bytes, the exact login plaintext,
and the raw Ed25519 writer public key. All keys are test-only; never use them in
an installation.

Run the independent verifier with Node (no packages required):

```sh
node crates/credentials-module/tests/fixtures/hub-wire-v1/verify.mjs
```

The verifier opens the Auth-mode login seal, checks the report signature, and
confirms that changing the authenticated AAD or signed body bytes breaks
verification. The samples use the maximum login `generation` and report `seq` to
show the different wire types. The report's invalid verdict carries only the public
reason `reported_invalid`.

Regenerate from the Rust wire producers when the contract changes:

```sh
CK_EMIT_HUB_WIRE_SAMPLES=1 cargo test --locked -p credentials-module \
  --features credentials-core/test-support --bin ck-claustrum hub_wire_samples_preserve_producer_bytes
```

A new login seal uses a fresh ephemeral key, so its ciphertext and encapsulated
key change on regeneration. The Rust test normally opens the checked-in value
and compares its AAD and plaintext to the current producer. The Ed25519 report is
deterministic and is compared byte for byte.
