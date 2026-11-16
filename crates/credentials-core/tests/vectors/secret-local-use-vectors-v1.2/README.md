# secret-local-use-vectors-v1.2

`vectors.json` is a vault-produced sample pack for `sudo`/`sudo_password` and
`ssh`/`ssh_sign`, generated and byte-pinned by
`tests/secret_local_use_vectors.rs`. All keys and material are fixed, public
**test-only** values; never use them in a real vault. The vectors directory's
existing `-text` rule in `.gitattributes` disables line-ending translation.

## Changes from v1.1

SSH requests and `ck-secret-local-use-statement/v1` statements no longer carry
`purpose`. SSH approvals bind the new statement bytes and digests. Requests with
a `purpose` member, including an empty string, are refused as `invalid_params`.
The statement tag remains v1; the pack's JSON index tag also remains
`secret-local-use-vectors-v1`.

Every sudo case, including the refused hour approval and sudo request refusals,
is byte-identical to v1.1. Deposit, listing, public keys and userauth data are
unchanged. The producer checks these against the v1.1 pack, whose directory is
still named `secret-local-use-vectors-v1/`. That directory and historical v1 and
v1.1 releases are untouched. The module permissions pack and the separately
generated Basic sign-in pack are unchanged.

`SHA256SUMS` is generated from the new `vectors.json`, in `sha256sum -c` format;
it excludes itself and this README.

## Contents

- Four cases: local and forwarded sudo password release, and local and forwarded
  SSH signing. Each includes request, statement, approval-required reply, signed
  phone approval envelope and final release/signing reply.
- A phone deposit, listing, refused sudo-hour approval and eleven request
  refusals (target/text grammar, command cap, userauth grammar, key enrollment
  and feature-switch checks).
- JSON records carry their exact compact UTF-8 bytes, unpadded base64url and
  SHA-256 digest alongside parsed JSON. Binary records use the same byte index.
  The outer `vectors.json` is pretty-printed without a trailing newline.

Invalid parameters are reported as transport errors, not an invented JSON body.
Local-use over-limit errors use class `permanent`, not the shared core
`context_overflow` class. Module contract tests pin this transport framing.

## Reproduction

Run from the repository root on Linux. With AFT's bash tool, use
`runon: "linux,8c"` and list the generated `vectors.json` and `SHA256SUMS` paths
in `return_paths` so both files reach the checkout:

```sh
CK_EMIT_SECRET_VECTORS=1 cargo test --locked -p credentials-core --features test-support --test secret_local_use_vectors secret_local_use_vectors_are_producer_generated_and_pinned -- --exact --nocapture
cargo test --locked -p credentials-core --features test-support --test secret_local_use_vectors
(cd crates/credentials-core/tests/vectors/secret-local-use-vectors-v1.2 && sha256sum -c SHA256SUMS)
```

The producer uses a fixed clock (1,700,000,000,000 ms), test keys, home member
`fed-computer:22222222222222222222222222222222`, forwarded asker
`fed-computer:11111111111111111111111111111111`, and phone fingerprint
`11111111111111111111111111111111`. It performs real deposit, card creation,
phone approval, listing and release/signing. Only random fixture identities
(incarnation, request id and grant id) are normalized before replay; production
members, digests, signatures and decisions are not replaced. At-rest ciphertext
and audit keys are not published.

The tests byte-compare fresh generation and verify `SHA256SUMS`. An independent
OpenSSL check verifies the SSH userauth signature and rejects altered packet or
signature bytes.
