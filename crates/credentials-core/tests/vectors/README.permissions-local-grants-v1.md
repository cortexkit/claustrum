# Local-program permissions samples

`permissions-local-grants-v1.json` contains one real `permissions.list` reply with
one sudo once grant held by an agent and one SSH session grant held by a worker.
The module dispatcher emits the reply after the normal phone approval path mints
both grants. Only generated grant ids and wall-clock grant timestamps are fixed
for reproducibility; targets, holders, duration, card reference and SSH fingerprint
come from the approved requests and stored grants.

Each case includes the request, the exact reply bytes as unpadded base64url, their
SHA-256 digest, and the decoded JSON. The companion
`permissions-local-grants-v1.SHA256SUMS` pins the complete sample file. Verify it
with `sha256sum -c permissions-local-grants-v1.SHA256SUMS` from this directory.
The existing `permissions-credential-grants-v1.json` corpus remains unchanged.

Regenerate on Linux from the repository root:

```sh
CK_EMIT_SECRET_VECTORS=1 cargo test --locked -p credentials-module \
  --features credentials-core/test-support \
  permissions_local_grants_dispatcher_pins_real_approval_samples -- --nocapture
```

Without the environment variable, the same test compares the producer's output
byte-for-byte with the published sample and verifies the checksum file.
