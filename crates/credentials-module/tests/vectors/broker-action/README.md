# Vault broker-action samples

`cases.json` is an ordered transcript of the vault's mint, approve, and token handlers.
Each case names the operation, route, clock time, request params, and the actual frame
kind and response body. The oversized mint omits its request params and describes how to
build them. Cases that change vault state (for example, switching the active policy or
filling the pending queue) use the setup in `broker_action_samples_tests.rs`.

The last part of each phone route label says whether the route identifies the phone's build
as production or development. The pack includes the fixed test phone's public key in
uncompressed SEC1 form; the phone approval samples contain actual DER P-256 signatures
over the decoded envelopes. Field values, scope references, and issued GitHub tokens are
synthetic test data.

From the repository root, regenerate the sample bytes and their `SHA256SUMS` with:

```sh
CK_EMIT_SECRET_VECTORS=1 cargo test --locked -p credentials-module --bin ck-claustrum \
  broker_action_samples_regenerate_byte_for_byte
```

Without `CK_EMIT_SECRET_VECTORS=1`, the test compares both files byte for byte.
