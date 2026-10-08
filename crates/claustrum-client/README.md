# cortexkit-claustrum-client

Rust client for the claustrum credential vault, used by subc-supervised CortexKit
modules. The vault owns this client alongside its TypeScript client so the wire
decoders can be tested against the producer's serialized replies.

```toml
[dependencies]
cortexkit-claustrum-client = "0.1.0"
```

Construct `ClaustrumCredentialResolver::new(connection_file_path, project_root,
consumer_module_id)` and import the `CredentialResolver` trait to call it. The
resolver lazily opens a route to `claustrum`, presenting the reserved consumer
identity and launch nonce obtained through `subc_os`. Scoped calls require a
supervised process with that nonce and the corresponding vault grants; the
client does not acquire grants or enroll a consumer.

`resolve` retains handle-based reads. `get_scoped` and `status_scoped` address a
credential by its vault ID under the route's principal. `sign`, `public_key` and
`list_scoped` retain their existing request shapes. Transient retry bounds,
transport classification and deadlines are unchanged. Listing failures are
row-local: callers should account for `undecodable_credentials` and
`undecodable_grants`; the library does not log them. Missing, empty or non-string
grant fields skip that tuple instead of creating an empty-string grant.

## Provenance and migration

Copied from `prefrontal/crates/prefrontal-ckcred-client` at prefrontal commit
`9d956c09fb9a1c24634bbfa5a9e0de455e44986e` (`9d956c09f`). The source crate was
private and unpublished. Consumers should change the dependency from
`prefrontal-ckcred-client` to `cortexkit-claustrum-client`, the Rust import path
from `prefrontal_ckcred_client` to `cortexkit_claustrum_client`, and the resolver
name from `CkcredCredentialResolver` to `ClaustrumCredentialResolver`. There is
no compatibility alias. The private `CkcredConsumer` became `ClaustrumConsumer`.

### Public API before and after

The complete public name inventory before the move was:

- Type alias: `CredentialResolverFuture<'a, T>`.
- Enum: `CredentialErrorClass` (`classifier_code`).
- Structs: `CredentialResolverError` (`new`, `unavailable`, `transport`, `code`,
  `retryable`, `is_transport`), `ResolvedCredential` (`new`, `expose`),
  `CredentialStatus`, `CredentialSignature`, `CredentialPublicKey`,
  `ScopedCredentialListing`, `ListedCredential`, `ListedGrant`,
  `UnavailableCredentialResolver`, `CkcredCredentialResolver` (`new`,
  `with_live_consumer_identity`, `with_target`).
- Traits: `CredentialResolver` (`resolve`, `get_scoped`, `status_scoped`, `sign`,
  `public_key`, `list_scoped`), and the doc-hidden `CredentialGetTarget`
  (`credential_get`, `credential_get_scoped`, `credential_status`,
  `credential_sign`, `credential_public_key`, `credential_list_scoped`).
- No public free functions or constants.

After the move the inventory and signatures are identical except for
`CkcredCredentialResolver` → `ClaustrumCredentialResolver`, and the new public
field `ScopedCredentialListing::undecodable_grants: Vec<String>`. Callers using
exhaustive struct literals must supply that field (or use `..Default::default()`).
All other public names, fields and enum variants remain unchanged, including the
doc-hidden constructor and target trait.

## Producer contract tests

The original client tests are retained. Additional tests read
`../credentials-module/tests/fixtures/enrollment_wire_contract.json` at runtime
relative to `CARGO_MANIFEST_DIR`, rather than embedding or packaging it. Run them
from a checkout of the vault repository:

```sh
cargo test --locked -p cortexkit-claustrum-client
```

The fixture contains two exact `list_scoped` replies, two `credential.get`
successes and two `credential.status` successes. Both get operations serialize
the producer's `GetResult`, so the get bytes also exercise `get_scoped`. The
fixture has only prose placeholders for `get_scoped` and
`report_auth_failure` successes, and has no `sign` or `public_key` replies. No
bytes are invented for those gaps; this client has no report method or decoder.
The original signing decoder tests remain, but are not producer-fixture pins.

License: MIT.
