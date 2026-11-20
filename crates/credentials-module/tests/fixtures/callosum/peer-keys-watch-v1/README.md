# `callosum.peer_keys_watch` samples (v1)

`cases.json` comes from the production watch and read handlers, backed by a
fixture pairing and stored hello key records. `notices` contains the complete
notice bodies emitted for each step. The two key changes follow the open
notices on the same watches; an empty `notices` array means no notice was sent.
The not-ready case instead records the final `refusal`.

Regenerate with:

```sh
UPDATE_PEER_KEYS_WATCH_VECTORS=1 cargo test --locked -p fed-module --lib peer_keys::tests::vectors_match_production -- --exact
```
