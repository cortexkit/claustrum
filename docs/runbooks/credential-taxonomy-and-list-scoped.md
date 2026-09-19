# Credential taxonomy and `list_scoped` deploy runbook

Status: implementation and deployment record for schema migration 9.

## Slice opening reads (completed before implementation)

1. **OR-1 — v0.1.2 audit reader.** Released v0.1.2 (`10dbfd4`) keeps
   `AuditEntry.op: String`; `verify_chain` MACs `e.op` as that string. The published,
   CI-built release artifact was downloaded and its sidecar checksum passed before it
   executed. `ck auth verify-audit` returned `intact` (rc 0) at schema 8 and with the
   ledger bumped to 9. A `set_category` spelling therefore needs no compatibility alias.
2. **OR-2 — deposit arms and insert site.** `admin_ops::apply` sends `StoreMode::Create`
   to `EncryptedStore::create_audited`, the sole `INSERT INTO credentials` site.
   `ReplaceUnconditional` and `StoreWithIdentityPolicy` are update-only and return
   `NotFound` for an absent id. This falsified the folded draft's upsert belief and was
   escalated. The owner retained the fail-closed existing-id contract; default categories
   and id reservation live at `create_audited`, while `apply` also performs the same id
   reservation before every replace arm so an invalid id has one refusal across modes.
3. **OR-3 — admin schema check and discriminator.** The authenticated pre-dispatch check
   is `AdminSurface::dispatch`; serde uses `#[serde(tag = "op")]` and explicit
   `admin.snake_case` rename strings. Dispatch now checks the exhaustive variant/version
   table: shipped variants require v1 and exactly the four taxonomy variants require v2.
4. **OR-4 — catalogs.** The API-key catalog has 15 entries:
   `apikey:zai`, `apikey:openrouter`, `apikey:deepseek`, `apikey:cerebras`,
   `apikey:fireworks-ai`, `apikey:groq`, `apikey:mistral`, `apikey:together`,
   `apikey:perplexity`, `apikey:moonshot`, `apikey:huggingface`, `apikey:nvidia`,
   `apikey:xai`, `apikey:openai`, `apikey:google`. The login catalog has 11:
   `oauth:anthropic`, `chatgpt:openai`, `oauth:xai`, `copilot:github`, `oauth:kimi`,
   `oauth:google`, `antigravity:google`, `oauth:cursor`, `oauth:devin`,
   `oauth:snowflake`, `oauth:digitalocean`. The sets are disjoint. Both catalogs now
   live only in `credentials-core`; source-ownership tests reject bin-local copies.
5. **OR-5 — connection and fencing.** No credentials connection setup enables
   `PRAGMA foreign_keys`; a normal fixture reports it off. `EncryptedStore::fenced_write`
   delegates one transaction closure to `SqliteStore::with_conn_fenced`; a competing
   writer is serialized by that whole transaction and a stale epoch latches the store
   fenced out. Category ownership therefore uses explicit deletes and does not rely on
   cascade enforcement.
6. **OR-6 — state spelling.** `RecordState::as_str()` already exists and returns exactly
   `active`, `needs_reauth`, `retired`, `corrupt`. The view encoder uses this accessor.
7. **OR-7 — admin status shape.** `status_result` returns aggregate health fields,
   `credentials`, and `read_grants`. Credential rows previously contained id/state/version;
   migration 9 adds sorted `categories`. Grant rows now also carry `selector_kind` and
   compute covered ids according to their selector kind.
8. **OR-8 — scoped coverage call sites.** `credential.sign`, `credential.public_key`,
   `credential.get_scoped`, and addressed `credential.status` all call
   `ReadSurface::authorize_scoped`, which now calls only `evaluate_scoped_coverage`.
   Record-level refusals remain `kind_not_signable` for sign/public-key kind mismatch,
   `kind_not_gettable` for get on a signing record, and `needs_reauth`/`corrupt` for
   lifecycle failures.
9. **OR-9 — live id reservation.** Measured 2026-09-19T00:04:37Z through a mode=ro
   SQLite connection: 60 credentials; byte-exact lowercase `category:` prefixes: 0;
   ids containing `|`: 0. The same two counts over `read_grants.credential_prefix` and
   `auth_events.credential_id` were 0/0. Positive controls: 17 `apikey:` ids and 60/60
   ids containing `:`. The migration reservation is safe to deploy.
10. **OR-10 — absent read params.** `ReadRequest.params` has `#[serde(default)]`; absent
    params become JSON null. `ListScopedParams {}` deliberately does not default, so both
    absent params and explicit null fail its decode as `invalid_params`; only `{}` works.
11. **OR-11 — migration runner.** The migration chain is a declarative
    `Migration { version, statements }` array with no SQL predicate/refusal hook.
    `EncryptedStore::migrate` is reachable before the runner and now performs the
    byte-exact Rust guard there, before migration 9 or its version ledger write.
12. **OR-12 — snapshot API.** `SqliteStore::with_conn` exposes one connection and
    rusqlite's `unchecked_transaction()` is already used for multi-statement operations.
    `list_scoped_snapshot` opens one deferred read transaction, loads grants, candidates,
    categories, metadata, and envelope bytes there, then commits before returning.
13. **OR-13 — released rollback surfaces.** Executed the checksummed published v0.1.2
    artifact (`10dbfd4`). At schema 9: `verify-audit`, `grants`, `list`, `usable`, and
    `events` all returned rc 0. At that tag, `verify-audit`/`usable`/`events`/`audit` are
    lease-free reads; `grants`/`list`/`status` resolve the key but still do not consult the
    schema ledger. The draft's read-write refusal belief was false: v0.1.2 `put` succeeds
    on a store-ahead ledger because the refusal landed later at `560073d`. The rollback
    baseline for migration 9 is therefore the next release cut at or after `560073d`, not
    v0.1.2. v0.1.2 remains the executable audit/read compatibility floor only.
14. **OR-14 — auth-event subject.** `auth_events.credential_id` is `TEXT NOT NULL` with
    no foreign key. Trimming is keyed by that exact value and capped at 64 rows. The CLI
    renderer treats it as an ordinary string and the cap report groups by it. The literal
    `credential.list_scoped` is therefore a bounded, renderable subject; rejected
    principals use it, and accepted principals never write an event.

## Owner-supplied catalog policy

The closed category vocabulary is `llm-provider`, `data-warehouse`, and
`cloud-infrastructure`. Every API-key entry is `llm-provider`. Login entries are
`llm-provider` except Snowflake (`data-warehouse`), DigitalOcean
(`cloud-infrastructure`), and Devin (uncategorized). `ModelVendor` is a separate closed
advisory vocabulary. The assignments are literal per-entry catalog fields; no key-derived
fallback or default builds either list. Exact-value tests pin all 26 rows.

## Deploy and rollback

1. Build and retain a rollback artifact from the first release at or after `560073d`.
   That is the minimum safe read-write rollback baseline: v0.1.2 can inspect a version-9
   store but does **not** refuse writes to one. No rollback procedure may ask v0.1.2 to
   open a version-9 store read-write.
2. Start the new binary. Migration 9 rebuilds `read_grants` with `selector_kind` in its
   primary key and creates empty `credential_categories`.
3. If migration refuses and names lowercase `category:` credential ids, stop. With the
   old store still at version 8, remove those exact ids using the previous binary, then
   retry migration. The predicate is case-sensitive: `Category:example` is not offending.
4. Run `ck auth reclassify --from-registry` once as the post-migration Gate-2 step, then
   inspect both `ck auth list` and `ck auth grants`. Migration itself never classifies.
5. Reclassification refills an empty set. Therefore a category set deliberately cleared
   by an operator stays empty during re-login, but a later explicit reclassify restores
   the registry default. Keep it empty by not rerunning reclassify, or clear it again
   afterward. `--force` replaces non-empty differing sets and is silent when unchanged.
6. Rollback is bounded: the safe rollback release refuses a read-write open when the
   schema ledger is newer than its chain. Restore the matching store backup or roll
   forward. v0.1.2 may be used only for the executable read/audit compatibility checks
   above, never as migration 9's write-capable rollback binary.
