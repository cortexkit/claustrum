# Machine-key exchange contract

The account service's machine-key exchange lets `ck account` enroll a per-machine Ed25519 key
once, then mint short-lived worker tokens by possession proof instead of another ordinary login.
The existing GitHub browser ceremony is unchanged. Passkey, Apple, email and Google browser
adapters also implement enrollment and step-up, but refuse until their individual enable is
exactly `true`. Adapter implementation and passing server tests are **not cutover approval** or
evidence of real-browser or provider-console support. Google device-code machine enrollment is
unsupported. The `ck account` client is unchanged; nothing here is evidence of client support
for the new methods. Ordinary account login and rendezvous device-token renewal remain separate
protocols; the ordinary-login start intent refusals below do not change successful login flows.

The normative source is the reviewed revision 6 of
`.cortexkit/internal-docs/designs/device-credential-exchange.md`: B.1–B.9 define the protocol;
**“B.10 Required vectors and races”** defines its release obligations. Method enablement requires
the separate operator evidence in the account-service runbook, not just the server merge gate.
[account-service.md](account-service.md#machine-key-lifecycle) describes storage and deployment;
[webhook-relay.md](webhook-relay.md#machine-parents-permits-and-step-ups) describes consumers.

## Origins, authentication and formats

Account routes use `https://account.cortexkit.io`; relay routes use `https://hooks.cortexkit.io`.
Authenticated routes use `Authorization: Bearer <JWT>`. Dangerous human DELETEs additionally
use `CK-Step-Up: <attestation>` and have **no body**. No caller-supplied account/principal header
is trusted. Human actors are distinct from machine actors, even when the signing key is shared.

All Part B JSON bodies are exact: reject missing/unknown members, duplicate members (including
escaped spellings), wrong types and more than 8 KiB. Formats are checked before verifying a signature or spending any one-use authorization.
Do not normalize a noncanonical input into a value that verifies.

| Field | Format |
| --- | --- |
| Account, key id, flow id, request id, JTI | Canonical uppercase ULID, `[0-7][0-9A-HJKMNP-TV-Z]{25}`. |
| Ed25519 public key / signature | Raw 32 / 64 bytes as 64 / 128 lowercase hex characters. Invalid and small-order public keys refuse. |
| Key fingerprint | Lowercase SHA-256 hex of the decoded 32-byte public key, never its hex text. |
| Label | Nonempty valid UTF-8, at most 64 bytes, no controls or `\|`; label hash is SHA-256 of those exact UTF-8 bytes. |
| `replaces` | Required JSON `null` or canonical key id. Transcripts use `-` for null. |
| Nonce, open token, raw completion code, handoff secret | 32 random bytes as canonical unpadded base64url (43 characters). Hash decoded bytes, not encoded text. |
| Paste user code | Eight uppercase Crockford base32 characters displayed `XXXX-XXXX`; this is not a completion code. |
| Handoff | `paste` or `loopback`, immutable at start. Loopback port: integer 1024–65535; host is literal `127.0.0.1`. |
| Audience, purpose, relay source | Exact allowlisted case-sensitive literals. Relay source is currently only `github`, independent of the authentication method. |
| `_ms` times | Safe-integer Unix milliseconds, not date strings. |
| JWT `iat`, `exp`, `auth_time` | Safe-integer Unix seconds. No expiry grace; worker verification allows `iat` at most 60 seconds in the future. |
| Sequences / event heads | Positive safe integers; head may be zero. No counter wrap or reset. |

Transcripts are UTF-8 with literal ASCII `|` separators and **no trailing newline**. The sealed
challenge is signed exactly as returned, including its MAC. SHA-256 target/request hashes use
RFC 8785 JSON canonicalization (JCS), not ordinary JSON serialization. An absent DELETE body
hashes canonical `{}`: `44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a`.

## Enrollment and raw-code completion

Only existing linked, active human accounts are eligible; these adapters never create accounts,
identities or passkeys. GitHub uses its linked numeric subject, Google and Apple their linked
`sub`, and passkey a stored `webauthn_credentials` row (not `userHandle`). Email requires an
`identities` row with `provider = 'email'` and the normalized address as subject; an email column
on another provider is not a link. GitHub installation ownership is not a login identity.
The new methods' link must still hold after fresh authentication: if the passkey, or the
Google, Apple or email identity, is removed or moved to another account, the Confirm page,
Confirm, the completion challenge and completion refuse 401 `auth_failed`, even while the
account stays active.
Machine inventory is independent of rendezvous devices: retiring one does not remove the other.

1. Generate the key locally. For loopback, bind an exclusive listener **before** starting.
   `POST /v1/machine/enroll/start` takes
   `{method:"github"|"passkey"|"apple"|"email"|"google",ed25519_pubkey_hex,label,replaces,handoff_mode,loopback_port?,handoff_secret?}`.
   Paste forbids port/secret; loopback requires both. Reply:
   `{flow_id,open_token,approval_url,comparison_phrase,paste_user_code?,expires_at_ms}`.
2. Open `approval_url`, which is `GET /v1/machine/enroll?flow_id=…&open_token=…`.
   The first browser claims the flow with a Secure, HttpOnly, SameSite=Lax, host-only cookie.
   Flow id or poll knowledge alone cannot open/approve it; any second open after claim refuses.
   Open dispatches by stored method to GitHub, the first-party passkey/email page, or the Google/
   Apple authorize URL. The GitHub CortexKit App still uses client id `Iv23liYJYQDHNotesltr` and
   pins `https://account.cortexkit.io/v1/login/github/callback` at authorization and exchange.
   Those GitHub pins do not gate other methods.
3. Provider authentication alone is not confirmation. New methods reach the shared
   `GET /v1/machine/auth/confirm`; GitHub retains its inline callback Confirm page.
   Fresh authentication rotates the claiming cookie. The first-party page shows account ULID,
   full fingerprint, label, persistent-access warning, exact replacement, comparison phrase,
   mode and start time. Compare these to the initiating terminal and explicitly Confirm or Cancel.
   Confirmation is a native form to `POST /v1/machine/enroll/confirm` with URL-encoded
   `{flow_id,csrf,action,paste_user_code?,mailbox_ack?}`, not JSON. It requires the fresh-auth
   browser session, CSRF and exact account Origin. Email Confirm also shows the verified address
   and mailbox-authorizer warning and requires `mailbox_ack=acknowledged`; other methods reject
   that field. Cancel does not require it. Paste reveals a completion code only after typing the
   terminal's short user code and confirming; five wrong attempts lock the ceremony.
4. Loopback Confirm returns a top-level 303 to
   `http://127.0.0.1:<port>/machine-enroll/complete?flow=<flow_id>&secret=<handoff_secret>&code=<completion_code>`.
   The CLI must check exact initiating port/path/flow/secret, refuse wrong/duplicate callbacks
   without consuming a later valid one, and scrub the successful local page's query/history.
   Use no-store, no-referrer, restrictive CSP, no scripts/assets or secret-bearing logs. Do not
   downgrade failed loopback to paste. Remote flows cannot hand back off-host. These listener
   protections are client obligations, not Worker tests; another local user's own listener is
   outside the loopback guarantee. Failed navigation may retain only bounded URL residue.
5. `POST /v1/machine/complete/challenge` takes `{flow_id,completion_code}` and returns
   `{challenge,expires_at_ms}`. The **raw** code is required here and at
   `POST /v1/machine/complete`, whose body is `{flow_id,completion_code,challenge,sig_hex}`.
   Possessing the proposed private key, all start/poll secrets and a captured code hash/challenge
   still cannot complete without the raw code. Sign:

   ```text
   cortexkit-machine-complete|v1|account.cortexkit.io|<account>|<flow_id>|<key_fingerprint>|<completion_code_hash>|<challenge>
   ```

   Read the account ULID from the sealed payload. Completion spends raw-code authority and proof
   in one transaction and returns `{jwt,attestation}`. The attestation's `iat` is fresh-auth time,
   `exp = iat + 300`; neither confirmation nor handoff resets it. The completion deadline is the
   earlier of confirmation +300 seconds and fresh authentication +300 seconds, and caps its
   challenge. If the completion reply is lost, obtain a new purpose-bound login and first-party confirmation
   rather than replaying the completion request.
6. `POST /v1/machine/keys`, authenticated by the returned human JWT, takes
   `{attestation,ed25519_pubkey_hex,label,replaces,sig_hex}`. Sign:

   ```text
   cortexkit-machine-enroll|v1|account.cortexkit.io|<account>|<ed25519_pubkey_hex>|<attestation_jti>|<replaces_or_dash>|<label_hash>
   ```

   The attestation is `ck-machine-enroll+jwt`, audience `cortexkit-account:machine-enroll`, with
   exact claims `{iss,aud,account,purpose,flow,key_fingerprint,label_hash,replaces,iat,exp,jti}`;
   `purpose` is `machine_enroll`. The tuple cannot change after approval or signing. Reply:
   `{key_id,created_at_ms}`. At most 20 live keys are allowed; exact replacement provides one
   slot credit only for its winner. A concurrent loser leaves no successor, spend, result,
   fingerprint, fence or outbox event. Retrying the successful `POST /v1/machine/keys` with the same signed attestation/key/label/replacement
   tuple returns the original result.
   Retired fingerprints are permanent across revocation, replacement, cleanup, merge and deletion,
   and cannot re-enroll under any account. A merge retires secondary keys, never transfers them.

Completion, possession transcripts, hand-back and the enrollment and step-up attestation claim
sets are unchanged across methods. Stored flow kind, method and successful attempt bind the
ceremony; method and kind are not new token claims. There is no second completion endpoint.

### Browser authentication routes (B.8)

All inputs are exact, including GET query members: reject unknown/duplicate members and more
than 8 KiB. Except for Apple's cross-site receipt ingress, browser POSTs require the exact
first-party Origin, claiming session and current CSRF token. Pre-auth pages rotate
`preauth_csrf_hash`; only after fresh auth does Confirm GET rotate `csrf_hash`. A pre-auth
token cannot approve a machine. `confirm_url` is always
`/v1/machine/auth/confirm?flow_id=<flow_id>`, never a caller-selected redirect.

| Endpoint | Exact input and result |
| --- | --- |
| `GET /v1/machine/auth/confirm` | Query `{ flow_id }`; fresh-authenticated claimed flow only. Render script-free Confirm posting to existing `/v1/machine/enroll/confirm`; stored kind selects enrollment or step-up wording. |
| `GET /v1/machine/auth/passkey` | Query `{ flow_id }`; claimed flow only, isolated WebAuthn page with per-response-nonce CSP. |
| `POST /v1/machine/auth/passkey/options` | JSON `{ flow_id, csrf }`; return `{ auth_attempt_id, publicKey }`, authentication options only. For step-up, `allowCredentials` lists only the authenticated human actor's stored passkeys. |
| `POST /v1/machine/auth/passkey/verify` | JSON `{ flow_id, csrf, auth_attempt_id, credential }`; return `{ confirm_url }` only after guarded fresh-auth success. |
| `GET /v1/machine/auth/email` | Query `{ flow_id }`; claimed-browser address/code forms without identity disclosure. |
| `POST /v1/machine/auth/email/send` | Form `{ flow_id, csrf, email }`, also for explicit resend; recipient must equal the first normalized input. Return 303 to the fixed email page with that flow id and the same generic “If eligible, a code was sent” form, even for ineligible identities or delivery failure. Rate limits still return 429. |
| `POST /v1/machine/auth/email/verify` | Form `{ flow_id, csrf, code }`; check the current server-selected attempt, then 303 to `confirm_url`. Failure does not reveal account existence. |
| `GET /v1/login/google/callback` | Query `{ state, code }` or denial `{ state, error }`, plus only the optional provider fields below. Require pinned URL, method/kind and claiming session before state use. Success 303 to `confirm_url`; denial is `consent_denied`. |
| `POST /v1/machine/auth/apple/callback` | URL-encoded success `{ state, code }` with optional unsigned `user`, or denial `{ state, error }` with optional `error_description`. Store an encrypted receipt and return 303 to resume; no authentication or token exchange yet. |
| `GET /v1/machine/auth/apple/resume` | Query `{ receipt }`; require original claiming browser and render only a Continue form, with no exchange. |
| `POST /v1/machine/auth/apple/resume` | Form `{ flow_id, csrf, auth_attempt_id, receipt }`; exact tuple match, one receipt/state reserve and exchange. Success 303 to `confirm_url`. |

Google success additionally permits only `scope` (ASCII, at most 2048 bytes), `authuser` (1–3
decimal digits), `prompt` (ASCII, at most 64 bytes), `hd` (ASCII, at most 253 bytes) and `iss`
(`accounts.google.com` or `https://accounts.google.com`). Verify `iss` when present; otherwise
these fields are ignored, never identity, authority, redirects or HTML. Denial additionally
permits only `error_description` (at most 1024 UTF-8 bytes) and `error_uri` (at most 2048 ASCII
bytes), neither rendered nor followed. Passkey `credential` is a bounded standard WebAuthn
AuthenticationResponseJSON, not registration data; `userHandle` never selects the account.

Google uses `GOOGLE_BROWSER_CLIENT_ID` and `GOOGLE_BROWSER_CLIENT_SECRET`, the pinned
`https://account.cortexkit.io/v1/login/google/callback`, S256 PKCE and an OIDC nonce, not device
login credentials. Apple uses `https://account.cortexkit.io/v1/machine/auth/apple/callback`,
`response_mode=form_post` and `response_type=code`, not `code id_token`. New OAuth state is
`ck-machine-auth.v1.<flow_kind>.<method>.<flow_id>.<random>`; GitHub retains
`ck-machine-enroll.v1.<flow_id>.<random>` for both kinds.

Google and Apple have one authorization attempt per flow, created at open. Denial or a failed
exchange/verification in the claiming browser terminates it; restart with a new flow id rather
than replaying a callback. A verified ID token must also still be unexpired when fresh
authentication is recorded; one that expires in between refuses 401 `auth_failed` and ends the
attempt. A cookie-less Google callback cancels nothing. Apple ingress needs
no claim cookie, Origin or CSRF, spends no state and sets no fresh auth or completion code;
only resume POST in the claiming browser can authenticate. At most three receipts are accepted
per attempt; the fourth is 429 `rate_limited` without changing the attempt.

Passkey options and email send allow up to three attempts per flow. Machine email codes are
exactly eight decimal digits as a string, expire after at most 300 seconds (also capped by the
flow deadline), and lock the flow on the fifth wrong guess. Ten failed guesses per address in
15 minutes lock machine verification for 15 minutes; a new flow cannot bypass that lock.
Machine and ordinary email sends count toward the same limits: five sends per address and
twenty per IP in 15 minutes.
An ineligible identity receives the same generic page and non-authorizing attempt, with no mail
sent. Machine codes are not ordinary login codes, paste user codes or completion codes.

The five ordinary-login start routes refuse `machine_enroll`, `step_up` and unknown intents
with 403 `enrollment_method_unsupported`, regardless of the master switch. Omitted intent,
`link`, `link_primary`, `engram_enable`, `mint_service`, `catalog_key` and `raise_ceiling` keep
their existing behavior. Poll, verify and the ordinary Apple/passkey callbacks are unchanged.

## Lost enrollment reply recovery

`POST /v1/machine/keys/recover/challenge` takes exactly
`{account,key_fingerprint,jti,replaces,label_hash}`. It returns `{challenge,expires_at_ms}`.
`POST /v1/machine/keys/recover` adds `ed25519_pubkey_hex`, `challenge`, `sig_hex`. Sign:

```text
cortexkit-machine-recover|v1|account.cortexkit.io|<account>|<key_fingerprint>|<jti>|<replaces_or_dash>|<label_hash>|<challenge>
```

Each recovery requires fresh possession and a new one-use proof; no human JWT is required.
It returns exactly the committed `{key_id,created_at_ms}`, even after enrollment attestation
expiry or with issuance disabled, **only while the originally enrolled key and its original active-human account remain live**. It never
re-enrolls, extends authority, re-revokes a replacement or substitutes the merged account.
Missing results refuse `enrollment_not_found`; a retired original key refuses `machine_revoked`.

## Worker exchange and closed allowlist

`POST /v1/machine/token/challenge` takes `{key_id,aud}` and returns `{challenge,expires_at_ms}`.
`POST /v1/machine/token` takes `{key_id,aud,challenge,sig_hex}`. Neither requires a JWT.
Sign:

```text
cortexkit-device-auth|v1|account.cortexkit.io|<account>|<key_id>|<challenge>|<aud>
```

Challenges are stateless and cannot reserve a key's slots or authenticated budget. Invalid
proofs do not debit the per-key budget. The current possession budget is 60 valid proofs per key
per 60 seconds, shared with relay authorization; challenge issuance has separate IP policy.
Redemption atomically requires current live account/key/sequences, statement-time expiry and a
fresh spend. A lost mint reply uses a new challenge, never recovers the old worker token.

Reply is `{jwt}`. Protected header is `{alg:"EdDSA",kid,typ:"ck-worker+jwt"}`, signed by the
account JWKS key. Payload has **exactly** `{account,device,iat,exp,aud,jti}`, no issuer or class
claim. `device` is key id; `iat` is D1 commit milliseconds floored to seconds; `exp = iat + 900`.
`aud` is one string: `cortexkit-account`, `cortexkit-webhook-relay` or `cortexkit-runners`, never an array.
Delayed signing/delivery never starts a new lifetime. Refuse at expiry. The verifier requires
trusted unambiguous kid, EdDSA, exact claim inventory, canonical ids and safe integer times.
Human and worker verifier paths refuse the other kind; legacy human JWTs remain human.

| Audience | Entire machine-token allowlist |
| --- | --- |
| `cortexkit-account` | `GET /v1/machine/keys`; bodyless `DELETE /v1/machine/keys/{key_id}` only for its own device; the relay proof routes below only for that same device. |
| `cortexkit-webhook-relay` | `POST /v1/relay/github/connect`; `GET /v1/relay/github/connect/{attempt_id}`; `GET /v1/relay/github/status`; permit-gated `POST /v1/relay/github/credentials`; bodyless `DELETE /v1/relay/github/credentials/{id}` only for its own child. |
| `cortexkit-runners` | `POST /v1/leases`; `POST /v1/leases/{job_id}/reattach`; `GET /v1/tenant`. |

List reply: `{keys:[{key_id,public_key,fingerprint,label,created_at_ms,last_used_at_ms,revoked_at_ms}]}`.
Self machine retirement reply: `{revoked:true,relay_propagation:"pending"}`. Own relay-child
retirement reply: `{revoked:true}`, without a fresh human login or `CK-Step-Up`, even when issuance is off. Another machine's
child is 404; any DELETE body is 400. The relay WebSocket uses the standing relay credential,
not a worker JWT. Public setup/result pages and provider callbacks gain no machine privilege.

## Relay credential permits

With a human JWT or account-audience worker JWT, call
`POST /v1/machine/relay-credential/challenge` with `{key_id,source:"github",request_id}`;
reply is `{challenge,expires_at_ms}`. The principal must own that live key, and a machine
principal's device must equal key id. `POST /v1/machine/relay-credential/authorize` adds
`challenge` and `sig_hex`. Sign:

```text
cortexkit-relay-credential-mint|v1|account.cortexkit.io|<account>|<key_id>|<source>|<request_id>|<challenge>
```

Reply is `{permit}`. Protected header is `typ: ck-relay-mint+jwt`, EdDSA and trusted kid;
exact claims are `{iss,aud,account,device,purpose,source,request_id,account_seq,key_seq,iat,exp,jti}`.
`iss` is `https://account.cortexkit.io`, `aud` is `cortexkit-webhook-relay:credential-mint`,
`purpose` is `relay_credential_mint`, and `exp = iat + 60` from D1 commit, not delivery.
This is not a worker JWT. Send it to `POST /v1/relay/github/credentials` with exact body
`{permit,request_id}` and a human or relay-audience worker bearer. The relay verifies trusted
account JWKS and principal equality, makes a new primary authority read and installs higher account/key revocation sequences
then atomically checks current fences/expiry, spends JTI and inserts a parented child. No internal
call can bypass that gate. Higher fences install even if cap/old permit refuses without spending.

There are four live credentials per source, no automatic eviction. A permit replay cannot recover
plaintext from a lost bearer response: inspect the machine's children, revoke the lost one, then
get a new proof. Minting alone never supersedes a connected consumer. Consent/connect/callback/
poll/status never mint a credential. Installed revocation fences permanently refuse affected
children; delayed events cannot roll back fences. During an account outage forwarding/admission
can fail open only from trusted local state until fence arrival; new mint fails closed. There is
no forwarding lease. The relay account DO's alarm retries a failed authority lookup for a
connected credential's parent machine in five minutes.

## Purpose-bound human step-ups

Machine enrollment is the dedicated `machine_enroll` ceremony above. The other three implemented
operations start at `POST /v1/machine/step-up/start` with a **human** bearer and
`{method:"github"|"passkey"|"apple"|"email"|"google",ed25519_pubkey_hex,operation,target,mutation_body,handoff_mode,loopback_port?,handoff_secret?}`.
The ephemeral public key binds only the hand-back channel, never enters the roster and consumes
no machine slot. For bodyless DELETE, `mutation_body` is `{}`. Browser claim, fresh linked-method login,
first-party Confirm and raw-code completion are the enrollment flow, not a recent ordinary JWT.
The returned `{jwt,attestation}` contains `ck-step-up+jwt`, never an enrollment attestation.

| Operation | Exact target | Consumer and mutation-local spend |
| --- | --- | --- |
| `machine_revoke_other` | `{account,key_id}` | Account `DELETE /v1/machine/keys/{key_id}`, D1 `machine_attestation_spends`. |
| `relay_credential_revoke_other` | `{account,source:"github",credential_id,parent_key_id}` | Relay `DELETE /v1/relay/github/credentials/{credential_id}`, account-DO `relay_step_up_spends`. |
| `relay_installation_unbind` | `{account,source:"github",installation_id,binding_gen}` | Relay `DELETE /v1/relay/github/installations/{installation_id}`, installation-DO `installation_step_up_spends`. |

The attestation has exactly `{iss,aud,account,purpose,operation,target,request_hash,auth_time,iat,exp,jti}`,
EdDSA and a trusted kid. `purpose` is `step_up`, `iss` the account issuer, `aud` is
`cortexkit-<consumer>:step-up:<operation>` (`account` or `webhook-relay`),
`iat = auth_time`, `exp = auth_time + 300`. Actor account, exact URL target, operation, audience
and canonical request hash must all match. The target cannot be changed at redemption.

Send `CK-Step-Up` alongside the human bearer. Missing or invalid binding refuses
`step_up_required`; a machine cannot use the human proof. Expiry and a fresh JTI spend are checked
in the store where the guarded mutation commits, **after** RPC awaits. No D1 pre-spend can
substitute for relay/installation SQLite. A failed mutation or RPC before commit burns nothing;
a lost reply after commit leaves one spend/mutation. Unlink compares authoritative generation
again, and confirmation warns that incoming unbound events **drop, not pause**. Seven-day buffered
events do not recover those drops. These controls apply even with issuance disabled.

Other dangerous routes (account merge/delete, rendezvous admin, org administration, billing and
login-method changes) are not added to the machine allowlist and are outside this step-up rollout.
Existing organization service-key create/rotate controls still bind the authenticated admin,
organization and one-use authorization; these govern organization daemons, not machine enrollment.

## Sealed challenges and deadlines

A challenge is `<payload_b64url>.<mac_b64url>`, exact JCS UTF-8 JSON and a versioned HMAC-SHA-256
under an issuer key separate from JWT signing. Reject unknown/extra members, wrong purpose or
bindings, version/kid, noncanonical payload/MAC encoding and invalid MAC. Common fields:
`{v,kid,purpose,account,key_fingerprint,nonce,issued_at_ms,expires_at_ms}`, with `v = 1`,
`kid` matching `[A-Za-z0-9_-]{1,32}`. The deadline is issuance +300000 ms, except `machine_complete`, capped by the earlier
confirmation +300 seconds and fresh-auth +300 seconds deadline.

| Purpose | Exact additional members |
| --- | --- |
| `machine_complete` | `flow_id`, `completion_code_hash` |
| `machine_recover` | Enrollment attestation `jti`, exact replaced key id or null in `replaces`, and SHA-256 of the approved label bytes in `label_hash`. |
| `worker_token` | `key_id`, `key_seq`, `account_seq`, `aud` |
| `relay_credential_mint` | `key_id`, `key_seq`, `account_seq`, `source`, `request_id` |

The proof spend key hashes the **entire sealed challenge**. Possession verification precedes
spending; only a newly inserted spend under the current ownership, liveness, expiry and replay checks
may authorize dependent mutation writes. Required zero-row writes
roll back the batch. Spend records remain through expiry +60 seconds. Old MAC keys remain only
through their configured retention (at least last challenge deadline +60 seconds); retaining a
key never makes expired challenges timeless. D1/DO statement clocks, not client or request-start
clocks, authorize mutations and expiry.

## Refusals and retry policy

Part B errors are `{"error":"<code>"}`. Retry responses additionally carry `retry_after_s` and
an equal `Retry-After` header. Existing provider/relay-consent codes keep their own envelope.

| Code | HTTP | Client action |
| --- | --- | --- |
| `invalid_request` | 400 | Fix format, tuple, unsupported audience/source. |
| `auth_failed`, `signature_invalid`, `principal_mismatch` | 401 | Wrong credential, proof or actor; do not retry the same proof. |
| `machine_revoked`, `machine_not_found` | 401 | Enroll a new key with fresh login; missing keys reveal no other account. |
| `account_not_active` | 403 | Terminal. |
| `machine_action_forbidden` | 403 | Principal not allowed on this action. |
| `step_up_required` | 403 | New operation-bound human login, not a JWT refresh. |
| `enrollment_method_unsupported` | 403 | Unknown/unsupported method (including `github_device`) or method enable off. No `Retry-After`; choose an enabled method or cancel, never ordinary-login fallback. |
| `consent_denied` | 403 | Cancel this ceremony. Google/Apple require a new flow for another authorization attempt. |
| `auth_method_mismatch` | 400 | Stored method/kind differs from callback or attempt. Cancel and start a new flow; no method substitution or ordinary-login fallback. |
| `browser_session_required` | 401 | Resume only in the originally claimed browser. Missing and foreign claims share this code; no state-only recovery or claim transfer. |
| `auth_attempt_expired`, `auth_attempt_spent`, `apple_receipt_expired` | 409 | New same-method attempt within the original flow's deadline and remaining attempt/identity budgets, or new flow. Google/Apple allow only one authorization attempt per flow. Never replay a code or assertion. |
| `email_code_expired` | 409 | Explicit resend within remaining deadline/budgets; the old code stays unusable. |
| `email_code_locked` | 429 | Flow terminal after five wrong guesses. Honor any address cooldown in equal `Retry-After`/`retry_after_s`; a new flow cannot bypass it. |
| `authentication_unavailable` | 503 | Enabled method is misconfigured, or provider/JWKS unavailable. Retry after equal `Retry-After`/`retry_after_s`; missing/wrong config needs operator repair. No downgrade or fresh-auth reset. Start a new flow if a Google/Apple exchange was already reserved. |
| `attestation_expired`, `attestation_spent`, `completion_expired`, `completion_spent` | 409 | New ceremony, except exact committed enrollment recovery. |
| `challenge_expired`, `challenge_spent`, `issuance_expired`, `permit_expired` | 409 | New challenge and proof immediately. |
| `permit_spent` | 409 | Inspect children, revoke any lost-result child, then new proof; never replay. |
| `key_already_enrolled`, `replacement_conflict`, `enrollment_conflict` | 409 | Recover an exact winner or new ceremony with a new key. |
| `enrollment_not_found` | 404 | No committed result; recovery cannot create one. |
| `key_limit`, `credential_limit` | 409 | Free a slot explicitly; no eviction. |
| `revocation_fence` | 409 | Re-read account/key status; never replay the old permit. A retired parent key cannot regain authority. |
| `sequence_exhausted` | 409 | Operator repair; never reset/wrap a counter. |
| `rate_limited` | 429 | Retry after the stated delay. |
| `exchange_disabled` | 503 | Retry after stated delay, no new login. |
| `account_check_unavailable`, `relay_security_unavailable` | 503 | Retry after stated delay, fail closed, no new login. |

The master switch is `MACHINE_CREDENTIALS_ENABLED`, enabled only by literal `true` (production
sets it). Missing/false blocks enrollment start and every stored `machine_enroll` route,
including auth pages, callbacks, Apple ingress/resume, Confirm and completion, with 503
`exchange_disabled`, `Retry-After: 60` and `retry_after_s: 60`, before any provider exchange.
Stored kind, not pathname, selects this gate. Worker exchange and relay authorization are also
blocked. Step-up start and every stored `step_up` route remain available for GitHub and each
enabled new method; a disabled step-up method returns the 403 even with the master off.
Listing, recovery, revoke, lifecycle/outbox, admission and alarm remain available. Existing JWTs
expire normally and parented relay credentials obey permanent account/key revocation fences.

Each new adapter separately requires `MACHINE_PASSKEY_ENABLED`, `MACHINE_APPLE_ENABLED`,
`MACHINE_EMAIL_ENABLED` or `MACHINE_GOOGLE_ENABLED` exactly `true`; absent or any other value is
off. Enable-off is 403 `enrollment_method_unsupported`, without `Retry-After`. Enable-on with
missing/wrong required configuration is instead 503 `authentication_unavailable`, with equal
`Retry-After` and `retry_after_s`. Start and every later stored-flow route recheck configuration
before claims, attempts, verifiers, receipts or provider calls; no account, identity or credential
is inserted. That recheck applies to the stored flow the route actually acts on: it reads the
request with the route's own parser, so a body's Content-Type label (a JSON completion body sent
as form data, or a form type with `charset` or spacing variants) cannot steer it to another flow
or past the check. A stored-flow request whose flow cannot be found is refused with that
parser's own refusal (for example 400 `invalid_request`) before any other route check; it never
skips the method check. Completion and challenge bodies are still read as JSON whatever their label.
See [per-method enablement](account-service.md#per-method-enablement-and-rollback)
for the configuration and independent release prerequisites. No adapter is enabled by this change.

After the master/issuer gate (step-up is exempt from the master gate), start strictly parses
the body and requires a string `method`: missing/unknown/duplicate members or a non-string
`method` are 400 `invalid_request`. Unknown or disabled string methods return 403 before validating the
public key or hand-back tuple; enabled methods check configuration (503) before those fields
(400). Step-up authenticates the actor and validates its target during strict parsing.

## Vectors and release evidence

[`test-vectors/machine-key/vectors.json`](../test-vectors/machine-key/vectors.json) is generated
from registered account routes with real D1. It pins enroll, complete, recover, both worker
audiences, relay permit and each implemented step-up, with exact requests/replies, transcript
UTF-8 hex, signatures and JWT headers/claims. This original GitHub corpus and its README SHA-256
cell remain byte-identical. New-method evidence lives in
[`r6-methods.json`](../test-vectors/machine-key/r6-methods.json) (each method's enrollment and
three step-ups through auth, Confirm, completion and attestation) and
[`refusals.json`](../test-vectors/machine-key/refusals.json) (new refusal codes/statuses). The
[README](../test-vectors/machine-key/README.md) lists purpose, SHA-256, update command, proof names
and the full B.10 evidence/follow-up table. Sequential wire bytes are pinned; races remain
assertions, not pinned scheduler output. No generator rewrites
[`test-vectors/rendezvous/renewal.json`](../test-vectors/rendezvous/renewal.json), Part A's corpus.
The public seeds and credentials in vectors are test material only. Method/client integration
follow-ups and operator callback/cutover checks remain release obligations, not implied approvals.
