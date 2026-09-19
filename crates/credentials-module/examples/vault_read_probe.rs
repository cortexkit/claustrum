#![forbid(unsafe_code)]

//! `vault_read_probe` — read a credential from a LIVE vault daemon by handle.
//!
//! A hand-driving consumer for the credential vault: it authenticates as a client
//! over the subc loopback handshake, waits for the vault module to appear in the
//! catalog, opens a route to its ManagementSurface, and issues `credential.get`
//! for a capability handle — printing whether the payload came back, without ever
//! printing the secret itself. It is the operator-facing twin of the e2e harness's
//! consumer driver, useful for verifying a real vault end-to-end.
//!
//! Usage:
//!   cargo run -p credentials-module --example vault_read_probe -- \
//!     --subc <connection-file> --handle <ckh_...> [--root <path>]
//!
//! It deliberately does NOT print the credential payload bytes (only its length and
//! a short fingerprint), so running it against a real credential does not splash the
//! token across a terminal or log.

use std::{path::PathBuf, time::Duration};

use serde_json::{json, Value};
use subc_protocol::{BindIdentity, Flags, Frame, FrameType, Priority, RouteTarget};
use subc_transport::{authenticate_client, connection_file, read_frame, write_frame};
use tokio::{net::TcpStream, time::Instant};

const MODULE_ID: &str = "claustrum";
const SETUP_TIMEOUT: Duration = Duration::from_secs(15);
const READ_TIMEOUT: Duration = Duration::from_secs(15);

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let mut subc: Option<PathBuf> = None;
    let mut handle: Option<String> = None;
    let mut handle_file: Option<PathBuf> = None;
    let mut root = std::env::temp_dir();
    let mut force_refresh = false;
    let mut min_ttl_ms: Option<i64> = None;
    let mut show_account_id = false;
    let mut show_claims = false;
    let mut report_auth_failure = false;
    let mut status = false;
    let mut reporter_source: Option<String> = None;
    // Repeatable: `--status-id A --status-id B` compares two scoped answers in ONE bind,
    // because the anti-enumeration property is about whether two bodies agree.
    let mut status_ids: Option<Vec<String>> = None;
    let mut scoped_id: Option<String> = None;
    let mut list_scoped = false;
    let mut as_module: Option<String> = None;
    let mut enroll_propose: Option<String> = None;
    let mut enroll_poll: Option<String> = None;
    let mut enroll_secret: Option<String> = None;
    let mut enrollment_token: Option<String> = None;
    let mut scoped_min_ttl_ms: Option<i64> = None;
    let mut sign_payload: Option<String> = None;
    let mut sign_payload_bytes: Option<Vec<u8>> = None;
    let mut public_key = false;
    let mut provider_status: u16 = 401;
    let mut record_version: Option<u64> = None;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--subc" => subc = args.next().map(PathBuf::from),
            "--handle" => handle = args.next(),
            // Read the handle from a file instead of the command line. A capability handle
            // is a bearer secret: `--handle ckh_...` puts it in argv, which means shell
            // history, `ps` output for any local user, CI logs, and -- when an agent runs
            // the probe -- the tool transcript, which leaves the machine. The file form
            // keeps it in a mode-600 file the process reads itself, so the secret never
            // appears in a place that is copied by default.
            "--handle-file" => handle_file = args.next().map(PathBuf::from),
            "--root" => {
                if let Some(value) = args.next() {
                    root = PathBuf::from(value);
                }
            }
            // Force a refresh-on-read regardless of the token's recorded expiry. This
            // makes the "google's token is dead, the vault refreshes it live" proof
            // DETERMINISTIC: without it, a credential whose auth.json carried no
            // `expires` is treated as not-stale and served as-is (no refresh), so an
            // empty google access token would come back empty and look like a failure.
            "--force-refresh" => force_refresh = true,
            // Refresh if the token has less than this many ms of life left.
            "--min-ttl-ms" => {
                min_ttl_ms = args.next().and_then(|v| v.parse().ok());
            }
            // Decode the served payload AS a JWT client-side and print ONLY the
            // non-secret ChatGPT account-id claim. Useful when the daemon predates
            // the GetResult.account_id field: the payload already carries the claim,
            // so the probe can surface it without printing the token.
            "--show-account-id" => show_account_id = true,
            // Decode the served payload AS a JWT and print its full claims object
            // (pretty JSON). The claims are the token's non-secret self-description
            // (issuer, audience, scopes, account bindings, expiry); the token itself
            // — header+signature, the actual bearer secret — is never printed. For
            // diffing two grants' claim sets during entitlement forensics.
            "--show-claims" => show_claims = true,
            // Send `credential.report_auth_failure` INSTEAD of a get, reporting the
            // given provider status against the given record_version.
            //
            // This exists so the report path can be exercised against a running vault
            // at all. It otherwise has no client: the only way to produce a report is a
            // consumer meeting a real provider 401, so the vault's handling of one was
            // covered by unit tests and by nothing live.
            //
            // Reporting a version the store has already moved past is the SAFE way to
            // drive it: the invalidate is version-gated, so a stale version changes
            // nothing, while the surrounding diagnostics still record the observation.
            // Point it at a disposable credential regardless -- a report at the CURRENT
            // version will mark that credential needs_reauth, which is the whole point
            // of the call.
            "--report-auth-failure" => report_auth_failure = true,
            // Exercise `credential.sign` / `credential.public_key` over the wire.
            //
            // These are route ops with NO CLI verb -- they exist for consumers, so
            // nothing an operator can run proves they answer. That gap is not
            // theoretical: the deploy that shipped them passed every acceptance leg
            // (hashes, identifiers, inode, serving count, fenced write) while these two
            // surfaces had never been called once. `scripts/accept-deploy.sh` says so
            // itself -- it asks whether the right bytes are in the right place, never
            // whether a behaviour is reachable.
            "--status" => status = true,
            "--reporter-source" => {
                reporter_source = args.next();
            }
            "--as-module" => {
                let Some(id) = args.next() else {
                    eprintln!("vault_read_probe: --as-module needs a module id");
                    std::process::exit(2);
                };
                as_module = Some(id);
            }
            "--enroll-propose" => {
                let Some(name) = args.next() else {
                    eprintln!("vault_read_probe: --enroll-propose needs a consumer name");
                    std::process::exit(2);
                };
                enroll_propose = Some(name);
            }
            "--enroll-poll" => {
                let Some(id) = args.next() else {
                    eprintln!("vault_read_probe: --enroll-poll needs a request id");
                    std::process::exit(2);
                };
                enroll_poll = Some(id);
            }
            "--enroll-secret" => {
                let Some(secret) = args.next() else {
                    eprintln!("vault_read_probe: --enroll-secret needs the request secret");
                    std::process::exit(2);
                };
                enroll_secret = Some(secret);
            }
            "--enrollment-token" => {
                let Some(token) = args.next() else {
                    eprintln!("vault_read_probe: --enrollment-token needs a token");
                    std::process::exit(2);
                };
                enrollment_token = Some(token);
            }
            // THE OP A CONSUMER SPENDS MOST, and it had no probe arm until the
            // anthropic-auth seat asked for a live acceptance that exercises it. That
            // absence is how `list_scoped` shipped querying grants under a hardcoded
            // `reserved` kind: nothing an operator could run would have shown it.
            "--list-scoped" => list_scoped = true,
            "--scoped-id" => {
                let Some(id) = args.next() else {
                    eprintln!("vault_read_probe: --scoped-id needs a credential id");
                    std::process::exit(2);
                };
                scoped_id = Some(id);
            }
            "--scoped-min-ttl-ms" => {
                let Some(raw) = args.next() else {
                    eprintln!("vault_read_probe: --scoped-min-ttl-ms needs a value");
                    std::process::exit(2);
                };
                match raw.parse::<i64>() {
                    Ok(ms) => scoped_min_ttl_ms = Some(ms),
                    Err(_) => {
                        eprintln!("vault_read_probe: --scoped-min-ttl-ms must be an integer");
                        std::process::exit(2);
                    }
                }
            }
            "--status-id" => {
                let id = args.next().unwrap_or_else(|| {
                    eprintln!("vault_read_probe: --status-id needs a credential id");
                    std::process::exit(2);
                });
                status_ids.get_or_insert_with(Vec::new).push(id);
            }
            "--sign" => sign_payload = args.next(),
            // SIGN THE FILE'S EXACT BYTES, never a shell-quoted copy of them.
            //
            // `--sign` takes its payload through argv, which is a one-byte mutation
            // channel: quoting, escaping and newline handling all sit between the file an
            // approver hashed and the bytes the vault signs. For a 4872-byte JSON
            // manifest that is not theoretical, and it defeats the SHA gate the ceremony
            // opens with — the approval would bind bytes H while the signature covers
            // something else, and both would look correct.
            "--sign-file" => {
                let path = args.next().expect("--sign-file needs a path");
                let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
                sign_payload_bytes = Some(bytes);
            }
            "--public-key" => public_key = true,
            "--provider-status" => {
                provider_status = args.next().and_then(|v| v.parse().ok()).unwrap_or(401);
            }
            "--record-version" => {
                record_version = args.next().and_then(|v| v.parse().ok());
            }
            other => {
                eprintln!("vault_read_probe: unexpected arg '{other}'");
                std::process::exit(2);
            }
        }
    }

    let subc = subc.unwrap_or_else(|| {
        eprintln!("vault_read_probe: --subc <connection-file> is required");
        std::process::exit(2);
    });
    // Reject both rather than picking a winner: a caller who passes both has one of the
    // two wrong, and silently preferring either can send a handle the caller did not mean
    // -- against a vault, an unintended credential read.
    if handle.is_some() && handle_file.is_some() {
        eprintln!("vault_read_probe: pass --handle OR --handle-file, not both");
        std::process::exit(2);
    }
    let handle = match (handle, handle_file) {
        (Some(value), _) => value,
        (None, Some(path)) => {
            let raw = std::fs::read_to_string(&path).unwrap_or_else(|err| {
                // Fail loud. An empty or unreadable handle file must not fall through to
                // an empty handle, which the vault answers with the same uniform
                // `not_found` it uses for a revoked one -- indistinguishable from a real
                // authorization result, and the probe would report a vault verdict for
                // what is actually a local file error.
                eprintln!(
                    "vault_read_probe: cannot read --handle-file {}: {err}",
                    path.display()
                );
                std::process::exit(2);
            });
            // Trim: a handle written with `> file` or by an editor carries a trailing
            // newline, and a handle with a newline in it is simply a different string.
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                eprintln!(
                    "vault_read_probe: --handle-file {} is empty",
                    path.display()
                );
                std::process::exit(2);
            }
            trimmed.to_string()
        }
        (None, None)
            if scoped_id.is_some()
                || status_ids.is_some()
                || list_scoped
                || enroll_propose.is_some()
                || enroll_poll.is_some() =>
        {
            // GRANT-ADDRESSED ARMS NEED NO HANDLE, and requiring one would misrepresent
            // the surface: `get_scoped` and scoped `status` are authorized by the
            // caller's grants, and the whole point of the cutover this probe exercises is
            // that a consumer stops holding capabilities at all. Demanding one here would
            // have meant the only way to test the handle-free path was to hold a handle.
            String::new()
        }
        (None, None) => {
            eprintln!(
                "vault_read_probe: --handle <ckh_...> or --handle-file <path> is required \
                 (grant-addressed arms --scoped-id / --status-id need no handle)"
            );
            std::process::exit(2);
        }
    };

    // Name the candidate locations rather than panicking with the path we were handed.
    // An empty or wrong `--subc` produced `Io { op: "stat", path: "" }`, which tells the
    // operator nothing about where the file actually lives -- and there are three
    // possible homes depending on how the supervisor was started, so guessing is the
    // expected failure rather than a careless one.
    if subc.as_os_str().is_empty() {
        eprintln!(
            "vault_read_probe: --subc <connection-file> was empty.\n\
             The supervisor writes it to one of:\n\
             \x20 $XDG_RUNTIME_DIR/subc-connection.json   (unset on stock macOS)\n\
             \x20 ~/.local/share/cortexkit/run/subc-connection.json\n\
             \x20 <temp>/subc-<user-token>.connection.json  (the macOS default)"
        );
        std::process::exit(2);
    }
    let conn = match connection_file::read(&subc) {
        Ok(conn) => conn,
        Err(err) => {
            eprintln!(
                "vault_read_probe: cannot read connection file {}: {err}",
                subc.display()
            );
            eprintln!(
                "  If the daemon is running, the file is most likely at\n\
                 \x20 ~/.local/share/cortexkit/run/subc-connection.json\n\
                 \x20 or <temp>/subc-<user-token>.connection.json"
            );
            std::process::exit(2);
        }
    };
    let endpoint = conn
        .endpoints
        .first()
        .expect("connection file has an endpoint");
    let mut stream = TcpStream::connect((endpoint.host.as_str(), endpoint.port))
        .await
        .expect("connect to daemon");
    authenticate_client(&mut stream, &conn, Duration::from_secs(2))
        .await
        .expect("client handshake");
    eprintln!(
        "[probe] authenticated to {}:{}",
        endpoint.host, endpoint.port
    );

    wait_for_catalog(&mut stream).await;
    eprintln!("[probe] vault module '{MODULE_ID}' is catalog-live");

    let (route_channel, route_epoch) = route_open(&mut stream, &root, as_module.as_deref()).await;
    eprintln!("[probe] route.open -> route_channel={route_channel} route_epoch={route_epoch}");

    if list_scoped {
        let body = credential_list_scoped(
            &mut stream,
            route_channel,
            route_epoch,
            enrollment_token.as_deref(),
        )
        .await;
        let parsed: Value = serde_json::from_slice(&body.body).unwrap_or(Value::Null);
        let rows = parsed["result"]["credentials"].as_array();
        match rows {
            Some(rows) => {
                eprintln!("[probe] list_scoped -> {} row(s)", rows.len());
                for row in rows {
                    // `serves` is the CANONICAL routing axis, not the id spelling:
                    // apikey:openrouter serves Anthropic models and contains no
                    // "anthropic" anywhere in its id.
                    eprintln!(
                        "  {}  categories={}  serves={}  state={}  v{}",
                        // The field is `id` here, NOT `credential_id`. `get` and `status`
                        // echo `credential_id` for binding verification; an inventory row
                        // IS the credential, so it does not need to name the concept
                        // twice. Reading the wrong key printed "?" for every row and said
                        // nothing about why.
                        row["id"].as_str().unwrap_or("?"),
                        row["categories"],
                        row["serves"],
                        row["state"].as_str().unwrap_or("?"),
                        row["record_version"]
                    );
                }
            }
            None => eprintln!(
                "[probe] list_scoped -> {}",
                serde_json::to_string(&parsed).unwrap_or_default()
            ),
        }
        return;
    }

    if report_auth_failure {
        let version = record_version.unwrap_or_else(|| {
            eprintln!(
                "vault_read_probe: --record-version <n> is required with \
                 --report-auth-failure (the vault refuses a versionless report)"
            );
            std::process::exit(2);
        });
        let body = credential_report_auth_failure(
            &mut stream,
            route_channel,
            route_epoch,
            ReportAddress {
                handle: &handle,
                credential_id: scoped_id.as_deref(),
                enrollment_token: enrollment_token.as_deref(),
            },
            provider_status,
            version,
            reporter_source.as_deref(),
        )
        .await;
        let parsed: Value = serde_json::from_slice(&body.body).unwrap_or(Value::Null);
        eprintln!(
            "[probe] report_auth_failure status={provider_status} record_version={version} -> {}",
            serde_json::to_string(&parsed).unwrap_or_default()
        );
        return;
    }

    if public_key
        || status
        || status_ids.is_some()
        || scoped_id.is_some()
        || enroll_propose.is_some()
        || enroll_poll.is_some()
        || sign_payload.is_some()
        || sign_payload_bytes.is_some()
    {
        // Both halves in one run when both are asked for, because the useful assertion
        // is that they AGREE: a signature that verifies under the returned key proves
        // the two ops name the same keypair. Either alone proves only that an op
        // answered, which is the weaker claim that let this gap exist.
        if status {
            let body =
                credential_status(&mut stream, route_channel, route_epoch, &handle, None, 12).await;
            let parsed: Value = serde_json::from_slice(&body.body).unwrap_or(Value::Null);
            eprintln!(
                "[probe] status -> {}",
                serde_json::to_string(&parsed).unwrap_or_default()
            );
        }
        // Two ids, one bind, printed together: the property is a COMPARISON, and a probe
        // that printed one body per invocation would leave the operator eyeballing two
        // runs for equality -- which is how a difference gets missed.
        if let Some(ids) = status_ids.as_ref() {
            let mut bodies: Vec<String> = Vec::new();
            for (n, id) in ids.iter().enumerate() {
                // Distinct correlation ids so the reply matcher cannot pair the second
                // answer with the first frame -- which would make two different bodies
                // read as identical, the exact way this comparison could lie.
                let corr = 40u64 + n as u64;
                let body = credential_status(
                    &mut stream,
                    route_channel,
                    route_epoch,
                    &handle,
                    Some(id),
                    corr,
                )
                .await;
                let parsed: Value = serde_json::from_slice(&body.body).unwrap_or(Value::Null);
                let rendered = serde_json::to_string(&parsed).unwrap_or_default();
                eprintln!("[probe] status(id={id}) -> {rendered}");
                bodies.push(rendered);
            }
            if bodies.len() >= 2 {
                let identical = bodies.windows(2).all(|w| w[0] == w[1]);
                eprintln!(
                    "[probe] scoped-status bodies identical: {identical}  <- must be true \
                     for ids this principal cannot reach; a difference is an enumeration \
                     oracle, not a cosmetic one"
                );
            }
        }
        if let Some(name) = enroll_propose.as_ref() {
            // The request secret is MINTED HERE and only its hash is sent. That asymmetry
            // is what stops a squatter who proposed a name it does not hold from
            // collecting the token even if an operator approves by mistake: the poll is
            // authenticated by the secret, which never left this process.
            // Entropy from the clock plus the pid, then hashed by the CORE's own
            // function rather than a re-derivation here. A probe that re-implemented the
            // domain separator could disagree with the vault and the disagreement would
            // present as "the ceremony is broken" rather than "the probe is wrong".
            // A CALLER-SUPPLIED SECRET MAKES THE RESUME TESTABLE. Without
            // `--enroll-secret` this arm mints a fresh secret from the clock and pid on
            // every run, so a second propose is a DIFFERENT caller by construction and can
            // only ever demonstrate `pending_exists`. Re-running it looks like the resume
            // is broken; it is the probe asking a different question.
            //
            // Measured during the live acceptance: I passed `--enroll-secret`, got
            // `pending_exists`, and nearly reported the just-landed resume as not working.
            // The flag was parsed and then read only by the poll arm.
            let seed = match enroll_secret.as_ref() {
                Some(supplied) => supplied.clone(),
                None => format!(
                    "{}-{}-{}",
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .expect("clock")
                        .as_nanos(),
                    name
                ),
            };
            let secret_hex = credentials_core::enrollment::enrollment_secret_hash(
                &credentials_core::enrollment::enrollment_secret_hash(&{
                    use std::collections::hash_map::DefaultHasher;
                    use std::hash::{Hash, Hasher};
                    let mut h = DefaultHasher::new();
                    seed.hash(&mut h);
                    format!(
                        "{:016x}{:016x}{:016x}{:016x}",
                        h.finish(),
                        h.finish().rotate_left(17),
                        h.finish().rotate_left(31),
                        h.finish().rotate_left(47)
                    )
                })
                .expect("seed is 32 hex bytes"),
            )
            .expect("hash is 32 hex bytes");
            let hash = credentials_core::enrollment::enrollment_secret_hash(&secret_hex)
                .expect("secret is 32 hex bytes");
            let body = enroll_call(
                &mut stream,
                route_channel,
                route_epoch,
                "auth.enroll_propose",
                json!({ "proposed_name": name, "request_secret_hash": hash }),
                60,
            )
            .await;
            let parsed: Value = serde_json::from_slice(&body.body).unwrap_or(Value::Null);
            eprintln!(
                "[probe] enroll_propose({name}) -> {}",
                serde_json::to_string(&parsed).unwrap_or_default()
            );
            eprintln!("[probe] request_secret (keep, needed to poll): {secret_hex}");
        }
        if let Some(request_id) = enroll_poll.as_ref() {
            let Some(secret) = enroll_secret.as_ref() else {
                eprintln!("vault_read_probe: --enroll-poll needs --enroll-secret");
                std::process::exit(2);
            };
            let body = enroll_call(
                &mut stream,
                route_channel,
                route_epoch,
                "auth.enroll_poll",
                json!({ "request_id": request_id, "request_secret": secret }),
                61,
            )
            .await;
            let parsed: Value = serde_json::from_slice(&body.body).unwrap_or(Value::Null);
            eprintln!(
                "[probe] enroll_poll -> {}",
                serde_json::to_string(&parsed).unwrap_or_default()
            );
        }
        if let Some(id) = scoped_id.as_ref() {
            let body = credential_get_scoped(
                &mut stream,
                route_channel,
                route_epoch,
                id,
                scoped_min_ttl_ms,
                enrollment_token.as_deref(),
                50,
            )
            .await;
            let parsed: Value = serde_json::from_slice(&body.body).unwrap_or(Value::Null);
            // Print the FINGERPRINT and length, never the payload: this arm is run against
            // production credentials and its output lands in a terminal scrollback.
            let served = parsed.pointer("/result/payload").and_then(Value::as_array);
            match served {
                Some(bytes) => {
                    let raw: Vec<u8> = bytes
                        .iter()
                        .filter_map(Value::as_u64)
                        .map(|b| b as u8)
                        .collect();
                    // fnv1a64, the same dependency-free fingerprint the handle arm uses:
                    // enough to compare two reads for equality, never enough to recover
                    // the secret from a terminal scrollback.
                    eprintln!(
                        "[probe] get_scoped(id={id}) -> {} bytes, fnv1a64 {:016x}, credential_id={}",
                        raw.len(),
                        fnv1a64(&raw),
                        parsed
                            .pointer("/result/credential_id")
                            .and_then(Value::as_str)
                            .unwrap_or("<absent>")
                    );
                }
                None => eprintln!(
                    "[probe] get_scoped(id={id}) -> {}",
                    serde_json::to_string(&parsed).unwrap_or_default()
                ),
            }
        }
        if public_key {
            let body =
                credential_public_key(&mut stream, route_channel, route_epoch, &handle).await;
            let parsed: Value = serde_json::from_slice(&body.body).unwrap_or(Value::Null);
            eprintln!(
                "[probe] public_key -> {}",
                serde_json::to_string(&parsed).unwrap_or_default()
            );
        }
        // File bytes take precedence and are used VERBATIM; the argv string keeps its
        // existing behaviour for short ad-hoc payloads.
        let to_sign: Option<Vec<u8>> =
            sign_payload_bytes.or_else(|| sign_payload.map(|p| p.into_bytes()));
        if let Some(payload) = to_sign {
            let body =
                credential_sign(&mut stream, route_channel, route_epoch, &handle, &payload).await;
            let parsed: Value = serde_json::from_slice(&body.body).unwrap_or(Value::Null);
            eprintln!(
                "[probe] sign({} bytes) -> {}",
                payload.len(),
                serde_json::to_string(&parsed).unwrap_or_default()
            );
        }
        return;
    }

    let body = credential_get(
        &mut stream,
        route_channel,
        route_epoch,
        &handle,
        force_refresh,
        min_ttl_ms,
    )
    .await;
    report(&body, show_account_id, show_claims);
}

/// Send `credential.public_key`.
///
/// This op exists precisely BECAUSE `credential.get` returns the record payload
/// verbatim, and for a signing-key record that payload IS the private PKCS#8. A
/// consumer that wants to publish a verifier key must have a route that cannot carry
/// private bytes, and this is it.
/// Ask `credential.status` about a handle.
///
/// THE PROBE COULD NOT REACH THIS OP AT ALL until 2026-08-27, which is the same
/// instrument gap found that morning for `sign` and `public_key`: an op with no CLI
/// verb is one nothing an operator runs ever touches, so it goes unexercised while
/// every surface reachable from a terminal gets proven on every deploy.
///
/// It exists here specifically to compare `status` against the VERB on the same handle.
/// A status surface that disagrees with the operation it describes is worse than no
/// status surface — it tells a caller the thing will work and the call then refuses.
/// `--status-id` addresses `status` the way `get_scoped` is addressed, and it exists
/// because A NEW ADDRESSING NEEDS ITS PROBE ARM IN THE SAME CHANGE. Without it the
/// deploy that shipped scoped status could not be acceptance-tested at all from an
/// operator terminal -- the identical gap the comment above records for `sign` and
/// `public_key`, reintroduced one addressing later.
///
/// From an UNGRANTED bind it exercises the anti-enumeration property rather than the
/// happy path: an uncovered id and an unknown id must return BYTE-IDENTICAL bodies. If
/// they ever differ, the surface has become an oracle for which credential ids exist,
/// which is a stop-the-deploy finding rather than a cosmetic one. The happy path needs
/// the granted principal and belongs to that consumer's seat.
/// Drive one enrollment ceremony step.
///
/// THE PROBE BINDS AS `Principal::Direct`, WHICH EVERY SCOPED OP REFUSES. That is not a
/// limitation to work around — it is the exact situation enrollment exists for, and it is
/// why a `--scoped-id` run without a token correctly answers `not_found`. A host-launched
/// consumer has no launch nonce and can never have one; the ceremony is how it acquires a
/// name the vault's grants can reach.
///
/// So these three arms make the probe the first thing on this host that can exercise the
/// campaign end to end: propose, wait for a master-key approval, poll, then spend.
async fn enroll_call(
    stream: &mut TcpStream,
    route_channel: u16,
    route_epoch: u32,
    method: &str,
    params: Value,
    corr: u64,
) -> Frame {
    let frame = Frame::build(
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        route_channel,
        route_epoch,
        corr,
        serde_json::to_vec(&json!({ "method": method, "params": params })).unwrap(),
    )
    .unwrap();
    write_frame(stream, &frame).await.unwrap();
    loop {
        let frame = read_frame_timeout(stream).await;
        if frame.header.corr == corr
            && matches!(frame.header.ty, FrameType::Response | FrameType::Error)
        {
            return frame;
        }
    }
}

/// Exercise `credential.get_scoped` — the grant-addressed fetch.
///
/// THIS ARM EXISTS BECAUSE THE OP HAD NO OPERATOR EXERCISE PATH AT ALL. It shipped in
/// v0.1.3, gained an `enrollment_token` parameter, then a `min_ttl_ms` parameter, and
/// across all three changes no tool on this host could call it. Its first live request
/// anywhere will be a consumer's, which means "it works" rested entirely on tests written
/// against the behaviour their author imagined.
///
/// `min_ttl_ms` is optional here rather than defaulted: a probe that always sent a floor
/// could not distinguish "the op honours a demand" from "the op applies one of its own",
/// and an absent demand is the shape most callers send.
async fn credential_get_scoped(
    stream: &mut TcpStream,
    route_channel: u16,
    route_epoch: u32,
    credential_id: &str,
    min_ttl_ms: Option<i64>,
    enrollment_token: Option<&str>,
    corr: u64,
) -> Frame {
    let mut params = json!({ "credential_id": credential_id });
    if let Some(ms) = min_ttl_ms {
        params["min_ttl_ms"] = json!(ms);
    }
    if let Some(token) = enrollment_token {
        params["enrollment_token"] = json!(token);
    }
    let frame = Frame::build(
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        route_channel,
        route_epoch,
        corr,
        serde_json::to_vec(&json!({
            "method": "credential.get_scoped",
            "params": params,
        }))
        .unwrap(),
    )
    .unwrap();
    write_frame(stream, &frame).await.unwrap();
    loop {
        let frame = read_frame_timeout(stream).await;
        if frame.header.corr == corr
            && matches!(frame.header.ty, FrameType::Response | FrameType::Error)
        {
            return frame;
        }
    }
}

async fn credential_status(
    stream: &mut TcpStream,
    route_channel: u16,
    route_epoch: u32,
    handle: &str,
    credential_id: Option<&str>,
    corr: u64,
) -> Frame {
    let params = match credential_id {
        Some(id) => json!({ "credential_id": id }),
        None => json!({ "handle": handle }),
    };
    let frame = Frame::build(
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        route_channel,
        route_epoch,
        corr,
        serde_json::to_vec(&json!({
            "method": "credential.status",
            "params": params,
        }))
        .unwrap(),
    )
    .unwrap();
    write_frame(stream, &frame).await.unwrap();
    loop {
        let frame = read_frame_timeout(stream).await;
        if frame.header.corr == corr
            && matches!(frame.header.ty, FrameType::Response | FrameType::Error)
        {
            return frame;
        }
    }
}

async fn credential_public_key(
    stream: &mut TcpStream,
    route_channel: u16,
    route_epoch: u32,
    handle: &str,
) -> Frame {
    let frame = Frame::build(
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        route_channel,
        route_epoch,
        11,
        serde_json::to_vec(&json!({
            "method": "credential.public_key",
            "params": { "handle": handle },
        }))
        .unwrap(),
    )
    .unwrap();
    write_frame(stream, &frame).await.unwrap();
    loop {
        let frame = read_frame_timeout(stream).await;
        if frame.header.corr == 11
            && matches!(frame.header.ty, FrameType::Response | FrameType::Error)
        {
            return frame;
        }
    }
}

/// Send `credential.sign`.
///
/// The payload is base64 on the wire because JSON cannot carry raw bytes, but the
/// vault signs the DECODED bytes. That distinction is load-bearing: signing the
/// encoded text would break the moment a caller re-encoded with different padding,
/// which is the canonicalization mismatch this whole design avoids by carrying exact
/// bytes end to end.
async fn credential_sign(
    stream: &mut TcpStream,
    route_channel: u16,
    route_epoch: u32,
    handle: &str,
    payload: &[u8],
) -> Frame {
    use base64::Engine as _;
    let frame = Frame::build(
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        route_channel,
        route_epoch,
        12,
        serde_json::to_vec(&json!({
            "method": "credential.sign",
            "params": {
                "handle": handle,
                "payload_b64": base64::engine::general_purpose::STANDARD.encode(payload),
            },
        }))
        .unwrap(),
    )
    .unwrap();
    write_frame(stream, &frame).await.unwrap();
    loop {
        let frame = read_frame_timeout(stream).await;
        if frame.header.corr == 12
            && matches!(frame.header.ty, FrameType::Response | FrameType::Error)
        {
            return frame;
        }
    }
}

async fn control_rpc(stream: &mut TcpStream, corr: u64, body: Value) -> Frame {
    // Channel-0 control frames carry the reserved epoch 0 (wire v2 §3.1).
    let frame = Frame::build(
        FrameType::Request,
        Flags::new(false, Priority::Passive, false),
        0,
        0,
        corr,
        serde_json::to_vec(&body).unwrap(),
    )
    .unwrap();
    write_frame(stream, &frame).await.unwrap();
    loop {
        let frame = read_frame_timeout(stream).await;
        if frame.header.channel == 0
            && matches!(frame.header.ty, FrameType::Response | FrameType::Error)
            && frame.header.corr == corr
        {
            return frame;
        }
    }
}

async fn read_frame_timeout(stream: &mut TcpStream) -> Frame {
    tokio::time::timeout(READ_TIMEOUT, async {
        read_frame(stream)
            .await
            .unwrap()
            .expect("connection should stay open")
    })
    .await
    .expect("timed out waiting for a frame")
}

async fn wait_for_catalog(stream: &mut TcpStream) {
    let deadline = Instant::now() + SETUP_TIMEOUT;
    let mut corr = 1000;
    loop {
        let frame = control_rpc(stream, corr, json!({ "op": "catalog.list" })).await;
        let value: Value = serde_json::from_slice(&frame.body).unwrap();
        let present = value["modules"]
            .as_array()
            .map(|ms| ms.iter().any(|m| m["module_id"] == MODULE_ID))
            .unwrap_or(false);
        if present {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "vault module did not appear in catalog within {SETUP_TIMEOUT:?}"
        );
        corr += 1;
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Open a route, optionally claiming a supervised launch.
///
/// `consumer_identity` IS WHAT DECIDES THE PRINCIPAL, and nothing in this repository has
/// ever sent one. Read at `subc-daemon/src/control.rs::route_open_principal`: a
/// `route.open` presenting `{ module_id, launch_nonce }` that the supervisor validates is
/// stamped `Principal::Reserved`; ABSENT IDENTITY IS `Direct` BY CONSTRUCTION, silently.
/// It is not a property of being supervised — a supervised module that does not send it
/// is Direct like anyone else.
///
/// Until this arm existed, every `Principal::Reserved` in this repository's tests was
/// hand-constructed and injected past the transport via `admin.record_bind(channel,
/// Principal::Reserved { .. })` — 29 such call sites. Those tests prove the authorization
/// logic is correct GIVEN a Reserved principal and say nothing about whether one can
/// arrive. The scoped surface shipped, was documented as working, and had a consumer
/// migration guide written for it before anything asked the transport that question.
///
/// So this arm is the missing half of the exercise path: `--as-module <id>` claims a
/// launch with the nonce the supervisor injected, and a scoped call can then be
/// authorized by a GRANT rather than by a bearer token.
///
/// MEASURED WITH A NEGATIVE CONTROL, because the dangerous failure would be silent: a
/// route.open carrying a WRONG nonce is answered with an ERROR FRAME and the route never
/// opens. It is NOT downgraded to `Direct`. That matters — a silent downgrade would make
/// a forged claim indistinguishable from no claim, and a consumer whose nonce had gone
/// stale would see scoped refusals and go looking at its grants.
async fn route_open(
    stream: &mut TcpStream,
    root: &std::path::Path,
    as_module: Option<&str>,
) -> (u16, u32) {
    let target = RouteTarget::ManagementSurface {
        module_id: MODULE_ID.to_string(),
    };
    // `BindIdentity::new` rather than a literal: 0.20 made the type non-exhaustive so an
    // additive field cannot force a construction-site migration. `project_id` stays
    // absent, which subc's contract calls the correct answer for a producer that cannot
    // answer consistently -- alternating forks the consumer's lineage silently.
    let identity = BindIdentity::new(
        root.to_path_buf(),
        "vault-read-probe".to_string(),
        "probe-1".to_string(),
    );
    let mut body = json!({ "op": "route.open", "target": target, "identity": identity });
    if let Some(module_id) = as_module {
        // The nonce comes from the environment the supervisor injected, never from a
        // flag: a nonce an operator can type is a nonce an operator can guess wrong, and
        // the failure would be a refused route rather than anything legible.
        let launch_nonce = std::env::var("SUBC_LAUNCH_NONCE").unwrap_or_else(|_| {
            eprintln!(
                "vault_read_probe: --as-module needs SUBC_LAUNCH_NONCE in the environment. \
                 Only a supervisor-spawned process has one; run this from inside a \
                 supervised module, or omit the flag to bind as Direct."
            );
            std::process::exit(2);
        });
        body["consumer_identity"] = json!({
            "module_id": module_id,
            "launch_nonce": launch_nonce,
        });
    }
    let frame = control_rpc(stream, 1, body).await;
    assert_eq!(
        frame.header.ty,
        FrameType::Response,
        "route.open refused. With --as-module this means the launch claim was REJECTED \
         (wrong or stale SUBC_LAUNCH_NONCE, or a module id the supervisor did not spawn); \
         the daemon refuses rather than downgrading to Direct. Body: {}",
        String::from_utf8_lossy(&frame.body)
    );
    let value: Value = serde_json::from_slice(&frame.body).unwrap();
    // Wire v2: route identity is (channel, epoch); both are stamped on every frame.
    (
        value["route_channel"].as_u64().unwrap() as u16,
        value["route_epoch"].as_u64().unwrap() as u32,
    )
}

/// Send `credential.report_auth_failure`. See the `--report-auth-failure` arm for why
/// this exists and why a stale `record_version` is the safe way to drive it.
/// Report a served credential dead.
///
/// THREE ADDRESSING SHAPES, and the third is why this arm exists: `handle` for an
/// anonymous bearer, `credential_id` for a supervised caller holding a `Read` grant, and
/// `credential_id` + `enrollment_token` for a host-launched consumer that holds neither.
/// Until the token was accepted here, an enrolled consumer could discover a credential and
/// fetch it and then had NO WAY TO SAY IT WAS DEAD -- the recovery loop broken for exactly
/// the caller enrollment creates.
/// How the caller is addressing the report. A struct rather than three more parameters,
/// because the three are mutually constrained -- a token is meaningless without an id, and
/// an id with a handle is refused -- and separate arguments let a caller express
/// combinations the vault rejects.
struct ReportAddress<'a> {
    handle: &'a str,
    credential_id: Option<&'a str>,
    enrollment_token: Option<&'a str>,
}

/// Enumerate what the caller's own grants cover.
///
/// EMPTY PARAMS ARE NOT ALLOWED TO BE ABSENT: the op decodes `params: {}` and rejects an
/// absent or null params object, so a caller cannot accidentally ask a different question
/// by omitting it.
async fn credential_list_scoped(
    stream: &mut TcpStream,
    route_channel: u16,
    route_epoch: u32,
    enrollment_token: Option<&str>,
) -> Frame {
    let mut params = json!({});
    if let Some(token) = enrollment_token {
        params["enrollment_token"] = json!(token);
    }
    let frame = Frame::build(
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        route_channel,
        route_epoch,
        9_001,
        serde_json::to_vec(&json!({
            "method": "credential.list_scoped",
            "params": params,
        }))
        .unwrap(),
    )
    .expect("build list_scoped frame");
    write_frame(stream, &frame).await.unwrap();
    // MATCH ON corr, like every other caller here: the daemon multiplexes, so the next
    // frame on the wire is not necessarily the answer to this question.
    loop {
        let frame = read_frame_timeout(stream).await;
        if frame.header.corr == 9_001
            && matches!(frame.header.ty, FrameType::Response | FrameType::Error)
        {
            return frame;
        }
    }
}

async fn credential_report_auth_failure(
    stream: &mut TcpStream,
    route_channel: u16,
    route_epoch: u32,
    address: ReportAddress<'_>,
    provider_status: u16,
    record_version: u64,
    reporter_source: Option<&str>,
) -> Frame {
    let mut params = json!({
        "provider_status": provider_status,
        "record_version": record_version,
    });
    // EXACTLY ONE ADDRESS. `handle` and `credential_id` together are refused by the vault
    // as `not_found` -- two addresses is a caller that does not know what it is holding.
    match address.credential_id {
        Some(id) => {
            params["credential_id"] = json!(id);
            if let Some(token) = address.enrollment_token {
                params["enrollment_token"] = json!(token);
            }
        }
        None => params["handle"] = json!(address.handle),
    }
    // Absent unless asked for, because ABSENT IS THE CONTRACT for every consumer that
    // predates the field: a probe that always sent it would prove the accepting path
    // and say nothing about whether omitting it still works.
    if let Some(src) = reporter_source {
        params["reporter_source"] = json!(src);
    }
    let frame = Frame::build(
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        route_channel,
        route_epoch,
        8,
        serde_json::to_vec(&json!({
            "method": "credential.report_auth_failure",
            "params": params,
        }))
        .unwrap(),
    )
    .unwrap();
    write_frame(stream, &frame).await.unwrap();
    loop {
        let frame = read_frame_timeout(stream).await;
        if frame.header.corr == 8
            && matches!(frame.header.ty, FrameType::Response | FrameType::Error)
        {
            return frame;
        }
    }
}

async fn credential_get(
    stream: &mut TcpStream,
    route_channel: u16,
    route_epoch: u32,
    handle: &str,
    force_refresh: bool,
    min_ttl_ms: Option<i64>,
) -> Frame {
    let mut params = json!({ "handle": handle, "force_refresh": force_refresh });
    if let Some(ttl) = min_ttl_ms {
        params["min_ttl_ms"] = json!(ttl);
    }
    let frame = Frame::build(
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        route_channel,
        route_epoch,
        7,
        serde_json::to_vec(&json!({ "method": "credential.get", "params": params })).unwrap(),
    )
    .unwrap();
    write_frame(stream, &frame).await.unwrap();
    loop {
        let frame = read_frame_timeout(stream).await;
        if frame.header.corr == 7
            && matches!(frame.header.ty, FrameType::Response | FrameType::Error)
        {
            return frame;
        }
    }
}

/// Decode a JWT access-token payload client-side and pull the non-secret ChatGPT
/// account-id claim (`"https://api.openai.com/auth".chatgpt_account_id`). This is
/// the same claim path the vault's own `account_id_for_adapter` uses; duplicated
/// here because the example must work against a daemon predating that field.
fn chatgpt_account_id_from_payload(payload: &[u8]) -> Option<String> {
    let claims = jwt_claims_from_payload(payload)?;
    claims
        .get("https://api.openai.com/auth")?
        .get("chatgpt_account_id")?
        .as_str()
        .map(str::to_string)
}

/// Decode a JWT's claims segment (payload part only — never the signature).
fn jwt_claims_from_payload(payload: &[u8]) -> Option<Value> {
    let token = std::str::from_utf8(payload).ok()?;
    let claims_b64 = token.split('.').nth(1)?;
    let claims_json = base64url_decode(claims_b64)?;
    serde_json::from_slice(&claims_json).ok()
}

/// Minimal unpadded base64url decoder (RFC 4648 §5) — dependency-free so the
/// example stays a pure consumer of the wire.
fn base64url_decode(s: &str) -> Option<Vec<u8>> {
    fn val(b: u8) -> Option<u32> {
        match b {
            b'A'..=b'Z' => Some((b - b'A') as u32),
            b'a'..=b'z' => Some((b - b'a') as u32 + 26),
            b'0'..=b'9' => Some((b - b'0') as u32 + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }
    let bytes = s.trim_end_matches('=').as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let mut acc: u32 = 0;
        for (i, &b) in chunk.iter().enumerate() {
            acc |= val(b)? << (18 - 6 * i);
        }
        let n = chunk.len();
        if n >= 2 {
            out.push((acc >> 16) as u8);
        }
        if n >= 3 {
            out.push((acc >> 8) as u8);
        }
        if n == 4 {
            out.push(acc as u8);
        }
    }
    Some(out)
}

/// FNV-1a-64: a stable, dependency-free fingerprint used only to compare two byte
/// strings for equality without revealing either. NOT a cryptographic hash.
fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Print whether the read succeeded WITHOUT exposing the secret: only the payload
/// length and a one-way fingerprint are shown.
fn report(frame: &Frame, show_account_id: bool, show_claims: bool) {
    match frame.header.ty {
        FrameType::Response => {
            let value: Value = serde_json::from_slice(&frame.body).unwrap_or(Value::Null);
            // The read surface wraps the result as `{ "result": { "payload": [u8...] } }`.
            // Show only the payload length and a one-way fingerprint (FNV-1a-64 hex of
            // the bytes) — never the content. The fingerprint lets an operator compare
            // the served bytes against an expected token's fingerprint WITHOUT either
            // side exposing the secret.
            let payload = value
                .get("result")
                .and_then(|r| r.get("payload"))
                .and_then(|p| p.as_array());
            match payload {
                Some(arr) => {
                    let bytes: Vec<u8> = arr
                        .iter()
                        .filter_map(|b| b.as_u64().map(|n| n as u8))
                        .collect();
                    println!("OK credential.get returned a Response.");
                    println!(
                        "   payload: {} byte(s), fnv1a64={:016x} (content withheld)",
                        bytes.len(),
                        fnv1a64(&bytes)
                    );
                    // Non-secret metadata, printed verbatim. `account_id` plus
                    // `record_version` is the routing binding; `credential_id` is printed
                    // only so a deploy can verify the operator's handle-to-manifest binding,
                    // never as another routing key.
                    //
                    // `email` AND `org_name` ARE HERE BECAUSE THEIR ABSENCE WAS UNREADABLE.
                    // The read surface serves three identity fields and this list carried
                    // one, so a record with an email and no `account_id` -- the exact shape
                    // `RecordIdentity::is_servable` exists to reject, which makes a consumer
                    // collapse its per-account labels into one unlabelled row -- rendered
                    // here IDENTICALLY to a record with no identity at all. A consumer
                    // reported that collapse from downstream and this probe could not
                    // confirm or refute the cause, which is the one job it has on a deploy.
                    let result = value.get("result");
                    for key in [
                        "credential_id",
                        "record_version",
                        "account_id",
                        "email",
                        "org_name",
                        "project_id",
                    ] {
                        if let Some(v) = result.and_then(|r| r.get(key)) {
                            println!("   {key}: {v}");
                        }
                    }
                    if show_account_id {
                        match chatgpt_account_id_from_payload(&bytes) {
                            Some(account) => println!("   chatgpt account id (client-side decode): {account}"),
                            None => println!("   chatgpt account id: none (payload is not a JWT carrying the claim)"),
                        }
                    }
                    if show_claims {
                        match jwt_claims_from_payload(&bytes) {
                            Some(claims) => println!(
                                "   claims:\n{}",
                                serde_json::to_string_pretty(&claims).unwrap_or_default()
                            ),
                            None => println!("   claims: payload is not a decodable JWT"),
                        }
                    }
                }
                None => {
                    println!("OK Response, but no result.payload array found.");
                    println!(
                        "   result.error = {}",
                        value
                            .get("result")
                            .and_then(|r| r.get("error"))
                            .cloned()
                            .unwrap_or(Value::Null)
                    );
                }
            }
        }
        FrameType::Error => {
            println!(
                "ERROR credential.get returned an Error frame: {}",
                String::from_utf8_lossy(&frame.body)
            );
            std::process::exit(1);
        }
        ty => {
            println!("UNEXPECTED terminal frame {ty:?}");
            std::process::exit(1);
        }
    }
}
