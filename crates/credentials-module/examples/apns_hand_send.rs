//! Send one already-sealed notification to APNs, by hand.
//!
//! The operator-driven half of the push path: it mints a provider token from the
//! APNs signing key and performs one submission. It does NOT seal — the blob is
//! produced elsewhere and passed in as hex — and it holds no device registry, so
//! the device token is an argument rather than a lookup.
//!
//! That scope is deliberate. The point of a hand-send is to exercise the pipe with
//! every other moving part removed, so a failure has one candidate cause. A tool
//! that also sealed, or also resolved a device, would fail in three places and
//! report one.
//!
//! ## Reading the key
//!
//! The signing key is passed by PATH rather than read from the vault over the route
//! plane, because the vault serves credentials to consumers that can reach it and
//! this tool runs beside an operator. The vault holds the key as source of record
//! with an audit chain; an operator reads it out and hands it here. That is the same
//! shape the eventual push Worker uses — a deploy-time read, not a runtime one.
//!
//! ## Usage
//!
//! ```text
//! cargo run --example apns_hand_send -- \
//!     --key-file ~/.appstoreconnect/private_keys/AuthKey_XXXXXXXXXX.p8 \
//!     --key-id XXXXXXXXXX --team-id YYYYYYYYYY \
//!     --topic io.cortexkit.alfonso \
//!     --device-token <hex> \
//!     --payload-hex <hex of the sealed blob> \
//!     [--sandbox] [--push-type background] [--priority 5]
//! ```

use credentials_core::apns::{mint_provider_token, ApnsEnvironment, ApnsKeyIdentity};
use credentials_core::apns_submit::{
    compose_envelope, submit, RefusalKind, SubmitOutcome, SubmitRequest, MUTABLE_CONTENT_KEY,
    SEALED_BLOB_KEY,
};

fn arg(name: &str) -> Option<String> {
    let args: Vec<String> = std::env::args().collect();
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn flag(name: &str) -> bool {
    std::env::args().any(|a| a == name)
}

fn require(name: &str) -> String {
    match arg(name) {
        Some(v) => v,
        None => {
            eprintln!("missing required argument {name}");
            eprintln!("see the module header for usage");
            std::process::exit(2);
        }
    }
}

fn decode_hex(s: &str, what: &str) -> Vec<u8> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        eprintln!("{what} is not valid hex: odd length");
        std::process::exit(2);
    }
    match (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect::<Result<Vec<u8>, _>>()
    {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("{what} is not valid hex: {e}");
            std::process::exit(2);
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let key_file = require("--key-file");
    let key_id = require("--key-id");
    let team_id = require("--team-id");
    let topic = require("--topic");
    let device_token = require("--device-token");
    let sealed_hex = arg("--sealed-hex");
    let payload_hex = arg("--payload-hex");

    let environment = if flag("--sandbox") {
        ApnsEnvironment::Sandbox
    } else {
        ApnsEnvironment::Production
    };
    let push_type = arg("--push-type").unwrap_or_else(|| "alert".to_string());
    let priority: u8 = arg("--priority").and_then(|p| p.parse().ok()).unwrap_or(10);

    let p8 = match std::fs::read_to_string(&key_file) {
        Ok(pem) => pem,
        Err(e) => {
            eprintln!("cannot read signing key at {key_file}: {e}");
            std::process::exit(2);
        }
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is before the unix epoch")
        .as_secs() as i64;

    let identity = ApnsKeyIdentity { key_id, team_id };
    let token = match mint_provider_token(&p8, &identity, now) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("cannot mint a provider token: {e}");
            std::process::exit(1);
        }
    };

    // Two ways to supply the body, and the default is the one that works.
    //
    // `--sealed-hex` takes the sealed blob alone and wraps it in the APNs payload
    // the device requires. `--payload-hex` takes a complete JSON body verbatim, for
    // sending something this tool does not model.
    //
    // The wrapping is not a convenience. A sealed blob sent as the whole body is a
    // valid APNs request that APNs ACCEPTS and the device DISCARDS: without an `aps`
    // dictionary it is not a displayable notification, and without `mutable-content`
    // iOS never runs the service extension that would decrypt it. Both failures are
    // silent and land on the device, which is the one place none of the senders can
    // observe -- so the tool composes the envelope rather than trusting each operator
    // to remember it.
    let body = match (sealed_hex.as_deref(), payload_hex.as_deref()) {
        (Some(sealed), None) => {
            // Validate as hex before wrapping, so a malformed blob is refused here
            // rather than delivered as a payload the device silently fails to open.
            let raw = decode_hex(sealed, "--sealed-hex");
            eprintln!(
                "[apns] wrapped {} sealed byte(s) as base64 under \"{}\", with \
                 {}:1",
                raw.len(),
                SEALED_BLOB_KEY,
                MUTABLE_CONTENT_KEY
            );
            compose_envelope(&raw, "Alfonso", "needs you")
        }
        (None, Some(payload)) => {
            eprintln!("[apns] sending --payload-hex verbatim; nothing is added to it");
            let raw = decode_hex(payload, "--payload-hex");
            // Verbatim mode sends the caller's body unchanged rather than composing
            // the envelope, so two omissions can reach the device: a body without
            // `mutable-content` is displayed with the service extension never running
            // (the sealed blob is never decrypted), and a body without an `aps`
            // dictionary is discarded entirely. APNs answers 200 to both, so this
            // process is the last one that can observe either.
            //
            // Warn rather than refuse: sending a deliberately odd body is the whole
            // reason this mode exists, and a tool that refuses its own escape hatch
            // gets worked around with curl, which warns about nothing at all.
            let text = String::from_utf8_lossy(&raw);
            if !text.contains(MUTABLE_CONTENT_KEY) {
                eprintln!(
                    "[apns] WARNING: no \"{MUTABLE_CONTENT_KEY}\" in this body. iOS will \
                     display the notification and never run the extension, so a sealed \
                     blob inside it is never decrypted. APNs will still answer 200."
                );
            }
            if !text.contains("\"aps\"") {
                eprintln!(
                    "[apns] WARNING: no \"aps\" dictionary in this body. iOS discards a \
                     notification without one. APNs will still answer 200."
                );
            }
            raw
        }
        (Some(_), Some(_)) => {
            eprintln!("error: pass --sealed-hex OR --payload-hex, not both");
            std::process::exit(2);
        }
        (None, None) => {
            eprintln!("error: one of --sealed-hex or --payload-hex is required");
            std::process::exit(2);
        }
    };

    // Print the exact bytes before sending. A sealed payload is opaque to everyone
    // between here and the device, so this is the last point at which a human can
    // see what is actually going out -- and the envelope's two silent failure modes
    // (no `aps` dictionary, no `mutable-content`) are visible here and nowhere else.
    if flag("--dry-run") {
        println!("{}", String::from_utf8_lossy(&body));
        eprintln!("[apns] --dry-run: nothing was sent");
        return;
    }

    // http2 is not optional here: APNs speaks nothing else, and without it the
    // client negotiates 1.1 and is refused at the transport with no APNs reason.
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("cannot build an http client: {e}");
            std::process::exit(1);
        }
    };

    let request = SubmitRequest {
        device_token_hex: &device_token,
        topic: &topic,
        environment,
        push_type: &push_type,
        priority,
        collapse_id: None,
    };

    println!("[apns] host {}", environment.host());
    println!("[apns] topic {topic}, push-type {push_type}, priority {priority}");
    println!("[apns] payload {} byte(s)", body.len());

    match submit(&client, &request, &token.jwt, &body).await {
        Ok(SubmitOutcome::Accepted { apns_id }) => {
            println!(
                "ACCEPTED FOR DELIVERY. apns-id {}",
                apns_id.as_deref().unwrap_or("(none returned)")
            );
            // Said plainly because the distinction is the whole difficulty of this
            // path: APNs offers no delivery callback, so acceptance is the strongest
            // signal that exists and it is not a confirmation.
            println!();
            println!("This means APNs accepted the request, NOT that a device received it.");
            println!("There is no delivery callback; the device is the only observer.");
            // The observations are listed here rather than left to be recalled because
            // this is the moment someone needs them, and because the middle row is the
            // trap: it has three causes and reads like one. Someone who takes it for a
            // decrypt failure investigates the sealing and opening code, which is the
            // part with tests, while the actual fault is a payload field or a routing
            // hop that fails by doing nothing.
            println!();
            println!("What each observation on the device proves:");
            println!("  opens to the ask         the payload decrypted AND the tap routed");
            println!("  opens, stays put         the id was absent OR routing is broken");
            println!("                           (this does NOT mean the decrypt failed)");
            println!("  generic line, untapped   proves delivery only, nothing about decryption");
            println!("  nothing at all           delivery failed; APNs already said it accepted");
        }
        Ok(SubmitOutcome::Refused {
            status,
            reason,
            detail,
        }) => {
            let reason_shown = if reason.is_empty() {
                "(no reason in body)"
            } else {
                &reason
            };
            println!("REFUSED {status} {reason_shown}");
            // The remedy, not just the classification. A refusal an operator cannot
            // act on is the same as no diagnosis.
            let advice = match detail {
                RefusalKind::ProviderToken => {
                    "the token or signing key is wrong; minting a fresh token may fix it"
                }
                RefusalKind::EnvironmentMismatch => {
                    "the signing key is configured for the OTHER APNs environment; \
                     no token minted from this key will satisfy this host — change \
                     the host or the key, never the token"
                }
                RefusalKind::DeviceToken => {
                    "the device token is unknown to this environment+topic, or the \
                     app was uninstalled"
                }
                RefusalKind::Topic => "the topic does not match the app this token was issued for",
                RefusalKind::PayloadTooLarge => "the sealed payload exceeds the APNs ceiling",
                RefusalKind::TokenChurn => {
                    "provider tokens are being minted too often; reuse one until it is stale"
                }
                RefusalKind::Transient => "transient; a retry may succeed",
                RefusalKind::Unclassified => {
                    "not a reason this tool models — report the status and reason \
                     rather than assuming a remedy"
                }
            };
            println!("  {advice}");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("TRANSPORT FAILURE: {e}");
            eprintln!("  no APNs reason exists for this — the request did not complete.");
            eprintln!("  if this mentions a protocol or ALPN error, the client lacks HTTP/2.");
            std::process::exit(1);
        }
    }
}
