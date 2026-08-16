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
//! with an audit chain; an operator reads it out and hands it here.
//!
//! DO NOT COPY THIS CHOICE INTO A SENDER. It is right for a hand-run diagnostic and
//! wrong for anything automated. The original text here generalised it to "the same
//! shape the eventual push Worker uses — a deploy-time read, not a runtime one", and
//! that reasoning only holds for an EDGE WORKER, which cannot reach this vault at all
//! and must therefore receive the key as a deployed secret.
//!
//! A HOST-SIDE SENDER CAN REACH THE VAULT, so it should fetch by capability handle at
//! send time. Two properties a deploy-time read cannot give it: revocation actually
//! takes effect (a deployed copy keeps working after the grant is withdrawn), and no
//! `.p8` exists in the sender's config or environment. prefrontal-core's push producer
//! is built that way deliberately.
//!
//! The generalisation was mine and it nearly propagated: it reads as guidance to the
//! next person who opens this file, and the next person's sender was not a Worker.
//!
//! ## Usage
//!
//! ```text
//! cargo run --example apns_hand_send -- \
//!     --key-file ~/.appstoreconnect/private_keys/AuthKey_XXXXXXXXXX.p8 \
//!     --key-id XXXXXXXXXX --team-id YYYYYYYYYY \
//!     --topic io.cortexkit.alfonso \
//!     --device-token <hex> \
//!     --sealed-hex <hex of the sealed blob> \
//!     [--title TEXT] [--body TEXT] [--dry-run] \
//!     [--sandbox] [--push-type background] [--priority 5]
//! ```
//!
//! `--sealed-hex` takes the blob alone and composes the APNs payload around it.
//! `--payload-hex` is the escape hatch: it sends a complete JSON body verbatim, for
//! shapes this tool does not model.
//!
//! ## Why the title is settable
//!
//! To LABEL a send, not to diagnose one. When several notifications are in flight,
//! the title is what identifies which submission produced the one on screen.
//!
//! It is deliberately not a diagnostic, and the distinction is worth stating because
//! the opposite is intuitive. A notification arriving with its sent title unchanged
//! is consistent with the receiving extension never having run AND with it having run
//! and failed to decrypt — two causes with different owners — whenever that extension
//! leaves the visible text alone on its failure path. Leaving it alone is the sane
//! choice there, since a failed decrypt should still show something coherent rather
//! than a diagnostic string, so a sender cannot assume otherwise.
//!
//! Splitting those two therefore requires something written unconditionally by the
//! receiver, which is not a property a sender can supply or verify. Treating the
//! title as that instrument would report "never invoked" for a decrypt failure and
//! send the investigation to the wrong component with false confidence.

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

/// Take the value out of a `name<sep>value` line, or return the input unchanged.
///
/// The values this tool consumes are produced elsewhere and reach it through a human
/// and a clipboard. A producer that emits them bare forces the human to remember
/// which of two identically-shaped hex strings goes where; a producer that labels
/// them removes that decision but hands this tool something it would otherwise reject
/// as malformed. Accepting the labelled form is what makes the label worth emitting.
///
/// Both `=` and `: ` are accepted because both are in use by different producers, and
/// a receiver that took only one would silently push the cost back onto the person
/// pasting. The label must MATCH the expected name: a line naming a different field
/// is a wrong-value paste, which is a different fault from a malformed one and must
/// not be quietly unwrapped into acceptance.
fn strip_label<'a>(line: &'a str, expected: &str) -> &'a str {
    let Some((name, value)) = line
        .split_once('=')
        .or_else(|| line.split_once(':'))
        .map(|(n, v)| (n.trim(), v.trim()))
    else {
        return line;
    };
    // Only a name this tool RECOGNISES counts as a label. Accepting any
    // separator-prefixed word would swallow text that merely contains a colon --
    // including a failure message, whose first word would then be reported as a
    // mislabelled field. That reading is both wrong and less useful than the one it
    // displaces, because the prose arm below says where the fault actually happened.
    //
    // So an unrecognised name falls through untouched and reaches the checks that can
    // classify it, rather than being claimed by this one.
    const KNOWN_LABELS: [&str; 2] = ["apns_device_token_hex", "push_seal_pubkey_hex"];
    if !KNOWN_LABELS
        .iter()
        .any(|known| name.eq_ignore_ascii_case(known))
    {
        return line;
    }
    if name.eq_ignore_ascii_case(expected) {
        return value;
    }
    eprintln!("error: this value is labelled {name:?}, but {expected:?} was expected.");
    eprintln!(
        "  Two 32-byte hex values are indistinguishable once their labels are gone, so \
         the label is the only thing that can catch this. Sent anyway, this would be \
         refused by APNs as an unknown device -- which reads as an enrollment or \
         environment problem and sends you checking things that are fine."
    );
    std::process::exit(2);
}

/// Strip surrounding whitespace and reject anything that is not lowercase-able hex.
///
/// Refuses rather than silently repairing anything beyond whitespace: a token with a
/// `0x` prefix or internal spaces is a paste that went wrong, and quietly "fixing" it
/// risks sending to an address the operator did not intend.
fn normalize_device_token(raw: &str) -> String {
    let trimmed = strip_label(raw.trim(), "apns_device_token_hex");
    if trimmed.is_empty() {
        eprintln!("error: --device-token is empty");
        std::process::exit(2);
    }
    // Before reporting a hex problem, check whether this is prose rather than a
    // damaged token. A value produced by a failing device-side read can reach a
    // clipboard as its own error text, and "not valid hex" is then true, precise and
    // misdirecting: it sends the reader to inspect their paste, while the fault it is
    // describing already happened on the device. An error message that becomes a
    // value stops being an error message, so the receiver has to recognise the shape.
    let looks_like_prose = trimmed.contains(':')
        || trimmed.contains(' ')
            && trimmed.split_whitespace().any(|w| {
                w.chars()
                    .any(|c| c.is_ascii_alphabetic() && !c.is_ascii_hexdigit())
            });
    if looks_like_prose {
        eprintln!("error: --device-token looks like a MESSAGE rather than a token: {trimmed:?}");
        eprintln!(
            "  A device token is bare lowercase hex. Text like this usually means the \
             value was copied from a control that reported a failure instead of \
             producing a key or token -- so the fault is on the device that generated \
             it, not in the paste. Do not retry the send; read the reported failure."
        );
        std::process::exit(2);
    }
    if let Some(bad) = trimmed.chars().find(|c| !c.is_ascii_hexdigit()) {
        eprintln!(
            "error: --device-token contains {bad:?}, which is not a hex digit. APNs \
             device tokens are hex only."
        );
        eprintln!(
            "  A token pasted from a screen may carry spaces or a 0x prefix. Note APNs \
             answers BadDeviceToken for a malformed token AND for an unregistered \
             device, so an unvalidated paste is indistinguishable from a device that \
             was never enrolled."
        );
        std::process::exit(2);
    }
    if !trimmed.len().is_multiple_of(2) {
        eprintln!(
            "error: --device-token has an odd number of hex digits ({}), so it is \
             truncated or over-copied.",
            trimmed.len()
        );
        std::process::exit(2);
    }
    trimmed.to_ascii_lowercase()
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
    // The device token arrives by copy-paste from a phone screen, so it is the input
    // most likely to carry whitespace or a stray prefix. It is interpolated straight
    // into the request path, and an unvalidated one produces a URL that APNs refuses
    // with `BadDeviceToken` -- the same reason a genuinely unknown device produces.
    //
    // That collision is the whole reason for validating here: `BadDeviceToken` is the
    // arm that means "this device is not registered for this environment and topic",
    // which sends someone to re-check the environment, the topic, and the enrollment.
    // A trailing newline would send them down that path over a paste artifact.
    let device_token = normalize_device_token(&require("--device-token"));
    let sealed_hex = arg("--sealed-hex");
    let payload_hex = arg("--payload-hex");

    // The title labels which send produced a given notification. It is not a
    // diagnostic: see the module header for why a sender cannot distinguish an
    // extension that never ran from one that ran and failed to decrypt.
    //
    // The default is distinct per send rather than a fixed string. A receiver that
    // preserves the sent title lets an observer say WHICH submission produced a given
    // notification, but only if the titles differ -- and with a fixed default the
    // useful case would depend on remembering to pass a flag, where forgetting is
    // indistinguishable from a receiver that discarded the value. The suffix is the
    // submission's own clock, so uniqueness needs no state and no coordination.
    let title = arg("--title").unwrap_or_else(|| {
        format!(
            "Alfonso #{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() % 100_000)
                .unwrap_or(0)
        )
    });
    let body = arg("--body").unwrap_or_else(|| "needs you".to_string());

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
    // Carried alongside the body so the acceptance can report what was sent. `None`
    // means this tool did not compose the payload, so it cannot vouch for its
    // contents -- which is a different statement from "no blob was sent" and is
    // reported as such.
    let mut sent_blob_len: Option<usize> = None;
    let body = match (sealed_hex.as_deref(), payload_hex.as_deref()) {
        (Some(sealed), None) => {
            // Validate as hex before wrapping, so a malformed blob is refused here
            // rather than delivered as a payload the device silently fails to open.
            let raw = decode_hex(sealed, "--sealed-hex");
            sent_blob_len = Some(raw.len());
            // Compose BEFORE reporting. Announcing the wrap first would print a
            // success line for a blob about to be refused, and the reader who scans
            // for the last line would see the error while the reader who scans for
            // the first would see a confirmation of something that did not happen.
            let envelope = match compose_envelope(&raw, &title, &body) {
                Ok(envelope) => envelope,
                Err(why) => {
                    eprintln!("error: {why}");
                    std::process::exit(2);
                }
            };
            eprintln!(
                "[apns] wrapped {} sealed byte(s) as base64 under \"{}\", with \
                 {}:1",
                raw.len(),
                SEALED_BLOB_KEY,
                MUTABLE_CONTENT_KEY
            );
            envelope
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
            // Echo what was sent alongside the acceptance. An observer comparing what
            // appeared on a device against what left here needs both halves, and only
            // this process holds the second one -- so printing it is what makes a later
            // comparison possible rather than a recollection.
            //
            // The sealed-key line is the load-bearing one. "Arrived carrying no sealed
            // blob" has two causes on different sides: the body was composed without
            // one, or it carried one and something between here and the device dropped
            // it. Nothing observable on the device separates them, because the device
            // sees only what arrived. Recording presence and size at the sending end is
            // the only evidence that can, and it costs one line.
            println!("Sent with title: {title}");
            // Echo the address this was sent to, abbreviated.
            //
            // The device token and the sealing key are both 32 bytes of hex, so a
            // human comparing them has nothing to go on but the values themselves --
            // no length, shape or checksum separates them. Printing the ends of what
            // was actually used lets someone hold it against the value the device
            // reports.
            //
            // What that comparison can and cannot do is worth being exact about,
            // because a displayed value reads as verification. Both renderings derive
            // from the same source value, so agreement proves only that it survived
            // the journey intact: it catches a truncated copy, a dropped character, a
            // paste that picked up part of a neighbouring line. It CANNOT show that
            // the right artefact was chosen -- the wrong value, faithfully copied,
            // matches perfectly. Only a party holding the corresponding private key
            // can establish that, and this process holds nothing of the kind.
            //
            // Ends rather than the whole thing: enough to compare against a screen, and
            // it keeps a routing address out of a line that may be pasted into a
            // channel. The full value is what was passed in, so it is not lost.
            println!(
                "Sent to device: {}…{} ({} hex chars)",
                &device_token[..8.min(device_token.len())],
                &device_token[device_token.len().saturating_sub(8)..],
                device_token.len()
            );
            println!(
                "Sent with \"{}\": {}",
                SEALED_BLOB_KEY,
                match sent_blob_len {
                    Some(n) => format!("present, {n} sealed byte(s) before base64"),
                    None => "ABSENT (verbatim payload; this tool did not compose it)".to_string(),
                }
            );
            println!();
            println!("This means APNs accepted the request, NOT that a device received it.");
            println!("There is no delivery callback; the device is the only observer.");
            // The observations are listed here rather than left to be recalled because
            // this is the moment someone needs them, and because the middle row is the
            // trap: it has three causes and reads like one.
            //
            // It is stated as proving NOTHING rather than as ruling any cause in or out.
            // Naming a likely cause sends the investigation there, and naming an
            // unlikely one sends it away -- both are the same error, and one of the
            // three causes IS the decryption not happening, since an extension that
            // never runs never decrypts. The three are indistinguishable from this
            // side because each fails by doing nothing at all.
            println!();
            println!("What each observation on the device proves:");
            println!("  opens to the ask         the payload decrypted AND the tap routed");
            println!("  opens, stays put         proves NOTHING on its own. Three causes:");
            println!("                           the id was absent from the payload, OR the");
            println!("                           extension never ran, OR the tap routing is");
            println!("                           broken. Each fails by doing nothing.");
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
