//! Submitting a sealed notification to APNs.
//!
//! The network half of [`crate::apns`]. It takes a device token and an already-sealed
//! payload and performs the one POST APNs defines; it does not seal, does not hold a
//! device registry, and does not decide what is worth sending.
//!
//! ## Why the response handling is the interesting part
//!
//! APNs answers a successful submission with a bare 200 and no body. That is the
//! whole confirmation — it means *accepted for delivery*, NOT delivered, and there is
//! no later callback that says otherwise. So a 200 is the weakest useful signal in
//! this path: it says the request was well-formed and authorized, and nothing about
//! whether a device ever saw it.
//!
//! What that does NOT mean, measured against the live service rather than reasoned
//! from the property: APNs is not silent about misconfiguration. A provider token
//! minted from a key configured for the other environment is refused AT SUBMIT with
//! `BadEnvironmentKeyInToken` — a named reason, not a drop. It is worth stating
//! because the opposite is the intuitive conclusion from "a token is valid in one
//! environment only", and reasoning from that true property to a silent failure
//! produces a plausible claim that costs an operator hours in the wrong place.
//!
//! So the refusals below are the diagnosis APNs actually offers, which is more than
//! it is usually credited with. Collapsing them into "push failed" throws it away;
//! that is the reason they are modelled as reasons rather than logged as strings.

use crate::apns::{device_path, ApnsEnvironment};

/// How APNs answered a submission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubmitOutcome {
    /// HTTP 200: accepted for delivery — NOT a delivery confirmation. `apns_id` is
    /// Apple's identifier for the notification, worth recording because it is the
    /// only handle a support conversation with Apple can use.
    Accepted { apns_id: Option<String> },
    /// A typed refusal. `status` and `reason` are Apple's own, kept verbatim so a
    /// reason we have not modelled is still legible rather than flattened.
    Refused {
        status: u16,
        reason: String,
        detail: RefusalKind,
    },
}

/// The refusal reasons worth branching on, with the ones that share a symptom kept
/// distinct because their remedies differ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalKind {
    /// 403 `ExpiredProviderToken` / `InvalidProviderToken` / `MissingProviderToken`.
    /// The signing key or the minted token is wrong. Retrying with the same token
    /// cannot succeed; minting a fresh one might.
    ProviderToken,
    /// 403 `BadEnvironmentKeyInToken`. The signing key is configured for the OTHER
    /// APNs environment than the host being addressed.
    ///
    /// Kept apart from [`RefusalKind::ProviderToken`] even though both are 403s,
    /// because the remedies are opposite: that arm says mint a fresh token, and
    /// minting a thousand fresh tokens from this key will never satisfy this host.
    /// The fix is the host or the key, never the token.
    ///
    /// This is also the reason a `.p8` needs no environment field to be diagnosable:
    /// the key's environment is not recorded in the file, but the service reports it
    /// on a mismatch. Submitting the same token to both hosts is therefore a live
    /// measurement of which environment a key was configured for — the production
    /// host answers `BadDeviceToken` (it authenticated, then failed to find the
    /// device) while the sandbox host answers this.
    EnvironmentMismatch,
    /// 400 `BadDeviceToken` / 410 `Unregistered`. The device token does not belong
    /// to this environment+topic, or the app was uninstalled.
    ///
    /// This is the arm that diagnoses an environment mismatch. A device token minted
    /// by a production build is refused here by the SANDBOX host, while the
    /// production host accepts it — so submitting the same token to both hosts
    /// distinguishes a production key from a sandbox one, which nothing in the `.p8`
    /// itself can do.
    DeviceToken,
    /// 400 `TopicDisallowed` / `DeviceTokenNotForTopic`. The topic does not match
    /// the app the token was issued for.
    Topic,
    /// 413 `PayloadTooLarge`. The sealed blob exceeded Apple's ceiling.
    PayloadTooLarge,
    /// 429 `TooManyProviderTokenUpdates` — minting a token per request rather than
    /// reusing one. A rate limit on token CHURN, not on notifications.
    TokenChurn,
    /// 429 (other) / 500 / 503. Transient; a retry may succeed.
    Transient,
    /// Anything not modelled above. Deliberately NOT folded into the nearest known
    /// arm: the known arms carry remedies, and sending an operator to rotate a key
    /// over a reason that meant something else is worse than saying nothing
    /// specific.
    Unclassified,
}

impl RefusalKind {
    /// Classify from Apple's status and reason string.
    ///
    /// Reason is checked BEFORE status, because status alone is ambiguous — 400
    /// covers a bad device token, a disallowed topic, and a malformed payload, which
    /// have three different remedies.
    pub fn classify(status: u16, reason: &str) -> Self {
        match reason {
            "ExpiredProviderToken" | "InvalidProviderToken" | "MissingProviderToken" => {
                RefusalKind::ProviderToken
            }
            "BadEnvironmentKeyInToken" => RefusalKind::EnvironmentMismatch,
            "BadDeviceToken" | "Unregistered" => RefusalKind::DeviceToken,
            "TopicDisallowed" | "DeviceTokenNotForTopic" => RefusalKind::Topic,
            "PayloadTooLarge" => RefusalKind::PayloadTooLarge,
            "TooManyProviderTokenUpdates" => RefusalKind::TokenChurn,
            "TooManyRequests" | "InternalServerError" | "ServiceUnavailable" | "Shutdown" => {
                RefusalKind::Transient
            }
            _ => match status {
                // Status-based fallback ONLY for reasons we have not seen. A 5xx is
                // safe to call transient; a 4xx is not safe to call anything.
                500..=599 => RefusalKind::Transient,
                _ => RefusalKind::Unclassified,
            },
        }
    }
}

/// What a submission needs beyond the payload. All non-secret.
#[derive(Debug, Clone)]
pub struct SubmitRequest<'a> {
    /// The target device's APNs token, hex.
    pub device_token_hex: &'a str,
    /// The app's bundle id.
    pub topic: &'a str,
    /// Production or sandbox. Selects the host.
    pub environment: ApnsEnvironment,
    /// `alert` for a user-visible notification, `background` for a silent one.
    pub push_type: &'a str,
    /// 10 for immediate, 5 for power-considerate.
    pub priority: u8,
    /// Optional collapse id — a later notification with the same id replaces an
    /// undelivered earlier one.
    pub collapse_id: Option<&'a str>,
}

/// The URL for a submission. Split out so the host/path composition is testable
/// without a network.
pub fn submit_url(request: &SubmitRequest<'_>) -> String {
    format!(
        "https://{}{}",
        request.environment.host(),
        device_path(request.device_token_hex)
    )
}

/// The headers APNs requires, as (name, value) pairs.
///
/// Built separately from the send so the header set is testable without a network.
/// `apns-topic` is mandatory under token auth (it is optional only for certificate
/// auth with a single-topic certificate), and omitting it is a 400 `MissingTopic`
/// rather than a default.
pub fn submit_headers<'a>(
    request: &SubmitRequest<'a>,
    bearer_jwt: &'a str,
) -> Vec<(&'static str, String)> {
    let mut headers = vec![
        ("authorization", format!("bearer {bearer_jwt}")),
        ("apns-topic", request.topic.to_string()),
        ("apns-push-type", request.push_type.to_string()),
        ("apns-priority", request.priority.to_string()),
    ];
    if let Some(collapse) = request.collapse_id {
        headers.push(("apns-collapse-id", collapse.to_string()));
    }
    headers
}

/// Classify an APNs response into an outcome.
///
/// Split from the send so the mapping is testable against recorded responses: the
/// interesting behaviour is what a status and body MEAN, and pinning that against
/// real captured shapes is worth more than exercising a socket.
pub fn classify_response(status: u16, apns_id: Option<String>, body: &str) -> SubmitOutcome {
    if status == 200 {
        return SubmitOutcome::Accepted { apns_id };
    }
    // APNs puts the reason in a JSON body: {"reason":"BadDeviceToken"}. A body that
    // does not parse is not an error to swallow -- it means Apple answered something
    // this code does not model, and an empty reason must not read as a known one.
    let reason = serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| {
            v.get("reason")
                .and_then(|r| r.as_str())
                .map(|s| s.to_string())
        })
        .unwrap_or_default();
    SubmitOutcome::Refused {
        status,
        detail: RefusalKind::classify(status, &reason),
        reason,
    }
}

/// Send one sealed notification to APNs.
///
/// Takes an already-minted bearer and an already-built body, because both are
/// decisions this function should not be making: the token is reused across many
/// sends (minting per request is a documented way to get rate-limited), and the
/// body's admissible contents are a contract question rather than a transport one.
///
/// The client MUST be built with HTTP/2 available. APNs speaks nothing else, and a
/// client that negotiates 1.1 is refused at the transport before any request is
/// seen — which presents as a connection error rather than as an APNs refusal, so
/// it is worth ruling out first when a submission fails without a reason string.
pub async fn submit(
    client: &reqwest::Client,
    request: &SubmitRequest<'_>,
    bearer_jwt: &str,
    body: &[u8],
) -> Result<SubmitOutcome, String> {
    let mut req = client
        .post(submit_url(request))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body.to_vec());
    for (name, value) in submit_headers(request, bearer_jwt) {
        req = req.header(name, value);
    }

    let response = req.send().await.map_err(|e| e.to_string())?;
    let status = response.status().as_u16();
    // Read apns-id BEFORE consuming the body: it is Apple's identifier for the
    // notification and the only handle a support conversation can use, so losing it
    // on the success path costs the one durable reference to a delivery.
    let apns_id = response
        .headers()
        .get("apns-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let text = response.text().await.unwrap_or_default();
    Ok(classify_response(status, apns_id, &text))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The header set APNs requires under token auth, including the one whose
    /// absence is a refusal rather than a default: `apns-topic` is optional only for
    /// certificate auth, and omitting it here is a 400 `MissingTopic`.
    #[test]
    fn headers_carry_what_token_auth_requires() {
        let req = SubmitRequest {
            device_token_hex: "abc123",
            topic: "io.cortexkit.alfonso",
            environment: ApnsEnvironment::Production,
            push_type: "alert",
            priority: 10,
            collapse_id: None,
        };
        let headers = submit_headers(&req, "JWT");
        let get = |name: &str| {
            headers
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| v.clone())
        };
        assert_eq!(get("authorization").as_deref(), Some("bearer JWT"));
        assert_eq!(get("apns-topic").as_deref(), Some("io.cortexkit.alfonso"));
        assert_eq!(get("apns-push-type").as_deref(), Some("alert"));
        assert_eq!(get("apns-priority").as_deref(), Some("10"));
        assert_eq!(
            get("apns-collapse-id"),
            None,
            "an absent collapse id must not become an empty header; APNs treats an \
             empty collapse id as a real one and coalesces unrelated notifications"
        );

        let collapsing = SubmitRequest {
            collapse_id: Some("ask-7"),
            ..req
        };
        let headers = submit_headers(&collapsing, "JWT");
        assert!(headers
            .iter()
            .any(|(k, v)| *k == "apns-collapse-id" && v == "ask-7"));
    }

    /// A 200 is acceptance; anything else carries Apple's own reason through to the
    /// classifier. The unparseable-body arm is the one worth having: a body this code
    /// cannot read must not resolve to a known reason.
    #[test]
    fn responses_classify_by_status_and_reason() {
        assert_eq!(
            classify_response(200, Some("id-1".into()), ""),
            SubmitOutcome::Accepted {
                apns_id: Some("id-1".into())
            }
        );

        assert_eq!(
            classify_response(400, None, r#"{"reason":"BadDeviceToken"}"#),
            SubmitOutcome::Refused {
                status: 400,
                reason: "BadDeviceToken".into(),
                detail: RefusalKind::DeviceToken,
            }
        );

        assert_eq!(
            classify_response(403, None, r#"{"reason":"BadEnvironmentKeyInToken"}"#),
            SubmitOutcome::Refused {
                status: 403,
                reason: "BadEnvironmentKeyInToken".into(),
                detail: RefusalKind::EnvironmentMismatch,
            }
        );

        // An unreadable body yields an empty reason and an Unclassified detail --
        // never a known arm, since a known arm carries a remedy.
        let garbled = classify_response(400, None, "<html>gateway error</html>");
        assert_eq!(
            garbled,
            SubmitOutcome::Refused {
                status: 400,
                reason: String::new(),
                detail: RefusalKind::Unclassified,
            },
            "a body this code cannot parse must not resolve to a remedy"
        );
    }

    #[test]
    fn url_composes_host_and_device_path() {
        let req = SubmitRequest {
            device_token_hex: "abc123",
            topic: "io.cortexkit.alfonso",
            environment: ApnsEnvironment::Production,
            push_type: "alert",
            priority: 10,
            collapse_id: None,
        };
        assert_eq!(
            submit_url(&req),
            "https://api.push.apple.com/3/device/abc123"
        );

        let sandbox = SubmitRequest {
            environment: ApnsEnvironment::Sandbox,
            ..req
        };
        assert_eq!(
            submit_url(&sandbox),
            "https://api.development.push.apple.com/3/device/abc123"
        );
    }

    /// Every modelled reason maps to its own arm. Written as an exhaustive table
    /// rather than as spot checks: the value of these arms is that they carry
    /// DIFFERENT remedies, so two reasons collapsing into one would send an operator
    /// to the wrong fix while every test still passed.
    #[test]
    fn each_reason_maps_to_its_own_remedy() {
        let cases: &[(u16, &str, RefusalKind)] = &[
            (403, "ExpiredProviderToken", RefusalKind::ProviderToken),
            (403, "InvalidProviderToken", RefusalKind::ProviderToken),
            (403, "MissingProviderToken", RefusalKind::ProviderToken),
            (
                403,
                "BadEnvironmentKeyInToken",
                RefusalKind::EnvironmentMismatch,
            ),
            (400, "BadDeviceToken", RefusalKind::DeviceToken),
            (410, "Unregistered", RefusalKind::DeviceToken),
            (400, "TopicDisallowed", RefusalKind::Topic),
            (400, "DeviceTokenNotForTopic", RefusalKind::Topic),
            (413, "PayloadTooLarge", RefusalKind::PayloadTooLarge),
            (429, "TooManyProviderTokenUpdates", RefusalKind::TokenChurn),
            (429, "TooManyRequests", RefusalKind::Transient),
            (500, "InternalServerError", RefusalKind::Transient),
            (503, "ServiceUnavailable", RefusalKind::Transient),
        ];
        for (status, reason, want) in cases {
            assert_eq!(
                RefusalKind::classify(*status, reason),
                *want,
                "{reason} ({status}) must classify as {want:?}"
            );
        }
    }

    /// The environment-diagnosis arm, pinned by name because the whole reason it is
    /// distinct is that it is the ONE observation which can settle whether the
    /// signing key is production or sandbox — a fact the `.p8` does not carry.
    #[test]
    fn bad_device_token_is_the_environment_diagnostic() {
        assert_eq!(
            RefusalKind::classify(400, "BadDeviceToken"),
            RefusalKind::DeviceToken,
            "a production device token refused by the sandbox host is what proves \
             the environment; folding it into a generic 400 loses the diagnosis"
        );
        // And it must NOT share an arm with the other 400s, or the diagnosis is
        // indistinguishable from a topic misconfiguration.
        assert_ne!(
            RefusalKind::classify(400, "BadDeviceToken"),
            RefusalKind::classify(400, "TopicDisallowed")
        );
    }

    /// The two 403s that mean opposite things must never share an arm.
    ///
    /// `InvalidProviderToken` says the token is wrong, and the remedy is to mint a
    /// fresh one. `BadEnvironmentKeyInToken` says the KEY is for the other
    /// environment, and no token minted from it will ever satisfy this host. Folding
    /// the second into the first sends an operator into a mint-and-retry loop that
    /// cannot terminate, which is strictly worse than reporting no diagnosis at all.
    ///
    /// Both reasons are observed values rather than guesses: a live probe against
    /// both APNs hosts with a deliberately impossible device token returned
    /// `BadDeviceToken` from production and `BadEnvironmentKeyInToken` from sandbox,
    /// with a corrupted-bearer control returning `InvalidProviderToken` to prove the
    /// first answer depended on the key rather than being that host's default reply.
    #[test]
    fn an_environment_mismatch_is_not_a_bad_token() {
        assert_eq!(
            RefusalKind::classify(403, "BadEnvironmentKeyInToken"),
            RefusalKind::EnvironmentMismatch
        );
        assert_ne!(
            RefusalKind::classify(403, "BadEnvironmentKeyInToken"),
            RefusalKind::classify(403, "InvalidProviderToken"),
            "minting a fresh token cannot fix a key configured for the other \
             environment; the arms must not merge"
        );
    }

    /// An unmodelled 4xx reason is Unclassified rather than folded into the nearest
    /// arm. Known arms carry remedies; sending an operator to rotate a signing key
    /// over a reason that meant something else is worse than reporting no diagnosis.
    #[test]
    fn unknown_4xx_reasons_are_not_folded_into_a_known_remedy() {
        assert_eq!(
            RefusalKind::classify(400, "SomeReasonAppleAddedLater"),
            RefusalKind::Unclassified
        );
        assert_eq!(
            RefusalKind::classify(403, "AnotherNewReason"),
            RefusalKind::Unclassified,
            "a 403 we do not recognise must not claim to be a provider-token problem"
        );
        // A 5xx with an unknown reason IS safe to call transient: retrying a server
        // error cannot mislead an operator the way a wrong 4xx diagnosis can.
        assert_eq!(
            RefusalKind::classify(502, "SomethingNew"),
            RefusalKind::Transient
        );
    }

    /// Reason is consulted before status. Pinned because the reverse order is the
    /// natural way to write it and silently collapses the three distinct 400s.
    #[test]
    fn reason_is_checked_before_status() {
        // All three are 400 and all three must differ.
        let bad_device = RefusalKind::classify(400, "BadDeviceToken");
        let topic = RefusalKind::classify(400, "TopicDisallowed");
        let unknown = RefusalKind::classify(400, "Unrecognised");
        assert_ne!(bad_device, topic);
        assert_ne!(bad_device, unknown);
        assert_ne!(topic, unknown);
    }
}
