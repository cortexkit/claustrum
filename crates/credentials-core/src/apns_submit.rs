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
//! no later callback that says otherwise. So a caller cannot distinguish "arrived on
//! the device" from "accepted and silently dropped" by anything on this side, and
//! every failure mode that matters (wrong environment, unregistered device, revoked
//! key) either surfaces here as a typed refusal or never surfaces at all.
//!
//! That asymmetry is why the refusal reasons are modelled rather than logged as
//! strings: the ones worth branching on say something an operator must act on, and
//! collapsing them into "push failed" throws away the only diagnosis APNs offers.

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

#[cfg(test)]
mod tests {
    use super::*;

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
