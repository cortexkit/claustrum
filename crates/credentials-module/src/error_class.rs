use serde::Serialize;

/// The fleet-wide error-class vocabulary. The class carries retry policy; the
/// accompanying error code carries the request-specific remedy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorClass {
    /// Retry may succeed (upstream may recover, lock may release).
    Transient,
    /// Retrying this credential with this request is futile until out-of-band action.
    Permanent,
    /// A human/admin must re-establish the credential (`login --replace`); consumers
    /// should surface an actionable auth prompt, not retry.
    AuthRequired,
    /// The request exceeds a bound (`get_many` cap); remedy is to reduce the request
    /// and retry — retrying the same request is futile.
    ContextOverflow,
}
