//! Process-local diagnostics for provider subscription strings the vault cannot map.

use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};

use credentials_core::engine::UnmappedPlanObservation;

const PLAN_LOG_CHAR_CAP: usize = 64;

#[derive(Default)]
struct PlanWarnings {
    seen: HashSet<(String, String)>,
}

impl PlanWarnings {
    fn report(&mut self, observation: &UnmappedPlanObservation) {
        // Dedupe on the complete provider string, not the truncated display: two
        // different plan names may share the same first 64 escaped characters.
        if !self
            .seen
            .insert((observation.credential_id.clone(), observation.raw.clone()))
        {
            return;
        }
        let credential_id: String = observation.credential_id.escape_debug().take(128).collect();
        let raw = log_raw(&observation.raw);
        tracing::warn!(
            target: "claustrum.plan",
            credential_id = %credential_id,
            provider = observation.provider,
            raw = %raw,
            "provider reported a plan the vault cannot map"
        );
    }
}

fn log_raw(raw: &str) -> String {
    raw.escape_debug().take(PLAN_LOG_CHAR_CAP).collect()
}

pub(crate) fn report(observation: Option<&UnmappedPlanObservation>) {
    static WARNINGS: OnceLock<Mutex<PlanWarnings>> = OnceLock::new();
    if let Some(observation) = observation {
        WARNINGS
            .get_or_init(Mutex::default)
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .report(observation);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use tracing::field::{Field, Visit};
    use tracing::span::{Attributes, Id, Record};
    use tracing::{Event, Metadata, Subscriber};

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<BTreeMap<String, String>>>>);

    impl Subscriber for Capture {
        fn enabled(&self, _: &Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &Attributes<'_>) -> Id {
            Id::from_u64(1)
        }
        fn record(&self, _: &Id, _: &Record<'_>) {}
        fn record_follows_from(&self, _: &Id, _: &Id) {}
        fn enter(&self, _: &Id) {}
        fn exit(&self, _: &Id) {}
        fn event(&self, event: &Event<'_>) {
            struct Fields(BTreeMap<String, String>);
            impl Visit for Fields {
                fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
                    self.0.insert(field.name().into(), format!("{value:?}"));
                }
                fn record_str(&mut self, field: &Field, value: &str) {
                    self.0.insert(field.name().into(), value.into());
                }
            }
            assert_eq!(event.metadata().level(), &tracing::Level::WARN);
            assert_eq!(event.metadata().target(), "claustrum.plan");
            let mut fields = Fields(BTreeMap::new());
            event.record(&mut fields);
            self.0.lock().unwrap().push(fields.0);
        }
    }

    fn observation(id: &str, raw: &str) -> UnmappedPlanObservation {
        UnmappedPlanObservation {
            credential_id: id.into(),
            provider: "anthropic",
            raw: raw.into(),
        }
    }

    #[test]
    fn unmapped_plan_logs_nothing_the_second_time_but_logs_a_different_string() {
        let capture = Capture::default();
        let _subscriber = tracing::subscriber::set_default(capture.clone());
        let mut warnings = PlanWarnings::default();
        let ultra = observation("oauth:anthropic:x", "default_claude_ultra");
        warnings.report(&ultra);
        assert_eq!(capture.0.lock().unwrap().len(), 1);
        warnings.report(&ultra);
        assert_eq!(
            capture.0.lock().unwrap().len(),
            1,
            "duplicate must log nothing"
        );
        warnings.report(&observation("oauth:anthropic:x", "default_claude_future"));
        assert_eq!(
            capture.0.lock().unwrap().len(),
            2,
            "a different string logs again"
        );
        warnings.report(&observation("oauth:anthropic:y", "default_claude_ultra"));
        let events = capture.0.lock().unwrap();
        assert_eq!(
            events.len(),
            3,
            "dedupe is per credential, not global per plan"
        );
        assert_eq!(
            events[0],
            BTreeMap::from([
                (
                    "message".into(),
                    "provider reported a plan the vault cannot map".into()
                ),
                ("credential_id".into(), "oauth:anthropic:x".into()),
                ("provider".into(), "anthropic".into()),
                ("raw".into(), "default_claude_ultra".into()),
            ])
        );
    }

    #[test]
    fn unmapped_plan_logs_escaped_text_capped_at_64_characters() {
        assert_eq!(log_raw(&"a".repeat(64)), "a".repeat(64));
        assert_eq!(log_raw(&"a".repeat(65)), "a".repeat(64));
        assert_eq!(log_raw("ultra\n\r\t\0\\\""), "ultra\\n\\r\\t\\0\\\\\\\"");
        assert_eq!(log_raw(&"\n".repeat(64)), "\\n".repeat(32));
        let capture = Capture::default();
        let _subscriber = tracing::subscriber::set_default(capture.clone());
        let mut warnings = PlanWarnings::default();
        let prefix = "a".repeat(64);
        warnings.report(&observation("oauth:anthropic:x\n", &format!("{prefix}b")));
        warnings.report(&observation("oauth:anthropic:x\n", &format!("{prefix}c")));
        let events = capture.0.lock().unwrap();
        assert_eq!(
            events.len(),
            2,
            "distinct strings with identical displays both log"
        );
        for event in events.iter() {
            assert_eq!(event["raw"], prefix);
            assert_eq!(event["credential_id"], "oauth:anthropic:x\\n");
        }
    }
}
