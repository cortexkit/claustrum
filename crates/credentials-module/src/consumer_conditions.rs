use super::{map_store_error, ErrorBody, ReadError, ReadSurface};
use crate::federation::ingress::ScopedCaller;
use credentials_core::audit::{AuditCtx, AuditOp};
use credentials_core::store::{AuthEventPrincipal, ConditionReport, GrantOperation, StoreOpError};
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReportConditionParams {
    credential_id: String,
    record_version: u64,
    reason: String,
    provider_status: u16,
    action_url: Option<String>,
    enrollment_token: Option<String>,
}

impl std::fmt::Debug for ReportConditionParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReportConditionParams")
            .field("record_version", &self.record_version)
            .field("provider_status", &self.provider_status)
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClearConditionParams {
    credential_id: String,
    record_version: u64,
    enrollment_token: Option<String>,
}

enum Mutation<'a> {
    Report(ConditionReport<'a>),
    Clear,
}

impl ReadSurface {
    pub(crate) fn report_condition_reply(
        &self,
        caller: &ScopedCaller,
        params: &ReportConditionParams,
    ) -> Value {
        let result = self.mutate_condition(
            caller,
            &params.credential_id,
            params.record_version,
            params.enrollment_token.as_deref(),
            Mutation::Report(ConditionReport {
                reason: &params.reason,
                provider_status: params.provider_status,
                action_url: params.action_url.as_deref(),
            }),
        );
        condition_reply("accepted", result.map(|_| true))
    }

    pub(crate) fn clear_condition_reply(
        &self,
        caller: &ScopedCaller,
        params: &ClearConditionParams,
    ) -> Value {
        let result = self.mutate_condition(
            caller,
            &params.credential_id,
            params.record_version,
            params.enrollment_token.as_deref(),
            Mutation::Clear,
        );
        condition_reply("cleared", result)
    }

    fn mutate_condition(
        &self,
        caller: &ScopedCaller,
        id: &str,
        version: u64,
        enrollment_token: Option<&str>,
        mutation: Mutation<'_>,
    ) -> Result<bool, ReadError> {
        let store = self.store();
        // Capture the lifetime before authorization, but never expose the lookup result
        // to an unauthorized caller. The transaction checks that lifetime again.
        let incarnation = store.credential_incarnation(id);
        let (kind, name) =
            self.authorize_scoped_as(caller, enrollment_token, id, GrantOperation::Read)?;
        let incarnation = incarnation.map_err(|error| map_store_error(&error))?;
        #[cfg(test)]
        self.run_incarnation_hook("admitted");

        let (actor, principal) = if kind == "enrolled" {
            (
                format!("enrolled:{name}"),
                AuthEventPrincipal::Enrolled(&name),
            )
        } else {
            (name.clone(), AuthEventPrincipal::Reserved(&name))
        };
        let audit = AuditCtx {
            op: match mutation {
                Mutation::Report(_) => AuditOp::ReportCondition,
                Mutation::Clear => AuditOp::ClearCondition,
            },
            actor: &actor,
            alarm: None,
        };
        let result = match mutation {
            Mutation::Report(report) => store.report_condition_in_incarnation(
                id,
                version,
                &incarnation,
                report,
                audit,
                principal,
            ),
            Mutation::Clear => {
                store.clear_condition_in_incarnation(id, version, &incarnation, audit, principal)
            }
        };
        result.map_err(|error| match error {
            StoreOpError::ConditionNotAdmitted => ReadError::ConditionNotAdmitted,
            StoreOpError::ConditionStatusRefused => ReadError::ConditionStatusRefused,
            StoreOpError::ConditionLinkRefused => ReadError::ConditionLinkRefused,
            other => map_store_error(&other),
        })
    }
}

fn condition_reply(field: &str, result: Result<bool, ReadError>) -> Value {
    match result {
        Ok(value) => json!({ (field): value }),
        Err(code) => json!({ (field): false, "error": ErrorBody { code, class: code.class() } }),
    }
}
