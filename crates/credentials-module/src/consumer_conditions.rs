use super::{map_store_error, ErrorBody, ReadError, ReadSurface};
use crate::federation::ingress::ScopedCaller;
use credentials_core::audit::{AuditCtx, AuditOp};
use credentials_core::store::{
    check_condition_report, AuthEventPrincipal, ConditionReport, GrantOperation, StoreOpError,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

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
    pub(crate) async fn report_condition_reply(
        self: &Arc<Self>,
        caller: &ScopedCaller,
        params: &ReportConditionParams,
    ) -> Value {
        self.mutate_condition(
            caller,
            &params.credential_id,
            params.record_version,
            params.enrollment_token.as_deref(),
            Mutation::Report(ConditionReport {
                reason: &params.reason,
                provider_status: params.provider_status,
                action_url: params.action_url.as_deref(),
            }),
        )
        .await
    }

    pub(crate) async fn clear_condition_reply(
        self: &Arc<Self>,
        caller: &ScopedCaller,
        params: &ClearConditionParams,
    ) -> Value {
        self.mutate_condition(
            caller,
            &params.credential_id,
            params.record_version,
            params.enrollment_token.as_deref(),
            Mutation::Clear,
        )
        .await
    }

    async fn mutate_condition(
        self: &Arc<Self>,
        caller: &ScopedCaller,
        id: &str,
        version: u64,
        enrollment_token: Option<&str>,
        mutation: Mutation<'_>,
    ) -> Value {
        let field = match mutation {
            Mutation::Report(_) => "accepted",
            Mutation::Clear => "cleared",
        };
        // Capture the lifetime before authorization, but never expose the lookup result
        // to an unauthorized caller. The write or dispatch checks that lifetime again.
        let surface = Arc::clone(self);
        let caller = caller.clone();
        let credential_id = id.to_owned();
        let token = enrollment_token.map(str::to_owned);
        let (copy, incarnation, (kind, name)) = match tokio::task::spawn_blocking(move || {
            let copy = surface.remote.remote_record(&credential_id);
            let incarnation = surface.store().credential_incarnation(&credential_id);
            let principal = surface.authorize_scoped_as(
                &caller,
                token.as_deref(),
                &credential_id,
                GrantOperation::Read,
            )?;
            #[cfg(test)]
            surface.run_incarnation_hook("admitted");
            Ok((copy, incarnation, principal))
        })
        .await
        {
            Ok(Ok(resolved)) => resolved,
            Ok(Err(error)) => return condition_reply(field, Err(error)),
            Err(_) => return condition_reply(field, Err(ReadError::StoreError)),
        };

        match copy {
            Ok(Some(copy)) => {
                let report = match mutation {
                    Mutation::Report(report) => {
                        if let Err(error) = check_condition_report(
                            copy.refresh_adapter.as_deref(),
                            report.reason,
                            report.provider_status,
                            report.action_url,
                        ) {
                            return condition_reply(field, Err(condition_error(&error)));
                        }
                        Some(report)
                    }
                    Mutation::Clear => None,
                };
                return match self.remote.forward_condition(&copy, version, report).await {
                    Ok(value) => json!({ (field): value }),
                    Err(refusal) => json!({ (field): false, "error": refusal.body() }),
                };
            }
            Ok(None) => {}
            Err(error) => return condition_reply(field, Err(map_store_error(&error))),
        }
        let incarnation = match incarnation {
            Ok(incarnation) => incarnation,
            Err(error) => return condition_reply(field, Err(map_store_error(&error))),
        };
        let store = Arc::clone(self.store());
        let id = id.to_owned();
        let report = match mutation {
            Mutation::Report(report) => Some((
                report.reason.to_owned(),
                report.provider_status,
                report.action_url.map(str::to_owned),
            )),
            Mutation::Clear => None,
        };
        let result = tokio::task::spawn_blocking(move || {
            let (actor, principal) = if kind == "enrolled" {
                (
                    format!("enrolled:{name}"),
                    AuthEventPrincipal::Enrolled(&name),
                )
            } else {
                (name.clone(), AuthEventPrincipal::Reserved(&name))
            };
            let audit = AuditCtx {
                op: match report {
                    Some(_) => AuditOp::ReportCondition,
                    None => AuditOp::ClearCondition,
                },
                actor: &actor,
                alarm: None,
            };
            match report {
                Some((reason, provider_status, action_url)) => store
                    .report_condition_in_incarnation(
                        &id,
                        version,
                        &incarnation,
                        ConditionReport {
                            reason: &reason,
                            provider_status,
                            action_url: action_url.as_deref(),
                        },
                        audit,
                        principal,
                    )
                    .map(|_| true),
                None => store.clear_condition_in_incarnation(
                    &id,
                    version,
                    &incarnation,
                    audit,
                    principal,
                ),
            }
            .map_err(|error| condition_error(&error))
        })
        .await
        .unwrap_or(Err(ReadError::StoreError));
        condition_reply(field, result)
    }
}

fn condition_error(error: &StoreOpError) -> ReadError {
    match error {
        StoreOpError::ConditionNotAdmitted => ReadError::ConditionNotAdmitted,
        StoreOpError::ConditionStatusRefused => ReadError::ConditionStatusRefused,
        StoreOpError::ConditionLinkRefused => ReadError::ConditionLinkRefused,
        other => map_store_error(other),
    }
}

fn condition_reply(field: &str, result: Result<bool, ReadError>) -> Value {
    match result {
        Ok(value) => json!({ (field): value }),
        Err(code) => json!({ (field): false, "error": ErrorBody { code, class: code.class() } }),
    }
}
