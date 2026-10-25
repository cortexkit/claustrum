//! The federation admin verbs: `transfer`, `remote`, `member` and `federation`.
//!
//! Each verb builds one admin op and commits it through `commit_admin`, so it runs on
//! the live daemon with `--subc` and on the offline lease path without it. The ops that
//! await an outbound call (a send, an accept, a remote add, a member grant, the self id)
//! exist only on the daemon: offline, the shared applier refuses them with
//! `federation_requires_daemon` before writing anything.
//!
//! Every member id an operator types (`--to`, `--from`, `--home`, `--member`, `self`)
//! is checked here against the canonical `fed-computer:<32 lowercase hex>` form before
//! anything is sent, and the vault checks it again.

use credentials_core::admin_ops::{AdminOpBody, ADMIN_OP_SCHEMA_V2};
use credentials_core::federation::{
    is_lower_hex_16_bytes, valid_member_id, MemberGrantOperation, MemberGrantSelector,
};
use serde_json::Value;

use crate::{commit_admin, has_flag, optional, CliError, GlobalArgs};

/// `ck auth transfer init|send|receive|accept|reject`.
pub fn cmd_transfer(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    let op = transfer_op(args)?;
    let reply = commit_admin(global, op.clone())?;
    match op {
        AdminOpBody::TransferInit { .. } => {
            println!(
                "transfer key {}; self id {}",
                text(&reply, "transfer_key"),
                text(&reply, "self_member")
            );
        }
        AdminOpBody::TransferRecover { .. } => {
            println!("transfer key replaced");
            for row in list(&reply, "rejected_incoming") {
                println!(
                    "rejected  {}  {}  from {}",
                    text(row, "transfer_id"),
                    text(row, "credential_id"),
                    text(row, "sender")
                );
            }
            for row in list(&reply, "abandoned_outgoing") {
                println!(
                    "abandoned  {}  {}  to {}  (send it again with `ck auth transfer send`)",
                    text(row, "transfer_id"),
                    text(row, "credential_id"),
                    text(row, "receiver")
                );
            }
        }
        AdminOpBody::TransferSend { .. } | AdminOpBody::TransferResume { .. } => {
            let transfer_id = text(&reply, "transfer_id");
            println!(
                "{transfer_id}  {}  to {}  reply {}",
                text(&reply, "credential_id"),
                text(&reply, "receiver"),
                text(&reply, "reply")
            );
            if reply.get("row_kept").and_then(Value::as_bool) == Some(true) {
                eprintln!(
                    "(the transfer is kept; deliver it again with \
                     `ck auth transfer send --resume {transfer_id}`)"
                );
            }
        }
        AdminOpBody::TransferReceive { .. } => {
            let pending = list(&reply, "pending");
            if pending.is_empty() {
                println!("no pending transfers");
            }
            for row in pending {
                println!(
                    "{}  from {}  {}  {}",
                    text(row, "transfer_id"),
                    text(row, "sender"),
                    text(row, "credential_id"),
                    text(row, "kind")
                );
            }
        }
        AdminOpBody::TransferAccept { .. } => {
            if reply.get("already_decided").and_then(Value::as_bool) == Some(true) {
                println!("already {}; nothing was written", text(&reply, "state"));
            } else {
                println!(
                    "accepted {} at version {}",
                    text(&reply, "credential_id"),
                    reply
                        .get("record_version")
                        .and_then(Value::as_u64)
                        .unwrap_or_default()
                );
            }
        }
        AdminOpBody::TransferReject { .. } => {
            println!("{}  {}", text(&reply, "transfer_id"), text(&reply, "state"));
        }
        _ => {}
    }
    Ok(())
}

/// The admin op a `transfer` invocation asks for.
fn transfer_op(args: &[String]) -> Result<AdminOpBody, CliError> {
    let (sub, rest) = subcommand(args, "transfer", "init|send|receive|accept|reject")?;
    let v = ADMIN_OP_SCHEMA_V2;
    match sub {
        "init" => match (optional(rest, "--self"), has_flag(rest, "--replace")) {
            (Some(member), false) => Ok(AdminOpBody::TransferInit {
                v,
                self_member: member_arg("--self", &member)?,
            }),
            (None, true) => Ok(AdminOpBody::TransferRecover { v }),
            _ => Err(CliError::Usage(
                "transfer init takes exactly one of --self <member> and --replace".into(),
            )),
        },
        "send" => match (
            optional(rest, "--resume"),
            optional(rest, "--id"),
            optional(rest, "--to"),
        ) {
            (Some(transfer_id), None, None) => Ok(AdminOpBody::TransferResume {
                v,
                transfer_id: transfer_id_arg(&transfer_id)?,
            }),
            (None, Some(credential_id), Some(to)) => Ok(AdminOpBody::TransferSend {
                v,
                credential_id,
                to: member_arg("--to", &to)?,
            }),
            _ => Err(CliError::Usage(
                "transfer send takes --id <credential> --to <member>, or --resume <transfer-id>"
                    .into(),
            )),
        },
        "receive" => Ok(AdminOpBody::TransferReceive { v }),
        "accept" | "reject" => {
            let transfer_id = single_positional(rest, &["--from"], sub)?;
            let from = optional(rest, "--from")
                .ok_or_else(|| CliError::Usage("--from <member> is required".into()))?;
            let transfer_id = transfer_id_arg(&transfer_id)?;
            let from = member_arg("--from", &from)?;
            if sub == "accept" {
                Ok(AdminOpBody::TransferAccept {
                    v,
                    transfer_id,
                    from,
                    replace: has_flag(rest, "--replace"),
                })
            } else {
                Ok(AdminOpBody::TransferReject {
                    v,
                    transfer_id,
                    from,
                })
            }
        }
        other => Err(unknown_subcommand(
            "transfer",
            other,
            "init|send|receive|accept|reject",
        )),
    }
}

/// `ck auth remote add|remove|list`.
pub fn cmd_remote(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    let op = remote_op(args)?;
    let reply = commit_admin(global, op.clone())?;
    match op {
        AdminOpBody::RemoteAdd { .. } => println!(
            "{}  home {}  incarnation {}  home version {}",
            text(&reply, "credential_id"),
            text(&reply, "home"),
            text(&reply, "incarnation"),
            reply
                .get("last_home_version")
                .and_then(Value::as_u64)
                .unwrap_or_default()
        ),
        AdminOpBody::RemoteRemove { .. } => println!(
            "removed {} (home {})",
            text(&reply, "credential_id"),
            text(&reply, "home")
        ),
        AdminOpBody::RemoteList { .. } => {
            let records = list(&reply, "remote_records");
            if records.is_empty() {
                println!("no remote records");
            }
            for row in records {
                println!(
                    "{}  home {}  incarnation {}  home version {}  state {}  last fetch {}",
                    text(row, "credential_id"),
                    text(row, "home"),
                    text(row, "incarnation"),
                    row.get("last_home_version")
                        .and_then(Value::as_u64)
                        .unwrap_or_default(),
                    text(row, "last_home_state"),
                    text(row, "last_fetch_outcome")
                );
            }
        }
        _ => {}
    }
    Ok(())
}

fn remote_op(args: &[String]) -> Result<AdminOpBody, CliError> {
    let (sub, rest) = subcommand(args, "remote", "add|remove|list")?;
    let v = ADMIN_OP_SCHEMA_V2;
    let id = || {
        optional(rest, "--id")
            .ok_or_else(|| CliError::Usage("--id <credential> is required".into()))
    };
    match sub {
        "add" => {
            let home = optional(rest, "--home")
                .ok_or_else(|| CliError::Usage("--home <member> is required".into()))?;
            Ok(AdminOpBody::RemoteAdd {
                v,
                credential_id: id()?,
                home: member_arg("--home", &home)?,
            })
        }
        "remove" => Ok(AdminOpBody::RemoteRemove {
            v,
            credential_id: id()?,
        }),
        "list" => Ok(AdminOpBody::RemoteList { v }),
        other => Err(unknown_subcommand("remote", other, "add|remove|list")),
    }
}

/// `ck auth member grant|revoke|list`.
pub fn cmd_member(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    let op = member_op(args)?;
    let reply = commit_admin(global, op.clone())?;
    match op {
        AdminOpBody::MemberGrant {
            member,
            operation,
            selector,
            ..
        } => {
            let verb = if reply.get("changed").and_then(Value::as_bool) == Some(false) {
                "already granted"
            } else {
                "granted"
            };
            println!(
                "{verb} {} {} to {member} (pairing {})",
                operation.as_str(),
                describe(&selector),
                text(&reply, "pairing_id")
            );
        }
        AdminOpBody::MemberRevoke {
            member,
            operation,
            selector,
            ..
        } => println!(
            "revoked {} {} from {member}",
            operation.as_str(),
            describe(&selector)
        ),
        AdminOpBody::MemberList { .. } => {
            let grants = list(&reply, "member_grants");
            if grants.is_empty() {
                println!("no member grants");
            }
            for row in grants {
                let selector = row.get("selector");
                println!(
                    "{}  {}  {} {}  pairing {}",
                    text(row, "member_id"),
                    text(row, "operation"),
                    selector.map_or("-", |s| text(s, "kind")),
                    selector.map_or("", |s| text(s, "selector")),
                    text(row, "pairing_id")
                );
            }
        }
        _ => {}
    }
    Ok(())
}

fn member_op(args: &[String]) -> Result<AdminOpBody, CliError> {
    let (sub, rest) = subcommand(args, "member", "grant|revoke|list")?;
    let v = ADMIN_OP_SCHEMA_V2;
    if sub == "list" {
        return Ok(AdminOpBody::MemberList { v });
    }
    if sub != "grant" && sub != "revoke" {
        return Err(unknown_subcommand("member", sub, "grant|revoke|list"));
    }
    let member = optional(rest, "--member")
        .ok_or_else(|| CliError::Usage("--member <member> is required".into()))?;
    let member = member_arg("--member", &member)?;
    let operation = match optional(rest, "--operation").as_deref() {
        Some("remote_read") => MemberGrantOperation::RemoteRead,
        Some("transfer_deliver") => MemberGrantOperation::TransferDeliver,
        _ => {
            return Err(CliError::Usage(
                "--operation must be remote_read or transfer_deliver".into(),
            ))
        }
    };
    let selector = match (
        operation,
        optional(rest, "--id"),
        optional(rest, "--category"),
    ) {
        (MemberGrantOperation::RemoteRead, Some(id), None) if !id.is_empty() => {
            MemberGrantSelector::Exact(id)
        }
        (MemberGrantOperation::RemoteRead, None, Some(category))
            if credentials_core::catalog::valid_category_name(&category) =>
        {
            MemberGrantSelector::Category(category)
        }
        (MemberGrantOperation::TransferDeliver, None, None) => MemberGrantSelector::None,
        (MemberGrantOperation::RemoteRead, _, _) => {
            return Err(CliError::Usage(
                "invalid_params: remote_read takes exactly one of --id <credential> and \
                 --category <name> (a valid category name)"
                    .into(),
            ))
        }
        (MemberGrantOperation::TransferDeliver, _, _) => {
            return Err(CliError::Usage(
                "invalid_params: transfer_deliver takes no --id or --category".into(),
            ))
        }
    };
    Ok(if sub == "grant" {
        AdminOpBody::MemberGrant {
            v,
            member,
            operation,
            selector,
        }
    } else {
        AdminOpBody::MemberRevoke {
            v,
            member,
            operation,
            selector,
        }
    })
}

/// `ck auth federation self <member>` and `ck auth federation mapping on|off`.
pub fn cmd_federation(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    let op = federation_op(args)?;
    let reply = commit_admin(global, op.clone())?;
    let changed = if reply.get("changed").and_then(Value::as_bool) == Some(false) {
        "unchanged"
    } else {
        "changed"
    };
    match op {
        AdminOpBody::FederationSelfSet { member, .. } => println!("self id {member} ({changed})"),
        AdminOpBody::FederationGateSet { enabled, .. } => println!(
            "member mapping {} ({changed})",
            if enabled { "on" } else { "off" }
        ),
        _ => {}
    }
    Ok(())
}

fn federation_op(args: &[String]) -> Result<AdminOpBody, CliError> {
    let (sub, rest) = subcommand(args, "federation", "self|mapping")?;
    let v = ADMIN_OP_SCHEMA_V2;
    let value = single_positional(rest, &[], sub)?;
    match sub {
        "self" => Ok(AdminOpBody::FederationSelfSet {
            v,
            member: member_arg("self", &value)?,
        }),
        "mapping" => match value.as_str() {
            "on" => Ok(AdminOpBody::FederationGateSet { v, enabled: true }),
            "off" => Ok(AdminOpBody::FederationGateSet { v, enabled: false }),
            _ => Err(CliError::Usage("federation mapping takes on or off".into())),
        },
        other => Err(unknown_subcommand("federation", other, "self|mapping")),
    }
}

// ---------------------------------------------------------------------------------
// Argument helpers
// ---------------------------------------------------------------------------------

/// The leading subcommand and the arguments after it.
fn subcommand<'a>(
    args: &'a [String],
    verb: &str,
    expected: &str,
) -> Result<(&'a str, &'a [String]), CliError> {
    match args.first() {
        Some(sub) if !sub.starts_with("--") => Ok((sub.as_str(), &args[1..])),
        _ => Err(CliError::Usage(format!(
            "{verb} requires a subcommand: {expected}"
        ))),
    }
}

fn unknown_subcommand(verb: &str, sub: &str, expected: &str) -> CliError {
    CliError::Usage(format!(
        "unknown {verb} subcommand {sub}: expected {expected}"
    ))
}

/// Exactly one argument that is neither a flag nor the value of one of `value_flags`.
fn single_positional(
    args: &[String],
    value_flags: &[&str],
    what: &str,
) -> Result<String, CliError> {
    let mut found = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if value_flags.contains(&arg.as_str()) {
            index += 2;
            continue;
        }
        if !arg.starts_with("--") {
            found.push(arg.clone());
        }
        index += 1;
    }
    match found.as_slice() {
        [one] => Ok(one.clone()),
        _ => Err(CliError::Usage(format!(
            "{what} takes exactly one positional argument"
        ))),
    }
}

/// A member id typed for `flag`, refused unless it is the canonical form.
fn member_arg(flag: &str, value: &str) -> Result<String, CliError> {
    if valid_member_id(value) {
        Ok(value.to_string())
    } else {
        Err(CliError::Usage(format!(
            "invalid_params: {flag} {value:?} is not a member id; expected fed-computer: \
             followed by 32 lowercase hex characters"
        )))
    }
}

fn transfer_id_arg(value: &str) -> Result<String, CliError> {
    if is_lower_hex_16_bytes(value) {
        Ok(value.to_string())
    } else {
        Err(CliError::Usage(format!(
            "invalid_params: {value:?} is not a transfer id; expected 32 lowercase hex characters"
        )))
    }
}

fn describe(selector: &MemberGrantSelector) -> String {
    match selector {
        MemberGrantSelector::Exact(id) => format!("on {id}"),
        MemberGrantSelector::Category(category) => format!("on category {category}"),
        MemberGrantSelector::None => String::new(),
    }
}

/// A string member of a reply, or `-` when it is absent or null.
fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or("-")
}

fn list<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value
        .get(key)
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MEMBER: &str = "fed-computer:0123456789abcdef0123456789abcdef";
    const TRANSFER_ID: &str = "00112233445566778899aabbccddeeff";

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|arg| arg.to_string()).collect()
    }

    fn usage(result: Result<AdminOpBody, CliError>) -> String {
        match result {
            Err(CliError::Usage(message)) => message,
            other => panic!("expected a usage refusal, got {other:?}"),
        }
    }

    #[test]
    fn every_member_argument_is_checked_against_the_canonical_form() {
        for bad in [
            "fed-computer:0123456789ABCDEF0123456789ABCDEF",
            "fed-phone:0123456789abcdef0123456789abcdef",
            "fed-computer:0123",
            "",
        ] {
            for invocation in [
                args(&["send", "--id", "apikey:x", "--to", bad]),
                args(&["accept", TRANSFER_ID, "--from", bad]),
                args(&["reject", TRANSFER_ID, "--from", bad]),
                args(&["init", "--self", bad]),
            ] {
                assert!(usage(transfer_op(&invocation)).starts_with("invalid_params"));
            }
            assert!(
                usage(remote_op(&args(&["add", "--id", "x", "--home", bad])))
                    .starts_with("invalid_params")
            );
            assert!(usage(member_op(&args(&[
                "grant",
                "--member",
                bad,
                "--operation",
                "transfer_deliver"
            ])))
            .starts_with("invalid_params"));
            assert!(usage(federation_op(&args(&["self", bad]))).starts_with("invalid_params"));
        }
    }

    #[test]
    fn verbs_build_the_admin_op_they_name() {
        assert!(matches!(
            transfer_op(&args(&["send", "--id", "apikey:x", "--to", MEMBER])).unwrap(),
            AdminOpBody::TransferSend { ref credential_id, ref to, .. }
                if credential_id == "apikey:x" && to == MEMBER
        ));
        assert!(matches!(
            transfer_op(&args(&["send", "--resume", TRANSFER_ID])).unwrap(),
            AdminOpBody::TransferResume { ref transfer_id, .. } if transfer_id == TRANSFER_ID
        ));
        assert!(matches!(
            transfer_op(&args(&["accept", "--from", MEMBER, TRANSFER_ID, "--replace"])).unwrap(),
            AdminOpBody::TransferAccept { replace: true, ref from, .. } if from == MEMBER
        ));
        assert!(matches!(
            transfer_op(&args(&["init", "--replace"])).unwrap(),
            AdminOpBody::TransferRecover { .. }
        ));
        assert!(matches!(
            member_op(&args(&[
                "grant",
                "--member",
                MEMBER,
                "--operation",
                "remote_read",
                "--category",
                "llm-provider"
            ]))
            .unwrap(),
            AdminOpBody::MemberGrant {
                selector: MemberGrantSelector::Category(_),
                ..
            }
        ));
        assert!(matches!(
            federation_op(&args(&["mapping", "on"])).unwrap(),
            AdminOpBody::FederationGateSet { enabled: true, .. }
        ));
    }

    #[test]
    fn malformed_shapes_are_refused_before_anything_is_sent() {
        usage(transfer_op(&args(&["init", "--self", MEMBER, "--replace"])));
        usage(transfer_op(&args(&[
            "send",
            "--resume",
            TRANSFER_ID,
            "--id",
            "x",
            "--to",
            MEMBER,
        ])));
        usage(transfer_op(&args(&["accept", "nothex", "--from", MEMBER])));
        usage(transfer_op(&args(&["accept", TRANSFER_ID])));
        usage(member_op(&args(&[
            "grant",
            "--member",
            MEMBER,
            "--operation",
            "transfer_deliver",
            "--id",
            "x",
        ])));
        usage(member_op(&args(&[
            "grant",
            "--member",
            MEMBER,
            "--operation",
            "remote_read",
        ])));
        usage(federation_op(&args(&["mapping", "maybe"])));
    }
}
