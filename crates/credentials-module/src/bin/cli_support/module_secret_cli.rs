//! Metadata-only operator commands for module-owned secrets.

use std::collections::BTreeMap;
use std::io::{IsTerminal, Write};

use credentials_core::admin_ops::{AdminOpBody, ADMIN_OP_SCHEMA_V2};
use credentials_core::store::module_secrets::validate_module_secret_name;

use crate::{commit_admin, CliError, GlobalArgs};

pub(crate) fn value_flags(verb: &str) -> Option<&'static [&'static str]> {
    Some(match verb {
        "list" => &["--module"],
        "delete" => &["--module", "--name", "--confirm"],
        "move" => &["--from", "--to"],
        _ => return None,
    })
}

fn parse(args: &[String]) -> Result<(AdminOpBody, Option<String>), CliError> {
    let Some((verb, rest)) = args.split_first() else {
        return Err(CliError::Usage(help_text(None)));
    };
    let flags = value_flags(verb).ok_or_else(|| CliError::Usage(help_text(None)))?;
    let mut values = BTreeMap::new();
    let mut iter = rest.iter();
    while let Some(flag) = iter.next() {
        if !flags.contains(&flag.as_str()) || values.contains_key(flag.as_str()) {
            return Err(CliError::Usage(format!(
                "unexpected or repeated argument for module-secret {verb}\n\n{}",
                help_text(Some(verb))
            )));
        }
        let value = iter
            .next()
            .filter(|value| !value.starts_with("--"))
            .ok_or_else(|| CliError::Usage(format!("{flag} requires a value")))?;
        if flag != "--confirm" {
            validate_module_secret_name(value).map_err(|_| {
                CliError::Usage(format!(
                    "invalid_params: {flag} must match [a-z0-9][a-z0-9._-]{{0,63}}"
                ))
            })?;
        }
        values.insert(flag.as_str(), value.clone());
    }
    let required = |flag| {
        values
            .get(flag)
            .cloned()
            .ok_or_else(|| CliError::Usage(format!("{flag} is required")))
    };
    let v = ADMIN_OP_SCHEMA_V2;
    let op = match verb.as_str() {
        "list" => AdminOpBody::ModuleSecretList {
            v,
            module: values.get("--module").cloned(),
        },
        "delete" => AdminOpBody::ModuleSecretDelete {
            v,
            module: required("--module")?,
            name: required("--name")?,
        },
        "move" => AdminOpBody::ModuleSecretMove {
            v,
            from: required("--from")?,
            to: required("--to")?,
        },
        _ => unreachable!("verb validated above"),
    };
    Ok((op, values.get("--confirm").cloned()))
}

pub fn guard_args(args: &[String]) -> Result<(), CliError> {
    parse(args).map(|_| ())
}

pub fn cmd_module_secret(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    let (op, confirm) = parse(args)?;
    if let AdminOpBody::ModuleSecretDelete { module, name, .. } = &op {
        let expected = format!("{module}:{name}");
        if let Some(confirm) = confirm {
            if confirm != expected {
                return Err(CliError::Usage(
                    "confirmation does not match module:name".into(),
                ));
            }
        } else {
            // Piped input must not accidentally authorize deletion; unattended callers
            // must identify the exact item with --confirm instead.
            if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
                return Err(CliError::Usage(
                    "non-terminal delete requires --confirm <module>:<name>".into(),
                ));
            }
            eprint!("Delete module secret {expected}, even if protected? Type {expected}: ");
            std::io::stderr()
                .flush()
                .map_err(|e| CliError::Io(e.to_string()))?;
            let mut answer = String::new();
            std::io::stdin()
                .read_line(&mut answer)
                .map_err(|e| CliError::Io(e.to_string()))?;
            if answer.trim_end_matches(['\r', '\n']) != expected {
                return Err(CliError::Usage(
                    "confirmation does not match module:name".into(),
                ));
            }
        }
    }
    let list = matches!(op, AdminOpBody::ModuleSecretList { .. });
    let result = commit_admin(global, op)?;
    if list {
        println!("MODULE\tNAME\tVERSION\tPROTECTED\tSTATE\tUPDATED");
        let items = result["items"]
            .as_array()
            .ok_or_else(|| CliError::Io("invalid module-secret list reply".into()))?;
        for item in items {
            println!(
                "{}\t{}\t{}\t{}\t{}\t{}",
                item["module"].as_str().unwrap_or(""),
                item["name"].as_str().unwrap_or(""),
                item["version"],
                item["protected"],
                item["state"].as_str().unwrap_or(""),
                item["updated_at_ms"]
            );
        }
    } else if let Some(moved) = result.get("moved") {
        println!("moved {moved} module secrets");
    } else {
        println!("deleted module secret");
    }
    Ok(())
}

pub fn help_text(verb: Option<&str>) -> String {
    let body = match verb {
        Some("list") => {
            "ck auth module-secret list [--module <id>]\n\
            \n\
            \x20 --module <id>  show only this module (default: all modules)\n\
            \n\
            Columns: module, name, version, protected, state, updated time (epoch ms).\n\
            Sorted by module then name. Values are never printed."
        }
        Some("delete") => {
            "ck auth module-secret delete --module <id> --name <name>\n\
            \x20                            [--confirm <id>:<name>]\n\
            \n\
            \x20 --module <id>          owning module\n\
            \x20 --name <name>          item to delete, including protected items\n\
            \x20 --confirm <id>:<name>  exact confirmation; required without a terminal\n\
            \n\
            Without --confirm, a terminal asks you to type <id>:<name>.\n\
            Missing items are refused as not_found. Values are never printed."
        }
        Some("move") => {
            "ck auth module-secret move --from <old id> --to <new id>\n\
            \n\
            \x20 --from <old id>  source module\n\
            \x20 --to <new id>    destination module\n\
            \n\
            Rename a module's entire secret space in one transaction.\n\
            The source must be nonempty; the destination must be empty and different.\n\
            Corrupt or locked items refuse the whole move. Values are never printed."
        }
        _ => {
            "ck auth module-secret <verb>\n\
            \n\
            \x20 list    list module-secret metadata, optionally for one module\n\
            \x20 delete  delete one item, including a protected item, with confirmation\n\
            \x20 move    move all items to a new module id for a module rename\n\
            \n\
            Run ck auth help module-secret <verb> for flags. Values are never printed."
        }
    };
    format!(
        "{body}\n\n\
        Module ids and names match [a-z0-9][a-z0-9._-]{{0,63}}.\n\
        Uses the authenticated admin plane online or the offline single-writer lease."
    )
}
