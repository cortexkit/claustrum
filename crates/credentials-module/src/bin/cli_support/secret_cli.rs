//! Operator controls for the independently opt-in phone channel.
use crate::{commit_admin, CliError, GlobalArgs};
use credentials_core::admin_ops::{AdminOpBody, ADMIN_OP_SCHEMA_V2};

pub fn cmd_secret(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    if args.len() != 2 || args[0] != "phone-gate" {
        return Err(CliError::Usage(
            "secret phone-gate takes on, off or status".into(),
        ));
    }
    if args[1] == "status" {
        let db = global.data_dir.join("store.db");
        if !db.exists() {
            println!("member mapping off\nphone setting off");
            return Ok(());
        }
        let [member, phone] = credentials_core::store::secret_phone_gate_status_read_only(&db)
            .map_err(|_| CliError::Usage("cannot read phone gate settings".into()))?;
        println!("member mapping {member}\nphone setting {phone}");
        return Ok(());
    }
    let enabled = match args[1].as_str() {
        "on" => true,
        "off" => false,
        _ => {
            return Err(CliError::Usage(
                "secret phone-gate takes on, off or status".into(),
            ))
        }
    };
    commit_admin(
        global,
        AdminOpBody::SecretPhoneGateSet {
            v: ADMIN_OP_SCHEMA_V2,
            enabled,
        },
    )?;
    println!("phone setting {}", if enabled { "on" } else { "off" });
    Ok(())
}
