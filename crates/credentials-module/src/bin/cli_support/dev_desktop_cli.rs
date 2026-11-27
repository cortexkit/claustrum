//! Unsigned desktop approvals: a development route, off by default, kept in alpha
//! releases until signed desktop approvals ship, then removed.
use crate::{commit_admin, store_path, CliError, GlobalArgs};
use credentials_core::{
    admin_ops::{AdminOpBody, ADMIN_OP_SCHEMA_V2},
    store::EncryptedStore,
};

pub fn setting(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    let usage = || CliError::Usage("secret dev-desktop-approvals takes on, off or status".into());
    let [action] = args else {
        return Err(usage());
    };
    if action == "status" {
        let status =
            EncryptedStore::secret_dev_desktop_approvals_status_read_only(&store_path(global))
                .map_err(|_| CliError::Usage("cannot read dev-desktop-approvals setting".into()))?;
        println!("dev-desktop-approvals setting {status}");
        return Ok(());
    }
    let enabled = match action.as_str() {
        "on" => true,
        "off" => false,
        _ => return Err(usage()),
    };
    commit_admin(
        global,
        AdminOpBody::SecretDevDesktopApprovalsSet {
            v: ADMIN_OP_SCHEMA_V2,
            enabled,
        },
    )?;
    println!(
        "dev-desktop-approvals setting {}",
        if enabled { "on" } else { "off" }
    );
    Ok(())
}
