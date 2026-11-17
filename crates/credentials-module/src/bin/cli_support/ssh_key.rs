use crate::{commit_admin, parse_ssh_key_op, CliError, GlobalArgs};

pub fn cmd_ssh_key(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    let result = commit_admin(global, parse_ssh_key_op(args)?)?;
    println!(
        "{}",
        serde_json::to_string(&result).expect("SSH enrollment result")
    );
    Ok(())
}
