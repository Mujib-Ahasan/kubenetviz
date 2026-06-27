use anyhow::Result;

use crate::cli::AuditArgs;

pub fn run(args: AuditArgs) -> Result<()> {
    println!("Audit command is not implemented yet.");
    println!("namespace: {}", args.namespace);
    println!("all namespaces: {}", args.all_namespaces);

    Ok(())
}