use anyhow::Result;

use crate::cli::ExplainArgs;

pub fn run(args: ExplainArgs) -> Result<()> {
    println!("Explain command is not implemented yet.");
    println!("namespace: {}", args.namespace);

    if let Some(from) = args.from {
        println!("from: {from}");
    }

    if let Some(to) = args.to {
        println!("to: {to}");
    }

    if let Some(port) = args.port {
        println!("port: {port}");
    }

    println!("protocol: {}", args.protocol);

    Ok(())
}