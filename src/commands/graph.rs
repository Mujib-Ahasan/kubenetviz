use anyhow::Result;

use crate::cli::GraphArgs;

pub fn run(args: GraphArgs) -> Result<()> {
    println!("Graph command is not implemented yet.");
    println!("namespace: {}", args.namespace);

    if let Some(output) = args.output {
        println!("output: {output}");
    }

    Ok(())
}