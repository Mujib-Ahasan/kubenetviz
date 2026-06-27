mod cli;
mod commands;
mod kube_client;
mod resources;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Commands};


#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Version => commands::version::run(),
        Commands::Explain(args) => commands::explain::run(args),
        Commands:: Health => commands::health::run().await,
        Commands::Graph(args) => commands::graph::run(args),
        Commands::Audit(args) => commands::audit::run(args),
        Commands::Get(args) => commands::get::run(args).await,
    }
}
