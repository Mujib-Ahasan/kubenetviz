mod ascii_graph;
mod cli;
mod commands;
mod kube_client;
mod resources;
mod selector;
mod pod_resolver;
mod policy_eval;
mod cidr;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Commands};


#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Version => commands::version::run(),
        Commands::Explain(args) => commands::explain::run(args).await,
        Commands::Health => commands::health::run().await,
        Commands::Graph(args) => commands::graph::run(args).await,
        Commands::Audit(args) => commands::audit::run(args).await,
    }
}
