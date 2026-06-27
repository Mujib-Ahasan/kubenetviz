use clap::{Args, Parser, Subcommand};

#[derive(Parser)]
#[command(name = "kubenetviz")]
#[command(about = "Analyze and visualize Kubernetes NetworkPolicy behavior")]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Print version information
    Version,

    /// Check Kubernetes cluster connectivity
     Health,

    /// Explain whether traffic is allowed or denied
    Explain(ExplainArgs),

    /// Generate a NetworkPolicy graph
    Graph(GraphArgs),

    /// Audit NetworkPolicy configuration
    Audit(AuditArgs),
}

#[derive(Args)]
pub struct ExplainArgs {
    /// Source pod selector, for example app=frontend
    #[arg(long)]
    pub from: Option<String>,

    /// Destination pod selector, for example app=db
    #[arg(long)]
    pub to: Option<String>,

    /// Kubernetes namespace
    #[arg(short, long, default_value = "default")]
    pub namespace: String,

    /// Destination port
    #[arg(long)]
    pub port: Option<u16>,

    /// Protocol, for example TCP or UDP
    #[arg(long, default_value = "TCP")]
    pub protocol: String,
}

#[derive(Args)]
pub struct GraphArgs {
    /// Kubernetes namespace
    #[arg(short, long, default_value = "default")]
    pub namespace: String,

    /// Output file path
    #[arg(short, long)]
    pub output: Option<String>,
}

#[derive(Args)]
pub struct AuditArgs {
    /// Kubernetes namespace
    #[arg(short, long, default_value = "default")]
    pub namespace: String,

    /// Audit all namespaces
    #[arg(long)]
    pub all_namespaces: bool,
}