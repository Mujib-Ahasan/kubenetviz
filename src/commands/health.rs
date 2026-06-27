use anyhow::Result;

use crate::kube_client;

pub async fn run() -> Result<()> {
    let client = kube_client::new_client().await?;

    let version = client.apiserver_version().await?;

    println!("Connected to Kubernetes");
    println!("Server version: {}", version.git_version);

    Ok(())
}