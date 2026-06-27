use anyhow::Result;
use kube::Client;

pub async fn new_client() -> Result<Client> {
    let client = Client::try_default().await?;
    Ok(client)
}