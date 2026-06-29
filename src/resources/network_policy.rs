use anyhow::Result;
use k8s_openapi::api::networking::v1::NetworkPolicy;
use kube::{
    api::{Api, ListParams},
    Client,
};

pub async fn fetch(
    client: Client,
    namespace: &str,
) -> Result<Vec<NetworkPolicy>> {
    let policies: Api<NetworkPolicy> = Api::namespaced(client, namespace);

    let policy_list = policies.list(&ListParams::default()).await?;

    Ok(policy_list.items)
}