use anyhow::Result;
use k8s_openapi::api::networking::v1::NetworkPolicy;
use kube::{
    api::{Api, ListParams},
    Client,
};

pub async fn list(client: Client, namespace: &str) -> Result<()> {
    let policies: Api<NetworkPolicy> = Api::namespaced(client, namespace);

    let policy_list = policies.list(&ListParams::default()).await?;

    println!(
        "{:<35} {:<20} {}",
        "NAME", "NAMESPACE", "POD-SELECTOR"
    );

    for policy in policy_list {
        let name = policy.metadata.name.unwrap_or_default();

        let namespace = policy.metadata.namespace.unwrap_or_default();

       let selector = policy
    .spec
    .as_ref()
    .and_then(|spec| spec.pod_selector.as_ref())
    .and_then(|selector| selector.match_labels.as_ref())
    .map(|labels| {
        labels
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join(",")
    })
    .unwrap_or_else(|| "<all-pods>".to_string());

        println!(
            "{:<35} {:<20} {}",
            name, namespace, selector
        );
    }

    Ok(())
}