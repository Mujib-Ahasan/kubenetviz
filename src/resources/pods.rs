use anyhow::Result;
use k8s_openapi::api::core::v1::Pod;
use kube::{
    api::{Api, ListParams},
    Client,
};

pub async fn list(client: Client, namespace: &str) -> Result<()> {
    let pods: Api<Pod> = Api::namespaced(client, namespace);

    let pod_list = pods.list(&ListParams::default()).await?;
    println!("my code is executing");

    println!(
        "{:<50} {:<30} {:<15} {}",
        "NAME", "NAMESPACE", "STATUS", "IP"
    );

    for pod in pod_list {
        let name = pod.metadata.name.unwrap_or_default();

        let namespace = pod.metadata.namespace.unwrap_or_default();

        let status = pod
            .status
            .as_ref()
            .and_then(|s| s.phase.clone())
            .unwrap_or_else(|| "Unknown".to_string());

        let ip = pod
            .status
            .as_ref()
            .and_then(|s| s.pod_ip.clone())
            .unwrap_or_default();

        println!(
            "{:<50} {:<30} {:<15} {}",
            name,
            namespace,
            status,
            ip
        );
    }

    Ok(())
}