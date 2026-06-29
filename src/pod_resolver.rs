use std::collections::BTreeMap;

use anyhow::{bail, Result};
use k8s_openapi::api::core::v1::Pod;
use kube::{
    api::{Api, ListParams},
    Client,
};

#[derive(Debug, Clone)]
pub struct PodInfo {
    pub name: String,
    pub namespace: String,
    pub labels: BTreeMap<String, String>,
    pub ip: Option<String>,
}

pub async fn resolve_pods(
    client: Client,
    namespace: &str,
    selector: &str,
) -> Result<Vec<PodInfo>> {
    let pods: Api<Pod> = Api::namespaced(client, namespace);

    let lp = ListParams::default().labels(selector);

    let pod_list = pods.list(&lp).await?;

    let resolved: Vec<PodInfo> = pod_list
        .into_iter()
        .map(|pod| {
            let name = pod.metadata.name.unwrap_or_default();

            let namespace = pod
                .metadata
                .namespace
                .unwrap_or_else(|| namespace.to_string());

            let labels = pod.metadata.labels.unwrap_or_default();

            let ip = pod.status.and_then(|status| status.pod_ip);

            PodInfo {
                name,
                namespace,
                labels,
                ip,
            }
        })
        .collect();

    if resolved.is_empty() {
        bail!("no pods found matching selector `{selector}` in namespace `{namespace}`");
    }

    Ok(resolved)
}