use std::collections::BTreeMap;

use anyhow::{bail, Result};
use k8s_openapi::api::core::v1::Namespace;
use kube::{
    api::{Api, ListParams},
    Client,
};

#[derive(Debug, Clone)]
pub struct NamespaceInfo {
    pub name: String,
    pub labels: BTreeMap<String, String>,
}

pub async fn fetch_all(client: Client) -> Result<Vec<NamespaceInfo>> {
    let namespaces: Api<Namespace> = Api::all(client);

    let namespace_list = namespaces.list(&ListParams::default()).await?;

    Ok(namespace_list
        .items
        .into_iter()
        .map(|ns| NamespaceInfo {
            name: ns.metadata.name.unwrap_or_default(),
            labels: ns.metadata.labels.unwrap_or_default(),
        })
        .collect())
}

pub fn find_namespace<'a>(
    namespaces: &'a [NamespaceInfo],
    name: &str,
) -> Result<&'a NamespaceInfo> {
    namespaces
        .iter()
        .find(|ns| ns.name == name)
        .ok_or_else(|| anyhow::anyhow!("namespace `{name}` not found"))
}