mod peer;
mod ingress;
mod egress;
mod connection;

pub use connection::evaluate_connection;

#[allow(unused_imports)]
pub use peer::{policy_selects_pod, peer_matches_pod};
pub use ingress::ingress_policies_selecting_pod;
#[allow(unused_imports)]
pub use ingress::is_ingress_allowed_by_pod_selector;
pub use egress::egress_policies_selecting_pod;
#[allow(unused_imports)]
pub use egress::is_egress_allowed;

/// Result of evaluating one direction (ingress or egress) of network policy.
#[derive(Debug)]
pub struct DirectionDecision {
    pub allowed: bool,
    pub reasons: Vec<String>,
}

/// Backward-compatible alias for ingress-only callers.
pub type IngressDecision = DirectionDecision;

/// Combined connectivity verdict for a source→destination pair.
#[derive(Debug)]
pub struct ConnectionDecision {
    pub ingress: DirectionDecision,
    pub egress: DirectionDecision,
    pub allowed: bool,
}

#[cfg(test)]
pub(crate) mod test_helpers {
    use std::collections::BTreeMap;
    use k8s_openapi::api::networking::v1::{
        IPBlock, NetworkPolicy, NetworkPolicyIngressRule, NetworkPolicyEgressRule,
        NetworkPolicyPeer, NetworkPolicyPort, NetworkPolicySpec,
    };
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, ObjectMeta};
    use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
    use crate::pod_resolver::PodInfo;
    use crate::resources::namespaces::NamespaceInfo;

    pub fn test_pod(name: &str, namespace: &str, labels: &[(&str, &str)], ip: Option<&str>) -> PodInfo {
        PodInfo {
            name: name.to_string(),
            namespace: namespace.to_string(),
            labels: labels.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            ip: ip.map(|s| s.to_string()),
        }
    }

    pub fn test_namespace(name: &str, labels: &[(&str, &str)]) -> NamespaceInfo {
        NamespaceInfo {
            name: name.to_string(),
            labels: labels.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
        }
    }

    pub fn test_ingress_policy(
        name: &str,
        pod_selector_labels: &[(&str, &str)],
        policy_types: Option<Vec<&str>>,
        ingress_rules: Option<Vec<NetworkPolicyIngressRule>>,
    ) -> NetworkPolicy {
        let match_labels: BTreeMap<String, String> = pod_selector_labels
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();

        NetworkPolicy {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: Some(NetworkPolicySpec {
                pod_selector: Some(LabelSelector {
                    match_labels: if match_labels.is_empty() { None } else { Some(match_labels) },
                    ..Default::default()
                }),
                policy_types: policy_types.map(|types| types.into_iter().map(String::from).collect()),
                ingress: ingress_rules,
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    pub fn test_egress_policy(
        name: &str,
        pod_selector_labels: &[(&str, &str)],
        policy_types: Option<Vec<&str>>,
        egress_rules: Option<Vec<NetworkPolicyEgressRule>>,
    ) -> NetworkPolicy {
        let match_labels: BTreeMap<String, String> = pod_selector_labels
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();

        NetworkPolicy {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: Some(NetworkPolicySpec {
                pod_selector: Some(LabelSelector {
                    match_labels: if match_labels.is_empty() { None } else { Some(match_labels) },
                    ..Default::default()
                }),
                policy_types: policy_types.map(|types| types.into_iter().map(String::from).collect()),
                egress: egress_rules,
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    pub fn make_peer(
        pod_labels: Option<&[(&str, &str)]>,
        ns_labels: Option<&[(&str, &str)]>,
        ip_block: Option<(&str, &[&str])>,
    ) -> NetworkPolicyPeer {
        NetworkPolicyPeer {
            pod_selector: pod_labels.map(|labels| LabelSelector {
                match_labels: Some(labels.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()),
                ..Default::default()
            }),
            namespace_selector: ns_labels.map(|labels| LabelSelector {
                match_labels: Some(labels.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()),
                ..Default::default()
            }),
            ip_block: ip_block.map(|(cidr, except)| IPBlock {
                cidr: cidr.to_string(),
                except: if except.is_empty() {
                    None
                } else {
                    Some(except.iter().map(|s| s.to_string()).collect())
                },
            }),
        }
    }

    pub fn make_ingress_rule(
        peers: Option<Vec<NetworkPolicyPeer>>,
        port: Option<(i32, &str)>,
    ) -> NetworkPolicyIngressRule {
        NetworkPolicyIngressRule {
            from: peers,
            ports: port.map(|(p, proto)| {
                vec![NetworkPolicyPort {
                    port: Some(IntOrString::Int(p)),
                    protocol: Some(proto.to_string()),
                    ..Default::default()
                }]
            }),
        }
    }

    pub fn make_egress_rule(
        peers: Option<Vec<NetworkPolicyPeer>>,
        port: Option<(i32, &str)>,
    ) -> NetworkPolicyEgressRule {
        NetworkPolicyEgressRule {
            to: peers,
            ports: port.map(|(p, proto)| {
                vec![NetworkPolicyPort {
                    port: Some(IntOrString::Int(p)),
                    protocol: Some(proto.to_string()),
                    ..Default::default()
                }]
            }),
        }
    }
}
