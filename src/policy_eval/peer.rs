use k8s_openapi::api::networking::v1::{NetworkPolicy, NetworkPolicyPeer};
use crate::cidr::ip_block_allows;
use crate::pod_resolver::PodInfo;
use crate::resources::namespaces::NamespaceInfo;
use crate::selector::matches_selector;

pub fn policy_selects_pod(policy: &NetworkPolicy, pod: &PodInfo) -> bool {
    let Some(spec) = &policy.spec else {
        return false;
    };

    let Some(pod_selector) = &spec.pod_selector else {
        return false;
    };

    matches_selector(pod_selector, &pod.labels)
}

pub(crate) fn has_ingress_policy_type(policy: &NetworkPolicy) -> bool {
    let Some(spec) = &policy.spec else {
        return false;
    };

    match &spec.policy_types {
        Some(types) => types.iter().any(|t| t == "Ingress"),
        None => spec.ingress.is_some(),
    }
}

pub(crate) fn has_egress_policy_type(policy: &NetworkPolicy) -> bool {
    let Some(spec) = &policy.spec else {
        return false;
    };

    match &spec.policy_types {
        Some(types) => types.iter().any(|t| t == "Egress"),
        None => spec.egress.is_some(),
    }
}

/// Check whether a single NetworkPolicyPeer matches a given pod and namespace.
/// Per K8s spec, ipBlock is mutually exclusive with selectors.
pub fn peer_matches_pod(
    peer: &NetworkPolicyPeer,
    peer_pod: &PodInfo,
    peer_namespace: &NamespaceInfo,
) -> bool {
    // ipBlock is mutually exclusive with selectors per K8s spec
    if let Some(ip_block) = &peer.ip_block {
        if let Some(pod_ip) = &peer_pod.ip {
            let except = ip_block.except.clone().unwrap_or_default();
            return ip_block_allows(pod_ip, &ip_block.cidr, &except).unwrap_or(false);
        }
        return false;
    }

    let namespace_matches = match &peer.namespace_selector {
        Some(ns_selector) => matches_selector(ns_selector, &peer_namespace.labels),
        None => true,
    };

    let pod_matches = match &peer.pod_selector {
        Some(pod_selector) => matches_selector(pod_selector, &peer_pod.labels),
        None => true,
    };

    namespace_matches && pod_matches
}

pub(crate) fn ports_allow(
    rule_ports: &Option<Vec<k8s_openapi::api::networking::v1::NetworkPolicyPort>>,
    requested_port: Option<u16>,
    requested_protocol: &str,
) -> bool {
    let Some(rule_ports) = rule_ports else {
        return true;
    };

    if rule_ports.is_empty() {
        return true;
    }

    for rule_port in rule_ports {
        let protocol_matches = rule_port
            .protocol
            .as_deref()
            .unwrap_or("TCP")
            .eq_ignore_ascii_case(requested_protocol);

        if !protocol_matches {
            continue;
        }

        let Some(port) = &rule_port.port else {
            return true;
        };

        let Some(requested_port) = requested_port else {
            return true;
        };

        if let k8s_openapi::apimachinery::pkg::util::intstr::IntOrString::Int(policy_port) = port {
            if *policy_port == requested_port as i32 {
                return true;
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_eval::test_helpers::*;

    #[test]
    fn peer_matches_by_pod_selector() {
        let pod = test_pod("api", "default", &[("app", "api")], None);
        let ns = test_namespace("default", &[]);
        let peer = make_peer(Some(&[("app", "api")]), None, None);

        assert!(peer_matches_pod(&peer, &pod, &ns));
    }

    #[test]
    fn peer_matches_by_namespace_selector() {
        let pod = test_pod("prom", "monitoring", &[("app", "prom")], None);
        let ns = test_namespace("monitoring", &[("team", "observability")]);
        let peer = make_peer(None, Some(&[("team", "observability")]), None);

        assert!(peer_matches_pod(&peer, &pod, &ns));
    }

    #[test]
    fn peer_matches_by_both_selectors() {
        let pod = test_pod("prom", "monitoring", &[("app", "prom")], None);
        let ns = test_namespace("monitoring", &[("team", "observability")]);
        let peer = make_peer(
            Some(&[("app", "prom")]),
            Some(&[("team", "observability")]),
            None,
        );

        assert!(peer_matches_pod(&peer, &pod, &ns));
    }

    #[test]
    fn peer_matches_by_ip_block() {
        let pod = test_pod("api", "default", &[], Some("10.244.1.5"));
        let ns = test_namespace("default", &[]);
        let peer = make_peer(None, None, Some(("10.244.0.0/16", &[])));

        assert!(peer_matches_pod(&peer, &pod, &ns));
    }

    #[test]
    fn peer_does_not_match_wrong_pod_labels() {
        let pod = test_pod("frontend", "default", &[("app", "frontend")], None);
        let ns = test_namespace("default", &[]);
        let peer = make_peer(Some(&[("app", "api")]), None, None);

        assert!(!peer_matches_pod(&peer, &pod, &ns));
    }
}
