use k8s_openapi::api::networking::v1::NetworkPolicy;
use crate::pod_resolver::PodInfo;
use crate::resources::namespaces::NamespaceInfo;

use super::peer::{policy_selects_pod, has_ingress_policy_type, peer_matches_pod, ports_allow};
use super::IngressDecision;

pub fn ingress_policies_selecting_pod<'a>(
    pod: &PodInfo,
    policies: &'a [NetworkPolicy],
) -> Vec<&'a NetworkPolicy> {
    policies
        .iter()
        .filter(|policy| policy_selects_pod(policy, pod))
        .filter(|policy| has_ingress_policy_type(policy))
        .collect()
}

pub fn is_ingress_allowed_by_pod_selector(
    from: &PodInfo,
    to: &PodInfo,
    from_namespace: &NamespaceInfo,
    policies: &[NetworkPolicy],
    port: Option<u16>,
    protocol: &str,
) -> IngressDecision {
    let selecting_policies = ingress_policies_selecting_pod(to, policies);

    if selecting_policies.is_empty() {
        return IngressDecision {
            allowed: true,
            reasons: vec![format!(
                "{}/{} is not ingress-isolated, so ingress is allowed by default",
                to.namespace, to.name
            )],
        };
    }

    for policy in selecting_policies {
        let policy_name = policy.metadata.name.as_deref().unwrap_or("<unknown>");

        let Some(spec) = &policy.spec else {
            continue;
        };

        let Some(ingress_rules) = &spec.ingress else {
            continue;
        };

        for rule in ingress_rules {
            if !ports_allow(&rule.ports, port, protocol) {
                continue;
            }
            let Some(from_peers) = &rule.from else {
                return IngressDecision {
                    allowed: true,
                    reasons: vec![format!(
                        "Policy {policy_name} has an ingress rule with no from peers, so it allows all sources"
                    )],
                };
            };

            for peer in from_peers {
                if peer_matches_pod(peer, from, from_namespace) {
                    let reason = if peer.ip_block.is_some() {
                        format!(
                            "Policy {policy_name} allows source pod {}/{} because its IP matches ipBlock",
                            from.namespace, from.name
                        )
                    } else {
                        format!(
                            "Policy {policy_name} allows source pod {}/{} because namespaceSelector/podSelector matched",
                            from.namespace, from.name
                        )
                    };
                    return IngressDecision {
                        allowed: true,
                        reasons: vec![reason],
                    };
                }
            }
        }
    }

    IngressDecision {
        allowed: false,
        reasons: vec![format!(
            "{}/{} is ingress-isolated, but no ingress rule allows source pod {}/{}",
            to.namespace, to.name, from.namespace, from.name
        )],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::networking::v1::{NetworkPolicy, NetworkPolicyIngressRule};
    use crate::policy_eval::test_helpers::*;

    #[test]
    fn ingress_allowed_when_no_policies_select_pod() {
        let source = test_pod("frontend", "default", &[("app", "frontend")], None);
        let dest = test_pod("db", "default", &[("app", "db")], None);
        let ns = test_namespace("default", &[]);
        let policies: Vec<NetworkPolicy> = vec![];

        let result = is_ingress_allowed_by_pod_selector(&source, &dest, &ns, &policies, None, "TCP");
        assert!(result.allowed);
    }

    #[test]
    fn ingress_denied_when_isolated_and_no_rule_matches() {
        let source = test_pod("frontend", "default", &[("app", "frontend")], None);
        let dest = test_pod("db", "default", &[("app", "db")], None);
        let ns = test_namespace("default", &[]);

        let policy = test_ingress_policy(
            "deny-all",
            &[("app", "db")],
            Some(vec!["Ingress"]),
            Some(vec![make_ingress_rule(
                Some(vec![make_peer(Some(&[("app", "api")]), None, None)]),
                None,
            )]),
        );

        let result = is_ingress_allowed_by_pod_selector(&source, &dest, &ns, &[policy], None, "TCP");
        assert!(!result.allowed);
    }

    #[test]
    fn ingress_allowed_by_pod_selector() {
        let source = test_pod("api", "default", &[("app", "api")], None);
        let dest = test_pod("db", "default", &[("app", "db")], None);
        let ns = test_namespace("default", &[]);

        let policy = test_ingress_policy(
            "allow-api",
            &[("app", "db")],
            Some(vec!["Ingress"]),
            Some(vec![make_ingress_rule(
                Some(vec![make_peer(Some(&[("app", "api")]), None, None)]),
                None,
            )]),
        );

        let result = is_ingress_allowed_by_pod_selector(&source, &dest, &ns, &[policy], None, "TCP");
        assert!(result.allowed);
    }

    #[test]
    fn ingress_allowed_by_namespace_selector() {
        let source = test_pod("prometheus", "monitoring", &[("app", "prometheus")], None);
        let dest = test_pod("db", "default", &[("app", "db")], None);
        let ns = test_namespace("monitoring", &[("team", "observability")]);

        let policy = test_ingress_policy(
            "allow-monitoring",
            &[("app", "db")],
            Some(vec!["Ingress"]),
            Some(vec![make_ingress_rule(
                Some(vec![make_peer(None, Some(&[("team", "observability")]), None)]),
                None,
            )]),
        );

        let result = is_ingress_allowed_by_pod_selector(&source, &dest, &ns, &[policy], None, "TCP");
        assert!(result.allowed);
    }

    #[test]
    fn ingress_allowed_by_pod_and_namespace_selector() {
        let source = test_pod("prometheus", "monitoring", &[("app", "prometheus")], None);
        let dest = test_pod("db", "default", &[("app", "db")], None);
        let ns = test_namespace("monitoring", &[("team", "observability")]);

        let policy = test_ingress_policy(
            "allow-monitoring-prometheus",
            &[("app", "db")],
            Some(vec!["Ingress"]),
            Some(vec![make_ingress_rule(
                Some(vec![make_peer(
                    Some(&[("app", "prometheus")]),
                    Some(&[("team", "observability")]),
                    None,
                )]),
                None,
            )]),
        );

        let result = is_ingress_allowed_by_pod_selector(&source, &dest, &ns, &[policy], None, "TCP");
        assert!(result.allowed);
    }

    #[test]
    fn ingress_denied_when_namespace_selector_does_not_match() {
        let source = test_pod("prometheus", "monitoring", &[("app", "prometheus")], None);
        let dest = test_pod("db", "default", &[("app", "db")], None);
        let ns = test_namespace("monitoring", &[("team", "dev")]);

        let policy = test_ingress_policy(
            "allow-observability-only",
            &[("app", "db")],
            Some(vec!["Ingress"]),
            Some(vec![make_ingress_rule(
                Some(vec![make_peer(None, Some(&[("team", "observability")]), None)]),
                None,
            )]),
        );

        let result = is_ingress_allowed_by_pod_selector(&source, &dest, &ns, &[policy], None, "TCP");
        assert!(!result.allowed);
    }

    #[test]
    fn ingress_allowed_by_ip_block() {
        let source = test_pod("api", "default", &[("app", "api")], Some("10.244.1.5"));
        let dest = test_pod("db", "default", &[("app", "db")], None);
        let ns = test_namespace("default", &[]);

        let policy = test_ingress_policy(
            "allow-cidr",
            &[("app", "db")],
            Some(vec!["Ingress"]),
            Some(vec![make_ingress_rule(
                Some(vec![make_peer(None, None, Some(("10.244.0.0/16", &[])))]),
                None,
            )]),
        );

        let result = is_ingress_allowed_by_pod_selector(&source, &dest, &ns, &[policy], None, "TCP");
        assert!(result.allowed);
    }

    #[test]
    fn ingress_denied_by_ip_block_except() {
        let source = test_pod("api", "default", &[("app", "api")], Some("10.244.1.5"));
        let dest = test_pod("db", "default", &[("app", "db")], None);
        let ns = test_namespace("default", &[]);

        let policy = test_ingress_policy(
            "allow-cidr-except",
            &[("app", "db")],
            Some(vec!["Ingress"]),
            Some(vec![make_ingress_rule(
                Some(vec![make_peer(None, None, Some(("10.244.0.0/16", &["10.244.1.0/24"])))]),
                None,
            )]),
        );

        let result = is_ingress_allowed_by_pod_selector(&source, &dest, &ns, &[policy], None, "TCP");
        assert!(!result.allowed);
    }

    #[test]
    fn ingress_allowed_when_rule_has_no_from_peers() {
        let source = test_pod("anyone", "default", &[("app", "anything")], None);
        let dest = test_pod("db", "default", &[("app", "db")], None);
        let ns = test_namespace("default", &[]);

        let policy = test_ingress_policy(
            "allow-all-sources",
            &[("app", "db")],
            Some(vec!["Ingress"]),
            Some(vec![NetworkPolicyIngressRule {
                from: None,
                ports: None,
            }]),
        );

        let result = is_ingress_allowed_by_pod_selector(&source, &dest, &ns, &[policy], None, "TCP");
        assert!(result.allowed);
    }

    #[test]
    fn ingress_port_matching_allows() {
        let source = test_pod("api", "default", &[("app", "api")], None);
        let dest = test_pod("db", "default", &[("app", "db")], None);
        let ns = test_namespace("default", &[]);

        let policy = test_ingress_policy(
            "allow-api-5432",
            &[("app", "db")],
            Some(vec!["Ingress"]),
            Some(vec![make_ingress_rule(
                Some(vec![make_peer(Some(&[("app", "api")]), None, None)]),
                Some((5432, "TCP")),
            )]),
        );

        let result = is_ingress_allowed_by_pod_selector(&source, &dest, &ns, &[policy], Some(5432), "TCP");
        assert!(result.allowed);
    }

    #[test]
    fn ingress_port_matching_denies_wrong_port() {
        let source = test_pod("api", "default", &[("app", "api")], None);
        let dest = test_pod("db", "default", &[("app", "db")], None);
        let ns = test_namespace("default", &[]);

        let policy = test_ingress_policy(
            "allow-api-5432",
            &[("app", "db")],
            Some(vec!["Ingress"]),
            Some(vec![make_ingress_rule(
                Some(vec![make_peer(Some(&[("app", "api")]), None, None)]),
                Some((5432, "TCP")),
            )]),
        );

        let result = is_ingress_allowed_by_pod_selector(&source, &dest, &ns, &[policy], Some(8080), "TCP");
        assert!(!result.allowed);
    }

    #[test]
    fn ingress_policy_type_implied_when_policy_types_omitted() {
        let source = test_pod("api", "default", &[("app", "api")], None);
        let dest = test_pod("db", "default", &[("app", "db")], None);
        let ns = test_namespace("default", &[]);

        // No policyTypes specified, but ingress rules exist — should imply Ingress type
        let policy = test_ingress_policy(
            "implied-ingress",
            &[("app", "db")],
            None, // policyTypes omitted
            Some(vec![make_ingress_rule(
                Some(vec![make_peer(Some(&[("app", "api")]), None, None)]),
                None,
            )]),
        );

        let result = is_ingress_allowed_by_pod_selector(&source, &dest, &ns, &[policy], None, "TCP");
        assert!(result.allowed);
    }

    #[test]
    fn ingress_not_selected_when_pod_labels_dont_match() {
        let source = test_pod("api", "default", &[("app", "api")], None);
        let dest = test_pod("frontend", "default", &[("app", "frontend")], None);
        let ns = test_namespace("default", &[]);

        // Policy selects app=db, but dest is app=frontend
        let policy = test_ingress_policy(
            "allow-api-to-db",
            &[("app", "db")],
            Some(vec!["Ingress"]),
            Some(vec![make_ingress_rule(
                Some(vec![make_peer(Some(&[("app", "api")]), None, None)]),
                None,
            )]),
        );

        // No policy selects this pod, so it's not isolated → allowed
        let result = is_ingress_allowed_by_pod_selector(&source, &dest, &ns, &[policy], None, "TCP");
        assert!(result.allowed);
    }
}
