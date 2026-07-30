use k8s_openapi::api::networking::v1::NetworkPolicy;
use crate::pod_resolver::PodInfo;
use crate::resources::namespaces::NamespaceInfo;

use super::peer::{policy_selects_pod, has_egress_policy_type, peer_matches_pod, ports_allow};
use super::DirectionDecision;

pub fn egress_policies_selecting_pod<'a>(
    pod: &PodInfo,
    policies: &'a [NetworkPolicy],
) -> Vec<&'a NetworkPolicy> {
    policies
        .iter()
        .filter(|policy| policy_selects_pod(policy, pod))
        .filter(|policy| has_egress_policy_type(policy))
        .collect()
}

/// Evaluate whether egress from the source pod toward the destination pod is allowed.
/// `dest_namespace` is the NamespaceInfo for the destination pod's namespace.
/// `policies` are NetworkPolicies from the SOURCE pod's namespace.
pub fn is_egress_allowed(
    from: &PodInfo,
    to: &PodInfo,
    dest_namespace: &NamespaceInfo,
    policies: &[NetworkPolicy],
    port: Option<u16>,
    protocol: &str,
) -> DirectionDecision {
    let selecting_policies = egress_policies_selecting_pod(from, policies);

    if selecting_policies.is_empty() {
        return DirectionDecision {
            allowed: true,
            reasons: vec![format!(
                "{}/{} is not egress-isolated, so egress is allowed by default",
                from.namespace, from.name
            )],
        };
    }

    for policy in selecting_policies {
        let policy_name = policy.metadata.name.as_deref().unwrap_or("<unknown>");

        let Some(spec) = &policy.spec else {
            continue;
        };

        let Some(egress_rules) = &spec.egress else {
            continue;
        };

        for rule in egress_rules {
            if !ports_allow(&rule.ports, port, protocol) {
                continue;
            }
            let Some(to_peers) = &rule.to else {
                return DirectionDecision {
                    allowed: true,
                    reasons: vec![format!(
                        "Policy {policy_name} has an egress rule with no to peers, so it allows all destinations"
                    )],
                };
            };

            for peer in to_peers {
                if peer_matches_pod(peer, to, dest_namespace) {
                    let reason = if peer.ip_block.is_some() {
                        format!(
                            "Policy {policy_name} allows destination pod {}/{} because its IP matches ipBlock",
                            to.namespace, to.name
                        )
                    } else {
                        format!(
                            "Policy {policy_name} allows destination pod {}/{} because namespaceSelector/podSelector matched",
                            to.namespace, to.name
                        )
                    };
                    return DirectionDecision {
                        allowed: true,
                        reasons: vec![reason],
                    };
                }
            }
        }
    }

    DirectionDecision {
        allowed: false,
        reasons: vec![format!(
            "{}/{} is egress-isolated, but no egress rule allows destination pod {}/{}",
            from.namespace, from.name, to.namespace, to.name
        )],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::networking::v1::NetworkPolicy;
    use crate::policy_eval::test_helpers::*;

    #[test]
    fn egress_allowed_when_no_policies_select_source() {
        let source = test_pod("frontend", "default", &[("app", "frontend")], None);
        let dest = test_pod("db", "default", &[("app", "db")], None);
        let dest_ns = test_namespace("default", &[]);
        let policies: Vec<NetworkPolicy> = vec![];

        let result = is_egress_allowed(&source, &dest, &dest_ns, &policies, None, "TCP");
        assert!(result.allowed);
    }

    #[test]
    fn egress_denied_when_isolated_and_no_rule_matches() {
        let source = test_pod("frontend", "default", &[("app", "frontend")], None);
        let dest = test_pod("db", "default", &[("app", "db")], None);
        let dest_ns = test_namespace("default", &[]);

        let policy = test_egress_policy(
            "restrict-frontend-egress",
            &[("app", "frontend")],
            Some(vec!["Egress"]),
            Some(vec![make_egress_rule(
                Some(vec![make_peer(Some(&[("app", "api")]), None, None)]),
                None,
            )]),
        );

        let result = is_egress_allowed(&source, &dest, &dest_ns, &[policy], None, "TCP");
        assert!(!result.allowed);
    }

    #[test]
    fn egress_allowed_by_pod_selector() {
        let source = test_pod("api", "default", &[("app", "api")], None);
        let dest = test_pod("db", "default", &[("app", "db")], None);
        let dest_ns = test_namespace("default", &[]);

        let policy = test_egress_policy(
            "allow-api-to-db",
            &[("app", "api")],
            Some(vec!["Egress"]),
            Some(vec![make_egress_rule(
                Some(vec![make_peer(Some(&[("app", "db")]), None, None)]),
                None,
            )]),
        );

        let result = is_egress_allowed(&source, &dest, &dest_ns, &[policy], None, "TCP");
        assert!(result.allowed);
    }

    #[test]
    fn egress_allowed_by_namespace_selector() {
        let source = test_pod("api", "default", &[("app", "api")], None);
        let dest = test_pod("db", "production", &[("app", "db")], None);
        let dest_ns = test_namespace("production", &[("env", "prod")]);

        let policy = test_egress_policy(
            "allow-to-prod",
            &[("app", "api")],
            Some(vec!["Egress"]),
            Some(vec![make_egress_rule(
                Some(vec![make_peer(None, Some(&[("env", "prod")]), None)]),
                None,
            )]),
        );

        let result = is_egress_allowed(&source, &dest, &dest_ns, &[policy], None, "TCP");
        assert!(result.allowed);
    }

    #[test]
    fn egress_allowed_by_pod_and_namespace_selector() {
        let source = test_pod("api", "default", &[("app", "api")], None);
        let dest = test_pod("db", "production", &[("app", "db")], None);
        let dest_ns = test_namespace("production", &[("env", "prod")]);

        let policy = test_egress_policy(
            "allow-to-prod-db",
            &[("app", "api")],
            Some(vec!["Egress"]),
            Some(vec![make_egress_rule(
                Some(vec![make_peer(
                    Some(&[("app", "db")]),
                    Some(&[("env", "prod")]),
                    None,
                )]),
                None,
            )]),
        );

        let result = is_egress_allowed(&source, &dest, &dest_ns, &[policy], None, "TCP");
        assert!(result.allowed);
    }

    #[test]
    fn egress_denied_when_namespace_selector_does_not_match() {
        let source = test_pod("api", "default", &[("app", "api")], None);
        let dest = test_pod("db", "staging", &[("app", "db")], None);
        let dest_ns = test_namespace("staging", &[("env", "staging")]);

        let policy = test_egress_policy(
            "allow-to-prod-only",
            &[("app", "api")],
            Some(vec!["Egress"]),
            Some(vec![make_egress_rule(
                Some(vec![make_peer(None, Some(&[("env", "prod")]), None)]),
                None,
            )]),
        );

        let result = is_egress_allowed(&source, &dest, &dest_ns, &[policy], None, "TCP");
        assert!(!result.allowed);
    }

    #[test]
    fn egress_allowed_by_ip_block() {
        let source = test_pod("api", "default", &[("app", "api")], None);
        let dest = test_pod("external", "default", &[], Some("10.0.1.50"));
        let dest_ns = test_namespace("default", &[]);

        let policy = test_egress_policy(
            "allow-cidr-egress",
            &[("app", "api")],
            Some(vec!["Egress"]),
            Some(vec![make_egress_rule(
                Some(vec![make_peer(None, None, Some(("10.0.0.0/8", &[])))]),
                None,
            )]),
        );

        let result = is_egress_allowed(&source, &dest, &dest_ns, &[policy], None, "TCP");
        assert!(result.allowed);
    }

    #[test]
    fn egress_denied_by_ip_block_except() {
        let source = test_pod("api", "default", &[("app", "api")], None);
        let dest = test_pod("external", "default", &[], Some("10.0.1.50"));
        let dest_ns = test_namespace("default", &[]);

        let policy = test_egress_policy(
            "allow-cidr-except-egress",
            &[("app", "api")],
            Some(vec!["Egress"]),
            Some(vec![make_egress_rule(
                Some(vec![make_peer(None, None, Some(("10.0.0.0/8", &["10.0.1.0/24"])))]),
                None,
            )]),
        );

        let result = is_egress_allowed(&source, &dest, &dest_ns, &[policy], None, "TCP");
        assert!(!result.allowed);
    }

    #[test]
    fn egress_allowed_when_rule_has_no_to_peers() {
        let source = test_pod("api", "default", &[("app", "api")], None);
        let dest = test_pod("anything", "default", &[], None);
        let dest_ns = test_namespace("default", &[]);

        let policy = test_egress_policy(
            "allow-all-egress",
            &[("app", "api")],
            Some(vec!["Egress"]),
            Some(vec![k8s_openapi::api::networking::v1::NetworkPolicyEgressRule {
                to: None,
                ports: None,
            }]),
        );

        let result = is_egress_allowed(&source, &dest, &dest_ns, &[policy], None, "TCP");
        assert!(result.allowed);
    }

    #[test]
    fn egress_port_matching() {
        let source = test_pod("api", "default", &[("app", "api")], None);
        let dest = test_pod("db", "default", &[("app", "db")], None);
        let dest_ns = test_namespace("default", &[]);

        let policy = test_egress_policy(
            "allow-api-to-db-5432",
            &[("app", "api")],
            Some(vec!["Egress"]),
            Some(vec![make_egress_rule(
                Some(vec![make_peer(Some(&[("app", "db")]), None, None)]),
                Some((5432, "TCP")),
            )]),
        );

        let result = is_egress_allowed(&source, &dest, &dest_ns, &[policy.clone()], Some(5432), "TCP");
        assert!(result.allowed);

        let result = is_egress_allowed(&source, &dest, &dest_ns, &[policy], Some(8080), "TCP");
        assert!(!result.allowed);
    }

    #[test]
    fn egress_policy_type_implied_when_egress_rules_exist() {
        let source = test_pod("api", "default", &[("app", "api")], None);
        let dest = test_pod("db", "default", &[("app", "db")], None);
        let dest_ns = test_namespace("default", &[]);

        // policyTypes omitted, but egress rules exist — should imply Egress type
        let policy = test_egress_policy(
            "implied-egress",
            &[("app", "api")],
            None,
            Some(vec![make_egress_rule(
                Some(vec![make_peer(Some(&[("app", "db")]), None, None)]),
                None,
            )]),
        );

        let result = is_egress_allowed(&source, &dest, &dest_ns, &[policy], None, "TCP");
        assert!(result.allowed);
    }

    #[test]
    fn egress_not_implied_when_policy_types_omitted_and_no_egress_rules() {
        let source = test_pod("api", "default", &[("app", "api")], None);
        let dest = test_pod("db", "default", &[("app", "db")], None);
        let dest_ns = test_namespace("default", &[]);

        // policyTypes omitted and no egress rules — should NOT imply Egress type
        let policy = test_ingress_policy(
            "ingress-only",
            &[("app", "api")],
            None,
            Some(vec![make_ingress_rule(
                Some(vec![make_peer(Some(&[("app", "api")]), None, None)]),
                None,
            )]),
        );

        let result = is_egress_allowed(&source, &dest, &dest_ns, &[policy], None, "TCP");
        assert!(result.allowed);
    }

    #[test]
    fn egress_isolated_with_empty_egress_list() {
        let source = test_pod("api", "default", &[("app", "api")], None);
        let dest = test_pod("db", "default", &[("app", "db")], None);
        let dest_ns = test_namespace("default", &[]);

        // policyTypes: ["Egress"] with egress: [] — blocks all egress
        let policy = test_egress_policy(
            "deny-all-egress",
            &[("app", "api")],
            Some(vec!["Egress"]),
            Some(vec![]),
        );

        let result = is_egress_allowed(&source, &dest, &dest_ns, &[policy], None, "TCP");
        assert!(!result.allowed);
    }
}
