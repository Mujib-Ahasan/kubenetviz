use k8s_openapi::api::networking::v1::NetworkPolicy;
use crate::pod_resolver::PodInfo;
use crate::resources::namespaces::NamespaceInfo;

use super::{ConnectionDecision, ingress::is_ingress_allowed_by_pod_selector, egress::is_egress_allowed};

/// Evaluate full connection: both egress from source AND ingress at destination.
pub fn evaluate_connection(
    from: &PodInfo,
    to: &PodInfo,
    source_namespace: &NamespaceInfo,
    dest_namespace: &NamespaceInfo,
    source_policies: &[NetworkPolicy],
    dest_policies: &[NetworkPolicy],
    port: Option<u16>,
    protocol: &str,
) -> ConnectionDecision {
    let ingress = is_ingress_allowed_by_pod_selector(from, to, source_namespace, dest_policies, port, protocol);
    let egress = is_egress_allowed(from, to, dest_namespace, source_policies, port, protocol);
    let allowed = ingress.allowed && egress.allowed;

    ConnectionDecision {
        ingress,
        egress,
        allowed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_eval::test_helpers::*;

    #[test]
    fn connection_allowed_when_both_ingress_and_egress_allowed() {
        let source = test_pod("api", "default", &[("app", "api")], None);
        let dest = test_pod("db", "default", &[("app", "db")], None);
        let source_ns = test_namespace("default", &[]);
        let dest_ns = test_namespace("default", &[]);

        // No policies → neither pod is isolated → both allowed
        let result = evaluate_connection(
            &source, &dest, &source_ns, &dest_ns, &[], &[], None, "TCP",
        );
        assert!(result.allowed);
        assert!(result.ingress.allowed);
        assert!(result.egress.allowed);
    }

    #[test]
    fn connection_denied_when_ingress_denied_egress_allowed() {
        let source = test_pod("frontend", "default", &[("app", "frontend")], None);
        let dest = test_pod("db", "default", &[("app", "db")], None);
        let source_ns = test_namespace("default", &[]);
        let dest_ns = test_namespace("default", &[]);

        // Ingress policy only allows app=api, not app=frontend
        let dest_policy = test_ingress_policy(
            "allow-api-only",
            &[("app", "db")],
            Some(vec!["Ingress"]),
            Some(vec![make_ingress_rule(
                Some(vec![make_peer(Some(&[("app", "api")]), None, None)]),
                None,
            )]),
        );

        let result = evaluate_connection(
            &source, &dest, &source_ns, &dest_ns, &[], &[dest_policy], None, "TCP",
        );
        assert!(!result.allowed);
        assert!(!result.ingress.allowed);
        assert!(result.egress.allowed);
    }

    #[test]
    fn connection_denied_when_ingress_allowed_egress_denied() {
        let source = test_pod("api", "default", &[("app", "api")], None);
        let dest = test_pod("db", "default", &[("app", "db")], None);
        let source_ns = test_namespace("default", &[]);
        let dest_ns = test_namespace("default", &[]);

        // Egress policy restricts api to only talk to app=cache
        let source_policy = test_egress_policy(
            "restrict-api-egress",
            &[("app", "api")],
            Some(vec!["Egress"]),
            Some(vec![make_egress_rule(
                Some(vec![make_peer(Some(&[("app", "cache")]), None, None)]),
                None,
            )]),
        );

        let result = evaluate_connection(
            &source, &dest, &source_ns, &dest_ns, &[source_policy], &[], None, "TCP",
        );
        assert!(!result.allowed);
        assert!(result.ingress.allowed);
        assert!(!result.egress.allowed);
    }

    #[test]
    fn connection_denied_when_both_denied() {
        let source = test_pod("frontend", "default", &[("app", "frontend")], None);
        let dest = test_pod("db", "default", &[("app", "db")], None);
        let source_ns = test_namespace("default", &[]);
        let dest_ns = test_namespace("default", &[]);

        let source_policy = test_egress_policy(
            "restrict-frontend-egress",
            &[("app", "frontend")],
            Some(vec!["Egress"]),
            Some(vec![make_egress_rule(
                Some(vec![make_peer(Some(&[("app", "api")]), None, None)]),
                None,
            )]),
        );

        let dest_policy = test_ingress_policy(
            "allow-api-only",
            &[("app", "db")],
            Some(vec!["Ingress"]),
            Some(vec![make_ingress_rule(
                Some(vec![make_peer(Some(&[("app", "api")]), None, None)]),
                None,
            )]),
        );

        let result = evaluate_connection(
            &source, &dest, &source_ns, &dest_ns,
            &[source_policy], &[dest_policy], None, "TCP",
        );
        assert!(!result.allowed);
        assert!(!result.ingress.allowed);
        assert!(!result.egress.allowed);
    }
}
