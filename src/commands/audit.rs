use anyhow::Result;
use k8s_openapi::api::networking::v1::NetworkPolicy;

use crate::cli::AuditArgs;
use crate::kube_client;
use crate::pod_resolver::{self, PodInfo};
use crate::policy_eval;
use crate::resources;
use crate::selector::matches_selector;

/// Severity level for audit findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Info,
    Warn,
}

/// A single audit finding.
#[derive(Debug, Clone)]
pub struct Finding {
    pub severity: Severity,
    pub message: String,
}

impl std::fmt::Display for Finding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let tag = match self.severity {
            Severity::Info => "INFO",
            Severity::Warn => "WARN",
        };
        write!(f, "{:<5} {}", tag, self.message)
    }
}

/// Run all audit checks and return findings.
pub fn audit(
    namespace: &str,
    pods: &[PodInfo],
    policies: &[NetworkPolicy],
) -> Vec<Finding> {
    let mut findings = Vec::new();

    check_policies_selecting_no_pods(namespace, pods, policies, &mut findings);
    check_unisolated_pods(namespace, pods, policies, &mut findings);
    check_overly_permissive_ip_blocks(namespace, policies, &mut findings);
    check_empty_policies(namespace, policies, &mut findings);

    findings
}

/// Detect policies whose podSelector matches zero pods.
fn check_policies_selecting_no_pods(
    namespace: &str,
    pods: &[PodInfo],
    policies: &[NetworkPolicy],
    findings: &mut Vec<Finding>,
) {
    for policy in policies {
        let policy_name = policy.metadata.name.as_deref().unwrap_or("<unknown>");

        let Some(spec) = &policy.spec else {
            continue;
        };

        let Some(pod_selector) = &spec.pod_selector else {
            continue;
        };

        let any_match = pods.iter().any(|pod| matches_selector(pod_selector, &pod.labels));

        if !any_match {
            findings.push(Finding {
                severity: Severity::Warn,
                message: format!("policy {namespace}/{policy_name} selects no pods"),
            });
        }
    }
}

/// Detect pods that lack ingress or egress isolation.
fn check_unisolated_pods(
    namespace: &str,
    pods: &[PodInfo],
    policies: &[NetworkPolicy],
    findings: &mut Vec<Finding>,
) {
    for pod in pods {
        let ingress_policies = policy_eval::ingress_policies_selecting_pod(pod, policies);
        let egress_policies = policy_eval::egress_policies_selecting_pod(pod, policies);

        if ingress_policies.is_empty() {
            findings.push(Finding {
                severity: Severity::Info,
                message: format!("pod {namespace}/{} is not ingress-isolated", pod.name),
            });
        }

        if egress_policies.is_empty() {
            findings.push(Finding {
                severity: Severity::Info,
                message: format!("pod {namespace}/{} is not egress-isolated", pod.name),
            });
        }
    }
}

/// Detect overly permissive ipBlock rules (0.0.0.0/0 or ::/0).
fn check_overly_permissive_ip_blocks(
    namespace: &str,
    policies: &[NetworkPolicy],
    findings: &mut Vec<Finding>,
) {
    for policy in policies {
        let policy_name = policy.metadata.name.as_deref().unwrap_or("<unknown>");

        let Some(spec) = &policy.spec else {
            continue;
        };

        // Check ingress rules
        if let Some(ingress_rules) = &spec.ingress {
            for rule in ingress_rules {
                if let Some(from_peers) = &rule.from {
                    for peer in from_peers {
                        if let Some(ip_block) = &peer.ip_block {
                            if is_open_cidr(&ip_block.cidr) {
                                findings.push(Finding {
                                    severity: Severity::Warn,
                                    message: format!(
                                        "policy {namespace}/{policy_name} allows {} (ingress)",
                                        ip_block.cidr
                                    ),
                                });
                            }
                        }
                    }
                }
            }
        }

        // Check egress rules
        if let Some(egress_rules) = &spec.egress {
            for rule in egress_rules {
                if let Some(to_peers) = &rule.to {
                    for peer in to_peers {
                        if let Some(ip_block) = &peer.ip_block {
                            if is_open_cidr(&ip_block.cidr) {
                                findings.push(Finding {
                                    severity: Severity::Warn,
                                    message: format!(
                                        "policy {namespace}/{policy_name} allows {} (egress)",
                                        ip_block.cidr
                                    ),
                                });
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Detect empty or ineffective policies (have policyTypes but no rules).
fn check_empty_policies(
    namespace: &str,
    policies: &[NetworkPolicy],
    findings: &mut Vec<Finding>,
) {
    for policy in policies {
        let policy_name = policy.metadata.name.as_deref().unwrap_or("<unknown>");

        let Some(spec) = &policy.spec else {
            findings.push(Finding {
                severity: Severity::Warn,
                message: format!("policy {namespace}/{policy_name} has no spec"),
            });
            continue;
        };

        let has_ingress_type = spec
            .policy_types
            .as_ref()
            .is_some_and(|types| types.iter().any(|t| t == "Ingress"));
        let has_egress_type = spec
            .policy_types
            .as_ref()
            .is_some_and(|types| types.iter().any(|t| t == "Egress"));

        let ingress_empty = spec
            .ingress
            .as_ref()
            .is_some_and(|rules| rules.is_empty());
        let egress_empty = spec
            .egress
            .as_ref()
            .is_some_and(|rules| rules.is_empty());

        // A policy with Ingress type but empty ingress rules denies all ingress
        if has_ingress_type && ingress_empty {
            findings.push(Finding {
                severity: Severity::Warn,
                message: format!(
                    "policy {namespace}/{policy_name} has Ingress type but empty ingress rules (denies all ingress)"
                ),
            });
        }

        // A policy with Egress type but empty egress rules denies all egress
        if has_egress_type && egress_empty {
            findings.push(Finding {
                severity: Severity::Warn,
                message: format!(
                    "policy {namespace}/{policy_name} has Egress type but empty egress rules (denies all egress)"
                ),
            });
        }

        // A policy with no rules at all and no policyTypes is effectively a no-op
        let no_rules = spec.ingress.is_none() && spec.egress.is_none();
        let no_policy_types = spec.policy_types.is_none();
        if no_rules && no_policy_types {
            findings.push(Finding {
                severity: Severity::Warn,
                message: format!(
                    "policy {namespace}/{policy_name} has no rules and no policyTypes (ineffective)"
                ),
            });
        }
    }
}

fn is_open_cidr(cidr: &str) -> bool {
    cidr == "0.0.0.0/0" || cidr == "::/0"
}

pub async fn run(args: AuditArgs) -> Result<()> {
    let client = kube_client::new_client().await?;

    let namespaces_to_audit: Vec<String> = if args.all_namespaces {
        let all = resources::namespaces::fetch_all(client.clone()).await?;
        all.into_iter().map(|ns| ns.name).collect()
    } else {
        vec![args.namespace.clone()]
    };

    let mut total_findings = 0;

    for ns_name in &namespaces_to_audit {
        let pods = pod_resolver::resolve_all_pods(client.clone(), ns_name).await?;
        let policies = resources::network_policy::fetch(client.clone(), ns_name).await?;

        let findings = audit(ns_name, &pods, &policies);

        for finding in &findings {
            println!("{finding}");
        }

        total_findings += findings.len();
    }

    if total_findings == 0 {
        println!("No issues found.");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_eval::test_helpers::*;

    #[test]
    fn detects_policy_selecting_no_pods() {
        let pods = vec![
            test_pod("frontend", "default", &[("app", "frontend")], None),
        ];

        // Policy selects app=db but no such pod exists
        let policy = test_ingress_policy(
            "old-policy",
            &[("app", "db")],
            Some(vec!["Ingress"]),
            Some(vec![make_ingress_rule(None, None)]),
        );

        let findings = audit("default", &pods, &[policy]);
        assert!(findings.iter().any(|f| {
            f.severity == Severity::Warn
                && f.message.contains("old-policy")
                && f.message.contains("selects no pods")
        }));
    }

    #[test]
    fn no_warning_when_policy_selects_pods() {
        let pods = vec![
            test_pod("db", "default", &[("app", "db")], None),
        ];

        let policy = test_ingress_policy(
            "allow-db",
            &[("app", "db")],
            Some(vec!["Ingress"]),
            Some(vec![make_ingress_rule(None, None)]),
        );

        let findings = audit("default", &pods, &[policy]);
        assert!(!findings.iter().any(|f| f.message.contains("selects no pods")));
    }

    #[test]
    fn detects_unisolated_pods() {
        let pods = vec![
            test_pod("frontend", "default", &[("app", "frontend")], None),
        ];

        let findings = audit("default", &pods, &[]);

        assert!(findings.iter().any(|f| {
            f.severity == Severity::Info
                && f.message.contains("frontend")
                && f.message.contains("not ingress-isolated")
        }));

        assert!(findings.iter().any(|f| {
            f.severity == Severity::Info
                && f.message.contains("frontend")
                && f.message.contains("not egress-isolated")
        }));
    }

    #[test]
    fn ingress_isolated_pod_not_reported() {
        let pods = vec![
            test_pod("db", "default", &[("app", "db")], None),
        ];

        let policy = test_ingress_policy(
            "isolate-db",
            &[("app", "db")],
            Some(vec!["Ingress"]),
            Some(vec![make_ingress_rule(
                Some(vec![make_peer(Some(&[("app", "api")]), None, None)]),
                None,
            )]),
        );

        let findings = audit("default", &pods, &[policy]);
        assert!(!findings.iter().any(|f| {
            f.message.contains("db") && f.message.contains("not ingress-isolated")
        }));
    }

    #[test]
    fn detects_overly_permissive_ipblock_ingress() {
        let pods = vec![
            test_pod("db", "default", &[("app", "db")], None),
        ];

        let policy = test_ingress_policy(
            "db-ingress",
            &[("app", "db")],
            Some(vec!["Ingress"]),
            Some(vec![make_ingress_rule(
                Some(vec![make_peer(None, None, Some(("0.0.0.0/0", &[])))]),
                None,
            )]),
        );

        let findings = audit("default", &pods, &[policy]);
        assert!(findings.iter().any(|f| {
            f.severity == Severity::Warn
                && f.message.contains("db-ingress")
                && f.message.contains("0.0.0.0/0")
        }));
    }

    #[test]
    fn detects_overly_permissive_ipblock_egress() {
        let pods = vec![
            test_pod("db", "default", &[("app", "db")], None),
        ];

        let policy = test_egress_policy(
            "db-egress",
            &[("app", "db")],
            Some(vec!["Egress"]),
            Some(vec![make_egress_rule(
                Some(vec![make_peer(None, None, Some(("0.0.0.0/0", &[])))]),
                None,
            )]),
        );

        let findings = audit("default", &pods, &[policy]);
        assert!(findings.iter().any(|f| {
            f.severity == Severity::Warn
                && f.message.contains("db-egress")
                && f.message.contains("0.0.0.0/0")
        }));
    }

    #[test]
    fn detects_empty_ingress_rules() {
        let pods = vec![
            test_pod("db", "default", &[("app", "db")], None),
        ];

        let policy = test_ingress_policy(
            "deny-all-ingress",
            &[("app", "db")],
            Some(vec!["Ingress"]),
            Some(vec![]), // empty ingress rules
        );

        let findings = audit("default", &pods, &[policy]);
        assert!(findings.iter().any(|f| {
            f.severity == Severity::Warn
                && f.message.contains("deny-all-ingress")
                && f.message.contains("denies all ingress")
        }));
    }

    #[test]
    fn detects_empty_egress_rules() {
        let pods = vec![
            test_pod("db", "default", &[("app", "db")], None),
        ];

        let policy = test_egress_policy(
            "deny-all-egress",
            &[("app", "db")],
            Some(vec!["Egress"]),
            Some(vec![]), // empty egress rules
        );

        let findings = audit("default", &pods, &[policy]);
        assert!(findings.iter().any(|f| {
            f.severity == Severity::Warn
                && f.message.contains("deny-all-egress")
                && f.message.contains("denies all egress")
        }));
    }

    #[test]
    fn detects_ineffective_policy() {
        let pods = vec![
            test_pod("db", "default", &[("app", "db")], None),
        ];

        // Policy with no rules and no policyTypes
        let policy = test_ingress_policy(
            "noop-policy",
            &[("app", "db")],
            None,  // no policyTypes
            None,  // no ingress rules
        );

        let findings = audit("default", &pods, &[policy]);
        assert!(findings.iter().any(|f| {
            f.severity == Severity::Warn
                && f.message.contains("noop-policy")
                && f.message.contains("ineffective")
        }));
    }

    #[test]
    fn no_findings_for_well_configured_setup() {
        let pods = vec![
            test_pod("api", "default", &[("app", "api")], None),
            test_pod("db", "default", &[("app", "db")], None),
        ];

        let policy = test_ingress_policy(
            "allow-api-to-db",
            &[("app", "db")],
            Some(vec!["Ingress"]),
            Some(vec![make_ingress_rule(
                Some(vec![make_peer(Some(&[("app", "api")]), None, None)]),
                None,
            )]),
        );

        let findings = audit("default", &pods, &[policy]);

        // Only unisolated findings should remain (api not ingress/egress isolated, db not egress isolated)
        // No WARN findings should exist
        assert!(!findings.iter().any(|f| f.severity == Severity::Warn));
    }

    #[test]
    fn finding_display_format() {
        let warn = Finding {
            severity: Severity::Warn,
            message: "policy default/old-policy selects no pods".to_string(),
        };
        assert_eq!(format!("{warn}"), "WARN  policy default/old-policy selects no pods");

        let info = Finding {
            severity: Severity::Info,
            message: "pod default/frontend is not ingress-isolated".to_string(),
        };
        assert_eq!(format!("{info}"), "INFO  pod default/frontend is not ingress-isolated");
    }
}
