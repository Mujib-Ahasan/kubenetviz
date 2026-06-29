use k8s_openapi::api::networking::v1::NetworkPolicy;

use crate::{
    pod_resolver::PodInfo,
    selector::matches_selector,
};

#[derive(Debug)]
pub struct IngressDecision {
    pub allowed: bool,
    pub reasons: Vec<String>,
}

pub fn policy_selects_pod(policy: &NetworkPolicy, pod: &PodInfo) -> bool {
    let Some(spec) = &policy.spec else {
        return false;
    };

    let Some(pod_selector) = &spec.pod_selector else {
        return false;
    };

    matches_selector(pod_selector, &pod.labels)
}

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

fn has_ingress_policy_type(policy: &NetworkPolicy) -> bool {
    let Some(spec) = &policy.spec else {
        return false;
    };

    match &spec.policy_types {
        Some(types) => types.iter().any(|t| t == "Ingress"),
        None => spec.ingress.is_some(),
    }
}

pub fn is_ingress_allowed_by_pod_selector(
    from: &PodInfo,
    to: &PodInfo,
    policies: &[NetworkPolicy],
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
            let Some(from_peers) = &rule.from else {
                return IngressDecision {
                    allowed: true,
                    reasons: vec![format!(
                        "Policy {policy_name} has an ingress rule with no from peers, so it allows all sources"
                    )],
                };
            };

            for peer in from_peers {
                if let Some(peer_pod_selector) = &peer.pod_selector {
                    if matches_selector(peer_pod_selector, &from.labels) {
                        return IngressDecision {
                            allowed: true,
                            reasons: vec![format!(
                                "Policy {policy_name} allows source pod {}/{} because it matches a podSelector",
                                from.namespace, from.name
                            )],
                        };
                    }
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