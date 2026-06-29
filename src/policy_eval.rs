use k8s_openapi::api::networking::v1::NetworkPolicy;

use crate::{
    pod_resolver::PodInfo,
    selector::matches_selector,
};

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