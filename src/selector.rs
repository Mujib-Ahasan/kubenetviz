use std::collections::BTreeMap;

use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;

pub fn matches_selector(
    selector: &LabelSelector,
    labels: &BTreeMap<String, String>,
) -> bool {
    if let Some(match_labels) = &selector.match_labels {
        for (key, expected_value) in match_labels {
            match labels.get(key) {
                Some(actual_value) if actual_value == expected_value => {}
                _ => return false,
            }
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn labels(items: &[(&str, &str)]) -> BTreeMap<String, String> {
        items
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn matches_when_all_match_labels_are_present() {
        let selector = LabelSelector {
            match_labels: Some(labels(&[("app", "db"), ("tier", "backend")])),
            match_expressions: None,
        };

        let pod_labels = labels(&[
            ("app", "db"),
            ("tier", "backend"),
            ("env", "prod"),
        ]);

        assert!(matches_selector(&selector, &pod_labels));
    }

    #[test]
    fn does_not_match_when_label_value_is_different() {
        let selector = LabelSelector {
            match_labels: Some(labels(&[("app", "db")])),
            match_expressions: None,
        };

        let pod_labels = labels(&[("app", "api")]);

        assert!(!matches_selector(&selector, &pod_labels));
    }

    #[test]
    fn does_not_match_when_label_key_is_missing() {
        let selector = LabelSelector {
            match_labels: Some(labels(&[("app", "db")])),
            match_expressions: None,
        };

        let pod_labels = labels(&[("tier", "backend")]);

        assert!(!matches_selector(&selector, &pod_labels));
    }

    #[test]
    fn empty_selector_matches_everything() {
        let selector = LabelSelector {
            match_labels: None,
            match_expressions: None,
        };

        let pod_labels = labels(&[("app", "db")]);

        assert!(matches_selector(&selector, &pod_labels));
    }
}