use std::fmt::Write as FmtWrite;
use std::fs;

use anyhow::Result;

use crate::ascii_graph::{self, ConnectivityGraph, Edge};
use crate::cli::GraphArgs;
use crate::kube_client;
use crate::pod_resolver::{self, PodInfo};
use crate::policy_eval;
use crate::resources::{self, namespaces::NamespaceInfo};

use k8s_openapi::api::networking::v1::NetworkPolicy;

/// Build an intermediate connectivity graph from pods and policies.
pub fn build_connectivity_graph(
    pods: &[PodInfo],
    namespace: &NamespaceInfo,
    policies: &[NetworkPolicy],
) -> ConnectivityGraph {
    let nodes: Vec<String> = pods.iter().map(|p| p.name.clone()).collect();
    let mut edges = Vec::new();

    for (i, from) in pods.iter().enumerate() {
        for (j, to) in pods.iter().enumerate() {
            if i == j {
                continue;
            }

            let decision = policy_eval::evaluate_connection(
                from, to, namespace, namespace, policies, policies, None, "TCP",
            );

            edges.push(Edge {
                from: i,
                to: j,
                allowed: decision.allowed,
            });
        }
    }

    ConnectivityGraph { nodes, edges }
}

/// Build a Graphviz DOT graph from pods and policies in a namespace.
pub fn build_dot(
    pods: &[PodInfo],
    namespace: &NamespaceInfo,
    policies: &[NetworkPolicy],
    include_denied: bool,
) -> String {
    let mut dot = String::from("digraph kubenetviz {\n");
    dot.push_str("    rankdir=LR;\n");

    // Emit a node for every pod so isolated pods still appear.
    for pod in pods {
        let _ = writeln!(dot, "    \"{}\";", pod.name);
    }

    // Evaluate every ordered pair of distinct pods.
    for from in pods {
        for to in pods {
            if from.name == to.name {
                continue; // skip self-loops
            }

            let decision = policy_eval::evaluate_connection(
                from,
                to,
                namespace,
                namespace,
                policies,
                policies,
                None,
                "TCP",
            );

            if decision.allowed {
                let _ = writeln!(dot, "    \"{}\" -> \"{}\";", from.name, to.name);
            } else if include_denied {
                let _ = writeln!(
                    dot,
                    "    \"{}\" -> \"{}\" [style=dashed color=red label=\"denied\"];",
                    from.name, to.name
                );
            }
        }
    }

    dot.push_str("}\n");
    dot
}

pub async fn run(args: GraphArgs) -> Result<()> {
    let client = kube_client::new_client().await?;

    let namespaces = resources::namespaces::fetch_all(client.clone()).await?;
    let namespace = resources::namespaces::find_namespace(&namespaces, &args.namespace)?;

    let pods = pod_resolver::resolve_all_pods(client.clone(), &args.namespace).await?;
    let policies = resources::network_policy::fetch(client, &args.namespace).await?;

    if let Some(path) = &args.output {
        let dot = build_dot(&pods, namespace, &policies, args.include_denied);
        fs::write(path, &dot)?;
        println!("Graph written to {path}");
    } else {
        let graph = build_connectivity_graph(&pods, namespace, &policies);
        let ascii = ascii_graph::build_ascii(&graph, args.include_denied);
        print!("{ascii}");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_eval::test_helpers::*;

    #[test]
    fn dot_with_no_policies_is_fully_connected() {
        let pods = vec![
            test_pod("frontend", "default", &[("app", "frontend")], None),
            test_pod("api", "default", &[("app", "api")], None),
        ];
        let ns = test_namespace("default", &[]);

        let dot = build_dot(&pods, &ns, &[], false);

        assert!(dot.contains("digraph kubenetviz {"));
        assert!(dot.contains("\"frontend\" -> \"api\""));
        assert!(dot.contains("\"api\" -> \"frontend\""));
        assert!(dot.ends_with("}\n"));
    }

    #[test]
    fn dot_omits_denied_by_default() {
        let pods = vec![
            test_pod("frontend", "default", &[("app", "frontend")], None),
            test_pod("db", "default", &[("app", "db")], None),
        ];
        let ns = test_namespace("default", &[]);

        // Policy denies ingress to db from frontend
        let policy = test_ingress_policy(
            "allow-api-only",
            &[("app", "db")],
            Some(vec!["Ingress"]),
            Some(vec![make_ingress_rule(
                Some(vec![make_peer(Some(&[("app", "api")]), None, None)]),
                None,
            )]),
        );

        let dot = build_dot(&pods, &ns, &[policy], false);

        // frontend -> db should be denied (ingress blocked) so not in output
        assert!(!dot.contains("\"frontend\" -> \"db\""));
        // db -> frontend should still be allowed (no egress restriction, no ingress policy on frontend)
        assert!(dot.contains("\"db\" -> \"frontend\""));
    }

    #[test]
    fn dot_includes_denied_when_flag_set() {
        let pods = vec![
            test_pod("frontend", "default", &[("app", "frontend")], None),
            test_pod("db", "default", &[("app", "db")], None),
        ];
        let ns = test_namespace("default", &[]);

        let policy = test_ingress_policy(
            "allow-api-only",
            &[("app", "db")],
            Some(vec!["Ingress"]),
            Some(vec![make_ingress_rule(
                Some(vec![make_peer(Some(&[("app", "api")]), None, None)]),
                None,
            )]),
        );

        let dot = build_dot(&pods, &ns, &[policy], true);

        // Denied edge should appear with dashed style
        assert!(dot.contains("\"frontend\" -> \"db\" [style=dashed color=red label=\"denied\"]"));
    }

    #[test]
    fn dot_includes_pod_nodes() {
        let pods = vec![
            test_pod("frontend", "default", &[("app", "frontend")], None),
            test_pod("api", "default", &[("app", "api")], None),
            test_pod("db", "default", &[("app", "db")], None),
        ];
        let ns = test_namespace("default", &[]);

        let dot = build_dot(&pods, &ns, &[], false);

        assert!(dot.contains("\"frontend\";"));
        assert!(dot.contains("\"api\";"));
        assert!(dot.contains("\"db\";"));
    }

    #[test]
    fn dot_no_self_loops() {
        let pods = vec![
            test_pod("api", "default", &[("app", "api")], None),
        ];
        let ns = test_namespace("default", &[]);

        let dot = build_dot(&pods, &ns, &[], false);

        assert!(!dot.contains("\"api\" -> \"api\""));
    }

    #[test]
    fn dot_three_pod_scenario() {
        let pods = vec![
            test_pod("frontend", "default", &[("app", "frontend")], None),
            test_pod("api", "default", &[("app", "api")], None),
            test_pod("db", "default", &[("app", "db")], None),
        ];
        let ns = test_namespace("default", &[]);

        // Allow only api -> db ingress
        let policy = test_ingress_policy(
            "allow-api-to-db",
            &[("app", "db")],
            Some(vec!["Ingress"]),
            Some(vec![make_ingress_rule(
                Some(vec![make_peer(Some(&[("app", "api")]), None, None)]),
                None,
            )]),
        );

        let dot = build_dot(&pods, &ns, &[policy], false);

        // api -> db allowed (ingress match)
        assert!(dot.contains("\"api\" -> \"db\""));
        // frontend -> db denied (ingress blocked)
        assert!(!dot.contains("\"frontend\" -> \"db\""));
        // All other connections allowed (no policies select them)
        assert!(dot.contains("\"frontend\" -> \"api\""));
        assert!(dot.contains("\"api\" -> \"frontend\""));
    }

    #[test]
    fn connectivity_graph_captures_all_edges() {
        let pods = vec![
            test_pod("frontend", "default", &[("app", "frontend")], None),
            test_pod("api", "default", &[("app", "api")], None),
        ];
        let ns = test_namespace("default", &[]);

        let graph = build_connectivity_graph(&pods, &ns, &[]);

        assert_eq!(graph.nodes.len(), 2);
        assert_eq!(graph.edges.len(), 2); // frontend->api and api->frontend
        assert!(graph.edges.iter().all(|e| e.allowed));
    }

    #[test]
    fn connectivity_graph_with_policy() {
        let pods = vec![
            test_pod("frontend", "default", &[("app", "frontend")], None),
            test_pod("db", "default", &[("app", "db")], None),
        ];
        let ns = test_namespace("default", &[]);

        let policy = test_ingress_policy(
            "allow-api-only",
            &[("app", "db")],
            Some(vec!["Ingress"]),
            Some(vec![make_ingress_rule(
                Some(vec![make_peer(Some(&[("app", "api")]), None, None)]),
                None,
            )]),
        );

        let graph = build_connectivity_graph(&pods, &ns, &[policy]);

        // frontend -> db should be denied
        let frontend_to_db = graph.edges.iter().find(|e| e.from == 0 && e.to == 1).unwrap();
        assert!(!frontend_to_db.allowed);

        // db -> frontend should be allowed
        let db_to_frontend = graph.edges.iter().find(|e| e.from == 1 && e.to == 0).unwrap();
        assert!(db_to_frontend.allowed);
    }
}
