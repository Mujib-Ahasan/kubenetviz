use anyhow::Result;

use crate::{
    cli::ExplainArgs,
    kube_client,
    pod_resolver,
    policy_eval,
    resources,
};

pub async fn run(args: ExplainArgs) -> Result<()> {
    let from_selector = args
        .from
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("--from is required"))?;

    let to_selector = args
        .to
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("--to is required"))?;

    let client = kube_client::new_client().await?;
    let from_ns_name = args
        .from_namespace
        .as_deref()
        .unwrap_or(&args.namespace);
    let dest_ns_name = &args.namespace;

    let namespaces = resources::namespaces::fetch_all(client.clone()).await?;
    let source_namespace = resources::namespaces::find_namespace(&namespaces, from_ns_name)?;
    let dest_namespace = resources::namespaces::find_namespace(&namespaces, dest_ns_name)?;

    let source_pods =
        pod_resolver::resolve_pods(client.clone(), from_ns_name, from_selector).await?;
    let destination_pods =
        pod_resolver::resolve_pods(client.clone(), dest_ns_name, to_selector).await?;

    // Fetch policies from both namespaces: source for egress, destination for ingress
    let source_policies =
        resources::network_policy::fetch(client.clone(), from_ns_name).await?;
    let dest_policies =
        resources::network_policy::fetch(client, dest_ns_name).await?;

    println!("Source pods:");
    for pod in &source_pods {
        println!("- {}/{}", pod.namespace, pod.name);
    }

    println!();

    println!("Destination pods:");
    for pod in &destination_pods {
        println!("- {}/{}", pod.namespace, pod.name);
    }

    println!();

    for from in &source_pods {
        for to in &destination_pods {
            let decision = policy_eval::evaluate_connection(
                from, to,
                source_namespace, dest_namespace,
                &source_policies, &dest_policies,
                args.port, &args.protocol,
            );

            println!(
                "Evaluating: {}/{} -> {}/{}",
                from.namespace, from.name, to.namespace, to.name
            );
            println!();

            println!("  Egress (source):");
            if decision.egress.allowed {
                println!("    ALLOWED");
            } else {
                println!("    DENIED");
            }
            for reason in &decision.egress.reasons {
                println!("    - {reason}");
            }
            println!();

            println!("  Ingress (destination):");
            if decision.ingress.allowed {
                println!("    ALLOWED");
            } else {
                println!("    DENIED");
            }
            for reason in &decision.ingress.reasons {
                println!("    - {reason}");
            }
            println!();

            if decision.allowed {
                println!("  Verdict: ALLOWED");
            } else {
                println!("  Verdict: DENIED");
            }
            println!(
                "    - Egress from source: {}",
                if decision.egress.allowed { "allowed" } else { "denied" }
            );
            println!(
                "    - Ingress to destination: {}",
                if decision.ingress.allowed { "allowed" } else { "denied" }
            );
            println!();
        }
    }

    Ok(())
}
