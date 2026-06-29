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

    let source_pods =
        pod_resolver::resolve_pods(client.clone(), &args.namespace, from_selector).await?;

    let destination_pods =
        pod_resolver::resolve_pods(client.clone(), &args.namespace, to_selector).await?;

    let policies =
        resources::network_policy::fetch(client, &args.namespace).await?;

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
        let decision =
            policy_eval::is_ingress_allowed_by_pod_selector(from, to, &policies);

        if decision.allowed {
            println!(
                "ALLOWED: {}/{} -> {}/{}",
                from.namespace, from.name, to.namespace, to.name
            );
        } else {
            println!(
                "DENIED: {}/{} -> {}/{}",
                from.namespace, from.name, to.namespace, to.name
            );
        }

        for reason in decision.reasons {
            println!("  - {reason}");
        }
    }
}

    Ok(())
}