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

    for pod in &destination_pods {
        let selecting_policies =
            policy_eval::ingress_policies_selecting_pod(pod, &policies);

        if selecting_policies.is_empty() {
            println!(
                "{}/{} is not ingress-isolated by any NetworkPolicy",
                pod.namespace, pod.name
            );
        } else {
            println!(
                "{}/{} is ingress-isolated by:",
                pod.namespace, pod.name
            );

            for policy in selecting_policies {
                let policy_name =
                    policy.metadata.name.as_deref().unwrap_or("<unknown>");
                println!("- {policy_name}");
            }
        }
    }

    Ok(())
}