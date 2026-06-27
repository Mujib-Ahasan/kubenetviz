use anyhow::Result;

use crate::{
    cli::{GetArgs, GetResource},
    kube_client,
    resources,
};

pub async fn run(args: GetArgs) -> Result<()> {
    let client = kube_client::new_client().await?;

    match args.resource {
        GetResource::Pods(pod_args) => {
            resources::pods::list(client, &pod_args.namespace).await?;
        }
    }

    Ok(())
}