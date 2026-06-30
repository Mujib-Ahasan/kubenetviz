use anyhow::Result;
use ipnet::IpNet;
use std::net::IpAddr;

pub fn ip_block_allows(
    pod_ip: &str,
    cidr: &str,
    except: &[String],
) -> Result<bool> {
    let pod_ip: IpAddr = pod_ip.parse()?;
    let cidr: IpNet = cidr.parse()?;

    if !cidr.contains(&pod_ip) {
        return Ok(false);
    }

    for excluded in except {
        let excluded_net: IpNet = excluded.parse()?;

        if excluded_net.contains(&pod_ip) {
            return Ok(false);
        }
    }

    Ok(true)
}