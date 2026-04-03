use hickory_resolver::TokioResolver;
use futures::stream::{self, StreamExt};
use std::net::{IpAddr, Ipv4Addr};
use tracing::debug;

fn make_resolver() -> TokioResolver {
    TokioResolver::builder_tokio().unwrap().build()
}

/// Given discovered IPs, PTR-scan each /24 for siblings.
pub async fn reverse_dns_sweep(
    ips: &[IpAddr],
    concurrency: usize,
) -> Vec<String> {
    let resolver = make_resolver();

    // Collect unique /24 networks
    let mut cidrs = std::collections::HashSet::new();
    for ip in ips {
        if let IpAddr::V4(v4) = ip {
            let octets = v4.octets();
            cidrs.insert([octets[0], octets[1], octets[2]]);
        }
    }

    debug!(cidr_count = cidrs.len(), "scanning /24 ranges");

    let all_ips: Vec<IpAddr> = cidrs.iter()
        .flat_map(|cidr| {
            (1..=254).map(move |last| {
                IpAddr::V4(Ipv4Addr::new(cidr[0], cidr[1], cidr[2], last))
            })
        })
        .collect();

    let results: Vec<Vec<String>> = stream::iter(all_ips)
        .map(|ip| {
            let resolver = resolver.clone();
            async move {
                match tokio::time::timeout(
                    std::time::Duration::from_secs(2),
                    resolver.reverse_lookup(ip),
                ).await {
                    Ok(Ok(names)) => {
                        names.iter()
                            .map(|n| {
                                let host = n.to_string().trim_end_matches('.').to_lowercase();
                                debug!(ip = %ip, ptr = %host, "PTR record");
                                host
                            })
                            .collect()
                    }
                    _ => Vec::new(),
                }
            }
        })
        .buffer_unordered(concurrency)
        .collect()
        .await;

    results.into_iter().flatten().collect()
}

/// Resolve a list of hostnames to their IPs.
pub async fn resolve_hosts(hosts: &[String]) -> Vec<IpAddr> {
    let resolver = make_resolver();

    let mut ips = Vec::new();
    for host in hosts {
        if let Ok(lookup) = resolver.lookup_ip(host.as_str()).await {
            for ip in lookup.iter() {
                ips.push(ip);
            }
        }
    }
    ips
}
