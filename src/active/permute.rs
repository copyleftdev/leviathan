use hickory_resolver::TokioResolver;
use futures::stream::{self, StreamExt};
use tracing::debug;

const PREFIXES: &[&str] = &[
    "dev", "staging", "stage", "stg", "test", "testing", "qa", "uat",
    "prod", "production", "preview", "beta", "alpha", "demo", "sandbox",
    "internal", "int", "ext", "external", "private", "priv", "pub",
    "admin", "mgmt", "management", "monitor", "metrics",
    "api", "api-v2", "api-v3", "v1", "v2", "v3",
    "old", "new", "legacy", "backup", "bak", "tmp", "temp",
    "dr", "failover", "replica", "secondary", "primary",
    "us", "eu", "ap", "us-east", "us-west", "eu-west",
];

const SEPARATORS: &[&str] = &["-", ".", ""];

/// Generate permutations from discovered subdomains and resolve them.
pub async fn permute_and_resolve(
    discovered: &[String],
    domain: &str,
    concurrency: usize,
) -> Vec<String> {
    let resolver = TokioResolver::builder_tokio().unwrap().build();

    let suffix = format!(".{domain}");
    let labels: Vec<&str> = discovered.iter()
        .filter_map(|s| s.strip_suffix(&suffix))
        .filter(|s| !s.contains('.') && !s.is_empty())
        .collect();

    let mut candidates = std::collections::HashSet::new();

    for label in &labels {
        for prefix in PREFIXES {
            for sep in SEPARATORS {
                candidates.insert(format!("{prefix}{sep}{label}.{domain}"));
                candidates.insert(format!("{label}{sep}{prefix}.{domain}"));
            }
        }
    }

    if labels.len() > 1 {
        for a in &labels {
            for b in &labels {
                if a != b {
                    for sep in SEPARATORS {
                        candidates.insert(format!("{a}{sep}{b}.{domain}"));
                    }
                }
            }
        }
    }

    debug!(candidate_count = candidates.len(), "generated permutations");

    let candidates: Vec<String> = candidates.into_iter().collect();

    let results: Vec<Option<String>> = stream::iter(candidates)
        .map(|candidate| {
            let resolver = resolver.clone();
            async move {
                match tokio::time::timeout(
                    std::time::Duration::from_secs(2),
                    resolver.lookup_ip(candidate.as_str()),
                ).await {
                    Ok(Ok(_)) => {
                        debug!(host = %candidate, "permutation resolved");
                        Some(candidate)
                    }
                    _ => None,
                }
            }
        })
        .buffer_unordered(concurrency)
        .collect()
        .await;

    results.into_iter().flatten().collect()
}
