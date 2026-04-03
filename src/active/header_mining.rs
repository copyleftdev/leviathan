use regex::Regex;
use reqwest::Client;
use tracing::debug;

/// Fetch HTTP/HTTPS response headers from discovered subdomains and extract domain references.
/// CSP headers are gold — they whitelist every domain the app communicates with.
pub async fn mine_headers(
    client: &Client,
    hosts: &[String],
    _domain: &str,
) -> Vec<String> {
    let domain_re = Regex::new(r"(?i)(?:[a-z0-9][-a-z0-9]*\.)+[a-z]{2,}").unwrap();
    let mut results = Vec::new();

    for host in hosts {
        // Try HTTPS first, then HTTP
        for scheme in &["https", "http"] {
            let url = format!("{scheme}://{host}/");
            let resp = match tokio::time::timeout(
                std::time::Duration::from_secs(5),
                client.get(&url).send(),
            ).await {
                Ok(Ok(r)) => r,
                _ => continue,
            };

            let headers = resp.headers();

            // Content-Security-Policy — the motherload
            for key in &[
                "content-security-policy",
                "content-security-policy-report-only",
            ] {
                if let Some(csp) = headers.get(*key) {
                    if let Ok(val) = csp.to_str() {
                        debug!(host = host, header = key, "mining CSP header");
                        for m in domain_re.find_iter(val) {
                            results.push(m.as_str().to_lowercase());
                        }
                    }
                }
            }

            // Access-Control-Allow-Origin
            if let Some(cors) = headers.get("access-control-allow-origin") {
                if let Ok(val) = cors.to_str() {
                    for m in domain_re.find_iter(val) {
                        results.push(m.as_str().to_lowercase());
                    }
                }
            }

            // Location redirect
            if let Some(location) = headers.get("location") {
                if let Ok(val) = location.to_str() {
                    for m in domain_re.find_iter(val) {
                        results.push(m.as_str().to_lowercase());
                    }
                }
            }

            // Link header
            if let Some(link) = headers.get("link") {
                if let Ok(val) = link.to_str() {
                    for m in domain_re.find_iter(val) {
                        results.push(m.as_str().to_lowercase());
                    }
                }
            }

            // X-Forwarded-Host, X-Backend-Server — infrastructure leak
            for key in &["x-forwarded-host", "x-backend-server", "x-served-by", "x-cache"] {
                if let Some(hdr) = headers.get(*key) {
                    if let Ok(val) = hdr.to_str() {
                        for m in domain_re.find_iter(val) {
                            results.push(m.as_str().to_lowercase());
                        }
                    }
                }
            }

            // If HTTPS worked, skip HTTP
            break;
        }
    }

    results
}
