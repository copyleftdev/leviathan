use regex::Regex;
use reqwest::Client;
use tracing::debug;

/// Fetch web pages and JavaScript files from discovered hosts,
/// extract hardcoded domain references. Frontend code is incredibly leaky.
pub async fn scrape_js(
    client: &Client,
    hosts: &[String],
    domain: &str,
) -> Vec<String> {
    let domain_re = Regex::new(
        &format!(r#"(?i)(?:[a-z0-9][-a-z0-9]*\.)*[a-z0-9][-a-z0-9]*\.{}"#, regex::escape(domain))
    ).unwrap();

    // Match <script src="..."> and common JS file patterns
    let script_re = Regex::new(r#"(?i)(?:src|href)\s*=\s*["']([^"']*\.js(?:\?[^"']*)?)["']"#).unwrap();

    let mut results = Vec::new();
    let mut js_urls = Vec::new();

    // Phase 1: Fetch HTML pages, extract inline domains and JS URLs
    for host in hosts {
        let url = format!("https://{host}/");
        let body = match fetch_body(client, &url).await {
            Some(b) => b,
            None => {
                // Try HTTP
                match fetch_body(client, &format!("http://{host}/")).await {
                    Some(b) => b,
                    None => continue,
                }
            }
        };

        // Extract domains from HTML body
        for m in domain_re.find_iter(&body) {
            results.push(m.as_str().to_lowercase());
        }

        // Collect JS file URLs
        for cap in script_re.captures_iter(&body) {
            if let Some(src) = cap.get(1) {
                let src = src.as_str();
                let js_url = if src.starts_with("http") {
                    src.to_string()
                } else if src.starts_with("//") {
                    format!("https:{src}")
                } else if src.starts_with('/') {
                    format!("https://{host}{src}")
                } else {
                    format!("https://{host}/{src}")
                };
                js_urls.push(js_url);
            }
        }
    }

    // Phase 2: Fetch JS files and extract domains
    // Limit to first 20 JS files to avoid going overboard
    js_urls.truncate(20);

    for js_url in &js_urls {
        debug!(url = %js_url, "fetching JS file");
        if let Some(body) = fetch_body(client, js_url).await {
            for m in domain_re.find_iter(&body) {
                results.push(m.as_str().to_lowercase());
            }
        }
    }

    results
}

async fn fetch_body(client: &Client, url: &str) -> Option<String> {
    let resp = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        client.get(url).send(),
    ).await.ok()?.ok()?;

    // Only read up to 2MB to avoid memory bombs
    let bytes = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        resp.bytes(),
    ).await.ok()?.ok()?;

    if bytes.len() > 2 * 1024 * 1024 {
        return None;
    }

    String::from_utf8(bytes.to_vec()).ok()
}
