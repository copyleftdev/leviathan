use super::{Source, SourceError};
use async_trait::async_trait;
use regex::Regex;
use reqwest::Client;

/// RapidDNS — HTML scraping with regex extraction.
pub struct RapidDns;

#[async_trait]
impl Source for RapidDns {
    fn name(&self) -> &'static str {
        "rapiddns"
    }

    async fn run(&self, client: &Client, domain: &str) -> Result<Vec<String>, SourceError> {
        let url = format!("https://rapiddns.io/subdomain/{domain}?full=1");
        let text = client.get(&url).send().await?.text().await?;

        // Extract subdomains from HTML table cells
        let pattern = format!(r"(?i)[a-z0-9][-a-z0-9]*\.{}", regex::escape(domain));
        let re = Regex::new(&pattern).map_err(|e| SourceError::Parse(e.to_string()))?;

        let results: Vec<String> = re
            .find_iter(&text)
            .map(|m| m.as_str().to_lowercase())
            .collect();

        Ok(results)
    }
}
