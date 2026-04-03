use super::{Source, SourceError};
use async_trait::async_trait;
use reqwest::Client;

/// HackerTarget hostsearch API — plain text, one line per result.
pub struct HackerTarget;

#[async_trait]
impl Source for HackerTarget {
    fn name(&self) -> &'static str {
        "hackertarget"
    }

    async fn run(&self, client: &Client, domain: &str) -> Result<Vec<String>, SourceError> {
        let url = format!("https://api.hackertarget.com/hostsearch/?q={domain}");
        let text = client.get(&url).send().await?.text().await?;

        if text.contains("error") || text.contains("API count exceeded") {
            return Err(SourceError::RateLimit);
        }

        let results: Vec<String> = text
            .lines()
            .filter_map(|line| {
                // Format: subdomain,IP
                let host = line.split(',').next()?;
                let host = host.trim().to_lowercase();
                if host.is_empty() { None } else { Some(host) }
            })
            .collect();

        Ok(results)
    }
}
