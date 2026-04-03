use super::{Source, SourceError};
use async_trait::async_trait;
use reqwest::Client;

/// Anubis-DB subdomain API — returns JSON array of subdomains.
pub struct Anubis;

#[async_trait]
impl Source for Anubis {
    fn name(&self) -> &'static str {
        "anubis"
    }

    async fn run(&self, client: &Client, domain: &str) -> Result<Vec<String>, SourceError> {
        let url = format!("https://jldc.me/anubis/subdomains/{domain}");
        let resp = client.get(&url).send().await?;
        let subs: Vec<String> = resp.json().await.map_err(|e| {
            SourceError::Parse(format!("anubis json: {e}"))
        })?;

        let results: Vec<String> = subs
            .into_iter()
            .map(|s| s.to_lowercase())
            .collect();

        Ok(results)
    }
}
