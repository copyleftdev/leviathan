use super::{Source, SourceError};
use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;

/// CertSpotter CT log monitoring API.
pub struct CertSpotter;

#[derive(Deserialize)]
struct CertSpotterEntry {
    dns_names: Vec<String>,
}

#[async_trait]
impl Source for CertSpotter {
    fn name(&self) -> &'static str {
        "certspotter"
    }

    async fn run(&self, client: &Client, domain: &str) -> Result<Vec<String>, SourceError> {
        let url = format!(
            "https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
        );
        let resp = client.get(&url).send().await?;
        let entries: Vec<CertSpotterEntry> = resp.json().await.map_err(|e| {
            SourceError::Parse(format!("certspotter json: {e}"))
        })?;

        let results: Vec<String> = entries
            .into_iter()
            .flat_map(|e| e.dns_names)
            .map(|s| s.to_lowercase())
            .collect();

        Ok(results)
    }
}
