use super::{Source, SourceError};
use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;

/// URLScan.io search API.
pub struct UrlScan;

#[derive(Deserialize)]
struct UrlScanResponse {
    results: Vec<UrlScanResult>,
}

#[derive(Deserialize)]
struct UrlScanResult {
    page: UrlScanPage,
}

#[derive(Deserialize)]
struct UrlScanPage {
    domain: String,
}

#[async_trait]
impl Source for UrlScan {
    fn name(&self) -> &'static str {
        "urlscan"
    }

    async fn run(&self, client: &Client, domain: &str) -> Result<Vec<String>, SourceError> {
        let url = format!(
            "https://urlscan.io/api/v1/search/?q=domain:{domain}&size=1000"
        );
        let resp = client.get(&url).send().await?;
        let data: UrlScanResponse = resp.json().await.map_err(|e| {
            SourceError::Parse(format!("urlscan json: {e}"))
        })?;

        let results: Vec<String> = data
            .results
            .into_iter()
            .map(|r| r.page.domain.to_lowercase())
            .collect();

        Ok(results)
    }
}
