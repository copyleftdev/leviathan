use super::{Source, SourceError};
use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;

/// AlienVault OTX passive DNS.
pub struct AlienVault;

#[derive(Deserialize)]
struct OtxResponse {
    passive_dns: Vec<OtxEntry>,
}

#[derive(Deserialize)]
struct OtxEntry {
    hostname: String,
}

#[async_trait]
impl Source for AlienVault {
    fn name(&self) -> &'static str {
        "alienvault"
    }

    async fn run(&self, client: &Client, domain: &str) -> Result<Vec<String>, SourceError> {
        let url = format!(
            "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns?limit=500"
        );
        let resp = client.get(&url).send().await?;
        let data: OtxResponse = resp.json().await.map_err(|e| {
            SourceError::Parse(format!("alienvault json: {e}"))
        })?;

        let results: Vec<String> = data
            .passive_dns
            .into_iter()
            .map(|e| e.hostname.to_lowercase())
            .collect();

        Ok(results)
    }
}
