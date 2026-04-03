use super::{Source, SourceError};
use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;

/// Certificate Transparency via crt.sh JSON API.
/// Subfinder's #1 source — we hit the JSON endpoint directly, no PostgreSQL.
pub struct CrtSh;

#[derive(Deserialize)]
struct CrtShEntry {
    name_value: String,
}

#[async_trait]
impl Source for CrtSh {
    fn name(&self) -> &'static str {
        "crtsh"
    }

    async fn run(&self, client: &Client, domain: &str) -> Result<Vec<String>, SourceError> {
        let url = format!("https://crt.sh/?q=%25.{domain}&output=json");
        let resp = client.get(&url).send().await?;
        let entries: Vec<CrtShEntry> = resp.json().await.map_err(|e| {
            SourceError::Parse(format!("crtsh json: {e}"))
        })?;

        let mut results = Vec::with_capacity(entries.len());
        for entry in entries {
            // crt.sh returns newline-separated names in name_value
            for name in entry.name_value.split('\n') {
                let name = name.trim().to_lowercase();
                if !name.is_empty() {
                    results.push(name);
                }
            }
        }
        Ok(results)
    }
}
