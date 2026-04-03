use super::{Source, SourceError};
use async_trait::async_trait;
use reqwest::Client;

/// Wayback Machine CDX API — extract subdomains from archived URLs.
pub struct WaybackArchive;

#[async_trait]
impl Source for WaybackArchive {
    fn name(&self) -> &'static str {
        "wayback"
    }

    async fn run(&self, client: &Client, domain: &str) -> Result<Vec<String>, SourceError> {
        let url = format!(
            "https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=text&fl=original&collapse=urlkey&limit=10000"
        );
        let text = client.get(&url).send().await?.text().await?;

        let results: Vec<String> = text
            .lines()
            .filter_map(|line| {
                let line = line.trim();
                // Extract hostname from URL
                let host = line
                    .strip_prefix("https://")
                    .or_else(|| line.strip_prefix("http://"))?;
                let host = host.split('/').next()?;
                let host = host.split(':').next()?; // strip port
                let host = host.to_lowercase();
                if host.is_empty() { None } else { Some(host) }
            })
            .collect();

        Ok(results)
    }
}
