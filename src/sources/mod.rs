pub mod alienvault;
pub mod anubis;
pub mod certspotter;
pub mod crtsh;
pub mod hackertarget;
pub mod rapiddns;
pub mod urlscan;
pub mod wayback;

use async_trait::async_trait;
use reqwest::Client;
use std::fmt;

/// Every source implements this trait. No channels, no goroutines —
/// just return a Vec of subdomains. The engine handles concurrency.
#[async_trait]
pub trait Source: Send + Sync {
    fn name(&self) -> &'static str;
    async fn run(&self, client: &Client, domain: &str) -> Result<Vec<String>, SourceError>;
}

#[derive(Debug)]
pub enum SourceError {
    Http(reqwest::Error),
    Parse(String),
    RateLimit,
    Timeout,
}

impl fmt::Display for SourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SourceError::Http(e) => write!(f, "http: {e}"),
            SourceError::Parse(s) => write!(f, "parse: {s}"),
            SourceError::RateLimit => write!(f, "rate limited"),
            SourceError::Timeout => write!(f, "timeout"),
        }
    }
}

impl From<reqwest::Error> for SourceError {
    fn from(e: reqwest::Error) -> Self {
        if e.is_timeout() {
            SourceError::Timeout
        } else {
            SourceError::Http(e)
        }
    }
}

/// Build the default set of all sources.
pub fn all_sources() -> Vec<Box<dyn Source>> {
    vec![
        Box::new(crtsh::CrtSh),
        Box::new(hackertarget::HackerTarget),
        Box::new(alienvault::AlienVault),
        Box::new(wayback::WaybackArchive),
        Box::new(anubis::Anubis),
        Box::new(certspotter::CertSpotter),
        Box::new(urlscan::UrlScan),
        Box::new(rapiddns::RapidDns),
    ]
}
