use crate::sources::Source;
use dashmap::DashSet;
use futures::stream::{self, StreamExt};
use governor::{Quota, RateLimiter};
use reqwest::Client;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, warn};

/// Shared state for all sources — single connection pool, single dedup set.
pub struct Engine {
    pub client: Client,
    pub seen: Arc<DashSet<String>>,
    pub rate_limiter: Arc<RateLimiter<governor::state::NotKeyed, governor::state::InMemoryState, governor::clock::DefaultClock>>,
}

impl Engine {
    pub fn new(requests_per_second: u32, timeout_secs: u64) -> Self {
        let client = Client::builder()
            // Force IPv4 — eliminates ENETUNREACH waste from IPv6 fallback
            .local_address(Some(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)))
            // Shared connection pool across ALL sources
            .pool_max_idle_per_host(32)
            .pool_idle_timeout(Duration::from_secs(90))
            // Keep-alive — no "Connection: close" header
            .tcp_keepalive(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(timeout_secs))
            .redirect(reqwest::redirect::Policy::limited(5))
            .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
            .build()
            .expect("failed to build HTTP client");

        let quota = Quota::per_second(NonZeroU32::new(requests_per_second.max(1)).unwrap());
        let rate_limiter = Arc::new(RateLimiter::direct(quota));

        Engine {
            client,
            seen: Arc::new(DashSet::new()),
            rate_limiter,
        }
    }

    /// Run all sources concurrently for a domain, streaming deduplicated results.
    pub async fn enumerate(
        &self,
        domain: &str,
        sources: Vec<Box<dyn Source>>,
        concurrency: usize,
        tx: mpsc::Sender<String>,
    ) {
        let domain = domain.to_lowercase();
        let engine_client = self.client.clone();
        let engine_rl = self.rate_limiter.clone();

        stream::iter(sources)
            .for_each_concurrent(concurrency, |source| {
                let client = engine_client.clone();
                let rl = engine_rl.clone();
                let domain = domain.clone();
                let tx = tx.clone();
                async move {
                    let name = source.name();
                    debug!(source = name, domain = %domain, "starting source");

                    // Timer-based rate limit — no spin-wait
                    rl.until_ready().await;

                    match source.run(&client, &domain).await {
                        Ok(results) => {
                            let mut count = 0u32;
                            for sub in results {
                                let sub = sub.trim().to_lowercase();
                                if sub.is_empty() {
                                    continue;
                                }
                                if tx.send(sub).await.is_err() {
                                    return;
                                }
                                count += 1;
                            }
                            debug!(source = name, count, "source completed");
                        }
                        Err(e) => {
                            warn!(source = name, error = %e, "source failed");
                        }
                    }
                }
            })
            .await;
    }
}
