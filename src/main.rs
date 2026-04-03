mod active;
mod engine;
mod sources;

use clap::Parser;
use engine::Engine;
use serde::Serialize;
use std::io::Write as IoWrite;
use std::time::Instant;
use tokio::sync::mpsc;
use tracing::Level;

#[derive(Parser)]
#[command(
    name = "leviathan",
    about = "From the deep — multi-phase subdomain recon engine",
    version
)]
struct Cli {
    /// Target domain(s), comma-separated
    #[arg(short, long, required = true, value_delimiter = ',')]
    domain: Vec<String>,

    /// Output file (default: stdout)
    #[arg(short, long)]
    output: Option<String>,

    /// JSON output format
    #[arg(long, default_value_t = false)]
    json: bool,

    /// Max concurrent sources per domain
    #[arg(short, long, default_value_t = 20)]
    concurrency: usize,

    /// Requests per second (global rate limit)
    #[arg(long, default_value_t = 25)]
    rate_limit: u32,

    /// HTTP timeout in seconds
    #[arg(short, long, default_value_t = 30)]
    timeout: u64,

    /// Silent mode — only print subdomains
    #[arg(short, long, default_value_t = false)]
    silent: bool,

    /// Passive only — skip active recon (SAN, DNS mining, reverse DNS, etc.)
    #[arg(long, default_value_t = false)]
    passive: bool,

    /// Skip permutation brute-forcing
    #[arg(long, default_value_t = false)]
    no_permute: bool,

    /// Skip reverse DNS /24 sweep
    #[arg(long, default_value_t = false)]
    no_reverse: bool,

    /// Verbose logging
    #[arg(short, long, default_value_t = false)]
    verbose: bool,
}

#[derive(Serialize)]
struct JsonResult {
    host: String,
    input: String,
    phase: String,
}

/// Validate, dedup, and write a subdomain. Returns true if new.
fn emit_sub(
    sub: String,
    phase: &str,
    domain: &str,
    domain_suffix: &str,
    engine: &Engine,
    writer: &mut dyn IoWrite,
    json: bool,
) -> bool {
    let sub = sub.trim().to_lowercase();
    let sub = sub.strip_prefix("*.").unwrap_or(&sub).to_string();
    if !sub.ends_with(domain_suffix) && sub != domain {
        return false;
    }
    if !engine.seen.insert(sub.clone()) {
        return false;
    }
    if json {
        let jr = JsonResult {
            host: sub,
            input: domain.to_string(),
            phase: phase.to_string(),
        };
        let _ = serde_json::to_writer(&mut *writer, &jr);
        let _ = writer.write_all(b"\n");
    } else {
        let _ = writeln!(writer, "{sub}");
    }
    true
}

#[tokio::main]
async fn main() {
    // Install rustls crypto provider before any TLS usage (SAN harvester uses rustls directly)
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    let cli = Cli::parse();

    let level = if cli.verbose { Level::DEBUG } else { Level::WARN };
    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();

    if !cli.silent {
        eprintln!(
            r#"
  _            _       _   _
 | | _____   _(_) __ _| |_| |__   __ _ _ __
 | |/ _ \ \ / / |/ _` | __| '_ \ / _` | '_ \
 | |  __/\ V /| | (_| | |_| | | | (_| | | | |
 |_|\___| \_/ |_|\__,_|\__|_| |_|\__,_|_| |_|
  from the deep — multi-phase subdomain recon
"#
        );
    }

    let engine = Engine::new(cli.rate_limit, cli.timeout);
    let start = Instant::now();
    let mut total_count = 0u32;

    let mut writer: Box<dyn IoWrite> = if let Some(ref path) = cli.output {
        Box::new(std::io::BufWriter::new(
            std::fs::File::create(path).expect("failed to create output file"),
        ))
    } else {
        Box::new(std::io::BufWriter::new(std::io::stdout().lock()))
    };

    for domain in &cli.domain {
        let domain = domain.trim().to_lowercase();
        if domain.is_empty() {
            continue;
        }

        let domain_suffix = format!(".{domain}");
        let mut domain_count = 0u32;

        // ═══════════════════════════════════════════════
        // PHASE 1: Passive sources (API queries)
        // ═══════════════════════════════════════════════
        if !cli.silent {
            eprintln!("[*] Phase 1: Passive sources for {domain}");
        }

        let sources = sources::all_sources();
        let (tx, mut rx) = mpsc::channel::<String>(256);
        let domain_clone = domain.clone();
        let concurrency = cli.concurrency;
        let client = engine.client.clone();
        let seen = engine.seen.clone();
        let rl = engine.rate_limiter.clone();

        let enum_handle = tokio::spawn(async move {
            let eng = Engine { client, seen, rate_limiter: rl };
            eng.enumerate(&domain_clone, sources, concurrency, tx).await;
        });

        while let Some(sub) = rx.recv().await {
            if emit_sub(sub, "passive", &domain, &domain_suffix, &engine, &mut *writer, cli.json) {
                domain_count += 1;
            }
        }
        let _ = enum_handle.await;

        if !cli.silent {
            eprintln!("[+] Phase 1 complete: {domain_count} subdomains from passive sources");
        }

        if cli.passive {
            total_count += domain_count;
            continue;
        }

        // ═══════════════════════════════════════════════
        // PHASE 2: DNS mining + NSEC walk + TLS SAN
        // ═══════════════════════════════════════════════
        if !cli.silent {
            eprintln!("[*] Phase 2: DNS mining + NSEC walk + TLS SAN harvest");
        }
        let phase1_count = domain_count;

        let (dns_results, nsec_results) = tokio::join!(
            active::dns_mining::mine_dns_records(&domain),
            active::nsec_walk::nsec_walk(&domain),
        );

        for sub in dns_results {
            if emit_sub(sub, "dns-mining", &domain, &domain_suffix, &engine, &mut *writer, cli.json) {
                domain_count += 1;
            }
        }
        for sub in nsec_results {
            if emit_sub(sub, "nsec-walk", &domain, &domain_suffix, &engine, &mut *writer, cli.json) {
                domain_count += 1;
            }
        }

        // SAN harvest — resolve current known hosts to IPs first
        let known_hosts: Vec<String> = engine.seen.iter().map(|r| r.key().clone()).collect();
        let ips = active::reverse_dns::resolve_hosts(&known_hosts).await;

        if !ips.is_empty() {
            let san_results = active::san_harvest::harvest_sans_batch(
                &ips, &domain, cli.concurrency,
            ).await;
            for sub in san_results {
                if emit_sub(sub, "tls-san", &domain, &domain_suffix, &engine, &mut *writer, cli.json) {
                    domain_count += 1;
                }
            }
        }

        if !cli.silent {
            eprintln!(
                "[+] Phase 2 complete: {} new subdomains (total: {domain_count})",
                domain_count - phase1_count
            );
        }

        // ═══════════════════════════════════════════════
        // PHASE 3: HTTP header mining + JS scraping
        // ═══════════════════════════════════════════════
        if !cli.silent {
            eprintln!("[*] Phase 3: HTTP header mining + JS analysis");
        }
        let phase2_count = domain_count;

        let known_hosts: Vec<String> = engine.seen.iter().map(|r| r.key().clone()).collect();

        let (header_results, js_results) = tokio::join!(
            active::header_mining::mine_headers(&engine.client, &known_hosts, &domain),
            active::js_scrape::scrape_js(&engine.client, &known_hosts, &domain),
        );

        for sub in header_results {
            if emit_sub(sub, "http-headers", &domain, &domain_suffix, &engine, &mut *writer, cli.json) {
                domain_count += 1;
            }
        }
        for sub in js_results {
            if emit_sub(sub, "js-scrape", &domain, &domain_suffix, &engine, &mut *writer, cli.json) {
                domain_count += 1;
            }
        }

        if !cli.silent {
            eprintln!(
                "[+] Phase 3 complete: {} new subdomains (total: {domain_count})",
                domain_count - phase2_count
            );
        }

        // ═══════════════════════════════════════════════
        // PHASE 4: Reverse DNS /24 sweep
        // ═══════════════════════════════════════════════
        if !cli.no_reverse {
            if !cli.silent {
                eprintln!("[*] Phase 4: Reverse DNS /24 sweep");
            }
            let phase3_count = domain_count;

            let known_hosts: Vec<String> = engine.seen.iter().map(|r| r.key().clone()).collect();
            let ips = active::reverse_dns::resolve_hosts(&known_hosts).await;

            let ptr_results = active::reverse_dns::reverse_dns_sweep(
                &ips, cli.concurrency.max(50),
            ).await;
            for sub in ptr_results {
                if emit_sub(sub, "reverse-dns", &domain, &domain_suffix, &engine, &mut *writer, cli.json) {
                    domain_count += 1;
                }
            }

            if !cli.silent {
                eprintln!(
                    "[+] Phase 4 complete: {} new subdomains (total: {domain_count})",
                    domain_count - phase3_count
                );
            }
        }

        // ═══════════════════════════════════════════════
        // PHASE 5: Permutation brute-force
        // ═══════════════════════════════════════════════
        if !cli.no_permute {
            if !cli.silent {
                eprintln!("[*] Phase 5: Permutation engine");
            }
            let phase4_count = domain_count;

            let known_hosts: Vec<String> = engine.seen.iter().map(|r| r.key().clone()).collect();

            let perm_results = active::permute::permute_and_resolve(
                &known_hosts, &domain, cli.concurrency.max(100),
            ).await;
            for sub in perm_results {
                if emit_sub(sub, "permutation", &domain, &domain_suffix, &engine, &mut *writer, cli.json) {
                    domain_count += 1;
                }
            }

            if !cli.silent {
                eprintln!(
                    "[+] Phase 5 complete: {} new subdomains (total: {domain_count})",
                    domain_count - phase4_count
                );
            }
        }

        total_count += domain_count;

        if !cli.silent {
            eprintln!("[=] {domain}: {domain_count} total unique subdomains");
        }
    }

    let _ = writer.flush();
    let elapsed = start.elapsed();

    if !cli.silent {
        eprintln!(
            "\n[*] Total: {total_count} unique subdomains in {:.2}s",
            elapsed.as_secs_f64()
        );
    }
}
