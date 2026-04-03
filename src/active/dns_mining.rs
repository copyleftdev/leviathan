use hickory_resolver::TokioResolver;
use hickory_resolver::proto::rr::RecordType;
use regex::Regex;
use tracing::debug;

type Resolver = TokioResolver;

fn make_resolver() -> Option<Resolver> {
    Some(Resolver::builder_tokio().unwrap().build())
}

/// Mine DNS records for subdomain references.
/// SPF includes, DMARC rua/ruf, MX hosts, NS records, CNAME targets, SOA mname/rname.
pub async fn mine_dns_records(domain: &str) -> Vec<String> {
    let resolver = match make_resolver() {
        Some(r) => r,
        None => return Vec::new(),
    };

    let mut results = Vec::new();

    // Mine TXT records (SPF, DMARC, verification records)
    results.extend(mine_txt(&resolver, domain).await);
    results.extend(mine_txt(&resolver, &format!("_dmarc.{domain}")).await);

    // Mine MX records
    results.extend(mine_mx(&resolver, domain).await);

    // Mine NS records
    results.extend(mine_ns(&resolver, domain).await);

    // Mine SOA record
    results.extend(mine_soa(&resolver, domain).await);

    // Mine SRV records for common services
    for prefix in &[
        "_sip._tcp", "_sip._udp", "_xmpp-server._tcp", "_xmpp-client._tcp",
        "_ldap._tcp", "_kerberos._tcp", "_http._tcp", "_https._tcp",
        "_caldav._tcp", "_carddav._tcp", "_imap._tcp", "_imaps._tcp",
        "_submission._tcp", "_pop3._tcp", "_pop3s._tcp",
    ] {
        results.extend(mine_srv(&resolver, &format!("{prefix}.{domain}")).await);
    }

    // Follow CNAME chains for common subdomains
    for sub in &[
        "www", "mail", "smtp", "pop", "imap", "ftp", "webmail", "autodiscover",
        "autoconfig", "cpanel", "whm", "ns1", "ns2", "vpn", "remote", "gateway",
        "proxy", "cdn", "static", "assets", "media", "img", "images",
    ] {
        results.extend(mine_cname(&resolver, &format!("{sub}.{domain}")).await);
    }

    results
}

/// Extract domains from TXT records — SPF includes, DMARC URIs, verification tokens.
async fn mine_txt(resolver: &Resolver, name: &str) -> Vec<String> {
    let mut results = Vec::new();

    let records = match resolver.txt_lookup(name).await {
        Ok(r) => r,
        Err(_) => return results,
    };

    let domain_re = Regex::new(r"(?i)(?:[a-z0-9][-a-z0-9]*\.)+[a-z]{2,}").unwrap();

    for record in records.iter() {
        let txt = record.to_string();
        debug!(name = name, txt = %txt, "TXT record");

        // SPF: extract include:, a:, mx:, redirect= targets
        if txt.contains("v=spf1") {
            for part in txt.split_whitespace() {
                if let Some(target) = part.strip_prefix("include:") {
                    results.push(target.to_lowercase());
                } else if let Some(target) = part.strip_prefix("a:") {
                    results.push(target.to_lowercase());
                } else if let Some(target) = part.strip_prefix("mx:") {
                    results.push(target.to_lowercase());
                } else if let Some(target) = part.strip_prefix("redirect=") {
                    results.push(target.to_lowercase());
                } else if let Some(target) = part.strip_prefix("exists:") {
                    for m in domain_re.find_iter(target) {
                        results.push(m.as_str().to_lowercase());
                    }
                }
            }
        }

        // DMARC: extract rua= and ruf= URIs
        if txt.contains("v=DMARC1") {
            for part in txt.split(';') {
                let part = part.trim();
                if part.starts_with("rua=") || part.starts_with("ruf=") {
                    for m in domain_re.find_iter(part) {
                        results.push(m.as_str().to_lowercase());
                    }
                }
            }
        }

        // Generic: any domain-looking string in TXT records
        for m in domain_re.find_iter(&txt) {
            let found = m.as_str().to_lowercase();
            if found.contains('.') {
                results.push(found);
            }
        }
    }

    results
}

/// Extract hostnames from MX records.
async fn mine_mx(resolver: &Resolver, name: &str) -> Vec<String> {
    let records = match resolver.mx_lookup(name).await {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    records.iter()
        .map(|mx| {
            let host = mx.exchange().to_string();
            let host = host.trim_end_matches('.').to_lowercase();
            debug!(name = name, mx = %host, "MX record");
            host
        })
        .collect()
}

/// Extract hostnames from NS records.
async fn mine_ns(resolver: &Resolver, name: &str) -> Vec<String> {
    let records = match resolver.ns_lookup(name).await {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    records.iter()
        .map(|ns| {
            let host = ns.to_string();
            let host = host.trim_end_matches('.').to_lowercase();
            debug!(name = name, ns = %host, "NS record");
            host
        })
        .collect()
}

/// Extract hostnames from SOA record (mname, rname).
async fn mine_soa(resolver: &Resolver, name: &str) -> Vec<String> {
    let records = match resolver.soa_lookup(name).await {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    let mut results = Vec::new();
    for soa in records.iter() {
        let mname = soa.mname().to_string().trim_end_matches('.').to_lowercase();
        let rname = soa.rname().to_string().trim_end_matches('.').to_lowercase();
        debug!(name = name, mname = %mname, rname = %rname, "SOA record");
        results.push(mname);
        results.push(rname);
    }
    results
}

/// Extract hostnames from SRV records.
async fn mine_srv(resolver: &Resolver, name: &str) -> Vec<String> {
    let records = match resolver.srv_lookup(name).await {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    records.iter()
        .map(|srv| {
            let host = srv.target().to_string().trim_end_matches('.').to_lowercase();
            debug!(name = name, srv = %host, "SRV record");
            host
        })
        .collect()
}

/// Follow CNAME chains — the targets often reveal naming patterns.
async fn mine_cname(resolver: &Resolver, name: &str) -> Vec<String> {
    let records = match resolver.lookup(name, RecordType::CNAME).await {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    records.iter()
        .filter_map(|r| {
            r.as_cname().map(|cname| {
                let host = cname.0.to_string().trim_end_matches('.').to_lowercase();
                debug!(name = name, cname = %host, "CNAME record");
                host
            })
        })
        .collect()
}
