use hickory_proto::op::{Message, Query, MessageType, OpCode};
use hickory_proto::rr::{Name, RecordType};
use hickory_proto::serialize::binary::BinEncodable;
use hickory_resolver::TokioResolver;
use tokio::net::UdpSocket;
use std::str::FromStr;
use tracing::{debug, warn};

/// Walk a DNSSEC NSEC chain to enumerate all records in a zone.
/// We parse raw DNS responses to extract NSEC next-domain-name without
/// needing the full DNSSEC crypto stack.
pub async fn nsec_walk(domain: &str) -> Vec<String> {
    let mut results = Vec::new();
    let nameservers = get_authoritative_ns(domain).await;

    if nameservers.is_empty() {
        debug!(domain = domain, "no authoritative NS found for NSEC walk");
        return results;
    }

    let ns_addr = &nameservers[0];
    let zone = match Name::from_str(&format!("{domain}.")) {
        Ok(n) => n,
        Err(_) => return results,
    };

    let mut current = zone.clone();
    let mut seen = std::collections::HashSet::new();

    for _ in 0..10000 {
        let current_str = current.to_string().trim_end_matches('.').to_lowercase();
        if seen.contains(&current_str) {
            break;
        }
        seen.insert(current_str.clone());
        results.push(current_str);

        match query_nsec_raw(ns_addr, &current).await {
            Some(next_name) => {
                debug!(current = %current, next = %next_name, "NSEC chain");
                let next_str = next_name.to_string().to_lowercase();
                let next_trimmed = next_str.trim_end_matches('.');
                if !next_trimmed.ends_with(domain) && next_name != zone {
                    break;
                }
                current = next_name;
            }
            None => {
                debug!(current = %current, "NSEC chain ended");
                break;
            }
        }
    }

    results
}

/// Query for NSEC by sending a query for a non-existent type and parsing
/// the raw authority section for NSEC (type 47) records.
async fn query_nsec_raw(ns_addr: &str, name: &Name) -> Option<Name> {
    let socket = UdpSocket::bind("0.0.0.0:0").await.ok()?;

    let mut msg = Message::new();
    msg.set_id(rand_id());
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(false);
    msg.set_checking_disabled(true);

    let mut query = Query::new();
    query.set_name(name.clone());
    query.set_query_type(RecordType::NSEC);
    msg.add_query(query);

    msg.set_authentic_data(true);
    let edns = msg.extensions_mut().get_or_insert_with(Default::default);
    edns.set_dnssec_ok(true);
    edns.set_max_payload(4096);

    let buf = msg.to_bytes().ok()?;

    let addr = format!("{ns_addr}:53");
    socket.send_to(&buf, &addr).await.ok()?;

    let mut resp_buf = vec![0u8; 4096];
    let timeout = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        socket.recv_from(&mut resp_buf),
    ).await;

    let (len, _) = timeout.ok()?.ok()?;
    let resp = Message::from_vec(&resp_buf[..len]).ok()?;

    // Look for records of type NSEC (47) in authority and answer sections
    for record in resp.name_servers().iter().chain(resp.answers().iter()) {
        if record.record_type() == RecordType::NSEC {
            // Without the dnssec crypto feature, NSEC rdata is parsed as Unknown.
            // Display it and try to extract the next domain name from the text.
            let rdata = record.data();
            let rdata_str = format!("{rdata}");
            let parts: Vec<&str> = rdata_str.split_whitespace().collect();
            if let Some(first) = parts.first() {
                if first.contains('.') {
                    if let Ok(next) = Name::from_str(first) {
                        return Some(next);
                    }
                }
            }
        }
    }

    None
}

async fn get_authoritative_ns(domain: &str) -> Vec<String> {
    let resolver = TokioResolver::builder_tokio().unwrap().build();

    match resolver.ns_lookup(domain).await {
        Ok(ns) => {
            let mut addrs = Vec::new();
            for name in ns.iter() {
                let ns_name = name.to_string().trim_end_matches('.').to_string();
                if let Ok(ips) = resolver.lookup_ip(&ns_name).await {
                    for ip in ips.iter() {
                        addrs.push(ip.to_string());
                        break;
                    }
                }
            }
            addrs
        }
        Err(e) => {
            warn!(domain = domain, error = %e, "NS lookup failed");
            Vec::new()
        }
    }
}

fn rand_id() -> u16 {
    use std::time::SystemTime;
    let t = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    (t & 0xFFFF) as u16
}
