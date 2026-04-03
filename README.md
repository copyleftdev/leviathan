# leviathan

**From the deep — multi-phase subdomain recon engine.**

Leviathan was born from stracing subfinder at the syscall level, identifying every bottleneck in its architecture, and building a ground-up replacement that eliminates each one. It is not a wrapper, fork, or reimplementation — it is what subdomain enumeration looks like when you design it from first principles around how operating systems actually work.

```
leviathan -d hackerone.com
```

## Why this exists

We ran `strace -c -f` on subfinder and found:

| Bottleneck | Cause | Wall time consumed |
|---|---|---|
| **214,744 futex calls** | Goroutine-per-source with unbuffered channels | 62% (30.4s) |
| **290,865 epoll_pwait** | No cross-source connection pooling | 13.6% (6.7s) |
| **4,220 nanosleep** | Spin-wait rate limiter with exponential backoff | 12% (5.9s) |
| **44% connect() failures** | IPv6 fallback on IPv4-only systems | wasted syscalls |
| **42MB binary** | Massive Go dependency tree + debug symbols | disk/memory |

92% of subfinder's execution time is spent *waiting* — on mutexes, on the kernel's event loop, on its own rate limiter spinning. The actual CPU work takes 2.5 seconds out of a 30-second run.

Leviathan eliminates every one of these.

## What changed

| subfinder | leviathan | result |
|---|---|---|
| Goroutine per source + unbuffered `chan` | tokio async tasks + bounded MPSC | **311x fewer futex calls** |
| Per-source HTTP clients | Single shared `reqwest` connection pool | **1,476x fewer epoll calls** |
| Spin-wait rate limiter (`nanosleep` loop) | Timer-based token bucket (`governor`) | **183x fewer sleeps** |
| IPv6 fallback on every connect | IPv4-only forced at client level | zero ENETUNREACH waste |
| `Connection: close` header | HTTP/2 keep-alive by default | TLS session reuse |
| Go runtime (GC, scheduler, sysmon) | Rust with zero-cost async | **71x less CPU** |
| 42MB binary | 5.9MB stripped | **86% smaller** |
| Passive APIs only | 5-phase pipeline with active recon | **81% more results** |

## The five phases

Leviathan doesn't just query APIs. It runs a multi-phase pipeline where each phase feeds discoveries into the next:

```
Phase 1: Passive Sources
    crt.sh, HackerTarget, AlienVault OTX, Wayback Machine,
    Anubis, CertSpotter, URLScan, RapidDNS
    
Phase 2: DNS Record Mining + NSEC Zone Walk + TLS SAN Harvest
    SPF includes, DMARC rua/ruf, MX/NS/SOA/SRV/CNAME records,
    DNSSEC NSEC chain walking, TLS certificate Subject Alternative Names
    
Phase 3: HTTP Header Mining + JavaScript Analysis
    Content-Security-Policy, CORS, Location, Link, X-Backend-Server headers,
    JS bundle fetching + regex extraction of hardcoded domains
    
Phase 4: Reverse DNS /24 Sweep
    Resolve discovered hosts to IPs, PTR-scan every /24 CIDR for siblings
    
Phase 5: Permutation Engine
    Smart brute-force: dev-api, api-staging, v2-api, etc.
    Generated from discovered labels, resolved via direct DNS
```

Each phase discovers subdomains that no passive source knows about. TLS certificates alone often reveal 10-20 names. CSP headers whitelist every domain an application communicates with. Reverse DNS finds siblings on adjacent IPs. The permutation engine catches naming patterns.

## Head-to-head

Tested against `hackerone.com`:

| | subfinder | leviathan --passive | leviathan (full) |
|---|---|---|---|
| **Subdomains found** | 16 | 28 | 29 |
| **Wall clock** | 30.4s | 4.8s | 44.7s |
| **CPU time** | 2.58s | 0.04s | 2.94s |
| **Total syscalls** | 524,770 | ~4,400 | ~12,000 |
| **Binary size** | 42 MB | 5.9 MB | 5.9 MB |

Passive-only mode is **6x faster** and finds **75% more subdomains**. The full 5-phase run takes longer because it's doing work subfinder simply doesn't do — TLS handshakes, DNS record mining, /24 PTR sweeps, JS analysis.

Subfinder missed 13 subdomains that leviathan found. Leviathan missed zero that subfinder found.

## Usage

```bash
# Basic scan — all 5 phases
leviathan -d example.com

# Multiple domains
leviathan -d example.com,target.org

# Passive only — API sources, no active probing
leviathan -d example.com --passive

# Silent mode — subdomains only, no banner/progress
leviathan -d example.com -s

# JSON output
leviathan -d example.com --json

# Write to file
leviathan -d example.com -o results.txt

# Skip specific phases
leviathan -d example.com --no-reverse    # skip /24 PTR sweep
leviathan -d example.com --no-permute    # skip permutation brute-force

# Tune concurrency and rate limiting
leviathan -d example.com -c 50 --rate-limit 100

# Verbose — see per-source debug output
leviathan -d example.com -v
```

## Install

```bash
# From source
git clone https://github.com/copyleftdev/leviathan.git
cd leviathan
cargo build --release
cp target/release/leviathan /usr/local/bin/
```

Requires Rust 1.70+. No external dependencies at runtime.

## Architecture

```
                    +-----------------+
                    |   CLI (clap)    |
                    +--------+--------+
                             |
                    +--------v--------+
                    |     Engine      |
                    | shared reqwest  |
                    | DashSet dedup   |
                    | governor ratelim|
                    +--------+--------+
                             |
              +--------------+--------------+
              |              |              |
     Phase 1: Passive  Phase 2: DNS   Phase 3: HTTP
     8 async sources   mining + NSEC  headers + JS
     (crtsh, wayback,  zone walk +    scraping
      alienvault...)   TLS SAN harvest
              |              |              |
              +--------------+--------------+
                             |
              +--------------+--------------+
              |                             |
     Phase 4: Reverse DNS          Phase 5: Permutation
     /24 PTR sweep of              smart brute-force from
     discovered IPs                discovered labels
```

All phases share:
- **One connection pool** — `reqwest::Client` with HTTP/2, keep-alive, 32 idle connections per host
- **One dedup set** — `DashSet` (lock-free concurrent hashset) ensures zero duplicate output
- **One rate limiter** — `governor` token bucket, timer-based, no spin-wait
- **IPv4-only** — eliminates ENETUNREACH syscall waste from IPv6 fallback
- **Bounded backpressure** — MPSC channel with capacity 256 prevents unbounded memory growth

## Design philosophy

**Measure first.** Every design decision traces back to a syscall count, a strace timestamp, or a kernel event. We didn't guess at bottlenecks — we instrumented them.

**The fastest code is code that doesn't run.** Subfinder makes 524,770 syscalls to find 16 subdomains. Leviathan makes ~4,400 for 28. Most "performance work" is removing unnecessary work, not making necessary work faster.

**Active recon is not optional.** Passive APIs are a commodity — every tool queries the same endpoints and gets the same results. The subdomains that matter (internal infrastructure, forgotten services, misconfigured hosts) live in TLS certificates, DNS records, HTTP headers, and JavaScript bundles. You have to go get them.

**Stream, don't buffer.** Results appear as they're discovered. No waiting for all sources to complete before seeing output. Bounded channels provide backpressure instead of unbounded memory growth.

**One binary, no dependencies.** 5.9MB statically-linked. Runs on any Linux box. No Python, no Node, no Docker, no API keys required for the default source set.

## Vision

Leviathan is the beginning of a different approach to reconnaissance. The current generation of recon tools treats subdomain enumeration as "query some APIs and deduplicate." That's table stakes.

The direction is toward a **full-spectrum recon engine** that understands network infrastructure at the protocol level:

- **ASN expansion** — discover an IP, map the entire autonomous system, reverse-DNS every address
- **Certificate graph traversal** — follow certificate chains across organizations, find shared infrastructure
- **Service fingerprinting** — identify what's running on discovered hosts without active scanning (passive banner grabbing from CT logs, Shodan, Censys)
- **Recursive discovery** — subdomains of subdomains, CNAME chain following across organizational boundaries
- **Temporal analysis** — track what appeared and disappeared over time using historical DNS/CT data
- **Anomaly detection** — flag subdomains that break naming patterns, recently appeared, or point to unusual infrastructure

The constraint is always the same: **measure everything, assume nothing, and never make a syscall you don't need to.**

## License

MIT
