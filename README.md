# Recon-x
# ⚡ RECON-X

<p align="center">
  <img src="https://img.shields.io/badge/language-Go-00ADD8?style=for-the-badge&logo=go" />
  <img src="https://img.shields.io/badge/license-MIT-green?style=for-the-badge" />
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-blue?style=for-the-badge" />
  <img src="https://img.shields.io/badge/use-Authorized%20Testing%20Only-red?style=for-the-badge" />
</p>

> **A comprehensive, all-in-one network reconnaissance and vulnerability scanner written in pure Go — no external dependencies.**


## 📖 Table of Contents

- [Features](#-features)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Modules](#-modules)
- [Usage & Flags](#-usage--flags)
- [Examples](#-examples)
- [Output Formats](#-output-formats)
- [CVE / NVD Integration](#-cve--nvd-integration)
- [Authenticated Crawling](#-authenticated-crawling)
- [Advanced DNS](#-advanced-dns)
- [Scan Timing](#-scan-timing)
- [Author](#-author)

---

## ✨ Features

| Category | Capabilities |
|---|---|
| **Port Scanning** | TCP connect, SYN (raw), UDP, IPv6, ping sweep, adaptive RTT, per-port retries |
| **Fingerprinting** | 7000+ service signatures (SSH, HTTP, DBs, IoT, SCADA, Cloud, ICS…) |
| **Vulnerability** | Live CVE lookup via NVD 2.0 API — paginated, scored, sorted by severity |
| **TLS Audit** | Weak ciphers, expired/self-signed certs, missing OCSP, export-grade detection |
| **HTTP Audit** | Security headers, cookie flags, WAF detection, dangerous methods, tech detection |
| **DNS** | A/AAAA/MX/NS/TXT/SOA/SRV/PTR/DMARC/DKIM/DNSSEC, zone transfer, NSEC walk |
| **Subdomains** | 500+ wordlist brute-force, mutation engine, wildcard filtering |
| **CT Logs** | crt.sh + CertSpotter + AlienVault OTX (3 sources in parallel) |
| **Web Crawler** | BFS crawler, JS rendering (headless Chrome), form testing, API discovery |
| **Auth Checks** | Redis, MongoDB, Elasticsearch, Docker, Kubernetes, Consul, Jenkins, and more |
| **Bruteforce** | FTP, SSH, Telnet, SMTP, MySQL, MSSQL, Redis, VNC, SNMP, WinRM, HTTP forms |
| **OS Detection** | TTL, banners, SMB, RDP, NBNS, SSH fingerprinting |
| **Protocols** | gRPC detection & reflection, MQTT auth, AMQP auth |
| **Output** | Colored terminal, JSON, HTML report, SARIF 2.1, CSV, XML |

---

## 🔧 Installation

### Prerequisites

- **Go 1.21+** — [Install Go](https://go.dev/dl/)
- No external Go dependencies — pure stdlib only

### Build from Source

```bash
# Clone the repository
git clone https://github.com/gopalakrishnsak/recon-x.git
cd recon-x

# Build
go build -o reconx main.go

# (Linux/macOS) Make executable and move to PATH
chmod +x reconx
sudo mv reconx /usr/local/bin/

# Verify
reconx --help
```

### Cross-compile for other platforms

```bash
# Windows
GOOS=windows GOARCH=amd64 go build -o reconx.exe main.go

# Linux ARM (e.g., Raspberry Pi)
GOOS=linux GOARCH=arm64 go build -o reconx-arm main.go

# macOS (Apple Silicon)
GOOS=darwin GOARCH=arm64 go build -o reconx-mac main.go
```

### SYN Scan (optional — requires elevated privileges)

```bash
# Linux: grant CAP_NET_RAW to the binary
sudo setcap cap_net_raw+ep ./reconx

# Or run as root
sudo reconx <target> -syn -all
```

---

## 🚀 Quick Start

```bash
# Scan a single host with all modules
reconx example.com -all

# Quick port scan only
reconx 192.168.1.1 -portscan

# Full recon with HTML report
reconx example.com -all -html report.html -v

# Scan a subnet
reconx 192.168.1.0/24 -portscan -auth -T 4

# Scan from a target list
reconx -iL targets.txt -all -json > results.json
```

---

## 🧩 Modules

### Port Scanner
Concurrent TCP connect scanner with adaptive RTT, per-port retries, timing profiles, SYN scan option, and UDP probing.

### Service Fingerprinter
Over 7,000 signatures covering SSH, FTP, SMTP, HTTP, databases, containers, network devices, IoT, ICS/SCADA, monitoring, CI/CD, messaging, and more.

### NVD Live CVE Lookup
After fingerprinting each service, RECON-X automatically queries the [NVD 2.0 API](https://nvd.nist.gov/developers/vulnerabilities) using the service's CPE string — fetching up to 10,000 CVEs per service, paginated, cached, and sorted by CVSS score.

### TLS Auditor
Checks TLS version (flags TLS 1.0/1.1), cipher strength, certificate expiry, self-signed status, wildcard usage, OCSP stapling, and export-grade ciphers.

### HTTP Auditor
Checks 10 security headers, dangerous HTTP methods (TRACE, PUT, DELETE), cookie flags (Secure, HttpOnly, SameSite), WAF detection, technology fingerprinting, robots.txt/sitemap.xml analysis, exposed `.git`, `.env`, and backup files.

### DNS Enumerator
Full DNS record enumeration, SPF/DMARC/DKIM analysis, DNSSEC validation, NSEC zone walking, zone transfer (AXFR), BIND version disclosure, open recursion, NXDOMAIN hijacking, PTR records, and SRV discovery.

### Subdomain Bruteforcer
Built-in 500+ word list with wildcard filtering, custom wordlist support, and a mutation engine that generates environment/region/numeric/typo variants.

### Certificate Transparency
Queries crt.sh, CertSpotter, and AlienVault OTX in parallel — discovers historical and wildcard subdomains from public CT logs.

### Web Crawler
BFS crawler with configurable depth and URL cap. Extracts links from HTML, JS `fetch()`/`axios`/XHR calls, and data attributes. Also probes 200+ sensitive paths (`.env`, `.git`, phpinfo, Actuator, backups, admin panels, etc.).

### Auth Checker
Tests for unauthenticated access to: Redis, MongoDB, Elasticsearch, Memcached, Docker API, Kubernetes API, etcd, ZooKeeper, CouchDB, RabbitMQ, Cassandra, Prometheus, Consul, Grafana (default creds), Jenkins.

### Bruteforcer
Tests common credentials against: FTP, SSH (banner + Hydra hint), Telnet, SMTP AUTH, MySQL, PostgreSQL, MSSQL, Redis, VNC (no-auth detection), SNMP community strings, WinRM, Grafana API, Tomcat Manager, HTTP Basic Auth, HTTP form login.

### OS Detector
Multi-probe OS detection: SSH banner, HTTP Server header, SMTP banner, FTP banner, RDP port probe, SMB negotiate, NBNS UDP, TTL analysis.

### gRPC Scanner
Detects gRPC services via HTTP/2 content-type and protocol preface. Also tests for server reflection (ServerReflectionInfo) which exposes all service definitions.

### MQTT Scanner
Sends MQTT CONNECT packet and analyzes CONNACK return code — detects no-auth brokers.

### AMQP Scanner
Sends AMQP 0-9-1 header and parses Connection.Start — detects RabbitMQ, ActiveMQ, Qpid, and checks for ANONYMOUS SASL.

---

## 📋 Usage & Flags

```
reconx <target> [flags]
```

### Target

| Flag | Description |
|---|---|
| `-target <host>` | Single target: IP, hostname, CIDR, or IP range |
| `-iL <file>` | File with one target per line |
| `-ports <spec>` | Ports: `80,443`, `1-1024`, `top1000`, ranges |
| `-exclude-ports <spec>` | Ports to exclude |

### Modules

| Flag | Description |
|---|---|
| `-all` | Enable ALL modules |
| `-portscan` | Port scan + banner + fingerprint |
| `-tls` | TLS/SSL audit |
| `-http` | HTTP headers/cookies/methods audit |
| `-dns` | DNS enumeration |
| `-sub` | Subdomain bruteforce |
| `-auth` | Unauthenticated access checks |
| `-crawl` | Web crawler |
| `-os` | OS detection |
| `-brute` | Credential bruteforce |
| `-api` | API endpoint discovery |
| `-grpc` | gRPC detection and reflection |
| `-mqtt` | MQTT broker detection |
| `-amqp` | AMQP broker detection |
| `-syn` | SYN scan (requires root/CAP_NET_RAW) |

### DNS Options

| Flag | Description |
|---|---|
| `-dns-server <ip>` | Custom DNS resolver (e.g. `8.8.8.8`) |
| `-dns-crt` | Certificate transparency via crt.sh |
| `-ct-enhanced` | Enhanced CT: crt.sh + CertSpotter + AlienVault |
| `-dns-mutate` | Mutation brute-force on discovered subdomains |
| `-dns-tld` | TLD expansion — probe all IANA TLDs |
| `-dns-snoop` | DNS cache snooping against target NS servers |
| `-dns-walk` | DNSSEC NSEC zone walk |
| `-dns-rev <cidr>` | Reverse PTR sweep for CIDR/range |

### Scan Tuning

| Flag | Default | Description |
|---|---|---|
| `-T <0-5>` | `3` | Timing: 0=paranoid, 3=normal, 5=insane |
| `-timeout <dur>` | `5s` | Per-connection timeout |
| `-workers <n>` | `100` | Concurrent workers |
| `-retries <n>` | `2` | Per-port retry count |
| `-max-rate <n>` | unlimited | Max probes/second |
| `-scan-delay <dur>` | `0` | Fixed delay between probes |
| `-rand-delay` | off | Random delay between probes |
| `-randomize-hosts` | off | Randomise host scan order |
| `-udp` | off | UDP scan on common ports |
| `-6` | off | IPv6 scan (AAAA records) |
| `-ping-sweep` | off | Drop unresponsive hosts first |
| `-no-ping` | off | Skip ping check entirely |
| `-os-aggressive` | off | Probe more ports for OS detection |
| `-pool` | off | HTTP connection pooling |

### CVE / NVD

| Flag | Default | Description |
|---|---|---|
| `-cve-limit <n>` | `10000` | Max CVEs per service |
| `-cve-min-score <f>` | `0` | Minimum CVSS score (e.g. `7.0`) |

### Web Crawl

| Flag | Default | Description |
|---|---|---|
| `-crawl-depth <n>` | `5` | BFS depth limit |
| `-crawl-max-urls <n>` | `500` | Max URLs to collect |
| `-form-test` | off | Submit forms with detection payloads |
| `-js-render` | off | Headless Chrome JS rendering |
| `-wordlist <file>` | built-in | Custom subdomain wordlist |

### Authenticated Crawl

| Flag | Description |
|---|---|
| `-login-url <url>` | POST credentials here before crawling |
| `-login-user <user>` | Username |
| `-login-pass <pass>` | Password |
| `-login-user-field <s>` | Form field name for username (default: `username`) |
| `-login-pass-field <s>` | Form field name for password (default: `password`) |
| `-login-cookie <s>` | Raw Cookie header to inject |
| `-login-token <s>` | Bearer token for Authorization header |

### Output

| Flag | Description |
|---|---|
| `-o <file>` | Write plain-text output to file |
| `-json` | Output results as JSON |
| `-html <file>` | Write HTML report |
| `-sarif <file>` | Write SARIF 2.1 report (GitHub/Azure DevOps) |
| `-csv <file>` | Write CSV findings report |
| `-xml <file>` | Write XML findings report |
| `-v` | Verbose output |
| `-debug` | Debug output |
| `-no-color` | Disable ANSI colors |

---

## 💡 Examples

### Basic Scans

```bash
# Default scan (port scan + auth checks + OS detection)
reconx example.com

# All modules, verbose
reconx example.com -all -v

# Scan top 1000 ports
reconx 10.0.0.1 -portscan -ports top1000

# Scan custom port range
reconx 10.0.0.1 -portscan -ports 1-10000

# Scan a subnet with ping sweep
reconx 192.168.1.0/24 -portscan -ping-sweep -T 4
```

### Web Recon

```bash
# Full web recon
reconx example.com -http -crawl -api -dns -sub

# Crawl with form testing and JS rendering
reconx example.com -crawl -form-test -js-render

# Authenticated crawl with session cookie
reconx example.com -crawl -login-cookie "session=abc123xyz"

# Authenticated crawl via login form
reconx example.com -crawl \
  -login-url https://example.com/login \
  -login-user admin \
  -login-pass password123
```

### DNS & Subdomain Recon

```bash
# Full DNS enumeration
reconx example.com -dns

# Subdomain brute-force with custom wordlist
reconx example.com -sub -wordlist /path/to/wordlist.txt

# Certificate transparency + mutation engine
reconx example.com -ct-enhanced -dns-mutate

# NSEC zone walk + zone transfer attempt
reconx example.com -dns -dns-walk

# Cache snooping against NS servers
reconx example.com -dns -dns-snoop

# Reverse PTR sweep
reconx example.com -dns-rev 192.168.1.0/24
```

### CVE Scanning

```bash
# Default: all CVEs for each service
reconx example.com -portscan

# Only HIGH and CRITICAL CVEs (CVSS >= 7.0)
reconx example.com -portscan -cve-min-score 7.0

# Limit to top 50 CVEs per service
reconx example.com -portscan -cve-limit 50
```

### Stealth Scanning

```bash
# Paranoid timing (slowest, least detectable)
reconx example.com -portscan -T 0

# Polite scan with fixed delay
reconx example.com -portscan -T 2 -scan-delay 500ms

# Randomize host order with random delays
reconx 10.0.0.0/24 -portscan -randomize-hosts -rand-delay

# Use a proxy
reconx example.com -all -proxy http://127.0.0.1:8080
```

### Multi-target & Reporting

```bash
# Scan from file, write all outputs
reconx -iL targets.txt -all \
  -html report.html \
  -csv findings.csv \
  -sarif results.sarif \
  -json > results.json

# Aggressive scan with full reporting
reconx example.com -all -T 4 \
  -html report.html \
  -v \
  -o full_output.txt
```

### Protocol-Specific

```bash
# SYN scan (requires root)
sudo reconx 10.0.0.1 -syn -ports 1-1024

# UDP scan
reconx 10.0.0.1 -udp -portscan

# gRPC + MQTT + AMQP detection
reconx 10.0.0.1 -grpc -mqtt -amqp

# IPv6 scan
reconx example.com -portscan -6
```

---

## 📊 Output Formats

### Terminal (default)
Color-coded with severity indicators, banners, TLS info, HTTP summaries, and findings grouped by severity.

### JSON (`-json`)
Full structured output — all ports, findings, DNS records, subdomains, HTTP audit, crawled URLs, and metadata.

### HTML (`-html report.html`)
Self-contained dark-theme HTML report with:
- Severity summary counters
- Expandable finding cards with CVE links
- Port table with risk indicators
- DNS records table
- HTTP audit section with forms and cookies

### SARIF 2.1 (`-sarif results.sarif`)
Import directly into GitHub Code Scanning, Azure DevOps, VS Code Security extension, or any SARIF-compatible platform.

### CSV (`-csv findings.csv`)
Excel-compatible (UTF-8 BOM) with columns: Target, Module, Severity, Title, Detail, Evidence, CVE, Remediation.

### XML (`-xml findings.xml`)
Structured XML with per-target sections: IPs, open ports, subdomains, and findings.

---

## 🔍 CVE / NVD Integration

RECON-X automatically queries the [National Vulnerability Database (NVD) 2.0 API](https://nvd.nist.gov/developers/vulnerabilities) after fingerprinting each service:

1. Builds a CPE 2.3 string from the fingerprinted service/version
2. Queries NVD with pagination (up to 2,000 CVEs per page)
3. Filters by minimum CVSS score (`-cve-min-score`)
4. Stops at configured limit (`-cve-limit`, default 10,000)
5. Caches results per CPE — the same service is never queried twice
6. Sorts results: CRITICAL → HIGH → MEDIUM → LOW, then newest first

Results include: CVE ID, CVSS score, severity, published date, description, public exploit indicator, and patch URL.

**Rate limiting:** RECON-X respects NVD's 50 requests/30s limit with a built-in 650ms token bucket.

---

## 🔐 Authenticated Crawling

RECON-X supports three authentication methods for web crawling:

### 1. Direct Cookie Injection
```bash
reconx example.com -crawl -login-cookie "sessionid=abc123; csrftoken=xyz"
```

### 2. Bearer Token
```bash
reconx example.com -crawl -login-token "eyJhbGciOiJIUzI1NiIsInR..."
```

### 3. Form Login
RECON-X will:
- GET the login page and harvest CSRF tokens automatically
- POST credentials to the login URL
- Capture session cookies from the response
- Inject those cookies into all subsequent crawl requests

```bash
reconx example.com -crawl \
  -login-url https://example.com/auth/login \
  -login-user admin \
  -login-pass P@ssw0rd \
  -login-user-field email \
  -login-pass-field password
```

---

## 🌐 Advanced DNS

### Zone Transfer (AXFR)
RECON-X attempts AXFR against each discovered nameserver. A successful transfer exposes all DNS records in the zone.

### NSEC Zone Walking
When DNSSEC uses NSEC (not NSEC3), RECON-X walks the chain to enumerate all hostnames in the zone without authentication.

### Cache Snooping
Queries target NS servers with `RD=0` (no recursion) for popular domains (GitHub, AWS, Discord, etc.) to reveal what the target's clients have recently resolved.

### DNS Mutation Engine
Takes each discovered subdomain, generates hundreds of permutations (env prefixes, region suffixes, numeric variants, typos), and resolves them — finding infrastructure that a wordlist alone would miss.

### TLD Expansion
Probes the base domain name against 80+ TLDs to discover other registrations (brand squatting, shadow infrastructure, defensive registrations).

---

## ⏱ Scan Timing

| Level | Name | Timeout | Delay | Workers | Use Case |
|---|---|---|---|---|---|
| `-T 0` | paranoid | 5 min | 5 min | 1 | Maximum stealth |
| `-T 1` | sneaky | 15s | 15s | 5 | Very slow, low noise |
| `-T 2` | polite | 5s | 400ms | 20 | Considerate |
| `-T 3` | normal | 5s | none | 100 | **Default** |
| `-T 4` | aggressive | 1.25s | none | 300 | Fast, internal networks |
| `-T 5` | insane | 300ms | none | 1000 | Maximum speed |

RECON-X also uses **adaptive RTT tracking** — per-host round-trip times are measured and the effective timeout auto-adjusts, just like Nmap's timing engine.

---

## 📁 Project Structure

```
recon-x/
├── main.go          # Complete source (single-file tool)
├── README.md        # This file
└── LICENSE          # MIT License
```

---

## 🤝 Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you'd like to change.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-module`)
3. Commit your changes (`git commit -am 'Add new module'`)
4. Push to the branch (`git push origin feature/new-module`)
5. Open a Pull Request

---

## 👤 Author

**GopalaKrishna Varma**

- 📧 Email: [Gopalakrishnsak@protonmail.com](mailto:Gopalakrishnsak@protonmail.com)
- 🌐 Website: [https://gkphotogallery.site123.me](https://gkphotogallery.site123.me)
- 🐙 GitHub: [https://github.com/gopalakrishnsak](https://github.com/gopalakrishnsak)

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

<p align="center">
  <strong>⚡ RECON-X — For authorized security testing only ⚡</strong>
</p>
