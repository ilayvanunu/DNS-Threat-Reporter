# DNS Threat Reporter

A defensive Python tool that monitors DNS traffic on your local network in real time, analyzes every query for signs of malicious activity, and reports findings through a live web dashboard or the terminal.

---

## Table of Contents

1. [What It Does](#what-it-does)
2. [How It Works](#how-it-works)
3. [Detection Methods](#detection-methods)
4. [Project Structure](#project-structure)
5. [Requirements](#requirements)
6. [Installation](#installation)
7. [Usage](#usage)
8. [Web Dashboard (GUI)](#web-dashboard-gui)
9. [Log Files](#log-files)
10. [Blacklist & Whitelist](#blacklist--whitelist)
11. [Running Tests](#running-tests)
12. [Threat Levels](#threat-levels)

---

## What It Does

Every time a device on your network looks up a domain name (visits a website, runs an app, phones home), it sends a DNS query. DNS Threat Reporter captures those queries and checks them against multiple detection methods to identify:

- Connections to **known malicious domains** (malware C2 servers, phishing sites, crypto miners)
- **Randomly generated domains** used by malware to find its command server (DGA)
- **Data exfiltration** attempts that smuggle data inside DNS queries
- **Suspicious TLDs** that are disproportionately abused by attackers
- **Abnormal query rates** from a single host (possible beaconing)

When a critical threat is found, the system fires a **browser notification** visible even if you are on a different tab, and plays an **audio alarm**.

---

## How It Works

The system is built as a linear four-stage pipeline:

```
Network Interface
       │
       ▼
 ┌─────────────┐
 │  DNSSniffer │  Captures raw UDP port 53 packets using Scapy + BPF filter
 └──────┬──────┘
        │ raw Scapy packet
        ▼
 ┌─────────────┐
 │  DNSParser  │  Extracts domain, record type, source IP → DNSQuery object
 └──────┬──────┘
        │ DNSQuery
        ▼
 ┌──────────────┐
 │  DNSAnalyzer │  Runs 6 detection checks → AnalysisResult with ThreatLevel
 └──────┬───────┘
        │ AnalysisResult
        ▼
 ┌──────────────┐
 │  DNSReporter │  Writes logs + outputs to terminal or web dashboard
 └──────────────┘
```

Each stage is a self-contained module with a single responsibility.

---

## Detection Methods

### 1. Blacklist Matching

Checks the queried domain and all of its parent domains against a list of known malicious domains. If `sub.evil.com` is queried and `evil.com` is on the blacklist, it matches. A blacklist hit immediately sets the threat level to **CRITICAL**.

### 2. Domain Length Analysis

Normal domain names are human-readable and short. Attackers sometimes encode stolen data (passwords, files, screenshots) inside unusually long subdomain labels and send them out as DNS queries — a technique called DNS data exfiltration. A domain longer than 50 characters is flagged as suspicious; longer than 100 is flagged as HIGH.

### 3. Shannon Entropy (DGA Detection)

Malware often uses **Domain Generation Algorithms (DGAs)** to automatically produce a large list of random-looking domain names. The malware and its C2 server both run the same algorithm, so only the attacker's server is actually registered. This makes it very hard to block by domain name alone.

Shannon entropy measures how random a string is. Human-readable names like `google.com` have low entropy (predictable characters). DGA names like `x7k9m2p4q8w1.xyz` have high entropy (uniform character distribution). The analyzer flags domains with entropy above 3.8 as suspicious and above 4.2 as HIGH.

**Shannon entropy formula:**

```
H = -Σ P(c) * log₂(P(c))
```

Where `P(c)` is the probability of each character in the string.

### 4. Rate Anomaly Detection

Tracks how many DNS queries arrive from each source IP in a 60-second sliding window. A legitimate user generates ~10–30 DNS queries per minute. Malware beaconing (repeatedly contacting its C2 server to receive instructions) or automated scanning can generate hundreds. More than 60 queries/minute is flagged MEDIUM; more than 180 is flagged HIGH.

### 5. DNS Tunneling Detection

DNS tunneling tools (e.g. `dnscat2`, `iodine`) encode arbitrary data inside DNS query subdomains to create a covert communication channel that bypasses firewalls — DNS port 53 is almost never blocked. The detector looks for:

- Hex-encoded strings of 16+ characters in subdomain labels
- Base64-like patterns (alphanumeric + `+/=`) of 20+ characters
- An unusually high ratio of numeric digits in a subdomain

### 6. Suspicious TLD Detection

Some top-level domains are provided for free or at very low cost and are heavily abused by attackers (e.g. `.tk`, `.ml`, `.ga`, `.cf`, `.gq`, `.xyz`). Queries to these TLDs are flagged as LOW suspicion. This is a weak signal on its own but combines with other checks to raise the overall threat level.

---

## Project Structure

```
DNS_Threat_Reporter/
│
├── main.py                          # Entry point — CLI argument parsing & orchestration
│
├── dns_threat_reporter/
│   ├── __init__.py
│   ├── sniffer.py                   # Stage 1: Raw packet capture (Scapy)
│   ├── parser.py                    # Stage 2: Packet → DNSQuery dataclass
│   ├── analyzer.py                  # Stage 3: Threat detection engine
│   ├── reporter.py                  # Stage 4: Console output + log files
│   └── gui.py                       # Web dashboard (local HTTP server + browser UI)
│
├── data/
│   ├── blacklist.txt                # Known malicious domains (35 entries, one per line)
│   └── whitelist.txt                # User-trusted domains (gitignored, personal per machine)
│
├── tests/
│   ├── test_analyzer.py             # 14 unit tests for the detection engine
│   └── test_parser.py               # 6 unit tests for the DNS parser
│
├── logs/                            # Auto-created at runtime, gitignored
│   ├── alerts_<timestamp>.log       # HIGH and CRITICAL threats only
│   ├── dns_queries_<timestamp>.log  # Full query audit trail
│   └── dns_data_<timestamp>.jsonl   # Machine-readable JSON Lines
│
├── requirements.txt
├── pyrightconfig.json               # Suppresses Scapy Pylance warnings
└── .gitignore
```

---

## Requirements

- Python 3.9+
- [Scapy](https://scapy.net/) — packet capture and crafting
- [pytest](https://pytest.org/) — for running tests (optional)

No other third-party packages are needed. The web GUI uses Python's built-in `http.server` module.

---

## Installation

```bash
# 1. Clone the repository
git clone <repo-url>
cd DNS_Threat_Reporter

# 2. Install dependencies
pip install scapy pytest

# 3. (Optional) Create a virtual environment first
python3 -m venv venv
source venv/bin/activate
pip install scapy pytest
```

---

## Usage

### Web Dashboard (recommended)

```bash
python3 main.py --gui
```

Opens the interactive dashboard in your browser. No root required for demo mode.

### Live Monitoring (requires root)

```bash
sudo python3 main.py
sudo python3 main.py -i en0          # specific interface
sudo python3 main.py -v              # verbose — show all queries including safe ones
```

### Demo Mode (no root, no network)

```bash
python3 main.py --demo
```

Runs 14 simulated DNS queries including blacklisted domains, DGA-style domains, and tunneling patterns. Good for testing and understanding the detection output.

### Analyze a PCAP File

```bash
python3 main.py --pcap path/to/capture.pcap
```

Runs the full detection pipeline offline on a previously captured packet file.

### All CLI Options

```
-i, --interface   Network interface to monitor (e.g. en0, eth0). Default: all.
-b, --blacklist   Path to a custom blacklist file.
-v, --verbose     Show all queries, including safe ones.
-l, --log-dir     Directory to write log files. Default: ./logs
--gui             Open the web dashboard.
--demo            Run with simulated traffic (no root needed).
--pcap FILE       Analyze an existing PCAP file.
```

---

## Web Dashboard (GUI)

Run `python3 main.py --gui` and the dashboard opens automatically in your browser at `http://127.0.0.1:8765`.

### Dashboard Features

| Feature              | Description                                                                |
| -------------------- | -------------------------------------------------------------------------- |
| **Start Monitoring** | Begin live DNS sniffing on the selected interface (requires sudo)          |
| **Stop**             | Stop live monitoring                                                       |
| **Run Demo**         | Replay 14 simulated queries with a visual delay — no root needed           |
| **Blacklist button** | View, add, and remove entries from the malicious domain list               |
| **Whitelist button** | View, add, and remove entries from the trusted domain list                 |
| **Threat table**     | Live table of MEDIUM+ threats, color-coded by severity                     |
| **Row click**        | Shows full alert details at the bottom of the page                         |
| **Exact / +Parent**  | Whitelist a specific domain or all its subdomains directly from a row      |
| **Notifications**    | Browser popup + audio alarm for CRITICAL threats, even when on another tab |

### Threat Row Colors

| Color         | Level    | Meaning                             |
| ------------- | -------- | ----------------------------------- |
| Yellow/orange | MEDIUM   | Suspicious — worth noting           |
| Red           | HIGH     | Likely malicious                    |
| Bright red    | CRITICAL | Confirmed malicious (blacklist hit) |

---

## Log Files

Three log files are written per session inside the `logs/` directory. The filename includes a timestamp so sessions never overwrite each other.

### `dns_queries_<timestamp>.log`

Full audit trail — every DNS query, one line per entry:

```
[2024-01-15 14:32:01] [CRITICAL ] malware-site.com         | A     | 192.168.1.5 | ALERTS: Known malicious domain...
[2024-01-15 14:32:02] [SAFE     ] google.com               | A     | 192.168.1.5
```

### `alerts_<timestamp>.log`

HIGH and CRITICAL threats only, with full details:

```
============================================================
[2024-01-15 14:32:01] ALERT - CRITICAL
Domain: malware-site.com
Type:   A
Source: 192.168.1.5
  -> Known malicious domain found in blacklist! (malware-site.com)
============================================================
```

### `dns_data_<timestamp>.jsonl`

One JSON object per line — suitable for importing into SIEM tools, Splunk, Elastic, or running custom analysis scripts:

```json
{
  "timestamp": "2024-01-15T14:32:01.123",
  "domain": "malware-site.com",
  "query_type": "A",
  "source_ip": "192.168.1.5",
  "threat_level": "CRITICAL",
  "alerts": ["Known malicious domain..."],
  "scores": { "blacklist": 1.0 }
}
```

---

## Blacklist & Whitelist

### Blacklist (`data/blacklist.txt`)

A plain text file with one domain per line. Lines starting with `#` are comments. The file ships with 35 pre-loaded entries across categories: malware C2 servers, phishing domains, crypto-mining domains, DNS tunneling infrastructure, and DGA-style domains.

You can add entries manually or through the GUI's **Blacklist** button.

### Whitelist (`data/whitelist.txt`)

A plain text file with one domain per line. Whitelisted domains (and all their subdomains) are never flagged, regardless of entropy or TLD. The built-in whitelist inside the analyzer covers major services like Google, Microsoft, Apple, and Cloudflare.

The whitelist file is **gitignored** — it is personal per machine and starts empty on each fresh clone.

You can add entries:

- **In the GUI** — click the Whitelist button, or use the Exact / +Parent buttons on any flagged row
- **In the terminal** — press `w` (exact) or `W` (parent domain) when prompted after an alert
- **Manually** — edit `data/whitelist.txt` directly

---

## Running Tests

```bash
pytest tests/ -v
```

Expected output:

```
tests/test_analyzer.py::TestBlacklist::test_exact_match         PASSED
tests/test_analyzer.py::TestBlacklist::test_subdomain_of_blacklisted PASSED
tests/test_analyzer.py::TestBlacklist::test_safe_domain         PASSED
tests/test_analyzer.py::TestEntropy::test_normal_domain         PASSED
tests/test_analyzer.py::TestEntropy::test_high_entropy_domain   PASSED
tests/test_analyzer.py::TestEntropy::test_dga_domain            PASSED
tests/test_analyzer.py::TestLength::test_normal_length          PASSED
tests/test_analyzer.py::TestLength::test_very_long_domain       PASSED
tests/test_analyzer.py::TestTunneling::test_hex_encoded_subdomain PASSED
tests/test_analyzer.py::TestTunneling::test_normal_subdomain    PASSED
tests/test_analyzer.py::TestTLD::test_suspicious_tld            PASSED
tests/test_analyzer.py::TestTLD::test_normal_tld                PASSED
tests/test_analyzer.py::TestWhitelist::test_whitelisted_domain_not_flagged PASSED
tests/test_analyzer.py::TestStats::test_stats_tracking          PASSED
tests/test_parser.py::...                                        PASSED (x6)

20 passed in <1s
```

---

## Threat Levels

| Level    | Value | Trigger Examples                                               |
| -------- | ----- | -------------------------------------------------------------- |
| SAFE     | 0     | Normal query, known safe domain                                |
| LOW      | 1     | Suspicious TLD (.tk, .ml, .xyz)                                |
| MEDIUM   | 2     | High entropy domain, long domain, high query rate              |
| HIGH     | 3     | Very high entropy (DGA), tunneling pattern, extreme query rate |
| CRITICAL | 4     | Domain found in blacklist                                      |

The final threat level of a query is the **highest** level returned by any single detection check. A whitelisted domain is downgraded to SAFE regardless of other signals — except for CRITICAL (blacklist) hits, which always remain CRITICAL.
