# DNS Threat Reporter

A tool that watches your network's DNS traffic in real time and alerts you when a device tries to connect to a suspicious or dangerous domain — even if you're on a completely different website at the time.

> **Don't know where to start?** Jump straight to [Quick Start](#quick-start).

---

## What Is This, Exactly?

Every time you visit a website, open an app, or your computer checks for updates, it first sends a **DNS query** — essentially asking *"what is the address of this domain?"* before making any connection.

This tool sits on your network and reads those DNS queries. It checks each one against a database of known dangerous domains and several other detection methods. If something looks bad, it tells you — with a notification, a sound alarm, and a color-coded entry in a live web dashboard.

**Example threats it can catch:**
- A device on your network trying to reach a known malware server
- Ransomware "phoning home" to receive instructions
- An attacker using DNS to silently steal data out of your network
- A phishing domain designed to look like `microsoft.com` (e.g. `micros0ft.com`)

---

## Quick Start

### Step 1 — Install Python

**Windows:** Download from [python.org/downloads](https://www.python.org/downloads/). During install, **check the box that says "Add Python to PATH"**.

**macOS:** Open Terminal and run:
```bash
python3 --version
```
If it's not installed, macOS will prompt you to install it automatically.

**Linux:** Python 3 is usually pre-installed. Check with `python3 --version`.

---

### Step 2 — Install the Required Library

Open a terminal (or Command Prompt on Windows) and run:

```bash
pip install scapy
```

**Windows users only:** Scapy needs an extra program to capture network packets. Download and install **Npcap** from [npcap.com](https://npcap.com/#download). Use all default options during installation.

---

### Step 3 — Run the Demo

This mode does **not** require admin rights and works on all platforms. It simulates 14 different DNS queries so you can see the system in action without any real network traffic.

**Windows:**
```
python main.py --demo
```

**macOS / Linux:**
```bash
python3 main.py --demo
```

---

### Step 4 — Open the Dashboard (Recommended)

The dashboard is a web page that opens in your browser and shows threats in real time. It works on all platforms without admin rights in demo mode.

**Windows:**
```
python main.py --gui
```

**macOS / Linux:**
```bash
python3 main.py --gui
```

Your browser will open automatically at `http://127.0.0.1:8765`. Click **Run Demo** to see it in action.

---

## Live Monitoring (Watches Your Real Network)

To monitor actual DNS traffic on your network, the tool needs administrator access because it reads raw network packets.

**Windows** — Open Command Prompt **as Administrator** (right-click → "Run as administrator"), then:
```
python main.py --gui
```

**macOS / Linux:**
```bash
sudo python3 main.py --gui
```

Once running, click **Start Monitoring** in the dashboard.

> **What interface should I pick?**
> Usually leave it on **All**. If you know your network card name (e.g. `en0` on Mac, `Wi-Fi` on Windows), you can select it for slightly better performance.

---

## The Dashboard — What You're Looking At

When you run with `--gui`, a web page opens in your browser. Here is what everything means:

```
┌──────────────────────────────────────────────────────────────────┐
│ 🔑 DNS Threat Reporter  [Start]  [Stop]  Interface: [All ▾]      │
│                         [🚫 Blacklist] [✓ Whitelist] [▶ Demo]   │
├──────────────────────────────────────────────────────────────────┤
│ ● Monitoring...                   Total: 42  Threats: 3  Safe: 39│
├──────────────────────────────────────────────────────────────────┤
│ Time     Level     Domain                  Type  Source IP   ...  │
│ 14:32:01 CRITICAL  malware-site.com        A     192.168.1.5 ...  │  ← red
│ 14:31:55 HIGH      a1b2c3d4e5f6.xyz        A     192.168.1.5 ...  │  ← red
│ 14:31:40 MEDIUM    unknown-site.tk         A     192.168.1.5 ...  │  ← orange
└──────────────────────────────────────────────────────────────────┘
│ Click a row for details. Right-click to whitelist.               │
└──────────────────────────────────────────────────────────────────┘
```

### Buttons

| Button | What it does |
|---|---|
| **Start Monitoring** | Starts watching real DNS traffic (needs admin/sudo) |
| **Stop** | Stops monitoring |
| **Run Demo** | Plays 14 simulated queries — no admin needed, great for testing |
| **🚫 Blacklist** | Opens a list of known bad domains. You can add or remove entries. |
| **✓ Whitelist** | Opens a list of trusted domains that will never trigger alerts. |

### Threat Colors

| Color | Level | What it means |
|---|---|---|
| Orange | MEDIUM | Something looks off — worth looking at |
| Red | HIGH | Likely malicious |
| Bright red | CRITICAL | Confirmed dangerous — matched a known bad domain |

### Clicking on a Row
Click any row to see the full details at the bottom of the page — which device made the query, what record type was requested, and exactly why the system flagged it.

### Whitelisting a Domain
If you see a domain flagged that you know is safe (e.g. your company's internal server), click the row and use the **Exact** or **+Parent** buttons to tell the system to ignore it in the future. This is saved to a file and persists across restarts.

### Notifications
When a **CRITICAL** threat is detected, the system will:
1. Pop up a **browser notification** — visible even if you're on a different website
2. Play a **3-tone alarm sound**

The first time you open the dashboard, your browser will ask for notification permission. Click **Allow**.

---

## Detection Methods — How It Finds Threats

The system uses six independent checks on every DNS query. You don't need to configure anything — they all run automatically.

### 1. Blacklist Check
Compares the domain against 270+ known malicious domains. The list includes malware servers, phishing sites, ransomware payment pages, and fake lookalike domains (e.g. `micros0ft.com`, `paypa1.com`, `rnicrosoft.com`).

If any part of the domain matches (for example, if `sub.malware-site.com` is queried and `malware-site.com` is on the list), it triggers a **CRITICAL** alert.

### 2. Typosquatting Awareness
Attackers register domains that look almost identical to trusted brands — replacing letters with numbers or similar-looking characters:
- `micros0ft.com` (zero instead of 'o')
- `rnicrosoft.com` ('rn' looks like 'm')
- `paypa1.com` (number 1 instead of 'l')
- `g00gle.com` (zeros instead of 'o')

All of these are on the blacklist.

### 3. Domain Length Check
Normal domain names are short and readable. Malware sometimes hides stolen data inside very long domain names and sends it out as a DNS query — a technique called **DNS data exfiltration**. Unusually long domains are flagged as suspicious.

### 4. Entropy / Randomness Check (DGA Detection)
Some malware generates random-looking domain names automatically (e.g. `x7k9m2p4q8w1.xyz`). This is called a **Domain Generation Algorithm (DGA)** and is used to make the malware hard to block. The system measures how "random" a domain looks — the more random, the more suspicious.

### 5. DNS Tunneling Detection
Attackers can use DNS to send data in and out of a network covertly, by hiding information inside the subdomain part of a query. This is called **DNS tunneling**. The system looks for telltale patterns like long strings of hex or base64 characters in subdomains.

### 6. Suspicious TLD Check
Some top-level domains like `.tk`, `.ml`, `.ga`, `.xyz` are free to register and are heavily used by attackers. Queries to these TLDs receive a LOW suspicion flag.

---

## Project Structure

```
DNS_Threat_Reporter/
│
├── main.py                    ← Start here — runs the whole system
│
├── dns_threat_reporter/
│   ├── sniffer.py             ← Captures packets from the network
│   ├── parser.py              ← Reads each packet and extracts the domain name
│   ├── analyzer.py            ← Runs the 6 detection checks
│   ├── reporter.py            ← Displays results and writes log files
│   └── gui.py                 ← The web dashboard
│
├── data/
│   ├── blacklist.txt          ← 270+ known bad domains (you can add more)
│   └── whitelist.txt          ← Your trusted domains (not tracked in git)
│
├── logs/                      ← Created automatically when the system runs
│   ├── alerts_*.log           ← Only HIGH and CRITICAL threats
│   ├── dns_queries_*.log      ← Every query, one per line
│   └── dns_data_*.jsonl       ← Full data in machine-readable format
│
└── tests/                     ← Automated tests for the detection engine
```

---

## Log Files

Every time you run the system, three log files are created inside the `logs/` folder. The timestamp in the filename means old sessions are never overwritten.

### `alerts_*.log` — The important one
Only contains HIGH and CRITICAL threats. This is the file to check after a monitoring session.

```
============================================================
[2024-01-15 14:32:01] ALERT - CRITICAL
Domain: malware-site.com
Type:   A
Source: 192.168.1.5
  -> Known malicious domain found in blacklist!
============================================================
```

### `dns_queries_*.log` — Full audit trail
Every single query, one line each. Useful for reviewing everything that happened.

```
[2024-01-15 14:32:01] [CRITICAL] malware-site.com     | A | 192.168.1.5
[2024-01-15 14:32:02] [SAFE    ] google.com            | A | 192.168.1.5
```

### `dns_data_*.jsonl` — Machine-readable data
Same information in JSON format. Useful for importing into other tools or writing your own analysis scripts.

---

## Managing the Blacklist and Whitelist

### Adding a Domain to the Blacklist
- **Via dashboard:** Click **🚫 Blacklist** → type the domain → click **+ Add**
- **Manually:** Open `data/blacklist.txt` and add one domain per line

### Adding a Domain to the Whitelist (to stop false alerts)
- **Via dashboard:** Click **✓ Whitelist** → type the domain → click **+ Add**
- **From a flagged row:** Click the row → use **Exact** (just this domain) or **+Parent** (this domain and all its subdomains)
- **In terminal mode:** Press `w` or `W` when prompted after an alert
- **Manually:** Open `data/whitelist.txt` and add one domain per line

> The whitelist file is not shared when you push to git — it stays local to your machine.

---

## Command Line Options (Advanced)

All options work on Windows (`python main.py`) and macOS/Linux (`python3 main.py`).

```
--gui                  Open the web dashboard in your browser
--demo                 Run with 14 simulated queries (no admin needed)
--pcap <file>          Analyze a saved .pcap packet capture file
-i / --interface <if>  Monitor a specific network interface (e.g. en0, eth0)
-v / --verbose         Show all queries, including safe ones
-b / --blacklist <f>   Use a different blacklist file
-l / --log-dir <dir>   Save logs to a different folder (default: ./logs)
```

---

## Running the Tests

```bash
pip install pytest
pytest tests/ -v
```

All 20 tests should pass in under a second.

---

## Troubleshooting

**"Permission denied" / "Operation not permitted"**
The sniffer needs admin access to read raw packets.
- Windows: Run Command Prompt as Administrator
- macOS/Linux: Add `sudo` before the command

**"No module named scapy"**
Run `pip install scapy` (Windows) or `pip3 install scapy` (macOS/Linux).

**Windows: "Npcap is not installed"**
Download and install Npcap from [npcap.com](https://npcap.com/#download), then try again.

**The browser doesn't open automatically**
Manually navigate to `http://127.0.0.1:8765` in any browser.

**"Address already in use"**
A previous instance of the server is still running. Close it (Ctrl+C in the terminal where it's running) and try again. On Windows you can also restart the terminal.

**Notifications don't appear**
Make sure you clicked **Allow** when the browser asked for notification permission. You can re-enable it in your browser's site settings for `localhost`.

---

## Requirements

- Python 3.9 or higher
- `scapy` library (`pip install scapy`)
- **Windows only:** [Npcap](https://npcap.com/#download) for live packet capture
- For running tests: `pytest` (`pip install pytest`)
