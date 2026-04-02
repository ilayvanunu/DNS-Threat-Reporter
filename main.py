#!/usr/bin/env python3
"""
DNS Threat Reporter - Main Entry Point
A defensive tool for DNS traffic monitoring and threat detection.

Usage:
    sudo python3 main.py                    # Sniff on all interfaces
    sudo python3 main.py -i en0             # Sniff on specific interface
    sudo python3 main.py -v                 # Verbose mode
    sudo python3 main.py --demo             # Run demo with simulated traffic
    sudo python3 main.py --pcap file.pcap   # Analyze a PCAP file
"""

import argparse
import signal
import sys
import os
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from dns_threat_reporter.sniffer import DNSSniffer
from dns_threat_reporter.parser import DNSParser
from dns_threat_reporter.analyzer import DNSAnalyzer
from dns_threat_reporter.reporter import DNSReporter


class DNSThreatReporter:
    """Main application - orchestrates all components."""

    def __init__(self, interface=None, blacklist_path=None, verbose=False, log_dir="logs"):
        self.sniffer = DNSSniffer(interface=interface)
        self.parser = DNSParser()
        self.analyzer = DNSAnalyzer(
            blacklist_path=blacklist_path or str(Path(__file__).parent / "data" / "blacklist.txt"),
            whitelist_path=str(Path(__file__).parent / "data" / "whitelist.txt"),
        )
        self.reporter = DNSReporter(log_dir=log_dir, verbose=verbose, analyzer=self.analyzer)

    def handle_packet(self, packet):
        """Pipeline: Sniffer -> Parser -> Analyzer -> Reporter"""
        # Only process DNS queries
        if not DNSSniffer.is_dns_query(packet):
            return

        # Parse the packet
        query = self.parser.parse(packet)
        if query is None:
            return

        # Analyze for threats
        result = self.analyzer.analyze(query)

        # Report findings
        self.reporter.report(result)

    def start_live(self):
        """Start live DNS monitoring."""
        self.reporter.print_banner()

        # Handle Ctrl+C gracefully
        def signal_handler(_sig, _frame):
            print("\n\nStopping DNS Threat Reporter...")
            self.reporter.print_stats()
            self.reporter.close()
            self.sniffer.stop()
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)

        print("[*] Starting DNS traffic monitoring... (Ctrl+C to stop)\n")
        self.sniffer.start(self.handle_packet)

    def analyze_pcap(self, pcap_path: str):
        """Analyze a PCAP file offline."""
        from scapy.all import rdpcap

        self.reporter.print_banner()
        print(f"[*] Analyzing PCAP file: {pcap_path}\n")

        packets = rdpcap(pcap_path)
        for packet in packets:
            self.handle_packet(packet)

        self.reporter.print_stats()
        self.reporter.close()

    def run_demo(self):
        """Run a demo with simulated DNS traffic for testing."""
        from scapy.all import IP, UDP, DNS, DNSQR

        self.reporter.print_banner()
        print("[*] Demo mode - running simulated traffic...\n")

        # Simulated test cases
        test_domains = [
            # Normal traffic
            ("ynet.co.il",       "A",    "Normal traffic"),
            ("www.google.com",   "A",    "Normal traffic"),
            ("mail.walla.co.il", "AAAA", "Normal traffic"),

            # Blacklisted domain
            ("malware-site.com",     "A", "Known malicious domain"),
            ("sub.evil-server.net",  "A", "Subdomain of blacklisted domain"),

            # Suspicious long domain (data exfiltration)
            ("password1234.hacker-server.com",                          "A",   "Long domain - possible data exfiltration"),
            ("aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Q.data-steal.com",    "TXT", "DNS Tunneling"),

            # DGA-style domain (high entropy)
            ("x7k9m2p4q8w1.xyz",        "A", "Random-looking domain - possible DGA"),
            ("a1b2c3d4e5f6g7h8i9j0.tk", "A", "Random domain with suspicious TLD"),

            # DNS Tunneling
            ("4a6f686e20446f6520736563726574.tunnel.evil.com", "TXT", "Hex-encoded data in subdomain"),

            # Suspicious TLD
            ("some-website.tk",   "A", "Suspicious TLD"),
            ("another-site.ml",   "A", "Suspicious TLD"),

            # More normal traffic
            ("cdn.github.com",      "A", "Normal traffic"),
            ("api.microsoft.com",   "A", "Normal traffic"),
        ]

        for domain, qtype, description in test_domains:
            print(f"{'-'*50}")
            print(f"  Scenario: {description}")
            print(f"  Domain:   {domain}")
            print(f"{'-'*50}")

            # Build a simulated DNS packet
            qtype_map = {"A": 1, "AAAA": 28, "TXT": 16, "MX": 15}
            pkt = (
                IP(src="192.168.1.100", dst="8.8.8.8")
                / UDP(sport=12345, dport=53)
                / DNS(qr=0, qd=DNSQR(qname=domain, qtype=qtype_map.get(qtype, 1)))
            )
            self.handle_packet(pkt)

        self.reporter.print_stats()
        self.reporter.close()
        print(f"\nDemo complete. Check the log directory: {self.reporter.log_dir}")


def main():
    parser = argparse.ArgumentParser(
        description="DNS Threat Reporter - Defensive tool for DNS traffic monitoring",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 main.py                  # Live monitoring on all interfaces
  sudo python3 main.py -i en0           # Monitor a specific interface
  sudo python3 main.py -v               # Verbose mode
  sudo python3 main.py --demo           # Run demo with simulated traffic
  sudo python3 main.py --pcap file.pcap # Analyze a PCAP file
        """,
    )
    parser.add_argument("-i", "--interface", help="Network interface to monitor (e.g., en0, eth0)")
    parser.add_argument("-b", "--blacklist", help="Path to a custom blacklist file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show details for all queries, including safe ones")
    parser.add_argument("-l", "--log-dir", default="logs", help="Log output directory (default: logs)")
    parser.add_argument("--demo", action="store_true", help="Run demo with simulated traffic")
    parser.add_argument("--pcap", help="Analyze an existing PCAP file")

    args = parser.parse_args()

    app = DNSThreatReporter(
        interface=args.interface,
        blacklist_path=args.blacklist,
        verbose=args.verbose,
        log_dir=args.log_dir,
    )

    if args.demo:
        app.run_demo()
    elif args.pcap:
        if not Path(args.pcap).exists():
            print(f"Error: PCAP file not found: {args.pcap}")
            sys.exit(1)
        app.analyze_pcap(args.pcap)
    else:
        # Live sniffing requires root privileges
        if os.geteuid() != 0:
            print("Error: Live monitoring requires root privileges. Run with sudo:")
            print(f"   sudo python3 {sys.argv[0]}")
            sys.exit(1)
        app.start_live()


if __name__ == "__main__":
    main()
