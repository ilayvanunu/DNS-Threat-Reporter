"""
DNS Reporter - Prints findings to the screen and writes to a log file.
Provides colored console output and structured log file writing.
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import TextIO, Optional

from .analyzer import AnalysisResult, ThreatLevel


class Colors:
    """ANSI color codes for terminal output."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BG_RED = "\033[41m"
    BG_YELLOW = "\033[43m"
    GRAY = "\033[90m"


THREAT_COLORS = {
    ThreatLevel.SAFE: Colors.GREEN,
    ThreatLevel.LOW: Colors.CYAN,
    ThreatLevel.MEDIUM: Colors.YELLOW,
    ThreatLevel.HIGH: Colors.RED,
    ThreatLevel.CRITICAL: Colors.BG_RED + Colors.WHITE,
}

THREAT_LABELS = {
    ThreatLevel.SAFE: "Safe",
    ThreatLevel.LOW: "Low Suspicion",
    ThreatLevel.MEDIUM: "Medium Suspicion",
    ThreatLevel.HIGH: "High Suspicion",
    ThreatLevel.CRITICAL: "Critical Threat",
}


class DNSReporter:
    """Handles output display and log file management."""

    def __init__(self, log_dir: str = "logs", verbose: bool = False, analyzer=None):
        self.verbose = verbose
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._analyzer = analyzer  # reference to analyzer for whitelisting

        # Create log files with timestamp in name
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self._alert_log = self._open_log(f"alerts_{timestamp}.log")
        self._full_log = self._open_log(f"dns_queries_{timestamp}.log")
        self._json_log = self._open_log(f"dns_data_{timestamp}.jsonl")

        self._stats = {
            "total_queries": 0,
            "safe": 0,
            "suspicious": 0,
            "critical": 0,
        }

    def _open_log(self, filename: str) -> TextIO:
        filepath = self.log_dir / filename
        return open(filepath, "a", encoding="utf-8")

    def report(self, result: AnalysisResult):
        """Process and output an analysis result."""
        self._stats["total_queries"] += 1

        if result.threat_level == ThreatLevel.SAFE:
            self._stats["safe"] += 1
        elif result.threat_level == ThreatLevel.CRITICAL:
            self._stats["critical"] += 1
        else:
            self._stats["suspicious"] += 1

        # Console output
        self._print_to_console(result)

        # Log to files - always write full audit trail
        self._write_to_log(result)
        self._write_to_json(result)

        # Only write to alert log for HIGH and CRITICAL
        if result.threat_level in (ThreatLevel.HIGH, ThreatLevel.CRITICAL):
            self._write_alert(result)

    def _print_to_console(self, result: AnalysisResult):
        """Print colored output to the terminal."""
        query = result.query
        color = THREAT_COLORS[result.threat_level]
        label = THREAT_LABELS[result.threat_level]
        timestamp = query.timestamp.strftime("%H:%M:%S")

        # SAFE and LOW - silent unless verbose
        if result.threat_level in (ThreatLevel.SAFE, ThreatLevel.LOW) and not self.verbose:
            return

        # MEDIUM - compact single line
        if result.threat_level == ThreatLevel.MEDIUM and not self.verbose:
            print(
                f"{Colors.YELLOW}[{timestamp}] "
                f"[{label}] "
                f"{query.domain} "
                f"| {result.alerts[0] if result.alerts else ''}"
                f"{Colors.RESET}"
            )
            self._prompt_whitelist(query.domain)
            return

        # HIGH and CRITICAL - full alert box
        print(f"\n{'='*70}")
        print(
            f"{color}{Colors.BOLD}"
            f"  Alert: [{result.threat_level.value}] - {label}"
            f"{Colors.RESET}"
        )
        print(f"{'='*70}")
        print(f"  Time:      {timestamp}")
        print(f"  Domain:    {color}{query.domain}{Colors.RESET}")
        print(f"  Type:      {query.query_type}")
        print(f"  Source:    {query.source_ip}")

        if result.alerts:
            print(f"  {'─'*50}")
            for alert in result.alerts:
                print(f"  {color}{alert}{Colors.RESET}")

        if result.scores and self.verbose:
            print(f"  {'─'*50}")
            print(f"  Scores: {result.scores}")

        print(f"{'='*70}")
        self._prompt_whitelist(query.domain)
        print()

    def _prompt_whitelist(self, domain: str):
        """Ask the user if they want to whitelist this domain."""
        if not self._analyzer:
            return

        # Extract parent domain (e.g. sub.company.com -> company.com)
        parts = domain.split(".")
        parent = ".".join(parts[-2:]) if len(parts) >= 2 else domain

        print(
            f"{Colors.GRAY}  >> Know this domain? "
            f"[w] whitelist '{domain}'  "
            f"[W] whitelist '*.{parent}'  "
            f"[Enter] ignore{Colors.RESET}"
        )

        try:
            choice = input("  >> ").strip()
            if choice == "w":
                self._analyzer.add_to_whitelist(domain)
                print(f"{Colors.GREEN}  >> '{domain}' added to whitelist.{Colors.RESET}")
            elif choice == "W":
                self._analyzer.add_to_whitelist(parent)
                print(f"{Colors.GREEN}  >> '*.{parent}' added to whitelist (covers all subdomains).{Colors.RESET}")
        except (EOFError, KeyboardInterrupt):
            pass  # non-interactive mode (demo/pcap), skip silently

    def _write_to_log(self, result: AnalysisResult):
        """Write to the full query log."""
        query = result.query
        timestamp = query.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        line = (
            f"[{timestamp}] [{result.threat_level.value:8s}] "
            f"{query.domain:50s} | {query.query_type:5s} | {query.source_ip}"
        )
        if result.alerts:
            line += f" | ALERTS: {'; '.join(result.alerts)}"
        self._full_log.write(line + "\n")
        self._full_log.flush()

    def _write_alert(self, result: AnalysisResult):
        """Write suspicious findings to the alert log."""
        query = result.query
        timestamp = query.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        self._alert_log.write(f"\n{'='*60}\n")
        self._alert_log.write(f"[{timestamp}] ALERT - {result.threat_level.value}\n")
        self._alert_log.write(f"Domain: {query.domain}\n")
        self._alert_log.write(f"Type:   {query.query_type}\n")
        self._alert_log.write(f"Source: {query.source_ip}\n")
        for alert in result.alerts:
            self._alert_log.write(f"  -> {alert}\n")
        self._alert_log.write(f"{'='*60}\n")
        self._alert_log.flush()

    def _write_to_json(self, result: AnalysisResult):
        """Write structured JSON log (one line per entry)."""
        entry = {
            "timestamp": result.query.timestamp.isoformat(),
            "domain": result.query.domain,
            "query_type": result.query.query_type,
            "source_ip": result.query.source_ip,
            "threat_level": result.threat_level.value,
            "alerts": result.alerts,
            "scores": result.scores,
        }
        self._json_log.write(json.dumps(entry) + "\n")
        self._json_log.flush()

    def print_banner(self):
        """Print the application banner."""
        banner = f"""
{Colors.CYAN}{Colors.BOLD}
+--------------------------------------------------------------+
|                                                              |
|              DNS Threat Reporter v1.0                        |
|                                                              |
|     Defensive tool for DNS traffic monitoring                |
|                                                              |
+--------------------------------------------------------------+
{Colors.RESET}
{Colors.YELLOW}[*] Detection engine: Blacklist | Entropy | Rate | DNS Tunneling{Colors.RESET}
{Colors.YELLOW}[*] Logs saved to: {self.log_dir}{Colors.RESET}
"""
        print(banner)

    def print_stats(self):
        """Print summary statistics."""
        total = self._stats["total_queries"]
        if total == 0:
            return

        detection_rate = (self._stats["suspicious"] + self._stats["critical"]) / total * 100
        print(f"\n{Colors.CYAN}{Colors.BOLD}--- Session Summary ---{Colors.RESET}")
        print(f"  Total queries:    {total}")
        print(f"  {Colors.GREEN}Safe:             {self._stats['safe']}{Colors.RESET}")
        print(f"  {Colors.YELLOW}Suspicious:       {self._stats['suspicious']}{Colors.RESET}")
        print(f"  {Colors.RED}Critical:         {self._stats['critical']}{Colors.RESET}")
        print(f"  Detection rate:   {detection_rate:.1f}%")

    def close(self):
        """Close all log files."""
        for log in [self._alert_log, self._full_log, self._json_log]:
            try:
                log.close()
            except Exception:
                pass
