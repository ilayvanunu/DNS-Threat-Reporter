"""
DNS Analyzer - Multi-layered threat detection engine.

This module is the third stage of the pipeline. It receives a DNSQuery
and runs it through six independent detection checks, each producing a
ThreatLevel and an optional human-readable alert message.

Detection methods
-----------------
1. Blacklist matching
   Compares the domain (and every parent domain) against a list of known
   malicious domains. A match immediately sets the threat level to CRITICAL.

2. Domain length analysis
   Unusually long domain names can indicate DNS-based data exfiltration,
   where a client encodes stolen data in the subdomain labels of a query
   (e.g. <base64-payload>.attacker.com).

3. Shannon entropy analysis (DGA detection)
   Legitimate domain names are human-readable and have low entropy.
   Malware often uses Domain Generation Algorithms (DGAs) to produce
   random-looking domains (e.g. 'x7k9m2p4q8w1.xyz') as C2 rendezvous
   points. High Shannon entropy is a strong indicator of DGA activity.

4. Rate anomaly detection
   Tracks queries per source IP in a 60-second sliding window.
   A very high query rate from a single host can indicate C2 beaconing
   (malware periodically phoning home) or automated scanning.

5. DNS tunneling detection
   Looks for hex- or base64-encoded data packed into subdomain labels.
   DNS tunneling tools (e.g. dnscat2, iodine) use this to exfiltrate data
   or establish covert command channels over DNS port 53, which is rarely
   blocked by firewalls.

6. Suspicious TLD detection
   Certain top-level domains (e.g. .tk, .ml, .ga, .xyz) are disproportionately
   used by attackers because they are free or very cheap to register.

After all checks, the final threat level is the highest level produced
by any single check. If the domain is on the whitelist the result is
downgraded to SAFE (except for CRITICAL blacklist hits).
"""

from __future__ import annotations

import math
import time
import re
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional, Dict, List, Tuple, Set

from .parser import DNSQuery


class ThreatLevel(Enum):
    """Threat severity levels."""
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class AnalysisResult:
    """Result of analyzing a DNS query."""
    query: DNSQuery
    threat_level: ThreatLevel
    alerts: list[str] = field(default_factory=list)
    scores: dict = field(default_factory=dict)

    @property
    def is_suspicious(self) -> bool:
        return self.threat_level != ThreatLevel.SAFE


class DNSAnalyzer:
    """
    Multi-layered DNS threat detection engine.

    Detection methods:
    1. Blacklist matching - known malicious domains
    2. Domain length analysis - unusually long domains (possible data exfiltration)
    3. Entropy analysis - high randomness (DGA - Domain Generation Algorithm)
    4. Rate analysis - high query frequency (possible C2 beaconing)
    5. DNS tunneling detection - encoded data in subdomains
    6. Suspicious TLD detection - uncommon/risky TLDs
    """

    # Thresholds
    MAX_SAFE_DOMAIN_LENGTH = 50
    MAX_SAFE_SUBDOMAIN_LENGTH = 30
    HIGH_ENTROPY_THRESHOLD = 3.8
    VERY_HIGH_ENTROPY_THRESHOLD = 4.2
    MAX_QUERIES_PER_MINUTE = 60
    MAX_NUMERIC_RATIO = 0.5
    MIN_TUNNELING_SUBDOMAIN_LENGTH = 25

    # Suspicious TLDs often used by attackers
    SUSPICIOUS_TLDS = {
        "tk", "ml", "ga", "cf", "gq",  # Free TLDs often abused
        "xyz", "top", "club", "work", "buzz",
        "pw", "cc", "su", "bit", "onion",
    }

    # Known safe domains (whitelist) - reduces false positives
    SAFE_DOMAINS = {
        "google.com", "googleapis.com", "gstatic.com",
        "microsoft.com", "windows.com", "office.com",
        "apple.com", "icloud.com", "akamai.net",
        "cloudflare.com", "amazonaws.com", "azure.com",
        "facebook.com", "twitter.com", "github.com",
        "ynet.co.il", "walla.co.il", "mako.co.il",
    }

    def __init__(self, blacklist_path: Optional[str] = None, whitelist_path: Optional[str] = None):
        self.blacklist: set[str] = set()
        self.user_whitelist: set[str] = set()
        self._blacklist_path: Optional[str] = blacklist_path
        self._whitelist_path: Optional[str] = whitelist_path
        self._query_history: dict[str, list[float]] = defaultdict(list)
        self._domain_counter: dict[str, int] = defaultdict(int)

        if blacklist_path:
            self.load_blacklist(blacklist_path)
        if whitelist_path:
            self.load_whitelist(whitelist_path)

    def load_blacklist(self, filepath: str):
        """Load malicious domains from a blacklist file."""
        path = Path(filepath)
        if not path.exists():
            print(f"[Analyzer] Warning: blacklist file not found: {filepath}")
            return

        with open(path, "r") as f:
            for line in f:
                line = line.strip().lower()
                if line and not line.startswith("#"):
                    self.blacklist.add(line)

        print(f"[Analyzer] Loaded {len(self.blacklist)} domains into blacklist")

    def load_whitelist(self, filepath: str):
        """Load user-whitelisted domains from file."""
        path = Path(filepath)
        if not path.exists():
            return  # whitelist starts empty, that's fine

        with open(path, "r") as f:
            for line in f:
                line = line.strip().lower()
                if line and not line.startswith("#"):
                    self.user_whitelist.add(line)

        if self.user_whitelist:
            print(f"[Analyzer] Loaded {len(self.user_whitelist)} user-whitelisted domains")

    def add_to_whitelist(self, domain: str):
        """Add a domain to the user whitelist and persist it to disk."""
        domain = domain.lower().strip()
        if domain in self.user_whitelist:
            return

        self.user_whitelist.add(domain)

        # Persist to file
        if self._whitelist_path:
            with open(self._whitelist_path, "a") as f:
                f.write(f"{domain}\n")
            print(f"[Analyzer] '{domain}' added to whitelist and saved.")

    def add_to_blacklist(self, domain: str):
        """Add a domain to the blacklist and persist it to disk."""
        domain = domain.lower().strip()
        if domain in self.blacklist:
            return

        self.blacklist.add(domain)

        if self._blacklist_path:
            with open(self._blacklist_path, "a") as f:
                f.write(f"{domain}\n")
            print(f"[Analyzer] '{domain}' added to blacklist and saved.")

    def remove_from_whitelist(self, domain: str):
        """Remove a domain from the user whitelist and rewrite the file."""
        domain = domain.lower().strip()
        self.user_whitelist.discard(domain)

        if self._whitelist_path:
            path = Path(self._whitelist_path)
            if path.exists():
                lines = path.read_text().splitlines()
                lines = [l for l in lines if l.strip().lower() != domain and l.strip()]
                path.write_text("\n".join(lines) + ("\n" if lines else ""))

    def remove_from_blacklist(self, domain: str):
        """Remove a domain from the blacklist and rewrite the file."""
        domain = domain.lower().strip()
        self.blacklist.discard(domain)

        if self._blacklist_path:
            path = Path(self._blacklist_path)
            if path.exists():
                lines = path.read_text().splitlines()
                lines = [l for l in lines if l.strip().lower() != domain and l.strip()]
                path.write_text("\n".join(lines) + ("\n" if lines else ""))

    def analyze(self, query: DNSQuery) -> AnalysisResult:
        """
        Run all detection methods on a DNS query.

        Returns:
            AnalysisResult with threat level and detailed alerts.
        """
        alerts = []
        scores = {}
        max_threat = ThreatLevel.SAFE

        # Compute once, reuse across all checks
        domain_lower = query.domain.lower()
        parts = domain_lower.split(".")

        # Track query for rate analysis
        self._query_history[query.source_ip].append(time.time())
        self._domain_counter[query.domain] += 1

        # === 1. Blacklist Check ===
        blacklist_result = self._check_blacklist(domain_lower, parts)
        if blacklist_result:
            alerts.append(f"Known malicious domain found in blacklist! ({blacklist_result})")
            scores["blacklist"] = 1.0
            max_threat = ThreatLevel.CRITICAL
        else:
            scores["blacklist"] = 0.0

        # === 2. Domain Length Check ===
        length_threat, length_alert = self._check_length(domain_lower, parts)
        if length_alert:
            alerts.append(length_alert)
            max_threat = self._max_threat(max_threat, length_threat)
        scores["length"] = len(domain_lower) / 100

        # === 3. Entropy Analysis (DGA Detection) ===
        entropy_threat, entropy_alert, entropy_val = self._check_entropy(parts)
        if entropy_alert:
            alerts.append(entropy_alert)
            max_threat = self._max_threat(max_threat, entropy_threat)
        scores["entropy"] = entropy_val

        # === 4. Rate Analysis ===
        rate_threat, rate_alert = self._check_rate(query.source_ip)
        if rate_alert:
            alerts.append(rate_alert)
            max_threat = self._max_threat(max_threat, rate_threat)

        # === 5. DNS Tunneling Detection ===
        tunnel_threat, tunnel_alert = self._check_tunneling(parts)
        if tunnel_alert:
            alerts.append(tunnel_alert)
            max_threat = self._max_threat(max_threat, tunnel_threat)

        # === 6. Suspicious TLD ===
        tld_threat, tld_alert = self._check_tld(parts)
        if tld_alert:
            alerts.append(tld_alert)
            max_threat = self._max_threat(max_threat, tld_threat)

        # Whitelist check - downgrade if domain is known safe
        if self._is_whitelisted(domain_lower) and max_threat != ThreatLevel.CRITICAL:
            max_threat = ThreatLevel.SAFE
            alerts.clear()

        return AnalysisResult(
            query=query,
            threat_level=max_threat,
            alerts=alerts,
            scores=scores,
        )

    def _check_blacklist(self, domain_lower: str, parts: List[str]) -> Optional[str]:
        """Check if domain or any parent domain is in the blacklist."""
        # Exact match
        if domain_lower in self.blacklist:
            return domain_lower

        # Check parent domains (e.g., sub.malware.com -> malware.com)
        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            if parent in self.blacklist:
                return parent

        return None

    def _check_length(self, domain_lower: str, parts: List[str]) -> Tuple[ThreatLevel, Optional[str]]:
        """Detect unusually long domains (possible data exfiltration)."""
        domain_len = len(domain_lower)

        if domain_len > self.MAX_SAFE_DOMAIN_LENGTH * 2:
            return ThreatLevel.HIGH, f"Suspicious Pattern (Length): very long domain ({domain_len} chars) - possible DNS data exfiltration"

        if domain_len > self.MAX_SAFE_DOMAIN_LENGTH:
            return ThreatLevel.MEDIUM, f"Suspicious Pattern (Length): long domain ({domain_len} chars)"

        # Check individual subdomain labels
        for label in parts:
            if len(label) > self.MAX_SAFE_SUBDOMAIN_LENGTH:
                return ThreatLevel.MEDIUM, f"Suspicious Pattern (Length): long subdomain label ({label[:20]}...) - possible encoded data"

        return ThreatLevel.SAFE, None

    def _check_entropy(self, parts: List[str]) -> Tuple[ThreatLevel, Optional[str], float]:
        """
        Calculate Shannon entropy to detect randomly generated domains (DGA).
        Higher entropy = more random = more suspicious.
        """
        # Calculate entropy on the domain name without TLD
        name_part = ".".join(parts[:-1]) if len(parts) >= 2 else ".".join(parts)

        entropy = self._shannon_entropy(name_part)

        if entropy > self.VERY_HIGH_ENTROPY_THRESHOLD:
            return (
                ThreatLevel.HIGH,
                f"Suspicious Pattern (Entropy): very high entropy ({entropy:.2f}) - possible DGA (Domain Generation Algorithm)",
                entropy,
            )
        elif entropy > self.HIGH_ENTROPY_THRESHOLD:
            return (
                ThreatLevel.MEDIUM,
                f"Suspicious Pattern (Entropy): high entropy ({entropy:.2f}) - randomly looking domain name",
                entropy,
            )

        return ThreatLevel.SAFE, None, entropy

    def _check_rate(self, source_ip: str) -> Tuple[ThreatLevel, Optional[str]]:
        """Detect high query frequency from a single source (possible beaconing)."""
        now = time.time()
        window = 60  # 1-minute sliding window

        # Remove entries outside the window
        self._query_history[source_ip] = [
            t for t in self._query_history[source_ip] if now - t < window
        ]

        count = len(self._query_history[source_ip])

        if count > self.MAX_QUERIES_PER_MINUTE * 3:
            return ThreatLevel.HIGH, f"Suspicious Pattern (Rate): abnormal query rate: {count} req/min from {source_ip} - possible C2 beaconing"
        elif count > self.MAX_QUERIES_PER_MINUTE:
            return ThreatLevel.MEDIUM, f"Suspicious Pattern (Rate): high query rate: {count} req/min from {source_ip}"

        return ThreatLevel.SAFE, None

    def _check_tunneling(self, parts: List[str]) -> Tuple[ThreatLevel, Optional[str]]:
        """
        Detect DNS tunneling patterns:
        - Very long subdomains with encoded data
        - High ratio of numeric/hex characters
        - Base64-like patterns
        """
        if len(parts) < 3:
            return ThreatLevel.SAFE, None

        # Check subdomain part (everything except the last 2 labels)
        subdomain = ".".join(parts[:-2])

        if len(subdomain) < self.MIN_TUNNELING_SUBDOMAIN_LENGTH:
            return ThreatLevel.SAFE, None

        # Check for hex-encoded data
        hex_pattern = re.compile(r"[0-9a-f]{16,}", re.IGNORECASE)
        if hex_pattern.search(subdomain):
            return ThreatLevel.HIGH, "Suspicious Pattern (Tunneling): hex-encoded data detected in subdomain"

        # Check for base64-like patterns
        base64_pattern = re.compile(r"[A-Za-z0-9+/=]{20,}")
        if base64_pattern.search(subdomain.replace(".", "")):
            return ThreatLevel.HIGH, "Suspicious Pattern (Tunneling): Base64-like pattern detected in subdomain"

        # High numeric ratio
        digits = sum(1 for c in subdomain if c.isdigit())
        if len(subdomain) > 0 and digits / len(subdomain) > self.MAX_NUMERIC_RATIO:
            return ThreatLevel.MEDIUM, "Suspicious Pattern (Tunneling): high numeric ratio in subdomain - possible data encoding"

        return ThreatLevel.SAFE, None

    def _check_tld(self, parts: List[str]) -> Tuple[ThreatLevel, Optional[str]]:
        """Check for suspicious top-level domains."""
        if not parts:
            return ThreatLevel.SAFE, None

        tld = parts[-1]  # already lowercased by analyze()
        if tld in self.SUSPICIOUS_TLDS:
            return ThreatLevel.LOW, f"Suspicious Pattern (TLD): .{tld} is a high-risk top-level domain"

        return ThreatLevel.SAFE, None

    def _is_whitelisted(self, domain_lower: str) -> bool:
        """Check if domain belongs to a known safe service or user whitelist."""
        # Check built-in safe domains
        for safe in self.SAFE_DOMAINS:
            if domain_lower == safe or domain_lower.endswith("." + safe):
                return True

        # Check user whitelist (exact and parent match)
        for safe in self.user_whitelist:
            if domain_lower == safe or domain_lower.endswith("." + safe):
                return True

        return False

    def get_stats(self) -> dict:
        """Return current analysis statistics."""
        return {
            "total_unique_domains": len(self._domain_counter),
            "blacklist_size": len(self.blacklist),
            "top_queried": sorted(
                self._domain_counter.items(), key=lambda x: x[1], reverse=True
            )[:10],
        }

    @staticmethod
    def _shannon_entropy(text: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0.0
        freq = defaultdict(int)
        for char in text:
            freq[char] += 1
        length = len(text)
        return -sum(
            (count / length) * math.log2(count / length) for count in freq.values()
        )

    @staticmethod
    def _max_threat(current: ThreatLevel, new: ThreatLevel) -> ThreatLevel:
        """Return the higher of two threat levels."""
        order = [ThreatLevel.SAFE, ThreatLevel.LOW, ThreatLevel.MEDIUM, ThreatLevel.HIGH, ThreatLevel.CRITICAL]
        return max(current, new, key=lambda t: order.index(t))
