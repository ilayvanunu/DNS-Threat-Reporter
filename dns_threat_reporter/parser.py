"""
DNS Parser - Reads a raw Scapy DNS packet and extracts structured data.

This module is the second stage of the pipeline. It receives a raw packet
from DNSSniffer and converts it into a clean DNSQuery dataclass that the
rest of the system works with.

Key responsibilities:
- Decode the binary qname field to a plain string (e.g. b'google.com.' -> 'google.com')
- Map the numeric qtype to a human-readable record type (e.g. 1 -> 'A', 28 -> 'AAAA')
- Extract the source IP address of the device making the query
- Timestamp the query at parse time

The DNSQuery dataclass is the central data object passed through the
Analyzer and Reporter stages.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List

from scapy.all import DNS, DNSQR, DNSRR, IP

# DNS record type mapping
RECORD_TYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    255: "ANY",
    65: "HTTPS",
}


@dataclass
class DNSQuery:
    """
    Structured representation of a single DNS query.

    This is the central data object that flows through the entire pipeline
    (Sniffer -> Parser -> Analyzer -> Reporter / GUI).

    Attributes:
        domain:      The fully-qualified domain name being queried
                     (e.g. 'sub.example.com').
        query_type:  DNS record type as a string (e.g. 'A', 'AAAA', 'TXT').
        source_ip:   IP address of the host that sent the query.
        timestamp:   When the query was captured (defaults to now).
        raw_packet:  Original Scapy packet, kept for advanced inspection.
                     Excluded from repr to keep logs readable.
    """
    domain: str
    query_type: str
    source_ip: str
    timestamp: datetime = field(default_factory=datetime.now)
    raw_packet: object = field(default=None, repr=False)

    @property
    def subdomain_depth(self) -> int:
        """
        Number of dot-separated labels minus 1.
        Example: 'a.b.c.com' -> 3, 'example.com' -> 1.
        """
        return len(self.domain.split(".")) - 1

    @property
    def domain_length(self) -> int:
        """Total character length of the full domain string."""
        return len(self.domain)


class DNSParser:
    """Parses raw DNS packets into structured DNSQuery objects."""

    @staticmethod
    def parse(packet) -> Optional[DNSQuery]:
        """
        Parse a DNS packet and extract query information.

        Returns:
            DNSQuery object or None if parsing fails.
        """
        try:
            if not (packet.haslayer(DNS) and packet.haslayer(DNSQR)):
                return None

            dns_layer = packet[DNS]
            query = dns_layer[DNSQR]

            # Extract and clean domain name
            raw_name = query.qname
            if isinstance(raw_name, bytes):
                raw_name = raw_name.decode("utf-8", errors="ignore")
            domain = raw_name.rstrip(".")

            # Get query type
            qtype_num = query.qtype
            query_type = RECORD_TYPES.get(qtype_num, f"TYPE{qtype_num}")

            # Get source IP
            source_ip = packet[IP].src if packet.haslayer(IP) else "unknown"

            return DNSQuery(
                domain=domain,
                query_type=query_type,
                source_ip=source_ip,
                timestamp=datetime.now(),
                raw_packet=packet,
            )

        except Exception as e:
            print(f"[Parser] Error parsing DNS packet: {e}")
            return None

    @staticmethod
    def parse_response(packet) -> List[str]:
        """Extract resolved IPs from DNS response."""
        ips = []
        if packet.haslayer(DNS) and packet[DNS].qr == 1:
            dns = packet[DNS]
            for i in range(dns.ancount or 0):           # ancount = number of answers
                try:
                    rr = dns.an[i]
                    if hasattr(rr, "rdata"):
                        ips.append(str(rr.rdata))
                except Exception:
                    pass
        return ips
