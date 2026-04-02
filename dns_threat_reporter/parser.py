"""
DNS Parser - Reads DNS packet body and extracts the queried domain name.
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
    """Parsed DNS query data."""
    domain: str
    query_type: str
    source_ip: str
    timestamp: datetime = field(default_factory=datetime.now)
    raw_packet: object = field(default=None, repr=False)

    @property
    def subdomain_depth(self) -> int:
        """Number of subdomain levels (e.g., a.b.c.com = 3)."""
        return len(self.domain.split(".")) - 1

    @property
    def domain_length(self) -> int:
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
