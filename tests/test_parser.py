"""Tests for the DNS Parser module."""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from scapy.all import IP, UDP, DNS, DNSQR
from dns_threat_reporter.parser import DNSParser


def make_dns_packet(domain: str, qtype: int = 1, src: str = "192.168.1.100"):
    return (
        IP(src=src, dst="8.8.8.8")
        / UDP(sport=12345, dport=53)
        / DNS(qr=0, qd=DNSQR(qname=domain, qtype=qtype))
    )


class TestDNSParser:
    def test_parse_simple_domain(self):
        pkt = make_dns_packet("example.com")
        result = DNSParser.parse(pkt)
        assert result is not None
        assert result.domain == "example.com"
        assert result.query_type == "A"
        assert result.source_ip == "192.168.1.100"

    def test_parse_subdomain(self):
        pkt = make_dns_packet("sub.domain.example.com")
        result = DNSParser.parse(pkt)
        assert result.domain == "sub.domain.example.com"
        assert result.subdomain_depth == 3

    def test_parse_aaaa_record(self):
        pkt = make_dns_packet("example.com", qtype=28)
        result = DNSParser.parse(pkt)
        assert result.query_type == "AAAA"

    def test_parse_txt_record(self):
        pkt = make_dns_packet("example.com", qtype=16)
        result = DNSParser.parse(pkt)
        assert result.query_type == "TXT"

    def test_domain_length_property(self):
        pkt = make_dns_packet("test.com")
        result = DNSParser.parse(pkt)
        assert result.domain_length == 8

    def test_parse_non_dns_returns_none(self):
        pkt = IP(src="1.1.1.1") / UDP(sport=80, dport=80)
        result = DNSParser.parse(pkt)
        assert result is None
