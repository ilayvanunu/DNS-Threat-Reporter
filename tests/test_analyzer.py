"""Tests for the DNS Analyzer module."""

import pytest
import sys
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))

from dns_threat_reporter.parser import DNSQuery
from dns_threat_reporter.analyzer import DNSAnalyzer, ThreatLevel


@pytest.fixture
def analyzer():
    a = DNSAnalyzer()
    a.blacklist = {"malware-site.com", "evil-server.net", "c2-server.ml"}
    return a


def make_query(domain: str, source_ip: str = "192.168.1.100", query_type: str = "A") -> DNSQuery:
    return DNSQuery(
        domain=domain,
        query_type=query_type,
        source_ip=source_ip,
        timestamp=datetime.now(),
    )


class TestBlacklist:
    def test_exact_match(self, analyzer):
        result = analyzer.analyze(make_query("malware-site.com"))
        assert result.threat_level == ThreatLevel.CRITICAL

    def test_subdomain_of_blacklisted(self, analyzer):
        result = analyzer.analyze(make_query("sub.evil-server.net"))
        assert result.threat_level == ThreatLevel.CRITICAL

    def test_safe_domain(self, analyzer):
        result = analyzer.analyze(make_query("google.com"))
        assert result.threat_level == ThreatLevel.SAFE


class TestEntropy:
    def test_normal_domain(self, analyzer):
        result = analyzer.analyze(make_query("google.com"))
        assert result.threat_level == ThreatLevel.SAFE

    def test_high_entropy_domain(self, analyzer):
        result = analyzer.analyze(make_query("x7k9m2p4q8w1z3.xyz"))
        assert result.is_suspicious

    def test_dga_domain(self, analyzer):
        result = analyzer.analyze(make_query("a1b2c3d4e5f6g7h8i9j0k.com"))
        assert result.is_suspicious


class TestLength:
    def test_normal_length(self, analyzer):
        result = analyzer.analyze(make_query("example.com"))
        assert result.threat_level == ThreatLevel.SAFE

    def test_very_long_domain(self, analyzer):
        long_domain = "a" * 60 + ".hacker.com"
        result = analyzer.analyze(make_query(long_domain))
        assert result.is_suspicious


class TestTunneling:
    def test_hex_encoded_subdomain(self, analyzer):
        result = analyzer.analyze(make_query("4a6f686e20446f6520736563726574.tunnel.evil.com"))
        assert result.is_suspicious
        assert any("Tunneling" in a or "tunneling" in a.lower() for a in result.alerts)

    def test_normal_subdomain(self, analyzer):
        result = analyzer.analyze(make_query("www.example.com"))
        assert result.threat_level == ThreatLevel.SAFE


class TestTLD:
    def test_suspicious_tld(self, analyzer):
        result = analyzer.analyze(make_query("unknown-site.tk"))
        assert result.is_suspicious

    def test_normal_tld(self, analyzer):
        result = analyzer.analyze(make_query("example.com"))
        assert result.threat_level == ThreatLevel.SAFE


class TestWhitelist:
    def test_whitelisted_domain_not_flagged(self, analyzer):
        result = analyzer.analyze(make_query("cdn.googleapis.com"))
        assert result.threat_level == ThreatLevel.SAFE


class TestStats:
    def test_stats_tracking(self, analyzer):
        analyzer.analyze(make_query("google.com"))
        analyzer.analyze(make_query("test.com"))
        stats = analyzer.get_stats()
        assert stats["total_unique_domains"] == 2
