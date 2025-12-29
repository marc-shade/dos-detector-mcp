"""Tests for traffic analysis functionality."""

import json
from pathlib import Path

import pytest

import sys
sys.path.insert(0, str(__file__).replace("/tests/test_traffic_analysis.py", "/src"))

from dos_detector_mcp.server import (
    parse_log_line,
    analyze_access_log,
    analyze_ip_rates,
    _rate_limiter,
)


class TestParseLogLine:
    """Tests for log line parsing."""

    def test_parse_apache_combined_format(self):
        """Test parsing Apache combined log format."""
        line = '192.168.1.1 - - [10/Oct/2023:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"'
        result = parse_log_line(line)

        assert result is not None
        assert result["ip"] == "192.168.1.1"
        assert result["method"] == "GET"
        assert result["path"] == "/index.html"
        assert result["status"] == "200"
        assert result["datetime"] is not None

    def test_parse_nginx_format(self):
        """Test parsing Nginx log format."""
        line = '10.0.0.1 - user [15/Nov/2023:10:30:00 +0000] "POST /api/data HTTP/1.1" 201 512 "https://example.com" "curl/7.68.0"'
        result = parse_log_line(line)

        assert result is not None
        assert result["ip"] == "10.0.0.1"
        assert result["method"] == "POST"
        assert result["path"] == "/api/data"
        assert result["status"] == "201"

    def test_parse_minimal_log_format(self):
        """Test parsing minimal log format."""
        line = '8.8.8.8 - - [01/Jan/2024:00:00:00 +0000] "HEAD / HTTP/2.0" 200 0'
        result = parse_log_line(line)

        assert result is not None
        assert result["ip"] == "8.8.8.8"
        assert result["method"] == "HEAD"

    def test_parse_invalid_line_returns_none(self):
        """Test invalid log line returns None."""
        invalid_lines = [
            "",
            "not a valid log line",
            "missing timestamp and method",
            "partial 192.168.1.1 data",
        ]

        for line in invalid_lines:
            result = parse_log_line(line)
            assert result is None

    def test_parse_line_with_special_characters(self):
        """Test parsing line with special characters in path."""
        line = '192.168.1.1 - - [10/Oct/2023:13:55:36 +0000] "GET /search?q=test%20query&page=1 HTTP/1.1" 200 500 "-" "Mozilla"'
        result = parse_log_line(line)

        assert result is not None
        assert "search" in result["path"]

    def test_parse_line_with_ipv4(self):
        """Test parsing various IPv4 addresses."""
        ips = ["127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.255.255"]

        for ip in ips:
            line = f'{ip} - - [10/Oct/2023:13:55:36 +0000] "GET / HTTP/1.1" 200 100'
            result = parse_log_line(line)
            assert result is not None
            assert result["ip"] == ip


class TestAnalyzeAccessLog:
    """Tests for analyze_access_log function."""

    @pytest.fixture(autouse=True)
    def reset_rate_limiter(self):
        """Reset rate limiter before each test."""
        _rate_limiter.tokens = _rate_limiter.burst_size

    @pytest.mark.asyncio
    async def test_analyze_normal_traffic(self, sample_log_file):
        """Test analysis of normal traffic log."""
        result = await analyze_access_log(str(sample_log_file))
        data = json.loads(result)

        assert data["success"] is True
        assert data["entries_analyzed"] == 100
        assert data["unique_ips"] == 10
        assert data["threat_level"] == "low"
        assert len(data["potential_attackers"]) == 0

    @pytest.mark.asyncio
    async def test_analyze_flood_attack(self, flood_attack_log):
        """Test detection of HTTP flood attack."""
        result = await analyze_access_log(str(flood_attack_log))
        data = json.loads(result)

        assert data["success"] is True
        assert len(data["potential_attackers"]) > 0
        assert data["threat_level"] in ["medium", "high"]

        # Attacker IP should be identified
        attacker_ips = [a["ip"] for a in data["potential_attackers"]]
        assert "10.0.0.100" in attacker_ips

    @pytest.mark.asyncio
    async def test_analyze_nonexistent_file(self):
        """Test error handling for non-existent file."""
        result = await analyze_access_log("/nonexistent/path/access.log")
        data = json.loads(result)

        assert data["success"] is False
        assert "not found" in data["error"].lower()

    @pytest.mark.asyncio
    async def test_analyze_empty_log(self, empty_log_file):
        """Test handling of empty log file."""
        result = await analyze_access_log(str(empty_log_file))
        data = json.loads(result)

        assert data["success"] is False
        assert "no valid" in data["error"].lower()

    @pytest.mark.asyncio
    async def test_analyze_malformed_log(self, malformed_log_file):
        """Test handling of malformed log entries."""
        result = await analyze_access_log(str(malformed_log_file))
        data = json.loads(result)

        # Should fail gracefully since no valid entries
        assert data["success"] is False

    @pytest.mark.asyncio
    async def test_analyze_attack_signatures(self, attack_signature_log):
        """Test detection of attack signatures."""
        result = await analyze_access_log(str(attack_signature_log))
        data = json.loads(result)

        assert data["success"] is True
        assert data["attack_signatures_found"] > 0
        assert len(data["signature_samples"]) > 0

    @pytest.mark.asyncio
    async def test_analyze_high_error_rate(self, high_error_rate_log):
        """Test detection of high error rates."""
        result = await analyze_access_log(str(high_error_rate_log))
        data = json.loads(result)

        assert data["success"] is True
        assert data["error_rate_percent"] >= 50

    @pytest.mark.asyncio
    async def test_analyze_respects_max_lines(self, sample_log_file):
        """Test max_lines parameter is respected."""
        result = await analyze_access_log(str(sample_log_file), max_lines=10)
        data = json.loads(result)

        assert data["success"] is True
        assert data["entries_analyzed"] == 10

    @pytest.mark.asyncio
    async def test_analyze_returns_thresholds(self, sample_log_file):
        """Test that thresholds are returned in analysis."""
        result = await analyze_access_log(str(sample_log_file))
        data = json.loads(result)

        assert "thresholds_used" in data
        assert "http_flood_rpm" in data["thresholds_used"]


class TestAnalyzeIpRates:
    """Tests for analyze_ip_rates function."""

    @pytest.mark.asyncio
    async def test_analyze_ip_rates_normal(self, sample_log_file):
        """Test IP rate analysis on normal traffic."""
        result = await analyze_ip_rates(str(sample_log_file))
        data = json.loads(result)

        assert data["success"] is True
        assert data["suspicious_ips"] == 0
        assert "No immediate action" in data["recommendation"]

    @pytest.mark.asyncio
    async def test_analyze_ip_rates_flood(self, flood_attack_log):
        """Test IP rate analysis detects flood."""
        result = await analyze_ip_rates(str(flood_attack_log), threshold_rpm=100)
        data = json.loads(result)

        assert data["success"] is True
        assert data["suspicious_ips"] > 0
        assert "Block" in data["recommendation"]

    @pytest.mark.asyncio
    async def test_analyze_ip_rates_custom_threshold(self, sample_log_file):
        """Test custom threshold parameter."""
        # Very low threshold should flag even normal traffic
        result = await analyze_ip_rates(str(sample_log_file), threshold_rpm=1)
        data = json.loads(result)

        assert data["success"] is True
        # With threshold of 1 RPM, some IPs might be flagged

    @pytest.mark.asyncio
    async def test_analyze_ip_rates_top_n(self, sample_log_file):
        """Test top_n parameter limits results."""
        result = await analyze_ip_rates(str(sample_log_file), top_n=5)
        data = json.loads(result)

        assert data["success"] is True
        assert len(data["top_ips"]) <= 5

    @pytest.mark.asyncio
    async def test_analyze_ip_rates_burst_detection(self, burst_traffic_log):
        """Test burst detection in IP rate analysis."""
        result = await analyze_ip_rates(str(burst_traffic_log), threshold_rpm=100)
        data = json.loads(result)

        assert data["success"] is True

        # Find the attacker IP
        attacker_data = None
        for ip_data in data["top_ips"]:
            if ip_data["ip"] == "10.20.30.40":
                attacker_data = ip_data
                break

        assert attacker_data is not None
        assert attacker_data["peak_burst_rpm"] > attacker_data["avg_rpm"]

    @pytest.mark.asyncio
    async def test_analyze_ip_rates_nonexistent_file(self):
        """Test error handling for non-existent file."""
        result = await analyze_ip_rates("/nonexistent/log.log")
        data = json.loads(result)

        assert data["success"] is False
        assert "error" in data
