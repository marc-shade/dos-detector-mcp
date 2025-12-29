"""Tests for pattern detection functionality."""

import json
from datetime import datetime

import pytest

import sys
sys.path.insert(0, str(__file__).replace("/tests/test_pattern_detection.py", "/src"))

from dos_detector_mcp.server import (
    detect_attack_signatures,
    detect_http_flood,
    detect_slowloris,
    ATTACK_PATTERNS,
)


class TestDetectAttackSignatures:
    """Tests for attack signature detection."""

    def test_detect_malicious_paths(self):
        """Test detection of malicious path patterns."""
        entries = [
            {"ip": "10.0.0.1", "path": "/etc/passwd", "datetime": datetime.now()},
            {"ip": "10.0.0.2", "path": "/../../../etc/shadow", "datetime": datetime.now()},
            {"ip": "10.0.0.3", "path": "/shell.php", "datetime": datetime.now()},
            {"ip": "10.0.0.4", "path": "/wp-admin/login.php", "datetime": datetime.now()},
            {"ip": "10.0.0.5", "path": "/.env", "datetime": datetime.now()},
        ]

        findings = detect_attack_signatures(entries)

        assert len(findings) >= 4  # At least 4 should be detected
        finding_types = [f["type"] for f in findings]
        assert "malicious_path" in finding_types

    def test_detect_suspicious_user_agents(self):
        """Test detection of suspicious user agents."""
        entries = [
            {"ip": "10.0.0.1", "path": "/", "user_agent": "sqlmap/1.5", "datetime": datetime.now()},
            {"ip": "10.0.0.2", "path": "/", "user_agent": "nikto/2.1.6", "datetime": datetime.now()},
            {"ip": "10.0.0.3", "path": "/", "user_agent": "nmap scripting engine", "datetime": datetime.now()},
            {"ip": "10.0.0.4", "path": "/", "user_agent": "masscan/1.0", "datetime": datetime.now()},
        ]

        findings = detect_attack_signatures(entries)

        assert len(findings) >= 3
        finding_types = [f["type"] for f in findings]
        assert "suspicious_user_agent" in finding_types

    def test_detect_curl_wget_user_agents(self):
        """Test detection of automation tool user agents."""
        entries = [
            {"ip": "10.0.0.1", "path": "/api", "user_agent": "curl/7.68.0", "datetime": datetime.now()},
            {"ip": "10.0.0.2", "path": "/api", "user_agent": "wget/1.20", "datetime": datetime.now()},
            {"ip": "10.0.0.3", "path": "/api", "user_agent": "python-requests/2.28.0", "datetime": datetime.now()},
        ]

        findings = detect_attack_signatures(entries)

        # These should be flagged as suspicious
        assert len(findings) >= 2
        user_agents = [f.get("user_agent", "") for f in findings]
        assert any("curl" in ua or "wget" in ua or "python" in ua for ua in user_agents)

    def test_no_false_positives_normal_traffic(self):
        """Test no false positives on normal traffic."""
        entries = [
            {"ip": "192.168.1.1", "path": "/index.html", "user_agent": "Mozilla/5.0 (Windows NT 10.0)", "datetime": datetime.now()},
            {"ip": "192.168.1.2", "path": "/about.html", "user_agent": "Mozilla/5.0 (Macintosh)", "datetime": datetime.now()},
            {"ip": "192.168.1.3", "path": "/contact", "user_agent": "Chrome/90.0", "datetime": datetime.now()},
        ]

        findings = detect_attack_signatures(entries)

        assert len(findings) == 0

    def test_detect_phpmyadmin_access(self):
        """Test detection of phpMyAdmin access attempts."""
        entries = [
            {"ip": "10.0.0.1", "path": "/phpMyAdmin/index.php", "datetime": datetime.now()},
            {"ip": "10.0.0.2", "path": "/phpmyadmin/", "datetime": datetime.now()},
        ]

        findings = detect_attack_signatures(entries)

        assert len(findings) >= 1
        paths = [f.get("path", "") for f in findings]
        assert any("phpmyadmin" in p.lower() for p in paths)

    def test_detect_directory_traversal(self):
        """Test detection of directory traversal attacks."""
        entries = [
            {"ip": "10.0.0.1", "path": "/download?file=../../../etc/passwd", "datetime": datetime.now()},
            {"ip": "10.0.0.2", "path": "/..%2F..%2F..%2Fetc/shadow", "datetime": datetime.now()},
        ]

        findings = detect_attack_signatures(entries)

        assert len(findings) >= 1

    def test_empty_entries_list(self):
        """Test handling of empty entries list."""
        findings = detect_attack_signatures([])
        assert findings == []

    def test_entries_with_missing_fields(self):
        """Test handling of entries with missing fields (path/user_agent not in dict)."""
        entries = [
            {"ip": "10.0.0.1"},  # Missing path and user_agent - uses default ''
            {"ip": "10.0.0.2", "path": "", "user_agent": ""},  # Empty strings
            {"ip": "10.0.0.3"},  # Another missing fields case
        ]

        # Should not raise exception when fields are missing (uses .get() with default '')
        findings = detect_attack_signatures(entries)
        assert isinstance(findings, list)

    def test_entries_with_none_values_raises(self):
        """Test that None values for path/user_agent cause TypeError.

        Note: This documents current behavior - the function uses re.search
        which requires string input. If path or user_agent is explicitly
        set to None (rather than missing), it will raise TypeError.
        """
        import re

        entries = [{"ip": "10.0.0.1", "path": None}]

        # Current implementation does not handle None values - documents this edge case
        with pytest.raises(TypeError):
            detect_attack_signatures(entries)


class TestDetectHttpFlood:
    """Tests for HTTP flood detection."""

    @pytest.mark.asyncio
    async def test_detect_flood_attack(self, flood_attack_log):
        """Test detection of HTTP flood attack."""
        result = await detect_http_flood(str(flood_attack_log), window_seconds=60, threshold_requests=100)
        data = json.loads(result)

        assert data["success"] is True
        assert data["attack_detected"] is True
        assert data["flood_sources"] >= 1

        # Check attacker IP is identified
        attacker_ips = [d["ip"] for d in data["detections"]]
        assert "10.0.0.100" in attacker_ips

    @pytest.mark.asyncio
    async def test_no_flood_normal_traffic(self, sample_log_file):
        """Test no false positives on normal traffic."""
        result = await detect_http_flood(str(sample_log_file), window_seconds=60, threshold_requests=100)
        data = json.loads(result)

        assert data["success"] is True
        assert data["attack_detected"] is False
        assert data["flood_sources"] == 0

    @pytest.mark.asyncio
    async def test_flood_severity_levels(self, flood_attack_log):
        """Test severity level assignment."""
        result = await detect_http_flood(str(flood_attack_log), window_seconds=60, threshold_requests=50)
        data = json.loads(result)

        assert data["success"] is True

        if data["detections"]:
            # Check severity field exists
            assert "severity" in data["detections"][0]
            assert data["detections"][0]["severity"] in ["high", "critical"]

    @pytest.mark.asyncio
    async def test_flood_mitigation_suggestions(self, flood_attack_log):
        """Test mitigation suggestions are provided."""
        result = await detect_http_flood(str(flood_attack_log), window_seconds=60, threshold_requests=100)
        data = json.loads(result)

        assert data["success"] is True
        assert "mitigation" in data
        assert len(data["mitigation"]) > 0

    @pytest.mark.asyncio
    async def test_flood_custom_window(self, burst_traffic_log):
        """Test custom window size."""
        # Shorter window should catch burst
        result = await detect_http_flood(str(burst_traffic_log), window_seconds=30, threshold_requests=50)
        data = json.loads(result)

        assert data["success"] is True

    @pytest.mark.asyncio
    async def test_flood_nonexistent_file(self):
        """Test error handling for non-existent file."""
        result = await detect_http_flood("/nonexistent/file.log")
        data = json.loads(result)

        assert data["success"] is False
        assert "error" in data


class TestDetectSlowloris:
    """Tests for Slowloris attack detection."""

    @pytest.mark.asyncio
    async def test_detect_slowloris_attack(self, slowloris_log):
        """Test detection of Slowloris attack patterns."""
        result = await detect_slowloris(str(slowloris_log))
        data = json.loads(result)

        assert data["success"] is True
        assert data["slowloris_indicators_found"] is True
        assert data["suspicious_ips"] >= 1

    @pytest.mark.asyncio
    async def test_no_slowloris_normal_traffic(self, sample_log_file):
        """Test no false positives on normal traffic."""
        result = await detect_slowloris(str(sample_log_file))
        data = json.loads(result)

        assert data["success"] is True
        assert data["slowloris_indicators_found"] is False

    @pytest.mark.asyncio
    async def test_slowloris_timeout_count(self, slowloris_log):
        """Test timeout count in Slowloris detection."""
        result = await detect_slowloris(str(slowloris_log), min_concurrent=5)
        data = json.loads(result)

        assert data["success"] is True

        if data["analysis"]:
            # Check the attacker IP has high timeout count
            attacker = next((a for a in data["analysis"] if a["ip"] == "10.0.0.50"), None)
            if attacker:
                assert attacker["timeouts"] > 0

    @pytest.mark.asyncio
    async def test_slowloris_detection_notes(self, slowloris_log):
        """Test detection notes are provided."""
        result = await detect_slowloris(str(slowloris_log))
        data = json.loads(result)

        assert "detection_notes" in data
        assert len(data["detection_notes"]) > 0

    @pytest.mark.asyncio
    async def test_slowloris_mitigation_provided(self, slowloris_log):
        """Test mitigation suggestions are provided."""
        result = await detect_slowloris(str(slowloris_log))
        data = json.loads(result)

        assert "mitigation" in data
        assert len(data["mitigation"]) > 0

    @pytest.mark.asyncio
    async def test_slowloris_custom_threshold(self, slowloris_log):
        """Test custom slow threshold parameter."""
        result = await detect_slowloris(str(slowloris_log), slow_threshold_seconds=60.0)
        data = json.loads(result)

        assert data["success"] is True

    @pytest.mark.asyncio
    async def test_slowloris_nonexistent_file(self):
        """Test error handling for non-existent file."""
        result = await detect_slowloris("/nonexistent/file.log")
        data = json.loads(result)

        assert data["success"] is False
        assert "error" in data


class TestAttackPatterns:
    """Tests for attack pattern definitions."""

    def test_attack_patterns_structure(self):
        """Test ATTACK_PATTERNS has expected structure."""
        assert "user_agents" in ATTACK_PATTERNS
        assert "paths" in ATTACK_PATTERNS
        assert isinstance(ATTACK_PATTERNS["user_agents"], list)
        assert isinstance(ATTACK_PATTERNS["paths"], list)

    def test_attack_patterns_not_empty(self):
        """Test attack patterns are defined."""
        assert len(ATTACK_PATTERNS["user_agents"]) > 0
        assert len(ATTACK_PATTERNS["paths"]) > 0

    def test_attack_patterns_are_valid_regex(self):
        """Test all patterns are valid regular expressions."""
        import re

        for pattern in ATTACK_PATTERNS["user_agents"]:
            try:
                re.compile(pattern)
            except re.error:
                pytest.fail(f"Invalid regex pattern: {pattern}")

        for pattern in ATTACK_PATTERNS["paths"]:
            try:
                re.compile(pattern)
            except re.error:
                pytest.fail(f"Invalid regex pattern: {pattern}")
