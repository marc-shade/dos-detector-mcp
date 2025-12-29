"""Tests for alerting and reporting functionality."""

import json
from datetime import datetime

import pytest

import sys
sys.path.insert(0, str(__file__).replace("/tests/test_alerting.py", "/src"))

from dos_detector_mcp.server import (
    generate_dos_report,
    get_attack_indicators,
    simulate_dos_metrics,
    AdaptiveThresholds,
    get_adaptive_threshold_status,
    add_to_whitelist,
    is_whitelisted,
    WHITELIST,
    THRESHOLDS,
    _adaptive_thresholds,
)


class TestAdaptiveThresholds:
    """Tests for adaptive threshold functionality."""

    def test_initial_state(self):
        """Test AdaptiveThresholds initial state."""
        thresholds = AdaptiveThresholds()

        assert thresholds.baseline_rpm == 0.0
        assert thresholds.baseline_rps == 0.0
        assert thresholds.baseline_samples == 0

    def test_update_baseline_first_sample(self):
        """Test first baseline update."""
        thresholds = AdaptiveThresholds()
        thresholds.update_baseline(100.0, 1.67)

        assert thresholds.baseline_rpm == 100.0
        assert thresholds.baseline_rps == 1.67
        assert thresholds.baseline_samples == 1

    def test_update_baseline_ema(self):
        """Test exponential moving average calculation."""
        thresholds = AdaptiveThresholds()

        # First update sets baseline directly
        thresholds.update_baseline(100.0, 1.67)

        # Second update uses EMA (alpha=0.1)
        thresholds.update_baseline(200.0, 3.33)

        # EMA: (1-0.1) * 100 + 0.1 * 200 = 90 + 20 = 110
        assert 105 <= thresholds.baseline_rpm <= 115

    def test_get_adaptive_thresholds_insufficient_data(self):
        """Test thresholds with insufficient baseline data."""
        thresholds = AdaptiveThresholds()
        thresholds.update_baseline(100.0, 1.67)
        thresholds.update_baseline(100.0, 1.67)

        # Less than 3 samples, should return defaults
        result = thresholds.get_adaptive_thresholds()
        assert result["http_flood_rpm"] == THRESHOLDS["http_flood_rpm"]

    def test_get_adaptive_thresholds_with_data(self):
        """Test thresholds adapt with sufficient data."""
        thresholds = AdaptiveThresholds()

        # Add enough samples
        for _ in range(5):
            thresholds.update_baseline(50.0, 0.83)

        result = thresholds.get_adaptive_thresholds()

        # Adaptive threshold should be max of default or 5x baseline
        expected_min = max(THRESHOLDS["http_flood_rpm"], 50.0 * 5)
        assert result["http_flood_rpm"] >= expected_min

    def test_get_status(self):
        """Test status reporting."""
        thresholds = AdaptiveThresholds()
        thresholds.update_baseline(100.0, 1.67)

        status = thresholds.get_status()

        assert "baseline_rpm" in status
        assert "baseline_rps" in status
        assert "samples" in status
        assert "adaptive_thresholds" in status

    def test_thread_safety(self):
        """Test thread-safe operations."""
        import threading

        thresholds = AdaptiveThresholds()
        errors = []

        def update_baseline():
            try:
                for _ in range(100):
                    thresholds.update_baseline(50.0, 0.83)
                    thresholds.get_adaptive_thresholds()
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=update_baseline) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0


class TestWhitelist:
    """Tests for whitelist functionality."""

    def test_is_whitelisted_ip(self):
        """Test IP whitelist check."""
        # Add an IP to whitelist
        WHITELIST["ips"].add("1.2.3.4")

        assert is_whitelisted("1.2.3.4") is True
        assert is_whitelisted("5.6.7.8") is False

        # Cleanup
        WHITELIST["ips"].discard("1.2.3.4")

    def test_is_whitelisted_user_agent(self):
        """Test user agent whitelist check."""
        # Googlebot should be whitelisted by default
        assert is_whitelisted("10.0.0.1", "Googlebot/2.1") is True
        assert is_whitelisted("10.0.0.1", "Bingbot/2.0") is True
        assert is_whitelisted("10.0.0.1", "RandomBot/1.0") is False

    def test_is_whitelisted_case_insensitive(self):
        """Test user agent matching is case insensitive."""
        assert is_whitelisted("10.0.0.1", "googlebot/2.1") is True
        assert is_whitelisted("10.0.0.1", "GOOGLEBOT/2.1") is True

    @pytest.mark.asyncio
    async def test_add_to_whitelist_ip(self):
        """Test adding IP to whitelist."""
        result = await add_to_whitelist(ip="10.20.30.40")
        data = json.loads(result)

        assert data["success"] is True
        assert "IP: 10.20.30.40" in data["added"]
        assert "10.20.30.40" in WHITELIST["ips"]

        # Cleanup
        WHITELIST["ips"].discard("10.20.30.40")

    @pytest.mark.asyncio
    async def test_add_to_whitelist_user_agent(self):
        """Test adding user agent pattern to whitelist."""
        original_len = len(WHITELIST["user_agents"])

        result = await add_to_whitelist(user_agent_pattern=r"TestBot/\d+")
        data = json.loads(result)

        assert data["success"] is True
        assert len(WHITELIST["user_agents"]) == original_len + 1

        # Cleanup
        WHITELIST["user_agents"].pop()

    @pytest.mark.asyncio
    async def test_get_adaptive_threshold_status(self):
        """Test getting adaptive threshold status."""
        result = await get_adaptive_threshold_status()
        data = json.loads(result)

        assert data["success"] is True
        assert "adaptive_thresholds" in data
        assert "rate_limiter" in data
        assert "whitelist" in data


class TestGenerateDosReport:
    """Tests for DoS report generation."""

    @pytest.mark.asyncio
    async def test_generate_report_normal_traffic(self, sample_log_file):
        """Test report generation for normal traffic."""
        result = await generate_dos_report(str(sample_log_file))
        data = json.loads(result)

        assert data["success"] is True
        assert "summary" in data
        assert "threat_assessment" in data
        assert "recommendations" in data
        assert data["threat_assessment"]["threat_level"] == "low"

    @pytest.mark.asyncio
    async def test_generate_report_attack_traffic(self, flood_attack_log):
        """Test report generation for attack traffic."""
        result = await generate_dos_report(str(flood_attack_log))
        data = json.loads(result)

        assert data["success"] is True
        assert data["threat_assessment"]["threat_level"] in ["medium", "high", "critical"]
        assert len(data["threat_assessment"]["reasons"]) > 0

    @pytest.mark.asyncio
    async def test_generate_report_summary_format(self, sample_log_file):
        """Test summary format output."""
        result = await generate_dos_report(str(sample_log_file), output_format="summary")
        data = json.loads(result)

        # Summary format should have fewer fields
        assert "threat_level" in data
        assert "threat_score" in data
        assert "entries_analyzed" in data

    @pytest.mark.asyncio
    async def test_generate_report_detailed_format(self, sample_log_file):
        """Test detailed format output."""
        result = await generate_dos_report(str(sample_log_file), output_format="detailed")
        data = json.loads(result)

        assert "summary" in data
        assert "threat_assessment" in data
        assert "top_requesters" in data
        assert "status_distribution" in data

    @pytest.mark.asyncio
    async def test_generate_report_threat_scoring(self, high_error_rate_log):
        """Test threat scoring logic."""
        result = await generate_dos_report(str(high_error_rate_log))
        data = json.loads(result)

        # High error rate should increase threat score
        assert data["threat_assessment"]["threat_score"] > 0

    @pytest.mark.asyncio
    async def test_generate_report_recommendations(self, flood_attack_log):
        """Test recommendations are context-aware."""
        result = await generate_dos_report(str(flood_attack_log))
        data = json.loads(result)

        # Attack traffic should trigger action recommendations
        assert len(data["recommendations"]) > 0

    @pytest.mark.asyncio
    async def test_generate_report_nonexistent_file(self):
        """Test error handling for non-existent file."""
        result = await generate_dos_report("/nonexistent/file.log")
        data = json.loads(result)

        assert data["success"] is False
        assert "error" in data


class TestGetAttackIndicators:
    """Tests for IoC extraction."""

    @pytest.mark.asyncio
    async def test_get_indicators_attack_traffic(self, attack_signature_log):
        """Test IoC extraction from attack traffic."""
        result = await get_attack_indicators(str(attack_signature_log))
        data = json.loads(result)

        assert data["success"] is True
        assert "indicators_of_compromise" in data
        assert "totals" in data

        iocs = data["indicators_of_compromise"]
        assert len(iocs["suspicious_ips"]) > 0 or len(iocs["malicious_paths"]) > 0

    @pytest.mark.asyncio
    async def test_get_indicators_blocking_rules(self, attack_signature_log):
        """Test blocking rule generation."""
        result = await get_attack_indicators(str(attack_signature_log))
        data = json.loads(result)

        assert "blocking_rules" in data
        assert "iptables_example" in data["blocking_rules"]
        assert "nginx_deny" in data["blocking_rules"]

    @pytest.mark.asyncio
    async def test_get_indicators_normal_traffic(self, sample_log_file):
        """Test IoC extraction from normal traffic."""
        result = await get_attack_indicators(str(sample_log_file))
        data = json.loads(result)

        assert data["success"] is True
        # Normal traffic should have fewer or no IoCs
        assert data["totals"]["suspicious_ips"] == 0

    @pytest.mark.asyncio
    async def test_get_indicators_high_volume_detection(self, flood_attack_log):
        """Test high volume IP detection."""
        result = await get_attack_indicators(str(flood_attack_log))
        data = json.loads(result)

        assert data["success"] is True
        assert len(data["indicators_of_compromise"]["high_volume_ips"]) > 0

    @pytest.mark.asyncio
    async def test_get_indicators_nonexistent_file(self):
        """Test error handling for non-existent file."""
        result = await get_attack_indicators("/nonexistent/file.log")
        data = json.loads(result)

        assert data["success"] is False


class TestSimulateDosMetrics:
    """Tests for DoS metric simulation."""

    @pytest.mark.asyncio
    async def test_simulate_default_parameters(self):
        """Test simulation with default parameters."""
        result = await simulate_dos_metrics()
        data = json.loads(result)

        assert data["success"] is True
        assert "simulation" in data
        assert "timeline" in data
        assert "detection_thresholds" in data

    @pytest.mark.asyncio
    async def test_simulate_custom_parameters(self):
        """Test simulation with custom parameters."""
        result = await simulate_dos_metrics(
            baseline_rps=20.0,
            attack_multiplier=5.0,
            attack_duration_seconds=120
        )
        data = json.loads(result)

        assert data["success"] is True
        assert data["simulation"]["baseline_rps"] == 20.0
        assert data["simulation"]["attack_multiplier"] == 5.0
        assert data["simulation"]["peak_rps"] == 100.0  # 20 * 5

    @pytest.mark.asyncio
    async def test_simulate_timeline_phases(self):
        """Test timeline includes all phases."""
        result = await simulate_dos_metrics()
        data = json.loads(result)

        phases = {entry["phase"] for entry in data["timeline"]}

        assert "normal" in phases
        assert "ramp_up" in phases
        assert "attack" in phases
        assert "subsiding" in phases

    @pytest.mark.asyncio
    async def test_simulate_detection_thresholds(self):
        """Test detection thresholds are calculated correctly."""
        result = await simulate_dos_metrics(baseline_rps=10.0)
        data = json.loads(result)

        thresholds = data["detection_thresholds"]

        assert thresholds["warning"] == 20.0  # 2x baseline
        assert thresholds["alert"] == 50.0    # 5x baseline
        assert thresholds["critical"] == 100.0  # 10x baseline

    @pytest.mark.asyncio
    async def test_simulate_timeline_timestamps(self):
        """Test timeline entries have valid timestamps."""
        result = await simulate_dos_metrics()
        data = json.loads(result)

        for entry in data["timeline"]:
            assert "timestamp" in entry
            # Should be ISO format
            datetime.fromisoformat(entry["timestamp"])

    @pytest.mark.asyncio
    async def test_simulate_rps_variation(self):
        """Test RPS values have realistic variation."""
        result = await simulate_dos_metrics(baseline_rps=10.0)
        data = json.loads(result)

        normal_rps = [e["rps"] for e in data["timeline"] if e["phase"] == "normal"]
        attack_rps = [e["rps"] for e in data["timeline"] if e["phase"] == "attack"]

        # Normal phase should be around baseline
        assert all(5.0 <= rps <= 15.0 for rps in normal_rps)

        # Attack phase should be much higher
        if attack_rps:
            assert sum(attack_rps) / len(attack_rps) > 50.0
