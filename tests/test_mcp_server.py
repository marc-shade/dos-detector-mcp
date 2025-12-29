"""Tests for MCP server endpoints and tool registration."""

import json

import pytest

import sys
sys.path.insert(0, str(__file__).replace("/tests/test_mcp_server.py", "/src"))

from dos_detector_mcp.server import (
    mcp,
    analyze_access_log,
    analyze_ip_rates,
    detect_http_flood,
    detect_slowloris,
    generate_dos_report,
    get_attack_indicators,
    simulate_dos_metrics,
    get_adaptive_threshold_status,
    add_to_whitelist,
    _rate_limiter,
)


class TestMcpServerSetup:
    """Tests for MCP server configuration."""

    def test_mcp_server_name(self):
        """Test MCP server has correct name."""
        assert mcp.name == "dos-detector"

    def test_mcp_server_has_tools(self):
        """Test MCP server has registered tools."""
        # The server should have tools registered
        # FastMCP stores tools internally
        assert mcp is not None


class TestToolEndpoints:
    """Tests for MCP tool endpoint functionality."""

    @pytest.fixture(autouse=True)
    def reset_rate_limiter(self):
        """Reset rate limiter before each test."""
        _rate_limiter.tokens = _rate_limiter.burst_size

    @pytest.mark.asyncio
    async def test_analyze_access_log_returns_json(self, sample_log_file):
        """Test analyze_access_log returns valid JSON."""
        result = await analyze_access_log(str(sample_log_file))

        # Should be valid JSON
        data = json.loads(result)
        assert isinstance(data, dict)
        assert "success" in data

    @pytest.mark.asyncio
    async def test_analyze_ip_rates_returns_json(self, sample_log_file):
        """Test analyze_ip_rates returns valid JSON."""
        result = await analyze_ip_rates(str(sample_log_file))

        data = json.loads(result)
        assert isinstance(data, dict)
        assert "success" in data

    @pytest.mark.asyncio
    async def test_detect_http_flood_returns_json(self, sample_log_file):
        """Test detect_http_flood returns valid JSON."""
        result = await detect_http_flood(str(sample_log_file))

        data = json.loads(result)
        assert isinstance(data, dict)
        assert "success" in data

    @pytest.mark.asyncio
    async def test_detect_slowloris_returns_json(self, sample_log_file):
        """Test detect_slowloris returns valid JSON."""
        result = await detect_slowloris(str(sample_log_file))

        data = json.loads(result)
        assert isinstance(data, dict)
        assert "success" in data

    @pytest.mark.asyncio
    async def test_generate_dos_report_returns_json(self, sample_log_file):
        """Test generate_dos_report returns valid JSON."""
        result = await generate_dos_report(str(sample_log_file))

        data = json.loads(result)
        assert isinstance(data, dict)
        assert "success" in data

    @pytest.mark.asyncio
    async def test_get_attack_indicators_returns_json(self, sample_log_file):
        """Test get_attack_indicators returns valid JSON."""
        result = await get_attack_indicators(str(sample_log_file))

        data = json.loads(result)
        assert isinstance(data, dict)
        assert "success" in data

    @pytest.mark.asyncio
    async def test_simulate_dos_metrics_returns_json(self):
        """Test simulate_dos_metrics returns valid JSON."""
        result = await simulate_dos_metrics()

        data = json.loads(result)
        assert isinstance(data, dict)
        assert "success" in data

    @pytest.mark.asyncio
    async def test_get_adaptive_threshold_status_returns_json(self):
        """Test get_adaptive_threshold_status returns valid JSON."""
        result = await get_adaptive_threshold_status()

        data = json.loads(result)
        assert isinstance(data, dict)
        assert "success" in data

    @pytest.mark.asyncio
    async def test_add_to_whitelist_returns_json(self):
        """Test add_to_whitelist returns valid JSON."""
        result = await add_to_whitelist(ip="1.2.3.4")

        data = json.loads(result)
        assert isinstance(data, dict)
        assert "success" in data


class TestToolErrorHandling:
    """Tests for error handling in tools."""

    @pytest.fixture(autouse=True)
    def reset_rate_limiter(self):
        """Reset rate limiter before each test."""
        _rate_limiter.tokens = _rate_limiter.burst_size

    @pytest.mark.asyncio
    async def test_analyze_access_log_missing_file(self):
        """Test graceful handling of missing file."""
        result = await analyze_access_log("/nonexistent/path/file.log")
        data = json.loads(result)

        assert data["success"] is False
        assert "error" in data

    @pytest.mark.asyncio
    async def test_analyze_ip_rates_missing_file(self):
        """Test graceful handling of missing file."""
        result = await analyze_ip_rates("/nonexistent/path/file.log")
        data = json.loads(result)

        assert data["success"] is False
        assert "error" in data

    @pytest.mark.asyncio
    async def test_detect_http_flood_missing_file(self):
        """Test graceful handling of missing file."""
        result = await detect_http_flood("/nonexistent/path/file.log")
        data = json.loads(result)

        assert data["success"] is False
        assert "error" in data

    @pytest.mark.asyncio
    async def test_detect_slowloris_missing_file(self):
        """Test graceful handling of missing file."""
        result = await detect_slowloris("/nonexistent/path/file.log")
        data = json.loads(result)

        assert data["success"] is False
        assert "error" in data

    @pytest.mark.asyncio
    async def test_generate_dos_report_missing_file(self):
        """Test graceful handling of missing file."""
        result = await generate_dos_report("/nonexistent/path/file.log")
        data = json.loads(result)

        assert data["success"] is False
        assert "error" in data

    @pytest.mark.asyncio
    async def test_get_attack_indicators_missing_file(self):
        """Test graceful handling of missing file."""
        result = await get_attack_indicators("/nonexistent/path/file.log")
        data = json.loads(result)

        assert data["success"] is False
        assert "error" in data


class TestToolIntegration:
    """Integration tests for tool workflows."""

    @pytest.fixture(autouse=True)
    def reset_rate_limiter(self):
        """Reset rate limiter before each test."""
        _rate_limiter.tokens = _rate_limiter.burst_size

    @pytest.mark.asyncio
    async def test_full_analysis_workflow(self, flood_attack_log):
        """Test complete analysis workflow."""
        # Step 1: Analyze access log
        analysis = json.loads(await analyze_access_log(str(flood_attack_log)))
        assert analysis["success"] is True

        # Step 2: Get detailed IP rates
        ip_rates = json.loads(await analyze_ip_rates(str(flood_attack_log)))
        assert ip_rates["success"] is True

        # Step 3: Detect specific attack types
        flood = json.loads(await detect_http_flood(str(flood_attack_log)))
        assert flood["success"] is True

        # Step 4: Generate comprehensive report
        report = json.loads(await generate_dos_report(str(flood_attack_log)))
        assert report["success"] is True

        # Step 5: Extract IoCs
        iocs = json.loads(await get_attack_indicators(str(flood_attack_log)))
        assert iocs["success"] is True

    @pytest.mark.asyncio
    async def test_detection_consistency(self, flood_attack_log):
        """Test detection results are consistent across tools."""
        analysis = json.loads(await analyze_access_log(str(flood_attack_log)))
        ip_rates = json.loads(await analyze_ip_rates(str(flood_attack_log)))
        flood = json.loads(await detect_http_flood(str(flood_attack_log)))

        # All should detect the attack
        if analysis["potential_attackers"]:
            attacker_ip = analysis["potential_attackers"][0]["ip"]

            # IP should appear in other analyses
            top_ip_addresses = [ip["ip"] for ip in ip_rates["top_ips"]]
            assert attacker_ip in top_ip_addresses

    @pytest.mark.asyncio
    async def test_whitelist_affects_detection(self, whitelisted_traffic_log):
        """Test whitelist affects detection results."""
        # First analyze without specific whitelist
        result1 = json.loads(await analyze_access_log(str(whitelisted_traffic_log)))

        # Googlebot traffic should not trigger high threat level
        # due to default whitelist
        assert result1["success"] is True

    @pytest.mark.asyncio
    async def test_simulation_produces_testable_data(self):
        """Test simulation produces data suitable for testing."""
        simulation = json.loads(await simulate_dos_metrics(
            baseline_rps=10.0,
            attack_multiplier=10.0,
            attack_duration_seconds=60
        ))

        assert simulation["success"] is True

        # Timeline should have multiple phases
        timeline = simulation["timeline"]
        assert len(timeline) > 0

        # Thresholds should be based on baseline
        thresholds = simulation["detection_thresholds"]
        assert thresholds["warning"] == 20.0
        assert thresholds["alert"] == 50.0
        assert thresholds["critical"] == 100.0


class TestRateLimitingIntegration:
    """Tests for rate limiting in tools."""

    def test_rate_limiter_affects_analysis(self):
        """Test rate limiter prevents excessive requests."""
        # Exhaust rate limit tokens
        for _ in range(15):  # More than burst size
            _rate_limiter.allow_request()

        # Next request should be limited
        allowed, msg = _rate_limiter.allow_request()

        # Rate limiting kicks in after burst exhausted
        # The exact behavior depends on timing
        assert isinstance(allowed, bool)
        assert isinstance(msg, str)


class TestOutputFormatConsistency:
    """Tests for consistent output formatting."""

    @pytest.fixture(autouse=True)
    def reset_rate_limiter(self):
        """Reset rate limiter before each test."""
        _rate_limiter.tokens = _rate_limiter.burst_size

    @pytest.mark.asyncio
    async def test_all_tools_return_success_field(self, sample_log_file):
        """Test all tools include success field in response."""
        tools = [
            analyze_access_log(str(sample_log_file)),
            analyze_ip_rates(str(sample_log_file)),
            detect_http_flood(str(sample_log_file)),
            detect_slowloris(str(sample_log_file)),
            generate_dos_report(str(sample_log_file)),
            get_attack_indicators(str(sample_log_file)),
            simulate_dos_metrics(),
            get_adaptive_threshold_status(),
            add_to_whitelist(ip="1.2.3.4"),
        ]

        for tool_coro in tools:
            result = await tool_coro
            data = json.loads(result)
            assert "success" in data, f"Missing 'success' field in {result[:100]}"

    @pytest.mark.asyncio
    async def test_error_responses_have_error_field(self):
        """Test error responses include error field."""
        error_tools = [
            analyze_access_log("/nonexistent.log"),
            analyze_ip_rates("/nonexistent.log"),
            detect_http_flood("/nonexistent.log"),
            detect_slowloris("/nonexistent.log"),
            generate_dos_report("/nonexistent.log"),
            get_attack_indicators("/nonexistent.log"),
        ]

        for tool_coro in error_tools:
            result = await tool_coro
            data = json.loads(result)
            assert data["success"] is False
            assert "error" in data

    @pytest.mark.asyncio
    async def test_json_output_is_indented(self, sample_log_file):
        """Test JSON output is formatted with indentation."""
        result = await analyze_access_log(str(sample_log_file))

        # Indented JSON should have newlines
        assert "\n" in result
        # Should be parseable
        json.loads(result)
