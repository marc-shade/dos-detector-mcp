"""Tests for rate limiting functionality."""

import time
import threading
from unittest.mock import patch

import pytest

# Import the module to test
import sys
sys.path.insert(0, str(__file__).replace("/tests/test_rate_limiting.py", "/src"))

from dos_detector_mcp.server import RateLimiter, check_rate_limit, _rate_limiter


class TestRateLimiter:
    """Tests for the RateLimiter class."""

    def test_init_default_values(self):
        """Test RateLimiter initializes with correct defaults."""
        limiter = RateLimiter()
        assert limiter.requests_per_minute == 30
        assert limiter.burst_size == 10
        assert limiter.tokens == 10

    def test_init_custom_values(self):
        """Test RateLimiter accepts custom configuration."""
        limiter = RateLimiter(requests_per_minute=60, burst_size=20)
        assert limiter.requests_per_minute == 60
        assert limiter.burst_size == 20
        assert limiter.tokens == 20

    def test_allow_request_within_burst(self):
        """Test requests within burst limit are allowed."""
        limiter = RateLimiter(requests_per_minute=60, burst_size=5)

        for i in range(5):
            allowed, msg = limiter.allow_request()
            assert allowed is True
            assert msg == "allowed"

    def test_allow_request_exceeds_burst(self):
        """Test requests exceeding burst limit are denied."""
        limiter = RateLimiter(requests_per_minute=60, burst_size=3)

        # Exhaust burst
        for _ in range(3):
            limiter.allow_request()

        # Next request should be denied
        allowed, msg = limiter.allow_request()
        assert allowed is False
        assert "Rate limited" in msg
        assert "Try again in" in msg

    def test_token_refill(self):
        """Test tokens refill over time."""
        limiter = RateLimiter(requests_per_minute=60, burst_size=2)

        # Exhaust tokens
        limiter.allow_request()
        limiter.allow_request()

        # Should be denied
        allowed, _ = limiter.allow_request()
        assert allowed is False

        # Wait for refill (1 token per second at 60 RPM)
        with patch.object(limiter, "last_update", limiter.last_update - 1.0):
            limiter._refill()

        # Now should be allowed
        allowed, _ = limiter.allow_request()
        assert allowed is True

    def test_token_refill_caps_at_burst_size(self):
        """Test token refill does not exceed burst size."""
        limiter = RateLimiter(requests_per_minute=60, burst_size=5)

        # Simulate long time passing
        with patch.object(limiter, "last_update", limiter.last_update - 100.0):
            limiter._refill()

        # Tokens should be capped at burst_size
        assert limiter.tokens == 5

    def test_thread_safety(self):
        """Test rate limiter is thread-safe."""
        limiter = RateLimiter(requests_per_minute=600, burst_size=100)
        results = []
        errors = []

        def make_requests():
            try:
                for _ in range(20):
                    limiter.allow_request()
                results.append("ok")
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=make_requests) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert len(results) == 5

    def test_wait_time_calculation(self):
        """Test wait time is calculated correctly when rate limited."""
        limiter = RateLimiter(requests_per_minute=60, burst_size=1)

        # Exhaust the single token
        limiter.allow_request()

        # Check wait time
        allowed, msg = limiter.allow_request()
        assert allowed is False
        # At 60 RPM, 1 token per second, wait ~1 second
        assert "0." in msg or "1." in msg  # Should be around 1 second


class TestCheckRateLimit:
    """Tests for the check_rate_limit function."""

    def test_check_rate_limit_uses_global_limiter(self):
        """Test check_rate_limit uses the global rate limiter."""
        # Reset global limiter
        _rate_limiter.tokens = _rate_limiter.burst_size

        allowed, msg = check_rate_limit()
        assert allowed is True
        assert msg == "allowed"

    def test_check_rate_limit_returns_tuple(self):
        """Test check_rate_limit returns proper tuple format."""
        result = check_rate_limit()
        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], bool)
        assert isinstance(result[1], str)
