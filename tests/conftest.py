"""Pytest fixtures for dos-detector-mcp tests."""

import os
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Generator

import pytest


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_log_file(temp_dir: Path) -> Path:
    """Create a sample access log file with normal traffic."""
    log_path = temp_dir / "access.log"
    base_time = datetime.now() - timedelta(hours=1)

    lines = []
    for i in range(100):
        ts = base_time + timedelta(seconds=i * 36)  # ~100 requests over 1 hour
        timestamp = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
        ip = f"192.168.1.{(i % 10) + 1}"
        path = f"/page{i % 5}.html"
        lines.append(
            f'{ip} - - [{timestamp}] "GET {path} HTTP/1.1" 200 1234 "-" "Mozilla/5.0"'
        )

    log_path.write_text("\n".join(lines))
    return log_path


@pytest.fixture
def flood_attack_log(temp_dir: Path) -> Path:
    """Create a log file simulating HTTP flood attack from single IP."""
    log_path = temp_dir / "flood.log"
    base_time = datetime.now() - timedelta(minutes=5)

    lines = []
    attacker_ip = "10.0.0.100"

    # 500 requests from attacker in 60 seconds
    for i in range(500):
        ts = base_time + timedelta(seconds=i * 0.12)
        timestamp = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
        lines.append(
            f'{attacker_ip} - - [{timestamp}] "GET /api/data HTTP/1.1" 200 512 "-" "python-requests/2.28.0"'
        )

    # Some normal traffic mixed in
    for i in range(50):
        ts = base_time + timedelta(seconds=i * 1.2)
        timestamp = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
        ip = f"192.168.1.{i % 10 + 1}"
        lines.append(
            f'{ip} - - [{timestamp}] "GET /index.html HTTP/1.1" 200 2048 "-" "Mozilla/5.0"'
        )

    log_path.write_text("\n".join(lines))
    return log_path


@pytest.fixture
def slowloris_log(temp_dir: Path) -> Path:
    """Create a log file simulating Slowloris attack patterns."""
    log_path = temp_dir / "slowloris.log"
    base_time = datetime.now() - timedelta(minutes=10)

    lines = []
    attacker_ip = "10.0.0.50"

    # Many 408 Request Timeout from attacker
    for i in range(30):
        ts = base_time + timedelta(seconds=i * 20)
        timestamp = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
        lines.append(
            f'{attacker_ip} - - [{timestamp}] "GET /slow HTTP/1.1" 408 0 "-" "slowloris"'
        )

    # Some 400 Bad Request (incomplete headers)
    for i in range(20):
        ts = base_time + timedelta(seconds=i * 30 + 10)
        timestamp = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
        lines.append(
            f'{attacker_ip} - - [{timestamp}] "GET /incomplete HTTP/1.1" 400 0 "-" "slowloris"'
        )

    # Normal traffic
    for i in range(100):
        ts = base_time + timedelta(seconds=i * 6)
        timestamp = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
        ip = f"192.168.1.{i % 20 + 1}"
        lines.append(
            f'{ip} - - [{timestamp}] "GET /page.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"'
        )

    log_path.write_text("\n".join(lines))
    return log_path


@pytest.fixture
def attack_signature_log(temp_dir: Path) -> Path:
    """Create a log file with known attack signatures."""
    log_path = temp_dir / "signatures.log"
    base_time = datetime.now() - timedelta(minutes=30)

    lines = []

    # SQL injection attempts
    malicious_paths = [
        "/page.php?id=1' OR '1'='1",
        "/admin/../../../etc/passwd",
        "/shell.php",
        "/wp-admin/admin-ajax.php",
        "/.env",
        "/phpMyAdmin/index.php",
    ]

    for i, path in enumerate(malicious_paths):
        ts = base_time + timedelta(seconds=i * 60)
        timestamp = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
        lines.append(
            f'10.0.0.{i + 1} - - [{timestamp}] "GET {path} HTTP/1.1" 404 0 "-" "nikto/2.1.6"'
        )

    # Requests with suspicious user agents
    suspicious_uas = [
        "sqlmap/1.0",
        "nmap scripting engine",
        "masscan/1.0",
        "curl/7.68.0",
        "wget/1.20",
    ]

    for i, ua in enumerate(suspicious_uas):
        ts = base_time + timedelta(seconds=(i + 10) * 60)
        timestamp = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
        lines.append(
            f'10.0.1.{i + 1} - - [{timestamp}] "GET /scan HTTP/1.1" 200 100 "-" "{ua}"'
        )

    log_path.write_text("\n".join(lines))
    return log_path


@pytest.fixture
def high_error_rate_log(temp_dir: Path) -> Path:
    """Create a log file with high error rates."""
    log_path = temp_dir / "errors.log"
    base_time = datetime.now() - timedelta(minutes=15)

    lines = []

    # 60% error responses (simulating attack or misconfiguration)
    for i in range(100):
        ts = base_time + timedelta(seconds=i * 9)
        timestamp = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
        ip = f"192.168.1.{i % 10 + 1}"

        # 60 errors, 40 success
        if i < 30:
            status = "500"
        elif i < 60:
            status = "404"
        else:
            status = "200"

        lines.append(
            f'{ip} - - [{timestamp}] "GET /api/data HTTP/1.1" {status} 512 "-" "Mozilla/5.0"'
        )

    log_path.write_text("\n".join(lines))
    return log_path


@pytest.fixture
def empty_log_file(temp_dir: Path) -> Path:
    """Create an empty log file."""
    log_path = temp_dir / "empty.log"
    log_path.write_text("")
    return log_path


@pytest.fixture
def malformed_log_file(temp_dir: Path) -> Path:
    """Create a log file with malformed entries."""
    log_path = temp_dir / "malformed.log"
    lines = [
        "This is not a valid log line",
        "Neither is this one",
        "192.168.1.1 - - invalid timestamp format",
        "",
        "random garbage data",
    ]
    log_path.write_text("\n".join(lines))
    return log_path


@pytest.fixture
def distributed_attack_log(temp_dir: Path) -> Path:
    """Create a log file simulating DDoS from multiple IPs."""
    log_path = temp_dir / "ddos.log"
    base_time = datetime.now() - timedelta(minutes=5)

    lines = []

    # Distributed attack from 50 different IPs, each sending 20 requests
    for ip_num in range(50):
        for req in range(20):
            ts = base_time + timedelta(seconds=req * 3 + ip_num * 0.1)
            timestamp = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
            ip = f"10.{ip_num // 256}.{ip_num % 256}.{req % 256}"
            lines.append(
                f'{ip} - - [{timestamp}] "GET /target HTTP/1.1" 200 100 "-" "BotAgent/1.0"'
            )

    log_path.write_text("\n".join(lines))
    return log_path


@pytest.fixture
def burst_traffic_log(temp_dir: Path) -> Path:
    """Create a log with traffic bursts."""
    log_path = temp_dir / "burst.log"
    base_time = datetime.now() - timedelta(minutes=10)

    lines = []
    attacker_ip = "10.20.30.40"

    # Normal traffic for 5 minutes
    for i in range(50):
        ts = base_time + timedelta(seconds=i * 6)
        timestamp = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
        ip = f"192.168.1.{i % 10 + 1}"
        lines.append(
            f'{ip} - - [{timestamp}] "GET /page.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"'
        )

    # Burst: 200 requests in 30 seconds from single IP
    burst_start = base_time + timedelta(minutes=5)
    for i in range(200):
        ts = burst_start + timedelta(seconds=i * 0.15)
        timestamp = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
        lines.append(
            f'{attacker_ip} - - [{timestamp}] "GET /api/flood HTTP/1.1" 200 100 "-" "AttackBot/1.0"'
        )

    # Normal traffic resumes
    for i in range(50):
        ts = burst_start + timedelta(seconds=60 + i * 6)
        timestamp = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
        ip = f"192.168.1.{i % 10 + 1}"
        lines.append(
            f'{ip} - - [{timestamp}] "GET /page.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"'
        )

    log_path.write_text("\n".join(lines))
    return log_path


@pytest.fixture
def whitelisted_traffic_log(temp_dir: Path) -> Path:
    """Create a log with traffic from whitelisted sources."""
    log_path = temp_dir / "whitelisted.log"
    base_time = datetime.now() - timedelta(minutes=30)

    lines = []

    # High volume from Googlebot (should be whitelisted)
    for i in range(200):
        ts = base_time + timedelta(seconds=i * 0.5)
        timestamp = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
        lines.append(
            f'66.249.66.{i % 256} - - [{timestamp}] "GET /sitemap.xml HTTP/1.1" 200 5000 "-" "Googlebot/2.1 (+http://www.google.com/bot.html)"'
        )

    # Normal user traffic
    for i in range(50):
        ts = base_time + timedelta(seconds=i * 6)
        timestamp = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
        ip = f"192.168.1.{i % 10 + 1}"
        lines.append(
            f'{ip} - - [{timestamp}] "GET /index.html HTTP/1.1" 200 2048 "-" "Mozilla/5.0"'
        )

    log_path.write_text("\n".join(lines))
    return log_path
