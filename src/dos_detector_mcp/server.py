#!/usr/bin/env python3
"""
DoS Detector MCP Server

Denial of Service attack detection through log analysis, traffic pattern
recognition, and anomaly detection.
"""

import json
import re
import statistics
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("dos-detector")

# Detection thresholds (configurable)
THRESHOLDS = {
    "http_flood_rpm": 100,  # requests per minute per IP
    "http_flood_rps": 10,   # requests per second per IP
    "syn_flood_halfopen": 50,  # half-open connections per second
    "slowloris_connections": 10,  # slow concurrent connections
    "bandwidth_spike_percent": 300,  # % of baseline
    "unique_ips_spike": 500,  # % of baseline
    "error_rate_threshold": 50,  # % 4xx/5xx errors
}

# Common attack signatures
ATTACK_PATTERNS = {
    "user_agents": [
        r"python-requests",
        r"curl/\d",
        r"wget/\d",
        r"^-$",
        r"nikto",
        r"sqlmap",
        r"nmap",
        r"masscan",
    ],
    "paths": [
        r"\.\.\/",
        r"etc/passwd",
        r"cmd\.exe",
        r"shell\.php",
        r"phpMyAdmin",
        r"wp-admin",
        r"\.env$",
    ],
}

# Apache/Nginx log regex
LOG_PATTERN = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s+'
    r'(?P<ident>-|\S+)\s+'
    r'(?P<user>-|\S+)\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<protocol>[^"]+)"\s+'
    r'(?P<status>\d+)\s+'
    r'(?P<size>-|\d+)\s*'
    r'(?:"(?P<referer>[^"]*)")?\s*'
    r'(?:"(?P<user_agent>[^"]*)")?'
)

# Alternative simpler pattern
LOG_PATTERN_SIMPLE = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+).*\[(?P<timestamp>[^\]]+)\].*"(?P<method>\S+)\s+(?P<path>\S+).*"\s+(?P<status>\d+)\s+(?P<size>\d+|-)'
)


def parse_log_line(line: str) -> Optional[dict]:
    """Parse a single log line."""
    match = LOG_PATTERN.match(line)
    if not match:
        match = LOG_PATTERN_SIMPLE.match(line)
    if match:
        data = match.groupdict()
        # Parse timestamp
        try:
            ts_str = data['timestamp'].split()[0]
            data['datetime'] = datetime.strptime(ts_str, '%d/%b/%Y:%H:%M:%S')
        except (ValueError, KeyError):
            data['datetime'] = None
        return data
    return None


def detect_attack_signatures(entries: list) -> list:
    """Check for known attack signatures in requests."""
    findings = []

    for entry in entries:
        path = entry.get('path', '')
        user_agent = entry.get('user_agent', '')

        # Check malicious paths
        for pattern in ATTACK_PATTERNS['paths']:
            if re.search(pattern, path, re.IGNORECASE):
                findings.append({
                    "type": "malicious_path",
                    "ip": entry['ip'],
                    "path": path,
                    "pattern": pattern,
                    "timestamp": str(entry.get('datetime', 'unknown'))
                })
                break

        # Check suspicious user agents
        for pattern in ATTACK_PATTERNS['user_agents']:
            if re.search(pattern, user_agent, re.IGNORECASE):
                findings.append({
                    "type": "suspicious_user_agent",
                    "ip": entry['ip'],
                    "user_agent": user_agent,
                    "pattern": pattern,
                    "timestamp": str(entry.get('datetime', 'unknown'))
                })
                break

    return findings


@mcp.tool()
async def analyze_access_log(
    log_path: str,
    time_window_minutes: int = 60,
    max_lines: int = 100000
) -> str:
    """
    Analyze web server access log for DoS attack indicators.

    Args:
        log_path: Path to access log file (Apache/Nginx format)
        time_window_minutes: Analysis window in minutes
        max_lines: Maximum log lines to process

    Returns:
        JSON with attack indicators and statistics
    """
    path = Path(log_path)
    if not path.exists():
        return json.dumps({"success": False, "error": f"Log file not found: {log_path}"})

    entries = []
    ip_requests = defaultdict(list)
    status_codes = Counter()
    paths = Counter()
    user_agents = Counter()

    try:
        with open(path, 'r', errors='ignore') as f:
            for i, line in enumerate(f):
                if i >= max_lines:
                    break
                parsed = parse_log_line(line)
                if parsed:
                    entries.append(parsed)
                    ip_requests[parsed['ip']].append(parsed)
                    status_codes[parsed.get('status', 'unknown')] += 1
                    paths[parsed.get('path', 'unknown')] += 1
                    user_agents[parsed.get('user_agent', 'unknown')] += 1
    except Exception as e:
        return json.dumps({"success": False, "error": str(e)})

    if not entries:
        return json.dumps({"success": False, "error": "No valid log entries found"})

    # Calculate rates per IP
    ip_rates = {}
    for ip, reqs in ip_requests.items():
        timestamps = [r['datetime'] for r in reqs if r.get('datetime')]
        if len(timestamps) >= 2:
            time_span = (max(timestamps) - min(timestamps)).total_seconds()
            if time_span > 0:
                ip_rates[ip] = {
                    "total_requests": len(reqs),
                    "requests_per_minute": len(reqs) / (time_span / 60),
                    "requests_per_second": len(reqs) / time_span if time_span > 0 else 0,
                    "unique_paths": len(set(r.get('path') for r in reqs)),
                    "status_codes": dict(Counter(r.get('status') for r in reqs))
                }
        else:
            ip_rates[ip] = {"total_requests": len(reqs), "requests_per_minute": len(reqs)}

    # Find potential attackers (exceeding thresholds)
    potential_attackers = []
    for ip, stats in ip_rates.items():
        rpm = stats.get('requests_per_minute', 0)
        if rpm > THRESHOLDS['http_flood_rpm']:
            potential_attackers.append({
                "ip": ip,
                "rpm": round(rpm, 2),
                "total": stats['total_requests'],
                "severity": "high" if rpm > THRESHOLDS['http_flood_rpm'] * 2 else "medium"
            })

    # Check for attack signatures
    signature_findings = detect_attack_signatures(entries)

    # Error rate analysis
    total_requests = sum(status_codes.values())
    error_codes = sum(v for k, v in status_codes.items() if k.startswith(('4', '5')))
    error_rate = (error_codes / total_requests * 100) if total_requests > 0 else 0

    # Determine overall threat level
    threat_level = "low"
    if potential_attackers or len(signature_findings) > 10:
        threat_level = "medium"
    if len(potential_attackers) > 5 or error_rate > 50:
        threat_level = "high"

    return json.dumps({
        "success": True,
        "log_file": log_path,
        "entries_analyzed": len(entries),
        "unique_ips": len(ip_requests),
        "time_window_minutes": time_window_minutes,
        "threat_level": threat_level,
        "potential_attackers": sorted(potential_attackers, key=lambda x: x['rpm'], reverse=True)[:20],
        "top_requesters": [
            {"ip": ip, **stats}
            for ip, stats in sorted(ip_rates.items(), key=lambda x: x[1].get('total_requests', 0), reverse=True)[:10]
        ],
        "status_distribution": dict(status_codes.most_common(10)),
        "error_rate_percent": round(error_rate, 2),
        "attack_signatures_found": len(signature_findings),
        "signature_samples": signature_findings[:10],
        "most_requested_paths": dict(paths.most_common(10)),
        "thresholds_used": THRESHOLDS
    }, indent=2)


@mcp.tool()
async def analyze_ip_rates(
    log_path: str,
    threshold_rpm: int = 100,
    top_n: int = 20
) -> str:
    """
    Analyze request rates per IP address to identify flood attacks.

    Args:
        log_path: Path to access log file
        threshold_rpm: Alert threshold (requests per minute)
        top_n: Number of top IPs to return

    Returns:
        JSON with per-IP rate analysis
    """
    path = Path(log_path)
    if not path.exists():
        return json.dumps({"success": False, "error": f"Log file not found: {log_path}"})

    ip_data = defaultdict(lambda: {"requests": [], "paths": set(), "methods": Counter()})

    try:
        with open(path, 'r', errors='ignore') as f:
            for line in f:
                parsed = parse_log_line(line)
                if parsed and parsed.get('datetime'):
                    ip = parsed['ip']
                    ip_data[ip]['requests'].append(parsed['datetime'])
                    ip_data[ip]['paths'].add(parsed.get('path', ''))
                    ip_data[ip]['methods'][parsed.get('method', 'UNKNOWN')] += 1
    except Exception as e:
        return json.dumps({"success": False, "error": str(e)})

    # Calculate rates
    results = []
    for ip, data in ip_data.items():
        timestamps = sorted(data['requests'])
        total = len(timestamps)

        if total < 2:
            continue

        time_span = (timestamps[-1] - timestamps[0]).total_seconds()
        rpm = (total / (time_span / 60)) if time_span > 0 else total

        # Burst detection - check for high rates in short windows
        burst_rate = 0
        for i in range(len(timestamps) - 10):
            window = (timestamps[i + 10] - timestamps[i]).total_seconds()
            if window > 0:
                window_rate = 10 / window * 60  # Convert to RPM
                burst_rate = max(burst_rate, window_rate)

        is_suspicious = rpm > threshold_rpm or burst_rate > threshold_rpm * 2

        results.append({
            "ip": ip,
            "total_requests": total,
            "avg_rpm": round(rpm, 2),
            "peak_burst_rpm": round(burst_rate, 2),
            "unique_paths": len(data['paths']),
            "methods": dict(data['methods']),
            "is_suspicious": is_suspicious,
            "first_seen": str(timestamps[0]),
            "last_seen": str(timestamps[-1])
        })

    # Sort by average RPM
    results.sort(key=lambda x: x['avg_rpm'], reverse=True)

    suspicious_count = sum(1 for r in results if r['is_suspicious'])

    return json.dumps({
        "success": True,
        "total_unique_ips": len(results),
        "suspicious_ips": suspicious_count,
        "threshold_rpm": threshold_rpm,
        "top_ips": results[:top_n],
        "recommendation": "Block IPs marked as suspicious" if suspicious_count > 0 else "No immediate action needed"
    }, indent=2)


@mcp.tool()
async def detect_http_flood(
    log_path: str,
    window_seconds: int = 60,
    threshold_requests: int = 100
) -> str:
    """
    Detect HTTP flood attacks by analyzing request bursts.

    Args:
        log_path: Path to access log file
        window_seconds: Time window for burst detection
        threshold_requests: Requests in window to trigger alert

    Returns:
        JSON with flood detection results
    """
    path = Path(log_path)
    if not path.exists():
        return json.dumps({"success": False, "error": f"Log file not found: {log_path}"})

    ip_timestamps = defaultdict(list)

    try:
        with open(path, 'r', errors='ignore') as f:
            for line in f:
                parsed = parse_log_line(line)
                if parsed and parsed.get('datetime'):
                    ip_timestamps[parsed['ip']].append(parsed['datetime'])
    except Exception as e:
        return json.dumps({"success": False, "error": str(e)})

    flood_detections = []

    for ip, timestamps in ip_timestamps.items():
        timestamps.sort()
        max_in_window = 0
        peak_window_start = None

        # Sliding window analysis
        for i, ts in enumerate(timestamps):
            window_end = ts + timedelta(seconds=window_seconds)
            count = sum(1 for t in timestamps[i:] if t <= window_end)
            if count > max_in_window:
                max_in_window = count
                peak_window_start = ts

        if max_in_window >= threshold_requests:
            flood_detections.append({
                "ip": ip,
                "max_requests_in_window": max_in_window,
                "window_seconds": window_seconds,
                "peak_window_start": str(peak_window_start),
                "total_requests": len(timestamps),
                "severity": "critical" if max_in_window >= threshold_requests * 2 else "high"
            })

    flood_detections.sort(key=lambda x: x['max_requests_in_window'], reverse=True)

    is_under_attack = len(flood_detections) > 0

    return json.dumps({
        "success": True,
        "attack_detected": is_under_attack,
        "flood_sources": len(flood_detections),
        "detection_threshold": f"{threshold_requests} requests in {window_seconds} seconds",
        "detections": flood_detections[:20],
        "mitigation": [
            "Rate limit offending IPs at firewall/reverse proxy",
            "Enable CAPTCHA for affected endpoints",
            "Scale horizontally if legitimate traffic is mixed in",
            "Contact upstream provider if DDoS"
        ] if is_under_attack else ["No immediate mitigation needed"]
    }, indent=2)


@mcp.tool()
async def detect_slowloris(
    log_path: str,
    slow_threshold_seconds: float = 30.0,
    min_concurrent: int = 5
) -> str:
    """
    Detect Slowloris-style slow HTTP attacks.

    Slowloris keeps connections open with slow, incomplete requests
    to exhaust server connection pools.

    Args:
        log_path: Path to access log
        slow_threshold_seconds: Consider request "slow" if above this
        min_concurrent: Minimum concurrent slow connections to flag

    Returns:
        JSON with Slowloris detection analysis
    """
    # Note: Full Slowloris detection requires connection-level data
    # This analyzes logs for slow request patterns as a proxy indicator

    path = Path(log_path)
    if not path.exists():
        return json.dumps({"success": False, "error": f"Log file not found: {log_path}"})

    # Look for patterns indicating slow attacks
    ip_data = defaultdict(lambda: {"slow_indicators": 0, "total": 0, "timeouts": 0})

    try:
        with open(path, 'r', errors='ignore') as f:
            for line in f:
                parsed = parse_log_line(line)
                if parsed:
                    ip = parsed['ip']
                    ip_data[ip]['total'] += 1

                    # 408 = Request Timeout (common in Slowloris)
                    # 400 = Bad Request (incomplete headers)
                    status = parsed.get('status', '')
                    if status in ('408', '400', '499'):
                        ip_data[ip]['slow_indicators'] += 1
                        if status == '408':
                            ip_data[ip]['timeouts'] += 1
    except Exception as e:
        return json.dumps({"success": False, "error": str(e)})

    # Find IPs with high slow indicator ratios
    suspicious = []
    for ip, data in ip_data.items():
        if data['total'] >= 10:  # Need enough requests to analyze
            slow_ratio = data['slow_indicators'] / data['total']
            if slow_ratio > 0.3 or data['timeouts'] >= min_concurrent:
                suspicious.append({
                    "ip": ip,
                    "total_requests": data['total'],
                    "slow_indicators": data['slow_indicators'],
                    "timeouts": data['timeouts'],
                    "slow_ratio": round(slow_ratio, 2),
                    "likely_slowloris": data['timeouts'] >= min_concurrent
                })

    suspicious.sort(key=lambda x: x['timeouts'], reverse=True)

    return json.dumps({
        "success": True,
        "slowloris_indicators_found": len(suspicious) > 0,
        "suspicious_ips": len(suspicious),
        "analysis": suspicious[:20],
        "detection_notes": [
            "408 Request Timeout is strong indicator of Slowloris",
            "High ratio of 400/408/499 errors suggests connection-level attack",
            "Full detection requires connection monitoring (netstat/ss)"
        ],
        "mitigation": [
            "Set aggressive connection timeouts",
            "Limit connections per IP (iptables/mod_qos)",
            "Use reverse proxy with Slowloris protection",
            "Enable HTTP/2 (more resistant to Slowloris)"
        ] if suspicious else ["No Slowloris indicators found"]
    }, indent=2)


@mcp.tool()
async def generate_dos_report(
    log_path: str,
    output_format: str = "detailed"
) -> str:
    """
    Generate comprehensive DoS attack analysis report.

    Args:
        log_path: Path to access log
        output_format: "detailed" or "summary"

    Returns:
        JSON with full attack analysis report
    """
    path = Path(log_path)
    if not path.exists():
        return json.dumps({"success": False, "error": f"Log file not found: {log_path}"})

    # Collect all metrics
    entries = []
    ip_requests = defaultdict(list)
    timestamps = []
    status_codes = Counter()
    bytes_transferred = 0

    try:
        with open(path, 'r', errors='ignore') as f:
            for i, line in enumerate(f):
                if i >= 500000:  # Limit for performance
                    break
                parsed = parse_log_line(line)
                if parsed:
                    entries.append(parsed)
                    ip_requests[parsed['ip']].append(parsed)
                    if parsed.get('datetime'):
                        timestamps.append(parsed['datetime'])
                    status_codes[parsed.get('status', 'unknown')] += 1
                    try:
                        bytes_transferred += int(parsed.get('size', 0))
                    except (ValueError, TypeError):
                        pass
    except Exception as e:
        return json.dumps({"success": False, "error": str(e)})

    if not entries:
        return json.dumps({"success": False, "error": "No valid entries"})

    # Time analysis
    timestamps.sort()
    time_span = (timestamps[-1] - timestamps[0]).total_seconds() if len(timestamps) >= 2 else 0
    overall_rps = len(entries) / time_span if time_span > 0 else 0

    # IP analysis
    top_ips = sorted(
        [(ip, len(reqs)) for ip, reqs in ip_requests.items()],
        key=lambda x: x[1],
        reverse=True
    )[:10]

    # Calculate standard deviation for anomaly detection
    request_counts = [len(reqs) for reqs in ip_requests.values()]
    avg_requests = statistics.mean(request_counts) if request_counts else 0
    std_requests = statistics.stdev(request_counts) if len(request_counts) > 1 else 0

    # Find anomalous IPs (>2 std deviations)
    anomalous_ips = [
        ip for ip, reqs in ip_requests.items()
        if len(reqs) > avg_requests + (2 * std_requests) and std_requests > 0
    ]

    # Attack signatures
    signatures = detect_attack_signatures(entries[:10000])

    # Error analysis
    total = sum(status_codes.values())
    error_requests = sum(v for k, v in status_codes.items() if k.startswith(('4', '5')))
    error_rate = (error_requests / total * 100) if total > 0 else 0

    # Threat assessment
    threat_score = 0
    threat_reasons = []

    if len(anomalous_ips) > 0:
        threat_score += 30
        threat_reasons.append(f"{len(anomalous_ips)} IPs with anomalous request rates")

    if error_rate > 30:
        threat_score += 25
        threat_reasons.append(f"High error rate: {error_rate:.1f}%")

    if len(signatures) > 20:
        threat_score += 25
        threat_reasons.append(f"{len(signatures)} attack signatures detected")

    if overall_rps > 100:
        threat_score += 20
        threat_reasons.append(f"High overall request rate: {overall_rps:.1f} RPS")

    threat_level = "low"
    if threat_score >= 30:
        threat_level = "medium"
    if threat_score >= 60:
        threat_level = "high"
    if threat_score >= 80:
        threat_level = "critical"

    report = {
        "success": True,
        "report_generated": datetime.now().isoformat(),
        "log_file": log_path,
        "summary": {
            "entries_analyzed": len(entries),
            "unique_ips": len(ip_requests),
            "time_span_seconds": round(time_span, 1),
            "overall_requests_per_second": round(overall_rps, 2),
            "total_bytes_transferred": bytes_transferred,
            "error_rate_percent": round(error_rate, 2)
        },
        "threat_assessment": {
            "threat_level": threat_level,
            "threat_score": threat_score,
            "reasons": threat_reasons
        },
        "top_requesters": [{"ip": ip, "requests": count} for ip, count in top_ips],
        "anomalous_ips": anomalous_ips[:20],
        "status_distribution": dict(status_codes),
        "attack_signatures": len(signatures),
        "recommendations": []
    }

    # Add recommendations based on findings
    if threat_level in ("high", "critical"):
        report["recommendations"].extend([
            "URGENT: Implement rate limiting immediately",
            "Consider blocking anomalous IPs at firewall",
            "Enable DDoS protection service if available",
            "Scale infrastructure if legitimate traffic mixed in"
        ])
    elif threat_level == "medium":
        report["recommendations"].extend([
            "Monitor situation closely",
            "Prepare rate limiting rules",
            "Review and block suspicious IPs"
        ])
    else:
        report["recommendations"].append("No immediate action required - continue monitoring")

    if output_format == "summary":
        return json.dumps({
            "threat_level": threat_level,
            "threat_score": threat_score,
            "entries_analyzed": len(entries),
            "anomalous_ips": len(anomalous_ips),
            "recommendations": report["recommendations"][:3]
        }, indent=2)

    return json.dumps(report, indent=2)


@mcp.tool()
async def get_attack_indicators(log_path: str) -> str:
    """
    Extract Indicators of Compromise (IoCs) from attack analysis.

    Args:
        log_path: Path to access log

    Returns:
        JSON with IoCs that can be used for blocking/alerting
    """
    path = Path(log_path)
    if not path.exists():
        return json.dumps({"success": False, "error": f"Log file not found: {log_path}"})

    ip_requests = defaultdict(int)
    malicious_paths = set()
    malicious_user_agents = set()
    suspicious_ips = set()

    try:
        with open(path, 'r', errors='ignore') as f:
            for i, line in enumerate(f):
                if i >= 100000:
                    break
                parsed = parse_log_line(line)
                if parsed:
                    ip = parsed['ip']
                    ip_requests[ip] += 1
                    path_str = parsed.get('path', '')
                    ua = parsed.get('user_agent', '')

                    # Check attack patterns
                    for pattern in ATTACK_PATTERNS['paths']:
                        if re.search(pattern, path_str, re.IGNORECASE):
                            malicious_paths.add(path_str[:100])
                            suspicious_ips.add(ip)

                    for pattern in ATTACK_PATTERNS['user_agents']:
                        if re.search(pattern, ua, re.IGNORECASE):
                            malicious_user_agents.add(ua[:100])
                            suspicious_ips.add(ip)
    except Exception as e:
        return json.dumps({"success": False, "error": str(e)})

    # Find high-volume IPs
    avg_requests = statistics.mean(ip_requests.values()) if ip_requests else 0
    high_volume_threshold = avg_requests * 10
    high_volume_ips = {ip for ip, count in ip_requests.items() if count > high_volume_threshold}

    return json.dumps({
        "success": True,
        "indicators_of_compromise": {
            "suspicious_ips": list(suspicious_ips)[:50],
            "high_volume_ips": list(high_volume_ips)[:50],
            "malicious_paths": list(malicious_paths)[:30],
            "suspicious_user_agents": list(malicious_user_agents)[:20]
        },
        "totals": {
            "suspicious_ips": len(suspicious_ips),
            "high_volume_ips": len(high_volume_ips),
            "malicious_paths": len(malicious_paths),
            "suspicious_user_agents": len(malicious_user_agents)
        },
        "blocking_rules": {
            "iptables_example": f"iptables -A INPUT -s {list(suspicious_ips)[0] if suspicious_ips else '1.2.3.4'} -j DROP",
            "nginx_deny": [f"deny {ip};" for ip in list(suspicious_ips)[:5]],
            "fail2ban_note": "Add suspicious IPs to fail2ban jail"
        }
    }, indent=2)


@mcp.tool()
async def simulate_dos_metrics(
    baseline_rps: float = 10.0,
    attack_multiplier: float = 10.0,
    attack_duration_seconds: int = 300
) -> str:
    """
    Generate simulated DoS attack metrics for testing/training.

    Args:
        baseline_rps: Normal traffic requests per second
        attack_multiplier: How much attack amplifies traffic
        attack_duration_seconds: Length of simulated attack

    Returns:
        JSON with simulated attack metrics
    """
    import random

    # Generate timeline
    timeline = []
    current_time = datetime.now()

    # Pre-attack (normal traffic)
    for i in range(60):
        timeline.append({
            "timestamp": (current_time - timedelta(seconds=360-i*6)).isoformat(),
            "rps": baseline_rps + random.uniform(-2, 2),
            "phase": "normal"
        })

    # Attack ramp-up
    for i in range(10):
        multiplier = 1 + (attack_multiplier - 1) * (i / 10)
        timeline.append({
            "timestamp": (current_time - timedelta(seconds=300-i*6)).isoformat(),
            "rps": baseline_rps * multiplier + random.uniform(-5, 5),
            "phase": "ramp_up"
        })

    # Full attack
    for i in range(int(attack_duration_seconds / 6)):
        timeline.append({
            "timestamp": (current_time - timedelta(seconds=240-i*6)).isoformat(),
            "rps": baseline_rps * attack_multiplier + random.uniform(-20, 20),
            "phase": "attack"
        })

    # Attack subsiding
    for i in range(10):
        multiplier = attack_multiplier - (attack_multiplier - 1) * (i / 10)
        timeline.append({
            "timestamp": (current_time - timedelta(seconds=60-i*6)).isoformat(),
            "rps": baseline_rps * multiplier + random.uniform(-5, 5),
            "phase": "subsiding"
        })

    return json.dumps({
        "success": True,
        "simulation": {
            "baseline_rps": baseline_rps,
            "attack_multiplier": attack_multiplier,
            "peak_rps": baseline_rps * attack_multiplier,
            "attack_duration_seconds": attack_duration_seconds
        },
        "timeline": timeline,
        "detection_thresholds": {
            "warning": baseline_rps * 2,
            "alert": baseline_rps * 5,
            "critical": baseline_rps * 10
        },
        "note": "Use this data to test alerting and detection systems"
    }, indent=2)


def main():
    """Run the DoS detector MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()
