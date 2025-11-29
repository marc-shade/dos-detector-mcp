# DoS Detector MCP Server

Denial of Service attack detection through log analysis and traffic pattern recognition.

## Features

- **Log Analysis**: Parse Apache, Nginx, auth logs for attack patterns
- **IP Rate Analysis**: Detect IPs exceeding request thresholds
- **Attack Pattern Detection**: SYN flood, HTTP flood, Slowloris signatures
- **Anomaly Detection**: Statistical analysis for unusual traffic patterns
- **Bandwidth Monitoring**: Track transfer rates and spikes
- **Real-time Alerts**: Trigger alerts for detected attacks

## Tools

| Tool | Description |
|------|-------------|
| `analyze_access_log` | Parse web server logs for DoS indicators |
| `detect_syn_flood` | Analyze connection patterns for SYN floods |
| `detect_http_flood` | Find HTTP request flooding patterns |
| `detect_slowloris` | Identify slow HTTP attacks |
| `analyze_ip_rates` | Rate analysis per IP address |
| `detect_amplification` | Check for reflection/amplification attacks |
| `generate_dos_report` | Comprehensive attack analysis report |
| `get_attack_indicators` | List of IoCs from detected attacks |

## Attack Detection Thresholds

Default thresholds (configurable):
- **HTTP Flood**: >100 requests/minute from single IP
- **SYN Flood**: >50 half-open connections/second
- **Slowloris**: >10 concurrent slow connections
- **Bandwidth Spike**: >300% of baseline

## Log Formats Supported

- Apache Combined/Common Log Format
- Nginx default log format
- Linux auth.log / secure log
- Custom formats via regex
