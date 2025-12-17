# DoS Detector MCP Server

[![MCP](https://img.shields.io/badge/MCP-Compatible-blue)](https://modelcontextprotocol.io)
[![Python-3.10+](https://img.shields.io/badge/Python-3.10%2B-green)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)
[![Part of Agentic System](https://img.shields.io/badge/Part_of-Agentic_System-brightgreen)](https://github.com/marc-shade/agentic-system-oss)

> **DoS attack detection and mitigation monitoring.**

Part of the [Agentic System](https://github.com/marc-shade/agentic-system-oss) - a 24/7 autonomous AI framework with persistent memory.

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
---

## Part of the MCP Ecosystem

This server integrates with other MCP servers for comprehensive AGI capabilities:

| Server | Purpose |
|--------|---------|
| [enhanced-memory-mcp](https://github.com/marc-shade/enhanced-memory-mcp) | 4-tier persistent memory with semantic search |
| [agent-runtime-mcp](https://github.com/marc-shade/agent-runtime-mcp) | Persistent task queues and goal decomposition |
| [agi-mcp](https://github.com/marc-shade/agi-mcp) | Full AGI orchestration with 21 tools |
| [cluster-execution-mcp](https://github.com/marc-shade/cluster-execution-mcp) | Distributed task routing across nodes |
| [node-chat-mcp](https://github.com/marc-shade/node-chat-mcp) | Inter-node AI communication |
| [ember-mcp](https://github.com/marc-shade/ember-mcp) | Production-only policy enforcement |

See [agentic-system-oss](https://github.com/marc-shade/agentic-system-oss) for the complete framework.
