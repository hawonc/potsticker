# Potsticker

A self-evolving honeypot system for WiFi security monitoring and attack detection.

Potsticker combines WiFi attack detection with adaptive honeypot technology. When attacks are detected, the system dynamically generates deceptive services using an LLM to lure and study attackers.

## Architecture

```
potsticker/
├── wifi/          # WiFi attack detection and monitoring
├── pots/          # Honeypot Flask server (containerized)
├── ai/            # LLM-powered honeypot evolution
```

## Features

- Real-time detection of deauthentication attacks and WPS brute force attempts
- AI-generated Flask servers with fake credentials, XSS vulnerabilities, and simulated command injection
- Web dashboard for monitoring and controlling detection systems
- Serial communication with FreeWilie board for creating decoy WiFi networks
- Docker-based honeypot services for isolation

---

## Modules

### wifi/ — WiFi Security Monitoring

Real-time detection of wireless attacks using Scapy packet sniffing.

| File | Description |
|------|-------------|
| `wifi.py` | Main `WiFiMonitor` class with threaded detection for deauth/WPS attacks |
| `detect_deauth.py` | Detects deauthentication floods (threshold: 10 packets/5 seconds) |
| `detect_wps_bf.py` | Detects WPS PIN brute force via EAPOL packet analysis |
| `web_server.py` | Flask web interface (port 6767) with REST API for control |
| `scap.py` | Low-level packet handler for debugging deauth/EAPOL packets |
| `trigger_attacks.py` | Test utility to simulate attacks for detection validation |

When an attack is detected:
1. Detection triggers callback
2. Creates decoy WiFi network via serial (FreeWilie board)
3. Connects monitoring system to honeypot network
4. Logs attacker activity

Usage:
```bash
cd wifi
pip install -r requirements.txt
sudo python wifi.py <interface>          # CLI mode
sudo python web_server.py                # Web interface at http://localhost:6767
```

### pots/ — Honeypot Server

Containerized Flask server designed to attract and log attacker reconnaissance.

| File | Description |
|------|-------------|
| `main.py` | Base Flask server with access logging |
| `temptation.py` | Enhanced honeypot with fake creds, XSS, command injection simulation |
| `access_log.txt` | Logs all endpoint access with IP/timestamp |
| `Dockerfile` | Python 3.11 slim container configuration |
| `docker-compose.yaml` | Service definition exposing port 3000 |

Possible Honeypot endpoints:
- `/robots.txt` — Reveals "disallowed" sensitive paths
- `/passwords` — Fake credentials JSON
- `/admin`, `/wp-admin` — Fake login portals
- `/search?q=` — Reflected XSS vulnerability
- `/ping?host=` — Simulated command injection
- `/api/v1/secrets` — Fake AWS keys and config

Deployment:
```bash
cd pots
docker-compose up -d
# Access at http://localhost:3000
```

### ai/ — LLM-Powered Evolution

Uses Google Gemini to analyze access logs and generate new honeypot configurations.

| File | Description |
|------|-------------|
| `main.py` | CLI tool to query Gemini with file context |
| `prompts/flask_gen.md` | System prompt for generating Flask honeypot code |

How it works:
1. Reads honeypot access logs
2. Sends logs and template to Gemini
3. LLM generates new Flask server with additional lures based on attacker behavior
4. Outputs deployable Python code

Usage:
```bash
cd ai
export GEMINI_API_KEY="your-key"
uv run main.py <template.py> <access_log.txt> <prompt.md> [output.py]
```

---

## Getting Started

### Prerequisites
- Python 3.11+
- Docker and Docker Compose
- Root/sudo access (for packet sniffing)
- Scapy-compatible network interface
- (Optional) FreeWilie board for decoy network creation

### Installation

```bash
# Clone the repository
git clone <repo-url> && cd potsticker

# WiFi monitoring
cd wifi && pip install -r requirements.txt

# Honeypot (Docker)
cd ../pots && docker-compose up -d

# AI module
cd ../ai && pip install google-genai python-dotenv
```

### Running the Full System

Terminal 1 — Start honeypot:
```bash
cd pots && docker-compose up
```

Terminal 2 — Start WiFi monitoring web interface:
```bash
cd wifi && sudo python web_server.py
```

Terminal 3 — (Optional) Simulate attacks for testing:
```bash
cd wifi && sudo python trigger_attacks.py <interface>
```

---

## Configuration

| Component | Port | Config File |
|-----------|------|-------------|
| WiFi Web UI | 6767 | `wifi/web_server.py` |
| Honeypot | 3000 | `pots/docker-compose.yaml` |
| Serial (FreeWilie) | COM3 | `wifi/web_server.py` |

### Environment Variables

```bash
# For AI module
GEMINI_API_KEY=your-google-genai-api-key
```

---

## Detection Thresholds

| Attack Type | Packets | Time Window | Cooldown |
|-------------|---------|-------------|----------|
| Deauthentication | 10+ | 5 seconds | 30 seconds |
| WPS Brute Force | 10+ | 5 seconds | 30 seconds |

---

## Disclaimer

This tool is intended for authorized security testing only. Sending deauthentication packets or monitoring networks without explicit permission is illegal in most jurisdictions. Use only on networks you own or have written authorization to test.
