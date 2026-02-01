# Potsticker

**A self-evolving honeypot system for WiFi security monitoring and attack detection**

Potsticker is an advanced WiFi security monitoring system that detects and responds to common WiFi attacks including deauthentication attacks and WPS brute force attempts. The system includes both command-line tools and a modern web interface for real-time monitoring and control.

## Features

### Attack Detection
- **Deauthentication Attack Detection**: Monitors for deauth packet floods that force clients to disconnect from access points
- **WPS Brute Force Detection**: Detects WPS PIN brute forcing attempts through EAPOL packet analysis
- **Configurable Thresholds**: Default detection at 10+ packets within 5 seconds
- **Real-time Alerts**: Immediate notification of detected attacks with attacker MAC addresses and target information

### Monitoring Capabilities
- **Web Interface**: Modern, responsive dashboard for monitoring and control
- **Attack Logging**: Persistent log of all detected attacks with timestamps and details
- **Multi-threaded Detection**: Parallel monitoring of multiple attack types
- **Callback System**: Extensible handler system for custom attack responses

### Testing Tools
- **Attack Simulation**: Built-in tools to test detection systems with simulated attacks
- **Packet Crafting**: Generate realistic deauth and EAPOL packets for testing
- **Configurable Parameters**: Adjust packet counts and timing for thorough testing

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
  - [Command-Line Interface](#command-line-interface)
  - [Web Interface](#web-interface)
  - [Testing Tools](#testing-tools)
- [Architecture](#architecture)
- [Configuration](#configuration)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)
- [License](#license)

## Prerequisites

### System Requirements
- **Operating System**: Linux or macOS
- **Python**: 3.11 or higher
- **Root Privileges**: Required for packet sniffing and injection
- **Network Interface**: WiFi adapter capable of monitor mode (for production use)

### macOS Specific
- On macOS, the default WiFi interface is typically `en0`
- Some features may be limited compared to Linux due to driver restrictions

### Linux Specific
- WiFi adapter that supports monitor mode
- Common interfaces: `wlan0`, `wlan1`, `wlp3s0`, etc.
- May require additional wireless tools (`aircrack-ng` suite for advanced features)

## Installation

### 1. Clone the Repository

```bash
cd /path/to/your/projects
git clone https://github.com/yourusername/potsticker.git
cd potsticker
```

### 2. Navigate to the WiFi Module

```bash
cd wifi
```

### 3. Install Dependencies

#### Using pip (Recommended)

```bash
pip install -r requirements.txt
```

This installs:
- `scapy>=2.5.0` - Packet manipulation and sniffing
- `flask>=2.3.0` - Web framework
- `flask-cors>=4.0.0` - Cross-Origin Resource Sharing support

#### Using pyproject.toml (Optional)

```bash
pip install -e .
```

### 4. Verify Installation

```bash
python -c "import scapy; import flask; print('Dependencies installed successfully!')"
```

## Usage

### Command-Line Interface

#### Basic Monitoring

Monitor for all attack types on a specific interface:

```bash
sudo python wifi.py <interface>
```

**Examples:**
```bash
# macOS
sudo python wifi.py en0

# Linux
sudo python wifi.py wlan0
```

#### Individual Detection Modules

Run detection modules separately:

**Deauthentication Detection:**
```bash
sudo python detect_deauth.py <interface>
```

**WPS Brute Force Detection:**
```bash
sudo python detect_wps_bf.py <interface>
```

#### Using as a Python Module

```python
from wifi import WiFiMonitor

# Initialize monitor
monitor = WiFiMonitor("wlan0")

# Start all detection
monitor.start_all()

# Or start individually
monitor.start_deauth_detection()
monitor.start_wps_detection()

# Check status
status = monitor.status()
print(f"Deauth running: {status['deauth_running']}")
print(f"WPS running: {status['wps_running']}")

# Stop all
monitor.stop_all()
```

**Custom Callbacks:**
```python
def my_deauth_handler(attack_info):
    print(f"Attack from: {attack_info['attacker_mac']}")
    # Custom response logic here

def my_wps_handler(attack_info):
    print(f"WPS attack detected: {attack_info['target_ap']}")
    # Custom response logic here

monitor = WiFiMonitor("wlan0", my_deauth_handler, my_wps_handler)
monitor.start_all()
```

### Web Interface

#### Starting the Web Server

```bash
sudo python web_server.py
```

The server starts on `http://localhost:6767`

#### Accessing the Dashboard

1. Open your browser to `http://localhost:6767`
2. Enter your network interface (e.g., `en0` or `wlan0`)
3. Click "Initialize" to start the monitoring system
4. Use the control panel to start/stop individual detection systems
5. View real-time attack logs in the dashboard

### Testing Tools

#### Trigger Attack Simulation

Test your detection systems with simulated attacks:

**Full Simulation (Both Attacks):**
```bash
sudo python trigger_attacks.py <interface>
```

**Deauthentication Only:**
```bash
sudo python trigger_attacks.py <interface> --deauth-only
```

**WPS Brute Force Only:**
```bash
sudo python trigger_attacks.py <interface> --wps-only
```

**Custom Packet Count:**
```bash
sudo python trigger_attacks.py <interface> --count 20
```

**Custom Delay:**
```bash
sudo python trigger_attacks.py <interface> --delay 0.2
```

#### Testing Workflow

For comprehensive testing, run these commands in separate terminals:

**Terminal 1 - Monitor:**
```bash
cd /path/to/potsticker/wifi
sudo python wifi.py en0
```

**Terminal 2 - Simulate Attack:**
```bash
cd /path/to/potsticker/wifi
sudo python trigger_attacks.py en0
```

Expected output in Terminal 1:
```
[2026-01-31 10:30:45] Deauthentication Attack Detected!
Attacker MAC: aa:bb:cc:dd:ee:ff
Target AP: 11:22:33:44:55:66
Packet count: 15 in 5 seconds
------------------------------------------------------------

[2026-01-31 10:30:48] WPS Brute Force Attack Detected!
Attacker MAC: aa:bb:cc:dd:ee:ff
Target AP: 11:22:33:44:55:66
Packet count: 15 in 5 seconds
------------------------------------------------------------
```

## Architecture

### Components

#### Core Detection Modules

**`detect_deauth.py`**
- Monitors Dot11Deauth frames
- Threshold: 10 packets in 5 seconds
- Extracts attacker MAC, target AP, and affected devices
- Supports custom callbacks for attack response

**`detect_wps_bf.py`**
- Monitors EAPOL frames (WPS handshakes)
- Threshold: 10 packets in 5 seconds
- Detects rapid WPS PIN attempts
- Tracks attacker patterns

**`wifi.py`**
- Main WiFiMonitor class
- Threading management for parallel detection
- Callback system for extensibility
- Status monitoring and control

#### Web Interface

**`web_server.py`**
- Flask-based REST API
- Endpoints for start/stop control
- Attack logging with history
- CORS-enabled for frontend access

**Frontend (HTML/CSS/JS)**
- Real-time status updates (2-second polling)
- Attack log visualization
- Responsive design with dark theme
- Notification system for user feedback

#### Testing Tools

**`trigger_attacks.py`**
- Packet crafting using Scapy
- Configurable attack simulations
- Supports both deauth and EAPOL injection
- Safety checks and warnings

### Detection Algorithm

Both detection modules use a sliding window algorithm:

1. **Packet Capture**: Monitor network interface for specific frame types
2. **Windowing**: Track packets in 5-second windows per MAC address
3. **Threshold Check**: Alert when packet count exceeds 10
4. **Cooldown**: 30-second cooldown between alerts per MAC
5. **Callback**: Execute custom handler with attack details

## Configuration

### Detection Thresholds

Edit in `detect_deauth.py` or `detect_wps_bf.py`:

```python
DEAUTH_THRESHOLD = 10    # Number of packets to trigger alert
TIME_WINDOW = 5          # Time window in seconds
```

### Cooldown Period

Modify alert cooldown (prevents spam):

```python
if now - last_alert[src_mac] > 30:  # 30 seconds between alerts
```

### Web Server Port

Edit in `web_server.py`:

```python
app.run(host='0.0.0.0', port=6767, debug=True)
```

### Attack Log Size

Maximum number of logged attacks:

```python
max_log_entries = 100  # In web_server.py
```

## Security Considerations

### Legal and Ethical Use

**WARNING**: This tool is for educational and authorized testing purposes only.

- **Only use on networks you own or have explicit written permission to test**
- Sending deauthentication packets to networks without permission is **illegal** in most jurisdictions
- Packet injection may violate computer fraud laws (e.g., CFAA in the US)
- Use the attack simulation tools only in isolated test environments

### Root Privileges

The tools require root access for:
- Raw packet capture (promiscuous mode)
- Packet injection
- Monitor mode interface control

**Best Practices:**
- Use a dedicated testing machine or VM
- Don't run the web server as root in production (use a reverse proxy)
- Review code before running with sudo
- Monitor system logs for unexpected activity

### Network Isolation

For testing:
- Use isolated WiFi networks (separate from production)
- Consider using a separate subnet or VLAN
- Use test equipment that won't affect critical infrastructure

## Troubleshooting

### Common Issues

#### Permission Denied

```bash
[!] Permission denied. Run with sudo
```

**Solution:**
```bash
sudo python wifi.py en0
```

#### Interface Not Found

```bash
OSError: [Errno 19] No such device: wlan0
```

**Solution:** Check available interfaces:
```bash
# macOS
ifconfig

# Linux
ip link show
# or
iwconfig
```

#### No Packets Detected

**Possible Causes:**
- Interface not in monitor mode (Linux)
- No actual attacks occurring
- Wrong interface selected
- Driver limitations (especially on macOS)

**Solutions:**
1. Verify interface: `ifconfig <interface>`
2. Test with simulation: `sudo python trigger_attacks.py <interface>`
3. Check for packet capture: `sudo tcpdump -i <interface>`

#### Web Server Won't Start

```bash
Address already in use
```

**Solution:**
```bash
# Find process using port 6767
lsof -i :6767

# Kill the process
kill -9 <PID>
```

#### Import Errors

```bash
ModuleNotFoundError: No module named 'scapy'
```

**Solution:**
```bash
pip install -r requirements.txt
```

### Debugging

#### Enable Verbose Output

Modify Scapy sniffing to show packets:

```python
sniff(iface=interface, prn=process_packet, store=False)  # verbose=True
```

#### Check Packet Capture

Verify packets are being captured:

```bash
sudo tcpdump -i en0 -e -n type mgt subtype deauth
```

#### Test Network Interface

```bash
# List all interfaces
python -c "from scapy.all import *; print(get_if_list())"

# Test packet capture
sudo python -c "from scapy.all import *; sniff(iface='en0', count=5, prn=lambda x: x.summary())"
```

## Development Notes

### Adding Custom Detection

To add new attack detection:

1. Create new detector file (e.g., `detect_evil_twin.py`)
2. Implement detection function with callback support
3. Add thread management to `wifi.py`
4. Create API endpoints in `web_server.py`
5. Update frontend controls in `index.html` and `script.js`

### Extending Attack Responses

Modify default handlers in `wifi.py`:

```python
def _default_deauth_handler(self, attack_info):
    # Add your response logic
    # e.g., create honeypot AP, block attacker, log to SIEM, etc.
    pass
```

### Testing in Monitor Mode (Linux)

```bash
# Enable monitor mode
sudo ip link set wlan0 down
sudo iw wlan0 set monitor control
sudo ip link set wlan0 up

# Verify
iwconfig wlan0
```

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Submit a pull request

## License

[Specify your license here]

## Acknowledgments

- Built with [Scapy](https://scapy.net/) for packet manipulation
- Web interface powered by [Flask](https://flask.palletsprojects.com/)
- Inspired by network security research and honeypot systems

---

**Disclaimer**: This tool is provided for educational and authorized security testing purposes only. Users are responsible for ensuring they have proper authorization before using this tool on any network.
