"""
Web interface for WiFi Security Monitoring System
"""

from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
from wifi import WiFiMonitor
import threading
import time
from datetime import datetime
import serial as serington
import random
import os
import subprocess
import tempfile
import sys
from pathlib import Path
from scapy.all import *
from scapy.layers.eap import EAP, EAPOL
import hashlib
from scapy.all import RadioTap
from scapy.layers.dot11 import Dot11, Dot11Auth
import re

# Add parent directory to path to import ai module
sys.path.insert(0, str(Path(__file__).parent.parent))
from ai.main import process_flask_file


  #time keep
_LAST_AP_TS = 0.0   # last time we actually ran the AP-create 
_COOLDOWN_S = 5.0   # X seconds (can be altered)
app = Flask(__name__)
CORS(app)

# Global monitor instance
monitor = None
attack_log = []
max_log_entries = 100

#creates a new network on the FreeWilie board
def custom_network_pot(x = 0):
  

# Configure the serial port parameters
# Replace 'COM4' with your port name (e.g., '/dev/ttyUSB0' on Linux or 'COM1' on Windows)
# Replace 9600 with the baud rate required by your device
    ser = serington.Serial(
        port='COM3',
        baudrate=9600,
        bytesize=serington.EIGHTBITS,
        parity=serington.PARITY_NONE,
        stopbits=serington.STOPBITS_ONE,
        timeout=1 # Set a timeout (in seconds)
    )
    try:
        # Wait a moment for the connection to establish
        time.sleep(.1)

        if ser.is_open:
            print(f"Serial port {ser.port} opened successfully.")

            # Data must be sent as bytes. Encode the string to bytes.
            waiting = '\n'
            data_to_send = f'e\\w\\a fakeeduroam password1 {x} 0' # The 'b' prefix creates a bytes object
            # Alternatively, use: data_to_send = bytes('Hello, world!\n', 'utf-8')
            ser.write(waiting.encode('utf-8'))
            ser.write(waiting.encode('utf-8'))
            time.sleep(0.3) # Wait for device to respond
            ser.write(data_to_send.encode('utf-8'))
            ser.write(waiting.encode('utf-8'))
            #ser.write(data_to_send.encode('utf-8'))
            print(f"Sent data: {data_to_send}")

            # Optional: Read response
            time.sleep(0.1) # Wait for device to respond
            if ser.in_waiting > 0:
                response = ser.readline().decode('utf-8').strip()
                print(f"Received response: {response}")
        else:
            print("Failed to open serial port.")

    except serington.SerialException as e:
        print(f"Error: {e}")

    finally:
        # Always close the port when done to free the resource
        if ser.is_open:
            ser.close()
            print(f"Serial port {ser.port} closed.")





#function to pull AP: MAC, IP, and SSID from serial
def info_pull():
    """
    Query serial device and return cleaned AP info string:
    'MAC: xx IP: x.x.x.x SSID: name'
    Returns None if not found.
    """

    ser = serington.Serial(
        port="COM3",
        baudrate=9600,
        bytesize=serington.EIGHTBITS,
        parity=serington.PARITY_NONE,
        stopbits=serington.STOPBITS_ONE,
        timeout=0.2
    )

    try:
        # allow port to settle
        time.sleep(0.3)

        # send command
        ser.write(b"e\\w\\p\r\n")

        # wait for device to respond
        time.sleep(0.5)

        raw_lines = []
        start = time.time()

        # read everything for ~2.5 seconds
        while time.time() - start < 2.5:
            line = ser.readline().decode(errors="ignore").strip()
            if line:
                raw_lines.append(line)

        raw_text = " ".join(raw_lines)

        # extract AP section (second MAC)
        match = re.search(
            r"AP\s+MAC:\s*([0-9a-f:]+)\s+IP:\s*([0-9.]+)\s+SSID:\s*(.*?)\s+Password:",
            raw_text,
            re.IGNORECASE
        )

        if not match:
            return None

        mac, ip, ssid = match.groups()
        return f"MAC: {mac} IP: {ip} SSID: {ssid.strip()}"

    except serington.SerialException:
        return None

    finally:
        if ser.is_open:
            ser.close()


#connectiion to the new fakeeduroam // testing dont push till it works or something
def connect_fakeeduroam():
    ssid = "fakeeduroam"
    pw = "password1"

    profile = f"""<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
  <name>{ssid}</name>
  <SSIDConfig><SSID><name>{ssid}</name></SSID></SSIDConfig>
  <connectionType>ESS</connectionType>
  <connectionMode>auto</connectionMode>
  <MSM>
    <security>
      <authEncryption>
        <authentication>WPA2PSK</authentication>
        <encryption>AES</encryption>
        <useOneX>false</useOneX>
      </authEncryption>
      <sharedKey>
        <keyType>passPhrase</keyType>
        <protected>false</protected>
        <keyMaterial>{pw}</keyMaterial>
      </sharedKey>
    </security>
  </MSM>
</WLANProfile>
"""

    with tempfile.TemporaryDirectory() as td:
        xml_path = Path(td) / f"{ssid}.xml"
        xml_path.write_text(profile, encoding="utf-8")

        subprocess.run(
            ["netsh", "wlan", "add", "profile", f"filename={str(xml_path)}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        subprocess.run(
            ["netsh", "wlan", "connect", f"name={ssid}", f"ssid={ssid}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )




def log_attack(attack_type, attack_info):
    """Log attack information"""
    global attack_log
    entry = {
        'timestamp': datetime.now().isoformat(),
        'type': attack_type,
        'info': attack_info
    }
    attack_log.insert(0, entry)
    if len(attack_log) > max_log_entries:
        attack_log = attack_log[:max_log_entries]
    

def custom_deauth_handler(attack_info):
    """Custom deauth handler that logs attacks"""
    log_attack('deauth', attack_info)
    print(f"\n>>> DEAUTH ATTACK DETECTED from {attack_info['attacker_mac']}")
    print(f">>> Target AP: {attack_info['target_ap']}")
    print(f">>> Affected devices: {attack_info['all_macs']}")
    custom_network_pot(3)
    for i in range(10):
        sendp(make_auth_exchange(attack_info['target_ap'], attack_info['attacker_mac']), iface=monitor.interface, verbose=False)
    time.sleep(.10)
    connect_fakeeduroam()

def custom_wps_handler(attack_info):
    """Custom WPS handler that logs attacks"""
    log_attack('wps', attack_info)
    print(f"\n>>> WPS BRUTE FORCE DETECTED from {attack_info['attacker_mac']}")
    print(f">>> Target AP: {attack_info['target_ap']}")
    print(f">>> Involved devices: {attack_info['all_macs']}")
    
    for j in range(10):
        sendp(eap_failure(attack_info['target_ap'], attack_info['attacker_mac']), iface=monitor.interface, verbose=False)
    custom_network_pot(3)
    time.sleep(.10)
    connect_fakeeduroam()
    for i in range(10):
        sendp(eap_success(attack_info['target_ap'], attack_info['attacker_mac']), iface=monitor.interface, verbose=False)
    

def eap_success(src_mac, dst_mac, identifier=0):
    """
    Create an EAP-Success frame.

    :param src_mac: Source MAC address
    :param dst_mac: Destination MAC address
    :param identifier: EAP Identifier (usually matches the request)
    :return: Scapy packet
    """
    return (
        Ether(src=src_mac, dst=dst_mac)
        / EAPOL(version=1, type=0)   # type=0 => EAP packet
        / EAP(code=3, id=identifier) # code=3 => Success
    )


def eap_failure(src_mac, dst_mac, identifier=0):
    """
    Create an EAP-Failure frame.

    :param src_mac: Source MAC address
    :param dst_mac: Destination MAC address
    :param identifier: EAP Identifier (usually matches the request)
    :return: Scapy packet
    """
    return (
        Ether(src=src_mac, dst=dst_mac)
        / EAPOL(version=1, type=0)
        / EAP(code=4, id=identifier) # code=4 => Failure
    )

"""def websocket_honeypot():
    ser = serial.Serial(
        port='COM3',
        baudrate=9600,
        bytesize=serial.EIGHTBITS,
        parity=serial.PARITY_NONE,
        stopbits=serial.STOPBITS_ONE,
        timeout=1 # Set a timeout (in seconds)
    )
    try:
        # Wait a moment for the connection to establish
        time.sleep(.1)

        if ser.is_open:
            print(f"Serial port {ser.port} opened successfully.")

            # Data must be sent as bytes. Encode the string to bytes.
            waiting = '\n'
            data_to_send = f'e\\(TODO)\\r on\\p 8765\\m password\\u admin\\p {os.getenv("WS_PASSWORD")}'
            # Alternatively, use: data_to_send = bytes('Hello, world!\n', 'utf-8')
            ser.write(waiting.encode('utf-8'))
            ser.write(waiting.encode('utf-8'))
            time.sleep(0.3) # Wait for device to respond
            ser.write(data_to_send.encode('utf-8'))
            ser.write(waiting.encode('utf-8'))
            #ser.write(data_to_send.encode('utf-8'))
            print(f"Sent data: {data_to_send}")

            # Optional: Read response
            time.sleep(0.1) # Wait for device to respond
            if ser.in_waiting > 0:
                response = ser.readline().decode('utf-8').strip()
                print(f"Received response: {response}")
        else:
            print("Failed to open serial port.")

    except serial.SerialException as e:
        print(f"Error: {e}")

    finally:
        # Always close the port when done to free the resource
        if ser.is_open:
            ser.close()
            print(f"Serial port {ser.port} closed.")"""

import hashlib
from scapy.layers.dot11 import Dot11, Dot11Auth


def make_auth_exchange(
    sta_mac: str,
    ap_mac: str,
    *,
    algo: int = 0,
    failure_status: int = 1,
):
    # ---- STA -> AP (Authentication request, seq 1) ----
    sta_req = (
        RadioTap()
        / Dot11(
            type=0,
            subtype=11,
            addr1=ap_mac,
            addr2=sta_mac,
            addr3=ap_mac,
        )
        / Dot11Auth(algo=algo, seqnum=1, status=0)
    )

    # hash ONLY the STA request (stable: no Radiotap)
    sta_req_hash = hashlib.sha256(bytes(sta_req[Dot11])).hexdigest()

    # ---- AP -> STA (Authentication response, seq 2) ----
    ap_hdr = Dot11(
        type=0,
        subtype=11,
        addr1=sta_mac,
        addr2=ap_mac,
        addr3=ap_mac,
    )

    ap_success = RadioTap() / ap_hdr / Dot11Auth(algo=algo, seqnum=2, status=0)
    ap_failure = RadioTap() / ap_hdr / Dot11Auth(algo=algo, seqnum=2, status=int(failure_status))

    return sta_req, sta_req_hash, ap_success, ap_failure



# Example:
# sta, ok, bad = make_80211_auth_exchange(
#     sta_mac="aa:bb:cc:dd:ee:ff",
#     ap_mac="11:22:33:44:55:66",
#     failure_status=13,
# )
# sta.show()
# ok.show()
# bad.show()





@app.route('/')
def index():
    """Serve the main page"""
    return render_template('index.html')

@app.route('/api/status')
def get_status():
    """Get current monitoring status"""
    if monitor is None:
        return jsonify({
            'initialized': False,
            'interface': None,
            'deauth_running': False,
            'wps_running': False
        })
    
    status = monitor.status()
    status['initialized'] = True
    return jsonify(status)

@app.route('/api/initialize', methods=['POST'])
def initialize_monitor():
    """Initialize the monitor with an interface"""
    global monitor
    
    data = request.json
    interface = data.get('interface')
    
    if not interface:
        return jsonify({'success': False, 'error': 'Interface required'}), 400
    
    try:
        monitor = WiFiMonitor(interface, custom_deauth_handler, custom_wps_handler)
        return jsonify({'success': True, 'message': f'Monitor initialized on {interface}'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/start/deauth', methods=['POST'])
def start_deauth():
    """Start deauth detection"""
    if monitor is None:
        return jsonify({'success': False, 'error': 'Monitor not initialized'}), 400
    
    try:
        success = monitor.start_deauth_detection()
        return jsonify({'success': success, 'message': 'Deauth detection started' if success else 'Already running'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/start/wps', methods=['POST'])
def start_wps():
    """Start WPS detection"""
    if monitor is None:
        return jsonify({'success': False, 'error': 'Monitor not initialized'}), 400
    
    try:
        success = monitor.start_wps_detection()
        return jsonify({'success': success, 'message': 'WPS detection started' if success else 'Already running'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/start/all', methods=['POST'])
def start_all():
    """Start all detection"""
    if monitor is None:
        return jsonify({'success': False, 'error': 'Monitor not initialized'}), 400
    
    try:
        monitor.start_all()
        return jsonify({'success': True, 'message': 'All detection started'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/stop/deauth', methods=['POST'])
def stop_deauth():
    """Stop deauth detection"""
    if monitor is None:
        return jsonify({'success': False, 'error': 'Monitor not initialized'}), 400
    
    try:
        success = monitor.stop_deauth_detection()
        return jsonify({'success': success, 'message': 'Deauth detection stopped'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/stop/wps', methods=['POST'])
def stop_wps():
    """Stop WPS detection"""
    if monitor is None:
        return jsonify({'success': False, 'error': 'Monitor not initialized'}), 400
    
    try:
        success = monitor.stop_wps_detection()
        return jsonify({'success': success, 'message': 'WPS detection stopped'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/stop/all', methods=['POST'])
def stop_all():
    """Stop all detection"""
    if monitor is None:
        return jsonify({'success': False, 'error': 'Monitor not initialized'}), 400
    
    try:
        monitor.stop_all()
        return jsonify({'success': True, 'message': 'All detection stopped'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/attacks')
def get_attacks():
    """Get attack log"""
    return jsonify({'attacks': attack_log})

@app.route('/api/attacks/clear', methods=['POST'])
def clear_attacks():
    """Clear attack log"""
    global attack_log
    attack_log = []
    return jsonify({'success': True, 'message': 'Attack log cleared'})

# Paths for honeypot files
POTS_DIR = Path(__file__).parent.parent / 'pots'
AI_DIR = Path(__file__).parent.parent / 'ai'
HONEYPOT_LOG_FILE = POTS_DIR / 'access_log.txt'
HONEYPOT_TEMPLATE = POTS_DIR / 'main.py'
HONEYPOT_OUTPUT = POTS_DIR / 'temptation.py'
FLASK_GEN_PROMPT = AI_DIR / 'prompts' / 'flask_gen.md'

@app.route('/api/honeypot/logs')
def get_honeypot_logs():
    """Get honeypot access logs from pots/access_log.txt"""
    try:
        if HONEYPOT_LOG_FILE.exists():
            with open(HONEYPOT_LOG_FILE, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Parse logs into structured format
            entries = []
            current_entry = None
            
            for line in content.split('\n'):
                line = line.strip()
                if line.startswith('=== Log Entry at'):
                    if current_entry:
                        entries.append(current_entry)
                    timestamp = line.replace('=== Log Entry at ', '').replace(' ===', '')
                    current_entry = {'timestamp': timestamp, 'accesses': []}
                elif line.startswith('Endpoint:'):
                    endpoint = line.replace('Endpoint: ', '')
                    if current_entry:
                        current_entry['accesses'].append({'endpoint': endpoint, 'ip': None, 'time': None})
                elif line.startswith('- IP:') and current_entry and current_entry['accesses']:
                    parts = line.replace('- IP: ', '').split(', Time: ')
                    if len(parts) == 2:
                        current_entry['accesses'][-1]['ip'] = parts[0]
                        current_entry['accesses'][-1]['time'] = parts[1]
            
            if current_entry:
                entries.append(current_entry)
            
            # Reverse to show newest first
            entries.reverse()
            
            return jsonify({
                'success': True,
                'entries': entries,
                'raw': content
            })
        else:
            return jsonify({
                'success': True,
                'entries': [],
                'raw': '',
                'message': 'No log file found'
            })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/honeypot/generate', methods=['POST'])
def generate_flask():
    """Generate a new Flask honeypot using AI"""
    try:
        # Read the prompt file
        if not FLASK_GEN_PROMPT.exists():
            return jsonify({'success': False, 'error': 'Prompt file not found'}), 404
        
        with open(FLASK_GEN_PROMPT, 'r', encoding='utf-8') as f:
            query = f.read()
        
        # Call process_flask_file from ai/main.py
        response = process_flask_file(
            template_path=str(HONEYPOT_TEMPLATE),
            logs_path=str(HONEYPOT_LOG_FILE),
            query=query,
            output_path=str(HONEYPOT_OUTPUT)
        )
        
        return jsonify({
            'success': True,
            'message': f'Flask honeypot generated successfully at {HONEYPOT_OUTPUT}',
            'output_file': str(HONEYPOT_OUTPUT)
        })
    except FileNotFoundError as e:
        return jsonify({'success': False, 'error': f'File not found: {str(e)}'}), 404
    except ValueError as e:
        return jsonify({'success': False, 'error': f'Configuration error: {str(e)}. Please ensure GEMINI_API_KEY is set.'}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/honeypot/status')
def honeypot_status():
    """Get honeypot generation status and file info"""
    try:
        status = {
            'template_exists': HONEYPOT_TEMPLATE.exists(),
            'log_exists': HONEYPOT_LOG_FILE.exists(),
            'output_exists': HONEYPOT_OUTPUT.exists(),
            'prompt_exists': FLASK_GEN_PROMPT.exists()
        }
        
        if HONEYPOT_OUTPUT.exists():
            stat = HONEYPOT_OUTPUT.stat()
            status['output_modified'] = datetime.fromtimestamp(stat.st_mtime).isoformat()
            status['output_size'] = stat.st_size
        
        if HONEYPOT_LOG_FILE.exists():
            stat = HONEYPOT_LOG_FILE.stat()
            status['log_modified'] = datetime.fromtimestamp(stat.st_mtime).isoformat()
            status['log_size'] = stat.st_size
        
        return jsonify({'success': True, **status})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ap-info')
def get_ap_info():
    """Get Access Point info from serial device"""
    try:
        info = info_pull()
        if info:
            # Parse the info string: 'MAC: xx IP: x.x.x.x SSID: name'
            parts = {}
            mac_match = re.search(r'MAC:\s*([0-9a-f:]+)', info, re.IGNORECASE)
            ip_match = re.search(r'IP:\s*([0-9.]+)', info)
            ssid_match = re.search(r'SSID:\s*(.+)$', info)
            
            if mac_match:
                parts['mac'] = mac_match.group(1)
            if ip_match:
                parts['ip'] = ip_match.group(1)
            if ssid_match:
                parts['ssid'] = ssid_match.group(1).strip()
            
            return jsonify({
                'success': True,
                'connected': True,
                'raw': info,
                **parts
            })
        else:
            return jsonify({
                'success': True,
                'connected': False,
                'message': 'No AP info available'
            })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

if __name__ == '__main__':
    print("Starting WiFi Monitor Web Interface...")
    print("Access the interface at: http://localhost:6767")
    app.run(host='0.0.0.0', port=6767, debug=False)
