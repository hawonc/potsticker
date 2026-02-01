"""
Web interface for WiFi Security Monitoring System
"""

from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
from wifi import WiFiMonitor
import threading
import time
from datetime import datetime
import serial
import random
import os
import subprocess
import tempfile
from pathlib import Path
from scapy.all import *
from scapy.layers.eap import EAP, EAPOL
import hashlib
from scapy.all import RadioTap
from scapy.layers.dot11 import Dot11, Dot11Auth


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
def custom_network_pot():
  

# Configure the serial port parameters
# Replace 'COM4' with your port name (e.g., '/dev/ttyUSB0' on Linux or 'COM1' on Windows)
# Replace 9600 with the baud rate required by your device
    ser = serial.Serial(
        port='COM3',
        baudrate=9600,
        bytesize=serial.EIGHTBITS,
        parity=serial.PARITY_NONE,
        stopbits=serial.STOPBITS_ONE,
        timeout=1 # Set a timeout (in seconds)
    )
    x = 0
    
    try:
        # Wait a moment for the connection to establish
        time.sleep(.1)

        if ser.is_open:
            print(f"Serial port {ser.port} opened successfully.")

            # Data must be sent as bytes. Encode the string to bytes.
            waiting = '\n'
            data_to_send = f'e\w\\a fakeeduroam password1 {x} 0' # The 'b' prefix creates a bytes object
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
            print(f"Serial port {ser.port} closed.")

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
    custom_network_pot()
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
    custom_network_pot()
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




from scapy.all import RadioTap
from scapy.layers.dot11 import Dot11, Dot11Auth


import hashlib
from scapy.all import RadioTap
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

if __name__ == '__main__':
    print("Starting WiFi Monitor Web Interface...")
    print("Access the interface at: http://localhost:6767")
    app.run(host='0.0.0.0', port=6767, debug=True)
