"""
Web interface for WiFi Security Monitoring System
"""

from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
from wifi import WiFiMonitor
import threading
import time
from datetime import datetime

app = Flask(__name__)
CORS(app)

# Global monitor instance
monitor = None
attack_log = []
max_log_entries = 100

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

def custom_wps_handler(attack_info):
    """Custom WPS handler that logs attacks"""
    log_attack('wps', attack_info)
    print(f"\n>>> WPS BRUTE FORCE DETECTED from {attack_info['attacker_mac']}")
    print(f">>> Target AP: {attack_info['target_ap']}")
    print(f">>> Involved devices: {attack_info['all_macs']}")

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
