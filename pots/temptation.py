from flask import Flask, request, render_template_string, jsonify
from datetime import datetime
import threading
import json
import os

app = Flask(__name__)

# Store unique accesses: {endpoint: set of (ip, timestamp)}
access_log = {}
log_lock = threading.Lock()
log_file = "access_log.txt"

def log_to_file():
    """Write access log to file every minute"""
    global access_log
    with log_lock:
        if access_log:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open(log_file, "a") as f:
                f.write(f"\n=== Log Entry at {timestamp} ===\n")
                for endpoint, accesses in access_log.items():
                    f.write(f"\nEndpoint: {endpoint}\n")
                    for ip, time in accesses:
                        f.write(f"  - IP: {ip}, Time: {time}\n")
                f.write("\n")
            access_log = {}
    # Schedule next write in 60 seconds
    threading.Timer(60.0, log_to_file).start()

@app.before_request
def log_request():
    """Log each unique access"""
    endpoint = request.path
    ip = request.remote_addr
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    with log_lock:
        if endpoint not in access_log:
            access_log[endpoint] = set()
        access_log[endpoint].add((ip, timestamp))

@app.route('/')
def index():
    return "Web Server - Passwords stored here! Sensitive directory listing enabled."

@app.route('/robots.txt')
def robots():
    return "User-agent: *\nDisallow: /passwords\nDisallow: /admin\nDisallow: /wp-admin\nDisallow: /api/v1/secrets", 200, {'Content-Type': 'text/plain'}

@app.route('/passwords')
def passwords():
    # Fake credentials for attackers to find
    creds = {
        "admin": "SuperSecret2026!",
        "db_user": "root_access_granted",
        "ssh_key_path": "/home/user/.ssh/id_rsa_backup"
    }
    return jsonify(creds)

@app.route('/admin')
def admin():
    return "<h1>Admin Portal</h1><p>Internal Access Only. Your IP has been logged.</p>", 403

@app.route('/wp-admin')
def wp_admin():
    return "<form>Username: <input type='text'><br>Password: <input type='password'><br><input type='submit' value='Login'></form>", 200

@app.route('/content')
def content():
    return "Index of /content/\n - uploads/\n - assets/\n - backup_2025.zip", 200

@app.route('/search')
def search():
    # VULNERABILITY: Reflected XSS
    query = request.args.get('q', '')
    template = f"""
    <html>
        <body>
            <h2>Search results for: {query}</h2>
            <p>0 results found.</p>
        </body>
    </html>
    """
    return render_template_string(template)

@app.route('/ping')
def ping():
    # VULNERABILITY: Simulated Command Injection
    target = request.args.get('host', '127.0.0.1')
    # We simulate the shell output to be safe in the container while looking vulnerable
    if ';' in target or '&&' in target or '|' in target:
        executed_cmd = target.split(';')[1] if ';' in target else "unknown"
        return f"<pre>PING {target} (127.0.0.1): 56 data bytes\nsh: 1: {executed_cmd}: permission denied</pre>", 200
    return f"<pre>PING {target} (127.0.0.1): 56 data bytes\n64 bytes from 127.0.0.1: icmp_seq=0 ttl=64 time=0.031 ms</pre>", 200

@app.route('/api/v1/secrets')
def secrets():
    # VULNERABILITY: Information Exposure
    config = {
        "DB_PASSWORD": "LegacyPassword_DontChange",
        "AWS_KEY": "AKIAJSI9242EXAMPLE",
        "ENV": "PRODUCTION",
        "INTERNAL_GATEWAY": "10.0.5.1"
    }
    return jsonify(config)

@app.route('/<path:path>')
def catch_all(path):
    return "Page Not Found", 404

def main():
    # Start the periodic logging
    log_to_file()
    
    # Run Flask server
    app.run(host='0.0.0.0', port=3000, debug=False)

if __name__ == '__main__':
    main()