from flask import Flask, request, render_template_string
from datetime import datetime
import threading
import json
import os

app = Flask(__name__)

# Store unique accesses: {endpoint: set of (ip, timestamp)}
access_log = {}
log_file = "access_log.txt"
log_lock = threading.Lock()

def log_to_file():
    """Write access log to file periodically"""
    global access_log
    with log_lock:
        if access_log:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            try:
                with open(log_file, "a") as f:
                    f.write(f"\n=== Log Entry at {timestamp} ===\n")
                    for endpoint, accesses in access_log.items():
                        f.write(f"\nEndpoint: {endpoint}\n")
                        for ip, time in accesses:
                            f.write(f"  - IP: {ip}, Time: {time}\n")
                    f.write("\n")
            except Exception as e:
                print(f"Logging error: {e}")
            access_log = {}
    # Schedule next write in 60 seconds
    threading.Timer(60.0, log_to_file).start()

@app.before_request
def log_request():
    """Log each unique access attempt"""
    endpoint = request.path
    ip = request.remote_addr
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    with log_lock:
        if endpoint not in access_log:
            access_log[endpoint] = set()
        access_log[endpoint].add((ip, timestamp))

@app.route('/')
def index():
    return "Web Server - Internal Portal. Passwords stored in /admin. Configuration in /config.", 200

@app.route('/robots.txt')
def robots():
    return "User-agent: *\nDisallow: /admin\nDisallow: /config\nDisallow: /content", 200

@app.route('/content')
def content():
    return "<h1>Site Content</h1><p>Publicly accessible assets are located here.</p>", 200

@app.route('/admin')
def admin():
    # Fake credentials for honeypot purposes
    creds = {
        "status": "authenticated",
        "user": "admin_root",
        "session_token": "7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d",
        "internal_notes": "Remember to change the DB password 'DB_Admin_Pass_2025' before next audit."
    }
    return json.dumps(creds), 200, {'Content-Type': 'application/json'}

@app.route('/config')
def config():
    # VULNERABILITY: Insecure exposure of fake API keys
    settings = {
        "AWS_KEY": "AKIAV7FAKE6EXAMPLE",
        "AWS_SECRET": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "DEBUG_LOGGING": True,
        "DB_HOST": "10.0.0.15"
    }
    return json.dumps(settings), 200, {'Content-Type': 'application/json'}

@app.route('/johnpork')
@app.route('/porkjohn')
def easter_egg():
    return "Found hidden endpoint. Logged for analysis.", 200

@app.route('/greet')
def greet():
    # VULNERABILITY: Reflected XSS (Educational example)
    # Usage: /greet?name=<script>alert('XSS')</script>
    name = request.args.get('name', 'User')
    template = f"""
    <html>
        <body>
            <h1>Hello, {name}!</h1>
            <p>Welcome to the secure user greeting module.</p>
        </body>
    </html>
    """
    return render_template_string(template)

@app.route('/ping')
def ping():
    # VULNERABILITY: Simulated Command Injection (Educational example)
    # This mimics a shell environment without actually executing commands on the host.
    target = request.args.get('host', '127.0.0.1')
    
    # Basic simulation of a ping response
    response = f"PING {target} (127.0.0.1): 56 data bytes\n64 bytes from 127.0.0.1: icmp_seq=0 ttl=64 time=0.035 ms"
    
    # Simulate the effect of a semicolon or ampersand injection
    if ';' in target or '&&' in target:
        parts = target.replace('&&', ';').split(';')
        injected_command = parts[1].strip() if len(parts) > 1 else "unknown"
        return f"<pre>{response}\nsh: 1: {injected_command}: not found</pre>", 200
    
    return f"<pre>{response}</pre>", 200

@app.route('/favicon.ico')
def favicon():
    return "", 204

@app.route('/<path:path>')
def catch_all(path):
    return f"Resource '{path}' not found on this server.", 404

def main():
    # Start the background logging thread
    log_to_file()
    
    # Run Flask server
    app.run(host='0.0.0.0', port=3000, debug=False)

if __name__ == '__main__':
    main()