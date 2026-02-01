from flask import Flask, request, render_template_string
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
    """Log each access attempt"""
    endpoint = request.path
    ip = request.remote_addr
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    with log_lock:
        if endpoint not in access_log:
            access_log[endpoint] = set()
        access_log[endpoint].add((ip, timestamp))

@app.route('/')
def index():
    return "<h1>Web Server Internal</h1><p>Welcome to the legacy management portal. Restricted area: /admin</p>", 200

@app.route('/robots.txt')
def robots():
    return "User-agent: *\nDisallow: /admin\nDisallow: /passwords\nDisallow: /wp-admin\nDisallow: /config", 200, {'Content-Type': 'text/plain'}

@app.route('/passwords')
def passwords():
    # FAKE CREDENTIALS FOR ATTACKERS
    creds = {
        "internal_admin": "Summer2024!",
        "db_user": "prod_db_access_9921",
        "ssh_key_passphrase": "blue-sky-mountain-44"
    }
    return json.dumps(creds), 200, {'Content-Type': 'application/json'}

@app.route('/admin')
def admin():
    return "<h1>Admin Control Panel</h1><p>Login required.</p><form>User: <input type='text'><br>Pass: <input type='password'><br><input type='submit'></form>", 200

@app.route('/wp-admin')
def wp_admin():
    return "WordPress 6.2.2 - Login Redirect Error. Please contact sysadmin.", 403

@app.route('/content')
def content():
    return "<h3>Index of /content</h3><ul><li><a href='#'>images/</a></li><li><a href='#'>backups/</a></li><li><a href='#'>scripts/</a></li></ul>", 200

@app.route('/greet')
def greet():
    # VULNERABILITY: Reflected XSS
    name = request.args.get('name', 'Guest')
    template = f"""
    <html>
        <body>
            <h2>Welcome, {name}!</h2>
            <p>You have been identified as an authorized viewer.</p>
        </body>
    </html>
    """
    return render_template_string(template)

@app.route('/ping')
def ping():
    # VULNERABILITY: Simulated Command Injection
    target = request.args.get('host', '127.0.0.1')
    # Simulated output to look like a shell error if special characters are used
    if ';' in target or '&&' in target or '|' in target:
        return f"PING {target}: (127.0.0.1) 56(84) bytes of data.\n/bin/sh: 1: {target}: not found", 200
    return f"<pre>PING {target} (127.0.0.1) 56(84) bytes of data.\n64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.031 ms</pre>", 200

@app.route('/config')
def config():
    # VULNERABILITY: Exposure of sensitive data
    settings = {
        "ENVIRONMENT": "PRODUCTION",
        "AWS_S3_BUCKET": "company-backup-bucket-us-east-1",
        "SECRET_TOKEN": "sk_live_51MabcXYZ123fakekey",
        "DEBUG": True
    }
    return json.dumps(settings), 200, {'Content-Type': 'application/json'}

@app.route('/<path:path>')
def catch_all(path):
    return f"Resource '{path}' not found on this server.", 404

def main():
    # Start the periodic logging
    log_to_file()
    
    # Run Flask server
    app.run(host='0.0.0.0', port=3000, debug=False)

if __name__ == '__main__':
    main()