from flask import Flask, request
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
    """Write access log to file every minute and update compressed log"""
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
    if request.path == '/':
        return
    endpoint = request.path
    ip = request.remote_addr
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    with log_lock:
        if endpoint not in access_log:
            access_log[endpoint] = set()
        access_log[endpoint].add((ip, timestamp))


@app.route('/')
def index():
    return "Web Server - Passwords stored here!"


@app.route('/<path:path>')
def catch_all(path):
    return "Page Not Found", 404


def main():
    # Start the periodic logging
    log_to_file()
    
    # Run Flask server
    app.run(host='0.0.0.0', port=3000, debug=False)


if __name__ == "__main__":
    main()
