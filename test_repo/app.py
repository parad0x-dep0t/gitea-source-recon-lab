"""
Sample Flask Application for Reconnaissance Testing
"""

import os
from flask import Flask, request, jsonify, send_file

app = Flask(__name__)

# Hardcoded password (P0 - SECRET)
ADMIN_PASSWORD = "SuperSecretAdminPassword123!"

@app.route("/api/v1/ping")
def ping():
    # User input source (P2 - SOURCE)
    host = request.args.get("host", "127.0.0.1")
    # Command execution sink (P0 - SINK) -> RCE Correlation!
    cmd = f"ping -c 1 {host}"
    output = os.system(cmd)
    return jsonify({"status": "executed", "code": output})

@app.route("/api/v1/read")
def read_doc():
    # User input source (P2 - SOURCE)
    filename = request.args.get("file")
    # File sink (P1 - FILE_SINK) -> Path Traversal Correlation!
    return send_file(f"/var/www/uploads/{filename}")

@app.route("/admin/status")
def admin_status():
    backup_path = "/etc/app/backup.conf"
    return jsonify({"backup_path": backup_path})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
