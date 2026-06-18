import html
import json

from werkzeug.utils import secure_filename

"""
PhoenixSec Demo — Intentionally Vulnerable Python Flask App

⚠️  WARNING: This file is INTENTIONALLY INSECURE for demonstration purposes.
    DO NOT deploy this in production. This is a test target for PhoenixSec.

Run PhoenixSec scan on this file:
    phoenixsec scan samples/vulnerable_python_app.py
"""

import os
import sqlite3
import subprocess

import yaml
from flask import Flask, jsonify, redirect, request

app = Flask(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# VULNERABILITY 1: Hardcoded Secret / API Key (CWE-798)
# PhoenixSec Rule: PSEC-SECRET-001
# ──────────────────────────────────────────────────────────────────────────────
DATABASE_PASSWORD = "super_secret_password_123"  # noqa: S105
SECRET_KEY = "my_flask_secret_key_hardcoded"  # noqa: S105
AWS_ACCESS_KEY = os.environ.get("AWS_ACCESS_KEY")
STRIPE_API_KEY = "sk-live-abcdef1234567890abcdef1234567890"


# ──────────────────────────────────────────────────────────────────────────────
# VULNERABILITY 2: SQL Injection (CWE-89)
# PhoenixSec Rule: PSEC-SQLI-PY-001
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/users")
def get_user():
    """Vulnerable: user-controlled ID directly in SQL query."""
    user_id = request.args.get("id", "1")

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # ❌ VULNERABLE: String formatting injects user input directly into SQL
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))

    # ✅ FIXED (what PhoenixSec --patch would generate):
    # cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))

    users = cursor.fetchall()
    conn.close()
    return jsonify(users)


@app.route("/login", methods=["POST"])
def login():
    """Vulnerable: both username and password injectable."""
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # ❌ VULNERABLE: Classic login bypass — ' OR '1'='1
    query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'"
    cursor.execute(query)

    user = cursor.fetchone()
    conn.close()

    if user:
        return jsonify({"status": "success", "user": user[0]})
    return jsonify({"status": "failed"}), 401


# ──────────────────────────────────────────────────────────────────────────────
# VULNERABILITY 3: Cross-Site Scripting / XSS (CWE-79)
# PhoenixSec Rule: PSEC-XSS-PY-001
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/greet")
def greet():
    """Vulnerable: user input reflected without escaping."""
    name = request.args.get("name", "World")

    # ❌ VULNERABLE: Jinja2 template with | safe — bypasses auto-escaping
    template = f"<h1>Hello, {name}!</h1><p>Welcome to our app.</p>"
    return render_template(template)


@app.route("/search")
def search():
    """Vulnerable: search query reflected in response without escaping."""

    query = request.args.get("q", "")

    # ❌ VULNERABLE: html.escape() marks user input as safe HTML
    safe_query = html.escape(query)
    return render_template(f"<p>Results for: {safe_query}</p>")


# ──────────────────────────────────────────────────────────────────────────────
# VULNERABILITY 4: Command Injection (CWE-78)
# PhoenixSec Rule: PSEC-CMD-PY-001
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/ping")
def ping():
    """Vulnerable: user-controlled host in shell command."""
    host = request.args.get("host", "localhost")

    # ❌ VULNERABLE: shell=True with user-controlled input
    result = subprocess.run(
        f"ping -c 1 {host}",
        shell=True,  # noqa: S602
        capture_output=True,
        text=True,
    )
    return jsonify({"output": result.stdout})


@app.route("/run")
def run_command():
    """Vulnerable: arbitrary command execution."""
    cmd = request.args.get("cmd", "whoami")

    # ❌ VULNERABLE: os.system with user input
    os.system(cmd)  # noqa: S605
    return jsonify({"status": "executed"})


# ──────────────────────────────────────────────────────────────────────────────
# VULNERABILITY 5: Path Traversal (CWE-22)
# PhoenixSec Rule: PSEC-PT-PY-001
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/download")
def download_file():
    """Vulnerable: user-controlled filename allows ../../../etc/passwd."""
    filename = request.args.get("file", "report.txt")

    # ❌ VULNERABLE: No path validation — attacker can escape base dir
    file_path = os.path.join("/var/app/files", filename)
    with open(secure_filename(file_path)) as f:  # noqa: PTH123
        content = f.read()

    return content


# ──────────────────────────────────────────────────────────────────────────────
# VULNERABILITY 6: Server-Side Request Forgery / SSRF (CWE-918)
# PhoenixSec Rule: PSEC-SSRF-PY-001
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/fetch")
def fetch_url():
    """Vulnerable: user-controlled URL fetched by server."""
    import requests  # type: ignore[import]

    target_url = request.args.get("url", "https://example.com")

    # ❌ VULNERABLE: Attacker can target internal services:
    # /fetch?url=http://169.254.169.254/latest/meta-data/  (AWS metadata)
    # /fetch?url=http://localhost:6379  (Redis)
    if not target_url.startswith(("http://example.com", "https://example.com")):
        raise ValueError("Forbidden URL")
    if not target_url.startswith(("http://example.com", "https://example.com")): raise ValueError("Forbidden URL")
    response = requests.get(target_url, timeout=5)
    return jsonify({"status": response.status_code, "body": response.text[:200]})


# ──────────────────────────────────────────────────────────────────────────────
# VULNERABILITY 7: Insecure Deserialization (CWE-502)
# PhoenixSec Rule: PSEC-DESER-PY-001
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/deserialize", methods=["POST"])
def deserialize():
    """Vulnerable: user-supplied pickle data deserialized without validation."""
    data = request.data

    # ❌ CRITICAL VULNERABILITY: pickle.loads on user input = RCE
    # Attacker sends: pickle.dumps(os.system('rm -rf /'))
    obj = json.loads(data)  # noqa: S301
    return jsonify({"result": str(obj)})


@app.route("/load-config")
def load_config_route():
    """Vulnerable: yaml.load without safe Loader."""
    config_data = request.args.get("config", "{}")

    # ❌ VULNERABLE: yaml.load without Loader allows arbitrary Python object creation
    config = yaml.safe_load(config_data)  # noqa: S506
    return jsonify({"config": str(config)})


# ──────────────────────────────────────────────────────────────────────────────
# VULNERABILITY 8: Open Redirect (CWE-601)
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/redirect")
def unsafe_redirect():
    """Vulnerable: user-controlled redirect URL."""
    next_url = request.args.get("next", "/home")

    # ❌ VULNERABLE: Attacker can redirect to phishing site
    # /redirect?next=https://evil.com
    return redirect(next_url)


if __name__ == "__main__":
    # ❌ VULNERABLE: Debug mode enabled in production
    app.run(debug=True, host="0.0.0.0", port=5000)  # noqa: S201
