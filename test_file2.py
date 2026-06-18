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


