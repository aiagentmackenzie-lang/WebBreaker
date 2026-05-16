"""Deliberately vulnerable Flask application for integration testing.

This app contains intentional security vulnerabilities for testing
WebBreaker's scanners against real HTTP endpoints. NEVER deploy this
in production or expose it to the internet.

Vulnerabilities included:
- SQL Injection (GET/POST parameters)
- Reflected XSS (search, error messages)
- Command Injection (ping utility)
- LFI (file viewer)
- Missing security headers
- Predictable session tokens
- CSRF-protected forms with weak tokens
- Directory listing (/files/)
"""

import os
import subprocess
import sqlite3
import uuid
from flask import (
    Flask, request, redirect, jsonify, session
)

app = Flask(__name__)
app.secret_key = "vulnerable-secret-key-for-testing-only"

# ── Database Setup ──────────────────────────────────────────────────

DB_PATH = "/tmp/webbreaker_vuln_app.db"


def init_db():
    """Initialize the vulnerable database with test data."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DROP TABLE IF EXISTS users")
    c.execute("""CREATE TABLE users (
        id INTEGER PRIMARY KEY,
        username TEXT,
        password TEXT,
        email TEXT,
        role TEXT DEFAULT 'user'
    )""")
    c.executemany(
        "INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
        [
            ("admin", "admin123", "admin@test.com", "admin"),
            ("alice", "password1", "alice@test.com", "user"),
            ("bob", "hunter2", "bob@test.com", "user"),
            ("charlie", "letmein", "charlie@test.com", "user"),
            ("diana", "qwerty", "diana@test.com", "user"),
        ],
    )
    conn.commit()
    conn.close()


# ── Home Page ───────────────────────────────────────────────────────

@app.route("/")
def index():
    """Homepage with links to all vulnerable endpoints."""
    return """<!DOCTYPE html>
<html><head><title>VulnApp - Integration Test Target</title></head>
<body>
<h1>VulnApp</h1>
<p>Deliberately vulnerable application for testing.</p>
<ul>
  <li><a href="/search">Search (XSS)</a></li>
  <li><a href="/user?id=1">User Profile (SQLi)</a></li>
  <li><a href="/login">Login (SQLi POST)</a></li>
  <li><a href="/ping">Ping Utility (CMDi)</a></li>
  <li><a href="/view?file=readme.txt">File Viewer (LFI)</a></li>
  <li><a href="/comment">Comments (Stored XSS)</a></li>
  <li><a href="/api/status">API Status (Headers)</a></li>
  <li><a href="/files/">Files (Directory Listing)</a></li>
</ul>
</body></html>"""


# ── Reflected XSS ───────────────────────────────────────────────────

@app.route("/search")
def search():
    """Reflected XSS: search parameter reflected in HTML without encoding."""
    query = request.args.get("q", "")
    return f"""<!DOCTYPE html>
<html><head><title>Search: {query}</title></head>
<body>
<h1>Search Results</h1>
<form action="/search" method="GET">
  <input type="text" name="q" value="{query}" />
  <button type="submit">Search</button>
</form>
<p>You searched for: <b>{query}</b></p>
<p>No results found for '{query}'.</p>
</body></html>"""


@app.route("/error")
def error_page():
    """Reflected XSS: error parameter reflected in error message."""
    msg = request.args.get("msg", "Unknown error")
    return f"""<!DOCTYPE html>
<html><head><title>Error</title></head>
<body>
<h1>Error Occurred</h1>
<p class="error">{msg}</p>
<script>var errMsg = "{msg}";</script>
</body></html>"""


# ── SQL Injection ──────────────────────────────────────────────────

@app.route("/user")
def user_profile():
    """SQLi: id parameter injected directly into SQL query."""
    user_id = request.args.get("id", "")
    conn = sqlite3.connect(DB_PATH)
    try:
        # VULNERABLE: Direct string interpolation in SQL
        query = f"SELECT id, username, email, role FROM users WHERE id = {user_id}"
        cursor = conn.execute(query)
        rows = cursor.fetchall()
        if rows:
            result = [
                {"id": r[0], "username": r[1], "email": r[2], "role": r[3]}
                for r in rows
            ]
            return jsonify({"users": result, "query": query})
        return jsonify({"error": "No users found", "query": query}), 404
    except Exception as e:
        return jsonify({"error": str(e), "query": query}), 500
    finally:
        conn.close()


@app.route("/login", methods=["GET", "POST"])
def login():
    """SQLi via POST login form."""
    if request.method == "GET":
        return """<!DOCTYPE html>
<html><head><title>Login</title></head>
<body>
<h1>Login</h1>
<form action="/login" method="POST">
  <input type="text" name="username" placeholder="Username" />
  <input type="password" name="password" placeholder="Password" />
  <button type="submit">Login</button>
</form>
</body></html>"""

    username = request.form.get("username", "")
    password = request.form.get("password", "")
    conn = sqlite3.connect(DB_PATH)
    try:
        # VULNERABLE: String interpolation in SQL
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        cursor = conn.execute(query)
        user = cursor.fetchone()
        if user:
            session["user_id"] = user[0]
            session["username"] = user[1]
            return redirect("/dashboard")
        return jsonify({"error": "Invalid credentials", "query": query}), 401
    except Exception as e:
        return jsonify({"error": str(e), "query": query}), 500
    finally:
        conn.close()


@app.route("/dashboard")
def dashboard():
    """Dashboard that requires login session."""
    if "user_id" not in session:
        return redirect("/login")
    return f"""<!DOCTYPE html>
<html><head><title>Dashboard</title></head>
<body>
<h1>Dashboard</h1>
<p>Welcome, {session.get('username', 'unknown')}!</p>
<p>Role: {session.get('role', 'user')}</p>
</body></html>"""


# ── Command Injection ──────────────────────────────────────────────

@app.route("/ping", methods=["GET", "POST"])
def ping():
    """CMDi: host parameter passed to subprocess without sanitization."""
    if request.method == "GET":
        return """<!DOCTYPE html>
<html><head><title>Ping Utility</title></head>
<body>
<h1>Ping Utility</h1>
<form action="/ping" method="POST">
  <input type="text" name="host" placeholder="Enter hostname or IP" />
  <button type="submit">Ping</button>
</form>
</body></html>"""

    host = request.form.get("host", "")
    try:
        # VULNERABLE: Unsanitized input in subprocess
        result = subprocess.run(
            ["ping", "-c", "1", host],
            capture_output=True, text=True, timeout=5
        )
        return jsonify({"output": result.stdout, "error": result.stderr, "host": host})
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Ping timeout", "host": host}), 408
    except Exception as e:
        return jsonify({"error": str(e), "host": host}), 500


# ── Local File Inclusion ───────────────────────────────────────────

@app.route("/view")
def view_file():
    """LFI: file parameter used to read local files."""
    filename = request.args.get("file", "readme.txt")
    # Prevent absolute path traversal (but vulnerable to relative)
    if filename.startswith("/"):
        return jsonify({"error": "Absolute paths not allowed"}), 400
    try:
        # VULNERABLE: Path traversal via ../
        filepath = os.path.join("/tmp/vulnapp_files", filename)
        with open(filepath, "r") as f:
            content = f.read()
        return f"""<!DOCTYPE html>
<html><head><title>File: {filename}</title></head>
<body>
<h1>Viewing: {filename}</h1>
<pre>{content}</pre>
</body></html>"""
    except FileNotFoundError:
        return jsonify({"error": f"File not found: {filename}"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Stored XSS ─────────────────────────────────────────────────────

_comments = []


@app.route("/comment", methods=["GET", "POST"])
def comment():
    """Stored XSS: comments stored and rendered without sanitization."""
    global _comments
    if request.method == "POST":
        text = request.form.get("text", "")
        author = request.form.get("author", "Anonymous")
        _comments.append({"text": text, "author": author, "id": len(_comments) + 1})
        return redirect("/comment")

    comments_html = "".join(
        f'<div class="comment"><p>{c["text"]}</p><small>— {c["author"]}</small></div>'
        for c in _comments
    )
    return f"""<!DOCTYPE html>
<html><head><title>Comments</title></head>
<body>
<h1>Comments</h1>
{comments_html}
<form action="/comment" method="POST">
  <textarea name="text" placeholder="Write a comment..."></textarea>
  <input type="text" name="author" placeholder="Your name" />
  <button type="submit">Post</button>
</form>
</body></html>"""


# ── Missing Security Headers ────────────────────────────────────────

@app.route("/api/status")
def api_status():
    """API endpoint missing security headers (no CSP, no X-Frame-Options)."""
    return jsonify({
        "status": "ok",
        "version": "1.0.0-vulnerable",
        "database": DB_PATH,
    })


# ── Directory Listing ──────────────────────────────────────────────

@app.route("/files/")
def file_listing():
    """Directory listing exposing internal files."""
    files = [
        {"name": "backup.sql", "size": 1048576, "modified": "2026-01-15"},
        {"name": "config.yml", "size": 512, "modified": "2026-02-01"},
        {"name": "id_rsa", "size": 3243, "modified": "2026-01-10"},
        {"name": ".env", "size": 256, "modified": "2026-03-01"},
    ]
    return jsonify({"path": "/files/", "files": files})


# ── CSRF-Vulnerable Form ──────────────────────────────────────────

@app.route("/transfer", methods=["GET", "POST"])
def transfer():
    """CSRF-vulnerable transfer form (no CSRF token)."""
    if request.method == "GET":
        return """<!DOCTYPE html>
<html><head><title>Transfer</title></head>
<body>
<h1>Transfer Funds</h1>
<form action="/transfer" method="POST">
  <input type="text" name="to" placeholder="Recipient" />
  <input type="number" name="amount" placeholder="Amount" />
  <button type="submit">Transfer</button>
</form>
</body></html>"""

    to_account = request.form.get("to", "")
    amount = request.form.get("amount", "0")
    return jsonify({"status": "transferred", "to": to_account, "amount": amount})


# ── Predictable Session Tokens ─────────────────────────────────────

@app.route("/session-info")
def session_info():
    """Endpoint that leaks session information."""
    return jsonify({
        "session_id": session.get("user_id", str(uuid.uuid4())),
        "secret_key": app.secret_key,
        "cookies": dict(request.cookies),
    })


# ── Startup ────────────────────────────────────────────────────────

def setup_files():
    """Create test files for LFI testing."""
    os.makedirs("/tmp/vulnapp_files", exist_ok=True)
    with open("/tmp/vulnapp_files/readme.txt", "w") as f:
        f.write("This is a test file for WebBreaker integration testing.\n")
    with open("/tmp/vulnapp_files/secret.txt", "w") as f:
        f.write("SECRET_DATA=should_not_be_accessible\n")


def create_app():
    """Application factory for testing."""
    init_db()
    setup_files()
    return app


if __name__ == "__main__":
    init_db()
    setup_files()
    app.run(host="127.0.0.1", port=18888, debug=False)