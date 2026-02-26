"""
VulnFlask - Intentionally Vulnerable Flask Application
FOR SECURITY TESTING AND DEMONSTRATION PURPOSES ONLY
"""

import os
import sqlite3
import subprocess
import pickle
import hashlib
from flask import Flask, request, render_template_string, redirect, session

app = Flask(__name__)

# VULN-001: Hardcoded secret key
app.secret_key = "super_secret_key_1234"

# VULN-002: Hardcoded API credentials
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
DATABASE_PASSWORD = "admin123"
JWT_SECRET = "mysecrettoken"

DB_PATH = "/tmp/users.db"


def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)""")
    c.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'admin123', 'admin')")
    c.execute("INSERT OR IGNORE INTO users VALUES (2, 'alice', 'password', 'user')")
    conn.commit()
    conn.close()


# VULN-003: SQL Injection
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        # Vulnerable: direct string interpolation in SQL query
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        c.execute(query)
        user = c.fetchone()
        conn.close()
        if user:
            session["user"] = username
            return redirect("/dashboard")
        return "Invalid credentials", 401
    return render_template_string("""
        <form method='post'>
            Username: <input name='username'><br>
            Password: <input type='password' name='password'><br>
            <input type='submit' value='Login'>
        </form>
    """)


# VULN-004: Cross-Site Scripting (XSS)
@app.route("/search")
def search():
    query = request.args.get("q", "")
    # Vulnerable: user input rendered directly without escaping
    template = f"<h1>Search results for: {query}</h1>"
    return render_template_string(template)


# VULN-005: Command Injection
@app.route("/ping")
def ping():
    host = request.args.get("host", "localhost")
    # Vulnerable: shell=True with unsanitized input
    result = subprocess.check_output(f"ping -c 1 {host}", shell=True)
    return result


# VULN-006: Path Traversal
@app.route("/file")
def read_file():
    filename = request.args.get("name", "")
    # Vulnerable: no path sanitization
    with open(f"/var/app/files/{filename}", "r") as f:
        return f.read()


# VULN-007: Insecure Deserialization
@app.route("/load", methods=["POST"])
def load_data():
    data = request.get_data()
    # Vulnerable: deserializing untrusted data with pickle
    obj = pickle.loads(data)
    return str(obj)


# VULN-008: Weak cryptography (MD5 for passwords)
@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username")
    password = request.form.get("password")
    # Vulnerable: MD5 is cryptographically broken for password hashing
    hashed = hashlib.md5(password.encode()).hexdigest()
    conn = sqlite3.connect(DB_PATH)
    conn.execute(f"INSERT INTO users (username, password, role) VALUES ('{username}', '{hashed}', 'user')")
    conn.commit()
    conn.close()
    return "Registered"


# VULN-009: Debug mode and verbose error exposure
@app.route("/user/<user_id>")
def get_user(user_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # Vulnerable: SQL injection via URL parameter
    c.execute(f"SELECT * FROM users WHERE id = {user_id}")
    user = c.fetchone()
    conn.close()
    if user:
        # Vulnerable: returns full user record including password
        return {"id": user[0], "username": user[1], "password": user[2], "role": user[3]}
    return "Not found", 404


@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/login")
    return f"Welcome, {session['user']}!"


if __name__ == "__main__":
    init_db()
    # VULN-010: Debug mode enabled in production
    app.run(debug=True, host="0.0.0.0", port=5000)
