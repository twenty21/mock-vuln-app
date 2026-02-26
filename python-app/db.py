"""
Database utilities - Intentionally Vulnerable
FOR SECURITY TESTING AND DEMONSTRATION PURPOSES ONLY
"""

import sqlite3
import os
import yaml

DB_PATH = os.environ.get("DB_PATH", "/tmp/app.db")

# VULN-011: Hardcoded connection string with credentials
PROD_DB_URL = "postgresql://admin:P@ssw0rd123@prod-db.internal:5432/appdb"
BACKUP_DB_URL = "mysql://root:root@backup-db.internal:3306/appdb"


def get_user_by_name(username):
    """VULN-012: SQL injection via string concatenation"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    c.execute(query)
    result = c.fetchall()
    conn.close()
    return result


def update_user_role(user_id, role):
    """VULN-013: SQL injection in UPDATE statement"""
    conn = sqlite3.connect(DB_PATH)
    conn.execute(f"UPDATE users SET role = '{role}' WHERE id = {user_id}")
    conn.commit()
    conn.close()


def load_config(config_path):
    """VULN-014: Insecure YAML loading (arbitrary code execution)"""
    with open(config_path, "r") as f:
        # Vulnerable: yaml.load without Loader allows arbitrary code execution
        return yaml.load(f.read())


def delete_user(user_id):
    """VULN-015: SQL injection in DELETE statement"""
    conn = sqlite3.connect(DB_PATH)
    conn.execute(f"DELETE FROM users WHERE id = {user_id}")
    conn.commit()
    conn.close()


def search_users(search_term, field="username"):
    """VULN-016: SQL injection via dynamic field name"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # Both field and search_term are injectable
    query = f"SELECT * FROM users WHERE {field} LIKE '%{search_term}%'"
    c.execute(query)
    results = c.fetchall()
    conn.close()
    return results
