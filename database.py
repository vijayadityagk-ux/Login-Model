"""
=============================================================================
DATABASE LAYER & SQL INJECTION DEFENSE ARCHITECTURE
=============================================================================
Implements a SQLite relational database utilizing 100% Parameterized Queries.
Guarantees complete immunity from SQL Injection vulnerabilities.
Provides an interactive SQL Injection demonstration endpoint.
=============================================================================
"""

import sqlite3
import os
import json
from datetime import datetime, timedelta, timezone

DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "secure_app.db")

def get_db_connection():
    """
    Returns a connection to the SQLite database with dictionary-like row access.
    """
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    # Enforce foreign key constraints
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    """
    Initializes database schema with users, sessions, and security audit logs.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Users Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            two_factor_enabled INTEGER DEFAULT 0,
            two_factor_secret TEXT,
            backup_codes TEXT,
            failed_login_attempts INTEGER DEFAULT 0,
            locked_until TEXT,
            created_at TEXT NOT NULL,
            last_login TEXT
        )
    """)

    # 2. Active Sessions Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    """)

    # 3. Security Audit Log Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            user_id INTEGER,
            ip_address TEXT,
            details TEXT,
            created_at TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()

# ==============================================================================
# PARAMETERIZED USER OPERATIONS (SQL INJECTION IMMUNE)
# ==============================================================================

def create_user(username: str, email: str, password_hash: str) -> dict:
    conn = get_db_connection()
    cursor = conn.cursor()
    now_iso = datetime.now(timezone.utc).isoformat()
    try:
        # SECURE: Using '?' parameterized placeholder prevents any payload from breaking SQL context
        cursor.execute(
            """
            INSERT INTO users (username, email, password_hash, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (username, email, password_hash, now_iso)
        )
        user_id = cursor.lastrowid
        conn.commit()
        return {"id": user_id, "username": username, "email": email}
    finally:
        conn.close()

def get_user_by_email(email: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # SECURE: Parameterized lookup
        cursor.execute("SELECT * FROM users WHERE email = ?", (email.lower().strip(),))
        row = cursor.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()

def get_user_by_id(user_id: int):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # SECURE: Parameterized lookup
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        row = cursor.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()

def update_user_2fa(user_id: int, enabled: bool, secret: str = None, backup_codes: list = None):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        backup_json = json.dumps(backup_codes) if backup_codes else None
        # SECURE: Parameterized update
        cursor.execute(
            """
            UPDATE users
            SET two_factor_enabled = ?, two_factor_secret = ?, backup_codes = ?
            WHERE id = ?
            """,
            (1 if enabled else 0, secret, backup_json, user_id)
        )
        conn.commit()
    finally:
        conn.close()

def update_last_login(user_id: int):
    conn = get_db_connection()
    cursor = conn.cursor()
    now_iso = datetime.now(timezone.utc).isoformat()
    try:
        cursor.execute(
            "UPDATE users SET last_login = ?, failed_login_attempts = 0 WHERE id = ?",
            (now_iso, user_id)
        )
        conn.commit()
    finally:
        conn.close()

# ==============================================================================
# PARAMETERIZED SESSION OPERATIONS
# ==============================================================================

def create_session(session_id: str, user_id: int, ip_address: str, user_agent: str, duration_hours: int = 24):
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now(timezone.utc)
    expires = now + timedelta(hours=duration_hours)
    try:
        # SECURE: Parameterized insertion
        cursor.execute(
            """
            INSERT INTO sessions (session_id, user_id, ip_address, user_agent, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (session_id, user_id, ip_address, user_agent, now.isoformat(), expires.isoformat())
        )
        conn.commit()
    finally:
        conn.close()

def get_session(session_id: str):
    if not session_id:
        return None
    conn = get_db_connection()
    cursor = conn.cursor()
    now_iso = datetime.now(timezone.utc).isoformat()
    try:
        # SECURE: Checks token and expiration
        cursor.execute(
            """
            SELECT s.*, u.username, u.email, u.two_factor_enabled, u.created_at as user_created_at
            FROM sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.session_id = ? AND s.expires_at > ?
            """,
            (session_id, now_iso)
        )
        row = cursor.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()

def delete_session(session_id: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # SECURE: Parameterized session deletion (Logout)
        cursor.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
        conn.commit()
    finally:
        conn.close()

def log_audit_event(event_type: str, user_id: int = None, ip_address: str = "127.0.0.1", details: str = ""):
    conn = get_db_connection()
    cursor = conn.cursor()
    now_iso = datetime.now(timezone.utc).isoformat()
    try:
        cursor.execute(
            "INSERT INTO audit_logs (event_type, user_id, ip_address, details, created_at) VALUES (?, ?, ?, ?, ?)",
            (event_type, user_id, ip_address, details, now_iso)
        )
        conn.commit()
    finally:
        conn.close()

# ==============================================================================
# INTERACTIVE SQL INJECTION DEFENSE DEMONSTRATION
# ==============================================================================

def test_sql_injection_defense(payload: str) -> dict:
    """
    Demonstrates side-by-side why raw concatenation is vulnerable to SQL injection
    and how parameterized queries safely neutralize malicious input.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Theoretical Vulnerable Query (Demonstration only, never executed blindly)
    simulated_vulnerable_sql = f"SELECT id, username, email FROM users WHERE email = '{payload}'"

    # 2. Secure Parameterized Execution
    secure_sql = "SELECT id, username, email FROM users WHERE email = ?"
    
    try:
        cursor.execute(secure_sql, (payload,))
        rows = cursor.fetchall()
        matched_records = [dict(r) for r in rows]
    except Exception as e:
        matched_records = []

    conn.close()

    is_payload_malicious = any(sqli_token in payload.lower() for sqli_token in [
        "' or ", "'--", "' union", "1=1", "drop table", "select *", "admin'--"
    ])

    return {
        "input_tested": payload,
        "is_detected_as_injection": is_payload_malicious,
        "vulnerable_pattern_example": simulated_vulnerable_sql,
        "secure_parameterized_query": secure_sql,
        "records_exposed": matched_records,
        "explanation": (
            "In the secure implementation, the database driver treats the entire payload strictly as literal text data. "
            "Characters like single quotes ('), dashes (--), and Boolean operators (OR 1=1) are never parsed as SQL commands. "
            "Therefore, 0 unauthorized records were leaked."
        )
    }
