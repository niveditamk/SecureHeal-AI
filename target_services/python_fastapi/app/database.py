# ============================================================================
# WARNING: THIS FILE IS INTENTIONALLY VULNERABLE FOR SECURITY TESTING PURPOSES
# DO NOT DEPLOY IN PRODUCTION. DO NOT USE AS A REFERENCE FOR SECURE CODE.
# Part of SecureHeal-AI test targets.
# ============================================================================

import sqlite3
import os

DATABASE_PATH = os.getenv("DATABASE_PATH", "secureheal_test.db")


def get_db_connection():
    """Get a raw SQLite connection."""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initialize the database with a users table and sample data."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            password_hash TEXT NOT NULL,
            bio TEXT DEFAULT '',
            is_active INTEGER DEFAULT 1
        )
    """)
    # Insert sample users if table is empty
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        sample_users = [
            ("admin", "admin@secureheal.test", "admin", "5f4dcc3b5aa765d61d8327deb882cf99", "System administrator"),
            ("alice", "alice@secureheal.test", "user", "d8578edf8458ce06fbc5bb76a58c5ca4", "Regular user Alice"),
            ("bob", "bob@secureheal.test", "user", "482c811da5d5b4bc6d497ffa98491e38", "Regular user Bob"),
            ("charlie", "charlie@secureheal.test", "analyst", "e99a18c428cb38d5f260853678922e03", "Security analyst"),
        ]
        cursor.executemany(
            "INSERT INTO users (username, email, role, password_hash, bio) VALUES (?, ?, ?, ?, ?)",
            sample_users,
        )
    conn.commit()
    conn.close()
