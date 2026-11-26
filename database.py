import sqlite3
import json
from pathlib import Path
from contextlib import closing

BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = BASE_DIR / "fixproof.db"


def get_connection():
    connection = sqlite3.connect(DATABASE_PATH, timeout=15)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout = 15000")
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def init_db():
    with closing(get_connection()) as connection:
        connection.execute("PRAGMA journal_mode = WAL")

        with connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE,
                    name TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            connection.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    url TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    score INTEGER NOT NULL,
                    level TEXT NOT NULL,
                    findings_json TEXT NOT NULL,
                    technologies_json TEXT NOT NULL DEFAULT '[]',
                    recommendations_json TEXT NOT NULL,
                    risk_level TEXT DEFAULT 'Pending',
                    results TEXT DEFAULT '{}',
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            """)


def create_user(name, email, password):
    try:
        with closing(get_connection()) as connection:
            with connection:
                connection.execute("""
                    INSERT INTO users
                    (username, name, email, password)
                    VALUES (?, ?, ?, ?)
                """, (email, name, email, password))

        return True

    except sqlite3.IntegrityError:
        return False


def get_user_by_email(email):
    with closing(get_connection()) as connection:
        cursor = connection.execute("""
            SELECT *
            FROM users
            WHERE email = ? OR username = ?
        """, (email, email))

        user = cursor.fetchone()
        return dict(user) if user else None


def save_scan(user_id, url, score, risk_level, results, technologies=None):
    results_json = json.dumps(results)
    technologies_json = json.dumps(technologies or [])

    recommendations = [
        {
            "name": item.get("name", "Security recommendation"),
            "guidance": item.get("guidance", "")
        }
        for item in results
    ]

    recommendations_json = json.dumps(recommendations)

    with closing(get_connection()) as connection:
        with connection:
            cursor = connection.execute("""
                INSERT INTO scans (
                    user_id, url, created_at, score, level,
                    findings_json, technologies_json,
                    recommendations_json, risk_level, results
                )
                VALUES (?, ?, CURRENT_TIMESTAMP, ?, ?, ?, ?, ?, ?, ?)
            """, (
                user_id,
                url,
                score,
                risk_level,
                results_json,
                technologies_json,
                recommendations_json,
                risk_level,
                results_json
            ))

            return cursor.lastrowid


def get_user_scans(user_id):
    with closing(get_connection()) as connection:
        cursor = connection.execute("""
            SELECT id, url, score, level AS risk_level, created_at
            FROM scans
            WHERE user_id = ?
            ORDER BY id DESC
        """, (user_id,))

        return [dict(scan) for scan in cursor.fetchall()]


def get_scan(scan_id, user_id):
    with closing(get_connection()) as connection:
        cursor = connection.execute("""
            SELECT *
            FROM scans
            WHERE id = ? AND user_id = ?
        """, (scan_id, user_id))

        scan = cursor.fetchone()

        if not scan:
            return None

        scan_data = dict(scan)

        try:
            scan_data["results"] = json.loads(
                scan_data.get("results") or
                scan_data.get("findings_json") or "[]"
            )
        except (json.JSONDecodeError, TypeError):
            scan_data["results"] = []

        try:
            scan_data["technologies"] = json.loads(
                scan_data.get("technologies_json") or "[]"
            )
        except (json.JSONDecodeError, TypeError):
            scan_data["technologies"] = []

        try:
            scan_data["recommendations"] = json.loads(
                scan_data.get("recommendations_json") or "[]"
            )
        except (json.JSONDecodeError, TypeError):
            scan_data["recommendations"] = []

        return scan_data