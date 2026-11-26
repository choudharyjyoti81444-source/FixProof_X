
import sqlite3
import json
from pathlib import Path
from datetime import datetime

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "fixproofx.db"


def get_connection():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    connection = get_connection()

    try:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL DEFAULT '',
                password_hash TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT '',
                email TEXT,
                is_verified INTEGER NOT NULL DEFAULT 1,
                name TEXT NOT NULL DEFAULT '',
                password TEXT NOT NULL DEFAULT ''
            )
        """)

        user_columns = {
            row["name"]
            for row in connection.execute(
                "PRAGMA table_info(users)"
            ).fetchall()
        }

        user_required = {
            "username": "TEXT NOT NULL DEFAULT ''",
            "password_hash": "TEXT NOT NULL DEFAULT ''",
            "created_at": "TEXT NOT NULL DEFAULT ''",
            "email": "TEXT",
            "is_verified": "INTEGER NOT NULL DEFAULT 1",
            "name": "TEXT NOT NULL DEFAULT ''",
            "password": "TEXT NOT NULL DEFAULT ''"
        }

        for column, definition in user_required.items():
            if column not in user_columns:
                connection.execute(
                    f"ALTER TABLE users ADD COLUMN {column} {definition}"
                )

        connection.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                url TEXT NOT NULL,
                score INTEGER NOT NULL DEFAULT 0,
                risk_level TEXT NOT NULL DEFAULT 'Pending',
                level TEXT NOT NULL DEFAULT 'Pending',
                results TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL DEFAULT ''
            )
        """)

        scan_columns = {
            row["name"]
            for row in connection.execute(
                "PRAGMA table_info(scans)"
            ).fetchall()
        }

        scan_required = {
            "user_id": "INTEGER NOT NULL DEFAULT 0",
            "url": "TEXT NOT NULL DEFAULT ''",
            "score": "INTEGER NOT NULL DEFAULT 0",
            "risk_level": "TEXT NOT NULL DEFAULT 'Pending'",
            "level": "TEXT NOT NULL DEFAULT 'Pending'",
            "results": "TEXT NOT NULL DEFAULT '{}'",
            "created_at": "TEXT NOT NULL DEFAULT ''"
        }

        for column, definition in scan_required.items():
            if column not in scan_columns:
                connection.execute(
                    f"ALTER TABLE scans ADD COLUMN {column} {definition}"
                )

        connection.commit()

    finally:
        connection.close()


def create_user(name, email, password_hash):
    connection = get_connection()

    try:
        existing = connection.execute(
            "SELECT id FROM users WHERE LOWER(email) = LOWER(?)",
            (email,)
        ).fetchone()

        if existing:
            return False

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        connection.execute("""
            INSERT INTO users
            (username, password_hash, created_at, email, name, password)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            name,
            password_hash,
            now,
            email,
            name,
            password_hash
        ))

        connection.commit()
        return True

    except sqlite3.Error:
        connection.rollback()
        raise

    finally:
        connection.close()


def get_user_by_email(email):
    connection = get_connection()

    try:
        user = connection.execute("""
            SELECT id, name, email, password, password_hash
            FROM users
            WHERE LOWER(email) = LOWER(?)
        """, (email,)).fetchone()

        if not user:
            return None

        data = dict(user)

        if not data.get("name"):
            data["name"] = data.get("username", "User")

        if not data.get("password"):
            data["password"] = data.get("password_hash", "")

        return data

    finally:
        connection.close()


def save_scan(user_id, url, score, risk_level, results):
    connection = get_connection()

    try:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        columns = {
            row["name"]
            for row in connection.execute(
                "PRAGMA table_info(scans)"
            ).fetchall()
        }

        values = {
            "user_id": user_id,
            "url": url,
            "score": score,
            "risk_level": risk_level,
            "level": risk_level,
            "results": json.dumps(results),
            "created_at": now
        }

        selected = {
            key: value
            for key, value in values.items()
            if key in columns
        }

        names = ", ".join(selected.keys())
        placeholders = ", ".join(["?"] * len(selected))

        cursor = connection.execute(
            f"INSERT INTO scans ({names}) VALUES ({placeholders})",
            tuple(selected.values())
        )

        connection.commit()
        return cursor.lastrowid

    except sqlite3.Error:
        connection.rollback()
        raise

    finally:
        connection.close()


def get_user_scans(user_id):
    connection = get_connection()

    try:
        rows = connection.execute("""
            SELECT id, user_id, url, score, risk_level, level, created_at
            FROM scans
            WHERE user_id = ?
            ORDER BY id DESC
        """, (user_id,)).fetchall()

        return [dict(row) for row in rows]

    finally:
        connection.close()


def get_scan(scan_id, user_id):
    connection = get_connection()

    try:
        row = connection.execute("""
            SELECT *
            FROM scans
            WHERE id = ? AND user_id = ?
        """, (scan_id, user_id)).fetchone()

        if not row:
            return None

        data = dict(row)

        if not data.get("risk_level"):
            data["risk_level"] = data.get("level", "Pending")

        try:
            data["results"] = json.loads(data["results"])
        except (TypeError, json.JSONDecodeError):
            data["results"] = {}

        return data

    finally:
        connection.close()


init_db()
