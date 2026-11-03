"""
Database layer for Secure Password Manager.
Uses SQLite for persistent storage of the vault metadata and encrypted credentials.
"""

import sqlite3
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vault.db")


def get_connection() -> sqlite3.Connection:
    """Return a connection to the SQLite database with row_factory set."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    """Create tables if they don't exist."""
    conn = get_connection()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS master (
            id          INTEGER PRIMARY KEY CHECK (id = 1),
            salt        BLOB    NOT NULL,
            key_hash    TEXT    NOT NULL,
            created_at  TEXT    NOT NULL
        );

        CREATE TABLE IF NOT EXISTS passwords (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            site_name           TEXT    NOT NULL,
            site_url            TEXT    DEFAULT '',
            username            TEXT    NOT NULL,
            encrypted_password  TEXT    NOT NULL,
            category            TEXT    DEFAULT 'General',
            notes               TEXT    DEFAULT '',
            created_at          TEXT    NOT NULL,
            updated_at          TEXT    NOT NULL
        );
    """)
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Master password helpers
# ---------------------------------------------------------------------------

def is_master_set() -> bool:
    """Return True if the master password has been configured."""
    try:
        conn = get_connection()
        row = conn.execute("SELECT COUNT(*) AS cnt FROM master").fetchone()
        conn.close()
        return row["cnt"] > 0
    except sqlite3.OperationalError:
        # Database file was deleted or tables are missing, auto-initialize
        init_db()
        return False


def save_master(salt: bytes, key_hash: str):
    """Persist the master salt and key hash."""
    conn = get_connection()
    conn.execute(
        "INSERT INTO master (id, salt, key_hash, created_at) VALUES (1, ?, ?, ?)",
        (salt, key_hash, datetime.utcnow().isoformat()),
    )
    conn.commit()
    conn.close()


def get_master() -> dict | None:
    """Retrieve master record (salt + key_hash)."""
    conn = get_connection()
    row = conn.execute("SELECT salt, key_hash FROM master WHERE id = 1").fetchone()
    conn.close()
    if row is None:
        return None
    return {"salt": row["salt"], "key_hash": row["key_hash"]}


# ---------------------------------------------------------------------------
# Password CRUD
# ---------------------------------------------------------------------------

def add_password(site_name: str, site_url: str, username: str,
                 encrypted_password: str, category: str, notes: str) -> int:
    """Insert a new credential and return its id."""
    now = datetime.utcnow().isoformat()
    conn = get_connection()
    cur = conn.execute(
        """INSERT INTO passwords
           (site_name, site_url, username, encrypted_password, category, notes, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (site_name, site_url, username, encrypted_password, category, notes, now, now),
    )
    conn.commit()
    new_id = cur.lastrowid
    conn.close()
    return new_id


def get_all_passwords() -> list[dict]:
    """Return every stored credential row as a list of dicts."""
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM passwords ORDER BY updated_at DESC"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_password_by_id(pw_id: int) -> dict | None:
    """Return a single credential by id."""
    conn = get_connection()
    row = conn.execute("SELECT * FROM passwords WHERE id = ?", (pw_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def update_password(pw_id: int, site_name: str, site_url: str,
                    username: str, encrypted_password: str,
                    category: str, notes: str) -> bool:
    """Update an existing credential. Returns True if a row was affected."""
    now = datetime.utcnow().isoformat()
    conn = get_connection()
    cur = conn.execute(
        """UPDATE passwords
           SET site_name = ?, site_url = ?, username = ?, encrypted_password = ?,
               category = ?, notes = ?, updated_at = ?
           WHERE id = ?""",
        (site_name, site_url, username, encrypted_password, category, notes, now, pw_id),
    )
    conn.commit()
    affected = cur.rowcount
    conn.close()
    return affected > 0


def delete_password(pw_id: int) -> bool:
    """Delete a credential by id. Returns True if a row was affected."""
    conn = get_connection()
    cur = conn.execute("DELETE FROM passwords WHERE id = ?", (pw_id,))
    conn.commit()
    affected = cur.rowcount
    conn.close()
    return affected > 0


def get_stats() -> dict:
    """Return aggregate statistics for the dashboard."""
    conn = get_connection()
    total = conn.execute("SELECT COUNT(*) AS cnt FROM passwords").fetchone()["cnt"]
    categories = conn.execute(
        "SELECT category, COUNT(*) AS cnt FROM passwords GROUP BY category ORDER BY cnt DESC"
    ).fetchall()
    conn.close()
    return {
        "total": total,
        "categories": [{"name": r["category"], "count": r["cnt"]} for r in categories],
    }


def update_master_and_reencrypt(new_salt: bytes, new_key_hash: str, reencrypted_passwords: list) -> bool:
    """Update master salt/hash and re-encrypt all stored passwords in a single transaction."""
    conn = get_connection()
    try:
        with conn:
            # Update master record
            conn.execute(
                "UPDATE master SET salt = ?, key_hash = ? WHERE id = 1",
                (new_salt, new_key_hash)
            )
            # Update each password
            for pw_id, enc_pw in reencrypted_passwords:
                conn.execute(
                    "UPDATE passwords SET encrypted_password = ? WHERE id = ?",
                    (enc_pw, pw_id)
                )
        return True
    except Exception:
        return False
    finally:
        conn.close()
