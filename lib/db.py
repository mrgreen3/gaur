"""
lib/db.py — Local state database

Tracks:
  - Installed packages and versions
  - Reviewed PKGBUILD commits (per package)
  - --force-unsafe usage log
"""

import sqlite3
import time
from pathlib import Path

DB_PATH = Path.home() / ".local" / "share" / "gaur" / "gaur.db"


class GaurDB:
    def __init__(self, path: Path = DB_PATH):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path)
        self._init_schema()

    def _init_schema(self):
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS installed (
                name        TEXT PRIMARY KEY,
                version     TEXT,
                installed_at INTEGER
            );

            CREATE TABLE IF NOT EXISTS reviewed_commits (
                name        TEXT PRIMARY KEY,
                commit_hash TEXT,
                reviewed_at INTEGER
            );

            CREATE TABLE IF NOT EXISTS force_unsafe_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                name        TEXT,
                logged_at   INTEGER
            );
        """)
        self.conn.commit()

    def mark_installed(self, name: str, version: str):
        self.conn.execute("""
            INSERT INTO installed (name, version, installed_at)
            VALUES (?, ?, ?)
            ON CONFLICT(name) DO UPDATE SET version=excluded.version,
                                            installed_at=excluded.installed_at
        """, (name, version, int(time.time())))
        self.conn.commit()

    def get_installed(self) -> dict:
        rows = self.conn.execute(
            "SELECT name, version FROM installed"
        ).fetchall()
        return {row[0]: row[1] for row in rows}

    def get_reviewed_commit(self, name: str) -> str | None:
        row = self.conn.execute(
            "SELECT commit_hash FROM reviewed_commits WHERE name = ?", (name,)
        ).fetchone()
        return row[0] if row else None

    def set_reviewed_commit(self, name: str, commit_hash: str):
        self.conn.execute("""
            INSERT INTO reviewed_commits (name, commit_hash, reviewed_at)
            VALUES (?, ?, ?)
            ON CONFLICT(name) DO UPDATE SET commit_hash=excluded.commit_hash,
                                            reviewed_at=excluded.reviewed_at
        """, (name, commit_hash, int(time.time())))
        self.conn.commit()

    def log_force_unsafe(self, name: str):
        self.conn.execute(
            "INSERT INTO force_unsafe_log (name, logged_at) VALUES (?, ?)",
            (name, int(time.time()))
        )
        self.conn.commit()

    def close(self):
        self.conn.close()
