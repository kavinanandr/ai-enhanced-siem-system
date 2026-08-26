"""
database/db.py
SQLite connection handling and schema initialization.

Schema follows PRD section 12 (Database Schema), with two small,
clearly-documented additions kept in the same spirit of the spec:
  - Logs.host_name  -> the parser (section 6, "Log Parser") is required
                       to extract a Host Name, so it needs a column.
  - Logs.is_suspicious / Logs.file_id -> needed to support "only
                       suspicious logs are forwarded to AI" and the
                       Upload page's per-file log view/delete.
  - Incidents.log_id / source_ip / username / reason -> needed so an
                       incident can be traced back to the log(s) that
                       triggered it and displayed meaningfully on the
                       dashboard / incident history / reports pages.
"""

import sqlite3
from pathlib import Path

from config import Config


def get_connection():
    Path(Config.DATABASE_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(Config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


SCHEMA = """
CREATE TABLE IF NOT EXISTS files (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    filename      TEXT NOT NULL,
    stored_path   TEXT NOT NULL,
    upload_time   TEXT NOT NULL DEFAULT (datetime('now')),
    log_count     INTEGER NOT NULL DEFAULT 0,
    status        TEXT NOT NULL DEFAULT 'uploaded'  -- uploaded | analyzed
);

CREATE TABLE IF NOT EXISTS logs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id       INTEGER REFERENCES files(id) ON DELETE CASCADE,
    timestamp     TEXT,
    ip_address    TEXT,
    username      TEXT,
    event_type    TEXT,
    host_name     TEXT,
    message       TEXT,
    raw_line      TEXT,
    is_suspicious INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS incidents (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id         INTEGER REFERENCES files(id) ON DELETE SET NULL,
    log_id          INTEGER REFERENCES logs(id) ON DELETE SET NULL,
    attack_type     TEXT NOT NULL,
    severity        TEXT NOT NULL CHECK (severity IN ('Low','Medium','High','Critical')),
    reason          TEXT,
    ai_summary      TEXT,
    recommendation  TEXT,
    source_ip       TEXT,
    username        TEXT,
    ai_provider     TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_logs_ip ON logs(ip_address);
CREATE INDEX IF NOT EXISTS idx_logs_file ON logs(file_id);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_incidents_created ON incidents(created_at);
"""


def init_db():
    conn = get_connection()
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()
