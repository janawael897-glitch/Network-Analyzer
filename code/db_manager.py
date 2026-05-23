#!/usr/bin/env python3
"""
db_manager.py — PacketGuard SQLite Database Manager
Creates and migrates all tables used by enterprise features.
"""

import os
import sqlite3
import threading

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH  = os.path.join(BASE_DIR, "packetguard.db")

_local = threading.local()


def get_db() -> sqlite3.Connection:
    """Return a thread-local SQLite connection."""
    conn = sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def run_migrations():
    """Create all tables if they don't exist."""
    conn = get_db()
    try:
        conn.executescript("""
            -- Correlation incidents
            CREATE TABLE IF NOT EXISTS incidents (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id     TEXT    NOT NULL UNIQUE,
                source_ip       TEXT    NOT NULL,
                alert_type      TEXT    NOT NULL DEFAULT 'UNKNOWN',
                severity        TEXT    NOT NULL DEFAULT 'LOW',
                status          TEXT    NOT NULL DEFAULT 'open',
                title           TEXT,
                description     TEXT,
                attack_chain    TEXT,
                first_seen      TEXT,
                last_seen       TEXT,
                closed_at       TEXT,
                notes           TEXT,
                risk_score      REAL    DEFAULT 0,
                confidence      REAL    DEFAULT 0,
                event_count     INTEGER DEFAULT 1,
                escalation_level INTEGER DEFAULT 0,
                ml_anomaly_count INTEGER DEFAULT 0
            );

            -- Host risk profiles (threat scoring)
            CREATE TABLE IF NOT EXISTS host_profiles (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                ip              TEXT    NOT NULL UNIQUE,
                risk_score      REAL    DEFAULT 0,
                classification  TEXT    DEFAULT 'Unknown',
                total_alerts    INTEGER DEFAULT 0,
                ml_anomaly_count INTEGER DEFAULT 0,
                unique_ports    INTEGER DEFAULT 0,
                recurrence      INTEGER DEFAULT 0,
                first_seen      TEXT,
                last_seen       TEXT,
                threat_level    TEXT    DEFAULT 'LOW'
            );

            -- Auto-response action log
            CREATE TABLE IF NOT EXISTS response_log (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                source_ip       TEXT    NOT NULL,
                action_type     TEXT    NOT NULL,
                action_label    TEXT,
                action_time     TEXT    NOT NULL,
                description     TEXT,
                risk_score      REAL    DEFAULT 0,
                executed        INTEGER DEFAULT 0,
                severity        TEXT    DEFAULT 'LOW',
                result          TEXT
            );

            -- Baseline traffic samples
            CREATE TABLE IF NOT EXISTS baseline_samples (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                sample_time TEXT    NOT NULL,
                pps         REAL    DEFAULT 0,
                bps         REAL    DEFAULT 0,
                tcp_pct     REAL    DEFAULT 0,
                udp_pct     REAL    DEFAULT 0
            );

            -- Anomaly history
            CREATE TABLE IF NOT EXISTS anomaly_history (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                event_time  TEXT    NOT NULL,
                metric      TEXT,
                value       REAL,
                baseline    REAL,
                deviation   REAL
            );
        """)
        conn.commit()
        print("[DB] Migrations complete.")
    except Exception as e:
        print(f"[DB] Migration error: {e}")
    finally:
        conn.close()