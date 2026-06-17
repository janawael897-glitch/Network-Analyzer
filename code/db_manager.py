#!/usr/bin/env python3
"""
<<<<<<< HEAD
db_manager.py — PacketGuard SQLite Database Manager
=======
db_manager.py - PacketGuard SQLite Database Manager
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
Creates and migrates all tables used by enterprise features.
"""

import os
import sqlite3
import threading

<<<<<<< HEAD
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
=======
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
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
<<<<<<< HEAD
=======
            
            -- Alerts (migrated from alerts.json)
            CREATE TABLE IF NOT EXISTS alerts (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id        TEXT    UNIQUE,
                alert_type      TEXT    NOT NULL DEFAULT 'UNKNOWN',
                severity        TEXT    NOT NULL DEFAULT 'LOW',
                source_ip       TEXT,
                destination_ip  TEXT,
                destination_port INTEGER,
                protocol        TEXT,
                message         TEXT,
                timestamp       TEXT    NOT NULL,
                additional_info TEXT,
                is_ml           INTEGER NOT NULL DEFAULT 0,
                status          TEXT    DEFAULT 'NEW',
                assigned_to     TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_alerts_type     ON alerts(alert_type);
            CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
            CREATE INDEX IF NOT EXISTS idx_alerts_src      ON alerts(source_ip);
            CREATE INDEX IF NOT EXISTS idx_alerts_time     ON alerts(timestamp);
            CREATE INDEX IF NOT EXISTS idx_alerts_ml       ON alerts(is_ml);
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
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
<<<<<<< HEAD
        """)
        conn.commit()
=======

            -- Live monitor state (single row, id always = 1, updated every second)
            CREATE TABLE IF NOT EXISTS email_queue (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                to_email    TEXT    NOT NULL,
                subject     TEXT    NOT NULL,
                body_plain  TEXT    NOT NULL,
                body_html   TEXT    NOT NULL DEFAULT '',
                status      TEXT    NOT NULL DEFAULT 'pending',
                created_at  REAL    NOT NULL DEFAULT (unixepoch('now')),
                sent_at     REAL
            );
            CREATE TABLE IF NOT EXISTS live_state (
                id               INTEGER PRIMARY KEY CHECK(id = 1),
                total_packets    INTEGER NOT NULL DEFAULT 0,
                bytes_total      INTEGER NOT NULL DEFAULT 0,
                packets_per_sec  REAL    NOT NULL DEFAULT 0.0,
                bytes_per_sec    REAL    NOT NULL DEFAULT 0.0,
                runtime_seconds  INTEGER NOT NULL DEFAULT 0,
                running          INTEGER NOT NULL DEFAULT 0,
                protocols        TEXT    NOT NULL DEFAULT '{}',
                top_ips          TEXT    NOT NULL DEFAULT '{}',
                ml_total         INTEGER NOT NULL DEFAULT 0,
                ml_detections    INTEGER NOT NULL DEFAULT 0,
                ml_recent_alerts TEXT    NOT NULL DEFAULT '[]',
                interface        TEXT,
                last_updated     TEXT    NOT NULL DEFAULT ''
            );
        """)
        conn.commit()

        # Column migrations for existing databases
        existing_alert_cols = {r[1] for r in conn.execute("PRAGMA table_info(alerts)").fetchall()}
        for col, defn in [("status", "TEXT DEFAULT 'NEW'"), ("assigned_to", "TEXT")]:
            if col not in existing_alert_cols:
                try:
                    conn.execute(f"ALTER TABLE alerts ADD COLUMN {col} {defn}")
                    conn.commit()
                except Exception:
                    pass

>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
        print("[DB] Migrations complete.")
    except Exception as e:
        print(f"[DB] Migration error: {e}")
    finally:
        conn.close()