"""
<<<<<<< HEAD
PacketGuard — Database migrations for the four new enterprise modules.
=======
PacketGuard - Database migrations for the four new enterprise modules.
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)

Run once at app startup via init_new_tables(db_conn) or call directly.
All queries are SQLite-compatible.
"""

import sqlite3
import logging

logger = logging.getLogger(__name__)


def init_new_tables(conn: sqlite3.Connection) -> None:
    """Create all new tables if they don't already exist."""
    conn.execute("PRAGMA journal_mode=WAL")   # better concurrency
    conn.execute("PRAGMA foreign_keys=ON")

    _create_correlated_incidents(conn)
    _create_threat_scores(conn)
    _create_response_actions(conn)
    _create_baseline_tables(conn)
<<<<<<< HEAD
=======
    _create_email_queue(conn)
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)

    conn.commit()
    logger.info("PacketGuard new tables initialised successfully.")


<<<<<<< HEAD
# ─────────────────────────────────────────────
# 1. Correlation engine
# ─────────────────────────────────────────────
=======
# ---------------------------------------------
# 1. Correlation engine
# ---------------------------------------------
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)

def _create_correlated_incidents(conn: sqlite3.Connection) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS correlated_incidents (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            source_ip       TEXT    NOT NULL,
            device_id       TEXT,
            -- Human-readable attack chain name, e.g. 'Possible Intrusion Attempt'
            chain_name      TEXT    NOT NULL,
            -- JSON array of alert IDs that were correlated
            alert_ids       TEXT    NOT NULL DEFAULT '[]',
            -- JSON array of individual event type strings
            event_types     TEXT    NOT NULL DEFAULT '[]',
            severity        TEXT    NOT NULL DEFAULT 'medium'
                                    CHECK(severity IN ('low','medium','high','critical')),
            -- Epoch timestamp of the first event in the window
            window_start    REAL    NOT NULL,
            -- Epoch timestamp of the last event
            window_end      REAL    NOT NULL,
            -- Prevent re-alerting on the same chain within a cooldown period
            last_alerted_at REAL,
            created_at      REAL    NOT NULL DEFAULT (unixepoch('now')),
            -- Whether a human analyst has acknowledged this incident
            acknowledged    INTEGER NOT NULL DEFAULT 0,
            notes           TEXT
        )
    """)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_ci_source_ip ON correlated_incidents(source_ip)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_ci_created ON correlated_incidents(created_at)"
    )


<<<<<<< HEAD
# ─────────────────────────────────────────────
# 2. Threat scoring
# ─────────────────────────────────────────────
=======
# ---------------------------------------------
# 2. Threat scoring
# ---------------------------------------------
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)

def _create_threat_scores(conn: sqlite3.Connection) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS threat_scores (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            source_ip       TEXT    NOT NULL UNIQUE,
            -- Current cumulative score (decays over time)
            score           REAL    NOT NULL DEFAULT 0,
            -- Derived label updated on every write
            threat_level    TEXT    NOT NULL DEFAULT 'low'
                                    CHECK(threat_level IN ('low','medium','high','critical')),
            -- JSON breakdown: {"port_scan": 20, "ml_anomaly": 30, ...}
            score_breakdown TEXT    NOT NULL DEFAULT '{}',
            -- Last time a scoring event was recorded
            last_event_at   REAL,
            -- Last time the decay background job ran on this row
            last_decay_at   REAL,
            first_seen_at   REAL    NOT NULL DEFAULT (unixepoch('now')),
            updated_at      REAL    NOT NULL DEFAULT (unixepoch('now'))
        )
    """)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_ts_score ON threat_scores(score DESC)"
    )

    # Audit log: every score change is recorded for forensic review
    conn.execute("""
        CREATE TABLE IF NOT EXISTS threat_score_events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            source_ip   TEXT    NOT NULL,
            event_type  TEXT    NOT NULL,   -- e.g. 'port_scan', 'syn_flood'
            delta       REAL    NOT NULL,   -- points added (positive) or decayed (negative)
            score_after REAL    NOT NULL,
            recorded_at REAL    NOT NULL DEFAULT (unixepoch('now'))
        )
    """)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_tse_ip ON threat_score_events(source_ip)"
    )


<<<<<<< HEAD
# ─────────────────────────────────────────────
# 3. Auto response (IPS)
# ─────────────────────────────────────────────
=======
# ---------------------------------------------
# 3. Auto response (IPS)
# ---------------------------------------------
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)

def _create_response_actions(conn: sqlite3.Connection) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS response_actions (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            source_ip       TEXT    NOT NULL,
            -- What action was taken
            action_type     TEXT    NOT NULL
                                    CHECK(action_type IN (
                                        'block_ip', 'add_firewall_rule',
                                        'send_email', 'quarantine',
                                        'kill_session', 'rate_limit'
                                    )),
            -- What triggered the action
            trigger_reason  TEXT    NOT NULL,
            -- Score or severity at time of action
            trigger_score   REAL,
            trigger_severity TEXT,
            -- Was this action taken automatically or by a human?
            triggered_by    TEXT    NOT NULL DEFAULT 'auto'
                                    CHECK(triggered_by IN ('auto', 'manual')),
            -- How long the action lasts (NULL = permanent)
            duration_seconds INTEGER,
            -- When the action expires (NULL = permanent)
            expires_at      REAL,
            -- Was the action reverted/overridden?
            reverted        INTEGER NOT NULL DEFAULT 0,
            reverted_by     TEXT,
            reverted_at     REAL,
            created_at      REAL    NOT NULL DEFAULT (unixepoch('now')),
            notes           TEXT
        )
    """)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_ra_source_ip ON response_actions(source_ip)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_ra_created ON response_actions(created_at)"
    )

    # Cooldown tracking: prevents the same action on the same IP within N seconds
    conn.execute("""
        CREATE TABLE IF NOT EXISTS response_cooldowns (
            source_ip       TEXT NOT NULL,
            action_type     TEXT NOT NULL,
            last_triggered  REAL NOT NULL,
            PRIMARY KEY (source_ip, action_type)
        )
    """)


<<<<<<< HEAD
# ─────────────────────────────────────────────
# 4. Baseline learning
# ─────────────────────────────────────────────
=======
# ---------------------------------------------
# 4. Baseline learning
# ---------------------------------------------
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)

def _create_baseline_tables(conn: sqlite3.Connection) -> None:
    # Per-hour rolling baseline profiles
    conn.execute("""
        CREATE TABLE IF NOT EXISTS baseline_profiles (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            -- 0-23 hour of day (local time) this profile applies to
            hour_of_day     INTEGER NOT NULL CHECK(hour_of_day BETWEEN 0 AND 23),
            -- Day of week 0=Mon … 6=Sun
            day_of_week     INTEGER NOT NULL CHECK(day_of_week BETWEEN 0 AND 6),
            -- Expected packets/second (rolling mean)
            avg_pkt_rate    REAL    NOT NULL DEFAULT 0,
            -- Standard deviation of packet rate (used to compute ±2σ threshold)
            std_pkt_rate    REAL    NOT NULL DEFAULT 0,
            avg_byte_rate   REAL    NOT NULL DEFAULT 0,
            std_byte_rate   REAL    NOT NULL DEFAULT 0,
            -- Expected number of unique active devices
            avg_device_count REAL   NOT NULL DEFAULT 0,
            std_device_count REAL   NOT NULL DEFAULT 0,
            -- JSON map: {"TCP": 0.65, "UDP": 0.25, "ICMP": 0.05, "OTHER": 0.05}
            protocol_dist   TEXT    NOT NULL DEFAULT '{}',
            -- How many observation windows contributed to this profile
            sample_count    INTEGER NOT NULL DEFAULT 0,
            updated_at      REAL    NOT NULL DEFAULT (unixepoch('now')),
            UNIQUE(hour_of_day, day_of_week)
        )
    """)

    # Raw observations stored per 60-second window (used to update profiles)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS baseline_stats (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            observed_at     REAL    NOT NULL DEFAULT (unixepoch('now')),
            hour_of_day     INTEGER NOT NULL,
            day_of_week     INTEGER NOT NULL,
            pkt_rate        REAL    NOT NULL,
            byte_rate       REAL    NOT NULL,
            device_count    INTEGER NOT NULL,
            -- JSON map of protocol counts
            protocol_counts TEXT    NOT NULL DEFAULT '{}',
            -- Deviation % from baseline at time of observation (NULL if no baseline yet)
            pkt_rate_deviation_pct  REAL,
            byte_rate_deviation_pct REAL,
            -- Was this window flagged as anomalous?
            anomalous       INTEGER NOT NULL DEFAULT 0
        )
    """)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_bstat_time ON baseline_stats(observed_at)"
    )

    # Per-IP baseline (tracks individual host normal behaviour)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS baseline_ip_profiles (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            source_ip       TEXT    NOT NULL,
            hour_of_day     INTEGER NOT NULL,
            avg_pkt_rate    REAL    NOT NULL DEFAULT 0,
            std_pkt_rate    REAL    NOT NULL DEFAULT 0,
            -- Typical destination ports (JSON array of most common ports)
            common_dst_ports TEXT   NOT NULL DEFAULT '[]',
            -- Typical protocols JSON map
            protocol_dist   TEXT    NOT NULL DEFAULT '{}',
            sample_count    INTEGER NOT NULL DEFAULT 0,
            updated_at      REAL    NOT NULL DEFAULT (unixepoch('now')),
            UNIQUE(source_ip, hour_of_day)
        )
    """)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_bip_ip ON baseline_ip_profiles(source_ip)"
    )
<<<<<<< HEAD
=======


# ---------------------------------------------
# 5. Email queue (for mail_worker.py)
# ---------------------------------------------

def _create_email_queue(conn: sqlite3.Connection) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS email_queue (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            to_email    TEXT NOT NULL,
            subject     TEXT NOT NULL,
            body_plain  TEXT NOT NULL,
            body_html   TEXT NOT NULL,
            status      TEXT NOT NULL DEFAULT 'pending'
                                CHECK(status IN ('pending','sent','failed')),
            created_at  REAL NOT NULL DEFAULT (unixepoch('now')),
            sent_at     REAL
        )
    """)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_eq_status ON email_queue(status, created_at)"
    )
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
