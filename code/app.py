"""
app.py — PacketGuard
Main entry point. Wires together all modules and starts the server.
Run with:  python app.py
Or via:    start.py  (imports app and socketio from here)
"""

import warnings
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")
warnings.filterwarnings("ignore", message=".*feature names.*",  category=UserWarning)
warnings.filterwarnings("ignore", message=".*delayed.*Parallel.*", category=UserWarning)

import logging

class _DropDisconnected(logging.Filter):
    """Suppress the benign 'Session is disconnected' KeyError from engine.io."""
    def filter(self, record):
        return "Session is disconnected" not in (record.getMessage())

for _log_name in ("werkzeug", "engineio", "socketio"):
    logging.getLogger(_log_name).addFilter(_DropDisconnected())

import os
import sys
import json
import sqlite3
import threading
import time
from datetime import datetime, timezone

# ── Core app & config ──────────────────────────────────────────────
from config import app, socketio, BASE_DIR, DB_PATH, SCAN_INTERVAL

# ── Auth service (DB init) ─────────────────────────────────────────
from auth_service import get_db, hash_password

# ── DB migrations (alerts table + enterprise tables) ───────────────
from db_manager import run_migrations

# ── Data service ───────────────────────────────────────────────────
from data_service import (
    load_alerts, load_ml_alerts, load_devices, load_live_stats, load_model_info,
    total_alert_count, push_alert, push_live_stats,
)

# ── Background threads ─────────────────────────────────────────────
from socket_handlers import init_socket_handlers

# ── Route blueprints ───────────────────────────────────────────────
from api_routes    import api_bp
from auth_routes   import auth_bp
from page_routes   import page_bp
from enterprise_bp import enterprise_bp

app.register_blueprint(api_bp)
app.register_blueprint(auth_bp)
app.register_blueprint(page_bp)
app.register_blueprint(enterprise_bp)


# ── DB init + migrations ───────────────────────────────────────────
def _init_db():
    """Create/migrate all tables."""
    conn = get_db()
    # users table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            name       TEXT NOT NULL,
            email      TEXT NOT NULL UNIQUE,
            password   TEXT NOT NULL,
            role       TEXT NOT NULL DEFAULT 'analyst',
            created_at TEXT NOT NULL,
            last_login TEXT
        )
    """)
    # access_log table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS access_log (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER,
            user_name  TEXT,
            user_email TEXT,
            user_role  TEXT,
            event_type TEXT,
            detail     TEXT,
            source_ip  TEXT,
            user_agent TEXT,
            timestamp  TEXT NOT NULL
        )
    """)
    # unblock_requests table — drop and recreate if schema is outdated
    existing_cols = {row[1] for row in conn.execute("PRAGMA table_info(unblock_requests)").fetchall()}
    if existing_cols and "submitted_by" not in existing_cols:
        conn.execute("DROP TABLE unblock_requests")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS unblock_requests (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            req_ip          TEXT NOT NULL,
            reason          TEXT,
            justification   TEXT,
            alert_ref       TEXT,
            submitted_by    INTEGER,
            submitter_name  TEXT,
            submitter_email TEXT,
            status          TEXT NOT NULL DEFAULT 'pending',
            submitted_at    TEXT NOT NULL DEFAULT (datetime('now')),
            admin_note      TEXT,
            reviewed_by     INTEGER,
            reviewer_name   TEXT,
            reviewed_at     TEXT
        )
    """)
    # account_requests table — pending signups awaiting admin approval
    conn.execute("""
        CREATE TABLE IF NOT EXISTS account_requests (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            name          TEXT NOT NULL,
            email         TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role          TEXT NOT NULL DEFAULT 'analyst',
            status        TEXT NOT NULL DEFAULT 'pending',
            submitted_at  TEXT NOT NULL DEFAULT (datetime('now')),
            admin_note    TEXT,
            reviewed_by   INTEGER,
            reviewer_name TEXT,
            reviewed_at   TEXT
        )
    """)
    conn.commit()
    conn.close()


# ── Scan history helpers ───────────────────────────────────────────
from config import SCAN_HISTORY_FILE

def load_scan_history():
    try:
        with open(SCAN_HISTORY_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


# ── Startup ────────────────────────────────────────────────────────
run_migrations()   # creates alerts + enterprise tables
_init_db()         # creates users, access_log, unblock_requests, account_requests

# Start packet capture in-process immediately (before socketio.run blocks).
# This runs in background threads inside this process — no subprocess needed,
# no lock-file races, no Werkzeug-reloader guard issues.
if not os.environ.get("PACKETGUARD_MONITOR_PROC"):
    try:
        from live_monitor import start_monitoring as _start_live_capture
        _start_live_capture(socketio=socketio, app=app)
        print("[CAPTURE] In-process packet capture started.")
    except Exception as _cap_err:
        print(f"[CAPTURE] Could not start in-process capture: {_cap_err}")

init_socket_handlers()

# ── Auto-response + correlation engine ────────────────────────────
# Wire socketio emit so block events reach the dashboard in real time
try:
    from firewall_enforcer import set_emit_callback as _fw_emit
    from block_manager     import set_emit_callback as _bm_emit
    _fw_emit(socketio.emit)
    _bm_emit(socketio.emit)
except Exception as _e:
    print(f"[BLOCK] Could not set emit callbacks: {_e}")

# Start correlation engine (runs every 15s — creates incidents from alerts)
try:
    from correlation_engine_v2 import start_correlation_thread
    start_correlation_thread()
    print("[CORR] Correlation engine started.")
except Exception as _e:
    print(f"[CORR] Could not start correlation engine: {_e}")

# Start auto-response sweep (runs every 120s — blocks top-risk IPs)
try:
    from auto_response import start_response_thread
    start_response_thread()
    print("[RESP] Auto-response thread started.")
except Exception as _e:
    print(f"[RESP] Could not start auto-response: {_e}")

# ── Auto ARP spoofing ──────────────────────────────────────────────
# Enabled by setting ARP_SPOOF_AUTO=true in code/env.
# Requires: Npcap installed, app running as Administrator.
# Sequence: wait for app → scan LAN for targets → start spoofing.
if os.environ.get("ARP_SPOOF_AUTO", "").lower() == "true":
    def _auto_arp_spoof_thread():
        time.sleep(12)  # let Flask + Scapy fully initialise
        # Discover LAN devices first so the spoof loop has real targets
        try:
            from api_routes import run_network_scan_with_history
            print("[ARP] Auto-spoof: running initial LAN scan...")
            run_network_scan_with_history()
            print("[ARP] Auto-spoof: LAN scan complete.")
        except Exception as _e:
            print(f"[ARP] Auto-spoof: scan error — {_e}")
        time.sleep(3)
        # Start spoofing
        try:
            from arp_spoof import start_spoofing, get_status
            ok = start_spoofing()
            time.sleep(0.5)   # let spoof loop run its first iteration
            st = get_status()
            if ok:
                print(f"[ARP] Auto-spoof ACTIVE — gateway: {st['gateway_ip']}, "
                      f"targets poisoned: {st['targets_poisoned']}")
            else:
                err = st.get("error", "unknown error")
                print(f"[ARP] Auto-spoof FAILED: {err}")
                print("[ARP] Fix: run app as Administrator and ensure Npcap is installed.")
        except Exception as _e:
            print(f"[ARP] Auto-spoof error: {_e}")

    threading.Thread(
        target=_auto_arp_spoof_thread,
        daemon=True,
        name="auto-arp-spoof"
    ).start()
    print("[ARP] Auto-spoof scheduled — starts after LAN scan (12s).")


# ── Main ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("""
+-----------------------------------------------------------+
|         PacketGuard - Network Threat Dashboard            |
|        Access from: http://localhost:5000                 |
|   Auto-scanning network every 20 seconds...              |
+-----------------------------------------------------------+
    """)

    try:
        from ml_detector import get_detector
        _det = get_detector()
        if _det.ready:
            print(f"[ML] Detector ready — models: {_det.status()['models_loaded']}")
        else:
            print("[ML] WARNING: No trained models found. Run train_cicids.py first.")
    except Exception as _e:
        print(f"[ML] Could not load detector: {_e}")

    socketio.run(app, host="0.0.0.0", port=5000, debug=False, allow_unsafe_werkzeug=True)
