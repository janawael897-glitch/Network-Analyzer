#!/usr/bin/env python3
"""
SENTINEL - Network Threat Detection Dashboard
Auto-scans network every 60 seconds so offline devices disappear.
"""

import json
import os
import re
import sys
import threading
import time
from datetime import datetime
from flask import Flask, jsonify, Response, request
from flask_cors import CORS

app = Flask(__name__)
app.secret_key = "packetguard-secret-key-2026"  # fixed key so sessions survive restarts
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_HTTPONLY"] = True
CORS(app, supports_credentials=True)

BASE_DIR         = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ALERTS_FILE      = os.path.join(BASE_DIR, "alerts.json")
ML_ALERTS_FILE   = os.path.join(BASE_DIR, "ml_alerts.json")
DEVICES_FILE     = os.path.join(BASE_DIR, "network_devices.json")
LIVE_MONITOR_LOG = os.path.join(BASE_DIR, "live_monitor.log")
MODELS_DIR       = os.path.join(BASE_DIR, "models")

# ── Auto-scan state ────────────────────────────────────────────────
_scan_status = {
    "running": False,
    "last_scan": None,
    "next_scan": None,
    "device_count": 0,
}
SCAN_INTERVAL = 20  # seconds between scans


def run_network_scan():
    """Run the network scanner in the background."""
    global _scan_status
    _scan_status["running"] = True
    try:
        scanner_path = os.path.join(BASE_DIR, "code", "network_scanner.py")
        if not os.path.exists(scanner_path):
            print(f"[AUTO-SCAN] Scanner not found at {scanner_path}")
            return

        # Import and run the scanner directly
        import importlib.util
        spec = importlib.util.spec_from_file_location("network_scanner", scanner_path)
        mod  = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        devices = mod.scan_network()

        _scan_status["last_scan"]    = datetime.now().isoformat()
        _scan_status["device_count"] = len(devices) if devices else 0
        print(f"[AUTO-SCAN] Done — {_scan_status['device_count']} device(s) found at {_scan_status['last_scan']}")

    except Exception as e:
        print(f"[AUTO-SCAN] Error: {e}")
    finally:
        _scan_status["running"] = False
        _scan_status["next_scan"] = (
            datetime.fromtimestamp(time.time() + SCAN_INTERVAL).isoformat()
        )


def auto_scan_loop():
    """Background thread: wait 3s for Flask to start, then scan every SCAN_INTERVAL seconds."""
    print(f"[AUTO-SCAN] Starting background scanner (interval={SCAN_INTERVAL}s) ...")
    time.sleep(3)  # Wait for Flask to fully start
    run_network_scan_with_history()
    while True:
        time.sleep(SCAN_INTERVAL)
        run_network_scan_with_history()


# Start background scanner thread when module loads
_scanner_thread = threading.Thread(target=auto_scan_loop, daemon=True)
_scanner_thread.start()
print("[AUTO-SCAN] Background scanner thread started.")


# ── Data loaders ──────────────────────────────────────────────────

def load_alerts():
    try:
        with open(ALERTS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []

def load_ml_alerts():
    try:
        with open(ML_ALERTS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []

def load_devices():
    try:
        with open(DEVICES_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"devices": [], "network_range": "N/A", "local_ip": "N/A"}

LIVE_STATE_FILE  = os.path.join(BASE_DIR, "live_state.json")

def load_live_stats():
    try:
        with open(LIVE_STATE_FILE, "r", encoding="utf-8") as f:
            s = json.load(f)
        return {
            "packets":          s.get("total_packets", 0),
            "rate":             s.get("rate", 0.0),
            "bytes_total":      s.get("bytes_total", 0),
            "runtime_seconds":  s.get("runtime_seconds", 0),
            "running":          s.get("running", False),
            "protocols":        s.get("protocols", {}),
            "top_ips":          s.get("top_ips", {}),
            "recent_alerts":    s.get("recent_alerts", []),
            "last_updated":     s.get("last_updated", None),
        }
    except Exception:
        return {"packets": 0, "rate": 0.0, "bytes_total": 0,
                "runtime_seconds": 0, "running": False,
                "protocols": {}, "top_ips": {}, "recent_alerts": []}


def load_model_info():
    info = {"trained": False, "samples": 0, "precision": None, "recall": None, "f1": None}
    try:
        # Try multiple possible locations for the models folder
        candidates = [
            os.path.join(BASE_DIR, "models"),
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "models"),
            os.path.join(os.getcwd(), "models"),
        ]
        for models_dir in candidates:
            iso  = os.path.join(models_dir, "isolation_forest.pkl")
            meta = os.path.join(models_dir, "model_metadata.json")
            if os.path.exists(iso):
                info["trained"] = True
                if os.path.exists(meta):
                    with open(meta, "r", encoding="utf-8") as f:
                        info.update(json.load(f))
                return info
    except Exception as e:
        print(f"[MODEL] load_model_info error: {e}")
    return info


# ── API routes ────────────────────────────────────────────────────

@app.route("/api/alerts")
def api_alerts():
    return jsonify(load_alerts())

@app.route("/api/ml_alerts")
def api_ml_alerts():
    return jsonify(load_ml_alerts())

@app.route("/api/devices")
def api_devices():
    return jsonify(load_devices())

@app.route("/api/scan_status")
def api_scan_status():
    return jsonify(_scan_status)


@app.route("/api/network_info")
def api_network_info():
    """Return the real local IP and network range for the monitor page."""
    import socket, struct
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        local_ip = "127.0.0.1"
    parts = local_ip.split(".")
    network_range = ".".join(parts[:3]) + ".0/24"
    # Also pull from saved scan if available
    devices_data = load_devices()
    saved_ip    = devices_data.get("local_ip", local_ip)
    saved_range = devices_data.get("network_range", network_range)
    return jsonify({
        "local_ip":      saved_ip    if saved_ip    != "N/A" else local_ip,
        "network_range": saved_range if saved_range != "N/A" else network_range,
    })

@app.route("/api/live_state")
def api_live_state():
    """Return full live monitor state — polled every 2s by dashboard."""
    return jsonify(load_live_stats())


@app.route("/api/stats")
def api_stats():
    """Main stats endpoint — used by dashboard for all panels."""
    alerts    = load_alerts()
    ml_alerts = load_ml_alerts()
    devices   = load_devices()
    live      = load_live_stats()
    model     = load_model_info()

    by_type        = {}
    severity_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for a in alerts:
        t = a.get("alert_type", "UNKNOWN")
        by_type[t] = by_type.get(t, 0) + 1
        s = a.get("severity", "LOW")
        severity_count[s] = severity_count.get(s, 0) + 1

    ml_by_type = {}
    ml_sev     = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for a in ml_alerts:
        t = a.get("alert_type", "ANOMALY")
        ml_by_type[t] = ml_by_type.get(t, 0) + 1
        s = a.get("severity", "HIGH")
        ml_sev[s] = ml_sev.get(s, 0) + 1

    return jsonify({
        "total_alerts":    len(alerts),
        "total_ml_alerts": len(ml_alerts),
        "total_devices":   len(devices.get("devices", [])),
        "alerts_by_type":  by_type,
        "ml_by_type":      ml_by_type,
        "ml_severity":     ml_sev,
        "severity_count":  severity_count,
        "live":            live,
        "model":           model,
        "network_range":   devices.get("network_range", "N/A"),
        "local_ip":        devices.get("local_ip", "N/A"),
        "scan_status":     _scan_status,
    })




# ── Auth (SQLite + Flask session) ─────────────────────────────────
import sqlite3
import hashlib
import secrets
from flask import request as _req, session as _sess

DB_PATH = os.path.join(BASE_DIR, "packetguard.db")

def _db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def _init_db():
    conn = _db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            name       TEXT NOT NULL,
            email      TEXT NOT NULL UNIQUE,
            password   TEXT NOT NULL,
            role       TEXT NOT NULL DEFAULT 'user',
            created_at TEXT NOT NULL,
            last_login TEXT
        )
    """)
    conn.commit()
    # Default admin account
    if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        salt = secrets.token_hex(16)
        pw   = hashlib.sha256((salt + "admin123").encode()).hexdigest()
        conn.execute(
            "INSERT INTO users (name,email,password,role,created_at) VALUES (?,?,?,?,?)",
            ("Admin", "admin@packetguard.io", f"{salt}:{pw}", "admin", datetime.utcnow().isoformat())
        )
        conn.commit()
        print("[AUTH] Default admin: admin@packetguard.io / admin123")
    conn.close()

def _hash(pw): 
    salt = secrets.token_hex(16)
    return f"{salt}:{hashlib.sha256((salt+pw).encode()).hexdigest()}"

def _verify(pw, stored):
    try:
        salt, h = stored.split(":")
        return hashlib.sha256((salt+pw).encode()).hexdigest() == h
    except: return False

_init_db()


@app.route("/api/auth/register", methods=["POST"])
def api_register():
    data  = _req.get_json() or {}
    name  = data.get("name","").strip()
    email = data.get("email","").strip().lower()
    pw    = data.get("password","")
    if not name or not email or not pw:
        return jsonify({"success": False, "error": "All fields required."})
    if len(pw) < 6:
        return jsonify({"success": False, "error": "Password must be at least 6 characters."})
    conn = _db()
    try:
        conn.execute(
            "INSERT INTO users (name,email,password,role,created_at) VALUES (?,?,?,?,?)",
            (name, email, _hash(pw), "user", datetime.utcnow().isoformat())
        )
        conn.commit()
        row = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        _sess["user_id"]    = row["id"]
        _sess["user_name"]  = row["name"]
        _sess["user_email"] = row["email"]
        _sess["user_role"]  = row["role"]
        return jsonify({"success": True, "user": {"name": row["name"], "email": row["email"], "role": row["role"]}})
    except sqlite3.IntegrityError:
        return jsonify({"success": False, "error": "Email already registered."})
    finally:
        conn.close()


@app.route("/api/auth/login", methods=["POST"])
def api_login():
    data  = _req.get_json() or {}
    email = data.get("email","").strip().lower()
    pw    = data.get("password","")
    conn  = _db()
    try:
        row = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if not row or not _verify(pw, row["password"]):
            return jsonify({"success": False, "error": "Invalid email or password."})
        conn.execute("UPDATE users SET last_login=? WHERE id=?", (datetime.utcnow().isoformat(), row["id"]))
        conn.commit()
        _sess["user_id"]    = row["id"]
        _sess["user_name"]  = row["name"]
        _sess["user_email"] = row["email"]
        _sess["user_role"]  = row["role"]
        return jsonify({"success": True, "user": {"name": row["name"], "email": row["email"], "role": row["role"]}})
    finally:
        conn.close()


@app.route("/api/auth/logout", methods=["POST"])
def api_logout():
    _sess.clear()
    return jsonify({"success": True})


@app.route("/api/auth/me", methods=["GET"])
def api_me():
    if "user_id" not in _sess:
        return jsonify({"success": False, "user": None}), 401
    return jsonify({"success": True, "user": {
        "name":  _sess.get("user_name"),
        "email": _sess.get("user_email"),
        "role":  _sess.get("user_role"),
    }})



# ── HTML ──────────────────────────────────────────────────────────

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>SENTINEL &mdash; Threat Detection Dashboard</title>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap" rel="stylesheet"/>
<style>
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
:root {
  --bg:        #03050a;
  --panel:     #080c14;
  --border:    #162030;
  --border2:   #1f304a;
  --accent:    #00c8ff;
  --accent2:   #ff2d55;
  --accent3:   #00ff88;
  --warn:      #ffb800;
  --purple:    #b060ff;
  --text:      #c0d4ee;
  --dim:       #3a5570;
  --font-mono: 'Share Tech Mono', monospace;
  --font-ui:   'Rajdhani', sans-serif;
  --radius:    6px;
}
html, body { height: 100%; background: var(--bg); color: var(--text); font-family: var(--font-ui); overflow-x: hidden; }
body::before {
  content: ''; position: fixed; inset: 0; pointer-events: none; z-index: 0;
  background-image:
    radial-gradient(ellipse 60% 40% at 15% 50%,  rgba(0,200,255,.05)  0%, transparent 60%),
    radial-gradient(ellipse 50% 35% at 85% 20%,  rgba(176,96,255,.04) 0%, transparent 60%),
    radial-gradient(ellipse 40% 30% at 55% 85%,  rgba(0,255,136,.03)  0%, transparent 60%);
}
body::after {
  content: ''; position: fixed; inset: 0; pointer-events: none; z-index: 9999;
  background: repeating-linear-gradient(0deg, transparent, transparent 3px, rgba(0,0,0,.055) 3px, rgba(0,0,0,.055) 4px);
}
.shell { display: grid; grid-template-rows: auto 1fr auto; min-height: 100vh; position: relative; z-index: 1; }

/* Header */
header {
  display: flex; align-items: center; gap: 18px;
  padding: 14px 28px;
  background: rgba(8,12,20,.96);
  border-bottom: 1px solid var(--border2);
  position: sticky; top: 0; z-index: 100;
  backdrop-filter: blur(12px);
}
.logo-mark {
  width: 38px; height: 38px; border-radius: 8px;
  background: linear-gradient(135deg, rgba(0,200,255,.12), rgba(176,96,255,.12));
  border: 1px solid rgba(0,200,255,.28);
  display: flex; align-items: center; justify-content: center;
  font-size: 15px; font-weight: 700; font-family: var(--font-mono);
  color: var(--accent);
  box-shadow: 0 0 18px rgba(0,200,255,.2), inset 0 0 10px rgba(0,200,255,.05);
  animation: pulse-logo 3s ease-in-out infinite;
  letter-spacing: 1px;
}
@keyframes pulse-logo {
  0%,100% { box-shadow: 0 0 12px rgba(0,200,255,.18), inset 0 0 10px rgba(0,200,255,.05); }
  50%      { box-shadow: 0 0 28px rgba(0,200,255,.45), inset 0 0 16px rgba(0,200,255,.1); }
}
.logo-text { line-height: 1; }
.logo-text h1 { font-size: 22px; font-weight: 700; letter-spacing: 4px; color: var(--accent); text-transform: uppercase; text-shadow: 0 0 22px rgba(0,200,255,.45); }
.logo-text span { font-size: 11px; font-family: var(--font-mono); color: var(--dim); letter-spacing: 2px; }
.header-right { margin-left: auto; display: flex; align-items: center; gap: 16px; }
.status-pill {
  display: flex; align-items: center; gap: 7px;
  font-family: var(--font-mono); font-size: 11px; color: var(--accent3);
  background: rgba(0,255,136,.05); border: 1px solid rgba(0,255,136,.18);
  padding: 5px 12px; border-radius: 20px;
}
.status-pill .dot { width: 7px; height: 7px; border-radius: 50%; background: var(--accent3); animation: blink 1.2s ease-in-out infinite; }
@keyframes blink { 0%,100%{opacity:1} 50%{opacity:.12} }

/* Scan status bar */
.scan-bar {
  display: flex; align-items: center; gap: 10px;
  font-family: var(--font-mono); font-size: 11px; color: var(--dim);
  background: rgba(0,200,255,.04); border: 1px solid var(--border);
  padding: 5px 14px; border-radius: 20px;
}
.scan-bar .scan-dot { width: 7px; height: 7px; border-radius: 50%; background: var(--dim); flex-shrink: 0; }
.scan-bar.scanning .scan-dot { background: var(--warn); animation: blink .6s ease-in-out infinite; }
.scan-bar.scanning { border-color: rgba(255,184,0,.25); color: var(--warn); }

/* Scan Now button */
.btn-scan {
  font-family: var(--font-mono); font-size: 11px; letter-spacing: 1px;
  padding: 6px 14px; border-radius: 4px; cursor: pointer;
  background: rgba(0,200,255,.07); border: 1px solid rgba(0,200,255,.25);
  color: var(--accent); transition: background .2s, border-color .2s;
}
.btn-scan:hover { background: rgba(0,200,255,.15); border-color: var(--accent); }
.btn-scan:disabled { opacity: .4; cursor: not-allowed; }

.clock { font-family: var(--font-mono); font-size: 12px; color: var(--dim); }
main { padding: 24px 28px; display: flex; flex-direction: column; gap: 24px; }

/* Stat cards */
.stat-row { display: grid; grid-template-columns: repeat(4,1fr); gap: 16px; }
.stat-card {
  background: var(--panel); border: 1px solid var(--border); border-radius: var(--radius);
  padding: 18px 20px; position: relative; overflow: hidden;
  transition: border-color .25s, transform .2s, box-shadow .25s;
  animation: card-in .5s ease both;
}
.stat-card:hover { border-color: var(--accent); transform: translateY(-2px); box-shadow: 0 6px 20px rgba(0,200,255,.07); }
.stat-card::before {
  content: ''; position: absolute; top: 0; left: 0; right: 0; height: 1px;
  background: linear-gradient(90deg, transparent, var(--line-color, var(--accent)) 50%, transparent); opacity: .65;
}
.stat-card::after {
  content: ''; position: absolute; top: 0; left: 0; width: 9px; height: 9px;
  border-top: 1px solid var(--line-color, var(--accent)); border-left: 1px solid var(--line-color, var(--accent)); opacity: .7;
}
.stat-card:nth-child(1) { --line-color: var(--accent); }
.stat-card:nth-child(2) { --line-color: var(--accent2); }
.stat-card:nth-child(3) { --line-color: var(--warn); }
.stat-card:nth-child(4) { --line-color: var(--accent3); }
.cbr { position: absolute; bottom: 0; right: 0; width: 9px; height: 9px; border-bottom: 1px solid var(--line-color, var(--accent)); border-right: 1px solid var(--line-color, var(--accent)); opacity: .4; }
@keyframes card-in { from{opacity:0;transform:translateY(14px)} to{opacity:1;transform:none} }
.stat-label { font-size: 10px; letter-spacing: 2px; text-transform: uppercase; color: var(--dim); margin-bottom: 10px; font-family: var(--font-mono); }
.stat-value { font-size: 38px; font-weight: 700; line-height: 1; color: #fff; font-family: var(--font-mono); }
.stat-sub   { font-size: 11px; color: var(--dim); margin-top: 6px; font-family: var(--font-mono); }

/* Grids */
.grid-two   { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
.grid-three { display: grid; grid-template-columns: 2fr 1fr; gap: 20px; }

/* Panel */
.panel { background: var(--panel); border: 1px solid var(--border); border-radius: var(--radius); overflow: hidden; position: relative; }
.panel::before { content: ''; position: absolute; top: 0; left: 0; width: 10px; height: 10px; border-top: 1px solid rgba(0,200,255,.18); border-left: 1px solid rgba(0,200,255,.18); pointer-events: none; }
.panel::after  { content: ''; position: absolute; top: 0; right: 0; width: 10px; height: 10px; border-top: 1px solid rgba(0,200,255,.18); border-right: 1px solid rgba(0,200,255,.18); pointer-events: none; }
.panel-head { padding: 12px 18px; border-bottom: 1px solid var(--border); display: flex; align-items: center; justify-content: space-between; background: rgba(0,200,255,.015); }
.panel-title { font-size: 11px; letter-spacing: 3px; text-transform: uppercase; color: var(--accent); font-family: var(--font-mono); }
.panel-badge { font-family: var(--font-mono); font-size: 10px; color: var(--dim); }
.panel-body  { padding: 16px 18px; }
.ml-panel { border-color: rgba(176,96,255,.2); }
.ml-panel::before, .ml-panel::after { border-color: rgba(176,96,255,.2); }
.ml-panel .panel-head { background: rgba(176,96,255,.02); }
.ml-panel .panel-title { color: var(--purple); }

/* Badges */
.badge { display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 10px; font-weight: 700; letter-spacing: 1px; text-transform: uppercase; }
.badge-CRITICAL { background: rgba(255,45,85,.1);  color: var(--accent2); border: 1px solid rgba(255,45,85,.22); }
.badge-HIGH     { background: rgba(255,100,0,.1);  color: #ff6400;         border: 1px solid rgba(255,100,0,.22); }
.badge-MEDIUM   { background: rgba(255,184,0,.08); color: var(--warn);     border: 1px solid rgba(255,184,0,.22); }
.badge-LOW      { background: rgba(0,255,136,.06); color: var(--accent3);  border: 1px solid rgba(0,255,136,.18); }

/* Bar chart */
.bar-chart { display: flex; flex-direction: column; gap: 12px; }
.bar-row   { display: flex; flex-direction: column; gap: 5px; }
.bar-label { display: flex; justify-content: space-between; font-family: var(--font-mono); font-size: 11px; }
.bar-name  { color: var(--dim); }
.bar-count { color: var(--text); }
.bar-track { height: 6px; background: var(--border); border-radius: 3px; overflow: hidden; }
.bar-fill  { height: 100%; border-radius: 3px; transition: width 1s cubic-bezier(.4,0,.2,1); position: relative; }
.bar-fill::after { content: ''; position: absolute; inset: 0; background: linear-gradient(90deg, transparent, rgba(255,255,255,.12) 50%, transparent); animation: shimmer 2.8s ease-in-out infinite; }
@keyframes shimmer { 0%{transform:translateX(-100%)} 100%{transform:translateX(200%)} }

/* Donut */
.donut-wrap   { display: flex; align-items: center; gap: 20px; padding: 8px 0; }
svg.donut     { overflow: visible; }
.donut-legend { display: flex; flex-direction: column; gap: 10px; flex: 1; }
.legend-item  { display: flex; align-items: center; gap: 8px; font-family: var(--font-mono); font-size: 11px; }
.legend-dot   { width: 10px; height: 10px; border-radius: 2px; flex-shrink: 0; }
.legend-label { color: var(--dim); flex: 1; }
.legend-val   { color: var(--text); font-weight: 600; }

/* Severity grid */
.sev-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
.sev-cell { padding: 12px; border-radius: var(--radius); border: 1px solid var(--border); text-align: center; font-family: var(--font-mono); }
.sev-num  { font-size: 28px; font-weight: 700; line-height: 1; }
.sev-lbl  { font-size: 9px; letter-spacing: 2px; color: var(--dim); margin-top: 4px; text-transform: uppercase; }

/* Device list */
.device-list { display: flex; flex-direction: column; gap: 10px; }
.device-item {
  display: flex; align-items: center; gap: 12px;
  padding: 10px 12px; border-radius: var(--radius);
  background: rgba(0,200,255,.025); border: 1px solid var(--border);
  font-family: var(--font-mono); font-size: 12px;
  transition: border-color .2s, background .2s;
  position: relative;
}
.device-item:hover { border-color: var(--accent); background: rgba(0,200,255,.04); }

/* Online/offline indicator */
.device-status {
  position: absolute; top: 8px; right: 10px;
  width: 8px; height: 8px; border-radius: 50%;
}
.device-status.online  { background: var(--accent3); box-shadow: 0 0 6px var(--accent3); animation: blink 2s ease-in-out infinite; }
.device-status.offline { background: var(--dim); }

.device-icon { width: 32px; height: 32px; border-radius: 6px; background: rgba(0,200,255,.07); border: 1px solid rgba(0,200,255,.14); display: flex; align-items: center; justify-content: center; font-size: 16px; flex-shrink: 0; }
.device-icon.local { background: rgba(0,255,136,.07); border-color: rgba(0,255,136,.18); }
.device-info { flex: 1; min-width: 0; padding-right: 20px; }
.device-name { color: var(--text); font-size: 13px; font-weight: 600; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.device-mac  { color: var(--dim); font-size: 10px; margin-top: 2px; }
.device-seen { color: var(--dim); font-size: 9px; margin-top: 2px; letter-spacing: 1px; }
.device-ip   { color: var(--accent); font-size: 12px; text-align: right; flex-shrink: 0; margin-right: 14px; }

/* Scan progress bar */
.scan-progress {
  height: 2px; background: var(--border); border-radius: 1px; margin: 8px 0 4px; overflow: hidden;
}
.scan-progress-fill {
  height: 100%; background: var(--warn); border-radius: 1px;
  transition: width 1s linear;
}
.scan-info { font-family: var(--font-mono); font-size: 10px; color: var(--dim); display: flex; justify-content: space-between; margin-top: 4px; }

/* Feed */
.live-feed, .ml-feed { height: 240px; overflow-y: auto; font-family: var(--font-mono); font-size: 11px; scrollbar-width: thin; scrollbar-color: var(--border) transparent; }
.feed-line { padding: 4px 0; border-bottom: 1px solid rgba(22,32,48,.55); display: flex; gap: 10px; }
.feed-line:hover { background: rgba(0,200,255,.03); }
.feed-time { color: var(--dim); flex-shrink: 0; width: 80px; }
.feed-type { flex-shrink: 0; width: 90px; }
.feed-msg  { color: var(--text); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; flex: 1; }

/* Live stats */
.live-stats     { display: flex; gap: 20px; padding: 14px 0; justify-content: space-around; }
.live-stat      { text-align: center; font-family: var(--font-mono); }
.live-stat-val  { font-size: 22px; color: var(--accent3); font-weight: 700; }
.live-stat-lbl  { font-size: 9px; color: var(--dim); letter-spacing: 2px; text-transform: uppercase; margin-top: 4px; }

/* ML stats */
.ml-stats-row  { display: flex; gap: 12px; padding: 12px 0; }
.ml-stat-box   { text-align: center; font-family: var(--font-mono); flex: 1; background: rgba(176,96,255,.05); border: 1px solid rgba(176,96,255,.15); border-radius: var(--radius); padding: 12px 8px; }
.ml-stat-val   { font-size: 22px; color: var(--purple); font-weight: 700; }
.ml-stat-lbl   { font-size: 9px; color: var(--dim); letter-spacing: 2px; text-transform: uppercase; margin-top: 4px; }

footer { padding: 14px 28px; border-top: 1px solid var(--border); font-family: var(--font-mono); font-size: 10px; color: var(--dim); display: flex; justify-content: space-between; background: var(--panel); }

::-webkit-scrollbar { width: 5px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: var(--border2); border-radius: 3px; }

.spinner { width: 18px; height: 18px; border: 2px solid var(--border); border-top-color: var(--accent); border-radius: 50%; animation: spin .8s linear infinite; margin: auto; }
@keyframes spin { to { transform: rotate(360deg) } }

/* ── Notifications ──────────────────────────────────────────────── */
#notif-container {
  position: fixed; top: 80px; right: 20px; z-index: 99999;
  display: flex; flex-direction: column; gap: 10px;
  pointer-events: none;
}
.notif {
  min-width: 320px; max-width: 400px;
  background: #0a0f1a;
  border-radius: 8px;
  padding: 0;
  overflow: hidden;
  box-shadow: 0 8px 32px rgba(0,0,0,.6);
  pointer-events: all;
  animation: notif-in .35s cubic-bezier(.2,1.4,.4,1) both;
  position: relative;
}
.notif.hide { animation: notif-out .3s ease forwards; }

@keyframes notif-in {
  from { opacity:0; transform: translateX(120px) scale(.92); }
  to   { opacity:1; transform: translateX(0)    scale(1); }
}
@keyframes notif-out {
  from { opacity:1; transform: translateX(0)    scale(1); max-height:200px; margin-bottom:0; }
  to   { opacity:0; transform: translateX(120px) scale(.92); max-height:0; margin-bottom:-10px; }
}

.notif-bar { height: 3px; width: 100%; }
.notif-bar.CRITICAL { background: linear-gradient(90deg, #ff2d55, #ff006e); }
.notif-bar.HIGH     { background: linear-gradient(90deg, #ff6400, #ffb800); }

.notif-body { display: flex; align-items: flex-start; gap: 12px; padding: 14px 16px; }
.notif-icon {
  width: 36px; height: 36px; border-radius: 8px; flex-shrink: 0;
  display: flex; align-items: center; justify-content: center;
  font-size: 18px;
}
.notif-icon.CRITICAL { background: rgba(255,45,85,.15); border: 1px solid rgba(255,45,85,.3); }
.notif-icon.HIGH     { background: rgba(255,100,0,.12); border: 1px solid rgba(255,100,0,.3); }

.notif-content { flex: 1; min-width: 0; }
.notif-title {
  font-family: var(--font-mono); font-size: 12px; font-weight: 700;
  letter-spacing: 1px; text-transform: uppercase; margin-bottom: 4px;
}
.notif-title.CRITICAL { color: #ff2d55; }
.notif-title.HIGH     { color: #ff6400; }
.notif-msg   { font-family: var(--font-mono); font-size: 11px; color: var(--text); line-height: 1.5; word-break: break-word; }
.notif-time  { font-family: var(--font-mono); font-size: 10px; color: var(--dim); margin-top: 5px; }

.notif-close {
  position: absolute; top: 10px; right: 10px;
  background: none; border: none; color: var(--dim);
  font-size: 14px; cursor: pointer; line-height: 1;
  padding: 2px 5px; border-radius: 3px;
  transition: color .2s, background .2s;
}
.notif-close:hover { color: var(--text); background: rgba(255,255,255,.06); }

.notif-progress {
  height: 2px; background: rgba(255,255,255,.06);
  margin: 0 16px 12px;
  border-radius: 1px; overflow: hidden;
}
.notif-progress-fill {
  height: 100%; border-radius: 1px;
  transition: width linear;
}
.notif-progress-fill.CRITICAL { background: rgba(255,45,85,.5); }
.notif-progress-fill.HIGH     { background: rgba(255,100,0,.5); }

@media (max-width: 900px) {
  .stat-row { grid-template-columns: 1fr 1fr; }
  .grid-two, .grid-three { grid-template-columns: 1fr; }
  .ml-stats-row { flex-wrap: wrap; }
}
</style>
</head>
<body>
<div class="shell">

<header>
  <div class="logo-mark">SN</div>
  <div class="logo-text">
    <h1>Sentinel</h1>
    <span>Network Threat Detection System</span>
  </div>
  <div class="header-right">
    <div class="status-pill"><div class="dot"></div> SYSTEM ONLINE</div>
    <div class="scan-bar" id="scan-bar">
      <div class="scan-dot"></div>
      <span id="scan-bar-text">Initializing scan...</span>
    </div>
    <button class="btn-scan" id="btn-scan-now" onclick="triggerScanNow()">SCAN NOW</button>
    <button class="btn-scan" style="border-color:rgba(255,45,85,.4);color:#ff2d55;background:rgba(255,45,85,.07)" onclick="testNotification()">TEST ALERT</button>
    <div class="clock" id="clock">--:--:--</div>
  </div>
</header>

<main>

<!-- Notification container -->
<div id="notif-container"></div>

  <div class="stat-row">
    <div class="stat-card"><div class="cbr"></div>
      <div class="stat-label">Total Alerts</div>
      <div class="stat-value" id="s-alerts"><div class="spinner"></div></div>
      <div class="stat-sub" id="s-alerts-sub">&nbsp;</div>
    </div>
    <div class="stat-card"><div class="cbr"></div>
      <div class="stat-label">Devices Online</div>
      <div class="stat-value" id="s-devices"><div class="spinner"></div></div>
      <div class="stat-sub" id="s-devices-sub">&nbsp;</div>
    </div>
    <div class="stat-card"><div class="cbr"></div>
      <div class="stat-label">Packets Captured</div>
      <div class="stat-value" id="s-packets"><div class="spinner"></div></div>
      <div class="stat-sub" id="s-packets-sub">&nbsp;</div>
    </div>
    <div class="stat-card"><div class="cbr"></div>
      <div class="stat-label">Capture Rate</div>
      <div class="stat-value" id="s-rate"><div class="spinner"></div></div>
      <div class="stat-sub">packets / second</div>
    </div>
  </div>

  <div class="grid-two">
    <div class="panel">
      <div class="panel-head"><span class="panel-title">Alerts by Type</span></div>
      <div class="panel-body"><div class="bar-chart" id="bar-chart"><div class="spinner"></div></div></div>
    </div>
    <div class="panel">
      <div class="panel-head"><span class="panel-title">Severity Breakdown</span></div>
      <div class="panel-body"><div class="sev-grid" id="sev-grid"><div class="spinner"></div></div></div>
    </div>
  </div>

  <div class="grid-three">
    <div class="panel">
      <div class="panel-head">
        <span class="panel-title">Recent Alerts Feed</span>
        <span class="panel-badge" id="feed-badge">Latest 50</span>
      </div>
      <div class="panel-body" style="padding:0 18px 16px">
        <div class="live-feed" id="live-feed"><div class="spinner" style="margin-top:20px"></div></div>
      </div>
    </div>

    <!-- Devices panel with scan progress -->
    <div class="panel">
      <div class="panel-head">
        <span class="panel-title">Network Devices</span>
        <span class="panel-badge" id="devices-badge">Live</span>
      </div>
      <div class="panel-body">
        <div class="scan-progress"><div class="scan-progress-fill" id="scan-progress-fill" style="width:0%"></div></div>
        <div class="scan-info">
          <span id="scan-info-left">Waiting for scan...</span>
          <span id="scan-info-right">Auto every 60s</span>
        </div>
        <div class="device-list" id="device-list" style="margin-top:12px"><div class="spinner"></div></div>
      </div>
    </div>
  </div>

  <div class="grid-two">
    <div class="panel">
      <div class="panel-head">
        <span class="panel-title">Live Monitor</span>
        <span class="panel-badge" id="live-status">READING LOG</span>
      </div>
      <div class="panel-body"><div class="live-stats" id="live-stats"><div class="spinner"></div></div></div>
    </div>
    <div class="panel">
      <div class="panel-head"><span class="panel-title">Attack Distribution</span></div>
      <div class="panel-body"><div class="donut-wrap" id="donut-wrap"><div class="spinner"></div></div></div>
    </div>
  </div>

  <div class="grid-two">
    <div class="panel ml-panel">
      <div class="panel-head">
        <span class="panel-title">ML Anomaly Detection</span>
        <span class="panel-badge" id="ml-feed-badge">Isolation Forest</span>
      </div>
      <div class="panel-body" style="padding:0 18px 16px">
        <div class="ml-feed" id="ml-feed"><div class="spinner" style="margin-top:20px"></div></div>
      </div>
    </div>
    <div class="panel ml-panel">
      <div class="panel-head">
        <span class="panel-title">Model Performance</span>
        <span class="panel-badge" id="model-status">OFFLINE</span>
      </div>
      <div class="panel-body">
        <div class="ml-stats-row" id="ml-stats-row"><div class="spinner"></div></div>
        <div class="sev-grid" id="ml-sev-grid" style="margin-top:14px"><div class="spinner"></div></div>
      </div>
    </div>
  </div>

</main>

<footer>
  <span>Sentinel v2.1 &mdash; Network Threat Detection System &mdash; Graduation Project</span>
  <span id="last-updated">Last updated: --</span>
</footer>
</div>

<script>
const PALETTE    = ['#00c8ff','#ff2d55','#ffb800','#00ff88','#b060ff','#f97316'];
const SEV_COLORS = {
  CRITICAL: { color:'#ff2d55', bg:'rgba(255,45,85,.07)'  },
  HIGH:     { color:'#ff6400', bg:'rgba(255,100,0,.07)'  },
  MEDIUM:   { color:'#ffb800', bg:'rgba(255,184,0,.07)'  },
  LOW:      { color:'#00ff88', bg:'rgba(0,255,136,.05)'  },
};

// Device icons based on vendor/hostname
function classifyDevice(d) {
  const vendor   = (d.vendor   || '').toLowerCase();
  const hostname = (d.hostname || '').toLowerCase();
  const mac      = (d.mac      || '').toUpperCase();
  const ip       = (d.ip       || '');
  const lastOctet = parseInt(ip.split('.').pop());

  if (d.is_local) return { icon: '&#x1F4BB;', label: 'Laptop / PC', css: 'local' };

  if (lastOctet === 1 || lastOctet === 254 ||
      hostname.includes('router') || hostname.includes('gateway') ||
      hostname.includes('dlink') || hostname.includes('tplink') ||
      vendor.includes('tp-link') || vendor.includes('d-link') ||
      vendor.includes('cisco') || vendor.includes('netgear') ||
      vendor.includes('asus') || vendor.includes('linksys')) {
    return { icon: '&#x1F4E1;', label: 'Router', css: '' };
  }

  const phoneKeywords = ['iphone','ipad','android','phone','mobile','galaxy',
    'redmi','poco','oneplus','pixel','honor','oppo','vivo','realme'];
  if (phoneKeywords.some(k => hostname.includes(k)))
    return { icon: '&#x1F4F1;', label: 'Phone / Tablet', css: '' };

  const phoneVendors = ['samsung','apple','xiaomi','oppo','huawei','oneplus',
    'vivo','realme','motorola','htc','sony mobile'];
  if (phoneVendors.some(v => vendor.includes(v)))
    return { icon: '&#x1F4F1;', label: 'Phone / Tablet', css: '' };

  // Randomized MAC (2nd nibble is 2,6,A,E) = almost always a phone
  if (mac.length >= 2 && ['2','6','A','E'].includes(mac[1]))
    return { icon: '&#x1F4F1;', label: 'Phone (random MAC)', css: '' };

  const pcVendors = ['intel','dell','hp','lenovo','asus','acer','msi',
    'gigabyte','realtek','vmware','microsoft','virtualbox'];
  if (pcVendors.some(v => vendor.includes(v)))
    return { icon: '&#x1F4BB;', label: 'Laptop / PC', css: '' };

  if (hostname.includes('tv') || hostname.includes('xbox') ||
      hostname.includes('playstation') || hostname.includes('ps4') ||
      hostname.includes('ps5') || vendor.includes('sony') || vendor.includes('tcl'))
    return { icon: '&#x1F4FA;', label: 'Smart TV', css: '' };

  if (hostname.includes('esp') || hostname.includes('raspberrypi') ||
      vendor.includes('raspberry') || vendor.includes('espressif') ||
      vendor.includes('altobeam') || vendor.includes('iot') ||
      vendor.includes('tuya') || vendor.includes('beken'))
    return { icon: '&#x1F9F0;', label: 'IoT / Smart Device', css: '' };

  return { icon: '&#x1F5A5;', label: 'Unknown Device', css: '' };
}

function timeSince(isoStr) {
  if (!isoStr) return '';
  const diff = Math.floor((Date.now() - new Date(isoStr)) / 1000);
  if (diff < 60)   return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff/60)}m ago`;
  return `${Math.floor(diff/3600)}h ago`;
}

// Scan countdown timer
let _lastScanTime = null;
let _scanRunning  = false;
let _scanInterval = 60;

function updateScanBar(status) {
  const bar   = document.getElementById('scan-bar');
  const text  = document.getElementById('scan-bar-text');
  const fill  = document.getElementById('scan-progress-fill');
  const left  = document.getElementById('scan-info-left');
  const right = document.getElementById('scan-info-right');
  const btn   = document.getElementById('btn-scan-now');

  if (status.running) {
    bar.className = 'scan-bar scanning';
    text.textContent = 'SCANNING...';
    fill.style.width = '60%';
    fill.style.background = 'var(--warn)';
    left.textContent = 'Scan in progress...';
    btn.disabled = true;
  } else {
    bar.className = 'scan-bar';
    btn.disabled = false;
    fill.style.background = 'var(--accent3)';
    if (status.last_scan) {
      const ago = timeSince(status.last_scan);
      text.textContent = `Last scan: ${ago}`;
      left.textContent = `Last scan: ${ago} — ${status.device_count} device(s) found`;
      fill.style.width = '100%';
      setTimeout(() => { fill.style.width = '0%'; fill.style.transition = 'none'; setTimeout(() => { fill.style.transition = 'width 1s linear'; }, 50); }, 1000);
    } else {
      text.textContent = 'Scan pending...';
      left.textContent = 'Waiting for first scan...';
    }
    right.textContent = 'Auto every 20s';
  }
}

async function triggerScanNow() {
  const btn = document.getElementById('btn-scan-now');
  btn.disabled = true;
  btn.textContent = 'SCANNING...';
  try {
    await fetch('/api/scan_now', { method: 'POST' });
  } catch(e) {}
  // Poll until scan finishes
  const poll = setInterval(async () => {
    try {
      const s = await (await fetch('/api/scan_status')).json();
      updateScanBar(s);
      if (!s.running) {
        clearInterval(poll);
        btn.textContent = 'SCAN NOW';
        refresh();
      }
    } catch(e) { clearInterval(poll); btn.textContent = 'SCAN NOW'; btn.disabled = false; }
  }, 2000);
}

function tick(){ document.getElementById('clock').textContent = new Date().toLocaleTimeString('en-GB'); }
setInterval(tick, 1000); tick();

async function fetchJSON(url){ const r = await fetch(url); return r.json(); }

function renderStats(stats){
  document.getElementById('s-alerts').textContent      = stats.total_alerts;
  document.getElementById('s-alerts-sub').textContent  = `${stats.severity_count.CRITICAL||0} CRITICAL / ${stats.severity_count.HIGH||0} HIGH`;
  document.getElementById('s-devices').textContent     = stats.total_devices;
  document.getElementById('s-devices-sub').textContent = stats.network_range;
  document.getElementById('s-packets').textContent     = (stats.live.packets||0).toLocaleString();
  document.getElementById('s-packets-sub').textContent = stats.live.running ? 'monitor active' : 'from log';
  document.getElementById('s-rate').textContent        = (stats.live.rate||0).toFixed(1);
  document.getElementById('live-status').textContent   = stats.live.running ? 'ACTIVE' : 'IDLE';
  document.getElementById('live-stats').innerHTML = `
    <div class="live-stat"><div class="live-stat-val">${(stats.live.packets||0).toLocaleString()}</div><div class="live-stat-lbl">Total Packets</div></div>
    <div class="live-stat"><div class="live-stat-val">${(stats.live.rate||0).toFixed(1)}</div><div class="live-stat-lbl">Pkt / Sec</div></div>
    <div class="live-stat"><div class="live-stat-val">${stats.local_ip||'N/A'}</div><div class="live-stat-lbl">Your IP</div></div>`;

  const entries = Object.entries(stats.alerts_by_type).sort((a,b)=>b[1]-a[1]);
  const maxVal  = entries[0]?.[1] || 1;
  document.getElementById('bar-chart').innerHTML = entries.map(([k,v],i) => `
    <div class="bar-row">
      <div class="bar-label"><span class="bar-name">${k}</span><span class="bar-count">${v}</span></div>
      <div class="bar-track"><div class="bar-fill" style="width:${(v/maxVal*100).toFixed(1)}%;background:${PALETTE[i%PALETTE.length]}"></div></div>
    </div>`).join('');

  const sc = stats.severity_count;
  document.getElementById('sev-grid').innerHTML = Object.entries(SEV_COLORS).map(([k,c]) => `
    <div class="sev-cell" style="border-color:${c.color}20;background:${c.bg}">
      <div class="sev-num" style="color:${c.color}">${sc[k]||0}</div>
      <div class="sev-lbl">${k}</div>
    </div>`).join('');

  renderDonut(entries);

  const m = stats.model;
  document.getElementById('model-status').textContent = m.trained ? 'ACTIVE' : 'OFFLINE';
  document.getElementById('ml-stats-row').innerHTML = `
    <div class="ml-stat-box"><div class="ml-stat-val">${m.samples||'--'}</div><div class="ml-stat-lbl">Samples</div></div>
    <div class="ml-stat-box"><div class="ml-stat-val">${m.precision!=null?(m.precision*100).toFixed(0)+'%':'--'}</div><div class="ml-stat-lbl">Precision</div></div>
    <div class="ml-stat-box"><div class="ml-stat-val">${m.recall!=null?(m.recall*100).toFixed(0)+'%':'--'}</div><div class="ml-stat-lbl">Recall</div></div>
    <div class="ml-stat-box"><div class="ml-stat-val">${m.f1!=null?(m.f1*100).toFixed(0)+'%':'--'}</div><div class="ml-stat-lbl">F1 Score</div></div>`;

  const ms = stats.ml_severity;
  document.getElementById('ml-sev-grid').innerHTML = Object.entries(SEV_COLORS).map(([k,c]) => `
    <div class="sev-cell" style="border-color:${c.color}20;background:${c.bg}">
      <div class="sev-num" style="color:${c.color}">${ms[k]||0}</div>
      <div class="sev-lbl">${k}</div>
    </div>`).join('');

  if (stats.scan_status) updateScanBar(stats.scan_status);
}

function renderDonut(entries){
  if(!entries.length){
    document.getElementById('donut-wrap').innerHTML = '<p style="color:var(--dim);font-size:12px;font-family:var(--font-mono)">No data</p>';
    return;
  }
  const total = entries.reduce((s,[,v]) => s+v, 0);
  const r=54, cx=70, cy=70, circ=2*Math.PI*r;
  let offset = 0;
  const slices = entries.map(([k,v],i) => {
    const dash = (v/total)*circ, gap = circ-dash;
    const el = `<circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="${PALETTE[i%PALETTE.length]}" stroke-width="14" stroke-dasharray="${dash} ${gap}" stroke-dashoffset="${-offset}"/>`;
    offset += dash;
    return el;
  });
  document.getElementById('donut-wrap').innerHTML = `
    <svg class="donut" width="140" height="140" viewBox="0 0 140 140">
      <circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="var(--border)" stroke-width="14"/>
      ${slices.join('')}
      <text x="${cx}" y="${cy-6}"  text-anchor="middle" fill="var(--text)" font-size="18" font-family="var(--font-mono)" font-weight="700">${total}</text>
      <text x="${cx}" y="${cy+14}" text-anchor="middle" fill="var(--dim)"  font-size="9"  font-family="var(--font-mono)">TOTAL</text>
    </svg>
    <div class="donut-legend">${entries.map(([k,v],i) => `
      <div class="legend-item">
        <div class="legend-dot" style="background:${PALETTE[i%PALETTE.length]}"></div>
        <span class="legend-label">${k}</span>
        <span class="legend-val">${(v/total*100).toFixed(0)}%</span>
      </div>`).join('')}
    </div>`;
}

function renderAlerts(alerts){
  const recent = alerts.slice(-50).reverse();
  document.getElementById('feed-badge').textContent = `Last ${recent.length} of ${alerts.length}`;
  document.getElementById('live-feed').innerHTML = recent.map(a => {
    const ts = new Date(a.timestamp);
    const timeStr = isNaN(ts) ? '??' : ts.toLocaleTimeString('en-GB');
    const sev = a.severity || 'LOW';
    return `<div class="feed-line">
      <span class="feed-time">${timeStr}</span>
      <span class="feed-type"><span class="badge badge-${sev}">${sev}</span></span>
      <span class="feed-msg">${a.message||a.alert_type}</span>
    </div>`;
  }).join('');
}

function renderMLAlerts(mlAlerts){
  document.getElementById('ml-feed-badge').textContent = `${mlAlerts.length} anomalies`;
  const recent = mlAlerts.slice(-50).reverse();
  if(!recent.length){
    document.getElementById('ml-feed').innerHTML = '<p style="color:var(--dim);font-size:11px;font-family:var(--font-mono);padding:16px 0">No ML anomalies. Run train_ml.py first.</p>';
    return;
  }
  document.getElementById('ml-feed').innerHTML = recent.map(a => {
    const ts = new Date(a.timestamp);
    const timeStr = isNaN(ts) ? '??' : ts.toLocaleTimeString('en-GB');
    const sev = a.severity || 'HIGH';
    return `<div class="feed-line">
      <span class="feed-time">${timeStr}</span>
      <span class="feed-type"><span class="badge badge-${sev}">${sev}</span></span>
      <span class="feed-msg">${a.message||a.alert_type||'Anomaly detected'}</span>
    </div>`;
  }).join('');
}

function renderDevices(data){
  const devs = data.devices || [];
  document.getElementById('devices-badge').textContent = `${devs.length} online`;
  if(!devs.length){
    document.getElementById('device-list').innerHTML = '<p style="color:var(--dim);font-size:12px;font-family:var(--font-mono)">Scanning network...</p>';
    return;
  }
  document.getElementById('device-list').innerHTML = devs.map(d => {
    const cls = classifyDevice(d);
    const displayName = d.hostname && d.hostname !== 'Unknown' ? d.hostname : cls.label;
    return `
    <div class="device-item">
      <div class="device-status online"></div>
      <div class="device-icon${cls.css ? ' '+cls.css : ''}">${cls.icon}</div>
      <div class="device-info">
        <div class="device-name">${displayName}</div>
        <div class="device-mac">${d.mac||''} &bull; <span style="color:var(--accent);opacity:.8">${cls.label}</span></div>
        <div class="device-seen">Last seen: ${timeSince(d.last_seen)||'just now'}</div>
      </div>
      <div class="device-ip">${d.ip}</div>
    </div>`;
  }).join('');
}

// ── Notification system ──────────────────────────────────────────
let _seenAlertIds = null;  // null = first load, don't notify
const NOTIF_DURATION = 6000; // ms before auto-dismiss

function testNotification() {
  // Fire a fake HIGH and a fake CRITICAL to test the popup
  showNotif({ severity: 'HIGH',     timestamp: new Date().toISOString(), message: 'Port scan detected from 192.168.1.99: 45 unique ports in 60s' });
  setTimeout(() => {
    showNotif({ severity: 'CRITICAL', timestamp: new Date().toISOString(), message: 'SYN flood detected from 185.220.101.45: 1200 packets/s' });
  }, 800);
}

function showNotif(alert) {
  const sev = alert.severity || 'HIGH';
  if (!['HIGH','CRITICAL'].includes(sev)) return;

  const container = document.getElementById('notif-container');
  const id  = 'notif-' + Date.now() + '-' + Math.random().toString(36).slice(2);
  const ts  = new Date(alert.timestamp);
  const timeStr = isNaN(ts) ? 'just now' : ts.toLocaleTimeString('en-GB');
  const msg = (alert.message || alert.alert_type || 'Threat detected').substring(0, 120);
  const icon = sev === 'CRITICAL' ? '&#x26A0;' : '&#x1F6A8;';

  const el = document.createElement('div');
  el.className = 'notif';
  el.id = id;
  el.innerHTML = `
    <div class="notif-bar ${sev}"></div>
    <div class="notif-body">
      <div class="notif-icon ${sev}">${icon}</div>
      <div class="notif-content">
        <div class="notif-title ${sev}">${sev} ALERT</div>
        <div class="notif-msg">${msg}</div>
        <div class="notif-time">${timeStr}</div>
      </div>
      <button class="notif-close" onclick="dismissNotif('${id}')">&times;</button>
    </div>
    <div class="notif-progress">
      <div class="notif-progress-fill ${sev}" id="${id}-bar" style="width:100%"></div>
    </div>`;

  container.appendChild(el);

  // Animate progress bar countdown
  const bar = document.getElementById(id + '-bar');
  if (bar) {
    bar.style.transition = `width ${NOTIF_DURATION}ms linear`;
    requestAnimationFrame(() => { bar.style.width = '0%'; });
  }

  // Auto-dismiss after duration
  setTimeout(() => dismissNotif(id), NOTIF_DURATION);

  // Keep max 5 notifications on screen
  const all = container.querySelectorAll('.notif:not(.hide)');
  if (all.length > 5) dismissNotif(all[0].id);
}

function dismissNotif(id) {
  const el = document.getElementById(id);
  if (!el || el.classList.contains('hide')) return;
  el.classList.add('hide');
  setTimeout(() => el.remove(), 350);
}

function checkNewAlerts(alerts) {
  const ids = new Set(alerts.map((a, i) => a.timestamp + i));

  // On first load: show the 2 most recent HIGH/CRITICAL alerts right away (1s delay)
  if (_seenAlertIds === null) {
    _seenAlertIds = ids;
    const top = [...alerts].reverse().filter(a => ['HIGH','CRITICAL'].includes(a.severity || 'LOW'));
    if (top[0]) setTimeout(() => showNotif(top[0]), 1000);
    if (top[1]) setTimeout(() => showNotif(top[1]), 2200);
    return;
  }

  // Find alerts we haven't seen before
  alerts.forEach((a, i) => {
    const key = a.timestamp + i;
    if (!_seenAlertIds.has(key)) {
      const sev = a.severity || 'LOW';
      if (['HIGH','CRITICAL'].includes(sev)) showNotif(a);
    }
  });

  _seenAlertIds = ids;
}

async function refresh(){
  try {
    const [stats, alerts, mlAlerts, devices] = await Promise.all([
      fetchJSON('/api/stats'),
      fetchJSON('/api/alerts'),
      fetchJSON('/api/ml_alerts'),
      fetchJSON('/api/devices'),
    ]);
    renderStats(stats);
    checkNewAlerts(alerts);
    renderAlerts(alerts);
    renderMLAlerts(mlAlerts);
    renderDevices(devices);
    document.getElementById('last-updated').textContent = 'Last updated: ' + new Date().toLocaleTimeString('en-GB');
  } catch(e) {
    console.error('Refresh error:', e);
  }
}

refresh();
setInterval(refresh, 10000);
</script>
</body>
</html>"""


HOME_HTML = '''<!DOCTYPE html>
<html lang="en" dir="ltr" data-theme="dark">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>PacketGuard — Network Threat Detection</title>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Syne:wght@400;600;700;800&family=DM+Sans:ital,wght@0,300;0,400;0,500;1,300&family=Tajawal:wght@300;400;500;700&display=swap" rel="stylesheet"/>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
[data-theme="dark"]{
  --bg:#020508;--surface:#060c14;--surface2:#0a1520;
  --border:#0f2035;--border2:#1a3050;
  --accent:#00d4ff;--accent2:#ff2d6b;--accent3:#00ff9d;--warn:#ffb800;--purple:#9d6fff;
  --text:#b8cfe8;--text2:#6a8aaa;--white:#e8f4ff;
  --card:rgba(6,12,20,0.92);--modal:#060e18;--inp:#040a12;--inp-b:#1a3050;--sh:rgba(0,0,0,.65);
}
[data-theme="light"]{
  --bg:#f0f4f8;--surface:#ffffff;--surface2:#f8fafc;
  --border:#d0dce8;--border2:#b8ccde;
  --accent:#0088cc;--accent2:#e0145a;--accent3:#00aa66;--warn:#e09000;--purple:#6a3fcc;
  --text:#2a4060;--text2:#6a8aaa;--white:#0a1525;
  --card:rgba(255,255,255,.96);--modal:#ffffff;--inp:#f4f8fc;--inp-b:#c0d4e8;--sh:rgba(0,0,0,.12);
}
:root{--fd:'Syne',sans-serif;--fb:'DM Sans',sans-serif;--fm:'Share Tech Mono',monospace;--fa:'Tajawal',sans-serif;}
html{scroll-behavior:smooth}
body{background:var(--bg);color:var(--text);font-family:var(--fb);overflow-x:hidden;line-height:1.6;transition:background .3s,color .3s}
[lang="ar"] *{font-family:var(--fa),var(--fb)}

.bg-orbs{position:fixed;inset:0;z-index:0;pointer-events:none;overflow:hidden}
.orb{position:absolute;border-radius:50%;filter:blur(90px);animation:od 18s ease-in-out infinite alternate}
.orb1{width:700px;height:700px;background:radial-gradient(circle,rgba(0,212,255,.06),transparent 70%);top:-250px;left:-150px}
.orb2{width:500px;height:500px;background:radial-gradient(circle,rgba(157,111,255,.05),transparent 70%);top:40%;right:-100px;animation-delay:-8s}
.orb3{width:400px;height:400px;background:radial-gradient(circle,rgba(0,255,157,.04),transparent 70%);bottom:-100px;left:35%;animation-delay:-15s}
[data-theme="light"] .orb1{background:radial-gradient(circle,rgba(0,136,204,.07),transparent 70%)}
[data-theme="light"] .orb2{background:radial-gradient(circle,rgba(106,63,204,.05),transparent 70%)}
@keyframes od{0%{transform:translate(0,0) scale(1)}100%{transform:translate(40px,30px) scale(1.1)}}
.bg-grid{position:fixed;inset:0;z-index:0;pointer-events:none;background-image:linear-gradient(var(--border) 1px,transparent 1px),linear-gradient(90deg,var(--border) 1px,transparent 1px);background-size:60px 60px;opacity:.4;mask-image:radial-gradient(ellipse 80% 80% at 50% 50%,black,transparent)}

/* NAV */
nav{position:fixed;top:0;left:0;right:0;z-index:1000;display:flex;align-items:center;justify-content:space-between;padding:0 48px;height:66px;background:rgba(2,5,8,.88);backdrop-filter:blur(20px);border-bottom:1px solid var(--border);transition:background .3s}
[data-theme="light"] nav{background:rgba(240,244,248,.93)}
.nav-logo{display:flex;align-items:center;gap:10px;font-family:var(--fd);font-size:18px;font-weight:800;color:var(--white);letter-spacing:2px;text-transform:uppercase;text-decoration:none}
.nav-logo-icon{width:32px;height:32px;border-radius:7px;flex-shrink:0;background:linear-gradient(135deg,rgba(0,212,255,.16),rgba(157,111,255,.14));border:1px solid rgba(0,212,255,.35);display:flex;align-items:center;justify-content:center;font-family:var(--fm);font-size:11px;color:var(--accent);font-weight:700;box-shadow:0 0 14px rgba(0,212,255,.2)}
.nav-c{display:flex;align-items:center;gap:30px}
.nav-c a{font-size:14px;font-weight:500;color:var(--text2);text-decoration:none;transition:color .2s}
.nav-c a:hover{color:var(--accent)}
.nav-r{display:flex;align-items:center;gap:10px}
/* Lang */
.lang-sw{position:relative}
.lang-btn{display:flex;align-items:center;gap:6px;padding:7px 11px;border-radius:6px;cursor:pointer;background:transparent;border:1px solid var(--border2);color:var(--text2);font-size:12px;font-family:var(--fm);transition:all .2s}
.lang-btn:hover{border-color:var(--accent);color:var(--accent)}
.lang-dd{position:absolute;top:calc(100% + 8px);right:0;background:var(--modal);border:1px solid var(--border2);border-radius:8px;overflow:hidden;min-width:130px;box-shadow:0 12px 40px var(--sh);display:none;z-index:200}
.lang-dd.open{display:block;animation:ddin .2s ease}
@keyframes ddin{from{opacity:0;transform:translateY(-6px)}to{opacity:1;transform:translateY(0)}}
.lang-opt{display:flex;align-items:center;gap:10px;padding:10px 16px;cursor:pointer;font-size:13px;color:var(--text);transition:background .15s}
.lang-opt:hover{background:rgba(0,212,255,.06)}
.lang-opt.active{color:var(--accent)}
/* Theme */
.theme-btn{width:34px;height:34px;border-radius:7px;cursor:pointer;background:transparent;border:1px solid var(--border2);color:var(--text2);font-size:15px;display:flex;align-items:center;justify-content:center;transition:all .2s}
.theme-btn:hover{border-color:var(--accent);color:var(--accent)}
.ndiv{width:1px;height:18px;background:var(--border2);margin:0 2px}
.btn-nl{padding:7px 16px;border-radius:6px;font-size:13px;font-weight:500;background:transparent;border:1px solid var(--border2);color:var(--text);cursor:pointer;transition:all .2s;font-family:var(--fb)}
.btn-nl:hover{border-color:var(--accent);color:var(--accent)}
.btn-ns{padding:7px 16px;border-radius:6px;font-size:13px;font-weight:600;background:linear-gradient(135deg,rgba(0,212,255,.14),rgba(157,111,255,.1));border:1px solid rgba(0,212,255,.4);color:var(--white);cursor:pointer;transition:all .2s;font-family:var(--fb);box-shadow:0 0 14px rgba(0,212,255,.1)}
.btn-ns:hover{box-shadow:0 0 24px rgba(0,212,255,.22);border-color:rgba(0,212,255,.6)}

/* HERO */
.hero{position:relative;z-index:1;min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;padding:120px 40px 80px}
.h-badge{display:inline-flex;align-items:center;gap:8px;padding:6px 18px;border-radius:20px;margin-bottom:28px;background:rgba(0,212,255,.06);border:1px solid rgba(0,212,255,.2);font-family:var(--fm);font-size:11px;color:var(--accent);letter-spacing:2px;animation:fu .7s ease both}
.bdot{width:6px;height:6px;border-radius:50%;background:var(--accent3);animation:bl 1.5s ease-in-out infinite}
@keyframes bl{0%,100%{opacity:1}50%{opacity:.2}}
.h-title{font-family:var(--fd);font-size:clamp(52px,9vw,106px);font-weight:800;line-height:.92;letter-spacing:-3px;color:var(--white);animation:fu .7s .1s ease both}
.h-title .glow{color:var(--accent);text-shadow:0 0 50px rgba(0,212,255,.5),0 0 100px rgba(0,212,255,.2)}
.h-title .sub{display:block;font-size:clamp(34px,5vw,64px);background:linear-gradient(135deg,var(--text) 0%,var(--text2) 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;letter-spacing:-1px;margin-top:6px}
.h-desc{max-width:540px;font-size:16px;font-weight:300;color:var(--text2);margin:26px auto 42px;line-height:1.75;animation:fu .7s .2s ease both}
.h-actions{display:flex;align-items:center;gap:14px;justify-content:center;flex-wrap:wrap;animation:fu .7s .3s ease both}
.btn-p{display:inline-flex;align-items:center;gap:10px;padding:13px 30px;border-radius:8px;background:linear-gradient(135deg,rgba(0,212,255,.15),rgba(157,111,255,.1));border:1px solid rgba(0,212,255,.4);color:var(--white);font-family:var(--fd);font-size:14px;font-weight:700;letter-spacing:2px;text-transform:uppercase;text-decoration:none;cursor:pointer;box-shadow:0 0 26px rgba(0,212,255,.14);transition:all .3s}
.btn-p:hover{box-shadow:0 0 46px rgba(0,212,255,.3);border-color:rgba(0,212,255,.7);transform:translateY(-2px)}
.btn-o{display:inline-flex;align-items:center;gap:8px;padding:13px 26px;border-radius:8px;background:transparent;border:1px solid var(--border2);color:var(--text2);font-size:14px;text-decoration:none;cursor:pointer;transition:all .3s}
.btn-o:hover{border-color:rgba(0,212,255,.3);color:var(--text)}

/* STATS */
.stats{position:relative;z-index:1;display:flex;justify-content:center;padding:0 40px 80px;animation:fu .7s .4s ease both}
.si{text-align:center;padding:22px 42px;border:1px solid var(--border);background:var(--card);backdrop-filter:blur(10px)}
.si:first-child{border-radius:10px 0 0 10px}
.si:last-child{border-radius:0 10px 10px 0}
.si+.si{border-left:none}
.sn{font-family:var(--fm);font-size:28px;color:var(--white);display:block}
.sn span{font-size:15px;color:var(--accent)}
.sl{font-size:11px;color:var(--text2);letter-spacing:1px;margin-top:3px;text-transform:uppercase}

/* SECTIONS */
section{position:relative;z-index:1;padding:96px 60px}
.stag{display:inline-flex;align-items:center;gap:8px;font-family:var(--fm);font-size:11px;letter-spacing:3px;color:var(--accent);text-transform:uppercase;margin-bottom:14px}
.stag::before{content:'//';opacity:.5}
.stitle{font-family:var(--fd);font-size:clamp(28px,3.8vw,44px);font-weight:800;color:var(--white);line-height:1.1;margin-bottom:13px}
.ssub{font-size:15px;color:var(--text2);max-width:460px;line-height:1.7}

/* FEATURES */
.fi{max-width:1200px;margin:0 auto}
.fh{margin-bottom:52px}
.fg{display:grid;grid-template-columns:repeat(3,1fr);gap:16px}
.fc{padding:26px;border-radius:12px;background:var(--card);border:1px solid var(--border);position:relative;overflow:hidden;transition:border-color .3s,transform .3s,box-shadow .3s}
.fc::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,var(--cc,var(--accent)) 50%,transparent);opacity:.5}
.fc:nth-child(1){--cc:var(--accent)}.fc:nth-child(2){--cc:var(--purple)}.fc:nth-child(3){--cc:var(--accent3)}.fc:nth-child(4){--cc:var(--warn)}.fc:nth-child(5){--cc:var(--accent2)}.fc:nth-child(6){--cc:var(--accent)}
.fc:hover{border-color:var(--cc,var(--accent));transform:translateY(-4px);box-shadow:0 14px 36px var(--sh)}
.fi-icon{width:42px;height:42px;border-radius:9px;background:rgba(0,212,255,.06);border:1px solid rgba(0,212,255,.14);display:flex;align-items:center;justify-content:center;font-size:19px;margin-bottom:16px}
.fc:nth-child(2) .fi-icon{background:rgba(157,111,255,.06);border-color:rgba(157,111,255,.15)}
.fc:nth-child(3) .fi-icon{background:rgba(0,255,157,.06);border-color:rgba(0,255,157,.15)}
.fc:nth-child(4) .fi-icon{background:rgba(255,184,0,.06);border-color:rgba(255,184,0,.15)}
.fc:nth-child(5) .fi-icon{background:rgba(255,45,107,.06);border-color:rgba(255,45,107,.15)}
.ft{font-family:var(--fd);font-size:16px;font-weight:700;color:var(--white);margin-bottom:7px}
.fd{font-size:13px;color:var(--text2);line-height:1.7}
.ftag{display:inline-block;margin-top:12px;padding:3px 9px;border-radius:4px;font-family:var(--fm);font-size:10px;letter-spacing:1px;background:rgba(0,212,255,.06);border:1px solid rgba(0,212,255,.14);color:var(--accent)}
.fc:nth-child(2) .ftag{background:rgba(157,111,255,.06);border-color:rgba(157,111,255,.15);color:var(--purple)}
.fc:nth-child(3) .ftag{background:rgba(0,255,157,.06);border-color:rgba(0,255,157,.15);color:var(--accent3)}
.fc:nth-child(4) .ftag{background:rgba(255,184,0,.06);border-color:rgba(255,184,0,.15);color:var(--warn)}
.fc:nth-child(5) .ftag{background:rgba(255,45,107,.06);border-color:rgba(255,45,107,.15);color:var(--accent2)}

/* HOW */
.how{background:var(--surface);border-top:1px solid var(--border);border-bottom:1px solid var(--border)}
.how-in{max-width:1080px;margin:0 auto;display:grid;grid-template-columns:1fr 1fr;gap:72px;align-items:center}
.steps{display:flex;flex-direction:column}
.step{display:flex;gap:16px;padding:22px 0;border-bottom:1px solid var(--border);opacity:.5;transition:opacity .3s}
.step:last-child{border-bottom:none}.step:hover{opacity:1}
.snum{width:32px;height:32px;border-radius:7px;flex-shrink:0;background:rgba(0,212,255,.06);border:1px solid rgba(0,212,255,.2);display:flex;align-items:center;justify-content:center;font-family:var(--fm);font-size:12px;color:var(--accent)}
.st{font-family:var(--fd);font-size:15px;font-weight:700;color:var(--white);margin-bottom:4px}
.sd{font-size:13px;color:var(--text2);line-height:1.6}
.rw{height:360px;border-radius:14px;border:1px solid var(--border);background:var(--card);display:flex;align-items:center;justify-content:center;position:relative;overflow:hidden}
.rw::before{content:'';position:absolute;inset:0;background:radial-gradient(circle at 50% 50%,rgba(0,212,255,.05),transparent 60%)}
.radar{position:relative;width:210px;height:210px}
.rr{position:absolute;border-radius:50%;border:1px solid rgba(0,212,255,.12);top:50%;left:50%;transform:translate(-50%,-50%)}
.rr:nth-child(1){width:52px;height:52px}.rr:nth-child(2){width:104px;height:104px}.rr:nth-child(3){width:156px;height:156px}.rr:nth-child(4){width:210px;height:210px}
.rsw{position:absolute;top:50%;left:50%;width:105px;height:2px;transform-origin:0 50%;background:linear-gradient(90deg,rgba(0,212,255,.8),transparent);animation:sw 3s linear infinite}
@keyframes sw{from{transform:rotate(0)}to{transform:rotate(360deg)}}
.rdot{position:absolute;width:7px;height:7px;border-radius:50%;background:var(--accent3);box-shadow:0 0 6px var(--accent3);animation:db 2s ease-in-out infinite}
.rdot:nth-child(5){top:28%;left:57%;animation-delay:.3s}
.rdot:nth-child(6){top:62%;left:23%;animation-delay:.9s;background:var(--accent2);box-shadow:0 0 6px var(--accent2)}
.rdot:nth-child(7){top:68%;left:62%;animation-delay:1.5s}
.rdot:nth-child(8){top:22%;left:33%;animation-delay:.6s;background:var(--warn);box-shadow:0 0 6px var(--warn)}
@keyframes db{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.2;transform:scale(.5)}}
.rlbl{position:absolute;bottom:18px;left:50%;transform:translateX(-50%);font-family:var(--fm);font-size:10px;color:var(--accent);letter-spacing:2px;opacity:.6}

/* ABOUT */
.ab-in{max-width:1080px;margin:0 auto;display:grid;grid-template-columns:1fr 1fr;gap:68px;align-items:start}
.ab-list{margin-top:26px;display:flex;flex-direction:column;gap:11px}
.ab-item{display:flex;align-items:flex-start;gap:10px;font-size:14px;color:var(--text2);line-height:1.6}
.ab-item::before{content:'▸';color:var(--accent);flex-shrink:0;margin-top:3px;font-size:11px}
.tc{background:var(--card);border:1px solid var(--border);border-radius:13px;padding:26px;position:relative;overflow:hidden}
.tc::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,var(--accent) 50%,transparent);opacity:.35}
.tstack{display:flex;flex-direction:column;gap:9px;margin-top:18px}
.tr{display:flex;align-items:center;justify-content:space-between;padding:9px 13px;border-radius:7px;background:rgba(0,212,255,.025);border:1px solid var(--border)}
.tn{font-family:var(--fm);font-size:12px;color:var(--text);letter-spacing:.5px}
.tt{flex:1;margin:0 13px;height:4px;background:var(--border);border-radius:2px;overflow:hidden}
.tf{height:100%;border-radius:2px;animation:grow 1.5s ease both}
@keyframes grow{from{width:0}to{width:var(--w)}}
.tp{font-family:var(--fm);font-size:11px;color:var(--text2)}

/* CTA */
.cta{text-align:center;padding:96px 40px;border-top:1px solid var(--border)}
.cta-g{width:170px;height:170px;border-radius:50%;background:radial-gradient(circle,rgba(0,212,255,.1),transparent 70%);margin:0 auto 34px;display:flex;align-items:center;justify-content:center;position:relative}
.cta-g::before,.cta-g::after{content:'';position:absolute;border-radius:50%;border:1px solid rgba(0,212,255,.1);animation:pr 2.5s ease-in-out infinite}
.cta-g::before{inset:-18px}.cta-g::after{inset:-36px;animation-delay:.6s}
@keyframes pr{0%,100%{transform:scale(1);opacity:1}50%{transform:scale(1.06);opacity:.4}}
.cta-icon{font-size:50px;position:relative;z-index:1}
.cta-t{font-family:var(--fd);font-size:clamp(28px,3.8vw,44px);font-weight:800;color:var(--white);margin-bottom:13px;line-height:1.1}
.cta-s{font-size:15px;color:var(--text2);margin-bottom:34px;line-height:1.7;max-width:440px;margin-left:auto;margin-right:auto}

/* FOOTER */
footer{border-top:1px solid var(--border);padding:26px 52px;display:flex;align-items:center;justify-content:space-between;position:relative;z-index:1;background:var(--surface)}
.fl{font-family:var(--fd);font-size:14px;font-weight:800;color:var(--text2);letter-spacing:2px}
.fc2{font-size:11px;color:var(--text2);opacity:.5;font-family:var(--fm)}
.flinks{display:flex;gap:18px}
.flinks a{font-size:12px;color:var(--text2);text-decoration:none;opacity:.5;transition:opacity .2s}
.flinks a:hover{opacity:1}

/* AUTH MODAL */
.overlay{position:fixed;inset:0;z-index:2000;background:rgba(0,0,0,.72);backdrop-filter:blur(8px);display:none;align-items:center;justify-content:center;padding:20px}
.overlay.open{display:flex;animation:fi .22s ease}
@keyframes fi{from{opacity:0}to{opacity:1}}
.amodal{background:var(--modal);border:1px solid var(--border2);border-radius:16px;width:100%;max-width:430px;overflow:hidden;box-shadow:0 28px 72px var(--sh),0 0 0 1px rgba(0,212,255,.05);animation:mi .28s cubic-bezier(.2,1.3,.4,1) both;position:relative}
@keyframes mi{from{opacity:0;transform:scale(.93) translateY(18px)}to{opacity:1;transform:scale(1) translateY(0)}}
.mclose{position:absolute;top:14px;right:18px;width:30px;height:30px;border-radius:7px;background:transparent;border:1px solid var(--border2);color:var(--text2);font-size:14px;cursor:pointer;display:flex;align-items:center;justify-content:center;transition:all .2s;z-index:10}
.mclose:hover{border-color:var(--accent2);color:var(--accent2)}
.atabs{display:flex;border-bottom:1px solid var(--border)}
.atab{flex:1;padding:16px;font-size:14px;font-weight:600;background:transparent;border:none;cursor:pointer;color:var(--text2);font-family:var(--fb);border-bottom:2px solid transparent;margin-bottom:-1px;transition:all .2s}
.atab.active{color:var(--accent);border-bottom-color:var(--accent)}
.abody{padding:28px}
.apanel{display:none}.apanel.active{display:block;animation:fu .28s ease}
.alo{display:flex;align-items:center;gap:9px;margin-bottom:7px}
.alo-icon{width:38px;height:38px;border-radius:9px;background:linear-gradient(135deg,rgba(0,212,255,.14),rgba(157,111,255,.1));border:1px solid rgba(0,212,255,.3);display:flex;align-items:center;justify-content:center;font-family:var(--fm);font-size:12px;color:var(--accent);font-weight:700}
.alo-name{font-family:var(--fd);font-size:17px;font-weight:800;color:var(--white);letter-spacing:1px}
.awelcome{font-size:13px;color:var(--text2);margin-bottom:24px}
.fg2{margin-bottom:16px}
.flbl{display:block;font-size:11px;font-weight:500;color:var(--text2);margin-bottom:6px;letter-spacing:.5px}
.finput{width:100%;padding:11px 15px;border-radius:7px;background:var(--inp);border:1px solid var(--inp-b);color:var(--white);font-size:14px;font-family:var(--fb);transition:border-color .2s,box-shadow .2s;outline:none}
.finput:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(0,212,255,.1)}
.finput::placeholder{color:var(--text2);opacity:.5}
.iw{position:relative}
.iico{position:absolute;right:13px;top:50%;transform:translateY(-50%);color:var(--text2);font-size:14px;cursor:pointer;transition:color .2s}
.iico:hover{color:var(--accent)}
.frow{display:flex;align-items:center;justify-content:space-between;margin-bottom:22px}
.cblbl{display:flex;align-items:center;gap:8px;cursor:pointer;font-size:13px;color:var(--text2)}
.cblbl input{display:none}
.cbbox{width:17px;height:17px;border-radius:4px;border:1px solid var(--inp-b);background:var(--inp);display:flex;align-items:center;justify-content:center;transition:all .2s;flex-shrink:0}
.cblbl input:checked+.cbbox{background:var(--accent);border-color:var(--accent)}
.cblbl input:checked+.cbbox::after{content:'✓';font-size:10px;color:#000;font-weight:700}
.flnk{font-size:13px;color:var(--accent);text-decoration:none;opacity:.8;transition:opacity .2s}
.flnk:hover{opacity:1}
.btn-auth{width:100%;padding:12px;border-radius:7px;font-size:14px;font-weight:700;background:linear-gradient(135deg,rgba(0,212,255,.16),rgba(157,111,255,.1));border:1px solid rgba(0,212,255,.4);color:var(--white);cursor:pointer;font-family:var(--fd);letter-spacing:1px;text-transform:uppercase;box-shadow:0 0 18px rgba(0,212,255,.1);transition:all .22s}
.btn-auth:hover{box-shadow:0 0 30px rgba(0,212,255,.24);border-color:rgba(0,212,255,.7);transform:translateY(-1px)}
.adiv{display:flex;align-items:center;gap:11px;margin:18px 0}
.adiv::before,.adiv::after{content:'';flex:1;height:1px;background:var(--border2)}
.adiv span{font-size:12px;color:var(--text2);white-space:nowrap}
.srow{display:grid;grid-template-columns:1fr 1fr;gap:9px}
.btn-soc{display:flex;align-items:center;justify-content:center;gap:7px;padding:10px;border-radius:7px;font-size:13px;font-weight:500;background:var(--inp);border:1px solid var(--inp-b);color:var(--text);cursor:pointer;font-family:var(--fb);transition:all .2s}
.btn-soc:hover{border-color:var(--accent);color:var(--white)}
.btn-soc svg{width:15px;height:15px;flex-shrink:0}
.pws{margin-top:5px;display:none}.pws.show{display:block}
.pwbars{display:flex;gap:4px;margin-bottom:3px}
.pwb{height:3px;flex:1;border-radius:2px;background:var(--border);transition:background .3s}
.pwlbl{font-size:11px;color:var(--text2)}
.terms{font-size:12px;color:var(--text2);text-align:center;margin-top:14px;line-height:1.6}
.terms a{color:var(--accent);text-decoration:none;opacity:.8}
.terms a:hover{opacity:1}

/* FORGOT MODAL */
.fmodal{background:var(--modal);border:1px solid var(--border2);border-radius:16px;width:100%;max-width:390px;padding:32px;box-shadow:0 28px 72px var(--sh);animation:mi .28s cubic-bezier(.2,1.3,.4,1) both;position:relative}
.fmod-t{font-family:var(--fd);font-size:21px;font-weight:800;color:var(--white);margin-bottom:7px}
.fmod-s{font-size:13px;color:var(--text2);margin-bottom:22px;line-height:1.6}
.btn-back{display:flex;align-items:center;gap:6px;background:none;border:none;color:var(--text2);font-size:13px;cursor:pointer;margin-top:14px;padding:0;font-family:var(--fb);transition:color .2s}
.btn-back:hover{color:var(--accent)}

/* Animations */
@keyframes fu{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:translateY(0)}}
@keyframes fade-up{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:translateY(0)}}
.reveal{opacity:0;transform:translateY(26px);transition:opacity .65s ease,transform .65s ease}
.reveal.visible{opacity:1;transform:translateY(0)}
::-webkit-scrollbar{width:5px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:var(--border2);border-radius:3px}
[dir="rtl"] .nav-logo,[dir="rtl"] .alo{flex-direction:row-reverse}
[dir="rtl"] .mclose{right:auto;left:18px}
[dir="rtl"] .lang-dd{right:auto;left:0}
[dir="rtl"] .ab-item::before{content:'◂'}

@media(max-width:960px){
  nav{padding:0 18px}.nav-c{display:none}
  section{padding:70px 22px}
  .fg{grid-template-columns:1fr}
  .how-in,.ab-in{grid-template-columns:1fr;gap:44px}
  .rw{display:none}
  .stats{flex-wrap:wrap;padding:0 20px 56px}
  .si{flex:1;min-width:120px}
  footer{flex-direction:column;gap:11px;text-align:center;padding:18px}
}
</style>
</head>
<body>
<div class="bg-orbs"><div class="orb orb1"></div><div class="orb orb2"></div><div class="orb orb3"></div></div>
<div class="bg-grid"></div>

<!-- NAV -->
<nav>
  <a href="#" class="nav-logo"><div class="nav-logo-icon">PG</div><span data-i18n="brand">PacketGuard</span></a>
  <div class="nav-c">
    <a href="#features" data-i18n="nav.features">Features</a>
    <a href="#how" data-i18n="nav.how">How It Works</a>
    <a href="#about" data-i18n="nav.about">About</a>
  </div>
  <div class="nav-r">
    <div class="lang-sw">
      <button class="lang-btn" onclick="toggleLang()">🌐 <span id="lc">EN</span> ▾</button>
      <div class="lang-dd" id="ldd">
        <div class="lang-opt active" onclick="setLang('en')">🇬🇧 English</div>
        <div class="lang-opt" onclick="setLang('ar')">🇸🇦 العربية</div>
        <div class="lang-opt" onclick="setLang('fr')">🇫🇷 Français</div>
      </div>
    </div>
    <button class="theme-btn" onclick="toggleTheme()" id="tbtn">🌙</button>
    <div class="ndiv"></div>
    <button class="btn-nl" onclick="openAuth('login')" data-i18n="nav.login">Log In</button>
    <button class="btn-ns" onclick="openAuth('signup')" data-i18n="nav.signup">Sign Up</button>
  </div>
</nav>

<!-- HERO -->
<section class="hero">
  <div class="h-badge"><div class="bdot"></div><span data-i18n="hero.badge">REAL-TIME THREAT INTELLIGENCE</span></div>
  <h1 class="h-title"><span class="glow">PacketGuard</span><span class="sub" data-i18n="hero.tagline">Network Guardian</span></h1>
  <p class="h-desc" data-i18n="hero.desc">Advanced network threat detection powered by machine learning. Monitor every device, detect every anomaly, protect your network in real time.</p>
  <div class="h-actions">
    <button class="btn-p" onclick="window.location.href='/dashboard'"><span data-i18n="hero.cta">GET STARTED FREE</span> →</button>
    <a href="#features" class="btn-o">↓ <span data-i18n="hero.explore">Explore Features</span></a>
  </div>
</section>

<!-- STATS -->
<div class="stats reveal">
  <div class="si"><span class="sn">795<span>+</span></span><div class="sl" data-i18n="stats.threats">Threats Detected</div></div>
  <div class="si"><span class="sn">20<span>s</span></span><div class="sl" data-i18n="stats.scan">Scan Interval</div></div>
  <div class="si"><span class="sn">5<span>+</span></span><div class="sl" data-i18n="stats.types">Attack Types</div></div>
  <div class="si"><span class="sn">24<span>/7</span></span><div class="sl" data-i18n="stats.monitor">Live Monitoring</div></div>
</div>

<!-- FEATURES -->
<section id="features">
  <div class="fi">
    <div class="fh reveal">
      <div class="stag" data-i18n="feat.tag">Capabilities</div>
      <h2 class="stitle" data-i18n="feat.title">Everything you need to<br/>secure your network</h2>
      <p class="ssub" data-i18n="feat.sub">Built from the ground up for real-time threat detection with powerful ML-driven anomaly analysis.</p>
    </div>
    <div class="fg">
      <div class="fc reveal"><div class="fi-icon">🔍</div><div class="ft" data-i18n="f1.t">Live Network Scanner</div><div class="fd" data-i18n="f1.d">Automatically discovers all devices every 20 seconds. Identifies phones, laptops, routers, and IoT devices by vendor and MAC address.</div><span class="ftag">AUTO-SCAN</span></div>
      <div class="fc reveal"><div class="fi-icon">🧠</div><div class="ft" data-i18n="f2.t">ML Anomaly Detection</div><div class="fd" data-i18n="f2.d">Isolation Forest learns your normal traffic patterns and flags outliers in real time — catching attacks rule-based systems miss.</div><span class="ftag">ISOLATION FOREST</span></div>
      <div class="fc reveal"><div class="fi-icon">⚡</div><div class="ft" data-i18n="f3.t">Real-Time Alerts</div><div class="fd" data-i18n="f3.d">Instant push notifications for HIGH and CRITICAL threats. Visual popups keep you informed without interrupting your workflow.</div><span class="ftag">LIVE ALERTS</span></div>
      <div class="fc reveal"><div class="fi-icon">📡</div><div class="ft" data-i18n="f4.t">Packet Capture Engine</div><div class="fd" data-i18n="f4.d">Deep packet inspection via Scapy. Monitors TCP, UDP, ICMP traffic and detects port scans, SYN floods, and abnormal sizes.</div><span class="ftag">SCAPY ENGINE</span></div>
      <div class="fc reveal"><div class="fi-icon">🛡️</div><div class="ft" data-i18n="f5.t">Multi-Vector Detection</div><div class="fd" data-i18n="f5.d">Simultaneous detection of port scans, SYN floods, brute force, DNS tunneling, and high packet rate anomalies.</div><span class="ftag">5 ATTACK TYPES</span></div>
      <div class="fc reveal"><div class="fi-icon">📊</div><div class="ft" data-i18n="f6.t">Analytics Dashboard</div><div class="fd" data-i18n="f6.d">Interactive charts, severity breakdowns, live alert feeds, and device monitoring. Auto-refreshes every 5 seconds.</div><span class="ftag">LIVE DASHBOARD</span></div>
    </div>
  </div>
</section>

<!-- HOW IT WORKS -->
<section class="how" id="how">
  <div class="how-in">
    <div>
      <div class="stag reveal" data-i18n="how.tag">Process</div>
      <h2 class="stitle reveal" data-i18n="how.title">How PacketGuard<br/>works</h2>
      <div class="steps">
        <div class="step reveal"><div class="snum">01</div><div><div class="st" data-i18n="s1.t">Network Discovery</div><div class="sd" data-i18n="s1.d">ARP scans discover every active device on the subnet, including sleeping phones and IoT devices.</div></div></div>
        <div class="step reveal"><div class="snum">02</div><div><div class="st" data-i18n="s2.t">Packet Capture</div><div class="sd" data-i18n="s2.d">Scapy captures live packets and feeds them through rule-based and ML-based detection pipelines.</div></div></div>
        <div class="step reveal"><div class="snum">03</div><div><div class="st" data-i18n="s3.t">Threat Analysis</div><div class="sd" data-i18n="s3.d">Each packet is scored by 4 detectors: Port Scan, SYN Flood, High Rate, and Isolation Forest.</div></div></div>
        <div class="step reveal"><div class="snum">04</div><div><div class="st" data-i18n="s4.t">Alert & Visualize</div><div class="sd" data-i18n="s4.d">Confirmed threats are logged, classified by severity, and pushed to the dashboard as notifications.</div></div></div>
      </div>
    </div>
    <div class="rw reveal">
      <div class="radar">
        <div class="rr"></div><div class="rr"></div><div class="rr"></div><div class="rr"></div>
        <div class="rsw"></div>
        <div class="rdot"></div><div class="rdot"></div><div class="rdot"></div><div class="rdot"></div>
      </div>
      <div class="rlbl" data-i18n="radar.lbl">NETWORK SCAN ACTIVE</div>
    </div>
  </div>
</section>

<!-- ABOUT -->
<section id="about">
  <div class="ab-in">
    <div class="reveal">
      <div class="stag" data-i18n="about.tag">About</div>
      <h2 class="stitle" data-i18n="about.title">Built as a graduation project in network security</h2>
      <p class="ssub" data-i18n="about.sub">PacketGuard combines classical intrusion detection with modern ML to deliver a complete monitoring solution.</p>
      <div class="ab-list">
        <div class="ab-item" data-i18n="a1">Real-time packet analysis using Python and Scapy for deep network visibility</div>
        <div class="ab-item" data-i18n="a2">Isolation Forest ML model trained on network traffic to detect anomalies</div>
        <div class="ab-item" data-i18n="a3">Flask-powered REST API serving a live updating web dashboard</div>
        <div class="ab-item" data-i18n="a4">Supports all device types — phones, laptops, smart devices, routers</div>
        <div class="ab-item" data-i18n="a5">Runs on Windows with administrator privileges for full packet capture</div>
      </div>
    </div>
    <div class="tc reveal">
      <div class="stag" data-i18n="tech.tag">Tech Stack</div>
      <div class="tstack">
        <div class="tr"><span class="tn">Python</span><div class="tt"><div class="tf" style="--w:95%;background:var(--accent)"></div></div><span class="tp">95%</span></div>
        <div class="tr"><span class="tn">Scapy</span><div class="tt"><div class="tf" style="--w:85%;background:var(--purple)"></div></div><span class="tp">85%</span></div>
        <div class="tr"><span class="tn">Flask</span><div class="tt"><div class="tf" style="--w:80%;background:var(--accent3)"></div></div><span class="tp">80%</span></div>
        <div class="tr"><span class="tn">Scikit-learn</span><div class="tt"><div class="tf" style="--w:75%;background:var(--warn)"></div></div><span class="tp">75%</span></div>
        <div class="tr"><span class="tn">HTML/CSS/JS</span><div class="tt"><div class="tf" style="--w:90%;background:var(--accent2)"></div></div><span class="tp">90%</span></div>
      </div>
    </div>
  </div>
</section>

<!-- CTA -->
<section class="cta reveal">
  <div class="cta-g"><div class="cta-icon">🛡️</div></div>
  <h2 class="cta-t" data-i18n="cta.title">Ready to protect<br/>your network?</h2>
  <p class="cta-s" data-i18n="cta.sub">Create your free account and start detecting threats in real time.</p>
  <button class="btn-p" onclick="openAuth('signup')" style="font-size:14px;padding:14px 38px"><span data-i18n="cta.btn">CREATE FREE ACCOUNT</span> →</button>
</section>

<!-- FOOTER -->
<footer>
  <div class="fl">PACKETGUARD</div>
  <div class="fc2">© 2026 — Network Threat Detection — Graduation Project</div>
  <div class="flinks">
    <a href="#features" data-i18n="nav.features">Features</a>
    <a href="#how" data-i18n="nav.how">How It Works</a>
    <a href="/dashboard" data-i18n="footer.dash">Dashboard</a>
  </div>
</footer>

<!-- AUTH MODAL -->
<div class="overlay" id="auth-overlay">
  <div class="amodal">
    <button class="mclose" onclick="closeAuth()">✕</button>
    <div class="atabs">
      <button class="atab active" id="tab-login" onclick="switchTab('login')" data-i18n="nav.login">Log In</button>
      <button class="atab" id="tab-signup" onclick="switchTab('signup')" data-i18n="nav.signup">Sign Up</button>
    </div>
    <div class="abody">
      <!-- LOGIN -->
      <div class="apanel active" id="panel-login">
        <div class="alo"><div class="alo-icon">PG</div><div class="alo-name">PacketGuard</div></div>
        <p class="awelcome" data-i18n="login.welcome">Welcome back! Log in to access your dashboard.</p>
        <div class="fg2">
          <label class="flbl" data-i18n="form.email">EMAIL ADDRESS</label>
          <input type="email" class="finput" id="l-email" data-i18n-ph="form.email.ph" placeholder="you@example.com"/>
        </div>
        <div class="fg2">
          <label class="flbl" data-i18n="form.password">PASSWORD</label>
          <div class="iw">
            <input type="password" class="finput" id="l-pass" data-i18n-ph="form.pass.ph" placeholder="Enter your password"/>
            <span class="iico" onclick="togglePass('l-pass',this)">👁</span>
          </div>
        </div>
        <div class="frow">
          <label class="cblbl"><input type="checkbox" id="remember"/><span class="cbbox"></span><span data-i18n="form.remember">Remember me</span></label>
          <a href="#" class="flnk" onclick="openForgot()" data-i18n="form.forgot">Forgot password?</a>
        </div>
        <button class="btn-auth" onclick="handleLogin()" data-i18n="nav.login">LOG IN</button>
        <div class="adiv"><span data-i18n="form.or">or continue with</span></div>
        <div class="srow">
          <button class="btn-soc" onclick="socialAuth('google')"><svg viewBox="0 0 24 24" fill="none"><path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/><path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/><path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l3.66-2.84z" fill="#FBBC05"/><path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/></svg>Google</button>
          <button class="btn-soc" onclick="socialAuth('github')"><svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"/></svg>GitHub</button>
        </div>
      </div>
      <!-- SIGNUP -->
      <div class="apanel" id="panel-signup">
        <div class="alo"><div class="alo-icon">PG</div><div class="alo-name">PacketGuard</div></div>
        <p class="awelcome" data-i18n="signup.welcome">Create your free account to get started.</p>
        <div class="fg2">
          <label class="flbl" data-i18n="form.name">FULL NAME</label>
          <input type="text" class="finput" id="s-name" data-i18n-ph="form.name.ph" placeholder="Your full name"/>
        </div>
        <div class="fg2">
          <label class="flbl" data-i18n="form.email">EMAIL ADDRESS</label>
          <input type="email" class="finput" id="s-email" data-i18n-ph="form.email.ph" placeholder="you@example.com"/>
        </div>
        <div class="fg2">
          <label class="flbl" data-i18n="form.password">PASSWORD</label>
          <div class="iw">
            <input type="password" class="finput" id="s-pass" data-i18n-ph="form.newpass.ph" placeholder="Create a strong password" oninput="checkStrength(this.value)"/>
            <span class="iico" onclick="togglePass('s-pass',this)">👁</span>
          </div>
          <div class="pws" id="pws">
            <div class="pwbars"><div class="pwb" id="pb1"></div><div class="pwb" id="pb2"></div><div class="pwb" id="pb3"></div><div class="pwb" id="pb4"></div></div>
            <div class="pwlbl" id="pwlbl"></div>
          </div>
        </div>
        <button class="btn-auth" onclick="handleSignup()" data-i18n="nav.signup">CREATE ACCOUNT</button>
        <div class="adiv"><span data-i18n="form.or">or continue with</span></div>
        <div class="srow">
          <button class="btn-soc" onclick="socialAuth('google')"><svg viewBox="0 0 24 24" fill="none"><path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/><path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/><path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l3.66-2.84z" fill="#FBBC05"/><path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/></svg>Google</button>
          <button class="btn-soc" onclick="socialAuth('github')"><svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"/></svg>GitHub</button>
        </div>
        <p class="terms" data-i18n="form.terms">By signing up, you agree to our <a href="#">Terms</a> and <a href="#">Privacy Policy</a></p>
      </div>
    </div>
  </div>
</div>

<!-- FORGOT PASSWORD MODAL -->
<div class="overlay" id="forgot-overlay">
  <div class="fmodal">
    <button class="mclose" onclick="closeForgot()">✕</button>
    <div class="alo" style="margin-bottom:18px"><div class="alo-icon">PG</div><div class="alo-name">PacketGuard</div></div>
    <div class="fmod-t" data-i18n="forgot.title">Reset Password</div>
    <div class="fmod-s" data-i18n="forgot.sub">Enter your email and we'll send you a reset link.</div>
    <div class="fg2">
      <label class="flbl" data-i18n="form.email">EMAIL ADDRESS</label>
      <input type="email" class="finput" id="f-email" placeholder="you@example.com"/>
    </div>
    <button class="btn-auth" onclick="handleForgot()" data-i18n="forgot.btn">SEND RESET LINK</button>
    <button class="btn-back" onclick="closeForgot();openAuth('login')">← <span data-i18n="forgot.back">Back to Login</span></button>
  </div>
</div>

<script>
const T={
  en:{brand:'PacketGuard','nav.features':'Features','nav.how':'How It Works','nav.about':'About','nav.login':'Log In','nav.signup':'Sign Up','hero.badge':'REAL-TIME THREAT INTELLIGENCE','hero.tagline':'Network Guardian','hero.desc':'Advanced network threat detection powered by machine learning. Monitor every device, detect every anomaly, protect your network in real time.','hero.cta':'GET STARTED FREE','hero.explore':'Explore Features','stats.threats':'Threats Detected','stats.scan':'Scan Interval','stats.types':'Attack Types','stats.monitor':'Live Monitoring','feat.tag':'Capabilities','feat.title':'Everything you need to<br/>secure your network','feat.sub':'Built from the ground up for real-time threat detection with powerful ML-driven anomaly analysis.','f1.t':'Live Network Scanner','f1.d':'Automatically discovers all devices every 20 seconds. Identifies phones, laptops, routers, and IoT devices by vendor and MAC address.','f2.t':'ML Anomaly Detection','f2.d':'Isolation Forest learns your normal traffic patterns and flags outliers in real time — catching attacks rule-based systems miss.','f3.t':'Real-Time Alerts','f3.d':'Instant push notifications for HIGH and CRITICAL threats. Visual popups keep you informed without interrupting your workflow.','f4.t':'Packet Capture Engine','f4.d':'Deep packet inspection via Scapy. Monitors TCP, UDP, ICMP traffic and detects port scans, SYN floods, and abnormal sizes.','f5.t':'Multi-Vector Detection','f5.d':'Simultaneous detection of port scans, SYN floods, brute force, DNS tunneling, and high packet rate anomalies.','f6.t':'Analytics Dashboard','f6.d':'Interactive charts, severity breakdowns, live alert feeds, and device monitoring. Auto-refreshes every 5 seconds.','how.tag':'Process','how.title':'How PacketGuard<br/>works','s1.t':'Network Discovery','s1.d':'ARP scans discover every active device on the subnet, including sleeping phones and IoT devices.','s2.t':'Packet Capture','s2.d':'Scapy captures live packets and feeds them through rule-based and ML-based detection pipelines.','s3.t':'Threat Analysis','s3.d':'Each packet is scored by 4 detectors: Port Scan, SYN Flood, High Rate, and Isolation Forest.','s4.t':'Alert & Visualize','s4.d':'Confirmed threats are logged, classified by severity, and pushed to the dashboard as notifications.','radar.lbl':'NETWORK SCAN ACTIVE','about.tag':'About','about.title':'Built as a graduation project in network security','about.sub':'PacketGuard combines classical intrusion detection with modern ML to deliver a complete monitoring solution.','a1':'Real-time packet analysis using Python and Scapy for deep network visibility','a2':'Isolation Forest ML model trained on network traffic to detect anomalies','a3':'Flask-powered REST API serving a live updating web dashboard','a4':'Supports all device types — phones, laptops, smart devices, routers','a5':'Runs on Windows with administrator privileges for full packet capture','tech.tag':'Tech Stack','cta.title':'Ready to protect<br/>your network?','cta.sub':'Create your free account and start detecting threats in real time.','cta.btn':'CREATE FREE ACCOUNT','footer.dash':'Dashboard','login.welcome':'Welcome back! Log in to access your dashboard.','signup.welcome':'Create your free account to get started.','form.email':'EMAIL ADDRESS','form.email.ph':'you@example.com','form.password':'PASSWORD','form.pass.ph':'Enter your password','form.newpass.ph':'Create a strong password','form.name':'FULL NAME','form.name.ph':'Your full name','form.remember':'Remember me','form.forgot':'Forgot password?','form.or':'or continue with','form.terms':'By signing up, you agree to our <a href="#">Terms</a> and <a href="#">Privacy Policy</a>','forgot.title':'Reset Password','forgot.sub':"Enter your email and we'll send you a reset link.",'forgot.btn':'SEND RESET LINK','forgot.back':'Back to Login','pw.weak':'Weak','pw.fair':'Fair','pw.good':'Good','pw.strong':'Strong'},
  ar:{brand:'PacketGuard','nav.features':'المميزات','nav.how':'كيف يعمل','nav.about':'عن المشروع','nav.login':'تسجيل الدخول','nav.signup':'إنشاء حساب','hero.badge':'كشف التهديدات في الوقت الفعلي','hero.tagline':'حارس الشبكة','hero.desc':'كشف متقدم لتهديدات الشبكة مدعوم بالذكاء الاصطناعي. راقب كل جهاز، اكتشف كل شذوذ، احمِ شبكتك في الوقت الفعلي.','hero.cta':'ابدأ مجاناً','hero.explore':'استكشف المميزات','stats.threats':'تهديد مكتشف','stats.scan':'فترة الفحص','stats.types':'أنواع الهجمات','stats.monitor':'مراقبة مستمرة','feat.tag':'الإمكانيات','feat.title':'كل ما تحتاجه لتأمين<br/>شبكتك','feat.sub':'مبني من الصفر لاكتشاف التهديدات في الوقت الفعلي مع تحليل الشذوذ بالذكاء الاصطناعي.','f1.t':'فحص الشبكة المباشر','f1.d':'يكتشف تلقائياً جميع الأجهزة كل 20 ثانية. يتعرف على الهواتف والأجهزة والراوترات وأجهزة إنترنت الأشياء.','f2.t':'كشف الشذوذ بالذكاء الاصطناعي','f2.d':'تتعلم خوارزمية Isolation Forest أنماط حركة المرور وترصد الشذوذ في الوقت الفعلي.','f3.t':'تنبيهات فورية','f3.d':'إشعارات فورية للتهديدات عالية الخطورة. نوافذ مرئية تبقيك على اطلاع دون مقاطعة عملك.','f4.t':'محرك التقاط الحزم','f4.d':'فحص عميق للحزم باستخدام Scapy. يراقب TCP وUDP وICMP ويكتشف فحص المنافذ وفيضان SYN.','f5.t':'كشف متعدد المتجهات','f5.d':'كشف متزامن لفحص المنافذ وهجمات SYN والقوة الغاشمة ونفق DNS وشذوذ معدل الحزم.','f6.t':'لوحة تحليلات','f6.d':'مخططات تفاعلية وتفصيل حسب الخطورة وتغذية تنبيهات مباشرة. تتحدث كل 5 ثوانٍ.','how.tag':'العملية','how.title':'كيف يعمل<br/>PacketGuard','s1.t':'اكتشاف الشبكة','s1.d':'تكتشف فحوصات ARP جميع الأجهزة النشطة بما في ذلك الهواتف النائمة.','s2.t':'التقاط الحزم','s2.d':'يلتقط Scapy حزم الشبكة ويغذيها عبر خطوط الكشف المبنية على القواعد والذكاء الاصطناعي.','s3.t':'تحليل التهديدات','s3.d':'تسجيل كل حزمة بواسطة 4 أدوات: فحص المنافذ، SYN، معدل عالٍ، ونموذج ML.','s4.t':'التنبيه والتصور','s4.d':'تُسجَّل التهديدات وتُصنَّف حسب الخطورة وتُرسَل للوحة القيادة.','radar.lbl':'فحص الشبكة نشط','about.tag':'عن المشروع','about.title':'مشروع تخرج في أمن الشبكات','about.sub':'يجمع PacketGuard بين تقنيات كشف التسلل الكلاسيكية والتعلم الآلي لتقديم حل مراقبة متكامل.','a1':'تحليل الحزم في الوقت الفعلي باستخدام Python وScapy','a2':'نموذج Isolation Forest لاكتشاف الشذوذ الإحصائي','a3':'واجهة REST مدعومة بـ Flask تخدم لوحة ويب متحدثة','a4':'يدعم جميع أنواع الأجهزة — هواتف، أجهزة محمولة، راوترات','a5':'يعمل على Windows بامتيازات المسؤول','tech.tag':'التقنيات','cta.title':'مستعد لحماية<br/>شبكتك؟','cta.sub':'أنشئ حسابك المجاني وابدأ في كشف التهديدات.','cta.btn':'إنشاء حساب مجاني','footer.dash':'لوحة التحكم','login.welcome':'مرحباً بعودتك! سجّل الدخول للوصول للوحة.','signup.welcome':'أنشئ حسابك المجاني للبدء.','form.email':'البريد الإلكتروني','form.email.ph':'example@mail.com','form.password':'كلمة المرور','form.pass.ph':'أدخل كلمة المرور','form.newpass.ph':'أنشئ كلمة مرور قوية','form.name':'الاسم الكامل','form.name.ph':'اسمك الكامل','form.remember':'تذكرني','form.forgot':'نسيت كلمة المرور؟','form.or':'أو المتابعة باستخدام','form.terms':'بالتسجيل توافق على <a href="#">الشروط</a> و<a href="#">الخصوصية</a>','forgot.title':'إعادة تعيين كلمة المرور','forgot.sub':'أدخل بريدك وسنرسل رابط إعادة التعيين.','forgot.btn':'إرسال الرابط','forgot.back':'العودة لتسجيل الدخول','pw.weak':'ضعيفة','pw.fair':'مقبولة','pw.good':'جيدة','pw.strong':'قوية'},
  fr:{brand:'PacketGuard','nav.features':'Fonctionnalités','nav.how':'Fonctionnement','nav.about':'À propos','nav.login':'Connexion','nav.signup':'Inscription','hero.badge':'DÉTECTION DE MENACES EN TEMPS RÉEL','hero.tagline':'Gardien du Réseau','hero.desc':'Détection avancée des menaces réseau propulsée par ML. Surveillez chaque appareil, détectez chaque anomalie, protégez votre réseau en temps réel.','hero.cta':'COMMENCER GRATUITEMENT','hero.explore':'Explorer','stats.threats':'Menaces Détectées','stats.scan':'Intervalle Scan','stats.types':'Types d\'Attaques','stats.monitor':'Surveillance Continue','feat.tag':'Capacités','feat.title':'Tout pour sécuriser<br/>votre réseau','feat.sub':'Conçu pour la détection en temps réel avec analyse d\'anomalies par ML.','f1.t':'Scanner Réseau Live','f1.d':'Découvre tous les appareils toutes les 20s. Identifie téléphones, laptops, routeurs et IoT.','f2.t':'Détection ML','f2.d':'Isolation Forest apprend vos schémas normaux et signale les anomalies en temps réel.','f3.t':'Alertes Temps Réel','f3.d':'Notifications instantanées pour menaces HIGH et CRITICAL. Popups visuelles non intrusives.','f4.t':'Capture de Paquets','f4.d':'Inspection profonde via Scapy. Surveille TCP, UDP, ICMP et détecte scans et floods.','f5.t':'Détection Multi-Vecteurs','f5.d':'Détection simultanée de scans, floods SYN, brute force, DNS tunneling et débits anormaux.','f6.t':'Tableau de Bord','f6.d':'Graphiques interactifs, alertes en direct et monitoring. Actualisation toutes les 5 secondes.','how.tag':'Processus','how.title':'Comment fonctionne<br/>PacketGuard','s1.t':'Découverte Réseau','s1.d':'Les scans ARP découvrent tous les appareils actifs, y compris les téléphones en veille.','s2.t':'Capture de Paquets','s2.d':'Scapy capture les paquets et les traite via pipelines règles et ML simultanément.','s3.t':'Analyse des Menaces','s3.d':'Chaque paquet est évalué: Scan ports, SYN Flood, Débit élevé, Isolation Forest.','s4.t':'Alerte & Visualisation','s4.d':'Menaces confirmées enregistrées, classées et envoyées au tableau de bord.','radar.lbl':'SCAN RÉSEAU ACTIF','about.tag':'À Propos','about.title':'Projet de fin d\'études en sécurité réseau','about.sub':'PacketGuard combine détection classique et ML moderne pour une solution complète.','a1':'Analyse temps réel avec Python et Scapy pour visibilité réseau approfondie','a2':'Modèle Isolation Forest entraîné sur le trafic réseau','a3':'API REST Flask servant un tableau de bord mis à jour en direct','a4':'Supporte tous les types: téléphones, laptops, IoT, routeurs','a5':'Fonctionne sous Windows avec privilèges admin','tech.tag':'Stack Technique','cta.title':'Prêt à protéger<br/>votre réseau ?','cta.sub':'Créez votre compte gratuit et commencez à détecter les menaces.','cta.btn':'CRÉER UN COMPTE GRATUIT','footer.dash':'Tableau de bord','login.welcome':'Bon retour ! Connectez-vous pour accéder à votre tableau.','signup.welcome':'Créez votre compte gratuit pour commencer.','form.email':'ADRESSE E-MAIL','form.email.ph':'vous@exemple.com','form.password':'MOT DE PASSE','form.pass.ph':'Votre mot de passe','form.newpass.ph':'Créez un mot de passe fort','form.name':'NOM COMPLET','form.name.ph':'Votre nom complet','form.remember':'Se souvenir','form.forgot':'Mot de passe oublié ?','form.or':'ou continuer avec','form.terms':'En vous inscrivant vous acceptez nos <a href="#">CGU</a> et <a href="#">Confidentialité</a>','forgot.title':'Réinitialiser','forgot.sub':'Entrez votre e-mail et nous vous enverrons un lien.','forgot.btn':'ENVOYER LE LIEN','forgot.back':'Retour à la connexion','pw.weak':'Faible','pw.fair':'Acceptable','pw.good':'Bon','pw.strong':'Fort'}
};

let lang='en';
function t(k){return T[lang][k]||T.en[k]||k}
function applyT(){
  document.documentElement.lang=lang;
  document.documentElement.dir=lang==='ar'?'rtl':'ltr';
  document.querySelectorAll('[data-i18n]').forEach(el=>{const v=t(el.getAttribute('data-i18n'));if(v)el.innerHTML=v});
  document.querySelectorAll('[data-i18n-ph]').forEach(el=>{const v=t(el.getAttribute('data-i18n-ph'));if(v)el.placeholder=v});
}
function setLang(l){
  lang=l;
  document.getElementById('lc').textContent=l.toUpperCase();
  document.querySelectorAll('.lang-opt').forEach(o=>o.classList.remove('active'));
  document.querySelector(`.lang-opt[onclick="setLang('${l}')"]`)?.classList.add('active');
  closeLang();applyT();
  try{localStorage.setItem('pg-lang',l)}catch(e){}
}
function toggleLang(){document.getElementById('ldd').classList.toggle('open')}
function closeLang(){document.getElementById('ldd').classList.remove('open')}
document.addEventListener('click',e=>{if(!e.target.closest('.lang-sw'))closeLang()});

let dark=true;
function toggleTheme(){
  dark=!dark;
  document.documentElement.setAttribute('data-theme',dark?'dark':'light');
  document.getElementById('tbtn').textContent=dark?'🌙':'☀️';
  try{localStorage.setItem('pg-theme',dark?'dark':'light')}catch(e){}
}

function openAuth(tab){
  document.getElementById('auth-overlay').classList.add('open');
  switchTab(tab);document.body.style.overflow='hidden';
}
function closeAuth(){document.getElementById('auth-overlay').classList.remove('open');document.body.style.overflow=''}
document.getElementById('auth-overlay').addEventListener('click',e=>{if(e.target===document.getElementById('auth-overlay'))closeAuth()});
function switchTab(tab){
  document.querySelectorAll('.atab').forEach(t=>t.classList.remove('active'));
  document.querySelectorAll('.apanel').forEach(p=>p.classList.remove('active'));
  document.getElementById('tab-'+tab).classList.add('active');
  document.getElementById('panel-'+tab).classList.add('active');
}
function openForgot(){closeAuth();document.getElementById('forgot-overlay').classList.add('open');document.body.style.overflow='hidden'}
function closeForgot(){document.getElementById('forgot-overlay').classList.remove('open');document.body.style.overflow=''}
document.getElementById('forgot-overlay').addEventListener('click',e=>{if(e.target===document.getElementById('forgot-overlay'))closeForgot()});

function togglePass(id,ico){const i=document.getElementById(id);if(i.type==='password'){i.type='text';ico.textContent='🙈'}else{i.type='password';ico.textContent='👁'}}

function checkStrength(v){
  const el=document.getElementById('pws');
  if(!v){el.classList.remove('show');return}
  el.classList.add('show');
  let s=0;
  if(v.length>=8)s++;if(/[A-Z]/.test(v))s++;if(/[0-9]/.test(v))s++;if(/[^A-Za-z0-9]/.test(v))s++;
  const cols=['','#ff2d6b','#ffb800','#00d4ff','#00ff9d'];
  const lbls=[t('pw.weak'),t('pw.weak'),t('pw.fair'),t('pw.good'),t('pw.strong')];
  ['pb1','pb2','pb3','pb4'].forEach((id,i)=>{
    const b=document.getElementById(id);
    b.style.background=i<s?cols[s]:'var(--border)';
  });
  const lbl=document.getElementById('pwlbl');
  lbl.textContent=lbls[s];lbl.style.color=cols[s]||'var(--text2)';
}

function handleLogin(){
  const e=document.getElementById('l-email').value,p=document.getElementById('l-pass').value;
  if(!e||!p){alert('Please fill in all fields.');return}
  // TODO: Connect to backend
  closeAuth(); window.location.href='/dashboard';
}
function handleSignup(){
  const n=document.getElementById('s-name').value,e=document.getElementById('s-email').value,p=document.getElementById('s-pass').value;
  if(!n||!e||!p){alert('Please fill in all fields.');return}
  // TODO: Connect to backend
  closeAuth(); window.location.href='/dashboard';
}
function handleForgot(){
  const e=document.getElementById('f-email').value;
  if(!e){alert('Please enter your email.');return}
  alert('📧 Reset link would be sent to: '+e);closeForgot();
}
function socialAuth(p){alert('🔗 OAuth with '+p+' — ready for backend integration!')}

// Scroll reveal
const obs=new IntersectionObserver(entries=>{
  entries.forEach(e=>{if(e.isIntersecting){e.target.classList.add('visible');obs.unobserve(e.target)}});
},{threshold:.1,rootMargin:'0px 0px -50px 0px'});
document.querySelectorAll('.reveal').forEach((el,i)=>{el.style.transitionDelay=(i%3)*.08+'s';obs.observe(el)});

document.querySelectorAll('a[href^="#"]').forEach(a=>{
  a.addEventListener('click',e=>{const t=document.querySelector(a.getAttribute('href'));if(t){e.preventDefault();t.scrollIntoView({behavior:'smooth'})}});
});
window.addEventListener('scroll',()=>{
  document.querySelector('nav').style.borderBottomColor=window.scrollY>50?'var(--border2)':'var(--border)';
});
document.addEventListener('keydown',e=>{if(e.key==='Escape'){closeAuth();closeForgot()}});

// Init
(function(){
  let sl='en',st='dark';
  try{sl=localStorage.getItem('pg-lang')||'en';st=localStorage.getItem('pg-theme')||'dark'}catch(e){}
  dark=st==='dark';
  document.documentElement.setAttribute('data-theme',st);
  document.getElementById('tbtn').textContent=dark?'🌙':'☀️';
  setLang(sl);
})();
</script>
</body>
</html>
''' 

def read_template(name):
    """Read an HTML file from the templates folder."""
    path = os.path.join(BASE_DIR, "templates", name)
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return f"<h1>Template not found: {name}</h1><p>Put {name} in the templates/ folder.</p>"


# ── Scan History ─────────────────────────────────────────────────
SCAN_HISTORY_FILE = os.path.join(BASE_DIR, "scan_history.json")

def load_scan_history():
    try:
        with open(SCAN_HISTORY_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []

def save_scan_history(entry):
    history = load_scan_history()
    history.append(entry)
    history = history[-200:]  # keep last 200 scans
    try:
        with open(SCAN_HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(history, f, indent=2, default=str)
    except Exception as e:
        print(f"[HISTORY] Could not save: {e}")

def run_network_scan_with_history():
    """Wrapper that saves scan result to history."""
    global _scan_status
    _scan_status["running"] = True
    try:
        scanner_path = os.path.join(BASE_DIR, "code", "network_scanner.py")
        if not os.path.exists(scanner_path):
            return
        import importlib.util
        spec = importlib.util.spec_from_file_location("network_scanner", scanner_path)
        mod  = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        devices = mod.scan_network()
        count = len(devices) if devices else 0
        _scan_status["last_scan"]    = datetime.now().isoformat()
        _scan_status["device_count"] = count
        # Save to history
        save_scan_history({
            "timestamp":    datetime.now().isoformat(),
            "device_count": count,
            "devices":      [d.get("ip","?") for d in (devices or [])],
            "trigger":      "auto",
        })
        print(f"[AUTO-SCAN] Done — {count} device(s) found")
    except Exception as e:
        print(f"[AUTO-SCAN] Error: {e}")
    finally:
        _scan_status["running"] = False
        _scan_status["next_scan"] = datetime.fromtimestamp(time.time() + SCAN_INTERVAL).isoformat()

@app.route("/api/scan_history")
def api_scan_history():
    return jsonify(load_scan_history())

@app.route("/api/scan_now", methods=["POST"])
def api_scan_now_history():
    if not _scan_status["running"]:
        def _run():
            global _scan_status
            _scan_status["running"] = True
            try:
                scanner_path = os.path.join(BASE_DIR, "code", "network_scanner.py")
                import importlib.util
                spec = importlib.util.spec_from_file_location("network_scanner", scanner_path)
                mod  = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                devices = mod.scan_network()
                count = len(devices) if devices else 0
                _scan_status["last_scan"]    = datetime.now().isoformat()
                _scan_status["device_count"] = count
                save_scan_history({
                    "timestamp":    datetime.now().isoformat(),
                    "device_count": count,
                    "devices":      [d.get("ip","?") for d in (devices or [])],
                    "trigger":      "manual",
                })
            except Exception as e:
                print(f"[SCAN_NOW] Error: {e}")
            finally:
                _scan_status["running"] = False
                _scan_status["next_scan"] = datetime.fromtimestamp(time.time() + SCAN_INTERVAL).isoformat()
        t = threading.Thread(target=_run, daemon=True)
        t.start()
        return jsonify({"status": "scan_started"})
    return jsonify({"status": "already_running"})


# ── IP Block / Whitelist ──────────────────────────────────────────
BLOCKLIST_FILE    = os.path.join(BASE_DIR, "blocklist.json")
WHITELIST_FILE    = os.path.join(BASE_DIR, "whitelist.json")

def load_blocklist():
    try:
        with open(BLOCKLIST_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []

def load_whitelist():
    try:
        with open(WHITELIST_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []

def save_list(path, data):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
    except Exception as e:
        print(f"[LIST] Save error: {e}")

@app.route("/api/blocklist", methods=["GET"])
def api_get_blocklist():
    return jsonify({"blocked": load_blocklist(), "whitelisted": load_whitelist()})

@app.route("/api/blocklist/block", methods=["POST"])
def api_block_ip():
    data = request.get_json() or {}
    ip   = data.get("ip","").strip()
    reason = data.get("reason","Manual block")
    if not ip:
        return jsonify({"success": False, "error": "IP required"})
    blocked = load_blocklist()
    if any(e["ip"] == ip for e in blocked):
        return jsonify({"success": False, "error": "Already blocked"})
    blocked.append({"ip": ip, "reason": reason, "timestamp": datetime.now().isoformat()})
    save_list(BLOCKLIST_FILE, blocked)
    return jsonify({"success": True})

@app.route("/api/blocklist/unblock", methods=["POST"])
def api_unblock_ip():
    data = request.get_json() or {}
    ip   = data.get("ip","").strip()
    blocked = [e for e in load_blocklist() if e["ip"] != ip]
    save_list(BLOCKLIST_FILE, blocked)
    return jsonify({"success": True})

@app.route("/api/blocklist/whitelist", methods=["POST"])
def api_whitelist_ip():
    data = request.get_json() or {}
    ip   = data.get("ip","").strip()
    reason = data.get("reason","Trusted device")
    if not ip:
        return jsonify({"success": False, "error": "IP required"})
    wl = load_whitelist()
    if any(e["ip"] == ip for e in wl):
        return jsonify({"success": False, "error": "Already whitelisted"})
    wl.append({"ip": ip, "reason": reason, "timestamp": datetime.now().isoformat()})
    save_list(WHITELIST_FILE, wl)
    return jsonify({"success": True})

@app.route("/api/blocklist/unwhitelist", methods=["POST"])
def api_unwhitelist_ip():
    data = request.get_json() or {}
    ip   = data.get("ip","").strip()
    wl = [e for e in load_whitelist() if e["ip"] != ip]
    save_list(WHITELIST_FILE, wl)
    return jsonify({"success": True})


# ── Email Alerts ──────────────────────────────────────────────────
EMAIL_CONFIG_FILE = os.path.join(BASE_DIR, "email_config.json")

def load_email_config():
    try:
        with open(EMAIL_CONFIG_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"enabled": False, "smtp_host": "smtp.gmail.com", "smtp_port": 587,
                "sender": "", "password": "", "recipient": "", "min_severity": "HIGH"}

def save_email_config(cfg):
    try:
        with open(EMAIL_CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
    except Exception as e:
        print(f"[EMAIL] Config save error: {e}")

def send_alert_email(alert):
    cfg = load_email_config()
    if not cfg.get("enabled") or not cfg.get("sender") or not cfg.get("recipient"):
        return
    sev_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    min_sev   = sev_order.get(cfg.get("min_severity","HIGH"), 2)
    alert_sev = sev_order.get(alert.get("severity","LOW"), 0)
    if alert_sev < min_sev:
        return
    try:
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[PacketGuard] {alert.get('severity','?')} ALERT — {alert.get('alert_type','Unknown')}"
        msg["From"]    = cfg["sender"]
        msg["To"]      = cfg["recipient"]
        html = f"""
        <div style="font-family:monospace;background:#03050a;color:#c0d4ee;padding:24px;border-radius:8px;max-width:600px">
          <h2 style="color:#00c8ff;margin-bottom:16px">⚠ PacketGuard Alert</h2>
          <table style="width:100%;border-collapse:collapse">
            <tr><td style="color:#3a5570;padding:6px 0;width:140px">Severity</td>
                <td style="color:{'#ff2d55' if alert.get('severity')=='CRITICAL' else '#ff6400' if alert.get('severity')=='HIGH' else '#ffb800'};font-weight:bold">{alert.get('severity','?')}</td></tr>
            <tr><td style="color:#3a5570;padding:6px 0">Type</td><td>{alert.get('alert_type','?')}</td></tr>
            <tr><td style="color:#3a5570;padding:6px 0">Source IP</td><td style="color:#00c8ff">{alert.get('source_ip','?')}</td></tr>
            <tr><td style="color:#3a5570;padding:6px 0">Message</td><td>{alert.get('message','?')}</td></tr>
            <tr><td style="color:#3a5570;padding:6px 0">Time</td><td>{alert.get('timestamp','?')}</td></tr>
          </table>
        </div>"""
        msg.attach(MIMEText(html, "html"))
        with smtplib.SMTP(cfg["smtp_host"], int(cfg["smtp_port"])) as s:
            s.starttls()
            s.login(cfg["sender"], cfg["password"])
            s.sendmail(cfg["sender"], cfg["recipient"], msg.as_string())
        print(f"[EMAIL] Alert sent to {cfg['recipient']}")
    except Exception as e:
        print(f"[EMAIL] Send error: {e}")

@app.route("/api/email_config", methods=["GET"])
def api_get_email_config():
    cfg = load_email_config()
    safe = dict(cfg)
    if safe.get("password"):
        safe["password"] = "••••••••"  # never expose password
    return jsonify(safe)

@app.route("/api/email_config", methods=["POST"])
def api_save_email_config():
    data = request.get_json() or {}
    cfg  = load_email_config()
    for k in ["enabled","smtp_host","smtp_port","sender","recipient","min_severity"]:
        if k in data:
            cfg[k] = data[k]
    if data.get("password") and data["password"] != "••••••••":
        cfg["password"] = data["password"]
    save_email_config(cfg)
    return jsonify({"success": True})

@app.route("/api/email_test", methods=["POST"])
def api_email_test():
    test_alert = {
        "alert_type": "TEST_ALERT", "severity": "HIGH",
        "source_ip": "127.0.0.1", "destination_ip": "N/A",
        "message": "This is a test alert from PacketGuard.",
        "timestamp": datetime.now().isoformat(),
    }
    try:
        send_alert_email(test_alert)
        return jsonify({"success": True, "message": "Test email sent!"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


# ── Geo-IP Lookup ─────────────────────────────────────────────────
def sev_rank(s):
    return {"LOW":0,"MEDIUM":1,"HIGH":2,"CRITICAL":3}.get(s,0)

@app.route("/api/geo_alerts")
def api_geo_alerts():
    """Return top suspicious IPs with geo info. Private IPs shown without lookup."""
    import urllib.request

    def is_private(ip):
        parts = ip.split(".")
        if len(parts) != 4:
            return True
        try:
            a, b = int(parts[0]), int(parts[1])
            return (a == 10 or a == 127 or
                    (a == 172 and 16 <= b <= 31) or
                    (a == 192 and b == 168) or
                    (a == 169 and b == 254))
        except Exception:
            return True

    alerts = load_alerts()
    ip_counts   = {}
    ip_severity = {}
    for a in alerts:
        ip = a.get("source_ip", "")
        if not ip or ip in ("N/A", "Multiple", ""):
            continue
        ip_counts[ip]   = ip_counts.get(ip, 0) + 1
        sev = a.get("severity", "LOW")
        if sev_rank(sev) > sev_rank(ip_severity.get(ip, "LOW")):
            ip_severity[ip] = sev

    if not ip_counts:
        return jsonify([])

    top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:20]
    results = []
    for ip, count in top_ips:
        if is_private(ip):
            # Don't call external API for private IPs — show as local
            results.append({
                "ip": ip, "count": count,
                "severity":    ip_severity.get(ip, "LOW"),
                "country":     "Local Network",
                "countryCode": "LO",
                "city":        "Private IP",
                "lat": 0, "lon": 0, "isp": "Internal",
            })
        else:
            try:
                url  = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,lat,lon,isp"
                req  = urllib.request.Request(url, headers={"User-Agent": "PacketGuard/1.0"})
                resp = urllib.request.urlopen(req, timeout=4)
                geo  = json.loads(resp.read().decode())
                if geo.get("status") == "success":
                    results.append({
                        "ip": ip, "count": count,
                        "severity":    ip_severity.get(ip, "LOW"),
                        "country":     geo.get("country", "Unknown"),
                        "countryCode": geo.get("countryCode", ""),
                        "city":        geo.get("city", ""),
                        "lat":         geo.get("lat", 0),
                        "lon":         geo.get("lon", 0),
                        "isp":         geo.get("isp", ""),
                    })
                else:
                    results.append({"ip": ip, "count": count, "severity": ip_severity.get(ip, "LOW"),
                                    "country": "Unknown", "countryCode": "", "city": "", "lat": 0, "lon": 0, "isp": ""})
            except Exception:
                results.append({"ip": ip, "count": count, "severity": ip_severity.get(ip, "LOW"),
                                "country": "Lookup failed", "countryCode": "", "city": "", "lat": 0, "lon": 0, "isp": ""})
    return jsonify(results)


# ── Export ────────────────────────────────────────────────────────
import csv, io

@app.route("/api/export/alerts.csv")
def export_alerts_csv():
    alerts = load_alerts()
    si = io.StringIO()
    w  = csv.DictWriter(si, fieldnames=["timestamp","alert_type","severity","source_ip","destination_ip","message"])
    w.writeheader()
    for a in alerts:
        w.writerow({k: a.get(k,"") for k in w.fieldnames})
    output = si.getvalue()
    return Response(output, mimetype="text/csv",
                    headers={"Content-Disposition": "attachment;filename=packetguard_alerts.csv"})

@app.route("/api/export/alerts.json")
def export_alerts_json():
    alerts = load_alerts()
    output = json.dumps(alerts, indent=2, default=str)
    return Response(output, mimetype="application/json",
                    headers={"Content-Disposition": "attachment;filename=packetguard_alerts.json"})

@app.route("/api/export/scan_history.csv")
def export_scan_history_csv():
    history = load_scan_history()
    si = io.StringIO()
    w  = csv.DictWriter(si, fieldnames=["timestamp","device_count","trigger","devices"])
    w.writeheader()
    for h in history:
        w.writerow({"timestamp": h.get("timestamp",""), "device_count": h.get("device_count",0),
                    "trigger": h.get("trigger",""), "devices": ", ".join(h.get("devices",[]))})
    return Response(si.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment;filename=packetguard_scan_history.csv"})


# ── HTML Routes ───────────────────────────────────────────────────
@app.route("/")
def home():
    return Response(read_template("index.html"), mimetype="text/html")

@app.route("/monitor")
def monitor():
    return Response(read_template("monitor.html"), mimetype="text/html")

@app.route("/dashboard")
def dashboard():
    return Response(read_template("dashboard.html"), mimetype="text/html")


if __name__ == "__main__":
    print("""
+-----------------------------------------------------------+
|         PacketGuard - Network Threat Dashboard           |
|        Access from: http://localhost:5000                 |
|   Auto-scanning network every 60 seconds...              |
+-----------------------------------------------------------+
    """)
    app.run(host="0.0.0.0", port=5000, debug=False)