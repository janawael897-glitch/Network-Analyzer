#!/usr/bin/env python3
<<<<<<< HEAD
import os
import warnings
os.environ["PYTHONWARNINGS"] = "ignore"
warnings.filterwarnings("ignore")
warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", category=FutureWarning)

import logging

class _SklearnWarningFilter(logging.Filter):
    def filter(self, record):
        msg = record.getMessage()
        if "sklearn" in msg or "joblib" in msg or "delayed" in msg or "Parallel" in msg:
            return False
        return True

logging.getLogger().addFilter(_SklearnWarningFilter())
logging.getLogger("py.warnings").addFilter(_SklearnWarningFilter())
=======
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
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
<<<<<<< HEAD
from flask_socketio import SocketIO, emit as ws_emit
from flask_cors import CORS

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")
app.secret_key = "packetguard-secret-key-2026"  # fixed key so sessions survive restarts
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"]   = False      # must be False for HTTP (localhost)
app.config["SESSION_COOKIE_NAME"]     = "pg_flask_session"
app.config["PERMANENT_SESSION_LIFETIME"] = 86400  # 24 hours

# ── File paths — defined early so all callbacks can reference them ─
=======
from flask_cors import CORS

app = Flask(__name__)
app.secret_key = "packetguard-secret-key-2026"  # fixed key so sessions survive restarts
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_HTTPONLY"] = True
CORS(app, supports_credentials=True)

>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
BASE_DIR         = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ALERTS_FILE      = os.path.join(BASE_DIR, "alerts.json")
ML_ALERTS_FILE   = os.path.join(BASE_DIR, "ml_alerts.json")
DEVICES_FILE     = os.path.join(BASE_DIR, "network_devices.json")
LIVE_MONITOR_LOG = os.path.join(BASE_DIR, "live_monitor.log")
<<<<<<< HEAD
LIVE_STATE_FILE  = os.path.join(BASE_DIR, "live_state.json")
MODELS_DIR       = os.path.join(BASE_DIR, "models")
BLOCKLIST_FILE   = os.path.join(BASE_DIR, "blocklist.json")
WHITELIST_FILE   = os.path.join(BASE_DIR, "whitelist.json")

# ── CORS: manual after_request handler (more reliable than flask-cors defaults) ──
# flask-cors with supports_credentials=True + no explicit origin can behave
# inconsistently across browsers (especially Brave). We handle it manually.
CORS(app, supports_credentials=True,
     origins=["http://localhost:5000", "http://127.0.0.1:5000",
               "http://localhost:5001", "http://127.0.0.1:5001"])

_ALLOWED_ORIGINS = {
    "http://localhost:5000", "http://127.0.0.1:5000",
    "http://localhost:5001", "http://127.0.0.1:5001",
}

@app.after_request
def _cors_headers(response):
    origin = request.headers.get("Origin", "")
    # For same-origin requests there's no Origin header - nothing needed.
    # For cross-origin (or Brave privacy-mode which may alter headers):
    if origin in _ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"]      = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Methods"]     = "GET, POST, PUT, DELETE, OPTIONS"
        response.headers["Access-Control-Allow-Headers"]     = "Content-Type, Authorization, X-Requested-With"
        response.headers["Access-Control-Max-Age"]           = "3600"
        response.headers["Vary"]                             = "Origin"
    elif not origin:
        # Same-origin request - still set Vary so caches work correctly
        response.headers.setdefault("Vary", "Origin")
    return response

@app.route("/api/auth/login",    methods=["OPTIONS"])
@app.route("/api/auth/register", methods=["OPTIONS"])
@app.route("/api/auth/logout",   methods=["OPTIONS"])
@app.route("/api/auth/me",       methods=["OPTIONS"])
def _auth_preflight():
    """Handle CORS preflight for all auth endpoints."""
    resp = Response("", status=204)
    origin = request.headers.get("Origin", "")
    if origin in _ALLOWED_ORIGINS:
        resp.headers["Access-Control-Allow-Origin"]      = origin
        resp.headers["Access-Control-Allow-Credentials"] = "true"
        resp.headers["Access-Control-Allow-Methods"]     = "GET, POST, OPTIONS"
        resp.headers["Access-Control-Allow-Headers"]     = "Content-Type, Authorization"
        resp.headers["Access-Control-Max-Age"]           = "3600"
    return resp

# ── Enterprise feature engines ─────────────────────────────────────
try:
    from db_manager          import run_migrations
    from enterprise_bp       import enterprise_bp
    from correlation_engine  import start_correlation_thread
    from threat_scoring      import start_decay_thread
    from auto_response       import start_response_thread
    from baseline_learning   import start_baseline_thread

    run_migrations()
    app.register_blueprint(enterprise_bp)
    start_correlation_thread()
    start_decay_thread()
    start_response_thread(email_fn=None)   # pass your send_alert_email here if desired
    start_baseline_thread()
    # Wire response engine into block_manager so BLOCK actions populate timeline
    try:
        from auto_response import get_engine as _get_re
        from block_manager import set_response_engine as _bm_set_re2
        _bm_set_re2(_get_re())
    except Exception:
        pass
    print("[ENTERPRISE] All four engines started successfully.")
except Exception as _e:
    print(f"[ENTERPRISE] Could not load enterprise modules (non-fatal): {_e}")

# ── SOC v2 modules: dedup, real correlation, firewall ─────────────
try:
    from soc_api               import soc_bp
    from alert_dedup           import set_emit_callback as _dedup_set_emit, ingest as _dedup_ingest
    from correlation_engine_v2 import start_correlation_thread as _start_corr_v2, feed_alert as _corr_feed
    from firewall_enforcer     import set_emit_callback as _fw_set_emit
    from block_manager         import (
        set_emit_callback as _bm_set_emit,
        set_response_engine as _bm_set_re,
        evaluate_alert as _bm_eval_alert,
    )

    app.register_blueprint(soc_bp)

    _alerts_write_lock = threading.Lock()

    def _on_dedup_alert(alert):
        """Called by alert_dedup after aggregation window — persist to SQLite + push + block eval."""
        try:
            with _alerts_write_lock:
                _known = {"alert_type","severity","source_ip","dest_ip","destination_ip","message","timestamp"}
                _extra = {k: v for k, v in alert.items() if k not in _known}
                _conn = _db_alerts()
                _conn.execute(
                    "INSERT INTO alerts (alert_type,severity,source_ip,dest_ip,message,timestamp,extra) VALUES (?,?,?,?,?,?,?)",
                    (
                        alert.get("alert_type"),
                        alert.get("severity"),
                        alert.get("source_ip"),
                        alert.get("dest_ip") or alert.get("destination_ip"),
                        alert.get("message"),
                        alert.get("timestamp"),
                        json.dumps(_extra, default=str) if _extra else None,
                    )
                )
                _conn.commit()
                _conn.close()
            push_alert(alert)
            _corr_feed(alert)
            _bm_eval_alert(alert)
        except Exception as _ex:
            print(f"[DEDUP-CB] {_ex}")

    _dedup_set_emit(_on_dedup_alert)
    _fw_set_emit(socketio.emit)
    _bm_set_emit(socketio.emit)
    # Wire response engine after it starts (done below in ENTERPRISE block)
    _start_corr_v2()
    print("[SOC-V2] Alert dedup, correlation v2, firewall enforcer, block manager loaded.")
except Exception as _e:
    print(f"[SOC-V2] Could not load SOC v2 modules (non-fatal): {_e}")

# ── Auto-start packet capture at module level ─────────────────────
# Works with any launcher (start.py, gunicorn, python web_dashboard.py)
def _auto_start_live_monitor():
    import sys, subprocess, os
    # Guard 1: never spawn from inside the live_monitor subprocess itself
    if os.environ.get("PACKETGUARD_MONITOR_PROC") == "1":
        return
    # Guard 2: when Flask debug=True is used, Werkzeug spawns a reloader child.
    # The subprocess must only be launched once — from the MAIN process, not the
    # reloader child.  WERKZEUG_RUN_MAIN is set to "true" inside the child, so
    # we skip launch there and let the main process (where it is absent) do it.
    # When start.py is used (no reloader), this env var is never set, so we
    # always launch correctly.
    if os.environ.get("WERKZEUG_RUN_MAIN") == "true":
        return
    try:
        monitor_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "live_monitor.py")
        if not os.path.exists(monitor_path):
            print("[LIVE-MONITOR] live_monitor.py not found at:", monitor_path)
            return
        print(f"[LIVE-MONITOR] Launching packet capture subprocess: {monitor_path}")
        env = os.environ.copy()
        env["PACKETGUARD_MONITOR_PROC"] = "1"   # prevents recursive launch
        env["PYTHONUTF8"] = "1"                  # force UTF-8 to prevent cp1252 crash
        env["PYTHONIOENCODING"] = "utf-8"        # belt and suspenders
        proc = subprocess.Popen(
            [sys.executable, "-X", "utf8", monitor_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=env,
            # Detach so the subprocess is NOT killed when Flask reloads
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0,
        )
        print(f"[LIVE-MONITOR] PID {proc.pid} capturing on Wi-Fi — alerts.json updating live.")
        # Store PID so we can check it's still alive (no restart loop — just log if dead)
        with open(os.path.join(os.path.dirname(monitor_path), ".monitor.pid"), "w") as _pf:
            _pf.write(str(proc.pid))
    except Exception as _e:
        print(f"[LIVE-MONITOR] Could not launch subprocess: {_e}")

threading.Thread(target=_auto_start_live_monitor, daemon=True, name="LiveMonitor").start()
=======
MODELS_DIR       = os.path.join(BASE_DIR, "models")
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b

# ── Auto-scan state ────────────────────────────────────────────────
_scan_status = {
    "running": False,
    "last_scan": None,
    "next_scan": None,
    "device_count": 0,
}
SCAN_INTERVAL = 20  # seconds between scans

<<<<<<< HEAD
# Cache the network_scanner module — import ONCE, reuse forever.
# Re-importing every 10 seconds causes a multi-second gap where network_devices.json
# is empty and the frontend shows "Scanning network..." and blanks the device list.
_network_scanner_mod = None

def _get_network_scanner():
    """Import network_scanner once and cache it. Returns the module or None."""
    global _network_scanner_mod
    if _network_scanner_mod is not None:
        return _network_scanner_mod
    try:
        scanner_path = os.path.join(BASE_DIR, "code", "network_scanner.py")
        if not os.path.exists(scanner_path):
            print(f"[AUTO-SCAN] Scanner not found at {scanner_path}")
            return None
        import importlib.util
        spec = importlib.util.spec_from_file_location("network_scanner", scanner_path)
        mod  = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _network_scanner_mod = mod
        return mod
    except Exception as e:
        print(f"[AUTO-SCAN] Failed to load network_scanner: {e}")
        return None

=======
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b

def run_network_scan():
    """Run the network scanner in the background."""
    global _scan_status
<<<<<<< HEAD
    try:
        mod = _get_network_scanner()
        if mod is None:
            return
        devices = mod.scan_network()
        _scan_status["last_scan"]    = datetime.now().isoformat()
        _scan_status["device_count"] = len(devices) if devices else 0
        print(f"[AUTO-SCAN] Done — {_scan_status['device_count']} device(s) found at {_scan_status['last_scan']}")
=======
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

>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
    except Exception as e:
        print(f"[AUTO-SCAN] Error: {e}")
    finally:
        _scan_status["running"] = False
        _scan_status["next_scan"] = (
            datetime.fromtimestamp(time.time() + SCAN_INTERVAL).isoformat()
        )


def auto_scan_loop():
<<<<<<< HEAD
    # _do_first_scan already ran — just keep looping every SCAN_INTERVAL
=======
    """Background thread: wait 3s for Flask to start, then scan every SCAN_INTERVAL seconds."""
    print(f"[AUTO-SCAN] Starting background scanner (interval={SCAN_INTERVAL}s) ...")
    time.sleep(3)  # Wait for Flask to fully start
    run_network_scan_with_history()
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
    while True:
        time.sleep(SCAN_INTERVAL)
        run_network_scan_with_history()


<<<<<<< HEAD
# Thread is started later (after all functions defined) — see bottom of file
=======
# Start background scanner thread when module loads
_scanner_thread = threading.Thread(target=auto_scan_loop, daemon=True)
_scanner_thread.start()
print("[AUTO-SCAN] Background scanner thread started.")
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b


# ── Data loaders ──────────────────────────────────────────────────

<<<<<<< HEAD
# ── WebSocket push helpers (called by live_monitor via import) ────
def push_alert(alert: dict):
    """Broadcast a new alert to all connected dashboard clients instantly."""
    try:
        socketio.emit("new_alert", alert)
    except Exception:
        pass


def push_live_stats(stats: dict):
    """Broadcast updated live stats to all connected dashboard clients."""
    try:
        socketio.emit("live_stats", stats)
    except Exception:
        pass


def _db_alerts():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def _ensure_alerts_table_wd():
    conn = _db_alerts()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_type  TEXT,
            severity    TEXT,
            source_ip   TEXT,
            dest_ip     TEXT,
            message     TEXT,
            timestamp   TEXT,
            extra       TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(timestamp)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_sev ON alerts(severity)")
    conn.commit()
    # One-time migration from alerts.json
    count = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    if count == 0 and os.path.exists(ALERTS_FILE):
        try:
            with open(ALERTS_FILE, "r", encoding="utf-8") as _f:
                old_alerts = json.load(_f)
            for a in old_alerts:
                known = {"alert_type","severity","source_ip","dest_ip","destination_ip","message","timestamp"}
                extra = {k: v for k, v in a.items() if k not in known}
                conn.execute(
                    "INSERT INTO alerts (alert_type,severity,source_ip,dest_ip,message,timestamp,extra) VALUES (?,?,?,?,?,?,?)",
                    (a.get("alert_type"), a.get("severity"), a.get("source_ip"),
                     a.get("dest_ip") or a.get("destination_ip"), a.get("message"),
                     a.get("timestamp"), json.dumps(extra, default=str) if extra else None)
                )
            conn.commit()
            print(f"[DB] Migrated {len(old_alerts)} alerts from alerts.json to SQLite")
        except Exception as _me:
            print(f"[DB] Migration skipped: {_me}")
    conn.close()


def _alert_row_to_dict(r):
    a = dict(r)
    if a.get("extra"):
        try: a.update(json.loads(a["extra"]))
        except: pass
    a.pop("extra", None)
    a.pop("id", None)
    return a


def load_alerts():
    try:
        conn = _db_alerts()
        rows = conn.execute("SELECT * FROM alerts ORDER BY id ASC").fetchall()
        conn.close()
        return [_alert_row_to_dict(r) for r in rows]
    except Exception:
        try:
            with open(ALERTS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []

_ml_alerts_cache = []  # last known good ML alerts

def load_ml_alerts():
    global _ml_alerts_cache
    # Primary: read from live_state.json
    try:
        with open(LIVE_STATE_FILE, "r", encoding="utf-8") as f:
            state = json.load(f)
        alerts = state.get("ml_recent_alerts", [])
        if alerts:
            _ml_alerts_cache = alerts
            return alerts
    except Exception:
        pass
    # Fallback: try ml_alerts.json
    try:
        with open(ML_ALERTS_FILE, "r", encoding="utf-8") as f:
            result = json.load(f)
            if result:
                _ml_alerts_cache = result
            return result
    except Exception:
        pass
    # Last resort: return cache so we never 500
    return _ml_alerts_cache

def load_devices():
    """Return all devices from the last scan.
    Always reads fresh from disk so disconnected devices disappear immediately."""
    try:
        with open(DEVICES_FILE, "r", encoding="utf-8") as f:
            raw = f.read().strip()
        if not raw:
            raise ValueError("empty")
        data = json.loads(raw)
        devs = data.get("devices", [])
        data["total_found"] = len(devs)
        return data
    except Exception:
        return {"devices": [], "network_range": "N/A", "local_ip": "N/A"}


def _ensure_live_state():
    """Reset packet counters in live_state.json on every startup.
    Keeps recent_alerts so the feed is not blanked on restart."""
    try:
        prev_alerts = []
        if os.path.exists(LIVE_STATE_FILE):
            try:
                with open(LIVE_STATE_FILE, "r", encoding="utf-8") as f:
                    old = json.load(f)
                prev_alerts = old.get("recent_alerts", [])
            except Exception:
                pass
        fresh = {
            "total_packets": 0, "rate": 0.0, "bytes_total": 0,
            "runtime_seconds": 0, "running": False,
            "protocols": {}, "top_ips": {},
            "recent_alerts": prev_alerts,
            "last_updated": None,
        }
        with open(LIVE_STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(fresh, f, indent=2)
    except Exception:
        pass

_ensure_live_state()   # run once on startup

_live_stats_cache = {}  # last known good stats - never return zeros once we have real data

def load_live_stats():
    global _live_stats_cache
    try:
        with open(LIVE_STATE_FILE, "r", encoding="utf-8") as f:
            raw = f.read().strip()
        if not raw:
            raise ValueError("empty file")
        s = json.loads(raw)
        rule_alerts = load_alerts()
        ml_alerts   = load_ml_alerts()
        suspicious  = len(rule_alerts) + len(ml_alerts)
        result = {
            "total_packets":    s.get("total_packets", 0),
=======
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
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
            "packets":          s.get("total_packets", 0),
            "rate":             s.get("rate", 0.0),
            "bytes_total":      s.get("bytes_total", 0),
            "runtime_seconds":  s.get("runtime_seconds", 0),
            "running":          s.get("running", False),
            "protocols":        s.get("protocols", {}),
            "top_ips":          s.get("top_ips", {}),
            "recent_alerts":    s.get("recent_alerts", []),
            "last_updated":     s.get("last_updated", None),
<<<<<<< HEAD
            "suspicious_count": suspicious,
        }
        # Never let total_packets go down — only increase
        if result["total_packets"] < _live_stats_cache.get("total_packets", 0):
            result["total_packets"] = _live_stats_cache["total_packets"]
            result["packets"]       = _live_stats_cache["total_packets"]
        _live_stats_cache = dict(result)
        return result
    except Exception:
        # File empty, mid-write, or corrupt - serve last known good data
        if _live_stats_cache:
            return dict(_live_stats_cache)
        return {"total_packets": 0, "packets": 0, "rate": 0.0, "bytes_total": 0,
                "runtime_seconds": 0, "running": False, "suspicious_count": 0,
=======
        }
    except Exception:
        return {"packets": 0, "rate": 0.0, "bytes_total": 0,
                "runtime_seconds": 0, "running": False,
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
                "protocols": {}, "top_ips": {}, "recent_alerts": []}


def load_model_info():
<<<<<<< HEAD
    """
    Return model metadata for the dashboard Model Performance panel.
    Merges data from model_metadata.json (written by train_cicids.py v2
    or train_ml.py) with live detector status from ml_detector.get_detector().
    """
    info = {
        "trained":      False,
        "samples":      0,
        "precision":    None,
        "recall":       None,
        "f1":           None,
        # v2 extras
        "winner_model": None,
        "cv_f1_mean":   None,
        "cv_f1_std":    None,
        "per_class_f1": {},
        "classes":      [],
        "dataset":      None,
        "accuracy":     None,
    }
    try:
=======
    info = {"trained": False, "samples": 0, "precision": None, "recall": None, "f1": None}
    try:
        # Try multiple possible locations for the models folder
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
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
<<<<<<< HEAD
                # Also check whether cicids_rf.pkl exists (supervised model)
                rf = os.path.join(models_dir, "cicids_rf.pkl")
                info["cicids_trained"] = os.path.exists(rf)
=======
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
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
<<<<<<< HEAD
    # Read ml_recent_alerts from live_state.json.
    # Use load_ml_alerts() which already has fallback logic and never raises 500.
    try:
        alerts = load_ml_alerts()
        return Response(json.dumps(alerts, ensure_ascii=False, default=str), mimetype="application/json")
    except Exception:
        return Response(json.dumps([]), mimetype="application/json")


@app.route("/api/ml_status")
def api_ml_status():
    """
    Live ML detector status — polled by the dashboard ML panel.

    Returns:
      ready          bool    – at least one model is loaded
      models_loaded  list    – e.g. ["cicids_rf", "isolation_forest"]
      active_flows   int     – flows currently buffered by the aggregator
      flow_timeout   float   – seconds before a flow is finalised
      max_flow_pkts  int     – hard cap on packets per flow
      iso_threshold  float   – anomaly score cut-off
      min_conf       float   – minimum fused confidence to fire an alert
      model_info     dict    – metadata from model_metadata.json (same as
                               stats.model) so callers have one endpoint
    """
    try:
        from ml_detector import get_detector
        det    = get_detector()
        status = det.status()
    except Exception as e:
        status = {"ready": False, "error": str(e), "models_loaded": [],
                  "active_flows": 0, "flow_timeout": 5, "max_flow_pkts": 50,
                  "iso_threshold": -0.1, "min_conf": 0.55}

    status["model_info"] = load_model_info()
    return jsonify(status)


_device_cache = {"data": None}  # never return [] mid-scan


@app.route("/api/devices")
def api_devices():
    data = load_devices()
    return jsonify(data)
=======
    return jsonify(load_ml_alerts())

@app.route("/api/devices")
def api_devices():
    return jsonify(load_devices())
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b

@app.route("/api/scan_status")
def api_scan_status():
    return jsonify(_scan_status)


@app.route("/api/network_info")
def api_network_info():
<<<<<<< HEAD
    """Return the real local IP, network range, and gateway IP for the monitor page."""
    import socket, subprocess, re
=======
    """Return the real local IP and network range for the monitor page."""
    import socket, struct
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        local_ip = "127.0.0.1"
    parts = local_ip.split(".")
    network_range = ".".join(parts[:3]) + ".0/24"
<<<<<<< HEAD
    # Auto-detect gateway IP
    gateway_ip = None
    try:
        import platform
        if platform.system() == "Windows":
            out = subprocess.check_output("ipconfig", shell=True).decode(errors="ignore")
            m = re.search(r"Default Gateway[^\d]*(\d+\.\d+\.\d+\.\d+)", out)
            if m:
                gateway_ip = m.group(1)
        else:
            out = subprocess.check_output("ip route", shell=True).decode(errors="ignore")
            m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", out)
            if m:
                gateway_ip = m.group(1)
    except Exception:
        pass
=======
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
    # Also pull from saved scan if available
    devices_data = load_devices()
    saved_ip    = devices_data.get("local_ip", local_ip)
    saved_range = devices_data.get("network_range", network_range)
    return jsonify({
        "local_ip":      saved_ip    if saved_ip    != "N/A" else local_ip,
        "network_range": saved_range if saved_range != "N/A" else network_range,
<<<<<<< HEAD
        "gateway_ip":    gateway_ip,
=======
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
    })

@app.route("/api/live_state")
def api_live_state():
    """Return full live monitor state — polled every 2s by dashboard."""
    return jsonify(load_live_stats())


<<<<<<< HEAD
@app.route("/api/interfaces")
def api_interfaces():
    """Return available network interfaces and which one is active."""
    try:
        import psutil, socket as _socket
        ifaces = []
        stats  = psutil.net_if_stats()
        addrs  = psutil.net_if_addrs()
        for name, iaddrs in addrs.items():
            for addr in iaddrs:
                if addr.family != _socket.AF_INET:
                    continue
                ifaces.append({
                    "name":   name,
                    "ip":     addr.address,
                    "is_up":  stats[name].isup if name in stats else False,
                    "speed":  stats[name].speed if name in stats else 0,
                })
        try:
            import live_monitor as _lm
            active = _lm.get_interface()
        except Exception:
            active = None
        return jsonify({"interfaces": ifaces, "active": active})
    except Exception as e:
        return jsonify({"interfaces": [], "active": None, "error": str(e)})


=======
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
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

<<<<<<< HEAD
# ── Role-Based Access Control ─────────────────────────────────────
try:
    from access_control import require_login, require_role, require_permission, \
        get_all_users, set_user_role, delete_user, ROLE_LEVEL
    print("[RBAC] Access control module loaded.")
except ImportError:
    # Graceful no-op fallbacks so the app still starts if file is missing
    def require_login(f): return f
    def require_role(r):
        def d(f): return f
        return d
    def require_permission(p):
        def d(f): return f
        return d
    print("[RBAC] access_control.py not found — running without RBAC.")

# ── Password hashing: werkzeug (bundled with Flask) ───────────────
# We use werkzeug.security instead of bcrypt to avoid version-mismatch
# crashes. werkzeug is ALWAYS installed alongside Flask (it's a hard
# dependency), so this can never fail.
try:
    from werkzeug.security import generate_password_hash, check_password_hash
    _USE_WERKZEUG = True
    print("[AUTH] Using werkzeug password hashing (pbkdf2:sha256).")
except ImportError:
    _USE_WERKZEUG = False
    print("[AUTH] Werkzeug not found — falling back to hashlib pbkdf2.")

DB_PATH = os.path.join(BASE_DIR, "packetguard.db")

def _db():
    # timeout=15  → wait up to 15s instead of instantly failing with "database is locked"
    # WAL mode    → allows concurrent reads while baseline_learning/auto_response write
    conn = sqlite3.connect(DB_PATH, timeout=5)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
=======
DB_PATH = os.path.join(BASE_DIR, "packetguard.db")

def _db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
    return conn

def _init_db():
    conn = _db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            name       TEXT NOT NULL,
            email      TEXT NOT NULL UNIQUE,
            password   TEXT NOT NULL,
<<<<<<< HEAD
            role       TEXT NOT NULL DEFAULT 'analyst',
=======
            role       TEXT NOT NULL DEFAULT 'user',
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
            created_at TEXT NOT NULL,
            last_login TEXT
        )
    """)
    conn.commit()
<<<<<<< HEAD
    _ensure_alerts_table_wd()  # ensure alerts table + migrate JSON
    # Check if default admin exists
    row = conn.execute("SELECT id, password FROM users WHERE email='admin@packetguard.io'").fetchone()
    if not row:
        # No admin at all — create fresh
        conn.execute(
            "INSERT INTO users (name,email,password,role,created_at) VALUES (?,?,?,?,?)",
            ("Admin", "admin@packetguard.io", _hash("admin123"), "admin", datetime.utcnow().isoformat())
        )
        conn.commit()
        print("[AUTH] Default admin created: admin@packetguard.io / admin123")
    elif row["password"].startswith("$2"):
        # Admin exists but has a legacy bcrypt hash — re-hash it now
        # so the first login doesn't crash if bcrypt module is broken
        conn.execute("UPDATE users SET password=? WHERE id=?", (_hash("admin123"), row["id"]))
        conn.commit()
        print("[AUTH] Default admin password migrated from bcrypt → werkzeug.")
    conn.close()

def _hash(pw):
    """Hash password using werkzeug (pbkdf2:sha256) or hashlib fallback."""
    if _USE_WERKZEUG:
        return generate_password_hash(pw, method="pbkdf2:sha256")
    # Pure-stdlib fallback: pbkdf2_hmac
    salt = secrets.token_hex(16)
    dk   = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 260000)
    return f"pbkdf2$sha256${salt}${dk.hex()}"

def _verify(pw, stored):
    """
    Verify password against stored hash.
    Handles 3 formats:
      1. werkzeug   → "pbkdf2:sha256:..."   (new default)
      2. stdlib     → "pbkdf2$sha256$..."   (fallback)
      3. bcrypt     → "$2b$..."             (legacy — attempt bcrypt import)
    Returns False (not a crash) for any error.
    """
    try:
        # ── werkzeug format ────────────────────────────────────────
        if stored.startswith("pbkdf2:"):
            if _USE_WERKZEUG:
                return check_password_hash(stored, pw)
            return False  # can't verify without werkzeug

        # ── stdlib pbkdf2 format ───────────────────────────────────
        if stored.startswith("pbkdf2$"):
            parts = stored.split("$")   # pbkdf2 $ sha256 $ salt $ hex
            if len(parts) != 4:
                return False
            _, _algo, salt, stored_hex = parts
            dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 260000)
            return dk.hex() == stored_hex

        # ── legacy bcrypt format ───────────────────────────────────
        if stored.startswith("$2"):
            try:
                import bcrypt as _bcrypt
                return _bcrypt.checkpw(pw.encode(), stored.encode())
            except ImportError:
                print("[AUTH] bcrypt not installed — cannot verify legacy hash. "
                      "Reset the password to fix.")
                return False
            except Exception as e:
                print(f"[AUTH] bcrypt verify error: {e}")
                return False

        # Unknown format
        print(f"[AUTH] Unknown hash format: {stored[:12]}...")
        return False

    except Exception as e:
        print(f"[AUTH] _verify unexpected error: {e}")
        return False
=======
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
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b

_init_db()


@app.route("/api/auth/register", methods=["POST"])
def api_register():
    data  = _req.get_json() or {}
    name  = data.get("name","").strip()
    email = data.get("email","").strip().lower()
    pw    = data.get("password","")
<<<<<<< HEAD
    otp   = data.get("otp","").strip()
    conn  = _db()
    try:
        if not otp:
            # Step 1: validate input, create account, send OTP
            if not name or not email or not pw:
                return jsonify({"success": False, "error": "All fields required."})
            if len(pw) < 6:
                return jsonify({"success": False, "error": "Password must be at least 6 characters."})
            try:
                hashed = _hash(pw)
            except Exception as _he:
                return jsonify({"success": False, "error": "Server error during registration."})
            try:
                conn.execute(
                    "INSERT INTO users (name,email,password,role,created_at) VALUES (?,?,?,?,?)",
                    (name, email, hashed, "analyst", datetime.utcnow().isoformat())
                )
                conn.commit()
            except sqlite3.IntegrityError:
                return jsonify({"success": False, "error": "Email already registered."})
            # Generate and send OTP
            code = str(_random.randint(100000, 999999))
            with _otp_lock:
                _otp_store["reg_" + email] = {
                    "otp":     code,
                    "expires": _time2fa.time() + 300,
                    "email":   email,
                    "name":    name,
                }
            sent = _send_otp_email(email, code, name)
            if not sent:
                # SMTP failed — complete registration without OTP
                print(f"[AUTH] SMTP unavailable during registration for {email}")
                with _otp_lock: _otp_store.pop("reg_" + email, None)
                _sess.permanent     = True
                _sess["user_id"]    = user_id
                _sess["user_name"]  = name
                _sess["user_email"] = email
                _sess["user_role"]  = "analyst"
                _sess.modified      = True
                return jsonify({"success": True, "user": {"name": name, "email": email, "role": "analyst"}})
            return jsonify({"success": False, "require_otp": True, "message": f"OTP sent to {email}"})
        else:
            # Step 2: verify OTP and log user in
            with _otp_lock:
                record = _otp_store.get("reg_" + email)
            if not record:
                return jsonify({"success": False, "error": "No OTP pending. Please register again."})
            if _time2fa.time() > record["expires"]:
                with _otp_lock: _otp_store.pop("reg_" + email, None)
                return jsonify({"success": False, "error": "OTP expired. Please register again."})
            if otp != record["otp"]:
                return jsonify({"success": False, "error": "Invalid OTP code. Try again."})
            with _otp_lock: _otp_store.pop("reg_" + email, None)
            row = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
            if not row:
                return jsonify({"success": False, "error": "Account not found. Please register again."})
            _sess.permanent     = True
            _sess["user_id"]    = row["id"]
            _sess["user_name"]  = row["name"]
            _sess["user_email"] = row["email"]
            _sess["user_role"]  = row["role"]
            _sess.modified      = True
            return jsonify({"success": True, "user": {"name": row["name"], "email": row["email"], "role": row["role"]}})
    except Exception as _e:
        print(f"[AUTH] Register error: {_e}")
        return jsonify({"success": False, "error": "Server error during registration."}), 500
=======
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
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
    finally:
        conn.close()


<<<<<<< HEAD
# ── 2FA OTP store ────────────────────────────────────────────────
import random as _random, smtplib as _smtplib, time as _time2fa
from email.mime.text import MIMEText as _MIMEText
from email.mime.multipart import MIMEMultipart as _MIMEMultipart
import threading as _threading2fa

_otp_store = {}
_otp_lock  = _threading2fa.Lock()

# ── Gmail SMTP config ─────────────────────────────────────────────
# Set these via environment variables (recommended) or edit directly.
# For Gmail, SMTP_PASSWORD must be a 16-character App Password — NOT
# your regular Gmail password. Generate one at:
#   https://myaccount.google.com/apppasswords
#   (Requires 2-Step Verification to be enabled on the account)
import os as _os
SMTP_EMAIL    = _os.environ.get("SMTP_EMAIL",    "packetguard.sys@gmail.com")
SMTP_PASSWORD = _os.environ.get("SMTP_PASSWORD", "")   # <-- set via env var or paste App Password here

def _send_otp_email(to_email, otp, name):
    if not SMTP_PASSWORD:
        print("[2FA] SMTP_PASSWORD is not set. Set the SMTP_PASSWORD environment variable "
              "or paste your Gmail App Password into web_dashboard.py.")
        return False
    try:
        msg = _MIMEMultipart("alternative")
        msg["Subject"] = "PacketGuard — Your Login Code"
        msg["From"]    = f"PacketGuard Security <{SMTP_EMAIL}>"
        msg["To"]      = to_email
        html = f"""<div style="font-family:monospace;background:#060e18;color:#c0d4ee;padding:32px;border-radius:12px;max-width:480px;margin:auto;border:1px solid rgba(0,200,255,.2)">
          <div style="color:#00c8ff;font-size:18px;font-weight:700;letter-spacing:3px;margin-bottom:8px">PACKETGUARD</div>
          <div style="color:#3a5570;font-size:11px;margin-bottom:24px">Network Threat Detection System</div>
          <div style="margin-bottom:16px">Hello <b style="color:#fff">{name}</b>,</div>
          <div style="margin-bottom:24px;color:#a0b4c8">Your one-time login code:</div>
          <div style="background:#0d1117;border:2px solid rgba(0,200,255,.3);border-radius:10px;padding:20px;text-align:center;margin-bottom:24px">
            <div style="font-size:36px;font-weight:700;letter-spacing:10px;color:#00c8ff">{otp}</div>
            <div style="color:#3a5570;font-size:11px;margin-top:8px">Valid for 5 minutes</div>
          </div>
          <div style="color:#3a5570;font-size:11px">If you did not request this, ignore this email.</div>
        </div>"""
        msg.attach(_MIMEText(html, "html"))
        with _smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.ehlo(); server.starttls()
            server.login(SMTP_EMAIL, SMTP_PASSWORD)
            server.sendmail(SMTP_EMAIL, to_email, msg.as_string())
        print(f"[2FA] OTP sent to {to_email}")
        return True
    except Exception as e:
        print(f"[2FA] Email error: {e}")
        return False

=======
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
@app.route("/api/auth/login", methods=["POST"])
def api_login():
    data  = _req.get_json() or {}
    email = data.get("email","").strip().lower()
    pw    = data.get("password","")
<<<<<<< HEAD
    otp   = data.get("otp","").strip()
    conn  = _db()
    try:
        row = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if not row:
            return jsonify({"success": False, "error": "Invalid email or password."})
        try:
            valid = _verify(pw, row["password"])
        except Exception as _ve:
            print(f"[AUTH] verify error: {_ve}")
            return jsonify({"success": False, "error": "Authentication error."})
        if not valid:
            return jsonify({"success": False, "error": "Invalid email or password."})
        if row["password"].startswith("$2"):
            try:
                conn.execute("UPDATE users SET password=? WHERE id=?", (_hash(pw), row["id"]))
            except Exception: pass
        if not otp:
            # Step 1: try OTP — if SMTP fails, log in directly with no error
            code = str(_random.randint(100000, 999999))
            with _otp_lock:
                _otp_store[email] = {"otp": code, "expires": _time2fa.time() + 300, "row": dict(row)}
            sent = _send_otp_email(row["email"], code, row["name"])
            if not sent:
                print(f"[AUTH] SMTP unavailable, logging in {email} directly")
                with _otp_lock: _otp_store.pop(email, None)
                try:
                    conn.execute("UPDATE users SET last_login=? WHERE id=?", (datetime.utcnow().isoformat(), row["id"]))
                    conn.commit()
                except Exception: pass
                _sess.permanent     = True
                _sess["user_id"]    = row["id"]
                _sess["user_name"]  = row["name"]
                _sess["user_email"] = row["email"]
                _sess["user_role"]  = row["role"]
                _sess.modified      = True
                return jsonify({"success": True, "user": {"name": row["name"], "email": row["email"], "role": row["role"]}})
            return jsonify({"success": False, "require_otp": True, "message": f"OTP sent to {row['email']}"})
        else:
            # Step 2: verify OTP
            with _otp_lock:
                record = _otp_store.get(email)
            if not record:
                return jsonify({"success": False, "error": "No OTP pending. Please start login again."})
            if _time2fa.time() > record["expires"]:
                with _otp_lock: _otp_store.pop(email, None)
                return jsonify({"success": False, "error": "OTP expired. Please login again."})
            if otp != record["otp"]:
                return jsonify({"success": False, "error": "Invalid OTP code. Try again."})
            with _otp_lock: _otp_store.pop(email, None)
            saved = record["row"]
            try:
                conn.execute("UPDATE users SET last_login=? WHERE id=?", (datetime.utcnow().isoformat(), saved["id"]))
                conn.commit()
            except Exception: pass
            _sess.permanent     = True
            _sess["user_id"]    = saved["id"]
            _sess["user_name"]  = saved["name"]
            _sess["user_email"] = saved["email"]
            _sess["user_role"]  = saved["role"]
            _sess.modified      = True
            return jsonify({"success": True, "user": {"name": saved["name"], "email": saved["email"], "role": saved["role"]}})
    except Exception as _e:
        print(f"[AUTH] Login error: {_e}")
        return jsonify({"success": False, "error": "Server error during login."}), 500
    finally:
        conn.close()

=======
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


>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
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


<<<<<<< HEAD
@app.route("/api/auth/profile", methods=["GET"])
def api_profile():
    if "user_id" not in _sess:
        return jsonify({"success": False, "error": "Not logged in"}), 401
    created_at = ""
    last_login = ""
    try:
        conn = _db()
        row  = conn.execute("SELECT created_at, last_login FROM users WHERE id=?",
                            (_sess["user_id"],)).fetchone()
        conn.close()
        if row:
            created_at = row["created_at"] or ""
            last_login  = row["last_login"]  or ""
    except Exception:
        pass
    return jsonify({"success": True, "user": {
        "id":         _sess["user_id"],
        "name":       _sess.get("user_name",  ""),
        "email":      _sess.get("user_email", ""),
        "role":       _sess.get("user_role",  "user"),
        "created_at": created_at,
        "last_login":  last_login,
    }})


@app.route("/api/auth/profile/update", methods=["POST"])
def api_profile_update():
    if "user_id" not in _sess:
        return jsonify({"success": False, "error": "Not logged in"}), 401
    data = request.get_json() or {}
    name = data.get("name", "").strip()
    if not name or len(name) < 2:
        return jsonify({"success": False, "error": "Name must be at least 2 characters."}), 400
    conn = _db()
    try:
        conn.execute("UPDATE users SET name = ? WHERE id = ?", (name, _sess["user_id"]))
        conn.commit()
        _sess["user_name"] = name
        _sess.modified = True
    finally:
        conn.close()
    return jsonify({"success": True, "message": "Profile updated."})


@app.route("/api/auth/change-password", methods=["POST"])
def api_change_password():
    if "user_id" not in _sess:
        return jsonify({"success": False, "error": "Not logged in"}), 401
    data = request.get_json() or {}
    current = data.get("current_password", "").strip()
    new_pw  = data.get("new_password", "").strip()
    confirm = data.get("confirm_password", "").strip()
    if not current or not new_pw or not confirm:
        return jsonify({"success": False, "error": "All fields are required."}), 400
    if new_pw != confirm:
        return jsonify({"success": False, "error": "New passwords do not match."}), 400
    if len(new_pw) < 6:
        return jsonify({"success": False, "error": "New password must be at least 6 characters."}), 400
    if current == new_pw:
        return jsonify({"success": False, "error": "New password must differ from current."}), 400
    conn2 = _db()
    try:
        row = conn2.execute("SELECT * FROM users WHERE id=?", (_sess["user_id"],)).fetchone()
        if not row or not _verify(current, row["password"]):
            return jsonify({"success": False, "error": "Current password is incorrect."}), 403
        conn2.execute("UPDATE users SET password = ? WHERE id = ?",
                     (_hash(new_pw), _sess["user_id"]))
        conn2.commit()
    finally:
        conn2.close()
    print(f"[AUTH] Password changed for: {_sess.get('user_email')}")
    return jsonify({"success": True, "message": "Password changed successfully."})


@app.route("/profile")
def profile_page():
    # Auth is handled client-side via /api/auth/profile (401 → redirect to /)
    return PROFILE_HTML


@app.route("/change-password")
def change_password_page():
    from flask import redirect
    return redirect("/profile")


# ── HTML ──────────────────────────────────────────────────────────

PROFILE_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>My Profile — PacketGuard</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700;800&family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css"/>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#07090f;--surface:#0d1117;--surface2:#111827;--surface3:#161f30;
  --border:rgba(0,200,255,.12);--border2:rgba(0,200,255,.22);
  --accent:#00c8ff;--accent2:#ff2d55;--accent3:#00ff88;--purple:#9d6fff;--gold:#f5a623;
  --text:#e2e8f0;--dim:#4b6070;--dim2:#64748b;
  --mono:'JetBrains Mono',monospace;--sans:'Inter',sans-serif;
  --glow:0 0 20px rgba(0,200,255,.15);
}
body{background:var(--bg);color:var(--text);font-family:var(--sans);min-height:100vh;display:flex;flex-direction:column;font-size:14px;line-height:1.6}

/* ── HEADER ── */
header{display:flex;align-items:center;gap:16px;padding:12px 28px;background:rgba(13,17,23,.98);border-bottom:1px solid var(--border);backdrop-filter:blur(20px);position:sticky;top:0;z-index:100}
.logo-mark{width:38px;height:38px;background:linear-gradient(135deg,#00c8ff,#9d6fff);border-radius:9px;display:flex;align-items:center;justify-content:center;font-family:var(--mono);font-weight:800;font-size:13px;color:#07090f;letter-spacing:-1px;flex-shrink:0}
.logo-text h1{font-family:var(--mono);font-size:14px;font-weight:700;letter-spacing:2px;color:var(--text)}
.logo-text span{font-family:var(--mono);font-size:9px;color:var(--dim2);letter-spacing:2px;text-transform:uppercase}
.hdr-right{margin-left:auto;display:flex;align-items:center;gap:8px}
.nav-btn{padding:6px 16px;border-radius:6px;font-family:var(--mono);font-size:10px;font-weight:600;letter-spacing:1.5px;color:var(--dim2);text-decoration:none;border:1px solid var(--border);background:transparent;transition:all .2s;cursor:pointer;white-space:nowrap}
.nav-btn:hover{color:var(--accent);border-color:var(--accent);background:rgba(0,200,255,.05)}
.nav-btn.danger:hover{color:var(--accent2);border-color:var(--accent2);background:rgba(255,45,85,.05)}

/* ── LAYOUT ── */
.page{flex:1;max-width:1000px;margin:0 auto;width:100%;padding:32px 20px;display:grid;grid-template-columns:260px 1fr;gap:20px;align-items:start}
@media(max-width:740px){.page{grid-template-columns:1fr}}

/* ── CARD ── */
.card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:24px;position:relative;overflow:hidden}
.card::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,var(--accent),transparent)}
.card-label{font-family:var(--mono);font-size:9px;letter-spacing:3px;color:var(--dim2);text-transform:uppercase;margin-bottom:18px;display:flex;align-items:center;gap:10px}
.card-label::after{content:'';flex:1;height:1px;background:var(--border)}

/* ── SIDEBAR ── */
.avatar-wrap{display:flex;flex-direction:column;align-items:center;margin-bottom:20px}
.avatar-ring{width:90px;height:90px;border-radius:50%;background:linear-gradient(135deg,rgba(0,200,255,.1),rgba(157,111,255,.1));border:1px solid rgba(0,200,255,.25);display:flex;align-items:center;justify-content:center;margin-bottom:14px;font-family:var(--mono);font-weight:800;font-size:32px;color:var(--accent);position:relative;box-shadow:var(--glow)}
.online-dot{position:absolute;bottom:5px;right:5px;width:12px;height:12px;border-radius:50%;background:var(--accent3);border:2px solid var(--surface);animation:pulse 2s infinite}
@keyframes pulse{0%,100%{box-shadow:0 0 0 0 rgba(0,255,136,.4)}50%{box-shadow:0 0 0 5px rgba(0,255,136,0)}}
.user-name{font-family:var(--mono);font-size:15px;font-weight:700;color:var(--text);margin-bottom:4px;text-align:center;letter-spacing:.5px}
.user-email{font-family:var(--mono);font-size:10px;color:var(--dim2);text-align:center;margin-bottom:12px;word-break:break-all}
.role-badge{display:inline-flex;align-items:center;gap:5px;padding:4px 12px;border-radius:20px;font-family:var(--mono);font-size:10px;font-weight:700;letter-spacing:2px;text-transform:uppercase}
.role-badge.admin{background:rgba(0,200,255,.08);border:1px solid rgba(0,200,255,.3);color:var(--accent)}
.role-badge.user{background:rgba(157,111,255,.08);border:1px solid rgba(157,111,255,.3);color:var(--purple)}

/* ── STAT BOXES ── */
.stat-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin:18px 0}
.stat-box{background:var(--surface2);border:1px solid var(--border);border-radius:9px;padding:12px 10px;text-align:center}
.stat-val{font-family:var(--mono);font-size:12px;font-weight:700;color:var(--accent);margin-bottom:3px}
.stat-lbl{font-family:var(--mono);font-size:8px;color:var(--dim2);letter-spacing:2px;text-transform:uppercase}

/* ── SIDEBAR ACTIONS ── */
.sidebar-nav{display:flex;flex-direction:column;gap:6px;margin-top:6px}
.snav-btn{width:100%;padding:10px 14px;border-radius:8px;font-family:var(--mono);font-size:10px;font-weight:600;letter-spacing:1.5px;cursor:pointer;transition:all .2s;text-align:left;display:flex;align-items:center;gap:10px;border:1px solid transparent;background:transparent;color:var(--dim2)}
.snav-btn:hover{color:var(--text);background:var(--surface2);border-color:var(--border)}
.snav-btn.active{color:var(--accent);background:rgba(0,200,255,.07);border-color:rgba(0,200,255,.2)}
.snav-btn.danger-btn{color:var(--accent2)!important;border-color:rgba(255,45,85,.2)!important;background:rgba(255,45,85,.04)!important}
.snav-btn .ico{width:16px;text-align:center;font-size:13px}

/* ── TABS ── */
.section{display:none}.section.active{display:block}

/* ── FORM ELEMENTS ── */
.field{margin-bottom:16px}
.field label{display:block;font-family:var(--mono);font-size:9px;font-weight:600;letter-spacing:2.5px;color:var(--dim2);text-transform:uppercase;margin-bottom:7px}
.field input{width:100%;background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:10px 14px;font-family:var(--mono);font-size:12px;color:var(--text);outline:none;transition:border-color .2s}
.field input:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(0,200,255,.08)}
.field input[readonly]{color:var(--dim2);cursor:not-allowed}
.field .hint{font-family:var(--mono);font-size:9px;color:var(--dim);margin-top:5px;letter-spacing:.5px}

/* ── BUTTONS ── */
.btn{padding:10px 22px;border-radius:8px;font-family:var(--mono);font-size:10px;font-weight:700;letter-spacing:2px;cursor:pointer;transition:all .2s;border:none;text-transform:uppercase}
.btn-primary{background:linear-gradient(135deg,rgba(0,200,255,.15),rgba(157,111,255,.15));border:1px solid rgba(0,200,255,.35);color:var(--accent)}
.btn-primary:hover{background:linear-gradient(135deg,rgba(0,200,255,.25),rgba(157,111,255,.25));box-shadow:var(--glow)}
.btn-danger{background:rgba(255,45,85,.08);border:1px solid rgba(255,45,85,.3);color:var(--accent2)}
.btn-danger:hover{background:rgba(255,45,85,.15)}

/* ── PW STRENGTH ── */
.pw-bar-wrap{height:3px;background:var(--surface3);border-radius:4px;margin-top:6px;overflow:hidden}
.pw-bar{height:100%;width:0;border-radius:4px;transition:width .3s,background .3s}
.pw-fields{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.pw-input-wrap{position:relative}
.pw-input-wrap input{width:100%;padding-right:40px}
.pw-eye{position:absolute;right:10px;top:50%;transform:translateY(-50%);background:none;border:none;cursor:pointer;color:var(--dim2);font-size:13px;padding:2px}

/* ── INFO TABLE ── */
.info-table{width:100%;border-collapse:collapse}
.info-table tr{border-bottom:1px solid var(--border)}
.info-table tr:last-child{border-bottom:none}
.info-table td{padding:11px 6px;font-family:var(--mono);font-size:11px}
.info-table td:first-child{color:var(--dim2);font-size:10px;letter-spacing:1px;width:38%}
.info-table td:last-child{color:var(--text);font-weight:500}
.badge-val{display:inline-flex;align-items:center;gap:5px;padding:3px 10px;border-radius:12px;font-size:9px;font-weight:700;letter-spacing:1.5px}
.badge-val.green{background:rgba(0,255,136,.08);border:1px solid rgba(0,255,136,.25);color:var(--accent3)}
.badge-val.blue{background:rgba(0,200,255,.08);border:1px solid rgba(0,200,255,.25);color:var(--accent)}
.badge-val.purple{background:rgba(157,111,255,.08);border:1px solid rgba(157,111,255,.25);color:var(--purple)}

/* ── MESSAGE ── */
.msg{font-family:var(--mono);font-size:10px;margin-top:10px;min-height:16px;letter-spacing:.5px}

/* ── TOAST ── */
.toast{position:fixed;bottom:24px;right:24px;padding:12px 20px;border-radius:8px;font-family:var(--mono);font-size:11px;font-weight:600;letter-spacing:1px;opacity:0;transform:translateY(10px);transition:all .3s;z-index:999;pointer-events:none;max-width:320px}
.toast.show{opacity:1;transform:translateY(0)}
.toast.success{background:#0d2b1a;border:1px solid rgba(0,255,136,.35);color:var(--accent3)}
.toast.error{background:#2b0d14;border:1px solid rgba(255,45,85,.35);color:var(--accent2)}
.toast.info{background:#0d1d2b;border:1px solid rgba(0,200,255,.35);color:var(--accent)}

footer{text-align:center;padding:20px;font-family:var(--mono);font-size:9px;color:var(--dim);letter-spacing:2px;border-top:1px solid var(--border)}

/* ── RBAC Role Badge (dashboard) ── */
.dash-role-badge{display:inline-flex;align-items:center;gap:5px;padding:3px 10px;border-radius:20px;font-family:var(--mono);font-size:10px;font-weight:700;letter-spacing:2px;text-transform:uppercase}
.dash-role-badge.admin{background:rgba(0,200,255,.08);border:1px solid rgba(0,200,255,.3);color:#00c8ff}
.dash-role-badge.analyst{background:rgba(176,96,255,.08);border:1px solid rgba(176,96,255,.3);color:#b060ff}
.dash-role-badge.viewer,.dash-role-badge.user{background:rgba(0,255,136,.06);border:1px solid rgba(0,255,136,.25);color:#00ff88}
.admin-only-btn{display:none}

</style>
</head>
<body>

<header>
  <div class="logo-mark">PG</div>
  <div class="logo-text">
    <h1>PacketGuard</h1>
    <span>Network Threat Detection System</span>
  </div>
  <div class="hdr-right">
    <a href="/dashboard" class="nav-btn"><i class="fa-solid fa-gauge"></i> Dashboard</a>
    <a href="/monitor"   class="nav-btn"><i class="fa-solid fa-satellite-dish"></i> Monitor</a>
    <button class="nav-btn danger" onclick="doLogout()"><i class="fa-solid fa-power-off"></i> Log Out</button>
  </div>
</header>

<div class="page">

  <!-- ── SIDEBAR ── -->
  <div class="card" style="padding:20px">
    <div class="card-label">Identity</div>
    <div class="avatar-wrap">
      <div class="avatar-ring">
        <span id="avatar-letter">?</span>
        <span class="online-dot"></span>
      </div>
      <div class="user-name"  id="prof-name">Loading…</div>
      <div class="user-email" id="prof-email">—</div>
      <div class="role-badge user" id="role-badge">—</div>
    </div>

    <div class="stat-grid">
      <div class="stat-box">
        <div class="stat-val" id="stat-joined">—</div>
        <div class="stat-lbl">Joined</div>
      </div>
      <div class="stat-box">
        <div class="stat-val" id="stat-lastlogin">—</div>
        <div class="stat-lbl">Last Login</div>
      </div>
    </div>

    <div class="sidebar-nav">
      <button class="snav-btn active" onclick="showSection('edit',this)"><span class="ico"><i class="fa-solid fa-pen"></i></span>Edit Profile</button>
      <button class="snav-btn" onclick="showSection('password',this)"><span class="ico"><i class="fa-solid fa-key"></i></span>Change Password</button>
      <button class="snav-btn" onclick="showSection('info',this)"><span class="ico"><i class="fa-solid fa-circle-info"></i></span>Account Info</button>
      <button class="snav-btn danger-btn" onclick="doLogout()"><span class="ico"><i class="fa-solid fa-power-off"></i></span>Log Out</button>
    </div>
  </div>

  <!-- ── MAIN PANEL ── -->
  <div style="display:flex;flex-direction:column;gap:20px">

    <!-- EDIT PROFILE -->
    <div class="card section active" id="section-edit">
      <div class="card-label">Edit Profile</div>
      <div class="field">
        <label>Display Name</label>
        <input type="text" id="edit-name" placeholder="Your full name" maxlength="60">
      </div>
      <div class="field">
        <label>Email Address <span style="color:var(--dim);font-size:8px">(READ-ONLY)</span></label>
        <input type="email" id="edit-email" readonly>
        <div class="hint">// Email cannot be changed. Contact admin if needed.</div>
      </div>
      <div class="field">
        <label>Role <span style="color:var(--dim);font-size:8px">(READ-ONLY)</span></label>
        <input type="text" id="edit-role" readonly>
      </div>
      <button class="btn btn-primary" onclick="saveProfile()"><i class="fa-solid fa-floppy-disk"></i> Save Changes</button>
      <div class="msg" id="edit-msg"></div>
    </div>

    <!-- CHANGE PASSWORD -->
    <div class="card section" id="section-password">
      <div class="card-label">Change Password</div>
      <div class="field">
        <label>Current Password</label>
        <div class="pw-input-wrap">
          <input type="password" id="pw-current" placeholder="Enter current password">
          <button class="pw-eye" onclick="togglePw('pw-current',this)"><i class="fa-solid fa-eye"></i></button>
        </div>
      </div>
      <div class="pw-fields">
        <div class="field">
          <label>New Password</label>
          <div class="pw-input-wrap">
            <input type="password" id="pw-new" placeholder="Min 6 characters" oninput="checkPwStrength(this.value)">
            <button class="pw-eye" onclick="togglePw('pw-new',this)"><i class="fa-solid fa-eye"></i></button>
          </div>
          <div class="pw-bar-wrap"><div class="pw-bar" id="pw-strength"></div></div>
        </div>
        <div class="field">
          <label>Confirm Password</label>
          <div class="pw-input-wrap">
            <input type="password" id="pw-confirm" placeholder="Repeat new password">
            <button class="pw-eye" onclick="togglePw('pw-confirm',this)"><i class="fa-solid fa-eye"></i></button>
          </div>
        </div>
      </div>
      <button class="btn btn-primary" onclick="changePassword()"><i class="fa-solid fa-lock"></i> Update Password</button>
      <div class="msg" id="pw-msg"></div>
    </div>

    <!-- ACCOUNT INFO -->
    <div class="card section" id="section-info">
      <div class="card-label">Account Info</div>
      <table class="info-table">
        <tr><td>USER ID</td><td><span class="badge-val blue" id="info-id">—</span></td></tr>
        <tr><td>FULL NAME</td><td id="info-name">—</td></tr>
        <tr><td>EMAIL</td><td id="info-email" style="word-break:break-all">—</td></tr>
        <tr><td>ROLE</td><td><span class="badge-val purple" id="info-role">—</span></td></tr>
        <tr><td>ACCESS LEVEL</td><td><span class="badge-val green" id="info-access">—</span></td></tr>
        <tr><td>ACCOUNT CREATED</td><td id="info-created">—</td></tr>
        <tr><td>LAST LOGIN</td><td id="info-lastlogin">—</td></tr>
      </table>
    </div>

  </div>
</div>

<div class="toast" id="toast"></div>
<footer>PacketGuard &copy; 2025 — Network Threat Detection System</footer>

<script>
let _user = null;

// ── Section switcher ──────────────────────────────────────────────
function showSection(name, btn) {
  document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('.snav-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('section-' + name).classList.add('active');
  if (btn) btn.classList.add('active');
}

// ── Toast ─────────────────────────────────────────────────────────
let _toastTimer;
function toast(msg, type='info') {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = 'toast show ' + type;
  clearTimeout(_toastTimer);
  _toastTimer = setTimeout(() => t.classList.remove('show'), 3500);
}

// ── Load profile ──────────────────────────────────────────────────
async function loadProfile() {
  try {
    const r = await fetch('/api/auth/profile', {credentials: 'include'});
    if (r.status === 401) {
      // Not logged in — redirect to home
      window.location.href = '/';
      return;
    }
    if (!r.ok) {
      toast('Server error (' + r.status + '). Try refreshing.', 'error');
      return;
    }
    const d = await r.json();
    if (!d.success) { window.location.href = '/'; return; }
    _user = d.user;
    renderProfile(_user);
  } catch(e) {
    console.error('Profile load error:', e);
    toast('Could not reach server. Check Flask is running.', 'error');
  }
}

function renderProfile(u) {
  const initial = (u.name || u.email || '?')[0].toUpperCase();
  document.getElementById('avatar-letter').textContent = initial;
  document.getElementById('prof-name').textContent     = u.name  || '—';
  document.getElementById('prof-email').textContent    = u.email || '—';
  document.getElementById('edit-name').value           = u.name  || '';
  document.getElementById('edit-email').value          = u.email || '';
  document.getElementById('edit-role').value           = u.role === 'admin' ? 'Administrator' : 'Standard User';

  const rb = document.getElementById('role-badge');
  const roleKey = u.role === 'admin' ? 'admin' : 'analyst';
  const roleEmoji = {admin:'⚡ ADMIN', analyst:'🔍 ANALYST'};
  rb.textContent = roleEmoji[u.role] || u.role.toUpperCase();
  rb.className   = 'role-badge ' + roleKey;
  // Set global role var
  window._userRole = u.role;
  window._sessionUser = u;

  document.getElementById('stat-joined').textContent    = u.created_at ? fmtDate(u.created_at) : '—';
  document.getElementById('stat-lastlogin').textContent = u.last_login  ? fmtDate(u.last_login)  : 'First visit';

  document.getElementById('info-id').textContent       = '#' + u.id;
  document.getElementById('info-name').textContent     = u.name;
  document.getElementById('info-email').textContent    = u.email;
  document.getElementById('info-role').textContent     = u.role === 'admin' ? 'ADMINISTRATOR' : 'USER';
  document.getElementById('info-access').textContent   = u.role === 'admin' ? 'FULL ACCESS' : 'READ-ONLY';
  document.getElementById('info-created').textContent  = u.created_at ? fmtFull(u.created_at) : '—';
  document.getElementById('info-lastlogin').textContent= u.last_login  ? fmtFull(u.last_login)  : '—';
}

function fmtDate(iso) {
  if (!iso) return '—';
  const d = new Date(iso + (iso.includes('Z') || iso.includes('+') ? '' : 'Z'));
  const diff = Math.floor((Date.now() - d) / 86400000);
  if (diff === 0) return 'Today';
  if (diff === 1) return 'Yesterday';
  if (diff < 30)  return diff + 'd ago';
  if (diff < 365) return Math.floor(diff/30) + 'mo ago';
  return Math.floor(diff/365) + 'yr ago';
}

function fmtFull(iso) {
  if (!iso) return '—';
  const d = new Date(iso + (iso.includes('Z') || iso.includes('+') ? '' : 'Z'));
  return d.toLocaleString('en-GB', {dateStyle:'medium', timeStyle:'short'});
}

// ── Save profile ──────────────────────────────────────────────────
async function saveProfile() {
  const name = document.getElementById('edit-name').value.trim();
  const msg  = document.getElementById('edit-msg');
  if (!name || name.length < 2) { msg.textContent = '// Name must be at least 2 characters'; msg.style.color='var(--accent2)'; return; }
  msg.textContent = '// Saving…'; msg.style.color = 'var(--dim2)';
  try {
    const r = await fetch('/api/auth/profile/update', {
      method:'POST', credentials:'include',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({name})
    });
    const d = await r.json();
    if (d.success) {
      _user.name = name;
      renderProfile(_user);
      msg.textContent = '// Profile updated successfully';
      msg.style.color = 'var(--accent3)';
      toast('Profile updated', 'success');
    } else {
      msg.textContent = '// Error: ' + (d.error || 'Unknown error');
      msg.style.color = 'var(--accent2)';
    }
  } catch(e) { msg.textContent = '// Network error'; msg.style.color = 'var(--accent2)'; }
}

// ── Password ──────────────────────────────────────────────────────
function togglePw(id, btn) {
  const el = document.getElementById(id);
  const show = el.type === 'password';
  el.type = show ? 'text' : 'password';
  btn.innerHTML = show ? '<i class="fa-solid fa-eye-slash"></i>' : '<i class="fa-solid fa-eye"></i>';
}

function checkPwStrength(pw) {
  let s = 0;
  if (pw.length >= 6) s++;
  if (pw.length >= 10) s++;
  if (/[A-Z]/.test(pw)) s++;
  if (/[0-9]/.test(pw)) s++;
  if (/[^A-Za-z0-9]/.test(pw)) s++;
  const bar = document.getElementById('pw-strength');
  bar.style.width = (s / 5 * 100) + '%';
  bar.style.background = ['#ff2d55','#ff9500','#ffcc00','#00c8ff','#00ff88'][s-1] || '#333';
}

async function changePassword() {
  const cur = document.getElementById('pw-current').value.trim();
  const npw = document.getElementById('pw-new').value.trim();
  const con = document.getElementById('pw-confirm').value.trim();
  const msg = document.getElementById('pw-msg');
  if (!cur || !npw || !con) { msg.textContent = '// All fields required'; msg.style.color='var(--accent2)'; return; }
  if (npw !== con)          { msg.textContent = '// Passwords do not match'; msg.style.color='var(--accent2)'; return; }
  if (npw.length < 6)       { msg.textContent = '// Min 6 characters'; msg.style.color='var(--accent2)'; return; }
  if (cur === npw)          { msg.textContent = '// Must differ from current password'; msg.style.color='var(--accent2)'; return; }
  msg.textContent = '// Updating…'; msg.style.color = 'var(--dim2)';
  try {
    const r = await fetch('/api/auth/change-password', {
      method:'POST', credentials:'include',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({current_password:cur, new_password:npw, confirm_password:con})
    });
    const d = await r.json();
    if (d.success) {
      msg.textContent = '// Password changed successfully';
      msg.style.color = 'var(--accent3)';
      document.getElementById('pw-current').value = '';
      document.getElementById('pw-new').value = '';
      document.getElementById('pw-confirm').value = '';
      document.getElementById('pw-strength').style.width = '0';
      toast('Password updated', 'success');
    } else {
      msg.textContent = '// Error: ' + (d.error || 'Unknown error');
      msg.style.color = 'var(--accent2)';
    }
  } catch(e) { msg.textContent = '// Network error'; msg.style.color = 'var(--accent2)'; }
}

// ── Logout ────────────────────────────────────────────────────────
function doLogout() {
  fetch('/api/auth/logout', {method:'POST', credentials:'include'})
    .finally(() => window.location.href = '/');
}

document.addEventListener('keydown', e => {
  if (e.key === 'Enter' && document.activeElement.closest('#section-edit'))     saveProfile();
  if (e.key === 'Enter' && document.activeElement.closest('#section-password')) changePassword();
});

loadProfile();
</script>
</body>
</html>
"""


=======

# ── HTML ──────────────────────────────────────────────────────────

>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<<<<<<< HEAD
<title>PacketGuard — Threat Detection Dashboard</title>
=======
<title>SENTINEL &mdash; Threat Detection Dashboard</title>
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
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
<<<<<<< HEAD
/* ── GeoIP Threat Map ──────────────────────────────────────────── */
.geo-panel { margin: 0 0 18px 0; }
#threat-map { height: 340px; width: 100%; border-radius: 8px; z-index: 1; background: #0a0f1a; }
.geo-ip-table { width: 100%; border-collapse: collapse; font-family: var(--font-mono); font-size: 10px; margin-top: 10px; }
.geo-ip-table th { color: var(--dim); font-weight: 400; text-align: left; padding: 4px 8px; border-bottom: 1px solid rgba(255,255,255,.06); }
.geo-ip-table td { padding: 5px 8px; border-bottom: 1px solid rgba(255,255,255,.03); vertical-align: middle; }
/* ── Blocked IPs Panel ─────────────────────────────────────────── */
.blocked-panel .panel-title { color: #ff2d55; }
.blocked-table { width:100%;border-collapse:collapse;font-family:var(--font-mono);font-size:10px;margin-top:6px }
.blocked-table th { color:var(--dim);font-weight:400;text-align:left;padding:5px 8px;border-bottom:1px solid rgba(255,255,255,.06) }
.blocked-table td { padding:5px 8px;border-bottom:1px solid rgba(255,255,255,.03);vertical-align:middle }
.blocked-table tr:hover td { background:rgba(255,45,85,.04) }
.blocked-ip-dot { display:inline-block;width:7px;height:7px;border-radius:50%;background:#ff2d55;box-shadow:0 0 6px #ff2d55;margin-right:5px;vertical-align:middle }
.unblock-btn { background:transparent;border:1px solid rgba(255,45,85,.4);color:#ff2d55;padding:2px 8px;border-radius:3px;font-family:var(--font-mono);font-size:8px;cursor:pointer;letter-spacing:1px }
.unblock-btn:hover { background:rgba(255,45,85,.15) }
.fw-status-bar { display:flex;gap:16px;padding:8px 0;margin-bottom:8px;border-bottom:1px solid rgba(255,255,255,.05) }
.fw-stat { display:flex;flex-direction:column;gap:2px }
.fw-stat-val { font-family:var(--font-mono);font-size:16px;font-weight:700;color:#ff2d55 }
.fw-stat-lbl { font-family:var(--font-mono);font-size:8px;letter-spacing:1px;color:var(--dim) }
.fw-enforcement { font-family:var(--font-mono);font-size:9px;padding:3px 8px;border-radius:3px;background:rgba(255,45,85,.12);color:#ff2d55;border:1px solid rgba(255,45,85,.3) }

.geo-ip-table tr:hover td { background: rgba(255,255,255,.02); }
.geo-flag { font-size: 14px; }
.geo-count-bar { display: inline-block; height: 4px; background: #00c8ff; border-radius: 2px; vertical-align: middle; margin-left: 6px; }

=======
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b

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

<<<<<<< HEAD

/* ── Incident Detail Slide-In Panel ─────────────────────────────── */
.inc-overlay{
  position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:900;
  opacity:0;pointer-events:none;transition:opacity .25s;
  backdrop-filter:blur(4px);
}
.inc-overlay.open{opacity:1;pointer-events:all;}

.inc-drawer{
  position:fixed;top:0;right:-580px;width:580px;height:100vh;
  background:#060e18;border-left:1px solid rgba(0,200,255,.18);
  z-index:901;display:flex;flex-direction:column;
  transition:right .28s cubic-bezier(.4,0,.2,1);
  box-shadow:-24px 0 80px rgba(0,0,0,.8);
}
.inc-drawer.open{right:0;}

.inc-drawer-header{
  padding:16px 20px;border-bottom:1px solid rgba(255,255,255,.06);
  display:flex;align-items:center;gap:12px;flex-shrink:0;
  background:linear-gradient(135deg,rgba(255,45,85,.05),rgba(0,0,0,0));
}
.inc-drawer-title{
  font-family:var(--font-mono);font-size:11px;font-weight:700;
  letter-spacing:3px;text-transform:uppercase;color:#ff2d55;flex:1;
}
.inc-drawer-close{
  width:28px;height:28px;border-radius:6px;background:rgba(255,255,255,.04);
  border:1px solid rgba(255,255,255,.08);color:#3a5570;cursor:pointer;
  display:flex;align-items:center;justify-content:center;transition:all .2s;
}
.inc-drawer-close:hover{color:#ff2d55;border-color:rgba(255,45,85,.3);}
.inc-drawer-body{flex:1;overflow-y:auto;padding:20px;}
.inc-drawer-body::-webkit-scrollbar{width:4px;}
.inc-drawer-body::-webkit-scrollbar-thumb{background:rgba(255,255,255,.1);border-radius:2px;}

/* Section labels */
.inc-section-title{font-family:var(--font-mono);font-size:9px;letter-spacing:2px;
  text-transform:uppercase;color:#3a5570;margin:18px 0 8px;padding-bottom:5px;
  border-bottom:1px solid rgba(255,255,255,.05);}

/* Risk gauge */
.inc-risk-gauge{display:flex;align-items:center;gap:14px;
  background:rgba(0,0,0,.3);border:1px solid rgba(255,255,255,.06);
  border-radius:8px;padding:14px 16px;margin-bottom:4px;}
.inc-risk-circle{width:56px;height:56px;flex-shrink:0;}
.inc-risk-label{flex:1;}
.inc-risk-val{font-family:var(--font-mono);font-size:24px;font-weight:700;line-height:1;}
.inc-risk-sub{font-size:9px;letter-spacing:1px;text-transform:uppercase;opacity:.4;margin-top:3px;}
.inc-confidence-bar{height:3px;background:rgba(255,255,255,.07);border-radius:2px;margin-top:10px;overflow:hidden;}
.inc-confidence-fill{height:100%;border-radius:2px;transition:width .7s ease;}

/* Meta grid */
.inc-meta-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:4px;}
.inc-meta-cell{background:rgba(0,0,0,.25);border:1px solid rgba(255,255,255,.05);border-radius:7px;padding:10px 12px;}
.inc-meta-cell-label{font-size:9px;letter-spacing:1px;text-transform:uppercase;color:#3a5570;margin-bottom:4px;}
.inc-meta-cell-val{font-family:var(--font-mono);font-size:12px;font-weight:600;word-break:break-all;}

/* Indicators */
.inc-indicators{background:rgba(0,0,0,.2);border:1px solid rgba(255,255,255,.05);border-radius:8px;padding:10px 14px;margin-bottom:4px;}
.inc-indicator-item{display:flex;align-items:flex-start;gap:8px;padding:5px 0;border-bottom:1px solid rgba(255,255,255,.04);font-size:11px;line-height:1.5;color:#a0b4c8;}
.inc-indicator-item:last-child{border-bottom:none;padding-bottom:0;}
.inc-indicator-dot{width:6px;height:6px;border-radius:50%;flex-shrink:0;margin-top:4px;}

/* Attack timeline */
.inc-timeline{margin-bottom:4px;}
.inc-timeline-item{display:flex;gap:10px;align-items:flex-start;padding:6px 0;position:relative;}
.inc-timeline-item:not(:last-child)::after{content:'';position:absolute;left:7px;top:18px;bottom:-6px;width:1px;background:rgba(255,255,255,.07);}
.inc-timeline-dot{width:14px;height:14px;border-radius:50%;flex-shrink:0;border:2px solid;display:flex;align-items:center;justify-content:center;margin-top:1px;}
.inc-timeline-content{flex:1;}
.inc-timeline-text{font-size:11px;line-height:1.5;color:#a0b4c8;}
.inc-timeline-time{font-size:9px;opacity:.35;font-family:var(--font-mono);margin-top:1px;}

/* Recommended actions */
.inc-rec-action{display:flex;align-items:flex-start;gap:10px;padding:8px 12px;
  border-radius:6px;margin-bottom:6px;font-size:11px;border:1px solid;line-height:1.5;}
.inc-rec-icon{font-size:14px;flex-shrink:0;margin-top:1px;}

/* Stat boxes */
.inc-stats-row{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:4px;}
.inc-stat-box{background:rgba(255,255,255,.025);border:1px solid rgba(255,255,255,.06);border-radius:8px;padding:10px;text-align:center;}
.inc-stat-val{font-family:var(--font-mono);font-size:16px;font-weight:700;color:#00c8ff;line-height:1;margin-bottom:3px;}
.inc-stat-lbl{font-family:var(--font-mono);font-size:8px;letter-spacing:1px;text-transform:uppercase;color:#3a5570;}

/* Field */
.inc-field{margin-bottom:12px;}
.inc-field-label{font-family:var(--font-mono);font-size:9px;letter-spacing:2.5px;text-transform:uppercase;color:#3a5570;margin-bottom:4px;}
.inc-field-value{font-family:var(--font-mono);font-size:12px;color:#c0d4ee;background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.06);border-radius:6px;padding:8px 12px;word-break:break-all;}
.inc-field-value.ip{color:#00c8ff;}
.inc-field-value.sev-HIGH{color:#ff6400;border-color:rgba(255,100,0,.2);}
.inc-field-value.sev-CRITICAL{color:#ff2d55;border-color:rgba(255,45,85,.2);}
.inc-field-value.sev-MEDIUM{color:#ffb800;border-color:rgba(255,184,0,.2);}
.inc-field-value.sev-LOW{color:#00ff88;border-color:rgba(0,255,136,.2);}

/* Action buttons */
.inc-action-row{display:flex;gap:8px;margin-top:18px;padding-top:14px;border-top:1px solid rgba(255,255,255,.05);}
.inc-btn{flex:1;padding:10px;border-radius:7px;font-family:var(--font-mono);font-size:10px;font-weight:700;letter-spacing:1.5px;cursor:pointer;text-transform:uppercase;border:1px solid;transition:all .2s;}
.inc-btn-investigate{background:rgba(0,200,255,.08);border-color:rgba(0,200,255,.3);color:#00c8ff;}
.inc-btn-investigate:hover{background:rgba(0,200,255,.18);box-shadow:0 0 16px rgba(0,200,255,.2);}
.inc-btn-investigate:disabled{opacity:.4;cursor:not-allowed;}
.inc-btn-close{background:rgba(0,255,136,.06);border-color:rgba(0,255,136,.2);color:#00ff88;}
.inc-btn-close:hover{background:rgba(0,255,136,.14);}
.inc-btn-danger{background:rgba(255,45,85,.07);border-color:rgba(255,45,85,.25);color:#ff2d55;}
.inc-btn-danger:hover{background:rgba(255,45,85,.18);}

/* AI output */
.inc-ai-output{margin-top:14px;padding:14px;background:rgba(0,200,255,.03);border:1px solid rgba(0,200,255,.1);border-radius:8px;font-family:var(--font-mono);font-size:11px;color:#b4b2a9;line-height:1.75;display:none;max-height:300px;overflow-y:auto;white-space:pre-wrap;}
.inc-ai-output.visible{display:block;}
.inc-ai-spinner{display:inline-block;width:10px;height:10px;border:1.5px solid rgba(0,200,255,.2);border-top-color:#00c8ff;border-radius:50%;animation:spin .8s linear infinite;margin-right:8px;vertical-align:middle;}
@keyframes spin{to{transform:rotate(360deg)}}

.ent-table tbody tr.inc-row-selected td{background:rgba(255,45,85,.06)!important;}
.ent-table tbody tr.inc-row{cursor:pointer;}
.ent-table tbody tr.inc-row:hover td{background:rgba(255,45,85,.04)!important;}

=======
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
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
<<<<<<< HEAD

/* ══ Admin Styles ════════════════════════════════════════════════ */
.apm{background:#080e1a;border:1px solid rgba(0,200,255,.22);border-radius:14px;width:100%;display:flex;flex-direction:column;overflow:hidden;box-shadow:0 0 40px rgba(0,0,0,.5),0 0 0 1px rgba(0,200,255,.06)}
.apm-hdr{padding:18px 26px;border-bottom:1px solid rgba(255,255,255,.06);display:flex;align-items:center;justify-content:space-between;background:linear-gradient(135deg,rgba(0,200,255,.04),rgba(176,96,255,.02))}
.apm-hdr h2{font-family:var(--font-mono);font-size:12px;letter-spacing:3px;text-transform:uppercase;color:#00c8ff;margin:0;display:flex;align-items:center;gap:12px}
.apm-hdr h2 small{font-size:9px;color:#1e3a50;letter-spacing:2px;font-weight:400}
.apm-body{padding:22px 26px;overflow-y:auto;flex:1}
/* Stats */
.apm-stats{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:22px}
.apm-stat{background:rgba(255,255,255,.025);border:1px solid rgba(255,255,255,.06);border-radius:8px;padding:14px;text-align:center}
.apm-stat .v{font-family:var(--font-mono);font-size:24px;font-weight:700;line-height:1}
.apm-stat .l{font-size:9px;letter-spacing:2px;text-transform:uppercase;color:#3a5570;margin-top:5px}
/* Create box */
.apm-create{background:rgba(0,200,255,.02);border:1px solid rgba(0,200,255,.1);border-radius:10px;padding:16px 18px;margin-bottom:16px}
.apm-sec-title{font-family:var(--font-mono);font-size:9px;letter-spacing:3px;text-transform:uppercase;color:#1e3a50;margin:0 0 10px}
.apm-create-grid{display:grid;grid-template-columns:1fr 1fr 1fr 150px auto;gap:8px;align-items:end}
.apm-create-grid input,.apm-create-grid select,.apm-search-input,.apm-filter-sel{background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08);color:#c0d4ee;border-radius:6px;padding:8px 11px;font-size:12px;font-family:var(--font-mono);outline:none;transition:border-color .2s}
.apm-create-grid input:focus,.apm-create-grid select:focus,.apm-search-input:focus{border-color:rgba(0,200,255,.4)}
.apm-create-btn{background:linear-gradient(135deg,rgba(0,200,255,.16),rgba(176,96,255,.1));border:1px solid rgba(0,200,255,.32);color:#00c8ff;border-radius:6px;padding:8px 18px;font-family:var(--font-mono);font-size:11px;font-weight:700;letter-spacing:1px;cursor:pointer;white-space:nowrap;transition:all .2s}
.apm-create-btn:hover{box-shadow:0 0 16px rgba(0,200,255,.2);border-color:rgba(0,200,255,.5)}
/* Search */
.apm-search-row{display:flex;gap:8px;margin-bottom:14px;align-items:center}
.apm-search-input{flex:1}
.apm-filter-sel{cursor:pointer}
.apm-refresh-btn{background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08);color:#3a5570;border-radius:6px;padding:8px 13px;cursor:pointer;font-size:14px;transition:all .2s;flex-shrink:0}
.apm-refresh-btn:hover{color:#00c8ff;border-color:rgba(0,200,255,.3)}
/* Table */
.apm-table{width:100%;border-collapse:collapse;font-size:12px}
.apm-table th{text-align:left;font-family:var(--font-mono);font-size:9px;letter-spacing:2px;text-transform:uppercase;color:#1e3a50;padding:8px 10px;border-bottom:1px solid rgba(255,255,255,.06)}
.apm-table td{padding:10px 10px;border-bottom:1px solid rgba(255,255,255,.03);vertical-align:middle}
.apm-table tr:hover td{background:rgba(255,255,255,.02)}
.apm-table tr.is-you td{background:rgba(0,200,255,.025)}
/* Role pills */
.rpill{display:inline-block;padding:2px 9px;border-radius:20px;font-family:var(--font-mono);font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:1px}
.rpill.admin{background:rgba(0,200,255,.1);border:1px solid rgba(0,200,255,.28);color:#00c8ff}
.rpill.analyst{background:rgba(176,96,255,.1);border:1px solid rgba(176,96,255,.28);color:#b060ff}
.rpill.viewer,.rpill.user{background:rgba(0,255,136,.07);border:1px solid rgba(0,255,136,.2);color:#00ff88}
/* Action controls */
.apm-role-sel{background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08);color:#c0d4ee;border-radius:5px;padding:3px 8px;font-size:11px;font-family:var(--font-mono);cursor:pointer;margin-right:4px}
.abtn{border-radius:5px;padding:3px 10px;font-size:10px;font-family:var(--font-mono);font-weight:700;cursor:pointer;border:1px solid;transition:all .15s;margin-left:2px}
.abtn.pw{background:rgba(255,184,0,.08);border-color:rgba(255,184,0,.28);color:#ffb800}
.abtn.pw:hover{background:rgba(255,184,0,.18)}
.abtn.del{background:rgba(255,45,85,.08);border-color:rgba(255,45,85,.28);color:#ff2d55}
.abtn.del:hover{background:rgba(255,45,85,.18)}
/* Legend */
.apm-legend{margin-top:20px;padding:13px 16px;background:rgba(0,200,255,.015);border:1px solid rgba(255,255,255,.05);border-radius:8px;font-size:11px;font-family:var(--font-mono);line-height:2.2;display:flex;flex-wrap:wrap;gap:0 28px}
.apm-empty td{text-align:center;color:#3a5570;padding:32px;font-family:var(--font-mono);font-size:12px}
/* Users button in header */
#admin-users-btn{display:none;background:rgba(0,200,255,.08);border:1px solid rgba(0,200,255,.3);color:#00c8ff;border-radius:6px;padding:6px 16px;font-family:var(--font-mono);font-size:11px;font-weight:700;letter-spacing:1px;cursor:pointer;transition:all .2s}
#admin-users-btn:hover{background:rgba(0,200,255,.16);box-shadow:0 0 12px rgba(0,200,255,.2)}

/* ── Header icon buttons ────────────────────────────────────────── */
.hdr-icon-btn{width:32px;height:32px;border-radius:6px;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08);color:#6a8aaa;cursor:pointer;display:flex;align-items:center;justify-content:center;transition:all .2s;flex-shrink:0}
.hdr-icon-btn:hover{background:rgba(0,200,255,.08);border-color:rgba(0,200,255,.3);color:#00c8ff}
.hdr-icon-btn.hdr-icon-danger:hover{background:rgba(255,45,85,.07);border-color:rgba(255,45,85,.3);color:#ff2d55}

/* ── Settings drawer tabs ───────────────────────────────────────── */
.stab{display:flex;align-items:center;gap:7px;padding:12px 14px;font-family:var(--font-mono);font-size:10px;font-weight:700;letter-spacing:1.5px;text-transform:uppercase;cursor:pointer;background:transparent;border:none;color:#3a5570;border-bottom:2px solid transparent;transition:all .2s;white-space:nowrap}
.stab:hover{color:#c0d4ee}
.stab.active{color:#00c8ff;border-bottom-color:#00c8ff}
.stab-panel{display:none}.stab-panel.active{display:block}

/* ── Config rows ────────────────────────────────────────────────── */
.scfg-section-title{font-family:var(--font-mono);font-size:9px;letter-spacing:3px;text-transform:uppercase;color:#1e3a50;margin-bottom:10px;margin-top:4px;padding-bottom:6px;border-bottom:1px solid rgba(255,255,255,.04)}
.scfg-row{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:10px 0;border-bottom:1px solid rgba(255,255,255,.03)}
.scfg-row:last-child{border-bottom:none}
.scfg-label{font-family:var(--font-mono);font-size:11px;color:#c0d4ee;flex:1}
.scfg-hint{font-size:9px;color:#3a5570;margin-top:3px;letter-spacing:.4px;font-weight:400}
.scfg-input{background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08);color:#c0d4ee;border-radius:6px;padding:8px 10px;font-family:var(--font-mono);font-size:11px;outline:none;transition:border-color .2s;width:100%}
.scfg-input:focus{border-color:rgba(0,200,255,.4)}
.scfg-stat-box{background:rgba(255,255,255,.025);border:1px solid rgba(255,255,255,.06);border-radius:7px;padding:12px 8px;text-align:center}
.scfg-stat-val{font-family:var(--font-mono);font-size:20px;font-weight:700;line-height:1}
.scfg-stat-lbl{font-size:9px;letter-spacing:2px;text-transform:uppercase;color:#3a5570;margin-top:4px}

/* ── Toggle switch ──────────────────────────────────────────────── */
.stoggle{position:relative;width:40px;height:22px;flex-shrink:0}
.stoggle input{opacity:0;width:0;height:0}
.stoggle-slider{position:absolute;cursor:pointer;inset:0;background:rgba(255,255,255,.08);border-radius:22px;transition:.25s;border:1px solid rgba(255,255,255,.1)}
.stoggle-slider::before{content:'';position:absolute;height:16px;width:16px;left:2px;bottom:2px;background:#3a5570;border-radius:50%;transition:.25s}
.stoggle input:checked+.stoggle-slider{background:rgba(0,200,255,.2);border-color:rgba(0,200,255,.4)}
.stoggle input:checked+.stoggle-slider::before{transform:translateX(18px);background:#00c8ff}
/* ══════════════════════════════════════════════════════════
   ENTERPRISE INTELLIGENCE SECTION — Professional Redesign
   ══════════════════════════════════════════════════════════ */

/* Section wrapper */
.ent-section{margin:24px 0;display:flex;flex-direction:column;gap:14px}

/* Section header */
.ent-section-header{display:flex;align-items:center;justify-content:space-between;padding:0 2px;margin-bottom:4px}
.ent-section-title{display:flex;align-items:center;gap:6px;font-family:var(--font-mono);font-size:11px;letter-spacing:4px;text-transform:uppercase;color:var(--text)}
.ent-bracket{color:rgba(0,200,255,.4);font-size:13px;font-weight:300}
.ent-title-text{background:linear-gradient(90deg,#00c8ff,#b060ff);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;font-weight:700;letter-spacing:5px}
.ent-header-meta{display:flex;align-items:center;gap:10px}
.ent-meta-pill{display:flex;align-items:center;gap:6px;font-family:var(--font-mono);font-size:9px;letter-spacing:2px;color:#00ff88;border:1px solid rgba(0,255,136,.2);border-radius:20px;padding:3px 10px;background:rgba(0,255,136,.05)}
.ent-pulse-dot{width:6px;height:6px;border-radius:50%;background:#00ff88;box-shadow:0 0 6px #00ff88;animation:entPulse 2s ease-in-out infinite}
@keyframes entPulse{0%,100%{opacity:1;box-shadow:0 0 6px #00ff88}50%{opacity:.5;box-shadow:0 0 12px #00ff88}}
.ent-meta-divider{color:rgba(255,255,255,.12);font-size:12px}
.ent-meta-label{font-family:var(--font-mono);font-size:9px;letter-spacing:2px;color:var(--dim);text-transform:uppercase}

/* KPI Strip */
.ent-kpi-strip{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}
.ent-kpi-card{position:relative;background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:18px 18px 18px 22px;display:flex;align-items:center;gap:14px;overflow:hidden;transition:border-color .25s,transform .2s}
.ent-kpi-card:hover{transform:translateY(-1px)}
.ent-kpi-critical:hover{border-color:rgba(255,45,85,.35)}
.ent-kpi-warn:hover{border-color:rgba(255,184,0,.35)}
.ent-kpi-purple:hover{border-color:rgba(176,96,255,.35)}
.ent-kpi-cyan:hover{border-color:rgba(0,200,255,.35)}
.ent-kpi-bar-accent{position:absolute;left:0;top:0;bottom:0;width:3px;border-radius:10px 0 0 10px}
.ent-kpi-glow{position:absolute;top:-20px;left:-20px;width:80px;height:80px;border-radius:50%;opacity:.06;pointer-events:none}
.ent-kpi-critical .ent-kpi-glow{background:#ff2d55}
.ent-kpi-warn .ent-kpi-glow{background:#ffb800}
.ent-kpi-purple .ent-kpi-glow{background:#b060ff}
.ent-kpi-cyan .ent-kpi-glow{background:#00c8ff}
.ent-kpi-icon{font-size:20px;opacity:.4;flex-shrink:0;font-family:var(--font-mono)}
.ent-kpi-body{flex:1;min-width:0}
.ent-kpi-value{font-family:var(--font-mono);font-size:26px;font-weight:700;line-height:1;margin-bottom:4px}
.ent-kpi-critical .ent-kpi-value{color:#ff2d55}
.ent-kpi-warn .ent-kpi-value{color:#ffb800}
.ent-kpi-purple .ent-kpi-value{color:#b060ff}
.ent-kpi-cyan .ent-kpi-value{color:#00c8ff}
.ent-kpi-label{font-family:var(--font-mono);font-size:9px;letter-spacing:2px;text-transform:uppercase;color:var(--text);opacity:.7}
.ent-kpi-sub{font-family:var(--font-mono);font-size:8px;letter-spacing:1px;text-transform:uppercase;color:var(--dim);margin-top:2px}

/* Panel base */
.ent-panel{background:var(--panel);border:1px solid var(--border);border-radius:10px;overflow:hidden;transition:border-color .2s}
.ent-panel:hover{border-color:rgba(255,255,255,.08)}
.ent-panel-header{display:flex;align-items:center;justify-content:space-between;padding:14px 18px;border-bottom:1px solid rgba(255,255,255,.04);background:rgba(255,255,255,.01)}
.ent-panel-title-group{display:flex;align-items:center;gap:9px}
.ent-panel-indicator{width:6px;height:6px;border-radius:50%;flex-shrink:0}
.ent-panel-title{font-family:var(--font-mono);font-size:10px;letter-spacing:3px;text-transform:uppercase;color:var(--text);font-weight:600}
.ent-panel-count{font-family:var(--font-mono);font-size:9px;letter-spacing:1px;color:var(--dim);background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.06);border-radius:4px;padding:2px 7px}
.ent-panel-subtitle{font-family:var(--font-mono);font-size:9px;letter-spacing:1px;color:var(--dim);text-transform:uppercase}

/* Live tag */
.ent-live-tag{font-family:var(--font-mono);font-size:8px;letter-spacing:2px;color:#00ff88;border:1px solid rgba(0,255,136,.2);border-radius:3px;padding:2px 7px;animation:entLiveBlink 3s ease-in-out infinite}
@keyframes entLiveBlink{0%,100%{opacity:1}50%{opacity:.5}}

/* Icon button */
.ent-icon-btn{background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08);color:var(--dim);border-radius:5px;padding:5px 7px;cursor:pointer;display:flex;align-items:center;justify-content:center;transition:all .2s}
.ent-icon-btn:hover{background:rgba(255,255,255,.08);color:var(--text);border-color:rgba(255,255,255,.16)}

/* Sweep button */
.ent-sweep-btn{display:flex;align-items:center;gap:6px;background:rgba(0,200,255,.08);border:1px solid rgba(0,200,255,.25);color:#00c8ff;border-radius:5px;padding:5px 12px;font-family:var(--font-mono);font-size:9px;letter-spacing:2px;cursor:pointer;transition:all .2s}
.ent-sweep-btn:hover{background:rgba(0,200,255,.15);box-shadow:0 0 12px rgba(0,200,255,.15)}
.ent-sweep-btn:disabled{opacity:.4;cursor:not-allowed}

/* Select */
.ent-select{background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08);color:var(--dim);border-radius:5px;padding:4px 8px;font-family:var(--font-mono);font-size:9px;cursor:pointer;letter-spacing:1px;outline:none}
.ent-select:focus{border-color:rgba(0,200,255,.3);color:var(--text)}

/* Incidents table */
.ent-table-wrap{overflow-x:auto}
.ent-table{width:100%;border-collapse:collapse;font-size:11px}
.ent-table thead tr{background:rgba(255,255,255,.02)}
.ent-table th{font-family:var(--font-mono);font-size:8px;letter-spacing:2px;text-transform:uppercase;color:var(--dim);padding:9px 14px;text-align:left;border-bottom:1px solid rgba(255,255,255,.05);white-space:nowrap}
.ent-table td{padding:10px 14px;border-bottom:1px solid rgba(255,255,255,.03);font-family:var(--font-mono);font-size:10px;color:var(--text);vertical-align:middle}
.ent-table tbody tr:last-child td{border-bottom:none}
.ent-table tbody tr:hover td{background:rgba(255,255,255,.02)}
.ent-table-empty{text-align:center;color:var(--dim);padding:28px;font-family:var(--font-mono);font-size:11px;letter-spacing:1px}

/* Severity badges */
.ent-sev{display:inline-flex;align-items:center;gap:4px;font-family:var(--font-mono);font-size:8px;font-weight:700;letter-spacing:2px;padding:3px 8px;border-radius:3px;text-transform:uppercase}
.ent-sev::before{content:'';width:4px;height:4px;border-radius:50%;flex-shrink:0}
.ent-sev-CRITICAL{background:rgba(255,45,85,.12);color:#ff2d55;border:1px solid rgba(255,45,85,.2)}
.ent-sev-CRITICAL::before{background:#ff2d55;box-shadow:0 0 4px #ff2d55}
.ent-sev-HIGH{background:rgba(255,100,0,.10);color:#ff6400;border:1px solid rgba(255,100,0,.2)}
.ent-sev-HIGH::before{background:#ff6400}
.ent-sev-MEDIUM{background:rgba(255,184,0,.10);color:#ffb800;border:1px solid rgba(255,184,0,.2)}
.ent-sev-MEDIUM::before{background:#ffb800}
.ent-sev-LOW{background:rgba(0,255,136,.07);color:#00ff88;border:1px solid rgba(0,255,136,.15)}
.ent-sev-LOW::before{background:#00ff88}

/* Close incident btn */
.ent-close-btn{font-family:var(--font-mono);font-size:8px;letter-spacing:1px;padding:3px 9px;border-radius:3px;cursor:pointer;background:rgba(0,255,136,.06);border:1px solid rgba(0,255,136,.18);color:#00ff88;text-transform:uppercase;transition:all .2s}
.ent-close-btn:hover{background:rgba(0,255,136,.14);box-shadow:0 0 8px rgba(0,255,136,.15)}

/* Two-column grid */
.ent-two-col{display:grid;grid-template-columns:1fr 1fr;gap:14px}

/* Threat score list */
.ent-score-list{padding:14px 18px;display:flex;flex-direction:column;gap:10px}
.ent-score-row{display:flex;align-items:center;gap:10px}
.ent-score-rank{font-family:var(--font-mono);font-size:8px;color:var(--dim);min-width:16px;text-align:right}
.ent-score-ip{font-family:var(--font-mono);font-size:10px;color:#00c8ff;min-width:120px}
.ent-score-bar-wrap{flex:1;height:4px;background:rgba(255,255,255,.06);border-radius:2px;overflow:hidden}
.ent-score-bar{height:100%;border-radius:2px;transition:width .7s cubic-bezier(.4,0,.2,1)}
.ent-score-val{font-family:var(--font-mono);font-size:10px;font-weight:700;min-width:34px;text-align:right}
.ent-score-level{font-family:var(--font-mono);font-size:8px;letter-spacing:1px;text-transform:uppercase;min-width:52px;text-align:right;opacity:.6}

/* Attack chain list */
.ent-chain-list{padding:14px 18px;display:flex;flex-direction:column;gap:0}
.ent-chain-row{display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid rgba(255,255,255,.03)}
.ent-chain-row:last-child{border-bottom:none}
.ent-chain-ip{font-family:var(--font-mono);font-size:10px;color:#00c8ff;min-width:112px}
.ent-chain-vector{flex:1;font-size:10px;color:var(--dim);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.ent-chain-date{font-family:var(--font-mono);font-size:8px;color:rgba(255,255,255,.2);white-space:nowrap}

/* Timeline */
.ent-timeline{padding:14px 18px;display:flex;flex-direction:column;gap:0;max-height:220px;overflow-y:auto}
.ent-timeline::-webkit-scrollbar{width:3px}
.ent-timeline::-webkit-scrollbar-thumb{background:rgba(255,255,255,.1);border-radius:2px}
.ent-tl-row{display:flex;align-items:flex-start;gap:10px;padding:8px 0;border-bottom:1px solid rgba(255,255,255,.03);position:relative}
.ent-tl-row:last-child{border-bottom:none}
.ent-tl-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0;margin-top:2px}
.ent-tl-dot.block{background:#ff2d55;box-shadow:0 0 5px #ff2d55}
.ent-tl-dot.alert{background:#ffb800;box-shadow:0 0 5px #ffb800}
.ent-tl-dot.scan{background:#00c8ff;box-shadow:0 0 5px #00c8ff}
.ent-tl-dot.ok{background:#00ff88;box-shadow:0 0 4px #00ff88}
.ent-tl-time{font-family:var(--font-mono);font-size:8px;color:var(--dim);min-width:38px;padding-top:1px;letter-spacing:.5px}
.ent-tl-msg{font-family:var(--font-mono);font-size:10px;color:var(--text);line-height:1.5;opacity:.8}
.ent-tl-ip{color:#00c8ff;opacity:1}

/* Chart area */
.ent-chart-area{padding:14px 18px 4px;position:relative}
.ent-chart-area canvas{width:100%;height:130px;display:block}
.ent-chart-legend{display:flex;align-items:center;gap:18px;padding:8px 18px 14px;font-family:var(--font-mono);font-size:8px;letter-spacing:1px;color:var(--dim);text-transform:uppercase}
.ent-legend-item{display:flex;align-items:center;gap:6px}

/* Leaderboard */
.ent-leaderboard{padding:14px 18px;display:flex;flex-direction:column;gap:8px}
.ent-lb-row{display:flex;align-items:center;gap:10px}
.ent-lb-rank{font-family:var(--font-mono);font-size:9px;color:var(--dim);min-width:20px;text-align:right;font-weight:700}
.ent-lb-rank-1{color:#ffb800}
.ent-lb-rank-2{color:rgba(255,255,255,.4)}
.ent-lb-rank-3{color:rgba(205,127,50,.6)}
.ent-lb-ip{font-family:var(--font-mono);font-size:10px;color:#00c8ff;min-width:120px}
.ent-lb-bar-wrap{flex:1;height:5px;background:rgba(255,255,255,.05);border-radius:2px;overflow:hidden}
.ent-lb-bar{height:100%;border-radius:2px;transition:width .8s cubic-bezier(.4,0,.2,1)}
.ent-lb-score{font-family:var(--font-mono);font-size:10px;font-weight:700;min-width:34px;text-align:right}
.ent-lb-level{font-family:var(--font-mono);font-size:8px;letter-spacing:1px;text-transform:uppercase;min-width:55px;text-align:right;opacity:.5}
.ent-lb-actions{font-family:var(--font-mono);font-size:8px;color:var(--dim);min-width:60px;text-align:right}

/* Spinner & loading */
.ent-loading{display:flex;align-items:center;gap:8px;padding:20px;justify-content:center;font-family:var(--font-mono);font-size:10px;color:var(--dim);letter-spacing:1px}
.ent-spinner{width:10px;height:10px;border:1.5px solid rgba(255,255,255,.1);border-top-color:#00c8ff;border-radius:50%;animation:entSpin .8s linear infinite;flex-shrink:0}
@keyframes entSpin{to{transform:rotate(360deg)}}
=======
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
</style>
</head>
<body>
<div class="shell">

<header>
<<<<<<< HEAD
  <div class="logo-mark">PG</div>
  <div class="logo-text">
    <h1>PacketGuard</h1>
=======
  <div class="logo-mark">SN</div>
  <div class="logo-text">
    <h1>Sentinel</h1>
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
    <span>Network Threat Detection System</span>
  </div>
  <div class="header-right">
    <div class="status-pill"><div class="dot"></div> SYSTEM ONLINE</div>
<<<<<<< HEAD
    <div class="status-pill" id="monitoring-pill" style="border-color:rgba(0,200,255,.35);color:#00c8ff">
      <div class="dot" style="background:#00c8ff;animation:blink 1s ease-in-out infinite;box-shadow:0 0 6px #00c8ff"></div>
      MONITORING LIVE
    </div>
    <button class="btn-scan" id="btn-scan-now" onclick="triggerScanNow()">SCAN NOW</button>
    <button class="btn-scan" style="border-color:rgba(255,45,85,.4);color:#ff2d55;background:rgba(255,45,85,.07)" onclick="testNotification()">TEST ALERT</button>
    <span id="hdr-role-badge" style="display:none;font-family:var(--font-mono);font-size:10px;font-weight:700;padding:4px 10px;border-radius:20px;letter-spacing:1px"></span>

    <!-- Divider -->
    <div style="width:1px;height:22px;background:rgba(255,255,255,.08);margin:0 2px"></div>

    <!-- Profile icon -->
    <button onclick="window.location.href='/profile'" title="My Profile" class="hdr-icon-btn">
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 3.6-7 8-7s8 3 8 7"/></svg>
    </button>

    <!-- Settings gear — opens Settings drawer -->
    <button onclick="openSettings('system')" title="Settings" class="hdr-icon-btn" id="hdr-settings-btn">
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
    </button>

    <!-- Log out icon -->
    <button onclick="doLogout()" title="Log Out" class="hdr-icon-btn hdr-icon-danger">
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
    </button>

=======
    <div class="scan-bar" id="scan-bar">
      <div class="scan-dot"></div>
      <span id="scan-bar-text">Initializing scan...</span>
    </div>
    <button class="btn-scan" id="btn-scan-now" onclick="triggerScanNow()">SCAN NOW</button>
    <button class="btn-scan" style="border-color:rgba(255,45,85,.4);color:#ff2d55;background:rgba(255,45,85,.07)" onclick="testNotification()">TEST ALERT</button>
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
    <div class="clock" id="clock">--:--:--</div>
  </div>
</header>

<<<<<<< HEAD
<!-- ══ SETTINGS DRAWER ══════════════════════════════════════════════ -->
<div id="settings-overlay" onclick="closeSettings()" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:800;backdrop-filter:blur(4px)"></div>
<aside id="settings-drawer" style="position:fixed;top:0;right:-520px;width:520px;height:100vh;background:#080d18;border-left:1px solid rgba(0,200,255,.15);z-index:801;display:flex;flex-direction:column;transition:right .28s cubic-bezier(.4,0,.2,1);box-shadow:-20px 0 60px rgba(0,0,0,.6)">

  <!-- Drawer header -->
  <div style="padding:18px 22px;border-bottom:1px solid rgba(255,255,255,.06);display:flex;align-items:center;gap:14px;background:linear-gradient(135deg,rgba(0,200,255,.04),rgba(176,96,255,.02));flex-shrink:0">
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#00c8ff" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
    <div style="flex:1">
      <div style="font-family:var(--font-mono);font-size:11px;font-weight:700;letter-spacing:3px;text-transform:uppercase;color:#00c8ff">SETTINGS</div>
      <div style="font-family:var(--font-mono);font-size:9px;color:#3a5570;letter-spacing:2px;margin-top:2px">PacketGuard Configuration Console</div>
    </div>
    <button onclick="closeSettings()" style="width:30px;height:30px;border-radius:6px;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08);color:#3a5570;cursor:pointer;font-size:16px;display:flex;align-items:center;justify-content:center;transition:all .2s" onmouseover="this.style.color='#ff2d55';this.style.borderColor='rgba(255,45,85,.3)'" onmouseout="this.style.color='#3a5570';this.style.borderColor='rgba(255,255,255,.08)'">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
    </button>
  </div>

  <!-- Drawer tabs -->
  <div style="display:flex;border-bottom:1px solid rgba(255,255,255,.06);flex-shrink:0;padding:0 8px">
    <button class="stab active" id="stab-system"       onclick="switchSettingsTab('system')">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/></svg>System
    </button>
    <button class="stab" id="stab-notifications" onclick="switchSettingsTab('notifications')">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>Alerts
    </button>
    <button class="stab" id="stab-security"     onclick="switchSettingsTab('security')">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>Security
    </button>
    <button class="stab" id="stab-users" onclick="switchSettingsTab('users')" style="display:none">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>Users
    </button>
  </div>

  <!-- Drawer body -->
  <div style="flex:1;overflow-y:auto;padding:22px">

    <!-- SYSTEM TAB -->
    <div class="stab-panel active" id="spanel-system">
      <div class="scfg-section-title">// NETWORK SCANNER</div>
      <div class="scfg-row">
        <div class="scfg-label">Scan Interval<div class="scfg-hint">How often the background scanner runs automatically.</div></div>
        <div style="display:flex;align-items:center;gap:8px">
          <span style="font-family:var(--font-mono);font-size:13px;font-weight:700;color:#00c8ff" id="cfg-interval-val">20s</span>
          <button onclick="triggerScanNow()" style="background:rgba(0,200,255,.07);border:1px solid rgba(0,200,255,.25);color:#00c8ff;border-radius:5px;padding:5px 12px;font-family:var(--font-mono);font-size:10px;font-weight:700;cursor:pointer;letter-spacing:1px">SCAN NOW</button>
        </div>
      </div>
      <div class="scfg-row">
        <div class="scfg-label">Last Scan<div class="scfg-hint">Timestamp of the most recently completed network scan.</div></div>
        <span style="font-family:var(--font-mono);font-size:11px;color:#c0d4ee" id="cfg-last-scan">—</span>
      </div>
      <div class="scfg-row">
        <div class="scfg-label">Devices Found<div class="scfg-hint">Total unique hosts discovered in the last scan cycle.</div></div>
        <span style="font-family:var(--font-mono);font-size:13px;font-weight:700;color:#00ff88" id="cfg-device-count">—</span>
      </div>

      <div class="scfg-section-title" style="margin-top:22px">// DATA REFRESH</div>
      <div class="scfg-row">
        <div class="scfg-label">Dashboard Polling<div class="scfg-hint">How often the UI fetches fresh data from the backend.</div></div>
        <span style="font-family:var(--font-mono);font-size:11px;color:#ffb800">Every 10 seconds</span>
      </div>
      <div class="scfg-row">
        <div class="scfg-label">Live Monitor Rate<div class="scfg-hint">Update frequency for packet rate and protocol charts.</div></div>
        <span style="font-family:var(--font-mono);font-size:11px;color:#ffb800">Every 2 seconds</span>
      </div>

      <div class="scfg-section-title" style="margin-top:22px">// SYSTEM STATUS</div>
      <div class="scfg-row">
        <div class="scfg-label">ML Engine<div class="scfg-hint">Isolation Forest anomaly detection model state.</div></div>
        <span style="font-family:var(--font-mono);font-size:10px;font-weight:700;padding:3px 10px;border-radius:4px;background:rgba(0,255,136,.07);border:1px solid rgba(0,255,136,.2);color:#00ff88" id="cfg-ml-status">—</span>
      </div>
      <div class="scfg-row">
        <div class="scfg-label">Enterprise Engines<div class="scfg-hint">Correlation, auto-response, baseline, and decay threads.</div></div>
        <span style="font-family:var(--font-mono);font-size:10px;font-weight:700;padding:3px 10px;border-radius:4px;background:rgba(0,200,255,.07);border:1px solid rgba(0,200,255,.2);color:#00c8ff">4 ACTIVE</span>
      </div>
      <div class="scfg-row">
        <div class="scfg-label">API Version<div class="scfg-hint">Current PacketGuard backend API version.</div></div>
        <span style="font-family:var(--font-mono);font-size:11px;color:#3a5570">v2.1.0-stable</span>
      </div>
    </div>

    <!-- NOTIFICATIONS TAB -->
    <div class="stab-panel" id="spanel-notifications">
      <div class="scfg-section-title">// ALERT THRESHOLDS</div>
      <div class="scfg-row">
        <div class="scfg-label">Pop-up Notifications<div class="scfg-hint">Desktop notifications shown for incoming HIGH/CRITICAL alerts.</div></div>
        <label class="stoggle"><input type="checkbox" id="cfg-notif-popup" checked onchange="saveCfgToggle('notif_popup',this.checked)"><span class="stoggle-slider"></span></label>
      </div>
      <div class="scfg-row">
        <div class="scfg-label">Sound on Critical<div class="scfg-hint">Play an audio cue when a CRITICAL severity alert arrives.</div></div>
        <label class="stoggle"><input type="checkbox" id="cfg-notif-sound" onchange="saveCfgToggle('notif_sound',this.checked)"><span class="stoggle-slider"></span></label>
      </div>
      <div class="scfg-row">
        <div class="scfg-label">Minimum Severity<div class="scfg-hint">Suppress notifications below this severity level.</div></div>
        <select id="cfg-min-severity" name="cfg-min-severity" style="background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.1);color:#c0d4ee;border-radius:5px;padding:5px 10px;font-family:var(--font-mono);font-size:11px;cursor:pointer">
          <option>HIGH &amp; CRITICAL</option>
          <option>MEDIUM and above</option>
          <option>ALL</option>
        </select>
      </div>

      <div class="scfg-section-title" style="margin-top:22px">// EMAIL ALERTS</div>
      <div class="scfg-row">
        <div class="scfg-label">SMTP Status<div class="scfg-hint">Whether the email alert pipeline is configured and active.</div></div>
        <span id="smtp-status-badge" style="font-family:var(--font-mono);font-size:10px;font-weight:700;padding:3px 10px;border-radius:4px;background:rgba(255,184,0,.06);border:1px solid rgba(255,184,0,.2);color:#ffb800">CHECKING…</span>
      </div>
      <div class="scfg-row">
        <div class="scfg-label">Alert Recipient<div class="scfg-hint">Email address that receives automatic threat notifications.</div></div>
        <input type="email" id="cfg-alert-email" name="cfg-alert-email" placeholder="admin@domain.com" style="background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08);color:#c0d4ee;border-radius:5px;padding:5px 10px;font-family:var(--font-mono);font-size:11px;width:190px;outline:none" onfocus="this.style.borderColor='rgba(0,200,255,.4)'" onblur="this.style.borderColor='rgba(255,255,255,.08)'">
      </div>
      <div style="margin-top:10px">
        <button onclick="sendTestEmail()" style="background:rgba(0,200,255,.07);border:1px solid rgba(0,200,255,.22);color:#00c8ff;border-radius:5px;padding:7px 16px;font-family:var(--font-mono);font-size:10px;font-weight:700;cursor:pointer;letter-spacing:1px">SEND TEST EMAIL</button>
      </div>
    </div>

    <!-- SECURITY TAB -->
    <div class="stab-panel" id="spanel-security">
      <div class="scfg-section-title">// ACTIVE SESSION</div>
      <div class="scfg-row">
        <div class="scfg-label">Logged In As<div class="scfg-hint">Currently authenticated operator.</div></div>
        <div style="text-align:right">
          <div style="font-family:var(--font-mono);font-size:11px;color:#c0d4ee" id="scfg-username">—</div>
          <div style="font-family:var(--font-mono);font-size:10px;color:#3a5570" id="scfg-useremail">—</div>
        </div>
      </div>
      <div class="scfg-row">
        <div class="scfg-label">Access Level<div class="scfg-hint">Role-based permission tier assigned to this account.</div></div>
        <span style="font-family:var(--font-mono);font-size:10px;font-weight:700;padding:3px 10px;border-radius:4px" id="scfg-role-badge">—</span>
      </div>
      <div class="scfg-row">
        <div class="scfg-label">Session Duration<div class="scfg-hint">Time elapsed since the current login session began.</div></div>
        <span style="font-family:var(--font-mono);font-size:12px;color:#00ff88" id="scfg-session-time">—</span>
      </div>

      <div class="scfg-section-title" style="margin-top:22px">// AUTHENTICATION</div>
      <div class="scfg-row">
        <div class="scfg-label">Session Lifetime<div class="scfg-hint">Maximum duration before the session token expires.</div></div>
        <span style="font-family:var(--font-mono);font-size:10px;color:#c0d4ee">24 hours</span>
      </div>
      <div style="margin-top:14px;display:flex;gap:8px">
        <button onclick="window.location.href='/profile'" style="background:rgba(0,200,255,.07);border:1px solid rgba(0,200,255,.22);color:#00c8ff;border-radius:5px;padding:7px 16px;font-family:var(--font-mono);font-size:10px;font-weight:700;cursor:pointer;letter-spacing:1px">EDIT PROFILE</button>
        <button onclick="doLogout()" style="background:rgba(255,45,85,.06);border:1px solid rgba(255,45,85,.22);color:#ff2d55;border-radius:5px;padding:7px 16px;font-family:var(--font-mono);font-size:10px;font-weight:700;cursor:pointer;letter-spacing:1px">END SESSION</button>
      </div>
    </div>

    <!-- USER MANAGEMENT TAB (admin only) -->
    <div class="stab-panel" id="spanel-users">

      <!-- Header -->
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px">
        <div>
          <div style="font-family:var(--font-mono);font-size:11px;font-weight:700;color:#00c8ff;letter-spacing:2px">ACCESS CONTROL</div>
          <div style="font-family:var(--font-mono);font-size:9px;color:#3a5570;letter-spacing:1px;margin-top:2px">OPERATOR REGISTRY &amp; ROLE MANAGEMENT</div>
        </div>
        <div style="font-family:var(--font-mono);font-size:9px;color:#3a5570;letter-spacing:1px" id="as-timestamp">—</div>
      </div>

      <!-- Stats row -->
      <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:18px">
        <div class="scfg-stat-box" style="border-color:rgba(0,200,255,.2);text-align:center">
          <div class="scfg-stat-val" id="as-total" style="color:#00c8ff;font-size:22px">—</div>
          <div class="scfg-stat-lbl" style="letter-spacing:1.5px">TOTAL OPERATORS</div>
        </div>
        <div class="scfg-stat-box" style="border-color:rgba(0,200,255,.15);text-align:center">
          <div class="scfg-stat-val" id="as-admin" style="color:#00c8ff;font-size:22px">—</div>
          <div class="scfg-stat-lbl" style="letter-spacing:1.5px">ADMINISTRATORS</div>
        </div>
        <div class="scfg-stat-box" style="border-color:rgba(176,96,255,.2);text-align:center">
          <div class="scfg-stat-val" id="as-analyst" style="color:#b060ff;font-size:22px">—</div>
          <div class="scfg-stat-lbl" style="letter-spacing:1.5px">ANALYSTS</div>
        </div>
      </div>

      <!-- Divider -->
      <div style="border-top:1px solid rgba(255,255,255,.04);margin-bottom:16px"></div>

      <!-- Provision new operator -->
      <div style="font-family:var(--font-mono);font-size:9px;font-weight:700;color:#3a5570;letter-spacing:2px;margin-bottom:10px">// PROVISION NEW OPERATOR</div>
      <div style="background:rgba(0,200,255,.03);border:1px solid rgba(0,200,255,.08);border-radius:8px;padding:14px;margin-bottom:18px">
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:8px">
          <div>
            <div style="font-family:var(--font-mono);font-size:9px;color:#3a5570;letter-spacing:1px;margin-bottom:4px">FULL NAME</div>
            <input id="an-name" placeholder="e.g. Jane Smith" autocomplete="off" class="scfg-input" style="width:100%;box-sizing:border-box"/>
          </div>
          <div>
            <div style="font-family:var(--font-mono);font-size:9px;color:#3a5570;letter-spacing:1px;margin-bottom:4px">EMAIL ADDRESS</div>
            <input id="an-email" placeholder="operator@company.com" type="email" autocomplete="off" class="scfg-input" style="width:100%;box-sizing:border-box"/>
          </div>
        </div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:10px">
          <div>
            <div style="font-family:var(--font-mono);font-size:9px;color:#3a5570;letter-spacing:1px;margin-bottom:4px">PASSWORD</div>
            <input id="an-pw" placeholder="Min. 6 characters" type="password" class="scfg-input" style="width:100%;box-sizing:border-box"/>
          </div>
          <div>
            <div style="font-family:var(--font-mono);font-size:9px;color:#3a5570;letter-spacing:1px;margin-bottom:4px">CLEARANCE LEVEL</div>
            <select id="an-role" class="scfg-input" style="cursor:pointer;width:100%;box-sizing:border-box">
              <option value="analyst">🔍 ANALYST</option>
              <option value="admin">⚡ ADMIN</option>
            </select>
          </div>
        </div>
        <button id="an-create-btn" onclick="adminCreateUser()" style="width:100%;background:linear-gradient(135deg,rgba(0,200,255,.12),rgba(176,96,255,.06));border:1px solid rgba(0,200,255,.25);color:#00c8ff;border-radius:6px;padding:10px;font-family:var(--font-mono);font-size:10px;font-weight:700;letter-spacing:2px;cursor:pointer;transition:all .2s" onmouseover="this.style.borderColor='rgba(0,200,255,.5)'" onmouseout="this.style.borderColor='rgba(0,200,255,.25)'">+ PROVISION OPERATOR</button>
      </div>

      <!-- Search + filter -->
      <div style="font-family:var(--font-mono);font-size:9px;font-weight:700;color:#3a5570;letter-spacing:2px;margin-bottom:10px">// REGISTERED OPERATORS</div>
      <div style="display:flex;gap:6px;margin-bottom:12px">
        <input class="scfg-input" style="flex:1" placeholder="Search by name, email or ID…" oninput="adminFilterSearch(this.value)"/>
        <select id="admin-role-filter" name="admin-role-filter" class="scfg-input" style="width:120px;cursor:pointer" onchange="adminFilterRole(this.value)">
          <option value="">All Roles</option>
          <option value="admin"> Admin</option>
          <option value="analyst"> Analyst</option>
        </select>
        <button onclick="adminLoadUsers()" title="Refresh" style="width:34px;height:34px;border-radius:5px;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08);color:#3a5570;cursor:pointer;font-size:14px;transition:all .2s" onmouseover="this.style.color='#00c8ff';this.style.borderColor='rgba(0,200,255,.3)'" onmouseout="this.style.color='#3a5570';this.style.borderColor='rgba(255,255,255,.08)'">⟳</button>
      </div>

      <!-- User table -->
      <div style="overflow-x:auto;border:1px solid rgba(255,255,255,.05);border-radius:8px">
        <table class="apm-table" style="min-width:420px">
          <thead><tr>
            <th style="width:40px">ID</th>
            <th>OPERATOR</th>
            <th style="width:100px">CLEARANCE</th>
            <th style="width:110px">JOINED / LAST</th>
            <th style="width:110px;text-align:right">ACTIONS</th>
          </tr></thead>
          <tbody id="admin-users-tbody">
            <tr class="apm-empty"><td colspan="5">Initializing…</td></tr>
          </tbody>
        </table>
      </div>

      <!-- Role legend -->
      <div style="display:flex;gap:16px;margin-top:14px;padding:10px 12px;background:rgba(255,255,255,.02);border:1px solid rgba(255,255,255,.04);border-radius:6px">
        <div style="font-family:var(--font-mono);font-size:9px"><span style="color:#00c8ff;font-weight:700">⚡ ADMIN</span><span style="color:#3a5570;margin-left:6px">Full system access</span></div>
        <div style="font-family:var(--font-mono);font-size:9px"><span style="color:#b060ff;font-weight:700">🔍 ANALYST</span><span style="color:#3a5570;margin-left:6px">Read + response actions</span></div>
      </div>
    </div>

  </div><!-- /drawer body -->
</aside>

=======
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
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

<<<<<<< HEAD

    <!-- ── Blocked IPs Panel ──────────────────────────────────── -->
    <div class="panel blocked-panel" style="border-color:rgba(255,45,85,.2);margin-bottom:18px">
      <div class="panel-head">
        <span class="panel-title" style="color:#ff2d55">🛡 Blocked IPs</span>
        <span class="panel-badge" id="blocked-badge" style="background:rgba(255,45,85,.15);color:#ff2d55">0 active</span>
        <span id="block-sync-badge" style="margin-left:8px;font-family:var(--font-mono);font-size:9px;opacity:.7"></span>
      </div>
      <div class="panel-body" style="padding:14px 18px 18px">
        <div class="fw-status-bar" id="fw-status-bar">
          <div class="fw-stat"><span class="fw-stat-val" id="fw-active-count">—</span><span class="fw-stat-lbl">ACTIVE BLOCKS</span></div>
          <div class="fw-stat"><span class="fw-stat-val" id="fw-real-count" style="color:#ffb800">—</span><span class="fw-stat-lbl">REAL FIREWALL</span></div>
          <div class="fw-stat"><span class="fw-stat-val" id="fw-total-count" style="color:var(--dim)">—</span><span class="fw-stat-lbl">TOTAL BLOCKED</span></div>
          <div style="margin-left:auto;display:flex;align-items:center">
            <span class="fw-enforcement" id="fw-enforcement-label">Loading...</span>
          </div>
        </div>
        <!-- Manual block form (admin only, shown after login) -->
        <div id="manual-block-form" style="display:none;margin:12px 0;padding:12px 14px;background:rgba(255,45,85,.05);border:1px solid rgba(255,45,85,.2);border-radius:6px">
          <div style="font-family:var(--font-mono);font-size:9px;color:#ff2d55;letter-spacing:1px;margin-bottom:8px">⊕ MANUAL BLOCK</div>
          <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">
            <input id="block-ip-input" type="text" placeholder="IP address (e.g. 1.2.3.4)"
              style="flex:1;min-width:160px;background:rgba(0,0,0,.4);border:1px solid rgba(255,45,85,.3);color:#e0e8ff;
                     padding:6px 10px;border-radius:4px;font-family:var(--font-mono);font-size:11px;outline:none"/>
            <select id="block-sev-select"
              style="background:rgba(0,0,0,.4);border:1px solid rgba(255,45,85,.3);color:#e0e8ff;
                     padding:6px 10px;border-radius:4px;font-family:var(--font-mono);font-size:11px;outline:none">
              <option value="HIGH">HIGH</option>
              <option value="CRITICAL">CRITICAL</option>
              <option value="MEDIUM">MEDIUM</option>
            </select>
            <input id="block-reason-input" type="text" placeholder="Reason (optional)"
              style="flex:2;min-width:180px;background:rgba(0,0,0,.4);border:1px solid rgba(255,45,85,.3);color:#e0e8ff;
                     padding:6px 10px;border-radius:4px;font-family:var(--font-mono);font-size:11px;outline:none"/>
            <button onclick="manualBlockIP()"
              style="background:rgba(255,45,85,.15);border:1px solid rgba(255,45,85,.5);color:#ff2d55;
                     padding:6px 16px;border-radius:4px;font-family:var(--font-mono);font-size:10px;
                     font-weight:700;letter-spacing:1px;cursor:pointer;white-space:nowrap">
              BLOCK IP
            </button>
          </div>
        </div>
        <table class="blocked-table">
          <thead><tr>
            <th>IP</th><th>Reason</th><th>Severity</th><th>Confidence</th>
            <th>Blocked At</th><th>Expires</th><th>Type / Source</th><th>Action</th>
          </tr></thead>
          <tbody id="blocked-table-body">
            <tr><td colspan="8" style="color:var(--dim);padding:12px 8px">Loading...</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- ── Whitelist Management Panel ───────────────────────── -->
    <div class="panel" id="whitelist-panel" style="border-color:rgba(0,200,255,.18);margin-bottom:18px;display:none">
      <div class="panel-head">
        <span class="panel-title" style="color:#00c8ff">🔐 IP Whitelist</span>
        <span class="panel-badge" id="whitelist-badge">0 entries</span>
      </div>
      <div class="panel-body" style="padding:14px 18px 18px">
        <!-- Add to whitelist form -->
        <div style="margin-bottom:12px;padding:10px 14px;background:rgba(0,200,255,.05);border:1px solid rgba(0,200,255,.2);border-radius:6px">
          <div style="font-family:var(--font-mono);font-size:9px;color:#00c8ff;letter-spacing:1px;margin-bottom:8px">⊕ ADD TO WHITELIST</div>
          <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">
            <input id="wl-ip-input" type="text" placeholder="IP address (e.g. 192.168.1.10)"
              style="flex:1;min-width:160px;background:rgba(0,0,0,.4);border:1px solid rgba(0,200,255,.3);color:#e0e8ff;
                     padding:6px 10px;border-radius:4px;font-family:var(--font-mono);font-size:11px;outline:none"/>
            <input id="wl-note-input" type="text" placeholder="Note (e.g. Trusted server)"
              style="flex:2;min-width:160px;background:rgba(0,0,0,.4);border:1px solid rgba(0,200,255,.3);color:#e0e8ff;
                     padding:6px 10px;border-radius:4px;font-family:var(--font-mono);font-size:11px;outline:none"/>
            <button onclick="addToWhitelist()"
              style="background:rgba(0,200,255,.15);border:1px solid rgba(0,200,255,.5);color:#00c8ff;
                     padding:6px 16px;border-radius:4px;font-family:var(--font-mono);font-size:10px;
                     font-weight:700;letter-spacing:1px;cursor:pointer;white-space:nowrap">
              ADD
            </button>
          </div>
        </div>
        <table class="blocked-table">
          <thead><tr>
            <th>IP Address</th><th>Note</th><th>Action</th>
          </tr></thead>
          <tbody id="whitelist-table-body">
            <tr><td colspan="3" style="color:var(--dim);padding:12px 8px">Loading...</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- ── GeoIP Threat Map ──────────────────────────────────── -->
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
    <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
    <div class="panel geo-panel" style="border-color:rgba(0,200,255,.15)">
      <div class="panel-head">
        <span class="panel-title" style="color:#00c8ff">🌍 GeoIP Threat Map</span>
        <span class="panel-badge" id="geo-badge">Loading...</span>
      </div>
      <div class="panel-body" style="padding:14px 18px 18px">
        <div id="threat-map"></div>
        <table class="geo-ip-table" style="margin-top:14px">
          <thead><tr>
            <th>IP</th><th>Country</th><th>City</th><th>ISP</th><th>Severity</th><th>Hits</th>
          </tr></thead>
          <tbody id="geo-table-body">
            <tr><td colspan="6" style="color:var(--dim);padding:12px 8px">Loading geo data...</td></tr>
          </tbody>
        </table>
      </div>
    </div>


<!-- ── User Info Card ─────────────────────────────────────────── -->
<div style="margin:18px 0;padding:16px 24px;background:rgba(0,200,255,.03);border:1px solid rgba(0,200,255,.12);border-radius:10px;display:flex;align-items:center;gap:24px">
  <div style="width:42px;height:42px;border-radius:50%;background:linear-gradient(135deg,rgba(0,200,255,.2),rgba(176,96,255,.15));border:1px solid rgba(0,200,255,.3);display:flex;align-items:center;justify-content:center;font-family:var(--font-mono);font-size:16px;font-weight:700;color:#00c8ff" id="hdr-avatar">?</div>
  <div>
    <div style="font-weight:700;font-size:14px" id="hdr-name">Loading…</div>
    <div style="font-size:11px;color:var(--dim);font-family:var(--font-mono)" id="hdr-email">—</div>
  </div>
  <div style="margin-left:8px">
    <div style="font-size:9px;letter-spacing:2px;text-transform:uppercase;color:var(--dim);font-family:var(--font-mono)">Access Level</div>
    <div style="font-family:var(--font-mono);font-size:12px;font-weight:700;margin-top:2px" id="hdr-access">—</div>
  </div>
  <div style="margin-left:8px">
    <div style="font-size:9px;letter-spacing:2px;text-transform:uppercase;color:var(--dim);font-family:var(--font-mono)">Session</div>
    <div style="font-family:var(--font-mono);font-size:12px;color:var(--accent3);margin-top:2px" id="hdr-session-time">—</div>
  </div>
  <div style="margin-left:auto;display:flex;align-items:center;gap:10px">
    <div style="width:8px;height:8px;border-radius:50%;background:#00ff88;box-shadow:0 0 6px #00ff88"></div>
    <span id="hdr-role-pill" style="font-family:var(--font-mono);font-size:10px;font-weight:700;padding:3px 10px;border-radius:20px;letter-spacing:1px">—</span>
  </div>
</div>

<!-- ══════════════════════════════════════════════════════════════ -->
<!-- ── ENTERPRISE INTELLIGENCE SECTION ──────────────────────── -->
<!-- ══════════════════════════════════════════════════════════════ -->
<div class="ent-section">

  <!-- Section Header -->
  <div class="ent-section-header">
    <div class="ent-section-title">
      <span class="ent-bracket">[</span>
      <span class="ent-title-text">ENTERPRISE INTELLIGENCE</span>
      <span class="ent-bracket">]</span>
    </div>
    <div class="ent-header-meta">
      <span class="ent-meta-pill" id="ent-engine-status">
        <span class="ent-pulse-dot"></span>ENGINES ONLINE
      </span>
      <span class="ent-meta-divider">|</span>
      <span class="ent-meta-label">MODULE v2.1</span>
    </div>
  </div>

  <!-- ── KPI Strip ─────────────────────────────────────────────── -->
  <div class="ent-kpi-strip">
    <div class="ent-kpi-card ent-kpi-critical">
      <div class="ent-kpi-glow"></div>
      <div class="ent-kpi-icon">⚠</div>
      <div class="ent-kpi-body">
        <div class="ent-kpi-value" id="ent-incidents">—</div>
        <div class="ent-kpi-label">OPEN INCIDENTS</div>
        <div class="ent-kpi-sub">ACTIVE THREATS</div>
      </div>
      <div class="ent-kpi-bar-accent" style="background:#ff2d55"></div>
    </div>
    <div class="ent-kpi-card ent-kpi-warn">
      <div class="ent-kpi-glow"></div>
      <div class="ent-kpi-icon">◈</div>
      <div class="ent-kpi-body">
        <div class="ent-kpi-value" id="ent-critical">—</div>
        <div class="ent-kpi-label">CRITICAL IPs</div>
        <div class="ent-kpi-sub">HOSTILE SOURCES</div>
      </div>
      <div class="ent-kpi-bar-accent" style="background:#ffb800"></div>
    </div>
    <div class="ent-kpi-card ent-kpi-purple">
      <div class="ent-kpi-glow"></div>
      <div class="ent-kpi-icon">⟳</div>
      <div class="ent-kpi-body">
        <div class="ent-kpi-value" id="ent-actions">—</div>
        <div class="ent-kpi-label">AUTO-ACTIONS</div>
        <div class="ent-kpi-sub">LAST 24 HOURS</div>
      </div>
      <div class="ent-kpi-bar-accent" style="background:#b060ff"></div>
    </div>
    <div class="ent-kpi-card ent-kpi-cyan">
      <div class="ent-kpi-glow"></div>
      <div class="ent-kpi-icon">◉</div>
      <div class="ent-kpi-body">
        <div class="ent-kpi-value" id="ent-anomalies">—</div>
        <div class="ent-kpi-label">ANOMALIES</div>
        <div class="ent-kpi-sub">LAST 24 HOURS</div>
      </div>
      <div class="ent-kpi-bar-accent" style="background:#00c8ff"></div>
    </div>
  </div>

  <!-- ── Incidents Table ───────────────────────────────────────── -->
  <div class="ent-panel">
    <div class="ent-panel-header">
      <div class="ent-panel-title-group">
        <div class="ent-panel-indicator" style="background:#ff2d55;box-shadow:0 0 8px #ff2d55"></div>
        <span class="ent-panel-title">ACTIVE INCIDENTS</span>
        <span class="ent-panel-count" id="incident-count-badge">—</span>
      </div>
      <div style="display:flex;align-items:center;gap:8px">
        <span class="ent-live-tag">● LIVE</span>
        <button class="ent-icon-btn" onclick="loadIncidents()" title="Refresh">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M23 4v6h-6M1 20v-6h6"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>
        </button>
      </div>
    </div>
    <div class="ent-table-wrap">
      <table class="ent-table">
        <thead>
          <tr>
            <th>INCIDENT ID</th>
            <th>SOURCE IP</th>
            <th>SEVERITY</th>
            <th>ATTACK VECTOR</th>
            <th>TTPS / CHAIN</th>
            <th>LAST SEEN</th>
            <th>ACTION</th>
          </tr>
        </thead>
        <tbody id="incidents-tbody">
          <tr><td colspan="7" class="ent-table-empty">
            <span class="ent-spinner"></span> Initializing incident feed…
          </td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <!-- ── 2-Column: Threat Scores + Top Threat Scores ──────────── -->
  <div class="ent-two-col">

    <!-- Threat Score Heatmap / Bars -->
    <div class="ent-panel">
      <div class="ent-panel-header">
        <div class="ent-panel-title-group">
          <div class="ent-panel-indicator" style="background:#ffb800;box-shadow:0 0 8px #ffb800"></div>
          <span class="ent-panel-title">THREAT INTELLIGENCE SCORES</span>
        </div>
        <span class="ent-panel-subtitle">RANKED BY RISK INDEX</span>
        <button onclick="triggerRescore()" id="rescore-btn" style="background:transparent;border:1px solid rgba(255,184,0,.4);color:#ffb800;font-size:10px;font-family:var(--font-mono);letter-spacing:.08em;padding:4px 10px;border-radius:4px;cursor:pointer;display:flex;align-items:center;gap:5px">
          <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M23 4v6h-6M1 20v-6h6"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>
          RESCORE
        </button>
      </div>
      <div id="threat-scores-list" class="ent-score-list">
        <div class="ent-loading"><span class="ent-spinner"></span>Loading…</div>
      </div>
    </div>

    <!-- Attack Chain Incidents -->
    <div class="ent-panel">
      <div class="ent-panel-header">
        <div class="ent-panel-title-group">
          <div class="ent-panel-indicator" style="background:#b060ff;box-shadow:0 0 8px #b060ff"></div>
          <span class="ent-panel-title">ATTACK CHAIN INCIDENTS</span>
        </div>
        <button class="ent-icon-btn" onclick="loadAttackChain()" title="Refresh">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M23 4v6h-6M1 20v-6h6"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>
        </button>
      </div>
      <div id="attack-chain-list" class="ent-chain-list">
        <div class="ent-loading"><span class="ent-spinner"></span>Loading…</div>
      </div>
    </div>

  </div>

  <!-- ── 2-Column: Auto Response + Baseline ───────────────────── -->
  <div class="ent-two-col">

    <!-- Auto Response Timeline -->
    <div class="ent-panel">
      <div class="ent-panel-header">
        <div class="ent-panel-title-group">
          <div class="ent-panel-indicator" style="background:#00ff88;box-shadow:0 0 8px #00ff88"></div>
          <span class="ent-panel-title">AUTO-RESPONSE TIMELINE</span>
        </div>
        <button class="ent-sweep-btn" onclick="runSweep()" id="sweep-btn">
          <svg width="10" height="10" viewBox="0 0 24 24" fill="currentColor"><polygon points="5,3 19,12 5,21"/></svg>
          RUN SWEEP
        </button>
      </div>
      <div id="auto-response-timeline" class="ent-timeline">
        <div class="ent-loading"><span class="ent-spinner"></span>Loading…</div>
      </div>
    </div>

    <!-- Baseline vs Current -->
    <div class="ent-panel">
      <div class="ent-panel-header">
        <div class="ent-panel-title-group">
          <div class="ent-panel-indicator" style="background:#00c8ff;box-shadow:0 0 8px #00c8ff"></div>
          <span class="ent-panel-title">BASELINE vs CURRENT</span>
        </div>
        <select id="baseline-metric-sel" onchange="loadBaseline()" class="ent-select">
          <option value="packets_per_sec">Packets/sec</option>
          <option value="bytes_per_sec">Bytes/sec</option>
          <option value="connections_per_sec">Connections</option>
          <option value="alerts_per_hour">Alerts/hour</option>
        </select>
      </div>
      <div class="ent-chart-area">
        <canvas id="baseline-canvas"></canvas>
      </div>
      <div class="ent-chart-legend">
        <div class="ent-legend-item">
          <svg width="22" height="8"><line x1="0" y1="4" x2="22" y2="4" stroke="#00c8ff" stroke-width="1.5" stroke-dasharray="4,3"/></svg>
          <span>BASELINE</span>
        </div>
        <div class="ent-legend-item">
          <svg width="22" height="8"><line x1="0" y1="4" x2="22" y2="4" stroke="#ff2d55" stroke-width="1.5"/></svg>
          <span>CURRENT</span>
        </div>
        <div class="ent-legend-item" id="baseline-delta-label">
          <span id="baseline-delta" style="color:#ffb800">Δ —</span>
        </div>
      </div>
    </div>

  </div>

  <!-- ── Threat Score Leaderboard (full width) ─────────────────── -->
  <div class="ent-panel">
    <div class="ent-panel-header">
      <div class="ent-panel-title-group">
        <div class="ent-panel-indicator" style="background:#00c8ff;box-shadow:0 0 8px #00c8ff"></div>
        <span class="ent-panel-title">THREAT SCORE LEADERBOARD</span>
        <span class="ent-panel-count">TOP 10 ADVERSARIES</span>
      </div>
      <span class="ent-panel-subtitle">RANKED BY COMPOSITE RISK</span>
    </div>
    <div id="threat-leaderboard-list" class="ent-leaderboard">
      <div class="ent-loading"><span class="ent-spinner"></span>Loading…</div>
    </div>
  </div>

</div>
</main>

<footer>
  <span>PacketGuard v2.1 &mdash; Network Threat Detection System</span>
=======
</main>

<footer>
  <span>Sentinel v2.1 &mdash; Network Threat Detection System &mdash; Graduation Project</span>
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
  <span id="last-updated">Last updated: --</span>
</footer>
</div>

<script>
const PALETTE    = ['#00c8ff','#ff2d55','#ffb800','#00ff88','#b060ff','#f97316'];
<<<<<<< HEAD

function openSettings(tab){
  const overlay = document.getElementById('settings-overlay');
  const drawer  = document.getElementById('settings-drawer');
  if(!overlay||!drawer) return;
  overlay.style.display = 'block';
  drawer.style.right = '0';
  if(tab) switchSettingsTab(tab);
  // Populate security tab live data
  const u = window._sessionUser;
  if(u){
    const el=(id)=>document.getElementById(id);
    if(el('scfg-username'))   el('scfg-username').textContent   = u.name  || '—';
    if(el('scfg-useremail'))  el('scfg-useremail').textContent  = u.email || '—';
    if(el('scfg-session-time')){
      const sc = document.getElementById('hdr-session-time');
      if(sc) el('scfg-session-time').textContent = sc.textContent || '—';
    }
    const roleLabel = {admin:'⚡ ADMIN',analyst:'🔍 ANALYST'};
    const roleColor = {admin:'#00c8ff',analyst:'#b060ff',viewer:'#00ff88',user:'#00ff88'};
    const roleBg    = {admin:'rgba(0,200,255,.08)',analyst:'rgba(176,96,255,.08)',viewer:'rgba(0,255,136,.06)',user:'rgba(0,255,136,.06)'};
    const rb = el('scfg-role-badge');
    if(rb){
      rb.textContent  = roleLabel[u.role] || u.role.toUpperCase();
      rb.style.color  = roleColor[u.role] || '#aaa';
      rb.style.background = roleBg[u.role] || '';
      rb.style.border = '1px solid ' + (roleColor[u.role] || '#aaa');
    }
  }
  // Populate system tab scan status
  fetch('/api/scan_status').then(r=>r.json()).then(s=>{
    const ls = document.getElementById('cfg-last-scan');
    const dc = document.getElementById('cfg-device-count');
    if(ls) ls.textContent = s.last_scan ? s.last_scan.replace('T',' ').split('.')[0] : '—';
    if(dc) dc.textContent = s.device_count ?? '—';
  }).catch(()=>{});
  fetch('/api/stats').then(r=>r.json()).then(s=>{
    const ml = document.getElementById('cfg-ml-status');
    if(ml) ml.textContent = s.model&&s.model.trained ? 'TRAINED' : 'UNTRAINED';
  }).catch(()=>{});
  // Sync settings session timer with main dashboard timer
  const sync = setInterval(()=>{
    const sc = document.getElementById('hdr-session-time');
    const st = document.getElementById('scfg-session-time');
    if(sc && st) st.textContent = sc.textContent;
    if(!document.getElementById('settings-overlay') || document.getElementById('settings-overlay').style.display==='none') clearInterval(sync);
  }, 1000);
}
function closeSettings(){
  const overlay = document.getElementById('settings-overlay');
  const drawer  = document.getElementById('settings-drawer');
  if(overlay) overlay.style.display = 'none';
  if(drawer)  drawer.style.right    = '-520px';
}
function switchSettingsTab(tab){
  document.querySelectorAll('.stab').forEach(b=>b.classList.remove('active'));
  document.querySelectorAll('.stab-panel').forEach(p=>p.classList.remove('active'));
  const btn = document.getElementById('stab-'+tab);
  const pan = document.getElementById('spanel-'+tab);
  if(btn) btn.classList.add('active');
  if(pan) pan.classList.add('active');
  if(tab==='users') { if(typeof adminLoadUsers==='function') adminLoadUsers(); }
}
document.addEventListener('keydown', e=>{ if(e.key==='Escape') closeSettings(); });

// ── Settings helper functions (defined early to avoid ReferenceError) ──
function saveCfgToggle(key,val){ try{localStorage.setItem('pg_cfg_'+key, val?'1':'0');}catch(e){} }
function saveCfgVal(key,val){ try{localStorage.setItem('pg_cfg_'+key, val);}catch(e){} }
function loadCfgToggles(){
  ['notif_popup','notif_sound','notif_email','notif_critical','notif_high',
   'notif_medium','notif_low','dark_mode','compact_mode','auto_refresh'].forEach(k=>{
    const el=document.getElementById('cfg-'+k.replace('_','-'));
    if(el){ const v=localStorage.getItem('pg_cfg_'+k); if(v!==null) el.checked=v==='1'; }
  });
}
// ── SMTP Status + Test Email ───────────────────────────────────
async function checkSmtpStatus(){
  const badge = document.getElementById('smtp-status-badge');
  if(!badge) return;
  try {
    const r = await fetch('/api/smtp-status', {credentials:'include'});
    const d = await r.json();
    if(d.configured){
      badge.textContent = 'ACTIVE';
      badge.style.background = 'rgba(0,200,255,.06)';
      badge.style.border = '1px solid rgba(0,200,255,.25)';
      badge.style.color = '#00c8ff';
    } else {
      badge.textContent = 'NOT CONFIGURED';
      badge.style.background = 'rgba(255,184,0,.06)';
      badge.style.border = '1px solid rgba(255,184,0,.2)';
      badge.style.color = '#ffb800';
    }
  } catch(e){
    badge.textContent = 'UNKNOWN';
  }
}
async function sendTestEmail(){
  const recipient = document.getElementById('cfg-alert-email')?.value?.trim();
  if(!recipient){ adminToast('✘ Enter a recipient email first.', true); return; }
  adminToast('Sending test email…');
  try {
    const r = await fetch('/api/smtp-test', {
      method:'POST', credentials:'include',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({to: recipient})
    });
    const d = await r.json();
    if(d.success) adminToast('✔ Test email sent to ' + recipient);
    else adminToast('✘ ' + (d.error||'Failed to send.'), true);
  } catch(e){ adminToast('✘ Network error.', true); }
}
// Auto-check SMTP status when settings panel opens
document.addEventListener('DOMContentLoaded', ()=>{ checkSmtpStatus(); });

// ── Desktop Push Notifications ─────────────────────────────────
(function initNotifPermission(){
  if('Notification' in window && Notification.permission==='default'){
    Notification.requestPermission();
  }
})();
function showNotification(title, body, sev){
  const enabled = localStorage.getItem('pg_cfg_notif_popup');
  if(enabled==='0') return;
  if(!('Notification' in window)) return;
  if(Notification.permission==='denied') return;
  const go = ()=>{
    const icon = sev==='CRITICAL' ? '/static/icon-critical.png' : '/static/icon-high.png';
    try{
      const n = new Notification('PacketGuard — '+title, {
        body: body,
        icon: icon,
        badge: icon,
        tag: 'pg-alert-'+Date.now(),
        requireInteraction: sev==='CRITICAL',
      });
      n.onclick = ()=>{ window.focus(); n.close(); };
      if(sev!=='CRITICAL') setTimeout(()=>n.close(), 7000);
    }catch(e){ console.warn('[PG Notif]', e); }
  };
  if(Notification.permission==='granted'){ go(); }
  else { Notification.requestPermission().then(p=>{ if(p==='granted') go(); }); }
}


=======
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
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
<<<<<<< HEAD
  // Update device count in scan info row
  const left  = document.getElementById('scan-info-left');
  const right = document.getElementById('scan-info-right');
  const btn   = document.getElementById('btn-scan-now');
  if (btn) btn.disabled = false;
  const cnt = status.device_count || 0;
  if (left) left.textContent = cnt + ' device(s) found — last scan: ' + (status.last_scan ? status.last_scan.replace('T',' ').split('.')[0] : 'pending');
  if (right) right.textContent = 'Always scanning';
=======
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
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
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
<<<<<<< HEAD
  if (!Array.isArray(mlAlerts)) mlAlerts = [];
=======
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
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
<<<<<<< HEAD
  const devs = (data.devices || []).filter(d => d.online !== false);
=======
  const devs = data.devices || [];
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
  document.getElementById('devices-badge').textContent = `${devs.length} online`;
  if(!devs.length){
    document.getElementById('device-list').innerHTML = '<p style="color:var(--dim);font-size:12px;font-family:var(--font-mono)">Scanning network...</p>';
    return;
  }
  document.getElementById('device-list').innerHTML = devs.map(d => {
<<<<<<< HEAD
    const cls         = classifyDevice(d);
=======
    const cls = classifyDevice(d);
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
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
<<<<<<< HEAD
  // Pulls the latest real alert from the backend instead of showing fake data
  fetch('/api/alerts',{credentials:'include'})
    .then(r=>r.json())
    .then(alerts=>{
      const high = alerts.filter(a=>['HIGH','CRITICAL'].includes(a.severity));
      if(high.length){ showNotif(high[0]); }
      else { showNotif({severity:'HIGH', timestamp:new Date().toISOString(), message:'No real alerts found — system is clean'}); }
    })
    .catch(()=>{});
=======
  // Fire a fake HIGH and a fake CRITICAL to test the popup
  showNotif({ severity: 'HIGH',     timestamp: new Date().toISOString(), message: 'Port scan detected from 192.168.1.99: 45 unique ports in 60s' });
  setTimeout(() => {
    showNotif({ severity: 'CRITICAL', timestamp: new Date().toISOString(), message: 'SYN flood detected from 185.220.101.45: 1200 packets/s' });
  }, 800);
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
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

<<<<<<< HEAD

// ── Session check ─────────────────────────────────────────────────
async function doLogout(){
  try{ await fetch('/api/auth/logout',{method:'POST',credentials:'include'}); }catch(e){}
  window.location.href = '/';
}

function showAdminSection(){
  const usersTab = document.getElementById('stab-users');
  if(usersTab) usersTab.style.display='flex';
  const sg = document.getElementById('hdr-settings-btn');
  if(sg){ sg.style.color='#00c8ff'; sg.style.borderColor='rgba(0,200,255,.3)'; sg.style.background='rgba(0,200,255,.07)'; }
}

(async function checkSession(){
  try{
    const r = await fetch('/api/auth/me', {credentials:'include'});
    const d = await r.json();
    if(!d.success){ window.location.href='/'; return; }
    if(d.user){
      window._userRole    = d.user.role;
      window._sessionUser = d.user;
      const u = d.user;
      const roleKey = u.role==='admin'?'admin':'analyst';
      const roleLabel = {admin:'⚡ ADMIN',analyst:'🔍 ANALYST'};
      const roleColor = {admin:'#00c8ff',analyst:'#b060ff',viewer:'#00ff88',user:'#00ff88'};
      const roleBg    = {admin:'rgba(0,200,255,.1)',analyst:'rgba(176,96,255,.1)',viewer:'rgba(0,255,136,.08)',user:'rgba(0,255,136,.08)'};

      // Header role badge
      const rb = document.getElementById('hdr-role-badge');
      if(rb){ rb.textContent=roleLabel[u.role]||u.role.toUpperCase(); rb.style.color=roleColor[u.role]||'#aaa'; rb.style.background=roleBg[u.role]||''; rb.style.border='1px solid '+roleColor[u.role]; rb.style.display=''; }

      // User info card
      const av = document.getElementById('hdr-avatar');
      if(av){ av.textContent=(u.name||'?')[0].toUpperCase(); }
      const nm = document.getElementById('hdr-name');
      if(nm) nm.textContent = u.name||'—';
      const em = document.getElementById('hdr-email');
      if(em) em.textContent = u.email||'—';
      const ac = document.getElementById('hdr-access');
      if(ac){ ac.textContent=roleKey==='admin'?'FULL ACCESS':roleKey==='analyst'?'READ + ACTIONS':'READ ONLY'; ac.style.color=roleColor[u.role]||'#aaa'; }
      const rp = document.getElementById('hdr-role-pill');
      if(rp){ rp.textContent=roleLabel[u.role]||u.role; rp.style.color=roleColor[u.role]; rp.style.background=roleBg[u.role]; rp.style.border='1px solid '+roleColor[u.role]; }

      // Session timer
      const sessionStart = new Date();
      setInterval(()=>{
        const el=document.getElementById('hdr-session-time');
        if(!el)return;
        const diff=Math.floor((new Date()-sessionStart)/1000);
        const h=String(Math.floor(diff/3600)).padStart(2,'0');
        const m=String(Math.floor((diff%3600)/60)).padStart(2,'0');
        const s=String(diff%60).padStart(2,'0');
        el.textContent=h+':'+m+':'+s;
      },1000);

      // Show Users tab in Settings for admin
      if(u.role==='admin'){
        showAdminSection();
      }

      // Deduplicate runaway incidents first, then load
      fetch('/api/v1/enterprise/sweep',{method:'POST',credentials:'include'})
        .catch(()=>{})
        .finally(()=>{
          loadEnterpriseSummary();
          loadIncidents();
          loadThreatScores();
          loadAttackChain();
          loadThreatLeaderboard();
          loadAutoResponseTimeline();
          loadBaseline();
        });
    }
  }catch(e){ console.error('Session check failed:',e); }
})();

// ── Enterprise data loaders ────────────────────────────────────────
async function loadEnterpriseSummary(){
  try{
    const r=await fetch('/api/v1/enterprise/summary',{credentials:'include'});
    const d=await r.json();
    const set=(id,v)=>{const el=document.getElementById(id);if(el)el.textContent=v;};
    set('ent-incidents', d.open_incidents??'—');
    set('ent-critical',  d.critical_ips??'—');
    set('ent-actions',   d.actions_24h??'—');
    set('ent-anomalies', d.anomalies_24h??'—');
    const badge=document.getElementById('incident-count-badge');
    if(badge&&d.open_incidents!=null)badge.textContent=d.open_incidents+' OPEN';
  }catch(e){}
}


async function loadIncidents(){
  const tb=document.getElementById('incidents-tbody');
  if(!tb)return;
  try{
    const r=await fetch('/api/v1/enterprise/incidents?status=open&limit=10',{credentials:'include'});
    const rows=await r.json();
    if(!rows.length){ tb.innerHTML='<tr><td colspan="7" class="ent-table-empty">No active incidents detected</td></tr>'; return; }
    const canAct=window._userRole==='admin'||window._userRole==='analyst';
    const vectorFrom=(chain)=>{
      if(!chain)return'—';
      const lc=chain.toLowerCase();
      if(lc.includes('lateral'))return'Lateral Movement';
      if(lc.includes('ddos')||lc.includes('flood'))return'DDoS / Flood';
      if(lc.includes('scan'))return'Port Scan';
      if(lc.includes('brute'))return'Brute Force';
      if(lc.includes('exfil'))return'Data Exfiltration';
      return chain.split(':')[0]||chain;
    };
    // Store rows globally so the panel can access them
    window._incidentRows = rows;
    tb.innerHTML=rows.map((i,idx)=>{
      const sev=i.severity||'LOW';
      return `<tr class="inc-row" onclick="openIncidentPanel(${idx})" data-idx="${idx}">
        <td style="color:rgba(255,255,255,.3);font-size:9px;letter-spacing:.5px">${i.incident_id.slice(0,8).toUpperCase()}…</td>
        <td style="color:#00c8ff">${i.source_ip}</td>
        <td><span class="ent-sev ent-sev-${sev}">${sev}</span></td>
        <td style="color:var(--text);opacity:.7">${vectorFrom(i.attack_chain)}</td>
        <td style="color:var(--dim);max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${i.attack_chain||''}">${i.attack_chain||'—'}</td>
        <td style="color:rgba(255,255,255,.25)">${i.last_seen?i.last_seen.replace('T',' ').slice(0,16):'—'}</td>
        <td onclick="event.stopPropagation()">${canAct?`<button class="ent-close-btn" onclick="closeIncident('${i.incident_id}')">CLOSE</button>`:'<span style="color:var(--dim);font-size:9px">—</span>'}</td>
      </tr>`;
    }).join('');
  }catch(e){ tb.innerHTML=`<tr><td colspan="7" class="ent-table-empty">Error loading incidents</td></tr>`; }
}

// ── Incident panel helpers ──────────────────────────────────────
let _currentIncidentIdx = null;

function _sevColor(sev){
  return sev==='CRITICAL'?'#ff2d55':sev==='HIGH'?'#ffb800':sev==='MEDIUM'?'#00c8ff':'#00ff88';
}
function _riskColor(score){
  return score>=76?'#ff2d55':score>=51?'#ffb800':score>=26?'#00c8ff':'#00ff88';
}
function _riskLabel(score){
  return score>=76?'CRITICAL RISK':score>=51?'HIGH RISK':score>=26?'MEDIUM RISK':'LOW RISK';
}
function _vectorLabel(chain){
  const lc=(chain||'').toLowerCase();
  if(lc.includes('lateral'))  return 'Lateral Movement';
  if(lc.includes('ddos')||lc.includes('flood')) return 'DDoS / Flood';
  if(lc.includes('scan'))     return 'Port Scan';
  if(lc.includes('brute'))    return 'Brute Force';
  if(lc.includes('exfil'))    return 'Data Exfiltration';
  if(lc.includes('recon'))    return 'Reconnaissance';
  if(lc.includes('intrusion'))return 'Intrusion Attempt';
  if(lc.includes('multi'))    return 'Multi-Vector Attack';
  return chain?chain.split(':')[0]:' — ';
}
function _recommendedActions(sev, chain){
  const lc=(chain||'').toLowerCase();
  const actions=[];
  if(sev==='CRITICAL'||sev==='HIGH'){
    actions.push({icon:'🚫',color:'#ff2d55',bg:'rgba(255,45,85,.07)',text:'Block source IP at firewall immediately'});
  }
  if(lc.includes('scan')||lc.includes('recon')){
    actions.push({icon:'🔎',color:'#ffb800',bg:'rgba(255,184,0,.07)',text:'Review port exposure — disable unnecessary open ports'});
  }
  if(lc.includes('flood')||lc.includes('ddos')){
    actions.push({icon:'⚡',color:'#ff6400',bg:'rgba(255,100,0,.07)',text:'Enable rate-limiting on affected interfaces'});
  }
  if(lc.includes('brute')){
    actions.push({icon:'🔑',color:'#b060ff',bg:'rgba(176,96,255,.07)',text:'Enforce account lockout policy and check auth logs'});
  }
  if(lc.includes('lateral')){
    actions.push({icon:'🛡',color:'#ff2d55',bg:'rgba(255,45,85,.07)',text:'Isolate affected host — check for lateral pivot activity'});
  }
  if(lc.includes('intrusion')||lc.includes('multi')){
    actions.push({icon:'🧪',color:'#00c8ff',bg:'rgba(0,200,255,.07)',text:'Capture full packet trace for forensic analysis'});
  }
  actions.push({icon:'📋',color:'#00ff88',bg:'rgba(0,255,136,.05)',text:'Document incident and update threat intelligence feed'});
  return actions.slice(0,4);
}
function _attackTimeline(i){
  const sev=i.severity||'LOW';
  const color=_sevColor(sev);
  const chain=i.attack_chain||i.title||'Unknown';
  const t=(ts)=>ts?(ts.replace('T',' ').slice(0,16)):'—';
  const steps=[];
  if(i.first_seen) steps.push({color:'#00ff88',text:'First activity detected from '+( i.source_ip||'source'),time:t(i.first_seen)});
  if(chain.toLowerCase().includes('scan')||chain.toLowerCase().includes('recon'))
    steps.push({color:'#ffb800',text:'Port scan / reconnaissance pattern identified',time:t(i.last_seen)});
  if(i.event_count>1)
    steps.push({color:color,text:`${i.event_count} correlated events matched attack pattern`,time:t(i.last_seen)});
  steps.push({color:color,text:`Incident classified: ${chain}`,time:t(i.last_seen)});
  if(i.confidence) steps.push({color:'#b060ff',text:`Confidence score: ${i.confidence}% — escalation threshold met`,time:t(i.last_seen)});
  return steps;
}

function openIncidentPanel(idx) {
  const rows = window._incidentRows;
  if (!rows || !rows[idx]) return;
  const i = rows[idx];
  _currentIncidentIdx = idx;

  // Highlight row
  document.querySelectorAll('.inc-row').forEach(r => r.classList.remove('inc-row-selected'));
  const selRow = document.querySelector(`.inc-row[data-idx="${idx}"]`);
  if (selRow) selRow.classList.add('inc-row-selected');

  const sev       = i.severity || 'LOW';
  const sevColor  = _sevColor(sev);
  const riskScore = i.risk_score ?? i.threat_score ?? 0;
  const riskColor = _riskColor(riskScore);
  const conf      = i.confidence || 0;
  const chain     = i.attack_chain || i.title || 'Unknown';
  const body      = document.getElementById('inc-drawer-body');

  // ── Build the full drawer body ──────────────────────────────────
  const actions  = _recommendedActions(sev, chain);
  const timeline = _attackTimeline(i);
  const indicators = (i.explanation && i.explanation.length)
    ? i.explanation
    : (i.description ? [i.description] : ['No indicator details available']);

  // SVG donut for risk score
  const r=22, circ=2*Math.PI*r;
  const filled=circ*(riskScore/100);
  const riskSVG=`<svg class="inc-risk-circle" viewBox="0 0 56 56">
    <circle cx="28" cy="28" r="${r}" fill="none" stroke="rgba(255,255,255,.07)" stroke-width="5"/>
    <circle cx="28" cy="28" r="${r}" fill="none" stroke="${riskColor}" stroke-width="5"
      stroke-dasharray="${filled} ${circ}" stroke-dashoffset="${circ/4}"
      stroke-linecap="round" transform="rotate(-90 28 28)"/>
    <text x="28" y="33" text-anchor="middle" font-family="monospace" font-size="11"
      font-weight="700" fill="${riskColor}">${riskScore}</text>
  </svg>`;

  body.innerHTML = `
    <!-- ID + timestamp -->
    <div style="margin-bottom:14px">
      <div style="font-family:var(--font-mono);font-size:13px;font-weight:700;color:#ff2d55;margin-bottom:3px">${i.incident_id||'—'}</div>
      <div style="font-family:var(--font-mono);font-size:10px;color:#3a5570">
        ${i.first_seen?'First seen: '+i.first_seen.replace('T',' ').slice(0,16):''}
        ${i.last_seen?' &nbsp;·&nbsp; Last seen: '+i.last_seen.replace('T',' ').slice(0,16):''}
      </div>
    </div>

    <!-- Risk gauge -->
    <div class="inc-section-title">RISK ASSESSMENT</div>
    <div class="inc-risk-gauge">
      ${riskSVG}
      <div class="inc-risk-label">
        <div class="inc-risk-val" style="color:${riskColor}">${riskScore}<span style="font-size:13px;opacity:.5">/100</span></div>
        <div class="inc-risk-sub">${_riskLabel(riskScore)}</div>
        <div style="font-size:9px;color:#3a5570;margin-top:6px">Confidence: <span style="color:${riskColor}">${conf}%</span></div>
        <div class="inc-confidence-bar"><div class="inc-confidence-fill" style="width:${conf}%;background:${riskColor}"></div></div>
      </div>
      <div style="text-align:right">
        <div style="font-family:var(--font-mono);font-size:9px;font-weight:700;padding:3px 8px;border-radius:4px;background:${sevColor}18;border:1px solid ${sevColor}44;color:${sevColor}">${sev}</div>
        <div style="font-size:9px;color:#3a5570;margin-top:6px">STATUS</div>
        <div style="font-family:var(--font-mono);font-size:9px;color:#00ff88;margin-top:2px">● OPEN</div>
      </div>
    </div>

    <!-- Meta grid -->
    <div class="inc-section-title">INCIDENT DETAILS</div>
    <div class="inc-meta-grid">
      <div class="inc-meta-cell">
        <div class="inc-meta-cell-label">Source IP</div>
        <div class="inc-meta-cell-val" style="color:#00c8ff">${i.source_ip||'—'}</div>
      </div>
      <div class="inc-meta-cell">
        <div class="inc-meta-cell-label">Destination IP</div>
        <div class="inc-meta-cell-val" style="color:#a0b4c8">${i.dst_ip||i.destination_ip||'—'}</div>
      </div>
      <div class="inc-meta-cell">
        <div class="inc-meta-cell-label">Attack Vector</div>
        <div class="inc-meta-cell-val" style="color:${sevColor}">${_vectorLabel(chain)}</div>
      </div>
      <div class="inc-meta-cell">
        <div class="inc-meta-cell-label">TTP / Chain</div>
        <div class="inc-meta-cell-val" style="color:#a0b4c8">${chain}</div>
      </div>
    </div>

    <!-- Stats -->
    <div class="inc-stats-row" style="margin-top:8px">
      <div class="inc-stat-box">
        <div class="inc-stat-val">${i.event_count||'—'}</div>
        <div class="inc-stat-lbl">Events</div>
      </div>
      <div class="inc-stat-box">
        <div class="inc-stat-val" style="color:${riskColor}">${riskScore}</div>
        <div class="inc-stat-lbl">Risk Score</div>
      </div>
      <div class="inc-stat-box">
        <div class="inc-stat-val" style="color:#b060ff">${conf}%</div>
        <div class="inc-stat-lbl">Confidence</div>
      </div>
    </div>

    <!-- Indicators -->
    <div class="inc-section-title">DETECTION INDICATORS</div>
    <div class="inc-indicators">
      ${indicators.map(ind=>`
        <div class="inc-indicator-item">
          <div class="inc-indicator-dot" style="background:${sevColor}"></div>
          <div>${ind}</div>
        </div>`).join('')}
    </div>

    <!-- Attack Timeline -->
    <div class="inc-section-title">ATTACK TIMELINE</div>
    <div class="inc-timeline">
      ${timeline.map(step=>`
        <div class="inc-timeline-item">
          <div class="inc-timeline-dot" style="border-color:${step.color};background:${step.color}22"></div>
          <div class="inc-timeline-content">
            <div class="inc-timeline-text">${step.text}</div>
            <div class="inc-timeline-time">${step.time}</div>
          </div>
        </div>`).join('')}
    </div>

    <!-- Recommended Actions -->
    <div class="inc-section-title">RECOMMENDED ACTIONS</div>
    ${actions.map(a=>`
      <div class="inc-rec-action" style="background:${a.bg};border-color:${a.color}33;color:#a0b4c8">
        <span class="inc-rec-icon">${a.icon}</span>
        <span>${a.text}</span>
      </div>`).join('')}

    <!-- Description -->
    ${i.description?`
    <div class="inc-section-title">ANALYST NOTES</div>
    <div style="font-size:11px;color:#7a8fa8;line-height:1.7;padding:10px 12px;background:rgba(0,0,0,.2);border-radius:6px;border:1px solid rgba(255,255,255,.05)">${i.description}</div>`:''}

    <!-- AI output placeholder -->
    <div class="inc-ai-output" id="inc-ai-output"></div>

    <!-- Actions -->
    <div class="inc-action-row">
      <button class="inc-btn inc-btn-investigate" id="inc-btn-investigate" onclick="investigateIncident()">
        🔍 AI Analyze
      </button>
      <button class="inc-btn inc-btn-close" onclick="closeIncidentFromPanel()">✓ Close</button>
      <button class="inc-btn inc-btn-danger" onclick="closeIncidentPanel()">✕ Dismiss</button>
    </div>
  `;

  // Open panel
  document.getElementById('inc-overlay').classList.add('open');
  document.getElementById('inc-drawer').classList.add('open');
  document.body.style.overflow = 'hidden';
}

function closeIncidentPanel() {
  document.getElementById('inc-overlay').classList.remove('open');
  document.getElementById('inc-drawer').classList.remove('open');
  document.body.style.overflow = '';
  document.querySelectorAll('.inc-row').forEach(r => r.classList.remove('inc-row-selected'));
  _currentIncidentIdx = null;
}

async function closeIncidentFromPanel() {
  const rows = window._incidentRows;
  if (_currentIncidentIdx === null || !rows) return;
  const i = rows[_currentIncidentIdx];
  closeIncidentPanel();
  await closeIncident(i.incident_id);
}

// ── AI-powered Investigate (calls Anthropic API) ────────────────
async function investigateIncident() {
  const rows = window._incidentRows;
  if (_currentIncidentIdx === null || !rows) return;
  const i = rows[_currentIncidentIdx];

  const btn   = document.getElementById('inc-btn-investigate');
  const aiOut = document.getElementById('inc-ai-output');
  if (!btn || !aiOut) return;

  btn.disabled = true;
  btn.innerHTML = '<span class="inc-ai-spinner"></span> Analyzing…';
  aiOut.textContent = '';
  aiOut.classList.add('visible');

  const prompt = `You are a senior SOC analyst. Analyze this network security incident and provide a structured threat assessment:

Incident ID: ${i.incident_id}
Source IP: ${i.source_ip}
Severity: ${i.severity || 'UNKNOWN'}
Attack Chain / TTP: ${i.attack_chain || i.title || 'Unknown'}
Risk Score: ${i.risk_score ?? i.threat_score ?? 'Unknown'}/100
Confidence: ${i.confidence ?? 'Unknown'}%
Event Count: ${i.event_count ?? 'Unknown'}
First Seen: ${i.first_seen || 'Unknown'}
Last Seen: ${i.last_seen || 'Unknown'}
Detection Indicators: ${(i.explanation||[]).join('; ') || i.description || 'None'}

Provide a concise SOC investigation report with:
1. THREAT SUMMARY (2-3 sentences — what is happening)
2. ATTACKER INTENT (what they are likely trying to achieve)
3. IMMEDIATE ACTIONS (3 specific steps the analyst should take RIGHT NOW)
4. INVESTIGATION STEPS (2-3 things to check in logs/network)
5. OVERALL RISK: Low / Medium / High / Critical

Be direct and actionable. Use plain text, no markdown symbols.`;

  try {
    const response = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "claude-sonnet-4-20250514",
        max_tokens: 600,
        messages: [{ role: "user", content: prompt }]
      })
    });
    const data = await response.json();
    if (data.content && data.content[0] && data.content[0].text) {
      aiOut.textContent = data.content[0].text.trim();
    } else if (data.error) {
      aiOut.textContent = "API Error: " + (data.error.message || JSON.stringify(data.error));
    } else {
      aiOut.textContent = "No analysis returned.";
    }
  } catch (err) {
    aiOut.textContent = "Network error: " + err.message;
  }

  btn.disabled = false;
  btn.innerHTML = '🔍 Re-analyze';
}

async function closeIncident(id){
  if(!confirm('Close incident '+id+'?'))return;
  try{
    const r=await fetch('/api/v1/enterprise/incidents/'+id+'/close',{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'},body:JSON.stringify({analyst_notes:'Closed from dashboard'})});
    const d=await r.json();
    if(d.success){loadIncidents();loadEnterpriseSummary();}
  }catch(e){}
}

async function triggerRescore(){
  const btn=document.getElementById('rescore-btn');
  const svgIcon='<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M23 4v6h-6M1 20v-6h6"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>';
  if(btn){btn.innerHTML=svgIcon+' SCORING…';btn.disabled=true;}
  try{
    const r=await fetch('/api/v1/enterprise/rescore',{method:'POST',credentials:'include'});
    const d=await r.json();
    console.log('[RESCORE]',d);
    if(d.success){
      // Brief "done" confirmation with IP count
      if(btn){btn.innerHTML=svgIcon+` ✓ ${d.ips_scored} IPs`;btn.style.color='#00ff88';btn.style.borderColor='rgba(0,255,136,.4)';}
      setTimeout(()=>{loadThreatScores();loadThreatLeaderboard();loadEnterpriseSummary();loadAutoResponseTimeline();},800);
    }
  }catch(e){console.error('[RESCORE]',e);}
  setTimeout(()=>{
    if(btn){
      btn.innerHTML=svgIcon+' RESCORE';
      btn.style.color='#ffb800';
      btn.style.borderColor='rgba(255,184,0,.4)';
      btn.disabled=false;
    }
  },4000);
}

async function loadThreatScores(){
  const el=document.getElementById('threat-scores-list');
  if(!el)return;
  try{
    const r=await fetch('/api/v1/enterprise/threat-scores?limit=8',{credentials:'include'});
    const rows=await r.json();
    if(!rows.length){ el.innerHTML='<div class="ent-loading">No threat intelligence data</div>'; return; }
    el.innerHTML=rows.map((t,idx)=>{
      const pct=Math.min(100,t.score);
      const col=t.score>=80?'#ff2d55':t.score>=50?'#ffb800':'#00ff88';
      return `<div class="ent-score-row">
        <span class="ent-score-rank">${idx+1}</span>
        <span class="ent-score-ip">${t.ip_address}</span>
        <div class="ent-score-bar-wrap"><div class="ent-score-bar" style="width:${pct}%;background:${col}"></div></div>
        <span class="ent-score-val" style="color:${col}">${Math.round(t.score)}</span>
        <span class="ent-score-level" style="color:${col}">${t.threat_level||''}</span>
      </div>`;
    }).join('');
  }catch(e){}
}

// ── Attack Chain Incidents ─────────────────────────────────────────
async function loadAttackChain(){
  const el=document.getElementById('attack-chain-list');
  if(!el)return;
  try{
    const r=await fetch('/api/v1/enterprise/incidents?status=open&limit=8',{credentials:'include'});
    const rows=await r.json();
    if(!rows.length){ el.innerHTML='<div class="ent-loading">No active incidents</div>'; return; }
    el.innerHTML=rows.map(i=>`
      <div class="ent-chain-row">
        <span class="ent-sev ent-sev-${i.severity||'LOW'}">${i.severity||'?'}</span>
        <span class="ent-chain-ip">${i.source_ip}</span>
        <span class="ent-chain-vector" title="${i.attack_chain||''}">${i.attack_chain||'—'}</span>
        <span class="ent-chain-date">${i.last_seen?i.last_seen.split('T')[0]:'—'}</span>
      </div>`).join('');
  }catch(e){
    el.innerHTML='<div class="ent-loading">Unavailable</div>';
  }
}

// ── Threat Score Leaderboard (Top 10) ─────────────────────────────
async function loadThreatLeaderboard(){
  const el=document.getElementById('threat-leaderboard-list');
  if(!el)return;
  try{
    const r=await fetch('/api/v1/enterprise/threat-scores?limit=10',{credentials:'include'});
    const rows=await r.json();
    if(!rows.length){ el.innerHTML='<div class="ent-loading">No leaderboard data</div>'; return; }
    el.innerHTML=rows.map((t,idx)=>{
      const pct=Math.min(100,t.score);
      const col=t.score>=80?'#ff2d55':t.score>=50?'#ffb800':'#00ff88';
      const rankCls=idx===0?'ent-lb-rank-1':idx===1?'ent-lb-rank-2':idx===2?'ent-lb-rank-3':'';
      const rankSym=idx===0?'◆':idx===1?'◇':idx===2?'▸':String(idx+1);
      return `<div class="ent-lb-row">
        <span class="ent-lb-rank ${rankCls}">${rankSym}</span>
        <span class="ent-lb-ip">${t.ip_address}</span>
        <div class="ent-lb-bar-wrap"><div class="ent-lb-bar" style="width:${pct}%;background:${col}"></div></div>
        <span class="ent-lb-score" style="color:${col}">${Math.round(t.score)}</span>
        <span class="ent-lb-level" style="color:${col}">${t.threat_level||''}</span>
      </div>`;
    }).join('');
  }catch(e){
    el.innerHTML='<div class="ent-loading">Unavailable</div>';
  }
}

// ── Auto Response Timeline ─────────────────────────────────────────
async function loadAutoResponseTimeline(){
  const el=document.getElementById('auto-response-timeline');
  if(!el)return;
  const typeMap={block:'block',BLOCK:'block',quarantine:'block',QUARANTINE:'block',alert:'alert',ALERT:'alert',scan:'scan',SCAN:'scan'};
  const actionLabel={block:'BLOCKED',quarantine:'QUARANTINED',alert:'ALERTED',scan:'SCANNED',ok:'OK'};
  const render=(rows)=>{
    // Deduplicate: same IP + same minute = one entry
    const seen=new Set();
    const unique=rows.filter(a=>{
      const key=(a.source_ip||a.target_ip||'')+'|'+(a.action_type||'')+'|'+(a.created_at||'').slice(0,16);
      if(seen.has(key))return false;
      seen.add(key);return true;
    });
    el.innerHTML=unique.map(a=>{
      const type=(a.action_type||'ok').toLowerCase();
      const dot=typeMap[type]||'ok';
      const label=actionLabel[type]||type.toUpperCase();
      const ts=a.created_at?a.created_at.split('T')[1].slice(0,5):'--:--';
      const ip=a.source_ip||a.target_ip||'';
      const sev=a.severity?(' <span style="opacity:.5;font-size:9px">['+a.severity+']</span>'):'';
      return '<div class="ent-tl-row">'
        +'<div class="ent-tl-dot '+dot+'"></div>'
        +'<span class="ent-tl-time">'+ts+'</span>'
        +'<span class="ent-tl-msg">'+(ip?'<span class="ent-tl-ip">'+ip+'</span> &mdash; ':'')+label+sev+'</span>'
        +'</div>';
    }).join('');
  };
  try{
    const r=await fetch('/api/v1/enterprise/actions?limit=8',{credentials:'include'});
    if(!r.ok){ el.innerHTML='<div class="ent-loading">No response events logged</div>'; return; }
    const rows=await r.json();
    if(!rows.length){ el.innerHTML='<div class="ent-loading">No response events logged</div>'; return; }
    render(rows);
  }catch(e){
    el.innerHTML='<div class="ent-loading">No response events logged</div>';
  }
}

async function runSweep(){
  const btn=document.getElementById('sweep-btn');
  if(btn){btn.innerHTML='<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M23 4v6h-6M1 20v-6h6"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg> RUNNING…';btn.disabled=true;}
  try{ await fetch('/api/v1/enterprise/sweep',{method:'POST',credentials:'include'}); }catch(e){}
  setTimeout(()=>{
    loadAutoResponseTimeline();
    if(btn){btn.innerHTML='<svg width="10" height="10" viewBox="0 0 24 24" fill="currentColor"><polygon points="5,3 19,12 5,21"/></svg> RUN SWEEP';btn.disabled=false;}
  },1800);
}

// ── Baseline vs Current ────────────────────────────────────────────
let _baselineChart=null;
async function loadBaseline(){
  const sel=document.getElementById('baseline-metric-sel');
  const metric=sel?sel.value:'packets_per_sec';
  const canvas=document.getElementById('baseline-canvas');
  if(!canvas)return;
  const ctx=canvas.getContext('2d');
  let baselineData=[],currentData=[],labels=[];
  try{
    const r=await fetch(`/api/v1/enterprise/baseline?metric=${metric}&limit=12`,{credentials:'include'});
    const d=await r.json();
    baselineData=d.baseline||[];currentData=d.current||[];labels=d.labels||[];
  }catch(e){}
  if(!baselineData.length){
    const dEl=document.getElementById('baseline-delta');
    if(dEl){dEl.textContent='No data';dEl.style.color='var(--dim)';}
    ctx.clearRect(0,0,canvas.width,canvas.height);
    ctx.fillStyle='rgba(255,255,255,0.06)';
    ctx.font='11px monospace';
    ctx.textAlign='center';
    ctx.fillText('No baseline data available',canvas.offsetWidth/2,65);
    return;
  }
  const delta=currentData.length?Math.round((currentData[currentData.length-1]-baselineData[baselineData.length-1])/baselineData[baselineData.length-1]*100):0;
  const dEl=document.getElementById('baseline-delta');
  if(dEl){dEl.textContent=`Δ ${delta>0?'+':''}${delta}%`;dEl.style.color=delta>20?'#ff2d55':delta>5?'#ffb800':'#00ff88';}
  const w=canvas.offsetWidth||500,h=130,pad={t:10,r:10,b:22,l:38};
  canvas.width=w;canvas.height=h;
  const allV=[...baselineData,...currentData];
  const minV=Math.min(...allV)*0.88,maxV=Math.max(...allV)*1.12;
  const scX=i=>(i/(labels.length-1))*(w-pad.l-pad.r)+pad.l;
  const scY=v=>h-pad.b-(v-minV)/(maxV-minV)*(h-pad.t-pad.b);
  ctx.clearRect(0,0,w,h);
  // grid lines
  for(let i=0;i<=4;i++){
    const y=pad.t+(h-pad.t-pad.b)/4*i;
    ctx.strokeStyle='rgba(255,255,255,.04)';ctx.lineWidth=1;
    ctx.beginPath();ctx.moveTo(pad.l,y);ctx.lineTo(w-pad.r,y);ctx.stroke();
    const val=maxV-(maxV-minV)/4*i;
    ctx.fillStyle='rgba(255,255,255,.2)';ctx.font='8px monospace';ctx.textAlign='right';
    ctx.fillText(val>=1000?Math.round(val/100)/10+'k':Math.round(val),pad.l-4,y+3);
  }
  // x labels
  ctx.fillStyle='rgba(255,255,255,.25)';ctx.font='8px monospace';ctx.textAlign='center';
  [0,3,6,9,11].forEach(i=>{if(labels[i])ctx.fillText(labels[i],scX(i),h-5);});
  const drawLine=(data,color,dash=[])=>{
    ctx.beginPath();ctx.strokeStyle=color;ctx.lineWidth=1.5;ctx.setLineDash(dash);
    data.forEach((v,i)=>i===0?ctx.moveTo(scX(i),scY(v)):ctx.lineTo(scX(i),scY(v)));
    ctx.stroke();ctx.setLineDash([]);
    // area fill
    const grad=ctx.createLinearGradient(0,pad.t,0,h-pad.b);
    const fillColor=color==='#00c8ff'?'rgba(0,200,255,0.12)':'rgba(255,45,85,0.12)';
    grad.addColorStop(0,fillColor);
    grad.addColorStop(1,'rgba(0,0,0,0)');
    ctx.beginPath();
    data.forEach((v,i)=>i===0?ctx.moveTo(scX(i),scY(v)):ctx.lineTo(scX(i),scY(v)));
    ctx.lineTo(scX(data.length-1),h-pad.b);ctx.lineTo(scX(0),h-pad.b);ctx.closePath();
    ctx.fillStyle=color==='#00c8ff'?'rgba(0,200,255,0.06)':'rgba(255,45,85,0.07)';
    ctx.fill();
  };
  drawLine(baselineData,'#00c8ff',[4,3]);
  drawLine(currentData,'#ff2d55');
}

=======
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
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

<<<<<<< HEAD
refresh();  // immediate first load
setInterval(refresh, 5000);  // refresh every 5s



async function refreshBlockedIPs() {
  try {
    const [fw, blocked, syncStatus] = await Promise.all([
      fetchJSON('/api/firewall_status'),
      fetchJSON('/api/blocked_ips'),
      fetchJSON('/api/block_sync_status').catch(() => null),
    ]);

    // Show manual block form for admins
    const isAdmin = window._userRole === 'admin';
    const form = document.getElementById('manual-block-form');
    if (form) form.style.display = isAdmin ? 'block' : 'none';

    // Sync health badge
    const syncEl = document.getElementById('block-sync-badge');
    if (syncEl && syncStatus) {
      const ok = syncStatus.sync_health === 'OK';
      syncEl.textContent = ok
        ? `✓ Synced (${syncStatus.active_blocks} active)`
        : `⚠ ${syncStatus.unsynced} unsynced`;
      syncEl.style.color = ok ? '#00c06e' : '#ffb800';
      syncEl.title = ok
        ? 'All BLOCK actions are reflected in the Blocked IPs table'
        : `Unsynced IPs: ${(syncStatus.unsynced_ips||[]).join(', ')}`;
    }

    // Update stats bar
    if (fw) {
      document.getElementById('fw-active-count').textContent = fw.active_blocks ?? '—';
      document.getElementById('fw-real-count').textContent   = fw.real_blocks  ?? '—';
      document.getElementById('fw-total-count').textContent  = fw.total_blocked ?? '—';
      const envEl = document.getElementById('fw-enforcement-label');
      envEl.textContent = fw.enforcement || 'Unknown';
      envEl.style.color = fw.status === 'ACTIVE' ? '#ff2d55' : '#ffb800';
    }

    const list = Array.isArray(blocked) ? blocked : [];
    if (!list.length) {
      document.getElementById('blocked-badge').textContent = '0 active';
      document.getElementById('blocked-table-body').innerHTML =
        '<tr><td colspan="8" style="color:var(--dim);padding:12px 8px">No IPs currently blocked.</td></tr>';
      return;
    }

    const active = list.filter(b => b.status === 'active');
    document.getElementById('blocked-badge').textContent = `${active.length} active`;

    const sevColor = s => s==='CRITICAL'?'#ff2d55':s==='HIGH'?'#ffb800':s==='MEDIUM'?'#00c8ff':'#7c3aed';

    document.getElementById('blocked-table-body').innerHTML = list.slice(0,50).map(b => {
      const sc  = sevColor(b.severity);
      const isActive = b.status === 'active';
      const dot = isActive ? `<span class="blocked-ip-dot"></span>` : '';
      const exp = b.expires_at
        ? new Date(b.expires_at).toLocaleTimeString('en-GB')
        : (b.duration ? '—' : 'Permanent');
      const typeLabel = b.real_block
        ? '<span style="color:#ff2d55;font-size:8px">● REAL</span>'
        : '<span style="color:#ffb800;font-size:8px">○ LOGGED</span>';
      const srcMap = {'auto-alert':'alert','auto-correlation':'corr','auto-sweep':'sweep','auto-policy':'policy','migrated':'legacy'};
      const srcLabel = b.operator ? `<br><span style="color:var(--dim);font-size:7px">${srcMap[b.operator]||b.operator}</span>` : '';
      const unblockBtn = (isAdmin && isActive)
        ? `<button class="unblock-btn" onclick="unblockIPPrompt('${b.ip}')">UNBLOCK</button>`
        : `<span style="color:var(--dim);font-size:8px">${b.status.toUpperCase()}</span>`;
      const conf = b.confidence ? `${Math.round(b.confidence*100)}%` : '—';
      const ts   = b.blocked_at ? new Date(b.blocked_at).toLocaleTimeString('en-GB') : '—';
      return `<tr style="${isActive ? '' : 'opacity:0.4'}">
        <td style="color:#ff2d55;font-weight:700">${dot}${b.ip}</td>
        <td style="color:var(--dim);max-width:140px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${b.reason||''}">${b.reason||'—'}</td>
        <td><span style="color:${sc};font-size:8px;font-weight:700">${b.severity}</span></td>
        <td style="color:#00c8ff">${conf}</td>
        <td style="color:var(--dim)">${ts}</td>
        <td style="color:var(--dim)">${exp}</td>
        <td>${typeLabel}${srcLabel}</td>
        <td>${unblockBtn}</td>
      </tr>`;
    }).join('');
  } catch(e) {
    console.error('[BLOCKED]', e);
  }
}

async function manualBlockIP() {
  const ip     = (document.getElementById('block-ip-input').value || '').trim();
  const sev    = document.getElementById('block-sev-select').value;
  const reason = (document.getElementById('block-reason-input').value || '').trim() || 'Manual block by admin';
  if (!ip) { alert('Enter an IP address.'); return; }
  if (!confirm(`Block ${ip} (${sev})?\nReason: ${reason}`)) return;
  try {
    const res = await fetch('/api/blocked_ips/block', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      credentials: 'include',
      body: JSON.stringify({ip, severity: sev, reason, confidence: 1.0}),
    });
    const data = await res.json();
    if (data.success) {
      document.getElementById('block-ip-input').value = '';
      document.getElementById('block-reason-input').value = '';
      refreshBlockedIPs();
    } else {
      alert('Block failed: ' + (data.error || 'Unknown error'));
    }
  } catch(e) { alert('Error: ' + e); }
}

async function unblockIP(ip) {
  if (!confirm(`Unblock ${ip}? The firewall rule will be removed.`)) return;
  try {
    const res = await fetch('/api/blocked_ips/unblock', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      credentials: 'include',
      body: JSON.stringify({ip}),
    });
    const data = await res.json();
    if (data.success) { refreshBlockedIPs(); }
    else { alert('Unblock failed: ' + (data.error||'Unknown error')); }
  } catch(e) { alert('Error: ' + e); }
}

document.addEventListener('DOMContentLoaded', () => {
  setTimeout(refreshBlockedIPs, 2000);
  setInterval(refreshBlockedIPs, 30000);
  setInterval(refreshBlockedIPs, 10000);
  // Show whitelist panel for admins after session check populates _userRole
  setTimeout(() => {
    if (window._userRole === 'admin') {
      const wp = document.getElementById('whitelist-panel');
      if (wp) { wp.style.display = 'block'; refreshWhitelist(); }
      setInterval(refreshWhitelist, 60000);
    }
  }, 3000);
});

// ── Whitelist management ──────────────────────────────────────────
async function refreshWhitelist() {
  try {
    var r = await fetch('/api/whitelist', { credentials: 'include' });
    if (!r.ok) return;
    var d     = await r.json();
    var ips   = Array.isArray(d.ips) ? d.ips : [];
    var notes = d.notes || {};
    var badge = document.getElementById('wl-count');
    if (badge) badge.textContent = ips.length;
    var tbody = document.querySelector('#whitelist-table tbody');
    if (!tbody) return;
    if (!ips.length) {
      tbody.innerHTML = '<tr><td colspan="3" style="color:var(--dim);padding:12px 8px">No IPs whitelisted.</td></tr>';
      return;
    }
    var rows = '';
    for (var i = 0; i < ips.length; i++) {
      var ip   = ips[i];
      var note = (notes[ip] || '-');
      rows += '<tr>' +
        '<td style="color:#00c8ff;font-family:var(--font-mono)">' + ip + '</td>' +
        '<td style="color:var(--dim);font-family:var(--font-mono);font-size:10px">' + note + '</td>' +
        '<td><button class="unblock-btn" onclick="removeFromWhitelist(this)" data-ip="' + ip + '">REMOVE</button></td>' +
        '</tr>';
    }
    tbody.innerHTML = rows;
  } catch(e) { console.error('[WHITELIST]', e); }
}
async function addToWhitelist() {
  const ip   = (document.getElementById('wl-ip-input').value || '').trim();
  const note = (document.getElementById('wl-note-input').value || '').trim();
  if (!ip) { alert('Enter an IP address.'); return; }
  try {
    const r = await fetch('/api/whitelist', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ action: 'add', ip, note }),
    });
    const d = await r.json();
    if (d.success) {
      document.getElementById('wl-ip-input').value   = '';
      document.getElementById('wl-note-input').value = '';
      refreshWhitelist();
    } else { alert('Failed: ' + (d.error || 'Unknown error')); }
  } catch(e) { alert('Error: ' + e); }
}

async function removeFromWhitelist(btnOrIp) {
  var ip = (typeof btnOrIp === 'string') ? btnOrIp : btnOrIp.getAttribute('data-ip');
  if (!ip) return;
  try {
    await fetch('/api/whitelist', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ action: 'remove', ip: ip })
    });
    refreshWhitelist();
  } catch(e) { console.error('[WHITELIST REMOVE]', e); }
}

async function unblockIPPrompt(ip) {
  const reason = prompt('Unblock ' + ip + ' - Reason for unblocking (optional):', 'Admin review - cleared');
  if (reason === null) return;
  try {
    const res = await fetch('/api/blocked_ips/unblock', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ ip, reason }),
    });
    const data = await res.json();
    if (data.success) { refreshBlockedIPs(); }
    else { alert('Unblock failed: ' + (data.error || 'Unknown error')); }
  } catch(e) { alert('Error: ' + e); }
}


// ── GeoIP Threat Map — Professional Edition ──────────────────────
let _geoMap     = null;
let _geoLayers  = [];   // all Leaflet layers added (markers + beams)
let _pulseCSS   = null; // injected <style> for SVG pulse animations

// ── Severity config ───────────────────────────────────────────────
const SEV_CFG = {
  CRITICAL: { color: '#ff2d55', glow: 'rgba(255,45,85,0.55)',  ring: 'rgba(255,45,85,0.18)', r: 22, beam: 'rgba(255,45,85,0.55)' },
  HIGH:     { color: '#ffb800', glow: 'rgba(255,184,0,0.50)',  ring: 'rgba(255,184,0,0.15)', r: 16, beam: 'rgba(255,184,0,0.45)' },
  MEDIUM:   { color: '#00c8ff', glow: 'rgba(0,200,255,0.45)',  ring: 'rgba(0,200,255,0.12)', r: 11, beam: 'rgba(0,200,255,0.35)' },
  LOW:      { color: '#7c3aed', glow: 'rgba(124,58,237,0.40)', ring: 'rgba(124,58,237,0.10)', r: 8,  beam: 'rgba(124,58,237,0.25)' },
};
function getSevCfg(sev) { return SEV_CFG[sev] || SEV_CFG.LOW; }

// ── Build pulsing SVG icon ────────────────────────────────────────
function pulsingIcon(sev, count, maxCount) {
  const cfg  = getSevCfg(sev);
  const size = cfg.r + Math.round((count / maxCount) * 10);
  const id   = 'pulse_' + sev;
  const html = `
    <div style="position:relative;width:${size*2}px;height:${size*2}px">
      <div class="geo-pulse-ring geo-ring-${sev}" style="
        position:absolute;inset:0;border-radius:50%;
        border:2px solid ${cfg.color};
        animation:geoPulse_${sev} 2s ease-out infinite;
        pointer-events:none;"></div>
      <div style="
        position:absolute;
        top:50%;left:50%;
        transform:translate(-50%,-50%);
        width:${size}px;height:${size}px;
        border-radius:50%;
        background:radial-gradient(circle, ${cfg.color} 0%, ${cfg.glow} 60%, transparent 100%);
        box-shadow:0 0 ${size}px ${cfg.glow}, 0 0 ${size/2}px ${cfg.color};
        border:1.5px solid ${cfg.color};
        display:flex;align-items:center;justify-content:center;
        font-family:monospace;font-size:${Math.max(7,size/3)}px;font-weight:700;
        color:#fff;cursor:pointer;
        ">
        ${count > 1 ? count : ''}
      </div>
    </div>`;
  return L.divIcon({ html, className: '', iconSize: [size*2, size*2], iconAnchor: [size, size] });
}

// ── Inject pulse keyframes once ───────────────────────────────────
function ensurePulseCSS() {
  if (_pulseCSS) return;
  const styles = Object.entries(SEV_CFG).map(([sev, cfg]) => `
    @keyframes geoPulse_${sev} {
      0%   { transform:scale(0.8); opacity:0.9; }
      70%  { transform:scale(2.2); opacity:0.0; }
      100% { transform:scale(2.2); opacity:0.0; }
    }
  `).join('');
  const el = document.createElement('style');
  el.textContent = styles;
  document.head.appendChild(el);
  _pulseCSS = el;
}

// ── Draw arc beam from attacker → target ─────────────────────────
function drawBeam(map, fromLat, fromLon, toLat, toLon, sev, layers) {
  const cfg = getSevCfg(sev);
  // Animate an arc using a polyline — 20 intermediate points
  const pts = [];
  for (let i = 0; i <= 20; i++) {
    const t   = i / 20;
    const lat = fromLat + (toLat - fromLat) * t;
    const lon = fromLon + (toLon - fromLon) * t;
    // Arc height proportional to distance
    const dist = Math.sqrt(Math.pow(toLat-fromLat,2)+Math.pow(toLon-fromLon,2));
    const arcH  = Math.sin(Math.PI * t) * Math.min(dist * 0.3, 15);
    pts.push([lat + arcH, lon]);
  }
  const beam = L.polyline(pts, {
    color:   cfg.beam,
    weight:  sev === 'CRITICAL' ? 2.5 : sev === 'HIGH' ? 1.8 : 1.2,
    opacity: 0.7,
    dashArray: sev === 'CRITICAL' ? null : '6,4',
    smoothFactor: 1,
  }).addTo(map);
  layers.push(beam);
}

// ── Build popup HTML ──────────────────────────────────────────────
function buildPopup(d) {
  const cfg   = getSevCfg(d.severity);
  const flags = { CRITICAL:'🔴', HIGH:'🟠', MEDIUM:'🔵', LOW:'🟣' };
  return `
    <div style="font-family:monospace;font-size:11px;min-width:200px;line-height:1.6">
      <div style="color:${cfg.color};font-size:13px;font-weight:700;margin-bottom:6px">
        ${flags[d.severity]||'⚪'} ${d.ip}
      </div>
      <div style="color:#ccc">📍 ${d.city || 'Unknown'}, ${d.country}</div>
      <div style="color:#aaa">🏢 ${d.isp || 'Unknown ISP'}</div>
      <hr style="border-color:rgba(255,255,255,.1);margin:6px 0">
      <div style="display:flex;justify-content:space-between">
        <span style="color:rgba(255,255,255,.5)">Severity</span>
        <span style="color:${cfg.color};font-weight:700">${d.severity}</span>
      </div>
      <div style="display:flex;justify-content:space-between">
        <span style="color:rgba(255,255,255,.5)">Alerts</span>
        <span style="color:#fff;font-weight:700">${d.count}</span>
      </div>
    </div>`;
}

// ── Main init ─────────────────────────────────────────────────────
function initGeoMap() {
  if (_geoMap) return;
  ensurePulseCSS();
  try {
    _geoMap = L.map('threat-map', {
      center: [25, 15],
      zoom: 2,
      zoomControl: true,
      attributionControl: false,
      minZoom: 1,
    });
    // Dark tactical tile layer
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_nolabels/{z}/{x}/{y}{r}.png', {
      maxZoom: 18,
    }).addTo(_geoMap);
    // Subtle labels on top
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_only_labels/{z}/{x}/{y}{r}.png', {
      maxZoom: 18, opacity: 0.4,
    }).addTo(_geoMap);
  } catch(e) { console.warn('GeoMap init error:', e); }
}

// ── Refresh: fetch data, plot markers + beams ─────────────────────
async function refreshGeoMap() {
  try {
    const data = await fetchJSON('/api/geo_alerts');
    if (!data || !data.length) {
      document.getElementById('geo-badge').textContent = '0 sources';
      document.getElementById('geo-table-body').innerHTML =
        '<tr><td colspan="6" style="color:var(--dim);padding:12px 8px">No external threat sources yet. Monitoring...</td></tr>';
      return;
    }

    initGeoMap();

    // Remove all old layers
    _geoLayers.forEach(l => { try { l.remove(); } catch(_){} });
    _geoLayers = [];

    const external = data.filter(d => (d.lat || d.lon) && d.countryCode !== 'LO');
    const maxCount = Math.max(...data.map(d => d.count), 1);

    // Get user's approximate location (fallback to Cairo)
    let myLat = 30.06, myLon = 31.24;
    try {
      const myGeo = await fetch('http://ip-api.com/json/?fields=lat,lon');
      const myData = await myGeo.json();
      if (myData.lat) { myLat = myData.lat; myLon = myData.lon; }
    } catch(_) {}

    // Draw beams first (so markers sit on top)
    external.forEach(d => {
      if (d.severity === 'CRITICAL' || d.severity === 'HIGH') {
        drawBeam(_geoMap, d.lat, d.lon, myLat, myLon, d.severity, _geoLayers);
      }
    });

    // Draw "my location" marker
    const myIcon = L.divIcon({
      html: `<div style="
        width:14px;height:14px;border-radius:50%;
        background:#00ff88;
        box-shadow:0 0 12px rgba(0,255,136,0.8), 0 0 4px #00ff88;
        border:2px solid #fff;"></div>`,
      className: '', iconSize: [14,14], iconAnchor: [7,7],
    });
    const myMarker = L.marker([myLat, myLon], { icon: myIcon })
      .bindPopup('<div style="font-family:monospace;font-size:11px"><b style="color:#00ff88">📡 Your Location</b><br>Monitoring point</div>')
      .addTo(_geoMap);
    _geoLayers.push(myMarker);

    // Draw threat markers
    external.forEach(d => {
      const icon = pulsingIcon(d.severity, d.count, maxCount);
      const marker = L.marker([d.lat, d.lon], { icon })
        .bindPopup(buildPopup(d), { maxWidth: 220 })
        .addTo(_geoMap);
      _geoLayers.push(marker);
    });

    // Update badge
    const critCount = data.filter(d => d.severity === 'CRITICAL').length;
    const highCount = data.filter(d => d.severity === 'HIGH').length;
    document.getElementById('geo-badge').textContent =
      `${data.length} sources · ${critCount} critical · ${highCount} high`;

    // Update table — sorted by severity then count
    const sevOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
    const sorted = [...data].sort((a,b) =>
      (sevOrder[a.severity]||9) - (sevOrder[b.severity]||9) || b.count - a.count);

    document.getElementById('geo-table-body').innerHTML = sorted.map(d => {
      const cfg    = getSevCfg(d.severity);
      const barW   = Math.round((d.count / maxCount) * 70);
      const isLocal = d.countryCode === 'LO';
      const dot    = `<span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:${cfg.color};box-shadow:0 0 6px ${cfg.color};margin-right:5px"></span>`;
      return `<tr>
        <td style="color:#00c8ff;font-weight:700">${d.ip}</td>
        <td>${isLocal ? '🏠' : '🌍'} ${d.country}</td>
        <td style="color:var(--dim)">${d.city || '—'}</td>
        <td style="color:var(--dim);max-width:130px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${d.isp || '—'}</td>
        <td>${dot}<span style="color:${cfg.color};font-size:9px;font-weight:700">${d.severity}</span></td>
        <td style="white-space:nowrap">${d.count} <span style="display:inline-block;height:3px;width:${barW}px;background:${cfg.color};border-radius:2px;vertical-align:middle;opacity:0.7"></span></td>
      </tr>`;
    }).join('');

  } catch(e) {
    console.error('[GeoMap] Error:', e);
  }
}

// Init map on first load, refresh every 60s
document.addEventListener('DOMContentLoaded', () => {
  setTimeout(() => { initGeoMap(); refreshGeoMap(); }, 1500);
  setInterval(refreshGeoMap, 60000);
});

</script>

<!-- Admin section moved to Settings drawer → Users tab -->

<!-- Settings drawer JS + Admin user management -->
<script>
document.addEventListener('keydown', e=>{ if(e.key==='Escape') closeIncidentPanel(); });

// ── Admin user management ─────────────────────────────────────────
let _adminAllUsers=[], _adminSearch='', _adminRoleF='';

async function adminLoadUsers(){
  const tb=document.getElementById('admin-users-tbody');
  if(!tb)return;
  tb.innerHTML='<tr class="apm-empty"><td colspan="5">⟳ Loading…</td></tr>';
  try{
    const r=await fetch('/api/admin/users',{credentials:'include'});
    const d=await r.json();
    if(!d.success){tb.innerHTML=`<tr class="apm-empty"><td colspan="5" style="color:#ff2d55">⚠ ${d.error}</td></tr>`;return;}
    _adminAllUsers=d.users||[];
    adminUpdateStats();
    adminRenderTable();
  }catch(e){tb.innerHTML=`<tr class="apm-empty"><td colspan="5" style="color:#ff2d55">⚠ ${e.message}</td></tr>`;}
}
function adminUpdateStats(){
  const u=_adminAllUsers;
  let a=0,an=0;
  u.forEach(x=>{if(x.role==='admin')a++;else an++;});
  const s=(id,v)=>{const el=document.getElementById(id);if(el)el.textContent=v;};
  s('as-total',u.length); s('as-admin',a); s('as-analyst',an);
  const ts=document.getElementById('as-timestamp');
  if(ts)ts.textContent='Updated '+new Date().toLocaleTimeString();
}
function adminRenderTable(){
  const tb=document.getElementById('admin-users-tbody');
  if(!tb)return;
  const s=_adminSearch.toLowerCase(), rf=_adminRoleF;
  const me=typeof _sessionUser!=='undefined'?_sessionUser:null;
  let list=_adminAllUsers.filter(u=>{
    const ms=!s||u.name.toLowerCase().includes(s)||u.email.toLowerCase().includes(s)||String(u.id).includes(s);
    const normRole=(u.role==='user'||u.role==='viewer')?'analyst':u.role; const mr=!rf||normRole===rf;
    return ms&&mr;
  });
  if(!list.length){tb.innerHTML='<tr class="apm-empty"><td colspan="5">No operators match filter.</td></tr>';return;}
  tb.innerHTML=list.map(u=>{
    const isYou=me&&u.id===me.id;
    const rk=(u.role==='user'||u.role==='viewer')?'analyst':u.role;
    const joined=u.created_at?u.created_at.split('T')[0]:'—';
    const last=u.last_login?u.last_login.split('T')[0]:'Never';
    return `<tr class="${isYou?'is-you':''}">
      <td style="font-family:var(--font-mono);font-size:10px;color:#3a5570">#${u.id}</td>
      <td>
        <div style="font-weight:600;font-size:12px">${esc(u.name)}${isYou?' <span style="font-size:9px;color:#00c8ff;font-family:var(--font-mono)">(you)</span>':''}</div>
        <div style="font-family:var(--font-mono);font-size:10px;color:#3a5570">${esc(u.email)}</div>
      </td>
      <td><span class="rpill ${rk}">${rk.toUpperCase()}</span></td>
      <td style="font-size:10px;color:#3a5570;font-family:var(--font-mono)">${joined}<br><span style="opacity:.6">Last: ${last}</span></td>
      <td style="white-space:nowrap;text-align:right">${!isYou?`
        <select id="apm-role-${u.id}" name="apm-role-${u.id}" class="apm-role-sel" onchange="adminSetRole(${u.id},this.value,this)">
          <option value="">Role…</option>
          <option value="analyst" ${rk==='analyst'?'selected':''}>Analyst</option>
          <option value="admin"   ${rk==='admin'?'selected':''}>Admin</option>
        </select>
        <button class="abtn pw" onclick="adminResetPw(${u.id},'${esc(u.email)}')">🔑</button>
        <button class="abtn del" onclick="adminDeleteUser(${u.id},'${esc(u.email)}')">✕</button>`
        :'<span style="font-size:9px;color:#3a5570;font-family:var(--font-mono)">— you —</span>'}
      </td></tr>`;
  }).join('');
}
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function adminFilterSearch(v){_adminSearch=v;adminRenderTable();}
function adminFilterRole(v){_adminRoleF=v;adminRenderTable();}

async function adminSetRole(uid,role,sel){
  if(!role)return;
  const u=_adminAllUsers.find(x=>x.id===uid);
  const roleLabel={analyst:' ANALYST',admin:' ADMIN'}[role]||role.toUpperCase();
  const confirmed=await pgConfirm(`CHANGE ROLE`,`Reassign <strong>${u?u.name:'operator'}</strong> to <strong style="color:#00c8ff">${roleLabel}</strong>?`);
  if(!confirmed){sel.value='';return;}
  sel.disabled=true;
  const r=await fetch(`/api/admin/users/${uid}/role`,{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'},body:JSON.stringify({role})});
  const d=await r.json();
  sel.disabled=false;
  if(d.success){adminToast(`✔ Clearance updated → ${roleLabel}`);adminLoadUsers();}
  else{adminToast(`✘ ${d.error}`,true);sel.value='';}
}
async function adminDeleteUser(uid,email){
  const confirmed=await pgConfirm(`REMOVE OPERATOR`,`Permanently revoke access for <strong>${email}</strong>?<br><span style="color:#ff2d55;font-size:10px">This action cannot be undone.</span>`);
  if(!confirmed)return;
  const r=await fetch(`/api/admin/users/${uid}`,{method:'DELETE',credentials:'include'});
  const d=await r.json();
  if(d.success){adminToast(`🗑 ${email} deleted.`);adminLoadUsers();}
  else adminToast(`❌ ${d.error}`,true);
}
async function adminResetPw(uid,email){
  const pw = await pgPrompt(
    'RESET CREDENTIALS',
    `Set a new password for <strong style="color:#00c8ff">${email}</strong>`,
    'New password (min 6 characters)',
    'password'
  );
  if(!pw)return;
  if(pw.length<6){adminToast('✘ Password too short — minimum 6 characters.',true);return;}
  const r=await fetch(`/api/admin/users/${uid}/reset-password`,{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'},body:JSON.stringify({new_password:pw})});
  const d=await r.json();
  adminToast(d.success?`✔ Password updated for ${email}.`:`✘ ${d.error}`,!d.success);
}
async function adminCreateUser(){
  const name=document.getElementById('an-name').value.trim();
  const email=document.getElementById('an-email').value.trim();
  const pw=document.getElementById('an-pw').value;
  const role=document.getElementById('an-role').value;
  if(!name||!email||!pw){adminToast('❌ All fields required.',true);return;}
  if(pw.length<6){adminToast('❌ Password min 6 chars.',true);return;}
  const btn=document.getElementById('an-create-btn');
  btn.disabled=true;btn.textContent='Provisioning…';
  try{
    const r=await fetch('/api/admin/users/create',{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'},body:JSON.stringify({name,email,password:pw,role})});
    const d=await r.json();
    if(d.success){
      adminToast(`✅ "${name}" provisioned as ${role.toUpperCase()}.`);
      document.getElementById('an-name').value='';
      document.getElementById('an-email').value='';
      document.getElementById('an-pw').value='';
      adminLoadUsers();
    }else adminToast(`❌ ${d.error}`,true);
  }finally{btn.disabled=false;btn.textContent='+ PROVISION OPERATOR';}
}
function pgPrompt(title,message,placeholder='',inputType='text'){
  return new Promise(resolve=>{
    let ov=document.getElementById('_pg_prompt_ov');
    if(ov)ov.remove();
    ov=document.createElement('div');
    ov.id='_pg_prompt_ov';
    ov.style.cssText='position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:99998;display:flex;align-items:center;justify-content:center;backdrop-filter:blur(4px)';
    ov.innerHTML=`<div style="background:#0a1220;border:1px solid rgba(0,200,255,.18);border-radius:12px;padding:28px 32px;min-width:340px;max-width:440px;box-shadow:0 24px 64px rgba(0,0,0,.6);font-family:var(--font-mono)">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:16px">
        <div style="width:32px;height:32px;border-radius:7px;background:rgba(0,200,255,.08);border:1px solid rgba(0,200,255,.2);display:flex;align-items:center;justify-content:center;font-size:14px">🔑</div>
        <div>
          <div style="font-size:11px;font-weight:700;color:#00c8ff;letter-spacing:2px">${title}</div>
          <div style="font-size:9px;color:#3a5570;letter-spacing:1px;margin-top:2px">PACKETGUARD // ACCESS CONTROL</div>
        </div>
      </div>
      <div style="font-size:12px;color:#c0d4ee;line-height:1.6;margin-bottom:14px;padding:10px 12px;background:rgba(255,255,255,.02);border-radius:6px;border:1px solid rgba(255,255,255,.04)">${message}</div>
      <input id="_pgp_input" type="${inputType}" placeholder="${placeholder}" style="width:100%;box-sizing:border-box;background:rgba(255,255,255,.04);border:1px solid rgba(0,200,255,.2);border-radius:7px;padding:10px 14px;font-family:var(--font-mono);font-size:12px;color:#c0d4ee;outline:none;margin-bottom:18px;transition:border-color .2s" />
      <div style="display:flex;gap:8px;justify-content:flex-end">
        <button id="_pgp_cancel" style="padding:8px 20px;border-radius:6px;border:1px solid rgba(255,255,255,.1);background:rgba(255,255,255,.04);color:#7a9ab8;font-family:var(--font-mono);font-size:10px;font-weight:700;letter-spacing:1.5px;cursor:pointer;transition:all .2s">CANCEL</button>
        <button id="_pgp_ok" style="padding:8px 24px;border-radius:6px;border:1px solid rgba(0,200,255,.35);background:linear-gradient(135deg,rgba(0,200,255,.14),rgba(176,96,255,.06));color:#00c8ff;font-family:var(--font-mono);font-size:10px;font-weight:700;letter-spacing:1.5px;cursor:pointer;transition:all .2s">CONFIRM</button>
      </div>
    </div>`;
    document.body.appendChild(ov);
    const inp=ov.querySelector('#_pgp_input');
    const ok=ov.querySelector('#_pgp_ok');
    const ca=ov.querySelector('#_pgp_cancel');
    inp.focus();
    inp.onfocus=()=>inp.style.borderColor='rgba(0,200,255,.5)';
    inp.onblur=()=>inp.style.borderColor='rgba(0,200,255,.2)';
    ok.onmouseover=()=>{ok.style.borderColor='rgba(0,200,255,.6)';ok.style.boxShadow='0 0 12px rgba(0,200,255,.15)';};
    ok.onmouseout=()=>{ok.style.borderColor='rgba(0,200,255,.35)';ok.style.boxShadow='none';};
    ca.onmouseover=()=>{ca.style.color='#c0d4ee';};
    ca.onmouseout=()=>{ca.style.color='#7a9ab8';};
    const done=v=>{ov.remove();resolve(v);};
    ok.onclick=()=>done(inp.value||null);
    ca.onclick=()=>done(null);
    ov.onclick=e=>{if(e.target===ov)done(null);};
    inp.onkeydown=e=>{if(e.key==='Enter')done(inp.value||null);else if(e.key==='Escape')done(null);};
  });
}
function pgConfirm(title,message){
  return new Promise(resolve=>{
    let ov=document.getElementById('_pg_confirm_ov');
    if(ov)ov.remove();
    ov=document.createElement('div');
    ov.id='_pg_confirm_ov';
    ov.style.cssText='position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:99998;display:flex;align-items:center;justify-content:center;backdrop-filter:blur(4px)';
    ov.innerHTML=`<div style="background:#0a1220;border:1px solid rgba(0,200,255,.18);border-radius:12px;padding:28px 32px;min-width:320px;max-width:420px;box-shadow:0 24px 64px rgba(0,0,0,.6);font-family:var(--font-mono)">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:16px">
        <div style="width:32px;height:32px;border-radius:7px;background:rgba(0,200,255,.08);border:1px solid rgba(0,200,255,.2);display:flex;align-items:center;justify-content:center;font-size:14px">⚙</div>
        <div>
          <div style="font-size:11px;font-weight:700;color:#00c8ff;letter-spacing:2px">${title}</div>
          <div style="font-size:9px;color:#3a5570;letter-spacing:1px;margin-top:2px">PACKETGUARD // ACCESS CONTROL</div>
        </div>
      </div>
      <div style="font-size:12px;color:#c0d4ee;line-height:1.6;margin-bottom:22px;padding:12px;background:rgba(255,255,255,.02);border-radius:6px;border:1px solid rgba(255,255,255,.04)">${message}</div>
      <div style="display:flex;gap:8px;justify-content:flex-end">
        <button id="_pgc_cancel" style="padding:8px 20px;border-radius:6px;border:1px solid rgba(255,255,255,.1);background:rgba(255,255,255,.04);color:#7a9ab8;font-family:var(--font-mono);font-size:10px;font-weight:700;letter-spacing:1.5px;cursor:pointer;transition:all .2s">CANCEL</button>
        <button id="_pgc_ok" style="padding:8px 24px;border-radius:6px;border:1px solid rgba(0,200,255,.35);background:linear-gradient(135deg,rgba(0,200,255,.14),rgba(176,96,255,.06));color:#00c8ff;font-family:var(--font-mono);font-size:10px;font-weight:700;letter-spacing:1.5px;cursor:pointer;transition:all .2s">CONFIRM</button>
      </div>
    </div>`;
    document.body.appendChild(ov);
    const ok=ov.querySelector('#_pgc_ok');
    const ca=ov.querySelector('#_pgc_cancel');
    ok.onmouseover=()=>{ok.style.borderColor='rgba(0,200,255,.6)';ok.style.boxShadow='0 0 12px rgba(0,200,255,.15)';};
    ok.onmouseout=()=>{ok.style.borderColor='rgba(0,200,255,.35)';ok.style.boxShadow='none';};
    ca.onmouseover=()=>{ca.style.color='#c0d4ee';};
    ca.onmouseout=()=>{ca.style.color='#7a9ab8';};
    const done=v=>{ov.remove();resolve(v);};
    ok.onclick=()=>done(true);
    ca.onclick=()=>done(false);
    ov.onclick=e=>{if(e.target===ov)done(false);};
    document.addEventListener('keydown',function h(e){if(e.key==='Escape'){done(false);document.removeEventListener('keydown',h);}else if(e.key==='Enter'){done(true);document.removeEventListener('keydown',h);}});
  });
}
function adminToast(msg,err=false){
  let t=document.getElementById('_adm_toast');
  if(!t){t=document.createElement('div');t.id='_adm_toast';t.style.cssText='position:fixed;bottom:30px;left:50%;transform:translateX(-50%);padding:10px 22px;border-radius:8px;font-family:var(--font-mono);font-size:12px;font-weight:700;z-index:9999;opacity:0;transition:opacity .25s;pointer-events:none;white-space:nowrap';document.body.appendChild(t);}
  t.textContent=msg;
  t.style.background=err?'rgba(40,6,12,.98)':'rgba(6,26,16,.98)';
  t.style.border=err?'1px solid rgba(255,45,85,.4)':'1px solid rgba(0,200,255,.3)';
  t.style.color=err?'#ff2d55':'#00c8ff';
  t.style.opacity='1';
  clearTimeout(t._t);
  t._t=setTimeout(()=>t.style.opacity='0',3200);
}
</script>

<!-- ── Incident Detail Slide-In Panel ─────────────────────────── -->
<div class="inc-overlay" id="inc-overlay" onclick="closeIncidentPanel()"></div>
<aside class="inc-drawer" id="inc-drawer">
  <div class="inc-drawer-header">
    <div style="width:28px;height:28px;border-radius:6px;background:rgba(255,45,85,.12);
      border:1px solid rgba(255,45,85,.3);display:flex;align-items:center;
      justify-content:center;font-size:13px;">⚠</div>
    <div class="inc-drawer-title">SOC Incident Investigation</div>
    <button class="inc-drawer-close" onclick="closeIncidentPanel()">
      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
        <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
      </svg>
    </button>
  </div>
  <div class="inc-drawer-body" id="inc-drawer-body">
    <div style="color:#3a5570;font-family:var(--font-mono);font-size:11px;padding:20px;text-align:center">
      Select an incident to investigate
    </div>
  </div>
</aside>

=======
refresh();
setInterval(refresh, 10000);
</script>
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
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
<<<<<<< HEAD
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css"/>
=======
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
[data-theme="dark"]{
  --bg:#020508;--surface:#060c14;--surface2:#0a1520;
  --border:#0f2035;--border2:#1a3050;
  --accent:#00d4ff;--accent2:#ff2d6b;--accent3:#00ff9d;--warn:#ffb800;--purple:#9d6fff;
  --text:#b8cfe8;--text2:#6a8aaa;--white:#e8f4ff;
  --card:rgba(6,12,20,0.92);--modal:#060e18;--inp:#040a12;--inp-b:#1a3050;--sh:rgba(0,0,0,.65);
<<<<<<< HEAD
  --danger:#ef4444;--primary:#3b82f6;
=======
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
}
[data-theme="light"]{
  --bg:#f0f4f8;--surface:#ffffff;--surface2:#f8fafc;
  --border:#d0dce8;--border2:#b8ccde;
  --accent:#0088cc;--accent2:#e0145a;--accent3:#00aa66;--warn:#e09000;--purple:#6a3fcc;
  --text:#2a4060;--text2:#6a8aaa;--white:#0a1525;
  --card:rgba(255,255,255,.96);--modal:#ffffff;--inp:#f4f8fc;--inp-b:#c0d4e8;--sh:rgba(0,0,0,.12);
<<<<<<< HEAD
  --danger:#ef4444;--primary:#3b82f6;
}
:root{--fd:'Syne',sans-serif;--fb:'DM Sans',sans-serif;--fm:'Share Tech Mono',monospace;--fa:'Tajawal',sans-serif;}
html{scroll-behavior:auto}
body{background:var(--bg);color:var(--text);font-family:var(--fb);overflow-x:hidden;line-height:1.6}
[lang="ar"] *{font-family:var(--fa),var(--fb)}

/* BG EFFECTS */
=======
}
:root{--fd:'Syne',sans-serif;--fb:'DM Sans',sans-serif;--fm:'Share Tech Mono',monospace;--fa:'Tajawal',sans-serif;}
html{scroll-behavior:smooth}
body{background:var(--bg);color:var(--text);font-family:var(--fb);overflow-x:hidden;line-height:1.6;transition:background .3s,color .3s}
[lang="ar"] *{font-family:var(--fa),var(--fb)}

>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
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
<<<<<<< HEAD
=======
/* Lang */
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
.lang-sw{position:relative}
.lang-btn{display:flex;align-items:center;gap:6px;padding:7px 11px;border-radius:6px;cursor:pointer;background:transparent;border:1px solid var(--border2);color:var(--text2);font-size:12px;font-family:var(--fm);transition:all .2s}
.lang-btn:hover{border-color:var(--accent);color:var(--accent)}
.lang-dd{position:absolute;top:calc(100% + 8px);right:0;background:var(--modal);border:1px solid var(--border2);border-radius:8px;overflow:hidden;min-width:130px;box-shadow:0 12px 40px var(--sh);display:none;z-index:200}
.lang-dd.open{display:block;animation:ddin .2s ease}
@keyframes ddin{from{opacity:0;transform:translateY(-6px)}to{opacity:1;transform:translateY(0)}}
.lang-opt{display:flex;align-items:center;gap:10px;padding:10px 16px;cursor:pointer;font-size:13px;color:var(--text);transition:background .15s}
.lang-opt:hover{background:rgba(0,212,255,.06)}
.lang-opt.active{color:var(--accent)}
<<<<<<< HEAD
=======
/* Theme */
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
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
<<<<<<< HEAD
@keyframes fu{from{opacity:0;transform:translateY(18px)}to{opacity:1;transform:translateY(0)}}

/* STATS BAR */
=======

/* STATS */
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
.stats{position:relative;z-index:1;display:flex;justify-content:center;padding:0 40px 80px;animation:fu .7s .4s ease both}
.si{text-align:center;padding:22px 42px;border:1px solid var(--border);background:var(--card);backdrop-filter:blur(10px)}
.si:first-child{border-radius:10px 0 0 10px}
.si:last-child{border-radius:0 10px 10px 0}
.si+.si{border-left:none}
.sn{font-family:var(--fm);font-size:28px;color:var(--white);display:block}
.sn span{font-size:15px;color:var(--accent)}
.sl{font-size:11px;color:var(--text2);letter-spacing:1px;margin-top:3px;text-transform:uppercase}

<<<<<<< HEAD
/* SECTION COMMON */
=======
/* SECTIONS */
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
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
<<<<<<< HEAD
.fd-text{font-size:13px;color:var(--text2);line-height:1.7}
=======
.fd{font-size:13px;color:var(--text2);line-height:1.7}
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
.ftag{display:inline-block;margin-top:12px;padding:3px 9px;border-radius:4px;font-family:var(--fm);font-size:10px;letter-spacing:1px;background:rgba(0,212,255,.06);border:1px solid rgba(0,212,255,.14);color:var(--accent)}
.fc:nth-child(2) .ftag{background:rgba(157,111,255,.06);border-color:rgba(157,111,255,.15);color:var(--purple)}
.fc:nth-child(3) .ftag{background:rgba(0,255,157,.06);border-color:rgba(0,255,157,.15);color:var(--accent3)}
.fc:nth-child(4) .ftag{background:rgba(255,184,0,.06);border-color:rgba(255,184,0,.15);color:var(--warn)}
.fc:nth-child(5) .ftag{background:rgba(255,45,107,.06);border-color:rgba(255,45,107,.15);color:var(--accent2)}

<<<<<<< HEAD
/* HOW IT WORKS */
=======
/* HOW */
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
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
<<<<<<< HEAD
.rlbl{position:absolute;bottom:18px;left:50%;transform:translateX(-50%);font-family:var(--fm);font-size:10px;color:var(--accent);letter-spacing:2px;white-space:nowrap}

/* ===== LIVE MONITOR SECTION ===== */
.monitor-section{background:var(--surface2);border-top:1px solid var(--border);border-bottom:1px solid var(--border)}
.monitor-inner{max-width:1100px;margin:0 auto}
.control-panel{background:var(--card);border:1px solid var(--border2);border-radius:14px;padding:1.8rem;margin-bottom:2rem;box-shadow:0 10px 40px var(--sh)}
.cp-header{display:flex;align-items:center;gap:10px;margin-bottom:1.4rem}
.cp-header .stag{margin-bottom:0}
.input-row{display:flex;flex-wrap:wrap;gap:12px;margin-bottom:1.2rem}
.pg-input{flex:1;min-width:200px;padding:.9rem 1.1rem;background:var(--inp);border:1px solid var(--inp-b);border-radius:8px;color:var(--white);font-size:.97rem;font-family:var(--fb);transition:border-color .2s,box-shadow .2s}
.pg-input:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(0,212,255,.15)}
.scan-btn{background:linear-gradient(135deg,rgba(0,212,255,.18),rgba(157,111,255,.12));border:1px solid rgba(0,212,255,.45);color:var(--white);padding:.9rem 2.2rem;border-radius:8px;font-family:var(--fd);font-weight:700;font-size:1rem;letter-spacing:1.5px;cursor:pointer;transition:all .2s;text-transform:uppercase;box-shadow:0 0 20px rgba(0,212,255,.1)}
.scan-btn:hover{box-shadow:0 0 36px rgba(0,212,255,.25);border-color:rgba(0,212,255,.7);transform:translateY(-2px)}
.scan-btn:disabled{opacity:.4;cursor:not-allowed;transform:none}
.scan-btn.stop{background:linear-gradient(135deg,rgba(239,68,68,.18),rgba(239,68,68,.08));border-color:rgba(239,68,68,.45);box-shadow:0 0 20px rgba(239,68,68,.1)}
.scan-btn.stop:hover{box-shadow:0 0 36px rgba(239,68,68,.25);border-color:rgba(239,68,68,.7)}

/* AUTH GATE */
.auth-gate{display:flex;flex-direction:column;align-items:center;justify-content:center;padding:4rem 2rem;text-align:center;position:relative}
.gate-lock{width:90px;height:90px;border-radius:50%;background:linear-gradient(135deg,rgba(0,212,255,.08),rgba(157,111,255,.06));border:1px solid rgba(0,212,255,.2);display:flex;align-items:center;justify-content:center;font-size:2.4rem;margin-bottom:1.8rem;position:relative;box-shadow:0 0 40px rgba(0,212,255,.1)}
.gate-lock::before{content:'';position:absolute;inset:-8px;border-radius:50%;border:1px dashed rgba(0,212,255,.15);animation:spin 18s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.gate-title{font-family:var(--fd);font-size:1.8rem;font-weight:800;color:var(--white);margin-bottom:.7rem}
.gate-sub{font-size:.95rem;color:var(--text2);max-width:420px;line-height:1.7;margin-bottom:2rem}
.gate-actions{display:flex;gap:12px;flex-wrap:wrap;justify-content:center}
.gate-blur{position:relative;filter:blur(6px);pointer-events:none;opacity:.35;user-select:none;margin-top:2rem}

/* USER BADGE (nav - logged in state) */
.user-badge{display:none;align-items:center;gap:8px;padding:6px 14px;border-radius:8px;background:rgba(0,212,255,.06);border:1px solid rgba(0,212,255,.2);color:var(--white);font-size:13px;font-family:var(--fm)}
.user-badge .u-dot{width:7px;height:7px;border-radius:50%;background:var(--accent3);animation:bl 1.5s ease-in-out infinite}
.user-badge.show{display:flex}
.btn-logout{padding:7px 14px;border-radius:6px;font-size:13px;background:transparent;border:1px solid rgba(239,68,68,.35);color:#ef4444;cursor:pointer;font-family:var(--fb);transition:all .2s}
.btn-logout:hover{background:rgba(239,68,68,.08);border-color:rgba(239,68,68,.6)}

/* DASHBOARD GRID */
.dashboard{display:grid;gap:1.4rem;grid-template-columns:1fr 1fr;opacity:0;pointer-events:none;max-height:0;overflow:hidden;transition:opacity .4s ease,max-height .4s ease}
.dashboard.active{opacity:1;pointer-events:auto;max-height:2000px;overflow:visible}
.stat-card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:1.5rem;transition:border-color .25s,transform .25s}
.stat-card:hover{border-color:var(--accent);transform:translateY(-3px)}
.stat-title{color:var(--text2);font-size:.88rem;letter-spacing:1px;text-transform:uppercase;font-family:var(--fm);margin-bottom:.5rem}
.stat-value{font-family:var(--fm);font-size:2rem;font-weight:700;color:var(--white);margin-bottom:.25rem}
.stat-sub{font-size:.88rem;color:var(--text2)}

/* RISK SCALE */
.risk-card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:1.8rem;text-align:center;grid-column:1/-1}
.scale-bar{height:28px;background:linear-gradient(to right,#10b981 0%,#f59e0b 45%,#ef4444 100%);border-radius:999px;margin:1.1rem 0;position:relative;overflow:hidden;box-shadow:0 0 20px rgba(0,0,0,.3)}
.scale-indicator{position:absolute;top:50%;transform:translateY(-50%);width:4px;height:200%;background:white;box-shadow:0 0 10px rgba(255,255,255,.8);transition:left .45s ease}
.scale-labels{display:flex;justify-content:space-between;font-family:var(--fm);font-size:.9rem;margin-top:.6rem}
.scale-labels .low{color:#10b981}.scale-labels .med{color:#f59e0b}.scale-labels .high{color:#ef4444}
.risk-info{margin-top:.9rem;font-size:1rem;color:var(--text)}

/* LIVE GRAPH PLACEHOLDER */
.live-graph-card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:1.5rem;height:280px;grid-column:1/-1;display:flex;flex-direction:column}
.lg-title{font-family:var(--fm);font-size:11px;letter-spacing:2px;color:var(--text2);text-transform:uppercase;margin-bottom:1rem}
.lg-body{flex:1;display:flex;align-items:center;justify-content:center;border:1px dashed var(--border2);border-radius:8px;color:var(--text2);flex-direction:column;gap:8px;font-size:.9rem}
.lg-body i{font-size:2rem;color:var(--accent);opacity:.5}

/* PORTS */
.ports-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:1rem;grid-column:1/-1}
.port-card{background:#0a1824;border:1px solid var(--border2);border-radius:10px;padding:1.2rem;transition:border-color .2s}
.port-card:hover{border-color:var(--accent)}
.port-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:.8rem}
.port-number{font-family:var(--fm);font-size:1.4rem;color:var(--accent)}
.port-status{padding:.25rem .7rem;border-radius:999px;font-size:.8rem;font-family:var(--fm);font-weight:600}
.open{background:#064e3b;color:#6ee7b7}.closed{background:#7f1d1d;color:#fca5a5}.filter{background:#78350f;color:#fbbf24}

/* ABOUT */
.about-in{max-width:1080px;margin:0 auto;display:grid;grid-template-columns:1fr 1fr;gap:72px;align-items:start}
.about-pts{display:flex;flex-direction:column;gap:14px;margin-top:20px}
.ap{display:flex;gap:12px;align-items:flex-start;font-size:14px;color:var(--text)}
.ap-dot{width:6px;height:6px;border-radius:50%;background:var(--accent3);margin-top:7px;flex-shrink:0}
.tech-stack{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-top:10px}
.tc{padding:14px;border-radius:9px;background:var(--card);border:1px solid var(--border);text-align:center;font-family:var(--fm);font-size:11px;color:var(--text2);letter-spacing:1px;transition:border-color .2s}
.tc:hover{border-color:var(--accent);color:var(--accent)}

/* CTA */
.cta-section{background:var(--surface);border-top:1px solid var(--border)}
.cta-in{max-width:700px;margin:0 auto;text-align:center}
.cta-in .stitle{margin-bottom:14px}

/* FOOTER */
footer{position:relative;z-index:1;text-align:center;padding:3rem 1rem 2rem;color:var(--text2);font-size:.88rem;border-top:1px solid var(--border)}
.footer-nav{display:flex;justify-content:center;gap:24px;margin-bottom:1.2rem;flex-wrap:wrap}
.footer-nav a{color:var(--text2);font-size:13px;text-decoration:none;transition:color .2s}
.footer-nav a:hover{color:var(--accent)}

/* AUTH MODAL */
.overlay{position:fixed;inset:0;background:rgba(0,0,0,.75);backdrop-filter:blur(8px);z-index:2000;display:flex;align-items:center;justify-content:center;opacity:0;pointer-events:none;transition:opacity .3s}
.overlay.open{opacity:1;pointer-events:all}
.amodal{background:var(--modal);border:1px solid var(--border2);border-radius:16px;padding:2.2rem;width:min(460px,95vw);position:relative;animation:fu .3s ease}
.mclose{position:absolute;top:14px;right:16px;background:transparent;border:none;color:var(--text2);font-size:18px;cursor:pointer;line-height:1;transition:color .2s}
.mclose:hover{color:var(--white)}
.alo{display:flex;align-items:center;gap:10px;justify-content:center;margin-bottom:1.5rem}
.alo-icon{width:36px;height:36px;border-radius:8px;background:linear-gradient(135deg,rgba(0,212,255,.16),rgba(157,111,255,.14));border:1px solid rgba(0,212,255,.35);display:flex;align-items:center;justify-content:center;font-family:var(--fm);font-size:12px;color:var(--accent);font-weight:700}
.alo-name{font-family:var(--fd);font-size:17px;font-weight:800;color:var(--white);letter-spacing:2px}
.atabs{display:flex;background:var(--inp);border-radius:8px;padding:4px;margin-bottom:1.6rem}
.atab{flex:1;padding:9px;border:none;border-radius:6px;background:transparent;color:var(--text2);font-size:14px;font-weight:500;cursor:pointer;transition:all .2s;font-family:var(--fb)}
.atab.active{background:var(--surface2);color:var(--white);box-shadow:0 2px 8px var(--sh)}
.awel{font-size:13px;color:var(--text2);text-align:center;margin-bottom:1.4rem;line-height:1.5}
.apanel{display:none}.apanel.active{display:block}
.fg2{margin-bottom:1rem}
.flbl{display:block;font-family:var(--fm);font-size:10px;letter-spacing:1.5px;color:var(--text2);margin-bottom:6px;text-transform:uppercase}
.finput-wrap{position:relative}
.finput{width:100%;padding:.85rem 1rem;background:var(--inp);border:1px solid var(--inp-b);border-radius:8px;color:var(--white);font-size:.95rem;font-family:var(--fb);transition:border-color .2s,box-shadow .2s}
.finput:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(0,212,255,.12)}
.fpass-toggle{position:absolute;right:12px;top:50%;transform:translateY(-50%);background:transparent;border:none;cursor:pointer;font-size:15px;color:var(--text2);line-height:1}
.frow{display:flex;justify-content:space-between;align-items:center;margin-bottom:1.4rem}
.fcheck{display:flex;align-items:center;gap:8px;font-size:13px;color:var(--text2);cursor:pointer}
.flink{font-size:13px;color:var(--accent);background:none;border:none;cursor:pointer;font-family:var(--fb)}
.flink:hover{text-decoration:underline}
.pws{display:none;margin-bottom:1rem}.pws.show{display:block}
.pb-row{display:flex;gap:4px;margin-bottom:6px}
.pb{flex:1;height:3px;border-radius:2px;background:var(--border);transition:background .3s}
.pw-lbl-row{display:flex;justify-content:flex-end}
.pw-lbl{font-family:var(--fm);font-size:10px;color:var(--text2);transition:color .3s}
.btn-auth{width:100%;padding:1rem;border-radius:8px;background:linear-gradient(135deg,rgba(0,212,255,.2),rgba(157,111,255,.15));border:1px solid rgba(0,212,255,.45);color:var(--white);font-family:var(--fd);font-size:13px;font-weight:700;letter-spacing:2px;cursor:pointer;transition:all .2s;margin-bottom:1.2rem;box-shadow:0 0 20px rgba(0,212,255,.1)}
.btn-auth:hover{box-shadow:0 0 36px rgba(0,212,255,.22);border-color:rgba(0,212,255,.7)}
.for{display:flex;align-items:center;gap:12px;margin-bottom:1.2rem;font-size:12px;color:var(--text2)}
.for::before,.for::after{content:'';flex:1;height:1px;background:var(--border2)}
.soc-row{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:1.2rem}
.btn-soc{padding:9px;border-radius:7px;background:var(--inp);border:1px solid var(--inp-b);color:var(--text);font-size:12px;display:flex;align-items:center;justify-content:center;gap:7px;cursor:pointer;transition:all .2s;font-family:var(--fb)}
.btn-soc:hover{border-color:var(--border2);color:var(--white)}
.btn-soc svg{width:14px;height:14px}
.terms{font-size:11px;color:var(--text2);text-align:center;line-height:1.6}
.terms a{color:var(--accent);text-decoration:none}

/* FORGOT MODAL */
.fmodal{background:var(--modal);border:1px solid var(--border2);border-radius:16px;padding:2.2rem;width:min(400px,95vw);position:relative;animation:fu .3s ease;text-align:center}
.fmod-t{font-family:var(--fd);font-size:20px;font-weight:800;color:var(--white);margin-bottom:8px}
.fmod-s{font-size:13px;color:var(--text2);margin-bottom:1.6rem;line-height:1.6}
.btn-back{background:transparent;border:none;color:var(--text2);font-size:13px;cursor:pointer;font-family:var(--fb);transition:color .2s}
.btn-back:hover{color:var(--accent)}

/* REVEAL */
.reveal{opacity:0;transform:translateY(22px);transition:opacity .6s ease,transform .6s ease}
.reveal.visible{opacity:1;transform:translateY(0)}

@media(max-width:900px){
  nav{padding:0 20px}.nav-c{display:none}
  .fg{grid-template-columns:1fr}
  .how-in,.about-in{grid-template-columns:1fr;gap:40px}
  .stats{overflow-x:auto}.si{padding:18px 24px}
  section{padding:72px 24px}
  .dashboard{grid-template-columns:1fr}
=======
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
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
}
</style>
</head>
<body>
<<<<<<< HEAD

=======
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
<div class="bg-orbs"><div class="orb orb1"></div><div class="orb orb2"></div><div class="orb orb3"></div></div>
<div class="bg-grid"></div>

<!-- NAV -->
<<<<<<< HEAD
<nav id="navbar">
  <a class="nav-logo" href="#">
    <div class="nav-logo-icon">PG</div>
    <span data-i18n="brand">PacketGuard</span>
  </a>
  <div class="nav-c">
    <a href="#features" data-i18n="nav.features">Features</a>
    <a href="/monitor" data-i18n="nav.monitor">Live Monitor</a>
=======
<nav>
  <a href="#" class="nav-logo"><div class="nav-logo-icon">PG</div><span data-i18n="brand">PacketGuard</span></a>
  <div class="nav-c">
    <a href="#features" data-i18n="nav.features">Features</a>
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
    <a href="#how" data-i18n="nav.how">How It Works</a>
    <a href="#about" data-i18n="nav.about">About</a>
  </div>
  <div class="nav-r">
    <div class="lang-sw">
<<<<<<< HEAD
      <button class="lang-btn" onclick="toggleLang()"><i class="fa-solid fa-globe"></i> <span id="lc">EN</span> ▾</button>
      <div class="lang-dd" id="ldd">
        <div class="lang-opt active" onclick="setLang('en')">🇺🇸 English</div>
=======
      <button class="lang-btn" onclick="toggleLang()">🌐 <span id="lc">EN</span> ▾</button>
      <div class="lang-dd" id="ldd">
        <div class="lang-opt active" onclick="setLang('en')">🇬🇧 English</div>
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
        <div class="lang-opt" onclick="setLang('ar')">🇸🇦 العربية</div>
        <div class="lang-opt" onclick="setLang('fr')">🇫🇷 Français</div>
      </div>
    </div>
<<<<<<< HEAD
    <div class="ndiv"></div>
    <button class="theme-btn" id="tbtn" onclick="toggleTheme()"><i class="fa-solid fa-moon"></i></button>
    <div id="nav-auth-btns">
      <button class="btn-nl" onclick="openAuth('login')" data-i18n="nav.login">Log In</button>
      <button class="btn-ns" onclick="openAuth('signup')" data-i18n="nav.signup">Sign Up</button>
    </div>
    <div id="nav-user" style="display:none;align-items:center;gap:10px">
      <div class="user-badge show"><div class="u-dot"></div><span id="nav-username">User</span></div>
      <a href="/dashboard" style="padding:7px 16px;border-radius:6px;font-family:var(--fd);font-size:12px;font-weight:700;letter-spacing:1px;color:var(--accent);text-decoration:none;border:1px solid rgba(0,212,255,.35);background:rgba(0,212,255,.07);transition:all .2s;white-space:nowrap" onmouseover="this.style.background='rgba(0,212,255,.18)'" onmouseout="this.style.background='rgba(0,212,255,.07)'"><i class="fa-solid fa-chart-line" style="margin-right:6px"></i>Full Dashboard</a>
      <button class="btn-logout" onclick="handleLogout()">Log Out</button>
    </div>
=======
    <button class="theme-btn" onclick="toggleTheme()" id="tbtn">🌙</button>
    <div class="ndiv"></div>
    <button class="btn-nl" onclick="openAuth('login')" data-i18n="nav.login">Log In</button>
    <button class="btn-ns" onclick="openAuth('signup')" data-i18n="nav.signup">Sign Up</button>
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
  </div>
</nav>

<!-- HERO -->
<section class="hero">
  <div class="h-badge"><div class="bdot"></div><span data-i18n="hero.badge">REAL-TIME THREAT INTELLIGENCE</span></div>
<<<<<<< HEAD
  <h1 class="h-title">
    <span class="glow">PacketGuard</span>
    <span class="sub" data-i18n="hero.tagline">Network Guardian</span>
  </h1>
  <p class="h-desc" data-i18n="hero.desc">Advanced network threat detection powered by machine learning. Monitor every device, detect every anomaly, protect your network in real time.</p>
  <div class="h-actions">
    <button class="btn-p" onclick="openAuth('signup')">
      <i class="fa-solid fa-shield-halved"></i>
      <span data-i18n="hero.cta">GET STARTED FREE</span>
    </button>
    <a class="btn-o" href="/monitor" onclick="handleMonitorNavClick(event)">
      <i class="fa-solid fa-radar"></i>
      <span data-i18n="hero.monitor">Try Live Monitor</span>
    </a>
=======
  <h1 class="h-title"><span class="glow">PacketGuard</span><span class="sub" data-i18n="hero.tagline">Network Guardian</span></h1>
  <p class="h-desc" data-i18n="hero.desc">Advanced network threat detection powered by machine learning. Monitor every device, detect every anomaly, protect your network in real time.</p>
  <div class="h-actions">
    <button class="btn-p" onclick="window.location.href='/dashboard'"><span data-i18n="hero.cta">GET STARTED FREE</span> →</button>
    <a href="#features" class="btn-o">↓ <span data-i18n="hero.explore">Explore Features</span></a>
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
  </div>
</section>

<!-- STATS -->
<<<<<<< HEAD
<div class="stats">
  <div class="si"><span class="sn">2.4<span>M+</span></span><div class="sl" data-i18n="stats.threats">Threats Detected</div></div>
  <div class="si"><span class="sn">20<span>s</span></span><div class="sl" data-i18n="stats.scan">Scan Interval</div></div>
  <div class="si"><span class="sn">12<span>+</span></span><div class="sl" data-i18n="stats.types">Attack Types</div></div>
  <div class="si"><span class="sn">24/7</span><div class="sl" data-i18n="stats.monitor">Live Monitoring</div></div>
=======
<div class="stats reveal">
  <div class="si"><span class="sn">795<span>+</span></span><div class="sl" data-i18n="stats.threats">Threats Detected</div></div>
  <div class="si"><span class="sn">20<span>s</span></span><div class="sl" data-i18n="stats.scan">Scan Interval</div></div>
  <div class="si"><span class="sn">5<span>+</span></span><div class="sl" data-i18n="stats.types">Attack Types</div></div>
  <div class="si"><span class="sn">24<span>/7</span></span><div class="sl" data-i18n="stats.monitor">Live Monitoring</div></div>
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
</div>

<!-- FEATURES -->
<section id="features">
  <div class="fi">
    <div class="fh reveal">
      <div class="stag" data-i18n="feat.tag">Capabilities</div>
<<<<<<< HEAD
      <div class="stitle" data-i18n="feat.title">Everything you need to<br/>secure your network</div>
      <div class="ssub" data-i18n="feat.sub">Built from the ground up for real-time threat detection with powerful ML-driven anomaly analysis.</div>
    </div>
    <div class="fg">
      <div class="fc reveal"><div class="fi-icon">🔍</div><div class="ft" data-i18n="f1.t">Live Network Scanner</div><div class="fd-text" data-i18n="f1.d">Automatically discovers all devices every 20 seconds.</div><div class="ftag">ARP • Scapy</div></div>
      <div class="fc reveal"><div class="fi-icon">🧠</div><div class="ft" data-i18n="f2.t">ML Anomaly Detection</div><div class="fd-text" data-i18n="f2.d">Isolation Forest learns your normal traffic patterns and flags outliers in real time.</div><div class="ftag">Isolation Forest</div></div>
      <div class="fc reveal"><div class="fi-icon">🚨</div><div class="ft" data-i18n="f3.t">Real-Time Alerts</div><div class="fd-text" data-i18n="f3.d">Instant push notifications for HIGH and CRITICAL threats.</div><div class="ftag">Push • Visual</div></div>
      <div class="fc reveal"><div class="fi-icon">📦</div><div class="ft" data-i18n="f4.t">Packet Capture Engine</div><div class="fd-text" data-i18n="f4.d">Deep packet inspection via Scapy. Monitors TCP, UDP, ICMP traffic.</div><div class="ftag">TCP • UDP • ICMP</div></div>
      <div class="fc reveal"><div class="fi-icon">⚔</div><div class="ft" data-i18n="f5.t">Multi-Vector Detection</div><div class="fd-text" data-i18n="f5.d">Simultaneous detection of port scans, SYN floods, brute force, DNS tunneling.</div><div class="ftag">Multi-Vector</div></div>
      <div class="fc reveal"><div class="fi-icon">📊</div><div class="ft" data-i18n="f6.t">Analytics Dashboard</div><div class="fd-text" data-i18n="f6.d">Interactive charts, severity breakdowns, live alert feeds. Auto-refreshes every 5s.</div><div class="ftag">Live Charts</div></div>
    </div>
  </div>
</section>

<!-- LIVE MONITOR SECTION -->
<section id="monitor" class="monitor-section">
  <div class="monitor-inner">
    <div class="fh reveal" style="text-align:center;margin-bottom:2rem">
      <div class="stag" data-i18n="monitor.tag">Live Demo</div>
      <div class="stitle" data-i18n="monitor.title">Live Network Monitor</div>
      <div class="ssub" style="max-width:500px;margin:0 auto" data-i18n="monitor.sub">Real-time packet monitoring with ML-powered threat analysis — available to authenticated users.</div>
    </div>

    <!-- AUTH GATE (shown when logged out) -->
    <div id="monitor-gate" class="reveal">
      <div class="auth-gate">
        <div class="gate-lock"><i class="fa-solid fa-lock"></i></div>
        <div class="gate-title">Secure Access Required</div>
        <div class="gate-sub">The Live Monitor is a sensitive security tool. Please log in or create a free account to access real-time network monitoring and threat detection.</div>
        <div class="gate-actions">
          <button class="btn-p" onclick="openAuth('signup')">
            <i class="fa-solid fa-user-plus"></i>
            <span>Create Free Account</span>
          </button>
          <button class="btn-o" onclick="openAuth('login')">
            <i class="fa-solid fa-right-to-bracket"></i>
            <span>Log In</span>
          </button>
        </div>
        <!-- Blurred preview of the dashboard -->
        <div class="gate-blur">
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:1rem;max-width:800px;margin:0 auto;pointer-events:none">
            <div class="stat-card"><div class="stat-title">Monitored Target</div><div class="stat-value" style="font-size:1.3rem">192.168.1.1</div><div class="stat-sub">Active monitoring session</div></div>
            <div class="stat-card"><div class="stat-title">Total Packets Captured</div><div class="stat-value">24,891</div><div class="stat-sub">Since session started</div></div>
            <div class="stat-card"><div class="stat-title">Live Traffic Rate</div><div class="stat-value">48 <small>pkt/s</small></div><div class="stat-sub">12.3 KB/s &nbsp;•&nbsp; +8.2%</div></div>
            <div class="stat-card"><div class="stat-title">Suspicious Packets</div><div class="stat-value" style="color:#f59e0b">7</div><div class="stat-sub">Flagged by anomaly detector</div></div>
          </div>
        </div>
      </div>
    </div>

    <!-- FULL MONITOR (shown when logged in) -->
    <div id="monitor-panel" style="display:none">

      <!-- Session info bar -->
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:1.5rem;padding:.9rem 1.2rem;background:rgba(0,212,255,.04);border:1px solid rgba(0,212,255,.12);border-radius:10px">
        <div style="display:flex;align-items:center;gap:10px;font-family:var(--fm);font-size:12px;color:var(--text2)">
          <div style="width:7px;height:7px;border-radius:50%;background:var(--accent3);animation:bl 1.5s ease-in-out infinite"></div>
          AUTHENTICATED SESSION &nbsp;—&nbsp; <span id="session-user" style="color:var(--accent)"><a href="/cdn-cgi/l/email-protection" class="__cf_email__" data-cfemail="4732342235073726242c22332032263523692e28">[email&#160;protected]</a></span>
        </div>
        <div style="font-family:var(--fm);font-size:11px;color:var(--text2)" id="session-time">Session started: --</div>
      </div>

      <!-- CONTROL PANEL -->
      <div class="control-panel">
        <div class="input-row">
          <input type="text" class="pg-input" id="targetIp" placeholder="Target IP / Range (e.g. 192.168.1.0/24)" value="192.168.1.1"/>
          <select class="pg-input" id="scanType">
            <option>Quick Scan (top 100 ports)</option>
            <option selected>Standard (top 1000 ports)</option>
            <option>Full (1–65535)</option>
          </select>
          <select class="pg-input" id="scanMode">
            <option>Monitor only</option>
            <option>Scan + Monitor</option>
          </select>
        </div>
        <button class="scan-btn" id="startBtn" onclick="toggleMonitor()">
          <i class="fa-solid fa-play"></i> <span id="btnLabel">Start Protection</span>
        </button>
        <a id="fullDashBtn" href="/dashboard" style="display:none;margin-top:12px;padding:10px 22px;border-radius:8px;font-family:var(--fd);font-weight:700;font-size:13px;letter-spacing:1px;text-transform:uppercase;text-decoration:none;color:var(--white);background:linear-gradient(135deg,rgba(0,212,255,.15),rgba(157,111,255,.12));border:1px solid rgba(0,212,255,.4);box-shadow:0 0 20px rgba(0,212,255,.1);transition:all .25s"><i class="fa-solid fa-chart-line" style="margin-right:8px"></i>Open Full Dashboard</a>
      </div>

      <!-- DASHBOARD -->
      <div class="dashboard" id="dashboard">
        <div class="stat-card">
          <div class="stat-title">Monitored Target</div>
          <div class="stat-value" id="deviceIp" style="font-size:1.4rem">192.168.1.1</div>
          <div class="stat-sub">Active monitoring session</div>
        </div>
        <div class="stat-card">
          <div class="stat-title">Total Packets Captured</div>
          <div class="stat-value" id="totalPackets">0</div>
          <div class="stat-sub">Since session started</div>
        </div>
        <div class="stat-card">
          <div class="stat-title">Live Traffic Rate</div>
          <div class="stat-value" id="pps">0 <small style="font-size:.9rem">pkt/s</small></div>
          <div class="stat-sub"><span id="bytesSec">0 KB/s</span> &nbsp;•&nbsp; <span id="change">+0%</span></div>
        </div>
        <div class="stat-card">
          <div class="stat-title">Suspicious Packets</div>
          <div class="stat-value" id="suspCount" style="color:#f59e0b">0</div>
          <div class="stat-sub">Flagged by anomaly detector</div>
        </div>
        <div class="risk-card">
          <div class="stat-title">Malicious Traffic Risk Level</div>
          <div class="scale-bar"><div class="scale-indicator" id="riskIndicator" style="left:15%"></div></div>
          <div class="scale-labels"><span class="low">Safe</span><span class="med">Warning</span><span class="high">Critical</span></div>
          <div class="risk-info">Current Risk: <strong id="riskLevel" style="color:#10b981">Low</strong></div>
        </div>
        <div class="live-graph-card">
          <div class="lg-title">Live Traffic Flow — Packets & Bandwidth</div>
          <div class="lg-body"><i class="fa-solid fa-wave-square"></i><span>Real-time Chart.js visualization active in production build</span></div>
        </div>
        <div class="ports-grid" id="portsArea"></div>
        <div style="grid-column:1/-1;display:flex;justify-content:center;padding-top:.5rem">
          <a href="/dashboard" style="display:inline-flex;align-items:center;gap:10px;padding:1rem 2.4rem;border-radius:10px;font-family:var(--fd);font-weight:700;font-size:1rem;letter-spacing:1.5px;text-transform:uppercase;text-decoration:none;color:var(--white);background:linear-gradient(135deg,rgba(0,212,255,.15),rgba(157,111,255,.12));border:1px solid rgba(0,212,255,.4);box-shadow:0 0 24px rgba(0,212,255,.12);transition:all .25s" onmouseover="this.style.boxShadow='0 0 40px rgba(0,212,255,.3)';this.style.borderColor='rgba(0,212,255,.7)'" onmouseout="this.style.boxShadow='0 0 24px rgba(0,212,255,.12)';this.style.borderColor='rgba(0,212,255,.4)'"><i class="fa-solid fa-chart-line"></i> Open Full Dashboard</a>
        </div>
      </div>

=======
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
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
    </div>
  </div>
</section>

<!-- HOW IT WORKS -->
<<<<<<< HEAD
<section id="how" class="how">
  <div class="how-in">
    <div class="reveal">
      <div class="stag" data-i18n="how.tag">Process</div>
      <div class="stitle" data-i18n="how.title">How PacketGuard<br/>works</div>
      <div class="steps">
        <div class="step"><div class="snum">01</div><div><div class="st" data-i18n="s1.t">Network Discovery</div><div class="sd" data-i18n="s1.d">ARP scans discover every active device on the subnet, including sleeping phones and IoT devices.</div></div></div>
        <div class="step"><div class="snum">02</div><div><div class="st" data-i18n="s2.t">Packet Capture</div><div class="sd" data-i18n="s2.d">Scapy captures live packets and feeds them through rule-based and ML-based detection pipelines.</div></div></div>
        <div class="step"><div class="snum">03</div><div><div class="st" data-i18n="s3.t">Threat Analysis</div><div class="sd" data-i18n="s3.d">Each packet is scored by 4 detectors: Port Scan, SYN Flood, High Rate, and Isolation Forest.</div></div></div>
        <div class="step"><div class="snum">04</div><div><div class="st" data-i18n="s4.t">Alert & Visualize</div><div class="sd" data-i18n="s4.d">Confirmed threats are logged, classified by severity, and pushed to the dashboard as notifications.</div></div></div>
=======
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
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
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
<<<<<<< HEAD
  <div class="about-in">
    <div class="reveal">
      <div class="stag" data-i18n="about.tag">About</div>
      <div class="stitle" data-i18n="about.title">Built as a graduation project in network security</div>
      <div class="ssub" data-i18n="about.sub">PacketGuard combines classical intrusion detection with modern ML to deliver a complete monitoring solution.</div>
      <div class="about-pts">
        <div class="ap"><div class="ap-dot"></div><span data-i18n="a1">Real-time packet analysis using Python and Scapy for deep network visibility</span></div>
        <div class="ap"><div class="ap-dot"></div><span data-i18n="a2">Isolation Forest ML model trained on network traffic to detect anomalies</span></div>
        <div class="ap"><div class="ap-dot"></div><span data-i18n="a3">Flask-powered REST API serving a live updating web dashboard</span></div>
        <div class="ap"><div class="ap-dot"></div><span data-i18n="a4">Supports all device types — phones, laptops, smart devices, routers</span></div>
        <div class="ap"><div class="ap-dot"></div><span data-i18n="a5">Runs on Windows with administrator privileges for full packet capture</span></div>
      </div>
    </div>
    <div class="reveal">
      <div class="stag" data-i18n="tech.tag">Tech Stack</div>
      <div class="tech-stack">
        <div class="tc">Python</div><div class="tc">Scapy</div><div class="tc">Flask</div>
        <div class="tc">Scikit-learn</div><div class="tc">Chart.js</div><div class="tc">SQLite</div>
        <div class="tc">JavaScript</div><div class="tc">REST API</div><div class="tc">ARP</div>
=======
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
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
      </div>
    </div>
  </div>
</section>

<<<<<<< HEAD


<!-- FOOTER -->
<footer>
  <div class="footer-nav">
    <a href="#features" data-i18n="nav.features">Features</a>
    <a href="/monitor" data-i18n="nav.monitor">Live Monitor</a>
    <a href="#how" data-i18n="nav.how">How It Works</a>
    <a href="#about" data-i18n="nav.about">About</a>
    <a href="/dashboard" data-i18n="footer.dash">Dashboard</a>
  </div>
  <p>PacketGuard © 2026 — Network Threat Detection</p>
=======
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
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
</footer>

<!-- AUTH MODAL -->
<div class="overlay" id="auth-overlay">
  <div class="amodal">
    <button class="mclose" onclick="closeAuth()">✕</button>
<<<<<<< HEAD
    <div class="alo"><div class="alo-icon">PG</div><div class="alo-name">PacketGuard</div></div>
=======
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
    <div class="atabs">
      <button class="atab active" id="tab-login" onclick="switchTab('login')" data-i18n="nav.login">Log In</button>
      <button class="atab" id="tab-signup" onclick="switchTab('signup')" data-i18n="nav.signup">Sign Up</button>
    </div>
<<<<<<< HEAD

    <!-- LOGIN -->
    <div class="apanel active" id="panel-login">
      <div class="awel" data-i18n="login.welcome">Welcome back! Log in to access your dashboard.</div>
      <div class="fg2">
        <label class="flbl" data-i18n="form.email">EMAIL ADDRESS</label>
        <input type="email" class="finput" id="l-email" data-i18n-ph="form.email.ph" placeholder="you@example.com"/>
      </div>
      <div class="fg2">
        <label class="flbl" data-i18n="form.password">PASSWORD</label>
        <div class="finput-wrap">
          <input type="password" class="finput" id="l-pass" data-i18n-ph="form.pass.ph" placeholder="Enter your password"/>
          <button class="fpass-toggle" onclick="togglePass('l-pass',this)"><i class="fa-solid fa-eye"></i></button>
        </div>
      </div>
      <div class="frow">
        <label class="fcheck"><input type="checkbox"/> <span data-i18n="form.remember">Remember me</span></label>
        <button class="flink" onclick="openForgot()" data-i18n="form.forgot">Forgot password?</button>
      </div>
      <div id="login-error" style="display:none;color:#ff4d4d;background:rgba(255,77,77,.1);border:1px solid rgba(255,77,77,.3);border-radius:8px;padding:.7rem 1rem;font-size:13px;font-family:var(--fm);margin-bottom:1rem;text-align:center"></div>
      <button class="btn-auth" onclick="handleLogin()" data-i18n="nav.login">LOG IN</button>
      <div class="for" data-i18n="form.or">or continue with</div>
      <div class="soc-row">
        <button class="btn-soc" onclick="socialAuth('Google')"><svg viewBox="0 0 24 24" fill="none"><path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/><path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/><path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l3.66-2.84z" fill="#FBBC05"/><path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/></svg>Google</button>
        <button class="btn-soc" onclick="socialAuth('GitHub')"><svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"/></svg>GitHub</button>
      </div>
    </div>

    <!-- SIGNUP -->
    <div class="apanel" id="panel-signup">
      <div class="awel" data-i18n="signup.welcome">Create your free account to get started.</div>
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
        <div class="finput-wrap">
          <input type="password" class="finput" id="s-pass" data-i18n-ph="form.newpass.ph" placeholder="Create a strong password" oninput="checkStrength(this.value)"/>
          <button class="fpass-toggle" onclick="togglePass('s-pass',this)"><i class="fa-solid fa-eye"></i></button>
        </div>
      </div>
      <div class="pws" id="pws">
        <div class="pb-row"><div class="pb" id="pb1"></div><div class="pb" id="pb2"></div><div class="pb" id="pb3"></div><div class="pb" id="pb4"></div></div>
        <div class="pw-lbl-row"><span class="pw-lbl" id="pwlbl"></span></div>
      </div>
      <button class="btn-auth" onclick="handleSignup()" data-i18n="nav.signup" style="margin-bottom:.8rem">SIGN UP</button>
      <div class="for" data-i18n="form.or">or continue with</div>
      <div class="soc-row">
        <button class="btn-soc" onclick="socialAuth('Google')"><svg viewBox="0 0 24 24" fill="none"><path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/><path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/><path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l3.66-2.84z" fill="#FBBC05"/><path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/></svg>Google</button>
        <button class="btn-soc" onclick="socialAuth('GitHub')"><svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"/></svg>GitHub</button>
      </div>
      <p class="terms" data-i18n="form.terms">By signing up, you agree to our <a href="#">Terms</a> and <a href="#">Privacy Policy</a></p>
=======
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
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
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

<<<<<<< HEAD
<script data-cfasync="false" src="/cdn-cgi/scripts/5c5dd728/cloudflare-static/email-decode.min.js"></script><script>
// ====== i18n ======
const T={
  en:{brand:'PacketGuard','nav.features':'Features','nav.how':'How It Works','nav.about':'About','nav.monitor':'Live Monitor','nav.login':'Log In','nav.signup':'Sign Up','hero.badge':'REAL-TIME THREAT INTELLIGENCE','hero.tagline':'Network Guardian','hero.desc':'Advanced network threat detection powered by machine learning. Monitor every device, detect every anomaly, protect your network in real time.','hero.cta':'GET STARTED FREE','hero.monitor':'Try Live Monitor','stats.threats':'Threats Detected','stats.scan':'Scan Interval','stats.types':'Attack Types','stats.monitor':'Live Monitoring','feat.tag':'Capabilities','feat.title':'Everything you need to<br/>secure your network','feat.sub':'Built from the ground up for real-time threat detection with powerful ML-driven anomaly analysis.','f1.t':'Live Network Scanner','f1.d':'Automatically discovers all devices every 20 seconds. Identifies phones, laptops, routers, and IoT.','f2.t':'ML Anomaly Detection','f2.d':'Isolation Forest learns your normal traffic patterns and flags outliers in real time.','f3.t':'Real-Time Alerts','f3.d':'Instant push notifications for HIGH and CRITICAL threats. Visual popups keep you informed.','f4.t':'Packet Capture Engine','f4.d':'Deep packet inspection via Scapy. Monitors TCP, UDP, ICMP traffic.','f5.t':'Multi-Vector Detection','f5.d':'Simultaneous detection of port scans, SYN floods, brute force, DNS tunneling.','f6.t':'Analytics Dashboard','f6.d':'Interactive charts, severity breakdowns, live alert feeds. Auto-refreshes every 5 seconds.','monitor.tag':'Live Demo','monitor.title':'Try the Monitor Now','monitor.sub':'Enter a target IP and start simulated packet monitoring with real-time threat analysis.','how.tag':'Process','how.title':'How PacketGuard<br/>works','s1.t':'Network Discovery','s1.d':'ARP scans discover every active device on the subnet, including sleeping phones and IoT devices.','s2.t':'Packet Capture','s2.d':'Scapy captures live packets and feeds them through rule-based and ML-based detection pipelines.','s3.t':'Threat Analysis','s3.d':'Each packet is scored by 4 detectors: Port Scan, SYN Flood, High Rate, and Isolation Forest.','s4.t':'Alert & Visualize','s4.d':'Confirmed threats are logged, classified by severity, and pushed to the dashboard as notifications.','radar.lbl':'NETWORK SCAN ACTIVE','about.tag':'About','about.title':'Built as a graduation project in network security','about.sub':'PacketGuard combines classical intrusion detection with modern ML to deliver a complete monitoring solution.','a1':'Real-time packet analysis using Python and Scapy for deep network visibility','a2':'Isolation Forest ML model trained on network traffic to detect anomalies','a3':'Flask-powered REST API serving a live updating web dashboard','a4':'Supports all device types — phones, laptops, smart devices, routers','a5':'Runs on Windows with administrator privileges for full packet capture','tech.tag':'Tech Stack','cta.title':'Ready to protect<br/>your network?','cta.sub':'Create your free account and start detecting threats in real time.','cta.btn':'CREATE FREE ACCOUNT','footer.dash':'Dashboard','login.welcome':'Welcome back! Log in to access your dashboard.','signup.welcome':'Create your free account to get started.','form.email':'EMAIL ADDRESS','form.email.ph':'you@example.com','form.password':'PASSWORD','form.pass.ph':'Enter your password','form.newpass.ph':'Create a strong password','form.name':'FULL NAME','form.name.ph':'Your full name','form.remember':'Remember me','form.forgot':'Forgot password?','form.or':'or continue with','form.terms':'By signing up, you agree to our <a href="#">Terms</a> and <a href="#">Privacy Policy</a>','forgot.title':'Reset Password','forgot.sub':"Enter your email and we'll send you a reset link.",'forgot.btn':'SEND RESET LINK','forgot.back':'Back to Login','pw.weak':'Weak','pw.fair':'Fair','pw.good':'Good','pw.strong':'Strong'},
  ar:{brand:'PacketGuard','nav.features':'المميزات','nav.how':'كيف يعمل','nav.about':'عن المشروع','nav.monitor':'المراقبة الحية','nav.login':'تسجيل الدخول','nav.signup':'إنشاء حساب','hero.badge':'كشف التهديدات في الوقت الفعلي','hero.tagline':'حارس الشبكة','hero.desc':'كشف متقدم لتهديدات الشبكة مدعوم بالذكاء الاصطناعي. راقب كل جهاز، اكتشف كل شذوذ، احمِ شبكتك.','hero.cta':'ابدأ مجاناً','hero.monitor':'جرب المراقبة','stats.threats':'تهديد مكتشف','stats.scan':'فترة الفحص','stats.types':'أنواع الهجمات','stats.monitor':'مراقبة مستمرة','feat.tag':'الإمكانيات','feat.title':'كل ما تحتاجه لتأمين<br/>شبكتك','feat.sub':'مبني للكشف الفوري عن التهديدات مع تحليل الشذوذ بالذكاء الاصطناعي.','f1.t':'فحص الشبكة المباشر','f1.d':'يكتشف تلقائياً جميع الأجهزة كل 20 ثانية.','f2.t':'كشف الشذوذ بالذكاء الاصطناعي','f2.d':'تتعلم خوارزمية Isolation Forest أنماط حركة المرور وترصد الشذوذ.','f3.t':'تنبيهات فورية','f3.d':'إشعارات فورية للتهديدات عالية الخطورة.','f4.t':'محرك التقاط الحزم','f4.d':'فحص عميق للحزم باستخدام Scapy. يراقب TCP وUDP وICMP.','f5.t':'كشف متعدد المتجهات','f5.d':'كشف متزامن لفحص المنافذ وهجمات SYN والقوة الغاشمة.','f6.t':'لوحة تحليلات','f6.d':'مخططات تفاعلية وتغذية تنبيهات مباشرة.','monitor.tag':'تجربة مباشرة','monitor.title':'جرب المراقبة الآن','monitor.sub':'أدخل IP المستهدف وابدأ مراقبة الحزم المحاكاة مع تحليل التهديدات.','how.tag':'العملية','how.title':'كيف يعمل<br/>PacketGuard','s1.t':'اكتشاف الشبكة','s1.d':'تكتشف فحوصات ARP جميع الأجهزة النشطة بما في ذلك الهواتف النائمة.','s2.t':'التقاط الحزم','s2.d':'يلتقط Scapy حزم الشبكة ويغذيها عبر خطوط الكشف.','s3.t':'تحليل التهديدات','s3.d':'تسجيل كل حزمة بواسطة 4 أدوات: فحص المنافذ، SYN، معدل عالٍ، ونموذج ML.','s4.t':'التنبيه والتصور','s4.d':'تُسجَّل التهديدات وتُصنَّف حسب الخطورة وتُرسَل للوحة القيادة.','radar.lbl':'فحص الشبكة نشط','about.tag':'عن المشروع','about.title':'مشروع تخرج في أمن الشبكات','about.sub':'يجمع PacketGuard بين تقنيات كشف التسلل الكلاسيكية والتعلم الآلي.','a1':'تحليل الحزم في الوقت الفعلي باستخدام Python وScapy','a2':'نموذج Isolation Forest لاكتشاف الشذوذ الإحصائي','a3':'واجهة REST مدعومة بـ Flask تخدم لوحة ويب متحدثة','a4':'يدعم جميع أنواع الأجهزة — هواتف، أجهزة محمولة، راوترات','a5':'يعمل على Windows بامتيازات المسؤول','tech.tag':'التقنيات','cta.title':'مستعد لحماية<br/>شبكتك؟','cta.sub':'أنشئ حسابك المجاني وابدأ في كشف التهديدات.','cta.btn':'إنشاء حساب مجاني','footer.dash':'لوحة التحكم','login.welcome':'مرحباً بعودتك! سجّل الدخول للوصول للوحة.','signup.welcome':'أنشئ حسابك المجاني للبدء.','form.email':'البريد الإلكتروني','form.email.ph':'example@mail.com','form.password':'كلمة المرور','form.pass.ph':'أدخل كلمة المرور','form.newpass.ph':'أنشئ كلمة مرور قوية','form.name':'الاسم الكامل','form.name.ph':'اسمك الكامل','form.remember':'تذكرني','form.forgot':'نسيت كلمة المرور؟','form.or':'أو المتابعة باستخدام','form.terms':'بالتسجيل توافق على <a href="#">الشروط</a> و<a href="#">الخصوصية</a>','forgot.title':'إعادة تعيين كلمة المرور','forgot.sub':'أدخل بريدك وسنرسل رابط إعادة التعيين.','forgot.btn':'إرسال الرابط','forgot.back':'العودة لتسجيل الدخول','pw.weak':'ضعيفة','pw.fair':'مقبولة','pw.good':'جيدة','pw.strong':'قوية'},
  fr:{brand:'PacketGuard','nav.features':'Fonctionnalités','nav.how':'Fonctionnement','nav.about':'À propos','nav.monitor':'Moniteur','nav.login':'Connexion','nav.signup':'Inscription','hero.badge':'DÉTECTION DE MENACES EN TEMPS RÉEL','hero.tagline':'Gardien du Réseau','hero.desc':'Détection avancée des menaces réseau propulsée par ML. Surveillez chaque appareil, protégez votre réseau.','hero.cta':'COMMENCER GRATUITEMENT','hero.monitor':'Essayer le Moniteur','stats.threats':'Menaces Détectées','stats.scan':'Intervalle Scan','stats.types':"Types d'Attaques",'stats.monitor':'Surveillance Continue','feat.tag':'Capacités','feat.title':'Tout pour sécuriser<br/>votre réseau','feat.sub':'Conçu pour la détection en temps réel avec analyse par ML.','f1.t':'Scanner Réseau Live','f1.d':'Découvre tous les appareils toutes les 20s.','f2.t':'Détection ML','f2.d':'Isolation Forest signale les anomalies en temps réel.','f3.t':'Alertes Temps Réel','f3.d':'Notifications instantanées pour menaces HIGH et CRITICAL.','f4.t':'Capture de Paquets','f4.d':'Inspection profonde via Scapy. Surveille TCP, UDP, ICMP.','f5.t':'Détection Multi-Vecteurs','f5.d':'Détection simultanée de scans, floods SYN, brute force.','f6.t':'Tableau de Bord','f6.d':'Graphiques interactifs, alertes en direct. Actualisation toutes les 5 secondes.','monitor.tag':'Démo Live','monitor.title':'Essayez le Moniteur','monitor.sub':'Entrez une IP cible et démarrez la surveillance simulée.','how.tag':'Processus','how.title':'Comment fonctionne<br/>PacketGuard','s1.t':'Découverte Réseau','s1.d':'Les scans ARP découvrent tous les appareils actifs.','s2.t':'Capture de Paquets','s2.d':'Scapy capture les paquets via pipelines règles et ML.','s3.t':'Analyse des Menaces','s3.d':'Chaque paquet est évalué: Scan ports, SYN Flood, Débit, Forest.','s4.t':'Alerte & Visualisation','s4.d':'Menaces enregistrées, classées et envoyées au tableau de bord.','radar.lbl':'SCAN RÉSEAU ACTIF','about.tag':'À Propos','about.title':"Projet de fin d'études en sécurité réseau",'about.sub':'PacketGuard combine détection classique et ML moderne.','a1':'Analyse temps réel avec Python et Scapy','a2':'Modèle Isolation Forest entraîné sur le trafic réseau','a3':'API REST Flask servant un tableau de bord en direct','a4':'Supporte tous les types: téléphones, laptops, IoT, routeurs','a5':'Fonctionne sous Windows avec privilèges admin','tech.tag':'Stack Technique','cta.title':'Prêt à protéger<br/>votre réseau ?','cta.sub':'Créez votre compte gratuit et commencez à détecter les menaces.','cta.btn':'CRÉER UN COMPTE GRATUIT','footer.dash':'Tableau de bord','login.welcome':'Bon retour ! Connectez-vous.','signup.welcome':'Créez votre compte gratuit.','form.email':'ADRESSE E-MAIL','form.email.ph':'vous@exemple.com','form.password':'MOT DE PASSE','form.pass.ph':'Votre mot de passe','form.newpass.ph':'Créez un mot de passe fort','form.name':'NOM COMPLET','form.name.ph':'Votre nom complet','form.remember':'Se souvenir','form.forgot':'Mot de passe oublié ?','form.or':'ou continuer avec','form.terms':'En vous inscrivant vous acceptez nos <a href="#">CGU</a> et <a href="#">Confidentialité</a>','forgot.title':'Réinitialiser','forgot.sub':'Entrez votre e-mail et nous vous enverrons un lien.','forgot.btn':'ENVOYER LE LIEN','forgot.back':'Retour à la connexion','pw.weak':'Faible','pw.fair':'Acceptable','pw.good':'Bon','pw.strong':'Fort'}
=======
<script>
const T={
  en:{brand:'PacketGuard','nav.features':'Features','nav.how':'How It Works','nav.about':'About','nav.login':'Log In','nav.signup':'Sign Up','hero.badge':'REAL-TIME THREAT INTELLIGENCE','hero.tagline':'Network Guardian','hero.desc':'Advanced network threat detection powered by machine learning. Monitor every device, detect every anomaly, protect your network in real time.','hero.cta':'GET STARTED FREE','hero.explore':'Explore Features','stats.threats':'Threats Detected','stats.scan':'Scan Interval','stats.types':'Attack Types','stats.monitor':'Live Monitoring','feat.tag':'Capabilities','feat.title':'Everything you need to<br/>secure your network','feat.sub':'Built from the ground up for real-time threat detection with powerful ML-driven anomaly analysis.','f1.t':'Live Network Scanner','f1.d':'Automatically discovers all devices every 20 seconds. Identifies phones, laptops, routers, and IoT devices by vendor and MAC address.','f2.t':'ML Anomaly Detection','f2.d':'Isolation Forest learns your normal traffic patterns and flags outliers in real time — catching attacks rule-based systems miss.','f3.t':'Real-Time Alerts','f3.d':'Instant push notifications for HIGH and CRITICAL threats. Visual popups keep you informed without interrupting your workflow.','f4.t':'Packet Capture Engine','f4.d':'Deep packet inspection via Scapy. Monitors TCP, UDP, ICMP traffic and detects port scans, SYN floods, and abnormal sizes.','f5.t':'Multi-Vector Detection','f5.d':'Simultaneous detection of port scans, SYN floods, brute force, DNS tunneling, and high packet rate anomalies.','f6.t':'Analytics Dashboard','f6.d':'Interactive charts, severity breakdowns, live alert feeds, and device monitoring. Auto-refreshes every 5 seconds.','how.tag':'Process','how.title':'How PacketGuard<br/>works','s1.t':'Network Discovery','s1.d':'ARP scans discover every active device on the subnet, including sleeping phones and IoT devices.','s2.t':'Packet Capture','s2.d':'Scapy captures live packets and feeds them through rule-based and ML-based detection pipelines.','s3.t':'Threat Analysis','s3.d':'Each packet is scored by 4 detectors: Port Scan, SYN Flood, High Rate, and Isolation Forest.','s4.t':'Alert & Visualize','s4.d':'Confirmed threats are logged, classified by severity, and pushed to the dashboard as notifications.','radar.lbl':'NETWORK SCAN ACTIVE','about.tag':'About','about.title':'Built as a graduation project in network security','about.sub':'PacketGuard combines classical intrusion detection with modern ML to deliver a complete monitoring solution.','a1':'Real-time packet analysis using Python and Scapy for deep network visibility','a2':'Isolation Forest ML model trained on network traffic to detect anomalies','a3':'Flask-powered REST API serving a live updating web dashboard','a4':'Supports all device types — phones, laptops, smart devices, routers','a5':'Runs on Windows with administrator privileges for full packet capture','tech.tag':'Tech Stack','cta.title':'Ready to protect<br/>your network?','cta.sub':'Create your free account and start detecting threats in real time.','cta.btn':'CREATE FREE ACCOUNT','footer.dash':'Dashboard','login.welcome':'Welcome back! Log in to access your dashboard.','signup.welcome':'Create your free account to get started.','form.email':'EMAIL ADDRESS','form.email.ph':'you@example.com','form.password':'PASSWORD','form.pass.ph':'Enter your password','form.newpass.ph':'Create a strong password','form.name':'FULL NAME','form.name.ph':'Your full name','form.remember':'Remember me','form.forgot':'Forgot password?','form.or':'or continue with','form.terms':'By signing up, you agree to our <a href="#">Terms</a> and <a href="#">Privacy Policy</a>','forgot.title':'Reset Password','forgot.sub':"Enter your email and we'll send you a reset link.",'forgot.btn':'SEND RESET LINK','forgot.back':'Back to Login','pw.weak':'Weak','pw.fair':'Fair','pw.good':'Good','pw.strong':'Strong'},
  ar:{brand:'PacketGuard','nav.features':'المميزات','nav.how':'كيف يعمل','nav.about':'عن المشروع','nav.login':'تسجيل الدخول','nav.signup':'إنشاء حساب','hero.badge':'كشف التهديدات في الوقت الفعلي','hero.tagline':'حارس الشبكة','hero.desc':'كشف متقدم لتهديدات الشبكة مدعوم بالذكاء الاصطناعي. راقب كل جهاز، اكتشف كل شذوذ، احمِ شبكتك في الوقت الفعلي.','hero.cta':'ابدأ مجاناً','hero.explore':'استكشف المميزات','stats.threats':'تهديد مكتشف','stats.scan':'فترة الفحص','stats.types':'أنواع الهجمات','stats.monitor':'مراقبة مستمرة','feat.tag':'الإمكانيات','feat.title':'كل ما تحتاجه لتأمين<br/>شبكتك','feat.sub':'مبني من الصفر لاكتشاف التهديدات في الوقت الفعلي مع تحليل الشذوذ بالذكاء الاصطناعي.','f1.t':'فحص الشبكة المباشر','f1.d':'يكتشف تلقائياً جميع الأجهزة كل 20 ثانية. يتعرف على الهواتف والأجهزة والراوترات وأجهزة إنترنت الأشياء.','f2.t':'كشف الشذوذ بالذكاء الاصطناعي','f2.d':'تتعلم خوارزمية Isolation Forest أنماط حركة المرور وترصد الشذوذ في الوقت الفعلي.','f3.t':'تنبيهات فورية','f3.d':'إشعارات فورية للتهديدات عالية الخطورة. نوافذ مرئية تبقيك على اطلاع دون مقاطعة عملك.','f4.t':'محرك التقاط الحزم','f4.d':'فحص عميق للحزم باستخدام Scapy. يراقب TCP وUDP وICMP ويكتشف فحص المنافذ وفيضان SYN.','f5.t':'كشف متعدد المتجهات','f5.d':'كشف متزامن لفحص المنافذ وهجمات SYN والقوة الغاشمة ونفق DNS وشذوذ معدل الحزم.','f6.t':'لوحة تحليلات','f6.d':'مخططات تفاعلية وتفصيل حسب الخطورة وتغذية تنبيهات مباشرة. تتحدث كل 5 ثوانٍ.','how.tag':'العملية','how.title':'كيف يعمل<br/>PacketGuard','s1.t':'اكتشاف الشبكة','s1.d':'تكتشف فحوصات ARP جميع الأجهزة النشطة بما في ذلك الهواتف النائمة.','s2.t':'التقاط الحزم','s2.d':'يلتقط Scapy حزم الشبكة ويغذيها عبر خطوط الكشف المبنية على القواعد والذكاء الاصطناعي.','s3.t':'تحليل التهديدات','s3.d':'تسجيل كل حزمة بواسطة 4 أدوات: فحص المنافذ، SYN، معدل عالٍ، ونموذج ML.','s4.t':'التنبيه والتصور','s4.d':'تُسجَّل التهديدات وتُصنَّف حسب الخطورة وتُرسَل للوحة القيادة.','radar.lbl':'فحص الشبكة نشط','about.tag':'عن المشروع','about.title':'مشروع تخرج في أمن الشبكات','about.sub':'يجمع PacketGuard بين تقنيات كشف التسلل الكلاسيكية والتعلم الآلي لتقديم حل مراقبة متكامل.','a1':'تحليل الحزم في الوقت الفعلي باستخدام Python وScapy','a2':'نموذج Isolation Forest لاكتشاف الشذوذ الإحصائي','a3':'واجهة REST مدعومة بـ Flask تخدم لوحة ويب متحدثة','a4':'يدعم جميع أنواع الأجهزة — هواتف، أجهزة محمولة، راوترات','a5':'يعمل على Windows بامتيازات المسؤول','tech.tag':'التقنيات','cta.title':'مستعد لحماية<br/>شبكتك؟','cta.sub':'أنشئ حسابك المجاني وابدأ في كشف التهديدات.','cta.btn':'إنشاء حساب مجاني','footer.dash':'لوحة التحكم','login.welcome':'مرحباً بعودتك! سجّل الدخول للوصول للوحة.','signup.welcome':'أنشئ حسابك المجاني للبدء.','form.email':'البريد الإلكتروني','form.email.ph':'example@mail.com','form.password':'كلمة المرور','form.pass.ph':'أدخل كلمة المرور','form.newpass.ph':'أنشئ كلمة مرور قوية','form.name':'الاسم الكامل','form.name.ph':'اسمك الكامل','form.remember':'تذكرني','form.forgot':'نسيت كلمة المرور؟','form.or':'أو المتابعة باستخدام','form.terms':'بالتسجيل توافق على <a href="#">الشروط</a> و<a href="#">الخصوصية</a>','forgot.title':'إعادة تعيين كلمة المرور','forgot.sub':'أدخل بريدك وسنرسل رابط إعادة التعيين.','forgot.btn':'إرسال الرابط','forgot.back':'العودة لتسجيل الدخول','pw.weak':'ضعيفة','pw.fair':'مقبولة','pw.good':'جيدة','pw.strong':'قوية'},
  fr:{brand:'PacketGuard','nav.features':'Fonctionnalités','nav.how':'Fonctionnement','nav.about':'À propos','nav.login':'Connexion','nav.signup':'Inscription','hero.badge':'DÉTECTION DE MENACES EN TEMPS RÉEL','hero.tagline':'Gardien du Réseau','hero.desc':'Détection avancée des menaces réseau propulsée par ML. Surveillez chaque appareil, détectez chaque anomalie, protégez votre réseau en temps réel.','hero.cta':'COMMENCER GRATUITEMENT','hero.explore':'Explorer','stats.threats':'Menaces Détectées','stats.scan':'Intervalle Scan','stats.types':'Types d\'Attaques','stats.monitor':'Surveillance Continue','feat.tag':'Capacités','feat.title':'Tout pour sécuriser<br/>votre réseau','feat.sub':'Conçu pour la détection en temps réel avec analyse d\'anomalies par ML.','f1.t':'Scanner Réseau Live','f1.d':'Découvre tous les appareils toutes les 20s. Identifie téléphones, laptops, routeurs et IoT.','f2.t':'Détection ML','f2.d':'Isolation Forest apprend vos schémas normaux et signale les anomalies en temps réel.','f3.t':'Alertes Temps Réel','f3.d':'Notifications instantanées pour menaces HIGH et CRITICAL. Popups visuelles non intrusives.','f4.t':'Capture de Paquets','f4.d':'Inspection profonde via Scapy. Surveille TCP, UDP, ICMP et détecte scans et floods.','f5.t':'Détection Multi-Vecteurs','f5.d':'Détection simultanée de scans, floods SYN, brute force, DNS tunneling et débits anormaux.','f6.t':'Tableau de Bord','f6.d':'Graphiques interactifs, alertes en direct et monitoring. Actualisation toutes les 5 secondes.','how.tag':'Processus','how.title':'Comment fonctionne<br/>PacketGuard','s1.t':'Découverte Réseau','s1.d':'Les scans ARP découvrent tous les appareils actifs, y compris les téléphones en veille.','s2.t':'Capture de Paquets','s2.d':'Scapy capture les paquets et les traite via pipelines règles et ML simultanément.','s3.t':'Analyse des Menaces','s3.d':'Chaque paquet est évalué: Scan ports, SYN Flood, Débit élevé, Isolation Forest.','s4.t':'Alerte & Visualisation','s4.d':'Menaces confirmées enregistrées, classées et envoyées au tableau de bord.','radar.lbl':'SCAN RÉSEAU ACTIF','about.tag':'À Propos','about.title':'Projet de fin d\'études en sécurité réseau','about.sub':'PacketGuard combine détection classique et ML moderne pour une solution complète.','a1':'Analyse temps réel avec Python et Scapy pour visibilité réseau approfondie','a2':'Modèle Isolation Forest entraîné sur le trafic réseau','a3':'API REST Flask servant un tableau de bord mis à jour en direct','a4':'Supporte tous les types: téléphones, laptops, IoT, routeurs','a5':'Fonctionne sous Windows avec privilèges admin','tech.tag':'Stack Technique','cta.title':'Prêt à protéger<br/>votre réseau ?','cta.sub':'Créez votre compte gratuit et commencez à détecter les menaces.','cta.btn':'CRÉER UN COMPTE GRATUIT','footer.dash':'Tableau de bord','login.welcome':'Bon retour ! Connectez-vous pour accéder à votre tableau.','signup.welcome':'Créez votre compte gratuit pour commencer.','form.email':'ADRESSE E-MAIL','form.email.ph':'vous@exemple.com','form.password':'MOT DE PASSE','form.pass.ph':'Votre mot de passe','form.newpass.ph':'Créez un mot de passe fort','form.name':'NOM COMPLET','form.name.ph':'Votre nom complet','form.remember':'Se souvenir','form.forgot':'Mot de passe oublié ?','form.or':'ou continuer avec','form.terms':'En vous inscrivant vous acceptez nos <a href="#">CGU</a> et <a href="#">Confidentialité</a>','forgot.title':'Réinitialiser','forgot.sub':'Entrez votre e-mail et nous vous enverrons un lien.','forgot.btn':'ENVOYER LE LIEN','forgot.back':'Retour à la connexion','pw.weak':'Faible','pw.fair':'Acceptable','pw.good':'Bon','pw.strong':'Fort'}
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
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

<<<<<<< HEAD
// Theme
=======
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
let dark=true;
function toggleTheme(){
  dark=!dark;
  document.documentElement.setAttribute('data-theme',dark?'dark':'light');
<<<<<<< HEAD
  document.getElementById('tbtn').innerHTML=dark?'<i class="fa-solid fa-moon"></i>':'<i class="fa-solid fa-sun"></i>';
  try{localStorage.setItem('pg-theme',dark?'dark':'light')}catch(e){}
}

// Auth
function openAuth(tab){document.getElementById('auth-overlay').classList.add('open');switchTab(tab);document.body.style.overflow='hidden'}
=======
  document.getElementById('tbtn').textContent=dark?'🌙':'☀️';
  try{localStorage.setItem('pg-theme',dark?'dark':'light')}catch(e){}
}

function openAuth(tab){
  document.getElementById('auth-overlay').classList.add('open');
  switchTab(tab);document.body.style.overflow='hidden';
}
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
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
<<<<<<< HEAD
function togglePass(id,ico){const i=document.getElementById(id);if(i.type==='password'){i.type='text';ico.innerHTML='<i class="fa-solid fa-eye-slash"></i>'}else{i.type='password';ico.innerHTML='<i class="fa-solid fa-eye"></i>'}}
function checkStrength(v){
  const el=document.getElementById('pws');if(!v){el.classList.remove('show');return}
  el.classList.add('show');let s=0;
  if(v.length>=8)s++;if(/[A-Z]/.test(v))s++;if(/[0-9]/.test(v))s++;if(/[^A-Za-z0-9]/.test(v))s++;
  const cols=['','#ff2d6b','#ffb800','#00d4ff','#00ff9d'];
  const lbls=[t('pw.weak'),t('pw.weak'),t('pw.fair'),t('pw.good'),t('pw.strong')];
  ['pb1','pb2','pb3','pb4'].forEach((id,i)=>{document.getElementById(id).style.background=i<s?cols[s]:'var(--border)'});
  const lbl=document.getElementById('pwlbl');lbl.textContent=lbls[s];lbl.style.color=cols[s]||'var(--text2)';
}
// ====== SESSION STATE ======
let currentUser = null;

function setLoggedIn(name, email) {
  currentUser = { name, email };
  // Nav swap
  document.getElementById('nav-auth-btns').style.display = 'none';
  const navUser = document.getElementById('nav-user');
  navUser.style.display = 'flex';
  document.getElementById('nav-username').textContent = name || email;
  // Reveal monitor
  document.getElementById('monitor-gate').style.display = 'none';
  const panel = document.getElementById('monitor-panel');
  panel.style.display = 'block';
  panel.style.animation = 'fu .5s ease both';
  document.getElementById('session-user').textContent = email;
  document.getElementById('session-time').textContent = 'Session started: ' + new Date().toLocaleTimeString();
}

function handleLogout() {
  if(monitoring) { monitoring=false; clearInterval(monitorInterval); }
  currentUser = null;
  document.getElementById('nav-auth-btns').style.display = 'flex';
  document.getElementById('nav-user').style.display = 'none';
  document.getElementById('monitor-gate').style.display = 'block';
  document.getElementById('monitor-panel').style.display = 'none';
  document.getElementById('dashboard').classList.remove('active');
  totalPackets=0; suspicious=0; risk=15;
}

function handleMonitorNavClick(e) {
  if (!currentUser) {
    e.preventDefault();
    openAuth('login');
  }
  // If logged in, href="/monitor" will navigate normally
}

async function _authFetch(url, body){
  // Try with full headers first. If that throws (CORS/network), try plain text fallback.
  const payload = JSON.stringify(body);
  try {
    const res = await fetch(url, {
      method: 'POST',
      credentials: 'include',
      headers: {'Content-Type': 'application/json'},
      body: payload
    });
    return await res.json();
  } catch(err) {
    console.error('[authFetch] primary fetch failed:', err.name, err.message, url);
    // Fallback: try without explicit Content-Type (avoids CORS preflight for some configs)
    try {
      const res2 = await fetch(url, {
        method: 'POST',
        credentials: 'same-origin',
        body: payload
      });
      return await res2.json();
    } catch(err2) {
      console.error('[authFetch] fallback fetch also failed:', err2.name, err2.message);
      throw new Error('Network error: ' + err.message + ' | Is the Flask server running on port 5000?');
    }
  }
}

// ── 2FA state ──────────────────────────────────────────────────
let _2fa_email = '', _2fa_pass = '', _2fa_pending = false;

async function handleLogin(){
  const errEl = document.getElementById('login-error');
  errEl.style.display = 'none';

  if(_2fa_pending){
    // Step 2: verify OTP
    const otp = document.getElementById('l-otp') ? document.getElementById('l-otp').value.trim() : '';
    if(!otp){ errEl.textContent='Please enter the OTP code.'; errEl.style.display='block'; return; }
    const btn = document.querySelector('#panel-login .btn-auth');
    if(btn){ btn.disabled=true; btn.textContent='Verifying...'; }
    try{
      const data = await _authFetch('/api/auth/login', {email:_2fa_email, password:_2fa_pass, otp});
      if(data.success){ window.location.href='/monitor'; }
      else{ errEl.textContent=data.error||'Invalid OTP.'; errEl.style.display='block'; }
    }catch(err){
      errEl.textContent=err.message||'Connection error.'; errEl.style.display='block';
    }finally{
      if(btn){ btn.disabled=false; btn.textContent='VERIFY CODE'; }
    }
    return;
  }

  // Step 1: submit email + password
  const e=document.getElementById('l-email').value, p=document.getElementById('l-pass').value;
  if(!e||!p){ errEl.textContent='Please fill in all fields.'; errEl.style.display='block'; return; }
  const btn=document.querySelector('#panel-login .btn-auth');
  if(btn){ btn.disabled=true; btn.textContent='Logging in...'; }
  try{
    const data = await _authFetch('/api/auth/login', {email:e, password:p});
    if(data.success){
      window.location.href='/monitor';
    } else if(data.require_otp){
      // Show OTP input
      _2fa_email   = e;
      _2fa_pass    = p;
      _2fa_pending = true;
      const loginPanel = document.getElementById('panel-login');
      // Hide email/pass fields, show OTP field
      const emailRow = document.getElementById('l-email').closest('.auth-field')||document.getElementById('l-email').parentElement;
      const passRow  = document.getElementById('l-pass').closest('.auth-field')||document.getElementById('l-pass').parentElement;
      if(emailRow) emailRow.style.display='none';
      if(passRow)  passRow.style.display='none';
      // Insert OTP field if not already there
      if(!document.getElementById('l-otp')){
        const otpDiv = document.createElement('div');
        otpDiv.id = 'otp-field-wrap';
        otpDiv.innerHTML = `
          <div style="margin-bottom:14px">
            <div style="font-family:monospace;font-size:9px;letter-spacing:2px;color:#3a5570;margin-bottom:8px;text-transform:uppercase">
              📧 OTP sent to ${data.message.replace('OTP sent to ','')}
            </div>
            <input id="l-otp" type="text" maxlength="6" placeholder="Enter 6-digit code"
              style="width:100%;padding:12px 14px;background:#0d1117;border:1px solid rgba(0,200,255,.3);
              border-radius:8px;color:#00c8ff;font-family:monospace;font-size:22px;letter-spacing:8px;
              text-align:center;outline:none;box-sizing:border-box"
              oninput="this.value=this.value.replace(/[^0-9]/g,'')"
              onkeydown="if(event.key==='Enter')handleLogin()">
            <div style="font-size:10px;color:#3a5570;margin-top:6px;text-align:center">Valid for 5 minutes</div>
          </div>`;
        const submitBtn = document.querySelector('#panel-login .btn-auth');
        if(submitBtn) submitBtn.parentElement.insertBefore(otpDiv, submitBtn);
      }
      if(btn){ btn.disabled=false; btn.textContent='VERIFY CODE'; }
      document.getElementById('l-otp') && document.getElementById('l-otp').focus();
    } else {
      errEl.textContent=data.error||'Invalid email or password.';
      errEl.style.display='block';
    }
  }catch(err){
    errEl.textContent=err.message||'Connection error. Is Flask running on port 5000?';
    errEl.style.display='block';
    console.error('[login]', err);
  }finally{
    if(!_2fa_pending && btn){ btn.disabled=false; btn.textContent='LOG IN'; }
  }
}
// ── Signup 2FA state ───────────────────────────────────────────
let _reg_email='', _reg_pass='', _reg_name='', _reg_otp_pending=false;

async function handleSignup(){
  const errEl = document.getElementById('signup-error') || (() => {
    const d=document.createElement('div');
    d.id='signup-error';
    d.style.cssText='color:#ff2d55;font-size:11px;margin-bottom:10px;display:none;padding:8px 12px;background:rgba(255,45,85,.08);border:1px solid rgba(255,45,85,.2);border-radius:6px;';
    const btn=document.querySelector('#panel-signup .btn-auth');
    if(btn) btn.parentElement.insertBefore(d, btn);
    return d;
  })();
  errEl.style.display='none';

  if(_reg_otp_pending){
    // Step 2: verify OTP
    const otp = document.getElementById('s-otp') ? document.getElementById('s-otp').value.trim() : '';
    if(!otp){ errEl.textContent='Please enter the OTP code.'; errEl.style.display='block'; return; }
    const btn = document.querySelector('#panel-signup .btn-auth');
    if(btn){ btn.disabled=true; btn.textContent='Verifying...'; }
    try{
      const data = await _authFetch('/api/auth/register', {name:_reg_name, email:_reg_email, password:_reg_pass, otp});
      if(data.success){ window.location.href='/monitor'; }
      else{ errEl.textContent=data.error||'Invalid OTP.'; errEl.style.display='block'; }
    }catch(err){
      errEl.textContent=err.message||'Connection error.'; errEl.style.display='block';
    }finally{
      if(btn){ btn.disabled=false; btn.textContent='VERIFY CODE'; }
    }
    return;
  }

  // Step 1: submit signup info
  const n=document.getElementById('s-name').value.trim();
  const e=document.getElementById('s-email').value.trim();
  const p=document.getElementById('s-pass').value;
  if(!n||!e||!p){ errEl.textContent='Please fill in all fields.'; errEl.style.display='block'; return; }
  const btn=document.querySelector('#panel-signup .btn-auth');
  if(btn){ btn.disabled=true; btn.textContent='Creating account...'; }
  try{
    const data = await _authFetch('/api/auth/register', {name:n, email:e, password:p});
    if(data.success){
      window.location.href='/monitor';
    } else if(data.require_otp){
      _reg_email = e; _reg_pass = p; _reg_name = n;
      _reg_otp_pending = true;
      // Hide signup fields
      ['s-name','s-email','s-pass'].forEach(id=>{
        const el=document.getElementById(id);
        if(el){ const row=el.closest('.auth-field')||el.parentElement; if(row) row.style.display='none'; }
      });
      // Insert OTP field
      if(!document.getElementById('s-otp')){
        const otpDiv=document.createElement('div');
        otpDiv.id='s-otp-wrap';
        otpDiv.innerHTML=`
          <div style="margin-bottom:14px">
            <div style="font-family:monospace;font-size:9px;letter-spacing:2px;color:#3a5570;margin-bottom:8px;text-transform:uppercase">
              📧 OTP sent to ${e}
            </div>
            <input id="s-otp" type="text" maxlength="6" placeholder="Enter 6-digit code"
              style="width:100%;padding:12px 14px;background:#0d1117;border:1px solid rgba(0,200,255,.3);
              border-radius:8px;color:#00c8ff;font-family:monospace;font-size:22px;letter-spacing:8px;
              text-align:center;outline:none;box-sizing:border-box"
              oninput="this.value=this.value.replace(/[^0-9]/g,'')"
              onkeydown="if(event.key==='Enter')handleSignup()">
            <div style="font-size:10px;color:#3a5570;margin-top:6px;text-align:center">Valid for 5 minutes</div>
          </div>`;
        const submitBtn=document.querySelector('#panel-signup .btn-auth');
        if(submitBtn) submitBtn.parentElement.insertBefore(otpDiv, submitBtn);
      }
      if(btn){ btn.disabled=false; btn.textContent='VERIFY CODE'; }
      document.getElementById('s-otp') && document.getElementById('s-otp').focus();
    } else {
      errEl.textContent=data.error||'Sign up failed.'; errEl.style.display='block';
    }
  }catch(err){
    errEl.textContent=err.message||'Connection error.'; errEl.style.display='block';
  }finally{
    if(!_reg_otp_pending && btn){ btn.disabled=false; btn.textContent='SIGN UP'; }
  }
}
function handleForgot(){const e=document.getElementById('f-email').value;if(!e){alert('Please enter your email.');return}alert('📧 Reset link would be sent to: '+e);closeForgot()}
function socialAuth(p){
  alert('Social login is not available. Please use email and password.');
}

// ====== LIVE MONITOR ======
let monitoring=false, totalPackets=0, suspicious=0, risk=15, monitorInterval=null;

function toggleMonitor(){
  const btn=document.getElementById('startBtn');
  const lbl=document.getElementById('btnLabel');
  const dashboard=document.getElementById('dashboard');

  if(!monitoring){
    monitoring=true;
    btn.classList.add('stop');
    lbl.textContent='Stop Protection';
    btn.querySelector('i').className='fa-solid fa-stop';
    document.getElementById('deviceIp').textContent=document.getElementById('targetIp').value||'192.168.1.1';
    dashboard.classList.add('active');
    document.getElementById('fullDashBtn').style.display='inline-flex';

    // Populate fake ports if "Scan + Monitor" mode
    if(document.getElementById('scanMode').value==='Scan + Monitor'){
      renderPorts();
    }
    monitorInterval=setInterval(updateStats,1800);
  } else {
    monitoring=false;
    btn.classList.remove('stop');
    lbl.textContent='Start Protection';
    btn.querySelector('i').className='fa-solid fa-play';
    clearInterval(monitorInterval);
  }
}

function updateStats(){
  if(!monitoring)return;
  const newPackets=Math.floor(Math.random()*120)+30;
  totalPackets+=newPackets;
  const pps=Math.floor(newPackets/1.8);
  const bytesSec=(pps*(Math.random()*800+200)/1024).toFixed(1);
  const changePct=(Math.random()*40-20).toFixed(1);

  document.getElementById('totalPackets').textContent=totalPackets.toLocaleString();
  document.getElementById('pps').innerHTML=`${pps} <small style="font-size:.9rem">pkt/s</small>`;
  document.getElementById('bytesSec').textContent=`${bytesSec} KB/s`;
  const chEl=document.getElementById('change');
  chEl.textContent=changePct>=0?`+${changePct}%`:`${changePct}%`;
  chEl.style.color=changePct>=0?'#10b981':'#ef4444';

  if(Math.random()>.85){suspicious+=Math.floor(Math.random()*3)+1;risk=Math.min(100,risk+8)}
  else if(Math.random()>.4){risk=Math.max(0,risk-3)}

  document.getElementById('suspCount').textContent=suspicious;
  document.getElementById('riskIndicator').style.left=`${risk}%`;

  let level='Low',color='#10b981';
  if(risk>70){level='Critical';color='#ef4444'}
  else if(risk>35){level='Warning';color='#f59e0b'}
  const rl=document.getElementById('riskLevel');
  rl.textContent=level;rl.style.color=color;
}

function renderPorts(){
  const portData=[
    {port:22,service:'SSH',status:'open'},{port:80,service:'HTTP',status:'open'},
    {port:443,service:'HTTPS',status:'open'},{port:23,service:'Telnet',status:'closed'},
    {port:3306,service:'MySQL',status:'filter'},{port:8080,service:'HTTP-Alt',status:'open'}
  ];
  const area=document.getElementById('portsArea');
  area.innerHTML='';
  portData.forEach(p=>{
    const card=document.createElement('div');
    card.className='port-card';
    card.innerHTML=`<div class="port-header"><span class="port-number">${p.port}</span><span class="port-status ${p.status}">${p.status.toUpperCase()}</span></div><div style="font-family:var(--fm);font-size:.85rem;color:var(--text2)">${p.service}</div>`;
    area.appendChild(card);
  });
}

=======

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

>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
// Scroll reveal
const obs=new IntersectionObserver(entries=>{
  entries.forEach(e=>{if(e.isIntersecting){e.target.classList.add('visible');obs.unobserve(e.target)}});
},{threshold:.1,rootMargin:'0px 0px -50px 0px'});
document.querySelectorAll('.reveal').forEach((el,i)=>{el.style.transitionDelay=(i%3)*.08+'s';obs.observe(el)});

document.querySelectorAll('a[href^="#"]').forEach(a=>{
<<<<<<< HEAD
  a.addEventListener('click',e=>{const target=document.querySelector(a.getAttribute('href'));if(target){e.preventDefault();target.scrollIntoView({behavior:'auto'})}});
=======
  a.addEventListener('click',e=>{const t=document.querySelector(a.getAttribute('href'));if(t){e.preventDefault();t.scrollIntoView({behavior:'smooth'})}});
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
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
<<<<<<< HEAD
  document.getElementById('tbtn').innerHTML=dark?'<i class="fa-solid fa-moon"></i>':'<i class="fa-solid fa-sun"></i>';
=======
  document.getElementById('tbtn').textContent=dark?'🌙':'☀️';
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
  setLang(sl);
})();
</script>
</body>
</html>
<<<<<<< HEAD

=======
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
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
<<<<<<< HEAD
    try:
        mod = _get_network_scanner()
        if mod is None:
            return
=======
    _scan_status["running"] = True
    try:
        scanner_path = os.path.join(BASE_DIR, "code", "network_scanner.py")
        if not os.path.exists(scanner_path):
            return
        import importlib.util
        spec = importlib.util.spec_from_file_location("network_scanner", scanner_path)
        mod  = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
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
<<<<<<< HEAD
        try:
            socketio.emit("scan_complete", {
                "device_count": count,
                "last_scan": _scan_status["last_scan"]
            })
        except Exception:
            pass
=======
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
    except Exception as e:
        print(f"[AUTO-SCAN] Error: {e}")
    finally:
        _scan_status["running"] = False
        _scan_status["next_scan"] = datetime.fromtimestamp(time.time() + SCAN_INTERVAL).isoformat()

<<<<<<< HEAD


# ── Smart Scanner: dual-tier real-time discovery ─────────────────
# Tier 1: reads OS ARP cache every 4s (zero network traffic)
# Tier 2: full ARP sweep every 45s (finds new/sleeping devices)
# Both tiers start immediately — no waiting
# Auto scan: run immediately on startup, then every SCAN_INTERVAL seconds
def _do_first_scan():
    run_network_scan_with_history()

threading.Thread(target=_do_first_scan, daemon=True, name="FirstScan").start()
threading.Thread(target=auto_scan_loop,  daemon=True, name="AutoScan").start()


@app.route("/api/ports", methods=["POST"])
@require_role("admin")
def api_ports():
    """
    Real port scanner endpoint called by monitor.html.
    Body JSON: { "target": "192.168.1.1", "scan_type": "Quick Scan (top 100 ports)" }
    Returns:   { "success": true, "target": "...", "ports": [...], "open_count": N }
    """
    from flask import session as _sess
    if not _sess.get("user_id"):
        return jsonify({"success": False, "error": "Not authenticated"}), 401

    data        = request.get_json() or {}
    target      = data.get("target", "").strip()
    scan_type   = data.get("scan_type", "Standard (top 1000 ports)")

    if not target:
        return jsonify({"success": False, "error": "No target IP provided"}), 400

    # Validate IP address
    import socket as _sock
    try:
        _sock.inet_aton(target.split("/")[0])
    except Exception:
        return jsonify({"success": False, "error": "Invalid IP address"}), 400

    try:
        scanner_path = os.path.join(BASE_DIR, "code", "network_scanner.py")
        import importlib.util
        spec = importlib.util.spec_from_file_location("network_scanner", scanner_path)
        mod  = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        ports      = mod.scan_ports(target, scan_type)
        open_count = sum(1 for p in ports if p["status"] == "open")

        # Only return open + filtered ports to keep response small
        visible = [p for p in ports if p["status"] in ("open", "filtered")]

        return jsonify({
            "success":    True,
            "target":     target,
            "scan_type":  scan_type,
            "ports":      visible,
            "open_count": open_count,
            "total_scanned": len(ports),
        })
    except Exception as e:
        print(f"[API/PORTS] Error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

=======
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
@app.route("/api/scan_history")
def api_scan_history():
    return jsonify(load_scan_history())

@app.route("/api/scan_now", methods=["POST"])
<<<<<<< HEAD
@require_role("analyst")
def api_scan_now_history():
    # Always start immediately, never block waiting for auto-scan to finish.
    # Uses the cached scanner module (no re-import delay).
    def _run():
        global _scan_status
        _scan_status["running"] = True
        try:
            mod = _get_network_scanner()
            if mod is None:
                return
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
            try:
                socketio.emit("scan_complete", {
                    "device_count": count,
                    "last_scan": _scan_status["last_scan"],
                    "trigger": "manual"
                })
            except Exception:
                pass
        except Exception as e:
            print(f"[SCAN_NOW] Error: {e}")
        finally:
            _scan_status["running"] = False
            _scan_status["next_scan"] = datetime.fromtimestamp(time.time() + SCAN_INTERVAL).isoformat()
    threading.Thread(target=_run, daemon=True).start()
    return jsonify({"status": "scan_started"})


# ── IP Block / Whitelist ──────────────────────────────────────────
=======
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
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b

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
<<<<<<< HEAD
@require_login
=======
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
def api_get_blocklist():
    return jsonify({"blocked": load_blocklist(), "whitelisted": load_whitelist()})

@app.route("/api/blocklist/block", methods=["POST"])
<<<<<<< HEAD
@require_role("admin")
=======
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
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
<<<<<<< HEAD
@require_role("admin")
=======
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
def api_unblock_ip():
    data = request.get_json() or {}
    ip   = data.get("ip","").strip()
    blocked = [e for e in load_blocklist() if e["ip"] != ip]
    save_list(BLOCKLIST_FILE, blocked)
    return jsonify({"success": True})

@app.route("/api/blocklist/whitelist", methods=["POST"])
<<<<<<< HEAD
@require_role("admin")
=======
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
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
<<<<<<< HEAD
@require_role("admin")
=======
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
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
<<<<<<< HEAD
@require_role("analyst")
=======
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
def api_get_email_config():
    cfg = load_email_config()
    safe = dict(cfg)
    if safe.get("password"):
        safe["password"] = "••••••••"  # never expose password
    return jsonify(safe)

@app.route("/api/email_config", methods=["POST"])
<<<<<<< HEAD
@require_role("admin")
=======
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
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
<<<<<<< HEAD
@require_role("admin")
=======
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
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


<<<<<<< HEAD
@app.route("/api/smtp-status")
@require_login
def api_smtp_status():
    configured = bool(SMTP_EMAIL and SMTP_PASSWORD and
                      SMTP_EMAIL != "your@gmail.com" and
                      SMTP_PASSWORD != "your-app-password")
    return jsonify({"configured": configured, "sender": SMTP_EMAIL if configured else None})


@app.route("/api/smtp-test", methods=["POST"])
@require_role("analyst")
def api_smtp_test():
    data = _req.get_json() or {}
    to = data.get("to", "").strip()
    if not to or "@" not in to:
        return jsonify({"success": False, "error": "Invalid recipient email."}), 400
    try:
        sent = _send_otp_email(to, "TEST-OK", "PacketGuard User")
        if sent:
            return jsonify({"success": True})
        return jsonify({"success": False, "error": "Failed to send. Check SMTP credentials."})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


=======
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
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
<<<<<<< HEAD
@require_role("analyst")
=======
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
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
<<<<<<< HEAD
@require_role("analyst")
=======
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
def export_alerts_json():
    alerts = load_alerts()
    output = json.dumps(alerts, indent=2, default=str)
    return Response(output, mimetype="application/json",
                    headers={"Content-Disposition": "attachment;filename=packetguard_alerts.json"})

@app.route("/api/export/scan_history.csv")
<<<<<<< HEAD
@require_role("analyst")
=======
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
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
<<<<<<< HEAD
@app.route("/favicon.ico")
def favicon():
    """Return a minimal inline SVG favicon as ICO to silence 404s."""
    # Shield icon as a 1x1 transparent GIF (32 bytes) — avoids any file dependency
    import base64
    ico = base64.b64decode(
        "AAABAAEAEBAQAAEABAAoAQAAFgAAACgAAAAQAAAAIAAAAAEABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAA////AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA"
        "/wAAAP8AAAD/AAAA/w=="
    )
    return Response(ico, mimetype="image/x-icon",
                    headers={"Cache-Control": "public, max-age=86400"})


@app.route("/")
def home():
    # Always serve the built-in HOME_HTML (landing page + login form).
    return Response(HOME_HTML, mimetype="text/html")

MONITOR_HTML = '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>PacketGuard - Live Monitor</title>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Syne:wght@400;600;700;800&family=DM+Sans:wght@300;400;500&display=swap" rel="stylesheet"/>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css"/>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#020508;--surface:#060c14;--surface2:#0a1520;
  --border:#0f2035;--border2:#1a3050;
  --accent:#00d4ff;--accent2:#ff2d6b;--accent3:#00ff9d;--warn:#ffb800;
  --text:#b8cfe8;--text2:#6a8aaa;--white:#e8f4ff;
  --card:rgba(6,12,20,0.95);--danger:#ef4444;
  --fm:'Share Tech Mono',monospace;--fd:'Syne',sans-serif;--fb:'DM Sans',sans-serif;
}
html{scroll-behavior:auto}
body{background:var(--bg);color:var(--text);font-family:var(--fb);overflow-x:hidden;min-height:100vh}

/* BG */
.bg-orbs{position:fixed;inset:0;z-index:0;pointer-events:none;overflow:hidden}
.orb{position:absolute;border-radius:50%;filter:blur(100px);animation:od 20s ease-in-out infinite alternate}
.orb1{width:600px;height:600px;background:radial-gradient(circle,rgba(0,212,255,.055),transparent 70%);top:-200px;left:-100px}
.orb2{width:500px;height:500px;background:radial-gradient(circle,rgba(0,255,157,.04),transparent 70%);bottom:-100px;right:-100px;animation-delay:-10s}
@keyframes od{0%{transform:translate(0,0)}100%{transform:translate(30px,25px)}}
.bg-grid{position:fixed;inset:0;z-index:0;pointer-events:none;
  background-image:linear-gradient(var(--border) 1px,transparent 1px),linear-gradient(90deg,var(--border) 1px,transparent 1px);
  background-size:50px 50px;opacity:.35;
  mask-image:radial-gradient(ellipse 80% 80% at 50% 50%,black,transparent)}

/* NAV */
nav{position:fixed;top:0;left:0;right:0;z-index:100;display:flex;align-items:center;justify-content:space-between;padding:0 40px;height:62px;
  background:rgba(2,5,8,.92);backdrop-filter:blur(20px);border-bottom:1px solid var(--border)}
.nav-logo{display:flex;align-items:center;gap:10px;font-family:var(--fd);font-size:17px;font-weight:800;color:var(--white);letter-spacing:2px;text-decoration:none}
.nav-logo-icon{width:30px;height:30px;border-radius:6px;background:linear-gradient(135deg,rgba(0,212,255,.15),rgba(0,255,157,.1));
  border:1px solid rgba(0,212,255,.3);display:flex;align-items:center;justify-content:center;
  font-family:var(--fm);font-size:10px;color:var(--accent);font-weight:700;box-shadow:0 0 12px rgba(0,212,255,.2)}
.nav-r{display:flex;align-items:center;gap:14px}
.user-pill{display:flex;align-items:center;gap:8px;padding:5px 14px;border-radius:20px;
  background:rgba(0,212,255,.05);border:1px solid rgba(0,212,255,.15);
  font-family:var(--fm);font-size:11px;color:var(--accent)}
.udot{width:7px;height:7px;border-radius:50%;background:var(--accent3);animation:bl 1.5s ease-in-out infinite}
@keyframes bl{0%,100%{opacity:1}50%{opacity:.2}}
.btn-dash{padding:7px 18px;border-radius:6px;font-family:var(--fd);font-size:12px;font-weight:700;letter-spacing:1px;
  background:rgba(0,212,255,.1);border:1px solid rgba(0,212,255,.3);color:var(--accent);cursor:pointer;transition:all .2s;text-decoration:none}
.btn-dash:hover{background:rgba(0,212,255,.18);box-shadow:0 0 20px rgba(0,212,255,.2)}
.btn-logout{padding:7px 14px;border-radius:6px;font-size:12px;background:transparent;
  border:1px solid rgba(239,68,68,.3);color:#ef4444;cursor:pointer;font-family:var(--fb);transition:all .2s}
.btn-logout:hover{background:rgba(239,68,68,.08);border-color:rgba(239,68,68,.6)}

/* MAIN */
main{position:relative;z-index:1;padding:100px 40px 60px;max-width:1100px;margin:0 auto}

/* HERO */
.hero{text-align:center;margin-bottom:3rem;animation:fu .6s ease both}
@keyframes fu{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:none}}
.hero-badge{display:inline-flex;align-items:center;gap:8px;padding:6px 16px;border-radius:20px;
  background:rgba(0,212,255,.06);border:1px solid rgba(0,212,255,.18);
  font-family:var(--fm);font-size:11px;color:var(--accent);letter-spacing:2px;margin-bottom:1.4rem}
.hero-badge .bdot{width:6px;height:6px;border-radius:50%;background:var(--accent3);animation:bl 1.5s ease-in-out infinite}
.hero h1{font-family:var(--fd);font-size:clamp(2rem,5vw,3.2rem);font-weight:800;color:var(--white);line-height:1.15;margin-bottom:1rem}
.hero h1 span{background:linear-gradient(135deg,var(--accent),var(--accent3));-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}
.hero p{font-size:1rem;color:var(--text2);max-width:520px;margin:0 auto}

/* CONTROL PANEL */
.panel{background:var(--card);border:1px solid var(--border2);border-radius:16px;padding:2rem;
  box-shadow:0 20px 60px rgba(0,0,0,.5);margin-bottom:2rem;animation:fu .6s .1s ease both;position:relative;overflow:hidden}
.panel::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;
  background:linear-gradient(90deg,transparent,rgba(0,212,255,.3),transparent)}
.panel-title{font-family:var(--fm);font-size:11px;letter-spacing:2px;color:var(--accent);margin-bottom:1.4rem;
  display:flex;align-items:center;gap:8px}
.panel-title::before{content:'';width:16px;height:1px;background:var(--accent)}
.input-row{display:flex;flex-wrap:wrap;gap:12px;margin-bottom:1.4rem}
.pg-input{flex:1;min-width:200px;padding:.9rem 1.1rem;background:rgba(4,10,18,.8);
  border:1px solid var(--border2);border-radius:8px;color:var(--white);font-size:.95rem;font-family:var(--fb);
  transition:border-color .2s,box-shadow .2s}
.pg-input:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(0,212,255,.12)}
.pg-input option{background:#040a12}

/* Feature toggles */
.features-row{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:1.6rem}
.feat-toggle{display:flex;align-items:center;gap:8px;padding:8px 16px;border-radius:8px;
  background:rgba(0,212,255,.04);border:1px solid var(--border2);cursor:pointer;transition:all .2s;
  font-size:13px;color:var(--text2);font-family:var(--fb);user-select:none}
.feat-toggle:hover{border-color:rgba(0,212,255,.3);color:var(--text)}
.feat-toggle.active{background:rgba(0,212,255,.1);border-color:rgba(0,212,255,.4);color:var(--accent)}
.feat-toggle i{font-size:12px}
.feat-toggle .toggle-dot{width:8px;height:8px;border-radius:50%;background:var(--border2);transition:background .2s}
.feat-toggle.active .toggle-dot{background:var(--accent3)}

.start-btn{width:100%;padding:1rem;border-radius:10px;font-family:var(--fd);font-weight:700;font-size:1rem;
  letter-spacing:2px;cursor:pointer;transition:all .25s;text-transform:uppercase;
  background:linear-gradient(135deg,rgba(0,212,255,.15),rgba(0,255,157,.08));
  border:1px solid rgba(0,212,255,.4);color:var(--white);
  box-shadow:0 0 30px rgba(0,212,255,.1)}
.start-btn:hover{box-shadow:0 0 50px rgba(0,212,255,.25);border-color:rgba(0,212,255,.7);transform:translateY(-2px)}
.start-btn.running{background:linear-gradient(135deg,rgba(239,68,68,.15),rgba(239,68,68,.08));
  border-color:rgba(239,68,68,.4);box-shadow:0 0 30px rgba(239,68,68,.1)}
.start-btn.running:hover{box-shadow:0 0 50px rgba(239,68,68,.25);border-color:rgba(239,68,68,.7)}

/* DASHBOARD STATS */
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:1rem;margin-bottom:1.5rem;animation:fu .6s .2s ease both}
.stat-card{background:var(--card);border:1px solid var(--border2);border-radius:12px;padding:1.4rem;
  transition:border-color .2s,transform .2s;position:relative;overflow:hidden}
.stat-card::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;
  background:linear-gradient(90deg,transparent,var(--accent-line,rgba(0,212,255,.25)),transparent)}
.stat-card:hover{border-color:rgba(0,212,255,.3);transform:translateY(-3px)}
.stat-card:nth-child(2){--accent-line:rgba(0,255,157,.25)}
.stat-card:nth-child(3){--accent-line:rgba(255,184,0,.25)}
.stat-card:nth-child(4){--accent-line:rgba(239,68,68,.25)}
.stat-label{font-family:var(--fm);font-size:10px;letter-spacing:2px;color:var(--text2);margin-bottom:.8rem;text-transform:uppercase}
.stat-val{font-family:var(--fm);font-size:2rem;font-weight:700;color:var(--white);line-height:1;margin-bottom:.4rem}
.stat-val small{font-size:.9rem;color:var(--text2)}
.stat-sub{font-size:.85rem;color:var(--text2)}

/* RISK SCALE */
.risk-card{background:var(--card);border:1px solid var(--border2);border-radius:12px;padding:1.6rem;
  margin-bottom:1.5rem;animation:fu .6s .25s ease both}
.risk-title{font-family:var(--fm);font-size:10px;letter-spacing:2px;color:var(--text2);margin-bottom:1.2rem;text-transform:uppercase}
.scale-bar{height:14px;border-radius:999px;
  background:linear-gradient(to right,#10b981 0%,#f59e0b 50%,#ef4444 100%);
  position:relative;margin-bottom:.8rem;box-shadow:0 0 20px rgba(0,0,0,.3)}
.scale-indicator{position:absolute;top:50%;transform:translate(-50%,-50%);
  width:5px;height:200%;background:white;border-radius:2px;
  box-shadow:0 0 10px rgba(255,255,255,.8);transition:left .5s ease}
.scale-labels{display:flex;justify-content:space-between;font-family:var(--fm);font-size:11px;margin-bottom:.8rem}
.scale-labels .low{color:#10b981}.scale-labels .med{color:#f59e0b}.scale-labels .high{color:#ef4444}
.risk-info{font-family:var(--fm);font-size:12px;color:var(--text2);text-align:center}

/* LIVE GRAPH PLACEHOLDER */
.graph-card{background:var(--card);border:1px solid var(--border2);border-radius:12px;padding:1.6rem;
  margin-bottom:1.5rem;animation:fu .6s .3s ease both}
.graph-title{font-family:var(--fm);font-size:10px;letter-spacing:2px;color:var(--text2);margin-bottom:1rem;text-transform:uppercase}
.graph-body{height:180px;display:flex;align-items:center;justify-content:center;
  gap:12px;color:var(--text2);font-family:var(--fm);font-size:12px;
  border:1px dashed var(--border2);border-radius:8px}
.graph-bars{display:flex;align-items:flex-end;gap:4px;height:80px}
.bar{width:8px;border-radius:3px 3px 0 0;background:rgba(0,212,255,.3);animation:bh 1.5s ease-in-out infinite alternate}
@keyframes bh{0%{transform:scaleY(.3)}100%{transform:scaleY(1)}}

/* PORTS */
.ports-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:1rem;animation:fu .6s .35s ease both}
.port-card{background:rgba(4,10,18,.8);border:1px solid var(--border2);border-radius:10px;padding:1.2rem}
.port-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:.5rem}
.port-num{font-family:var(--fm);font-size:1.4rem;font-weight:700;color:var(--accent)}
.port-badge{padding:3px 10px;border-radius:4px;font-family:var(--fm);font-size:10px;font-weight:700;letter-spacing:1px}
.port-badge.open{background:rgba(0,255,157,.08);color:var(--accent3);border:1px solid rgba(0,255,157,.2)}
.port-badge.closed{background:rgba(239,68,68,.08);color:#ef4444;border:1px solid rgba(239,68,68,.2)}
.port-badge.filter{background:rgba(255,184,0,.08);color:var(--warn);border:1px solid rgba(255,184,0,.2)}
.port-svc{font-family:var(--fm);font-size:.8rem;color:var(--text2)}

/* ALERT SECTION */
.alert-card{background:var(--card);border:1px solid var(--border2);border-radius:12px;padding:1.6rem;
  margin-bottom:1.5rem;animation:fu .6s .28s ease both;max-height:300px;overflow-y:auto}
.alert-card::-webkit-scrollbar{width:4px}
.alert-card::-webkit-scrollbar-track{background:var(--surface)}
.alert-card::-webkit-scrollbar-thumb{background:var(--border2);border-radius:2px}
.alert-line{display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid var(--border);font-family:var(--fm);font-size:11px}
.alert-line:last-child{border-bottom:none}
.alert-time{color:var(--text2);min-width:70px}
.alert-badge{padding:2px 8px;border-radius:3px;font-size:10px;font-weight:700;letter-spacing:1px}
.badge-CRITICAL{background:rgba(255,45,85,.1);color:#ff2d55;border:1px solid rgba(255,45,85,.2)}
.badge-HIGH{background:rgba(255,100,0,.1);color:#ff6400;border:1px solid rgba(255,100,0,.2)}
.badge-MEDIUM{background:rgba(255,184,0,.08);color:var(--warn);border:1px solid rgba(255,184,0,.2)}
.alert-msg{color:var(--text);flex:1}
.empty-state{text-align:center;padding:2rem;color:var(--text2);font-family:var(--fm);font-size:12px}

/* BOTTOM NAV */
.bottom-bar{display:flex;justify-content:space-between;align-items:center;margin-top:2rem;
  padding:1.2rem 1.6rem;background:var(--card);border:1px solid var(--border2);border-radius:12px;
  animation:fu .6s .4s ease both}
.bb-info{font-family:var(--fm);font-size:11px;color:var(--text2)}
.bb-info span{color:var(--accent)}
.btn-full-dash{padding:10px 24px;border-radius:8px;font-family:var(--fd);font-weight:700;font-size:13px;
  letter-spacing:1.5px;background:linear-gradient(135deg,rgba(0,212,255,.15),rgba(157,111,255,.1));
  border:1px solid rgba(0,212,255,.4);color:var(--white);cursor:pointer;transition:all .2s;text-decoration:none;
  display:inline-flex;align-items:center;gap:8px}
.btn-full-dash:hover{box-shadow:0 0 30px rgba(0,212,255,.2);transform:translateY(-2px)}

/* DASHBOARD always visible */
#live-dashboard{display:block}
#live-dashboard.show #dash-waiting{display:none}
#dash-waiting{
  display:flex;flex-direction:column;align-items:center;justify-content:center;
  padding:3rem 2rem;gap:1rem;color:var(--text2);font-family:var(--fm);font-size:13px;
  letter-spacing:1px;text-align:center;
}
#dash-waiting .wait-icon{font-size:2.5rem;color:var(--border2);margin-bottom:.5rem}
.stats-grid,.risk-card,.alert-card,.graph-card,.bottom-bar,#portsSection{
  opacity:0;pointer-events:none;transition:opacity .4s ease;
}
#live-dashboard.show .stats-grid,
#live-dashboard.show .risk-card,
#live-dashboard.show .alert-card,
#live-dashboard.show .graph-card,
#live-dashboard.show .bottom-bar{
  opacity:1;pointer-events:auto;
}

[data-theme="light"]{
  --bg:#ffffff;--surface:#f4f7fb;--surface2:#edf1f7;
  --border:#d0dce8;--border2:#b8ccde;
  --text:#1a2f48;--text2:#5a7a9a;--white:#1a2f48;
  --card:rgba(255,255,255,0.98);--accent:#0077aa;--accent3:#00aa66;
}
[data-theme="light"] body{background:#ffffff;background-image:none}
[data-theme="light"] body::before{display:none}
[data-theme="light"] body::after{display:none}
[data-theme="light"] nav{background:rgba(255,255,255,.95);border-bottom:1px solid var(--border)}
[data-theme="light"] .panel{background:#ffffff;border-color:var(--border);box-shadow:0 2px 12px rgba(0,0,0,.06)}
[data-theme="light"] .stat-card{background:#ffffff;border-color:var(--border);box-shadow:0 2px 8px rgba(0,0,0,.06)}
[data-theme="light"] .stat-num{color:var(--text)}
[data-theme="light"] .start-btn{background:linear-gradient(135deg,rgba(0,119,170,.15),rgba(0,170,102,.1));border-color:rgba(0,119,170,.4)}
[data-theme="light"] .toggle-feature{background:rgba(0,119,170,.06);border-color:var(--border)}
[data-theme="light"] .toggle-feature.active{background:rgba(0,119,170,.12);border-color:rgba(0,119,170,.4)}
[data-theme="light"] .finput,.finput-wrap input{background:#f4f7fb;border-color:var(--border);color:var(--text)}
[data-theme="light"] .pg-input{background:#f4f7fb;border-color:var(--border);color:var(--text)}
[data-theme="light"] .pg-input option{background:#ffffff;color:var(--text)}
[data-theme="light"] select{background:#f4f7fb;border-color:var(--border);color:var(--text)}
[data-theme="light"] .alert-card{background:#f8fafc;border-color:var(--border)}
[data-theme="light"] .alert-item{border-color:var(--border)}
[data-theme="light"] .bottom-bar{background:#ffffff;border-color:var(--border)}
[data-theme="light"] .hero h1{color:var(--text)}
[data-theme="light"] .hero h1 span{-webkit-text-fill-color:var(--accent)}

/* Theme toggle button */
.btn-theme{padding:7px 12px;border-radius:6px;font-size:14px;background:transparent;
  border:1px solid var(--border2);color:var(--text2);cursor:pointer;transition:all .2s;line-height:1}
.btn-theme:hover{border-color:var(--accent);color:var(--accent)}

</style>
</head>
<body>

<div class="bg-orbs"><div class="orb orb1"></div><div class="orb orb2"></div></div>
<div class="bg-grid"></div>

<!-- NAV -->
<nav>
  <a class="nav-logo" href="/">
    <div class="nav-logo-icon">PG</div>
    PACKETGUARD
  </a>
  <div class="nav-r">
    <div class="user-pill"><div class="udot"></div><span id="nav-username">User</span></div>
    <a class="btn-dash" href="/dashboard">Full Dashboard</a>
    <button class="btn-theme" id="theme-btn" onclick="toggleTheme()" title="Toggle theme"><i class="fa-solid fa-moon"></i></button>
    <button class="btn-logout" onclick="handleLogout()">Log Out</button>
  </div>
</nav>

<main>
  <!-- HERO -->
  <div class="hero">
    <div class="hero-badge"><div class="bdot"></div>LIVE NETWORK MONITOR</div>
    <h1>Start <span>Protecting</span> Your Network</h1>
    <p>Enter a target IP, choose your scan options and features, then launch real-time packet monitoring.</p>
  </div>

  <!-- CONTROL PANEL -->
  <div class="panel">
    <div class="panel-title">// MONITOR CONFIGURATION</div>

    <div class="input-row">
      <input type="text" class="pg-input" id="targetIp" placeholder="Target IP / Range (e.g. 192.168.1.0/24)" value=""/>
      <select class="pg-input" id="scanType">
        <option>Quick Scan (top 100 ports)</option>
        <option selected>Standard (top 1000 ports)</option>
        <option>Full (1â€“65535)</option>
      </select>
      <select class="pg-input" id="scanMode">
        <option value="monitor">Monitor Only</option>
        <option value="scan">Scan + Monitor</option>
        <option value="deep">Deep Analysis</option>
      </select>
    </div>

    <!-- Feature toggles -->
    <div class="features-row" id="featureToggles">
      <div class="feat-toggle active" data-feat="ml" onclick="toggleFeature(this)">
        <div class="toggle-dot"></div><i class="fa-solid fa-brain"></i> ML Detection
      </div>
      <div class="feat-toggle active" data-feat="alerts" onclick="toggleFeature(this)">
        <div class="toggle-dot"></div><i class="fa-solid fa-bell"></i> Real-Time Alerts
      </div>
      <div class="feat-toggle" data-feat="ports" onclick="toggleFeature(this)">
        <div class="toggle-dot"></div><i class="fa-solid fa-network-wired"></i> Port Scanner
      </div>
      <div class="feat-toggle active" data-feat="rate" onclick="toggleFeature(this)">
        <div class="toggle-dot"></div><i class="fa-solid fa-gauge-high"></i> Rate Monitor
      </div>
      <div class="feat-toggle" data-feat="geo" onclick="toggleFeature(this)">
        <div class="toggle-dot"></div><i class="fa-solid fa-location-dot"></i> Geo Tracking
      </div>
      <div class="feat-toggle" data-feat="block" onclick="toggleFeature(this)">
        <div class="toggle-dot"></div><i class="fa-solid fa-ban"></i> IP Blocking
      </div>
    </div>

    <button class="start-btn" id="startBtn" onclick="toggleMonitor()">
      <i class="fa-solid fa-play" id="startIcon"></i>&nbsp;&nbsp;<span id="startLabel">START PROTECTION</span>
    </button>
  </div>

  <!-- LIVE DASHBOARD (shown after start) -->
  <div id="live-dashboard">

    <!-- WAITING STATE -->
    <div id="dash-waiting">
      <div class="wait-icon"><i class="fa-solid fa-shield"></i></div>
      <div>Click <strong style="color:var(--accent)">START PROTECTION</strong> to begin live monitoring</div>
    </div>

    <!-- STAT CARDS -->
    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-label">Monitored Target</div>
        <div class="stat-val" id="d-ip" style="font-size:1.2rem">â€”</div>
        <div class="stat-sub" id="d-session">Session not started</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Packets Captured</div>
        <div class="stat-val" id="d-packets">0</div>
        <div class="stat-sub">Since session started</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Live Traffic Rate</div>
        <div class="stat-val" id="d-pps">0 <small>pkt/s</small></div>
        <div class="stat-sub"><span id="d-kbs">0 KB/s</span> &nbsp;â€¢&nbsp; <span id="d-change">+0%</span></div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Suspicious Packets</div>
        <div class="stat-val" id="d-susp" style="color:#f59e0b">0</div>
        <div class="stat-sub">Flagged by anomaly detector</div>
      </div>
    </div>

    <!-- RISK SCALE -->
    <div class="risk-card">
      <div class="risk-title">Malicious Traffic Risk Level</div>
      <div class="scale-bar"><div class="scale-indicator" id="riskIndicator" style="left:15%"></div></div>
      <div class="scale-labels"><span class="low">Safe</span><span class="med">Warning</span><span class="high">Critical</span></div>
      <div class="risk-info">Current Risk: <strong id="riskLevel" style="color:#10b981">Low</strong> &nbsp;â€¢&nbsp; <span id="d-susp2">0</span> suspicious packets</div>
    </div>

    <!-- ALERTS FEED (shown if alerts feature active) -->
    <div class="alert-card" id="alertSection">
      <div class="panel-title" style="margin-bottom:1rem">// LIVE ALERTS FEED</div>
      <div id="alertFeed"><div class="empty-state"><i class="fa-solid fa-shield-check" style="font-size:1.5rem;margin-bottom:.5rem;display:block;color:var(--accent3)"></i>No threats detected â€” network is clean</div></div>
    </div>

    <!-- LIVE GRAPH -->
    <div class="graph-card">
      <div class="graph-title">Live Traffic Flow</div>
      <div class="graph-body">
        <div class="graph-bars" id="graphBars"></div>
        <span>Real-time visualization â€” Chart.js in production build</span>
      </div>
    </div>

    <!-- PORT RESULTS (shown if port scanner active) -->
    <div id="portsSection" style="display:none">
      <div class="panel-title" style="margin-bottom:1rem;margin-top:1rem">// PORT SCAN RESULTS</div>
      <div class="ports-grid" id="portsGrid"></div>
    </div>

    <!-- BOTTOM BAR -->
    <div class="bottom-bar">
      <div class="bb-info">Session active on <span id="bb-ip">â€”</span> &nbsp;â€¢&nbsp; Runtime: <span id="bb-runtime">00:00</span> &nbsp;â€¢&nbsp; <span id="bb-feat-count">0</span> features enabled</div>
      <a class="btn-full-dash" id="dashBtn" href="/dashboard"><i class="fa-solid fa-chart-line"></i> Open Full Dashboard</a>
    </div>

  </div>

</main>

<script>
// â”€â”€ Session guard â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
document.documentElement.style.visibility = 'hidden';
(async function(){
  try {
    const res  = await fetch('/api/auth/me');
    const data = await res.json();
    if (data.success && data.user) {
      document.getElementById('nav-username').textContent = data.user.name || data.user.email;
      document.documentElement.style.visibility = 'visible';
      // Auto-fill real network IP and gateway
      try {
        const ni = await (await fetch('/api/network_info')).json();
        if (ni.local_ip && ni.local_ip !== '127.0.0.1') {
          const subnet = ni.network_range || ni.local_ip;
          document.getElementById('targetIp').value = subnet;
          // Store gateway globally for display
          window._gatewayIp = ni.gateway_ip || null;
          window._subnetVal  = subnet;
          // Show gateway label next to input if available
          if (ni.gateway_ip) {
            let gwLabel = document.getElementById('gw-label');
            if (!gwLabel) {
              gwLabel = document.createElement('div');
              gwLabel.id = 'gw-label';
              gwLabel.style.cssText = 'font-family:var(--fm);font-size:0.78rem;color:var(--accent3);margin-top:6px;letter-spacing:0.04em;';
              document.getElementById('targetIp').parentNode.appendChild(gwLabel);
            }
            gwLabel.textContent = '⬡ Gateway: ' + ni.gateway_ip + '  //  Subnet: ' + subnet;
          }
        }
      } catch(e) {}
      return;
    }
  } catch(e) {}
  document.documentElement.style.visibility = 'visible';
  document.body.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100vh;background:#020508;font-family:monospace;color:#00d4ff;font-size:18px;flex-direction:column;gap:16px"><span style="font-size:40px">&#128274;</span><span>Session expired &mdash; redirecting to login&hellip;</span></div>';
  setTimeout(function(){ window.location.href = '/'; }, 1500);
})();

function handleLogout() {
  fetch('/api/auth/logout', { method: 'POST' }).finally(() => { window.location.href = '/'; });
}

// â”€â”€ Feature toggles â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
function toggleFeature(el) {
  el.classList.toggle('active');
  updateFeatureCount();
}
function updateFeatureCount() {
  const count = document.querySelectorAll('.feat-toggle.active').length;
  const el = document.getElementById('bb-feat-count');
  if (el) el.textContent = count;
}
updateFeatureCount();

// â”€â”€ Live monitoring â€” real data from /api/live_state & /api/alerts â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
let monitoring = false, monInterval = null, alertPollInterval = null;
let startTime = null, lastAlertCount = 0;

function toggleMonitor() {
  const btn   = document.getElementById('startBtn');
  const icon  = document.getElementById('startIcon');
  const label = document.getElementById('startLabel');
  const dash  = document.getElementById('live-dashboard');

  if (!monitoring) {
    monitoring = true;
    startTime  = Date.now();
    btn.classList.add('running');
    icon.className = 'fa-solid fa-stop';
    label.textContent = 'STOP PROTECTION';


    const ip = document.getElementById('targetIp').value || '192.168.1.0/24';
    const gwSuffix = window._gatewayIp ? ' (GW: ' + window._gatewayIp + ')' : '';
    document.getElementById('d-ip').textContent      = ip + gwSuffix;
    document.getElementById('d-ip').title            = window._gatewayIp ? 'Gateway: ' + window._gatewayIp : '';
    document.getElementById('d-session').textContent = 'Active monitoring session';
    document.getElementById('bb-ip').textContent     = ip;

    dash.classList.add('show');

    // Init graph bars
    const gb = document.getElementById('graphBars');
    gb.innerHTML = '';
    for (let i = 0; i < 20; i++) {
      const b = document.createElement('div');
      b.className = 'bar';
      b.style.height = Math.random() * 60 + 20 + 'px';
      b.style.animationDelay = (i * 0.07) + 's';
      gb.appendChild(b);
    }

    // Port scan if selected
    const mode = document.getElementById('scanMode').value;
    const portFeat = document.querySelector('[data-feat="ports"]');
    if (mode === 'scan' || (portFeat && portFeat.classList.contains('active'))) {
      renderPorts();
    }

    // Start real data polling
    updateLiveState();
    monInterval      = setInterval(updateLiveState, 2000);
    alertPollInterval = setInterval(pollAlerts, 3000);
    setInterval(updateRuntime, 1000);

  } else {
    monitoring = false;
    btn.classList.remove('running');
    icon.className = 'fa-solid fa-play';
    label.textContent = 'START PROTECTION';
    document.getElementById('d-session').textContent = 'Session stopped';
    clearInterval(monInterval);
    clearInterval(alertPollInterval);
  }
}

// â”€â”€ Real data from /api/live_state (polled every 2s) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
async function updateLiveState() {
  if (!monitoring) return;
  try {
    const res  = await fetch('/api/live_state');
    const data = await res.json();

    // Packets
    const pkts = data.total_packets || 0;
    document.getElementById('d-packets').textContent = pkts.toLocaleString();

    // Rate
    const rate = data.rate || 0;
    const kbs  = ((rate * 500) / 1024).toFixed(1);  // rough bytes estimate
    document.getElementById('d-pps').innerHTML = `${rate.toFixed(1)} <small>pkt/s</small>`;
    document.getElementById('d-kbs').textContent = `${kbs} KB/s`;

    // Suspicious = total alerts
    const susp = data.suspicious_count || 0;
    document.getElementById('d-susp').textContent  = susp;
    document.getElementById('d-susp2').textContent = susp;

    // Risk level based on real suspicious count
    let risk = 15;
    if (susp > 20)     risk = 90;
    else if (susp > 10) risk = 65;
    else if (susp > 4)  risk = 40;
    else if (susp > 0)  risk = 25;

    document.getElementById('riskIndicator').style.left = `${risk}%`;
    let level = 'Low', color = '#10b981';
    if (risk > 70)      { level = 'Critical'; color = '#ef4444'; }
    else if (risk > 35) { level = 'Warning';  color = '#f59e0b'; }
    const rl = document.getElementById('riskLevel');
    rl.textContent = level; rl.style.color = color;

    // Animate graph bar with real rate
    const bars = document.querySelectorAll('#graphBars .bar');
    if (bars.length) {
      const b = bars[Math.floor(Math.random() * bars.length)];
      const h = Math.min(95, 15 + rate * 2);
      b.style.height = h + 'px';
      b.style.background = risk > 60 ? 'rgba(239,68,68,.5)' : risk > 35 ? 'rgba(255,184,0,.4)' : 'rgba(0,212,255,.4)';
    }

    // Change indicator
    const chEl = document.getElementById('d-change');
    const running = data.running;
    chEl.textContent = running ? 'â— LIVE' : 'â—‹ Idle';
    chEl.style.color = running ? '#10b981' : '#6b7280';

  } catch(e) {
    // Backend not reachable â€” show offline state quietly
    document.getElementById('d-change').textContent = 'Offline';
    document.getElementById('d-change').style.color = '#6b7280';
  }
}

// â”€â”€ Real alerts from /api/alerts (polled every 3s) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
async function pollAlerts() {
  if (!monitoring) return;
  try {
    const alertFeat = document.querySelector('[data-feat="alerts"]');
    if (!alertFeat || !alertFeat.classList.contains('active')) return;

    const res    = await fetch('/api/alerts');
    const alerts = await res.json();
    if (!Array.isArray(alerts)) return;

    // Only show new alerts since last poll
    if (alerts.length <= lastAlertCount) return;
    const newAlerts = alerts.slice(lastAlertCount);
    lastAlertCount  = alerts.length;

    const feed = document.getElementById('alertFeed');
    if (feed.querySelector('.empty-state')) feed.innerHTML = '';

    newAlerts.reverse().forEach(a => {
      const sev = a.severity || 'MEDIUM';
      const msg = a.message  || a.alert_type || 'Threat detected';
      const src = a.source_ip      ? `<span style="color:#f97316">${a.source_ip}</span>` : '';
      const dst = a.destination_ip ? `<span style="color:#00c8ff">${a.destination_ip}</span>` : '';
      const ips = (src && dst) ? ` &nbsp;Â·&nbsp; ${src} â†’ ${dst}` : (src || dst);

      const ts  = new Date(a.timestamp);
      const t   = isNaN(ts) ? '' : ts.toLocaleTimeString('en-GB');

      const div = document.createElement('div');
      div.className = 'alert-line';
      div.innerHTML = `
        <span class="alert-time">${t}</span>
        <span class="alert-badge badge-${sev}">${sev}</span>
        <span class="alert-msg">${msg}${ips}</span>`;
      feed.prepend(div);
      while (feed.children.length > 30) feed.removeChild(feed.lastChild);
    });

  } catch(e) { /* silently skip */ }
}

function updateRuntime() {
  if (!monitoring || !startTime) return;
  const s   = Math.floor((Date.now() - startTime) / 1000);
  const m   = String(Math.floor(s / 60)).padStart(2,'0');
  const sec = String(s % 60).padStart(2,'0');
  document.getElementById('bb-runtime').textContent = `${m}:${sec}`;
}

async function renderPorts() {
  const ip       = document.getElementById('targetIp').value || window._subnetVal || '127.0.0.1';
  const scanType = document.getElementById('scanType').value || 'Standard (top 1000 ports)';
  const grid     = document.getElementById('portsGrid');
  const section  = document.getElementById('portsSection');

  // Show loading state
  section.style.display = 'block';
  grid.innerHTML = `
    <div style="grid-column:1/-1;text-align:center;padding:2rem;
      font-family:var(--fm);font-size:12px;color:var(--text2);">
      <i class="fa-solid fa-spinner fa-spin" style="font-size:1.5rem;
        margin-bottom:.8rem;display:block;color:var(--accent)"></i>
      Scanning ports on ${ip} â€” this may take a moment...
    </div>`;

  try {
    const res  = await fetch('/api/ports', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ target: ip, scan_type: scanType })
    });
    const data = await res.json();

    if (!data.success) {
      grid.innerHTML = `<div style="grid-column:1/-1;text-align:center;
        padding:2rem;font-family:var(--fm);font-size:12px;color:#ef4444;">
        <i class="fa-solid fa-circle-exclamation" style="margin-right:8px"></i>
        ${data.error || 'Scan failed'}</div>`;
      return;
    }

    if (!data.ports || data.ports.length === 0) {
      grid.innerHTML = `<div style="grid-column:1/-1;text-align:center;
        padding:2rem;font-family:var(--fm);font-size:12px;color:var(--text2);">
        <i class="fa-solid fa-shield-check" style="font-size:1.5rem;
          margin-bottom:.8rem;display:block;color:var(--accent3)"></i>
        No open or filtered ports found on ${ip}</div>`;
      return;
    }

    grid.innerHTML = data.ports.map(p => {
      const statusClass = p.status === 'open' ? 'open' :
                          p.status === 'filtered' ? 'filter' : 'closed';
      return `
        <div class="port-card">
          <div class="port-header">
            <span class="port-num">${p.port}</span>
            <span class="port-badge ${statusClass}">${p.status.toUpperCase()}</span>
          </div>
          <div class="port-svc">${p.service}</div>
        </div>`;
    }).join('');

    // Show summary line above grid
    const summary = document.createElement('div');
    summary.style.cssText = 'grid-column:1/-1;font-family:var(--fm);font-size:11px;' +
      'color:var(--text2);margin-bottom:.5rem;';
    summary.innerHTML = `Scanned <span style="color:var(--accent)">${data.total_scanned}</span> ports â€” ` +
      `<span style="color:var(--accent3)">${data.open_count} open</span>`;
    grid.prepend(summary);

  } catch(err) {
    grid.innerHTML = `<div style="grid-column:1/-1;text-align:center;
      padding:2rem;font-family:var(--fm);font-size:12px;color:#ef4444;">
      Connection error: ${err.message}</div>`;
  }
}

// â”€â”€ Theme toggle â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
function toggleTheme(){
  const html = document.documentElement;
  const isLight = html.getAttribute('data-theme') === 'light';
  html.setAttribute('data-theme', isLight ? 'dark' : 'light');
  document.getElementById('theme-btn').innerHTML = isLight ? '<i class="fa-solid fa-moon"></i>' : '<i class="fa-solid fa-sun"></i>';
  localStorage.setItem('pg-theme', isLight ? 'dark' : 'light');
}
// Apply saved theme on load
(function(){
  const saved = localStorage.getItem('pg-theme') || 'dark';
  document.documentElement.setAttribute('data-theme', saved);
  const btn = document.getElementById('theme-btn');
  if(btn) btn.innerHTML = saved === 'light' ? '<i class="fa-solid fa-sun"></i>' : '<i class="fa-solid fa-moon"></i>';
})();

// ── WebSocket: real-time push from Flask-SocketIO ──────────────────────────
(function initWebSocket() {
  // Socket.IO client — served by Flask-SocketIO at /socket.io/socket.io.js
  const script = document.createElement('script');
  script.src = '/socket.io/socket.io.js';
  script.onload = function() {
    const socket = io({ transports: ['websocket', 'polling'] });

    // ── WS status dot ──────────────────────────────────────────────
    const dot = document.createElement('span');
    dot.id = 'ws-dot';
    dot.title = 'WebSocket: connecting...';
    dot.style.cssText = 'display:inline-block;width:8px;height:8px;border-radius:50%;' +
      'background:#6b7280;margin-left:8px;vertical-align:middle;transition:background .3s';
    const hdr = document.querySelector('.nav-brand') || document.querySelector('nav');
    if (hdr) hdr.appendChild(dot);

    socket.on('connect',    () => { dot.style.background='#10b981'; dot.title='WebSocket: live'; });
    socket.on('disconnect', () => { dot.style.background='#ef4444'; dot.title='WebSocket: disconnected'; });

    // ── Live stats push (replaces 2s polling when WS is connected) ─
    socket.on('live_stats', (data) => {
      if (!monitoring) return;
      try {
        const pkts = data.total_packets || 0;
        const el = document.getElementById('d-packets');
        if (el) el.textContent = pkts.toLocaleString();
        const rate = data.rate || 0;
        const ppsEl = document.getElementById('d-pps');
        if (ppsEl) ppsEl.innerHTML = rate.toFixed(1) + ' <small>pkt/s</small>';
        const kbsEl = document.getElementById('d-kbs');
        if (kbsEl) kbsEl.textContent = ((rate * 500) / 1024).toFixed(1) + ' KB/s';
      } catch(e) {}
    });

    // ── New alert push (instant, no need to wait for poll cycle) ───
    // ── Scan complete: instantly refresh devices panel ──────────
    socket.on('scan_complete', (data) => {
      try {
        if (typeof refresh === 'function') refresh();
        const el = document.getElementById('s-devices');
        if (el && data.device_count != null) el.textContent = data.device_count;
        const scanInfo = document.getElementById('scan-info');
        if (scanInfo) scanInfo.textContent = 'Last scan: ' + new Date().toLocaleTimeString('en-GB') + (data.source ? ' [' + data.source + ']' : '');
      } catch(e) {}
    });

    // ── New device found: flash count and refresh device list ─────
    socket.on('new_device', (dev) => {
      try {
        if (typeof refresh === 'function') refresh();
        const el = document.getElementById('s-devices');
        if (el) {
          el.style.color = '#00ff88';
          setTimeout(() => { el.style.color = ''; }, 1500);
        }
        console.log('[LIVE] New device:', dev.ip, dev.device_type);
      } catch(e) {}
    });

    socket.on('new_alert', (alert) => {
      try {
        // Add to the live alert feed if the function exists
        if (typeof addAlertToFeed === 'function') addAlertToFeed(alert);
        // Show toast notification for HIGH/CRITICAL
        const sev = (alert.severity || '').toUpperCase();
        if ((sev === 'HIGH' || sev === 'CRITICAL') && typeof showNotification === 'function') {
          showNotification(alert.alert_type || 'Alert', alert.message || '', sev);
        }
        // Bump suspicious counter
        const el = document.getElementById('d-susp');
        if (el) el.textContent = (parseInt(el.textContent) || 0) + 1;
        const el2 = document.getElementById('d-susp2');
        if (el2) el2.textContent = (parseInt(el2.textContent) || 0) + 1;
      } catch(e) {}
    });
  };
  document.head.appendChild(script);
})();

</script>
</body>
</html>
'''

@app.route("/monitor")
def monitor():
    return Response(MONITOR_HTML, mimetype="text/html")

@app.route("/dashboard")
def dashboard():
    return Response(HTML, mimetype="text/html")

@app.route("/enterprise")
def enterprise():
    # Enterprise features are now integrated into the main dashboard.
    from flask import redirect
    return redirect("/dashboard", code=301)


# ── Admin: User Management API ────────────────────────────────────

@app.route("/api/admin/users", methods=["GET"])
@require_role("admin")
def admin_list_users():
    """List all users (admin only)."""
    try:
        from access_control import get_all_users
        users = get_all_users(_db)
        return jsonify({"success": True, "users": users})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/admin/users/<int:user_id>/role", methods=["POST"])
@require_role("admin")
def admin_set_role(user_id):
    """Change a user's role (admin only). Cannot demote yourself."""
    if user_id == _sess.get("user_id"):
        return jsonify({"success": False, "error": "Cannot change your own role."}), 400
    data = _req.get_json() or {}
    new_role = data.get("role", "").strip()
    from access_control import set_user_role, ROLE_LEVEL
    if new_role not in ROLE_LEVEL:
        return jsonify({"success": False, "error": f"Invalid role. Choose: {list(ROLE_LEVEL.keys())}"}), 400
    ok = set_user_role(_db, user_id, new_role)
    if ok:
        print(f"[RBAC] User {user_id} role → {new_role} by admin {_sess.get('user_email')}")
        return jsonify({"success": True, "message": f"Role updated to {new_role}."})
    return jsonify({"success": False, "error": "User not found."}), 404


@app.route("/api/admin/users/<int:user_id>", methods=["DELETE"])
@require_role("admin")
def admin_delete_user(user_id):
    """Delete a user account (admin only). Cannot delete yourself."""
    from access_control import delete_user
    ok, msg = delete_user(_db, user_id, _sess.get("user_id"))
    if ok:
        print(f"[RBAC] User {user_id} deleted by admin {_sess.get('user_email')}")
        return jsonify({"success": True, "message": msg})
    return jsonify({"success": False, "error": msg}), 400


@app.route("/api/admin/users/create", methods=["POST"])
@require_role("admin")
def admin_create_user():
    """Create a new user with a specific role (admin only)."""
    data  = _req.get_json() or {}
    name  = data.get("name", "").strip()
    email = data.get("email", "").strip().lower()
    pw    = data.get("password", "")
    role  = data.get("role", "analyst").strip()
    from access_control import ROLE_LEVEL
    if not name or not email or not pw:
        return jsonify({"success": False, "error": "name, email, and password are required."}), 400
    if len(pw) < 6:
        return jsonify({"success": False, "error": "Password must be at least 6 characters."}), 400
    if role not in ROLE_LEVEL:
        return jsonify({"success": False, "error": f"Invalid role. Choose: {list(ROLE_LEVEL.keys())}"}), 400
    conn = _db()
    try:
        conn.execute(
            "INSERT INTO users (name,email,password,role,created_at) VALUES (?,?,?,?,?)",
            (name, email, _hash(pw), role, datetime.utcnow().isoformat())
        )
        conn.commit()
        print(f"[RBAC] User created: {email} ({role}) by admin {_sess.get('user_email')}")
        return jsonify({"success": True, "message": f"User {email} created with role {role}."})
    except sqlite3.IntegrityError:
        return jsonify({"success": False, "error": "Email already registered."}), 409
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        conn.close()


@app.route("/api/admin/users/<int:user_id>/reset-password", methods=["POST"])
@require_role("admin")
def admin_reset_password(user_id):
    """Reset any user's password (admin only)."""
    data   = _req.get_json() or {}
    new_pw = data.get("new_password", "").strip()
    if len(new_pw) < 6:
        return jsonify({"success": False, "error": "Password must be at least 6 characters."}), 400
    conn = _db()
    try:
        row = conn.execute("SELECT id FROM users WHERE id=?", (user_id,)).fetchone()
        if not row:
            return jsonify({"success": False, "error": "User not found."}), 404
        conn.execute("UPDATE users SET password=? WHERE id=?", (_hash(new_pw), user_id))
        conn.commit()
        print(f"[RBAC] Password reset for user {user_id} by admin {_sess.get('user_email')}")
        return jsonify({"success": True, "message": "Password reset successfully."})
    finally:
        conn.close()
=======
@app.route("/")
def home():
    return Response(read_template("index.html"), mimetype="text/html")

@app.route("/monitor")
def monitor():
    return Response(read_template("monitor.html"), mimetype="text/html")

@app.route("/dashboard")
def dashboard():
    return Response(read_template("dashboard.html"), mimetype="text/html")
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b


if __name__ == "__main__":
    print("""
+-----------------------------------------------------------+
|         PacketGuard - Network Threat Dashboard           |
|        Access from: http://localhost:5000                 |
|   Auto-scanning network every 60 seconds...              |
+-----------------------------------------------------------+
    """)
<<<<<<< HEAD

    # "ML Anomaly Detection" 
    try:
        from ml_detector import get_detector
        _det = get_detector()
        if _det.ready:
            print(f"[ML] Detector ready — models: {_det.status()['models_loaded']}")
        else:
            print("[ML] WARNING: No trained models found. Run train_cicids.py first.")
    except Exception as _e:
        print(f"[ML] Could not load detector: {_e}")



    socketio.run(app, host="0.0.0.0", port=5000, debug=False)
=======
    app.run(host="0.0.0.0", port=5000, debug=False)
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
