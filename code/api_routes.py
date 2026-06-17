"""
api_routes.py — PacketGuard
All /api/* endpoints (except /api/auth/*) extracted from web_dashboard.py.
"""

import csv
import io
import json
import os
import sqlite3
import threading
import time
from datetime import datetime, timezone

from flask import Blueprint, Response, jsonify, request

from config import (
    BASE_DIR, ALERTS_FILE, ML_ALERTS_FILE, BLOCKLIST_FILE, WHITELIST_FILE,
    SCAN_HISTORY_FILE, socketio,
)
# Optional config keys - safe fallback if not defined in config.py
try:
    from config import EMAIL_CONFIG_FILE
except ImportError:
    EMAIL_CONFIG_FILE = os.path.join(BASE_DIR, "email_config.json")
try:
    from config import RESEND_API_KEY
except ImportError:
    RESEND_API_KEY = ""
try:
    from config import RESEND_FROM_EMAIL
except ImportError:
    RESEND_FROM_EMAIL = ""

from data_service import (
    load_alerts, load_ml_alerts, load_alerts_by_date, load_devices, load_live_stats,
    load_model_info, total_alert_count,
)

api_bp = Blueprint("api", __name__)

_MIME_JSON      = "application/json"
_MIME_CSV       = "text/csv"
_ERR_DATE_FMT   = "Invalid date format — use YYYY-MM-DD"
_LOCAL_IP_PROBE = "8.8.8.8"   # NOSONAR - not an endpoint, used only to probe local routing interface
_PWD_FIELD      = "password"
_ERR_IP_REQUIRED = "IP required"
_TAC_C2          = "Command & Control"
_TAC_INITIAL     = "Initial Access"

# ── RBAC helpers ──────────────────────────────────────────────────
from functools import wraps
from auth import validate_session, SESSION_COOKIE, validate_password_strength

ROLE_LEVEL = {"admin": 3, "analyst": 2, "viewer": 1}

def _get_current_user():
    """Resolve user from cookie-based session (auth.py)."""
    from flask import request as _req
    token = _req.cookies.get(SESSION_COOKIE)
    return validate_session(token) if token else None

def require_login(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        user = _get_current_user()
        if not user:
            return jsonify({"success": False, "error": "Authentication required"}), 401
        return f(*args, **kwargs)
    return wrapped

def require_role(min_role: str):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            user = _get_current_user()
            if not user:
                return jsonify({"success": False, "error": "Authentication required"}), 401
            role = user.get("role", "viewer")
            if ROLE_LEVEL.get(role, 0) < ROLE_LEVEL.get(min_role, 99):
                return jsonify({"success": False, "error": "Insufficient permissions"}), 403
            return f(*args, **kwargs)
        return wrapped
    return decorator


# ── DB helper ─────────────────────────────────────────────────────
def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(os.path.join(BASE_DIR, "packetguard.db"), timeout=5)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def _log_access(event, detail="", user_id=None, user_name=None,
                user_email=None, user_role=None):
    try:
        conn = _db()
        ts = datetime.now(timezone.utc).isoformat()
        ip_addr = request.remote_addr or ""
        ua = request.headers.get("User-Agent", "")[:200]
        conn.execute(
            "INSERT INTO access_log "
            "(user_id,user_name,user_email,user_role,event_type,detail,source_ip,user_agent,timestamp)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            (user_id, user_name, user_email, user_role, event,
             detail[:500], ip_addr, ua, ts)
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


# ── Blocklist / Whitelist helpers ─────────────────────────────────
def load_blocklist():
    try:
        with open(BLOCKLIST_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []

def load_whitelist():
    """Return whitelist as a list of dicts {ip, reason, timestamp}.
    Normalises plain-string entries (old format) to dict format on load."""
    try:
        with open(WHITELIST_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, list):
            return []
        result = []
        for e in data:
            if isinstance(e, str):
                result.append({"ip": e, "reason": "Trusted device", "timestamp": ""})
            elif isinstance(e, dict) and "ip" in e:
                result.append(e)
        return result
    except Exception:
        return []

def save_list(path, data):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
    except Exception as e:
        print(f"[LIST] Save error: {e}")


# ── Scan history helpers ───────────────────────────────────────────
def load_scan_history():
    try:
        with open(SCAN_HISTORY_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []

def save_scan_history(entry):
    history = load_scan_history()
    history.append(entry)
    history = history[-200:]
    try:
        with open(SCAN_HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(history, f, indent=2, default=str)
    except Exception as e:
        print(f"[HISTORY] Could not save: {e}")


# ── Scan state (module-level, shared with socket_handlers) ────────
_scan_status = {
    "running": False,
    "last_scan": None,
    "next_scan": None,
    "device_count": 0,
}
_network_scanner_mod = None
_IFACE_OVERRIDE_FILE = os.path.join(BASE_DIR, "capture_iface.txt")


def _get_network_scanner():
    global _network_scanner_mod
    if _network_scanner_mod is not None:
        return _network_scanner_mod
    try:
        scanner_path = os.path.join(BASE_DIR, "network_scanner.py")
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


def run_network_scan_with_history():
    global _scan_status
    try:
        mod = _get_network_scanner()
        if mod is None:
            return
        devices = mod.scan_network()
        count   = len(devices) if devices else 0
        _scan_status["last_scan"]    = datetime.now().isoformat()
        _scan_status["device_count"] = count
        save_scan_history({
            "timestamp":    datetime.now().isoformat(),
            "device_count": count,
            "devices":      [d.get("ip", "?") for d in (devices or [])],
            "trigger":      "auto",
        })
        print(f"[AUTO-SCAN] Done — {count} device(s) found")
        try:
            socketio.emit("scan_complete", {
                "device_count": count,
                "last_scan": _scan_status["last_scan"]
            })
        except Exception:
            pass
    except Exception as e:
        print(f"[AUTO-SCAN] Error: {e}")
    finally:
        _scan_status["running"]    = False
        _scan_status["next_scan"]  = datetime.fromtimestamp(
            time.time() + 20).isoformat()


def auto_scan_loop():
    while True:
        time.sleep(20)
        run_network_scan_with_history()


# ── Email helpers ─────────────────────────────────────────────────
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
    min_sev   = sev_order.get(cfg.get("min_severity", "HIGH"), 2)
    alert_sev = sev_order.get(alert.get("severity", "LOW"), 0)
    if alert_sev < min_sev:
        return
    try:
        import smtplib
        import html as _html_mod
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        msg = MIMEMultipart("alternative")
        msg["Subject"] = (f"[PacketGuard] {alert.get('severity','?')} ALERT"
                          f" — {alert.get('alert_type','Unknown')}")
        msg["From"] = cfg["sender"]
        msg["To"]   = cfg["recipient"]
        _sev = alert.get("severity")
        if _sev == "CRITICAL":
            sev_color = "#ff2d55"
        elif _sev == "HIGH":
            sev_color = "#ff6400"
        else:
            sev_color = "#ffb800"
        _e = _html_mod.escape
        html = f"""
        <div style="font-family:monospace;background:#03050a;color:#c0d4ee;padding:24px;border-radius:8px;max-width:600px">
          <h2 style="color:#00c8ff;margin-bottom:16px">&#9888; PacketGuard Alert</h2>
          <table style="width:100%;border-collapse:collapse">
            <tr><td style="color:#3a5570;padding:6px 0;width:140px">Severity</td>
                <td style="color:{sev_color};font-weight:bold">{_e(str(alert.get('severity','?')))}</td></tr>
            <tr><td style="color:#3a5570;padding:6px 0">Type</td><td>{_e(str(alert.get('alert_type','?')))}</td></tr>
            <tr><td style="color:#3a5570;padding:6px 0">Source IP</td><td style="color:#00c8ff">{_e(str(alert.get('source_ip','?')))}</td></tr>
            <tr><td style="color:#3a5570;padding:6px 0">Message</td><td>{_e(str(alert.get('message','?')))}</td></tr>
            <tr><td style="color:#3a5570;padding:6px 0">Time</td><td>{_e(str(alert.get('timestamp','?')))}</td></tr>
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


# ── MITRE map + enrich helper ─────────────────────────────────────
MITRE_MAP = {
    "PORT_SCAN":      {"tactic": "TA0043", "tactic_name": "Reconnaissance",    "technique": "T1046", "tech_name": "Network Service Discovery"},
    "SYN_FLOOD":      {"tactic": "TA0040", "tactic_name": "Impact",            "technique": "T1498", "tech_name": "Network DoS"},
    "DNS_ANOMALY":    {"tactic": "TA0011", "tactic_name": _TAC_C2,             "technique": "T1071", "tech_name": "DNS Protocol Abuse"},
    "DNS_TUNNELING":  {"tactic": "TA0011", "tactic_name": _TAC_C2,             "technique": "T1572", "tech_name": "Protocol Tunneling"},
    "BRUTE_FORCE":    {"tactic": "TA0006", "tactic_name": "Credential Access", "technique": "T1110", "tech_name": "Brute Force"},
    "HIGH_RATE":      {"tactic": "TA0040", "tactic_name": "Impact",            "technique": "T1498", "tech_name": "Network Flood"},
    "PLAIN_HTTP":     {"tactic": "TA0009", "tactic_name": "Collection",        "technique": "T1040", "tech_name": "Network Sniffing"},
    "FRAGMENT_STORM": {"tactic": "TA0040", "tactic_name": "Impact",            "technique": "T1499", "tech_name": "Resource Exhaustion"},
    "ICMP_FLOOD":     {"tactic": "TA0040", "tactic_name": "Impact",            "technique": "T1498", "tech_name": "ICMP Flood"},
    "ANOMALY":        {"tactic": "TA0001", "tactic_name": _TAC_INITIAL,         "technique": "T1190", "tech_name": "Exploit Public-Facing"},
    "ML_ANOMALY":     {"tactic": "TA0002", "tactic_name": "Execution",         "technique": "T1059", "tech_name": "Command & Scripting Interpreter"},
}

def _enrich_alert(a: dict) -> dict:
    atype = (a.get("alert_type") or a.get("type") or "").upper()
    mitre = MITRE_MAP.get(atype, MITRE_MAP["ANOMALY"])
    a.setdefault("mitre_tactic",    mitre["tactic"])
    a.setdefault("mitre_tactic_nm", mitre["tactic_name"])
    a.setdefault("mitre_tech",      mitre["technique"])
    a.setdefault("mitre_tech_nm",   mitre["tech_name"])
    a.setdefault("status",          "NEW")
    a.setdefault("assigned_to",     None)
    return a


# ── Core data endpoints ───────────────────────────────────────────

@api_bp.route("/api/alerts", methods=["GET"])
def api_alerts():
    return jsonify(load_alerts())


@api_bp.route("/api/alerts/daily", methods=["GET"])
def api_alerts_daily():
    """Return all alerts for a given date. ?date=YYYY-MM-DD (defaults to today)."""
    date_str = request.args.get("date", datetime.now().strftime("%Y-%m-%d"))
    try:
        datetime.strptime(date_str, "%Y-%m-%d")
    except ValueError:
        return jsonify({"error": _ERR_DATE_FMT}), 400
    alerts = load_alerts_by_date(date_str)
    return jsonify({"date": date_str, "count": len(alerts), "alerts": alerts})


@api_bp.route("/api/ml_alerts", methods=["GET"])
def api_ml_alerts():
    try:
        alerts = load_ml_alerts()
        return Response(json.dumps(alerts, ensure_ascii=False, default=str),
                        mimetype=_MIME_JSON)
    except Exception:
        return Response(json.dumps([]), mimetype=_MIME_JSON)


@api_bp.route("/api/ml_status", methods=["GET"])
def api_ml_status():
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


@api_bp.route("/api/devices", methods=["GET"])
def api_devices():
    return jsonify(load_devices())


@api_bp.route("/api/scan_status", methods=["GET"])
def api_scan_status():
    from config import SCAN_INTERVAL
    return jsonify({**_scan_status, "scan_interval": SCAN_INTERVAL})


@api_bp.route("/api/network_info", methods=["GET"])
def api_network_info():
    import socket, subprocess, re
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((_LOCAL_IP_PROBE, 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        local_ip = "127.0.0.1"
    parts         = local_ip.split(".")
    network_range = ".".join(parts[:3]) + ".0/24"
    gateway_ip    = None
    try:
        import platform
        if platform.system() == "Windows":
            out = subprocess.check_output(["ipconfig"], shell=False).decode(errors="ignore")
            m   = re.search(r"Default Gateway[^\d]*(\d+\.\d+\.\d+\.\d+)", out)
            if m:
                gateway_ip = m.group(1)
        else:
            out = subprocess.check_output(["ip", "route"], shell=False).decode(errors="ignore")
            m   = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", out)
            if m:
                gateway_ip = m.group(1)
    except Exception:
        pass
    # Always return freshly detected values — DB cache may be stale (old network)
    return jsonify({
        "local_ip":      local_ip,
        "network_range": network_range,
        "gateway_ip":    gateway_ip,
    })


@api_bp.route("/api/live_state", methods=["GET"])
def api_live_state():
    return jsonify(load_live_stats())


@api_bp.route("/api/interfaces", methods=["GET"])
def api_interfaces():
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
                    "name":  name,
                    "ip":    addr.address,
                    "is_up": stats[name].isup  if name in stats else False,
                    "speed": stats[name].speed if name in stats else 0,
                })
        try:
            import live_monitor as _lm
            active = _lm.get_interface()
        except Exception:
            active = None
        return jsonify({"interfaces": ifaces, "active": active})
    except Exception as e:
        return jsonify({"interfaces": [], "active": None, "error": str(e)})


@api_bp.route("/api/set_capture_iface", methods=["POST"])
def api_set_capture_iface():
    if (_get_current_user() or {}).get("role") != "admin":
        return jsonify({"success": False, "error": "Admin access required"}), 403
    data  = request.get_json() or {}
    iface = data.get("interface", "").strip()
    if not iface:
        return jsonify({"success": False, "error": "No interface specified"}), 400
    try:
        with open(_IFACE_OVERRIDE_FILE, "w", encoding="utf-8") as f:
            f.write(iface)
        return jsonify({"success": True, "interface": iface,
                        "message": "Saved. Restart the server for the new interface to take effect."})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@api_bp.route("/api/get_capture_iface", methods=["GET"])
def api_get_capture_iface():
    try:
        import live_monitor as _lm
        active = _lm.get_interface()
    except Exception:
        active = None
    saved = None
    try:
        if os.path.exists(_IFACE_OVERRIDE_FILE):
            with open(_IFACE_OVERRIDE_FILE, "r", encoding="utf-8") as f:
                saved = f.read().strip() or None
    except Exception:
        pass
    return jsonify({"active": active, "saved_override": saved})


@api_bp.route("/api/stats", methods=["GET"])
def api_stats():
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
    # total_alerts counts only heuristic alerts (is_ml=0) — consistent with
    # severity_count and alerts_by_type which are also computed from heuristic only.
    heuristic_count = len(alerts)
    ml_count        = len(ml_alerts)
    return jsonify({
        "total_alerts":    heuristic_count,
        "total_ml_alerts": ml_count,
        "total_all_alerts": heuristic_count + ml_count,
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


# ── Scan / History ─────────────────────────────────────────────────

@api_bp.route("/api/ports", methods=["POST"])
@require_role("analyst")
def api_ports():
    data      = request.get_json() or {}
    target    = data.get("target", "").strip()
    scan_type = data.get("scan_type", "Standard (top 1000 ports)")
    if not target:
        return jsonify({"success": False, "error": "No target IP provided"}), 400
    import socket as _sock
    try:
        _sock.inet_aton(target.split("/")[0])
    except Exception:
        return jsonify({"success": False, "error": "Invalid IP address"}), 400
    try:
        t0           = time.time()
        scanner_path = os.path.join(BASE_DIR, "network_scanner.py")
        import importlib.util
        spec = importlib.util.spec_from_file_location("network_scanner", scanner_path)
        mod  = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        ports          = mod.scan_ports(target, scan_type)
        duration_s     = round(time.time() - t0, 1)
        open_count     = sum(1 for p in ports if p["status"] == "open")
        filtered_count = sum(1 for p in ports if p["status"] == "filtered")
        closed_count   = len(ports) - open_count - filtered_count
        # Return all open + filtered; frontend handles display/filtering
        visible = [p for p in ports if p["status"] in ("open", "filtered")]
        return jsonify({
            "success":        True,
            "target":         target,
            "scan_type":      scan_type,
            "ports":          visible,
            "open_count":     open_count,
            "filtered_count": filtered_count,
            "closed_count":   closed_count,
            "total_scanned":  len(ports),
            "duration_s":     duration_s,
            "scanned_at":     datetime.now(timezone.utc).isoformat(),
        })
    except Exception as e:
        print(f"[API/PORTS] Error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


@api_bp.route("/api/scan_history", methods=["GET"])
def api_scan_history():
    return jsonify(load_scan_history())


@api_bp.route("/api/session_history", methods=["GET"])
def api_session_history():
    # Try session_history.json first, fall back to scan_history.json
    HISTORY_FILE = os.path.join(BASE_DIR, "session_history.json")
    try:
        history = []
        if os.path.exists(HISTORY_FILE):
            with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                history = json.load(f)
        live         = load_live_stats()
        today_str    = datetime.now().strftime("%Y-%m-%d")
        today_alerts = load_alerts_by_date(today_str)
        _sev   = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        _types = {}
        for _a in today_alerts:
            _s = _a.get("severity", "").upper()
            if _s in _sev:
                _sev[_s] += 1
            _t = _a.get("alert_type", _a.get("type", "UNKNOWN"))
            _types[_t] = _types.get(_t, 0) + 1
        today_row = {
            "date":            today_str + " (today)",
            "timestamp":       datetime.now().isoformat(),
            "total_packets":   live.get("total_packets", 0),
            "bytes_total":     live.get("bytes_total", 0),
            "runtime_seconds": live.get("runtime_seconds", 0),
            "protocols":       live.get("protocols", {}),
            "top_ips":         live.get("top_ips", {}),
            "ml_total":        live.get("ml_total", 0),
            "alert_count":     len(today_alerts),
            "critical_count":  _sev["CRITICAL"],
            "high_count":      _sev["HIGH"],
            "medium_count":    _sev["MEDIUM"],
            "low_count":       _sev["LOW"],
            "alert_types":     _types,
            "is_today":        True,
        }
        return jsonify({"history": [today_row] + list(reversed(history))})
    except Exception as e:
        return jsonify({"history": [], "error": str(e)})


@api_bp.route("/api/scan_now", methods=["POST"])
@require_role("analyst")
def api_scan_now():
    def _run():
        global _scan_status
        _scan_status["running"] = True
        try:
            mod = _get_network_scanner()
            if mod is None:
                return
            devices = mod.scan_network()
            count   = len(devices) if devices else 0
            _scan_status["last_scan"]    = datetime.now().isoformat()
            _scan_status["device_count"] = count
            save_scan_history({
                "timestamp":    datetime.now().isoformat(),
                "device_count": count,
                "devices":      [d.get("ip", "?") for d in (devices or [])],
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
            _scan_status["running"]   = False
            _scan_status["next_scan"] = datetime.fromtimestamp(
                time.time() + 20).isoformat()
    threading.Thread(target=_run, daemon=True).start()
    return jsonify({"status": "scan_started"})


# ── Blocklist ──────────────────────────────────────────────────────

@api_bp.route("/api/blocklist", methods=["GET"])
@require_login
def api_get_blocklist():
    return jsonify({"blocked": load_blocklist(), "whitelisted": load_whitelist()})


@api_bp.route("/api/blocklist/block", methods=["POST"])
@require_role("analyst")
def api_block_ip():
    data     = request.get_json() or {}
    ip       = data.get("ip", "").strip()
    reason   = data.get("reason", "Manual block")
    operator = data.get("operator", "admin")
    if not ip:
        return jsonify({"success": False, "error": _ERR_IP_REQUIRED})

    # 1 — Windows Firewall rule via block_manager (manual bypass trust scoring)
    fw_result = None
    try:
        from block_manager import manual_block
        fw_result = manual_block(ip=ip, reason=reason, operator=operator)
    except Exception:
        pass  # firewall unavailable — still write to packet-filter list below

    # 2 — Keep blocklist.json in sync so live_monitor packet filter picks it up
    blocked = load_blocklist()
    if not any(e["ip"] == ip for e in blocked):
        blocked.append({"ip": ip, "reason": reason,
                        "timestamp": datetime.now().isoformat(),
                        "fw_enforced": bool(fw_result and fw_result.get("real_block"))})
        save_list(BLOCKLIST_FILE, blocked)
    elif fw_result is None:
        return jsonify({"success": False, "error": "Already blocked"})

    return jsonify({
        "success":     True,
        "fw_enforced": bool(fw_result and fw_result.get("real_block")),
        "fw_status":   fw_result.get("fw_message", "n/a") if fw_result else "block_manager unavailable",
    })


@api_bp.route("/api/blocklist/unblock", methods=["POST"])
@require_role("analyst")
def api_unblock_ip():
    data     = request.get_json() or {}
    ip       = data.get("ip", "").strip()
    operator = data.get("operator", "admin")

    # 1 — Remove Windows Firewall rule
    try:
        from firewall_enforcer import unblock_ip as _fw_unblock
        _fw_unblock(ip=ip, operator=operator)
    except Exception:
        pass

    # 2 — Remove from packet-filter list
    blocked = [e for e in load_blocklist() if e["ip"] != ip]
    save_list(BLOCKLIST_FILE, blocked)
    return jsonify({"success": True})


@api_bp.route("/api/blocklist/whitelist", methods=["POST"])
@require_role("analyst")
def api_whitelist_ip():
    data   = request.get_json() or {}
    ip     = data.get("ip", "").strip()
    reason = data.get("reason", "Trusted device")
    if not ip:
        return jsonify({"success": False, "error": _ERR_IP_REQUIRED})
    wl = load_whitelist()
    if any(e["ip"] == ip for e in wl):
        return jsonify({"success": False, "error": "Already whitelisted"})
    wl.append({"ip": ip, "reason": reason,
               "timestamp": datetime.now().isoformat()})
    save_list(WHITELIST_FILE, wl)
    return jsonify({"success": True})


@api_bp.route("/api/blocklist/unwhitelist", methods=["POST"])
@require_role("analyst")
def api_unwhitelist_ip():
    data = request.get_json() or {}
    ip   = data.get("ip", "").strip()
    wl   = [e for e in load_whitelist() if e["ip"] != ip]
    save_list(WHITELIST_FILE, wl)
    return jsonify({"success": True})


# ── Access Audit Log ───────────────────────────────────────────────

@api_bp.route("/api/admin/access_log", methods=["GET"])
def api_access_log():
    if (_get_current_user() or {}).get("role") != "admin":
        return jsonify({"success": False, "error": "Admin only"}), 403
    try:
        limit = min(int(request.args.get("limit", 200)), 500)
    except (ValueError, TypeError):
        limit = 200
    conn  = _db()
    try:
        rows = conn.execute(
            "SELECT * FROM access_log ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return jsonify({"success": True, "logs": [dict(r) for r in rows]})
    finally:
        conn.close()


# ── Unblock Requests ───────────────────────────────────────────────

@api_bp.route("/api/unblock_requests", methods=["GET"])
def api_list_unblock_requests():
    user = _get_current_user()
    if not user:
        return jsonify({"success": False, "error": "Not logged in"}), 401
    conn = _db()
    try:
        if user.get("role") == "admin":
            rows = conn.execute(
                "SELECT * FROM unblock_requests ORDER BY id DESC LIMIT 100"
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM unblock_requests WHERE submitted_by=? "
                "ORDER BY id DESC LIMIT 50",
                (user.get("id", 0),)
            ).fetchall()
        return jsonify({"success": True, "requests": [dict(r) for r in rows]})
    finally:
        conn.close()


@api_bp.route("/api/unblock_requests/submit", methods=["POST"])
def api_submit_unblock_request():
    user = _get_current_user()
    if not user:
        return jsonify({"success": False, "error": "Not logged in"}), 401
    if user.get("role") == "admin":
        return jsonify({"success": False, "error": "Admins can unblock directly."}), 400
    data          = request.get_json() or {}
    req_ip        = data.get("ip", "").strip()
    reason        = data.get("reason", "").strip()
    justification = data.get("justification", "").strip()
    alert_ref     = data.get("alert_ref", "").strip()
    if not req_ip:
        return jsonify({"success": False, "error": "IP address required"}), 400
    if not reason:
        return jsonify({"success": False, "error": "Reason required"}), 400
    uid   = user.get("id", 0)
    uname = user.get("name")
    uemail = user.get("email")
    urole  = user.get("role", "viewer")
    conn  = _db()
    try:
        existing = conn.execute(
            "SELECT id FROM unblock_requests WHERE req_ip=? "
            "AND submitted_by=? AND status=?",
            (req_ip, uid, "pending")
        ).fetchone()
        if existing:
            return jsonify({"success": False,
                            "error": "A pending request for this IP already exists."}), 400
        conn.execute(
            "INSERT INTO unblock_requests "
            "(req_ip,reason,justification,alert_ref,submitted_by,"
            "submitter_name,submitter_email,status,submitted_at) "
            "VALUES (?,?,?,?,?,?,?,'pending',?)",
            (req_ip, reason, justification, alert_ref, uid, uname, uemail,
             datetime.now(timezone.utc).isoformat())
        )
        conn.commit()
    finally:
        conn.close()
    _log_access("UNBLOCK_REQUEST_SUBMITTED",
                f"Analyst requested unblock for {req_ip} — {reason}",
                user_id=uid, user_name=uname, user_email=uemail, user_role=urole)
    try:
        socketio.emit("unblock_request_new", {
            "ip": req_ip, "submitter": uname, "reason": reason
        })
    except Exception:
        pass
    return jsonify({"success": True, "message": "Request submitted successfully."})


@api_bp.route("/api/unblock_requests/review", methods=["POST"])
def api_review_unblock_request():
    admin = _get_current_user()
    if not admin or admin.get("role") != "admin":
        return jsonify({"success": False, "error": "Admin only"}), 403
    data       = request.get_json() or {}
    req_id     = data.get("id")
    action     = data.get("action", "").lower()
    admin_note = data.get("note", "").strip()
    if not req_id or action not in ("approve", "reject"):
        return jsonify({"success": False, "error": "id and action required"}), 400
    conn    = _db()
    try:
        req_row = conn.execute(
            "SELECT * FROM unblock_requests WHERE id=?", (req_id,)
        ).fetchone()
        if not req_row:
            return jsonify({"success": False, "error": "Request not found"}), 404
        if req_row["status"] != "pending":
            return jsonify({"success": False, "error": "Request already reviewed"}), 400
        new_status = "approved" if action == "approve" else "rejected"
        conn.execute(
            "UPDATE unblock_requests SET status=?, reviewed_by=?, "
            "reviewer_name=?, admin_note=?, reviewed_at=? WHERE id=?",
            (new_status, admin.get("id", 0), admin.get("name"),
             admin_note, datetime.now(timezone.utc).isoformat(), req_id)
        )
        conn.commit()
    finally:
        conn.close()
    if action == "approve":
        ip      = req_row["req_ip"]
        blocked = [e for e in load_blocklist() if e["ip"] != ip]
        save_list(BLOCKLIST_FILE, blocked)
        _log_access("UNBLOCK_APPROVED",
                    f"Admin approved unblock of {ip} (req #{req_id}) — {admin_note}",
                    user_id=admin.get("id"), user_name=admin.get("name"),
                    user_email=admin.get("email"), user_role="admin")
    else:
        _log_access("UNBLOCK_REJECTED",
                    f"Admin rejected unblock of {req_row['req_ip']} "
                    f"(req #{req_id}) — {admin_note}",
                    user_id=admin.get("id"), user_name=admin.get("name"),
                    user_email=admin.get("email"), user_role="admin")
    try:
        socketio.emit("unblock_request_reviewed", {
            "id": req_id, "ip": req_row["req_ip"],
            "status": new_status, "reviewer": admin.get("name"),
            "note": admin_note
        })
    except Exception:
        pass
    return jsonify({"success": True, "status": new_status})


# ── Email config ───────────────────────────────────────────────────

@api_bp.route("/api/email_config", methods=["GET"])
@require_role("analyst")
def api_get_email_config():
    cfg  = load_email_config()
    safe = dict(cfg)
    if safe.get(_PWD_FIELD):
        safe[_PWD_FIELD] = "••••••••"
    return jsonify(safe)


@api_bp.route("/api/email_config", methods=["POST"])
@require_role("analyst")
def api_save_email_config():
    data = request.get_json() or {}
    cfg  = load_email_config()
    for k in ["enabled", "smtp_host", "smtp_port", "sender", "recipient", "min_severity"]:
        if k in data:
            cfg[k] = data[k]
    if data.get("password") and data["password"] != "••••••••":
        cfg["password"] = data["password"]
    save_email_config(cfg)
    return jsonify({"success": True})


@api_bp.route("/api/email_test", methods=["POST"])
@require_role("analyst")
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


@api_bp.route("/api/smtp-status", methods=["GET"])
@require_login
def api_smtp_status():
    from config import SMTP_EMAIL as _smtp_email, SMTP_PASSWORD as _smtp_pw
    configured = bool(_smtp_pw and _smtp_email)
    return jsonify({"configured": configured,
                    "sender": _smtp_email if configured else None})


@api_bp.route("/api/smtp-test", methods=["POST"])
@require_role("analyst")
def api_smtp_test():
    data = request.get_json() or {}
    to   = data.get("to", "").strip()
    if not to or "@" not in to:
        return jsonify({"success": False, "error": "Invalid recipient email."}), 400
    try:
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        from smtp_service import SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS

        msg = MIMEMultipart("alternative")
        msg["Subject"] = "PacketGuard — SMTP Test"
        msg["From"]    = f"PacketGuard <{SMTP_USER}>"
        msg["To"]      = to
        msg.attach(MIMEText(
            "<h2 style='color:#00c8ff;font-family:monospace'>PacketGuard SMTP Test</h2>"
            "<p>Your email alerts are configured correctly.</p>"
            "<p style='color:#888;font-size:12px'>PacketGuard Security Platform</p>",
            "html"
        ))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
            s.ehlo()
            s.starttls()
            s.login(SMTP_USER, SMTP_PASS)
            s.sendmail(SMTP_USER, to, msg.as_string())

        return jsonify({"success": True})
    except smtplib.SMTPAuthenticationError:
        return jsonify({"success": False, "error": "SMTP authentication failed. Check email/password."})
    except smtplib.SMTPException as e:
        return jsonify({"success": False, "error": f"SMTP error: {str(e)}"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


# ── Geo-IP ────────────────────────────────────────────────────────

_SEV_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

# Delegate all resolution to the standalone geo_resolver module
from geo_resolver import resolve_geo as _resolve_geo, is_private as _is_private_ip


@api_bp.route("/api/geo_alerts", methods=["GET"])
def api_geo_alerts():
    alerts      = load_alerts()
    ip_counts   = {}
    ip_severity = {}
    for a in alerts:
        ip = a.get("source_ip", "")
        if not ip or ip in ("N/A", "Multiple", ""):
            continue
        ip_counts[ip] = ip_counts.get(ip, 0) + 1
        sev = a.get("severity", "LOW")
        if _SEV_RANK.get(sev, 0) > _SEV_RANK.get(ip_severity.get(ip, "LOW"), 0):
            ip_severity[ip] = sev

    if not ip_counts:
        return jsonify([])

    top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:20]

    # Resolve geo for all IPs in parallel so the endpoint never blocks on HTTP lookups
    from concurrent.futures import ThreadPoolExecutor, as_completed
    _FALLBACK_GEO = {"country": "Unknown", "countryCode": "", "city": "",
                     "lat": 0, "lon": 0, "isp": "", "source": "timeout"}
    geo_map = {}
    with ThreadPoolExecutor(max_workers=10) as ex:
        futures = {ex.submit(_resolve_geo, ip): ip for ip, _ in top_ips}
        try:
            for fut in as_completed(futures, timeout=6.0):
                ip = futures[fut]
                try:
                    geo_map[ip] = fut.result()
                except Exception:
                    geo_map[ip] = _FALLBACK_GEO.copy()
        except TimeoutError:
            pass  # remaining IPs fall through to the fallback loop below
    # Any IPs that didn't finish within 6.0 s get the fallback
    for ip, _ in top_ips:
        if ip not in geo_map:
            geo_map[ip] = _FALLBACK_GEO.copy()

    results = [
        {"ip": ip, "count": count, "severity": ip_severity.get(ip, "LOW"),
         **geo_map.get(ip, _FALLBACK_GEO)}
        for ip, count in top_ips
    ]
    return jsonify(results)


def _country_entry(country: dict, c: str, cc: str) -> dict:
    if c not in country:
        country[c] = {"country": c, "countryCode": cc,
                      "alert_count": 0, "block_count": 0, "max_severity": "LOW"}
    return country[c]


def _agg_alerts_by_country(country: dict) -> None:
    for a in load_alerts():
        ip  = a.get("source_ip", "")
        sev = a.get("severity", "LOW")
        if not ip or ip in ("N/A", "Multiple", "") or _is_private_ip(ip):
            continue
        geo  = _resolve_geo(ip)
        row  = _country_entry(country, geo.get("country", "Unknown") or "Unknown",
                               geo.get("countryCode", ""))
        row["alert_count"] += 1
        if _SEV_RANK.get(sev, 0) > _SEV_RANK.get(row["max_severity"], 0):
            row["max_severity"] = sev


def _agg_blocks_by_country(country: dict) -> None:
    try:
        from firewall_enforcer import get_blocked_list
        for b in get_blocked_list():
            if b.get("status") != "active":
                continue
            ip = b.get("ip", "")
            if not ip or _is_private_ip(ip):
                continue
            geo = _resolve_geo(ip)
            row = _country_entry(country, geo.get("country", "Unknown") or "Unknown",
                                  geo.get("countryCode", ""))
            row["block_count"] += 1
    except Exception:
        pass


@api_bp.route("/api/geo_summary", methods=["GET"])
def api_geo_summary():
    """Country-level threat aggregation across all alerts + blocked IPs."""
    country: dict = {}
    _agg_alerts_by_country(country)
    _agg_blocks_by_country(country)

    rows = sorted(country.values(),
                  key=lambda x: x["alert_count"] + x["block_count"] * 2,
                  reverse=True)[:15]
    try:
        from geo_resolver import geo_source
        source = geo_source()
    except Exception:
        source = "unknown"
    return jsonify({"rows": rows, "source": source})


# ── Export ────────────────────────────────────────────────────────

@api_bp.route("/api/export/alerts.csv", methods=["GET"])
@require_role("analyst")
def export_alerts_csv():
    date_str = request.args.get("date", "")
    if date_str:
        try:
            datetime.strptime(date_str, "%Y-%m-%d")
        except ValueError:
            return jsonify({"error": _ERR_DATE_FMT}), 400
        alerts = load_alerts_by_date(date_str)
        fname  = f"packetguard_alerts_{date_str}.csv"
    else:
        alerts = load_alerts()
        fname  = "packetguard_alerts.csv"
    si = io.StringIO()
    w  = csv.DictWriter(si, fieldnames=[
        "timestamp", "alert_type", "severity", "source_ip",
        "destination_ip", "message"])
    w.writeheader()
    for a in alerts:
        w.writerow({k: a.get(k, "") for k in w.fieldnames})
    return Response(si.getvalue(), mimetype=_MIME_CSV,
                    headers={"Content-Disposition": f"attachment;filename={fname}"})


@api_bp.route("/api/export/alerts.json", methods=["GET"])
@require_role("analyst")
def export_alerts_json():
    date_str = request.args.get("date", "")
    if date_str:
        try:
            datetime.strptime(date_str, "%Y-%m-%d")
        except ValueError:
            return jsonify({"error": _ERR_DATE_FMT}), 400
        alerts = load_alerts_by_date(date_str)
        fname  = f"packetguard_alerts_{date_str}.json"
    else:
        alerts = load_alerts()
        fname  = "packetguard_alerts.json"
    return Response(json.dumps(alerts, indent=2, default=str),
                    mimetype=_MIME_JSON,
                    headers={"Content-Disposition": f"attachment;filename={fname}"})


@api_bp.route("/api/export/scan_history.csv", methods=["GET"])
@require_role("analyst")
def export_scan_history_csv():
    history = load_scan_history()
    si = io.StringIO()
    w  = csv.DictWriter(si, fieldnames=[
        "timestamp", "device_count", "trigger", "devices"])
    w.writeheader()
    for h in history:
        w.writerow({
            "timestamp":    h.get("timestamp", ""),
            "device_count": h.get("device_count", 0),
            "trigger":      h.get("trigger", ""),
            "devices":      ", ".join(h.get("devices", []))
        })
    return Response(si.getvalue(), mimetype=_MIME_CSV,
                    headers={"Content-Disposition":
                             "attachment;filename=packetguard_scan_history.csv"})


def _format_runtime(runtime: int) -> str:
    if runtime >= 3600:
        return f"{runtime//3600}h {(runtime%3600)//60}m {runtime%60}s"
    if runtime >= 60:
        return f"{runtime//60}m {runtime%60}s"
    return f"{runtime}s"


def _format_bytes(n: int) -> str:
    if n > 1073741824:
        return f"{n/1073741824:.2f} GB"
    if n > 1048576:
        return f"{n/1048576:.1f} MB"
    if n > 1024:
        return f"{n/1024:.1f} KB"
    return f"{n} B"


def _top_ip_entry(lst: list, idx: int) -> tuple:
    return (lst[idx][0] if len(lst) > idx else "",
            lst[idx][1] if len(lst) > idx else 0)


def _compute_alert_stats(alerts: list) -> tuple:
    sev_counts  = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    alert_types = {}
    src_counts  = {}
    for a in alerts:
        sev = a.get("severity", "").upper()
        if sev in sev_counts:
            sev_counts[sev] += 1
        atype = a.get("alert_type", a.get("type", "UNKNOWN"))
        alert_types[atype] = alert_types.get(atype, 0) + 1
        src = a.get("source_ip", "")
        if src and src not in ("N/A", "Multiple", ""):
            src_counts[src] = src_counts.get(src, 0) + 1
    return sev_counts, alert_types, src_counts


def _build_session_rows():
    """Build a list of enriched session rows (today + saved history)."""
    HISTORY_FILE_PATH = os.path.join(BASE_DIR, "session_history.json")
    saved = []
    if os.path.exists(HISTORY_FILE_PATH):
        try:
            with open(HISTORY_FILE_PATH, "r", encoding="utf-8") as f:
                saved = json.load(f)
        except Exception:
            pass

    live   = load_live_stats()
    alerts = load_alerts()
    ml_al  = load_ml_alerts()

    sev_counts, alert_types, _alert_src_counts = _compute_alert_stats(alerts)

    protos   = live.get("protocols", {})
    top_ips  = live.get("top_ips", {})
    runtime  = live.get("runtime_seconds", 0)
    pkts     = live.get("total_packets", 0)
    bytes_t  = live.get("bytes_total", 0)

    top_proto_list  = sorted(protos.items(), key=lambda x: x[1], reverse=True)
    top_ip_list     = sorted(top_ips.items(), key=lambda x: x[1], reverse=True)
    blocked_count   = len(load_blocklist())
    ml_total_true   = live.get("ml_total", len(ml_al))
    proto_sum       = sum(protos.values()) or 1

    top_alert_src       = max(_alert_src_counts, key=_alert_src_counts.get) if _alert_src_counts else ""
    top_alert_src_count = _alert_src_counts.get(top_alert_src, 0)
    top_alert_type      = max(alert_types, key=alert_types.get) if alert_types else ""

    today = {
        "date":              datetime.now().strftime("%Y-%m-%d"),
        "session_label":     "Today (live)",
        "session_status":    "live",
        "start_time":        datetime.now().strftime("%Y-%m-%d %H:%M"),
        "runtime_seconds":   runtime,
        "runtime_human":     _format_runtime(runtime),
        "total_packets":     pkts,
        "bytes_total":       bytes_t,
        "bytes_human":       _format_bytes(bytes_t),
        "avg_packets_per_sec":   round(pkts / runtime, 2) if runtime > 0 else 0,
        "peak_rate_pps":         live.get("rate", 0),
        "avg_packet_size_bytes": round(bytes_t / pkts, 1) if pkts > 0 else 0,
        "data_rate_bps":         round(bytes_t / runtime, 2) if runtime > 0 else 0,
        "total_alerts":          len(alerts),
        "alert_rate_per_minute": round(len(alerts) / (runtime / 60), 2) if runtime > 0 else 0,
        "alerts_critical":       sev_counts["CRITICAL"],
        "alerts_high":           sev_counts["HIGH"],
        "alerts_medium":         sev_counts["MEDIUM"],
        "alerts_low":            sev_counts["LOW"],
        "alerts_info":           sev_counts["INFO"],
        "alert_types":           ", ".join(f"{k}:{v}" for k, v in sorted(alert_types.items(), key=lambda x: -x[1])),
        "top_alert_type":        top_alert_type,
        "top_alert_source_ip":   top_alert_src,
        "top_alert_source_count": top_alert_src_count,
        "ml_anomalies":          ml_total_true,
        "ml_anomaly_rate_per_hour": round((ml_total_true / runtime) * 3600, 2) if runtime > 0 else 0,
        "ml_anomaly_count":      alert_types.get("ML_ANOMALY", 0) + alert_types.get("ML_ANOMALY_AGGREGATED", 0),
        "ml_burst_count":        alert_types.get("ML_ANOMALY_BURST", 0) + alert_types.get("ML_ANOMALY_BURST_AGGREGATED", 0),
        "ml_dos_count":          alert_types.get("ML_DOS", 0),
        "ml_other_count":        alert_types.get("ML_OTHER", 0),
        "port_scan_count":       alert_types.get("PORT_SCAN", 0),
        "syn_flood_count":       alert_types.get("SYN_FLOOD", 0),
        "high_rate_count":       alert_types.get("HIGH_PACKET_RATE", 0) + alert_types.get("HIGH_PACKET_RATE_AGGREGATED", 0),
        "dns_anomaly_count":     alert_types.get("DNS_ANOMALY", 0),
        "abnormal_size_count":   alert_types.get("ABNORMAL_SIZE", 0),
        "blocked_ips_count":     blocked_count,
        "unique_src_ips":        len(top_ips),
        "proto_tcp":             protos.get("TCP", 0),
        "proto_tcp_pct":         round(protos.get("TCP", 0) / proto_sum * 100, 1),
        "proto_udp":             protos.get("UDP", 0),
        "proto_udp_pct":         round(protos.get("UDP", 0) / proto_sum * 100, 1),
        "proto_icmp":            protos.get("ICMP", 0),
        "proto_icmp_pct":        round(protos.get("ICMP", 0) / proto_sum * 100, 1),
        "proto_dns":             protos.get("DNS", 0),
        "proto_http":            protos.get("HTTP", 0),
        "proto_https":           protos.get("HTTPS", 0),
        "proto_other":           protos.get("Other", protos.get("OTHER", 0)),
        "proto_other_pct":       round(protos.get("Other", protos.get("OTHER", 0)) / proto_sum * 100, 1),
        "top_protocol":          top_proto_list[0][0] if top_proto_list else "",
        "all_protocols":         ", ".join(f"{k}:{v}" for k, v in top_proto_list),
        "top_ip_1":              _top_ip_entry(top_ip_list, 0)[0],
        "top_ip_1_packets":      _top_ip_entry(top_ip_list, 0)[1],
        "top_ip_2":              _top_ip_entry(top_ip_list, 1)[0],
        "top_ip_2_packets":      _top_ip_entry(top_ip_list, 1)[1],
        "top_ip_3":              _top_ip_entry(top_ip_list, 2)[0],
        "top_ip_3_packets":      _top_ip_entry(top_ip_list, 2)[1],
        "top_ip_4":              _top_ip_entry(top_ip_list, 3)[0],
        "top_ip_4_packets":      _top_ip_entry(top_ip_list, 3)[1],
        "top_ip_5":              _top_ip_entry(top_ip_list, 4)[0],
        "top_ip_5_packets":      _top_ip_entry(top_ip_list, 4)[1],
        "all_top_ips":           ", ".join(f"{ip}:{cnt}" for ip, cnt in top_ip_list[:10]),
    }
    return [today] + list(reversed(saved))


_SESSION_CSV_FIELDS = [
    "date", "session_label", "session_status", "start_time",
    "runtime_seconds", "runtime_human",
    "total_packets", "bytes_total", "bytes_human",
    "avg_packets_per_sec", "peak_rate_pps", "avg_packet_size_bytes",
    "data_rate_bps", "total_alerts", "alert_rate_per_minute",
    "alerts_critical", "alerts_high", "alerts_medium", "alerts_low", "alerts_info",
    "alert_types", "top_alert_type", "top_alert_source_ip", "top_alert_source_count",
    "ml_anomalies", "ml_anomaly_rate_per_hour",
    "ml_anomaly_count", "ml_burst_count", "ml_dos_count", "ml_other_count",
    "port_scan_count", "syn_flood_count", "high_rate_count",
    "dns_anomaly_count", "abnormal_size_count",
    "blocked_ips_count", "unique_src_ips",
    "proto_tcp", "proto_tcp_pct", "proto_udp", "proto_udp_pct",
    "proto_icmp", "proto_icmp_pct", "proto_dns", "proto_http", "proto_https",
    "proto_other", "proto_other_pct", "top_protocol", "all_protocols",
    "top_ip_1", "top_ip_1_packets", "top_ip_2", "top_ip_2_packets",
    "top_ip_3", "top_ip_3_packets", "top_ip_4", "top_ip_4_packets",
    "top_ip_5", "top_ip_5_packets", "all_top_ips",
]


@api_bp.route("/api/export/session_history.csv", methods=["GET"])
@require_role("analyst")
def export_session_history_csv():
    try:
        rows = _build_session_rows()
        si   = io.StringIO()
        w    = csv.DictWriter(si, fieldnames=_SESSION_CSV_FIELDS, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in _SESSION_CSV_FIELDS})
        return Response(si.getvalue(), mimetype=_MIME_CSV,
                        headers={"Content-Disposition":
                                 "attachment;filename=packetguard_session_history.csv"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@api_bp.route("/api/export/session_history.json", methods=["GET"])
@require_role("analyst")
def export_session_history_json():
    try:
        rows = _build_session_rows()
        output = json.dumps({
            "exported_at":    datetime.now().isoformat(),
            "export_version": "2.0",
            "generator":      "PacketGuard SOC Platform",
            "total_sessions": len(rows),
            "summary": {
                "total_packets":      sum(r.get("total_packets", 0) for r in rows),
                "total_bytes":        sum(r.get("bytes_total",   0) for r in rows),
                "total_alerts":       sum(r.get("total_alerts",  0) for r in rows),
                "total_ml_anomalies": sum(r.get("ml_anomalies",  0) for r in rows),
                "sessions_exported":  len(rows),
            },
            "fields_included": _SESSION_CSV_FIELDS,
            "sessions":        rows,
        }, indent=2, default=str)
        return Response(output, mimetype=_MIME_JSON,
                        headers={"Content-Disposition":
                                 "attachment;filename=packetguard_session_history.json"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Admin: User Management ────────────────────────────────────────

@api_bp.route("/api/admin/users", methods=["GET"])
@require_role("analyst")
def admin_list_users():
    try:
        from access_control import get_all_users
        users = get_all_users(_db)
        return jsonify({"success": True, "users": users})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@api_bp.route("/api/admin/users/<int:user_id>/role", methods=["POST"])
@require_role("admin")
def admin_set_role(user_id):
    if user_id == (_get_current_user() or {}).get("id"):
        return jsonify({"success": False, "error": "Cannot change your own role."}), 400
    data     = request.get_json() or {}
    new_role = data.get("role", "").strip()
    from access_control import set_user_role, ROLE_LEVEL as _RL
    if new_role not in _RL:
        return jsonify({"success": False,
                        "error": f"Invalid role. Choose: {list(_RL.keys())}"}), 400
    ok = set_user_role(_db, user_id, new_role)
    if ok:
        return jsonify({"success": True, "message": f"Role updated to {new_role}."})
    return jsonify({"success": False, "error": "User not found."}), 404


@api_bp.route("/api/admin/users/<int:user_id>", methods=["DELETE"])
@require_role("admin")
def admin_delete_user(user_id):
    from access_control import delete_user
    ok, msg = delete_user(_db, user_id, (_get_current_user() or {}).get("id"))
    if ok:
        return jsonify({"success": True, "message": msg})
    return jsonify({"success": False, "error": msg}), 400


@api_bp.route("/api/admin/users/create", methods=["POST"])
@require_role("admin")
def admin_create_user():
    data  = request.get_json() or {}
    name  = data.get("name", "").strip()
    email = data.get("email", "").strip().lower()
    pw    = data.get("password", "")
    role  = data.get("role", "analyst").strip()
    from access_control import ROLE_LEVEL as _RL
    if not name or not email or not pw:
        return jsonify({"success": False,
                        "error": "name, email, and password are required."}), 400
    pw_ok, pw_msg = validate_password_strength(pw)
    if not pw_ok:
        return jsonify({"success": False, "error": pw_msg}), 400
    if role not in _RL:
        return jsonify({"success": False,
                        "error": f"Invalid role. Choose: {list(_RL.keys())}"}), 400
    from auth_service import hash_password
    conn = _db()
    try:
        conn.execute(
            "INSERT INTO users (name,email,password,role,created_at) VALUES (?,?,?,?,?)",
            (name, email, hash_password(pw), role, datetime.now(timezone.utc).isoformat())
        )
        conn.commit()
        return jsonify({"success": True,
                        "message": f"User {email} created with role {role}."})
    except sqlite3.IntegrityError:
        return jsonify({"success": False, "error": "Email already registered."}), 409
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        conn.close()


@api_bp.route("/api/admin/users/<int:user_id>/reset-password", methods=["POST"])
@require_role("admin")
def admin_reset_password(user_id):
    data   = request.get_json() or {}
    new_pw = data.get("new_password", "").strip()
    pw_ok, pw_msg = validate_password_strength(new_pw)
    if not pw_ok:
        return jsonify({"success": False, "error": pw_msg}), 400
    from auth_service import hash_password
    conn = _db()
    try:
        row = conn.execute("SELECT id FROM users WHERE id=?", (user_id,)).fetchone()
        if not row:
            return jsonify({"success": False, "error": "User not found."}), 404
        conn.execute("UPDATE users SET password=? WHERE id=?",
                     (hash_password(new_pw), user_id))
        conn.commit()
        return jsonify({"success": True, "message": "Password reset successfully."})
    finally:
        conn.close()


# ── Threat Hunting ────────────────────────────────────────────────

def _afield(a: dict, key: str) -> str:
    return (a.get(key) or "").upper()


def _alert_matches(a: dict, sev: str, atype: str, proto: str,
                   ip_filter: str, port_filter: str, free_text: str) -> bool:
    src_dst = (a.get("source_ip") or "") + (a.get("destination_ip") or "")
    ports   = str(a.get("source_port", "")) + str(a.get("destination_port", ""))
    if sev         and _afield(a, "severity")   != sev:              return False
    if atype       and atype   not in _afield(a, "alert_type"):      return False
    if proto       and proto   not in _afield(a, "protocol"):        return False
    if ip_filter   and ip_filter   not in src_dst:                   return False
    if port_filter and port_filter not in ports:                     return False
    if free_text   and free_text   not in json.dumps(a).lower():     return False
    return True


def _parse_hunt_query(q: str) -> tuple:
    import re as _re
    kv        = dict(_re.findall(r'(\w+):(\S+)', q))
    free_text = _re.sub(r'\w+:\S+', '', q).strip()
    return kv, free_text


def _hunt_params() -> tuple:
    return (
        (request.args.get("q")        or "").strip().lower(),
        (request.args.get("severity") or "").upper(),
        (request.args.get("protocol") or "").upper(),
        (request.args.get("type")     or "").upper(),
        (request.args.get("ip")       or "").strip(),
        (request.args.get("port")     or "").strip(),
        min(int(request.args.get("limit", 200) or 200), 1000),
    )


@api_bp.route("/api/hunt", methods=["GET"])
def api_hunt():
    q, sev, proto, atype, ip_filter, port_filter, limit = _hunt_params()

    alerts = load_alerts(limit=10000)
    try:
        alerts = alerts + load_ml_alerts(limit=5000)
    except Exception:
        pass

    alerts    = [_enrich_alert(dict(a)) for a in alerts]
    kv, free_text = _parse_hunt_query(q)

    if kv.get("severity"): sev         = kv["severity"].upper()
    if kv.get("type"):     atype       = kv["type"].upper()
    if kv.get("ip"):       ip_filter   = kv["ip"]
    if kv.get("port"):     port_filter = kv["port"]
    if kv.get("proto"):    proto       = kv["proto"].upper()

    results = []
    for a in reversed(alerts):
        if not _alert_matches(a, sev, atype, proto, ip_filter, port_filter, free_text):
            continue
        results.append(a)
        if len(results) >= limit:
            break

    return jsonify({"total": len(results), "results": results})


@api_bp.route("/api/alert/status", methods=["POST"])
def api_alert_status():
    body   = request.get_json(force=True) or {}
    ts     = body.get("timestamp")
    status = body.get("status", "TRIAGED")
    assign = body.get("assigned_to")
    valid  = {"NEW", "TRIAGED", "INVESTIGATING", "ESCALATED",
              "CONTAINED", "RESOLVED", "FALSE_POSITIVE"}
    if status not in valid:
        return jsonify({"error": "invalid status"}), 400
    if not ts:
        return jsonify({"error": "timestamp required"}), 400
    try:
        conn = _db()
        cur = conn.execute(
            "UPDATE alerts SET status=?, assigned_to=? WHERE timestamp=?",
            (status, assign, ts)
        )
        conn.commit()
        updated = cur.rowcount > 0
        conn.close()
        return jsonify({"ok": True, "updated": updated})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@api_bp.route("/api/alerts/purge-own", methods=["POST"])
@require_role("admin")
def api_purge_own_alerts():
    """Remove all alerts sourced from this machine's own IPs (false positives)."""
    import socket as _sock
    own_ips = {'127.0.0.1', '::1', '0.0.0.0', 'localhost'}
    try:
        own_ips.add(_sock.gethostbyname(_sock.gethostname()))
    except Exception:
        pass
    try:
        from scapy.interfaces import get_if_list
        from scapy.arch import get_if_addr
        for iface in get_if_list():
            try:
                ip = get_if_addr(iface)
                if ip and ip != '0.0.0.0':
                    own_ips.add(ip)
            except Exception:
                pass
    except Exception:
        pass
    removed = 0

    # Purge from SQLite DB (primary alert store)
    try:
        db_conn = _db()
        placeholders = ','.join('?' * len(own_ips))
        cur = db_conn.execute(
            f"DELETE FROM alerts WHERE source_ip IN ({placeholders})",
            list(own_ips)
        )
        removed += cur.rowcount
        db_conn.commit()
        db_conn.close()
    except Exception as _e:
        print(f"[PURGE] DB purge error: {_e}")

    # Also purge from JSON fallback files (used by /api/hunt)
    for fpath in [ALERTS_FILE, ML_ALERTS_FILE]:
        try:
            with open(fpath, 'r', encoding='utf-8') as f:
                alerts = json.load(f)
            filtered = [a for a in alerts if a.get('source_ip') not in own_ips]
            removed += len(alerts) - len(filtered)
            with open(fpath, 'w', encoding='utf-8') as f:
                json.dump(filtered, f, indent=2)
        except Exception:
            pass
    return jsonify({'success': True, 'removed': removed, 'own_ips': sorted(own_ips)})


# ── Missing routes ─────────────────────────────────────────────────

@api_bp.route("/api/debug/clear_alerts", methods=["POST"])
@require_role("admin")
def api_clear_alerts():
    """Admin-only: wipe all alerts from DB and JSON files."""
    deleted = 0
    try:
        conn = _db()
        cur = conn.execute("DELETE FROM alerts")
        deleted = cur.rowcount
        conn.commit()
        conn.close()
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    # Also clear the JSON fallback files used by /api/hunt
    for fpath in [ALERTS_FILE, ML_ALERTS_FILE]:
        try:
            with open(fpath, 'w', encoding='utf-8') as f:
                json.dump([], f)
        except Exception:
            pass
    return jsonify({"success": True, "deleted": deleted})


@api_bp.route("/api/debug/capture", methods=["GET"])
def api_debug_capture():
    """Diagnostic endpoint — capture state + DB alert counts."""
    try:
        import live_monitor as _lm
        import threading, sqlite3 as _sq
        threads = {t.name: t.is_alive() for t in threading.enumerate()}

        # Count alerts directly in DB
        db_path = os.path.join(BASE_DIR, "packetguard.db")
        conn = _sq.connect(db_path, timeout=3)
        db_total   = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        db_regular = conn.execute("SELECT COUNT(*) FROM alerts WHERE is_ml=0").fetchone()[0]
        db_ml      = conn.execute("SELECT COUNT(*) FROM alerts WHERE is_ml=1").fetchone()[0]
        recent_rows = conn.execute(
            "SELECT alert_type, severity, source_ip, timestamp FROM alerts "
            "ORDER BY id DESC LIMIT 5"
        ).fetchall()
        schema = conn.execute(
            "PRAGMA table_info(alerts)"
        ).fetchall()
        conn.close()

        return jsonify({
            "running":           _lm._state.get("running", False),
            "packets_captured":  _lm._state.get("packets_captured", 0),
            "alerts_total_mem":  _lm._state.get("alerts_total", 0),
            "alerts_total_db":   db_total,
            "alerts_regular_db": db_regular,
            "alerts_ml_db":      db_ml,
            "recent_db_alerts":  [dict(zip(["type","sev","src","ts"], r)) for r in recent_rows],
            "alerts_schema":     [r[1] for r in schema],  # column names
            "last_nonzero_rate": _lm._last_nonzero_rate,
            "interface":         _lm._state.get("interface", "?"),
            "threads_alive":     {n: a for n, a in threads.items() if "PacketGuard" in n or
                                  n in ("rate-calc","capture","ml-wire","ml-emitter",
                                        "rate_calc","LIVE-EMITTER")},
            "all_thread_names":  sorted(threads.keys()),
            "syn_counts":        dict(list(_lm._syn_counts.items())[:5]),
            "port_scan":         {k: len(v) for k, v in list(_lm._port_scan_tr.items())[:5]},
            "top_talkers":       dict(sorted(_lm._state.get("top_talkers", {}).items(),
                                             key=lambda x: x[1], reverse=True)[:5]),
        })
    except Exception as e:
        return jsonify({"error": str(e), "type": type(e).__name__}), 500


@api_bp.route("/api/firewall_status", methods=["GET"])
def api_firewall_status():
    try:
        from firewall_enforcer import get_firewall_status
        return jsonify(get_firewall_status())
    except Exception:
        return jsonify({"enabled": False, "active_blocks": 0,
                        "real_blocks": 0, "total_blocked": 0,
                        "enforcement": "Unavailable", "status": "ERROR"})


@api_bp.route("/api/blocked_ips", methods=["GET"])
def api_blocked_ips():
    try:
        from firewall_enforcer import get_blocked_list
        return jsonify({"success": True, "blocked": get_blocked_list()})
    except Exception as e:
        return jsonify({"success": False, "blocked": [], "error": str(e)})


@api_bp.route("/api/blocked_ips/block", methods=["POST"])
@require_role("analyst")
def api_blocked_ips_block():
    """Dashboard block form — routes to block_manager for firewall enforcement."""
    data   = request.get_json() or {}
    ip     = data.get("ip", "").strip()
    reason = data.get("reason", "Manual block")
    if not ip:
        return jsonify({"success": False, "error": _ERR_IP_REQUIRED})
    try:
        from block_manager import manual_block
        result = manual_block(ip=ip, reason=reason, operator="admin")
        # Also sync to blocklist.json for packet filter
        blocked = load_blocklist()
        if not any(e["ip"] == ip for e in blocked):
            blocked.append({"ip": ip, "reason": reason,
                            "timestamp": datetime.now().isoformat(),
                            "fw_enforced": bool(result and result.get("real_block"))})
            save_list(BLOCKLIST_FILE, blocked)
        return jsonify({
            "success":     True,
            "fw_enforced": bool(result and result.get("real_block")),
            "status":      result.get("status", "unknown") if result else "logged",
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@api_bp.route("/api/blocked_ips/unblock", methods=["POST"])
@require_role("analyst")
def api_blocked_ips_unblock():
    """Dashboard unblock — removes firewall rule and syncs both lists."""
    data = request.get_json() or {}
    ip   = data.get("ip", "").strip()
    if not ip:
        return jsonify({"success": False, "error": _ERR_IP_REQUIRED})
    try:
        from firewall_enforcer import unblock_ip as _fw_unblock
        _fw_unblock(ip=ip, operator="admin")
    except Exception:
        pass
    blocked = [e for e in load_blocklist() if e["ip"] != ip]
    save_list(BLOCKLIST_FILE, blocked)
    return jsonify({"success": True})


@api_bp.route("/api/block_sync_status", methods=["GET"])
def api_block_sync_status():
    try:
        from firewall_enforcer import get_firewall_status
        fw = get_firewall_status()
        active   = fw.get("active_blocks", 0)
        real     = fw.get("real_blocks", 0)
        unsynced = max(0, active - real)
        return jsonify({
            "success":       True,
            "sync_health":   "OK" if unsynced == 0 else "UNSYNCED",
            "sync":          "synced" if unsynced == 0 else "unsynced",
            "active_blocks": active,
            "real_blocks":   real,
            "unsynced":      unsynced,
            "unsynced_ips":  fw.get("unsynced_ips", []),
            "status":        fw.get("status", "UNKNOWN"),
            "enforcement":   fw.get("enforcement", "Unknown"),
        })
    except Exception:
        return jsonify({"success": True, "sync_health": "OK", "sync": "synced",
                        "active_blocks": 0, "real_blocks": 0, "unsynced": 0})


# ── Monitor control ────────────────────────────────────────────────

@api_bp.route("/api/monitor/status", methods=["GET"])
def api_monitor_status():
    live = load_live_stats()
    ml_ready = False
    ml_models = 0
    try:
        from ml_detector import get_detector
        det = get_detector()
        if det and det.ready:
            ml_ready = True
            ml_models = det.status().get("models_loaded", 0)
    except Exception:
        pass
    return jsonify({
        "running":       live.get("running", False),
        "total_packets": live.get("total_packets", 0),
        "rate":          live.get("rate", 0),
        "interface":     live.get("interface"),
        "runtime":       live.get("runtime_seconds", 0),
        "alerts_total":  live.get("alerts_total", 0),
        "ml": {
            "ready":         ml_ready,
            "models_loaded": ml_models,
        },
    })


@api_bp.route("/api/monitor/start", methods=["POST"])
@require_role("analyst")
def api_monitor_start():
    try:
        from socket_handlers import _auto_start_live_monitor
        import threading
        threading.Thread(target=_auto_start_live_monitor, daemon=True,
                         name="ManualMonitorStart").start()
        return jsonify({"success": True, "message": "Monitor start requested."})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@api_bp.route("/api/monitor/stop", methods=["POST"])
@require_role("analyst")
def api_monitor_stop():
    try:
        from socket_handlers import _kill_existing_monitors
        import threading
        threading.Thread(target=_kill_existing_monitors, daemon=True,
                         name="ManualMonitorStop").start()
        return jsonify({"success": True, "message": "Monitor stop requested."})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ── ARP spoof control ──────────────────────────────────────────────

@api_bp.route("/api/arp_spoof/status", methods=["GET"])
def api_arp_spoof_status():
    try:
        from arp_spoof import get_status
        return jsonify(get_status())
    except Exception as e:
        return jsonify({"running": False, "error": str(e)})


@api_bp.route("/api/arp_spoof/start", methods=["POST"])
@require_role("analyst")
def api_arp_spoof_start():
    try:
        from arp_spoof import start_spoofing
        ok = start_spoofing()
        from arp_spoof import get_status
        return jsonify({"success": ok, **get_status()})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@api_bp.route("/api/arp_spoof/stop", methods=["POST"])
@require_role("analyst")
def api_arp_spoof_stop():
    try:
        from arp_spoof import stop_spoofing
        stop_spoofing()
        return jsonify({"success": True, "message": "ARP spoofing stopped."})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ── Flow data endpoints ────────────────────────────────────────────

@api_bp.route("/api/flows/recent", methods=["GET"])
def api_flows_recent():
    try:
        n = min(int(request.args.get("n", 100)), 1000)
    except (ValueError, TypeError):
        n = 100
    try:
        from flow_exporter import FlowExporter
        exporter = FlowExporter()
        return jsonify(exporter.get_recent_flows(n))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@api_bp.route("/api/flows/stats", methods=["GET"])
def api_flows_stats():
    try:
        from live_monitor import _get_flow_builder
        fb = _get_flow_builder()
        active = fb.get_active_count()
    except Exception:
        active = 0
    try:
        from flow_exporter import FlowExporter
        flows = FlowExporter().get_recent_flows(1000)
        total = len(flows)
        proto_counts: dict = {}
        for f in flows:
            p = f.get("protocol", "OTHER")
            proto_counts[p] = proto_counts.get(p, 0) + 1
    except Exception:
        total, proto_counts = 0, {}
    return jsonify({
        "active_flows":  active,
        "flows_today":   total,
        "top_protocols": proto_counts,
    })


# ── AI Incident Analysis — local rule-based engine (no API key needed) ────────

_MITRE = {
    "PORT_SCAN":             ("TA0043", "Reconnaissance",     "T1046", "Network Service Discovery"),
    "SYN_FLOOD":             ("TA0040", "Impact",             "T1498", "Network Denial of Service"),
    "HIGH_PACKET_RATE":      ("TA0040", "Impact",             "T1498", "Network Flood"),
    "ML_ANOMALY":            ("TA0002", "Execution",          "T1059", "Anomalous Execution Pattern"),
    "ML_FLOW_ANOMALY":       ("TA0001", _TAC_INITIAL,          "T1190", "Anomalous Flow Pattern"),
    "BRUTE_FORCE":           ("TA0006", "Credential Access",  "T1110", "Brute Force"),
    "DNS_ANOMALY":           ("TA0011", _TAC_C2,               "T1071", "DNS Protocol Abuse"),
    "ARP_SPOOF":             ("TA0009", "Collection",         "T1040", "Network Sniffing"),
}

def _incident_actions(attack: str, src_ip: str) -> list:
    atk = attack.replace(" ", "_")
    if "PORT_SCAN" in atk:
        return [
            f"Block {src_ip} at the firewall immediately using the Block IP button.",
            "Review which ports responded to the scan and close unnecessary ones.",
            "Enable port-scan detection alerts on your firewall/IDS for this subnet.",
        ]
    if "FLOOD" in attack or "HIGH_RATE" in atk:
        return [
            f"Rate-limit or block {src_ip} at the network perimeter.",
            "Enable TCP SYN cookies on affected servers to mitigate connection exhaustion.",
            "Contact your ISP if the traffic volume exceeds your mitigation capacity.",
        ]
    if "BRUTE" in attack:
        return [
            f"Block {src_ip} immediately and review authentication logs.",
            "Enable account lockout policies on all exposed services.",
            "Force password resets for accounts targeted during this window.",
        ]
    return [
        f"Isolate or block {src_ip} while investigation is ongoing.",
        "Capture a packet trace from this source for deeper forensic analysis.",
        "Escalate to Tier 2 if activity persists after blocking.",
    ]


def _incident_inv_steps(src_ip: str, first_seen: str, last_seen: str) -> list:
    return [
        f"Check all alerts from {src_ip} in the Alerts panel — filter by source IP.",
        f"Review the session history log for {src_ip} between {first_seen} and {last_seen}.",
        "Correlate with firewall and authentication logs to determine if any access was gained.",
    ]


def _incident_verdict(risk: float, severity: str) -> tuple:
    if risk >= 80 or severity == "CRITICAL":
        return "CRITICAL", "high risk score and critical severity classification"
    if risk >= 60 or severity == "HIGH":
        return "HIGH", "elevated risk score with confirmed malicious indicators"
    if risk >= 40 or severity == "MEDIUM":
        return "MEDIUM", "moderate risk — monitor closely and investigate"
    return "LOW", "low confidence or limited event count — continue monitoring"


def _local_incident_analysis(inc: dict) -> str:
    attack      = (inc.get("attack_chain") or inc.get("title") or "Unknown Attack").upper()
    src_ip      = inc.get("source_ip",   "Unknown")
    severity    = (inc.get("severity")   or "MEDIUM").upper()
    risk        = inc.get("risk_score")  or inc.get("threat_score") or 0
    confidence  = inc.get("confidence")  or 0
    events      = inc.get("event_count") or 0
    indicators  = inc.get("explanation") or []
    first_seen  = inc.get("first_seen",  "Unknown")
    last_seen   = inc.get("last_seen",   "Unknown")

    # MITRE lookup
    mitre_key   = next((k for k in _MITRE if k in attack.replace(" ", "_")), None)
    mitre       = _MITRE.get(mitre_key, ("TA0001", _TAC_INITIAL,   "T1190", "Unknown Technique"))

    # Threat summary by attack type
    summaries = {
        "PORT_SCAN":        f"{src_ip} performed an active port scan targeting this network. "
                            f"{events} scan events were recorded with {confidence}% confidence. "
                            "This indicates a reconnaissance phase — the attacker is mapping open services before launching a targeted exploit.",
        "SYN_FLOOD":        f"{src_ip} sent a high volume of TCP SYN packets without completing handshakes. "
                            f"This is a classic SYN flood denial-of-service attack ({events} events detected). "
                            "The intent is to exhaust server connection tables and cause service disruption.",
        "HIGH_PACKET_RATE": f"{src_ip} generated an abnormally high packet rate ({events} events). "
                            "This pattern matches network flooding or DDoS behavior and may cause degraded performance for legitimate users.",
        "BRUTE_FORCE":      f"{src_ip} made repeated authentication attempts ({events} events). "
                            "This is a brute-force credential attack targeting login services on this network.",
        "DNS_ANOMALY":      f"{src_ip} exhibited unusual DNS query behavior ({events} events). "
                            "This may indicate DNS tunneling for covert command-and-control communication or data exfiltration.",
        "ML_ANOMALY":       f"The ML engine detected statistically anomalous traffic from {src_ip} ({events} events, confidence {confidence}%). "
                            "The traffic pattern deviates significantly from established baselines, suggesting evasion techniques or novel attack behavior.",
    }
    summary = next((v for k, v in summaries.items() if k in attack.replace(" ", "_")),
                   f"Suspicious activity detected from {src_ip} ({events} events, confidence {confidence}%). "
                   f"The system classified this as a {severity} severity incident requiring investigation.")

    # Intent by attack type
    intents = {
        "PORT_SCAN":    "Map open services and identify exploitable entry points before launching a targeted attack.",
        "SYN_FLOOD":    "Exhaust server resources and cause denial of service to legitimate users.",
        "BRUTE_FORCE":  "Gain unauthorized access by guessing credentials to internal services.",
        "DNS_ANOMALY":  "Establish a covert communication channel or exfiltrate data bypassing standard security controls.",
        "ML_ANOMALY":   "Evade signature-based detection using novel or obfuscated attack techniques.",
    }
    intent = next((v for k, v in intents.items() if k in attack.replace(" ", "_")),
                  "Gain unauthorized access or disrupt network services.")

    actions   = _incident_actions(attack, src_ip)
    inv_steps = _incident_inv_steps(src_ip, first_seen, last_seen)
    verdict, verdict_reason = _incident_verdict(risk, severity)

    ind_text = ("\nDETECTION INDICATORS\n" +
                "\n".join(f"  - {x}" for x in indicators[:5])
                if indicators else "")

    return (
        f"SOC INCIDENT ANALYSIS REPORT\n"
        f"{'='*46}\n\n"
        f"Incident  : {inc.get('incident_id','N/A')}\n"
        f"Source IP : {src_ip}\n"
        f"Severity  : {severity}  |  Risk Score: {risk}/100  |  Confidence: {confidence}%\n"
        f"MITRE ATT&CK: {mitre[0]} {mitre[1]} — {mitre[2]} ({mitre[3]})\n"
        f"Events    : {events}  |  Active: {first_seen} to {last_seen}\n"
        f"\n1. THREAT SUMMARY\n{summary}\n"
        f"\n2. ATTACKER INTENT\n{intent}\n"
        f"\n3. IMMEDIATE ACTIONS\n" +
        "\n".join(f"  {i+1}. {a}" for i, a in enumerate(actions)) +
        "\n\n4. INVESTIGATION STEPS\n" +
        "\n".join(f"  {i+1}. {s}" for i, s in enumerate(inv_steps)) +
        f"{ind_text}\n"
        f"\n5. OVERALL RISK: {verdict}\n"
        f"   Basis: {verdict_reason}.\n"
    )


@api_bp.route("/api/incidents/analyze", methods=["POST"])
@require_login
def api_incident_analyze():
    body = request.get_json(force=True) or {}
    inc  = body.get("incident", {})
    if not inc:
        return jsonify({"error": "incident data required"}), 400
    try:
        text = _local_incident_analysis(inc)
        return jsonify({"success": True, "text": text})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
