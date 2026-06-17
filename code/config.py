#!/usr/bin/env python3
"""
config.py — PacketGuard
All constants, file paths, and Flask app/SocketIO setup.
Import this first; every other module imports from here.
"""
import os
import warnings
import logging
import secrets

os.environ["PYTHONWARNINGS"] = "ignore"
warnings.filterwarnings("ignore")
warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", category=FutureWarning)


class _SklearnWarningFilter(logging.Filter):
    def filter(self, record):
        msg = record.getMessage()
        if "sklearn" in msg or "joblib" in msg or "delayed" in msg or "Parallel" in msg:
            return False
        return True


logging.getLogger().addFilter(_SklearnWarningFilter())
logging.getLogger("py.warnings").addFilter(_SklearnWarningFilter())

# ── Load env file FIRST so every os.environ.get() below picks it up ──────────
def _load_env_file():
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "env")
    if not os.path.exists(env_path):
        return
    with open(env_path, "r", encoding="utf-8") as _f:
        for _line in _f:
            _line = _line.strip()
            if not _line or _line.startswith("#") or "=" not in _line:
                continue
            _key, _, _val = _line.partition("=")
            _key = _key.strip()
            _val = _val.strip().strip('"').strip("'")
            if _key and _key not in os.environ:
                os.environ[_key] = _val

_load_env_file()

from flask import Flask, request, Response
from flask_socketio import SocketIO
from flask_cors import CORS

# "" App """"""""""""""""""""""""""""""""""""""""""""""""""""""""""""
app = Flask(__name__, template_folder="templates")
app.config["JSON_AS_ASCII"] = False
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.jinja_env.auto_reload = True
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="threading",
    logger=False,
    engineio_logger=False,
    ping_timeout=60,
    ping_interval=25,
    allow_upgrades=False,
)
# SECRET_KEY is now read AFTER _load_env_file() so the env file value is used.
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config["SESSION_COOKIE_SAMESITE"]      = "Lax"
app.config["SESSION_COOKIE_HTTPONLY"]      = True
app.config["SESSION_COOKIE_SECURE"]        = False
app.config["SESSION_COOKIE_NAME"]          = "pg_flask_session"
app.config["PERMANENT_SESSION_LIFETIME"]   = 86400  # 24 h

# "" File paths """""""""""""""""""""""""""""""""""""""""""""""""""""
BASE_DIR          = os.path.dirname(os.path.abspath(__file__))
ALERTS_FILE       = os.path.join(BASE_DIR, "alerts.json")
ML_ALERTS_FILE    = os.path.join(BASE_DIR, "ml_alerts.json")
DEVICES_FILE      = os.path.join(BASE_DIR, "network_devices.json")
LIVE_MONITOR_LOG  = os.path.join(BASE_DIR, "live_monitor.log")
LIVE_STATE_FILE   = os.path.join(BASE_DIR, "live_state.json")
MODELS_DIR        = os.path.join(BASE_DIR, "models")
BLOCKLIST_FILE    = os.path.join(BASE_DIR, "blocklist.json")
WHITELIST_FILE    = os.path.join(BASE_DIR, "whitelist.json")
ALERT_COUNT_FILE  = os.path.join(BASE_DIR, "alert_count.json")
SCAN_HISTORY_FILE = os.path.join(BASE_DIR, "scan_history.json")
HISTORY_FILE      = os.path.join(BASE_DIR, "session_history.json")
EMAIL_CONFIG_FILE = os.path.join(BASE_DIR, "email_config.json")
DB_PATH           = os.path.join(BASE_DIR, "packetguard.db")
_IFACE_OVERRIDE_FILE = os.path.join(BASE_DIR, "capture_iface.txt")

# "" Scan config """"""""""""""""""""""""""""""""""""""""""""""""""""
SCAN_INTERVAL = 20   # seconds between auto scans

# "" Resend / 2FA """"""""""""""""""""""""""""""""""""""""""""""""""
RESEND_API_KEY    = os.environ.get("RESEND_API_KEY", "")
RESEND_FROM_EMAIL = os.environ.get("RESEND_FROM_EMAIL", "PacketGuard <onboarding@resend.dev>")

# "" SMTP / 2FA email (Gmail) """""""""""""""""""""""""""""""""""""""
SMTP_EMAIL    = os.environ.get("SMTP_EMAIL", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")

# "" CORS """"""""""""""""""""""""""""""""""""""""""""""""""""""""""
_ALLOWED_ORIGINS = {
    "http://localhost:5000", "http://127.0.0.1:5000",
    "http://localhost:5001", "http://127.0.0.1:5001",
}

CORS(app, supports_credentials=True, origins=list(_ALLOWED_ORIGINS))


@app.after_request
def _cors_headers(response):
    # Skip socket.io engine paths — SocketIO manages its own CORS
    if request.path.startswith("/socket.io"):
        return response
    origin = request.headers.get("Origin", "")
    if origin in _ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"]      = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Methods"]     = "GET, POST, PUT, DELETE, OPTIONS"
        response.headers["Access-Control-Allow-Headers"]     = "Content-Type, Authorization, X-Requested-With"
        response.headers["Access-Control-Max-Age"]           = "3600"
        response.headers["Vary"]                             = "Origin"
    elif not origin:
        response.headers.setdefault("Vary", "Origin")
    return response


@app.route("/api/auth/login",    methods=["OPTIONS"])
@app.route("/api/auth/register", methods=["OPTIONS"])
@app.route("/api/auth/logout",   methods=["OPTIONS"])
@app.route("/api/auth/me",       methods=["OPTIONS"])
def _auth_preflight():
    resp   = Response("", status=204)
    origin = request.headers.get("Origin", "")
    if origin and origin in _ALLOWED_ORIGINS:
        resp.headers["Access-Control-Allow-Origin"]      = origin
        resp.headers["Access-Control-Allow-Credentials"] = "true"
        resp.headers["Access-Control-Allow-Methods"]     = "GET, POST, OPTIONS"
        resp.headers["Access-Control-Allow-Headers"]     = "Content-Type, Authorization"
        resp.headers["Access-Control-Max-Age"]           = "3600"
    return resp

# "" Alert ring-buffer cap """""""""""""""""""""""""""""""""""""""""
ALERTS_MAX_ENTRIES = 2000   # alerts.json is trimmed to this many entries

# "" Interface override file (public alias) """"""""""""""""""""""""
# _IFACE_OVERRIDE_FILE kept for backward compat; use IFACE_OVERRIDE_FILE in new code
IFACE_OVERRIDE_FILE = _IFACE_OVERRIDE_FILE

# "" Monitor PID file """"""""""""""""""""""""""""""""""""""""""""""
MONITOR_PID_FILE = os.path.join(BASE_DIR, ".monitor.pid")
