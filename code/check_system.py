"""
check_system.py — PacketGuard System Health Check
Run from the code/ directory: python check_system.py
"""
import sys
import os
import json
import sqlite3
import socket
import urllib.request
import urllib.error

CODE_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = CODE_DIR   # config.py sets BASE_DIR = dirname(__file__), so DB is in code/
sys.path.insert(0, CODE_DIR)

# Disable ANSI colours on Windows unless the terminal supports them
_use_colour = sys.stdout.isatty() and os.name != 'nt'
PASS  = "\033[92m  [PASS]\033[0m" if _use_colour else "  [PASS]"
FAIL  = "\033[91m  [FAIL]\033[0m" if _use_colour else "  [FAIL]"
WARN  = "\033[93m  [WARN]\033[0m" if _use_colour else "  [WARN]"
INFO  = "\033[94m  [INFO]\033[0m" if _use_colour else "  [INFO]"

issues = []

def chk(label, ok, detail="", warn=False):
    tag = WARN if (warn and not ok) else (PASS if ok else FAIL)
    print(f"{tag} {label}" + (f"  ->  {detail}" if detail else ""))
    if not ok and not warn:
        issues.append(label)

print("\n+==================================================+")
print("|       PacketGuard -- System Health Check         |")
print("+==================================================+\n")

# ── 1. Python version ─────────────────────────────────────────────
v = sys.version_info
chk("Python version", v >= (3, 9), f"{v.major}.{v.minor}.{v.micro}")

# ── 2. Required packages ──────────────────────────────────────────
print("\n[ Dependencies ]")
packages = [
    ("flask",           "Flask"),
    ("flask_socketio",  "Flask-SocketIO"),
    ("scapy",           "Scapy"),
    ("numpy",           "NumPy"),
    ("sklearn",         "scikit-learn"),
    ("xgboost",         "XGBoost"),
    ("joblib",          "Joblib"),
    ("pandas",          "Pandas"),
    ("cryptography",    "Cryptography"),
]
for mod, name in packages:
    try:
        m = __import__(mod)
        ver = getattr(m, "__version__", "?")
        chk(name, True, ver)
    except ImportError:
        chk(name, False, "not installed")

# ── 3. Key project files ──────────────────────────────────────────
print("\n[ Project Files ]")
required_files = [
    (os.path.join(CODE_DIR, "app.py"),            "app.py"),
    (os.path.join(CODE_DIR, "config.py"),          "config.py"),
    (os.path.join(CODE_DIR, "live_monitor.py"),    "live_monitor.py"),
    (os.path.join(CODE_DIR, "ml_detector.py"),     "ml_detector.py"),
    (os.path.join(CODE_DIR, "api_routes.py"),      "api_routes.py"),
    (os.path.join(CODE_DIR, "data_service.py"),    "data_service.py"),
    (os.path.join(CODE_DIR, "auth_routes.py"),     "auth_routes.py"),
]
for path, name in required_files:
    chk(name, os.path.isfile(path))

# ── 4. ML models ──────────────────────────────────────────────────
print("\n[ ML Models ]")
models_dir = os.path.join(CODE_DIR, "models")
model_files = ["ensemble_model.pkl", "rf_model.pkl", "iso_model.pkl",
               "xgb_model.pkl", "scaler.pkl", "label_encoder.pkl", "feature_names.pkl"]
for mf in model_files:
    path = os.path.join(models_dir, mf)
    exists = os.path.isfile(path)
    size = f"{os.path.getsize(path)//1024} KB" if exists else ""
    chk(mf, exists, size, warn=True)

# ── 5. Database ───────────────────────────────────────────────────
print("\n[ Database ]")
db_path = os.path.join(BASE_DIR, "packetguard.db")
chk("packetguard.db exists", os.path.isfile(db_path))
if os.path.isfile(db_path):
    try:
        conn = sqlite3.connect(db_path, timeout=3)
        tables = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()]
        required_tables = ["users", "alerts", "sessions", "unblock_requests"]
        for t in required_tables:
            chk(f"  table: {t}", t in tables)
        alert_count = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        ml_count    = conn.execute("SELECT COUNT(*) FROM alerts WHERE is_ml=1").fetchone()[0]
        user_count  = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        print(f"{INFO} alerts in DB: {alert_count} (heuristic), {ml_count} (ML)")
        print(f"{INFO} registered users: {user_count}")
        conn.close()
    except Exception as e:
        chk("DB accessible", False, str(e))

# ── 6. Config / environment ───────────────────────────────────────
print("\n[ Config ]")
try:
    from config import SMTP_EMAIL, SMTP_PASSWORD
    chk("SMTP configured", bool(SMTP_EMAIL) and bool(SMTP_PASSWORD),
        SMTP_EMAIL if SMTP_EMAIL else "not set", warn=True)
except Exception as e:
    chk("config.py import", False, str(e))

# ── 7. App running (port 5000) ────────────────────────────────────
print("\n[ Running App ]")
app_running = False
try:
    with socket.create_connection(("127.0.0.1", 5000), timeout=2):
        app_running = True
except OSError:
    pass
chk("App listening on port 5000", app_running,
    "app is running" if app_running else "start with: python app.py")

if app_running:
    # Check /api/monitor/status
    try:
        req = urllib.request.Request(
            "http://127.0.0.1:5000/api/monitor/status",
            headers={"Accept": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read())
        running = data.get("running", False)
        chk("Live monitor running", running,
            f"interface: {data.get('interface','?')}" if running else "not capturing")
        # /api/monitor/status now returns ml.ready; also try /api/ml_status
        # which forces the detector to load if not already loaded.
        ml_ready = data.get("ml", {}).get("ready", False)
        if not ml_ready:
            try:
                req2 = urllib.request.Request(
                    "http://127.0.0.1:5000/api/ml_status",
                    headers={"Accept": "application/json"}
                )
                with urllib.request.urlopen(req2, timeout=10) as resp2:
                    ml_data = json.loads(resp2.read())
                ml_ready = ml_data.get("ready", False)
            except Exception:
                pass
        chk("ML detector ready", ml_ready, warn=True)
    except Exception as e:
        chk("API /api/monitor/status", False, str(e))

# ── 8. Own-IP exclusion sanity check ─────────────────────────────
print("\n[ False-Positive Guard ]")
try:
    own_ips = {"127.0.0.1", "::1", "0.0.0.0", "localhost"}
    hostname = socket.gethostname()
    for info in socket.getaddrinfo(hostname, None):
        own_ips.add(info[4][0])
    real = [ip for ip in own_ips if ip not in {"127.0.0.1","::1","0.0.0.0","localhost"}]
    chk("Own-IP list built", bool(real), f"machine IPs: {', '.join(real)}")
except Exception as e:
    chk("Own-IP detection", False, str(e))

# ── Summary ───────────────────────────────────────────────────────
print("\n" + "-" * 52)
if not issues:
    msg = "\033[92m  All checks passed -- system is ready.\033[0m" if _use_colour else "  All checks passed -- system is ready."
    print(msg)
else:
    hdr = "\033[91m" if _use_colour else ""
    end = "\033[0m"  if _use_colour else ""
    print(f"{hdr}  {len(issues)} issue(s) found:{end}")
    for i in issues:
        print(f"{hdr}    * {i}{end}")
print()
