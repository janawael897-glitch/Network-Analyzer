#!/usr/bin/env python3
<<<<<<< HEAD
<<<<<<< HEAD
import warnings
warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)
=======
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
=======
import warnings
warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", category=FutureWarning)

# Override showwarning so joblib/sklearn worker-thread warnings (which bypass
# filterwarnings because they use stacklevel>1) are also silenced.
def _silent_showwarning(message, category, filename, lineno, file=None, line=None):
    pass
warnings.showwarning = _silent_showwarning
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
"""
start.py - PacketGuard Master Launcher
Run from project root as Administrator: python start.py

Home page  : http://localhost:5000/
Dashboard  : http://localhost:5000/dashboard
"""
import sys
import os
import threading
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE_DIR, "code"))

<<<<<<< HEAD
<<<<<<< HEAD
# Reset live_state.json counters before anything loads
import json as _json
_live_state_path = os.path.join(BASE_DIR, "live_state.json")
try:
    _prev_alerts = []
    if os.path.exists(_live_state_path):
        try:
            with open(_live_state_path, "r", encoding="utf-8") as _f:
                _old = _json.load(_f)
            _prev_alerts = _old.get("recent_alerts", [])
        except Exception:
            pass
    with open(_live_state_path, "w", encoding="utf-8") as _f:
        _json.dump({
            "total_packets": 0, "rate": 0.0, "bytes_total": 0,
            "runtime_seconds": 0, "running": False,
            "protocols": {}, "top_ips": {},
            "recent_alerts": _prev_alerts,
            "last_updated": None,
        }, _f, indent=2)
    print("[INIT] Packet counters reset to 0")
except Exception as _e:
    print(f"[INIT] Could not reset live_state.json: {_e}")

# Import app AND socketio from web_dashboard
from web_dashboard import app, socketio
from arp_spoof import start_spoofing, stop_spoofing
=======
# Import the existing Flask app
from web_dashboard import app
from flask import Response

TEMPLATES = os.path.join(BASE_DIR, "templates")

def read_html(name):
    path = os.path.join(TEMPLATES, name)
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return f"<h1>File not found: templates/{name}</h1><p>Put {name} in the templates folder.</p>"

# Override the routes to serve from templates folder
app.view_functions["home"]      = lambda: Response(read_html("index.html"),   mimetype="text/html")
app.view_functions["monitor"]   = lambda: Response(read_html("monitor.html"), mimetype="text/html")
app.view_functions["dashboard"] = lambda: Response(read_html("dashboard.html"), mimetype="text/html")
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b

def start_monitor():
    try:
        import live_monitor
        live_monitor.start_monitoring()
    except Exception as e:
        print(f"\n[MONITOR] Could not start: {e}")
=======
# Preserve live_state.json — do NOT wipe it on startup.
# live_monitor will set running=True and write real data within seconds.
import json as _json
_live_state_path = os.path.join(BASE_DIR, "live_state.json")
try:
    if not os.path.exists(_live_state_path):
        with open(_live_state_path, "w", encoding="utf-8") as _f:
            _json.dump({
                "total_packets": 0, "rate": 0.0, "bytes_total": 0,
                "runtime_seconds": 0, "running": False,
                "protocols": {}, "top_ips": {},
                "recent_alerts": [], "last_updated": None,
            }, _f, indent=2)
        print("[INIT] Created fresh live_state.json")
    else:
        print("[INIT] Preserving existing live_state.json")
except Exception as _e:
    print(f"[INIT] live_state.json check failed: {_e}")

# Import app AND socketio from app.py (app.py starts monitoring automatically on import)
from app import app, socketio
from arp_spoof import start_spoofing, stop_spoofing

def _start_mail_worker():
    """
    Start mail_worker.py as a non-elevated process so it can reach Gmail SMTP.
    Uses Windows Task Scheduler (/rl limited) to de-elevate even though start.py
    runs as Administrator.
    """
    import subprocess, datetime
    worker = os.path.join(BASE_DIR, "mail_worker.py")
    python = sys.executable
    task   = "PacketGuard-MailWorker"

    # Kill any previous instance
    subprocess.run(["schtasks", "/end",    "/tn", task], capture_output=True)
    subprocess.run(["schtasks", "/delete", "/tn", task, "/f"], capture_output=True)

    # Schedule one-time task starting 1 minute from now (time is ignored — we /run it)
    start_time = (datetime.datetime.now() + datetime.timedelta(minutes=1)).strftime("%H:%M")
    create = subprocess.run([
        "schtasks", "/create",
        "/tn", task,
        "/tr", f'"{python}" "{worker}"',
        "/sc", "once", "/st", start_time,
        "/rl", "limited",   # non-elevated — can reach Gmail SMTP
        "/f",
    ], capture_output=True, text=True)

    if create.returncode != 0:
        print(f"[MAIL] Could not register mail worker ({create.stderr.strip()})")
        print("[MAIL] If OTP emails don't arrive, run in a separate terminal: python mail_worker.py")
        return

    subprocess.run(["schtasks", "/run", "/tn", task], capture_output=True)
    print("[MAIL] Mail worker started (non-elevated — Gmail SMTP active)")

>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)

if __name__ == "__main__":
    print("""
+===========================================================+
|   PacketGuard  --  Network Threat Detection System        |
|   Home page  : http://localhost:5000/                     |
|   Dashboard  : http://localhost:5000/dashboard            |
|   Press Ctrl+C to stop                                    |
+===========================================================+
    """)
<<<<<<< HEAD
<<<<<<< HEAD

    print("[1/3] Starting ARP spoof (intercept router traffic)...")
=======

    print("[1/4] Starting mail worker (non-elevated Gmail sender)...")
    _start_mail_worker()

    print("[2/4] Starting ARP spoof (intercept router traffic)...")
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
    # ↓ Change "192.168.1" to match YOUR subnet (run: ipconfig)
    spoof_result = [False]
    def run_spoof():
        spoof_result[0] = start_spoofing("192.168.1")

    spoof_thread = threading.Thread(target=run_spoof, daemon=True)
    spoof_thread.start()
    print("[ARP] Running ping sweep — this takes ~15 seconds...")
    spoof_thread.join(timeout=60)  # wait up to 60s for ping sweep to finish

    if spoof_result[0]:
        print("[ARP] Spoof active — capturing all LAN traffic")
    else:
        print("[ARP] WARNING: Spoof failed — capturing only this PC's traffic")

<<<<<<< HEAD
    print("[2/3] Starting live network monitor...")
    threading.Thread(target=start_monitor, daemon=True).start()
    time.sleep(1)

    print("[3/3] Starting web server (WebSocket enabled)...")
=======
    print("[3/4] Network monitor starts automatically with the web server...")

    print("[4/4] Starting web server (WebSocket enabled)...")
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
    print("\n  Home : http://localhost:5000/")
    print("  Dash : http://localhost:5000/dashboard\n")
    try:
        socketio.run(app, host="0.0.0.0", port=5000, debug=False, use_reloader=False)
    except KeyboardInterrupt:
        print("\nShutting down...")
        stop_spoofing()
<<<<<<< HEAD
        sys.exit(0)
=======
    print("[1/2] Starting live network monitor...")
    threading.Thread(target=start_monitor, daemon=True).start()
    time.sleep(1)
    print("[2/2] Starting web server...")
    print("\n  Home : http://localhost:5000/")
    print("  Dash : http://localhost:5000/dashboard\n")
    try:
        app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)
    except KeyboardInterrupt:
        print("\nShutting down...")
        sys.exit(0)
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
=======
        import subprocess as _sp
        _sp.run(["schtasks", "/end",    "/tn", "PacketGuard-MailWorker"], capture_output=True)
        _sp.run(["schtasks", "/delete", "/tn", "PacketGuard-MailWorker", "/f"], capture_output=True)
        sys.exit(0)
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
