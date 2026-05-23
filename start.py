#!/usr/bin/env python3
<<<<<<< HEAD
import warnings
warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)
=======
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
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

    print("[1/3] Starting ARP spoof (intercept router traffic)...")
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

    print("[2/3] Starting live network monitor...")
    threading.Thread(target=start_monitor, daemon=True).start()
    time.sleep(1)

    print("[3/3] Starting web server (WebSocket enabled)...")
    print("\n  Home : http://localhost:5000/")
    print("  Dash : http://localhost:5000/dashboard\n")
    try:
        socketio.run(app, host="0.0.0.0", port=5000, debug=False, use_reloader=False)
    except KeyboardInterrupt:
        print("\nShutting down...")
        stop_spoofing()
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
