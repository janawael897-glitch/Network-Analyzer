#!/usr/bin/env python3
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
