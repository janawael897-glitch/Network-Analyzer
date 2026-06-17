"""
socket_handlers.py – PacketGuard
Background threads: live monitor subprocess, auto-scan loop, live_update emitter.
Call init_socket_handlers() from app.py after all blueprints are registered.
"""

import os
import signal
import subprocess
import sys
import threading
import time
from config import BASE_DIR, socketio
from api_routes import run_network_scan_with_history, auto_scan_loop

# Paths
_PID_FILE       = os.path.join(BASE_DIR, ".monitor.pid")
_MONITOR_SCRIPT = "live_monitor.py"


def _start_baseline():
    try:
        from baseline_learning import start_baseline_thread
        start_baseline_thread()
    except Exception as e:
        print(f"[BASELINE] Could not start: {e}")


def _start_auto_response():
    pass   # auto_response thread started directly by app.py to avoid double-start


# ── 1. Kill any existing monitor processes ────────────────────────────────────
def _kill_existing_monitors():
    """Kill every live_monitor.py process before launching a fresh one.
    Uses PowerShell on Windows (WMIC is deprecated/broken on Win11)."""
    killed = []
    own_pid = os.getpid()

    def _taskkill(pid):
        subprocess.call(
            ["taskkill", "/PID", str(pid), "/F", "/T"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

    # Strategy A: kill PID saved in .monitor.pid
    if os.path.exists(_PID_FILE):
        try:
            with open(_PID_FILE) as _pf:
                old_pid = int(_pf.read().strip())
            if old_pid != own_pid:
                if sys.platform == "win32":
                    _taskkill(old_pid)
                else:
                    os.kill(old_pid, signal.SIGTERM)
                killed.append(old_pid)
                print(f"[LIVE-MONITOR] Killed monitor PID {old_pid}")
        except Exception:
            pass
        try:
            os.remove(_PID_FILE)
        except Exception:
            pass

    # Strategy B: PowerShell CimInstance scan (works on Win10/11, no WMIC needed)
    if sys.platform == "win32":
        try:
            ps_cmd = (
                "Get-CimInstance Win32_Process -Filter \"name='python.exe'\" "
                "| Select-Object ProcessId,CommandLine "
                "| ConvertTo-Json -Compress"
            )
            raw = subprocess.check_output(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                stderr=subprocess.DEVNULL, encoding="utf-8", errors="ignore", timeout=10,
            )
            import json as _j
            procs = _j.loads(raw) if raw.strip() else []
            if isinstance(procs, dict):
                procs = [procs]
            for p in procs:
                pid = int(p.get("ProcessId") or 0)
                cmd = str(p.get("CommandLine") or "")
                if pid and pid != own_pid and _MONITOR_SCRIPT in cmd and pid not in killed:
                    _taskkill(pid)
                    killed.append(pid)
                    print(f"[LIVE-MONITOR] Killed orphan monitor PID {pid}")
        except Exception as e:
            print(f"[LIVE-MONITOR] PowerShell scan failed: {e}")
    else:
        try:
            raw = subprocess.check_output(
                ["pgrep", "-f", _MONITOR_SCRIPT],
                stderr=subprocess.DEVNULL, encoding="utf-8",
            )
            for pid_str in raw.strip().splitlines():
                pid = int(pid_str)
                if pid != own_pid and pid not in killed:
                    os.kill(pid, signal.SIGTERM)
                    killed.append(pid)
                    print(f"[LIVE-MONITOR] Killed orphan monitor PID {pid}")
        except Exception:
            pass

    if killed:
        time.sleep(1.5)


# ── 2. Live monitor subprocess ────────────────────────────────────────────────
_HEARTBEAT_TTL = 30   # seconds; live_state.json must be newer than this

def _is_monitor_healthy() -> bool:
    """Return True only if the live_monitor is running AND wrote a DB heartbeat recently.
    Checks SQLite live_state table (last_updated column) — replaces the old live_state.json
    check after migrating live state to SQLite."""
    try:
        pid_file = os.path.join(BASE_DIR, ".monitor.pid")
        if not os.path.exists(pid_file):
            return False

        # Heartbeat check via SQLite: _rate_thread writes every second.
        # If the row is missing or last_updated is stale, the monitor has stopped.
        try:
            import sqlite3 as _sq, datetime as _dt
            db_path = os.path.join(BASE_DIR, "packetguard.db")
            conn = _sq.connect(db_path, timeout=2)
            row  = conn.execute(
                "SELECT last_updated FROM live_state WHERE id=1"
            ).fetchone()
            conn.close()
            if not row or not row[0]:
                return False
            last = _dt.datetime.fromisoformat(row[0])
            if last.tzinfo is None:
                last = last.replace(tzinfo=_dt.timezone.utc)
            age = (_dt.datetime.now(_dt.timezone.utc) - last).total_seconds()
            if age > _HEARTBEAT_TTL:
                return False
        except Exception:
            return False

        # PID existence check
        with open(pid_file) as _f:
            pid = int(_f.read().strip())

        if sys.platform == "win32":
            import json as _j
            raw = subprocess.check_output(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                 f"Get-CimInstance Win32_Process -Filter 'ProcessId={pid}' "
                 "| Select-Object Name,CommandLine | ConvertTo-Json -Compress"],
                stderr=subprocess.DEVNULL, encoding="utf-8", errors="ignore", timeout=6,
            )
            if not raw.strip():
                return False
            info = _j.loads(raw)
            if isinstance(info, list): info = info[0] if info else {}
            return ("python" in str(info.get("Name", "")).lower() and
                    "live_monitor" in str(info.get("CommandLine", "")))
        else:
            os.kill(pid, 0)
            return True
    except Exception:
        return False


def _auto_start_live_monitor():
    """
    Launch live_monitor.py subprocess if one is not already running.
    Guards prevent double-launch or recursive spawning.
    """
    # Guard 1: never recurse inside the monitor process itself
    if os.environ.get("PACKETGUARD_MONITOR_PROC") == "1":
        return
    # Guard 2: Werkzeug reloader child – only the parent launches
    if os.environ.get("WERKZEUG_RUN_MAIN") == "true":
        return

    # Guard 3: in-process capture already running (started directly by app.py)
    try:
        import live_monitor as _lm
        if _lm._state.get("running"):
            print("[LIVE-MONITOR] In-process capture active – skipping subprocess spawn.")
            return
    except Exception:
        pass

    # Guard 4: if a healthy monitor subprocess is already running, do nothing
    if _is_monitor_healthy():
        print("[LIVE-MONITOR] Already running – skipping launch.")
        return

    # Kill stale orphans before spawning a fresh one
    _kill_existing_monitors()

    try:
        monitor_path = os.path.join(BASE_DIR, _MONITOR_SCRIPT)
        if not os.path.exists(monitor_path):
            print(f"[LIVE-MONITOR] {_MONITOR_SCRIPT} not found at: {monitor_path}")
            return

        print("[LIVE-MONITOR] Launching fresh packet capture subprocess...")
        env = os.environ.copy()
        env["PACKETGUARD_MONITOR_PROC"] = "1"
        env["PYTHONUTF8"]               = "1"
        env["PYTHONIOENCODING"]         = "utf-8"

        log_path = os.path.join(BASE_DIR, "live_monitor.log")
        log_fh   = open(log_path, "a", encoding="utf-8", buffering=1)
        proc = subprocess.Popen(
            [sys.executable, "-X", "utf8", monitor_path],
            stdout=log_fh,
            stderr=log_fh,
            env=env,
            cwd=BASE_DIR,
            creationflags=(
                subprocess.CREATE_NEW_PROCESS_GROUP
                if sys.platform == "win32" else 0
            ),
        )
        print(f"[LIVE-MONITOR] PID {proc.pid} capturing - logs in live_monitor.log")

        # Record PID so next restart can kill it cleanly
        with open(_PID_FILE, "w") as pf:
            pf.write(str(proc.pid))

    except Exception as e:
        print(f"[LIVE-MONITOR] Could not launch subprocess: {e}")


# ── 3. First scan ─────────────────────────────────────────────────────────────
def _do_first_scan():
    run_network_scan_with_history()


# ── 4. Live update emitter ────────────────────────────────────────────────────
def _live_update_loop():
    """Read live state from SQLite every second and push to all dashboard clients."""
    print("[LIVE-EMITTER] Started – pushing live_update every second.")
    while True:
        try:
            from data_service import load_live_stats
            s = load_live_stats()
            socketio.emit("live_stats", {
                "rate":          s.get("rate", 0),
                "packets":       s.get("total_packets", 0),
                "total_packets": s.get("total_packets", 0),
                "bytes_per_sec": s.get("bytes_per_sec", 0),
                "protocols":     s.get("protocols", {}),
                "top_ips":       s.get("top_ips", {}),
                "alerts_total":  s.get("alerts_total", 0),
                "ml_detections": s.get("ml_detections", 0),
                "running":       s.get("running", False),
                "interface":     s.get("interface", ""),
                "runtime":       s.get("runtime_seconds", 0),
                "device_count":  None,
            })
        except Exception:
            pass
        time.sleep(1)


# ── 5. Public init ────────────────────────────────────────────────────────────
def init_socket_handlers():
    """
    Start all background threads.
    Call this once from app.py at module load time.
    """
    threading.Thread(
        target=_auto_start_live_monitor,
        daemon=True,
        name="LiveMonitor",
    ).start()

    threading.Thread(
        target=_do_first_scan,
        daemon=True,
        name="FirstScan",
    ).start()

    threading.Thread(
        target=auto_scan_loop,
        daemon=True,
        name="AutoScan",
    ).start()

    threading.Thread(
        target=_start_baseline,
        daemon=True,
        name="Baseline",
    ).start()

    threading.Thread(
        target=_start_auto_response,
        daemon=True,
        name="AutoResponse",
    ).start()

    threading.Thread(
        target=_live_update_loop,
        daemon=True,
        name="LiveEmitter",
    ).start()

    print("[SOCKET-HANDLERS] LiveMonitor, FirstScan, AutoScan, Baseline, AutoResponse, LiveEmitter threads started.")