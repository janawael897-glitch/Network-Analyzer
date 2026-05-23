#!/usr/bin/env python3
"""
<<<<<<< HEAD
live_monitor.py — PacketGuard Live Network Traffic Monitor
===========================================================
v2 — Intelligent Trust Scoring Integration

Changes:
  - handle_packet() now feeds alerts through the trust-aware pipeline:
      alert → alert_dedup → correlation_engine_v2 → block_manager (trust gate)
  - ML alerts are NEVER directly routed to firewall_enforcer.evaluate_for_block().
    They go to the correlation engine and accumulate evidence.  Only when
    correlation confidence + persistence + multi-indicator threshold is met
    does the trust scorer permit enforcement.
  - Detector thresholds for port_scan, syn_flood, high_rate are kept
    at sensitive levels (good detection) but the enforcement gate in
    block_manager filters out false positives.
"""

import os
import sys
import warnings
if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    try: sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception: pass
if sys.stderr and hasattr(sys.stderr, 'reconfigure'):
    try: sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception: pass
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

import json
import time
import threading
from datetime import datetime, timezone
from collections import defaultdict, deque

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def _best_interface() -> str:
    try:
        import psutil
        from scapy.all import conf as _scapy_conf
        stats = psutil.net_if_stats()
        addrs = psutil.net_if_addrs()
        candidates = []
        for iface, iaddrs in addrs.items():
            if not stats.get(iface, None) or not stats[iface].isup:
                continue
            for addr in iaddrs:
                import socket as _socket
                if addr.family != _socket.AF_INET:
                    continue
                ip = addr.address
                parts = ip.split(".")
                if ip.startswith("127.") or ip == "0.0.0.0":
                    continue
                if (parts[0] == "10" or parts[0] == "172" or
                        (parts[0] == "192" and parts[1] == "168")):
                    candidates.append((iface, ip, stats[iface].speed))
        if candidates:
            best = max(candidates, key=lambda x: x[2])
            return best[0]
        return str(_scapy_conf.iface)
    except Exception:
        try:
            from scapy.all import conf as _scapy_conf
            return str(_scapy_conf.iface)
        except Exception:
            return "eth0"

CAPTURE_IFACE = _best_interface()

def _push_alert(alert: dict):
    if os.environ.get("PACKETGUARD_MONITOR_PROC") == "1":
        return
    try:
        import web_dashboard as _wd
        _wd.push_alert(alert)
    except Exception as _push_err:
        log.debug(f"[PUSH] push_alert failed: {_push_err}")


def _push_stats(stats: dict):
    if os.environ.get("PACKETGUARD_MONITOR_PROC") == "1":
        return
    try:
        import web_dashboard as _wd
        _wd.push_live_stats(stats)
    except Exception as _push_err:
        log.debug(f"[PUSH] push_stats failed: {_push_err}")


LIVE_STATE_FILE = os.path.join(BASE_DIR, "live_state.json")
ALERTS_FILE     = os.path.join(BASE_DIR, "alerts.json")      # kept for fallback migration only
ML_ALERTS_FILE  = os.path.join(BASE_DIR, "ml_alerts.json")   # kept for fallback migration only
DB_PATH         = os.path.join(BASE_DIR, "packetguard.db")
LOG_FILE        = os.path.join(BASE_DIR, "live_monitor.log")

sys.path.insert(0, os.path.join(BASE_DIR, "code"))

_ensure_alerts_table_called = False

def _init_alerts_db():
    global _ensure_alerts_table_called
    if not _ensure_alerts_table_called:
        _ensure_alerts_table()
        _ensure_alerts_table_called = True

=======
Live Network Traffic Monitor
Captures packets in real-time and writes stats to live_state.json
so the dashboard updates every 2 seconds automatically.

Run via: python start.py  (recommended)
Or standalone: python code/live_monitor.py
"""

import json
import os
import sys
import time
import logging
import threading
from datetime import datetime
from collections import defaultdict, deque

BASE_DIR        = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LIVE_STATE_FILE = os.path.join(BASE_DIR, "live_state.json")
ALERTS_FILE     = os.path.join(BASE_DIR, "alerts.json")
ML_ALERTS_FILE  = os.path.join(BASE_DIR, "ml_alerts.json")
LOG_FILE        = os.path.join(BASE_DIR, "live_monitor.log")

# Add code dir to path so ml_detector can be imported
sys.path.insert(0, os.path.join(BASE_DIR, "code"))

>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ]
)
log = logging.getLogger(__name__)

<<<<<<< HEAD
_ml = None

def _wire_ml_detector():
    global _ml
    try:
        from ml_detector import get_detector as _get_ml_detector
        det = _get_ml_detector()

        def _ml_on_alert(alert):
            if alert is None:
                return
            try:
                with state_lock:
                    state["ml_recent_alerts"].insert(0, alert)
                    state["ml_recent_alerts"] = state["ml_recent_alerts"][:20]
                    state["ml_total"] = state.get("ml_total", 0) + 1
                # ML alerts go to dedup → correlation only.
                # They do NOT directly trigger evaluate_for_block.
                save_alert(alert)
                _push_alert(alert)
                log.warning(f"[ML] {alert.get('alert_type')} - {alert.get('message','')}")
            except Exception as e:
                log.error(f"[ML] on_alert state update error: {e}")

        det.on_alert = _ml_on_alert
        _ml = det
        if det.ready:
            st = det.status()
            log.info(f"[ML] Detector ready. Models: {st['models_loaded']} | "
                     f"Threshold: {st['iso_threshold']:.3f} | MinConf: {st['min_conf']}")
        else:
            log.info("[ML] Models not found — auto-training started in background.")
    except Exception as _e:
        log.warning(f"[ML] ML detector not available: {_e}")

_wire_ml_detector()


def _load_previous_alerts():
    try:
        if os.path.exists(LIVE_STATE_FILE):
            with open(LIVE_STATE_FILE, "r", encoding="utf-8") as f:
                prev = json.load(f)
            return {
                "recent_alerts":    prev.get("recent_alerts", []),
                "ml_recent_alerts": prev.get("ml_recent_alerts", []),
            }
    except Exception:
        pass
    return {}

_prev = _load_previous_alerts()
=======
# Load ML detector (silently if model not trained yet)
try:
    from ml_detector import get_detector as _get_ml_detector
    _ml = _get_ml_detector()
    if _ml.ready:
        log.info("[ML] Isolation Forest model loaded and ready.")
    else:
        log.info("[ML] No trained model yet. Run: python code/train_ml.py")
except Exception as _e:
    _ml = None
    log.info(f"[ML] ML detector not available: {_e}")

# Shared state
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
state = {
    "running": False,
    "start_time": None,
    "total_packets": 0,
    "rate": 0.0,
    "runtime_seconds": 0,
    "protocols": {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0},
    "top_ips": {},
<<<<<<< HEAD
    "recent_alerts":    _prev.get("recent_alerts", []),
    "ml_recent_alerts": _prev.get("ml_recent_alerts", []),
=======
    "recent_alerts": [],
    "ml_recent_alerts": [],
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
    "ml_total": 0,
    "bytes_total": 0,
    "last_updated": None,
}
<<<<<<< HEAD
state_lock        = threading.Lock()
packet_timestamps = deque(maxlen=500)
_save_state_lock  = threading.Lock()


def _write_json_safe(path, data):
    if sys.platform == "win32":
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
    else:
        import uuid
        tmp = path + "." + uuid.uuid4().hex + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        os.replace(tmp, path)
=======
state_lock = threading.Lock()
packet_timestamps = deque(maxlen=500)
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b


def save_state():
    with state_lock:
        data = dict(state)
        data["top_ips"] = dict(
            sorted(data["top_ips"].items(), key=lambda x: x[1], reverse=True)[:10]
        )
<<<<<<< HEAD
    with _save_state_lock:
        try:
            _write_json_safe(LIVE_STATE_FILE, data)
        except Exception as e:
            log.error(f"Could not save state: {e}")


def save_ml_alert(alert):
    """Save ML alert to SQLite (and JSON as backup)."""
    try:
        conn = _db_conn()
        _insert_alert(conn, alert)
        conn.commit()
        conn.close()
    except Exception as e:
        log.error(f"Could not save ML alert to DB: {e}")
        # Fallback to JSON
        try:
            existing = []
            if os.path.exists(ML_ALERTS_FILE):
                with open(ML_ALERTS_FILE, "r", encoding="utf-8") as f:
                    existing = json.load(f)
            existing.append(alert)
            with open(ML_ALERTS_FILE, "w", encoding="utf-8") as f:
                json.dump(existing, f, indent=2, default=str)
        except Exception as e2:
            log.error(f"Could not save ML alert to JSON either: {e2}")


def _db_conn():
    import sqlite3 as _sq
    conn = _sq.connect(DB_PATH, timeout=10)
    conn.row_factory = _sq.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def _ensure_alerts_table():
    """Create alerts table if it does not exist, and migrate JSON data once."""
    conn = _db_conn()
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
    # One-time migration from alerts.json if table is empty
    count = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    if count == 0 and os.path.exists(ALERTS_FILE):
        try:
            with open(ALERTS_FILE, "r", encoding="utf-8") as _f:
                old_alerts = json.load(_f)
            for a in old_alerts:
                _insert_alert(conn, a)
            conn.commit()
            log.info(f"[DB] Migrated {len(old_alerts)} alerts from alerts.json to SQLite")
        except Exception as _me:
            log.warning(f"[DB] Migration failed: {_me}")
    conn.close()


def _insert_alert(conn, alert):
    import json as _json
    known = {"alert_type","severity","source_ip","dest_ip","destination_ip","message","timestamp"}
    extra = {k: v for k, v in alert.items() if k not in known}
    conn.execute(
        "INSERT INTO alerts (alert_type,severity,source_ip,dest_ip,message,timestamp,extra) VALUES (?,?,?,?,?,?,?)",
        (
            alert.get("alert_type"),
            alert.get("severity"),
            alert.get("source_ip"),
            alert.get("dest_ip") or alert.get("destination_ip"),
            alert.get("message"),
            alert.get("timestamp"),
            _json.dumps(extra, default=str) if extra else None,
        )
    )


def load_existing_alerts():
    """Load all alerts from SQLite. Falls back to JSON if DB unavailable."""
    try:
        conn = _db_conn()
        rows = conn.execute(
            "SELECT * FROM alerts ORDER BY id ASC"
        ).fetchall()
        conn.close()
        import json as _json
        result = []
        for r in rows:
            a = dict(r)
            if a.get("extra"):
                try: a.update(_json.loads(a["extra"]))
                except: pass
            a.pop("extra", None)
            a.pop("id", None)
            result.append(a)
        return result
    except Exception as _e:
        log.warning(f"[DB] load_existing_alerts fallback to JSON: {_e}")
        try:
            with open(ALERTS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []


_alerts_lock = threading.Lock()

def save_alert(alert):
    """Route alert through dedup engine, then persist to SQLite."""
    try:
        from alert_dedup import ingest as _dedup_ingest
        _dedup_ingest(alert)
        return
    except ImportError:
        pass
    with _alerts_lock:
        try:
            conn = _db_conn()
            _insert_alert(conn, alert)
            conn.commit()
            conn.close()
        except Exception as e:
            log.error(f"Could not save alert to DB: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# Detectors
# ─────────────────────────────────────────────────────────────────────────────

class PortScanDetector:
    def __init__(self, threshold=5, window=60):
        self.threshold = threshold
        self.window    = window
        self.records   = defaultdict(list)

    def check(self, src_ip, dst_port, ts):
        self.records[src_ip].append((dst_port, ts))
        self.records[src_ip] = [
            (p, t) for p, t in self.records[src_ip] if ts - t < self.window
        ]
        unique_ports = len(set(p for p, t in self.records[src_ip]))
        if unique_ports >= self.threshold:
            return {
                "timestamp":      datetime.now(timezone.utc).isoformat(),
                "alert_type":     "PORT_SCAN",
                "severity":       "HIGH",
                "message":        f"Port scan from {src_ip}: {unique_ports} unique ports in {self.window}s",
                "source_ip":      src_ip,
=======
    try:
        with open(LIVE_STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
    except Exception as e:
        log.error(f"Could not save state: {e}")


def save_ml_alert(alert):
    """Append ML alert to ml_alerts.json."""
    try:
        existing = []
        if os.path.exists(ML_ALERTS_FILE):
            with open(ML_ALERTS_FILE, "r", encoding="utf-8") as f:
                existing = json.load(f)
        existing.append(alert)
        with open(ML_ALERTS_FILE, "w", encoding="utf-8") as f:
            json.dump(existing, f, indent=2, default=str)
    except Exception as e:
        log.error(f"Could not save ML alert: {e}")


def load_existing_alerts():
    try:
        with open(ALERTS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def save_alert(alert):
    alerts = load_existing_alerts()
    alerts.append(alert)
    try:
        with open(ALERTS_FILE, "w", encoding="utf-8") as f:
            json.dump(alerts, f, indent=2, default=str)
    except Exception as e:
        log.error(f"Could not save alert: {e}")


# Detectors
class PortScanDetector:
    def __init__(self, threshold=20, window=60):
        self.threshold = threshold
        self.window = window
        self.records = defaultdict(list)

    def check(self, src_ip, dst_port, ts):
        self.records[src_ip].append((dst_port, ts))
        self.records[src_ip] = [(p, t) for p, t in self.records[src_ip] if ts - t < self.window]
        unique_ports = len(set(p for p, t in self.records[src_ip]))
        if unique_ports >= self.threshold:
            return {
                "timestamp": datetime.utcnow().isoformat(),
                "alert_type": "PORT_SCAN",
                "severity": "HIGH",
                "message": f"Port scan from {src_ip}: {unique_ports} unique ports in {self.window}s",
                "source_ip": src_ip,
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
                "destination_ip": "N/A",
                "additional_info": {"ports_scanned": unique_ports},
            }
        return None


class SynFloodDetector:
<<<<<<< HEAD
    def __init__(self, threshold=20, window=10):
        self.threshold = threshold
        self.window    = window
        self.records   = defaultdict(list)
=======
    def __init__(self, threshold=100, window=10):
        self.threshold = threshold
        self.window = window
        self.records = defaultdict(list)
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b

    def check(self, dst_ip, ts):
        self.records[dst_ip].append(ts)
        self.records[dst_ip] = [t for t in self.records[dst_ip] if ts - t < self.window]
        count = len(self.records[dst_ip])
        if count >= self.threshold:
            return {
<<<<<<< HEAD
                "timestamp":      datetime.now(timezone.utc).isoformat(),
                "alert_type":     "SYN_FLOOD",
                "severity":       "CRITICAL",
                "message":        f"SYN flood targeting {dst_ip}: {count} SYN pkts in {self.window}s",
                "source_ip":      "Multiple",
=======
                "timestamp": datetime.utcnow().isoformat(),
                "alert_type": "SYN_FLOOD",
                "severity": "CRITICAL",
                "message": f"SYN flood targeting {dst_ip}: {count} SYN pkts in {self.window}s",
                "source_ip": "Multiple",
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
                "destination_ip": dst_ip,
                "additional_info": {"syn_count": count},
            }
        return None


class LargePacketDetector:
    def check(self, src_ip, dst_ip, size):
        if size > 9000:
            return {
<<<<<<< HEAD
                "timestamp":      datetime.now(timezone.utc).isoformat(),
                "alert_type":     "ABNORMAL_SIZE",
                "severity":       "MEDIUM",
                "message":        f"Abnormally large packet: {size} bytes from {src_ip}",
                "source_ip":      src_ip,
=======
                "timestamp": datetime.utcnow().isoformat(),
                "alert_type": "ABNORMAL_SIZE",
                "severity": "MEDIUM",
                "message": f"Abnormally large packet: {size} bytes from {src_ip}",
                "source_ip": src_ip,
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
                "destination_ip": dst_ip,
                "additional_info": {"packet_size": size},
            }
        return None


class HighRateDetector:
<<<<<<< HEAD
    def __init__(self, threshold=30, window=5):
        self.threshold = threshold
        self.window    = window
        self.records   = defaultdict(list)
        self.alerted   = set()
=======
    def __init__(self, threshold=200, window=5):
        self.threshold = threshold
        self.window = window
        self.records = defaultdict(list)
        self.alerted = set()
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b

    def check(self, src_ip, ts):
        self.records[src_ip].append(ts)
        self.records[src_ip] = [t for t in self.records[src_ip] if ts - t < self.window]
        rate = len(self.records[src_ip]) / self.window
        if rate >= self.threshold and src_ip not in self.alerted:
            self.alerted.add(src_ip)
            return {
<<<<<<< HEAD
                "timestamp":      datetime.now(timezone.utc).isoformat(),
                "alert_type":     "HIGH_PACKET_RATE",
                "severity":       "HIGH",
                "message":        f"High packet rate from {src_ip}: {rate:.0f} pkt/s",
                "source_ip":      src_ip,
=======
                "timestamp": datetime.utcnow().isoformat(),
                "alert_type": "HIGH_PACKET_RATE",
                "severity": "HIGH",
                "message": f"High packet rate from {src_ip}: {rate:.0f} pkt/s",
                "source_ip": src_ip,
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
                "destination_ip": "N/A",
                "additional_info": {"rate": rate},
            }
        elif rate < self.threshold:
            self.alerted.discard(src_ip)
        return None


<<<<<<< HEAD
port_scan_det = PortScanDetector(threshold=5, window=60)
syn_flood_det = SynFloodDetector(threshold=20, window=10)
large_pkt_det = LargePacketDetector()
high_rate_det = HighRateDetector(threshold=30, window=5)

_cooldown = {}
COOLDOWN  = 60
=======
port_scan_det = PortScanDetector(threshold=5, window=60)   # 5 unique ports = alert (was 20)
syn_flood_det = SynFloodDetector(threshold=20, window=10)  # 20 SYN pkts = alert (was 100)
large_pkt_det = LargePacketDetector()
high_rate_det = HighRateDetector(threshold=30, window=5)   # 30 pkt/s = alert (was 200)

_cooldown = {}
COOLDOWN = 15  # was 30 — fire same alert again after 15s
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b


def should_alert(key):
    now = time.time()
    if key not in _cooldown or now - _cooldown[key] > COOLDOWN:
        _cooldown[key] = now
        return True
    return False


<<<<<<< HEAD
# ─────────────────────────────────────────────────────────────────────────────
# Packet handler
# ─────────────────────────────────────────────────────────────────────────────

=======
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
def handle_packet(pkt):
    try:
        from scapy.layers.inet import IP, TCP, UDP, ICMP
        now = time.time()
        packet_timestamps.append(now)

        with state_lock:
            state["total_packets"] += 1
<<<<<<< HEAD
            state["bytes_total"]   += len(pkt)
            state["last_updated"]   = datetime.now(timezone.utc).isoformat()

            if pkt.haslayer(TCP):    state["protocols"]["TCP"]   += 1
            elif pkt.haslayer(UDP):  state["protocols"]["UDP"]   += 1
            elif pkt.haslayer(ICMP): state["protocols"]["ICMP"]  += 1
            else:                    state["protocols"]["Other"] += 1
=======
            state["bytes_total"] += len(pkt)
            state["last_updated"] = datetime.utcnow().isoformat()

            if pkt.haslayer(TCP):   state["protocols"]["TCP"] += 1
            elif pkt.haslayer(UDP): state["protocols"]["UDP"] += 1
            elif pkt.haslayer(ICMP):state["protocols"]["ICMP"] += 1
            else:                   state["protocols"]["Other"] += 1
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b

            if pkt.haslayer(IP):
                src = pkt[IP].src
                state["top_ips"][src] = state["top_ips"].get(src, 0) + 1

        alert = None
        if pkt.haslayer(IP):
<<<<<<< HEAD
            src  = pkt[IP].src
            dst  = pkt[IP].dst
=======
            src = pkt[IP].src
            dst = pkt[IP].dst
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
            size = len(pkt)

            a = large_pkt_det.check(src, dst, size)
            if a and should_alert(f"SIZE_{src}"):
                alert = a

            a = high_rate_det.check(src, now)
            if a and should_alert(f"RATE_{src}"):
                alert = a

            if pkt.haslayer(TCP):
                flags = pkt[TCP].flags
                dport = pkt[TCP].dport

                a = port_scan_det.check(src, dport, now)
                if a and should_alert(f"SCAN_{src}"):
                    alert = a

                if flags & 0x02 and not (flags & 0x10):
                    a = syn_flood_det.check(dst, now)
                    if a and should_alert(f"SYN_{dst}"):
                        alert = a

        if alert:
<<<<<<< HEAD
            save_alert(alert)   # → dedup → correlation
            with state_lock:
                state["recent_alerts"].insert(0, alert)
                state["recent_alerts"] = state["recent_alerts"][:20]
            _push_alert(alert)
            log.warning(f"[ALERT] {alert['alert_type']} - {alert['message']}")

            # Feed correlation engine v2
            try:
                from correlation_engine_v2 import feed_alert as _corr_feed
                _corr_feed(alert)
            except ImportError:
                pass

            # ── IMPORTANT: Non-ML alerts route through block_manager (trust gate) ──
            # ML alerts are handled exclusively via the correlation engine above.
            # evaluate_for_block in firewall_enforcer now also routes through block_manager.
            atype = alert.get("alert_type", "")
            if not atype.startswith("ML_"):
                try:
                    from firewall_enforcer import evaluate_for_block as _fw_eval
                    _fw_eval(alert)
                except ImportError:
                    pass

        # ML scoring — feed into flow aggregator; on_alert callback routes to dedup + correlation
        if _ml and _ml.ready:
            try:
                _ml.score_packet(pkt)
            except Exception as _ml_err:
                log.error(f"[ML] score_packet error: {_ml_err}", exc_info=True)

    except Exception as _pkt_err:
        log.error(f"[PKT] handle_packet error: {_pkt_err}", exc_info=True)


RESET_INTERVAL = 48 * 60 * 60

def _reset_counters():
    with state_lock:
        state["total_packets"]  = 0
        state["bytes_total"]    = 0
        state["ml_total"]       = 0
        state["protocols"]      = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}
        state["top_ips"]        = {}
    packet_timestamps.clear()
    log.info("[RESET] 48-hour counter reset")


def stats_loop():
    start      = time.time()
    last_reset = time.time()
    while True:
        time.sleep(1)
        now = time.time()
        if now - last_reset >= RESET_INTERVAL:
            _reset_counters()
            last_reset = now
        recent = [t for t in packet_timestamps if now - t <= 5]
        rate   = len(recent) / 5.0
        with state_lock:
            state["rate"]            = round(rate, 2)
            state["runtime_seconds"] = int(now - start)
        save_state()
        _push_stats({
            "total_packets":   state["total_packets"],
            "rate":            state["rate"],
            "bytes_total":     state["bytes_total"],
            "runtime_seconds": state["runtime_seconds"],
            "protocols":       dict(state["protocols"]),
            "ml_total":        state.get("ml_total", 0),
        })
        total = state["total_packets"]
        if total > 0 and total % 100 == 0:
            ml_total  = state.get("ml_total", 0)
            ml_status = "ready" if (_ml and _ml.ready) else "NOT READY"
            log.info(f"[STATS] Processed {total} packets ({rate:.2f} pkt/s) "
                     f"| ML={ml_status} | ML alerts={ml_total}")


_stats_thread = threading.Thread(target=stats_loop, daemon=True, name="StatsLoop")
_stats_thread.start()


def start_monitoring():
    _init_alerts_db()   # ensure SQLite alerts table exists + migrate JSON
=======
            save_alert(alert)
            with state_lock:
                state["recent_alerts"].insert(0, alert)
                state["recent_alerts"] = state["recent_alerts"][:20]
            log.warning(f"[ALERT] {alert['alert_type']} - {alert['message']}")

        # ML scoring (runs every packet if model is loaded)
        if _ml and _ml.ready:
            ml_alert = _ml.score_packet(pkt)
            if ml_alert and should_alert(f"ML_{ml_alert.get('source_ip','?')}"):
                save_ml_alert(ml_alert)
                with state_lock:
                    state["ml_recent_alerts"].insert(0, ml_alert)
                    state["ml_recent_alerts"] = state["ml_recent_alerts"][:20]
                    state["ml_total"] = state.get("ml_total", 0) + 1
                log.warning(f"[ML] {ml_alert['alert_type']} - {ml_alert['message']}")

    except Exception:
        pass


def stats_loop():
    start = time.time()
    while state["running"]:
        time.sleep(1)
        now = time.time()
        recent = [t for t in packet_timestamps if now - t <= 5]
        rate = len(recent) / 5.0
        with state_lock:
            state["rate"] = round(rate, 2)
            state["runtime_seconds"] = int(now - start)
        save_state()
        total = state["total_packets"]
        if total > 0 and total % 100 == 0:
            log.info(f"[STATS] Processed {total} packets ({rate:.2f} pkt/s)")


def start_monitoring():
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
    try:
        from scapy.all import sniff
    except ImportError:
        log.error("Scapy not installed. Run: pip install scapy")
        sys.exit(1)

    log.info("[START] Starting live network monitoring...")
<<<<<<< HEAD
    log.info(f"[NET]   Interface: {CAPTURE_IFACE} (auto-selected)")
    log.info("        Press Ctrl+C to stop")

    with state_lock:
        state["running"]    = True
        state["start_time"] = datetime.now(timezone.utc).isoformat()
    save_state()

    try:
        sniff(iface=CAPTURE_IFACE, prn=handle_packet, store=False, promisc=True)
=======
    log.info("[NET]   Interface: Default")
    log.info("        Press Ctrl+C to stop")

    with state_lock:
        state["running"] = True
        state["start_time"] = datetime.utcnow().isoformat()
    save_state()

    stats_thread = threading.Thread(target=stats_loop, daemon=True)
    stats_thread.start()

    try:
        sniff(prn=handle_packet, store=False)
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
    except KeyboardInterrupt:
        log.info("\n[STOP] Monitoring stopped.")
    finally:
        with state_lock:
            state["running"] = False
        save_state()


<<<<<<< HEAD
def get_interface() -> str:
    return CAPTURE_IFACE


if __name__ == "__main__":
    start_monitoring()
=======
if __name__ == "__main__":
    start_monitoring()
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
