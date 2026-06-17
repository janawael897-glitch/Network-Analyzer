<<<<<<< HEAD
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

=======
"""
live_monitor.py " PacketGuard Live Network Traffic Monitor
Real-time packet capture, anomaly detection, alert generation,
and ML scoring via ml_detector.get_detector().
"""
import os
import sys
import json
import time
import threading
import logging
import uuid
from datetime import datetime, timezone
from collections import defaultdict, deque

# """ LOGGING """"""""""""""""""""""""""""""""""""""""""""""
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [MONITOR] %(message)s',
    handlers=[
        logging.FileHandler('live_monitor.log', encoding='utf-8'),
        logging.StreamHandler(sys.stdout),
    ]
)
log = logging.getLogger('live_monitor')

# """ STATE FILE """""""""""""""""""""""""""""""""""""""""""
BASE_DIR       = os.path.dirname(os.path.abspath(__file__))
LIVE_STATE     = os.path.join(BASE_DIR, 'live_state.json')
ALERTS_FILE    = os.path.join(BASE_DIR, 'alerts.json')
BLOCK_FILE     = os.path.join(BASE_DIR, 'blocked_ips.json')  # same as firewall_enforcer
WHITELIST_FILE = os.path.join(BASE_DIR, 'whitelist.json')  # match config.py

# """ RUNTIME STATE """"""""""""""""""""""""""""""""""""""""
_state = {
    'running':          False,
    'interface':        None,
    'packets_captured': 0,
    'bytes_total':      0,
    'packets_per_sec':  0,
    'bytes_per_sec':    0,
    'alerts_total':     0,
    'ml_detections':    0,
    'ml_total':         0,
    'ml_recent_alerts': [],
    'start_time':       None,
    'top_talkers':      {},
    'protocol_counts':  defaultdict(int),
    'port_counts':      defaultdict(int),
    'recent_packets':   deque(maxlen=200),
}
_state_lock      = threading.Lock()
_alert_callbacks = []   # registered by web_dashboard / socketio
_stop_event      = threading.Event()
_g_socketio      = None   # set by start_monitoring — used by _on_ml_alert for live emit
_g_app           = None

# ── ML Validation Gate ────────────────────────────────────
_ml_pending      = {}   # {src_ip: {'alert': dict, 'queued_at': float}}
_ml_pending_lock = threading.Lock()
_ML_GATE_TIMEOUT = 60   # seconds to wait for ML confirmation before fallback
_ML_BYPASS_CONF  = 0.95 # ML confidence that bypasses the gate immediately
# Alert types that skip the gate and block right away
_ML_BYPASS_TYPES = {'HEARTBLEED', 'ARP_SPOOF', 'SQL_INJECTION', 'XSS'}

# ── Own-machine IP cache (skip heuristics when we are the source) ─
def _build_own_ips() -> set:
    """Return all IP addresses assigned to this machine (loopback + all interfaces)."""
    import socket
    ips = {'127.0.0.1', '::1', '0.0.0.0', 'localhost'}
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None):
            ips.add(info[4][0])
    except Exception:
        pass
    try:
        from scapy.all import get_if_list, get_if_addr
        for iface in get_if_list():
            try:
                ip = get_if_addr(iface)
                if ip:
                    ips.add(ip)
            except Exception:
                pass
    except Exception:
        pass
    return ips

_own_ips: set = _build_own_ips()


def _build_own_macs() -> set:
    """Return all MAC addresses assigned to this machine's interfaces."""
    macs = set()
    try:
        from scapy.all import get_if_list, get_if_hwaddr
        for iface in get_if_list():
            try:
                mac = get_if_hwaddr(iface)
                if mac and mac not in ('00:00:00:00:00:00', 'ff:ff:ff:ff:ff:ff'):
                    macs.add(mac.lower())
            except Exception:
                pass
    except Exception:
        pass
    return macs

_own_macs: set = _build_own_macs()

# ── Flow-based processing layer ───────────────────────────────────
_flow_builder  = None
_flow_exporter = None


def _get_flow_builder():
    global _flow_builder
    if _flow_builder is None:
        from flow_builder import FlowBuilder
        _flow_builder = FlowBuilder(timeout=30.0)
    return _flow_builder


def _get_flow_exporter():
    global _flow_exporter
    if _flow_exporter is None:
        from flow_exporter import FlowExporter
        _flow_exporter = FlowExporter()
    return _flow_exporter

# """ PACKET RATE TRACKING """""""""""""""""""""""""""""""""
_rate_window  = deque(maxlen=300)   # (timestamp, bytes) — 5-min buffer
_last_nonzero_rate = 0.0            # keep last non-zero rate for display


def _save_state():
    """Persist live state to SQLite live_state table (atomic INSERT OR REPLACE)."""
    try:
        with _state_lock:
            pkts  = _state['packets_captured']
            rate  = _state['packets_per_sec']
            bps   = _state['bytes_per_sec']
            start = _state['start_time']
            runtime = 0
            if start:
                try:
                    start_dt = datetime.fromisoformat(start)
                    if start_dt.tzinfo is None:
                        start_dt = start_dt.replace(tzinfo=timezone.utc)
                    runtime = (datetime.now(timezone.utc) - start_dt).total_seconds()
                except Exception:
                    runtime = 0
            def _json_safe(obj):
                try:
                    import numpy as _np
                    if isinstance(obj, (_np.bool_,)):   return bool(obj)
                    if isinstance(obj, _np.integer):    return int(obj)
                    if isinstance(obj, _np.floating):   return float(obj)
                    if isinstance(obj, _np.ndarray):    return obj.tolist()
                except ImportError:
                    pass
                return str(obj)
            protocols = json.dumps(dict(_state['protocol_counts']), default=_json_safe)
            top_ips   = json.dumps(dict(sorted(
                _state['top_talkers'].items(),
                key=lambda x: x[1], reverse=True
            )[:10]), default=_json_safe)
            ml_recent = json.dumps(list(_state['ml_recent_alerts'])[:50], default=_json_safe)
            row = (
                pkts,
                _state['bytes_total'],
                rate,
                bps,
                int(runtime),
                1 if _state['running'] else 0,
                protocols,
                top_ips,
                _state['ml_total'],
                _state['ml_detections'],
                ml_recent,
                _state['interface'],
                datetime.now(timezone.utc).isoformat(),
            )

        import sqlite3 as _sql
        _db_path = os.path.join(BASE_DIR, 'packetguard.db')
        conn = _sql.connect(_db_path, timeout=5)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=3000")
        try:
            # Ensure the table exists (in case migrations haven't run yet)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS live_state (
                    id INTEGER PRIMARY KEY CHECK(id = 1),
                    total_packets INTEGER NOT NULL DEFAULT 0,
                    bytes_total INTEGER NOT NULL DEFAULT 0,
                    packets_per_sec REAL NOT NULL DEFAULT 0.0,
                    bytes_per_sec REAL NOT NULL DEFAULT 0.0,
                    runtime_seconds INTEGER NOT NULL DEFAULT 0,
                    running INTEGER NOT NULL DEFAULT 0,
                    protocols TEXT NOT NULL DEFAULT '{}',
                    top_ips TEXT NOT NULL DEFAULT '{}',
                    ml_total INTEGER NOT NULL DEFAULT 0,
                    ml_detections INTEGER NOT NULL DEFAULT 0,
                    ml_recent_alerts TEXT NOT NULL DEFAULT '[]',
                    interface TEXT,
                    last_updated TEXT NOT NULL DEFAULT ''
                )
            """)
            conn.execute("""
                INSERT OR REPLACE INTO live_state
                (id, total_packets, bytes_total, packets_per_sec, bytes_per_sec,
                 runtime_seconds, running, protocols, top_ips,
                 ml_total, ml_detections, ml_recent_alerts, interface, last_updated)
                VALUES (1,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, row)
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        log.warning(f"[STATE] Save error: {e}")


# Cached blocklist / whitelist - refreshed at most every 5 seconds to avoid
# per-packet disk reads, which would be catastrophically expensive at high pps.
_bl_cache: set = set()
_wl_cache: set = set()
_bl_ts: float = 0.0
_wl_ts: float = 0.0
_LIST_TTL = 5.0  # seconds


def _load_blocklist() -> set:
    global _bl_cache, _bl_ts
    now = time.time()
    if now - _bl_ts < _LIST_TTL:
        return _bl_cache
    try:
        if os.path.exists(BLOCK_FILE):
            with open(BLOCK_FILE, encoding='utf-8') as f:
                data = json.load(f)
            if isinstance(data, list):
                _bl_cache = {e['ip'] if isinstance(e, dict) else e for e in data}
            elif isinstance(data, dict):
                _bl_cache = set(data.keys())
            else:
                _bl_cache = set()
        else:
            _bl_cache = set()
    except Exception:
        pass
    _bl_ts = now
    return _bl_cache


def _load_whitelist() -> set:
    global _wl_cache, _wl_ts
    now = time.time()
    if now - _wl_ts < _LIST_TTL:
        return _wl_cache
    try:
        if os.path.exists(WHITELIST_FILE):
            with open(WHITELIST_FILE, encoding='utf-8') as f:
                data = json.load(f)
            if isinstance(data, list):
                _wl_cache = {e['ip'] if isinstance(e, dict) else e for e in data}
            elif isinstance(data, dict):
                _wl_cache = set(data.keys())
            else:
                _wl_cache = set()
        else:
            _wl_cache = set()
    except Exception:
        pass
    _wl_ts = now
    return _wl_cache


# """ ALERT PIPELINE """""""""""""""""""""""""""""""""""""""
def _dispatch_alert(alert: dict):
    """Send alert to all registered callbacks (socketio, db, etc.)."""
    if not alert.get('alert_id') and not alert.get('id'):
        alert['alert_id'] = 'ALT-' + uuid.uuid4().hex[:8].upper()
    with _state_lock:
        _state['alerts_total'] += 1
    # Insert alert into SQLite DB
    try:
        from data_service import push_alert as _push_alert
        ok = _push_alert(alert, is_ml=False)
        if not ok:
            log.warning(f"[ALERT] push_alert returned False for type={alert.get('alert_type')} — DB write may have failed")
    except Exception as e:
        log.warning(f"[ALERT] push_alert exception: {e}", exc_info=True)

    # Fire registered callbacks (copy first so mutations during iteration are safe)
    for cb in _alert_callbacks[:]:
        try:
            cb(alert)
        except Exception as e:
            log.debug(f"Alert callback error: {e}")

    log.info(f"[{alert.get('severity','?')}] {alert.get('message','')}")

    # Deduplicate: merge repeated alerts within rolling windows before blocking
    try:
        from alert_dedup import ingest as _dedup_ingest
        _dedup_ingest(alert)
    except Exception:
        pass

    # ML Validation Gate: queue heuristic alerts for ML confirmation before blocking.
    # Bypass types (Heartbleed, ARP_SPOOF, etc.) and already-ML-confirmed IPs block immediately.
    src = alert.get('source_ip', '')
    atype = alert.get('alert_type', '')
    if src:
        bypass = atype in _ML_BYPASS_TYPES or _ml_recently_confirmed(src)
        if bypass:
            _execute_block(alert, src, 'immediate')
        else:
            with _ml_pending_lock:
                _ml_pending[src] = {'alert': alert, 'queued_at': time.time()}
            _write_response_log(src, 'PENDING_ML',
                                f"Heuristic: {atype} — awaiting ML confirmation",
                                alert, 0)


def register_alert_callback(fn):
    """Called by web_dashboard.py to receive alerts in real time."""
    if fn not in _alert_callbacks:
        _alert_callbacks.append(fn)


def _write_response_log(src_ip, action_type, label, alert, executed):
    """Write one row to the response_log DB table."""
    try:
        from db_manager import get_db
        db = get_db()
        db.execute(
            """INSERT INTO response_log
                (source_ip, action_type, action_label, action_time,
                 description, risk_score, executed, severity, result)
                VALUES (?,?,?,?,?,?,?,?,?)""",
            (
                src_ip,
                action_type,
                label,
                datetime.now(timezone.utc).isoformat(),
                alert.get('message', ''),
                float(alert.get('confidence', 0)) * 100,
                executed,
                alert.get('severity', 'LOW'),
                label,
            )
        )
        db.commit()
        db.close()
    except Exception as e:
        log.debug(f"response_log write error: {e}")


def _execute_block(alert, src, reason_suffix=''):
    """Evaluate and execute a firewall block, writing result to response_log."""
    try:
        from firewall_enforcer import evaluate_for_block
        result = evaluate_for_block(alert)
        if result and result.get('success'):
            _write_response_log(src, 'BLOCK',
                                f"{alert.get('severity','?')} Auto-Block ({reason_suffix})",
                                alert, 1)
            log.info(f"[GATE] BLOCK executed for {src} ({reason_suffix}): "
                     f"{result.get('fw_message','firewall')}")
        else:
            _write_response_log(src, 'MONITOR',
                                f"Firewall unavailable — monitoring {src}",
                                alert, 0)
    except Exception as e:
        log.debug(f"_execute_block error: {e}")
        _write_response_log(src, 'MONITOR',
                            f"Block failed — monitoring {src}: {e}",
                            alert, 0)


def _ml_recently_confirmed(ip: str, window: float = 60.0) -> bool:
    """Return True if ML confirmed this IP as malicious within `window` seconds."""
    try:
        from ml_detector import get_detector
        det = get_detector()
        entry = getattr(det, '_recent_attacks', {}).get(ip)
        if entry and (time.time() - entry['ts']) < window:
            return True
    except Exception:
        pass
    return False


def _ml_gate_cleanup():
    """Every 30 s: expire pending gate entries older than _ML_GATE_TIMEOUT."""
    while True:
        time.sleep(30)
        now = time.time()
        expired = []
        with _ml_pending_lock:
            for ip, v in list(_ml_pending.items()):
                if now - v['queued_at'] > _ML_GATE_TIMEOUT:
                    expired.append((ip, v))
                    del _ml_pending[ip]
        for ip, v in expired:
            log.info(f"[GATE] {ip} — ML did not confirm within {_ML_GATE_TIMEOUT}s, "
                     "falling back to MONITOR.")
            _write_response_log(ip, 'MONITOR',
                                f"ML unconfirmed after {_ML_GATE_TIMEOUT}s — monitoring",
                                v['alert'], 0)


# """ HEURISTIC DETECTION """"""""""""""""""""""""""""""""""
_syn_counts   = defaultdict(int)
_port_scan_tr = defaultdict(set)
_dns_counts   = defaultdict(int)

# -- new counters --
_udp_counts   = defaultdict(int)
_icmp_counts  = defaultdict(int)
# C2 beaconing tracker: {(src_ip, dst_ip, dst_port) → [timestamps]}
_beacon_ts: dict = defaultdict(list)
_BEACON_WINDOW      = 120   # look-back window in seconds
_BEACON_MIN_HITS    = 5     # minimum connections before checking regularity
_BEACON_MAX_CV      = 0.25  # coefficient of variation threshold (lower = more regular)
_BEACON_MIN_INTERVAL = 8.0  # ignore intervals < 8s (normal keep-alive, not beaconing)
_brute_ports  = {22, 21, 3389, 23, 3306, 5900, 5432, 1433}
_brute_counts = defaultdict(lambda: defaultdict(int))
_stealth_tr   = defaultdict(set)

_last_heur    = time.time()

HEUR_RESET_INTERVAL = 30

_BRUTE_PORT_LABEL = {
    22:   'SSH',
    21:   'FTP',
    3389: 'RDP',
    23:   'Telnet',
    3306: 'MySQL',
    5900: 'VNC',
    5432: 'PostgreSQL',
    1433: 'MSSQL',
}


import re as _re

# ARP spoof tracking: {ip → mac} seen so far
_arp_table: dict = {}
_arp_spoof_seen: set = set()

# SQL / web injection patterns
_SQL_RE = _re.compile(
    rb"(union[\s\+]+select|select[\s\+]+.{0,40}from|insert[\s\+]+into|drop[\s\+]+table"
    rb"|delete[\s\+]+from|update[\s\+]+set|exec[\s\+]*\(|xp_cmdshell"
    rb"|1[\s]*=[\s]*1|'[\s]*or[\s]*'|--[\s]|;[\s]*drop|;[\s]*select"
    rb"|benchmark[\s]*\(|sleep[\s]*\(|char[\s]*\(|concat[\s]*\(|0x[0-9a-f]{4})",
    _re.IGNORECASE,
)
_CMD_RE = _re.compile(
    rb"(;[\s]*(ls|cat|id|whoami|passwd|wget|curl|bash|sh\b|cmd\.exe|powershell)"
    rb"|\$\([^)]{1,40}\)|/etc/passwd|/bin/sh|cmd\.exe)",
    _re.IGNORECASE,
)
# HTTP flood / slow-HTTP / web brute-force tracking
_http_req_counts:  dict = defaultdict(int)          # {src_ip → requests per window}
_http_login_counts: dict = defaultdict(int)
_slow_http_conns:  dict = defaultdict(int)          # {(src_ip, dst_ip, dst_port) → slow conn count}
_slow_http_ts:     dict = {}                        # {(src_ip, dst_ip, dst_port) → first_seen}
_XSS_RE = _re.compile(
    rb"(<script[\s>]|javascript:|onerror\s*=|onload\s*=|onmouseover\s*=|"
    rb"alert\s*\(|document\.cookie|<iframe[\s>]|<img[^>]+src\s*=\s*[\"']javascript)",
    _re.IGNORECASE,
)
_DB_PORTS   = {3306, 5432, 1433, 1521, 27017, 6379}
# Include port 5000 (PacketGuard web app) so slowloris against our own app is caught
_PLAIN_PORTS = {80, 8080, 8000, 3000, 5000} | _DB_PORTS
_HTTP_FLOOD_THRESHOLD  = 50    # requests from same IP in one window → HTTP flood
_HTTP_SLOW_TIMEOUT     = 8.0   # seconds before an incomplete connection is flagged
_HTTP_SLOW_THRESHOLD   = 5     # slow connections from same source IP → alert


def _maybe_reset_counters(now: float) -> None:
    global _last_heur
    if now - _last_heur > HEUR_RESET_INTERVAL:
        _syn_counts.clear()
        _udp_counts.clear()
        _icmp_counts.clear()
        _port_scan_tr.clear()
        _stealth_tr.clear()
        _dns_counts.clear()
        _brute_counts.clear()
        _http_login_counts.clear()
        _http_req_counts.clear()
        _slow_http_conns.clear()   # reset per-source slow connection counts
        _slow_http_ts.clear()      # reset first-seen timestamps
        _arp_spoof_seen.clear()
        _beacon_ts.clear()
        _last_heur = now


def _chk_arp_spoof(pkt) -> dict | None:
    """Detect ARP spoofing: an IP claiming a MAC different from what we saw before."""
    try:
        op       = pkt.op          # 1=who-has (request), 2=is-at (reply)
        src_ip   = pkt.psrc        # sender IP
        src_mac  = pkt.hwsrc       # sender MAC
        if not src_ip or src_ip in ('0.0.0.0', '255.255.255.255'):
            return None
        # 00:00:00:00:00:00 = normal ARP probe (RFC 5227), not a spoof
        if src_mac in ('00:00:00:00:00:00', 'ff:ff:ff:ff:ff:ff'):
            return None
        # Skip packets sent by this machine's own interfaces — the ARP spoof
        # module sends poison packets from our MAC claiming to be other IPs,
        # which would otherwise trigger a false-positive ARP_SPOOF alert.
        if src_mac.lower() in _own_macs:
            _arp_table[src_ip] = src_mac   # still track for consistency
            return None
        # Also skip if the claimed IP belongs to this machine
        if src_ip in _own_ips:
            return None
        known_mac = _arp_table.get(src_ip)
        if known_mac is None:
            _arp_table[src_ip] = src_mac
            return None
        # If the entry we stored was our own MAC (we poisoned it), the real
        # device restoring its true MAC is not an attack — just clear and move on.
        if known_mac.lower() in _own_macs:
            _arp_table[src_ip] = src_mac
            return None
        if known_mac != src_mac and src_ip not in _arp_spoof_seen:
            _arp_spoof_seen.add(src_ip)
            return {
                'timestamp':     datetime.now(timezone.utc).isoformat(),
                'alert_type':    'ARP_SPOOF',
                'severity':      'HIGH',
                'confidence':    0.85,
                'message':       (f"ARP spoofing detected: {src_ip} was {known_mac}, "
                                  f"now claims {src_mac} — possible MITM"),
                'source_ip':     src_ip,
                'destination_ip': pkt.pdst,
                'protocol':      'ARP',
                'additional_info': {
                    'old_mac': known_mac, 'new_mac': src_mac,
                    'arp_op':  'reply' if op == 2 else 'request',
                },
            }
        # Update table (legitimate re-assignment after first detection clears)
        _arp_table[src_ip] = src_mac
    except Exception:
        pass
    return None


def _chk_injection(pkt, src_ip: str, dst_ip: str, dst_port: int) -> dict | None:
    """Detect SQL injection and command injection in TCP payloads."""
    try:
        from scapy.layers.inet import TCP
        if not pkt.haslayer(TCP):
            return None
        raw = bytes(pkt[TCP].payload)
        if len(raw) < 10:
            return None
        sql_match = _SQL_RE.search(raw)
        cmd_match = _CMD_RE.search(raw)
        if not sql_match and not cmd_match:
            return None
        kind    = 'SQL_INJECTION' if sql_match else 'CMD_INJECTION'
        sev     = 'CRITICAL' if dst_port in _DB_PORTS else 'HIGH'
        conf    = 0.95 if sev == 'CRITICAL' else 0.90
        snippet = (sql_match or cmd_match).group(0).decode('utf-8', errors='replace')[:60]
        return {
            'timestamp':      datetime.now(timezone.utc).isoformat(),
            'alert_type':     kind,
            'severity':       sev,
            'confidence':     conf,
            'message':        (f"{kind.replace('_',' ').title()} attempt: "
                               f"{src_ip} → {dst_ip}:{dst_port} — pattern: {snippet!r}"),
            'source_ip':      src_ip,
            'destination_ip': dst_ip,
            'destination_port': dst_port,
            'protocol':       'TCP',
            'additional_info': {'pattern': snippet, 'dst_port': dst_port},
        }
    except Exception:
        pass
    return None


def _chk_syn_flood(src_ip, dst_ip, src_port, dst_port, proto, flags_str):
    if proto != 'TCP' or 'S' not in flags_str or 'A' in flags_str:
        return None
    # Skip own machine — the built-in network scanner generates many SYNs to local IPs
    if src_ip in _own_ips:
        return None
    # Only flag SYN floods targeting LOCAL IPs — outgoing SYNs to public IPs are normal browsing
    try:
        from firewall_enforcer import is_private as _isp
        if not _isp(dst_ip):
            return None
    except Exception:
        pass
    _syn_counts[src_ip] += 1
    if _syn_counts[src_ip] <= 200:
        return None
    count = _syn_counts[src_ip]
    _syn_counts[src_ip] = 0
    severity = 'CRITICAL' if count >= 1000 else 'HIGH'
    return {
        'timestamp':   datetime.now(timezone.utc).isoformat(),
        'alert_type':  'SYN_FLOOD', 'severity': severity,
        'confidence':  1.0,
        'message':     f"SYN flood from {src_ip} ({count} SYN packets, no ACK)",
        'source_ip':   src_ip, 'destination_ip': dst_ip,
        'destination_port': dst_port, 'protocol': proto,
        'additional_info': {'dst_port': dst_port, 'src_port': src_port,
                            'protocol': proto, 'syn_count': count, 'flow_pkts': count},
    }


def _chk_udp_flood(src_ip, dst_ip, src_port, dst_port, proto):
    if proto != 'UDP':
        return None
    if src_ip in _own_ips:
        return None
    try:
        from firewall_enforcer import is_private as _isp
        if not _isp(dst_ip):
            return None
    except Exception:
        pass
    _udp_counts[src_ip] += 1
    if _udp_counts[src_ip] <= 1000:
        return None
    count = _udp_counts[src_ip]
    _udp_counts[src_ip] = 0
    severity = 'CRITICAL' if count >= 5000 else 'HIGH'
    return {
        'timestamp':  datetime.now(timezone.utc).isoformat(),
        'alert_type': 'UDP_FLOOD', 'severity': severity,
        'confidence': 0.90,
        'message':    f"UDP flood from {src_ip} ({count} UDP packets)",
        'source_ip':  src_ip, 'destination_ip': dst_ip,
        'destination_port': dst_port, 'protocol': proto,
        'additional_info': {'dst_port': dst_port, 'src_port': src_port,
                            'protocol': proto, 'flow_pkts': count},
    }


def _chk_icmp_flood(src_ip, dst_ip, src_port, proto):
    if proto != 'ICMP':
        return None
    if src_ip in _own_ips:
        return None
    _icmp_counts[src_ip] += 1
    if _icmp_counts[src_ip] <= 200:
        return None
    count = _icmp_counts[src_ip]
    _icmp_counts[src_ip] = 0
    severity = 'CRITICAL' if count >= 1000 else 'HIGH'
    return {
        'timestamp':  datetime.now(timezone.utc).isoformat(),
        'alert_type': 'ICMP_FLOOD', 'severity': severity,
        'confidence': 0.90,
        'message':    f"ICMP flood from {src_ip} ({count} ICMP packets)",
        'source_ip':  src_ip, 'destination_ip': dst_ip,
        'destination_port': None, 'protocol': proto,
        'additional_info': {'src_port': src_port, 'protocol': proto, 'flow_pkts': count},
    }


def _chk_port_scan(src_ip, dst_ip, src_port, dst_port, proto):
    if not dst_port:
        return None
    # Skip own machine — the built-in network scanner enumerates many local ports
    if src_ip in _own_ips:
        return None
    # Only track scans targeting local IPs — browsing touches many external ports normally
    try:
        from firewall_enforcer import is_private as _isp
        if not _isp(dst_ip):
            return None
    except Exception:
        pass
    _port_scan_tr[src_ip].add(dst_port)
    if len(_port_scan_tr[src_ip]) <= 50:
        return None
    ports_scanned = len(_port_scan_tr[src_ip])
    _port_scan_tr[src_ip] = set()
    severity = 'CRITICAL' if ports_scanned >= 500 else 'HIGH'
    return {
        'timestamp':  datetime.now(timezone.utc).isoformat(),
        'alert_type': 'PORT_SCAN', 'severity': severity,
        'confidence': 0.90,
        'message':    f"Port scan from {src_ip} ({ports_scanned} unique ports)",
        'source_ip':  src_ip, 'destination_ip': dst_ip,
        'destination_port': dst_port, 'protocol': proto,
        'additional_info': {'ports_scanned': ports_scanned, 'dst_port': dst_port,
                            'src_port': src_port, 'protocol': proto},
    }


def _chk_stealth_scan(src_ip, dst_ip, src_port, dst_port, proto, flags):
    if proto != 'TCP' or flags is None:
        return None
    if src_ip in _own_ips:
        return None
    try:
        f = int(flags)
        is_null = (f == 0x00)
        is_fin  = (f == 0x01)
        is_xmas = ((f & 0x29) == 0x29)
        if not (is_null or is_fin or is_xmas):
            return None
        _stealth_tr[src_ip].add(dst_port)
        if len(_stealth_tr[src_ip]) <= 5:
            return None
        ports_probed = len(_stealth_tr[src_ip])
        if is_null:
            scan_type = 'NULL'
        elif is_xmas:
            scan_type = 'XMAS'
        else:
            scan_type = 'FIN'
        _stealth_tr[src_ip] = set()
        return {
            'timestamp':  datetime.now(timezone.utc).isoformat(),
            'alert_type': 'STEALTH_SCAN', 'severity': 'CRITICAL',
            'confidence': 0.95,
            'message':    f"{scan_type} stealth scan from {src_ip} ({ports_probed} ports probed)",
            'source_ip':  src_ip, 'destination_ip': dst_ip,
            'destination_port': dst_port, 'protocol': proto,
            'additional_info': {'scan_type': scan_type, 'ports_scanned': ports_probed,
                                'dst_port': dst_port, 'src_port': src_port, 'protocol': proto},
        }
    except Exception:
        return None


def _chk_brute_force(src_ip, dst_ip, src_port, dst_port, proto):
    if proto != 'TCP' or dst_port not in _brute_ports:
        return None
    if src_ip in _own_ips:
        return None
    _brute_counts[src_ip][dst_port] += 1
    if _brute_counts[src_ip][dst_port] <= 10:
        return None
    count     = _brute_counts[src_ip][dst_port]
    svc_label = _BRUTE_PORT_LABEL.get(dst_port, f'port {dst_port}')
    _brute_counts[src_ip][dst_port] = 0
    severity = 'CRITICAL' if count >= 50 else 'HIGH'
    return {
        'timestamp':  datetime.now(timezone.utc).isoformat(),
        'alert_type': 'BRUTE_FORCE', 'severity': severity,
        'confidence': 0.90,
        'message':    f"Brute force on {svc_label} from {src_ip} ({count} attempts)",
        'source_ip':  src_ip, 'destination_ip': dst_ip,
        'destination_port': dst_port, 'protocol': proto,
        'additional_info': {'service': svc_label, 'dst_port': dst_port,
                            'src_port': src_port, 'protocol': proto, 'flow_pkts': count},
    }


def _chk_dns_anomaly(src_ip, dst_ip, src_port, dst_port, proto):
    if dst_port != 53:
        return None
    if src_ip in _own_ips:
        return None
    _dns_counts[src_ip] += 1
    if _dns_counts[src_ip] <= 100:
        return None
    count = _dns_counts[src_ip]
    _dns_counts[src_ip] = 0
    return {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'alert_type': 'DNS_ANOMALY', 'severity': 'MEDIUM',
        'confidence': 0.70,
        'message': f"Abnormal DNS query rate from {src_ip} ({count} queries)",
        'source_ip': src_ip, 'destination_ip': dst_ip,
        'destination_port': 53, 'protocol': proto,
        'additional_info': {'dst_port': 53, 'src_port': src_port,
                            'protocol': proto, 'flow_pkts': count},
    }


def _chk_http_flood(pkt, src_ip: str, dst_ip: str, dst_port: int) -> dict | None:
    """Detect HTTP DoS floods (GoldenEye, Hulk) — high-rate HTTP GET/POST from one IP."""
    if src_ip in _own_ips:
        return None
    try:
        from scapy.layers.inet import TCP
        if not pkt.haslayer(TCP):
            return None
        raw = bytes(pkt[TCP].payload)
        if len(raw) < 7:
            return None
        # Only count actual HTTP request lines
        if not (raw.startswith(b'GET ') or raw.startswith(b'POST ') or
                raw.startswith(b'HEAD ') or raw.startswith(b'PUT ')):
            return None
        _http_req_counts[src_ip] += 1
        count = _http_req_counts[src_ip]
        if count < _HTTP_FLOOD_THRESHOLD:
            return None
        _http_req_counts[src_ip] = 0
        # Try to identify sub-type from user-agent or URL randomisation patterns
        kind = 'DOS_HULK' if b'?' in raw[:200] and b'=' in raw[:200] else 'DOS_GOLDENEYE'
        return {
            'timestamp':      datetime.now(timezone.utc).isoformat(),
            'alert_type':     'HTTP_FLOOD',
            'severity':       'CRITICAL',
            'confidence':     0.90,
            'message':        (f"HTTP flood ({kind}) from {src_ip} — "
                               f"{count} requests to {dst_ip}:{dst_port}"),
            'source_ip':      src_ip,
            'destination_ip': dst_ip,
            'destination_port': dst_port,
            'protocol':       'TCP',
            'additional_info': {'subtype': kind, 'request_count': count, 'dst_port': dst_port},
        }
    except Exception:
        pass
    return None


def _chk_slow_http(pkt, src_ip: str, dst_ip: str, dst_port: int) -> dict | None:
    """Detect Slowloris / Slowhttptest — many slow/incomplete HTTP connections from one IP."""
    try:
        from scapy.layers.inet import TCP
        if not pkt.haslayer(TCP):
            return None
        raw = bytes(pkt[TCP].payload)
        now = time.time()
        key = (src_ip, dst_ip, dst_port)

        # Track incomplete HTTP headers (no double CRLF = request never finished)
        if raw and (b'GET ' in raw or b'POST ' in raw or b'HEAD ' in raw):
            if b'\r\n\r\n' not in raw:
                if key not in _slow_http_ts:
                    _slow_http_ts[key] = now
                _slow_http_conns[key] += 1  # count slow connections per source IP

        # Also catch keepalive header injections (slowloris keepalive pattern)
        elif raw and b'\r\n' in raw and b': ' in raw and key in _slow_http_ts:
            _slow_http_conns[key] += 1

        # Fire when source has >= threshold slow connections that have been open long enough
        if key in _slow_http_ts:
            age       = now - _slow_http_ts[key]
            conn_count = _slow_http_conns.get(key, 0)
            if age >= _HTTP_SLOW_TIMEOUT and conn_count >= _HTTP_SLOW_THRESHOLD:
                del _slow_http_ts[key]
                del _slow_http_conns[key]
                return {
                    'timestamp':      datetime.now(timezone.utc).isoformat(),
                    'alert_type':     'SLOW_HTTP',
                    'severity':       'HIGH',
                    'confidence':     0.85,
                    'message':        (f"Slowloris/Slow-HTTP attack from {src_ip} — "
                                       f"{conn_count} slow connections to {dst_ip}:{dst_port} "
                                       f"held for {round(age,1)}s"),
                    'source_ip':      src_ip,
                    'destination_ip': dst_ip,
                    'destination_port': dst_port,
                    'protocol':       'TCP',
                    'additional_info': {'slow_conns': conn_count,
                                        'hold_time_s': round(age, 1)},
                }
    except Exception:
        pass
    return None


def _chk_web_brute(pkt, src_ip: str, dst_ip: str, dst_port: int) -> dict | None:
    """Detect web-based brute force — repeated HTTP POST to login-like endpoints."""
    try:
        from scapy.layers.inet import TCP
        if not pkt.haslayer(TCP):
            return None
        raw = bytes(pkt[TCP].payload)
        if len(raw) < 10:
            return None
        if not raw.startswith(b'POST '):
            return None
        # Only flag POST to common login/auth paths
        login_paths = (b'/login', b'/signin', b'/auth', b'/wp-login',
                       b'/admin', b'/user/login', b'/account/login')
        if not any(p in raw[:200] for p in login_paths):
            return None
        _http_login_counts[src_ip] += 1
        count = _http_login_counts[src_ip]
        if count < 30:
            return None
        _http_login_counts[src_ip] = 0
        return {
            'timestamp':      datetime.now(timezone.utc).isoformat(),
            'alert_type':     'WEB_BRUTE_FORCE',
            'severity':       'HIGH',
            'confidence':     0.90,
            'message':        (f"Web brute force from {src_ip} — "
                               f"{count} POST attempts to {dst_ip}:{dst_port}"),
            'source_ip':      src_ip,
            'destination_ip': dst_ip,
            'destination_port': dst_port,
            'protocol':       'TCP',
            'additional_info': {'attempt_count': count, 'dst_port': dst_port},
        }
    except Exception:
        pass
    return None


def _chk_xss(pkt, src_ip: str, dst_ip: str, dst_port: int) -> dict | None:
    """Detect XSS payloads in HTTP requests."""
    try:
        from scapy.layers.inet import TCP
        if not pkt.haslayer(TCP):
            return None
        raw = bytes(pkt[TCP].payload)
        if len(raw) < 10:
            return None
        if not (raw.startswith(b'GET ') or raw.startswith(b'POST ')):
            return None
        match = _XSS_RE.search(raw)
        if not match:
            return None
        snippet = match.group(0).decode('utf-8', errors='replace')[:60]
        return {
            'timestamp':      datetime.now(timezone.utc).isoformat(),
            'alert_type':     'XSS',
            'severity':       'HIGH',
            'confidence':     0.85,
            'message':        (f"XSS attempt from {src_ip} → {dst_ip}:{dst_port} "
                               f"— pattern: {snippet!r}"),
            'source_ip':      src_ip,
            'destination_ip': dst_ip,
            'destination_port': dst_port,
            'protocol':       'TCP',
            'additional_info': {'pattern': snippet, 'dst_port': dst_port},
        }
    except Exception:
        pass
    return None


def _chk_heartbleed(pkt, src_ip: str, dst_ip: str, dst_port: int) -> dict | None:
    """Detect Heartbleed (CVE-2014-0160) — TLS heartbeat with oversized length."""
    try:
        from scapy.layers.inet import TCP
        if not pkt.haslayer(TCP):
            return None
        raw = bytes(pkt[TCP].payload)
        # TLS record layout: type[1] + version[2] + length[2] = 5-byte header
        # Heartbeat message starts at byte 5: type[1] + payload_length[2] + payload[...]
        if len(raw) < 8:
            return None
        if raw[0] != 0x18:  # not heartbeat record type
            return None
        if raw[1] != 0x03:  # TLS version major byte
            return None
        hb_type   = raw[5]               # heartbeat message type: 1=request, 2=response
        hb_length = (raw[6] << 8) | raw[7]  # stated payload length
        actual    = len(raw) - 8         # actual payload bytes after 8-byte header
        if hb_type == 1 and hb_length > actual + 16:  # requesting more than sent
            return {
                'timestamp':      datetime.now(timezone.utc).isoformat(),
                'alert_type':     'HEARTBLEED',
                'severity':       'CRITICAL',
                'confidence':     1.0,
                'message':        (f"Heartbleed exploit attempt from {src_ip} → "
                                   f"{dst_ip}:{dst_port} "
                                   f"(claimed {hb_length}B, sent {actual}B)"),
                'source_ip':      src_ip,
                'destination_ip': dst_ip,
                'destination_port': dst_port,
                'protocol':       'TCP',
                'additional_info': {
                    'claimed_length': hb_length,
                    'actual_length':  actual,
                    'dst_port':       dst_port,
                },
            }
    except Exception:
        pass
    return None


def _chk_beaconing(src_ip: str, dst_ip: str, dst_port: int, now: float):
    """Detect C2 beaconing: repeated connections at regular intervals to same host."""
    if src_ip in _own_ips:
        return None
    try:
        from firewall_enforcer import is_private as _isp
        if _isp(dst_ip):          # ignore beaconing to local IPs (normal LAN traffic)
            return None
    except Exception:
        pass
    key = (src_ip, dst_ip, dst_port)
    ts  = _beacon_ts[key]
    ts.append(now)
    cutoff = now - _BEACON_WINDOW
    _beacon_ts[key] = [t for t in ts if t >= cutoff]
    ts = _beacon_ts[key]
    if len(ts) < _BEACON_MIN_HITS:
        return None
    intervals = [ts[i+1] - ts[i] for i in range(len(ts) - 1)]
    if not intervals:
        return None
    mean_iv = sum(intervals) / len(intervals)
    if mean_iv < _BEACON_MIN_INTERVAL:
        return None
    std_iv = (sum((x - mean_iv) ** 2 for x in intervals) / len(intervals)) ** 0.5
    cv = std_iv / mean_iv if mean_iv > 0 else 1.0
    if cv > _BEACON_MAX_CV:
        return None
    _beacon_ts[key] = []   # reset after firing
    return {
        'timestamp':     datetime.now(timezone.utc).isoformat(),
        'alert_type':    'C2_BEACONING',
        'severity':      'CRITICAL',
        'confidence':    0.90,
        'message':       (f"C2 beaconing detected: {src_ip} → {dst_ip}:{dst_port} "
                          f"every ~{mean_iv:.0f}s ({len(ts)} hits, regularity CV={cv:.2f})"),
        'source_ip':     src_ip,
        'destination_ip': dst_ip,
        'destination_port': dst_port,
        'protocol':      'TCP',
        'additional_info': {
            'interval_s': round(mean_iv, 1),
            'hit_count':  len(ts),
            'cv':         round(cv, 3),
        },
    }


def _chk_heartbleed_443(pkt, src_ip: str, dst_ip: str) -> dict | None:
    """Detect Heartbleed on port 443 — checks TLS record structure (not encrypted content)."""
    try:
        from scapy.layers.inet import TCP
        if not pkt.haslayer(TCP):
            return None
        raw = bytes(pkt[TCP].payload)
        # TLS record layout: type[1] + version[2] + length[2] = 5-byte header
        # Heartbeat message starts at byte 5: type[1] + payload_length[2] + payload[...]
        if len(raw) < 8 or raw[0] != 0x18 or raw[1] != 0x03:
            return None
        hb_type   = raw[5]               # heartbeat message type: 1=request, 2=response
        hb_length = (raw[6] << 8) | raw[7]  # stated payload length
        actual    = len(raw) - 8         # actual payload bytes after 8-byte header
        if hb_type == 1 and hb_length > actual + 16:
            return {
                'timestamp':      datetime.now(timezone.utc).isoformat(),
                'alert_type':     'HEARTBLEED',
                'severity':       'CRITICAL',
                'confidence':     1.0,
                'message':        (f"Heartbleed (CVE-2014-0160) from {src_ip} → "
                                   f"{dst_ip}:443 — claimed {hb_length}B, sent {actual}B"),
                'source_ip':      src_ip,
                'destination_ip': dst_ip,
                'destination_port': 443,
                'protocol':       'TCP',
                'additional_info': {'claimed': hb_length, 'actual': actual},
            }
    except Exception:
        pass
    return None


def _heuristic_check(src_ip, dst_ip, src_port, dst_port, proto, flags):
    """Fast heuristic checks — rules ordered by severity."""
    now       = time.time()
    flags_str = str(flags) if flags else ''
    alert = (
        _chk_syn_flood(src_ip, dst_ip, src_port, dst_port, proto, flags_str)
        or _chk_udp_flood(src_ip, dst_ip, src_port, dst_port, proto)
        or _chk_icmp_flood(src_ip, dst_ip, src_port, proto)
        or _chk_port_scan(src_ip, dst_ip, src_port, dst_port, proto)
        or _chk_stealth_scan(src_ip, dst_ip, src_port, dst_port, proto, flags)
        or _chk_brute_force(src_ip, dst_ip, src_port, dst_port, proto)
        or _chk_dns_anomaly(src_ip, dst_ip, src_port, dst_port, proto)
        or _chk_beaconing(src_ip, dst_ip, dst_port or 0, now)
    )
    _maybe_reset_counters(now)
    return alert


def _get_pkt_fields(pkt):
    """Extract (src_ip, dst_ip, proto, src_port, dst_port, flags) from a scapy packet.
    Returns None if the packet has no IP layer."""
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    if not pkt.haslayer(IP):
        return None
    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    if pkt.haslayer(TCP):
        return src_ip, dst_ip, 'TCP', pkt[TCP].sport, pkt[TCP].dport, pkt[TCP].flags
    if pkt.haslayer(UDP):
        return src_ip, dst_ip, 'UDP', pkt[UDP].sport, pkt[UDP].dport, None
    if pkt.haslayer(ICMP):
        return src_ip, dst_ip, 'ICMP', 0, 0, None
    return src_ip, dst_ip, 'OTHER', 0, 0, None


def handle_packet(pkt):
    """Called for every captured packet. Runs heuristics + ML scoring + dispatches alerts."""
    if _stop_event.is_set():
        return

    now  = time.time()
    size = len(pkt)

    # Rate tracking + byte accumulation
    _rate_window.append((now, size))

    with _state_lock:
        _state['packets_captured'] += 1
        _state['bytes_total'] += size

    try:
        # ── ARP spoof detection (before IP check — ARP has no IP layer) ──
        try:
            from scapy.layers.l2 import ARP
            if pkt.haslayer(ARP):
                arp_alert = _chk_arp_spoof(pkt[ARP])
                if arp_alert:
                    _dispatch_alert(arp_alert)
        except Exception:
            pass

        fields = _get_pkt_fields(pkt)
        if fields is None:
            return
        src_ip, dst_ip, proto, src_port, dst_port, flags = fields


        # Blocklist / whitelist check
        blocklist  = _load_blocklist()
        whitelist  = _load_whitelist()
        if src_ip in blocklist and src_ip not in whitelist:
            return

        # Update state counters
        with _state_lock:
            _state['protocol_counts'][proto] += 1
            if dst_port:
                _state['port_counts'][str(dst_port)] = \
                    _state['port_counts'].get(str(dst_port), 0) + 1
            _state['top_talkers'][src_ip] = \
                _state['top_talkers'].get(src_ip, 0) + 1
            _state['recent_packets'].append({
                'time':     datetime.now(timezone.utc).isoformat(),
                'src':      src_ip,
                'dst':      dst_ip,
                'proto':    proto,
                'src_port': src_port,
                'dst_port': dst_port,
                'size':     size,
            })

        # Heuristic detection
        alert = _heuristic_check(src_ip, dst_ip, src_port, dst_port, proto, flags)
        if alert:
            _dispatch_alert(alert)
            try:
                from correlation_engine_v2 import feed_alert
                feed_alert(alert)
            except Exception:
                pass

        # Layer-7 attack detection — plaintext ports only (skip 443/TLS encrypted traffic)
        # Skip own machine — own HTTP traffic generates benign payloads that match rules
        if proto == 'TCP' and dst_port and dst_port in _PLAIN_PORTS and src_ip not in _own_ips:
            for _fn in (_chk_injection, _chk_xss, _chk_http_flood,
                        _chk_slow_http, _chk_web_brute, _chk_heartbleed):
                _l7 = _fn(pkt, src_ip, dst_ip, dst_port)
                if _l7:
                    _dispatch_alert(_l7)
                    break  # one alert per packet

        # Heartbleed on port 443 — structural TLS header check (not content inspection)
        if proto == 'TCP' and dst_port == 443 and src_ip not in _own_ips:
            _hb = _chk_heartbleed_443(pkt, src_ip, dst_ip)
            if _hb:
                _dispatch_alert(_hb)

        # ML detection — feed ALL packets (including own-IP responses) so the flow
        # aggregator tracks bidirectional features (pkts_bwd, bwd lengths, down/up ratio).
        # Alert suppression for own-IP-initiated flows is handled inside score_packet().
        try:
            from ml_detector import get_detector
            detector = get_detector()
            if detector.ready:
                detector.score_packet(pkt)
        except Exception as e:
            log.debug(f"ML score error: {e}")

        # ── Flow-based pipeline ───────────────────────────────────
        try:
            pkt_info = {
                "src_ip":    src_ip,
                "dst_ip":    dst_ip,
                "src_port":  src_port or 0,
                "dst_port":  dst_port or 0,
                "proto":     proto,
                "size":      size,
                "timestamp": now,
            }
            completed_flows = _get_flow_builder().add_packet(pkt_info)
            exporter = _get_flow_exporter()
            for flow in completed_flows:
                # Export for visualization / CSV download only
                exporter.write_flow(flow)
                # ML scoring is handled by ml_detector's FlowAggregator via score_packet() above,
                # which uses all 78 CIC-IDS2017 features. The flow_to_ml_input() helper only
                # provides 10 incompatible features so is not used for prediction here.
        except Exception as _fbe:
            log.warning(f"[FLOW-BUILDER] error: {_fbe}", exc_info=True)

    except Exception as e:
        log.warning(f"[HANDLE_PACKET] error: {e}", exc_info=True)


# """ RATE CALCULATOR THREAD """""""""""""""""""""""""""""""
def _rate_thread():
    """Updates packets/sec and bytes/sec every second using 5s rolling window + EMA smoothing."""
    _ema_pps = 0.0
    _ema_bps = 0.0
    _alpha   = 0.3   # EMA smoothing factor " lower = smoother, higher = more responsive

    while not _stop_event.is_set():
        time.sleep(1)
        now    = time.time()

        # 5-second rolling window to avoid single-second spikes
        cutoff = now - 5.0
        recent = [(t, b) for t, b in _rate_window if t >= cutoff]
        elapsed = max(now - cutoff, 1.0)

        raw_pps = len(recent)  / elapsed
        raw_bps = sum(b for _, b in recent) / elapsed

        # Exponential moving average to smooth out bursts
        _ema_pps = _alpha * raw_pps + (1 - _alpha) * _ema_pps
        _ema_bps = _alpha * raw_bps + (1 - _alpha) * _ema_bps

        global _last_nonzero_rate
        if _ema_pps > 0:
            _last_nonzero_rate = round(_ema_pps, 1)
        display_pps = round(_ema_pps, 1) if _ema_pps > 0 else _last_nonzero_rate

        with _state_lock:
            _state['packets_per_sec'] = display_pps
            _state['bytes_per_sec']   = round(_ema_bps, 1)
        _save_state()


# """ ML ALERT CALLBACK """"""""""""""""""""""""""""""""""""
ML_ALERTS_FILE = os.path.join(BASE_DIR, 'ml_alerts.json')

def _on_ml_alert(alert: dict):
    """Receives ML-generated alerts - writes ONLY to ml_alerts.json, not alerts.json."""
    if not alert.get('alert_id') and not alert.get('id'):
        alert['alert_id'] = 'ML-' + uuid.uuid4().hex[:8].upper()

    # ML gate: if ML confirms a pending heuristic alert, execute the block now
    src = alert.get('source_ip', '')
    conf = float(alert.get('confidence', 0))
    pending_entry = None
    if src:
        with _ml_pending_lock:
            pending_entry = _ml_pending.pop(src, None)
    if pending_entry:
        log.info(f"[GATE] ML confirmed {src} (conf={conf:.2f}) — executing deferred block.")
        _execute_block(pending_entry['alert'], src, f'ML-confirmed conf={conf:.2f}')
    elif src and conf >= _ML_BYPASS_CONF:
        # High-confidence ML hit on an IP that wasn't in the pending queue — block directly
        log.info(f"[GATE] High-conf ML ({conf:.2f}) for {src} — immediate block.")
        _execute_block(alert, src, f'ML-highconf {conf:.2f}')

    with _state_lock:
        _state['ml_detections'] += 1
        _state['ml_total'] += 1
        _state['ml_recent_alerts'].insert(0, alert)
        _state['ml_recent_alerts'] = _state['ml_recent_alerts'][:50]
    # Fire registered callbacks (socketio etc) but do NOT call _dispatch_alert
    for cb in _alert_callbacks[:]:
        try:
            cb(alert)
        except Exception:
            pass
    # Insert ML alert into SQLite DB (is_ml=True)
    try:
        from data_service import push_alert as _push_alert
        _push_alert(alert, is_ml=True)
    except Exception as e:
        log.debug(f"ML alert DB write error: {e}")

    # Emit dedicated ml_alert socket event so the ML feed updates in real time
    if _g_socketio and _g_app:
        try:
            with _g_app.app_context():
                _g_socketio.emit('ml_alert', alert)
        except Exception:
            pass

    # Feed into correlation engine
    try:
        from correlation_engine_v2 import feed_alert
        feed_alert(alert)
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
    except Exception:
        pass


<<<<<<< HEAD
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
=======
def _wire_ml_detector():
    """Attach _on_ml_alert to the ML detector once it's loaded."""
    try:
        from ml_detector import get_detector
        detector = get_detector()
        detector.on_alert = _on_ml_alert
        log.info(f"[ML] Detector wired. Status: {detector.status()}")
    except Exception as e:
        log.warning(f"[ML] Could not wire detector: {e}")


# """ INTERFACE SELECTION """"""""""""""""""""""""""""""""""""""""""
# Hardcoded active interface (192.168.1.2) " confirmed working
ACTIVE_IFACE = r'\Device\NPF_{6AE9C84A-0C4E-4922-BB77-49FAB27D9034}'

def _get_adapter_map() -> dict:
    """
    Parse `ipconfig /all` and return {ipv4_address: description} mapping.
    Used to identify whether an adapter is Ethernet or WiFi.
    """
    result = {}
    try:
        import subprocess as _sp
        out = _sp.check_output(["ipconfig", "/all"],
                               stderr=_sp.DEVNULL).decode(errors="ignore")
        current_desc = ""
        for line in out.splitlines():
            line = line.strip()
            if line.endswith(":") and not line.startswith(" "):
                current_desc = line.rstrip(":")
            elif "Description" in line or "Beschreibung" in line:
                current_desc = line.split(":", 1)[-1].strip()
            elif "IPv4 Address" in line or "IP-Adresse" in line:
                ip = line.split(":", 1)[-1].strip().replace("(Preferred)", "").strip()
                if ip:
                    result[ip] = current_desc.lower()
    except Exception:
        pass
    return result


def _pick_interface():
    """
    Pick the best available network interface.
    Preference order: saved override → Ethernet (non-virtual) → any active → fallback.
    """
    # 1. Saved override from dashboard interface selector
    try:
        override_path = os.path.join(BASE_DIR, "capture_iface.txt")
        if os.path.exists(override_path):
            with open(override_path, "r", encoding="utf-8") as _f:
                saved = _f.read().strip()
            if saved:
                return saved
    except Exception:
        pass

    # 2. Auto-detect using ipconfig /all descriptions to rank adapters
    try:
        from scapy.arch import get_if_list
        from scapy.all import get_if_addr
        adapter_map = _get_adapter_map()

        _VIRTUAL = ("vmware", "virtualbox", "hyper-v", "vethernet",
                    "loopback", "pseudo", "tunnel", "isatap", "teredo")
        _WIFI    = ("wireless", "wi-fi", "802.11", "wlan", "intel.*wi-fi",
                    "intel.*ax", "qualcomm", "atheros", "broadcom.*802")

        # Buckets: confirmed Ethernet > unidentified > WiFi
        ethernet, unknown, wifi = [], [], []
        for iface in get_if_list():
            try:
                ip = get_if_addr(iface)
                if not ip or ip.startswith(("0.", "127.", "169.254")):
                    continue
                desc = adapter_map.get(ip, "")
                if not desc:
                    # IP not in ipconfig /all — adapter likely disabled or virtual
                    unknown.append(iface)
                    continue
                desc_l = desc.lower()
                if any(k in desc_l for k in _VIRTUAL):
                    continue                     # skip virtual
                if any(k in desc_l for k in _WIFI):
                    wifi.append(iface)
                else:
                    ethernet.append(iface)      # confirmed Ethernet
            except Exception:
                continue

        # Prefer confirmed Ethernet, then unidentified, then WiFi as last resort
        for candidate in (ethernet + unknown + wifi):
            return candidate

    except Exception:
        pass

    # 3. Hardcoded fallback
    return ACTIVE_IFACE


# """ START / STOP """""""""""""""""""""""""""""""""""""""""
def start_monitoring(interface=None, socketio=None, app=None):
    """
    Entry point called by main.py / start.py.
    Starts packet capture in a background thread.
    """
    global _alert_callbacks

    if _state['running']:
        log.info("Monitor already running.")
        return

    # Register socketio emit as alert callback
    if socketio and app:
        def _socketio_cb(alert):
            try:
                with app.app_context():
                    socketio.emit('new_alert', alert)
            except Exception as e:
                log.debug(f"SocketIO emit error: {e}")
        register_alert_callback(_socketio_cb)

        # Store refs so _on_ml_alert can emit 'ml_alert' directly
        global _g_socketio, _g_app
        _g_socketio = socketio
        _g_app      = app

    _stop_event.clear()

    # Pick interface
    iface = interface or _pick_interface()
    with _state_lock:
        _state['running']    = True
        _state['interface']  = str(iface) if iface else 'default'
        _state['start_time'] = datetime.now(timezone.utc).isoformat()

    log.info(f"Starting packet capture on interface: {iface or 'default'}")

    # Wire ML detector
    threading.Thread(target=_wire_ml_detector, daemon=True, name='ml-wire').start()

    # ML gate cleanup (expires stale pending confirmations every 30 s)
    threading.Thread(target=_ml_gate_cleanup, daemon=True, name='ml-gate-cleanup').start()

    # Rate calculator
    threading.Thread(target=_rate_thread, daemon=True, name='rate-calc').start()

    # Packet capture thread
    def _capture():
        # ── tshark engine ────────────────────────────────────────────────
        _engine = os.environ.get("CAPTURE_ENGINE", "scapy").lower()
        if _engine == "tshark":
            try:
                from tshark_adapter import TsharkCapture, is_tshark_available
                if is_tshark_available():
                    log.info("[CAPTURE] tshark engine active.")
                    print("\n[CAPTURE] ► tshark engine active — using Wireshark capture.\n")
                    TsharkCapture(iface, handle_packet, _stop_event).start()
                    # If we reach here because stop was requested, exit cleanly.
                    if _stop_event.is_set():
                        return
                    # tshark exited unexpectedly — print a visible banner then fall
                    # through to the Scapy block below.
                    _msg = (
                        "\n"
                        "╔══════════════════════════════════════════════════════╗\n"
                        "║  ⚠  tshark STOPPED — switching to Scapy capture  ⚠  ║\n"
                        "╚══════════════════════════════════════════════════════╝\n"
                    )
                    log.warning("[CAPTURE] tshark exited unexpectedly — falling back to Scapy.")
                    print(_msg)
                else:
                    log.warning("[CAPTURE] tshark not found — falling back to Scapy.")
                    print("\n[CAPTURE] tshark not found in PATH — falling back to Scapy.\n")
            except Exception as _te:
                log.warning(f"[CAPTURE] tshark engine failed ({_te}) — falling back to Scapy.")
                print(f"\n[CAPTURE] tshark engine error ({_te}) — falling back to Scapy.\n")

        # ── Scapy engine (default / fallback) ────────────────────────────
        try:
            from scapy.all import sniff
            log.info("[CAPTURE] Scapy sniff() started.")
            # Try monitor mode first (captures ALL WiFi frames without Ethernet).
            # Falls back to promiscuous mode if the adapter doesn't support it.
            try:
                log.info("[CAPTURE] Trying monitor mode...")
                sniff(
                    iface=iface,
                    prn=handle_packet,
                    store=False,
                    monitor=True,
                    stop_filter=lambda _: _stop_event.is_set(),
                )
            except Exception as _mon_err:
                log.info(f"[CAPTURE] Monitor mode not supported ({_mon_err}), using promiscuous mode.")
                sniff(
                    iface=iface,
                    prn=handle_packet,
                    store=False,
                    promisc=True,
                    stop_filter=lambda _: _stop_event.is_set(),
                )
        except Exception:
            log.exception("[CAPTURE] sniff() failed")
            with _state_lock:
                _state['running'] = False

    t = threading.Thread(target=_capture, daemon=True, name='packet-capture')
    t.start()
    log.info("Live monitor started.")
    return t


def stop_monitoring():
    """Stop packet capture."""
    _stop_event.set()
    with _state_lock:
        _state['running'] = False
    _save_state()
    log.info("Live monitor stopped.")


# """ PUBLIC API """""""""""""""""""""""""""""""""""""""""""
def get_live_stats() -> dict:
    """Return current live statistics snapshot."""
    with _state_lock:
        return {
            'running':          _state['running'],
            'interface':        _state['interface'],
            'packets_captured': _state['packets_captured'],
            'bytes_total':      _state['bytes_total'],
            'packets_per_sec':  _state['packets_per_sec'],
            'bytes_per_sec':    _state['bytes_per_sec'],
            'alerts_total':     _state['alerts_total'],
            'ml_detections':    _state['ml_detections'],
            'ml_total':         _state['ml_total'],
            'start_time':       _state['start_time'],
            'protocol_counts':  dict(_state['protocol_counts']),
            'top_talkers':      dict(sorted(
                _state['top_talkers'].items(),
                key=lambda x: x[1], reverse=True
            )[:10]),
        }


def get_recent_packets(limit: int = 50) -> list:
    """Return the most recent captured packets."""
    with _state_lock:
        pkts = list(_state['recent_packets'])
    return pkts[-limit:]


def get_interface() -> str | None:
    """Return the currently active capture interface name."""
    return _state.get('interface')


def get_status() -> dict:
    """Health-check endpoint used by /api/monitor/status."""
    try:
        from ml_detector import get_detector
        ml_status = get_detector().status()
    except Exception:
        ml_status = {'ready': False}
    return {
        'monitor_running': _state['running'],
        'interface':       _state['interface'],
        'uptime_seconds':  (
            (lambda st: (
                (datetime.now(timezone.utc) - (
                    st if st.tzinfo else st.replace(tzinfo=timezone.utc)
                )).total_seconds()
            ))(datetime.fromisoformat(_state['start_time']))
            if _state['start_time'] else 0
        ),
        'ml': ml_status,
    }


if __name__ == '__main__':
    # ── Single-instance lock (race-safe) ─────────────────────────────
    # open('x') = exclusive create: the OS guarantees only ONE process
    # succeeds even when two start at exactly the same time.
    _LOCK_FILE = os.path.join(BASE_DIR, '.monitor.pid')
    _my_pid    = os.getpid()

    def _is_live_monitor(pid: int) -> bool:
        """Return True if pid is a running python live_monitor.py process."""
        if pid == _my_pid:
            return False
        try:
            if sys.platform == 'win32':
                import subprocess as _sp, json as _json
                raw = _sp.check_output(
                    ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                     f"Get-CimInstance Win32_Process -Filter 'ProcessId={pid}' "
                     "| Select-Object Name,CommandLine | ConvertTo-Json -Compress"],
                    stderr=_sp.DEVNULL, encoding="utf-8", errors="ignore", timeout=6,
                )
                if not raw.strip():
                    return False
                info = _json.loads(raw)
                if isinstance(info, list): info = info[0] if info else {}
                return ("python" in str(info.get("Name","")).lower() and
                        "live_monitor" in str(info.get("CommandLine","")))
            else:
                os.kill(pid, 0)
                return True
        except Exception:
            return False

    def _remove_lock_file() -> None:
        try:
            os.remove(_LOCK_FILE)
        except Exception:
            pass

    def _acquire_single_instance() -> bool:
        """Returns True if we successfully took the single-instance lock."""
        for _ in range(10):
            try:
                with open(_LOCK_FILE, 'x') as _lf:
                    _lf.write(str(_my_pid))
                return True
            except FileExistsError:
                try:
                    with open(_LOCK_FILE) as _lf:
                        _holder = int(_lf.read().strip())
                except Exception:
                    _remove_lock_file()
                    time.sleep(0.1)
                    continue
                if _is_live_monitor(_holder):
                    return False
                _remove_lock_file()
                time.sleep(0.05)
        return False

    if not _acquire_single_instance():
        log.warning(f"[LOCK] Another live_monitor already running. Exiting (PID {_my_pid}).")
        sys.exit(0)

    log.info(f"[LOCK] Lock acquired (PID {_my_pid}).")

    log.info(f"[LOCK] Single-instance lock acquired (PID {_my_pid}).")

    # ── Start capture ─────────────────────────────────────────────────
    start_monitoring()
    try:
        while True:
            time.sleep(5)
            stats = get_live_stats()
            log.info(f"pkts={stats['packets_captured']}  "
                     f"pps={stats['packets_per_sec']}  "
                     f"alerts={stats['alerts_total']}  "
                     f"ml={stats['ml_detections']}")
    except KeyboardInterrupt:
        stop_monitoring()
        log.info("Stopped.")
    finally:
        try:
            os.remove(_LOCK_FILE)
        except Exception:
            pass
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
