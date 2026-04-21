#!/usr/bin/env python3
"""
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

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ]
)
log = logging.getLogger(__name__)

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
state = {
    "running": False,
    "start_time": None,
    "total_packets": 0,
    "rate": 0.0,
    "runtime_seconds": 0,
    "protocols": {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0},
    "top_ips": {},
    "recent_alerts": [],
    "ml_recent_alerts": [],
    "ml_total": 0,
    "bytes_total": 0,
    "last_updated": None,
}
state_lock = threading.Lock()
packet_timestamps = deque(maxlen=500)


def save_state():
    with state_lock:
        data = dict(state)
        data["top_ips"] = dict(
            sorted(data["top_ips"].items(), key=lambda x: x[1], reverse=True)[:10]
        )
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
                "destination_ip": "N/A",
                "additional_info": {"ports_scanned": unique_ports},
            }
        return None


class SynFloodDetector:
    def __init__(self, threshold=100, window=10):
        self.threshold = threshold
        self.window = window
        self.records = defaultdict(list)

    def check(self, dst_ip, ts):
        self.records[dst_ip].append(ts)
        self.records[dst_ip] = [t for t in self.records[dst_ip] if ts - t < self.window]
        count = len(self.records[dst_ip])
        if count >= self.threshold:
            return {
                "timestamp": datetime.utcnow().isoformat(),
                "alert_type": "SYN_FLOOD",
                "severity": "CRITICAL",
                "message": f"SYN flood targeting {dst_ip}: {count} SYN pkts in {self.window}s",
                "source_ip": "Multiple",
                "destination_ip": dst_ip,
                "additional_info": {"syn_count": count},
            }
        return None


class LargePacketDetector:
    def check(self, src_ip, dst_ip, size):
        if size > 9000:
            return {
                "timestamp": datetime.utcnow().isoformat(),
                "alert_type": "ABNORMAL_SIZE",
                "severity": "MEDIUM",
                "message": f"Abnormally large packet: {size} bytes from {src_ip}",
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "additional_info": {"packet_size": size},
            }
        return None


class HighRateDetector:
    def __init__(self, threshold=200, window=5):
        self.threshold = threshold
        self.window = window
        self.records = defaultdict(list)
        self.alerted = set()

    def check(self, src_ip, ts):
        self.records[src_ip].append(ts)
        self.records[src_ip] = [t for t in self.records[src_ip] if ts - t < self.window]
        rate = len(self.records[src_ip]) / self.window
        if rate >= self.threshold and src_ip not in self.alerted:
            self.alerted.add(src_ip)
            return {
                "timestamp": datetime.utcnow().isoformat(),
                "alert_type": "HIGH_PACKET_RATE",
                "severity": "HIGH",
                "message": f"High packet rate from {src_ip}: {rate:.0f} pkt/s",
                "source_ip": src_ip,
                "destination_ip": "N/A",
                "additional_info": {"rate": rate},
            }
        elif rate < self.threshold:
            self.alerted.discard(src_ip)
        return None


port_scan_det = PortScanDetector(threshold=5, window=60)   # 5 unique ports = alert (was 20)
syn_flood_det = SynFloodDetector(threshold=20, window=10)  # 20 SYN pkts = alert (was 100)
large_pkt_det = LargePacketDetector()
high_rate_det = HighRateDetector(threshold=30, window=5)   # 30 pkt/s = alert (was 200)

_cooldown = {}
COOLDOWN = 15  # was 30 — fire same alert again after 15s


def should_alert(key):
    now = time.time()
    if key not in _cooldown or now - _cooldown[key] > COOLDOWN:
        _cooldown[key] = now
        return True
    return False


def handle_packet(pkt):
    try:
        from scapy.layers.inet import IP, TCP, UDP, ICMP
        now = time.time()
        packet_timestamps.append(now)

        with state_lock:
            state["total_packets"] += 1
            state["bytes_total"] += len(pkt)
            state["last_updated"] = datetime.utcnow().isoformat()

            if pkt.haslayer(TCP):   state["protocols"]["TCP"] += 1
            elif pkt.haslayer(UDP): state["protocols"]["UDP"] += 1
            elif pkt.haslayer(ICMP):state["protocols"]["ICMP"] += 1
            else:                   state["protocols"]["Other"] += 1

            if pkt.haslayer(IP):
                src = pkt[IP].src
                state["top_ips"][src] = state["top_ips"].get(src, 0) + 1

        alert = None
        if pkt.haslayer(IP):
            src = pkt[IP].src
            dst = pkt[IP].dst
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
    try:
        from scapy.all import sniff
    except ImportError:
        log.error("Scapy not installed. Run: pip install scapy")
        sys.exit(1)

    log.info("[START] Starting live network monitoring...")
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
    except KeyboardInterrupt:
        log.info("\n[STOP] Monitoring stopped.")
    finally:
        with state_lock:
            state["running"] = False
        save_state()


if __name__ == "__main__":
    start_monitoring()
