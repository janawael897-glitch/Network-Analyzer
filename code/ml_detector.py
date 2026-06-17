<<<<<<< HEAD
#!/usr/bin/env python3
<<<<<<< HEAD
import warnings
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")
warnings.filterwarnings("ignore", category=UserWarning, module="joblib")
warnings.filterwarnings("ignore", category=DeprecationWarning)
"""
ML Detector — PacketGuard  (v3 — SOC-grade IDS Engine)
=======================================================
Improvements over v2:
  • Alert deduplication — groups repeated anomalies from same source IP
    into aggregated events ("192.168.x.x triggered 12 anomalous flows")
  • Explainable ML — every alert includes feature-level reasoning
    (e.g. "abnormal SYN rate", "high packet burst", "unusual port")
  • Auto-training — if models are missing, trains automatically once
  • Professional alert categories (PORT_SCAN, SYN_FLOOD, ANOMALOUS_FLOW…)
  • Rate-limited logging — no console spam from repeated same-IP alerts
"""

import os
import sys
import pickle
import json
import logging
import threading
import time
import subprocess
from collections import defaultdict, deque
from datetime import datetime, timezone

import numpy as np
import pandas as pd

BASE_DIR   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.path.join(BASE_DIR, "models")
CODE_DIR   = os.path.dirname(os.path.abspath(__file__))

log = logging.getLogger(__name__)

# ── Tunable constants ──────────────────────────────────────────────
FLOW_TIMEOUT    = 5.0    # seconds of inactivity → finalise flow
MAX_FLOW_PKTS   = 50     # hard cap; finalise at this many packets
MIN_ALERT_CONF  = 0.35   # minimum fused confidence to fire an alert
ISO_WEIGHT      = 0.60
RF_WEIGHT       = 0.40

# ── Deduplication settings ─────────────────────────────────────────
DEDUP_WINDOW    = 30.0   # seconds — group alerts from same src IP
DEDUP_THRESHOLD = 3      # fire aggregated alert after this many dupes
DEDUP_MAX_STORE = 500    # max IPs tracked in dedup table

# ── Severity mapping ───────────────────────────────────────────────
CLASS_SEVERITY = {
    "BENIGN":        None,
    "DDOS":          "CRITICAL",
    "DOS":           "CRITICAL",
    "BOTNET":        "HIGH",
    "BRUTE_FORCE":   "HIGH",
    "PORT_SCAN":     "HIGH",
    "WEB_ATTACK":    "HIGH",
    "HEARTBLEED":    "CRITICAL",
    "INFILTRATION":  "CRITICAL",
    "OTHER":         "MEDIUM",
    "ANOMALY":       "HIGH",
}

# ── Feature list (must match train_cicids.py SELECTED_FEATURES) ────
FEATURES = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Max",
    "Bwd Packet Length Mean",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Fwd IAT Mean",
    "Bwd IAT Mean",
    "Fwd PSH Flags",
    "SYN Flag Count",
    "RST Flag Count",
    "Average Packet Size",
]

# ── Internal globals ───────────────────────────────────────────────
_alert_lock      = threading.Lock()
_ML_ALERTS_FILE  = os.path.join(BASE_DIR, "ml_alerts.json")

# ── ML init status (shown in dashboard) ───────────────────────────
ML_STATUS = {
    "state":   "initializing",   # initializing | training | active | failed
    "message": "ML Engine Initializing...",
    "models":  [],
}
_status_lock = threading.Lock()

def _set_ml_status(state: str, message: str, models: list = None):
    with _status_lock:
        ML_STATUS["state"]   = state
        ML_STATUS["message"] = message
        if models is not None:
            ML_STATUS["models"] = models
    log.info(f"[ML STATUS] {state.upper()}: {message}")


# ══════════════════════════════════════════════════════════════════
# Helper: load a pickle from models/
# ══════════════════════════════════════════════════════════════════

def _load(filename):
    path = os.path.join(MODELS_DIR, filename)
    if not os.path.exists(path):
        return None
    try:
        with open(path, "rb") as f:
            return pickle.load(f)
    except Exception as e:
        log.warning(f"[ML] Could not load {filename}: {e}")
        return None


# ══════════════════════════════════════════════════════════════════
# Auto-trainer — runs train_ml.py if models are missing
# ══════════════════════════════════════════════════════════════════

def _auto_train():
    """Run in a thread. Trains models if missing, then reloads detector."""
    _set_ml_status("training", "Model Training in progress (first-time setup)...")
    train_script = os.path.join(CODE_DIR, "train_ml.py")
    if not os.path.exists(train_script):
        _set_ml_status("failed", "train_ml.py not found — cannot auto-train.")
        return

    try:
        log.info("[ML] Auto-training started...")
        result = subprocess.run(
            [sys.executable, train_script],
            cwd=CODE_DIR,
            capture_output=True,
            text=True,
            timeout=300,
        )
        if result.returncode == 0:
            log.info("[ML] Auto-training complete.")
            # Force reload
            global _detector
            with _detector_lock:
                _detector = None
            det = get_detector()
            if det.ready:
                _set_ml_status("active",
                               f"ML Detection Active — models: {det.status()['models_loaded']}",
                               det.status()["models_loaded"])
            else:
                _set_ml_status("failed", "Training finished but models still not loading.")
        else:
            _set_ml_status("failed", f"Training failed: {result.stderr[-300:]}")
    except subprocess.TimeoutExpired:
        _set_ml_status("failed", "Auto-training timed out after 5 minutes.")
    except Exception as e:
        _set_ml_status("failed", f"Auto-training error: {e}")


# ══════════════════════════════════════════════════════════════════
# Alert Deduplicator
# ══════════════════════════════════════════════════════════════════

class AlertDeduplicator:
    """
    Groups repeated alerts from the same source IP within a time window.
    After DEDUP_THRESHOLD hits, fires one aggregated alert and resets.
    Prevents alert spam when normal traffic is mis-scored repeatedly.
    """

    def __init__(self, window: float = DEDUP_WINDOW, threshold: int = DEDUP_THRESHOLD):
        self._window    = window
        self._threshold = threshold
        self._buckets   = {}   # src_ip → {"count":int, "first_ts":float, "last_alert":dict}
        self._lock      = threading.Lock()

    def process(self, alert: dict):
        """
        Returns:
          None          — alert is a duplicate, suppress it
          alert         — first occurrence, pass through immediately
          agg_alert     — aggregated summary after threshold reached
        """
        src = alert.get("source_ip", "unknown")
        now = time.monotonic()

        with self._lock:
            # Purge stale entries
            if len(self._buckets) > DEDUP_MAX_STORE:
                stale = [k for k, v in self._buckets.items()
                         if now - v["first_ts"] > self._window * 2]
                for k in stale:
                    del self._buckets[k]

            if src not in self._buckets:
                # First occurrence — pass through
                self._buckets[src] = {
                    "count":      1,
                    "first_ts":   now,
                    "last_alert": alert,
                    "scores":     [alert.get("confidence", 0)],
                }
                return alert

            bucket = self._buckets[src]

            # Reset if window expired
            if now - bucket["first_ts"] > self._window:
                self._buckets[src] = {
                    "count":      1,
                    "first_ts":   now,
                    "last_alert": alert,
                    "scores":     [alert.get("confidence", 0)],
                }
                return alert

            # Within window — accumulate
            bucket["count"] += 1
            bucket["last_alert"] = alert
            bucket["scores"].append(alert.get("confidence", 0))

            count = bucket["count"]

            # Suppress until threshold
            if count < self._threshold:
                return None

            # At threshold and every Nth after — fire aggregated alert
            if count == self._threshold or count % 10 == 0:
                avg_conf = float(np.mean(bucket["scores"]))
                duration = now - bucket["first_ts"]
                agg = dict(alert)   # copy base alert
                agg["alert_type"] = "ML_ANOMALY_BURST"
                agg["severity"]   = "HIGH" if avg_conf < 0.7 else "CRITICAL"
                agg["message"]    = (
                    f"[IDS] {src} triggered {count} anomalous flows "
                    f"in {duration:.0f}s | avg confidence={avg_conf*100:.0f}%"
                )
                agg["confidence"] = round(avg_conf, 3)
                agg["additional_info"] = dict(alert.get("additional_info", {}))
                agg["additional_info"]["burst_count"]    = count
                agg["additional_info"]["burst_duration"] = round(duration, 1)
                agg["additional_info"]["burst_avg_conf"] = round(avg_conf, 3)
                return agg

            return None


# ══════════════════════════════════════════════════════════════════
# Explainability Engine
# ══════════════════════════════════════════════════════════════════

def explain_flow(flow, iso_score: float, fused: float, rf_label: str) -> dict:
    """
    Produce human-readable feature explanations for an anomalous flow.
    Returns a dict with 'triggers' list and 'risk_summary' string.
    """
    triggers = []
    duration = max(flow.last_ts - flow.start_ts, 1e-6)

    # SYN flood indicator
    if flow.syn_count > 5:
        triggers.append(f"High SYN count ({flow.syn_count} SYN flags)")

    # RST anomaly
    if flow.rst_count > 3:
        triggers.append(f"Abnormal RST count ({flow.rst_count} RST flags)")

    # Packet burst
    pkt_rate = flow.total_pkts / duration
    if pkt_rate > 50:
        triggers.append(f"Packet burst ({pkt_rate:.0f} pkts/s)")

    # Byte rate anomaly
    byte_rate = (flow.fwd_bytes + flow.bwd_bytes) / duration
    if byte_rate > 100_000:
        triggers.append(f"High byte rate ({byte_rate/1000:.0f} KB/s)")

    # Asymmetric flow (possible scan or exfil)
    if flow.fwd_pkts > 0 and flow.bwd_pkts == 0:
        triggers.append("One-directional flow (no response — possible scan)")
    elif flow.bwd_pkts > 0 and flow.fwd_pkts == 0:
        triggers.append("Unexpected inbound-only flow")

    # Small packet anomaly (common in scans)
    avg_len = np.mean(flow.all_lens) if flow.all_lens else 0
    if avg_len < 60 and flow.total_pkts > 5:
        triggers.append(f"Unusually small packets (avg {avg_len:.0f} bytes)")

    # High port entropy (port scan indicator)
    if flow.dst_port > 1024 and flow.syn_count > 2:
        triggers.append(f"High-port SYN activity (dst:{flow.dst_port})")

    # Low IAT variance (machine-generated traffic)
    all_iats = flow.fwd_iats + flow.bwd_iats
    if all_iats and np.std(all_iats) < 0.001 and len(all_iats) > 3:
        triggers.append("Uniform inter-arrival time (automated/scripted traffic)")

    # RF label hint
    if rf_label not in ("BENIGN", "UNKNOWN"):
        triggers.append(f"RF classifier flagged as: {rf_label}")

    if not triggers:
        triggers.append(f"IsoForest anomaly score ({iso_score:.3f}) below threshold")

    # Risk summary
    conf_pct = int(fused * 100)
    if fused >= 0.80:
        risk = "CRITICAL — strong anomaly signal across multiple features"
    elif fused >= 0.65:
        risk = "HIGH — clear deviation from baseline traffic patterns"
    else:
        risk = "MEDIUM — mild anomaly, may be unusual but benign traffic"

    return {
        "triggers":     triggers,
        "risk_summary": risk,
        "confidence_pct": conf_pct,
        "iso_score":    round(iso_score, 4),
        "explanation":  "; ".join(triggers[:3]),   # short version for UI
    }


# ══════════════════════════════════════════════════════════════════
# Flow record
# ══════════════════════════════════════════════════════════════════

class FlowRecord:
    """Accumulates packets belonging to a single bidirectional flow."""

    __slots__ = (
        "src_ip", "dst_ip", "src_port", "dst_port", "proto",
        "start_ts", "last_ts",
        "fwd_pkts", "bwd_pkts",
        "fwd_bytes", "bwd_bytes",
        "fwd_lens", "bwd_lens",
        "fwd_iats", "bwd_iats",
        "_last_fwd_ts", "_last_bwd_ts",
        "syn_count", "rst_count", "psh_fwd",
        "all_lens",
    )

    def __init__(self, src_ip, dst_ip, src_port, dst_port, proto):
        self.src_ip   = src_ip
        self.dst_ip   = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.proto    = proto
        now = time.monotonic()
        self.start_ts  = now
        self.last_ts   = now
        self.fwd_pkts  = 0
        self.bwd_pkts  = 0
        self.fwd_bytes = 0
        self.bwd_bytes = 0
        self.fwd_lens  = []
        self.bwd_lens  = []
        self.fwd_iats  = []
        self.bwd_iats  = []
        self._last_fwd_ts = None
        self._last_bwd_ts = None
        self.syn_count = 0
        self.rst_count = 0
        self.psh_fwd   = 0
        self.all_lens  = []

    @property
    def total_pkts(self):
        return self.fwd_pkts + self.bwd_pkts

    def add(self, pkt_len: int, is_forward: bool, syn: int, rst: int, psh: int):
        now = time.monotonic()
        self.last_ts = now
        self.all_lens.append(pkt_len)
        self.syn_count += syn
        self.rst_count += rst

        if is_forward:
            iat = now - self._last_fwd_ts if self._last_fwd_ts else 0.0
            self._last_fwd_ts = now
            self.fwd_pkts  += 1
            self.fwd_bytes += pkt_len
            self.fwd_lens.append(pkt_len)
            if iat > 0:
                self.fwd_iats.append(iat)
            self.psh_fwd += psh
        else:
            iat = now - self._last_bwd_ts if self._last_bwd_ts else 0.0
            self._last_bwd_ts = now
            self.bwd_pkts  += 1
            self.bwd_bytes += pkt_len
            self.bwd_lens.append(pkt_len)
            if iat > 0:
                self.bwd_iats.append(iat)

    def to_feature_vector(self) -> np.ndarray:
        duration    = max(self.last_ts - self.start_ts, 1e-6)
        total_bytes = self.fwd_bytes + self.bwd_bytes
        total_pkts  = self.total_pkts
        all_iats    = self.fwd_iats + self.bwd_iats

        def _mean(lst): return float(np.mean(lst)) if lst else 0.0
        def _std(lst):  return float(np.std(lst))  if len(lst) > 1 else 0.0
        def _max(lst):  return float(max(lst))      if lst else 0.0

        return np.array([
            self.dst_port,
            duration,
            self.fwd_pkts,
            self.bwd_pkts,
            self.fwd_bytes,
            self.bwd_bytes,
            _max(self.fwd_lens),
            _mean(self.fwd_lens),
            _max(self.bwd_lens),
            _mean(self.bwd_lens),
            total_bytes / duration,
            total_pkts  / duration,
            _mean(all_iats),
            _std(all_iats),
            _mean(self.fwd_iats),
            _mean(self.bwd_iats),
            self.psh_fwd,
            self.syn_count,
            self.rst_count,
            _mean(self.all_lens),
        ], dtype=np.float32)


# ══════════════════════════════════════════════════════════════════
# Flow Aggregator
# ══════════════════════════════════════════════════════════════════

class FlowAggregator:
    """Buffers packets into flows; calls on_flow_ready when finalised."""

    def __init__(self, on_flow_ready, timeout=FLOW_TIMEOUT, max_pkts=MAX_FLOW_PKTS):
        self._flows        = {}
        self._on_ready     = on_flow_ready
        self._timeout      = timeout
        self._max_pkts     = max_pkts
        self._lock         = threading.Lock()
        t = threading.Thread(target=self._reap_loop, daemon=True, name="flow-reaper")
        t.start()

    def ingest(self, pkt):
        try:
            from scapy.layers.inet import IP, TCP, UDP, ICMP
            if not pkt.haslayer(IP):
                return None
            ip  = pkt[IP]
            src, dst = ip.src, ip.dst
            proto = ip.proto

            sport, dport, syn, rst, psh = 0, 0, 0, 0, 0
            pkt_len = len(pkt)

            if pkt.haslayer(TCP):
                tcp   = pkt[TCP]
                sport = tcp.sport
                dport = tcp.dport
                flags = int(tcp.flags)
                syn   = 1 if flags & 0x02 else 0
                rst   = 1 if flags & 0x04 else 0
                psh   = 1 if flags & 0x08 else 0
            elif pkt.haslayer(UDP):
                udp   = pkt[UDP]
                sport = udp.sport
                dport = udp.dport

            key_fwd = (src, dst, sport, dport, proto)
            key_bwd = (dst, src, dport, sport, proto)

            with self._lock:
                if key_fwd in self._flows:
                    flow = self._flows[key_fwd]
                    flow.add(pkt_len, True, syn, rst, psh)
                    if flow.total_pkts >= self._max_pkts:
                        del self._flows[key_fwd]
                        return self._on_ready(flow)
                elif key_bwd in self._flows:
                    flow = self._flows[key_bwd]
                    flow.add(pkt_len, False, syn, rst, psh)
                    if flow.total_pkts >= self._max_pkts:
                        del self._flows[key_bwd]
                        return self._on_ready(flow)
                else:
                    self._flows[key_fwd] = FlowRecord(src, dst, sport, dport, proto)
                    self._flows[key_fwd].add(pkt_len, True, syn, rst, psh)
        except Exception as e:
            log.error(f"[ML] FlowAggregator.ingest error: {e}", exc_info=True)
        return None

    def _reap_loop(self):
        while True:
            time.sleep(10)
            now = time.monotonic()
            try:
                with self._lock:
                    expired = [k for k, f in self._flows.items()
                               if now - f.last_ts > self._timeout]
                    log.info(f"[ML] reap: {len(self._flows)} active flows, "
                             f"{len(expired)} expired")
                    for k in expired:
                        flow = self._flows.pop(k)
                        try:
                            self._on_ready(flow)
                        except Exception as e:
                            log.error(f"[ML] flow callback error: {e}", exc_info=True)
            except Exception as e:
                log.error(f"[ML] reap_loop error: {e}")


# ══════════════════════════════════════════════════════════════════
# Ensemble Scorer
# ══════════════════════════════════════════════════════════════════

class EnsembleScorer:
    def __init__(self, rf, iso, scaler, label_encoder, iso_threshold,
                 iso_scaler=None, deduplicator=None):
        self.rf            = rf
        self.iso           = iso
        self.scaler        = scaler
        self.label_encoder = label_encoder
        self.iso_threshold = iso_threshold
        self.iso_scaler    = iso_scaler
        self._cicids_ok    = (rf is not None and scaler is not None
                              and label_encoder is not None)
        self._dedup        = deduplicator or AlertDeduplicator()

    def score_flow(self, flow: FlowRecord) -> dict | None:
        try:
            vec      = flow.to_feature_vector()
            X_df     = pd.DataFrame(vec.reshape(1, -1), columns=FEATURES)
            X_scaled = self.scaler.transform(X_df) if self.scaler else vec.reshape(1, -1)

            rf_label = "UNKNOWN"
            rf_conf  = 0.0
            rf_anomaly_prob = 0.0

            if self._cicids_ok:
                enc      = self.rf.predict(X_scaled)[0]
                proba    = self.rf.predict_proba(X_scaled)[0]
                rf_conf  = float(np.max(proba))
                rf_label = self.label_encoder.inverse_transform([enc])[0]
                if rf_label == "BENIGN":
                    benign_idx = list(self.label_encoder.classes_).index("BENIGN") \
                                 if "BENIGN" in self.label_encoder.classes_ else -1
                    rf_anomaly_prob = 1.0 - (proba[benign_idx] if benign_idx >= 0
                                             else (1 - rf_conf))
                else:
                    rf_anomaly_prob = rf_conf

            iso_anomaly_prob = 0.0
            iso_score        = None

            if self.iso:
                if self.iso_scaler is not None:
                    n = self.iso.n_features_in_
                    iso_features = FEATURES[:n] if n <= len(FEATURES) else FEATURES
                    X_iso = self.iso_scaler.transform(
                        pd.DataFrame(vec.reshape(1, -1)[:, :n], columns=iso_features)
                    )
                else:
                    X_iso = X_scaled
                iso_score        = float(self.iso.score_samples(X_iso)[0])
                delta            = self.iso_threshold - iso_score
                iso_anomaly_prob = 1.0 / (1.0 + np.exp(-10 * delta))

            # Weighted ensemble
            if self._cicids_ok and self.iso:
                fused = RF_WEIGHT * rf_anomaly_prob + ISO_WEIGHT * iso_anomaly_prob
                if iso_anomaly_prob > 0.65:
                    fused = max(fused, iso_anomaly_prob)
            elif self._cicids_ok:
                fused = rf_anomaly_prob
            elif self.iso:
                fused = iso_anomaly_prob
            else:
                return None

            log.info(f"[ML] flow {flow.src_ip}->{flow.dst_ip} | "
                     f"RF={rf_anomaly_prob:.2f} ISO={iso_anomaly_prob:.2f} "
                     f"fused={fused:.2f} label={rf_label if self._cicids_ok else 'N/A'}")

            if fused < MIN_ALERT_CONF:
                return None

            # ── Label and severity ────────────────────────────────
            if self._cicids_ok and rf_label not in ("BENIGN", "UNKNOWN") \
                    and rf_conf >= MIN_ALERT_CONF:
                label    = rf_label
                severity = CLASS_SEVERITY.get(label, "MEDIUM")
                model    = "cicids_rf+iso_ensemble" if self.iso else "cicids_rf"
            elif iso_anomaly_prob >= MIN_ALERT_CONF:
                label    = "ANOMALY"
                severity = "HIGH"
                model    = "isolation_forest"
            else:
                return None

            # ── Explainability ────────────────────────────────────
            explain = explain_flow(flow, iso_score or 0.0, fused, rf_label)

            # ── Build alert ───────────────────────────────────────
            alert = {
                "timestamp":       datetime.now(timezone.utc).isoformat(),
                "alert_type":      f"ML_{label}",
                "severity":        severity,
                "message":         (
                    f"[IDS] Anomalous flow: {flow.src_ip} → {flow.dst_ip} "
                    f"| conf={fused*100:.0f}% | {explain['explanation']}"
                ),
                "source_ip":       flow.src_ip,
                "destination_ip":  flow.dst_ip,
                "ml_label":        label,
                "confidence":      round(fused, 3),
                "model":           model,
                "additional_info": {
                    "label":             label,
                    "rf_label":          rf_label,
                    "rf_confidence":     round(rf_conf, 3),
                    "iso_score":         round(iso_score, 4) if iso_score is not None else None,
                    "iso_anomaly_prob":  round(iso_anomaly_prob, 3),
                    "fused_score":       round(fused, 3),
                    "dst_port":          flow.dst_port,
                    "flow_pkts":         flow.total_pkts,
                    "flow_bytes":        flow.fwd_bytes + flow.bwd_bytes,
                    "flow_duration":     round(flow.last_ts - flow.start_ts, 3),
                    "syn_count":         flow.syn_count,
                    "rst_count":         flow.rst_count,
                    # Explainability fields
                    "triggers":          explain["triggers"],
                    "risk_summary":      explain["risk_summary"],
                    "confidence_pct":    explain["confidence_pct"],
                },
            }

            # ── Deduplication ─────────────────────────────────────
            return self._dedup.process(alert)

        except Exception as e:
            log.error(f"[ML] EnsembleScorer.score_flow error: {e}", exc_info=True)
            return None


# ══════════════════════════════════════════════════════════════════
# Persistence
# ══════════════════════════════════════════════════════════════════

def save_ml_alert(alert: dict) -> None:
    """Append alert to ml_alerts.json (thread-safe, JSON-safe)."""
    def _clean(obj):
        if isinstance(obj, dict):   return {k: _clean(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)): return [_clean(v) for v in obj]
        if hasattr(obj, "item"):    return obj.item()
        return obj

    alert = _clean(alert)
    with _alert_lock:
        try:
            try:
                with open(_ML_ALERTS_FILE, "r", encoding="utf-8") as f:
                    alerts = json.load(f)
                if not isinstance(alerts, list):
                    alerts = []
            except (FileNotFoundError, json.JSONDecodeError):
                alerts = []
            alerts.append(alert)
            if len(alerts) > 1000:
                alerts = alerts[-1000:]
            with open(_ML_ALERTS_FILE, "w", encoding="utf-8") as f:
                json.dump(alerts, f, indent=2, default=str)
        except Exception as e:
            log.warning(f"[ML] Failed to write ml_alerts.json: {e}")


# ══════════════════════════════════════════════════════════════════
# MLDetector  (public API)
# ══════════════════════════════════════════════════════════════════

class MLDetector:
    def __init__(self):
        self.rf             = None
        self.iso            = None
        self.scaler         = None
        self.iso_scaler     = None
        self.label_encoder  = None
        self.iso_threshold  = -0.1
        self._ready         = False
        self._cicids_ready  = False
        self._dedup         = AlertDeduplicator()
        self._load_models()
        self.on_alert       = save_ml_alert
        self._scorer        = EnsembleScorer(
            self.rf, self.iso, self.scaler, self.label_encoder,
            self.iso_threshold, iso_scaler=self.iso_scaler,
            deduplicator=self._dedup,
        )
        self._aggregator    = FlowAggregator(on_flow_ready=self._flow_ready)

    def _load_models(self):
        self.rf            = _load("cicids_rf.pkl")
        self.scaler        = _load("cicids_scaler.pkl")
        self.label_encoder = _load("cicids_label_encoder.pkl")

        if self.rf and self.scaler and self.label_encoder:
            self._cicids_ready = True
            log.info("[ML] CICIDS2017 RF loaded — supervised classification active")

        raw_iso = _load("isolation_forest.pkl")
        if isinstance(raw_iso, dict):
            self.iso        = raw_iso.get("model")
            self.iso_scaler = raw_iso.get("scaler")
            if not self.scaler:
                self.scaler = self.iso_scaler
            self.iso_threshold = raw_iso.get("threshold", -0.1)
        else:
            self.iso = raw_iso

        if self.iso:
            log.info("[ML] Isolation Forest loaded")

        meta_path = os.path.join(MODELS_DIR, "model_metadata.json")
        if os.path.exists(meta_path):
            try:
                with open(meta_path) as f:
                    meta = json.load(f)
                self.iso_threshold = meta.get("threshold", self.iso_threshold)
            except Exception:
                pass

        self._ready = self._cicids_ready or (self.iso is not None)

        if self._ready:
            loaded = []
            if self._cicids_ready: loaded.append("cicids_rf")
            if self.iso:           loaded.append("isolation_forest")
            _set_ml_status("active",
                           f"ML Detection Active — {', '.join(loaded)}",
                           loaded)
            log.info(f"[ML] Detector ready. Models: {loaded} | "
                     f"Threshold: {self.iso_threshold:.3f} | MinConf: {MIN_ALERT_CONF}")
        else:
            _set_ml_status("initializing",
                           "Models not found — auto-training will start shortly...")
            log.warning("[ML] No models found — scheduling auto-train.")
            t = threading.Thread(target=_auto_train, daemon=True, name="ml-auto-train")
            t.start()

    @property
    def ready(self):
        return self._ready

    def score_packet(self, pkt):
        if not self._ready:
            return None
        alert = self._aggregator.ingest(pkt)
        if alert:
            return alert
        if not self._cicids_ready and self.iso and self.scaler:
            return self._score_single_packet(pkt)
        return None

    def _flow_ready(self, flow: FlowRecord) -> dict | None:
        alert = self._scorer.score_flow(flow)
        if alert and callable(self.on_alert):
            try:
                self.on_alert(alert)
            except Exception as e:
                log.debug(f"on_alert callback error: {e}")
        return alert

    def _score_single_packet(self, pkt) -> dict | None:
        try:
            from scapy.layers.inet import IP, TCP, UDP
            if not pkt.haslayer(IP): return None
            ip  = pkt[IP]
            pkt_len = len(pkt)
            dport, syn, rst, psh = 0, 0, 0, 0
            if pkt.haslayer(TCP):
                tcp   = pkt[TCP]
                dport = tcp.dport
                flags = int(tcp.flags)
                syn   = 1 if flags & 0x02 else 0
                rst   = 1 if flags & 0x04 else 0
                psh   = 1 if flags & 0x08 else 0
            elif pkt.haslayer(UDP):
                dport = pkt[UDP].dport

            n  = self.iso.n_features_in_
            sc = self.iso_scaler or self.scaler
            if sc is None: return None
            vec      = np.zeros(n, dtype=np.float32)
            vec[0]   = dport
            vec[2]   = 1
            vec[4]   = pkt_len
            vec[6]   = pkt_len
            vec[7]   = pkt_len
            vec[10]  = pkt_len
            vec[11]  = 1
            vec[17]  = syn
            vec[18]  = rst
            vec[19]  = pkt_len

            cols  = FEATURES[:n] if n <= len(FEATURES) else FEATURES
            X_iso = sc.transform(pd.DataFrame(vec.reshape(1, -1), columns=cols))
            score = float(self.iso.score_samples(X_iso)[0])
            delta = self.iso_threshold - score
            prob  = 1.0 / (1.0 + np.exp(-10 * delta))

            if prob < MIN_ALERT_CONF:
                return None

            alert = {
                "timestamp":       datetime.now(timezone.utc).isoformat(),
                "alert_type":      "ML_ANOMALY",
                "severity":        "MEDIUM",
                "message":         (f"[IsoForest] Single-packet anomaly: "
                                   f"{ip.src} → {ip.dst} | score={score:.3f}"),
                "source_ip":       ip.src,
                "destination_ip":  ip.dst,
                "ml_label":        "ANOMALY",
                "confidence":      round(prob, 3),
                "model":           "isolation_forest",
                "additional_info": {
                    "iso_score":    round(score, 4),
                    "iso_anomaly_prob": round(prob, 3),
                    "fused_score":  round(prob, 3),
                    "dst_port":     dport,
                    "flow_pkts":    1,
                    "flow_bytes":   pkt_len,
                    "triggers":     ["Single-packet IsoForest anomaly"],
                    "risk_summary": "Low confidence — single packet, no flow context",
                },
            }
            return self._dedup.process(alert)
        except Exception as e:
            log.debug(f"_score_single_packet error: {e}")
            return None

    def status(self) -> dict:
        return {
            "ready":         self._ready,
            "models_loaded": (
                (["cicids_rf"] if self._cicids_ready else []) +
                (["isolation_forest"] if self.iso else [])
            ),
            "active_flows":  len(self._aggregator._flows),
            "flow_timeout":  FLOW_TIMEOUT,
            "max_flow_pkts": MAX_FLOW_PKTS,
            "iso_threshold": self.iso_threshold,
            "min_conf":      MIN_ALERT_CONF,
            "ml_status":     dict(ML_STATUS),
        }


# ══════════════════════════════════════════════════════════════════
# Singleton
# ══════════════════════════════════════════════════════════════════

_detector: MLDetector | None = None
_detector_lock = threading.Lock()

def get_detector() -> MLDetector:
    global _detector
    if _detector is None:
        with _detector_lock:
            if _detector is None:
                _detector = MLDetector()
    return _detector
=======
"""
ml_detector.py
--------------
Isolation Forest anomaly detector.
- Loaded by live_monitor.py to score every packet in real-time.
- Loaded by network_analyzer.py to score PCAP flows.
- Model is trained by train_ml.py and saved to models/isolation_forest.pkl

Feature vector (10 features) extracted per packet/flow:
  0  packet_size        - total bytes
  1  is_tcp             - 1/0
  2  is_udp             - 1/0
  3  is_icmp            - 1/0
  4  dst_port           - destination port (0 if none)
  5  src_port           - source port (0 if none)
  6  is_syn             - TCP SYN flag
  7  is_fin             - TCP FIN flag
  8  is_rst             - TCP RST flag
  9  payload_size       - raw payload bytes
"""

import os
import pickle
import logging
import numpy as np

log = logging.getLogger(__name__)

BASE_DIR   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, "models", "isolation_forest.pkl")

FEATURE_NAMES = [
    "packet_size", "is_tcp", "is_udp", "is_icmp",
    "dst_port", "src_port", "is_syn", "is_fin", "is_rst",
    "payload_size",
]


def extract_features(pkt):
    """
    Extract a 10-element feature vector from a Scapy packet.
    Returns numpy array or None if packet can't be parsed.
    """
    try:
        from scapy.layers.inet import IP, TCP, UDP, ICMP

        size = len(pkt)
        is_tcp = int(pkt.haslayer(TCP))
        is_udp = int(pkt.haslayer(UDP))
        is_icmp = int(pkt.haslayer(ICMP))

        dst_port = 0
        src_port = 0
        is_syn = 0
        is_fin = 0
        is_rst = 0

        if pkt.haslayer(TCP):
            dst_port = int(pkt[TCP].dport)
            src_port = int(pkt[TCP].sport)
            flags = int(pkt[TCP].flags)
            is_syn = int(bool(flags & 0x02))
            is_fin = int(bool(flags & 0x01))
            is_rst = int(bool(flags & 0x04))
        elif pkt.haslayer(UDP):
            dst_port = int(pkt[UDP].dport)
            src_port = int(pkt[UDP].sport)

        # Payload size
        payload = 0
        if pkt.haslayer(TCP) and pkt[TCP].payload:
            payload = len(bytes(pkt[TCP].payload))
        elif pkt.haslayer(UDP) and pkt[UDP].payload:
            payload = len(bytes(pkt[UDP].payload))

        return np.array([
            size, is_tcp, is_udp, is_icmp,
            dst_port, src_port, is_syn, is_fin, is_rst,
            payload
        ], dtype=np.float32)

    except Exception:
        return None


def extract_features_from_dict(d):
    """
    Extract features from a plain dict (used for flow-based data).
    Dict keys: packet_size, protocol, dst_port, src_port, flags, payload_size
    """
    proto = d.get("protocol", "").upper()
    flags = d.get("flags", 0)
    return np.array([
        d.get("packet_size", 0),
        int(proto == "TCP"),
        int(proto == "UDP"),
        int(proto == "ICMP"),
        d.get("dst_port", 0),
        d.get("src_port", 0),
        int(bool(flags & 0x02)) if isinstance(flags, int) else 0,
        int(bool(flags & 0x01)) if isinstance(flags, int) else 0,
        int(bool(flags & 0x04)) if isinstance(flags, int) else 0,
        d.get("payload_size", 0),
    ], dtype=np.float32)


class MLDetector:
    """
    Wraps the Isolation Forest model.
    Usage:
        detector = MLDetector()
        if detector.ready:
            alert = detector.score_packet(pkt)
    """

    def __init__(self):
        self.model     = None
        self.scaler    = None          # StandardScaler saved during training
        self.threshold = -0.1
        self.ready     = False
        self._load()

    def _load(self):
        if os.path.exists(MODEL_PATH):
            try:
                with open(MODEL_PATH, "rb") as f:
                    saved = pickle.load(f)
                self.model     = saved["model"]
                self.scaler    = saved.get("scaler", None)   # may be None for old models
                self.threshold = saved.get("threshold", -0.1)
                self.ready     = True
                log.info(f"[ML] Model loaded from {MODEL_PATH}")
            except Exception as e:
                log.warning(f"[ML] Could not load model: {e}")
        else:
            log.info("[ML] No trained model found. Run train_ml.py to train one.")

    def score_packet(self, pkt):
        """Score a Scapy packet. Returns alert dict if anomalous, else None."""
        if not self.ready:
            return None
        features = extract_features(pkt)
        if features is None:
            return None
        return self._score(features, pkt)

    def score_flow(self, flow_dict):
        """Score a flow dict."""
        if not self.ready:
            return None
        features = extract_features_from_dict(flow_dict)
        return self._score_raw(features, flow_dict.get("src_ip", "?"), flow_dict.get("dst_ip", "?"))

    def _score(self, features, pkt):
        try:
            from scapy.layers.inet import IP
            src = pkt[IP].src if pkt.haslayer(IP) else "?"
            dst = pkt[IP].dst if pkt.haslayer(IP) else "?"
        except Exception:
            src, dst = "?", "?"
        return self._score_raw(features, src, dst)

    def _score_raw(self, features, src, dst):
        try:
            X = np.array([features], dtype=np.float32)
            # Apply the same scaler used during training
            if self.scaler is not None:
                X = self.scaler.transform(X)
            score = self.model.score_samples(X)[0]
            if score < self.threshold:
                severity = "CRITICAL" if score < -0.5 else "HIGH" if score < -0.35 else "MEDIUM"
                from datetime import datetime
                return {
                    "timestamp":   datetime.utcnow().isoformat(),
                    "alert_type":  "ML_ANOMALY",
                    "severity":    severity,
                    "message":     f"ML anomaly detected from {src} (score: {score:.3f})",
                    "source_ip":   src,
                    "destination_ip": dst,
                    "additional_info": {
                        "ml_score":  round(float(score), 4),
                        "threshold": self.threshold,
                        "detector":  "IsolationForest",
                    },
                }
        except Exception as e:
            log.debug(f"[ML] Scoring error: {e}")
        return None


# Singleton instance — import this in live_monitor and network_analyzer
_detector = None


def get_detector():
    global _detector
    if _detector is None:
        _detector = MLDetector()
    return _detector
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
=======
"""
ml_detector.py - PacketGuard ML Detection Engine
Provides: get_detector() → LiveDetector singleton
Used by: live_monitor.py
"""
import logging
import threading
import numpy as np
import joblib
import os
import warnings
from collections import defaultdict
from datetime import datetime, timezone

# Suppress sklearn noise — use message= filter because sklearn uses stacklevel>1,
# making warnings appear to originate from our code (module= filter won't match).
warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", category=FutureWarning)

log = logging.getLogger(__name__)

from sklearn.ensemble import RandomForestClassifier, VotingClassifier, IsolationForest
from sklearn.metrics import classification_report, accuracy_score, f1_score
from sklearn.utils.class_weight import compute_sample_weight
import xgboost as xgb

# --- CONFIG -----------------------------------------------
PROCESSED_DIR = os.environ.get(
    "PROCESSED_DIR",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "dataset", "processed"),
)
MODELS_DIR    = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")
os.makedirs(MODELS_DIR, exist_ok=True)


# --- TRAINING FUNCTIONS (run via: python ml_detector.py) --

def load_data():
    print("=" * 60)
    print("Loading processed data...")
    print("=" * 60)
    X_train = np.load(os.path.join(PROCESSED_DIR, 'X_train.npy'))
    X_test  = np.load(os.path.join(PROCESSED_DIR, 'X_test.npy'))
    y_train = np.load(os.path.join(PROCESSED_DIR, 'y_train.npy'))
    y_test  = np.load(os.path.join(PROCESSED_DIR, 'y_test.npy'))
    le      = joblib.load(os.path.join(PROCESSED_DIR, 'label_encoder.pkl'))
    feature_names = joblib.load(os.path.join(PROCESSED_DIR, 'feature_names.pkl'))
    print(f"X_train: {X_train.shape} | X_test: {X_test.shape}")
    print(f"Classes ({len(le.classes_)}): {list(le.classes_)}")
    return X_train, X_test, y_train, y_test, le, feature_names


def train_random_forest(X_train, y_train):
    print("\n" + "=" * 60)
    print("MODEL 1: Training Random Forest...")
    print("=" * 60)
    rf = RandomForestClassifier(
        n_estimators=100, max_depth=20, n_jobs=-1,
        random_state=42, class_weight='balanced', verbose=0
    )
    rf.fit(X_train, y_train)
    joblib.dump(rf, os.path.join(MODELS_DIR, 'rf_model.pkl'))
    print("✅ Random Forest saved.")
    return rf


def train_isolation_forest(X_train):
    print("\n" + "=" * 60)
    print("MODEL 2: Training Isolation Forest (Anomaly Detection)...")
    print("=" * 60)
    iso = IsolationForest(
        n_estimators=100, contamination=0.1,
        n_jobs=-1, random_state=42, verbose=0
    )
    iso.fit(X_train)
    joblib.dump(iso, os.path.join(MODELS_DIR, 'iso_model.pkl'))
    print("✅ Isolation Forest saved.")
    return iso


def train_xgboost(X_train, y_train):
    print("\n" + "=" * 60)
    print("MODEL 3: Training XGBoost...")
    print("=" * 60)
    sample_weights = compute_sample_weight('balanced', y_train)
    xgbm = xgb.XGBClassifier(
        n_estimators=300, learning_rate=0.05, max_depth=8,
        n_jobs=-1, random_state=42, eval_metric='mlogloss', verbosity=0
    )
    xgbm.fit(X_train, y_train, sample_weight=sample_weights)
    joblib.dump(xgbm, os.path.join(MODELS_DIR, 'xgb_model.pkl'))
    print("✅ XGBoost saved.")
    return xgbm


def train_ensemble(X_train, y_train, rf, xgbm):
    print("\n" + "=" * 60)
    print("MODEL 4: Building Ensemble (RF + XGBoost)...")
    print("=" * 60)
    ensemble = VotingClassifier(
        estimators=[('rf', rf), ('xgb', xgbm)],
        voting='soft', n_jobs=-1
    )
    print("Fitting ensemble...")
    ensemble.fit(X_train, y_train)
    joblib.dump(ensemble, os.path.join(MODELS_DIR, 'ensemble_model.pkl'))
    print("✅ Ensemble saved.")
    return ensemble


def evaluate(name, model, X_test, y_test, le, is_anomaly=False):
    print(f"\n--- {name} ---")
    if is_anomaly:
        preds        = model.predict(X_test)
        preds_binary = np.where(preds == -1, 1, 0)
        y_binary     = np.where(y_test == 0, 0, 1)
        acc = accuracy_score(y_binary, preds_binary)
        f1  = f1_score(y_binary, preds_binary, average='weighted')
        print(f"Accuracy: {acc * 100:.2f}%  |  F1: {f1 * 100:.2f}%")
        print("(Binary: BENIGN vs ATTACK)")
    else:
        preds = model.predict(X_test)
        acc   = accuracy_score(y_test, preds)
        f1    = f1_score(y_test, preds, average='weighted')
        print(f"Accuracy: {acc * 100:.2f}%  |  F1: {f1 * 100:.2f}%")
        print(classification_report(y_test, preds,
              target_names=le.classes_, zero_division=0))


# --- FLOW AGGREGATOR --------------------------------------
class FlowAggregator:
    """Aggregates raw packets into CIC-IDS2017 flow-level features."""

    def __init__(self, feature_names, timeout=3.0):
        self.feature_names = feature_names
        self.timeout       = timeout
        self.flows         = {}
        self.lock          = threading.Lock()
        self._on_flow_ready = None  # set by LiveDetector to (_predict, _fire_alert) pair
        self._start_flush_thread()

    def _flow_key(self, pkt):
        """Return a bidirectional flow key: both directions map to the same key.
        Convention: (client_ip, server_ip, client_port, server_port, proto)
        where the server has the lower well-known port."""
        try:
            from scapy.layers.inet import IP, TCP, UDP
            if not pkt.haslayer(IP):
                return None
            src = pkt[IP].src
            dst = pkt[IP].dst
            if pkt.haslayer(TCP):
                sport, dport, proto = pkt[TCP].sport, pkt[TCP].dport, 6
            elif pkt.haslayer(UDP):
                sport, dport, proto = pkt[UDP].sport, pkt[UDP].dport, 17
            else:
                sport, dport, proto = 0, 0, 0
            # Normalize: only swap when sport is a well-known server port (<1024).
            # This keeps bidirectional tracking for SSH/FTP/HTTP/HTTPS/etc. while
            # avoiding false-positive swaps for high ports like 5000 (our web app).
            if sport < 1024 and dport >= 1024:
                return (dst, src, dport, sport, proto)
            return (src, dst, sport, dport, proto)
        except Exception:
            return None

    def ingest(self, pkt):
        import time
        key = self._flow_key(pkt)
        if key is None:
            return None
        now = time.time()
        with self.lock:
            if key not in self.flows:
                self.flows[key] = {
                    'start':    now,  'last':    now,
                    'pkts_fwd': 0,    'pkts_bwd': 0,
                    'bytes_fwd': [],  'bytes_bwd': [],
                    'iat_fwd':  [],   'iat_bwd':  [],
                    'flags':    defaultdict(int),
                    'last_fwd': now,  'last_bwd': now,
                    'act_data_pkts_fwd': 0,
                    'init_win_fwd': None,
                    'init_win_bwd': None,
                    # ── Bulk tracking (CICFlowMeter spec) ──────────────
                    # A bulk = ≥4 consecutive same-direction pkts, IAT < 1s
                    'blk_f_cnt': 0,   'blk_f_bytes': 0, 'blk_f_pkts': 0, 'blk_f_dur': 0.0,
                    'blk_f_cur_p': 0, 'blk_f_cur_b': 0, 'blk_f_cur_t': now,
                    'blk_b_cnt': 0,   'blk_b_bytes': 0, 'blk_b_pkts': 0, 'blk_b_dur': 0.0,
                    'blk_b_cur_p': 0, 'blk_b_cur_b': 0, 'blk_b_cur_t': now,
                }
            flow = self.flows[key]
            size = len(pkt)
            try:
                from scapy.layers.inet import IP as _IP
                is_fwd = pkt.haslayer(_IP) and pkt[_IP].src == key[0]
            except Exception:
                is_fwd = True

            _BULK_MIN_PKTS = 4      # min consecutive packets to count as a bulk
            _BULK_IAT_MAX  = 1.0   # max IAT (seconds) within a bulk

            if is_fwd:
                if flow['pkts_fwd'] > 0:
                    iat_f = now - flow['last_fwd']
                    flow['iat_fwd'].append(iat_f)
                    # Bulk logic — forward direction
                    if iat_f <= _BULK_IAT_MAX:
                        flow['blk_f_cur_p'] += 1
                        flow['blk_f_cur_b'] += size
                    else:
                        if flow['blk_f_cur_p'] >= _BULK_MIN_PKTS:
                            flow['blk_f_cnt']   += 1
                            flow['blk_f_bytes'] += flow['blk_f_cur_b']
                            flow['blk_f_pkts']  += flow['blk_f_cur_p']
                            flow['blk_f_dur']   += (flow['last_fwd'] - flow['blk_f_cur_t'])
                        flow['blk_f_cur_p'] = 1
                        flow['blk_f_cur_b'] = size
                        flow['blk_f_cur_t'] = now
                else:
                    flow['blk_f_cur_p'] = 1
                    flow['blk_f_cur_b'] = size
                    flow['blk_f_cur_t'] = now
                flow['last_fwd'] = now
                flow['pkts_fwd'] += 1
                flow['bytes_fwd'].append(size)
                if size > 40:
                    flow['act_data_pkts_fwd'] += 1
            else:
                if flow['pkts_bwd'] > 0:
                    iat_b = now - flow['last_bwd']
                    flow['iat_bwd'].append(iat_b)
                    # Bulk logic — backward direction
                    if iat_b <= _BULK_IAT_MAX:
                        flow['blk_b_cur_p'] += 1
                        flow['blk_b_cur_b'] += size
                    else:
                        if flow['blk_b_cur_p'] >= _BULK_MIN_PKTS:
                            flow['blk_b_cnt']   += 1
                            flow['blk_b_bytes'] += flow['blk_b_cur_b']
                            flow['blk_b_pkts']  += flow['blk_b_cur_p']
                            flow['blk_b_dur']   += (flow['last_bwd'] - flow['blk_b_cur_t'])
                        flow['blk_b_cur_p'] = 1
                        flow['blk_b_cur_b'] = size
                        flow['blk_b_cur_t'] = now
                else:
                    flow['blk_b_cur_p'] = 1
                    flow['blk_b_cur_b'] = size
                    flow['blk_b_cur_t'] = now
                flow['last_bwd'] = now
                flow['pkts_bwd'] += 1
                flow['bytes_bwd'].append(size)

            try:
                from scapy.layers.inet import TCP as _TCP
                if pkt.haslayer(_TCP):
                    tcp = pkt[_TCP]
                    flags = tcp.flags
                    for fname, fbit in [('FIN', 0x01), ('SYN', 0x02), ('RST', 0x04),
                                        ('PSH', 0x08), ('ACK', 0x10), ('URG', 0x20)]:
                        if flags & fbit:
                            flow['flags'][fname] += 1
                    # Capture initial TCP window size (first SYN packet per direction)
                    if flags & 0x02:  # SYN flag
                        if is_fwd and flow['init_win_fwd'] is None:
                            flow['init_win_fwd'] = int(tcp.window)
                        elif not is_fwd and flow['init_win_bwd'] is None:
                            flow['init_win_bwd'] = int(tcp.window)
            except Exception:
                pass

            flow['last'] = now

            total_pkts = flow['pkts_fwd'] + flow['pkts_bwd']
            # Close flow immediately on TCP FIN or RST (connection ended)
            tcp_closed = bool(flow['flags']['FIN'] or flow['flags']['RST'])
            if (now - flow['start'] >= self.timeout or
                    total_pkts >= 60 or
                    (tcp_closed and total_pkts >= 2)):
                features = self._extract(flow, key)
                del self.flows[key]
                return features
        return None

    def flush_stale(self) -> list:
        """Return feature dicts for all flows that have exceeded the timeout.
        Called by the background flush thread so short-lived flows are not lost.
        Min 1 packet — nmap SYN scans create 1-packet flows (RST is from own IP,
        skipped by live_monitor) so they must be scored via flush, not ingest."""
        import time as _t
        now  = _t.time()
        done = []
        with self.lock:
            stale = [k for k, f in self.flows.items()
                     if now - f['last'] >= self.timeout and
                        (f['pkts_fwd'] + f['pkts_bwd']) >= 1]
            for k in stale:
                done.append(self._extract(self.flows.pop(k), k))
        return done

    def _start_flush_thread(self):
        """Background thread: flush stale flows every (timeout/2) seconds."""
        def _loop():
            import time as _t
            while True:
                _t.sleep(self.timeout / 2)
                try:
                    ready = self.flush_stale()
                    if ready and callable(self._on_flow_ready):
                        for feat in ready:
                            self._on_flow_ready(feat)
                except Exception:
                    pass
        t = threading.Thread(target=_loop, daemon=True, name='flow-flusher')
        t.start()

    def _safe_stat(self, arr):
        if not arr:
            return 0.0, 0.0, 0.0, 0.0
        a = np.array(arr, dtype=float)
        return float(a.mean()), float(a.std()), float(a.max()), float(a.min())

    _BULK_MIN_PKTS = 4
    _BULK_IAT_MAX  = 1.0
    _ACTIVE_TIMEOUT = 5.0   # seconds — matches flow timeout

    def _bulk_features(self, flow: dict) -> dict:
        """
        Finalise any in-progress bulk and return the 6 CICFlowMeter bulk features.
        Called from _extract() so the flow dict is already closed (no lock needed).
        """
        def _finalise(cnt, total_b, total_p, total_d, cur_p, cur_b, cur_t, last_t):
            if cur_p >= self._BULK_MIN_PKTS:
                cnt     += 1
                total_b += cur_b
                total_p += cur_p
                total_d += max(last_t - cur_t, 0.0)
            avg_bytes  = total_b / cnt if cnt > 0 else 0.0
            avg_pkts   = total_p / cnt if cnt > 0 else 0.0
            avg_rate   = total_b / total_d if total_d > 0 else 0.0
            return avg_bytes, avg_pkts, avg_rate

        f_bytes, f_pkts, f_rate = _finalise(
            flow['blk_f_cnt'], flow['blk_f_bytes'], flow['blk_f_pkts'], flow['blk_f_dur'],
            flow['blk_f_cur_p'], flow['blk_f_cur_b'], flow['blk_f_cur_t'], flow['last_fwd'],
        )
        b_bytes, b_pkts, b_rate = _finalise(
            flow['blk_b_cnt'], flow['blk_b_bytes'], flow['blk_b_pkts'], flow['blk_b_dur'],
            flow['blk_b_cur_p'], flow['blk_b_cur_b'], flow['blk_b_cur_t'], flow['last_bwd'],
        )
        return {
            'Fwd Avg Bytes/Bulk':   f_bytes,
            'Fwd Avg Packets/Bulk': f_pkts,
            'Fwd Avg Bulk Rate':    f_rate,
            'Bwd Avg Bytes/Bulk':   b_bytes,
            'Bwd Avg Packets/Bulk': b_pkts,
            'Bwd Avg Bulk Rate':    b_rate,
        }

    def _active_idle_features(self, all_iat: list) -> dict:
        """
        Compute Active/Idle Mean/Std/Max/Min from the combined IAT list.
        Active period  = sequence of consecutive IATs all < ACTIVE_TIMEOUT.
        Idle period    = a single IAT >= ACTIVE_TIMEOUT (a gap between active periods).
        """
        active, idle, cur = [], [], 0.0
        for iat in all_iat:
            if iat < self._ACTIVE_TIMEOUT:
                cur += iat
            else:
                if cur > 0:
                    active.append(cur)
                    cur = 0.0
                idle.append(iat)
        if cur > 0:
            active.append(cur)

        def _stats(arr):
            if not arr:
                return 0.0, 0.0, 0.0, 0.0
            a = np.array(arr, dtype=float)
            return float(a.mean()), float(a.std()), float(a.max()), float(a.min())

        am, astd, amax, amin = _stats(active)
        im, istd, imax, imin = _stats(idle)
        return {
            'Active Mean': am,   'Active Std': astd,
            'Active Max':  amax, 'Active Min': amin,
            'Idle Mean':   im,   'Idle Std':   istd,
            'Idle Max':    imax, 'Idle Min':   imin,
        }

    def _extract(self, flow, key):
        duration   = max(flow['last'] - flow['start'], 1e-6)
        all_bytes  = flow['bytes_fwd'] + flow['bytes_bwd']
        all_iat    = flow['iat_fwd']   + flow['iat_bwd']
        fwd_mean,  fwd_std,  fwd_max,  fwd_min  = self._safe_stat(flow['bytes_fwd'])
        bwd_mean,  bwd_std,  bwd_max,  bwd_min  = self._safe_stat(flow['bytes_bwd'])
        pkt_mean,  pkt_std,  pkt_max,  pkt_min  = self._safe_stat(all_bytes)
        iat_mean,  iat_std,  iat_max,  iat_min  = self._safe_stat(all_iat)
        fiat_mean, fiat_std, fiat_max, fiat_min = self._safe_stat(flow['iat_fwd'])
        biat_mean, biat_std, biat_max, biat_min = self._safe_stat(flow['iat_bwd'])
        total_fwd   = sum(flow['bytes_fwd'])
        total_bwd   = sum(flow['bytes_bwd'])
        total_pkts  = flow['pkts_fwd'] + flow['pkts_bwd']
        total_bytes = total_fwd + total_bwd
        if key[4] == 6:
            _proto_str = 'TCP'
        elif key[4] == 17:
            _proto_str = 'UDP'
        else:
            _proto_str = 'OTHER'
        return {
            # Private metadata for _fire_alert_from_feat (stripped before prediction)
            '_src_ip':  key[0],
            '_dst_ip':  key[1],
            '_sport':   key[2],
            '_dport':   key[3],
            '_proto':   _proto_str,
            'Destination Port':             key[3],
            'Flow Duration':                duration * 1e6,
            'Total Fwd Packets':            flow['pkts_fwd'],
            'Total Backward Packets':       flow['pkts_bwd'],
            'Total Length of Fwd Packets':  total_fwd,
            'Total Length of Bwd Packets':  total_bwd,
            'Fwd Packet Length Max':        fwd_max,
            'Fwd Packet Length Min':        fwd_min,
            'Fwd Packet Length Mean':       fwd_mean,
            'Fwd Packet Length Std':        fwd_std,
            'Bwd Packet Length Max':        bwd_max,
            'Bwd Packet Length Min':        bwd_min,
            'Bwd Packet Length Mean':       bwd_mean,
            'Bwd Packet Length Std':        bwd_std,
            'Flow Bytes/s':                 total_bytes / duration,
            'Flow Packets/s':               total_pkts  / duration,
            'Flow IAT Mean':                iat_mean,
            'Flow IAT Std':                 iat_std,
            'Flow IAT Max':                 iat_max,
            'Flow IAT Min':                 iat_min,
            'Fwd IAT Total':                sum(flow['iat_fwd']),
            'Fwd IAT Mean':                 fiat_mean,
            'Fwd IAT Std':                  fiat_std,
            'Fwd IAT Max':                  fiat_max,
            'Fwd IAT Min':                  fiat_min,
            'Bwd IAT Total':                sum(flow['iat_bwd']),
            'Bwd IAT Mean':                 biat_mean,
            'Bwd IAT Std':                  biat_std,
            'Bwd IAT Max':                  biat_max,
            'Bwd IAT Min':                  biat_min,
            'Fwd PSH Flags':                flow['flags']['PSH'],
            'Bwd PSH Flags':                0,
            'Fwd URG Flags':                flow['flags']['URG'],
            'Bwd URG Flags':                0,
            'Fwd Header Length':            flow['pkts_fwd'] * 40,
            'Bwd Header Length':            flow['pkts_bwd'] * 40,
            'Fwd Packets/s':                flow['pkts_fwd'] / duration,
            'Bwd Packets/s':                flow['pkts_bwd'] / duration,
            'Min Packet Length':            pkt_min,
            'Max Packet Length':            pkt_max,
            'Packet Length Mean':           pkt_mean,
            'Packet Length Std':            pkt_std,
            'Packet Length Variance':       pkt_std ** 2,
            'FIN Flag Count':               flow['flags']['FIN'],
            'SYN Flag Count':               flow['flags']['SYN'],
            'RST Flag Count':               flow['flags']['RST'],
            'PSH Flag Count':               flow['flags']['PSH'],
            'ACK Flag Count':               flow['flags']['ACK'],
            'URG Flag Count':               flow['flags']['URG'],
            'CWE Flag Count':               0,
            'ECE Flag Count':               0,
            'Down/Up Ratio':                (total_bwd / total_fwd) if total_fwd > 0 else 0,
            'Average Packet Size':          pkt_mean,
            'Avg Fwd Segment Size':         fwd_mean,
            'Avg Bwd Segment Size':         bwd_mean,
            'Fwd Header Length.1':          flow['pkts_fwd'] * 40,
            # ── Bulk features ─────────────────────────────────────
            # Finalise any in-progress bulk before computing averages
            **self._bulk_features(flow),
            'Subflow Fwd Packets':          flow['pkts_fwd'],
            'Subflow Fwd Bytes':            total_fwd,
            'Subflow Bwd Packets':          flow['pkts_bwd'],
            'Subflow Bwd Bytes':            total_bwd,
            'Init_Win_bytes_forward':       flow.get('init_win_fwd') or 0,
            'Init_Win_bytes_backward':      flow.get('init_win_bwd') or 0,
            'act_data_pkt_fwd':             flow.get('act_data_pkts_fwd', 0),
            'min_seg_size_forward':         max(int(fwd_min) - 40, 0),
            # ── Active / Idle features ────────────────────────────
            **self._active_idle_features(all_iat),
        }


# --- LIVE DETECTOR ----------------------------------------
class LiveDetector:
    """
    Singleton ML detector used by live_monitor.py.
    Access via get_detector().
    Exposes: .ready, .status(), .score_packet(pkt), .on_alert
    """
    def __init__(self):
        self.scaler    = None
        self.le        = None
        self.features  = None
        self.ensemble  = None
        self.iso       = None
        self.rf        = None
        self.xgb_model = None
        self.ready     = False
        self.on_alert  = None
        self._agg      = None
        # Per-instance dedup cache - not a class variable (avoids shared-state issues)
        self._dedup_cache: dict = {}
        self._DEDUP_WINDOW         = 30    # suppress repeat src+label within 30 s
        self._MIN_CONF             = 0.80  # minimum confidence to fire an attack alert
        self._MIN_ANOMALY_CONF     = 0.80  # minimum (1-benign_conf) to fire iso-forest anomaly
        self._MAX_BENIGN_CONF      = 0.20  # anomaly fires only when benign conf < 20% (strong signal)
        self._ANOMALY_DEDUP_WINDOW = 300   # suppress iso-forest-only anomalies for 5 min/IP
        # Recent ML-confirmed attacks: {ip: {'label': str, 'confidence': float, 'ts': float}}
        # Used by the ML validation gate in live_monitor to skip the wait for known-bad IPs.
        self._recent_attacks: dict = {}
        self._load_models()

    def _load_models(self):
        try:
            # Load ALL preprocessing artifacts from MODELS_DIR so scaler, label encoder,
            # and feature list always match the trained models saved there.
            # PROCESSED_DIR contains a separate scaler fit on pre-normalized data — using
            # it with these models produces wrong scaled inputs (70/78 features mismatched).
            self.scaler   = self._try_load('scaler.pkl')
            self.le       = self._try_load('label_encoder.pkl')
            self.features = self._try_load('feature_names.pkl')

            if self.scaler is None or self.le is None or self.features is None:
                raise FileNotFoundError(
                    "scaler.pkl / label_encoder.pkl / feature_names.pkl not found "
                    f"in {MODELS_DIR}"
                )

            # trained models live in models/
            self.ensemble  = self._try_load('ensemble_model.pkl')
            self.iso       = self._try_load('iso_model.pkl')
            self.rf        = self._try_load('rf_model.pkl')
            self.xgb_model = self._try_load('xgb_model.pkl')
            # Silence verbose=1 baked into saved pickle files
            for _m in [self.rf, self.iso, self.xgb_model]:
                if _m is not None and hasattr(_m, 'verbose'):
                    _m.verbose = 0
            if self.ensemble is not None:
                # estimators_ is a flat list of fitted estimators (not name-tuples)
                for _est in getattr(self.ensemble, 'estimators_', None) or []:
                    if hasattr(_est, 'verbose'):
                        _est.verbose = 0
            self._agg = FlowAggregator(self.features, timeout=3.0)
            # Wire flush thread so stale/short flows are scored automatically
            self._agg._on_flow_ready = self._score_feat_dict
            self.ready = True
            n = sum(1 for m in [self.ensemble, self.iso, self.rf, self.xgb_model] if m)
            print(f"[MLDetector] All models loaded. ({n} models ready)")
        except Exception as e:
            print(f"[MLDetector] Could not load models: {e}")
            self.ready = False

    def _try_load(self, filename):
        path = os.path.join(MODELS_DIR, filename)
        return joblib.load(path) if os.path.exists(path) else None

    def _try_load_path(self, directory, filename):
        path = os.path.join(directory, filename)
        return joblib.load(path) if os.path.exists(path) else None

    def status(self):
        active_flows = 0
        try:
            if self._agg is not None:
                with self._agg.lock:
                    active_flows = len(self._agg.flows)
        except Exception:
            pass
        return {
            'ready':         self.ready,
            'models_loaded': sum(1 for m in [self.ensemble, self.iso, self.rf, self.xgb_model] if m),
            'active_flows':  active_flows,
            'flow_timeout':  getattr(self._agg, 'timeout', 5),
            'iso_threshold': 0.1,
            'min_conf':      self._MIN_CONF if self.ready else 0.6,
        }

    def score_packet(self, pkt):
        """Called per-packet from live_monitor.handle_packet().
        ALL packets are fed into the flow aggregator (including own-IP responses)
        so that backward features (pkts_bwd, bwd lengths, down/up ratio) are tracked.
        Alerts are only fired for flows whose source IP is NOT this machine."""
        if not self.ready or self._agg is None:
            return
        try:
            feat_dict = self._agg.ingest(pkt)
            if feat_dict is None:
                return
            # Don't alert on flows initiated by this machine
            try:
                from live_monitor import _own_ips as _lm_own_ips
                if feat_dict.get('_src_ip', '') in _lm_own_ips:
                    return
            except Exception:
                pass
            result = self._predict(feat_dict)
            if not result:
                return
            attack_hit  = result['is_attack']  and result['confidence'] >= self._MIN_CONF
            anomaly_hit = (result['is_anomaly'] and not result['is_attack']
                           and (1 - result['confidence']) >= self._MIN_ANOMALY_CONF)
            if attack_hit or anomaly_hit:
                self._fire_alert(result, pkt, feat_dict)
        except Exception as e:
            print(f"[MLDetector] score_packet error: {e}")

    def _score_feat_dict(self, feat_dict: dict):
        """Called by FlowAggregator flush thread for flows completed without a triggering packet."""
        if not self.ready:
            return
        try:
            result = self._predict(feat_dict)
            if not result:
                return
            src = str(feat_dict.get('_src_ip', 'unknown'))
            dst = str(feat_dict.get('_dst_ip', 'unknown'))
            # Skip flows originating from this machine — same guard as score_packet()
            try:
                from live_monitor import _own_ips as _monitor_own_ips
                if src in _monitor_own_ips:
                    return
            except Exception:
                pass
            attack_hit  = result['is_attack']  and result['confidence'] >= self._MIN_CONF
            anomaly_hit = (result['is_anomaly'] and not result['is_attack']
                           and (1 - result['confidence']) >= self._MIN_ANOMALY_CONF)
            if attack_hit or anomaly_hit:
                self._fire_alert_from_feat(result, src, dst, feat_dict)
        except Exception as e:
            print(f"[MLDetector] _score_feat_dict error: {e}")

    def _predict(self, features: dict) -> dict:
        """Run ALL loaded classifiers and pick the highest-confidence result.
        Previously only the ensemble ran (others were dead fallbacks). Now RF and
        XGB vote too — if any model detects an attack above threshold, it fires."""
        try:
            import pandas as pd
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                vec_df     = pd.DataFrame([{f: features.get(f, 0) for f in self.features}])
                vec_scaled = self.scaler.transform(vec_df)

                # ── Run every loaded classifier ──────────────────────────────
                _model_names = {
                    id(self.ensemble):  'Ensemble(RF+XGB)',
                    id(self.xgb_model): 'XGBoost',
                    id(self.rf):        'RandomForest',
                }
                votes = []       # list of (label, confidence, model_name)
                for mdl in [self.ensemble, self.xgb_model, self.rf]:
                    if mdl is None:
                        continue
                    try:
                        proba     = mdl.predict_proba(vec_scaled)[0]
                        idx       = int(np.argmax(proba))
                        lbl       = self.le.inverse_transform([idx])[0]
                        conf      = float(proba[idx])
                        votes.append((lbl, conf, _model_names.get(id(mdl), 'Unknown')))
                    except Exception:
                        pass

                if not votes:
                    return None

                # ── Pick best result ─────────────────────────────────────────
                # Priority: highest-confidence attack across all models wins.
                # If all say BENIGN, use the ensemble's (or highest) confidence.
                attack_votes = [(lbl, conf, nm) for lbl, conf, nm in votes if lbl != 'BENIGN']
                if attack_votes:
                    label, confidence, winner = max(attack_votes, key=lambda x: x[1])
                else:
                    label, confidence, winner = max(votes, key=lambda x: x[1])

                # ── Isolation Forest ─────────────────────────────────────────
                is_anomaly = False
                iso_score  = None
                if self.iso:
                    is_anomaly = bool(self.iso.predict(vec_scaled)[0] == -1)
                    try:
                        iso_score = float(self.iso.decision_function(vec_scaled)[0])
                    except Exception:
                        pass

            return {
                'label':       label,
                'confidence':  confidence,
                'is_attack':   label != 'BENIGN',
                'is_anomaly':  is_anomaly,
                'iso_score':   iso_score,
                'voted_by':    winner,
                'num_votes':   len(votes),
                'attack_votes': [(lbl, round(conf, 4), nm) for lbl, conf, nm in attack_votes],
            }
        except Exception as e:
            print(f"[MLDetector] _predict error: {e}")
            return None

    def _top_feature(self, feat_dict: dict) -> str:
        """Return the name of the feature that deviates most from zero (scaled baseline)."""
        try:
            # Features most diagnostic for attack detection
            PRIORITY = [
                'SYN Flag Count', 'Flow Packets/s', 'Flow Bytes/s',
                'Total Fwd Packets', 'RST Flag Count', 'Flow Duration',
                'Fwd Packet Length Mean', 'Bwd Packet Length Mean',
                'Destination Port', 'PSH Flag Count',
            ]
            best, best_val = '', 0.0
            for feat in PRIORITY:
                val = abs(float(feat_dict.get(feat, 0) or 0))
                if val > best_val:
                    best_val = val
                    best = feat
            return best or 'packet_rate_deviation'
        except Exception:
            return 'packet_rate_deviation'

    def _fire_alert_from_feat(self, result, src, dst, feat_dict):
        """Fire an alert built purely from feat_dict (used by flush thread — no packet available)."""
        dst_port = feat_dict.get('_dport') or feat_dict.get('Destination Port')
        protocol = feat_dict.get('_proto', 'UNKNOWN')
        self._build_and_dispatch_alert(result, src, dst, dst_port, protocol, feat_dict)

    def _fire_alert(self, result, pkt, feat_dict=None):
        try:
            from scapy.layers.inet import IP, TCP, UDP
            src      = pkt[IP].src  if pkt.haslayer(IP)  else 'unknown'
            dst      = pkt[IP].dst  if pkt.haslayer(IP)  else 'unknown'
            dst_port = None
            protocol = None
            if pkt.haslayer(TCP):
                dst_port = pkt[TCP].dport
                protocol = 'TCP'
            elif pkt.haslayer(UDP):
                dst_port = pkt[UDP].dport
                protocol = 'UDP'
        except Exception:
            src, dst, dst_port, protocol = 'unknown', 'unknown', None, None
        self._build_and_dispatch_alert(result, src, dst, dst_port, protocol, feat_dict)

    def _build_and_dispatch_alert(self, result, src, dst, dst_port, protocol, feat_dict=None):
        import time as _time
        # Dedup: suppress identical src+label within dedup window
        # Anomaly-only (BENIGN classified) hits use a much longer window (5 min)
        # to prevent iso-forest flooding on legitimate CDN/cloud traffic.
        is_anomaly_only = result.get('is_anomaly', False) and not result.get('is_attack', False)
        dedup_window  = self._ANOMALY_DEDUP_WINDOW if is_anomaly_only else self._DEDUP_WINDOW
        dedup_key     = f"{src}|{'ANOMALY' if is_anomaly_only else result['label']}"
        now           = _time.time()
        if now - self._dedup_cache.get(dedup_key, 0) < dedup_window:
            return
        self._dedup_cache[dedup_key] = now
        if len(self._dedup_cache) > 500:
            cutoff = now - self._DEDUP_WINDOW
            self._dedup_cache = {k: v for k, v in self._dedup_cache.items() if v > cutoff}

        fd          = feat_dict or {}
        total_pkts  = int((fd.get('Total Fwd Packets', 0) or 0) +
                          (fd.get('Total Backward Packets', 0) or 0))
        total_bytes = int((fd.get('Total Length of Fwd Packets', 0) or 0) +
                          (fd.get('Total Length of Bwd Packets', 0) or 0))
        pkt_rate    = round(float(fd.get('Flow Packets/s', 0) or 0), 2)
        syn_count   = int(fd.get('SYN Flag Count', 0) or 0)
        rst_count   = int(fd.get('RST Flag Count', 0) or 0)
        top_feature = self._top_feature(fd)
        model_name  = result.get('voted_by', (
                       'Ensemble (RF+XGB)' if self.ensemble else
                       'XGBoost'           if self.xgb_model else
                       'Random Forest'     if self.rf else 'Unknown'))

        is_attack = result.get('is_attack', False)
        is_anomaly_only = result.get('is_anomaly', False) and not is_attack

        if is_attack:
            alert_type   = f"ML_{result['label'].replace(' ', '_').upper()}"
            severity     = 'CRITICAL' if result['confidence'] > 0.95 else 'HIGH'
            display_conf = result['confidence']   # attack probability — already meaningful
            message      = (f"ML detected {result['label']} from {src} "
                            f"(confidence: {result['confidence']:.1%})")
        else:
            # Anomaly-only: classifier said BENIGN but iso-forest disagrees.
            # Show 1 - benign_conf as the anomaly confidence so the number
            # means "how sure the model is this is NOT normal traffic".
            alert_type   = 'ML_ANOMALY'
            severity     = 'MEDIUM' if (1 - result['confidence']) > 0.90 else 'LOW'
            display_conf = round(1 - result['confidence'], 4)
            message      = (f"Anomalous flow from {src} — iso-forest flagged "
                            f"(anomaly confidence: {display_conf:.1%}, top signal: {top_feature})")

        alert = {
            'timestamp':        datetime.now(timezone.utc).isoformat(),
            'alert_type':       alert_type,
            'severity':         severity,
            'message':          message,
            'source_ip':        src,
            'destination_ip':   dst,
            'destination_port': dst_port,
            'protocol':         protocol,
            'confidence':       display_conf,
            'ml_label':         result['label'],
            'model':            model_name,
            'top_feature':      top_feature,
            'additional_info': {
                'rf_label':        result['label'],
                'confidence':      display_conf,
                'iso_score':       result.get('iso_score'),
                'fused_score':     display_conf,
                'is_anomaly':      result['is_anomaly'],
                'benign_conf_raw': result['confidence'],
                'model':           model_name,
                'voted_by':        result.get('voted_by'),
                'num_votes':       result.get('num_votes', 0),
                'attack_votes':    result.get('attack_votes', []),
                'top_feature':     top_feature,
                'flow_pkts':       total_pkts  if total_pkts  else None,
                'flow_bytes':      total_bytes if total_bytes else None,
                'rate':            pkt_rate    if pkt_rate    else None,
                'syn_count':       syn_count   if syn_count   else None,
                'rst_count':       rst_count   if rst_count   else None,
                'dst_port':        dst_port,
                'protocol':        protocol,
            },
        }
        # Track recent ML-confirmed attacks for the validation gate
        if is_attack and src not in ('unknown', ''):
            self._recent_attacks[src] = {
                'label': result['label'],
                'confidence': result['confidence'],
                'ts': now,
            }
            # Evict stale entries (older than 5 min) to keep the dict small
            if len(self._recent_attacks) > 200:
                cutoff = now - 300
                self._recent_attacks = {k: v for k, v in self._recent_attacks.items()
                                        if v['ts'] > cutoff}

        if callable(self.on_alert):
            self.on_alert(alert)

    def predict(self, features: dict) -> dict:
        """Direct prediction from feature dict - for testing."""
        return self._predict(features)


# --- SINGLETON --------------------------------------------
_detector_instance = None
_detector_lock     = threading.Lock()


def get_detector() -> LiveDetector:
    """Returns the singleton LiveDetector. Called by live_monitor.py."""
    global _detector_instance
    with _detector_lock:
        if _detector_instance is None:
            _detector_instance = LiveDetector()
    return _detector_instance


# --- MAIN (training mode only) ----------------------------
if __name__ == '__main__':
    X_train, X_test, y_train, y_test, le, feature_names = load_data()
    num_classes = len(le.classes_)

    rf   = train_random_forest(X_train, y_train)
    iso  = train_isolation_forest(X_train)
    xgbm = train_xgboost(X_train, y_train)
    ens  = train_ensemble(X_train, y_train, rf, xgbm)

    print("\n" + "=" * 60)
    print("FINAL EVALUATION")
    print("=" * 60)
    evaluate("Random Forest",    rf,   X_test, y_test, le)
    evaluate("Isolation Forest", iso,  X_test, y_test, le, is_anomaly=True)
    evaluate("XGBoost",          xgbm, X_test, y_test, le)
    evaluate("Ensemble",         ens,  X_test, y_test, le)

    print("""
╔----------------------------------------------------------╗
║           ALL MODELS TRAINED AND SAVED ✅                ║
║  Models: rf_model.pkl, iso_model.pkl,                   ║
║          xgb_model.pkl, ensemble_model.pkl              ║
║  get_detector() ready for live_monitor.py!              ║
╚----------------------------------------------------------╝
    """)
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
