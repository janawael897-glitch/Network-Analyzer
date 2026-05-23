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
