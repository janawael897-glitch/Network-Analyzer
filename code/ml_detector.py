#!/usr/bin/env python3
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
