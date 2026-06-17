#!/usr/bin/env python3
"""
Network Traffic Analyzer for Threat Detection
Main entry point for the threat detection system
"""

import sys
<<<<<<< HEAD
<<<<<<< HEAD
import os
import logging
import pickle
import threading
import numpy as np
import pandas as pd
from scapy.all import sniff, rdpcap, IP, TCP, UDP, ICMP, DNS, Raw
from collections import defaultdict, Counter
import time
import json
import socket
import struct
from datetime import datetime
import warnings
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")
=======
=======
import os
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
import logging
import pickle
import threading
import numpy as np
import pandas as pd
from scapy.all import sniff, rdpcap, IP, TCP, UDP, ICMP, DNS, Raw
from collections import defaultdict, Counter
import time
import json
import socket
import struct
from datetime import datetime
<<<<<<< HEAD

>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
=======
import warnings
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('network_analyzer.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

<<<<<<< HEAD
<<<<<<< HEAD
# ── Paths ────────────────────────────────────────────────────────
=======
# -- Paths --------------------------------------------------------
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
BASE_DIR       = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR     = os.path.join(BASE_DIR, "models")
ALERTS_FILE    = os.path.join(BASE_DIR, "alerts.json")
ML_ALERTS_FILE = os.path.join(BASE_DIR, "ml_alerts.json")
LIVE_STATE_FILE= os.path.join(BASE_DIR, "live_state.json")

<<<<<<< HEAD
# ── CICIDS2017 feature names — must match training exactly ────────
=======
# -- CICIDS2017 feature names - must match training exactly --------
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
FEATURE_NAMES = [
    "Destination Port", "Flow Duration",
    "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Fwd Packet Length Max", "Fwd Packet Length Mean",
    "Bwd Packet Length Max", "Bwd Packet Length Mean",
    "Flow Bytes/s", "Flow Packets/s",
    "Flow IAT Mean", "Flow IAT Std",
    "Fwd IAT Mean", "Bwd IAT Mean",
    "Fwd PSH Flags", "SYN Flag Count",
    "RST Flag Count", "Average Packet Size",
]

<<<<<<< HEAD
# ── Severity for ML classes ───────────────────────────────────────
=======
# -- Severity for ML classes ---------------------------------------
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
CLASS_SEVERITY = {
    "BENIGN": None, "BRUTE_FORCE": "HIGH", "DDOS": "CRITICAL",
    "DOS": "CRITICAL", "HEARTBLEED": "CRITICAL",
    "INFILTRATION": "CRITICAL", "OTHER": "MEDIUM", "PORT_SCAN": "HIGH",
}

<<<<<<< HEAD
# ── Whitelist — never flagged ────────────────────────────────────
=======
# -- Whitelist - never flagged ------------------------------------
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
WHITELIST = {
    "127.0.0.1", "0.0.0.0",
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
    "192.168.1.1", "192.168.0.1", "10.0.0.1",
}

<<<<<<< HEAD
# ── Per-type cooldowns (seconds) ─────────────────────────────────
=======
# -- Per-type cooldowns (seconds) ---------------------------------
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
COOLDOWN = {
    "PORT_SCAN": 30, "SYN_FLOOD": 10, "PACKET_FLOOD": 10,
    "DGA_DOMAIN": 60, "C2_BEACONING": 60,
    "DATA_EXFILTRATION": 120, "ABNORMAL_SIZE": 30,
    "MALFORMED_PACKET": 30,
}



<<<<<<< HEAD
# ══════════════════════════════════════════════════════════════════
# ML MODEL  (CICIDS2017 Random Forest)
# ══════════════════════════════════════════════════════════════════
=======
# ------------------------------------------------------------------
# ML MODEL  (CICIDS2017 Random Forest)
# ------------------------------------------------------------------
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)

class MLModel:
    def __init__(self):
        self.rf = self.scaler = self.encoder = None
        self.ready = False
        self._load()

    def _load(self):
        rf_path = os.path.join(MODELS_DIR, "cicids_rf.pkl")
        sc_path = os.path.join(MODELS_DIR, "cicids_scaler.pkl")
        le_path = os.path.join(MODELS_DIR, "cicids_label_encoder.pkl")
        if not all(os.path.exists(p) for p in [rf_path, sc_path, le_path]):
<<<<<<< HEAD
            logger.warning("[ML] Model files not found — ML disabled.")
=======
            logger.warning("[ML] Model files not found - ML disabled.")
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
            return
        try:
            with open(rf_path,"rb") as f: self.rf      = pickle.load(f)
            with open(sc_path,"rb") as f: self.scaler  = pickle.load(f)
            with open(le_path,"rb") as f: self.encoder = pickle.load(f)
            self.ready = True
            logger.info("[ML] CICIDS2017 Random Forest loaded.")
        except Exception as e:
            logger.error(f"[ML] Load error: {e}")

    def predict(self, feature_dict):
        if not self.ready: return None
        try:
            X = pd.DataFrame([feature_dict], columns=FEATURE_NAMES)
            X.replace([np.inf, -np.inf], 0, inplace=True)
            X.fillna(0, inplace=True)
            X_scaled = self.scaler.transform(X)
            label    = self.encoder.inverse_transform(self.rf.predict(X_scaled))[0]
            proba    = self.rf.predict_proba(X_scaled)[0]
            if max(proba) < 0.60:
                return "BENIGN"
            return label
        except Exception as e:
            logger.error(f"[ML] Predict error: {e}")
            return None


<<<<<<< HEAD
# ══════════════════════════════════════════════════════════════════
# FLOW BUILDER
# ══════════════════════════════════════════════════════════════════
=======
# ------------------------------------------------------------------
# FLOW BUILDER
# ------------------------------------------------------------------
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)

class Flow:
    def __init__(self, flow_id, start_time):
        self.flow_id     = flow_id
        self.start_time  = start_time
        self.last_seen   = start_time
        self.predicted   = False
        self.fwd_packets = []   # (ts, size, flags)
        self.bwd_packets = []
        self.syn_count   = 0
        self.rst_count   = 0
        self.fwd_psh     = 0

    def add_packet(self, ts, size, flags, is_forward):
        self.last_seen = ts
        if is_forward:
            self.fwd_packets.append((ts, size, flags))
            if flags:
                if flags & 0x02: self.syn_count += 1
                if flags & 0x04: self.rst_count += 1
                if flags & 0x08: self.fwd_psh   += 1
        else:
            self.bwd_packets.append((ts, size, flags))

    def duration(self):
        return self.last_seen - self.start_time

    def extract_features(self):
        _, _, _, dst_port, _ = self.flow_id
        dur = max(self.duration(), 1e-6)
        fs  = [s for _,s,_ in self.fwd_packets]
        bs  = [s for _,s,_ in self.bwd_packets]
        all_s = fs + bs
        nf, nb = len(fs), len(bs)
        tfb, tbb = sum(fs), sum(bs)
        all_ts = sorted([t for t,_,_ in self.fwd_packets+self.bwd_packets])
        iats = [all_ts[i]-all_ts[i-1] for i in range(1,len(all_ts))] if len(all_ts)>1 else [0]
        fts  = sorted([t for t,_,_ in self.fwd_packets])
        fi   = [fts[i]-fts[i-1] for i in range(1,len(fts))] if len(fts)>1 else [0]
        bts  = sorted([t for t,_,_ in self.bwd_packets])
        bi   = [bts[i]-bts[i-1] for i in range(1,len(bts))] if len(bts)>1 else [0]
        M    = 1_000_000
        return {
            "Destination Port":            dst_port,
            "Flow Duration":               dur*M,
            "Total Fwd Packets":           nf,
            "Total Backward Packets":      nb,
            "Total Length of Fwd Packets": tfb,
            "Total Length of Bwd Packets": tbb,
            "Fwd Packet Length Max":       max(fs) if fs else 0,
            "Fwd Packet Length Mean":      float(np.mean(fs)) if fs else 0.0,
            "Bwd Packet Length Max":       max(bs) if bs else 0,
            "Bwd Packet Length Mean":      float(np.mean(bs)) if bs else 0.0,
            "Flow Bytes/s":                (tfb+tbb)/dur,
            "Flow Packets/s":              (nf+nb)/dur,
            "Flow IAT Mean":               float(np.mean(iats))*M,
            "Flow IAT Std":                float(np.std(iats))*M,
            "Fwd IAT Mean":                float(np.mean(fi))*M,
            "Bwd IAT Mean":                float(np.mean(bi))*M,
            "Fwd PSH Flags":               self.fwd_psh,
            "SYN Flag Count":              self.syn_count,
            "RST Flag Count":              self.rst_count,
            "Average Packet Size":         float(np.mean(all_s)) if all_s else 0.0,
        }


class FlowManager:
    FLOW_TIMEOUT     = 5
    PREDICT_INTERVAL = 3

    def __init__(self, ml_model, alert_system):
        self.flows = {}
        self.ml    = ml_model
        self.alerts= alert_system
        self._lock = threading.Lock()
        self._schedule()

    def _schedule(self):
        t = threading.Timer(self.PREDICT_INTERVAL, self._process)
        t.daemon = True
        t.start()

    def add_packet(self, flow_id, ts, size, flags, is_forward):
        with self._lock:
            if flow_id not in self.flows:
                self.flows[flow_id] = Flow(flow_id, ts)
            self.flows[flow_id].add_packet(ts, size, flags, is_forward)

    def _process(self):
        now, to_pred = time.time(), []
        with self._lock:
            for fid, flow in list(self.flows.items()):
                age = now - flow.last_seen
                if age >= self.FLOW_TIMEOUT and not flow.predicted:
                    flow.predicted = True
                    to_pred.append(flow)
                if age > 120:
                    del self.flows[fid]
        for flow in to_pred:
            self._predict(flow)
        self._schedule()

    def _predict(self, flow):
        if not self.ml.ready: return
        total = len(flow.fwd_packets) + len(flow.bwd_packets)
        if total < 5: return
        src_ip, dst_ip = flow.flow_id[0], flow.flow_id[1]
        if src_ip in WHITELIST or dst_ip in WHITELIST: return
        features = flow.extract_features()
        label    = self.ml.predict(features)
        if not label or label == "BENIGN": return
        severity = CLASS_SEVERITY.get(label, "MEDIUM")
        _, _, src_port, dst_port, proto = flow.flow_id
        alert = {
            "timestamp":       datetime.now().isoformat(),
            "alert_type":      f"ML_{label}",
            "severity":        severity,
            "message":         f"[ML] {label}: {src_ip}:{src_port}→{dst_ip}:{dst_port} ({total}pkts, {flow.duration():.1f}s)",
            "source_ip":       src_ip,
            "destination_ip":  dst_ip,
            "additional_info": {"ml_label": label, "dst_port": dst_port,
                                "protocol": proto, "flow_duration": round(flow.duration(),3),
                                "total_packets": total},
        }
        # Save to ml_alerts.json (separate from rule-based alerts.json)
        self.alerts.add_ml_alert(alert)
        logger.warning(f"[ML] {label} ({severity}): {src_ip}→{dst_ip}:{dst_port}")

<<<<<<< HEAD
=======
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
=======
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)

class FeatureExtractor:
    """Extract features from network packets"""
    
    def __init__(self):
        self.features = []
    
    def extract_packet_features(self, packet):
        """Extract comprehensive features from a single packet"""
        features = {
            'timestamp': time.time(),
            'packet_length': len(packet)
        }
        
        # IP Layer features
        if IP in packet:
            features.update({
                'src_ip': packet[IP].src,
                'dst_ip': packet[IP].dst,
                'ttl': packet[IP].ttl,
                'protocol': packet[IP].proto,
                'ip_flags': packet[IP].flags,
                'frag_offset': packet[IP].frag
            })
        
        # TCP Layer features
        if TCP in packet:
            features.update({
                'src_port': packet[TCP].sport,
                'dst_port': packet[TCP].dport,
                'tcp_flags': str(packet[TCP].flags),
                'window_size': packet[TCP].window,
                'seq_num': packet[TCP].seq,
                'ack_num': packet[TCP].ack
            })
            
        # UDP Layer features
        elif UDP in packet:
            features.update({
                'src_port': packet[UDP].sport,
                'dst_port': packet[UDP].dport,
                'udp_length': packet[UDP].len
            })
        
        # ICMP Layer features
        elif ICMP in packet:
            features.update({
                'icmp_type': packet[ICMP].type,
                'icmp_code': packet[ICMP].code
            })
        
        # DNS Layer features
        if DNS in packet:
            features.update({
                'dns_query': packet[DNS].qd.qname.decode() if packet[DNS].qd else None,
                'dns_qr': packet[DNS].qr  # 0 for query, 1 for response
            })
        
        # Payload analysis
        if Raw in packet:
            payload = bytes(packet[Raw].load)
            features.update({
                'payload_length': len(payload),
                'payload_entropy': self.calculate_entropy(payload)
            })
        
        return features
    
    @staticmethod
    def calculate_entropy(data):
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
        
        entropy = 0.0
        for x in range(256):
            p_x = float(data.count(bytes([x]))) / len(data)
            if p_x > 0:
                entropy += - p_x * np.log2(p_x)
        return entropy
    
    def extract_flow_features(self, packets):
        """Extract flow-level features from multiple packets"""
        if not packets:
            return {}
        
        flow_features = {
            'total_packets': len(packets),
            'total_bytes': sum(len(p) for p in packets),
            'duration': packets[-1].time - packets[0].time if len(packets) > 1 else 0,
            'avg_packet_size': np.mean([len(p) for p in packets]),
            'std_packet_size': np.std([len(p) for p in packets])
        }
        
        # Calculate inter-arrival times
        if len(packets) > 1:
            inter_arrival_times = [
                packets[i].time - packets[i-1].time 
                for i in range(1, len(packets))
            ]
            flow_features['avg_iat'] = np.mean(inter_arrival_times)
            flow_features['std_iat'] = np.std(inter_arrival_times)
        
        return flow_features


class PortScanDetector:
    """Detect port scanning activities"""
<<<<<<< HEAD
<<<<<<< HEAD

    def __init__(self, threshold=20, time_window=60):
        self.threshold     = threshold
        self.time_window   = time_window
        self.scan_attempts = defaultdict(list)
        self._consec       = defaultdict(int)
        self.whitelist: set = set()   # populated by NetworkThreatAnalyzer

    def analyze(self, src_ip, dst_ip, dst_port, timestamp, payload_size=0):
        """Analyze for port scan patterns."""
        if src_ip in self.whitelist or src_ip in WHITELIST:
            return {'detected': False}
        if dst_ip in self.whitelist:
            return {'detected': False}

        self.scan_attempts[src_ip].append((dst_port, timestamp, payload_size))
        self.scan_attempts[src_ip] = [
            (p,ts,ps) for p,ts,ps in self.scan_attempts[src_ip]
            if timestamp - ts <= self.time_window
        ]
        unique_ports = len(set(p for p,_,_ in self.scan_attempts[src_ip]))
        avg_payload  = sum(ps for _,_,ps in self.scan_attempts[src_ip]) / max(len(self.scan_attempts[src_ip]),1)

        if unique_ports > self.threshold and avg_payload < 100:
            self._consec[src_ip] += 1
        else:
            self._consec[src_ip] = 0

        if self._consec[src_ip] >= 3:
            return {
                'detected': True, 'type': 'PORT_SCAN', 'severity': 'HIGH',
                'source': src_ip, 'destination': dst_ip, 'ports_scanned': unique_ports,
                'message': f'Port scan from {src_ip} → {dst_ip}: {unique_ports} unique ports in {self.time_window}s'
            }
=======
    
=======

>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
    def __init__(self, threshold=20, time_window=60):
        self.threshold     = threshold
        self.time_window   = time_window
        self.scan_attempts = defaultdict(list)
        self._consec       = defaultdict(int)
        self.whitelist: set = set()   # populated by NetworkThreatAnalyzer

    def analyze(self, src_ip, dst_ip, dst_port, timestamp, payload_size=0):
        """Analyze for port scan patterns."""
        if src_ip in self.whitelist or src_ip in WHITELIST:
            return {'detected': False}
        if dst_ip in self.whitelist:
            return {'detected': False}

        self.scan_attempts[src_ip].append((dst_port, timestamp, payload_size))
        self.scan_attempts[src_ip] = [
            (p,ts,ps) for p,ts,ps in self.scan_attempts[src_ip]
            if timestamp - ts <= self.time_window
        ]
        unique_ports = len(set(p for p,_,_ in self.scan_attempts[src_ip]))
        avg_payload  = sum(ps for _,_,ps in self.scan_attempts[src_ip]) / max(len(self.scan_attempts[src_ip]),1)

        if unique_ports > self.threshold and avg_payload < 100:
            self._consec[src_ip] += 1
        else:
            self._consec[src_ip] = 0

        if self._consec[src_ip] >= 3:
            return {
                'detected': True, 'type': 'PORT_SCAN', 'severity': 'HIGH',
                'source': src_ip, 'destination': dst_ip, 'ports_scanned': unique_ports,
                'message': f'Port scan from {src_ip} → {dst_ip}: {unique_ports} unique ports in {self.time_window}s'
            }
<<<<<<< HEAD
        
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
=======
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
        return {'detected': False}


class DDoSDetector:
<<<<<<< HEAD
<<<<<<< HEAD
    # Trusted IPs never flagged for floods
    WHITELIST = {'127.0.0.1', '::1'}

    """Detect DDoS attack patterns"""
    
    def __init__(self, syn_threshold=100, packet_threshold=2000, time_window=10):
        self.syn_threshold    = syn_threshold
        self.packet_threshold = packet_threshold
        self.time_window      = time_window
        self.syn_packets      = defaultdict(list)
        self.packet_counts    = defaultdict(list)
        self._syn_consec      = defaultdict(int)
        self._pkt_consec      = defaultdict(int)

    def analyze_syn_flood(self, src_ip, dst_ip, tcp_flags, timestamp):
        """Detect SYN flood attacks."""
        if src_ip in self.WHITELIST or src_ip in WHITELIST:
            return {'detected': False}
        if 'S' in str(tcp_flags) and 'A' not in str(tcp_flags):
            self.syn_packets[src_ip].append(timestamp)
            self.syn_packets[src_ip] = [
                ts for ts in self.syn_packets[src_ip]
                if timestamp - ts <= self.time_window
            ]
            syn_c = len(self.syn_packets[src_ip])
            pkt_c = len(self.packet_counts.get(src_ip, []))
            # Combined: SYN flood + high packet rate
            if syn_c > self.syn_threshold and pkt_c > self.packet_threshold * 0.3:
                self._syn_consec[src_ip] += 1
            else:
                self._syn_consec[src_ip] = 0
            if self._syn_consec[src_ip] >= 3:
                return {
                    'detected': True, 'type': 'SYN_FLOOD', 'severity': 'CRITICAL',
                    'source': src_ip, 'destination': dst_ip, 'syn_count': syn_c,
                    'message': f'SYN flood from {src_ip} → {dst_ip}: {syn_c} SYN pkts in {self.time_window}s'
                }
        return {'detected': False}

    def analyze_packet_flood(self, src_ip, dst_ip, timestamp):
        if src_ip in self.WHITELIST:
            return {'detected': False}
        """Detect general packet flooding"""
        if src_ip in WHITELIST:
            return {'detected': False}
        self.packet_counts[src_ip].append(timestamp)
        self.packet_counts[src_ip] = [
            ts for ts in self.packet_counts[src_ip]
            if timestamp - ts <= self.time_window
        ]
        pkt_c = len(self.packet_counts[src_ip])
        if pkt_c > self.packet_threshold:
            self._pkt_consec[src_ip] += 1
        else:
            self._pkt_consec[src_ip] = 0
        if self._pkt_consec[src_ip] >= 3:
            return {
                'detected': True, 'type': 'PACKET_FLOOD', 'severity': 'HIGH',
                'source': src_ip, 'destination': dst_ip, 'packet_count': pkt_c,
                'message': f'Packet flood from {src_ip} → {dst_ip}: {pkt_c} pkts in {self.time_window}s'
            }
=======
=======
    # Trusted IPs never flagged for floods
    WHITELIST = {'127.0.0.1', '::1'}

>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
    """Detect DDoS attack patterns"""
    
    def __init__(self, syn_threshold=100, packet_threshold=2000, time_window=10):
        self.syn_threshold    = syn_threshold
        self.packet_threshold = packet_threshold
        self.time_window      = time_window
        self.syn_packets      = defaultdict(list)
        self.packet_counts    = defaultdict(list)
        self._syn_consec      = defaultdict(int)
        self._pkt_consec      = defaultdict(int)

    def analyze_syn_flood(self, src_ip, dst_ip, tcp_flags, timestamp):
        """Detect SYN flood attacks."""
        if src_ip in self.WHITELIST or src_ip in WHITELIST:
            return {'detected': False}
        if 'S' in str(tcp_flags) and 'A' not in str(tcp_flags):
            self.syn_packets[src_ip].append(timestamp)
            self.syn_packets[src_ip] = [
                ts for ts in self.syn_packets[src_ip]
                if timestamp - ts <= self.time_window
            ]
            syn_c = len(self.syn_packets[src_ip])
            pkt_c = len(self.packet_counts.get(src_ip, []))
            # Combined: SYN flood + high packet rate
            if syn_c > self.syn_threshold and pkt_c > self.packet_threshold * 0.3:
                self._syn_consec[src_ip] += 1
            else:
                self._syn_consec[src_ip] = 0
            if self._syn_consec[src_ip] >= 3:
                return {
                    'detected': True, 'type': 'SYN_FLOOD', 'severity': 'CRITICAL',
                    'source': src_ip, 'destination': dst_ip, 'syn_count': syn_c,
                    'message': f'SYN flood from {src_ip} → {dst_ip}: {syn_c} SYN pkts in {self.time_window}s'
                }
        return {'detected': False}

    def analyze_packet_flood(self, src_ip, dst_ip, timestamp):
        if src_ip in self.WHITELIST:
            return {'detected': False}
        """Detect general packet flooding"""
        if src_ip in WHITELIST:
            return {'detected': False}
        self.packet_counts[src_ip].append(timestamp)
        self.packet_counts[src_ip] = [
            ts for ts in self.packet_counts[src_ip]
            if timestamp - ts <= self.time_window
        ]
        pkt_c = len(self.packet_counts[src_ip])
        if pkt_c > self.packet_threshold:
            self._pkt_consec[src_ip] += 1
        else:
            self._pkt_consec[src_ip] = 0
        if self._pkt_consec[src_ip] >= 3:
            return {
                'detected': True, 'type': 'PACKET_FLOOD', 'severity': 'HIGH',
                'source': src_ip, 'destination': dst_ip, 'packet_count': pkt_c,
                'message': f'Packet flood from {src_ip} → {dst_ip}: {pkt_c} pkts in {self.time_window}s'
            }
<<<<<<< HEAD
        
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
=======
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
        return {'detected': False}


class DNSAnomalyDetector:
    """Detect DNS-based anomalies including DGA"""
    
<<<<<<< HEAD
<<<<<<< HEAD
    def __init__(self, entropy_threshold=2.8):
        self.entropy_threshold = entropy_threshold
        self.dns_queries = defaultdict(list)
        self.nxdomain_counts = defaultdict(int)
    
    def analyze_dga(self, domain, src_ip, dst_ip=None):
=======
    def __init__(self, entropy_threshold=3.5):
=======
    def __init__(self, entropy_threshold=2.8):
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
        self.entropy_threshold = entropy_threshold
        self.dns_queries = defaultdict(list)
        self.nxdomain_counts = defaultdict(int)
    
<<<<<<< HEAD
    def analyze_dga(self, domain, src_ip):
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
=======
    def analyze_dga(self, domain, src_ip, dst_ip=None):
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
        """Detect Domain Generation Algorithm (DGA) patterns"""
        if not domain:
            return {'detected': False}
        
        # Calculate domain entropy
        domain_str = domain.decode() if isinstance(domain, bytes) else domain
<<<<<<< HEAD
<<<<<<< HEAD
        domain_str = domain_str.rstrip('.')
        domain_entropy = self.calculate_domain_entropy(domain_str)

        # Track query volume per source IP
        self.dns_queries[src_ip].append(domain_str)

        if src_ip in WHITELIST:
            return {'detected': False}

        subdomain = domain_str.split('.')[0] if '.' in domain_str else domain_str
        dst_label = f' → {dst_ip}' if dst_ip else ''

        # Combined: high entropy AND long subdomain (reduces false positives)
        if domain_entropy > 3.2 and len(subdomain) > 12:
            return {
                'detected': True, 'type': 'DGA_DOMAIN', 'severity': 'HIGH',
                'source': src_ip, 'destination': dst_ip, 'domain': domain_str,
                'entropy': round(domain_entropy, 2),
                'message': f'DGA domain from {src_ip}{dst_label}: {domain_str} (entropy {domain_entropy:.2f}, len {len(subdomain)})'
            }

        # DGA spray: very high volume of unique domains
        unique_domains = len(set(self.dns_queries[src_ip]))
        if unique_domains > 30:
            return {
                'detected': True, 'type': 'DGA_DOMAIN', 'severity': 'HIGH',
                'source': src_ip, 'destination': dst_ip, 'domain': domain_str,
                'entropy': round(domain_entropy, 2),
                'message': f'DGA spray from {src_ip}{dst_label}: {unique_domains} unique domains'
=======
=======
        domain_str = domain_str.rstrip('.')
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
        domain_entropy = self.calculate_domain_entropy(domain_str)

        # Track query volume per source IP
        self.dns_queries[src_ip].append(domain_str)

        if src_ip in WHITELIST:
            return {'detected': False}

        subdomain = domain_str.split('.')[0] if '.' in domain_str else domain_str
        dst_label = f' → {dst_ip}' if dst_ip else ''

        # Combined: high entropy AND long subdomain (reduces false positives)
        if domain_entropy > 3.2 and len(subdomain) > 12:
            return {
<<<<<<< HEAD
                'detected': True,
                'type': 'DGA_DOMAIN',
                'severity': 'HIGH',
                'source': src_ip,
                'domain': domain_str,
                'entropy': domain_entropy,
                'message': f'Potential DGA domain detected: {domain_str} (entropy: {domain_entropy:.2f})'
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
=======
                'detected': True, 'type': 'DGA_DOMAIN', 'severity': 'HIGH',
                'source': src_ip, 'destination': dst_ip, 'domain': domain_str,
                'entropy': round(domain_entropy, 2),
                'message': f'DGA domain from {src_ip}{dst_label}: {domain_str} (entropy {domain_entropy:.2f}, len {len(subdomain)})'
            }

        # DGA spray: very high volume of unique domains
        unique_domains = len(set(self.dns_queries[src_ip]))
        if unique_domains > 30:
            return {
                'detected': True, 'type': 'DGA_DOMAIN', 'severity': 'HIGH',
                'source': src_ip, 'destination': dst_ip, 'domain': domain_str,
                'entropy': round(domain_entropy, 2),
                'message': f'DGA spray from {src_ip}{dst_label}: {unique_domains} unique domains'
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
            }
        
        return {'detected': False}
    
    @staticmethod
    def calculate_domain_entropy(domain):
        """Calculate entropy of domain name"""
        if not domain:
            return 0.0
        
        # Remove TLD for better analysis
        domain_parts = domain.rstrip('.').split('.')
        if len(domain_parts) > 1:
            domain = domain_parts[-2]  # Get second-level domain
        
        # Calculate character frequency
        char_freq = Counter(domain.lower())
        domain_len = len(domain)
        
        entropy = 0.0
        for count in char_freq.values():
            p = count / domain_len
            entropy += -p * np.log2(p)
        
        return entropy


class AbnormalPacketDetector:
    """Detect abnormal packet characteristics"""
    
    def __init__(self):
        self.packet_size_stats = {'mean': 500, 'std': 200}  # Initialize with defaults
    
<<<<<<< HEAD
<<<<<<< HEAD
    def analyze_packet_size(self, packet_len, src_ip=None, dst_ip=None):
        """Detect abnormally sized packets"""
        if packet_len is None:
            return {'detected': False}
        ips = f' ({src_ip} → {dst_ip})' if src_ip and dst_ip else ''

        # Very small packets (could be probes)
        if packet_len < 40:
            return {
                'detected': True, 'type': 'ABNORMAL_SIZE', 'severity': 'MEDIUM',
                'source': src_ip, 'destination': dst_ip, 'packet_size': packet_len,
                'message': f'Abnormally small packet{ips}: {packet_len} bytes (possible probe)'
=======
    def analyze_packet_size(self, packet_len):
=======
    def analyze_packet_size(self, packet_len, src_ip=None, dst_ip=None):
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
        """Detect abnormally sized packets"""
        if packet_len is None:
            return {'detected': False}
        ips = f' ({src_ip} → {dst_ip})' if src_ip and dst_ip else ''

        # Very small packets (could be probes)
        if packet_len < 40:
            return {
<<<<<<< HEAD
                'detected': True,
                'type': 'ABNORMAL_SIZE',
                'severity': 'MEDIUM',
                'packet_size': packet_len,
                'message': f'Abnormally small packet detected: {packet_len} bytes'
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
=======
                'detected': True, 'type': 'ABNORMAL_SIZE', 'severity': 'MEDIUM',
                'source': src_ip, 'destination': dst_ip, 'packet_size': packet_len,
                'message': f'Abnormally small packet{ips}: {packet_len} bytes (possible probe)'
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
            }
        
        # Very large packets (could be fragmentation attack)
        if packet_len > 9000:
            return {
<<<<<<< HEAD
<<<<<<< HEAD
                'detected': True, 'type': 'ABNORMAL_SIZE', 'severity': 'MEDIUM',
                'source': src_ip, 'destination': dst_ip, 'packet_size': packet_len,
                'message': f'Abnormally large packet{ips}: {packet_len} bytes'
=======
                'detected': True,
                'type': 'ABNORMAL_SIZE',
                'severity': 'MEDIUM',
                'packet_size': packet_len,
                'message': f'Abnormally large packet detected: {packet_len} bytes'
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
=======
                'detected': True, 'type': 'ABNORMAL_SIZE', 'severity': 'MEDIUM',
                'source': src_ip, 'destination': dst_ip, 'packet_size': packet_len,
                'message': f'Abnormally large packet{ips}: {packet_len} bytes'
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
            }
        
        return {'detected': False}
    
<<<<<<< HEAD
<<<<<<< HEAD
    def analyze_malformed_packet(self, packet, src_ip=None, dst_ip=None):
        """Detect malformed packets"""
        ips = f' ({src_ip} → {dst_ip})' if src_ip and dst_ip else ''
        try:
            if IP in packet:
                if packet[IP].version not in [4, 6]:
                    return {
                        'detected': True, 'type': 'MALFORMED_PACKET', 'severity': 'HIGH',
                        'source': src_ip, 'destination': dst_ip,
                        'message': f'Invalid IP version{ips}: {packet[IP].version}'
                    }
                if packet[IP].ttl == 0 or packet[IP].ttl > 255:
                    return {
                        'detected': True, 'type': 'MALFORMED_PACKET', 'severity': 'MEDIUM',
                        'source': src_ip, 'destination': dst_ip,
                        'message': f'Invalid TTL value{ips}: {packet[IP].ttl}'
                    }
            if TCP in packet:
                flags = str(packet[TCP].flags)
                if 'F' in flags and 'S' in flags:
                    return {
                        'detected': True, 'type': 'MALFORMED_PACKET', 'severity': 'HIGH',
                        'source': src_ip, 'destination': dst_ip,
                        'message': f'Invalid TCP flags{ips}: {flags}'
                    }
        except Exception as e:
            logger.error(f"Error analyzing malformed packet: {e}")
        return {'detected': False}


class C2BeaconingDetector:
    """Detect Command & Control beaconing traffic"""

    def __init__(self, beacon_threshold=8, time_window=600):
        self.beacon_threshold = beacon_threshold
        self.time_window = time_window
        self.connection_times = defaultdict(list)

    def analyze(self, src_ip, dst_ip, dst_port, timestamp):
        if not src_ip or not dst_ip:
            return {'detected': False}

        key = (src_ip, dst_ip, dst_port)
        self.connection_times[key].append(timestamp)

        self.connection_times[key] = [
            ts for ts in self.connection_times[key]
            if timestamp - ts <= self.time_window
        ]

        count = len(self.connection_times[key])
        if count >= self.beacon_threshold:
            if count >= 3:
                intervals = [
                    self.connection_times[key][i] - self.connection_times[key][i-1]
                    for i in range(1, len(self.connection_times[key]))
                ]
                avg_interval = np.mean(intervals)
                std_interval = np.std(intervals)
                regularity = std_interval / avg_interval if avg_interval > 0 else 1

                if regularity < 0.4:
                    return {
                        'detected': True,
                        'type': 'C2_BEACONING',
                        'severity': 'CRITICAL',
                        'source': src_ip,
                        'destination': dst_ip,
                        'port': dst_port,
                        'beacon_count': count,
                        'avg_interval': round(avg_interval, 2),
                        'regularity_score': round(regularity, 3),
                        'message': (
                            f'C2 beaconing detected: {src_ip} -> {dst_ip}:{dst_port} '
                            f'({count} times, every ~{avg_interval:.1f}s)'
                        )
                    }
        return {'detected': False}


class DataExfiltrationDetector:
    # Trusted destinations — cloud backup, update servers etc.
    WHITELIST = {'127.0.0.1', '::1'}

    """Detect large outbound data transfers (exfiltration)"""

    def __init__(self, bytes_threshold=2000000, time_window=300):
        self.bytes_threshold = bytes_threshold
        self.time_window = time_window
        self.transfer_data = defaultdict(list)
        self.safe_destinations = {'8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1'}

    def analyze(self, src_ip, dst_ip, packet_len, timestamp):
        if not src_ip or not dst_ip:
            return {'detected': False}
        if dst_ip in self.safe_destinations:
            return {'detected': False}

        key = (src_ip, dst_ip)
        self.transfer_data[key].append((packet_len, timestamp))

        self.transfer_data[key] = [
            (b, ts) for b, ts in self.transfer_data[key]
            if timestamp - ts <= self.time_window
        ]

        total_bytes = sum(b for b, _ in self.transfer_data[key])

        if total_bytes > self.bytes_threshold:
            return {
                'detected': True,
                'type': 'DATA_EXFILTRATION',
                'severity': 'CRITICAL',
                'source': src_ip,
                'destination': dst_ip,
                'total_bytes': total_bytes,
                'message': (
                    f'Possible data exfiltration: {src_ip} -> {dst_ip} '
                    f'({total_bytes / 1024:.1f} KB in {self.time_window}s)'
                )
            }
        return {'detected': False}


def get_trusted_ips():
    """Auto-detect local IP and gateway to add to whitelists."""
    trusted = {'127.0.0.1', '::1'}
    try:
        # Get local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        local_ip = s.getsockname()[0]
        s.close()
        trusted.add(local_ip)
    except Exception:
        pass
    try:
        # Get default gateway from /proc/net/route (Linux) or via socket trick
        with open('/proc/net/route') as f:
            for line in f.readlines()[1:]:
                parts = line.strip().split()
                if parts[1] == '00000000':  # default route
                    gw = socket.inet_ntoa(bytes.fromhex(parts[2].zfill(8))[::-1])
                    trusted.add(gw)
                    break
    except Exception:
        pass
    try:
        import subprocess
        # Windows fallback
        out = subprocess.check_output('ipconfig', shell=True).decode(errors='ignore')
        for line in out.splitlines():
            if 'Default Gateway' in line and ':' in line:
                gw = line.split(':')[-1].strip()
                if gw:
                    trusted.add(gw)
    except Exception:
        pass
    return trusted


class AlertSystem:
    """Handle and log security alerts"""

    def __init__(self, output_file=None):
        self.output_file    = output_file or ALERTS_FILE
        self.ml_output_file = ML_ALERTS_FILE
        self._lock          = threading.Lock()
        # Load existing so count keeps growing across restarts
        self.alerts         = self._load(self.output_file)
        self.ml_alerts      = self._load(self.ml_output_file)
        # Cooldown tracker: (alert_type, src_ip) -> last timestamp
        self._last_seen     = {}

    def _load(self, path):
        try:
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)
        except Exception:
            pass
        return []

    def _is_cooldown(self, alert_type, src_ip):
        key  = (alert_type, src_ip or "")
        now  = time.time()
        cd   = COOLDOWN.get(alert_type, 15)
        last = self._last_seen.get(key, 0)
        if now - last < cd:
            return True
        self._last_seen[key] = now
        return False

    def add_alert(self, alert_data, packet_features):
        """Called by rule-based detectors — saves to alerts.json"""
        alert_type = alert_data.get('type')
        src_ip     = packet_features.get('src_ip', '')
        if self._is_cooldown(alert_type, src_ip):
            return   # suppress duplicate

        alert = {
            'timestamp':       datetime.now().isoformat(),
            'alert_type':      alert_type,
            'severity':        alert_data.get('severity'),
            'message':         alert_data.get('message'),
            'source_ip':       src_ip,
            'destination_ip':  packet_features.get('dst_ip'),
            'additional_info': {k: v for k, v in alert_data.items()
                                if k not in ['type','severity','message','detected']}
        }
        logger.warning(f"ALERT: {alert['alert_type']} — {alert['message']}")
        with self._lock:
            self.alerts.append(alert)
            self._write(self.output_file, self.alerts)

    def add_ml_alert(self, alert):
        """Called by FlowManager — saves to ml_alerts.json"""
        logger.warning(f"ML ALERT: {alert['alert_type']} — {alert['message']}")
        with self._lock:
            self.ml_alerts.append(alert)
            self._write(self.ml_output_file, self.ml_alerts)

    def _write(self, path, data):
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving {path}: {e}")

    def get_alert_summary(self):
        """Get summary of alerts"""
        all_alerts = self.alerts + self.ml_alerts
        if not all_alerts:
            return "No alerts detected"
        alert_types     = Counter(a['alert_type'] for a in all_alerts)
        severity_counts = Counter(a['severity']   for a in all_alerts)
        summary  = f"\n{'='*60}\nALERT SUMMARY\n{'='*60}\n"
        summary += f"Total: {len(all_alerts)} (Rule: {len(self.alerts)}, ML: {len(self.ml_alerts)})\n\n"
        summary += "By Type:\n"
        for t, c in alert_types.most_common():
            summary += f"  {t}: {c}\n"
        summary += "\nBy Severity:\n"
        for s, c in severity_counts.most_common():
            summary += f"  {s}: {c}\n"
        summary += f"{'='*60}\n"
=======
    def analyze_malformed_packet(self, packet):
=======
    def analyze_malformed_packet(self, packet, src_ip=None, dst_ip=None):
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
        """Detect malformed packets"""
        ips = f' ({src_ip} → {dst_ip})' if src_ip and dst_ip else ''
        try:
            if IP in packet:
                if packet[IP].version not in [4, 6]:
                    return {
                        'detected': True, 'type': 'MALFORMED_PACKET', 'severity': 'HIGH',
                        'source': src_ip, 'destination': dst_ip,
                        'message': f'Invalid IP version{ips}: {packet[IP].version}'
                    }
                if packet[IP].ttl == 0 or packet[IP].ttl > 255:
                    return {
                        'detected': True, 'type': 'MALFORMED_PACKET', 'severity': 'MEDIUM',
                        'source': src_ip, 'destination': dst_ip,
                        'message': f'Invalid TTL value{ips}: {packet[IP].ttl}'
                    }
            if TCP in packet:
                flags = str(packet[TCP].flags)
                if 'F' in flags and 'S' in flags:
                    return {
                        'detected': True, 'type': 'MALFORMED_PACKET', 'severity': 'HIGH',
                        'source': src_ip, 'destination': dst_ip,
                        'message': f'Invalid TCP flags{ips}: {flags}'
                    }
        except Exception as e:
            logger.error(f"Error analyzing malformed packet: {e}")
        return {'detected': False}


class C2BeaconingDetector:
    """Detect Command & Control beaconing traffic"""

    def __init__(self, beacon_threshold=8, time_window=600):
        self.beacon_threshold = beacon_threshold
        self.time_window = time_window
        self.connection_times = defaultdict(list)

    def analyze(self, src_ip, dst_ip, dst_port, timestamp):
        if not src_ip or not dst_ip:
            return {'detected': False}

        key = (src_ip, dst_ip, dst_port)
        self.connection_times[key].append(timestamp)

        self.connection_times[key] = [
            ts for ts in self.connection_times[key]
            if timestamp - ts <= self.time_window
        ]

        count = len(self.connection_times[key])
        if count >= self.beacon_threshold:
            if count >= 3:
                intervals = [
                    self.connection_times[key][i] - self.connection_times[key][i-1]
                    for i in range(1, len(self.connection_times[key]))
                ]
                avg_interval = np.mean(intervals)
                std_interval = np.std(intervals)
                regularity = std_interval / avg_interval if avg_interval > 0 else 1

                if regularity < 0.4:
                    return {
                        'detected': True,
                        'type': 'C2_BEACONING',
                        'severity': 'CRITICAL',
                        'source': src_ip,
                        'destination': dst_ip,
                        'port': dst_port,
                        'beacon_count': count,
                        'avg_interval': round(avg_interval, 2),
                        'regularity_score': round(regularity, 3),
                        'message': (
                            f'C2 beaconing detected: {src_ip} -> {dst_ip}:{dst_port} '
                            f'({count} times, every ~{avg_interval:.1f}s)'
                        )
                    }
        return {'detected': False}


class DataExfiltrationDetector:
    # Trusted destinations - cloud backup, update servers etc.
    WHITELIST = {'127.0.0.1', '::1'}

    """Detect large outbound data transfers (exfiltration)"""

    def __init__(self, bytes_threshold=2000000, time_window=300):
        self.bytes_threshold = bytes_threshold
        self.time_window = time_window
        self.transfer_data = defaultdict(list)
        self.safe_destinations = {'8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1'}

    def analyze(self, src_ip, dst_ip, packet_len, timestamp):
        if not src_ip or not dst_ip:
            return {'detected': False}
        if dst_ip in self.safe_destinations:
            return {'detected': False}

        key = (src_ip, dst_ip)
        self.transfer_data[key].append((packet_len, timestamp))

        self.transfer_data[key] = [
            (b, ts) for b, ts in self.transfer_data[key]
            if timestamp - ts <= self.time_window
        ]

        total_bytes = sum(b for b, _ in self.transfer_data[key])

        if total_bytes > self.bytes_threshold:
            return {
                'detected': True,
                'type': 'DATA_EXFILTRATION',
                'severity': 'CRITICAL',
                'source': src_ip,
                'destination': dst_ip,
                'total_bytes': total_bytes,
                'message': (
                    f'Possible data exfiltration: {src_ip} -> {dst_ip} '
                    f'({total_bytes / 1024:.1f} KB in {self.time_window}s)'
                )
            }
        return {'detected': False}


def get_trusted_ips():
    """Auto-detect local IP and gateway to add to whitelists."""
    trusted = {'127.0.0.1', '::1'}
    try:
        # Get local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        local_ip = s.getsockname()[0]
        s.close()
        trusted.add(local_ip)
    except Exception:
        pass
    try:
        # Get default gateway from /proc/net/route (Linux) or via socket trick
        with open('/proc/net/route') as f:
            for line in f.readlines()[1:]:
                parts = line.strip().split()
                if parts[1] == '00000000':  # default route
                    gw = socket.inet_ntoa(bytes.fromhex(parts[2].zfill(8))[::-1])
                    trusted.add(gw)
                    break
    except Exception:
        pass
    try:
        import subprocess
        # Windows fallback
        out = subprocess.check_output('ipconfig', shell=True).decode(errors='ignore')
        for line in out.splitlines():
            if 'Default Gateway' in line and ':' in line:
                gw = line.split(':')[-1].strip()
                if gw:
                    trusted.add(gw)
    except Exception:
        pass
    return trusted


class AlertSystem:
    """Handle and log security alerts"""

    def __init__(self, output_file=None):
        self.output_file    = output_file or ALERTS_FILE
        self.ml_output_file = ML_ALERTS_FILE
        self._lock          = threading.Lock()
        # Load existing so count keeps growing across restarts
        self.alerts         = self._load(self.output_file)
        self.ml_alerts      = self._load(self.ml_output_file)
        # Cooldown tracker: (alert_type, src_ip) -> last timestamp
        self._last_seen     = {}

    def _load(self, path):
        try:
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)
        except Exception:
            pass
        return []

    def _is_cooldown(self, alert_type, src_ip):
        key  = (alert_type, src_ip or "")
        now  = time.time()
        cd   = COOLDOWN.get(alert_type, 15)
        last = self._last_seen.get(key, 0)
        if now - last < cd:
            return True
        self._last_seen[key] = now
        return False

    def add_alert(self, alert_data, packet_features):
        """Called by rule-based detectors - saves to alerts.json"""
        alert_type = alert_data.get('type')
        src_ip     = packet_features.get('src_ip', '')
        if self._is_cooldown(alert_type, src_ip):
            return   # suppress duplicate

        alert = {
            'timestamp':       datetime.now().isoformat(),
            'alert_type':      alert_type,
            'severity':        alert_data.get('severity'),
            'message':         alert_data.get('message'),
            'source_ip':       src_ip,
            'destination_ip':  packet_features.get('dst_ip'),
            'additional_info': {k: v for k, v in alert_data.items()
                                if k not in ['type','severity','message','detected']}
        }
        logger.warning(f"ALERT: {alert['alert_type']} - {alert['message']}")
        with self._lock:
            self.alerts.append(alert)
            self._write(self.output_file, self.alerts)

    def add_ml_alert(self, alert):
        """Called by FlowManager - saves to ml_alerts.json"""
        logger.warning(f"ML ALERT: {alert['alert_type']} - {alert['message']}")
        with self._lock:
            self.ml_alerts.append(alert)
            self._write(self.ml_output_file, self.ml_alerts)

    def _write(self, path, data):
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving {path}: {e}")

    def get_alert_summary(self):
        """Get summary of alerts"""
        all_alerts = self.alerts + self.ml_alerts
        if not all_alerts:
            return "No alerts detected"
        alert_types     = Counter(a['alert_type'] for a in all_alerts)
        severity_counts = Counter(a['severity']   for a in all_alerts)
        summary  = f"\n{'='*60}\nALERT SUMMARY\n{'='*60}\n"
        summary += f"Total: {len(all_alerts)} (Rule: {len(self.alerts)}, ML: {len(self.ml_alerts)})\n\n"
        summary += "By Type:\n"
        for t, c in alert_types.most_common():
            summary += f"  {t}: {c}\n"
        summary += "\nBy Severity:\n"
        for s, c in severity_counts.most_common():
            summary += f"  {s}: {c}\n"
        summary += f"{'='*60}\n"
<<<<<<< HEAD
        
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
=======
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
        return summary


class NetworkThreatAnalyzer:
    """Main threat analyzer integrating all detection modules"""
<<<<<<< HEAD
<<<<<<< HEAD

    def __init__(self, interface='eth0'):
        self.interface         = interface
        self.feature_extractor = FeatureExtractor()
        self.port_scan_detector= PortScanDetector()
        self.ddos_detector     = DDoSDetector()
        self.dns_detector      = DNSAnomalyDetector()
        self.packet_detector   = AbnormalPacketDetector()
        self.c2_detector       = C2BeaconingDetector()
        self.exfil_detector    = DataExfiltrationDetector()
        self.alert_system      = AlertSystem()

        # Flow-based ML
        self.ml    = MLModel()
        self.flows = FlowManager(self.ml, self.alert_system)

        self.packet_count = 0
        self.start_time   = time.time()

        # Auto-detect trusted IPs (local machine + gateway) and whitelist them
        trusted = get_trusted_ips()
        self.port_scan_detector.WHITELIST = trusted   # DDoS/Exfil use class attribute
        self.port_scan_detector.whitelist = trusted   # PortScanDetector uses instance attr
        self.ddos_detector.WHITELIST      = trusted
        self.exfil_detector.WHITELIST     = trusted
        logger.info(f"[WHITELIST] Trusted IPs auto-detected: {trusted}")

        if self.ml.ready:
            logger.info("[ML] Flow-based CICIDS2017 detection is ACTIVE.")
        else:
            logger.warning("[ML] Running in rule-based only mode.")

    def packet_callback(self, packet):
        """Process each captured packet"""
        self.packet_count += 1

        # Extract features
        features = self.feature_extractor.extract_packet_features(packet)

        # ── Feed into Flow Manager for ML ────────────────────────
        if IP in packet:
            src_ip   = features.get('src_ip', '')
            dst_ip   = features.get('dst_ip', '')
            src_port = features.get('src_port', 0)
            dst_port = features.get('dst_port', 0)
            proto    = packet[IP].proto
            size     = len(packet)
            flags    = int(packet[TCP].flags) if TCP in packet else None
            ts       = features['timestamp']
            if (src_ip, src_port) < (dst_ip, dst_port):
                flow_id, is_fwd = (src_ip,dst_ip,src_port,dst_port,proto), True
            else:
                flow_id, is_fwd = (dst_ip,src_ip,dst_port,src_port,proto), False
            self.flows.add_packet(flow_id, ts, size, flags, is_fwd)

        # ── Rule-based detectors ─────────────────────────────────
        alerts = []
        src_ip = features.get('src_ip')
        dst_ip = features.get('dst_ip')

        if features.get('dst_port'):
            payload_size = features.get('payload_length', 0)
            a = self.port_scan_detector.analyze(
                src_ip, dst_ip, features.get('dst_port'),
                features.get('timestamp'), payload_size)
            if a.get('detected'): alerts.append(a)

        if features.get('tcp_flags'):
            a = self.ddos_detector.analyze_syn_flood(
                src_ip, dst_ip, features.get('tcp_flags'),
                features.get('timestamp'))
            if a.get('detected'): alerts.append(a)

        if src_ip:
            a = self.ddos_detector.analyze_packet_flood(
                src_ip, dst_ip, features.get('timestamp'))
            if a.get('detected'): alerts.append(a)

        if features.get('dns_query'):
            a = self.dns_detector.analyze_dga(
                features.get('dns_query'), src_ip, dst_ip)
            if a.get('detected'): alerts.append(a)

        a = self.packet_detector.analyze_packet_size(
            features.get('packet_length'), src_ip, dst_ip)
        if a.get('detected'): alerts.append(a)

        a = self.packet_detector.analyze_malformed_packet(packet, src_ip, dst_ip)
        if a.get('detected'): alerts.append(a)

        if features.get('dst_port') and dst_ip:
            a = self.c2_detector.analyze(
                src_ip, dst_ip,
                features.get('dst_port'), features.get('timestamp'))
            if a.get('detected'): alerts.append(a)

        if src_ip and dst_ip:
            a = self.exfil_detector.analyze(
                src_ip, dst_ip,
                features.get('packet_length', 0), features.get('timestamp'))
            if a.get('detected'): alerts.append(a)

        for alert in alerts:
            self.alert_system.add_alert(alert, features)

        if self.packet_count % 1000 == 0:
            elapsed = time.time() - self.start_time
            logger.info(f"Processed {self.packet_count} pkts ({self.packet_count/elapsed:.1f}/s) | "
                        f"Flows: {len(self.flows.flows)}")
=======
    
=======

>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
    def __init__(self, interface='eth0'):
        self.interface         = interface
        self.feature_extractor = FeatureExtractor()
        self.port_scan_detector= PortScanDetector()
        self.ddos_detector     = DDoSDetector()
        self.dns_detector      = DNSAnomalyDetector()
        self.packet_detector   = AbnormalPacketDetector()
        self.c2_detector       = C2BeaconingDetector()
        self.exfil_detector    = DataExfiltrationDetector()
        self.alert_system      = AlertSystem()

        # Flow-based ML
        self.ml    = MLModel()
        self.flows = FlowManager(self.ml, self.alert_system)

        self.packet_count = 0
        self.start_time   = time.time()

        # Auto-detect trusted IPs (local machine + gateway) and whitelist them
        trusted = get_trusted_ips()
        self.port_scan_detector.WHITELIST = trusted   # DDoS/Exfil use class attribute
        self.port_scan_detector.whitelist = trusted   # PortScanDetector uses instance attr
        self.ddos_detector.WHITELIST      = trusted
        self.exfil_detector.WHITELIST     = trusted
        logger.info(f"[WHITELIST] Trusted IPs auto-detected: {trusted}")

        if self.ml.ready:
            logger.info("[ML] Flow-based CICIDS2017 detection is ACTIVE.")
        else:
            logger.warning("[ML] Running in rule-based only mode.")

    def packet_callback(self, packet):
        """Process each captured packet"""
        self.packet_count += 1

        # Extract features
        features = self.feature_extractor.extract_packet_features(packet)

        # -- Feed into Flow Manager for ML ------------------------
        if IP in packet:
            src_ip   = features.get('src_ip', '')
            dst_ip   = features.get('dst_ip', '')
            src_port = features.get('src_port', 0)
            dst_port = features.get('dst_port', 0)
            proto    = packet[IP].proto
            size     = len(packet)
            flags    = int(packet[TCP].flags) if TCP in packet else None
            ts       = features['timestamp']
            if (src_ip, src_port) < (dst_ip, dst_port):
                flow_id, is_fwd = (src_ip,dst_ip,src_port,dst_port,proto), True
            else:
                flow_id, is_fwd = (dst_ip,src_ip,dst_port,src_port,proto), False
            self.flows.add_packet(flow_id, ts, size, flags, is_fwd)

        # -- Rule-based detectors ---------------------------------
        alerts = []
        src_ip = features.get('src_ip')
        dst_ip = features.get('dst_ip')

        if features.get('dst_port'):
            payload_size = features.get('payload_length', 0)
            a = self.port_scan_detector.analyze(
                src_ip, dst_ip, features.get('dst_port'),
                features.get('timestamp'), payload_size)
            if a.get('detected'): alerts.append(a)

        if features.get('tcp_flags'):
            a = self.ddos_detector.analyze_syn_flood(
                src_ip, dst_ip, features.get('tcp_flags'),
                features.get('timestamp'))
            if a.get('detected'): alerts.append(a)

        if src_ip:
            a = self.ddos_detector.analyze_packet_flood(
                src_ip, dst_ip, features.get('timestamp'))
            if a.get('detected'): alerts.append(a)

        if features.get('dns_query'):
            a = self.dns_detector.analyze_dga(
                features.get('dns_query'), src_ip, dst_ip)
            if a.get('detected'): alerts.append(a)

        a = self.packet_detector.analyze_packet_size(
            features.get('packet_length'), src_ip, dst_ip)
        if a.get('detected'): alerts.append(a)

        a = self.packet_detector.analyze_malformed_packet(packet, src_ip, dst_ip)
        if a.get('detected'): alerts.append(a)

        if features.get('dst_port') and dst_ip:
            a = self.c2_detector.analyze(
                src_ip, dst_ip,
                features.get('dst_port'), features.get('timestamp'))
            if a.get('detected'): alerts.append(a)

        if src_ip and dst_ip:
            a = self.exfil_detector.analyze(
                src_ip, dst_ip,
                features.get('packet_length', 0), features.get('timestamp'))
            if a.get('detected'): alerts.append(a)

        for alert in alerts:
            self.alert_system.add_alert(alert, features)

        if self.packet_count % 1000 == 0:
            elapsed = time.time() - self.start_time
<<<<<<< HEAD
            rate = self.packet_count / elapsed
            logger.info(f"Processed {self.packet_count} packets ({rate:.2f} packets/sec)")
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
=======
            logger.info(f"Processed {self.packet_count} pkts ({self.packet_count/elapsed:.1f}/s) | "
                        f"Flows: {len(self.flows.flows)}")
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
    
    def start_live_capture(self, packet_count=0):
        """Start live packet capture"""
        logger.info(f"Starting live capture on interface {self.interface}")
        logger.info("Press Ctrl+C to stop")
        
        try:
            sniff(iface=self.interface, prn=self.packet_callback, count=packet_count, store=0)
        except KeyboardInterrupt:
            logger.info("Capture stopped by user")
        except Exception as e:
            logger.error(f"Error during capture: {e}")
        finally:
            self.print_summary()
    
    def analyze_pcap(self, pcap_file):
        """Analyze existing PCAP file"""
        logger.info(f"Analyzing PCAP file: {pcap_file}")
        
        try:
            packets = rdpcap(pcap_file)
            logger.info(f"Loaded {len(packets)} packets from {pcap_file}")
            
            for packet in packets:
                self.packet_callback(packet)
            
            self.print_summary()
            
        except Exception as e:
            logger.error(f"Error analyzing PCAP: {e}")
    
    def print_summary(self):
        """Print analysis summary"""
        elapsed = time.time() - self.start_time
        
        logger.info("\n" + "="*60)
        logger.info("ANALYSIS COMPLETE")
        logger.info("="*60)
        logger.info(f"Total packets processed: {self.packet_count}")
        logger.info(f"Total time: {elapsed:.2f} seconds")
        logger.info(f"Average rate: {self.packet_count/elapsed:.2f} packets/sec")
        logger.info(self.alert_system.get_alert_summary())


def main():
    """Main entry point"""
    print("""
    ╔-----------------------------------------------------------╗
    ║   Network Traffic Analyzer for Threat Detection          ║
    ║   Version 1.0                                            ║
    ╚-----------------------------------------------------------╝
    """)
    
    # Parse command line arguments
    if len(sys.argv) < 2:
        print("Usage:")
        print("  Live capture: python network_analyzer.py live [interface]")
        print("  PCAP analysis: python network_analyzer.py pcap <file.pcap>")
        sys.exit(1)
    
    mode = sys.argv[1].lower()
    
    analyzer = NetworkThreatAnalyzer()
    
    if mode == 'live':
        interface = sys.argv[2] if len(sys.argv) > 2 else 'eth0'
        analyzer.interface = interface
        analyzer.start_live_capture()
    
    elif mode == 'pcap':
        if len(sys.argv) < 3:
            print("Error: Please specify PCAP file")
            sys.exit(1)
        pcap_file = sys.argv[2]
        analyzer.analyze_pcap(pcap_file)
    
    else:
        print(f"Error: Unknown mode '{mode}'")
        print("Use 'live' or 'pcap'")
        sys.exit(1)


if __name__ == '__main__':
    main()