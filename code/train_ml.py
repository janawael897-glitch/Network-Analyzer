#!/usr/bin/env python3
"""
train_ml.py — Trains Isolation Forest anomaly detection model.

Run from project root:
    python code/train_ml.py

Works even with no PCAP files — uses synthetic normal traffic as baseline.
"""

import os, sys, json, time, pickle, logging
import numpy as np

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s",
                    handlers=[logging.StreamHandler(sys.stdout)])
log = logging.getLogger(__name__)

BASE_DIR      = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PCAP_DIR      = os.path.join(BASE_DIR, "data", "pcaps")
ALERTS_FILE   = os.path.join(BASE_DIR, "alerts.json")
MODEL_DIR     = os.path.join(BASE_DIR, "models")
MODEL_PATH    = os.path.join(MODEL_DIR, "isolation_forest.pkl")
REPORT_PATH   = os.path.join(MODEL_DIR, "training_report.json")
METADATA_PATH = os.path.join(MODEL_DIR, "model_metadata.json")

os.makedirs(MODEL_DIR, exist_ok=True)

BANNER = """
+===========================================================+
|   SENTINEL ML Trainer                                     |
|   Isolation Forest Anomaly Detection                      |
+===========================================================+
"""

# ── Feature extraction ────────────────────────────────────────────

def features_from_packet(pkt):
    try:
        from scapy.layers.inet import TCP, UDP, ICMP
        size    = len(pkt)
        is_tcp  = int(pkt.haslayer(TCP))
        is_udp  = int(pkt.haslayer(UDP))
        is_icmp = int(pkt.haslayer(ICMP))
        dst_port = src_port = is_syn = is_fin = is_rst = payload = 0
        if pkt.haslayer(TCP):
            dst_port = int(pkt[TCP].dport); src_port = int(pkt[TCP].sport)
            flags = int(pkt[TCP].flags)
            is_syn = int(bool(flags & 0x02)); is_fin = int(bool(flags & 0x01)); is_rst = int(bool(flags & 0x04))
            if pkt[TCP].payload: payload = len(bytes(pkt[TCP].payload))
        elif pkt.haslayer(UDP):
            dst_port = int(pkt[UDP].dport); src_port = int(pkt[UDP].sport)
            if pkt[UDP].payload: payload = len(bytes(pkt[UDP].payload))
        return [size, is_tcp, is_udp, is_icmp, dst_port, src_port, is_syn, is_fin, is_rst, payload]
    except Exception:
        return None

def features_from_alert(alert):
    info  = alert.get("additional_info", {})
    atype = alert.get("alert_type", "")
    size  = info.get("packet_size", 1500)
    return [size, int(atype in ("PORT_SCAN","SYN_FLOOD")), int(atype=="DGA_DOMAIN"), 0,
            80, 0, int(atype=="SYN_FLOOD"), 0, 0, max(0, size-40)]

# ── Data loaders ──────────────────────────────────────────────────

def load_pcap_features():
    try:
        from scapy.all import rdpcap
    except ImportError:
        return [], []
    features, labels = [], []
    if not os.path.exists(PCAP_DIR): return [], []
    files = [f for f in os.listdir(PCAP_DIR) if f.endswith((".pcap",".cap"))]
    if not files: return [], []
    for fname in files:
        is_mal = "malicious" in fname.lower() or "attack" in fname.lower()
        log.info(f"  Loading: {fname} ({'malicious' if is_mal else 'normal'})")
        try:
            pkts = rdpcap(os.path.join(PCAP_DIR, fname)); count = 0
            for pkt in pkts:
                f = features_from_packet(pkt)
                if f: features.append(f); labels.append(int(is_mal)); count += 1
            log.info(f"    -> {count} packets extracted")
        except Exception as e:
            log.warning(f"    -> Could not read {fname}: {e}")
    return features, labels

def load_alert_features():
    features, labels = [], []
    if not os.path.exists(ALERTS_FILE): return [], []
    try:
        with open(ALERTS_FILE,"r",encoding="utf-8") as f: alerts = json.load(f)
        for a in alerts: features.append(features_from_alert(a)); labels.append(1)
        log.info(f"  Loaded {len(features)} samples from alerts.json")
    except Exception as e:
        log.warning(f"Could not read alerts.json: {e}")
    return features, labels

def generate_synthetic_normal(n=3000):
    log.info(f"  Generating {n} synthetic normal traffic samples...")
    rng = np.random.default_rng(42); samples = []
    for _ in range(n//5):
        s = int(rng.normal(800,300)); samples.append([max(40,s),1,0,0,80,int(rng.integers(1024,65535)),0,0,0,max(0,s-40)])
    for _ in range(n//5):
        s = int(rng.normal(1200,400)); samples.append([max(40,s),1,0,0,443,int(rng.integers(1024,65535)),0,0,0,max(0,s-40)])
    for _ in range(n//5):
        s = int(rng.normal(100,40)); samples.append([max(28,s),0,1,0,53,int(rng.integers(1024,65535)),0,0,0,max(0,s-28)])
    for _ in range(n//5):
        s = int(rng.normal(500,200)); samples.append([max(40,s),1,0,0,22,int(rng.integers(1024,65535)),0,0,0,max(0,s-40)])
    for _ in range(n//5):
        port = int(rng.choice([80,443,22,8080,3389])); samples.append([60,1,0,0,port,int(rng.integers(1024,65535)),1,0,0,0])
    log.info(f"  Generated {len(samples)} synthetic normal samples")
    return samples, [0]*len(samples)

# ── Training ──────────────────────────────────────────────────────

def train():
    print(BANNER)
    start = time.time()

    log.info("[1/4] Loading PCAP data...")
    pcap_feats, pcap_labels = load_pcap_features()
    log.info("[2/4] Loading alert data...")
    alert_feats, alert_labels = load_alert_features()

    all_feats  = pcap_feats + alert_feats
    all_labels = pcap_labels + alert_labels

    if not all_feats:
        log.warning("No data found — using synthetic normal traffic as baseline.")
        all_feats, all_labels = generate_synthetic_normal(3000)
    elif all_labels.count(0) == 0:
        log.info("  Only malicious samples — adding synthetic normal for contrast.")
        sf, sl = generate_synthetic_normal(max(len(all_feats)*3, 1000))
        all_feats += sf; all_labels += sl

    X = np.array(all_feats, dtype=np.float32)
    log.info(f"\n  Total: {len(X)}  Normal: {all_labels.count(0)}  Malicious: {all_labels.count(1)}")

    log.info("\n[3/4] Normalizing features...")
    from sklearn.preprocessing import StandardScaler
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    log.info("[4/4] Training Isolation Forest...")
    from sklearn.ensemble import IsolationForest
    n_mal = all_labels.count(1)
    contamination = min(max(n_mal/len(all_labels), 0.05), 0.4) if n_mal > 0 else 0.05
    log.info(f"  Contamination: {contamination:.2f}")

    model = IsolationForest(n_estimators=200, contamination=contamination,
                            max_samples="auto", random_state=42, n_jobs=-1)
    model.fit(X_scaled)

    scores = model.score_samples(X_scaled)
    if n_mal > 0:
        mal_s  = [s for s,l in zip(scores,all_labels) if l==1]
        norm_s = [s for s,l in zip(scores,all_labels) if l==0]
        threshold = (np.percentile(mal_s,20) + (np.percentile(norm_s,80) if norm_s else np.percentile(mal_s,20))) / 2
    else:
        threshold = float(np.percentile(scores, 15))

    log.info(f"  Score range: {scores.min():.4f} to {scores.max():.4f}")
    log.info(f"  Threshold  : {threshold:.4f}")

    predictions = (scores < threshold).astype(int)
    y = np.array(all_labels)
    precision = recall = f1 = 0.0

    if len(set(all_labels)) > 1:
        from sklearn.metrics import classification_report, confusion_matrix
        log.info("\n  Classification Report:")
        for line in classification_report(y, predictions, target_names=["Normal","Malicious"]).split("\n"):
            if line.strip(): log.info("    " + line)
        cm = confusion_matrix(y, predictions)
        tn,fp,fn,tp = cm.ravel() if cm.size==4 else (0,0,0,0)
        precision = tp/(tp+fp) if (tp+fp)>0 else 0
        recall    = tp/(tp+fn) if (tp+fn)>0 else 0
        f1        = 2*precision*recall/(precision+recall) if (precision+recall)>0 else 0
        log.info(f"\n  Precision: {precision:.2%}  Recall: {recall:.2%}  F1: {f1:.2%}")
    else:
        log.info("  (Single class — skipping report)")

    # Save model (with scaler — critical for correct scoring at runtime)
    with open(MODEL_PATH,"wb") as f:
        pickle.dump({"model":model,"scaler":scaler,"threshold":float(threshold),
                     "features":["packet_size","is_tcp","is_udp","is_icmp",
                                 "dst_port","src_port","is_syn","is_fin","is_rst","payload_size"],
                     "n_samples":len(X),"contamination":contamination}, f)
    log.info(f"\n  Model saved    : {MODEL_PATH}")

    elapsed = time.time() - start

    # Save training_report.json
    with open(REPORT_PATH,"w") as f:
        json.dump({"trained_at":__import__("datetime").datetime.utcnow().isoformat(),
                   "total_samples":len(X),"normal_samples":all_labels.count(0),
                   "malicious_samples":all_labels.count(1),"threshold":round(float(threshold),4),
                   "precision":round(precision,4),"recall":round(recall,4),"f1_score":round(f1,4),
                   "training_time_s":round(elapsed,2)}, f, indent=2)

    # Save model_metadata.json (read by dashboard Model Performance panel)
    with open(METADATA_PATH,"w") as f:
        json.dump({"trained":True,"samples":len(X),"precision":round(precision,4),
                   "recall":round(recall,4),"f1":round(f1,4),"threshold":round(float(threshold),4),
                   "trained_at":__import__("datetime").datetime.utcnow().isoformat()}, f, indent=2)
    log.info(f"  Metadata saved : {METADATA_PATH}")

    print(f"""
+===========================================================+
|   Training Complete!                                      |
|   Samples: {len(X):<6}  Precision: {precision:.0%}  F1: {f1:.0%}           |
|   Threshold: {threshold:.4f}                                   |
|                                                           |
|   Next: python start.py                                  |
|   ML anomaly detection is now ACTIVE on the dashboard!  |
+===========================================================+
""")

if __name__ == "__main__":
    train()
