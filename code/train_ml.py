#!/usr/bin/env python3
"""
<<<<<<< HEAD
train_ml.py — SENTINEL ML Trainer (Enterprise Refactor)
========================================================
Trains an Isolation Forest anomaly detection model with a fully
leakage-free pipeline:

  load_data() → split_data() → preprocess() → train_model()
  → compute_threshold() → evaluate() → save_artifacts()

Key fixes over previous version:
  - Train/test split BEFORE any scaling
  - StandardScaler fitted ONLY on training normals
  - Isolation Forest trained ONLY on normal traffic
  - Threshold derived ONLY from training scores (no test label usage)
  - Evaluation performed ONLY on held-out test set

Run from project root:
    python code/train_ml.py
"""

import os
import sys
import json
import time
import pickle
import logging
import datetime
import numpy as np

# ── Logging setup ─────────────────────────────────────────────────────────────

LOG_FORMAT = "[%(asctime)s] [%(levelname)-8s] %(message)s"
logging.basicConfig(
    level=logging.INFO,
    format=LOG_FORMAT,
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(
            os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         "train_ml.log"),
            mode="w",
            encoding="utf-8",
        ),
    ],
)
log = logging.getLogger("sentinel.train_ml")

# ── Paths ─────────────────────────────────────────────────────────────────────
=======
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
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b

BASE_DIR      = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PCAP_DIR      = os.path.join(BASE_DIR, "data", "pcaps")
ALERTS_FILE   = os.path.join(BASE_DIR, "alerts.json")
MODEL_DIR     = os.path.join(BASE_DIR, "models")
MODEL_PATH    = os.path.join(MODEL_DIR, "isolation_forest.pkl")
REPORT_PATH   = os.path.join(MODEL_DIR, "training_report.json")
METADATA_PATH = os.path.join(MODEL_DIR, "model_metadata.json")

os.makedirs(MODEL_DIR, exist_ok=True)

<<<<<<< HEAD
# ── Constants ─────────────────────────────────────────────────────────────────

FEATURE_NAMES = [
    "packet_size", "is_tcp", "is_udp", "is_icmp",
    "dst_port", "src_port", "is_syn", "is_fin", "is_rst", "payload_size",
]

RANDOM_SEED   = 42
TEST_SIZE     = 0.25   # 25 % held out — never touched during training or thresholding

BANNER = """
+===========================================================+
|   SENTINEL ML Trainer  (Enterprise Edition)               |
|   Isolation Forest — Leakage-Free Anomaly Detection       |
+===========================================================+
"""

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 1 — Feature extraction
# ─────────────────────────────────────────────────────────────────────────────

def features_from_packet(pkt) -> list | None:
    """Extract a 10-element feature vector from a Scapy packet."""
    try:
        from scapy.layers.inet import TCP, UDP, ICMP
        size     = len(pkt)
        is_tcp   = int(pkt.haslayer(TCP))
        is_udp   = int(pkt.haslayer(UDP))
        is_icmp  = int(pkt.haslayer(ICMP))
        dst_port = src_port = is_syn = is_fin = is_rst = payload = 0

        if pkt.haslayer(TCP):
            dst_port = int(pkt[TCP].dport)
            src_port = int(pkt[TCP].sport)
            flags    = int(pkt[TCP].flags)
            is_syn   = int(bool(flags & 0x02))
            is_fin   = int(bool(flags & 0x01))
            is_rst   = int(bool(flags & 0x04))
            if pkt[TCP].payload:
                payload = len(bytes(pkt[TCP].payload))
        elif pkt.haslayer(UDP):
            dst_port = int(pkt[UDP].dport)
            src_port = int(pkt[UDP].sport)
            if pkt[UDP].payload:
                payload = len(bytes(pkt[UDP].payload))

        return [size, is_tcp, is_udp, is_icmp,
                dst_port, src_port, is_syn, is_fin, is_rst, payload]
    except Exception:
        return None


def features_from_alert(alert: dict) -> list:
    """Convert a saved alert dict to a feature vector."""
    info  = alert.get("additional_info", {})
    atype = alert.get("alert_type", "")
    size  = info.get("packet_size", 1500)
    return [
        size,
        int(atype in ("PORT_SCAN", "SYN_FLOOD")),
        int(atype == "DGA_DOMAIN"),
        0,
        80, 0,
        int(atype == "SYN_FLOOD"),
        0, 0,
        max(0, size - 40),
    ]


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 2 — Data loading
# ─────────────────────────────────────────────────────────────────────────────

def load_pcap_features() -> tuple[list, list]:
    """
    Load features from PCAP files.
    Files with 'malicious' or 'attack' in the name are labelled 1,
    all others 0 (normal).
    """
    try:
        from scapy.all import rdpcap
    except ImportError:
        log.warning("[DATA] Scapy not installed — skipping PCAP loading.")
        return [], []

    features, labels = [], []
    if not os.path.exists(PCAP_DIR):
        return [], []

    files = [f for f in os.listdir(PCAP_DIR) if f.endswith((".pcap", ".cap"))]
    if not files:
        return [], []

    for fname in files:
        is_mal = "malicious" in fname.lower() or "attack" in fname.lower()
        log.info("[DATA]   %s  →  label=%d", fname, int(is_mal))
        try:
            pkts = rdpcap(os.path.join(PCAP_DIR, fname))
            count = 0
            for pkt in pkts:
                vec = features_from_packet(pkt)
                if vec:
                    features.append(vec)
                    labels.append(int(is_mal))
                    count += 1
            log.info("[DATA]     %d packets extracted", count)
        except Exception as exc:
            log.warning("[DATA]     Could not read %s: %s", fname, exc)

    return features, labels


def load_alert_features() -> tuple[list, list]:
    """Load malicious samples from saved alerts.json."""
    features, labels = [], []
    if not os.path.exists(ALERTS_FILE):
        return [], []
    try:
        with open(ALERTS_FILE, "r", encoding="utf-8") as fh:
            alerts = json.load(fh)
        for a in alerts:
            features.append(features_from_alert(a))
            labels.append(1)   # all alerts are malicious by definition
        log.info("[DATA]   %d samples loaded from alerts.json", len(features))
    except Exception as exc:
        log.warning("[DATA]   Could not read alerts.json: %s", exc)
    return features, labels


def generate_synthetic_normal(n: int = 3000) -> tuple[list, list]:
    """
    Generate synthetic normal traffic when no real PCAP data is available.
    Covers HTTP, HTTPS, DNS, SSH, and TCP handshake patterns.
    """
    log.info("[DATA]   Generating %d synthetic normal samples (seed=%d)...",
             n, RANDOM_SEED)
    rng     = np.random.default_rng(RANDOM_SEED)
    samples = []
    chunk   = n // 5

    # HTTP
    for _ in range(chunk):
        s = int(rng.normal(800, 300))
        samples.append([max(40, s), 1, 0, 0, 80,
                         int(rng.integers(1024, 65535)), 0, 0, 0, max(0, s - 40)])
    # HTTPS
    for _ in range(chunk):
        s = int(rng.normal(1200, 400))
        samples.append([max(40, s), 1, 0, 0, 443,
                         int(rng.integers(1024, 65535)), 0, 0, 0, max(0, s - 40)])
    # DNS (UDP)
    for _ in range(chunk):
        s = int(rng.normal(100, 40))
        samples.append([max(28, s), 0, 1, 0, 53,
                         int(rng.integers(1024, 65535)), 0, 0, 0, max(0, s - 28)])
    # SSH
    for _ in range(chunk):
        s = int(rng.normal(500, 200))
        samples.append([max(40, s), 1, 0, 0, 22,
                         int(rng.integers(1024, 65535)), 0, 0, 0, max(0, s - 40)])
    # TCP SYN (connection setup — normal)
    for _ in range(chunk):
        port = int(rng.choice([80, 443, 22, 8080, 3389]))
        samples.append([60, 1, 0, 0, port,
                         int(rng.integers(1024, 65535)), 1, 0, 0, 0])

    log.info("[DATA]   Generated %d synthetic normal samples.", len(samples))
    return samples, [0] * len(samples)


def load_data() -> tuple[np.ndarray, np.ndarray]:
    """
    Aggregate all data sources and return raw (unscaled) X, y arrays.

    Labels: 0 = normal, 1 = malicious
    """
    log.info("[DATA] ── Loading data ─────────────────────────────────────")
    pcap_f, pcap_l   = load_pcap_features()
    alert_f, alert_l = load_alert_features()

    all_f = pcap_f + alert_f
    all_l = pcap_l + alert_l

    if not all_f:
        log.warning("[DATA] No real data found — falling back to synthetic normals only.")
        all_f, all_l = generate_synthetic_normal(3000)
    elif sum(1 for l in all_l if l == 0) == 0:
        log.warning("[DATA] No normal samples found — adding synthetic normals for contrast.")
        sf, sl = generate_synthetic_normal(max(len(all_f) * 3, 1000))
        all_f += sf
        all_l += sl

    X = np.array(all_f, dtype=np.float32)
    y = np.array(all_l, dtype=np.int32)

    n_normal = int((y == 0).sum())
    n_mal    = int((y == 1).sum())
    log.info("[DATA] Total: %d  |  Normal: %d  |  Malicious: %d", len(X), n_normal, n_mal)
    return X, y


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 3 — Train / test split  (LEAKAGE FIX #1)
# ─────────────────────────────────────────────────────────────────────────────

def split_data(X: np.ndarray, y: np.ndarray) -> tuple:
    """
    Split into train and test BEFORE any preprocessing.

    Why this matters:
        In the old code, StandardScaler.fit_transform() ran on ALL data before
        any split, meaning the scaler had already seen the test set's mean and
        variance. Any threshold or metric derived afterwards was therefore
        optimistic — the model had implicitly 'peeked' at the test distribution.

    Returns: X_train_raw, X_test_raw, y_train, y_test
    """
    from sklearn.model_selection import train_test_split

    # Stratify only if both classes are present
    stratify = y if len(np.unique(y)) > 1 else None

    X_train_raw, X_test_raw, y_train, y_test = train_test_split(
        X, y,
        test_size=TEST_SIZE,
        random_state=RANDOM_SEED,
        stratify=stratify,
    )

    log.info("[SPLIT] ── Train/test split ──────────────────────────────────")
    log.info("[SPLIT] Train: %d samples  (%.0f%%)", len(X_train_raw),
             100 * len(X_train_raw) / len(X))
    log.info("[SPLIT] Test : %d samples  (%.0f%%)", len(X_test_raw),
             100 * len(X_test_raw) / len(X))
    log.info("[SPLIT] Train — Normal: %d  |  Malicious: %d",
             int((y_train == 0).sum()), int((y_train == 1).sum()))
    log.info("[SPLIT] Test  — Normal: %d  |  Malicious: %d",
             int((y_test == 0).sum()), int((y_test == 1).sum()))

    # Safety assertions
    assert len(X_train_raw) + len(X_test_raw) == len(X), \
        "Split sizes do not add up to total — data loss!"
    assert len(X_train_raw) > 0,  "Training set is empty!"
    assert len(X_test_raw)  > 0,  "Test set is empty!"

    return X_train_raw, X_test_raw, y_train, y_test


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 4 — Preprocessing  (LEAKAGE FIX #2)
# ─────────────────────────────────────────────────────────────────────────────

def preprocess(
    X_train_raw: np.ndarray,
    X_test_raw:  np.ndarray,
    y_train:     np.ndarray,
) -> tuple:
    """
    Fit StandardScaler ONLY on training normals, then transform both sets.

    Why this matters:
        The old code called scaler.fit_transform(X) on ALL data before
        splitting.  This exposed the scaler to test-set statistics (mean,
        std), so when predictions were later made on the 'test' set, the
        scaling was no longer truly unseen — a subtle but real form of
        leakage that inflates anomaly detection metrics.

    Isolation Forest convention:
        The scaler (and later the model) should only see NORMAL training
        traffic during fitting.  We therefore filter to normal samples
        for the fit call, then transform the full training set.

    Returns: X_train_scaled, X_test_scaled, scaler
    """
    from sklearn.preprocessing import StandardScaler

    # Fit on training normals only
    X_train_normal = X_train_raw[y_train == 0]
    assert len(X_train_normal) > 0, \
        "No normal samples in training set — cannot fit scaler!"

    scaler  = StandardScaler()
    scaler.fit(X_train_normal)   # ← fit on training normals ONLY

    X_train_scaled = scaler.transform(X_train_raw)   # transform full train
    X_test_scaled  = scaler.transform(X_test_raw)    # transform test (no fit)

    log.info("[PREP] ── Preprocessing ──────────────────────────────────────")
    log.info("[PREP] Scaler fitted on %d normal training samples only.",
             len(X_train_normal))
    log.info("[PREP] Scaler was NOT fitted on test data.  ✓ (leakage-free)")
    log.info("[PREP] Feature means (train normal): %s",
             np.round(scaler.mean_, 2))

    return X_train_scaled, X_test_scaled, scaler


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 5 — Model training  (LEAKAGE FIX #3)
# ─────────────────────────────────────────────────────────────────────────────

def train_model(
    X_train_scaled: np.ndarray,
    y_train:        np.ndarray,
) -> object:
    """
    Train Isolation Forest on NORMAL traffic ONLY.

    Why this matters:
        Isolation Forest is an unsupervised anomaly detector.  Its core
        assumption is: "I know what normal looks like; anything that
        deviates far from normal is an anomaly."

        Training it on malicious samples (as the old code did) breaks this
        assumption.  The model learns to include attack patterns as part of
        its 'normal' boundary, so attacks become harder to isolate and
        anomaly scores are unreliable.

        Correct usage: fit only on normal, score everything, flag low-scoring
        samples as anomalies.
    """
    from sklearn.ensemble import IsolationForest

    X_train_normal = X_train_scaled[y_train == 0]
    n_normal       = len(X_train_normal)
    n_mal_in_train = int((y_train == 1).sum())

    assert n_normal > 0, "No normal samples to train on!"

    log.info("[TRAIN] ── Model training ───────────────────────────────────")
    log.info("[TRAIN] Training ONLY on %d normal samples.", n_normal)
    if n_mal_in_train > 0:
        log.info("[TRAIN] Excluded %d malicious training samples from fit.  ✓",
                 n_mal_in_train)
    log.info("[TRAIN] Malicious samples will only be used for evaluation.")

    # contamination='auto' is correct here because we are training
    # on normal-only data; the model does not need a contamination hint.
    model = IsolationForest(
        n_estimators=200,
        contamination="auto",   # appropriate for normal-only training
        max_samples="auto",
        random_state=RANDOM_SEED,
        n_jobs=-1,
    )

    t0 = time.time()
    model.fit(X_train_normal)
    log.info("[TRAIN] IsolationForest trained in %.1fs.", time.time() - t0)
    log.info("[TRAIN] Malicious samples NOT used during training.  ✓")

    return model


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 6 — Threshold computation  (LEAKAGE FIX #4)
# ─────────────────────────────────────────────────────────────────────────────

def compute_threshold(
    model:          object,
    X_train_scaled: np.ndarray,
    y_train:        np.ndarray,
) -> float:
    """
    Derive the anomaly threshold from TRAINING DATA ONLY.

    Why this matters:
        The old code computed the threshold using scores derived from
        ALL data (including the future test set), then reported metrics
        on the same data.  This is circular — the threshold was tuned to
        the exact dataset it was evaluated on, producing optimistic numbers
        that would not hold on new traffic.

    Strategy:
        Score the training set and set the threshold at the 5th percentile
        of normal-traffic scores.  This means only the lowest-scoring 5 %
        of normal flows would be (incorrectly) flagged — giving a ~5 % FPR
        on normals by construction, which is a principled starting point.

        If labelled malicious training samples are available, we use them to
        pick a threshold that separates the two distributions, still without
        touching the test set.
    """
    log.info("[THRESH] ── Threshold computation ────────────────────────────")

    train_scores  = model.score_samples(X_train_scaled)
    normal_scores = train_scores[y_train == 0]
    mal_scores    = train_scores[y_train == 1]

    if len(mal_scores) > 0:
        # Data-driven: midpoint between 20th pct of malicious and
        # 80th pct of normals (both from training set only)
        mal_p20  = float(np.percentile(mal_scores,   20))
        norm_p80 = float(np.percentile(normal_scores, 80))
        threshold = (mal_p20 + norm_p80) / 2.0
        log.info("[THRESH] Malicious training samples available — using "
                 "data-driven midpoint strategy.")
        log.info("[THRESH]   Malicious P20   : %.4f", mal_p20)
        log.info("[THRESH]   Normal    P80   : %.4f", norm_p80)
    else:
        # No labels: use 5th percentile of normal training scores.
        # This gives ~5 % FPR on the training distribution by design.
        threshold = float(np.percentile(normal_scores, 5))
        log.info("[THRESH] No malicious training samples — using "
                 "5th-percentile of normal scores.")

    log.info("[THRESH] Threshold : %.4f", threshold)
    log.info("[THRESH] Score range (train): [%.4f, %.4f]",
             train_scores.min(), train_scores.max())
    log.info("[THRESH] Test set was NOT used for thresholding.  ✓")

    return threshold


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 7 — Evaluation on held-out test set  (LEAKAGE FIX #5)
# ─────────────────────────────────────────────────────────────────────────────

def evaluate(
    model:         object,
    X_test_scaled: np.ndarray,
    y_test:        np.ndarray,
    threshold:     float,
) -> dict:
    """
    Evaluate ONLY on the untouched test set.

    Returns a metrics dict for saving to JSON artifacts.
    """
    from sklearn.metrics import (
        classification_report, confusion_matrix,
        precision_score, recall_score, f1_score,
    )

    log.info("[EVAL] ── Evaluation on held-out test set ───────────────────")
    log.info("[EVAL] Test set has never been seen by scaler, model, "
             "or threshold.  ✓")

    test_scores  = model.score_samples(X_test_scaled)
    predictions  = (test_scores < threshold).astype(int)  # 1 = anomaly

    n_normal_test = int((y_test == 0).sum())
    n_mal_test    = int((y_test == 1).sum())
    log.info("[EVAL] Test distribution — Normal: %d  |  Malicious: %d",
             n_normal_test, n_mal_test)

    if len(np.unique(y_test)) < 2:
        log.warning("[EVAL] Only one class in test set — metrics skipped.")
        return {
            "precision": 0.0, "recall": 0.0, "f1": 0.0,
            "false_positive_rate": 0.0,
            "note": "single class in test set",
        }

    precision = float(precision_score(y_test, predictions, zero_division=0))
    recall    = float(recall_score(y_test, predictions,    zero_division=0))
    f1        = float(f1_score(y_test, predictions,        zero_division=0))

    cm = confusion_matrix(y_test, predictions)
    tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    log.info("[EVAL] ── Results ────────────────────────────────────────────")
    log.info("[EVAL]   Precision          : %.2f%%", precision * 100)
    log.info("[EVAL]   Recall (Detection) : %.2f%%", recall    * 100)
    log.info("[EVAL]   F1 Score           : %.2f%%", f1        * 100)
    log.info("[EVAL]   False Positive Rate: %.2f%%", fpr       * 100)
    log.info("[EVAL]   Confusion Matrix   : TN=%d  FP=%d  FN=%d  TP=%d",
             tn, fp, fn, tp)
    log.info("[EVAL] ── Classification Report ─────────────────────────────")
    report = classification_report(
        y_test, predictions, target_names=["Normal", "Malicious"]
    )
    for line in report.split("\n"):
        if line.strip():
            log.info("[EVAL]   %s", line)

    # Realistic expectation notes
    log.info("[EVAL] ── Performance Context ───────────────────────────────")
    if f1 > 0.90:
        log.info("[EVAL]   F1 > 90%% — excellent for an unsupervised detector.")
    elif f1 > 0.70:
        log.info("[EVAL]   F1 70–90%% — good for Isolation Forest on real traffic.")
    elif f1 > 0.50:
        log.info("[EVAL]   F1 50–70%% — acceptable; consider supervised alternatives.")
    else:
        log.warning("[EVAL]   F1 < 50%% — poor; review feature quality or data balance.")

    if fpr > 0.05:
        log.warning("[EVAL]   FPR > 5%% — alert fatigue risk.  Raise threshold or "
                    "review benign traffic representation in training data.")

    return {
        "precision":          round(precision, 4),
        "recall":             round(recall,    4),
        "f1":                 round(f1,        4),
        "false_positive_rate":round(fpr,       4),
        "true_positives":     int(tp),
        "false_positives":    int(fp),
        "true_negatives":     int(tn),
        "false_negatives":    int(fn),
        "test_normal":        n_normal_test,
        "test_malicious":     n_mal_test,
    }


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 8 — Artifact saving (dashboard-compatible)
# ─────────────────────────────────────────────────────────────────────────────

def save_artifacts(
    model:     object,
    scaler:    object,
    threshold: float,
    metrics:   dict,
    n_train:   int,
    elapsed:   float,
) -> None:
    """
    Save model pickle, training_report.json, and model_metadata.json.

    The pickle format is identical to the old code so ml_detector.py
    continues to work without any changes.
    """
    log.info("[SAVE] ── Saving artifacts ───────────────────────────────────")

    # ── Model pickle ──────────────────────────────────────────────────────────
    payload = {
        "model":         model,
        "scaler":        scaler,
        "threshold":     float(threshold),
        "features":      FEATURE_NAMES,
        "n_samples":     n_train,
        "contamination": "auto",
        # Extra metadata for auditability
        "trained_normal_only": True,
        "leakage_free":        True,
    }
    with open(MODEL_PATH, "wb") as fh:
        pickle.dump(payload, fh)
    log.info("[SAVE] Model pickle  → %s", MODEL_PATH)

    now_iso = datetime.datetime.utcnow().isoformat()

    # ── training_report.json ──────────────────────────────────────────────────
    report = {
        "trained_at":          now_iso,
        "training_time_s":     round(elapsed, 2),
        "n_train_samples":     n_train,
        "normal_only_training":True,
        "leakage_free":        True,
        "threshold":           round(float(threshold), 4),
        **{k: round(v, 4) if isinstance(v, float) else v
           for k, v in metrics.items()},
    }
    with open(REPORT_PATH, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    log.info("[SAVE] Training report → %s", REPORT_PATH)

    # ── model_metadata.json (read by dashboard Model Performance panel) ───────
    metadata = {
        "trained":    True,
        "samples":    n_train,
        "precision":  metrics.get("precision", 0.0),
        "recall":     metrics.get("recall",    0.0),
        "f1":         metrics.get("f1",        0.0),
        "threshold":  round(float(threshold),  4),
        "trained_at": now_iso,
        "leakage_free":       True,
        "normal_only_training": True,
    }
    with open(METADATA_PATH, "w", encoding="utf-8") as fh:
        json.dump(metadata, fh, indent=2)
    log.info("[SAVE] Model metadata → %s", METADATA_PATH)


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 9 — Master training function
# ─────────────────────────────────────────────────────────────────────────────

def train() -> None:
    """
    Full leakage-free training pipeline:

        load_data()
            → split_data()
            → preprocess()
            → train_model()
            → compute_threshold()
            → evaluate()
            → save_artifacts()
    """
    print(BANNER)
    t_start = time.time()

    # 1. Load raw data
    X, y = load_data()

    # 2. Split BEFORE any preprocessing
    X_train_raw, X_test_raw, y_train, y_test = split_data(X, y)

    # 3. Scale using training normals only
    X_train_scaled, X_test_scaled, scaler = preprocess(
        X_train_raw, X_test_raw, y_train
    )

    # 4. Train on normal traffic only
    model = train_model(X_train_scaled, y_train)

    # 5. Derive threshold from training data only
    threshold = compute_threshold(model, X_train_scaled, y_train)

    # 6. Evaluate on held-out test set
    metrics = evaluate(model, X_test_scaled, y_test, threshold)

    # 7. Save everything
    elapsed = time.time() - t_start
    save_artifacts(model, scaler, threshold, metrics, len(X_train_raw), elapsed)

    # ── Final summary ─────────────────────────────────────────────────────────
    f1  = metrics.get("f1",        0.0)
    pre = metrics.get("precision", 0.0)
    rec = metrics.get("recall",    0.0)
    fpr = metrics.get("false_positive_rate", 0.0)

    print(f"""
+===========================================================+
|   Training Complete!  (Leakage-Free Pipeline)            |
|                                                           |
|   Train samples : {len(X_train_raw):<6}                              |
|   Test  samples : {len(X_test_raw):<6}  (held-out, never touched)    |
|                                                           |
|   Precision : {pre:.1%}                                    |
|   Recall    : {rec:.1%}                                    |
|   F1 Score  : {f1:.1%}                                    |
|   FPR       : {fpr:.1%}  (false alarms on normal traffic) |
|   Threshold : {threshold:.4f}                                   |
=======
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
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
|                                                           |
|   Next: python start.py                                  |
|   ML anomaly detection is now ACTIVE on the dashboard!  |
+===========================================================+
""")

<<<<<<< HEAD

# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    train()
=======
if __name__ == "__main__":
    train()
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
