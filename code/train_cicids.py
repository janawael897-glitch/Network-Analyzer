#!/usr/bin/env python3
"""
train_cicids.py — PacketGuard  (v3 — Enterprise-Grade Training)
===============================================================
Trains the supervised detection model for PacketGuard using the
CICIDS2017 dataset.

WHAT'S NEW IN v3
----------------
• Safe SMOTE       — classes with < MIN_SAMPLES_FOR_SMOTE real samples are
                     merged into OTHER instead of being synthetically
                     exploded (was: 7→95k, now: stays in OTHER).
                     Max oversample ratio capped at MAX_SMOTE_RATIO (5×).

• Column auto-map  — fuzzy matching bridges CSV naming differences so
                     "Destination Port", "Total Backward Packets" etc. are
                     recovered correctly from any CICIDS2017 CSV variant.

• Faster CV        — 3-fold CV on a 200k-row stratified sample instead of
                     5-fold on the full 2M-row set. Same signal, 60% less
                     RAM/CPU.

• FP-aware eval    — reports False Positive Rate (primary IDS metric),
                     BENIGN precision/recall, and per-class F1 prominently.

• class_weight     — RF uses balanced weighting for residual imbalance
                     instead of relying solely on synthetic oversampling.

• Winner selection — FPR included in winner scoring (not just F1).

• Architecture     — RF/XGBoost is PRIMARY detector. Isolation Forest is
                     ANOMALY layer only (trained on BENIGN flows).

HOW TO USE
----------
    python code/train_cicids.py
    python start.py

Output files (models/):
    cicids_rf.pkl, isolation_forest.pkl, cicids_scaler.pkl,
    cicids_label_encoder.pkl, cicids_features.json, model_metadata.json
"""

import os
import re
import sys
import json
import glob
import pickle
import warnings
from collections import Counter
from datetime import datetime

import numpy as np
import pandas as pd

warnings.filterwarnings("ignore")

# ── Paths ──────────────────────────────────────────────────────────
BASE_DIR   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR   = os.path.join(BASE_DIR, "data", "dataset")
MODELS_DIR = os.path.join(BASE_DIR, "models")
os.makedirs(MODELS_DIR, exist_ok=True)
os.makedirs(DATA_DIR,   exist_ok=True)

# ── Safety thresholds ──────────────────────────────────────────────
# Classes with fewer real samples than this are merged into OTHER
# instead of being synthetically exploded by SMOTE.
MIN_SAMPLES_FOR_SMOTE = 100

# Maximum growth ratio SMOTE can apply to any minority class.
# 5× means 200 samples → at most 1,000. Prevents memorisation.
MAX_SMOTE_RATIO = 5

# CV runs on at most this many rows (stratified sample of training set).
CV_SAMPLE_CAP = 200_000

# Number of CV folds (3 is enough for 200k+ rows)
CV_FOLDS = 3

# ── Label normalisation ────────────────────────────────────────────
LABEL_MAP = {
    "benign":                          "BENIGN",
    "bot":                             "OTHER",
    "botnet":                          "OTHER",
    "ddos":                            "DDOS",
    "dos goldeneye":                   "DOS",
    "dos hulk":                        "DOS",
    "dos slowhttptest":                "DOS",
    "dos slowloris":                   "DOS",
    "ftp-patator":                     "BRUTE_FORCE",
    "ssh-patator":                     "BRUTE_FORCE",
    # HEARTBLEED (11 real samples) and INFILTRATION (36 real samples)
    # are merged into OTHER — too few to SMOTE safely.
    "heartbleed":                      "OTHER",
    "infiltration":                    "OTHER",
    "portscan":                        "PORT_SCAN",
    "web attack \u2013 brute force":   "WEB_ATTACK",
    "web attack \u2013 sql injection": "WEB_ATTACK",
    "web attack \u2013 xss":           "WEB_ATTACK",
    "web attack \u2014 brute force":   "WEB_ATTACK",
    "web attack \u2014 sql injection": "WEB_ATTACK",
    "web attack \u2014 xss":           "WEB_ATTACK",
    "web attack – brute force":        "WEB_ATTACK",
    "web attack – sql injection":      "WEB_ATTACK",
    "web attack – xss":                "WEB_ATTACK",
    "web attack brute force":          "WEB_ATTACK",
    "web attack sql injection":        "WEB_ATTACK",
    "web attack xss":                  "WEB_ATTACK",
}

# ── Features ───────────────────────────────────────────────────────
SELECTED_FEATURES = [
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


# ══════════════════════════════════════════════════════════════════
# Column auto-mapper
# ══════════════════════════════════════════════════════════════════

def _norm(name: str) -> str:
    """Lowercase + collapse whitespace/underscore/dash → single space."""
    return re.sub(r"[\s_\-/]+", " ", name.strip().lower())


def _build_col_map(df_columns, desired_features):
    """
    Return {actual_csv_col: canonical_feature_name}.
    Uses exact normalised match first, then single-hit substring fuzzy match.
    """
    norm_index = {_norm(c): c for c in df_columns}
    mapping, unmatched = {}, []

    for feat in desired_features:
        key = _norm(feat)
        if key in norm_index:
            mapping[norm_index[key]] = feat
        else:
            hits = [actual for nk, actual in norm_index.items()
                    if key in nk or nk in key]
            if len(hits) == 1:
                mapping[hits[0]] = feat
                print(f"  [COL-MAP fuzzy] '{hits[0]}' → '{feat}'")
            else:
                unmatched.append(feat)

    matched = len(mapping)
    total   = len(desired_features)
    if unmatched:
        print(f"  [COL-MAP] Matched {matched}/{total}. "
              f"Zero-padding {len(unmatched)} missing: {unmatched}")
    else:
        print(f"  [COL-MAP] All {total} features matched ✓")
    return mapping


def _find_label_col(df_columns):
    candidates = {"label", "labels", "attack", "class", "category"}
    for col in df_columns:
        if col.strip().lower() in candidates:
            return col
    last = df_columns[-1]
    print(f"  [WARN] Label column not detected — using last column: '{last}'")
    return last


# ══════════════════════════════════════════════════════════════════
# Data loading
# ══════════════════════════════════════════════════════════════════

def load_cicids_data():
    csv_files = glob.glob(os.path.join(DATA_DIR, "**", "*.csv"), recursive=True)
    if not csv_files:
        print(f"\n[ERROR] No CSV files found in: {DATA_DIR}")
        print("  Place CICIDS2017 CSV(s) in that folder and re-run.")
        sys.exit(1)

    print(f"[DATA] Found {len(csv_files)} CSV file(s):")
    dfs = []
    for f in sorted(csv_files):
        try:
            df = pd.read_csv(f, low_memory=False)
            df.columns = df.columns.str.strip()
            print(f"       {os.path.basename(f):45s}  {len(df):>9,} rows")
            dfs.append(df)
        except Exception as e:
            print(f"  [WARN] Could not read {f}: {e}")

    if not dfs:
        print("[ERROR] No files could be loaded.")
        sys.exit(1)

    data = pd.concat(dfs, ignore_index=True)
    print(f"\n[DATA] Total rows: {len(data):,}")
    return data


# ══════════════════════════════════════════════════════════════════
# Preprocessing
# ══════════════════════════════════════════════════════════════════

def preprocess(df):
    """
    1. Auto-map CSV column names → canonical SELECTED_FEATURES (fixes mismatches).
    2. Normalise labels via LABEL_MAP (ultra-rare classes → OTHER).
    3. Drop NaN/Inf rows.
    4. Clip extreme outliers.
    Returns X (DataFrame, columns = SELECTED_FEATURES), y (str array), label_counts.
    """
    label_col = _find_label_col(df.columns)
    print(f"\n[PREP] Label column: '{label_col}'")

    # ── Column mapping FIRST (before any column-dependent operations) ─
    print("[PREP] Mapping CSV columns → canonical feature names...")
    col_map = _build_col_map(df.columns, SELECTED_FEATURES)
    df = df.rename(columns=col_map)

    # ── Label normalisation ───────────────────────────────────────────
    df["_label"] = (
        df[label_col].astype(str).str.strip().str.lower()
        .map(lambda x: LABEL_MAP.get(x, "OTHER"))
    )
    df = df.dropna(subset=["_label"])

    # ── Label distribution ────────────────────────────────────────────
    label_counts = df["_label"].value_counts()
    print("\n[PREP] Label distribution after normalisation:")
    for lbl, cnt in label_counts.items():
        note = ""
        if lbl != "BENIGN" and cnt < MIN_SAMPLES_FOR_SMOTE:
            note = f"  ← in OTHER (only {cnt} real samples)"
        print(f"       {lbl:25s}  {cnt:>9,}  ({cnt/len(df)*100:.1f}%){note}")

    # ── Available vs missing features ─────────────────────────────────
    available = [f for f in SELECTED_FEATURES if f in df.columns]
    missing   = [f for f in SELECTED_FEATURES if f not in df.columns]

    # ── Drop NaN / Inf ────────────────────────────────────────────────
    df = df.replace([np.inf, -np.inf], np.nan)
    before = len(df)
    df = df.dropna(subset=available)
    print(f"\n[PREP] Dropped {before - len(df):,} NaN/Inf rows → {len(df):,} remaining")

    if missing:
        print(f"[PREP] Zero-padding {len(missing)} missing feature(s): {missing}")

    # ── Build feature matrix ──────────────────────────────────────────
    X = df[available].copy()
    for f in missing:
        X[f] = 0.0
    X = X[SELECTED_FEATURES].copy()

    # Clip per-column at 99.99th percentile
    for col in X.columns:
        q_hi = X[col].quantile(0.9999)
        if q_hi > 0:
            X[col] = X[col].clip(upper=q_hi)

    y = df["_label"].values
    return X, y, label_counts


# ══════════════════════════════════════════════════════════════════
# Safe SMOTE
# ══════════════════════════════════════════════════════════════════

def apply_smote(X_train, y_train, label_encoder):
    """
    Conservative SMOTE:
    - Only runs on classes with >= MIN_SAMPLES_FOR_SMOTE real samples.
    - Caps growth at MAX_SMOTE_RATIO × original count.
    - Ultra-rare classes (HEARTBLEED/INFILTRATION) are already folded
      into OTHER by preprocess(), so they never reach this function.
    """
    try:
        from imblearn.over_sampling import SMOTE
    except ImportError:
        print("[SMOTE] imbalanced-learn not installed — skipping. "
              "pip install imbalanced-learn")
        return X_train, y_train

    counts = Counter(y_train)
    majority_count = max(counts.values())

    eligible = {
        cls: cnt for cls, cnt in counts.items()
        if MIN_SAMPLES_FOR_SMOTE <= cnt < majority_count * 0.30
    }

    if not eligible:
        print("[SMOTE] No eligible minority classes — skipping.")
        print("        RF class_weight='balanced' handles residual imbalance.")
        return X_train, y_train

    sampling_strategy = {}
    for cls, cnt in eligible.items():
        target = min(cnt * MAX_SMOTE_RATIO, int(majority_count * 0.30))
        target = max(target, cnt)
        sampling_strategy[cls] = target

    min_cnt = min(counts[cls] for cls in eligible)
    k = max(1, min(5, min_cnt - 1))

    print(f"\n[SMOTE] Balancing {len(eligible)} class(es)  "
          f"(k={k}, max_ratio={MAX_SMOTE_RATIO}×):")
    for cls, cnt in eligible.items():
        name   = label_encoder.inverse_transform([cls])[0]
        target = sampling_strategy[cls]
        print(f"        {name:25s}  {cnt:>7,} → {target:>7,}  "
              f"({target/cnt:.1f}× growth)")

    try:
        smote = SMOTE(sampling_strategy=sampling_strategy,
                      k_neighbors=k, random_state=42)
        X_res, y_res = smote.fit_resample(X_train, y_train)
        print(f"[SMOTE] Done. {len(X_train):,} → {len(X_res):,} training rows")
        return X_res, y_res
    except Exception as e:
        print(f"[SMOTE] Failed ({e}) — continuing without resampling.")
        return X_train, y_train


# ══════════════════════════════════════════════════════════════════
# Model factories
# ══════════════════════════════════════════════════════════════════

def build_random_forest():
    from sklearn.ensemble import RandomForestClassifier
    return RandomForestClassifier(
        n_estimators=120,
        max_depth=18,
        min_samples_leaf=10,
        max_features="sqrt",
        n_jobs=4,          # ← was -1, this is the freeze fix
        random_state=42,
        class_weight="balanced",
    )


def build_xgboost(n_classes):
    try:
        from xgboost import XGBClassifier
        return XGBClassifier(
            n_estimators=300,
            max_depth=7,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            min_child_weight=5,
            use_label_encoder=False,
            eval_metric="mlogloss",
            n_jobs=-1,
            random_state=42,
            verbosity=0,
        )
    except ImportError:
        print("[TRAIN] XGBoost not installed — skipping. pip install xgboost")
        return None


def train_isolation_forest(X_benign):
    """Anomaly layer — trained on BENIGN only. NOT the primary detector."""
    from sklearn.ensemble import IsolationForest
    print(f"\n[ISO]  Training Isolation Forest on {len(X_benign):,} BENIGN samples")
    print("       Role: anomaly/unknown-behaviour layer ONLY — not primary detector.")
    iso = IsolationForest(
        n_estimators=200,
        contamination=0.02,
        random_state=42,
        n_jobs=-1,
    )
    iso.fit(X_benign)
    return iso


# ══════════════════════════════════════════════════════════════════
# Cross-validation (fast, memory-safe)
# ══════════════════════════════════════════════════════════════════

def cross_validate_safe(model_factory, X_train, y_train):
    """
    3-fold CV on a stratified sample (max CV_SAMPLE_CAP rows).
    Statistically valid and RAM-safe on 2M-row datasets.
    """
    try:
        from sklearn.model_selection import StratifiedKFold, cross_val_score

        n = len(X_train)
        if n > CV_SAMPLE_CAP:
            from sklearn.model_selection import StratifiedShuffleSplit
            sss = StratifiedShuffleSplit(n_splits=1, train_size=CV_SAMPLE_CAP,
                                        random_state=42)
            idx, _ = next(sss.split(X_train, y_train))
            X_cv, y_cv = X_train[idx], y_train[idx]
            print(f"[CV]   Subsampled {CV_SAMPLE_CAP:,}/{n:,} rows for CV")
        else:
            X_cv, y_cv = X_train, y_train
            print(f"[CV]   Using full {n:,}-row set for CV")

        skf    = StratifiedKFold(n_splits=CV_FOLDS, shuffle=True, random_state=42)
        scores = cross_val_score(model_factory(), X_cv, y_cv,
                                 cv=skf, scoring="f1_weighted", n_jobs=-1)
        mean_f1 = float(np.mean(scores))
        std_f1  = float(np.std(scores))
        print(f"[CV]   {CV_FOLDS}-fold F1: {mean_f1*100:.2f}% ± {std_f1*100:.2f}%")
        return round(mean_f1, 4), round(std_f1, 4)

    except Exception as e:
        print(f"[CV]   Skipped: {e}")
        return None, None


# ══════════════════════════════════════════════════════════════════
# Calibration
# ══════════════════════════════════════════════════════════════════

def calibrate(model, X_val, y_val):
    try:
        from sklearn.calibration import CalibratedClassifierCV
        cal = CalibratedClassifierCV(model, method="sigmoid", cv="prefit")
        cal.fit(X_val, y_val)
        print("[CALIB] Platt scaling applied ✓")
        return cal
    except Exception as e:
        print(f"[CALIB] Skipped ({e})")
        return model


# ══════════════════════════════════════════════════════════════════
# FP-aware evaluation
# ══════════════════════════════════════════════════════════════════

def evaluate_model(model, X_test, y_test, label_encoder, name):
    """
    Reports classification metrics with emphasis on:
    - False Positive Rate (FPR): fraction of benign flows wrongly flagged
    - BENIGN precision & recall
    - Per-class F1

    FPR is the #1 quality metric for a production IDS.
    Target: FPR < 1% to avoid alert fatigue on normal traffic.
    """
    from sklearn.metrics import (
        classification_report, accuracy_score,
        f1_score, precision_score, recall_score,
    )

    y_pred = model.predict(X_test)
    acc    = accuracy_score(y_test, y_pred)
    f1_w   = f1_score(y_test, y_pred, average="weighted", zero_division=0)
    prec_w = precision_score(y_test, y_pred, average="weighted", zero_division=0)
    rec_w  = recall_score(y_test, y_pred, average="weighted", zero_division=0)

    classes = label_encoder.classes_.tolist()

    print(f"\n{'='*65}")
    print(f"  [{name}] Evaluation")
    print(f"{'='*65}")
    print(f"  Accuracy   : {acc*100:.2f}%")
    print(f"  F1 (wtd)   : {f1_w*100:.2f}%")
    print(f"  Precision  : {prec_w*100:.2f}%")
    print(f"  Recall     : {rec_w*100:.2f}%")

    fpr = benign_prec = benign_rec = None
    try:
        benign_enc   = label_encoder.transform(["BENIGN"])[0]
        benign_mask  = (y_test == benign_enc)
        benign_total = int(np.sum(benign_mask))

        fp  = int(np.sum((y_pred != benign_enc) & benign_mask))
        tn  = benign_total - fp
        fpr = fp / benign_total if benign_total > 0 else 0.0

        pred_benign = (y_pred == benign_enc)
        tp_b = int(np.sum(benign_mask & pred_benign))
        fp_b = int(np.sum(~benign_mask & pred_benign))
        benign_prec = tp_b / (tp_b + fp_b) if (tp_b + fp_b) > 0 else 0.0
        benign_rec  = tp_b / benign_total   if benign_total > 0 else 0.0

        grade = ("✓ EXCELLENT (<0.5%)" if fpr < 0.005 else
                 "✓ GOOD (<1%)"        if fpr < 0.01  else
                 "⚠ ACCEPTABLE (<3%)" if fpr < 0.03  else
                 "✗ HIGH — tune thresholds")

        print(f"\n  ── BENIGN / False-Positive Report ──────────────────────")
        print(f"  BENIGN test samples : {benign_total:,}")
        print(f"  False Positives     : {fp:,}  ({fpr*100:.2f}%)  {grade}")
        print(f"  True Negatives      : {tn:,}")
        print(f"  BENIGN Precision    : {benign_prec*100:.2f}%")
        print(f"  BENIGN Recall       : {benign_rec*100:.2f}%")
        print(f"  ──────────────────────────────────────────────────────────")
        print(f"  Note: FPR measures alert fatigue on YouTube/Discord/gaming.")
        print(f"        Target < 1% for production deployment.")
    except Exception as e:
        print(f"  [WARN] FPR calculation failed: {e}")

    print(f"\n  Classification Report:")
    print(classification_report(y_test, y_pred,
                                target_names=sorted(set(classes)),
                                zero_division=0))

    # Per-class F1
    sorted_classes = sorted(set(y_test))
    f1_per = f1_score(y_test, y_pred, average=None,
                      labels=sorted_classes, zero_division=0)
    per_class_f1 = {}
    for enc_cls, f1_val in zip(sorted_classes, f1_per):
        try:
            lbl = label_encoder.inverse_transform([enc_cls])[0]
            per_class_f1[lbl] = round(float(f1_val), 4)
        except Exception:
            pass

    return {
        "accuracy":            round(float(acc),    4),
        "f1":                  round(float(f1_w),   4),
        "precision":           round(float(prec_w), 4),
        "recall":              round(float(rec_w),  4),
        "false_positive_rate": round(float(fpr), 4) if fpr is not None else None,
        "benign_precision":    round(float(benign_prec), 4) if benign_prec is not None else None,
        "benign_recall":       round(float(benign_rec),  4) if benign_rec  is not None else None,
        "per_class_f1":        per_class_f1,
    }


# ══════════════════════════════════════════════════════════════════
# Save helpers
# ══════════════════════════════════════════════════════════════════

def _pkl(obj, name):
    path = os.path.join(MODELS_DIR, name)
    with open(path, "wb") as f:
        pickle.dump(obj, f)
    size_mb = os.path.getsize(path) / 1_048_576
    print(f"[SAVE] {name}  ({size_mb:.1f} MB)")


def save_all(best_model, iso, scaler, label_encoder, feature_list, meta):
    _pkl(best_model,    "cicids_rf.pkl")
    _pkl(iso,           "isolation_forest.pkl")
    _pkl(scaler,        "cicids_scaler.pkl")
    _pkl(label_encoder, "cicids_label_encoder.pkl")

    feat_path = os.path.join(MODELS_DIR, "cicids_features.json")
    with open(feat_path, "w") as f:
        json.dump(feature_list, f, indent=2)
    print(f"[SAVE] cicids_features.json")

    meta_path = os.path.join(MODELS_DIR, "model_metadata.json")
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2, default=str)
    print(f"[SAVE] model_metadata.json")


# ══════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════

def main():
    print("=" * 65)
    print("  PacketGuard — CICIDS2017 Enterprise Training  (v3)")
    print("=" * 65)
    print(f"  SMOTE min_samples : {MIN_SAMPLES_FOR_SMOTE} "
          f"(below this → merged to OTHER)")
    print(f"  SMOTE max_ratio   : {MAX_SMOTE_RATIO}× original count")
    print(f"  CV config         : {CV_FOLDS}-fold on ≤{CV_SAMPLE_CAP//1000}k rows")
    print()

    try:
        from sklearn.preprocessing import LabelEncoder, StandardScaler
        from sklearn.model_selection import train_test_split
    except ImportError:
        print("[ERROR] scikit-learn not installed. pip install scikit-learn")
        sys.exit(1)

    # ── Load & preprocess ──────────────────────────────────────────
    df = load_cicids_data()
    X, y, label_counts = preprocess(df)

    # ── Encode labels ──────────────────────────────────────────────
    le      = LabelEncoder()
    y_enc   = le.fit_transform(y)
    classes = le.classes_.tolist()
    print(f"\n[PREP] {len(classes)} classes: {classes}")

    # ── Train / val / test split  (60 / 20 / 20) ──────────────────
    # CRITICAL: split on RAW data BEFORE fitting the scaler.
    # Fitting the scaler on the full dataset before splitting leaks
    # test-set statistics into training and inflates every metric.
    X_np = X.values  # raw numpy, unscaled
    X_train_raw, X_tmp_raw, y_train, y_tmp = train_test_split(
        X_np, y_enc, test_size=0.40, random_state=42, stratify=y_enc
    )
    X_val_raw, X_test_raw, y_val, y_test = train_test_split(
        X_tmp_raw, y_tmp, test_size=0.50, random_state=42, stratify=y_tmp
    )
    print(f"\n[SPLIT] Train: {len(X_train_raw):,}  "
          f"Val: {len(X_val_raw):,}  Test: {len(X_test_raw):,}")

    # ── Scale — fit on TRAINING data only ─────────────────────────
    scaler  = StandardScaler()
    X_train = scaler.fit_transform(X_train_raw)   # fit + transform
    X_val   = scaler.transform(X_val_raw)          # transform only
    X_test  = scaler.transform(X_test_raw)         # transform only
    # Keep X_scaled as a reference-free alias so downstream code that
    # uses it (e.g. Isolation Forest benign mask) stays correct.
    X_scaled = None  # explicitly poison — do not use below

    # ── Conservative SMOTE ─────────────────────────────────────────
    X_train_bal, y_train_bal = apply_smote(X_train, y_train, le)

    # ── Random Forest (PRIMARY classifier) ────────────────────────
    print("\n[TRAIN] Random Forest — PRIMARY attack classifier...")
    rf_cv_mean, rf_cv_std = cross_validate_safe(
        build_random_forest, X_train_bal, y_train_bal
    )
    rf = build_random_forest()
    print("[TRAIN] Starting RF training... (this takes 5-15 min, do not close)")
    rf.fit(X_train_bal, y_train_bal)
    print("[TRAIN] RF training complete.")
    rf_cal     = calibrate(rf, X_val, y_val)
    rf_metrics = evaluate_model(rf_cal, X_test, y_test, le, "Random Forest")

    # ── XGBoost ───────────────────────────────────────────────────────
    xgb_metrics = xgb_cal = xgb_cv_mean = xgb_cv_std = None
    xgb = build_xgboost(len(classes))
    if xgb is not None:
        print("\n[TRAIN] XGBoost...")
        from xgboost import XGBClassifier
        xgb_cv_mean, xgb_cv_std = cross_validate_safe(
            lambda: XGBClassifier(
                n_estimators=300, max_depth=7, learning_rate=0.1,
                subsample=0.8, colsample_bytree=0.8, min_child_weight=5,
                use_label_encoder=False, eval_metric="mlogloss",
                n_jobs=-1, random_state=42, verbosity=0,
            ),
            X_train_bal, y_train_bal,
        )
        xgb.fit(X_train_bal, y_train_bal,
                eval_set=[(X_val, y_val)], verbose=False)
        xgb_cal     = calibrate(xgb, X_val, y_val)
        xgb_metrics = evaluate_model(xgb_cal, X_test, y_test, le, "XGBoost")

    # ── Pick winner: combined F1 + FPR score ───────────────────────
    def _combined_score(m):
        if m is None:
            return -1.0
        fpr = m.get("false_positive_rate") or 0.05
        return m["f1"] - fpr * 0.5   # penalise false alarm rate

    if xgb_metrics and _combined_score(xgb_metrics) > _combined_score(rf_metrics):
        best_model, best_name = xgb_cal, "XGBoost"
        best_metrics = xgb_metrics
        best_cv_mean, best_cv_std = xgb_cv_mean, xgb_cv_std
    else:
        best_model, best_name = rf_cal, "RandomForest"
        best_metrics = rf_metrics
        best_cv_mean, best_cv_std = rf_cv_mean, rf_cv_std

    fpr_pct = (best_metrics.get("false_positive_rate") or 0) * 100
    print(f"\n[WINNER] {best_name}  "
          f"F1={best_metrics['f1']*100:.2f}%  FPR={fpr_pct:.2f}%")

    # ── Isolation Forest — ANOMALY LAYER ONLY ─────────────────────
    # Train on TRAINING-SET benign rows only (already scaled).
    # Using full pre-split data would leak test statistics.
    benign_train_mask = (le.inverse_transform(y_train) == "BENIGN")
    X_benign          = X_train[benign_train_mask]
    print(f"[ISO]  Benign training samples: {len(X_benign):,}")
    iso = train_isolation_forest(X_benign)

    # ── Metadata ───────────────────────────────────────────────────
    meta = {
        "trained":             True,
        "trained_at":          datetime.utcnow().isoformat(),
        "dataset":             "CICIDS2017",
        "version":             "v3",
        "winner_model":        best_name,
        "samples_train":       int(len(X_train_bal)),
        "samples_test":        int(len(X_test)),
        "accuracy":            best_metrics["accuracy"],
        "precision":           best_metrics["precision"],
        "recall":              best_metrics["recall"],
        "f1":                  best_metrics["f1"],
        "false_positive_rate": best_metrics.get("false_positive_rate"),
        "benign_precision":    best_metrics.get("benign_precision"),
        "benign_recall":       best_metrics.get("benign_recall"),
        "per_class_f1":        best_metrics["per_class_f1"],
        "cv_f1_mean":          best_cv_mean,
        "cv_f1_std":           best_cv_std,
        "cv_folds":            CV_FOLDS,
        "cv_sample_cap":       CV_SAMPLE_CAP,
        "classes":             classes,
        "features":            SELECTED_FEATURES,
        "label_counts":        {k: int(v) for k, v in label_counts.items()},
        "rf_f1":               rf_metrics["f1"],
        "rf_fpr":              rf_metrics.get("false_positive_rate"),
        "xgb_f1":              xgb_metrics["f1"] if xgb_metrics else None,
        "xgb_fpr":             xgb_metrics.get("false_positive_rate") if xgb_metrics else None,
        "smote_min_samples":   MIN_SAMPLES_FOR_SMOTE,
        "smote_max_ratio":     MAX_SMOTE_RATIO,
        "cicids_trained":      True,
        "architecture": [
            "Rule-Based Detection",
            f"{best_name} (PRIMARY classifier — attack detection)",
            "Isolation Forest (anomaly layer — unknown behaviour only)",
            "Correlation Engine",
            "Threat Scoring",
            "Auto Response",
        ],
    }

    # ── Save ───────────────────────────────────────────────────────
    print("\n[SAVE] Writing model files...")
    save_all(best_model, iso, scaler, le, SELECTED_FEATURES, meta)

    # ── Final summary ──────────────────────────────────────────────
    print("\n" + "=" * 65)
    print(f"  Training complete!  [{best_name}  v3]")
    print(f"  Accuracy   : {best_metrics['accuracy']*100:.2f}%")
    print(f"  F1 Score   : {best_metrics['f1']*100:.2f}%")
    print(f"  FPR        : {fpr_pct:.2f}%  ← false alarms on benign traffic")
    if best_cv_mean:
        print(f"  CV F1      : {best_cv_mean*100:.2f}% ± {best_cv_std*100:.2f}%"
              f"  ({CV_FOLDS}-fold, {CV_SAMPLE_CAP//1000}k-row sample)")
    print(f"  Classes    : {', '.join(classes)}")
    print("=" * 65)
    print("\nNext step:")
    print("  python start.py\n")


if __name__ == "__main__":
    main()