#!/usr/bin/env python3
"""
baseline_learning.py — PacketGuard Baseline Traffic Learning
Learns normal traffic patterns and flags deviations.
Exports: start_baseline_thread(), get_baseline_snapshot(), get_history_for_chart()
"""

import json
import os
import threading
import time
from collections import deque
from datetime import datetime, timezone

BASE_DIR        = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LIVE_STATE_FILE = os.path.join(BASE_DIR, "live_state.json")

_lock    = threading.Lock()
_history: deque = deque(maxlen=120)   # last 120 samples (~2 hours at 60s interval)

_snapshot = {
    "baseline_pps":      0.0,
    "baseline_bps":      0.0,
    "current_pps":       0.0,
    "current_bps":       0.0,
    "pps_deviation":     0.0,
    "bps_deviation":     0.0,
    "deviation_threshold": 0.5,
    "anomaly_flag":      False,
    "samples_collected": 0,
    "last_updated":      None,
}

DEVIATION_THRESHOLD = 0.5   # 50% above baseline = anomaly
MIN_SAMPLES         = 10    # need at least this many before flagging anomalies


def _read_live_state() -> dict:
    try:
        with open(LIVE_STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _sample():
    state = _read_live_state()
    pps   = float(state.get("rate", 0) or 0)
    # Estimate bytes/sec: assume average 500 bytes/packet
    bps   = pps * 500

    now = datetime.now(tz=timezone.utc).isoformat()

    with _lock:
        _history.append({"t": now, "v": pps, "bps": bps})
        n = len(_history)

        if n < 2:
            return

        # Rolling average (baseline) over all collected samples
        avg_pps = sum(h["v"]   for h in _history) / n
        avg_bps = sum(h["bps"] for h in _history) / n

        # Deviation ratio
        pps_dev = ((pps - avg_pps) / max(avg_pps, 0.1))
        bps_dev = ((bps - avg_bps) / max(avg_bps, 0.1))

        anomaly = (
            n >= MIN_SAMPLES
            and (abs(pps_dev) > DEVIATION_THRESHOLD or abs(bps_dev) > DEVIATION_THRESHOLD)
        )

        _snapshot.update({
            "baseline_pps":      round(avg_pps, 2),
            "baseline_bps":      round(avg_bps, 2),
            "current_pps":       round(pps, 2),
            "current_bps":       round(bps, 2),
            "pps_deviation":     round(pps_dev, 3),
            "bps_deviation":     round(bps_dev, 3),
            "deviation_threshold": DEVIATION_THRESHOLD,
            "anomaly_flag":      anomaly,
            "samples_collected": n,
            "last_updated":      now,
        })

        if anomaly:
            print(f"[BASELINE] Anomaly detected — pps={pps:.1f} (baseline={avg_pps:.1f}, "
                  f"dev={pps_dev:+.1%})")


def get_baseline_snapshot() -> dict:
    with _lock:
        return dict(_snapshot)


def get_history_for_chart(metric: str = "pps", points: int = 60) -> list:
    """Return the last `points` history entries as [{t, v}]."""
    with _lock:
        hist = list(_history)

    key = "bps" if metric == "bps" else "v"
    return [{"t": h["t"], "v": h.get(key, 0)} for h in hist[-points:]]


def _baseline_loop():
    while True:
        time.sleep(60)
        try:
            _sample()
        except Exception as e:
            print(f"[BASELINE] Sample error: {e}")


def start_baseline_thread():
    t = threading.Thread(target=_baseline_loop, daemon=True, name="baseline-learning")
    t.start()
    print("[BASELINE] Baseline learning thread started.")
    return t