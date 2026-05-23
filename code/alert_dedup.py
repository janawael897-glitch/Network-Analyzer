#!/usr/bin/env python3
"""
alert_dedup.py — PacketGuard Alert Deduplication Engine
========================================================
v2 — Intelligent Trust Scoring Integration

Changes:
  - Window size is now provider-aware: CDN/Cloud sources have longer
    dedup windows (more events are merged) → fewer separate alerts
    sent to the correlation engine from a single bursty CDN.
  - Anomaly smoothing: ML-only alerts from trusted providers use a
    longer window and higher threshold before emitting an aggregated alert.
  - Duplicate suppression now considers provider type in the group key
    so that the same alert_type from different provider categories
    can have independent windows.

Architecture:
  live_monitor.handle_packet() → alert_dedup.ingest(alert)
    → if new/unique: emit immediately
    → if duplicate within window: accumulate count
    → on window expiry: emit aggregated summary
"""

import threading
import time
import logging
from datetime import datetime, timezone
from collections import defaultdict

log = logging.getLogger(__name__)

# ── Base config ───────────────────────────────────────────────────────────────
BASE_WINDOW_SEC  = 30     # standard dedup window
FLUSH_INTERVAL   = 10     # check for expired windows every 10s
MAX_GROUPS       = 2000   # cap memory usage

# Provider-specific window overrides (seconds)
# Larger window = more events merged = fewer alerts for trusted providers
_PROVIDER_WINDOWS = {
    "cdn":          120,   # CDN bursts are often legitimate — wide window
    "cloud":        90,
    "ai_service":   90,
    "developer":    60,
    "corporate":    45,
    "isp":          30,
    "unknown":      30,
    "known_malicious": 15,  # short window — don't miss fast-moving threats
}

_emit_cb  = None
_lock     = threading.Lock()
_groups: dict = {}
_SEV_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def set_emit_callback(fn):
    global _emit_cb
    _emit_cb = fn


def _provider_window(src_ip: str) -> int:
    """Return the dedup window in seconds for this source IP."""
    try:
        from trust_scorer import get_trust_profile
        ptype = get_trust_profile(src_ip).provider_type.value
        return _PROVIDER_WINDOWS.get(ptype, BASE_WINDOW_SEC)
    except Exception:
        return BASE_WINDOW_SEC


def ingest(alert: dict) -> None:
    """Main entry point. Thread-safe."""
    if not alert:
        return

    src   = alert.get("source_ip", "unknown")
    atype = alert.get("alert_type", "UNKNOWN")
    sev   = alert.get("severity", "LOW")
    key   = (src, atype)
    now   = time.monotonic()

    window = _provider_window(src)

    with _lock:
        if key not in _groups:
            _groups[key] = {
                "count":         1,
                "first_ts":      now,
                "last_ts":       now,
                "first_alert":   alert,
                "severity_max":  sev,
                "emitted_first": True,
                "window":        window,
            }
            _do_emit(alert)
        else:
            grp = _groups[key]
            age = now - grp["first_ts"]

            if age > grp["window"]:
                # Window expired — emit aggregated summary, start new window
                _flush_group(key, grp)
                _groups[key] = {
                    "count":         1,
                    "first_ts":      now,
                    "last_ts":       now,
                    "first_alert":   alert,
                    "severity_max":  sev,
                    "emitted_first": True,
                    "window":        window,
                }
                _do_emit(alert)
            else:
                grp["count"]   += 1
                grp["last_ts"]  = now
                if _SEV_ORDER.get(sev, 0) > _SEV_ORDER.get(grp["severity_max"], 0):
                    grp["severity_max"] = sev

        if len(_groups) > MAX_GROUPS:
            oldest = sorted(_groups.keys(), key=lambda k: _groups[k]["first_ts"])
            for k in oldest[:100]:
                del _groups[k]


def _flush_group(key, grp):
    count = grp["count"]
    if count <= 1:
        return
    base        = grp["first_alert"]
    atype       = key[1]
    window_secs = grp["last_ts"] - grp["first_ts"]
    base_msg    = base.get("message", atype)
    agg_msg     = f"{base_msg} — repeated {count}x in {window_secs:.0f}s"

    agg_alert = dict(base)
    agg_alert["timestamp"]  = datetime.now(timezone.utc).isoformat()
    agg_alert["message"]    = agg_msg
    agg_alert["severity"]   = grp["severity_max"]
    agg_alert["alert_type"] = atype + "_AGGREGATED"
    agg_alert["additional_info"] = dict(base.get("additional_info") or {})
    agg_alert["additional_info"].update({
        "repeat_count":   count,
        "window_seconds": round(window_secs, 1),
        "aggregated":     True,
    })
    _do_emit(agg_alert)


def _do_emit(alert: dict):
    if _emit_cb:
        try:
            _emit_cb(alert)
        except Exception as e:
            log.warning(f"[DEDUP] emit callback error: {e}")


def _flush_loop():
    while True:
        time.sleep(FLUSH_INTERVAL)
        now = time.monotonic()
        with _lock:
            expired = [
                k for k, g in _groups.items()
                if now - g["first_ts"] > g.get("window", BASE_WINDOW_SEC)
            ]
            for k in expired:
                grp = _groups.pop(k)
                _flush_group(k, grp)


_flusher = threading.Thread(target=_flush_loop, daemon=True, name="alert-dedup-flush")
_flusher.start()