#!/usr/bin/env python3
"""
<<<<<<< HEAD
correlation_engine.py — PacketGuard Correlation Engine (v1 compatibility shim)
=======
correlation_engine.py - PacketGuard Correlation Engine (v1 compatibility shim)
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
Provides the API surface that enterprise_bp.py imports:
  - get_open_incidents(limit)
  - get_incident_summary()
  - close_incident(incident_id, operator)
  - sweep_incidents()
  - start_correlation_thread()

All persistent data is read from / written to incidents.json so it shares
state with correlation_engine_v2.py seamlessly.
"""

import json
import os
import threading
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone

BASE_DIR       = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INCIDENTS_FILE = os.path.join(BASE_DIR, "incidents.json")
ALERTS_FILE    = os.path.join(BASE_DIR, "alerts.json")

_lock = threading.Lock()

# In-memory open-incident registry  { incident_id -> incident_dict }
_open: dict = {}

MAX_STORED = 500


<<<<<<< HEAD
# ── Persistence helpers ───────────────────────────────────────────
=======
# -- Persistence helpers -------------------------------------------
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)

def _load() -> list:
    try:
        with open(INCIDENTS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def _save(incidents: list):
    try:
        trimmed = incidents[-MAX_STORED:]
        with open(INCIDENTS_FILE, "w", encoding="utf-8") as f:
            json.dump(trimmed, f, indent=2, default=str)
    except Exception as e:
        print(f"[CORR-V1] Save error: {e}")


<<<<<<< HEAD
# ── Field normaliser (v2 → v1 shape expected by enterprise_bp) ───
=======
# -- Field normaliser (v2 → v1 shape expected by enterprise_bp) ---
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)

def _to_v1(inc: dict) -> dict:
    """
    Map correlation_engine_v2 incident fields to the field names
    that enterprise_bp._norm_incident() reads.
    """
    chain = (
        inc.get("attack_chain")
        or inc.get("category")
        or inc.get("alert_type")
        or "Unknown"
    )
    return {
        "incident_id":      inc.get("id") or inc.get("incident_id", ""),
        "source_ip":        inc.get("src_ip") or inc.get("source_ip", ""),
        "severity":         inc.get("severity", "LOW"),
        "attack_chain":     chain,
        "last_seen":        inc.get("timestamp") or inc.get("last_seen", ""),
        "first_seen":       inc.get("timestamp") or inc.get("first_seen", ""),
        "title":            inc.get("category", ""),
        "description":      inc.get("description", ""),
        "risk_score":       inc.get("risk_score", 0),
        "confidence":       inc.get("confidence", 0),
        "event_count":      inc.get("event_count", 1),
        "escalation_level": 0,
        "status":           inc.get("status", "open"),
        "alert_type":       inc.get("category", "UNKNOWN"),
    }


<<<<<<< HEAD
# ── Public API ────────────────────────────────────────────────────
=======
# -- Public API ----------------------------------------------------
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)

def get_open_incidents(limit: int = 50) -> list:
    """Return the most recent open incidents, newest first."""
    all_inc = _load()
    open_inc = [i for i in all_inc if i.get("status", "open") == "open"]
    open_inc.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return [_to_v1(i) for i in open_inc[:limit]]


def get_incident_summary() -> dict:
    """Return summary counts used by /api/v1/enterprise/summary."""
    all_inc  = _load()
    open_inc = [i for i in all_inc if i.get("status", "open") == "open"]

    by_sev = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for i in open_inc:
        sev = i.get("severity", "LOW")
        by_sev[sev] = by_sev.get(sev, 0) + 1

    return {
        "open_incidents": len(open_inc),
        "total":          len(all_inc),
        "by_severity":    by_sev,
    }


def close_incident(incident_id: str, operator: str = "dashboard") -> bool:
    """Mark an incident as closed. Returns True if found and updated."""
    with _lock:
        all_inc = _load()
        found   = False
        for inc in all_inc:
            iid = inc.get("id") or inc.get("incident_id", "")
            if iid == incident_id and inc.get("status", "open") == "open":
                inc["status"]      = "closed"
                inc["closed_at"]   = datetime.now(tz=timezone.utc).isoformat()
                inc["closed_by"]   = operator
                found = True
        if found:
            _save(all_inc)
    return found


def sweep_incidents() -> int:
    """
    Close duplicate open incidents (same src_ip + category), keeping the
    highest-risk one. Returns the number of incidents closed.
    """
    with _lock:
        all_inc  = _load()
        open_inc = [i for i in all_inc if i.get("status", "open") == "open"]

        # Group by (src_ip, category)
        groups: dict = defaultdict(list)
        for inc in open_inc:
            key = (
                inc.get("src_ip") or inc.get("source_ip", ""),
                inc.get("category") or inc.get("alert_type", ""),
            )
            groups[key].append(inc)

        closed = 0
        now = datetime.now(tz=timezone.utc).isoformat()
        for key, group in groups.items():
            if len(group) <= 1:
                continue
            # Keep highest risk score
            group.sort(key=lambda x: x.get("risk_score", 0), reverse=True)
            for dup in group[1:]:
                dup["status"]     = "closed"
                dup["closed_at"]  = now
                dup["closed_by"]  = "sweep"
                closed += 1

        if closed:
            _save(all_inc)

    return closed


<<<<<<< HEAD
# ── Background thread (lightweight — v2 does the real work) ──────
=======
# -- Background thread (lightweight - v2 does the real work) ------
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)

def _loop():
    """Periodic sweep of duplicates every 5 minutes."""
    while True:
        time.sleep(300)
        try:
            n = sweep_incidents()
            if n:
                print(f"[CORR-V1] Swept {n} duplicate incident(s).")
        except Exception as e:
            print(f"[CORR-V1] Sweep error: {e}")


def start_correlation_thread():
    """Start the background sweep thread (called by web_dashboard.py)."""
    t = threading.Thread(target=_loop, daemon=True, name="correlation-v1")
    t.start()
    print("[CORR-V1] Correlation shim thread started.")
    return t
