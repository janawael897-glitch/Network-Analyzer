#!/usr/bin/env python3
"""
threat_scoring.py — PacketGuard Threat Scoring Engine
======================================================
v2 — Intelligent Trust Scoring Integration

Changes:
  - Score increments are now provider-aware.  The same alert from a
    Cloudflare IP and an unknown IP contribute differently to the score.
  - ML_ANOMALY bonus is gated: for trusted providers it only contributes
    if there are corroborating non-ML indicators.
  - Scoring uses a smoothing window to prevent a single spike from
    rocketing an IP to CRITICAL.  Score is the weighted average of
    the last N observations rather than a pure accumulator.
  - Tier boundaries are unchanged so the rest of the system (auto_response,
    block_manager) continues to work without modification.

Exports: get_engine(), start_decay_thread(), BASE_DIR
"""

import json
import os
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone

BASE_DIR    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ALERTS_FILE = os.path.join(BASE_DIR, "alerts.json")

_lock   = threading.Lock()
_engine = None

# ── Smoothing window ──────────────────────────────────────────────────────────
# Score = exponential moving average over this many recent contributions.
# Prevents a single alert burst from instantly hitting CRITICAL.
SMOOTHING_ALPHA = 0.30   # lower = smoother (less reactive to spikes)


def _get_provider_score_modifier(ip: str) -> float:
    """
    Return a score multiplier based on provider type.
    Trusted providers need repeated evidence before score climbs — their
    single-alert contribution is reduced so one anomaly can't trigger CRITICAL.
    """
    try:
        from trust_scorer import get_trust_profile, ProviderType
        ptype = get_trust_profile(ip).provider_type
        modifiers = {
            ProviderType.UNKNOWN:         1.00,
            ProviderType.ISP:             1.00,
            ProviderType.CORPORATE:       0.85,
            ProviderType.DEVELOPER:       0.70,
            ProviderType.AI_SERVICE:      0.60,
            ProviderType.CLOUD:           0.55,
            ProviderType.CDN:             0.50,
            ProviderType.KNOWN_MALICIOUS: 1.50,
        }
        return modifiers.get(ptype, 1.0)
    except Exception:
        return 1.0


class ThreatScoringEngine:
    """
    Additive scorer with provider-aware modifiers and smoothing:
      - CRITICAL alert  +25 pts  (× provider modifier)
      - HIGH            +15 pts  (× provider modifier)
      - MEDIUM          +8  pts  (× provider modifier)
      - LOW             +2  pts  (× provider modifier)
      - ML_ANOMALY      +10 pts bonus ONLY when non-ML indicators also present
    Score decays 5% every 10 minutes toward 0.
    """

    SEV_POINTS = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 2}
    TIERS = [
        (76, "CRITICAL"),
        (51, "HIGH"),
        (26, "MEDIUM"),
        (0,  "LOW"),
    ]

    def __init__(self):
        self._hosts: dict = defaultdict(lambda: {
            "score":           0.0,
            "smoothed_score":  0.0,
            "alerts":          0,
            "ml_count":        0,
            "non_ml_count":    0,   # track non-ML alerts separately
            "ports":           set(),
            "first_seen":      None,
            "last_seen":       None,
            "recent_pts":      deque(maxlen=10),  # last 10 point additions
        })

    def ingest_alert(self, alert: dict):
        ip    = alert.get("source_ip", "")
        if not ip or ip in ("N/A", "Multiple", ""):
            return

        sev   = alert.get("severity", "LOW")
        atype = alert.get("alert_type", "")
        port  = alert.get("destination_port")
        now   = datetime.now(tz=timezone.utc).isoformat()
        is_ml = "ML" in atype

        # Provider-aware point modifier
        modifier = _get_provider_score_modifier(ip)
        pts      = self.SEV_POINTS.get(sev, 2) * modifier

        with _lock:
            h = self._hosts[ip]
            h["alerts"] += 1

            if is_ml:
                h["ml_count"] += 1
                # ML bonus only fires if there are already non-ML indicators
                # This prevents ML-only score inflation for trusted providers
                if h["non_ml_count"] > 0:
                    pts += 10 * modifier
                else:
                    # First ML alert with no other indicators — reduced contribution
                    pts = pts * 0.5
            else:
                h["non_ml_count"] += 1

            # Apply smoothing: EMA over recent contributions
            h["recent_pts"].append(pts)
            avg_recent = sum(h["recent_pts"]) / len(h["recent_pts"])
            # Smoothed score is EMA — prevents single-spike CRITICAL
            h["smoothed_score"] = (
                SMOOTHING_ALPHA * avg_recent +
                (1 - SMOOTHING_ALPHA) * h["smoothed_score"]
            )
            # Raw score still accumulates (used for leaderboard)
            h["score"] = min(100.0, h["score"] + pts)

            if port:
                h["ports"].add(port)
            if not h["first_seen"]:
                h["first_seen"] = now
            h["last_seen"] = now

    def _effective_score(self, h: dict) -> float:
        """
        The effective score used for tier classification and block decisions.
        For unknown IPs: raw score.
        For well-established activity: blend of raw + smoothed.
        The smoothed score prevents a single burst from triggering CRITICAL.
        """
        if h["alerts"] < 3:
            # Very few alerts — use smoothed (conservative)
            return h["smoothed_score"]
        # Blend: 60% raw, 40% smoothed for established activity
        return 0.6 * h["score"] + 0.4 * h["smoothed_score"]

    def decay(self):
        """Decay all scores by 5%."""
        with _lock:
            for h in self._hosts.values():
                h["score"]          = max(0.0, h["score"] * 0.95)
                h["smoothed_score"] = max(0.0, h["smoothed_score"] * 0.95)

    def _tier(self, score: float) -> dict:
        for threshold, label in self.TIERS:
            if score >= threshold:
                return {"label": label, "threshold": threshold}
        return {"label": "LOW", "threshold": 0}

    def get_leaderboard(self, top_n: int = 20) -> list:
        with _lock:
            items = []
            for ip, h in self._hosts.items():
                eff = self._effective_score(h)
                if eff <= 0:
                    continue
                items.append({
                    "ip":               ip,
                    "risk_score":       round(eff, 2),
                    "raw_score":        round(h["score"], 2),
                    "tier":             self._tier(eff),
                    "classification":   self._tier(eff)["label"],
                    "total_alerts":     h["alerts"],
                    "ml_anomaly_count": h["ml_count"],
                    "non_ml_alerts":    h["non_ml_count"],
                    "unique_ports":     len(h["ports"]),
                    "first_seen":       h["first_seen"] or "",
                    "last_seen":        h["last_seen"] or "",
                })
        items.sort(key=lambda x: x["risk_score"], reverse=True)
        return items[:top_n]

    def get_host(self, ip: str) -> dict:
        with _lock:
            h = self._hosts.get(ip)
            if not h:
                return {}
            eff = self._effective_score(h)
            return {
                "ip":               ip,
                "risk_score":       round(eff, 2),
                "raw_score":        round(h["score"], 2),
                "tier":             self._tier(eff),
                "classification":   self._tier(eff)["label"],
                "total_alerts":     h["alerts"],
                "ml_anomaly_count": h["ml_count"],
                "non_ml_alerts":    h["non_ml_count"],
                "unique_ports":     len(h["ports"]),
                "first_seen":       h["first_seen"] or "",
                "last_seen":        h["last_seen"] or "",
            }

    def status(self) -> dict:
        with _lock:
            return {"tracked_ips": len(self._hosts)}


def get_engine() -> ThreatScoringEngine:
    global _engine
    if _engine is None:
        _engine = ThreatScoringEngine()
        try:
            with open(ALERTS_FILE, "r", encoding="utf-8") as f:
                alerts = json.load(f)
            for a in alerts[-500:]:
                _engine.ingest_alert(a)
        except Exception:
            pass
    return _engine


def _decay_loop():
    while True:
        time.sleep(600)
        try:
            get_engine().decay()
        except Exception as e:
            print(f"[SCORING] Decay error: {e}")


def start_decay_thread():
    t = threading.Thread(target=_decay_loop, daemon=True, name="threat-decay")
    t.start()
    print("[SCORING] Threat scoring decay thread started.")
    return t