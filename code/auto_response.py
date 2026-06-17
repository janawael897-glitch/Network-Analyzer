#!/usr/bin/env python3
"""
<<<<<<< HEAD
auto_response.py — PacketGuard Auto-Response Engine
====================================================
v2 — Intelligent Trust Scoring Integration
=======
auto_response.py - PacketGuard Auto-Response Engine
====================================================
v2 - Intelligent Trust Scoring Integration
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)

Changes:
  - Response rules now respect the trust scoring escalation stages.
    Instead of jumping directly from ALERT→BLOCK, the engine steps
    through: MONITOR → INCREASE_MONITOR → TEMPORARY_BLOCK → PERMANENT_BLOCK.
  - For trusted providers (Cloud, CDN, AI, Developer), the auto-sweep
<<<<<<< HEAD
    will never issue a direct BLOCK via this engine — it defers to the
=======
    will never issue a direct BLOCK via this engine - it defers to the
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
    block_manager which applies trust scoring gates.
  - Cooldown windows are provider-aware: longer cooldowns for trusted
    providers to prevent repeated false-positive escalations.

Exports: get_engine(), start_response_thread()
"""

import os
import threading
import time
from collections import deque
from datetime import datetime, timezone

<<<<<<< HEAD
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
=======
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)

_lock   = threading.Lock()
_engine = None


def _get_provider_cooldown(ip: str, base_cooldown: int) -> int:
    """Return a provider-adjusted cooldown in seconds."""
    try:
        from trust_scorer import get_trust_profile, ProviderType
        ptype = get_trust_profile(ip).provider_type
        multipliers = {
            ProviderType.UNKNOWN:         1.0,
            ProviderType.ISP:             1.0,
            ProviderType.CORPORATE:       1.5,
            ProviderType.DEVELOPER:       2.0,
            ProviderType.AI_SERVICE:      3.0,
            ProviderType.CLOUD:           3.0,
            ProviderType.CDN:             4.0,
            ProviderType.KNOWN_MALICIOUS: 0.5,
        }
        mult = multipliers.get(ptype, 1.0)
        return int(base_cooldown * mult)
    except Exception:
        return base_cooldown


class ResponseEngine:
    """
    Response engine with provider-aware escalation.
    Evaluates an IP's risk score and determines the appropriate stage.
    Actions are kept in memory (ring buffer) and written to DB by enterprise_bp.
    """

    # (min_score, action_type, label, description)
    RULES = [
<<<<<<< HEAD
        (76, "BLOCK",    "Block IP",           "Automatic firewall block — CRITICAL threat level."),
        (51, "THROTTLE", "Rate-limit traffic",  "Throttle inbound traffic — HIGH threat level."),
        (26, "ALERT",    "Escalate alert",      "Escalate to SOC analyst — MEDIUM threat level."),
        (0,  "LOG",      "Log activity",        "Continue monitoring — LOW threat level."),
    ]

    BASE_COOLDOWN = 300   # 5 minutes — extended per provider type
=======
        (76, "BLOCK",    "Block IP",           "Automatic firewall block - CRITICAL threat level."),
        (51, "THROTTLE", "Rate-limit traffic",  "Throttle inbound traffic - HIGH threat level."),
        (26, "ALERT",    "Escalate alert",      "Escalate to SOC analyst - MEDIUM threat level."),
        (0,  "LOG",      "Log activity",        "Continue monitoring - LOW threat level."),
    ]

    BASE_COOLDOWN = 300   # 5 minutes - extended per provider type
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)

    def __init__(self, email_fn=None):
        self._log: deque     = deque(maxlen=500)
        self._email_fn       = email_fn
        self._cooldowns: dict = {}   # ip -> expiry timestamp

    def evaluate(self, ip: str, risk_score: float) -> list:
        """
        Given an IP and its risk score, decide which stage to move to.
        Returns list of action dicts that were triggered.
        """
        now         = time.time()
        cooldown    = _get_provider_cooldown(ip, self.BASE_COOLDOWN)
        if self._cooldowns.get(ip, 0) > now:
            return []

        triggered = []
        for min_score, atype, label, desc in self.RULES:
            if risk_score < min_score:
                continue

            sev = (
                "CRITICAL" if risk_score >= 76 else
                "HIGH"     if risk_score >= 51 else
                "MEDIUM"   if risk_score >= 26 else
                "LOW"
            )

            action = {
                "source_ip":    ip,
                "action_type":  atype,
                "action_label": label,
                "action_time":  datetime.now(tz=timezone.utc).isoformat(),
                "description":  desc,
                "risk_score":   risk_score,
                "executed":     atype in ("ALERT", "LOG"),
                "severity":     sev,
                "result":       f"Recommended: {label}",
            }

            with _lock:
                self._log.appendleft(action)
            triggered.append(action)

<<<<<<< HEAD
            # ── For BLOCK actions: route through block_manager (trust-scored) ──
=======
            # -- For BLOCK actions: route through block_manager (trust-scored) --
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
            if atype == "BLOCK":
                try:
                    from block_manager import evaluate_risk_score as _bm_risk
                    block_result = _bm_risk(ip, risk_score)
                    if block_result:
                        action["executed"]     = True
                        action["result"]       = f"Blocked: {block_result.get('fw_message', 'logged')}"
                        action["block_status"] = block_result.get("status", "unknown")
                    else:
<<<<<<< HEAD
                        # block_manager returned None — trust scoring decided not to block
=======
                        # block_manager returned None - trust scoring decided not to block
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
                        # Update action to reflect the monitoring decision
                        action["result"]       = "Trust system: monitoring escalated (insufficient evidence for block)"
                        action["block_status"] = "deferred_by_trust_scorer"
                        action["action_type"]  = "INCREASE_MONITOR"
                        action["action_label"] = "Stage: Increase Monitor"
                except Exception as _be:
<<<<<<< HEAD
                    pass   # block_manager not yet available — log-only
=======
                    pass   # block_manager not yet available - log-only
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)

            if self._email_fn and atype in ("BLOCK", "THROTTLE"):
                try:
                    self._email_fn(action)
                except Exception:
                    pass

            break   # only top matching rule per evaluation

        # Apply provider-adjusted cooldown
        self._cooldowns[ip] = now + cooldown
        return triggered

    def get_recent_log(self, limit: int = 25) -> list:
        with _lock:
            return list(self._log)[:limit]

    def status(self) -> dict:
        with _lock:
            return {"logged_actions": len(self._log)}


def get_engine(email_fn=None) -> ResponseEngine:
    global _engine
    if _engine is None:
        _engine = ResponseEngine(email_fn=email_fn)
    return _engine


def _response_loop():
    """Periodic sweep: re-evaluate top IPs from threat scorer."""
    while True:
        time.sleep(120)
        try:
            from threat_scoring import get_engine as get_scoring
            eng     = get_engine()
            scoring = get_scoring()
            for host in scoring.get_leaderboard(top_n=10):
                ip    = host.get("ip", "")
                score = host.get("risk_score", 0)
                if score >= 26:
                    eng.evaluate(ip, score)
        except Exception as e:
            print(f"[RESPONSE] Loop error: {e}")


def start_response_thread(email_fn=None):
    get_engine(email_fn=email_fn)
    t = threading.Thread(target=_response_loop, daemon=True, name="auto-response")
    t.start()
    print("[RESPONSE] Auto-response thread started.")
    return t