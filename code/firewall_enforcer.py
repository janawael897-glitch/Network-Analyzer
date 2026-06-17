#!/usr/bin/env python3
"""
<<<<<<< HEAD
firewall_enforcer.py — PacketGuard Windows Firewall Integration
===============================================================
v2 — Intelligent Trust Scoring Integration
=======
firewall_enforcer.py - PacketGuard Windows Firewall Integration
===============================================================
v2 - Intelligent Trust Scoring Integration
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)

Block thresholds are now provider-aware.  The raw confidence/severity
check is a first gate; the trust scorer applies provider-specific
multipliers on top before any firewall rule is written.

SAFETY RULES (never violated):
  - NEVER block private/RFC1918 IPs
  - NEVER block localhost (127.x.x.x)
  - NEVER block the default gateway
  - Only block PUBLIC IPs that exceed risk thresholds
  - ML score alone NEVER triggers blocking
  - Single anomaly / single traffic spike NEVER triggers blocking
  - Cloud/CDN providers require higher evidence bar

<<<<<<< HEAD
Block tiers (base — trust scorer may raise these):
=======
Block tiers (base - trust scorer may raise these):
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
  CRITICAL (score ≥ 90): permanent block
  HIGH     (score ≥ 75): 1-hour temporary block
  MEDIUM   (score ≥ 60): 30-minute temporary block  [only if multi-factor met]
"""

import ipaddress
import json
import logging
import os
import platform
import subprocess
import threading
import time
from datetime import datetime, timezone

log = logging.getLogger(__name__)

BASE_DIR         = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BLOCKED_FILE     = os.path.join(BASE_DIR, "blocked_ips.json")
WHITELIST_FILE   = os.path.join(BASE_DIR, "ip_whitelist.json")

_lock       = threading.Lock()
_emit_cb    = None
_IS_WINDOWS = platform.system() == "Windows"

BLOCK_THRESHOLDS = {
<<<<<<< HEAD
    "CRITICAL": {"min_score": 90, "duration": None,  "reason": "Critical threat — permanent block"},
    "HIGH":     {"min_score": 75, "duration": 3600,  "reason": "High-risk activity — 1h block"},
    "MEDIUM":   {"min_score": 60, "duration": 1800,  "reason": "Suspicious activity — 30min block"},
=======
    "CRITICAL": {"min_score": 90, "duration": None,  "reason": "Critical threat - permanent block"},
    "HIGH":     {"min_score": 75, "duration": 3600,  "reason": "High-risk activity - 1h block"},
    "MEDIUM":   {"min_score": 60, "duration": 1800,  "reason": "Suspicious activity - 30min block"},
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
}

_PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
]


def set_emit_callback(fn):
    global _emit_cb
    _emit_cb = fn


def is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _PRIVATE_RANGES)
    except ValueError:
        return True


def _load_whitelist() -> set:
    try:
        with open(WHITELIST_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return set(data.get("ips", []))
    except Exception:
        return set()


def _load_blocked() -> list:
    try:
        with open(BLOCKED_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def _save_blocked(entries: list):
    try:
        with open(BLOCKED_FILE, "w", encoding="utf-8") as f:
            json.dump(entries[-500:], f, indent=2, default=str)
    except Exception as e:
        log.warning(f"[FW] Save error: {e}")


def _is_already_blocked(ip: str, entries: list) -> bool:
    for e in entries:
        if e.get("ip") == ip and e.get("status") == "active":
            return True
    return False


<<<<<<< HEAD
# ─────────────────────────────────────────────────────────────────────────────
# Windows Firewall commands
# ─────────────────────────────────────────────────────────────────────────────

def _add_firewall_rule(ip: str, rule_name: str) -> tuple[bool, str]:
    if not _IS_WINDOWS:
        return False, "Not Windows — firewall enforcement skipped"
=======
# -----------------------------------------------------------------------------
# Windows Firewall commands
# -----------------------------------------------------------------------------

def _add_firewall_rule(ip: str, rule_name: str) -> tuple[bool, str]:
    if not _IS_WINDOWS:
        return False, "Not Windows - firewall enforcement skipped"
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
    cmd = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_name}", "dir=in", "action=block",
        f"remoteip={ip}", "enable=yes", "profile=any",
    ]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW if _IS_WINDOWS else 0,
        )
        if result.returncode == 0:
            return True, "Firewall rule added successfully"
        return False, f"netsh error: {result.stderr.strip() or result.stdout.strip()}"
    except subprocess.TimeoutExpired:
        return False, "netsh command timed out"
    except Exception as e:
        return False, f"Subprocess error: {e}"


def _remove_firewall_rule(rule_name: str) -> tuple[bool, str]:
    if not _IS_WINDOWS:
        return False, "Not Windows"
    cmd = [
        "netsh", "advfirewall", "firewall", "delete", "rule",
        f"name={rule_name}",
    ]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW if _IS_WINDOWS else 0,
        )
        return result.returncode == 0, result.stdout.strip()
    except Exception as e:
        return False, str(e)


<<<<<<< HEAD
# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────
=======
# -----------------------------------------------------------------------------
# Public API
# -----------------------------------------------------------------------------
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)

def block_ip(ip: str, reason: str, severity: str,
             confidence: float = 0.0, duration: int | None = None,
             operator: str = "auto") -> dict:
    """
    Attempt to block ip via Windows Firewall.
    Returns a block_record dict regardless of success.
    """
    now_iso   = datetime.now(timezone.utc).isoformat()
    rule_name = f"PacketGuard_BLOCK_{ip}"

    if is_private(ip):
<<<<<<< HEAD
        return {"success": False, "ip": ip,
                "reason": "Private IP — blocked refused",
                "status": "rejected", "timestamp": now_iso}
=======
        # Manual admin blocks may target LAN IPs intentionally — allow them.
        # Auto-blocks on LAN IPs are only effective when ARP spoofing is active
        # (PacketGuard is the MITM and the firewall rule actually intercepts traffic).
        if operator != "manual":
            try:
                from arp_spoof import get_status as _arp_status
                if not _arp_status().get("running"):
                    return {"success": False, "ip": ip,
                            "reason": "Private IP - ARP spoof not active",
                            "status": "rejected", "timestamp": now_iso}
            except Exception:
                return {"success": False, "ip": ip,
                        "reason": "Private IP - blocked refused",
                        "status": "rejected", "timestamp": now_iso}
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)

    whitelist = _load_whitelist()
    if ip in whitelist:
        return {"success": False, "ip": ip,
                "reason": "IP is whitelisted",
                "status": "rejected", "timestamp": now_iso}

    with _lock:
        entries = _load_blocked()
        if _is_already_blocked(ip, entries):
            return {"success": False, "ip": ip,
                    "reason": "Already blocked",
                    "status": "duplicate", "timestamp": now_iso}

        success, fw_msg = _add_firewall_rule(ip, rule_name)

        expires_at = None
        if duration:
            import datetime as _dt
            exp = _dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(seconds=duration)
            expires_at = exp.isoformat()

<<<<<<< HEAD
        record = {
            "ip":         ip,
            "rule_name":  rule_name,
            "reason":     reason,
            "severity":   severity,
            "confidence": round(confidence, 2),
            "blocked_at": now_iso,
            "expires_at": expires_at,
            "duration":   duration,
            "operator":   operator,
            "status":     "active" if success else "failed",
            "real_block": success,
            "fw_message": fw_msg,
=======
        # Geo-enrich the record (best-effort, non-blocking)
        geo = {}
        try:
            from geo_resolver import resolve_geo as _rg
            g   = _rg(ip)
            geo = {"country": g.get("country", ""), "countryCode": g.get("countryCode", ""),
                   "city":    g.get("city", ""),    "isp": g.get("isp", "")}
        except Exception:
            pass

        record = {
            "ip":          ip,
            "rule_name":   rule_name,
            "reason":      reason,
            "severity":    severity,
            "confidence":  round(confidence, 2),
            "blocked_at":  now_iso,
            "expires_at":  expires_at,
            "duration":    duration,
            "operator":    operator,
            "status":      "active" if success else "failed",
            "real_block":  success,
            "fw_message":  fw_msg,
            **geo,
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
        }
        entries.append(record)
        _save_blocked(entries)

    if _emit_cb:
        try:
            _emit_cb("ip_blocked", {
                "ip": ip, "severity": severity,
                "reason": reason, "real": success,
            })
        except Exception:
            pass

    verb = "BLOCKED" if success else "BLOCK ATTEMPTED (failed)"
    log.warning(f"[FW] {verb}: {ip} | {reason} | {fw_msg}")
    return {**record, "success": success}


def unblock_ip(ip: str, operator: str = "admin", reason: str = "") -> dict:
    rule_name = f"PacketGuard_BLOCK_{ip}"
    _fw_ok, msg = _remove_firewall_rule(rule_name)

    with _lock:
        entries = _load_blocked()
        for e in entries:
            if e.get("ip") == ip and e.get("status") == "active":
                e["status"]       = "unblocked"
                e["unblocked_at"] = datetime.now(timezone.utc).isoformat()
                e["unblocked_by"] = operator
                if reason:
                    e["unblock_reason"] = reason
        _save_blocked(entries)

    if _emit_cb:
        try:
            _emit_cb("ip_unblocked", {"ip": ip, "operator": operator})
        except Exception:
            pass

<<<<<<< HEAD
    # When an operator unblocks, that suggests the block was a false positive —
=======
    # When an operator unblocks, that suggests the block was a false positive -
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
    # update trust profile accordingly (raise threshold for this IP)
    try:
        from trust_scorer import invalidate_profile
        invalidate_profile(ip)
        log.info(f"[FW] Trust profile invalidated for {ip} after manual unblock.")
    except Exception:
        pass

    log.info(f"[FW] UNBLOCKED: {ip} by {operator} | {msg}")
    return {"success": True, "ip": ip, "message": msg or "Unblocked successfully"}


def get_blocked_list() -> list:
    return _load_blocked()


def get_firewall_status() -> dict:
    entries     = _load_blocked()
    active      = [e for e in entries if e.get("status") == "active"]
    real_blocks = [e for e in active if e.get("real_block")]
    return {
        "enabled":       _IS_WINDOWS,
        "platform":      platform.system(),
        "active_blocks": len(active),
        "real_blocks":   len(real_blocks),
        "total_blocked": len(entries),
        "enforcement":   "Windows Defender Firewall" if _IS_WINDOWS else "Monitoring Only",
        "status":        "ACTIVE" if _IS_WINDOWS else "MONITORING_ONLY",
    }


def evaluate_for_block(alert: dict) -> dict | None:
    """
    Called by the alert pipeline for every alert.

    v2 changes:
      - ML-only alerts are never auto-blocked
      - All alerts pass through block_manager which applies trust scoring
      - Single spike / single anomaly cannot trigger blocking
    """
    src  = alert.get("source_ip", "")
<<<<<<< HEAD
    if not src or is_private(src):
        return None

    atype = alert.get("alert_type", "")

    # ── ML score alone NEVER triggers a block from this path ──
    if atype.startswith("ML_"):
        log.debug(f"[FW] ML-only alert {atype} from {src} — forwarding to monitor pipeline, not blocking")
=======
    if not src:
        return None
    # Private-IP gating is handled inside block_manager (ARP-spoof-aware).
    # Do not filter here — let block_manager decide.

    atype = alert.get("alert_type", "")

    # -- ML score alone NEVER triggers a block from this path --
    if atype.startswith("ML_"):
        log.debug(f"[FW] ML-only alert {atype} from {src} - forwarding to monitor pipeline, not blocking")
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
        return None

    sev  = alert.get("severity", "LOW")
    conf = float(alert.get("confidence", 0))

    # Use block_manager which includes trust scoring
    try:
        from block_manager import evaluate_alert as _bm_eval
        return _bm_eval(alert)
    except ImportError:
        pass

    # Fallback (block_manager not loaded): direct check with high thresholds
    if sev == "CRITICAL" and conf >= 0.75:
        tier = BLOCK_THRESHOLDS["CRITICAL"]
    elif sev == "HIGH" and conf >= 0.85:   # raised from 0.80
        tier = BLOCK_THRESHOLDS["HIGH"]
    else:
        return None

    reason = f"{atype}: {tier['reason']}"
    return block_ip(ip=src, reason=reason, severity=sev, confidence=conf,
                    duration=tier["duration"], operator="auto-policy")


<<<<<<< HEAD
# ─────────────────────────────────────────────────────────────────────────────
# Expiry checker
# ─────────────────────────────────────────────────────────────────────────────
=======
# -----------------------------------------------------------------------------
# Expiry checker
# -----------------------------------------------------------------------------
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)

def _expiry_loop():
    while True:
        time.sleep(60)
        try:
            import datetime as _dt
            now = _dt.datetime.now(_dt.timezone.utc)
            with _lock:
                entries = _load_blocked()
                changed = False
                for e in entries:
                    if e.get("status") != "active":
                        continue
                    exp = e.get("expires_at")
                    if not exp:
                        continue
                    try:
                        exp_dt = _dt.datetime.fromisoformat(exp.replace("Z", "+00:00"))
                        if now > exp_dt:
                            _remove_firewall_rule(e.get("rule_name", ""))
                            e["status"]       = "expired"
                            e["unblocked_at"] = now.isoformat()
                            e["unblocked_by"] = "auto-expiry"
                            changed = True
                            log.info(f"[FW] Expired block removed: {e.get('ip')}")
                    except Exception:
                        pass
                if changed:
                    _save_blocked(entries)
        except Exception as ex:
            log.error(f"[FW] Expiry loop error: {ex}")


_expiry_thread = threading.Thread(target=_expiry_loop, daemon=True, name="fw-expiry")
_expiry_thread.start()