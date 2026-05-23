#!/usr/bin/env python3
"""
soc_api.py — PacketGuard SOC REST API Blueprint
================================================
Provides routes for:
  - /api/firewall_status       GET  — firewall engine status
  - /api/blocked_ips           GET  — list of blocked IPs
  - /api/blocked_ips/block     POST — manually block an IP (admin only)
  - /api/blocked_ips/unblock   POST — unblock an IP (admin only)
  - /api/whitelist             GET/POST — IP whitelist management
  - /api/incidents             GET  — all incidents (alias for enterprise)
  - /api/incidents/<id>/close  POST — close an incident

All write endpoints require admin role via RBAC.
"""

import json
import os
import logging
from datetime import datetime, timezone
from flask import Blueprint, jsonify, request, session

log = logging.getLogger(__name__)

BASE_DIR       = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WHITELIST_FILE = os.path.join(BASE_DIR, "ip_whitelist.json")

soc_bp = Blueprint("soc", __name__)


# ── Auth helpers ──────────────────────────────────────────────────

def _is_admin():
    return session.get("user_role") in ("admin",)

def _is_logged_in():
    return "user_id" in session

def _require_login():
    if not _is_logged_in():
        return jsonify({"success": False, "error": "Authentication required"}), 401
    return None

def _require_admin():
    err = _require_login()
    if err:
        return err
    if not _is_admin():
        return jsonify({"success": False, "error": "Admin role required"}), 403
    return None


# ── Whitelist helpers ─────────────────────────────────────────────

def _load_whitelist() -> dict:
    try:
        with open(WHITELIST_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"ips": [], "notes": {}}

def _save_whitelist(data: dict):
    with open(WHITELIST_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


# ══════════════════════════════════════════════════════════════════
# Firewall Status
# ══════════════════════════════════════════════════════════════════

@soc_bp.route("/api/firewall_status")
def api_firewall_status():
    try:
        from firewall_enforcer import get_firewall_status
        return jsonify(get_firewall_status())
    except ImportError:
        return jsonify({
            "enabled": False,
            "status": "MODULE_NOT_LOADED",
            "enforcement": "Monitoring Only",
            "active_blocks": 0,
            "real_blocks": 0,
        })


# ══════════════════════════════════════════════════════════════════
# Blocked IPs
# ══════════════════════════════════════════════════════════════════

@soc_bp.route("/api/blocked_ips")
def api_blocked_ips():
    err = _require_login()
    if err:
        return err
    try:
        from firewall_enforcer import get_blocked_list
        entries = get_blocked_list()
        # Sort: active first, then by blocked_at desc
        active  = [e for e in entries if e.get("status") == "active"]
        others  = [e for e in entries if e.get("status") != "active"]
        active.sort(key=lambda x: x.get("blocked_at", ""), reverse=True)
        others.sort(key=lambda x: x.get("blocked_at", ""), reverse=True)
        return jsonify(active + others[:50])
    except ImportError:
        return jsonify([])


@soc_bp.route("/api/blocked_ips/block", methods=["POST"])
def api_block_ip():
    err = _require_admin()
    if err:
        return err
    data = request.get_json() or {}
    ip   = data.get("ip", "").strip()
    if not ip:
        return jsonify({"success": False, "error": "IP required"}), 400
    try:
        from firewall_enforcer import block_ip, is_private
        if is_private(ip):
            return jsonify({"success": False, "error": "Cannot block private/local IP"}), 400
        result = block_ip(
            ip=ip,
            reason=data.get("reason", "Manual block by operator"),
            severity=data.get("severity", "HIGH"),
            confidence=float(data.get("confidence", 1.0)),
            duration=data.get("duration"),   # None = permanent
            operator=session.get("user_email", "admin"),
        )
        return jsonify(result)
    except ImportError:
        return jsonify({"success": False, "error": "Firewall module not loaded"}), 500


@soc_bp.route("/api/blocked_ips/unblock", methods=["POST"])
def api_unblock_ip():
    err = _require_admin()
    if err:
        return err
    data = request.get_json() or {}
    ip   = (data.get("ip") or "").strip()
    if not ip:
        return jsonify({"success": False, "error": "IP required"}), 400
    reason = (data.get('reason') or '').strip()
    try:
        from firewall_enforcer import unblock_ip
        result = unblock_ip(ip, operator=session.get('user_email', 'admin'), reason=reason)
        return jsonify(result)
    except ImportError:
        return jsonify({"success": False, "error": "Firewall module not loaded"}), 500


# ══════════════════════════════════════════════════════════════════
# Whitelist
# ══════════════════════════════════════════════════════════════════

@soc_bp.route("/api/whitelist", methods=["GET"])
def api_whitelist_get():
    err = _require_admin()
    if err:
        return err
    return jsonify(_load_whitelist())


@soc_bp.route("/api/whitelist", methods=["POST"])
def api_whitelist_post():
    err = _require_admin()
    if err:
        return err
    data = request.get_json() or {}
    action = data.get("action")   # "add" or "remove"
    ip     = (data.get("ip") or "").strip()
    if not ip or action not in ("add", "remove"):
        return jsonify({"success": False, "error": "action and ip required"}), 400

    wl = _load_whitelist()
    if action == "add":
        if ip not in wl["ips"]:
            wl["ips"].append(ip)
        if data.get("note"):
            wl.setdefault("notes", {})[ip] = data["note"]
    else:
        wl["ips"] = [x for x in wl["ips"] if x != ip]
        wl.get("notes", {}).pop(ip, None)

    _save_whitelist(wl)
    return jsonify({"success": True, "whitelist": wl})


# ══════════════════════════════════════════════════════════════════
# Incidents (SOC view)
# ══════════════════════════════════════════════════════════════════

@soc_bp.route("/api/incidents")
def api_incidents():
    err = _require_login()
    if err:
        return err
    try:
        from correlation_engine import get_open_incidents
        limit = int(request.args.get("limit", 50))
        return jsonify(get_open_incidents(limit=limit))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@soc_bp.route("/api/incidents/<incident_id>/close", methods=["POST"])
def api_close_incident(incident_id):
    err = _require_login()
    if err:
        return err
    try:
        from correlation_engine import close_incident
        ok = close_incident(incident_id, operator=session.get("user_email", "operator"))
        return jsonify({"success": ok})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500



# ══════════════════════════════════════════════════════════════════
# Block Sync Status — cross-references timeline with blocked_ips
# ══════════════════════════════════════════════════════════════════

@soc_bp.route("/api/block_sync_status")
def api_block_sync_status():
    """
    Returns a summary of auto-response BLOCK actions vs actual blocked_ips records.
    Used by dashboard to show sync health.
    """
    err = _require_login()
    if err:
        return err
    try:
        from firewall_enforcer import get_blocked_list
        from auto_response import get_engine as get_re

        blocked_ips = {e["ip"] for e in get_blocked_list() if e.get("status") == "active"}
        timeline    = get_re().get_recent_log(limit=100) if get_re() else []

        block_actions = [a for a in timeline if a.get("action_type") == "BLOCK"]
        synced   = [a for a in block_actions if a.get("source_ip") in blocked_ips]
        unsynced = [a for a in block_actions if a.get("source_ip") not in blocked_ips]

        return jsonify({
            "active_blocks":    len(blocked_ips),
            "timeline_blocks":  len(block_actions),
            "synced":           len(synced),
            "unsynced":         len(unsynced),
            "sync_health":      "OK" if not unsynced else "PARTIAL",
            "unsynced_ips":     [a.get("source_ip") for a in unsynced[:10]],
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@soc_bp.route("/api/soc_summary")
def api_soc_summary():
    try:
        from firewall_enforcer import get_firewall_status, get_blocked_list
        fw     = get_firewall_status()
        active = len([e for e in get_blocked_list() if e.get("status") == "active"])
    except ImportError:
        fw     = {"active_blocks": 0, "status": "MONITORING_ONLY"}
        active = 0

    try:
        from correlation_engine import get_incident_summary
        inc_summary = get_incident_summary()
    except Exception:
        inc_summary = {"open_incidents": 0, "by_severity": {}}

    return jsonify({
        "blocked_ips":     active,
        "open_incidents":  inc_summary.get("open_incidents", 0),
        "by_severity":     inc_summary.get("by_severity", {}),
        "firewall_status": fw.get("status", "UNKNOWN"),
        "enforcement":     fw.get("enforcement", "Monitoring Only"),
    })

# ══════════════════════════════════════════════════════════════════
# Audit Log — block/unblock history with reasons
# ══════════════════════════════════════════════════════════════════

@soc_bp.route("/api/audit_log")
def api_audit_log():
    """
    Returns the full blocked_ips history as an audit log,
    including both active and unblocked entries with reasons.
    """
    err = _require_login()
    if err:
        return err
    try:
        from firewall_enforcer import get_blocked_list
        entries = get_blocked_list()
        log = []
        for e in reversed(entries[-200:]):
            record = {
                "ip":            e.get("ip"),
                "action":        "unblocked" if e.get("status") == "unblocked" else ("expired" if e.get("status") == "expired" else "blocked"),
                "severity":      e.get("severity"),
                "reason":        e.get("reason"),
                "operator":      e.get("operator"),
                "real_block":    e.get("real_block", False),
                "blocked_at":    e.get("blocked_at"),
                "unblocked_at":  e.get("unblocked_at"),
                "unblocked_by":  e.get("unblocked_by"),
                "unblock_reason":e.get("unblock_reason"),
                "expires_at":    e.get("expires_at"),
                "status":        e.get("status"),
            }
            log.append(record)
        return jsonify(log)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@soc_bp.route("/api/verify_block/<ip>")
def api_verify_block(ip):
    """
    Check whether a given IP is currently in the active block list.
    """
    err = _require_login()
    if err:
        return err
    try:
        from firewall_enforcer import get_blocked_list
        entries = get_blocked_list()
        active = [e for e in entries if e.get("ip") == ip and e.get("status") == "active"]
        return jsonify({
            "ip":      ip,
            "blocked": bool(active),
            "record":  active[0] if active else None,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500