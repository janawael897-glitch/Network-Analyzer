#!/usr/bin/env python3
"""
block_manager.py — PacketGuard Centralized Block Manager
=========================================================
Single source of truth for all IP blocking decisions.

v2 — Intelligent Trust Scoring Integration
------------------------------------------
All blocking decisions now pass through the TrustScorer before any
firewall action is taken.  This eliminates false positives caused by
legitimate cloud, CDN, AI-service, and developer traffic without
creating blind spots — every IP is still monitored.

Blocking pipeline:
  1. Classify provider (CDN, Cloud, Developer, Unknown, …)
  2. Build evidence dict from alert / incident
  3. Query TrustProfile.recommended_stage() — uses provider-aware thresholds
  4. Only call firewall_enforcer when stage ≥ TEMPORARY_BLOCK AND
     multi-factor validation passes:
       • persistence ≥ threshold
       • repeat count ≥ threshold
       • indicator diversity ≥ threshold
       • correlation confidence ≥ threshold
       • ML score alone is NEVER sufficient
  5. Emit WebSocket event and log Auto-Response timeline entry

Escalation stages:
  MONITOR          → just log
  INCREASE_MONITOR → log at WARNING level, feed threat scorer
  TEMPORARY_BLOCK  → 1-hour firewall block
  PERMANENT_BLOCK  → permanent firewall block (requires very high confidence)

Receives events from:
  - alert_dedup  (per-alert evaluation via evaluate_alert)
  - correlation_engine_v2 (incident-level blocks for HIGH/CRITICAL)
  - auto_response (BLOCK action from risk-score sweep)
  - soc_api / web_dashboard (manual admin blocks)
"""

import logging
import threading
import time
from datetime import datetime, timezone

log = logging.getLogger(__name__)

_lock            = threading.Lock()
_emit_cb         = None    # socketio.emit — set by web_dashboard
_response_engine = None    # auto_response.ResponseEngine — set at startup


def set_emit_callback(fn):
    global _emit_cb
    _emit_cb = fn


def set_response_engine(eng):
    global _response_engine
    _response_engine = eng


# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

def _get_trust_scorer():
    try:
        from trust_scorer import get_trust_profile, should_escalate, EscalationStage
        return get_trust_profile, should_escalate, EscalationStage
    except ImportError:
        return None, None, None


def _log_to_timeline(ip: str, reason: str, severity: str,
                     confidence: float, block_result: dict, source: str):
    """Append a BLOCK action to the Auto-Response engine's in-memory log."""
    global _response_engine
    if _response_engine is None:
        try:
            from auto_response import get_engine
            _response_engine = get_engine()
        except Exception:
            return

    eng = _response_engine
    if eng is None:
        return

    action = {
        "source_ip":    ip,
        "action_type":  "BLOCK",
        "action_label": "IP Blocked",
        "action_time":  datetime.now(tz=timezone.utc).isoformat(),
        "description":  reason,
        "risk_score":   round(confidence * 100),
        "executed":     block_result.get("real_block", False),
        "severity":     severity,
        "result":       f"Firewall: {block_result.get('fw_message', 'logged')}",
        "block_id":     block_result.get("ip", ip),
        "block_status": block_result.get("status", "unknown"),
        "source":       source,
    }
    import threading as _t
    with _t.Lock():
        eng._log.appendleft(action)


def _log_monitor_action(ip: str, reason: str, severity: str, stage_name: str,
                        evidence: dict, source: str):
    """
    Log a monitoring action (not a block) to the Auto-Response timeline so
    the dashboard always shows what PacketGuard is doing, even when it
    decides NOT to block a trusted provider.
    """
    global _response_engine
    if _response_engine is None:
        try:
            from auto_response import get_engine
            _response_engine = get_engine()
        except Exception:
            return

    eng = _response_engine
    if eng is None:
        return

    action = {
        "source_ip":    ip,
        "action_type":  "MONITOR" if stage_name == "MONITOR" else "ESCALATE_MONITOR",
        "action_label": f"Stage: {stage_name.replace('_', ' ').title()}",
        "action_time":  datetime.now(tz=timezone.utc).isoformat(),
        "description":  reason,
        "risk_score":   round(evidence.get("correlation_conf", 0)),
        "executed":     True,
        "severity":     severity,
        "result":       (
            f"Trust system: insufficient evidence to block "
            f"(repeat={evidence.get('repeat_count',0)} "
            f"persist={evidence.get('persistence_secs',0):.0f}s "
            f"indicators={evidence.get('indicator_types',0)})"
        ),
        "block_id":     None,
        "block_status": "monitored",
        "source":       source,
    }
    import threading as _t
    with _t.Lock():
        eng._log.appendleft(action)


# ─────────────────────────────────────────────────────────────────────────────
# Core block dispatcher
# ─────────────────────────────────────────────────────────────────────────────

def attempt_block(ip: str, reason: str, severity: str,
                  confidence: float = 1.0,
                  duration: int | None = None,
                  operator: str = "auto",
                  source: str = "unknown",
                  evidence: dict | None = None) -> dict | None:
    """
    Unified entry point for all block requests.

    When evidence dict is supplied, the trust scoring system evaluates
    whether blocking is appropriate for this provider type.
    When evidence is None (e.g. manual admin block), it bypasses
    trust scoring and executes immediately.

    Returns block_record on success, None if skipped/rejected.
    """
    try:
        from firewall_enforcer import block_ip, is_private
    except ImportError:
        log.error("[BM] firewall_enforcer not available")
        return None

    if is_private(ip):
        return None

    # ── Trust scoring gate (skipped for manual operator blocks) ──
    if evidence is not None and operator != "manual":
        get_profile, escalate_fn, EscalationStage = _get_trust_scorer()
        if get_profile and escalate_fn and EscalationStage:
            try:
                profile = get_profile(ip)
                stage   = escalate_fn(ip, evidence)

                if stage == EscalationStage.MONITOR:
                    log.info(
                        f"[BM] MONITOR only: {ip} ({profile.provider_name}) "
                        f"— insufficient evidence for enforcement. Source={source}"
                    )
                    _log_monitor_action(ip, reason, severity, "MONITOR",
                                        evidence, source)
                    return None

                if stage == EscalationStage.INCREASE_MONITOR:
                    log.warning(
                        f"[BM] INCREASE MONITOR: {ip} ({profile.provider_name}) "
                        f"— escalating collection but not blocking yet. Source={source}"
                    )
                    _log_monitor_action(ip, reason, severity, "INCREASE_MONITOR",
                                        evidence, source)
                    # Emit dashboard event so analysts can see escalation
                    if _emit_cb:
                        try:
                            _emit_cb("monitoring_escalated", {
                                "ip":           ip,
                                "provider":     profile.provider_name,
                                "severity":     severity,
                                "reason":       reason,
                                "stage":        "INCREASE_MONITOR",
                                "source":       source,
                            })
                        except Exception:
                            pass
                    return None

                # Stage 3/4 — proceed with block, set duration appropriately
                if stage == EscalationStage.TEMPORARY_BLOCK:
                    if duration is None:
                        duration = 3600   # default 1-hour temp block
                    log.warning(
                        f"[BM] TEMPORARY BLOCK approved: {ip} "
                        f"({profile.provider_name}) | {reason} | source={source}"
                    )

                elif stage == EscalationStage.PERMANENT_BLOCK:
                    duration = None   # permanent
                    log.warning(
                        f"[BM] PERMANENT BLOCK approved: {ip} "
                        f"({profile.provider_name}) | {reason} | source={source}"
                    )

            except Exception as trust_err:
                log.warning(f"[BM] Trust scoring error for {ip}: {trust_err} — proceeding with default policy")

    # ── Execute firewall block ──
    result = block_ip(
        ip=ip,
        reason=reason,
        severity=severity,
        confidence=confidence,
        duration=duration,
        operator=operator,
    )

    # Log to Auto-Response timeline
    _log_to_timeline(ip, reason, severity, confidence, result, source)

    # WebSocket push to dashboard
    if _emit_cb and result.get("status") not in ("duplicate", "rejected"):
        try:
            _emit_cb("ip_blocked", {
                "ip":       ip,
                "severity": severity,
                "reason":   reason,
                "real":     result.get("real_block", False),
                "source":   source,
            })
        except Exception:
            pass

    if result.get("status") in ("duplicate", "rejected"):
        return None

    log.warning(
        f"[BM] BLOCK via {source}: {ip} | {severity} | {reason[:60]} | "
        f"fw={result.get('real_block')} status={result.get('status')}"
    )
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Alert-level evaluation
# ─────────────────────────────────────────────────────────────────────────────

def evaluate_alert(alert: dict) -> dict | None:
    """
    Called for every de-duplicated alert.
    Applies trust-scoring before any block decision.

    Changes from v1:
      - ML_ANOMALY alerts alone will NEVER trigger a block regardless of severity
      - All alerts pass through the trust scoring evidence gate
      - Cloud/CDN providers require much higher evidence before enforcement
    """
    try:
        from firewall_enforcer import is_private
    except ImportError:
        return None

    src  = alert.get("source_ip", "")
    if not src or is_private(src):
        return None

    sev   = alert.get("severity", "LOW")
    conf  = float(alert.get("confidence", 0))
    atype = alert.get("alert_type", "")
    info  = alert.get("additional_info") or {}

    # ── ML score alone: NEVER blocks — always just monitors ──
    if atype.startswith("ML_") and not info.get("protocol_abuse"):
        log.debug(f"[BM] ML-only alert for {src} — monitoring, not blocking (conf={conf:.2f})")
        return None

    # ── Build evidence from alert context ──
    try:
        from trust_scorer import build_evidence_from_alert
        evidence = build_evidence_from_alert(alert)
    except ImportError:
        evidence = None

    # ── Determine base blocking parameters ──
    if sev == "CRITICAL" and conf >= 0.75:
        duration = None
        reason   = f"Auto-block: CRITICAL alert — {atype}"
    elif sev == "HIGH" and conf >= 0.80:
        duration = 3600
        reason   = f"Auto-block: HIGH alert — {atype}"
    else:
        return None   # below minimum confidence — monitor only

    return attempt_block(
        ip=src,
        reason=reason,
        severity=sev,
        confidence=conf,
        duration=duration,
        operator="auto-alert",
        source="alert_pipeline",
        evidence=evidence,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Incident-level evaluation
# ─────────────────────────────────────────────────────────────────────────────

def evaluate_incident(incident: dict) -> dict | None:
    """
    Called by correlation_engine_v2 when a new incident is created.
    Blocks the source IP only when trust-scoring confirms sufficient evidence.

    Incidents already have rich multi-indicator context, making them the
    primary driver of blocking decisions (not individual alerts).
    """
    src  = incident.get("src_ip", "")
    sev  = incident.get("severity", "LOW")
    conf = float(incident.get("confidence", 0)) / 100.0
    cat  = incident.get("category", "Unknown")
    inc_id = incident.get("id", "")

    if sev not in ("CRITICAL", "HIGH"):
        return None
    if conf < 0.70:
        return None

    try:
        from firewall_enforcer import is_private
        if is_private(src):
            return None
    except ImportError:
        return None

    # ── Build rich evidence from incident ──
    try:
        from trust_scorer import build_evidence_from_incident
        evidence = build_evidence_from_incident(incident)
    except ImportError:
        evidence = None

    duration = None if sev == "CRITICAL" else 3600

    return attempt_block(
        ip=src,
        reason=f"Incident {inc_id}: {cat}",
        severity=sev,
        confidence=conf,
        duration=duration,
        operator="auto-correlation",
        source="correlation_engine",
        evidence=evidence,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Risk-score sweep evaluation
# ─────────────────────────────────────────────────────────────────────────────

def evaluate_risk_score(ip: str, risk_score: float) -> dict | None:
    """
    Called by auto_response sweep for top-risk IPs.
    Only blocks at CRITICAL tier (≥76).  Even then, trust scoring applies —
    a Cloudflare IP with a high risk score from WebSocket traffic alone
    will be escalated to INCREASE_MONITOR rather than blocked.
    """
    if risk_score < 76:
        return None

    try:
        from firewall_enforcer import is_private
        if is_private(ip):
            return None
    except ImportError:
        return None

    conf = min(risk_score / 100.0, 1.0)

    # Risk-score sweep has limited evidence context — build minimal dict
    evidence = {
        "repeat_count":     3,    # sweep only fires after multiple scoring cycles
        "persistence_secs": 60.0, # at least 1 cycle = 2 min by auto_response loop
        "correlation_conf": risk_score,
        "ml_score":         0.0,
        "indicator_types":  2,    # conservatively assume 2
        "protocol_abuse":   False,
        "scan_behaviour":   False,
    }

    return attempt_block(
        ip=ip,
        reason=f"Auto-block: risk score {risk_score:.0f}/100 — CRITICAL threshold",
        severity="CRITICAL",
        confidence=conf,
        duration=None,
        operator="auto-sweep",
        source="risk_score_sweep",
        evidence=evidence,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Manual admin block (bypasses trust scoring)
# ─────────────────────────────────────────────────────────────────────────────

def manual_block(ip: str, reason: str, operator: str = "admin",
                 duration: int | None = None) -> dict | None:
    """
    Manual admin-initiated block.  Bypasses trust scoring — an operator
    who explicitly wants to block something should be able to do so.
    Still enforces private-IP safety check.
    """
    return attempt_block(
        ip=ip,
        reason=reason,
        severity="HIGH",
        confidence=1.0,
        duration=duration,
        operator="manual",   # bypasses trust gate
        source=f"manual:{operator}",
        evidence=None,       # no evidence needed for manual blocks
    )