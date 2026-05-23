#!/usr/bin/env python3
"""
correlation_engine_v2.py — PacketGuard Real Correlation Engine
==============================================================
v2.1 — Intelligent Trust Scoring Integration

Changes in this version:
  - Every correlation rule queries the TrustScorer before assigning
    confidence.  Cloud/CDN sources require more corroborating evidence
    before an incident is elevated to HIGH/CRITICAL.
  - ML_ANOMALY alone never creates a HIGH/CRITICAL incident for trusted
    providers — it needs to be combined with at least one other indicator.
  - Incidents are only routed to block_manager when the TrustScorer
    confirms that evidence meets the provider-appropriate threshold.
  - All incidents still created and persisted (monitoring continues).
    Trust scoring only affects the enforcement stage, not visibility.

Correlation rules:
  - ReconRule:            Port scan + optional ML → Reconnaissance
  - DDoSRule:             SYN flood or high rate + persistence → DDoS Pattern
  - IntrusionRule:        Repeated ML anomalies + unusual ports → Intrusion Attempt
  - ReconExploitRule:     Port scan + ML anomaly → Recon + Exploit chain
  - SuspiciousBurstRule:  Isolated ML burst → Suspicious Traffic Burst
"""

import json
import os
import threading
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone

log_import = __import__("logging").getLogger(__name__)

BASE_DIR       = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INCIDENTS_FILE = os.path.join(BASE_DIR, "incidents.json")

_lock    = threading.Lock()
_running = False

EVIDENCE_TTL = 120   # seconds — evidence expires after 2 min of silence


# ─────────────────────────────────────────────────────────────────────────────
# EvidenceWindow — accumulates evidence per source IP
# ─────────────────────────────────────────────────────────────────────────────

class EvidenceWindow:
    """Accumulates evidence for a single source IP."""
    __slots__ = (
        "src_ip", "first_ts", "last_ts",
        "port_scan", "syn_flood", "high_rate", "ml_anomaly",
        "ml_burst", "large_pkt",
        "alert_types", "ml_scores", "port_count",
        "event_count", "severity_max",
    )
    _SEV = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

    def __init__(self, src_ip):
        now = time.monotonic()
        self.src_ip       = src_ip
        self.first_ts     = now
        self.last_ts      = now
        self.port_scan    = False
        self.syn_flood    = False
        self.high_rate    = False
        self.ml_anomaly   = False
        self.ml_burst     = False
        self.large_pkt    = False
        self.alert_types  = set()
        self.ml_scores    = []
        self.port_count   = 0
        self.event_count  = 0
        self.severity_max = "LOW"

    def ingest(self, alert: dict):
        self.last_ts     = time.monotonic()
        self.event_count += 1
        atype = alert.get("alert_type", "")
        sev   = alert.get("severity", "LOW")
        self.alert_types.add(atype)

        if self._SEV.get(sev, 0) > self._SEV.get(self.severity_max, 0):
            self.severity_max = sev

        info = alert.get("additional_info") or {}

        if atype == "PORT_SCAN":
            self.port_scan  = True
            self.port_count = max(self.port_count, int(info.get("ports_scanned", 0)))
        if atype == "SYN_FLOOD":
            self.syn_flood  = True
        if atype in ("HIGH_PACKET_RATE", "DDOS_PATTERN"):
            self.high_rate  = True
        if atype in ("ML_ANOMALY", "ML_ANOMALY_AGGREGATED", "ML_ANOMALY_BURST"):
            self.ml_anomaly = True
            score = info.get("iso_score") or info.get("fused_score")
            if score is not None:
                self.ml_scores.append(float(score))
        if atype == "ML_ANOMALY_BURST":
            self.ml_burst   = True
        if atype == "ABNORMAL_SIZE":
            self.large_pkt  = True

    @property
    def age(self):
        return time.monotonic() - self.first_ts

    @property
    def is_stale(self):
        return (time.monotonic() - self.last_ts) > EVIDENCE_TTL

    def non_ml_indicator_count(self) -> int:
        """Count of indicator types that are NOT ML-based."""
        return sum([self.port_scan, self.syn_flood, self.high_rate, self.large_pkt])

    def total_indicator_types(self) -> int:
        return self.non_ml_indicator_count() + (1 if self.ml_anomaly or self.ml_burst else 0)


# ─────────────────────────────────────────────────────────────────────────────
# Provider-aware confidence adjustment
# ─────────────────────────────────────────────────────────────────────────────

def _get_provider_confidence_modifier(src_ip: str) -> tuple[float, str]:
    """
    Return (confidence_modifier, provider_name).
    modifier < 1.0 means confidence is reduced (need more evidence).
    modifier > 1.0 means confidence is boosted (known-bad range).
    """
    try:
        from trust_scorer import get_trust_profile, ProviderType
        profile = get_trust_profile(src_ip)
        ptype   = profile.provider_type

        modifiers = {
            ProviderType.UNKNOWN:         1.00,
            ProviderType.ISP:             1.00,
            ProviderType.CORPORATE:       0.90,
            ProviderType.DEVELOPER:       0.80,
            ProviderType.AI_SERVICE:      0.75,
            ProviderType.CLOUD:           0.70,
            ProviderType.CDN:             0.65,
            ProviderType.KNOWN_MALICIOUS: 1.30,
        }
        return modifiers.get(ptype, 1.0), profile.provider_name
    except Exception:
        return 1.0, "Unknown"


def _ml_only_for_trusted(ev: EvidenceWindow) -> bool:
    """
    Returns True if the ONLY meaningful indicators are ML-based and
    the source belongs to a trusted provider category.
    In that case, confidence is capped so we don't reach block threshold.
    """
    if ev.non_ml_indicator_count() > 0:
        return False   # has non-ML indicators — normal processing
    try:
        from trust_scorer import get_trust_profile, ProviderType
        profile = get_trust_profile(ev.src_ip)
        trusted_types = {
            ProviderType.CLOUD, ProviderType.CDN,
            ProviderType.AI_SERVICE, ProviderType.DEVELOPER
        }
        return profile.provider_type in trusted_types
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Correlation Rules
# ─────────────────────────────────────────────────────────────────────────────

class CorrelationRule:
    name     = "BASE"
    category = "Unknown"
    min_conf = 60

    def evaluate(self, ev: EvidenceWindow) -> dict | None:
        raise NotImplementedError


class ReconRule(CorrelationRule):
    """Port scan + optional ML anomaly → Reconnaissance"""
    name     = "RECON"
    category = "Reconnaissance"

    def evaluate(self, ev: EvidenceWindow):
        if not ev.port_scan:
            return None

        conf = 60
        explanation = ["Port scan detected"]

        if ev.ml_anomaly:
            conf += 20
            explanation.append("ML anomaly from same source IP")
        if ev.port_count > 50:
            conf += 10
            explanation.append(f"Wide port scan ({ev.port_count} unique ports)")
        if ev.high_rate:
            conf += 5
            explanation.append("Elevated packet rate during scan")

        modifier, pname = _get_provider_confidence_modifier(ev.src_ip)
        conf = int(conf * modifier)

        if pname != "Unknown":
            explanation.append(f"Provider context: {pname} (threshold adjusted)")

        conf = min(conf, 98)
        if conf < self.min_conf:
            return None

        return _build_incident(ev, self.category, "HIGH", conf, explanation)


class DDoSRule(CorrelationRule):
    """SYN flood or high rate + persistence → DDoS Pattern"""
    name     = "DDOS"
    category = "DDoS Pattern"

    def evaluate(self, ev: EvidenceWindow):
        if not (ev.syn_flood or ev.high_rate):
            return None

        conf = 55
        explanation = []

        if ev.syn_flood:
            conf += 20
            explanation.append("SYN flood detected")
        if ev.high_rate:
            conf += 15
            explanation.append("Abnormal packet rate")
        if ev.age > 30:
            conf += 10
            explanation.append(f"Persistent attack ({ev.age:.0f}s duration)")
        if ev.ml_burst:
            conf += 10
            explanation.append("ML anomaly burst detected")

        modifier, pname = _get_provider_confidence_modifier(ev.src_ip)
        conf = int(conf * modifier)

        if pname != "Unknown":
            explanation.append(f"Provider context: {pname} (threshold adjusted)")

        conf = min(conf, 98)
        if conf < self.min_conf:
            return None

        sev = "CRITICAL" if conf >= 85 else "HIGH"
        return _build_incident(ev, self.category, sev, conf, explanation)


class IntrusionRule(CorrelationRule):
    """Repeated ML anomalies + unusual ports → Intrusion Attempt"""
    name     = "INTRUSION"
    category = "Intrusion Attempt"
    min_conf = 65

    def evaluate(self, ev: EvidenceWindow):
        if not ev.ml_anomaly:
            return None
        if ev.event_count < 3:
            return None

        # ── For trusted providers, ML-only evidence is capped ──
        if _ml_only_for_trusted(ev):
            log_import.debug(
                f"[CORR-V2] IntrusionRule: ML-only evidence for trusted provider "
                f"{ev.src_ip} — capping confidence to monitoring level"
            )
            # Still create an incident for visibility, but at MEDIUM severity
            # so it doesn't trigger automatic blocking
            conf = 45
            explanation = [
                "Repeated ML anomalies detected",
                "Provider classified as trusted — monitoring only (no non-ML indicators)",
                f"Event count: {ev.event_count}",
            ]
            return _build_incident(ev, self.category, "MEDIUM", conf, explanation)

        conf = 55
        explanation = []
        ml_avg = sum(ev.ml_scores) / len(ev.ml_scores) if ev.ml_scores else 0

        if ev.ml_burst:
            conf += 20
            explanation.append(f"ML anomaly burst ({ev.event_count} events)")
        elif ev.ml_anomaly:
            conf += 12
            explanation.append(f"Repeated ML anomalies ({ev.event_count} events)")
        if ml_avg > 0.7:
            conf += 10
            explanation.append(f"High anomaly confidence (avg {ml_avg*100:.0f}%)")
        if ev.port_scan:
            conf += 10
            explanation.append("Port scan preceding anomaly")
        if ev.age > 20:
            conf += 8
            explanation.append(f"Sustained anomalous activity ({ev.age:.0f}s)")

        modifier, pname = _get_provider_confidence_modifier(ev.src_ip)
        conf = int(conf * modifier)

        if pname != "Unknown":
            explanation.append(f"Provider context: {pname} (threshold adjusted)")

        conf = min(conf, 97)
        if conf < self.min_conf:
            return None

        return _build_incident(ev, self.category, "HIGH", conf, explanation)


class ReconExploitRule(CorrelationRule):
    """Port scan + ML anomaly together = Recon → Exploit chain"""
    name     = "RECON_EXPLOIT"
    category = "Recon + Exploit"
    min_conf = 75

    def evaluate(self, ev: EvidenceWindow):
        if not (ev.port_scan and ev.ml_anomaly):
            return None

        conf = 75
        explanation = [
            "Port scan followed by anomalous traffic",
            "Attack chain: Reconnaissance → Exploitation",
        ]

        if ev.ml_burst:
            conf += 10
            explanation.append("Multiple anomalous flows after scan")
        if ev.event_count > 5:
            conf += 5
            explanation.append(f"High event density ({ev.event_count} events)")

        modifier, pname = _get_provider_confidence_modifier(ev.src_ip)
        conf = int(conf * modifier)

        if pname != "Unknown":
            explanation.append(f"Provider context: {pname} (threshold adjusted)")

        conf = min(conf, 98)
        if conf < self.min_conf:
            return None

        sev = "CRITICAL" if conf >= 85 else "HIGH"
        return _build_incident(ev, self.category, sev, conf, explanation)


class SuspiciousBurstRule(CorrelationRule):
    """Isolated ML burst without scan = Suspicious Traffic"""
    name     = "SUSPICIOUS_BURST"
    category = "Suspicious Traffic Burst"
    min_conf = 60

    def evaluate(self, ev: EvidenceWindow):
        if not ev.ml_burst:
            return None
        if ev.port_scan or ev.syn_flood:
            return None   # covered by other rules

        # For trusted providers, an isolated ML burst creates a LOW severity
        # monitoring incident but cannot escalate to blocking without more evidence
        if _ml_only_for_trusted(ev):
            conf = 40   # below any blocking threshold
            explanation = [
                "Anomalous traffic burst detected by ML engine",
                "Provider classified as trusted — requires additional indicators before enforcement",
            ]
            if ev.event_count > 8:
                explanation.append(f"High volume of anomalous flows ({ev.event_count})")
            return _build_incident(ev, self.category, "LOW", conf, explanation)

        conf = 60
        explanation = ["Anomalous traffic burst detected by ML engine"]

        if ev.event_count > 8:
            conf += 10
            explanation.append(f"High volume of anomalous flows ({ev.event_count})")
        if ev.high_rate:
            conf += 10
            explanation.append("Elevated packet rate")

        modifier, pname = _get_provider_confidence_modifier(ev.src_ip)
        conf = int(conf * modifier)

        if pname != "Unknown":
            explanation.append(f"Provider context: {pname} (threshold adjusted)")

        conf = min(conf, 90)
        if conf < self.min_conf:
            return None

        return _build_incident(ev, self.category, "MEDIUM", conf, explanation)


# Ordered by priority — first matching rule wins for a given IP
RULES = [
    ReconExploitRule(),
    DDoSRule(),
    ReconRule(),
    IntrusionRule(),
    SuspiciousBurstRule(),
]


# ─────────────────────────────────────────────────────────────────────────────
# Incident builder
# ─────────────────────────────────────────────────────────────────────────────

def _build_incident(ev: EvidenceWindow, category: str,
                    severity: str, confidence: int,
                    explanation: list) -> dict:
    sev_mult = {"CRITICAL": 1.25, "HIGH": 1.0, "MEDIUM": 0.75, "LOW": 0.5}
    risk = min(int(confidence * sev_mult.get(severity, 1.0)), 100)

    return {
        "id":          "INC-" + uuid.uuid4().hex[:8].upper(),
        "incident_id": "INC-" + uuid.uuid4().hex[:8].upper(),
        "timestamp":   datetime.now(timezone.utc).isoformat(),
        "src_ip":      ev.src_ip,
        "source_ip":   ev.src_ip,
        "category":    category,
        "attack_chain": category,
        "severity":    severity,
        "confidence":  confidence,
        "risk_score":  risk,
        "event_count": ev.event_count,
        "duration_s":  round(ev.age, 1),
        "status":      "open",
        "explanation": explanation,
        "evidence": {
            "port_scan":   ev.port_scan,
            "syn_flood":   ev.syn_flood,
            "high_rate":   ev.high_rate,
            "ml_anomaly":  ev.ml_anomaly,
            "ml_burst":    ev.ml_burst,
            "indicator_count": ev.total_indicator_types(),
        },
        "alert_types": list(ev.alert_types),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Persistence
# ─────────────────────────────────────────────────────────────────────────────

def _load_incidents() -> list:
    try:
        with open(INCIDENTS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def _save_incidents(incidents: list):
    try:
        with open(INCIDENTS_FILE, "w", encoding="utf-8") as f:
            json.dump(incidents[-1000:], f, indent=2, default=str)
    except Exception as e:
        log_import.warning(f"[CORR-V2] Save error: {e}")


def _is_duplicate(incident: dict, existing: list) -> bool:
    """Check if an open incident for same IP+category already exists."""
    src = incident.get("src_ip", "")
    cat = incident.get("category", "")
    cutoff = time.time() - 300   # 5-minute dedup window
    for ex in existing:
        if ex.get("status", "open") != "open":
            continue
        if ex.get("src_ip") != src or ex.get("category") != cat:
            continue
        try:
            import datetime as _dt
            ts = ex.get("timestamp", "")
            dt = _dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))
            if dt.timestamp() > cutoff:
                return True
        except Exception:
            pass
    return False


# ─────────────────────────────────────────────────────────────────────────────
# Evidence store + ingestion
# ─────────────────────────────────────────────────────────────────────────────

_evidence: dict[str, EvidenceWindow] = {}
_ev_lock  = threading.Lock()


def feed_alert(alert: dict):
    """Feed an alert into the correlation engine. Thread-safe."""
    src = alert.get("source_ip", "")
    if not src or src in ("Multiple", "N/A", "Unknown", ""):
        return
    with _ev_lock:
        if src not in _evidence:
            _evidence[src] = EvidenceWindow(src)
        _evidence[src].ingest(alert)


# ─────────────────────────────────────────────────────────────────────────────
# Main correlation loop
# ─────────────────────────────────────────────────────────────────────────────

def _correlate_all():
    """Run all rules against all evidence windows. Create incidents for matches."""
    with _ev_lock:
        windows = dict(_evidence)

    existing = _load_incidents()
    new_incidents = []

    for src_ip, ev in windows.items():
        if ev.is_stale:
            continue
        if ev.event_count < 2:
            continue

        for rule in RULES:
            incident = rule.evaluate(ev)
            if incident and not _is_duplicate(incident, existing + new_incidents):
                new_incidents.append(incident)
                log_import.warning(
                    f"[CORR-V2] New incident {incident['id']}: "
                    f"{incident['category']} from {src_ip} "
                    f"(conf={incident['confidence']}% sev={incident['severity']})"
                )
                break   # one incident per IP per pass

    if new_incidents:
        all_inc = existing + new_incidents
        _save_incidents(all_inc)

        # Route to block_manager — it applies trust scoring before enforcement
        for inc in new_incidents:
            try:
                from block_manager import evaluate_incident as _bm_eval
                _bm_eval(inc)
            except Exception as _be:
                log_import.debug(f"[CORR-V2] block_manager unavailable: {_be}")

    # Prune stale evidence
    with _ev_lock:
        stale = [k for k, v in _evidence.items() if v.is_stale]
        for k in stale:
            del _evidence[k]


def _loop():
    while _running:
        time.sleep(15)
        try:
            _correlate_all()
        except Exception as e:
            log_import.error(f"[CORR-V2] Loop error: {e}")


def start_correlation_thread():
    global _running
    if _running:
        return
    _running = True
    t = threading.Thread(target=_loop, daemon=True, name="corr-v2")
    t.start()
    log_import.info("[CORR-V2] Correlation engine started (with trust scoring).")
    return t