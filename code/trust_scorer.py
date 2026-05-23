#!/usr/bin/env python3
"""
trust_scorer.py — PacketGuard Intelligent Trust Scoring System
==============================================================
Implements dynamic, provider-aware trust levels for reducing false positives
WITHOUT blind trust.  Every IP is still monitored and inspected; trusted
providers simply require stronger evidence before enforcement actions fire.

Trust is NOT binary.  It is a continuous modifier that raises the evidence
threshold required before an IP moves through the escalation stages:

    Stage 1 → monitor
    Stage 2 → increase monitoring
    Stage 3 → temporary block
    Stage 4 → permanent block

Key design principles:
  - NO service is fully trusted or permanently allowed
  - ML score alone NEVER triggers a block
  - Cloud / CDN providers need multiple corroborating indicators
  - Blocking requires persistence + repeat count + protocol abuse +
    high-confidence correlation — not a single anomaly
  - Everything is still monitored

Public API
----------
    from trust_scorer import get_trust_profile, TrustProfile
    profile = get_trust_profile(src_ip)
    if profile.meets_block_threshold(evidence_dict):
        ...

    from trust_scorer import should_escalate
    stage = should_escalate(src_ip, evidence)
"""

import ipaddress
import logging
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

log = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Enumerations
# ─────────────────────────────────────────────────────────────────────────────

class ProviderType(Enum):
    UNKNOWN      = "unknown"
    CLOUD        = "cloud"          # AWS, Azure, GCP, etc.
    CDN          = "cdn"            # Cloudflare, Fastly, Akamai, etc.
    DEVELOPER    = "developer"      # GitHub, npm, PyPI, etc.
    AI_SERVICE   = "ai_service"     # OpenAI, Anthropic APIs, HuggingFace, etc.
    ISP          = "isp"            # Consumer ISP — normal sensitivity
    CORPORATE    = "corporate"      # Corporate / enterprise range
    KNOWN_MALICIOUS = "known_malicious"  # Confirmed-bad ASN / range


class EscalationStage(Enum):
    MONITOR           = 1   # Log and watch
    INCREASE_MONITOR  = 2   # Increase collection granularity
    TEMPORARY_BLOCK   = 3   # Short-duration firewall block
    PERMANENT_BLOCK   = 4   # Full block until admin reviews


# ─────────────────────────────────────────────────────────────────────────────
# Provider classification database
# Kept lightweight — real-world deployment would query a GeoIP/ASN database.
# ─────────────────────────────────────────────────────────────────────────────

# (prefix, provider_type, display_name)
# Ordered from most specific to least specific.
_PROVIDER_PREFIXES: list[tuple] = [
    # ── Cloudflare ──
    ("1.1.1.", ProviderType.CDN, "Cloudflare DNS"),
    ("1.0.0.", ProviderType.CDN, "Cloudflare DNS"),

    # ── Google / GCP ──
    ("8.8.8.", ProviderType.CDN, "Google DNS"),
    ("8.8.4.", ProviderType.CDN, "Google DNS"),
    ("34.",    ProviderType.CLOUD, "Google Cloud"),
    ("35.",    ProviderType.CLOUD, "Google Cloud"),
    ("104.",   ProviderType.CDN,   "Google CDN"),

    # ── AWS ──
    ("52.",    ProviderType.CLOUD, "Amazon AWS"),
    ("54.",    ProviderType.CLOUD, "Amazon AWS"),
    ("18.",    ProviderType.CLOUD, "Amazon AWS"),
    ("3.",     ProviderType.CLOUD, "Amazon AWS"),
    ("13.",    ProviderType.CLOUD, "Amazon AWS"),

    # ── Azure ──
    ("40.",    ProviderType.CLOUD, "Microsoft Azure"),
    ("20.",    ProviderType.CLOUD, "Microsoft Azure"),
    ("51.",    ProviderType.CLOUD, "Microsoft Azure"),
    ("23.",    ProviderType.CDN,   "Microsoft CDN"),

    # ── Fastly / Akamai ──
    ("151.101.", ProviderType.CDN, "Fastly CDN"),
    ("199.232.", ProviderType.CDN, "Fastly CDN"),
    ("104.16.",  ProviderType.CDN, "Cloudflare CDN"),
    ("104.17.",  ProviderType.CDN, "Cloudflare CDN"),
    ("104.18.",  ProviderType.CDN, "Cloudflare CDN"),
    ("104.19.",  ProviderType.CDN, "Cloudflare CDN"),
    ("104.20.",  ProviderType.CDN, "Cloudflare CDN"),
    ("172.67.",  ProviderType.CDN, "Cloudflare CDN"),
    ("172.64.",  ProviderType.CDN, "Cloudflare CDN"),

    # ── Developer services ──
    ("140.82.", ProviderType.DEVELOPER, "GitHub"),
    ("192.30.", ProviderType.DEVELOPER, "GitHub"),
    ("185.199.", ProviderType.DEVELOPER, "GitHub Pages"),

    # ── AI / ML API services ──
    ("162.159.", ProviderType.AI_SERVICE, "Cloudflare / AI API Proxy"),
    ("104.21.",  ProviderType.AI_SERVICE, "Cloudflare / AI API Proxy"),

    # ── Known malicious ASN ranges (examples — expand for production) ──
    # These lower the evidence threshold (easier to block)
    ("185.220.", ProviderType.KNOWN_MALICIOUS, "Tor Exit Node Range"),
    ("194.165.", ProviderType.KNOWN_MALICIOUS, "Known Malicious Hosting"),
    ("45.142.",  ProviderType.KNOWN_MALICIOUS, "Known Botnet Hosting"),
    ("91.108.",  ProviderType.KNOWN_MALICIOUS, "Known Abuse Range"),
]

# ─────────────────────────────────────────────────────────────────────────────
# Threshold tables — how much evidence is required per provider type
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class BlockThresholds:
    """
    Minimum evidence requirements before each escalation stage fires.
    Higher values = harder to block (fewer false positives).
    Lower values  = easier to block (for known-bad providers).
    """
    # Minimum ML confidence score before it contributes to scoring
    ml_min_confidence: float       = 0.60

    # Minimum number of repeated anomalous events before any action
    min_repeat_count: int          = 3

    # Minimum persistence window (seconds) showing repeated behaviour
    min_persistence_secs: float    = 30.0

    # Minimum correlation confidence (0-100) for TEMPORARY_BLOCK
    temp_block_correlation: float  = 70.0

    # Minimum correlation confidence for PERMANENT_BLOCK
    perm_block_correlation: float  = 85.0

    # Number of independent indicator types required before Stage 3
    min_indicator_types: int       = 2

    # Whether a single ML burst can advance stage (always False for CDN/Cloud)
    single_ml_burst_allowed: bool  = False

    # Whether a single packet rate spike alone can advance stage
    single_rate_spike_allowed: bool = False

    # Additional repeat multiplier applied on top of base thresholds
    # e.g. CDN = 2.0 means everything needs to be seen 2× as many times
    repeat_multiplier: float       = 1.0


# Per-provider-type threshold profiles
_THRESHOLDS: dict[ProviderType, BlockThresholds] = {

    ProviderType.UNKNOWN: BlockThresholds(
        ml_min_confidence     = 0.55,
        min_repeat_count      = 3,
        min_persistence_secs  = 20.0,
        temp_block_correlation= 65.0,
        perm_block_correlation= 80.0,
        min_indicator_types   = 2,
        repeat_multiplier     = 1.0,
    ),

    ProviderType.ISP: BlockThresholds(
        ml_min_confidence     = 0.55,
        min_repeat_count      = 3,
        min_persistence_secs  = 20.0,
        temp_block_correlation= 65.0,
        perm_block_correlation= 80.0,
        min_indicator_types   = 2,
        repeat_multiplier     = 1.0,
    ),

    ProviderType.CORPORATE: BlockThresholds(
        ml_min_confidence     = 0.60,
        min_repeat_count      = 4,
        min_persistence_secs  = 30.0,
        temp_block_correlation= 70.0,
        perm_block_correlation= 85.0,
        min_indicator_types   = 2,
        repeat_multiplier     = 1.2,
    ),

    ProviderType.DEVELOPER: BlockThresholds(
        ml_min_confidence     = 0.65,
        min_repeat_count      = 5,
        min_persistence_secs  = 45.0,
        temp_block_correlation= 75.0,
        perm_block_correlation= 88.0,
        min_indicator_types   = 3,
        single_ml_burst_allowed= False,
        repeat_multiplier     = 1.5,
    ),

    ProviderType.AI_SERVICE: BlockThresholds(
        ml_min_confidence     = 0.70,
        min_repeat_count      = 6,
        min_persistence_secs  = 60.0,
        temp_block_correlation= 78.0,
        perm_block_correlation= 90.0,
        min_indicator_types   = 3,
        single_ml_burst_allowed= False,
        single_rate_spike_allowed= False,
        repeat_multiplier     = 1.8,
    ),

    ProviderType.CLOUD: BlockThresholds(
        ml_min_confidence     = 0.70,
        min_repeat_count      = 6,
        min_persistence_secs  = 60.0,
        temp_block_correlation= 80.0,
        perm_block_correlation= 92.0,
        min_indicator_types   = 3,
        single_ml_burst_allowed= False,
        single_rate_spike_allowed= False,
        repeat_multiplier     = 2.0,
    ),

    ProviderType.CDN: BlockThresholds(
        ml_min_confidence     = 0.72,
        min_repeat_count      = 7,
        min_persistence_secs  = 90.0,
        temp_block_correlation= 82.0,
        perm_block_correlation= 93.0,
        min_indicator_types   = 4,
        single_ml_burst_allowed= False,
        single_rate_spike_allowed= False,
        repeat_multiplier     = 2.5,
    ),

    # Known-bad ranges have LOWER thresholds — easier to block
    ProviderType.KNOWN_MALICIOUS: BlockThresholds(
        ml_min_confidence     = 0.40,
        min_repeat_count      = 1,
        min_persistence_secs  = 5.0,
        temp_block_correlation= 50.0,
        perm_block_correlation= 65.0,
        min_indicator_types   = 1,
        single_ml_burst_allowed= True,
        single_rate_spike_allowed= True,
        repeat_multiplier     = 0.5,
    ),
}


# ─────────────────────────────────────────────────────────────────────────────
# TrustProfile — per-IP computed trust profile
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class TrustProfile:
    ip:            str
    provider_type: ProviderType    = ProviderType.UNKNOWN
    provider_name: str             = "Unknown"
    thresholds:    BlockThresholds = field(default_factory=BlockThresholds)

    # Dynamic modifiers updated from traffic history
    _incident_count: int   = field(default=0, repr=False)
    _last_incident_ts: float = field(default=0.0, repr=False)
    _confirmed_malicious: bool = field(default=False, repr=False)

    def record_confirmed_incident(self):
        """Call when an operator confirms a block was warranted."""
        self._incident_count += 1
        self._last_incident_ts = time.monotonic()
        if self._incident_count >= 3:
            self._confirmed_malicious = True

    @property
    def effective_repeat_multiplier(self) -> float:
        """
        If an IP from a trusted provider has been previously confirmed
        malicious, progressively lower its protection.
        """
        if self._confirmed_malicious:
            return max(self.thresholds.repeat_multiplier * 0.3, 0.5)
        if self._incident_count > 0:
            reduction = 0.15 * self._incident_count
            return max(self.thresholds.repeat_multiplier - reduction, 0.7)
        return self.thresholds.repeat_multiplier

    def effective_min_repeat(self) -> int:
        base = self.thresholds.min_repeat_count
        return max(1, int(base * self.effective_repeat_multiplier))

    def effective_temp_block_corr(self) -> float:
        base = self.thresholds.temp_block_correlation
        if self._confirmed_malicious:
            return max(base * 0.7, 50.0)
        return base

    def effective_perm_block_corr(self) -> float:
        base = self.thresholds.perm_block_correlation
        if self._confirmed_malicious:
            return max(base * 0.8, 65.0)
        return base

    def meets_block_threshold(self, evidence: dict) -> bool:
        """
        Evaluate whether the given evidence dict is sufficient to justify
        a blocking action for this IP.

        evidence dict keys (all optional):
            repeat_count      int   — how many times anomalous behaviour seen
            persistence_secs  float — duration of anomalous activity
            correlation_conf  float — 0-100 correlation engine confidence
            ml_score          float — 0-1 fused ML anomaly probability
            indicator_types   int   — number of independent indicator types
            protocol_abuse    bool  — true if protocol anomaly detected
            scan_behaviour    bool  — true if scanning behaviour confirmed
        """
        # ── Rule 1: ML score alone is NEVER enough ──
        ml_score = float(evidence.get("ml_score", 0))
        only_ml  = (
            evidence.get("repeat_count", 0) <= 1
            and not evidence.get("protocol_abuse", False)
            and not evidence.get("scan_behaviour", False)
            and evidence.get("indicator_types", 0) <= 1
        )
        if only_ml:
            return False

        # ── Rule 2: Persistence check ──
        persistence = float(evidence.get("persistence_secs", 0))
        if persistence < self.thresholds.min_persistence_secs:
            return False

        # ── Rule 3: Repeat count ──
        repeat = int(evidence.get("repeat_count", 0))
        if repeat < self.effective_min_repeat():
            return False

        # ── Rule 4: Correlation confidence ──
        corr_conf = float(evidence.get("correlation_conf", 0))
        if corr_conf < self.effective_temp_block_corr():
            return False

        # ── Rule 5: Indicator diversity ──
        ind_types = int(evidence.get("indicator_types", 0))
        if ind_types < self.thresholds.min_indicator_types:
            return False

        return True

    def meets_permanent_block_threshold(self, evidence: dict) -> bool:
        """Stricter check for permanent blocks."""
        if not self.meets_block_threshold(evidence):
            return False
        corr_conf = float(evidence.get("correlation_conf", 0))
        return corr_conf >= self.effective_perm_block_corr()

    def recommended_stage(self, evidence: dict) -> EscalationStage:
        """
        Determine the appropriate escalation stage given current evidence.
        """
        repeat = int(evidence.get("repeat_count", 0))
        corr   = float(evidence.get("correlation_conf", 0))
        persist = float(evidence.get("persistence_secs", 0))

        if self.meets_permanent_block_threshold(evidence):
            return EscalationStage.PERMANENT_BLOCK

        if self.meets_block_threshold(evidence):
            return EscalationStage.TEMPORARY_BLOCK

        # Stage 2: some indicators but not enough for enforcement
        has_some_indicators = (
            repeat >= max(1, self.effective_min_repeat() // 2)
            or corr >= self.effective_temp_block_corr() * 0.75
            or persist >= self.thresholds.min_persistence_secs * 0.5
        )
        if has_some_indicators:
            return EscalationStage.INCREASE_MONITOR

        return EscalationStage.MONITOR

    def summary(self) -> dict:
        return {
            "ip":                  self.ip,
            "provider_type":       self.provider_type.value,
            "provider_name":       self.provider_name,
            "block_threshold":     self._threshold_label(),
            "min_repeat_required": self.effective_min_repeat(),
            "temp_block_corr_req": round(self.effective_temp_block_corr(), 1),
            "perm_block_corr_req": round(self.effective_perm_block_corr(), 1),
            "confirmed_malicious": self._confirmed_malicious,
            "past_incidents":      self._incident_count,
        }

    def _threshold_label(self) -> str:
        labels = {
            ProviderType.UNKNOWN:         "medium",
            ProviderType.ISP:             "medium",
            ProviderType.CORPORATE:       "medium-high",
            ProviderType.DEVELOPER:       "high",
            ProviderType.AI_SERVICE:      "very high",
            ProviderType.CLOUD:           "very high",
            ProviderType.CDN:             "very high",
            ProviderType.KNOWN_MALICIOUS: "low",
        }
        return labels.get(self.provider_type, "medium")


# ─────────────────────────────────────────────────────────────────────────────
# Provider classification
# ─────────────────────────────────────────────────────────────────────────────

def classify_provider(ip: str) -> tuple[ProviderType, str]:
    """
    Classify an IP address into a ProviderType.
    Returns (ProviderType, display_name).
    Uses prefix matching — extend _PROVIDER_PREFIXES for production.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ProviderType.UNKNOWN, "Unknown"

    # Private IPs should never reach the trust scorer (firewall_enforcer
    # guards these), but handle gracefully just in case.
    if addr.is_private or addr.is_loopback:
        return ProviderType.CORPORATE, "Private Network"

    for prefix, ptype, name in _PROVIDER_PREFIXES:
        if ip.startswith(prefix):
            return ptype, name

    return ProviderType.UNKNOWN, "Unknown"


# ─────────────────────────────────────────────────────────────────────────────
# Profile cache
# ─────────────────────────────────────────────────────────────────────────────

_profile_cache: dict[str, TrustProfile] = {}
_cache_lock = threading.Lock()
_CACHE_TTL  = 3600   # seconds — profiles are refreshed hourly


def get_trust_profile(ip: str) -> TrustProfile:
    """
    Return the TrustProfile for an IP.  Cached for _CACHE_TTL seconds.
    Thread-safe.
    """
    with _cache_lock:
        profile = _profile_cache.get(ip)
        if profile is not None:
            return profile

        ptype, pname = classify_provider(ip)
        thresholds   = _THRESHOLDS.get(ptype, BlockThresholds())
        profile = TrustProfile(
            ip            = ip,
            provider_type = ptype,
            provider_name = pname,
            thresholds    = thresholds,
        )
        _profile_cache[ip] = profile
        return profile


def invalidate_profile(ip: str):
    """Remove a cached profile so it is recomputed on next access."""
    with _cache_lock:
        _profile_cache.pop(ip, None)


def record_confirmed_incident(ip: str):
    """
    Call when an operator confirms an incident / block was legitimate.
    This progressively lowers the threshold for that IP even if it belongs
    to a trusted provider.
    """
    profile = get_trust_profile(ip)
    profile.record_confirmed_incident()
    log.info(f"[TRUST] Confirmed incident recorded for {ip} "
             f"(provider={profile.provider_name}, "
             f"count={profile._incident_count})")


# ─────────────────────────────────────────────────────────────────────────────
# Evidence builder helper
# ─────────────────────────────────────────────────────────────────────────────

def build_evidence_from_alert(alert: dict) -> dict:
    """
    Convert a PacketGuard alert dict into a normalised evidence dict
    suitable for TrustProfile.meets_block_threshold().
    """
    atype = alert.get("alert_type", "")
    info  = alert.get("additional_info") or {}
    conf  = float(alert.get("confidence", 0))
    sev   = alert.get("severity", "LOW")

    indicator_types = 0
    if "PORT_SCAN"  in atype: indicator_types += 1
    if "SYN_FLOOD"  in atype: indicator_types += 1
    if "HIGH_RATE"  in atype or "DDOS" in atype: indicator_types += 1
    if "ML_"        in atype: indicator_types += 1
    if "ABNORMAL"   in atype: indicator_types += 1

    return {
        "repeat_count":     int(info.get("repeat_count", 1)),
        "persistence_secs": float(info.get("window_seconds", 0)),
        "correlation_conf": 0.0,   # filled by correlation engine
        "ml_score":         conf if "ML_" in atype else 0.0,
        "indicator_types":  indicator_types,
        "protocol_abuse":   "SYN_FLOOD" in atype,
        "scan_behaviour":   "PORT_SCAN" in atype,
    }


def build_evidence_from_incident(incident: dict) -> dict:
    """
    Convert a PacketGuard correlation incident into an evidence dict.
    """
    ev = incident.get("evidence", {})
    indicator_types = sum([
        bool(ev.get("port_scan")),
        bool(ev.get("syn_flood")),
        bool(ev.get("high_rate")),
        bool(ev.get("ml_anomaly")),
        bool(ev.get("ml_burst")),
    ])
    return {
        "repeat_count":     int(incident.get("event_count", 1)),
        "persistence_secs": float(incident.get("duration_s", 0)),
        "correlation_conf": float(incident.get("confidence", 0)),
        "ml_score":         0.0,   # ML is one input, not the decider
        "indicator_types":  indicator_types,
        "protocol_abuse":   bool(ev.get("syn_flood")),
        "scan_behaviour":   bool(ev.get("port_scan")),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Convenience function used by block_manager and correlation engine
# ─────────────────────────────────────────────────────────────────────────────

def should_escalate(ip: str, evidence: dict) -> EscalationStage:
    """
    Top-level entry point: given an IP and evidence dict, return the
    recommended EscalationStage.

    This is the function all other modules should call before deciding
    whether to block.
    """
    profile = get_trust_profile(ip)
    stage   = profile.recommended_stage(evidence)

    log.debug(
        f"[TRUST] {ip} ({profile.provider_name}) → "
        f"stage={stage.name} | "
        f"repeat={evidence.get('repeat_count',0)} "
        f"corr={evidence.get('correlation_conf',0):.0f}% "
        f"persist={evidence.get('persistence_secs',0):.0f}s "
        f"indicators={evidence.get('indicator_types',0)}"
    )
    return stage
