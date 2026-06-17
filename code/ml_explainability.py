#!/usr/bin/env python3
"""
<<<<<<< HEAD
ml_explainability.py — PacketGuard ML Alert Explainability
=======
ml_explainability.py - PacketGuard ML Alert Explainability
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
Returns human-readable reasons why a flow was flagged as anomalous.
Exports: explain_alert(alert_dict) -> list[str]
"""


# Common ports considered "normal" for filtering
_COMMON_PORTS = {
    20, 21, 22, 23, 25, 53, 67, 68, 80, 110, 119,
    123, 143, 161, 194, 389, 443, 445, 465, 514,
    587, 636, 993, 995, 1080, 1433, 1521, 3306,
    3389, 5432, 5900, 6379, 8080, 8443, 8888, 27017,
}

_SEV_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def explain_alert(alert: dict) -> list:
    """
    Given an alert dict, return up to 6 human-readable explanation strings
    describing why the flow was flagged.
    """
    reasons = []
    info    = alert.get("additional_info") or {}

<<<<<<< HEAD
    # ── 1. Isolation Forest score ──────────────────────────────
=======
    # -- 1. Isolation Forest score ------------------------------
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
    iso = info.get("iso_score") or info.get("anomaly_score")
    if iso is not None:
        try:
            iso = float(iso)
            if iso < -0.3:
<<<<<<< HEAD
                reasons.append(f"Isolation Forest anomaly score is very low ({iso:.3f}) — highly anomalous flow")
=======
                reasons.append(f"Isolation Forest anomaly score is very low ({iso:.3f}) - highly anomalous flow")
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
            elif iso < -0.1:
                reasons.append(f"Isolation Forest anomaly score ({iso:.3f}) exceeds detection threshold")
        except (ValueError, TypeError):
            pass

<<<<<<< HEAD
    # ── 2. Fused confidence ────────────────────────────────────
=======
    # -- 2. Fused confidence ------------------------------------
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
    conf = info.get("fused_confidence") or info.get("confidence")
    if conf is not None:
        try:
            pct = float(conf) * 100 if float(conf) <= 1 else float(conf)
            if pct >= 85:
                reasons.append(f"High fused model confidence: {pct:.0f}%")
            elif pct >= 65:
                reasons.append(f"Elevated model confidence: {pct:.0f}%")
        except (ValueError, TypeError):
            pass

<<<<<<< HEAD
    # ── 3. Packet rate ─────────────────────────────────────────
=======
    # -- 3. Packet rate -----------------------------------------
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
    pkt_rate = info.get("packet_rate") or info.get("pps")
    if pkt_rate is not None:
        try:
            rate = float(pkt_rate)
            if rate > 1000:
<<<<<<< HEAD
                reasons.append(f"Extremely high packet rate: {rate:.0f} pkt/s — possible flood")
=======
                reasons.append(f"Extremely high packet rate: {rate:.0f} pkt/s - possible flood")
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
            elif rate > 200:
                reasons.append(f"Elevated packet rate: {rate:.0f} pkt/s (above baseline)")
        except (ValueError, TypeError):
            pass

<<<<<<< HEAD
    # ── 4. Byte rate ───────────────────────────────────────────
=======
    # -- 4. Byte rate -------------------------------------------
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
    byte_rate = info.get("byte_rate") or info.get("bps")
    if byte_rate is not None:
        try:
            bps = float(byte_rate)
            if bps > 1_000_000:
<<<<<<< HEAD
                reasons.append(f"High byte rate: {bps/1e6:.1f} MB/s — potential data exfiltration or flood")
=======
                reasons.append(f"High byte rate: {bps/1e6:.1f} MB/s - potential data exfiltration or flood")
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
            elif bps > 100_000:
                reasons.append(f"Elevated byte rate: {bps/1000:.0f} KB/s")
        except (ValueError, TypeError):
            pass

<<<<<<< HEAD
    # ── 5. Unusual destination port ────────────────────────────
=======
    # -- 5. Unusual destination port ----------------------------
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
    dst_port = alert.get("destination_port") or info.get("dst_port")
    if dst_port is not None:
        try:
            port = int(dst_port)
            if port not in _COMMON_PORTS:
<<<<<<< HEAD
                reasons.append(f"Unusual destination port {port} — not a standard service port")
        except (ValueError, TypeError):
            pass

    # ── 6. TCP flag anomaly ────────────────────────────────────
=======
                reasons.append(f"Unusual destination port {port} - not a standard service port")
        except (ValueError, TypeError):
            pass

    # -- 6. TCP flag anomaly ------------------------------------
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
    flags = info.get("tcp_flags") or info.get("flags", "")
    if flags:
        flags_str = str(flags).upper()
        if "SYN" in flags_str and "ACK" not in flags_str:
<<<<<<< HEAD
            reasons.append("SYN-only flood pattern detected — possible SYN flood attack")
        elif "FIN" in flags_str and "ACK" not in flags_str:
            reasons.append("FIN scan pattern detected — possible stealth port scan")
        elif "RST" in flags_str:
            reasons.append("Repeated RST packets — possible connection reset attack")

    # ── 7. Alert type context ──────────────────────────────────
=======
            reasons.append("SYN-only flood pattern detected - possible SYN flood attack")
        elif "FIN" in flags_str and "ACK" not in flags_str:
            reasons.append("FIN scan pattern detected - possible stealth port scan")
        elif "RST" in flags_str:
            reasons.append("Repeated RST packets - possible connection reset attack")

    # -- 7. Alert type context ----------------------------------
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
    atype = alert.get("alert_type", "")
    if not reasons:
        # Fallback: generic reason from the alert type
        if "ML_ANOMALY_BURST" in atype:
            reasons.append("Burst of anomalous flows detected within a short time window")
        elif "ML_ANOMALY" in atype:
            reasons.append("Flow characteristics deviate significantly from learned baseline")
        elif "PORT_SCAN" in atype:
            reasons.append("Sequential connection attempts to multiple ports detected")
        elif "HIGH_PACKET_RATE" in atype:
            reasons.append("Packet rate significantly exceeds the established baseline")
        elif "BRUTE_FORCE" in atype:
            reasons.append("Repeated authentication attempts suggest credential brute-forcing")
        else:
            reasons.append(f"Alert type '{atype}' triggered detection rule")

    return reasons[:6]