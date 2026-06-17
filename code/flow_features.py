"""
flow_features.py — PacketGuard
Extracts ML-ready feature vectors from completed flow records.
Bridges flow_builder output → existing ML engine input format.

The ML detector in this codebase (ml_detector.py) uses a 10-feature
Isolation Forest trained on the following keys (see FEATURE_NAMES there):

    packet_size, is_tcp, is_udp, is_icmp,
    dst_port, src_port, is_syn, is_fin, is_rst,
    payload_size

Flows from FlowBuilder carry aggregated statistics rather than per-packet
flags, so we map the closest meaningful fields and zero-fill the rest.
"""

# ── All feature keys the ML detector expects ─────────────────────────
ML_FEATURE_KEYS = [
    "packet_size",
    "is_tcp",
    "is_udp",
    "is_icmp",
    "dst_port",
    "src_port",
    "is_syn",
    "is_fin",
    "is_rst",
    "payload_size",
]

# Safe defaults for any key the flow data cannot supply
_DEFAULTS = {k: 0 for k in ML_FEATURE_KEYS}


def extract_features(flow: dict) -> dict:
    """
    Convert a completed flow dict (from FlowBuilder) into the feature dict
    the ML detector expects.

    Mapping rationale
    -----------------
    packet_size  → avg_packet_size  (closest scalar representation of size)
    is_tcp       → 1 if protocol == 'TCP'
    is_udp       → 1 if protocol == 'UDP'
    is_icmp      → 1 if protocol == 'ICMP'
    dst_port     → dst_port
    src_port     → src_port
    is_syn       → 0  (aggregated flows don't carry per-packet TCP flags)
    is_fin       → 0
    is_rst       → 0
    payload_size → byte_count (total bytes transferred; best proxy for payload)
    """
    proto = str(flow.get("protocol", "")).upper()

    return {
        "packet_size":  float(flow.get("avg_packet_size", 0) or 0),
        "is_tcp":       1 if proto == "TCP"  else 0,
        "is_udp":       1 if proto == "UDP"  else 0,
        "is_icmp":      1 if proto == "ICMP" else 0,
        "dst_port":     int(flow.get("dst_port", 0) or 0),
        "src_port":     int(flow.get("src_port", 0) or 0),
        "is_syn":       0,   # not available at flow level
        "is_fin":       0,
        "is_rst":       0,
        "payload_size": float(flow.get("byte_count", 0) or 0),
    }


def flow_to_ml_input(flow: dict) -> dict:
    """
    Same as extract_features but guarantees that EVERY key the ML model
    expects is present, filling missing entries with safe defaults (0).
    This prevents KeyError / NaN crashes in the detector.
    """
    features = dict(_DEFAULTS)          # start with safe defaults
    features.update(extract_features(flow))  # overwrite with actual values
    return features


def flow_to_log_row(flow: dict) -> dict:
    """
    Human-readable summary of a flow suitable for logging or CSV export.
    All values are plain Python scalars (str / int / float).
    """
    return {
        "flow_id":         str(flow.get("flow_id",         "")),
        "start_time":      str(flow.get("start_time",      "")),
        "end_time":        str(flow.get("end_time",        "")),
        "duration":        round(float(flow.get("duration",        0) or 0), 6),
        "src_ip":          str(flow.get("src_ip",          "")),
        "src_port":        int(flow.get("src_port",        0) or 0),
        "dst_ip":          str(flow.get("dst_ip",          "")),
        "dst_port":        int(flow.get("dst_port",        0) or 0),
        "protocol":        str(flow.get("protocol",        "")),
        "packet_count":    int(flow.get("packet_count",    0) or 0),
        "byte_count":      int(flow.get("byte_count",      0) or 0),
        "avg_packet_size": round(float(flow.get("avg_packet_size", 0) or 0), 2),
        "packets_per_sec": round(float(flow.get("packets_per_sec", 0) or 0), 4),
        "bytes_per_sec":   round(float(flow.get("bytes_per_sec",   0) or 0), 4),
        "direction":       str(flow.get("direction",       "forward")),
    }
