"""
utils/helpers.py - PacketGuard Shared Utilities
General-purpose helpers: file I/O, JSON, IP validation, time formatting.
"""

import json
import os
import re
import sys
import time
from datetime import datetime, timezone


# -- JSON file helpers ---------------------------------------------

def read_json(path: str, default=None):
    """Read a JSON file safely. Returns `default` on any error."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default if default is not None else []


def write_json(path: str, data, indent: int = 2) -> bool:
    """
    Write data to a JSON file atomically (temp-file + rename).
    Falls back to direct write on Windows where rename can fail.
    Returns True on success.
    """
    try:
        payload = json.dumps(data, indent=indent, default=str)
        if sys.platform == "win32":
            with open(path, "w", encoding="utf-8") as f:
                f.write(payload)
        else:
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(payload)
            os.replace(tmp, path)
        return True
    except Exception as e:
        print(f"[HELPERS] write_json failed ({path}): {e}")
        return False


def append_json_list(path: str, item: dict, max_items: int = None) -> bool:
    """
    Append one item to a JSON list file.
    Optionally trims to keep only the latest `max_items` entries.
    """
    data = read_json(path, default=[])
    if not isinstance(data, list):
        data = []
    data.append(item)
    if max_items:
        data = data[-max_items:]
    return write_json(path, data)


# -- IP validation -------------------------------------------------

_IP_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)

def is_valid_ip(ip: str) -> bool:
    """Return True if `ip` is a valid IPv4 address."""
    return bool(ip and _IP_RE.match(ip.strip()))


def is_private_ip(ip: str) -> bool:
    """Return True if IP is in a RFC-1918 private range."""
    if not is_valid_ip(ip):
        return False
    parts = list(map(int, ip.split(".")))
    return (
        parts[0] == 10
        or (parts[0] == 172 and 16 <= parts[1] <= 31)
        or (parts[0] == 192 and parts[1] == 168)
    )


# -- Time helpers --------------------------------------------------

def utcnow_iso() -> str:
    """Return current UTC time as ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


def iso_to_ts(iso: str) -> float:
    """Parse ISO-8601 string to Unix timestamp float. Returns 0 on error."""
    try:
        return datetime.fromisoformat(iso).timestamp()
    except Exception:
        return 0.0


def seconds_ago(iso: str) -> float:
    """Return how many seconds ago an ISO timestamp was."""
    return time.time() - iso_to_ts(iso)


# -- Severity helpers ----------------------------------------------

_SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

def sev_rank(severity: str) -> int:
    """Return numeric rank for a severity string (higher = more severe)."""
    return _SEV_RANK.get((severity or "").upper(), 0)


def sev_color(severity: str) -> str:
    """Return a hex color for a severity string."""
    return {
        "CRITICAL": "#ff2d55",
        "HIGH":     "#ff6400",
        "MEDIUM":   "#ffb800",
        "LOW":      "#00c8ff",
        "INFO":     "#6a8aaa",
    }.get((severity or "").upper(), "#6a8aaa")
