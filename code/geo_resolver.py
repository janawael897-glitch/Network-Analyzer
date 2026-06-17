"""
geo_resolver.py — PacketGuard
Resolves IP addresses to country / city / ISP / lat-lon.

Resolution order (no registration required for any step):
  1. In-memory + disk cache (24 h TTL, survives restarts)
  2. Local .mmdb database — db-ip.com free download, no account needed
     OR MaxMind GeoLite2-City.mmdb if you have one
  3. ip-api.com  — no API key, 1 000 req/min (primary online fallback)
  4. ipapi.co    — no API key, 1 000 req/day  (secondary online fallback)

To enable offline mode (optional, no registration):
  1. Go to: https://db-ip.com/db/download/ip-to-city-lite
  2. Select MMDB format, click Download (no account needed)
  3. Extract the .gz file — you get dbip-city-lite-YYYY-MM.mmdb
  4. Rename it to: GeoLite2-City.mmdb
  5. Place it at: <project-root>/GeoLite2-City.mmdb
  6. pip install geoip2
  7. Restart app.py — dashboard badge shows "db-ip offline"
"""

import glob
import json
import os
import time
import threading

# Project root is one level above this file (code/)
BASE_DIR    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_CACHE_FILE = os.path.join(BASE_DIR, "geo_cache.json")
_CACHE_TTL  = 86400   # 24 h
_CACHE_LOCK = threading.Lock()

# Accept any .mmdb file in the project root so both MaxMind and db-ip work
def _find_mmdb() -> str | None:
    patterns = [
        os.path.join(BASE_DIR, "GeoLite2-City.mmdb"),
        os.path.join(BASE_DIR, "GeoLite2-*.mmdb"),
        os.path.join(BASE_DIR, "dbip-city-lite-*.mmdb"),
        os.path.join(BASE_DIR, "*.mmdb"),
    ]
    for pattern in patterns:
        matches = glob.glob(pattern)
        if matches:
            return matches[0]
    return None


# ---------------------------------------------------------------------------
# Private IP check
# ---------------------------------------------------------------------------

def is_private(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return True
    try:
        a, b = int(parts[0]), int(parts[1])
        return (a == 10 or a == 127
                or (a == 172 and 16 <= b <= 31)
                or (a == 192 and b == 168)
                or (a == 169 and b == 254))
    except Exception:
        return True


# ---------------------------------------------------------------------------
# Persistent cache
# ---------------------------------------------------------------------------

def _load_cache() -> tuple[dict, dict]:
    try:
        with open(_CACHE_FILE, "r", encoding="utf-8") as f:
            raw = json.load(f)
        return ({k: v["info"] for k, v in raw.items()},
                {k: v["ts"]   for k, v in raw.items()})
    except Exception:
        return {}, {}


def _save_cache(info_map: dict, ts_map: dict) -> None:
    try:
        payload = {ip: {"info": info_map[ip], "ts": ts_map[ip]} for ip in info_map}
        tmp = _CACHE_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f)
        os.replace(tmp, _CACHE_FILE)
    except Exception:
        pass


_geo_cache, _geo_cache_ts = _load_cache()


# ---------------------------------------------------------------------------
# MMDB reader (MaxMind GeoLite2 or db-ip.com — same geoip2 library)
# ---------------------------------------------------------------------------

_mmdb_reader      = None
_mmdb_reader_lock = threading.Lock()
_mmdb_path_used   = None


def _get_mmdb_reader():
    global _mmdb_reader, _mmdb_path_used
    if _mmdb_reader is not None:
        return _mmdb_reader
    mmdb = _find_mmdb()
    if not mmdb:
        return None
    with _mmdb_reader_lock:
        if _mmdb_reader is not None:
            return _mmdb_reader
        try:
            import geoip2.database  # type: ignore
            _mmdb_reader    = geoip2.database.Reader(mmdb)
            _mmdb_path_used = mmdb
            return _mmdb_reader
        except Exception:
            return None


def _resolve_with_mmdb(ip: str) -> dict | None:
    reader = _get_mmdb_reader()
    if reader is None:
        return None
    try:
        r    = reader.city(ip)
        name = os.path.basename(_mmdb_path_used or "")
        src  = "db-ip" if "dbip" in name.lower() else "maxmind"
        return {
            "country":     r.country.name or "Unknown",
            "countryCode": r.country.iso_code or "",
            "city":        r.city.name or "",
            "lat":         float(r.location.latitude  or 0),
            "lon":         float(r.location.longitude or 0),
            "isp":         (getattr(r.traits, "autonomous_system_organization", None)
                            or getattr(r.traits, "isp", None) or ""),
            "source":      src,
        }
    except Exception:
        return None


# ---------------------------------------------------------------------------
# ip-api.com  (no key, 1 000 req/min, primary online fallback)
# ---------------------------------------------------------------------------

def _resolve_with_ipapi_com(ip: str) -> dict | None:
    import urllib.request
    try:
        url  = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,lat,lon,isp,org"
        req  = urllib.request.Request(url, headers={"User-Agent": "PacketGuard/1.0"})
        resp = urllib.request.urlopen(req, timeout=5)
        geo  = json.loads(resp.read().decode())
        if geo.get("status") == "success":
            return {
                "country":     geo.get("country", "Unknown"),
                "countryCode": geo.get("countryCode", ""),
                "city":        geo.get("city", ""),
                "lat":         geo.get("lat", 0),
                "lon":         geo.get("lon", 0),
                "isp":         geo.get("isp") or geo.get("org", ""),
                "source":      "ip-api.com",
            }
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# ipapi.co  (no key, 1 000 req/day, secondary online fallback)
# ---------------------------------------------------------------------------

def _resolve_with_ipapiCo(ip: str) -> dict | None:
    import urllib.request
    try:
        url  = f"https://ipapi.co/{ip}/json/"
        req  = urllib.request.Request(url, headers={"User-Agent": "PacketGuard/1.0"})
        resp = urllib.request.urlopen(req, timeout=5)
        geo  = json.loads(resp.read().decode())
        if geo.get("latitude") and not geo.get("error"):
            return {
                "country":     geo.get("country_name", "Unknown"),
                "countryCode": geo.get("country_code", ""),
                "city":        geo.get("city", ""),
                "lat":         geo.get("latitude",  0),
                "lon":         geo.get("longitude", 0),
                "isp":         geo.get("org", ""),
                "source":      "ipapi.co",
            }
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_LOCAL_GEO = {
    "country": "Local Network", "countryCode": "LO",
    "city": "Private IP", "lat": 0, "lon": 0, "isp": "Internal",
    "source": "local",
}

_FAILED_GEO = {
    "country": "Unknown", "countryCode": "",
    "city": "", "lat": 0, "lon": 0, "isp": "", "source": "failed",
}


def resolve_geo(ip: str) -> dict:
    """
    Return geo dict for ip.  Always returns a complete dict — never raises.
    Keys: country, countryCode, city, lat, lon, isp, source
    """
    if is_private(ip):
        return _LOCAL_GEO.copy()

    with _CACHE_LOCK:
        cached = _geo_cache.get(ip)
        if cached and (time.time() - _geo_cache_ts.get(ip, 0)) < _CACHE_TTL:
            result = dict(cached)
            result["source"] = "cache"
            return result

    info = (_resolve_with_mmdb(ip)
            or _resolve_with_ipapi_com(ip)
            or _resolve_with_ipapiCo(ip)
            or _FAILED_GEO.copy())

    with _CACHE_LOCK:
        _geo_cache[ip]    = info
        _geo_cache_ts[ip] = time.time()
        _save_cache(_geo_cache, _geo_cache_ts)

    return info


def geo_source() -> str:
    """Human-readable name of the active primary source."""
    reader = _get_mmdb_reader()
    if reader is None:
        return "ip-api.com"
    name = os.path.basename(_mmdb_path_used or "")
    return "db-ip offline" if "dbip" in name.lower() else "maxmind offline"
