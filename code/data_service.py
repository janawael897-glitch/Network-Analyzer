"""
data_service.py — PacketGuard Data Loading Service
Alerts are stored in SQLite (alerts table).
All other data (devices, live state, ML alerts) unchanged.
"""

import json
import os
import sqlite3
from datetime import datetime, timezone

from config import (
    ML_ALERTS_FILE, DEVICES_FILE, BASE_DIR,
)

DB_PATH = os.path.join(BASE_DIR, "packetguard.db")

# ── Model directory ────────────────────────────────────────────────
def _find_models_dir():
    candidates = [
        os.path.join(BASE_DIR, "models"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "models"),
        os.path.join(os.getcwd(), "models"),
    ]
    for d in candidates:
        if os.path.isdir(d):
            return d
    return candidates[0]

MODELS_DIR = _find_models_dir()


# ── DB helpers ─────────────────────────────────────────────────────
def _get_db():
    conn = sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def _read_json(path, default=None):
    for _ in range(3):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except json.JSONDecodeError:
            import time; time.sleep(0.05)
        except Exception:
            break
    return default if default is not None else []


# ── Alert helpers ──────────────────────────────────────────────────
def _row_to_alert(row) -> dict:
    """Convert a DB row to the alert dict shape the dashboard expects."""
    d = dict(row)
    # Parse additional_info JSON
    try:
        d["additional_info"] = json.loads(d.get("additional_info") or "{}")
    except Exception:
        d["additional_info"] = {}
    return d


def push_alert(alert: dict, is_ml: bool = False) -> bool:
    """Insert a single alert into the DB. Returns True on success."""
    try:
        conn = _get_db()
        info = alert.get("additional_info")
        conn.execute(
            """INSERT OR IGNORE INTO alerts
               (alert_id, alert_type, severity, source_ip, destination_ip,
                destination_port, protocol, message, timestamp, additional_info, is_ml)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (
                alert.get("alert_id") or alert.get("id"),
                alert.get("alert_type", "UNKNOWN"),
                alert.get("severity", "LOW"),
                alert.get("source_ip"),
                alert.get("destination_ip"),
                alert.get("destination_port"),
                alert.get("protocol"),
                alert.get("message"),
                alert.get("timestamp", datetime.now(timezone.utc).isoformat()),
                json.dumps(info, default=str) if isinstance(info, dict) else (info or "{}"),
                1 if is_ml else 0,
            )
        )
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"[DATA_SERVICE] push_alert error: {e}")
        return False


def push_live_stats(stats: dict) -> bool:
    """Write live stats to the live_state SQLite table."""
    try:
        conn = _get_db()
        try:
            conn.execute("""
                INSERT OR REPLACE INTO live_state
                (id, total_packets, bytes_total, packets_per_sec, bytes_per_sec,
                 runtime_seconds, running, protocols, top_ips,
                 ml_total, ml_detections, ml_recent_alerts, interface, last_updated)
                VALUES (1,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                stats.get("total_packets", 0),
                stats.get("bytes_total", 0),
                stats.get("packets_per_sec", stats.get("rate", 0.0)),
                stats.get("bytes_per_sec", 0.0),
                stats.get("runtime_seconds", 0),
                1 if stats.get("running") else 0,
                json.dumps(stats.get("protocols", {}), default=str),
                json.dumps(stats.get("top_ips", {}), default=str),
                stats.get("ml_total", 0),
                stats.get("ml_detections", 0),
                json.dumps(stats.get("ml_recent_alerts", []), default=str),
                stats.get("interface"),
                datetime.now(timezone.utc).isoformat(),
            ))
            conn.commit()
        finally:
            conn.close()
        return True
    except Exception as e:
        print(f"[DATA_SERVICE] push_live_stats error: {e}")
        return False


def total_alert_count() -> int:
    """Return total number of alerts in DB."""
    try:
        conn = _get_db()
        count = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        conn.close()
        return count
    except Exception:
        return 0


def load_alerts(limit: int = 5000) -> list:
    """Return the most recent alerts from DB, newest first."""
    try:
        conn = _get_db()
        rows = conn.execute(
            "SELECT * FROM alerts WHERE is_ml=0 ORDER BY timestamp DESC LIMIT ?",
            (limit,)
        ).fetchall()
        conn.close()
        return [_row_to_alert(r) for r in rows]
    except Exception as e:
        print(f"[DATA_SERVICE] load_alerts error: {e}")
        return []


def load_alerts_by_date(date_str: str) -> list:
    """Return all alerts (heuristic + ML) for a specific date (YYYY-MM-DD), newest first."""
    try:
        conn = _get_db()
        rows = conn.execute(
            "SELECT * FROM alerts WHERE date(timestamp) = ? ORDER BY timestamp DESC",
            (date_str,)
        ).fetchall()
        conn.close()
        return [_row_to_alert(r) for r in rows]
    except Exception as e:
        print(f"[DATA_SERVICE] load_alerts_by_date error: {e}")
        return []


def load_ml_alerts(limit: int = 5000) -> list:
    """Return ML-generated alerts from DB."""
    try:
        conn = _get_db()
        rows = conn.execute(
            "SELECT * FROM alerts WHERE is_ml=1 ORDER BY timestamp DESC LIMIT ?",
            (limit,)
        ).fetchall()
        conn.close()
        return [_row_to_alert(r) for r in rows]
    except Exception as e:
        print(f"[DATA_SERVICE] load_ml_alerts error: {e}")
        # Fallback to file
        return _read_json(ML_ALERTS_FILE, [])


def load_devices() -> dict:
    return _read_json(DEVICES_FILE, {
        "scan_time": None, "local_ip": "N/A",
        "network_range": "N/A", "total_found": 0, "devices": []
    })


def _live_stats_defaults() -> dict:
    return {
        "packets": 0, "total_packets": 0, "rate": 0.0,
        "packets_per_sec": 0.0, "bytes_total": 0, "bytes_per_sec": 0.0,
        "runtime_seconds": 0, "running": False, "protocols": {}, "top_ips": {},
        "recent_alerts": [], "alerts_total": total_alert_count(),
        "ml_total": 0, "ml_detections": 0, "ml_recent_alerts": [],
        "interface": None, "last_updated": None,
    }


def load_live_stats() -> dict:
    """Read live capture stats from the SQLite live_state table."""
    try:
        conn = _get_db()
        try:
            row = conn.execute("SELECT * FROM live_state WHERE id=1").fetchone()
        finally:
            conn.close()
        if not row:
            return _live_stats_defaults()

        def _j(v, default):
            try:
                return json.loads(v) if v else default
            except Exception:
                return default

        return {
            "packets":          row["total_packets"],
            "total_packets":    row["total_packets"],
            "rate":             row["packets_per_sec"],
            "packets_per_sec":  row["packets_per_sec"],
            "bytes_total":      row["bytes_total"],
            "bytes_per_sec":    row["bytes_per_sec"],
            "runtime_seconds":  row["runtime_seconds"],
            "running":          bool(row["running"]),
            "protocols":        _j(row["protocols"], {}),
            "top_ips":          _j(row["top_ips"], {}),
            "recent_alerts":    [],
            "alerts_total":     total_alert_count(),
            "ml_total":         row["ml_total"],
            "ml_detections":    row["ml_detections"],
            "ml_recent_alerts": _j(row["ml_recent_alerts"], []),
            "interface":        row["interface"],
            "last_updated":     row["last_updated"],
        }
    except Exception as e:
        print(f"[DATA_SERVICE] load_live_stats error: {e}")
        return _live_stats_defaults()


def load_model_info() -> dict:
    models_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")
    if not os.path.isdir(models_dir):
        models_dir = os.path.join(BASE_DIR, "models")

    required = ["ensemble_model.pkl", "xgb_model.pkl", "rf_model.pkl", "iso_model.pkl"]
    trained  = all(os.path.exists(os.path.join(models_dir, m)) for m in required)

    info = {
        "trained":        trained,
        "samples":        2016638,
        "precision":      0.9988,
        "recall":         0.9988,
        "f1":             0.9988,
        "accuracy":       0.9988,
        "winner_model":   "Ensemble (RF + XGBoost)",
        "cv_f1_mean":     0.9988,
        "cv_f1_std":      0.001,
        "dataset":        "CIC-IDS2017 (2.02M samples, 15 classes)",
        "cicids_trained": True,
        "detector_ready": False,
        "classes": [
            "BENIGN", "Bot", "DDoS", "DoS GoldenEye", "DoS Hulk",
            "DoS Slowhttptest", "DoS slowloris", "FTP-Patator",
            "Heartbleed", "Infiltration", "PortScan", "SSH-Patator",
            "Web Attack Brute Force", "Web Attack Sql Injection", "Web Attack XSS"
        ],
        "per_class_f1": {
            "BENIGN": 1.00, "DDoS": 1.00, "DoS Hulk": 1.00,
            "DoS GoldenEye": 1.00, "FTP-Patator": 1.00,
            "SSH-Patator": 1.00, "Infiltration": 1.00,
            "DoS slowloris": 0.99, "DoS Slowhttptest": 0.99,
            "PortScan": 0.99, "Bot": 0.82,
            "Web Attack Brute Force": 0.80, "Heartbleed": 0.67,
            "Web Attack Sql Injection": 0.67, "Web Attack XSS": 0.49,
        },
        "models": {
            "ensemble":         {"accuracy": 0.9988, "f1": 0.9988},
            "xgboost":          {"accuracy": 0.9986, "f1": 0.9987},
            "random_forest":    {"accuracy": 0.9941, "f1": 0.9958},
            "isolation_forest": {"accuracy": 0.8223, "f1": 0.8031},
        },
        "models_loaded": [m.replace(".pkl","").replace("_model","")
                          for m in required
                          if os.path.exists(os.path.join(models_dir, m))],
    }

    try:
        from ml_detector import get_detector
        det = get_detector()
        if det and det.ready:
            info["detector_ready"]  = True
            info["detector_models"] = det.status().get("models_loaded", 0)
    except Exception:
        pass

    return info
