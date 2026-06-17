"""
<<<<<<< HEAD
enterprise_bp.py  –  PacketGuard Enterprise REST API  (v3 — Field-shape fix)
=======
enterprise_bp.py  -  PacketGuard Enterprise REST API  (v3 - Field-shape fix)
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
Place in: code/
All routes live under /api/v1/enterprise/

v3 changes vs v2:
  All API responses are normalized to the exact field names the dashboard JS
  expects. The JS was written against a different schema; normalizing here
  means zero JS changes needed.

  JS field expectations  →  what engines actually return:

  /threat-scores:
    JS reads:  ip_address, score, threat_level
    Engine:    ip,         risk_score, tier.label
    → _norm_host() translates

  /incidents:
    JS reads:  incident_id, source_ip, severity, attack_chain, last_seen
<<<<<<< HEAD
    Engine:    same, but 'attack_chain' doesn't exist —
=======
    Engine:    same, but 'attack_chain' doesn't exist -
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
               mapped from 'classification' or 'alert_type'
    → _norm_incident() translates

  /actions (response timeline):
    JS reads:  source_ip, action_type, timestamp, trigger_reason, result
    Engine:    source_ip, action_type, action_time, action_label, description
    → _norm_action() translates

  /summary:
    JS reads:  open_incidents, critical_ips, actions_24h, anomalies_24h
    → returned directly with those key names
"""

import uuid
import datetime
<<<<<<< HEAD
=======
from datetime import timezone as _tz
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
import logging

from flask import Blueprint, jsonify, request

log = logging.getLogger(__name__)

<<<<<<< HEAD
# ── Auth stubs ────────────────────────────────────────────────────
=======
# -- Auth stubs ----------------------------------------------------
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
try:
    from access_control import require_login, require_role
except ImportError:
    def require_login(f):
        return f
<<<<<<< HEAD
    def require_role(r):
=======
    def require_role(*_args, **_kwargs):
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
        def d(f):
            return f
        return d

enterprise_bp = Blueprint("enterprise", __name__, url_prefix="/api/v1/enterprise")


<<<<<<< HEAD
# ══════════════════════════════════════════════════════════════════
# Shape normalisers
# ══════════════════════════════════════════════════════════════════
=======
# ------------------------------------------------------------------
# Shape normalisers
# ------------------------------------------------------------------
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)

def _norm_host(h: dict) -> dict:
    """Engine host dict / host_profiles row → JS threat-score shape."""
    tier = h.get("tier") or {}
    tier_label = (
        tier.get("label", "") if isinstance(tier, dict) else str(tier)
    )
    return {
        "ip_address":     h.get("ip") or h.get("ip_address", ""),
        "score":          round(float(h.get("risk_score") or h.get("score") or 0), 2),
        "threat_level":   tier_label or h.get("threat_level") or h.get("classification") or "",
        "classification": h.get("classification", ""),
        "recurrence":     h.get("recurrence", 0),
        "unique_ports":   h.get("unique_ports", 0),
        "first_seen":     h.get("first_seen", ""),
        "last_seen":      h.get("last_seen", ""),
        "components":     h.get("components", {}),
    }


def _norm_incident(i: dict) -> dict:
    """Correlation engine incident / incidents row → JS incident shape."""
    chain = (
        i.get("attack_chain")
        or i.get("classification")
        or i.get("alert_type")
        or ""
    )
    return {
        "incident_id":      i.get("incident_id", ""),
        "source_ip":        i.get("source_ip", ""),
        "severity":         i.get("severity", "LOW"),
        "attack_chain":     chain,
        "last_seen":        i.get("last_seen", ""),
        "title":            i.get("title", ""),
        "description":      i.get("description", ""),
        "risk_score":       i.get("risk_score", 0),
        "confidence":       i.get("confidence", 0),
        "event_count":      i.get("event_count", 1),
        "escalation_level": i.get("escalation_level", 0),
        "status":           i.get("status", "open"),
    }


def _norm_action(a: dict) -> dict:
    """Auto-response engine action / response_log row → JS timeline shape."""
    return {
        "source_ip":      a.get("source_ip", ""),
        "action_type":    a.get("action_type", ""),
        "timestamp":      a.get("action_time") or a.get("timestamp") or a.get("created_at") or "",
        "created_at":     a.get("action_time") or a.get("created_at") or "",
        "trigger_reason": a.get("action_label") or a.get("trigger_reason") or a.get("action_type", ""),
        "result":         a.get("description") or a.get("result") or "",
        "risk_score":     a.get("risk_score", 0),
        "executed":       a.get("executed", False),
        "severity":       a.get("severity", ""),
    }


def _db():
    from db_manager import get_db
    return get_db()


<<<<<<< HEAD
# ══════════════════════════════════════════════════════════════════
# 1. Incidents
# ══════════════════════════════════════════════════════════════════

@enterprise_bp.route("/incidents")
=======
# ------------------------------------------------------------------
# 1. Incidents
# ------------------------------------------------------------------

@enterprise_bp.route("/incidents", methods=["GET"])
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
@require_login
def get_incidents():
    status = request.args.get("status", "open")
    limit  = int(request.args.get("limit", 50))

    live = []
    if status == "open":
        try:
            from correlation_engine import get_open_incidents
            live = [_norm_incident(i) for i in get_open_incidents(limit=limit)]
        except Exception as e:
            log.debug("[enterprise_bp] correlation_engine unavailable: %s", e)

    db_rows = []
    try:
        conn = _db()
<<<<<<< HEAD
        db_rows = [
            _norm_incident(dict(r))
            for r in conn.execute(
                "SELECT * FROM incidents WHERE status=? ORDER BY last_seen DESC LIMIT ?",
                (status, limit)
            ).fetchall()
        ]
        conn.close()
=======
        try:
            db_rows = [
                _norm_incident(dict(r))
                for r in conn.execute(
                    "SELECT * FROM incidents WHERE status=? ORDER BY last_seen DESC LIMIT ?",
                    (status, limit)
                ).fetchall()
            ]
        finally:
            conn.close()
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
    except Exception as e:
        log.debug("[enterprise_bp] DB incidents error: %s", e)

    if status == "open" and live:
        live_ids = {i["incident_id"] for i in live}
        merged   = live + [r for r in db_rows if r["incident_id"] not in live_ids]
        merged.sort(key=lambda x: x.get("risk_score", 0), reverse=True)
        return jsonify(merged[:limit])

    return jsonify(db_rows)


@enterprise_bp.route("/incidents/<incident_id>/close", methods=["POST"])
@require_role("analyst")
def close_incident_route(incident_id):
    data  = request.get_json() or {}
    notes = data.get("notes") or data.get("analyst_notes", "Closed from dashboard")

    closed_live = False
    try:
        from correlation_engine import close_incident
        closed_live = close_incident(incident_id, operator=data.get("operator", "dashboard"))
    except Exception as e:
        log.debug("[enterprise_bp] live close_incident error: %s", e)

    try:
        conn = _db()
<<<<<<< HEAD
        conn.execute(
            "UPDATE incidents SET status='closed', notes=?, closed_at=? WHERE incident_id=?",
            (notes, datetime.datetime.utcnow().isoformat(), incident_id)
        )
        conn.commit()
        conn.close()
=======
        try:
            conn.execute(
                "UPDATE incidents SET status='closed', notes=?, closed_at=? WHERE incident_id=?",
                (notes, datetime.datetime.now(_tz.utc).isoformat(), incident_id)
            )
            conn.commit()
        finally:
            conn.close()
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
    except Exception as e:
        log.debug("[enterprise_bp] DB close_incident error: %s", e)

    return jsonify({"success": True, "live_engine_updated": closed_live})


@enterprise_bp.route("/incidents", methods=["POST"])
@require_role("analyst")
def create_incident():
    data       = request.get_json() or {}
    source_ip  = data.get("source_ip", "")
    alert_type = data.get("alert_type") or data.get("classification", "MANUAL")
    severity   = data.get("severity", "LOW")

    try:
        conn = _db()
<<<<<<< HEAD
        existing = conn.execute(
            "SELECT incident_id FROM incidents WHERE source_ip=? AND alert_type=? AND status='open' LIMIT 1",
            (source_ip, alert_type)
        ).fetchone()

        if existing:
            conn.close()
            return jsonify({"created": False, "incident_id": existing["incident_id"]}), 200

        iid = "INC-" + uuid.uuid4().hex[:8].upper()
        now = datetime.datetime.utcnow().isoformat()
        conn.execute(
            """INSERT INTO incidents
                   (incident_id, source_ip, alert_type, severity, status,
                    title, first_seen, last_seen, event_count, risk_score, confidence)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (iid, source_ip, alert_type, severity, "open",
             data.get("title", f"Manual — {source_ip}"),
             now, now, 1, data.get("risk_score", 0.0), data.get("confidence", 0.5))
        )
        conn.commit()
        conn.close()
        return jsonify({"created": True, "incident_id": iid}), 201

    except Exception as e:
        log.error("[enterprise_bp] create_incident error: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500


# ══════════════════════════════════════════════════════════════════
# 2. Threat Scores
# ══════════════════════════════════════════════════════════════════

@enterprise_bp.route("/threat-scores")
=======
        try:
            existing = conn.execute(
                "SELECT incident_id FROM incidents WHERE source_ip=? AND alert_type=? AND status='open' LIMIT 1",
                (source_ip, alert_type)
            ).fetchone()
            if existing:
                return jsonify({"created": False, "incident_id": existing["incident_id"]}), 200
            iid = "INC-" + uuid.uuid4().hex[:8].upper()
            now = datetime.datetime.now(_tz.utc).isoformat()
            conn.execute(
                """INSERT INTO incidents
                       (incident_id, source_ip, alert_type, severity, status,
                        title, first_seen, last_seen, event_count, risk_score, confidence)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (iid, source_ip, alert_type, severity, "open",
                 data.get("title", f"Manual - {source_ip}"),
                 now, now, 1, data.get("risk_score", 0.0), data.get("confidence", 0.5))
            )
            conn.commit()
        finally:
            conn.close()
        return jsonify({"created": True, "incident_id": iid}), 201
    except Exception as e:
        log.exception("[enterprise_bp] create_incident error")
        return jsonify({"success": False, "error": str(e)}), 500


# ------------------------------------------------------------------
# 2. Threat Scores
# ------------------------------------------------------------------

@enterprise_bp.route("/threat-scores", methods=["GET"])
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
@require_login
def get_threat_scores():
    limit = int(request.args.get("limit", 20))

    try:
        from threat_scoring import get_engine
        leaderboard = get_engine().get_leaderboard(top_n=limit)
        if leaderboard:
            return jsonify([_norm_host(h) for h in leaderboard])
    except Exception as e:
        log.debug("[enterprise_bp] threat_scoring engine unavailable: %s", e)

    try:
        conn = _db()
<<<<<<< HEAD
        rows = [
            _norm_host(dict(r))
            for r in conn.execute(
                """SELECT ip, risk_score, classification, total_alerts, ml_anomaly_count,
                          first_seen, last_seen
                   FROM host_profiles ORDER BY risk_score DESC LIMIT ?""",
                (limit,)
            ).fetchall()
        ]
        conn.close()
        return jsonify(rows)
    except Exception as e:
        log.error("[enterprise_bp] DB threat-scores error: %s", e)
        return jsonify([]), 500


@enterprise_bp.route("/threat-scores/<ip>")
=======
        try:
            rows = [
                _norm_host(dict(r))
                for r in conn.execute(
                    """SELECT ip, risk_score, classification, total_alerts, ml_anomaly_count,
                              first_seen, last_seen
                       FROM host_profiles ORDER BY risk_score DESC LIMIT ?""",
                    (limit,)
                ).fetchall()
            ]
        finally:
            conn.close()
        return jsonify(rows)
    except Exception as e:
        log.exception("[enterprise_bp] DB threat-scores error")
        return jsonify([]), 500


@enterprise_bp.route("/threat-scores/<ip>", methods=["GET"])
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
@require_login
def get_threat_score_for_ip(ip):
    try:
        from threat_scoring import get_engine
        host = get_engine().get_host(ip)
        if host:
            return jsonify(_norm_host(host))
    except Exception:
        pass
    try:
        conn = _db()
<<<<<<< HEAD
        row  = conn.execute("SELECT * FROM host_profiles WHERE ip=?", (ip,)).fetchone()
        conn.close()
=======
        try:
            row = conn.execute("SELECT * FROM host_profiles WHERE ip=?", (ip,)).fetchone()
        finally:
            conn.close()
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
        if row:
            return jsonify(_norm_host(dict(row)))
    except Exception:
        pass
    return jsonify({"error": "IP not found"}), 404


<<<<<<< HEAD
# ══════════════════════════════════════════════════════════════════
# 3. Auto Response
# ══════════════════════════════════════════════════════════════════

@enterprise_bp.route("/response-history")
=======
# ------------------------------------------------------------------
# 3. Auto Response
# ------------------------------------------------------------------

@enterprise_bp.route("/response-history", methods=["GET"])
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
@require_login
def get_response_history():
    limit = int(request.args.get("limit", 25))

    try:
        from auto_response import get_engine as get_response_engine
        eng = get_response_engine()
        if eng:
            return jsonify([_norm_action(a) for a in eng.get_recent_log(limit=limit)])
    except Exception as e:
        log.debug("[enterprise_bp] auto_response engine unavailable: %s", e)

    try:
        conn = _db()
<<<<<<< HEAD
        rows = [
            _norm_action(dict(r))
            for r in conn.execute(
                "SELECT * FROM response_log ORDER BY action_time DESC LIMIT ?", (limit,)
            ).fetchall()
        ]
        conn.close()
        return jsonify(rows)
    except Exception as e:
        log.error("[enterprise_bp] DB response-history error: %s", e)
        return jsonify([]), 500


@enterprise_bp.route("/actions")
=======
        try:
            rows = [
                _norm_action(dict(r))
                for r in conn.execute(
                    "SELECT * FROM response_log ORDER BY action_time DESC LIMIT ?", (limit,)
                ).fetchall()
            ]
        finally:
            conn.close()
        return jsonify(rows)
    except Exception as e:
        log.exception("[enterprise_bp] DB response-history error")
        return jsonify([]), 500


@enterprise_bp.route("/actions", methods=["GET"])
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
@require_login
def get_actions():
    return get_response_history()


@enterprise_bp.route("/response/evaluate", methods=["POST"])
@require_role("analyst")
def evaluate_responses():
    try:
        from threat_scoring import get_engine as get_scoring
        from auto_response  import get_engine as get_response_engine

        re_eng  = get_response_engine()
        scoring = get_scoring()
        if not re_eng:
            return jsonify({"success": False, "error": "Response engine not started"}), 503

        triggered = 0
        for host in scoring.get_leaderboard(top_n=30):
            ip    = host.get("ip", "")
            score = host.get("risk_score", 0.0)
            if score >= 26:
                triggered += len(re_eng.evaluate(ip, score))

        return jsonify({"success": True, "actions_triggered": triggered})
    except Exception as e:
<<<<<<< HEAD
        log.error("[enterprise_bp] evaluate_responses error: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500


# ══════════════════════════════════════════════════════════════════
# 4. Baseline Learning
# ══════════════════════════════════════════════════════════════════

@enterprise_bp.route("/baseline")
=======
        log.exception("[enterprise_bp] evaluate_responses error")
        return jsonify({"success": False, "error": str(e)}), 500


# ------------------------------------------------------------------
# 4. Baseline Learning
# ------------------------------------------------------------------

@enterprise_bp.route("/baseline", methods=["GET"])
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
@require_login
def get_baseline():
    metric = request.args.get("metric", "pps")
    points = int(request.args.get("limit", 60))

    _metric_map = {
        "packets_per_sec": "pps", "packets_sec": "pps",
        "bytes_per_sec":   "bps", "bytes_sec":   "bps",
        "tcp_pct": "tcp_pct",     "udp_pct":     "udp_pct",
    }
    metric = _metric_map.get(metric, metric)

    try:
<<<<<<< HEAD
        from baseline_learning import get_baseline_snapshot, get_history_for_chart
        snapshot = get_baseline_snapshot()
        history  = get_history_for_chart(metric=metric, points=points)
        labels   = [h.get("t", "")[-8:-3] for h in history]
        current  = [round(float(h.get("v") or 0), 2) for h in history]
        base_val = float(snapshot.get(f"baseline_{metric}") or snapshot.get("baseline_pps") or 0)
        return jsonify({
            "snapshot": snapshot,
            "baseline": [round(base_val, 2)] * len(history),
=======
        # Read live_state.json directly - works across processes
        import json as _json, os as _os
        from config import BASE_DIR
        _baseline_file = _os.path.join(BASE_DIR, "baseline_history.json")

        # Load history from file if it exists
        history = []
        if _os.path.exists(_baseline_file):
            try:
                with open(_baseline_file, "r") as _f:
                    history = _json.load(_f)
            except Exception:
                history = []

        # Fall back to live_state from SQLite if no history
        if not history:
            try:
                from data_service import load_live_stats
                live = load_live_stats()
                pps = float(live.get("rate", 0) or 0)
                now = datetime.datetime.now().strftime("%H:%M")
                history = [{"t": now, "v": pps, "bps": pps * 500}]
            except Exception:
                history = []

        key = "bps" if metric == "bps" else "v"
        labels  = [h.get("t", "")[-5:] for h in history[-points:]]
        current = [round(float(h.get(key) or 0), 2) for h in history[-points:]]
        avg     = sum(current) / max(len(current), 1)
        return jsonify({
            "snapshot": {"samples_collected": len(history)},
            "baseline": [round(avg, 2)] * len(current),
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
            "current":  current,
            "labels":   labels,
        })
    except Exception as e:
<<<<<<< HEAD
        log.debug("[enterprise_bp] baseline_learning unavailable: %s", e)
=======
        log.debug("[enterprise_bp] baseline read error: %s", e)
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)

    try:
        col_map = {"pps": "pps", "bps": "bps", "tcp_pct": "tcp_pct", "udp_pct": "udp_pct"}
        col     = col_map.get(metric, "pps")
        conn    = _db()
<<<<<<< HEAD
        rows    = list(reversed([
            dict(r) for r in conn.execute(
                f"SELECT sample_time, {col} FROM baseline_samples ORDER BY sample_time DESC LIMIT ?",
                (points,)
            ).fetchall()
        ]))
        conn.close()
=======
        try:
            rows = list(reversed([
                dict(r) for r in conn.execute(
                    f"SELECT sample_time, {col} FROM baseline_samples ORDER BY sample_time DESC LIMIT ?",
                    (points,)
                ).fetchall()
            ]))
        finally:
            conn.close()
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
        labels  = [r["sample_time"][11:16] for r in rows]
        current = [round(float(r.get(col) or 0), 2) for r in rows]
        avg     = sum(current) / max(len(current), 1)
        return jsonify({
            "snapshot": {},
            "baseline": [round(avg, 2)] * len(rows),
            "current":  current,
            "labels":   labels,
        })
    except Exception as e:
<<<<<<< HEAD
        log.error("[enterprise_bp] DB baseline error: %s", e)
        return jsonify({"baseline": [], "current": [], "labels": [], "snapshot": {}}), 500


@enterprise_bp.route("/baseline/trend")
=======
        log.exception("[enterprise_bp] DB baseline error")
        return jsonify({"baseline": [], "current": [], "labels": [], "snapshot": {}}), 500


@enterprise_bp.route("/baseline/trend", methods=["GET"])
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
@require_login
def get_baseline_trend():
    return get_baseline()


<<<<<<< HEAD
@enterprise_bp.route("/baseline/anomalies")
=======
@enterprise_bp.route("/baseline/anomalies", methods=["GET"])
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
@require_login
def get_baseline_anomalies():
    try:
        from baseline_learning import get_baseline_snapshot
        snap = get_baseline_snapshot()
        return jsonify({
            "anomaly_active":      snap.get("anomaly_flag", False),
            "pps_deviation":       snap.get("pps_deviation", 0),
            "bps_deviation":       snap.get("bps_deviation", 0),
            "deviation_threshold": snap.get("deviation_threshold", 0.5),
            "current_pps":         snap.get("current_pps", 0),
            "baseline_pps":        snap.get("baseline_pps", 0),
        })
    except Exception as e:
        return jsonify({"anomaly_active": False, "error": str(e)}), 200


<<<<<<< HEAD
# ══════════════════════════════════════════════════════════════════
# 5. Summary
# JS reads: open_incidents, critical_ips, actions_24h, anomalies_24h
# ══════════════════════════════════════════════════════════════════

@enterprise_bp.route("/summary")
=======
# ------------------------------------------------------------------
# 5. Summary
# JS reads: open_incidents, critical_ips, actions_24h, anomalies_24h
# ------------------------------------------------------------------

@enterprise_bp.route("/summary", methods=["GET"])
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
@require_login
def get_summary():
    open_incidents = 0
    critical_ips   = 0
    actions_24h    = 0
    anomalies_24h  = 0

    try:
        from correlation_engine import get_incident_summary
        summary        = get_incident_summary()
        open_incidents = summary.get("open_incidents", 0)
        by_sev         = summary.get("by_severity", {})
        critical_ips   = by_sev.get("CRITICAL", 0) + by_sev.get("HIGH", 0)
    except Exception:
        pass

    if open_incidents == 0:
        try:
            conn = _db()
<<<<<<< HEAD
            open_incidents = conn.execute(
                "SELECT COUNT(*) FROM incidents WHERE status='open'"
            ).fetchone()[0]
            critical_ips = conn.execute(
                "SELECT COUNT(*) FROM host_profiles WHERE risk_score >= 76"
            ).fetchone()[0]
            conn.close()
=======
            try:
                open_incidents = conn.execute(
                    "SELECT COUNT(*) FROM incidents WHERE status='open'"
                ).fetchone()[0]
                critical_ips = conn.execute(
                    "SELECT COUNT(*) FROM host_profiles WHERE risk_score >= 76"
                ).fetchone()[0]
            finally:
                conn.close()
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
        except Exception:
            pass

    try:
        conn = _db()
<<<<<<< HEAD
        actions_24h = conn.execute(
            "SELECT COUNT(*) FROM response_log WHERE action_time >= datetime('now', '-1 day')"
        ).fetchone()[0]
        conn.close()
=======
        try:
            actions_24h = conn.execute(
                "SELECT COUNT(*) FROM response_log WHERE action_time >= datetime('now', '-1 day')"
            ).fetchone()[0]
        finally:
            conn.close()
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
    except Exception:
        pass

    try:
        from baseline_learning import get_baseline_snapshot
        if get_baseline_snapshot().get("anomaly_flag"):
            anomalies_24h = 1
    except Exception:
        pass

    if anomalies_24h == 0:
        try:
            conn = _db()
<<<<<<< HEAD
            anomalies_24h = conn.execute(
                "SELECT COUNT(*) FROM anomaly_history WHERE event_time >= datetime('now', '-1 day')"
            ).fetchone()[0]
            conn.close()
=======
            try:
                anomalies_24h = conn.execute(
                    "SELECT COUNT(*) FROM anomaly_history WHERE event_time >= datetime('now', '-1 day')"
                ).fetchone()[0]
            finally:
                conn.close()
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
        except Exception:
            pass

    return jsonify({
        "open_incidents": open_incidents,
        "critical_ips":   critical_ips,
        "actions_24h":    actions_24h,
        "anomalies_24h":  anomalies_24h,
    })


<<<<<<< HEAD
# ══════════════════════════════════════════════════════════════════
# 6. Sweep / Deduplication
# ══════════════════════════════════════════════════════════════════
=======
# ------------------------------------------------------------------
# 6. Sweep / Deduplication
# ------------------------------------------------------------------
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)

@enterprise_bp.route("/sweep", methods=["POST"])
@require_login
def run_sweep():
    try:
        from correlation_engine import sweep_incidents
        return jsonify({"success": True, "duplicates_closed": sweep_incidents()})
    except Exception as e:
        log.debug("[enterprise_bp] live sweep error: %s", e)

    try:
<<<<<<< HEAD
        conn  = _db()
        dupes = conn.execute(
            """SELECT source_ip, alert_type, COUNT(*) AS cnt, MIN(incident_id) AS keep_id
               FROM incidents WHERE status='open'
               GROUP BY source_ip, alert_type HAVING cnt > 1"""
        ).fetchall()
        closed = 0
        for row in dupes:
            r = conn.execute(
                """UPDATE incidents SET status='closed',
                   notes='Auto-closed: duplicate by sweep'
                   WHERE source_ip=? AND alert_type=? AND status='open' AND incident_id != ?""",
                (row["source_ip"], row["alert_type"], row["keep_id"])
            )
            closed += r.rowcount
        conn.commit()
        conn.close()
        return jsonify({"success": True, "duplicates_closed": closed})
    except Exception as e:
        log.error("[enterprise_bp] DB sweep error: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500


# ══════════════════════════════════════════════════════════════════
# 7. Rescore
# ══════════════════════════════════════════════════════════════════
=======
        conn   = _db()
        closed = 0
        try:
            dupes = conn.execute(
                """SELECT source_ip, alert_type, COUNT(*) AS cnt, MIN(incident_id) AS keep_id
                   FROM incidents WHERE status='open'
                   GROUP BY source_ip, alert_type HAVING cnt > 1"""
            ).fetchall()
            for row in dupes:
                r = conn.execute(
                    """UPDATE incidents SET status='closed',
                       notes='Auto-closed: duplicate by sweep'
                       WHERE source_ip=? AND alert_type=? AND status='open' AND incident_id != ?""",
                    (row["source_ip"], row["alert_type"], row["keep_id"])
                )
                closed += r.rowcount
            conn.commit()
        finally:
            conn.close()
        return jsonify({"success": True, "duplicates_closed": closed})
    except Exception as e:
        log.exception("[enterprise_bp] DB sweep error")
        return jsonify({"success": False, "error": str(e)}), 500


# ------------------------------------------------------------------
# 7. Rescore
# ------------------------------------------------------------------
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)

@enterprise_bp.route("/rescore", methods=["POST"])
@require_login
def trigger_rescore():
<<<<<<< HEAD
    import json as _json, os

    try:
        from threat_scoring import get_engine, BASE_DIR
        ALERTS_FILE = os.path.join(BASE_DIR, "alerts.json")
=======
    try:
        from threat_scoring import get_engine
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
    except Exception as e:
        return jsonify({"success": False, "error": f"threat_scoring unavailable: {e}"}), 500

    try:
<<<<<<< HEAD
        with open(ALERTS_FILE, encoding="utf-8") as f:
            alerts = _json.load(f)
    except FileNotFoundError:
        return jsonify({"success": False, "error": f"alerts.json not found"}), 404
=======
        from data_service import load_alerts
        alerts = load_alerts(limit=5000)
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

    utc    = datetime.timezone.utc
    now    = datetime.datetime.now(utc)
    cutoff = now - datetime.timedelta(hours=24)

    def _parse_ts(a):
        for key in ("timestamp", "created_at", "time", "detected_at"):
            v = a.get(key)
            if v:
                try:
                    s  = str(v).replace("Z", "+00:00")
                    dt = datetime.datetime.fromisoformat(s)
                    return dt if dt.tzinfo else dt.replace(tzinfo=utc)
                except Exception:
                    pass
        return None

    recent = [a for a in alerts if (_parse_ts(a) or cutoff) >= cutoff]

    eng = get_engine()
    for a in recent:
        try:
            eng.ingest_alert(a)
        except Exception:
            pass

    return jsonify({
        "success":          True,
        "alerts_processed": len(recent),
        "ips_scored":       len(eng.get_leaderboard(top_n=50)),
        "window_hours":     24,
    })