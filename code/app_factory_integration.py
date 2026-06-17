"""
PacketGuard — App Factory Integration
======================================
Shows exactly how to wire the four new enterprise modules into your existing
Flask application factory (create_app function).

This is a reference snippet — merge it into your existing create_app().
"""

import sqlite3
import logging
from flask import Flask
from flask_socketio import SocketIO

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Database connection factory
# Replace with your existing connection pooling if you have one.
# ─────────────────────────────────────────────────────────────────────────────

def make_db_factory(db_path: str):
    """
    Returns a callable that creates a new sqlite3.Connection.
    Uses check_same_thread=False so connections can be shared across threads
    (each engine should call this to get its own connection).
    """
    def factory() -> sqlite3.Connection:
        conn = sqlite3.connect(db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn
    return factory


# ─────────────────────────────────────────────────────────────────────────────
# create_app integration
# ─────────────────────────────────────────────────────────────────────────────

def create_app(config: dict = None) -> tuple[Flask, SocketIO]:
    """
    Extend your existing create_app to initialise the four enterprise modules.

    Example config keys:
        DB_PATH        : path to SQLite file
        SMTP_HOST      : email server
        SMTP_PORT      : (default 587)
        SMTP_USER      : username
        SMTP_PASS      : password
        ALERT_FROM     : from address
        ALERT_TO       : comma-separated recipient addresses
    """
    app = Flask(__name__)
    config = config or {}
    app.config.update(config)

    socketio = SocketIO(app, async_mode="threading", cors_allowed_origins="*")

    db_path    = app.config.get("DB_PATH", "packetguard.db")
    db_factory = make_db_factory(db_path)

    # ── Run schema migrations ──────────────────────────────────────────────
    from database.migrations import init_new_tables
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        init_new_tables(conn)

    # ── Initialise engines ─────────────────────────────────────────────────
    from detection.correlation_engine import CorrelationEngine
    from detection.threat_scoring     import ThreatScoringEngine
    from alerts.auto_response         import AutoResponseEngine
    from ml.baseline_learning         import BaselineLearner

    email_config = {
        "smtp_host": app.config.get("SMTP_HOST", ""),
        "smtp_port": int(app.config.get("SMTP_PORT", 587)),
        "username":  app.config.get("SMTP_USER", ""),
        "password":  app.config.get("SMTP_PASS", ""),
        "from_addr": app.config.get("ALERT_FROM", ""),
        "to_addrs":  app.config.get("ALERT_TO", "").split(","),
    }

    correlation_engine = CorrelationEngine(
        db_conn_factory=db_factory,
        socketio=socketio,
        window_seconds=300,         # 5-minute correlation window
    )

    threat_engine = ThreatScoringEngine(
        db_conn_factory=db_factory,
        socketio=socketio,
        decay_interval_seconds=60,
    )
    threat_engine.start()           # starts background decay thread

    auto_response = AutoResponseEngine(
        db_conn_factory=db_factory,
        socketio=socketio,
        email_config=email_config,
    )

    baseline_learner = BaselineLearner(
        db_conn_factory=db_factory,
        threat_engine=threat_engine,
        socketio=socketio,
        window_seconds=60,
    )
    baseline_learner.start()        # starts background observation thread

    # ── Attach engines to the blueprint via dependency injection ───────────
    from api.enterprise_bp import enterprise_bp
    enterprise_bp.correlation_engine = correlation_engine
    enterprise_bp.threat_engine      = threat_engine
    enterprise_bp.auto_response      = auto_response
    enterprise_bp.baseline_learner   = baseline_learner
    app.register_blueprint(enterprise_bp)

    # Store on app context so other modules can access them
    app.correlation_engine = correlation_engine
    app.threat_engine      = threat_engine
    app.auto_response      = auto_response
    app.baseline_learner   = baseline_learner

    return app, socketio


# ─────────────────────────────────────────────────────────────────────────────
# Integration: Alert pipeline hook
# ─────────────────────────────────────────────────────────────────────────────

def on_alert_generated(app: Flask, alert: dict) -> None:
    """
    Call this from your existing alert manager whenever a new alert is created.
    This is the single integration point that feeds all four new modules.

    Parameters
    ----------
    alert : dict
        {
            "id":          <int>,
            "source_ip":   "1.2.3.4",
            "event_type":  "ssh_brute_force",   # must match SCORE_TABLE keys
            "severity":    "high",
            "timestamp":   1700000000.0,
        }

    Wire this in your existing alerts/manager.py:
        from app_factory import on_alert_generated
        ...
        on_alert_generated(current_app._get_current_object(), alert_dict)
    """
    source_ip  = alert.get("source_ip")
    event_type = alert.get("event_type")
    severity   = alert.get("severity")

    if not source_ip:
        return

    # 1. Update threat score
    score_result = app.threat_engine.record_event(source_ip, event_type)
    current_score = score_result["score"] if score_result else None

    # 2. Correlate alert into attack chains
    app.correlation_engine.ingest_alert(alert)

    # 3. Evaluate auto-response
    if current_score is not None:
        app.auto_response.evaluate(
            source_ip  = source_ip,
            score      = current_score,
            severity   = severity,
            event_type = event_type,
        )


# ─────────────────────────────────────────────────────────────────────────────
# Integration: Packet handler hook
# ─────────────────────────────────────────────────────────────────────────────

def on_packet_captured(app: Flask, src_ip: str, protocol: str, byte_count: int) -> None:
    """
    Call this from your Scapy packet sniffer callback for every captured packet.
    This feeds the baseline learner with raw traffic observations.

    Wire this in your monitoring/sniffer.py:
        from app_factory import on_packet_captured
        ...
        on_packet_captured(app, src_ip, proto, len(pkt))
    """
    app.baseline_learner.record_packet(src_ip, protocol, byte_count)


# ─────────────────────────────────────────────────────────────────────────────
# SocketIO event handlers for the SOC dashboard namespace
# ─────────────────────────────────────────────────────────────────────────────

def register_socketio_handlers(socketio: SocketIO, app: Flask) -> None:
    """Register /soc namespace handlers. Call from create_app after socketio init."""

    @socketio.on("connect", namespace="/soc")
    def soc_connect():
        logger.info("SOC dashboard client connected")

    @socketio.on("request_summary", namespace="/soc")
    def soc_summary():
        """Dashboard can request a full summary on connect."""
        from flask import current_app
        with app.app_context():
            lt   = __import__("time").localtime()
            socketio.emit("summary", {
                "top_threats":     app.threat_engine.get_top_threats(10),
                "recent_incidents":app.correlation_engine.get_recent_incidents(10),
                "recent_actions":  app.auto_response.get_response_history(10),
                "baseline_stats":  app.baseline_learner.get_recent_stats(5),
            }, namespace="/soc")


# ─────────────────────────────────────────────────────────────────────────────
# Dashboard JavaScript integration reference
# ─────────────────────────────────────────────────────────────────────────────

DASHBOARD_JS_REFERENCE = """
// ── Connect to the SOC namespace ──────────────────────────────────────────
const socket = io('/soc');

socket.on('connect', () => {
    socket.emit('request_summary');
});

// ── 1. New correlated incident ─────────────────────────────────────────────
socket.on('new_incident', (incident) => {
    // incident: { id, source_ip, chain_name, severity, event_types, created_at }
    addIncidentToTimeline(incident);
    showSeverityBadge(incident.severity);
});

// ── 2. Threat score update ─────────────────────────────────────────────────
socket.on('threat_score_update', (data) => {
    // data: { source_ip, score, threat_level, delta, event_type }
    updateThreatScoreTable(data.source_ip, data.score, data.threat_level);
    updateThreatMap(data);
});

// ── 3. Auto-response action ────────────────────────────────────────────────
socket.on('auto_response_action', (action) => {
    // action: { source_ip, action_type, trigger_reason, success, created_at }
    addActionToLog(action);
    if (action.action_type === 'block_ip') {
        markIPAsBlocked(action.source_ip);
    }
});

// ── 4. Baseline update (every 60s) ────────────────────────────────────────
socket.on('baseline_update', (stats) => {
    // stats: { pkt_rate, baseline_pkt_rate, pkt_rate_dev_pct, anomalous, ... }
    updateTrafficChart(stats.pkt_rate, stats.baseline_pkt_rate);
    updateDeviationGauge(stats.pkt_rate_dev_pct);
    if (stats.anomalous) {
        showAnomalyBanner(stats);
    }
});

// ── 4b. Baseline anomaly alert ────────────────────────────────────────────
socket.on('baseline_anomaly', (data) => {
    // data: { pkt_rate_dev_pct, byte_rate_dev_pct, timestamp }
    showCriticalBanner(
        `Traffic anomaly: ${data.pkt_rate_dev_pct.toFixed(1)}% above baseline`
    );
});
"""
