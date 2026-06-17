-- ============================================================
-- PacketGuard Schema v2 - Enterprise Feature Extensions
-- Adds: Correlation Engine, Threat Scoring, Auto Response,
--       Baseline Learning
-- ============================================================

-- ─────────────────────────────────────────────────────────────
-- 1. CORRELATION ENGINE
-- ─────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS correlated_incidents (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id     TEXT UNIQUE NOT NULL,          -- UUID e.g. "INC-2024-xxxxxx"
    source_ip       TEXT NOT NULL,
    attack_chain    TEXT NOT NULL,                 -- JSON list of alert types
    severity        TEXT NOT NULL DEFAULT 'medium',-- low|medium|high|critical
    status          TEXT NOT NULL DEFAULT 'open',  -- open|investigating|closed
    alert_ids       TEXT NOT NULL,                 -- JSON list of contributing alert IDs
    first_seen      DATETIME NOT NULL,
    last_seen       DATETIME NOT NULL,
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    resolved_at     DATETIME,
    analyst_notes   TEXT
);

CREATE INDEX IF NOT EXISTS idx_incidents_ip     ON correlated_incidents(source_ip);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON correlated_incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_seen   ON correlated_incidents(last_seen);

-- ─────────────────────────────────────────────────────────────
-- 2. THREAT SCORING SYSTEM
-- ─────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS threat_scores (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address      TEXT UNIQUE NOT NULL,
    score           REAL NOT NULL DEFAULT 0.0,
    threat_level    TEXT NOT NULL DEFAULT 'low',   -- low|medium|high|critical
    score_breakdown TEXT,                           -- JSON: {reason: points}
    first_seen      DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_updated    DATETIME DEFAULT CURRENT_TIMESTAMP,
    decay_applied   DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_scores_ip    ON threat_scores(ip_address);
CREATE INDEX IF NOT EXISTS idx_scores_level ON threat_scores(threat_level);

CREATE TABLE IF NOT EXISTS threat_score_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address  TEXT NOT NULL,
    delta       REAL NOT NULL,                     -- positive = increase, negative = decay
    reason      TEXT NOT NULL,
    score_after REAL NOT NULL,
    recorded_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_score_hist_ip ON threat_score_history(ip_address);

-- ─────────────────────────────────────────────────────────────
-- 3. AUTO RESPONSE SYSTEM
-- ─────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS response_actions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    action_id       TEXT UNIQUE NOT NULL,          -- UUID
    source_ip       TEXT NOT NULL,
    action_type     TEXT NOT NULL,                 -- block|quarantine|alert|firewall_rule
    trigger_reason  TEXT NOT NULL,                 -- what caused this action
    triggered_by    TEXT NOT NULL DEFAULT 'auto',  -- auto|analyst:<username>
    severity        TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'active',-- active|expired|overridden|failed
    expires_at      DATETIME,                      -- NULL = permanent
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    overridden_by   TEXT,                          -- analyst username if manually overridden
    override_reason TEXT,
    metadata        TEXT                           -- JSON extra context
);

CREATE INDEX IF NOT EXISTS idx_response_ip     ON response_actions(source_ip);
CREATE INDEX IF NOT EXISTS idx_response_status ON response_actions(status);
CREATE INDEX IF NOT EXISTS idx_response_type   ON response_actions(action_type);

CREATE TABLE IF NOT EXISTS response_policies (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    policy_name     TEXT UNIQUE NOT NULL,
    severity_trigger TEXT NOT NULL,                -- high|critical
    score_threshold  REAL NOT NULL DEFAULT 70.0,
    action_type      TEXT NOT NULL,
    duration_minutes INTEGER,                      -- NULL = permanent
    cooldown_minutes INTEGER NOT NULL DEFAULT 30,
    enabled          INTEGER NOT NULL DEFAULT 1,   -- SQLite BOOLEAN
    created_at       DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Seed default response policies
INSERT OR IGNORE INTO response_policies
    (policy_name, severity_trigger, score_threshold, action_type, duration_minutes, cooldown_minutes)
VALUES
    ('AutoBlock-Critical',    'critical', 81.0, 'block',          1440, 60),
    ('AutoBlock-High',        'high',     51.0, 'block',           120, 30),
    ('QuarantineRepeater',    'high',     65.0, 'quarantine',       60, 30),
    ('EmailAlert-Critical',   'critical', 81.0, 'alert',          NULL, 10),
    ('EmailAlert-High',       'high',     51.0, 'alert',          NULL, 15);

-- ─────────────────────────────────────────────────────────────
-- 4. BASELINE LEARNING
-- ─────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS baseline_profiles (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_key     TEXT UNIQUE NOT NULL,          -- e.g. "global" or "subnet:10.0.0.0/24"
    window_hours    INTEGER NOT NULL DEFAULT 24,
    metric          TEXT NOT NULL,                 -- packets_per_sec|bandwidth|device_count|...
    mean            REAL NOT NULL DEFAULT 0.0,
    std_dev         REAL NOT NULL DEFAULT 0.0,
    min_val         REAL NOT NULL DEFAULT 0.0,
    max_val         REAL NOT NULL DEFAULT 0.0,
    sample_count    INTEGER NOT NULL DEFAULT 0,
    last_updated    DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_baseline_key_metric
    ON baseline_profiles(profile_key, metric);

CREATE TABLE IF NOT EXISTS baseline_stats (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_key     TEXT NOT NULL,
    metric          TEXT NOT NULL,
    value           REAL NOT NULL,
    deviation_pct   REAL,                          -- % deviation from baseline at record time
    is_anomaly      INTEGER NOT NULL DEFAULT 0,    -- 1 if outside threshold
    recorded_at     DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_bstats_key     ON baseline_stats(profile_key);
CREATE INDEX IF NOT EXISTS idx_bstats_metric  ON baseline_stats(metric);
CREATE INDEX IF NOT EXISTS idx_bstats_time    ON baseline_stats(recorded_at);
CREATE INDEX IF NOT EXISTS idx_bstats_anomaly ON baseline_stats(is_anomaly);
