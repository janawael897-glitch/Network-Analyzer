"""
PacketGuard RBAC - Database Schema & Initialization
=====================================================
Tables: users, roles, permissions, role_permissions, audit_log
"""

import sqlite3
import os
from datetime import datetime
from werkzeug.security import generate_password_hash

from app.auth.permissions import get_all_permissions, get_permissions_for_role

DB_PATH = os.environ.get("PACKETGUARD_DB", "packetguard.db")


def get_db() -> sqlite3.Connection:
    """Return a configured SQLite connection."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


# ─────────────────────────────────────────────────────────────────────────────
# Schema
# ─────────────────────────────────────────────────────────────────────────────

SCHEMA_SQL = """
-- Roles table
CREATE TABLE IF NOT EXISTS roles (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL UNIQUE,
    description TEXT,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Permissions table (master list)
CREATE TABLE IF NOT EXISTS permissions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL UNIQUE,
    description TEXT
);

-- Many-to-many: which permissions belong to which role
CREATE TABLE IF NOT EXISTS role_permissions (
    role_id       INTEGER NOT NULL REFERENCES roles(id)       ON DELETE CASCADE,
    permission_id INTEGER NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT    NOT NULL UNIQUE,
    email           TEXT    NOT NULL UNIQUE,
    password_hash   TEXT    NOT NULL,
    role_id         INTEGER NOT NULL REFERENCES roles(id),
    is_active       INTEGER NOT NULL DEFAULT 1,   -- 0 = disabled
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    last_login      TEXT,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    TEXT                          -- NULL = not locked
);

-- Audit log - every privileged action is recorded here
CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER REFERENCES users(id) ON DELETE SET NULL,
    username    TEXT    NOT NULL,
    action      TEXT    NOT NULL,               -- e.g. "block_ip"
    target      TEXT,                           -- e.g. "192.168.1.5"
    detail      TEXT,                           -- JSON extra context
    ip_address  TEXT,
    status      TEXT    NOT NULL DEFAULT 'success',  -- success | denied | error
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_audit_user    ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_action  ON audit_log(action);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_users_role    ON users(role_id);
"""


def init_db():
    """
    Create tables, seed roles/permissions, and create the default admin user
    if one doesn't already exist.
    """
    conn = get_db()
    try:
        conn.executescript(SCHEMA_SQL)
        _seed_roles_and_permissions(conn)
        _seed_default_admin(conn)
        conn.commit()
        print("[PacketGuard] Database initialized successfully.")
    finally:
        conn.close()


def _seed_roles_and_permissions(conn: sqlite3.Connection):
    """Insert roles and permissions if they don't exist yet."""

    roles = [
        ("admin",   "Full system access — SOC administrator"),
        ("analyst", "Threat analysis and incident investigation"),
        ("viewer",  "Read-only dashboard access"),
    ]

    for role_name, desc in roles:
        conn.execute(
            "INSERT OR IGNORE INTO roles (name, description) VALUES (?, ?)",
            (role_name, desc),
        )

    for perm_name in get_all_permissions():
        conn.execute(
            "INSERT OR IGNORE INTO permissions (name) VALUES (?)",
            (perm_name,),
        )

    # Link roles → permissions
    for role_name, _, in [(r[0], r[1]) for r in roles]:
        role_row = conn.execute(
            "SELECT id FROM roles WHERE name = ?", (role_name,)
        ).fetchone()
        if not role_row:
            continue

        role_id = role_row["id"]
        role_perms = get_permissions_for_role(role_name)

        for perm_name in role_perms:
            perm_row = conn.execute(
                "SELECT id FROM permissions WHERE name = ?", (perm_name,)
            ).fetchone()
            if perm_row:
                conn.execute(
                    "INSERT OR IGNORE INTO role_permissions (role_id, permission_id)"
                    " VALUES (?, ?)",
                    (role_id, perm_row["id"]),
                )


def _seed_default_admin(conn: sqlite3.Connection):
    """Create a default admin account if no users exist yet."""
    count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if count > 0:
        return

    admin_role = conn.execute(
        "SELECT id FROM roles WHERE name = 'admin'"
    ).fetchone()
    if not admin_role:
        return

    default_password = os.environ.get("ADMIN_DEFAULT_PASSWORD", "Admin@PacketGuard1!")
    conn.execute(
        """INSERT INTO users (username, email, password_hash, role_id)
           VALUES ('admin', 'admin@packetguard.local', ?, ?)""",
        (generate_password_hash(default_password), admin_role["id"]),
    )
    print(f"[PacketGuard] Default admin created. Password: {default_password}")
    print("[PacketGuard] ⚠  Change this password immediately after first login!")
