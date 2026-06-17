"""
PacketGuard RBAC - Session & User Management
=============================================
Handles session validation, user loading, and permission caching.
"""

import json
from datetime import datetime, timedelta
from functools import wraps
from typing import Optional

from flask import session, request, g
from werkzeug.security import check_password_hash, generate_password_hash

from app.database.models import get_db

# Account lockout settings
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15
SESSION_TIMEOUT_MINUTES = 60


# ─────────────────────────────────────────────────────────────────────────────
# User loading (called before every request via before_request)
# ─────────────────────────────────────────────────────────────────────────────

def load_logged_in_user():
    """
    Attach the current user (and their permissions) to Flask's `g` object.
    This runs before every request so every route can access g.user.
    """
    user_id = session.get("user_id")
    g.user = None
    g.permissions = set()

    if user_id is None:
        return

    # Check session hasn't expired
    session_created = session.get("created_at")
    if session_created:
        created = datetime.fromisoformat(session_created)
        if datetime.utcnow() - created > timedelta(minutes=SESSION_TIMEOUT_MINUTES):
            session.clear()
            return

    conn = get_db()
    try:
        user = conn.execute(
            """
            SELECT u.id, u.username, u.email, u.is_active,
                   u.locked_until, r.name AS role_name
            FROM users u
            JOIN roles r ON u.role_id = r.id
            WHERE u.id = ?
            """,
            (user_id,),
        ).fetchone()

        if user is None or not user["is_active"]:
            session.clear()
            return

        # Check account lock
        if user["locked_until"]:
            locked_until = datetime.fromisoformat(user["locked_until"])
            if datetime.utcnow() < locked_until:
                session.clear()
                return
            else:
                # Lockout expired — clear it
                conn.execute(
                    "UPDATE users SET locked_until = NULL, failed_attempts = 0 WHERE id = ?",
                    (user_id,),
                )
                conn.commit()

        # Load permissions from DB
        perms = conn.execute(
            """
            SELECT p.name FROM permissions p
            JOIN role_permissions rp ON p.id = rp.permission_id
            JOIN roles r ON rp.role_id = r.id
            WHERE r.name = ?
            """,
            (user["role_name"],),
        ).fetchall()

        g.user = dict(user)
        g.permissions = {row["name"] for row in perms}

    finally:
        conn.close()


# ─────────────────────────────────────────────────────────────────────────────
# Authentication helpers
# ─────────────────────────────────────────────────────────────────────────────

def authenticate_user(username: str, password: str) -> tuple[Optional[dict], str]:
    """
    Validate credentials. Returns (user_dict, error_message).
    On success: (user, ""). On failure: (None, reason).
    """
    conn = get_db()
    try:
        user = conn.execute(
            """
            SELECT u.*, r.name AS role_name
            FROM users u
            JOIN roles r ON u.role_id = r.id
            WHERE u.username = ?
            """,
            (username,),
        ).fetchone()

        if user is None:
            return None, "Invalid credentials."

        if not user["is_active"]:
            return None, "This account has been disabled."

        # Check lockout
        if user["locked_until"]:
            locked_until = datetime.fromisoformat(user["locked_until"])
            if datetime.utcnow() < locked_until:
                remaining = int((locked_until - datetime.utcnow()).total_seconds() / 60) + 1
                return None, f"Account locked. Try again in {remaining} minute(s)."
            else:
                conn.execute(
                    "UPDATE users SET locked_until = NULL, failed_attempts = 0 WHERE id = ?",
                    (user["id"],),
                )
                conn.commit()

        if not check_password_hash(user["password_hash"], password):
            _record_failed_attempt(conn, user["id"])
            return None, "Invalid credentials."

        # Success — reset failed attempts and update last_login
        conn.execute(
            "UPDATE users SET failed_attempts = 0, locked_until = NULL,"
            " last_login = datetime('now') WHERE id = ?",
            (user["id"],),
        )
        conn.commit()
        return dict(user), ""

    finally:
        conn.close()


def _record_failed_attempt(conn, user_id: int):
    """Increment failed attempt counter; lock account if threshold reached."""
    row = conn.execute(
        "SELECT failed_attempts FROM users WHERE id = ?", (user_id,)
    ).fetchone()

    new_count = (row["failed_attempts"] or 0) + 1

    if new_count >= MAX_FAILED_ATTEMPTS:
        locked_until = (
            datetime.utcnow() + timedelta(minutes=LOCKOUT_MINUTES)
        ).isoformat()
        conn.execute(
            "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
            (new_count, locked_until, user_id),
        )
    else:
        conn.execute(
            "UPDATE users SET failed_attempts = ? WHERE id = ?",
            (new_count, user_id),
        )
    conn.commit()


def create_user_session(user: dict):
    """Write user info into the Flask session after successful login."""
    session.clear()
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["role"] = user["role_name"]
    session["created_at"] = datetime.utcnow().isoformat()
    session.permanent = True


# ─────────────────────────────────────────────────────────────────────────────
# User CRUD (used by admin APIs)
# ─────────────────────────────────────────────────────────────────────────────

def get_all_users() -> list[dict]:
    conn = get_db()
    try:
        rows = conn.execute(
            """
            SELECT u.id, u.username, u.email, u.is_active,
                   u.created_at, u.last_login, u.failed_attempts,
                   u.locked_until, r.name AS role_name
            FROM users u JOIN roles r ON u.role_id = r.id
            ORDER BY u.created_at DESC
            """
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_user_by_id(user_id: int) -> Optional[dict]:
    conn = get_db()
    try:
        row = conn.execute(
            """SELECT u.*, r.name AS role_name FROM users u
               JOIN roles r ON u.role_id = r.id WHERE u.id = ?""",
            (user_id,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def create_user(username: str, email: str, password: str, role_name: str) -> tuple[bool, str]:
    conn = get_db()
    try:
        role = conn.execute(
            "SELECT id FROM roles WHERE name = ?", (role_name,)
        ).fetchone()
        if not role:
            return False, f"Role '{role_name}' does not exist."

        conn.execute(
            "INSERT INTO users (username, email, password_hash, role_id) VALUES (?, ?, ?, ?)",
            (username, email, generate_password_hash(password), role["id"]),
        )
        conn.commit()
        return True, ""
    except Exception as e:
        if "UNIQUE" in str(e):
            return False, "Username or email already exists."
        return False, str(e)
    finally:
        conn.close()


def update_user_role(user_id: int, new_role: str) -> tuple[bool, str]:
    conn = get_db()
    try:
        role = conn.execute(
            "SELECT id FROM roles WHERE name = ?", (new_role,)
        ).fetchone()
        if not role:
            return False, f"Role '{new_role}' not found."
        conn.execute(
            "UPDATE users SET role_id = ? WHERE id = ?", (role["id"], user_id)
        )
        conn.commit()
        return True, ""
    finally:
        conn.close()


def toggle_user_status(user_id: int) -> bool:
    """Enable or disable a user. Returns the new is_active state."""
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT is_active FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        if not row:
            return False
        new_status = 0 if row["is_active"] else 1
        conn.execute(
            "UPDATE users SET is_active = ? WHERE id = ?", (new_status, user_id)
        )
        conn.commit()
        return bool(new_status)
    finally:
        conn.close()


def reset_user_password(user_id: int, new_password: str) -> bool:
    conn = get_db()
    try:
        conn.execute(
            "UPDATE users SET password_hash = ?, failed_attempts = 0,"
            " locked_until = NULL WHERE id = ?",
            (generate_password_hash(new_password), user_id),
        )
        conn.commit()
        return True
    finally:
        conn.close()
