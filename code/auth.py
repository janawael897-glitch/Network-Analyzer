#!/usr/bin/env python3
"""
auth.py — PacketGuard Authentication System
SQLite-based user registration, login, and session management.

Features:
  - Passwords hashed with bcrypt (via werkzeug)
  - Sessions stored server-side in SQLite
  - Session tokens sent as secure cookies
  - Auto-creates admin account on first run
"""

import os
import sqlite3
import secrets
import hashlib
<<<<<<< HEAD
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify, make_response

BASE_DIR  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
=======
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import request, jsonify, make_response

BASE_DIR  = os.path.dirname(os.path.abspath(__file__))
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
DB_PATH   = os.path.join(BASE_DIR, "packetguard.db")

SESSION_DURATION_HOURS = 24   # sessions expire after 24 hours
SESSION_COOKIE         = "pg_session"


# ── Database setup ────────────────────────────────────────────────────────────

def get_db():
    """Get a database connection."""
<<<<<<< HEAD
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
=======
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
    return conn


def init_db():
    """Create tables if they don't exist."""
    conn = get_db()
    c = conn.cursor()

    # Users table
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            name       TEXT    NOT NULL,
            email      TEXT    NOT NULL UNIQUE,
            password   TEXT    NOT NULL,
<<<<<<< HEAD
<<<<<<< HEAD
            role       TEXT    NOT NULL DEFAULT 'analyst',
=======
            role       TEXT    NOT NULL DEFAULT 'user',
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
=======
            role       TEXT    NOT NULL DEFAULT 'analyst',
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
            created_at TEXT    NOT NULL,
            last_login TEXT
        )
    """)

    # Sessions table
    c.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            token      TEXT PRIMARY KEY,
            user_id    INTEGER NOT NULL,
            created_at TEXT    NOT NULL,
            expires_at TEXT    NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    conn.commit()
    conn.close()
    print("[AUTH] Database initialized.")


def hash_password(password: str) -> str:
    """Hash a password using SHA-256 + salt (no extra deps needed)."""
    salt = secrets.token_hex(16)
    hashed = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"{salt}:{hashed}"


def verify_password(password: str, stored: str) -> bool:
<<<<<<< HEAD
    """Verify a password against its stored hash."""
    try:
        salt, hashed = stored.split(":")
        return hashlib.sha256((salt + password).encode()).hexdigest() == hashed
=======
    """Verify password — handles werkzeug pbkdf2, bcrypt, and salt:sha256 formats."""
    try:
        if stored.startswith("pbkdf2:"):
            from werkzeug.security import check_password_hash
            return check_password_hash(stored, password)
        if stored.startswith("$2"):
            try:
                import bcrypt as _bcrypt
                return _bcrypt.checkpw(password.encode(), stored.encode())
            except ImportError:
                return False
        if ":" in stored:
            salt, hashed = stored.split(":", 1)
            return hashlib.sha256((salt + password).encode()).hexdigest() == hashed
        return False
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
    except Exception:
        return False


# ── User management ───────────────────────────────────────────────────────────

<<<<<<< HEAD
<<<<<<< HEAD
def create_user(name: str, email: str, password: str, role: str = "analyst"):
=======
def create_user(name: str, email: str, password: str, role: str = "user"):
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
    """Create a new user. Returns (success, message)."""
    if len(password) < 6:
        return False, "Password must be at least 6 characters."
=======
PASSWORD_POLICY_MSG = "Password must be 8+ chars with uppercase, lowercase, number, and special character."


def validate_password_strength(password: str):
    """Check a password against the project-wide strength policy. Returns (ok, message)."""
    import re as _re
    if (len(password) < 8 or not _re.search(r'[A-Z]', password) or not _re.search(r'[a-z]', password)
            or not _re.search(r'[0-9]', password) or not _re.search(r'[^A-Za-z0-9]', password)):
        return False, PASSWORD_POLICY_MSG
    return True, ""


def create_user(name: str, email: str, password: str, role: str = "analyst"):
    """Create a new user. Returns (success, message)."""
    ok, msg = validate_password_strength(password)
    if not ok:
        return False, msg
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
    if not email or "@" not in email:
        return False, "Invalid email address."
    if not name or len(name.strip()) < 2:
        return False, "Name must be at least 2 characters."

    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO users (name, email, password, role, created_at) VALUES (?, ?, ?, ?, ?)",
<<<<<<< HEAD
            (name.strip(), email.lower().strip(), hash_password(password), role, datetime.utcnow().isoformat())
=======
            (name.strip(), email.lower().strip(), hash_password(password), role, datetime.now(timezone.utc).isoformat())
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
        )
        conn.commit()
        print(f"[AUTH] New user created: {email} (role={role})")
        return True, "Account created successfully."
    except sqlite3.IntegrityError:
        return False, "An account with this email already exists."
    except Exception as e:
        return False, str(e)
    finally:
        conn.close()


def authenticate_user(email: str, password: str):
    """Check email/password. Returns user dict or None."""
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT * FROM users WHERE email = ?", (email.lower().strip(),)
        ).fetchone()
        if row and verify_password(password, row["password"]):
            # Update last login
            conn.execute(
                "UPDATE users SET last_login = ? WHERE id = ?",
<<<<<<< HEAD
                (datetime.utcnow().isoformat(), row["id"])
=======
                (datetime.now(timezone.utc).isoformat(), row["id"])
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
            )
            conn.commit()
            return dict(row)
        return None
    finally:
        conn.close()


def get_user_by_id(user_id: int):
    """Get a user by ID."""
    conn = get_db()
    try:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_all_users():
    """Get all users (admin only)."""
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT id, name, email, role, created_at, last_login FROM users ORDER BY created_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def delete_user(user_id: int):
    """Delete a user and their sessions."""
    conn = get_db()
    try:
        conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        return True
    finally:
        conn.close()


# ── Session management ────────────────────────────────────────────────────────

def create_session(user_id: int) -> str:
    """Create a new session token for a user."""
    token = secrets.token_urlsafe(32)
<<<<<<< HEAD
    now   = datetime.utcnow()
=======
    now   = datetime.now(timezone.utc)
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
    exp   = now + timedelta(hours=SESSION_DURATION_HOURS)

    conn = get_db()
    try:
        # Clean up old sessions for this user
        conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        conn.execute(
            "INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
            (token, user_id, now.isoformat(), exp.isoformat())
        )
        conn.commit()
        return token
    finally:
        conn.close()


def validate_session(token: str):
    """Validate a session token. Returns user dict or None."""
    if not token:
        return None
    conn = get_db()
    try:
        row = conn.execute(
            """SELECT s.*, u.id as uid, u.name, u.email, u.role
               FROM sessions s JOIN users u ON s.user_id = u.id
               WHERE s.token = ?""",
            (token,)
        ).fetchone()
        if not row:
            return None
        # Check expiry
        exp = datetime.fromisoformat(row["expires_at"])
<<<<<<< HEAD
        if datetime.utcnow() > exp:
=======
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) > exp:
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
            conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
            conn.commit()
            return None
        return {"id": row["uid"], "name": row["name"], "email": row["email"], "role": row["role"]}
    finally:
        conn.close()


def delete_session(token: str):
    """Delete a session (logout)."""
    conn = get_db()
    try:
        conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
        conn.commit()
    finally:
        conn.close()


def cleanup_expired_sessions():
    """Remove all expired sessions from the database."""
    conn = get_db()
    try:
<<<<<<< HEAD
        conn.execute("DELETE FROM sessions WHERE expires_at < ?", (datetime.utcnow().isoformat(),))
=======
        conn.execute("DELETE FROM sessions WHERE expires_at < ?", (datetime.now(timezone.utc).isoformat(),))
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
        conn.commit()
    finally:
        conn.close()


# ── Flask helpers ─────────────────────────────────────────────────────────────

def get_current_user():
    """Get the currently logged-in user from the request cookie."""
    token = request.cookies.get(SESSION_COOKIE)
    return validate_session(token)


def login_required(f):
    """Decorator: requires a valid session, returns 401 if not logged in."""
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user:
            return jsonify({"error": "Authentication required", "code": 401}), 401
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    """Decorator: requires admin role."""
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user:
            return jsonify({"error": "Authentication required", "code": 401}), 401
        if user.get("role") != "admin":
            return jsonify({"error": "Admin access required", "code": 403}), 403
        return f(*args, **kwargs)
    return decorated


<<<<<<< HEAD
=======
_SECURE_COOKIE = os.environ.get("SECURE_COOKIE", "").lower() not in ("0", "false", "no", "")


>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
def make_auth_response(data: dict, token: str = None, clear: bool = False):
    """Create a JSON response with optional session cookie."""
    resp = make_response(jsonify(data))
    if token:
        resp.set_cookie(
            SESSION_COOKIE, token,
            httponly=True,
            samesite="Lax",
<<<<<<< HEAD
            secure=False,
            max_age=SESSION_DURATION_HOURS * 3600
        )
    if clear:
        resp.set_cookie(SESSION_COOKIE, "", expires=0)
=======
            secure=_SECURE_COOKIE,
            max_age=SESSION_DURATION_HOURS * 3600
        )
    if clear:
        resp.set_cookie(SESSION_COOKIE, "", expires=0, secure=_SECURE_COOKIE)
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
    return resp


# ── Initialize on import ──────────────────────────────────────────────────────
init_db()
<<<<<<< HEAD

# Create default admin account if no users exist
conn = get_db()
count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
conn.close()

if count == 0:
    ok, msg = create_user("Admin", "admin@packetguard.io", "admin123", role="admin")
    if ok:
        print("[AUTH] Default admin account created:")
        print("[AUTH]   Email   : admin@packetguard.io")
        print("[AUTH]   Password: admin123")
<<<<<<< HEAD
        print("[AUTH]   ⚠️  Change this password after first login!")
=======
        print("[AUTH]   ⚠️  Change this password after first login!")
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
=======
# No default admin account is auto-created — the first person to register
# through the signup form becomes admin (see is_first_user in auth_routes.py).
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
