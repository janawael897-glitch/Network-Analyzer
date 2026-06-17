"""
account_requests.py — PacketGuard
Pending self-registration requests that require admin approval before the
corresponding row is created in the `users` table.
"""

import sqlite3
from datetime import datetime, timezone

from auth import get_db, hash_password, verify_password, validate_password_strength


def create_account_request(name: str, email: str, password: str, role: str):
    """Store a pending signup. Returns (success, message)."""
    pw_ok, pw_msg = validate_password_strength(password)
    if not pw_ok:
        return False, pw_msg
    conn = get_db()
    try:
        existing_user = conn.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
        if existing_user:
            return False, "An account with this email already exists."
        existing_request = conn.execute(
            "SELECT id FROM account_requests WHERE email=? AND status='pending'", (email,)
        ).fetchone()
        if existing_request:
            return False, "A request for this email is already pending review."
        conn.execute(
            "INSERT INTO account_requests (name, email, password_hash, role, status, submitted_at) "
            "VALUES (?, ?, ?, ?, 'pending', ?)",
            (name, email, hash_password(password), role, datetime.now(timezone.utc).isoformat())
        )
        conn.commit()
        return True, "Registration submitted. An administrator must approve your account before you can log in."
    finally:
        conn.close()


def check_request_status(email: str, password: str):
    """Verify credentials against the most recent request for this email.
    Returns 'pending', 'rejected', or None (no matching request)."""
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT * FROM account_requests WHERE email=? ORDER BY id DESC LIMIT 1", (email,)
        ).fetchone()
        if not row or not verify_password(password, row["password_hash"]):
            return None
        return row["status"] if row["status"] in ("pending", "rejected") else None
    finally:
        conn.close()


def list_account_requests():
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT id, name, email, role, status, submitted_at, "
            "reviewer_name, admin_note, reviewed_at FROM account_requests ORDER BY id DESC LIMIT 200"
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def review_account_request(req_id: int, admin: dict, action: str, note: str):
    """Approve or reject a pending request. Returns (success, message)."""
    conn = get_db()
    try:
        row = conn.execute("SELECT * FROM account_requests WHERE id=?", (req_id,)).fetchone()
        if not row:
            return False, "Request not found."
        if row["status"] != "pending":
            return False, "Request already reviewed."

        now = datetime.now(timezone.utc).isoformat()

        if action == "approve":
            taken = conn.execute("SELECT id FROM users WHERE email=?", (row["email"],)).fetchone()
            if taken:
                conn.execute(
                    "UPDATE account_requests SET status='rejected', reviewed_by=?, reviewer_name=?, "
                    "admin_note=?, reviewed_at=? WHERE id=?",
                    (admin["id"], admin["name"], "Auto-rejected: email already registered.", now, req_id)
                )
                conn.commit()
                return False, "An account with this email already exists."
            conn.execute(
                "INSERT INTO users (name, email, password, role, created_at) VALUES (?, ?, ?, ?, ?)",
                (row["name"], row["email"], row["password_hash"], row["role"], now)
            )

        new_status = "approved" if action == "approve" else "rejected"
        conn.execute(
            "UPDATE account_requests SET status=?, reviewed_by=?, reviewer_name=?, "
            "admin_note=?, reviewed_at=? WHERE id=?",
            (new_status, admin["id"], admin["name"], note, now, req_id)
        )
        conn.commit()
        return True, f"Request {new_status}."
    finally:
        conn.close()
