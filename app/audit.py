"""
PacketGuard RBAC - Audit Logging
==================================
Every privileged action is written to the audit_log table.
Call log_action() from any route or service function.
"""

import json
from flask import g, request
from app.database.models import get_db


def log_action(
    action: str,
    target: str = None,
    detail: dict = None,
    status: str = "success",
):
    """
    Write an audit record.

    Args:
        action:  The action name, e.g. "block_ip", "delete_user"
        target:  What was acted on, e.g. "192.168.1.5" or "user:42"
        detail:  Optional dict with extra context (stored as JSON)
        status:  "success" | "denied" | "error"
    """
    user_id  = g.user["id"]       if (hasattr(g, "user") and g.user) else None
    username = g.user["username"] if (hasattr(g, "user") and g.user) else "anonymous"
    ip_addr  = request.remote_addr if request else None
    detail_json = json.dumps(detail) if detail else None

    try:
        conn = get_db()
        conn.execute(
            """
            INSERT INTO audit_log
                (user_id, username, action, target, detail, ip_address, status)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (user_id, username, action, target, detail_json, ip_addr, status),
        )
        conn.commit()
        conn.close()
    except Exception as e:
        # Audit failures must never crash the main app
        print(f"[AUDIT ERROR] Could not write audit log: {e}")


def get_audit_log(
    limit: int = 100,
    user_id: int = None,
    action: str = None,
) -> list[dict]:
    """Retrieve audit log entries (admin only)."""
    conn = get_db()
    try:
        conditions = []
        params = []

        if user_id:
            conditions.append("user_id = ?")
            params.append(user_id)
        if action:
            conditions.append("action LIKE ?")
            params.append(f"%{action}%")

        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        params.append(limit)

        rows = conn.execute(
            f"SELECT * FROM audit_log {where} ORDER BY created_at DESC LIMIT ?",
            params,
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()
