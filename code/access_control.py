"""
access_control.py  –  PacketGuard Role-Based Access Control
Place in: code/

Roles (highest → lowest privilege):
  admin   – full access: all read + write + destructive actions + user management
  analyst – read + limited write: can view dashboard, close incidents, override
            responses, run scans. CANNOT: manage users, change email config,
            block/unblock IPs

Usage in web_dashboard.py / enterprise_bp.py:
  from access_control import require_login, require_role

  @app.route("/api/something")
  @require_login
  def something(): ...

  @app.route("/api/admin-only")
  @require_role("admin")
  def admin_only(): ...

  @app.route("/api/analyst-or-admin")
  @require_role("analyst")   # allows analyst AND admin
  def analyst_action(): ...
"""

from functools import wraps
from flask import session, jsonify, request

# ── Role hierarchy ────────────────────────────────────────────────
# Each role inherits all permissions of roles below it.
ROLE_LEVEL = {
    "analyst": 1,
    "user":    1,   # legacy alias — treated as analyst
    "viewer":  1,   # legacy alias — treated as analyst
    "admin":   2,
}

# ── Permissions table ─────────────────────────────────────────────
# Maps permission name → minimum role level required
PERMISSIONS = {
    # Dashboard / read — analyst+
    "read_dashboard":       1,
    "read_alerts":          1,
    "read_devices":         1,
    "read_stats":           1,
    "read_geo":             1,
    "read_scan_history":    1,
    "read_blocklist":       1,
    "read_incidents":       1,
    "read_threat_scores":   1,
    "read_responses":       1,
    "read_baseline":        1,
    "read_exports":         1,

    # Analyst actions — analyst+
    "run_scan":             1,
    "close_incident":       1,
    "override_response":    1,
    "evaluate_responses":   1,
    "read_email_config":    1,

    # Admin-only actions
    "block_ip":             2,
    "unblock_ip":           2,
    "whitelist_ip":         2,
    "change_email_config":  2,
    "manage_users":         2,
    "change_ports":         2,
    "delete_data":          2,
}


def _role_level(role: str) -> int:
    return ROLE_LEVEL.get(role, 0)


def _has_permission(role: str, permission: str) -> bool:
    required = PERMISSIONS.get(permission, 3)   # unknown permissions require admin
    return _role_level(role) >= required


# ── Decorators ────────────────────────────────────────────────────

def require_login(f):
    """Reject unauthenticated requests with 401."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({
                "success": False,
                "error": "Authentication required. Please log in.",
                "code": "NOT_AUTHENTICATED"
            }), 401
        return f(*args, **kwargs)
    return decorated


def require_role(minimum_role: str):
    """
    Reject requests where the logged-in user's role is below minimum_role.
    Also rejects unauthenticated requests (401 vs 403).

    Example:
        @require_role("analyst")  → allows analyst + admin, rejects viewer
        @require_role("admin")    → allows admin only
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if "user_id" not in session:
                return jsonify({
                    "success": False,
                    "error": "Authentication required. Please log in.",
                    "code": "NOT_AUTHENTICATED"
                }), 401
            user_role = session.get("user_role", "viewer")
            if _role_level(user_role) < _role_level(minimum_role):
                return jsonify({
                    "success": False,
                    "error": f"Access denied. Required role: {minimum_role.upper()}. Your role: {user_role.upper()}.",
                    "code": "INSUFFICIENT_ROLE",
                    "required_role": minimum_role,
                    "your_role": user_role,
                }), 403
            return f(*args, **kwargs)
        return decorated
    return decorator


def require_permission(permission: str):
    """
    Fine-grained permission check (alternative to require_role).
    Uses the PERMISSIONS table above.
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if "user_id" not in session:
                return jsonify({
                    "success": False,
                    "error": "Authentication required.",
                    "code": "NOT_AUTHENTICATED"
                }), 401
            user_role = session.get("user_role", "viewer")
            if not _has_permission(user_role, permission):
                return jsonify({
                    "success": False,
                    "error": f"Access denied. Permission required: {permission}.",
                    "code": "INSUFFICIENT_PERMISSION",
                    "permission": permission,
                    "your_role": user_role,
                }), 403
            return f(*args, **kwargs)
        return decorated
    return decorator


# ── Admin user management helpers ─────────────────────────────────

def get_all_users(db_fn):
    """Return all users (minus password). db_fn() must return a sqlite3 connection."""
    conn = db_fn()
    rows = conn.execute(
        "SELECT id, name, email, role, created_at, last_login FROM users ORDER BY id"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def set_user_role(db_fn, user_id: int, new_role: str) -> bool:
    if new_role not in ROLE_LEVEL:
        return False
    conn = db_fn()
    conn.execute("UPDATE users SET role=? WHERE id=?", (new_role, user_id))
    conn.commit()
    conn.close()
    return True


def delete_user(db_fn, user_id: int, requester_id: int) -> tuple[bool, str]:
    if user_id == requester_id:
        return False, "Cannot delete your own account."
    conn = db_fn()
    row = conn.execute("SELECT role FROM users WHERE id=?", (user_id,)).fetchone()
    if not row:
        conn.close()
        return False, "User not found."
    conn.execute("DELETE FROM users WHERE id=?", (user_id,))
    conn.commit()
    conn.close()
    return True, "User deleted."