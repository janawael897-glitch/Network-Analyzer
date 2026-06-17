"""
PacketGuard RBAC - Decorators
==============================
Drop these on any route to enforce authentication and permissions.

Usage:
    @require_login
    def my_view(): ...

    @require_permission("start_capture")
    def start_capture_route(): ...

    @require_role("admin")
    def admin_only(): ...

    @require_any_permission("view_alerts", "view_logs")
    def analyst_view(): ...
"""

from functools import wraps
from flask import g, redirect, url_for, flash, request, jsonify, abort

from app.auth.audit import log_action


# ─────────────────────────────────────────────────────────────────────────────
# Core helpers
# ─────────────────────────────────────────────────────────────────────────────

def _is_api_request() -> bool:
    """True when the caller expects JSON (API route or AJAX)."""
    return (
        request.path.startswith("/api/")
        or request.headers.get("Accept", "").startswith("application/json")
        or request.headers.get("X-Requested-With") == "XMLHttpRequest"
    )


def _deny(reason: str, status: int = 403):
    """Return JSON 403/401 for API calls, redirect for browser calls."""
    if _is_api_request():
        return jsonify({"error": reason, "status": status}), status
    if status == 401:
        flash("Please log in to continue.", "warning")
        return redirect(url_for("auth.login", next=request.url))
    flash(f"Access denied: {reason}", "danger")
    return redirect(url_for("dashboard.index"))


# ─────────────────────────────────────────────────────────────────────────────
# @require_login  — must be authenticated
# ─────────────────────────────────────────────────────────────────────────────

def require_login(f):
    """Redirect unauthenticated users to the login page."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if g.user is None:
            log_action(
                action="unauthorized_access",
                target=request.endpoint,
                status="denied",
            )
            return _deny("Authentication required.", 401)
        return f(*args, **kwargs)
    return decorated


# ─────────────────────────────────────────────────────────────────────────────
# @require_permission("perm_name")  — single permission check
# ─────────────────────────────────────────────────────────────────────────────

def require_permission(permission: str):
    """
    Decorator factory.  Requires the user to hold a specific permission.

        @require_permission("start_capture")
        def start():
            ...
    """
    def decorator(f):
        @wraps(f)
        @require_login          # Also enforces authentication
        def decorated(*args, **kwargs):
            if permission not in g.permissions:
                log_action(
                    action="permission_denied",
                    target=f"{request.endpoint}:{permission}",
                    status="denied",
                )
                return _deny(f"You lack the '{permission}' permission.")
            return f(*args, **kwargs)
        return decorated
    return decorator


# ─────────────────────────────────────────────────────────────────────────────
# @require_role("admin")  — role-level check (less granular, use sparingly)
# ─────────────────────────────────────────────────────────────────────────────

def require_role(*roles: str):
    """
    Require the user's role to be one of the specified roles.
    Prefer @require_permission for fine-grained control.

        @require_role("admin")
        def admin_panel(): ...

        @require_role("admin", "analyst")
        def shared_view(): ...
    """
    def decorator(f):
        @wraps(f)
        @require_login
        def decorated(*args, **kwargs):
            if g.user.get("role_name") not in roles:
                log_action(
                    action="role_denied",
                    target=f"{request.endpoint}:roles={roles}",
                    status="denied",
                )
                return _deny(f"Role '{g.user.get('role_name')}' is not authorized here.")
            return f(*args, **kwargs)
        return decorated
    return decorator


# ─────────────────────────────────────────────────────────────────────────────
# @require_any_permission("p1", "p2")  — OR logic
# ─────────────────────────────────────────────────────────────────────────────

def require_any_permission(*permissions: str):
    """
    Allow access if the user holds AT LEAST ONE of the listed permissions.

        @require_any_permission("view_alerts", "view_logs")
        def analyst_panel(): ...
    """
    def decorator(f):
        @wraps(f)
        @require_login
        def decorated(*args, **kwargs):
            if not any(p in g.permissions for p in permissions):
                log_action(
                    action="permission_denied",
                    target=f"{request.endpoint}:any={permissions}",
                    status="denied",
                )
                return _deny("Insufficient permissions.")
            return f(*args, **kwargs)
        return decorated
    return decorator


# ─────────────────────────────────────────────────────────────────────────────
# @require_all_permissions("p1", "p2")  — AND logic
# ─────────────────────────────────────────────────────────────────────────────

def require_all_permissions(*permissions: str):
    """Allow access only if the user holds ALL listed permissions."""
    def decorator(f):
        @wraps(f)
        @require_login
        def decorated(*args, **kwargs):
            missing = [p for p in permissions if p not in g.permissions]
            if missing:
                log_action(
                    action="permission_denied",
                    target=f"{request.endpoint}:missing={missing}",
                    status="denied",
                )
                return _deny(f"Missing required permissions: {', '.join(missing)}")
            return f(*args, **kwargs)
        return decorated
    return decorator


# ─────────────────────────────────────────────────────────────────────────────
# Template helper — check permissions in Jinja
# ─────────────────────────────────────────────────────────────────────────────

def can(permission: str) -> bool:
    """
    Use inside Jinja2 templates to conditionally show UI elements.

        {% if can('block_ip') %}
            <button>Block IP</button>
        {% endif %}

    Register with app.jinja_env.globals['can'] = can
    """
    if not hasattr(g, "permissions"):
        return False
    return permission in g.permissions


def has_role(role_name: str) -> bool:
    """Template helper to check the current user's role."""
    if not hasattr(g, "user") or g.user is None:
        return False
    return g.user.get("role_name") == role_name
