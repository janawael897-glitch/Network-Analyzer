"""
PacketGuard RBAC - Admin API Blueprint
========================================
All routes here require the "admin" role or specific admin permissions.
Prefix: /api/admin/
"""

from flask import Blueprint, jsonify, request, g
from app.auth.decorators import require_permission, require_role
from app.auth.audit import log_action, get_audit_log
from app.auth.session_manager import (
    get_all_users,
    get_user_by_id,
    create_user,
    update_user_role,
    toggle_user_status,
    reset_user_password,
)

admin_api_bp = Blueprint("admin_api", __name__, url_prefix="/api/admin")

VALID_ROLES = ("admin", "analyst", "viewer")


# ─────────────────────────────────────────────────────────────────────────────
# User Management
# ─────────────────────────────────────────────────────────────────────────────

@admin_api_bp.route("/users", methods=["GET"])
@require_permission("view_users")
def list_users():
    users = get_all_users()
    # Strip password hash from response
    for u in users:
        u.pop("password_hash", None)
    return jsonify({"users": users, "count": len(users)})


@admin_api_bp.route("/users", methods=["POST"])
@require_permission("create_users")
def create_user_endpoint():
    data = request.get_json(force=True) or {}
    username = data.get("username", "").strip()
    email    = data.get("email", "").strip()
    password = data.get("password", "")
    role     = data.get("role", "viewer")

    if not all([username, email, password]):
        return jsonify({"error": "username, email, and password are required."}), 400

    if role not in VALID_ROLES:
        return jsonify({"error": f"Invalid role. Choose from: {VALID_ROLES}"}), 400

    ok, error = create_user(username, email, password, role)
    if not ok:
        return jsonify({"error": error}), 400

    log_action(
        action="create_user",
        target=username,
        detail={"email": email, "role": role},
    )
    return jsonify({"message": f"User '{username}' created with role '{role}'."}), 201


@admin_api_bp.route("/users/<int:user_id>", methods=["GET"])
@require_permission("view_users")
def get_user(user_id):
    user = get_user_by_id(user_id)
    if not user:
        return jsonify({"error": "User not found."}), 404
    user.pop("password_hash", None)
    return jsonify(user)


@admin_api_bp.route("/users/<int:user_id>/role", methods=["PATCH"])
@require_permission("assign_roles")
def change_role(user_id):
    data = request.get_json(force=True) or {}
    new_role = data.get("role", "").strip()

    if new_role not in VALID_ROLES:
        return jsonify({"error": f"Invalid role. Choose from: {VALID_ROLES}"}), 400

    # Prevent admins from demoting themselves
    if user_id == g.user["id"] and new_role != "admin":
        return jsonify({"error": "You cannot change your own role."}), 403

    ok, error = update_user_role(user_id, new_role)
    if not ok:
        return jsonify({"error": error}), 400

    user = get_user_by_id(user_id)
    log_action(
        action="assign_role",
        target=user.get("username", str(user_id)),
        detail={"new_role": new_role},
    )
    return jsonify({"message": f"Role updated to '{new_role}'."})


@admin_api_bp.route("/users/<int:user_id>/toggle", methods=["PATCH"])
@require_permission("edit_users")
def toggle_user(user_id):
    # Prevent self-disable
    if user_id == g.user["id"]:
        return jsonify({"error": "You cannot disable your own account."}), 403

    new_status = toggle_user_status(user_id)
    user = get_user_by_id(user_id)

    status_str = "enabled" if new_status else "disabled"
    log_action(
        action=f"user_{status_str}",
        target=user.get("username", str(user_id)),
    )
    return jsonify({"message": f"Account {status_str}.", "is_active": new_status})


@admin_api_bp.route("/users/<int:user_id>/reset-password", methods=["POST"])
@require_permission("edit_users")
def reset_password(user_id):
    data = request.get_json(force=True) or {}
    new_password = data.get("new_password", "")

    if len(new_password) < 10:
        return jsonify({"error": "Password must be at least 10 characters."}), 400

    ok = reset_user_password(user_id, new_password)
    if not ok:
        return jsonify({"error": "User not found."}), 404

    user = get_user_by_id(user_id)
    log_action(
        action="password_reset",
        target=user.get("username", str(user_id)),
    )
    return jsonify({"message": "Password reset successfully."})


@admin_api_bp.route("/users/<int:user_id>", methods=["DELETE"])
@require_permission("delete_users")
def delete_user(user_id):
    if user_id == g.user["id"]:
        return jsonify({"error": "You cannot delete your own account."}), 403

    from app.database.models import get_db
    user = get_user_by_id(user_id)
    if not user:
        return jsonify({"error": "User not found."}), 404

    conn = get_db()
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()

    log_action(
        action="delete_user",
        target=user.get("username", str(user_id)),
    )
    return jsonify({"message": f"User '{user['username']}' deleted."})


# ─────────────────────────────────────────────────────────────────────────────
# Audit Log
# ─────────────────────────────────────────────────────────────────────────────

@admin_api_bp.route("/audit-log", methods=["GET"])
@require_permission("view_audit_log")
def audit_log():
    limit   = min(int(request.args.get("limit", 100)), 500)
    user_id = request.args.get("user_id", type=int)
    action  = request.args.get("action")

    entries = get_audit_log(limit=limit, user_id=user_id, action=action)
    return jsonify({"entries": entries, "count": len(entries)})


# ─────────────────────────────────────────────────────────────────────────────
# Current User Info (used by frontend to render role-aware UI)
# ─────────────────────────────────────────────────────────────────────────────

@admin_api_bp.route("/me", methods=["GET"])
@require_permission("view_dashboard")   # Any logged-in user
def me():
    return jsonify({
        "id":          g.user["id"],
        "username":    g.user["username"],
        "role":        g.user["role_name"],
        "permissions": sorted(g.permissions),
    })
