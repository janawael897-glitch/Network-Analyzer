"""
PacketGuard RBAC - Dashboard Blueprint
=========================================
Demonstrates role-based dashboard rendering.
Each role sees a different view of the same URL.
"""

from flask import Blueprint, render_template, g, redirect, url_for
from app.auth.decorators import require_permission, require_login
from app.auth.audit import log_action

dashboard_bp = Blueprint("dashboard", __name__, url_prefix="/")


@dashboard_bp.route("/")
@require_permission("view_dashboard")
def index():
    """
    Render the dashboard. The template uses `can()` helpers to show/hide
    UI panels depending on the user's permissions.
    """
    log_action(action="view_dashboard")
    return render_template(
        "dashboard/index.html",
        role=g.user["role_name"],
        username=g.user["username"],
    )


@dashboard_bp.route("/capture")
@require_permission("view_capture")
def capture():
    return render_template("dashboard/capture.html")


@dashboard_bp.route("/alerts")
@require_permission("view_alerts")
def alerts():
    return render_template("dashboard/alerts.html")


@dashboard_bp.route("/incidents")
@require_permission("view_incidents")
def incidents():
    return render_template("dashboard/incidents.html")


@dashboard_bp.route("/ip-management")
@require_permission("view_blocklist")
def ip_management():
    return render_template("dashboard/ip_management.html")


@dashboard_bp.route("/detection-rules")
@require_permission("view_rules")
def detection_rules():
    return render_template("dashboard/rules.html")


@dashboard_bp.route("/ml-status")
@require_permission("view_ml_status")
def ml_status():
    return render_template("dashboard/ml.html")


@dashboard_bp.route("/reports")
@require_permission("view_reports")
def reports():
    return render_template("dashboard/reports.html")


@dashboard_bp.route("/admin/users")
@require_permission("view_users")
def user_management():
    """Admin-only user management page."""
    return render_template("admin/users.html")


@dashboard_bp.route("/admin/audit-log")
@require_permission("view_audit_log")
def audit_log_view():
    """Admin-only audit log page."""
    return render_template("admin/audit_log.html")


@dashboard_bp.route("/settings")
@require_permission("view_settings")
def settings():
    return render_template("admin/settings.html")
