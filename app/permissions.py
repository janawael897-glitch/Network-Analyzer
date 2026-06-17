"""
PacketGuard RBAC - Permissions Registry
========================================
Central definition of ALL permissions in the system.
Adding a new permission = add it here. That's it.
"""

from enum import Enum


class Permission(str, Enum):
    """
    Every granular action in PacketGuard lives here.
    Roles are just named bundles of these permissions.
    """

    # ── Dashboard ──────────────────────────────────────────────────────────────
    VIEW_DASHBOARD          = "view_dashboard"
    VIEW_STATISTICS         = "view_statistics"

    # ── Packet Capture ─────────────────────────────────────────────────────────
    VIEW_CAPTURE            = "view_capture"
    START_CAPTURE           = "start_capture"
    STOP_CAPTURE            = "stop_capture"
    EXPORT_CAPTURE          = "export_capture"

    # ── Traffic Analysis ───────────────────────────────────────────────────────
    VIEW_TRAFFIC            = "view_traffic"
    ANALYZE_TRAFFIC         = "analyze_traffic"
    FILTER_TRAFFIC          = "filter_traffic"

    # ── Alerts ─────────────────────────────────────────────────────────────────
    VIEW_ALERTS             = "view_alerts"
    ACKNOWLEDGE_ALERTS      = "acknowledge_alerts"
    DISMISS_ALERTS          = "dismiss_alerts"
    CONFIGURE_ALERTS        = "configure_alerts"

    # ── Logs ───────────────────────────────────────────────────────────────────
    VIEW_LOGS               = "view_logs"
    EXPORT_LOGS             = "export_logs"
    DELETE_LOGS             = "delete_logs"

    # ── Incidents ──────────────────────────────────────────────────────────────
    VIEW_INCIDENTS          = "view_incidents"
    INVESTIGATE_INCIDENTS   = "investigate_incidents"
    CLOSE_INCIDENTS         = "close_incidents"

    # ── IP Management ──────────────────────────────────────────────────────────
    VIEW_BLOCKLIST          = "view_blocklist"
    BLOCK_IP                = "block_ip"
    UNBLOCK_IP              = "unblock_ip"
    MANAGE_WHITELIST        = "manage_whitelist"

    # ── Detection Rules ────────────────────────────────────────────────────────
    VIEW_RULES              = "view_rules"
    CREATE_RULES            = "create_rules"
    EDIT_RULES              = "edit_rules"
    DELETE_RULES            = "delete_rules"

    # ── ML / Models ────────────────────────────────────────────────────────────
    VIEW_ML_STATUS          = "view_ml_status"
    CONFIGURE_ML            = "configure_ml"
    RETRAIN_ML              = "retrain_ml"

    # ── Reports ────────────────────────────────────────────────────────────────
    VIEW_REPORTS            = "view_reports"
    GENERATE_REPORTS        = "generate_reports"
    EXPORT_REPORTS          = "export_reports"

    # ── User Management ────────────────────────────────────────────────────────
    VIEW_USERS              = "view_users"
    CREATE_USERS            = "create_users"
    EDIT_USERS              = "edit_users"
    DELETE_USERS            = "delete_users"
    ASSIGN_ROLES            = "assign_roles"

    # ── System Settings ────────────────────────────────────────────────────────
    VIEW_SETTINGS           = "view_settings"
    EDIT_SETTINGS           = "edit_settings"
    VIEW_AUDIT_LOG          = "view_audit_log"
    MANAGE_API_KEYS         = "manage_api_keys"


# ─────────────────────────────────────────────────────────────────────────────
# Role → Permission mapping
# This is the ONLY place you configure what each role can do.
# ─────────────────────────────────────────────────────────────────────────────

ROLE_PERMISSIONS: dict[str, set[Permission]] = {

    "admin": set(Permission),   # All permissions

    "analyst": {
        # Dashboard
        Permission.VIEW_DASHBOARD,
        Permission.VIEW_STATISTICS,
        # Capture (view only)
        Permission.VIEW_CAPTURE,
        Permission.EXPORT_CAPTURE,
        # Traffic
        Permission.VIEW_TRAFFIC,
        Permission.ANALYZE_TRAFFIC,
        Permission.FILTER_TRAFFIC,
        # Alerts
        Permission.VIEW_ALERTS,
        Permission.ACKNOWLEDGE_ALERTS,
        Permission.DISMISS_ALERTS,
        # Logs
        Permission.VIEW_LOGS,
        Permission.EXPORT_LOGS,
        # Incidents
        Permission.VIEW_INCIDENTS,
        Permission.INVESTIGATE_INCIDENTS,
        Permission.CLOSE_INCIDENTS,
        # IP Management (view only)
        Permission.VIEW_BLOCKLIST,
        # Rules (view only)
        Permission.VIEW_RULES,
        # ML (view only)
        Permission.VIEW_ML_STATUS,
        # Reports
        Permission.VIEW_REPORTS,
        Permission.GENERATE_REPORTS,
        Permission.EXPORT_REPORTS,
    },

    "viewer": {
        Permission.VIEW_DASHBOARD,
        Permission.VIEW_STATISTICS,
        Permission.VIEW_CAPTURE,
        Permission.VIEW_TRAFFIC,
        Permission.VIEW_ALERTS,
        Permission.VIEW_LOGS,
        Permission.VIEW_INCIDENTS,
        Permission.VIEW_BLOCKLIST,
        Permission.VIEW_RULES,
        Permission.VIEW_ML_STATUS,
        Permission.VIEW_REPORTS,
    },
}


def get_permissions_for_role(role_name: str) -> set[str]:
    """Return a set of permission strings for the given role name."""
    perms = ROLE_PERMISSIONS.get(role_name, set())
    return {p.value for p in perms}


def get_all_permissions() -> list[str]:
    """Return all defined permission strings (for seeding the DB)."""
    return [p.value for p in Permission]
