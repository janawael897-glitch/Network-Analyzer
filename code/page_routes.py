import base64

from flask import Blueprint, Response, redirect, render_template, request
from auth import validate_session, SESSION_COOKIE

page_bp = Blueprint("pages", __name__)


def _get_session_user():
    """Return the validated user dict or None."""
    token = (
        request.cookies.get(SESSION_COOKIE)
        or request.headers.get("Authorization", "").replace("Bearer ", "")
    )
    return validate_session(token) if token else None


# ── Static assets ─────────────────────────────────────────────────

@page_bp.route("/favicon.ico", methods=["GET"])
def favicon():
    """Return a minimal inline ICO to silence 404s — no file dependency."""
    ico = base64.b64decode(
        "AAABAAEAEBAQAAEABAAoAQAAFgAAACgAAAAQAAAAIAAAAAEABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAA////AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA"
        "/wAAAP8AAAD/AAAA/w=="
    )
    return Response(
        ico,
        mimetype="image/x-icon",
        headers={"Cache-Control": "public, max-age=86400"},
    )


# ── Page routes ───────────────────────────────────────────────────

@page_bp.route("/", methods=["GET"])
def home():
    """Landing page with login form."""
    return render_template("home.html")


@page_bp.route("/monitor", methods=["GET"])
def monitor():
    """Live packet-monitoring interface — requires authentication."""
    if not _get_session_user():
        return redirect("/?next=monitor")
    return render_template("monitor.html")


@page_bp.route("/dashboard", methods=["GET"])
def dashboard():
    """Analytics and statistics dashboard — requires authentication."""
    if not _get_session_user():
        return redirect("/?next=dashboard")
    return render_template("dashboard.html")


@page_bp.route("/enterprise", methods=["GET"])
def enterprise():
    """Enterprise SOC view — now integrated into /dashboard (permanent redirect)."""
    return redirect("/dashboard", code=301)


@page_bp.route("/hunt", methods=["GET"])
def hunt():
    """Threat-hunting and alert investigation page — requires authentication."""
    if not _get_session_user():
        return redirect("/?next=hunt")
    return render_template("hunt.html")


@page_bp.route("/profile", methods=["GET"])
def profile_page():
    """User profile page — requires authentication."""
    if not _get_session_user():
        return redirect("/?next=profile")
    return render_template("profile.html")


@page_bp.route("/change-password", methods=["GET"])
def change_password_page():
    """Legacy URL — password change is now part of the profile page."""
    return redirect("/profile")
