"""
PacketGuard RBAC - Application Factory
=========================================
"""

import os
from flask import Flask
from app.auth.decorators import can, has_role
from app.auth.session_manager import load_logged_in_user
from app.database.models import init_db


def create_app(config: dict = None) -> Flask:
    app = Flask(__name__, template_folder="templates")

    # ── Security config ────────────────────────────────────────────────────────
    app.config["SECRET_KEY"] = os.environ.get(
        "FLASK_SECRET_KEY",
        "CHANGE-THIS-IN-PRODUCTION-USE-SECRETS-MODULE",
    )
    app.config["SESSION_COOKIE_HTTPONLY"]  = True
    app.config["SESSION_COOKIE_SAMESITE"]  = "Lax"
    app.config["SESSION_COOKIE_SECURE"]    = os.environ.get("HTTPS", "false") == "true"
    app.config["PERMANENT_SESSION_LIFETIME"] = 3600  # 1 hour

    if config:
        app.config.update(config)

    # ── Initialize database ────────────────────────────────────────────────────
    with app.app_context():
        init_db()

    # ── Jinja2 globals — use can() / has_role() in every template ──────────────
    app.jinja_env.globals["can"]      = can
    app.jinja_env.globals["has_role"] = has_role

    # ── Load user before every request ────────────────────────────────────────
    app.before_request(load_logged_in_user)

    # ── Register blueprints ───────────────────────────────────────────────────
    from app.auth.routes      import auth_bp
    from app.dashboard.routes import dashboard_bp
    from app.api.admin_routes import admin_api_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(admin_api_bp)

    # ── Error handlers ─────────────────────────────────────────────────────────
    @app.errorhandler(403)
    def forbidden(e):
        from flask import render_template
        return render_template("errors/403.html"), 403

    @app.errorhandler(404)
    def not_found(e):
        from flask import render_template
        return render_template("errors/404.html"), 404

    return app
