"""
auth_routes.py - PacketGuard
All /api/auth/* endpoints.
OTP is required on both login and signup.

Flow:
  LOGIN:  POST /api/auth/login/request-otp  → sends OTP to email
          POST /api/auth/login              → verifies OTP, creates session

  SIGNUP: POST /api/auth/register/request-otp  → validates fields, sends OTP
          POST /api/auth/register              → verifies OTP, creates user + session
"""

import sqlite3
import time
import threading
from collections import defaultdict
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify, make_response, g

from auth import (
    authenticate_user, create_user, create_session, validate_session,
    delete_session, get_all_users, delete_user as _delete_user_by_id,
    get_db, hash_password, verify_password, validate_password_strength,
    SESSION_COOKIE, SESSION_DURATION_HOURS,
    login_required, admin_required,
)
from account_requests import (
    create_account_request, check_request_status,
    list_account_requests, review_account_request,
)
from auth_service import create_otp, verify_otp  # OTP store (in-memory)
from smtp_service import send_otp_email, send_welcome_admin_email  # Isolated SMTP module

try:
    from config import ROLES, DEFAULT_ROLE
except ImportError:
    ROLES = {"admin": {"level": 3}, "analyst": {"level": 2}, "viewer": {"level": 1}}
    DEFAULT_ROLE = "analyst"

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")


# --- SMTP diagnostic (remove after confirming email works) -------------------
@auth_bp.route("/smtp-test", methods=["GET"])
def smtp_test():
    import socket, smtplib
    from smtp_service import SMTP_USER, SMTP_PASS, SMTP_HOST, _send_starttls
    results = {}
    # TCP connectivity test
    for port in [587, 465, 443]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(8)
            s.connect(("smtp.gmail.com", port))
            s.close()
            results[f"tcp_{port}"] = "CONNECTED"
        except socket.timeout:
            results[f"tcp_{port}"] = "TIMEOUT"
        except Exception as e:
            results[f"tcp_{port}"] = f"{type(e).__name__}: {e}"
    # Full SMTP test on whichever port connected
    if results.get("tcp_587") == "CONNECTED":
        try:
            _send_starttls(SMTP_HOST, SMTP_USER, SMTP_PASS, SMTP_USER,
                           f"From:{SMTP_USER}\r\nTo:{SMTP_USER}\r\n"
                           f"Subject:PG Test\r\n\r\nTest")
            results["smtp"] = "OK — email sent"
        except Exception as e:
            results["smtp"] = f"FAILED: {type(e).__name__}: {e}"
    else:
        results["smtp"] = "skipped (port 587 unreachable)"
    return jsonify(results)


# --- Failed login tracking ---------------------------------------------------
_FAIL_WINDOW   = 300        # seconds to count failures within
_FAIL_LIMIT    = 10         # alert threshold
_BLOCK_LIMIT   = 20         # hard block after this many failures
_BLOCK_SECONDS = 900        # 15-minute block duration

_fail_lock     = threading.Lock()
_fail_counts   = defaultdict(list)  # ip → [timestamps of failures]
_blocked_until = {}                 # ip → unblock_timestamp

def _get_client_ip() -> str:
    return (request.headers.get("X-Forwarded-For", "") or "").split(",")[0].strip() \
           or request.remote_addr or "unknown"

def _record_failure(ip: str):
    """Track a failed login attempt. Returns (blocked, fail_count)."""
    now = time.time()
    with _fail_lock:
        # Prune old entries outside the window
        _fail_counts[ip] = [t for t in _fail_counts[ip] if now - t < _FAIL_WINDOW]
        _fail_counts[ip].append(now)
        count = len(_fail_counts[ip])

        # Hard block
        if count >= _BLOCK_LIMIT:
            _blocked_until[ip] = now + _BLOCK_SECONDS
            _fail_counts[ip] = []

    # Fire alert at threshold (and every 5 after that)
    if count == _FAIL_LIMIT or (count > _FAIL_LIMIT and (count - _FAIL_LIMIT) % 5 == 0):
        _push_brute_alert(ip, count)

    return count

def _is_blocked(ip: str) -> bool:
    until = _blocked_until.get(ip)
    if until and time.time() < until:
        return True
    if until:
        del _blocked_until[ip]
    return False

def _push_brute_alert(ip: str, count: int):
    try:
        from data_service import push_alert
        push_alert({
            "timestamp":    datetime.now(timezone.utc).isoformat(),
            "alert_type":   "BRUTE_FORCE",
            "severity":     "HIGH",
            "message":      f"Web login brute force from {ip} — {count} failed attempts in {_FAIL_WINDOW}s",
            "source_ip":    ip,
            "destination_ip": "127.0.0.1",
            "destination_port": 5000,
            "protocol":     "TCP",
            "additional_info": {"service": "PacketGuard Web Login",
                                "fail_count": count, "window_seconds": _FAIL_WINDOW},
        }, is_ml=False)
    except Exception as e:
        print(f"[AUTH] brute alert error: {e}")


def _get_token():
    return (
        request.cookies.get(SESSION_COOKIE)
        or request.headers.get("Authorization", "").replace("Bearer ", "")
    )

def _current_user():
    return validate_session(_get_token())

def _make_session_response(user, token):
    """Build a JSON response with the session cookie set."""
    response = make_response(jsonify({
        "success": True,
        "message": "Login successful.",
        "token": token,
        "user": {
            "username":     user["email"],
            "display_name": user["name"],
            "role":         user["role"],
        },
    }))
    response.set_cookie(
        SESSION_COOKIE, token,
        max_age=SESSION_DURATION_HOURS * 3600,
        httponly=True,
        samesite="Lax",
    )
    return response


# --- LOGIN - Step 1: Request OTP ---------------------------------------------

@auth_bp.route("/login/request-otp", methods=["POST"])
def api_login_request_otp():
    """Validate credentials, then send OTP to the user's email."""
    data     = request.get_json(silent=True) or {}
    email    = (data.get("email") or "").strip().lower()
    password = data.get("password", "")

    if not email or not password:
        return jsonify({"success": False, "error": "Email and password are required."}), 400

    ip = _get_client_ip()
    if _is_blocked(ip):
        return jsonify({"success": False, "error": "Too many failed attempts. Try again in 15 minutes."}), 429

    user = authenticate_user(email, password)
    if not user:
        pending_status = check_request_status(email, password)
        if pending_status == "pending":
            return jsonify({"success": False, "error": "Your account is pending admin approval."}), 403
        if pending_status == "rejected":
            return jsonify({"success": False, "error": "Your registration request was rejected. Contact an administrator."}), 403
        _record_failure(ip)
        return jsonify({"success": False, "error": "Invalid email or password."}), 401

    otp = create_otp(f"login:{email}", extra={"user_id": user["id"]})
    sent = send_otp_email(email, otp, user["name"])

    if not sent:
        # Still allow bypass in dev if SMTP isn't configured - print to console
        print(f"[OTP-DEV] Login OTP for {email}: {otp}")
        return jsonify({
            "success": True,
            "dev_warning": "SMTP not configured - OTP printed to server console.",
        })

    return jsonify({"success": True})


# --- LOGIN - Step 2: Verify OTP -----------------------------------------------

@auth_bp.route("/login", methods=["POST"])
def api_login():
    """Verify the OTP sent after credentials check, then create session."""
    data  = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    otp   = (data.get("otp") or "").strip()

    if not email or not otp:
        return jsonify({"success": False, "error": "Email and OTP are required."}), 400

    valid, err, record = verify_otp(f"login:{email}", otp)
    if not valid:
        return jsonify({"success": False, "error": err}), 401

    # Fetch fresh user record
    try:
        conn = get_db()
        try:
            row  = conn.execute(
                "SELECT id, name, email, role FROM users WHERE email=?", (email,)
            ).fetchone()
            conn.execute(
                "UPDATE users SET last_login=? WHERE email=?",
                (datetime.now(timezone.utc).isoformat(), email)
            )
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        print(f"[AUTH] login DB error: {e}")
        return jsonify({"success": False, "error": "Database error."}), 500

    if not row:
        return jsonify({"success": False, "error": "User not found."}), 404

    user  = dict(row)
    token = create_session(user["id"])
    return _make_session_response(user, token)


# --- LOGOUT -------------------------------------------------------------------

@auth_bp.route("/logout", methods=["POST"])
def api_logout():
    token = _get_token()
    if token:
        delete_session(token)
    response = make_response(jsonify({"success": True, "message": "Logged out."}))
    response.delete_cookie(SESSION_COOKIE)
    return response


# --- CURRENT USER / "ME" -----------------------------------------------------

@auth_bp.route("/me", methods=["GET"])
@login_required
def api_me():
    user = _current_user()
    return jsonify({
        "success": True,
        "user": {
            "username":     user["email"],
            "display_name": user["name"],
            "role":         user["role"],
        },
    })


# --- PROFILE -----------------------------------------------------------------

@auth_bp.route("/profile", methods=["GET"])
@login_required
def api_profile():
    user = _current_user()
    email = user["email"]
    try:
        conn = get_db()
        try:
            row = conn.execute(
                "SELECT id, name, created_at, last_login FROM users WHERE email=?", (email,)
            ).fetchone()
        finally:
            conn.close()
    except Exception as e:
        print(f"[AUTH] profile DB error: {e}")
        row = None

    return jsonify({
        "success": True,
        "user": {
            "id":         row["id"]         if row else None,
            "name":       row["name"]       if row else user["name"],
            "email":      email,
            "role":       user["role"],
            "created_at": row["created_at"] if row else "",
            "last_login": row["last_login"] if row else "",
        },
    })


# --- PROFILE UPDATE -----------------------------------------------------------

@auth_bp.route("/profile/update", methods=["POST"])
@login_required
def api_profile_update():
    user  = _current_user()
    uid   = user["id"]
    email = user["email"]
    data  = request.get_json(silent=True) or {}
    name  = data.get("name", "").strip()

    if not name or len(name) < 2:
        return jsonify({"success": False, "error": "Name must be at least 2 characters."}), 400

    new_email = None
    if user.get("role") == "admin":
        candidate = data.get("email", "").strip().lower()
        if candidate and candidate != email:
            if "@" not in candidate or "." not in candidate.split("@")[-1]:
                return jsonify({"success": False, "error": "Invalid email address."}), 400
            new_email = candidate

    try:
        conn = get_db()
        try:
            if new_email:
                taken = conn.execute(
                    "SELECT id FROM users WHERE email=? AND id!=?", (new_email, uid)
                ).fetchone()
                if taken:
                    return jsonify({"success": False, "error": "That email is already in use."}), 409
                conn.execute("UPDATE users SET name=?, email=? WHERE id=?", (name, new_email, uid))
            else:
                conn.execute("UPDATE users SET name=? WHERE id=?", (name, uid))
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        print(f"[AUTH] profile update error: {e}")
        return jsonify({"success": False, "error": "Database error."}), 500

    return jsonify({"success": True, "message": "Profile updated.",
                    "new_email": new_email if new_email else email})


# --- CHANGE PASSWORD ----------------------------------------------------------

@auth_bp.route("/change-password", methods=["POST"])
@login_required
def api_change_password():
    user    = _current_user()
    email   = user["email"]
    data    = request.get_json(silent=True) or {}
    current = (data.get("current_password") or data.get("old_password") or "").strip()
    new_pw  = data.get("new_password", "").strip()
    confirm = data.get("confirm_password", "").strip()

    if not current or not new_pw or not confirm:
        return jsonify({"success": False, "error": "All password fields are required."}), 400
    if new_pw != confirm:
        return jsonify({"success": False, "error": "New passwords do not match."}), 400
    pw_ok, pw_msg = validate_password_strength(new_pw)
    if not pw_ok:
        return jsonify({"success": False, "error": pw_msg}), 400
    if current == new_pw:
        return jsonify({"success": False, "error": "New password must differ from current."}), 400

    try:
        conn = get_db()
        try:
            row = conn.execute("SELECT password FROM users WHERE email=?", (email,)).fetchone()
            if not row or not verify_password(current, row["password"]):
                return jsonify({"success": False, "error": "Current password is incorrect."}), 403
            conn.execute("UPDATE users SET password=? WHERE email=?", (hash_password(new_pw), email))
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        print(f"[AUTH] change-password error: {e}")
        return jsonify({"success": False, "error": "Database error."}), 500

    return jsonify({"success": True, "message": "Password changed successfully."})


# --- REGISTER - Step 1: Request OTP ------------------------------------------

@auth_bp.route("/register/request-otp", methods=["POST"])
def api_register_request_otp():
    """
    Validate signup fields and send OTP to the requested email.
    Anyone can call this (no auth required) - account is NOT created yet.
    """
    data     = request.get_json(silent=True) or {}
    name     = (data.get("display_name") or data.get("name") or "").strip()
    email    = (data.get("email") or "").strip().lower()
    password = data.get("password", "").strip()
    role     = data.get("role", DEFAULT_ROLE)

    if not email or not password:
        return jsonify({"success": False, "error": "Email and password are required."}), 400
    pw_ok, pw_msg = validate_password_strength(password)
    if not pw_ok:
        return jsonify({"success": False, "error": pw_msg}), 400

    # Check email not already taken
    try:
        conn = get_db()
        try:
            existing = conn.execute(
                "SELECT id FROM users WHERE email=?", (email,)
            ).fetchone()
        finally:
            conn.close()
        if existing:
            return jsonify({"success": False, "error": "An account with this email already exists."}), 400
    except Exception as e:
        print(f"[AUTH] register check error: {e}")
        return jsonify({"success": False, "error": "Database error."}), 500

    # Store pending registration data in OTP record so step-2 can create the user
    otp = create_otp(f"register:{email}", extra={
        "name":     name or email,
        "email":    email,
        "password": password,
        "role":     role,
    })
    sent = send_otp_email(email, otp, name or email, subject="PacketGuard - Verify Your Email")

    if not sent:
        print(f"[OTP-DEV] Register OTP for {email}: {otp}")
        return jsonify({
            "success": True,
            "dev_warning": "SMTP not configured - OTP printed to server console.",
        })

    return jsonify({"success": True})


# --- REGISTER - Step 2: Verify OTP + Create Account -------------------------

@auth_bp.route("/register", methods=["POST"])
def api_register():
    """
    Verify OTP from registration flow, then create the user and log them in.
    Falls back to admin-only direct creation if 'otp' field is absent
    (preserves backward-compat for admin user management panel).
    """
    data = request.get_json(silent=True) or {}
    otp  = (data.get("otp") or "").strip()

    # -- Admin direct-create path (no OTP, must be authenticated admin) -------
    if not otp:
        token = _get_token()
        actor = validate_session(token) if token else None
        if not actor or actor.get("role") != "admin":
            return jsonify({"success": False, "error": "OTP verification required."}), 403

        name     = data.get("display_name") or data.get("username") or ""
        email    = data.get("email") or data.get("username") or ""
        password = data.get("password", "")
        role     = data.get("role", DEFAULT_ROLE)

        if not email or not password:
            return jsonify({"success": False, "error": "Email and password are required."}), 400

        ok, message = create_user(name or email, email, password, role)
        return jsonify({"success": ok, ("message" if ok else "error"): message}), (201 if ok else 400)

    # -- Normal OTP signup path ------------------------------------------------
    email = (data.get("email") or "").strip().lower()
    if not email:
        return jsonify({"success": False, "error": "Email is required."}), 400

    valid, err, record = verify_otp(f"register:{email}", otp)
    if not valid:
        return jsonify({"success": False, "error": err}), 401

    # Check if this is the very first user - if so, make them admin
    try:
        conn = get_db()
        try:
            user_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        finally:
            conn.close()
    except Exception:
        user_count = 1  # safe fallback - don't accidentally grant admin

    is_first_user = (user_count == 0)

    # First user bootstraps as admin and skips approval (someone has to be
    # around to approve everyone else's requests).
    if is_first_user:
        ok, message = create_user(
            record.get("name", email),
            record.get("email", email),
            record.get("password", ""),
            "admin",
        )
        if not ok:
            return jsonify({"success": False, "error": message}), 400

        send_welcome_admin_email(email, record.get("name", ""))

        user = authenticate_user(email, record["password"])
        if not user:
            return jsonify({"success": True, "message": "Account created. Please log in."}), 201
        token = create_session(user["id"])
        return _make_session_response(user, token)

    # Everyone else goes into the approval queue — no account or session yet.
    ok, message = create_account_request(
        record.get("name", email),
        record.get("email", email),
        record.get("password", ""),
        record.get("role", DEFAULT_ROLE),
    )
    if not ok:
        return jsonify({"success": False, "error": message}), 400
    return jsonify({"success": True, "pending": True, "message": message}), 201


# --- PASSWORD RESET - Step 1: Send OTP ---------------------------------------

@auth_bp.route("/reset/request-otp", methods=["POST"])
def api_reset_request_otp():
    data  = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    if not email:
        return jsonify({"success": False, "error": "Email is required."}), 400
    try:
        conn = get_db()
        try:
            row = conn.execute("SELECT id, name FROM users WHERE email=?", (email,)).fetchone()
        finally:
            conn.close()
    except Exception as e:
        print(f"[AUTH] reset-otp DB error: {e}")
        return jsonify({"success": False, "error": "Database error."}), 500

    if not row:
        return jsonify({"success": False, "error": "No account found with that email."}), 404

    otp  = create_otp(f"reset:{email}")
    sent = send_otp_email(email, otp, row["name"], subject="PacketGuard - Password Reset Code")
    if not sent:
        print(f"[OTP-DEV] Reset OTP for {email}: {otp}")
        return jsonify({"success": True, "dev_warning": "SMTP not configured - OTP printed to console."})
    return jsonify({"success": True})


# --- PASSWORD RESET - Step 2: Verify OTP -------------------------------------

# In-memory store for verified reset tokens {email: timestamp}
import time as _time
_reset_verified = {}

@auth_bp.route("/reset/verify-otp", methods=["POST"])
def api_reset_verify_otp():
    data  = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    otp   = (data.get("otp") or "").strip()
    if not email or not otp:
        return jsonify({"success": False, "error": "Email and OTP are required."}), 400

    valid, err, _ = verify_otp(f"reset:{email}", otp)
    if not valid:
        return jsonify({"success": False, "error": err}), 401

    _reset_verified[email] = _time.time()
    return jsonify({"success": True})


# --- PASSWORD RESET - Step 3: Set New Password --------------------------------

@auth_bp.route("/reset/set-password", methods=["POST"])
def api_reset_set_password():
    data     = request.get_json(silent=True) or {}
    email    = (data.get("email") or "").strip().lower()
    new_pw   = data.get("new_password", "").strip()
    confirm  = data.get("confirm_password", "").strip()

    if not email or not new_pw or not confirm:
        return jsonify({"success": False, "error": "All fields are required."}), 400
    if new_pw != confirm:
        return jsonify({"success": False, "error": "Passwords do not match."}), 400
    pw_ok, pw_msg = validate_password_strength(new_pw)
    if not pw_ok:
        return jsonify({"success": False, "error": pw_msg}), 400

    # Check OTP was verified within last 10 minutes
    verified_at = _reset_verified.get(email)
    if not verified_at or (_time.time() - verified_at) > 600:
        return jsonify({"success": False, "error": "Session expired. Please start over."}), 401
    del _reset_verified[email]

    try:
        conn = get_db()
        try:
            conn.execute("UPDATE users SET password=? WHERE email=?", (hash_password(new_pw), email))
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        print(f"[AUTH] reset set-password error: {e}")
        return jsonify({"success": False, "error": "Database error."}), 500

    return jsonify({"success": True, "message": "Password reset successfully."})


# --- LIST USERS (admin only) --------------------------------------------------

@auth_bp.route("/users", methods=["GET"])
@admin_required
def api_list_users():
    return jsonify({"success": True, "users": get_all_users()})


# --- DELETE USER (admin only) -------------------------------------------------

@auth_bp.route("/users/<int:user_id>", methods=["DELETE"])
@admin_required
def api_delete_user(user_id: int):
    current = _current_user()
    try:
        conn = get_db()
        try:
            row = conn.execute("SELECT id FROM users WHERE id=?", (user_id,)).fetchone()
        finally:
            conn.close()
        if row and row["id"] == current.get("id"):
            return jsonify({"success": False, "error": "You cannot delete your own account."}), 403
    except Exception:
        pass
    _delete_user_by_id(user_id)
    return jsonify({"success": True, "message": "User deleted."})


# --- ACCOUNT REQUESTS (admin only) --------------------------------------------

@auth_bp.route("/account-requests", methods=["GET"])
@admin_required
def api_list_account_requests():
    return jsonify({"success": True, "requests": list_account_requests()})


@auth_bp.route("/account-requests/<int:req_id>/review", methods=["POST"])
@admin_required
def api_review_account_request(req_id: int):
    admin  = _current_user()
    data   = request.get_json(silent=True) or {}
    action = (data.get("action") or "").strip().lower()
    note   = (data.get("note") or "").strip()

    if action not in ("approve", "reject"):
        return jsonify({"success": False, "error": "action must be 'approve' or 'reject'."}), 400

    ok, message = review_account_request(req_id, admin, action, note)
    return jsonify({"success": ok, ("message" if ok else "error"): message}), (200 if ok else 400)


# --- GOOGLE OAUTH -------------------------------------------------------------

import os as _os
from authlib.integrations.flask_client import OAuth as _OAuth

_oauth = _OAuth()
_google = None

def _get_google():
    global _google
    if _google is None:
        from config import app as _app
        _oauth.init_app(_app)
        client_id     = _os.environ.get("GOOGLE_CLIENT_ID", "")
        client_secret = _os.environ.get("GOOGLE_CLIENT_SECRET", "")
        if not client_id or not client_secret:
            raise RuntimeError(
                "Google OAuth requires GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET env vars."
            )
        _google = _oauth.register(
            name="google",
            client_id=client_id,
            client_secret=client_secret,
            server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
            client_kwargs={"scope": "openid email profile"},
        )
    return _google


@auth_bp.route("/google/login")
def google_login():
    from flask import url_for, redirect
    redirect_uri = url_for("auth.google_callback", _external=True)
    return _get_google().authorize_redirect(redirect_uri)


@auth_bp.route("/google/callback")
def google_callback():
    from flask import redirect
    try:
        token = _get_google().authorize_access_token()
        info  = token.get("userinfo") or _get_google().userinfo()
        email = (info.get("email") or "").strip().lower()
        name  = info.get("name") or email.split("@")[0]
    except Exception as e:
        print(f"[GOOGLE] OAuth error: {e}")
        return redirect("/?error=google_failed")

    if not email:
        return redirect("/?error=no_email")

    # Get or create user in DB
    try:
        conn = get_db()
        try:
            row = conn.execute("SELECT id,name,email,role FROM users WHERE email=?", (email,)).fetchone()
            if not row:
                conn.execute(
                    "INSERT INTO users (name,email,password,role,created_at) VALUES (?,?,?,?,?)",
                    (name, email, "", "analyst", datetime.now(timezone.utc).isoformat())
                )
                conn.commit()
                row = conn.execute("SELECT id,name,email,role FROM users WHERE email=?", (email,)).fetchone()
        finally:
            conn.close()
    except Exception as e:
        print(f"[GOOGLE] DB error: {e}")
        return redirect("/?error=db_error")

    user = dict(row)

    # Issue OTP and redirect to OTP verification page
    otp  = create_otp(f"google:{email}", extra={"user_id": user["id"], "name": user["name"]})
    sent = send_otp_email(email, otp, user["name"])
    if not sent:
        print(f"[GOOGLE-OTP] OTP for {email}: {otp}")

    # Redirect to OTP page, passing email as query param
    from flask import redirect as _redirect
    import urllib.parse
    return _redirect(f"/?google_otp=1&email={urllib.parse.quote(email)}")


@auth_bp.route("/google/verify-otp", methods=["POST"])
def google_verify_otp():
    """Verify OTP issued after Google OAuth callback, then create session."""
    data  = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    otp   = (data.get("otp")   or "").strip()

    if not email or not otp:
        return jsonify({"success": False, "error": "Email and OTP are required."}), 400

    valid, err, record = verify_otp(f"google:{email}", otp)
    if not valid:
        return jsonify({"success": False, "error": err}), 401

    # Update last_login
    try:
        conn = get_db()
        try:
            conn.execute("UPDATE users SET last_login=? WHERE email=?",
                         (datetime.now(timezone.utc).isoformat(), email))
            conn.commit()
            user_row = conn.execute(
                "SELECT id,name,email,role FROM users WHERE email=?", (email,)
            ).fetchone()
        finally:
            conn.close()
    except Exception as e:
        print(f"[GOOGLE-OTP] DB error: {e}")
        return jsonify({"success": False, "error": "Database error."}), 500

    if not user_row:
        return jsonify({"success": False, "error": "User not found."}), 404
    user  = dict(user_row)
    token = create_session(user["id"])
    resp  = make_response(jsonify({
        "success":  True,
        "redirect": "/dashboard",
        "user": {"name": user["name"], "email": user["email"], "role": user["role"]},
    }))
    resp.set_cookie(SESSION_COOKIE, token,
                    max_age=SESSION_DURATION_HOURS * 3600,
                    httponly=True, samesite="Lax")
    return resp
