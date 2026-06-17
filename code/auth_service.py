"""
auth_service.py - PacketGuard authentication service
DB init, password hashing/verification, OTP store, email sending.
"""
import hashlib
import json
import secrets
import smtplib
import sqlite3
import threading
import time
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from config import DB_PATH, SMTP_EMAIL, SMTP_PASSWORD

# -- Werkzeug password hashing -------------------------------------
try:
    from werkzeug.security import generate_password_hash, check_password_hash
    _USE_WERKZEUG = True
    print("[AUTH] Using werkzeug password hashing (pbkdf2:sha256).")
except ImportError:
    _USE_WERKZEUG = False
    print("[AUTH] Werkzeug not found - falling back to hashlib pbkdf2.")

# -- DB connection -------------------------------------------------
def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=5)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn

def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            name       TEXT NOT NULL,
            email      TEXT NOT NULL UNIQUE,
            password   TEXT NOT NULL,
            role       TEXT NOT NULL DEFAULT 'analyst',
            created_at TEXT NOT NULL,
            last_login TEXT
        )
    """)
    conn.commit()
    conn.close()
    # Default admin creation is handled by auth.py's init_db() to avoid duplicate accounts.

# -- Password helpers ----------------------------------------------
def hash_password(pw: str) -> str:
    if _USE_WERKZEUG:
        return generate_password_hash(pw, method="pbkdf2:sha256")
    salt = secrets.token_hex(16)
    dk   = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 260000)
    return f"pbkdf2$sha256${salt}${dk.hex()}"

def verify_password(pw: str, stored: str) -> bool:
    try:
        if stored.startswith("pbkdf2:"):
            return check_password_hash(stored, pw) if _USE_WERKZEUG else False
        if stored.startswith("pbkdf2$"):
            _, _algo, salt, stored_hex = stored.split("$")
            dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 260000)
            return dk.hex() == stored_hex
        if stored.startswith("$2"):
            try:
                import bcrypt as _bcrypt
                return _bcrypt.checkpw(pw.encode(), stored.encode())
            except ImportError:
                print("[AUTH] bcrypt not installed - cannot verify legacy hash.")
                return False
        return False
    except Exception as e:
        print(f"[AUTH] verify error: {e}")
        return False

# -- OTP store -----------------------------------------------------
_otp_store: dict = {}
_otp_lock = threading.Lock()

def create_otp(key: str, extra: dict = None) -> str:
    code = str(100000 + secrets.randbelow(900000))
    entry = {"otp": code, "expires": time.time() + 300}
    if extra:
        entry.update(extra)
    with _otp_lock:
        _otp_store[key] = entry
    return code

def verify_otp(key: str, code: str) -> tuple[bool, str, dict]:
    """Returns (valid, error_msg, entry)."""
    with _otp_lock:
        record = _otp_store.get(key)
    if not record:
        return False, "No OTP pending. Please start again.", {}
    if time.time() > record["expires"]:
        with _otp_lock:
            _otp_store.pop(key, None)
        return False, "OTP expired. Please try again.", {}
    if code != record["otp"]:
        return False, "Invalid OTP code. Try again.", {}
    with _otp_lock:
        _otp_store.pop(key, None)
    return True, "", record

# -- OTP email -----------------------------------------------------
def send_otp_email(to_email: str, otp: str, name: str, subject: str = "PacketGuard - Your Login Code") -> bool:
    if not SMTP_PASSWORD:
        print("[2FA] SMTP_PASSWORD is not set. Configure via SMTP_PASSWORD env var.")
        return False
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = f"PacketGuard Security <{SMTP_EMAIL}>"
        msg["To"]      = to_email
        html = f"""<div style="font-family:monospace;background:#060e18;color:#c0d4ee;padding:32px;border-radius:12px;max-width:480px;margin:auto;border:1px solid rgba(0,200,255,.2)">
          <div style="color:#00c8ff;font-size:18px;font-weight:700;letter-spacing:3px;margin-bottom:8px">PACKETGUARD</div>
          <div style="color:#3a5570;font-size:11px;margin-bottom:24px">Network Threat Detection System</div>
          <div style="margin-bottom:16px">Hello <b style="color:#fff">{name}</b>,</div>
          <div style="margin-bottom:24px;color:#a0b4c8">Your one-time login code:</div>
          <div style="background:#0d1117;border:2px solid rgba(0,200,255,.3);border-radius:10px;padding:20px;text-align:center;margin-bottom:24px">
            <div style="font-size:36px;font-weight:700;letter-spacing:10px;color:#00c8ff">{otp}</div>
            <div style="color:#3a5570;font-size:11px;margin-top:8px">Valid for 5 minutes</div>
          </div>
          <div style="color:#3a5570;font-size:11px">If you did not request this, ignore this email.</div>
        </div>"""
        msg.attach(MIMEText(html, "html"))
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.ehlo()
            server.starttls()
            server.login(SMTP_EMAIL, SMTP_PASSWORD)
            server.sendmail(SMTP_EMAIL, to_email, msg.as_string())
        print(f"[2FA] OTP sent to {to_email}")
        return True
    except Exception as e:
        print(f"[2FA] Email error: {e}")
        return False
