# -*- coding: utf-8 -*-
"""
smtp_service.py -- PacketGuard
Sends OTP emails via Gmail SMTP.
"""

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

import os as _os

try:
    from config import SMTP_EMAIL as SMTP_USER, SMTP_PASSWORD as SMTP_PASS
except ImportError:
    SMTP_USER = _os.environ.get("SMTP_EMAIL", "")
    SMTP_PASS = _os.environ.get("SMTP_PASSWORD", "")

SMTP_HOST    = _os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT    = int(_os.environ.get("SMTP_PORT", "587"))
RESEND_KEY   = _os.environ.get("RESEND_API_KEY", "")
RESEND_FROM  = _os.environ.get("RESEND_FROM_EMAIL", f"PacketGuard <{SMTP_USER}>")


def _ensure_firewall_rules():
    """
    Add Windows Firewall outbound ALLOW rules for SMTP ports.
    Called once at import time — silently skipped on non-Windows or non-admin.
    Running as Administrator is required (PacketGuard already does this).
    """
    import subprocess, sys
    if sys.platform != "win32":
        return
    for port, name in [(587, "PacketGuard-SMTP-587"), (465, "PacketGuard-SMTP-465")]:
        try:
            # Skip if rule already exists
            check = subprocess.run(
                ["netsh", "advfirewall", "firewall", "show", "rule", f"name={name}"],
                capture_output=True, text=True,
            )
            if "No rules match" not in check.stdout and check.returncode == 0:
                continue
            subprocess.run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={name}",
                "protocol=TCP", "dir=out",
                f"remoteport={port}",
                "action=allow", "profile=any", "enable=yes",
            ], capture_output=True, check=True)
            print(f"[SMTP] Firewall: added outbound allow rule for port {port}")
        except Exception:
            pass  # Non-admin or unsupported — silently skip


_ensure_firewall_rules()


def _resolve_ipv4(host, port):
    """Return the first IPv4 address for host:port, or host if none found."""
    import socket
    try:
        infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
        if infos:
            return infos[0][4][0]
    except Exception:
        pass
    return host


def _send_starttls(host, user, password, to, raw):
    """Connect on port 587 with STARTTLS, forced to IPv4 to avoid WinError 10051."""
    import socket
    ipv4 = _resolve_ipv4(host, 587)
    with smtplib.SMTP(ipv4, 587, timeout=15) as s:
        s._host = host          # restore hostname so starttls() uses it for SNI/cert
        s.ehlo(); s.starttls(); s.ehlo()
        s.login(user, password)
        s.sendmail(user, to, raw)


def _send_ssl(host, user, password, to, raw):
    """Connect on port 465 with implicit SSL, forced to IPv4 to avoid WinError 10051."""
    import socket
    ipv4 = _resolve_ipv4(host, 465)

    class _SMTP_SSL_IPv4(smtplib.SMTP_SSL):
        def _get_socket(self, h, p, timeout):
            # connect to IPv4 address but wrap SSL using self._host (original hostname)
            sock = socket.create_connection((ipv4, p), timeout=timeout)
            return self._context.wrap_socket(sock, server_hostname=self._host)

    with _SMTP_SSL_IPv4(host, 465, timeout=15) as s:
        s.ehlo()
        s.login(user, password)
        s.sendmail(user, to, raw)


def _send_via_subprocess(to_email: str, raw: str) -> bool:
    """Python subprocess — gets a fresh socket context."""
    import subprocess, sys, base64, json
    script = (
        "import sys, smtplib, base64, json, socket\n"
        "d = json.loads(base64.b64decode(sys.argv[1]))\n"
        "def ipv4(h,p):\n"
        "    try:\n"
        "        r=socket.getaddrinfo(h,p,socket.AF_INET,socket.SOCK_STREAM)\n"
        "        return r[0][4][0] if r else h\n"
        "    except: return h\n"
        "errors = []\n"
        "for method in ['starttls', 'ssl']:\n"
        "    try:\n"
        "        if method == 'starttls':\n"
        "            s = smtplib.SMTP(ipv4(d['host'],587), 587, timeout=15)\n"
        "            s._host=d['host']; s.ehlo(); s.starttls(); s.ehlo()\n"
        "        else:\n"
        "            s = smtplib.SMTP_SSL(ipv4(d['host'],465), 465, timeout=15)\n"
        "            s._host=d['host']; s.ehlo()\n"
        "        s.login(d['user'], d['pw'])\n"
        "        s.sendmail(d['user'], d['to'], d['raw'])\n"
        "        s.quit()\n"
        "        print('OK:' + method)\n"
        "        sys.exit(0)\n"
        "    except Exception as e:\n"
        "        errors.append(method + ':' + str(e))\n"
        "print('FAIL:' + '|'.join(errors))\n"
        "sys.exit(1)\n"
    )
    payload = base64.b64encode(json.dumps({
        "host": SMTP_HOST, "user": SMTP_USER, "pw": SMTP_PASS,
        "to": to_email, "raw": raw,
    }).encode()).decode()
    try:
        r = subprocess.run(
            [sys.executable, "-c", script, payload],
            capture_output=True, text=True, timeout=60,
        )
        out = r.stdout.strip()
        if out.startswith("OK:"):
            return True
        print(f"[SMTP] subprocess result: {out or r.stderr.strip()}")
        return False
    except Exception as e:
        print(f"[SMTP] subprocess failed: {e}")
        return False


def _send_via_powershell(to_email: str, subject: str, body: str) -> bool:
    """
    PowerShell .NET SmtpClient — completely different network stack.
    Works when Python sockets are blocked by Windows security for elevated processes.
    Credentials passed via environment variables (never appear in process list).
    """
    import subprocess, os
    ps = (
        "$u=$env:_PG_U; $p=$env:_PG_P; $t=$env:_PG_T; "
        "$s=$env:_PG_S; $b=$env:_PG_B; "
        "try { "
        "  $c=New-Object Net.Mail.SmtpClient('smtp.gmail.com',587); "
        "  $c.EnableSsl=$true; $c.Timeout=20000; "
        "  $c.Credentials=New-Object Net.NetworkCredential($u,$p); "
        "  $m=New-Object Net.Mail.MailMessage($u,$t,$s,$b); "
        "  $c.Send($m); Write-Output 'OK' "
        "} catch { Write-Output ('FAIL:'+$_.Exception.Message) }"
    )
    env = os.environ.copy()
    env.update({
        "_PG_U": SMTP_USER, "_PG_P": SMTP_PASS,
        "_PG_T": to_email,  "_PG_S": subject, "_PG_B": body,
    })
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True, text=True, timeout=30, env=env,
        )
        out = (r.stdout or "").strip()
        if out == "OK":
            return True
        print(f"[SMTP] PowerShell result: {out or r.stderr.strip()}")
        return False
    except Exception as e:
        print(f"[SMTP] PowerShell failed: {e}")
        return False


def _queue_email(to_email: str, subject: str, plain: str, html: str) -> None:
    """Write email to the DB queue so mail_worker.py (non-elevated) can send it."""
    import sqlite3, time
    db = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "packetguard.db")
    try:
        with sqlite3.connect(db, timeout=10) as conn:
            conn.execute(
                "INSERT INTO email_queue "
                "(to_email, subject, body_plain, body_html, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (to_email, subject, plain, html, time.time()),
            )
            conn.commit()
        print(f"[SMTP] Queued email to {to_email} — mail_worker.py will send it")
    except Exception as e:
        print(f"[SMTP] Queue write failed: {e}")


def _send_via_resend(to_email: str, subject: str, html: str, plain: str) -> bool:
    """
    Send via Resend.com HTTP API (port 443 — works even when SMTP ports are blocked).
    Requires RESEND_API_KEY in code/env.  Free tier: 3 000 emails/month.
    Sign up at https://resend.com  (takes ~2 minutes, no credit card).
    """
    if not RESEND_KEY:
        return False
    try:
        import urllib.request, json as _json
        payload = _json.dumps({
            "from":    RESEND_FROM,
            "to":      [to_email],
            "subject": subject,
            "html":    html,
            "text":    plain,
        }).encode()
        req = urllib.request.Request(
            "https://api.resend.com/emails",
            data=payload,
            headers={
                "Authorization": f"Bearer {RESEND_KEY}",
                "Content-Type":  "application/json",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status in (200, 201)
    except Exception as e:
        print(f"[SMTP] Resend API failed: {type(e).__name__}: {e}")
        return False


def _queue_email_to_db(to_email: str, subject: str, plain: str, html: str) -> bool:
    """
    Write email to the email_queue table so mail_worker.py (non-elevated) can send it.
    Returns True if queued successfully.
    """
    import sqlite3, os
    db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "packetguard.db")
    try:
        conn = sqlite3.connect(db_path, timeout=10)
        conn.execute(
            "INSERT INTO email_queue (to_email, subject, body_plain, body_html) "
            "VALUES (?, ?, ?, ?)",
            (to_email, subject, plain, html),
        )
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"[SMTP] DB queue failed: {e}")
        return False


def send_otp_email(to_email: str, otp: str, name: str = "", subject: str = "PacketGuard - Your Login Code") -> bool:
    display = name or to_email

    plain = (
        f"Hello {display},\n\n"
        f"Your PacketGuard one-time login code is:\n\n"
        f"    {otp}\n\n"
        f"This code is valid for 5 minutes.\n"
        f"If you did not request this, ignore this email.\n\n"
        f"-- PacketGuard Security"
    )

    html = f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#f4f6f8;font-family:'Courier New',monospace;">
  <table width="100%" cellpadding="0" cellspacing="0">
    <tr>
      <td align="center" style="padding:40px 16px;">
        <table width="480" cellpadding="0" cellspacing="0"
               style="background:#ffffff;border-radius:12px;
                      border:1px solid #dde3ea;overflow:hidden;">

          <!-- Header -->
          <tr>
            <td style="padding:32px 40px 24px;border-bottom:1px solid #eef0f3;">
              <p style="margin:0;font-size:13px;font-weight:700;
                        letter-spacing:3px;color:#1a7fc1;">PACKETGUARD</p>
              <p style="margin:6px 0 0;font-size:11px;letter-spacing:1px;
                        color:#90a0b0;">Network Threat Detection System</p>
            </td>
          </tr>

          <!-- Body -->
          <tr>
            <td style="padding:32px 40px;">
              <p style="margin:0 0 8px;font-size:14px;color:#2c3e50;">
                Hello <strong>{display}</strong>,
              </p>
              <p style="margin:0 0 28px;font-size:14px;color:#2c3e50;">
                Your one-time login code:
              </p>

              <!-- OTP Box -->
              <table width="100%" cellpadding="0" cellspacing="0">
                <tr>
                  <td align="center"
                      style="background:#f0f7fd;border:1px solid #c8dff0;
                             border-radius:8px;padding:28px 20px;">
                    <p style="margin:0;font-size:42px;font-weight:700;
                              letter-spacing:16px;color:#1a7fc1;
                              font-family:'Courier New',monospace;">
                      {otp}
                    </p>
                    <p style="margin:10px 0 0;font-size:11px;
                              letter-spacing:1px;color:#90a0b0;">
                      Valid for 5 minutes
                    </p>
                  </td>
                </tr>
              </table>

              <p style="margin:28px 0 0;font-size:12px;color:#90a0b0;">
                If you did not request this, ignore this email.
              </p>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = f"PacketGuard Security <{SMTP_USER}>"
    msg["To"]      = to_email
    # Plain text MUST come before HTML (spam filters prefer it, RFC 2046)
    msg.attach(MIMEText(plain, "plain", "utf-8"))
    msg.attach(MIMEText(html,  "html",  "utf-8"))

    raw = msg.as_string()
    errors = []

    # 1. Resend HTTPS API first if key is configured (port 443 — never blocked by ISP)
    if RESEND_KEY:
        if _send_via_resend(to_email, subject, html, plain):
            print(f"[SMTP] OTP sent to {to_email} via Resend API")
            return True

    # 2. Try direct STARTTLS / SSL (IPv4-forced to avoid WinError 10051)
    for method, fn in [("587/STARTTLS", _send_starttls), ("465/SSL", _send_ssl)]:
        try:
            fn(SMTP_HOST, SMTP_USER, SMTP_PASS, to_email, raw)
            print(f"[SMTP] OTP sent to {to_email} via {method}")
            return True
        except smtplib.SMTPAuthenticationError as e:
            print(f"[SMTP] Auth failed — check SMTP_EMAIL/SMTP_PASSWORD in code/env: {e}")
            return False
        except smtplib.SMTPRecipientsRefused as e:
            print(f"[SMTP] Recipient refused ({to_email}): {e}")
            return False
        except Exception as e:
            errors.append(f"{method}: {type(e).__name__}: {e}")

    # 3. Direct methods failed — try subprocess (fresh socket context)
    print(f"[SMTP] Direct methods failed ({'; '.join(errors)}) — trying subprocess...")
    if _send_via_subprocess(to_email, raw):
        print(f"[SMTP] OTP sent to {to_email} via subprocess")
        return True

    # 4. Subprocess also blocked — use PowerShell .NET SmtpClient (different stack)
    print("[SMTP] Subprocess failed — trying PowerShell .NET SmtpClient...")
    if _send_via_powershell(to_email, subject, plain):
        print(f"[SMTP] OTP sent to {to_email} via PowerShell")
        return True

    # 5. All SMTP methods blocked — use Resend HTTPS API (port 443, never blocked)
    print("[SMTP] PowerShell failed — trying Resend HTTPS API...")
    if _send_via_resend(to_email, subject, html, plain):
        print(f"[SMTP] OTP sent to {to_email} via Resend API")
        return True

    # 5. Queue for the non-elevated mail worker (python mail_worker.py)
    _queue_email(to_email, subject, plain, html)
    print("[SMTP] All direct methods blocked — email queued for mail_worker.py")
    print("[SMTP] Run in a separate non-admin terminal:  python mail_worker.py")
    return False


def send_welcome_admin_email(to_email: str, name: str = "") -> bool:
    """Send a welcome email to the first user who becomes admin."""
    display = name or to_email

    html = f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#f4f6f8;font-family:'Courier New',monospace;">
  <table width="100%" cellpadding="0" cellspacing="0">
    <tr>
      <td align="center" style="padding:40px 16px;">
        <table width="480" cellpadding="0" cellspacing="0"
               style="background:#ffffff;border-radius:12px;
                      border:1px solid #dde3ea;overflow:hidden;">

          <!-- Header -->
          <tr>
            <td style="padding:32px 40px 24px;border-bottom:1px solid #eef0f3;">
              <p style="margin:0;font-size:13px;font-weight:700;
                        letter-spacing:3px;color:#1a7fc1;">PACKETGUARD</p>
              <p style="margin:6px 0 0;font-size:11px;letter-spacing:1px;
                        color:#90a0b0;">Network Threat Detection System</p>
            </td>
          </tr>

          <!-- Body -->
          <tr>
            <td style="padding:32px 40px;">
              <p style="margin:0 0 8px;font-size:14px;color:#2c3e50;">
                Hello <strong>{display}</strong>,
              </p>
              <p style="margin:0 0 20px;font-size:14px;color:#2c3e50;">
                You are the <strong>first user</strong> on PacketGuard -
                your account has been automatically granted <strong>Admin</strong> privileges.
              </p>

              <!-- Warning box -->
              <table width="100%" cellpadding="0" cellspacing="0">
                <tr>
                  <td style="background:#fff8e6;border:1px solid #f0d080;
                             border-radius:8px;padding:20px 24px;">
                    <p style="margin:0;font-size:13px;color:#7a5c00;font-weight:700;
                              letter-spacing:1px;">
                      &#9888; ACTION REQUIRED
                    </p>
                    <p style="margin:10px 0 0;font-size:13px;color:#7a5c00;">
                      Please log in and change your password immediately
                      from your profile settings to keep your account secure.
                    </p>
                  </td>
                </tr>
              </table>

              <p style="margin:28px 0 0;font-size:12px;color:#90a0b0;">
                If you did not create this account, please contact your system administrator.
              </p>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""

    plain_welcome = (
        f"Hello {display},\n\n"
        f"You are the first user on PacketGuard — your account has been "
        f"automatically granted Admin privileges.\n\n"
        f"ACTION REQUIRED: Please log in and change your password immediately "
        f"from your profile settings to keep your account secure.\n\n"
        f"If you did not create this account, contact your system administrator.\n\n"
        f"-- PacketGuard Security"
    )

    msg = MIMEMultipart("alternative")
    _WELCOME_SUBJECT = "PacketGuard - Welcome, Admin!"
    msg["Subject"] = _WELCOME_SUBJECT
    msg["From"]    = f"PacketGuard Security <{SMTP_USER}>"
    msg["To"]      = to_email
    msg.attach(MIMEText(plain_welcome, "plain", "utf-8"))
    msg.attach(MIMEText(html, "html", "utf-8"))

    raw = msg.as_string()
    for method, fn in [("587/STARTTLS", _send_starttls), ("465/SSL", _send_ssl)]:
        try:
            fn(SMTP_HOST, SMTP_USER, SMTP_PASS, to_email, raw)
            print(f"[SMTP] Welcome email sent to {to_email} via {method}")
            return True
        except smtplib.SMTPAuthenticationError as e:
            print(f"[SMTP] Auth failed: {e}")
            return False
        except Exception as e:
            print(f"[SMTP] {method} failed: {type(e).__name__}: {e}")

    if _send_via_subprocess(to_email, raw):
        print(f"[SMTP] Welcome email sent to {to_email} via subprocess")
        return True
    if _send_via_powershell(to_email, _WELCOME_SUBJECT, plain_welcome):
        print(f"[SMTP] Welcome email sent to {to_email} via PowerShell")
        return True
    if _send_via_resend(to_email, _WELCOME_SUBJECT, html, plain_welcome):
        print(f"[SMTP] Welcome email sent to {to_email} via Resend API")
        return True
    _queue_email(to_email, _WELCOME_SUBJECT, plain_welcome, html)
    return False
