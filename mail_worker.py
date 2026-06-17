#!/usr/bin/env python3
"""
mail_worker.py — PacketGuard email queue processor.

Run this in a SECOND terminal WITHOUT administrator:
    cd "d:\\network-analyzer-project jeeeeeeeeee"
    python mail_worker.py

The main app (running as admin) cannot reach Gmail SMTP due to elevated-process
firewall restrictions. This worker runs non-elevated and sends queued emails
using the same Gmail credentials from code/env.

Keep this running alongside start.py. Ctrl+C to stop.
"""
import os, sys, sqlite3, smtplib, time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH  = os.path.join(BASE_DIR, "code", "packetguard.db")
sys.path.insert(0, os.path.join(BASE_DIR, "code"))


def _load_env():
    env_path = os.path.join(BASE_DIR, "code", "env")
    if not os.path.exists(env_path):
        return
    with open(env_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip()
            if key and key not in os.environ:
                os.environ[key] = val

_load_env()

SMTP_USER = os.environ.get("SMTP_EMAIL", "")
SMTP_PASS = os.environ.get("SMTP_PASSWORD", "")
SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")


def _resolve_ipv4(host, port):
    import socket
    try:
        infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
        if infos:
            return infos[0][4][0]
    except Exception:
        pass
    return host


def _send(to_email, subject, plain, html):
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = f"PacketGuard Security <{SMTP_USER}>"
    msg["To"]      = to_email
    msg.attach(MIMEText(plain, "plain", "utf-8"))
    msg.attach(MIMEText(html,  "html",  "utf-8"))
    raw = msg.as_string()

    for port, use_ssl in [(587, False), (465, True)]:
        try:
            ipv4 = _resolve_ipv4(SMTP_HOST, port)
            if use_ssl:
                class _SMTP_SSL_IPv4(smtplib.SMTP_SSL):
                    def _get_socket(self, h, p, timeout):
                        import socket as _sock
                        conn = _sock.create_connection((ipv4, p), timeout=timeout)
                        return self._context.wrap_socket(conn, server_hostname=self._host)
                s = _SMTP_SSL_IPv4(SMTP_HOST, port, timeout=20)
                s.ehlo()
            else:
                s = smtplib.SMTP(ipv4, port, timeout=20)
                s._host = SMTP_HOST
                s.ehlo(); s.starttls(); s.ehlo()
            s.login(SMTP_USER, SMTP_PASS)
            s.sendmail(SMTP_USER, to_email, raw)
            s.quit()
            return True
        except Exception as e:
            print(f"  [port {port}] {type(e).__name__}: {e}")
    return False


def process_queue():
    if not os.path.exists(DB_PATH):
        return
    try:
        conn = sqlite3.connect(DB_PATH, timeout=10)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT id, to_email, subject, body_plain, body_html "
            "FROM email_queue WHERE status='pending' ORDER BY created_at LIMIT 10"
        ).fetchall()
    except Exception as e:
        print(f"[WORKER] DB read error: {e}")
        return

    for row in rows:
        print(f"[WORKER] Sending to {row['to_email']} — {row['subject']!r}")
        ok = _send(row["to_email"], row["subject"], row["body_plain"], row["body_html"])
        status = "sent" if ok else "failed"
        print(f"[WORKER] {'OK' if ok else 'FAILED'}")
        try:
            conn.execute(
                "UPDATE email_queue SET status=?, sent_at=unixepoch('now') WHERE id=?",
                (status, row["id"]),
            )
            conn.commit()
        except Exception:
            pass
    conn.close()


def main():
    if not SMTP_USER or not SMTP_PASS:
        print("[WORKER] ERROR: SMTP_EMAIL / SMTP_PASSWORD not set in code/env")
        sys.exit(1)

    print(f"""
+----------------------------------------------------------+
|  PacketGuard Mail Worker                                 |
|  Sending as: {SMTP_USER:<40s}|
|  DB: {os.path.basename(DB_PATH):<48s}|
|  Press Ctrl+C to stop                                    |
+----------------------------------------------------------+
""")

    # Verify SMTP works before entering the loop
    print("[WORKER] Testing Gmail SMTP connection...")
    try:
        _ipv4 = _resolve_ipv4(SMTP_HOST, 587)
        s = smtplib.SMTP(_ipv4, 587, timeout=15)
        s._host = SMTP_HOST
        s.ehlo(); s.starttls(); s.ehlo()
        s.login(SMTP_USER, SMTP_PASS)
        s.quit()
        print("[WORKER] SMTP OK — ready to deliver queued emails.\n")
    except Exception as e:
        print(f"[WORKER] SMTP test failed: {e}")
        print("[WORKER] Check SMTP_EMAIL and SMTP_PASSWORD in code/env, then restart.")
        sys.exit(1)

    print("[WORKER] Watching email queue (checks every 5 s)...\n")
    while True:
        try:
            process_queue()
        except KeyboardInterrupt:
            print("\n[WORKER] Stopped.")
            break
        except Exception as e:
            print(f"[WORKER] Unexpected error: {e}")
        time.sleep(5)


if __name__ == "__main__":
    main()
