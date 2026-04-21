#!/usr/bin/env python3
"""
Alert Simulator — adds realistic HIGH/CRITICAL alerts to alerts.json
every 15 seconds so dashboard notifications fire automatically.

Run alongside live_monitor.py for demo purposes:
  python code/alert_simulator.py

Press Ctrl+C to stop.
"""

import json
import os
import time
import random
from datetime import datetime, timezone

BASE_DIR    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ALERTS_FILE = os.path.join(BASE_DIR, "alerts.json")

ATTACK_TEMPLATES = [
    {
        "alert_type": "PORT_SCAN",
        "severity": "HIGH",
        "message": "Port scan detected from {ip}: {n} unique ports in 60s",
        "source_ips": ["185.220.101.45", "45.142.212.100", "194.165.16.11", "103.75.190.5"],
    },
    {
        "alert_type": "SYN_FLOOD",
        "severity": "CRITICAL",
        "message": "SYN flood detected from {ip}: {n} SYN packets in 10s",
        "source_ips": ["45.142.212.100", "91.108.56.130", "185.234.218.52"],
    },
    {
        "alert_type": "HIGH_PACKET_RATE",
        "severity": "HIGH",
        "message": "High packet rate from {ip}: {n} pkt/s",
        "source_ips": ["192.168.1.105", "10.0.0.44", "172.16.0.9"],
    },
    {
        "alert_type": "BRUTE_FORCE",
        "severity": "CRITICAL",
        "message": "SSH brute force from {ip}: {n} failed attempts in 30s",
        "source_ips": ["194.165.16.11", "45.33.32.156", "198.199.100.9"],
    },
    {
        "alert_type": "DNS_TUNNELING",
        "severity": "HIGH",
        "message": "Suspicious DNS queries from {ip}: {n} queries in 5s",
        "source_ips": ["192.168.1.108", "10.0.0.55"],
    },
]


def load_alerts():
    try:
        with open(ALERTS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def save_alerts(alerts):
    with open(ALERTS_FILE, "w", encoding="utf-8") as f:
        json.dump(alerts, f, indent=2)


def generate_alert():
    tmpl = random.choice(ATTACK_TEMPLATES)
    ip   = random.choice(tmpl["source_ips"])
    n    = random.randint(20, 150)
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "alert_type": tmpl["alert_type"],
        "severity": tmpl["severity"],
        "message": tmpl["message"].format(ip=ip, n=n),
        "source_ip": ip,
        "destination_ip": f"192.168.1.{random.randint(1, 10)}",
        "additional_info": {"simulated": True},
    }


def main():
    print("[SIMULATOR] Starting alert simulator...")
    print("[SIMULATOR] Adding a HIGH/CRITICAL alert every 15 seconds.")
    print("[SIMULATOR] Press Ctrl+C to stop.\n")

    while True:
        alert = generate_alert()
        alerts = load_alerts()
        alerts.append(alert)
        save_alerts(alerts)
        print(f"[+] Added {alert['severity']} alert: {alert['message']}")
        time.sleep(15)


if __name__ == "__main__":
    main()
