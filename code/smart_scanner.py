#!/usr/bin/env python3
"""
smart_scanner.py — Real-time ARP-based device monitor
======================================================
Instead of polling every N seconds, this module:
  1. Runs an initial ARP broadcast to discover all current devices
  2. Passively sniffs ALL ARP packets on the network continuously
  3. Any ARP seen from a device → marked online immediately (< 1 second)
  4. No ARP from a device for OFFLINE_TIMEOUT seconds → marked offline instantly
  5. Writes network_devices.json atomically after every change

Result: device joins/leaves are reflected on the dashboard in under 2 seconds,
with zero polling delay.
"""

import json
import os
import socket
import struct
import subprocess
import sys
import threading
import time
from datetime import datetime

BASE_DIR    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_FILE = os.path.join(BASE_DIR, "network_devices.json")

# How long (seconds) with no ARP traffic before a device is marked offline.
# Phones sleep and go quiet for 30-60 s between ARP packets, so 10 s was
# causing constant flapping (connect → remove → connect).  90 s is the
# minimum that reliably stops phone flapping while still detecting true
# disconnects within ~2 minutes.
OFFLINE_TIMEOUT = 90

# Lock protecting _devices dict
_lock    = threading.Lock()
_devices = {}   # ip -> device dict
_running = False


# ── Helpers ────────────────────────────────────────────────────────────────────

def _get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def _get_gateway_ip():
    try:
        if sys.platform == "win32":
            out = subprocess.check_output(
                ["route", "print", "0.0.0.0"], stderr=subprocess.DEVNULL
            ).decode(errors="ignore")
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 3 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                    return parts[2]
    except Exception:
        pass
    local = _get_local_ip()
    return ".".join(local.split(".")[:3]) + ".1"


def _get_subnet_cidr(local_ip):
    parts = local_ip.split(".")
    return ".".join(parts[:3]) + ".0/24"


def _resolve_hostname(ip, timeout=0.5):
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""
    finally:
        socket.setdefaulttimeout(None)


def _guess_vendor(mac):
    """Minimal OUI lookup — full table is in network_scanner.py."""
    try:
        from network_scanner import guess_vendor
        return guess_vendor(mac)
    except Exception:
        return "Unknown"


def _fingerprint(ip, mac, hostname, vendor, is_gateway):
    if is_gateway:
        return {"device_type": "Router", "icon": "\U0001f310", "confidence": "High"}
    try:
        from network_scanner import fingerprint_device
        return fingerprint_device(ip, mac, hostname, vendor)
    except Exception:
        return {"device_type": "Unknown", "icon": "❓", "confidence": "Low"}


def _save():
    """Write current device list to network_devices.json atomically."""
    local_ip   = _get_local_ip()
    gateway_ip = _get_gateway_ip()
    with _lock:
        devs = list(_devices.values())

    # Sort: gateway first, then local, then by IP
    def _sort_key(d):
        try:
            return (not d.get("is_gateway"), not d.get("is_local"),
                    struct.unpack("!I", socket.inet_aton(d["ip"]))[0])
        except Exception:
            return (True, True, 0)

    devs.sort(key=_sort_key)
    output = {
        "scan_time":     datetime.now().isoformat(),
        "local_ip":      local_ip,
        "gateway_ip":    gateway_ip,
        "network_range": _get_subnet_cidr(local_ip),
        "total_found":   len(devs),
        "devices":       devs,
    }
    tmp = OUTPUT_FILE + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2)
        try:
            os.remove(OUTPUT_FILE)
        except OSError:
            pass
        os.replace(tmp, OUTPUT_FILE)
    except Exception as e:
        print(f"[SmartScanner] Save error: {e}")


def _make_device(ip, mac, local_ip, gateway_ip):
    hostname   = _resolve_hostname(ip)
    is_local   = (ip == local_ip)
    is_gateway = (ip == gateway_ip)
    vendor     = _guess_vendor(mac)
    fp         = _fingerprint(ip, mac, hostname, vendor, is_gateway)
    return {
        "ip":          ip,
        "mac":         mac if mac else "Unknown",
        "hostname":    hostname or ("This Device" if is_local else ("Router/Gateway" if is_gateway else "Unknown")),
        "vendor":      vendor,
        "device_type": fp["device_type"],
        "icon":        fp["icon"],
        "confidence":  fp["confidence"],
        "is_local":    is_local,
        "is_gateway":  is_gateway,
        "last_seen":   datetime.now().isoformat(),
        "online":      True,
    }


# ── ARP sniffer ────────────────────────────────────────────────────────────────

def _on_arp(pkt):
    """Called for every ARP packet seen on the network."""
    try:
        from scapy.layers.l2 import ARP as ScapyARP
        if not pkt.haslayer(ScapyARP):
            return
        arp  = pkt[ScapyARP]
        ip   = arp.psrc
        mac  = arp.hwsrc.upper()

        # Ignore broadcast/empty
        if not ip or ip == "0.0.0.0" or mac in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"):
            return

        local_ip   = _get_local_ip()
        gateway_ip = _get_gateway_ip()

        # Only track devices on our subnet
        subnet = ".".join(local_ip.split(".")[:3]) + "."
        if not ip.startswith(subnet):
            return

        # Ignore ARP packets where source MAC matches our own MAC but IP is not ours.
        # (Windows sends gratuitous ARPs that can create ghost entries for other IPs.)
        # We look up our MAC from _devices if already known, to avoid any dependency
        # on an external call at handler time.
        with _lock:
            local_dev = _devices.get(local_ip)
            local_mac = local_dev.get("mac") if local_dev else None
        if local_mac and local_mac not in ("Unknown", "", "00:00:00:00:00:00"):
            if mac == local_mac and ip != local_ip:
                return

        changed = False
        with _lock:
            if ip in _devices:
                # Update last_seen and mac if we now have it
                _devices[ip]["last_seen"] = datetime.now().isoformat()
                _devices[ip]["online"]    = True
                if mac and mac != "00:00:00:00:00:00" and _devices[ip].get("mac") in ("Unknown", "", None):
                    _devices[ip]["mac"] = mac
                    changed = True
                if not _devices[ip].get("online_prev", True):
                    changed = True  # was offline, now back online
                _devices[ip]["online_prev"] = True
            else:
                # New device — build full record
                dev = _make_device(ip, mac, local_ip, gateway_ip)
                dev["online_prev"] = True
                _devices[ip] = dev
                changed = True
                print(f"[SmartScanner] NEW device: {ip} ({mac})")

        if changed:
            _save()
    except Exception as e:
        print(f"[SmartScanner] ARP handler error: {e}")


def _offline_watcher():
    """Every second, REMOVE devices if last_seen > OFFLINE_TIMEOUT — never mark offline."""
    while _running:
        time.sleep(1)
        now        = time.time()
        changed    = False
        local_ip   = _get_local_ip()
        gateway_ip = _get_gateway_ip()
        with _lock:
            to_remove = []
            for ip, dev in _devices.items():
                # Never remove the local machine or the gateway — always
                # refresh their timestamps so they stay permanently online.
                if dev.get("is_local") or dev.get("is_gateway") or ip == local_ip or ip == gateway_ip:
                    dev["last_seen"] = datetime.now().isoformat()
                    dev["online"]    = True
                    continue
                try:
                    last = datetime.fromisoformat(dev["last_seen"]).timestamp()
                except Exception:
                    last = now  # if timestamp is bad, keep the device
                if (now - last) >= OFFLINE_TIMEOUT:
                    to_remove.append(ip)
            for ip in to_remove:
                print(f"[SmartScanner] {ip} -> REMOVED (offline)")
                del _devices[ip]
                changed = True
        if changed:
            _save()


def _initial_arp_sweep(local_ip, gateway_ip):
    """One-time ARP broadcast at startup to populate the device list."""
    try:
        from scapy.all import ARP, Ether, srp, conf
        conf.verb = 0
        subnet    = ".".join(local_ip.split(".")[:3]) + ".0/24"
        print(f"[SmartScanner] Initial ARP sweep on {subnet} ...")
        answered, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet),
            timeout=3, retry=1, verbose=False, multi=True
        )
        with _lock:
            for _, received in answered:
                ip  = received.psrc
                mac = received.hwsrc.upper()
                if ip and ip not in _devices:
                    dev = _make_device(ip, mac, local_ip, gateway_ip)
                    dev["online_prev"] = True
                    _devices[ip] = dev
        # Always ensure the local machine is in the list, even if ARP missed it
        with _lock:
            if local_ip not in _devices:
                import subprocess, re as _re
                local_mac = ""
                try:
                    out = subprocess.check_output(
                        ["arp", "-a", local_ip], stderr=subprocess.DEVNULL
                    ).decode(errors="ignore")
                    m = _re.search(r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}", out)
                    if m:
                        local_mac = m.group(0).upper().replace("-", ":")
                except Exception:
                    pass
                dev = _make_device(local_ip, local_mac, local_ip, gateway_ip)
                dev["online_prev"] = True
                _devices[local_ip] = dev
                print(f"[SmartScanner] Local device added: {local_ip}")

        print(f"[SmartScanner] Initial sweep done — {len(_devices)} device(s) found.")
        _save()
    except Exception as e:
        print(f"[SmartScanner] Initial sweep error: {e}")


class SmartScanner:
    @staticmethod
    def start():
        global _running
        if _running:
            return
        _running = True

        try:
            from scapy.all import sniff, ARP, conf
            conf.verb = 0
        except ImportError:
            raise ImportError("Scapy not installed")

        local_ip   = _get_local_ip()
        gateway_ip = _get_gateway_ip()

        # 1. Initial sweep in background (doesn't block startup)
        threading.Thread(
            target=_initial_arp_sweep,
            args=(local_ip, gateway_ip),
            daemon=True, name="SmartScanner-Sweep"
        ).start()

        # 2. Offline watcher — marks devices offline after OFFLINE_TIMEOUT seconds
        threading.Thread(
            target=_offline_watcher,
            daemon=True, name="SmartScanner-OfflineWatcher"
        ).start()

        # 3. Passive ARP sniffer — runs forever, calls _on_arp for every ARP packet
        def _sniff_loop():
            print(f"[SmartScanner] Passive ARP sniffer started (offline timeout: {OFFLINE_TIMEOUT}s)")
            while _running:
                try:
                    sniff(filter="arp", prn=_on_arp, store=False, timeout=10)
                except Exception as e:
                    print(f"[SmartScanner] Sniffer error: {e} — restarting in 2s")
                    time.sleep(2)

        threading.Thread(
            target=_sniff_loop,
            daemon=True, name="SmartScanner-Sniffer"
        ).start()

        print(f"[SmartScanner] Started. Local: {local_ip} | Gateway: {gateway_ip}")