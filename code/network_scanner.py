#!/usr/bin/env python3
"""
Network Device Scanner - Aggressive Mode
Finds ALL connected devices including sleeping phones using ARP broadcast.
Devices do NOT need to open any app — just being connected is enough.
Run as Administrator for best results.
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

try:
    from scapy.all import ARP, Ether, srp, conf, get_if_list
    conf.verb = 0
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

BASE_DIR    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_FILE = os.path.join(BASE_DIR, "network_devices.json")


# ── Helpers ───────────────────────────────────────────────────────────────────

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


<<<<<<< HEAD
def get_gateway_ip():
    """Get the default gateway IP (the router)."""
    try:
        if sys.platform == "win32":
            out = subprocess.check_output(["route", "print", "0.0.0.0"],
                stderr=subprocess.DEVNULL).decode(errors="ignore")
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 3 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                    return parts[2]
        else:
            out = subprocess.check_output(["ip", "route"],
                stderr=subprocess.DEVNULL).decode(errors="ignore")
            for line in out.splitlines():
                if line.startswith("default"):
                    parts = line.split()
                    if len(parts) >= 3:
                        return parts[2]
    except Exception:
        pass
    # Fallback: assume .1 is the gateway
    local = get_local_ip()
    return ".".join(local.split(".")[:3]) + ".1"


=======
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
def ip_to_int(ip):
    return struct.unpack("!I", socket.inet_aton(ip))[0]


def get_subnet_range(local_ip, prefix=24):
    parts = local_ip.split(".")
    network = ".".join(parts[:3]) + ".0"
    hosts   = [f"{'.'.join(parts[:3])}.{i}" for i in range(1, 255)]
    return network, hosts


def resolve_hostname(ip, timeout=1.0):
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""
    finally:
        socket.setdefaulttimeout(None)


def get_mac_from_arp_cache(ip):
    try:
        if sys.platform == "win32":
            out = subprocess.check_output(["arp", "-a", ip], stderr=subprocess.DEVNULL).decode(errors="ignore")
            for line in out.splitlines():
                if ip in line:
                    for p in line.split():
                        if "-" in p and len(p) == 17:
                            return p.replace("-", ":").upper()
                        if ":" in p and len(p) == 17:
                            return p.upper()
        else:
            out = subprocess.check_output(["arp", "-n", ip], stderr=subprocess.DEVNULL).decode(errors="ignore")
            for line in out.splitlines():
                if ip in line:
                    for p in line.split():
                        if ":" in p and len(p) >= 11:
                            return p.upper()
    except Exception:
        pass
    return ""


# ── Method 1: Aggressive ARP broadcast (main method) ─────────────────────────

def scan_arp_aggressive(network_cidr):
    """
    Send ARP broadcast packets to every IP in the subnet.
    Every device that is connected to the network MUST reply to ARP
    to maintain its network connection — even sleeping phones.
    Uses retry=3 and timeout=6 for maximum coverage.
    """
    print(f"  [ARP] Broadcasting ARP to {network_cidr} (retry x3, timeout 6s) ...")
    try:
        answered, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network_cidr),
<<<<<<< HEAD
            timeout=3,
            retry=1,        # single retry — keeps scan fast so file stays fresh
=======
            timeout=6,
            retry=3,        # retry 3 times for slow/sleeping devices
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
            verbose=False,
            multi=True      # capture multiple replies per IP
        )
        results = []
        seen = set()
        for sent, received in answered:
            ip  = received.psrc
            mac = received.hwsrc.upper()
            if ip not in seen:
                seen.add(ip)
                results.append({"ip": ip, "mac": mac})
        print(f"  [ARP] {len(results)} device(s) replied to ARP broadcast.")
        return results
    except Exception as e:
        print(f"  [ARP] ARP scan failed: {e}")
        return []


# ── Method 2: Read full OS ARP table ─────────────────────────────────────────

def get_full_arp_table(local_ip):
    """
<<<<<<< HEAD
    Read the entire Windows/Linux ARP table.
    Parses 'arp -a' output and returns only real unicast LAN devices:
    - must be in the same /24 subnet
    - must be a dynamic entry (not static/multicast/broadcast)
    - must have a valid unicast MAC (not ff:ff:ff:ff:ff:ff or 01:xx multicast)
=======
    Read the entire Windows ARP table.
    This catches any device that has communicated recently,
    even if it didn't reply to our broadcast directly.
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
    """
    entries = []
    try:
        out = subprocess.check_output(["arp", "-a"], stderr=subprocess.DEVNULL).decode(errors="ignore")
        subnet_prefix = ".".join(local_ip.split(".")[:3]) + "."
        for line in out.splitlines():
            parts = line.split()
<<<<<<< HEAD
            # Windows: "  IP   MAC   Type"  — need at least 3 parts
            # Linux:   "IP  (IP)  at  MAC  [ether]  on  iface"
            if len(parts) < 2:
                continue

            ip  = parts[0].strip()
            mac = parts[1].strip()

            # Must be in our subnet
            if not ip.startswith(subnet_prefix):
                continue

            # Skip broadcast / network addresses
            last = ip.split(".")[-1]
            if last in ("0", "255"):
                continue

            # Skip multicast IP range (224.x.x.x and above)
            try:
                if int(ip.split(".")[0]) >= 224:
                    continue
            except Exception:
                continue

            # On Windows, parts[2] is the type — skip static entries
            if len(parts) >= 3 and parts[2].strip().lower() == "static":
                continue

            # Normalise MAC: accept dash or colon format, must be 17 chars
            if "-" in mac and len(mac) == 17:
                mac = mac.replace("-", ":").upper()
            elif ":" in mac and len(mac) == 17:
                mac = mac.upper()
            else:
                continue  # not a valid MAC

            # Skip broadcast and multicast MACs
            if mac in ("FF:FF:FF:FF:FF:FF",):
                continue
            if mac.startswith("01:") or mac.startswith("33:33:"):
                continue

            entries.append({"ip": ip, "mac": mac})

    except Exception as e:
        print(f"  [ARP TABLE] Error reading ARP table: {e}")
    print(f"  [ARP TABLE] {len(entries)} real device(s) found in OS ARP cache.")
=======
            if len(parts) >= 2:
                ip  = parts[0].strip()
                mac = parts[1].strip()
                if not ip.startswith(subnet_prefix):
                    continue
                if ip.endswith(".255") or ip.endswith(".0"):
                    continue
                if "-" in mac and len(mac) == 17:
                    mac = mac.replace("-", ":").upper()
                    entries.append({"ip": ip, "mac": mac})
                elif ":" in mac and len(mac) == 17:
                    entries.append({"ip": ip, "mac": mac.upper()})
    except Exception as e:
        print(f"  [ARP TABLE] Error reading ARP table: {e}")
    print(f"  [ARP TABLE] {len(entries)} entries found in OS ARP cache.")
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
    return entries


# ── Method 3: Ping sweep fallback ─────────────────────────────────────────────

def ping_sweep(hosts, local_ip):
    """
    Fallback ping sweep when scapy isn't available.
    Uses 250 parallel threads for speed.
    """
    print(f"  [PING] Fallback ping sweep ({len(hosts)} hosts) ...")
    lock  = threading.Lock()
    alive = []

    def check(ip):
        try:
            if sys.platform == "win32":
                r = subprocess.run(["ping", "-n", "1", "-w", "800", ip],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                r = subprocess.run(["ping", "-c", "1", "-W", "1", ip],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if r.returncode == 0:
                with lock:
                    alive.append(ip)
        except Exception:
            pass

    batch_size = 250
    for i in range(0, len(hosts), batch_size):
        chunk   = hosts[i:i + batch_size]
        threads = [threading.Thread(target=check, args=(ip,), daemon=True) for ip in chunk]
        for t in threads: t.start()
        for t in threads: t.join(timeout=4)

    print(f"  [PING] {len(alive)} host(s) responded to ping.")
    return [{"ip": ip, "mac": get_mac_from_arp_cache(ip)} for ip in alive]


# ── Method 4: Force ARP cache population via netsh ───────────────────────────

def force_arp_population(hosts):
    """
    On Windows, send UDP packets to every host to force the OS
    to send ARP requests and cache the responses.
    This is a background method that runs in parallel with ARP scan.
    """
    def send_udp(ip):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.1)
            s.sendto(b'\x00', (ip, 1))
            s.close()
        except Exception:
            pass

    print(f"  [UDP] Sending UDP probes to populate ARP cache ...")
    threads = [threading.Thread(target=send_udp, args=(ip,), daemon=True) for ip in hosts]
    for t in threads: t.start()
    for t in threads: t.join(timeout=2)


# ── Merge all results ─────────────────────────────────────────────────────────

def merge_results(sources, local_ip):
    seen = {}
    for entry in sources:
        ip  = entry.get("ip", "").strip()
        mac = entry.get("mac", "").strip()
        if not ip:
            continue
        if ip not in seen:
            seen[ip] = {"ip": ip, "mac": mac}
        elif mac and mac != "Unknown" and (not seen[ip]["mac"] or seen[ip]["mac"] == "Unknown"):
            seen[ip]["mac"] = mac

    if local_ip not in seen:
        seen[local_ip] = {"ip": local_ip, "mac": get_mac_from_arp_cache(local_ip)}

    return list(seen.values())


# ── Main scan ─────────────────────────────────────────────────────────────────

def scan_network():
<<<<<<< HEAD
    local_ip   = get_local_ip()
    gateway_ip = get_gateway_ip()
=======
    local_ip = get_local_ip()
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
    network, hosts = get_subnet_range(local_ip)
    network_cidr   = f"{network}/24"

    print(f"""
+-----------------------------------------------------------+
|     Network Device Scanner  (Aggressive ARP Mode)        |
|  Finds ALL devices - no app needed, works while sleeping  |
+-----------------------------------------------------------+

  Local IP : {local_ip}
  Network  : {network_cidr}
  Method   : ARP Broadcast + ARP Cache + UDP Probe
""")

    all_found = []

    # Run UDP probes + ARP cache read in parallel while ARP scan runs
    udp_thread = threading.Thread(target=force_arp_population, args=(hosts,), daemon=True)
    udp_thread.start()

    if SCAPY_OK:
        # Primary: aggressive ARP broadcast
        arp_results = scan_arp_aggressive(network_cidr)
        all_found.extend(arp_results)

<<<<<<< HEAD
    # Always: send UDP probes to populate the OS ARP table, then read it.
    # This catches devices that filter ARP broadcasts (phones in sleep mode etc.)
    # UDP probes run in parallel so total time is not increased.
    udp_thread.join(timeout=4)
    arp_cache = get_full_arp_table(local_ip)
    all_found.extend(arp_cache)

    if not SCAPY_OK:
        print("  [INFO] Scapy not available — using ARP cache + ping fallback.")
        ping_results = ping_sweep(hosts, local_ip)
        all_found.extend(ping_results)
=======
        # Wait for UDP probes to finish then read ARP cache
        udp_thread.join(timeout=3)
        time.sleep(1)  # let OS ARP cache settle
        arp_table = get_full_arp_table(local_ip)
        all_found.extend(arp_table)
    else:
        print("  [INFO] Scapy not available — using ping + ARP cache fallback.")
        udp_thread.join(timeout=3)
        time.sleep(1)
        ping_results = ping_sweep(hosts, local_ip)
        arp_table    = get_full_arp_table(local_ip)
        all_found.extend(ping_results)
        all_found.extend(arp_table)
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b

    # Merge and deduplicate
    found = merge_results(all_found, local_ip)
    print(f"\n  [MERGE] {len(found)} unique device(s) found total.")

    # Resolve hostnames
    print(f"  [DNS] Resolving hostnames ...")
    devices = []
    for entry in found:
        ip       = entry["ip"]
        mac      = entry.get("mac", "") or ""
        hostname = resolve_hostname(ip)
<<<<<<< HEAD
        is_local      = (ip == local_ip)
        is_gateway    = (ip == gateway_ip)
        vendor        = guess_vendor(mac)
        fp            = fingerprint_device(ip, mac, hostname, vendor)
        # Override device type for gateway
        if is_gateway and fp["device_type"] in ("Unknown", "Windows PC", "Linux/Android"):
            fp["device_type"] = "Router"
            fp["icon"]        = "🌐"  # globe
            fp["confidence"]  = "High"

        device = {
            "ip":          ip,
            "mac":         mac if mac else "Unknown",
            "hostname":    hostname if hostname else ("Router/Gateway" if is_gateway else ("This Device" if is_local else "Unknown")),
            "vendor":      vendor,
            "device_type": fp["device_type"],
            "icon":        fp["icon"],
            "confidence":  fp["confidence"],
            "is_local":    is_local,
            "is_gateway":  is_gateway,
            "last_seen":   datetime.now().isoformat(),
=======
        is_local = (ip == local_ip)

        device = {
            "ip":        ip,
            "mac":       mac if mac else "Unknown",
            "hostname":  hostname if hostname else ("This Device" if is_local else "Unknown"),
            "vendor":    guess_vendor(mac),
            "is_local":  is_local,
            "last_seen": datetime.now().isoformat(),
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
        }
        devices.append(device)

        flag = "  <-- THIS DEVICE" if is_local else ""
        print(f"    {ip:<18} {mac:<20} {hostname or 'Unknown':<30}{flag}")

    # Sort: local first, then by IP
    devices.sort(key=lambda d: (not d["is_local"], ip_to_int(d["ip"])))

<<<<<<< HEAD
    # Save to JSON — write to temp file then atomic rename so the dashboard
    # never sees an empty or half-written file during the scan.
    output = {
        "scan_time":     datetime.now().isoformat(),
        "local_ip":      local_ip,
        "gateway_ip":    gateway_ip,
=======
    # Save to JSON
    output = {
        "scan_time":     datetime.now().isoformat(),
        "local_ip":      local_ip,
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
        "network_range": network_cidr,
        "total_found":   len(devices),
        "devices":       devices,
    }
<<<<<<< HEAD
    tmp_file = OUTPUT_FILE + ".tmp"
    with open(tmp_file, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)
    # Windows: delete target first to avoid Access Denied on rename
    try:
        os.remove(OUTPUT_FILE)
    except OSError:
        pass
    os.replace(tmp_file, OUTPUT_FILE)
=======
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b

    print(f"""
+-----------------------------------------------------------+
  SCAN COMPLETE
  Found    : {len(devices)} device(s)
  Saved to : {OUTPUT_FILE}
+-----------------------------------------------------------+
""")
    print(f"  {'#':<4} {'IP Address':<18} {'MAC Address':<20} {'Vendor':<15} {'Hostname'}")
    print(f"  {'-'*4} {'-'*18} {'-'*20} {'-'*15} {'-'*25}")
    for i, d in enumerate(devices, 1):
        flag = " (*)" if d["is_local"] else ""
        print(f"  {i:<4} {d['ip']:<18} {d['mac']:<20} {d['vendor']:<15} {d['hostname']}{flag}")
    print(f"\n  (*) = This device\n")
    return devices


# ── Vendor OUI lookup ─────────────────────────────────────────────────────────

OUI_MAP = {
    # Samsung
    "00:16:32": "Samsung", "00:17:C9": "Samsung", "00:1A:8A": "Samsung",
    "00:1D:25": "Samsung", "00:1E:7D": "Samsung", "00:21:19": "Samsung",
    "00:23:39": "Samsung", "00:24:54": "Samsung", "00:26:37": "Samsung",
    "08:08:C2": "Samsung", "08:D4:2B": "Samsung", "0C:71:5D": "Samsung",
    "10:1D:C0": "Samsung", "10:D5:42": "Samsung", "14:49:E0": "Samsung",
    "18:22:7E": "Samsung", "18:26:49": "Samsung", "1C:62:B8": "Samsung",
    "20:64:32": "Samsung", "20:D3:90": "Samsung", "24:4B:03": "Samsung",
    "28:BA:B5": "Samsung", "2C:AE:2B": "Samsung", "30:07:4D": "Samsung",
    "34:BE:00": "Samsung", "38:2D:D1": "Samsung", "3C:62:00": "Samsung",
    "40:0E:85": "Samsung", "44:78:3E": "Samsung", "48:44:F7": "Samsung",
    "4C:3C:16": "Samsung", "50:01:BB": "Samsung", "50:32:75": "Samsung",
    "54:88:0E": "Samsung", "58:D3:49": "Samsung", "5C:49:79": "Samsung",
    "60:6B:FF": "Samsung", "64:B3:10": "Samsung", "68:27:37": "Samsung",
    "6C:2F:2C": "Samsung", "70:F9:27": "Samsung", "74:45:8A": "Samsung",
    "78:1F:DB": "Samsung", "7C:1C:4E": "Samsung", "84:25:DB": "Samsung",
    "88:32:9B": "Samsung", "8C:71:F8": "Samsung", "90:18:7C": "Samsung",
    "94:35:0A": "Samsung", "98:52:B1": "Samsung", "9C:3A:AF": "Samsung",
    "A0:07:98": "Samsung", "A4:EB:D3": "Samsung", "A8:06:00": "Samsung",
    "AC:5A:14": "Samsung", "B0:72:BF": "Samsung", "B4:3A:28": "Samsung",
    "B8:5E:7B": "Samsung", "BC:20:A4": "Samsung", "C0:97:27": "Samsung",
    "C4:42:02": "Samsung", "C8:BA:94": "Samsung", "CC:07:AB": "Samsung",
    "D0:22:BE": "Samsung", "D4:87:D8": "Samsung", "D8:57:EF": "Samsung",
    "DC:71:96": "Samsung", "E0:CB:EE": "Samsung", "E4:40:E2": "Samsung",
    "E8:9F:80": "Samsung", "EC:1F:72": "Samsung", "F0:25:B7": "Samsung",
    "F4:42:8F": "Samsung", "F8:04:2E": "Samsung", "FC:A1:3E": "Samsung",
    # Apple
    "00:1E:C2": "Apple",   "18:65:90": "Apple",   "3C:15:C2": "Apple",
    "A4:C3:61": "Apple",   "00:1E:64": "Apple",   "00:23:32": "Apple",
    "A8:66:7F": "Apple",   "AC:87:A3": "Apple",   "B8:E8:56": "Apple",
    "BC:52:B7": "Apple",   "C8:2A:14": "Apple",   "D0:03:DF": "Apple",
    "D8:1D:72": "Apple",   "DC:2B:2A": "Apple",   "E0:F8:47": "Apple",
    "E4:CE:8F": "Apple",   "E8:04:0B": "Apple",   "F0:D1:A9": "Apple",
    "F4:1B:A1": "Apple",   "F8:1E:DF": "Apple",   "F8:FF:C2": "Apple",
    # Huawei
    "FC:F8:AE": "Huawei",  "00:E0:FC": "Huawei",  "00:18:82": "Huawei",
    "04:C0:6F": "Huawei",  "08:19:A6": "Huawei",  "0C:37:DC": "Huawei",
    "10:1B:54": "Huawei",  "10:47:80": "Huawei",  "14:A5:1A": "Huawei",
    "18:C5:8A": "Huawei",  "1C:1D:67": "Huawei",  "20:08:ED": "Huawei",
    "24:09:95": "Huawei",  "28:31:52": "Huawei",  "2C:AB:00": "Huawei",
    "30:87:30": "Huawei",  "34:6B:D3": "Huawei",  "38:37:8B": "Huawei",
    "3C:47:11": "Huawei",  "40:4D:8E": "Huawei",  "44:55:B1": "Huawei",
    "48:AD:08": "Huawei",  "4C:8B:EF": "Huawei",  "50:01:D4": "Huawei",
    "54:89:98": "Huawei",  "58:2A:F7": "Huawei",  "5C:4C:A9": "Huawei",
    "60:DE:44": "Huawei",  "64:16:F0": "Huawei",  "68:CC:6E": "Huawei",
    "6C:8D:C1": "Huawei",  "70:72:3C": "Huawei",  "74:A0:2F": "Huawei",
    "78:1D:BA": "Huawei",  "7C:1C:F1": "Huawei",
    # Xiaomi
    "00:9E:C8": "Xiaomi",  "0C:1D:AF": "Xiaomi",  "10:2A:B3": "Xiaomi",
    "14:F6:5A": "Xiaomi",  "18:59:36": "Xiaomi",  "20:82:C0": "Xiaomi",
    "28:6C:07": "Xiaomi",  "34:80:B3": "Xiaomi",  "38:A4:ED": "Xiaomi",
    "3C:BD:D8": "Xiaomi",  "40:31:3C": "Xiaomi",  "4C:49:E3": "Xiaomi",
    "50:64:2B": "Xiaomi",  "58:44:98": "Xiaomi",  "5C:E8:EB": "Xiaomi",
    "64:09:80": "Xiaomi",  "64:CC:2E": "Xiaomi",  "68:DF:DD": "Xiaomi",
    "6C:5A:B0": "Xiaomi",  "74:23:44": "Xiaomi",  "78:11:DC": "Xiaomi",
    "7C:1E:52": "Xiaomi",  "8C:BE:BE": "Xiaomi",  "98:FA:E3": "Xiaomi",
    "9C:99:A0": "Xiaomi",  "A0:86:C6": "Xiaomi",  "AC:C1:EE": "Xiaomi",
    "B0:E2:35": "Xiaomi",  "B4:0B:44": "Xiaomi",  "B8:2C:A0": "Xiaomi",
    "C4:0B:CB": "Xiaomi",  "C8:14:79": "Xiaomi",  "D4:97:0B": "Xiaomi",
    "F0:B4:29": "Xiaomi",  "F4:8B:32": "Xiaomi",  "F8:A4:5F": "Xiaomi",
    "FC:64:BA": "Xiaomi",
    # Oppo / OnePlus
    "00:1A:4B": "Oppo",    "04:D9:F5": "Oppo",    "1C:77:F6": "Oppo",
    "2C:6F:C9": "Oppo",    "34:14:5F": "Oppo",    "3C:28:6D": "Oppo",
    "48:73:CB": "Oppo",    "74:EE:2A": "Oppo",    "88:C9:D0": "Oppo",
    "8C:0D:76": "Oppo",    "90:B6:86": "Oppo",    "A4:50:46": "Oppo",
    "AC:3B:77": "Oppo",    "5E:0A:5B": "OnePlus",
    # TP-Link
    "78:4F:43": "TP-Link", "EC:08:6B": "TP-Link", "50:C7:BF": "TP-Link",
    "10:FE:ED": "TP-Link", "C0:4A:00": "TP-Link", "18:D6:C7": "TP-Link",
    "BC:46:99": "TP-Link", "F4:EC:38": "TP-Link", "14:CC:20": "TP-Link",
    "30:DE:4B": "TP-Link", "48:8A:D2": "TP-Link", "54:AF:97": "TP-Link",
    "60:32:B1": "TP-Link", "64:70:02": "TP-Link", "6C:5C:14": "TP-Link",
    "74:DA:38": "TP-Link", "90:F6:52": "TP-Link", "94:D9:B3": "TP-Link",
    "A0:F3:C1": "TP-Link", "AC:84:C9": "TP-Link", "B0:48:7A": "TP-Link",
    "B4:B0:24": "TP-Link", "C4:6E:1F": "TP-Link", "D8:0D:17": "TP-Link",
    "E8:DE:27": "TP-Link", "F0:A7:31": "TP-Link",
    # IoT / Smart Home chips
    "DC:29:19": "AltoBeam-IoT",
    "18:FE:34": "Espressif-IoT",
    "24:0A:C4": "Espressif-IoT",
    "30:AE:A4": "Espressif-IoT",
    "A4:CF:12": "Espressif-IoT",
    "84:F3:EB": "Espressif-IoT",
    "CC:50:E3": "Espressif-IoT",
    "10:52:1C": "Espressif-IoT",
    "BC:DD:C2": "Espressif-IoT",
    "80:7D:3A": "Espressif-IoT",
    "3C:71:BF": "Espressif-IoT",
    "68:C6:3A": "Espressif-IoT",
    "94:B9:7E": "Espressif-IoT",
    "AC:67:B2": "Espressif-IoT",
    "48:3F:DA": "Espressif-IoT",
    # Others
    "00:50:56": "VMware",         "00:0C:29": "VMware",
    "00:15:5D": "Microsoft",      "08:00:27": "VirtualBox",
    "B8:27:EB": "Raspberry Pi",   "DC:A6:32": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",   "00:1A:11": "Google",
    "F4:F5:D8": "Google",         "AC:37:43": "HTC",
    "00:E0:4C": "Realtek",        "52:54:00": "QEMU/KVM",
    "00:1B:21": "Intel",          "00:21:6A": "Intel",
    "8C:8D:28": "Intel",          "94:C6:91": "Intel",
    "70:4D:7B": "Intel",          "00:26:B9": "Dell",
    "14:18:77": "Dell",           "D4:BE:D9": "Dell",
    "F8:DB:88": "Dell",           "00:1D:09": "Dell",
}

def guess_vendor(mac):
    if not mac or mac == "Unknown":
        return "Unknown"
    return OUI_MAP.get(mac[:8].upper(), "Unknown")


<<<<<<< HEAD
def fingerprint_device(ip, mac, hostname, vendor):
    """
    Identify device type using TTL, MAC vendor, hostname, and open ports.
    Returns a dict with device_type, icon, and confidence.
    """
    device_type = "Unknown"
    icon        = "❓"
    confidence  = "Low"
    clues       = []

    # ── 1. TTL-based OS fingerprint ──────────────────────────────
    try:
        import subprocess, platform
        cmd = ["ping", "-n", "1", "-w", "1000", ip] if platform.system() == "Windows" else ["ping", "-c", "1", "-W", "1", ip]
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=2).decode(errors="ignore")
        ttl = None
        for part in out.split():
            if "ttl=" in part.lower():
                ttl = int(part.lower().replace("ttl=", ""))
                break
        if ttl:
            if ttl <= 64:
                clues.append(("Linux/Android", 3))
            elif ttl <= 128:
                clues.append(("Windows", 3))
            elif ttl >= 200:
                clues.append(("Router/Network", 3))
    except Exception:
        pass

    # ── 2. Hostname pattern matching ─────────────────────────────
    h = (hostname or "").lower()
    if any(k in h for k in ["iphone", "apple", "mac", "macbook", "imac"]):
        clues.append(("Apple Device", 4))
    elif any(k in h for k in ["android", "samsung", "pixel", "huawei", "xiaomi", "oppo"]):
        clues.append(("Android Phone", 4))
    elif any(k in h for k in ["windows", "desktop", "pc", "laptop", "workstation"]):
        clues.append(("Windows PC", 4))
    elif any(k in h for k in ["router", "gateway", "dlink", "tplink", "netgear", "asus", "linksys", "cisco", "mikrotik"]):
        clues.append(("Router", 4))
    elif any(k in h for k in ["printer", "hp", "canon", "epson", "brother"]):
        clues.append(("Printer", 4))
    elif any(k in h for k in ["tv", "firetv", "roku", "chromecast", "appletv", "shield"]):
        clues.append(("Smart TV", 4))
    elif any(k in h for k in ["camera", "cam", "nvr", "dvr", "hikvision", "dahua"]):
        clues.append(("IP Camera", 4))
    elif any(k in h for k in ["raspberry", "pi", "arduino", "esp", "nodemcu"]):
        clues.append(("IoT Device", 4))

    # ── 3. MAC vendor matching ───────────────────────────────────
    v = (vendor or "").lower()
    if any(k in v for k in ["apple"]):
        clues.append(("Apple Device", 3))
    elif any(k in v for k in ["samsung"]):
        clues.append(("Android Phone", 3))
    elif any(k in v for k in ["intel", "realtek", "dell", "hp", "lenovo", "asus", "acer", "microsoft"]):
        clues.append(("Windows PC", 2))
    elif any(k in v for k in ["cisco", "netgear", "tp-link", "d-link", "zyxel", "ubiquiti", "mikrotik", "huawei"]):
        clues.append(("Router", 3))
    elif any(k in v for k in ["raspberry", "espressif", "arduino"]):
        clues.append(("IoT Device", 3))
    elif any(k in v for k in ["canon", "epson", "brother", "xerox", "ricoh"]):
        clues.append(("Printer", 3))
    elif any(k in v for k in ["lg", "sony", "vizio", "tcl", "hisense", "roku"]):
        clues.append(("Smart TV", 3))

    # ── 4. Quick port check ──────────────────────────────────────
    try:
        import socket
        # Port 9100 = printer, 5900 = VNC, 62078 = iPhone, 7000 = AirPlay
        probe_ports = {9100: ("Printer", 4), 62078: ("Apple Device", 4),
                       7000: ("Apple Device", 3), 5357: ("Windows PC", 3),
                       1900: ("Smart TV/IoT", 2), 8080: ("Router", 2)}
        for port, (ptype, weight) in probe_ports.items():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.3)
                if s.connect_ex((ip, port)) == 0:
                    clues.append((ptype, weight))
                s.close()
            except Exception:
                pass
    except Exception:
        pass

    # ── 5. Resolve best guess from clues ─────────────────────────
    if clues:
        scores = {}
        for dtype, weight in clues:
            scores[dtype] = scores.get(dtype, 0) + weight
        device_type = max(scores, key=scores.get)
        top_score   = scores[device_type]
        confidence  = "High" if top_score >= 6 else "Medium" if top_score >= 3 else "Low"

    # ── 6. Assign icon ───────────────────────────────────────────
    icon_map = {
        "Windows PC":     "🖥️",
        "Linux/Android":  "🐧",
        "Apple Device":   "🍎",
        "Android Phone":  "📱",
        "Router":         "🌐",
        "Printer":        "🖨️",
        "Smart TV":       "📺",
        "Smart TV/IoT":   "📺",
        "IP Camera":      "📷",
        "IoT Device":     "🔌",
        "Unknown":        "❓",
    }
    icon = icon_map.get(device_type, "❓")

    return {
        "device_type": device_type,
        "icon":        icon,
        "confidence":  confidence,
    }


# ── Port Scanner ─────────────────────────────────────────────────────────────

PORT_SERVICES = {
    21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP", 53:"DNS", 67:"DHCP",
    68:"DHCP", 69:"TFTP", 80:"HTTP", 110:"POP3", 119:"NNTP", 123:"NTP",
    135:"MS-RPC", 139:"NetBIOS", 143:"IMAP", 161:"SNMP", 194:"IRC",
    389:"LDAP", 443:"HTTPS", 445:"SMB", 465:"SMTPS", 500:"IKE",
    514:"Syslog", 587:"SMTP", 631:"IPP", 636:"LDAPS", 993:"IMAPS",
    995:"POP3S", 1080:"SOCKS", 1194:"OpenVPN", 1433:"MSSQL", 1723:"PPTP",
    2049:"NFS", 2083:"cPanel", 2222:"SSH-Alt", 3306:"MySQL", 3389:"RDP",
    4444:"Metasploit", 5000:"UPnP", 5432:"PostgreSQL", 5900:"VNC",
    5985:"WinRM", 6379:"Redis", 6881:"BitTorrent", 7547:"CWMP",
    8080:"HTTP-Alt", 8443:"HTTPS-Alt", 8888:"HTTP-Alt",
    9200:"Elasticsearch", 27017:"MongoDB",
}

TOP_100_PORTS = [
    21,22,23,25,53,80,110,111,119,123,135,139,143,161,194,389,
    443,445,465,500,514,587,631,636,993,995,1080,1194,1433,1723,
    2049,2083,2222,3306,3389,4444,5000,5432,5900,5985,6379,6881,
    7547,8080,8443,8888,9200,27017,81,82,83,88,102,264,411,412,
    497,554,1025,1026,1027,1028,1029,1110,1720,1900,2000,2001,
    2002,4000,4001,4002,4100,4200,4343,4848,5001,5009,5060,5101,
    5357,5800,6000,6001,6006,6543,6789,7000,7001,7070,7080,7171,
    8000,8008,9000,9001,9090,9100,9999,10000,
]

def scan_ports(target_ip, scan_type="Standard (top 1000 ports)", timeout=0.5):
    """
    Scan ports on a target IP.
    Returns list of dicts: {port, service, status}
    """
    if "100" in scan_type and "1000" not in scan_type:
        ports = TOP_100_PORTS
    elif "65535" in scan_type or "Full" in scan_type:
        ports = list(range(1, 65536))
        timeout = 0.3
    else:
        ports = list(range(1, 1001))

    print(f"  [PORT SCAN] Scanning {len(ports)} ports on {target_ip} ...")
    results = []
    lock = threading.Lock()

    def check_port(port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            r = s.connect_ex((target_ip, port))
            s.close()
            status = "open" if r == 0 else "closed"
        except Exception:
            status = "filtered"
        svc = PORT_SERVICES.get(port, f"port-{port}")
        with lock:
            results.append({"port": port, "service": svc, "status": status})

    batch_size = 100
    for i in range(0, len(ports), batch_size):
        batch = ports[i:i+batch_size]
        threads = [threading.Thread(target=check_port, args=(p,), daemon=True) for p in batch]
        for t in threads: t.start()
        for t in threads: t.join(timeout=timeout+1)

    results.sort(key=lambda x: x["port"])
    open_count = sum(1 for r in results if r["status"] == "open")
    print(f"  [PORT SCAN] Done — {open_count} open port(s) out of {len(ports)} scanned.")
    return results

=======
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    try:
        scan_network()
    except KeyboardInterrupt:
        print("\n[!] Scan cancelled.")
    except PermissionError:
        print("\n[!] Permission denied. Run VS Code as Administrator.")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error: {e}")
<<<<<<< HEAD
        sys.exit(1)
=======
        sys.exit(1)
>>>>>>> 32ec94c197df011701a41008123c09d1b7019b4b
