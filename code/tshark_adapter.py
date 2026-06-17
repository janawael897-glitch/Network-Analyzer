#!/usr/bin/env python3
"""
tshark_adapter.py — PacketGuard
Runs tshark as a subprocess (-T fields, tab-separated) and converts each
line into a duck-typed packet object that satisfies the Scapy packet
interface used throughout live_monitor.py and ml_detector.py.

Set CAPTURE_ENGINE=tshark in code/env to activate.
Requires Wireshark (tshark) installed: winget install WiresharkFoundation.Wireshark
"""
import logging
import os
import subprocess
import threading

log = logging.getLogger(__name__)

# ── Fields exported by tshark (order matters — maps to tab-split positions) ──
_FIELDS = [
    "frame.len",
    "ip.src", "ip.dst",
    "tcp.srcport", "tcp.dstport", "tcp.flags", "tcp.window_size_value", "tcp.payload",
    "udp.srcport", "udp.dstport",
    "icmp.type",
    "arp.opcode", "arp.src.proto_ipv4", "arp.src.hw_mac", "arp.dst.proto_ipv4",
]


# ── TsharkFlags: int that str()s like Scapy flag letters ─────────────────────

class TsharkFlags(int):
    """
    Detection code does:  'S' not in str(flags)  and  flags & 0x02
    This subclass satisfies both — behaves as int for bitwise ops,
    and __str__ returns Scapy-style letter abbreviations.
    """
    _BITS = [
        (0x001, 'F'), (0x002, 'S'), (0x004, 'R'), (0x008, 'P'),
        (0x010, 'A'), (0x020, 'U'), (0x040, 'E'), (0x080, 'C'),
    ]

    def __str__(self):
        s = ''.join(c for bit, c in self._BITS if self & bit)
        return s or '.'

    def __repr__(self):
        return str(self)


# ── TsharkPayload: wraps raw bytes so bytes(pkt[TCP].payload) works ───────────

class TsharkPayload:
    def __init__(self, raw: bytes):
        self._raw = raw

    def __bytes__(self):
        return self._raw

    def __len__(self):
        return len(self._raw)

    def __bool__(self):
        return bool(self._raw)


# ── Layer objects ─────────────────────────────────────────────────────────────

class TsharkIP:
    def __init__(self, src: str, dst: str):
        self.src = src
        self.dst = dst


class TsharkTCP:
    def __init__(self, sport: int, dport: int, flags: int, window: int, payload: bytes):
        self.sport   = sport
        self.dport   = dport
        self.flags   = TsharkFlags(flags)
        self.window  = window
        self.payload = TsharkPayload(payload)


class TsharkUDP:
    def __init__(self, sport: int, dport: int):
        self.sport = sport
        self.dport = dport


class TsharkICMP:
    def __init__(self, type_: int):
        self.type = type_


class TsharkARP:
    def __init__(self, op: int, psrc: str, hwsrc: str, pdst: str):
        self.op    = op
        self.psrc  = psrc
        self.hwsrc = hwsrc
        self.pdst  = pdst


# ── TsharkPacket: top-level duck-typed Scapy replacement ─────────────────────

class TsharkPacket:
    """
    Satisfies the Scapy packet interface used throughout PacketGuard:
        pkt.haslayer(IP)       → bool
        pkt[IP].src            → str
        pkt[TCP].flags         → TsharkFlags (int + str compatible)
        pkt[TCP].payload       → TsharkPayload (bytes() compatible)
        len(pkt)               → int (frame length)
    """

    def __init__(self, frame_len: int,
                 ip=None, tcp=None, udp=None, icmp=None, arp=None):
        self._frame_len = frame_len
        self._layers = {
            "IP":   ip,
            "TCP":  tcp,
            "UDP":  udp,
            "ICMP": icmp,
            "ARP":  arp,
        }

    def haslayer(self, layer_cls) -> bool:
        name = getattr(layer_cls, "__name__", str(layer_cls))
        return self._layers.get(name) is not None

    def __getitem__(self, layer_cls):
        name = getattr(layer_cls, "__name__", str(layer_cls))
        obj  = self._layers.get(name)
        if obj is None:
            raise KeyError(f"Layer {name} not in packet")
        return obj

    def __len__(self) -> int:
        return self._frame_len

    def __repr__(self):
        layers = [k for k, v in self._layers.items() if v is not None]
        return f"<TsharkPacket layers={layers} len={self._frame_len}>"


# ── Tab-separated line → TsharkPacket ────────────────────────────────────────

def _int(val: str, base: int = 10, default: int = 0) -> int:
    if not val:
        return default
    try:
        return int(val, base) if base != 10 else int(val)
    except (ValueError, TypeError):
        return default


def _parse_flags(val: str) -> int:
    """Parse tshark tcp.flags — may be '0x0002' or plain decimal."""
    if not val:
        return 0
    try:
        return int(val, 16) if val.startswith("0x") else int(val)
    except (ValueError, TypeError):
        return 0


def _parse_payload(val: str) -> bytes:
    """Convert tshark colon-hex payload to bytes: '48:54:54:50' → b'HTTP'"""
    if not val:
        return b""
    try:
        return bytes.fromhex(val.replace(":", ""))
    except Exception:
        return b""


def parse_fields_line(line: str) -> "TsharkPacket | None":
    """
    Parse one tab-separated tshark -T fields output line into a TsharkPacket.
    Returns None for lines with no IP/ARP data (e.g. pure 802.11 management).
    """
    parts = line.rstrip("\n").split("|")
    # Pad to full field count so zip always produces all keys
    parts += [""] * len(_FIELDS)
    d = dict(zip(_FIELDS, parts))

    frame_len = _int(d["frame.len"]) or 60

    # ── IP ──────────────────────────────────────────────────────────────────
    ip_src = d["ip.src"]
    ip_dst = d["ip.dst"]
    ip = TsharkIP(ip_src, ip_dst) if ip_src else None

    # ── TCP ─────────────────────────────────────────────────────────────────
    tcp = None
    if d["tcp.srcport"]:
        try:
            tcp = TsharkTCP(
                sport   = _int(d["tcp.srcport"]),
                dport   = _int(d["tcp.dstport"]),
                flags   = _parse_flags(d["tcp.flags"]),
                window  = _int(d["tcp.window_size_value"]),
                payload = _parse_payload(d["tcp.payload"]),
            )
        except Exception:
            pass

    # ── UDP ─────────────────────────────────────────────────────────────────
    udp = None
    if d["udp.srcport"]:
        try:
            udp = TsharkUDP(
                sport = _int(d["udp.srcport"]),
                dport = _int(d["udp.dstport"]),
            )
        except Exception:
            pass

    # ── ICMP ────────────────────────────────────────────────────────────────
    icmp = None
    if d["icmp.type"]:
        try:
            icmp = TsharkICMP(type_=_int(d["icmp.type"]))
        except Exception:
            pass

    # ── ARP ─────────────────────────────────────────────────────────────────
    arp = None
    if d["arp.opcode"]:
        try:
            arp = TsharkARP(
                op    = _int(d["arp.opcode"]),
                psrc  = d["arp.src.proto_ipv4"],
                hwsrc = d["arp.src.hw_mac"],
                pdst  = d["arp.dst.proto_ipv4"],
            )
        except Exception:
            pass

    if not ip and not arp:
        return None

    return TsharkPacket(frame_len=frame_len, ip=ip, tcp=tcp, udp=udp, icmp=icmp, arp=arp)


# ── tshark path detection ─────────────────────────────────────────────────────

def is_tshark_available() -> bool:
    import shutil
    if shutil.which("tshark"):
        return True
    return os.path.isfile(r"C:\Program Files\Wireshark\tshark.exe")


def _tshark_path() -> str:
    import shutil
    p = shutil.which("tshark")
    return p if p else r"C:\Program Files\Wireshark\tshark.exe"


# ── TsharkCapture: subprocess manager ────────────────────────────────────────

class TsharkCapture:
    """
    Runs tshark -T fields (tab-separated) and calls on_packet(TsharkPacket)
    for every captured packet. Blocks until stop_event is set.
    """

    def __init__(self, iface: str, on_packet, stop_event: threading.Event):
        self._iface      = iface
        self._on_packet  = on_packet
        self._stop_event = stop_event
        self._proc       = None

    def start(self):
        field_args = []
        for f in _FIELDS:
            field_args += ["-e", f]

        cmd = [
            _tshark_path(),
            "-i", self._iface,
            "-T", "fields",
            "-E", "separator=|",
            "-E", "occurrence=f",   # first occurrence of each field per packet
            "-l",                   # line-buffered — critical for low latency
        ] + field_args

        log.info(f"[TSHARK] Starting on interface: {self._iface}")

        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=1,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        except Exception as e:
            log.error(f"[TSHARK] Failed to start: {e}")
            return

        # Drain stderr in background so it never blocks the capture pipe
        threading.Thread(
            target=self._drain_stderr,
            args=(self._proc.stderr,),
            daemon=True,
            name="tshark-stderr"
        ).start()

        log.info("[TSHARK] Capture running.")
        try:
            for line in self._proc.stdout:
                if self._stop_event.is_set():
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    pkt = parse_fields_line(line)
                    if pkt is not None:
                        self._on_packet(pkt)
                except Exception as e:
                    log.debug(f"[TSHARK] Dispatch error: {e}")
        finally:
            self._terminate()

    def _drain_stderr(self, stderr):
        try:
            for line in stderr:
                line = line.strip()
                if not line:
                    continue
                # Surface errors so they appear in the console
                lower = line.lower()
                if any(w in lower for w in ("error", "permission", "failed", "invalid", "warn")):
                    log.warning(f"[TSHARK] {line}")
                    print(f"[TSHARK] {line}")
                else:
                    log.debug(f"[TSHARK] {line}")
        except Exception:
            pass

    def _terminate(self):
        if self._proc and self._proc.poll() is None:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=3)
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass
        log.info("[TSHARK] Stopped.")
