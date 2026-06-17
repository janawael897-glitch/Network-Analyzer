"""
flow_builder.py — PacketGuard
Aggregates raw packets into network flows (5-tuple sessions).
Acts as middleware between packet capture and feature extraction/ML.
"""

import threading
import time
from collections import namedtuple

# FlowKey is the 5-tuple that uniquely identifies a flow direction
FlowKey = namedtuple("FlowKey", ["src_ip", "dst_ip", "src_port", "dst_port", "proto"])


class FlowBuilder:
    """
    Thread-safe flow aggregator.
    Receives raw packet-info dicts and emits completed flow dicts.
    """

    def __init__(self, timeout: float = 30.0, max_flows: int = 50000):
        """
        Parameters
        ----------
        timeout   : seconds of inactivity before a flow is expired
        max_flows : hard cap on the number of simultaneously tracked flows;
                    oldest flows are evicted when the cap is reached
        """
        self.timeout   = timeout
        self.max_flows = max_flows

        self._flows: dict     = {}   # FlowKey -> _flow_state dict
        self._lock            = threading.Lock()
        self._call_count: int = 0    # counter used to throttle expiry checks

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_packet(self, pkt_info: dict) -> list:
        """
        Ingest one packet and return a (possibly empty) list of completed
        flow dicts.

        Expected keys in pkt_info
        -------------------------
        src_ip, dst_ip, src_port, dst_port, proto, size, timestamp
        """
        src_ip    = pkt_info.get("src_ip",    "0.0.0.0")
        dst_ip    = pkt_info.get("dst_ip",    "0.0.0.0")
        src_port  = int(pkt_info.get("src_port",  0))
        dst_port  = int(pkt_info.get("dst_port",  0))
        proto     = str(pkt_info.get("proto",     "OTHER")).upper()
        size      = int(pkt_info.get("size",      0))
        timestamp = float(pkt_info.get("timestamp", time.time()))

        key       = FlowKey(src_ip, dst_ip, src_port, dst_port, proto)
        completed = []

        with self._lock:
            # Enforce max-flows cap: evict the oldest flow by last-seen time
            if key not in self._flows and len(self._flows) >= self.max_flows:
                oldest_key = min(self._flows,
                                 key=lambda k: self._flows[k]["last_time"])
                completed.append(self._close_flow(oldest_key))

            if key not in self._flows:
                self._flows[key] = {
                    "start_time":   timestamp,
                    "last_time":    timestamp,
                    "packet_count": 0,
                    "byte_count":   0,
                }

            flow = self._flows[key]
            flow["last_time"]     = timestamp
            flow["packet_count"] += 1
            flow["byte_count"]   += size

            self._call_count += 1

        # Run expiry check every 100 calls (outside lock to reduce contention)
        if self._call_count % 100 == 0:
            completed.extend(self._expire_flows())

        return completed

    def _expire_flows(self) -> list:
        """Close flows that have been idle longer than self.timeout."""
        now       = time.time()
        cutoff    = now - self.timeout
        completed = []

        with self._lock:
            stale = [k for k, f in self._flows.items()
                     if f["last_time"] < cutoff]
            for k in stale:
                completed.append(self._close_flow(k))

        return completed

    def flush_all(self) -> list:
        """Close every active flow.  Call this on monitor stop."""
        with self._lock:
            keys      = list(self._flows.keys())
            completed = [self._close_flow(k) for k in keys]
        return completed

    def get_active_count(self) -> int:
        with self._lock:
            return len(self._flows)

    # ------------------------------------------------------------------
    # Internal helpers  (must be called with self._lock already held)
    # ------------------------------------------------------------------

    def _close_flow(self, key: FlowKey) -> dict:
        """
        Pop a flow from the active table and return its completed flow dict.
        Caller MUST hold self._lock.
        """
        flow       = self._flows.pop(key)
        start_time = flow["start_time"]
        end_time   = flow["last_time"]
        duration   = end_time - start_time
        pkt_count  = flow["packet_count"]
        byte_count = flow["byte_count"]

        avg_pkt_size    = byte_count / pkt_count   if pkt_count  > 0 else 0.0
        packets_per_sec = pkt_count  / max(duration, 0.001)
        bytes_per_sec   = byte_count / max(duration, 0.001)

        flow_id = (
            f"{key.src_ip}:{key.src_port}"
            f"-{key.dst_ip}:{key.dst_port}"
            f"-{key.proto}"
            f"-{int(start_time)}"
        )

        return {
            "flow_id":         flow_id,
            "start_time":      start_time,
            "end_time":        end_time,
            "duration":        duration,
            "packet_count":    pkt_count,
            "byte_count":      byte_count,
            "protocol":        key.proto,
            "src_ip":          key.src_ip,
            "dst_ip":          key.dst_ip,
            "src_port":        key.src_port,
            "dst_port":        key.dst_port,
            "avg_packet_size": avg_pkt_size,
            "direction":       "forward",
            "packets_per_sec": packets_per_sec,
            "bytes_per_sec":   bytes_per_sec,
        }
