"""
flow_exporter.py — PacketGuard
Exports completed flows to JSON/CSV for analysis and visualization.

Files are stored under BASE_DIR/flows/ and rotated daily:
  flows_YYYY-MM-DD.json
  flows_YYYY-MM-DD.csv
"""

import csv
import json
import os
import queue
import threading
from datetime import datetime, timezone

# BASE_DIR is the code/ directory where all other data files live
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# CSV columns exported for each flow
CSV_FIELDS = [
    "flow_id",
    "start_time",
    "end_time",
    "duration",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "protocol",
    "packet_count",
    "byte_count",
    "avg_packet_size",
    "packets_per_sec",
    "bytes_per_sec",
]


class FlowExporter:
    """
    Non-blocking flow exporter.

    write_flow() enqueues a flow record on a queue; a background daemon
    thread drains the queue and writes to the daily JSON + CSV files.
    """

    def __init__(self, export_dir: str = None):
        if export_dir is None:
            export_dir = os.path.join(BASE_DIR, "flows")
        self._export_dir = export_dir
        os.makedirs(self._export_dir, exist_ok=True)

        self._queue: queue.Queue = queue.Queue()
        self._thread = threading.Thread(
            target=self._worker,
            daemon=True,
            name="flow-exporter",
        )
        self._thread.start()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def write_flow(self, flow: dict) -> None:
        """
        Enqueue a flow for non-blocking export.
        Returns immediately; actual file I/O happens in the background thread.
        """
        self._queue.put(flow)

    def get_recent_flows(self, n: int = 100) -> list:
        """
        Return the last *n* flows from today's JSON export file.
        Returns an empty list if the file does not exist yet.
        """
        json_path = self._daily_json_path()
        if not os.path.exists(json_path):
            return []
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                flows = json.load(f)
            return flows[-n:] if len(flows) > n else flows
        except Exception:
            return []

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _today(self) -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d")

    def _daily_json_path(self) -> str:
        return os.path.join(self._export_dir, f"flows_{self._today()}.json")

    def _daily_csv_path(self) -> str:
        return os.path.join(self._export_dir, f"flows_{self._today()}.csv")

    def _worker(self) -> None:
        """Background thread: drain the queue and write to disk."""
        while True:
            try:
                flow = self._queue.get(timeout=1.0)
            except queue.Empty:
                continue
            try:
                self._append_json(flow)
                self._append_csv(flow)
            except Exception:
                pass  # never crash the exporter thread
            finally:
                self._queue.task_done()

    def _append_json(self, flow: dict) -> None:
        """Append a single flow record to today's JSON array file."""
        json_path = self._daily_json_path()
        flows: list = []
        if os.path.exists(json_path):
            try:
                with open(json_path, "r", encoding="utf-8") as f:
                    flows = json.load(f)
            except Exception:
                flows = []
        flows.append(flow)
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(flows, f, indent=2, default=str)

    def _append_csv(self, flow: dict) -> None:
        """Append a single flow record to today's CSV file."""
        csv_path   = self._daily_csv_path()
        write_hdr  = not os.path.exists(csv_path)
        with open(csv_path, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=CSV_FIELDS,
                extrasaction="ignore",
            )
            if write_hdr:
                writer.writeheader()
            row = {field: flow.get(field, "") for field in CSV_FIELDS}
            writer.writerow(row)
