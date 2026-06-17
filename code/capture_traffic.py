#!/usr/bin/env python3
"""
capture_traffic.py  -  PacketGuard Traffic Capture Tool
========================================================
Captures live network flows using the EXACT same FlowAggregator
as ml_detector.py (78 CICIDS2017 features) and saves them to
  data/captured/<LABEL>_<timestamp>.json

Usage:
    python capture_traffic.py --label BENIGN   --duration 300
    python capture_traffic.py --label SYN_FLOOD --duration 60
    python capture_traffic.py --label PORT_SCAN --duration 60
    python capture_traffic.py --label UDP_FLOOD --duration 60
    python capture_traffic.py --label ICMP_FLOOD --duration 60

After capturing all labels, run:
    python retrain_local.py

Requirements:
    pip install scapy --break-system-packages   (or in .venv)
    Run as Administrator (packet capture needs admin)
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime

# -- Paths ----------------------------------------------------------
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
CAPTURE_DIR = os.path.join(BASE_DIR, "data", "captured")
os.makedirs(CAPTURE_DIR, exist_ok=True)

# -- Valid labels ---------------------------------------------------
VALID_LABELS = {
    "BENIGN":     0,
    "SYN_FLOOD":  1,
    "PORT_SCAN":  1,
    "UDP_FLOOD":  1,
    "ICMP_FLOOD": 1,
    "BRUTE_FORCE": 1,
}


def get_interface():
    """Auto-detect the best interface (Wi-Fi or Ethernet)."""
    try:
        from scapy.arch import get_if_list
        ifaces = get_if_list()
        # Prefer Wi-Fi then Ethernet
        for keyword in ["Wi-Fi", "Ethernet", "eth0", "wlan0", "en0"]:
            for iface in ifaces:
                if keyword.lower() in iface.lower():
                    return iface
        return ifaces[0] if ifaces else None
    except Exception:
        return None


def capture(label: str, duration: int, iface: str = None):
    """
    Capture network flows for `duration` seconds on `iface`.
    Uses the exact same FlowAggregator as ml_detector.py so features match.
    """
    # -- Import FlowAggregator from ml_detector ----------------------
    try:
        sys.path.insert(0, BASE_DIR)
        from ml_detector import FlowAggregator
    except ImportError as e:
        print(f"[ERROR] Cannot import FlowAggregator from ml_detector.py: {e}")
        print("        Make sure ml_detector.py is in the same directory.")
        sys.exit(1)

    # -- Load feature names so FlowAggregator knows the order --------
    try:
        import joblib
        PROCESSED_DIR = os.path.join(
            os.path.dirname(BASE_DIR), "dataset", "processed"
        )
        feature_names = joblib.load(os.path.join(PROCESSED_DIR, "feature_names.pkl"))
        print(f"[INFO] Loaded {len(feature_names)} feature names from processed dir.")
    except Exception:
        # Fallback: hardcode the 78 CICIDS feature names in order
        feature_names = [
            'Destination Port', 'Flow Duration', 'Total Fwd Packets',
            'Total Backward Packets', 'Total Length of Fwd Packets',
            'Total Length of Bwd Packets', 'Fwd Packet Length Max',
            'Fwd Packet Length Min', 'Fwd Packet Length Mean',
            'Fwd Packet Length Std', 'Bwd Packet Length Max',
            'Bwd Packet Length Min', 'Bwd Packet Length Mean',
            'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s',
            'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
            'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max',
            'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std',
            'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags',
            'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length',
            'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s',
            'Min Packet Length', 'Max Packet Length', 'Packet Length Mean',
            'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count',
            'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count',
            'ACK Flag Count', 'URG Flag Count', 'CWE Flag Count',
            'ECE Flag Count', 'Down/Up Ratio', 'Average Packet Size',
            'Avg Fwd Segment Size', 'Avg Bwd Segment Size',
            'Fwd Header Length.1', 'Fwd Avg Bytes/Bulk',
            'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate',
            'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk',
            'Bwd Avg Bulk Rate', 'Subflow Fwd Packets', 'Subflow Fwd Bytes',
            'Subflow Bwd Packets', 'Subflow Bwd Bytes',
            'Init_Win_bytes_forward', 'Init_Win_bytes_backward',
            'act_data_pkt_fwd', 'min_seg_size_forward',
            'Active Mean', 'Active Std', 'Active Max', 'Active Min',
            'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min',
        ]
        print(f"[INFO] Using hardcoded {len(feature_names)} feature names.")

    agg = FlowAggregator(feature_names, timeout=5.0)

    # -- Interface selection ------------------------------------------
    if not iface:
        iface = get_interface()
    if not iface:
        print("[ERROR] No network interface found. Specify with --iface.")
        sys.exit(1)

    print(f"\n{'='*60}")
    print(f"  CAPTURING: {label}")
    print(f"  Interface: {iface}")
    print(f"  Duration:  {duration}s")
    print(f"  Flows will be saved when complete (every 5s or 20 pkts)")
    print(f"{'='*60}")

    if label == "BENIGN":
        print("\n  ► Browse normally, stream video, open websites.")
        print("  ► The more varied traffic, the better the model.")
    else:
        print(f"\n  ► START YOUR {label} ATTACK NOW FROM KALI/VMWARE.")
        print("  ► Keep the attack running for the full duration.")

    print(f"\n  Starting in 3 seconds...\n")
    time.sleep(3)

    # -- Capture loop -------------------------------------------------
    from scapy.all import sniff

    flows_captured = []
    start_time     = time.time()
    pkt_count      = 0
    label_int      = VALID_LABELS.get(label, 1)

    def handle_pkt(pkt):
        nonlocal pkt_count
        pkt_count += 1
        feat = agg.ingest(pkt)
        if feat is not None:
            flows_captured.append({
                "features": feat,
                "label":    label_int,
                "label_name": label,
                "timestamp": datetime.utcnow().isoformat(),
            })
            elapsed = time.time() - start_time
            remaining = max(0, duration - elapsed)
            print(f"\r  Flows: {len(flows_captured):4d}  |  Packets: {pkt_count:6d}  |"
                  f"  Remaining: {remaining:5.0f}s   ", end="", flush=True)

    def stop_filter(pkt):
        return (time.time() - start_time) >= duration

    try:
        sniff(
            iface=iface,
            prn=handle_pkt,
            stop_filter=stop_filter,
            store=False,
        )
    except KeyboardInterrupt:
        print("\n\n  [INFO] Capture stopped by user.")
    except Exception as e:
        print(f"\n\n  [ERROR] Sniff error: {e}")
        print("  Make sure you're running as Administrator.")

    elapsed = time.time() - start_time
    print(f"\n\n  Capture complete: {len(flows_captured)} flows in {elapsed:.0f}s")

    if not flows_captured:
        print("  [WARNING] No flows captured. Check interface or generate more traffic.")
        return

    # -- Save ---------------------------------------------------------
    ts       = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    out_file = os.path.join(CAPTURE_DIR, f"{label}_{ts}.json")
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(flows_captured, f, indent=2, default=str)

    print(f"  Saved → {out_file}")
    print(f"\n  Summary:")
    print(f"    Flows captured : {len(flows_captured)}")
    print(f"    Label          : {label} (int={label_int})")
    print(f"    Features/flow  : {len(feature_names)}")

    # Show what already exists
    _show_capture_summary()

    print(f"\n  Next steps:")
    if label == "BENIGN":
        print("  1. Capture attack traffic:")
        print("     python capture_traffic.py --label SYN_FLOOD  --duration 60")
        print("     python capture_traffic.py --label PORT_SCAN  --duration 60")
        print("     python capture_traffic.py --label UDP_FLOOD  --duration 60")
    else:
        print("  1. Capture more attack types or more BENIGN if needed.")
    print("  2. When done, retrain:")
    print("     python retrain_local.py")


def _show_capture_summary():
    """Print what capture files exist so far."""
    files = [f for f in os.listdir(CAPTURE_DIR) if f.endswith(".json")]
    if not files:
        return
    print(f"\n  Existing capture files in data/captured/:")
    label_counts = {}
    for fname in sorted(files):
        try:
            with open(os.path.join(CAPTURE_DIR, fname)) as f:
                data = json.load(f)
            lbl = data[0]["label_name"] if data else "?"
            label_counts[lbl] = label_counts.get(lbl, 0) + len(data)
            print(f"    {fname:40s}  {len(data):4d} flows  [{lbl}]")
        except Exception:
            print(f"    {fname}  (unreadable)")
    print(f"\n  Total flows by label:")
    for lbl, cnt in sorted(label_counts.items()):
        status = "✓" if cnt >= 50 else "⚠ (need ≥50)"
        print(f"    {lbl:15s}: {cnt:4d} flows  {status}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Capture network flows for ML retraining."
    )
    parser.add_argument(
        "--label", required=True,
        choices=list(VALID_LABELS.keys()),
        help="Traffic label: BENIGN or attack type"
    )
    parser.add_argument(
        "--duration", type=int, default=120,
        help="Capture duration in seconds (default: 120)"
    )
    parser.add_argument(
        "--iface", default=None,
        help="Network interface (auto-detected if not specified)"
    )
    args = parser.parse_args()
    capture(args.label, args.duration, args.iface)
