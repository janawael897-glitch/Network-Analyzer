import sys
sys.path.insert(0, 'code')
from ml_detector import get_detector
from scapy.all import sniff
import time

d = get_detector()
print('Threshold:', d.iso_threshold)
print('Flow timeout:', d._aggregator._timeout, 'seconds')
print('Capturing for 30 seconds to let flows complete...')

sniff(timeout=30, prn=lambda p: d.score_packet(p), store=False)

print('Active flows:', len(d._aggregator._flows))
print('ML total alerts:', 0)

# Force expire all flows
import threading
flows = list(d._aggregator._flows.items())
print(f'Forcing {len(flows)} flows to complete...')
for key, flow in flows:
    result = d._flow_ready(flow)
    if result:
        print(f'ALERT: {result["alert_type"]} from {result["source_ip"]}')
    else:
        print(f'Flow {flow.src_ip}->{flow.dst_ip}: {flow.total_pkts} pkts - no alert')

print('Done.')