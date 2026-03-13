from scapy.all import *
import random
import string

print("Generating test threat traffic...")

# 1. Simulate Port Scan (SYN scan to multiple ports)
print("Creating port scan packets...")
port_scan_packets = []
for port in range(80, 110):  # Scan ports 80-109 (30 ports)
    pkt = IP(dst="192.168.1.100")/TCP(dport=port, flags="S")
    port_scan_packets.append(pkt)

# 2. Simulate SYN Flood (DDoS attack)
print("Creating SYN flood packets...")
syn_flood_packets = []
for i in range(150):  # Send 150 SYN packets
    pkt = IP(dst="192.168.1.100")/TCP(dport=80, flags="S")
    syn_flood_packets.append(pkt)

# 3. Simulate DNS DGA (Domain Generation Algorithm - malware behavior)
print("Creating DNS DGA packets...")
dga_packets = []
for i in range(10):
    # Generate random domain name (typical malware behavior)
    random_domain = ''.join(random.choices(string.ascii_lowercase, k=15)) + '.com'
    pkt = IP(dst="8.8.8.8")/UDP(dport=53)/DNS(qd=DNSQR(qname=random_domain))
    dga_packets.append(pkt)

# 4. Simulate abnormally large packets
print("Creating abnormal packets...")
large_packets = []
for i in range(5):
    # Create very large packet (potential attack)
    pkt = IP(dst="192.168.1.100")/TCP(dport=80)/Raw(load="X" * 10000)
    large_packets.append(pkt)

# Combine all packets
all_packets = port_scan_packets + syn_flood_packets + dga_packets + large_packets

# Save to PCAP file
wrpcap("data/pcaps/malicious_traffic.pcap", all_packets)

print("\n" + "="*60)
print("✅ SUCCESS! Created malicious_traffic.pcap")
print("="*60)
print(f"Total packets: {len(all_packets)}")
print(f"  - Port scan packets: {len(port_scan_packets)}")
print(f"  - SYN flood packets: {len(syn_flood_packets)}")
print(f"  - DNS DGA packets: {len(dga_packets)}")
print(f"  - Large packets: {len(large_packets)}")
print("="*60)
print("\nNow run: python code\\network_analyzer.py pcap data\\pcaps\\malicious_traffic.pcap")
