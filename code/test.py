from scapy.all import *

print("Testing Scapy...")
packets = rdpcap("data/pcaps/v6-http.cap")
print(f"Loaded {len(packets)} packets!")
print("Success! Scapy is working.")