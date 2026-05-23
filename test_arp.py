from scapy.all import srp, Ether, ARP 
IFACE = r"\Device\NPF_{6AE9C84A-0C4E-4922-BB77-49FAB27D9034}" 
ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.1.1"), iface=IFACE, timeout=3, verbose=True) 
for s,r in ans: print("MAC:", r[Ether].src) 
