#!/usr/bin/env python3
from scapy.all import *

def packet_handler(pkt):
    pkt.show()
    # Check for deauth packets
    if pkt.haslayer(Dot11Deauth):
        print("\n[DEAUTH DETECTED]")
        print(f"Source: {pkt.addr2}")
        print(f"Destination: {pkt.addr1}")
        print(f"BSSID: {pkt.addr3}")
        print(f"Reason: {pkt[Dot11Deauth].reason}")
        print("-" * 50)
    
    # Check for EAPOL packets (4-way handshake)
    if pkt.haslayer(EAPOL):
        print("\n[EAPOL DETECTED]")
        print(f"Source: {pkt.addr2}")
        print(f"Destination: {pkt.addr1}")
        print(f"BSSID: {pkt.addr3}")
        if pkt.haslayer(Raw):
            print(f"Data length: {len(pkt[Raw].load)}")
        print("-" * 50)

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: sudo python script.py <interface>")
        print("Example: sudo python script.py en0")
        sys.exit(1)
    
    interface = sys.argv[1]
    
    print(f"[*] Starting packet capture on {interface}")
    print("[*] Listening for deauth and EAPOL packets...")
    print("[*] Press Ctrl+C to stop\n")
    
    try:
        # Sniff on the specified interface for 802.11 packets
        sniff(iface=interface, prn=packet_handler, store=0)
    except KeyboardInterrupt:
        print("\n[*] Stopping capture...")