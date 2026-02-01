#!/usr/bin/env python3
from scapy.all import *

def packet_handler(pkt):
    # Check for special encapsulated EAPOL packets
    if pkt.haslayer(Ether) and pkt.haslayer(Raw):
        # Check if this is the special wrapper format
        if (pkt[Ether].dst == "00:00:08:00:00:00" and 
            pkt[Ether].src == "00:00:08:01:00:00"):
            
            # Extract the real MAC addresses from the Raw payload
            raw_data = pkt[Raw].load
            if len(raw_data) >= 10:
                # Convert Ethernet type to bytes (2 bytes, big-endian)
                ether_type_bytes = pkt[Ether].type.to_bytes(2, 'big')
                # First 6 bytes are destination MAC (2 from ether type + 4 from raw)
                real_dst = ':'.join(f'{b:02x}' for b in ether_type_bytes) + ':'
                real_dst += ':'.join(f'{b:02x}' for b in raw_data[0:4])
                # Next 6 bytes are source MAC
                real_src = ':'.join(f'{b:02x}' for b in raw_data[4:10])
                
                print("\n[EAPOL DETECTED]")
                print(f"Destination: {real_dst}")
                print(f"Source: {real_src}")
                print(f"Data length: {len(raw_data)}")
                print(f"Raw data: {raw_data.hex()}")
                print("-" * 50)
        elif (pkt[Ether].dst == "00:00:08:00:00:00" and 
            pkt[Ether].src == "00:00:c0:00:00:00"):
            # Extract the real MAC addresses from the Raw payload
            raw_data = pkt[Raw].load
            if len(raw_data) >= 10:
                # Convert Ethernet type to bytes (2 bytes, big-endian)
                ether_type_bytes = pkt[Ether].type.to_bytes(2, 'big')
                # First 6 bytes are destination MAC (2 from ether type + 4 from raw)
                real_dst = ':'.join(f'{b:02x}' for b in ether_type_bytes) + ':'
                real_dst += ':'.join(f'{b:02x}' for b in raw_data[0:4])
                # Next 6 bytes are source MAC
                real_src = ':'.join(f'{b:02x}' for b in raw_data[4:10])
                
                print("\n[DEAUTH PACKET DETECTED]")
                print(f"Destination: {real_dst}")
                print(f"Source: {real_src}")
                print(f"Data length: {len(raw_data)}")
                print(f"Raw data: {raw_data.hex()}")
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
    except Exception as e:
        print(f"Error: {e}")