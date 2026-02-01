from scapy.all import *
import datetime
from collections import deque, defaultdict
import time

def detect_wps_brute_force(interface, callback=None):
    """Continuously detect WPS PIN brute force attacks by monitoring EAPOL packets."""
    
    EAPOL_THRESHOLD = 10
    TIME_WINDOW = 5
    
    eapol_packets = defaultdict(deque)
    last_alert = defaultdict(float)
    
    def process_packet(packet):
        # Check for special encapsulated EAPOL packets
        if packet.haslayer(Ether) and packet.haslayer(Raw):
            if (packet[Ether].dst == "00:00:08:00:00:00" and 
                packet[Ether].src == "00:00:08:01:00:00"):
                
                # Extract the real MAC addresses from the Raw payload
                raw_data = packet[Raw].load
                if len(raw_data) >= 10:
                    # Convert Ethernet type to bytes (2 bytes, big-endian)
                    ether_type_bytes = packet[Ether].type.to_bytes(2, 'big')
                    # First 6 bytes are destination MAC (2 from ether type + 4 from raw)
                    real_dst = ':'.join(f'{b:02x}' for b in ether_type_bytes) + ':'
                    real_dst += ':'.join(f'{b:02x}' for b in raw_data[0:4])
                    # Next 6 bytes are source MAC
                    real_src = ':'.join(f'{b:02x}' for b in raw_data[4:10])
                    
                    now = time.time()
                    src_mac = real_src
                    
                    eapol_packets[src_mac].append((now, packet))
                    while eapol_packets[src_mac] and now - eapol_packets[src_mac][0][0] > TIME_WINDOW:
                        eapol_packets[src_mac].popleft()
                    
                    if len(eapol_packets[src_mac]) >= EAPOL_THRESHOLD and now - last_alert[src_mac] > 30:
                        target_ap = real_dst
                    if len(eapol_packets[src_mac]) >= EAPOL_THRESHOLD and now - last_alert[src_mac] > 30:
                        target_ap = real_dst
                        # Extract addresses
                        macs = set()
                        ips = set()
                        for _, pkt in eapol_packets[src_mac]:
                            if pkt.haslayer(Ether) and pkt.haslayer(Raw):
                                raw = pkt[Raw].load
                                if len(raw) >= 10:
                                    et_bytes = pkt[Ether].type.to_bytes(2, 'big')
                                    dst = ':'.join(f'{b:02x}' for b in et_bytes) + ':' + ':'.join(f'{b:02x}' for b in raw[0:4])
                                    src = ':'.join(f'{b:02x}' for b in raw[4:10])
                                    macs.add(dst)
                                    macs.add(src)
                            if pkt.haslayer(IP):
                                ips.add(pkt[IP].src)
                                ips.add(pkt[IP].dst)
                        
                        # Print alert
                        print(f"\n[{datetime.datetime.now()}] WPS Brute Force Attack Detected!")
                        print(f"Attacker MAC: {src_mac}")
                        print(f"Target AP: {target_ap}")
                        print(f"Packet count: {len(eapol_packets[src_mac])} in {TIME_WINDOW} seconds")
                        print(f"All MACs: {list(macs)}")
                        if ips:
                            print(f"IPs: {list(ips)}")
                        print("-" * 60)
                        
                        last_alert[src_mac] = now
                        
                        # Trigger callback if provided
                        if callback:
                            attack_info = {
                                'type': 'wps_brute_force',
                                'attacker_mac': src_mac,
                                'target_ap': target_ap,
                                'all_macs': list(macs),
                                'ips': list(ips),
                                'packet_count': len(eapol_packets[src_mac])
                            }
                            callback(attack_info)
    
    print(f"[{datetime.datetime.now()}] Monitoring {interface} for WPS brute force attacks...")
    print("Press Ctrl+C to stop\n")
    
    try:
        sniff(iface=interface, prn=process_packet, store=False)
    except KeyboardInterrupt:
        print("\n[!] Stopped")

if __name__ == "__main__":
    import sys
    interface = sys.argv[1] if len(sys.argv) > 1 else "en0"
    detect_wps_brute_force(interface)
