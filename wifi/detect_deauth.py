from scapy.all import *
import datetime
from collections import deque, defaultdict
import time

def detect_deauth(interface, callback=None):
    """Continuously detect deauthentication attacks by monitoring Dot11Deauth packets."""
    
    DEAUTH_THRESHOLD = 10
    TIME_WINDOW = 5
    
    deauth_packets = defaultdict(deque)
    last_alert = defaultdict(float)
    
    def process_packet(packet):
        if packet.haslayer(Dot11Deauth) and packet.haslayer(Dot11):
            now = time.time()
            src_mac = packet.addr2
            
            deauth_packets[src_mac].append((now, packet))
            while deauth_packets[src_mac] and now - deauth_packets[src_mac][0][0] > TIME_WINDOW:
                deauth_packets[src_mac].popleft()
            
            if len(deauth_packets[src_mac]) >= DEAUTH_THRESHOLD and now - last_alert[src_mac] > 30:
                # Extract addresses
                macs = set()
                ips = set()
                for _, pkt in deauth_packets[src_mac]:
                    if pkt.addr1: macs.add(pkt.addr1)
                    if pkt.addr2: macs.add(pkt.addr2)
                    if pkt.addr3: macs.add(pkt.addr3)
                    if pkt.haslayer(IP):
                        ips.add(pkt[IP].src)
                        ips.add(pkt[IP].dst)
                
                # Print alert
                print(f"\n[{datetime.datetime.now()}] Deauthentication Attack Detected!")
                print(f"Attacker MAC: {src_mac}")
                print(f"Target AP: {packet.addr3}")
                print(f"Packet count: {len(deauth_packets[src_mac])} in {TIME_WINDOW} seconds")
                print(f"All MACs: {list(macs)}")
                if ips:
                    print(f"IPs: {list(ips)}")
                print("-" * 60)
                
                last_alert[src_mac] = now
                
                # Trigger callback if provided
                if callback:
                    attack_info = {
                        'type': 'deauth',
                        'attacker_mac': src_mac,
                        'target_ap': packet.addr3,
                        'all_macs': list(macs),
                        'ips': list(ips),
                        'packet_count': len(deauth_packets[src_mac])
                    }
                    callback(attack_info)
    
    print(f"[{datetime.datetime.now()}] Monitoring {interface} for deauthentication attacks...")
    print("Press Ctrl+C to stop\n")
    
    try:
        sniff(iface=interface, prn=process_packet, store=False)
    except KeyboardInterrupt:
        print("\n[!] Stopped")

if __name__ == "__main__":
    import sys
    interface = sys.argv[1] if len(sys.argv) > 1 else "en0"
    detect_deauth(interface)