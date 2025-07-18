from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from scapy.layers.dns import DNS
from datetime import datetime
import string

def clean_payload(data):
    """Filter non-printable characters in payload."""
    return ''.join(c if c in string.printable else '.' for c in data)

def packet_callback(packet):
    time_stamp = datetime.now().strftime("%H:%M:%S")
    proto = "Unknown"

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if packet.haslayer(TCP):
            proto = "TCP"
        elif packet.haslayer(UDP):
            proto = "UDP"
        elif packet.haslayer(ICMP):
            proto = "ICMP"

        print(f"[{time_stamp}] {proto} Packet: {src_ip} --> {dst_ip}")

        # Optional: Show DNS query
        if packet.haslayer(DNS) and packet[DNS].qd:
            try:
                dns_query = packet[DNS].qd.qname.decode()
                print(f"   [DNS Query] {dns_query}")
            except:
                print("   [DNS Query] <error decoding>")

        # Optional: Show payload
        if packet.haslayer(Raw):
            try:
                raw_data = packet[Raw].load.decode(errors='ignore')
                print(f"   Payload: {clean_payload(raw_data[:100])}")
            except:
                print("   Payload: <unreadable>")
        print("-" * 60)

def main():
    print("Starting packet capture... Press Ctrl+C to stop.\n")
    try:
        # You can filter with iface="eth0" or filter="udp"
        sniff(prn=packet_callback, store=0)
    except KeyboardInterrupt:
        print("\n[+] Capture stopped.")
    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    main()
