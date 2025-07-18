# CodeAlpha Network Sniffer

📡 Packet Sniffer (Python + Scapy)
A lightweight Python tool for capturing and analyzing real-time network packets using Scapy. It shows source/destination IPs, protocols (TCP/UDP/ICMP), and payloads, and highlights DNS queries.

🔧 Features
Real-time packet capture

Supports TCP, UDP, ICMP, and DNS

Displays source/destination IPs and protocol types

Cleans and shows printable payload data

Gracefully handles Ctrl+C

Cross-compatible with Linux (Kali) and Windows (with Npcap)

🚀 Requirements
Python 3.6+

Scapy

Root/admin privileges

🔄 Install Dependencies

pip install scapy
🖥️ How to Run
🔐 On Linux (e.g., Kali):

sudo python3 packet_sniffer.py
🪟 On Windows:
Install Npcap

Run the script as Administrator:

python packet_sniffer.py
📂 Output Sample

[14:17:17] UDP Packet: 10.0.2.15 --> 8.8.8.8
   [DNS Query] www.google.com.
   Payload: ..'...x....D..e@....'..dns.....
------------------------------------------------------------
[14:17:18] TCP Packet: 192.168.1.10 --> 172.217.174.78
   Payload: GET / HTTP/1.1
------------------------------------------------------------
⚙️ Customization
🧠 Filter Protocols: filter="udp" in sniff()

🌐 Target Interface: iface="eth0" or wlan0

📥 Log to File or Save as .pcap: coming soon!

📜 License
MIT License © 2025 [Sparsh Agarwal]
