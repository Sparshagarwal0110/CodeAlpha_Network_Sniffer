
# 📡 Packet Sniffer (Python + Scapy)

A lightweight Python tool for capturing and analyzing real-time network packets using **Scapy**.  
It displays source/destination IPs, protocol types (TCP, UDP, ICMP), payload data, and DNS queries.

---

## 🔧 Features

- Real-time packet capture using Scapy
- Supports **TCP**, **UDP**, **ICMP**, and **DNS**
- Displays source/destination IPs and protocol type
- Extracts and filters readable payloads
- Gracefully handles Ctrl+C interruption
- Works on **Linux (Kali)** and **Windows (with Npcap)**

---

## 🚀 Requirements

- Python 3.6 or higher
- Scapy library
- Root/admin privileges

### 🔄 Install Scapy

```bash
pip install scapy
```

---

## 🖥️ Usage

### ✅ On Kali Linux

```bash
sudo python3 packet_sniffer.py
```

### ✅ On Windows

1. Install [Npcap](https://nmap.org/npcap/) (with WinPcap compatibility)
2. Run Command Prompt as **Administrator**
3. Run the script:
```bash
python packet_sniffer.py
```

---

## 📂 Sample Output

```
[14:17:17] UDP Packet: 10.0.2.15 --> 8.8.8.8
   [DNS Query] www.google.com.
   Payload: ..............example.payload.dns....
------------------------------------------------------------
[14:17:18] TCP Packet: 192.168.1.10 --> 172.217.174.78
   Payload: GET / HTTP/1.1
------------------------------------------------------------
```

---

## ⚙️ Customization Options

| Feature          | How to Use                        |
|------------------|-----------------------------------|
| Filter Protocols | `filter="udp"` in `sniff()`       |
| Choose Interface | `iface="eth0"` or `iface="wlan0"` |
| Save to File     | (Feature Coming Soon)             |

---

## 📜 License

MIT License © 2025 [Sparsh Agarwal]
