# 🔍 Cross-Platform Network Sniffer

A Python-based network packet sniffer that captures and analyzes live network traffic in real time. Works on **Windows, Linux, and macOS**.

---

## 📋 Overview

This script opens a raw socket connection to your network interface via **Scapy** and listens to every packet passing through. For each packet it decodes and displays:

- **Ethernet layer** — source & destination MAC addresses
- **IPv4 / IPv6 layer** — source & destination IPs, TTL, protocol
- **TCP** — ports, flags (SYN, ACK, FIN, RST…), sequence numbers, and HTTP detection
- **UDP** — ports, length, and DNS query/response details
- **ICMP** — type and code (Echo Request, Echo Reply, etc.)
- **Payload** — hex + ASCII dump of packet contents

All output is printed to the screen and can optionally be saved to a plain text log or a Wireshark-compatible `.pcap` file.

---

## ⚙️ Requirements

### All Platforms
```bash
pip install scapy
```

### Windows Only
- Download and install **Npcap** from [https://npcap.com/#download](https://npcap.com/#download)
- Run your terminal as **Administrator**

### Linux / macOS
- Run with `sudo`

---

## 🚀 Usage

```bash
# List available network interfaces
python network_sniffer_crossplatform.py --list

# Capture all traffic on the default interface
python network_sniffer_crossplatform.py

# Capture on a specific interface
python network_sniffer_crossplatform.py --iface "Ethernet"

# Filter by protocol
python network_sniffer_crossplatform.py --filter tcp
python network_sniffer_crossplatform.py --filter udp
python network_sniffer_crossplatform.py --filter icmp

# Stop after N packets
python network_sniffer_crossplatform.py --count 50

# Save output to a plain text log file
python network_sniffer_crossplatform.py --log capture.txt

# Save to a .pcap file (open in Wireshark)
python network_sniffer_crossplatform.py --output capture.pcap

# Combine options
python network_sniffer_crossplatform.py --filter tcp --count 100 --log tcp_log.txt --output capture.pcap
```

---

## 🗂️ Output Options

| Flag | Description |
|---|---|
| `--log FILE` | Saves everything printed to screen into a readable `.txt` file |
| `--output FILE` | Saves raw packets to a `.pcap` file — open with Wireshark |
| Both together | Saves both formats at the same time |

---

## 🖥️ Sample Output

```
════════════════════════════════════════════════════════════════════════
  CROSS-PLATFORM NETWORK SNIFFER
────────────────────────────────────────────────────────────────────────
  OS        : Windows
  Interface : Ethernet
  Filter    : ALL
  Count     : unlimited
────────────────────────────────────────────────────────────────────────
  Press Ctrl+C to stop capturing
════════════════════════════════════════════════════════════════════════
──────────────────────────────────────────────────────────────────────
  [#1] 14:23:05.412
    Ethernet   a4:c3:f0:12:34:56  →  ff:ff:ff:ff:ff:ff
    IPv4       192.168.1.5  →  8.8.8.8  TTL=64  Proto=UDP  Len=60
    UDP        54321  →  53  Len=40
        ▶ DNS Query   www.google.com.
```

---

## 📊 Capture Summary

When you press `Ctrl+C` to stop, the script prints a summary:

```
════════════════════════════════════════════════════════════════════════
  CAPTURE SUMMARY
────────────────────────────────────────────────────────────────────────
  TOTAL   : 143
  TCP     : 89
  UDP     : 41
  ICMP    : 8
  DNS     : 23
════════════════════════════════════════════════════════════════════════
```

---

## 📁 Project Structure

```
network_sniffer_crossplatform.py   # Main sniffer script
README.md                          # This file
capture.txt                        # Plain text log (generated with --log)
capture.pcap                       # Wireshark file  (generated with --output)
```

---

## ⚠️ Notes

- Raw packet capture requires **elevated privileges** (Administrator on Windows, `sudo` on Linux/macOS)
- This tool is intended for **educational and authorised use only**
- Only capture traffic on networks you own or have permission to monitor

---

## 📚 Dependencies

| Library | Purpose |
|---|---|
| `scapy` | Packet capture and parsing |
| `npcap` *(Windows only)* | Low-level network driver for Windows |
