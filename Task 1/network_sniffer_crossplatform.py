#!/usr/bin/env python3
"""
Cross-Platform Network Sniffer
================================
Works on Windows, Linux, and macOS using Scapy.

Requirements:
    pip install scapy

  Windows  → also install Npcap from https://npcap.com/#download
             then run this script as Administrator
  Linux    → run with: sudo python3 network_sniffer_crossplatform.py
  macOS    → run with: sudo python3 network_sniffer_crossplatform.py

Usage:
    python network_sniffer_crossplatform.py               # auto-pick interface
    python network_sniffer_crossplatform.py --list        # list interfaces
    python network_sniffer_crossplatform.py --iface eth0  # pick interface
    python network_sniffer_crossplatform.py --filter tcp  # protocol filter
    python network_sniffer_crossplatform.py --count 50    # stop after 50 packets
    python network_sniffer_crossplatform.py --output capture.pcap
    python network_sniffer_crossplatform.py --log capture.txt
"""

import sys
import os
import platform
import argparse
import datetime

# ── Dependency check ────────────────────────────────────────────────────────
try:
    from scapy.all import (
        sniff, get_if_list, conf,
        IP, IPv6, TCP, UDP, ICMP, DNS, Raw, Ether,
        wrpcap,
    )
    # On Windows, Scapy needs Npcap; this import will fail if absent
    if platform.system() == "Windows":
        from scapy.arch.windows import get_windows_if_list
except ImportError:
    print("ERROR: Scapy is not installed.")
    print("  Run:  pip install scapy")
    if platform.system() == "Windows":
        print("  Also: Install Npcap from https://npcap.com/#download")
    sys.exit(1)


# ──────────────────────────────────────────────
# Globals
# ──────────────────────────────────────────────
OS      = platform.system()          # "Windows" | "Linux" | "Darwin"
SEP     = "─" * 72
SEP2    = "═" * 72
TAB     = "    "
TAB2    = TAB * 2

stats            = {"TCP": 0, "UDP": 0, "ICMP": 0, "DNS": 0, "OTHER": 0, "TOTAL": 0}
captured_packets = []
log_handle       = None   # set to an open file if --log is used


def output(text: str):
    """Print to screen and optionally write to log file."""
    print(text)
    if log_handle:
        log_handle.write(text + "\n")


# ──────────────────────────────────────────────
# Privilege / Environment Checks
# ──────────────────────────────────────────────

def check_privileges():
    """It will warn the user if the program does not have access to the necessary privileges."""
    if OS == "Windows":
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("⚠  WARNING: Not running as Administrator.")
            print("   Right-click your terminal → 'Run as administrator'")
            print("   then re-run this script.\n")
    else:
        if os.geteuid() != 0:
            print("⚠  WARNING: Not running as root.")
            print(f"   Try:  sudo python3 {sys.argv[0]}\n")


def check_npcap_windows():
    """This will verify that npcap is installed and exists in the system32 files."""
    if OS != "Windows":
        return
    npcap_path = r"C:\Windows\System32\Npcap"
    if not os.path.isdir(npcap_path):
        print("⚠  Npcap does not appear to be installed.")
        print("   Download it from: https://npcap.com/#download")
        print("   Install it, then re-run this script.\n")


# ──────────────────────────────────────────────
# Interface Helpers
# ──────────────────────────────────────────────

def list_interfaces():
    """Print available network interfaces."""
    print(SEP2)
    print("  AVAILABLE NETWORK INTERFACES")
    print(SEP)

    if OS == "Windows":
        try:
            ifaces = get_windows_if_list()
            for i, iface in enumerate(ifaces):
                name  = iface.get("name", "?")
                desc  = iface.get("description", "")
                ips   = ", ".join(iface.get("ips", [])) or "no IP"
                print(f"  [{i}] {desc}")
                print(f"       Name : {name}")
                print(f"       IPs  : {ips}")
                print()
        except Exception as e:
            print(f"  Could not enumerate interfaces: {e}")
    else:
        ifaces = get_if_list()
        for i, iface in enumerate(ifaces):
            print(f"  [{i}] {iface}")

    print(SEP2)
    print("  Use --iface <name> to select one.")
    print(SEP2)


def pick_default_interface():
    """Return the default interface Scapy would use."""
    try:
        return conf.iface
    except Exception:
        return None


# ──────────────────────────────────────────────
# Packet Formatting Helpers
# ──────────────────────────────────────────────

def format_hex(data: bytes, indent: str = "") -> str:
    """Hex + ASCII dump, 16 bytes per row."""
    lines = []
    for i in range(0, min(len(data), 128), 16):
        chunk   = data[i:i+16]
        hex_p   = " ".join(f"{b:02x}" for b in chunk).ljust(47)
        ascii_p = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{indent}  {hex_p}  {ascii_p}")
    if len(data) > 128:
        lines.append(f"{indent}  ... ({len(data)-128} more bytes)")
    return "\n".join(lines)


ICMP_TYPES = {
    0: "Echo Reply",
    3: "Dest Unreachable",
    8: "Echo Request",
    11: "Time Exceeded",
    12: "Parameter Problem",
}


# ──────────────────────────────────────────────
# Protocol Filter
# ──────────────────────────────────────────────

PROTO_FILTER = "all"   # set by CLI arg; checked inside process_packet

def _proto_allowed(name: str) -> bool:
    return PROTO_FILTER in ("all", name.lower())


# ──────────────────────────────────────────────
# Main Packet Callback
# ──────────────────────────────────────────────

def process_packet(pkt):
    """Called by Scapy for every captured packet."""
    stats["TOTAL"] += 1
    captured_packets.append(pkt)

    ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]

    # ── Determine transport protocol first (for filter) ──────────────────
    if TCP  in pkt: transport = "tcp"
    elif UDP  in pkt: transport = "udp"
    elif ICMP in pkt: transport = "icmp"
    else:             transport = "other"

    if not _proto_allowed(transport):
        return

    output(SEP)

    # ── Ethernet header (may be absent on some Windows captures) ─────────
    if Ether in pkt:
        eth = pkt[Ether]
        output(f"  [#{stats['TOTAL']}] {ts}")
        output(f"{TAB}Ethernet   {eth.src}  →  {eth.dst}")
    else:
        output(f"  [#{stats['TOTAL']}] {ts}  (no Ethernet header)")

    # ── IPv4 ─────────────────────────────────────────────────────────────
    if IP in pkt:
        ip = pkt[IP]
        proto_label = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(ip.proto, f"IP({ip.proto})")
        output(f"{TAB}IPv4       {ip.src}  →  {ip.dst}  "
               f"TTL={ip.ttl}  Proto={proto_label}  Len={ip.len}")

        if TCP in pkt:
            _handle_tcp(pkt)
        elif UDP in pkt:
            _handle_udp(pkt)
        elif ICMP in pkt:
            _handle_icmp(pkt)
        else:
            stats["OTHER"] += 1

    # ── IPv6 (basic) ─────────────────────────────────────────────────────
    elif IPv6 in pkt:
        ip6 = pkt[IPv6]
        output(f"{TAB}IPv6       {ip6.src}  →  {ip6.dst}")
        if TCP in pkt:
            _handle_tcp(pkt)
        elif UDP in pkt:
            _handle_udp(pkt)
        else:
            stats["OTHER"] += 1

    else:
        stats["OTHER"] += 1
        output(f"{TAB}Non-IP packet")


def _handle_tcp(pkt):
    stats["TCP"] += 1
    tcp   = pkt[TCP]
    flags = tcp.sprintf("%flags%")
    output(f"{TAB}TCP        {tcp.sport}  →  {tcp.dport}  "
           f"Flags=[{flags}]  Seq={tcp.seq}  Ack={tcp.ack}")

    if Raw in pkt:
        raw = pkt[Raw].load
        try:
            decoded = raw[:400].decode("utf-8", errors="replace")
            if decoded.startswith(("GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "HTTP/")):
                first_line = decoded.split("\r\n")[0]
                output(f"{TAB2}▶ HTTP  {first_line}")
        except Exception:
            pass
        output(f"{TAB2}Payload: {len(raw)} bytes")
        output(format_hex(raw, TAB2))


def _handle_udp(pkt):
    stats["UDP"] += 1
    udp = pkt[UDP]
    output(f"{TAB}UDP        {udp.sport}  →  {udp.dport}  Len={udp.len}")

    if DNS in pkt:
        stats["DNS"] += 1
        dns = pkt[DNS]
        if dns.qr == 0:
            qname = dns.qd.qname.decode(errors="replace") if dns.qd else "?"
            output(f"{TAB2}▶ DNS Query   {qname}")
        else:
            answers = []
            an = dns.an
            while an:
                try:
                    answers.append(str(an.rdata))
                except Exception:
                    pass
                an = an.payload if hasattr(an, "payload") else None
            output(f"{TAB2}▶ DNS Response  {', '.join(answers) or '(no data)'}")
    elif Raw in pkt:
        raw = pkt[Raw].load
        output(f"{TAB2}Payload: {len(raw)} bytes")
        output(format_hex(raw, TAB2))


def _handle_icmp(pkt):
    stats["ICMP"] += 1
    icmp      = pkt[ICMP]
    type_desc = ICMP_TYPES.get(icmp.type, "Other")
    output(f"{TAB}ICMP       Type={icmp.type} ({type_desc})  Code={icmp.code}")


# ──────────────────────────────────────────────
# Summary
# ──────────────────────────────────────────────

def print_summary(output_file=None, log_file=None):
    output(SEP2)
    output("  CAPTURE SUMMARY")
    output(SEP)
    for k, v in stats.items():
        if v:
            output(f"  {k:<8}: {v}")
    if output_file and captured_packets:
        wrpcap(output_file, captured_packets)
        output(SEP)
        output(f"  Saved {len(captured_packets)} packets → {output_file} (Wireshark .pcap)")
    if log_file:
        output(SEP)
        output(f"  Log saved → {log_file} (plain text)")
    output(SEP2)


# ──────────────────────────────────────────────
# Entry Point
# ──────────────────────────────────────────────

def main():
    global PROTO_FILTER

    parser = argparse.ArgumentParser(
        description="Cross-Platform Network Sniffer (Windows / Linux / macOS)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--list",   action="store_true",
                        help="List available network interfaces and exit")
    parser.add_argument("--iface",  type=str, default=None,
                        help="Interface name to sniff on (use --list to find names)")
    parser.add_argument("--filter", type=str, default="all",
                        choices=["tcp", "udp", "icmp", "all"],
                        help="Protocol filter (default: all)")
    parser.add_argument("--count",  type=int, default=0,
                        help="Stop after N packets (0 = unlimited)")
    parser.add_argument("--output", type=str, default=None,
                        help="Save captured packets to a .pcap file (open in Wireshark)")
    parser.add_argument("--log",    type=str, default=None,
                        help="Save output to a plain text .txt log file")
    args = parser.parse_args()

    # ── List interfaces and exit ─────────────────────────────────────────
    if args.list:
        list_interfaces()
        return

    # ── Environment checks ───────────────────────────────────────────────
    check_privileges()
    check_npcap_windows()

    PROTO_FILTER = args.filter

    # ── Open log file ────────────────────────────────────────────────────
    global log_handle
    if args.log:
        log_handle = open(args.log, "w", encoding="utf-8")

    # ── Resolve interface ────────────────────────────────────────────────
    iface = args.iface or pick_default_interface()

    # ── Banner ───────────────────────────────────────────────────────────
    print(SEP2)
    print("  CROSS-PLATFORM NETWORK SNIFFER")
    print(SEP)
    print(f"  OS        : {OS}")
    print(f"  Interface : {iface or 'auto'}")
    print(f"  Filter    : {args.filter.upper()}")
    print(f"  Count     : {args.count if args.count else 'unlimited'}")
    if args.output:
        print(f"  Output    : {args.output}  (.pcap for Wireshark)")
    if args.log:
        print(f"  Log       : {args.log}  (plain text)")
    print(SEP)
    print("  Press Ctrl+C to stop capturing")
    print(SEP2)

    # ── Start sniffing ───────────────────────────────────────────────────
    try:
        sniff(
            prn=process_packet,
            count=args.count,
            iface=iface,
            store=False,
        )
    except PermissionError:
        print("\nERROR: Permission denied.")
        if OS == "Windows":
            print("  → Run Command Prompt as Administrator")
        else:
            print(f"  → Run:  sudo python3 {sys.argv[0]}")
    except OSError as e:
        print(f"\nERROR: Could not open interface: {e}")
        print("  → Run with --list to see available interfaces")
    except KeyboardInterrupt:
        print("\n\nCapture stopped by user.")
    finally:
        print_summary(args.output, args.log)
        if log_handle:
            log_handle.close()


if __name__ == "__main__":
    main()
