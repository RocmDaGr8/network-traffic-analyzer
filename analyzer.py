#!/usr/bin/env python3
"""
Network Traffic Analyzer
Captures and analyzes network packets to detect anomalies and security threats.
Requires root/admin privileges for live capture.
"""

import argparse
import sys
from collections import Counter, defaultdict
from datetime import datetime

try:
    from scapy.all import sniff, rdpcap, IP, TCP, UDP, ICMP, ARP
    from scapy.layers.http import HTTP
except ImportError:
    print("[!] scapy not installed. Run: pip install scapy")
    sys.exit(1)


SUSPICIOUS_PORTS = {
    22: "SSH", 23: "Telnet", 445: "SMB", 3389: "RDP",
    4444: "Metasploit default", 1337: "Common backdoor",
    6667: "IRC (often C2)", 31337: "Elite backdoor",
}

PORT_SCAN_THRESHOLD = 15   # unique ports from one IP = port scan
HIGH_VOLUME_THRESHOLD = 200  # packets from one IP = high volume


class TrafficAnalyzer:
    def __init__(self):
        self.packets = []
        self.ip_counter = Counter()
        self.dst_counter = Counter()
        self.protocol_counter = Counter()
        self.port_counter = Counter()
        self.src_ports = defaultdict(set)   # src_ip -> set of dst ports contacted
        self.alerts = []
        self.start_time = None
        self.end_time = None

    def process_packet(self, pkt):
        if self.start_time is None:
            self.start_time = datetime.now()
        self.end_time = datetime.now()
        self.packets.append(pkt)

        if pkt.haslayer(IP):
            src = pkt[IP].src
            dst = pkt[IP].dst
            self.ip_counter[src] += 1
            self.dst_counter[dst] += 1

            if pkt.haslayer(TCP):
                self.protocol_counter["TCP"] += 1
                dport = pkt[TCP].dport
                self.port_counter[dport] += 1
                self.src_ports[src].add(dport)
                if dport in SUSPICIOUS_PORTS:
                    self.alerts.append(
                        f"[!] Suspicious port {dport} ({SUSPICIOUS_PORTS[dport]}) "
                        f"from {src} -> {dst}"
                    )

            elif pkt.haslayer(UDP):
                self.protocol_counter["UDP"] += 1
                dport = pkt[UDP].dport
                self.port_counter[dport] += 1
                self.src_ports[src].add(dport)

            elif pkt.haslayer(ICMP):
                self.protocol_counter["ICMP"] += 1

        elif pkt.haslayer(ARP):
            self.protocol_counter["ARP"] += 1

    def detect_anomalies(self):
        for ip, ports in self.src_ports.items():
            if len(ports) >= PORT_SCAN_THRESHOLD:
                self.alerts.append(
                    f"[!] POSSIBLE PORT SCAN: {ip} contacted {len(ports)} unique ports"
                )

        for ip, count in self.ip_counter.items():
            if count >= HIGH_VOLUME_THRESHOLD:
                self.alerts.append(
                    f"[!] HIGH VOLUME TRAFFIC: {ip} sent {count} packets"
                )

    def print_report(self):
        self.detect_anomalies()
        duration = (self.end_time - self.start_time).total_seconds() if self.start_time else 0

        print("\n" + "=" * 60)
        print("        NETWORK TRAFFIC ANALYSIS REPORT")
        print("=" * 60)
        print(f"  Total Packets : {len(self.packets)}")
        print(f"  Duration      : {duration:.1f}s")
        print(f"  Capture Time  : {self.start_time.strftime('%Y-%m-%d %H:%M:%S') if self.start_time else 'N/A'}")

        print("\n--- Protocol Breakdown ---")
        for proto, count in self.protocol_counter.most_common():
            pct = (count / len(self.packets) * 100) if self.packets else 0
            print(f"  {proto:<8} {count:>6} packets  ({pct:.1f}%)")

        print("\n--- Top 10 Source IPs ---")
        for ip, count in self.ip_counter.most_common(10):
            print(f"  {ip:<20} {count:>6} packets")

        print("\n--- Top 10 Destination Ports ---")
        for port, count in self.port_counter.most_common(10):
            label = SUSPICIOUS_PORTS.get(port, "")
            flag = " [SUSPICIOUS]" if label else ""
            print(f"  Port {port:<8} {count:>6} hits   {label}{flag}")

        print("\n--- Security Alerts ---")
        if self.alerts:
            seen = set()
            for alert in self.alerts:
                if alert not in seen:
                    print(f"  {alert}")
                    seen.add(alert)
        else:
            print("  No anomalies detected.")

        print("=" * 60 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Network Traffic Analyzer — capture and analyze packets for security threats"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-i", "--interface", help="Network interface for live capture (e.g. eth0)")
    group.add_argument("-r", "--read", help="Read from a .pcap file instead of live capture")
    parser.add_argument("-c", "--count", type=int, default=100,
                        help="Number of packets to capture in live mode (default: 100)")
    parser.add_argument("-f", "--filter", default="",
                        help="BPF filter string (e.g. 'tcp', 'port 80')")
    args = parser.parse_args()

    analyzer = TrafficAnalyzer()

    if args.read:
        print(f"[*] Reading packets from: {args.read}")
        try:
            packets = rdpcap(args.read)
            for pkt in packets:
                analyzer.process_packet(pkt)
        except FileNotFoundError:
            print(f"[!] File not found: {args.read}")
            sys.exit(1)
    else:
        print(f"[*] Capturing {args.count} packets on interface: {args.interface}")
        print("[*] Press Ctrl+C to stop early\n")
        try:
            sniff(
                iface=args.interface,
                count=args.count,
                filter=args.filter,
                prn=analyzer.process_packet,
                store=False,
            )
        except PermissionError:
            print("[!] Permission denied. Run with sudo for live capture.")
            sys.exit(1)
        except KeyboardInterrupt:
            print("\n[*] Capture stopped by user.")

    analyzer.print_report()


if __name__ == "__main__":
    main()
