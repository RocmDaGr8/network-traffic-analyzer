# network-traffic-analyzer

Python tool to capture and analyze network packets, detect anomalies and potential security threats.

## Features

- Live packet capture on any network interface
- Read and analyze existing `.pcap` files
- Protocol breakdown (TCP, UDP, ICMP, ARP)
- Top talkers — most active source IPs
- Top destination ports with suspicious port flagging
- Anomaly detection:
  - Port scan detection (single IP contacting 15+ unique ports)
  - High volume traffic detection (200+ packets from one IP)
- BPF filter support (e.g. `tcp`, `port 80`, `host 192.168.1.1`)
- Clean terminal report at end of capture

## Screenshots / Demo

```
============================================================
        NETWORK TRAFFIC ANALYSIS REPORT
============================================================
  Total Packets : 250
  Duration      : 12.3s
  Capture Time  : 2026-06-01 14:22:10

--- Protocol Breakdown ---
  TCP      189 packets  (75.6%)
  UDP       43 packets  (17.2%)
  ICMP      18 packets  (7.2%)

--- Top 10 Source IPs ---
  192.168.1.105         87 packets
  10.0.0.22             54 packets

--- Security Alerts ---
  [!] POSSIBLE PORT SCAN: 10.0.0.22 contacted 23 unique ports
  [!] Suspicious port 4444 (Metasploit default) from 10.0.0.22 -> 192.168.1.1
============================================================
```

## Installation

```bash
git clone https://github.com/RocmDaGr8/network-traffic-analyzer.git
cd network-traffic-analyzer
pip install -r requirements.txt
```

## Usage

**Live capture** (requires root/sudo):
```bash
sudo python3 analyzer.py -i eth0 -c 200
sudo python3 analyzer.py -i eth0 -c 500 -f "tcp"
```

**Analyze a .pcap file:**
```bash
python3 analyzer.py -r capture.pcap
```

**Full options:**
```
usage: analyzer.py [-h] (-i INTERFACE | -r READ) [-c COUNT] [-f FILTER]

  -i INTERFACE   Network interface for live capture (e.g. eth0, wlan0)
  -r READ        Read from a .pcap file
  -c COUNT       Number of packets to capture (default: 100)
  -f FILTER      BPF filter string (e.g. 'tcp', 'port 443')
```

## How It Works

Packets are captured via Scapy's `sniff()` function or loaded from a pcap file. Each packet is parsed for IP, TCP, UDP, ICMP, and ARP layers. The analyzer tracks per-IP traffic volume and unique destination ports to flag port scans and high-volume sources. A report is printed at the end of the capture session.

## Roadmap

- [ ] CSV/JSON export of results
- [ ] Real-time dashboard (Flask + Chart.js)
- [ ] GeoIP lookup for external IPs
- [ ] DNS query logging

## License

MIT
