# 🛡️ ArpGuard: Network Intrusion Detection System

![Python](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python)
![Scapy](https://img.shields.io/badge/Powered%20By-Scapy-green?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Linux-red?style=for-the-badge&logo=linux)
![License](https://img.shields.io/badge/License-MIT-orange?style=for-the-badge)

> **ArpGuard** is a lightweight, stealthy Python script that detects ARP Spoofing attacks in real-time. It acts as a "Blue Team" tool, alerting you instantly if a hacker attempts a Man-in-the-Middle (MitM) attack on your local network.

---

## 📋 Table of Contents
- [Features](#-features)
- [Installation](#-installation)
- [Usage](#-usage)
- [How It Works](#-how-it-works)
- [Disclaimer](#-disclaimer)

---

## 🚀 Features
| Feature | Description |
| :--- | :--- |
| **Auto-Gateway Detection** | Automatically finds your Router IP and MAC address. |
| **Stealth Mode** | Uses passive sniffing; does not broadcast packets unless necessary. |
| **ARP Anomaly Alerts** | Checks gateway claims in ARP requests and replies, and flags mismatches between Ethernet source and ARP sender MAC addresses. |
| **IPv6 NDP checks** | Optionally checks IPv6 router advertisements and neighbor advertisements against a separately verified router address and MAC. |
| **Low Resource Usage** | Optimized with BPF filters to run on low-end hardware (e.g., Raspberry Pi). |
| **Linux service example** | Includes a systemd unit for unattended monitoring with packet-capture capability instead of running the full service as root. |
| **Rotating JSON logs** | Keeps alert logs bounded and lets you choose their location. |

---

## 📦 Installation

**1. Clone the repository**
```bash
git clone [https://github.com/Rafiq-root/ArpGuard.git](https://github.com/Rafiq-root/ArpGuard.git)
cd ArpGuard


2. Install Dependencies You need Python 3 and Scapy.
Bash
sudo apt update
sudo apt install python3-scapy


🛠️ Usage
Live monitoring requires raw packet-capture privileges. You can run it with `sudo`, or use the example systemd service below, which runs as a dedicated account with `CAP_NET_RAW`.

Basic Run:

Bash
sudo python3 arpguard.py

On startup, ArpGuard discovers the default gateway and asks you to verify its MAC address before trusting it. Check the displayed value against your router's admin page, label, or another trusted source. If you cannot confirm it, answer `n` (or press Enter) and monitoring exits.

For repeat runs, provide a MAC address that you have already verified:

```bash
sudo python3 arpguard.py --gateway-mac aa:bb:cc:dd:ee:ff
```

ArpGuard still probes the gateway at startup and exits if the discovered MAC does not match the configured value. This avoids silently trusting an unexpected startup response. Recheck the configured MAC if you replace your router or change network hardware.

To monitor a specific interface, pass its name. Gateway discovery, the baseline ARP probe, and passive capture all use the selected interface:

```bash
sudo python3 arpguard.py --interface eth0
sudo python3 arpguard.py --interface eth0 --gateway-mac aa:bb:cc:dd:ee:ff
```

Without `--interface`, ArpGuard uses the interface selected by the default route. An explicitly selected interface must have a usable default route; ArpGuard exits with an error rather than silently monitoring a different network.

On dual-stack networks, you can also monitor IPv6 Neighbor Discovery by supplying the router's IPv6 address and a MAC you verified independently. Router Advertisements from another IPv6 address or MAC, and Neighbor Advertisements claiming the configured router address from another MAC, are reported:

```bash
sudo python3 arpguard.py --interface eth0 --gateway-mac aa:bb:cc:dd:ee:ff --ipv6-gateway-ip fe80::1 --ipv6-gateway-mac aa:bb:cc:dd:ee:ff
```

The IPv6 trust values are explicit and are never learned from the monitored packets. If your network has multiple legitimate IPv6 routers, configure and account for them before enabling this check; announcements from other routers are reported as unexpected.

### Offline PCAP replay

You can analyze a saved capture without root access or sending packets. Supply the gateway IP and a MAC address verified from a trusted source. Add the optional IPv6 router pair to inspect NDP traffic too:

```bash
python3 arpguard.py --pcap capture.pcap --gateway-ip 192.168.1.1 --gateway-mac aa:bb:cc:dd:ee:ff
python3 arpguard.py --pcap capture.pcap --gateway-ip 192.168.1.1 --gateway-mac aa:bb:cc:dd:ee:ff --ipv6-gateway-ip fe80::1 --ipv6-gateway-mac aa:bb:cc:dd:ee:ff
```

Offline mode reads packets from the PCAP and reports matching anomalies using the same detector as live monitoring. It does not discover or probe a gateway and does not start a live network capture. The IPv4 gateway pair is required; the IPv6 pair is optional. Supplied values keep the replay from treating a value learned from the capture itself as trusted.

What to Expect:

The script will print the Gateway's MAC address.

It will sit silently until an attack occurs.

If an attack is detected, you will see:

[!!!] YOU ARE UNDER ATTACK! Real MAC: XX:XX... Fake MAC: YY:YY...

### Run as a Linux service

The example unit runs ArpGuard as a dedicated `arpguard` user. Install Scapy for the system Python first, then from the repository root:

```bash
sudo apt update
sudo apt install -y python3-scapy
sudo useradd --system --no-create-home --shell /usr/sbin/nologin arpguard
sudo install -d -m 0755 /opt/arpguard /etc/arpguard
sudo install -m 0755 arpguard.py /opt/arpguard/arpguard.py
sudo install -m 0644 packaging/arpguard.service /etc/systemd/system/arpguard.service
```

Create `/etc/arpguard/arpguard.conf` with the interface and gateway MAC you verified independently:

```text
ARPGUARD_INTERFACE=eth0
ARPGUARD_GATEWAY_MAC=aa:bb:cc:dd:ee:ff
```

Then enable and inspect the service:

```bash
sudo chmod 0644 /etc/arpguard/arpguard.conf
sudo systemctl daemon-reload
sudo systemctl enable --now arpguard
sudo systemctl status arpguard
sudo journalctl -u arpguard -f
```

The service probes the gateway at startup and stops if its MAC differs from the configured value. Update the config if your gateway hardware changes. Logs are written to `/var/lib/arpguard/arpguard.log`.

🧠 How It Works
ArpGuard uses the Trust-On-First-Use (TOFU) principle:

Baseline: On startup, it asks the router for its real MAC address.

Monitor: It listens to all ARP traffic using Scapy.

Compare: Every time a packet claims to be the router, it compares the MAC address to the baseline.

Alert: If they don't match, it triggers an alarm.

ArpGuard also inspects ARP requests as well as replies, so gateway claims in gratuitous ARP announcements are checked too. It flags packets where the Ethernet source MAC differs from the ARP sender MAC. These checks identify suspicious packet attributes; investigate the device and network context before treating every alert as a confirmed attack.

Each alert is written as one JSON object to the terminal and a rotating log file. By default the file is `arpguard.log` in the current directory; five 5 MB files are kept. Set a different location or file size with `--log-file` and `--log-size-mb`, for example:

```bash
sudo python3 arpguard.py --log-file /var/log/arpguard/events.jsonl --log-size-mb 10
```

Each entry includes the timestamp, capture mode, interface for live capture (or `null` for offline replay), PCAP filename when replaying, packet type, gateway IP and expected MAC, observed sender MACs, and the reasons for the alert. The log contents are JSON Lines, with one alert object per line.

⚠️ Disclaimer
For Educational Purposes Only. This tool is designed for defensive use (Blue Teaming) to protect your own network. The author is not responsible for any misuse of this tool.
