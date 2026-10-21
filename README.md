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
| **Low Resource Usage** | Optimized with BPF filters to run on low-end hardware (e.g., Raspberry Pi). |

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
This tool requires root privileges to access the network card.

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

What to Expect:

The script will print the Gateway's MAC address.

It will sit silently until an attack occurs.

If an attack is detected, you will see:

[!!!] YOU ARE UNDER ATTACK! Real MAC: XX:XX... Fake MAC: YY:YY...

🧠 How It Works
ArpGuard uses the Trust-On-First-Use (TOFU) principle:

Baseline: On startup, it asks the router for its real MAC address.

Monitor: It listens to all ARP traffic using Scapy.

Compare: Every time a packet claims to be the router, it compares the MAC address to the baseline.

Alert: If they don't match, it triggers an alarm.

ArpGuard also inspects ARP requests as well as replies, so gateway claims in gratuitous ARP announcements are checked too. It flags packets where the Ethernet source MAC differs from the ARP sender MAC. These checks identify suspicious packet attributes; investigate the device and network context before treating every alert as a confirmed attack.

Each alert is written as one JSON object to the terminal and `arpguard.log`. It includes the timestamp, captured interface when Scapy provides it, packet type, gateway IP and expected MAC, observed sender MACs, and the reasons for the alert. The interface is reported as `unknown` when the capture backend does not provide it.

⚠️ Disclaimer
For Educational Purposes Only. This tool is designed for defensive use (Blue Teaming) to protect your own network. The author is not responsible for any misuse of this tool.
