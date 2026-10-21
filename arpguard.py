#!/usr/bin/env python3
from scapy.all import *
import argparse
import logging
import re
import sys

# 1. Initialize the Black Box Logger
logging.basicConfig(
    filename='arpguard.log',
    level=logging.WARNING,
    format='%(asctime)s - [ALERT] - %(message)s'
)

def get_gateway_ip():
    """Automatically find the default gateway IP."""
    return conf.route.route("0.0.0.0")[2]

def get_real_mac(ip):
    """Send a legitimate ARP request to get the true MAC address."""
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, verbose=0)
    for snd, rcv in ans:
        if rcv.haslayer(ARP) and rcv[ARP].psrc == ip:
            return rcv[ARP].hwsrc.lower()
    return None

def normalize_mac(mac):
    """Return a normalized MAC address, or None when the value is invalid."""
    if not mac or not re.fullmatch(r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}", mac):
        return None
    return mac.lower()

def parse_args():
    parser = argparse.ArgumentParser(description="Detect ARP spoofing attempts against the default gateway.")
    parser.add_argument(
        "--gateway-mac",
        help="Expected gateway MAC address. The discovered MAC must match this value.",
    )
    return parser.parse_args()

# 2. Baseline Configuration
print("========================================")
print("      🛡️ ArpGuard IDS Active 🛡️      ")
print("========================================")

args = parse_args()
configured_gateway_mac = normalize_mac(args.gateway_mac) if args.gateway_mac else None
if args.gateway_mac and not configured_gateway_mac:
    print("[!] Error: --gateway-mac must be a MAC address like aa:bb:cc:dd:ee:ff.")
    sys.exit(2)

gateway_ip = get_gateway_ip()
print(f"[*] Discovering Gateway IP: {gateway_ip}")

gateway_mac = get_real_mac(gateway_ip)
if not gateway_mac:
    print("[!] Error: Could not resolve Gateway MAC. Check your network connection.")
    sys.exit(1)

if configured_gateway_mac:
    if gateway_mac != configured_gateway_mac:
        print(f"[!] Error: Discovered gateway MAC {gateway_mac} does not match configured MAC {configured_gateway_mac}.")
        print("[!] Verify the gateway MAC on a trusted network before starting ArpGuard.")
        sys.exit(1)
    gateway_mac = configured_gateway_mac
    print("[*] Discovered gateway MAC matches the configured expected MAC.")
else:
    print("[!] Trust check: verify this gateway MAC using your router label/admin page or another trusted source.")
    try:
        confirmation = input("[?] Use this MAC as the trusted baseline? [y/N]: ").strip().lower()
    except EOFError:
        confirmation = ""
    if confirmation not in ("y", "yes"):
        print("[*] Baseline not confirmed. ArpGuard will exit without monitoring.")
        sys.exit(1)

print(f"[*] True Gateway MAC locked as: {gateway_mac}")
print("[*] Monitoring local traffic... (Press Ctrl+C to stop)\n")

# 3. Core Detection Engine
def process_packet(packet):
    if not packet.haslayer(ARP) or packet[ARP].op not in (1, 2):
        return

    arp = packet[ARP]
    sender_mac = arp.hwsrc.lower()
    ethernet_mac = packet[Ether].src.lower() if packet.haslayer(Ether) else None
    reasons = []

    # Requests and gratuitous ARP announcements can also poison neighbor caches.
    if arp.psrc == gateway_ip and sender_mac != gateway_mac:
        reasons.append(f"gateway IP {gateway_ip} claimed by unexpected MAC {sender_mac} (expected {gateway_mac})")

    # The Ethernet source and ARP sender hardware address should describe the same device.
    if ethernet_mac and ethernet_mac != sender_mac:
        reasons.append(f"Ethernet source {ethernet_mac} does not match ARP sender MAC {sender_mac}")

    if reasons:
        packet_type = "request" if arp.op == 1 else "reply"
        alert_msg = f"Suspicious ARP {packet_type}: " + "; ".join(reasons)

        print("[!!!] Suspicious ARP activity detected!")
        print(f"[!!!] {alert_msg}\n")
        logging.warning(alert_msg)

# 4. Start the Sniffer
try:
    # store=0 ensures we don't eat up your RAM by keeping packets in memory
    sniff(filter="arp", prn=process_packet, store=0)
except KeyboardInterrupt:
    print("\n[*] Shutting down ArpGuard. Stay safe.")
    sys.exit(0)
