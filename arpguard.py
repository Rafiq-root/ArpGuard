#!/usr/bin/env python3
from scapy.all import *
import argparse
from datetime import datetime
import ipaddress
import json
import logging
import os
import re
import sys

# 1. Initialize the Black Box Logger
logging.basicConfig(
    filename='arpguard.log',
    level=logging.WARNING,
    format='%(message)s'
)

def get_gateway_route(interface=None):
    """Return the default-route interface and gateway, optionally scoped to an interface."""
    route = conf.route.route("0.0.0.0", dev=interface) if interface else conf.route.route("0.0.0.0")
    return route[0], route[2]

def get_real_mac(ip, interface=None):
    """Send a legitimate ARP request to get the true MAC address."""
    ans, unans = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip),
        timeout=2,
        verbose=0,
        iface=interface,
    )
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
    parser.add_argument(
        "--interface",
        help="Network interface to use (defaults to the interface selected by the default route).",
    )
    parser.add_argument("--pcap", help="Replay an offline PCAP file instead of monitoring a live interface.")
    parser.add_argument("--gateway-ip", help="Gateway IPv4 address to use with --pcap.")
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

if args.pcap:
    if args.interface:
        print("[!] Error: --interface cannot be used with --pcap.")
        sys.exit(2)
    if not args.gateway_ip or not configured_gateway_mac:
        print("[!] Error: Offline replay requires both --gateway-ip and --gateway-mac.")
        sys.exit(2)
    try:
        if ipaddress.ip_address(args.gateway_ip).version != 4:
            raise ValueError("gateway must be IPv4")
    except ValueError as exc:
        print(f"[!] Error: Invalid --gateway-ip: {exc}")
        sys.exit(2)
    if not os.path.isfile(args.pcap):
        print(f"[!] Error: PCAP file not found: {args.pcap}")
        sys.exit(2)
    gateway_ip = args.gateway_ip
    gateway_mac = configured_gateway_mac
    selected_interface = None
    print(f"[*] Replaying offline capture: {args.pcap}")
    print(f"[*] Using supplied gateway baseline: {gateway_ip} / {gateway_mac}")
else:
    if args.gateway_ip:
        print("[!] Error: --gateway-ip is only valid with --pcap.")
        sys.exit(2)
    if args.interface and args.interface not in get_if_list():
        print(f"[!] Error: Interface '{args.interface}' was not found.")
        print("[*] Available interfaces: " + ", ".join(get_if_list()))
        sys.exit(2)

    try:
        selected_interface, gateway_ip = get_gateway_route(args.interface)
    except Exception as exc:
        print(f"[!] Error: Could not find a default route on the selected interface: {exc}")
        sys.exit(1)

    if not gateway_ip or gateway_ip == "0.0.0.0":
        print("[!] Error: No usable default gateway was found on the selected interface.")
        sys.exit(1)

    if args.interface and selected_interface != args.interface:
        print(f"[!] Error: The default route resolved to '{selected_interface}', not '{args.interface}'.")
        sys.exit(1)

    print(f"[*] Using interface: {selected_interface}")
    print(f"[*] Discovering Gateway IP: {gateway_ip}")

    gateway_mac = get_real_mac(gateway_ip, selected_interface)
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

if args.pcap:
    print("[*] Replaying packets...\n")

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
        event = {
            "timestamp": datetime.now().astimezone().isoformat(timespec="seconds"),
            "event": "suspicious_arp",
            "capture_mode": "offline" if args.pcap else "live",
            "packet_type": packet_type,
            "interface": None if args.pcap else (getattr(packet, "sniffed_on", None) or selected_interface or "unknown"),
            "capture_file": os.path.basename(args.pcap) if args.pcap else None,
            "gateway_ip": gateway_ip,
            "expected_gateway_mac": gateway_mac,
            "arp_sender_ip": arp.psrc,
            "arp_sender_mac": sender_mac,
            "ethernet_source_mac": ethernet_mac,
            "reasons": reasons,
        }
        alert_msg = json.dumps(event, sort_keys=True)

        print(f"[!!!] Suspicious ARP activity detected: {alert_msg}\n")
        logging.warning(alert_msg)

# 4. Start the Sniffer
try:
    # store=0 ensures we don't eat up your RAM by keeping packets in memory.
    if args.pcap:
        sniff(offline=args.pcap, prn=process_packet, store=0)
        print("[*] Offline replay complete.")
    else:
        sniff(iface=selected_interface, filter="arp", prn=process_packet, store=0)
except KeyboardInterrupt:
    print("\n[*] Shutting down ArpGuard. Stay safe.")
    sys.exit(0)
except Exception as exc:
    print(f"[!] Error while reading capture or monitoring: {exc}")
    sys.exit(1)
