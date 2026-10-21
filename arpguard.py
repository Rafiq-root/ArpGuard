#!/usr/bin/env python3
from scapy.all import *
import argparse
from datetime import datetime
import ipaddress
import json
import logging
from logging.handlers import RotatingFileHandler
import os
import re
import sys

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
        "--trusted-gateway-mac",
        action="append",
        default=[],
        help="Additional verified MAC allowed to claim the IPv4 gateway (repeat for HA/failover MACs).",
    )
    parser.add_argument(
        "--interface",
        help="Network interface to use (defaults to the interface selected by the default route).",
    )
    parser.add_argument("--pcap", help="Replay an offline PCAP file instead of monitoring a live interface.")
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="Validate startup configuration and live capture access, then exit without monitoring or replaying.",
    )
    parser.add_argument("--gateway-ip", help="Gateway IPv4 address to use with --pcap.")
    parser.add_argument("--ipv6-gateway-ip", help="Trusted IPv6 router address to monitor for Neighbor Discovery spoofing.")
    parser.add_argument("--ipv6-gateway-mac", help="Trusted MAC address for the IPv6 router; must be verified independently.")
    parser.add_argument(
        "--trusted-ipv6-router",
        action="append",
        default=[],
        metavar="IPv6=MAC",
        help="Additional verified IPv6 router address and MAC (repeat for multiple routers).",
    )
    parser.add_argument("--log-file", default="arpguard.log", help="JSON alert log path (default: arpguard.log).")
    parser.add_argument(
        "--log-size-mb",
        type=int,
        default=5,
        help="Maximum size for each alert log file before rotation (default: 5 MB; 5 backups are kept).",
    )
    return parser.parse_args()

# 2. Baseline Configuration
print("========================================")
print("      🛡️ ArpGuard IDS Active 🛡️      ")
print("========================================")

args = parse_args()
if args.log_size_mb < 1:
    print("[!] Error: --log-size-mb must be at least 1.")
    sys.exit(2)

try:
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.WARNING)
    log_handler = RotatingFileHandler(
        args.log_file,
        maxBytes=args.log_size_mb * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    log_handler.setFormatter(logging.Formatter("%(message)s"))
    root_logger.addHandler(log_handler)
except OSError as exc:
    print(f"[!] Error: Could not open alert log '{args.log_file}': {exc}")
    sys.exit(1)

configured_gateway_mac = normalize_mac(args.gateway_mac) if args.gateway_mac else None
if args.gateway_mac and not configured_gateway_mac:
    print("[!] Error: --gateway-mac must be a MAC address like aa:bb:cc:dd:ee:ff.")
    sys.exit(2)

trusted_gateway_macs = {configured_gateway_mac} if configured_gateway_mac else set()
for trusted_mac in args.trusted_gateway_mac:
    normalized_mac = normalize_mac(trusted_mac)
    if not normalized_mac:
        print(f"[!] Error: Invalid --trusted-gateway-mac '{trusted_mac}'. Expected aa:bb:cc:dd:ee:ff.")
        sys.exit(2)
    trusted_gateway_macs.add(normalized_mac)

if bool(args.ipv6_gateway_ip) != bool(args.ipv6_gateway_mac):
    print("[!] Error: IPv6 monitoring requires both --ipv6-gateway-ip and --ipv6-gateway-mac.")
    sys.exit(2)

ipv6_gateway_ip = None
ipv6_gateway_mac = None
trusted_ipv6_routers = {}
if args.ipv6_gateway_ip:
    try:
        if ipaddress.ip_address(args.ipv6_gateway_ip).version != 6:
            raise ValueError("router address must be IPv6")
    except ValueError as exc:
        print(f"[!] Error: Invalid --ipv6-gateway-ip: {exc}")
        sys.exit(2)
    ipv6_gateway_mac = normalize_mac(args.ipv6_gateway_mac)
    if not ipv6_gateway_mac:
        print("[!] Error: --ipv6-gateway-mac must be a MAC address like aa:bb:cc:dd:ee:ff.")
        sys.exit(2)
    ipv6_gateway_ip = str(ipaddress.IPv6Address(args.ipv6_gateway_ip))
    trusted_ipv6_routers[ipv6_gateway_ip] = ipv6_gateway_mac

for trusted_router in args.trusted_ipv6_router:
    try:
        router_ip_text, router_mac_text = trusted_router.rsplit("=", 1)
        router_ip = str(ipaddress.IPv6Address(router_ip_text))
    except (ValueError, TypeError):
        print(f"[!] Error: Invalid --trusted-ipv6-router '{trusted_router}'. Expected IPv6=MAC.")
        sys.exit(2)
    router_mac = normalize_mac(router_mac_text)
    if not router_mac:
        print(f"[!] Error: Invalid MAC in --trusted-ipv6-router '{trusted_router}'. Expected IPv6=aa:bb:cc:dd:ee:ff.")
        sys.exit(2)
    trusted_ipv6_routers[router_ip] = router_mac

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
    if not args.check_only:
        print(f"[*] Replaying offline capture: {args.pcap}")
    print(f"[*] Using supplied gateway baseline: {gateway_ip} / {gateway_mac}")
    if ipv6_gateway_ip:
        print(f"[*] Using supplied IPv6 router baseline: {ipv6_gateway_ip} / {ipv6_gateway_mac}")
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
    trusted_gateway_macs.add(gateway_mac)
    if ipv6_gateway_ip:
        print(f"[*] Monitoring IPv6 router: {ipv6_gateway_ip} / {ipv6_gateway_mac}")
    if not args.check_only:
        print("[*] Monitoring local traffic... (Press Ctrl+C to stop)\n")

capture_filter = "arp or icmp6" if trusted_ipv6_routers else "arp"

if args.check_only:
    if args.pcap:
        print("[*] Configuration check passed: offline PCAP and trusted baselines are ready.")
    else:
        try:
            capture_socket = conf.L2listen(iface=selected_interface, filter=capture_filter)
            capture_socket.close()
        except Exception as exc:
            print(f"[!] Error: Capture preflight failed on '{selected_interface}': {exc}")
            sys.exit(1)
        print(f"[*] Configuration check passed: capture is available on {selected_interface} with filter '{capture_filter}'.")
    sys.exit(0)

if args.pcap:
    print("[*] Replaying packets...\n")

# 3. Core Detection Engine
def process_ndp_packet(packet):
    if not trusted_ipv6_routers or not packet.haslayer(IPv6):
        return

    ethernet_mac = packet[Ether].src.lower() if packet.haslayer(Ether) else None
    reasons = []
    advertised_mac = None
    expected_ip = None
    expected_mac = None
    mapping_violation = False

    if packet.haslayer(ICMPv6ND_RA):
        packet_type = "router_advertisement"
        router_ip = packet[IPv6].src
        expected_ip = router_ip
        expected_mac = trusted_ipv6_routers.get(router_ip)
        if expected_mac is None:
            mapping_violation = True
            reasons.append(f"router advertisement from untrusted IPv6 address {router_ip}")
        if ethernet_mac and expected_mac and ethernet_mac != expected_mac:
            mapping_violation = True
            reasons.append(f"router advertisement Ethernet source {ethernet_mac} does not match expected MAC {expected_mac}")
        if packet.haslayer(ICMPv6NDOptSrcLLAddr):
            advertised_mac = packet[ICMPv6NDOptSrcLLAddr].lladdr
            if advertised_mac:
                advertised_mac = advertised_mac.lower()
                if expected_mac and advertised_mac != expected_mac:
                    mapping_violation = True
                    reasons.append(f"router advertisement source MAC option {advertised_mac} does not match expected MAC {expected_mac}")
        target_ip = router_ip
    elif packet.haslayer(ICMPv6ND_NA):
        neighbor = packet[ICMPv6ND_NA]
        target_ip = neighbor.tgt
        expected_ip = target_ip
        expected_mac = trusted_ipv6_routers.get(target_ip)
        if expected_mac is None:
            return
        packet_type = "neighbor_advertisement"
        if ethernet_mac and ethernet_mac != expected_mac:
            mapping_violation = True
            reasons.append(f"neighbor advertisement Ethernet source {ethernet_mac} does not match expected MAC {expected_mac}")
        if packet.haslayer(ICMPv6NDOptDstLLAddr):
            advertised_mac = packet[ICMPv6NDOptDstLLAddr].lladdr
            if advertised_mac:
                advertised_mac = advertised_mac.lower()
                if advertised_mac != expected_mac:
                    mapping_violation = True
                    reasons.append(f"neighbor advertisement target MAC option {advertised_mac} does not match expected MAC {expected_mac}")
    else:
        return

    if not reasons:
        return

    event = {
        "timestamp": datetime.now().astimezone().isoformat(timespec="seconds"),
        "event": "suspicious_ipv6_ndp",
        "severity": "high" if mapping_violation else "medium",
        "capture_mode": "offline" if args.pcap else "live",
        "packet_type": packet_type,
        "interface": None if args.pcap else (getattr(packet, "sniffed_on", None) or selected_interface or "unknown"),
        "capture_file": os.path.basename(args.pcap) if args.pcap else None,
        "expected_router_ipv6": expected_ip,
        "expected_router_mac": expected_mac,
        "ipv6_source": packet[IPv6].src,
        "ipv6_target": target_ip,
        "ethernet_source_mac": ethernet_mac,
        "advertised_link_layer_mac": advertised_mac,
        "reasons": reasons,
    }
    alert_msg = json.dumps(event, sort_keys=True)
    print(f"[!!!] Suspicious IPv6 NDP activity detected: {alert_msg}\n")
    logging.warning(alert_msg)

def process_packet(packet):
    process_ndp_packet(packet)
    if not packet.haslayer(ARP) or packet[ARP].op not in (1, 2):
        return

    arp = packet[ARP]
    sender_mac = arp.hwsrc.lower()
    ethernet_mac = packet[Ether].src.lower() if packet.haslayer(Ether) else None
    reasons = []

    # Requests and gratuitous ARP announcements can also poison neighbor caches.
    if arp.psrc == gateway_ip and sender_mac not in trusted_gateway_macs:
        reasons.append(f"gateway IP {gateway_ip} claimed by unexpected MAC {sender_mac} (expected {gateway_mac})")

    # The Ethernet source and ARP sender hardware address should describe the same device.
    if ethernet_mac and ethernet_mac != sender_mac:
        reasons.append(f"Ethernet source {ethernet_mac} does not match ARP sender MAC {sender_mac}")

    if reasons:
        packet_type = "request" if arp.op == 1 else "reply"
        event = {
            "timestamp": datetime.now().astimezone().isoformat(timespec="seconds"),
            "event": "suspicious_arp",
            "severity": "high" if any(reason.startswith(f"gateway IP {gateway_ip} claimed") for reason in reasons) else "medium",
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
        sniff(iface=selected_interface, filter=capture_filter, prn=process_packet, store=0)
except KeyboardInterrupt:
    print("\n[*] Shutting down ArpGuard. Stay safe.")
    sys.exit(0)
except Exception as exc:
    print(f"[!] Error while reading capture or monitoring: {exc}")
    sys.exit(1)
