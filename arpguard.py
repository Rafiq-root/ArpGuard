#!/usr/bin/env python3
from scapy.all import *
import logging
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
        return rcv.sprintf(r"%Ether.src%")
    return None

# 2. Baseline Configuration
print("========================================")
print("      🛡️ ArpGuard IDS Active 🛡️      ")
print("========================================")

gateway_ip = get_gateway_ip()
print(f"[*] Discovering Gateway IP: {gateway_ip}")

gateway_mac = get_real_mac(gateway_ip)
if not gateway_mac:
    print("[!] Error: Could not resolve Gateway MAC. Check your network connection.")
    sys.exit(1)

print(f"[*] True Gateway MAC locked as: {gateway_mac}")
print("[*] Monitoring local traffic... (Press Ctrl+C to stop)\n")

# 3. Core Detection Engine
def process_packet(packet):
    # We only care about ARP responses (op=2) claiming to be the Gateway
    if packet.haslayer(ARP) and packet[ARP].op == 2:
        if packet[ARP].psrc == gateway_ip:
            real_mac = gateway_mac
            fake_mac = packet[ARP].hwsrc

            # If the MAC in the packet doesn't match the locked MAC -> Attack!
            if real_mac != fake_mac:
                alert_msg = f"Gateway Spoofing Detected! Real: {real_mac} | Attacker: {fake_mac}"
                
                # Print to terminal
                print(f"[!!!] YOU ARE UNDER ATTACK!")
                print(f"[!!!] {alert_msg}\n")
                
                # Write quietly to the log file
                logging.warning(alert_msg)

# 4. Start the Sniffer
try:
    # store=0 ensures we don't eat up your RAM by keeping packets in memory
    sniff(filter="arp", prn=process_packet, store=0)
except KeyboardInterrupt:
    print("\n[*] Shutting down ArpGuard. Stay safe.")
    sys.exit(0)
