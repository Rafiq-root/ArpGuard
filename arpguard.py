#!/usr/bin/env python3
import scapy.all as scapy
import sys

def get_mac(ip):
    # 1. Create an ARP Request ("Who has this IP?")
    arp_request = scapy.ARP(pdst=ip)
    # 2. Create an Ethernet Frame (Broadcast to everyone: ff:ff:ff:ff:ff:ff)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # 3. Combine them
    arp_request_broadcast = broadcast/arp_request
    # 4. Send and wait for answer (timeout=1s so it doesn't hang)
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    # Return the MAC address from the first answer
    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        return None

def sniff(interface):
    # Filter for ARP packets only
    scapy.sniff(iface=interface, store=False, prn=process_packet)

def process_packet(packet):
    # Check if the packet is an ARP Response (op=2)
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
        try:
            # Get the IP and MAC from the packet
            real_mac = get_mac(packet[scapy.ARP].psrc)
            response_mac = packet[scapy.ARP].hwsrc

            # THE LIE DETECTOR
            # If the MAC we just saw (response_mac) does NOT match the real one...
            if real_mac != response_mac:
                print(f"\n[!!!] YOU ARE UNDER ATTACK!")
                print(f"[!!!] Real MAC: {real_mac}, Fake MAC: {response_mac}")
            
        except IndexError:
            pass

# --- Main Execution ---
# Replace with your specific Gateway IP
gateway_ip = "10.97.82.219" 

try:
    print(f"[+] Getting MAC address for Gateway: {gateway_ip}")
    # Get the Golden Record
    original_mac = get_mac(gateway_ip)
    
    if not original_mac:
        print("[-] Could not find Gateway MAC. Check IP address.")
        sys.exit()
        
    print(f"[+] Gateway MAC is: {original_mac}")
    print("[+] ArpGuard is running... (Press Ctrl+C to stop)")
    
    # Start the sniffer
    sniff("wlan0")
    
except KeyboardInterrupt:
    print("\n[+] Detected CTRL+C ... Quitting.")
