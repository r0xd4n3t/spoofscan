#!/usr/bin/env python
import argparse
import colorama
from colorama import Fore, Style
from scapy.all import *

def perform_scan(protocol, spoofed_ip, target_ip):
    open_ports = []
    packet = IP(src=spoofed_ip, dst=target_ip) / protocol(dport=(1, 65535))
    responses, _ = sr(packet, timeout=10)

    for response in responses:
        if response[1].haslayer(protocol):
            port = response[1][protocol].sport
            open_ports.append(port)

    return open_ports

def print_open_ports(protocol, open_ports):
    if open_ports:
        print(f"Open {protocol} ports:")
        for port in open_ports:
            print(f"Port {port} is open.")
    else:
        print(f"No open {protocol} ports.")

def print_banner():
    banner = """
    +==============================================+
    |       Network Spoofing Scanning Script       |
    |                  by r0xd4n3t                 |
    +==============================================+
    """
    print(banner)

def main(spoofed_ip, target_ip):
    colorama.init()  # Initialize colorama for cross-platform color support

    print_banner()
    print(f"{Fore.YELLOW}Spoofed IP: {spoofed_ip}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Target IP: {target_ip}{Style.RESET_ALL}\n")

    protocols = [
        {"name": "TCP", "scan_func": TCP},
        {"name": "UDP", "scan_func": UDP}
    ]

    for protocol in protocols:
        print(f"{Fore.CYAN}Performing {protocol['name']} scan...{Style.RESET_ALL}")
        open_ports = perform_scan(protocol['scan_func'], spoofed_ip, target_ip)
        print_open_ports(protocol['name'], open_ports)
        print()

    # Summary
    print(f"{Fore.GREEN}Scan complete!{Style.RESET_ALL}")
    print(f"TCP ports scanned: {len(open_ports[0])}")
    print(f"UDP ports scanned: {len(open_ports[1])}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network Spoofing Scanning Script")
    parser.add_argument("-s", "--spoof", metavar="spoofed_ip", help="Spoofed IP address", required=True)
    parser.add_argument("-t", "--target", metavar="target_ip", help="Target IP address", required=True)
    args = parser.parse_args()

    main(args.spoof, args.target)
