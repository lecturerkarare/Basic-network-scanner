# ============================================================
# Project: Network Scanner
# File: scanner.py
# Author: Moffat Gichure
# Date: 09-Nov-2025
# Description: Contains the core logic for ICMP and TCP scanning.
# ============================================================

import scapy.all as scapy
import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor

class NetworkScanner:
    def __init__(self, timeout=2.0, concurrency=10):
        self.timeout = timeout
        self.concurrency = concurrency

    # -------------------------
    # ICMP (Ping) Scan
    # -------------------------
    def icmp_scan(self, target):
        results = {}
        try:
            packet = scapy.IP(dst=target)/scapy.ICMP()
            reply = scapy.sr1(packet, timeout=self.timeout, verbose=False)
            results[target] = "Alive" if reply else "No response"
        except Exception as e:
            results[target] = f"Error: {e}"
        return results

    # -------------------------
    # TCP Port Scan
    # -------------------------
    def tcp_port_scan(self, target, ports):
        results = {target: []}
        def scan_port(port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(self.timeout)
                    result = s.connect_ex((target, port))
                    if result == 0:
                        results[target].append(port)
            except Exception:
                pass

        with ThreadPoolExecutor(max_workers=self.concurrency) as executor:
            executor.map(scan_port, ports)
        return results

    # -------------------------
    # ARP Scan (Local Network)
    # -------------------------
    def arp_scan(self, network):
        results = []
        try:
            arp_req = scapy.ARP(pdst=str(network))
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_req_broadcast = broadcast / arp_req
            answered = scapy.srp(arp_req_broadcast, timeout=self.timeout, verbose=False)[0]
            for sent, received in answered:
                results.append({'ip': received.psrc, 'mac': received.hwsrc})
        except Exception as e:
            results.append({'error': str(e)})
        return results
