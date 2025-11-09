# ============================================================
# Project: Network Scanner
# File: main.py
# Author: Moffat Gichure
# Date: 09-Nov-2025
# Description: Command-line interface for running scans.
# ============================================================
@"
#!/usr/bin/env python3
\"\"\"Network Scanner CLI\"\"\"
import argparse
import json
import sys
from src.scanner import NetworkScanner

def parse_ports(port_str):
    ports = set()
    if not port_str:
        return []
    for part in port_str.split(','):
        part = part.strip()
        if '-' in part:
            a, b = part.split('-', 1)
            ports.update(range(int(a), int(b)+1))
        else:
            ports.add(int(part))
    return sorted(p for p in ports if 1 <= p <= 65535)

def main():
    parser = argparse.ArgumentParser(description='Network Scanner - ICMP / TCP / ARP')
    parser.add_argument('target', help='Target IP or network (e.g. 192.168.1.1 or 192.168.1.0/24)')
    parser.add_argument('-t', '--type', choices=['all','icmp','tcp','arp'], default='all',
                        help='Scan type (default: all)')
    parser.add_argument('-p', '--ports', help='Ports to scan, e.g. 22,80 or 1-1024')
    parser.add_argument('-T', '--timeout', type=float, default=2.0, help='Timeout seconds (default 2)')
    parser.add_argument('-c', '--concurrency', type=int, default=100, help='Max concurrent port threads')
    parser.add_argument('-o', '--output', choices=['text','json'], default='text', help='Output format')
    parser.add_argument('--dry-run', action='store_true', help='Validate args without sending packets')
    args = parser.parse_args()

    ports = parse_ports(args.ports)
    scanner = NetworkScanner(timeout=args.timeout, concurrency=args.concurrency)

    if args.dry_run:
        print('Dry run: targets and options validated.')
        print('Target:', args.target)
        print('Scan type:', args.type)
        print('Ports:', ports or 'default common ports')
        sys.exit(0)

    try:
        results = {}
        if args.type in ('all','icmp'):
            results['icmp'] = scanner.icmp_scan(args.target)
        if args.type in ('all','tcp'):
            if not ports:
                ports = [22,80,443,8080,3389]
            results['tcp'] = scanner.tcp_port_scan(args.target, ports)
        if args.type in ('all','arp'):
            results['arp'] = scanner.arp_scan(args.target)
    except PermissionError:
        print('Permission error: run PowerShell as Administrator (Windows) or use sudo on *nix.', file=sys.stderr)
        sys.exit(2)
    except ValueError as e:
        print(f'Input error: {e}', file=sys.stderr)
        sys.exit(3)

    if args.output == 'json':
        print(json.dumps(results, indent=2))
    else:
        if 'icmp' in results:
            print('ICMP results:')
            for host, up in results['icmp'].items():
                print(f'  {host}\t{"UP" if up else "DOWN"}')
        if 'tcp' in results:
            print('\\nTCP port scan results:')
            for host, ports_dict in results['tcp'].items():
                print(f'  {host}:')
                for port, state in sorted(ports_dict.items()):
                    print(f'    {port}\\t{state}')
        if 'arp' in results:
            print('\\nARP scan results (IP -> MAC):')
            for ip, mac in results['arp'].items():
                print(f'  {ip} -> {mac}')

if __name__ == '__main__':
    main()
"@ | Out-File -Encoding utf8 src\main.py
