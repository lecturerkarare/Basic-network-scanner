@"
# Network Scanner

Command-line network scanner (ICMP, TCP SYN, ARP) built with Scapy.

## Quick start (Windows 11)
1. Install Npcap (https://npcap.com/) and reboot if required.
2. Open PowerShell **as Administrator** to run scans.
3. Activate venv:
..venv\Scripts\Activate.ps1

## markdown

4. Run example:
python .\src\main.py 127.0.0.1 -t all -p 22,80

## pgsql


## Safety & Legal
- Only scan networks you own or have explicit permission to test.
- Scanning without authorization may be illegal.
"@ | Out-File -Encoding utf8 README.m