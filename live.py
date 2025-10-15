
#!/usr/bin/env python3
"""
live_ids.py - simple IDS: live capture with Scapy + IOC auto-updater (2h)
Run with: sudo python3 live_ids.py
"""

import requests
import ipaddress
import threading
import time
import json
from scapy.all import sniff, IP  # requires scapy installed
import logging

# -----------------------------
# Logging / config
# -----------------------------
logging.basicConfig(
    filename="alerts.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s",
)
CONSOLE = True  # also print to console
UPDATE_INTERVAL_HOURS = 2
BPF_FILTER = "ip"  # change to "tcp" or "udp" or more specific filter if needed

# -----------------------------
# IOC fetchers (cleaning + validation)
# -----------------------------
def fetch_ipsum():
    url = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"
    try:
        r = requests.get(url, timeout=15)
        r.raise_for_status()
        ips = set()
        for line in r.text.splitlines():
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            ip = parts[0].split("/")[0].strip()
            try:
                ipaddress.ip_address(ip)
                ips.add(ip)
            except ValueError:
                continue
        return ips
    except requests.RequestException as e:
        print(f"[!] Failed to fetch IPsum list: {e}")
        return set()

def fetch_bitwire():
    url = "https://raw.githubusercontent.com/bitwire-it/ipblocklist/refs/heads/main/ip-list.txt"
    try:
        r = requests.get(url, timeout=15)
        r.raise_for_status()
        ips = set()
        for line in r.text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            ip = line.split()[0].split("/")[0]
            try:
                ipaddress.ip_address(ip)
                ips.add(ip)
            except ValueError:
                continue
        return ips
    except requests.RequestException as e:
        print(f"[!] Failed to fetch Bitwire list: {e}")
        return set()

def load_ioc_lists():
    print("[*] Fetching IPsum and Bitwire lists...")
    isum = fetch_ipsum()
    bwire = fetch_bitwire()
    combined = isum.union(bwire)
    print(f"[+] Loaded {len(combined)} malicious IPs from IOC feeds")
    return combined

# -----------------------------
# IDS state (shared)
# -----------------------------
class IDSState:
    def __init__(self):
        self.lock = threading.Lock()
        self.blocklist = set()

    def replace_blocklist(self, newset):
        with self.lock:
            self.blocklist = newset

    def get_blocklist_snapshot(self):
        with self.lock:
            return set(self.blocklist)  # return a copy to minimize lock hold

IDS = IDSState()

# -----------------------------
# Updater thread
# -----------------------------
def auto_update(state: IDSState, interval_hours=UPDATE_INTERVAL_HOURS):
    while True:
        print(f"[*] Auto-update: fetching IOC feeds (every {interval_hours} hours)...")
        new_list = load_ioc_lists()
        state.replace_blocklist(new_list)
        print(f"[✓] IOC feeds updated ({len(new_list)} IPs)")
        time.sleep(interval_hours * 3600)

# -----------------------------
# Packet handler (Scapy)
# -----------------------------
def alert(packet_src, packet_dst, proto):
    msg = f"ALERT: {packet_src} -> {packet_dst} proto={proto}"
    logging.info(msg)
    if CONSOLE:
        print(msg)

def handle_pkt(pkt):
    # Only process IPv4 packets
    if not pkt.haslayer(IP):
        return

    ip_layer = pkt[IP]
    src = ip_layer.src
    dst = ip_layer.dst
    proto = ip_layer.proto

    # Get a snapshot of current blocklist (copy) to avoid holding lock while checking
    blocklist = IDS.get_blocklist_snapshot()

    if src in blocklist or dst in blocklist:
        # build reason(s)
        reasons = []
        if src in blocklist:
            reasons.append("src in IOC")
        if dst in blocklist:
            reasons.append("dst in IOC")
        # log/alert
        alert(f"{src}", f"{dst} ({','.join(reasons)})", proto)

# -----------------------------
# Main
# -----------------------------
def main():
    # initial load
    IDS.replace_blocklist(load_ioc_lists())

    # start updater thread
    t = threading.Thread(target=auto_update, args=(IDS, UPDATE_INTERVAL_HOURS), daemon=True)
    t.start()

    print("[*] Starting live capture. Press Ctrl+C to stop.")
    print(f"[*] BPF filter: {BPF_FILTER}")
    try:
        # sniff: store=0 (no packet storage), prn callback, filter BPF string, iface None uses default
        sniff(filter=BPF_FILTER, prn=handle_pkt, store=0)
    except PermissionError:
        print("[!] Permission denied. Run as root (sudo).")
    except KeyboardInterrupt:
        print("\n[!] Stopped by user. Exiting.")
    except Exception as e:
        print(f"[!] Sniffing error: {e}")

if __name__ == "__main__":
    main()
