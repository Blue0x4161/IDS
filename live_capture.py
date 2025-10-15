
import requests
import ipaddress
import threading
import time
from scapy.all import sniff, IP



@staticmethod
def fetch_ipsum():
    url = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        ips = set()
        for line in response.text.splitlines():
            if line and not line.startswith("#"):
                parts = line.split()  # splits on any whitespace
                ips.add(parts[0].strip())  # first column = IP
        return ips
    except requests.RequestException as e:
        print(f"[!] Failed to fetch IPsum list: {e}")
        return set()



def fetch_bitwire():
        url = "https://raw.githubusercontent.com/bitwire-it/ipblocklist/refs/heads/main/ip-list.txt"
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            return {
                line.strip()
                for line in response.text.splitlines()
                if line and not line.startswith("#")
            }
        except requests.RequestException as e:
            print(f"[!] Failed to fetch Bitwire list: {e}")
            return set()


def load_ioc_lists():
    """Combines all fetched IOC IPs into a single set."""
    print("[*] Fetching IPsum and Bitwire lists...")
    ipsum_ips = fetch_ipsum()
    bitwire_ips = fetch_bitwire()
    combined = ipsum_ips
    combined = ipsum_ips.union(bitwire_ips)
    print(f"[+] Loaded {len(combined)} malicious IPs from IOC feeds")
    return combined


# Example: checking traffic logs or packets
def check_packet(packet, malicious_ips):
    """Checks whether packet src/dst IP matches IOC feed."""
   # print("Inside check packet") 
    src_ip = packet.get("src_ip")
    dst_ip = packet.get("dst_ip")

    if src_ip in malicious_ips or dst_ip in malicious_ips:
        print(f"[!] ALERT: Packet matched IOC IP ({src_ip} -> {dst_ip})")
        return True
    return False




def auto_update(malicious_ips_container, interval_hours=2):
    """Background thread to refresh IOC feeds every interval_hours."""
    while True:
        print("[*] Refreshing IOC feeds...")
        new_list = load_ioc_lists()
        malicious_ips_container["ips"] = new_list  # update shared container
        time.sleep(interval_hours * 3600)




def live_capture(malicious_ips):
    """Sniffs live network packets and checks them against IOC list."""
    print("[*] Starting live capture... Press Ctrl+C to stop.")
    try:
        sniff(
            filter="ip",  # capture only IP packets
            store=False,  # don't keep packets in memory
            prn=lambda pkt: process_packet(pkt, malicious_ips)
        )
    except PermissionError:
        print("[!] Permission denied. Run with sudo.")
    except KeyboardInterrupt:
        print("\n[!] Capture stopped by user.")
    except Exception as e:
        print(f"[!] Sniffing error: {e}")

def process_packet(pkt, malicious_ips):
    """Extract IP info from packet and check."""
    if IP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        packet = {"src_ip": src_ip, "dst_ip": dst_ip}
        check_packet(packet, malicious_ips["ips"])



# Example usage
if __name__ == "__main__":
    malicious_ips = {"ips": load_ioc_lists()}
   # malicious_ips = fetch_ipsum()

    updater_thread = threading.Thread(
        target=auto_update, args=(malicious_ips, 2), daemon=True
    )
    updater_thread.start()

    print("[*] Starting live capture... Press Ctrl+C to stop.")

    live_capture(malicious_ips)
