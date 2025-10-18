import packet_capture
import ioc_fetcher
from scapy.all import IP


def check_packet(packet, malicious_ips):
    src_ip = packet.get("src_ip")
    dst_ip = packet.get("dst_ip")

    if src_ip in malicious_ips:
        print(f"[!] ALERT: Packet source IP matched IOC. \n(Source IP:{src_ip} -> Destination IP:{dst_ip})")
        return True
    return False

def process_packet(pkt, malicious_ips):
    if IP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        packet = {"src_ip": src_ip , "dst_ip": dst_ip }
        check_packet(packet,malicious_ips["ips"])





