import pyshark
from collections import defaultdict

pcap_file = "data/http.cap"

cap = pyshark.FileCapture(pcap_file)

# Dictionary to store flows
# key = tuple (src_ip, dst_ip, src_port, dst_port, protocol)
flows = defaultdict(int)

for packet in cap:
    if 'IP' in packet:
        src = packet.ip.src
        dst = packet.ip.dst
        proto = packet.transport_layer  # TCP or UDP
        sport = int(packet[proto].srcport) if proto else 0
        dport = int(packet[proto].dstport) if proto else 0

        key = (src, dst, sport, dport, proto)
        flows[key] += 1  # count packets in this flow

# Print flows
for flow, count in flows.items():
    src, dst, sport, dport, proto = flow
    print({
        "src_ip": src,
        "dst_ip": dst,
        "src_port": sport,
        "dst_port": dport,
        "protocol": proto,
        "packet_count": count
    })

