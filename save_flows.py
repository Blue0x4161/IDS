import pyshark
import json
from collections import defaultdict

pcap_file = "data/http.cap"
output_file = "data/flows.jsonl"

cap = pyshark.FileCapture(pcap_file)

# Dictionary to store flows
flows = defaultdict(int)

for packet in cap:
    if 'IP' in packet:
        src = packet.ip.src
        dst = packet.ip.dst
        proto = packet.transport_layer  # TCP or UDP
        sport = int(packet[proto].srcport) if proto else 0
        dport = int(packet[proto].dstport) if proto else 0

        key = (src, dst, sport, dport, proto)
        flows[key] += 1

# Save flows to JSONL
with open(output_file, "w") as f:
    for flow, count in flows.items():
        src, dst, sport, dport, proto = flow
        json_line = {
            "src_ip": src,
            "dst_ip": dst,
            "src_port": sport,
            "dst_port": dport,
            "protocol": proto,
            "packet_count": count
        }
        f.write(json.dumps(json_line) + "\n")

print(f"Saved {len(flows)} flows to {output_file}")

