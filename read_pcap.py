import pyshark

pcap_file = "/home/ayat/Documents/Code/projects/IDS/data/http.cap"

cap = pyshark.FileCapture(pcap_file)

for packet in cap:
    if 'IP' in packet:
        src = packet.ip.src
        dst = packet.ip.dst
        print(f"{src} -> {dst}")

