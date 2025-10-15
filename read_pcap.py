import pyshark
#we use pyshark to read and analyze network packets directly in python
pcap_file = "/home/ayat/Documents/Code/projects/IDS/data/http.cap"

cap = pyshark.FileCapture(pcap_file)
#we open the pcap_file...FileCapture returns something we loop through. like a lisat of packets.
#Each packet in cap is an object contains all the layers (Ethernet, IP, TCP, DNS, etc.) and fields (source, destination, protocol, etc)

#we loop through each packet in cap.
for packet in cap:
    if 'IP' in packet:             
        src = packet.ip.src
        dst = packet.ip.dst
        print(f"{src} -> {dst}")



#If 'IP' in packets:  here we check if the packet has an IP. cuz we don't need a packet that doesn't have one like arp packets for example
