import packet_processor
import ioc_fetcher
import ioc_manager
import packet_capture
from scapy.all import IP  #for testing
import time #for testing

manager= ioc_manager.ioc_manager()
print(f"Initial load done: {len(manager.malicious_ips['ips'])} IPs loaded")
print("Starting background updater ...")
manager.auto_updater(interval_hours=(10/3600))   #10 seconds for testing

#test packet
#packet= IP(src="80.94.93.119", dst="8.8.8.8")
pcap = packet_capture.packet_capture()
pcap.start_capture("wlp4s0")

print("sniffing for 10 seconds ....")
time.sleep(10)

while not pcap.packet_queue.empty():
    packet = pcap.packet_queue.get()
    packet_processor.process_packet(packet,manager.malicious_ips)


