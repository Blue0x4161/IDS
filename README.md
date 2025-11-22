IoT and ICS Host-Based Intrusion Detection System (IoT-HIDS)

 Project Overview

This project implements a lightweight, host-based Intrusion Detection System (IDS) specifically designed for monitoring network traffic originating from or destined for Industrial Control Systems (ICS) and constrained Internet of Things (IoT) devices.

Running directly on the protected device, it operates by sniffing local network packets in real-time and subjecting them to multiple layers of checks, including local Indicators of Compromise (IoC), policy enforcement, and external reputation checks (AbuseIPDB). The system is designed to run in a continuous loop, providing real-time alerts and logging critical events. 



Features

1. IOC Management:
   
Dynamic Blacklisting: Automatically fetches and updates global malicious IP lists from external sources (via ioc_fetcher.py).
Auto-Update: IOC lists are updated on a configurable timer (currently set to 2 hours in main.py).

2. Multi-Layer Checking:

IP Reputation: Checks IPs against a local IOC blacklist and an external API (AbuseIPDB) for malicious activity.
ICS/IoT Policy Enforcement: Implements specific rules for constrained environments, including port whitelisting for known control protocols (like Modbus/MQTT) and source spoofing detection which is critical for securing IoT sensors.
High-Risk Port Monitoring: Assigns extra weight to traffic on commonly abused ports (e.g., Telnet, unencrypted HTTP).

3. Alert Logging & De-duplication:

Structured alerts (JSON format) are saved to ids_alerts.json.
Rate Limiting: Implements a flow-based cooldown (60 seconds) to prevent the system from logging hundreds of identical, repetitive alerts.
Caching (cache_manager.py): Caches the reputation check results for IPs to reduce external API calls and improve processing speed.



Prerequisites

To run this project, you need:
1. Python 3.x
2. Required Libraries: Install them using pip:
   pip install scapy requests python-dotenv
3. Root/Admin Privileges: Packet sniffing often requires elevated privileges (e.g., running with sudo on Linux).



Installation and Setup

Configure the Environment
Create a file named .env in the root directory of the project to store your API key.

# .env file
ABUSEIPDB_KEY="YOUR_ABUSEIPDB_API_KEY_HERE"


Run the IDS
Execute the main file, specifying your network interface (e.g., eth0, wlp4s0, en0). You may need sudo!

# Example for a Linux/macOS machine
sudo python3 main.py


Configuration Tuning

To adjust the system's sensitivity, you can modify global constants in ip_checker.py:
alert_threshold: The minimum combined score a packet must reach to trigger an alert.
abuseipdb_rate_limit: Limits the number of external API checks to stay within the free tier quota.
alert_logger.ALERT_COOLDOWN_SECONDS: Sets the time (in seconds, default 60) that an identical alert will be suppressed.
