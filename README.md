#  Host-Based Intrusion Detection System (HIDS)

A lightweight **host-based Intrusion Detection System (IDS)** built for monitoring network traffic in **Industrial Control Systems (ICS)** and **IoT devices**.

The IDS runs directly on the protected device, sniffing packets in real-time and applying multiple security checks including local Indicators of Compromise (IoCs), ICS-specific policy enforcement, port reputation scoring, and AbuseIPDB lookups. All alerts are logged, rate-limited, and cached for performance.


## Features

### 1. IOC Management
- **Dynamic Blacklisting:** Auto‑fetches global malicious IP lists with `ioc_fetcher.py`.
- **Auto‑Update:** IOC list refresh interval configurable (default: 2 hours).

###  2. Multi-Layer Traffic Analysis
- **IP Reputation Checking:** Combines local IoCs with AbuseIPDB external lookups.
- **ICS/IoT Policy Enforcement:**  
  - ICS protocol port whitelisting (e.g., Modbus 502).  
  - IoT spoofing source detection.  
- **High-Risk Port Monitoring:** Flags traffic on commonly abused ports.

###  3. Alert Logging & De‑duplication
- Alerts saved in **`ids_alerts.json`** in structured JSON.
- **Rate-limiting:** Suppresses duplicate alerts for 60 seconds.
- **Caching:** All IP reputation results cached via `cache_manager.py` to reduce API load.


## Prerequisites

Install dependencies:

```bash
pip install scapy requests python-dotenv
```
To run this project, you need:
1. Python 3.x
2. Required Libraries: Install them using pip:
   pip install scapy requests python-dotenv
3. Root/Admin Privileges: Packet sniffing often requires elevated privileges (e.g., running with sudo on Linux).


## Installation and Setup

Configure the Environment
Create a file named .env in the root directory of the project to store your API key.
```bash
# .env file
ABUSEIPDB_KEY="YOUR_ABUSEIPDB_API_KEY_HERE"
```

Run the IDS
Execute the main file, specifying your network interface (e.g., eth0, wlp4s0, en0). You may need sudo!
```bash
# Example for a Linux/macOS machine
sudo python3 main.py
```

## Configuration Tuning

To adjust the system's sensitivity, you can modify global constants in packet_processor.py:
alert_threshold: The minimum combined score a packet must reach to trigger an alert.
abuseipdb_rate_limit: Limits the number of external API checks to stay within the free tier quota.
alert_logger.ALERT_COOLDOWN_SECONDS: Sets the time (in seconds, default 60) that an identical alert will be suppressed.

### Example Alert Output (In Terminal)
```bash
==================== IDS ALERT ====================
Score reached: 120
Protected Device: 192.168.87.19
Flow: 10.0.0.8:502 -> 192.168.87.19:502 | State: NEW | Direction: INBOUND
Reasons:
 • [!!!] CRITICAL: Unauthorized access on ICS port 502 from 10.0.0.8.
===================================================
```

## Dashboard Setup

To monitor alerts via the web interface, follow these steps:

1. **Install Dependencies**
   Run the following command to install the required libraries:
   
```bash
pip install scapy requests python-dotenv uvicorn fastapi
```
2. Run the Dashboard Navigate to the project directory and start the server

```bash
uvicorn app:app --reload
```

View in browser. Access the dashboard at: http://127.0.0.1:8000
