import json

flows_file = "data/flows.jsonl"
blocklist_file = "data/blocklist.txt"
output_file = "data/alerts.jsonl"

# Load blocklist into a Python set for fast lookup
with open(blocklist_file, "r") as f:
    blocklist = set(line.strip() for line in f if line.strip())

alerts = []

# Read each flow
with open(flows_file, "r") as f:
    for line in f:
        flow = json.loads(line)
        score = 0
        reasons = []

        # Check source and destination IPs
        if flow["src_ip"] in blocklist:
            score += 70
            reasons.append("Source IP in blocklist")

        if flow["dst_ip"] in blocklist:
            score += 70
            reasons.append("Destination IP in blocklist")

        # If score >= 70 → flag as alert
        if score >= 70:
            alert = {
                "src_ip": flow["src_ip"],
                "dst_ip": flow["dst_ip"],
                "protocol": flow["protocol"],
                "score": score,
                "reasons": reasons
            }
            alerts.append(alert)

# Save alerts to file
with open(output_file, "w") as f:
    for alert in alerts:
        f.write(json.dumps(alert) + "\n")

print(f"✅ Found {len(alerts)} alerts. Saved to {output_file}.")

