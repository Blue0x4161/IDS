import json
import os
import time
from typing import List, Dict, Any

# Define the file path for the alerts log
ALERT_FILE_PATH = "ids_alerts.json"

# --- NEW: Alert De-duplication Cache and Configuration ---
# In-memory cache to store the last timestamp an alert key was logged.
_ALERT_COOLDOWN_CACHE: Dict[str, float] = {}
# Time (in seconds) to suppress identical alerts
ALERT_COOLDOWN_SECONDS = 60 

def _create_alert_key(alert_data: Dict[str, Any]) -> str:
    """
    Generates a unique, reproducible string key for de-duplication based on flow and reason.
    This key must be consistent for identical alerts.
    """
    # Combine the critical, non-timestamp-related fields into a tuple
    key_fields = (
        alert_data["source_ip"],
        alert_data["destination_ip"],
        str(alert_data["source_port"]),
        str(alert_data["destination_port"]),
        #alert_data["protocol"],
        alert_data["direction"],
        # Sort reasons to ensure consistent key regardless of the internal order of the list
        tuple(sorted(alert_data["reasons"])) 
    )
    # Use hashing for a compact, consistent key
    return str(hash(key_fields))

# --------------------------------------------------------

def load_alerts() -> List[Dict[str, Any]]:
    """
    Loads existing alerts from the JSON file. 
    Returns an empty list if the file doesn't exist or is invalid.
    """
    if not os.path.exists(ALERT_FILE_PATH):
        return []
    try:
        with open(ALERT_FILE_PATH, 'r') as f:
            # Load the entire list of alerts
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError, IOError):
        # Handle cases where the file is empty, corrupted, or cannot be read
        print(f"[!] Warning: Could not load or parse {ALERT_FILE_PATH}. Starting with an empty alert list.")
        return []

def save_alerts(alerts: List[Dict[str, Any]]):
    """Writes the entire list of alerts to the JSON file, overwriting the old content."""
    try:
        with open(ALERT_FILE_PATH, 'w') as f:
            # Use indent=4 for human-readable formatting in the file
            json.dump(alerts, f, indent=4)
    except IOError as e:
        print(f"[!] Error saving alerts to {ALERT_FILE_PATH}: {e}")

def log_alert(alert_data: Dict[str, Any]):
    """
    Public function to append a new structured alert to the log file,
    after applying de-duplication logic.
    """
    # We need 'global' here because we are modifying module-level variables inside a function
    global _ALERT_COOLDOWN_CACHE, ALERT_COOLDOWN_SECONDS
    now = time.time()
    
    # 1. Generate unique key for this alert flow
    alert_key = _create_alert_key(alert_data)
    
    # 2. Check de-duplication cache
    last_alert_time = _ALERT_COOLDOWN_CACHE.get(alert_key, 0)
    
    if (now - last_alert_time) < ALERT_COOLDOWN_SECONDS:
        # Alert is within the cooldown period, suppress logging to file
        return 
        
    # 3. Update the cache with the new time (only if we are about to log it)
    _ALERT_COOLDOWN_CACHE[alert_key] = now
    
    # 4. If outside the cooldown, proceed with logging
    alerts = load_alerts()
    alerts.append(alert_data)
    save_alerts(alerts)
