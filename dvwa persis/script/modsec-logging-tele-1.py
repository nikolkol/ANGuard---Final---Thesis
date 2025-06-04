import requests
import time
import re
from datetime import datetime

BOT_TOKEN = '7630019232:AAHW0MOrN04ob8Tq9WVE5YBK9wELbBOlBQM'
CHAT_ID = '1104663066'
LOG_FILE = "D:/thesis/dvwa persis/logs/modsec_audit.log"

IP_REGEX = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
RULE_ID_REGEX = r'\[id\s"(\d+)"\]'
URL_REGEX = r'\[url\s"([^"]+)"\]|\[uri\s"([^"]+)"\]'
HOSTNAME_REGEX = r'\[hostname\s"([^"]+)"\]'
UNIQUE_ID_REGEX = r'\[unique_id\s"([^"]+)"\]'
MESSAGE_REGEX = r'\[msg\s"([^"]+)"\]'

sent_alerts = set()

def send_to_telegram(message):
    """Send formatted security alert to Telegram."""
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": CHAT_ID,
        "text": message,
        "parse_mode": "Markdown"
    }
    try:
        response = requests.post(url, json=payload)
        result = response.json()
        if not result.get("ok"):
            print(f"Error sending message: {result}")
        return result
    except Exception as e:
        print(f"Error: {e}")

def extract_info(log_entry):
    """Extract key details from ModSecurity log entry."""
    source_ip = re.search(IP_REGEX, log_entry)
    rule_id = re.search(RULE_ID_REGEX, log_entry)
    url = re.search(URL_REGEX, log_entry)
    hostname = re.search(HOSTNAME_REGEX, log_entry)
    unique_id = re.search(UNIQUE_ID_REGEX, log_entry)
    message = re.search(MESSAGE_REGEX, log_entry)

    details = {
        "source_ip": source_ip.group(0) if source_ip else "N/A",
        "rule_id": rule_id.group(1) if rule_id else "N/A",
        "url": url.group(1) if url and url.group(1) else (url.group(2) if url else "N/A"),
        "hostname": hostname.group(1) if hostname else "N/A",
        "unique_id": unique_id.group(1) if unique_id else "N/A",
        "message": message.group(1) if message else "N/A",
        "detection_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }

    if details["rule_id"] == "N/A" or details["unique_id"] == "N/A":
        return None

    return details

def format_log_message(log_entries):
    """Format multiple log entries into a single Telegram message."""
    if not log_entries:
        return None

    first_entry = log_entries[0]
    formatted_message = f"""
⚠️ Security Alert ⚠️

Rule Triggered: {first_entry['rule_id']}
Source: {first_entry['source_ip']} 
Requested URL: {first_entry['url']}
Hostname: {first_entry['hostname']}
Unique ID: {first_entry['unique_id']}

🚨 Detected Issues 🚨
"""

    for entry in log_entries:
        formatted_message += f"""
- **Message:** {entry['message']}
  - **Variable:** `REQUEST_HEADERS:Host`
  - **Value:** `{entry['source_ip']}`
  - **Detection Time:** {entry['detection_time']}
"""

    return formatted_message

def is_complete_log(log_entry):
    """Check if log entry is complete based on unique_id or closing brackets."""
    return bool(re.search(UNIQUE_ID_REGEX, log_entry))

def monitor_log():
    """Continuously monitor the log file for new entries, handling multi-line logs."""
    last_position = 0
    print("Monitoring log file...")

    buffer = ""
    log_entries = {}

    while True:
        try:
            with open(LOG_FILE, "r") as file:
                file.seek(last_position)
                lines = file.readlines()

                if lines:
                    for line in lines:
                        if line.strip() == "":
                            continue

                        buffer += line

                        if is_complete_log(buffer):
                            details = extract_info(buffer)
                            if details:
                                alert_key = f"{details['rule_id']}_{details['unique_id']}"
                                if alert_key not in sent_alerts:
                                    if alert_key not in log_entries:
                                        log_entries[alert_key] = []
                                    log_entries[alert_key].append(details)

                                buffer = ""  

                    for alert_key, entries in log_entries.items():
                        formatted_message = format_log_message(entries)
                        if formatted_message:
                            print(f"New log detected:\n{formatted_message}")
                            send_to_telegram(formatted_message)
                            sent_alerts.add(alert_key)

                    last_position = file.tell()

                time.sleep(2)

        except Exception as e:
            print(f"Error: {e}")
            time.sleep(5)

if __name__ == "__main__":
    monitor_log()
