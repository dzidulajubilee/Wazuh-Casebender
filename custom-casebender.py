#!/usr/bin/env python

import json
import os
import sys
import datetime

try:
    import requests
except ModuleNotFoundError:
    print("No module 'requests' found. Install it with: pip install requests")
    sys.exit(1)

# Constants
ALERT_INDEX = 1
API_KEY_INDEX = 2
BASE_URL_INDEX = 3

# Hardcoded secret
HARDCODED_API_SECRET = "a01150b70f1482f1ac3bab6513e7e5f329c43e723c580eac003d05f8762895e7"

# Log file path
LOG_FILE = "/var/ossec/logs/casebender_integration.log"

def main(args):
    if len(args) < 4:
        print("Usage: script.py <alert_file> <api_key> <base_url>")
        sys.exit(2)

    alert_file = args[ALERT_INDEX]
    api_key = args[API_KEY_INDEX]
    base_url = args[BASE_URL_INDEX]
    api_secret = HARDCODED_API_SECRET

    alert = load_alert(alert_file)

    payload = generate_casebender_payload(alert)

    # Determine endpoint based on alert level
    level = alert['rule']['level']
    if level <= 9:
        endpoint = "/api/alerts"
        action_type = "alert"
    else:
        endpoint = "/api/cases"
        action_type = "case"

    full_url = base_url.rstrip("/") + endpoint

    success = send_to_casebender(full_url, api_key, api_secret, payload)

    # Write to log file
    log_action(alert, action_type, success)

def load_alert(filepath):
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error reading alert file: {e}")
        sys.exit(3)

def generate_casebender_payload(alert):
    level = alert['rule']['level']

    # Map Wazuh "level" to CaseBender severity
    if level <= 4:
        severity = 1  # Low
    elif 5 <= level <= 7:
        severity = 2  # Medium
    else:
        severity = 3  # High

    agent_name = alert.get('agent', {}).get('name', 'unknown')
    agent_ip = alert.get('agent', {}).get('ip', 'unknown')
    agent_id = alert.get('agent', {}).get('id', 'unknown')
    timestamp = alert.get('timestamp', 'unknown')
    rule_id = alert.get('rule', {}).get('id', 'unknown')
    rule_description = alert.get('rule', {}).get('description', 'No description available')
    groups = ", ".join(alert.get('rule', {}).get('groups', [])) if 'groups' in alert.get('rule', {}) else "unknown"

    # Agent information
    agent_info = f"""Agent Information:
- Name: {agent_name}
- IP: {agent_ip}
- ID: {agent_id}
"""

    # Alert metadata
    alert_metadata = f"""Alert Metadata:
- Rule ID: {rule_id}
- Rule Description: {rule_description}
- Severity Level: {level}
- Timestamp: {timestamp}
- Groups: {groups}
"""

    # Data section
    data_info = "Data:\n"
    if 'data' in alert:
        try:
            win_data = alert['data'].get('win', {})
            if not win_data:
                data_info += "- No 'win' section found under 'data'\n"
            else:
                system_data = win_data.get('system', {})
                eventdata = win_data.get('eventdata', {})

                if system_data:
                    data_info += "\nSystem:\n"
                    for key, value in system_data.items():
                        data_info += f"- {key}: {value}\n"
                else:
                    data_info += "- No system information available.\n"

                if eventdata:
                    data_info += "\nEvent Data:\n"
                    for key, value in eventdata.items():
                        data_info += f"- {key}: {value}\n"
                else:
                    data_info += "- No event data available.\n"

        except Exception as e:
            data_info += f"- Failed to parse 'data' field: {e}\n"
    else:
        data_info += "- No data field found in alert.\n"

    # Final description
    description = f"{agent_info}\n{alert_metadata}\n{data_info}"

    payload = {
        "description": description,
        "count": 1,
        "title": rule_description or 'Wazuh Alert',
        "statusValue": "new",
        "severity": severity,
    }
    return payload

def send_to_casebender(url, api_key, api_secret, payload):
    headers = {
        "X-Api-Key": api_key,
        "X-Api-Secret": api_secret,
        "Content-Type": "application/json",
    }
    try:
        response = requests.post(url, json=payload, headers=headers, timeout=10)
        print(f"Sent to {url}")
        print(f"Response status code: {response.status_code}")
        print(response.text)
        return response.status_code in (200, 201, 400, 401, 403, 500)
    except Exception as e:
        print(f"Failed to send alert/case: {e}")
        return False

def log_action(alert, action_type, success):
    timestamp = datetime.datetime.utcnow().isoformat()
    rule_id = alert['rule'].get('id', 'unknown')
    level = alert['rule'].get('level', 'unknown')
    title = alert['rule'].get('description', 'No title')

    status = "SUCCESS" if success else "FAILED"

    log_entry = f"[{timestamp}] {status} sending {action_type.upper()} | Rule ID: {rule_id} | Level: {level} | Title: {title}\n"

    try:
        with open(LOG_FILE, 'a') as f:
            f.write(log_entry)
    except Exception as e:
        print(f"Error writing log file: {e}")

if __name__ == "__main__":
    main(sys.argv)
