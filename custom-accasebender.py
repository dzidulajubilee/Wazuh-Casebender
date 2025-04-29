#!/usr/bin/env python

import json
import os
import sys
import datetime
import time

try:
    import requests
except ModuleNotFoundError:
    print("No module 'requests' found. Install it with: pip install requests")
    sys.exit(1)

# Constants
ALERT_INDEX = 1
API_KEY_INDEX = 2
BASE_URL_INDEX = 3

# Hardcoded secret (consider moving this to a config or environment variable)
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
    severity = get_severity(alert)

    if severity > 2:
        payload = generate_case_payload(alert)
        endpoint = "/api/cases"
        action_type = "case"
    else:
        payload = generate_alert_payload(alert)
        endpoint = "/api/alerts"
        action_type = "alert"

    full_url = base_url.rstrip("/") + endpoint
    success = send_to_casebender(full_url, api_key, api_secret, payload)
    log_action(alert, action_type, success)

def load_alert(filepath):
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error reading alert file: {e}")
        sys.exit(3)

def get_severity(alert):
    try:
        level = int(alert.get('rule', {}).get('level', 0))
    except (ValueError, TypeError):
        level = 0

    if level <= 4:
        return 1  # Low
    elif 5 <= level <= 9:
        return 2  # Medium
    elif 10 <= level <= 14:
        return 3  # High
    else:
        return 4  # Critical

def build_description(alert):
    rule = alert.get('rule', {})
    agent = alert.get('agent', {})

    level = rule.get('level', 'unknown')
    agent_name = agent.get('name', 'unknown')
    agent_ip = agent.get('ip', 'unknown')
    agent_id = agent.get('id', 'unknown')
    timestamp = alert.get('timestamp', 'unknown')
    rule_id = rule.get('id', 'unknown')
    rule_description = rule.get('description', 'No description available')
    groups = ", ".join(rule.get('groups', [])) if rule.get('groups') else "unknown"
    full_log = alert.get('full_log', 'No full_log available.')

    agent_info = f"""Agent Information:
- **Name**: {agent_name}
- **IP**: {agent_ip}
- **ID**: {agent_id}
"""

    alert_metadata = f"""Alert Metadata:
- **Rule ID**: {rule_id}
- **Rule Description**: {rule_description}
- **Severity Level**: {level}
- **Timestamp**: {timestamp}
- **Groups**: {groups}
"""

    data_info = "**Data**:\n"
    try:
        win_data = alert.get('data', {}).get('win', {})
        if not win_data:
            data_info += "- No 'win' section found under 'data'\n"
        else:
            system_data = win_data.get('system', {})
            eventdata = win_data.get('eventdata', {})

            if system_data:
                data_info += "\n  System Information:\n"
                for key, value in sorted(system_data.items()):
                    data_info += f"    - {key}: {value}\n"
            else:
                data_info += "  - No system information available.\n"

            if eventdata:
                data_info += "\n  Event Data:\n"
                for key, value in sorted(eventdata.items()):
                    data_info += f"    - {key}: {value}\n"
            else:
                data_info += "  - No event data available.\n"

    except Exception as e:
        data_info += f"- Failed to parse 'data' field: {e}\n"

    full_log_info = f"""
**Full Log**:
{full_log}
"""
    return f"{agent_info}\n{alert_metadata}\n{data_info}\n{full_log_info}"

def generate_case_payload(alert):
    severity = get_severity(alert)
    rule_description = alert.get('rule', {}).get('description', 'No description available')

    return {
        "title": rule_description or 'Wazuh Alert',
        "description": build_description(alert),
        "severity": severity,
        "statusValue": "new",
        "tlp": severity,
        "pap": severity
    }

def generate_alert_payload(alert):
    severity = get_severity(alert)
    rule_description = alert.get('rule', {}).get('description', 'No description available')

    return {
        "description": "tlp",
        "count": 1,
        "title": rule_description or "Wazuh Alert",
        "statusValue": "new",
        "severity": severity,
        "tlp": severity
    }

def send_to_casebender(url, api_key, api_secret, payload, max_retries=3):
    headers = {
        "X-Api-Key": api_key,
        "X-Api-Secret": api_secret,
        "Content-Type": "application/json",
    }

    for attempt in range(1, max_retries + 1):
        try:
            response = requests.post(url, json=payload, headers=headers, timeout=10)
            print(f"[Attempt {attempt}] Sent to {url}")
            print(f"Status: {response.status_code} | Response: {response.text}")

            if response.status_code in (200, 201):
                return True  # Success
            elif 500 <= response.status_code < 600:
                print("Server error, will retry...")
            else:
                print("Client error or unexpected response, not retrying.")
                return False
        except requests.RequestException as e:
            print(f"Request failed: {e}. Retrying...")

        time.sleep(2 ** attempt)  # Exponential backoff: 2s, 4s, 8s

    print("Max retries reached. Giving up.")
    return False

def log_action(alert, action_type, success):
    timestamp = datetime.datetime.utcnow().isoformat()
    rule = alert.get('rule', {})
    rule_id = rule.get('id', 'unknown')
    level = rule.get('level', 'unknown')
    title = rule.get('description', 'No title')
    status = "SUCCESS" if success else "FAILED"

    log_entry = f"[{timestamp}] {status} sending {action_type.upper()} | Rule ID: {rule_id} | Level: {level} | Title: {title}\n"

    try:
        with open(LOG_FILE, 'a') as f:
            f.write(log_entry)
    except Exception as e:
        print(f"Error writing log: {e}")

if __name__ == "__main__":
    main(sys.argv)
