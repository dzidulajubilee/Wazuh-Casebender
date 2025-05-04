#!/usr/bin/env python3

import json
import os
import sys
import datetime
import time
import logging

try:
    import requests
except ModuleNotFoundError:
    print("No module 'requests' found. Install it with: pip install requests")
    sys.exit(1)

# Constants
ALERT_INDEX = 1
API_KEY_INDEX = 2
BASE_URL_INDEX = 3

HARDCODED_API_SECRET = "a01150b70f1482f1ac3bab6513e7e5f329c43e723c580eac003d05f8762895e7"

# Logging
LOG_FILE = "/var/ossec/logs/casebender_integration.log"
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='[%(asctime)s] %(message)s')

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
        logging.error(f"Error reading alert file: {e}")
        sys.exit(3)

def get_field(obj, path, default="unknown"):
    for part in path.split('.'):
        if isinstance(obj, dict):
            obj = obj.get(part, default)
        else:
            return default
    return obj if obj is not None else default

def get_severity(alert):
    try:
        level = int(get_field(alert, 'rule.level', 0))
    except (ValueError, TypeError):
        level = 0

    if level <= 4:
        return 1
    elif 5 <= level <= 9:
        return 2
    elif 10 <= level <= 14:
        return 3
    else:
        return 4

def build_description(alert):
    description_lines = []

    def safe_line(label, value):
        return f"- **{label}**: {value if value is not None else 'unknown'}"

    description_lines.append("**Agent Information:**")
    description_lines.append(safe_line("Name", get_field(alert, "agent.name")))
    description_lines.append(safe_line("IP", get_field(alert, "agent.ip")))
    description_lines.append(safe_line("ID", get_field(alert, "agent.id")))

    description_lines.append("\n**Alert Metadata:**")
    description_lines.append(safe_line("Rule ID", get_field(alert, "rule.id")))
    description_lines.append(safe_line("Description", get_field(alert, "rule.description")))
    description_lines.append(safe_line("Severity", get_field(alert, "rule.level")))
    description_lines.append(safe_line("Timestamp", get_field(alert, "timestamp")))
    groups = get_field(alert, "rule.groups", [])
    description_lines.append(safe_line("Groups", ", ".join(groups) if isinstance(groups, list) else groups))

    description_lines.append("\n**Full Log:**")
    description_lines.append(get_field(alert, "full_log", "No full_log available."))

    # Add dynamic additional fields
    standard_keys = {
        "agent", "rule", "full_log", "timestamp", "manager", "decoder", "location", "syscheck", "@timestamp"
    }

    def flatten(d, parent_key='', sep='.'):
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(flatten(v, new_key, sep=sep))
            else:
                items.append((new_key, v))
        return items

    additional_data = flatten(alert)
    additional_data_filtered = [(k, v) for k, v in additional_data if k.split('.')[0] not in standard_keys]

    if additional_data_filtered:
        description_lines.append("\n**Additional Data:**")
        for key, value in additional_data_filtered:
            if isinstance(value, (str, int, float, bool)):
                description_lines.append(safe_line(key, value))

    return "\n".join(description_lines)

def generate_case_payload(alert):
    severity = get_severity(alert)
    title = get_field(alert, "rule.description", "Wazuh Alert")

    return {
        "title": title,
        "description": build_description(alert),
        "severity": severity,
        "statusValue": "new",
        "tlp": severity,
        "pap": severity
    }

def generate_alert_payload(alert):
    severity = get_severity(alert)
    title = get_field(alert, "rule.description", "Wazuh Alert")

    return {
        "description": build_description(alert),
        "count": 1,
        "title": title,
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
            logging.info(f"[Attempt {attempt}] Sent to {url}")
            logging.info(f"Status: {response.status_code} | Response: {response.text}")

            if response.status_code in (200, 201):
                return True
            elif 500 <= response.status_code < 600:
                logging.warning("Server error, retrying...")
            else:
                logging.error("Client error or unexpected response, not retrying.")
                return False
        except requests.RequestException as e:
            logging.error(f"Request failed: {e}. Retrying...")

        time.sleep(2 ** attempt)

    logging.error("Max retries reached. Giving up.")
    return False

def log_action(alert, action_type, success):
    timestamp = datetime.datetime.utcnow().isoformat()
    rule_id = get_field(alert, "rule.id", "unknown")
    level = get_field(alert, "rule.level", "unknown")
    title = get_field(alert, "rule.description", "No title")
    status = "SUCCESS" if success else "FAILED"

    log_entry = f"{status} sending {action_type.upper()} | Rule ID: {rule_id} | Level: {level} | Title: {title}"
    logging.info(log_entry)

if __name__ == "__main__":
    main(sys.argv)
