#!/usr/bin/env python

import json
import os
import sys

try:
    import requests
except ModuleNotFoundError:
    print("No module 'requests' found. Install it with: pip install requests")
    sys.exit(1)

# Constants
ALERT_INDEX = 1
API_KEY_INDEX = 2
API_URL_INDEX = 3

# Hardcoded secret
HARDCODED_API_SECRET = "a01150b70f1482f1ac3bab6513e7e5f329c43e723c580eac003d05f8762895e7"

def main(args):
    if len(args) < 4:
        print("Usage: script.py <alert_file> <api_key> <casebender_url>")
        sys.exit(2)

    alert_file = args[ALERT_INDEX]
    api_key = args[API_KEY_INDEX]
    casebender_url = args[API_URL_INDEX]
    api_secret = HARDCODED_API_SECRET

    alert = load_alert(alert_file)

    payload = generate_casebender_payload(alert)

    send_to_casebender(casebender_url, api_key, api_secret, payload)

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

    payload = {
        "description": alert.get('full_log', 'No description available'),
        "count": 1,
        "title": alert['rule'].get('description', 'Wazuh Alert'),
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
        print(f"Response status code: {response.status_code}")
        print(response.text)
    except Exception as e:
        print(f"Failed to send alert: {e}")
        sys.exit(4)

if __name__ == "__main__":
    main(sys.argv)
