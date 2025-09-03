#!/var/ossec/venv/bin/python

import json
import os
import re
import sys
from datetime import datetime
import requests

# Read config from Wazuh env vars
WEBHOOK_CRITICAL = os.getenv("OSSEC_INTEGRATION_WEBHOOK_CRITICAL", "")
WEBHOOK_HIGH = os.getenv("OSSEC_INTEGRATION_WEBHOOK_HIGH", "")
WEBHOOK_MEDIUM = os.getenv("OSSEC_INTEGRATION_WEBHOOK_MEDIUM", "")

LEVEL_CRITICAL = int(os.getenv("OSSEC_INTEGRATION_LEVEL_CRITICAL", "11"))
LEVEL_HIGH = int(os.getenv("OSSEC_INTEGRATION_LEVEL_HIGH", "7"))

excluded_rules: list = []  # Example: ["1002", "5715", "18107"]


def escape_markdown(text):
    if not isinstance(text, str):
        text = str(text)
    return re.sub(r"([*`_~])", r"\\\1", text)


def choose_webhook(level):
    try:
        lvl = int(level)
    except ValueError:
        return WEBHOOK_MEDIUM
    if lvl >= LEVEL_CRITICAL:
        return WEBHOOK_CRITICAL
    elif lvl >= LEVEL_HIGH:
        return WEBHOOK_HIGH
    else:
        return WEBHOOK_MEDIUM


def main():
    if len(sys.argv) < 2:
        print("[ERROR] No alert file path provided.")
        sys.exit(1)
    alert_file = sys.argv[1]
    try:
        with open(alert_file) as f:
            alert = json.load(f)
    except Exception as e:
        print(f"[ERROR] Failed to read or parse JSON: {e}")
        sys.exit(1)

    rule_id = alert.get("rule", {}).get("id")
    if rule_id in excluded_rules:
        print(f"[INFO] Skipping excluded rule ID: {rule_id}")
        sys.exit(0)

    data = alert.get("data", {})
    srcuser = data.get("srcuser") or data.get("dstuser") or "unknown"
    srcip = data.get("srcip", "unknown")
    srcport = data.get("srcport", "unknown")
    agent_name = alert.get("agent", {}).get("name", "unknown")
    alert_level = alert.get("rule", {}).get("level", "unknown")
    description = alert.get("rule", {}).get("description", "No description")
    full_log = alert.get("full_log", "No full log available")
    timestamp_raw = alert.get("timestamp", "unknown")

    try:
        dt = datetime.fromisoformat(timestamp_raw.replace("Z", "+00:00"))
        timestamp = dt.strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        timestamp = timestamp_raw

    text = (
        "*:rotating_light: Wazuh Alert Notification*\n\n"
        f"*Time:* `{escape_markdown(timestamp)}`\n"
        f"*Username:* `{escape_markdown(srcuser)}`\n"
        f"*Source IP:* `{escape_markdown(srcip)}`\n"
        f"*Source Port:* `{escape_markdown(srcport)}`\n"
        f"*Agent:* `{escape_markdown(agent_name)}`\n\n"
        f"*Rule ID:* `{escape_markdown(rule_id)}`\n"
        f"*Level:* `{escape_markdown(alert_level)}`\n\n"
        f"*Description:*\n```{escape_markdown(description)}```\n\n"
        f"*Full Log:*\n```{full_log}```"
    )

    vuln = alert.get("vulnerability", {})
    cve_id = vuln.get("cve", "")
    cve_title = vuln.get("title", "")
    if cve_id:
        cve_url = f"https://cti.wazuh.com/vulnerabilities/cves/{cve_id}"
        text += (
            f"\n\n*🛡️ CVE:* `{escape_markdown(cve_id)}`\n"
            f"*Title:* {escape_markdown(cve_title)}\n"
            f"<{escape_markdown(cve_url)}|Details in CTI>"
        )

    text += "\n\n────────────────────────\n"

    webhook_url = choose_webhook(alert_level)
    if not webhook_url:
        print("[ERROR] No webhook configured for this level.")
        sys.exit(1)

    payload = {"text": text}
    resp = requests.post(webhook_url, json=payload)
    if resp.status_code != 200:
        print(f"[ERROR] Slack response: {resp.status_code} – {resp.text}")


if __name__ == "__main__":
    main()
