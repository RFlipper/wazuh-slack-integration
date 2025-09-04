#!/var/ossec/venv/bin/python

import json, os, re, sys
from datetime import datetime
import requests

def escape_markdown(text):
    if not isinstance(text, str):
        text = str(text)
    return re.sub(r"([*`_~])", r"\\\1", text)

def load_options():
    opts_json = os.getenv("OSSEC_INTEGRATION_OPTIONS", "{}")
    try:
        return json.loads(opts_json)
    except json.JSONDecodeError:
        print(f"[ERROR] OSSEC_INTEGRATION_OPTIONS contains invalid JSON: {opts_json}")
        sys.exit(1)

def choose_webhook(level, options):
    try:
        lvl = int(level)
    except (ValueError, TypeError):
        return None
    levels = options.get("levels", {})
    webhooks = options.get("webhooks", {})
    # Find appropriate tier
    for tier in ["critical", "high", "medium"]:
        if lvl >= levels.get(tier, float('inf')):
            return webhooks.get(tier)
    return None

def main():
    if len(sys.argv) < 2:
        print("[ERROR] No alert file path provided.")
        sys.exit(1)
    alert_file = sys.argv[1]
    try:
        alert = json.load(open(alert_file))
    except Exception as e:
        print(f"[ERROR] Failed to read or parse JSON: {e}")
        sys.exit(1)

    options = load_options()
    alert_level = alert.get("rule", {}).get("level", "0")
    webhook_url = choose_webhook(alert_level, options)
    if not webhook_url:
        print(f"[ERROR] No valid webhook for level {alert_level}.")
        sys.exit(1)

    # Build message
    data = alert.get("data", {})
    timestamp_raw = alert.get("timestamp", "")
    ts = timestamp_raw
    try:
        ts = datetime.fromisoformat(timestamp_raw.replace("Z","+00:00")).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        pass

    text = (
        "*:rotating_light: Wazuh Alert Notification*\n\n"
        f"*Time:* `{escape_markdown(ts)}`\n"
        f"*Username:* `{escape_markdown(data.get('srcuser') or data.get('dstuser') or 'unknown')}`\n"
        f"*Source IP:* `{escape_markdown(data.get('srcip','unknown'))}`\n"
        f"*Source Port:* `{escape_markdown(data.get('srcport','unknown'))}`\n"
        f"*Agent:* `{escape_markdown(alert.get('agent', {}).get('name','unknown'))}`\n\n"
        f"*Rule ID:* `{escape_markdown(alert.get('rule', {}).get('id','unknown'))}`\n"
        f"*Level:* `{escape_markdown(alert_level)}`\n\n"
        f"*Description:*\n```{escape_markdown(alert.get('rule', {}).get('description','No description'))}```\n\n"
        f"*Full Log:*\n```{alert.get('full_log','No full log available')}```"
    )

    vuln = alert.get("vulnerability", {})
    if vuln.get("cve"):
        cve = escape_markdown(vuln.get("cve"))
        title = escape_markdown(vuln.get("title",""))
        url = escape_markdown(f"https://cti.wazuh.com/vulnerabilities/cves/{vuln.get('cve')}")
        text += f"\n\n*🛡️ CVE:* `{cve}`\n*Title:* {title}\n<{url}|Details in CTI>"

    text += "\n\n────────────────────────\n"
    resp = requests.post(webhook_url, json={"text": text})
    if resp.status_code != 200:
        print(f"[ERROR] Slack returned {resp.status_code}: {resp.text}")

if __name__ == "__main__":
    main()
