import json
from pathlib import Path
from nmap_tracker import NmapTracker
import requests
from datetime import datetime

def send_discord(content: str, WEBHOOK_URL):
    """Send a message to the Discord webhook. Splits if over 2000 chars."""
    chunks = [content[i:i+2000] for i in range(0, len(content), 2000)]
    for chunk in chunks:
        requests.post(WEBHOOK_URL, json={"content": chunk})


def build_message(result, team, scan_name) -> str:
    """Build a formatted Discord message from scan results."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if not result.has_findings:
        return f"**{team} {scan_name} Scan** \t {timestamp} \tNo new findings."

    lines = [f"## {team} {scan_name} Scan {timestamp}"]

    if result.new_hosts:
        lines.append(":tada: **New Hosts** :tada:")
        for host, ports in result.new_hosts.items():
            lines.append(f"\t**{host}**")
            for port, proto, state in ports:
                lines.append(f"\t\t`{port}/{proto}` — {state}")
        lines.append("")

    if result.new_ports:
        lines.append("🔔 **New Ports on Known Hosts**")
        for host, ports in result.new_ports.items():
            lines.append(f"  **{host}**")
            for port, proto, state in ports:
                lines.append(f"    `{port}/{proto}` — {state}")

    return "\n".join(lines)

def test():
    print("test!!!!!!!!!!!!!!!!!!!!!!")
    new = "/home/akio/git/OldManTouchy/results/quick/team01_latest.xml"
    old = "/home/akio/git/OldManTouchy/results/quick/team01_20260308_224138.xml"

    webhook = Path("webhook.link")
    if not webhook.exists():
        print("[!] Webhook file does not exist")
        sys.exit(1)
    with open(webhook) as f:
        WEBHOOK_URL = f.read().strip()
    
    tracker = NmapTracker("results/quick/known_hosts.json")
    result = tracker.process_scan(new)

    message = build_message(result, "team01", "quick")
    send_discord(message, WEBHOOK_URL)

def diff(report, path, team_name, scan_name):

    # Deal with Discord webhook URL
    webhook = Path("webhook.link")
    if not webhook.exists():
        print("[!] Webhook file does not exist")
        sys.exit(1)
    with open(webhook) as f:
        WEBHOOK_URL = f.read().strip()
    
    master = path / (team_name + "_known_hosts.json")
    tracker = NmapTracker(master)
    result = tracker.process_scan(report)

    message = build_message(result, team_name, scan_name)
    send_discord(message, WEBHOOK_URL)

if __name__ == "__main__":
    test()