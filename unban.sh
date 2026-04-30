#!/usr/bin/env bash
# unban.sh — interactive WAF unban tool
# Run as root (or the user owning the bans file) on the WAF server.
# Usage: ./unban.sh [bans_file]
set -euo pipefail

BANS_FILE="${1:-/var/log/webfirewall/bans.json}"

if [[ ! -f "$BANS_FILE" ]]; then
    echo "Error: bans file not found: $BANS_FILE" >&2
    exit 1
fi

python3 - "$BANS_FILE" << 'PYEOF'
import json, sys, os, time, shutil

bans_file = sys.argv[1]

def load():
    with open(bans_file) as f:
        return json.load(f)

def save(bans):
    tmp = bans_file + ".tmp"
    with open(tmp, "w") as f:
        json.dump(bans, f, indent=2)
    shutil.move(tmp, bans_file)

def fmt_time(ts):
    t = time.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S")
    remaining = int(time.mktime(t) - time.time())
    if remaining <= 0:
        return "expired"
    h, s = divmod(remaining, 3600)
    m, s = divmod(s, 60)
    parts = []
    if h: parts.append(f"{h}h")
    if m: parts.append(f"{m}m")
    if s or not parts: parts.append(f"{s}s")
    return "expires in " + "".join(parts)

while True:
    try:
        bans = load()
    except json.JSONDecodeError:
        print("Error: bans file is not valid JSON.")
        sys.exit(1)

    # Filter out expired bans for display
    now = time.time()
    active = {ip: e for ip, e in bans.items()
              if time.mktime(time.strptime(e["expires_at"][:19], "%Y-%m-%dT%H:%M:%S")) > now}

    if not active:
        print("\n✓ No active bans.")
        break

    print(f"\n{'IP':<20} {'Score':<7} {'Reason':<35} {'Expires'}")
    print("-" * 80)
    for ip, e in sorted(active.items(), key=lambda x: x[1].get("score", 0), reverse=True):
        reason = e.get("reason", "?")[:34]
        score  = e.get("score", 0)
        exp    = fmt_time(e.get("expires_at", ""))
        print(f"{ip:<20} {score:<7} {reason:<35} {exp}")

    print()
    try:
        ip_input = input("Enter IP to unban (blank to quit): ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        break

    if not ip_input:
        break

    if ip_input not in bans:
        # Try partial match
        matches = [ip for ip in bans if ip.startswith(ip_input)]
        if len(matches) == 1:
            ip_input = matches[0]
        elif len(matches) > 1:
            print(f"Ambiguous — matches: {', '.join(matches)}")
            continue
        else:
            print(f"IP not found: {ip_input}")
            continue

    del bans[ip_input]
    save(bans)
    print(f"✓ Unbanned {ip_input}")

    # Try fail2ban unban if available
    try:
        import subprocess
        result = subprocess.run(
            ["fail2ban-client", "set", "waf", "unbanip", ip_input],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            print(f"✓ fail2ban: unbanned {ip_input}")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass  # fail2ban not installed or timed out, that's fine

PYEOF
