"""
generate_attack_logs.py  -  WoodCraft Task 3

Turns the login attempts you recorded on the OverTheWire Bandit lab
(bandit_attempts.csv) into server-style log entries (attack_logs.json)
that look like the entries in logs.json, so detect.py can scan them.

Why "simulated" IPs?
  The Bandit server never shows us its own logs, and we should not put
  our real home IP in a public repo. So each attempt gets a stand-in
  source IP from the documentation ranges 203.0.113.0/24 and
  198.51.100.0/24 (RFC 5737). These ranges are reserved for examples
  and never belong to a real computer.

    failed attempts     -> attacker IP   (default 203.0.113.45)
    successful logins   -> normal user IP (default 198.51.100.10)

Usage:
    python generate_attack_logs.py
    python generate_attack_logs.py --input bandit_attempts.csv --output attack_logs.json
"""

import argparse
import csv
import json
import random
import sys
from datetime import datetime, timezone

HOST = "bandit.labs.overthewire.org"
PORT = 2220
MIN_FAILED = 10  # the mentor checks for at least 10 failed-login entries


def parse_time(text):
    """Read the ISO timestamp written by record_attempts.py (e.g. 2026-11-06T16:20:05Z)."""
    text = text.strip().replace("Z", "+00:00")
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:            # no timezone given -> assume UTC
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def format_time(dt, style):
    if style == "iso":
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    return dt.strftime("%d/%b/%Y:%H:%M:%S +0000")   # Apache style, same as logs.json


def to_log_entry(attempt, ip, port, pid, time_style):
    """
    Build ONE log entry.
    The first five keys match the log viewer columns from Task 1
    (ip, timestamp, request, status, size). If your logs.json uses
    different key names, rename them here.
    """
    failed = attempt["result"] == "failed"
    user = attempt["username"]

    if failed:
        message = f"sshd[{pid}]: Failed password for {user} from {ip} port {port} ssh2"
    else:
        message = f"sshd[{pid}]: Accepted password for {user} from {ip} port {port} ssh2"

    return {
        "ip": ip,
        "timestamp": format_time(attempt["time"], time_style),
        "request": f"SSH login {user}@{HOST}:{PORT}",
        "status": 401 if failed else 200,   # 401 = rejected, 200 = accepted
        "size": 0,
        "service": "sshd",
        "username": user,
        "event": "failed_login" if failed else "login_success",
        "message": message,                  # looks like a line from /var/log/auth.log
        "source": "OverTheWire Bandit lab - real attempt, simulated source IP",
    }


def main():
    parser = argparse.ArgumentParser(description="Build attack_logs.json from Bandit login attempts.")
    parser.add_argument("--input", default="bandit_attempts.csv")
    parser.add_argument("--output", default="attack_logs.json")
    parser.add_argument("--attacker-ip", default="203.0.113.45")
    parser.add_argument("--user-ip", default="198.51.100.10")
    parser.add_argument("--time-format", choices=["apache", "iso"], default="apache",
                        help="match the timestamp style used in your logs.json")
    args = parser.parse_args()

    try:
        with open(args.input, newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
    except FileNotFoundError:
        sys.exit(f"{args.input} not found. Run record_attempts.py first.")

    attempts = []
    for row in rows:
        result = (row.get("result") or "").strip().lower()
        if result not in ("failed", "success"):
            continue                      # skip network errors etc.
        attempts.append({
            "time": parse_time(row["timestamp_utc"]),
            "username": row["username"].strip(),
            "result": result,
            "source_ip": (row.get("source_ip") or "").strip(),
        })
    attempts.sort(key=lambda a: a["time"])

    rng = random.Random(2220)   # fixed seed -> same CSV always gives the same JSON
    entries = []
    for a in attempts:
        ip = a["source_ip"] or (args.attacker_ip if a["result"] == "failed" else args.user_ip)
        port = rng.randint(49152, 65535)   # random client port, like a real connection
        pid = rng.randint(1000, 32000)     # random sshd process id
        entries.append(to_log_entry(a, ip, port, pid, args.time_format))

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=2)

    failed = sum(1 for e in entries if e["event"] == "failed_login")
    print(f"Wrote {len(entries)} entries to {args.output} "
          f"({failed} failed logins, {len(entries) - failed} successful).")
    if failed < MIN_FAILED:
        print(f"WARNING: only {failed} failed logins. The task needs at least {MIN_FAILED} - "
              f"record a few more attempts.")


if __name__ == "__main__":
    main()
