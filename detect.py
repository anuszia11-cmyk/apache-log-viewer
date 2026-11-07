"""
detect.py  -  WoodCraft rule-based log detector (updated in Task 3)

Reads one or more JSON log files and flags suspicious activity.

  Rule R1 - 404 burst
      The same IP gets 3 or more "404 Not Found" responses within 5 minutes.
      Meaning: someone is probing the portal for hidden pages.

  Rule R2 - Repeated failed logins (brute force)
      The same IP fails to log in 5 or more times within 10 minutes.
      Works for web logins (POST /login answered with 401/403) and for
      SSH logins ("Failed password for ..." lines, as in attack_logs.json).
      Meaning: someone is guessing passwords.

Usage:
    python detect.py                                 # logs.json (+ attack_logs.json if present)
    python detect.py attack_logs.json                # only that file
    python detect.py logs.json attack_logs.json --out alerts.json

Output:
    alerts.json  - every flagged log entry, with the rule that caught it
    console      - a short summary
"""

import argparse
import json
import os
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone

# ---------------- Rule settings (change these to tune the detector) ----------------
NOT_FOUND_THRESHOLD = 3
NOT_FOUND_WINDOW = timedelta(minutes=5)

FAILED_LOGIN_THRESHOLD = 5
FAILED_LOGIN_WINDOW = timedelta(minutes=10)

# ---------------- Regex patterns (matched against one log "line") ----------------
# R1: the status code right after the quoted request is 404
NOT_FOUND_PATTERN = re.compile(r'" 404 ')

# R2: any common sign of a failed login
FAILED_LOGIN_PATTERN = re.compile(
    r"Failed password"                      # sshd: wrong password
    r"|Invalid user"                        # sshd: username does not exist
    r"|authentication failure"              # PAM / generic
    r'|"(?:POST|GET) [^"]*login[^"]*" 40[13] ',   # web portal: /login -> 401 or 403
    re.IGNORECASE,
)


def pick(entry, *names, default=""):
    """Return the first key that exists, so slightly different log formats still work."""
    for name in names:
        if name in entry and entry[name] not in (None, ""):
            return entry[name]
    return default


def parse_time(value):
    """Understand Apache time (06/Nov/2026:16:20:05 +0000) and ISO time (2026-11-06T16:20:05Z)."""
    text = str(value).strip()
    for fmt in ("%d/%b/%Y:%H:%M:%S %z", "%Y-%m-%d %H:%M:%S"):
        try:
            dt = datetime.strptime(text, fmt)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def as_line(entry):
    """Rebuild an Apache-style text line from a JSON entry so the regexes can read it."""
    ip = pick(entry, "ip", "client_ip", "remote_addr", default="-")
    ts = pick(entry, "timestamp", "time", "datetime", default="-")
    request = pick(entry, "request")
    if not request:
        request = " ".join(str(pick(entry, k)) for k in ("method", "path", "protocol")).strip()
    status = pick(entry, "status", "status_code", default="-")
    size = pick(entry, "size", "bytes", default="-")
    message = pick(entry, "message", "msg")
    return f'{ip} - - [{ts}] "{request}" {status} {size} {message}'.strip()


def load_entries(path):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict):            # allow {"logs": [...]} as well as [...]
        data = data.get("logs") or data.get("entries") or []
    return data


def find_bursts(hits, threshold, window):
    """
    Sliding window: hits is a time-sorted list of (time, entry) for ONE IP.
    Returns every hit that is part of a window holding >= threshold hits.
    """
    flagged = set()
    start = 0
    for end in range(len(hits)):
        while hits[end][0] - hits[start][0] > window:
            start += 1
        if end - start + 1 >= threshold:
            flagged.update(range(start, end + 1))
    return [hits[i] for i in sorted(flagged)]


def run_rule(records, pattern, threshold, window):
    """Group matching records by IP, then look for bursts inside the time window."""
    by_ip = defaultdict(list)
    for rec in records:
        if rec["time"] is not None and pattern.search(rec["line"]):
            by_ip[rec["ip"]].append((rec["time"], rec))
    results = {}
    for ip, hits in by_ip.items():
        hits.sort(key=lambda h: h[0])
        burst = find_bursts(hits, threshold, window)
        if burst:
            results[ip] = [rec for _, rec in burst]
    return results


def main():
    parser = argparse.ArgumentParser(description="Rule-based detector for WoodCraft logs.")
    parser.add_argument("files", nargs="*", help="JSON log files to scan")
    parser.add_argument("--out", default="alerts.json", help="where to save the alerts")
    args = parser.parse_args()

    files = args.files or [p for p in ("logs.json", "attack_logs.json") if os.path.exists(p)]
    if not files:
        sys.exit("No log files found. Put logs.json next to detect.py or pass a file name.")

    records, skipped = [], 0
    for path in files:
        entries = load_entries(path)
        print(f"Loaded {len(entries):>3} entries from {path}")
        for entry in entries:
            t = parse_time(pick(entry, "timestamp", "time", "datetime"))
            if t is None:
                skipped += 1
            records.append({
                "entry": entry,
                "file": path,
                "time": t,
                "ip": pick(entry, "ip", "client_ip", "remote_addr", default="-"),
                "line": as_line(entry),
            })
    if skipped:
        print(f"Note: {skipped} entries had an unreadable timestamp and were not checked.")

    rules = [
        ("R1_404_BURST", "medium", NOT_FOUND_PATTERN, NOT_FOUND_THRESHOLD, NOT_FOUND_WINDOW,
         "'404 Not Found' responses"),
        ("R2_REPEATED_FAILED_LOGIN", "high", FAILED_LOGIN_PATTERN, FAILED_LOGIN_THRESHOLD,
         FAILED_LOGIN_WINDOW, "failed logins"),
    ]

    alerts, alert_groups = [], 0
    print()
    for rule_id, severity, pattern, threshold, window, label in rules:
        minutes = int(window.total_seconds() // 60)
        for ip, recs in run_rule(records, pattern, threshold, window).items():
            alert_groups += 1
            users = sorted({str(pick(r["entry"], "username", "user")) for r in recs} - {""})
            first, last = recs[0]["time"], recs[-1]["time"]
            reason = (f"{len(recs)} {label} from {ip} "
                      f"(rule: >= {threshold} within {minutes} min)")
            print(f"[{rule_id}] {ip}: {len(recs)} {label}, "
                  f"{first:%H:%M:%S} -> {last:%H:%M:%S} UTC"
                  + (f", users: {', '.join(users)}" if users else ""))
            for r in recs:
                flagged = dict(r["entry"])
                flagged.update({
                    "alert_rule": rule_id,
                    "alert_severity": severity,
                    "alert_reason": reason,
                    "source_file": r["file"],
                })
                alerts.append(flagged)

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(alerts, f, indent=2)

    if alerts:
        print(f"\n{len(alerts)} suspicious entries found ({alert_groups} alert(s)). Saved to {args.out}")
    else:
        print(f"\nNo suspicious activity found. Empty list saved to {args.out}")


if __name__ == "__main__":
    main()
