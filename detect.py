#!/usr/bin/env python3
"""
detect.py - WoodCraft Furniture log monitor
Task 2: rule-based detection of suspicious activity in web server logs.

WHAT IT DOES
  1. Reads log entries from a JSON file (default: logs.json).
  2. Applies two detection rules (described below).
  3. Writes every alert, with the log lines that caused it, to alerts.json.
  4. Prints a short summary to the console.

USAGE
  python detect.py                         # scan logs.json  -> alerts.json
  python detect.py attack_logs.json        # scan another file
  python detect.py logs.json -o out.json   # choose the output file

DETECTION RULES
  R1  404 scan (severity MEDIUM)
      Trigger: one IP gets 4 or more "404 Not Found" responses within 5 minutes.
      Why: attackers and automated scanners guess at hidden pages such as
      /admin, /.env or /backup.zip. Most of those pages do not exist, so the
      server answers 404 again and again. A normal visitor may hit one broken
      link, but rarely several within a few minutes.

  R2  Brute-force login (severity HIGH)
      Trigger: one IP makes 3 or more failed login attempts within 10 minutes.
      A "failed login" is either
        - a request to a login URL (e.g. "POST /login") that the server
          answered with 401 Unauthorized or 403 Forbidden, or
        - a log message that says so, e.g. "Failed password" (SSH-style logs).
      Why: repeated wrong passwords from one address usually means someone is
      guessing passwords, by hand or with a tool.

  Both rules use a sliding time window (see find_burst) so that a few harmless
  events spread across a whole day do not raise an alert. The numbers live in
  the SETTINGS block below and can be tuned.
"""

import argparse
import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone

# ---------------------------------------------------------------------------
# SETTINGS - change these to make the rules more or less sensitive
# ---------------------------------------------------------------------------
NOT_FOUND_THRESHOLD = 4                      # this many 404s from one IP...
NOT_FOUND_WINDOW = timedelta(minutes=5)      # ...inside this much time = alert

FAILED_LOGIN_THRESHOLD = 3                   # this many failed logins...
FAILED_LOGIN_WINDOW = timedelta(minutes=10)  # ...inside this much time = alert

# ---------------------------------------------------------------------------
# REGULAR EXPRESSIONS used by the rules
# ---------------------------------------------------------------------------
# R1: the HTTP status code is exactly 404.
NOT_FOUND_RE = re.compile(r"^404$")

# R2 (web logs), part 1: the request is aimed at a login page, e.g.
#   "POST /login HTTP/1.1"   or   "POST /wp-login.php HTTP/1.1"
LOGIN_REQUEST_RE = re.compile(
    r"^(?:POST|GET)\s+\S*(?:login|signin|sign-in|logon|auth)\S*",
    re.IGNORECASE,
)
# R2 (web logs), part 2: the server refused it (401 Unauthorized / 403 Forbidden).
FAILED_STATUS_RE = re.compile(r"^(?:401|403)$")

# R2 (SSH / system logs): the text itself says the login failed.
FAILED_TEXT_RE = re.compile(
    r"failed password|authentication failure|login failed|invalid user",
    re.IGNORECASE,
)

# If an entry is a raw Apache log line (a plain string) instead of a JSON
# object, this pulls the fields out of it. Example line:
#   203.0.113.45 - - [30/Oct/2026:09:20:02 +0000] "POST /login HTTP/1.1" 401 298
APACHE_LINE_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<request>[^"]*)" (?P<status>\d{3}) (?P<size>\S+)'
)

# ---------------------------------------------------------------------------
# READING THE LOG FILE
# ---------------------------------------------------------------------------
# Log generators name their fields differently, so accept the common names.
FIELD_NAMES = {
    "ip": ("ip", "client_ip", "remote_addr", "remote_host", "source_ip", "src_ip", "host"),
    "timestamp": ("timestamp", "time", "datetime", "date"),
    "request": ("request", "request_line", "req", "url", "path"),
    "status": ("status", "status_code", "code", "response"),
    "message": ("message", "msg", "event", "description"),
}

TIME_FORMATS = (
    "%d/%b/%Y:%H:%M:%S %z",  # Apache:  30/Oct/2026:09:20:02 +0000
    "%d/%b/%Y:%H:%M:%S",
    "%Y-%m-%dT%H:%M:%S%z",   # ISO:     2026-10-30T09:20:02+00:00
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S%z",
    "%Y-%m-%d %H:%M:%S",     # simple:  2026-10-30 09:20:02
)


def load_entries(path):
    """Read the log file and return a list of raw entries."""
    try:
        with open(path, encoding="utf-8") as f:
            text = f.read()
    except FileNotFoundError:
        sys.exit(f"Error: '{path}' not found. Run the script from the repository "
                 f"folder, or give the path: python detect.py path/to/logs.json")

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # Not one JSON document - maybe one JSON object (or raw line) per line.
        data = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data.append(json.loads(line))
            except json.JSONDecodeError:
                data.append(line)  # treat it as a raw Apache line

    if isinstance(data, dict):
        # Accept {"logs": [...]} as well as a plain list [...]
        for key in ("logs", "entries", "records", "data"):
            if isinstance(data.get(key), list):
                return data[key]
        sys.exit(f"Error: '{path}' is a JSON object but has no list of log entries.")
    if not isinstance(data, list):
        sys.exit(f"Error: '{path}' should contain a JSON list of log entries.")
    return data


def parse_timestamp(value):
    """Turn a timestamp (text or Unix number) into a datetime, or None."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc).replace(tzinfo=None)

    text = str(value).strip()
    parsed = None
    for fmt in TIME_FORMATS:
        try:
            parsed = datetime.strptime(text, fmt)
            break
        except ValueError:
            continue
    if parsed is None:
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None

    # Convert to UTC so logs from different time zones can be compared.
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed


def pick(entry, field):
    """Return the first non-empty value among the accepted names for a field."""
    for key in FIELD_NAMES[field]:
        if entry.get(key) not in (None, ""):
            return entry[key]
    return None


def normalize(raw):
    """
    Convert one raw entry into a simple, predictable dict:
        {ip, time, request, status, message, original}
    Returns None if the entry has no usable IP or timestamp.
    """
    if isinstance(raw, str):
        match = APACHE_LINE_RE.match(raw)
        if not match:
            return None
        fields = match.groupdict()
    elif isinstance(raw, dict):
        fields = {str(k).lower(): v for k, v in raw.items()}
    else:
        return None

    ip = pick(fields, "ip")
    when = parse_timestamp(pick(fields, "timestamp"))
    if ip is None or when is None:
        return None

    request = str(pick(fields, "request") or "")
    method = fields.get("method")
    if method and not request.upper().startswith(str(method).upper()):
        request = f"{method} {request}"  # e.g. {"method": "POST", "url": "/login"}

    return {
        "ip": str(ip),
        "time": when,
        "request": request,
        "status": str(pick(fields, "status") or ""),
        "message": str(pick(fields, "message") or ""),
        "original": raw,  # kept so alerts.json shows the real log line
    }


# ---------------------------------------------------------------------------
# THE RULES
# ---------------------------------------------------------------------------
def is_not_found(entry):
    """R1 match: the response was 404 Not Found."""
    return bool(NOT_FOUND_RE.match(entry["status"]))


def is_failed_login(entry):
    """R2 match: a refused request to a login page, or a 'login failed' message."""
    refused_web_login = (LOGIN_REQUEST_RE.match(entry["request"])
                         and FAILED_STATUS_RE.match(entry["status"]))
    failure_text = FAILED_TEXT_RE.search(f"{entry['request']} {entry['message']}")
    return bool(refused_web_login or failure_text)


RULES = [
    {
        "id": "R1",
        "name": "404 scan",
        "severity": "MEDIUM",
        "matches": is_not_found,
        "threshold": NOT_FOUND_THRESHOLD,
        "window": NOT_FOUND_WINDOW,
        "what": "'404 Not Found' responses to",
        "meaning": "possible scan for hidden pages",
    },
    {
        "id": "R2",
        "name": "Brute-force login",
        "severity": "HIGH",
        "matches": is_failed_login,
        "threshold": FAILED_LOGIN_THRESHOLD,
        "window": FAILED_LOGIN_WINDOW,
        "what": "failed login attempts from",
        "meaning": "possible password guessing",
    },
]


def find_burst(events, threshold, window):
    """
    Sliding-window check for the events of ONE IP address (sorted by time).

    Imagine a frame `window` long sliding along the timeline. `start` is its
    left edge and `end` its right edge. Each time `end` moves to the next event,
    `start` moves forward until the frame spans no more than `window` of time.
    If the frame then holds `threshold` or more events, they are all suspicious.
    """
    flagged = set()
    start = 0
    for end in range(len(events)):
        while events[end]["time"] - events[start]["time"] > window:
            start += 1
        if end - start + 1 >= threshold:
            flagged.update(range(start, end + 1))
    return [events[i] for i in sorted(flagged)]


def format_duration(delta):
    seconds = int(delta.total_seconds())
    minutes, seconds = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m {seconds}s"
    return f"{seconds}s"


def run_rule(rule, entries):
    """Apply one rule to all entries and return a list of alerts (one per IP)."""
    # Step 1: keep only the entries this rule cares about, grouped by IP.
    by_ip = defaultdict(list)
    for entry in entries:
        if rule["matches"](entry):
            by_ip[entry["ip"]].append(entry)

    # Step 2: for each IP, check whether enough of them happened close together.
    alerts = []
    for ip, events in sorted(by_ip.items()):
        events.sort(key=lambda e: e["time"])
        hits = find_burst(events, rule["threshold"], rule["window"])
        if not hits:
            continue
        first, last = hits[0]["time"], hits[-1]["time"]
        window_min = int(rule["window"].total_seconds() // 60)
        alerts.append({
            "rule_id": rule["id"],
            "rule": rule["name"],
            "severity": rule["severity"],
            "ip": ip,
            "count": len(hits),
            "first_seen": first.strftime("%Y-%m-%d %H:%M:%S"),
            "last_seen": last.strftime("%Y-%m-%d %H:%M:%S"),
            "description": (f"{len(hits)} {rule['what']} {ip} in "
                            f"{format_duration(last - first)} - {rule['meaning']} "
                            f"(rule: {rule['threshold']}+ within {window_min} min)"),
            "entries": [h["original"] for h in hits],
        })
    return alerts


# ---------------------------------------------------------------------------
# OUTPUT
# ---------------------------------------------------------------------------
def print_summary(source, total, skipped, alerts, output):
    line = "-" * 78
    print(f"WoodCraft Log Monitor - scanned {total} entries from {source}")
    if skipped:
        print(f"(skipped {skipped} entries with no readable IP or timestamp)")
    print(line)
    if not alerts:
        print("No suspicious activity found.")
    for a in alerts:
        print(f"[{a['severity']:<6}] {a['alert_id']}  {a['rule']:<17} {a['ip']:<15} "
              f"{a['count']:>3} events  {a['first_seen']} -> {a['last_seen'][11:]}")
    print(line)
    suspicious = sum(a["count"] for a in alerts)
    print(f"{suspicious} suspicious entries found in {len(alerts)} alert(s). "
          f"Details saved to {output}")


def main():
    parser = argparse.ArgumentParser(
        description="Rule-based detection of suspicious activity in WoodCraft web logs.")
    parser.add_argument("logfile", nargs="?", default="logs.json",
                        help="log file to scan (default: logs.json)")
    parser.add_argument("-o", "--output", default="alerts.json",
                        help="where to write the alerts (default: alerts.json)")
    args = parser.parse_args()

    raw_entries = load_entries(args.logfile)
    entries = [e for e in (normalize(r) for r in raw_entries) if e is not None]
    skipped = len(raw_entries) - len(entries)

    alerts = []
    for rule in RULES:
        alerts.extend(run_rule(rule, entries))

    # Most serious first, then oldest first; then number them.
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    alerts.sort(key=lambda a: (order.get(a["severity"], 9), a["first_seen"]))
    for number, alert in enumerate(alerts, start=1):
        alert["alert_id"] = f"ALERT-{number:03d}"
    alerts = [{"alert_id": a.pop("alert_id"), **a} for a in alerts]  # id first

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(alerts, f, indent=2)

    print_summary(args.logfile, len(raw_entries), skipped, alerts, args.output)


if __name__ == "__main__":
    main()