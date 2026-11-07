"""
record_attempts.py  -  WoodCraft Task 3 helper

Records every SSH login attempt you make on the OverTheWire Bandit lab
(bandit.labs.overthewire.org, port 2220) into bandit_attempts.csv.
For each attempt it saves: UTC timestamp, username tried, result.

Two ways to use it
------------------
1) MANUAL mode (works on Windows, Mac and Linux - recommended)

       python record_attempts.py

   Keep this window open. In a SECOND terminal run:
       ssh bandit1@bandit.labs.overthewire.org -p 2220
   and type a WRONG password. Every time you see "Permission denied",
   come back to this window and press Enter. The time is recorded.

2) AUTO mode (this script opens ssh for you, one attempt at a time)

       python record_attempts.py --auto --count 12

   When asked, type a WRONG password. The script checks whether the
   server rejected it and records the result.

Be a good lab citizen: Bandit is a shared, free server. Type the
attempts yourself (10-15 is plenty). Never point a brute-force tool
such as hydra at it.
"""

import argparse
import csv
import os
import subprocess
import sys
import time
from datetime import datetime, timezone

HOST = "bandit.labs.overthewire.org"
PORT = "2220"
CSV_FIELDS = ["timestamp_utc", "username", "result", "source_ip", "note"]
MAX_AUTO_ATTEMPTS = 20  # keep the load on the shared lab small


def now_utc():
    """Current time in UTC, ISO 8601 format, e.g. 2026-11-06T16:20:05Z"""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def append_row(path, row):
    """Add one attempt to the CSV (writes the header the first time)."""
    new_file = not os.path.exists(path) or os.path.getsize(path) == 0
    with open(path, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        if new_file:
            writer.writeheader()
        writer.writerow(row)


def manual_mode(path, username):
    print(f"\nRecording attempts for user '{username}' into {path}")
    print("In another terminal run:")
    print(f"    ssh {username}@{HOST} -p {PORT}")
    print("Then, after each attempt:")
    print("    Enter      -> record a FAILED attempt (you saw 'Permission denied')")
    print("    s + Enter  -> record a SUCCESSFUL login")
    print("    u + Enter  -> change the username")
    print("    q + Enter  -> quit\n")

    failed = success = 0
    while True:
        choice = input(f"[{username}] attempt? ").strip().lower()
        if choice == "q":
            break
        if choice == "u":
            username = input("New username: ").strip() or username
            continue
        result = "success" if choice == "s" else "failed"
        ts = now_utc()
        append_row(path, {"timestamp_utc": ts, "username": username,
                          "result": result, "source_ip": "", "note": "manual"})
        if result == "failed":
            failed += 1
        else:
            success += 1
        print(f"   saved: {ts}  {username}  {result}")

    print(f"\nDone. {failed} failed + {success} successful attempts saved to {path}")


def auto_mode(path, username, count):
    count = min(count, MAX_AUTO_ATTEMPTS)
    cmd = [
        "ssh", "-p", PORT,
        "-o", "PreferredAuthentications=password",
        "-o", "PubkeyAuthentication=no",
        "-o", "NumberOfPasswordPrompts=1",       # one password = one attempt
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "ConnectTimeout=15",
        f"{username}@{HOST}",
        "exit",                                 # if login works, leave at once
    ]
    print(f"\nAuto mode: {count} attempts as '{username}'. Type a WRONG password each time.\n")

    failed = 0
    for i in range(1, count + 1):
        print(f"--- Attempt {i}/{count}: type a password and press Enter ---")
        ts = now_utc()
        try:
            proc = subprocess.run(cmd, stderr=subprocess.PIPE, text=True)
        except FileNotFoundError:
            sys.exit("ssh was not found. Install OpenSSH or use manual mode.")
        err = proc.stderr or ""

        if proc.returncode == 0:
            result, note = "success", "login accepted"
        elif "Permission denied" in err:
            result, note = "failed", "Permission denied"
            failed += 1
        else:
            # network problem, timeout, etc. - not a login attempt
            last_line = err.strip().splitlines()[-1] if err.strip() else "unknown error"
            result, note = "error", last_line[:120]

        append_row(path, {"timestamp_utc": ts, "username": username,
                          "result": result, "source_ip": "", "note": note})
        print(f"   saved: {ts}  {username}  {result}  ({note})")
        time.sleep(1)  # small pause between attempts

    print(f"\nDone. {failed} failed attempts saved to {path}")


def main():
    parser = argparse.ArgumentParser(description="Record SSH login attempts on the Bandit lab.")
    parser.add_argument("--out", default="bandit_attempts.csv", help="CSV file to append to")
    parser.add_argument("--user", default="bandit1", help="username to try (default: bandit1)")
    parser.add_argument("--auto", action="store_true", help="let the script run ssh for you")
    parser.add_argument("--count", type=int, default=12, help="attempts in auto mode (max 20)")
    args = parser.parse_args()

    if args.auto:
        auto_mode(args.out, args.user, args.count)
    else:
        manual_mode(args.out, args.user)


if __name__ == "__main__":
    main()
