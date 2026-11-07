## Threat detection (`detect.py`)

`detect.py` scans the server log and flags suspicious activity using two rule-based alerts. It needs only Python 3.8+ (no extra packages).

### How to run

```bash
python detect.py                    # scans logs.json, writes alerts.json
python detect.py attack_logs.json   # scan a different log file
```

### Detection rules

| ID | Rule | Triggers when | Severity |
|----|------|---------------|----------|
| R1 | 404 scan | one IP gets 4+ `404 Not Found` responses within 5 minutes | Medium |
| R2 | Brute-force login | one IP has 3+ failed logins (401/403 on a login URL, or a "Failed password" message) within 10 minutes | High |

The thresholds are in the `SETTINGS` block at the top of `detect.py` and can be tuned.

### Output

- **Console**: one line per alert plus a total, e.g. `10 suspicious entries found in 2 alert(s)`.
- **alerts.json**: a list of alerts. Each alert has the rule, severity, IP, first/last time seen, a description, and the log lines that triggered it.

### Results on the sample logs

Running on `logs.json` raises 2 alerts:

- **R2** — `203.0.113.45` made 5 failed logins in 39 seconds
- **R1** — `198.51.100.23` requested 5 pages that don't exist (`/admin`, `/.env`, `/backup.zip` …) in 79 seconds

The sample also contains activity that should **not** trigger, to show the rules avoid false alarms: a staff member mistyping their password once, a single broken link, and an IP whose four 404s are spread over 18 minutes.

### Limitations

- Many web apps answer a wrong password with `200 OK` and an error message, which an access log can't tell apart from success. R2 relies on the server returning 401/403.
- If the portal sits behind a proxy, every request may show the proxy's IP; the real client IP would need to be logged.


## Simulated attack logs (Task 3)

To prove the detection rules work on realistic data, I generated a second log file,
`attack_logs.json`, from real failed SSH login attempts on the free
[OverTheWire Bandit](https://overthewire.org/wargames/bandit/) lab
(`bandit.labs.overthewire.org`, port 2220).

### How the attack logs were generated

1. **Made the attempts.** I connected with `ssh bandit1@bandit.labs.overthewire.org -p 2220`
   and typed wrong passwords on purpose (plus a few tries with a username that does not exist, `admin`).
   Each wrong password returned `Permission denied`. I finished with one correct login as
   `bandit0` (password `bandit0`) to have a normal, successful login in the data too.
2. **Recorded each attempt.** `record_attempts.py` saved the UTC time, the username and the
   result (failed / success) of every attempt to `bandit_attempts.csv`.
3. **Converted to log format.** `generate_attack_logs.py` turned each CSV row into a JSON log
   entry with the same fields as `logs.json` (`ip`, `timestamp`, `request`, `status`, `size`),
   plus an `sshd`-style `message` like the lines in a Linux `/var/log/auth.log`:
   `sshd[7706]: Failed password for bandit1 from 203.0.113.45 port 64634 ssh2`
4. **Validated detection.** Ran `python detect.py attack_logs.json`. Rule R2
   (≥ 5 failed logins from one IP within 10 minutes) flagged the attack.

```bash
python record_attempts.py            # record attempts while using ssh in another terminal
python generate_attack_logs.py       # bandit_attempts.csv -> attack_logs.json
python detect.py attack_logs.json    # check that alerts are produced
python detect.py                     # scan logs.json + attack_logs.json together -> alerts.json
```

### Field mapping

| Field      | Failed attempt                          | Successful login                     |
|------------|-----------------------------------------|--------------------------------------|
| `ip`       | `203.0.113.45` (simulated attacker)     | `198.51.100.10` (simulated staff PC) |
| `status`   | `401` (rejected)                        | `200` (accepted)                     |
| `event`    | `failed_login`                          | `login_success`                      |
| `message`  | `Failed password for <user> from <ip>…` | `Accepted password for <user> …`     |

**Why simulated IPs?** The Bandit server does not share its own logs, and a real home IP should
not be published in a public repo. The source IPs come from the documentation-only ranges
`203.0.113.0/24` and `198.51.100.0/24` (RFC 5737), which never belong to a real machine.
Timestamps and usernames are the real values from my attempts.

### Result

<!-- Replace with YOUR console output after running detect.py -->
```
Loaded  13 entries from attack_logs.json

[R2_REPEATED_FAILED_LOGIN] 203.0.113.45: 12 failed logins, 16:20:05 -> 16:26:17 UTC, users: admin, bandit1

12 suspicious entries found (1 alert(s)). Saved to alerts.json
```

The successful `bandit0` login was **not** flagged, so the rule catches the attack without
raising a false alarm on normal use.

> Lab etiquette: Bandit is a shared, free server. All attempts were typed by hand (about a dozen);
> no brute-force tool was pointed at it.

---

<!-- Short note for the Ezitech portal submission (Task 3) -->

**What I did and why (Task 3):**
I made 12 failed SSH login attempts on the OverTheWire Bandit lab and recorded the time,
username and result of each one. A Python script converted these records into
`attack_logs.json`, using the same fields as `logs.json` plus an sshd-style message, with
documentation-range IPs instead of real ones for privacy. I updated `detect.py` so it accepts
a file name and recognises SSH "Failed password" lines as well as web `/login` failures.
Running it on the new file flagged the brute-force pattern from `203.0.113.45` and did not flag
the normal successful login, which shows the rule works on realistic attack data.
