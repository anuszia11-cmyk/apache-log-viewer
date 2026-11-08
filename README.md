# WoodCraft Log Monitoring and Incident Detection

A lightweight, self-hosted log monitoring toolkit for WoodCraft Furniture's internal web portal. It includes a log viewer, a Python detection script with two rule-based alerts, simulated attack logs from a free lab, an alerts page, and an incident response runbook. Everything runs on Python 3 and a web browser: no database, server software or paid service is needed.

## Live demo

| Page | Link |
|---|---|
| Log viewer | https://anuszia11-cmyk.github.io/apache-log-viewer/ |
| Current alerts | https://anuszia11-cmyk.github.io/apache-log-viewer/alerts.html |
| Incident response runbook | [runbook.md](runbook.md) (web version: https://anuszia11-cmyk.github.io/apache-log-viewer/runbook.html) |

## Project structure

| File | What it is |
|---|---|
| `index.html` | Log viewer that shows the first 10 entries of `logs.json` in a table |
| `alerts.html` | Alerts page that shows every entry `detect.py` flagged, read from `alerts.json` |
| `logs.json` | 25 sample Apache access-log entries |
| `detect.py` | Detection script with two rules: 404 bursts (R1) and repeated failed logins (R2) |
| `alerts.json` | Output of `detect.py`, the data shown on the Alerts page |
| `record_attempts.py` | Records the time, username and result of each SSH login attempt on the Bandit lab |
| `bandit_attempts.csv` | The recorded Bandit login attempts |
| `generate_attack_logs.py` | Turns `bandit_attempts.csv` into `attack_logs.json` |
| `attack_logs.json` | Simulated SSH attack logs in the same format as `logs.json` |
| `runbook.md` | What staff should do when an alert appears |

## Log viewer

`index.html` loads `logs.json` with `fetch()` and shows the first 10 entries, with columns for IP, timestamp, request, status and size. It works on GitHub Pages and on a local test server:

```bash
python -m http.server 8000
# then open http://localhost:8000 in a browser
```

## Threat detection (`detect.py`)

`detect.py` scans the logs and flags suspicious activity with two rule-based alerts. It needs only Python 3.8+ and no extra packages.

### How to run

```bash
python detect.py                    # scans logs.json (+ attack_logs.json if present), writes alerts.json
python detect.py attack_logs.json   # scan one specific file
```

### Detection rules

| ID | Rule | Triggers when | Severity |
|----|------|---------------|----------|
| R1 | 404 burst | one IP gets 3+ `404 Not Found` responses within 5 minutes | Medium |
| R2 | Repeated failed logins | one IP has 5+ failed logins within 10 minutes (401/403 on a login URL, or an SSH `Failed password` / `Invalid user` message) | High |

The thresholds are in the settings block at the top of `detect.py` and can be tuned.

### Output

- **Console:** one line per alert plus a total, e.g. `10 suspicious entries found (2 alert(s))`.
- **alerts.json:** a list of every flagged log entry. Each entry keeps its original fields and adds `alert_rule`, `alert_severity`, `alert_reason` and `source_file`.

### Results on the sample logs

Running on `logs.json` raises 2 alerts:

- **R1:** `198.51.100.23` requested 5 pages that don't exist (`/admin`, `/.env`, `/backup.zip` …) in 79 seconds
- **R2:** `203.0.113.45` made 5 failed logins in 39 seconds

The sample also contains activity that should **not** trigger, to show that the rules avoid false alarms: a staff member mistyping their password once, a single broken link, and an IP whose four 404s are spread over 18 minutes.

### Limitations

- Many web apps answer a wrong password with `200 OK` and an error message, which an access log can't tell apart from a success. R2 relies on the server returning 401/403.
- If the portal sits behind a proxy, every request may show the proxy's IP. The real client IP would need to be logged.

## Simulated attack logs

To prove the detection rules work on realistic data, I generated a second log file, `attack_logs.json`, from real SSH login attempts on the free [OverTheWire Bandit](https://overthewire.org/wargames/bandit/) lab (`bandit.labs.overthewire.org`, port 2220).

### How the attack logs were generated

1. **Made the attempts.** I connected with `ssh bandit1@bandit.labs.overthewire.org -p 2220` and typed wrong passwords on purpose. Each one returned `Permission denied`.
2. **Recorded each attempt.** `record_attempts.py` saved the UTC time, the username and the result (failed or success) of every attempt to `bandit_attempts.csv`.
3. **Converted to log format.** `generate_attack_logs.py` turned each CSV row into a JSON log entry with the same fields as `logs.json` (`ip`, `timestamp`, `request`, `status`, `size`), plus an `sshd`-style `message` like the lines in a Linux `/var/log/auth.log`, for example `sshd[7706]: Failed password for bandit1 from 203.0.113.45 port 64634 ssh2`.
4. **Validated detection.** Ran `python detect.py attack_logs.json` to check that rule R2 flags the attack.

```bash
python record_attempts.py            # record attempts while using ssh in another terminal
python generate_attack_logs.py       # bandit_attempts.csv -> attack_logs.json
python detect.py attack_logs.json    # check that alerts are produced
python detect.py                     # scan logs.json + attack_logs.json together -> alerts.json
```

**Why simulated IPs?** The Bandit server doesn't share its own logs, and a real home IP shouldn't be published in a public repo. The source IPs come from the documentation-only ranges `203.0.113.0/24` and `198.51.100.0/24` (RFC 5737), which never belong to a real machine. Timestamps and usernames are the real values from my attempts.

<!-- TODO: paste the console output of `python detect.py attack_logs.json` here after recording at least 10 failed attempts -->

## Incident response

When an alert appears, staff follow [runbook.md](runbook.md). It covers five steps (detection, triage, evidence collection, mitigation and communication) plus a lessons-learned review, with a severity table, ready-to-use server commands and an incident log template.

### Updating the alerts on the site

```bash
python detect.py                 # re-scan the logs and rewrite alerts.json
git add alerts.json
git commit -m "Update alerts"
git push
```

Without Git, upload the new `alerts.json` on GitHub with **Add file → Upload files**. GitHub Pages republishes the site automatically within a minute or two. Then click **Reload** on the Alerts page.

## Hand-over note for WoodCraft Furniture

This repository contains a lightweight, self-hosted log monitoring toolkit for the WoodCraft internal web portal. The **log viewer** shows recent web-server requests. The **detection script** (`detect.py`) flags two common attack patterns: a burst of 404 errors from one IP, which usually means someone is scanning for hidden pages, and repeated failed logins, which usually means password guessing. Flagged entries appear on the **Alerts** page. When an alert appears, staff should follow the **incident response runbook** (`runbook.md`), which covers detection, triage, evidence collection, mitigation and communication. Before going live, please fill in the contact table at the top of the runbook.

## Limitations and recommended next steps

- **The demo uses sample and simulated data.** It does not read the live server log. For real use, point `detect.py` at the portal's Apache log and run it on a schedule (for example, every 15 minutes with `cron`).
- **Don't publish real logs on a public site.** GitHub Pages sites are public, and real logs contain customer IP addresses and page activity. For production, host the viewer on an internal server or behind a login.
- **Alerts update only when `detect.py` runs.** A future version could email the administrator when new alerts appear.
- **Extra protection worth adding:** fail2ban (blocks IPs automatically after repeated failures), multi-factor login for admin accounts, and regular software updates.
