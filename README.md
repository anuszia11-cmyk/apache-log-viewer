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
