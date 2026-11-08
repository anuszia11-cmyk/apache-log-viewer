<!--
  Paste everything below this comment at the END of your existing README.md.
  Then use Find & Replace (Ctrl+H in VS Code):
    USERNAME -> your GitHub username   (e.g. anaszia)
    REPO     -> your repository name   (e.g. woodcraft-log-monitor)
  Check the "Project structure" table against your real file names and fix any that differ.
  Delete this comment block when you're done.
-->

## Live demo

| Page | Link |
|---|---|
| Log viewer | https://USERNAME.github.io/REPO/ |
| Current alerts | https://USERNAME.github.io/REPO/alerts.html |
| Incident response runbook | [runbook.md](runbook.md) (web version: https://USERNAME.github.io/REPO/runbook.html) |

## Project structure

| File | What it is |
|---|---|
| `index.html` | Log viewer that shows entries from `logs.json` in a table |
| `alerts.html` | Alerts page that shows the entries `detect.py` flagged, read from `alerts.json` |
| `logs.json` | Sample Apache access-log entries (Task 1) |
| `attack_logs.json` | Simulated failed-login entries made from the OverTheWire Bandit lab (Task 3) |
| `detect.py` | Detection script with two rules: 404 bursts and repeated failed logins (Task 2) |
| `alerts.json` | Output of `detect.py`, the data shown on the Alerts page |
| `runbook.md` | What staff should do when an alert appears |

## Updating the alerts on the site

```bash
python detect.py                 # re-scan the logs and rewrite alerts.json
git add alerts.json
git commit -m "Update alerts"
git push
```

GitHub Pages republishes the site automatically, usually within a minute or two. Then click **Reload** on the Alerts page.

To preview the site on your own computer first:

```bash
python -m http.server 8000
# then open http://localhost:8000 in a browser
```

## Hand-over note for WoodCraft Furniture

This repository contains a lightweight, self-hosted log monitoring toolkit for the WoodCraft internal web portal. The **log viewer** shows recent web-server requests. The **detection script** (`detect.py`) flags two common attack patterns: a burst of 404 errors from one IP within five minutes, which usually means someone is scanning for hidden pages, and repeated failed logins, which usually means password guessing. Flagged entries appear on the **Alerts** page. When an alert appears, staff should follow the **incident response runbook** (`runbook.md`), which covers detection, triage, evidence collection, mitigation and communication. Before going live, please fill in the contact table at the top of the runbook. Everything runs on Python 3 and a web browser, so no database or paid service is needed.

## Limitations and recommended next steps

- **The demo uses sample and simulated data.** It does not read the live server log. For real use, point `detect.py` at the portal's Apache log and run it on a schedule (for example, every 15 minutes with `cron`).
- **Don't publish real logs on a public site.** GitHub Pages sites are public, and real logs contain customer IP addresses and page activity. For production, host the viewer on an internal server or behind a login.
- **Alerts update only when `detect.py` runs.** A future version could email the administrator when new alerts appear.
- **Extra protection worth adding:** fail2ban (blocks IPs automatically after repeated failures), multi-factor login for admin accounts, and regular software updates.
