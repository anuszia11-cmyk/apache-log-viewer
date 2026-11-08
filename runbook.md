# WoodCraft Furniture: Incident Response Runbook

**Applies to:** the WoodCraft internal web portal and the log monitor in this repository
**Owner:** Portal administrator · **Version:** 1.0 · **Last reviewed:** November 2026

Use this runbook whenever `detect.py` raises an alert, or whenever someone reports something odd on the portal. Work through the steps in order, and record what you do in the [incident log](#incident-log-template) at the bottom.

> **Golden rules**
> 1. **Don't delete anything.** Logs are evidence.
> 2. **Write it down.** Note what you saw, what you did, and when. Record all times in UTC.
> 3. **Escalate early.** If you aren't sure whether something is serious, treat it as serious and tell the Incident Lead.

## Quick reference

| Step | What you do | Target time |
|---|---|---|
| 1. Detection | See the alert, open an incident record | As soon as it appears |
| 2. Triage | Decide whether it's real and how serious it is | 15 minutes |
| 3. Evidence | Copy the logs and fingerprint them *before* changing anything | 15 minutes |
| 4. Mitigation | Block, reset, fix, then monitor | Depends on severity |
| 5. Communication | Tell the right people the facts | See the table in step 5 |
| 6. Review | Write down lessons learned and update this runbook | Within 1 week |

## Roles and contacts

Fill these in before you need them. Entries marked "to be confirmed" must be replaced with real names and contact details by WoodCraft before go-live.

| Role | Responsibility | Name | Phone / email |
|---|---|---|---|
| Incident Lead | Owns the incident and makes containment decisions | WoodCraft IT Manager (to be confirmed) | it@woodcraft-furniture.example |
| Portal administrator | Has server access, blocks IPs, resets accounts | Anas Zia (Ezitech intern, during the demo) | anuszia11@gmail.com |
| Management contact | Approves any message to customers or authorities | WoodCraft Operations Manager (to be confirmed) | management@woodcraft-furniture.example |
| Hosting provider | Network-level blocking, server snapshots | Hosting provider support (to be confirmed) | support@hosting-provider.example |

## Severity levels

| Level | Meaning | Example | Respond within |
|---|---|---|---|
| **Low** | Noise or a one-off, with no sign of access | A few 404s from a search-engine crawler | Next working day |
| **Medium** | A clear attack attempt, but nothing got in | A 404 scan or failed password guessing from one IP | 4 hours |
| **High** | The attack is still running, or an account may be compromised | A successful login right after many failures from the same IP | 1 hour |
| **Critical** | Confirmed break-in, exposed data, or the portal is down | An attacker using an admin account, or customer data accessed | Immediately |

---

## 1. Detection

**How alerts reach you**

1. `detect.py` reads the logs (`logs.json`, plus `attack_logs.json` if present) and checks them against two rules:

   | Rule | What it looks for | Alert severity | What it usually means |
   |---|---|---|---|
   | **R1_404_BURST** | 3 or more `404 Not Found` responses for one IP within 5 minutes | Medium | Someone is scanning for hidden pages, old admin panels or backup files |
   | **R2_REPEATED_FAILED_LOGIN** | 5 or more failed logins from one IP within 10 minutes (`401`/`403` on a login URL, or SSH `Failed password` / `Invalid user`) | High | Password guessing (brute force) or reused stolen passwords (credential stuffing) |

   The alert severity is a starting point. Triage (step 2) decides the real severity of the incident.

2. It writes every flagged log entry to `alerts.json`, with the rule, severity and reason attached.
3. The **Alerts** page (`alerts.html`) on the demo site shows those matches in a table.

**To check for new alerts by hand**

```bash
python detect.py
```

Then refresh the Alerts page.

**Open an incident record** as soon as you see an alert. Copy the [incident log template](#incident-log-template), give it an ID such as `INC-2026-11-08-01`, and write down the time you noticed it.

## 2. Triage

**Goal:** decide in 15 minutes or less whether the alert is real and how serious it is.

Answer these questions and write the answers in the incident log:

- [ ] **Who?** Which IP address or addresses? Do you recognise them (office, staff VPN, our own monitoring)?
- [ ] **What?** Which rule fired? Which pages or usernames were targeted?
- [ ] **When?** When did it start? Is it still going on? Check the newest log lines.
- [ ] **How much?** How many requests or attempts? From one IP or from many?
- [ ] **Did it work?** Look for a successful login (`200` or a redirect on the login page) *after* the failures, or a `200` on a page the scanner was probing for.

**Quick look-ups on the server** (replace the example IP with the real one):

```bash
grep "203.0.113.45" /var/log/apache2/access.log | tail -n 50          # latest activity from this IP
grep "203.0.113.45" /var/log/apache2/access.log | grep -c '" 404 '    # how many 404s
grep "203.0.113.45" /var/log/apache2/access.log | grep "POST /login"  # login attempts and their status codes
sudo grep "Failed password" /var/log/auth.log | tail -n 20            # recent failed SSH logins
```

Outside checks that need no login: look the IP up on **AbuseIPDB** to see whether others have reported it, and run a **WHOIS** lookup to see which network and country it belongs to.

**Decide**

| What you found | Classify as | Next step |
|---|---|---|
| A known IP with an innocent explanation (a broken link, a staff member who forgot their password) | False positive | Record it, close the incident, and consider tuning the rule |
| An outside IP, all attempts failed, and the attack has stopped | **Medium** | Evidence → block the IP → tell the Incident Lead |
| The attack is still running, or there's a success after the failures | **High** | Collect evidence quickly → contain now → escalate |
| Signs of data access, changed files or an attacker inside | **Critical** | Call the Incident Lead now, follow every step, and consider outside help |

## 3. Evidence collection

**Goal:** keep an untouched copy of what happened *before* you change anything. Blocking, resetting and restarting all change the system and can destroy clues.

**Do**

1. Make an evidence folder named after the incident, then **copy** (never move) the logs into it:

   ```bash
   INC=INC-2026-11-08-01
   mkdir -p ~/evidence/$INC
   sudo cp /var/log/apache2/access.log /var/log/apache2/error.log ~/evidence/$INC/
   sudo cp /var/log/auth.log ~/evidence/$INC/      # SSH login attempts
   cp alerts.json ~/evidence/$INC/
   ```

2. Record a fingerprint (hash) of each file, so you can prove later that nothing was changed:

   ```bash
   cd ~/evidence/$INC && sha256sum * > SHA256SUMS.txt
   ```

3. Take a screenshot of the Alerts page.
4. In the incident log, note who collected the evidence, when, and where it's stored.

**Don't**

- Edit, "clean up" or rotate log files during an incident.
- Restart or wipe the server before the evidence is copied, unless the Incident Lead decides the ongoing damage is worse.
- Log in to an account you suspect is compromised "to have a look".

## 4. Mitigation

Work in this order: **contain → remove → recover**.

**Contain: stop the attack from continuing**

| Situation | Action |
|---|---|
| One IP is scanning or guessing passwords | Block it at the firewall: `sudo ufw deny from 203.0.113.45` |
| Many IPs are involved | Enable rate limiting or **fail2ban** on the login page and SSH, and ask the hosting provider to filter traffic |
| An account was targeted but no login succeeded | Check that it has a strong, unique password, and turn on lockout after repeated failures |
| An account may be compromised | Reset its password, end its active sessions, and review what it did |
| The server may be compromised | Put up a maintenance page, take the portal offline and contact the hosting provider |

To undo a block later: `sudo ufw delete deny from 203.0.113.45`

**Remove: get rid of the cause**

- Delete any account, file or scheduled task the attacker created.
- Remove or protect anything the scanner found: old admin pages, test pages, and backup files such as `.zip`, `.bak` or `.sql`.
- Install pending security updates for the web server, the portal software and plugins.

**Recover: return to normal and keep watching**

- Bring the portal back online once the cause has been fixed.
- Run `detect.py` more often for the next 48 hours, and confirm that the blocked IP has not returned under a new address pattern.

## 5. Communication

**Who to tell, and when**

| Severity | Tell | When |
|---|---|---|
| Low | Nobody. Note it in the incident log | — |
| Medium | Incident Lead | Same day |
| High | Incident Lead and management | Within 1 hour |
| Critical | Incident Lead, management and the hosting provider | Immediately |

**Rules**

- Stick to facts. Don't guess who is behind it or why.
- If email or the portal itself may be compromised, use the phone.
- Only one person speaks to anyone outside the company, and management approves the message.
- If customer personal data (names, addresses, phone numbers, payment details) may have been exposed, management must check whether the law requires telling customers or the authorities, and by when.

**Internal update template**

```text
Subject: [INCIDENT INC-2026-11-08-01] Medium – password-guessing attempts on portal login

What happened: Between 10:02 and 10:09 UTC on 8 Nov, IP 203.0.113.45 made 37 failed
               login attempts on the portal login page.
Impact:        No successful logins. No customer data affected as far as we know.
What we did:   Evidence saved at 10:15. IP blocked at the firewall at 10:20.
Next steps:    Watching the logs closely for 48 hours. Next update by 15:00 UTC.
Contact:       <name>, <phone>
```

## 6. Review (lessons learned)

Within a week of closing a Medium or higher incident, hold a short meeting and agree on:

- the timeline: what happened, and when we noticed;
- what worked and what slowed us down;
- what to change: detection thresholds, passwords, server settings, or this runbook.

Then update this runbook and increase its version number.

---

## Incident log template

```text
Incident ID:
Opened by / time (UTC):
Rule that fired:
Source IP(s):
Target (page / username):
Severity:            Low / Medium / High / Critical
Timeline (UTC):
  HH:MM  ...
  HH:MM  ...
Evidence saved at:
Actions taken:
People notified:
Closed by / time (UTC):
Lessons learned:
```
