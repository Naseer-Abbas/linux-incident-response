# Linux Incident Response Script

A Bash script for the first minutes of a suspected compromise on a Linux host. It collects evidence in order of volatility, hashes it, checks for common indicators of compromise and produces an HTML report. Containment is optional and off by default.

## Why the order matters

Killing processes or cutting the network first destroys evidence (memory, open connections, running programs). This script follows the DFIR order of operations:

1. **Collect** volatile evidence first, then less volatile evidence
2. **Hash** every evidence file with SHA-256
3. **Analyse** for indicators of compromise
4. **Contain**, only if the responder asks, and only after evidence is saved
5. **Report** everything in a self-contained HTML file

## What it collects

| Volatile | Non-volatile |
|---|---|
| System time (UTC and local), uptime | Login history (`last`) |
| Network connections, interfaces, routes, ARP table | Accounts with UID 0 |
| Process tree with start times | Cron jobs and systemd timers |
| Running programs deleted from disk | SSH `authorized_keys` files |
| Logged-in users, kernel modules | Files modified in the last 24 hours, recent auth log |

Each file records the exact command and UTC collection time.

## What it detects

- Connections to IPs on the [abuse.ch Feodo Tracker](https://feodotracker.abuse.ch/) botnet C2 blocklist (exact address matching)
- Processes with suspicious names (e.g. `xmrig`, `mimikatz`) or running from `/tmp`, `/dev/shm` or `/var/tmp`
- Running programs whose file has been deleted from disk
- Extra accounts with UID 0
- Recent remote logins by privileged accounts, listed for review rather than treated as proof

## Containment (only with `--contain`)

- Keeps the responder's IP reachable first (taken from the SSH session or `--mgmt-ip`)
- Blocks traffic to and from malicious IPs
- **Suspends** suspicious processes with `SIGSTOP` instead of killing them, so memory can still be acquired; `kill -CONT <pid>` resumes them
- Locks only the accounts the responder names with `--lock-user`
- Full network isolation with `--isolate-network`, refused without a management IP so the responder is never locked out
- Asks for confirmation (type `YES`) unless `--yes` is given

## Usage

```bash
chmod +x incident_response.sh

sudo ./incident_response.sh                        # dry run: collect, analyse, report
sudo ./incident_response.sh --no-feed              # offline (skip the threat feed)
sudo ./incident_response.sh --contain              # collect, then contain
sudo ./incident_response.sh --contain --isolate-network --mgmt-ip 10.0.0.5
sudo ./incident_response.sh --contain --lock-user bob
```

## Output

```
/var/tmp/IR-<host>-<UTC time>/
├── evidence/          # one text file per command
│   └── SHA256SUMS     # hashes of all evidence files
├── actions.log        # every containment action (or planned action in a dry run)
├── case.log           # timestamped log of the whole run
├── report.html        # the report
└── report.sha256
```

All command output shown in the report is HTML-escaped, so attacker-controlled text such as process names cannot run as script when the report is opened.

## Requirements

Linux, Bash 4+, root. Uses standard tools: `ss` (or `netstat`), `ip`, `ps`, `last`, `iptables`, `flock`, `sha256sum`, and `curl` (plus `jq`, optional) for the threat feed.

## Limitations

- Name- and path-based process checks catch only unsophisticated malware; rootkits can hide from every tool run on the compromised host itself.
- It does not capture memory. Use a dedicated tool such as LiME or AVML before rebooting.
- Writes its output to the same disk it is investigating; for serious cases, collect to external or network storage.
- IPv4 only.

This project was built for learning. Test it in a lab VM before using it on a real system.
