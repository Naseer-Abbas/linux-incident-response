#!/usr/bin/env bash

# Incident Response Collection and Containment Script
# Collects volatile evidence first, hashes it, looks for indicators of
# compromise, and only then (if asked) contains the system.
# Default is a dry run: evidence is collected but nothing on the system is changed.

# Default settings
THREAT_FEED="https://feodotracker.abuse.ch/downloads/ipblocklist.json"
USE_FEED=1
CONTAIN=0               # 1 = apply containment actions (--contain)
ISOLATE_NETWORK=0       # 1 = drop all traffic except the management IP (--isolate-network)
ASSUME_YES=0            # 1 = skip the confirmation prompt (--yes)
MGMT_IP=""              # responder IP that must stay reachable
LOCK_USERS=()           # accounts to lock, chosen by the responder (--lock-user)
OUTPUT_BASE="/var/tmp"
SUSPICIOUS_KEYWORDS=("malware" "backdoor" "ransomware" "exploit" "xmrig" "mimikatz")
SUSPICIOUS_PATHS=("/tmp/" "/dev/shm/" "/var/tmp/")
CRITICAL_USERS=("root" "admin")
LOCK_FILE="/run/incident_response.lock"

# Results filled in during the run
MALICIOUS_IPS=()
SUSPICIOUS_PROCS=()     # "pid|user|reason|command"
DELETED_BINARIES=()
EXTRA_UID0=()
REMOTE_ADMIN_LOGINS=()
FEED_STATUS="not checked"

usage() {
    cat <<EOF
Usage: sudo $0 [options]

By default this is a dry run: evidence is collected and analysed, nothing is changed.

  --contain            Apply containment: block malicious IPs, suspend suspicious processes,
                       lock accounts given with --lock-user
  --isolate-network    With --contain, drop all traffic except the management IP
  --mgmt-ip IP         Responder IP to keep reachable (default: taken from your SSH session)
  --lock-user USER     Lock this account during containment (repeatable)
  --no-feed            Do not download the threat intelligence feed
  --feed URL           Use a different JSON IP blocklist
  --output DIR         Where to create the case folder (default: $OUTPUT_BASE)
  --yes                Do not ask for confirmation before containment
  -h, --help           Show this help
EOF
}

# Timestamped status line, also kept in the case log
log() {
    local msg
    msg="$(date -u '+%F %T') UTC  $*"
    echo "$msg"
    [[ -n "${CASE_DIR:-}" ]] && echo "$msg" >> "${CASE_DIR}/case.log"
}

# Record a containment action (or what would have been done in a dry run)
action() {
    log "ACTION: $*"
    echo "$(date -u '+%F %T') UTC  $*" >> "${CASE_DIR}/actions.log"
}

# Run a command and save its output as an evidence file with a header
collect() {
    local name=$1
    shift
    local file="${EVIDENCE_DIR}/${name}.txt"
    {
        echo "# Command:   $*"
        echo "# Collected: $(date -u '+%F %T') UTC on $(hostname)"
        echo
        "$@" 2>&1
    } > "$file"
    log "Collected ${name}"
}

# Escape text so it is shown, never run, inside the HTML report
html_escape() {
    sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g' -e "s/'/\&#39;/g"
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --contain)          CONTAIN=1 ;;
            --isolate-network)  ISOLATE_NETWORK=1 ;;
            --mgmt-ip)          MGMT_IP=${2:?--mgmt-ip needs an IP}; shift ;;
            --lock-user)        LOCK_USERS+=("${2:?--lock-user needs a username}"); shift ;;
            --no-feed)          USE_FEED=0 ;;
            --feed)             THREAT_FEED=${2:?--feed needs a URL}; shift ;;
            --output)           OUTPUT_BASE=${2:?--output needs a folder}; shift ;;
            --yes)              ASSUME_YES=1 ;;
            -h|--help)          usage; exit 0 ;;
            *)                  echo "Unknown option: $1"; usage; exit 1 ;;
        esac
        shift
    done
    if (( ISOLATE_NETWORK && ! CONTAIN )); then
        echo "--isolate-network only works together with --contain"
        exit 1
    fi
}

# Root check, single-instance lock and case folder
preflight() {
    if (( EUID != 0 )); then
        echo "Run as root (sudo): evidence collection needs full access to processes and logs."
        exit 1
    fi

    # flock releases the lock automatically if the script dies, so no stale lock files
    exec 9> "$LOCK_FILE"
    if ! flock -n 9; then
        echo "Another instance is already running."
        exit 1
    fi

    # Keep the responder's SSH session reachable during isolation
    if [[ -z "$MGMT_IP" && -n "${SSH_CLIENT:-}" ]]; then
        MGMT_IP=${SSH_CLIENT%% *}
    fi

    CASE_ID="IR-$(hostname)-$(date -u '+%Y%m%dT%H%M%SZ')"
    CASE_DIR="${OUTPUT_BASE}/${CASE_ID}"
    EVIDENCE_DIR="${CASE_DIR}/evidence"
    mkdir -p "$EVIDENCE_DIR" || { echo "Cannot create $CASE_DIR"; exit 1; }
    chmod 700 "$CASE_DIR"

    log "Case ${CASE_ID} started by ${SUDO_USER:-root} (mode: $( (( CONTAIN )) && echo CONTAIN || echo DRY-RUN ))"
}

# Step 1: collect evidence, most volatile first (order of volatility)
collect_evidence() {
    log "Collecting volatile evidence..."
    collect 01_system_time      bash -c 'echo "UTC:   $(date -u)"; echo "Local: $(date)"; uptime'
    collect 02_system_info      uname -a

    if command -v ss &>/dev/null; then
        collect 03_network_connections ss -tunap
    else
        collect 03_network_connections netstat -tunap
    fi
    collect 04_network_interfaces ip addr
    collect 05_routes            ip route
    collect 06_arp_neighbours    ip neigh
    collect 07_processes         ps -eo pid,ppid,user,lstart,etime,args --forest
    collect 08_deleted_binaries  bash -c 'ls -l /proc/[0-9]*/exe 2>/dev/null | grep "(deleted)"'
    collect 09_logged_in_users   w
    collect 10_kernel_modules    lsmod

    log "Collecting non-volatile evidence..."
    collect 11_login_history     last -n 30 -F
    collect 12_uid0_accounts     awk -F: '$3 == 0' /etc/passwd
    collect 13_cron_jobs         bash -c 'cat /etc/crontab 2>/dev/null; ls -la /etc/cron.* 2>/dev/null; for u in $(cut -d: -f1 /etc/passwd); do c=$(crontab -l -u "$u" 2>/dev/null) && echo "--- $u ---" && echo "$c"; done'
    collect 14_systemd_timers    systemctl list-timers --all --no-pager
    collect 15_ssh_authorized_keys bash -c 'for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do [ -f "$f" ] && ls -l "$f" && cat "$f" && echo; done'
    collect 16_recent_files      bash -c 'find / -xdev \( -path /proc -o -path /sys -o -path /dev -o -path /run \) -prune -o -type f -mmin -1440 -printf "%TY-%Tm-%Td %TH:%TM  %u  %p\n" 2>/dev/null | sort -r | head -n 300'

    if [[ -r /var/log/auth.log ]]; then
        collect 17_auth_log tail -n 300 /var/log/auth.log
    elif [[ -r /var/log/secure ]]; then
        collect 17_auth_log tail -n 300 /var/log/secure
    else
        collect 17_auth_log journalctl -n 300 --no-pager
    fi
}

# Step 2: hash the evidence so any later change can be detected
hash_evidence() {
    (cd "$EVIDENCE_DIR" && sha256sum ./*.txt > SHA256SUMS)
    log "Evidence hashed (evidence/SHA256SUMS)"
}

# Remote IPv4 addresses from current connections
remote_addresses() {
    if command -v ss &>/dev/null; then
        ss -tunH 2>/dev/null | awk '{print $6}'
    else
        netstat -tun 2>/dev/null | awk 'NR > 2 {print $5}'
    fi | sed -E 's/:[0-9]+$//' | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' | sort -u
}

# Step 3: look for indicators of compromise
detect_threats() {
    log "Analysing for indicators of compromise..."

    # Connections to known malicious IPs (exact matches against the feed)
    if (( USE_FEED )); then
        local feed_file="${CASE_DIR}/threat_feed.json" ip
        if curl -fsS --max-time 20 "$THREAT_FEED" -o "$feed_file" 2>/dev/null; then
            declare -A bad=()
            while read -r ip; do
                [[ -n "$ip" ]] && bad[$ip]=1
            done < <(if command -v jq &>/dev/null; then
                         jq -r '.[].ip_address // empty' "$feed_file" 2>/dev/null
                     else
                         grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' "$feed_file"
                     fi)
            FEED_STATUS="checked ${#bad[@]} IPs from $THREAT_FEED"
            while read -r ip; do
                [[ -n "${bad[$ip]:-}" ]] && MALICIOUS_IPS+=("$ip")
            done < <(remote_addresses)
        else
            FEED_STATUS="download failed ($THREAT_FEED), network check skipped"
        fi
    else
        FEED_STATUS="disabled (--no-feed)"
    fi
    log "Threat feed: $FEED_STATUS"

    # Processes with suspicious names or running from world-writable folders
    local pid user args keyword path reason
    while read -r pid user args; do
        [[ "$pid" == "$$" || "$args" == *"$0"* ]] && continue
        reason=""
        for keyword in "${SUSPICIOUS_KEYWORDS[@]}"; do
            [[ "${args,,}" == *"$keyword"* ]] && reason+="name contains '$keyword'; "
        done
        for path in "${SUSPICIOUS_PATHS[@]}"; do
            [[ "$args" == "$path"* ]] && reason+="runs from $path; "
        done
        reason=${reason%; }
        [[ -n "$reason" ]] && SUSPICIOUS_PROCS+=("${pid}|${user}|${reason}|${args}")
    done < <(ps -eo pid=,user=,args=)

    # Running programs whose file has been deleted from disk (common malware trick)
    mapfile -t DELETED_BINARIES < <(ls -l /proc/[0-9]*/exe 2>/dev/null | grep '(deleted)' | awk '{split($9, p, "/"); print "PID " p[3] ": " $11}')

    # Extra accounts with root privileges
    mapfile -t EXTRA_UID0 < <(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd)

    # Recent remote logins by privileged accounts: not proof of compromise, but worth reviewing
    local u
    for u in "${CRITICAL_USERS[@]}"; do
        while read -r line; do
            REMOTE_ADMIN_LOGINS+=("$line")
        done < <(last -n 20 -F "$u" 2>/dev/null | grep 'pts/' | head -n 5)
    done

    log "Found: ${#MALICIOUS_IPS[@]} malicious IP connection(s), ${#SUSPICIOUS_PROCS[@]} suspicious process(es), ${#DELETED_BINARIES[@]} deleted binary(ies), ${#EXTRA_UID0[@]} extra UID 0 account(s)"
}

# Step 4: containment (dry run unless --contain)
contain_system() {
    if (( ! CONTAIN )); then
        log "Dry run: no changes made. Planned actions are listed in the report."
        local entry ip u
        for ip in "${MALICIOUS_IPS[@]}"; do action "[dry run] would block $ip"; done
        for entry in "${SUSPICIOUS_PROCS[@]}"; do action "[dry run] would suspend PID ${entry%%|*}"; done
        for u in "${LOCK_USERS[@]}"; do action "[dry run] would lock account $u"; done
        (( ${#MALICIOUS_IPS[@]} + ${#SUSPICIOUS_PROCS[@]} + ${#LOCK_USERS[@]} == 0 )) && action "[dry run] nothing to contain"
        return
    fi

    if (( ! ASSUME_YES )); then
        echo
        echo "About to apply containment on $(hostname):"
        echo "  block ${#MALICIOUS_IPS[@]} IP(s), suspend ${#SUSPICIOUS_PROCS[@]} process(es), lock ${#LOCK_USERS[@]} account(s)"
        (( ISOLATE_NETWORK )) && echo "  and DROP ALL network traffic except ${MGMT_IP:-<no management IP>}"
        read -r -p "Type YES to continue: " answer
        [[ "$answer" == "YES" ]] || { log "Containment cancelled by responder"; CONTAIN=0; return; }
    fi

    local ip entry pid u

    # Network: always keep the responder reachable before any DROP rule
    if [[ -n "$MGMT_IP" ]]; then
        iptables -I INPUT 1 -s "$MGMT_IP" -j ACCEPT
        iptables -I OUTPUT 1 -d "$MGMT_IP" -j ACCEPT
        action "allowed management IP $MGMT_IP"
    fi
    for ip in "${MALICIOUS_IPS[@]}"; do
        iptables -I INPUT -s "$ip" -j DROP
        iptables -I OUTPUT -d "$ip" -j DROP
        action "blocked traffic to and from $ip"
    done
    if (( ISOLATE_NETWORK )); then
        if [[ -z "$MGMT_IP" ]]; then
            action "network isolation SKIPPED: no management IP (use --mgmt-ip), to avoid locking out the responder"
        else
            iptables -A INPUT -i lo -j ACCEPT
            iptables -A OUTPUT -o lo -j ACCEPT
            iptables -P INPUT DROP
            iptables -P OUTPUT DROP
            iptables -P FORWARD DROP
            action "isolated network: all traffic dropped except loopback and $MGMT_IP"
        fi
    fi

    # Processes: suspend instead of kill, so memory stays available for analysis
    for entry in "${SUSPICIOUS_PROCS[@]}"; do
        pid=${entry%%|*}
        if kill -STOP "$pid" 2>/dev/null; then
            action "suspended PID $pid (resume with: kill -CONT $pid)"
        else
            action "could not suspend PID $pid (already exited?)"
        fi
    done

    # Accounts: only those the responder chose
    for u in "${LOCK_USERS[@]}"; do
        if passwd -l "$u" &>/dev/null; then
            pkill -KILL -u "$u" 2>/dev/null
            action "locked account $u and ended its sessions"
        else
            action "could not lock account $u"
        fi
    done
}

# Print an evidence file as an escaped <pre> block (long files are truncated in the report only)
evidence_block() {
    local name=$1 title=$2 file="${EVIDENCE_DIR}/$1.txt" lines
    lines=$(wc -l < "$file")
    echo "<h3>${title}</h3>"
    echo "<pre>"
    head -n 200 "$file" | html_escape
    (( lines > 200 )) && echo "... ($((lines - 200)) more lines in evidence/${name}.txt)"
    echo "</pre>"
}

# Print a bash array as an escaped HTML list, or a "none" line
html_list() {
    local empty_text=$1 item
    shift
    if (( $# == 0 )); then
        echo "<p class='none'>${empty_text}</p>"
        return
    fi
    echo "<ul>"
    for item in "$@"; do
        echo "<li><code>$(printf '%s' "$item" | html_escape)</code></li>"
    done
    echo "</ul>"
}

# Step 5: HTML report
generate_report() {
    local report="${CASE_DIR}/report.html" mode_text mode_class procs=() entry
    if (( CONTAIN )); then
        mode_text="CONTAINMENT APPLIED"; mode_class="contain"
    else
        mode_text="DRY RUN - no changes made to the system"; mode_class="dryrun"
    fi
    for entry in "${SUSPICIOUS_PROCS[@]}"; do
        IFS='|' read -r pid user reason args <<< "$entry"
        procs+=("PID $pid ($user) - $reason: $args")
    done

    {
        cat <<HTML
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Incident Report ${CASE_ID}</title>
<style>
  body { font-family: Arial, sans-serif; margin: 20px; color: #222; }
  .container { max-width: 1100px; margin: 0 auto; }
  h1 { color: #b00020; margin-bottom: 4px; }
  h2 { color: #0b4f8a; border-bottom: 1px solid #ddd; padding-bottom: 6px; margin-top: 32px; }
  .status { padding: 12px 16px; border-radius: 6px; font-weight: bold; }
  .dryrun { background: #fff8e1; border: 1px solid #f0b400; }
  .contain { background: #ffebee; border: 1px solid #b00020; }
  table { border-collapse: collapse; width: 100%; }
  td, th { border: 1px solid #ddd; padding: 6px 8px; text-align: left; font-size: 14px; }
  pre { background: #f6f8fa; padding: 12px; border-radius: 4px; overflow-x: auto; max-height: 320px; font-size: 12px; }
  code { font-size: 13px; }
  .none { color: #2e7d32; }
  .footer { margin-top: 32px; color: #777; font-size: 13px; }
</style>
</head>
<body>
<div class="container">
<h1>Incident Response Report</h1>
<p>Case <b>${CASE_ID}</b> | Host <b>$(hostname | html_escape)</b> | Generated $(date -u '+%F %T') UTC by ${SUDO_USER:-root}</p>
<div class="status ${mode_class}">${mode_text}</div>

<h2>Findings</h2>
<p><b>Threat feed:</b> $(printf '%s' "$FEED_STATUS" | html_escape)</p>
<h3>Connections to known malicious IPs</h3>
$(html_list "None found" "${MALICIOUS_IPS[@]}")
<h3>Suspicious processes</h3>
$(html_list "None found" "${procs[@]}")
<h3>Running programs deleted from disk</h3>
$(html_list "None found" "${DELETED_BINARIES[@]}")
<h3>Extra accounts with UID 0</h3>
$(html_list "None found" "${EXTRA_UID0[@]}")
<h3>Recent remote logins by privileged accounts (review)</h3>
$(html_list "None found" "${REMOTE_ADMIN_LOGINS[@]}")

<h2>Actions</h2>
<pre>$(html_escape < "${CASE_DIR}/actions.log")</pre>

<h2>Evidence</h2>
$(evidence_block 03_network_connections "Network connections")
$(evidence_block 07_processes "Processes")
$(evidence_block 09_logged_in_users "Logged-in users")
$(evidence_block 11_login_history "Login history")
$(evidence_block 13_cron_jobs "Scheduled tasks (cron)")
$(evidence_block 15_ssh_authorized_keys "SSH authorized keys")
$(evidence_block 16_recent_files "Files modified in the last 24 hours")
$(evidence_block 17_auth_log "Authentication log (last 300 lines)")

<h2>Evidence integrity (SHA-256)</h2>
<table>
<tr><th>File</th><th>SHA-256</th></tr>
$(while read -r hash file; do echo "<tr><td>$(printf '%s' "${file#./}" | html_escape)</td><td><code>${hash}</code></td></tr>"; done < "${EVIDENCE_DIR}/SHA256SUMS")
</table>

<h2>Recommended next steps</h2>
<ol>
  <li>Keep the system isolated until the scope is understood.</li>
  <li>Acquire a memory image (for example with LiME or AVML) before rebooting.</li>
  <li>Review the findings and evidence above; confirm or rule out each indicator.</li>
  <li>Identify the initial access vector and check for persistence (cron, systemd, SSH keys, new accounts).</li>
  <li>Rebuild the system from a known-good image before returning it to service.</li>
</ol>

<div class="footer">Full evidence: ${CASE_DIR}/evidence | Case log: ${CASE_DIR}/case.log</div>
</div>
</body>
</html>
HTML
    } > "$report"

    sha256sum "$report" > "${CASE_DIR}/report.sha256"
    log "Report written: $report"
}

main() {
    parse_args "$@"
    preflight
    touch "${CASE_DIR}/actions.log"
    collect_evidence
    hash_evidence
    detect_threats
    contain_system
    generate_report
    echo
    echo "Case folder: $CASE_DIR"
    echo "Open the report: xdg-open '${CASE_DIR}/report.html'"
}

main "$@"
