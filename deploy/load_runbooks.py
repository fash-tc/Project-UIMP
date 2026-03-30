#!/usr/bin/env python3
"""
Bulk-load runbook entries from Confluence wiki pages into the UIP Runbook API.

Sources:
  - TRS Alerts Troubleshooting (Confluence page 9599746088)
  - Critical TLD List for Enom/Hover/OpenSRS (Confluence page 9487810580)
  - Alert & Incident Handling (Confluence page 9487679522)

Run once on the UIP server:
  python3 /home/fash/uip/load_runbooks.py
"""

import json
import urllib.request
import sys

# Runbook API endpoint (container network)
RUNBOOK_API = "http://172.18.0.13:8090"

# ─────────────────────────────────────────────
# TRS Alert Runbook Entries
# ─────────────────────────────────────────────

TRS_ENTRIES = [
    {
        "alert_name": "[TRS] APT WARNING packages available for upgrade 0 critical updates",
        "hostname": "",
        "service": "TRS",
        "severity": "low",
        "remediation": (
            "APT alerts are for package upgrades. If the alert says '0 critical updates', it can be IGNORED.\n\n"
            "All servers mentioned belong to the Anycast Cloud. The Anycast Team handles these.\n\n"
            "If the alert mentions critical updates, let us know NEXT BUSINESS DAY — chances are we already know.\n\n"
            "CONTACT: Ernesto Hernandez, Manuel Zambrano, Pritesh Thakkar (Anycast Team)\n"
            "ESCALATION: Next Business Day\n\n"
            "NOTE: APT alerts have been trimmed. Notify Farshad Ash if alerts still happening."
        ),
    },
    {
        "alert_name": "[TRS] iax3.uniregistry.net APT WARNING packages available for upgrade",
        "hostname": "iax3.uniregistry.net",
        "service": "TRS",
        "severity": "low",
        "remediation": (
            "Non-DNS node operated by Manuel Zambrano and Ernesto Hernandez. "
            "Package upgrade alert on a different (non-Anycast) node.\n\n"
            "CONTACT: Manuel Zambrano, Ernesto Hernandez\n"
            "ESCALATION: Next Business Day"
        ),
    },
    {
        "alert_name": "[TRS] SWAP CRITICAL dns1.tucows.net dns2.tucows.net",
        "hostname": "",
        "service": "TRS",
        "severity": "low",
        "remediation": (
            "The Anycast nodes (dns1 & dns2.tucows.net) SOMETIMES have long-running processes that "
            "start using swap memory until they get a chance to push their data to analytics.\n\n"
            "ACTION: Wait 30-60 minutes to see if it clears itself. If not, contact us NEXT BUSINESS DAY.\n\n"
            "CONTACT: Manuel Zambrano, Ernesto Hernandez\n"
            "ESCALATION: Next Business Day"
        ),
    },
    {
        "alert_name": "[TRS] CPU STATISTICS CRITICAL iowait log01.den1.srs.uniregistry.net",
        "hostname": "log01.den1.srs.uniregistry.net",
        "service": "TRS",
        "severity": "low",
        "remediation": (
            "This is log rotation time. Notice the increased iowait while there's a lot of idle CPU — "
            "that's files being compressed on the log server.\n\n"
            "Should subside in ~10 minutes (can take more on a busy day). It's a log server, so we don't "
            "care about heavy CPU load for compression. We DO care about RUNNING OUT OF SPACE.\n\n"
            "Actual severity: Minor (despite being tagged Critical)\n\n"
            "CONTACT: Manuel Zambrano, Ernesto Hernandez"
        ),
    },
    {
        "alert_name": "[TRS] fw02.lax1.srs.uniregistry.net SWAP WARNING",
        "hostname": "fw02.lax1.srs.uniregistry.net",
        "service": "TRS",
        "severity": "info",
        "remediation": (
            "Pending further explanation.\n\n"
            "CONTACT: Manuel Zambrano, Ernesto Hernandez"
        ),
    },
    {
        "alert_name": "[TRS] hsm01.lax1.srs.uniregistry.net CPU STATISTICS",
        "hostname": "hsm01.lax1.srs.uniregistry.net",
        "service": "TRS",
        "severity": "low",
        "remediation": (
            "This is a multiuse server with logs for the LAX1 node. At certain times of the day, "
            "daily Escrows run. Notice moderate iowait but plenty of idle CPU.\n\n"
            "Takes roughly an hour to complete all Escrows.\n\n"
            "CONTACT: Manuel Zambrano, Ernesto Hernandez"
        ),
    },
    {
        "alert_name": "TLDs AGE CRITICAL errors found",
        "hostname": "",
        "service": "TRS",
        "severity": "low",
        "remediation": (
            "This alert means a zone's serial number hasn't updated for too long. "
            "Zone serials are timestamps (epoch dates) updated every 5 minutes.\n\n"
            "This may indicate a connectivity or server-specific issue, unless the name server "
            "has been taken offline intentionally."
        ),
    },
    {
        "alert_name": "ICANN MOSAPI CRIT alarmed Disabled mosapi",
        "hostname": "",
        "service": "TRS",
        "severity": "critical",
        "remediation": (
            "*** CALL IMMEDIATELY for any ICANN MOSAPI Alert ***\n\n"
            "ICANN MOSAPI (Monitoring System API) monitors registry operator compliance. "
            "See https://www.icann.org/mosapi\n\n"
            "ESCALATION PATH (in order):\n"
            "1. Manuel Zambrano, Sukhvir Grewal, or Ernesto Hernandez\n"
            "2. If alert hasn't cleared after 30 minutes, escalate to:\n"
            "   - Andreas Huber\n"
            "   - Dariana Hernandez\n"
            "   - Marco Walraven\n"
            "   - Francisco Obispo (final escalation)"
        ),
    },
    {
        "alert_name": "[TRS] status.uniregistry.net DISK CRITICAL free space",
        "hostname": "status.uniregistry.net",
        "service": "TRS",
        "severity": "medium",
        "remediation": (
            "Disk space alert on TRS status server.\n\n"
            "CONTACT: Manuel Zambrano"
        ),
    },
    {
        "alert_name": "[TRS] mad01.dns2.tucows.net Host Status",
        "hostname": "mad01.dns2.tucows.net",
        "service": "TRS",
        "severity": "low",
        "remediation": (
            "Anycast DNS node host status alert. Single node — not service impacting "
            "unless multiple nodes are down simultaneously.\n\n"
            "CONTACT: Manuel Zambrano"
        ),
    },
    {
        "alert_name": "[TRS] DISK CRITICAL /var/log dns02.lax1.srs.uniregistry.net",
        "hostname": "dns02.lax1.srs.uniregistry.net",
        "service": "TRS",
        "severity": "low",
        "remediation": (
            "\"It's not critical on that partition, it can wait until logrotate.\"\n\n"
            "ACTION: Wait for logrotate to run. No immediate action needed.\n\n"
            "CONTACT: Manuel Zambrano\n"
            "ESCALATION: Next Business Day"
        ),
    },
    {
        "alert_name": "[TRS] mgmt01.lax1.srs.uniregistry.net DISK CRITICAL /log",
        "hostname": "mgmt01.lax1.srs.uniregistry.net",
        "service": "TRS",
        "severity": "low",
        "remediation": (
            "\"It's not critical on that partition, it can wait until logrotate.\"\n\n"
            "ACTION: Wait for logrotate to run.\n\n"
            "CONTACT: Manuel Zambrano\n"
            "ESCALATION: Next Business Day"
        ),
    },
    {
        "alert_name": "[TRS] mgmt01.lax1.srs.uniregistry.net DISK CRITICAL /var/backups",
        "hostname": "mgmt01.lax1.srs.uniregistry.net",
        "service": "TRS",
        "severity": "low",
        "remediation": (
            "Partition /var/backups on LAX1 mgmt01 holds three things:\n"
            "1. Submitted RyDE for TRS gTLDs — self-cleaning, FIVE DAYS retention\n"
            "2. Submitted RyDE for TRS ccTLDs (countries not mandated for RyDEs) — self-cleaning, FIVE DAYS retention\n"
            "3. Submitted ICANN SLAM reports — NOT self-cleaning for practical reasons\n\n"
            "There's nothing NOC can do other than reach out to the contacts below. "
            "This setup will move to AWS and Ops will be able to assist.\n\n"
            "CONTACT: Manuel Zambrano or Luis Munoz"
        ),
    },
    {
        "alert_name": "UPTIME Host Status alerts dns1.tucows.net dns2.tucows.net anycast",
        "hostname": "",
        "service": "TRS",
        "severity": "low",
        "remediation": (
            "Servers on the Anycast clouds (dns1.tucows.net, dns2.tucows.net) CAN and WILL be "
            "unreachable at times.\n\n"
            "RULES:\n"
            "- 2-3 nodes down: NOT an issue unless they take more than 15-30 minutes to come back\n"
            "- 10+ nodes down simultaneously: WE NEED TO KNOW IMMEDIATELY\n"
            "- Under normal circumstances, unreachable status may happen\n\n"
            "ACTION: When an alert for any dns(1,2).tucows.net server being unreachable comes in, "
            "wait 30 MINUTES before opening a ticket, unless 10+ servers are down at the same time.\n\n"
            "CONTACT (for 10+ down scenario): Manuel Zambrano → Pritesh Thakkar → Ernesto Hernandez → Marco Walraven\n"
            "One or two servers down can wait until NBD if they don't reappear on their own."
        ),
    },
    {
        "alert_name": "DNS Zone Delegation zone is not synced SOA Serial",
        "hostname": "",
        "service": "TRS",
        "severity": "medium",
        "remediation": (
            "Every 5 minutes, new TLD zones are created, signed for security, and given a new timestamp "
            "(SOA serial = epoch date). Servers are notified to sync the latest zones, but if some miss "
            "the update, they fall behind.\n\n"
            "Monitoring checks SOA serials across servers and alerts if there are mismatches.\n\n"
            "CHECK:\n"
            "1. Are flapping alerts targeting the same server?\n"
            "2. Is the serial (SOA Serial) updating?\n"
            "3. Is the delay more than 300 seconds? (zones update every 5 min) — this can reveal "
            "connectivity or server-specific issues, unless the nameserver has been taken offline intentionally.\n\n"
            "NOTE: PDT zones are NOT critical outside business hours. Any other zone requires a page outside BH.\n\n"
            "CONTACT: Manuel Zambrano"
        ),
    },
    {
        "alert_name": "admin console whois HTTP HTTPS service odregistry.com",
        "hostname": "",
        "service": "TRS",
        "severity": "medium",
        "remediation": (
            "For any HTTP or HTTPS service that starts with 'admin', 'console', or 'whois':\n\n"
            "CHECK THE DOMAIN NAME:\n"
            "- If the domain contains 'ote' (e.g., admin.ote.odregistry.com): This is an OTE "
            "(Operational Test Environment) and is NOT critical. Fix during business hours.\n"
            "- If the domain does NOT contain 'ote': This is PRODUCTION and requires IMMEDIATE action.\n\n"
            "CONTACT: Sukhvir Grewal (for both OTE and production)"
        ),
    },
    {
        "alert_name": "Escrow Agent Report HTTP CRITICAL 404 Not Found coop",
        "hostname": "mgmt02.lax1.srs.uniregistry.net",
        "service": "TRS",
        "severity": "medium",
        "remediation": (
            "Escrow upload verification alert. Steps to investigate:\n\n"
            "1. Check if the Escrow was indeed generated correctly on our server\n"
            "2. Check if the Escrow was uploaded to the agent at the expected time\n"
            "3. Check if the upload is 'still there' (meaning it has not been processed yet)\n"
            "   - If it HAS been processed: reach out to the provider and ask about the notification\n"
            "   - If it HASN'T been processed: wait until after 20:00 UTC (3pm EST)\n"
            "     If still alarming after 20:00 UTC, inform Ops to reach out to the agent.\n\n"
            "CONTACT: Ernesto Hernandez-Novich or Manuel Zambrano"
        ),
    },
    {
        "alert_name": "r01 r02 atl1 lax1 router nwc_health hostalive srs.uniregistry.net",
        "hostname": "",
        "service": "TRS",
        "severity": "critical",
        "remediation": (
            "*** CRITICAL — IMMEDIATE ACTION REQUIRED ***\n\n"
            "r01/r02 at atl1 and lax1 are ROUTERS that provide internet access to TRS services. "
            "Any alert for routers requires IMMEDIATE action. Same applies to routers in LAX1.\n\n"
            "CONTACT: Manuel Zambrano"
        ),
    },
    {
        "alert_name": "TRS DNS Aggres process is not running",
        "hostname": "",
        "service": "TRS",
        "severity": "medium",
        "remediation": (
            "The 'aggres' process aggregates DNS analytics data and injects it into the database. "
            "Both the tapper (capture) and aggres (aggregation) processes need to be running:\n"
            "- Grabbing without aggregation → out of memory errors and no data downstream\n"
            "- Aggregation without grabbing → no data downstream\n\n"
            "CONTACT: Manuel Zambrano"
        ),
    },
    {
        "alert_name": "TRS DNS Tapper process is not running",
        "hostname": "",
        "service": "TRS",
        "severity": "medium",
        "remediation": (
            "The 'tapper' process captures real-time DNS events. The 'aggres' process aggregates and injects them. "
            "Both need to be running:\n"
            "- Grabbing without aggregation → out of memory errors and no data downstream\n"
            "- Aggregation without grabbing → no data downstream\n\n"
            "CONTACT: Manuel Zambrano or Pritesh Thakkar"
        ),
    },
    {
        "alert_name": "[TRS] del01.dns1.tucows.net del01.dns2.tucows.net CRITICAL up 1 minutes",
        "hostname": "",
        "service": "TRS",
        "severity": "low",
        "remediation": (
            "Server just rebooted (uptime = minutes). No service impact for individual Anycast nodes.\n\n"
            "Actual severity: Class IV (despite tagged Critical)\n\n"
            "CONTACT: Manuel Zambrano or Ernesto Hernandez"
        ),
    },
    {
        "alert_name": "tapdb01.prod-trs-anycast PostgreSQL Service is down Zabbix agent not available",
        "hostname": "tapdb01.prod-trs-anycast.bra2.tucows.systems",
        "service": "TRS",
        "severity": "critical",
        "remediation": (
            "PostgreSQL database and/or Zabbix agent down on the TRS Anycast analytics DB.\n\n"
            "CONTACT:\n"
            "- 1st level: Pritesh Thakkar or Manuel Zambrano\n"
            "- 2nd level: Ernesto Hernandez-Novich"
        ),
    },
    {
        "alert_name": "tapdb01.prod-trs-anycast Disk usage /var/lib/postgresql",
        "hostname": "tapdb01.prod-trs-anycast.bra2.tucows.systems",
        "service": "TRS",
        "severity": "high",
        "remediation": (
            "Page Domains DBA ANY TIME /var/lib/postgresql space utilization is over 75%.\n\n"
            "CONTACT: Domains DBA team\n"
            "ESCALATION: Page immediately (any time, including outside business hours)"
        ),
    },
    {
        "alert_name": "PING CRITICAL Packet loss 100% anycast dns uniregistry.net dns1.tucows.net dns2.tucows.net",
        "hostname": "",
        "service": "TRS",
        "severity": "low",
        "remediation": (
            "Anycast node packet loss. One node down will NOT affect DNS service for TRS "
            "as there are 70+ nodes in the cloud.\n\n"
            "Hostnames use closest IATA airport code (e.g., ory01 for Paris, lax01 for Los Angeles). "
            "dns.uniregistry.net is being replaced by dns[1,2].tucows.net.\n\n"
            "CONTACT: Manuel Zambrano or Ernesto Hernandez"
        ),
    },
    {
        "alert_name": "DISK CRITICAL /var/lib/barman mgmt01.atl1 mgmt01.lax1 backup01.den1",
        "hostname": "",
        "service": "TRS",
        "severity": "medium",
        "remediation": (
            "Barman manages database backups. Two full backups are kept; the oldest is deleted "
            "after the current day's backup completes. Therefore there are times when nearly "
            "three full backups are present.\n\n"
            "NOTE: ATL1 and LAX1 mgmt01 are CRITICAL, DEN1 backup01 is the backup copy.\n\n"
            "ACTION: Page if still alarming by 04:00-06:00 UTC.\n\n"
            "CONTACT: Ernesto Hernandez"
        ),
    },
    {
        "alert_name": "[TRS] db01.atl1.srs.uniregistry.net Registry Health Renewal Rate",
        "hostname": "db01.atl1.srs.uniregistry.net",
        "service": "TRS",
        "severity": "low",
        "remediation": (
            "Non-urgent. There is a CRON job that updates Renewal Statistics. "
            "This is low priority and can be investigated, or the CRON can be re-run "
            "during business hours.\n\n"
            "CONTACT: Sukhvir Grewal"
        ),
    },
    {
        "alert_name": "trs_prod Kubernetes Nodes not Ready state Unknown",
        "hostname": "",
        "service": "TRS",
        "severity": "medium",
        "remediation": (
            "Kubernetes node readiness alert from TRS production clusters.\n\n"
            "CRITICAL REGIONS (page immediately):\n"
            "- ap-south-1 (Mumbai)\n"
            "- us-east-2 (Ohio)\n\n"
            "DISASTER RECOVERY REGIONS (handle during business hours):\n"
            "- ap-south-2\n"
            "- us-west-2\n\n"
            "CONTACT: Domains A team"
        ),
    },
    {
        "alert_name": "[TRS] db01 DISK CRITICAL TRS database server",
        "hostname": "",
        "service": "TRS",
        "severity": "critical",
        "remediation": (
            "*** ANY disk issue on TRS db servers requires immediate attention ***\n\n"
            "Call immediately for any TRS db server disk issue.\n\n"
            "CONTACT: Manuel Zambrano, Ernesto Hernandez"
        ),
    },
    {
        "alert_name": "trs-syslog-prod",
        "hostname": "",
        "service": "TRS",
        "severity": "medium",
        "remediation": (
            "TRS syslog production alert.\n\n"
            "CONTACT: DevOps — specifically Jose Tecson or Pritesh Thakkar"
        ),
    },
    {
        "alert_name": "adminlite.unr.com HTTP CRITICAL 503 Service Unavailable",
        "hostname": "adminlite.unr.com",
        "service": "TRS",
        "severity": "critical",
        "remediation": (
            "Admin interface service unavailable.\n\n"
            "CONTACT: Sukhvir Grewal, Manuel Zambrano, and (maybe) Andreas Huber"
        ),
    },
    {
        "alert_name": "master.west.prod.aws.tucowsregistry.net Disk space is low",
        "hostname": "master.west.prod.aws.tucowsregistry.net",
        "service": "TRS",
        "severity": "low",
        "remediation": (
            "Disk space alert on TRS AWS west production master node.\n\n"
            "CONTACT: Domains A team"
        ),
    },
    {
        "alert_name": "manage.shopco.com HTTPS WARNING",
        "hostname": "manage.shopco.com",
        "service": "TRS",
        "severity": "medium",
        "remediation": (
            "HTTP(S) service warning on manage.shopco.com.\n\n"
            "CONTACT: Luis Gonzalez"
        ),
    },
    {
        "alert_name": "escrow.east.prod.aws.tucowsregistry.net /var/backups Disk space is low",
        "hostname": "escrow.east.prod.aws.tucowsregistry.net",
        "service": "TRS",
        "severity": "low",
        "remediation": (
            "Disk space on the escrow east production server.\n\n"
            "RULES:\n"
            "- Business hours escalation ONLY\n"
            "- Paging is ONLY necessary if usage exceeds 95%\n\n"
            "CONTACT: Domains A team"
        ),
    },
]

# ─────────────────────────────────────────────
# OpenSRS / Enom / Hover — Critical TLD Policy
# ─────────────────────────────────────────────

OPENSRS_ENTRIES = [
    {
        "alert_name": "OpenSRS Enom Hover TLD registry connection outage",
        "hostname": "",
        "service": "OpenSRS",
        "severity": "varies",
        "remediation": (
            "CRITICAL TLD LIST FOR ENOM / HOVER / OPENSRS\n"
            "=============================================\n\n"
            "Critical TLDs: .com, .net, .org, .ca, .za, .uk, .au, .info, .co, .de, .fr, .biz, .it\n\n"
            "RULES:\n"
            "- Critical TLD outage → PAGE IMMEDIATELY\n"
            "- Customer complaints for ANY TLD (critical or non-critical) → PAGE IMMEDIATELY\n"
            "- Non-critical TLD outage (no customer complaints) → Ticket and escalate during BUSINESS HOURS only"
        ),
    },
]

# ─────────────────────────────────────────────
# General Alert & Incident Handling Procedure
# ─────────────────────────────────────────────

GENERAL_ENTRIES = [
    {
        "alert_name": "Alert Incident Handling general procedure",
        "hostname": "",
        "service": "",
        "severity": "",
        "remediation": (
            "GENERAL ALERT HANDLING PROCEDURE\n"
            "================================\n\n"
            "1. Assess the alert: determine impact by analyzing past incidents, experience, or wiki\n"
            "2. Create a Jira Ticket in the OCCIR Project BEFORE taking any actions\n"
            "3. Resolve the alert using predetermined steps, or escalate to relevant engineering\n"
            "4. Send/update Incident Update (IU) via Statuspage.io if necessary\n"
            "5. Once resolved, CLOSE the corresponding Jira Ticket\n\n"
            "FOR CLASS III AND ABOVE — use this closing template:\n"
            "- What happened?\n"
            "- Why it happened?\n"
            "- Will it happen again?\n"
            "- Restoration Steps\n"
            "- How to prevent this from happening?\n"
            "- Monitoring gaps?\n\n"
            "FOR CLASS II AND ABOVE:\n"
            "- Open the Incident Worksheet (Google Sheets), make a copy, rename to OCCIR-XXXX\n"
            "- Notify OCC Manager\n"
            "- For Class II: optionally open a dedicated Slack channel + Google Meet bridge\n"
            "- For Class I: Slack channel is MANDATORY\n"
            "- Record all actions/impacts/steps in the Notes section of the worksheet\n"
            "- Attach completed worksheet to Jira Ticket when resolved"
        ),
    },
]

# ─────────────────────────────────────────────
# AI Instructions
# ─────────────────────────────────────────────

AI_INSTRUCTIONS = [
    {
        "instruction": (
            "TRS Anycast DNS nodes (dns1.tucows.net, dns2.tucows.net) are part of a 70+ node cloud. "
            "Individual node outages are NOT service-impacting. Only escalate immediately if 10+ nodes "
            "are down simultaneously. Individual node alerts (PING CRITICAL, Host Status, SWAP, uptime) "
            "should wait 30 minutes before ticketing unless a large group is affected. Hostnames use "
            "IATA airport codes (ory01=Paris, lax01=Los Angeles, mad01=Madrid, etc.)."
        ),
        "active": True,
    },
    {
        "instruction": (
            "For Enom/Hover/OpenSRS alerts involving TLD outages: Critical TLDs requiring immediate "
            "paging are .com, .net, .org, .ca, .za, .uk, .au, .info, .co, .de, .fr, .biz, .it. "
            "Non-critical TLDs can be escalated during business hours only. Customer complaints about "
            "any TLD (critical or not) always require immediate paging."
        ),
        "active": True,
    },
    {
        "instruction": (
            "TRS server alert context: Log servers (log01.*) frequently show high iowait during log "
            "rotation — this is normal and subsides in ~10 minutes. Management servers (mgmt01.*) run "
            "daily Escrows that cause iowait for ~1 hour. Firewall servers (fw02.*) may show swap usage. "
            "Database servers (db01.*) require immediate attention for ANY disk issue. The /var/backups "
            "partition on mgmt01.lax1 holds RyDE and ICANN SLAM reports — space issues should be "
            "escalated to Manuel Zambrano or Luis Munoz."
        ),
        "active": True,
    },
]


def post_json(url, data):
    """POST JSON to a URL and return the response."""
    body = json.dumps(data).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8")


def main():
    all_entries = TRS_ENTRIES + OPENSRS_ENTRIES + GENERAL_ENTRIES
    print(f"Loading {len(all_entries)} runbook entries...")

    success = 0
    failed = 0
    for entry in all_entries:
        payload = {
            "alert_name": entry["alert_name"],
            "hostname": entry.get("hostname", ""),
            "service": entry.get("service", ""),
            "severity": entry.get("severity", ""),
            "remediation": entry["remediation"],
            "sre_user": "wiki-import",
        }
        status, resp = post_json(f"{RUNBOOK_API}/api/runbook/entries", payload)
        if status in (200, 201):
            success += 1
            entry_id = resp.get("id", "?") if isinstance(resp, dict) else "?"
            print(f"  OK [{entry_id}] {entry['alert_name'][:60]}")
        else:
            failed += 1
            print(f"  FAIL ({status}) {entry['alert_name'][:60]}: {resp}")

    print(f"\nRunbook entries: {success} created, {failed} failed")

    # Load AI instructions
    print(f"\nLoading {len(AI_INSTRUCTIONS)} AI instructions...")
    ai_ok = 0
    for instr in AI_INSTRUCTIONS:
        status, resp = post_json(
            f"{RUNBOOK_API}/api/runbook/ai-instructions", instr
        )
        if status in (200, 201):
            ai_ok += 1
            print(f"  OK: {instr['instruction'][:70]}...")
        else:
            print(f"  FAIL ({status}): {resp}")

    print(f"AI instructions: {ai_ok} created")
    print(f"\nDone! Total: {success} runbook entries + {ai_ok} AI instructions loaded.")

    if failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
