"""
Incident History page — SENTINEL SOC-AI platform.
Imported by dashboard/app.py and called from the sidebar nav.
"""

import random
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# Make sure agents/ is importable from the dashboard directory
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# ─────────────────────────────────────────────────────────────────────────────
# CSS — extends the global SENTINEL theme
# ─────────────────────────────────────────────────────────────────────────────
INCIDENT_CSS = """<style>
/* Status badges */
.status-badge { padding: 2px 8px; border-radius: 3px; display: inline-block; font-family: monospace; font-size: 10px; }
.status-new           { background: rgba(139,92,246,.15); color: #c4b5fd; border: 1px solid rgba(139,92,246,.35); }
.status-investigating { background: rgba(249,115,22,.12); color: #fdba74; border: 1px solid rgba(249,115,22,.35); }
.status-contained     { background: rgba(234,179,8,.12);  color: #fde047; border: 1px solid rgba(234,179,8,.35);  }
.status-resolved      { background: rgba(34,197,94,.10);  color: #86efac; border: 1px solid rgba(34,197,94,.3);   }
.status-closed        { background: rgba(100,116,139,.12);color: #94a3b8; border: 1px solid rgba(100,116,139,.3); }

/* Timeline */
.tl-row  { display: flex; align-items: flex-start; gap: 10px; padding: 7px 0; border-bottom: 1px solid rgba(255,255,255,.04); }
.tl-dot  { width: 7px; height: 7px; border-radius: 50%; margin-top: 5px; flex-shrink: 0; }
.tl-dot.critical { background: #ef4444; }
.tl-dot.high     { background: #f97316; }
.tl-dot.medium   { background: #eab308; }
.tl-dot.low      { background: #3b82f6; }
.tl-dot.info     { background: #64748b; }
.tl-time { font-family: monospace; font-size: 10px; color: #64748b; min-width: 70px; }
.tl-text { font-family: monospace; font-size: 11px; color: #94a3b8; line-height: 1.5; }

/* Log lines */
.log-line { font-family: monospace; font-size: 10px; color: #22c55e; background: rgba(34,197,94,.04); border-left: 2px solid rgba(34,197,94,.2); padding: 4px 10px; margin-bottom: 3px; border-radius: 0 3px 3px 0; white-space: pre-wrap; word-break: break-all; }

/* Recommendations */
.rec-item { font-family: monospace; font-size: 11px; color: #94a3b8; padding: 6px 10px; border-left: 2px solid rgba(59,130,246,.3); margin-bottom: 4px; background: rgba(59,130,246,.04); border-radius: 0 4px 4px 0; }

/* Playbook tags */
.pb-tag { display: inline-block; font-family: monospace; font-size: 10px; padding: 2px 8px; border-radius: 3px; margin: 2px; }
.pb-tag.blocked  { color: #fca5a5; background: rgba(239,68,68,.1);  border: 1px solid rgba(239,68,68,.25);  }
.pb-tag.isolated { color: #fdba74; background: rgba(249,115,22,.1); border: 1px solid rgba(249,115,22,.25); }
.pb-tag.disabled { color: #fde047; background: rgba(234,179,8,.1);  border: 1px solid rgba(234,179,8,.25);  }
.pb-tag.rule     { color: #86efac; background: rgba(34,197,94,.07); border: 1px solid rgba(34,197,94,.2);   }

/* Risk bar */
.risk-wrap { background: rgba(255,255,255,.06); border-radius: 3px; height: 7px; overflow: hidden; margin: 5px 0; }
.risk-fill { height: 100%; border-radius: 3px; }
.risk-crit { background: #ef4444; }
.risk-high { background: #f97316; }
.risk-med  { background: #eab308; }
.risk-low  { background: #3b82f6; }

/* Chips */
.mitre-chip { font-family: monospace; font-size: 10px; color: #c4b5fd; background: rgba(139,92,246,.12); border: 1px solid rgba(139,92,246,.25); padding: 1px 7px; border-radius: 3px; }
.sim-chip   { display: inline-block; font-family: monospace; font-size: 10px; color: #60a5fa; background: rgba(59,130,246,.08); border: 1px solid rgba(59,130,246,.2); padding: 3px 10px; border-radius: 3px; margin: 2px; }
.tag-chip   { display: inline-block; font-family: monospace; font-size: 9px; color: #64748b; background: rgba(100,116,139,.1); border: 1px solid rgba(100,116,139,.2); padding: 1px 7px; border-radius: 3px; margin: 2px; }

/* AI summary */
.ai-box { background: rgba(34,197,94,.04); border: 1px solid rgba(34,197,94,.15); border-left: 3px solid #22c55e; border-radius: 6px; padding: 14px 16px; font-family: monospace; font-size: 11px; color: #94a3b8; line-height: 1.7; white-space: pre-wrap; }

/* Empty state */
.empty-state { text-align: center; padding: 50px 20px; }
.empty-icon  { font-size: 38px; opacity: .3; margin-bottom: 12px; }
.empty-msg   { font-family: monospace; font-size: 14px; color: #64748b; }
.empty-sub   { font-family: monospace; font-size: 11px; color: #334155; margin-top: 6px; }

/* Detail panel */
.detail-wrap  { background: #111827; border: 1px solid rgba(59,130,246,.2); border-radius: 8px; padding: 20px; margin-top: 12px; }
.detail-title { font-family: monospace; font-size: 15px; color: #e2e8f0; font-weight: 700; margin-bottom: 10px; }

/* Page info */
.pg-info { font-family: monospace; font-size: 11px; color: #64748b; text-align: center; padding: 8px 0; }

/* Threat Intel enrichment cards */
.ti-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px; margin-top: 12px; }
.ti-card { background: #0d1117; border: 1px solid rgba(255,255,255,.07); border-radius: 6px; padding: 12px 14px; }
.ti-card.danger  { border-left: 3px solid #ef4444; }
.ti-card.warning { border-left: 3px solid #eab308; }
.ti-card.safe    { border-left: 3px solid #22c55e; }
.ti-card.neutral { border-left: 3px solid #3b82f6; }
.ti-card.unknown { border-left: 3px solid #64748b; }
.ti-src   { font-family: monospace; font-size: 9px; color: #64748b; letter-spacing: .1em; margin-bottom: 6px; }
.ti-score { font-family: monospace; font-size: 22px; font-weight: 700; line-height: 1.1; }
.ti-score.red    { color: #ef4444; }
.ti-score.yellow { color: #eab308; }
.ti-score.green  { color: #22c55e; }
.ti-score.blue   { color: #60a5fa; }
.ti-score.gray   { color: #64748b; }
.ti-label { font-family: monospace; font-size: 10px; color: #64748b; margin-top: 2px; }
.ti-meta  { font-family: monospace; font-size: 10px; color: #4a7fa5; margin-top: 6px; line-height: 1.5; }
.ti-row   { display: flex; justify-content: space-between; font-family: monospace; font-size: 10px; padding: 3px 0; border-bottom: 1px solid rgba(255,255,255,.03); }
.ti-row:last-child { border-bottom: none; }
.ti-row .key { color: #64748b; }
.ti-row .val { color: #e2e8f0; }
.ti-ioc-item { font-family: monospace; font-size: 10px; color: #94a3b8; padding: 4px 8px; background: rgba(239,68,68,.05); border-left: 2px solid rgba(239,68,68,.3); margin-top: 4px; border-radius: 0 3px 3px 0; }
.ti-error { font-family: monospace; font-size: 10px; color: #64748b; padding: 8px; }

/* Tab overrides */
.stTabs [data-baseweb="tab-list"] { background: transparent !important; border-bottom: 1px solid rgba(255,255,255,.08) !important; gap: 0 !important; }
.stTabs [data-baseweb="tab"] { font-family: monospace !important; font-size: 11px !important; color: #64748b !important; padding: 7px 16px !important; border-radius: 0 !important; border-bottom: 2px solid transparent !important; }
.stTabs [aria-selected="true"] { color: #60a5fa !important; border-bottom-color: #3b82f6 !important; background: rgba(59,130,246,.05) !important; }
</style>"""


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def status_badge(status: str) -> str:
    css_map = {
        "New": "status-new",
        "Investigating": "status-investigating",
        "Contained": "status-contained",
        "Resolved": "status-resolved",
        "Closed": "status-closed",
    }
    css = css_map.get(status, "status-closed")
    return f'<span class="status-badge {css}">{status.upper()}</span>'


def _risk_bar(score: int, sev: str) -> str:
    cls = {"critical": "risk-crit", "high": "risk-high", "medium": "risk-med"}.get(sev, "risk-low")
    return (
        f'<div style="font-family:\'Share Tech Mono\',monospace;font-size:11px;color:#4a7fa5;">RISK SCORE</div>'
        f'<div style="font-family:\'Share Tech Mono\',monospace;font-size:28px;font-weight:700;color:#e6f1ff;">'
        f'{score}<span style="font-size:14px;color:#4a7fa5;">/100</span></div>'
        f'<div class="risk-wrap"><div class="risk-fill {cls}" style="width:{score}%;"></div></div>'
    )


def _generate_export_text(inc: dict) -> str:
    lines = [
        "=" * 64,
        f"  SENTINEL SOC-AI · INCIDENT REPORT",
        f"  Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        "=" * 64,
        "",
        f"  Incident ID   : {inc['id']}",
        f"  Severity      : {inc['severity'].upper()}",
        f"  Attack Type   : {inc['attack_type']}",
        f"  Source IP     : {inc['src_ip']}",
        f"  Target Host   : {inc['target_host']}",
        f"  Status        : {inc['status']}",
        f"  MITRE ID      : {inc['mitre_id']} — {inc['mitre_name']}",
        f"  Detection     : {inc['detection_date']}",
        f"  Analyst       : {inc['analyst']}",
        f"  Risk Score    : {inc['risk_score']}/100",
        f"  Alert Count   : {inc['alerts_count']}",
        "",
        "-" * 64,
        "  DESCRIPTION",
        "-" * 64,
        inc["description"],
        "",
        "-" * 64,
        "  AI SUMMARY",
        "-" * 64,
        inc["ai_summary"],
        "",
        "-" * 64,
        "  TIMELINE",
        "-" * 64,
    ]
    for t in inc["timeline"]:
        lines.append(f"  [{t['time']}] [{t['level'].upper():8}] {t['event']}")
    lines += ["", "-" * 64, "  CORRELATED LOGS", "-" * 64]
    for log in inc["logs"]:
        lines.append(f"  {log}")
    lines += ["", "-" * 64, "  RECOMMENDATIONS", "-" * 64]
    for i, rec in enumerate(inc["recommendations"], 1):
        lines.append(f"  {i}. {rec}")
    pb = inc["playbook"]
    lines += ["", "-" * 64, "  PLAYBOOK ACTIONS", "-" * 64]
    if pb["blocked_ips"]:
        lines.append(f"  Blocked IPs    : {', '.join(pb['blocked_ips'])}")
    if pb["isolated_machines"]:
        lines.append(f"  Isolated Hosts : {', '.join(pb['isolated_machines'])}")
    if pb["disabled_accounts"]:
        lines.append(f"  Disabled Accts : {', '.join(pb['disabled_accounts'])}")
    for rule in pb["firewall_rules"]:
        lines.append(f"  Firewall Rule  : {rule}")
    lines += ["", "=" * 64, "  END OF REPORT — SENTINEL SOC-AI PLATFORM", "=" * 64]
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Mock incident database (12 incidents, realistic SOC environment)
# ─────────────────────────────────────────────────────────────────────────────

def get_incident_mock_data() -> list:
    return [
        {
            "id": "INC-2026-0145",
            "severity": "critical",
            "attack_type": "SSH Brute Force",
            "src_ip": "192.168.110.151",
            "target_host": "zaim-VMware-Virtual-Platform",
            "status": "Investigating",
            "mitre_id": "T1110.001",
            "mitre_name": "Password Guessing",
            "detection_date": "2026-05-12 21:34",
            "analyst": "SOC-AI (Auto)",
            "risk_score": 92,
            "alerts_count": 752,
            "description": "Coordinated SSH brute force attack targeting root account. 752 failed authentication attempts across 7 Wazuh rules over ~15 minutes from a single internal source.",
            "ai_summary": (
                "An automated SSH brute force campaign was detected originating from 192.168.110.151 targeting "
                "zaim-VMware-Virtual-Platform. The attack generated 752 alerts across 7 Wazuh rules over approximately "
                "15 minutes.\n\n"
                "Key Observations:\n"
                "  • 443 authentication failures  (rule 5760, level 5)\n"
                "  • 82  max auth exceeded events (rule 5758, level 8)\n"
                "  • 57  brute force confirmations (rule 5763, level 10)\n"
                "  • Root account targeted exclusively\n"
                "  • Packet cadence consistent with Hydra / Medusa automated tooling\n\n"
                "Threat Assessment: HIGH — Active brute force with automated tooling signatures. "
                "Immediate containment recommended."
            ),
            "timeline": [
                {"time": "21:20:00", "event": "First SSH connection attempt from 192.168.110.151", "level": "info"},
                {"time": "21:22:15", "event": "Rule 5760 triggered — SSH authentication failed (×15)", "level": "low"},
                {"time": "21:25:30", "event": "Rule 5758 triggered — Maximum authentication attempts exceeded", "level": "medium"},
                {"time": "21:28:45", "event": "Rule 5763 triggered — SSH brute force pattern confirmed", "level": "high"},
                {"time": "21:30:00", "event": "Rule 2502 triggered — Multiple missed passwords (×69)", "level": "high"},
                {"time": "21:34:51", "event": "SENTINEL auto-created incident INC-2026-0145", "level": "critical"},
            ],
            "logs": [
                "2026-05-12T21:34:51 [WAZUH:5763:HIGH]  sshd: brute force trying to get access. Authentication failed. srcip=192.168.110.151",
                "2026-05-12T21:34:49 [WAZUH:5760:LOW]   sshd: authentication failed. srcip=192.168.110.151 user=root",
                "2026-05-12T21:34:49 [SYSLOG]           Failed password for root from 192.168.110.151 port 44512 ssh2",
                "2026-05-12T21:30:12 [WAZUH:5758:MED]   Maximum authentication attempts exceeded. srcip=192.168.110.151",
                "2026-05-12T21:25:04 [WAZUH:2502:HIGH]  syslog: User missed the password more than one time. user=root",
                "2026-05-12T21:20:03 [FIREWALL]         ALLOW TCP 192.168.110.151:44100 -> 192.168.110.155:22 [NEW]",
            ],
            "recommendations": [
                "Block IP 192.168.110.151 at the firewall immediately (iptables -A INPUT -s 192.168.110.151 -j DROP)",
                "Enable and tune fail2ban — threshold ≤ 5 attempts / 60 seconds",
                "Disable root SSH login (set PermitRootLogin no in /etc/ssh/sshd_config)",
                "Enforce SSH key-based authentication only — disable password auth",
                "Review /var/log/auth.log for any successful logins from this IP",
                "Consider network segmentation — isolate SSH management traffic",
            ],
            "playbook": {
                "blocked_ips": ["192.168.110.151"],
                "isolated_machines": [],
                "disabled_accounts": [],
                "firewall_rules": ["iptables -A INPUT -s 192.168.110.151 -p tcp --dport 22 -j DROP"],
            },
            "similar": ["INC-2026-0138", "INC-2026-0131", "INC-2026-0127"],
            "tags": ["ssh", "brute-force", "credential-access", "T1110.001", "live"],
        },
        {
            "id": "INC-2026-0144",
            "severity": "critical",
            "attack_type": "Ransomware Staging",
            "src_ip": "10.24.56.89",
            "target_host": "db-master",
            "status": "Contained",
            "mitre_id": "T1486",
            "mitre_name": "Data Encrypted for Impact",
            "detection_date": "2026-05-11 14:22",
            "analyst": "M. Hartmann",
            "risk_score": 97,
            "alerts_count": 284,
            "description": "Ransomware staging detected on db-master. Encryption modules loaded, Volume Shadow Copies deleted. Contained before encryption executed.",
            "ai_summary": (
                "Critical ransomware staging event on the primary database server. The attacker loaded encryption "
                "modules and began deleting Volume Shadow Copies before containment.\n\n"
                "Attack Chain:\n"
                "  • Initial access via compromised service account (svc_backup_db)\n"
                "  • LOLBins used: vssadmin, wmic for discovery and defense evasion\n"
                "  • Shadow copy deletion executed (all VSS copies removed)\n"
                "  • Encryption binary staged in %TEMP%\\svc_update.dll\n\n"
                "Containment Status: Machine isolated at 14:28. Encryption did NOT reach primary DB files. "
                "Forensic image in progress. Estimated recovery: 4 hours from clean snapshot."
            ),
            "timeline": [
                {"time": "14:10:00", "event": "Lateral movement from web-prod-01 to db-master via SMB", "level": "medium"},
                {"time": "14:15:00", "event": "Service account svc_backup_db used for authentication", "level": "high"},
                {"time": "14:18:30", "event": "vssadmin delete shadows /all /quiet executed", "level": "critical"},
                {"time": "14:20:15", "event": "Suspicious binary dropped in C:\\Windows\\Temp\\", "level": "high"},
                {"time": "14:22:00", "event": "Encryption module loaded — Sysmon Event ID 7 triggered", "level": "critical"},
                {"time": "14:28:00", "event": "Machine isolated by analyst M. Hartmann", "level": "info"},
            ],
            "logs": [
                "2026-05-11T14:22:00 [SYSMON:7]       Image loaded: C:\\Windows\\Temp\\svc_update.dll — Unsigned",
                "2026-05-11T14:18:30 [SYSMON:1]       Process: vssadmin.exe 'delete shadows /all /quiet'",
                "2026-05-11T14:18:00 [WAZUH:100200]   Privilege escalation attempt detected on db-master",
                "2026-05-11T14:15:00 [WAZUH:18107]    Windows audit failure: svc_backup_db — LOGON TYPE 3",
                "2026-05-11T14:10:00 [FIREWALL]        ALLOW TCP 10.24.56.89:52145 -> 10.0.1.50:445 [SMB NEW]",
            ],
            "recommendations": [
                "Maintain db-master network isolation until forensic analysis completes",
                "Restore db-master from 2026-05-10 clean snapshot",
                "Audit svc_backup_db permissions — enforce principle of least privilege",
                "Deploy honeypot decoy files (canary tokens) to detect future encryption attempts",
                "Implement application whitelisting (AppLocker/WDAC) on all database servers",
                "Enable VSS snapshot protection — use Protected Folders (Controlled Folder Access)",
            ],
            "playbook": {
                "blocked_ips": ["10.24.56.89"],
                "isolated_machines": ["db-master"],
                "disabled_accounts": ["svc_backup_db"],
                "firewall_rules": ["Block all outbound from db-master pending forensics"],
            },
            "similar": ["INC-2026-0135", "INC-2026-0128"],
            "tags": ["ransomware", "T1486", "shadow-copies", "encryption", "critical-asset"],
        },
        {
            "id": "INC-2026-0143",
            "severity": "high",
            "attack_type": "C2 Beacon",
            "src_ip": "185.220.101.45",
            "target_host": "k8s-edge-3",
            "status": "Investigating",
            "mitre_id": "T1071.001",
            "mitre_name": "Web Protocols C2",
            "detection_date": "2026-05-10 09:15",
            "analyst": "L. Okafor",
            "risk_score": 78,
            "alerts_count": 143,
            "description": "Regular beaconing traffic from k8s-edge-3 to known Tor exit node. HTTPS traffic JA3 fingerprint matches Cobalt Strike default profile.",
            "ai_summary": (
                "Command and Control beaconing activity detected from internal Kubernetes edge node to 185.220.101.45, "
                "a known Tor exit node listed in multiple threat intelligence feeds.\n\n"
                "Key Indicators:\n"
                "  • Regular 60-second beacon intervals (±2s jitter)\n"
                "  • JA3 fingerprint matches Cobalt Strike default profile\n"
                "  • Encrypted HTTPS traffic with self-signed certificate\n"
                "  • UserAgent anomaly: Mozilla/5.0 from non-browser process\n"
                "  • File integrity alert on /usr/local/bin/kubectl (modified)\n\n"
                "Assessment: Host likely compromised via supply-chain or container escape. "
                "Cobalt Strike Beacon implant suspected. Full memory dump required."
            ),
            "timeline": [
                {"time": "09:00:00", "event": "First outbound beacon to 185.220.101.45:443", "level": "medium"},
                {"time": "09:01:00", "event": "Second beacon — 60s interval confirmed", "level": "high"},
                {"time": "09:05:00", "event": "File integrity alert: /usr/local/bin/kubectl modified", "level": "high"},
                {"time": "09:10:00", "event": "Suricata: JA3 fingerprint matched to Cobalt Strike", "level": "critical"},
                {"time": "09:15:00", "event": "Incident created — analyst L. Okafor assigned", "level": "info"},
            ],
            "logs": [
                "2026-05-10T09:10:00 [SURICATA:2028371]  ET MALWARE Cobalt Strike Beacon Observed",
                "2026-05-10T09:05:00 [WAZUH:554]         Integrity checksum changed: /usr/local/bin/kubectl",
                "2026-05-10T09:01:00 [FIREWALL]          ALLOW TCP k8s-edge-3:49234 -> 185.220.101.45:443",
                "2026-05-10T09:00:00 [FIREWALL]          ALLOW TCP k8s-edge-3:49233 -> 185.220.101.45:443",
                "2026-05-10T08:58:00 [DNS]                Query: update.microsoft-telemetry.com -> 185.220.101.45 [SINKHOLE]",
            ],
            "recommendations": [
                "Isolate k8s-edge-3 from production cluster immediately",
                "Block 185.220.101.45 at perimeter firewall and DNS sinkhole",
                "Dump memory of k8s-edge-3 for Cobalt Strike implant extraction",
                "Rotate ALL credentials accessible from k8s-edge-3",
                "Review K8s RBAC — restrict lateral movement capabilities",
                "Audit container images — check for supply-chain compromise",
            ],
            "playbook": {
                "blocked_ips": ["185.220.101.45"],
                "isolated_machines": [],
                "disabled_accounts": [],
                "firewall_rules": ["Block 185.220.101.45 on all ports", "DNS sinkhole: *.185.220.101.45"],
            },
            "similar": ["INC-2026-0140", "INC-2026-0133"],
            "tags": ["c2", "cobalt-strike", "beacon", "T1071.001", "kubernetes"],
        },
        {
            "id": "INC-2026-0142",
            "severity": "high",
            "attack_type": "SQL Injection",
            "src_ip": "91.234.56.78",
            "target_host": "web-prod-01",
            "status": "Resolved",
            "mitre_id": "T1190",
            "mitre_name": "Exploit Public-Facing Application",
            "detection_date": "2026-05-09 16:45",
            "analyst": "S. Iyer",
            "risk_score": 71,
            "alerts_count": 47,
            "description": "Blind SQL injection on /api/users endpoint. WAF blocked 41/47 attempts. 6 payloads reached app layer. No exfiltration confirmed.",
            "ai_summary": (
                "SQL injection campaign targeting the public API endpoint /api/users. Time-based blind injection "
                "payloads detected. Database schema reconnaissance was in progress before WAF rules were updated.\n\n"
                "Payload Analysis:\n"
                "  • Time-based blind injection: ' AND SLEEP(5)--\n"
                "  • Union-based recon: ' UNION SELECT NULL,NULL,NULL--\n"
                "  • Error-based extraction attempted\n\n"
                "Impact: No data exfiltration confirmed. WAF updated, endpoint patched with parameterized queries."
            ),
            "timeline": [
                {"time": "16:40:00", "event": "First SQL injection payload blocked by WAF", "level": "medium"},
                {"time": "16:42:00", "event": "6 payloads bypass WAF — reached application layer", "level": "high"},
                {"time": "16:45:00", "event": "Incident created — WAF rule update initiated", "level": "info"},
                {"time": "17:10:00", "event": "WAF rules updated — attack 100% blocked", "level": "info"},
                {"time": "18:00:00", "event": "Patch deployed — parameterized queries enforced", "level": "info"},
                {"time": "18:30:00", "event": "Incident resolved — no data breach confirmed", "level": "info"},
            ],
            "logs": [
                "2026-05-09T16:42:00 [WAF:BYPASS]   POST /api/users?id=1' AND SLEEP(5)-- HTTP/1.1 200",
                "2026-05-09T16:41:30 [WAF:BLOCK]    GET /api/users?id=1 OR 1=1-- HTTP/1.1 403",
                "2026-05-09T16:40:00 [WAZUH:31151]  SQL injection attempt detected. srcip=91.234.56.78",
                "2026-05-09T16:40:00 [NGINX]         91.234.56.78 POST /api/users 500 342ms",
            ],
            "recommendations": [
                "All user-facing endpoints must use parameterized queries / prepared statements",
                "Implement strict input validation and output encoding (OWASP guidelines)",
                "Deploy ModSecurity WAF with OWASP Core Rule Set (CRS) version 4.x",
                "Conduct quarterly OWASP Top 10 penetration testing",
                "Enable database activity monitoring (DAM) on all production databases",
            ],
            "playbook": {
                "blocked_ips": ["91.234.56.78"],
                "isolated_machines": [],
                "disabled_accounts": [],
                "firewall_rules": ["WAF: Block 91.234.56.78 for 30 days", "Rate-limit /api/users to 60 req/min"],
            },
            "similar": ["INC-2026-0130"],
            "tags": ["sql-injection", "web-attack", "T1190", "OWASP-A03"],
        },
        {
            "id": "INC-2026-0141",
            "severity": "high",
            "attack_type": "Phishing Campaign",
            "src_ip": "203.0.113.42",
            "target_host": "win-dc-01",
            "status": "Closed",
            "mitre_id": "T1566.001",
            "mitre_name": "Spearphishing Attachment",
            "detection_date": "2026-05-08 11:20",
            "analyst": "M. Hartmann",
            "risk_score": 68,
            "alerts_count": 23,
            "description": "Spearphishing .docm attachment targeting finance department. Macro execution blocked by EDR. 3 users targeted, 1 opened attachment.",
            "ai_summary": (
                "Targeted spearphishing attack against finance department. Malicious Word document with VBA macro "
                "payload designed to download Emotet loader. EDR successfully blocked macro execution.\n\n"
                "Campaign Details:\n"
                "  • Sender domain: contoso-corp.xyz (lookalike for legitimate vendor)\n"
                "  • Subject: 'Q1 Financial Report — URGENT ACTION REQUIRED'\n"
                "  • Attachment: Q1_Report.docm (embedded VBA + PowerShell dropper)\n"
                "  • 3 finance users targeted — 1 opened attachment\n\n"
                "No breach confirmed. Security awareness training initiated for affected team."
            ),
            "timeline": [
                {"time": "11:10:00", "event": "Phishing email delivered to 3 finance department inboxes", "level": "medium"},
                {"time": "11:15:00", "event": "User j.smith opens Q1_Report.docm on win-dc-01", "level": "high"},
                {"time": "11:15:30", "event": "EDR blocks VBA macro execution — WINWORD.EXE → cmd.exe", "level": "info"},
                {"time": "11:20:00", "event": "Incident created — email quarantined across all mailboxes", "level": "info"},
                {"time": "12:00:00", "event": "Domain contoso-corp.xyz sinkholed", "level": "info"},
            ],
            "logs": [
                "2026-05-08T11:15:30 [EDR:BLOCK]    WINWORD.EXE attempting to spawn cmd.exe — BLOCKED",
                "2026-05-08T11:15:00 [SYSMON:11]    File created: C:\\Users\\jsmith\\Downloads\\Q1_Report.docm",
                "2026-05-08T11:10:00 [MAILGW:QUARANTINE] From: accounts@contoso-corp.xyz Subject: Q1 Report",
                "2026-05-08T11:10:00 [WAZUH:31166]  Malicious attachment detected in email gateway",
            ],
            "recommendations": [
                "Block sender domain contoso-corp.xyz at mail gateway (permanent)",
                "Run targeted security awareness training for finance team",
                "Enable Protected View for all Office documents from Internet zone",
                "Enforce DMARC/DKIM/SPF and reject unauthenticated email",
                "Deploy sandboxed email attachment detonation before delivery",
            ],
            "playbook": {
                "blocked_ips": ["203.0.113.42"],
                "isolated_machines": [],
                "disabled_accounts": [],
                "firewall_rules": ["Email gateway: Block domain contoso-corp.xyz", "DNS sinkhole: contoso-corp.xyz"],
            },
            "similar": ["INC-2026-0136"],
            "tags": ["phishing", "T1566.001", "macro", "finance", "emotet"],
        },
        {
            "id": "INC-2026-0140",
            "severity": "critical",
            "attack_type": "Privilege Escalation",
            "src_ip": "10.0.0.55",
            "target_host": "auth-svc",
            "status": "Investigating",
            "mitre_id": "T1078.003",
            "mitre_name": "Valid Accounts: Local Accounts",
            "detection_date": "2026-05-07 03:47",
            "analyst": "L. Okafor",
            "risk_score": 89,
            "alerts_count": 178,
            "description": "Critical privilege escalation on auth-svc. Local account created with sudo at 03:47 UTC — off-hours activity strongly suggests unauthorized access.",
            "ai_summary": (
                "Critical privilege escalation event on authentication service. New local admin account created at "
                "03:47 UTC via CVE-2024-1234 kernel exploit.\n\n"
                "Key Risk Factors:\n"
                "  • auth-svc holds OAuth tokens and session credentials for ALL platform services\n"
                "  • Off-hours activity (03:47 UTC) — no authorized change window\n"
                "  • CVE-2024-1234 exploit confirmed (unpatched kernel)\n"
                "  • Account 'svc_maint' added to sudoers silently\n\n"
                "Full incident response engaged. OAuth token rotation in progress."
            ),
            "timeline": [
                {"time": "03:35:00", "event": "Initial SSH login via svc_legacy key from 10.0.0.55", "level": "low"},
                {"time": "03:40:00", "event": "CVE-2024-1234 kernel exploit attempt detected", "level": "high"},
                {"time": "03:44:00", "event": "Exploit successful — root shell obtained", "level": "critical"},
                {"time": "03:47:00", "event": "New user svc_maint created and added to sudoers", "level": "critical"},
                {"time": "03:48:00", "event": "SENTINEL alert — L. Okafor paged on-call", "level": "info"},
                {"time": "04:00:00", "event": "OAuth tokens rotated — svc_maint and svc_legacy disabled", "level": "info"},
            ],
            "logs": [
                "2026-05-07T03:47:00 [WAZUH:5902]   New user added to system. user=svc_maint groups=sudo",
                "2026-05-07T03:47:00 [SYSLOG]        usermod -aG sudo svc_maint",
                "2026-05-07T03:44:00 [WAZUH:40106]   Kernel exploit attempt — CVE-2024-1234 pattern matched",
                "2026-05-07T03:40:00 [WAZUH:5715]    SSHD session opened for svc_legacy from 10.0.0.55",
                "2026-05-07T03:35:00 [SYSLOG]         Accepted publickey for svc_legacy from 10.0.0.55 port 51234",
            ],
            "recommendations": [
                "Immediately disable and audit accounts svc_maint and svc_legacy",
                "Rotate ALL OAuth tokens and session secrets stored on auth-svc",
                "Patch CVE-2024-1234 — kernel privilege escalation (kernel ≥ 6.8.4 required)",
                "Implement privileged access workstations (PAW) for all admin operations",
                "Enable auditd with immutable log mode on all critical authentication servers",
                "Review and rotate all service-to-service credentials",
            ],
            "playbook": {
                "blocked_ips": ["10.0.0.55"],
                "isolated_machines": [],
                "disabled_accounts": ["svc_maint", "svc_legacy"],
                "firewall_rules": ["Restrict auth-svc inbound SSH to known admin IPs only"],
            },
            "similar": ["INC-2026-0144", "INC-2026-0132"],
            "tags": ["privilege-escalation", "T1078.003", "CVE-2024-1234", "off-hours", "auth-svc"],
        },
        {
            "id": "INC-2026-0139",
            "severity": "high",
            "attack_type": "Data Exfiltration",
            "src_ip": "45.76.221.13",
            "target_host": "db-master",
            "status": "Contained",
            "mitre_id": "T1048",
            "mitre_name": "Exfiltration Over Alternative Protocol",
            "detection_date": "2026-05-06 19:33",
            "analyst": "S. Iyer",
            "risk_score": 85,
            "alerts_count": 312,
            "description": "4.7 GB data exfiltrated via DNS tunneling from db-master to external C2. GDPR breach notification assessment in progress.",
            "ai_summary": (
                "Data exfiltration via DNS tunneling detected. 4.7 GB of data encoded in DNS TXT queries over "
                "45 minutes to 45.76.221.13.\n\n"
                "Exfiltration Profile:\n"
                "  • Tool: IODINE DNS tunneling (confirmed by Suricata signature)\n"
                "  • Volume: 4.7 GB across 14,800+ DNS TXT queries\n"
                "  • Encoding: base64 chunking in subdomain labels\n"
                "  • Data origin: /tmp/.hidden_backup.sql.gz (DB dump)\n\n"
                "GDPR Impact: Likely PII exposure — 72-hour notification window active. "
                "Legal team has been engaged."
            ),
            "timeline": [
                {"time": "18:55:00", "event": "Hidden DB dump file created: /tmp/.hidden_backup.sql.gz", "level": "high"},
                {"time": "19:00:00", "event": "Anomalous DNS query volume from db-master (baseline: 40/min → 380/min)", "level": "medium"},
                {"time": "19:15:00", "event": "Suricata: DNS TXT pattern matches IODINE tunneling tool", "level": "high"},
                {"time": "19:33:00", "event": "Incident created — DNS blocked, machine contained", "level": "critical"},
                {"time": "19:45:00", "event": "4.7 GB transfer quantified — GDPR team notified", "level": "critical"},
            ],
            "logs": [
                "2026-05-06T19:33:00 [SURICATA:2025431]  ET DNS Tunneling via IODINE — Confirmed",
                "2026-05-06T19:15:00 [DNS]                TXT query: aGVsbG8gd29ybGQ=.exfil.45.76.221.13",
                "2026-05-06T19:00:00 [FIREWALL]           ALLOW UDP db-master:56789 -> 45.76.221.13:53",
                "2026-05-06T18:55:00 [WAZUH:554]          File created: /tmp/.hidden_backup.sql.gz (2.1 GB)",
            ],
            "recommendations": [
                "Block all direct DNS traffic from internal servers — route through corporate DNS resolver only",
                "Implement DNS Response Policy Zone (RPZ) filtering with threat intel feeds",
                "Assess GDPR breach notification requirements (72-hour countdown active)",
                "Forensic analysis of db-master to determine exact data scope and classification",
                "Implement DLP solutions to detect and block large file staging operations",
            ],
            "playbook": {
                "blocked_ips": ["45.76.221.13"],
                "isolated_machines": ["db-master"],
                "disabled_accounts": [],
                "firewall_rules": ["Block UDP/53 from db-master to external IPs", "DNS sinkhole: 45.76.221.13"],
            },
            "similar": ["INC-2026-0144", "INC-2026-0134"],
            "tags": ["exfiltration", "dns-tunneling", "T1048", "GDPR", "PII"],
        },
        {
            "id": "INC-2026-0138",
            "severity": "medium",
            "attack_type": "SSH Brute Force",
            "src_ip": "192.168.1.105",
            "target_host": "vpn-gw",
            "status": "Resolved",
            "mitre_id": "T1110",
            "mitre_name": "Brute Force",
            "detection_date": "2026-05-05 08:12",
            "analyst": "SOC-AI (Auto)",
            "risk_score": 45,
            "alerts_count": 89,
            "description": "SSH brute force from internal IT laptop 192.168.1.105 targeting VPN gateway. Root cause: misconfigured Ansible playbook.",
            "ai_summary": (
                "Internal SSH brute force from 192.168.1.105 against vpn-gw. Pattern analysis indicates "
                "misconfigured automation tool rather than malicious activity.\n\n"
                "Analysis:\n"
                "  • Source IP belongs to IT department laptop (asset: ansible-control-01)\n"
                "  • Authentication user: 'ansible' (service account)\n"
                "  • Pattern: rapid sequential attempts (no delay) — typical of misconfigured script\n"
                "  • No lateral movement or persistence indicators\n\n"
                "Verdict: FALSE POSITIVE — Ansible playbook updated with wrong credentials after rotation. "
                "Playbook corrected, fail2ban exception added."
            ),
            "timeline": [
                {"time": "08:05:00", "event": "Auth failures begin from 192.168.1.105 for ansible user", "level": "low"},
                {"time": "08:12:00", "event": "SENTINEL auto-creates incident (threshold exceeded)", "level": "medium"},
                {"time": "08:20:00", "event": "Analyst confirms source = IT laptop ansible-control-01", "level": "info"},
                {"time": "08:25:00", "event": "IT team contacted — misconfigured Ansible vault credential", "level": "info"},
                {"time": "08:45:00", "event": "Resolved — playbook corrected, fail2ban whitelist updated", "level": "info"},
            ],
            "logs": [
                "2026-05-05T08:05:00 [WAZUH:5760]  sshd: authentication failed. srcip=192.168.1.105 user=ansible",
                "2026-05-05T08:05:02 [WAZUH:5760]  sshd: authentication failed. srcip=192.168.1.105 user=ansible",
                "2026-05-05T08:05:04 [WAZUH:5758]  Maximum authentication attempts exceeded. srcip=192.168.1.105",
            ],
            "recommendations": [
                "Add Ansible service account SSH key to authorized_keys on all managed hosts after each rotation",
                "Implement credential rotation automation to update Ansible Vault simultaneously",
                "Whitelist known automation IPs in fail2ban jail.local configuration",
                "Add change validation step to Ansible playbook runs (dry-run first)",
            ],
            "playbook": {
                "blocked_ips": [],
                "isolated_machines": [],
                "disabled_accounts": [],
                "firewall_rules": ["fail2ban whitelist: 192.168.1.105 (ansible-control-01)"],
            },
            "similar": ["INC-2026-0145", "INC-2026-0134"],
            "tags": ["ssh", "false-positive", "automation", "T1110", "ansible"],
        },
        {
            "id": "INC-2026-0137",
            "severity": "high",
            "attack_type": "Lateral Movement",
            "src_ip": "10.0.2.15",
            "target_host": "win-dc-01",
            "status": "Closed",
            "mitre_id": "T1021.001",
            "mitre_name": "Remote Desktop Protocol",
            "detection_date": "2026-05-04 15:22",
            "analyst": "M. Hartmann",
            "risk_score": 74,
            "alerts_count": 56,
            "description": "RDP lateral movement from compromised workstation to domain controller. Pass-the-Hash detected. Session active 4 minutes before termination.",
            "ai_summary": (
                "Lateral movement via RDP from compromised workstation 10.0.2.15 to win-dc-01. "
                "Attacker used Pass-the-Hash technique to authenticate as domain admin j.smith.\n\n"
                "Session Details:\n"
                "  • Duration: 4 minutes 12 seconds\n"
                "  • Actions observed: directory listing, user enumeration\n"
                "  • No persistence mechanisms deployed\n"
                "  • No data staged for exfiltration\n\n"
                "Response: Session terminated, account disabled, all domain admin passwords rotated."
            ),
            "timeline": [
                {"time": "15:10:00", "event": "Workstation 10.0.2.15 compromised (Emotet initial access)", "level": "high"},
                {"time": "15:15:00", "event": "Anomalous RDP connection from 10.0.2.15 to win-dc-01", "level": "high"},
                {"time": "15:18:00", "event": "Pass-the-Hash technique detected — NTLM relay", "level": "critical"},
                {"time": "15:22:00", "event": "RDP session terminated — account j.smith disabled", "level": "info"},
                {"time": "16:00:00", "event": "All domain admin passwords rotated", "level": "info"},
                {"time": "16:30:00", "event": "Incident closed — no persistent access found", "level": "info"},
            ],
            "logs": [
                "2026-05-04T15:18:00 [WAZUH:18109]  Pass-the-Hash attack detected. src=10.0.2.15 user=j.smith",
                "2026-05-04T15:15:00 [WEV:4624]      Account logon: DOMAIN\\j.smith on win-dc-01 Type=10 (RemoteInteractive)",
                "2026-05-04T15:14:00 [SURICATA]       ET EXPLOIT SMB NTLM Relay Attack Pattern",
                "2026-05-04T15:10:00 [EDR]             Mimikatz-like credential dumping detected on 10.0.2.15",
            ],
            "recommendations": [
                "Enable Credential Guard on all workstations to prevent NTLM hash extraction",
                "Restrict RDP access to jump servers only — disable direct DC RDP from workstations",
                "Add all privileged accounts to Protected Users security group",
                "Deploy Microsoft LAPS for randomized local admin passwords",
                "Implement Network Level Authentication (NLA) for all RDP connections",
            ],
            "playbook": {
                "blocked_ips": ["10.0.2.15"],
                "isolated_machines": [],
                "disabled_accounts": ["j.smith"],
                "firewall_rules": ["Block RDP (3389) between workstations", "Allow RDP only from jump server 10.0.100.5"],
            },
            "similar": ["INC-2026-0140"],
            "tags": ["lateral-movement", "RDP", "pass-the-hash", "T1021.001", "domain-controller"],
        },
        {
            "id": "INC-2026-0136",
            "severity": "medium",
            "attack_type": "DNS Tunneling",
            "src_ip": "23.106.160.88",
            "target_host": "fw-core",
            "status": "Resolved",
            "mitre_id": "T1071.004",
            "mitre_name": "DNS Command & Control",
            "detection_date": "2026-05-03 12:08",
            "analyst": "S. Iyer",
            "risk_score": 52,
            "alerts_count": 198,
            "description": "DNS tunneling probe from fw-core to 23.106.160.88. Low-volume reconnaissance — no data exfiltration confirmed. Pre-attack mapping suspected.",
            "ai_summary": (
                "DNS tunneling reconnaissance detected originating from fw-core. Low query volume (198 queries over "
                "8 minutes) suggests initial probing phase rather than active exfiltration.\n\n"
                "Assessment: Pre-attack mapping activity. No data confirmed exfiltrated. "
                "Proactively blocked before escalation."
            ),
            "timeline": [
                {"time": "12:00:00", "event": "Unusual DNS TXT query rate from fw-core (×24/min baseline → ×198/8min)", "level": "medium"},
                {"time": "12:08:00", "event": "Suricata alert — DNS tunneling signature triggered", "level": "high"},
                {"time": "12:15:00", "event": "DNS traffic to 23.106.160.88 blocked — incident resolved", "level": "info"},
            ],
            "logs": [
                "2026-05-03T12:08:00 [SURICATA:2025431]  ET DNS Tunneling via IODINE (probe phase)",
                "2026-05-03T12:00:00 [DNS]                198 TXT queries in 8min: *.exfil.23.106.160.88",
            ],
            "recommendations": [
                "Implement DNS monitoring with anomaly detection — alert on TXT query volume spikes",
                "Block DNS TXT queries for non-business domains at recursive resolver",
                "Deploy DNS firewall with threat intelligence feeds (e.g. Cisco Umbrella)",
            ],
            "playbook": {
                "blocked_ips": ["23.106.160.88"],
                "isolated_machines": [],
                "disabled_accounts": [],
                "firewall_rules": ["DNS sinkhole: 23.106.160.88", "Block UDP/53 to non-corporate resolvers from fw-core"],
            },
            "similar": ["INC-2026-0139"],
            "tags": ["dns-tunneling", "C2", "T1071.004", "reconnaissance"],
        },
        {
            "id": "INC-2026-0135",
            "severity": "critical",
            "attack_type": "Web Shell Upload",
            "src_ip": "195.178.110.51",
            "target_host": "web-prod-01",
            "status": "Closed",
            "mitre_id": "T1505.003",
            "mitre_name": "Server Software Component: Web Shell",
            "detection_date": "2026-05-02 20:55",
            "analyst": "M. Hartmann",
            "risk_score": 94,
            "alerts_count": 67,
            "description": "PHP web shell uploaded via unrestricted file upload. RCE active for 7 minutes before EDR detection. Server reimaged from clean snapshot.",
            "ai_summary": (
                "Critical web shell installation on production web server. PHP reverse shell uploaded via "
                "unrestricted file upload vulnerability in /upload endpoint.\n\n"
                "Attacker achieved Remote Code Execution (RCE) for approximately 7 minutes:\n"
                "  • Commands observed: id, uname -a, cat /etc/passwd, ls /var/www\n"
                "  • No pivot attempts detected in 7-minute window\n"
                "  • File: invoice_march.php (PHP reverse shell — PentestMonkey variant)\n\n"
                "Immediate Actions: Web server isolated → reimaged from 2026-05-01 snapshot."
            ),
            "timeline": [
                {"time": "20:48:00", "event": "File upload: invoice_march.php to /var/www/html/uploads/", "level": "high"},
                {"time": "20:50:00", "event": "Web shell accessed via HTTP — RCE established", "level": "critical"},
                {"time": "20:52:00", "event": "Commands executed: id, uname, passwd, ls", "level": "critical"},
                {"time": "20:55:00", "event": "Wazuh FIM alert — incident created, server isolated", "level": "critical"},
                {"time": "21:30:00", "event": "Server reimaged from 2026-05-01 clean snapshot", "level": "info"},
            ],
            "logs": [
                "2026-05-02T20:50:00 [WAZUH:31301]  Web shell detected: /var/www/html/uploads/invoice_march.php",
                "2026-05-02T20:50:10 [SYSLOG]        www-data: id → uid=33(www-data) gid=33(www-data)",
                "2026-05-02T20:48:00 [NGINX]          POST /upload HTTP/1.1 200 195.178.110.51 — invoice_march.php",
                "2026-05-02T20:48:00 [WAZUH:554]     FIM: New file created /var/www/html/uploads/invoice_march.php",
            ],
            "recommendations": [
                "Implement file type validation — whitelist permitted extensions (.jpg, .png, .pdf only)",
                "Store uploaded files outside webroot directory (/var/uploads/ not /var/www/html/uploads/)",
                "Execute uploaded files in sandboxed environment — never serve PHP from upload directory",
                "Deploy RASP (Runtime Application Self-Protection) for real-time RCE detection",
                "Implement Content Security Policy (CSP) and X-Content-Type-Options headers",
            ],
            "playbook": {
                "blocked_ips": ["195.178.110.51"],
                "isolated_machines": ["web-prod-01"],
                "disabled_accounts": [],
                "firewall_rules": ["Block 195.178.110.51 at WAF and border firewall", "Disable PHP execution in /uploads/"],
            },
            "similar": ["INC-2026-0142"],
            "tags": ["web-shell", "RCE", "file-upload", "T1505.003", "PHP"],
        },
        {
            "id": "INC-2026-0134",
            "severity": "medium",
            "attack_type": "Credential Stuffing",
            "src_ip": "142.250.80.196",
            "target_host": "auth-svc",
            "status": "Resolved",
            "mitre_id": "T1110.004",
            "mitre_name": "Credential Stuffing",
            "detection_date": "2026-05-01 07:30",
            "analyst": "S. Iyer",
            "risk_score": 48,
            "alerts_count": 2341,
            "description": "Large-scale credential stuffing against login API using leaked credential database. 2341 attempts across 45 rotating IPs. MFA blocked all breaches.",
            "ai_summary": (
                "Automated credential stuffing attack using a leaked credential database. 2341 login attempts "
                "distributed across 45 source IPs detected within 90 minutes.\n\n"
                "Positive Outcome:\n"
                "  • MFA enforcement prevented ALL breach attempts (100% block rate)\n"
                "  • Rate limiting triggered after 500 req/min threshold\n"
                "  • Attack ceased after geo-IP blocking of attack cluster\n\n"
                "Recommend: Monitor HaveIBeenPwned for credential leaks matching user base."
            ),
            "timeline": [
                {"time": "07:00:00", "event": "Distributed credential stuffing begins from 45 rotating IPs", "level": "medium"},
                {"time": "07:30:00", "event": "Rate limiting triggered — incident auto-created", "level": "medium"},
                {"time": "08:00:00", "event": "Geo-IP block deployed — all 45 IPs blocked", "level": "info"},
                {"time": "08:30:00", "event": "Attack ceased — incident resolved", "level": "info"},
            ],
            "logs": [
                "2026-05-01T07:30:00 [WAF:RATE]     Rate limit exceeded: 500 req/min on /api/auth/login",
                "2026-05-01T07:15:00 [WAZUH:31151]  Multiple authentication failures from distributed IPs (45 unique)",
                "2026-05-01T07:00:00 [AUTH-SVC]      MFA challenge triggered for 2341 login attempts — all DENIED",
            ],
            "recommendations": [
                "Implement CAPTCHA on login endpoint after 3 consecutive failures",
                "Deploy adaptive MFA with step-up authentication for suspicious geolocations",
                "Subscribe to HaveIBeenPwned Enterprise API for proactive credential leak monitoring",
                "Consider passwordless authentication (WebAuthn/FIDO2) to eliminate credential stuffing risk",
            ],
            "playbook": {
                "blocked_ips": ["142.250.80.196"],
                "isolated_machines": [],
                "disabled_accounts": [],
                "firewall_rules": ["Rate limit /api/auth/login: 10 req/min per IP", "Block ASN AS15169 subnets temporarily"],
            },
            "similar": ["INC-2026-0145", "INC-2026-0138"],
            "tags": ["credential-stuffing", "T1110.004", "MFA", "rate-limiting"],
        },
    ]


# ─────────────────────────────────────────────────────────────────────────────
# Threat Intel enrichment helpers
# ─────────────────────────────────────────────────────────────────────────────

def _fetch_threat_intel(ip: str) -> dict:
    """Call all 5 threat intel APIs in parallel for a given IP."""
    from agents.rag_threat_agent import (
        check_abuseipdb, check_virustotal, check_greynoise,
        check_threatfox, check_urlhaus,
    )
    with ThreadPoolExecutor(max_workers=5) as pool:
        futs = {
            "abuseipdb":  pool.submit(check_abuseipdb,  ip),
            "virustotal": pool.submit(check_virustotal, ip),
            "greynoise":  pool.submit(check_greynoise,  ip),
            "threatfox":  pool.submit(check_threatfox,  ip),
            "urlhaus":    pool.submit(check_urlhaus,    ip),
        }
        return {k: f.result() for k, f in futs.items()}


def _ti_row(key: str, val) -> str:
    return f'<div class="ti-row"><span class="key">{key}</span><span class="val">{val}</span></div>'


def _render_threat_intel_results(results: dict, ip: str):
    """Render the 5 API results as styled cards."""

    # ── AbuseIPDB ────────────────────────────────────────────────────
    ab = results.get("abuseipdb", {})
    vt = results.get("virustotal", {})
    gn = results.get("greynoise", {})
    tf = results.get("threatfox", {})
    uh = results.get("urlhaus", {})

    # --- AbuseIPDB card ---
    if "error" not in ab:
        score = ab.get("abuse_confidence_score", 0) or 0
        card_cls = "danger" if score >= 75 else "warning" if score >= 30 else "safe"
        score_cls = "red" if score >= 75 else "yellow" if score >= 30 else "green"
        rows = (
            _ti_row("Country", ab.get("country") or "—")
            + _ti_row("ISP", ab.get("isp") or "—")
            + _ti_row("Reports", ab.get("total_reports") or 0)
            + _ti_row("Last seen", (ab.get("last_reported") or "—")[:10])
        )
        ab_html = (
            f'<div class="ti-card {card_cls}">'
            f'<div class="ti-src">ABUSEIPDB</div>'
            f'<div class="ti-score {score_cls}">{score}<span style="font-size:12px;color:#64748b;">/100</span></div>'
            f'<div class="ti-label">Abuse Confidence</div>'
            f'<div style="margin-top:8px;">{rows}</div>'
            f'</div>'
        )
    else:
        ab_html = f'<div class="ti-card unknown"><div class="ti-src">ABUSEIPDB</div><div class="ti-error">{ab["error"]}</div></div>'

    # --- VirusTotal card ---
    if "error" not in vt:
        mal = vt.get("malicious", 0) or 0
        sus = vt.get("suspicious", 0) or 0
        total_vt = mal + sus + (vt.get("harmless", 0) or 0) + (vt.get("undetected", 0) or 0)
        card_cls = "danger" if mal >= 5 else "warning" if mal >= 1 else "safe"
        score_cls = "red" if mal >= 5 else "yellow" if mal >= 1 else "green"
        rows = (
            _ti_row("Malicious", mal)
            + _ti_row("Suspicious", sus)
            + _ti_row("Harmless", vt.get("harmless", 0) or 0)
            + _ti_row("Owner", (vt.get("owner") or "—")[:25])
            + _ti_row("Country", vt.get("country") or "—")
        )
        vt_html = (
            f'<div class="ti-card {card_cls}">'
            f'<div class="ti-src">VIRUSTOTAL</div>'
            f'<div class="ti-score {score_cls}">{mal}<span style="font-size:12px;color:#64748b;">/{total_vt} engines</span></div>'
            f'<div class="ti-label">Malicious detections</div>'
            f'<div style="margin-top:8px;">{rows}</div>'
            f'</div>'
        )
    else:
        vt_html = f'<div class="ti-card unknown"><div class="ti-src">VIRUSTOTAL</div><div class="ti-error">{vt["error"]}</div></div>'

    # --- GreyNoise card ---
    if "error" not in gn:
        noise = gn.get("noise", False)
        classification = gn.get("classification") or "unclassified"
        card_cls = "danger" if classification == "malicious" else "warning" if noise else "neutral"
        score_val = classification.upper() if classification else ("NOISE" if noise else "CLEAN")
        score_cls = "red" if classification == "malicious" else "yellow" if noise else "blue"
        rows = (
            _ti_row("Noise", "YES" if noise else "NO")
            + _ti_row("RIOT", "YES" if gn.get("riot") else "NO")
            + _ti_row("Name", (gn.get("name") or "—")[:25])
            + _ti_row("Last seen", (gn.get("last_seen") or "—")[:10])
        )
        gn_html = (
            f'<div class="ti-card {card_cls}">'
            f'<div class="ti-src">GREYNOISE</div>'
            f'<div class="ti-score {score_cls}" style="font-size:14px;margin-top:4px;">{score_val}</div>'
            f'<div class="ti-label">Classification</div>'
            f'<div style="margin-top:8px;">{rows}</div>'
            f'</div>'
        )
    else:
        gn_html = f'<div class="ti-card unknown"><div class="ti-src">GREYNOISE</div><div class="ti-error">{gn["error"]}</div></div>'

    # --- ThreatFox card ---
    if "error" not in tf:
        found = tf.get("found", False)
        card_cls = "danger" if found else "safe"
        iocs = tf.get("iocs", [])
        score_val = f"{tf.get('total_iocs', 0)} IOCs" if found else "CLEAN"
        score_cls = "red" if found else "green"
        ioc_items = "".join(
            f'<div class="ti-ioc-item">{i.get("threat_type","?")} · {i.get("malware","?")} · conf {i.get("confidence_level","?")}%</div>'
            for i in iocs
        ) if iocs else ""
        tf_html = (
            f'<div class="ti-card {card_cls}">'
            f'<div class="ti-src">THREATFOX</div>'
            f'<div class="ti-score {score_cls}" style="font-size:16px;margin-top:4px;">{score_val}</div>'
            f'<div class="ti-label">Known IOCs</div>'
            f'{ioc_items}'
            f'</div>'
        )
    else:
        tf_html = f'<div class="ti-card unknown"><div class="ti-src">THREATFOX</div><div class="ti-error">{tf["error"]}</div></div>'

    # --- URLHaus card ---
    if "error" not in uh:
        found = uh.get("found", False)
        card_cls = "danger" if found else "safe"
        score_val = f"{uh.get('urls_count', 0)} URLs" if found else "CLEAN"
        score_cls = "red" if found else "green"
        bl = uh.get("blacklists", {})
        bl_str = ", ".join(f"{k}:{v}" for k, v in bl.items()) if bl else "—"
        urls = uh.get("urls", [])
        url_items = "".join(
            f'<div class="ti-ioc-item">[{u.get("url_status","?")}] {(u.get("url") or "")[:50]}</div>'
            for u in urls
        ) if urls else ""
        uh_html = (
            f'<div class="ti-card {card_cls}">'
            f'<div class="ti-src">URLHAUS</div>'
            f'<div class="ti-score {score_cls}" style="font-size:16px;margin-top:4px;">{score_val}</div>'
            f'<div class="ti-label">Malware URLs</div>'
            + (_ti_row("Blacklists", bl_str[:35]) if found else "")
            + url_items
            + f'</div>'
        )
    else:
        uh_html = f'<div class="ti-card unknown"><div class="ti-src">URLHAUS</div><div class="ti-error">{uh["error"]}</div></div>'

    st.markdown(
        f'<div class="ti-grid">{ab_html}{vt_html}{gn_html}{tf_html}{uh_html}</div>',
        unsafe_allow_html=True,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Detail panel renderer
# ─────────────────────────────────────────────────────────────────────────────

def _render_detail(inc: dict, sev_badge):
    sev = inc["severity"]
    risk = inc["risk_score"]
    risk_cls = {"critical": "risk-crit", "high": "risk-high", "medium": "risk-med"}.get(sev, "risk-low")

    # ── Header strip ──────────────────────────────────────────────────
    col_id, col_sev, col_stat, col_risk = st.columns([3, 1.5, 1.5, 2])
    with col_id:
        st.markdown(
            f'<div class="detail-title">{inc["id"]}</div>'
            f'<div style="font-family:\'Share Tech Mono\',monospace;font-size:10px;color:#4a7fa5;">'
            f'{inc["attack_type"]} &nbsp;·&nbsp; {inc["detection_date"]}'
            f'&nbsp;·&nbsp; 👤 {inc["analyst"]}</div>',
            unsafe_allow_html=True,
        )
    with col_sev:
        st.markdown(
            f'<div style="font-family:\'Share Tech Mono\',monospace;font-size:10px;color:#4a7fa5;margin-bottom:4px;">SEVERITY</div>'
            f'{sev_badge(sev)}',
            unsafe_allow_html=True,
        )
    with col_stat:
        st.markdown(
            f'<div style="font-family:\'Share Tech Mono\',monospace;font-size:10px;color:#4a7fa5;margin-bottom:4px;">STATUS</div>'
            f'{status_badge(inc["status"])}',
            unsafe_allow_html=True,
        )
    with col_risk:
        st.markdown(
            f'<div style="font-family:\'Share Tech Mono\',monospace;font-size:10px;color:#4a7fa5;">RISK SCORE</div>'
            f'<div style="font-family:\'Share Tech Mono\',monospace;font-size:24px;font-weight:700;color:#e6f1ff;">'
            f'{risk}<span style="font-size:12px;color:#4a7fa5;">/100</span></div>'
            f'<div class="risk-wrap"><div class="risk-fill {risk_cls}" style="width:{risk}%;"></div></div>',
            unsafe_allow_html=True,
        )

    st.markdown("---")

    # ── Tags ──────────────────────────────────────────────────────────
    tag_html = " ".join(f'<span class="tag-chip">#{t}</span>' for t in inc.get("tags", []))
    st.markdown(tag_html, unsafe_allow_html=True)
    st.markdown("<br>", unsafe_allow_html=True)

    # ── Tabs ──────────────────────────────────────────────────────────
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "🧠 AI Summary",
        "⏱ Timeline",
        "📜 Correlated Logs",
        "🎯 MITRE + Recs",
        "🔧 Playbook",
    ])

    # Tab 1 — AI Summary
    with tab1:
        st.markdown(
            f'<div class="ai-box">{inc["ai_summary"]}</div>',
            unsafe_allow_html=True,
        )
        st.markdown("<br>", unsafe_allow_html=True)
        # Similar incidents
        if inc.get("similar"):
            st.markdown(
                '<div style="font-family:\'Share Tech Mono\',monospace;font-size:10px;'
                'color:#4a7fa5;letter-spacing:.1em;margin-bottom:8px;">AI CORRELATION · SIMILAR INCIDENTS</div>',
                unsafe_allow_html=True,
            )
            chips = " ".join(f'<span class="sim-chip">{s}</span>' for s in inc["similar"])
            st.markdown(chips, unsafe_allow_html=True)

        # ── Threat Intel enrichment ───────────────────────────────────
        st.markdown(
            '<div class="section-hdr" style="margin-top:20px;">// ENRICHISSEMENT THREAT INTEL · '
            f'{inc["src_ip"]}</div>',
            unsafe_allow_html=True,
        )

        cache_key = f"_ti_{inc['id']}"

        if cache_key not in st.session_state:
            col_btn, _ = st.columns([2, 5])
            with col_btn:
                if st.button(
                    "🔍  Enrichir depuis les APIs",
                    key=f"btn_ti_{inc['id']}",
                    help="Interroge AbuseIPDB · VirusTotal · GreyNoise · ThreatFox · URLHaus",
                ):
                    with st.spinner("Interrogation des sources threat intel en cours..."):
                        st.session_state[cache_key] = _fetch_threat_intel(inc["src_ip"])
                    st.rerun()
        else:
            col_res, col_clear = st.columns([6, 1])
            with col_clear:
                if st.button("↺ Rafraîchir", key=f"btn_ti_clear_{inc['id']}"):
                    del st.session_state[cache_key]
                    st.rerun()
            _render_threat_intel_results(st.session_state[cache_key], inc["src_ip"])

    # Tab 2 — Timeline
    with tab2:
        tl_html = ""
        for entry in inc["timeline"]:
            lvl = entry["level"]
            tl_html += (
                f'<div class="tl-row">'
                f'<div class="tl-dot {lvl}"></div>'
                f'<div class="tl-time">{entry["time"]}</div>'
                f'<div class="tl-text">{entry["event"]}</div>'
                f'</div>'
            )
        st.markdown(f'<div class="glass-panel" style="padding:10px 16px;">{tl_html}</div>', unsafe_allow_html=True)

    # Tab 3 — Correlated Logs
    with tab3:
        log_html = ""
        for log in inc["logs"]:
            log_html += f'<div class="log-line">{log}</div>'
        st.markdown(
            f'<div class="glass-panel" style="padding:12px 16px;background:rgba(0,20,10,.6);">{log_html}</div>',
            unsafe_allow_html=True,
        )

    # Tab 4 — MITRE + Recommendations
    with tab4:
        mitre_col, _ = st.columns([2, 1])
        with mitre_col:
            st.markdown(
                f'<div class="glass-panel" style="padding:16px 20px;">'
                f'<div style="font-family:\'Share Tech Mono\',monospace;font-size:10px;color:#4a7fa5;margin-bottom:10px;">MITRE ATT&CK MAPPING</div>'
                f'<div style="display:flex;align-items:center;gap:14px;margin-bottom:8px;">'
                f'<span class="mitre-chip">{inc["mitre_id"]}</span>'
                f'<span style="font-family:\'Share Tech Mono\',monospace;font-size:13px;color:#c9d1d9;">{inc["mitre_name"]}</span>'
                f'</div>'
                f'<div style="font-family:\'Share Tech Mono\',monospace;font-size:10px;color:#4a7fa5;">Attack Type: {inc["attack_type"]}</div>'
                f'</div>',
                unsafe_allow_html=True,
            )
        st.markdown(
            '<div style="font-family:\'Share Tech Mono\',monospace;font-size:10px;'
            'color:#4a7fa5;letter-spacing:.1em;margin:14px 0 8px;">AI RECOMMENDATIONS</div>',
            unsafe_allow_html=True,
        )
        recs_html = ""
        for i, rec in enumerate(inc["recommendations"], 1):
            recs_html += f'<div class="rec-item"><span style="color:#00aaff;">{i:02d}.</span> {rec}</div>'
        st.markdown(recs_html, unsafe_allow_html=True)

    # Tab 5 — Playbook
    with tab5:
        pb = inc["playbook"]
        left_pb, right_pb = st.columns(2)

        with left_pb:
            st.markdown(
                '<div style="font-family:\'Share Tech Mono\',monospace;font-size:10px;color:#4a7fa5;margin-bottom:8px;">BLOCKED IPs</div>',
                unsafe_allow_html=True,
            )
            if pb["blocked_ips"]:
                html = " ".join(f'<span class="pb-tag blocked">🚫 {ip}</span>' for ip in pb["blocked_ips"])
                st.markdown(html, unsafe_allow_html=True)
            else:
                st.markdown('<span style="font-family:\'Share Tech Mono\',monospace;font-size:11px;color:#1e3a52;">None</span>', unsafe_allow_html=True)

            st.markdown("<br>", unsafe_allow_html=True)
            st.markdown(
                '<div style="font-family:\'Share Tech Mono\',monospace;font-size:10px;color:#4a7fa5;margin-bottom:8px;">ISOLATED MACHINES</div>',
                unsafe_allow_html=True,
            )
            if pb["isolated_machines"]:
                html = " ".join(f'<span class="pb-tag isolated">⚠ {m}</span>' for m in pb["isolated_machines"])
                st.markdown(html, unsafe_allow_html=True)
            else:
                st.markdown('<span style="font-family:\'Share Tech Mono\',monospace;font-size:11px;color:#1e3a52;">None</span>', unsafe_allow_html=True)

        with right_pb:
            st.markdown(
                '<div style="font-family:\'Share Tech Mono\',monospace;font-size:10px;color:#4a7fa5;margin-bottom:8px;">DISABLED ACCOUNTS</div>',
                unsafe_allow_html=True,
            )
            if pb["disabled_accounts"]:
                html = " ".join(f'<span class="pb-tag disabled">🔒 {a}</span>' for a in pb["disabled_accounts"])
                st.markdown(html, unsafe_allow_html=True)
            else:
                st.markdown('<span style="font-family:\'Share Tech Mono\',monospace;font-size:11px;color:#1e3a52;">None</span>', unsafe_allow_html=True)

            st.markdown("<br>", unsafe_allow_html=True)
            st.markdown(
                '<div style="font-family:\'Share Tech Mono\',monospace;font-size:10px;color:#4a7fa5;margin-bottom:8px;">FIREWALL RULES APPLIED</div>',
                unsafe_allow_html=True,
            )
            if pb["firewall_rules"]:
                html = "".join(f'<span class="pb-tag rule" style="display:block;margin:3px 0;">▶ {r}</span>' for r in pb["firewall_rules"])
                st.markdown(html, unsafe_allow_html=True)
            else:
                st.markdown('<span style="font-family:\'Share Tech Mono\',monospace;font-size:11px;color:#1e3a52;">None</span>', unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# Analytics charts
# ─────────────────────────────────────────────────────────────────────────────

def _render_analytics(incidents: list):
    SEV_COLORS = {
        "critical": "#ef4444", "high": "#f97316",
        "medium": "#eab308", "low": "#3b82f6", "info": "#6b7280",
    }
    CHART_LAYOUT = dict(
        template="plotly_dark",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Share Tech Mono", size=11),
        margin=dict(l=0, r=10, t=10, b=0),
    )

    c1, c2 = st.columns(2)

    # Chart 1 — Incidents by Severity (donut)
    with c1:
        st.markdown('<div class="section-hdr" style="font-size:11px;">🔴 INCIDENTS BY SEVERITY</div>', unsafe_allow_html=True)
        sev_counts = {}
        for inc in incidents:
            sev_counts[inc["severity"]] = sev_counts.get(inc["severity"], 0) + 1
        fig = go.Figure(go.Pie(
            labels=list(sev_counts.keys()),
            values=list(sev_counts.values()),
            hole=0.55,
            marker=dict(colors=[SEV_COLORS.get(s, "#6b7280") for s in sev_counts.keys()],
                        line=dict(color="#050810", width=2)),
            textfont=dict(family="Share Tech Mono", size=11),
            hoverinfo="label+value+percent",
        ))
        fig.update_layout(**CHART_LAYOUT, height=280,
                          legend=dict(font=dict(family="Share Tech Mono", size=10)))
        st.plotly_chart(fig, use_container_width=True)

    # Chart 2 — Attacks by Type
    with c2:
        st.markdown('<div class="section-hdr" style="font-size:11px;">⚡ ATTACKS BY TYPE</div>', unsafe_allow_html=True)
        type_counts = {}
        for inc in incidents:
            type_counts[inc["attack_type"]] = type_counts.get(inc["attack_type"], 0) + 1
        types_sorted = sorted(type_counts.items(), key=lambda x: x[1])
        fig = go.Figure(go.Bar(
            x=[v for _, v in types_sorted],
            y=[k for k, _ in types_sorted],
            orientation="h",
            marker=dict(color="#00aaff", opacity=0.8, line=dict(width=0)),
            text=[v for _, v in types_sorted],
            textposition="outside",
            textfont=dict(family="Share Tech Mono", size=10),
        ))
        fig.update_layout(**CHART_LAYOUT, height=280,
                          xaxis=dict(gridcolor="rgba(255,255,255,.05)"),
                          yaxis=dict(gridcolor="rgba(0,0,0,0)"))
        st.plotly_chart(fig, use_container_width=True)

    c3, c4 = st.columns(2)

    # Chart 3 — Daily Incident Trend (last 14 days)
    with c3:
        st.markdown('<div class="section-hdr" style="font-size:11px;">📈 DAILY INCIDENT TREND</div>', unsafe_allow_html=True)
        rng = random.Random(2026)
        days = pd.date_range(end=datetime.utcnow(), periods=14)
        trend_data = []
        for day in days:
            for sev in ["critical", "high", "medium", "low"]:
                n = rng.randint(0, {"critical": 2, "high": 4, "medium": 6, "low": 3}[sev])
                if n > 0:
                    trend_data.append({"day": day, "severity": sev, "count": n})
        df_trend = pd.DataFrame(trend_data)
        fig = px.area(df_trend, x="day", y="count", color="severity",
                      color_discrete_map=SEV_COLORS)
        fig.update_layout(**CHART_LAYOUT, height=280,
                          xaxis=dict(gridcolor="rgba(255,255,255,.05)"),
                          yaxis=dict(gridcolor="rgba(255,255,255,.05)"),
                          legend=dict(font=dict(family="Share Tech Mono", size=10)))
        st.plotly_chart(fig, use_container_width=True)

    # Chart 4 — Top Attacking IPs
    with c4:
        st.markdown('<div class="section-hdr" style="font-size:11px;">🌐 TOP ATTACKING IPs</div>', unsafe_allow_html=True)
        ip_counts = {}
        for inc in incidents:
            ip_counts[inc["src_ip"]] = ip_counts.get(inc["src_ip"], 0) + inc["alerts_count"]
        top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:8]
        top_ips_sorted = sorted(top_ips, key=lambda x: x[1])
        fig = go.Figure(go.Bar(
            x=[v for _, v in top_ips_sorted],
            y=[k for k, _ in top_ips_sorted],
            orientation="h",
            marker=dict(
                color=[v for _, v in top_ips_sorted],
                colorscale=[[0, "#0d3a5c"], [0.5, "#0077cc"], [1, "#ef4444"]],
                line=dict(width=0),
            ),
            text=[v for _, v in top_ips_sorted],
            textposition="outside",
            textfont=dict(family="Share Tech Mono", size=10),
        ))
        fig.update_layout(**CHART_LAYOUT, height=280,
                          xaxis=dict(gridcolor="rgba(255,255,255,.05)"),
                          yaxis=dict(gridcolor="rgba(0,0,0,0)"))
        st.plotly_chart(fig, use_container_width=True)


# ─────────────────────────────────────────────────────────────────────────────
# Main entry point — called from app.py
# ─────────────────────────────────────────────────────────────────────────────

def render_incident_history(sev_badge, kpi_card):
    # ── CSS ───────────────────────────────────────────────────────────
    st.markdown(INCIDENT_CSS, unsafe_allow_html=True)

    # ── Page header ──────────────────────────────────────────────────
    st.markdown("""
    <div class="sentinel-header">
      <p class="sentinel-title">📚 INCIDENT HISTORY</p>
      <p class="sentinel-sub">VIEW · ANALYZE · MANAGE PREVIOUSLY DETECTED SECURITY INCIDENTS</p>
      <div class="sentinel-badge">◉ HISTORY MODULE</div>
    </div>
    """, unsafe_allow_html=True)

    # ── Session state: incident database ─────────────────────────────
    if "inc_db" not in st.session_state:
        st.session_state.inc_db = get_incident_mock_data()
    if "inc_page" not in st.session_state:
        st.session_state.inc_page = 0
    if "inc_show_detail" not in st.session_state:
        st.session_state.inc_show_detail = True

    inc_all = st.session_state.inc_db

    # ── KPI Summary Cards ─────────────────────────────────────────────
    n_total    = len(inc_all)
    n_crit     = sum(1 for i in inc_all if i["severity"] == "critical")
    n_open     = sum(1 for i in inc_all if i["status"] in ["New", "Investigating"])
    n_resolved = sum(1 for i in inc_all if i["status"] in ["Resolved", "Closed"])

    st.markdown(
        '<div class="kpi-grid" style="grid-template-columns:repeat(4,1fr);">'
        + kpi_card("Total Incidents",     n_total,    f"▲ 3 new today",     "info",  "📊")
        + kpi_card("Critical",            n_crit,     f"▲ 1 escalated",     "crit",  "🔴")
        + kpi_card("Open Investigations", n_open,     "",                   "high",  "🔍")
        + kpi_card("Resolved / Closed",   n_resolved, "▼ avg 4.2h MTTR",   "green", "✓")
        + "</div>",
        unsafe_allow_html=True,
    )

    # ── Search & Filters ──────────────────────────────────────────────
    st.markdown('<div class="section-hdr">// SEARCH & FILTER</div>', unsafe_allow_html=True)

    ATTACK_TYPES = [
        "All Types", "SSH Brute Force", "Phishing Campaign", "Ransomware Staging",
        "C2 Beacon", "SQL Injection", "Privilege Escalation", "Data Exfiltration",
        "Lateral Movement", "DNS Tunneling", "Web Shell Upload", "Credential Stuffing",
    ]
    STATUSES   = ["All Statuses", "New", "Investigating", "Contained", "Resolved", "Closed"]
    SEVERITIES = ["All Severities", "Critical", "High", "Medium", "Low", "Info"]

    col_s, col_sev, col_stat, col_type = st.columns([3, 1.5, 1.5, 2])
    search_q   = col_s.text_input("Search", placeholder="🔍  IP address · MITRE ID · Attack type · Hostname · Username", label_visibility="collapsed")
    sev_f      = col_sev.selectbox("Severity", SEVERITIES, label_visibility="collapsed")
    stat_f     = col_stat.selectbox("Status", STATUSES, label_visibility="collapsed")
    type_f     = col_type.selectbox("Attack Type", ATTACK_TYPES, label_visibility="collapsed")

    # ── Apply filters ─────────────────────────────────────────────────
    inc_filtered = inc_all[:]
    if search_q:
        q = search_q.lower()
        inc_filtered = [
            i for i in inc_filtered
            if q in i["src_ip"].lower()
            or q in i["mitre_id"].lower()
            or q in i["mitre_name"].lower()
            or q in i["attack_type"].lower()
            or q in i["target_host"].lower()
            or q in i.get("description", "").lower()
            or q in " ".join(i.get("tags", [])).lower()
        ]
    if sev_f != "All Severities":
        inc_filtered = [i for i in inc_filtered if i["severity"] == sev_f.lower()]
    if stat_f != "All Statuses":
        inc_filtered = [i for i in inc_filtered if i["status"] == stat_f]
    if type_f != "All Types":
        inc_filtered = [i for i in inc_filtered if i["attack_type"] == type_f]

    # ── Pagination ────────────────────────────────────────────────────
    PAGE_SIZE   = 8
    total_pages = max(1, (len(inc_filtered) + PAGE_SIZE - 1) // PAGE_SIZE)
    st.session_state.inc_page = min(st.session_state.inc_page, total_pages - 1)
    page_slice  = inc_filtered[
        st.session_state.inc_page * PAGE_SIZE:
        (st.session_state.inc_page + 1) * PAGE_SIZE
    ]

    # ── Incident Registry Table ───────────────────────────────────────
    st.markdown('<div class="section-hdr">// INCIDENT REGISTRY</div>', unsafe_allow_html=True)

    if not inc_filtered:
        st.markdown("""
        <div class="glass-panel empty-state">
          <div class="empty-icon">🔍</div>
          <div class="empty-msg">NO INCIDENTS MATCH YOUR FILTERS</div>
          <div class="empty-sub">Try adjusting the search query or filter criteria</div>
        </div>
        """, unsafe_allow_html=True)
    else:
        # Build table HTML
        rows_html = ""
        for inc in page_slice:
            sb = sev_badge(inc["severity"])
            stb = status_badge(inc["status"])
            mitre = f'<span class="mitre-chip">{inc["mitre_id"]}</span>'
            rows_html += (
                f"<tr>"
                f"<td style='color:#00aaff;font-weight:700;'>{inc['id']}</td>"
                f"<td>{sb}</td>"
                f"<td>{inc['attack_type']}</td>"
                f"<td style='color:#00ffaa;'>{inc['src_ip']}</td>"
                f"<td>{inc['target_host']}</td>"
                f"<td>{stb}</td>"
                f"<td>{mitre} {inc['mitre_name']}</td>"
                f"<td style='color:#4a7fa5;'>{inc['detection_date']}</td>"
                f"<td>{inc['analyst']}</td>"
                f"</tr>"
            )

        headers = "".join(
            f"<th>{h}</th>" for h in [
                "INCIDENT ID", "SEVERITY", "ATTACK TYPE", "SOURCE IP",
                "TARGET HOST", "STATUS", "MITRE TECHNIQUE", "DETECTED", "ANALYST",
            ]
        )
        table_html = (
            f'<div class="glass-panel" style="padding:0;overflow-x:auto;">'
            f'<table class="alert-table">'
            f'<thead><tr>{headers}</tr></thead>'
            f'<tbody>{rows_html}</tbody>'
            f'</table></div>'
        )
        st.markdown(table_html, unsafe_allow_html=True)

        # Pagination controls
        p_left, p_mid, p_right = st.columns([1, 3, 1])
        with p_left:
            if st.button("◀ PREV", disabled=(st.session_state.inc_page == 0)):
                st.session_state.inc_page -= 1
                st.rerun()
        with p_mid:
            st.markdown(
                f'<div class="pg-info">'
                f'PAGE {st.session_state.inc_page + 1} / {total_pages}'
                f' &nbsp;·&nbsp; {len(inc_filtered)} INCIDENTS FOUND'
                f'</div>',
                unsafe_allow_html=True,
            )
        with p_right:
            if st.button("NEXT ▶", disabled=(st.session_state.inc_page >= total_pages - 1)):
                st.session_state.inc_page += 1
                st.rerun()

    # ── Incident Detail Panel ─────────────────────────────────────────
    if inc_filtered:
        st.markdown('<div class="section-hdr">// INCIDENT ANALYSIS PANEL</div>', unsafe_allow_html=True)

        inc_ids = [i["id"] for i in inc_filtered]

        sel_col, b_view, b_reopen, b_export = st.columns([3, 1, 1, 1])
        selected_id = sel_col.selectbox(
            "Select Incident",
            inc_ids,
            label_visibility="collapsed",
            format_func=lambda x: f"▶  {x}",
            key="inc_selector",
        )
        selected = next((i for i in inc_filtered if i["id"] == selected_id), None)

        if b_view.button("◉  VIEW DETAILS"):
            st.session_state.inc_show_detail = True

        if b_reopen.button("⟳  REOPEN"):
            if selected and selected["status"] in ("Resolved", "Closed", "Contained"):
                for inc in st.session_state.inc_db:
                    if inc["id"] == selected_id:
                        inc["status"] = "Investigating"
                st.rerun()

        if selected and b_export.button("⬇  EXPORT PDF"):
            report = _generate_export_text(selected)
            st.download_button(
                label="⬇ Download Report",
                data=report.encode("utf-8"),
                file_name=f"{selected_id}_SENTINEL_report.txt",
                mime="text/plain",
            )

        if st.session_state.inc_show_detail and selected:
            with st.container():
                st.markdown('<div class="detail-wrap">', unsafe_allow_html=True)
                _render_detail(selected, sev_badge)
                st.markdown("</div>", unsafe_allow_html=True)

    # ── Analytics Section ─────────────────────────────────────────────
    st.markdown('<div class="section-hdr" style="margin-top:28px;">// INCIDENT ANALYTICS</div>', unsafe_allow_html=True)
    with st.expander("EXPAND ANALYTICS DASHBOARD", expanded=True):
        _render_analytics(inc_all)
