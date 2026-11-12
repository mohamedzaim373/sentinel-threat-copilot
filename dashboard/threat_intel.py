"""
Threat Intelligence page — SENTINEL SOC-AI platform.
"""
import random
from datetime import datetime, timedelta

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# ─────────────────────────────────────────────────────────────────────────────
# CSS
# ─────────────────────────────────────────────────────────────────────────────
THREAT_INTEL_CSS = """<style>
/* IOC type badges */
.ioc-badge { padding: 2px 8px; border-radius: 3px; display: inline-block; font-family: monospace; font-size: 10px; }
.ioc-ip     { background: rgba(59,130,246,.15);  color: #93c5fd; border: 1px solid rgba(59,130,246,.35);  }
.ioc-domain { background: rgba(139,92,246,.15);  color: #c4b5fd; border: 1px solid rgba(139,92,246,.35);  }
.ioc-url    { background: rgba(249,115,22,.15);  color: #fdba74; border: 1px solid rgba(249,115,22,.35);  }
.ioc-hash   { background: rgba(20,184,166,.15);  color: #5eead4; border: 1px solid rgba(20,184,166,.35);  }
.ioc-email  { background: rgba(234,179,8,.15);   color: #fde047; border: 1px solid rgba(234,179,8,.35);   }
.ioc-file   { background: rgba(100,116,139,.15); color: #94a3b8; border: 1px solid rgba(100,116,139,.3);  }

/* IOC status badges */
.ioc-status    { padding: 2px 8px; border-radius: 3px; display: inline-block; font-family: monospace; font-size: 10px; }
.ioc-active    { background: rgba(239,68,68,.15);  color: #fca5a5; border: 1px solid rgba(239,68,68,.35);  }
.ioc-expired   { background: rgba(100,116,139,.12);color: #94a3b8; border: 1px solid rgba(100,116,139,.3); }
.ioc-blocked   { background: rgba(34,197,94,.10);  color: #86efac; border: 1px solid rgba(34,197,94,.3);   }
.ioc-monitoring{ background: rgba(234,179,8,.12);  color: #fde047; border: 1px solid rgba(234,179,8,.35);  }

/* Confidence bar */
.conf-wrap { background: rgba(255,255,255,.06); border-radius: 3px; height: 5px; overflow: hidden; width: 80px; display: inline-block; vertical-align: middle; margin-left: 6px; }
.conf-fill { height: 100%; border-radius: 3px; }
.conf-high { background: #22c55e; }
.conf-med  { background: #eab308; }
.conf-low  { background: #ef4444; }

/* Feed cards */
.feed-card  { background: #111827; border: 1px solid rgba(255,255,255,.08); border-radius: 8px; padding: 12px 14px; margin-bottom: 8px; }
.feed-name  { font-family: monospace; font-size: 12px; color: #e2e8f0; font-weight: 700; }
.feed-meta  { font-family: monospace; font-size: 9px; color: #64748b; margin-top: 4px; }
.feed-dot-ok  { display: inline-block; width: 6px; height: 6px; border-radius: 50%; background: #22c55e; margin-right: 6px; }
.feed-dot-err { display: inline-block; width: 6px; height: 6px; border-radius: 50%; background: #ef4444; margin-right: 6px; }
.feed-dot-warn{ display: inline-block; width: 6px; height: 6px; border-radius: 50%; background: #eab308; margin-right: 6px; }
.feed-count { font-family: monospace; font-size: 18px; color: #60a5fa; font-weight: 700; }

/* Malware cards */
.malware-card          { background: #111827; border: 1px solid rgba(255,255,255,.08); border-radius: 8px; padding: 12px 14px; margin-bottom: 8px; }
.malware-card.critical { border-left: 3px solid #ef4444; }
.malware-card.high     { border-left: 3px solid #f97316; }
.malware-name { font-family: monospace; font-size: 13px; color: #e2e8f0; font-weight: 700; }
.malware-meta { font-family: monospace; font-size: 10px; color: #64748b; margin-top: 4px; }

/* Campaign rows */
.camp-row    { display: flex; align-items: center; gap: 10px; padding: 8px 12px; border-bottom: 1px solid rgba(255,255,255,.04); font-family: monospace; font-size: 11px; }
.camp-row:hover { background: rgba(59,130,246,.04); }
.camp-name   { color: #e2e8f0; font-weight: 700; flex: 2; }
.camp-actor  { color: #c4b5fd; flex: 2; }
.camp-sector { color: #64748b; flex: 1.5; }
.camp-since  { color: #64748b; flex: 1.5; font-size: 10px; }

/* Correlation findings */
.corr-finding { background: rgba(34,197,94,.04); border: 1px solid rgba(34,197,94,.15); border-left: 3px solid #22c55e; border-radius: 6px; padding: 12px 16px; margin-bottom: 10px; }
.corr-hdr  { font-family: monospace; font-size: 11px; color: #22c55e; margin-bottom: 6px; }
.corr-body { font-family: monospace; font-size: 11px; color: #94a3b8; line-height: 1.6; }
.corr-tags { margin-top: 8px; }
.corr-tag  { display: inline-block; font-family: monospace; font-size: 9px; color: #60a5fa; background: rgba(59,130,246,.08); border: 1px solid rgba(59,130,246,.2); padding: 1px 7px; border-radius: 3px; margin: 2px; }

/* Watchlist */
.watch-item  { display: flex; align-items: center; gap: 10px; padding: 7px 12px; border-bottom: 1px solid rgba(255,255,255,.04); }
.watch-item:hover { background: rgba(34,197,94,.03); }
.watch-value { font-family: monospace; font-size: 11px; color: #60a5fa; flex: 3; }
.watch-meta  { font-family: monospace; font-size: 10px; color: #64748b; flex: 2; }

/* Dark web badge */
.dw-badge { display: inline-block; font-family: monospace; font-size: 9px; color: #fca5a5; background: rgba(239,68,68,.1); border: 1px solid rgba(239,68,68,.25); padding: 1px 7px; border-radius: 3px; margin-left: 6px; }

/* YARA/Sigma code block */
.rule-block { background: #0a0f1a; border: 1px solid rgba(255,255,255,.08); border-radius: 6px; padding: 12px; font-family: monospace; font-size: 10px; color: #22c55e; white-space: pre; overflow-x: auto; line-height: 1.6; }
.rule-kw  { color: #60a5fa; }
.rule-str { color: #fde047; }
.rule-cmt { color: #64748b; }

/* Pulse badge */
.pulse-badge { display: inline-flex; align-items: center; gap: 6px; font-family: monospace; font-size: 11px; color: #22c55e; border: 1px solid rgba(34,197,94,.25); padding: 4px 12px; border-radius: 20px; background: rgba(34,197,94,.05); }
.pulse-dot   { width: 7px; height: 7px; border-radius: 50%; background: #22c55e; animation: blink 1.5s infinite; flex-shrink: 0; }

/* Map / AI box */
.map-wrap   { background: #0a0f1a; border: 1px solid rgba(255,255,255,.08); border-radius: 8px; overflow: hidden; }
.ioc-ai-box { background: rgba(34,197,94,.04); border: 1px solid rgba(34,197,94,.15); border-left: 3px solid #22c55e; border-radius: 6px; padding: 14px 16px; font-family: monospace; font-size: 11px; color: #94a3b8; line-height: 1.75; white-space: pre-wrap; }

/* IOC timeline */
.ti-tl-row  { display: flex; align-items: flex-start; gap: 10px; padding: 7px 0; border-bottom: 1px solid rgba(255,255,255,.04); }
.ti-tl-dot  { width: 7px; height: 7px; border-radius: 50%; margin-top: 5px; flex-shrink: 0; }
.ti-tl-dot.critical { background: #ef4444; }
.ti-tl-dot.high     { background: #f97316; }
.ti-tl-dot.medium   { background: #eab308; }
.ti-tl-dot.low      { background: #3b82f6; }
.ti-tl-dot.info     { background: #64748b; }
.ti-tl-time { font-family: monospace; font-size: 10px; color: #64748b; min-width: 88px; }
.ti-tl-text { font-family: monospace; font-size: 11px; color: #94a3b8; }

/* Related / CVE chips */
.rel-ioc  { display: inline-block; font-family: monospace; font-size: 10px; color: #93c5fd; background: rgba(59,130,246,.08); border: 1px solid rgba(59,130,246,.2); padding: 3px 10px; border-radius: 3px; margin: 2px; }
.cve-chip { display: inline-block; font-family: monospace; font-size: 10px; color: #fca5a5; background: rgba(239,68,68,.08); border: 1px solid rgba(239,68,68,.25); padding: 2px 8px; border-radius: 3px; margin: 2px; }
</style>"""


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def ioc_type_badge(t: str) -> str:
    css = {"IP":"ioc-ip","Domain":"ioc-domain","URL":"ioc-url",
           "Hash":"ioc-hash","Email":"ioc-email","File":"ioc-file"}.get(t,"ioc-file")
    return f'<span class="ioc-badge {css}">{t}</span>'

def ioc_status_badge(s: str) -> str:
    css = {"Active":"ioc-active","Expired":"ioc-expired",
           "Blocked":"ioc-blocked","Monitoring":"ioc-monitoring"}.get(s,"ioc-expired")
    return f'<span class="ioc-status {css}">{s.upper()}</span>'

def confidence_bar(score: int) -> str:
    cls = "conf-high" if score >= 75 else "conf-med" if score >= 45 else "conf-low"
    return (f'<span style="font-family:\'Share Tech Mono\',monospace;font-size:10px;color:#8892a4;">{score}%</span>'
            f'<span class="conf-wrap"><span class="conf-fill {cls}" style="width:{score}%;"></span></span>')

def _generate_threat_report(iocs: list, campaigns: list) -> str:
    lines = [
        "=" * 64,
        "  SENTINEL SOC-AI · THREAT INTELLIGENCE REPORT",
        f"  Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        "=" * 64, "",
        f"  Total IOCs     : {len(iocs)}",
        f"  Active IOCs    : {sum(1 for i in iocs if i['status']=='Active')}",
        f"  Critical IOCs  : {sum(1 for i in iocs if i['severity']=='critical')}",
        f"  Campaigns      : {len(campaigns)}",
        "", "-" * 64, "  IOC SUMMARY", "-" * 64,
    ]
    for ioc in iocs[:10]:
        lines.append(f"  [{ioc['severity'].upper():8}] {ioc['type']:7} {ioc['value']:<40} {ioc['status']}")
    lines += ["", "-" * 64, "  ACTIVE CAMPAIGNS", "-" * 64]
    for c in campaigns:
        lines.append(f"  [{c['severity'].upper():8}] {c['name']:<30} Actor: {c['actor']}")
    lines += ["", "=" * 64, "  END OF REPORT — SENTINEL SOC-AI", "=" * 64]
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Mock data
# ─────────────────────────────────────────────────────────────────────────────

def get_ioc_mock_data() -> list:
    now = datetime.utcnow()
    return [
        {
            "id": "IOC-001", "type": "IP", "value": "192.168.110.151",
            "category": "Brute Force Source", "severity": "critical", "confidence": 98,
            "source": "Wazuh (Internal)", "first_seen": "2026-05-12 21:20",
            "last_seen": "2026-05-13 09:00", "status": "Active",
            "country": "Internal", "asn": "LAN", "org": "Internal Network",
            "mitre_tactic": "Credential Access", "mitre_technique": "T1110.001",
            "mitre_name": "Password Guessing",
            "related_incidents": ["INC-2026-0145"],
            "related_assets": ["zaim-VMware-Virtual-Platform"],
            "dark_web_mentions": 0,
            "tags": ["ssh", "brute-force", "internal", "active"],
            "ai_summary": (
                "This internal IP (192.168.110.151) launched a coordinated SSH brute force against the "
                "production host generating 752 Wazuh alerts over 15 minutes.\n\n"
                "Behavioral Profile:\n"
                "  • Automated tooling pattern (Hydra/Medusa cadence)\n"
                "  • Exclusively targeting root account\n"
                "  • No successful authentication detected\n"
                "  • Source is an internal host — possible compromised machine or authorized pentest\n\n"
                "Recommendation: Isolate source host and verify if this is authorized testing."
            ),
            "timeline": [
                {"time": "2026-05-12 21:20", "event": "First SSH connection attempt", "level": "info"},
                {"time": "2026-05-12 21:25", "event": "Brute force pattern confirmed (rule 5763)", "level": "high"},
                {"time": "2026-05-12 21:34", "event": "752nd attempt — incident auto-created", "level": "critical"},
            ],
            "related_iocs": ["IOC-014", "IOC-015"],
            "recommendations": [
                "Block 192.168.110.151 at firewall (iptables -A INPUT -s 192.168.110.151 -j DROP)",
                "Investigate what process on .151 is initiating the SSH connections",
                "Enable fail2ban on target host with threshold ≤ 5 attempts",
            ],
            "geo": {"lat": 36.8, "lon": 10.18, "country_name": "Internal LAN"},
            "cves": [],
            "watchlisted": True,
        },
        {
            "id": "IOC-002", "type": "IP", "value": "185.220.101.45",
            "category": "C2 Server / Tor Exit", "severity": "critical", "confidence": 97,
            "source": "AbuseIPDB + Suricata", "first_seen": "2026-05-10 09:00",
            "last_seen": "2026-05-13 07:45", "status": "Active",
            "country": "DE", "asn": "AS204720", "org": "Frantech Solutions",
            "mitre_tactic": "Command and Control", "mitre_technique": "T1071.001",
            "mitre_name": "Web Protocols C2",
            "related_incidents": ["INC-2026-0143"],
            "related_assets": ["k8s-edge-3"],
            "dark_web_mentions": 7,
            "tags": ["cobalt-strike", "tor-exit", "c2", "APT"],
            "ai_summary": (
                "Known Tor exit node frequently associated with Cobalt Strike C2 infrastructure. "
                "This IP appears in multiple threat intel feeds and was observed beaconing from "
                "k8s-edge-3 with 60-second intervals and JA3 fingerprint matching Cobalt Strike.\n\n"
                "Threat Actor: Likely APT-affiliated — infrastructure overlaps with NOBELIUM campaigns.\n"
                "Dark Web Mentions: 7 references in underground forums (last 30 days)."
            ),
            "timeline": [
                {"time": "2026-05-10 09:00", "event": "First beacon from k8s-edge-3 to this IP", "level": "medium"},
                {"time": "2026-05-10 09:10", "event": "Cobalt Strike JA3 fingerprint confirmed", "level": "critical"},
                {"time": "2026-05-13 07:45", "event": "Still actively beaconing — last observation", "level": "high"},
            ],
            "related_iocs": ["IOC-005", "IOC-010", "IOC-018"],
            "recommendations": [
                "Block 185.220.101.45 at all perimeter controls immediately",
                "DNS sinkhole — intercept all queries to this IP",
                "Memory dump of k8s-edge-3 to extract Cobalt Strike configuration",
                "Rotate all credentials accessible from k8s-edge-3",
            ],
            "geo": {"lat": 51.1, "lon": 10.4, "country_name": "Germany"},
            "cves": [],
            "watchlisted": True,
        },
        {
            "id": "IOC-003", "type": "IP", "value": "45.76.221.13",
            "category": "Data Exfiltration C2", "severity": "critical", "confidence": 94,
            "source": "Suricata + VirusTotal", "first_seen": "2026-05-06 19:00",
            "last_seen": "2026-05-06 19:45", "status": "Blocked",
            "country": "US", "asn": "AS20473", "org": "Choopa LLC / Vultr",
            "mitre_tactic": "Exfiltration", "mitre_technique": "T1048",
            "mitre_name": "Exfiltration Over Alternative Protocol",
            "related_incidents": ["INC-2026-0139"],
            "related_assets": ["db-master"],
            "dark_web_mentions": 4,
            "tags": ["dns-tunneling", "exfiltration", "IODINE", "data-breach"],
            "ai_summary": (
                "This IP served as DNS tunneling C2 server receiving 4.7 GB of data exfiltrated "
                "from db-master via IODINE DNS tunneling tool.\n\n"
                "Infrastructure Assessment: VPS-hosted C2 on Vultr infrastructure, commonly "
                "abused for transient C2 operations. IP has been rotated since incident — "
                "likely reassigned."
            ),
            "timeline": [
                {"time": "2026-05-06 19:00", "event": "DNS tunneling traffic begins", "level": "medium"},
                {"time": "2026-05-06 19:33", "event": "4.7 GB exfiltration confirmed — IP blocked", "level": "critical"},
            ],
            "related_iocs": ["IOC-008", "IOC-012"],
            "recommendations": [
                "IP already blocked — maintain block permanently",
                "Add to perimeter DNS RPZ feed",
                "Assess all traffic logs from db-master during this window",
            ],
            "geo": {"lat": 37.7, "lon": -122.4, "country_name": "United States"},
            "cves": [],
            "watchlisted": False,
        },
        {
            "id": "IOC-004", "type": "Domain", "value": "update.microsoft-telemetry.com",
            "category": "C2 Domain (Lookalike)", "severity": "critical", "confidence": 96,
            "source": "DNS Analytics + VirusTotal", "first_seen": "2026-05-10 08:58",
            "last_seen": "2026-05-13 06:30", "status": "Blocked",
            "country": "RU", "asn": "AS197695", "org": "Domain RegRU",
            "mitre_tactic": "Command and Control", "mitre_technique": "T1568.002",
            "mitre_name": "Domain Generation Algorithms",
            "related_incidents": ["INC-2026-0143"],
            "related_assets": ["k8s-edge-3"],
            "dark_web_mentions": 12,
            "tags": ["c2", "lookalike-domain", "cobalt-strike", "APT29"],
            "ai_summary": (
                "Domain masquerading as Microsoft telemetry service. Registered in Russia "
                "3 weeks before first detection. Resolves to 185.220.101.45 (IOC-002).\n\n"
                "Campaign Attribution: Infrastructure overlaps with APT29 (Cozy Bear) "
                "known domains. 12 dark web references link this domain to NOBELIUM campaign materials."
            ),
            "timeline": [
                {"time": "2026-04-22", "event": "Domain registered via RegRU", "level": "info"},
                {"time": "2026-05-10 08:58", "event": "DNS query from k8s-edge-3 detected", "level": "high"},
                {"time": "2026-05-10 09:00", "event": "DNS sinkhled — traffic redirected", "level": "info"},
            ],
            "related_iocs": ["IOC-002", "IOC-010"],
            "recommendations": [
                "DNS sinkhole maintained — no action required",
                "Submit to OpenPhish and PhishTank databases",
                "Monitor for re-registration of similar lookalike domains",
            ],
            "geo": {"lat": 55.7, "lon": 37.6, "country_name": "Russia"},
            "cves": [],
            "watchlisted": True,
        },
        {
            "id": "IOC-005", "type": "Domain", "value": "analytics-cdn.top",
            "category": "Beacon C2 Domain", "severity": "high", "confidence": 89,
            "source": "Suricata IDS", "first_seen": "2026-05-10 09:00",
            "last_seen": "2026-05-12 14:20", "status": "Blocked",
            "country": "NL", "asn": "AS60781", "org": "LeaseWeb Netherlands",
            "mitre_tactic": "Command and Control", "mitre_technique": "T1071.001",
            "mitre_name": "Web Protocols C2",
            "related_incidents": ["INC-2026-0143"],
            "related_assets": ["k8s-edge-3"],
            "dark_web_mentions": 3,
            "tags": ["c2", "beacon", "https", "cobalt-strike"],
            "ai_summary": (
                "Secondary C2 domain used in the Cobalt Strike campaign targeting k8s-edge-3. "
                "Hosted on LeaseWeb Netherlands infrastructure. Domain uses fast-flux DNS "
                "for resilience. Related to IOC-002 and IOC-004."
            ),
            "timeline": [
                {"time": "2026-05-10 09:00", "event": "Domain first queried by k8s-edge-3", "level": "medium"},
                {"time": "2026-05-12 14:20", "event": "Last observed DNS query", "level": "low"},
            ],
            "related_iocs": ["IOC-002", "IOC-004"],
            "recommendations": ["Block at DNS level", "Monitor for domain resurrection"],
            "geo": {"lat": 52.3, "lon": 4.9, "country_name": "Netherlands"},
            "cves": [],
            "watchlisted": False,
        },
        {
            "id": "IOC-006", "type": "Domain", "value": "contoso-corp.xyz",
            "category": "Phishing Domain", "severity": "high", "confidence": 99,
            "source": "Mail Gateway", "first_seen": "2026-05-08 11:10",
            "last_seen": "2026-05-08 12:00", "status": "Blocked",
            "country": "NG", "asn": "AS37148", "org": "Mainone Cable Nigeria",
            "mitre_tactic": "Initial Access", "mitre_technique": "T1566.001",
            "mitre_name": "Spearphishing Attachment",
            "related_incidents": ["INC-2026-0141"],
            "related_assets": ["win-dc-01"],
            "dark_web_mentions": 1,
            "tags": ["phishing", "spearphishing", "finance", "emotet-dropper"],
            "ai_summary": (
                "Lookalike domain impersonating legitimate corporate vendor used in spearphishing "
                "campaign targeting finance department. Domain registered in Nigeria, "
                "used to send .docm macro-laced invoices. Emotet loader payload confirmed."
            ),
            "timeline": [
                {"time": "2026-05-08 11:10", "event": "Phishing email from accounts@contoso-corp.xyz", "level": "high"},
                {"time": "2026-05-08 12:00", "event": "Domain blocked and sinkholed", "level": "info"},
            ],
            "related_iocs": ["IOC-015", "IOC-019"],
            "recommendations": ["Block at email gateway", "Submit to phishing databases"],
            "geo": {"lat": 6.5, "lon": 3.4, "country_name": "Nigeria"},
            "cves": [],
            "watchlisted": False,
        },
        {
            "id": "IOC-007", "type": "Hash",
            "value": "a5b2c3d4e5f60718293a4b5c6d7e8f901234567890abcdef1234567890abcdef",
            "category": "Emotet Loader", "severity": "critical", "confidence": 100,
            "source": "VirusTotal (67/72)", "first_seen": "2026-05-08 11:15",
            "last_seen": "2026-05-08 11:15", "status": "Blocked",
            "country": "—", "asn": "—", "org": "—",
            "mitre_tactic": "Execution", "mitre_technique": "T1204.002",
            "mitre_name": "Malicious File",
            "related_incidents": ["INC-2026-0141"],
            "related_assets": ["win-dc-01"],
            "dark_web_mentions": 0,
            "tags": ["emotet", "macro", "word-document", "loader"],
            "ai_summary": (
                "SHA-256 hash of Q1_Report.docm — Emotet loader document detected on win-dc-01. "
                "67/72 VirusTotal engines flag this as Emotet.Gen. VBA macro contains PowerShell "
                "dropper targeting %APPDATA%\\svchost32.exe.\n\n"
                "File Type: OOXML Word Document with embedded VBA macro\n"
                "Size: 487 KB\n"
                "Compiler: VBA7 / Office 2016+"
            ),
            "timeline": [
                {"time": "2026-05-08 11:15", "event": "File created: Q1_Report.docm on win-dc-01", "level": "high"},
                {"time": "2026-05-08 11:15", "event": "EDR blocked execution — macro prevented", "level": "info"},
            ],
            "related_iocs": ["IOC-006", "IOC-019"],
            "recommendations": [
                "Hash added to EDR blocklist — no further action",
                "Scan all endpoints for file presence",
                "Submit to sandbox for full behavioral analysis",
            ],
            "geo": {"lat": 0, "lon": 0, "country_name": "N/A"},
            "cves": [],
            "watchlisted": True,
        },
        {
            "id": "IOC-008", "type": "Hash",
            "value": "d1f3e8a2b7c94056123def789abc012345678901234567890abcdef1234567890",
            "category": "LockBit 3.0 Ransomware", "severity": "critical", "confidence": 100,
            "source": "VirusTotal (71/72)", "first_seen": "2026-05-11 14:22",
            "last_seen": "2026-05-11 14:22", "status": "Blocked",
            "country": "—", "asn": "—", "org": "—",
            "mitre_tactic": "Impact", "mitre_technique": "T1486",
            "mitre_name": "Data Encrypted for Impact",
            "related_incidents": ["INC-2026-0144"],
            "related_assets": ["db-master"],
            "dark_web_mentions": 2,
            "tags": ["lockbit", "ransomware", "encryption", "dll-sideloading"],
            "ai_summary": (
                "SHA-256 hash of svc_update.dll — LockBit 3.0 ransomware DLL staged in "
                "C:\\Windows\\Temp\\ on db-master.\n\n"
                "Analysis:\n"
                "  • DLL sideloading via legitimate Windows service\n"
                "  • RSA-2048 + AES-256 encryption routine embedded\n"
                "  • Ransom note: HLjkNskOq.README.txt template (LockBit 3.0)\n"
                "  • Anti-analysis: RDTSC timing checks, VM detection\n\n"
                "Machine isolated before encryption executed — no files encrypted."
            ),
            "timeline": [
                {"time": "2026-05-11 14:20", "event": "DLL dropped to C:\\Windows\\Temp\\svc_update.dll", "level": "critical"},
                {"time": "2026-05-11 14:22", "event": "DLL loaded — Sysmon Event 7 triggered", "level": "critical"},
                {"time": "2026-05-11 14:28", "event": "Machine isolated — DLL execution prevented", "level": "info"},
            ],
            "related_iocs": ["IOC-011", "IOC-003"],
            "recommendations": [
                "Maintain hash in EDR blocklist and SIEM correlation rules",
                "Submit to sandbox for YARA rule generation",
                "Add to threat sharing platforms (MISP, OpenCTI)",
            ],
            "geo": {"lat": 0, "lon": 0, "country_name": "N/A"},
            "cves": ["CVE-2023-4966", "CVE-2021-34527"],
            "watchlisted": True,
        },
        {
            "id": "IOC-009", "type": "IP", "value": "91.234.56.78",
            "category": "SQL Injection Scanner", "severity": "high", "confidence": 88,
            "source": "WAF + AbuseIPDB", "first_seen": "2026-05-09 16:40",
            "last_seen": "2026-05-09 17:00", "status": "Blocked",
            "country": "RO", "asn": "AS34665", "org": "PIDGINHOST",
            "mitre_tactic": "Initial Access", "mitre_technique": "T1190",
            "mitre_name": "Exploit Public-Facing Application",
            "related_incidents": ["INC-2026-0142"],
            "related_assets": ["web-prod-01"],
            "dark_web_mentions": 0,
            "tags": ["sql-injection", "web-scanner", "automated-attack"],
            "ai_summary": (
                "Romanian VPS used for automated SQL injection scanning. "
                "AbuseIPDB confidence score: 92%. 47 injection payloads detected against /api/users endpoint. "
                "Pattern consistent with sqlmap automated tool."
            ),
            "timeline": [
                {"time": "2026-05-09 16:40", "event": "SQL injection scanning begins", "level": "medium"},
                {"time": "2026-05-09 17:00", "event": "WAF block + IP blocked at firewall", "level": "info"},
            ],
            "related_iocs": ["IOC-020"],
            "recommendations": ["Block maintained", "Update WAF SQLi rules"],
            "geo": {"lat": 45.9, "lon": 24.9, "country_name": "Romania"},
            "cves": [],
            "watchlisted": False,
        },
        {
            "id": "IOC-010", "type": "IP", "value": "194.165.16.78",
            "category": "Emotet Distribution Node", "severity": "high", "confidence": 91,
            "source": "AlienVault OTX", "first_seen": "2026-05-01 00:00",
            "last_seen": "2026-05-13 08:00", "status": "Active",
            "country": "UA", "asn": "AS39608", "org": "Highload Systems",
            "mitre_tactic": "Command and Control", "mitre_technique": "T1071",
            "mitre_name": "Application Layer Protocol",
            "related_incidents": [],
            "related_assets": [],
            "dark_web_mentions": 8,
            "tags": ["emotet", "epoch4", "botnet", "malspam-c2"],
            "ai_summary": (
                "Emotet Epoch 4 C2 node actively distributing malspam campaigns. "
                "Listed in Feodotracker and AlienVault OTX with 15+ community pulses. "
                "Currently serving Emotet payloads as of last check."
            ),
            "timeline": [
                {"time": "2026-05-01", "event": "First seen in AlienVault OTX feed", "level": "high"},
                {"time": "2026-05-13", "event": "Still active — confirmed by multiple feeds", "level": "high"},
            ],
            "related_iocs": ["IOC-006", "IOC-007"],
            "recommendations": [
                "Block at perimeter immediately",
                "Add to email gateway IP blocklist",
                "Subscribe to Feodotracker feed for live C2 updates",
            ],
            "geo": {"lat": 50.4, "lon": 30.5, "country_name": "Ukraine"},
            "cves": [],
            "watchlisted": True,
        },
        {
            "id": "IOC-011", "type": "IP", "value": "5.188.86.172",
            "category": "Ransomware C2", "severity": "critical", "confidence": 95,
            "source": "CISA KEV + VirusTotal", "first_seen": "2026-04-15 00:00",
            "last_seen": "2026-05-12 22:00", "status": "Active",
            "country": "RU", "asn": "AS57523", "org": "Chang Way Technologies",
            "mitre_tactic": "Command and Control", "mitre_technique": "T1071.001",
            "mitre_name": "Web Protocols C2",
            "related_incidents": ["INC-2026-0144"],
            "related_assets": ["db-master"],
            "dark_web_mentions": 15,
            "tags": ["lockbit", "ransomware-c2", "CISA-KEV", "Russia"],
            "ai_summary": (
                "LockBit 3.0 ransomware C2 server. Listed in CISA Known Exploited Vulnerabilities "
                "as active ransomware infrastructure. 15 dark web references link this IP to "
                "LockBit affiliate operations."
            ),
            "timeline": [
                {"time": "2026-04-15", "event": "Added to CISA KEV threat feed", "level": "critical"},
                {"time": "2026-05-12 22:00", "event": "Active C2 beacon confirmed by multiple sensors", "level": "critical"},
            ],
            "related_iocs": ["IOC-008", "IOC-003"],
            "recommendations": [
                "Block at all perimeter controls — no exceptions",
                "CISA advisory: implement network segmentation for critical systems",
                "Patch CVE-2023-4966 (Citrix Bleed) and CVE-2021-34527 (PrintNightmare)",
            ],
            "geo": {"lat": 55.7, "lon": 37.6, "country_name": "Russia"},
            "cves": ["CVE-2023-4966", "CVE-2021-34527", "CVE-2021-44228"],
            "watchlisted": True,
        },
        {
            "id": "IOC-012", "type": "URL",
            "value": "hxxps://cdn-loader.ru/payload.ps1",
            "category": "Malware Delivery URL", "severity": "critical", "confidence": 97,
            "source": "VirusTotal (58/72)", "first_seen": "2026-05-11 14:15",
            "last_seen": "2026-05-11 14:30", "status": "Blocked",
            "country": "RU", "asn": "AS197695", "org": "RegRU Hosting",
            "mitre_tactic": "Execution", "mitre_technique": "T1059.001",
            "mitre_name": "PowerShell",
            "related_incidents": ["INC-2026-0144"],
            "related_assets": ["db-master"],
            "dark_web_mentions": 3,
            "tags": ["powershell-dropper", "ransomware-staging", "russia"],
            "ai_summary": (
                "PowerShell dropper URL used in ransomware staging attack on db-master. "
                "Script downloads and executes LockBit 3.0 DLL via IEX (Invoke-Expression).\n\n"
                "Payload Analysis:\n"
                "  • Obfuscated PowerShell using base64 encoding\n"
                "  • Downloads svc_update.dll to C:\\Windows\\Temp\\\n"
                "  • Uses regsvr32.exe for DLL execution (LOLBin)"
            ),
            "timeline": [
                {"time": "2026-05-11 14:15", "event": "URL fetched from db-master", "level": "critical"},
                {"time": "2026-05-11 14:16", "event": "payload.ps1 executed — DLL downloaded", "level": "critical"},
            ],
            "related_iocs": ["IOC-008", "IOC-011"],
            "recommendations": ["URL blocked at proxy", "Submit to urlscan.io and VirusTotal"],
            "geo": {"lat": 55.7, "lon": 37.6, "country_name": "Russia"},
            "cves": [],
            "watchlisted": False,
        },
        {
            "id": "IOC-013", "type": "Email", "value": "accounts@contoso-corp.xyz",
            "category": "Phishing Sender", "severity": "high", "confidence": 99,
            "source": "Mail Gateway", "first_seen": "2026-05-08 11:10",
            "last_seen": "2026-05-08 11:10", "status": "Blocked",
            "country": "NG", "asn": "—", "org": "—",
            "mitre_tactic": "Initial Access", "mitre_technique": "T1566.001",
            "mitre_name": "Spearphishing Attachment",
            "related_incidents": ["INC-2026-0141"],
            "related_assets": ["win-dc-01"],
            "dark_web_mentions": 1,
            "tags": ["phishing-sender", "finance-lure", "emotet-campaign"],
            "ai_summary": (
                "Phishing sender email address impersonating finance department. "
                "Domain contoso-corp.xyz registered in Nigeria 48 hours before the phishing campaign. "
                "Sent .docm Emotet loader to 3 finance department targets."
            ),
            "timeline": [
                {"time": "2026-05-08 11:10", "event": "Phishing email sent to finance team (3 recipients)", "level": "high"},
                {"time": "2026-05-08 11:20", "event": "Domain and sender blocked at mail gateway", "level": "info"},
            ],
            "related_iocs": ["IOC-006", "IOC-007"],
            "recommendations": ["Sender blocked", "Report to DMARC reporting tools"],
            "geo": {"lat": 6.5, "lon": 3.4, "country_name": "Nigeria"},
            "cves": [],
            "watchlisted": False,
        },
        {
            "id": "IOC-014", "type": "IP", "value": "195.178.110.51",
            "category": "Web Shell Upload Source", "severity": "critical", "confidence": 93,
            "source": "Nginx Logs + Wazuh", "first_seen": "2026-05-02 20:48",
            "last_seen": "2026-05-02 21:00", "status": "Blocked",
            "country": "IR", "asn": "AS58224", "org": "PJSC Rostelecom",
            "mitre_tactic": "Persistence", "mitre_technique": "T1505.003",
            "mitre_name": "Web Shell",
            "related_incidents": ["INC-2026-0135"],
            "related_assets": ["web-prod-01"],
            "dark_web_mentions": 2,
            "tags": ["web-shell", "php", "RCE", "iran"],
            "ai_summary": (
                "Iranian IP responsible for PHP web shell upload to web-prod-01 via unrestricted "
                "file upload vulnerability. Achieved 7 minutes of RCE before EDR detection. "
                "Attribution: consistent with TA455 (MuddyWater affiliate) TTPs."
            ),
            "timeline": [
                {"time": "2026-05-02 20:48", "event": "PHP web shell uploaded via POST /upload", "level": "critical"},
                {"time": "2026-05-02 20:50", "event": "Web shell executed — RCE established", "level": "critical"},
                {"time": "2026-05-02 20:55", "event": "IP blocked — server isolated", "level": "info"},
            ],
            "related_iocs": ["IOC-021"],
            "recommendations": ["Block maintained at all controls", "Report to CISA threat sharing"],
            "geo": {"lat": 35.6, "lon": 51.4, "country_name": "Iran"},
            "cves": [],
            "watchlisted": False,
        },
        {
            "id": "IOC-015", "type": "IP", "value": "23.106.160.88",
            "category": "DNS Tunneling C2", "severity": "medium", "confidence": 82,
            "source": "Suricata", "first_seen": "2026-05-03 12:00",
            "last_seen": "2026-05-03 12:15", "status": "Blocked",
            "country": "US", "asn": "AS20326", "org": "T-Mobile USA",
            "mitre_tactic": "Command and Control", "mitre_technique": "T1071.004",
            "mitre_name": "DNS C2",
            "related_incidents": ["INC-2026-0136"],
            "related_assets": ["fw-core"],
            "dark_web_mentions": 0,
            "tags": ["dns-tunneling", "iodine", "reconnaissance"],
            "ai_summary": (
                "DNS tunneling probe destination. Low-confidence attribution — may be "
                "shared hosting victim. Suricata IODINE signature triggered. "
                "No confirmed data exfiltration from this IP."
            ),
            "timeline": [
                {"time": "2026-05-03 12:00", "event": "DNS tunneling probe begins", "level": "medium"},
                {"time": "2026-05-03 12:15", "event": "Traffic blocked", "level": "info"},
            ],
            "related_iocs": ["IOC-003"],
            "recommendations": ["DNS sinkhled — monitor for re-emergence"],
            "geo": {"lat": 37.7, "lon": -95.7, "country_name": "United States"},
            "cves": [],
            "watchlisted": False,
        },
    ]


def get_feed_data() -> list:
    return [
        {"name": "AbuseIPDB",      "icon": "◈", "status": "ok",   "last_update": "2026-05-13 09:10", "ioc_count": 45_231, "health": 98, "enabled": True,  "type": "IP Reputation"},
        {"name": "AlienVault OTX", "icon": "◈", "status": "ok",   "last_update": "2026-05-13 08:45", "ioc_count": 128_540,"health": 97, "enabled": True,  "type": "Threat Intel"},
        {"name": "VirusTotal",     "icon": "◈", "status": "ok",   "last_update": "2026-05-13 09:05", "ioc_count": 892_100,"health": 99, "enabled": True,  "type": "Malware / IOC"},
        {"name": "MITRE ATT&CK",  "icon": "◈", "status": "ok",   "last_update": "2026-05-01 00:00", "ioc_count": 730,    "health": 100,"enabled": True,  "type": "TTP Framework"},
        {"name": "CISA KEV",       "icon": "◈", "status": "ok",   "last_update": "2026-05-12 18:00", "ioc_count": 1_108,  "health": 100,"enabled": True,  "type": "CVE Exploits"},
        {"name": "OpenCTI / MISP", "icon": "◈", "status": "warn", "last_update": "2026-05-11 14:00", "ioc_count": 22_400, "health": 74, "enabled": True,  "type": "Threat Sharing"},
        {"name": "Feodotracker",   "icon": "◈", "status": "ok",   "last_update": "2026-05-13 06:00", "ioc_count": 3_210,  "health": 95, "enabled": True,  "type": "Botnet C2"},
        {"name": "URLhaus",        "icon": "◈", "status": "err",  "last_update": "2026-05-12 09:00", "ioc_count": 0,      "health": 0,  "enabled": False, "type": "Malware URLs"},
    ]


def get_malware_data() -> list:
    return [
        {
            "name": "Emotet",       "severity": "critical", "family": "Banking Trojan / Loader",
            "infection": "Malspam · Malicious Macros",
            "targets": ["Windows 7–11", "Office environments"],
            "behavior": "Downloads secondary payloads (Cobalt Strike, QBot, IcedID). Spreads via email contact harvesting.",
            "detections": 7, "active_since": "2014", "cves": [],
            "related_iocs": ["IOC-006", "IOC-007", "IOC-010", "IOC-013"],
        },
        {
            "name": "LockBit 3.0",  "severity": "critical", "family": "Ransomware-as-a-Service",
            "infection": "RDP · Phishing · Exploit (CVE-2023-4966)",
            "targets": ["Windows Server", "VMware ESXi", "Linux"],
            "behavior": "Double extortion: encrypts + exfiltrates. Deletes VSS, disables backup services.",
            "detections": 3, "active_since": "2022", "cves": ["CVE-2023-4966","CVE-2021-34527"],
            "related_iocs": ["IOC-008", "IOC-011", "IOC-012"],
        },
        {
            "name": "Cobalt Strike", "severity": "critical", "family": "Post-Exploitation Framework",
            "infection": "Phishing · Web Shell · Supply Chain",
            "targets": ["Windows", "Linux", "macOS", "Kubernetes"],
            "behavior": "Malleable C2 beacon, lateral movement, credential dumping, SOCKS proxy pivot.",
            "detections": 57, "active_since": "2012 (cracked builds: 2020)", "cves": [],
            "related_iocs": ["IOC-002", "IOC-004", "IOC-005"],
        },
        {
            "name": "RedLine Stealer","severity": "high", "family": "Info Stealer",
            "infection": "Malvertising · Fake software downloads",
            "targets": ["Windows 10/11"],
            "behavior": "Steals browser credentials, crypto wallets, FTP creds, Discord tokens.",
            "detections": 2, "active_since": "2020", "cves": [],
            "related_iocs": [],
        },
        {
            "name": "QBot (QakBot)", "severity": "high", "family": "Banking Trojan / Loader",
            "infection": "Thread Hijacking · Malspam",
            "targets": ["Windows"],
            "behavior": "Email thread hijacking for high-trust phishing. Drops Cobalt Strike, BlackBasta ransomware.",
            "detections": 4, "active_since": "2007", "cves": [],
            "related_iocs": ["IOC-010"],
        },
        {
            "name": "AgentTesla",   "severity": "medium", "family": "RAT / Keylogger",
            "infection": "Phishing emails · .NET payload",
            "targets": ["Windows"],
            "behavior": "Keylogging, credential theft, clipboard monitoring, screen capture. Exfiltrates via SMTP.",
            "detections": 1, "active_since": "2014", "cves": [],
            "related_iocs": [],
        },
    ]


def get_campaign_data() -> list:
    return [
        {
            "name": "Operation ShadowNet", "actor": "APT29 (Cozy Bear)", "sector": "Government / Cloud",
            "country": "RU", "severity": "critical", "active_since": "2026-04-01", "status": "Active",
            "mitre_techniques": ["T1566.001","T1071.001","T1078","T1003.001"],
            "malware": ["Cobalt Strike", "BEATDROP", "BOOMMIC"],
            "cves": ["CVE-2023-4966"],
            "description": "Credential-theft campaign targeting government cloud tenants. Uses Cobalt Strike and custom implants.",
        },
        {
            "name": "PhishStorm 2026", "actor": "TA505", "sector": "Financial / Retail",
            "country": "NG", "severity": "high", "active_since": "2026-03-15", "status": "Active",
            "mitre_techniques": ["T1566.001","T1204.002","T1059.001"],
            "malware": ["Emotet", "QBot"],
            "cves": [],
            "description": "Large-scale malspam campaign using hijacked email threads to distribute Emotet.",
        },
        {
            "name": "LockBit Wave 9", "actor": "LockBit Affiliate", "sector": "Healthcare / Manufacturing",
            "country": "RU", "severity": "critical", "active_since": "2026-04-20", "status": "Active",
            "mitre_techniques": ["T1190","T1486","T1490","T1048"],
            "malware": ["LockBit 3.0"],
            "cves": ["CVE-2023-4966","CVE-2021-34527"],
            "description": "Ransomware campaign exploiting Citrix Bleed + PrintNightmare for initial access.",
        },
        {
            "name": "MuddyC2", "actor": "MuddyWater (TA455)", "sector": "Telecom / Energy",
            "country": "IR", "severity": "high", "active_since": "2026-02-10", "status": "Monitoring",
            "mitre_techniques": ["T1505.003","T1059.001","T1071.001"],
            "malware": ["PhonyC2", "Cobalt Strike"],
            "cves": [],
            "description": "Iranian APT targeting telecom and energy sectors with web shell uploads and custom C2.",
        },
        {
            "name": "SilentDNS", "actor": "Unknown", "sector": "Cross-sector",
            "country": "US", "severity": "medium", "active_since": "2026-05-01", "status": "Investigating",
            "mitre_techniques": ["T1071.004","T1048"],
            "malware": ["IODINE", "dnscat2"],
            "cves": [],
            "description": "DNS tunneling campaign probing multiple organizations. Likely reconnaissance phase.",
        },
    ]


# ─────────────────────────────────────────────────────────────────────────────
# IOC Detail Panel
# ─────────────────────────────────────────────────────────────────────────────

def _render_ioc_detail(ioc: dict, sev_badge):
    sev = ioc["severity"]
    risk_cls = {"critical":"risk-crit","high":"risk-high","medium":"risk-med"}.get(sev,"risk-low")

    # ── Header ────────────────────────────────────────────────────────
    c1, c2, c3, c4 = st.columns([3, 1.5, 1.5, 1.5])
    with c1:
        dw = f'<span class="dw-badge">🌑 {ioc["dark_web_mentions"]} DW mentions</span>' if ioc["dark_web_mentions"] > 0 else ""
        st.markdown(
            f'<div style="font-family:\'Share Tech Mono\',monospace;font-size:15px;color:#e6f1ff;font-weight:700;">'
            f'{ioc["value"]}{dw}</div>'
            f'<div style="font-family:\'Share Tech Mono\',monospace;font-size:10px;color:#4a7fa5;margin-top:4px;">'
            f'{ioc_type_badge(ioc["type"])} &nbsp; {ioc["category"]} &nbsp;·&nbsp; {ioc["source"]}'
            f'</div>',
            unsafe_allow_html=True,
        )
    with c2:
        st.markdown(f'<div style="font-family:\'Share Tech Mono\',monospace;font-size:10px;color:#4a7fa5;">SEVERITY</div>{sev_badge(sev)}', unsafe_allow_html=True)
    with c3:
        st.markdown(f'<div style="font-family:\'Share Tech Mono\',monospace;font-size:10px;color:#4a7fa5;">STATUS</div>{ioc_status_badge(ioc["status"])}', unsafe_allow_html=True)
    with c4:
        st.markdown(f'<div style="font-family:\'Share Tech Mono\',monospace;font-size:10px;color:#4a7fa5;">CONFIDENCE</div>{confidence_bar(ioc["confidence"])}', unsafe_allow_html=True)

    st.markdown("---")

    # tags
    tag_html = " ".join(f'<span style="display:inline-block;font-family:\'Share Tech Mono\',monospace;font-size:9px;color:#4a7fa5;background:rgba(74,127,165,.1);border:1px solid rgba(74,127,165,.25);padding:1px 7px;border-radius:3px;margin:2px;">#{t}</span>' for t in ioc.get("tags",[]))
    st.markdown(tag_html + "<br>", unsafe_allow_html=True)

    tab1, tab2, tab3, tab4, tab5, tab6, tab7, tab8, tab9 = st.tabs([
        "🧠 AI Summary", "🏷 Classification", "🎯 MITRE",
        "🔗 Incidents", "🖥 Assets", "🌍 Geolocation",
        "⏱ Timeline", "🔀 Related IOCs", "💊 Remediation",
    ])

    with tab1:
        st.markdown(f'<div class="ioc-ai-box">{ioc["ai_summary"]}</div>', unsafe_allow_html=True)

    with tab2:
        cve_chips = " ".join(f'<span class="cve-chip">{c}</span>' for c in ioc["cves"])
        cve_section = (
            '<br><div style="font-family:\'Share Tech Mono\',monospace;font-size:9px;color:#4a7fa5;">EXPLOITED CVEs</div>'
            f'<div style="margin-top:6px;">{cve_chips}</div>'
        ) if ioc["cves"] else ""
        st.markdown(
            f'<div class="glass-panel">'
            f'<div style="font-family:\'Share Tech Mono\',monospace;font-size:10px;color:#4a7fa5;margin-bottom:10px;">THREAT CLASSIFICATION</div>'
            f'<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">'
            f'<div><div style="font-family:\'Share Tech Mono\',monospace;font-size:9px;color:#4a7fa5;">CATEGORY</div>'
            f'<div style="font-family:\'Share Tech Mono\',monospace;font-size:13px;color:#e6f1ff;margin-top:4px;">{ioc["category"]}</div></div>'
            f'<div><div style="font-family:\'Share Tech Mono\',monospace;font-size:9px;color:#4a7fa5;">COUNTRY / ASN</div>'
            f'<div style="font-family:\'Share Tech Mono\',monospace;font-size:12px;color:#c9d1d9;margin-top:4px;">{ioc["country"]} · {ioc["asn"]}</div></div>'
            f'<div><div style="font-family:\'Share Tech Mono\',monospace;font-size:9px;color:#4a7fa5;">ORGANIZATION</div>'
            f'<div style="font-family:\'Share Tech Mono\',monospace;font-size:12px;color:#c9d1d9;margin-top:4px;">{ioc["org"]}</div></div>'
            f'<div><div style="font-family:\'Share Tech Mono\',monospace;font-size:9px;color:#4a7fa5;">FIRST / LAST SEEN</div>'
            f'<div style="font-family:\'Share Tech Mono\',monospace;font-size:11px;color:#c9d1d9;margin-top:4px;">{ioc["first_seen"]}<br>{ioc["last_seen"]}</div></div>'
            f'</div>'
            f'{cve_section}'
            f'</div>',
            unsafe_allow_html=True,
        )

    with tab3:
        st.markdown(
            f'<div class="glass-panel">'
            f'<div style="font-family:\'Share Tech Mono\',monospace;font-size:10px;color:#4a7fa5;margin-bottom:12px;">MITRE ATT&CK MAPPING</div>'
            f'<div style="display:flex;align-items:center;gap:14px;margin-bottom:10px;">'
            f'<span style="font-family:\'Share Tech Mono\',monospace;font-size:10px;color:#c4b5fd;background:rgba(139,92,246,.12);border:1px solid rgba(139,92,246,.3);padding:2px 8px;border-radius:4px;">{ioc["mitre_technique"]}</span>'
            f'<span style="font-family:\'Share Tech Mono\',monospace;font-size:13px;color:#e6f1ff;">{ioc["mitre_name"]}</span>'
            f'</div>'
            f'<div style="font-family:\'Share Tech Mono\',monospace;font-size:11px;color:#4a7fa5;">Tactic: {ioc["mitre_tactic"]}</div>'
            f'</div>',
            unsafe_allow_html=True,
        )

    with tab4:
        if ioc["related_incidents"]:
            rows = ""
            for inc_id in ioc["related_incidents"]:
                rows += f'<div class="watch-item"><span class="watch-value">{inc_id}</span><span class="watch-meta">→ View in Incident History</span></div>'
            st.markdown(f'<div class="glass-panel" style="padding:0;">{rows}</div>', unsafe_allow_html=True)
        else:
            st.markdown('<div class="glass-panel" style="text-align:center;padding:30px;font-family:\'Share Tech Mono\',monospace;font-size:11px;color:#1e3a52;">No correlated incidents</div>', unsafe_allow_html=True)

    with tab5:
        if ioc["related_assets"]:
            rows = ""
            for asset in ioc["related_assets"]:
                rows += f'<div class="watch-item"><span style="font-family:\'Share Tech Mono\',monospace;font-size:11px;color:#00ffaa;">🖥 {asset}</span></div>'
            st.markdown(f'<div class="glass-panel" style="padding:0;">{rows}</div>', unsafe_allow_html=True)
        else:
            st.markdown('<div class="glass-panel" style="text-align:center;padding:30px;font-family:\'Share Tech Mono\',monospace;font-size:11px;color:#1e3a52;">No affected assets</div>', unsafe_allow_html=True)

    with tab6:
        geo = ioc.get("geo", {})
        if geo and geo.get("lat", 0) != 0:
            fig = go.Figure(go.Scattergeo(
                lat=[geo["lat"]], lon=[geo["lon"]],
                mode="markers",
                marker=dict(size=18, color="#ef4444", symbol="circle",
                            line=dict(color="#fca5a5", width=2),
                            opacity=0.85),
                text=[f'{ioc["value"]}<br>{geo["country_name"]}'],
                hoverinfo="text",
            ))
            fig.update_layout(
                geo=dict(
                    showland=True, landcolor="#0a1020",
                    showocean=True, oceancolor="#050810",
                    showlakes=False,
                    showcountries=True, countrycolor="rgba(0,170,255,.2)",
                    showframe=False, bgcolor="#050810",
                    projection_type="natural earth",
                ),
                paper_bgcolor="rgba(0,0,0,0)", height=280,
                margin=dict(l=0,r=0,t=0,b=0),
            )
            st.plotly_chart(fig, use_container_width=True)
            st.markdown(
                f'<div style="font-family:\'Share Tech Mono\',monospace;font-size:11px;color:#4a7fa5;text-align:center;">'
                f'📍 {geo["country_name"]} &nbsp;|&nbsp; {geo["lat"]}°N {geo["lon"]}°E</div>',
                unsafe_allow_html=True,
            )
        else:
            st.markdown('<div style="font-family:\'Share Tech Mono\',monospace;font-size:11px;color:#1e3a52;text-align:center;padding:40px;">Geolocation not available for this IOC type</div>', unsafe_allow_html=True)

    with tab7:
        tl_html = ""
        for entry in ioc.get("timeline", []):
            lvl = entry.get("level", "info")
            tl_html += (f'<div class="ti-tl-row"><div class="ti-tl-dot {lvl}"></div>'
                        f'<div class="ti-tl-time">{entry["time"]}</div>'
                        f'<div class="ti-tl-text">{entry["event"]}</div></div>')
        st.markdown(f'<div class="glass-panel" style="padding:10px 16px;">{tl_html}</div>', unsafe_allow_html=True)

    with tab8:
        related = ioc.get("related_iocs", [])
        if related:
            chips = " ".join(f'<span class="rel-ioc">🔗 {r}</span>' for r in related)
            st.markdown(f'<div class="glass-panel">{chips}</div>', unsafe_allow_html=True)
        else:
            st.markdown('<div class="glass-panel" style="font-family:\'Share Tech Mono\',monospace;font-size:11px;color:#1e3a52;">No correlated IOCs</div>', unsafe_allow_html=True)

    with tab9:
        recs = ioc.get("recommendations", [])
        recs_html = ""
        for i, rec in enumerate(recs, 1):
            recs_html += f'<div style="font-family:\'Share Tech Mono\',monospace;font-size:11px;color:#8892a4;padding:7px 12px;border-left:2px solid rgba(0,170,255,.35);margin-bottom:5px;background:rgba(0,170,255,.04);border-radius:0 5px 5px 0;"><span style="color:#00aaff;">{i:02d}.</span> {rec}</div>'
        st.markdown(recs_html or '<div style="color:#1e3a52;font-family:\'Share Tech Mono\',monospace;font-size:11px;">No recommendations available</div>', unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# Threat Feeds
# ─────────────────────────────────────────────────────────────────────────────

def _render_feeds(feeds: list):
    st.markdown('<div class="section-hdr" style="font-size:11px;">📡 INTELLIGENCE FEEDS</div>', unsafe_allow_html=True)
    for f in feeds:
        dot = f'<span class="feed-dot-{"ok" if f["status"]=="ok" else "err" if f["status"]=="err" else "warn"}"></span>'
        health_bar = (f'<div style="background:rgba(255,255,255,.05);border-radius:3px;height:4px;overflow:hidden;margin-top:4px;">'
                      f'<div style="height:100%;width:{f["health"]}%;background:{"#00ffaa" if f["health"]>80 else "#eab308" if f["health"]>40 else "#ef4444"};border-radius:3px;"></div></div>')
        enabled_txt = '<span style="color:#00ffaa;font-size:9px;">● ENABLED</span>' if f["enabled"] else '<span style="color:#ef4444;font-size:9px;">○ DISABLED</span>'
        st.markdown(
            f'<div class="feed-card">'
            f'<div style="display:flex;justify-content:space-between;align-items:center;">'
            f'<span class="feed-name">{dot}{f["name"]}</span>'
            f'{enabled_txt}'
            f'</div>'
            f'<div class="feed-meta">{f["type"]} &nbsp;·&nbsp; Updated: {f["last_update"]}</div>'
            f'<div style="display:flex;align-items:center;justify-content:space-between;margin-top:8px;">'
            f'<span class="feed-count">{f["ioc_count"]:,}</span>'
            f'<span class="feed-meta">IOCs &nbsp;·&nbsp; Health: {f["health"]}%</span>'
            f'</div>'
            f'{health_bar}'
            f'</div>',
            unsafe_allow_html=True,
        )


# ─────────────────────────────────────────────────────────────────────────────
# Malware Analysis
# ─────────────────────────────────────────────────────────────────────────────

def _render_malware(malwares: list, sev_badge):
    st.markdown('<div class="section-hdr" style="font-size:11px;">🦠 MALWARE FAMILIES</div>', unsafe_allow_html=True)
    for m in malwares:
        cves_html = " ".join(f'<span class="cve-chip">{c}</span>' for c in m["cves"]) if m["cves"] else ""
        ioc_count = len(m["related_iocs"])
        st.markdown(
            f'<div class="malware-card {m["severity"]}">'
            f'<div style="display:flex;justify-content:space-between;align-items:flex-start;">'
            f'<span class="malware-name">🦠 {m["name"]}</span>'
            f'{sev_badge(m["severity"])}'
            f'</div>'
            f'<div class="malware-meta" style="margin-top:6px;">{m["family"]}</div>'
            f'<div class="malware-meta">📥 {m["infection"]}</div>'
            f'<div class="malware-meta">🖥 {" · ".join(m["targets"])}</div>'
            f'<div style="font-family:\'Share Tech Mono\',monospace;font-size:10px;color:#8892a4;margin-top:6px;line-height:1.5;">{m["behavior"][:100]}…</div>'
            f'<div style="display:flex;justify-content:space-between;align-items:center;margin-top:8px;">'
            f'<span style="font-family:\'Share Tech Mono\',monospace;font-size:10px;color:#4a7fa5;">Since {m["active_since"]} &nbsp;·&nbsp; {m["detections"]} detections &nbsp;·&nbsp; {ioc_count} IOCs</span>'
            f'{cves_html}'
            f'</div>'
            f'</div>',
            unsafe_allow_html=True,
        )


# ─────────────────────────────────────────────────────────────────────────────
# Attack Campaigns
# ─────────────────────────────────────────────────────────────────────────────

def _render_campaigns(campaigns: list, sev_badge):
    st.markdown('<div class="section-hdr">// ACTIVE THREAT CAMPAIGNS</div>', unsafe_allow_html=True)

    STATUS_COLOR = {"Active": "#ef4444", "Monitoring": "#eab308", "Investigating": "#f97316"}

    # Table header
    hdr = (
        '<div class="glass-panel" style="padding:0;overflow-x:auto;">'
        '<table class="alert-table"><thead><tr>'
        '<th>CAMPAIGN</th><th>THREAT ACTOR</th><th>TARGET SECTOR</th>'
        '<th>ORIGIN</th><th>SEVERITY</th><th>ACTIVE SINCE</th><th>STATUS</th>'
        '</tr></thead><tbody>'
    )
    rows = ""
    for c in campaigns:
        sc = STATUS_COLOR.get(c["status"], "#6b7280")
        rows += (
            f'<tr>'
            f'<td style="color:#e6f1ff;font-weight:700;">{c["name"]}</td>'
            f'<td style="color:#c4b5fd;">{c["actor"]}</td>'
            f'<td style="color:#8892a4;">{c["sector"]}</td>'
            f'<td style="color:#8892a4;">{c["country"]}</td>'
            f'<td>{sev_badge(c["severity"])}</td>'
            f'<td style="color:#4a7fa5;font-size:10px;">{c["active_since"]}</td>'
            f'<td><span style="font-family:\'Share Tech Mono\',monospace;font-size:10px;color:{sc};">● {c["status"].upper()}</span></td>'
            f'</tr>'
        )
    st.markdown(hdr + rows + "</tbody></table></div>", unsafe_allow_html=True)

    # Campaign detail expander
    st.markdown('<div style="margin-top:12px;"></div>', unsafe_allow_html=True)
    camp_names = [c["name"] for c in campaigns]
    sel_camp = st.selectbox("Campaign Detail", camp_names, label_visibility="collapsed",
                            format_func=lambda x: f"▶  {x}", key="ti_camp_sel")
    camp = next(c for c in campaigns if c["name"] == sel_camp)

    with st.expander(f"CAMPAIGN INTELLIGENCE — {camp['name']}", expanded=False):
        left, right = st.columns(2)
        with left:
            techniques = " ".join(f'<span style="font-family:\'Share Tech Mono\',monospace;font-size:10px;color:#c4b5fd;background:rgba(139,92,246,.12);border:1px solid rgba(139,92,246,.25);padding:2px 7px;border-radius:4px;margin:2px;display:inline-block;">{t}</span>' for t in camp["mitre_techniques"])
            malware_tags = " ".join(f'<span style="font-family:\'Share Tech Mono\',monospace;font-size:10px;color:#fca5a5;background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.2);padding:2px 7px;border-radius:4px;margin:2px;display:inline-block;">🦠 {m}</span>' for m in camp["malware"])
            cve_tags = " ".join(f'<span class="cve-chip">{c}</span>' for c in camp["cves"]) if camp["cves"] else '<span style="font-family:\'Share Tech Mono\',monospace;font-size:10px;color:#1e3a52;">None confirmed</span>'
            st.markdown(
                f'<div class="glass-panel">'
                f'<div style="font-family:\'Share Tech Mono\',monospace;font-size:10px;color:#4a7fa5;margin-bottom:6px;">DESCRIPTION</div>'
                f'<div style="font-family:\'Share Tech Mono\',monospace;font-size:11px;color:#8892a4;line-height:1.65;">{camp["description"]}</div>'
                f'<div style="font-family:\'Share Tech Mono\',monospace;font-size:10px;color:#4a7fa5;margin:10px 0 6px;">MITRE TECHNIQUES</div>{techniques}'
                f'<div style="font-family:\'Share Tech Mono\',monospace;font-size:10px;color:#4a7fa5;margin:10px 0 6px;">MALWARE USED</div>{malware_tags}'
                f'<div style="font-family:\'Share Tech Mono\',monospace;font-size:10px;color:#4a7fa5;margin:10px 0 6px;">EXPLOITED CVEs</div>{cve_tags}'
                f'</div>',
                unsafe_allow_html=True,
            )
        with right:
            # YARA rule stub for campaign
            yara_rule = (
                f'<span class="rule-kw">rule</span> {camp["name"].replace(" ","_")} {{\n'
                f'  <span class="rule-kw">meta</span>:\n'
                f'    author = <span class="rule-str">"SENTINEL SOC-AI"</span>\n'
                f'    campaign = <span class="rule-str">"{camp["name"]}"</span>\n'
                f'    actor = <span class="rule-str">"{camp["actor"]}"</span>\n'
                f'  <span class="rule-kw">strings</span>:\n'
                f'    $s1 = <span class="rule-str">"{camp["malware"][0] if camp["malware"] else "unknown"}"</span> nocase\n'
                f'    $s2 = <span class="rule-str">"{camp["mitre_techniques"][0] if camp["mitre_techniques"] else "T0000"}"</span>\n'
                f'  <span class="rule-kw">condition</span>:\n'
                f'    any of them\n'
                f'}}'
            )
            st.markdown(
                f'<div class="glass-panel" style="padding:12px 14px;">'
                f'<div style="font-family:\'Share Tech Mono\',monospace;font-size:10px;color:#4a7fa5;margin-bottom:8px;">YARA RULE (AI-GENERATED)</div>'
                f'<div class="rule-block">{yara_rule}</div>'
                f'</div>',
                unsafe_allow_html=True,
            )


# ─────────────────────────────────────────────────────────────────────────────
# Threat Map
# ─────────────────────────────────────────────────────────────────────────────

def _render_threat_map(iocs: list):
    st.markdown('<div class="section-hdr" style="font-size:11px;">🌍 GLOBAL THREAT MAP</div>', unsafe_allow_html=True)

    TARGET_LAT, TARGET_LON = 36.8, 10.18  # Tunisia (your network location)

    attack_origins = [
        {"lat": 55.75, "lon": 37.62, "country": "Russia",        "count": 3, "color": "#ef4444"},
        {"lat": 51.16, "lon": 10.45, "country": "Germany",       "count": 2, "color": "#f97316"},
        {"lat": 6.45,  "lon": 3.40,  "country": "Nigeria",       "count": 2, "color": "#f97316"},
        {"lat": 35.68, "lon": 51.39, "country": "Iran",          "count": 1, "color": "#ef4444"},
        {"lat": 52.37, "lon": 4.90,  "country": "Netherlands",   "count": 1, "color": "#eab308"},
        {"lat": 50.45, "lon": 30.52, "country": "Ukraine",       "count": 1, "color": "#f97316"},
        {"lat": 45.94, "lon": 24.97, "country": "Romania",       "count": 1, "color": "#eab308"},
        {"lat": 37.77, "lon": -122.4,"country": "United States",  "count": 2, "color": "#eab308"},
    ]

    traces = []

    # Attack lines
    for o in attack_origins:
        traces.append(go.Scattergeo(
            lat=[o["lat"], TARGET_LAT], lon=[o["lon"], TARGET_LON],
            mode="lines",
            line=dict(width=max(1, o["count"]), color=o["color"]),
            opacity=0.55,
            showlegend=False, hoverinfo="skip",
        ))

    # Origin markers
    traces.append(go.Scattergeo(
        lat=[o["lat"] for o in attack_origins],
        lon=[o["lon"] for o in attack_origins],
        mode="markers",
        marker=dict(
            size=[8 + o["count"] * 3 for o in attack_origins],
            color=[o["color"] for o in attack_origins],
            opacity=0.85,
            line=dict(color="rgba(255,255,255,.3)", width=1),
        ),
        text=[f'{o["country"]} ({o["count"]} IOCs)' for o in attack_origins],
        hoverinfo="text",
        name="Attack Origins",
    ))

    # Target marker
    traces.append(go.Scattergeo(
        lat=[TARGET_LAT], lon=[TARGET_LON],
        mode="markers",
        marker=dict(size=14, color="#00ffaa", symbol="circle",
                    line=dict(color="#00ffaa", width=2), opacity=0.9),
        text=["Your Network (Target)"],
        hoverinfo="text",
        name="Target",
    ))

    fig = go.Figure(data=traces)
    fig.update_layout(
        geo=dict(
            showland=True, landcolor="#0a1020",
            showocean=True, oceancolor="#050810",
            showlakes=False,
            showcountries=True, countrycolor="rgba(0,170,255,.15)",
            showframe=False, bgcolor="#050810",
            projection_type="natural earth",
        ),
        paper_bgcolor="rgba(0,0,0,0)",
        height=360,
        margin=dict(l=0, r=0, t=0, b=0),
        showlegend=False,
        font=dict(family="Share Tech Mono"),
    )
    st.plotly_chart(fig, use_container_width=True)

    # Country stats
    country_counts = {o["country"]: o["count"] for o in sorted(attack_origins, key=lambda x: -x["count"])}
    cols = st.columns(4)
    for i, (country, count) in enumerate(list(country_counts.items())[:4]):
        with cols[i]:
            st.markdown(
                f'<div style="text-align:center;font-family:\'Share Tech Mono\',monospace;">'
                f'<div style="font-size:18px;font-weight:700;color:#ef4444;">{count}</div>'
                f'<div style="font-size:9px;color:#4a7fa5;letter-spacing:.08em;">{country.upper()}</div>'
                f'</div>',
                unsafe_allow_html=True,
            )


# ─────────────────────────────────────────────────────────────────────────────
# MITRE ATT&CK Matrix (simplified heatmap)
# ─────────────────────────────────────────────────────────────────────────────

def _render_mitre_matrix(iocs: list):
    st.markdown('<div class="section-hdr" style="font-size:11px;">🎯 MITRE ATT&CK HEATMAP</div>', unsafe_allow_html=True)

    TACTICS = ["Recon", "Init Access", "Execution", "Persistence",
               "Priv Esc", "Cred Access", "Lateral Mv", "C2", "Exfiltration", "Impact"]

    TECHNIQUES = [
        ("T1566", "Phishing",              [0,3,0,0,0,0,0,0,0,0]),
        ("T1190", "Exploit Public App",    [0,2,0,0,0,0,0,0,0,0]),
        ("T1204", "User Execution",        [0,0,4,0,0,0,0,0,0,0]),
        ("T1059", "Command Scripting",     [0,0,3,0,0,0,0,0,0,0]),
        ("T1505", "Server Component",      [0,0,0,2,0,0,0,0,0,0]),
        ("T1078", "Valid Accounts",        [0,0,0,1,2,0,0,0,0,0]),
        ("T1110", "Brute Force",           [0,0,0,0,0,5,0,0,0,0]),
        ("T1003", "OS Cred Dump",          [0,0,0,0,0,3,0,0,0,0]),
        ("T1021", "Remote Services",       [0,0,0,0,0,0,2,0,0,0]),
        ("T1071", "App Layer Protocol",    [0,0,0,0,0,0,0,4,0,0]),
        ("T1071.004","DNS C2",             [0,0,0,0,0,0,0,2,0,0]),
        ("T1048", "Exfil Alt Protocol",    [0,0,0,0,0,0,0,0,3,0]),
        ("T1486", "Data Encrypted",        [0,0,0,0,0,0,0,0,0,2]),
        ("T1490", "Inhibit Recovery",      [0,0,0,0,0,0,0,0,0,2]),
    ]

    z      = [row[2] for row in TECHNIQUES]
    y_lbls = [f"{row[0]} {row[1]}" for row in TECHNIQUES]

    fig = go.Figure(go.Heatmap(
        z=z, x=TACTICS, y=y_lbls,
        colorscale=[[0,"#050810"],[0.01,"#0d3a5c"],[0.4,"#0077cc"],[1,"#ef4444"]],
        showscale=False,
        hovertemplate="<b>%{y}</b><br>Tactic: %{x}<br>Detections: %{z}<extra></extra>",
    ))
    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Share Tech Mono", size=9),
        height=380,
        margin=dict(l=0, r=0, t=10, b=0),
        xaxis=dict(side="top", tickfont=dict(size=8), gridcolor="rgba(0,0,0,0)"),
        yaxis=dict(tickfont=dict(size=8), gridcolor="rgba(255,255,255,.03)"),
    )
    st.plotly_chart(fig, use_container_width=True)


# ─────────────────────────────────────────────────────────────────────────────
# Analytics
# ─────────────────────────────────────────────────────────────────────────────

def _render_analytics(iocs: list):
    SEV_COLORS = {"critical":"#ef4444","high":"#f97316","medium":"#eab308","low":"#3b82f6","info":"#6b7280"}
    TYPE_COLORS = {"IP":"#00aaff","Domain":"#c4b5fd","URL":"#fdba74","Hash":"#5eead4","Email":"#fde047","File":"#94a3b8"}
    LAYOUT = dict(
        template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Share Tech Mono", size=10),
        margin=dict(l=0,r=10,t=10,b=0),
    )

    c1, c2, c3 = st.columns(3)

    with c1:
        st.markdown('<div class="section-hdr" style="font-size:10px;">🔴 THREATS BY SEVERITY</div>', unsafe_allow_html=True)
        sev_c = {}
        for i in iocs: sev_c[i["severity"]] = sev_c.get(i["severity"], 0) + 1
        fig = go.Figure(go.Pie(
            labels=list(sev_c.keys()), values=list(sev_c.values()), hole=0.55,
            marker=dict(colors=[SEV_COLORS.get(s,"#6b7280") for s in sev_c.keys()],
                        line=dict(color="#050810",width=2)),
            textfont=dict(family="Share Tech Mono",size=10),
        ))
        fig.update_layout(**LAYOUT, height=240, legend=dict(font=dict(family="Share Tech Mono",size=9)))
        st.plotly_chart(fig, use_container_width=True)

    with c2:
        st.markdown('<div class="section-hdr" style="font-size:10px;">🏷 IOC TYPE DISTRIBUTION</div>', unsafe_allow_html=True)
        type_c = {}
        for i in iocs: type_c[i["type"]] = type_c.get(i["type"], 0) + 1
        fig = go.Figure(go.Bar(
            x=list(type_c.keys()), y=list(type_c.values()),
            marker=dict(color=[TYPE_COLORS.get(t,"#6b7280") for t in type_c.keys()], line=dict(width=0)),
            text=list(type_c.values()), textposition="outside",
            textfont=dict(family="Share Tech Mono",size=9),
        ))
        fig.update_layout(**LAYOUT, height=240, xaxis=dict(gridcolor="rgba(0,0,0,0)"),
                          yaxis=dict(gridcolor="rgba(255,255,255,.05)"))
        st.plotly_chart(fig, use_container_width=True)

    with c3:
        st.markdown('<div class="section-hdr" style="font-size:10px;">🌐 TOP ATTACKING COUNTRIES</div>', unsafe_allow_html=True)
        country_c = {}
        for i in iocs:
            c = i.get("country","—")
            if c not in ("—","Internal",""):
                country_c[c] = country_c.get(c, 0) + 1
        if country_c:
            sorted_c = sorted(country_c.items(), key=lambda x: x[1])
            fig = go.Figure(go.Bar(
                x=[v for _,v in sorted_c], y=[k for k,_ in sorted_c], orientation="h",
                marker=dict(color=[v for _,v in sorted_c],
                            colorscale=[[0,"#0d3a5c"],[0.5,"#0077cc"],[1,"#ef4444"]],
                            line=dict(width=0)),
                text=[v for _,v in sorted_c], textposition="outside",
                textfont=dict(family="Share Tech Mono",size=9),
            ))
            fig.update_layout(**LAYOUT, height=240, xaxis=dict(gridcolor="rgba(255,255,255,.05)"),
                              yaxis=dict(gridcolor="rgba(0,0,0,0)"))
            st.plotly_chart(fig, use_container_width=True)

    c4, c5 = st.columns(2)

    with c4:
        st.markdown('<div class="section-hdr" style="font-size:10px;">📈 IOC TREND (14 DAYS)</div>', unsafe_allow_html=True)
        rng = random.Random(42)
        days = pd.date_range(end=datetime.utcnow(), periods=14)
        trend = []
        for d in days:
            for sev in ["critical","high","medium"]:
                n = rng.randint(0, {"critical":3,"high":5,"medium":8}[sev])
                if n: trend.append({"day":d,"severity":sev,"count":n})
        if trend:
            df = pd.DataFrame(trend)
            fig = px.area(df, x="day", y="count", color="severity",
                          color_discrete_map=SEV_COLORS)
            fig.update_layout(**LAYOUT, height=240,
                              xaxis=dict(gridcolor="rgba(255,255,255,.05)"),
                              yaxis=dict(gridcolor="rgba(255,255,255,.05)"),
                              legend=dict(font=dict(family="Share Tech Mono",size=9)))
            st.plotly_chart(fig, use_container_width=True)

    with c5:
        st.markdown('<div class="section-hdr" style="font-size:10px;">🦠 TOP MALWARE DETECTIONS</div>', unsafe_allow_html=True)
        mal_data = {"Cobalt Strike":57,"Emotet":7,"QBot":4,"LockBit 3.0":3,"RedLine":2,"AgentTesla":1}
        fig = go.Figure(go.Bar(
            x=list(mal_data.values()), y=list(mal_data.keys()), orientation="h",
            marker=dict(color=list(mal_data.values()),
                        colorscale=[[0,"#0d3a5c"],[0.5,"#f97316"],[1,"#ef4444"]],
                        line=dict(width=0)),
            text=list(mal_data.values()), textposition="outside",
            textfont=dict(family="Share Tech Mono",size=9),
        ))
        fig.update_layout(**LAYOUT, height=240,
                          xaxis=dict(gridcolor="rgba(255,255,255,.05)"),
                          yaxis=dict(gridcolor="rgba(0,0,0,0)"))
        st.plotly_chart(fig, use_container_width=True)


# ─────────────────────────────────────────────────────────────────────────────
# AI Correlation Engine
# ─────────────────────────────────────────────────────────────────────────────

def _render_correlation(iocs: list, campaigns: list):
    st.markdown('<div class="section-hdr">// AI THREAT CORRELATION ENGINE</div>', unsafe_allow_html=True)

    findings = [
        {
            "title": "◉ COORDINATED BRUTE FORCE CLUSTER DETECTED",
            "body": (
                "AI detected a coordinated SSH brute force campaign linked to 3 incidents "
                "(INC-2026-0145, INC-2026-0138, INC-2026-0131). Attacker IPs share the same /24 "
                "subnet (192.168.110.0/24) and exhibit identical timing patterns (2-second intervals). "
                "Pattern consistent with internal compromised host acting as pivot."
            ),
            "tags": ["SSH", "Brute Force", "Internal Threat", "T1110.001", "CLUSTER"],
        },
        {
            "title": "◉ APT29 INFRASTRUCTURE OVERLAP — HIGH CONFIDENCE",
            "body": (
                "IOC-002 (185.220.101.45) and IOC-004 (update.microsoft-telemetry.com) share "
                "infrastructure with known APT29 (Cozy Bear) tooling. Domain registration patterns, "
                "ASN overlap (Frantech/AS204720), and Cobalt Strike malleable profile match "
                "NOBELIUM campaign indicators from 2025 MSTIC report. Confidence: 87%."
            ),
            "tags": ["APT29", "Cobalt Strike", "NOBELIUM", "T1071.001", "C2-CLUSTER"],
        },
        {
            "title": "◉ LOCKBIT AFFILIATE REUSING INFRASTRUCTURE",
            "body": (
                "IOC-008 (LockBit DLL hash), IOC-011 (5.188.86.172), and IOC-012 (payload URL) "
                "form a complete LockBit 3.0 attack chain. CISA KEV confirms this infrastructure "
                "is attributed to LockBit affiliate ID #14. Same affiliate attacked 3 healthcare "
                "organizations in Q1 2026. Vulnerabilities exploited: CVE-2023-4966, CVE-2021-34527."
            ),
            "tags": ["LockBit", "Ransomware", "CISA-KEV", "T1486", "Affiliate-14"],
        },
        {
            "title": "◉ PHISHING → LOADER → C2 KILL CHAIN CORRELATED",
            "body": (
                "AI correlated 4 IOCs into a single Emotet kill chain: "
                "contoso-corp.xyz (phishing domain) → Q1_Report.docm (Emotet loader) → "
                "accounts@contoso-corp.xyz (phishing sender) → 194.165.16.78 (Emotet C2). "
                "This matches PhishStorm 2026 campaign TTPs (TA505). "
                "3 finance users targeted — no breach, EDR blocked macro execution."
            ),
            "tags": ["Emotet", "TA505", "PhishStorm-2026", "T1566.001", "Kill-Chain"],
        },
        {
            "title": "◉ DNS TUNNELING RECONNAISSANCE PATTERN",
            "body": (
                "Two DNS tunneling incidents (INC-2026-0136, INC-2026-0139) share identical "
                "IODINE tool signatures and query encoding patterns. Different source IPs but "
                "same C2 infrastructure (AS20473 / Choopa LLC). Likely same threat actor "
                "conducting pre-attack reconnaissance across multiple network segments."
            ),
            "tags": ["DNS-Tunneling", "IODINE", "Reconnaissance", "T1071.004", "Same-Actor"],
        },
    ]

    for f in findings:
        tags_html = " ".join(f'<span class="corr-tag">{t}</span>' for t in f["tags"])
        st.markdown(
            f'<div class="corr-finding">'
            f'<div class="corr-hdr">{f["title"]}</div>'
            f'<div class="corr-body">{f["body"]}</div>'
            f'<div class="corr-tags">{tags_html}</div>'
            f'</div>',
            unsafe_allow_html=True,
        )


# ─────────────────────────────────────────────────────────────────────────────
# Watchlist
# ─────────────────────────────────────────────────────────────────────────────

def _render_watchlist(iocs: list, sev_badge):
    st.markdown('<div class="section-hdr">// ANALYST WATCHLIST</div>', unsafe_allow_html=True)
    watched = [i for i in iocs if i.get("watchlisted")]

    if not watched:
        st.markdown(
            '<div class="glass-panel" style="text-align:center;padding:40px;font-family:\'Share Tech Mono\',monospace;font-size:12px;color:#1e3a52;">'
            'Watchlist empty — mark IOCs as watchlisted from the IOC detail panel.'
            '</div>',
            unsafe_allow_html=True,
        )
        return

    rows_html = ""
    for i in watched:
        dw = f'<span class="dw-badge">🌑 {i["dark_web_mentions"]}</span>' if i["dark_web_mentions"] > 0 else ""
        rows_html += (
            f'<div class="watch-item">'
            f'<span style="flex:0.5;">{ioc_type_badge(i["type"])}</span>'
            f'<span style="font-family:\'Share Tech Mono\',monospace;font-size:11px;color:#00aaff;flex:3;">{i["value"]}{dw}</span>'
            f'<span style="flex:1;">{sev_badge(i["severity"])}</span>'
            f'<span style="font-family:\'Share Tech Mono\',monospace;font-size:10px;color:#4a7fa5;flex:1.5;">{i["status"]}</span>'
            f'<span style="font-family:\'Share Tech Mono\',monospace;font-size:10px;color:#4a7fa5;flex:2;">{i["last_seen"]}</span>'
            f'</div>'
        )
    st.markdown(
        f'<div class="glass-panel" style="padding:0;overflow-x:auto;">{rows_html}</div>',
        unsafe_allow_html=True,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Main entry point
# ─────────────────────────────────────────────────────────────────────────────

def render_threat_intelligence(sev_badge, kpi_card):
    st.markdown(THREAT_INTEL_CSS, unsafe_allow_html=True)

    # ── Page header ──────────────────────────────────────────────────
    st.markdown("""
    <div class="sentinel-header">
      <p class="sentinel-title">🔍 THREAT INTELLIGENCE</p>
      <p class="sentinel-sub">MONITOR · CORRELATE · ANALYZE CYBER THREAT INTELLIGENCE FEEDS IN REAL TIME</p>
      <div class="sentinel-badge">
        <span class="pulse-dot"></span> FEEDS ACTIVE
      </div>
    </div>
    """, unsafe_allow_html=True)

    # ── Session state ────────────────────────────────────────────────
    if "ti_iocs"          not in st.session_state: st.session_state.ti_iocs     = get_ioc_mock_data()
    if "ti_page"          not in st.session_state: st.session_state.ti_page     = 0
    if "ti_show_detail"   not in st.session_state: st.session_state.ti_show_detail = True

    all_iocs  = st.session_state.ti_iocs
    feeds     = get_feed_data()
    malwares  = get_malware_data()
    campaigns = get_campaign_data()

    # ── KPI Summary Cards ─────────────────────────────────────────────
    n_active   = sum(1 for i in all_iocs if i["status"] == "Active")
    n_mal_ips  = sum(1 for i in all_iocs if i["type"] == "IP")
    n_domains  = sum(1 for i in all_iocs if i["type"] == "Domain")
    n_malware  = len(malwares)
    n_feeds    = sum(1 for f in feeds if f["enabled"])
    n_campaigns= sum(1 for c in campaigns if c["status"] == "Active")

    st.markdown(
        '<div class="kpi-grid" style="grid-template-columns:repeat(6,1fr);">'
        + kpi_card("Active Threats",    n_active,    "▲ 2 new today",   "crit",  "🚨")
        + kpi_card("Malicious IPs",     n_mal_ips,   "▲ 3 added",       "high",  "🌐")
        + kpi_card("Malicious Domains", n_domains,   "▲ 1 new",         "high",  "🔗")
        + kpi_card("Malware Families",  n_malware,   "",                "med",   "🦠")
        + kpi_card("Feeds Connected",   n_feeds,     "▲ 1 degraded",    "green", "📡")
        + kpi_card("Active Campaigns",  n_campaigns, "▲ 1 escalated",   "crit",  "⚔")
        + "</div>",
        unsafe_allow_html=True,
    )

    # ── Search & Filter ───────────────────────────────────────────────
    st.markdown('<div class="section-hdr">// IOC SEARCH & FILTER ENGINE</div>', unsafe_allow_html=True)

    IOC_TYPES  = ["All Types", "IP", "Domain", "URL", "Hash", "Email", "File"]
    IOC_SEVS   = ["All Severities", "Critical", "High", "Medium", "Low"]
    IOC_STATUS = ["All Statuses", "Active", "Expired", "Blocked", "Monitoring"]
    IOC_SRCS   = ["All Sources", "AbuseIPDB", "AlienVault OTX", "VirusTotal",
                  "Suricata", "Wazuh (Internal)", "CISA KEV", "Mail Gateway"]

    col_s, col_t, col_sev, col_stat, col_src = st.columns([3, 1.2, 1.2, 1.2, 1.5])
    search_q  = col_s.text_input("Search IOC", placeholder="🔍  IP · Domain · Hash · CVE · Malware · MITRE ID · Attacker Group", label_visibility="collapsed")
    type_f    = col_t.selectbox("Type",     IOC_TYPES,  label_visibility="collapsed")
    sev_f     = col_sev.selectbox("Severity",  IOC_SEVS,   label_visibility="collapsed")
    stat_f    = col_stat.selectbox("Status",    IOC_STATUS, label_visibility="collapsed")
    src_f     = col_src.selectbox("Source",    IOC_SRCS,   label_visibility="collapsed")

    # ── Apply filters ─────────────────────────────────────────────────
    iocs = all_iocs[:]
    if search_q:
        q = search_q.lower()
        iocs = [i for i in iocs if
                q in i["value"].lower() or q in i["category"].lower() or
                q in i["mitre_technique"].lower() or q in i["mitre_name"].lower() or
                q in i.get("mitre_tactic","").lower() or q in i.get("org","").lower() or
                q in i.get("country","").lower() or q in " ".join(i.get("tags",[])).lower() or
                any(q in cve.lower() for cve in i.get("cves",[])) or
                any(q in inc.lower() for inc in i.get("related_incidents",[]))]
    if type_f  != "All Types":      iocs = [i for i in iocs if i["type"] == type_f]
    if sev_f   != "All Severities": iocs = [i for i in iocs if i["severity"] == sev_f.lower()]
    if stat_f  != "All Statuses":   iocs = [i for i in iocs if i["status"] == stat_f]
    if src_f   != "All Sources":    iocs = [i for i in iocs if src_f in i["source"]]

    # ── IOC Table ─────────────────────────────────────────────────────
    st.markdown('<div class="section-hdr">// IOC INTELLIGENCE REGISTRY</div>', unsafe_allow_html=True)

    PAGE_SIZE   = 8
    total_pages = max(1, (len(iocs) + PAGE_SIZE - 1) // PAGE_SIZE)
    st.session_state.ti_page = min(st.session_state.ti_page, total_pages - 1)
    page_iocs   = iocs[st.session_state.ti_page * PAGE_SIZE : (st.session_state.ti_page + 1) * PAGE_SIZE]

    if not iocs:
        st.markdown("""
        <div class="glass-panel" style="text-align:center;padding:60px 20px;">
          <div style="font-size:40px;opacity:.3;margin-bottom:14px;">🔍</div>
          <div style="font-family:'Share Tech Mono',monospace;font-size:14px;color:#4a7fa5;">NO IOCs MATCH YOUR FILTERS</div>
          <div style="font-family:'Share Tech Mono',monospace;font-size:11px;color:#1e3a52;margin-top:8px;">Adjust search or filter criteria</div>
        </div>""", unsafe_allow_html=True)
    else:
        rows_html = ""
        for ioc in page_iocs:
            watch_icon = "★" if ioc.get("watchlisted") else "☆"
            dw = f'<span class="dw-badge">🌑{ioc["dark_web_mentions"]}</span>' if ioc["dark_web_mentions"] > 0 else ""
            rows_html += (
                f"<tr>"
                f"<td>{ioc_type_badge(ioc['type'])}</td>"
                f"<td style='color:#00aaff;font-family:\"Share Tech Mono\",monospace;font-size:10px;'>{ioc['value'][:45]}{dw}</td>"
                f"<td style='color:#8892a4;'>{ioc['category']}</td>"
                f"<td>{sev_badge(ioc['severity'])}</td>"
                f"<td>{confidence_bar(ioc['confidence'])}</td>"
                f"<td style='color:#4a7fa5;font-size:10px;'>{ioc['source'][:25]}</td>"
                f"<td style='color:#4a7fa5;font-size:10px;'>{ioc['first_seen'][:10]}</td>"
                f"<td style='color:#4a7fa5;font-size:10px;'>{ioc['last_seen'][:10]}</td>"
                f"<td>{ioc_status_badge(ioc['status'])}</td>"
                f"<td style='color:#eab308;font-size:12px;'>{watch_icon}</td>"
                f"</tr>"
            )
        headers = "".join(f"<th>{h}</th>" for h in [
            "TYPE","IOC VALUE","CATEGORY","SEVERITY","CONFIDENCE",
            "SOURCE","FIRST SEEN","LAST SEEN","STATUS","★",
        ])
        st.markdown(
            f'<div class="glass-panel" style="padding:0;overflow-x:auto;">'
            f'<table class="alert-table"><thead><tr>{headers}</tr></thead>'
            f'<tbody>{rows_html}</tbody></table></div>',
            unsafe_allow_html=True,
        )

        p1, p2, p3 = st.columns([1, 3, 1])
        with p1:
            if st.button("◀ PREV", disabled=(st.session_state.ti_page == 0), key="ti_prev"):
                st.session_state.ti_page -= 1; st.rerun()
        with p2:
            st.markdown(
                f'<div style="font-family:\'Share Tech Mono\',monospace;font-size:11px;color:#4a7fa5;text-align:center;padding:8px;">'
                f'PAGE {st.session_state.ti_page+1} / {total_pages} &nbsp;·&nbsp; {len(iocs)} IOCs</div>',
                unsafe_allow_html=True,
            )
        with p3:
            if st.button("NEXT ▶", disabled=(st.session_state.ti_page >= total_pages-1), key="ti_next"):
                st.session_state.ti_page += 1; st.rerun()

    # ── IOC Detail Panel ──────────────────────────────────────────────
    if iocs:
        st.markdown('<div class="section-hdr">// IOC INTELLIGENCE PANEL</div>', unsafe_allow_html=True)

        sel_col, b1, b2, b3, b4 = st.columns([3, 1, 1, 1, 1])
        selected_id = sel_col.selectbox(
            "Select IOC", [i["id"] for i in iocs],
            label_visibility="collapsed",
            format_func=lambda x: f"▶  {x}  —  {next((i['value'][:40] for i in iocs if i['id']==x), '')}",
            key="ti_ioc_sel",
        )
        selected = next((i for i in iocs if i["id"] == selected_id), None)

        if b1.button("◉ INVESTIGATE", key="ti_investigate"):
            st.session_state.ti_show_detail = True

        if selected and b2.button("🚫 BLOCK IOC", key="ti_block"):
            for ioc in st.session_state.ti_iocs:
                if ioc["id"] == selected_id:
                    ioc["status"] = "Blocked"
            st.rerun()

        if selected and b3.button("★ WATCHLIST", key="ti_watch"):
            for ioc in st.session_state.ti_iocs:
                if ioc["id"] == selected_id:
                    ioc["watchlisted"] = not ioc.get("watchlisted", False)
            st.rerun()

        if selected and b4.button("⬇ EXPORT", key="ti_export"):
            report = _generate_threat_report(all_iocs, campaigns)
            st.download_button("⬇ Download Report", data=report.encode(),
                               file_name="SENTINEL_threat_intel_report.txt", mime="text/plain")

        if st.session_state.ti_show_detail and selected:
            with st.container():
                st.markdown('<div style="background:linear-gradient(135deg,#060d1a,#0b1628);border:1px solid rgba(0,170,255,.28);border-radius:12px;padding:22px 24px;margin-top:14px;">', unsafe_allow_html=True)
                _render_ioc_detail(selected, sev_badge)
                st.markdown('</div>', unsafe_allow_html=True)

    # ── Feeds + Malware (side by side) ────────────────────────────────
    st.markdown('<div style="margin-top:20px;"></div>', unsafe_allow_html=True)
    col_feeds, col_mal = st.columns([1, 1])
    with col_feeds:
        _render_feeds(feeds)
    with col_mal:
        _render_malware(malwares[:3], sev_badge)

    # ── Campaigns ─────────────────────────────────────────────────────
    _render_campaigns(campaigns, sev_badge)

    # ── Threat Map + MITRE Matrix ─────────────────────────────────────
    st.markdown('<div style="margin-top:20px;"></div>', unsafe_allow_html=True)
    col_map, col_mitre = st.columns([3, 2])
    with col_map:
        _render_threat_map(all_iocs)
    with col_mitre:
        _render_mitre_matrix(all_iocs)

    # ── Analytics ─────────────────────────────────────────────────────
    st.markdown('<div class="section-hdr" style="margin-top:20px;">// THREAT ANALYTICS</div>', unsafe_allow_html=True)
    with st.expander("EXPAND ANALYTICS DASHBOARD", expanded=True):
        _render_analytics(all_iocs)

    # ── AI Correlation Engine ─────────────────────────────────────────
    _render_correlation(all_iocs, campaigns)

    # ── Watchlist ─────────────────────────────────────────────────────
    _render_watchlist(all_iocs, sev_badge)
