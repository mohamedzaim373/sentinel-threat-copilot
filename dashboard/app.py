import os
import random
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import requests
import streamlit as st
from dotenv import load_dotenv
from incidents import render_incident_history
from threat_intel import render_threat_intelligence

PROJECT_ROOT = Path(__file__).resolve().parents[1]

load_dotenv(PROJECT_ROOT / ".env")

API_URL = os.getenv("API_URL", "http://localhost:8001")

st.set_page_config(
    page_title="SOC-AI Wazuh RAG · SENTINEL",
    page_icon="🛡️",
    layout="wide",
)

# ===========================================================================
# THEME — DARK MINIMAL
# ===========================================================================
st.markdown("""
<style>
/* ── Base ── */
.stApp { background: #0e1117; color: #e2e8f0; }
#MainMenu, footer, header { visibility: hidden; }
.block-container { padding-top: 1rem; padding-bottom: 2rem; }
h1, h2, h3, h4 { color: #e2e8f0 !important; }

/* ── Sidebar ── */
section[data-testid="stSidebar"] { background: #0a0f1a; border-right: 1px solid rgba(255,255,255,.08); }
[data-testid="stSidebarNav"] { display: none; }
section[data-testid="stSidebar"] .stRadio > div { gap: 1px !important; }
section[data-testid="stSidebar"] .stRadio label {
  font-family: monospace !important; font-size: 13px !important; color: #64748b !important;
  padding: 6px 10px 6px 12px !important; border-radius: 4px !important;
  border-left: 2px solid transparent !important; display: block !important;
  width: 100% !important; cursor: pointer !important;
}
section[data-testid="stSidebar"] .stRadio label:hover {
  color: #60a5fa !important; background: rgba(59,130,246,.07) !important;
  border-left-color: rgba(59,130,246,.4) !important;
}
section[data-testid="stSidebar"] .stRadio [data-baseweb="radio"] input:checked + div + label,
section[data-testid="stSidebar"] .stRadio label[data-selected="true"] {
  color: #60a5fa !important; border-left-color: #3b82f6 !important;
  background: rgba(59,130,246,.08) !important;
}
section[data-testid="stSidebar"] .stRadio [data-baseweb="radio"] > div:first-child { display: none !important; }
section[data-testid="stSidebar"] .stButton > button {
  background: transparent !important; border: 1px solid rgba(255,255,255,.1) !important;
  color: #64748b !important; font-family: monospace !important; font-size: 11px !important;
  width: 100% !important; border-radius: 4px !important; padding: 5px 0 !important;
}
section[data-testid="stSidebar"] .stButton > button:hover {
  background: rgba(59,130,246,.08) !important; border-color: rgba(59,130,246,.35) !important;
  color: #60a5fa !important;
}

/* ── Sidebar brand ── */
.sb-logo-wrap { text-align: center; padding: 16px 12px 8px; }
.sb-logo-hex  { font-family: monospace; font-size: 22px; color: #3b82f6; display: block; }
.sb-logo-sub  { font-family: monospace; font-size: 9px; color: #334155; letter-spacing: .18em; }
.sb-nav-section { font-family: monospace; font-size: 10px; color: #334155; letter-spacing: .16em; padding: 10px 12px 4px; text-transform: uppercase; }
.sb-sep     { height: 1px; background: rgba(255,255,255,.06); margin: 8px 12px; }
.sb-status  { text-align: center; font-family: monospace; font-size: 11px; color: #22c55e; padding: 6px; }
.sb-ts      { font-family: monospace; font-size: 9px; color: #1e293b; text-align: center; padding-bottom: 4px; }
.sb-version { font-family: monospace; font-size: 9px; color: #1e293b; text-align: center; padding: 2px; }

/* ── API status panel ── */
.api-panel { background: #111827; border: 1px solid rgba(255,255,255,.07); border-radius: 6px; overflow: hidden; margin: 6px 0; }
.api-panel-hdr { background: rgba(255,255,255,.03); border-bottom: 1px solid rgba(255,255,255,.05); font-family: monospace; font-size: 9px; color: #64748b; padding: 5px 10px; letter-spacing: .15em; text-transform: uppercase; display: flex; justify-content: space-between; }
.api-row { display: flex; align-items: center; gap: 8px; padding: 5px 10px; border-bottom: 1px solid rgba(255,255,255,.03); }
.api-row:last-child { border-bottom: none; }
.api-dot-ok   { color: #22c55e; font-size: 8px; flex-shrink: 0; }
.api-dot-err  { color: #ef4444; font-size: 8px; flex-shrink: 0; }
.api-dot-warn { color: #eab308; font-size: 8px; flex-shrink: 0; }
.api-name      { font-family: monospace; font-size: 10px; flex: 1; color: #94a3b8; }
.api-name.ok   { color: #94a3b8; }
.api-name.err  { color: #ef4444; }
.api-name.warn { color: #eab308; }
.api-detail    { font-family: monospace; font-size: 9px; color: #334155; }
.api-summary   { display: flex; justify-content: space-around; padding: 5px; font-family: monospace; font-size: 9px; background: rgba(0,0,0,.2); border-top: 1px solid rgba(255,255,255,.04); }
.api-sum-ok  { color: #22c55e; }
.api-sum-err { color: #ef4444; }
.api-sum-warn{ color: #eab308; }

/* ── Page header ── */
.sentinel-header { background: #111827; border: 1px solid rgba(255,255,255,.08); border-radius: 8px; padding: 16px 20px; margin-bottom: 20px; position: relative; }
.sentinel-title  { font-family: monospace; font-size: 22px; color: #3b82f6; margin: 0; }
.sentinel-sub    { font-family: monospace; font-size: 11px; color: #64748b; margin-top: 4px; }
.sentinel-badge  { position: absolute; right: 20px; top: 16px; font-family: monospace; font-size: 10px; color: #22c55e; border: 1px solid rgba(34,197,94,.25); padding: 3px 10px; border-radius: 4px; background: rgba(34,197,94,.06); }

/* ── Section header ── */
.section-hdr { font-family: monospace; font-size: 12px; letter-spacing: .12em; text-transform: uppercase; color: #3b82f6; border-left: 2px solid #3b82f6; padding-left: 8px; margin: 16px 0 12px; }

/* ── Glass panel ── */
.glass-panel { background: #111827; border: 1px solid rgba(255,255,255,.08); border-radius: 8px; padding: 16px; margin-bottom: 14px; }

/* ── KPI ── */
.kpi-grid { display: grid; grid-template-columns: repeat(5,1fr); gap: 12px; margin-bottom: 18px; }
.kpi-card { background: #111827; border: 1px solid rgba(255,255,255,.08); border-radius: 8px; padding: 14px 16px; position: relative; }
.kpi-card.crit  { border-bottom: 2px solid #ef4444; }
.kpi-card.high  { border-bottom: 2px solid #f97316; }
.kpi-card.info  { border-bottom: 2px solid #3b82f6; }
.kpi-card.green { border-bottom: 2px solid #22c55e; }
.kpi-card.med   { border-bottom: 2px solid #eab308; }
.kpi-label { font-family: monospace; font-size: 10px; color: #64748b; text-transform: uppercase; letter-spacing: .1em; margin-bottom: 6px; }
.kpi-value { font-family: monospace; font-size: 24px; font-weight: 700; color: #e2e8f0; line-height: 1; }
.kpi-delta { font-family: monospace; font-size: 11px; color: #22c55e; margin-top: 4px; }
.kpi-delta.neg { color: #ef4444; }
.kpi-icon  { position: absolute; right: 14px; top: 14px; font-size: 20px; opacity: .3; }

/* ── Alert table ── */
.alert-table { width: 100%; border-collapse: collapse; font-size: 12px; }
.alert-table thead th { font-family: monospace; color: #64748b; font-size: 10px; letter-spacing: .08em; text-transform: uppercase; padding: 7px 10px; text-align: left; border-bottom: 1px solid rgba(255,255,255,.08); }
.alert-table tbody tr { border-bottom: 1px solid rgba(255,255,255,.04); }
.alert-table tbody tr:hover { background: rgba(59,130,246,.05); }
.alert-table tbody td { padding: 6px 10px; font-family: monospace; color: #94a3b8; vertical-align: middle; }
.alert-table tbody td.score-cell { color: #e2e8f0; font-weight: 700; }

/* ── Severity badges ── */
.sev-critical { background: rgba(239,68,68,.15); color: #fca5a5; border: 1px solid rgba(239,68,68,.35); padding: 1px 7px; border-radius: 3px; font-family: monospace; font-size: 10px; }
.sev-high     { background: rgba(249,115,22,.15); color: #fdba74; border: 1px solid rgba(249,115,22,.35); padding: 1px 7px; border-radius: 3px; font-family: monospace; font-size: 10px; }
.sev-medium   { background: rgba(234,179,8,.15);  color: #fde047; border: 1px solid rgba(234,179,8,.35);  padding: 1px 7px; border-radius: 3px; font-family: monospace; font-size: 10px; }
.sev-low      { background: rgba(59,130,246,.15); color: #93c5fd; border: 1px solid rgba(59,130,246,.35); padding: 1px 7px; border-radius: 3px; font-family: monospace; font-size: 10px; }
.sev-info     { background: rgba(100,116,139,.15);color: #94a3b8; border: 1px solid rgba(100,116,139,.3);  padding: 1px 7px; border-radius: 3px; font-family: monospace; font-size: 10px; }

/* ── Live dot ── */
.dot-live { width: 7px; height: 7px; border-radius: 50%; background: #22c55e; display: inline-block; animation: blink 1.5s infinite; }
.dot-mock { width: 7px; height: 7px; border-radius: 50%; background: #eab308; display: inline-block; }
@keyframes blink { 0%,100%{opacity:1} 50%{opacity:.25} }

/* ── Alert banners ── */
.live-alert { background: rgba(239,68,68,.08); border: 1px solid rgba(239,68,68,.25); border-left: 3px solid #ef4444; border-radius: 6px; padding: 10px 14px; font-family: monospace; font-size: 12px; color: #fca5a5; margin-bottom: 12px; }
.info-alert { background: rgba(59,130,246,.07); border: 1px solid rgba(59,130,246,.2);  border-left: 3px solid #3b82f6; border-radius: 6px; padding: 10px 14px; font-family: monospace; font-size: 12px; color: #93c5fd; margin-bottom: 12px; }

/* ── Kanban ── */
.kanban-col { border-radius: 8px; padding: 12px; }
.kanban-col.open     { background: rgba(239,68,68,.04);  border: 1px solid rgba(239,68,68,.15);  }
.kanban-col.progress { background: rgba(249,115,22,.04); border: 1px solid rgba(249,115,22,.15); }
.kanban-col.resolved { background: rgba(34,197,94,.04);  border: 1px solid rgba(34,197,94,.15);  }
.kanban-hdr { font-family: monospace; font-size: 11px; letter-spacing: .12em; text-transform: uppercase; padding-bottom: 8px; margin-bottom: 8px; border-bottom: 1px solid rgba(255,255,255,.05); }
.kanban-hdr.open     { color: #ef4444; }
.kanban-hdr.progress { color: #f97316; }
.kanban-hdr.resolved { color: #22c55e; }
.inc-card  { background: #111827; border: 1px solid rgba(255,255,255,.07); border-radius: 6px; padding: 10px 12px; margin-bottom: 7px; }
.inc-id    { font-family: monospace; font-size: 10px; color: #64748b; margin-bottom: 4px; }
.inc-title { font-size: 13px; color: #e2e8f0; font-weight: 600; margin-bottom: 5px; }
.inc-meta  { font-family: monospace; font-size: 10px; color: #64748b; margin-top: 4px; }

/* ── Widgets ── */
.stSelectbox > div > div, .stTextInput > div > div > input {
  background: #111827 !important; border-color: rgba(255,255,255,.12) !important;
  color: #e2e8f0 !important; font-family: monospace !important;
}
.stButton > button {
  background: rgba(59,130,246,.1) !important; border: 1px solid rgba(59,130,246,.3) !important;
  color: #60a5fa !important; font-family: monospace !important; font-size: 12px !important;
  border-radius: 5px !important;
}
.stButton > button:hover { background: rgba(59,130,246,.18) !important; border-color: #3b82f6 !important; }

/* ── Scrollbar ── */
::-webkit-scrollbar { width: 5px; height: 5px; }
::-webkit-scrollbar-track { background: #0e1117; }
::-webkit-scrollbar-thumb { background: rgba(255,255,255,.15); border-radius: 3px; }
</style>
""", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEV_COLORS = {
    "critical": "#ef4444",
    "high":     "#f97316",
    "medium":   "#eab308",
    "low":      "#3b82f6",
    "info":     "#6b7280",
}
MITRE = [
    ("T1110", "Brute Force"),
    ("T1078", "Valid Accounts"),
    ("T1059", "Command Execution"),
    ("T1486", "Data Encrypted"),
    ("T1071", "App Layer Protocol"),
    ("T1003", "OS Credential Dump"),
    ("T1566", "Phishing"),
    ("T1190", "Exploit Public App"),
]
ASSETS = ["web-prod-01", "db-master", "k8s-edge-3", "vpn-gw", "fw-core",
          "auth-svc", "mail-relay", "win-dc-01"]

RULE_MITRE_MAP = {
    "5760":   ("T1110", "Brute Force"),
    "5758":   ("T1110", "Brute Force"),
    "5763":   ("T1110.001", "Password Guessing"),
    "5551":   ("T1110", "Brute Force"),
    "5503":   ("T1110", "Brute Force"),
    "2502":   ("T1110", "Brute Force"),
    "40111":  ("T1110", "Brute Force"),
    "100500": ("T1110", "Brute Force"),
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def get_api_data(endpoint: str, timeout: int = 900):
    try:
        r = requests.get(f"{API_URL}{endpoint}", timeout=timeout)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        st.markdown(f'<div class="info-alert">⚠ API error : {e}</div>', unsafe_allow_html=True)
        return None


def sev_badge(sev: str) -> str:
    return f'<span class="sev-{sev}">{sev.upper()}</span>'


def wazuh_level_to_severity(level) -> str:
    try:
        lvl = int(level)
    except Exception:
        return "info"
    if lvl >= 12: return "critical"
    if lvl >= 9:  return "high"
    if lvl >= 6:  return "medium"
    if lvl >= 3:  return "low"
    return "info"


def kpi_card(label, value, delta="", accent="info", icon=""):
    delta_html = f"<div class='kpi-delta'>{delta}</div>" if delta else ""
    return (
        f'<div class="kpi-card {accent}">'
        f'<div class="kpi-icon">{icon}</div>'
        f'<div class="kpi-label">{label}</div>'
        f'<div class="kpi-value">{value}</div>'
        f'{delta_html}'
        f'</div>'
    )


def alert_table_html(df_view, cols):
    rows_html = ""
    for _, row in df_view.iterrows():
        cells = ""
        for c in cols:
            val = row.get(c, "")
            if c == "score":
                cells += f'<td class="score-cell">{val}</td>'
            elif c == "sev":
                cells += f'<td>{val}</td>'
            else:
                cells += f'<td>{val}</td>'
        rows_html += f"<tr>{cells}</tr>"
    headers = "".join(f"<th>{c}</th>" for c in cols)
    return f"""
    <div class="glass-panel" style="padding:0;overflow-x:auto;">
      <table class="alert-table">
        <thead><tr>{headers}</tr></thead>
        <tbody>{rows_html}</tbody>
      </table>
    </div>"""


@st.cache_data(ttl=30)
def mock_alert_stream(n: int = 60, seed: int = 42) -> pd.DataFrame:
    rng = random.Random(seed)
    now = datetime.utcnow()
    rows = []
    for i in range(n):
        sev = rng.choices(SEVERITIES, weights=[1, 2, 3, 4, 2])[0]
        m = rng.choice(MITRE)
        score = {"critical": 90, "high": 70, "medium": 50,
                 "low": 30, "info": 10}[sev] + rng.randint(-5, 9)
        rows.append({
            "id": f"ALT-{10000+i}",
            "ts": now - timedelta(seconds=i * rng.randint(20, 600)),
            "src_ip": f"{rng.randint(10,240)}.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(0,255)}",
            "asset": rng.choice(ASSETS),
            "rule_id": str(5000 + rng.randint(0, 4000)),
            "mitre": m[0], "mitre_name": m[1],
            "severity": sev, "score": score,
            "description": rng.choice([
                "Multiple authentication failures",
                "Suspicious PowerShell invocation",
                "Outbound connection to known C2",
                "Privilege escalation attempt",
                "Unusual login geolocation",
                "Lateral movement pattern detected",
                "DNS tunneling indicators",
            ]),
            "count": rng.randint(1, 25),
        })
    return pd.DataFrame(rows)


@st.cache_data(ttl=30)
def load_real_alerts(limit: int = 100) -> pd.DataFrame:
    try:
        r = requests.get(f"{API_URL}/alerts/ssh?limit={limit}&min_level=8", timeout=15)
        r.raise_for_status()
        data = r.json()
        alerts = data.get("alerts", [])
        if not alerts:
            return pd.DataFrame()
        rng = random.Random(99)
        rows = []
        for i, a in enumerate(alerts):
            sev = wazuh_level_to_severity(a.get("rule_level"))
            rule_id = str(a.get("rule_id", ""))
            mitre_t = RULE_MITRE_MAP.get(rule_id, rng.choice(MITRE))
            score = ({"critical": 90, "high": 70, "medium": 50, "low": 30, "info": 10}[sev]
                     + rng.randint(-5, 9))
            try:
                ts = pd.to_datetime(a.get("timestamp"))
            except Exception:
                ts = datetime.utcnow() - timedelta(seconds=i * 60)
            rows.append({
                "id": f"ALT-{rule_id}-{i}",
                "ts": ts,
                "src_ip": a.get("srcip") or f"{rng.randint(10,240)}.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(0,255)}",
                "asset": a.get("agent_name") or rng.choice(ASSETS),
                "rule_id": rule_id,
                "mitre": mitre_t[0], "mitre_name": mitre_t[1],
                "severity": sev, "score": score,
                "description": a.get("description") or "Unknown alert",
                "count": 1,
            })
        return pd.DataFrame(rows)
    except Exception:
        return pd.DataFrame()


def get_alert_data(limit: int = 100) -> pd.DataFrame:
    df = load_real_alerts(limit)
    if not df.empty:
        return df
    return mock_alert_stream(limit)


# ---------------------------------------------------------------------------
# API Connection Checker
# ---------------------------------------------------------------------------
import os as _os

_GROQ_KEY       = _os.getenv("GROQ_API_KEY", "")
_ABUSEIPDB_KEY  = _os.getenv("ABUSEIPDB_API_KEY", "")
_VT_KEY         = _os.getenv("VIRUSTOTAL_API_KEY", "")
_GN_KEY         = _os.getenv("GREYNOISE_API_KEY", "")
_OPENSEARCH_URL = "https://localhost:9200"
_OPENSEARCH_USR = "admin"
_OPENSEARCH_PWD = _os.getenv("OPENSEARCH_PASS", "")
_CHROMA_PATH    = PROJECT_ROOT / "chroma_db" / "chroma.sqlite3"


def _ping(url, timeout=4, **kw):
    try:
        r = requests.get(url, timeout=timeout, **kw)
        return r.status_code < 500, r.status_code
    except requests.exceptions.ConnectionError:
        return False, "unreachable"
    except requests.exceptions.Timeout:
        return False, "timeout"
    except Exception as e:
        return False, str(e)


def _check_all_apis() -> list[dict]:
    results = []

    # 1. FastAPI backend
    ok, code = _ping(f"{API_URL}/")
    results.append({"name": "FastAPI Backend", "icon": "⬡",
                     "ok": ok, "detail": f":{API_URL.split(':')[-1]} · HTTP {code}"})

    # 2. OpenSearch
    ok, code = _ping(_OPENSEARCH_URL, auth=(_OPENSEARCH_USR, _OPENSEARCH_PWD), verify=False)
    results.append({"name": "OpenSearch", "icon": "◈",
                     "ok": ok, "detail": f":9200 · HTTP {code}"})

    # 3. Groq API
    if not _GROQ_KEY or _GROQ_KEY.startswith("your_"):
        results.append({"name": "Groq API", "icon": "◆",
                         "ok": None, "detail": "key not configured"})
    else:
        ok, code = _ping("https://api.groq.com", timeout=6)
        results.append({"name": "Groq API", "icon": "◆",
                         "ok": ok, "detail": f"llama-3.3-70b · HTTP {code}"})

    # 4. AbuseIPDB
    if not _ABUSEIPDB_KEY or _ABUSEIPDB_KEY.startswith("your_"):
        results.append({"name": "AbuseIPDB", "icon": "◇",
                         "ok": None, "detail": "key not configured"})
    else:
        try:
            r = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": _ABUSEIPDB_KEY, "Accept": "application/json"},
                params={"ipAddress": "8.8.8.8", "maxAgeInDays": 1},
                timeout=6,
            )
            ok = r.status_code == 200
            results.append({"name": "AbuseIPDB", "icon": "◇",
                             "ok": ok, "detail": f"HTTP {r.status_code}"})
        except Exception as e:
            results.append({"name": "AbuseIPDB", "icon": "◇",
                             "ok": False, "detail": str(e)[:30]})

    # 5. VirusTotal
    if not _VT_KEY or _VT_KEY.startswith("your_"):
        results.append({"name": "VirusTotal", "icon": "◇",
                         "ok": None, "detail": "key not configured"})
    else:
        try:
            r = requests.get(
                "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8",
                headers={"x-apikey": _VT_KEY},
                timeout=6,
            )
            ok = r.status_code == 200
            results.append({"name": "VirusTotal", "icon": "◇",
                             "ok": ok, "detail": f"HTTP {r.status_code}"})
        except Exception as e:
            results.append({"name": "VirusTotal", "icon": "◇",
                             "ok": False, "detail": str(e)[:30]})

    # 6. GreyNoise
    if not _GN_KEY or _GN_KEY.startswith("your_"):
        results.append({"name": "GreyNoise", "icon": "◇",
                         "ok": None, "detail": "key not configured"})
    else:
        try:
            r = requests.get(
                "https://api.greynoise.io/v3/community/8.8.8.8",
                headers={"key": _GN_KEY}, timeout=6,
            )
            ok = r.status_code in (200, 404)
            results.append({"name": "GreyNoise", "icon": "◇",
                             "ok": ok, "detail": f"HTTP {r.status_code}"})
        except Exception as e:
            results.append({"name": "GreyNoise", "icon": "◇",
                             "ok": False, "detail": str(e)[:30]})

    # 7. ThreatFox
    try:
        r = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "search_ioc", "search_term": "8.8.8.8"},
            timeout=6,
        )
        ok = r.status_code == 200
        results.append({"name": "ThreatFox", "icon": "◇",
                         "ok": ok, "detail": f"HTTP {r.status_code}"})
    except Exception as e:
        results.append({"name": "ThreatFox", "icon": "◇",
                         "ok": False, "detail": str(e)[:30]})

    # 8. URLHaus
    try:
        r = requests.post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            data={"host": "8.8.8.8"}, timeout=6,
        )
        ok = r.status_code == 200
        results.append({"name": "URLHaus", "icon": "◇",
                         "ok": ok, "detail": f"HTTP {r.status_code}"})
    except Exception as e:
        results.append({"name": "URLHaus", "icon": "◇",
                         "ok": False, "detail": str(e)[:30]})

    # 9. ChromaDB (local)
    chroma_ok = _CHROMA_PATH.exists()
    size_kb    = round(_CHROMA_PATH.stat().st_size / 1024) if chroma_ok else 0
    results.append({"name": "ChromaDB", "icon": "◉",
                     "ok": chroma_ok, "detail": f"local · {size_kb} KB" if chroma_ok else "file not found"})

    return results


def _render_api_status(results: list[dict]):
    n_ok   = sum(1 for s in results if s["ok"] is True)
    n_err  = sum(1 for s in results if s["ok"] is False)
    n_warn = sum(1 for s in results if s["ok"] is None)

    rows_html = ""
    for s in results:
        if s["ok"] is True:
            dot_cls, name_cls, dot_sym = "api-dot-ok",   "ok",   "●"
        elif s["ok"] is False:
            dot_cls, name_cls, dot_sym = "api-dot-err",  "err",  "●"
        else:
            dot_cls, name_cls, dot_sym = "api-dot-warn", "warn", "●"
        rows_html += (
            f'<div class="api-row">'
            f'<span class="{dot_cls}">{dot_sym}</span>'
            f'<span class="api-name {name_cls}">{s["name"]}</span>'
            f'<span class="api-detail">{s["detail"]}</span>'
            f'</div>'
        )

    st.markdown(
        f'<div class="api-panel">'
        f'<div class="api-panel-hdr">'
        f'<span>CONNECTION STATUS</span>'
        f'<span style="color:#1a3a52;">{n_ok}/{len(results)} OK</span>'
        f'</div>'
        f'{rows_html}'
        f'<div class="api-summary">'
        f'<span class="api-sum-ok">✓ {n_ok} OK</span>'
        f'<span class="api-sum-err">✗ {n_err} ERR</span>'
        f'<span class="api-sum-warn">⚠ {n_warn} WARN</span>'
        f'</div>'
        f'</div>',
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------
with st.sidebar:
    # ── Logo ─────────────────────────────────────────────────────────
    st.markdown(
        '<div class="sb-logo-wrap">'
        '<span class="sb-logo-hex">⬡ SENTINEL</span>'
        '<span class="sb-logo-sub">SOC-AI · WAZUH RAG · v2.0</span>'
        '</div>',
        unsafe_allow_html=True,
    )

    # ── Dashboard nav ─────────────────────────────────────────────────
    st.markdown('<div class="sb-nav-section">DASHBOARD</div>', unsafe_allow_html=True)
    page = st.radio(
        "nav",
        [
            "🧠 SOC Overview",
            "🚨 Alert Triage",
            "🎯 MITRE ATT&CK",
            "📋 Incidents",
            "📚 Incident History",
            "🔍 Threat Intelligence",
            "📈 Analytics",
        ],
        label_visibility="collapsed",
        key="nav_dash",
    )

    # ── LLM Agents nav ────────────────────────────────────────────────
    st.markdown('<div class="sb-nav-section">LLM AGENTS</div>', unsafe_allow_html=True)
    page_agent = st.radio(
        "agents",
        [
            "—",
            "Dernière alerte",
            "Analyse Agent 1",
            "Analyse RAG Agent 2",
            "Rapport SOC Final",
        ],
        label_visibility="collapsed",
        key="nav_agent",
    )

    # resolve active page (agent selection overrides dashboard)
    if page_agent != "—":
        page = page_agent

    # ── Controls ──────────────────────────────────────────────────────
    st.markdown('<div class="sb-sep"></div>', unsafe_allow_html=True)
    if st.button("⟳  REFRESH DATA"):
        st.cache_data.clear()
        st.session_state["nav_agent"] = "—"
        st.rerun()

    # ── API Status ────────────────────────────────────────────────────
    st.markdown('<div class="sb-nav-section">API STATUS</div>', unsafe_allow_html=True)
    if st.button("◎  CHECK CONNECTIONS"):
        with st.spinner(""):
            st.session_state["api_check"] = _check_all_apis()

    if "api_check" in st.session_state:
        _render_api_status(st.session_state["api_check"])

    # ── Footer ────────────────────────────────────────────────────────
    st.markdown('<div class="sb-sep"></div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="sb-status">'
        '<span class="dot-live" style="display:inline-block;"></span>'
        'SENTINEL ONLINE'
        '</div>',
        unsafe_allow_html=True,
    )
    st.markdown(
        f'<div class="sb-ts">UTC&nbsp;{datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")}</div>',
        unsafe_allow_html=True,
    )
    st.markdown('<div class="sb-version">WAZUH + GROQ + CHROMA</div>', unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Global header
# ---------------------------------------------------------------------------
st.markdown("""
<div class="sentinel-header">
  <p class="sentinel-title">⬡ SOC-AI WAZUH RAG · SENTINEL</p>
  <p class="sentinel-sub">SECURITY OPERATIONS CENTER · LLM AGENTS · RAG THREAT INTELLIGENCE</p>
  <div class="sentinel-badge">◉ SYSTEM ACTIVE</div>
</div>
""", unsafe_allow_html=True)


# ===========================================================================
# 1. SOC OVERVIEW
# ===========================================================================
if page == "🧠 SOC Overview":
    st.markdown('<div class="section-hdr">// SITUATIONAL AWARENESS</div>', unsafe_allow_html=True)

    df = get_alert_data(80)
    is_live = not load_real_alerts(1).empty

    latest = get_api_data("/alerts/latest", timeout=10)
    if latest and latest.get("rule_id"):
        real_sev = wazuh_level_to_severity(latest.get("rule_level"))
        groups_str = ", ".join(latest.get("groups") or []) or "—"
        st.markdown(
            f'<div class="live-alert">'
            f'◉ LIVE · Rule {latest.get("rule_id")} · {sev_badge(real_sev)} · '
            f'SRC {latest.get("srcip", "—")} · USER {latest.get("target_user", "—")} · '
            f'GROUPS {groups_str}'
            f'</div>',
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            '<div class="info-alert">◎ API Wazuh non disponible — données simulées actives</div>',
            unsafe_allow_html=True,
        )

    # KPI row
    n_crit = len(df[df.severity == "critical"])
    status_dot = "dot-live" if is_live else "dot-mock"
    status_txt = "LIVE DATA" if is_live else "SIMULATED"
    st.markdown(
        f'<div class="kpi-grid">'
        + kpi_card("Alertes 1h",   len(df),               f"▲ {n_crit} critical", "crit",  "🔔")
        + kpi_card("Incidents",    7,                      "▲ 2 new",             "high",  "🚨")
        + kpi_card("MTTD",         "4m 12s",              "▼ 18%",               "green", "⏱")
        + kpi_card("MTTR",         "23m",                  "▼ 9%",               "info",  "🔧")
        + kpi_card("Sources uniq", df["src_ip"].nunique(), f'<span class="{status_dot}" style="display:inline-block;width:6px;height:6px;border-radius:50%;margin-right:4px;"></span>{status_txt}', "med", "🌐")
        + '</div>',
        unsafe_allow_html=True,
    )

    st.markdown('<div class="section-hdr">// REAL-TIME STREAMS</div>', unsafe_allow_html=True)
    left, right = st.columns([3, 2])

    with left:
        st.markdown('<div class="section-hdr" style="font-size:11px;">📡 ALERT STREAM</div>', unsafe_allow_html=True)
        stream = df.sort_values("ts", ascending=False).head(15).copy()
        stream["sev"]  = stream["severity"].map(sev_badge)
        stream["time"] = pd.to_datetime(stream["ts"]).dt.strftime("%H:%M:%S")
        cols_s = ["time", "sev", "score", "src_ip", "asset", "mitre", "description"]
        st.markdown(alert_table_html(stream, cols_s), unsafe_allow_html=True)

    with right:
        st.markdown('<div class="section-hdr" style="font-size:11px;">🎚 SEVERITY DIST.</div>', unsafe_allow_html=True)
        sev_counts = df["severity"].value_counts().reindex(SEVERITIES, fill_value=0)
        fig = go.Figure(go.Bar(
            x=sev_counts.values, y=sev_counts.index, orientation="h",
            marker_color=[SEV_COLORS[s] for s in sev_counts.index],
            text=sev_counts.values, textposition="outside",
            marker=dict(line=dict(width=0)),
        ))
        fig.update_layout(
            template="plotly_dark", height=290,
            margin=dict(l=0, r=30, t=10, b=10),
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            font=dict(family="Share Tech Mono"),
            xaxis=dict(gridcolor="rgba(255,255,255,.05)"),
            yaxis=dict(gridcolor="rgba(0,0,0,0)"),
        )
        st.plotly_chart(fig, use_container_width=True)

    st.markdown('<div class="section-hdr">// THREAT LANDSCAPE</div>', unsafe_allow_html=True)
    c1, c2 = st.columns(2)

    with c1:
        st.markdown('<div class="section-hdr" style="font-size:11px;">🎯 TOP ATTACKED ASSETS</div>', unsafe_allow_html=True)
        top = df.groupby("asset")["count"].sum().sort_values(ascending=True).tail(8)
        fig = go.Figure(go.Bar(
            x=top.values, y=top.index, orientation="h",
            marker=dict(
                color=top.values,
                colorscale=[[0, "#0d3a5c"], [1, "#00aaff"]],
                line=dict(width=0),
            ),
        ))
        fig.update_layout(
            template="plotly_dark", height=320,
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            font=dict(family="Share Tech Mono"),
            margin=dict(l=0, r=10, t=10, b=10),
            xaxis=dict(gridcolor="rgba(255,255,255,.05)"),
        )
        st.plotly_chart(fig, use_container_width=True)

    with c2:
        st.markdown('<div class="section-hdr" style="font-size:11px;">⏱ EVENT TIMELINE</div>', unsafe_allow_html=True)
        tl = df.copy()
        tl["ts"]     = pd.to_datetime(tl["ts"])
        tl["bucket"] = tl["ts"].dt.floor("5min")
        agg = tl.groupby(["bucket", "severity"]).size().reset_index(name="n")
        fig = px.area(agg, x="bucket", y="n", color="severity",
                      color_discrete_map=SEV_COLORS)
        fig.update_layout(
            template="plotly_dark", height=320,
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            font=dict(family="Share Tech Mono"),
            margin=dict(l=0, r=10, t=10, b=10),
            xaxis=dict(gridcolor="rgba(255,255,255,.05)"),
            yaxis=dict(gridcolor="rgba(255,255,255,.05)"),
        )
        st.plotly_chart(fig, use_container_width=True)


# ===========================================================================
# 2. ALERT TRIAGE
# ===========================================================================
elif page == "🚨 Alert Triage":
    st.markdown('<div class="section-hdr">// TRIAGE PANEL · INGESTION + SCORING + DEDUP</div>', unsafe_allow_html=True)

    df = get_alert_data(120)

    f1, f2, f3, f4 = st.columns(4)
    sev_f   = f1.selectbox("Severity", ["all"] + SEVERITIES)
    asset_f = f2.selectbox("Asset",    ["all"] + sorted(df["asset"].unique().tolist()))
    mitre_f = f3.selectbox("MITRE",    ["all"] + sorted(df["mitre"].unique().tolist()))
    dedup   = f4.toggle("Dedup view", value=True)

    view = df.copy()
    if sev_f   != "all": view = view[view.severity == sev_f]
    if asset_f != "all": view = view[view.asset == asset_f]
    if mitre_f != "all": view = view[view.mitre == mitre_f]

    if dedup:
        view = (view.groupby(["src_ip", "rule_id"], as_index=False)
                    .agg(ts=("ts", "max"), severity=("severity", "first"),
                         score=("score", "max"), asset=("asset", "first"),
                         mitre=("mitre", "first"), description=("description", "first"),
                         dedup=("id", "count")))

    view = view.sort_values("ts", ascending=False).head(60).copy()
    view["sev"]  = view["severity"].map(sev_badge)
    view["time"] = pd.to_datetime(view["ts"]).dt.strftime("%H:%M:%S")

    cols = ["time", "sev", "score", "src_ip", "asset", "rule_id", "mitre", "description"]
    if dedup: cols.append("dedup")

    st.markdown(
        f'<div class="glass-panel" style="padding:10px 16px;margin-bottom:12px;">'
        f'<span style="font-family:\'Share Tech Mono\',monospace;font-size:11px;color:#00aaff;">QUEUE</span>'
        f'<span style="font-family:\'Share Tech Mono\',monospace;font-size:20px;color:#e6f1ff;margin-left:12px;font-weight:700;">{len(view)}</span>'
        f'<span style="font-family:\'Share Tech Mono\',monospace;font-size:11px;color:#4a7fa5;margin-left:6px;">alertes</span>'
        f'</div>',
        unsafe_allow_html=True,
    )
    st.markdown(alert_table_html(view, cols), unsafe_allow_html=True)

    st.markdown('<div class="section-hdr" style="margin-top:20px;">// PROMOTE TO INCIDENT</div>', unsafe_allow_html=True)
    col_a, col_b = st.columns([3, 1])
    sel = col_a.text_input("ID / IP à promouvoir", label_visibility="collapsed", placeholder="ID / IP à promouvoir en incident")
    if col_b.button("⬆ PROMOTE"):
        st.markdown(
            f'<div class="live-alert">✓ Alerte {sel or "(sélection)"} promue → INC-{random.randint(1000,9999)}</div>',
            unsafe_allow_html=True,
        )


# ===========================================================================
# 3. MITRE ATT&CK
# ===========================================================================
elif page == "🎯 MITRE ATT&CK":
    st.markdown('<div class="section-hdr">// MITRE ATT&CK COVERAGE HEATMAP</div>', unsafe_allow_html=True)

    df = get_alert_data(150)
    counts = df.groupby(["mitre", "mitre_name"]).size().reset_index(name="hits")
    counts = counts.sort_values("hits", ascending=False)

    fig = px.treemap(counts, path=["mitre_name"], values="hits",
                     color="hits", color_continuous_scale=[[0,"#0d3a5c"],[.5,"#0077cc"],[1,"#ef4444"]])
    fig.update_layout(
        template="plotly_dark", height=480,
        paper_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=0, r=0, t=10, b=0),
        font=dict(family="Share Tech Mono"),
    )
    fig.update_traces(textfont=dict(family="Share Tech Mono", size=14))
    st.plotly_chart(fig, use_container_width=True)

    st.markdown('<div class="section-hdr">// TECHNIQUE BREAKDOWN</div>', unsafe_allow_html=True)
    counts["badge"] = counts["hits"].apply(
        lambda n: sev_badge("critical" if n > 25 else "high" if n > 15 else "medium" if n > 8 else "low")
    )
    rows = ""
    for _, r in counts.iterrows():
        rows += (f"<tr><td>{r['mitre']}</td><td>{r['mitre_name']}</td>"
                 f"<td class='score-cell'>{r['hits']}</td><td>{r['badge']}</td></tr>")
    st.markdown(
        f'<div class="glass-panel" style="padding:0;overflow-x:auto;">'
        f'<table class="alert-table"><thead><tr>'
        f'<th>TECHNIQUE</th><th>NAME</th><th>HITS</th><th>LEVEL</th>'
        f'</tr></thead><tbody>{rows}</tbody></table></div>',
        unsafe_allow_html=True,
    )


# ===========================================================================
# 4. INCIDENTS
# ===========================================================================
elif page == "📋 Incidents":
    st.markdown('<div class="section-hdr">// INCIDENT MANAGEMENT · KANBAN</div>', unsafe_allow_html=True)

    incidents = [
        {"id": "INC-2026-0142", "title": "SSH brute-force coordonné · edge nodes",
         "status": "Open", "severity": "critical", "assignee": "M. Hartmann", "alerts": 47},
        {"id": "INC-2026-0141", "title": "PowerShell suspect sur win-dc-01",
         "status": "Open", "severity": "high", "assignee": "—", "alerts": 12},
        {"id": "INC-2026-0140", "title": "Beacon C2 sortant depuis k8s-edge-3",
         "status": "In Progress", "severity": "critical", "assignee": "L. Okafor", "alerts": 89},
        {"id": "INC-2026-0139", "title": "Egress data anormal sur db-master",
         "status": "In Progress", "severity": "high", "assignee": "S. Iyer", "alerts": 23},
        {"id": "INC-2026-0138", "title": "Phishing payload via mail-relay",
         "status": "Resolved", "severity": "medium", "assignee": "M. Hartmann", "alerts": 6},
    ]

    latest = get_api_data("/alerts/latest", timeout=10)
    if latest and latest.get("rule_id"):
        real_sev = wazuh_level_to_severity(latest.get("rule_level"))
        incidents.insert(0, {
            "id": "INC-LIVE",
            "title": f"[LIVE] {latest.get('description','SSH alert')} · {latest.get('srcip','—')}",
            "status": "Open", "severity": real_sev, "assignee": "—", "alerts": 1,
        })

    KANBAN = [("Open","open","◎ OPEN"), ("In Progress","progress","◉ IN PROGRESS"), ("Resolved","resolved","✓ RESOLVED")]
    cols = st.columns(3)
    for col, (status, css, label) in zip(cols, KANBAN):
        with col:
            cards_html = f'<div class="kanban-col {css}"><div class="kanban-hdr {css}">{label}</div>'
            for inc in [x for x in incidents if x["status"] == status]:
                cards_html += (
                    f'<div class="inc-card">'
                    f'<div class="inc-id">{inc["id"]}</div>'
                    f'<div class="inc-title">{inc["title"]}</div>'
                    f'{sev_badge(inc["severity"])}'
                    f'<div class="inc-meta">👤 {inc["assignee"]} &nbsp;·&nbsp; 🔔 {inc["alerts"]} alertes</div>'
                    f'</div>'
                )
            cards_html += '</div>'
            st.markdown(cards_html, unsafe_allow_html=True)


# ===========================================================================
# 5. INCIDENT HISTORY
# ===========================================================================
elif page == "📚 Incident History":
    render_incident_history(sev_badge, kpi_card)


# ===========================================================================
# 6. THREAT INTELLIGENCE
# ===========================================================================
elif page == "🔍 Threat Intelligence":
    render_threat_intelligence(sev_badge, kpi_card)


# ===========================================================================
# 7. ANALYTICS
# ===========================================================================
elif page == "📈 Analytics":
    st.markdown('<div class="section-hdr">// SOC KPIs · 14-DAY TREND</div>', unsafe_allow_html=True)

    days = pd.date_range(end=datetime.utcnow(), periods=14)
    rng  = random.Random(7)
    kpi  = pd.DataFrame({
        "day":       days,
        "MTTD (min)": [rng.randint(3, 12)  for _ in days],
        "MTTR (min)": [rng.randint(15, 45) for _ in days],
        "Alerts":     [rng.randint(120, 380) for _ in days],
    })

    c1, c2 = st.columns(2)
    with c1:
        fig = px.line(kpi, x="day", y=["MTTD (min)", "MTTR (min)"], markers=True,
                      color_discrete_sequence=["#00aaff", "#f97316"])
        fig.update_layout(
            template="plotly_dark", height=320,
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            font=dict(family="Share Tech Mono"),
            xaxis=dict(gridcolor="rgba(255,255,255,.05)"),
            yaxis=dict(gridcolor="rgba(255,255,255,.05)"),
            margin=dict(l=0,r=10,t=10,b=0),
        )
        st.plotly_chart(fig, use_container_width=True)
    with c2:
        fig = px.bar(kpi, x="day", y="Alerts", color="Alerts",
                     color_continuous_scale=[[0,"#0d3a5c"],[1,"#00aaff"]])
        fig.update_layout(
            template="plotly_dark", height=320,
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            font=dict(family="Share Tech Mono"),
            xaxis=dict(gridcolor="rgba(255,255,255,.05)"),
            yaxis=dict(gridcolor="rgba(255,255,255,.05)"),
            margin=dict(l=0,r=10,t=10,b=0),
        )
        st.plotly_chart(fig, use_container_width=True)

    st.markdown('<div class="section-hdr">// RISK HEATMAP · ASSET × TECHNIQUE</div>', unsafe_allow_html=True)
    df = get_alert_data(200)
    pivot = df.pivot_table(index="asset", columns="mitre", values="score",
                           aggfunc="max", fill_value=0)
    fig = px.imshow(pivot, color_continuous_scale=[[0,"#050810"],[.4,"#0d3a5c"],[1,"#ef4444"]], aspect="auto")
    fig.update_layout(
        template="plotly_dark", height=380,
        paper_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Share Tech Mono"),
        margin=dict(l=0,r=0,t=10,b=0),
    )
    st.plotly_chart(fig, use_container_width=True)


# ===========================================================================
# LLM AGENT PAGES
# ===========================================================================
elif page == "Dernière alerte":
    st.markdown('<div class="section-hdr">// DERNIÈRE ALERTE WAZUH (TOUS TYPES)</div>', unsafe_allow_html=True)
    min_lvl = st.slider("Niveau minimum Wazuh", min_value=1, max_value=15, value=5)
    data = get_api_data(f"/alerts/latest?min_level={min_lvl}", timeout=60)
    if data and data.get("rule_id"):
        sev = wazuh_level_to_severity(data.get("rule_level"))
        groups_str = ", ".join(data.get("groups") or []) or "—"
        st.markdown(
            f'<div class="glass-panel">'
            f'Severity : {sev_badge(sev)} &nbsp;·&nbsp; '
            f'Groupes : <span style="font-family:monospace;color:#60a5fa;">{groups_str}</span>'
            f'</div>',
            unsafe_allow_html=True,
        )
        alert_df = pd.DataFrame([{
            "Rule ID":     data.get("rule_id"),
            "Level":       data.get("rule_level"),
            "Groupes":     groups_str,
            "Description": data.get("description"),
            "Agent ID":    data.get("agent_id"),
            "Agent":       data.get("agent_name"),
            "Victim IP":   data.get("agent_ip"),
            "Source IP":   data.get("srcip"),
            "Target User": data.get("target_user"),
            "Timestamp":   data.get("timestamp"),
        }])
        st.dataframe(alert_df, use_container_width=True)
        with st.expander("Raw JSON"):
            st.json(data)
    else:
        st.markdown('<div class="info-alert">Aucune alerte trouvée pour ce niveau.</div>', unsafe_allow_html=True)


elif page == "Analyse Agent 1":
    st.markdown('<div class="section-hdr">// AGENT 1 · ALERT ANALYZER (TOUS TYPES)</div>', unsafe_allow_html=True)
    with st.spinner("Analyse LLM en cours..."):
        data = get_api_data("/analyze/latest", timeout=900)
    if data:
        alert = data.get("alert", {})
        groups_str = ", ".join(alert.get("groups") or []) or "—"
        st.markdown(
            f'<div class="glass-panel" style="font-family:monospace;font-size:11px;color:#64748b;">'
            f'Rule {alert.get("rule_id")} · Groupes : {groups_str} · {alert.get("description","")}'
            f'</div>',
            unsafe_allow_html=True,
        )
        with st.expander("Alerte Wazuh", expanded=False):
            st.json(alert)
        st.markdown('<div class="section-hdr">// ANALYSE SOC</div>', unsafe_allow_html=True)
        st.markdown(f'<div class="glass-panel">{data.get("llm_analysis","Aucune analyse générée.")}</div>',
                    unsafe_allow_html=True)


elif page == "Analyse RAG Agent 2":
    st.markdown('<div class="section-hdr">// AGENT 2 · RAG THREAT INTELLIGENCE (TOUS TYPES)</div>', unsafe_allow_html=True)
    with st.spinner("Enrichissement RAG en cours..."):
        data = get_api_data("/rag/latest", timeout=900)
    if data:
        alert = data.get("alert", {})
        groups_str = ", ".join(alert.get("groups") or []) or "—"
        st.markdown(
            f'<div class="glass-panel" style="font-family:monospace;font-size:11px;color:#64748b;">'
            f'Rule {alert.get("rule_id")} · Groupes : {groups_str} · {alert.get("description","")}'
            f'</div>',
            unsafe_allow_html=True,
        )
        with st.expander("Alerte Wazuh", expanded=False):
            st.json(alert)
        st.markdown('<div class="section-hdr">// ANALYSE AGENT 1</div>', unsafe_allow_html=True)
        st.markdown(f'<div class="glass-panel">{data.get("agent_1_analysis","—")}</div>', unsafe_allow_html=True)
        st.markdown('<div class="section-hdr">// ENRICHISSEMENT RAG AGENT 2</div>', unsafe_allow_html=True)
        st.markdown(f'<div class="glass-panel">{data.get("agent_2_rag_enrichment","—")}</div>', unsafe_allow_html=True)


elif page == "Rapport SOC Final":
    st.markdown('<div class="section-hdr">// AGENT 3 · RAPPORT SOC FINAL (TOUS TYPES)</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="info-alert">Clique sur GENERATE pour lancer la génération complète (2-8 min).</div>',
        unsafe_allow_html=True,
    )
    if "final_report_data" not in st.session_state:
        st.session_state.final_report_data = None

    if st.button("⬡ GENERATE REPORT"):
        with st.spinner("Génération du rapport SOC final..."):
            st.session_state.final_report_data = get_api_data("/report/latest", timeout=1200)

    data = st.session_state.final_report_data
    if data:
        alert = data.get("alert", {})
        st.markdown(
            '<div class="kpi-grid" style="grid-template-columns:repeat(4,1fr);">'
            + kpi_card("Rule ID",   alert.get("rule_id",    "—"), "", "crit",  "🆔")
            + kpi_card("Level",     alert.get("rule_level", "—"), "", "high",  "⚡")
            + kpi_card("Source IP", alert.get("srcip",      "—"), "", "info",  "🌐")
            + kpi_card("User",      alert.get("target_user","—"), "", "green", "👤")
            + '</div>',
            unsafe_allow_html=True,
        )
        final_report = data.get("final_soc_report", "Aucun rapport généré.")
        st.markdown('<div class="section-hdr">// RAPPORT FINAL</div>', unsafe_allow_html=True)
        if final_report.startswith("[ERROR]"):
            st.markdown(f'<div class="live-alert">{final_report}</div>', unsafe_allow_html=True)
        else:
            st.markdown(f'<div class="glass-panel">{final_report}</div>', unsafe_allow_html=True)
        with st.expander("Analyse Agent 1"):
            st.markdown(data.get("agent_1_analysis", ""))
        with st.expander("Enrichissement Agent 2 RAG"):
            st.markdown(data.get("agent_2_rag_enrichment", ""))
        with st.expander("Alerte brute Wazuh"):
            st.json(alert)
