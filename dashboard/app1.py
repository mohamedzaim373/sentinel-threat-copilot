import random
from datetime import datetime, timedelta

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import requests
import streamlit as st

API_URL = "http://localhost:8000"

st.set_page_config(
    page_title="SOC-AI Wazuh RAG · SENTINEL",
    page_icon="🛡️",
    layout="wide",
)

# ---------------------------------------------------------------------------
# THEME (cyber-ops dark)
# ---------------------------------------------------------------------------
st.markdown(
    """
    <style>
      .stApp { background-color: #0a0e14; color: #d6deeb; }
      section[data-testid="stSidebar"] { background-color: #0d1218; }
      h1, h2, h3, h4 { color: #e6f1ff; font-family: 'Courier New', monospace; }
      .sev-critical { background:#7f1d1d; color:#fecaca; padding:2px 8px; border-radius:4px; font-family:monospace; font-size:11px; }
      .sev-high     { background:#9a3412; color:#fed7aa; padding:2px 8px; border-radius:4px; font-family:monospace; font-size:11px; }
      .sev-medium   { background:#854d0e; color:#fde68a; padding:2px 8px; border-radius:4px; font-family:monospace; font-size:11px; }
      .sev-low      { background:#1e40af; color:#bfdbfe; padding:2px 8px; border-radius:4px; font-family:monospace; font-size:11px; }
      .sev-info     { background:#374151; color:#d1d5db; padding:2px 8px; border-radius:4px; font-family:monospace; font-size:11px; }
      .panel { background:#0f141b; border:1px solid #1f2937; border-radius:8px; padding:14px; }
      .pulse { display:inline-block; width:8px; height:8px; background:#22c55e; border-radius:50%; margin-right:6px;
               animation: pulse 1.4s infinite; }
      @keyframes pulse { 0%{opacity:1;} 50%{opacity:.3;} 100%{opacity:1;} }
    </style>
    """,
    unsafe_allow_html=True,
)

st.title("🛡️ SOC-AI Wazuh RAG · SENTINEL")
st.caption("Plateforme SOAR-lite · Wazuh + LLM Agents + RAG")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEV_COLORS = {
    "critical": "#ef4444",
    "high": "#f97316",
    "medium": "#eab308",
    "low": "#3b82f6",
    "info": "#6b7280",
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


def get_api_data(endpoint: str, timeout: int = 900):
    try:
        r = requests.get(f"{API_URL}{endpoint}", timeout=timeout)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        st.error(f"Erreur API : {e}")
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


@st.cache_data(ttl=30)
def mock_alert_stream(n: int = 60, seed: int = 42) -> pd.DataFrame:
    """Fallback simulé quand l'API ne renvoie pas d'historique."""
    rng = random.Random(seed)
    now = datetime.utcnow()
    rows = []
    for i in range(n):
        sev = rng.choices(SEVERITIES, weights=[1, 2, 3, 4, 2])[0]
        m = rng.choice(MITRE)
        score = {"critical": 90, "high": 70, "medium": 50,
                 "low": 30, "info": 10}[sev] + rng.randint(-5, 9)
        rows.append({
            "id": f"ALT-{10000 + i}",
            "ts": now - timedelta(seconds=i * rng.randint(20, 600)),
            "src_ip": f"{rng.randint(10, 240)}.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(0,255)}",
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


# ---------------------------------------------------------------------------
# Sidebar navigation
# ---------------------------------------------------------------------------
with st.sidebar:
    st.header("⚡ Navigation")
    page = st.radio(
        "Section",
        [
            "🧠 SOC Overview",
            "🚨 Alert Triage",
            "🎯 MITRE ATT&CK",
            "📋 Incidents",
            "📈 Analytics",
            "Dernière alerte SSH",
            "Analyse Agent 1",
            "Analyse RAG Agent 2",
            "Rapport SOC Final",
        ],
    )
    st.divider()
    if st.button("🔄 Rafraîchir"):
        st.cache_data.clear()
        st.session_state.clear()
        st.rerun()

    st.markdown("---")
    st.markdown('<span class="pulse"></span> **Sentinel agent online**', unsafe_allow_html=True)
    st.caption(f"UTC · {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}")


# ===========================================================================
# 1. SOC OVERVIEW
# ===========================================================================
if page == "🧠 SOC Overview":
    st.subheader("Core Dashboard · Situational Awareness")

    df = mock_alert_stream(80)
    # tente d'enrichir avec la dernière alerte réelle Wazuh
    latest = get_api_data("/alerts/ssh/latest", timeout=10)
    if latest:
        real_sev = wazuh_level_to_severity(latest.get("rule_level"))
        st.success(f"Alerte Wazuh live : rule {latest.get('rule_id')} · {real_sev.upper()} · {latest.get('srcip')}")

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Alertes (1h)", len(df), f"+{len(df[df.severity=='critical'])} crit")
    c2.metric("Incidents actifs", 7, "+2")
    c3.metric("MTTD", "4m 12s", "-18%")
    c4.metric("MTTR", "23m", "-9%")
    c5.metric("Sources uniques", df["src_ip"].nunique())

    st.markdown("---")

    left, right = st.columns([2, 1])

    with left:
        st.markdown("#### 📡 Real-time Alert Stream")
        stream = df.sort_values("ts", ascending=False).head(15).copy()
        stream["sev"] = stream["severity"].map(lambda s: sev_badge(s))
        stream["ts"] = stream["ts"].dt.strftime("%H:%M:%S")
        st.write(
            stream[["ts", "sev", "score", "src_ip", "asset", "mitre", "description"]]
            .to_html(escape=False, index=False),
            unsafe_allow_html=True,
        )

    with right:
        st.markdown("#### 🎚️ Severity Distribution")
        sev_counts = df["severity"].value_counts().reindex(SEVERITIES, fill_value=0)
        fig = go.Figure(go.Bar(
            x=sev_counts.values, y=sev_counts.index, orientation="h",
            marker_color=[SEV_COLORS[s] for s in sev_counts.index],
            text=sev_counts.values, textposition="outside",
        ))
        fig.update_layout(
            template="plotly_dark", height=280, margin=dict(l=10, r=10, t=10, b=10),
            paper_bgcolor="#0f141b", plot_bgcolor="#0f141b",
        )
        st.plotly_chart(fig, use_container_width=True)

    st.markdown("---")
    c1, c2 = st.columns(2)

    with c1:
        st.markdown("#### 🎯 Top Attacked Assets")
        top = df.groupby("asset")["count"].sum().sort_values(ascending=True).tail(8)
        fig = go.Figure(go.Bar(x=top.values, y=top.index, orientation="h",
                               marker_color="#3b82f6"))
        fig.update_layout(template="plotly_dark", height=320,
                          paper_bgcolor="#0f141b", plot_bgcolor="#0f141b",
                          margin=dict(l=10, r=10, t=10, b=10))
        st.plotly_chart(fig, use_container_width=True)

    with c2:
        st.markdown("#### ⏱️ Timeline of Events (1h)")
        tl = df.copy()
        tl["bucket"] = tl["ts"].dt.floor("5min")
        agg = tl.groupby(["bucket", "severity"]).size().reset_index(name="n")
        fig = px.area(agg, x="bucket", y="n", color="severity",
                      color_discrete_map=SEV_COLORS)
        fig.update_layout(template="plotly_dark", height=320,
                          paper_bgcolor="#0f141b", plot_bgcolor="#0f141b",
                          margin=dict(l=10, r=10, t=10, b=10))
        st.plotly_chart(fig, use_container_width=True)


# ===========================================================================
# 2. ALERT TRIAGE
# ===========================================================================
elif page == "🚨 Alert Triage":
    st.subheader("Sentinel Triage Panel · ingestion + scoring + dedup")

    df = mock_alert_stream(120)

    f1, f2, f3, f4 = st.columns(4)
    sev_f = f1.selectbox("Severity", ["all"] + SEVERITIES)
    asset_f = f2.selectbox("Asset", ["all"] + sorted(df["asset"].unique().tolist()))
    mitre_f = f3.selectbox("MITRE", ["all"] + sorted(df["mitre"].unique().tolist()))
    dedup = f4.toggle("Dedup view", value=True)

    view = df.copy()
    if sev_f != "all":   view = view[view.severity == sev_f]
    if asset_f != "all": view = view[view.asset == asset_f]
    if mitre_f != "all": view = view[view.mitre == mitre_f]

    if dedup:
        view = (view.groupby(["src_ip", "rule_id"], as_index=False)
                    .agg(ts=("ts", "max"), severity=("severity", "first"),
                         score=("score", "max"), asset=("asset", "first"),
                         mitre=("mitre", "first"), description=("description", "first"),
                         dedup=("id", "count")))

    view = view.sort_values("ts", ascending=False).head(60).copy()
    view["sev"] = view["severity"].map(sev_badge)
    view["ts"] = pd.to_datetime(view["ts"]).dt.strftime("%H:%M:%S")

    cols = ["ts", "sev", "score", "src_ip", "asset", "rule_id", "mitre", "description"]
    if dedup: cols.append("dedup")

    st.markdown(f"**Queue · {len(view)} alertes**")
    st.write(view[cols].to_html(escape=False, index=False), unsafe_allow_html=True)

    st.markdown("---")
    sel = st.text_input("ID / IP à promouvoir en incident")
    if st.button("⬆️ Promote to incident"):
        st.success(f"Alerte {sel or '(sélection)'} promue en incident INC-{random.randint(1000,9999)}")


# ===========================================================================
# 3. MITRE ATT&CK
# ===========================================================================
elif page == "🎯 MITRE ATT&CK":
    st.subheader("MITRE ATT&CK Coverage Heatmap")

    df = mock_alert_stream(150)
    counts = df.groupby(["mitre", "mitre_name"]).size().reset_index(name="hits")
    counts = counts.sort_values("hits", ascending=False)

    fig = px.treemap(counts, path=["mitre_name"], values="hits",
                     color="hits", color_continuous_scale="Reds")
    fig.update_layout(template="plotly_dark", height=500,
                      paper_bgcolor="#0a0e14", margin=dict(l=10, r=10, t=10, b=10))
    st.plotly_chart(fig, use_container_width=True)

    st.markdown("#### Détail des techniques détectées")
    counts["badge"] = counts["hits"].apply(
        lambda n: sev_badge("critical" if n > 25 else "high" if n > 15 else "medium" if n > 8 else "low")
    )
    st.write(counts[["mitre", "mitre_name", "hits", "badge"]]
             .to_html(escape=False, index=False), unsafe_allow_html=True)


# ===========================================================================
# 4. INCIDENTS
# ===========================================================================
elif page == "📋 Incidents":
    st.subheader("Incident Management")

    incidents = [
        {"id": "INC-2026-0142", "title": "SSH brute-force coordonné · edge nodes",
         "status": "In Progress", "severity": "critical", "assignee": "M. Hartmann", "alerts": 47},
        {"id": "INC-2026-0141", "title": "PowerShell suspect sur win-dc-01",
         "status": "Open", "severity": "high", "assignee": "—", "alerts": 12},
        {"id": "INC-2026-0140", "title": "Beacon C2 sortant depuis k8s-edge-3",
         "status": "In Progress", "severity": "critical", "assignee": "L. Okafor", "alerts": 89},
        {"id": "INC-2026-0139", "title": "Egress data anormal sur db-master",
         "status": "Open", "severity": "high", "assignee": "S. Iyer", "alerts": 23},
        {"id": "INC-2026-0138", "title": "Phishing payload via mail-relay",
         "status": "Resolved", "severity": "medium", "assignee": "M. Hartmann", "alerts": 6},
    ]

    cols = st.columns(3)
    for i, status in enumerate(["Open", "In Progress", "Resolved"]):
        with cols[i]:
            st.markdown(f"### {status}")
            for inc in [x for x in incidents if x["status"] == status]:
                st.markdown(
                    f"""<div class="panel" style="margin-bottom:8px;">
                    <div style="font-family:monospace;font-size:11px;color:#94a3b8;">{inc['id']}</div>
                    <div style="margin:4px 0;"><b>{inc['title']}</b></div>
                    {sev_badge(inc['severity'])}
                    <div style="font-size:11px;color:#94a3b8;margin-top:6px;">
                      👤 {inc['assignee']} · 🔔 {inc['alerts']} alertes
                    </div></div>""",
                    unsafe_allow_html=True,
                )


# ===========================================================================
# 5. ANALYTICS
# ===========================================================================
elif page == "📈 Analytics":
    st.subheader("SOC Analytics · KPIs")

    days = pd.date_range(end=datetime.utcnow(), periods=14)
    rng = random.Random(7)
    kpi = pd.DataFrame({
        "day": days,
        "MTTD (min)": [rng.randint(3, 12) for _ in days],
        "MTTR (min)": [rng.randint(15, 45) for _ in days],
        "Alerts": [rng.randint(120, 380) for _ in days],
    })

    c1, c2 = st.columns(2)
    with c1:
        fig = px.line(kpi, x="day", y=["MTTD (min)", "MTTR (min)"], markers=True)
        fig.update_layout(template="plotly_dark", paper_bgcolor="#0f141b",
                          plot_bgcolor="#0f141b", height=320)
        st.plotly_chart(fig, use_container_width=True)
    with c2:
        fig = px.bar(kpi, x="day", y="Alerts", color="Alerts",
                     color_continuous_scale="Blues")
        fig.update_layout(template="plotly_dark", paper_bgcolor="#0f141b",
                          plot_bgcolor="#0f141b", height=320)
        st.plotly_chart(fig, use_container_width=True)

    st.markdown("#### Risk Heatmap (asset × technique)")
    df = mock_alert_stream(200)
    pivot = df.pivot_table(index="asset", columns="mitre", values="score",
                           aggfunc="max", fill_value=0)
    fig = px.imshow(pivot, color_continuous_scale="Reds", aspect="auto")
    fig.update_layout(template="plotly_dark", paper_bgcolor="#0a0e14", height=400)
    st.plotly_chart(fig, use_container_width=True)


# ===========================================================================
# === Pages d'origine (FastAPI) =============================================
# ===========================================================================
elif page == "Dernière alerte SSH":
    st.subheader("Dernière alerte SSH Wazuh")
    data = get_api_data("/alerts/ssh/latest", timeout=60)
    if data:
        sev = wazuh_level_to_severity(data.get("rule_level"))
        st.markdown(f"Severity calculée : {sev_badge(sev)}", unsafe_allow_html=True)
        alert_df = pd.DataFrame([{
            "Rule ID": data.get("rule_id"),
            "Level": data.get("rule_level"),
            "Description": data.get("description"),
            "Agent ID": data.get("agent_id"),
            "Agent": data.get("agent_name"),
            "Victim IP": data.get("agent_ip"),
            "Source IP": data.get("srcip"),
            "Target User": data.get("target_user"),
            "Timestamp": data.get("timestamp"),
        }])
        st.dataframe(alert_df, use_container_width=True)
        with st.expander("Voir l'alerte brute JSON"):
            st.json(data)


elif page == "Analyse Agent 1":
    st.subheader("Agent 1 — Alert Analyzer")
    with st.spinner("Analyse de l'alerte par Agent 1..."):
        data = get_api_data("/analyze/ssh/latest", timeout=900)
    if data:
        st.markdown("### Alerte Wazuh")
        st.json(data.get("alert"))
        st.markdown("### Analyse SOC")
        st.markdown(data.get("llm_analysis", "Aucune analyse générée."))


elif page == "Analyse RAG Agent 2":
    st.subheader("Agent 2 — RAG Threat Intelligence")
    with st.spinner("Analyse RAG en cours... Cela peut prendre du temps."):
        data = get_api_data("/rag/ssh/latest", timeout=900)
    if data:
        st.markdown("### Alerte Wazuh")
        st.json(data.get("alert"))
        st.markdown("### Analyse Agent 1")
        st.markdown(data.get("agent_1_analysis", "Aucune analyse Agent 1."))
        st.markdown("### Enrichissement RAG Agent 2")
        st.markdown(data.get("agent_2_rag_enrichment", "Aucun enrichissement RAG."))


elif page == "Rapport SOC Final":
    st.subheader("Agent 3 — Rapport SOC Final")
    st.info(
        "Clique sur le bouton ci-dessous pour générer le rapport final. "
        "La génération peut prendre 2 à 8 minutes avec Ollama dans une VM."
    )
    if "final_report_data" not in st.session_state:
        st.session_state.final_report_data = None
    if st.button("Générer le rapport SOC final"):
        with st.spinner("Génération du rapport SOC final en cours..."):
            st.session_state.final_report_data = get_api_data("/report/ssh/latest", timeout=1200)

    data = st.session_state.final_report_data
    if data:
        alert = data.get("alert", {})
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Rule ID", alert.get("rule_id", "-"))
        c2.metric("Level", alert.get("rule_level", "-"))
        c3.metric("Source IP", alert.get("srcip", "-"))
        c4.metric("User", alert.get("target_user", "-"))
        st.divider()
        final_report = data.get("final_soc_report", "Aucun rapport généré.")
        if final_report.startswith("[ERROR]"):
            st.error(final_report)
        else:
            st.markdown("## Rapport final")
            st.markdown(final_report)
        with st.expander("Voir analyse Agent 1"):
            st.markdown(data.get("agent_1_analysis", ""))
        with st.expander("Voir enrichissement Agent 2 RAG"):
            st.markdown(data.get("agent_2_rag_enrichment", ""))
        with st.expander("Voir alerte brute Wazuh"):
            st.json(alert)
