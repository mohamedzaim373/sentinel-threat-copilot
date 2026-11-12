import sys
import asyncio
from pathlib import Path
from functools import partial
from fastapi import FastAPI
from fastapi.responses import JSONResponse

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

from backend.fetch_alerts import (
    load_recent_alerts, load_recent_ssh_alerts, load_latest_alert,
    load_recent_web_alerts, load_latest_web_alert,
)
from agents.alert_analyzer_agent import analyze_alert
from agents.rag_threat_agent import enrich_with_rag
from agents.report_agent import generate_soc_report

app = FastAPI(
    title="SOC-AI Wazuh Alert API",
    description="API for Wazuh alerts analysis using LLM + RAG",
    version="2.0",
)


def _run_sync(fn, *args, **kwargs):
    """Run a blocking function in the default thread-pool executor."""
    loop = asyncio.get_event_loop()
    return loop.run_in_executor(None, partial(fn, *args, **kwargs))


@app.get("/")
async def home():
    return {
        "message": "SOC-AI Wazuh Alert API is running",
        "version": "2.1",
        "endpoints": {
            "generic": [
                "/alerts",
                "/alerts/latest",
                "/analyze/latest",
                "/rag/latest",
                "/report/latest",
            ],
            "ssh_legacy": [
                "/alerts/ssh",
                "/alerts/ssh/latest",
                "/analyze/ssh/latest",
                "/rag/ssh/latest",
                "/report/ssh/latest",
            ],
            "web_threats": [
                "/alerts/web",
                "/alerts/web/latest",
                "/analyze/web/latest",
                "/rag/web/latest",
                "/report/web/latest",
            ],
        },
    }


# ===========================================================================
# GENERIC ENDPOINTS — tous types de logs
# ===========================================================================

@app.get("/alerts")
async def get_all_alerts(
    limit: int = 20,
    min_level: int = 5,
    agent_id: str = None,
    rule_id: str = None,
):
    alerts = await _run_sync(
        load_recent_alerts,
        limit=limit,
        min_level=min_level,
        agent_id=agent_id,
        rule_id=rule_id,
    )
    return {"count": len(alerts), "alerts": alerts}


@app.get("/alerts/latest")
async def get_latest_alert(min_level: int = 5, agent_id: str = None):
    alert = await _run_sync(load_latest_alert, min_level=min_level, agent_id=agent_id)
    if not alert:
        return {"message": "Aucune alerte trouvée"}
    return alert


@app.get("/analyze/latest")
async def analyze_latest_alert(min_level: int = 5):
    alert = await _run_sync(load_latest_alert, min_level=min_level)
    if not alert:
        return {"message": "Aucune alerte trouvée"}
    analysis = await _run_sync(analyze_alert, alert)
    return {"alert": alert, "llm_analysis": analysis}


@app.get("/rag/latest")
async def rag_enrich_latest_alert(min_level: int = 5):
    alert = await _run_sync(load_latest_alert, min_level=min_level)
    if not alert:
        return {"message": "Aucune alerte trouvée"}
    agent1_analysis = await _run_sync(analyze_alert, alert)
    rag_analysis    = await _run_sync(enrich_with_rag, alert, agent1_analysis)
    return {
        "alert":                   alert,
        "agent_1_analysis":        agent1_analysis,
        "agent_2_rag_enrichment":  rag_analysis,
    }


@app.get("/report/latest")
async def generate_latest_report(min_level: int = 5):
    alert = await _run_sync(load_latest_alert, min_level=min_level)
    if not alert:
        return {"message": "Aucune alerte trouvée"}
    agent_1_analysis   = await _run_sync(analyze_alert,       alert)
    agent_2_enrichment = await _run_sync(enrich_with_rag,     alert, agent_1_analysis)
    final_report       = await _run_sync(generate_soc_report, alert, agent_1_analysis, agent_2_enrichment)
    return {
        "alert":                   alert,
        "agent_1_analysis":        agent_1_analysis,
        "agent_2_rag_enrichment":  agent_2_enrichment,
        "final_soc_report":        final_report,
    }


# ===========================================================================
# WEB THREAT ENDPOINTS — sites malveillants, DNS, firewall, Sysmon
# ===========================================================================

@app.get("/alerts/web")
async def get_web_alerts(
    limit: int = 20,
    min_level: int = 3,
    agent_id: str = None,
):
    alerts = await _run_sync(
        load_recent_web_alerts,
        limit=limit,
        agent_id=agent_id,
        min_level=min_level,
    )
    return {"count": len(alerts), "alerts": alerts}


@app.get("/alerts/web/latest")
async def get_latest_web_alert(min_level: int = 3, agent_id: str = None):
    alert = await _run_sync(load_latest_web_alert, agent_id=agent_id, min_level=min_level)
    if not alert:
        return {"message": "Aucune alerte web/réseau trouvée"}
    return alert


@app.get("/analyze/web/latest")
async def analyze_latest_web_alert(min_level: int = 3):
    alert = await _run_sync(load_latest_web_alert, min_level=min_level)
    if not alert:
        return {"message": "Aucune alerte web/réseau trouvée"}
    analysis = await _run_sync(analyze_alert, alert)
    return {"alert": alert, "llm_analysis": analysis}


@app.get("/rag/web/latest")
async def rag_enrich_latest_web_alert(min_level: int = 3):
    alert = await _run_sync(load_latest_web_alert, min_level=min_level)
    if not alert:
        return {"message": "Aucune alerte web/réseau trouvée"}
    agent1_analysis = await _run_sync(analyze_alert, alert)
    rag_analysis    = await _run_sync(enrich_with_rag, alert, agent1_analysis)
    return {
        "alert":                  alert,
        "agent_1_analysis":       agent1_analysis,
        "agent_2_rag_enrichment": rag_analysis,
    }


@app.get("/report/web/latest")
async def generate_latest_web_report(min_level: int = 3):
    alert = await _run_sync(load_latest_web_alert, min_level=min_level)
    if not alert:
        return {"message": "Aucune alerte web/réseau trouvée"}
    agent_1_analysis   = await _run_sync(analyze_alert,       alert)
    agent_2_enrichment = await _run_sync(enrich_with_rag,     alert, agent_1_analysis)
    final_report       = await _run_sync(generate_soc_report, alert, agent_1_analysis, agent_2_enrichment)
    return {
        "alert":                  alert,
        "agent_1_analysis":       agent_1_analysis,
        "agent_2_rag_enrichment": agent_2_enrichment,
        "final_soc_report":       final_report,
    }


@app.get("/alerts/ssh")
async def get_ssh_alerts(
    limit: int = 20,
    min_level: int = 5,
    agent_id: str = None,
    rule_id: str = None,
):
    alerts = await _run_sync(
        load_recent_alerts,
        limit=limit,
        min_level=min_level,
        agent_id=agent_id,
        rule_id=rule_id,
    )
    return {"count": len(alerts), "alerts": alerts}


@app.get("/alerts/ssh/latest")
async def get_latest_ssh_alert(
    min_level: int = 5,
    agent_id: str = None,
    rule_id: str = None,
):
    alerts = await _run_sync(
        load_recent_alerts,
        limit=1,
        min_level=min_level,
        agent_id=agent_id,
        rule_id=rule_id,
    )
    if not alerts:
        return {"message": "No alert found"}
    return alerts[0]


@app.get("/analyze/ssh/latest")
async def analyze_latest_ssh_alert():
    alerts = await _run_sync(load_recent_ssh_alerts, limit=1)
    if not alerts:
        return {"message": "No SSH brute force related alert found"}

    latest_alert = alerts[0]
    analysis = await _run_sync(analyze_alert, latest_alert)
    return {"alert": latest_alert, "llm_analysis": analysis}


@app.get("/rag/ssh/latest")
async def rag_enrich_latest_ssh_alert():
    alerts = await _run_sync(load_recent_ssh_alerts, limit=1)
    if not alerts:
        return {"message": "No SSH brute force related alert found"}

    latest_alert = alerts[0]

    # Agent 1 and OpenSearch already cached — run sequentially (Agent 2 needs Agent 1 output)
    agent1_analysis = await _run_sync(analyze_alert, latest_alert)
    rag_analysis    = await _run_sync(enrich_with_rag, latest_alert, agent1_analysis)

    return {
        "alert":               latest_alert,
        "agent_1_analysis":    agent1_analysis,
        "agent_2_rag_enrichment": rag_analysis,
    }


@app.get("/report/ssh/latest")
async def generate_latest_ssh_report():
    alerts = await _run_sync(load_recent_ssh_alerts, limit=1)
    if not alerts:
        return {"message": "No SSH brute force related alert found"}

    latest_alert = alerts[0]

    # Sequential chain: each agent needs the previous output
    agent_1_analysis  = await _run_sync(analyze_alert,    latest_alert)
    agent_2_enrichment = await _run_sync(enrich_with_rag, latest_alert, agent_1_analysis)
    final_report       = await _run_sync(generate_soc_report,
                                         latest_alert, agent_1_analysis, agent_2_enrichment)

    return {
        "alert":                  latest_alert,
        "agent_1_analysis":       agent_1_analysis,
        "agent_2_rag_enrichment": agent_2_enrichment,
        "final_soc_report":       final_report,
    }
