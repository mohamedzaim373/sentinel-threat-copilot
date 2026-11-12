# Sentinel Threat Copilot

An AI-assisted SOC analyst for [Wazuh](https://wazuh.com/). It pulls live alerts from the
Wazuh indexer, runs them through a three-agent LLM pipeline that enriches each alert with
RAG playbooks, MITRE ATT&CK mapping and live threat-intelligence lookups, and produces a
ready-to-read incident report — surfaced in a dark-themed SENTINEL dashboard.

> Defensive security project. The agents are prompted to stay strictly within a blue-team
> context and produce triage/response guidance, never offensive instructions.

---

## How it works

```
Wazuh agents → Wazuh manager → OpenSearch (wazuh-alerts-4.x-*)
                                      │
                       backend/fetch_alerts.py   (query + normalise + TTL cache)
                                      │
                               FastAPI  (backend/main.py)
                                      │
        ┌─────────────────────────────┼─────────────────────────────┐
        ▼                             ▼                             ▼
  Agent 1 — Triage           Agent 2 — RAG enrichment      Agent 3 — Reporting
 alert_analyzer_agent.py      rag_threat_agent.py            report_agent.py
 severity, victim, attacker   ChromaDB playbooks             final SOC incident
 IOCs, true/false positive    + MITRE ATT&CK mapping         report (10 sections,
 next analyst action          + AbuseIPDB / VirusTotal       MITRE mapping, risk
                              / GreyNoise / ThreatFox        level, actions)
                              / URLhaus
                                      │
                         Streamlit dashboard (dashboard/app.py)
```

All three agents run on **Groq** with `llama-3.3-70b-versatile`. The pipeline is sequential
by necessity — each agent consumes the previous agent's output — while the five
threat-intel providers are queried in parallel via a thread pool.

### The RAG layer

Markdown playbooks in `rag_docs/playbooks/` are chunked and indexed into ChromaDB. Retrieval
deliberately uses a **deterministic hash embedding plus keyword scoring** rather than a
neural embedding model, so the knowledge base needs no model download, no Ollama and no ONNX
runtime — it runs anywhere, offline. Current playbooks cover SSH brute force, web attacks,
privilege escalation, malware/rootkits and netstat port changes.

---

## Project layout

| Path | What it is |
|------|------------|
| `backend/fetch_alerts.py` | OpenSearch queries, alert normalisation, rule-ID catalogue (SSH, web, Sysmon, firewall, IOC rules), 60 s TTL cache |
| `backend/main.py` | FastAPI app — generic, web-threat and SSH endpoint families |
| `agents/alert_analyzer_agent.py` | Agent 1 — level-1 triage analysis |
| `agents/rag_threat_agent.py` | Agent 2 — RAG + MITRE + 5 threat-intel providers |
| `agents/report_agent.py` | Agent 3 — final SOC incident report |
| `rag/ingest_docs.py` | Chunk and index `rag_docs/` into ChromaDB |
| `rag/retriever.py` | Knowledge-base search |
| `dashboard/app.py` | Streamlit SENTINEL dashboard |
| `dashboard/incidents.py` | Incident History page |
| `dashboard/threat_intel.py` | Threat Intelligence / IOC page |
| `dashboard/sentinel-bundle/frontend/` | React + Vite + TanStack Router + shadcn/ui dashboard (work in progress) |
| `rag_docs/playbooks/` | SOC response playbooks — the RAG knowledge base |

---

## Setup

### Requirements

- Python 3.10+
- A reachable Wazuh indexer / OpenSearch at `https://localhost:9200` (for live alerts)
- A Groq API key — [console.groq.com/keys](https://console.groq.com/keys)

### Install

```bash
git clone https://github.com/mohamedzaim373/sentinel-threat-copilot.git
cd sentinel-threat-copilot

python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Configure

```bash
cp .env.example .env
```

Fill in `GROQ_API_KEY` and `OPENSEARCH_PASS`. The threat-intel keys (AbuseIPDB, VirusTotal,
GreyNoise) are optional — enrichment degrades gracefully when one is missing, and ThreatFox
and URLhaus need no key at all.

### Build the knowledge base

```bash
python rag/ingest_docs.py
```

`chroma_db/` is generated output and is not tracked in git — run this once after cloning,
and again whenever you add a playbook to `rag_docs/`.

### Run

Two processes, two terminals:

```bash
# Terminal 1 — API on :8001
uvicorn backend.main:app --reload --port 8001

# Terminal 2 — dashboard on :8501
streamlit run dashboard/app.py
```

The dashboard calls the API at `http://localhost:8001` by default; override with `API_URL`
in `.env`. When the backend or indexer is unreachable, dashboard pages fall back to
generated sample data so the UI stays explorable without a live Wazuh stack.

### React frontend (optional, WIP)

```bash
cd dashboard/sentinel-bundle/frontend
bun install && bun run dev
```

---

## API

Base URL `http://localhost:8001`. Every family exposes the same four stages, so you can stop
at whichever depth you need — raw alerts, triage, enrichment, or full report.

| Endpoint | Description |
|----------|-------------|
| `GET /alerts` | Recent alerts — `limit`, `min_level`, `agent_id`, `rule_id` |
| `GET /alerts/latest` | Most recent alert of any type |
| `GET /analyze/latest` | Alert + Agent 1 triage |
| `GET /rag/latest` | Alert + Agent 1 + Agent 2 RAG enrichment |
| `GET /report/latest` | Full chain + final SOC report |
| `GET /alerts/web`, `/analyze/web/latest`, `/rag/web/latest`, `/report/web/latest` | Same chain, scoped to web/network threats (Apache, ModSecurity, Sysmon DNS, firewall, IOC matches) |
| `GET /alerts/ssh`, `/analyze/ssh/latest`, `/rag/ssh/latest`, `/report/ssh/latest` | Same chain, scoped to SSH brute-force rules |

Interactive docs at `http://localhost:8001/docs`.

---

## Dashboard

**SOC Overview** · **Alert Triage** · **MITRE ATT&CK** · **Incidents** · **Incident History**
· **Threat Intelligence** · **Analytics** — plus a direct LLM Agents section to run the
latest alert through Agent 1, Agent 2 and the final report on demand, and an API status
panel that health-checks the backend, indexer and each threat-intel provider.

---

## Notes

- Agent prompts and generated reports are in **French**; the code, API and docs are in English.
- `.env` is gitignored. If you fork or redeploy this, use your own keys.
- Lab-oriented defaults: OpenSearch at `localhost:9200` with TLS verification disabled and
  the `admin` user. Review these before pointing it at anything beyond a test environment.
