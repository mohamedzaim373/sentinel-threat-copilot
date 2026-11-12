import json
import os
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import sys
from dotenv import load_dotenv
from groq import Groq

sys.path.append(str(Path(__file__).resolve().parents[1]))

load_dotenv()

from rag.retriever import search_knowledge_base

MODEL_NAME = "llama-3.3-70b-versatile"
client = Groq(api_key=os.getenv("GROQ_API_KEY"))

ABUSEIPDB_API_KEY  = os.getenv("ABUSEIPDB_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
GREYNOISE_API_KEY  = os.getenv("GREYNOISE_API_KEY", "")

# Mapping Wazuh rule groups → MITRE techniques pertinentes
_GROUPS_MITRE_MAP = {
    "authentication_failed":  ["T1110", "T1110.001"],
    "authentication_success": ["T1078"],
    "attack":                 ["T1190", "T1059"],
    "web":                    ["T1190", "T1071.001"],
    "rootcheck":              ["T1014", "T1543"],
    "malware":                ["T1204", "T1059"],
    "firewall":               ["T1071", "T1562.004"],
    "dos":                    ["T1499"],
    "ddos":                   ["T1498"],
    "sysmon":                 ["T1059", "T1055"],
    "windows":                ["T1059.001", "T1078"],
    "audit":                  ["T1562", "T1070"],
    "syslog":                 ["T1110"],
}

_DEFAULT_MITRE = ["T1110", "T1059", "T1190"]


def _infer_mitre_techniques(alert: dict) -> list[str]:
    """Pick MITRE techniques based on the alert's rule groups and description."""
    groups = alert.get("groups") or []
    techniques: set[str] = set()
    for g in groups:
        for key, techs in _GROUPS_MITRE_MAP.items():
            if key in g.lower():
                techniques.update(techs)
    if not techniques:
        desc = (alert.get("description") or "").lower()
        if "ssh" in desc or "brute" in desc or "password" in desc:
            techniques.update(["T1110", "T1110.001", "T1021.004"])
        elif "web" in desc or "http" in desc or "sql" in desc:
            techniques.update(["T1190", "T1071.001"])
        elif "malware" in desc or "trojan" in desc or "virus" in desc:
            techniques.update(["T1204", "T1059"])
        else:
            techniques.update(_DEFAULT_MITRE)
    return list(techniques)[:4]  # limit to 4 techniques for API cost

# Shared session for connection reuse
_session = requests.Session()
_session.headers.update({"User-Agent": "SOC-AI/1.0"})


def check_abuseipdb(ip: str) -> dict:
    if not ip or not ABUSEIPDB_API_KEY:
        return {"error": "Clé API AbuseIPDB manquante ou IP vide"}
    try:
        r = _session.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=8,
        )
        r.raise_for_status()
        d = r.json().get("data", {})
        return {
            "ip": d.get("ipAddress"),
            "abuse_confidence_score": d.get("abuseConfidenceScore"),
            "country": d.get("countryCode"),
            "isp": d.get("isp"),
            "total_reports": d.get("totalReports"),
            "last_reported": d.get("lastReportedAt"),
            "is_whitelisted": d.get("isWhitelisted"),
        }
    except Exception as e:
        return {"error": f"AbuseIPDB : {e}"}


def check_virustotal(ip: str) -> dict:
    if not ip or not VIRUSTOTAL_API_KEY:
        return {"error": "Clé API VirusTotal manquante ou IP vide"}
    try:
        r = _session.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": VIRUSTOTAL_API_KEY},
            timeout=8,
        )
        r.raise_for_status()
        attrs = r.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "ip": ip,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "country": attrs.get("country"),
            "owner": attrs.get("as_owner"),
            "reputation": attrs.get("reputation"),
        }
    except Exception as e:
        return {"error": f"VirusTotal : {e}"}


def check_greynoise(ip: str) -> dict:
    if not ip or not GREYNOISE_API_KEY:
        return {"error": "Clé API GreyNoise manquante ou IP vide"}
    try:
        r = _session.get(
            f"https://api.greynoise.io/v3/community/{ip}",
            headers={"key": GREYNOISE_API_KEY, "Accept": "application/json"},
            timeout=8,
        )
        if r.status_code == 404:
            return {"ip": ip, "noise": False, "riot": False, "message": "IP inconnue de GreyNoise"}
        r.raise_for_status()
        d = r.json()
        return {
            "ip": ip, "noise": d.get("noise"), "riot": d.get("riot"),
            "classification": d.get("classification"), "name": d.get("name"),
            "last_seen": d.get("last_seen"), "message": d.get("message"),
            "link": d.get("link"),
        }
    except Exception as e:
        return {"error": f"GreyNoise : {e}"}


def check_threatfox(ip: str) -> dict:
    if not ip:
        return {"error": "IP vide"}
    try:
        r = _session.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "search_ioc", "search_term": ip},
            timeout=8,
        )
        r.raise_for_status()
        d = r.json()
        if d.get("query_status") != "ok":
            return {"ip": ip, "found": False, "message": d.get("query_status", "Aucun résultat")}
        iocs = d.get("data", [])[:3]
        return {
            "ip": ip, "found": True, "total_iocs": len(d.get("data", [])),
            "iocs": [
                {
                    "ioc": i.get("ioc"), "threat_type": i.get("threat_type"),
                    "malware": i.get("malware"), "confidence_level": i.get("confidence_level"),
                    "first_seen": i.get("first_seen"), "last_seen": i.get("last_seen"),
                }
                for i in iocs
            ],
        }
    except Exception as e:
        return {"error": f"ThreatFox : {e}"}


def check_urlhaus(ip: str) -> dict:
    if not ip:
        return {"error": "IP vide"}
    try:
        r = _session.post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            data={"host": ip}, timeout=8,
        )
        r.raise_for_status()
        d = r.json()
        if d.get("query_status") != "is_host":
            return {"ip": ip, "found": False, "message": d.get("query_status", "Host non trouvé")}
        urls = d.get("urls", [])[:3]
        return {
            "ip": ip, "found": True, "urls_count": len(d.get("urls", [])),
            "blacklists": d.get("blacklists", {}),
            "urls": [
                {
                    "url": u.get("url"), "url_status": u.get("url_status"),
                    "threat": u.get("threat"), "date_added": u.get("date_added"),
                }
                for u in urls
            ],
        }
    except Exception as e:
        return {"error": f"URLHaus : {e}"}


def get_mitre_technique(technique_id: str) -> dict:
    try:
        r = _session.get(
            "https://attack.mitre.org/taxii/api/v21/collections/enterprise-attack/objects/",
            headers={"Accept": "application/taxii+json;version=2.1"},
            params={
                "match[type]": "attack-pattern",
                "match[external_references.external_id]": technique_id,
            },
            timeout=10,
        )
        r.raise_for_status()
        objects = r.json().get("objects", [])
        if not objects:
            return {"error": f"Technique {technique_id} introuvable"}
        obj = objects[0]
        mitre_ref = next(
            (ref for ref in obj.get("external_references", [])
             if ref.get("source_name") == "mitre-attack"),
            {}
        )
        return {
            "id": technique_id, "name": obj.get("name"),
            "description": obj.get("description", "")[:400],
            "url": mitre_ref.get("url"),
            "tactics": [p.get("phase_name") for p in obj.get("kill_chain_phases", [])],
            "platforms": obj.get("x_mitre_platforms", []),
        }
    except Exception as e:
        return {"error": f"MITRE ATT&CK : {e}"}


def enrich_with_rag(alert: dict, alert_analysis: str = "") -> str:
    srcip = alert.get("srcip")
    mitre_techniques = _infer_mitre_techniques(alert)

    # Build RAG query dynamically from the actual alert content
    rag_query = (
        f"Wazuh alert\n"
        f"rule_id: {alert.get('rule_id')}\n"
        f"groups: {alert.get('groups')}\n"
        f"description: {alert.get('description')}\n"
        f"source_ip: {srcip}\n"
        f"target_user: {alert.get('target_user')}\n"
        f"full_log: {alert.get('full_log')}"
    )

    # ── Parallel I/O: RAG + 5 threat intel APIs + MITRE lookups ─────────────
    tasks: dict[str, object] = {}

    with ThreadPoolExecutor(max_workers=10) as pool:
        tasks["rag"] = pool.submit(search_knowledge_base, rag_query, 3)
        if srcip:
            tasks["abuseipdb"]  = pool.submit(check_abuseipdb,  srcip)
            tasks["virustotal"] = pool.submit(check_virustotal, srcip)
            tasks["greynoise"]  = pool.submit(check_greynoise,  srcip)
            tasks["threatfox"]  = pool.submit(check_threatfox,  srcip)
            tasks["urlhaus"]    = pool.submit(check_urlhaus,    srcip)
        for tid in mitre_techniques:
            tasks[f"mitre_{tid}"] = pool.submit(get_mitre_technique, tid)

        results = {key: fut.result() for key, fut in tasks.items()}

    # Unpack results
    docs = results.get("rag", [])
    rag_context = "\n\n".join(
        f"Source: {doc['metadata'].get('source')}\n{doc['content']}"
        for doc in docs
    )

    no_ip = {"error": "IP source absente"}
    abuseipdb  = results.get("abuseipdb",  no_ip)
    virustotal = results.get("virustotal", no_ip)
    greynoise  = results.get("greynoise",  no_ip)
    threatfox  = results.get("threatfox",  no_ip)
    urlhaus    = results.get("urlhaus",    no_ip)
    mitre_data = {tid: results.get(f"mitre_{tid}", {}) for tid in mitre_techniques}

    alert_type = alert.get("description") or "Alerte Wazuh"
    groups_str = ", ".join(alert.get("groups") or []) or "non spécifié"

    prompt = f"""
Tu es un agent Threat Intelligence SOC utilisant une base RAG et des sources externes.

Contexte du laboratoire :
- Projet PFA autorisé.
- Serveur Wazuh : 192.168.110.155
- Réseau surveillé : 192.168.110.0/24

Alerte Wazuh :
{json.dumps(alert, indent=2, ensure_ascii=False)}

Type d'alerte : {alert_type}
Groupes Wazuh : {groups_str}

Analyse Agent 1 :
{alert_analysis}

--- THREAT INTELLIGENCE EXTERNE ---

AbuseIPDB (IP source : {srcip}) :
{json.dumps(abuseipdb, indent=2, ensure_ascii=False)}

VirusTotal (IP source : {srcip}) :
{json.dumps(virustotal, indent=2, ensure_ascii=False)}

GreyNoise (IP source : {srcip}) :
{json.dumps(greynoise, indent=2, ensure_ascii=False)}

ThreatFox (IP source : {srcip}) :
{json.dumps(threatfox, indent=2, ensure_ascii=False)}

URLHaus (IP source : {srcip}) :
{json.dumps(urlhaus, indent=2, ensure_ascii=False)}

MITRE ATT&CK (techniques inférées pour ce type d'alerte) :
{json.dumps(mitre_data, indent=2, ensure_ascii=False)}

--- CONTEXTE RAG ---
{rag_context}

Réponds en français avec :

1. Type de menace identifié
2. Mapping MITRE ATT&CK (avec nom et tactique pour chaque technique)
3. Analyse de réputation IP (AbuseIPDB + VirusTotal + GreyNoise + ThreatFox + URLHaus)
4. Description technique de l'attaque/incident détecté
5. Niveau de risque SOC
6. Preuves observées
7. Vérifications recommandées
8. Actions défensives recommandées
9. Classification finale
10. Sources utilisées (RAG + Threat Intel externe)

Important :
- Adapte ton analyse au TYPE D'ALERTE réel (pas forcément SSH).
- Utilise et cite AbuseIPDB, VirusTotal, GreyNoise, ThreatFox, URLHaus et MITRE ATT&CK.
- Utilise prioritairement le contexte RAG pour les recommandations.
- Ne donne pas d'instructions offensives.
- Reste dans un cadre SOC défensif.
"""

    try:
        response = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
            max_tokens=1200,
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"[ERROR] Groq API : {e}"


if __name__ == "__main__":
    sample_alert = {
        "timestamp": "2026-05-09T12:00:00",
        "rule_id": "5758", "rule_level": 8,
        "description": "Maximum authentication attempts exceeded.",
        "agent_name": "zaim-VMware-Virtual-Platform",
        "agent_ip": "192.168.110.155",
        "srcip": "192.168.110.151",
        "target_user": "root",
        "full_log": "Maximum authentication attempts exceeded for root from 192.168.110.151",
    }
    print(enrich_with_rag(sample_alert))
