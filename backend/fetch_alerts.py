import json
import os
import time
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

OPENSEARCH_URL  = "https://localhost:9200"
OPENSEARCH_USER = "admin"
OPENSEARCH_PASS = os.getenv("OPENSEARCH_PASS", "")

SSH_RULE_IDS = {"5760", "5758", "5551", "5763", "5503", "2502", "40111", "100500"}

# Web attacks (Apache/Nginx/IIS + OWASP)
WEB_RULE_IDS = {
    # Apache / Nginx access anomalies
    "31100", "31101", "31103", "31105", "31106", "31108",
    "31151", "31161", "31165", "31166",
    # ModSecurity / OWASP style
    "87102", "87103", "87104", "87105", "87106",
    # Sysmon — DNS query (Event ID 22) & network connection (Event ID 3)
    "61603", "61650", "61651",
    # Firewall blocks toward malicious destinations
    "4151",  "4152",  "40105", "40112",
    # VirusTotal / custom threat-intel IOC rules
    "87550", "87551",
    "100200", "100201", "100202",
}

MONITORED_RULES = {
    # ── SSH ──────────────────────────────────────────────────────────────────
    "5760":   "SSH authentication failed",
    "5758":   "Maximum authentication attempts exceeded",
    "5763":   "SSH brute force detected",
    "5551":   "PAM multiple failed logins",
    "5503":   "PAM user login failed",
    "2502":   "Multiple missed passwords",
    "40111":  "Multiple authentication failures",
    "100500": "PFA custom high severity SSH brute force",
    # ── Web attacks ───────────────────────────────────────────────────────────
    "31100":  "Multiple web server 400 errors",
    "31101":  "Web server 500 errors",
    "31103":  "Web attack detected",
    "31105":  "Attempt to access forbidden file/directory",
    "31106":  "Web attack — header injection",
    "31108":  "Invalid HTTP request",
    "31151":  "Web attack — possible buffer overflow",
    "31161":  "Web attack — SQL injection",
    "31165":  "Web attack — XSS",
    "31166":  "Web attack",
    "87102":  "Web attack: SQL injection (ModSecurity)",
    "87103":  "Web attack: XSS (ModSecurity)",
    "87104":  "Web attack: code injection",
    "87105":  "Web attack: path traversal",
    "87106":  "Web attack: remote file include",
    # ── Sysmon (Windows) ──────────────────────────────────────────────────────
    "61603":  "Sysmon: outbound network connection (Event ID 3)",
    "61650":  "Sysmon: DNS query to malicious domain (Event ID 22)",
    "61651":  "Sysmon: DNS query",
    # ── Firewall / network ────────────────────────────────────────────────────
    "4151":   "Firewall DROP — outbound to blacklisted IP",
    "4152":   "Firewall REJECT — suspicious destination",
    "40105":  "Multiple connection attempts to suspicious host",
    "40112":  "Connection attempt to known malicious IP",
    # ── Threat-intel / VirusTotal IOC ─────────────────────────────────────────
    "87550":  "VirusTotal: file hash flagged as malware",
    "87551":  "VirusTotal: URL flagged as malicious",
    "100200": "IOC match — malicious URL detected",
    "100201": "IOC match — malicious domain DNS query",
    "100202": "IOC match — malicious IP connection",
}

# Wazuh rule groups associated with web / network threat events
WEB_GROUPS = {"web", "attack", "sysmon", "windows", "firewall", "dos"}

# Human-readable labels for Wazuh rule groups
GROUP_LABELS = {
    "authentication_failed": "Authentification échouée",
    "authentication_success": "Authentification réussie",
    "syslog": "Syslog",
    "attack": "Attaque",
    "web": "Web",
    "rootcheck": "Rootkit",
    "malware": "Malware",
    "firewall": "Pare-feu",
    "dos": "DoS",
    "windows": "Windows",
    "sysmon": "Sysmon",
    "audit": "Audit",
}

# ── Persistent session with retry + connection pooling ────────────────────────
_retry = Retry(total=2, backoff_factor=0.3, status_forcelist=[502, 503, 504])
_adapter = HTTPAdapter(max_retries=_retry, pool_connections=4, pool_maxsize=8)
_session = requests.Session()
_session.mount("https://", _adapter)
_session.mount("http://",  _adapter)

# ── Simple TTL in-memory cache ────────────────────────────────────────────────
_cache: dict = {}
_CACHE_TTL = 60  # seconds


def _cache_get(key: str):
    entry = _cache.get(key)
    if entry and (time.time() - entry["ts"]) < _CACHE_TTL:
        return entry["data"]
    return None


def _cache_set(key: str, data):
    _cache[key] = {"ts": time.time(), "data": data}


# ── Alert cleaning ─────────────────────────────────────────────────────────────
def _clean_opensearch_hit(hit: dict) -> dict:
    s    = hit.get("_source", {})
    data = s.get("data", {})
    win  = data.get("win", {}).get("eventdata", {})  # Sysmon/Windows fields
    return {
        "timestamp":   s.get("timestamp"),
        "rule_id":     str(s.get("rule", {}).get("id", "")),
        "rule_level":  s.get("rule", {}).get("level"),
        "description": s.get("rule", {}).get("description"),
        "groups":      s.get("rule", {}).get("groups", []),
        "agent_id":    s.get("agent", {}).get("id"),
        "agent_name":  s.get("agent", {}).get("name"),
        "agent_ip":    s.get("agent", {}).get("ip"),
        "srcip":       data.get("srcip"),
        "target_user": data.get("dstuser"),
        "full_log":    s.get("full_log"),
        # ── Web / network enrichment ──────────────────────────────────────────
        "url":         data.get("url") or data.get("uri"),
        "domain":      data.get("hostname") or win.get("queryName"),
        "http_method": data.get("method"),
        "http_status": data.get("id") or data.get("status"),
        "dest_ip":     data.get("dstip") or win.get("destinationIp"),
        "dest_port":   data.get("dstport") or win.get("destinationPort"),
        "protocol":    data.get("protocol") or win.get("protocol"),
    }


def _query_opensearch(query: dict, limit: int = 20) -> list:
    cache_key = f"{json.dumps(query, sort_keys=True)}:{limit}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    try:
        resp = _session.post(
            f"{OPENSEARCH_URL}/wazuh-alerts-4.x-*/_search",
            json={
                "size": limit,
                "sort": [{"timestamp": {"order": "desc"}}],
                "query": query,
                "_source": [
                    "timestamp", "rule.id", "rule.level", "rule.description",
                    "rule.groups", "agent.id", "agent.name", "agent.ip",
                    "data.srcip", "data.dstuser", "full_log",
                    # web / network fields
                    "data.url", "data.uri", "data.hostname", "data.method",
                    "data.status", "data.id", "data.dstip", "data.dstport",
                    "data.protocol",
                    # Sysmon / Windows fields
                    "data.win.eventdata.queryName",
                    "data.win.eventdata.destinationIp",
                    "data.win.eventdata.destinationPort",
                    "data.win.eventdata.protocol",
                ],
            },
            auth=(OPENSEARCH_USER, OPENSEARCH_PASS),
            verify=False,
            timeout=10,
        )
        resp.raise_for_status()
        hits = resp.json().get("hits", {}).get("hits", [])
        result = [_clean_opensearch_hit(h) for h in hits]
        _cache_set(cache_key, result)
        return result
    except Exception as e:
        print(f"[OpenSearch ERROR] {e}")
        return []


def load_recent_alerts(limit=20, min_level=5, agent_id=None, rule_id=None):
    must = []
    if agent_id:
        must.append({"term": {"agent.id": str(agent_id)}})
    if rule_id:
        must.append({"term": {"rule.id": str(rule_id)}})
    if min_level:
        must.append({"range": {"rule.level": {"gte": min_level}}})
    query = {"bool": {"must": must}} if must else {"match_all": {}}
    return _query_opensearch(query, limit=limit)


def load_latest_alert(min_level=5, agent_id=None, groups=None):
    """Return the single most recent alert of any type matching the filters."""
    must = []
    if min_level:
        must.append({"range": {"rule.level": {"gte": min_level}}})
    if agent_id:
        must.append({"term": {"agent.id": str(agent_id)}})
    if groups:
        must.append({"terms": {"rule.groups": groups}})
    query = {"bool": {"must": must}} if must else {"match_all": {}}
    results = _query_opensearch(query, limit=1)
    return results[0] if results else None


def load_recent_ssh_alerts(limit=20, agent_id=None):
    must = [{"terms": {"rule.id": list(SSH_RULE_IDS)}}]
    if agent_id:
        must.append({"term": {"agent.id": str(agent_id)}})
    query = {"bool": {"must": must}}
    return _query_opensearch(query, limit=limit)


def load_recent_web_alerts(limit=20, agent_id=None, min_level=3):
    """Return recent web/network threat alerts (malicious sites, DNS, firewall blocks)."""
    should = [
        {"terms": {"rule.id": list(WEB_RULE_IDS)}},
        {"terms": {"rule.groups": list(WEB_GROUPS)}},
    ]
    must = [
        {"bool": {"should": should, "minimum_should_match": 1}},
        {"range": {"rule.level": {"gte": min_level}}},
    ]
    if agent_id:
        must.append({"term": {"agent.id": str(agent_id)}})
    query = {"bool": {"must": must}}
    return _query_opensearch(query, limit=limit)


def load_latest_web_alert(agent_id=None, min_level=3):
    results = load_recent_web_alerts(limit=1, agent_id=agent_id, min_level=min_level)
    return results[0] if results else None
