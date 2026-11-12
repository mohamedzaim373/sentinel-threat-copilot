import json
import os
from groq import Groq
from dotenv import load_dotenv

load_dotenv()

MODEL_NAME = "llama-3.3-70b-versatile"
client = Groq(api_key=os.getenv("GROQ_API_KEY"))


def generate_soc_report(alert: dict, agent_1_analysis: str, agent_2_enrichment: str) -> str:
    alert_type = alert.get("description") or "Alerte Wazuh"
    groups_str = ", ".join(alert.get("groups") or []) or "non spécifié"

    prompt = f"""
Tu es un analyste SOC niveau 2.

Tu dois générer un rapport SOC final à partir :
- d'une alerte Wazuh
- de l'analyse Agent 1
- de l'enrichissement RAG Agent 2

Contexte du laboratoire :
- Projet PFA autorisé.
- Serveur Wazuh : 192.168.110.155
- Réseau surveillé : 192.168.110.0/24

Type d'alerte : {alert_type}
Groupes Wazuh : {groups_str}

Alerte Wazuh :
{json.dumps(alert, indent=2, ensure_ascii=False)}

Analyse Agent 1 :
{agent_1_analysis}

Enrichissement Agent 2 RAG :
{agent_2_enrichment}

Génère un rapport final en français avec cette structure :

# Rapport d'incident SOC-AI

## 1. Titre de l'incident

## 2. Résumé exécutif

## 3. Informations de l'alerte
- Date / heure
- Rule ID
- Niveau Wazuh
- Groupes Wazuh
- Agent victime
- IP victime
- IP source attaquante
- Utilisateur ciblé

## 4. Description technique

## 5. Preuves observées

## 6. Mapping MITRE ATT&CK

## 7. Classification de l'incident
Choisir une seule valeur :
- Test autorisé
- Suspect
- Incident confirmé
- Faux positif

## 8. Niveau de risque final
Low / Medium / High / Critical

## 9. Actions recommandées

## 10. Conclusion

Important :
- Adapte le rapport au TYPE D'ALERTE réel (pas forcément SSH).
- Reste dans un cadre défensif SOC.
- Ne donne pas d'instructions offensives.
- Le rapport doit être propre et directement utilisable dans un PFA.
"""

    try:
        response = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
            max_tokens=1500
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"[ERROR] Groq API : {e}"


if __name__ == "__main__":
    sample_alert = {
        "timestamp": "2026-05-06T18:23:40",
        "rule_id": "5758",
        "rule_level": 8,
        "description": "Maximum authentication attempts exceeded.",
        "agent_name": "wazuh-VMware-Virtual-Platform",
        "agent_ip": "192.168.190.130",
        "srcip": "192.168.190.129",
        "target_user": "wazuh",
        "full_log": "Maximum authentication attempts exceeded for wazuh from 192.168.190.129"
    }

    print(generate_soc_report(
        sample_alert,
        "Agent 1 : tentative de brute force SSH détectée.",
        "Agent 2 : mapping MITRE T1110 Brute Force, playbook SSH brute force utilisé."
    ))
