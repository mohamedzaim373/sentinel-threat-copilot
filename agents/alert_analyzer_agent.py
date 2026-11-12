import json
import os
from groq import Groq
from dotenv import load_dotenv

load_dotenv()

MODEL_NAME = "llama-3.3-70b-versatile"
client = Groq(api_key=os.getenv("GROQ_API_KEY"))


def analyze_alert(alert: dict) -> str:
    prompt = f"""
Tu es un analyste SOC niveau 1 spécialisé en Wazuh.

Analyse cette alerte de sécurité Wazuh et réponds en français.

Alerte Wazuh :
{json.dumps(alert, indent=2, ensure_ascii=False)}

Ta réponse doit contenir :

1. Résumé court de l'alerte
2. Type d'incident
3. Niveau de gravité estimé
4. Machine victime
5. Adresse IP attaquante
6. Utilisateur ciblé
7. Preuves observées
8. Hypothèse principale
9. Est-ce probablement une attaque réelle, un test ou un faux positif ?
10. Prochaine action recommandée pour un analyste SOC

Important :
- Ne donne pas d'instructions offensives.
- Reste dans un contexte défensif SOC.
- Sois clair et professionnel.
"""
    try:
        response = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
            max_tokens=800
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"[ERROR] Groq API : {e}"


if __name__ == "__main__":
    sample_alert = {
        "timestamp": "2026-05-09T12:00:00",
        "rule_id": "5760",
        "rule_level": 5,
        "description": "sshd: authentication failed.",
        "agent_name": "zaim-VMware-Virtual-Platform",
        "agent_ip": "192.168.110.155",
        "srcip": "192.168.110.151",
        "target_user": "root",
        "full_log": "Failed password for root from 192.168.110.151 port 39406 ssh2"
    }
    print(analyze_alert(sample_alert))
