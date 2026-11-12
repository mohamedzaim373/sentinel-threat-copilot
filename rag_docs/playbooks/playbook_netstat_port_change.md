# Playbook SOC - Changement d'état des ports réseau (Netstat)

## Description
Une alerte netstat indique qu'un port en écoute a été ouvert ou fermé sur une machine surveillée. Ce type d'alerte peut signaler un service nouvellement démarré, une backdoor, ou une modification de configuration malveillante.

## Signes observables
- Changement de la liste des ports en écoute (netstat).
- Apparition d'un nouveau port non attendu (ex : port non standard > 1024).
- Fermeture soudaine d'un port normalement actif.
- Port ouvert sans processus légitime associé.
- Ports inhabituels : 4444, 1337, 31337, 6666, 5555 (backdoors communes).

## Règles Wazuh associées
- 533 : Netstat output changed (port listening state changed).
- 534 : Netstat output changed (port closed).
- 535 : Netstat output changed (new port listening).

## Techniques MITRE ATT&CK associées
- T1049 : System Network Connections Discovery (Discovery) - l'attaquant enumère les connexions réseau.
- T1571 : Non-Standard Port (Command and Control) - communication C2 sur port non standard.
- T1205 : Traffic Signaling (Defense Evasion / C2) - port ouvert uniquement sur signal spécifique.
- T1543 : Create or Modify System Process (Persistence) - service créé pour maintenir l'accès.
- T1059 : Command and Scripting Interpreter (Execution) - script ayant ouvert le port.

## Analyse du contexte
Les ports observés dans cette alerte (22 SSH, 443 HTTPS, 631 CUPS, 1514/1515 Wazuh, 1883 Mosquitto, 8001/8501 app, 9200/9300 OpenSearch, 55000 Wazuh API) sont tous des ports légitimes liés à l'infrastructure SOC-AI. Ce profil est cohérent avec un environnement de lab autorisé.

## Ports légitimes de l'infrastructure SOC-AI
- 22 : OpenSSH
- 443 : HTTPS
- 631 : CUPS (impression)
- 1514 : Wazuh agent communication
- 1515 : Wazuh agent enrollment
- 1883 : Mosquitto MQTT broker
- 8001 : FastAPI backend SOC-AI
- 8501 : Streamlit dashboard
- 9200 : OpenSearch REST API
- 9300 : OpenSearch cluster communication
- 55000 : Wazuh API REST

## Procédure de réponse
1. Identifier le nouveau port ou le port modifié.
2. Vérifier le processus lié au port : `ss -tlnp` ou `lsof -i :<port>`.
3. Confirmer si le processus est légitime (service connu, PID attendu).
4. Si port non reconnu : isoler la machine et investiguer.
5. Vérifier les logs système : `journalctl -u <service> --since "10 minutes ago"`.
6. Comparer avec la baseline des ports autorisés.

## Actions défensives
- Maintenir une liste blanche des ports autorisés.
- Surveiller les changements netstat avec Wazuh rootcheck.
- Configurer un firewall (iptables/ufw) avec règles strictes.
- Activer l'audit des processus qui ouvrent des sockets réseau.

## Niveau de risque par défaut
- Port nouveau non reconnu : HIGH
- Port de l'infrastructure SOC-AI : INFO / faux positif probable
- Port backdoor connu (4444, 1337) : CRITICAL
