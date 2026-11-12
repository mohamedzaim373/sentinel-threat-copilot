# Playbook SOC - Attaques Web (SQLi, XSS, Path Traversal, RCE)

## Description
Les attaques web ciblent les applications exposées sur HTTP/HTTPS. Wazuh, couplé à un WAF ou à l'analyse des logs Apache/Nginx, détecte les tentatives d'injection SQL, XSS, traversée de répertoire, et exécution de commandes à distance.

## Signes observables
- Requêtes HTTP contenant des payloads SQL (UNION SELECT, OR 1=1, --).
- Requêtes contenant des balises script (<script>, alert(), onerror).
- Tentatives de traversée : /../../../etc/passwd.
- Codes HTTP 500 répétés depuis la même IP.
- Requêtes vers des chemins sensibles : /admin, /wp-login, /phpmyadmin.
- User-Agents suspects : sqlmap, nikto, nmap, havij.

## Règles Wazuh associées
- 31101 : Web attack detected.
- 31103 : SQL injection attempt.
- 31104 : XSS attempt detected.
- 31106 : Path traversal attempt.
- 31107 : Remote file inclusion attempt.
- 2501 : Multiple web server 400 errors.
- 2502 : Multiple web server 404 errors.

## Techniques MITRE ATT&CK associées
- T1190 : Exploit Public-Facing Application (Initial Access).
- T1059 : Command and Scripting Interpreter (Execution).
- T1505.003 : Web Shell (Persistence).
- T1071.001 : Web Protocols (Command and Control).
- T1110 : Brute Force (Credential Access) - sur formulaires login.
- T1083 : File and Directory Discovery (Discovery).

## Procédure de réponse
1. Identifier l'IP source et les requêtes malveillantes dans les logs.
2. Bloquer immédiatement l'IP source au niveau WAF/firewall.
3. Vérifier si une exploitation a réussi (codes HTTP 200 sur des endpoints sensibles).
4. Inspecter les fichiers récemment créés sur le serveur web.
5. Analyser les logs d'accès complets de la période d'attaque.
6. Restaurer les fichiers potentiellement compromis.

## Actions défensives
- Déployer un WAF (ModSecurity, AWS WAF).
- Utiliser des requêtes paramétrées (prepared statements) contre SQLi.
- Encoder les sorties HTML pour prévenir XSS.
- Restreindre les accès aux répertoires système depuis le web.
- Mettre à jour les frameworks et CMS régulièrement.

## Niveau de risque
- Tentative SQLi sans succès : MEDIUM
- RCE confirmée : CRITICAL
- Webshell détecté : CRITICAL
