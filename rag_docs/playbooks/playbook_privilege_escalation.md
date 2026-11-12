# Playbook SOC - Escalade de Privilèges

## Description
Une escalade de privilèges se produit lorsqu'un utilisateur ou processus obtient des droits supérieurs à ceux qui lui sont accordés (ex : passage de user à root/admin).

## Signes observables
- Commandes sudo exécutées par un utilisateur non autorisé.
- Tentatives d'exploitation de SUID/SGID binaries.
- Modification des fichiers /etc/sudoers ou /etc/passwd.
- Exécution de commandes en tant que root par un utilisateur non-root.
- Erreurs "sudo: authentication failure" répétées.
- Accès à /etc/shadow ou /etc/passwd.

## Règles Wazuh associées
- 5401 : Attempt to run sudo without tty.
- 5402 : Sudo rules not set for this user.
- 5501 : Login session opened for root.
- 5400 : Attempts to login using a root password over SSH.
- 2503 : User missed password more than one time.
- 2501 : User authentication failure (PAM).

## Techniques MITRE ATT&CK associées
- T1548 : Abuse Elevation Control Mechanism (Privilege Escalation).
- T1548.003 : Sudo and Sudo Caching (Privilege Escalation).
- T1078 : Valid Accounts (Privilege Escalation / Persistence).
- T1068 : Exploitation for Privilege Escalation.
- T1055 : Process Injection (Privilege Escalation / Defense Evasion).

## Procédure de réponse
1. Identifier l'utilisateur impliqué et les commandes exécutées.
2. Vérifier les logs sudo : `grep sudo /var/log/auth.log`.
3. Vérifier les modifications récentes sur /etc/sudoers, /etc/passwd, /etc/shadow.
4. Vérifier les binaires SUID : `find / -perm -4000 -type f 2>/dev/null`.
5. Analyser les processus en cours d'exécution en tant que root.

## Actions défensives
- Appliquer le principe du moindre privilège.
- Auditer régulièrement les règles sudo.
- Désactiver la connexion root SSH (PermitRootLogin no).
- Utiliser PAM avec des politiques strictes.
- Déployer auditd pour surveiller les appels système sensibles.

## Niveau de risque
- Tentative échouée : MEDIUM
- Escalade réussie confirmée : CRITICAL
