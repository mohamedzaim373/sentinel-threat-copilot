# Playbook SOC - SSH Brute Force

## Description
Une attaque SSH brute force consiste à tester plusieurs mots de passe ou identifiants afin d'obtenir un accès non autorisé à une machine distante via SSH.

## Signes observables
- Plusieurs échecs d'authentification SSH.
- Logs contenant "Failed password".
- Logs contenant "Maximum authentication attempts exceeded".
- Même adresse IP source répétée.
- Même utilisateur ciblé.
- Activité sur le port 22.

## Règles Wazuh associées
- 5760 : sshd authentication failed.
- 5758 : Maximum authentication attempts exceeded.
- 5551 : PAM multiple failed logins.
- 40111 : Multiple authentication failures.
- 100500 : Custom PFA high severity SSH brute force.

## Mapping MITRE ATT&CK
- Tactique : Credential Access
- Technique : Brute Force
- ID : T1110

## Gravité
La gravité est moyenne à élevée.
Elle devient élevée si plusieurs tentatives proviennent de la même adresse IP en peu de temps.

## Vérifications SOC
1. Vérifier l'adresse IP source.
2. Vérifier si une connexion SSH réussie a eu lieu après les échecs.
3. Vérifier les utilisateurs ciblés.
4. Vérifier le fichier /var/log/auth.log sur la victime.
5. Vérifier si l'adresse IP source est interne, externe ou appartient au lab.
6. Vérifier si l'activité correspond à un test autorisé.

## Actions défensives recommandées
1. Bloquer temporairement l'adresse IP source si elle n'est pas autorisée.
2. Activer ou vérifier Fail2ban.
3. Désactiver l'authentification SSH par mot de passe si possible.
4. Utiliser une authentification par clés SSH.
5. Désactiver la connexion root SSH.
6. Appliquer une politique de mots de passe robustes.
7. Surveiller les connexions réussies après les échecs.

## Commandes défensives utiles
sudo tail -n 100 /var/log/auth.log
sudo grep "Failed password" /var/log/auth.log
sudo grep "Accepted password" /var/log/auth.log
sudo ss -tulpn | grep :22

## Classification
- Faux positif : erreur utilisateur isolée.
- Test autorisé : activité générée dans un lab PFA ou test interne validé.
- Suspect : plusieurs tentatives échouées depuis la même IP.
- Confirmé : plusieurs échecs suivis d'une connexion réussie ou activité provenant d'une IP non autorisée.
