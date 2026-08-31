# Dépôts

Un dépôt est une cible de scan : une URL de clonage, une branche, éventuellement un
sous-chemin, et une récurrence.

## En enregistrer un

**Dépôts → ajouter.**

| Champ | Notes |
|---|---|
| **URL du dépôt** | HTTPS pour un dépôt public, SSH là où une clé de déploiement est nécessaire. |
| **Nom affiché** | Le nom sous lequel tous les autres écrans le désignent. |
| **Branche** | La branche analysée à chaque exécution. |
| **Sous-chemin** | Pour un monodépôt. Enregistrez un monodépôt **une fois par projet**, pas une fois pour l'arbre entier — sinon un seul SBOM confond les dépendances de plusieurs applications et aucun verdict ne veut plus rien dire. |
| **Niveau de criticité métier** | Niveau 1 · critique pour la mission, niveau 2 · opérationnel, niveau 3 · interne. |
| **Agent requis** | Épingle le scan à un agent. Laissez vide, sauf si le dépôt n'est routable que depuis un segment réseau particulier. |

## Identifiants {#credentials}

Les dépôts privés s'authentifient avec une clé de déploiement enregistrée sous
[Clés SSH](../administration/ssh-keys.md). Donnez-lui un accès **en lecture seule** chez votre
hébergeur — Vectispire ne fait jamais que cloner.

La moitié privée est chiffrée au repos avec votre `ENCRYPTION_KEY`. Le stockage d'une clé est
refusé net tant que cette variable n'est pas posée.

## Récurrence {#recurrence}

Posez soit un **intervalle de scan**, soit une **expression cron**. L'expression l'emporte
quand les deux sont présents.

Préférez cron. Un intervalle dérive de quelques minutes à chaque exécution, si bien qu'un scan
configuré pour 03:00 migre dans la journée de travail en quelques semaines — et un scan qui
concurrence la journée de travail est le scan que quelqu'un finit par désactiver.

La récurrence est la raison d'être du produit plutôt qu'une commodité : de nouvelles
vulnérabilités sont publiées contre du code qui n'a pas changé, donc un dépôt analysé une fois
est un dépôt dont la posture est connue à une date passée.

## Niveaux de criticité métier {#business-criticality-tiers}

Trois niveaux, et ils existent pour que le classement tienne compte de ce qu'une cible *est*
plutôt que seulement de ce qu'on y a trouvé :

- **Niveau 1 · critique pour la mission**
- **Niveau 2 · opérationnel**
- **Niveau 3 · interne**

La même CVE critique n'est pas le même problème dans un chemin de paiement et dans un outil
interne jetable. Sans niveau, le backlog affirme qu'ils sont identiques.

## La pastille README

Chaque dépôt peut exposer une pastille dynamique pour son propre README, montrant la note de
posture de sécurité. Elle met le chiffre sous les yeux des gens qui commitent, c'est-à-dire là
où il change les comportements.

## Supprimer un dépôt

Retirer un dépôt retire ses scans et son historique d'issues avec lui. Là où vous devez garder
la trace, exportez d'abord
[l'historique de détection et de triage](history.md) — ce document est écrit pour être lu
après coup par quelqu'un qui n'était pas là.
