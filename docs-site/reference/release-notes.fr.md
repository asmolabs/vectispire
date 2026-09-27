# Notes de version

## Prochaine version (après 0.9.0)

Pas encore étiquetée. Lisez d'abord **Avant la mise à jour** : trois de ses points arrêtent
quelque chose tant qu'un opérateur n'a pas agi, et c'est voulu.

### Avant la mise à jour

**Les scans délégués s'arrêtent tant que chaque agent délégué n'est pas mis à jour et n'a pas de
clé de signature épinglée.** Un agent en mode d'identifiants `delegated` reçoit la clé SSH ou le
jeton HTTPS d'un dépôt scellé pour sa clé de scellement. Cette clé n'est désormais acceptée que si
l'agent la signe avec la clé Ed25519 qu'un administrateur a épinglée
([décision 0031](https://github.com/asmolabs/vectispire/blob/main/docs/architecture/fr/decisions/0031-a-sealing-key-is-believed-only-on-the-pinned-key.md)),
et aucun identifiant n'est plus jamais envoyé en clair, TLS ou pas. Tant qu'un agent n'est pas mis
à jour **et** que sa clé de signature n'est pas épinglée, il ne réclame aucun scan qui a besoin
d'un identifiant : ces scans attendent, en file et sans consommer de tentative, un exécuteur qui
peut les prendre. Les agents en mode `local`, les scans d'images et les dépôts sans identifiant ne
sont pas concernés. Avant la mise à jour : épinglez la clé de signature de chaque agent délégué
sur l'écran **Agents**, puis mettez les agents à jour. Voir [Agents](../administration/agents.md).

**Les secrets arrivent dans les conteneurs sous forme de fichiers, plus de variables
d'environnement.** Le `docker-compose.yml` livré remet désormais `ENCRYPTION_KEY`, les mots de
passe de la base, le mot de passe d'amorçage, `VECTISPIRE_SIGNING_KEY` et le secret du client OIDC
comme secrets Compose sous `/run/secrets/` : l'environnement d'un conteneur est lisible par tout ce
qui peut l'inspecter à travers le démon Docker. Si vous utilisez votre propre composition ou vos
propres manifestes, passez-les en fichiers de la même façon (`ENCRYPTION_KEY_FILE`,
`spring.config.import: optional:configtree:/run/secrets/`). Votre `.env` doit déclarer
`VECTISPIRE_SIGNING_KEY` et `VECTISPIRE_OIDC_CLIENT_SECRET`, vides s'ils ne servent pas : Compose
s'arrête en nommant la variable plutôt que de perdre une clé de signature qu'une installation
utilisait, parce qu'une clé remplacée rend invérifiable tout document déjà signé.

**La base n'est plus publiée sur l'hôte.** La publication du port `127.0.0.1:3306` a disparu et la
base est sur un réseau interne. Un outil qui s'y connectait depuis l'hôte passe par
`docker compose exec` ou par un réseau à lui.

**Tout corps de requête a un plafond.** 1 Mo par défaut (`VECTISPIRE_MAX_BODY_DEFAULT`) ; les
routes qui ont le leur le gardent : VEX 16 Mo, imports SARIF 32 Mo, envoi de jeux de règles
64 Mo, résultats d'agent 256 Mo. Un client qui envoie un corps plus gros à une route ordinaire
reçoit désormais un 413.

**Les migrations V32 à V41 s'exécutent au démarrage**, sur MySQL et PostgreSQL. Sauvegardez la
base avant, comme pour toute mise à jour — [sauvegarde et restauration](https://github.com/asmolabs/vectispire/blob/main/docs/fr/BACKUP_AND_RESTORE.fr.md).

### Changements visibles d'une intégration

- Un **413** est désormais toujours un problème RFC 9457 (`application/problem+json` avec
  `detail`), y compris quand il est refusé sur la longueur annoncée avant la lecture.
- Accorder un dépôt ou une image qui n'existe pas, ou que l'administrateur qui accorde ne voit
  pas, est refusé par un **404** ; un droit qui nomme un projet absent était un 400 et devient un
  404.
- Une **clé API restreinte à une cible** n'agit que sur cette cible ; une restriction qu'aucune
  route n'appliquerait est refusée à l'émission. Une clé restreinte à une cible supprimée est
  révoquée avec elle, et chaque révocation est auditée sous l'identifiant de la clé.
- Les clés d'intégration agissent pour le compte auquel elles appartiennent ; la clé d'un agent
  est cantonnée aux routes d'agent (403 ailleurs).
- La synchronisation threat-intel est auditée sous `THREAT_INTEL_SYNCED`, plus sous
  `SETTING_UPDATED` ; un changement de périmètre certifié l'est sous `CERTIFIED_SCOPE_CHANGED`. Un
  filtre sur l'ancienne opération ne trouve plus les synchronisations.
- Enregistrer un verdict de barrière est une écriture : l'auditeur et le gouverneur de la
  plateforme sont refusés.
- Nouveaux types de résultats `plugin` et `imported`, et nouveaux champs sur les problèmes et les
  scans (`tool`, `toolName`, `toolVersion`, `importSource`, les `plugins[]` d'un scan). Le
  document OpenAPI du dépôt fait foi.

### Nouveautés

- **Solutions et projets** : une solution contient des projets, un projet référence des dépôts,
  et un droit peut viser un projet entier — [Solutions et projets](../administration/solutions-and-projects.md).
- **Plugins d'analyse** : des analyseurs tiers livrés en images de conteneur, enregistrés par le
  gouverneur de la plateforme, activés par projet, lancés confinés comme les scanners intégrés, et
  seulement quand un langage qu'ils déclarent est présent. Une image peut déclarer son signataire ;
  la signature est vérifiée avant le pull, et `VECTISPIRE_PLUGIN_SIGNATURE_REQUIRED` en exige une
  pour tout plugin.
- **Imports SARIF** depuis des sources internes déclarées (un job de CI, un SonarQube sur site),
  chacune liée à une clé restreinte et à un périmètre, avec la provenance conservée sur chaque
  problème — [Plugins et imports SARIF](../administration/plugins.md). Les politiques de barrière
  ne comptent les résultats des plugins et importés que si elles le disent (`include_plugins`).
- **Git en HTTPS** avec un jeton géré lié à un hôte, à côté des clés SSH ;
  `VECTISPIRE_GIT_ALLOWED_HOSTS` restreint les hôtes d'où l'on clone.
- **Export SIEM** en syslog UDP, TCP ou TLS (RFC 5424, CEF), envoyé après le commit —
  [Export SIEM](../integrations/siem.md).
- **Scans parallèles sur un agent**, de 1 à 16 à la fois (`max_concurrent`), comptés par la base.
- **Réinitialiser la clé de scellement d'un agent** depuis l'écran Agents, pour un hôte dont
  l'horloge a été remise en arrière ou une clé soupçonnée d'avoir fui.
- L'authentification unique enregistre le second facteur du fournisseur et peut l'exiger
  (`VECTISPIRE_OIDC_REQUIRE_MFA`) ; Vault Transit peut détenir la clé de chiffrement.

### Sécurité

Cette version corrige les constats de la revue de sécurité du 2026-09-26 et leurs suites —
limites d'authentification sous tentatives concurrentes, liaison de l'authentification unique,
SSRF et différences d'analyse des URL de clonage, lectures sortantes bornées, complétude de
l'audit et du SIEM, clé de scellement de l'agent. Les dépendances et plugins de la construction
sont désormais vérifiés par signature et somme de contrôle. Le détail est dans l'historique des
commits et dans le
[registre des décisions](https://github.com/asmolabs/vectispire/tree/main/docs/architecture/fr/decisions).
