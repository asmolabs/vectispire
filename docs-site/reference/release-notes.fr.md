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

**Les tentatives comptées par les réclamations retenues sont rendues une fois, au premier
démarrage.** Avant cette version, chaque interrogation d'un tel agent prenait un scan qui avait
besoin d'un identifiant — une tentative — et le remettait en file : un scan que rien n'avait essayé
pouvait échouer en « bail épuisé » à sa première vraie reprise. Sur une base qui déclare un agent
`delegated`, les scans en attente de dépôts portant un identifiant qu'aucun agent n'a jamais reçu
(pas d'`AGENT_CREDENTIAL_SENT`) voient leurs tentatives remises à 0, consigné une fois sous
`SCAN_ATTEMPTS_REPAIRED`. Ne sont pas touchés : un scan livré au moins une fois, en cours, terminé ou
déjà en échec — relancez à la main un scan en échec —, les scans d'images et les dépôts sans
identifiant.

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

**Le flux KEV est le catalogue de la CISA, lu sur le réseau.** C'était une liste de dix
enregistrements écrits dans le code ; le plan de contrôle lit désormais
`known_exploited_vulnerabilities.json` toutes les six heures et depuis l'onglet **Threat
Intelligence** des paramètres, et un scan interroge la copie stockée au lieu de la télécharger. Le
plan de contrôle doit joindre `www.cisa.gov` — ou `VECTISPIRE_KEV_URL` doit désigner un miroir (et
`VECTISPIRE_KEV_ALLOW_PRIVATE=true` s'il est sur un réseau privé), voir
[Configuration](configuration.md#threat-intelligence). La mise à jour vide l'ancien flux : jusqu'à la
première synchronisation, le statut indique *jamais synchronisé* et un scan ne marque rien comme
activement exploité. Cette première synchronisation **retire** aussi le marquage des constats
ouverts dont la CVE ne figure pas au catalogue, y compris ceux que la liste écrite en dur avait
marqués.

**Les analyses demandent un répertoire de l'hôte monté au même chemin — la composition livrée en
crée un désormais.** Les analyseurs sont des conteneurs que lance le démon Docker, et il résout ce
qu'il y monte sur son propre hôte ; la composition gardait les espaces de travail dans le `/tmp` du
plan de contrôle, si bien que chaque analyseur recevait un répertoire vide et **qu'aucune analyse du
`docker-compose.yml` livré n'a jamais abouti**. Elle monte maintenant `VECTISPIRE_WORK_DIR` (par
défaut `/var/lib/vectispire/work`, quelque 3 Go pour la base de vulnérabilités) au même chemin et le
prépare par un service ponctuel `work-dir` ; `docker compose up` s'en charge, il suffit d'avoir le
disque. Si vous utilisez **votre propre composition ou vos propres manifestes**, montez un
répertoire de l'hôte au même chemin absolu et réglez `JDK_JAVA_OPTIONS=-Djava.io.tmpdir=<chemin>` —
voir [Installation](../getting-started/installation.md) et
[Configuration](configuration.md#espaces-de-travail-des-analyses). Les analyseurs tournent
désormais sous le propriétaire de l'espace de travail et non plus sous root, qui ne pouvait pas le
lire.

**Les images construites depuis le `Dockerfile` tournent en 1000:1000**, comme les images publiées.
Si vous avez construit la vôtre et que son volume du miroir d'audit existe déjà, remettez-le une
fois : `docker run --rm -v vectispire_audit:/a alpine chown -R 1000:1000 /a`.

**Les migrations V32 à V43 s'exécutent au démarrage**, sur MySQL et PostgreSQL. Sauvegardez la
base avant, comme pour toute mise à jour — [sauvegarde et restauration](https://github.com/asmolabs/vectispire/blob/main/docs/fr/BACKUP_AND_RESTORE.fr.md).

### Changements visibles d'une intégration

- **Chaque erreur est un problème RFC 9457** (`application/problem+json`) avec un `detail` fait
  pour être affiché — voir [Erreurs de l'API](errors.md). Les refus qui ne portaient aucune phrase
  en portent une : une route inconnue, 405, 406, 415, un corps illisible, les refus de connexion,
  le 401 d'un identifiant absent ou invalide (qui n'avait pas de corps) et le 403 d'un rôle (qui
  portait le `{timestamp, status, error, path}` du conteneur). Les trois limiteurs de débit
  répondaient `{"message": …}` : la phrase est désormais `detail`, et un nouveau
  `retryAfterSeconds` répète l'en-tête `Retry-After`. Un client qui lit `message` doit lire
  `detail`.
- **Un 500 ne cite plus la défaillance.** Une erreur pour laquelle personne n'a écrit de message —
  y compris celles qui répondaient 400 ou 404 avec les mots d'une bibliothèque (« For input
  string », « No value present », « No enum constant … ») — est un 500 dont le `detail` donne un
  `correlationId`, journalisé avec l'erreur. Les refus que Vectispire écrit gardent leur statut et
  leur phrase.
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
- `GET /api/v1/threat-intel/status` et les deux routes de synchronisation renvoient la version du
  catalogue, sa date de publication, la dernière tentative et son erreur ; `status` vaut
  `NEVER_SYNCED`, `SYNCED` ou `FAILED`. Une synchronisation qui ne peut pas lire le catalogue répond
  **200** avec `FAILED` et la raison, conserve le catalogue en usage, et est auditée comme un
  `THREAT_INTEL_SYNCED` en échec. `GET /api/v1/epss/cve/{id}` ne répond plus que depuis le catalogue
  stocké — un **404** pour une CVE qu'il ne contient pas.
- Une revue OWASP est enregistrée avant que le modèle soit interrogé : `GET …/owasp-review` peut
  répondre `status: running` pendant qu'une autre demande attend, et se lit `failed` une fois le
  délai du modèle dépassé sans personne pour la clore.
- Nouveaux types de résultats `plugin` et `imported`, et nouveaux champs sur les problèmes et les
  scans (`tool`, `toolName`, `toolVersion`, `importSource`, les `plugins[]` d'un scan). Le
  document OpenAPI du dépôt fait foi.
- **L'atteignabilité n'est pas calculée, et le dit.** Les champs `reachability` et
  `reachableSymbols` d'un problème restent dans `GET /api/v1/issues` et `GET /api/v1/issues/{id}`,
  marqués dépréciés dans le document OpenAPI : toujours `UNKNOWN` et null, puisque rien n'analyse
  le graphe d'appels. Retirés là où seule l'interface les lisait : `reachableEpssCount` et la
  `reachability` de chaque problème classé de `GET /api/v1/epss/priorities`, la `reachability` de
  chaque cible du rayon d'impact, la clé `reachability` des `metadata` d'un nœud de chemin
  d'attaque, et `deterministic.exposure` de la réponse du conseiller IA.
  `POST /api/v1/ai-advisor/explain/cve/{id}` ignore un paramètre `reachability`. En OpenVEX, un
  constat en attente de triage indique « Awaiting contextual triage. » au lieu de « Awaiting
  reachability confirmation and contextual triage. »

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
- **Une base de vulnérabilités par hôte**, téléchargée une fois sous verrou et partagée en lecture
  seule par toutes les analyses au lieu d'une fois par analyse (quelque 3 Go), dans
  `VECTISPIRE_VULNERABILITY_DB_DIR` ; le rapprocheur tourne désormais sans réseau.
- **Réinitialiser la clé de scellement d'un agent** depuis l'écran Agents, pour un hôte dont
  l'horloge a été remise en arrière ou une clé soupçonnée d'avoir fui.
- L'authentification unique enregistre le second facteur du fournisseur et peut l'exiger
  (`VECTISPIRE_OIDC_REQUIRE_MFA`) ; Vault Transit peut détenir la clé de chiffrement.
- **Les écrans n'affichent plus l'atteignabilité**, que rien ne calcule : la liste des problèmes
  perd ses étiquettes atteignable / non atteignable, le détail d'un problème son encadré
  d'atteignabilité, la page EPSS sa carte « appelables et armées » et sa colonne, le rayon d'impact
  sa colonne. Le scorecard facture chaque critique 8 points, le classement EPSS est CVSS × EPSS
  avec le KEV au-dessus, et les chemins d'attaque ne retiennent ni ne signalent plus un nœud sur
  cette base — aucun chiffre qu'une installation a affiché ne bouge, puisque chaque problème valait
  `UNKNOWN`. Le conseiller IA indique que l'exposition n'a pas été évaluée.

### Sécurité

Cette version corrige les constats de la revue de sécurité du 2026-09-26 et leurs suites —
limites d'authentification sous tentatives concurrentes, liaison de l'authentification unique,
SSRF et différences d'analyse des URL de clonage, lectures sortantes bornées, complétude de
l'audit et du SIEM, clé de scellement de l'agent. Les dépendances et plugins de la construction
sont désormais vérifiés par signature et somme de contrôle. Le détail est dans l'historique des
commits et dans le
[registre des décisions](https://github.com/asmolabs/vectispire/tree/main/docs/architecture/fr/decisions).
