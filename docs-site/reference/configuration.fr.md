# Configuration

L'essentiel des réglages vit dans la base de données et s'édite depuis
[Réglages](../administration/settings.md). Ce qui suit est ce qui doit être juste *avant* le
démarrage de l'application, parce que c'est nécessaire pour atteindre cet écran.

## Base de données

| Variable | Défaut |
|---|---|
| `VECTISPIRE_DB_URL` | `jdbc:mysql://localhost:3306/vectispire` — une URL **JDBC** ; MySQL est le moteur par défaut, celui que livre `docker-compose.yml`. PostgreSQL : `jdbc:postgresql://localhost:5432/vectispire` |
| `VECTISPIRE_DB_USER` | `vectispire` |
| `VECTISPIRE_DB_PASSWORD` | vide |

Le moteur est lu depuis l'URL. Il n'y a pas de réglage de dialecte séparé.

## Serveur et réseau

| Variable | Défaut | Notes |
|---|---|---|
| `VECTISPIRE_PORT` | `3180` | Le port HTTP. L'API, l'interface et le protocole des agents le partagent. |
| `VECTISPIRE_TRUSTED_PROXIES` | *aucun* | Adresses ou plages CIDR, séparées par des virgules, dont on croit le `X-Forwarded-For`. Vide signifie que rien n'est devant : l'en-tête est ignoré et c'est l'adresse du pair que les limiteurs de débit et le journal d'audit retiennent. Derrière un répartiteur de charge ou un ingress, nommez-le — sinon chaque requête arrive de lui et tout le parc partage un seul compteur. |
| `VECTISPIRE_PUBLIC_URL` | *aucun* | L'URL de base à laquelle on joint cette instance. Nommée dans l'URI d'information d'un export SARIF et dans l'identifiant d'un document VEX, pour qu'un document remis à quelqu'un d'autre dise d'où il vient, et utilisée pour les liens des notifications par courriel et des exports de projet. |

## Chiffrement

| Variable | Notes |
|---|---|
| `ENCRYPTION_KEY` | L'enregistrement de tout secret est refusé tant que celle-ci ou la forme fichier n'est pas posée. |
| `ENCRYPTION_KEY_FILE` | Un chemin vers un fichier contenant la clé. **À préférer en production.** Poser les deux est refusé ; un chemin qui ne résout pas arrête l'application. |
| `VECTISPIRE_SIGNING_KEY` | La clé privée ECDSA P-256 (PEM, PKCS#8) qui signe les paquets de preuves, VEX, CSAF, CycloneDX et enveloppes in-toto ; sa moitié publique est publiée sur `/api/v1/crypto/public-key.pub`. Non posée, une clé est générée au premier usage et conservée chiffrée sous `ENCRYPTION_KEY` : elle survit aux redémarrages — et rien ne peut être signé sans `ENCRYPTION_KEY`. **En 0.10.0, ce premier usage échoue** : une installation sans cette clé répond 500 à son premier paquet de preuves, parce que la clé était créée dans une transaction en lecture seule (corrigé dans la version qui suit la 0.10.0, voir les [notes de version](release-notes.md)). En 0.10.0, posez-la. **À poser dès que plus d'une instance tourne**, pour qu'elles signent toutes avec la même clé. Une clé conservée qu'aucune `ENCRYPTION_KEY` configurée ne sait déchiffrer est refusée, jamais remplacée : la remplacer rendrait invérifiable tout document déjà signé. La composition livrée la remet en fichier, `/run/secrets/vectispire.signing.key`, jamais en environnement, et demande la variable déclarée dans `.env`, même vide. |
| `VECTISPIRE_PREVIOUS_ENCRYPTION_KEYS` | Anciennes clés séparées par des virgules, essayées **au déchiffrement seulement**. |
| `VECTISPIRE_PREVIOUS_ENCRYPTION_KEYS_FILE` | La même liste depuis un fichier, séparée par des virgules ou des sauts de ligne. |

Voir [Rotation et purge](../administration/maintenance.md).

### Garde des clés dans HashiCorp Vault

`VECTISPIRE_ENCRYPTION_KMS_TYPE=vault` chiffre par le moteur Transit de Vault au lieu d'une clé locale,
avec `VECTISPIRE_ENCRYPTION_VAULT_ENDPOINT`, `VECTISPIRE_ENCRYPTION_VAULT_TOKEN` (ou `…_TOKEN_FILE`),
`VECTISPIRE_ENCRYPTION_VAULT_KEY_NAME` (par défaut `vectispire`) et `VECTISPIRE_ENCRYPTION_VAULT_MOUNT_PATH`
(par défaut `transit`). Demander Vault sans point d'accès ou sans jeton arrête l'application plutôt que
de se rabattre sur une clé locale.

**La clé Transit doit être dérivée** : `vault write -f transit/keys/vectispire derived=true`. Chaque
secret est chiffré avec la ligne à laquelle il appartient comme contexte, si bien qu'un chiffré déplacé
vers une autre ligne ne se déchiffre pas — et Vault n'utilise ce contexte que sur une clé dérivée, il
l'ignore sur une clé ordinaire. Vectispire lit la clé une fois et **refuse de chiffrer sous une clé non
dérivée** ; ce qu'une telle clé détient déjà reste lisible, avec une erreur dans le journal, jusqu'à ce
que les secrets soient enregistrés de nouveau sous une clé dérivée.

## Premier compte

| Variable | Notes |
|---|---|
| `VECTISPIRE_BOOTSTRAP_USERNAME` | Utilisé seulement quand la table des utilisateurs est vide. |
| `VECTISPIRE_BOOTSTRAP_PASSWORD` | Au moins 12 caractères. |

Dès qu'un compte existe, les deux sont ignorés.

## Authentification

| Variable | Défaut | Notes |
|---|---|---|
| `VECTISPIRE_OIDC_ISSUER` | *aucun* | Active l'[authentification unique](../administration/sso.md). |
| `VECTISPIRE_PASSWORD_LOGIN` | `true` | `false` délègue entièrement l'authentification. **Ignoré, bruyamment, sans émetteur posé** — cela ne laisserait aucune entrée. |
| `VECTISPIRE_OIDC_LINK_PRIVILEGED_ACCOUNTS` | `false` | Permet de lier un compte privilégié (tout rôle sauf USER) à sa première connexion par son nom ; jamais un compte doté d'un second facteur local. Seulement pour un realm où personne ne choisit son nom. |
| `VECTISPIRE_OIDC_REQUIRE_MFA` | `false` | Refuse une connexion SSO dont le jeton n'atteste aucun second facteur. Une connexion fédérée saute le TOTP local : le second facteur relève du fournisseur. |
| `VECTISPIRE_OIDC_MFA_AMR` | `mfa,otp,hwk,fido` | Les valeurs `amr` (RFC 8176) qui valent second facteur. |
| `VECTISPIRE_OIDC_MFA_ACR` | *aucun* | Les niveaux `acr` qui en valent un, quand le fournisseur signale le MFA ainsi. |
| `VECTISPIRE_SESSION_LIFETIME` | `12h` | Une session prend fin ce délai après son ouverture, quelle que soit son activité — ce qui borne l'utilité d'un jeton volé ; aucune activité ne la prolonge. |
| `VECTISPIRE_SESSION_IDLE` | `60m` | Une session prend fin après ce délai sans requête — ce qui protège un écran resté déverrouillé. |
| `VECTISPIRE_BEARER_FAILURES_PER_WINDOW` | `60` | Les jetons porteurs refusés — sessions, clés d'agent et d'intégration, jeton SCIM — comptés ensemble par adresse ; au-delà, l'adresse est refusée jusqu'à la fin de la fenêtre et le journal d'audit le consigne. Seuls les échecs comptent : un agent qui interroge avec une clé valide ne dépense rien. Généreux à dessein : ces jetons sont longs et aléatoires, et l'essentiel de la valeur du contrôle est l'entrée d'audit, pas le refus. |
| `VECTISPIRE_BEARER_FAILURE_WINDOW` | `PT5M` | La fenêtre du réglage ci-dessus, en durée ISO-8601. |
| `VECTISPIRE_API_KEY_REQUESTS_PER_MINUTE` | `600` | Requêtes par minute par [clé d'API d'intégration](../administration/api-keys.md) ; au-delà, `429` avec `Retry-After`. Les sessions et les agents ne sont pas comptés. |
| `VECTISPIRE_WEBHOOK_REQUESTS_PER_WINDOW` | `300` | Livraisons acceptées par fenêtre et par adresse sur le [webhook entrant du tracker](../integrations/ticketing.md#inbound-webhook) ; au-delà, `429` avec `Retry-After`. À relever si un tracker derrière une sortie partagée fait des transitions en masse plus grandes. |
| `VECTISPIRE_WEBHOOK_REQUEST_WINDOW` | `PT1M` | La fenêtre du réglage ci-dessus, en durée ISO-8601. |

Les livraisons de webhook refusées sont auditées avec parcimonie : la première d'une adresse sur dix
minutes, une fois encore si cette adresse en atteint vingt, et au plus cent entrées en dix minutes au
total. Chaque refus reçoit toujours sa réponse `401` ou `403`.

## Corps de requête

Chaque corps de requête est borné pendant sa lecture, qu'il déclare sa longueur ou non. Les routes
qui ne sont pas nommées ci-dessous prennent la limite par défaut ; une route nommée prend la sienne à
la place — plus grande ou plus petite — et n'est jamais ramenée au défaut. Au-delà de sa limite, une
route répond `413`, par un document de problème dont le `detail` donne la limite.

| Variable | Défaut | Route |
|---|---|---|
| `VECTISPIRE_MAX_BODY_DEFAULT` | `1MB` | chaque route non nommée ci-dessous, quelle que soit la méthode — un triage, une liste d'accès, un paramètre ou un utilisateur SCIM pèse au plus quelques dizaines de kilo-octets |
| `VECTISPIRE_MAX_BODY_RULE_SET_UPLOAD` | `64MB` | `POST /api/v1/rule-sets` — un jeu de règles peut contenir 32 Mo de fichiers, et le JSON qui les porte échappe leur YAML |
| `VECTISPIRE_MAX_BODY_TICKET_WEBHOOK` | `1MB` | `POST /api/v1/tickets/webhook/{provider}` — un événement de tracker pèse quelques dizaines de kilo-octets |
| `VECTISPIRE_MAX_BODY_VEX_INGEST` | `16MB` | `POST /api/v1/vex/ingest` — un document VEX pour un gros produit |
| `VECTISPIRE_MAX_BODY_AGENT_RESULT` | `256MB` | `POST /api/v1/agent/jobs/{id}/result` — le résultat porte le SBOM |
| `VECTISPIRE_MAX_BODY_SIGN_IN` | `16KB` | chaque `POST /api/v1/auth/…` — une connexion, un code à usage unique ou un échange de session pèse quelques centaines d'octets |
| `VECTISPIRE_MAX_BODY_SARIF_IMPORT` | `32MB` | `POST /api/v1/repositories/{id}/sarif-imports` — le rapport SARIF d'un outil interne pour un dépôt ; voir [Plugins et imports SARIF](../administration/plugins.md) |
| `VECTISPIRE_MAX_BODY_COVERAGE_IMPORT` | `16MB` | `POST /api/v1/repositories/{id}/coverage-imports` — un rapport JaCoCo ou Cobertura d'un gros dépôt fait quelques mégaoctets ; seuls les totaux sont gardés |
| `VECTISPIRE_MAX_BODY_TEST_REPORT_IMPORT` | `32MB` | `POST /api/v1/repositories/{id}/test-report-imports` — un document JUnit, ou un zip de plusieurs, dont les échecs portent des traces de pile ; le zip est borné de nouveau une fois décompressé |
| `VECTISPIRE_MAX_BODY_CHECKLIST_TEMPLATE_IMPORT` | `10MB` | `POST /api/v1/checklist-templates/{slug}/versions` — le classeur de checklist d'une organisation, lu en entier et borné de nouveau une fois décompressé |
| `VECTISPIRE_MAX_BODY_SBOM_IMPORT` | `32MB` | `POST /api/v1/repositories/{id}/build-sbom-imports` — le SBOM CycloneDX d'un build, quelques mégaoctets pour un gros build multi-modules ; relu jusqu'à 50 000 composants — voir [Importer le SBOM d'un build](../administration/plugins.md#importer-le-sbom-dun-build) |

## Clonage

| Variable | Défaut | Notes |
|---|---|---|
| `VECTISPIRE_GIT_ALLOWED_HOSTS` | *aucun* | Hôtes, séparés par des virgules, depuis lesquels les dépôts peuvent être clonés — `gitlab.corp.example, *.corp.example`. Vide, tout hôte est permis sauf les adresses link-local et les autres adresses de métadonnées du cloud, toujours refusées. Vérifié à la saisie de l'URL et avant chaque analyse. |
| `VECTISPIRE_HOST_SSH` | `true` | Un dépôt sans clé de déploiement attachée se rabat sur le `~/.ssh` de l'hôte qui analyse. Mettez `false` partout où les personnes qui ajoutent des cibles ne sont pas celles qui possèdent cette clé : le repli vaut pour tout l'hôte, si bien qu'ajouter une URL suffit alors à la faire cloner avec une identité que personne ne lui a attachée. `false` dans le `docker-compose.yml` livré, qui ne monte aucun `~/.ssh`. |

Un clone SSH avec clé de déploiement vérifie la clé d'hôte de la forge contre
`<home>/.ssh/known_hosts` de l'exécutant : inscrite au premier contact, refusée si elle change,
seulement comparée quand le fichier est en lecture seule — voir
[En SSH : la clé d'hôte de la forge](../guide/repositories.md#ssh-host-keys). Aucune `config` ssh
n'est lue pour un tel clone.

## Espaces de travail des analyses

L'espace de travail d'une analyse — et, sauf réglage ci-dessous, la base de vulnérabilités — est
créé dans le répertoire temporaire de la JVM, puis monté dans chaque analyseur **par le démon
Docker, qui résout le chemin sur son propre hôte**. Quand Vectispire tourne lui-même dans un
conteneur, ce répertoire doit donc être un répertoire de l'hôte monté **au même chemin absolu**,
sans quoi chaque analyseur reçoit un répertoire vide.

| Variable | Défaut | Notes |
|---|---|---|
| `VECTISPIRE_WORK_DIR` | `/var/lib/vectispire/work` | `docker-compose.yml` seulement. Le répertoire de l'hôte monté dans le plan de contrôle au même chemin, préparé pour son utilisateur (1000:1000, 0700) par le service `work-dir`, et donné comme `-Djava.io.tmpdir` par `JDK_JAVA_OPTIONS`. Contient le clone de chaque analyse en cours et la base du rapprocheur (quelque 3 Go), et sous `home/` le home du processus (`-Duser.home`), où les clés d'hôte SSH sont inscrites — le home propre de l'image, `HOME=/home/vectispire`, est dans la couche du conteneur et ne lui survit pas. Hors de la composition, faites de même à la main. |
| `VECTISPIRE_AGENT_WORK_DIR` | `/var/lib/vectispire/agent-work` | `docker-compose.yml`, profil `with-agent` : la même chose pour l'agent, dans un répertoire à lui. |

## Scanners

| Variable | Défaut | Notes |
|---|---|---|
| `VECTISPIRE_IMAGE_SYFT`, `VECTISPIRE_IMAGE_GRYPE`, `VECTISPIRE_IMAGE_GITLEAKS`, `VECTISPIRE_IMAGE_CHECKOV`, `VECTISPIRE_IMAGE_SEMGREP` | *l'empreinte épinglée* | L'image de chaque scanner, une à une. Vide garde l'empreinte livrée avec Vectispire — celle qui a été revue, dans `ScannerImages`. À poser pour tirer depuis un registre interne, comme doit le faire un parc isolé. Qui en surcharge une reprend à son compte ce que l'empreinte protégeait : un tag tire ce qui a été poussé sous lui le matin même, dans un conteneur qui lit du code que personne ne maîtrise — **nommez une empreinte**, `registry.corp.example/anchore/syft@sha256:…`. Lues par le worker intégré du plan de contrôle et, sous les mêmes noms, par chaque agent. |
| `VECTISPIRE_IMAGE_SCAN_PLATFORM` | *aucun* | La plateforme tirée pour l'analyse d'une image de conteneur, par exemple `linux/amd64`. Vide laisse le démon choisir sa propre architecture : une machine arm64 auditerait une variante que personne ne déploie. |

## Worker intégré et tâches périodiques

| Variable | Défaut | Notes |
|---|---|---|
| `VECTISPIRE_EMBEDDED_WORKER` | `true` | `false` pour un plan de contrôle qui n'exécute lui-même aucune analyse : les analyses en file attendent un agent distant, et les plugins de rapport n'ont pas d'exécuteur. |
| `VECTISPIRE_SCAN_MAX_CONCURRENT` | `2` | Les analyses que le worker intégré de cette instance exécute en même temps. Pas celles d'un agent : voir plus bas. |
| `VECTISPIRE_WORKER_LABELS` | *aucun* | Les étiquettes auxquelles répond le worker intégré. Vide à dessein : il ne prend alors que le travail qui n'exige aucune étiquette. |
| `VECTISPIRE_WORKER_INTERVAL` | `15s` | La fréquence à laquelle le worker intégré cherche du travail. |
| `VECTISPIRE_SCHEDULER_INTERVAL` | `60s` | La fréquence à laquelle on cherche les cibles dues pour une analyse périodique. |
| `VECTISPIRE_MAINTENANCE_INTERVAL` | `1h` | La fréquence du tic de maintenance — rétention, triages arrivant à échéance, balayage des tickets, flux de threat intelligence et le reste de l'entretien ; chaque tâche garde sa propre cadence à l'intérieur (le catalogue KEV toutes les six heures, EPSS chaque jour). |

L'intervalle de l'outbox, `VECTISPIRE_RELAY_INTERVAL`, est sous [Export SIEM](#export-siem).

## Base de vulnérabilités

| Variable | Défaut | Notes |
|---|---|---|
| `VECTISPIRE_VULNERABILITY_DB_DIR` | *un répertoire du répertoire temporaire — `VECTISPIRE_WORK_DIR` dans la composition* | Où la base du rapprocheur de vulnérabilités — quelque 3 Go — est téléchargée **une fois pour l'hôte** et partagée, en lecture seule, par toutes les analyses ; chaque analyse téléchargeait la sienne. Un seul téléchargement à la fois sous un verrou sur ce répertoire, publié en entier par un renommage atomique, vérifié toutes les heures, et les générations remplacées supprimées dès qu'aucune analyse ne peut plus les lire. Le rapprocheur lui-même tourne sans réseau. Un chemin de l'hôte du démon Docker, comme les espaces de travail ; un disque qui survit à un redémarrage épargne le téléchargement à la première analyse qui suit. |

## Plugins

| Variable | Défaut | Notes |
|---|---|---|
| `VECTISPIRE_PLUGIN_REGISTRY` | *aucun* | Le registre interne depuis lequel chaque image de [plugin](../administration/plugins.md) est tirée — `registry.corp.example:5000/mirror`. L'hôte du registre de l'image est remplacé, son chemin et son digest conservés : le miroir peut servir un plugin mais pas en substituer un autre. Ni schéma, ni identifiant. Positionnez la même valeur sur chaque agent. |
| `VECTISPIRE_PLUGIN_SIGNATURE_REQUIRED` | `true` | Le worker intégré ne lance aucun plugin dont le manifeste ne déclare pas de [signataire](../administration/plugins.md#signer-limage), sauf si le gouverneur de la plateforme a [levé l'exigence](../administration/plugins.md#faire-tourner-un-plugin-non-signe) pour ce plugin : il est *refusé* dans le scan (`unsigned`), et rien de lui n'est démarré. Un signataire déclaré est vérifié avec cosign avant le pull quoi que dise ce réglage. `false` lance tout plugin non signé sur cet exécuteur — préférez la dérogation par plugin. Chaque agent a le sien. **Un [plugin de rapport](../administration/report-plugins.fr.md) n'est pas concerné** : son signataire est toujours exigé. |
| `VECTISPIRE_REPORT_CONCURRENCY` | `2` | Combien d'[exécutions de rapport](../administration/report-plugins.fr.md#demander-un-rapport) cette instance du plan de contrôle mène à la fois — chacune un pull, une vérification de signature et un conteneur de jusqu'à cinq minutes. Les plugins de rapport s'exécutent sur le point d'accès conteneur du plan de contrôle, sous l'interrupteur du worker intégré : avec `VECTISPIRE_EMBEDDED_WORKER=false` il n'y en a pas, et une demande de rapport est refusée. Le miroir des plugins est `VECTISPIRE_PLUGIN_REGISTRY` ci-dessus. |
| `VECTISPIRE_REPORT_INTERVAL` | `10s` | À quelle fréquence il cherche les exécutions de rapport en attente, et celles qu'un exécuteur a laissées. |
| `VECTISPIRE_DISCOVERY_CONCURRENCY` | `2` | Combien de [découvertes de forge](../administration/forge-connections.fr.md#decouvrir-les-depots) cette instance du plan de contrôle mène à la fois — chacune un listage de jusqu'à trente minutes, qui dort sur les limites de débit de la forge. Les découvertes tournent sur chaque instance, quoi que dise `VECTISPIRE_EMBEDDED_WORKER`, et jamais sur un agent. |
| `VECTISPIRE_DISCOVERY_INTERVAL` | `5s` | À quelle fréquence elle cherche les découvertes en attente, et celles qu'une instance a laissées en route. |

## Threat intelligence

Le catalogue KEV de la CISA est lu toutes les six heures par la tâche de maintenance, le fichier
EPSS quotidien du FIRST une fois par jour, et les deux à la demande depuis l'onglet **Threat
Intelligence** des paramètres. Un scan lit les copies stockées et n'interroge personne : rien de ce
que contient un dépôt ne quitte le plan de contrôle, et un parc sans accès sortant scanne de la même
façon dès qu'un miroir sert les deux flux.

| Variable | Défaut | Notes |
|---|---|---|
| `VECTISPIRE_KEV_URL` | le `known_exploited_vulnerabilities.json` de la CISA | Un miroir, pour un parc qui ne joint pas `www.cisa.gov`. Il doit servir le catalogue entier au format de la CISA : un document sans sa liste, qui ne liste rien, qui porte moins d'entrées que son `count`, ou plus ancien que le catalogue en usage est refusé, et le catalogue en usage est conservé — ce qu'un catalogue partiel omet se lirait comme « n'est plus exploité ». |
| `VECTISPIRE_KEV_ALLOW_PRIVATE` | `false` | `true` autorise cette URL à se résoudre vers une adresse privée ou de bouclage — un miroir interne au parc. Le lien local (le point de métadonnées du cloud) reste refusé. Une propriété du déploiement plutôt qu'un paramètre, pour qu'aucune session ne puisse diriger cet appel vers le réseau interne. |
| `VECTISPIRE_EPSS_URL` | le `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz` du FIRST | Un miroir, pour un parc qui ne le joint pas — le fichier tel que le FIRST le publie, gzip ou CSV brut, première ligne `#model_version:…,score_date:…`. Une redirection vers le même hôte est suivie (l'adresse du FIRST redirige vers le fichier du jour) ; toute autre est refusée. Un fichier tronqué, qui a une ligne mal formée ou un score hors de [0, 1], qui porte moins de 100 000 scores ou un dixième de moins que le fichier en usage, qui dépasse 128 Mio une fois décompressé, ou plus ancien que le fichier en usage est refusé, et les scores en usage sont conservés. |
| `VECTISPIRE_EPSS_ALLOW_PRIVATE` | `false` | Comme `VECTISPIRE_KEV_ALLOW_PRIVATE`, pour le miroir EPSS — chaque flux a son propre interrupteur, pour qu'ouvrir le réseau privé à l'un ne l'ouvre pas à l'autre. |

L'onglet indique, pour chaque flux, quand il a été lu pour la dernière fois, ce qui est en usage — la
version et la date de publication CISA du catalogue, le modèle EPSS et le jour dont ses scores
relèvent — et la dernière tentative en échec avec sa raison. Jamais synchronisé, un scan ne marque
rien comme activement exploité et ne donne aucun score EPSS : inconnu, jamais zéro — le journal le dit
à chaque scan. Une fois un fichier EPSS appliqué, les scores des constats ouverts en sont rafraîchis,
si bien que la barrière, les scorecards et le classement EPSS lisent ceux du jour.

## Audit

| Variable | Notes |
|---|---|
| `VECTISPIRE_AUDIT_MIRROR` | Un chemin où chaque entrée d'audit est ajoutée comme une ligne JSON, hors de la base de données qu'elle surveille. Désactivé signifie que le journal n'a qu'une copie, et l'écran de vérification le dit. |

## Export SIEM

L'export se configure sur son [écran de réglages](../integrations/siem.fr.md), pas par des variables,
tout comme la possibilité de joindre un collecteur sur un réseau privé : le réglage **Autoriser une
destination SIEM privée**, réservé à un administrateur, désactivé par défaut et distinct de celui des
notifications. Trois choses autour de lui relèvent du déploiement :

| Variable | Défaut | Notes |
|---|---|---|
| `VECTISPIRE_RELAY_INTERVAL` | `60s` | La fréquence à laquelle l'outbox est vidée — notifications et événements SIEM confondus, donc l'attente la plus longue d'un événement après sa validation. |
| `HOSTNAME` | le nom de la machine | Ce que l'en-tête syslog déclare comme hôte émetteur. Les environnements de conteneurs le fixent. |
| `JAVA_TOOL_OPTIONS` | *aucun* | Options de la JVM. Un collecteur syslog sur TLS signé par une autorité privée n'a plus besoin de `-Djavax.net.ssl.trustStore=…` : épinglez son autorité sur la carte SIEM ([TLS](../integrations/siem.md#tls)), qui ne la reconnaît que pour cette connexion et non pour toutes les connexions TLS sortantes. Le nom du collecteur est vérifié contre son certificat dans tous les cas. |

## Personnalisation

| Variable | Défaut |
|---|---|
| `VECTISPIRE_BRAND_NAME` | `Vectispire` — en-tête, rapports PDF, et exports SARIF / VEX / CSAF |
| `VECTISPIRE_GITLAB_URL` | `https://github.com/asmolabs/vectispire` — l'URL des sources affichée à côté du pied de page « Powered by Vectispire ». Le nom est un reste de l'époque où le projet était hébergé sur GitLab ; le réglage est indépendant de la forge et son défaut n'est pas une URL GitLab. |
| `VECTISPIRE_VEX_AUTHOR` | le nom de marque | L'auteur que déclare un document VEX. |
| `VECTISPIRE_VERSION` | *la version du build lui-même* | La version d'outil que déclarent les documents exportés — SARIF, CSAF, CycloneDX, in-toto. Laissez-la vide : une version autre que celle de l'artefact rend les deux irréconciliables là où un évaluateur les lit. À poser seulement pour une reconstruction livrée sous une version propre. |

`VECTISPIRE_BRANDING_NAME` et `VECTISPIRE_INSTANCE_NAME`, d'anciennes graphies de `VECTISPIRE_BRAND_NAME`,
sont encore lues, dans cet ordre, quand elle n'est pas posée.

## Documentation de l'API

| Variable | Défaut | Notes |
|---|---|---|
| `VECTISPIRE_API_DOCS_ENABLED` | `false` | Sert le document OpenAPI, `/v3/api-docs`. |
| `VECTISPIRE_SWAGGER_UI_ENABLED` | `false` | Sert Swagger UI, `/swagger-ui.html`, qui lit ce document. |
| `VECTISPIRE_ANONYMOUS_API_DOCS` | `false` | Qui peut les lire une fois servis : fermé par défaut, une session ouverte est donc nécessaire. `true` convient à une démonstration publique, ou à un déploiement derrière une passerelle qui authentifie déjà — un catalogue complet des routes est exactement la reconnaissance que ce produit rapporte sur le parc des autres. |

Swagger UI est **désactivé par défaut en production**. Activez-le en développement :

```bash
export VECTISPIRE_SWAGGER_UI_ENABLED=true
export VECTISPIRE_API_DOCS_ENABLED=true
```

Puis `http://localhost:3180/swagger-ui.html`.

## File des analyses {#scan-queue}

| Variable | Défaut | Notes |
|---|---|---|
| `VECTISPIRE_SCAN_RETRY_DELAYS` | `1m,5m,15m` | Combien de temps une analyse attend, après une tentative qui n'a pas pu s'exécuter pour une raison transitoire — le réseau, un délai dépassé, un bail expiré —, avant de pouvoir être réclamée de nouveau : la première valeur après la première tentative, la dernière pour toute tentative au-delà de la liste, dans la limite du nombre de tentatives (trois). Un échec permanent — une clé d'hôte refusée, un dépôt absent — échoue aussitôt et n'attend rien. Des durées telles que Spring les lit (`30s`, `2m`) ; une durée négative empêche l'application de démarrer. |

## Agents distants

| Variable | Notes |
|---|---|
| `VECTISPIRE_URL` | Le plan de contrôle que l'agent interroge. |
| `VECTISPIRE_AGENT_TOKEN` | Une clé d'API avec la portée `agent`, affichée une seule fois à la création. |
| `VECTISPIRE_AGENT_WAIT` | Combien de temps une interrogation attend du travail, `30s` par défaut ; le serveur tient la requête, si bien qu'une analyse en file part dans la seconde. |
| `VECTISPIRE_AGENT_RETRY` | Combien de temps l'agent attend avant d'interroger de nouveau après un échec, `10s`. |
| `VECTISPIRE_AGENT_HEARTBEAT` | La fréquence à laquelle le bail d'une analyse en cours est renouvelé, `60s` — bien en deçà du bail, pour qu'un battement manqué n'expire pas une analyse qui progresse. |
| `VECTISPIRE_IMAGE_SYFT` … `VECTISPIRE_IMAGE_SEMGREP` | Les images des scanners sur cet agent, comme pour le plan de contrôle [plus haut](#scanners). Un agent sur un réseau fermé est là où elles pointent d'ordinaire vers un registre interne. |
| `VECTISPIRE_AGENT_SIGNING_KEY` | La moitié privée de la clé Ed25519 qu'un administrateur a épinglée pour cet agent, en base64. Vide : les résultats sont acceptés sur la seule clé API. L'épingler est ce qui empêche une clé volée de déclarer une cible propre — le résultat vide qui résout tout un backlog. |
| `VECTISPIRE_PLUGIN_REGISTRY` | Le registre interne depuis lequel cet agent tire les images de plugins — hôte relogé, chemin et digest conservés. Vide, chacune est tirée de son propre registre, qu'un agent sur réseau fermé ne peut pas atteindre : le plugin est alors absent du scan et ses issues restent telles quelles. |
| `VECTISPIRE_PLUGIN_SIGNATURE_REQUIRED` | Activé par défaut : cet agent ne lance aucun plugin dont le manifeste ne déclare pas de signataire, sauf dérogation du gouverneur pour ce plugin — la tâche la porte. `false` lance tout plugin non signé sur l'hôte de cet agent. Un signataire déclaré est vérifié avant le pull dans tous les cas. |
| `VECTISPIRE_VULNERABILITY_DB_DIR` | Où cet agent garde la base du rapprocheur de vulnérabilités, téléchargée une fois et partagée en lecture seule par ses analyses — comme pour le plan de contrôle plus haut. Vide : un répertoire du répertoire temporaire. |

Le nombre d'analyses qu'un agent mène en parallèle n'est **pas** l'une de ses variables : il se règle
sur la ligne de l'agent dans le plan de contrôle, de 1 à 16, et l'agent le lit dans chaque réponse à
ses interrogations — voir
[Mener plusieurs analyses en parallèle](../administration/agents.md#running-several-scans-at-once).
`VECTISPIRE_SCAN_MAX_CONCURRENT` est celle du worker intégré, et n'a aucun effet sur un agent distant :
elle compte les analyses que tient le worker de cette instance, jamais celles des agents.

Voir [Agents](../administration/agents.md).
