# Plugins de rapport

Un plugin de rapport est **le document propre à votre organisation, rendu par votre propre image de
conteneur** à partir de l'[export](../guide/exports.fr.md#export-de-projet) d'un projet : une checklist dans
la mise en page de tableur de votre fonction sécurité, une synthèse trimestrielle dans le modèle de votre
direction. Vectispire donne l'export à l'image, vérifie le fichier qu'elle écrit et le signe avec la clé de
la plateforme. La décision
[0035](https://github.com/asmolabs/vectispire/blob/main/docs/architecture/fr/decisions/0035-report-plugins.md)
explique pourquoi il fonctionne ainsi.

!!! warning "Cette version exécute un rapport, elle ne vous remet pas encore le document"
    Vous pouvez enregistrer un plugin de rapport, faire approuver son manifeste, l'activer pour un projet, le
    retirer et **demander un rapport** : le plan de contrôle construit l'export du projet, vérifie le
    signataire de l'image et exécute le plugin dans sa forme fermée, et l'exécution enregistre ce qui en est
    sorti — la taille et le SHA-256 de la sortie compris. **Le document lui-même n'est pas encore servi** : sa
    vérification contre son type déclaré, sa signature et son téléchargement viennent dans une version
    ultérieure, et d'ici là ses octets ne sont pas conservés.

## Le manifeste

```json
{
  "id": "quarterly-summary",
  "name": "Quarterly risk summary",
  "image": "registry.example.internal/reports/quarterly-summary@sha256:4f2d…(64 hex)",
  "export_schema": 1,
  "arguments": ["--in", "{input}", "--out", "{output}"],
  "output": "summary.xlsx",
  "media_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  "max_output_bytes": 20971520,
  "timeout_seconds": 120,
  "signature": {
    "identity": "https://ci.example.internal/reports/quarterly-summary/release@refs/tags/v2.1.0",
    "issuer": "https://ci.example.internal/oidc"
  }
}
```

| Champ | Ce qu'il signifie |
|---|---|
| `id` | 2 à 40 lettres minuscules, chiffres et tirets intérieurs. **Jamais renommé ni réutilisé** : les documents qu'il a produits le nomment. |
| `name` | Ce que montrent les écrans, 100 caractères au plus. |
| `image` | Épinglée **par digest** : `repository@sha256:<64 hex>`, sans étiquette. |
| `export_schema` | La version majeure de `vectispire-project-export` que lit le plugin. Une majeure que l'installation ne produit pas est refusée ; `GET /api/v1/schemas/project-export/{major}` sert celles qu'elle produit. |
| `arguments` | La commande remise au point d'entrée de l'image, sous forme de liste — sans shell. `{input}` et `{output}` deviennent les chemins d'entrée et de sortie du conteneur. |
| `output` | L'unique fichier que le plugin écrit dans `/report/output` : un nom nu finissant par l'extension de son type (`.xlsx`, `.docx`, `.pptx`, `.ods`, `.odt`, `.pdf`, `.csv`, `.txt`). |
| `media_type` | L'un des types classeur, document et présentation Office Open XML, `application/vnd.oasis.opendocument.spreadsheet`, `application/vnd.oasis.opendocument.text`, `application/pdf`, `text/csv`, `text/plain`. **Le HTML, les anciens formats Office binaires et les paquets à macros sont refusés.** |
| `max_output_bytes` | Le plafond de la sortie, 50 Mio au plus ; 20 Mio par défaut. |
| `timeout_seconds` | 10 à 300 ; 120 par défaut. |
| `signature` | **Obligatoire, sans dérogation** — sans clé (`identity` et `issuer`, les deux, comparés exactement) ou `public_key`, comme pour les [plugins d'analyse](plugins.fr.md#signer-limage). La plateforme signe ce que le plugin écrit, et ne prête pas sa clé à une image dont personne ne répond. |

Il n'y a **pas de champ `network`** : un plugin de rapport tourne toujours sans réseau. Son entrée est
l'état trié entier d'un projet.

**Le manifeste ne porte aucun secret.** Une image d'un registre privé est tirée — et sa signature
vérifiée — avec la **configuration Docker du plan de contrôle** (`DOCKER_CONFIG`, `~/.docker/config.json`) :
donnez au plan de contrôle des identifiants de lecture pour ce registre, comme un exécuteur en reçoit pour
les plugins d'analyse ([identifiants de registre](../guide/containers.fr.md#identifiants-de-registre)).
Vectispire ne stocke aucun identifiant de registre.

## Enregistrer, approuver, activer

| Geste | Qui | Route |
|---|---|---|
| Enregistrer un plugin | le gouverneur de la plateforme | `POST /api/v1/report-plugins` |
| Lui donner un autre manifeste | le gouverneur de la plateforme | `PUT /api/v1/report-plugins/{id}` |
| Approuver un digest de manifeste | le gouverneur de la plateforme, un administrateur ou un CISO — **pas le compte qui l'a enregistré** tant que les [quatre yeux](four-eyes.fr.md) sont actifs | `POST /api/v1/report-plugins/{id}/manifests/{digest}/approval` |
| L'activer ou le désactiver | le gouverneur de la plateforme | `PUT /api/v1/report-plugins/{id}/enabled` |
| L'activer ou le désactiver pour un projet | le gouverneur de la plateforme, un administrateur ou un CISO | `PUT` / `DELETE /api/v1/projects/{id}/report-plugins/{pluginId}` |
| Retirer un digest de manifeste | le gouverneur de la plateforme, avec une justification | `POST /api/v1/report-plugins/{id}/manifests/{digest}/withdrawal` |

**Quatre yeux actifs**, un manifeste enregistré ou mis à jour est `pending_approval` jusqu'à ce qu'une
autre personne qui écrit la gouvernance approuve **ce digest**. Entre-temps, le manifeste approuvé
précédent du plugin continue de servir ; un plugin qui n'en a aucun ne peut pas être activé pour un projet.
Enregistrer un autre manifeste avant l'approbation de celui en attente met ce dernier de côté
(`superseded`) : il ne peut plus être approuvé. Ramener un plugin à un manifeste approuvé auparavant, et
jamais retiré, prend effet aussitôt — deux personnes ont déjà répondu de ces octets-là.

**Quatre yeux inactifs**, un enregistrement ou une mise à jour prend effet aussitôt, enregistré comme
approuvé avec `approvalFourEyes: false`. Un manifeste resté en attente d'avant la bascule peut alors être
approuvé par quiconque écrit la gouvernance, celui qui l'a enregistré compris.

Chaque manifeste qu'un plugin a eu est gardé, par digest, avec son statut — `pending_approval`, `approved`,
`superseded` ou `withdrawn` —, qui l'a enregistré, qui l'a approuvé et si les quatre yeux s'appliquaient :
les `manifests` de `GET /api/v1/report-plugins/{id}`, le plus récent d'abord. Lire le registre est réservé
aux rôles qui lisent la gouvernance ; les plugins activés pour un projet
(`GET /api/v1/projects/{id}/report-plugins`) sont listés à quiconque voit tout le projet, images comprises —
ceux qui en demanderont les rapports.

## Retirer un manifeste

Une signature ne se défait pas. Quand une image se révèle fautive — un rendu qui perd des lignes, un
signataire compromis —, le gouverneur **retire** son digest, avec une justification de 20 à 500
caractères. Le digest ne tourne plus jamais et ne peut pas être enregistré à nouveau ; s'il était le
manifeste approuvé du plugin, celui-ci n'en a plus jusqu'à l'approbation d'une image corrigée — un nouveau
manifeste. Les documents qu'il a produits restent stockés et seront servis marqués comme retirés, avec la
justification. Il n'y a pas de suppression : un identifiant nomme chaque document que le plugin a produit.

## Demander un rapport

`POST /api/v1/projects/{id}/reports` avec `{"pluginId": "quarterly-summary"}` demande un rapport du projet
par un plugin activé pour lui. La réponse est **202** avec l'exécution, `pending` ; l'exécuteur du plan de
contrôle la prend en quelques secondes. **Les comptes en écriture et les auditeurs** peuvent la demander,
s'ils voient le projet entier, images comprises — tout autre reçoit le 404 d'un projet qui n'existe pas ; le
gouverneur de la plateforme, qui n'agit sur rien de ce que contient un projet, reçoit un 403. Les clés
d'intégration ne peuvent pas demander de rapport : l'export est construit pour une personne.

**Où il s'exécute : sur le plan de contrôle, jamais sur un agent.** Le plugin s'exécute sur le point d'accès
Docker qu'utilise le worker intégré (`VECTISPIRE_DOCKER_HOST` ou `DOCKER_HOST` — le proxy de socket dans la
composition livrée). Une installation dont le worker intégré est coupé (`VECTISPIRE_EMBEDDED_WORKER=false`,
toutes les analyses sur des agents) **ne peut pas exécuter de plugins de rapport dans cette version** : une
demande est refusée, 409 `report-executor-unavailable`, plutôt que mise en file pour personne. L'exécution
sur un agent est un lot ultérieur. Les exécutions mises en file avant la coupure du worker ne restent pas en
attente : celle que rien ne prend en charge pendant dix-sept minutes, alors qu'aucun exécuteur n'exécute ni ne
démarre rien, passe en échec `executor_unavailable`, et celle qui était en cours passe en échec
`executor_lost` quand son bail expire — chaque instance cherche les deux chaque minute.

**Ce que fait la prise en charge**, dans l'ordre :

1. revérifie ce que la demande a vérifié — le plugin toujours activé pour le projet, activé, avec un
   manifeste approuvé — et exécute **le manifeste approuvé à cet instant**, jamais un manifeste en attente
   d'approbation ;
2. relit le demandeur : un compte désactivé, ou qui ne voit plus le projet entier ou n'a plus un rôle qui
   peut demander, n'obtient aucun export ;
3. construit l'[export](../guide/exports.fr.md#export-de-projet) du projet pour le demandeur, à cet instant —
   celui que décrit le document ;
4. vérifie le signataire de l'image avec le cosign épinglé **avant que l'image soit tirée**, avec la
   configuration Docker du plan de contrôle pour un registre privé ; tout ce qui n'est pas un signataire
   vérifié est un refus, et rien n'est démarré ;
5. exécute l'image **sans aucun réseau**, pas en root, toutes les capacités retirées, un système de fichiers
   racine en lecture seule, les plafonds de mémoire, de processus et de CPU des analyseurs ; l'export seul,
   en lecture seule, à `/report/input/export.json` ; un seul répertoire inscriptible, `/report/output`, qui
   ne peut contenir ni plus que le `max_output_bytes` du manifeste ni plus de 16 fichiers ; arrêtée au
   `timeout_seconds` du manifeste ;
6. lit le fichier que nomme le manifeste, comme fichier régulier, dans le plafond. **Code de sortie 0, ou
   l'exécution est en échec.**

Une exécution est dans exactement un état :

| État | Sens |
|---|---|
| `pending` | Demandée, en attente de l'exécuteur. |
| `running` | Prise en charge. Son exécuteur renouvelle son bail tant qu'elle tourne, quelle que soit la durée du pull et de la vérification de la signature. Une exécution dont le bail expire — le plus long délai qu'un manifeste peut déclarer, les deux minutes du vérificateur et dix minutes, dix-sept minutes sans renouvellement — a été laissée par un exécuteur arrêté : elle passe en échec, `executor_lost`, sans nouvelle tentative. Redemandez-la. |
| `produced` | Le plugin est sorti avec 0 et a écrit son fichier dans ses limites. L'export qu'il a reçu est conservé avec l'exécution. |
| `failed` | `exit_code`, `timeout`, `output_full` (le répertoire s'est rempli ou un fichier a dépassé le plafond), `output_missing`, `output_not_regular`, `export_too_large`, `requester_not_allowed`, `plugin_unavailable`, `executor_lost`, `executor_unavailable` (rien ne l'a prise en charge pendant dix-sept minutes alors qu'aucun exécuteur ne travaillait), `executor_error` — avec le détail, les propres mots du plugin pour un code de sortie. |
| `refused` | Pas démarrée : `signature_unverified`, `unsigned`, `registry_authentication_required`, ou `export_schema_unavailable` (le manifeste lit une version majeure d'export que cette installation ne produit plus). La correction porte sur la provenance de l'image ou sa version, pas sur son code. |

**Une exécution d'un plugin par projet à la fois** : une seconde demande pendant qu'une autre est en attente
ou en cours est refusée, 409 `report-run-in-progress` — c'est celle-là qu'il faut attendre. Les exécutions du
projet, de la plus récente à la plus ancienne, sont à `GET /api/v1/projects/{id}/reports`, une seule à
`GET /api/v1/projects/{id}/reports/{runId}`, pour quiconque voit le projet entier : l'état, son motif et son
détail, le manifeste, l'image et le signataire avec lesquels elle s'est exécutée, le SHA-256 et la taille de
l'export, le SHA-256 et la taille de la sortie, les instants de demande, de début, d'export et de fin.

**Combien à la fois** : `VECTISPIRE_REPORT_CONCURRENCY`, deux par défaut, sur chaque instance du plan de
contrôle ; il cherche les exécutions en attente toutes les `VECTISPIRE_REPORT_INTERVAL` (10 s). **Ce qui est
conservé** : l'export qu'a reçu une exécution produite, jusqu'à ce que la [fenêtre des preuves](maintenance.fr.md)
(`evidence_retention_days`) soit passée — ses octets partent alors et l'exécution garde son empreinte ; une
exécution en échec ou refusée ne garde rien qu'elle-même et son motif. Supprimer un projet emporte ses
exécutions et leurs exports.

## Ce qui est enregistré

Chaque geste est écrit au [journal d'audit](audit-log.fr.md) — `REPORT_PLUGIN_REGISTERED`,
`REPORT_PLUGIN_UPDATED`, `REPORT_PLUGIN_APPROVED`, `REPORT_PLUGIN_ENABLED_CHANGED`,
`REPORT_PLUGIN_ACTIVATED`, `REPORT_PLUGIN_DEACTIVATED`, `REPORT_PLUGIN_WITHDRAWN`, chacun nommant le digest du
manifeste — et envoyé au [SIEM](../integrations/siem.fr.md#catalogue-des-evenements) comme `VECTI-SEC-031`. Un
geste qui ne change rien — le même manifeste à nouveau, un plugin déjà activé — n'enregistre rien.

Une exécution de rapport enregistre `REPORT_REQUESTED` quand elle est demandée, `PROJECT_EXPORTED` quand
l'export atteint le conteneur du plugin (envoyé au SIEM comme `VECTI-SEC-032`, le SHA-256 de l'export en
tête), puis `REPORT_PRODUCED` (les empreintes de la sortie, du manifeste et de l'export), `REPORT_FAILED` ou
`REPORT_REFUSED` — chacun au nom du demandeur. **Un refus est envoyé au SIEM comme `VECTI-SEC-033`** : une
image sans signataire vérifié sollicitée pour s'exécuter, c'est ainsi qu'un plugin altéré se trahit. Un
échec pour une raison ordinaire est journalisé, pas signalé.

## Refus

| Réponse | Quand |
|---|---|
| 400 | Un manifeste refusé — le `detail` nomme la première chose qui ne va pas ; un retrait sans sa justification. |
| 403 | Un rôle qui ne peut pas faire ce geste. |
| 404 | Un plugin, ou un digest de celui-ci, qui n'existe pas ; un projet qui n'existe pas ou que vous ne voyez pas en entier (`Project not found.`) ; un rapport demandé à un plugin non activé pour le projet, dans les mêmes mots qu'il existe ou non. |
| 409 `report-plugin-id-taken` | L'identifiant est déjà enregistré. |
| 409 `report-plugin-four-eyes` | Les quatre yeux sont actifs et vous avez enregistré ce digest. |
| 409 `report-plugin-not-pending` | Le digest n'attend pas d'approbation : approuvé, mis de côté ou retiré. |
| 409 `report-plugin-not-approved` | Activer un plugin, ou lui demander un rapport, sans manifeste approuvé. |
| 409 `report-plugin-disabled` | Demander un rapport à un plugin que le gouverneur a désactivé. |
| 409 `report-executor-unavailable` | Demander un rapport là où le worker intégré est coupé : cette version n'exécute les plugins de rapport que sur le plan de contrôle. |
| 409 `report-run-in-progress` | Un rapport de ce plugin pour ce projet est déjà en attente ou en cours. |
| 409 `report-plugin-withdrawn` | Enregistrer à nouveau, ou retirer à nouveau, un digest déjà retiré. |
| 409 `report-plugin-changed` | Un autre geste a modifié le plugin pendant que le vôtre était décidé : relisez-le. |
