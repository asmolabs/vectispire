# 0017 — Les checks propres à une organisation arrivent en images de conteneur émettant du SARIF, et le SARIF n'est importé que de sources internes déclarées

**Date :** 2026-09-27 · **Statut :** accepté · **Décideur :** Laurent Boucher

*Proposée le 2026-08-29 sous le titre « checks personnalisés en images de conteneur, pas en JAR » ;
amendée et acceptée le 2026-09-27, quand les plugins ont été construits. Ce qui a changé depuis la
proposition est listé à la fin.*

## Contexte

La question posée était de savoir si Vectispire devait accepter un JAR téléversé pour qu'une
entreprise ajoute des contrôles propres à son organisation — un paquet interne interdit, une
convention de configuration que personne d'extérieur ne reconnaîtrait, une règle de nommage qui n'a
de sens que face au registre de cette entreprise. Une seconde question est arrivée le 2026-09-25 : une
équipe qui fait déjà tourner un analyseur — un SonarQube sur site, un job de CI qui lance Semgrep ou
CodeQL — veut ses résultats dans le même backlog, triés une seule fois.

**Le besoin est réel.** Le téléversement de jeux de règles Semgrep couvre ce que Semgrep sait
exprimer, et
[`RuleSetService`](../../../../vectispire-java/vectispire-core/src/main/java/com/asmolabs/vectispire/core/rules/RuleSetService.java)
résout déjà la moitié difficile — stocker un artefact au centre et le servir à chaque exécuteur par
empreinte, pour que deux agents ne puissent pas diverger sur ce qui a été cherché. Rien ne couvrait un
contrôle qui doit *exécuter du code*, ni un rapport que l'outil de quelqu'un d'autre a déjà produit.

La question, c'est le véhicule, pas le besoin.

### Pourquoi pas un JAR

**Il n'y a plus de bac à sable dans la JVM.** Le `SecurityManager` a été retiré pour de bon, et ce
projet tourne sur JDK 25. Un JAR chargé dans le processus obtient ce que le processus a : le pool de
connexions, la clé qui chiffre les clés de déploiement et les jetons de tracker, le point d'accès
Docker, le réseau, le système de fichiers. Toutes les contraintes que
[`ContainerRunner`](../../../../vectispire-java/vectispire-common/src/main/java/com/asmolabs/vectispire/common/scanning/ContainerRunner.java)
construit délibérément seraient contournées par n'importe quel plugin. Un produit dont le but est
d'auditer une chaîne d'approvisionnement offrirait l'exécution de code tiers arbitraire dans son propre
plan de contrôle.

**Il casse l'architecture à deux côtés.**
[`ScanRunner`](../../../../vectispire-java/vectispire-common/src/main/java/com/asmolabs/vectispire/common/scanning/ScanRunner.java)
tourne à l'identique dans le worker intégré et sur un agent distant, sans accès à la persistance. Un
JAR devrait être provisionné sur le disque de chaque agent — deux agents qui se relaient sur une même
cible, l'un en version A, l'autre en version B, résolvent et rouvrent le backlog à chaque tour.

**Il fige l'API interne** — `Workspace`, `ContainerRun` et les records de constat deviennent le contrat
de compilation de quelqu'un d'autre — et **il se trompe sur [0007](0007-none-is-not-an-empty-list.md)
en silence** : un plugin qui renvoie `List.of()` depuis une exception avalée déclare la cible corrigée.

### Pourquoi cela ne rouvre pas 0010

[0010](0010-one-scan-runner.md) dit qu'un registre de moteurs d'analyse, chacun avec son modèle
d'arguments et son fichier de règles, la remplacerait. **Ce n'est pas cela.** Aucune interface
`ScannerEngine` ne revient : on ajoute un scanner concret de plus, `PluginScanner`, avec un format de
sortie fixe (SARIF 2.1.0) et un confinement fixe, paramétré par un manifeste que le gouverneur a écrit.
Les arguments d'un manifeste sont la ligne de commande du plugin lui-même, pas un modèle Vectispire par
moteur. 0010 reste inchangée.

## Décision

### 1. Un plugin est un conteneur, lancé exactement comme les scanners livrés avec Vectispire

Un plugin est **une image OCI épinglée par digest plus un manifeste**, exécutée par le
`ContainerRunner` existant, via le même point d'accès Docker (`DOCKER_HOST`, le proxy interne — jamais
un socket monté, jamais un démon propre au plugin), et il écrit **du SARIF 2.1.0 dans un fichier**.

- **La forme fermée, sans exception** : `ContainerRun.of(...)` — `cap_drop: ALL`, `no-new-privileges`,
  système de fichiers racine en lecture seule, espace temporaire tmpfs `noexec`, les plafonds de
  mémoire, de processus et de CPU des scanners, une étiquette, le conteneur supprimé dans un `finally`.
- **Pas root** : il tourne sous l'`uid:gid` du propriétaire de l'espace de travail, la leçon du montage
  de la base Grype — ce que root écrit dans un montage appartient à root sur l'hôte. Un hôte qui ne
  rapporte aucun propriétaire ne lance pas de plugin du tout plutôt que de le lancer en root.
- **Seul l'arbre analysé est monté**, en lecture seule, sur `/repo/source` (le sous-chemin du dépôt
  s'il en a un, après que `SourceFiles.within` a prouvé qu'il est dans le clone). **Pas l'espace de
  travail** : sa racine contient le rapport de secrets en clair et le SBOM.
- **Un seul répertoire accessible en écriture**, vide, créé pour l'exécution, sur `/repo/output` ; le
  rapport est lu dans `/repo/output/<output>`, pas sur la sortie standard, pour que le plugin puisse
  journaliser librement. Il est lu comme un fichier ordinaire, pas à travers un lien, et seulement
  jusqu'au plafond de sortie des scanners (`ScannerLimits.outputBytes`, celui ajouté le 2026-09-26),
  appliqué pendant la lecture.
- **Réseau `none`.** Un plugin qui a besoin du réseau le dit dans son manifeste avec une justification
  écrite (20 à 500 caractères), que le gouverneur enregistre et que le journal d'audit porte — le
  précédent de Grype rendu explicite. Il n'y a pas d'autre moyen de l'ouvrir.
- **Les arguments sont une liste**, passée au point d'entrée de l'image sans aucun shell du côté de
  Vectispire ; `{source}` et `{output}` sont remplacés par les deux chemins du conteneur.
- **Durée bornée** : le manifeste peut demander moins que les quinze minutes des scanners, jamais plus.
- **Il tourne partout où tournent les scanners** : le worker intégré ou un agent distant, par le même
  `ScanRunner` ; un plugin ne voit donc jamais la base de données ni `ENCRYPTION_KEY`.
- **Les bases de règles et de vulnérabilités** sont embarquées dans l'image épinglée, ou atteintes par
  l'exception réseau déclarée vers un miroir interne (le modèle Grype). Jamais un téléchargement libre
  au démarrage : le réseau est coupé sauf déclaration.

La campagne conteneurs lance un busybox épinglé qui rapporte son propre confinement depuis l'intérieur
— pas l'uid 0, pas d'ethernet ni de route, image et arbre en lecture seule, espace temporaire `noexec`,
pas de socket, et `/repo` ne contenant que `source` et `output` (`PluginScannerIntegrationTest`).

### 2. Le manifeste

```json
{
  "id": "acme-lint",
  "name": "ACME house rules",
  "image": "registry.acme.internal/sec/acme-lint@sha256:<64 hex>",
  "languages": ["java", "kotlin"],
  "arguments": ["--sarif", "{output}", "{source}"],
  "output": "results.sarif",
  "exit_codes": [0, 1],
  "network": false,
  "network_justification": null,
  "timeout_seconds": 600
}
```

| Champ | Règle |
|---|---|
| `id` | 2 à 40 lettres minuscules, chiffres, tirets intérieurs. **Entre dans l'empreinte de chaque issue ; jamais renommé, jamais réutilisé** — il n'y a pas de suppression. |
| `name` | 1 à 100 caractères, affichage seulement. |
| `image` | `dépôt@sha256:<64 hex minuscules>`, **sans tag, pas même à côté du digest**. |
| `languages` | Au moins un, parmi les répertoires du catalogue Semgrep (`Language`). |
| `arguments` | Au plus 32 entrées d'au plus 4 096 caractères ; retour à la ligne et tabulation admis (un script `sh -c` dans l'image), tout autre caractère de contrôle refusé. |
| `output` | Un nom de fichier nu dans `/repo/output`, `results.sarif` par défaut. |
| `exit_codes` | Les codes qui signifient « analysé », constats ou non ; `[0]` par défaut. Tout autre code fait échouer l'étape. |
| `network` / `network_justification` | Coupé par défaut ; ouvert seulement avec une justification, et une justification sans lui est refusée. |
| `timeout_seconds` | 10 à 900, ou absent pour la durée des scanners. |

Le **digest** du manifeste (`PluginManifest.digest`) couvre tous les champs. Mémoire, processus et CPU
sont ceux des scanners et ne se négocient pas plugin par plugin.

**Un registre interne** : `vectispire.scanning.plugin-registry` (`VECTISPIRE_PLUGIN_REGISTRY`, et
`vectispire.agent.images.plugin-registry` côté agent) reloge chaque image de plugin — l'hôte du
registre remplacé, le chemin du dépôt et le digest conservés — pour qu'un miroir puisse servir l'image
sans pouvoir en substituer une autre. C'est plus strict que la surcharge des images de scanners, qui
accepte n'importe quelle référence, parce qu'un plugin est du code tiers qui lit chaque fichier qu'on
lui donne.

### 3. Le plan de contrôle fait autorité ; les exécuteurs récupèrent par id et digest

Le dispatcher décide des plugins d'une analyse quand il construit la tâche — les plugins activés pour
le projet du dépôt et non désactivés — et la tâche porte chacun sous la forme `{id, digest}`, comme elle
porte l'empreinte du jeu de règles. L'exécuteur récupère le manifeste par ses deux moitiés (le worker
intégré dans ses propres tables, un agent via `GET /api/v1/agent/plugins/{id}/{digest}`), **recalcule le
digest et refuse un manifeste qui ne correspond pas**. Tous les manifestes qu'un plugin a eus sont
conservés, par digest, et jamais réécrits : une tâche mise en file avant une mise à jour obtient le
manifeste avec lequel elle a été construite. Une ligne modifiée dans la base ne correspond plus à sa
clé et n'est servie à personne.

Un agent plus ancien que les plugins ignore le champ et ne rapporte aucune étape de plugin ; c'est lu
comme absent et ne résout rien, donc la version du contrat d'agent ne bouge pas.

### 4. Les langages, et le troisième état

Un plugin ne tourne que si l'un des langages qu'il déclare est présent dans l'arbre analysé.
`LanguageCensus` en décide : **les noms de fichiers seulement, jamais le contenu** — une copie en
minuscules, un `lastIndexOf`, deux recherches dans une table par fichier, les manifestes (`pom.xml`,
`package.json`, `pyproject.toml`, `go.mod`, `Cargo.toml`…) comptés comme indices — liens ni suivis ni
comptés, `.git` et `node_modules` ignorés. Linéaire dans les noms, sans motif qui puisse revenir en
arrière (l'audit du 2026-09-26), et borné : 200 000 entrées ou soixante secondes, et plus tôt dès que
chaque langage demandé par un plugin a été vu. **Un recensement qui a atteint une borne ne peut pas
prouver l'absence d'un langage, et tous les plugins tournent alors.**

Chaque plugin d'une analyse finit dans exactement un de trois états, portés par
`ScanArtifacts.plugins` sous forme d'un `PluginStep` scellé avec un discriminant sur le fil :

| État | Sens | Ce que fait l'ingestion |
|---|---|---|
| `produced` | Il a tourné, est sorti sur un code déclaré, et son rapport a été lu : chaque run a réussi et porte un tableau `results`. | Ses constats deviennent des issues `plugin` ; **ses propres** issues ouvertes sur la cible qu'il n'a pas rapportées sont résolues — un rapport vide les résout toutes, et rien d'autre. |
| `not_applicable` | Aucun de ses langages n'est dans l'arbre ; il n'a pas été lancé. | Ses issues restent telles quelles. **Pas un échec** : l'analyse dit « non applicable », pas « échoué ». |
| `absent` | Il aurait dû tourner et n'a produit aucun rapport exploitable — définition non obtenue ou ne correspondant pas à son digest, code de sortie non déclaré, pas de rapport, rapport refusé (taille, lien, emplacement hors de l'arbre, mal formé), un run qui dit `executionSuccessful: false`, un run sans `results`, ou aucun run. | Ses issues restent telles quelles, **et la raison est un échec de l'analyse**, sous `plugin <id>`. |

Absent et non applicable laissent le backlog en paix pour la même raison — rien n'a été examiné — et
sont distingués parce qu'un seul des deux est le problème de quelqu'un. Rapporter un plugin Java sur un
dépôt Python comme absent mettrait un échec sur chaque analyse jusqu'à ce que plus personne ne lise les
échecs ; le rapporter vide résoudrait ses issues le jour où le Java part et les rouvrirait, triage
effacé, quand il revient. Un plugin manquant de la liste est absent ; une étape `produced` dont les
constats ne sont pas arrivés est lue comme absente, jamais comme « a tourné, n'a rien trouvé ».

SARIF le dit déjà : un run dont la propriété `results` est absente n'a pas calculé de résultats ; un
tableau vide signifie qu'il n'en a trouvé aucun. `SarifReport` le garde sous forme d'`Optional`.

### 5. Le contrat d'empreinte

Un constat de plugin ou importé est identifié par l'unique formule, avec la **clé d'outil à la place du
paquet** :

```
SHA-256(cible NUL type NUL id de règle NUL clé d'outil NUL chemin normalisé)
```

- **type** : `plugin` pour un plugin que Vectispire a lancé, `imported` pour le rapport d'une source
  déclarée — deux types, pour que la provenance soit la première chose que montrent chaque écran,
  chaque filtre et chaque export.
- **clé d'outil** : `plugin:<id>`, ou `import:<slug de la source>/<nom de l'outil, épuré et en
  minuscules>`. **Ni l'image, ni son digest, ni la version de l'outil** : un plugin passé à une nouvelle
  image garde son id et tout son triage. Renommer le plugin, la source ou l'outil résout et recrée le
  backlog ; la documentation le dit.
- **id de règle** : le `ruleId` SARIF (ou la règle vers laquelle pointe le résultat), entier. Un
  résultat qui ne nomme aucune règle fait refuser le rapport — sans elle, il n'a pas d'identité d'un
  run à l'autre.
- **chemin** : l'emplacement normalisé par `SarifPaths` — `%XX` décodés en UTF-8, barres obliques
  inverses comme séparateurs, `file:` retiré, le `/repo/source` du conteneur retiré, segments vides et
  `.` supprimés, joints par `/`. Un `..`, un autre schéma, un chemin absolu hors de la racine connue ou
  un caractère de contrôle fait refuser le rapport. La ligne n'y entre pas.

La clé d'outil est aussi le **périmètre de résolution** : un rapport propre résout les issues de cet
outil et jamais celles du type ; un plugin revenu vide ne dit donc rien d'un autre plugin, d'un import
ou d'un scanner. Elle est épinglée par valeur dans `ToolFingerprintTest`.

### 6. L'enregistrement revient au gouverneur de la plateforme ; l'activation se fait par projet

- **Enregistrer, mettre à jour, activer et désactiver un plugin exigent `@RequiresPlatformGovernor`**
  (`Role.governsPlatform`, SUPERUSER seul). Décider que du code tiers qui lira le source du parc peut
  exister sur la plateforme est une règle que tous les autres suivent. Chaque changement est audité
  (`PLUGIN_REGISTERED`, `PLUGIN_UPDATED`, `PLUGIN_ENABLED_CHANGED`) avec le digest du manifeste,
  l'image, les langages et l'exception réseau, et signalé au SIEM en `ZAN-SEC-021`.
- **Activer un plugin pour un projet exige `@RequiresSecurityLead`** — les rôles qui
  `canWriteGovernance` et voient tout le parc : la décision qu'est l'activation d'un jeu de règles,
  restreinte à un projet. `PLUGIN_ACTIVATED` / `PLUGIN_DEACTIVATED`, `ZAN-SEC-021` aussi.
- **Rien n'est global.** Un dépôt rangé dans aucun projet (décision 0023) ne lance aucun plugin ; un
  plugin désactivé garde ses activations et n'en lance aucune ; supprimer un projet emporte ses
  activations (`ProjectDeleted`, publié par `targets` dans la transaction de suppression).
- **Pas de suppression** : un id nomme chaque issue ouverte par le plugin, et un autre code enregistré
  sous cet id hériterait de leur triage.
- Lire le registre est ouvert à tout compte connecté — une image, des arguments et des langages ne
  nomment aucune cible ; les projets qu'un plugin lit sont réservés aux rôles de gouvernance.

**La barrière** : les constats de plugin et importés sont `GateParticipation.ON_REQUEST`, comme la revue
IA — le « critique » d'un outil tiers ne doit pas faire échouer un build que personne n'a prévenu — sur
leur propre drapeau de politique, `include_plugins`, qu'une politique enregistrée ou un appelant peut
activer. Le drapeau de revue IA n'admet que les constats IA. Ils restent hors des indicateurs de
sécurité, de l'estimation d'effort et du total de remédiation, pour la même raison.

### 7. Du SARIF de sources internes seulement

La politique décidée le 2026-09-25 : **externe veut dire hors de l'organisation.** Les résultats d'un
service hors de l'organisation, à qui le code aurait été remis — SonarCloud hébergé, CodeQL hébergé, un
scanner SaaS — ne sont pas importés. Le SARIF produit par un outil interne qui a déjà le code — un
SonarQube sur site, la CI de l'équipe — l'est.

**Une source est déclarée**, par le gouverneur de la plateforme (c'est la plateforme qui dit « ce
producteur est dans l'organisation ») : un slug, une clé d'API d'intégration portant le scope
`sarif_import` (jamais accordé par défaut), **exactement un périmètre — un projet ou un dépôt, jamais
tout le parc** — et les noms d'outils qu'elle peut livrer. Une clé, une source : la clé nomme la
source. `SARIF_SOURCE_CHANGED`, `ZAN-SEC-022`.

**Un import** (`POST /api/v1/repositories/{id}/sarif-imports`, `@AcceptsApiKey(SARIF_IMPORT)`,
`@RequiresWriteAccount`) n'est accepté que si :

1. il vient avec une clé d'intégration — une session n'est pas une source (403) ;
2. la clé est déclarée pour une source active — sinon 403, audité `SARIF_IMPORT_REFUSED` et signalé
   `ZAN-SEC-023` ;
3. le dépôt est visible par la clé (la visibilité de son compte intersectée avec la restriction propre
   de la clé, décision 0024) **et** dans le périmètre de la source — sinon 404, dans les termes d'un
   dépôt qui n'existe pas (le cas hors périmètre est audité et signalé aussi) ;
4. le corps tient dans `vectispire.http.max-body.sarif-import` (32 Mo, `RequestBodyLimitFilter`, 413),
   et se lit sous les gardes de `SarifReport` — imbrication 64, chaînes de 1 Mo, 20 runs, 100 000
   résultats, clés dupliquées et contenu après la fin refusés, `externalPropertyFileReferences` et
   `inlineExternalProperties` refusés, **tout emplacement relatif** (la copie de travail du producteur
   est inconnue ici, donc un chemin absolu est hors de l'arbre) (400) ;
5. chaque run a réussi, porte `results`, et a été produit par un outil que la source déclare — un run
   en échec ou sans résultats est refusé (400) plutôt que lu comme propre ; un outil non déclaré donne
   403, audité et signalé.

Ensuite, les mêmes règles qu'un plugin : l'outil de chaque run est son propre périmètre et sa propre
clé d'empreinte ; le rapport résout ce que cet outil ne rapporte plus sur ce dépôt, et rien d'autre.
Les issues importées portent leur provenance — type `imported`, `tool` (la clé), `toolName` et
`toolVersion` issus de `tool.driver`, et `importSource`, le slug de la source déclarée, conservé après
la suppression de la source. L'import lui-même est une ligne (`t_sarif_import` : source, clé, dépôt,
outils, SHA-256 du document, compteurs) et une entrée d'audit `SARIF_IMPORTED` : la preuve datée d'une
issue importée, là où une issue analysée a son analyse.

**Les limites, honnêtement.** Rien dans un fichier SARIF ne prouve où il a été fabriqué ; la clé d'une
source déclarée peut téléverser ce que son détenteur possède. Ce qui rend la politique *suffisamment*
applicable :

- la déclaration est un acte nommé et audité de l'unique rôle qui fixe les règles de la plateforme, et
  lie une clé à un producteur et à un périmètre — un import est attribuable à une clé et à une personne ;
- la liste d'outils autorisés par source attrape une CI qui se met à déposer la sortie d'un autre outil
  — y compris celle d'un service hébergé, qui se nomme lui-même (`SonarCloud` n'est pas `SonarQube`) ;
- l'empreinte de chaque document accepté est enregistrée, pour rapprocher un rapport de l'exécution de
  CI qui l'a produit ;
- un import refusé est un événement SIEM : une clé utilisée pour autre chose que ce pour quoi elle a été
  déclarée se voit.

**Une liste noire de noms de pilotes SaaS a été envisagée et écartée.** Ce serait du théâtre dans un
sens — un pilote renommé passe — et faux dans l'autre : CodeQL CLI lancé dans la CI de l'organisation
et CodeQL hébergé par GitHub disent tous deux `CodeQL`. La liste autorisée par source est le même
contrôle tourné dans le bon sens : elle nomme ce que ce producteur est censé envoyer. Ce qui reste est la
discipline de l'organisation sur qui détient une clé déclarée, que la piste d'audit rend vérifiable au
lieu d'invisible.

### 8. Les analyseurs qui compilent — conçus, pas construits

CodeQL pour Java, SpotBugs et leurs semblables doivent construire le code, ce que la forme fermée
interdit : l'arbre est en lecture seule et le réseau coupé. La conception, consignée pour la suite :

- **un volume de travail dédié, accessible en écriture et jetable**, copie de l'arbre (jamais l'arbre
  lui-même, jamais l'espace de travail), monté sur `/repo/work` et supprimé avec l'espace de travail —
  le source reste en lecture seule ;
- **un réseau limité à un miroir interne de dépendances déclaré par plugin** (Nexus, Artifactory) : le
  manifeste nomme l'hôte du miroir, la justification dit pourquoi, et le conteneur rejoint un réseau dont
  la seule route est ce miroir (un proxy de sortie à liste autorisée, ou un réseau Docker sans route par
  défaut) — jamais le réseau ouvert ;
- les mêmes plafonds, avec une durée plus longue seulement comme champ de manifeste explicite et audité.

Pas construit maintenant : il faut un réseau Docker par miroir et un proxy de sortie qui n'existent pas
encore, et une version à moitié faite ouvrirait le réseau plus largement que le manifeste ne le dit.
**Le seul point d'accroche qui existe** est l'exception réseau déclarée, qu'un tel plugin peut utiliser
dès aujourd'hui — avec tout le réseau, et c'est exactement pour cela que la justification est exigée et
auditée.

## Conséquences

- Une migration, `V41`, écrite une fois dans `common` : `t_plugin`, `t_plugin_manifest`,
  `t_plugin_activation`, `t_sarif_source`, `t_sarif_import`, des colonnes de provenance sur `t_issue` et
  `t_finding`, le sort de chaque plugin sur `t_scan` (`plugin_steps` — le seul endroit où un plugin non
  applicable est consigné, puisque ce n'est l'échec de personne), `include_plugins` sur `t_gate_policy`. Pas de clé étrangère : les écouteurs du module
  `plugins` purgent ses lignes sur `TargetDeleted` et `ProjectDeleted`.
- Un nouveau module, `core.plugins`, qui utilise `access`, `access::security`, `issues`, `scanning` et
  `targets` ; `scanning` déclare le port `ScanPlugins` qu'il implémente. La route des agents vit dans
  `agents`, par ce port.
- **Un agent sur un réseau fermé échoue au pull**, ce qui laisse le plugin absent et son backlog intact.
  Pré-télécharger, ou pointer `VECTISPIRE_PLUGIN_REGISTRY` vers un registre que les agents atteignent.
- **Ce qui est abandonné** : l'extension dans le processus ; un plugin voit un arbre et émet des
  constats sur cet arbre, et un contrôle qui a besoin du corpus est une règle sur les données ingérées,
  pas un plugin.
- **Non borné** : le disque dans lequel le plugin écrit sous `/repo/output` — un montage de répertoire ne
  peut pas porter de limite de taille. Le rapport est lu jusqu'au plafond, le conteneur jusqu'à sa
  durée ; un volume à taille limitée est une suite à donner. La vérification cosign de l'image avant le
  pull aussi.

## Ce qui a changé depuis la proposition du 2026-08-29

| Proposé | Décidé |
|---|---|
| SARIF sur la sortie standard | SARIF dans un fichier sous `/repo/output` : le plugin peut journaliser, et le rapport est lu avec les gardes des fichiers. |
| Enregistrement par un administrateur, une liste de registres autorisés | Enregistrement par le gouverneur de la plateforme ; images relogées vers un registre interne, digest conservé. |
| Un type de constat `CUSTOM` | `PLUGIN` et `IMPORTED`, pour que la provenance se voie au type ; tous deux sur demande, par `include_plugins`. |
| Empreinte `id du check + ruleId + fichier` | L'unique formule avec la clé d'outil à la place du paquet, la clé étant `plugin:<id>` ou `import:<source>/<outil>`. |
| Contrôles globaux d'abord, par cible ensuite | Activation par projet dès le départ ; rien de global. |
| Aucun modèle de langages | Langages déclarés, recensement borné, et un troisième état : non applicable. |
| — | Import de SARIF depuis des sources internes déclarées. |
| Vérification cosign en phase 3 | Toujours une suite à donner. |
