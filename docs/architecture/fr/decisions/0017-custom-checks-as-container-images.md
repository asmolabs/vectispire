# 0017 — Les checks propres à une organisation arrivent en images de conteneur émettant du SARIF, et le SARIF n'est importé que de sources internes déclarées

**Date :** 2026-09-27 · **Statut :** accepté · **Décideur :** Laurent Boucher · **§7 amendé par :** [0032](0032-security-checklists.md) (imports de couverture et de rapports de tests)

> **Note (2026-09-28).** Les identifiants de signature SIEM que cette décision nomme `ZAN-SEC-nnn`
> sont émis en `VECTI-SEC-nnn` depuis la 0.10.0 — mêmes numéros, mêmes sens. Le
> texte ci-dessous est laissé tel qu'accepté ; voir le [catalogue SIEM](../../../../docs-site/integrations/siem.fr.md#catalogue-des-evenements).

*Proposée le 2026-08-29 sous le titre « checks personnalisés en images de conteneur, pas en JAR » ;
amendée et acceptée le 2026-09-27, quand les plugins ont été construits. Ce qui a changé depuis la
proposition est listé à la fin. Amendée de nouveau le 2026-09-27 par le §9 (le signataire de l'image,
vérifié avant le pull) et le §10 (ce qu'écrit un plugin est borné), les deux suites que la première
version laissait ouvertes. Amendée le 2026-09-30 par le §9.1 : un signataire est **exigé par défaut**,
un plugin non signé est **refusé** — un quatrième état — et le gouverneur de la plateforme peut lever
l'exigence pour un plugin, par écrit.*

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
  rapporte aucun propriétaire ne lance pas de plugin du tout plutôt que de le lancer en root, et un
  Vectispire qui tourne lui-même en root non plus : son espace de travail appartient à root, donc son
  propriétaire est root. Les images tournent en `1000:1000` ; le conteneur des jobs de la CI non,
  et c'est ainsi que la faille a été trouvée.
- **Seul l'arbre analysé est monté**, en lecture seule, sur `/repo/source` (le sous-chemin du dépôt
  s'il en a un, après que `SourceFiles.within` a prouvé qu'il est dans le clone). **Pas l'espace de
  travail** : sa racine contient le rapport de secrets en clair et le SBOM.
- **Un seul répertoire accessible en écriture**, vide, sur `/repo/output`, **qui ne contient pas plus que
  le plafond de sortie des scanners** (`ScannerLimits.outputBytes`, 256 Mio) et 4 096 fichiers — un
  tmpfs à taille limitée, jamais un répertoire de l'hôte (§10). Le rapport est lu dans
  `/repo/output/<output>`, pas sur la sortie standard, pour que le plugin puisse journaliser librement ;
  il est lu comme un fichier ordinaire, pas à travers un lien, jusqu'au même plafond, vérifié avant que
  son contenu soit lu.
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

Un manifeste peut aussi nommer **qui doit avoir signé l'image** (§9) ; l'exécuteur le vérifie alors
avec cosign avant que l'image soit tirée, et n'en lance jamais une qu'il ne vérifie pas.

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
  "timeout_seconds": 600,
  "signature": {
    "identity": "https://github.com/acme/lint/.github/workflows/release.yml@refs/tags/v4.2.0",
    "issuer": "https://token.actions.githubusercontent.com"
  }
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
| `signature` | Facultatif (§9). Sans clé — `identity` et `issuer`, les deux, comparés à l'identique — ou `public_key`, une clé publique PEM (ECDSA P-256/384/521, Ed25519, RSA d'au moins 2 048 bits). Exactement l'une des deux formes. Absent : l'image n'est reconnue que par son digest, ce qu'un exécuteur peut refuser. |

Le **digest** du manifeste (`PluginManifest.digest`) couvre tous les champs. Mémoire, processus et CPU
sont ceux des scanners et ne se négocient pas plugin par plugin. Le signataire n'est ajouté aux champs
du digest **que lorsqu'il est déclaré**, si bien qu'un manifeste sans signataire se hache exactement
comme avant l'existence du champ (§9).

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
| `refused` *(§9.1, 2026-09-30)* | L'exécuteur ne l'a pas démarré faute de signataire vérifié : `unsigned` ou `signature_unverified`. | Comme absent — laissées telles quelles, un échec de l'analyse — distingué parce que le remède est la provenance de l'image, pas son code. |

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
  l'image, les langages et l'exception réseau, et signalé au SIEM en `ZAN-SEC-021`. De même pour la
  dérogation à l'exigence de signature (§9.1, `PLUGIN_SIGNATURE_WAIVED`,
  `PLUGIN_SIGNATURE_WAIVER_REVOKED`), avec sa justification.
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

### 9. Qui a construit l'image : un signataire déclaré, vérifié avant le pull

Le digest est l'intégrité, pas la provenance. Il dit *ce qui* tourne et rien de qui l'a fabriqué : un
gouverneur qui colle un digest depuis une merge request se porte garant d'octets que personne n'a
examinés, et un registre qui sert le digest sert ce qu'y a poussé quiconque pouvait pousser.

**Ce que déclare le gouverneur.** Le champ facultatif `signature` du manifeste, sous l'une de deux
formes :

- **sans clé** (keyless) — `identity` et `issuer` : le sujet du certificat Fulcio qui a signé l'image (l'URI
  d'un workflow de CI, l'adresse d'un compte de service) et l'émetteur OIDC qui s'en est porté garant.
  **Les deux, et comparés à l'identique.** Le `--certificate-identity-regexp` de cosign n'est pas
  proposé : `.*acme.*` admet `evil-acme.example`, et une erreur d'ancrage n'est pas de celles qu'une
  relecture attrape. L'une des deux moitiés seule admet quiconque l'autre admet ; l'une sans l'autre est
  donc refusée.
- **par clé** — `public_key` : la clé publique PEM avec laquelle l'organisation signe (le `cosign.pub` de
  `cosign generate-key-pair`). La clé est la racine de confiance, donc le journal de transparence n'est
  **pas** consulté (`--insecure-ignore-tlog`) : une organisation qui signe ses images internes avec sa
  propre clé n'a pas à publier leurs noms dans un journal public, et la vérification n'a besoin que du
  registre, rien de Sigstore.

**Déclaré par plugin ; exigé par exécuteur, par défaut.** Un plugin qui déclare un signataire est
vérifié partout où il tourne, quels que soient les réglages de l'exécuteur. Qu'un exécuteur lance ou non
un plugin qui n'en déclare aucun relève de `VECTISPIRE_PLUGIN_SIGNATURE_REQUIRED`
(`vectispire.scanning.plugin-signature-required` sur le worker intégré,
`vectispire.agent.images.plugin-signature-required` sur un agent), **activé par défaut depuis le
2026-09-30** (§9.1) : un plugin non signé est refusé avec la raison et rien n'est démarré, sauf si le
gouverneur a levé l'exigence pour lui. Le réglage appartient à l'exécuteur plutôt qu'à la plateforme
parce que c'est l'hôte de l'exécuteur qui lance le code : l'exploitant d'un agent peut désactiver
l'exigence pour son hôte — tout plugin non signé y tourne alors — sans l'aval du plan de contrôle.
*La première version de cette section la désactivait par défaut et notait que le propriétaire pouvait
l'inverser ; le §9.1 consigne qu'il l'a fait, et pourquoi.*

**Où, et comment.** Les deux exécuteurs lancent des plugins, donc les deux vérifient, et l'agent n'a
besoin de rien de ce que détient le plan de contrôle : le signataire est dans le manifeste qu'il
récupère déjà par id et digest, et le vérificateur est dans `vectispire-common`. Le vérificateur est
**cosign lui-même, lancé comme un scanner** : `ghcr.io/sigstore/cosign/cosign` v3.1.3 — la version du
workflow de release — épinglé par le digest de son index multi-architecture, lancé par
`ContainerRunner` dans la forme fermée (pas root, racine en lecture seule, aucune capacité, les limites
des scanners, supprimé dans un `finally`), relogé vers le registre des plugins comme l'image d'un
plugin. Une implémentation Java a été écartée : une chaîne Fulcio, la preuve d'inclusion d'un journal
de transparence, un client TUF pour la racine de confiance et la disposition des signatures dans le
registre feraient un second cosign à tenir au pas de la façon dont cosign signe, dans le plan de
contrôle et sur chaque agent.

**Le réseau, dit tel quel.** La signature vit dans le registre, donc le vérificateur a le réseau — le
précédent de Grype, pour l'outil épinglé de Vectispire lui-même. Il ne reçoit **aucun fichier de la
cible** : ni arbre, ni espace de travail ; la seule clé publique, montée en lecture seule, quand le
manifeste en déclare une. La vérification sans clé récupère la racine de confiance de Sigstore depuis
son dépôt TUF et vérifie l'inclusion dans le journal hors ligne, depuis le bundle de la signature ; la
vérification par clé n'atteint que le registre — **la forme hors ligne**, pour ce qui est de Sigstore.
Le vérificateur ne reçoit **aucun identifiant de registre** : une image qu'un registre ne sert qu'à un
pull authentifié ne peut pas être vérifiée, et elle est refusée. Un miroir réglé par
`VECTISPIRE_PLUGIN_REGISTRY` doit porter les signatures aussi (`cosign copy` le fait) : la référence
vérifiée est celle qui est tirée.

**Avant le pull, et la vérification est la barrière.** Le vérificateur tourne avant que le conteneur
du plugin soit créé, donc avant que son image soit récupérée : une image que personne n'a vérifiée
n'est même pas sur l'hôte. Toute réponse autre que la sortie 0 de cosign — aucune signature, un autre
signataire, un registre ou une racine de confiance injoignable — rend le plugin **refusé**
(`signature_unverified`, §9.1), avec les mots de cosign comme raison ; un vérificateur incapable de
démarrer n'a rien dit de l'image et laisse le plugin absent. Dans les deux cas l'image ne tourne jamais.
Rien n'est mis en cache : chaque analyse vérifie chaque plugin signé, un aller-retour au registre
chacun, un coût accepté pour qu'une signature révoquée ou repoussée se voie à l'analyse suivante.

**Le digest, et les manifestes conservés.** Le signataire est dans le digest du manifeste — le changer
est un nouveau manifeste, audité comme les autres, et une tâche ne peut pas recevoir une image sous un
signataire que le gouverneur n'a pas nommé. Il n'est ajouté **que lorsqu'il est déclaré** : chaque ligne
que garde `t_plugin_manifest` est indexée par son digest, et une formule qui aurait changé pour tous les
manifestes les aurait laissés se hacher vers rien de ce que leurs tâches nomment — servis à personne,
chaque plugin absent jusqu'à un nouvel enregistrement. La formule sans signataire est épinglée par
valeur (`PluginSignatureTest`) ; V41 n'est pas publiée, mais une base de développement continue de
fonctionner tout de même, et la colonne JSON n'a besoin d'aucune migration. Le résumé d'audit nomme le
signataire : l'identité et l'émetteur, ou l'empreinte de la clé.

**Ce que cela ne prouve pas.** Que le signataire est celui que croit le gouverneur : la déclaration est
la sienne, auditée comme le reste du manifeste. Un signataire dont la CI est compromise signe ce qu'on
lui donne ; l'épinglage par digest dit toujours de quels octets il s'agissait.

### 9.1. Exigée par défaut, refusée visiblement, levée par écrit (2026-09-30)

**La décision.** `VECTISPIRE_PLUGIN_SIGNATURE_REQUIRED` vaut `true` par défaut sur les deux exécuteurs.
Un plugin dont le manifeste ne déclare aucun signataire n'est pas démarré, pas plus que celui dont le
signataire déclaré ne vérifie pas l'image. Les plugins n'existaient pas en 0.9.0 : aucune installation
publiée ne perd un plugin à ce changement ; une version de développement, si, et ses notes de version
le disent sous *Avant la mise à jour*.

**Pourquoi le défaut change.** Désactivée par défaut, l'exigence faisait confiance au seul digest, et le
digest est ce que le gouverneur a collé — depuis une merge request, depuis la page de tags d'un
registre. Un registre, un miroir ou un tag compromis en amont de ce collage fait tourner le code de
quelqu'un d'autre sur le source de chaque projet pour lequel le plugin est activé. La forme fermée
(§1, §10) empêche ce code d'atteindre le réseau, l'espace de travail ou l'hôte ; **elle ne l'empêche pas
de mentir**. Le produit d'un plugin est son rapport, et un rapport peut inventer des constats — du bruit,
ou un leurre vers un « correctif » — ou taire ceux qui existent, ce qui les résout : un SARIF propre est
le seul résultat qui ferme des issues (§4). Sans réseau n'est pas honnête. Ce qui rend un rapport digne
d'être ingéré, c'est de savoir qui a construit l'outil qui l'a écrit, et un défaut qui ne demande rien à
personne est le défaut que personne ne relit.

**Refusé, un quatrième état, jamais confondu avec absent.** `PluginStep.Refused`, `state: "refused"` sur
le fil, avec un `refusal` — `unsigned` (aucun signataire déclaré, un exigé, pas de dérogation) ou
`signature_unverified` (cosign n'a pas vérifié le signataire déclaré) — et la phrase de l'exécuteur. Pour
le backlog, c'est absent : rien n'a été examiné, rien n'est résolu, et c'est un échec de l'analyse sous
`plugin <id>`. Il est distingué parce que le remède diffère — signer l'image ou enregistrer une
dérogation, pas déboguer le plugin — et parce qu'un « non signé » rapporté comme « planté » est la façon
dont une exigence que personne ne voit finit désactivée. Une ligne de checklist mesurée sur un tel
plugin est sans données avec la raison `plugin_unsigned` ou `plugin_signature_unverified` plutôt que
`step_absent` (l'ensemble fermé de la décision 0032 §6, deux de plus). Une étape produite consigne la
base sur laquelle elle a tourné, `signature` : `verified`, `waived`, ou `not_required` — l'exploitant de
son exécuteur a désactivé l'exigence — de sorte qu'un plugin qui a tourné sans signature le dise dans
chaque analyse où il a tourné, pas seulement dans le registre.

**La dérogation.** Le gouverneur de la plateforme — qui peut enregistrer un plugin,
`@RequiresPlatformGovernor` — peut marquer un plugin enregistré « tourne sans signature », avec une
justification de 20 à 500 caractères : `PUT /api/v1/plugins/{id}/unsigned-waiver`, retirée par `DELETE`.
Conservée sur le plugin (V60, `t_plugin.unsigned_waiver`, `unsigned_waived_by`, `unsigned_waived_at`),
montrée sur son détail, auditée (`PLUGIN_SIGNATURE_WAIVED`, `PLUGIN_SIGNATURE_WAIVER_REVOKED`, la
justification dans l'entrée) et signalée en `VECTI-SEC-021` comme tout autre changement de plugin. Le
répartiteur la pose sur la référence de chaque tâche (`PluginRef.runsUnsigned`), de sorte que les deux
exécuteurs décident sur les mêmes faits et qu'aucun ne demande.

- **Elle lève l'obligation de déclarer un signataire, rien d'autre.** Un signataire que déclare le
  manifeste est vérifié tout de même ; celui qui ne vérifie pas est refusé quelle que soit la
  dérogation. Une dérogation ne transforme pas « les mauvaises personnes ont signé ceci » en succès.
- **Sur le plugin, pas dans le manifeste.** Un champ du manifeste ferait de chaque octroi et de chaque
  retrait un nouveau digest — chaque tâche en attente nommant l'ancien — et cacherait une décision sur
  la confiance de la plateforme dans un document sur l'image. La dérogation est un geste à part,
  audité comme tel, et survit à une mise à jour d'image : un nouveau manifeste est lui-même l'acte
  audité du gouverneur, et redemander à chaque digest n'apprendrait à personne qu'à coller deux fois la
  justification.
- **Un agent la respecte.** La première version soutenait qu'un agent ne doit pas croire le plan de
  contrôle sur parole quant à ce qu'il peut exécuter. Il le croit déjà sur *quelle image* il exécute —
  le manifeste, par id et digest. Ce contre quoi une signature protège, c'est un registre ou un tag
  poussé par quelqu'un d'autre, pas le plan de contrôle : un gouverneur capable de lever l'exigence
  pourrait tout aussi bien enregistrer un signataire de son choix. La dérogation a la même autorité que
  le manifeste, et voyage de la même façon.
- **L'interrupteur reste, et n'est pas la voie documentée.** L'exploitant d'un exécuteur peut toujours
  positionner `VECTISPIRE_PLUGIN_SIGNATURE_REQUIRED=false` ; tout plugin non signé y tourne alors,
  consigné `not_required` et justifié nulle part. La dérogation nomme un plugin, dit pourquoi, et reste
  au dossier — c'est pourquoi la documentation y renvoie.

### 10. Ce qu'écrit un plugin est borné

La première version montait en écriture un répertoire de l'espace de travail sur `/repo/output`, et
**un montage de répertoire ne porte aucune taille** : un plugin pouvait remplir le disque de
l'exécuteur aussi longtemps que sa durée le permettait. Le rapport était lu jusqu'au plafond ; rien ne
bornait ce qui était écrit à côté.

Ce qui a été pesé, face au point d'accès Docker que le projet utilise réellement — le proxy de socket,
dont le filtre ouvre `CONTAINERS`, `IMAGES`, `POST` et ferme `VOLUMES` :

| Option | Pourquoi pas, ou pourquoi |
|---|---|
| `HostConfig.Tmpfs` avec `size=` | La borne évidente, et elle ne se relit pas : l'API d'archive répond « Could not find the file » pour un tmpfs de conteneur, qu'il tourne ou soit arrêté (mesuré, Docker 29). |
| Un volume nommé à taille limitée | Il faut l'API `/volumes` que le proxy ferme, et le pilote local ne dimensionne que le tmpfs. |
| `--storage-opt size=` sur la couche inscriptible | overlay2 sur xfs avec `pquota` seulement, et le système de fichiers racine reste de toute façon en lecture seule. |
| Un chien de garde qui interroge le répertoire | Pas une borne : un plugin écrit des gigaoctets entre deux interrogations. |
| **Un volume tmpfs déclaré dans la création, tenu par un gardien** | Construit. |

**Comment.** `ContainerRun.withBoundedOutput` : un volume anonyme du pilote local, `type=tmpfs` avec
`size=` (le plafond) et `nr_inodes=4096`, appartenant à l'`uid:gid` du plugin, mode `0700`, `noexec`,
`nosuid`, `nodev`, déclaré dans `Mounts` à l'intérieur de `POST /containers/create` — aucun appel à
`/volumes`. Un volume tmpfs est vidé quand le dernier conteneur qui l'utilise s'arrête ; un **gardien**
— un busybox épinglé qui ne fait que dormir, dans la même forme fermée — le détient donc ; le plugin
l'atteint par `VolumesFrom` ; une fois le plugin terminé, le rapport est lu depuis le gardien par l'API
d'archive ; puis le gardien est arrêté et imprime le `df` du répertoire, en octets et en inodes, qui est
la mesure même du noyau de « plein » plutôt qu'une supposition tirée de ce qui y reste. Les deux
conteneurs, et le volume avec eux, sont étiquetés et supprimés dans un `finally` ; un gardien qu'un
plantage aurait laissé expire après la durée du plugin plus dix minutes.

**Plein veut dire absent.** Moins d'une page ou aucun inode restant signifie qu'une écriture a été
refusée, ou que la suivante l'aurait été : le plugin est absent — son rapport, aussi bien formé soit-il,
n'est pas cru, puisque ce qu'il n'a pas pu écrire n'y est pas (0007).

**Chaque fichier du plugin est borné aussi.** Le plugin reçoit une limite `fsize` au plafond. Un tmpfs
garde un fichier creux de n'importe quelle taille apparente dans aucune page, et le démon archive la
taille apparente : sans la limite, un `truncate -s 1T` à côté du rapport serait relu comme un téraoctet
de zéros. Elle s'applique à chaque fichier qu'écrit le plugin, son espace temporaire compris : un plugin
ne peut écrire nulle part un fichier plus grand que le plafond. Un processus enfant qui la dépasse est
tué (`SIGXFSZ`, sortie 153, rapportée comme telle) ; le premier processus du conteneur n'est pas tué par
un signal par défaut et reçoit `EFBIG` à la place.

**De la mémoire, pas du disque.** Les pages sont imputées au plafond mémoire du plugin lui-même (2 Gio, à
côté de `/tmp` et `$HOME`) ; le disque de l'hôte n'est pas touché du tout. La campagne conteneurs le
prouve : un plugin qui remplit son répertoire, qui l'inonde de fichiers, qui écrit un téraoctet creux ou
un fichier au-delà de la limite, qui laisse un lien, chacun absent avec sa raison, l'espace de travail
inchangé, rien de laissé derrière — et la même exécution à travers le proxy de socket épinglé avec le
filtre de la composition (`SocketProxyIntegrationTest`).

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
  Pré-télécharger, ou pointer `VECTISPIRE_PLUGIN_REGISTRY` vers un registre que les agents atteignent —
  il doit alors porter `library/busybox` (le gardien de la sortie) et, pour les plugins signés,
  `sigstore/cosign/cosign` et les signatures.
- **Une migration de plus, `V60`, écrite une fois dans `common`** : les trois colonnes nullables de la
  dérogation sur `t_plugin` (§9.1).
- **Un plugin non signé est refusé par défaut** (§9.1) : une organisation qui ne peut pas encore signer
  une image enregistre une dérogation pour elle, ou désactive l'exigence sur un exécuteur.
- **Un plugin signé a besoin du registre depuis l'exécuteur à chaque analyse**, la vérification sans
  clé du dépôt TUF de Sigstore aussi. Un registre qui exige une authentification pour la lecture ne peut
  pas encore être vérifié : le vérificateur ne détient aucun identifiant.
- **Ce qui est abandonné** : l'extension dans le processus ; un plugin voit un arbre et émet des
  constats sur cet arbre, et un contrôle qui a besoin du corpus est une règle sur les données ingérées,
  pas un plugin.
- **Ce qu'écrit un plugin est borné** (§10) : le plafond et 4 096 fichiers dans `/repo/output`, aucun
  fichier plus grand que le plafond nulle part, en mémoire plutôt que sur le disque de l'hôte. Un plugin
  qui a besoin d'écrire plus que le plafond de sortie des scanners ne peut pas tourner ici.
- **Non construit** : des identifiants de registre pour le vérificateur ; une vérification sans clé
  entièrement hors ligne (un fichier de racine de confiance et un bundle de signature livrés avec le
  manifeste) ; la mise en cache d'une vérification d'une analyse à l'autre.

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
| Vérification cosign en phase 3 | Construite (§9) : un signataire déclaré, sans clé ou par clé, vérifié par un cosign épinglé avant le pull ; un exécuteur peut en exiger un. |
| Un exécuteur peut exiger un signataire (désactivé par défaut) | Exigé par défaut (§9.1, 2026-09-30) ; un plugin non signé est refusé, visiblement, sauf dérogation écrite du gouverneur. |
| — | Ce qu'écrit un plugin est borné (§10) : un volume tmpfs tenu par un gardien, `fsize`, `nr_inodes`. |
