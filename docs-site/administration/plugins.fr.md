# Plugins et imports SARIF

Un plugin est **votre propre analyseur, empaqueté en image de conteneur**, que Vectispire lance
pendant un scan à côté de Syft, Grype, Gitleaks, Checkov et Semgrep — et qui rapporte ce qu'il a
trouvé en SARIF. Un import SARIF en est l'autre moitié : un rapport qu'un de vos outils internes a déjà
produit — un SonarQube sur site, votre propre CI — déposé dans le backlog d'un dépôt.

Les deux arrivent dans le même backlog, triés une seule fois. La décision
[0017](https://github.com/asmolabs/vectispire/blob/main/docs/architecture/fr/decisions/0017-custom-checks-as-container-images.md)
consigne pourquoi ils fonctionnent ainsi.

!!! danger "À lire d'abord : le code de sortie 0 signifie *analysé*"
    Un plugin qui sort sur l'un de ses codes déclarés et écrit un journal SARIF dont le tableau
    `results` est vide a dit à Vectispire **« j'ai regardé ce dépôt et je n'ai rien trouvé »**. Chaque
    issue ouverte par ce plugin sur le dépôt est alors **résolue** — triage, justifications et tout.
    Si votre analyseur échoue, **sortez sur un autre code, ou n'écrivez pas le rapport, ou écrivez le
    run sans `results`, ou mettez `"executionSuccessful": false`** : chacun de ces cas laisse les
    issues du plugin exactement comme elles étaient et inscrit l'échec sur le scan. N'avalez jamais
    une erreur pour écrire un rapport vide.

## Écrire un plugin

### Le manifeste

```json
{
  "id": "acme-lint",
  "name": "ACME house rules",
  "image": "registry.acme.internal/sec/acme-lint@sha256:4f2d…(64 hex)",
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

| Champ | Ce qu'il signifie |
|---|---|
| `id` | 2 à 40 lettres minuscules, chiffres et tirets intérieurs. **Il fait partie de chaque issue que le plugin ouvre** : il ne peut jamais être renommé ni réutilisé. |
| `name` | Ce que montrent les écrans. |
| `image` | Épinglée **par digest** : `dépôt@sha256:<64 hex>`. Un tag — même à côté du digest — est refusé. |
| `languages` | Les langages que le plugin lit, dans la liste du catalogue Semgrep : `apex`, `bash`, `c`, `clojure`, `csharp`, `dockerfile`, `elixir`, `go`, `html`, `java`, `javascript`, `json`, `kotlin`, `ocaml`, `php`, `python`, `ruby`, `rust`, `scala`, `solidity`, `swift`, `terraform`, `typescript`, `yaml`. |
| `arguments` | La commande passée au point d'entrée de l'image, sous forme de liste — aucun shell n'intervient. `{source}` devient `/repo/source`, `{output}` devient `/repo/output/<output>`. |
| `output` | Le nom du fichier où le plugin écrit son SARIF, dans `/repo/output`. `results.sarif` par défaut. |
| `exit_codes` | Les codes de sortie qui signifient « analysé », constats ou non. `[0]` par défaut. Tout autre code fait échouer l'étape du plugin. |
| `network` | `false` sauf si le plugin doit vraiment atteindre quelque chose — un miroir interne de règles. `true` exige `network_justification`, de 20 à 500 caractères, inscrite au journal d'audit. |
| `timeout_seconds` | 10 à 900. Il peut raccourcir les quinze minutes des scanners, jamais les allonger. |
| `signature` | Facultatif : qui doit avoir signé l'image — voir [Signer l'image](#signer-limage). |

### Ce sous quoi le plugin tourne

Exactement ce sous quoi tourne chaque scanner livré avec Vectispire — aucune option ne permet de
l'assouplir :

- **l'arbre analysé seulement, en lecture seule**, sur `/repo/source` (le sous-chemin du dépôt, s'il
  en a un). Pas le reste de l'espace de travail ;
- **un seul répertoire accessible en écriture, vide**, `/repo/output`, où va le rapport, **qui contient
  au plus 256 Mio et 4 096 fichiers** — en mémoire, jamais sur le disque de la machine qui analyse.
  Écrivez vos journaux sur la sortie standard ou d'erreur à votre guise — le rapport est lu dans le
  fichier. **Un plugin qui remplit le répertoire est absent**, même s'il écrit ensuite un rapport valide :
  une écriture a été refusée, le rapport peut donc manquer de ce qu'il n'a pas pu écrire ;
- **aucun fichier de plus de 256 Mio nulle part**, `/tmp` compris : au-delà, l'écriture échoue (`File
  too large`) ou le processus est arrêté ;
- **pas de réseau** sauf si le manifeste le déclare ; **pas de socket Docker**, aucune capacité,
  `no-new-privileges`, un **système de fichiers racine en lecture seule**, `/tmp` et `$HOME` comme
  petits espaces temporaires `noexec` ;
- **pas root** : l'utilisateur propriétaire de l'espace de travail sur la machine qui analyse. Votre
  image doit fonctionner sous un uid non root arbitraire ;
- les limites des scanners pour la mémoire (2 Go), les processus et le CPU, et votre durée ;
- le rapport est lu comme un fichier ordinaire (un lien est refusé), jusqu'à 256 Mio.

Les bases de règles ou de vulnérabilités ont leur place **dans l'image**, épinglées avec elle. Si le
plugin doit les récupérer, déclarez l'exception réseau et pointez-la vers un miroir interne : rien
n'est téléchargé librement au démarrage.

Essayez-le sous le même confinement avant de l'enregistrer :

```bash
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges \
  --read-only --tmpfs /tmp:rw,noexec,nosuid --user "$(id -u):$(id -g)" \
  --ulimit fsize=268435456 --tmpfs "/repo/output:rw,noexec,nosuid,size=256m,uid=$(id -u),gid=$(id -g)" \
  -v "$PWD:/repo/source:ro" \
  registry.acme.internal/sec/acme-lint@sha256:… --sarif /repo/output/results.sarif /repo/source
```

(Ajoutez `; cat /repo/output/results.sarif` à votre commande, ou lancez-la par un shell, pour voir le
rapport : un tmpfs ne survit pas au conteneur.)

### Signer l'image

Le digest dit **ce qui** tourne ; une signature dit **qui l'a construit**. Déclarez le signataire dans le
manifeste et chaque exécuteur vérifie l'image avec cosign **avant de la tirer** ; une image qui ne se
vérifie pas n'est jamais lancée, et le plugin est **absent** avec la raison donnée par cosign.

- **Sans clé** (Sigstore) : `identity` est l'identité du certificat de signature — pour un workflow
  GitHub Actions, `https://github.com/<owner>/<repo>/.github/workflows/<fichier>@refs/tags/<tag>` — et
  `issuer` son émetteur OIDC (`https://token.actions.githubusercontent.com` pour GitHub Actions). **Les
  deux sont obligatoires et comparés à l'identique** ; il n'y a pas de motif. L'exécuteur doit atteindre
  le registre et la racine de confiance publique de Sigstore.
- **Avec votre propre clé** : `"signature": {"public_key": "-----BEGIN PUBLIC KEY-----\n…"}`, le
  `cosign.pub` de `cosign generate-key-pair`, et signez avec `cosign sign --key cosign.key <image>@<digest>`.
  Le journal de transparence n'est pas consulté : l'exécuteur a besoin de votre registre et de rien de
  Sigstore, et les noms de vos images internes ne sont publiés nulle part.

Vérifiez votre signature comme Vectispire le fera avant d'enregistrer :

```bash
cosign verify --certificate-identity "<identité>" --certificate-oidc-issuer "<émetteur>" <image>@<digest>
cosign verify --key cosign.pub --insecure-ignore-tlog=true <image>@<digest>
```

Changer de signataire est un nouveau manifeste, audité comme tout autre changement. Le vérificateur ne
s'authentifie pas auprès de votre registre : la signature doit être lisible sans identifiants. Un miroir
réglé par `VECTISPIRE_PLUGIN_REGISTRY` doit porter les signatures aussi (`cosign copy` copie les deux).

**Exiger une signature.** Positionnez `VECTISPIRE_PLUGIN_SIGNATURE_REQUIRED=true` sur le plan de contrôle
(pour son worker intégré) et sur chaque agent qui doit refuser du code non signé : un plugin dont le
manifeste ne déclare aucun signataire y est alors absent, et rien de lui n'est démarré. C'est le réglage
propre à chaque exécuteur, parce que c'est cette machine-là qui lance le code.

### Ce que le rapport doit dire

- **SARIF 2.1.0**, un ou plusieurs runs, chacun nommant son outil (`tool.driver.name`).
- **Chaque run porte un tableau `results`** — éventuellement vide. Un run *sans* `results`, ou dont
  l'invocation dit `"executionSuccessful": false`, est lu comme un échec.
- **Chaque résultat nomme sa règle** (`ruleId`, ou une règle vers laquelle il pointe). L'id de règle
  fait partie de l'identité de l'issue : renommer une règle perd le triage qui lui est attaché.
- **Les emplacements sont des chemins dans l'arbre** : relatifs à `/repo/source`, ou absolus sous lui
  (`/repo/source/src/App.java`, `file:///repo/source/src/App.java`). Un emplacement hors de l'arbre,
  un `..` ou une URL fait refuser tout le rapport.
- La sévérité vient de `properties.security-severity` (le score façon CVSS, sur le résultat ou sa
  règle) quand il existe, sinon du niveau : `error` est élevée, `warning` (le défaut) moyenne, `note`
  et `none` basses.
- Un résultat de type `pass` ou `notApplicable`, ou portant une suppression acceptée, n'est pas un
  constat.
- Pas de `externalPropertyFileReferences`, pas de `inlineExternalProperties`.

## Enregistrer un plugin

Seul le **gouverneur de la plateforme** enregistre, met à jour, active ou désactive un plugin : c'est
du code tiers qui lira le source de chaque projet pour lequel il sera activé. Chaque changement est au
journal d'audit avec le digest du manifeste, et transmis au SIEM (`ZAN-SEC-021`).

**À l'écran**, **Plugins** — dans la barre latérale sous Configuration, pour tout compte — liste chaque
plugin avec son état, ses langages, son exception réseau et le début du digest de son manifeste ; l'œil
ouvre son détail : l'image, le digest complet, les arguments dans l'ordre, le fichier du rapport, les
codes de sortie, le réseau et sa justification, le délai, et qui l'a enregistré et modifié en dernier.
Les rôles de gouvernance voient aussi les projets pour lesquels il est activé. Seul le gouverneur a
**Enregistrer un plugin**, le crayon qui modifie le manifeste, et **Activer** / **Désactiver**. Le
formulaire dit, là où l'id se saisit, qu'il ne pourra jamais être renommé ni réutilisé, et le verrouille
en modification ; un refus — id déjà pris, tag à côté du digest, justification trop courte — reste dans
le formulaire avec la raison donnée par le serveur.

Par l'API :

- `POST /api/v1/plugins` avec le manifeste l'enregistre.
- `PUT /api/v1/plugins/{id}` avec un nouveau manifeste le met à jour. **Une nouvelle version d'image
  garde l'id, et garde chaque issue et son triage.** L'id lui-même ne change jamais.
- `PUT /api/v1/plugins/{id}/enabled` avec `{"enabled": false}` l'arrête partout dès le scan suivant,
  sans oublier où il était activé.
- Il n'y a pas de suppression : l'id nomme chaque issue que le plugin a ouverte.

Tout compte connecté peut lire le registre (`GET /api/v1/plugins`).

**Un registre interne.** Positionnez `VECTISPIRE_PLUGIN_REGISTRY` (et la même chose sur chaque agent)
pour tirer chaque image de plugin depuis votre miroir : l'hôte du registre est remplacé, le chemin et
le digest sont conservés, de sorte que le miroir peut servir l'image mais pas en substituer une autre.
Le miroir doit aussi porter `library/busybox`, qui tient le répertoire de sortie de chaque plugin, et —
pour les plugins signés — `sigstore/cosign/cosign`, aux digests qu'épingle Vectispire.

## L'activer pour un projet

Un plugin ne tourne sur rien tant qu'il n'est pas activé pour un
[projet](solutions-and-projects.md) : `PUT /api/v1/projects/{projectId}/plugins/{pluginId}` —
administrateurs, RSSI et gouverneur. Un dépôt rangé dans aucun projet ne lance aucun plugin.
`DELETE` le désactive ; ses issues ouvertes restent telles quelles.

**À l'écran**, dans [Solutions et projets](solutions-and-projects.md), chaque projet propose **Plugins**
aux rôles de gouvernance : chaque plugin enregistré avec ses langages et un interrupteur, allumé pour
ceux qui tournent sur le projet, avec qui l'a activé et quand. Les interrupteurs fonctionnent pour les
administrateurs, le RSSI et le gouverneur ; un auditeur les lit. Un plugin désactivé sur la plateforme
le dit sur sa ligne — son activation est conservée et ne lance rien tant qu'il n'est pas réactivé.

## Ce qu'un scan dit de chaque plugin

Chaque plugin d'un scan finit dans l'un de trois états :

| État | Quand | Ses issues sur le dépôt |
|---|---|---|
| **produit** | Il a tourné et son rapport a été lu. | Ouvertes pour ce qu'il rapporte ; **résolues pour ce qu'il ne rapporte plus** — ses propres issues seulement. |
| **non applicable** | Aucun de ses langages n'est dans le dépôt ; il n'a pas été lancé. | Laissées telles quelles. Pas un échec. |
| **absent** | Il aurait dû tourner et n'a donné aucun rapport exploitable (signature non vérifiée, pull en échec, code de sortie non déclaré, répertoire de sortie plein, pas de rapport, rapport refusé, run en échec). | Laissées telles quelles, et le scan liste l'échec sous `plugin <id>`. |

Le détail du scan liste chaque plugin avec son état (`plugins` : `produced` avec son nombre de
constats, `not_applicable` avec les langages qu'il cherchait, `absent` avec la raison). Sur la page du
scan, la carte **Plugins** montre les trois distinctement, à dessein : **produit** en vert avec le nombre
de constats de son rapport, **non applicable** en gris avec les langages qu'il cherchait, **absent —
échec** en rouge avec la raison. Chacun nomme son plugin, lié au registre, et le digest de son
manifeste. Les constats d'un plugin disent quel outil et quelle version les ont rapportés.

Les langages sont détectés à partir des noms de fichiers et des manifestes (`pom.xml`, `package.json`,
`pyproject.toml`, `go.mod`…), dans une borne ; un dépôt trop grand pour être recensé lance tous les
plugins plutôt que d'en sauter un à tort.

## Comment une issue garde son identité

Une issue de plugin est identifiée par **sa règle, son chemin normalisé et l'outil** —
`plugin:<id>` — sur son dépôt. L'image, son digest et la version de l'outil n'en font **pas** partie,
ce qui permet de mettre un plugin à jour sans perdre le triage. Renommer le plugin, la règle, ou
déplacer le fichier crée une nouvelle issue. Le numéro de ligne n'en fait jamais partie.

Les constats de plugin et importés **ne font pas échouer une barrière CI sauf si sa politique les
inclut** (`include_plugins`, voir les [politiques de barrière](gate-policies.md)) : le « critique »
d'un outil tiers ne doit pas casser un build que personne n'a prévenu. Ils ne comptent pas non plus
dans les indicateurs de sécurité.

## Importer du SARIF d'un outil interne

**Seulement depuis l'intérieur de l'organisation.** Un SonarQube sur site, votre propre job de CI — un
outil qui avait déjà le code. **Jamais un service hébergé hors de l'organisation** à qui le code aurait
été remis. Vectispire ne peut pas savoir, à partir d'un fichier, où il a été produit : la règle est donc
appliquée en *déclarant* chaque source interne, et par ce que la déclaration lie.

### 1. Émettre la clé

Sur [Clés d'API](api-keys.md), émettez une clé portant le scope **`sarif_import`** (jamais accordé par
défaut) depuis un compte qui peut agir — pas un auditeur. Restreignez-la à un dépôt quand la source n'en
alimente qu'un.

### 2. Déclarer la source

Le **gouverneur de la plateforme** la déclare — c'est la plateforme qui affirme « ce producteur est dans
l'organisation » :

```bash
curl -X POST https://vectispire.example/api/v1/sarif-sources \
  -H "Authorization: Bearer $GOVERNOR_SESSION" -H "Content-Type: application/json" \
  -d '{"slug": "payments-ci", "name": "Payments CI", "api_key_id": "<id de la clé>",
       "project_id": 12, "tools": ["Semgrep OSS", "SonarQube"]}'
```

- **une clé, une source** : la clé nomme la source quand elle téléverse ;
- **exactement un périmètre** — un projet (`project_id`) ou un dépôt (`repository_id`), jamais tout le
  parc ;
- **les outils qu'elle peut livrer**, comparés au `tool.driver.name` de chaque run sans tenir compte de
  la casse. Un rapport de tout autre outil est refusé — y compris celui d'un service hébergé, qui se nomme
  lui-même.

Le slug fait partie de l'identité de chaque issue importée : nommez le producteur, pas la clé. Déclarer à
nouveau le même slug avec une nouvelle clé — pour la faire tourner — prolonge le même backlog.

**À l'écran**, **Sources déclarées**, dans la section Administration pour les rôles de gouvernance,
liste les déclarations — identifiant et nom, la portée par nom de projet ou de dépôt, ce que chacune
**livre** (SARIF, couverture, rapports de tests), les outils, la clé, qui l'a déclarée. Le gouverneur a
**Déclarer une source** : les types se cochent (SARIF par défaut, au moins un), la clé se choisit parmi
les clés non expirées portant la portée de chaque type coché — `sarif_import` pour le SARIF,
`report_import` pour les deux autres —, la portée est un projet *ou* un dépôt, et les outils, séparés
par des virgules, ne sont demandés que tant que SARIF est coché.
Désactiver arrête les imports d'une source ; la retirer conserve les issues qu'elle a importées, sous son
identifiant.

### 3. Téléverser

```bash
curl -X POST https://vectispire.example/api/v1/repositories/42/sarif-imports \
  -H "Authorization: Bearer $VECTISPIRE_SARIF_KEY" \
  -H "Content-Type: application/sarif+json" \
  --data-binary @results.sarif
```

La réponse (`201`) dit ce que le rapport a fait : `resultsCount`, `createdCount`, `resolvedCount`,
`reopenedCount`, les outils, et le SHA-256 du document envoyé. Il est refusé avec :

| Statut | Pourquoi |
|---|---|
| `403` | pas une clé d'intégration, une clé pour laquelle aucune source active n'est déclarée, ou un outil pour lequel la source n'est pas déclarée |
| `404` | un dépôt que la clé ne voit pas, ou hors du périmètre de la source — répondu comme s'il n'existait pas |
| `400` | pas du SARIF 2.1.0, un emplacement hors du dépôt ou absolu, un lien vers un contenu externe, un run en échec ou sans `results` |
| `413` | plus grand que `VECTISPIRE_MAX_BODY_SARIF_IMPORT` (32 Mo) |

**Les emplacements doivent être relatifs à la racine du dépôt** (`src/App.java`) : le chemin de copie de
votre CI est inconnu de Vectispire, donc un chemin absolu est refusé. L'outil de chaque run est son
propre périmètre : un rapport ultérieur du même outil résout ce qu'il ne rapporte plus sur ce dépôt, et
ne touche à rien d'autre — ni aux issues d'un autre outil, ni à celles d'un plugin, ni à celles d'un
scanner.

Les issues importées disent d'où elles viennent : type **imported**, la source, le nom et la version de
l'outil. Un auditeur distingue d'un coup d'œil « analysé par Vectispire » (types `plugin`, `sast`…) de
« déclaré par la CI » (`imported`). Chaque import est conservé avec l'empreinte de son document et au
journal d'audit ; un import refusé est un événement SIEM (`ZAN-SEC-023`).

Chaque ligne de [Dépôts](../guide/repositories.md) a **Imports**, qui ouvre la dernière couverture et
le dernier rapport de tests de ce dépôt (voir [plus bas](#importer-des-rapports-de-couverture-et-de-tests))
puis l'historique de ses imports SARIF, en lecture seule : quand et par quelle source et quel compte, les outils, les nombres
d'issues ouvertes, résolues et rouvertes, et le SHA-256 du document. Rien n'est téléversé depuis
l'interface. Dans le backlog, une issue importée dit d'où elle vient sous son type (« déclaré par
payments-ci · SonarQube »), le filtre par type propose **plugin** et **importé**, et la page d'une issue
a une carte **Provenance** avec le plugin ou la source, l'outil et sa version, et la clé d'outil qui
borne sa résolution.

### Exemple : GitLab CI lançant Semgrep

```yaml
sast-to-vectispire:
  image: semgrep/semgrep@sha256:…
  script:
    - semgrep scan --config p/default --sarif --output semgrep.sarif .
    - >
      curl --fail-with-body -X POST
      "$VECTISPIRE_URL/api/v1/repositories/$VECTISPIRE_REPOSITORY_ID/sarif-imports"
      -H "Authorization: Bearer $VECTISPIRE_SARIF_KEY"
      -H "Content-Type: application/sarif+json"
      --data-binary @semgrep.sarif
```

`VECTISPIRE_SARIF_KEY` est une variable de CI masquée et protégée. Déclarez le nom d'outil que porte
votre rapport — regardez `runs[0].tool.driver.name` dans `semgrep.sarif`. Semgrep écrit des chemins
relatifs au répertoire analysé, ce qu'attend Vectispire quand il analyse la racine du dépôt.

### Exemple : SonarQube sur vos sites

SonarQube n'écrit pas de SARIF par lui-même. L'étape qui transforme les issues de votre projet SonarQube
en journal SARIF — un petit job qui lit son API Web (`/api/issues/search`), ou un convertisseur que votre
équipe a validé — est la vôtre ; gardez-la dans l'organisation, comme SonarQube lui-même. Ensuite :

```bash
curl --fail-with-body -X POST \
  "https://vectispire.example/api/v1/repositories/42/sarif-imports" \
  -H "Authorization: Bearer $VECTISPIRE_SARIF_KEY" \
  -H "Content-Type: application/sarif+json" \
  --data-binary @sonarqube.sarif
```

Déclarez la source avec le nom de pilote qu'écrit votre convertisseur (par exemple `SonarQube`), et
vérifiez que les chemins sont relatifs à la racine du dépôt, pas au répertoire de base du projet
SonarQube s'ils diffèrent.

### Ce que la déclaration peut prouver, et ce qu'elle ne peut pas

Elle ne peut pas prouver qu'un fichier ne vient pas d'un SaaS : qui détient une clé déclarée peut
téléverser ce qu'il possède. Ce qu'elle vous donne : **une décision nommée et auditée** du gouverneur de
la plateforme qui lie une clé à un producteur et à un périmètre ; **une liste d'outils autorisés** qui
refuse un rapport de toute autre provenance ; **l'empreinte de chaque document accepté**, pour rapprocher
un rapport de l'exécution de CI qui l'a produit ; et **un événement SIEM à chaque refus**. Qui détient
une clé déclarée relève alors de la discipline de votre organisation, et la piste d'audit la rend
vérifiable.

## Importer des rapports de couverture et de tests

Les mêmes sources déclarées peuvent envoyer **un rapport de couverture** et **un rapport de tests
JUnit** pour un dépôt — les chiffres qu'une checklist de sécurité lira
([décision 0032](https://github.com/asmolabs/vectispire/blob/main/docs/architecture/fr/decisions/0032-security-checklists.md)).
Ils suivent les règles du SARIF ci-dessus, depuis l'intérieur de l'organisation et par une source
déclarée, et en diffèrent sur un point : **ils n'ouvrent ni ne résolvent aucune issue**. Un chiffre de
couverture n'est pas un constat.

### 1. Émettre la clé et déclarer ce que la source livre

Une source déclare ses **types** : `sarif`, `coverage`, `test_report`, un ou plusieurs. Un pipeline est
une source, même quand il envoie du SARIF et de la couverture. Chaque type demande sa portée sur la clé :

| Type | La clé détient | Outils |
|---|---|---|
| `sarif` | `sarif_import` | obligatoires : les outils qu'elle peut livrer |
| `coverage`, `test_report` | `report_import` | aucun — refusés sur une source qui ne livre pas de SARIF |

`report_import` n'est jamais accordée par défaut, et c'est une portée à part pour qu'une clé émise pour
envoyer un chiffre de couverture ne dépose jamais de constats. Une déclaration sans `kinds` est `sarif`
seul, ce que reste toute source déclarée avant cette version.

```bash
curl -X POST https://vectispire.example/api/v1/sarif-sources \
  -H "Authorization: Bearer $GOVERNOR_SESSION" -H "Content-Type: application/json" \
  -d '{"slug": "payments-ci", "name": "Payments CI", "api_key_id": "<id de la clé>",
       "project_id": 12, "kinds": ["coverage", "test_report"]}'
```

### 2. Téléverser

**Couverture** — JaCoCo XML, Cobertura XML ou un fichier lcov. Le format est **déclaré**, jamais
deviné : un fichier JaCoCo tronqué n'est pas lu comme du lcov par accident.

```bash
curl --fail-with-body -X POST \
  "https://vectispire.example/api/v1/repositories/42/coverage-imports?format=jacoco&commit=$CI_COMMIT_SHA&branch=$CI_COMMIT_REF_NAME" \
  -H "Authorization: Bearer $VECTISPIRE_REPORT_KEY" \
  -H "Content-Type: application/xml" \
  --data-binary @target/site/jacoco/jacoco.xml
```

`format` vaut `jacoco`, `cobertura` ou `lcov` (envoyez le lcov en `text/plain`). La réponse (`201`)
porte les lignes couvertes et totales, les branches quand le rapport en a compté (`null` sinon — jamais
0 sur 0), la version de l'outil quand le rapport la nomme, et le SHA-256 du document.

**Rapport de tests** — un document JUnit XML en `application/xml`, ou un zip de plusieurs en
`application/zip`, puisque la plupart des outils de build écrivent un fichier par classe de test :

```bash
(cd target/surefire-reports && zip -q ../surefire-reports.zip TEST-*.xml)
curl --fail-with-body -X POST \
  "https://vectispire.example/api/v1/repositories/42/test-report-imports?commit=$CI_COMMIT_SHA" \
  -H "Authorization: Bearer $VECTISPIRE_REPORT_KEY" \
  -H "Content-Type: application/zip" \
  --data-binary @target/surefire-reports.zip
```

La réponse porte les documents, suites et tests comptés, avec les échecs, erreurs et tests ignorés.
Vectispire garde **les chiffres, jamais le document** : les totaux, ceux de chaque suite, l'empreinte
du document, la source et la clé. `commit` et `branch` sont facultatifs et gardés tels que le pipeline
les énonce — c'est sa parole, vérifiée contre rien.

`scripts/vectispire-cli.sh` fait les deux, et affiche le refus du serveur quand il y en a un :

```bash
./vectispire-cli.sh coverage --repo-id 42 --format jacoco --file target/site/jacoco/jacoco.xml --commit "$CI_COMMIT_SHA"
./vectispire-cli.sh test-report --repo-id 42 --file target/surefire-reports.zip --commit "$CI_COMMIT_SHA"
```

Refusé avec :

| Statut | Pourquoi |
|---|---|
| `403` | pas une clé d'intégration, une clé sans `report_import`, une clé pour laquelle aucune source active n'est déclarée, ou un type pour lequel sa source n'est pas déclarée |
| `404` | un dépôt que la clé ne voit pas, ou hors du périmètre de la source — répondu comme s'il n'existait pas |
| `400` | un format non déclaré ou hors des trois, un corps qui ne se lit pas comme lui, un rapport qui ne compte aucune ligne ou aucun test, un commit qui n'est pas un nom hexadécimal, un zip au-delà de ses garde-fous |
| `413` | plus grand que `VECTISPIRE_MAX_BODY_COVERAGE_IMPORT` (16 Mo) ou `VECTISPIRE_MAX_BODY_TEST_REPORT_IMPORT` (32 Mo) |

**Un rapport vide est refusé**, pas enregistré comme zéro : un rapport de couverture sans aucune ligne,
ou un rapport de tests sans aucun cas, dit que l'étape n'a pas tourné — et « a tourné, n'a rien
trouvé » est une autre affirmation
([décision 0007](https://github.com/asmolabs/vectispire/blob/main/docs/architecture/fr/decisions/0007-none-is-not-an-empty-list.md)).
Les lecteurs ne chargent aucune DTD et ne résolvent aucune entité ; un zip est décompressé en mémoire et
compté à mesure, au plus 5 000 entrées, 32 Mo chacune et 256 Mo en tout, et une archive à l'intérieur
est refusée.

**À l'écran**, la fenêtre **Imports** du dépôt s'ouvre sur sa dernière couverture — lignes et branches
en pourcentage avec leurs nombres, ou *Non comptées par le rapport* quand il n'y avait pas de branches,
le format et la version de l'outil, le commit et la branche tels que le pipeline les a énoncés, quand et
depuis quelle source — et sur son dernier rapport de tests : tests, échecs, erreurs et ignorés. Rien
n'est téléversé depuis l'interface.

Chaque import accepté figure au journal d'audit (`COVERAGE_IMPORTED`, `TEST_REPORT_IMPORTED`) ; un refus
pour ce que la clé prétendait est audité `REPORT_IMPORT_REFUSED` et envoyé au SIEM comme `ZAN-SEC-027`.
Les cinquante derniers imports de chaque type d'un dépôt se lisent à
`GET /api/v1/repositories/{id}/coverage-imports` et `…/test-report-imports`.

## Les analyseurs qui compilent

CodeQL pour Java, SpotBugs et les outils semblables doivent construire le code, ce que l'arbre en
lecture seule et le réseau coupé interdisent. Une copie de l'arbre dédiée et accessible en écriture, et
un réseau limité à votre miroir interne de dépendances, sont conçus (décision 0017) mais pas encore
disponibles. D'ici là, lancez-les dans votre propre CI et importez leur SARIF comme ci-dessus.
