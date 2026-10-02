# Exemples CI

Trois pipelines commentés, chacun avec la clé dont il a besoin et rien de plus :

1. [**GitLab CI**](#gitlab-ci) — analyser un dépôt, attendre le résultat, faire échouer le pipeline
   sur le verdict de la barrière avec le modèle livré, et envoyer la couverture JaCoCo et les
   résultats JUnit ;
2. [**Jenkins**](#jenkins) — la même chose dans un pipeline déclaratif, le verdict comme résultat de
   l'étape ;
3. [**SonarQube**](#sonarqube) — exporter les issues de SonarQube en SARIF et les importer par une
   source déclarée, pour qu'une règle de checklist portant sur `import:quality-server/SonarQube`
   les mesure.

Ce que la barrière décide et comment sa politique est stockée se lit sur [Barrière CI](ci-gate.md) ;
cette page dit comment la brancher. **Remplacez chaque `<…>` avant de lancer quoi que ce soit** :
c'est une valeur que vous seul connaissez, et une commande qui en garde un échoue au lieu de deviner.

## Trois clés, pas une {#three-keys}

Les clés s'émettent sur [Clés d'API](../administration/api-keys.md). Une clé par job, parce que
chaque job fait une chose et qu'une clé qui fuit ne doit livrer que cette chose-là :

| Clé | Portées | Limitée à | Déclarée comme source | Utilisée par |
|---|---|---|---|---|
| **Barrière CI** | `scan`, `read` | le dépôt que le pipeline construit | non | le scan et la barrière |
| **Rapports** | `report_import` | le dépôt | oui, livrant `coverage` et `test_report` | l'envoi de la couverture et du JUnit |
| **SonarQube** | `sarif_import` | le dépôt — ou aucune, quand la source couvre un projet de plusieurs dépôts | oui, livrant `sarif` de l'outil `SonarQube` | l'envoi du SARIF |

**Pourquoi `read` sur la clé de barrière.** Déclencher un scan et demander un verdict demandent
`scan` ; attendre le scan lit `GET /api/v1/scans/{id}`, qui est une route `read`. Sans `read`,
l'attente est refusée par un `403` — *This API key lacks the read scope.* Un pipeline qui ne fait
que demander un verdict sur un scan lancé par la planification n'a besoin que de `scan`.

**Pourquoi limitée.** Un pipeline de demande de fusion exécute la définition de job de la branche
poussée : quiconque peut pousser une branche peut modifier le job pour afficher la variable. Le
masquage cache un secret du journal, pas d'un job modifié. Une clé limitée à un dépôt qui fuit met
en file et lit les scans de ce dépôt ; une clé sans restriction agit avec tout ce que son compte
voit, sur tout le parc. Une restriction rétrécit la visibilité du compte, elle ne l'élargit jamais,
et supprimer le dépôt révoque les clés qui lui sont limitées.

**Qui émet la clé de barrière.** Une clé agit pour le compte qui l'a émise et ne fait jamais plus
que ce compte : déclencher un scan est un acte d'administrateur, et un verdict est *consigné*, donc
le compte doit être de ceux qui écrivent — la clé d'un auditeur ou d'un gouverneur de la plateforme
est refusée par la barrière. Chaque scan déclenché par la clé est dans le
[journal d'audit](../administration/audit-log.md) sous la forme `alice (API key ci-payments)`.

**Pourquoi des clés distinctes pour les rapports et le SARIF.** Une clé est une source déclarée, et
une clé qui dépose un chiffre de couverture ne doit pas pouvoir déposer de constats, qui ouvrent et
résolvent des issues (voir
[Importer des rapports de couverture et de tests](../administration/plugins.md#importer-des-rapports-de-couverture-et-de-tests)).

## Déclencher un scan et l'attendre {#scan-and-wait}

Aucun des scripts livrés ne met de scan en file :
[`ci/vectispire-gate.sh`](https://github.com/asmolabs/vectispire/blob/main/ci/vectispire-gate.sh)
demande un verdict sur le backlog *tel qu'il est*. Barrer sans analyser d'abord répond sur le
dernier scan, quel qu'en soit l'âge. Les deux exemples ci-dessous versionnent ce script dans le
dépôt sous `ci/vectispire-scan.sh` ; il demande `curl` et `jq`. Il est identique à la version
anglaise de cette page, messages compris, pour que les tableaux de refus s'appliquent aux deux.

```sh
#!/bin/sh
# Queue a Vectispire scan of one repository and wait until it has finished.
#   exit 0 — the scan completed: a verdict asked now describes it
#   exit 2 — no verdict can be trusted: the scan was refused, failed, or is still running
set -eu

: "${VECTISPIRE_URL:?set VECTISPIRE_URL to the control plane}"
: "${VECTISPIRE_TOKEN:?set VECTISPIRE_TOKEN to the CI key (scopes scan and read)}"
: "${VECTISPIRE_REPOSITORY_ID:?set VECTISPIRE_REPOSITORY_ID to the repository id}"

api="${VECTISPIRE_URL%/}/api/v1"
auth="Authorization: Bearer $VECTISPIRE_TOKEN"
timeout="${VECTISPIRE_SCAN_TIMEOUT:-1800}"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# A GET that shows the server's refusal: `curl -f` would print the status and drop the
# problem document, whose `detail` names the missing scope.
get() {
    code=$(curl -sS -o "$2" -w '%{http_code}' -H "$auth" "$1") || code=000
    if [ "$code" != 200 ]; then
        echo "vectispire: GET $1 answered HTTP $code" >&2
        if [ -s "$2" ]; then cat "$2" >&2; echo >&2; fi
        exit 2
    fi
}

status=$(curl -sS -o "$work/queued.json" -w '%{http_code}' -X POST \
    -H "$auth" -H 'Content-Type: application/json' --data '{}' \
    "$api/repositories/$VECTISPIRE_REPOSITORY_ID/scan") || status=000

case "$status" in
    200)
        scan_id=$(jq -r '.id' "$work/queued.json") ;;
    409)
        # A scan of this repository is already waiting: wait for that one rather than fail.
        get "$api/scans?repo_id=$VECTISPIRE_REPOSITORY_ID&limit=1" "$work/latest.json"
        scan_id=$(jq -r '.[0].id' "$work/latest.json") ;;
    *)
        echo "vectispire: the scan was refused (HTTP $status)" >&2
        if [ -s "$work/queued.json" ]; then cat "$work/queued.json" >&2; echo >&2; fi
        exit 2 ;;
esac

echo "vectispire: waiting for scan $scan_id"
deadline=$(( $(date +%s) + timeout ))
while :; do
    get "$api/scans/$scan_id" "$work/scan.json"
    state=$(jq -r '.scan.status' "$work/scan.json")
    case "$state" in
        completed)
            echo "vectispire: scan $scan_id completed"
            exit 0 ;;
        failed)
            echo "vectispire: scan $scan_id failed: $(jq -r '.scan.error // "no detail"' "$work/scan.json")" >&2
            exit 2 ;;
    esac
    if [ "$(date +%s)" -ge "$deadline" ]; then
        echo "vectispire: scan $scan_id is still $state after ${timeout}s" >&2
        exit 2
    fi
    sleep 10
done
```

Ses codes de sortie suivent ceux du script de barrière : `2` veut dire « impossible de décider »,
jamais « passé ». Un scan passe par `pending`, `scanning`, puis `completed` ou `failed` ; un scan
échoué n'est pas une base de verdict, puisque le verdict décrirait le scan d'avant.

!!! warning "Le scan lit la branche configurée sur le dépôt, pas le commit du pipeline"
    Vectispire clone lui-même le dépôt, à la branche réglée sur [Dépôts](../guide/repositories.md),
    quand un exécuteur prend le scan. Dans le pipeline d'une branche de fonctionnalité, le verdict
    décrit toujours la branche configurée. Les deux exemples n'analysent et ne barrent donc que sur
    la branche que Vectispire analyse.

La [CLI du dépôt](https://github.com/asmolabs/vectispire/blob/main/scripts/vectispire-cli.sh) fait
de même avec `scan --repo-id <id> --wait`, en lisant la clé dans `VECTISPIRE_API_KEY` : elle adopte
le scan déjà en attente sur un `409`, affiche le `detail` du serveur sur un refus et sort avec les
mêmes trois codes. C’est vrai depuis la 0.10.0 ; la CLI taguée `v0.9.0` appelait
`curl -f`, sortait avec le code `22` de curl sur chaque refus et n'affichait rien de la réponse. À
partir de la version qui suit la 0.10.0, c'est un asset de version, `vectispire-cli.sh`, avec un
paquet Sigstore vérifié comme celui du script de barrière — téléchargez-la depuis la version,
comparez son SHA-256 à celui qu'affichent les notes de version, puis exécutez-la ;
[Intégration CI/CD](https://github.com/asmolabs/vectispire/blob/main/docs/fr/CI_CD_INTEGRATION.fr.md#-obtenir-la-cli)
donne les commandes.

## 1. GitLab CI {#gitlab-ci}

### Clés et variables

Dans **Settings → CI/CD → Variables** :

| Variable | Valeur | Options |
|---|---|---|
| `VECTISPIRE_URL` | `https://<vectispire-host>` | — |
| `VECTISPIRE_TOKEN` | la clé **Barrière CI** (`scan`, `read`, limitée au dépôt) | **Masked** ; **Protected** quand seules les branches protégées barrent |
| `VECTISPIRE_REPORT_KEY` | la clé **Rapports** (`report_import`, source déclarée) | **Masked** ; Protected de même |

Une variable protégée n'est pas donnée aux pipelines des branches non protégées : les scripts s'y
arrêtent sur *set VECTISPIRE_TOKEN…* au lieu d'envoyer une requête. C'est l'échange voulu — la clé
est hors de portée de qui peut pousser une branche.

La clé des rapports est déclarée une fois par le gouverneur de la plateforme, sur
**Administration → Sources déclarées** (types `coverage` et `test_report`, portée le dépôt ou son
projet) ; voir
[Importer des rapports de couverture et de tests](../administration/plugins.md#importer-des-rapports-de-couverture-et-de-tests).

### `.gitlab-ci.yml`

```yaml
include:
  # Épinglé : un modèle lu depuis une branche mouvante change votre pipeline sans commit de votre part.
  - remote: 'https://raw.githubusercontent.com/asmolabs/vectispire/<tag>/ci/gitlab/vectispire-gate.gitlab-ci.yml'

stages: [test, vectispire]

variables:
  # L'identifiant du dépôt dans Vectispire, lu par les trois jobs ci-dessous.
  VECTISPIRE_REPOSITORY_ID: "<repository-id>"
  # Le tag de l'include ci-dessus : le modèle télécharge le script de barrière de cette version.
  VECTISPIRE_GATE_VERSION: "<tag>"

# Votre propre job de tests ; ce qui compte est qu'il garde les deux rapports en artefacts.
unit-tests:
  stage: test
  image: maven:3.9-eclipse-temurin-21
  script:
    - mvn -B verify          # avec le goal `report` de jacoco-maven-plugin lié au build
  artifacts:
    paths:
      - target/site/jacoco/jacoco.xml
      - target/surefire-reports/

vectispire-reports:
  stage: vectispire
  image: alpine:3.22
  needs: [unit-tests]
  before_script:
    - apk add --no-cache curl zip
  script:
    - |
      set -eu
      api="${VECTISPIRE_URL%/}/api/v1/repositories/$VECTISPIRE_REPOSITORY_ID"
      curl --fail-with-body -sS -X POST "$api/coverage-imports" \
        --url-query "format=jacoco" \
        --url-query "commit=$CI_COMMIT_SHA" --url-query "branch=$CI_COMMIT_REF_NAME" \
        -H "Authorization: Bearer $VECTISPIRE_REPORT_KEY" -H "Content-Type: application/xml" \
        --data-binary @target/site/jacoco/jacoco.xml
      (cd target/surefire-reports && zip -q ../surefire-reports.zip TEST-*.xml)
      curl --fail-with-body -sS -X POST "$api/test-report-imports" \
        --url-query "commit=$CI_COMMIT_SHA" --url-query "branch=$CI_COMMIT_REF_NAME" \
        -H "Authorization: Bearer $VECTISPIRE_REPORT_KEY" -H "Content-Type: application/zip" \
        --data-binary @target/surefire-reports.zip

vectispire-scan:
  stage: vectispire
  image: alpine:3.22
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH   # la branche que Vectispire analyse
  before_script:
    - apk add --no-cache curl jq
  script:
    - sh ci/vectispire-scan.sh

vectispire-gate:
  extends: .vectispire-gate
  stage: vectispire
  needs: [vectispire-scan]
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

`<tag>` est la 0.10.0 ou une version ultérieure. Le modèle tagué `v0.9.0` ne peut pas être inclus tel
quel : il lance `ci/vectispire-gate.sh` depuis votre checkout, où ce fichier n'existe pas, livre
`allow_failure: true`, et déclare `VECTISPIRE_REPOSITORY_ID: ""` sur son job, ce qui masque une
valeur globale.

À quoi sert chaque pièce :

- **`--url-query`** (curl 7.87 ou plus récent ; `alpine:3.22` l'a) encode la branche, qui peut
  porter des caractères qu'une chaîne de requête ne peut pas. `commit` doit être un nom de commit
  hexadécimal ; les deux sont gardés tels que le pipeline les déclare, vérifiés contre rien.
- **Le rapport de tests est zippé** parce que Surefire écrit un fichier par classe de test ; un
  seul fichier JUnit XML s'envoie en `application/xml`. Avec Gradle, les fichiers sont
  `build/reports/jacoco/test/jacocoTestReport.xml` et `build/test-results/test/TEST-*.xml`.
- **Le job de barrière** télécharge le `vectispire-gate.sh` de la version, compare son SHA-256 à
  l'empreinte que porte le modèle, et ne le lance que si elles concordent : un script qui n'est pas
  celui publié à côté du modèle arrête le job, de même qu'un `VECTISPIRE_GATE_VERSION` nommant une
  autre version dont le script diffère. Le script sort ensuite en `0` quand la barrière est passée,
  `1` quand elle a échoué et `2` quand elle n'a pas pu être interrogée ; `1` et `2` font échouer le
  pipeline.
- **Consultatif, sciemment.** `VECTISPIRE_GATE_MODE: advisory` change un verdict rouge en sortie
  `3`, que l'`allow_failure` du modèle accepte : le job s'affiche en avertissement, le pipeline
  passe, et le verdict est consigné quand même. `VECTISPIRE_ON_ERROR: warn` fait de même pour un plan
  de contrôle injoignable, en laissant passer le build non barré. Les deux bloquent par défaut.
- **Gardez une copie plutôt qu'`include: remote`** si votre GitLab ne joint pas GitHub : versionnez
  le modèle dans votre projet, utilisez `include: local`, et pointez `VECTISPIRE_GATE_SCRIPT_URL` sur
  une copie du `vectispire-gate.sh` de la version, sur un serveur que vous joignez. La vérification
  de l'empreinte s'applique toujours : la copie ne tourne que si c'est le fichier publié.

Le verdict est dans le journal du job : la politique appliquée, sa version et son seuil, le nombre
d'issues prises en compte, puis une ligne par violation avec sa gravité, son identifiant, le paquet,
la raison et les versions corrigées quand il y en a. Le verdict est aussi consigné, sur l'écran
**Registre des verdicts** : chaque appel en écrit un, donc demandez une fois par pipeline, pas en
boucle.

### Quand c'est refusé {#when-it-is-refused}

| Lu dans le journal | Cause | Que faire |
|---|---|---|
| `set VECTISPIRE_TOKEN…` | la variable est protégée et la branche ne l'est pas | attendu sur les branches non protégées ; barrez les protégées |
| `set VECTISPIRE_GATE_VERSION…` | le job de barrière ne sait pas quelle version du script récupérer | posez-la au tag de l'`include` |
| `…is not the one this template was released with` | le SHA-256 du script téléchargé n'est pas celui du modèle : l'include et `VECTISPIRE_GATE_VERSION` nomment des versions différentes, ou `VECTISPIRE_GATE_SCRIPT_URL` sert un autre fichier | le même tag aux deux endroits ; rien ne tourne tant qu'ils diffèrent |
| `HTTP 401` | aucune clé, ou une clé inconnue, révoquée ou expirée, ou son compte désactivé | émettez une nouvelle clé ; la réponse ne dit jamais laquelle de ces causes |
| `HTTP 403` *This API key lacks the scan scope.* — ou *read* | il manque une portée à la clé | émettez-en une avec `scan` et `read` |
| `HTTP 403` *This credential is not allowed to call this route.* | le compte de la clé ne peut pas faire cela : pas administrateur pour le scan ; auditeur ou gouverneur de la plateforme pour la barrière | émettez la clé depuis un compte administrateur |
| `HTTP 404` | l'identifiant du dépôt est faux, **ou hors de la restriction de la clé** — la même réponse, exprès | comparez l'identifiant à la cible de la clé |
| `HTTP 400` *Unknown severity* | une faute de frappe dans `VECTISPIRE_FAIL_ON_SEVERITY` | `critical`, `high`, `medium`, `low` ou `none` |
| `HTTP 429` | le budget de requêtes par minute de la clé est épuisé | attendez `Retry-After` ; une boucle interroge trop vite |
| rapports : `403` | la clé des rapports ne détient pas `report_import`, ou aucune source active n'est déclarée pour elle, ou pas pour ce type | faites-la déclarer par le gouverneur avec `coverage` et `test_report` |
| rapports : `404` | le dépôt est hors de la restriction de la clé ou de la portée de la source | accordez l'identifiant, la clé et la source |
| rapports : `400` | le format n'est pas `jacoco`, `cobertura` ou `lcov`, le corps ne se lit pas comme tel, il ne compte aucune ligne ou aucun test, ou le commit n'est pas hexadécimal | un rapport vide est refusé, jamais consigné comme zéro |
| rapports : `413` | au-delà de `VECTISPIRE_MAX_BODY_COVERAGE_IMPORT` (16 Mo) ou `VECTISPIRE_MAX_BODY_TEST_REPORT_IMPORT` (32 Mo) | faites relever le plafond par l'exploitant — un rapport coupé en deux ferait deux rapports, le second pris pour le plus récent |

Chaque refus est un [document de problème](../reference/errors.md) : `application/problem+json`,
avec un `detail` écrit pour la personne qui lit le journal. Aucun de ces refus ne porte de type
`urn:vectispire:problem:` — il est réservé aux conflits qu'un écran doit distinguer — donc un script
décide sur le statut et affiche le `detail`.

## 2. Jenkins {#jenkins}

### Identifiants

Dans les **Credentials** du dossier qui contient le job — pas le magasin global, pour que seuls les
jobs de ce dossier puissent les lier — ajoutez deux identifiants de type **Secret text** :

| ID | Secret |
|---|---|
| `vectispire-ci-gate` | la clé **Barrière CI** (`scan`, `read`, limitée au dépôt) |
| `vectispire-reports` | la clé **Rapports** (`report_import`, source déclarée) |

`withCredentials` lie un secret pour les seules étapes qu'il contient, et Jenkins masque sa valeur
dans la console. Gardez tout script `sh` qui en utilise un entre **apostrophes simples** : le shell
développe `$VECTISPIRE_TOKEN` à l'exécution, alors qu'une chaîne Groovy `"…${…}"` écrirait le secret
dans la ligne de commande que Jenkins consigne — il prévient précisément de cela. Et pas de `set -x`.

La même réserve que pour GitLab vaut pour les pipelines multibranches : c'est le `Jenkinsfile` de la
branche qui s'exécute, donc qui peut pousser une branche peut lier l'identifiant. C'est la
restriction qui borne cela.

### `Jenkinsfile`

```groovy
pipeline {
    // Un agent avec sh, curl, jq et zip.
    agent { label '<agent-label>' }

    environment {
        VECTISPIRE_URL           = 'https://<vectispire-host>'
        VECTISPIRE_REPOSITORY_ID = '<repository-id>'
    }

    stages {
        stage('Build and test') {
            steps {
                sh 'mvn -B verify'
            }
            post {
                always {
                    junit 'target/surefire-reports/TEST-*.xml'
                }
            }
        }

        stage('Vectispire reports') {
            steps {
                withCredentials([string(credentialsId: 'vectispire-reports', variable: 'VECTISPIRE_REPORT_KEY')]) {
                    // GIT_COMMIT vient du checkout, BRANCH_NAME d'un pipeline multibranche :
                    // retirez le paramètre branch ailleurs.
                    sh '''
                        set -eu
                        api="${VECTISPIRE_URL%/}/api/v1/repositories/$VECTISPIRE_REPOSITORY_ID"
                        curl --fail-with-body -sS -X POST "$api/coverage-imports" \
                          --url-query "format=jacoco" \
                          --url-query "commit=$GIT_COMMIT" --url-query "branch=$BRANCH_NAME" \
                          -H "Authorization: Bearer $VECTISPIRE_REPORT_KEY" -H "Content-Type: application/xml" \
                          --data-binary @target/site/jacoco/jacoco.xml
                        (cd target/surefire-reports && zip -q ../surefire-reports.zip TEST-*.xml)
                        curl --fail-with-body -sS -X POST "$api/test-report-imports" \
                          --url-query "commit=$GIT_COMMIT" --url-query "branch=$BRANCH_NAME" \
                          -H "Authorization: Bearer $VECTISPIRE_REPORT_KEY" -H "Content-Type: application/zip" \
                          --data-binary @target/surefire-reports.zip
                    '''
                }
            }
        }

        stage('Vectispire scan') {
            when { branch '<configured-branch>' }   // la branche que Vectispire analyse
            steps {
                withCredentials([string(credentialsId: 'vectispire-ci-gate', variable: 'VECTISPIRE_TOKEN')]) {
                    sh 'sh ci/vectispire-scan.sh'
                }
            }
        }

        stage('Vectispire gate') {
            when { branch '<configured-branch>' }
            environment {
                // Le script de barrière de la version et son empreinte : le VECTISPIRE_GATE_SHA256
                // de ci/gitlab/vectispire-gate.gitlab-ci.yml au même tag.
                VECTISPIRE_GATE_VERSION = '<tag>'
                VECTISPIRE_GATE_SHA256  = '<sha256>'
            }
            steps {
                sh '''
                    curl -fsSL -o vectispire-gate.sh \
                      "https://github.com/asmolabs/vectispire/releases/download/$VECTISPIRE_GATE_VERSION/vectispire-gate.sh"
                    echo "$VECTISPIRE_GATE_SHA256  vectispire-gate.sh" | sha256sum -c -
                '''
                withCredentials([string(credentialsId: 'vectispire-ci-gate', variable: 'VECTISPIRE_TOKEN')]) {
                    script {
                        int verdict = sh(returnStatus: true,
                                         script: 'sh vectispire-gate.sh --repository "$VECTISPIRE_REPOSITORY_ID"')
                        if (verdict == 1) {
                            error('Vectispire gate failed: the violations are listed above.')
                        }
                        if (verdict != 0) {
                            // 2 : la barrière n'a pas pu être interrogée. Bloquer est le défaut ;
                            // unstable(...) à la place laisse passer le build, visiblement non barré.
                            error("Vectispire gate could not be asked (exit ${verdict}).")
                        }
                    }
                }
            }
        }
    }
}
```

- **`returnStatus: true`** garde séparés les trois codes de sortie de la barrière, pour que « votre
  code ne respecte pas la politique » et « Vectispire n'a pas répondu » finissent en deux messages
  différents — et, si vous le choisissez, en deux résultats d'étape différents.
- **`when { branch … }`** fonctionne dans un pipeline multibranche. Dans un job à branche unique,
  retirez le `when` et pointez le job sur la branche que Vectispire analyse.
- Les options `--url-query` et `--fail-with-body` de `curl` demandent curl 7.87 ou plus récent sur
  l'agent.
- **Le script de barrière est vérifié avant de tourner**, contre l'empreinte qu'épingle le modèle
  GitLab au même tag ; `sha256sum -c` fait échouer l'étape sur tout autre fichier. La version porte
  aussi un bundle Sigstore pour lui, vérifié comme le jar — voir
  [Barrière CI](ci-gate.md#la-version-courte). `vectispire-gate.sh` est un asset de version depuis
  la 0.10.0.

Les refus sont ceux du [tableau GitLab](#when-it-is-refused) : les scripts affichent le statut et le
`detail` du serveur dans la console.

## 3. SonarQube {#sonarqube}

SonarQube n'écrit pas de SARIF lui-même. Le job ci-dessous lit son API Web, écrit un run SARIF dont
l'outil est `SonarQube`, et le téléverse par une source déclarée nommée `quality-server`. Une ligne
de checklist liée à la portée `import:quality-server/SonarQube` mesure alors ces issues.

**Seulement depuis l'intérieur de l'organisation** : SonarQube sur vos sites, le job sur votre propre
exécuteur. Une source déclarée est la plateforme qui affirme que ce producteur est interne ; voir
[Importer du SARIF d'un outil interne](../administration/plugins.md#importer-du-sarif-dun-outil-interne).

### 1. La clé et la source

1. Sur **Clés d'API**, un administrateur émet une clé avec **`sarif_import`** seule. Limitez-la au
   dépôt quand la source n'en alimente qu'un. Une restriction de clé ne nomme qu'une cible : une
   source qui couvre un projet de plusieurs dépôts utilise une clé sans restriction, et c'est alors
   **la portée de la source** qui la confine à ce projet.
2. Sur **Administration → Sources déclarées**, le gouverneur de la plateforme déclare la source :
   slug **`quality-server`**, livrant du **SARIF**, outil **`SonarQube`**, la clé ci-dessus, et le
   projet ou le dépôt. Le même appel en script — la route prend la session du gouverneur, jamais une
   clé :

```bash
curl --fail-with-body -X POST "https://<vectispire-host>/api/v1/sarif-sources" \
  -H "Authorization: Bearer $GOVERNOR_SESSION" -H "Content-Type: application/json" \
  -d '{"slug": "quality-server", "name": "SonarQube on premises", "api_key_id": "<key-id>",
       "repository_id": <repository-id>, "kinds": ["sarif"], "tools": ["SonarQube"]}'
```

**Le slug et le nom de l'outil font partie de l'identité de chaque issue importée**, sous la forme
`import:quality-server/sonarqube` à côté de la règle et du chemin. Renommez l'un des deux plus tard
et chaque issue importée est résolue puis rouverte sous le nouveau nom, son triage laissé derrière.
Choisissez-les une fois. Faire tourner la clé garde le slug : déclarez le même slug à nouveau avec la
nouvelle clé.

### 2. Le convertisseur

Versionnez ceci sous `ci/sonarqube-to-sarif.sh`. Il demande `curl` et `jq`, et un jeton SonarQube
d'un compte technique ayant la permission **Browse** sur le projet, dans `SONAR_TOKEN`. Comme le
script de scan, il est identique à la version anglaise.

```sh
#!/bin/sh
# Export a SonarQube project's unresolved issues as one SARIF 2.1.0 run named "SonarQube".
#   usage: sonarqube-to-sarif.sh <sonarqube-project-key> <output.sarif>
# Any failure exits non-zero and writes no report: an empty `results` would tell Vectispire
# "SonarQube found nothing" and resolve every issue it imported.
set -eu

: "${SONAR_HOST_URL:?set SONAR_HOST_URL to the SonarQube server}"
: "${SONAR_TOKEN:?set SONAR_TOKEN to a token allowed to browse the project}"
project="$1"
output="$2"
sonar="${SONAR_HOST_URL%/}"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

version=$(curl -fsS -u "$SONAR_TOKEN:" "$sonar/api/server/version")

page=1
: > "$work/issues.jsonl"
while :; do
    curl -fsS -u "$SONAR_TOKEN:" -o "$work/page.json" --get "$sonar/api/issues/search" \
        --data-urlencode "componentKeys=$project" \
        --data "resolved=false" --data "ps=500" --data "p=$page"
    total=$(jq -r '.paging.total' "$work/page.json")
    # The Web API serves at most 10,000 issues per query. Sending the first 10,000 would
    # resolve the others in Vectispire, so refuse instead.
    if [ "$total" -gt 10000 ]; then
        echo "sonarqube-to-sarif: $total issues, past the 10,000 the Web API can page through" >&2
        exit 1
    fi
    jq -c '.issues[]' "$work/page.json" >> "$work/issues.jsonl"
    [ $(( page * 500 )) -lt "$total" ] || break
    page=$(( page + 1 ))
done

jq -s --arg version "$version" '{
  version: "2.1.0",
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  runs: [{
    tool: { driver: { name: "SonarQube", version: $version } },
    results: map({
      ruleId: .rule,
      message: { text: .message },
      properties: { "security-severity":
        ({ BLOCKER: "9.5", CRITICAL: "8.0", MAJOR: "5.5", MINOR: "2.0", INFO: "1.0" }[.severity // ""] // "5.5") },
      locations: (if (.component | contains(":")) then [{
        physicalLocation: ({ artifactLocation: { uri: (.component | sub("^[^:]*:"; "")) } }
          + (if .line then { region: { startLine: .line } } else {} end))
      }] else [] end)
    })
  }]
}' "$work/issues.jsonl" > "$work/report.sarif"
mv "$work/report.sarif" "$output"
echo "sonarqube-to-sarif: $(jq '.runs[0].results | length' "$output") issue(s) written to $output"
```

Ce qu'il décide, et pourquoi :

- **Les issues non résolues seulement** (`resolved=false`). Une issue fermée dans SonarQube —
  corrigée, *won't fix*, *false positive* — est alors absente du rapport suivant, et Vectispire la
  résout : SonarQube reste l'endroit où son triage se fait. Chaque rapport remplace le précédent de
  cet outil sur ce dépôt et ne touche à rien d'autre.
- **La gravité par `security-severity`**, le score que Vectispire lit en premier : `BLOCKER` devient
  critique, `CRITICAL` élevée, `MAJOR` moyenne, `MINOR` et `INFO` faible. Une issue sans gravité —
  les versions récentes de SonarQube décrivent des impacts à la place — est lue comme moyenne ;
  adaptez la correspondance si votre serveur fait cela pour toutes les issues.
- **Le chemin** est la clé de composant SonarQube moins son préfixe `projectKey:`, relative au
  répertoire de base de l'analyse. Vectispire refuse les chemins absolus et les veut relatifs à la
  racine du dépôt : si `sonar.projectBaseDir` est un sous-répertoire, préfixez-le. Une issue portant
  sur le projet lui-même n'a pas d'emplacement.
- **Tous les types d'issues sont exportés.** Pour ne mesurer que les vulnérabilités et les bogues,
  resserrez la requête avec les filtres de l'API Web elle-même ; `/web_api/api/issues/search` sur
  votre serveur liste les paramètres que sa version accepte.

### 3. Le job

Après l'analyse — et après que SonarQube l'a *traitée* : le scanner rend la main avant que le serveur
ait calculé les issues, donc lancez-le avec `-Dsonar.qualitygate.wait=true`, sinon l'export lit
l'analyse précédente. Dans Jenkins, une étape du pipeline ci-dessus — elle réutilise
`VECTISPIRE_URL` et `VECTISPIRE_REPOSITORY_ID` — avec deux identifiants **Secret text** de plus,
`sonarqube-browse-token` et `vectispire-sonarqube` (la clé `sarif_import`) :

```groovy
stage('SonarQube to Vectispire') {
    environment {
        SONAR_HOST_URL = 'https://<sonarqube-host>'
    }
    steps {
        withCredentials([string(credentialsId: 'sonarqube-browse-token', variable: 'SONAR_TOKEN'),
                         string(credentialsId: 'vectispire-sonarqube', variable: 'VECTISPIRE_SARIF_KEY')]) {
            sh '''
                set -eu
                sh ci/sonarqube-to-sarif.sh "<sonarqube-project-key>" sonarqube.sarif
                curl --fail-with-body -sS -X POST \
                  "${VECTISPIRE_URL%/}/api/v1/repositories/$VECTISPIRE_REPOSITORY_ID/sarif-imports" \
                  -H "Authorization: Bearer $VECTISPIRE_SARIF_KEY" \
                  -H "Content-Type: application/sarif+json" \
                  --data-binary @sonarqube.sarif
            '''
        }
    }
}
```

Dans GitLab CI, ce sont les deux mêmes commandes dans un job, avec `SONAR_TOKEN` et
`VECTISPIRE_SARIF_KEY` en variables masquées. La réponse (`201`) compte les résultats et les issues
créées, résolues et rouvertes, avec le SHA-256 du document — gardez-la dans le journal du job pour
rattacher un import à son exécution.

### 4. La règle de checklist

Sur **Administration → Modèles de checklists**, sur un brouillon, liez la ligne qui demande une
analyse statique à une règle `findings_threshold` — voir
[lignes mesurées](../administration/checklist-templates.md#lignes-mesurees-la-regle-liee-a-une-ligne) :

```json
{"kind": "findings_threshold", "maxAgeDays": 7,
 "scopes": ["import:quality-server/SonarQube"],
 "thresholds": {"critical": {"maxOpen": 0}, "high": {"maxOpen": 0}}}
```

La portée est stockée en minuscules, `import:quality-server/sonarqube`, comme les issues sont
indexées. Deux conséquences à prévoir :

- **`maxAgeDays` est un calendrier.** La ligne ne passe que si un import de cette portée est arrivé
  dans ce délai, sur chaque dépôt du projet. Un job qui ne tourne que lorsque quelqu'un pousse lit
  `stale` sur un dépôt calme : planifiez-le aussi, chaque nuit par exemple
  (`cron('H 2 * * *')` dans les `triggers` de Jenkins).
- **Un slug nomme une source, et une source un projet ou un dépôt.** La règle mesure là où
  `quality-server` livre. Un autre projet alimenté par une autre source a un autre slug, et cette
  portée y lit `never_examined`.

Les issues importées ne font pas échouer la [barrière CI](ci-gate.md) sauf si la politique de
barrière les inclut (`include_plugins`), et elles ne sont pas comptées dans les chiffres de sécurité :
le « critique » d'un outil tiers ne casse pas une construction que personne n'a prévenue. La
checklist les mesure ; la barrière, par défaut, non.

### Quand c'est refusé {#sonarqube-refusals}

| Statut | Cause |
|---|---|
| `403` | pas une clé d'intégration, une clé pour laquelle aucune source **active** n'est déclarée, ou un outil que la source ne déclare pas — le nom du driver doit être `SonarQube`, comparé sans égard à la casse |
| `404` | un dépôt hors de la restriction de la clé ou de la portée de la source, répondu comme s'il n'existait pas |
| `400` | pas du SARIF 2.1.0, un emplacement absolu ou hors du dépôt, un résultat sans règle, un run sans `results` ou marqué en échec |
| `413` | au-delà de `VECTISPIRE_MAX_BODY_SARIF_IMPORT` (32 Mo). Ne coupez pas le rapport : chaque envoi remplace le précédent de l'outil sur ce dépôt, donc la seconde moitié résoudrait la première. Resserrez la requête, ou faites relever le plafond par l'exploitant |

Un import refusé est audité et envoyé au SIEM comme `VECTI-SEC-023` ; un import accepté est gardé
avec l'empreinte de son document, et listé sous **Imports** sur la ligne du dépôt dans
[Dépôts](../guide/repositories.md).
