# Audit approfondi — code, sécurité, documentation

**30 août 2026, 14:22** · *English version: [`2026-08-30_14_22_14_in_depth_code_security_doc_audit.en.md`](../en/2026-08-30_14_22_14_in_depth_code_security_doc_audit.en.md)*

## Note globale : **7,8 / 10** — en baisse depuis 8,4

**Le terrain ne s'est pas dégradé. Ce qui a changé, c'est où se trouve le terrain.** L'audit de
13:11 a corrigé quatre choses réelles et les a commitées. Trois heures plus tard, ces cinq commits
sont sur `develop` et **`main` ne les a pas**. Or `main` est la branche par défaut, donc la seule
depuis laquelle GitHub déclenche un workflow planifié : le nocturne de ce matin, vert, a certifié
l'arbre *d'avant* les correctifs. La remédiation est écrite ; elle n'est pas en vigueur.

Et l'exécution qui aurait dû le rattraper tournait encore : le run `verify` de la tête de
`develop` est resté `in_progress` trois heures. Je l'ai d'abord écrit comme un blocage ; **ce n'en
était pas un — il a fini avec succès en 67,3 minutes**, et le fait qu'il tourne aussi longtemps à
chaque poussée s'est révélé plus intéressant. Voir §3.2, qui est une correction autant qu'un
constat.

| Domaine | Note | Mouvement |
|---|---|---|
| Documentation & Architecture | **7,5** | ↓ |
| Sécurité & Cryptographie | **8,0** | ↓ |
| Qualité du code | **8,5** | = |
| Conformité & Standards | **8,5** | = |
| **Vérification réellement exécutée** | **6,5** | ↓↓ |

**Deux des cinq baisses sont « un audit précédent avait noté ce qu'il n'avait pas mesuré », et
je le dis parce que la distinction est le sujet du prompt.** Le `curl` non épinglé de `cosign`
est là depuis le portage du 27 août (`8b56333`) : quatre audits l'ont lu sans le voir. Le
« quatre moteurs » du README contredit l'ADR 0014 depuis le 25 août : cinq audits ont vérifié la
parité bilingue *par comptage de fichiers* sans jamais lire ce que les deux fichiers disaient.

---

## 0. État de remédiation — cinq des huit recommandations sont faites

*Ajouté après l'audit. Vérification à froid : **1328 tests JVM** (1327 + le cas AAD), **0 échec** ;
**146 tests Angular** ; checkov **260 + 384 = 644 contrôles, 0 échec** ; **779 liens, 0 cassé** ;
`check-doc-facts.py` **23 affirmations chiffrées, 0 contredite**.*

| # | Recommandation | Fait par | Preuve |
|---|---|---|---|
| 2 | Borner les jobs, et corriger ce qui en rendait un lent | **Les dix-sept jobs des quatre workflows** portent un `timeout-minutes` — `release.yml` et `docs.yml` n'en avaient pas non plus. Mais un plafond seul n'aurait fait que rendre le run #17 rouge : les **boucles à un conteneur par sonde disparaissent** aussi. L'attente de la base est un `docker exec` dans le conteneur déjà lancé, et la sonde de santé est un conteneur qui réessaie en interne au lieu de 90 qui réessaient une fois chacun. Les deux bornes sont en temps réel, donc le log et le plafond partagent une unité. | `yaml.safe_load` sur les quatre fichiers : **0 job sans `timeout-minutes`**. La sonde a été exercée localement sur ses trois chemins : sain → **0**, rien à l'écoute → **1** à l'échéance +1 s, API-mais-pas-l'interface → **2**. L'attente par `exec` aboutit en **6 s** contre 67 min pour la boucle qu'elle remplace |
| 3 | Épingler et vérifier `cosign` | Version **v3.1.3** — ce que `latest` résolvait au moment d'épingler, donc aucun changement de comportement — et empreinte `4629c757…` vérifiée par `sha256sum -c` **avant** `install`. Téléchargé dans `/tmp` et non directement dans `/usr/local/bin` : écrire d'abord et vérifier ensuite laisse un exécutable non vérifié sur le `PATH` pendant la fenêtre entre les deux. | L'empreinte a été **obtenue puis re-vérifiée en téléchargeant réellement le binaire** ; checkov reparse et valide |
| 6 | « four engines » et « 840 tests » | **Le README dit maintenant deux moteurs déployables et une fixture, en citant l'ADR 0014.** Le compte de tests est *retiré* plutôt que corrigé : un nombre qui bouge à chaque commit est le mauvais genre de fait à écrire en prose. Et la parité s'étend aux chiffres — voir ci-dessous. | `grep -niE "four engines\|all four\|840"` → **0** ; les deux README citent 0014 |
| 7 | La règle i18n | **Le plancher de 40 devient un compte exact de 54**, plus un **cliquet** à 89 sur les libellés en dur. Le cliquet plutôt que l'interdiction : `src/app` en porte 89 sur 14 fichiers, et une règle qui échoue à sa première exécution est une règle qu'on désactive. | **Remettre les deux libellés en dur fait échouer `npm test`, exit 1** — il passait vert ce matin. Le cliquet se déclenche seul : un libellé ajouté sans toucher aucune clé → **90 > 89, exit 1** |
| 8 | L'AAD de `SealedEnvelope` | Un cas qui **redérive la clé de session indépendamment** — même accord X25519, même sel HKDF — puis déchiffre les octets produits par `seal` deux fois : avec la clé éphémère en AAD, puis sans. Même clé, même nonce, mêmes octets ; seule l'AAD varie. Le commentaire du test voisin dit désormais pourquoi il ne prouvait pas ce que son nom annonce. | Avant : l'AAD vidée faisait échouer **1 test sur 701**, le vecteur d'or. Après : **2 sur 702**, dont celui qui porte le nom de la propriété |

### Ce que la remédiation a appris

**La règle qui vérifie la documentation a trouvé un défaut vivant à sa première exécution, dans
l'autre sens.** `scripts/check-doc-facts.py` a été écrit pour le « four engines » — un survente.
Il a immédiatement signalé `COMPLIANCE_AND_REGULATORY`, **dans les deux langues** : *« cinq
référentiels internationaux majeurs »* au-dessus d'une liste de **six**, et le bundle de preuves
n'en nommait que cinq, SOC 2 omis. Sept affirmations périmées sur quatre fichiers, y compris
« 20 contrôles » contre 24. Le §4 du prompt le dit exactement : sous-vendre coûte autant que
survendre.

**Et la première version de cette règle était mauvaise, ce qui est le plus utile du lot.** Elle
exigeait l'égalité sur tout nombre voisin de « moteurs » : **dix-sept faux positifs**, parce que
`un moteur` est un article en français et que `0014-two-engines` dans une cible de lien ressemble
à une affirmation de quatorze moteurs. Deux corrections en ont découlé — ne lire que la prose
(blocs de code et cibles de liens neutralisés en préservant les offsets), et traiter les moteurs
comme un **plafond** plutôt qu'une égalité, puisque le défaut ne fait jamais qu'enfler. Une règle
qui crie au loup obtient une liste d'exemptions, puis se fait ignorer, puis se fait supprimer.

**Le garde-fou anti-règle-vide s'est déclenché avant tout le reste.** À sa toute première
exécution, `check-doc-facts.py` a refusé de passer parce qu'une de ses quatre affirmations ne
correspondait à rien : les documents disent « catégories d'évaluation » là où le code dit
`Category`. La règle ne s'est pas tue — elle a exigé un humain. C'est précisément ce qui manquait
à `check-i18n-keys.mjs`.

### Ce qui reste, et pourquoi

| # | Recommandation | Pourquoi ce n'est pas fait ici |
|---|---|---|
| 1 | **Fusionner `develop` dans `main`** | Une opération sortante sur la branche par défaut. Et cette remédiation **creuse l'écart** : il est maintenant de cinq commits plus ce travail |
| 4 | Déclencher `release.yml` | Demande `gh auth` et signe au nom du projet |
| 5 | Activer GitHub Pages | Réglage exigeant les droits d'administration sur `asmolabs/vectispire` |

**Et il faut le redire, parce que la remédiation l'aggrave plutôt que de l'améliorer : tant que
le #1 n'est pas fait, tout ce qui précède est corrigé sur une branche que rien de planifié
n'exécute.**


## 1. Ce que j'ai exécuté

| Contrôle | Commande | Résultat |
|---|---|---|
| Suites JVM, à froid | `./gradlew build --rerun-tasks` | **1327 tests, 260 suites, 0 échec, 0 erreur, 0 ignoré** |
| Campagne multi-moteurs | `./gradlew integrationTestAll --rerun-tasks` | **PostgreSQL 29, MySQL 29, SQLite 29 = 87 tests, 0 échec** |
| Conteneurs à l'exécution | `:vectispire-common:integrationTest` | **14 cas, 0 échec**, démon vivant |
| Suite navigateur | plan de contrôle démarré à la main, puis `npx playwright test` | **13 passés** en 2,2 min |
| Exercice de restauration | `bash scripts/restore-drill.sh` | **passé**, mutation intégrée comprise |
| Suites Angular | `npm test` | **146 tests, 23 fichiers, 0 échec** ; i18n **54 clés, 2 bundles** |
| `gitleaks` | image CI épinglée par digest | **382 commits, 16,28 Mo, aucune fuite** |
| Politique Dockerfile / Actions | image checkov épinglée par digest | **260 + 380 = 640 contrôles, 0 échec**, 2 ignorés |
| Liens relatifs | `python3 scripts/check-doc-links.py` | **774 liens, 0 cassé** — **778** après ajout des deux rapports ci-dessous, toujours 0 |
| Dérive C4 | `shasum -a 256` vs `diagrams/.workspace.sha256` | **en phase** |
| Site de documentation | `mkdocs build --strict` en venv | **construit**, 0,46 s — voir §3.5 |
| Parité bilingue | `find docs/{fr,en}` | docs **12 / 12** ; ADR **18 / 18** ; bflorat **6 / 6** ; STRIDE **2 / 2** |
| Isolation de l'agent | `:vectispire-agent:dependencies` | **0** JDBC / Hibernate / Flyway / JPA ; `ENCRYPTION_KEY` absent de `src/main` |
| Bac à sable des scanners | lecture de `ContainerRunner` + `docker-compose.yml` | `cap_drop` **toutes**, `no-new-privileges`, rootfs **read-only**, réseau `none`, plafonds mémoire/CPU/PID ; `docker.sock` monté **uniquement** sur `control-plane` et `agent` |
| Cryptographie | `SecretCipher`, `SealedEnvelope`, `PasswordHasher` | préfixe `v2:`, nonce **12 o**, tag **128 bits**, AAD de contexte, X25519+HKDF+GCM, Argon2id **PHC** |
| Conformité, par le compte | `grep -c` sur le catalogue | **6 référentiels, 24 contrôles, 7 catégories, 3 plafonds plate-forme** |
| Historique GitHub | API publique | **20 exécutions** — voir §2 |
| Releases et tags | `git tag`, API `/releases` | **0 et 0** — `release.yml` n'a toujours jamais tourné |
| Écart de branches | `git rev-list --count origin/main..develop` | **5** — voir §3.1 |
| Arbre de travail | `git status --short` | **propre** |

### Une note sur le prompt lui-même

`PROMPT_AUDIT.md` §1 parle des « ADR 0001 à 0016 » : il y en a **dix-sept**, la 0017 (*checks
d'organisation en images de conteneur*) datant du 29 août. Le §5 décrit encore `.gitlab-ci.yml`
comme conservé et non maintenu ; **le fichier n'existe plus**, supprimé par `3668dfe`, ce que
l'audit de 13:11 avait déjà relevé. Le prompt dérive de l'arbre qu'il audite ; c'est bénin, mais
un prompt qui décrit un dépôt d'avant-hier finit par faire chercher des choses absentes et par
faire manquer celles qui sont arrivées depuis.

---

## 2. L'état réel de la forge

`git remote -v` → `git@github.com:asmolabs/vectispire.git`. Branche par défaut : `main`, dépôt
public, `has_pages: false`.

| Workflow | Exécutions | Depuis | Dernier verdict |
|---|---|---|---|
| `verify` (`ci.yml`) | 17 | `develop` et `main` | succès — mais **#17 a mis 67 min dans `images`** contre 4 min pour le suivant, voir §3.2 |
| `nightly` | 2 | `main`, `schedule` | succès (29 août 09:17, 30 août 08:29) |
| `docs` | 1 | `main` | **échec**, voir §3.5 |
| `release` | **0** | — | **jamais déclenché** |

Le nocturne fonctionne : deux déclenchements planifiés, tous deux depuis `main`, tous deux verts.
La question ouverte depuis le 28 août est bien close. Mais elle a été remplacée par une autre,
qui est le constat principal de cet audit.

---

## 3. Les constats

### 3.1 🔴 La branche que GitHub planifie a cinq commits de retard, donc rien de ce que les deux derniers audits ont corrigé n'est en vigueur

```
$ git rev-list --count origin/main..develop
5
$ git log --oneline -1 origin/main
dfbd7f8 docs(analysis): les deux constats du 16e audit sont fermés…
```

`origin/main` est resté au commit de documentation du **16e** audit. Les cinq commits absents
sont ceux qui portent toute la remédiation des 17e et 18e passes :

| Commit | Ce que `main` n'a pas |
|---|---|
| `fafb3cf` | `ReadCostSweepTest` — et les trois correctifs de lecture (`/epss/priorities` N+1, `/scorecards/global`, `/attack-paths/overview`) |
| `e920718` | Le correctif i18n et `check-i18n-keys.mjs` |
| `014503a` | `release.yml` avec SBOM, double signature, double vérification et `gh release create` |
| `e716fe6` | Le runbook d'exposition de secrets corrigé sur la forge |
| `c4a6112` | Les rapports des 17e et 18e audits |

Vérifié fichier par fichier :

```
$ git ls-tree -r --name-only origin/main | grep -cE "ReadCostSweepTest|check-i18n-keys"
0
$ git ls-tree -r --name-only origin/develop | grep -cE "ReadCostSweepTest|check-i18n-keys"
2
$ git ls-tree -r --name-only origin/main | grep -c ReadCostRoutesTest
1
$ git show origin/main:.github/workflows/release.yml | grep -ci sbom
0
```

`main` porte encore `ReadCostRoutesTest`, l'énumération de quatre routes que `fafb3cf` a retirée
précisément parce qu'elle ne pouvait pas voir les trois autres. **Et `main` porte encore les trois
routes non corrigées**, dont le N+1 à 468 requêtes pour 620 constats.

**La conséquence est celle que le prompt §5 décrit exactement.** GitHub n'exécute un workflow
planifié que depuis la branche par défaut. Le nocturne du 30 août à 08:29 est vert — et il a
exercé la campagne multi-moteurs, la suite navigateur et l'exercice de restauration **sur l'arbre
d'avant les correctifs**. Un vert sur `main` aujourd'hui ne dit rien de ce qui a été réparé hier.
C'est la troisième fois dans cette série qu'un écart `main`/`develop` transforme une garantie en
décor ; les deux premières fois l'écart était de 75 puis de 3 commits.

**Recommandation 1 (bloquante, et c'est la seule qui débloque les autres).** Fusionner `develop`
dans `main`. Tant que ce n'est pas fait, tout ce que le 18e audit a mesuré comme corrigé est
corrigé sur une branche que rien de planifié n'exécute.

---

### 3.2 🔴 Un job de fumée compte des démarrages de conteneur comme des secondes, et a mis 67 minutes à faire trois minutes et demie de travail

**Corrigé après coup, et la correction est le constat.** Pendant cet audit, le run #17 est resté
`in_progress` trois heures, son job `images` sans complétion, et je l'ai écrit comme bloqué — un
job qui occuperait un runner jusqu'au plafond de six heures de GitHub sans rapporter ni succès ni
échec. **Il n'était pas bloqué. Il a fini, avec succès, en 67,3 minutes**, et je ne le sais que
parce que pousser la remédiation m'a fait regarder à nouveau :

```
$ curl .../actions/runs/33308940758/jobs
images   success   67,3 min      <- tous les autres jobs : de 0,1 à 4,2 min
jvm      success    4,2 min
frontend success    1,0 min
```

L'affirmation du plafond était fausse. Ce qu'il y a dessous est pire que ce que j'affirmais, parce
qu'un vert lent est invisible là où un rouge ne l'est jamais : ce job prenait plus d'une heure à
chaque exécution et rien ne le disait.

**La cause est dans les boucles d'attente, et c'est une erreur d'unité.** Toutes deux démarrent
*un conteneur par tentative* tout en rapportant des tentatives comme des secondes :

```yaml
for attempt in $(seq 1 120); do
  if docker run --rm --network smoke mysql:8 mysqladmin ping ...; then
    echo "database ready after ${attempt}s"; break        # <- une tentative n'est pas une seconde
  fi
  sleep 1
done
```

Une tentative coûte une création, un démarrage, une exécution et une suppression de conteneur. La
sonde de santé fait de même avec `curlimages/curl`, jusqu'à 90 fois. Une boucle documentée comme
bornée à 120 secondes est donc bornée à 120 × (1 s + surcoût de conteneur), et sur un runner
chargé cela fait une heure. Mesurée localement, la même attente faite par `docker exec` dans la
base déjà lancée aboutit en **6 secondes**.

**Et `ci.yml` ne bornait aucun job**, quand `nightly.yml` bornait ses quatre depuis toujours :

```
$ grep -n "timeout-minutes" .github/workflows/*.yml
nightly.yml:37,57,72,159   40, 30, 30, 30
ci.yml                     (rien)
```

Cela reste à corriger pour soi-même — un job qui pend vraiment ne rapporte *rien*, et rien est la
seule réponse qu'aucune procédure ne traite. Mais un délai n'aurait fait que rendre ce run rouge ;
il n'aurait dit à personne pourquoi.

**Recommandation 2.** Les deux moitiés. Borner chaque job, et corriger les boucles pour que la
borne dise ce qu'elle dit : `docker exec` dans la base déjà lancée plutôt qu'un conteneur client
par sonde, et *un seul* conteneur de sonde qui réessaie en interne plutôt qu'un par tentative.
Alors le nombre dans le log et le nombre dans le plafond sont la même unité.
---

### 3.3 🔴 Le workflow qui signe télécharge son outil de signature depuis une URL mutable, sans vérification — dans le job qui détient `id-token: write`

`.github/workflows/release.yml`, lignes 75-79 :

```yaml
      - name: install cosign
        run: |
          curl -fsSL -o /usr/local/bin/cosign \
            https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64
          chmod +x /usr/local/bin/cosign
```

Pas de version. Pas de somme de contrôle. Pas de signature vérifiée. `latest` désigne ce que son
propriétaire décide aujourd'hui.

**Ce qui rend ce constat cher, c'est que le fichier énonce la règle qu'il enfreint, seize lignes
plus haut :**

> *« Chaque `uses:` ici est épinglé à un SHA de commit. Cela compte plus dans ce fichier que
> partout ailleurs : ce qu'un consommateur vérifie est "ce workflow, dans ce dépôt, sur ce tag",
> et une action échangée sous un tag mutable s'exécute dans le job qui détient `id-token: write`. »*

Le raisonnement est juste et complet. Il ne couvre que les `uses:`. Le seul binaire du job qui
n'est pas une action GitHub est **l'outil qui fabrique la provenance**, et c'est celui qui arrive
non épinglé.

**La conséquence n'est pas théorique.** `cosign` signe ici en mode *keyless*, avec le jeton OIDC
du workflow. Un binaire substitué signe donc avec l'identité **légitime** du projet, et les
paquets qu'il produit passent la commande que `GETTING_STARTED` §8 dit aux utilisateurs de lancer
— même `--certificate-identity`, même `--certificate-oidc-issuer`. La vérification côté
consommateur ne peut pas voir la différence, parce qu'il n'y a pas de différence à voir : le
certificat est authentique. Tout ce que la signature prouve, c'est que ce workflow a signé ; si
l'outil de signature n'est pas celui qu'on croit, cette preuve est exactement aussi bonne que le
`curl`.

**Ancienneté.** `git log -S "cosign-linux-amd64"` ne rend qu'un commit : `8b56333`, le portage
vers GitHub Actions du 27 août. C'est donc un défaut d'origine, présent pendant les quatre audits
suivants, et aucun ne l'a vu — **y compris celui d'hier qui a réécrit ce fichier pour y ajouter le
SBOM et la publication**. C'est « un audit précédent avait noté ce qu'il n'avait pas mesuré », et
non une dégradation.

**Recommandation 3.** Épingler la version de `cosign` et vérifier son empreinte avant
`chmod +x` :

```yaml
      - name: install cosign
        env:
          COSIGN_VERSION: v2.4.1
          COSIGN_SHA256: <l'empreinte publiée pour cette version>
        run: |
          curl -fsSL -o /tmp/cosign \
            "https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-linux-amd64"
          echo "${COSIGN_SHA256}  /tmp/cosign" | sha256sum -c -
          install -m 0755 /tmp/cosign /usr/local/bin/cosign
```

`sigstore/cosign-installer` épinglé par SHA est l'autre voie, et a l'avantage de rentrer dans la
règle que l'en-tête énonce déjà pour les `uses:` — donc de ne plus avoir d'exception à expliquer.

---

### 3.4 🟠 `release.yml` n'a toujours jamais tourné

Inchangé depuis l'audit de 13:11, et redit ici parce que le §5 du prompt demande de distinguer
partout « affirmé » d'« exécuté » :

```
$ git tag | wc -l
0
$ curl .../releases
[]
$ # 20 runs, aucun n'est « release »
```

Tout le chemin de signature — le SBOM au digest syft épinglé, la double signature, la double
vérification, `gh release create` — est **affirmé et non exécuté**. Le 18e audit l'a rendu plus
juste ; il ne l'a pas fait tourner. Et §3.3 ci-dessus ajoute une raison de le faire tourner
*après* correction plutôt qu'avant : une répétition générale qui installe un `cosign` non vérifié
répète aussi cela.

**Recommandation 4.** Déclencher `release.yml` en `workflow_dispatch` depuis `main` une fois le
§3.1 et le §3.3 réglés. La répétition ne publie rien (`if: startsWith(github.ref, 'refs/tags/')`)
et laisse un artefact à 90 jours qu'un humain peut inspecter. Cela demande vos identifiants ; ce
n'est pas une action que je prends à votre place.

---

### 3.5 🟠 `docs` échoue toujours, et j'ai reproduit la cause exacte

Les étapes du run unique :

```
1-4  checkout, setup-python, pip install          success
5    mkdocs build --strict                        success
6    actions/configure-pages                      FAILURE
7    upload-pages-artifact                        skipped
     deploy                                       skipped
```

Reproduit localement dans un venv depuis `ci/docs/requirements.txt` :
`mkdocs build --strict` → *Documentation built in 0.46 seconds*. **La documentation est saine.**
L'échec est en aval, sur `configure-pages`, et l'API du dépôt donne la raison en un champ :
`has_pages: false`.

Ce n'est pas un défaut de code. C'est un réglage de dépôt, ouvert depuis le 17e audit, et il
demande les droits d'administration sur `asmolabs/vectispire`.

**Recommandation 5.** Activer Pages (source : GitHub Actions) puis relancer `docs` en
`workflow_dispatch` — le workflow prévoit ce cas et le commente.

---

### 3.6 🟠 Le README anglais annonce quatre moteurs de base de données ; il y en a deux et une fixture, et son propre ADR le dit depuis cinq jours

```
README.md:348  Four engines are supported — PostgreSQL and MySQL, with SQLite as the test
               fixture — and **each is exercised by the full integration campaign**.
README.md:354  …running all four is the only way it gets found, and it found several.
README.md:438  **CI runs the first command and the Angular ones, and not the four-engine
               campaign**…
```

La phrase 348 se contredit dans sa propre parenthèse : elle annonce quatre moteurs et en nomme
trois, dont un qu'elle qualifie elle-même de fixture. Et le même fichier écrit ailleurs :

```
README.md:174  …on all two engines.
README.md:433  ./gradlew integrationTestAll # all two engines — ten minutes, needs Docker
```

Mesuré plutôt que déduit :

```
$ grep -n "val engines" vectispire-core/build.gradle.kts
190:  val engines = listOf("postgres", "mysql", "sqlite")
$ ls src/main/resources/db/migration/
mysql  postgresql  sqlite          (16 migrations chacun)
$ ./gradlew integrationTestAll --rerun-tasks
PostgreSQL 29, MySQL 29, SQLite 29
```

Trois cibles, dont une fixture. **Le registre de décisions est, lui, exact et honnête :**

```
0009-four-engines.md   Status: **superseded** by 0014 on 2026-08-25
0014-two-engines…      Status: accepted · Supersedes: 0009
```

C'est le cas de figure que le §4 du prompt décrit : *« parler de six moteurs surévend autant que
d'en annoncer quatre en sous-évend »*. Ici c'est un survente, sur le fichier qu'un visiteur lit en
premier, contre un registre qui a raison et que personne ne lit avant.

**Et la parité bilingue ne l'a pas vu, parce qu'elle compte des fichiers.** `README.fr.md` est
correct :

> *« Support complet et validé par tests de **PostgreSQL** et **MySQL** ; **SQLite** sert de
> fixture de test et n'est pas un moteur déployable (décision 0014). »*

Les deux README disent deux choses différentes sur un fait de dossier, et c'est l'anglais — le
long, le principal — qui a tort. Cinq audits ont validé « parité 12/12 » en comptant les
fichiers ; aucun n'a comparé ce que deux fichiers appariés affirmaient.

**Un défaut de la même famille, quatre lignes plus bas :** `README.md:437` annonce *« Around 840
unit tests »*. La mesure du jour en donne **1327**. Le chiffre est périmé d'environ 40 %.

**Recommandation 6.** Corriger 348, 354, 438 et 437. Et ajouter au contrôle de parité une
comparaison des chiffres cités : un test qui compte les fichiers ne peut pas voir deux fichiers
appariés qui se contredisent, et c'est précisément le défaut que la parité prétend écarter.

---

### 3.7 🟡 La règle i18n ajoutée hier ne voit pas le défaut pour lequel elle a été écrite

`e920718` s'intitule *« deux libellés anglais en dur sur un écran traduit, **et la règle qui les
aurait vus** »*. J'ai testé cette affirmation en remettant exactement les deux littéraux :

```diff
   readonly aiProviders = computed(() => {
       this.i18n.translations();
       return [
-          { label: this.i18n.t('settings.ai_provider_ollama'), value: 'ollama' },
-          { label: this.i18n.t('settings.ai_provider_openai'), value: 'openai' }
+          { label: 'Ollama - a model on a host you run', value: 'ollama' },
+          { label: 'OpenAI-compatible API', value: 'openai' }
       ];
   });
```

```
$ npm test
Vérification i18n : 52 clés référencées, toutes présentes en français et en anglais.
Test Files  23 passed (23)
     Tests  146 passed (146)
$ echo $?
0
```

**Rien n'échoue.** `check-i18n-keys.mjs` vérifie que les clés *référencées* existent dans les deux
bundles ; un libellé en dur n'est pas une clé référencée, donc il sort du champ de la règle au
lieu d'entrer dans son verdict. Le compteur passe de **54 à 52** sans un mot : le garde-fou est un
plancher à 40, et 52 le franchit largement.

Il faut être juste avec le script : son propre commentaire de tête est honnête, et dit qu'il
empêche *« la prochaine clé d'être référencée sans jamais être ajoutée »*. C'est vrai et c'est
utile. C'est le **titre du commit** qui affirme davantage que ce que le fichier fait — et c'est
cette phrase-là qu'un lecteur retient en décidant que le sujet est clos.

**Recommandation 7.** Deux gestes, l'un cher et l'autre gratuit.
- Épingler le compte plutôt que le plancher : `expect(referenced.size).toBe(54)` échoue quand une
  clé disparaît, ce que `> 40` ne fera jamais. Un chiffre qu'il faut mettre à jour en même temps
  qu'on retire une clé est un chiffre qui pose la question au bon moment.
- Ou, plus près du défaut : refuser un littéral non vide dans un champ nommé `label`/`title` d'un
  composant qui appelle `i18n.t` ailleurs. C'est la règle que le titre du commit décrit.

---

### 3.8 🟡 L'AAD de `SealedEnvelope` n'est toujours protégé que par un vecteur d'or, et le test qui prétend l'assurer passe sans lui

Report du 18e audit, re-mesuré parce qu'il n'a pas été fermé. Mutation : la clé éphémère retirée
de l'AAD, aux deux extrémités.

```diff
-  GCMModeCipher cipher = newCipher(sessionKey, nonce, ephemeralPublic, true);
+  GCMModeCipher cipher = newCipher(sessionKey, nonce, new byte[0], true);
-  GCMModeCipher cipher = newCipher(sessionKey, nonce, ephemeralPublic, false);
+  GCMModeCipher cipher = newCipher(sessionKey, nonce, new byte[0], false);
```

```
$ ./gradlew :vectispire-common:test
SealedEnvelopeTest > anEnvelopeSealedByAnEarlierBuildStillOpens() FAILED
701 tests completed, 1 failed
```

**Un seul test sur 701, et ce n'est pas celui qui porte le nom.**
`refusesAnEnvelopeWhoseEphemeralKeyWasReplaced` — dont le commentaire dit *« la clé de l'émetteur
est une donnée associée, donc l'échanger doit faire échouer l'authentification »* — passe
intégralement sans aucune AAD. Il passe pour une autre raison : échanger la clé éphémère change
le secret partagé X25519, donc la clé de session, donc GCM échoue de toute façon.

Ce qui rattrape la mutation est `anEnvelopeSealedByAnEarlierBuildStillOpens`, le vecteur littéral
épinglé, et il échoue parce que le **format** a changé — pas parce que le lien est asserté.
Autrement dit : si quelqu'un modifiait l'AAD et régénérait le vecteur dans le même commit, rien
n'objecterait, et le test qui porte le nom du sujet resterait vert.

La protection existe donc, mais elle est incidente. Ce n'est pas une faille : c'est une assertion
qui ne peut pas échouer pour la raison qu'elle annonce, et le prompt en fait une catégorie à part
pour de bonnes raisons.

**Recommandation 8.** Un cas qui isole l'AAD sans toucher au secret partagé : sceller, puis
réécrire uniquement les octets de clé éphémère *du préambule* tout en laissant l'accord de clés
inchangé — ou, plus simple à écrire et tout aussi probant, un test au niveau de `newCipher` qui
chiffre avec l'AAD et déchiffre sans, et exige `InvalidCipherTextException`. Renommer ensuite
`refusesAnEnvelopeWhoseEphemeralKeyWasReplaced` d'après ce qu'il vérifie réellement.

---

## 4. Tester mes propres tests

Quatre mutations, toutes annulées après mesure. Deux confirment que la règle mord ; deux ouvrent
un constat, et sont traitées en §3.7 et §3.8.

| Mutation appliquée | Attendu | Observé |
|---|---|---|
| `getGlobalScorecard` : la projection `IssueRows.Posture` remise en `findAll` d'entités | échec | **`ReadCostSweepTest` échoue** — *« /api/v1/scorecards/global loaded 224 entities at 220 issues against 24 at 20 (+200) »* |
| `ApiExceptionHandler` : `NOT_FOUND` → `FORBIDDEN` | échec | **18 tests échouent**, dont *« an export of somebody else's target is 404, never 403 »* |
| Les deux libellés d'IA remis en dur | échec | **aucun échec** — voir §3.7 |
| `SealedEnvelope` : AAD vidé aux deux bouts | échec du test nommé | **1 échec sur 701, et pas celui-là** — voir §3.8 |

**Ce que la première mutation apprend.** `ReadCostSweepTest`, livré hier, est du bon travail et je
l'ai vérifié plutôt que lu. Il demande sa table de routage à Spring, mesure entités *et* requêtes,
borne la **pente** plutôt que le compte, refuse toute exemption sur le compteur de requêtes, et
échoue s'il balaie moins de 25 routes — le garde-fou contre la règle qui n'inspecte rien, celui
qui manque justement à `check-i18n-keys.mjs`. Le message d'échec nomme la route, les deux mesures
et la croissance. C'est le contraire exact du §3.7 : ici la règle voit le défaut pour lequel elle
a été écrite, et je l'ai fait échouer pour le prouver.

**Ce que la deuxième apprend.** Dix-huit tests sur une seule ligne, et leurs noms disent la règle
plutôt que le mécanisme. Le cloisonnement des locataires est la partie la mieux tenue de ce
dépôt ; la mutation ne laisse aucun doute là-dessus.

---

## 5. Ce qui tient, et qui a été exécuté pour le dire

**Sécurité.** Le chiffrement au repos est conforme à sa description au détail près :
`FORMAT_PREFIX = "v2:"`, `NONCE_LENGTH_BYTES = 12`, `TAG_LENGTH_BITS = 128`, AAD de contexte
passée à `AEADParameters`. Argon2id via BouncyCastle, sortie PHC `$argon2id$v=19$m=…,t=…,p=…$`,
donc les paramètres voyagent avec l'empreinte et relever le coût n'invalide rien. `SealedEnvelope`
est bien X25519 + HKDF + GCM vers une clé éphémère publiée par l'agent.

**Le bac à sable.** `ContainerRunner` pose `withCapDrop(Capability.values())`,
`withSecurityOpts(["no-new-privileges"])`, `withReadonlyRootfs(true)`,
`withNetworkMode(… : "none")`, plus mémoire, CPU et PID. `docker-compose.yml` ne monte
`/var/run/docker.sock` que sur `control-plane` et `agent` — jamais dans un scanner, ce qui est
toute la raison d'être du bac à sable.

**L'isolation de l'agent.** `:vectispire-agent:dependencies` sur `runtimeClasspath` : **zéro**
occurrence de JDBC, Hibernate, Flyway, JPA, PostgreSQL ou MySQL. `ENCRYPTION_KEY` absent de tout
`src/main` de l'agent.

**La conformité, comptée.** 6 référentiels, **24** `new ComplianceControl(`, 7 catégories dans
l'énumération et 7 branches dans le `switch` de `ComplianceEngine`, 3 plafonds `cappedByPlatform`
(secrets sans clé, journal sans miroir, gouvernance sans quatre yeux). La répartition est
inégale — 7 contrôles en `VULNERABILITY_MANAGEMENT`, 1 en `GOVERNANCE` — ce qui est exactement ce
qu'une cartographie produit et pourquoi deux contrôles partageant une catégorie reçoivent le même
verdict. **Un évaluateur de posture, six cartographies.** La description du prompt est juste et le
code la tient.

**L'architecture.** `ArchitectureTest` porte 11 règles, dont *« finds classes to check at all »* —
le garde-fou contre la règle vide — et *« an outbound call goes through the door that validates
and pins »*. Le registre d'ADR est complet, bilingue à l'unité, et les renversements y sont
datés et croisés (0008 → 0009 → 0014, 0011 → 0013).

**L'exercice de restauration** passe, et porte sa propre mutation : il rejoue la restauration en
jetant le miroir, montre que `missingFromTable` retombe à 0 et que la perte devient invisible,
puis nomme le compteur qui la voit encore. Un script qui se piège lui-même est rare ; celui-ci le
fait et l'explique.

**Et une note de méthode sur la suite navigateur.** `npx playwright test` seul donne **12 échecs
sur 13** : la `webServer` de `playwright.config.ts` ne démarre que l'interface Angular sur 4280,
et rien n'écoute sur 3180. Après avoir démarré le plan de contrôle à la main comme le fait le job
`e2e` du nocturne, **13 passés en 2,2 min**. Mes douze échecs étaient mon environnement, pas une
régression — je le dis parce que la même erreur a déjà été commise et consignée dans cette série
le 29 août, et parce que taire un faux positif coûte plus cher que l'écrire.

---

## 6. Récapitulatif des recommandations

| # | Recommandation | Priorité | Vérifiée comment |
|---|---|---|---|
| 1 | **Fusionner `develop` dans `main`** — sans quoi rien de ce que les 17e et 18e audits ont corrigé n'est exécuté par quoi que ce soit de planifié | 🔴 | `git rev-list --count origin/main..develop` → **5** ; `git ls-tree origin/main` : `ReadCostSweepTest` et `check-i18n-keys.mjs` **absents**, `ReadCostRoutesTest` **présent**, `sbom` **absent** de `release.yml` |
| 2 | Borner chaque job **et** corriger les boucles à un conteneur par sonde | 🔴 | API des jobs : `images` **67,3 min** sur une étape bornée sur le papier à 3 min 30 ; la même attente par `docker exec` mesurée localement à **6 s** ; `grep timeout-minutes` → 4 dans `nightly.yml`, **0** dans `ci.yml` |
| 3 | Épingler et vérifier `cosign` | 🔴 | `release.yml:75-79` lu ; `git log -S` → introduit par `8b56333` le 27 août, jamais relevé depuis |
| 4 | Déclencher `release.yml` (après 1 et 3) | 🟠 | **affirmé, non exécuté** — 0 tag, 0 release, absent des 20 runs. Demande vos identifiants |
| 5 | Activer GitHub Pages puis relancer `docs` | 🟠 | `mkdocs build --strict` **passe** en local ; l'échec est `configure-pages`, et `has_pages: false` |
| 6 | Corriger « four engines » (README 348, 354, 438) et « 840 tests » (437), puis étendre la parité aux chiffres cités | 🟠 | `val engines = listOf("postgres","mysql","sqlite")` ; 3 répertoires de migration ; campagne 3 × 29 ; ADR 0009 **superseded** par 0014 ; `README.fr.md` correct |
| 7 | Épingler le compte de clés i18n, ou refuser le littéral | 🟡 | mutation : les deux libellés remis en dur → **146 tests verts, exit 0**, compteur 54 → 52 en silence |
| 8 | Un cas qui isole l'AAD de `SealedEnvelope` | 🟡 | mutation : AAD vidé → **1 échec sur 701**, et c'est le vecteur d'or, pas le test qui porte le nom |

**Les recommandations 4 et 5 demandent vos identifiants ou vos droits d'administration, pas du
code.** Les six autres sont du travail dans l'arbre. Et il faut le dire aussi clairement que la
dernière fois : **tant que la 1 n'est pas faite, la 7 et la 8 corrigent des tests que rien de
planifié n'exécute.**

---

## 7. Sur la baisse de note

Le prompt demande de dire, quand une note baisse, si le terrain s'est dégradé ou si un audit
précédent avait noté ce qu'il n'avait pas mesuré. Les deux, et pas dans les mêmes cases.

**Le terrain a bougé en 3.1, et le 3.2 est encore autre chose.** Cinq commits non fusionnés,
c'est un état, pas un défaut de conception, et il se règle par une fusion — mais un état qui vide de
son contenu tout ce qu'un tableau vert affirme. Le 3.2 est autre chose : un défaut qui tournait
depuis que ce job existe, vert à soixante-sept minutes la course, et que j'ai failli classer comme
un blocage passager. **M'être trompé au premier passage est ce qu'il faut en retenir** : j'ai
déduit un blocage d'un run seulement lent, et seule la mesure du job terminé a montré l'erreur
d'unité en dessous. L'axe vérification tombe à 6,5 pour les deux.

**Trois audits ont noté ce qu'ils n'avaient pas mesuré**, et il vaut mieux le nommer que le
répartir :
- le `curl` de `cosign` traverse quatre audits, dont celui d'hier qui a réécrit ce fichier ;
- « four engines » traverse cinq audits qui ont tous validé la parité bilingue en comptant des
  fichiers ;
- l'AAD de `SealedEnvelope` a été correctement identifié par le 18e audit et n'a pas été fermé.

**La qualité du code, elle, ne bouge pas, et c'est mérité.** `ReadCostSweepTest` est la meilleure
chose livrée dans cette série depuis `AuthorizationCoverageTest` : il remplace une liste par une
règle, il porte son propre garde-fou contre l'inspection vide, et il a trouvé trois routes qu'une
énumération ne pouvait pas trouver. Je l'ai fait échouer exprès pour le vérifier. Le contraste
avec `check-i18n-keys.mjs`, livré dans le même lot et incapable de voir son propre motif, est ce
que cet audit a de plus utile à dire sur la manière dont ce dépôt écrit ses règles : **une règle
se juge en la faisant échouer, jamais en la lisant.**
