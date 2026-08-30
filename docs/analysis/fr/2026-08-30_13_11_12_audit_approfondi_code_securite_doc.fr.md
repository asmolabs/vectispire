# Audit approfondi — code, sécurité, documentation

**30 août 2026, 13:11** · *English version: [`2026-08-30_13_11_12_in_depth_code_security_doc_audit.en.md`](../en/2026-08-30_13_11_12_in_depth_code_security_doc_audit.en.md)*

## Note globale : **8,4 / 10** — en baisse depuis 8,7

**La baisse est entièrement la mienne, et d'un audit précisément.** L'audit d'hier a conclu à
**10,0** sur l'axe vérification après avoir lu l'historique GitHub. Il a lu `verify` et `nightly`,
qui sont verts, et n'a pas demandé si les **deux autres** workflows avaient jamais tourné. Ils
n'ont pas : `docs` a échoué à son unique exécution, et **`release.yml` n'a jamais été déclenché** —
0 tag, 0 release, absent des 19 exécutions. C'est « un audit précédent avait noté ce qu'il n'avait
pas mesuré », et l'audit précédent est le mien, vieux de quinze heures.

**Le constat principal est un écart entre ce que la documentation promet d'une release et ce que le
workflow produit.** `GETTING_STARTED` §8 annonce, dans les deux langues, *« quatre fichiers : le
jar, son SBOM, et un paquet Sigstore pour chacun »*. `release.yml` en produit **deux**, ne mentionne
jamais de SBOM, et **ne crée aucune GitHub Release** : il téléverse un artefact de workflow à
rétention 90 jours. L'en-tête de ce même fichier met en garde contre exactement cette famille de
défaut.

| Domaine | Note | Mouvement |
|---|---|---|
| Documentation & Architecture | **8,0** | ↓ |
| Sécurité & Cryptographie | **8,5** | = |
| Qualité du code | **8,5** | ↑ |
| Conformité & Standards | **8,5** | = |
| **Vérification réellement exécutée** | **8,5** | ↓↓ |

---

## 0. État de remédiation — quatre des sept recommandations sont faites

*Ajouté après l'audit. Vérification : **1327 tests JVM** (1326 + le cas de redirection), **0 échec** ;
checkov **380 contrôles Actions, 0 échec** ; **774 liens, 0 cassé**.*

| # | Recommandation | Fait par | Preuve |
|---|---|---|---|
| 2 | Réconcilier `GETTING_STARTED` §8 avec le workflow | **Le workflow, pas le texte.** `release.yml` produit désormais le SBOM du jar signé (syft, au digest que `ci.yml` épingle), signe **les deux** fichiers et **vérifie les deux** avant publication. La phrase « quatre fichiers » devient vraie : jar, son bundle, SBOM, son bundle. | `grep -ci sbom release.yml` → **12** (était 0) ; checkov parse et valide |
| 3 | Publier une vraie GitHub Release | `gh release create` sur le tag, avec les quatre fichiers et l'identité de certificat dans les notes. `permissions: contents: write`, commenté sur place comme le seul workflow qui écrit. **Gardé derrière `if: startsWith(github.ref, 'refs/tags/')`** : la répétition générale tourne depuis une branche et ne doit rien publier, ce que « publishes nothing » a toujours voulu dire. | checkov 0 échec ; l'artefact 90 jours reste, pour que la répétition laisse quelque chose à inspecter |
| 5 | Mettre à jour `ROTATION_AND_PURGE` | Encadré réécrit dans les deux langues : la forge est GitHub, vérifiée par `git remote -v`, et **l'action restante concerne l'ancien dépôt, pas l'actuel — deux dépôts distincts, pas un renommage**. Le §2.1 porte maintenant le tableau de ce qui a été mesuré, et dit pourquoi le 404 non authentifié ne tranche toujours rien. | `grep -c 'désormais GitLab'` → **0** dans les deux fichiers |
| 7 | Garder la sonde de redirection | `PinnedHttpSenderTest` porte un cinquième cas : un vrai serveur répond `302 Location:` vers un hôte non vérifié, et le test exige un 302 non suivi. | **Retirer `disableRedirectHandling()` fait échouer ce cas** — il ne faisait échouer aucun test avant |

### Ce que la remédiation a appris

**Le §2 avait deux directions possibles et la bonne était la plus coûteuse.** Corriger le texte pour
dire « deux fichiers » était honnête et immédiat ; produire le SBOM rend la phrase vraie et donne au
consommateur la liste de composants signée qu'il lit pour décider si un avis le concerne. Un SBOM non
signé est une liste que n'importe qui peut réécrire, et c'est le seul fichier de la release dont le
contenu est une affirmation sur le reste.

**Le §3 a rouvert une question de permissions.** `release.yml` portait `contents: read`, avec ce
commentaire : *« tous les autres workflows de ce dépôt sont en lecture seule »*. Publier une release
exige `contents: write`. Le commentaire a été réécrit sur place plutôt que supprimé : c'est
exactement le genre d'élargissement qui doit se lire dans le diff.

### Ce qui reste, et pourquoi

| # | Recommandation | Pourquoi ce n'est pas fait ici |
|---|---|---|
| 1 | Déclencher `release.yml` | Demande `gh auth` et signe au nom du projet — une action sortante, pas la mienne à prendre |
| 4 | Commiter et pousser | Le commit est prêt ; la publication vous revient |
| 6 | Activer GitHub Pages | Réglage de dépôt exigeant les droits d'administration sur `asmolabs/vectispire` |

**Les trois demandent vos identifiants ou votre décision, pas du code.** Et il faut le dire
clairement : tant que le #1 n'est pas fait, le chemin de signature reste **affirmé et non exécuté**.
Ce que la remédiation change, c'est ce que ce chemin fera quand il tournera — elle ne le fait pas
tourner.

---

## 1. Ce que j'ai exécuté

| Contrôle | Commande | Résultat |
|---|---|---|
| Suites JVM, à froid | `./gradlew build --rerun-tasks` | **1326 tests, 0 échec, 0 erreur, 0 ignoré** (260 suites, 35 tâches) |
| Campagne multi-moteurs | `./gradlew integrationTestAll --rerun-tasks` | **PostgreSQL 29, MySQL 29, SQLite 29 — 87 tests, 0 échec** |
| Conteneurs à l'exécution | `:vectispire-common:integrationTest --rerun-tasks` | **14 cas, 0 échec**, démon vivant |
| Suite navigateur | `npx playwright test` | **13 passés** en 2,2 min, vrai plan de contrôle |
| Exercice de restauration | `bash scripts/restore-drill.sh` | **passé**, mutation intégrée comprise |
| Suites Angular | `npm test` | **146 tests, 23 fichiers, 0 échec**, + contrôle i18n : 54 clés, 2 bundles |
| `gitleaks` | image CI épinglée | **377 commits, 16,1 Mo, aucune fuite** |
| Politique Dockerfile / Actions | image checkov épinglée | **260 + 372 = 632 contrôles, 0 échec** |
| Liens relatifs | `python3 scripts/check-doc-links.py` | **754 liens, 0 cassé** |
| Dérive C4 | `shasum -a 256` vs `.workspace.sha256` | **en phase** |
| Parité bilingue | `find docs/{fr,en}` | **12 / 12** ; ADR **18 / 18** ; bflorat **6 / 6** |
| Isolation de l'agent | `:vectispire-agent:dependencies` | **0** JDBC / Hibernate / Flyway / JPA ; `ENCRYPTION_KEY` absent de `src/main` |
| Conformité, par le compte | `grep -c` sur le catalogue | **6 référentiels, 24 contrôles, 7 catégories, 3 plafonds** |
| **Historique GitHub** | API publique | **19 exécutions** — voir §3.1 et §4 |
| **Releases et tags** | `git tag`, API `/releases` | **0 et 0** — `release.yml` n'a jamais tourné |
| **Runbook de purge** | ses propres commandes, lancées | voir §3.2 |
| Écart de branches | `git rev-list --count origin/main..develop` | **0** |
| Arbre de travail | `git status --short` | **21 fichiers non commités** — voir §3.5 |

### Une note sur le prompt lui-même

`PROMPT_AUDIT.md` §5 décrit `.gitlab-ci.yml` comme *« le pipeline d'avant la bascule, conservé et
non maintenu »*. **Le fichier n'existe plus** — supprimé par `3668dfe`. Le prompt demande
explicitement de ne pas le croire sur parole ; vérifié, il a raison de le demander.
`ci/gitlab/vectispire-gate.gitlab-ci.yml`, le template livré aux clients, est bien là et reste
valide.

---

## 2. Tester mes propres tests

Trois mutations, toutes annulées, sur des règles que cette série n'avait jamais mutées.

| Mutation appliquée | Attendu | Observé |
|---|---|---|
| Une classe de `core` construisant son propre `HttpClient` — le « septième appelant » que la règle SSRF interdit | échec | **`ArchitectureTest` échoue** — *« an outbound call goes through the door that validates and pins »*, 6 violations |
| `ComplianceEngine` : `cappedByPlatform` retiré de la boucle d'évaluation | échec | **3 tests échouent** — secrets sans clé, journal sans miroir, gouvernance sans quatre yeux |
| `SealedEnvelope` : la clé éphémère retirée de l'AAD | échec | **1 test sur 11 échoue** — et pas celui qu'on croit, voir ci-dessous |
| `PinnedHttpSender` : `disableRedirectHandling()` retiré | échec | **aucun test n'échoue** — les 1326 passent, voir §3.4 |

### Ce que la troisième mutation apprend

Le test `refusesAnEnvelopeWhoseEphemeralKeyWasReplaced` porte ce commentaire : *« la clé de
l'émetteur est une donnée associée, donc l'échanger doit faire échouer l'authentification »*. **Il
n'échoue pas quand on retire l'AAD.** Il passe pour une autre raison : échanger la clé éphémère
change le secret partagé X25519, donc la clé de session, donc GCM échoue de toute façon. L'AAD est
une troisième ceinture sur une bretelle déjà double.

Ce qui attrape le retrait, c'est `anEnvelopeSealedByAnEarlierBuildStillOpens` — un **vecteur
littéral épinglé**. C'est la **troisième** occurrence de ce patron dans le projet, après
`IssueFingerprint` et `SecretCipher`, et les trois fois c'est lui qui tient le contrat quand les
tests de propriétés passent quand même. Cela mérite d'être nommé comme un patron du projet, pas
comme trois coïncidences.

---

## 3. Constats

### 3.1 🔴 La documentation promet quatre fichiers signés ; le workflow en produit deux, sans SBOM, et n'a jamais tourné

**Exécuté.** Trois mesures indépendantes, toutes concordantes.

```
git tag | wc -l                                   →  0
GET /repos/asmolabs/vectispire/releases           →  0 releases
GET /actions/runs (19 exécutions)                 →  release : absent
grep -ci 'sbom\|cyclonedx' .github/workflows/release.yml  →  0
grep -cE 'gh release|softprops|create-release'    →  0
```

**Ce que la documentation dit.** [`docs/en/GETTING_STARTED.md:161`](../../en/GETTING_STARTED.md) et
[`docs/fr/GETTING_STARTED.fr.md:186`](../../fr/GETTING_STARTED.fr.md), à l'identique :

> *Chaque release porte quatre fichiers : le jar, son SBOM, et un paquet Sigstore pour chacun.
> Vérifiez avant de lancer quoi que ce soit — un outil de sécurité pris sur parole est une
> contradiction.*

**Ce que le workflow fait.** [`release.yml`](../../../.github/workflows/release.yml), étape finale :

```yaml
      - uses: actions/upload-artifact@…
        with:
          name: release
          path: |
            ${{ env.JAR }}
            ${{ env.JAR }}.cosign.bundle
          retention-days: 90
```

**Deux** fichiers. Aucun SBOM n'est généré ni signé nulle part dans ce workflow — le job `sbom`
existe, mais dans `ci.yml`, et ses artefacts ne rejoignent jamais une release. Et il n'y a **pas de
GitHub Release du tout** : un artefact de workflow n'est téléchargeable que par quelqu'un de
connecté qui sait retrouver l'exécution, et il disparaît au bout de 90 jours.

**Trois affirmations fausses, donc, dans la section qui apprend à ne rien prendre sur parole :** le
nombre de fichiers, l'existence du SBOM signé, et le canal de distribution.

**Pourquoi c'est le constat le plus lourd.** L'en-tête de `release.yml` met en garde contre
précisément ce défaut, en connaissance de cause :

> *Ce projet a déjà livré une documentation disant aux utilisateurs de vérifier contre un émetteur
> qui n'était pas celui qui signait — une instruction qui ne peut pas réussir, ce qui est pire que
> rien : elle apprend à son lecteur que le contrôle est passé le jour où il le tape de travers.*

Et plus bas, sur l'étape de vérification : *« c'est ce qui fait de l'instruction de
GETTING_STARTED une affirmation testée plutôt qu'une affirmation pleine d'espoir »*. Cette phrase
est elle-même affirmée et non exécutée : le `workflow_dispatch` existe précisément comme
« répétition générale », et il n'a **jamais** été déclenché.

**Ce qui est juste et ne doit pas être défait.** La commande de `GETTING_STARTED` est correcte dans
sa forme : elle épingle le fichier de workflow **et** le tag dans `--certificate-identity`, exige
`--certificate-oidc-issuer`, et utilise un `--bundle`. Les trois paragraphes qui expliquent
pourquoi chaque partie compte sont justes. C'est le décor autour qui décrit autre chose que ce qui
existe.

**Recommandation, par ordre de coût croissant.**
1. Déclencher `release.yml` par `workflow_dispatch` — sa raison d'être déclarée — pour que le
   chemin de signature ait tourné une fois avant de compter sur lui.
2. Corriger la phrase des deux `GETTING_STARTED` pour dire deux fichiers, ou ajouter le SBOM et sa
   signature au workflow pour qu'elle devienne vraie. La seconde est mieux ; la première est
   honnête tout de suite.
3. Publier une vraie GitHub Release (`gh release create`) plutôt qu'un artefact à rétention, sans
   quoi la procédure §8 n'a pas de fichier à vérifier.

**Vérification : exécutée** — commandes ci-dessus.

### 3.2 🟠 Un runbook de sécurité oriente son lecteur vers la mauvaise forge, et déclare impossible une vérification qui ne l'est plus

**Exécuté.** [`docs/en/ROTATION_AND_PURGE.md:116`](../../en/ROTATION_AND_PURGE.md) et
[`docs/fr/ROTATION_AND_PURGE.fr.md:116`](../../fr/ROTATION_AND_PURGE.fr.md) portent le même
encadré :

> *Le remote du projet est désormais GitLab : quiconque rejoue la procédure a besoin de
> l'équivalent GitLab — sa demande de support, sa vérification des forks.*

`git remote -v` → `git@github.com:asmolabs/vectispire.git`. **Le remote est GitHub.** Ce document
est le seul de l'arbre à porter encore cette affirmation : `grep` sur tous les `docs/*.md`,
`README*.md` et `SECURITY.md` ne remonte que ces lignes-là, les autres mentions de GitLab étant des
intégrations client légitimes. `GETTING_STARTED.md:186` dit d'ailleurs correctement *« le projet est
passé de GitLab à… »*.

**Et le §2.1 déclare sa propre vérification impraticable :**

> *Ces commandes n'ont pas pu être lancées de façon concluante ici : `gh` n'est pas authentifié sur
> cette machine et le dépôt est privé, donc les 404 obtenus ne veulent rien dire.*

Le dépôt **n'est plus privé**. Lancées aujourd'hui :

| Vérification | Résultat |
|---|---|
| `GET /repos/asmolabs/vectispire` | `visibility: public`, `forks_count: 0`, `network_count: 0`, créé le **2026-08-27** |
| Les cinq anciens SHA contre le dépôt **actuel** | **422** × 5 — objets absents |
| `git rev-list --objects --all \| grep -iE '\.sqlite\|id_rsa\|\.pem$'` | **vide**, sur 391 commits |
| `gitleaks` sur 377 commits | **aucune fuite** |

**Ce que cela règle et ce que cela ne règle pas.** Le dépôt courant est propre : il a été créé le
27 août, ne porte aucun artefact de l'incident, et n'a aucun fork. La question ouverte du §2 porte
sur l'**ancien** dépôt `Asmo1973/Vectispire`, qui répond 404 non authentifié — et le document a
raison de dire qu'un 404 non authentifié ne prouve rien. L'action reste ouverte ; ce sont les faits
qui l'entourent qui ont pourri.

**Pourquoi cela compte plus qu'une coquille.** C'est un document qui décrit une exposition de
secrets et dont l'unique fonction est d'orienter quelqu'un vers une action restante. Un lecteur qui
le suit aujourd'hui part chercher un formulaire de support GitLab pour un projet hébergé sur
GitHub, sur la foi d'une phrase écrite à l'indicatif présent.

**Recommandation.** Mettre l'encadré à jour — la forge est GitHub, le dépôt courant est public et
propre, et l'action restante concerne l'ancien dépôt — et remplacer le §2.1 par ce qui a été mesuré
ici. Garder le corps de la procédure tel quel : le document a raison de ne pas réécrire un
compte-rendu en instruction. **Vérification : exécutée.**

### 3.3 🟡 Le quatrième workflow échoue toujours, et le site qu'il publie n'existe pas

Rapporté hier en addendum, **inchangé et revérifié aujourd'hui** :

```
GET /repos/asmolabs/vectispire/pages   →  404   (Pages non activé)
GET https://asmolabs.github.io/vectispire/  →  404
```

`docs` #1, 29 août 19:31 UTC, reste la seule exécution du workflow et reste en échec au pas
`actions/configure-pages`. [`mkdocs.yml:1`](../../../mkdocs.yml) (et `site_url:` ligne 16) et
[`.github/workflows/docs.yml:1`](../../../.github/workflows/docs.yml) annoncent toujours le site au
présent. C'est un réglage de dépôt qui demande les droits d'administration — non fait ici,
délibérément.

### 3.4 🟡 Le refus des redirections peut être retiré sans qu'aucun test ne bouge — mais la seconde ceinture tient

**Exécuté, et le résultat corrige ce que je cherchais.** Retirer `.disableRedirectHandling()` de
[`PinnedHttpSender`](../../../vectispire-java/vectispire-core/src/main/java/com/asmolabs/vectispire/core/services/PinnedHttpSender.java)
laisse **les 1326 tests verts**. Les quatre cas de `PinnedHttpSenderTest` couvrent l'épinglage DNS
et aucun ne couvre le refus des redirections, que le code affirme pourtant en gras.

**J'ai supposé une faille SSRF et la mesure a dit non.** Sonde écrite pour l'occasion : un serveur
« approuvé » qui répond `302 Location:` vers un second serveur sur un hôte non vérifié.

| Configuration | Résultat de la sonde |
|---|---|
| Code livré | `status=302`, corps vide — redirection non suivie |
| Redirections réactivées | **refusée** — *« the request tried to reach a host that was never checked (elsewhere.invalid was not the checked host (approved.invalid)) »* |

Le résolveur épinglé attrape ce que la redirection désactivée aurait laissé passer, exactement
comme sa javadoc l'annonce — *« une redirection que quelqu'un aurait réactivée »*. **C'est de la
défense en profondeur, revendiquée et désormais mesurée.**

**Ce qui reste est mineur et vaut d'être posé** : la couche externe part sans bruit. Un cas qui
lance un vrai 302 vers un hôte non vérifié et exige un 302 non suivi coûte quinze lignes — la sonde
ci-dessus, gardée au lieu d'être jetée. **Vérification : exécutée.**

### 3.5 🟠 Tout le travail de remédiation d'hier est non commité, donc aucun runner ne l'a vu

**Exécuté.** `git status --short | wc -l` → **21**. `git rev-list --count origin/main..develop` →
**0**.

Le nocturne de ce matin (#2, 30 août 08:29 UTC) a tourné sur `dfbd7f8f`, la tête commune de `main`
et `develop`. Il n'a donc **pas** exécuté : le balayage de coût de lecture `ReadCostSweepTest`, les
trois correctifs qu'il garde (EPSS, scorecard, chemins d'attaque), le contrôle `check-i18n-keys.mjs`
ni les libellés de fournisseur traduits.

Ce n'est pas un défaut du produit ; c'est l'écart exact que cet axe mesure. Une garantie qui n'a
tourné que sur un poste de travail est une garantie plus forte qu'un fichier relu, et plus faible
qu'un pipeline vert. **Recommandation :** commiter et pousser. Le coût est nul et cela déplace
quatre contrôles de « exécuté ici » vers « exécuté sur le runner ».

---

## 4. Ce qui est vérifié sain

- **Le pipeline qui tourne, tourne bien.** `verify` #16 sur `main` : dix jobs verts — `c4-drift`,
  `secrets`, `jvm`, `dockerfile-policy`, `npm-audit`, `frontend`, `links`, `images`, `sbom`,
  `vulnerabilities`. `nightly` s'est déclenché **deux fois depuis `main`**, les deux fois vert, la
  seconde ce matin sur la tête courante ; ses quatre jobs — `e2e`, `dockerfiles`, `restore`,
  `databases` — sont passés. Sur 19 exécutions : 12 succès, 4 annulations (concurrence), 3 échecs
  dont les deux premières du portage et `docs`.
- **La règle SSRF est architecturale et elle mord.** Voir §2. Trois classes seulement peuvent tenir
  un client HTTP, la règle est écrite sur le nom complet pour couvrir les classes anonymes, et une
  quatrième classe la fait échouer immédiatement.
- **Le plafonnement de conformité est couvert.** Les trois arms — secrets sans clé, journal sans
  miroir, gouvernance sans quatre yeux — font échouer un test chacun quand on les retire. Un
  contrôle n'est jamais déclaré conforme sur la foi d'un mécanisme éteint, et c'est testé.
- **Conformité, par le compte.** 6 référentiels, **24** `new ComplianceControl`, **7** catégories
  dans `evaluateControl`, **3** plafonds. « Un évaluateur de posture, six cartographies » est exact.
- **Cryptographie de transit.** `SealedEnvelope` : 11 cas, X25519 + HKDF + GCM, préfixe
  `sealed:v1:`, clé éphémère par enveloppe. Deux seals du même secret diffèrent — vérifié.
- **Isolation de l'agent.** 0 pilote JDBC, 0 Hibernate, 0 Flyway, 0 JPA sur le classpath
  d'exécution ; `ENCRYPTION_KEY` n'apparaît nulle part dans `vectispire-agent/src/main`.
- **Historique propre.** 391 commits, aucun `.sqlite`, aucune clé privée, aucune fuite gitleaks.
- **Portabilité.** 87 tests sur trois moteurs ; `SchemaParityIntegrationTest` vert partout.
- **Documentation.** 754 liens 0 cassé, C4 en phase, 12/12 par langue, ADR 0001→0017 dans les deux
  langues, 6/6 vues bflorat par langue.
- **Le balayage de coût de lecture, en tant qu'auditeur de mon propre travail d'hier.** Il tourne
  dans les 1326, il énumère la table de routage de Spring plutôt qu'une liste, et il compte les
  entités **et** les requêtes.

---

## 5. Vérification réellement exécutée — 8,5, et pourquoi la note tombe de 10,0

**Le terrain ne s'est pas dégradé.** Rien n'a cessé de fonctionner entre hier soir et aujourd'hui ;
`verify` et `nightly` sont exactement aussi verts. Ce qui a changé, c'est que j'ai posé une question
que je n'avais pas posée.

L'addendum d'hier a lu l'historique, constaté que les deux workflows qu'il regardait étaient verts,
et conclu à 10,0 — *« chaque contrôle dont le projet se réclame est présent et s'exécute et passe »*.
Il y a **quatre** workflows. Les deux autres :

- **`release.yml` n'a jamais été déclenché.** C'est le workflow qui signe ce que les utilisateurs
  exécutent, et le seul à porter `id-token: write`. Zéro exécution, zéro tag, zéro release.
- **`docs` a échoué à son unique exécution**, et échouera à la suivante pour la même raison.

Une garantie non exécutée n'est pas une garantie. Le chemin de signature d'une release — build, jar
nommé d'après le tag, cosign, vérification avec la commande de l'utilisateur — est entièrement
affirmé et entièrement non exécuté. 8,5 est ce que valent deux workflows verts sur quatre, dont le
plus critique n'a jamais démarré.

**Et il faut y ajouter le §3.5** : la remédiation d'hier n'est sur aucun runner.

---

## 6. Recommandations, par priorité

| # | Constat | Action | Comment cela a été vérifié |
|---|---|---|---|
| 1 | §3.1 | Déclencher `release.yml` par `workflow_dispatch` — la répétition générale que son commentaire décrit | **Exécuté** — 0 exécution sur 19, 0 tag, 0 release |
| 2 | §3.1 | Réconcilier `GETTING_STARTED` §8 avec le workflow : soit deux fichiers dans le texte, soit le SBOM et sa signature dans le workflow | **Exécuté** — `grep -ci sbom release.yml` → 0, l'étape upload liste deux chemins |
| 3 | §3.1 | Publier une GitHub Release plutôt qu'un artefact à 90 jours, sans quoi §8 n'a rien à vérifier | **Exécuté** — aucune action de release dans le workflow |
| 4 | §3.5 | Commiter et pousser les 21 fichiers, pour que le balayage et les trois correctifs passent sur un runner | **Exécuté** — `git status`, `git rev-list` |
| 5 | §3.2 | Mettre à jour l'encadré et le §2.1 de `ROTATION_AND_PURGE` dans les deux langues | **Exécuté** — `git remote -v`, API dépôt, cinq SHA, historique |
| 6 | §3.3 | Activer Pages (`source: GitHub Actions`) puis relancer `docs`, ou corriger la phrase des deux fichiers | **Exécuté** — API Pages 404, site 404 |
| 7 | §3.4 | Garder la sonde de redirection comme cas de test | **Exécuté** — mutation, 1326 verts ; sonde, refusée par le pin |

---

## 7. Ce que cet audit n'a pas pu mesurer

- **Le chemin de release, de bout en bout.** Le déclencher publierait ou signerait au nom du projet ;
  c'est une action sortante que je n'ai pas faite. Tout le §3.1 est de la lecture de configuration
  et de l'interrogation d'API, pas une exécution du workflow.
- **`gh` n'est pas authentifié.** Toutes les données de forge de ce rapport viennent de l'API
  publique. Cela suffit pour les exécutions, les tags, les releases, Pages et les forks du dépôt
  courant ; cela ne suffit pas pour statuer sur l'**ancien** dépôt `Asmo1973/Vectispire`, dont le
  404 reste ambigu — exactement ce que le §2.1 du runbook dit déjà.
- **L'échelle.** Le coût des lectures est mesuré à 220 constats sur SQLite.
- **L'agent, de bout en bout.** Isolation prouvée par le classpath ; aucun processus agent démarré.
- **La construction d'image par Jib** — inchangé, bloquée sur un pull Docker Hub non authentifié.

---

*Arbre de travail : cet audit a ajouté une classe sonde et une sonde de redirection puis les a
retirées, et appliqué quatre mutations temporaires, toutes annulées. `git status` montre les mêmes
**21** fichiers qu'à l'ouverture — la remédiation de l'audit précédent, toujours non commitée. Le
`./gradlew build --rerun-tasks` final a exécuté les 35 tâches à froid : 1326 tests, 0 échec.*
