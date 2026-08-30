# Audit approfondi — code, sécurité, documentation

**29 août 2026, 22:03** · *English version: [`2026-08-29_22_03_19_in_depth_code_security_doc_audit.en.md`](../en/2026-08-29_22_03_19_in_depth_code_security_doc_audit.en.md)*

## Note globale : **8,7 / 10** — en hausse depuis 8,4

**Le premier audit de la série où rien n'est resté « affirmé, non exécuté » faute d'outil.** Docker
était là, et les deux contrôles que chaque audit précédent avait dû laisser ouverts — `gitleaks` et
la politique Dockerfile/Actions — ont tourné pour la première fois. Ils sont verts : **377 commits
scannés, aucune fuite** ; **632 contrôles checkov, 0 échec**.

**Les deux constats du 21:10 sont fermés, et vérifiés par mutation plutôt que par relecture.**
Remettre l'ancienne condition des quatre yeux fait échouer les deux cas ajoutés ; remettre un
`findAll` fait échouer l'épinglage du coût de lecture. Ce ne sont pas des assertions qui ne peuvent
pas échouer.

**Et la même mesure, élargie, en a trouvé trois de plus.** Le §3.2 du 21:10 corrigeait quatre routes
et en épinglait quatre. L'épinglage ne couvre que celles-là. Un balayage des **40 points d'entrée
GET sans paramètre** montre que **trois autres** chargent tout le parc — dont un qui y ajoute un
N+1 franc, **468 requêtes pour 620 constats**.

| Domaine | Note | Mouvement |
|---|---|---|
| Documentation & Architecture | **8,5** | ↓ — voir §8 |
| Sécurité & Cryptographie | **8,5** | ↑ |
| Qualité du code | **8,0** | = |
| Conformité & Standards | **8,5** | ↑ |
| **Vérification réellement exécutée** | **10,0** | ↑ — voir §8 |

*Deux notes ont bougé **après** la rédaction, quand `gh` a été installé et l'historique des
exécutions enfin lu. La note globale ne bouge pas ; sa composition, si. Le détail est au §8.*

---

## 0. État de remédiation — les deux constats sont fermés, et la règle en a trouvé quatre de plus

*Ajouté après l'audit. Vérification complète après les changements : **1326 tests JVM, 0 échec**,
campagne trois moteurs verte, **146 tests Angular**, **13 cas Playwright** contre un plan de
contrôle vivant.*

### Ce qui a été fait, dans l'ordre où la méthode l'exige

**Le balayage a été écrit en premier, et il était rouge avant tout correctif.** C'est le seul ordre
qui prouve quelque chose : corriger d'abord et écrire le test ensuite produit une assertion qui ne
peut plus échouer, ce que ce projet a livré trois fois.

| # | Constat | Fermé par | Preuve qu'il peut échouer |
|---|---|---|---|
| §3.1 | `/epss/priorities` — N+1 **et** lecture de table | `ThreatIntelFeedService.lookupCves` lit l'intel en une requête et conserve le repli sur le catalogue curé ; la lecture passe par une projection `IssueRows.EpssRow` ; `topPriorities` est enfin un *top* (50), les compteurs agrégés continuant de peser tout le parc. | Le lot remis en boucle → le balayage échoue sur **+150 requêtes** ; le plafond retiré → `EpssRoutesTest` échoue. |
| §3.1 | `/scorecards/global` — lecture de table | Projection `IssueRows.Posture` (quatre colonnes) aux trois sites de `SecurityScorecardService`. | `findAll` remis → le balayage échoue sur **+200 entités**. |
| §3.1 | `/attack-paths/overview` — lecture **et réponse** non bornées | Projection `IssueRows.GraphNode`, plus un plafond de **10 nœuds par cible**, classés KEV → gravité → atteignabilité. Le score de risque se calcule sur ce qui a été trouvé, pas sur ce qui est dessiné. | Plafond retiré → `AttackPathRoutesTest` échoue. |
| §3.2 | Libellés de fournisseur en dur | `aiProviders` devient un `computed` passant par `i18n.t`, clés ajoutées aux **deux** bundles. | Clé retirée de `fr.json` → `check-i18n-keys.mjs` échoue. |

### La règle a trouvé ce que ma liste avait manqué

`ReadCostSweepTest` énumère la table de routage de Spring plutôt qu'une liste de chemins. Au
premier passage il a signalé **sept** routes, pas trois : les quatre que mon audit ignorait sont
`/vex/aggregate.json`, `/cyclonedx/aggregate.json`, `/csaf/aggregate.json` et
`/compliance/evidence-bundle.zip`.

Vérification faite, **ces quatre-là sont légitimes** : ce sont des exports documentaires dont la
charge utile contient une entrée par constat, donc une lecture en O(n) pour une réponse en O(n).
Elles sont dans `MAY_GROW` avec l'argument, et cette distinction est ce que la règle encode : une
lecture qui suit le parc est un défaut quand la *réponse* ne le suit pas.

### Une assertion qui ne pouvait pas échouer, attrapée sur mon propre correctif

Après avoir corrigé le N+1 de l'EPSS, je l'ai remis — **et le balayage est resté vert.** Il ne
mesurait que les entités chargées, pas les requêtes émises, donc il aurait validé la moitié du
correctif indéfiniment. Le balayage compte désormais les deux, et le second compteur ne consulte
**aucune** liste d'exemptions : un export peut légitimement lire n lignes, jamais émettre n
requêtes. Remuté, il échoue maintenant sur `+150 requêtes`.

### Une correction sur ce que j'affirmais du plafond du graphe

J'avais écrit que scorer le graphe coupé le ferait paraître plus sûr. La mesure dit non :
`calculateRiskScore` sature ses deux termes de constats — `Math.min(3, vulnCount)`, et un compte de
secrets qui atteint le plafond de 100 dès quatre — donc avec une coupe à dix, **le score ne peut
pas bouger**. Le service le calcule quand même sur ce qui a été trouvé, parce que l'équivalence
cesse dès qu'on abaisse le plafond ou qu'on repondère la formule ; et le test dit ce qui est
vérifiable plutôt que ce que j'avais supposé.

### `ReadCostRoutesTest` a été replié dans le balayage

Il épinglait quatre routes nommées avec la même fixture et le même compteur. Tout ce qu'il
affirmait l'est désormais sur l'ensemble de la surface, donc le garder ferait deux copies d'une
règle — et la copie périmée est celle qui cesse d'être mise à jour. Vérifié plutôt que supposé : le
`findAll` de `SlaService` remis fait échouer le balayage sur `/compliance/summary` **et** sur
`/compliance/export.pdf`, que l'ancien test ne couvrait pas.

---

## 1. Ce que j'ai exécuté

| Contrôle | Commande | Résultat |
|---|---|---|
| Suites JVM, à froid | `./gradlew build --rerun-tasks` | **1326 tests, 0 échec, 0 erreur, 0 ignoré** (260 suites, 35 tâches) |
| Campagne multi-moteurs | `./gradlew integrationTestAll --rerun-tasks` | **PostgreSQL 29, MySQL 29, SQLite 29 — 87 tests, 0 échec** |
| Conteneurs à l'exécution | `./gradlew :vectispire-common:integrationTest --rerun-tasks` | **14 cas, 0 échec**, contre un démon vivant |
| Suite navigateur | `npx playwright test` (depuis `vectispire-angular/`) | **13 passés** en 2,2 min, vrai plan de contrôle, vrai Chromium |
| Exercice de restauration | `bash scripts/restore-drill.sh` | **passé**, mutation intégrée comprise |
| **`gitleaks`** | image CI épinglée, `detect --config .gitleaks.toml --baseline-path …` | **377 commits, 16,1 Mo, aucune fuite** — *jamais exécuté avant cet audit* |
| **Politique Dockerfile / Actions** | image checkov épinglée, `--framework dockerfile,github_actions` | **260 + 372 = 632 contrôles, 0 échec** — *jamais exécuté avant cet audit* |
| Image livrée | `docker build -f Dockerfile -t vectispire:audit .` | **construite, 347 Mo** |
| Suites Angular | `npm test` | **146 tests, 23 fichiers, 0 échec** |
| Liens relatifs | `python3 scripts/check-doc-links.py` | **740 liens, 0 cassé** |
| Dérive C4 | `shasum -a 256` vs `diagrams/.workspace.sha256` | **identiques — en phase** |
| Parité bilingue | `find docs/{fr,en} -name '*.md'` | **12 / 12** |
| Registre ADR | `ls docs/architecture/{en,fr}/decisions/` | **0001 → 0017**, deux langues, 18 fichiers chacune |
| Vues bflorat | `ls docs/architecture/bflorat/{en,fr}/` | **5 / 5** dans chaque langue |
| Isolation de l'agent | `./gradlew :vectispire-agent:dependencies --configuration runtimeClasspath` | **0** occurrence de `jdbc`, `postgres`, `mysql`, `sqlite`, `hibernate`, `flyway`, `jpa` |
| Empreinte — vecteur littéral | mutation, ci-dessous | **épinglé, et il mord** |
| **Coût des lectures, 40 routes** | compteurs Hibernate, 3 tailles de parc | **trois points d'entrée linéaires — §3.1** |
| Écart de branches | `git rev-list --count origin/main..develop` | **0** — le §3.3 du 21:10 est fermé |
| Historique GitHub | *initialement* **non exécuté** — pas de CLI `gh` | **exécuté depuis** — `gh` installé, 19 exécutions lues, voir §8 |

### Une correction sur ma propre méthode, consignée

Ma première `./gradlew integrationTestAll` a rendu `BUILD SUCCESSFUL in 673ms`, **18 tâches
up-to-date**. C'est exactement l'erreur que le prompt interdit sur les jobs CI — *un job déclaré
n'est pas un job qui a tourné* — appliquée à Gradle : **une tâche `UP-TO-DATE` n'est pas une tâche
qui s'est exécutée.** Relancée avec `--rerun-tasks`, la campagne prend 2 min 23 et exécute vraiment
les 87 tests. Aucun chiffre de ce rapport ne vient d'un cache.

De même, ma première `npx playwright test` a été lancée depuis la racine et a ramassé les fichiers
`.spec.ts` de Vitest. La configuration Playwright est dans `vectispire-angular/`, et c'est de là que
le job nocturne la lance.

---

## 2. Tester mes propres tests

Quatre mutations, toutes annulées, dont trois sur des assertions que cette série n'avait jamais
mutées.

| Mutation appliquée | Attendu | Observé |
|---|---|---|
| `IssueFingerprint.of` : `target` et `type` **permutés** — le défaut exact établi le 26 août | échec | **1 test sur 8 échoue** — *« a known finding has a known fingerprint »*. Les sept tests de propriétés restent verts, ce qui est précisément la raison d'être du vecteur littéral. |
| `SecretCipher` : l'**AAD de contexte** remplacée par une constante des deux côtés | échec | **3 tests échouent** — *« a value written with a context does not read without one »*, *« a ciphertext moved to another row does not decrypt »*, et *« a secret sealed by an earlier build still opens »* |
| `IssueTriageService.queueIfNotApprover` : recondition sur `NOT_AFFECTED` au lieu de `isSettled()` | échec | **2 tests échouent** — les deux cas ajoutés par la remédiation du 21:10 |
| `ScorecardController` : ajout d'une route nommant une cible sans garde | échec | **`RouteScopingTest` échoue** ; **`AuthorizationCoverageTest` passe** |

**La quatrième mérite un mot.** Les deux règles ne sont pas redondantes, et la plus grossière ne
voit pas ce que la plus fine attrape : le contrôleur mentionne toujours `VisibilityService` ailleurs
dans le fichier, donc le lint de classe est satisfait. C'est mot pour mot l'angle mort que
`RouteScopingTest` documente dans son propre en-tête — *« la vingt-quatrième fuite est passée par
là »* — et il est désormais vérifié par mesure, pas seulement raconté.

**La deuxième aussi.** *« a secret sealed by an earlier build still opens »* est un vecteur
littéral de la même famille que celui de l'empreinte : un chiffré écrit par une version antérieure,
stocké en dur, qui doit continuer à s'ouvrir. Deux contrats de données du projet sont épinglés de
cette façon, et les deux mordent.

---

## 3. Constats

### 3.1 🟠 Trois points d'entrée chargent tout le parc — et l'un d'eux le fait en N+1

**Exécuté.** Une sonde temporaire a balayé les **40 routes GET sans paramètre** de la surface HTTP,
compteurs Hibernate `getEntityLoadCount` / `getQueryExecutionCount`, en tant qu'administrateur, à
20 puis 220 puis 620 constats.

| Route | charg. 20 / 220 / 620 | requêtes 20 / 220 / 620 |
|---|---|---|
| `/api/v1/epss/priorities` | 23 / 223 / **623** | 18 / 168 / **468** |
| `/api/v1/scorecards/global` | 24 / 224 / **624** | 5 / 5 / 5 |
| `/api/v1/attack-paths/overview` | 18 / 168 / **468** | 4 / 4 / 4 |
| `/api/v1/dashboard` *(témoin, corrigé le 21:10)* | 3 / 3 / 3 | 15 / 15 / 15 |
| `/api/v1/repositories` *(témoin borné)* | 3 / 3 / 3 | 3 / 3 / 3 |

Les deux témoins sont plats : **le correctif du 21:10 tient**, et le contraste est ce qui rend les
trois premières lignes non ambiguës.

**`/api/v1/epss/priorities` est le pire des trois, et pour deux raisons cumulées.** Le nombre de
*requêtes* croît lui aussi — c'est un vrai N+1, pas seulement une lecture de table. Dans
[`EpssPrioritizationService.getFleetSummary`](../../../vectispire-java/vectispire-core/src/main/java/com/asmolabs/vectispire/core/services/EpssPrioritizationService.java),
la boucle `for (IssueEntity issue : openIssues)` appelle `threatIntelService.lookupCve(cveId)`, qui
exécute `intelRepo.findByCveIdIgnoreCase(...)` — **une requête par constat ouvert**. S'y ajoutent
deux `findAll()` en tête de méthode (dépôts et conteneurs, matérialisés en `Map`).

**`/api/v1/attack-paths/overview`** charge les constats ouverts du périmètre visible via
`findByStateAndRepoIdIn("open", repoIds)` puis parcourt tout en Java
([`AttackPathService`](../../../vectispire-java/vectispire-core/src/main/java/com/asmolabs/vectispire/core/services/AttackPathService.java),
lignes 336–344). Le coefficient est ~0,75 n parce que la fixture n'ouvre que trois constats sur
quatre — la pente suit les constats ouverts, pas la table entière, ce qui est la même maladie à un
facteur près.

**`/api/v1/scorecards/global`** est le cas le plus simple : coût constant en requêtes, linéaire en
entités matérialisées.

**Ce qui est juste, et qu'il ne faut pas défaire.** Les trois routes résolvent correctement une
`Visibility` — `visibility.of(...)` sur `EpssController:44` et `ScorecardController:75`,
`allowanceOf(principal)` sur `AttackPathController:66`. **Ce n'est pas un constat de cloisonnement.**
Le commentaire de `getFleetSummary` raconte d'ailleurs qu'il en fut un — *« aucune visibilité du
tout, donc un lecteur restreint recevait la liste classée des vulnérabilités les plus exploitables
de toutes les autres cibles »* — et que cela a été réparé. Le coût est ce qui reste.

**Pourquoi le 21:10 ne les a pas vues.** Il a mesuré les routes qu'il soupçonnait à partir des sites
`findAll` qu'il avait lus, puis a épinglé celles-là. `ReadCostRoutesTest` couvre quatre routes
nommées. Ce n'est pas du terrain qui se dégrade : **c'est un audit précédent qui a noté ce qu'il
n'avait pas mesuré**, pour la seconde fois de suite sur exactement ce sujet.

**Recommandation.** Deux choses, et la seconde compte plus que la première.
1. Projeter les colonnes plutôt que matérialiser les lignes aux trois sites, comme `IssueRows` le
   fait déjà pour les cinq lectures converties le 21:10 ; et pour l'EPSS, remplacer le
   `lookupCve` par constat par une seule lecture `findByCveIdInIgnoreCase(...)` chargée en `Map`
   avant la boucle.
2. **Faire du balayage la règle plutôt que la liste.** `ReadCostRoutesTest` énumère quatre routes ;
   une version qui parcourt la surface GET et échoue sur *toute* route dont le compte suit la taille
   du parc aurait attrapé ces trois-là le 21:10, et attrapera la prochaine. La liste des exemptions
   — les routes légitimement paginées — est un argument qu'on écrit, exactement comme
   `NAMES_NO_TARGET` dans `RouteScopingTest`.

**Vérification : exécutée** — tableau ci-dessus, trois tailles, sonde retirée depuis.

### 3.2 🟡 Une chaîne anglaise en dur sur un écran par ailleurs traduit — ouvert depuis trois audits

Rapporté le 29 août à 20:04 (§3.6), puis à 21:10 (§3.4), inchangé.
[`settings.ts:143-146`](../../../vectispire-angular/src/app/pages/settings/settings.ts) construit
`aiProviders` à partir de littéraux — `'Ollama — a model on a host you run'`, `'OpenAI-compatible
API'` — alors que les libellés voisins passent par `this.i18n.t(…)`.

**Mesuré cette fois plutôt qu'affirmé :** les deux bundles aplatis comptent **661 clés en français
et 609 en anglais**, avec **52 clés françaises sans équivalent anglais et aucune l'inverse**. Aucune
de ces 52 ne concerne les fournisseurs — `grep -i 'ollama\|provider'` sur les deux fichiers ne
retourne rien. Les 52 restent voulues : `settings.ts:379` lit `translated !== key ? translated :
setting.label`, donc l'anglais retombe sur le libellé serveur et seul le français a besoin d'une
surcharge.

---

## 4. Ce qui est vérifié sain

Exécuté cette fois, et correct.

- **Secrets.** `gitleaks` sur **377 commits** et 16,1 Mo d'historique : aucune fuite. La ligne de
  base et la configuration ne sont plus « lues, pas exécutées ».
- **Politique d'image et de pipeline.** checkov, à l'image que `ScannerImages` épingle, sur
  `dockerfile` et `github_actions` : **632 contrôles, 0 échec, 2 ignorés**. Le job est bloquant en
  CI et il passe ici.
- **Cryptographie au repos.** AES-256-GCM, nonce 12 o, tag 128 bits, préfixe `v2:`, AAD de contexte
  — la mutation du §2 prouve que l'AAD est réellement liante et pas décorative.
- **Mots de passe.** `PasswordHasher` : `MEMORY_KIB = 19 * 1024`, `ITERATIONS = 2`,
  `PARALLELISM = 1`, sortie PHC `$argon2id$v=19$m=…,t=…,p=…$…`. Les paramètres voyagent avec
  l'empreinte, et `PasswordHasher:128` compare les paramètres stockés aux courants pour décider
  qu'un rehachage est dû — relever le coût n'invalide donc pas l'existant, comme annoncé.
- **Isolation de l'agent.** Le classpath d'exécution de `vectispire-agent` ne contient **aucun**
  pilote JDBC, ni Hibernate, ni Flyway, ni JPA. `ENCRYPTION_KEY` n'apparaît dans tout le module que
  dans `AgentIsolationTest`, c'est-à-dire dans le test qui affirme son absence.
- **Bac à sable.** 14 cas contre un démon vivant : toutes les capacités retirées, aucun gain de
  privilège, système de fichiers de l'image non modifiable, réseau coupé sauf demande explicite,
  scanner trop long arrêté et non abandonné. Aucun socket Docker n'est monté dans un scanner ; les
  deux montages de `docker-compose.yml` (lignes 81 et 125) sont ceux du plan de contrôle et de
  l'agent, ce qui est la raison d'être du bac à sable et non une exception à sa règle.
- **Cloisonnement des locataires.** `RouteScopingTest` parcourt la surface route par route, exige
  qu'un helper *prouve* dans son propre corps qu'il résout une allocation, et refuse >60 routes non
  couvertes ; les deux listes d'exemption portent un argument par entrée et sont partagées, pas
  copiées. La mutation du §2 confirme qu'elle mord.
- **Quatre yeux.** `queueIfNotApprover` conditionne sur `TriageStatus.isSettled()`, donc `FIXED`
  comme `NOT_AFFECTED` passent par la file, et l'ordre valider-puis-mettre-en-file évite d'exiger
  une justification VEX d'un correctif. Mutation ci-dessus : les deux cas mordent.
- **Conformité — un évaluateur, six cartographies, compté.** `ComplianceEngine` commute sur les
  **sept** catégories annoncées ; `ComplianceFramework` déclare **six** référentiels (NIS_2,
  ISO_27001, EU_CRA, DORA, PCI_DSS, SOC_2) portant **24** `new ComplianceControl` au total, répartis
  VULNERABILITY_MANAGEMENT 7, SECRETS_MANAGEMENT 5, SUPPLY_CHAIN 4, SECURE_CODING 3,
  AUDIT_AND_LOGGING 3, INFRASTRUCTURE_AS_CODE 1, GOVERNANCE 1. La description « un évaluateur de
  posture, six cartographies » est exacte au chiffre près.
- **`cappedByPlatform`.** Trois plafonds, chacun nommant le commutateur à basculer : SECRETS à 60
  sans clé de chiffrement, AUDIT à 70 sans miroir, GOVERNANCE à 75 sans quatre yeux. Le plafond
  GOVERNANCE repose désormais sur un mécanisme qui couvre réellement les deux statuts réglants —
  ce qui n'était pas vrai au 21:10, et qui était le vrai fond du constat de conformité.
- **Portabilité.** 87 tests sur trois moteurs, migrations Flyway appliquées et schéma validé.
- **Forge.** `git remote -v` → `git@github.com:asmolabs/vectispire.git`. `main` et `develop` portent
  **exactement les mêmes quatre workflows** (`git diff origin/main develop -- .github/` est vide) :
  le `cron: '30 2 * * *'` de `nightly.yml` est sur la branche par défaut et pointe sur l'arbre
  courant. Le §3.3 du 21:10 est fermé.
- **Documentation.** 740 liens, 0 cassé. Empreinte C4 identique à celle enregistrée. 12/12 par arbre
  de langue, 5/5 vues bflorat par langue, STRIDE dans les deux langues, ADR 0001 → 0017 dans les
  deux langues avec les renversements consignés (`0004 → 0008 → 0009 → 0014`, `0011 → 0013`).

---

## 5. Vérification réellement exécutée — 9,5 au moment de l'audit, 10,0 depuis

> **Cette section est conservée telle qu'elle a été écrite, et le §8 la corrige.** Le seul écart
> qu'elle nomme — n'avoir lu aucun historique d'exécution — a été fermé après coup en installant
> `gh`. Réécrire la section effacerait la distinction entre ce que je savais en auditant et ce que
> j'ai su ensuite, qui est précisément ce que ce rapport prétend tenir.

La note monte de 9,0 parce que les deux contrôles que chaque audit précédent devait déclarer
« affirmé, non exécuté » ont tourné, et parce que le nocturne pointe enfin sur l'arbre courant.

Ce qui reste tient en une phrase : **aucun historique d'exécution GitHub n'a été lu.** Il n'y a
toujours pas de CLI `gh` sur cette machine, et rien dans ce rapport ne dit qu'un job GitHub a jamais
été vert. Tout le §1 a été exécuté ici. C'est une affirmation plus forte que relire un fichier de
workflow, et plus faible qu'un pipeline vert sur le runner.

Un détail environnemental, conservé du 21:10 parce qu'il reste vrai : `./gradlew
:vectispire-core:jibDockerBuild` échoue localement en tirant `eclipse-temurin` sans authentification
Docker Hub. La voie `Dockerfile` — celle qui est livrée — construit sans problème, 347 Mo. Le job
`images` dépend d'un pull de registre qui peut être limité.

---

## 6. Recommandations, par priorité

| # | Constat | Action | Comment cela a été vérifié |
|---|---|---|---|
| 1 | §3.1 | `EpssPrioritizationService` : une seule lecture `findByCveIdInIgnoreCase` en `Map` avant la boucle, au lieu d'un `lookupCve` par constat | **Exécuté** — 468 requêtes pour 620 constats, compteurs Hibernate |
| 2 | §3.1 | Projeter les colonnes aux trois sites, comme `IssueRows` le fait déjà pour les cinq lectures du 21:10 | **Exécuté** — 623 / 624 / 468 chargements d'entités à 620 constats |
| 3 | §3.1 | **Transformer `ReadCostRoutesTest` en balayage** : échouer sur toute route GET dont le compte suit la taille du parc, avec une liste d'exemptions argumentée | **Exécuté** — le balayage de 40 routes a trouvé trois routes que la liste de quatre ne couvrait pas |
| 4 | §5 | Consigner l'URL et la date de la première exécution GitHub verte dans `docs/analysis/` | **Affirmé, non exécuté** — pas de CLI `gh` |
| 5 | §3.2 | Faire passer les deux libellés de fournisseur par `i18n.t` | **Exécuté** — 661 vs 609 clés aplaties, aucune clé fournisseur dans l'un ou l'autre bundle |

---

## 7. Ce que cet audit n'a pas pu mesurer

- **L'historique des exécutions CI** — pas de CLI `gh`. C'est le seul écart structurel restant.
- **Neuf routes de mon propre balayage.** `/api/v1/compliance`, `/api/v1/history`,
  `/api/v1/scorecards`, `/api/v1/tickets`, `/api/v1/threat-intel`, `/api/v1/vex`,
  `/api/v1/attestations` ont répondu **404**, et `/api/v1/inventory/versions` et
  `/api/v1/inventory/search` ont répondu **400** faute d'un paramètre requis. Ce sont des chemins
  que j'ai devinés, pas des routes propres : **elles sont non mesurées, pas saines.** La sonde le
  dit d'elle-même en refusant de compter un 404 comme un coût nul — c'est la garde que
  `ReadCostRoutesTest` porte déjà, et j'ai gardé la même.
- **L'échelle.** La mesure plafonne à 620 constats sur SQLite. La linéarité y est sans ambiguïté ;
  le coût en temps réel à 500 000 lignes sur PostgreSQL en est déduit, pas mesuré.
- **La construction d'image par Jib** — bloquée sur un pull Docker Hub, §5.
- **L'agent, de bout en bout.** Son isolation est vérifiée par le classpath, ce qui est une preuve
  d'absence solide ; aucun processus agent n'a été démarré contre un plan de contrôle vivant.

---

## 8. Addendum — l'historique des exécutions, enfin lu

*Ajouté après l'audit et après la remédiation. `gh` a été installé ; le dépôt est public, donc
l'API des exécutions répond sans authentification.*

### Ce que dit l'historique — 19 exécutions

**La série peut enfin dire qu'un job GitHub a été vert, avec une date.** La première exécution
verte est `verify` **#5 et #6, le 28 août 2026 à 08:59 UTC**, sur `develop` et sur `main`. Les deux
premières exécutions, le 27 août à 13:52, ont **échoué** — le bug de portage que l'audit du 28 août
décrivait, confirmé ici par la source plutôt que déduit.

**Le nocturne s'est déclenché, deux fois, depuis `main`, et les deux fois avec succès :**

| Exécution | Déclenchée | SHA | Résultat |
|---|---|---|---|
| `nightly` #1 | 29 août 09:17 UTC | `788afdcb` | **succès** |
| `nightly` #2 | 30 août 08:29 UTC | `dfbd7f8f` | **succès** — l'arbre courant |

C'est la question restée ouverte depuis l'audit du 28 août, réglée par la mesure. Les quatre jobs
du nocturne — `e2e`, `dockerfiles`, `restore`, `databases` — sont verts sur le SHA qui est
aujourd'hui la tête de `main` et de `develop`.

**Et les dix jobs de `verify` sont verts sur `main`** (#16, 29 août 19:48 UTC) : `c4-drift`,
`secrets`, `jvm`, `dockerfile-policy`, `npm-audit`, `frontend`, `links`, `images`, `sbom`,
`vulnerabilities`. Chaque contrôle dont le projet se réclame est présent **et** s'exécute **et**
passe, sur le runner et non seulement sur ma machine. C'est l'affirmation la plus forte que cette
série ait jamais pu faire, et elle vaut le 0,5 qui manquait.

**Une nuance factuelle sur le `cron:`.** Il dit `30 2 * * *`, et les deux exécutions ont démarré à
09:17 et 08:29 UTC. GitHub retarde les workflows planifiés sur les runners partagés, parfois de
plusieurs heures. Le mécanisme fonctionne ; l'heure n'est pas celle qui est écrite, et un document
qui promettrait « chaque nuit à 2h30 » serait à corriger.

### 3.3 🟠 Un quatrième workflow existe, a tourné une seule fois, et a échoué

**Exécuté.** `docs` **#1**, le 29 août à 19:31 UTC, sur `main` : **échec**, au pas
`actions/configure-pages`, le job `deploy` sauté. C'est le seul échec de l'historique récent, et
c'est le seul workflow des quatre qui n'a jamais réussi.

**La cause, vérifiée et non supposée.** `GET /repos/asmolabs/vectispire/pages` répond **404** :
GitHub Pages n'est pas activé sur le dépôt, et `configure-pages` échoue exactement pour cette
raison. `https://asmolabs.github.io/vectispire/` répond **404** lui aussi.

**Pourquoi cela dépasse un job rouge.** Deux fichiers l'affirment au présent, comme un fait :

- [`mkdocs.yml:1`](../../../mkdocs.yml) — *« Le site de documentation publique, publié sur
  https://asmolabs.github.io/vectispire/ »*, et `site_url:` à la ligne 16 pointe la même adresse ;
- [`.github/workflows/docs.yml:1`](../../../.github/workflows/docs.yml) — *« Le site de
  documentation, publié sur https://asmolabs.github.io/vectispire/ »*.

C'est la famille de constat que ce projet traite comme la pire : une garantie écrite au présent que
rien n'exécute. L'audit du 25 août en avait relevé une jumelle — une commande de vérification de
signature qui ne pouvait pas réussir, affirmée comme un fait dans deux documents.

**Et il ne se réessaiera pas tout seul.** `docs.yml` ne se déclenche que sur un push vers `main`
touchant `docs-site/**`, `mkdocs.yml`, `ci/docs/requirements.txt` ou lui-même — plus
`workflow_dispatch`. Tant que Pages n'est pas activé, chaque déclenchement échouera au même pas.

**Recommandation.** Activer GitHub Pages sur le dépôt avec `source: GitHub Actions`, puis relancer
`docs` par `workflow_dispatch`. C'est un réglage de dépôt et non un changement de code — il demande
les droits d'administration sur `asmolabs/vectispire`, donc il n'a pas été fait ici. Si le site
n'est pas voulu pour l'instant, c'est la phrase des deux fichiers qui doit changer, pas le réglage :
elle décrit une intention au présent de l'indicatif.

### Ce que cela change aux notes

- **Vérification réellement exécutée : 9,5 → 10,0.** L'unique écart structurel du rapport est
  fermé, et il l'est dans le bon sens : l'historique confirme ce que le rapport affirmait.
- **Documentation & Architecture : 9,0 → 8,5.** Non pas parce que la documentation s'est dégradée,
  mais parce que j'avais noté un axe sur ce que je pouvais mesurer sans réseau. Deux fichiers
  annoncent un site qui n'existe pas ; c'est du terrain qu'aucun audit de la série n'avait mesuré,
  pas une régression.

La note globale reste **8,7**. Elle est simplement mieux répartie.

---

*Arbre de travail : cet audit a ajouté une sonde de coût de lecture puis l'a retirée, et appliqué
quatre mutations temporaires, toutes annulées. `git status` est propre. Le `./gradlew build
--rerun-tasks` final a exécuté les 35 tâches à froid — 1326 tests, 0 échec — après restauration de
la dernière mutation.*
