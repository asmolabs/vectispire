# Rapport d'Audit Approfondi : Documentation, Code Source & Sécurité

**Date :** 2 septembre 2026, 10:36 · **Arbre audité :** `develop` @ `a2ff1971` · **Note globale : 8,2 / 10** (précédent : 7,8)

---

## 0. En un paragraphe

**La note monte de 7,8 à 8,2, et les deux mouvements qui la composent vont en sens contraire.**
Les cinq recommandations ouvertes du 30 août sont fermées et je les ai vérifiées une par une : les
**17 jobs des quatre workflows sont bornés** (0 sans `timeout-minutes`), `cosign` est épinglé en
`v3.1.3` avec vérification d'empreinte, `check-doc-facts.py` tourne et contrôle 23 affirmations
chiffrées. En face, **le constat structurel de la série se reproduit** : `main` a **10 commits de
retard** sur `develop`, dont les neuf d'aujourd'hui — et `main` est la seule branche depuis
laquelle GitHub déclenche un workflow planifié. Le nocturne de cette nuit certifiera un arbre qui
ne contient ni les trois migrations `V17`–`V19`, ni le rôle `AUDITOR`, ni le correctif VEX.

**Et le constat le plus lourd de cet audit n'est pas une dégradation : c'est cinq audits qui ont
noté « reachability » comme une capacité de chaîne d'approvisionnement sans jamais mesurer ce
qu'elle calculait.** `ReachabilityAnalyzer` ne fait aucune analyse de graphe d'appels ; il cherche
le nom du paquet en sous-chaîne dans les constats Semgrep. Son verdict « non atteignable » — posé
dès qu'aucun constat ne mentionne le paquet — était publié tel quel en `not_affected` dans les
documents OpenVEX et `known_not_affected` dans les CSAF livrés aux clients, **sans humain dans la
boucle**. Corrigé pendant cet audit (`a2ff1971`).

---

## 1. Tableau des notes

| Domaine | Note | Mouvement | Ce qui la fixe |
|---|---|---|---|
| 📚 Documentation & Architecture | **9,0 / 10** | = | 5 vues Florat × 2 langues, 17 ADR × 2, parité 11/11 exacte, 862 liens sans rupture. SPDX encore annoncé dans un tag OpenAPI. |
| 🛡️ Sécurité & Cryptographie | **8,2 / 10** | ▲ | Crypto conforme et vérifiée par exécution ; défaut VEX majeur fermé ce jour ; trois écarts de séparation des pouvoirs ouverts. |
| ⚙️ Qualité du Code | **8,5 / 10** | ▲ | 1343 tests verts, ArchUnit 6/6, vecteur d'empreinte épinglé **et prouvé par mutation**. Une lecture non bornée mesurée à 52 entités. |
| 📋 Conformité & Standards | **8,5 / 10** | ▲ | 6 référentiels × 4 contrôles = 24, 7 catégories, `cappedByPlatform` en place. La correction VEX était aussi un sujet de conformité. |
| 🔁 Vérification réellement exécutée | **7,0 / 10** | ▼ | 17/17 jobs bornés, `cosign` épinglé — mais `main` ne porte pas l'arbre audité, et l'historique des exécutions n'a pas pu être lu. |

---

## 2. Méthode, et ses limites déclarées

Tout ce qui suit a été **exécuté**, sauf ce qui est explicitement marqué *affirmé, non exécuté*.

**Une limite d'outillage, énoncée d'emblée :** `gh` n'est pas authentifié sur cette machine
(`gh auth login` requis, aucun `GH_TOKEN`). **Je n'ai donc pas pu lire l'historique des
exécutions.** Tout ce que ce rapport dit du pipeline porte sur ce qui est *déclaré* dans les
fichiers de workflow, jamais sur ce qui a *tourné*. La série a déjà montré que la différence est
décisive : c'est elle qui a fait perdre 0,5 point le 28 août.

Deux mutations ont été pratiquées, et leurs résultats sont rapportés en §5.1 et §5.2.

---

## 3. 📚 Documentation & Architecture — 9,0 / 10

### Ce qui a été exécuté

| Contrôle | Commande | Résultat |
|---|---|---|
| Vues Florat | `ls docs/architecture/bflorat/{fr,en}` | **5 vues + README dans chaque langue** |
| C4 | `ls docs/architecture/c4/` | `workspace.dsl` + `diagrams/` présents |
| STRIDE | `ls docs/architecture/security/*/` | `STRIDE_THREAT_MODEL` en FR et EN |
| ADR | `ls docs/architecture/{en,fr}/decisions/` | **17 ADR (0001–0017)**, symétriques |
| Parité bilingue | `comm` sur les basenames de `docs/en` et `docs/fr` | **11 / 11, aucun orphelin dans un sens ni dans l'autre** |
| Liens | `python3 scripts/check-doc-links.py` | **862 liens relatifs, 0 rompu**, exit=0 |
| Affirmations chiffrées | `python3 scripts/check-doc-facts.py` | **26 documents, 23 affirmations, aucune contredite**, exit=0 |

`check-doc-facts.py` recoupe indépendamment trois de mes comptages : 17 ADR, 6 référentiels /
24 contrôles / 7 catégories, et 2 moteurs déployables pour 3 jeux de migrations. C'est la première
fois de la série qu'un contrôle du dépôt confirme les chiffres de l'auditeur au lieu de dépendre de
lui.

### 🟡 D1 — SPDX est encore annoncé dans la surface d'API

L'ADR 0016 (25 août) acte que **SPDX n'est pas produit** et note qu'il était alors « listé dans
quatre documents et dans la description d'API ». Les quatre documents ont été nettoyés — aucune
occurrence ne subsiste dans `README.md` ni dans `docs-site/`. Il en reste **une**, dans le code :

```
vectispire-core/.../api/config/OpenApiConfiguration.java:50
  new Tag().name("SBOM & VEX").description("Software Bill of Materials (CycloneDX, SPDX), CSAF and OpenVEX documents")
```

Vérifié par balayage exhaustif : `grep -rn -i 'spdx' --include='*.java' */src/main` filtré sur les
annotations de description ne retourne que cette ligne. La description de la route
`GET /{id}/sbom`, que l'ADR nommait, a bien été corrigée — c'est le tag de regroupement qui a été
manqué. Un intégrateur qui lit le Swagger y trouve toujours la promesse.

### 🟡 D2 — Le prompt d'audit lui-même est en retard

`PROMPT_AUDIT.md` annonce « ADR 0001 à 0016 » dans les deux langues ; il y en a 17 depuis l'ajout
de `0017-custom-checks-as-container-images.md`. Sans conséquence pour le produit, mais le document
qui sert à contrôler la documentation est le dernier endroit où une dérive devrait vivre.

---

## 4. 🛡️ Sécurité & Cryptographie — 8,2 / 10

### 4.1 Ce qui tient, vérifié

| Contrôle | Vérification | Résultat |
|---|---|---|
| Argon2id | `PasswordHasher.java`, BouncyCastle `Argon2BytesGenerator` | Présent, format PHC documenté |
| AES-256-GCM | `SecretCipher.java` | `FORMAT_PREFIX = "v2:"`, `NONCE_LENGTH_BYTES = 12`, AAD de contexte |
| SealedEnvelope | `SealedEnvelope.java`, `AgentProtocol.java` | X25519, nonce 12 o, clé éphémère publiée par l'agent |
| Rate limiting | `LoginRateLimitFilter.java` | Bucket4j (`Bandwidth`, `Bucket`, `ConsumptionProbe`) |
| Journal d'audit | `AuditLogService.verify()` + `verifyAgainstMirror()` | **12 cas verts** |
| Cloisonnement | `RouteAuthorizationTest` **11 cas**, `TeamVisibility` **11 cas**, `AuthorizationCoverage` + `RouteScoping` | **0 échec** |

**Isolation de l'agent — mesurée, pas lue.** Plutôt que d'inspecter le `build.gradle.kts`, j'ai
résolu le classpath réel :

```
./gradlew :vectispire-agent:dependencies --configuration runtimeClasspath
  | grep -icE 'mysql|postgresql|sqlite|jdbc|hibernate|spring-boot-data-jpa'
→ 0
```

Zéro occurrence, et aucune référence à `ENCRYPTION_KEY` dans `vectispire-agent/src/main`.
L'étanchéité annoncée est réelle.

### 4.2 🔴 S1 — L'absence de preuve était publiée comme une preuve d'absence *(fermé pendant cet audit)*

C'est le constat le plus lourd, et il n'est **pas** une dégradation du terrain : c'est un terrain
que cinq audits ont noté sans le mesurer. « Reachability » figure dans l'axe 4 du prompt depuis
l'origine, aux côtés de CycloneDX et CSAF, et personne n'avait ouvert `ReachabilityAnalyzer`.

**Ce qu'il calculait.** Aucune analyse de graphe d'appels. Un composant était déclaré *atteignable*
quand un constat Semgrep du même scan contenait le nom du paquet **en sous-chaîne**, dans sa
description ou son chemin de fichier. La constante `HIGH_RISK_SYMBOLS` déclarée en tête de classe
n'était **lue nulle part**. Ce que la colonne `reachable_symbols` contenait n'était pas un
symbole : un `fichier:ligne` — le test de l'analyseur épinglait `TemplateHelper.java:42`.

**Le sens inverse faisait le dégât.** Un composant devenait *non atteignable* dès que Semgrep avait
produit un constat quelque part et qu'aucun ne mentionnait le paquet. Or `SAST_ENABLED` vaut
`false` par défaut — le réglage dit lui-même que l'activer fait passer un dépôt « de quelques
dizaines de vulnérabilités à quelques milliers de constats » — et le produit ne livre qu'une règle
Semgrep pour raisons de licence. Un dépôt qui active l'analyse sans installer de jeu de règles
obtient quelques constats pour deux cents dépendances : **presque tout se retrouve estampillé « non
atteignable », sur une absence de preuve.**

**Et cette valeur était publiée sans humain dans la boucle.** Quatre chemins :

- `VexGeneratorService:84` et `:125` → OpenVEX `not_affected`, justification
  `vulnerable_code_not_in_execute_path`, avec la phrase « Vectispire static analysis **verified** no
  direct call path invokes the vulnerable code » ;
- `CsafGeneratorService:63` et `:130` → produit placé dans `known_not_affected`, qui est une
  déclaration formelle de non-exposition ;
- `CycloneDxGeneratorService:214` → même conclusion dans le bloc d'analyse ;
- `AiVulnerabilityAdvice:69-71` → suggestion `not_affected` / `code_not_reachable` avec « l'analyse
  de portée **démontre** que les méthodes vulnérables ne sont pas exécutées », et le prompt du
  modèle (`AiReviewService:323`) offrait `code_not_reachable` parmi ses choix en lui passant la
  valeur.

Deux verbes de preuve — *verified*, *démontre* — au-dessus d'une recherche de texte, dans des
documents lisibles par machine. Le nom d'outil inscrit dans chaque OpenVEX était « Vectispire
Reachability & Exploitability Engine ».

**Fermé par `a2ff1971`.** L'analyseur devient unidirectionnel : il peut lever la main, il ne peut
disculper personne ; l'absence de correspondance vaut `UNKNOWN`. Les trois générateurs ne dérivent
plus d'exonération de ce champ — seul un triage humain, justifié et signé, disculpe. Le nom d'outil
devient « Vectispire ASPM ».

**La barrière de qualité n'a jamais lu ce champ** (`grep -rn -i 'reachab'
vectispire-common/.../domain/gate/` → vide) : le chemin le plus opérationnel était épargné.

### 4.3 🟠 S2 — Le contrôle des quatre yeux s'éteint depuis l'intérieur *(ouvert)*

`FOUR_EYES_APPROVAL_REQUIRED` s'écrit par le PUT de `SettingsController:137`, ouvert à SUPERUSER,
ADMIN et CISO. Les trois portent `canApproveTriage() == true` (`Role.java:18-20`). Un CISO dont la
décision part en file d'approbation peut désactiver le réglage, régler seul, et le réactiver. Le
changement est audité, donc détectable après coup — mais une détection a posteriori n'est pas le
contrôle que les quatre yeux sont censés être.

**Le nœud :** aucun rôle capable d'écrire les réglages n'est incapable d'approuver. Il n'existe
donc personne à qui confier ce réglage sans rouvrir le même trou.

**À porter au crédit du modèle :** l'approbateur est comparé au **demandeur** enregistré sur
l'événement, pas seulement au rôle. Un compte ne peut pas approuver sa propre demande même en ayant
le rôle. Le trou est plus étroit qu'il n'y paraît — mais éteindre le réglage court-circuite tout le
mécanisme, ce contrôle compris.

### 4.4 🟡 S3 — SUPERUSER et ADMIN sont le même rôle *(ouvert)*

Les deux portent `(true, true, true, true)`. Aucune ligne de production ne les distingue ; seul
`BootstrapService:105` en crée un. L'écran des comptes propose une élévation qui n'existe pas.

### 4.5 🟡 S4 — Approuver la dérogation et abaisser la barrière sont le même rôle *(ouvert)*

`GatePoliciesController` est ouvert en écriture au CISO, qui approuve aussi les triages. Ce n'est
pas un défaut en soi — c'est souvent la personne dont c'est le métier — mais dans un produit dont
la raison d'être est de tenir une barrière, la question mérite d'être tranchée explicitement.

### 4.6 Ce qui a été renforcé depuis le 30 août

Trois travaux menés avant cet audit et vérifiés par lui :

- **Un rôle `AUDITOR`** et la séparation d'un marqueur de *lecture* de gouvernance
  (`@RequiresGovernanceRead`) d'un marqueur d'*écriture* (`@RequiresSecurityLead`). Auparavant, la
  seule façon d'ouvrir le journal d'audit à quelqu'un était de lui donner le droit de réécrire la
  politique qu'il venait vérifier.
- **Les clés étrangères réelles sur MySQL** (`V19`). Vingt-quatre colonnes déclaraient
  `references … on delete cascade` en ligne, forme que MySQL analyse et jette — vérifié
  empiriquement sur un MySQL 8 neuf : la forme en ligne ne produit ni contrainte ni index, la forme
  au niveau table produit les deux.
- **Le quota CPU des conteneurs de scan**, qui interrogeait `availableProcessors()` de la JVM
  alors que le conteneur tourne sur l'hôte du démon. Sur un poste macOS : 10 cœurs côté JVM,
  4 côté démon, et Docker refusait la création — aucun scan ne démarrait.

---

## 5. ⚙️ Qualité du Code — 8,5 / 10

### 5.1 Mutation n°1 — Le vecteur d'empreinte, permuté

Le prompt désigne ce point comme le plus piégeux, et il documente le trou du 26 août 2026 :
« en permutant deux champs : aucun test n'a échoué ». **Le trou est refermé, et je l'ai prouvé.**

`IssueFingerprintTest:52` épingle désormais un littéral :
`44c39a41c912df031c920698f4698aa76cdcf27617f2e99f4f6759de1f97851d`.

J'ai permuté `input.type().wireName()` et `input.identifier()` dans `IssueFingerprint.of` :

```
sous permutation : 0 échec(s) sur 4    (propriétés relationnelles)
sous permutation : 0 échec(s) sur 3    (ce qui distingue deux constats)
sous permutation : 1 échec(s) sur 1    → « a known finding has a known fingerprint »
```

**Les sept tests relationnels passent tous.** Déterminisme, version exclue, cibles séparées,
priorité du purl, frontière de champ : aucun ne voit une permutation qui changerait pourtant chaque
empreinte du parc et perdrait tout le triage en silence. Seul le vecteur littéral la détecte. C'est
la démonstration la plus nette que ce dépôt possède de la valeur d'un test d'or.

### 5.2 Mutation n°2 — Les listes de marqueurs d'autorisation

En ajoutant un sixième marqueur, j'ai cassé deux invariants simultanément : l'expression
security-lead privée de CISO, et une route à qui l'on rend son `@PreAuthorize` en ligne.
**Trois échecs sur onze**, chaque nouveau cas attrapant le sien. Mutations annulées.

Ce test a aussi révélé que la liste des marqueurs vivait **à trois endroits** côté test —
`RouteAuthorizationTest` en classes, `RouteScopingTest` en alternation de regex,
`AuthorizationCoverageTest` en chaîne de `contains` — et que les deux dernières signalaient comme
« non gardées » toutes les routes ayant adopté le nouveau marqueur. Ramenées à une seule source.

### 5.3 Ce qui tient

| Contrôle | Commande | Résultat |
|---|---|---|
| Suite complète | `./gradlew test` | **1343 tests, 0 échec** |
| Couches | `--tests '*Architecture*'` | **6 cas, 0 échec** |
| Migrations | `--tests '*Migrations*'` | **3 cas, 0 échec** |
| ADR 0007 | `grep 'Optional.empty()' scanning/scanners/` | 8 occurrences |
| Playwright | `ls e2e/*.spec.ts` + `grep -c 'test('` | 5 suites, **13 cas** *(déclarés ; non exécutés ici, pas de navigateur lancé)* |

### 5.4 🟠 Q1 — Une lecture non bornée, mesurée

Le prompt demande de mesurer plutôt que de raisonner. J'ai instrumenté `SbomDiffService.diffLatest`
avec les compteurs Hibernate, sur un parc de 51 dépôts dont un seul m'intéresse :

```
>>> MESURE diffLatest : entites=52 requetes=5
    (2 scans à comparer, 50 scans d'autres cibles dans le parc)
```

**52 entités chargées pour en comparer 2.** `SbomDiffService:164` fait
`scans.findAll().stream().filter(...)` — le filtre par cible en Java sur toute la table `t_scan`,
dimensionnée à 100 000 lignes par an. Le coût suit le parc, pas la cible.

**Ce qui rend le constat net :** `Scans` expose `findByRepoId` et `findByContainerId`, et
`LicenseGovernanceService:122-124` les utilise correctement, quarante lignes plus loin dans la même
couche. Depuis `V18`, `idx_scan_repo` sert cette requête. La bonne façon existe, elle est indexée,
et elle est déjà employée à côté.

Deux lectures du même genre, **relevées par inspection et non mesurées** :

- `EvidenceVaultService:144` — `scansRepo.findAll().stream().filter(...).limit(20)` : charge tout le
  parc pour en garder vingt.
- `LicenseGovernanceService:126` — `findAll()` sans filtre lorsqu'aucune cible n'est demandée
  (vue globale). Défendable pour un rapport de parc, non borné malgré tout.

Une quatrième, `SecurityScorecardService:123`, est **délibérée et documentée** : son commentaire
explique que l'allocation du lecteur est un ensemble de cibles et non une colonne, donc qu'aucune
requête dérivée ne peut l'exprimer, et qu'elle est « nommée plutôt que laissée passer pour un
oubli ». Je la compte comme un arbitrage assumé, pas comme un défaut.

---

## 6. 📋 Conformité & Standards — 8,5 / 10

### 6.1 Un évaluateur, six cartographies — vérifié par comptage

```
référentiels : 6  ['NIS_2', 'ISO_27001', 'EU_CRA', 'DORA', 'PCI_DSS', 'SOC_2']
contrôles    : 4 par référentiel → 24
catégories commutées dans evaluateControl : 7
  AUDIT_AND_LOGGING, GOVERNANCE, INFRASTRUCTURE_AS_CODE, SECRETS_MANAGEMENT,
  SECURE_CODING, SUPPLY_CHAIN, VULNERABILITY_MANAGEMENT
```

La description du prompt est exacte, et `check-doc-facts.py` confirme les mêmes trois nombres de
son côté. `cappedByPlatform` est bien appliqué à chaque évaluation (`ComplianceEngine:94`), donc un
contrôle ne peut pas être déclaré conforme sur la foi d'un mécanisme éteint.

### 6.2 Formats de chaîne d'approvisionnement

CycloneDX 1.6, CSAF 2.0 et OpenVEX ont des générateurs réels et des routes exposées
(`/csaf/scans/{id}/csaf.json`, `/vex/scans/{id}/openvex.json`, plus les agrégats). **SPDX n'est pas
produit** — le balayage ne trouve que du vocabulaire de licence (`spdxExpression`), conformément à
l'ADR 0016. Voir D1 pour la promesse résiduelle dans le tag OpenAPI.

**La correction VEX de §4.2 est aussi un sujet de conformité** : un document CSAF plaçant un
produit dans `known_not_affected` sur la foi d'une recherche de texte est une déclaration que
l'éditeur ne pourrait pas défendre si un client la contestait.

---

## 7. 🔁 Vérification réellement exécutée — 7,0 / 10

### 7.1 Ce qui est déclaré, et correctement

| Contrôle | Vérification | Résultat |
|---|---|---|
| Bornage des jobs | Parse YAML des 4 workflows | **17 jobs, 0 sans `timeout-minutes`** |
| `cosign` | `release.yml:111-113` | Épinglé `v3.1.3`, empreinte vérifiée |
| Nocturne déclenchable | `git cat-file -e github/main:.github/workflows/nightly.yml` | **Présent sur `main`** — le `cron:` peut donc se déclencher |
| Contrôles doc | `check-doc-links.py`, `check-doc-facts.py` | exit=0 tous les deux |

La recommandation du 30 août sur les timeouts est **fermée** : mon premier comptage, fait à la
regex, annonçait 25 jobs pour 17 timeouts et aurait produit un faux constat ; le parse YAML donne
17 pour 17.

### 7.2 🔴 V1 — `main` ne porte pas l'arbre audité *(le constat qui se reproduit)*

```
git rev-list --left-right --count github/main...github/develop
→ main en avance: 0   develop en avance sur main: 10
```

Les neuf commits d'aujourd'hui — les trois migrations, le rôle `AUDITOR`, le correctif VEX, le
quota CPU — **sont tous absents de `main`**. Or GitHub n'exécute un workflow planifié que depuis la
branche par défaut.

Conséquences concrètes, dans l'ordre de gravité :

1. **La campagne multi-moteurs du nocturne (`integrationTestAll`) n'exercera pas `V17`, `V18` ni
   `V19`.** Ce sont des migrations de schéma, dont une qui pose 24 clés étrangères et supprime des
   orphelins. Elles ont été validées ici contre un PostgreSQL et un MySQL réels via Testcontainers,
   mais aucune vérification *planifiée* ne les couvrira tant que `main` n'avance pas.
2. **Le correctif VEX ne sera couvert par aucune exécution nocturne.** C'est le changement le plus
   conséquent de la journée.
3. `ci.yml` ne contient **aucune** invocation d'`integrationTest` (`grep -c` → 0) : la campagne
   moteurs est un contrôle exclusivement nocturne, donc exclusivement dépendant de `main`.

Le 28 août, le même écart avait fait perdre 0,5 point ; le 30 août il valait un constat en tête de
rapport. Il n'a pas été refermé structurellement — seulement rattrapé une fois.

### 7.3 ⚪ V2 — L'historique des exécutions n'a pas pu être lu *(affirmé, non exécuté)*

`gh run list` retourne :

```
To get started with GitHub CLI, please run: gh auth login
```

Aucun `GH_TOKEN` dans l'environnement. **Ce rapport ne peut donc rien affirmer sur ce qui a
réellement tourné** : ni la date du dernier nocturne vert, ni l'état de `docs.yml` (dont l'audit du
29 août notait qu'il avait échoué une fois, Pages n'étant pas activé), ni si `release.yml` a été
déclenché depuis. Trois questions ouvertes par les audits précédents restent ouvertes faute
d'outil, et non faute d'avoir cherché.

---

## 8. Recommandations, par ordre de valeur

| # | Recommandation | Vérification à l'appui |
|---|---|---|
| **R1** | **Fusionner `develop` dans `main`.** Sans cela, le correctif VEX et les trois migrations ne seront couverts par aucune vérification planifiée. | `git rev-list --left-right --count` → 0 / 10. **Exécuté.** |
| **R2** | **Trancher qui peut éteindre les quatre yeux** (S2). Deux issues : retirer l'approbation de triage aux administrateurs — attention, une installation dont les seuls comptes sont administratifs n'aurait alors plus personne pour vider la file — ou exiger deux personnes pour changer un réglage de gouvernance. | `Role.java:18-20` + `SettingsController:137`. **Exécuté** (lecture croisée, pas de mutation : le changement modifie des permissions en service). |
| **R3** | **Borner `SbomDiffService.diffLatest`** en appelant `findByRepoId` / `findByContainerId`, déjà indexées depuis `V18` et déjà employées par `LicenseGovernanceService`. | **Mesuré : 52 entités pour 2 scans.** |
| **R4** | **Authentifier `gh` sur la machine d'audit**, ou fournir un `GH_TOKEN` en lecture seule. Trois constats de la série restent invérifiables sans cela. | **Non exécuté**, et c'est le sujet. |
| **R5** | **Retirer SPDX du tag OpenAPI** (D1). Une ligne. | `grep` exhaustif : une seule occurrence résiduelle. **Exécuté.** |
| **R6** | **Décider du sort de SUPERUSER** (S3) : lui donner un pouvoir propre — l'administration des rôles est la réponse classique — ou le fusionner dans ADMIN. | `Role.java:18-19`, `BootstrapService:105`. **Exécuté.** |
| **R7** | **Renommer `reachable_symbols`.** La colonne contient des `fichier:ligne`. Un nom qui ment sur son contenu est la façon dont le défaut de §4.2 a survécu à cinq audits. | Test de l'analyseur épinglant `TemplateHelper.java:42`. **Exécuté.** |
| **R8** | **Ajouter `integrationTestAll` à `ci.yml`**, au moins sur les pull requests touchant `db/migration/`. La campagne moteurs ne doit pas dépendre d'une seule branche. | `grep -c integrationTest .github/workflows/ci.yml` → **0**. **Exécuté.** |

---

## 9. Sur la variation de note

Le prompt demande de dire si le terrain s'est dégradé ou si un audit précédent avait noté ce qu'il
n'avait pas mesuré. Les deux, et il faut les séparer.

**Le terrain s'est amélioré** sur la vérification déclarative (17/17 jobs bornés, `cosign` épinglé)
et sur la sécurité (rôle de lecture seule, clés étrangères réelles, quota CPU réparé). Ce sont des
travaux faits, que j'ai contrôlés.

**Un audit précédent avait noté ce qu'il n'avait pas mesuré** sur l'atteignabilité. Le mot figure
dans l'axe 4 du prompt depuis l'origine, entre CycloneDX et EPSS, et cinq rapports l'ont compté
comme une capacité acquise. Personne n'avait ouvert la classe. La note de conformité de ces cinq
rapports était, sur ce point, surévaluée — non par complaisance, mais parce que la capacité était
listée et jamais sondée. C'est exactement le motif que ce prompt existe pour casser.

**Et un constat structurel se reproduit** : `main` en retard. Ce n'est ni l'un ni l'autre — c'est
un défaut de processus qui a été rattaché à la main deux fois et jamais outillé.
