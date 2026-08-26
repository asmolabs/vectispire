# Rapport d'Audit Approfondi : Documentation, Code Source & Sécurité

* **Projet :** Vectispire — ASPM & Plan de Contrôle de Sécurité Logicielle
* **Date :** 26 août 2026, 14:30
* **Commit audité :** `8e122447` (`develop`)
* **Périmètre :** les cinq axes de [`PROMPT_AUDIT.md`](../../../PROMPT_AUDIT.md)

> **Cet audit a été mené sans lire les précédents.** C'était la demande. Les notes
> ci-dessous ne sont donc **pas comparables** à celles des huit rapports antérieurs : une
> hausse ou une baisse ne dit rien, faute de base commune. Ce qui est comparable, ce sont les
> constats nommés.

---

## 0. Ce qui a été exécuté

La méthode du prompt est « exécuter, ne pas lire ». Voici ce qui a réellement tourné, avec sa
sortie — le reste du rapport ne s'appuie sur rien d'autre.

| commande | résultat |
|---|---|
| `./gradlew check` | **vert** |
| `./gradlew integrationTestAll` | **vert sur les trois moteurs** — MySQL, PostgreSQL, SQLite, 2 min 12 s |
| `npx ng test --no-watch` | **18 fichiers, 119 tests** |
| `python3 scripts/check-doc-links.py` | **566 liens, 0 cassé** |
| `gitleaks detect` + ligne de base | **aucune fuite** ; une clé neuve committée par-dessus **échoue** |
| empreinte C4 | enregistrée = réelle (`8aa3fc9d…`) |
| parité des jeux de fichiers `docs/{en,fr}` et ADR | **identiques** |

Ce qui **n'a pas** été exécuté, et qu'aucune note ne doit compter comme acquis : la suite
Playwright (pilotée en CI seulement), et la joignabilité à travers la frontière `docker:dind`,
invérifiable depuis un poste.

---

## 1. Synthèse

| Domaine | Note | Ce qui la fixe |
|---|:---:|---|
| **Documentation & Architecture** | **9,0 / 10** | Structure complète et *vérifiée par machine* ; le contrôle de dérive C4 est plus faible qu'il n'en a l'air |
| **Sécurité & Cryptographie** | **8,3 / 10** | Tout ce que le prompt nomme existe et s'exécute — mais une **24ᵉ route non cloisonnée** subsiste |
| **Qualité du Code** | **8,4 / 10** | Vingt lectures non bornées, dont deux sur des chemins chauds |
| **Conformité & Standards** | **9,2 / 10** | Moteurs et formats présents ; SPDX honnêtement refusé (ADR-0016) |
| **Vérification exécutée** | **8,0 / 10** | Le pipeline existe, tourne, et a trouvé de vrais défauts — mais ne part que si quelqu'un clique |

---

## 2. Documentation & Architecture — 9,0

Les cinq vues Florat existent dans les deux langues, les seize ADR sont appariés en/fr sans
écart, `docs/en` et `docs/fr` ont des jeux de fichiers **identiques** — vérifié par `diff`, pas
à l'œil. Le modèle STRIDE est présent dans les deux langues.

**Ce qui coûte les points.**

**Le contrôle de dérive C4 ne contrôle pas ce que son nom promet.** Le job `c4-drift` compare
une empreinte SHA-256 de `workspace.dsl` à une valeur enregistrée. Il détecte donc qu'on a
modifié le modèle sans régénérer. Il ne peut **pas** détecter que les diagrammes committés ne
correspondent pas au modèle — si l'empreinte a été enregistrée sans que le script tourne
vraiment, le contrôle est vert à jamais. Le fichier CI le reconnaît (« weaker, stated »), et
c'est à son crédit ; ce rapport le compte quand même comme une garantie partielle.

**🟡 D1 — ADR-0001 n'a pas de raisonnement.** Quinze lignes, sections *Context* et *Decision*,
rien sur l'alternative ni sur le coût accepté. Elle est *superseded* par 0010, donc le prix est
faible — mais c'est précisément le scénario que le prompt décrit : elle a été renversée, et on
ne peut pas savoir si le renversement a corrigé une erreur ou perdu une raison.

---

## 3. Sécurité & Cryptographie — 8,3

Le cloisonnement est l'histoire de ce projet, donc je ne me suis pas fié à
`AuthorizationCoverageTest` : j'ai refait le balayage.

**Au niveau contrôleur, le test tient.** Trois contrôleurs sur 44 n'ont ni garde de rôle ni
`VisibilityService` — `AuthController`, `CryptoController`, `TicketingWebhookController` — et
les trois figurent dans la liste justifiée du test. Aucun trou nouveau par cette règle.

### 🟠 A1 — `GET /api/v1/inventory/versions` renvoie l'inventaire de tout le parc

```java
@GetMapping("/versions")
public List<String> versions(@RequestParam String name) {          // pas de principal
    return components.versionsOf("%" + name + "%", Limit.of(200))  // pas de Visibility
```

La requête n'a **aucune** jointure vers un scan ou une cible :

```sql
select distinct c.version from ComponentEntity c
 where lower(c.name) like :name or lower(c.purl) like :name
```

**Et la route voisine, quatre lignes plus haut, filtre.** `search` résout une `Visibility` et
applique `allowed.permits(targetOf(occurrence))` sur chaque ligne. Même contrôleur, même
source de données, une filtre et l'autre non : ce n'est pas un choix de conception, c'est un
oubli.

Ce que ça donne à un lecteur restreint : un oracle. *« Est-ce que quelqu'un, ici, fait tourner
log4j 2.14.1 ? »* — la réponse arrive sans qu'il ait accès au moindre dépôt. Pour un produit
dont le métier est de savoir qui est exposé, c'est la question la plus intéressante qu'on
puisse poser.

### 🟡 A2 — `GET /api/v1/ai/status` publie l'URL interne d'Ollama

```java
public Map<String, Object> getStatus() {
    return Map.of("enabled", …, "ollamaUrl", aiReviewService.ollamaUrl(), …);
```

Accessible à tout compte connecté. Une adresse d'un service interne n'est pas un secret, mais
elle est un point de départ, et rien n'oblige cette route à la donner.

### 🟡 A3 — la règle qui empêche A1 ne peut pas voir A1

`AuthorizationCoverageTest` travaille à la maille **contrôleur** : il exige qu'un contrôleur
*mentionne* `VisibilityService`. `InventoryController` le mentionne — et passe, avec une route
qui ne l'utilise pas.

J'ai tenté un balayage à la maille **route** pour faire mieux. Il a produit 30 candidats, dont
**28 faux positifs** : le filtrage passe très souvent par une méthode d'aide privée
(`requireVisible(principal, …)`, `visible(principal, id)`, `requireVisibleIssue(…)`) qu'aucune
regex ne reconnaît. C'est mon outil qui était faux, pas le code — et c'est la raison honnête
pour laquelle la maille contrôleur a été choisie. Le constat reste : **la règle est plus
grossière que la classe de défaut qu'elle surveille**, et A1 en est la démonstration.

### Ce qui a été vérifié bon

Le durcissement des conteneurs (`cap_drop`, `read-only`, `network: none`, plafonds
mémoire/PID/CPU) est assuré par `ContainerHardeningTest`, qui capture le `HostConfig` réel.
L'isolation de l'agent est un **fait du graphe de build** — `vectispire-agent` ne dépend que de
`vectispire-common`, aucun pilote JDBC sur son classpath — et `AgentIsolationTest` interdit
l'import. La chaîne d'audit, Argon2id, AES-256-GCM, le quatre-yeux et les deux limiteurs de
débit sont couverts par des tests qui tournent dans `check`.

---

## 4. Qualité du Code — 8,4

Spring Boot 4.1 / JDK 25 idiomatique, six couches tenues par ArchUnit, ADR-0007 respectée. La
campagne trois moteurs passe.

### 🟠 B1 — `ThreatIntelFeedService.syncThreatIntel` lit `t_issue` en entier, puis requête par ligne

```java
List<IssueEntity> allOpenIssues = issuesRepo.findAll().stream()
        .filter(i -> !"closed".equalsIgnoreCase(i.getState()) …)
for (IssueEntity issue : allOpenIssues) {
    Optional<ThreatIntelEntity> match = intelRepo.findByCveIdIgnoreCase(issue.getIdentifier());
```

Deux défauts superposés : la table entière chargée puis filtrée **en Java** alors que l'état est
une colonne indexée, et un N+1 par constat. Le job est déclenché par un administrateur
(`POST /epss/sync`), donc ce n'est pas un chemin utilisateur — mais sur l'estimation de 500 000
lignes du dossier, c'est la lecture la plus lourde du dépôt.

### 🟠 B2 — `SecurityScorecardService` lit tous les scans pour répondre « oui » ou « non »

```java
boolean hasAttestation = scansRepo.findAll().stream()
        .anyMatch(s -> repoId.equals(s.getRepoId()) && "completed".equalsIgnoreCase(s.getStatus()));
```

Trois fois dans la même classe, sur un chemin **par requête HTTP** (`GET /scorecards/…`). Une
dérivée `existsByRepoIdAndStatus` fait la même chose en une ligne indexée.

Vingt sites `findAll()` subsistent dans les services. Tous ne sont pas des défauts —
`SettingsService` et `TargetNaming` lisent des tables bornées par le nombre de cibles — mais
**personne ne les distingue mécaniquement** : quatre tests seulement mesurent le coût aux
compteurs Hibernate.

### 🟡 B3 — 13 specs pour 28 pages frontales

Les 119 tests passent et couvrent ce qu'ils couvrent. Quinze pages n'ont aucune spec, dont
plusieurs qui affichent des chiffres agrégés — exactement le genre d'écran où une erreur se lit
comme une donnée.

---

## 5. Conformité & Standards — 9,2

`ComplianceService` porte CRA, NIS 2, DORA et OWASP Top 10. CycloneDX 1.6 avec VEX intégré,
CSAF 2.0, OpenVEX, EPSS et la *reachability* sont produits. **SPDX n'est pas produit, et
ADR-0016 le dit** au lieu de le laisser croire — c'est ce qui fait la note ici : un format
refusé et consigné vaut mieux qu'un format revendiqué et absent.

---

## 6. Vérification réellement exécutée — 8,0

C'est l'axe le plus jeune, et celui qui a le plus bougé aujourd'hui.

**Le pipeline existe et tourne.** `.gitlab-ci.yml` porte treize jobs ; l'étape `verify` a huit
contrôles, `package` construit les deux images **et démarre le plan de contrôle contre un vrai
MySQL**. `.github/workflows/` est conservé comme trace et ne s'exécute pas.

**Les nocturnes ont trouvé de vrais défauts à leur première exécution** — un hôte codé en dur
qui ne survit pas à `docker:dind`, et une image Playwright en retard de treize versions
mineures. Les deux corrigés le jour même. C'est la meilleure preuve possible que cet axe
manquait.

**Ce qui plafonne la note :** les trois nocturnes (`databases`, `dockerfiles`, `e2e`) sont
conditionnés à `$CI_PIPELINE_SOURCE == "schedule"`, et **aucun *schedule* n'existe**. Ils ne
partent aujourd'hui que par un « Run pipeline » manuel. Un contrôle qui dépend de la mémoire de
quelqu'un est exactement ce que cet axe existe pour interdire.

---

## 7. Recommandations, par ordre de coût

| # | Action | Vérifié comment |
|---|---|---|
| 🟠 1 | Cloisonner `GET /inventory/versions` comme sa route sœur : passer le principal, résoudre la `Visibility`, joindre le scan | mesuré : la requête n'a aucune jointure de cible ; `search`, 4 lignes plus haut, filtre |
| 🟠 2 | Remplacer les trois `scansRepo.findAll()` de `SecurityScorecardService` par `existsByRepoIdAndStatus` | lu dans le code ; **non mesuré aux compteurs** — à faire avant de crier victoire |
| 🟠 3 | Borner `syncThreatIntel` : filtrer l'état en SQL, et joindre le renseignement en un lot | lu dans le code, non mesuré |
| 🟡 4 | Retirer `ollamaUrl` de `/ai/status` | lu dans le code |
| 🟡 5 | Créer le *schedule* nocturne dans les réglages CI/CD | **affirmé, non exécuté** — hors de portée d'un audit |
| 🟡 6 | Donner une spec aux pages qui publient des chiffres agrégés | mesuré : 13 / 28 |
| 🟡 7 | Écrire le raisonnement d'ADR-0001, ou la marquer explicitement comme historique | mesuré par balayage des seize ADR |

**Et une recommandation sur la méthode elle-même :** `AuthorizationCoverageTest` devrait
détecter, dans un contrôleur qui connaît `VisibilityService`, une route qui ne consulte ni
`Visibility` ni méthode d'aide reconnue. Mon balayage a échoué à le faire proprement à cause des
aides privées ; la voie praticable est probablement de nommer ces aides par convention
(`requireVisible*`, `visible*`) et de faire porter la règle sur cette convention. Sans quoi la
règle continuera de laisser passer la classe de défaut qu'elle surveille — A1 en est la preuve.
