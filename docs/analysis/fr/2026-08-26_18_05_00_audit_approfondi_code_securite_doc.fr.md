# Rapport d'Audit Approfondi : Documentation, Code Source & Sécurité

* **Projet :** Vectispire — ASPM & Plan de Contrôle de Sécurité Logicielle
* **Date :** 26 août 2026, 18:05
* **Commit audité :** `a791f53f` (`develop`)
* **Périmètre :** les cinq axes de [`PROMPT_AUDIT.md`](../../../PROMPT_AUDIT.md)

> **Douzième passage, le troisième de la journée.** Les deux précédents ont sondé l'autorisation,
> la crypto, le coût des lectures et le contrat d'empreinte. Celui-ci vise le seul axe que douze
> passages ont nommé sans jamais l'exécuter : **la règle ADR-0007, appliquée aux endroits qui ne
> sont pas des constats.**

---

## 0. Ce qui a été exécuté

| commande | résultat |
|---|---|
| `./gradlew check` | **vert** |
| `./gradlew integrationTestAll --rerun-tasks` | **vert sur les trois moteurs**, 2 min |
| `npx ng test --no-watch` | **23 fichiers, 146 tests** |
| `npx playwright test` | **13 sur 13** (exécuté plus tôt dans la journée, navigateur réel) |

---

## 1. Synthèse

| Domaine | Note | Ce qui la fixe |
|---|:---:|---|
| **Documentation & Architecture** | **9,2 / 10** | Parité bilingue vérifiée jusqu'aux titres de section, pas seulement aux noms de fichiers |
| **Sécurité & Cryptographie** | **8,8 / 10** | Inchangé depuis le onzième : rien de neuf trouvé, rien de neuf sondé |
| **Qualité du Code** | **7,9 / 10** | **ADR-0007 est violée à l'ingestion, et la conséquence est visible à l'écran** |
| **Conformité & Standards** | **9,3 / 10** | Un évaluateur de posture, six cartographies |
| **Vérification exécutée** | **9,0 / 10** | La suite navigateur teste enfin quelque chose ; toujours aucun nocturne vert |

---

## 2. Le constat : 🔴 D1 — un analyseur en échec efface l'inventaire des contrats

ADR-0007 énonce la règle : **absent veut dire « n'a pas tourné », vide veut dire « a tourné, n'a
rien trouvé »**. Le prompt la rappelle depuis douze passages. `ScanIngestor` la respecte pour le
SBOM, et le dit à voix haute trois lignes avant de la briser :

```java
// Absent quand le cataloguer n'a pas tourné — et absent veut dire que l'inventaire du scan
// précédent est laissé tel quel plutôt que remplacé par rien.
artifacts.sbom().ifPresent(sbom -> inventory.record(scan.getId(), sbom, graph));

apiInventory.ifPresent(service -> {
    if (artifacts.apiEndpoints().isPresent() || artifacts.apiContracts().isPresent()) {
        service.record(scan,
                artifacts.apiEndpoints().orElse(List.of()),    // ← absent devient vide
                artifacts.apiContracts().orElse(List.of()));   // ←
    }
});
```

**Le garde ne protège que le cas où les deux sont absents.** Si l'extracteur d'endpoints a tourné
et que le cataloguer de contrats a échoué, `record` reçoit `[]` pour les contrats. Et `record`
commence par supprimer :

```java
apiEndpoints.deleteByRepositoryIdOrScanId(repoId, scanId);
apiContracts.deleteByRepositoryIdOrScanId(repoId, scanId);   // inconditionnel
if (endpoints != null && !endpoints.isEmpty()) { … }          // ne réécrit que le non-vide
```

**Tous les contrats connus du dépôt disparaissent parce qu'un analyseur est tombé.**

### Et la conséquence n'est pas une case vide, c'est un verdict faux

`ShadowApiDiff` est correct — c'est l'entrée qu'on lui ment :

```java
if (contracts == null || contracts.isEmpty()) {
    // Aucun contrat déclaré : tous les endpoints du code sont considérés non documentés / fantômes
    return new ShadowApiDiff(List.of(), codeEndpoints, List.of());
}
```

Donc l'écran de surface d'attaque passe **entièrement au rouge** : chaque endpoint est signalé
« API fantôme ». Pas parce que le système a changé — parce qu'un cataloguer a échoué. C'est la
forme exacte que l'ADR-0007 existe pour interdire, à un endroit que son propre exemple ne couvre
pas.

### Pourquoi aucun test ne l'a vu

`ScanIngestorTest` couvre le cas voisin, et le couvre bien :

```java
ScanArtifacts artifacts = ScanArtifacts.builder()
        .apiEndpoints(List.of(endpoint))
        .apiContracts(List.of())        // explicitement vide — « a tourné, rien trouvé »
        .build(Duration.ZERO);
```

Il épingle le comportement **correct** pour une liste vide, et n'exerce jamais le cas ambigu :
`apiContracts` **absent**. C'est précisément ainsi qu'un défaut de cette famille survit — le test
qui l'entoure a l'air de le couvrir.

### Correctif proposé

Passer les `Optional` jusqu'à `record`, et n'effacer que ce que l'on a de quoi remplacer. Un
analyseur absent doit laisser sa moitié de l'inventaire intacte, exactement comme le SBOM trois
lignes plus haut.

---

## 3. Documentation — 9,2

La parité bilingue avait été vérifiée sur les **noms de fichiers** au dixième passage. Cette fois
sur le **contenu** : les cinq vues Florat ont le même nombre de titres de section en français et en
anglais (8, 11, 7, 6, 11). Ce n'est pas une preuve de traduction fidèle, et c'est ce qu'un
contrôle mécanique peut dire — une divergence de structure y serait apparue.

---

## 4. Vérification — 9,0, en hausse et pour une raison précise

La suite navigateur **teste enfin quelque chose**. Avant aujourd'hui, chaque cas naviguait avec
`page.goto` après connexion — or le jeton vit en mémoire, délibérément pas dans `localStorage`, si
bien que toute navigation complète le perdait et renvoyait à l'écran de connexion. Quatre cas
n'assertaient que « un `body` est visible », ce qui y est vrai. Les treize passent maintenant, et
chacun a été mis à l'épreuve par mutation.

Ce qui plafonne toujours : **aucun pipeline nocturne n'est passé au vert.**

---

## 5. Recommandations

| # | Action | Vérifié comment |
|---|---|---|
| 🔴 1 | Passer les `Optional` jusqu'à `ApiInventoryService.record` et n'effacer que ce qu'on remplace | **mesuré** : `record` supprime inconditionnellement, `ShadowApiDiff` traite « vide » comme « rien de déclaré » |
| 🟡 2 | Un test d'ingestion pour `apiContracts` **absent** — pas seulement vide | mesuré : `ScanIngestorTest` ne couvre que le cas vide |
| 🟡 3 | Balayer les autres `Optional` du domaine pour la même confusion | argumenté : deux sites trouvés ici, la famille n'a pas été balayée |
