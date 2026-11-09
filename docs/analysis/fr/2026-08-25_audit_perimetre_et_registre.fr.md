# Audit du Périmètre & du Registre : Documentation, Code Source & Sécurité (Français)

* **Projet :** Vectispire — Control Plane ASPM & Sécurité Logicielle
* **Date d'analyse :** 25 août 2026 (cinquième passe)
* **Évaluateur :** Claude (Anthropic) — audit automatisé du code, de la sécurité et de la documentation
* **Périmètre :** Les quatre axes de [`PROMPT_AUDIT.md`](../../../PROMPT_AUDIT.md)
* **Précédents :** [Approfondi](2026-08-25_audit_approfondi_code_securite_doc.fr.md) 7,9 → [Post-Remédiation](2026-08-25_audit_post_remediation.fr.md) 8,9 → [Quatre Axes](2026-08-25_audit_approfondi_4_axes.fr.md) 8,7 → [Vérification](2026-08-25_audit_verification.fr.md) 9,1

> **Ce que cette passe a de différent.** Les quatre commits depuis le dernier rapport ont surtout
> *retiré* des choses — deux moteurs de base, un second scanner de secrets, un réglage documenté qui
> n'avait jamais existé. La suppression est le changement le plus susceptible de laisser quelque
> chose pendre et le moins susceptible qu'on s'en aperçoive : cette passe a donc commencé par
> chasser les orphelins. Puis elle est allée sur un terrain qu'aucune des quatre précédentes
> n'avait couvert : le verdict de gate, et le frontal.

---

## 📊 1. Tableau Récapitulatif des Notes

| Domaine évalué | Vérification | Cette passe | Statut |
|---|:---:|:---:|:---:|
| **Documentation & Architecture** | 9,2 | **9,0 / 10** | 🟢 Une mesure l'a fait baisser |
| **Sécurité & Cryptographie** | 9,1 | **9,3 / 10** | 🟢 Frontière de l'agent énoncée précisément |
| **Qualité du Code & Architecture** | 8,9 | **9,1 / 10** | 🟢 Périmètre ramené au déployable |
| **Conformité Réglementaire & Standards** | 9,3 | **9,3 / 10** | 🟢 Certifiable |
| **Global** | 9,1 | **9,2 / 10** | 🟢 |

La documentation *baisse* alors que tout le reste monte, et la raison est le constat ci-dessous :
cinq décisions d'architecture ont reçu leur raisonnement cette session, ce qui a rendu possible de
mesurer combien n'en ont toujours aucun.

### Le constat

| # | Constat | Sévérité | Preuve |
|:--:|---|:--:|---|
| **D1** | **Neuf des quinze ADR sont des coquilles de onze lignes ou moins**, et ce sont de façon disproportionnée celles que le code cite. La [0007](../../architecture/fr/decisions/0007-none-is-not-an-empty-list.md) — « none is not an empty list » — fait 11 lignes, et c'est la règle référencée par `ScanRunner`, `ScannerContractTest`, les deux documents techniques, et la remédiation qui a fermé le constat le plus grave de toute cette série d'audits. | 🟠 **Moyenne** | Mesuré sur `docs/architecture/en/decisions/` |

**Pourquoi c'est un constat et non un haussement d'épaules.** Le registre n'est pas décoratif ici :
cette session s'en est servie deux fois comme argument. La
[0015](../../architecture/fr/decisions/0015-one-secrets-engine.md) a retiré le second moteur de
secrets *sur le précédent de* la [0010](../../architecture/fr/decisions/0010-one-scan-runner.md),
qui fait sept lignes et n'énonce aucun raisonnement — le précédent a donc dû être reconstruit depuis
le code plutôt que lu. Et le périmètre des moteurs s'est renversé trois fois en six jours
précisément parce qu'aucun enregistrement n'expliquait le renversement précédent.

Les coquilles, par la fréquence à laquelle le code s'appuie dessus :

| ADR | Lignes | Cité par |
|---|:--:|---|
| **0007** — none is not an empty list | 11 | `ScanRunner`, `ScannerContractTest`, `ScanArtifacts`, les deux documents techniques |
| **0010** — un seul exécuteur de scan | 7 | `ScanRunner`, et l'ADR 0015 comme précédent |
| **0006** — règles semgrep écrites ici | 11 | Le modèle STRIDE, comme atténuation Tampering |
| **0005** — la qualité ne bloque jamais la gate | 11 | `PolicyGate`, `TriageStatus` |
| **0002** — la base porte la file | 11 | `ScanQueue`, la documentation du pipeline |

**Correctif :** écrire la 0007 d'abord. C'est la décision dont la violation a produit le défaut le
plus coûteux de ce projet, et celle vers laquelle un lecteur se tournera le plus volontiers.

**Une instance plus petite du même phénomène :** [`PROMPT_AUDIT.md`](../../../PROMPT_AUDIT.md)
demande toujours « ADR 0001 à 0013 ». Il y en a quinze. La spécification de l'audit a dérivé du
système qu'elle audite.

---

## 📚 2. Documentation & Architecture — 9,0

**Vérifié inchangé et sain :** les cinq vues Florat à parité de lignes exacte (88/75/52/66/73),
STRIDE complet (E1–E4, P1–P5, DS1–DS2, F1–F16, six catégories, 171 lignes de chaque côté),
**402 liens relatifs qui résolvent, 0 cassé**, et les diagrammes C4 en phase avec `workspace.dsl` —
vérifié en exportant et comparant, ce qui est désormais aussi un job de CI.

**Ce qui s'est amélioré, et c'est le plus grand changement documentaire de la série.** Cinq
décisions ont gagné leur raisonnement : la
[0003](../../architecture/fr/decisions/0003-long-polling-for-agents.md) (11 → 57 lignes), la
[0009](../../architecture/fr/decisions/0009-four-engines.md) (7 → 32), la
[0013](../../architecture/fr/decisions/0013-flyway-multi-dialect-migrations.md) (7 → 40), plus la
[0014](../../architecture/fr/decisions/0014-two-engines-and-a-test-fixture.md) et la
[0015](../../architecture/fr/decisions/0015-one-secrets-engine.md) écrites de neuf. Chacune consigne
ce à quoi l'on renonce autant que ce que l'on gagne, ce qui est la moitié qu'un enregistrement de
décision omet d'ordinaire et celle dont le renversement suivant a besoin.

**Ce qui la maintient à 9,0 :** le D1 ci-dessus. Le registre est désormais à moitié argumenté, et la
moitié non argumentée est celle qui sert tous les jours.

---

## 🛡️ 3. Sécurité & Cryptographie — 9,3

### 3.1 Le verdict de gate, audité pour la première fois

[`PolicyGate`](../../../vectispire-java/vectispire-common/src/main/java/com/asmolabs/vectispire/common/domain/gate/PolicyGate.java)
produit la réponse qui fait échouer la construction de quelqu'un, et aucune passe antérieure ne
l'avait lu. Il tient :

- **KEV prime sur la sévérité**, et signale une violation par anomalie plutôt que deux — la sortie
  reste actionnable au lieu d'être dupliquée.
- **Les constats de qualité ne peuvent jamais atteindre un verdict.** `gateParticipation()` en fait
  une propriété du type de constat plutôt qu'un drapeau de politique : aucune configuration ne peut
  les y faire entrer.
- **La revue IA est sur activation**, parce qu'un modèle local à qui l'on remet le code source du
  dépôt peut être orienté par lui.
- **`harden()` est un vrai contrôle de sécurité et se lit comme tel.** Un pipeline ne peut que
  *resserrer* la politique stockée ; une demande de `fail_on_severity: null` est refusée, et — le
  point qui compte — **le refus est signalé en retour** plutôt qu'ignoré en silence, de sorte qu'un
  pipeline croyant avoir désactivé une règle apprend qu'il ne l'a pas fait. Dix-neuf tests.

### 3.2 La frontière de l'agent, énoncée telle qu'elle est

La passe précédente avait établi que « l'agent ne détient aucun identifiant » était trop fort.
L'ADR 0003 consigne désormais la frontière en trois parties : aucune base (imposé par le graphe de
modules, la violation échoue donc à la compilation), aucune `ENCRYPTION_KEY`, et des clés de
déploiement **uniquement** en mode `DELEGATED`, scellées X25519 → HKDF → AES-256-GCM vers la clé que
l'agent a annoncée à l'enrôlement, auditées à chaque envoi. Elle consigne aussi que l'agent refuse
une enveloppe qu'il ne peut pas ouvrir plutôt que de passer le chiffré à git, et qu'un mode inconnu
se lit `LOCAL`.

Cette précision est la différence entre une affirmation qu'un évaluateur peut vérifier et une qu'il
dévalue.

### 3.3 Un seul moteur de secrets

Le second moteur a disparu, et la
[0015](../../architecture/fr/decisions/0015-one-secrets-engine.md) consigne pourquoi : il
n'acceptait que des images gitleaks-compatibles, ce cas est déjà couvert en nommant l'image
primaire, et rien ne l'exerçait. Ce qui reste est la signature qui rend le défaut de perte
silencieuse d'origine **inexprimable** — `ran(…)` ne compile pas contre une `List` nue, et
`ScannerContractTest` le vérifie par réflexion pour tout scanner ajouté ensuite.

---

## ⚙️ 4. Qualité du Code & Architecture — 9,1

**Spring Boot 4.1.0 / JDK 25**, zéro `TODO`/`FIXME` en production, les six règles ArchUnit, JaCoCo à
**83,6 % instructions / 69,4 % branches** sur `common.domain` face à un plancher 80/65.

**Le périmètre correspond désormais au déployable.** PostgreSQL et MySQL, avec SQLite nommé pour la
fixture de test qu'il a toujours été — il ne peut pas démarrer l'application packagée sous
`ddl-auto: validate`, ce qui était su à l'intérieur du profil de test et jamais reflété dans le
périmètre supporté. Trois jeux de quatorze migrations, aucun orphelin laissé par le retrait, et
`integrationTestAll` vert en 2 min 44 (contre 3 min 58).

**Le frontal, audité pour la première fois.** 55 sources, 34 gabarits, TypeScript `strict` et
Angular `strictTemplates` tous deux actifs, et **aucun contournement de sanitisation** — la seule
occurrence d'`innerHTML` est un commentaire mettant en garde contre. Le client est généré depuis
`openapi.json`, les DTO ne peuvent donc pas dériver de l'API à la main.

**Résiduel :** 15 fichiers de spec pour 55 sources. La couverture unitaire est la moitié la plus
mince de la stratégie de test, et les campagnes E2E qui compenseraient n'ont toujours jamais tourné
sur un runner.

---

## 📋 5. Conformité Réglementaire & Standards — 9,3

Six référentiels évalués dans le domaine pur ; CycloneDX, SPDX, CSAF 2.0, OpenVEX, EPSS et
reachability tous présents. Le moteur mesure toujours le control plane et pas seulement la flotte —
un contrôle est plafonné à `PARTIAL` quand la capacité qui le porte est éteinte — et le miroir
d'audit est désormais actif par défaut en compose, de sorte que le plafond `AUDIT_AND_LOGGING` ne
s'applique plus au déploiement livré.

La projection groupée derrière le sommaire est désormais exercée sur chaque moteur par
`ComplianceSummaryIntegrationTest`, qui remplace la vérification à la main que la passe précédente
avait dû mener.

---

## 🎯 6. Recommandations Priorisées

### 🟠 Ensuite
1. **Écrire l'ADR 0007 correctement**, puis les 0010, 0006, 0005 et 0002 *(D1)*. Commencer par la
   0007 : c'est la règle dont la violation a produit le défaut le plus grave de cette série.
2. **Exécuter `nightly.yml` et le nouveau job `images` une fois sur un runner.** Les deux ont été
   raisonnés et corrigés en local ; aucun n'a tourné là où il tournera.
3. **Mettre à jour `PROMPT_AUDIT.md`** — il demande les ADR 0001 à 0013, et il y en a quinze.

### 🟡 Plus tard
4. Relever la couverture unitaire du frontal, ou énoncer délibérément que les campagnes E2E la
   portent.
5. Étendre le plancher JaCoCo au-delà de `common.domain` maintenant que la forme des requêtes est
   stabilisée.
6. Se demander si `SecurityDebtService` et l'outbox de notifications méritent la couverture
   d'intégration que le sommaire de conformité vient de recevoir — ni l'un ni l'autre n'a été audité
   en cinq passes.

---

## 7. Conclusion

Cinq passes, et la nature de ce qu'elles trouvent a complètement changé. La première a trouvé des
contrôles mal câblés. La deuxième, des défauts introduits par la réparation. La troisième, un chemin
de perte silencieuse dans le traitement des identifiants fuités. La quatrième a exécuté le logiciel
et établi que les correctifs tenaient sur des moteurs que les tests ne touchent jamais. Celle-ci a
cherché ce que la suppression avait laissé derrière, n'a rien trouvé, et a dû aller chercher dans la
gate et le frontal — tous deux en bon état.

Ce qu'elle a trouvé est une mesure que seule la réparation partielle du registre a rendue possible :
**neuf décisions d'architecture sur quinze consignent encore ce qui a été choisi et non pourquoi**,
et ce sont celles que le code cite. Ce n'est pas un défaut du logiciel. C'est la différence entre un
projet capable de s'expliquer à la personne suivante et un projet qui renversera une quatrième fois
la même décision.

**9,2 / 10.**
