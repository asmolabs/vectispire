# 0039 — Le SBOM d'un build complète l'inventaire du scanner : l'union, la version déclarée par le build l'emporte, le plus récent pour chaque scan suivant

**Date :** 2026-10-03 · **Statut :** proposée · **S'appuie sur :** [0007](0007-none-is-not-an-empty-list.md), [0017](0017-custom-checks-as-container-images.md), [0032](0032-security-checklists.md), [0033](0033-internal-reactions-leave-through-the-outbox.md), [0035](0035-report-plugins.md) · **Décideur :** Laurent Boucher

*Proposée avec le lot G10, qui l'implémente telle qu'écrite ; la préséance ci-dessous est celle que le
code applique, et les questions de la fin sont à trancher à la revue.*

## Contexte

Tout inventaire que Vectispire tient d'un dépôt est celui du scanner : Syft lit l'arborescence des
sources et liste ce que ses manifestes déclarent. Pour une arborescence Maven, cela ne suffit pas, de
deux façons qui produisent chacune une réponse fausse :

- **Une version gérée par un parent ou une BOM vaut `UNKNOWN`.** Syft ne résout pas une BOM importée :
  `spring-core` déclaré sans version sous `spring-framework-bom` sort en `"version": "UNKNOWN"` avec un
  purl sans version. Une ligne de checklist `component_versions` n'a alors pas de donnée pour lui
  (`version_unrecorded`, [0032](0032-security-checklists.md) §6).
- **Une bibliothèque tirée transitivement n'est pas listée du tout.** Les poms déclarent `spring-core` ;
  le build embarque `spring-jcl` avec. Une ligne demandant « `snakeyaml` est-il utilisé, et dans quelle
  version » reçoit *absent de son SBOM* — un **faux « non »**, que les réponses automatiques
  ([0032](0032-security-checklists.md), amendement « les scans répondent aux lignes qu'ils mesurent »)
  écrivent dans une checklist comme « non ».

Le build connaît le graphe résolu : le `makeAggregateBom` de `cyclonedx-maven-plugin` et le plugin
CycloneDX de Gradle l'écrivent en JSON CycloneDX. Vectispire admet déjà les documents d'un pipeline par
les sources déclarées ([0017](0017-custom-checks-as-container-images.md) §7,
[0032](0032-security-checklists.md) §7) : SARIF, couverture, rapports de tests. La question n'est pas
comment recevoir le SBOM du build — la même porte — mais ce qu'il signifie à côté de celui du scanner,
et pour quels lecteurs.

## Décision

### 1. Reçu comme un rapport : un quatrième genre, `sbom`

`POST /api/v1/repositories/{id}/build-sbom-imports`, par `ReportImportService` et les mêmes étapes
que la couverture : une clé d'intégration, jamais une session ; une clé déclarée comme source active
dont les genres comptent `sbom` (portée `report_import` — il n'ouvre aucun problème) ; un dépôt que la
clé voit, dans la portée de la source (404 sinon, dans les mots d'une absence) ; un corps sous
`vectispire.http.max-body.sbom-import` (32 Mo). Chaque refus de ce que l'appelant prétend est audité
`REPORT_IMPORT_REFUSED` et signalé `VECTI-SEC-027` ; un import accepté est `BUILD_SBOM_IMPORTED`, après
le commit, avec le SHA-256 du document et le scan complété. `commit` et `branch` sont la parole du
pipeline.

Le document est lu par `BuildSbom` : `bomFormat` `CycloneDX`, `specVersion` 1.4, 1.5 ou 1.6, en JSON
seulement ; imbrication, chaînes et nombres bornés, clé en double refusée, contenu après la fin
refusé ; au plus 50 000 composants, imbriqués compris ; une valeur plus large que sa colonne refusée,
jamais tronquée. **Rien n'est récupéré** : `externalReferences`, un `bom-link`, un `$schema` ne sont
jamais suivis. Un document sans `components` est refusé — il n'a rien listé à quoi on puisse le tenir
— et un tableau vide est un build sans dépendance ([0007](0007-none-is-not-an-empty-list.md)).

### 2. Gardé par l'inventaire, avec ses composants

`inventory` garde l'import (`t_build_sbom`) et ses composants (`t_build_sbom_component`), pas
seulement un chiffre : chaque scan suivant est complété par lui. La gouvernance — la source, la clé,
l'audit — reste à `plugins`, qui ajoute `inventory` à sa liste pour cela ; la dépendance va dans un
seul sens.

### 3. La préséance : l'inventaire du scanner, complété par le SBOM de build le plus récent

**L'inventaire d'un scan est ce que son scanner a listé, complété par le SBOM de build le plus récent
de son dépôt qui déclare la branche du scan ou aucune branche.** La complétion
(`InventoryCompletion`) :

1. **L'union.** Tout composant listé par le scanner reste ; tout composant que le build liste et que le
   scanner ne liste pas est ajouté. Le scanner voit ce qu'aucun build ne déclare — un front à côté de
   l'arborescence Maven, un fichier embarqué — et le build voit ce que le scanner ne peut pas voir.
2. **Un paquet, reconnu par son purl** sans version, qualificatifs ni sous-chemin. Le qualificatif par
   défaut `type=jar` du plugin Maven est retiré à la lecture, si bien que
   `pkg:maven/g/a@1.0?type=jar` et le `pkg:maven/g/a@1.0` de Syft sont un seul paquet ; tout autre
   qualificatif reste. Une ligne du scanner sans purl ne correspond à rien — un nom n'est pas une
   identité d'un écosystème à l'autre.
3. **La version déclarée par le build l'emporte** là où les deux listent un paquet, quoi qu'ait écrit
   le scanner : `UNKNOWN`, rien, ou une version lue dans un manifeste. Le build a résolu le graphe et
   embarqué ce qu'il déclare. Un build qui ne déclare pas de version laisse celle du scanner.
4. **Plusieurs versions d'un paquet dans le build** complètent une ligne du scanner avec celle de sa
   propre version, sinon la première listée ; les autres sont ajoutées. Rien de ce que le build a
   déclaré n'est perdu.

**Quand elle s'applique.** Deux fois : quand l'inventaire d'un scan est écrit (le puits de
l'ingestion, dans sa transaction), et quand un SBOM arrive — le scan terminé le plus récent du dépôt
qui garde un SBOM est complété à nouveau dans la transaction de l'import, qui met aussi en file la
réaction des checklists par l'outbox ([0033](0033-internal-reactions-leave-through-the-outbox.md)),
si bien que chaque lecteur la voit dès la réponse à l'import. Un SBOM plus récent remplace la
complétion d'un plus ancien : ce que l'ancien avait ajouté s'en va, et une ligne qu'il avait complétée
retrouve la version et le purl du scanner (`scanned_version`, `scanned_purl`).

**Les scans plus anciens gardent ce qu'ils ont reçu.** L'inventaire d'un scan est de l'histoire : seul
le scan le plus récent bouge à un import. **Un scan dont le scanner n'a gardé aucun inventaire n'est pas
complété** — son étape SBOM a échoué, ou la rétention des charges a purgé le SBOM avant sa lecture : la
parole du build complète l'inventaire d'un scanner, elle ne remplace pas un scan qui n'a pas regardé.

**La provenance sur chaque ligne.** `t_component.origin` est nul pour le scanner (toute ligne écrite
avant V82 et toute ligne qu'un scan écrit), `build` pour un composant que seul le build a listé, `both`
pour une ligne du scanner que le build liste aussi — la version et le purl sont alors ceux du build,
ceux du scanner gardés à côté. `declared_license` porte la licence déclarée par le build ;
`build_sbom_id` nomme l'import, comme simple référence.

### 4. Qui le lit, et comment

Les lignes complétées *sont* l'inventaire : aucun lecteur ne choisit entre deux sources, donc aucun ne
peut contredire un autre.

| Lecteur | Ce qu'il lit après ceci |
|---|---|
| La recherche de composants, `GET /api/v1/inventory/search` | les lignes de chaque scan, chacune avec `source` (`scanner`, `build`, `both`) et, pour `both`, `scannerVersion` |
| L'inventaire consolidé du projet et son export CycloneDX | le scan terminé le plus récent de chaque cible, complété ; chaque composant fusionné avec `sources` |
| L'export de projet ([0035](0035-report-plugins.md) §1) | la même chose, `inventory.components[].sources` — un champ facultatif, schéma **1.1** |
| Les règles de checklist `component_versions` et `component_present` | les composants du scan le plus récent de chaque dépôt où l'étape de dépendances a produit (`ComponentCatalog.componentsOf`, la lecture que les deux règles partagent), **complétés par le SBOM de build le plus récent de la branche de ce scan** : les versions du build à la place d'`UNKNOWN`, les bibliothèques transitives présentes. Le scan qu'elles lisent ne change pas ; un SBOM de build seul n'est pas un scan, et une règle qui exige que ce scan garde son SBOM l'exige toujours |
| L'inventaire des licences et ses décomptes | le SBOM du scanner et les lignes de composants, comme avant ; une ligne complétée remplace l'entrée que le SBOM du scanner donnait sous sa propre version, avec la licence déclarée par le build (sinon celle du scanner). Le tampon des décomptes compte les lignes complétées par un build et l'import le plus récent parmi elles, si bien qu'un SBOM qui arrive les fait recompter sans qu'aucun scan ne bouge |
| Le diff de SBOM entre deux scans | les lignes des deux scans, complétées comme chacun l'a été |
| La correspondance des vulnérabilités | **inchangée** : Grype tourne dans le scan sur le SBOM du scanner. Un SBOM de build n'ouvre ni ne résout aucun problème |

### 5. Rétention et suppression

Les imports et leurs composants partent avec la **fenêtre de preuve** (`evidence_retention_days`,
`BuildSbomRetentionTask`), zéro ne purgeant rien. Les lignes avec lesquelles un scan a été complété
restent avec le scan : un inventaire est ce qu'il a reçu. Un dépôt dont le pipeline a cessé d'envoyer
des SBOM lit donc le scanner seul sur ses scans suivants une fois le dernier SBOM sorti de la fenêtre.
Les imports d'un dépôt partent avec lui (`TargetDeleted`, première phase) ; les lignes complétées des
scans partent avec les scans.

## Rejeté

- **Le SBOM du build seulement s'il est plus récent que le scan.** La règle paraît plus sûre et
  surprend davantage : un scan planifié d'une arborescence inchangée passe après le dernier push, si
  bien que chaque semaine calme ramènerait le faux « non » jusqu'au push suivant. Les scans
  n'enregistrent aucun commit à comparer.
- **Le SBOM du build à la place de celui du scanner.** Il perd ce que seul le scanner voit —
  l'arborescence npm à côté de la Maven, les binaires embarqués — et fait d'un pipeline qui oublie un
  module l'autorité sur tout le dépôt.
- **Une fusion calculée par chaque lecteur.** Six lecteurs, six occasions de se contredire :
  l'inventaire, les licences et la checklist auraient répondu à trois questions sur une seule
  arborescence. Matérialisée une fois, ils lisent les mêmes lignes.
- **La version du build seulement là où celle du scanner vaut `UNKNOWN`.** Syft lit un `1.0` déclaré
  là où la médiation de Maven a embarqué `1.1` ; garder celle du scanner garderait la mauvaise. Là où
  le build déclare une version, c'est celle qui est embarquée.
- **Grype sur le SBOM du build.** Utile, et pas ici : la correspondance tourne dans la forme fermée du
  scan, sur l'exécuteur, et un second matcher hors d'elle est une décision à part entière.

## Conséquences

- Le faux « non » d'une ligne `component_versions` ou `component_present` disparaît pour un dépôt dont
  le pipeline envoie son SBOM, et `version_unrecorded` avec lui, dès la réponse à l'import — le remède
  que nomme la preuve de cette règle (« importez un SBOM produit par le build »).
- Un SBOM de build périmé — un pipeline qui a cessé d'en envoyer — continue de compléter les scans
  jusqu'à ce que la fenêtre de preuve le retire. Sa date d'import est dans l'historique et au journal
  d'audit.
- Deux imports complétant un même scan au même instant sont sérialisés par un verrou sur les lignes du
  scan ; un scan dont le scanner n'a rien listé n'a aucune ligne à verrouiller, et deux tels imports
  peuvent ajouter tous deux leurs composants — l'import ou le scan suivant du dépôt les réécrit.
- L'export de projet passe en **1.1** : un champ facultatif, selon la règle du schéma.

## Questions ouvertes

1. Un SBOM de build plus ancien que la fenêtre de preuve — ou qu'un âge donné — doit-il cesser de
   compléter les scans avant d'être purgé ?
2. La portée (`required`, `optional`, `excluded`) d'un composant CycloneDX doit-elle l'exclure de la
   lecture de la checklist ? Aujourd'hui tout composant listé compte, comme les dépendances de test de
   Syft.
