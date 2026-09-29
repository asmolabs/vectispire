# 0032 — Une checklist de sécurité est le modèle de l'organisation, versionné, rempli par projet par des personnes, et prérempli seulement à partir de preuves qui ont été produites

**Date :** 2026-09-28 · **Statut :** acceptée · **Amende :** [0017](0017-custom-checks-as-container-images.md) §7 · **Décideur :** Laurent Boucher

> **Note (2026-09-28).** Les identifiants de signature SIEM que cette décision nomme `ZAN-SEC-nnn`
> sont émis en `VECTI-SEC-nnn` depuis la version qui suit la 0.9.0 — mêmes numéros, mêmes sens. Le
> texte ci-dessous est laissé tel qu'accepté ; voir le [catalogue SIEM](../../../../docs-site/integrations/siem.fr.md#catalogue-des-evenements).

## Contexte

Avant la mise en service d'un produit, beaucoup d'organisations demandent à l'équipe qui le
construit de remplir une **checklist de sécurité** et de la remettre à qui approuve la livraison. La
checklist appartient à l'organisation : un classeur écrit par sa fonction sécurité, révisé de temps
en temps, et rendu rempli — dans le même format — pour chaque produit. Certaines de ses lignes
demandent ce que Vectispire mesure déjà (dépendances analysées, analyse statique suffisamment
propre, aucun secret dans l'arborescence), d'autres ce qu'un pipeline de CI mesure et que
Vectispire ne voit jamais (couverture de tests, une suite de tests d'architecture), et le reste ce
que seule une personne peut affirmer (un test de pénétration a été mené, la documentation existe).

Aujourd'hui ce classeur se remplit à la main, à partir de captures d'écran des outils. Les réponses
ne portent ni date ni preuve, l'auteur de chaque ligne est celui qui a enregistré le fichier en
dernier, et une nouvelle révision du modèle se remplit de zéro ou, pire, en recopiant les anciennes
réponses sur des lignes qui ne demandent plus la même chose.

La décision [0023](0023-solutions-projects-and-repositories.md) a introduit les projets précisément
parce que « les rapports et les checklists s'écrivent par projet ». Cet enregistrement conçoit la
checklist.

### Ce que le produit a déjà, et pourquoi rien de cela n'est la checklist

- **La déclaration d'applicabilité** ([`StatementOfApplicability`](../../../../vectispire-java/vectispire-common/src/main/java/com/asmolabs/vectispire/common/domain/compliance/StatementOfApplicability.java))
  est une seule déclaration pour toute l'organisation, par référentiel, dont les contrôles sont une
  énumération du jar. Une checklist est par projet, ses contrôles arrivent dans un fichier écrit par
  l'organisation, et ils changent d'une version à l'autre. Ce que la DdA enseigne — et que cet
  enregistrement garde — c'est que **l'artefact intéressant est le désaccord entre ce qui est déclaré
  et ce qui est mesuré**, et qu'un contrôle prouvé ailleurs est « non mesuré ici », jamais un constat.
- **Les imports SARIF depuis des sources internes déclarées** ([0017](0017-custom-checks-as-container-images.md)
  §7) : une clé d'intégration, une source déclarée, un périmètre, une liste d'outils autorisés, chaque
  document accepté haché et audité. Les rapports de couverture et de tests sont le même problème — la
  sortie d'une CI interne, déposée par une clé — et reprennent ce modèle plutôt que d'en inventer un
  second.
- **Les quatre yeux** sur le triage ([`IssueTriageService`](../../../../vectispire-java/vectispire-core/src/main/java/com/asmolabs/vectispire/core/issues/IssueTriageService.java)) :
  comptés comme deux personnes et non deux rôles, derrière `FOUR_EYES_APPROVAL_REQUIRED`, qu'on ne
  peut pas activer tant qu'aucun second approbateur n'existe.
- **La signature** ([`SigningKeyService`](../../../../vectispire-java/vectispire-core/src/main/java/com/asmolabs/vectispire/core/crypto/SigningKeyService.java))
  et [`ProductVersion`](../../../../vectispire-java/vectispire-core/src/main/java/com/asmolabs/vectispire/core/settings/ProductVersion.java) :
  tout document produit par Vectispire est signé par une seule clé et indique la version qui l'a
  produit.

### À quoi ressemble un modèle — sa structure, pas son contenu

Le premier modèle apporté par le responsable est interne à l'organisation qui l'a écrit. **Son
contenu n'entre pas dans ce dépôt** : ni contrôle, ni nom de domaine, ni fichier. Ce qu'il a appris,
c'est sa forme, qui est vraisemblablement celle de tout classeur de ce genre :

- un classeur de trois feuilles : des instructions en prose, la checklist elle-même, et une feuille
  portant la liste des valeurs de réponse ;
- sur la feuille de checklist, une ligne de titre fusionnée, puis des **cellules d'en-tête** — une
  date, le produit, l'auteur — chacune une cellule de libellé avec sa cellule de valeur à côté, puis
  une **ligne d'en-têtes de colonnes**, puis **une ligne par contrôle** ;
- sept colonnes par contrôle : domaine, objectif, contrôle, personne à contacter, KPI, réponse,
  commentaire. Le domaine et l'objectif sont écrits sur la première ligne de leur groupe et **laissés
  vides en dessous**, à lire comme « idem ». Le contact est un rôle, pas une personne. Le KPI est du
  texte libre, le plus souvent vide. L'en-tête du commentaire dit qu'il est obligatoire quand la
  réponse est négative ;
- les cellules de réponse portent une **liste de validation** qui pointe vers la feuille des valeurs
  — deux valeurs, un oui et un non, dans la langue de l'organisation. Cette validation est stockée
  comme élément d'extension Office, et une bibliothèque courante a annoncé en chargeant le fichier
  qu'elle l'abandonnerait : un aller-retour par un modèle de tableur aurait perdu la seule règle que
  le modèle impose ;
- la cellule de valeur de la date contient une **formule recalculée à chaque ouverture**, qui date
  toute copie enregistrée du jour où quelqu'un l'a regardée pour la dernière fois ;
- **rien n'identifie un contrôle sauf son texte** : pas de colonne d'identifiant, une numérotation
  dans le libellé de l'objectif, un commentaire de cellule sur une ligne.

Tous les exemples de cet enregistrement sont inventés pour lui.

## Décision

### 1. Un module, `checklists`, et ce qu'il possède

Un nouveau module vertical `core.checklists` (décisions 0028–0030), au-dessus de `plugins` et
en dessous de `compliance` et `platform`. Il possède les modèles, leurs versions et leurs lignes, les
checklists des projets, leurs réponses, preuves et mesures, et les documents rendus. Son
`package-info` déclare, chacune avec sa raison :

| Dépendance | Pourquoi |
|---|---|
| `access`, `access::security` | les marqueurs des routes, `VisibilityService`, et la garde sur le projet entier (§8) |
| `targets` | les projets, leurs dépôts, les planifications des dépôts ; `ProjectDeleted` |
| `scanning`, `scanning::queries` | la plus récente analyse qui a examiné un type, l'empreinte de son SBOM (§6) |
| `issues`, `issues::queries` | les comptes ouverts et résolus par portée d'outil et par sévérité, via `IssueFilters` |
| `plugins` | les résultats des plugins, les imports SARIF, les imports de couverture et de rapports de tests (§7) |
| `inventory` | les composants du plus récent SBOM, pour la règle de versions de composants |

Le socle qu'il utilise (`audit`, `settings`, `crypto`) est partagé et n'est pas listé.
`ArchitectureTest.MODULES` et `ModularityTest.MODULES` gagnent le module. `checklists` n'est pas dans
`accessForRoutesOnly` : ses services refusent eux-mêmes un projet (§8).

Les parties pures — le modèle, l'évaluation des règles sur des vues, le lecteur et le rédacteur de
classeur — vivent dans `vectispire-common/domain/checklists`, JDK seul : `java.util.zip` et StAX,
aucune bibliothèque de tableur (§10).

Les tables, toutes créées par des migrations communes à partir de V49 (le prochain numéro libre au
moment du lot) avec les placeholders de `MigrationDialect`, **sans clé étrangère** — les écouteurs du
propriétaire les purgent, sur le modèle de `t_plugin_activation` :

| Table | Propriétaire | Contenu |
|---|---|---|
| `t_checklist_template` | `checklists` | slug (unique), nom, créé par et le |
| `t_checklist_template_version` | `checklists` | modèle, ordinal, libellé, statut (`draft`, `published`, `retired`), le SHA-256 et les octets du fichier source, la **disposition** (JSON : feuille, cellules d'en-tête, lettres des colonnes, première et dernière ligne, mots de réponse), l'offre ou non de « non applicable », importée, publiée, retirée par et le |
| `t_checklist_item` | `checklists` | version, **clé de ligne**, position, domaine, objectif, contrôle, contact, texte du KPI, **empreinte du contenu**, sa ligne dans la feuille, l'exigence de preuve, la règle liée (type et paramètres, JSON) |
| `t_checklist` | `checklists` | projet, version du modèle, **révision**, statut (`draft`, `submitted`, `signed_off`, `superseded`), l'auteur de l'en-tête, ouverte, soumise, renvoyée, validée par et le, la révision qu'elle remplace, une colonne `open_slot` (ci-dessous) |
| `t_checklist_answer` | `checklists` | checklist, ligne, valeur, commentaire, répondu par et le, la mesure sur laquelle elle repose, reportée depuis quelle réponse et par qui, `needs_confirmation`. **En ajout seul** |
| `t_checklist_evidence` | `checklists` | checklist, ligne, un lien ou un fichier (nom, type de média, taille, SHA-256), réalisé le, valable jusqu'au, ajouté par et le, retiré par et le |
| `t_checklist_file` | `checklists` | les octets d'un fichier déposé, à part, pour qu'aucune liste ne les charge jamais |
| `t_checklist_measurement` | `checklists` | checklist, ligne, type de règle, empreinte des paramètres, résultat, raison, instant « en date du », calculée le, la preuve (JSON) |
| `t_checklist_document` | `checklists` | le paquet rendu d'une révision validée : octets, SHA-256, signature, `ProductVersion`, produit le |
| `t_sarif_source` (+ `kinds`) | `plugins` | les types de rapports qu'une source déclarée peut livrer (§7) |
| `t_coverage_import` | `plugins` | source, clé, dépôt, format, comptes de lignes et de branches, SHA-256, le commit et la branche que le pipeline indique |
| `t_test_report_import`, `t_test_suite_result` | `plugins` | les totaux et le SHA-256 de l'import ; par suite, son nom et ses comptes |
| `t_scan` (+ `examined_types`) | `scanning` | les types intégrés qu'une analyse a effectivement examinés (§6) |

Deux remarques de portabilité, tranchées maintenant parce que chacune a son piège :

- **Les colonnes binaires demandent un placeholder qui n'existe pas encore** : `${bytes}` — `bytea`,
  `longblob`, `blob`. Un nouveau placeholder est permis ; sa valeur est figée dès qu'une migration
  l'utilise. Les entités le mappent avec un type JDBC explicite, **jamais `@Lob`**, que Hibernate mappe
  sur un grand objet PostgreSQL (`oid`) plutôt que sur `bytea` ; `SchemaParityIntegrationTest` tranche
  sur les trois moteurs.
- **« Au plus une checklist ouverte par projet »** est une contrainte d'unicité sur
  `(project_id, open_slot)` où `open_slot` vaut `1` pour une révision en brouillon ou soumise et
  `null` sinon. Les trois moteurs admettent plusieurs nulls sous une contrainte d'unicité, là où un
  index partiel aurait demandé trois dialectes pour le dire.

### 2. Le modèle

Un **modèle** est la checklist de l'organisation, sous un slug. Il a des **versions** ; une ligne
appartient à une version. Une ligne porte :

- **domaine, objectif, contrôle, contact, KPI** — les mots du modèle, stockés tels qu'importés et
  affichés tels qu'écrits. Le contact est du texte : un rôle, pas un compte ;
- une **clé de ligne**, stable d'une version à l'autre (§4), et une **empreinte du contenu**,
  SHA-256 du domaine, de l'objectif, du contrôle, du texte du KPI, de l'exigence de preuve et de la
  règle liée, normalisés ;
- une **exigence de preuve** : aucune, un lien ou un fichier, ou un fichier ; et, quand une preuve
  expire, une validité en mois ;
- au plus une **règle liée** (§6) — une ligne que Vectispire sait mesurer.

Une **réponse** appartient à un ensemble fermé, `ChecklistAnswer` : `YES`, `NO`, `NOT_APPLICABLE`.
Le commentaire est **obligatoire pour `NO` et `NOT_APPLICABLE`** — une réponse négative sans sa
raison est la ligne dont le lecteur du document a le plus besoin, et « non applicable » sans
justification est une exclusion que personne n'a argumentée, ce que la DdA refuse déjà
(`EXCLUDED_WITHOUT_JUSTIFICATION`). Une version n'offre `NOT_APPLICABLE` que si son importateur l'a
dit (question ouverte 1). Bornés avant l'écriture : un commentaire à 4 000 caractères, un lien à
2 000, un lien `https:` ou `http:` seulement.

Une **checklist** est une révision des réponses d'un projet contre une version. Son **en-tête** est
le nom du projet (le produit), l'auteur — le compte qui en répond, choisi à l'ouverture — et la
date, qui dans un document est **l'instant de la validation**, jamais « maintenant » (§10).

### 3. Importer un modèle depuis un classeur

`POST /api/v1/checklist-templates/{slug}/versions` reçoit le `.xlsx` en corps brut (pas de
multipart : aucune route multipart n'existe, et `RequestBodyLimitFilter` borne un corps brut là où il
ne pourrait pas borner une partie), 10 Mo, une ligne à part dans le filtre. Le lecteur, dans
`common/domain`, refuse avant d'analyser : plus de 200 entrées zip, plus de 50 Mo décompressés, une
entrée compressée plus de cent fois, une DTD dans une partie (un classeur n'en a jamais besoin), une
cible de relation externe. Les macros (`.xlsm`) et le format binaire sont refusés par le type de
contenu et par l'absence de la partie classeur.

L'import est **une version brouillon, prévisualisée, puis publiée** — jamais publiée d'un seul geste :

1. **La disposition est proposée, puis confirmée.** Le lecteur trouve la ligne d'en-têtes de
   colonnes, les cellules d'en-tête et la liste de réponses (la validation posée sur la colonne de
   réponse, et la plage qu'elle nomme), et les propose. Il les trouve par la structure du fichier —
   plages de validation, cellules fusionnées, ligne suivie d'une suite de lignes remplies — et jamais
   par une liste de mots attendus, qui serait le vocabulaire d'une organisation inscrit dans le
   produit. L'importateur confirme ou corrige chaque lettre de colonne et chaque cellule d'en-tête.
   La disposition confirmée est stockée avec la version ; le rendu ne lit rien d'autre.
2. **Les cellules vides de domaine et d'objectif sont recopiées vers le bas** dans les lignes de
   contrôle, comme la feuille l'entend. Une ligne dont la cellule de contrôle est vide n'est pas une
   ligne de checklist.
3. **Les mots de réponse sont associés** à `YES` et `NO` par l'importateur — les mots du modèle,
   quelle que soit sa langue — et à `NOT_APPLICABLE` si la version l'offre.
4. **Le KPI reste du texte.** Les seuils d'une règle sont des paramètres structurés liés par une
   personne (§6). Un KPI n'est jamais analysé pour en tirer un seuil : un nombre lu dans une phrase
   est une règle que personne n'a écrite, pour la même raison que la nature d'un échec vient d'un
   type et jamais des mots d'un message. La prévisualisation montre le texte du KPI à côté des
   paramètres liés, pour que la personne qui les lie voie tout désaccord.
5. **Les lignes sont appariées avec la version précédente** (§4), et l'appariement est affiché.
6. **Publiée**, par qui en a le droit (§8). Une version publiée est immuable. Changer un seuil, une
   liaison ou un mot, c'est une nouvelle version — qui peut être **dérivée** de la précédente sans
   nouveau fichier : même classeur, même disposition, nouvelles liaisons.

Le fichier source est conservé, octets et SHA-256 : le rendu écrit dedans, et un auditeur peut
comparer le document remis au modèle qu'il prétend suivre.

### 4. Les versions, et comment les réponses les traversent

**Une nouvelle version ne réécrit jamais une réponse donnée sous une ancienne.** Les réponses sont
des lignes d'une checklist, une checklist appartient à une version, et publier une version ne change
aucune checklist.

**Identité d'une ligne.** La clé vient d'une colonne d'identifiant quand la disposition en nomme une ;
sinon elle est dérivée du texte normalisé du contrôle. Apparier une nouvelle version avec la
précédente :

- même clé, même empreinte — **inchangée** ;
- même clé, empreinte différente — **modifiée** : le KPI, la liaison ou la formulation a bougé ;
- pas de clé en face — **ajoutée** ou **retirée** ;
- l'importateur peut apparier à la main une ligne ajoutée avec une ligne retirée (« même contrôle,
  reformulé »), ce qui donne à la nouvelle ligne l'ancienne clé et la marque modifiée. L'appariement
  est enregistré dans la version.

**Passer un projet à une nouvelle version** est un acte explicite sur ce projet
(`POST /api/v1/projects/{id}/checklists`, en nommant la version). Il ouvre une nouvelle révision sur
la nouvelle version et y **reporte** les réponses : chaque réponse reportée est une nouvelle ligne qui
pointe vers la réponse d'origine, garde l'auteur et l'instant de celle-ci comme les siens, et nomme
qui l'a reportée et quand. La réponse d'une ligne inchangée est reportée comme courante. Celle d'une
ligne modifiée est reportée avec `needs_confirmation`, et une révision qui en contient une ne peut
pas être soumise tant que quelqu'un n'a pas répondu à nouveau ou confirmé. Une ligne ajoutée démarre
sans réponse ; la réponse d'une ligne retirée reste là où elle a été donnée. Les mesures ne sont
**jamais reportées** — elles sont recalculées (§6). La révision précédente reste lisible ; en
brouillon ou soumise, elle devient `superseded` ; validée, elle reste validée.

Retirer une version empêche d'ouvrir de nouvelles checklists sur elle ; toute checklist qui l'utilise
reste lisible et exportable.

### 5. Une checklist par projet : sa vie et son historique

```
            soumettre               valider
  draft ────────────► submitted ────────────► signed_off
    ▲                     │                       │
    └──── renvoyer ───────┘                       │ rouvrir
    ▲  (avec une raison)                          ▼
    └────────────────────────────── nouvelle révision, draft
```

- **Répondre** écrit une nouvelle ligne de réponse ; la précédente n'est pas modifiée. La réponse
  courante est la plus récente par ligne, l'**historique** est l'ensemble des lignes avec leur auteur
  et leur instant. L'auteur est le principal, jamais un nom pris dans le corps de la requête. On ne
  répond pas à une révision soumise : on la renvoie d'abord.
- **Une preuve** est un lien ou un fichier déposé (25 Mo, une ligne à part dans les limites de corps),
  avec la date à laquelle le travail a été fait et, pour une ligne qui le demande, sa validité. Un
  fichier n'est rendu qu'en téléchargement — `Content-Disposition: attachment`,
  `X-Content-Type-Options: nosniff`, son type de média stocké jamais cru pour l'affichage — parce
  qu'un fichier HTML ou SVG déposé et servi en ligne est un script sur l'origine du plan de contrôle.
  Une preuve est retirée, jamais supprimée, tant que la révision est en brouillon ; le retrait est daté
  et attribué.
- **Soumettre** exige que chaque ligne ait sa réponse, chaque réponse négative ou non applicable son
  commentaire, chaque exigence de preuve soit remplie et en cours de validité, qu'aucune réponse
  n'attende de confirmation, et que les mesures soient recalculées (§6).
- **Rouvrir** une révision validée ouvre la révision suivante avec toutes les réponses reportées
  comme courantes (même version, rien à confirmer) ; la révision validée n'est jamais modifiée.

### 6. Ce que Vectispire préremplit, à partir de quoi, et quand il refuse

**Vectispire ne répond jamais.** Il écrit des **mesures** ; des personnes écrivent les réponses. Une
ligne liée à une règle affiche sa mesure à côté de la réponse, et le formulaire de réponse en est
prérempli — un clic pour accepter, qui enregistre une réponse de cette personne reposant sur cette
mesure. Une réponse écrite par le système mettrait, dans un document qu'une personne signe, une
affirmation que cette personne n'a jamais faite ; l'acteur est le principal.

Une mesure a un résultat — `PASS`, `FAIL` ou `NO_DATA` — une raison typée, l'instant **en date
duquel** elle vaut (la plus ancienne preuve sur laquelle elle repose), l'instant où elle a été
calculée, et sa preuve : pour chaque dépôt du projet, l'analyse ou l'import lu, sa date, son
empreinte et les chiffres.

**Les règles sont un ensemble fermé** (`ChecklistRule`, une interface scellée dans `common/domain`,
un record de paramètres par type). Aucun paramètre n'a de valeur par défaut du produit qui décide
d'un résultat : les seuils sont le KPI de l'organisation, énoncés quand la règle est liée, et une
règle sans âge maximal est refusée à la liaison. Le formulaire propose sept jours.

| Type | Lit | `PASS` quand, sur chaque dépôt du projet |
|---|---|---|
| `DEPENDENCY_ANALYSIS` | la plus récente analyse dont l'étape de dépendances **a produit**, son SBOM ; la planification du dépôt | une telle analyse est dans l'âge maximal, elle a stocké un SBOM, et — si la règle le demande — le dépôt est planifié au moins aussi souvent que l'âge maximal ; seuils facultatifs sur les vulnérabilités ouvertes |
| `FINDINGS_THRESHOLD` | pour chaque portée d'outil nommée — `builtin:sast`, `builtin:secret`, `builtin:iac`, `builtin:vulnerability`, `plugin:<id>`, `import:<source>/<outil>` — la plus récente analyse ou le plus récent import où cette portée **a produit** ; le backlog de cette portée | chaque portée a produit dans l'âge maximal, et les comptes ouverts et taux de résolution atteignent les seuils par sévérité |
| `COVERAGE_THRESHOLD` | le plus récent import de couverture (§7) | il est dans l'âge maximal et son taux de lignes (ou de branches) atteint le minimum — par dépôt, ou pondéré sur le projet si la règle le dit |
| `TEST_SUITE_PASSED` | le plus récent import de rapport de tests (§7) et les suites qui correspondent à un motif glob | au moins une suite correspond, elle a exécuté au moins le minimum de tests indiqué (les tests ignorés ne comptent pas), aucun échec ni erreur, dans l'âge maximal |
| `COMPONENT_VERSIONS` | les composants du plus récent SBOM | chaque paquet déclaré (un préfixe purl) est présent dans une des versions que l'organisation autorise |

« Aucun secret en clair dans la configuration », c'est `FINDINGS_THRESHOLD` sur `builtin:secret`
avec tous les comptes à zéro, proposé comme préréglage. Un exemple inventé de liaison :
*« L'analyse statique tourne à chaque modification »*, KPI *« aucun critique, au plus deux élevés,
60 % des moyens résolus »*, lié à `FINDINGS_THRESHOLD` sur `builtin:sast` et
`import:quality-server/sonarqube`, âge maximal 7 jours, `critical.max_open = 0`,
`high.max_open = 2`, `medium.min_resolved_ratio = 0.6`.

**Le taux de résolution** d'une sévérité est résolus ÷ (résolus + ouverts) sur les problèmes du
projet dans ces portées, **le triage réglé laissé hors des deux côtés** — la règle que suit tout
chiffre de risque, avec `not in (TriageStatus.settledWireNames())`, pour qu'un statut que cette
version ne connaît pas compte encore comme ouvert. Chaque compte utilisé figure dans la preuve (la
question ouverte 6 porte sur la fenêtre).

**`COMPONENT_VERSIONS` est désactivée par défaut au sens le plus fort** : le produit ne livre aucune
liste de paquets, et le type n'apparaît dans aucun modèle tant qu'une organisation ne l'a pas lié avec
ses propres préfixes et versions autorisées. Il existe pour l'organisation qui exige ses bibliothèques
internes à des versions maintenues ; rien sur l'une d'elles en particulier n'est écrit dans le code ni
dans la documentation.

**`NO_DATA` n'est jamais `PASS`, et dit pourquoi** — l'ADR [0007](0007-none-is-not-an-empty-list.md)
appliquée à une ligne de checklist. Les raisons sont un ensemble fermé :

| Raison | Sens |
|---|---|
| `NO_REPOSITORY` | le projet n'a aucun dépôt. « Chacun de zéro dépôt réussit » est exactement la vérité vide que cette règle interdit |
| `NEVER_EXAMINED` | un dépôt n'a aucune analyse ni aucun import où la portée a produit |
| `STALE` | le plus récent est plus vieux que l'âge maximal |
| `STEP_ABSENT` | l'étape ou le plugin était absent dans toutes les analyses de la période — n'a pas regardé, et non n'a rien trouvé |
| `EXAMINATION_UNRECORDED` | les analyses de la période précèdent `examined_types`, donc on ne sait pas si l'étape a tourné |
| `NOT_APPLICABLE_ANYWHERE` | un plugin était `not_applicable` sur tous les dépôts : il ne s'applique à aucun, et une ligne validée par un outil qui n'a rien regardé serait validée sur des données absentes |
| `SUITE_NOT_FOUND`, `NO_TEST_RAN` | aucune suite ne correspond, ou celles qui correspondent n'ont rien exécuté |

**Les trois états d'un plugin sont conservés** ([0017](0017-custom-checks-as-container-images.md)) :
un dépôt où le plugin était `not_applicable` est laissé hors des chiffres de cette portée et ne la fait
pas échouer ; un dépôt où il était `absent` est `STEP_ABSENT`. L'outil d'un import SARIF a produit
quand l'import a été accepté — la 0017 refuse déjà un run en échec ou sans résultats.

**`t_scan.examined_types` est un prérequis.** Une analyse enregistre quels plugins ont produit
(`plugin_steps`) mais pas quelles étapes intégrées l'ont fait : `ScanIngestor` calcule l'ensemble et
le jette, et les échecs d'étape ne survivent que comme une phrase dans `error`. L'ensemble est écrit
sur l'analyse à partir de V49. Les analyses antérieures restent `EXAMINATION_UNRECORDED` jusqu'à ce
que chaque dépôt soit analysé de nouveau, ce qui est la réponse honnête : rien n'a enregistré si
elles avaient regardé.

**La fraîcheur est rejugée à chaque étape qui s'y fie.** Une mesure est calculée à la demande, à la
soumission, et de nouveau dans la validation. Une réponse `YES` repose sur une mesure ; si le recalcul
de la validation ne donne plus `PASS`, la validation est refusée et nomme les lignes — une signature
ne doit pas attester d'une preuve qui a cessé d'être vraie entre la soumission et la signature. Une
révision validée fige ses mesures avec elle.

**La réponse et la mesure sont réconciliées** dans le vocabulaire de la DdA, affichées à l'écran et
dans le document :

| Réponse | Mesure | Ligne |
|---|---|---|
| `YES` | `PASS` | cohérente |
| `YES` | `FAIL` | **contredite** — refusée à la soumission (question ouverte 3) |
| `YES` | `NO_DATA` | déclarée, non mesurée — permise avec un commentaire et une preuve (question ouverte 4) |
| `NO` | `PASS` | sous-déclarée — permise ; le commentaire dit pourquoi |
| toute | aucune règle liée | non mesurée ici |

**Les contrôles de traçabilité** — une piste d'audit, un rôle qui la consulte — décrivent le produit
construit, que Vectispire ne voit pas. Ils restent manuels. Une organisation qui les prouve par ses
propres tests lie `TEST_SUITE_PASSED` à ces suites.

**Performance et limites.** Les règles lisent les API des propriétaires (`ScanCatalog`,
`IssueCatalog`, les catalogues des plugins et de l'inventaire), chacune gagnant la requête groupée
dont elle a besoin — jamais le repository d'un autre module. Les identifiants des dépôts d'un projet
atteignent ces requêtes par lots de 1 000, la règle de `TargetCatalog.carryingCredentials` : un
`in (:list)` dimensionné par les données échoue un jour.

### 7. Deux nouvelles entrées : couverture et rapports de tests, depuis des sources internes déclarées

La couverture et les rapports de tests sont la sortie de la CI interne, comme son SARIF, et arrivent
de la même façon. Ceci amende la 0017 §7 :

- **Une source déclarée indique les types qu'elle peut livrer** : `sarif`, `coverage`, `test_report`
  (`t_sarif_source.kinds`, `sarif` pour toute ligne existante). Un pipeline, une clé, une déclaration,
  un périmètre — un projet ou un dépôt, jamais le parc. La table garde son nom : la renommer est une
  migration à elle seule pour rien qu'un lecteur voie.
- **Une nouvelle portée de clé, `report_import`**, jamais accordée par défaut, exigée pour les deux
  nouveaux types ; `sarif_import` reste celle du SARIF. Une clé présentée pour un type que sa source ne
  déclare pas, ou sans la portée, est refusée en 403, auditée et signalée.
- **Les routes**, `@AcceptsApiKey(REPORT_IMPORT)`, `@RequiresWriteAccount`, avec les refus de la
  0017 dans l'ordre de la 0017 — une session n'est pas une source (403), source non déclarée (403),
  dépôt caché ou hors périmètre (404, dans les mots d'un dépôt absent) :
  - `POST /api/v1/repositories/{id}/coverage-imports?format=jacoco|cobertura|lcov`, 16 Mo. Le format
    est déclaré, jamais deviné ; un corps qui ne se lit pas comme tel est un 400. Stockés : lignes et
    branches couvertes et totales, l'outil et sa version si le format les indique, le SHA-256, et le
    `commit` et la `branch` que le pipeline indique — gardés comme la parole du pipeline, vérifiés
    contre rien.
  - `POST /api/v1/repositories/{id}/test-report-imports`, 32 Mo : un document JUnit XML (racine
    `testsuites` ou `testsuite`) ou un zip de tels documents, puisque la plupart des outils de build
    écrivent un fichier par classe — au plus 5 000 entrées, et les gardes zip du lecteur. Stockés :
    les totaux, et par suite son nom et ses comptes.
- **Le XML est lu sans rien résoudre.** Certains formats de couverture s'ouvrent sur un `DOCTYPE` qui
  nomme une DTD, donc refuser tout DOCTYPE les refuserait : la déclaration est tolérée, jamais
  chargée, et une déclaration d'entité est refusée. Profondeur, nombre d'attributs et d'éléments sont
  bornés comme ceux de `SarifReport`.
- **Un rapport vide est refusé, pas enregistré.** Une couverture sur zéro ligne n'est ni 0 % ni
  100 % ; un rapport de tests sans aucun test n'est pas une suite réussie. Les deux sont des 400, en
  mots.
- Acceptés : `COVERAGE_IMPORTED`, `TEST_REPORT_IMPORTED`. La page du dépôt liste le plus récent de
  chaque, avec sa source et sa date.

La couverture par fichier, et les cas de test eux-mêmes, ne sont pas stockés dans cette version.

### 8. Qui peut faire quoi

| Acte | Qui | Marqueur, et ce que vérifie le service |
|---|---|---|
| Importer, dériver, lier des règles sur une version brouillon | `canWriteGovernance` — gouverneur de la plateforme, administrateur, RSSI | `@RequiresSecurityLead`, qui admet exactement ces trois |
| Publier, retirer une version | les mêmes, et, avec les quatre yeux, **pas la personne qui l'a importée ou dérivée** | idem |
| Déclarer une source de rapports | gouverneur de la plateforme | `@RequiresPlatformGovernor`, comme les sources SARIF |
| Lire les checklists d'un projet | quiconque voit **le projet entier** | `@RequiresAccount` + la garde ci-dessous |
| Ouvrir, répondre, joindre, soumettre, renvoyer, rouvrir | `canCauseEffects`, projet entier visible | `@RequiresWriteAccount` + la garde |
| Valider | `canApproveTriage` — administrateur, RSSI, security champion — projet entier visible, et, avec les quatre yeux, **pas l'auteur de la soumission** | `@RequiresWriteAccount` (aucun marqueur ne porte exactement les approbateurs) + la garde + le drapeau et la comparaison dans le service |

**Le projet entier, ou rien.** Une checklist parle pour chaque dépôt de son projet, et ses mesures
portent des chiffres de chacun. Un lecteur qui ne voit qu'une partie d'un projet lirait, en une seule
ligne, l'état de dépôts qui lui sont cachés. Les checklists d'un projet sont donc visibles quand la
visibilité de l'appelant est tout, quand le projet lui est accordé en tant que tel, ou quand chacun de
ses dépôts est visible et qu'il y en a au moins un ; sinon 404, dans les mots d'un projet absent
(question ouverte 5). La garde est `RowVisibility.requireWhollyVisibleProject`, qui émet un
`VisibleProject` — les services de checklist le reçoivent, jamais un identifiant nu, et refusent par
lui ; les routes laissent le refus au service (`routesLeaveTheRefusalToTheirServices`). Une clé
d'intégration restreinte à un dépôt ne voit jamais un projet entier, donc la route du document qui
accepte `@AcceptsApiKey(EXPORT)` répond 404 à une telle clé.

**Le gouverneur de la plateforme définit la checklist et ne la remplit pas.** Il peut écrire les
modèles — il décide des règles — et ne détient ni `canCauseEffects` ni `canApproveTriage` : il ne peut
ni répondre ni valider. L'auditeur lit tout et n'écrit rien.

**Les quatre yeux sur la validation suivent le réglage de la plateforme**,
`FOUR_EYES_APPROVAL_REQUIRED`, comparés comme deux personnes à la manière du triage (question
ouverte 2). Le document dit lequel s'est appliqué : soumis par qui, validé par qui, et si la règle
exigeait qu'ils diffèrent.

### 9. Audit et SIEM

Chaque écriture est une `AuditOperation`, enregistrée après validation de la transaction (un
`TransactionTemplate` pour les écritures, puis `AuditLogService.record`). Le corps est privé, la
méthode auditée le seul chemin d'entrée.

`CHECKLIST_TEMPLATE_IMPORTED`, `CHECKLIST_TEMPLATE_DERIVED`, `CHECKLIST_TEMPLATE_PUBLISHED`,
`CHECKLIST_TEMPLATE_RETIRED`, `CHECKLIST_OPENED`, `CHECKLIST_MOVED_TO_VERSION`, `CHECKLIST_ANSWERED`,
`CHECKLIST_EVIDENCE_ADDED`, `CHECKLIST_EVIDENCE_WITHDRAWN`, `CHECKLIST_SUBMITTED`, `CHECKLIST_RETURNED`,
`CHECKLIST_SIGNED_OFF`, `CHECKLIST_SIGN_OFF_REFUSED`, `CHECKLIST_REOPENED`, `CHECKLIST_EXPORTED`,
`COVERAGE_IMPORTED`, `TEST_REPORT_IMPORTED`, `REPORT_IMPORT_REFUSED`.

Événements SIEM, par l'outbox (décision 0025). Les numéros sont proposés, figés par
`SecurityEventTypeTest` quand ils sont émis :

| Id | Événement | Pourquoi un SOC le veut |
|---|---|---|
| `ZAN-SEC-024` | modèle de checklist publié ou retiré | ce que chaque projet atteste a changé |
| `ZAN-SEC-025` | checklist validée | une attestation de livraison a été donnée, et par qui |
| `ZAN-SEC-026` | validation refusée ou checklist renvoyée | un refus des quatre yeux, ou une preuve qui a cessé de tenir |
| `ZAN-SEC-027` | import de rapport refusé | une clé utilisée pour ce que sa source n'a pas déclaré — le jumeau de `ZAN-SEC-023` |

Une source déclarée dont les types changent est `ZAN-SEC-022` : c'est le même acte — qui peut déposer
quoi — et son identifiant est le contrat. Les réponses ne signalent rien : c'est du travail, pas un
événement de sécurité.

### 10. Le classeur rempli, signé — rendu dans le cœur ; les plugins de rapport plus tard

**Le document.** `GET /api/v1/projects/{id}/checklists/{revision}/document` renvoie un zip :

- `checklist.xlsx` — **le fichier du modèle lui-même, retouché**. Le rendu copie chaque partie du
  paquet octet pour octet et ne réécrit que les cellules de réponse et de commentaire de chaque ligne
  de contrôle et les cellules de valeur de l'en-tête : la réponse dans le mot du modèle, le
  commentaire tel qu'écrit, l'auteur, le produit, et la date **comme valeur — l'instant de la
  validation**, qui remplace une formule si le modèle en avait une (et supprime la chaîne de calcul,
  qui nommerait sinon une formule disparue). Toutes les autres feuilles, les listes de validation,
  les extensions, les commentaires, les styles survivent parce que rien ne les lit. Une feuille est
  **ajoutée**, `Evidence`, une ligne par contrôle : réponse, auteur, instant, résultat de la mesure,
  date et résumé de la preuve, liens et empreintes des preuves, puis l'auteur de la soumission, le
  valideur et la règle des quatre yeux (question ouverte 12). Les cellules sont écrites en chaînes en
  ligne pour que la table des chaînes partagées reste intacte. Les entrées sont écrites dans leur
  ordre d'origine avec des horodatages fixes, pour qu'une révision se rende en les mêmes octets.
- `checklist.json` — la même déclaration, lisible par une machine : projet, révision, slug du modèle,
  version et SHA-256 de la source, chaque ligne avec ses réponses et leur historique, mesures et
  empreintes des preuves, auteur de la soumission, valideur, `ProductVersion`. Les pièces jointes sont
  nommées par leur empreinte, pas incluses.
- `checklist.xlsx.sig`, `checklist.json.sig` — des signatures détachées par la clé de signature,
  vérifiables avec `cosign verify-blob --key` contre la clé publique publiée, comme tout autre export.

Le paquet d'une révision **validée** est rendu et signé dans la validation et stocké dans
`t_checklist_document` ; la route sert ces octets, de sorte que le document qu'un auditeur reçoit
l'année suivante est celui qui a été signé. Une révision en brouillon ou soumise se rend à la demande,
sans signature, sa feuille `Evidence` s'ouvrant sur *« Brouillon — non validé »*.

**Pourquoi le cœur rend la première version, et pourquoi le plugin de rapport vient plus tard.**

- La signature appartient de toute façon au plan de contrôle : la clé ne le quitte jamais, donc un
  plugin rendrait des octets et le cœur les signerait. Concevoir cette passation — quelles données
  d'un projet un conteneur peut recevoir, sous quelle forme, et ce que prétend alors une signature sur
  la sortie d'un plugin — est une décision à part entière, et c'est au bloc « plugins de rapport » du
  P3 qu'elle appartient.
- Un plugin de rapport reçoit les données d'un projet comme un plugin d'analyse reçoit une
  arborescence — dans la forme fermée, sans réseau, une sortie bornée. Réponses, preuves et chiffres
  sont confidentiels d'une manière qu'une arborescence déjà remise à un scanner ne l'est pas. Cette
  frontière mérite son propre enregistrement plutôt que d'être tranchée en sous-produit de la première
  checklist.
- Le premier rendu est une fonction pure dans `common/domain` — les octets du modèle et une
  déclaration `checklist.json` en entrée, les octets du paquet en sortie — testable en processus
  contre des classeurs générés. **`checklist.json` est le contrat d'entrée qu'un plugin de rapport
  recevra** ; le rendu du cœur en devient l'implémentation intégrée, comme les scanners intégrés à côté
  des plugins.
- Aucune bibliothèque de tableur : le rendu n'a pas besoin de comprendre un classeur, seulement de
  remplacer une poignée de cellules dans une partie. Une bibliothèque qui charge puis réenregistre un
  paquet garde ce qu'elle modélise, et la seule règle que ce modèle impose vivait dans une extension
  qu'un lecteur courant abandonne.

### 11. Hors périmètre

- Les images de conteneur dans une checklist : elles ne sont pas rangées dans des projets (0023).
- Les checklists par dépôt, par solution, ou pour toute l'organisation (c'est la DdA).
- Les `.xls` anciens, les `.ods`, les classeurs à macros, et les formules évaluées par le produit.
- L'affectation des lignes à des comptes depuis la colonne de contact, les rappels, les échéances, les
  notifications.
- Exécuter un DAST ou un test de pénétration : le produit enregistre qu'il a été fait.
- La couverture par fichier, les cas de test individuels, les tendances.
- Les checklists signées dans le dossier de preuves de conformité — une étape ultérieure, qui fera
  dépendre `compliance` de `checklists`.
- Le mécanisme des plugins de rapport (§10), et tout autre rendu que le classeur.
- Une signature électronique qualifiée de la validation : la validation est un acte authentifié et
  audité, et le document est signé par la clé de la plateforme.

## Alternatives considérées

- **La checklist comme un référentiel de plus de la déclaration d'applicabilité.** La DdA est une
  déclaration pour l'organisation, sur des contrôles inscrits dans le jar ; elle n'a ni projet, ni
  version, ni fichier de modèle. L'étirer ferait de sa ligne « non déclaré » du bruit sur chaque
  projet.
- **Livrer une checklist.** Le modèle de l'organisation fait autorité, et le premier n'est pas le
  nôtre à publier. Le produit livre un modèle de données et un importateur ; un modèle d'exemple pour
  la suite de tests est généré par le test, à partir de contrôles inventés.
- **Vectispire répondant lui-même aux lignes mesurables.** Plus rapide, et cela mettrait dans un
  document signé des affirmations qu'aucune personne n'a faites. Des mesures à côté des réponses
  gardent l'acteur comme principal et gardent le désaccord visible, et c'est par lui qu'un évaluateur
  commence.
- **Analyser la colonne KPI pour en tirer des seuils.** Lit des règles dans de la prose ; la
  formulation d'un modèle n'est pas un contrat. Des paramètres structurés, liés et publiés par une
  personne, avec le texte du KPI à côté.
- **Indexer les réponses par numéro de ligne, ou réécrire les réponses sur la nouvelle version en
  place.** Un numéro de ligne bouge quand une ligne est insérée ; réécrire les réponses est
  précisément ce que l'exigence interdit. Des copies reportées qui pointent vers leur origine,
  confirmées là où la ligne a changé, gardent les deux versions vraies.
- **Une bibliothèque de tableur (Apache POI, ou un aller-retour par un modèle).** Une grosse
  dépendance avec un historique d'avis XML et zip, et un aller-retour ne garde que ce qu'il modélise.
  Retoucher les cellules d'une partie garde tout le reste par construction.
- **Des fichiers sur le disque du plan de contrôle.** Ils échapperaient à la sauvegarde de base que
  l'exercice de restauration prouve, et une seconde instance ne les verrait pas. Des octets en base,
  bornés, dans une table qu'aucune liste ne lit.
- **La couverture par SARIF, ou un plugin qui exécute les tests.** SARIF n'a pas de couverture ;
  exécuter des tests demande un build, que la forme fermée interdit (0017 §8).
- **Un second type de source déclarée pour les rapports de CI.** Un pipeline aurait besoin de deux
  clés et de deux déclarations pour un seul producteur ; un type sur la déclaration unique dit la même
  chose une fois.
- **Valider une ligne quand le projet n'a aucun dépôt, ou quand une portée ne s'appliquait nulle
  part.** La vérité vide que l'ADR 0007 existe pour refuser.

## Conséquences

- Un 27e module, `checklists` ; la liste de `package-info` ci-dessus, revue ligne par ligne.
- Des migrations à partir de V49, écrites une fois dans `common` si elles ne diffèrent que par les
  types ; `${bytes}` rejoint `MigrationDialect`. `integrationTestAll` pour chaque lot qui les touche.
- `t_scan.examined_types` : le préremplissage à partir des analyses commence à fonctionner pour un
  dépôt à sa première analyse après la mise à jour. Les notes de mise à jour le disent, et les lignes
  disent `EXAMINATION_UNRECORDED` d'ici là.
- Une nouvelle portée de clé, `report_import` ; de nouvelles limites de corps (modèle 10 Mo, preuve
  25 Mo, couverture 16 Mo, rapports de tests 32 Mo), chacune une ligne de `RequestBodyLimitFilter`
  avec sa raison.
- De nouvelles opérations d'audit et quatre identifiants SIEM ; le test du catalogue les fige.
- De nouvelles routes : le contrat OpenAPI est régénéré à chaque lot backend, les types du client
  avec lui.
- Aucune `MaintenanceTask` : tout est calculé à la lecture et figé à la validation. Une preuve dont
  la validité expire est visible à la lecture suivante, pas annoncée.
- De la documentation dans les deux langues : une page du guide pour les checklists de projet, une
  page d'administration pour les modèles, la page d'intégration CI pour les deux imports, et le lien
  depuis la page de conformité.
- Une checklist signée ne vaut que ce que valent ses entrées : un chiffre de couverture est la parole
  du pipeline, liée à une clé déclarée et hachée, et le document dit laquelle. C'est la même limite
  que la 0017 énonce pour le SARIF, redite ici parce qu'une checklist est l'endroit où quelqu'un
  l'oubliera.

## Questions tranchées le 2026-09-28

Le responsable a accepté chaque recommandation ci-dessous telle qu'elle est écrite ; chacune fait désormais partie de la décision.

Chacune avec la recommandation de cette proposition.

1. **« Non applicable ».** L'offrir ? *Recommandé : par version, désactivé sauf si l'importateur lui
   associe un mot ; son commentaire est obligatoire. Quand la liste de valeurs du modèle n'a pas ce
   mot, l'importateur en fournit un ; le rendu l'écrit et ne modifie pas la liste du modèle.*
2. **Les quatre yeux sur la validation : le réglage de la plateforme, ou toujours ?** *Recommandé :
   le réglage. Une installation avec un seul approbateur ne pourrait sinon jamais valider, et activer
   le réglage exige déjà un second approbateur ; le document dit quelle règle s'est appliquée.*
3. **`YES` contre une mesure en échec.** Refuser, ou permettre avec un commentaire ? *Recommandé :
   refuser à la soumission. Un faux positif se règle par le triage, que les chiffres laissent alors
   de côté ; une organisation en désaccord avec la règle change la liaison dans une nouvelle version,
   visiblement.*
4. **`YES` sans données.** *Recommandé : permis, avec un commentaire et une preuve, marqué « déclaré,
   non mesuré » à l'écran et dans le document.*
5. **Un lecteur qui voit une partie d'un projet.** *Recommandé : 404 sur les checklists du projet.
   L'alternative — les réponses sans les mesures — fuit par les réponses elles-mêmes (« non : le dépôt
   X a encore un critique »).*
6. **La fenêtre d'un taux de résolution.** *Recommandé : tout problème jamais enregistré dans ces
   portées sur le projet, le triage réglé hors des deux côtés, les comptes dans la preuve.
   Alternative : un paramètre de fenêtre sur la règle (problèmes vus pour la première fois dans les N
   derniers jours).*
7. **Où vivent les imports de couverture et de tests.** *Recommandé : `plugins`, à côté des sources
   déclarées dont ils dépendent. Alternative : un nouveau module `imports` qui emporterait les imports
   SARIF — plus propre, et une refonte de code livré à faire d'abord.*
8. **Une portée pour les deux nouveaux types.** *Recommandé : `report_import` pour la couverture et
   les rapports de tests, `sarif_import` inchangée. Alternative : une portée par type.*
9. **Les quatre yeux sur la publication d'une version de modèle.** *Recommandé : oui, quand le
   réglage est actif — publier change ce que chaque projet atteste.*
10. **Supprimer un projet.** *Recommandé : ses checklists, réponses, preuves et documents sont purgés
    dans la transaction de `ProjectDeleted`, sur le modèle que suit toute autre ligne rattachée à un
    projet ; les entrées d'audit restent, et les documents signés déjà remis aussi. Alternative :
    garder les révisions validées orphelines — une preuve que personne ne peut voir par aucun droit.*
11. **Les versions de composants.** *Recommandé : une liste explicite de versions autorisées par
    préfixe purl en v1. L'ordre des versions par écosystème (« au moins 3.2 ») est une étape
    ultérieure ; un ordre mal fait valide une ligne.*
12. **Où va la preuve dans le classeur.** *Recommandé : la feuille `Evidence` ajoutée, les feuilles du
    modèle ne portant que les colonnes de l'organisation. Alternative : ajoutée à la cellule de
    commentaire.*
13. **Les fichiers déposés en v1, ou les liens seulement.** *Recommandé : les deux, bornés, servis en
    téléchargement seulement.*
14. **Le mécanisme des plugins de rapport dans la première version.** *Recommandé : non — §10.*
15. **Les checklists signées dans le dossier de preuves.** *Recommandé : un lot ultérieur, une fois
    qu'une révision validée existe pour y figurer.*
16. **La colonne de contact.** *Recommandé : texte seul en v1 ; associer les rôles à des équipes pour
    l'affectation est une étape ultérieure.*

## Mise en œuvre

Découpée en lots livrables indépendamment dans
[le plan de mise en œuvre](../../../analysis/security-checklists-plan.md) (en anglais).

## Amendement (2026-09-29) — qui définit l'exigence de preuve d'un item

**Le manque.** Le §2 donne à chaque item une exigence de preuve — aucune, un lien ou un fichier, ou un
fichier, et une validité en mois — et le §5 refuse une soumission tant que chacune n'est pas satisfaite
et à jour ; aucun des deux ne dit qui la définit. Aucune colonne du classeur d'une organisation ne
l'énonce, si bien que l'import du §3 lisait chaque item comme `none`, et qu'aucune preuve n'était
jamais demandée à personne.

**La résolution.** L'exigence est définie par une personne sur une version **brouillon**, comme sa
disposition et ses appariements (§3, avant l'étape 6) :
`PUT /api/v1/checklist-templates/{slug}/versions/{ordinal}/evidence`, pour chaque item nommé par sa
clé, la sorte et la validité facultative (1 à 120 mois). Elle revient au responsable sécurité (§8),
nomme la `revision` que l'éditeur a lue (absente 400, périmée 409 `checklist-template-changed`), fait
de son éditeur l'un des auteurs du brouillon pour la double validation, et est consignée comme
`CHECKLIST_TEMPLATE_EVIDENCE_SET` — une opération à elle, puisque rien du classeur n'est relu. Les
exigences d'une version publiée ne changent jamais : on dérive une nouvelle version, qui les reporte.

L'exigence reste dans l'empreinte du contenu, comme le veut le §2 : une exigence qui bouge rend l'item
*modifié* (§4) et une réponse reportée attend confirmation. Deux conséquences en découlent, tranchées
de la même façon — une exigence suit la clé de son item : confirmer à nouveau la disposition d'un
brouillon garde l'exigence de chaque item, et l'item d'un nouveau classeur prend l'exigence de l'item
de même clé de la version précédente. Lues comme le dit le classeur, les deux perdraient chaque
exigence, et la seconde marquerait modifié chacun de ces items.

## Amendement (2026-09-29) — ce que le §10 laissait ouvert, tel que le rendu l'a tranché

La construction du lot L8 a rencontré quatre cas que le §10 ne tranche pas. Chacun est réglé dans le
code ; cet amendement les consigne pour que la décision et le module disent la même chose.

- **La date d'un rendu non signé est vide.** Le §2 et le §10 disent qu'un document est daté par
  l'instant de la signature, jamais par « maintenant ». Une révision en brouillon ou soumise n'a pas de
  signature, et garder la formule du modèle (`NOW()` dans le premier modèle réel) voudrait dire
  exactement « maintenant ». La cellule garde son style et ne contient rien ; `checklist.json` porte
  `header.date` à `null`.
- **Une révision signée avant l'existence des documents signés** n'a pas de paquet enregistré. Son
  téléchargement est un rendu non signé dont la feuille `Evidence` s'ouvre par *« Signed off by … at …
  — but no signed document was produced then: this rendering is not signed »*, et le zip ne contient
  aucun `.sig`. La signer maintenant attesterait, sous la clé et la lecture d'aujourd'hui, une signature
  donnée sans document.
- **La feuille `Evidence` est rédigée en anglais**, quelle que soit la langue du modèle, et ses instants
  en texte ISO-8601 UTC. Les feuilles de l'organisation gardent leurs mots ; la feuille ajoutée est la
  déclaration de Vectispire, lue par les auditeurs et par les plugins de rapport qui recevront
  `checklist.json`.
- **Une signature peut désormais échouer sur le rendu ou la signature, et s'annule en entier.** Une
  installation sans `ENCRYPTION_KEY` ni `vectispire.signing.key` répond 412 à la signature, comme tout
  autre export signé. Un modèle dont une cellule écrite est le maître d'une formule partagée ne peut pas
  être rendu, donc aucune de ses révisions ne peut être signée ; le vérifier par un rendu d'essai à la
  publication de la version est une étape ultérieure.

## Amendement (2026-09-29) — les scans répondent aux lignes qu'ils mesurent

**Ce qui change.** Le §6 disait *« Vectispire ne répond jamais »*. Le propriétaire du produit est revenu
sur ce choix le 2026-09-29 : une ligne liée à une règle reçoit de Vectispire la réponse que donne sa
mesure, pour que la checklist d'un projet arrive remplie de tout ce que les scans peuvent affirmer. Le
risque que nommait le §6 — un document signé portant une affirmation que son signataire n'a jamais faite
— est traité en nommant l'auteur, pas en interdisant la réponse.

- **Quand.** Quand un scan ou un import se termine sur un dépôt d'un projet dont la checklist est en
  brouillon, et quand une checklist est ouverte ou passe à une autre version. Jamais sur une révision
  soumise ou signée, jamais à la lecture.
- **Quoi.** `PASS` répond *oui* ; `FAIL` répond *non*, avec un commentaire généré à partir de la mesure
  (la règle et les chiffres qui l'ont fait échouer) — le commentaire qu'exige un *non* (§5) dit ce qui a
  été mesuré, il ne prétend pas qu'une personne l'a écrit. `NO_DATA` ne répond rien.
- **Qui.** L'auteur est **Vectispire**, un acteur système qui n'est pas un compte et ne peut porter aucun
  rôle. Chaque réponse de ce type repose sur la mesure qui l'a produite (la même référence que garde la
  réponse en un clic), entre dans l'historique de la ligne, est auditée `CHECKLIST_ANSWERED` avec le
  système pour acteur, et est affichée *automatique* à l'écran, dans la feuille `Evidence` et dans
  `checklist.json`.
- **Les personnes d'abord.** Une réponse donnée par une personne n'est jamais remplacée par le système.
  Une réponse automatique est remplacée par le système quand ce qu'elle affirme change — sa valeur ou
  son commentaire généré, qui porte les chiffres ; un nouveau scan qui mesure la même chose la laisse
  (l'historique garde les deux) —, et par une personne qui répond à la ligne — la réponse est dès lors la sienne et les scans n'y
  touchent plus.
- **Ce qui reste à une personne.** Soumettre et signer restent des actes de personnes, sous double
  validation ; celui qui soumet atteste la révision entière, réponses automatiques comprises, et le
  document dit quelles réponses étaient automatiques.
- **Qui décide.** Un réglage de plateforme, actif par défaut, permet à une organisation de revenir à des
  réponses données par des personnes seulement ; la réponse en un clic et l'acte « comme mesuré »
  restent dans les deux cas.

**Tel que construit (2026-09-29).** Six points que l'amendement laissait à l'implémentation, tranchés
dans le code :

- **L'auteur est une nature, pas un nom.** `t_checklist_answer.answered_by_kind` (`person`, `system`,
  V56), et `answered_by_id` nul pour le système et pour lui seul — une contrainte de vérification tient
  les deux ensemble sur chaque moteur. `answered_by` vaut *Vectispire*, nom qu'un compte peut aussi
  porter : chaque lecteur (les scans, la double validation, le document) décide par la nature. Le
  système n'est aucun des auteurs d'une révision.
- **L'absence de données retire la réponse de Vectispire.** La table reste en ajout seul : une ligne
  système marquée `withdrawn` rend la ligne sans réponse et garde dans l'historique ce qui a été retiré.
  Laissé debout, un *oui* sur des données qui ont cessé d'exister serait une affirmation que personne ne
  fait ; la soumission ne l'attraperait que comme un *oui* sans données.
- **Remplacée quand ce qu'elle affirme change**, pas quand l'empreinte des preuves change : l'empreinte
  nomme le scan et sa date, si bien que chaque scan mesurant la même chose écrivait une nouvelle ligne et
  faisait bouger l'édition sous les personnes qui remplissent la checklist — refusant leur soumission
  suivante comme modifiée. La valeur ou le commentaire généré, qui porte les chiffres (« 5 ouverts »
  devenant « 3 ouverts » est une nouvelle réponse), ou une réponse reportée d'une autre révision, est
  réécrit ; la réponse continue de reposer sur la mesure à partir de laquelle elle a été écrite, et
  l'approbation mesure de toute façon à nouveau (décidé le 2026-09-29).
- **L'entrée d'audit n'a pas d'acteur**, comme toute entrée que personne n'a demandée (le rapport de
  posture, une acceptation échue) : une description qui nomme Vectispire, jamais un utilisateur inventé.
- **Le commentaire généré est en anglais**, comme la feuille `Evidence` — la plateforme ne déclare pas de
  langue de document — et dit *Measured by Vectispire*.
- **Les déclencheurs sont des ports** que déclarent `scanning` et `plugins` (`RepositoryScanned`,
  `RepositoryReported`), appelés après leur propre commit et incapables de faire échouer le scan ou
  l'import ; une ouverture répond juste après son propre commit, pour que la réponse montre les réponses.
  Le réglage `checklist_auto_answer` appartient au gouverneur de plateforme, comme les autres règles, et
  est audité comme réglage de sécurité.

## Amendement (2026-09-29) — l'analyse statique ne compte que ce qu'elle a lu

**Le trou.** Le §6 lit un périmètre de constats comme examiné quand son étape a *produit*. L'étape SAST
intégrée produit dès que Semgrep tourne — avec les seules règles embarquées, un motif Python — si bien
qu'un dépôt Java mesurait `builtin:sast` à zéro constat et passait : rien trouvé, parce que rien lu.
Depuis l'amendement précédent, ce succès est un *oui* automatique dans un document signé. La décision
[0007](0007-none-is-not-an-empty-list.md) une fois de plus : une étape qui ne savait pas lire l'arbre
n'a pas regardé.

**La résolution.** `builtin:sast`, `builtin:quality` (Semgrep tous deux) et chaque `plugin:<id>` sont
jugés sur les langages qu'a enregistrés l'analyse examinée — jamais sur les règles ou le manifeste
d'aujourd'hui, qui laisseraient un jeu activé après l'analyse revendiquer une couverture qu'elle n'a
jamais eue :

- les langages de l'arbre : le recensement de l'analyse (`detected_languages`, V57) ;
- la portée de Semgrep : les langages des règles que portait sa tâche (`sast_languages`, V58), écrits
  par le plan de contrôle quand il construit la tâche, depuis l'empreinte même que la tâche nomme — les
  règles embarquées plus le jeu actif, chaque fichier compté pour son répertoire du catalogue, jamais en
  analysant son YAML (`RuleSet`) ;
- la portée d'un plugin : les langages du manifeste que l'analyse a nommé par son empreinte (les
  manifestes sont gardés pour toujours).

**Deux raisons rejoignent l'ensemble fermé.** `LANGUAGE_NOT_ANALYSED` : un langage source de l'arbre
qu'aucune règle ne lit — pour les étapes intégrées, *chaque* langage source doit être lu, donc Java lu
et TypeScript non, c'est pas de données ; un plugin, choisi pour ce qu'il déclare, doit avoir lu un des
langages de l'arbre, et les preuves nomment les langages source qu'il ne lit pas sans refuser la ligne
pour eux. `LANGUAGES_UNRECORDED` : un des deux côtés inconnu — une analyse d'avant V57 ou V58, un
recensement arrêté à sa borne, un manifeste qui n'est plus connu.

**Les langages source** sont le vocabulaire moins `json`, `yaml`, `html`, `dockerfile` et `terraform`
(`SourceLanguages`, un `switch` exhaustif). `bash` compte. Un arbre sans aucun langage source que le
recensement connaît est `LANGUAGE_NOT_ANALYSED` : du code dans un langage hors du vocabulaire n'est pas
du code que personne n'a écrit.

**Coûts acceptés.** Chaque ligne sur ces périmètres mesure `LANGUAGES_UNRECORDED` après la mise à jour
jusqu'à la prochaine analyse de chaque dépôt, et le *oui* automatique de Vectispire est retiré par le
chemin existant ; le précédent est `EXAMINATION_UNRECORDED`. Les règles qu'un exécuteur lit dans son
propre `VECTISPIRE_SEMGREP_RULES_DIR` ne sont pas comptées, et une règle `javascript/` qui lit aussi
TypeScript compte pour JavaScript seul : les deux erreurs empêchent une ligne de passer et n'en font
jamais passer une. Les outils importés n'enregistrent aucun langage et n'en sont pas jugés.
