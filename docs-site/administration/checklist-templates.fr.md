# Modèles de checklists

Un modèle de checklist est **la checklist de sécurité de votre organisation**, importée depuis le
classeur que vous utilisez déjà : ses domaines, objectifs, contrôles, contacts et KPI, dans ses
propres mots et sa propre langue. Les projets y répondent ligne par ligne — voir
[checklists de sécurité](../guide/security-checklists.fr.md) ; cette page est celle où le modèle
lui-même est importé, vérifié et publié.

Ouvrez-la depuis **Administration → Modèles de checklists**. La décision
[0032](https://github.com/asmolabs/vectispire/blob/main/docs/architecture/fr/decisions/0032-security-checklists.md)
consigne pourquoi il fonctionne ainsi.

!!! info "Jamais publié en une étape"
    Un classeur devient un **brouillon**. Quelqu'un confirme où se trouve la checklist dans le
    classeur et ce que veulent dire ses mots de réponse, ses lignes sont appariées avec la version
    précédente, et c'est seulement ensuite qu'il est publié. Une version publiée ne change jamais :
    un nouveau mot, une nouvelle disposition ou une nouvelle liaison fait une nouvelle version.

## Qui peut faire quoi

| | Gouverneur de la plateforme, administrateur, CISO | Auditeur | Tous les autres |
|---|---|---|---|
| Voir les modèles, leurs versions, la feuille, la disposition, les items et l'appariement | oui | oui | non — l'entrée n'est pas dans leur menu |
| Importer un classeur, confirmer une disposition, apparier des items, dire quelle preuve chaque ligne demande, dériver une version | oui | non | non |
| Publier un brouillon, retirer une version publiée | oui et, [double validation](four-eyes.fr.md) active, **pas la personne qui l'a écrit** | non | non |
| Écarter un brouillon | oui, son auteur compris | non | non |

L'auditeur voit chaque écran décrit ci-dessous sans une seule commande qui modifie quoi que ce soit.

## 1. Importer un classeur

Donnez au modèle un **identifiant** — de 1 à 64 minuscules, chiffres et tirets intérieurs, comme
`checklist-livraison`. Un nouvel identifiant crée le modèle, nommé par **Nom du modèle** ; un
identifiant existant reçoit sa version suivante et le nom n'est pas demandé. Le **libellé de la
version** est facultatif (`Édition 2026`).

Le `.xlsx` est envoyé tel quel. L'écran refuse un fichier de plus de **10 Mo** avant d'envoyer quoi
que ce soit, avec la phrase que le serveur répondrait. Le serveur refuse un classeur à macros
(`.xlsm`), le format binaire, et un fichier qui échoue à l'un de ses gardes — plus de 200 entrées zip,
plus de 50 Mo décompressés, une entrée compressée plus de 100 pour un, une DTD dans une partie
quelconque, une cible de relation externe. Un modèle a **au plus un brouillon à la fois** : tant qu'il
en existe un, l'import est refusé jusqu'à ce qu'il soit publié ou écarté.

Le fichier source est conservé avec son SHA-256, affiché sur la version : les documents signés d'un
lot ultérieur s'écrivent dedans, et un auditeur peut comparer un document livré avec le modèle qu'il
dit suivre.

## 2. Confirmer la disposition, sur la feuille elle-même

Ouvrir une version montre sa feuille sous forme de grille — numéros de ligne sur le côté, lettres de
colonne en haut — avec un sélecteur pour les autres feuilles du classeur. Le lecteur a **proposé** une
disposition à partir de la structure du classeur : ses plages de validation, ses cellules fusionnées,
et la ligne suivie d'une suite de lignes remplies. Il ne cherche jamais de mots attendus, qui seraient
le vocabulaire d'une seule organisation inscrit dans le produit. La grille dessine la disposition à
l'écran par-dessus les cellules :

- l'en-tête d'une colonne nomme le champ qu'elle porte — `C · Contrôle` ;
- les lignes d'items des colonnes nommées sont surlignées en bleu ;
- les cellules d'en-tête sont surlignées en ambre ;
- la ligne d'en-têtes de colonnes trouvée par le lecteur est en gras ; `ƒ` signale une formule.

Corrigez ce qui est faux ; la grille suit la saisie.

| Partie | Ce qu'il faut donner |
|---|---|
| Colonnes | Les lettres de chaque champ. **Contrôle, réponse et commentaire sont obligatoires** ; identifiant, domaine, objectif, contact et KPI quand le modèle les a. Une colonne identifiant fait de ses valeurs les clés des items ; sans elle, une clé est tirée du texte du contrôle. |
| Lignes d'items | La première et la dernière ligne qui portent des items, 5 000 lignes au plus. |
| Cellules d'en-tête | Pour la date, le produit et l'auteur, chacun seulement si le modèle l'a : la cellule du libellé, laissée telle quelle, et la cellule de la valeur, où l'on écrit. Les deux ou aucune ; jamais parmi les lignes d'items, et deux entrées ne partagent jamais une cellule de valeur. |
| Mots de réponse | Les mots du modèle lui-même pour **oui** et **non**, quelle que soit sa langue. La liste de réponses trouvée par le lecteur dans la validation de la colonne réponse est affichée à côté ; l'écran ne l'associe jamais à votre place — quel mot veut dire oui, c'est à vous de le dire. |
| Non applicable | Proposé seulement si vous le cochez et nommez son mot. Quand la liste du modèle n'a pas ce mot, saisissez-en un : le document le porte, et la liste du modèle reste telle quelle. Une réponse « non applicable » exige toujours sa justification. |

**Confirmer la disposition** lit les items : les cellules de domaine et d'objectif vides sont remplies
vers le bas, comme la feuille les entend, et une ligne dont la cellule contrôle est vide n'est pas un
item. Les items lus apparaissent sous la grille. Confirmer à nouveau plus tard les relit et **efface
les appariements faits à la main**, puisqu'ils nommaient les items tels que la disposition précédente
les lisait.

## 3. Apparier les items avec la version précédente

Une fois la disposition confirmée, chaque item est comparé avec la version publiée précédente :

| Changement | Ce qu'il signifie pour la réponse d'un projet, quand le projet passe à la nouvelle version |
|---|---|
| Inchangé | Même clé, même contenu : reportée telle quelle. |
| Modifié | Même clé, contenu différent — la formulation, le KPI, l'exigence de preuve ou la liaison ont bougé : reportée, à confirmer. |
| Ajouté | Aucune clé dans la version précédente : commence sans réponse. |
| Supprimé | Absent de cette version : sa réponse reste là où elle a été donnée. |

Un contrôle seulement reformulé apparaît comme un item supprimé et un item ajouté. **Appariez-les à
la main** : choisissez l'item ajouté et l'item supprimé qu'il est, puis **Les apparier**. Le nouvel
item prend l'ancienne clé et devient *modifié*, *apparié à la main*, afin que la réponse d'un projet
le suive, à confirmer. **Désapparier** défait un appariement. Une première version n'a rien avec quoi
s'apparier : chaque item est nouveau.

Confirmer une disposition et apparier des items sont envoyés sur la **révision affichée**, comme la
publication : quand un autre responsable a modifié le brouillon après que vous l'avez ouvert, votre
modification est refusée, la révision que vous aviez à l'écran nommée, plutôt que de remplacer la
sienne sans qu'il le voie. Rechargez le brouillon et refaites-la.

## 4. Dire quelle preuve chaque ligne demande

Un classeur dit ce que chaque ligne demande, jamais la preuve qu'il lui faut : chaque ligne d'un
nouveau brouillon ne demande donc **aucune** preuve — sauf si la ligne existait déjà : confirmer à
nouveau une disposition garde ce que chaque ligne demandait, et la ligne d'un nouveau classeur prend
l'exigence de la ligne de même clé de la version précédente. Sur un brouillon dont la disposition est
confirmée, la colonne **Preuve demandée** des items lus propose, pour chaque ligne, l'exigence :

| Exigence | Ce qu'un *oui* demande avant que la checklist puisse être soumise |
|---|---|
| **Aucune** (`none`) | Rien. |
| **Lien ou fichier** (`link_or_file`) | Un lien ou un fichier, à jour. |
| **Fichier** (`file`) | Un fichier, à jour — un lien ne suffit pas. |

et, à côté, pour une preuve qui expire, **combien de mois elle vaut**, de 1 à 120 — chaque preuve vaut
alors jusqu'au jour où le travail a été fait plus ce nombre de mois. Laissez les mois vides pour une
preuve qui n'expire pas ; une ligne qui ne demande aucune preuve n'a pas de mois à donner, et le champ
est grisé. L'écran refuse une validité hors de 1 à 120, ou qui n'est pas un nombre entier de mois,
avant de rien envoyer.

**Enregistrer la preuve demandée** envoie les lignes que vous avez modifiées, et seulement elles — une
ligne ramenée à ce qu'elle demandait n'est pas envoyée, et le bouton compte les lignes qu'il enverra.
Elles sont envoyées sur la **révision affichée**, comme une disposition, et qui les définit devient
l'un des auteurs du brouillon. Sur une version publiée ou retirée, et pour l'auditeur, la colonne dit
seulement ce que chaque ligne demande — *Lien ou fichier · valable 12 mois*.

L'exigence **fait partie de ce que la ligne demande** : une ligne dont l'exigence a bougé est
*modifiée* par rapport à la version précédente, et la réponse d'un projet reportée sur elle attend que
quelqu'un la confirme — elle a été donnée quand aucune preuve, ou une autre, n'était demandée. Les
exigences d'une version publiée ne changent jamais ; dérivez un nouveau brouillon pour en changer une.

## Lignes mesurées : la règle liée à une ligne

Une ligne que Vectispire sait mesurer — dépendances analysées, aucun secret dans l'arbre, analyse
statique assez propre, couverture, une suite d'architecture passée, bibliothèques internes à des
versions maintenues — est **liée à une règle** sur le brouillon, et la checklist de chaque projet
montre alors la mesure de la règle à côté de la réponse. Vectispire ne répond jamais : il mesure, et
des personnes répondent.

Sur un brouillon dont la disposition est confirmée, le tableau des éléments a une colonne **Mesurée
par**. Choisissez **Lier une règle** (ou **Changer la règle**) sur une ligne : le formulaire s'ouvre
avec le contrôle de la ligne et **son indicateur, tel que le modèle l'écrit, à côté des paramètres**,
et en dessous *ce que la règle mesure* en mots. L'indicateur n'est jamais lu comme un seuil ; comparez
les deux avant de garder la règle — « aucun critique, au plus deux élevés » face à une règle qui en
permet cinq est le désaccord que cette disposition doit montrer. Choisissez le type, indiquez ses
paramètres, puis **Garder cette règle** ; **Préréglage : secrets à zéro** remplit la règle que nomme la
décision 0032 (l'étape secrets, critique et élevée à zéro ouvert, preuves d'au plus sept jours). Les
étapes intégrées d'une règle de constats se cochent ; un plugin (`plugin:<id>`) ou un outil que
déclare une source SARIF (`import:<source>/<outil>`) se saisit, et le champ suggère les plugins
enregistrés et les outils des sources SARIF déclarées. Le formulaire refuse, en mots et avant l'envoi,
ce que le serveur refuserait. Choisir **Aucune règle** puis **Mesurer sans règle** délie la ligne.

Les règles gardées restent à l'écran, marquées *Non enregistrée*, jusqu'à **Enregistrer les règles** :
seules les lignes dont la règle a changé sont envoyées, sur la **révision** du brouillon affichée — un
brouillon modifié entre-temps est refusé et la page propose de le relire. Seuls un gouverneur de la
plateforme, un administrateur ou un CISO lient des règles, et qui le fait devient l'un des auteurs du
brouillon ; tous les autres, l'auditeur compris, et toute version publiée, montrent la règle de chaque
ligne en mots et rien à changer. Un script fait de même avec
`PUT /api/v1/checklist-templates/{slug}/versions/{ordinal}/rules?revision=…`, chaque ligne nommée par
son `itemKey` avec sa `rule`, ou `null` pour la délier.

| Type | Ce qu'il lit | Une ligne est satisfaite quand, sur chaque dépôt du projet |
|---|---|---|
| `dependency_analysis` | l'analyse la plus récente dont l'étape des dépendances a produit | elle date de moins que l'âge maximal et a conservé son SBOM ; si `requireSchedule`, le dépôt est planifié au moins aussi souvent que l'âge maximal ; des `thresholds` facultatifs sur les vulnérabilités ouvertes |
| `findings_threshold` | pour chacun de ses `scopes` — `builtin:secret`, `builtin:sast`, `builtin:iac`, `builtin:vulnerability`, `builtin:quality`, `builtin:eol`, `builtin:license`, `plugin:<id>`, `import:<source>/<outil>` — l'analyse ou l'import le plus récent où ce périmètre a produit | chaque périmètre a produit dans l'âge maximal — pour `builtin:sast`, `builtin:quality` et un plugin, sur un arbre dont il a lu les langages ([ce que l'analyse a lu](../guide/security-checklists.md#lignes-mesurees)) — et le passif respecte les `thresholds` par sévérité : `maxOpen`, `minResolvedRatio` (résolus ÷ résolus et ouverts), le triage réglé exclu des deux côtés |
| `coverage_threshold` | l'import de couverture le plus récent | il date de moins que l'âge maximal et son taux de `line` ou de `branch` (`metric`) atteint `minimumRatio` — `per_repository`, ou `project_weighted` (`aggregation`) — sur tout le rapport, ou sur les paquets que nomme son `scope` facultatif ([ci-dessous](#couverture-sur-un-perimetre-de-paquets)) |
| `test_suite_passed` | l'import de rapport de tests le plus récent | une suite correspond à `suitePattern` (`*` et `?`), celles qui correspondent ont exécuté au moins `minimumTests` tests (les ignorés non comptés), aucun en échec ni en erreur — ou, pour des tests unitaires **et** fonctionnels sur une même ligne, `suitePatterns` (2 à 10, `["*Test", "*IT"]`), **chacun** satisfait par ses propres suites : une grande suite unitaire ne remplace pas une suite fonctionnelle absente |
| `component_versions` | les composants du SBOM analysé le plus récent, complétés par le [SBOM de build](plugins.md#importer-le-sbom-dun-build) le plus récent de sa branche quand le pipeline en envoie un | chaque paquet déclaré (`purlPrefix`) est présent à l'une de ses `versions` listées — des versions exactes, et des plages Maven pour un paquet `pkg:maven/` ([ci-dessous](#composants-presence-versions-et-plages)) |
| `component_present` | les mêmes composants, complétés de même | chaque paquet déclaré (`purlPrefix`) est présent, quelle que soit sa version — y compris une version que le SBOM n'indique pas |
| `change_review` | la lecture la plus récente de la forge du dépôt, par la connexion qui l'a importé ou découvert ([ci-dessous](#revue-des-changements-comment-ils-arrivent-sur-une-branche)) | les réglages de la forge exigent `minimumApprovals` approbations avant une fusion, celle de l'auteur refusée et un push direct refusé — ou, parmi les merge requests ou pull requests fusionnées dans la `branch` (par défaut : la branche par défaut de la forge) ces `windowDays` derniers jours, au moins `minimumRatio` avaient `minimumApprovals` approbations par d'autres personnes que leur auteur |

**Rien n'est supposé.** Chaque type exige `maxAgeDays` (1 à 366 — sept est un bon début), une règle
de dépendances indique `requireSchedule`, une règle de constats indique au moins un seuil — *aucun
secret en clair* est `builtin:secret` avec chaque compte à zéro — et un paramètre d'un autre type est
refusé plutôt qu'ignoré. La colonne KPI reste les mots du modèle : un seuil est un paramètre écrit
par quelqu'un, jamais un nombre lu dans une phrase. Aucune liste de paquets n'est livrée avec le
produit ; `component_versions` et `component_present` existent pour l'organisation qui les lie avec les
siens.

Un `purlPrefix` est une URL de paquet sans sa version ; il désigne un composant dont l'URL de paquet
est exactement lui, ou le prolonge par `/`, `@`, `?` ou `#` — `pkg:npm/left` ne désigne pas
`pkg:npm/left-pad`. Pour exiger chaque paquet d'un espace de noms, arrêtez-vous avant le séparateur :
`pkg:maven/com.example.tools`, et non `pkg:maven/com.example.tools/`, qui ne désignait aucun paquet
et est refusé à la liaison. Une ligne liée avec le `/` final avant ce refus garde son texte — son
empreinte le lit — et sa mesure indique qu'il ne désigne aucun paquet ; dérivez un brouillon pour la
lier à nouveau.

### Composants : présence, versions et plages

Les deux types de composants lisent le même inventaire : les composants de l'analyse la plus récente de
chaque dépôt dont l'étape des dépendances a produit dans `maxAgeDays`. Une ligne qui demande si une
bibliothèque **est utilisée** et une ligne qui demande **quelles versions** sont autorisées répondent
depuis le même SBOM, et de la même manière quand la rétention des charges l'a purgé : l'inventaire qu'il a
laissé est lu, et un inventaire vide est `inventory_absent`, sans données — jamais un échec.

**« La bibliothèque X est utilisée »**, c'est `component_present`. La ligne est satisfaite quand un
composant correspond au préfixe, quelle que soit sa version — y compris une version que le SBOM
n'indique pas, ce que Syft écrit (`UNKNOWN`) pour une dépendance Maven dont un POM parent ou un BOM gère
la version. Elle échoue quand l'inventaire ne liste aucun tel composant, et n'a pas de données quand le
dépôt n'a aucune analyse dans l'âge, ou quand sa dernière analyse ne conserve plus son SBOM et que son
inventaire ne liste rien (`inventory_absent`) : une absence que personne n'aurait pu voir n'est pas
« non utilisée ».

```json
{ "kind": "component_present", "maxAgeDays": 7,
  "components": [{ "purlPrefix": "pkg:maven/org.example.platform/platform-application" }] }
```

**« Les versions de la famille Y utilisées »**, c'est un préfixe d'espace de noms —
`pkg:maven/org.example.platform` — sur l'un ou l'autre type. La preuve liste, par dépôt, chaque paquet
sous le préfixe avec les versions qu'indiquent ses occurrences (vingt paquets au plus, les autres
comptés) : le relecteur lit ce qui est déployé et planifie les mises à jour à côté de la ligne.

**Les versions autorisées**, c'est `component_versions`, ses `versions` exactes ou, pour un paquet
`pkg:maven/`, des plages Maven — écrites comme Maven les écrit et lues dans l'ordre de Maven :

| Entrée | Autorise |
|---|---|
| `1.17.7` | exactement `1.17.7`, tel que le SBOM l'écrit |
| `[1.17.7]` | `1.17.7` dans l'ordre de Maven — `1.17.7.0` aussi |
| `[1.17,2.0)` | de `1.17` inclus à `2.0` exclu |
| `(,2.0)` | tout ce qui est sous `2.0` |
| `[1.0,1.2],[1.5,)` | une union : de `1.0` à `1.2`, ou `1.5` et au-delà |

```json
{ "kind": "component_versions", "maxAgeDays": 7,
  "components": [{ "purlPrefix": "pkg:maven/org.example.platform", "versions": ["[1.17,2.0)", "1.16.4"] }] }
```

L'ordre de Maven n'est pas celui d'une chaîne : `1.9` est sous `1.17` ; `1.17-SNAPSHOT`, `1.17-RC1` et
`1.17-alpha` sont sous `1.17`, si bien que `[1.17,2.0)` les refuse et admet `2.0-SNAPSHOT` ;
`5.3.0.RELEASE`, `5.3.0.Final` et `5.3.0` sont une même version ; un service pack, `1.17-sp1`, suit sa
version. Une plage illisible est refusée à la liaison, en mots — une borne basse au-dessus de la borne
haute, une version seule entre parenthèses, des plages qui se chevauchent, une plage qui n'admet aucune
version ou les admet toutes (liez `component_present` pour cela). Une plage sur un autre type
(`pkg:npm/…`) est refusée : chaque écosystème ordonne ses versions à sa manière, et seul l'ordre de
Maven est implémenté. Une règle liée avant l'existence des plages garde son texte et son empreinte, et
ses versions exactes leur sens.

**Une version que le SBOM n'indique pas** n'est pas jugée par `component_versions` : un paquet dont
aucune occurrence n'en indique est `version_unrecorded`, et sa preuve dit que la version est gérée hors
du SBOM — un POM parent ou un BOM — et qu'un SBOM produit par le build, qui l'indique, résout la ligne.
Quand la ligne demande seulement si la bibliothèque est utilisée, liez `component_present`.

### Revue des changements : comment ils arrivent sur une branche

Une ligne comme *toute merge request est approuvée par au moins un pair avant la fusion* est liée à une
règle `change_review`. Vectispire ne la lit pas dans une analyse : la forge y répond, par la
[connexion de forge](forge-connections.fr.md#revues-des-changements-ce-que-les-checklists-demandent-a-la-forge)
qui a importé le dépôt — ou, pour un dépôt saisi à la main, une connexion dont la découverte a listé un
dépôt à la même URL (l'identité que compare le formulaire de dépôt). Un dépôt que rien ne lie est
`forge_unlinked`, jamais une réussite.

```json
{ "kind": "change_review", "maxAgeDays": 1, "minimumApprovals": 1, "windowDays": 30, "minimumRatio": 1 }
```

`minimumApprovals` (1 à 10) compte des **personnes distinctes autres que l'auteur du changement** ;
`windowDays` (1 à 366) dit sur combien de jours les changements fusionnés sont comptés ; `minimumRatio`
(supérieur à 0, jusqu'à 1) est la part d'entre eux qui doit avoir les approbations — `1` pour tous ;
`branch`, facultatif, nomme la branche cible, et sans lui la branche par défaut de la forge est lue.
`maxAgeDays` est l'âge que peut avoir la lecture de la forge : elle est faite chaque heure, et chaque
dépôt relu toutes les six heures, si bien que `1` est une valeur raisonnable. Le serveur exige les quatre
paramètres sauf la branche ; le formulaire propose un pair, tous les changements et trente jours — les
mots de la ligne pour laquelle la règle est écrite — dans des champs que la personne lit et modifie.

**Deux sources, selon ce que la forge expose**, toutes deux lues à chaque lecture :

| Source | GitLab | GitHub | Prouve |
|---|---|---|---|
| **Réglages** — une preuve de configuration | Premium et Ultimate seulement : les règles d'approbation qui s'appliquent à la branche (`approvals_required`, la plus grande), *Empêcher l'approbation par l'auteur* (`merge_requests_author_approval`), et les niveaux de push de la branche protégée (*Personne*) | les règles qui s'appliquent à la branche (la règle `pull_request` des rulesets), et les revues exigées par la protection de branche classique quand elle s'impose aux administrateurs | tous les changements, le prochain compris : une réussite sur les seuls réglages quand ils exigent les approbations, refusent celle de l'auteur et refusent un push direct |
| **Historique** — ce qui s'est passé | toutes les éditions, **Community Edition comprise** : les merge requests fusionnées dans la branche pendant la fenêtre, et le `approved_by` de chacune | les pull requests fusionnées dans la branche pendant la fenêtre, et les revues de chacune — la dernière décision d'un relecteur fait foi | les changements de la fenêtre : une réussite quand la part est atteinte |

**GitLab Community Edition (et l'offre Free) n'a pas de règle d'approbation** : elle répond 404 pour les
réglages, et la ligne est jugée sur l'historique — la lecture le dit dans ses preuves. Deux conséquences,
écrites plutôt que cachées :

- **Rien sur la forge n'empêche un auteur d'approuver sa propre merge request** ; Vectispire l'exclut
  donc : une approbation par l'auteur n'est comptée nulle part, et les preuves disent combien de
  changements en avaient une (*1 approved by their author too, not counted*).
- **Un push direct sur la branche n'est pas une merge request**, et l'historique ne le voit pas. Protégez
  la branche (*Autorisé à pousser et fusionner : Personne*, *Autorisé à fusionner : Mainteneurs*) pour que
  tout changement passe par une merge request ; la lecture ne lit pas ce réglage sur la Community Edition.

Un approbateur qui a aussi poussé des commits sur le changement compte comme un pair : le réglage
*Empêcher les approbations par les utilisateurs qui ajoutent des commits* de GitLab Premium n'est pas lu,
et la Community Edition n'en a pas.

**Ce que la ligne montre.** Par dépôt, la source et ses chiffres — *47 of 47 merged merge requests
approved by a peer in 30 days*, ou *settings: GitLab approval rules require 2 approvals on main, author
approval prevented, direct push refused* — et, en cas d'échec, les changements sans les approbations
(*without: !12, !15*). Le résumé est ce qu'imprime la feuille `Evidence` du document signé ; la lecture y
est nommée par son identifiant et son SHA-256, que portent les preuves de la mesure. Ces phrases sont
celles du serveur, en anglais, comme tous les résumés de mesure.

**Pas de données, jamais une réussite :** `never_examined` (pas encore lu — la première lecture vient dans
l'heure), `forge_unlinked`, `forge_unreadable` (le jeton s'est vu refuser le projet, ses merge requests ou
ses pull requests — les preuves donnent la réponse de la forge, `HTTP 403` et la permission à accorder),
`review_incomplete` (plus de 500 changements fusionnés dans la fenêtre, ou une lecture plus étroite que la
fenêtre de la règle juste après qu'elle a été élargie), `no_change_merged` (rien de fusionné dans la
fenêtre : chacun de zéro n'est pas tous), et `stale`.

### Couverture sur un périmètre de paquets

Une règle `coverage_threshold` mesure tout le rapport, sauf si elle nomme un **périmètre** (`scope`) :
les paquets qu'elle mesure, décidés par l'organisation dans le modèle. Filtrer plutôt dans chaque build
— les `<includes>` de JaCoCo dans un `pom.xml`, un `--include` de l'outil de couverture — change le
chiffre là où personne qui relit la checklist ne le voit ; un périmètre est lié avec la règle, affiché à
côté de sa mesure et imprimé dans le document signé.

```json
{
  "kind": "coverage_threshold", "maxAgeDays": 7, "metric": "line", "minimumRatio": 0.8,
  "aggregation": "per_repository",
  "scope": { "include": ["**/service/**", "org/example/billing/**"], "exclude": ["**/generated/**"] }
}
```

Dans le formulaire, **Paquets mesurés** porte les deux listes, motifs séparés par des virgules ; les
deux vides valent tout le rapport.

**Les motifs portent sur les chemins des paquets**, tels qu'un import de couverture les conserve : un
paquet JaCoCo tel que JaCoCo l'écrit (`org/example/service`), un paquet Cobertura avec ses points lus
comme des barres obliques (`org.example.service` devient `org/example/service` ; le `.` de premier
niveau de coverage.py est le chemin vide), et pour lcov le répertoire qui contient chaque fichier `SF:`,
tel que le fichier de trace l'écrit — chemin absolu compris, d'où l'intérêt de commencer un motif pour
lcov par `**/`.

| Motif | Correspond à | Ne correspond pas à |
|---|---|---|
| `**/service/**` | `service`, `org/example/service`, `org/example/service/impl` | `org/example/services` |
| `org/example/**` | `org/example` et tout ce qu'il contient | `org/examples` |
| `org/example` | ce seul paquet | `org/example/service` |
| `org/example/*-api` | `org/example/billing-api` | `org/example/billing/api` |
| `src/app/**` | `src/app`, `src/app/orders/web` (lcov) | `/builds/shop/src/app` — écrire `**/src/app/**` |

`**` vaut un nombre quelconque de segments entiers, aucun compris ; `*` vaut des caractères au sein
d'un segment ; rien d'autre n'est un joker, et la comparaison respecte la casse. Un paquet est **dans le
périmètre** quand un motif d'`include` lui correspond — tout paquet quand `include` est vide — et
qu'aucun motif d'`exclude` ne lui correspond. Vingt motifs au plus dans chaque liste.

**Refusé à la liaison de la règle**, en mots, plutôt que laissé ne rien désigner : un nom de paquet à
points (`org.example.service` — écrire `org/example/service`), `**` au sein d'un segment (`**/serv**`),
`?`, crochets, accolades ou `!` (qu'un lecteur prendrait pour des jokers), une barre oblique inverse,
une barre oblique au début, à la fin ou doublée, un segment `.` ou `..`, un motif vide, un motif de plus
de 500 caractères, un motif listé deux fois, et un périmètre sans aucun motif — omettre `scope` pour
mesurer tout le rapport.

**Ce qu'il mesure.** Les lignes (ou branches) couvertes sur celles comptées, additionnées sur les
paquets du périmètre dans l'import de couverture le plus récent de chaque dépôt — par dépôt, ou sur le
projet pondéré par la taille, selon `aggregation`. La preuve de chaque dépôt dit combien de paquets
correspondent — *2 of 14 packages in the scope; 412 of 480 lines covered* — et le résumé de la mesure,
que la feuille `Evidence` du document signé imprime, énonce le périmètre à côté du chiffre, réussite
comprise.

**Pas de données, jamais un chiffre qui ne serait pas celui du périmètre :**

- `scope_matches_nothing` — aucun paquet du rapport n'entre dans le périmètre : ni 0 %, ni 100 %.
  Comparer les motifs aux chemins du rapport (ceux de lcov sont souvent absolus).
- `packages_unrecorded` — l'import le plus récent a été accepté avant que les imports ne conservent
  leurs paquets ; seuls ses totaux sont connus. Le prochain envoi du pipeline mesure le périmètre.
- `packages_not_kept` — l'import a conservé ses totaux et pas ses paquets : plus de 10 000, un chemin de
  plus de 1 000 caractères ou portant un caractère de contrôle, ou des comptes par paquet qui ne
  s'additionnent pas aux totaux du rapport ([ce qu'un import conserve](plugins.fr.md#importer-des-rapports-de-couverture-et-de-tests)).

Une règle sans périmètre est mesurée exactement comme avant, et garde la forme canonique — donc
l'empreinte de contenu — qu'elle avait.

Une liaison **fait partie de ce que la ligne demande**, comme son exigence de preuve : une ligne dont
la liaison a changé est *modifiée* par rapport à la version précédente, et la réponse d'un projet
reportée sur elle attend une confirmation. Elle suit la clé de sa ligne — une disposition confirmée
à nouveau la garde, un brouillon dérivé la copie, la ligne d'un nouveau classeur reprend la liaison
de la version précédente sous la même clé. Les liaisons d'une version publiée ne changent jamais ;
dérivez un nouveau brouillon pour en changer une. Les lignes de la version portent la liaison en
`boundRule`, structurée comme la route des règles la reçoit ; sa forme canonique — clés triées — est
ce que lit l'empreinte de contenu de la ligne et ce qu'énonce le `checklist.json` signé.

Ce que la ligne d'un projet montre ensuite, et quand une mesure refuse une soumission ou une
approbation, est dans [checklists de sécurité](../guide/security-checklists.fr.md#lignes-mesurees).

## 5. Publier

Publier fait de la version celle sur laquelle les projets ouvrent leurs checklists. Le bouton nomme la
**révision** affichée — le compteur de modifications du brouillon — et c'est cette révision qui est
envoyée : une modification faite par quelqu'un d'autre après l'ouverture de la page refuse la
publication plutôt que de publier ce que personne ici n'a lu.

**Publier remplit le classeur une fois, comme le ferait une approbation** — chaque ligne répondue et
commentée, le produit, l'auteur et la date de l'en-tête écrits — et n'en garde rien : ni document, ni
signature, ni entrée d'audit. Un classeur dans lequel aucune approbation ne pourrait écrire est refusé
ici, plutôt qu'à la première approbation, quand un projet a déjà répondu à chaque ligne d'une
checklist qui ne pourrait jamais être signée. Le cas rencontré jusqu'ici est
[une formule dans une cellule que Vectispire écrit](#une-formule-dans-une-cellule-que-vectispire-ecrit).

Quand le serveur refuse — une publication, ou toute autre modification d'une version — l'écran dit
pourquoi, en une phrase pour chaque cause que le serveur nomme (voir
[le tableau plus bas](#refus-pour-les-scripts-et-les-integrations)), et propose **Recharger la
version** là où la relire est le remède :

- **Vous avez écrit ce brouillon** — vous l'avez importé ou dérivé, avez confirmé sa disposition,
  apparié ses items ou fixé la preuve que ses lignes demandent — et la double validation est active :
  **une deuxième personne doit le publier**, un autre gouverneur de la plateforme, administrateur ou
  CISO qui n'en a rien écrit. Chaque compte qui a façonné le brouillon en est l'auteur, pas seulement
  celui qui l'a importé. L'écran vous prévient aussi avant le clic.
- **La version a changé depuis que vous l'avez lue** : la révision que vous aviez à l'écran est
  nommée. Rechargez-la, relisez-la, puis publiez.
- **Elle n'a pas de disposition confirmée** ; **ce n'est plus un brouillon** parce que quelqu'un l'a
  publié ou écarté entre-temps — dérivez un nouveau brouillon de la version publiée pour la changer ;
  **le modèle a déjà un brouillon**, quand vous en importez ou en dérivez un autre ; **elle n'est pas
  publiée**, quand vous dérivez d'un brouillon ou d'une version retirée ; **elle est déjà retirée** ;
  **elle ne suit aucune version publiée**, il n'y a donc rien à apparier.

Un refus dont le serveur ne nomme pas la cause est affiché dans les mots du serveur — de même que
**aucune approbation ne pourrait remplir son classeur**, dont la phrase (en anglais) nomme chaque
cellule à corriger.

### Une formule dans une cellule que Vectispire écrit

Une approbation écrit les **cellules de réponse et de commentaire de chaque ligne d'item** et les
**cellules de valeur de l'en-tête** — la date, le produit, l'auteur. Ce que ces cellules contiennent est
remplacé ; une formule seule y est remplacée aussi, ce qui arrive à un `AUJOURDHUI()` dans la cellule
de date : le document est daté par l'approbation, pas par la prochaine personne qui l'ouvre.

Ce qui ne peut pas être remplacé, c'est une formule **dont d'autres cellules dépendent** :

- **la cellule maîtresse d'une formule partagée.** Quand une formule est recopiée vers le bas ou vers
  la droite, Excel n'enregistre son texte qu'une fois, dans la première cellule, et les autres ne font
  que renvoyer à celle-ci. Écrire une réponse ou un commentaire par-dessus cette première cellule
  laisserait les autres renvoyer à rien, et quiconque ouvrirait le document serait invité à le
  réparer. Une formule d'aide dans la colonne des commentaires —
  `=SI(F7="Non fait";"Expliquer pourquoi";"")` recopiée vers le bas — en est l'origine habituelle ;
- **une formule matricielle saisie sur plusieurs cellules.**

Le refus nomme chacune de ces cellules avec la plage qui en dépend — *Cell G7 (the master of a formula
shared across G7:G9) of the checklist sheet is a cell Vectispire writes…* — et, pour un script, le
membre `cells` du problème les liste : `cell`, `kind` (`shared` ou `array`) et `range`.

**Corrigez le classeur en retirant la formule des cellules que Vectispire écrit** — leur contenu est de
toute façon remplacé à l'approbation :

- **Excel** : sélectionnez les cellules nommées — pour une matrice entière, *Accueil → Rechercher et
  sélectionner → Sélectionner les cellules → Matrice en cours* — puis *Accueil → Effacer → Effacer le
  contenu*. Pour garder ce qu'elles affichent en simple texte, *Copier*, puis *Collage spécial →
  Valeurs* sur les mêmes cellules. Si la formule d'aide doit rester, coupez-la et collez-la dans une
  colonne que la disposition ne nomme pas.
- **LibreOffice Calc** : sélectionnez les cellules — pour une matrice entière, *Édition → Sélectionner
  → Sélectionner la matrice* ou `Ctrl+/` — puis *Feuille → Supprimer le contenu…* avec *Formules*
  coché. Pour garder ce qu'elles affichent, *Copier*, puis *Édition → Collage spécial → Coller
  uniquement les valeurs*. Déplacer la formule d'aide se fait comme dans Excel.

Enregistrez, puis **écartez le brouillon** — le classeur d'une version ne change jamais une fois
importé — et importez le classeur corrigé. Confirmez de nouveau sa disposition ; les exigences de
preuve et les règles ne sont héritées, par clé, que de la version *publiée* précédente : refixez donc ce
que vous aviez fixé sur le brouillon écarté.

Une version **publiée avant ce contrôle** qui a une telle cellule refuse chaque approbation, dans les
mêmes termes. Publiez une version corrigée comme ci-dessus, et faites
[passer les checklists des projets sur celle-ci](../guide/security-checklists.fr.md#7-passer-a-une-version-plus-recente) :
leurs réponses sont reportées. Entre-temps, aucune checklist n'est ouverte sur une telle version ni
passée à celle-ci — le même essai y est exécuté et l'écran nomme les cellules (409
`checklist-version-unrenderable`) — tandis qu'une checklist qui s'y trouve déjà peut toujours la quitter.
Retirez-la une fois la version corrigée publiée, pour qu'elle ne soit plus proposée.

Double validation active, la plateforme refuse de se retrouver avec un seul compte capable de
publier — voir [double validation](four-eyes.fr.md#lactiver-demande-quune-seconde-personne-existe).

## 6. Dériver, retirer, écarter

- **Dériver un nouveau brouillon** d'une version publiée pour changer ce qu'une version publiée ne peut
  jamais changer en place : le même classeur, la même disposition et les mêmes items — chacun demandant la même preuve —, apparié avec la
  version dont il vient, et un libellé à lui si vous en donnez un.
- **Retirer** une version publiée : aucune nouvelle checklist ne s'ouvre dessus, et chaque checklist
  qui l'utilise déjà reste lisible et exportable. Double validation active, elle est retirée par
  quelqu'un qui ne l'a pas écrite.
- **Écarter le brouillon** quand il ne doit jamais être publié. Cela ne change rien à ce qu'un projet
  atteste, donc cela ne demande personne d'autre, et la version s'affiche comme *retirée*.

## Refus, pour les scripts et les intégrations

Chaque refus d'une route de modèle qui tient à l'état de la version répond **409**, et nomme sa cause
dans le `type` du problème, `urn:vectispire:problem:` suivi du jeton ci-dessous — pour qu'un script
distingue « relisez » de « quelqu'un d'autre doit le faire » sans lire la phrase, écrite pour une
personne et susceptible de changer.

| `type` se termine par | Signification | Que faire |
|---|---|---|
| `checklist-template-changed` | Le brouillon a changé depuis la `revision` nommée | Le relire |
| `checklist-template-not-draft` | La version est publiée ou retirée | Dériver un nouveau brouillon de la version publiée |
| `checklist-template-no-layout` | La disposition du brouillon n'est pas confirmée | La confirmer d'abord |
| `checklist-template-has-draft` | Le modèle a déjà un brouillon | Le publier ou l'écarter d'abord |
| `checklist-template-not-published` | Dériver d'un brouillon ou d'une version retirée | Dériver d'une version publiée |
| `checklist-template-retired` | La version est déjà retirée | — |
| `checklist-template-nothing-to-pair` | Une première version : aucune précédente avec laquelle apparier | — |
| `checklist-template-unrenderable` | À la publication : aucune approbation ne pourrait remplir le classeur — une cellule qu'elle écrit porte une formule dont d'autres cellules dépendent, chacune nommée dans le membre `cells` du problème | [Corriger le classeur](#une-formule-dans-une-cellule-que-vectispire-ecrit), écarter le brouillon et l'importer de nouveau |
| `checklist-four-eyes` | Le double contrôle est activé et vous avez écrit ce brouillon | Quelqu'un d'autre le publie ou le retire |

`checklist-four-eyes` est aussi le jeton de l'approbation d'une checklist de projet : il y signifie la
même chose.

## Ce qui est consigné

Chaque import, confirmation de disposition, appariement, exigence de preuve définie, liaison de
règle, dérivation, publication et retrait est inscrit au [journal d'audit](audit-log.fr.md). Publier une version, et retirer une version publiée, est aussi
signalé au SIEM comme `VECTI-SEC-024`.

## À lire aussi

- [Checklists de sécurité](../guide/security-checklists.fr.md) — la checklist d'un projet, remplie sur une version
  publiée, et ce que le passage à une nouvelle version reporte.
- [Double validation](four-eyes.fr.md) — le réglage qui décide qui peut publier.
- [Utilisateurs et équipes](users-and-teams.fr.md) — les rôles et ce que chacun peut faire.
- [Journal d'audit](audit-log.fr.md) — où chaque changement d'un modèle est inscrit.
