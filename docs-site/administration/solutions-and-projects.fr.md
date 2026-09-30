# Solutions et projets

Vectispire analyse les dépôts un par un, mais on l'interroge par produit : *quelle est l'exposition
de la plateforme de paiement*, *qui peut voir l'application mobile*. Les solutions et les projets
sont la façon de dire à Vectispire quels sont les produits.

## Le modèle

- Une **solution** contient des **projets** — une gamme, une plateforme, une offre client.
- Un **projet** appartient à une seule solution et référence les **dépôts** et les **images de
  conteneur** qui le composent.
- Un dépôt ou une image est dans **un projet au plus**. C'est voulu : un chiffre ou un rapport doit
  s'additionner à un seul projet sans rien compter deux fois, et « dans quel projet est-il » doit avoir
  une seule réponse.

Les noms sont uniques sans égard à la casse : celui d'une solution dans toute l'installation, celui
d'un projet dans sa solution. Deux solutions peuvent chacune contenir une « API ». Un nom déjà pris est
refusé de la même façon à la création, au renommage ou au déplacement vers une solution : `409`, de
type `urn:vectispire:problem:solution-name-taken` pour une solution et
`urn:vectispire:problem:project-name-taken` pour un projet, et la boîte de dialogue reste ouverte en
disant quel nom est pris.

## « Sans projet »

Les dépôts et les images qui existaient avant la création du premier projet démarrent **sans
projet**. Rien n'est déduit de leur nom, de leur URL ni de leur registre — un administrateur les range.

« Sans projet » est un groupe à part entière partout où il apparaît, jamais masqué : l'arbre y liste
ces dépôts et ces images, avec leurs constats ouverts, pour qu'un rangement inachevé se voie inachevé.

## Ranger, déplacer et retirer un dépôt ou une image

Seuls les administrateurs modifient l'arbre. Ranger un dépôt ou une image dans un projet le sort du
projet où il se trouvait ; le retirer le ramène à « sans projet ».

**Ranger change des accès.** Une attribution de projet couvre les dépôts et les images du projet *au
moment de chaque requête* (voir plus bas) : déplacer l'un d'eux d'un projet à un autre le retire aux
titulaires du premier et le donne à ceux du second, immédiatement. Le journal d'audit enregistre
chaque déplacement en ces termes, sous `PROJECT_REPOSITORIES_CHANGED` pour un dépôt et
`PROJECT_CONTAINERS_CHANGED` pour une image.

## Déplacer un projet vers une autre solution

Un administrateur peut déplacer un projet vers une autre solution. **Tout ce que le projet contient
le suit** : ses dépôts et ses images restent rangés dans le projet, et ses attributions, ses checklists, les plugins
activés pour lui et les sources SARIF qui le visent nomment le projet, pas la solution — aucun d'eux ne
change. **Personne ne gagne ni ne perd la vue sur quoi que ce soit** : il n'existe pas d'attribution
sur une solution, un déplacement ne change donc que l'endroit où le projet est dessiné dans l'arbre —
et quelle solution le compte dans ses chiffres et dans son filtre d'issues, dès la requête suivante.

Le déplacement est refusé quand la solution cible contient déjà un projet du même nom, casse ignorée
(renommez d'abord l'un des deux), et une solution inexistante est traitée comme absente. Déplacer un
projet vers la solution où il se trouve déjà ne change rien. Le journal d'audit enregistre le
déplacement sous `PROJECT_UPDATED`, en nommant les deux solutions.

## Attributions sur un projet

Dans [Utilisateurs et équipes](users-and-teams.md#ce-quune-attribution-nomme), un compte ou une
équipe peut se voir attribuer un projet, à côté de dépôts et d'images individuels :

- L'attribution couvre **tous les dépôts et toutes les images du projet au moment de chaque
  requête**. Un dépôt ou une image rangé dans le projet le mois prochain est visible de ses titulaires
  dès qu'il y est rangé, sans rien réattribuer — et celui qu'on en retire cesse aussitôt de leur être
  visible par cette attribution.
- Les attributions **s'additionnent** : ce qu'une personne voit est l'union de ses attributions de
  dépôts, d'images et de projets, directes et par ses équipes.
- Il n'y a **pas d'attribution sur une solution**. Un seul niveau d'héritage est ce qu'un auditeur
  peut suivre ; une attribution à l'échelle d'une solution n'est rien d'autre qu'une attribution sur
  chacun de ses projets.
- Une clé d'API ne peut pas être restreinte à un projet : sa restriction reste un dépôt ou une image.

## Ce que voit un lecteur

L'arbre des solutions est lisible par tout compte, et ne montre que ce que ce compte peut voir :

- Un **projet apparaît** quand le lecteur a une attribution sur lui ou voit au moins un de ses
  dépôts ou de ses images. Il ne liste que les dépôts et les images que le lecteur peut voir.
- Un projet que le lecteur ne voit qu'en partie — un dépôt attribué sur trois, ou ses dépôts sans son
  image, par exemple — est
  marqué **partiel**, et ses chiffres ne portent que sur ce que le lecteur voit. Une attribution
  partielle voit un projet partiel, et le dit, plutôt que de présenter la moitié d'un projet comme
  s'il était entier.
- Une **solution apparaît** quand l'un de ses projets apparaît, et elle est partielle dès qu'un dépôt
  ou une image rangé sous elle est caché au lecteur.
- Les administrateurs, RSSI et auditeurs voient toutes les solutions et tous les projets, vides
  compris.

Chaque projet, chaque solution et le groupe « sans projet » portent leurs **constats ouverts par
sévérité**, comptés sur les dépôts et les images que le lecteur peut voir et sans le triage réglé (non affecté,
corrigé), comme tout autre chiffre de risque.

## Supprimer

- **Supprimer un projet** ramène ses dépôts et ses images à « sans projet » et révoque toute
  attribution qui le nomme. Cela ne supprime **aucun dépôt, aucune image ni aucun constat**. L'entrée
  d'audit indique combien de dépôts et d'images ont été détachés et combien d'attributions révoquées.
- **Supprimer une solution** est refusé tant qu'elle contient un projet : déplacez ses projets vers
  une autre solution ou supprimez-les d'abord, chacun étant une décision auditée à part.

## L'écran

**Solutions et projets**, dans le menu à côté des dépôts, dessine l'arbre pour tout compte : chaque
solution, ses projets, les dépôts et les images de conteneur rangés dans chacun, puis **Sans projet**
en dernier — affiché même vide. Dans chaque projet et sous « Sans projet », les dépôts viennent
d'abord, puis les images, distingués par leur icône : une arborescence pour un dépôt, une boîte pour
une image — celle que le menu donne à **Conteneurs**. Chaque solution, chaque projet et le groupe
« sans projet » portent deux comptes, **Dépôts : N** et **Images : N**, et une étiquette par sévérité
qui a des constats ouverts (« 2 Critique », « 1 Élevée »), ou « Aucun constat ouvert » — comptés sur
les dépôts comme sur les images. Un nœud que vous ne voyez qu'en partie porte **Visible en partie :
N dépôts et M images que vous pouvez voir**. Le nom d'un dépôt ouvre les constats de ce dépôt, celui
d'une image ceux de cette image. **Le nom d'un projet ouvre la page du projet** (plus bas), et chaque
solution porte **Conformité et score**, qui ouvre la conformité et le score de la solution sur ce que
vous en voyez — le même dessin que celui de la page du projet.

Sur une solution ou un projet, **chaque étiquette de sévérité est un lien** vers la
[liste des constats](../guide/issues.md) restreinte à cette solution ou à ce projet, à cette sévérité,
et à **Masquer le triage réglé** — la clause selon laquelle l'étiquette compte, pour que la liste
contienne le nombre que l'étiquette affichait. Les étiquettes de **Sans projet** ne sont que des
chiffres : la liste n'a pas de filtre « dans aucun projet ».

Les administrateurs disposent en plus de :

| Action | Où | Ce que l'écran dit d'abord |
|---|---|---|
| **Nouvelle solution** | en haut de la page | — |
| **Nouveau projet** | sur une solution | — |
| Renommer ou décrire (crayon) | sur une solution ou un projet | — |
| **Déplacer vers…** | sur un projet | que tout ce que contient le projet le suit et que personne ne gagne ni ne perd la vue sur quoi que ce soit ; la solution se choisit parmi les autres, avec un nouveau nom facultatif |
| Supprimer (corbeille) | sur une solution ou un projet | pour un projet : ses dépôts et ses images reviennent à « sans projet » et toute attribution qui le nomme est révoquée ; pour une solution : refusé tant qu'elle contient des projets, avec la raison donnée par le serveur |
| **Ranger dans un projet** | sur un dépôt ou une image de « Sans projet » | qui le voit désormais : tout compte et toute équipe titulaires d'une attribution sur le projet |
| Déplacer (deux flèches) | sur un dépôt ou une image rangés | qui cesse de le voir et qui le voit désormais |
| Retirer du projet (croix) | sur un dépôt ou une image rangés | qui cesse de le voir |

Une image se range, se déplace et se retire exactement comme un dépôt, par les mêmes fenêtres ;
chaque bouton porte, pour un lecteur d'écran, le nom du dépôt ou de l'image sur lequel il agit
(« Retirer nginx:1.27 de son projet »). Un refus — une image supprimée entre-temps répond « Target not
found. », une image déjà retirée de ce projet « This image is not in that project. » — s'affiche dans
les mots du serveur, au-dessus de l'arbre.

Quand un projet est déplacé vers une solution qui contient déjà un projet du même nom, la fenêtre de
déplacement reste ouverte, le dit, et accepte un nouveau nom dans la même fenêtre ; une fois le
projet déplacé, l'arbre est redessiné et un avis dit où il est allé.

Le projet de destination se choisit dans une liste groupée par solution. Les noms sont limités à
100 caractères et les descriptions à 255, dans le formulaire comme sur le serveur. Les autres comptes
voient le même arbre sans aucune de ces actions ; le serveur les refuserait de toute façon.

Les rôles de gouvernance ont aussi **Plugins** sur chaque projet : le registre avec un interrupteur
par plugin, actif pour les administrateurs, le RSSI et le gouverneur, en lecture seule pour un
auditeur, les langages de chaque plugin confrontés à ceux du projet (voir
[Plugins et imports SARIF](plugins.md#les-langages-detectes-dans-un-depot)). Un projet dont les dépôts
ont été recensés montre l'union de leurs langages en petites étiquettes à côté de ses chiffres.

La liste des dépôts indique sur chaque dépôt le projet où il est rangé — un lien vers ce projet dans
l'arbre — ou « — » s'il n'est dans aucun. **Conteneurs** indique de même, sur chaque image,
**Projet :** et un lien vers ce projet dans l'arbre — ou **sans projet**, un lien vers ce groupe.

## Un projet seul : ses chiffres, sa conformité et ses composants

Quatre lectures répondent pour un projet — ou, pour la conformité, une solution — plutôt que pour
l'arbre entier, à l'usage d'un écran ou d'un plugin de rapport qui rend compte d'un produit. Chacune
suit la règle de l'arbre : vous obtenez le projet si vous voyez tout, détenez le projet en tant que tel
ou voyez au moins un de ses dépôts ou de ses images ; un projet dont vous ne voyez rien reçoit
exactement la réponse d'un projet inexistant, `404` *Project not found.* (*Solution not found.* pour une
solution).

- **La lecture du projet** est son nœud dans l'arbre — sa solution nommée, ses dépôts et ses images,
  ses problèmes ouverts par gravité, **partiel**, si ses checklists vous sont ouvertes, les langages
  détectés — calculé par le même code, si bien que les deux ne divergent jamais.
- **La conformité par projet et par solution** est l'évaluation du parc exécutée sur les seules cibles
  du projet : mêmes contrôles, mêmes plafonds de couverture et de fraîcheur, `NO_DATA` quand aucune de
  ses cibles n'a été analysée — quel que soit l'état du reste du parc — et la **fiche de score** du
  portefeuille (score, note, recommandations) calculée de la même manière. Un projet propre dans un parc
  sale se lit conforme. Voir [Conformité](../guide/compliance.fr.md#par-projet-et-par-solution).
- **Le SBOM consolidé** fusionne les composants de la dernière analyse terminée de chaque dépôt et de
  chaque image, par package URL et version, et nomme les cibles qui portent chacun. Chaque cible est
  listée avec ce qui en a été lu : *listed* (listée), *empty* (son SBOM ne listait rien), *absent* (sa
  dernière analyse terminée ne garde pas de SBOM) ou *never_scanned* (jamais analysée). L'inventaire
  d'une analyse plus ancienne ne remplace jamais celui d'une dernière analyse sans SBOM, et le résultat
  se dit **incomplet** tant qu'une cible est absente ou jamais analysée — une fusion qui les aurait
  sautées en silence affirmerait « nous n'embarquons pas cette bibliothèque » d'une arborescence que
  personne n'a regardée.
- **Le document CycloneDX** de la même fusion, avec les problèmes CVE du projet en VEX. Chaque composant
  nomme ses porteurs (propriété `vectispire:target`) ; `compositions` vaut `complete` seulement quand
  toutes les cibles du projet ont été vues et lues, `incomplete` sinon, et les métadonnées nomment chaque
  cible dont l'inventaire est inconnu. Il n'est pas signé, comme les autres exports.

**Un projet vu en partie est calculé sur la partie vue, et le dit** (`partial`), comme les chiffres de
l'arbre et la liste des problèmes : chaque entrée est restreinte aux cibles que vous voyez, rien des
cibles masquées ne vous parvient hormis le fait qu'elles existent. Les checklists de sécurité sont
l'exception : leurs lignes parlent en mots pour chaque dépôt du projet, elles sont donc refusées à un
lecteur partiel.

### La page du projet

La page d'un projet — son nom dans l'arbre, ou `/projects/{id}` — réunit ces lectures pour un produit :

- **L'en-tête** : le nom du projet et sa solution, sa description, **Dépôts : N** et **Images : N**,
  l'étiquette **Visible en partie** dans les mots de l'arbre quand vous n'en voyez qu'une partie, les
  langages détectés, **Constats ouverts : N** — un lien vers la [liste des constats](../guide/issues.md)
  restreinte au projet avec **Masquer le triage réglé**, la clause selon laquelle le chiffre compte — et
  **Checklist de sécurité** quand la checklist s'ouvrirait pour vous.
- **Conformité et score** : la fiche de score (score sur 100, note, les comptes dont elle est tirée,
  ses recommandations), puis les chiffres, la matrice par cible, les référentiels et les contrôles de la
  page de conformité du parc, dessinés par le même composant. Au-dessus, *Calculé sur N cible(s)*, et
  sur un projet partiel un avertissement que les chiffres ne couvrent que ce que vous voyez. **Un projet
  dont aucune cible n'a jamais été analysée se lit *Aucune donnée*** — un tiret pour chaque référentiel
  et pour le score, pas une note : la fiche part de cent et retranche ce qu'elle trouve, si bien que sur
  rien d'observé elle lirait *A*.
- **Composants** : la liste consolidée, filtrable par nom ou par package URL, chaque composant avec les
  cibles qui le portent ; au-dessus, **Inventaire par cible** donne à chaque dépôt et à chaque image son
  état — *N composant(s)*, *Aucun composant dans son SBOM*, *Pas de SBOM* ou *Jamais analysée*, avec la
  date de l'analyse lue. Tant qu'une cible est *Pas de SBOM* ou *Jamais analysée*, un bandeau **Liste
  incomplète** dit pour combien de cibles la liste ne peut pas parler. **Télécharger le CycloneDX**
  enregistre le document CycloneDX 1.5 avec son VEX.

Un projet qui n'existe pas et un projet dont vous ne voyez rien affichent le même *Ce projet n'existe
pas, ou vous ne voyez aucun de ses dépôts ni de ses images.* La page **Conformité et score** d'une
solution (`/solutions/{id}/compliance`) dessine le périmètre de la solution de la même façon.

## Par l'API

Les mêmes opérations, pour les scripts :

| Route | Qui | Effet |
|---|---|---|
| `GET /api/v1/solutions` | tout compte | l'arbre, dans la mesure de ce que l'appelant peut voir |
| `POST /api/v1/solutions` | administrateur | créer une solution (`name`, `description`) ; `409` de type `urn:vectispire:problem:solution-name-taken` quand le nom est pris |
| `PATCH /api/v1/solutions/{id}` | administrateur | la renommer ou la décrire ; un champ absent est conservé ; `409` de type `urn:vectispire:problem:solution-name-taken` quand le nom est pris |
| `DELETE /api/v1/solutions/{id}` | administrateur | la supprimer ; `409` tant qu'elle contient des projets |
| `POST /api/v1/solutions/{id}/projects` | administrateur | y créer un projet ; `409` de type `urn:vectispire:problem:project-name-taken` quand la solution contient déjà ce nom |
| `PATCH /api/v1/projects/{id}` | administrateur | renommer ou décrire un projet, ou le déplacer : `solutionId` ; `409` de type `urn:vectispire:problem:project-name-taken` quand la solution où il aboutit contient déjà son nom — renommé, déplacé ou les deux — `404` pour une solution inexistante |
| `DELETE /api/v1/projects/{id}` | administrateur | supprimer un projet, comme décrit plus haut |
| `PUT /api/v1/projects/{id}/repositories/{repositoryId}` | administrateur | ranger ou déplacer un dépôt |
| `DELETE /api/v1/projects/{id}/repositories/{repositoryId}` | administrateur | retour à « sans projet » |
| `PUT /api/v1/projects/{id}/containers/{containerId}` | administrateur | ranger ou déplacer une image de conteneur |
| `DELETE /api/v1/projects/{id}/containers/{containerId}` | administrateur | retour à « sans projet » |
| `GET /api/v1/projects/{id}` | tout compte, clé de lecture | un projet tel que le décrit son nœud dans l'arbre, avec sa `solution` (`id`, `name`) |
| `GET /api/v1/projects/{id}/compliance`, `GET /api/v1/solutions/{id}/compliance` | tout compte, clé de lecture | sa conformité (`compliance`, la forme du résumé du parc) et sa `scorecard`, sur les cibles que voit l'appelant ; `partial`, `targetCount` |
| `GET /api/v1/projects/{id}/components` | tout compte, clé de lecture | le SBOM consolidé : `components` (chacun avec les `targets` qui le portent), `targets` (chacune avec son `inventory`), `complete`, `partial` |
| `GET /api/v1/cyclonedx/projects/{id}/cyclonedx-vex.json` | tout compte, clé d'export | le même en document CycloneDX 1.5 avec le VEX du projet |

`GET /api/v1/repositories` et `GET /api/v1/containers` indiquent aussi dans quel projet se trouve
chaque dépôt ou image (`projectId`, `projectName`). Dans l'arbre, chaque projet et le groupe « sans
projet » listent leurs images sous `containers` et les comptent dans `containerCount`, à côté de
`repositories` et `repositoryCount`.

## Ce qui reste propre aux dépôts

La **checklist de sécurité** d'un projet mesure toujours ses seuls dépôts, et n'est toujours montrée
qu'à qui les voit tous : les images n'entrent pas dans les mesures d'une checklist, si bien qu'une
checklist signée dit exactement ce qu'elle disait. Un projet partiel du seul fait d'une image que vous ne
voyez pas vous laisse donc sa checklist ouverte. Les langages détectés d'un projet et les plugins
activés pour lui portent sur des arborescences de sources : ils concernent eux aussi ses dépôts.

## Voir aussi

- [Utilisateurs et équipes](users-and-teams.md) — attribuer un projet à un compte ou à une équipe.
- [Journal d'audit](audit-log.md) — où sont enregistrés créations, suppressions et déplacements.
- [Checklists de sécurité](../guide/security-checklists.fr.md) — la checklist d'un projet, montrée seulement à qui voit le projet en entier.
