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
d'une image ceux de cette image.

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
