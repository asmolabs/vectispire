# Solutions et projets

Vectispire analyse les dépôts un par un, mais on l'interroge par produit : *quelle est l'exposition
de la plateforme de paiement*, *qui peut voir l'application mobile*. Les solutions et les projets
sont la façon de dire à Vectispire quels sont les produits.

## Le modèle

- Une **solution** contient des **projets** — une gamme, une plateforme, une offre client.
- Un **projet** appartient à une seule solution et référence les **dépôts** qui le composent.
- Un dépôt est dans **un projet au plus**. C'est voulu : un chiffre ou un rapport doit s'additionner
  à un seul projet sans rien compter deux fois, et « dans quel projet est-il » doit avoir une seule
  réponse.
- Les images de conteneur ne sont pas encore rattachées aux projets.

Les noms sont uniques sans égard à la casse : celui d'une solution dans toute l'installation, celui
d'un projet dans sa solution. Deux solutions peuvent chacune contenir une « API ».

## « Sans projet »

Les dépôts qui existaient avant la création du premier projet démarrent **sans projet**. Rien n'est
déduit de leur nom ni de leur URL — un administrateur les range.

« Sans projet » est un groupe à part entière partout où il apparaît, jamais masqué : l'arbre y liste
ces dépôts, avec leurs constats ouverts, pour qu'un rangement inachevé se voie inachevé.

## Ranger, déplacer et retirer un dépôt

Seuls les administrateurs modifient l'arbre. Ranger un dépôt dans un projet le sort du projet où il
se trouvait ; le retirer le ramène à « sans projet ».

**Ranger un dépôt change des accès.** Une attribution de projet couvre les dépôts du projet *au
moment de chaque requête* (voir plus bas) : déplacer un dépôt d'un projet à un autre le retire aux
titulaires du premier et le donne à ceux du second, immédiatement. Le journal d'audit enregistre
chaque déplacement en ces termes, sous `PROJECT_REPOSITORIES_CHANGED`.

## Attributions sur un projet

Dans [Utilisateurs et équipes](users-and-teams.md#ce-quune-attribution-nomme), un compte ou une
équipe peut se voir attribuer un projet, à côté de dépôts et d'images individuels :

- L'attribution couvre **tous les dépôts du projet au moment de chaque requête**. Un dépôt rangé
  dans le projet le mois prochain est visible de ses titulaires dès qu'il y est rangé, sans rien
  réattribuer.
- Les attributions **s'additionnent** : ce qu'une personne voit est l'union de ses attributions de
  dépôts, d'images et de projets, directes et par ses équipes.
- Il n'y a **pas d'attribution sur une solution**. Un seul niveau d'héritage est ce qu'un auditeur
  peut suivre ; une attribution à l'échelle d'une solution n'est rien d'autre qu'une attribution sur
  chacun de ses projets.
- Une clé d'API ne peut pas être restreinte à un projet : sa restriction reste un dépôt ou une image.

## Ce que voit un lecteur

L'arbre des solutions est lisible par tout compte, et ne montre que ce que ce compte peut voir :

- Un **projet apparaît** quand le lecteur a une attribution sur lui ou voit au moins un de ses
  dépôts. Il ne liste que les dépôts que le lecteur peut voir.
- Un projet que le lecteur ne voit qu'en partie — un dépôt attribué sur trois, par exemple — est
  marqué **partiel**, et ses chiffres ne portent que sur ce que le lecteur voit. Une attribution
  partielle voit un projet partiel, et le dit, plutôt que de présenter la moitié d'un projet comme
  s'il était entier.
- Une **solution apparaît** quand l'un de ses projets apparaît, et elle est partielle dès qu'un dépôt
  rangé sous elle est caché au lecteur.
- Les administrateurs, RSSI et auditeurs voient toutes les solutions et tous les projets, vides
  compris.

Chaque projet, chaque solution et le groupe « sans projet » portent leurs **constats ouverts par
sévérité**, comptés sur les dépôts que le lecteur peut voir et sans le triage réglé (non affecté,
corrigé), comme tout autre chiffre de risque.

## Supprimer

- **Supprimer un projet** ramène ses dépôts à « sans projet » et révoque toute attribution qui le
  nomme. Cela ne supprime **aucun dépôt ni aucun constat**. L'entrée d'audit indique combien de
  dépôts ont été détachés et combien d'attributions révoquées.
- **Supprimer une solution** est refusé tant qu'elle contient un projet : supprimez ou videz d'abord
  ses projets, chacun étant une décision auditée à part.

## L'écran

**Solutions et projets**, dans le menu à côté des dépôts, dessine l'arbre pour tout compte : chaque
solution, ses projets, les dépôts rangés dans chacun, puis **Sans projet** en dernier — affiché même
vide. Chaque solution, chaque projet et le groupe « sans projet » portent leur nombre de dépôts et une
étiquette par sévérité qui a des constats ouverts (« 2 Critique », « 1 Élevée »), ou « Aucun constat
ouvert ». Un nœud que vous ne voyez qu'en partie porte **Visible en partie : N dépôts que vous
pouvez voir**. Le nom d'un dépôt ouvre les constats de ce dépôt.

Les administrateurs disposent en plus de :

| Action | Où | Ce que l'écran dit d'abord |
|---|---|---|
| **Nouvelle solution** | en haut de la page | — |
| **Nouveau projet** | sur une solution | — |
| Renommer ou décrire (crayon) | sur une solution ou un projet | — |
| Supprimer (corbeille) | sur une solution ou un projet | pour un projet : ses dépôts reviennent à « sans projet » et toute attribution qui le nomme est révoquée ; pour une solution : refusé tant qu'elle contient des projets, avec la raison donnée par le serveur |
| **Ranger dans un projet** | sur un dépôt de « Sans projet » | qui le voit désormais : tout compte et toute équipe titulaires d'une attribution sur le projet |
| Déplacer (deux flèches) | sur un dépôt rangé | qui cesse de le voir et qui le voit désormais |
| Retirer du projet (croix) | sur un dépôt rangé | qui cesse de le voir |

Le projet de destination se choisit dans une liste groupée par solution. Les noms sont limités à
100 caractères et les descriptions à 255, dans le formulaire comme sur le serveur. Les autres comptes
voient le même arbre sans aucune de ces actions ; le serveur les refuserait de toute façon.

La liste des dépôts indique sur chaque dépôt le projet où il est rangé — un lien vers ce projet dans
l'arbre — ou « — » s'il n'est dans aucun.

## Par l'API

Les mêmes opérations, pour les scripts :

| Route | Qui | Effet |
|---|---|---|
| `GET /api/v1/solutions` | tout compte | l'arbre, dans la mesure de ce que l'appelant peut voir |
| `POST /api/v1/solutions` | administrateur | créer une solution (`name`, `description`) |
| `PATCH /api/v1/solutions/{id}` | administrateur | la renommer ou la décrire ; un champ absent est conservé |
| `DELETE /api/v1/solutions/{id}` | administrateur | la supprimer ; `409` tant qu'elle contient des projets |
| `POST /api/v1/solutions/{id}/projects` | administrateur | y créer un projet |
| `PATCH /api/v1/projects/{id}` | administrateur | renommer ou décrire un projet |
| `DELETE /api/v1/projects/{id}` | administrateur | supprimer un projet, comme décrit plus haut |
| `PUT /api/v1/projects/{id}/repositories/{repositoryId}` | administrateur | ranger ou déplacer un dépôt |
| `DELETE /api/v1/projects/{id}/repositories/{repositoryId}` | administrateur | retour à « sans projet » |

`GET /api/v1/repositories` indique aussi dans quel projet se trouve chaque dépôt (`projectId`,
`projectName`).

## Voir aussi

- [Utilisateurs et équipes](users-and-teams.md) — attribuer un projet à un compte ou à une équipe.
- [Journal d'audit](audit-log.md) — où sont enregistrés créations, suppressions et déplacements.
