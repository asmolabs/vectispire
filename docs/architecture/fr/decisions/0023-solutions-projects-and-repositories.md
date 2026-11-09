# 0023 — Une solution contient des projets, un projet référence des dépôts, et un droit peut viser un projet

**Date :** 2026-09-25 · **Statut :** acceptée · **Décideur :** Laurent Boucher

## Contexte

Tout, dans Vectispire, dépend d'une cible d'analyse — un dépôt ou une image de conteneur. C'est la
bonne unité pour analyser, et la mauvaise pour tout ce que les organisations en attendent ensuite :
un produit, ce sont plusieurs dépôts ; un rapport s'écrit pour un produit ; et un droit d'accès
accordé dépôt par dépôt doit être répété chaque fois qu'un produit en gagne un. Les rapports et
checklists (les plugins de rapport qui suivent cette décision) s'écrivent **par projet** : il faut
donc que le projet existe d'abord.

## Décision

- **Une solution contient des projets ; un projet référence des dépôts.** Deux nouvelles tables,
  `t_solution` et `t_project` (un projet appartient à exactement une solution), et une colonne
  `project_id` facultative sur `t_repository`.
- **Un dépôt appartient à un projet au plus.** Une colonne, pas une table de liaison : un problème,
  un score ou un rapport doivent se sommer sur un projet sans double compte, et « dans quel projet
  est ce dépôt » doit avoir une seule réponse.
- **Les dépôts existants commencent sans projet.** Rien n'est déduit des noms ou des URL ; un
  administrateur les range. Chaque écran et chaque agrégat traite « sans projet » explicitement plutôt
  que de masquer ces dépôts.
- **Un droit peut viser un projet** — pour un compte ou une équipe, à côté des droits par dépôt et par
  conteneur existants. Il est résolu à chaque requête en l'ensemble des dépôts du projet *à ce
  moment*, si bien qu'un dépôt ajouté à un projet devient visible pour qui détient le projet, sans rien
  réaccorder. Les droits par dépôt restent valables ; la visibilité est l'**union** des deux. Il n'y a
  **pas de droit sur une solution** : un niveau d'héritage suffit à auditer, et un droit sur toute une
  solution est une liste de droits par projet qu'un administrateur peut voir.
- La résolution a lieu dans `VisibilityService`, avant toute requête : la `Visibility` passée aux
  requêtes reste un ensemble de cibles, si bien que chaque route qui filtre déjà par visibilité filtre
  correctement les dépôts d'un projet sans être modifiée, et un refus reste un 404.
- Les conteneurs ne sont pas rattachés aux projets dans cette étape (ils le sont depuis l'amendement du
  2026-09-30 ci-dessous).

## Conséquences

- Déplacer un dépôt d'un projet à un autre déplace aussitôt sa visibilité pour les titulaires des
  projets, dans les deux sens — l'entrée d'audit du déplacement le dit.
- Supprimer un projet détache ses dépôts (ils reviennent à « sans projet ») ; cela ne supprime aucun
  dépôt ni aucun problème. Supprimer une solution exige qu'elle soit vide.
- Les agrégats par projet et par solution (problèmes, scores, conformité, SBOM consolidé) se calculent
  sur les dépôts membres que le lecteur peut voir — un droit partiel voit un projet partiel, et le dit.

## Amendement (2026-09-30) — les images de conteneur rejoignent les projets

**Le manque.** Un produit, ce sont ses dépôts *et* les images construites à partir d'eux, et plusieurs
fonctions parlaient déjà des « cibles d'un projet » : un droit sur un projet, les filtres `project_id`
et `solution_id` du backlog, les chiffres de l'arbre, le déplacement d'un projet vers une autre
solution. Les images hors de tout projet, un titulaire voyait le code d'un produit et pas ce qui tourne
en production, et le backlog d'un projet laissait de côté les problèmes que portent ses images.

**La décision.**

- **Une image est rangée dans un projet au plus, comme un dépôt.** Une colonne facultative
  `t_container.project_id` (V59), avec une clé étrangère nommée `fk_container_project … on delete set
  null` et un index, écrite trois fois (`db/migration/{postgresql,mysql,sqlite}/`) puisqu'une clé
  étrangère est une structure qui diverge (décision 0027). Les images existantes commencent sans projet ;
  rien n'est déduit. L'entité mappe la colonne en lecture seule et deux mises à jour ciblées l'écrivent,
  pour la raison donnée pour les dépôts : l'enregistrement d'un formulaire lu avant un déplacement ne doit
  pas ramener l'image.
- **Les routes reprennent celles des dépôts** : `PUT` et `DELETE /api/v1/projects/{id}/containers/{containerId}`,
  administrateurs seulement, 204 ; une image que l'appelant ne voit pas reçoit le 404 d'une image absente
  (« Target not found. »), une image qui n'est pas dans ce projet un 404 à elle ; la ranger là où elle est
  n'enregistre rien.
- **Auditées sous `PROJECT_CONTAINERS_CHANGED`, une opération à part** plutôt que
  `PROJECT_REPOSITORIES_CHANGED` réutilisée : la ressource de l'entrée est l'identifiant de l'image, et un
  dépôt et une image peuvent porter le même numéro — sous l'opération des dépôts, « 42 » désignerait la
  mauvaise cible à qui filtre le journal. Elle signale `ACCESS_GRANT_CHANGED` au SIEM, comme sa voisine,
  et ses termes disent que la visibilité se déplace.
- **Un droit sur un projet se résout en ses dépôts et ses images**, à chaque requête, dans
  `VisibilityService`, comme avant : la `Visibility` reste un ensemble de cibles et chaque route qui filtre
  par elle filtre les images sans changement. Un lecteur titulaire d'un projet gagne donc ses images —
  c'est voulu —, en perd une dès qu'elle quitte le projet, et un déplacement entre projets la fait passer
  des titulaires de l'un à ceux de l'autre, sans qu'aucune ligne de droit ne bouge. La recherche lie mille
  projets à la fois.
- **L'arbre les liste** : chaque `ProjectNode` porte `containerCount` et `containers` (`id`, `name`), le
  groupe « sans projet » liste les images non rangées que le lecteur voit, et chaque `openIssues` —
  projet, solution, sans projet — compte les problèmes ouverts des images listées à côté de ceux des
  dépôts. `repositoryCount` reste un compte de dépôts ; `partial` est levé quand un dépôt **ou** une image
  est masqué.
- **Ce qui suit un projet suit ses images** : les filtres `project_id` et `solution_id` du backlog
  incluent leurs problèmes (chaque cible par sa propre colonne, écrite dans la requête en littéraux) ;
  déplacer un projet les emporte, puisque seul `t_container.project_id` le nomme ; supprimer un projet les
  ramène à « sans projet », explicitement, et l'entrée d'audit les compte ; une équipe titulaire d'un
  projet est notifiée des analyses de ses images comme de celles de ses dépôts.
- **Ce qui ne bouge pas dans ce lot, délibérément** : les **checklists**. Leurs mesures portent sur les
  dépôts du projet (`ProjectMembers.repositoryIds`), comme la garde qui ne sert une checklist qu'à un
  lecteur qui voit le projet entier. Un document de checklist signé énonce ce qui a été mesuré, et faire
  entrer les images dans le périmètre changerait ce dont une réponse déjà donnée répond sans que personne
  l'ait décidé. L'union des langages et les plugins activés pour un projet restent aussi à la forme des
  dépôts : une image ne porte pas de recensement de langages, et un plugin s'exécute sur une arborescence
  de sources.

**Point ouvert.** La plupart des règles de checklist ont la forme d'un dépôt (analyse statique,
couverture, tests, langages) ; l'analyse des dépendances et les seuils de problèmes sur les périmètres de
vulnérabilités pourraient utilement inclure les images. En décider change les mesures *et* la garde du
projet entier ensemble — un lecteur qui voit tous les dépôts et pas l'image serait alors refusé — et est
laissé à une décision propre.
