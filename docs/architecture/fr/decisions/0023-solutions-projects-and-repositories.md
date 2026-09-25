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
- Les conteneurs ne sont pas rattachés aux projets dans cette étape.

## Conséquences

- Déplacer un dépôt d'un projet à un autre déplace aussitôt sa visibilité pour les titulaires des
  projets, dans les deux sens — l'entrée d'audit du déplacement le dit.
- Supprimer un projet détache ses dépôts (ils reviennent à « sans projet ») ; cela ne supprime aucun
  dépôt ni aucun problème. Supprimer une solution exige qu'elle soit vide.
- Les agrégats par projet et par solution (problèmes, scores, conformité, SBOM consolidé) se calculent
  sur les dépôts membres que le lecteur peut voir — un droit partiel voit un projet partiel, et le dit.
