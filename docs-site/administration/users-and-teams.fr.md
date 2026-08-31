# Utilisateurs et équipes

## Comptes

Il n'y a **aucune page d'inscription**. Un administrateur crée chaque compte.

Le premier vient des variables d'amorçage au premier démarrage, et seulement quand la table des
utilisateurs est vide — voir
[Installation](../getting-started/installation.md#the-first-account). Ensuite, les deux
variables sont ignorées.

Un compte porte un indicateur `is_active`. Un compte désactivé ne peut pas se connecter, et son
historique reste intact — ce qui est tout l'intérêt de désactiver plutôt que de supprimer.

## Rôles

Les rôles décident de ce qu'une personne peut faire. SUPERUSER est le rôle qui peut administrer
les autres comptes, et c'est celui qu'il faut distribuer avec parcimonie : le journal d'audit
n'a de sens qu'à proportion du nombre de gens capables de changer ce qu'il enregistre.

## Équipes et visibilité

Les équipes décident de ce qu'une personne peut **voir**. Les cibles appartiennent à des
équipes, et chaque liste, chaque export et chaque série de tendance est restreint par la
visibilité du lecteur — la série « backlog dans le temps » du tableau de bord comprise.

Cette restriction est uniforme à dessein. Une vue qui l'ignorerait discrètement laisserait
quelqu'un déduire la forme d'un parc qu'il ne peut pas ouvrir.

## Cibles sans étiquette

Une cible n'appartenant à aucune équipe n'est visible que de ceux qui voient tout. Il vaut la
peine de les chercher après un import en masse : une cible sans propriétaire est une cible dont
personne n'est responsable, et ses scans continuent de compter dans le tableau de bord de
personne.

## Voir aussi

- [Authentification unique](sso.md) — déléguer l'authentification sans déléguer l'autorisation.
- [Clés d'API](api-keys.md) — pour des machines plutôt que pour des personnes.
- [Journal d'audit](audit-log.md) — ce qui est enregistré de tout cela.
