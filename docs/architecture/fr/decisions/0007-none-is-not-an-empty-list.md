# 0007 — Un analyseur qui échoue renvoie `None`, jamais une liste vide `[]`

**Date :** 2026-08-07 · **Statut :** accepté

## Contexte

Un analyseur qui plante ou expire ne produit aucun constat. Confondre une étape non exécutée avec une liste vide `[]` résoudrait à tort tout le backlog d'issues existantes.

## Décision

- `[]` signifie *"analysé, aucune anomalie trouvée"*.
- `None` (`Optional.empty()`) signifie *"l'analyse n'a pas pu s'exécuter"*.

Les étapes non exécutées ne modifient pas l'état du backlog.
