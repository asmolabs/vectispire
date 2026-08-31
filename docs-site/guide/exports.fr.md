# Exports

Ce qui fait sortir un constat du tableau de bord pour le mettre sous les yeux de la personne
qui peut agir dessus.

## SARIF 2.1.0 {#sarif-210}

Pour GitHub code scanning, GitLab et Azure DevOps.

C'est l'export qui compte le plus en pratique, parce qu'il place le constat **sur la demande de
fusion qui l'a introduit** plutôt que sur un tableau de bord que quelqu'un consulte le jeudi.
Un constat annoté sur le différentiel se corrige ; le même constat dans une liste se trie.

## OpenVEX

Un document VEX construit depuis vos décisions de triage — ce que vous avez évalué comme non
affecté, et pourquoi.

Remettez-le à quiconque consomme votre SBOM. Sans lui, cette personne re-dérive votre backlog
entier depuis votre liste de dépendances et arrive à des conclusions que vous aviez déjà
instruites et écartées.

## CSV

Les issues en fichier plat, pour l'analyse que quelqu'un veut mener dans son propre outil.

## SBOM

Le SBOM exactement tel que le catalogueur l'a produit, non modifié.

Il vaut la peine de dire pourquoi il n'est pas remis en forme : un SBOM est une preuve, et une
preuve qui a subi une transformation est aussi une preuve sur la transformation.

## Des documents écrits pour des gens

Deux rapports PDF, écrits pour être lus plutôt qu'analysés par une machine :

- la **posture** d'une cible — où elle en est aujourd'hui ;
- son **historique de détection et de triage** — ce qui a été trouvé, et ce qui en a été
  décidé.

Voir [Historique et preuves](history.md).

## Paquet de preuves de conformité

Un ZIP signé cryptographiquement, couvert sous [Conformité](compliance.md).

## Personnalisation

Les exports et les rapports portent le nom de votre instance là où `VECTISPIRE_BRAND_NAME` est
posé — en-tête, PDF, sorties SARIF, VEX et CSAF. Voir
[Configuration](../reference/configuration.md).
