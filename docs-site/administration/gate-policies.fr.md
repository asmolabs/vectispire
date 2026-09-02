# Politiques de barrière

**Administration → Politiques de barrière.** Une politique globale, redéfinie par cible là où
c'est nécessaire.

!!! info "Qui lit, qui modifie"
    Lire une politique est ouvert aux administrateurs, au CISO et au rôle **Auditeur**. En changer
    une — la politique globale, une redéfinition par cible, une suppression — demande un
    administrateur ou le CISO. Un auditeur voit exactement ce que la barrière impose, et ne peut
    pas l'adoucir.

## Stockée et versionnée

Une politique est stockée et porte une version, avec un **« pourquoi » conservé avec la
version**.

Le champ de justification n'est pas décoratif. Six mois plus tard, « seuil : élevé » est un
nombre que personne ne peut défendre ; « seuil : élevé, parce que les critiques dans les
dépendances transitives faisaient échouer toutes les constructions et que les équipes avaient
commencé à contourner la barrière » est une décision que quelqu'un peut réexaminer.

Les règles arrivaient autrefois dans le corps de la requête CI, ce qui signifiait que chaque
projet posait sa propre barre et que rien n'était comparable. Désormais, une requête ne peut
que **durcir** la politique stockée, jamais l'assouplir.

## Le défaut intégré

Là où rien n'est stocké, un défaut intégré s'applique. L'écran le montre **à côté** de ce que
vous avez stocké, pour que « non posé » et « posé à la même valeur » ne se ressemblent pas :
ils se comportent identiquement aujourd'hui et divergent à l'instant où le défaut change.

## Ce qu'une politique règle

| | |
|---|---|
| **Faire échouer la construction à** | le seuil de gravité |
| **Corrigeables seulement** | ignorer les constats sans correctif publié |
| **Activement exploitées** | comment les entrées KEV sont traitées |
| **Constats triés** | si une issue triée compte encore |
| **Violations de licence** | échouer sur une licence bloquée |
| **Revue par modèle** | si un verdict de revue IA participe |

## Redéfinitions

Par cible. Servez-vous-en pour les cas que la politique globale ne peut réellement pas
exprimer — un service de niveau 1 tenu à une barre plus stricte, une cible héritée qu'on
remonte sur un trimestre.

Gardez-les peu nombreuses. Un parc où chaque cible a sa propre politique n'a pas de politique,
et la comparaison pour laquelle la barre globale existait redevient impossible.

## « Corrigeables seulement », en pratique

L'activer est généralement juste au début. Faire échouer des constructions sur des constats
sans correctif publié demande aux équipes quelque chose que personne ne peut faire, et une
barrière qu'on ne peut pas satisfaire est une barrière qu'on contourne.

Désactivez-le une fois le backlog corrigeable maîtrisé — à ce moment-là, des critiques
incorrigeables deviennent une vraie décision sur l'opportunité de livrer, plutôt que du bruit.

## Voir aussi

[Barrière CI](../integrations/ci-gate.md) · [Tickets](../integrations/ticketing.md) — qui
utilise la même politique, délibérément.
