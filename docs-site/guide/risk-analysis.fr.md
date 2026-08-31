# Analyse de risque

Quatre vues qui répondent à « qu'est-ce que cela met réellement en risque », chacune sous un
angle différent.

## EPSS

La page **EPSS** classe le parc par probabilité d'exploitation plutôt que par CVSS. Chaque
vulnérabilité porte son score, et l'écart entre les deux nombres est tout le propos : le CVSS
dit à quel point ce serait grave, l'EPSS dit à quel point quelqu'un est susceptible d'essayer.

Le statut **KEV** de la CISA se tient à côté — non pas une prédiction, mais un constat que
l'exploitation a été observée. Une entrée KEV passe devant un EPSS élevé, qui passe devant un
CVSS élevé.

## Chemins d'attaque

La visionneuse de chemins d'attaque enchaîne les constats en itinéraires plutôt que de les
énumérer un à un : un composant exposé, une vulnérabilité qui l'atteint, un identifiant commité
à côté. Un itinéraire fait de trois constats moyens peut compter davantage que n'importe quel
constat élevé sur la même cible, et aucune liste triée par gravité ne le montrera jamais.

## Rayon d'impact

Le rayon d'impact travaille depuis un composant vers l'extérieur : si ce paquet est compromis,
qu'atteint-il ? Les graphes de dépendances multi-niveaux sont cartographiés sur chaque dépôt et
chaque image enregistrés, si bien que la réponse couvre le parc plutôt qu'un projet.

Lisez-le avec le [niveau de criticité métier](repositories.md#business-criticality-tiers). Un
large rayon d'impact qui ne touche que des outils internes de niveau 3, ce n'est pas le même
lundi qu'un rayon qui touche un chemin de paiement de niveau 1.

## Surface d'attaque et OWASP

La **surface d'attaque** rassemble ce qui est joignable depuis l'extérieur — les points
d'entrée qu'un constat doit franchir pour compter.

**OWASP** regroupe le backlog par catégories OWASP, qui sont le vocabulaire que la plupart des
revues de sécurité et la plupart des auditeurs parlent déjà. C'est une reformulation des mêmes
constats, pas un scan séparé.

## Bien s'en servir

Aucune de ces vues ne produit de nouveaux constats. Elles reclassent ceux que vous avez selon
une question à laquelle la gravité ne répond pas. Servez-vous-en quand le backlog est trop long
pour être traité dans l'ordre — ce qui, sur un parc réel, est toujours le cas.
