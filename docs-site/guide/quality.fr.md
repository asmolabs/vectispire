# Qualité du code

Semgrep produit deux sortes de constats, et Vectispire les tient à part exprès.

**Les constats de sécurité** passent la barrière comme n'importe quelle vulnérabilité : ils
comptent pour une politique et ils peuvent faire échouer une construction.

**Les constats de qualité** sont visibles dans le backlog et **ne peuvent jamais faire échouer
une barrière CI**. Non par configuration — par construction.

La raison vaut d'être dite. Une barrière qui peut échouer sur du style est une barrière que les
équipes apprennent à contourner, et dès que le contournement devient routinier, la moitié
sécurité cesse elle aussi de fonctionner. Le backlog de qualité est là pour être lu et traité,
pas pour bloquer une livraison.

## La section Qualité

Classée de trois façons, parce que la question utile diffère selon qui la pose :

- **Par règle** — quelle règle se déclenche le plus dans le parc. C'est celle qui trouve un
  problème systémique méritant une transformation automatisée plutôt que cent corrections
  individuelles.
- **Par fichier** — les fichiers qui concentrent la dette.
- **Par dépôt** — où envoyer l'effort.

## L'activer

Semgrep est **désactivé par défaut** et analyse le code source directement — une requête SQL
concaténée, une commande passée à un shell, un certificat TLS non vérifié. Aucun autre scanner
ici ne voit quoi que ce soit de tout cela. Il s'exécute réseau désactivé, comme tous les
autres.

**Vectispire n'embarque qu'une seule règle.** C'est une contrainte de licence et non un oubli :
les jeux de règles publics ne sont pas redistribuables. La couverture réelle vient d'un jeu de
règles que vous installez vous-même.

[Installer un jeu de règles Semgrep →](../administration/rule-sets.md)
