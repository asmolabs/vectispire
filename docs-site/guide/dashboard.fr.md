# Tableau de bord

La navigation est groupée en deux, et cette séparation est une affirmation sur ce que chaque
moitié peut faire à une construction.

**Sécurité** porte le verdict de barrière par cible, le backlog des issues, les dépôts et les
conteneurs. Tout ce qui est ici peut faire échouer une construction.

**Qualité** classe le backlog de qualité du code par règle, par fichier et par dépôt, et dit
clairement que rien de tout cela ne peut faire échouer une construction. Voir
[Qualité du code](quality.md).

![Le tableau de bord : l'encours et les mouvements quotidiens sur deux graphiques empilés, les cibles en échec nommées en dessous.](../assets/screens/fr/dashboard.png)

## La vue d'ensemble Sécurité

Par cible : le verdict de barrière, le backlog courant par gravité, et la date du dernier scan.
Les chiffres par gravité écartent les constats triés non affecté ou corrigé, comme tout chiffre de
risque ; chacun ouvre la liste des constats avec le même filtre, pour que le compte et la liste
concordent.
Le verdict est calculé depuis que les politiques de barrière existent ; cet écran est l'endroit
où il est enfin montré.

Deux états sont nommés ici et nulle part ailleurs : une cible **jamais analysée**, et une cible
dont le **dernier scan a échoué**. Toutes deux portent un backlog vide, et un backlog vide
passe toutes les politiques. Un tableau de bord qui n'afficherait que les chiffres montrerait
ces deux-là en vert.

![La vue d'ensemble Sécurité : un verdict par cible, et le bandeau qui nomme les cibles qu'aucun scan n'a encore observées.](../assets/screens/fr/security-overview.png)

## Backlog dans le temps

Les chiffres ci-dessus sont des instantanés. Ils répondent à « combien » et jamais à « mieux ou
moins bien que le mois dernier ». La série, elle, y répond : backlog courant jour par jour, ce
qui est apparu face à ce qui a été résolu, et le délai moyen de résolution.

Le MTTR est affiché **absent** plutôt que zéro pour une période où rien n'a été résolu. Zéro se
lirait comme « corrigé le jour de son apparition », soit l'inverse de ce qui s'est passé.

La série est restreinte par votre visibilité, comme toutes les autres vues — voir
[Utilisateurs et équipes](../administration/users-and-teams.md).

## Note de posture de sécurité

Le classement de maturité donne à chaque dépôt et conteneur **la note de son scorecard**, de A+ à F,
à côté de son niveau de criticité métier. Le niveau est ce que vous posez à l'enregistrement du
dépôt ; la note est calculée depuis le backlog. Un service de niveau 1 avec une mauvaise note est la
première ligne à lire sur cette page.

**Une cible, une note.** Le score et la note d'une ligne sont ceux de la fiche scorecard de la cible et
de sa pastille README, calculés par la même règle — vulnérabilités exploitées, critiques et hautes,
licences non autorisées, et cinq points pour un scan terminé — décrite dans
[Comment la note du scorecard est calculée](repositories.md#comment-la-note-du-scorecard-est-calculee).
Les problèmes triés **non affecté** ou **corrigé** sont écartés, comme sur le scorecard et à la
barrière ; un problème dont l'exclusion est en attente d'approbation compte toujours. Les moyennes et
les basses sont affichées dans leurs colonnes et ne pèsent pas sur le score, comme sur le scorecard.

**Quelles cibles sont listées.** Toute cible que vous voyez qui porte un problème ouvert ou un scan
terminé, et celles dont tous les problèmes sont clos. Une cible scannée sans constat est listée à 100,
A+. Une cible sans scan terminé — ses constats viennent d'un seul import SARIF — est classée en dernier
comme *Aucune donnée*, sans score ; ses comptes restent. Une cible enregistrée et jamais scannée, sans
aucun problème, n'est pas listée.

L'échelle sature par le bas, comme celle du scorecard : à partir de vingt-sept hautes ouvertes, ou de
quatre critiques exploitées, une cible lit 0, F, quoi qu'elle porte d'autre. Lisez les
compteurs à côté de la lettre.
