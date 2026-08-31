# Images de conteneur

Une image de conteneur est une cible de scan au même titre qu'un dépôt, enregistrée dans
**Conteneurs** avec sa référence — registre, nom, et tag ou empreinte.

Préférez une empreinte quand vous le pouvez. Un tag est mutable : un verdict enregistré contre
`monapp:latest` est un verdict sur ce que `latest` désignait au moment du scan, ce qui n'est
pas un fait sur lequel quiconque peut agir une semaine plus tard.

## Ce qui est contrôlé

L'image est cataloguée par Syft et rapprochée par Grype exactement comme un dépôt : mêmes
lignes `Finding`, même enrichissement EPSS et KEV, même évaluation de licences, même
réconciliation d'issues.

Un contrôle est propre aux images : le statut de **fin de support** de la distribution sur
laquelle l'image est construite, lu depuis le catalogue endoflife.date. Il vaut la peine de
dire pourquoi il compte, parce qu'il ne porte aucune CVE. Une image de base sortie de son
support de sécurité n'a aucun problème *actuel* que vous puissiez montrer du doigt ; elle a la
garantie que rien ne sera corrigé pour le *prochain*.

La couverture y est délibérément limitée aux produits — langages, exécutions, cadriciels,
distributions — plutôt qu'à chaque bibliothèque du catalogue.

## Identifiants de registre

Les registres privés demandent des identifiants. Ils sont stockés chiffrés avec la même
`ENCRYPTION_KEY` que les clés de déploiement, sous le même refus de stocker quoi que ce soit
avant que cette clé existe.

## Scan et récurrence

Identiques aux dépôts : à la demande, ou avec un intervalle ou une expression cron,
l'expression l'emportant quand les deux sont posés. Voir
[Dépôts](repositories.md#recurrence).

## Dérive du SBOM entre deux versions

Comparer deux images de la même application répond à la question qu'un scan isolé ne peut pas
poser : qu'est-ce que cette version a changé ? La visionneuse de **différentiel de SBOM** montre
les paquets ajoutés et retirés, les migrations de licence — une dépendance permissive devenue
copyleft GPL ou AGPL entre deux tags est exactement le genre de changement que personne ne
remarque dans un différentiel de fichier de verrouillage — et l'impact net en CVE.

Voir [Inventaire et licences](inventory-and-licenses.md).
