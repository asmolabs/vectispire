# Les licences de ce que Vectispire distribue

*English version: [`docs/en/LICENSES.md`](../en/LICENSES.md).*

Vectispire est distribué sous Apache-2.0 sous forme de deux jars, trois images de conteneur et
l'interface compilée dans le jar du plan de contrôle. Chacun embarque du code d'autrui, et cette page
dit comment on vérifie que leurs licences le permettent. [`NOTICE`](../../NOTICE) liste les composants.

## Ce qui est vérifié, et où

| Ce qui est livré | Lu depuis | Vérifié par |
|---|---|---|
| Les jars d'exécution dans `vectispire-core.jar` et `vectispire-agent.jar` | les SBOM que le job `sbom` produit avec Syft | `licences` (ci.yml) |
| Les paquets npm à partir desquels l'interface est construite | `package-lock.json`, dépendances de développement exclues | `licences` |
| Les paquets système des trois images | les SBOM des images qu'`images` vient de construire | `images` |
| `NOTICE` | chaque jar sous une autre licence qu'Apache-2.0 doit y être nommé | `licences` |

Les trois exécutent [`ci/licences/check.py`](../../ci/licences/check.py) contre
[`ci/licences/allowed.txt`](../../ci/licences/allowed.txt), qui contient deux sortes de lignes :

- les **licences** permises, chacune avec la raison pour laquelle elle peut être livrée dans une
  distribution Apache-2.0, et une portée : GPL et LGPL sont permises pour les paquets d'une image —
  des programmes distincts agrégés à côté du jar — et pour aucun jar ni aucun paquet npm ;
- les **composants** examinés un par un : métadonnées absentes (docker-java, JGit), ambiguës
  (double licence comme EPL-2.0 ou LGPL-2.1 pour Logback, enregistrée comme celle retenue) ou
  nommant une licence hors de la liste. Une telle ligne se porte garante des identifiants de licence
  que les métadonnées déclaraient quand elle a été lue, et de rien d'autre : une nouvelle version qui
  en déclare une autre échoue jusqu'à être relue.

Un composant sous une licence que personne n'a examinée échoue, et un composant sans licence aussi.
La réponse est une décision consignée dans ce fichier avec sa raison, ou une autre dépendance ; une
licence qui ne permet pas la distribution sous Apache-2.0 — GPL ou AGPL dans un jar ou l'interface,
SSPL, Commons Clause — n'y est jamais ajoutée. Une exécution qui n'a lu aucun composant échoue aussi.

## L'état en 1.0.0 (audit du 2026-10-30)

- **Jars** : 156 composants dans le plan de contrôle, 51 dans l'agent. Apache-2.0 pour la grande
  majorité ; MIT, BSD-2-Clause, BSD-3-Clause (EDL-1.0 compris), CC0 et EPL-2.0 pour le reste. EPL-2.0
  est un copyleft au niveau du fichier, dont les fichiers sont livrés sans modification, leur source
  chez leurs auteurs.
- **L'interface** : 74 paquets dans l'arbre de dépendances, MIT, ISC, Apache-2.0, BSD et 0BSD, et
  MPL-2.0 pour `lightningcss`, un outil de construction de Tailwind qui n'atteint pas le bundle. Les
  notices du bundle lui-même sont `static/licenses/3rdpartylicenses.txt`, écrit par `ng build`.
- **Images** : 44 paquets Alpine dans les images du plan de contrôle et de l'agent, 25 paquets Debian
  dans l'image distroless du plugin de rapport, dont des paquets GPL-2.0, GPL-3.0 et LGPL et le JRE
  (GPL-2.0 avec la Classpath Exception).

### À décider par le mainteneur

Rien de ce qui a été trouvé n'est incompatible avec une distribution sous Apache-2.0. Deux points sont
des décisions plutôt que des constats, et sont consignés plutôt que tranchés ici :

1. **MySQL Connector/J** est sous GPL-2.0 avec l'Universal FOSS Exception d'Oracle. `NOTICE` consigne
   déjà le raisonnement — `runtimeOnly`, atteint par JDBC, l'exception listant Apache-2.0 — et la
   liste ne permet cette licence que pour ce jar. À confirmer avant que le dépôt devienne public,
   puisque c'est la seule licence copyleft dans le jar ; le pilote PostgreSQL (BSD-2-Clause) est
   l'alternative qui supprimerait la question, et la 1.0 ne prend en charge que MySQL.
2. **La source des paquets GPL dans les images.** Distribuer une image distribue busybox, coreutils
   et le JRE sous forme binaire, et la GPL demande au distributeur de fournir leur source
   correspondante ou une offre écrite. `NOTICE` renvoie aux archives de source des distributions
   (aports d'Alpine, Debian, Adoptium) aux versions que portent les images. Savoir si ce renvoi
   suffit, ou si la release doit publier une archive de sources à côté des images, est une décision
   du mainteneur.
