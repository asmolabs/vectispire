# Inter, embarqué

## Pourquoi le fichier est ici plutôt qu'une URL

La feuille précédente était chargée depuis `fonts.googleapis.com`, et **le CSP de Zanshin
la refusait** : `style-src 'self' 'unsafe-inline'` (voir
`zanshin/api/security_headers.py`) n'autorise aucune feuille tierce. La police n'a donc
jamais été appliquée en production — l'interface tournait sur le repli système, avec la
géométrie voulue et la typographie d'un autre.

Élargir le CSP aurait été la correction facile et la mauvaise. Une console de sécurité qui
appelle un tiers à chaque chargement de page rend son inventaire de dépendances faux, fuite
l'adresse de chaque analyste vers ce tiers, et cesse de fonctionner sur un réseau isolé —
le réseau où ce genre d'outil est précisément déployé. `font-src 'self' data:` était déjà
là ; il ne manquait que le fichier.

## Pourquoi Inter et pas Lato

Deux raisons, une esthétique et une juridique.

**Les chiffres.** Inter porte de vrais chiffres tabulaires (`tnum`) et des zéros barrés
(`zero`). Zanshin est une application de colonnes de nombres — CVSS, EPSS, compteurs, dates.
Avec une police à chasse proportionnelle, `9.8` et `10.0` n'ont pas la même largeur et les
colonnes ondulent d'une ligne à l'autre.

**La licence.** SIL Open Font License 1.1 (`LICENSE.txt`) : redistribuable dans un dépôt
libre, ce qui est la situation de Zanshin. Elle demande de conserver le texte de licence et
de ne pas vendre la police seule — les deux sont satisfaits par la présence de ce
répertoire.

## Ce que contiennent les fichiers

Deux sous-ensembles Unicode d'une police *variable* (une seule graisse continue de 400 à
800, pas quatre fichiers) :

| Fichier | Plage | Poids |
|---|---|---|
| `inter-latin.woff2` | latin | 48 Ko |
| `inter-latin-ext.woff2` | latin étendu | 85 Ko |

Le second couvre les caractères que le premier n'a pas ; le navigateur ne télécharge que
celui dont il a besoin, grâce aux `unicode-range` déclarés dans `assets/theme.css`. Les
autres sous-ensembles amont (cyrillique, grec, vietnamien) ne sont pas embarqués : cette
interface est en français.

Origine : `https://fonts.gstatic.com/s/inter/v20/`, sous-ensembles servis par Google Fonts
pour `family=Inter:wght@400..800`. Pour les mettre à jour, récupérer la feuille CSS avec un
agent utilisateur de navigateur, y lire les URL `latin` et `latin-ext`, et remplacer les
deux fichiers — les `unicode-range` de `theme.css` sont à revérifier à cette occasion.
