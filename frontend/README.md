# Zanshin — interface Angular

L'interface de Zanshin, en cours de portage depuis Reflex. Voir
[`docs/migration-nestjs-angular.md`](../docs/migration-nestjs-angular.md) pour le plan
d'ensemble et l'état d'avancement.

```bash
npm run start:frontend    # depuis la racine, sert sur http://localhost:4200
npm run build             # les deux workspaces
npm test                  # vérification des ressources + suite Vitest
```

Le serveur de développement relaie `/api` vers `http://localhost:3000` (voir
`proxy.conf.json`), où écoute le backend NestJS.

## La pile, et pourquoi

**Angular 21.** Imposé par Optimus UI, dont les dépendances de pair sont en `^21.0.0`.

**Optimus UI** (`@openng/optimus-ui`) plutôt que PrimeNG. PrimeTek a archivé le dépôt
PrimeNG et basculé la v22 en licence commerciale ; Optimus est le fork communautaire de
la v21, la dernière version MIT. Les sous-chemins d'import sont identiques
(`@openng/optimus-ui/table` là où l'on écrivait `primeng/table`), ce qui rend la
documentation PrimeNG v21 directement utilisable.

Deux renommages à connaître, hérités de ce fork :

| PrimeNG | Optimus |
|---|---|
| `PrimeNG` (service de configuration) | `Optimus` |
| `providePrimeNG()` | `provideOptimus()` |

**Sakai** (MIT, PrimeTek) pour la coquille : barre supérieure, barre latérale, thème
sombre, configurateur d'apparence. `LICENSE.md` est celle du template et doit y rester.

Deux choses à savoir si vous reprenez le template à la source :

- `src/assets` est un **sous-module git** (`cetincakiroglu/sakai-assets`). Un clone
  superficiel ne le récupère pas, et l'on croit alors le dépôt cassé — `angular.json`
  référence des feuilles de style absentes. Ici les assets sont copiés en dur, pas
  montés en sous-module.
- Les pages de démonstration (`uikit`, `crud`, `landing`, `documentation`…) ont été
  supprimées. Seuls la coquille, l'authentification et les pages d'erreur sont conservés.

**`primeicons` est épinglé en `7.0.0`**, exactement. La 8.0.0 a suivi PrimeNG sous
licence propriétaire — c'est-à-dire précisément ce que le passage à Optimus visait à
éviter. La contrainte est un `=` déguisé : ne la relâchez pas sans lire la licence.

## Vérification des ressources

`npm test` commence par `scripts/check-assets.mjs`, qui refuse toute référence à un
domaine tiers dans `index.html` et `styles.scss`, et vérifie que les polices déclarées
existent réellement et sont de vrais `woff2`.

Ce n'est pas du zèle. La politique de sécurité de contenu de Zanshin refuse les
feuilles de style tierces, et Sakai chargeait Lato depuis un CDN. Une telle référence
ne casse rien de visible : la requête est bloquée, la page retombe sur la police
système, et rien ne le signale. C'est ce qui est arrivé à la version Reflex, dont la
typographie n'a jamais atteint la production — il a fallu mesurer dans le navigateur
pour le découvrir. Inter est donc servi depuis `public/fonts/`, licence OFL comprise.
