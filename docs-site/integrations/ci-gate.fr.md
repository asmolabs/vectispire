# Barrière CI

La barrière répond à une question posée par votre pipeline : **cette construction doit-elle
échouer ?**

## La version courte

```bash
curl -sSL https://raw.githubusercontent.com/asmolabs/vectispire/main/ci/vectispire-gate.sh | sh
```

Ou utilisez les intégrations livrées plutôt que d'écrire la requête à la main :

- [`ci/vectispire-gate.sh`](https://github.com/asmolabs/vectispire/blob/main/ci/vectispire-gate.sh) — un script shell pour n'importe quel exécuteur ;
- [`ci/github-action/action.yml`](https://github.com/asmolabs/vectispire/blob/main/ci/github-action/action.yml) — une action composite GitHub ;
- [`ci/gitlab/vectispire-gate.gitlab-ci.yml`](https://github.com/asmolabs/vectispire/blob/main/ci/gitlab/vectispire-gate.gitlab-ci.yml) — un modèle GitLab.

Les trois demandent `VECTISPIRE_API_KEY` dans l'environnement du job, issue d'une
[clé d'API](../administration/api-keys.md) avec la bonne portée.

## Le verdict nomme sa politique

La réponse dit quelle politique a été appliquée. Cela compte quand une construction échoue et
que son auteur veut savoir à quelle barre il a été tenu — « la politique globale, version 4 »
est une réponse ; « échec » n'en est pas une.

## Les politiques sont stockées, pas envoyées

**Un objet `policy` dans la requête ne peut que *durcir* ce qui s'applique, jamais l'assouplir.**

Cela n'a pas toujours été le cas. Les règles arrivaient autrefois dans le corps de la requête,
ce qui signifiait que chaque projet décidait de sa propre barre, donc que la barrière ne
mesurait rien de comparable à l'échelle du parc. Désormais, la politique appliquée est une
politique **stockée et versionnée** — globale, ou redéfinie par cible — écrite dans
**Administration → Politiques de barrière**. Une requête peut être plus stricte qu'elle. Elle
ne peut pas être plus laxiste.

Là où rien n'est stocké, le défaut intégré s'applique. L'écran montre ce défaut à côté de ce
qui est stocké, pour que « non posé » et « posé à la même valeur » ne se ressemblent pas.

[Configurer les politiques →](../administration/gate-policies.md)

## Ce qu'une politique peut prendre en compte

| | |
|---|---|
| **Seuil** | la gravité à partir de laquelle la construction échoue |
| **Corrigeables seulement** | ignorer ce dont aucun correctif n'est publié — on ne peut pas demander à une équipe de corriger ce que l'amont n'a pas corrigé |
| **Activement exploitées** | traiter les entrées KEV différemment du reste |
| **Constats triés** | si une issue triée compte encore |
| **Violations de licence** | échouer sur une licence bloquée |
| **Revue par modèle** | si un verdict de revue IA participe |

## La qualité ne fait jamais échouer une construction

Les constats de qualité Semgrep ne peuvent pas faire échouer une barrière, par construction
plutôt que par configuration. Voir [Qualité du code](../guide/quality.md) pour comprendre
pourquoi cette frontière est portante.

## Où placer la barrière

Après le scan et avant le déploiement. Deux modes d'échec à éviter :

**Barrer sur un scan périmé.** Un verdict sur le commit de la semaine dernière ne dit rien de
celui-ci. Déclenchez le scan dans le pipeline, puis barrez dessus.

**Barrer sur une cible jamais analysée.** Un backlog vide passe toutes les politiques. Voir
[Lire les résultats](../getting-started/reading-results.md#two-states-with-an-empty-backlog).

## Annoter aussi la demande de fusion

Une barrière est binaire et arrive à la fin. Exportez du
[SARIF](../guide/exports.md#sarif-210) à côté, pour que les constats atterrissent sur le
différentiel, là où ils se corrigent au lieu de se trier.
