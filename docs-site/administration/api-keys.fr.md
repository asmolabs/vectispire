# Clés d'API

Émises depuis l'interface, pour des machines plutôt que pour des personnes. Une barrière CI
s'authentifie avec une clé ; un agent distant aussi.

## Portées

Une clé porte une portée, et la portée est toute l'histoire côté sécurité. La portée `agent`
est celle à comprendre : elle permet à un processus d'interroger la file de travaux et d'y
poster des résultats, et **rien d'autre** — en particulier, aucun accès à la base de données.

Donnez à une barrière CI une clé capable de demander un verdict. Elle n'a pas besoin d'une clé
capable d'enregistrer des cibles.

![Quatre clés : une sans restriction, une limitée à un dépôt, une clé d'agent jamais utilisée, et une expirée.](../assets/screens/fr/api-keys.png)

## Pas de restriction à une cible

Une clé ne peut pas être limitée à un dépôt ou à un conteneur : en émettre une est refusé avec
`400`. Ces clés étaient acceptées et listées avec le nom de leur cible, et ne restreignaient rien —
les seules clés qui s'authentifient sont celles des agents, émises sans restriction à la
déclaration de l'agent, et le protocole des agents ne lit aucune visibilité. Restreignez ce que les
personnes voient avec les [équipes](users-and-teams.md). Une clé émise restreinte avant ce
changement garde son libellé dans la liste et ne s'authentifie toujours nulle part.

## Affichée une seule fois

Une clé est affichée une fois, à sa création. Vectispire stocke ce dont il a besoin pour
vérifier une clé présentée, et ne peut pas vous en remontrer la valeur.

Mettez-la directement dans votre coffre à secrets. Si elle est perdue, révoquez-la et
émettez-en une autre — c'est une opération de deux minutes, alors qu'une clé collée dans une
fenêtre de discussion pour s'en épargner est une opération permanente.

## En-têtes d'authentification

| En-tête | Pour |
|---|---|
| `Authorization: Bearer …` | une session utilisateur (JWT) |
| `X-API-Key` | une clé d'API |
| `X-Agent-Key` | un agent distant |

## Révoquer

Révoquez une clé quand le pipeline qui l'utilisait est retiré, quand quelqu'un qui pouvait la
lire s'en va, ou quand vous n'êtes pas sûr. La révocation est immédiate, et chaque usage figure
dans le [journal d'audit](audit-log.md).

## En CI

```yaml
env:
  VECTISPIRE_API_KEY: ${{ secrets.VECTISPIRE_API_KEY }}
```

Jamais dans le dépôt, jamais dans la définition du job. Voir
[Barrière CI](../integrations/ci-gate.md).
