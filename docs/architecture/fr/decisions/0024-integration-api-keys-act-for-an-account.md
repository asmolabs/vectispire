# 0024 — Une clé API d'intégration agit pour un compte, sur les routes qui l'acceptent

**Date :** 2026-09-25 · **Statut :** acceptée · **Décideur :** Laurent Boucher

## Contexte

L'écran des clés API émettait des clés de portée `read`, `scan` et `export`, et aucune ne
s'authentifiait nulle part : le filtre bearer n'acceptait que la clé propre d'un agent. Le document
OpenAPI annonçait un schéma `X-API-Key`, et la documentation de la barrière CI disait d'utiliser une
clé API, alors que le script de la barrière envoyait une session. Les outils qui doivent appeler
Vectispire sans personne devant un navigateur — une chaîne CI, SonarQube, un script de rapport —
n'avaient aucun identifiant fait pour eux.

Un second fait a pesé : `@RequiresAccount` vérifie seulement que l'appelant est authentifié, et une
clé d'agent est authentifiée. Rien ne cantonnait un identifiant autre qu'une session aux routes qui
lui sont destinées ; une clé d'agent atteignant une route de compte y voyait une visibilité vide, ce
qui est une conséquence et non une règle.

## Décision

- **Une clé d'intégration agit pour le compte qui l'a émise.** Elle porte le rôle et la visibilité de
  ce compte, restreinte encore par la restriction de cibles facultative de la clé — restriction de
  nouveau appliquée. Une clé dont le compte est désactivé ou supprimé cesse de fonctionner.
- **Un identifiant autre qu'une session n'atteint que les routes qui le déclarent.** Une route accepte
  une clé d'intégration en portant `@AcceptsApiKey(portée)` ; une clé sans cette portée, ou sur une
  route sans le marqueur, est refusée (403 — la route existe pour son titulaire, et le dire ne révèle
  aucune cible). Les clés d'agent sont cantonnées de même aux routes marquées `@RequiresAgentKey`. Les
  marqueurs de rôle s'appliquent en plus : une clé ne dépasse jamais son compte.
- **Les portées sont des familles de routes :** `read` (problèmes, analyses, SBOM, conformité,
  verdicts de la barrière), `scan` (déclencher une analyse, évaluer la barrière), `export` (VEX, CSAF,
  SARIF, CycloneDX, rapports). Rien d'administratif n'accepte de clé. La portée `agent` n'est pas
  émise depuis cet écran : la clé d'un agent est créée avec l'agent.
- La clé se présente en `Authorization: Bearer <clé>` ou `X-API-Key: <clé>`. Elle est stockée hachée,
  retrouvée par son préfixe, expire quand on l'a voulu, se révoque en la supprimant, est limitée en
  débit par clé, et chaque écriture qu'elle fait est auditée au nom de son compte, la clé nommée à
  côté.

## Conséquences

- Une migration : `t_api_key.owner_user_id`. Les clés émises avant n'ont pas de titulaire et ne
  s'authentifient nulle part, comme avant ; elles sont signalées comme telles et doivent être
  réémises.
- Le cantonnement ferme aussi le trou de la clé d'agent décrit plus haut.
- Une clé est aussi puissante que son compte, dans ses portées : émettez les clés d'intégration depuis
  un compte dont le rôle et la visibilité conviennent à l'intégration, ou restreignez la clé à ses
  cibles.
