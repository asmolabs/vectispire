# Authentification unique

**OpenID Connect** facultatif, testé contre Keycloak.

## Ce que le fournisseur décide, et ce qu'il ne décide pas

Le fournisseur répond à exactement une question : *qui est-ce ?*

Vectispire émet toujours sa propre session. Les règles de visibilité, la piste d'audit, les
durées de session et les clés d'API continuent de fonctionner sans changement, parce
qu'aucune d'elles n'a été déléguée.

## Aucun compte n'est créé à la connexion

C'est la partie qui mérite deux lectures.

Un administrateur crée le compte d'abord, et **le rôle reste la décision de Vectispire**.
Quiconque peut obtenir un jeton depuis un royaume partagé ne doit pas obtenir par là même une
vue de lecteur sur toutes les cibles — et dans un royaume partagé, cela représente beaucoup
plus de monde que ceux que vous vouliez laisser entrer.

## Lier une identité

La **première** connexion lie le compte dont le nom d'utilisateur correspond à la revendication.

Toutes les suivantes s'appuient sur le **sujet** du fournisseur, pas sur le nom d'utilisateur.
Un nom d'utilisateur n'est pas stable sur la vie d'une personne : on se marie, on change
d'équipe, un import RH vous renomme. Le sujet, lui, l'est.

## Configuration

```bash
VECTISPIRE_OIDC_ISSUER=https://keycloak.internal/realms/company
```

Plus les identifiants client que votre fournisseur émet.

### Désactiver la connexion par mot de passe

```bash
VECTISPIRE_PASSWORD_LOGIN=false
```

L'authentification est alors entièrement déléguée, et le second facteur est celui du royaume.

Ce réglage est **ignoré, bruyamment**, quand aucun `VECTISPIRE_OIDC_ISSUER` n'est posé.
L'honorer ne laisserait aucune entrée du tout, et un outil de sécurité qui verrouille dehors
ses administrateurs n'est pas devenu plus sûr.

## Voir aussi

[Utilisateurs et équipes](users-and-teams.md) · [Configuration](../reference/configuration.md)
