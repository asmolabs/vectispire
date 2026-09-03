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

## Les groupes deviennent des équipes, et en sortir les retire

Quand le jeton porte une revendication `groups`, chaque valeur est appariée à un **nom d'équipe**
et le compte rejoint celles qui correspondent.

Il **quitte** aussi celles qui ne sont plus revendiquées — mais uniquement celles que le
fournisseur avait accordées. Une équipe attribuée à la main par un administrateur, ou provisionnée
par SCIM, n'est jamais retirée par une connexion : chaque canal réconcilie ses propres
appartenances, si bien que deux annuaires ne peuvent pas défaire le travail l'un de l'autre et
qu'une connexion ne peut pas effacer en silence une décision délibérée.

Une revendication **vide ou absente ne retire rien**. Un mapper oublié est une panne de
configuration, pas une déclaration que cette personne n'appartient à aucune équipe — révoquer sur
cette base couperait tout le monde au premier réglage manqué.

## Configuration

```bash
VECTISPIRE_OIDC_ISSUER=https://keycloak.internal/realms/company
```

Plus les identifiants client que votre fournisseur émet.

### Ce que le rapport de conformité en dit

Les contrôles de journalisation sont **plafonnés tant que l'authentification est plus faible que
le rapport ne le laisse croire**. Aucun fournisseur les plafonne à 65 % : la chaîne d'empreintes
prouve qu'une entrée n'a pas été altérée, elle ne prouve pas que le nom qu'elle porte est celui de
la personne qui a agi. Un fournisseur *à côté* d'un mot de passe ouvert les plafonne à 85 % — le
second facteur du realm se contourne par l'autre porte.

C'est délibérément un chiffre et non un refus. PCI DSS et SOC 2 exigent tous deux un second
facteur, et un rapport qui les déclarait conformes pendant que Vectispire acceptait un mot de passe
seul rendait à l'évaluateur sa propre diligence sous forme de conclusion.

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
