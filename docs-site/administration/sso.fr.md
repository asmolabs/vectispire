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

Cette première liaison fait confiance à une revendication, et une revendication est ce que le realm
laisse chacun écrire. Elle obéit donc à quatre règles :

- **Le nom doit être celui du compte, accent compris.** Seule la casse est pardonnée. La collation
  par défaut de MySQL trouve `admin` pour `ádmin` ; c'est une autre identité, et elle est refusée.
- **Une adresse e-mail ne sert que si le fournisseur l'a vérifiée** (`email_verified`), et seulement
  quand aucun `preferred_username` n'est venu.
- **Un compte privilégié n'est pas lié par son nom** — tout rôle sauf USER : SUPERUSER, ADMIN, CISO,
  AUDITOR et SECURITY_CHAMPION, puisque chacun administre, gouverne, lit la sécurité de tout le parc
  ou approuve le triage. Dans un realm ouvert à l'inscription, n'importe qui peut s'enregistrer
  comme `admin`. Liez ces comptes par
  [SCIM](#provisioning-from-the-directory-scim), qui prend le sujet chez le fournisseur, ou — pour un
  realm où personne ne choisit son nom — autorisez-le avec
  `VECTISPIRE_OIDC_LINK_PRIVILEGED_ACCOUNTS=true`. Le Keycloak du profil compose `sso` se connecte en
  `admin` : son `.env.oidc.example` le règle.
- **Un compte doté d'un second facteur local n'est jamais lié par son nom**, quel que soit le
  réglage ci-dessus. Une connexion unique contourne le TOTP local — le fournisseur possède le second
  facteur — et le lier sur une revendication échangerait le facteur que son titulaire a enrôlé contre
  un nom que quelqu'un d'autre a pu écrire. Son titulaire se connecte avec mot de passe et code, ou
  le fait lier par SCIM.

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

## Provisionnement depuis l'annuaire (SCIM) {#provisioning-from-the-directory-scim}

Un fournisseur d'identité peut créer, modifier, désactiver et supprimer des comptes par SCIM 2.0
(`/scim/v2/Users`, `/scim/v2/Groups`), authentifié par le jeton SCIM. Ce jeton vit dans la
configuration du fournisseur ; ce qu'il peut faire est donc volontairement borné :

- **Les comptes administratifs ne relèvent pas de l'annuaire.** Remplacer, modifier ou supprimer un
  administrateur ou un super-administrateur répond `403` ; ils s'administrent dans Vectispire.
- **L'annuaire n'accorde que les rôles bornés — User et Security Champion.** Une valeur `roles` à
  `ADMIN`, `SUPERUSER`, `CISO` ou `AUDITOR` — un rôle qui administre ou voit tout le parc — répond
  `400` : ces rôles s'accordent dans Vectispire, par ses administrateurs. Aucun réglage ne l'élargit :
  un annuaire qui déciderait de ces rôles, c'est un jeton d'annuaire qui détient le parc. Renvoyer le
  rôle qu'un compte a déjà n'est pas une attribution, et est accepté.
- **Un remplacement sans `roles` laisse le rôle tel quel** — il ne rétrograde plus en Utilisateur.
- **`externalId` n'est lié qu'une fois.** Le changer sur un compte qui en a déjà un répond `400` :
  un nouveau sujet, c'est un nouveau compte.
- **Un changement de rôle ferme les sessions du compte**, comme une désactivation.

## Le second facteur relève du fournisseur

Une connexion SSO **saute le TOTP de Vectispire**, délibérément : l'authentification est déléguée, et
le second facteur avec elle — un code local en plus ferait concourir deux facteurs. Ce que le
fournisseur a fait n'est plus une supposition pour autant. Chaque connexion fédérée inscrit dans le
journal d'audit ce que le jeton atteste — des valeurs `amr` de la RFC 8176 comme `otp` ou `hwk`, ou un
niveau `acr` — ou qu'il n'atteste rien.

Une fois que votre fournisseur envoie cette information (Keycloak : ajoutez au client un mapper
*Authentication Method Reference*, ou configurez un niveau `acr`), posez
`VECTISPIRE_OIDC_REQUIRE_MFA=true` : une connexion qui n'atteste aucun second facteur est alors
refusée, avec un message qui dit pourquoi. Les valeurs qui comptent sont `VECTISPIRE_OIDC_MFA_AMR` et
`VECTISPIRE_OIDC_MFA_ACR` — voir [Configuration](../reference/configuration.fr.md).

## Configuration

```bash
VECTISPIRE_OIDC_ISSUER=https://keycloak.internal/realms/company
```

Plus les identifiants client que votre fournisseur émet. Avec la composition livrée, l'issuer,
l'identifiant du client et le nom affiché vont dans `.env.oidc`, et le **secret du client dans
`.env`** (`VECTISPIRE_OIDC_CLIENT_SECRET`) : `.env.oidc` devient l'environnement du conteneur, que
`docker inspect` montre à tout client du démon, tandis que le secret de `.env` arrive dans le
conteneur en fichier sous `/run/secrets/`.

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
