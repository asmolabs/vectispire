# Le realm livré avec le profil `sso`

```sh
docker compose --profile sso up
cp .env.oidc.example .env.oidc      # puis relancer le plan de contrôle
```

Keycloak écoute alors sur `127.0.0.1:8081`, avec le realm `vectispire` déjà importé : le client,
son secret, et **le mapper de groupes correctement réglé** — ce dernier étant précisément ce que
l'on rate en configurant Keycloak à la main.

## Ce n'est pas un Keycloak de production, et le fichier le dit

`start-dev` l'annonce lui-même au démarrage : stockage éphémère, pas de HTTPS. Le secret client et
le mot de passe du compte sont **en clair dans le realm et nommés pour ce qu'ils sont** —
`evaluation-only-not-a-secret`, `change-me-evaluation-only`.

Ils ne peuvent pas venir de l'environnement : **l'import de realm Keycloak ne substitue pas
`${env.…}`**. Vérifié plutôt que supposé, en plaçant un marqueur dans un champ public — il ressort
littéral, le `${}` consommé et le nom de variable conservé. Un déploiement réel pointe donc
`VECTISPIRE_OIDC_ISSUER` vers le Keycloak de l'organisation, avec ses propres secrets.

## Les deux réglages qui cassent en silence

Ils sont dans le fichier, corrects, et `ShippedRealmTest` les garde — parce qu'un fichier livré
pour épargner une erreur la répand s'il la porte lui-même.

| Réglage | Valeur | Ce qu'une erreur produit |
|---|---|---|
| `full.path` | `false` | À `true`, Keycloak émet `/AppSec` ; aucune équipe ne s'appelle ainsi, la synchronisation ne fait rien, sans erreur ni journal |
| `redirectUris` | `…/login/oauth2/code/oidc` | Le chemin est celui du filtre Spring Security, pas un choix. Approchant, c'est un « invalid redirect_uri » qu'on impute une demi-journée au secret ou à l'issuer |

Le compte du realm s'appelle `admin` parce que c'est le défaut de `VECTISPIRE_BOOTSTRAP_USERNAME`
dans `docker-compose.yml`. Aucun compte n'est créé à la connexion : la première liaison se fait sur
le nom d'utilisateur, et deux noms qui ne coïncident pas ne se remarquent qu'au moment de fermer la
porte du mot de passe — c'est-à-dire trop tard.

## Ce qui a été vérifié en exécutant

Le profil démarré, le realm importé, et un vrai jeton demandé au serveur : la revendication vaut
`["AppSec"]` — des noms simples, appariables à une équipe — et `preferred_username` vaut `admin`.
L'octroi direct a été activé le temps de la mesure puis remis à `false` ; il reste désactivé dans
le fichier livré.
