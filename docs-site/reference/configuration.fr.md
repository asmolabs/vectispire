# Configuration

L'essentiel des réglages vit dans la base de données et s'édite depuis
[Réglages](../administration/settings.md). Ce qui suit est ce qui doit être juste *avant* le
démarrage de l'application, parce que c'est nécessaire pour atteindre cet écran.

## Base de données

| Variable | Défaut |
|---|---|
| `VECTISPIRE_DB_URL` | `jdbc:postgresql://localhost:5432/vectispire` — une URL **JDBC**. MySQL : `jdbc:mysql://localhost:3306/vectispire` |
| `VECTISPIRE_DB_USER` | `vectispire` |
| `VECTISPIRE_DB_PASSWORD` | vide |

Le moteur est lu depuis l'URL. Il n'y a pas de réglage de dialecte séparé.

## Chiffrement

| Variable | Notes |
|---|---|
| `ENCRYPTION_KEY` | L'enregistrement de tout secret est refusé tant que celle-ci ou la forme fichier n'est pas posée. |
| `ENCRYPTION_KEY_FILE` | Un chemin vers un fichier contenant la clé. **À préférer en production.** Poser les deux est refusé ; un chemin qui ne résout pas arrête l'application. |
| `VECTISPIRE_SIGNING_KEY` | La clé privée ECDSA P-256 (PEM, PKCS#8) qui signe les coffres de preuves, VEX, CSAF, CycloneDX et enveloppes in-toto ; sa moitié publique est publiée sur `/api/v1/crypto/public-key.pub`. Non posée, une clé est générée au premier usage et conservée chiffrée sous `ENCRYPTION_KEY` : elle survit aux redémarrages — et rien ne peut être signé sans `ENCRYPTION_KEY`. **À poser dès que plus d'une instance tourne**, pour qu'elles signent toutes avec la même clé. Une clé conservée qu'aucune `ENCRYPTION_KEY` configurée ne sait déchiffrer est refusée, jamais remplacée : la remplacer rendrait invérifiable tout document déjà signé. |
| `VECTISPIRE_PREVIOUS_ENCRYPTION_KEYS` | Anciennes clés séparées par des virgules, essayées **au déchiffrement seulement**. |
| `VECTISPIRE_PREVIOUS_ENCRYPTION_KEYS_FILE` | La même liste depuis un fichier, séparée par des virgules ou des sauts de ligne. |

Voir [Rotation et purge](../administration/maintenance.md).

### Garde des clés dans HashiCorp Vault

`VECTISPIRE_ENCRYPTION_KMS_TYPE=vault` chiffre par le moteur Transit de Vault au lieu d'une clé locale,
avec `VECTISPIRE_ENCRYPTION_VAULT_ENDPOINT`, `VECTISPIRE_ENCRYPTION_VAULT_TOKEN` (ou `…_TOKEN_FILE`),
`VECTISPIRE_ENCRYPTION_VAULT_KEY_NAME` (par défaut `vectispire`) et `VECTISPIRE_ENCRYPTION_VAULT_MOUNT_PATH`
(par défaut `transit`). Demander Vault sans point d'accès ou sans jeton arrête l'application plutôt que
de se rabattre sur une clé locale.

**La clé Transit doit être dérivée** : `vault write -f transit/keys/vectispire derived=true`. Chaque
secret est chiffré avec la ligne à laquelle il appartient comme contexte, si bien qu'un chiffré déplacé
vers une autre ligne ne se déchiffre pas — et Vault n'utilise ce contexte que sur une clé dérivée, il
l'ignore sur une clé ordinaire. Vectispire lit la clé une fois et **refuse de chiffrer sous une clé non
dérivée** ; ce qu'une telle clé détient déjà reste lisible, avec une erreur dans le journal, jusqu'à ce
que les secrets soient enregistrés de nouveau sous une clé dérivée.

## Premier compte

| Variable | Notes |
|---|---|
| `VECTISPIRE_BOOTSTRAP_USERNAME` | Utilisé seulement quand la table des utilisateurs est vide. |
| `VECTISPIRE_BOOTSTRAP_PASSWORD` | Au moins 8 caractères. |

Dès qu'un compte existe, les deux sont ignorés.

## Authentification

| Variable | Défaut | Notes |
|---|---|---|
| `VECTISPIRE_OIDC_ISSUER` | *aucun* | Active l'[authentification unique](../administration/sso.md). |
| `VECTISPIRE_PASSWORD_LOGIN` | `true` | `false` délègue entièrement l'authentification. **Ignoré, bruyamment, sans émetteur posé** — cela ne laisserait aucune entrée. |
| `VECTISPIRE_OIDC_LINK_PRIVILEGED_ACCOUNTS` | `false` | Permet de lier un compte SUPERUSER ou ADMIN à sa première connexion par son nom. Seulement pour un realm où personne ne choisit son nom. |
| `VECTISPIRE_OIDC_REQUIRE_MFA` | `false` | Refuse une connexion SSO dont le jeton n'atteste aucun second facteur. Une connexion fédérée saute le TOTP local : le second facteur relève du fournisseur. |
| `VECTISPIRE_OIDC_MFA_AMR` | `mfa,otp,hwk,fido` | Les valeurs `amr` (RFC 8176) qui valent second facteur. |
| `VECTISPIRE_OIDC_MFA_ACR` | *aucun* | Les niveaux `acr` qui en valent un, quand le fournisseur signale le MFA ainsi. |

## Clonage

| Variable | Défaut | Notes |
|---|---|---|
| `VECTISPIRE_GIT_ALLOWED_HOSTS` | *aucun* | Hôtes, séparés par des virgules, depuis lesquels les dépôts peuvent être clonés — `gitlab.corp.example, *.corp.example`. Vide, tout hôte est permis sauf les adresses link-local, toujours refusées. Vérifié à la saisie de l'URL et avant chaque analyse. |

## Audit

| Variable | Notes |
|---|---|
| `VECTISPIRE_AUDIT_MIRROR` | Un chemin où chaque entrée d'audit est ajoutée comme une ligne JSON, hors de la base de données qu'elle surveille. Désactivé signifie que le journal n'a qu'une copie, et l'écran de vérification le dit. |

## Personnalisation

| Variable | Défaut |
|---|---|
| `VECTISPIRE_BRAND_NAME` | `Vectispire` — en-tête, rapports PDF, et exports SARIF / VEX / CSAF |
| `VECTISPIRE_GITLAB_URL` | `https://github.com/asmolabs/vectispire` — l'URL des sources affichée à côté du pied de page « Powered by Vectispire ». Le nom est un reste de l'époque où le projet était hébergé sur GitLab ; le réglage est indépendant de la forge et son défaut n'est pas une URL GitLab. |

## Documentation de l'API

Swagger UI est **désactivé par défaut en production**. Activez-le en développement :

```bash
export VECTISPIRE_SWAGGER_UI_ENABLED=true
export VECTISPIRE_API_DOCS_ENABLED=true
```

Puis `http://localhost:3180/swagger-ui.html`.

## Agents distants

| Variable | Notes |
|---|---|
| `VECTISPIRE_URL` | Le plan de contrôle que l'agent interroge. |
| `VECTISPIRE_AGENT_TOKEN` | Une clé d'API avec la portée `agent`, affichée une seule fois à la création. |
| `VECTISPIRE_AGENT_SIGNING_KEY` | La moitié privée de la clé Ed25519 qu'un administrateur a épinglée pour cet agent, en base64. Vide : les résultats sont acceptés sur la seule clé API. L'épingler est ce qui empêche une clé volée de déclarer une cible propre — le résultat vide qui résout tout un backlog. |

Voir [Agents](../administration/agents.md).
