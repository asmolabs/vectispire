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
| `VECTISPIRE_PREVIOUS_ENCRYPTION_KEYS` | Anciennes clés séparées par des virgules, essayées **au déchiffrement seulement**. |
| `VECTISPIRE_PREVIOUS_ENCRYPTION_KEYS_FILE` | La même liste depuis un fichier, séparée par des virgules ou des sauts de ligne. |

Voir [Rotation et purge](../administration/maintenance.md).

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

Voir [Agents](../administration/agents.md).
