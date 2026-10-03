# Plugins de rapport

Un plugin de rapport est **le document propre à votre organisation, rendu par votre propre image de
conteneur** à partir de l'[export](../guide/exports.fr.md#export-de-projet) d'un projet : une checklist dans
la mise en page de tableur de votre fonction sécurité, une synthèse trimestrielle dans le modèle de votre
direction. Vectispire donne l'export à l'image, vérifie le fichier qu'elle écrit et le signe avec la clé de
la plateforme. La décision
[0035](https://github.com/asmolabs/vectispire/blob/main/docs/architecture/fr/decisions/0035-report-plugins.md)
explique pourquoi il fonctionne ainsi.

!!! warning "Cette version a le registre, pas l'exécuteur"
    Vous pouvez enregistrer un plugin de rapport, faire approuver son manifeste, l'activer pour un projet
    et le retirer. **Rien ne rend encore de rapport** : l'exécution d'un plugin, la vérification de sa
    sortie et la signature du document viennent dans une version ultérieure. Enregistrer dès maintenant
    règle à l'avance qui se porte garant de quelle image.

## Le manifeste

```json
{
  "id": "quarterly-summary",
  "name": "Quarterly risk summary",
  "image": "registry.example.internal/reports/quarterly-summary@sha256:4f2d…(64 hex)",
  "export_schema": 1,
  "arguments": ["--in", "{input}", "--out", "{output}"],
  "output": "summary.xlsx",
  "media_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  "max_output_bytes": 20971520,
  "timeout_seconds": 120,
  "signature": {
    "identity": "https://ci.example.internal/reports/quarterly-summary/release@refs/tags/v2.1.0",
    "issuer": "https://ci.example.internal/oidc"
  }
}
```

| Champ | Ce qu'il signifie |
|---|---|
| `id` | 2 à 40 lettres minuscules, chiffres et tirets intérieurs. **Jamais renommé ni réutilisé** : les documents qu'il a produits le nomment. |
| `name` | Ce que montrent les écrans, 100 caractères au plus. |
| `image` | Épinglée **par digest** : `repository@sha256:<64 hex>`, sans étiquette. |
| `export_schema` | La version majeure de `vectispire-project-export` que lit le plugin. Une majeure que l'installation ne produit pas est refusée ; `GET /api/v1/schemas/project-export/{major}` sert celles qu'elle produit. |
| `arguments` | La commande remise au point d'entrée de l'image, sous forme de liste — sans shell. `{input}` et `{output}` deviennent les chemins d'entrée et de sortie du conteneur. |
| `output` | L'unique fichier que le plugin écrit dans `/report/output` : un nom nu finissant par l'extension de son type (`.xlsx`, `.docx`, `.pptx`, `.ods`, `.odt`, `.pdf`, `.csv`, `.txt`). |
| `media_type` | L'un des types classeur, document et présentation Office Open XML, `application/vnd.oasis.opendocument.spreadsheet`, `application/vnd.oasis.opendocument.text`, `application/pdf`, `text/csv`, `text/plain`. **Le HTML, les anciens formats Office binaires et les paquets à macros sont refusés.** |
| `max_output_bytes` | Le plafond de la sortie, 50 Mio au plus ; 20 Mio par défaut. |
| `timeout_seconds` | 10 à 300 ; 120 par défaut. |
| `signature` | **Obligatoire, sans dérogation** — sans clé (`identity` et `issuer`, les deux, comparés exactement) ou `public_key`, comme pour les [plugins d'analyse](plugins.fr.md#signer-limage). La plateforme signe ce que le plugin écrit, et ne prête pas sa clé à une image dont personne ne répond. |

Il n'y a **pas de champ `network`** : un plugin de rapport tourne toujours sans réseau. Son entrée est
l'état trié entier d'un projet.

**Le manifeste ne porte aucun secret.** Une image d'un registre privé est tirée — et sa signature
vérifiée — avec la **configuration Docker du plan de contrôle** (`DOCKER_CONFIG`, `~/.docker/config.json`) :
donnez au plan de contrôle des identifiants de lecture pour ce registre, comme un exécuteur en reçoit pour
les plugins d'analyse ([identifiants de registre](../guide/containers.fr.md#identifiants-de-registre)).
Vectispire ne stocke aucun identifiant de registre.

## Enregistrer, approuver, activer

| Geste | Qui | Route |
|---|---|---|
| Enregistrer un plugin | le gouverneur de la plateforme | `POST /api/v1/report-plugins` |
| Lui donner un autre manifeste | le gouverneur de la plateforme | `PUT /api/v1/report-plugins/{id}` |
| Approuver un digest de manifeste | le gouverneur de la plateforme, un administrateur ou un CISO — **pas le compte qui l'a enregistré** tant que les [quatre yeux](four-eyes.fr.md) sont actifs | `POST /api/v1/report-plugins/{id}/manifests/{digest}/approval` |
| L'activer ou le désactiver | le gouverneur de la plateforme | `PUT /api/v1/report-plugins/{id}/enabled` |
| L'activer ou le désactiver pour un projet | le gouverneur de la plateforme, un administrateur ou un CISO | `PUT` / `DELETE /api/v1/projects/{id}/report-plugins/{pluginId}` |
| Retirer un digest de manifeste | le gouverneur de la plateforme, avec une justification | `POST /api/v1/report-plugins/{id}/manifests/{digest}/withdrawal` |

**Quatre yeux actifs**, un manifeste enregistré ou mis à jour est `pending_approval` jusqu'à ce qu'une
autre personne qui écrit la gouvernance approuve **ce digest**. Entre-temps, le manifeste approuvé
précédent du plugin continue de servir ; un plugin qui n'en a aucun ne peut pas être activé pour un projet.
Enregistrer un autre manifeste avant l'approbation de celui en attente met ce dernier de côté
(`superseded`) : il ne peut plus être approuvé. Ramener un plugin à un manifeste approuvé auparavant, et
jamais retiré, prend effet aussitôt — deux personnes ont déjà répondu de ces octets-là.

**Quatre yeux inactifs**, un enregistrement ou une mise à jour prend effet aussitôt, enregistré comme
approuvé avec `approvalFourEyes: false`. Un manifeste resté en attente d'avant la bascule peut alors être
approuvé par quiconque écrit la gouvernance, celui qui l'a enregistré compris.

Chaque manifeste qu'un plugin a eu est gardé, par digest, avec son statut — `pending_approval`, `approved`,
`superseded` ou `withdrawn` —, qui l'a enregistré, qui l'a approuvé et si les quatre yeux s'appliquaient :
les `manifests` de `GET /api/v1/report-plugins/{id}`, le plus récent d'abord. Lire le registre est réservé
aux rôles qui lisent la gouvernance ; les plugins activés pour un projet
(`GET /api/v1/projects/{id}/report-plugins`) sont listés à quiconque voit tout le projet, images comprises —
ceux qui en demanderont les rapports.

## Retirer un manifeste

Une signature ne se défait pas. Quand une image se révèle fautive — un rendu qui perd des lignes, un
signataire compromis —, le gouverneur **retire** son digest, avec une justification de 20 à 500
caractères. Le digest ne tourne plus jamais et ne peut pas être enregistré à nouveau ; s'il était le
manifeste approuvé du plugin, celui-ci n'en a plus jusqu'à l'approbation d'une image corrigée — un nouveau
manifeste. Les documents qu'il a produits restent stockés et seront servis marqués comme retirés, avec la
justification. Il n'y a pas de suppression : un identifiant nomme chaque document que le plugin a produit.

## Ce qui est enregistré

Chaque geste est écrit au [journal d'audit](audit-log.fr.md) — `REPORT_PLUGIN_REGISTERED`,
`REPORT_PLUGIN_UPDATED`, `REPORT_PLUGIN_APPROVED`, `REPORT_PLUGIN_ENABLED_CHANGED`,
`REPORT_PLUGIN_ACTIVATED`, `REPORT_PLUGIN_DEACTIVATED`, `REPORT_PLUGIN_WITHDRAWN`, chacun nommant le digest du
manifeste — et envoyé au [SIEM](../integrations/siem.fr.md#catalogue-des-evenements) comme `VECTI-SEC-031`. Un
geste qui ne change rien — le même manifeste à nouveau, un plugin déjà activé — n'enregistre rien.

## Refus

| Réponse | Quand |
|---|---|
| 400 | Un manifeste refusé — le `detail` nomme la première chose qui ne va pas ; un retrait sans sa justification. |
| 403 | Un rôle qui ne peut pas faire ce geste. |
| 404 | Un plugin, ou un digest de celui-ci, qui n'existe pas ; un projet qui n'existe pas ou que vous ne voyez pas en entier (`Project not found.`). |
| 409 `report-plugin-id-taken` | L'identifiant est déjà enregistré. |
| 409 `report-plugin-four-eyes` | Les quatre yeux sont actifs et vous avez enregistré ce digest. |
| 409 `report-plugin-not-pending` | Le digest n'attend pas d'approbation : approuvé, mis de côté ou retiré. |
| 409 `report-plugin-not-approved` | Activer un plugin sans manifeste approuvé. |
| 409 `report-plugin-withdrawn` | Enregistrer à nouveau, ou retirer à nouveau, un digest déjà retiré. |
| 409 `report-plugin-changed` | Un autre geste a modifié le plugin pendant que le vôtre était décidé : relisez-le. |
