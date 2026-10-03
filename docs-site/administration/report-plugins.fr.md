# Plugins de rapport

Un plugin de rapport est **le document propre à votre organisation, rendu par votre propre image de
conteneur** à partir de l'[export](../guide/exports.fr.md#export-de-projet) d'un projet : une checklist dans
la mise en page de tableur de votre fonction sécurité, une synthèse trimestrielle dans le modèle de votre
direction. Vectispire donne l'export à l'image, vérifie le fichier qu'elle écrit et le signe avec la clé de
la plateforme. La décision
[0035](https://github.com/asmolabs/vectispire/blob/main/docs/architecture/fr/decisions/0035-report-plugins.md)
explique pourquoi il fonctionne ainsi.

**À l'écran** : le registre est sous **Administration → Plugins de rapport** — chaque plugin avec ses
digests approuvé et en attente et l'historique de ses manifestes ; le gouverneur colle un manifeste, vérifié
en mots avant d'être envoyé, active, désactive et retire ; un responsable sécurité approuve, et sous les
quatre yeux le compte qui a enregistré un digest voit pourquoi il ne peut pas l'approuver. La page d'un
projet porte les plugins activés pour lui, les exécutions, les téléchargements et l'export du projet : voir
[Rapports](../guide/exports.fr.md#rapports) dans le guide utilisateur. Chaque route ci-dessous reste là pour
l'automatisation.

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
manifeste. Il n'y a pas de suppression : un identifiant nomme chaque document que le plugin a produit.

**Chaque document produit par le digest est retiré avec lui, et conservé.** Rien n'est supprimé ni réécrit :
le paquet reste exactement tel qu'il a été remis — la preuve de ce qui est sorti — et sa signature se vérifie
toujours, puisqu'une signature détachée ne se défait pas. Ce qui change, c'est ce que l'installation en dit :

- chaque exécution qui a utilisé le digest porte `withdrawnAt`, `withdrawnBy` et `withdrawalJustification` dans
  `GET /api/v1/projects/{id}/reports` et `…/reports/{runId}` ;
- son téléchargement est toujours servi, avec l'en-tête `Vectispire-Document-Status: withdrawn` (`upheld` pour
  tout autre document) ;
- la [route de statut](#linstallation-se-porte-t-elle-toujours-garante-dun-document) répond `withdrawn` à
  quiconque la consulte à son sujet.

Le retrait est lu sur le manifeste à chaque réponse, pas recopié sur les documents : il atteint donc chaque
document du digest, quel que soit le moment où il a été produit. **Une exécution en cours au moment du retrait
ne signe rien** : le fichier qu'elle écrit est écarté et l'exécution échoue `plugin_unavailable`, comme une
exécution prise en charge après le retrait. L'entrée d'audit `REPORT_PLUGIN_WITHDRAWN` compte les documents
retirés.

## Demander un rapport

`POST /api/v1/projects/{id}/reports` avec `{"pluginId": "quarterly-summary"}` demande un rapport du projet
par un plugin activé pour lui. La réponse est **202** avec l'exécution, `pending` ; l'exécuteur du plan de
contrôle la prend en quelques secondes. **Les comptes en écriture et les auditeurs** peuvent la demander,
s'ils voient le projet entier, images comprises — tout autre reçoit le 404 d'un projet qui n'existe pas ; le
gouverneur de la plateforme, qui n'agit sur rien de ce que contient un projet, reçoit un 403. Les clés
d'intégration ne peuvent pas demander de rapport : l'export est construit pour une personne.

**Où il s'exécute : sur le plan de contrôle, jamais sur un agent.** Le plugin s'exécute sur le point d'accès
Docker qu'utilise le worker intégré (`VECTISPIRE_DOCKER_HOST` ou `DOCKER_HOST` — le proxy de socket dans la
composition livrée). Une installation dont le worker intégré est coupé (`VECTISPIRE_EMBEDDED_WORKER=false`,
toutes les analyses sur des agents) **ne peut pas exécuter de plugins de rapport dans cette version** : une
demande est refusée, 409 `report-executor-unavailable`, plutôt que mise en file pour personne. L'exécution
sur un agent est un lot ultérieur. Les exécutions mises en file avant la coupure du worker ne restent pas en
attente : celle que rien ne prend en charge pendant dix-sept minutes, alors qu'aucun exécuteur n'exécute ni ne
démarre rien, passe en échec `executor_unavailable`, et celle qui était en cours passe en échec
`executor_lost` quand son bail expire — chaque instance cherche les deux chaque minute.

**Ce que fait la prise en charge**, dans l'ordre :

1. revérifie ce que la demande a vérifié — le plugin toujours activé pour le projet, activé, avec un
   manifeste approuvé — et exécute **le manifeste approuvé à cet instant**, jamais un manifeste en attente
   d'approbation ;
2. relit le demandeur : un compte désactivé, ou qui ne voit plus le projet entier ou n'a plus un rôle qui
   peut demander, n'obtient aucun export ;
3. construit l'[export](../guide/exports.fr.md#export-de-projet) du projet pour le demandeur, à cet instant —
   celui que décrit le document ;
4. vérifie le signataire de l'image avec le cosign épinglé **avant que l'image soit tirée**, avec la
   configuration Docker du plan de contrôle pour un registre privé ; tout ce qui n'est pas un signataire
   vérifié est un refus, et rien n'est démarré ;
5. exécute l'image **sans aucun réseau**, pas en root, toutes les capacités retirées, un système de fichiers
   racine en lecture seule, les plafonds de mémoire, de processus et de CPU des analyseurs ; l'export seul,
   en lecture seule, à `/report/input/export.json` ; un seul répertoire inscriptible, `/report/output`, qui
   ne peut contenir ni plus que le `max_output_bytes` du manifeste ni plus de 16 fichiers ; arrêtée au
   `timeout_seconds` du manifeste ;
6. lit le fichier que nomme le manifeste, comme fichier régulier, dans le plafond. **Code de sortie 0, ou
   l'exécution est en échec.**
7. **vérifie le fichier sur ses octets** contre le `media_type` du manifeste — voir
   [plus bas](#la-verification-de-la-sortie) — et, s'il passe, le signe et stocke son paquet. Un fichier qui
   n'est pas ce qui a été déclaré est **refusé**, `output_refused`, et jeté sans signature.

Une exécution est dans exactement un état :

| État | Sens |
|---|---|
| `pending` | Demandée, en attente de l'exécuteur. |
| `running` | Prise en charge. Son exécuteur renouvelle son bail tant qu'elle tourne, quelle que soit la durée du pull et de la vérification de la signature. Une exécution dont le bail expire — le plus long délai qu'un manifeste peut déclarer, les deux minutes du vérificateur et dix minutes, dix-sept minutes sans renouvellement — a été laissée par un exécuteur arrêté : elle passe en échec, `executor_lost`, sans nouvelle tentative. Redemandez-la. |
| `produced` | Le plugin est sorti avec 0, a écrit son fichier dans ses limites, le fichier a passé la vérification de son type déclaré, et son paquet signé est stocké. L'export qu'il a reçu est conservé avec l'exécution. |
| `failed` | `exit_code`, `timeout`, `output_full` (le répertoire s'est rempli ou un fichier a dépassé le plafond), `output_missing`, `output_not_regular`, `export_too_large`, `requester_not_allowed`, `plugin_unavailable`, `executor_lost`, `executor_unavailable` (rien ne l'a prise en charge pendant dix-sept minutes alors qu'aucun exécuteur ne travaillait), `executor_error` — avec le détail, les propres mots du plugin pour un code de sortie. |
| `refused` | Pas démarrée : `signature_unverified`, `unsigned`, `registry_authentication_required`, ou `export_schema_unavailable` (le manifeste lit une version majeure d'export que cette installation ne produit plus). Ou démarrée, et **`output_refused`** : le fichier écrit n'est pas ce que déclare son manifeste — le détail dit ce que la vérification a trouvé. Ses octets sont jetés ; l'exécution garde leur SHA-256 et leur taille, et le signataire qui s'est porté garant de l'image. Chacun est la façon dont un plugin altéré, ou dont personne ne se porte garant, se trahit. |

**Une exécution d'un plugin par projet à la fois** : une seconde demande pendant qu'une autre est en attente
ou en cours est refusée, 409 `report-run-in-progress` — c'est celle-là qu'il faut attendre. Les exécutions du
projet, de la plus récente à la plus ancienne, sont à `GET /api/v1/projects/{id}/reports`, une seule à
`GET /api/v1/projects/{id}/reports/{runId}`, pour quiconque voit le projet entier : l'état, son motif et son
détail, le manifeste, l'image et le signataire avec lesquels elle s'est exécutée, le SHA-256 et la taille de
l'export, le SHA-256, la taille et le type de média de la sortie, le SHA-256 du paquet et la clé qui l'a
signé, les instants de demande, de début, d'export et de fin.

**Combien à la fois** : `VECTISPIRE_REPORT_CONCURRENCY`, deux par défaut, sur chaque instance du plan de
contrôle ; il cherche les exécutions en attente toutes les `VECTISPIRE_REPORT_INTERVAL` (10 s). **Ce qui est
conservé** : l'export qu'a reçu une exécution produite, et le paquet de son document, jusqu'à ce que la
[fenêtre des preuves](maintenance.fr.md) (`evidence_retention_days`) soit passée — leurs octets partent alors
et l'exécution garde leurs empreintes ; une exécution en échec ou refusée ne garde rien qu'elle-même et son
motif. Supprimer un projet emporte ses exécutions, leurs exports et leurs documents.

**Sur MySQL, l'export d'un rapport est aussi borné par `max_allowed_packet`.** L'export est gardé dans une
ligne, écrite en une instruction, et le pilote l'envoie encodé en hexadécimal, au double de sa taille : sur un
serveur laissé à son paquet par défaut de 64 Mio, une exécution dont l'export dépasserait environ 32 Mio passe
en échec `export_too_large` avant que le plugin ne s'exécute, le détail le disant. Démarrez MySQL avec
`--max-allowed-packet=160M` (la composition livrée ne le fait pas) et tout export jusqu'à la borne de 64 Mio est
gardé. La borne est lue sur le serveur à chaque exécution ; PostgreSQL n'en a aucune en deçà de 64 Mio. Un
téléchargement de l'export (`GET …/export`) ne garde rien et n'est pas concerné. **Le paquet du document est une
ligne à lui, sous le même paquet** : sur un serveur par défaut, le fichier qu'un plugin peut écrire est abaissé,
pour l'exécution, du `max_output_bytes` de son manifeste à environ 31 Mio, et un plugin qui le remplit passe en
échec `output_full`, le détail disant pourquoi. Le même `--max-allowed-packet=160M` rend le plafond du
manifeste, jusqu'à 50 Mio.

## La vérification de la sortie

Avant que quoi que ce soit soit signé, le fichier est confronté au type que déclare son manifeste — **sur ses
octets**, pas sur son nom :

| Type | Ce qui est vérifié |
|---|---|
| Office Open XML (`.xlsx`, `.docx`, `.pptx`) | Un zip lu avec les garde-fous qu'applique l'import des modèles de checklist — au plus 2 000 entrées, chacune se décompressant en au plus 256 Mio et toutes en 512 Mio, aucune plus de 100 fois sa taille compressée, aucun nom présent deux fois, aucune archive à l'intérieur — et deux de plus : aucun nom d'entrée absolu ou contenant `..`, et un répertoire central qui liste exactement les entrées que contient le fichier, dans l'ordre (c'est ce répertoire que lit le programme du destinataire). `[Content_Types].xml` présent, la partie principale du paquet présente et du type qu'exige le type déclaré. **Aucun projet VBA (`vbaProject.bin`), aucune feuille macro, aucune partie à macros, aucun contrôle ActiveX** — un classeur à macros renommé `.xlsx` est refusé. Aucune relation externe sauf un lien hypertexte : un modèle attaché récupéré sur un serveur est la façon dont un document sans macro à lui en exécute une. |
| OpenDocument (`.ods`, `.odt`) | Les mêmes garde-fous de zip ; la première entrée `mimetype`, stockée sans compression, contenant exactement le type déclaré ; aucun répertoire `Basic/` ou `Scripts/`. |
| PDF | Commence par `%PDF-1.` ou `%PDF-2.`, et `%%EOF` dans son dernier kilo-octet. |
| CSV, texte brut | UTF-8 valide, aucun octet NUL, et **rien qu'un navigateur lirait comme du HTML ou du XML** — une page qui s'ouvre par `<!DOCTYPE html`, `<html`, `<script`, `<?xml`… est du HTML sous un autre nom. |

Pour tout type : non vide, et dans le `max_output_bytes` du manifeste.

**C'est une vérification de type, pas une analyse antivirale.** Un PDF peut porter du JavaScript dans un flux
d'objets compressé qu'aucune recherche d'octets ne trouve. Ce qui borne ce risque, c'est le signataire
qu'exige tout plugin de rapport, l'examen de qui peut signer, et la façon dont le fichier est servi : toujours
en pièce jointe, `X-Content-Type-Options: nosniff`, sous `Content-Security-Policy: sandbox`.

## Le document, et comment le vérifier

`GET /api/v1/projects/{id}/reports/{runId}/document` télécharge le **paquet** d'une exécution produite, un zip
nommé `report-<exécution>-<plugin>.zip`, pour quiconque voit le projet entier — ceux qui peuvent lire
l'exécution. Journalisé `REPORT_DOWNLOADED`. Il contient trois fichiers :

| Fichier | Ce que c'est |
|---|---|
| `<output>` | Le fichier du plugin, octet pour octet — `summary.xlsx` pour le manifeste ci-dessus. |
| `<output>.sig` | Sa signature détachée par la clé de la plateforme, celle qui signe chaque export Vectispire. |
| `provenance.json` | Une déclaration [in-toto](https://in-toto.io/) dont le sujet est le SHA-256 du fichier, dans une enveloppe DSSE signée par la même clé. |

**La provenance indique** l'exécution (identifiant, et les instants de demande, de début, d'export et de fin),
le projet (identifiant et nom), le demandeur (identifiant de compte et nom affiché — jamais une adresse
e-mail), le plugin (identifiant, digest du manifeste, image et digest de l'image, et le signataire que cosign a
vérifié : identité et émetteur, ou le SHA-256 de sa clé), l'export (schéma, version, identifiant, SHA-256 et
taille), le fichier (nom, type de média, SHA-256 et taille), la version du produit et l'identifiant de la clé
de signature. Chaque champ est une valeur que l'exécution a enregistrée : les mêmes figurent dans
`GET /api/v1/projects/{id}/reports/{runId}`.

**Vérifiez-le contre une clé obtenue séparément**, jamais une clé remise avec le document :

```bash
curl -fsS -H "Authorization: Bearer $VECTISPIRE_TOKEN" -o report.zip \
  "$VECTISPIRE_URL/api/v1/projects/12/reports/34/document"
curl -fsS -o vectispire-signing-key.pub "$VECTISPIRE_URL/api/v1/crypto/public-key.pub"
unzip report.zip
cosign verify-blob --key vectispire-signing-key.pub --insecure-ignore-tlog=true \
  --signature summary.xlsx.sig summary.xlsx
cosign verify-blob-attestation --key vectispire-signing-key.pub --insecure-ignore-tlog=true \
  --type https://vectispire.dev/report-provenance/v1 --signature provenance.json summary.xlsx
```

La seconde commande vérifie la signature de l'enveloppe **et** que le sujet de la déclaration est l'empreinte
de ce fichier. `--insecure-ignore-tlog=true` dit seulement que la signature n'a jamais été publiée dans le
journal de transparence public de Sigstore — Vectispire signe avec sa propre clé et ne publie rien ; c'est la
clé qui est vérifiée. Pour lire la déclaration : `jq -r .payload provenance.json | base64 -d | jq .`

**Ce que signifie la signature : la provenance, pas la vérité.** Elle dit que *cette installation a donné cet
export, de ce projet, à cet instant, à cette image, vérifiée comme construite par ce signataire, à la demande
de ce compte, et que ce sont les octets que l'image a écrits*. Elle ne dit **pas** que le document rend
fidèlement l'export : un moteur de rendu peut omettre une ligne ou en inventer une, et rien d'autre que relire
chaque format pour en extraire des faits ne pourrait le déceler. La déclaration le dit elle-même (`claim`). Ce
qui le rend vérifiable à la place : l'export est conservé avec l'exécution pendant la fenêtre des preuves et
son SHA-256 figure dans la déclaration, l'image est épinglée par digest, et un moteur de rendu déterministe à
qui l'on donne le même export écrit les mêmes octets — quiconque doute du document refait le rendu de l'export
avec la même image et compare.

### L'installation se porte-t-elle toujours garante d'un document ?

Une signature qui se vérifie dit que l'installation a produit le document ; elle ne peut pas dire que
l'installation n'a pas, depuis, retiré le code qui l'a produit. Demandez-le, avec le SHA-256 du paquet reçu
**ou du fichier qu'il contient** :

```bash
sha256sum summary.xlsx
curl -fsS -H "Authorization: Bearer $VECTISPIRE_TOKEN" \
  "$VECTISPIRE_URL/api/v1/report-documents/<sha256>"
```

```json
{
  "sha256": "9c1e…(64 hex)",
  "standing": "withdrawn",
  "productions": [{
    "matched": "output",
    "runId": 34, "projectId": 12, "projectName": "Checkout",
    "pluginId": "quarterly-summary",
    "manifestDigest": "5be0…", "imageDigest": "sha256:4f2d…",
    "outputMediaType": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "outputSha256": "9c1e…", "packageSha256": "0d7a…",
    "producedAt": "2026-10-01T09:12:44.120Z",
    "signingKeyId": "e3b4…",
    "documentKept": true,
    "withdrawnAt": "2026-10-03T14:02:10.551Z", "withdrawnBy": "governor",
    "withdrawalJustification": "The renderer dropped accepted issues from the sheet."
  }]
}
```

| `standing` | Signification |
|---|---|
| `upheld` | Produit et signé ici, par un manifeste qui n'a pas été retiré. |
| `withdrawn` | Produit et signé ici, et le manifeste qui l'a produit a été retiré depuis — quand, par qui et pourquoi figurent sur la production. |
| `unknown` | Rien de ce que vous pouvez voir n'a cette empreinte. |

**Qui reçoit une réponse.** Tout compte connecté — pas de clé d'intégration —, au sujet des documents des
projets qu'il voit en entier, images comprises : ceux qui peuvent lire les exécutions. **Un document d'un projet
que vous ne voyez pas en entier, d'un projet supprimé, et une empreinte jamais produite ici répondent tous
`unknown`, dans les mêmes mots** : une réponse distincte pour « existe, mais pas pour vous » dirait à
quiconque en détient une copie de quel projet il vient. Un détenteur sans ce droit demande à quelqu'un qui l'a.

`productions` liste les exécutions qui l'ont produit, de la plus récente à la plus ancienne : une pour un
paquet, qui nomme son exécution ; parfois davantage pour un fichier, puisqu'un moteur de rendu déterministe peut
écrire deux fois les mêmes octets — `upheld` tant que l'une d'elles tient. Un document dont la
[fenêtre des preuves](maintenance.fr.md) a purgé les octets reçoit toujours une réponse, avec
`documentKept: false` : des copies en circulent encore. Une exécution dont la sortie a été refusée n'a rien
signé, et n'est pas un document ici. L'empreinte compte 64 caractères hexadécimaux, en minuscules ou majuscules,
préfixe `sha256:` accepté ; tout le reste est un 400. La question n'est pas journalisée : elle ne montre rien
que les exécutions ne montrent déjà.

## Le plugin de démonstration

Vectispire publie un plugin de rapport à lui, **`vectispire-report-demo`** : une référence à lire, un point
de départ à copier, et le test exécutable du contrat (décision 0035 §6). Personne n'est censé le garder
activé.

**Ce qu'il rend** : `summary.xlsx`, trois feuilles tirées de l'export et de rien d'autre —

| Feuille | Contenu |
|---|---|
| `Summary` | Le projet, sa solution, qui a demandé, l'installation, la version de Vectispire, l'instant et l'identifiant de l'export ; le dernier verdict de la barrière par cible (`never judged` quand il n'y en a pas) ; les comptes de l'export par type, sévérité, état et statut de tri, et leur total. |
| `Issues` | Une ligne par problème que l'export liste, dans son ordre : cible, type, sévérité, identifiant, titre, outil, composant, chemin et ligne, première et dernière détection, KEV, EPSS, CVSS, versions correctives, la décision de tri avec qui l'a prise et quand, l'échéance de remédiation. |
| `Checklists` | Une ligne par ligne de chaque checklist que l'export embarque : le modèle, la révision et son statut, la réponse, son commentaire, qui l'a donnée et si c'était une personne ou Vectispire, la mesure, les preuves encore en vigueur nommées par nom de fichier et SHA-256. |

Les intitulés de feuilles et de colonnes sont en anglais, comme le schéma de l'export. Une valeur que
l'export laisse nulle reste une cellule vide — jamais un zéro que personne n'a mesuré. Il lit tout export
1.x et ignore ce qu'il ne connaît pas ; un export d'un autre schéma ou d'une autre majeure le fait sortir en
2, un export auquel manque une partie en 1, chacun avec sa raison sur stderr — que l'exécution enregistre
comme son détail. Son classeur passe la [vérification de la sortie](#la-verification-de-la-sortie) :
chaque build de Vectispire le vérifie.

**Le même export donne les mêmes octets.** Le classeur ne porte aucun « maintenant » : l'instant qu'il
énonce est celui de l'export, chaque entrée du zip est datée du 1980-02-01, les parties vont dans un ordre
fixe. Le SHA-256 de la sortie d'une exécution peut donc être vérifié par quiconque détient l'export qu'elle a
reçu, en le rendant à nouveau avec la même image. Cette version conserve cet export avec l'exécution et ne le
sert pas encore ; un [export](../guide/exports.fr.md#export-de-projet) téléchargé plus tard est un autre
document — son propre identifiant, son propre instant — et rend un autre classeur. Pour constater la propriété
vous-même, téléchargez un export, posez-le dans `in/` sous le nom `export.json`, et rendez-le deux fois —

```bash
docker run --rm --network none --read-only --user "$(id -u):$(id -g)" \
  -v "$PWD/in:/report/input:ro" -v "$PWD/out:/report/output" \
  ghcr.io/asmolabs/vectispire-report-demo@sha256:<digest> \
  --in /report/input/export.json --out /report/output/summary.xlsx
sha256sum out/summary.xlsx
```

**L'enregistrer.** Chaque version joint le manifeste du plugin, `vectispire-report-demo.manifest.json`, avec
son paquet Sigstore. Le manifeste nomme l'image par l'empreinte que la version a poussée et signée, et
l'identité de signature de cette version —
`https://github.com/asmolabs/vectispire/.github/workflows/release.yml@refs/tags/<tag>`, émetteur
`https://token.actions.githubusercontent.com`. Vérifiez-le avant de le coller où que ce soit :

```bash
cosign verify-blob \
  --bundle vectispire-report-demo.manifest.json.cosign.bundle \
  --certificate-identity "https://github.com/asmolabs/vectispire/.github/workflows/release.yml@refs/tags/<tag>" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  vectispire-report-demo.manifest.json
```

puis, en gouverneur de la plateforme, `POST /api/v1/report-plugins` avec le fichier pour corps. Il ressemble
à ceci, l'image et l'identité étant celles de la version :

```json
{
  "id": "vectispire-report-demo",
  "name": "Vectispire demonstration summary",
  "image": "ghcr.io/asmolabs/vectispire-report-demo@sha256:<digest>",
  "export_schema": 1,
  "arguments": ["--in", "{input}", "--out", "{output}"],
  "output": "summary.xlsx",
  "media_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  "max_output_bytes": 20971520,
  "timeout_seconds": 120,
  "signature": {
    "identity": "https://github.com/asmolabs/vectispire/.github/workflows/release.yml@refs/tags/<tag>",
    "issuer": "https://token.actions.githubusercontent.com"
  }
}
```

Faites-le approuver (par quelqu'un d'autre si les quatre yeux sont actifs), activez-le pour un projet et
demandez un rapport, comme plus haut. L'image est publique sur GHCR : le plan de contrôle doit joindre
`ghcr.io` et le journal de transparence public de Sigstore, et n'a besoin d'aucun identifiant de registre.
Une installation qui reflète ses plugins (`VECTISPIRE_PLUGIN_REGISTRY`) copie l'image **avec sa signature**.

**Écrire le vôtre à partir de lui.** Le source est
[`vectispire-java/vectispire-report-demo`](https://github.com/asmolabs/vectispire/tree/main/vectispire-java/vectispire-report-demo) :
un programme Java qui ne dépend de rien de Vectispire — un plugin connaît le
[schéma](../guide/exports.fr.md#export-de-projet) de l'export, pas la plateforme — construit en image distroless
par Jib. Ce qu'il faut en garder, quel que soit le langage du vôtre : lire l'export comme un arbre et ignorer
ce qu'on ne connaît pas ; refuser une autre majeure plutôt que deviner ; ne jamais rendre une partie absente
comme une partie vide ; écrire le fichier une fois, en entier ; ne prendre aucun instant à l'horloge.

## Ce qui est enregistré

Chaque geste est écrit au [journal d'audit](audit-log.fr.md) — `REPORT_PLUGIN_REGISTERED`,
`REPORT_PLUGIN_UPDATED`, `REPORT_PLUGIN_APPROVED`, `REPORT_PLUGIN_ENABLED_CHANGED`,
`REPORT_PLUGIN_ACTIVATED`, `REPORT_PLUGIN_DEACTIVATED`, `REPORT_PLUGIN_WITHDRAWN`, chacun nommant le digest du
manifeste — et envoyé au [SIEM](../integrations/siem.fr.md#catalogue-des-evenements) comme `VECTI-SEC-031`. Un
geste qui ne change rien — le même manifeste à nouveau, un plugin déjà activé — n'enregistre rien.

Une exécution de rapport enregistre `REPORT_REQUESTED` quand elle est demandée, `PROJECT_EXPORTED` quand
l'export atteint le conteneur du plugin (envoyé au SIEM comme `VECTI-SEC-032`, le SHA-256 de l'export en
tête), puis `REPORT_PRODUCED` (les empreintes de la sortie, du paquet, du manifeste et de l'export, et la clé
de signature), `REPORT_FAILED` ou `REPORT_REFUSED` — chacun au nom du demandeur. **Un refus est envoyé au SIEM
comme `VECTI-SEC-033`**, une sortie refusée comprise (son SHA-256 dans l'entrée) : une image sans signataire
vérifié sollicitée pour s'exécuter, ou un fichier qui n'est pas ce qu'il déclarait, c'est ainsi qu'un plugin
altéré se trahit. Un échec pour une raison ordinaire est journalisé, pas signalé. Un téléchargement
enregistre `REPORT_DOWNLOADED`, avec les SHA-256 de la sortie et du paquet, au nom de qui télécharge — et, pour
un document retiré, qu'il a été servi comme retiré. Le `REPORT_PLUGIN_WITHDRAWN` d'un retrait indique le nombre
de documents retirés avec le digest, puis la justification.

## Refus

| Réponse | Quand |
|---|---|
| 400 | Un manifeste refusé — le `detail` nomme la première chose qui ne va pas ; un retrait sans sa justification ; un statut de document demandé avec autre chose qu'un SHA-256. |
| 403 | Un rôle qui ne peut pas faire ce geste. |
| 404 | Un plugin, ou un digest de celui-ci, qui n'existe pas ; un projet qui n'existe pas ou que vous ne voyez pas en entier (`Project not found.`) ; un rapport demandé à un plugin non activé pour le projet, dans les mêmes mots qu'il existe ou non ; le document d'une exécution qui n'a pas produit, ou dont la fenêtre des preuves a purgé les octets — l'exécution garde ses empreintes. |
| 409 `report-plugin-id-taken` | L'identifiant est déjà enregistré. |
| 409 `report-plugin-four-eyes` | Les quatre yeux sont actifs et vous avez enregistré ce digest. |
| 409 `report-plugin-not-pending` | Le digest n'attend pas d'approbation : approuvé, mis de côté ou retiré. |
| 409 `report-plugin-not-approved` | Activer un plugin, ou lui demander un rapport, sans manifeste approuvé. |
| 409 `report-plugin-disabled` | Demander un rapport à un plugin que le gouverneur a désactivé. |
| 409 `report-executor-unavailable` | Demander un rapport là où le worker intégré est coupé : cette version n'exécute les plugins de rapport que sur le plan de contrôle. |
| 409 `report-run-in-progress` | Un rapport de ce plugin pour ce projet est déjà en attente ou en cours. |
| 409 `report-plugin-withdrawn` | Enregistrer à nouveau, ou retirer à nouveau, un digest déjà retiré. |
| 409 `report-plugin-changed` | Un autre geste a modifié le plugin pendant que le vôtre était décidé : relisez-le. |
