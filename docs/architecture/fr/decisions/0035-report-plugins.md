# 0035 — Un plugin de rapport est une image de conteneur signée qui transforme un export de projet en un document, que la plateforme vérifie, signe et conserve avec sa provenance

**Date :** 2026-10-03 · **Statut :** acceptée · **S'appuie sur :** [0017](0017-custom-checks-as-container-images.md), [0032](0032-security-checklists.md) §10 · **Décideur :** Laurent Boucher

*Acceptée le 2026-10-03 : le responsable du produit a tranché les questions ouvertes sur lesquelles se
terminait la proposition ; les réponses sont reportées dans le corps et listées dans « Décidé le
2026-10-03 » à la fin. Rien n'en était construit à l'acceptation ; les lots à la fin disent dans quel
ordre ce l'est.*

## Contexte

Les organisations ne veulent pas les écrans de Vectispire dans leurs dossiers : elles veulent **leurs
propres documents** — une checklist de sécurité dans la mise en page de tableur que leur fonction
sécurité a conçue il y a des années, une synthèse de risque trimestrielle dans le modèle de traitement
de texte que lit leur direction, un PDF que réclame le formulaire de leur régulateur. Le format de
chaque organisation lui appartient, souvent interne, et change à son propre rythme. Aucun n'a sa place
dans ce dépôt.

La [0032](0032-security-checklists.md) §10 a rencontré le premier de ces documents et l'a réglé dans le
cœur : le classeur de l'organisation, patché cellule par cellule, signé dans la validation. Elle a aussi
écrit pourquoi ce n'était pas la réponse générale, et renvoyé la réponse générale à cette décision :

- la signature est celle du plan de contrôle — la clé ne le quitte jamais — donc un plugin rend des
  octets et le cœur les signe, et *ce qu'affirme une signature sur la sortie d'un plugin* reste à
  décider ;
- un plugin de rapport reçoit des données de projet comme un plugin d'analyse reçoit un arbre, dans la
  forme fermée — mais des décisions de triage, des réponses de checklist et des chiffres sur tout un
  projet sont confidentiels d'une manière qu'un arbre source déjà confié à un scanner ne l'est pas ;
- `checklist.json` a été déclaré le contrat d'entrée qu'un plugin de rapport recevrait.

La [0017](0017-custom-checks-as-container-images.md) a déjà répondu sur le véhicule du code écrit par
d'autres : **pas un JAR dans la JVM, une image de conteneur épinglée par digest**, signée par un
signataire déclaré, exécutée dans la forme fermée de `ContainerRun`, enregistrée par le gouverneur de la
plateforme et activée par projet. Cette décision reprend cette réponse partout où elle tient et dit où un
rapport diffère d'un check. Il en diffère de trois manières qui comptent :

1. **Les données circulent dans l'autre sens.** Un plugin d'analyse lit un arbre que Vectispire a cloné
   et émet des constats que Vectispire ne croit qu'après les avoir lus. Un plugin de rapport lit ce que
   Vectispire *sait* — l'état agrégé et trié d'un projet — et émet un document que Vectispire ne sait
   pas relire en faits.
2. **La sortie porte la signature de la plateforme.** Le rapport d'un scanner devient des lignes ; la
   sortie d'un plugin de rapport quitte la plateforme comme un fichier, signé par la clé qui signe tout
   document de Vectispire ([`SigningKeyService`](../../../../vectispire-java/vectispire-core/src/main/java/com/asmolabs/vectispire/core/crypto/SigningKeyService.java)).
3. **Le déclencheur est une personne, pas un calendrier.** Un rapport est demandé pour un projet par
   quelqu'un qui le voit, et le demandeur fait partie de ce que le document affirme.

Chaque exemple de cette décision est inventé pour elle. Le plugin de démonstration du §6 est le seul
plugin que ce dépôt contiendra jamais.

## Décision

### 1. Ce que reçoit un plugin de rapport : l'export de projet, un document JSON versionné

Un plugin de rapport reçoit **un fichier, `export.json`**, un document que Vectispire construit pour **un
projet, tel que le demandeur le voit**, conforme à un schéma publié. Il ne reçoit rien d'autre : ni base
de données, ni route, ni jeton, ni réseau (§2). **Le plugin n'interroge jamais Vectispire** — tout ce
dont le document a besoin doit être dans l'export, et ce qui n'y est pas, le plugin ne peut pas
l'apprendre.

**Le schéma** s'appelle **`vectispire-project-export`**, versionné `MAJEUR.MINEUR`, à partir de `1.0`.

- C'est un JSON Schema (draft 2020-12) gardé dans le dépôt sous
  `vectispire-java/vectispire-common/src/main/resources/schemas/project-export/v1.schema.json` — un
  fichier par majeure — publié avec le guide utilisateur, et servi par le plan de contrôle sur
  `GET /api/v1/schemas/project-export/{major}` pour qu'un auteur de plugin lise la version que
  l'installation produit réellement.
- Chaque export indique `"schema": "vectispire-project-export"` et `"schema_version": "1.0"` dans ses
  deux premiers champs.
- **Une mineure ajoute, ne retire ni ne change jamais** : un champ optionnel nouveau, une valeur
  d'énumération nouvelle annoncée comme ouverte dans le schéma. Un plugin écrit pour `1.0` lit `1.3`
  sans changement ; un plugin doit ignorer ce qu'il ne connaît pas, et le schéma le dit.
- **Une majeure est tout le reste** : un champ retiré, renommé, retypé, ou un sens changé. Une nouvelle
  majeure est un nouveau fichier de schéma ; le plan de contrôle produit **la majeure courante et la
  précédente** pendant au moins une ligne de versions mineures du produit après l'apparition de la
  nouvelle, et les notes de version nomment la version qui abandonne l'ancienne.
- **Le manifeste déclare la majeure qu'il lit** (`export_schema: 1`, §2). Un plugin qui demande une
  majeure que l'installation ne produit plus n'est pas lancé, et le dit ; on ne lui remet jamais un
  document d'une autre majeure.
- **Le schéma est tenu au code par un test**, comme `openapi.json` : chaque export construit par la suite
  de tests est validé contre le fichier de schéma, et une modification du fichier fait échouer un test
  qui épingle son digest jusqu'à ce que la modification soit relue et la mineure ou la majeure
  incrémentée. Un générateur et un schéma qui divergent seraient un contrat que personne ne tient.

**Ce que contient la version 1.0**, chaque partie bornée et présente même vide — une partie absente
signifie « non produite », un tableau vide « produite, rien dedans »
([0007](0007-none-is-not-an-empty-list.md)) :

| Partie | Contenu |
|---|---|
| `export` | schéma et version, identifiant de l'export, instant de génération (UTC), `ProductVersion`, le demandeur (identifiant de compte et nom affiché), sa langue, le nom de l'installation |
| `project` | identifiant, nom, description, sa solution, ses dépôts et les images de conteneur qui y sont rangées (nom, URL affichée **sans identifiants**, branche par défaut, sous-chemin) |
| `scans` | par cible, la plus récente analyse terminée : identifiant, fin, les types qu'elle a examinés, ses échecs et les étapes de plugins (les états de la 0017 §4) |
| `gate` | par cible, le dernier verdict enregistré, le nom de sa politique et les raisons |
| `issues` | chaque problème **non résolu** des cibles du projet : identifiant, type, sévérité, règle, titre, clé d'outil, paquet et version, identifiants d'avis, chemin et ligne, première et dernière détection, statut, la décision de triage avec sa justification, qui a décidé et quand, la date de revue, l'échéance de remédiation |
| `issue_counts` | par type et sévérité : ouverts, acceptés, faux positifs et résolus — pour qu'un document donne des totaux sans porter l'historique résolu |
| `inventory` | les composants consolidés du projet : nom, version, purl, licences, les cibles d'où ils viennent |
| `compliance` | l'état de conformité du projet, calculé sur ses cibles comme l'écran de conformité du projet le calcule : par référentiel, son statut et son score, et par contrôle son identifiant, son nom, son statut, son score et ses détails ; les cibles suivies, observées et fraîches, qui plafonnent ces verdicts — une ligne de checklist et un document qui la cite ont besoin de l'état contre lequel la checklist a été mesurée |
| `checklists` | par modèle, l'énoncé de la plus récente révision **validée**, embarqué tel quel — le `checklist.json` de la [0032](0032-security-checklists.md) §10, avec sa propre version — et celui de la révision ouverte s'il y en a une, marqué `"draft": true` |

**Ce qui en est exclu, délibérément :**

- **Le code source, et tout ce qui en est cité** : aucun extrait, aucune valeur d'un secret (un problème
  de secret donne sa règle et son fichier, comme l'événement SIEM), aucun échange de revue IA.
- **Tout identifiant ou secret** : clés de déploiement, jetons de clone, identifiants de registre, clés
  d'API, les paramètres de l'installation.
- **Les octets des fichiers de preuve** : nommés par nom, type de média, taille et SHA-256, comme
  `checklist.json` le fait déjà. Un rapport peut citer un fichier ; il ne peut pas le porter.
- **Les comptes au-delà de leur nom affiché** : ni adresse e-mail, ni rôle, ni équipe, ni attribution.
  Les noms qui y figurent sont ceux du demandeur, des auteurs des décisions de triage et des auteurs de
  checklist — déjà sur chaque checklist signée ; une adresse e-mail n'y est jamais, même pour un compte
  sans nom affiché (l'export porte alors l'identifiant du compte seul).
- **Le journal d'audit, les autres projets, la déclaration d'applicabilité de l'organisation et la
  configuration SIEM.** Un rapport de projet parle pour un projet.
- **La posture** : le score de sécurité, le scorecard et son candidat, le classement et les plans. Ce
  sont des chiffres du portefeuille, réglés à leur propre rythme ; un document qui en a besoin cite
  l'écran.
- **Les problèmes résolus un par un** — comptés dans `issue_counts`, pas listés : un historique résolu
  sur des années dominerait chaque export et ne servirait presque aucun document.

**Des bornes, refusées plutôt que tronquées.** Un export de plus de **64 Mio** de JSON, ou de plus de
**100 000** problèmes ou composants, n'est pas construit : la demande est refusée avec le chiffre qui a
dépassé. Un export tronqué serait signé dans un document qui a l'air complet ; c'est le mensonge que la
0007 existe pour refuser.

**Visibilité : tout le projet, ou rien** — la règle de la [0032](0032-security-checklists.md) §8, pour la
même raison. Un rapport parle pour un projet et est signé par la plateforme ; construit à partir d'une
partie du projet, il affirmerait, sous la clé de la plateforme, un état qui omet des dépôts sans que le
lecteur le sache. L'export n'est construit que si
[`RowVisibility.requireWhollyVisibleProject`](../../../../vectispire-java/vectispire-core/src/main/java/com/asmolabs/vectispire/core/access/RowVisibility.java)
admet l'appelant (l'attribution du compte intersectée avec la restriction de la clé d'intégration,
[0024](0024-integration-api-keys-act-for-an-account.md)) ; sinon **404**, les mots d'un projet absent.
Le service d'export prend le `VisibleProject` que la garde produit, jamais un identifiant nu.

**L'export se télécharge aussi seul**, signé : `GET /api/v1/projects/{id}/export` renvoie `export.json`
et sa signature détachée, aux appelants qui peuvent demander un rapport (§4 : les comptes en écriture
et les auditeurs voyant tout le projet), sous `@AcceptsApiKey(EXPORT)`, audité `PROJECT_EXPORTED` et
signalé `VECTI-SEC-032`. C'est ainsi qu'une organisation écrit et teste son plugin privé contre ses propres
données **sans que Vectispire l'exécute** — et cela ne donne à personne rien qu'il ne pouvait déjà lire
par les routes ; cela le rassemble seulement.

### 2. Comment il s'exécute : la forme fermée de la 0017, resserrée

Un plugin de rapport est **une image OCI épinglée par digest plus un manifeste**, exécutée par le
`ContainerRunner` existant dans la forme de `ContainerRun.of(...)` — `cap_drop: ALL`,
`no-new-privileges`, racine en lecture seule, espace temporaire `noexec`, pas root, les plafonds de
mémoire, de processus et de CPU des scanners, supprimé dans un `finally` — exactement comme la 0017 §1 le
dit. Ce qui diffère :

```json
{
  "id": "acme-checklist",
  "name": "Security checklist, organisation layout",
  "image": "registry.example.internal/reports/acme-checklist@sha256:<64 hex>",
  "export_schema": 1,
  "arguments": ["--in", "{input}", "--out", "{output}"],
  "output": "checklist.xlsx",
  "media_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  "max_output_bytes": 20971520,
  "timeout_seconds": 120,
  "signature": {
    "identity": "https://ci.example.internal/reports/acme-checklist/release@refs/tags/v2.1.0",
    "issuer": "https://ci.example.internal/oidc"
  }
}
```

| Champ | Règle |
|---|---|
| `id`, `name`, `image`, `arguments` | Comme la 0017 §2 : identifiant en minuscules jamais renommé ni réutilisé, nom affiché, `repository@sha256:<64 hex>` sans tag, une liste d'arguments sans shell du côté de Vectispire. `{input}` et `{output}` sont remplacés par les deux chemins du conteneur. |
| `export_schema` | La majeure de `vectispire-project-export` que le plugin lit (§1). |
| `output` | Un nom de fichier nu dans `/report/output`. |
| `media_type` | Un type de la liste fermée du §3. |
| `max_output_bytes` | Au plus **50 Mio** ; 20 Mio par défaut. |
| `timeout_seconds` | 10 à 300 ; 120 par défaut. |
| `signature` | **Obligatoire** — sans clé (`identity` et `issuer`, les deux, exacts) ou `public_key`, comme la 0017 §9. |

Le digest du manifeste couvre chaque champ, et chaque manifeste qu'un plugin a eu est gardé par digest,
comme la 0017 §3 : une exécution nomme le digest avec lequel elle a démarré, et la provenance (§3) le
nomme aussi.

**Pas de réseau, et pas d'exception.** La 0017 §1 permet à un plugin d'analyse d'ouvrir le réseau avec
une justification écrite, parce qu'un scanner peut avoir besoin d'une base de vulnérabilités. Un moteur
de rendu n'a besoin de rien du réseau : ses polices, ses modèles et ses logos sont dans son image.
L'entrée est la donnée confidentielle la plus agrégée que la plateforme détient ; une exception réseau
serait un canal d'exfiltration déclaré. Le manifeste n'a pas de champ `network`, et le conteneur est
créé avec le réseau `none`.

**Une entrée, en lecture seule.** `export.json` est écrit dans un répertoire propre à l'exécution, sur
l'exécuteur, qui ne contient que ce fichier, monté en lecture seule sur `/report/input`, et supprimé dans
le `finally` — pas l'espace de travail, pas un clone, rien d'autre. Que le fichier soit monté ou copié
par l'API d'archive se règle à l'implémentation face au filtre du proxy de socket, comme la 0017 §10 a
réglé la sortie.

**Une sortie, bornée.** `/report/output` est la sortie bornée de la 0017 §10 — le volume tmpfs gardé par
un conteneur témoin, `fsize` au plafond — avec `max_output_bytes` du manifeste comme plafond et **16
inodes** : un moteur de rendu écrit un fichier, et la place de quelques fichiers temporaires est tout ce
qu'on lui donne. La sortie est lue comme un fichier ordinaire, jamais à travers un lien, comparée au
plafond avant que ses octets soient lus. Un volume plein signifie que l'exécution a échoué, comme dans la
0017 : ce qui n'a pas pu être écrit n'est pas dans le document.

**Le code de sortie est `0`, ou l'exécution a échoué.** Un moteur de rendu n'a pas de code « trouvé
quelque chose » à déclarer.

**Le signataire est obligatoire, et il n'y a pas de dérogation.** La 0017 §9.1 permet au gouverneur de
dispenser de signature un plugin d'analyse, et à l'opérateur d'un exécuteur de couper l'exigence. Ni
l'un ni l'autre ne s'applique ici. La sortie d'un plugin d'analyse devient des lignes que l'analyse
suivante peut contredire ; celle d'un plugin de rapport quitte la plateforme **sous la signature de la
plateforme**. Signer la sortie d'une image dont personne ne répond prêterait la clé de l'installation à
quiconque peut pousser dans un registre. Un plugin de rapport non signé ou non vérifié est **refusé** —
`unsigned`, `signature_unverified`, les raisons de la 0017 §9.1 — et rien n'est démarré.
`VECTISPIRE_PLUGIN_SIGNATURE_REQUIRED=false` ne l'atteint pas.

**Où il s'exécute : le point d'accès conteneurs du plan de contrôle, pas un agent — dans cette version.**
La réponse de la 0017 pour les checks est « partout où tournent les scanners », parce qu'un plugin
d'analyse lit un arbre que l'exécuteur détient déjà. Un plugin de rapport lit un document que le plan de
contrôle construit à partir de sa base ; l'envoyer à un agent distant expédierait tout l'état trié du
projet vers un hôte qui reçoit aujourd'hui des clones et rend des constats, et dont l'opérateur n'est pas
forcément quelqu'un qui peut lire le projet. Un rapport s'exécute donc sur **le point d'accès Docker
qu'utilise le worker intégré** (`DOCKER_HOST`, le proxy de socket de la
[0018](0018-the-docker-socket-is-never-mounted.md) — jamais un socket monté), par le même
`ContainerRunner`. Le principe que la 0017 garde est gardé : le code du plugin est dans un conteneur,
jamais dans la JVM, et ne voit jamais la base, `ENCRYPTION_KEY` ni la clé de signature ; seul l'export
l'atteint.

Une installation sans point d'accès conteneurs sur le plan de contrôle — le worker intégré coupé, toutes
les analyses sur des agents — **ne peut pas exécuter de plugin de rapport dans cette version**, et les
écrans comme la route le disent (409, `report-executor-unavailable`) plutôt que de mettre en file une
exécution que personne ne prendra. L'exécution sur un agent est un lot ultérieur
(décidé le 2026-10-03, réponse 1) ; d'ici là, une installation dont toutes les analyses tournent sur des
agents reçoit le 409.

**Les exécutions sont mises en file dans la base, pas tenues dans une requête.**
`POST /api/v1/projects/{id}/reports` enregistre une exécution (`pending`) et répond 202 avec son
identifiant ; un pool borné du plan de contrôle (deux exécutions à la fois par défaut) la prend,
construit l'export **à la prise** — l'instant que le document décrit — et lance le plugin. Une exécution
est dans exactement un état :

| État | Sens |
|---|---|
| `pending`, `running` | Demandée ; prise. Une exécution `running` plus vieille que son délai plus dix minutes au démarrage est mise en échec avec `executor_lost`. |
| `produced` | Le plugin est sorti en `0`, sa sortie a passé les contrôles du §3, le paquet est signé et stocké. |
| `failed` | Code de sortie, délai, sortie pleine, pas de sortie, sortie refusée par le §3, export hors bornes — avec la raison. Rien n'est stocké que l'exécution et sa raison. |
| `refused` | Non démarré faute de signataire vérifié (`unsigned`, `signature_unverified`), ou `export_schema` du manifeste non produit (`export_schema_unavailable`). Distingué de `failed` parce que la correction est la provenance ou la version, pas le code du plugin. |

### 3. Ce qu'il produit : un fichier, contrôlé, signé par la plateforme, avec sa provenance

**Un fichier, d'un type déclaré.** Le `media_type` du manifeste fait partie d'une liste fermée, chacun
avec un contrôle que Vectispire applique aux octets avant de croire la déclaration :

| Type de média | Contrôle |
|---|---|
| Classeur, document, présentation Office Open XML (`.xlsx`, `.docx`, `.pptx`) | un zip, lu avec les gardes de zip que l'import des modèles de checklist applique déjà (`WorkbookReader`) (nombre d'entrées, taille décompressée totale, aucun nom d'entrée absolu ou avec `..`) ; `[Content_Types].xml` présent et nommant la partie principale que le type exige ; **pas de `vbaProject.bin`** — un paquet à macros est refusé quelle que soit son extension |
| Classeur, texte OpenDocument (`.ods`, `.odt`) | un zip dont la première entrée est `mimetype`, stockée, contenant exactement le type déclaré ; les mêmes gardes ; pas de répertoire `Basic/` ni `Scripts/` |
| PDF | commence par `%PDF-1.` ou `%PDF-2.`, finit par `%%EOF` dans son dernier kilo-octet |
| CSV, texte brut | UTF-8 valide, aucun octet NUL |

**HTML n'est pas proposé.** Un document servi depuis l'origine du produit et ouvert dans un navigateur
s'exécute dans cette origine ; le cloisonner correctement est une conception à part entière pour un
format qu'aucune organisation n'a demandé.

**Le contrôle est un contrôle de type, pas une analyse antivirus**, et la décision le dit : un PDF peut
porter du JavaScript dans un flux d'objets compressé qu'aucune recherche d'octets ne trouve. Ce qui borne
ce risque, c'est l'exigence de signataire (§2), la revue par le gouverneur de qui peut signer (§4), et la
manière dont le fichier est servi — **toujours en pièce jointe**, avec `Content-Type` au type déclaré,
`X-Content-Type-Options: nosniff` et `Content-Security-Policy: sandbox`, jamais rendu en ligne par
l'interface.

**Stocké, borné, dans la base.** Les octets du paquet vont dans une table à part qu'aucune liste ne lit,
dans une colonne `${bytes}` (le substitut introduit par la 0032), jamais sur le disque du plan de
contrôle — l'exercice de restauration prouve la base, et une seconde instance ne verrait pas un fichier.
L'export remis au plugin est gardé avec l'exécution, selon la même règle : ce que la signature atteste
(plus bas) inclut l'entrée, et une entrée qu'on ne peut plus produire est une affirmation que personne ne
peut vérifier. Les deux sont purgés avec l'exécution par la **fenêtre des preuves**
(`evidence_retention_days`, [maintenance](../../../../docs-site/administration/maintenance.fr.md)),
comme les autres preuves ; la ligne de l'exécution et ses digests restent aussi longtemps que le journal
d'audit.

**Signé par la clé de la plateforme, en signature détachée, quel que soit le format.** Le paquet est un
zip, comme celui de la 0032 :

- `<output>` — le fichier du plugin, octet pour octet ;
- `<output>.sig` — une signature détachée par la clé de signature, vérifiable par
  `cosign verify-blob --key` contre la clé publique publiée, comme tout autre export ;
- `provenance.json` — une déclaration in-toto dont le sujet est le SHA-256 de la sortie, enveloppée dans
  une enveloppe DSSE signée par la même clé (`SigningKeyService.wrapAndSignDsse`, comme l'attestation du
  paquet de preuves).

**La provenance indique** : l'identifiant de l'exécution ; le projet (identifiant et nom) ;
l'identifiant du plugin, le digest de son manifeste, le digest de son image et le signataire que cosign a
vérifié (identité et émetteur, ou empreinte de la clé) ; le schéma et la version de l'export et le
SHA-256 de l'export ; le type de média, la taille et le SHA-256 de la sortie ;
[`ProductVersion`](../../../../vectispire-java/vectispire-core/src/main/java/com/asmolabs/vectispire/core/settings/ProductVersion.java) ;
le demandeur ; les instants de demande, d'export, de début et de fin ; l'identifiant de la clé de
signature. Les mêmes champs sont des colonnes de l'exécution, et l'entrée d'audit `REPORT_PRODUCED` nomme
les digests.

**Ce qu'affirme la signature de la plateforme — et ce qu'elle n'affirme pas.** Elle affirme : *cette
installation a remis cet export, de ce projet, à cet instant, à cette image, vérifiée comme construite par
ce signataire, à la demande de ce compte, et voici les octets que l'image a écrits.* Elle n'affirme
**pas** que le document est un rendu fidèle de l'export : un moteur de rendu peut omettre une ligne ou en
inventer une, et rien à part relire chaque format en faits ne pourrait le dire. La provenance rend cela
vérifiable à la place : l'export est gardé, son digest est signé, et quiconque doute du document peut
rendre l'export à nouveau avec la même image — l'image est épinglée, l'export est figé, un moteur de rendu
déterministe donne les mêmes octets. La documentation destinée aux auteurs de plugins demande le
déterminisme (pas de « maintenant », pas d'identifiant aléatoire), et le plugin de démonstration (§6)
l'est.

**Le PDF signé et les signatures Office ont été écartés** (alternatives) : une signature détachée
fonctionne pour tous les types, ne demande aucune bibliothèque de format dans le plan de contrôle, et se
vérifie avec l'outil qui vérifie tous les autres documents de Vectispire.

### 4. Gouvernance : le registre de la 0017, une liste à part, les quatre yeux sur l'image

**Un registre à lui, à côté de celui des plugins d'analyse.** Les plugins de rapport vivent dans leurs
propres tables — plugin, manifestes par digest, activations, exécutions, documents — dans un nouveau
module `core.reportplugins` (§7), pas dans `t_plugin` avec une colonne `kind`. L'identifiant d'un plugin
d'analyse entre dans les empreintes, son manifeste a des langages et des codes de sortie, son activation
décide d'une analyse ; celui d'un plugin de rapport n'a rien de cela et a un type de média, une majeure
d'export et un demandeur. Partager une table rendrait chaque règle de l'un conditionnelle au type de
l'autre. Ce qu'ils partagent, c'est du code, pas des lignes : les règles d'image et de signataire du
manifeste, la relocalisation par `VECTISPIRE_PLUGIN_REGISTRY`, le vérificateur cosign et la sortie
bornée, tous dans `vectispire-common`.

| Acte | Qui | Marqueur, et ce que le service vérifie |
|---|---|---|
| Enregistrer un plugin, mettre à jour son manifeste, l'activer ou le désactiver | gouverneur de la plateforme | `@RequiresPlatformGovernor`, comme la 0017 §6 |
| **Approuver** un manifeste enregistré ou mis à jour | avec `FOUR_EYES_APPROVAL_REQUIRED` activé, **une autre personne** détenant `canWriteGovernance` (gouverneur, administrateur, RSSI) ; désactivé, l'enregistrement prend effet aussitôt | `@RequiresSecurityLead` + la comparaison dans le service |
| L'activer ou le désactiver pour un projet | responsable sécurité, tout le projet visible | `@RequiresSecurityLead` + la garde |
| Demander un rapport, télécharger l'export | les comptes en écriture (`canCauseEffects`) **et les auditeurs** (`AUDITOR`), tout le projet visible — le gouverneur de la plateforme n'est ni l'un ni l'autre | `@RequiresAccount` + le contrôle du rôle et la garde, tous deux dans le service (export : `@AcceptsApiKey(EXPORT)` aussi) ; chaque demande auditée |
| Lire les exécutions d'un projet et télécharger un document produit | tout le projet visible | `@RequiresAccount` + la garde |
| Retirer les documents d'un manifeste | gouverneur de la plateforme | `@RequiresPlatformGovernor` |

**Les quatre yeux sur l'image, que la 0017 n'a pas.** Un manifeste enregistré ou mis à jour alors que les
quatre yeux sont activés est `pending_approval` jusqu'à ce qu'une seconde personne approuve ce digest ;
une exécution n'utilise jamais un digest non approuvé, et le précédent digest approuvé continue de servir
entre-temps. La raison est la signature : la sortie d'un plugin d'analyse est revérifiée par chaque
analyse, celle d'un plugin de rapport part sous la clé de l'installation, et une personne décidant seule
quel code peut produire des documents signés est la concentration que les quatre yeux existent pour
séparer. La règle suit le paramètre de la plateforme plutôt que de s'appliquer toujours, pour la raison
de la 0032 : une installation avec un seul approbateur ne pourrait sinon jamais en enregistrer. Savoir si
les plugins d'analyse doivent gagner la même règle est laissé à un changement à part (décidé le
2026-10-03) : il amenderait une décision acceptée, la 0017 §6.

**Rien de global, pas de suppression** — comme la 0017 §6 : un plugin de rapport ne s'exécute que pour un
projet où il est activé ; le désactiver garde les activations et n'exécute rien ; supprimer un projet
emporte ses activations, ses exécutions et ses documents ; un identifiant n'est jamais réutilisé, puisque
des documents dans le monde le nomment.

**Retrait.** Une signature détachée ne se défait pas. Quand une image se révèle fautive — un moteur de
rendu qui a perdu des lignes, un signataire compromis — le gouverneur **retire** un digest de manifeste,
avec une justification de 20 à 500 caractères : chaque document qu'il a produit est marqué `withdrawn`,
reste stocké (preuve de ce qui a été remis), est servi avec le retrait indiqué dans la réponse et à
l'écran, et `GET /api/v1/report-documents/{sha256}` répond à un détenteur connecté d'un document si
l'installation le soutient toujours. Retirer désactive le digest ; une image corrigée est un nouveau
manifeste.

**Audit**, chacun après commit par `AuditLogService` : `REPORT_PLUGIN_REGISTERED`,
`REPORT_PLUGIN_UPDATED`, `REPORT_PLUGIN_APPROVED`, `REPORT_PLUGIN_ENABLED_CHANGED`,
`REPORT_PLUGIN_ACTIVATED`, `REPORT_PLUGIN_DEACTIVATED`, `REPORT_PLUGIN_WITHDRAWN`, `PROJECT_EXPORTED`,
`REPORT_REQUESTED`, `REPORT_PRODUCED`, `REPORT_FAILED`, `REPORT_REFUSED`, `REPORT_DOWNLOADED`.

**SIEM**, par l'outbox ([0025](0025-siem-events-leave-through-the-outbox.md)). Le plus haut identifiant
émis à l'acceptation est `VECTI-SEC-030` ; ces trois-là sont **réservés** depuis ce jour — aucun autre
événement ne les prend — et figés par `SecurityEventTypeTest` à mesure que chaque lot émet le sien :

| Id | Événement | Sévérité | Pourquoi un SOC le veut |
|---|---|---|---|
| `VECTI-SEC-031` | Plugin de rapport enregistré, modifié, approuvé, activé ou retiré | 6 | du code tiers gagne ou perd l'accès à tout l'état trié d'un projet, ou le droit de produire des documents sous la clé de l'installation |
| `VECTI-SEC-032` | Un export de projet a quitté la plateforme | 4 | un export a été téléchargé ou remis à un plugin de rapport : qui a pris l'état entier d'un projet, et où il est allé |
| `VECTI-SEC-033` | Plugin de rapport refusé, ou sa sortie refusée | 6 | une image sans signataire vérifié a été appelée, ou a produit un fichier qui n'est pas ce qu'elle déclarait — c'est ainsi que se montre un plugin altéré |

Une exécution en échec pour une raison ordinaire (code de sortie, délai) est auditée, pas signalée : c'est
du travail qui tourne mal, pas un événement de sécurité.

### 5. Plugins privés : registres privés, dépôts privés, rien ici

Le plugin dont une organisation a réellement besoin est, par construction, privé : sa mise en page est
celle de l'organisation, et son code aussi. **Rien d'un plugin privé n'entre dans ce dépôt** — ni son
manifeste, ni sa référence d'image, ni sa mise en page, ni un échantillon de sa sortie, ni un test qui le
nomme. Le dépôt porte le schéma, le mécanisme et le plugin de démonstration du §6 ; une organisation porte
son plugin dans son propre dépôt, construit par sa propre chaîne, signé par son propre signataire, poussé
dans son propre registre, et déclaré dans la base de sa propre installation.

**Tirer d'un registre privé.** *(Corrigé le 2026-10-03 : le texte accepté disait que Vectispire stocke
des identifiants de registre pour l'analyse de conteneurs, chiffrés sous `ENCRYPTION_KEY`, et que le
vérificateur ne pouvait pas encore s'en servir. Ni l'un ni l'autre n'était vrai — rien dans le code ne
stocke d'identifiant de registre — et le vérificateur lit un registre privé depuis la
[0017](0017-custom-checks-as-container-images.md) §9.2.)* **Vectispire ne stocke aucun identifiant de
registre.** Le pull d'une image — et, depuis la 0017 §9.2, la vérification de signature qui le précède —
utilise la configuration Docker de la machine qui l'exécute (`DOCKER_CONFIG`, `~/.docker/config.json`,
ou les propriétés `registry.*` de docker-java) : le démon reçoit ce que docker-java résout pour cette
référence, et le vérificateur reçoit exactement cela, pour une exécution, dans une configuration à une
entrée en lecture seule effacée avec le conteneur. Un registre qui refuse la lecture est refusé comme
`registry_authentication_required`, jamais comme un signataire non vérifié.

Un plugin de rapport s'exécute sur le plan de contrôle (§2), donc **l'image d'un plugin privé est tirée
et vérifiée avec la configuration Docker du plan de contrôle** — l'exploitant y donne les identifiants
de ce registre, comme il donne ceux d'un exécuteur pour un plugin d'analyse. Rien ne traverse la base,
le protocole des agents ni `ENCRYPTION_KEY` ; rien n'est scellé vers un agent. **Le manifeste ne porte
aucun secret et ne nomme aucun identifiant** : l'identifiant est celui que résout le pull de la
référence de l'image, si bien que le digest d'un manifeste ne porte rien qui tourne. Un registre qui ne
peut pas tenir d'identifiant utilisable par le plan de contrôle peut être recopié via
`VECTISPIRE_PLUGIN_REGISTRY`, qui garde le digest et exige que les signatures soient copiées avec.

**Un signataire privé.** La `signature` du manifeste accepte la clé propre d'une organisation
(`public_key`, vérifiée sans le journal de transparence, 0017 §9) ou son propre émetteur OIDC et son
identité de CI : aucun des deux n'a à être public, et aucun n'entre dans ce dépôt.

### 6. Le plugin de démonstration : le test exécutable du contrat

**`vectispire-report-demo`** est le seul plugin de rapport que ce dépôt contient. C'est une référence, un
test et un point de départ — pas une fonctionnalité qu'on s'attend à voir activée.

- **Ce qu'il fait** : il lit `export.json`, refuse un `schema` qu'il ne connaît pas ou une majeure autre
  que la sienne (code 2, et un message sur la sortie d'erreur), et écrit **`summary.xlsx`** : une feuille
  `Summary` (projet, demandeur, `ProductVersion`, instant de l'export, verdicts de gate par cible,
  comptes par type et sévérité), une feuille `Issues` (une ligne par problème de l'export, triage
  compris) et une feuille `Checklists` (les items, réponses et auteurs de chaque checklist embarquée).
  Déterministe : l'instant de l'export, jamais « maintenant » ; des horodatages et un ordre d'entrées zip
  fixes ; le même export donne les mêmes octets.
- **Où il vit** : un sous-projet Gradle, `vectispire-java/vectispire-report-demo`, le JDK seul pour le
  classeur — `java.util.zip` et un écrivain XML, l'approche que la 0032 §10 a prise pour la checklist
  plutôt qu'une bibliothèque de tableur — et Jackson pour l'entrée. Il ne dépend ni de `vectispire-core`
  ni de `vectispire-common` : un plugin connaît le schéma, pas la plateforme, et une démonstration qui
  importerait les records de la plateforme ne prouverait rien sur le contrat.
- **Comment il est construit et signé** : par Jib, comme les deux images, dans le job `build` du
  workflow `release`, remis en archive avec sa somme de contrôle ; `publish` le pousse dans le même
  espace de noms, **le signe par digest** avec la même identité sans clé que les images du plan de
  contrôle (`…/.github/workflows/release.yml@refs/tags/<tag>`), vérifie cette signature avant de
  continuer, et indique son digest dans les notes de version — exactement le chemin des deux images dans
  [`release.yml`](../../../../.github/workflows/release.yml). Le manifeste qu'un opérateur colle pour
  l'essayer est dans le guide utilisateur, avec ce digest et cette identité.
- **Comment il sert de test du contrat** :
  1. le job `jvm` l'exécute en processus contre des exports construits par la suite de tests du cœur à
     partir de projets générés, et vérifie le classeur qu'il écrit — chaque problème de l'export est une
     ligne, chaque compte correspond ;
  2. la suite conteneurs construit son image en archive locale, l'enregistre dans une installation de
     test, et exécute un rapport de bout en bout par le vrai `ContainerRunner` — export, forme fermée,
     sortie bornée, contrôle de type, signature, provenance — puis vérifie le paquet par
     `cosign verify-blob` contre la clé publique de l'installation, la commande que la documentation dit
     à un destinataire d'exécuter ;
  3. un changement de schéma que la démonstration ne lit plus échoue en (1) avant d'atteindre une
     version ; une montée de majeure qui oublie la démonstration échoue en (2).

### 7. Où il se place

Un nouveau module vertical **`core.reportplugins`** (décisions 0028–0030), au-dessus de `checklists` —
l'export embarque leurs énoncés — et au-dessus de `compliance`, dont l'export porte l'état du projet
(réponse 8). Son `package-info` liste, chacun avec sa
raison : `access`, `access::security` (les marqueurs, la garde du projet entier), `targets` (le projet,
ses cibles, `ProjectDeleted`), `scanning` (les analyses les plus récentes, les étapes de plugins),
`issues`, `issues::queries` (le backlog, par `IssueFilters`), `inventory` (les composants consolidés),
`gate` (les verdicts), `checklists` (les énoncés validés), `compliance` (l'état de conformité du
projet). Le socle (`audit`, `settings`, `crypto`) est
partagé. Le nom du module évite `reporting`, qui est la pagination PDF que partagent quatre domaines, et
`common/domain/reports`, qui porte les imports de couverture et de rapports de tests.

Le constructeur d'export est un service de `reportplugins` qui lit par les interfaces publiées de ces
modules ; les parties pures — les records de l'export, son écrivain, les contrôles de type de la sortie —
vivent dans `vectispire-common/domain/reportplugins`, JDK et Jackson seulement.

## Alternatives envisagées

- **Une interface de plugin Java chargée dans le plan de contrôle.** La 0017 l'a écartée pour les checks,
  et chaque raison est plus forte ici : un plugin de rapport dans la JVM détiendrait la base,
  `ENCRYPTION_KEY` et la clé de signature elle-même, et pourrait signer ce qu'il veut.
- **Un langage de gabarits dans le cœur** (un modèle que l'organisation téléverse, rempli par
  Vectispire). Il répond aux mises en page les plus simples et à aucune autre — un document qui calcule,
  regroupe ou choisit — et devient un langage de programmation avec la clé de la plateforme derrière lui.
  Le moteur de rendu de checklist de la 0032 est le seul gabarit intégré, et il le reste.
- **Des plugins appelant l'API de Vectispire avec un jeton éphémère.** Plus simple à écrire, et le plugin
  pourrait demander exactement ce dont il a besoin. Cela donnerait au code tiers un chemin réseau vers le
  plan de contrôle, rendrait inconnaissable après coup ce qu'il a lu, et l'entrée du document
  irreproductible. Un export figé, gardé et haché, est ce qui donne un sens à la signature.
- **Plusieurs exports plus étroits** (problèmes seuls, checklist seule) choisis par le manifeste. Chacun
  est un contrat à versionner ; un export à parties, chacune présente ou absente, est un seul schéma à
  tenir.
- **Une visibilité partielle, avec les omissions marquées** — le comportement de l'export CycloneDX d'un
  projet (construit pour « le projet tel que l'appelant le voit »). Acceptable pour un inventaire, pas
  pour une affirmation signée sur un projet : un destinataire lit le titre, pas une note de bas de page.
  Un rapport partiel marqué reste possible comme option ultérieure si quelqu'un le demande (réponse 2) ;
  personne ne l'a fait.
- **L'exécution sur des agents, comme la 0017 pour les checks.** Voir le §2 : les données quitteraient le
  plan de contrôle pour un hôte qui ne les a jamais détenues. Esquissée comme lot ultérieur, avec l'export
  scellé pour un agent que le gouverneur désigne, par les clés de scellement de la
  [0031](0031-a-sealing-key-is-believed-only-on-the-pinned-key.md).
- **Une exception réseau, comme la 0017 le permet.** Un moteur de rendu n'a pas besoin du réseau ; une
  exception serait un chemin d'exfiltration déclaré pour le document le plus confidentiel que la
  plateforme construit.
- **Une dérogation pour les plugins de rapport non signés, comme la 0017 §9.1 le permet.** La plateforme
  signe la sortie ; dispenser la provenance de l'image prêterait la clé de l'installation à une image
  anonyme.
- **Signer la sortie dans son propre format** — PAdES pour le PDF, XML-DSig pour les fichiers Office.
  Trois mécanismes, trois bibliothèques avec leurs propres avis de sécurité, et rien pour le CSV ; un
  destinataire aurait besoin d'un outil différent par format. La signature détachée est uniforme et se
  vérifie déjà comme tout autre export de Vectispire. Une organisation qui a besoin d'une signature
  électronique qualifiée l'appose ensuite, par une personne, ce que signifie de toute façon une telle
  signature.
- **Le plugin signant sa propre sortie.** Une clé dans une image est une clé que détient quiconque la
  tire ; et l'affirmation qui vaut d'être signée est celle de la plateforme — ce qu'elle a remis et ce
  qui est revenu — pas celle du moteur de rendu.
- **Un seul registre avec les plugins d'analyse (`t_plugin.kind`).** Voir le §4 : deux jeux de règles
  dans une table, chacun conditionnel au type de l'autre ; on partage le code à la place.
- **Rendre de manière synchrone dans la requête.** Un démarrage de conteneur, un pull et une vérification
  de signature dépassent ce qu'une requête devrait tenir, et un redémarrage perdrait le travail sans
  trace. Une ligne d'exécution est la trace.
- **Le plugin de démonstration en script shell sur busybox.** Plus petit, et incapable d'écrire un
  classeur sans réimplémenter le zip : une démonstration qui produit du CSV n'exercerait pas les gardes
  de zip, qui sont les contrôles les plus susceptibles d'être faux.

## Conséquences

- Un nouveau module, `reportplugins`, et son `package-info`, relu ligne par ligne ;
  `ArchitectureTest.MODULES` et `ModularityTest.MODULES` le gagnent.
- Des migrations à partir de la prochaine version libre quand le lot arrive, écrites une fois dans
  `common` avec les substituts : `t_report_plugin`, `t_report_plugin_manifest`,
  `t_report_plugin_activation`, `t_report_run`, `t_report_document` (octets à part, `${bytes}`),
  `t_report_export` (octets à part). Pas de clé étrangère ; les écouteurs du module purgent sur
  `ProjectDeleted`, et le tic de maintenance purge selon la fenêtre des preuves — une `MaintenanceTask`,
  pour que `MaintenanceJobsTest` vérifie qu'elle est appelée.
- Un schéma publié, `vectispire-project-export` 1.0, avec un test qui le tient au générateur ; toute
  modification ultérieure de l'export est une modification de schéma relue.
- De nouvelles routes et leur contrat OpenAPI ; trois identifiants SIEM et une entrée de catalogue
  chacun ; de nouvelles opérations d'audit.
- Une troisième image construite et signée par la release, et son digest dans les notes de version.
- **Une installation sans point d'accès conteneurs sur le plan de contrôle n'a pas de plugins de
  rapport** tant que l'exécution sur agent n'est pas construite.
- **Un registre privé exigeant une authentification est lu avec la configuration Docker du plan de
  contrôle** (§5) : l'exploitant l'y fournit ; Vectispire n'en stocke aucune.
- La signature de la plateforme sur un rapport signifie *provenance*, pas *vérité* ; le guide
  utilisateur le dit en ces termes, et un destinataire qui a besoin de plus rend à nouveau l'export
  gardé.
- Documentation dans les deux langues : une page d'administration pour les plugins de rapport (registre,
  approbation, activation, retrait), une page de guide pour demander et vérifier un rapport, une page de
  référence pour le schéma d'export et les auteurs de plugins, et le catalogue SIEM.

## Décidé le 2026-10-03

La proposition se terminait par onze questions ouvertes. Le responsable du produit y a répondu le
2026-10-03 ; le corps ci-dessus se lit déjà avec ses réponses.

1. **Les installations dont toutes les analyses tournent sur des agents.** L'exécution sur le plan de
   contrôle d'abord ; l'exécution sur agent — un export scellé pour un agent désigné, par les clés de la
   0031 — est un lot ultérieur. D'ici là, une installation sans point d'accès conteneurs sur le plan de
   contrôle reçoit le 409 `report-executor-unavailable` (§2).
2. **Tout le projet ou rien.** Oui : l'export et chaque rapport ne sont construits que pour un appelant
   qui voit tout le projet, et tout autre reçoit le 404 d'un projet absent (§1). Aucun rapport partiel
   marqué n'est proposé.
3. **Les noms dans l'export.** Les noms affichés du demandeur, des auteurs des décisions de triage et des
   auteurs de checklist sont dans l'export ; les adresses e-mail jamais (§1).
4. **Qui peut demander un rapport.** **Les comptes en écriture et les auditeurs** (`Role.AUDITOR`) qui
   voient tout le projet — la proposition laissait l'auditeur de côté. Un auditeur lit déjà l'état entier
   d'un projet ; remettre ce même état à un document, c'est lire, pas agir, et un audit est précisément
   l'endroit où le document propre à une organisation est attendu. Le gouverneur de la plateforme, qui
   ne cause aucun effet et ne trie rien, ne demande pas de rapport. Chaque demande est auditée
   (`PROJECT_EXPORTED`, `REPORT_REQUESTED`), et un export qui quitte la plateforme lève
   `VECTI-SEC-032` (§4).
5. **Les types de média.** Office Open XML (`.xlsx`, `.docx`, `.pptx`), OpenDocument (`.ods`, `.odt`),
   PDF et CSV (le texte brut avec lui) ; HTML, les anciens formats Office binaires et les paquets à
   macros sont refusés (§3).
6. **Ni réseau, et un signataire exigé sans dérogation.** Confirmé tel qu'écrit (§2).
7. **La conservation.** La fenêtre des preuves — `evidence_retention_days`, 400 jours par défaut — pour
   les exports et les documents ; les lignes d'exécution sont gardées avec le journal d'audit (§3).
8. **Conformité et posture dans l'export.** L'export 1.0 porte **l'état de conformité** du projet — les
   lignes mesurées d'une checklist et les documents bâtis dessus le citent — et **pas la posture** (§1).
9. **Les rapports planifiés.** Hors périmètre : un demandeur fait partie de ce qu'affirme un document,
   et un calendrier n'en a pas.
10. **Les quatre yeux sur les plugins d'analyse.** Laissés à un changement à part : il amenderait la
    0017 §6, une décision acceptée, et se décide là, pas ici.
11. **Les numéros SIEM.** `VECTI-SEC-031` à `VECTI-SEC-033` sont réservés depuis ce jour (§4).

## Construit en R1 (2026-10-03) : là où le code en dit plus que le §1

Le lot R1 — l'export, son schéma et son téléchargement signé — a tranché ces points que le §1 laissait
ouverts ou énonçait sans précision. Le code est dans `core.reportplugins` (`ProjectExportService`) et
`common/domain/reportplugins` (`ProjectExport`, `ProjectExportSchema`, `ProjectExportBounds`).

- **Le projet entier comprend ses images.** La garde des checklists ne lit que les dépôts ; un export
  porte aussi les analyses, le backlog et les composants des images, il n'est donc construit que pour un
  appelant qui voit chaque cible rangée dans le projet (`RowVisibility.requireEveryTargetOfProject`), la
  règle des checklists valant aussi.
- **Le téléchargement est un zip** d'`export.json` et d'`export.json.sig` — la forme du paquet de
  checklist, la signature telle que `cosign` l'écrit. La route du schéma demande un compte connecté ou une
  clé `export`.
- **Les énoncés embarqués nomment les personnes par nom affiché.** `checklist.json` enregistre des noms
  d'utilisateur ; l'export remplace chacun par le nom affiché du compte, ou null, et nomme le paquet signé
  par son SHA-256 (`document_sha256`) — l'énoncé sous la signature est celui du paquet. Un nom affiché qui
  est une adresse e-mail est omis comme tel.
- **Le texte d'un problème n'est repris que pour les vulnérabilités, les licences et les fins de vie**
  (`title`) ; pour tout autre type il est null, puisque le message d'un outil peut citer le code qu'il a
  reconnu, et celui d'un secret le secret.
- **Le registre de la barrière garde des décomptes, pas des raisons** : l'export porte les décomptes
  enregistrés, la source et la version de la politique, et aucune raison une à une.
- **Les composants ne portent pas de licence en 1.0** : l'inventaire n'en indexe aucune par composant.
  Une mineure les ajoute quand il le fera.
- **L'installation est nommée par son nom de marque et son URL publique**, là où elle est configurée.
- **Une décision de triage est une décision que quelqu'un a enregistrée** : un problème en revue par
  défaut, sans personne de nommé, a `triage: null` ; son statut est dans `issue_counts`, compté par type,
  sévérité, état et statut de triage.
- **Au-delà d'une borne, 409 `project-export-too-large`** avec la partie, le chiffre et la borne en
  membres ; les problèmes sont comptés avant d'en lire un, le JSON écrit dans un tampon qui s'arrête à
  64 Mio.

## Construit en R2 (2026-10-03) : là où le code en dit plus que le §4

Le lot R2 — le registre — a tranché ces points que le §4 laissait ouverts. Le code est dans
`core.reportplugins` (`ReportPluginService`, migration V72) et `common/domain/reportplugins`
(`ReportPluginManifest`, `ReportMediaType`, `ReportPluginManifestStatus`) ; ce que les deux registres
imposent pareillement (identifiant, nom, arguments, nom de sortie) est passé dans
`common/domain/plugins/ManifestRules`, partagé comme code avec le manifeste de la 0017, dont les messages et
le digest ne changent pas.

- **Un digest de manifeste est dans l'un de quatre états** : `pending_approval`, `approved`, `superseded` —
  en attente, et remplacé par un enregistrement ultérieur avant que quiconque l'approuve : il n'a jamais
  tourné et ne peut plus être approuvé — et `withdrawn`, définitif. Un plugin tient au plus un digest
  approuvé, celui qu'utilise une exécution, et un en attente.
- **Un digest approuvé auparavant, et jamais retiré, sert à nouveau aussitôt** quand le gouverneur y ramène
  le plugin : deux personnes ont répondu de ces octets-là. Un digest retiré est refusé (409
  `report-plugin-withdrawn`).
- **Les quatre yeux sont lus au moment de l'approbation**, comme pour la publication d'un modèle de
  checklist : un manifeste resté en attente d'avant l'extinction de la règle peut alors être approuvé par
  celui qui l'a enregistré. La comparaison se fait par identifiant de compte ; la route porte
  `@RequiresSecurityLead` et le service vérifie à nouveau `canWriteGovernance`. Allumer les quatre yeux
  demande déjà deux comptes qui écrivent la gouvernance (la règle des modèles de checklist), ce qu'il faut
  aussi à une approbation : pas de garde propre.
- **Le nom de la sortie finit par l'extension de son type** : le nom est ce qu'ouvre un destinataire, et un
  classeur déclaré `.xlsx` nommé `.xlsm` s'ouvrirait comme un classeur à macros.
- **`export_schema` doit être une majeure que l'installation produit** à l'enregistrement, plutôt qu'un
  plugin enregistré pour être refusé à chaque exécution.
- **Tout digest pas encore retiré peut l'être**, y compris un digest en attente, qui ne peut alors plus être
  approuvé. Retirer le digest approuvé laisse le plugin sans aucun jusqu'à l'approbation d'un nouveau
  manifeste.
- **Activer un plugin demande un digest approuvé** (409 `report-plugin-not-approved`) et la garde de
  l'export : toutes les cibles rangées dans le projet, images comprises. Les activations d'un projet sont
  listées à tout compte qui le voit en entier — ceux qui en demanderont les rapports ; le registre lui-même
  relève de la lecture de gouvernance.
- **La ligne du plugin porte une révision optimiste** : une approbation qui croise une mise à jour échoue en
  409 `report-plugin-changed` plutôt que d'installer un digest que la mise à jour venait d'écarter.
- **Chaque 409 nomme sa cause** (`report-plugin-id-taken`, `-four-eyes`, `-not-pending`, `-not-approved`,
  `-withdrawn`, `-changed`). Les sept opérations d'audit signalent chacune `VECTI-SEC-031`, comme
  `REPORT_PLUGIN_CHANGED`.

## Construit en R3 (2026-10-03) : là où le code en dit plus que le §2

Le lot R3 — l'exécuteur — a tranché ces points que le §2 laissait ouverts. Le code est dans
`core.reportplugins` (`ReportRunService`, `internal/ReportQueue`, `ReportExecution`, `ReportWorker`,
migration V75) et `common/scanning/scanners/ReportPluginRenderer`, qui exécute un plugin à travers le
`ContainerRunner` et l'`ImageSignatureVerifier` de la 0017, partagés comme code ; `ReportRunState` et
`ReportRunReason` sont les mots fermés d'une exécution.

- **L'entrée est un montage bind**, d'un répertoire ne contenant qu'`export.json`, en lecture seule à
  `/report/input` — le bind par lequel passent déjà tous les analyseurs à travers le proxy de socket, si bien
  que le filtre du proxy n'a besoin de rien de nouveau. Le répertoire est dans l'espace de travail propre à
  l'exécution, la clé du signataire et l'identifiant de registre à côté et jamais dedans, et l'export n'y est
  écrit qu'une fois le signataire vérifié. `{input}` vaut `/report/input/export.json`, `{output}`
  `/report/output/<output>`.
- **Seize inodes est un paramètre de la sortie bornée** (`BoundedOutput.inodes`, 4096 restant celui des
  plugins d'analyse), et la sortie est lue jusqu'au plus petit de `max_output_bytes` et du plafond de sortie
  des analyseurs. Un dépassement de délai est un type (`ScannerFailureException.TimedOut`) : `timeout` se lit
  dans une classe, jamais dans une phrase.
- **Une exécution d'un plugin par projet à la fois.** Une exécution porte `active_key` =
  `<plugin>@<projet>` tant qu'elle est en attente ou en cours, null une fois terminée, sous une contrainte
  d'unicité que les deux moteurs n'appliquent qu'aux valeurs non nulles ; une seconde demande reçoit 409
  `report-run-in-progress`. Un insert en échec n'est pas la preuve d'une course perdue : la ligne validée est
  interrogée avant de dire à la demande d'attendre. Le pool du §2 — deux exécutions à la fois — est par instance
  (`VECTISPIRE_REPORT_CONCURRENCY`), qui cherche les exécutions en attente toutes les dix secondes.
- **La prise est celle de la file des analyses** : les exécutions en attente lues de la plus ancienne à la plus
  récente, chacune prise par une mise à jour conditionnelle ; aucun verrou de ligne. **Le bail** est le plus
  long délai qu'un manifeste peut déclarer, les deux minutes du vérificateur et les dix minutes du §2 —
  dix-sept minutes pour toute exécution, le manifeste n'étant lu qu'après la prise — et **son exécuteur le
  renouvelle** tous les tiers de bail tant que l'exécution vit, chaque renouvellement nommant celui qui l'a
  prise : fixe, il mettait en échec comme perdue une exécution dont le pull ou la vérification de signature
  n'était que lent, et jetait ce qu'elle produisait ensuite. Une exécution au-delà est mise en échec
  `executor_lost` par le tour suivant de n'importe quelle instance, au démarrage ou non, et **sans
  nouvelle tentative** : un rapport décrit l'instant pour lequel il a été demandé. Chaque écriture après la
  prise nomme celui qui l'a prise : un exécuteur dont le bail a expiré n'enregistre rien — ni ne stocke son
  export.
- **Une exécution que personne ne peut prendre passe en échec, `executor_unavailable`** : celle encore en
  attente un bail entier après sa demande, alors qu'aucune exécution ne tourne et qu'aucune n'a démarré dans ce
  bail — un exécuteur occupé tient des exécutions, un exécuteur oisif prend en charge en dix secondes, donc
  aucun n'est là. Une demande est refusée là où il n'y a pas d'exécuteur, mais une exécution mise en file avant
  la coupure du worker intégré, puis un redémarrage sans lui, restait en attente pour toujours, bloquant le tour
  du plugin pour le projet, et celle en cours restait `running` : le tour du worker, seul balayage, est inactif
  sans exécuteur. Les deux balayages sont une tâche de maintenance à la minute du planificateur
  (`ReportRunSweepTask`), sur chaque instance, chacun une mise à jour conditionnelle journalisée `REPORT_FAILED`.
- **La prise re-tranche ce que la demande avait tranché** : un plugin désactivé pour le projet, désactivé ou
  laissé sans manifeste approuvé met l'exécution en échec `plugin_unavailable` ; un demandeur désactivé,
  rétrogradé, ou qui ne voit plus le projet entier la met en échec `requester_not_allowed` — l'export est
  construit pour lui seul, sa visibilité relue sans qu'aucun identifiant ne la restreigne, un rapport ne se
  demandant que par une session. **Le manifeste qu'utilise une exécution est celui approuvé pour le plugin à la
  prise**, enregistré alors : une approbation tombée entre la demande et la prise est ce qui s'exécute, jamais
  un digest non approuvé. Un manifeste dont la version majeure d'export n'est plus produite est refusé
  `export_schema_unavailable`.
- **Les motifs d'échec sont fermés** : `exit_code`, `timeout`, `output_full` (un répertoire plein, `SIGXFSZ`,
  ou un fichier au-delà du plafond), `output_missing`, `output_not_regular`, `export_too_large`,
  `requester_not_allowed`, `plugin_unavailable`, `executor_lost`, `executor_unavailable`, `executor_error` ; les refus `unsigned`,
  `signature_unverified`, `registry_authentication_required`, `export_schema_unavailable`. Un vérificateur qui
  n'a pas pu démarrer n'a rien dit de l'image : c'est `executor_error`, pas un refus — la règle de la 0017.
- **Ce que R3 garde, et ce qu'il ne garde pas.** Une exécution produite garde l'export qu'elle a reçu
  (`t_report_export`, purgé par la fenêtre des preuves par `ReportExportRetentionTask` ; l'exécution garde son
  empreinte). **Les octets de la sortie ne sont pas gardés** : R3 enregistre leur taille et leur SHA-256, et R4
  les vérifie, les signe et les stocke dans la même étape, si bien qu'aucun document non vérifié ne séjourne
  dans la base et qu'aucune route n'en sert. Une exécution en échec ou refusée ne garde rien qu'elle-même.
  Supprimer un projet emporte ses exécutions et leurs exports.
- **Audit et SIEM** : `REPORT_REQUESTED` ; `PROJECT_EXPORTED` quand l'export atteint le conteneur du plugin —
  jamais pour un refus, qui n'atteint rien — signalé `VECTI-SEC-032` ; puis `REPORT_PRODUCED` (les empreintes de
  la sortie, du manifeste et de l'export, en tête), `REPORT_FAILED` ou `REPORT_REFUSED`, chacun au nom du
  demandeur. **`VECTI-SEC-033` est émis dès R3** pour chaque refus, `export_schema_unavailable` compris ; R4
  ajoute la sortie refusée pour ne pas être ce qu'elle déclarait.
- **L'exécuteur existe là où existe le worker intégré** (`vectispire.worker.enabled`) : une seule condition
  pour « ce plan de contrôle a un point d'accès conteneur », d'où découlent le 409
  `report-executor-unavailable` et un tour inactif. Le miroir des plugins d'analyse
  (`VECTISPIRE_PLUGIN_REGISTRY`) s'applique ; leur `VECTISPIRE_PLUGIN_SIGNATURE_REQUIRED` non.

## Mise en œuvre, en lots

| Lot | Contenu | Taille |
|---|---|---|
| R1 | Schéma d'export 1.0, ses records et son écrivain dans `common`, le constructeur dans `reportplugins`, la garde du projet entier, le test de schéma, `GET …/export` signé, `PROJECT_EXPORTED`, `VECTI-SEC-032` | M |
| R2 | Le registre : règles du manifeste, tables, routes du gouverneur, approbation à quatre yeux, activation, audit, `VECTI-SEC-031` ; `integrationTestAll` pour la migration | M |
| R3 | L'exécuteur : file et prise des exécutions, export à la prise, montage de l'entrée, sortie bornée à 16 inodes, signataire obligatoire sans dérogation, les quatre états, reprise au redémarrage ; l'export conservé et sa tâche de purge ; `VECTI-SEC-033` pour un plugin refusé | L |
| R4 | Contrôles de sortie par type de média, stockage, paquet signé et provenance DSSE, en-têtes de téléchargement, `VECTI-SEC-033` pour une sortie refusée, la purge des documents | M |
| R5 | `vectispire-report-demo` : le module, Jib, les tests de contrat en processus et en conteneur, construction, signature, vérification et notes de version dans `release.yml` | M |
| R6 | L'interface : écrans du registre et de l'approbation, un onglet **Rapports** par projet, états des exécutions, téléchargements, retrait | M |
| R7 | Le retrait et la route d'état d'un document | S |
| R8 | Documentation en anglais et en français : administration, guide, référence du schéma, catalogue SIEM, notes de montée de version | M |
| Plus tard | Exécution sur agent avec un export scellé | L |

R1 est utile seul — une organisation peut commencer à écrire son plugin contre son propre export — et
R2 à R4 sont livrés ensemble, puisqu'un registre que rien n'exécute, ou un exécuteur que rien ne
gouverne, n'est pas une fonctionnalité.
