# Exports

Ce qui fait sortir un constat du tableau de bord pour le mettre sous les yeux de la personne
qui peut agir dessus.

## SARIF 2.1.0 {#sarif-210}

Pour GitHub code scanning, GitLab et Azure DevOps.

C'est l'export qui compte le plus en pratique, parce qu'il place le constat **sur la demande de
fusion qui l'a introduit** plutôt que sur un tableau de bord que quelqu'un consulte le jeudi.
Un constat annoté sur le différentiel se corrige ; le même constat dans une liste se trie.

## OpenVEX

Un document VEX construit depuis vos décisions de triage — ce que vous avez évalué comme non
affecté, et pourquoi.

Remettez-le à quiconque consomme votre SBOM. Sans lui, cette personne re-dérive votre backlog
entier depuis votre liste de dépendances et arrive à des conclusions que vous aviez déjà
instruites et écartées.

## CSV

Les issues en fichier plat, pour l'analyse que quelqu'un veut mener dans son propre outil.

## SBOM

Le SBOM exactement tel que le catalogueur l'a produit, non modifié.

Il vaut la peine de dire pourquoi il n'est pas remis en forme : un SBOM est une preuve, et une
preuve qui a subi une transformation est aussi une preuve sur la transformation.

## Des documents écrits pour des gens

Deux rapports PDF, écrits pour être lus plutôt qu'analysés par une machine :

- la **posture** d'une cible — où elle en est aujourd'hui ;
- son **historique de détection et de triage** — ce qui a été trouvé, et ce qui en a été
  décidé.

Voir [Historique et preuves](history.md).

## Paquet de preuves de conformité

Un ZIP signé cryptographiquement, couvert sous [Conformité](compliance.md).

## Export de projet

Un projet entier en un document JSON signé — l'entrée que reçoit un [plugin de rapport](https://github.com/asmolabs/vectispire/blob/main/docs/architecture/fr/decisions/0035-report-plugins.md),
et ce contre quoi une organisation écrit son propre plugin. **Télécharger l'export**, dans la section
**Rapports** de la page du projet ([plus bas](#rapports)), l'enregistre avec votre session ; un pipeline
interroge la route avec une clé d'intégration portant la portée `export`.

```bash
curl -H "X-API-Key: $KEY" -o export.zip https://vectispire.example.org/api/v1/projects/42/export
unzip export.zip                       # export.json et export.json.sig
cosign verify-blob --key public-key.pub --signature export.json.sig export.json
```

`public-key.pub` est `/api/v1/crypto/public-key.pub`, la clé qui signe chaque document de Vectispire.

**Ce qu'il contient**, chaque partie présente même vide — une liste vide veut dire « rien », `null` « non
enregistré », jamais zéro : le projet et les dépôts et images qui y sont rangés ; pour chaque cible,
l'analyse terminée la plus récente (ce qu'elle a examiné, ce qui a échoué, l'état de chaque plugin) et le
dernier verdict de la barrière ; chaque problème non résolu, avec sa décision de triage ; les décomptes
par type, sévérité, état et statut de triage, problèmes résolus compris ; les composants consolidés ;
l'état de conformité du projet ; et les énoncés de checklist — chacun de ceux qui ont été validés avec
l'empreinte de son paquet signé, et la révision ouverte marquée `draft`.

**Ce qu'il ne contient jamais** : du code source ou ce qui en est cité — le texte d'un problème n'est
repris que pour les vulnérabilités, les licences et les fins de vie, jamais le message d'un secret ou
d'une règle ; la valeur d'un secret ; un identifiant (un jeton dans l'URL d'un dépôt est masqué) ; les
octets d'un fichier de preuve (nommé par SHA-256) ; une adresse e-mail — les personnes apparaissent par
identifiant de compte et nom affiché, et un nom affiché qui est une adresse est omis.

**Qui peut en prendre un** : un compte qui peut agir (pas le gouverneur de la plateforme) ou un auditeur,
qui voit **tout** le projet, images comprises. Tout autre s'entend dire que le projet n'existe pas (404),
dans les mêmes mots que pour un projet qui n'existe pas. Une clé d'intégration restreinte à un dépôt ne
voit jamais un projet entier. Chaque téléchargement est audité (`PROJECT_EXPORTED`) et envoyé au SIEM
comme `VECTI-SEC-032`.

**Borné, jamais tronqué** : au-delà de 100 000 problèmes ou composants, ou de 64 Mio de JSON, l'export
est refusé (409 `project-export-too-large`, nommant la partie, le chiffre et la borne) plutôt que signé
incomplet.

**Son schéma** est `vectispire-project-export`, versionné `MAJEURE.MINEURE` et indiqué dans les deux
premiers champs de l'export. L'installation sert celui qu'elle produit à
`/api/v1/schemas/project-export/1` ; le fichier est
[`v1.schema.json`](https://github.com/asmolabs/vectispire/blob/main/vectispire-java/vectispire-common/src/main/resources/schemas/project-export/v1.schema.json)
dans les sources. Une mineure ne fait qu'ajouter des champs optionnels : un plugin doit ignorer ce qu'il
ne connaît pas. Une majeure est un nouveau fichier, et les notes de version disent quand elle apparaît et
quand la précédente cesse d'être produite.

## Rapports

Un **rapport** est le document propre à votre organisation — une checklist dans la mise en page de tableur
de votre fonction sécurité, une synthèse trimestrielle dans le modèle de votre direction — rendu à partir de
l'export d'un projet par un [plugin de rapport](../administration/report-plugins.fr.md) que vos
administrateurs ont enregistré et approuvé. Vectispire donne l'export au plugin, vérifie le fichier qu'il
écrit et le signe avec la clé de la plateforme. Les rapports se trouvent sur la page du projet, dans la
section **Rapports**.

### Qui voit quoi

La section est montrée à quiconque voit le projet **entier**, images comprises : un rapport et l'export
décrivent tout le projet, ils ne sont donc construits pour personne qui n'en voit qu'une partie. Un lecteur
qui n'en voit qu'une partie en est averti, et rien ne lui est proposé.

| Vous êtes | Vous pouvez |
|---|---|
| Tout compte qui voit le projet entier | lire les plugins activés pour lui et chaque exécution, et télécharger un document produit |
| Un compte en écriture (développeur, champion sécurité, administrateur, RSSI) ou un auditeur | aussi **demander un rapport** et **télécharger l'export** |
| Un responsable sécurité (gouverneur de la plateforme, administrateur, RSSI) | aussi **activer ou désactiver** un plugin approuvé pour le projet |

Le gouverneur de la plateforme n'agit sur rien de ce que contient un projet : les deux boutons lui restent
visibles, désactivés, avec la raison. Chaque demande et chaque téléchargement de l'export sont inscrits au
journal d'audit, et un export qui quitte la plateforme est signalé au SIEM.

### Demander un rapport

Sous **Plugins de rapport activés**, appuyez sur **Demander un rapport** à côté du plugin. L'exécution
apparaît sous **Exécutions de rapport**, *En attente*, et la page la suit jusqu'à sa fin : elle interroge à
nouveau le serveur toutes les cinq secondes tant qu'une exécution attend ou tourne, et s'arrête dès qu'il
n'y en a plus. **Une exécution d'un plugin à la fois** : le bouton reste désactivé pendant qu'une est en
cours, et c'est celle-là qu'il faut attendre.

Une exécution se termine dans l'un de trois états :

| État | Ce qu'il signifie |
|---|---|
| **Produit** | Le plugin a écrit son document, le document est ce que déclare son manifeste, et son paquet signé est conservé. |
| **Échec** | Le travail a mal tourné : le plugin est sorti en erreur, a dépassé son délai, n'a rien écrit ou trop, ou aucun exécuteur n'a pris l'exécution. La raison est donnée en mots, avec le message du plugin lui-même quand il en a écrit un. Redemandez une fois la cause corrigée. |
| **Refusé** | L'image n'avait pas de signataire vérifié, ou le fichier qu'elle a écrit n'est pas ce que déclare son manifeste. **Refusé n'est pas un échec**, et s'affiche en rouge plutôt qu'en orange : c'est ainsi qu'un plugin altéré, ou dont personne ne répond, se trahit. Prévenez vos administrateurs. |

Quand la demande elle-même est refusée, la page dit pourquoi : le gouverneur de la plateforme a désactivé
le plugin, il n'a aucun manifeste approuvé, une exécution est déjà en attente ou en cours, ou cette
installation ne peut pas exécuter de plugins de rapport du tout — son worker intégré est désactivé, et cette
version ne les exécute pas sur les agents.

**Provenance**, sous chaque exécution, liste ce avec quoi elle a tourné : les empreintes du manifeste et de
l'image, le signataire, le SHA-256 et la version de schéma de l'export, les SHA-256 du document et du
paquet, et la clé de signature.

### Télécharger un document

**Télécharger** sur une exécution produite enregistre son **paquet**, un zip nommé par le serveur,
`report-<exécution>-<plugin>.zip`, de trois fichiers :

- le document, tel que le plugin l'a écrit, une fois vérifié par rapport au type que déclare son manifeste ;
- `<document>.sig`, sa signature détachée par la clé de la plateforme ;
- `provenance.json`, une déclaration signée de quel export de ce projet a été remis à quelle image,
  vérifiée comme construite par quel signataire, à la demande de qui, et le SHA-256 du document.

Un document est conservé pendant la fenêtre de conservation des preuves. Passé ce délai, la page dit que le
document n'est plus disponible ; l'exécution et ses empreintes restent.

### Vérifier un document

Vérifiez le paquet avec la clé publique de l'instance, obtenue séparément — jamais une clé remise avec le
document. Les commandes sont dans le guide d'administration,
[le document, et comment le vérifier](../administration/report-plugins.fr.md#le-document-et-comment-le-verifier),
et la section **Rapports** y renvoie.

**Ce que signifie la signature : la provenance, pas la vérité.** Elle dit quel export cette installation a
remis à quelle image, à la demande de qui, et que ce sont les octets que l'image a écrits. Elle ne dit pas
que le document rend fidèlement l'export : l'export est conservé avec l'exécution et l'image est épinglée,
quiconque doute d'un document peut donc rendre l'export à nouveau avec la même image et comparer.

!!! note "Les documents d'un plugin retiré ne sont pas encore marqués"
    Quand un administrateur retire le manifeste d'un plugin, les documents qu'il a produits restent
    conservés et sont encore proposés au téléchargement sans marque. Les marquer comme retirés, et répondre
    si l'installation se porte toujours garante d'un document, viennent dans une version ultérieure.

### Activer un plugin pour un projet

Les responsables sécurité voient un sélecteur **Activer** sous les plugins, qui propose les plugins
approuvés pas encore activés pour le projet. **Désactiver** à côté d'un plugin arrête les nouvelles
demandes ; ses exécutions et ses documents restent. Enregistrer, approuver et retirer des plugins se fait
sous **Administration → Plugins de rapport** ([comment](../administration/report-plugins.fr.md)).

## Personnalisation

Les exports et les rapports portent le nom de votre instance là où `VECTISPIRE_BRAND_NAME` est
posé — en-tête, PDF, sorties SARIF, VEX et CSAF. Voir
[Configuration](../reference/configuration.md).
