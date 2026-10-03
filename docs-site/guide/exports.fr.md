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

Un projet entier en un document JSON signé — l'entrée que recevra un [plugin de rapport](https://github.com/asmolabs/vectispire/blob/main/docs/architecture/fr/decisions/0035-report-plugins.md),
et ce contre quoi une organisation écrit son propre plugin avant que Vectispire n'exécute quoi que ce
soit. Pas encore de bouton : interrogez la route, avec votre session ou une clé d'intégration portant la
portée `export`.

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

## Documents de rapport

Un document qu'un [plugin de rapport](../administration/report-plugins.fr.md) a rendu à partir de l'export
d'un projet arrive sous forme d'un zip de trois fichiers : le document lui-même, sa signature détachée
`<fichier>.sig`, et `provenance.json` — une déclaration signée de quel export de quel projet a été donné à
quelle image, vérifiée comme construite par quel signataire, à la demande de qui, et le SHA-256 du document.
Les deux se vérifient avec `cosign` contre la clé publique de l'instance
([les commandes](../administration/report-plugins.fr.md#le-document-et-comment-le-verifier)). La signature
atteste **la provenance, pas la vérité** : elle ne dit pas que le document rend fidèlement l'export, et
l'export conservé avec l'exécution est ce qui permet de le vérifier.

## Personnalisation

Les exports et les rapports portent le nom de votre instance là où `VECTISPIRE_BRAND_NAME` est
posé — en-tête, PDF, sorties SARIF, VEX et CSAF. Voir
[Configuration](../reference/configuration.md).
