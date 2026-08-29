# 0017 — Les checks propres à une organisation arrivent en images de conteneur, pas en JAR téléversé

**Date :** 2026-08-29 · **Statut :** proposé · **Décideur :** Laurent Boucher

## Contexte

La question posée était de savoir si Vectispire devait accepter le téléversement d'un JAR pour
qu'une société puisse ajouter des checks propres à son organisation — un paquet interne proscrit,
une convention de configuration que personne à l'extérieur ne reconnaîtrait, une règle de nommage
qui n'a de sens que contre le registre de cette société.

**Le besoin est réel et n'est aujourd'hui pas servi.** Le téléversement de règles Semgrep couvre ce
que Semgrep sait exprimer, et [`RuleSetService`](../../../../vectispire-java/vectispire-core/src/main/java/com/asmolabs/vectispire/core/services/RuleSetService.java)
résout déjà la moitié difficile du problème — stocker un artefact centralement et le servir à tous
les exécuteurs, pour que deux agents ne puissent pas diverger sur ce qui a été cherché. Rien ne
couvre un check qui doit *exécuter du code* : lire un fichier de verrouillage dans un format maison,
appliquer une convention interne, croiser un manifeste avec un catalogue interne.

C'est le véhicule qui pose question, pas le besoin.

### Pourquoi pas un JAR

**Il n'y a plus de bac à sable dans la JVM.** Le `SecurityManager` a été supprimé définitivement, et
ce projet tourne sur JDK 25. Un JAR chargé dans le process obtient ce que le process a : le pool de
connexions, la clé qui chiffre les clés de déploiement et les jetons tracker, le socket Docker, le
réseau, le système de fichiers. Toutes les contraintes que
[`ContainerRunner`](../../../../vectispire-java/vectispire-common/src/main/java/com/asmolabs/vectispire/common/scanning/ContainerRunner.java)
construit délibérément — réseau coupé, montage en lecture seule, conteneur éphémère,
`cap_drop: ALL` — seraient contournées par n'importe quel plugin. Un produit dont l'objet est
d'auditer une chaîne d'approvisionnement offrirait l'exécution de code tiers arbitraire au cœur de
son propre control plane.

**Cela casse l'architecture à deux côtés.**
[`ScanRunner`](../../../../vectispire-java/vectispire-common/src/main/java/com/asmolabs/vectispire/common/scanning/ScanRunner.java)
s'exécute à l'identique dans le control plane et sur un agent distant, et il lui est interdit
d'atteindre la persistance — `ArchitectureTest` le vérifie. Un JAR devrait donc être provisionné sur
le système de fichiers de chaque agent, ce qui est exactement l'asymétrie que `RuleSetService` a été
écrit pour supprimer : deux agents, l'un provisionné et l'autre non, alternant sur la même cible
font résoudre puis réapparaître le backlog à chaque tour, silencieusement, parce que l'étape *a
tourné* les deux fois. Un JAR reproduit cela en pire — non pas présent contre absent, mais version A
contre version B.

**Cela gèle l'API interne.** Un plugin compilé contre `IacFinding`, `Workspace` et `ContainerRun`
fait de ces types un contrat public, et chaque refactorisation devient le JAR cassé de quelqu'un
d'autre. Le Jackson du client rencontre celui de Spring Boot 4.1 sur le même classpath.

**Cela se trompe en silence sur la [décision 0007](0007-none-is-not-an-empty-list.md).** Une liste
vide signifie « analysé, propre » et autorise l'ingestion à résoudre les issues de ce type sur la
cible. Un plugin tiers qui renvoie `List.of()` depuis une exception avalée déclare la cible
réparée. Cette distinction est subtile, porteuse, et précisément ce qu'un auteur de check écrivant
son premier plugin ignore.

### Pourquoi cela ne rouvre pas 0010

La [décision 0010](0010-one-scan-runner.md) dit qu'un registre de moteurs d'analyse, chacun avec son
gabarit d'arguments et son fichier de règles, serait une décision différente qui devrait la
remplacer. **Ce n'est pas cela.** Aucune interface `ScannerEngine` ne revient, et aucun gabarit
d'arguments par moteur n'est introduit : ce qui est ajouté est un scanner concret de plus à côté
d'`IacScanner` et de `SastScanner`, avec une forme de commande fixe et un format de sortie fixe,
paramétré par un digest d'image — ce que `ScannerImages` fait déjà pour chaque scanner ici. 0010
reste inchangée.

## Décision

Un check personnalisé est **une image OCI plus une déclaration**, exécutée par le `ContainerRunner`
existant, produisant du **SARIF 2.1.0 sur stdout**.

### Le contrat d'exécution

Exécution via `ContainerRun.of(...)`, qui est la forme fermée : réseau coupé, système de fichiers
racine en lecture seule, 512 Mo de tmpfs pour les écritures, `cap_drop: ALL`, `no-new-privileges`,
l'arbre analysé monté en lecture seule au chemin source habituel. Le socket Docker est hors
d'atteinte — `ContainerRunner` ne porte aucune option pour le monter, et cette capacité absente
*est* l'isolation.

**SARIF, parce que c'est déjà dans la maison.** `SarifExport` en produit et `SastScanner` en analyse
déjà de cette famille : aucun format n'est inventé et aucun parseur supplémentaire n'est à
maintenir. L'analyse SARIF est extraite de `SastScanner` vers un composant que les deux appellent.
Un auteur de check peut tester son image avec `docker run` seul, sans instance Vectispire.

**Le code de sortie 0 signifie « analysé », avec ou sans findings. Tout autre code est un échec**,
remonte en `ScannerFailureException`, et laisse l'artefact absent — ce que l'ingestion lit comme
« pas regardé » et qui laisse le backlog intact, conformément à
[0007](0007-none-is-not-an-empty-list.md). C'est le seul endroit où un auteur de check peut se
tromper dangereusement : une image qui sort 0 avec un SARIF vide après un plantage déclare la cible
propre et résout tout son backlog personnalisé. **La documentation du plugin s'ouvre sur ce
paragraphe.**

### Digest, jamais tag

Le control plane résout le tag en `sha256:…` à l'enregistrement, et `ScanTask` transporte le digest.
`ScanTask` transporte déjà `rulesHash` pour exactement cette raison : un exécuteur qui lit « le set
actif » pour lui-même analyse avec ce qu'il a trouvé au moment où il a demandé, et deux exécuteurs
divergent. Un tag `latest` reproduit cette défaillance à l'identique.

### Le type de finding n'appartient pas au plugin

Un nouveau `FindingType.CUSTOM` avec `GateParticipation.ON_REQUEST` — l'argument est celui
d'`AI_REVIEW`, inchangé : du code tiers qui inventerait un « critical » ferait échouer le build de
quelqu'un d'autre. Un administrateur peut le promouvoir en `ALWAYS` par politique. **C'est le choix
le plus lourd de conséquences ici après le bac à sable**, parce que le défaut décide de ce qu'un
check erroné ou hostile peut faire à une chaîne que personne n'a prévenue.

### Les empreintes sont préfixées par l'identifiant du check

Le `ruleId` SARIF entre dans l'empreinte de l'issue — c'est la raison du `--no-rewrite-rule-ids` de
`SastScanner`. Deux checks émettant tous deux `CKV_AWS_20` fusionneraient sinon en une seule issue.
L'empreinte est donc `identifiant du check + ruleId + fichier + …`, et la documentation dit
clairement que renommer une règle perd le triage qui y est attaché.

### L'enregistrement est un acte d'administrateur

Le pull est la seule opération réseau et il a lieu sur l'hôte, hors du conteneur. Il n'exécute rien,
mais laisser n'importe quel utilisateur faire tirer une image arbitraire sur le démon Docker reste
une décision d'opérateur, pas de lecteur. L'enregistrement est réservé aux administrateurs et
contraint par une liste blanche de registres ; une vérification cosign optionnelle avant le pull
réutilise l'infrastructure DSSE déjà présente.

**Stockage et activation restent séparés**, comme dans `RuleSetService` : l'activation change ce que
la prochaine analyse cherche, et l'opérateur voit l'impact sur le triage avant de décider.

## Conséquences

**Un agent sur un réseau fermé échoue au pull**, ce qui lève une `ScannerFailureException`, ce qui
laisse l'artefact absent et le backlog intact. Correct par défaut, et documenté : pré-tirer l'image
sur chaque agent, ou utiliser un registre que les agents peuvent joindre.

**Ce à quoi on renonce.** L'extension in-process, et avec elle la possibilité pour un check de
consulter la base, l'historique des issues ou une autre cible. Un check voit un arbre et émet des
findings sur cet arbre. Tout ce qui a besoin du corpus est une règle sur des données déjà ingérées —
une autre fonctionnalité, sur l'écran des politiques de gate, sans aucun code non fiable dedans.

**Si un JAR est malgré tout exigé** — un acheteur le demandera nommément — la réponse est un process
séparé, jamais la JVM de l'application : un module `vectispire-plugin-sdk` avec une interface
stable, le plugin lancé en `java -jar` à travers ce même `ContainerRunner` réseau coupé, dialoguant
en JSON sur stdin/stdout, vérifié par cosign au téléversement, version de SDK épinglée, timeout par
check. C'est-à-dire cette décision avec un emballage en forme de Java — ce qui démontre que le JAR
était un détail de packaging et jamais une architecture.

## Ce que cela touche

| Module | Travail |
|---|---|
| `vectispire-common` | `CustomScanner` à côté d'`IacScanner` ; analyse SARIF extraite de `SastScanner` ; `ScanTask.Step.CUSTOM` et les checks déclarés portés par la task ; `ScanArtifacts.custom(...)` en `Optional` |
| `vectispire-core` | entité et `CustomCheckService` calqués sur `RuleSetService` ; contrôleur d'administration ; résolution tag vers digest ; ingestion et `FindingType.CUSTOM` |
| `vectispire-angular` | Administration → Checks personnalisés |
| tests | `ScannerContractTest` étendu plutôt que dupliqué — c'est là que le contrat `Optional` est verrouillé |
| docs | ce document, et le guide de l'auteur de plugin dont le premier paragraphe est le contrat de code de sortie |

## Découpage

1. **Le contrat.** `CustomScanner`, analyse SARIF partagée, un seul check déclaré globalement, gated
   en `ON_REQUEST`. Rien dans l'interface pour l'instant.
2. **La réalité du déploiement.** Checks par cible, liste blanche de registres, épinglage par
   digest, documentation du pré-tirage sur les agents.
3. **L'exploitation.** L'écran d'administration, la vérification cosign, l'impact triage avant
   activation.
