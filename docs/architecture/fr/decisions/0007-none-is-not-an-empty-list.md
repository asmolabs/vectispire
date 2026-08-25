# 0007 — L'absence n'est pas une liste vide

**Date :** 2026-08-12 · **Statut :** accepté · **Décideur :** Laurent Boucher

## Contexte

Une étape d'analyse produit une liste de constats. Quand l'étape n'a pas lieu — le conteneur
expire, l'image ne se tire pas, le rapport est illisible, l'outil sort en non-zéro — la chose
naturelle à tenir pour un appelant est une liste vide, parce que c'est à cela que ressemble
« aucun constat » en mémoire.

C'est aussi l'erreur la plus coûteuse que ce système puisse commettre, et il la commet en silence.

`IssueSyncService` réconcilie les constats d'une analyse avec le backlog ouvert : une anomalie d'un
type que l'analyse couvrait, et que l'analyse n'a pas signalée, est **résolue**. C'est correct et
nécessaire — sans cela, une vulnérabilité corrigée resterait ouverte à jamais. C'est aussi pourquoi
une liste vide n'est pas une valeur neutre. Un `[]` de l'étape secrets est l'affirmation *« j'ai
regardé, il n'y a pas de secret dans ce dépôt »*, et elle ferme chaque constat de secret ouvert
pour cette cible : triage, justification VEX, historique compris.

Les deux états doivent donc être distingués au niveau du type, car rien d'autre ne les distinguera.
Un échec ici ne lève aucune exception, ne journalise aucune erreur, et produit une analyse marquée
`completed` avec un backlog plus court qu'avant — ce qui se lit comme un progrès.

## Décision

**`[]` signifie « l'étape a tourné et n'a rien trouvé ».** Elle résout les anomalies ouvertes de ce
type.

**L'absence signifie « l'étape n'a pas tourné ».** Elle laisse le backlog intact.

Chaque scanner renvoie `Optional<List<…>>`, chaque champ de
[`ScanArtifacts`](../../../../vectispire-java/vectispire-common/src/main/java/com/asmolabs/vectispire/common/scanning/ScanArtifacts.java)
est un `Optional`, et `ScanRunner.ran(…)` transforme un résultat absent en échec d'étape inscrit
plutôt que de laisser l'appelant en décider. Un seul endroit décide de ce que fait une étape en
échec.

## Conséquences

**La règle est imposée par les types, pas par la discipline.** `ran(…)` ne compile pas contre une
`List` nue, et
[`ScannerContractTest`](../../../../vectispire-java/vectispire-common/src/test/java/com/asmolabs/vectispire/common/scanning/scanners/ScannerContractTest.java)
vérifie par réflexion que chaque scanner lançant un conteneur renvoie un `Optional` — identifié par
le fait qu'il détient un `ContainerRunner` et non par son nom, de sorte qu'un scanner ajouté plus
tard entre dans le périmètre dès qu'il existe.

**Cette imposition existe parce que la règle a été rompue là où elle comptait le plus.** L'étape
secrets exécutait deux scanners et les fusionnait dans un `catch (Exception ignored)`, tous deux
renvoyant des `List` nues. Un échec du second moteur produisait donc les seuls résultats du
premier — non nuls, donc « complets » — et tout identifiant fuité que seul le second détectait était
résolu en silence. Le type de constat était la fuite d'identifiants, où une fausse résolution est la
réponse la plus coûteuse que le produit puisse donner. C'est un audit qui l'a trouvé, pas un test,
et rien dans le système de types n'avait objecté.

**Un résultat absent est un échec, pas un silence.** Auparavant, les appelants consommaient un
artefact absent par `ifPresent` : le backlog était correctement protégé, mais `failures` restait
vide, l'analyse était inscrite `completed` sans erreur à montrer, et un exploitant lisant une liste
SAST vide voyait un dépôt propre au lieu d'une étape qui n'avait jamais tourné. Le faire remonter
par `ran(…)` fait voyager la raison jusqu'à l'enregistrement de l'analyse.

**Les codes de sortie ne suffisent pas, et c'est pourquoi ceci est une règle sur les valeurs.** Une
exécution Semgrep où la plupart des fichiers ont expiré sort en 0 avec une liste courte. `errors[]`
et `paths.scanned` sont inspectés, et au-delà de 25 % d'erreurs le résultat est absent — une étape
peut échouer en signalant un succès, la décision ne peut donc pas être déléguée au processus.

**Les étapes qui ne s'appliquent pas restent absentes aussi.** Secrets, IaC et SAST ne tournent pas
contre une image de conteneur : ils cherchent dans du code source, et les déclarer analysés
résoudrait tout l'historique de cette cible pour ces types.
