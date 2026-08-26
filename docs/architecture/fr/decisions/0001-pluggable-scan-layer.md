# 0001 — La couche de scan est extensible via `ScannerEngine`

**Date :** 2026-07-28 · **Statut :** **remplacé** par [0010](0010-one-scan-runner.md) le 2026-08-17 · **Décideur :** Laurent Boucher

## Contexte

Le pipeline d'analyse appelait directement `docker.containers.run` en dur pour Syft puis Grype. L'ajout d'un type d'analyse supplémentaire (secrets, IaC, SAST) ou d'un mode d'exécution autre que Docker nécessitait de dupliquer l'orchestrateur.

## Décision

Créer une interface commune, [`ScanRunner`](../../../../vectispire-java/vectispire-common/src/main/java/com/asmolabs/vectispire/common/scanning/ScanRunner.java), séparant **ce qui doit être scanné** de la manière et de l'endroit **où cela est exécuté**. L'orchestrateur appelle l'implémentation configurée ; le moteur Docker reste le choix par défaut.

## Quelle était l'alternative, et ce que la couture a coûté

**L'alternative était de garder l'orchestrateur codé en dur et de le dupliquer par type
d'analyse.** Rejetée sur une prévision : secrets, IaC et SAST étaient attendus sous quelques
semaines, et chacun aurait recopié le cycle de vie du conteneur — tirer, exécuter sous plafonds,
collecter, nettoyer — avec sa propre gestion du délai, subtilement différente. Quatre copies de
cela, c'est quatre endroits où un réglage de bac à sable peut être oublié.

**Ce que la couture a coûté, c'est une indirection pour une seule implémentation.** Accepté en
connaissance de cause : une interface à un seul implémenteur se lit comme spéculative, et
l'argument pour la payer était que le second implémenteur était à quelques semaines, pas
hypothétique.

**La prévision était fausse, et c'est la leçon du renversement.** Les types d'analyse
supplémentaires sont arrivés comme *davantage d'images de scanners derrière le même exécuteur
Docker*, pas comme de nouveaux exécuteurs — ce qui variait, c'était l'outil, que `ScannerImages`
paramétrait déjà. La couture est restée inutilisée jusqu'à ce que 0010 la retire. Ce que le
renversement montre n'est pas que la couture était sotte, mais que l'axe de variation avait été
mal prédit : la dimension enfichable s'est révélée être **où l'exécuteur tourne** (l'agent
distant), pas **comment**.

---

> **Remplacé le 2026-08-17 par [0010](0010-one-scan-runner.md).** Seule l'implémentation Docker a été construite. La décision 0010 abandonne l'interface intermédiaire et établit l'agent distant comme le seul point d'extension conservé.
