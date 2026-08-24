# 0001 — La couche de scan est extensible via `ScannerEngine`

**Date :** 2026-07-28 · **Statut :** **remplacé** par [0010](0010-one-scan-runner.md) le 2026-08-17 · **Décideur :** Laurent Boucher

## Contexte

Le pipeline d'analyse appelait directement `docker.containers.run` en dur pour Syft puis Grype. L'ajout d'un type d'analyse supplémentaire (secrets, IaC, SAST) ou d'un mode d'exécution autre que Docker nécessitait de dupliquer l'orchestrateur.

## Décision

Créer une interface commune, [`ScanRunner`](../../../../vectispire-java/vectispire-common/src/main/java/com/asmolabs/vectispire/common/scanning/ScanRunner.java), séparant **ce qui doit être scanné** de la manière et de l'endroit **où cela est exécuté**. L'orchestrateur appelle l'implémentation configurée ; le moteur Docker reste le choix par défaut.

---

> **Remplacé le 2026-08-17 par [0010](0010-one-scan-runner.md).** Seule l'implémentation Docker a été construite. La décision 0010 abandonne l'interface intermédiaire et établit l'agent distant comme le seul point d'extension conservé.
