# 0010 — Un exécuteur ScanRunner unique, et l'agent comme point de distribution

**Date :** 2026-08-17 · **Statut :** accepté · **Remplace :** [0001](0001-pluggable-scan-layer.md)

## Contexte & Décision

Une classe `ScanRunner` unique et concrète gère l'exécution des conteneurs d'analyse. Les agents distants constituent le point d'extension naturel pour distribuer le scan.
