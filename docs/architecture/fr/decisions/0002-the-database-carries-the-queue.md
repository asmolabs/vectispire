# 0002 — La base de données porte la file d'attente, pas un broker externe

**Date :** 2026-08-06 · **Statut :** accepté

## Contexte

La file d'attente des scans était gérée en mémoire via un `ThreadPoolExecutor`. Une seconde instance ne pouvait pas prendre en charge le travail, et un redémarrage perdait les analyses en cours.

## Décision

Les scans sont des lignes de la table `t_scan`. Le verrouillage est transactionnel (`SELECT … FOR UPDATE SKIP LOCKED` ou requêtes conditionnelles selon le dialecte). Déclencher un scan insère une ligne à l'état `queued`/`pending` et retourne immédiatement sans bloquer le client.
