# 0002 — La base porte la file, pas un broker

**Date :** 2026-08-06 · **Statut :** acceptée

## Contexte

La file d'attente des scans était un `ThreadPoolExecutor` de module : elle vivait dans le
processus qui avait reçu la requête. Une seconde instance ne pouvait donc pas prendre le
travail, et un redémarrage perdait ce qui était en vol.

## Décision

Les scans sont des lignes avec un statut, et la base est la source de vérité. La
réclamation est **transactionnelle** : `SELECT … FOR UPDATE SKIP LOCKED` puis le changement
de statut dans la *même* transaction. Soit une instance tient la ligne et la ligne le dit,
soit ni l'un ni l'autre.

`trigger_scan` n'exécute plus : il insère une ligne `pending` et rend la main.

Un bail (`claimed_by`, `lease_expires_at`, `attempts`) rend la reprise possible sans que le
démarrage d'une instance tue les scans de l'autre.

## Ce qu'on a écarté

**Un broker de messages** — RabbitMQ, Kafka, NATS. Deux raisons.

Un broker introduit une **double écriture** entre la ligne de scan et le message : message
publié puis transaction annulée, ou transaction validée et publication échouée. La
correction standard est un *transactional outbox*, c'est-à-dire **plus de machinerie que
la file qu'on remplace**.

Et un broker ne dispense pas du bail. Un consommateur qui meurt en tenant un message
demande un *visibility timeout* — le même travail sous un autre nom.

Le jour où un broker devient justifié — une tâche consommée par plusieurs abonnés aux
préoccupations différentes, plusieurs milliers de messages par seconde, ou le rejeu d'un
historique d'événements — la file en base reste la source de vérité et le broker se greffe
à côté. **Commencer par la base ne ferme aucune porte ; commencer par le broker engage
tout de suite dans l'outbox.**

## Conséquences

`SKIP LOCKED` n'existe pas sur SQLite, qui garde un `UPDATE` conditionnel — correct pour
les threads d'un processus, ce qui est tout ce que SQLite permet. Le contrôle de dialecte
est explicite parce que le dialecte SQLite de SQLAlchemy **laisse tomber `FOR UPDATE` en
silence** : demander sans vérifier aurait produit une réclamation d'apparence
transactionnelle, verte en développement, distribuant le même scan à deux processus en
production.

Une garantie de concurrence doit être exécutée contre un vrai serveur pour être une
garantie : voir [04](../04-execution-et-deploiement.md) pour ce que dix réclamants
concurrents ont révélé.
