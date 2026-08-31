# Rotation et purge

## Faire tourner la clé de chiffrement

`ENCRYPTION_KEY` protège les clés de déploiement et les jetons de tracker au repos. La faire
tourner est une opération en quatre étapes, sans interruption de service.

**1. Garder l'ancienne clé lisible.**

```bash
ENCRYPTION_KEY_FILE=/run/secrets/vectispire-key-new
VECTISPIRE_PREVIOUS_ENCRYPTION_KEYS_FILE=/run/secrets/vectispire-keys-old
```

Les clés précédentes ne sont essayées **qu'au déchiffrement**. Jamais à l'écriture.

**2. Redémarrer.** Les valeurs existantes se déchiffrent avec une ancienne clé ; les nouvelles
écritures utilisent la nouvelle.

**3. Réenregistrer les secrets.** Les valeurs migrent vers la nouvelle clé au fur et à mesure
qu'elles sont réenregistrées. La page [Clés SSH](ssh-keys.md) marque les lignes qui dépendent
encore d'une ancienne clé — ce marquage est ce qui vous dit que la rotation est terminée plutôt
que seulement commencée.

**4. Retirer l'ancienne clé** de la liste des clés précédentes une fois que plus rien n'est
marqué.

Ne repoussez pas indéfiniment l'étape 4. Une rotation qui laisse l'ancienne clé lisible en
permanence a changé quelle clé est écrite, et rien d'autre.

!!! warning "Les clés antérieures à tout ENCRYPTION_KEY"
    Une valeur chiffrée avec le défaut autrefois livré dans ce dépôt s'affichera comme
    illisible. Ce défaut a été retiré et **sa moitié privée est publique**. Remplacez la paire
    de clés chez votre hébergeur Git plutôt que d'essayer de la récupérer.

## Le fichier plutôt que l'environnement

`ENCRYPTION_KEY_FILE` plutôt qu'`ENCRYPTION_KEY`, en production, toujours. Cela garde la valeur
hors de `/proc/<pid>/environ`, de `docker inspect` et des journaux de votre orchestrateur, et
c'est ce qu'un secret Docker ou Kubernetes monte nativement.

Poser les deux est refusé. Un chemin qui ne résout pas arrête l'application plutôt que de la
démarrer sans clé — un démarrage qui se poursuivrait silencieusement sans clé refuserait toute
écriture de secret des heures plus tard, à un endroit sans rapport.

## Rétention et purge

Les scans s'accumulent : constats normalisés, plus le SBOM brut et la sortie du moteur de
rapprochement, conservés pour l'audit. La rétention se configure sous [Réglages](settings.md).

Deux choses à mettre en balance :

**Les blobs bruts sont la partie volumineuse.** Ce sont aussi les preuves dont quelqu'un a
besoin pour re-dériver vos conclusions plutôt que de les prendre sur parole.

**Purger un scan ne purge pas l'issue.** Les issues suivent les problèmes d'un scan à l'autre
et portent leur propre historique et leurs décisions de triage. Le registre de ce qui a été
décidé survit au registre de l'exécution qui l'a observé en premier.

## Avant de supprimer une cible

Retirer un dépôt ou une image retire ses scans et son historique d'issues avec lui. Exportez
d'abord l'[historique de détection et de triage](../guide/history.md) là où ce registre doit
survivre — il est écrit précisément pour le lecteur qui n'était pas là.
