# Clés SSH

Des clés de déploiement, pour que Vectispire puisse cloner des dépôts privés.

## En ajouter une

**Clés SSH → ajouter**, collez la moitié privée, et enregistrez la moitié publique chez votre
hébergeur Git avec un accès **en lecture seule**. Vectispire ne pousse jamais.

Le stockage d'une clé est **refusé net** tant que `ENCRYPTION_KEY` ou `ENCRYPTION_KEY_FILE`
n'est pas posé. La moitié privée est chiffrée au repos avec.

## Après une rotation de clé

Changez la clé de chiffrement et les valeurs existantes cessent de se déchiffrer. Déclarez la
clé précédente pour qu'elles se déchiffrent à nouveau :

```bash
VECTISPIRE_PREVIOUS_ENCRYPTION_KEYS=ancienne-cle-1,ancienne-cle-2
# ou, mieux, entièrement hors de l'environnement :
VECTISPIRE_PREVIOUS_ENCRYPTION_KEYS_FILE=/run/secrets/vectispire-previous-keys
```

Les clés précédentes ne sont essayées **qu'au déchiffrement**. Les valeurs migrent vers la
nouvelle clé au fur et à mesure qu'elles sont réenregistrées, et cette page marque les lignes
qui dépendent encore d'une ancienne — ce marquage est ce qui vous dit quand la rotation est
réellement terminée plutôt que seulement commencée.

La forme fichier accepte une liste séparée par des virgules ou des sauts de ligne, pour qu'une
rotation n'ait pas à remettre l'ancienne clé dans l'environnement.

Procédure complète : [Rotation et purge](maintenance.md).

## Une clé affichée « illisible »

Aucune clé configurée ne la déchiffre. Le plus probable est qu'elle précède tout
`ENCRYPTION_KEY` et qu'elle a été chiffrée avec un défaut qui était autrefois livré dans ce
dépôt.

Ce défaut a été retiré, et **sa moitié privée est publique**. N'essayez pas de récupérer la
clé : remplacez la paire chez votre hébergeur Git, puis enregistrez la nouvelle ici.

## Voir aussi

[Dépôts](../guide/repositories.md#credentials) ·
[Agents](agents.md#credentials-modes) — comment une clé déléguée atteint un agent distant, et
ce que cela coûte.
