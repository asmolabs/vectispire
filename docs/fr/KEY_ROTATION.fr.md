# Faire tourner `ENCRYPTION_KEY`

*English version: [`docs/en/KEY_ROTATION.md`](../en/KEY_ROTATION.md).*

`ENCRYPTION_KEY` déchiffre tout ce que Vectispire garde scellé : les clés de déploiement attachées
aux dépôts, les identifiants de registres de conteneurs, les jetons de ticketing, les enveloppes
scellées qu'un agent ouvre. La faire tourner est donc une opération sur des données vivantes, et
cette page en est la procédure.

> **Pourquoi cette page est séparée.** La procédure vivait dans
> la note de travail d'une exposition d'identifiants précise, en août 2026, remplacée depuis par une
> [note d'incident](../analysis/fr/2026-08-06_incident_exposition_identifiants.fr.md). Quelqu'un cherchant « comment faire tourner la clé »
> ouvrait un rapport d'incident et lisait l'histoire d'une fuite. Le récit de l'incident est gardé à part, daté, et la
> partie réutilisable est ici.

## La rotation

Les deux clés sont vivantes en même temps : la nouvelle pour toute écriture, l'ancienne pour les
lectures qui n'ont pas encore migré.

```bash
ENCRYPTION_KEY="<nouvelle clé>" \
VECTISPIRE_PREVIOUS_ENCRYPTION_KEYS="<ancienne clé>" \
cd vectispire-java && ./gradlew :vectispire-core:bootRun
```

L'ancienne clé sert **au déchiffrement uniquement** — toute écriture passe sous la nouvelle. Les
valeurs migrent au fur et à mesure qu'elles sont ré-enregistrées, et la page *Clés SSH* affiche
**« À tourner »** tant qu'une ligne dépend encore de l'ancienne. **L'ancienne clé sort de
l'environnement quand plus aucune ligne ne l'affiche**, pas avant : la retirer trop tôt laisse ces
lignes illisibles sans que rien ne le dise.

Plusieurs clés précédentes peuvent être listées, séparées par des virgules — c'est ce qu'exige une
rotation interrompue.

### Les stockages qui montrent leur état

Trois stockages disent, ligne par ligne, sous quelle clé ils sont scellés (`encryptionState` :
`current`, `previous_key`, `unreadable`), et chacun est rescellé par son propre geste :

| Stockage | Où l'état se voit | Ce qui rescelle une ligne |
|---|---|---|
| Clés de déploiement SSH | la page *Clés SSH*, `GET /api/v1/ssh-keys` | ajouter la clé à nouveau et supprimer l'ancienne ligne |
| Jetons de clonage HTTPS ([0022](../architecture/fr/decisions/0022-https-clone-tokens-are-bound-to-a-host.md)) | `GET /api/v1/git-tokens` | ajouter le jeton à nouveau et supprimer l'ancienne ligne |
| Connexions de forge ([0037](../architecture/fr/decisions/0037-discovering-repositories-at-setup.md)) | `GET /api/v1/forge-connections` | enregistrer la connexion (`PATCH /api/v1/forge-connections/{id}` — un `{}` vide suffit) ou remplacer son jeton (`PUT …/token`) |

La rotation est terminée quand aucun d'eux ne liste de ligne `previous_key`.

## En production, les deux moitiés appartiennent à des fichiers

```bash
ENCRYPTION_KEY_FILE=/run/secrets/vectispire-key
VECTISPIRE_PREVIOUS_ENCRYPTION_KEYS_FILE=/run/secrets/vectispire-previous-keys
```

Un montage de secret Docker ou Kubernetes, et les clés restent hors de `/proc/<pid>/environ`, de
`docker inspect`, des journaux de l'orchestrateur et de l'historique de ce shell. La seconde
variable existe précisément pour ce moment : une rotation est le moment où deux clés sont vivantes
en même temps, et sans elle l'ancienne — qui déchiffre encore de vraies lignes — devrait retourner
dans l'environnement pour achever une rotation dont tout l'objet était d'en sortir la nouvelle.

Le fichier contient la même liste, séparée par des virgules ou des retours à la ligne ; une clé par
ligne est la forme lisible dès lors qu'elle n'est plus comprimée sur une ligne de shell.

**Définir une variable et sa forme `_FILE` ensemble est refusé au démarrage plutôt que départagé**,
de sorte que la migration de l'une vers l'autre est terminée quand vous le croyez. Et un chemin qui
ne résout pas arrête l'application au lieu de démarrer sans clé — ce qui compte ici plus
qu'ailleurs : un déploiement sans clé continue de tout lire et ne refuse que les nouvelles
écritures. En pleine rotation, cela ressemble exactement à un succès.

## Ce qu'une rotation ne couvre pas

- **La chaîne d'audit** est hachée, pas chiffrée. Faire tourner la clé ne la casse ni ne la
  rescelle.
- **Les clés d'agent** sont leurs propres identifiants : elles se révoquent et se réémettent depuis
  la page des agents.
- **Les mots de passe** sont des empreintes Argon2id et n'impliquent pas cette clé ; ils sont
  réécrits sous les paramètres courants à la connexion suivante du compte.
- **Une sauvegarde prise avant la rotation** a toujours besoin de la clé qui était courante au
  moment où elle a été prise. Un instantané et la clé qui l'ouvre sont deux artefacts : gardez-les
  séparés, et gardez l'ancienne clé aussi longtemps qu'une sauvegarde que vous restaureriez encore
  a été écrite sous elle. [Sauvegarde et restauration](BACKUP_AND_RESTORE.fr.md) dit comment les
  deux se prennent, se gardent et se restaurent ensemble.
