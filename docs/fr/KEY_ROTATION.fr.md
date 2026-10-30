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

L'ancienne clé sert **au déchiffrement uniquement** — toute écriture passe sous la nouvelle.
**L'ancienne clé sort de l'environnement quand plus aucun stockage scellé n'en dépend**, pas avant :
la retirer trop tôt laisse ces valeurs illisibles — seconds facteurs refusés à la connexion, plus
rien de signé, l'en-tête d'autorisation du SIEM abandonné — sans que rien ne le dise.

Plusieurs clés précédentes peuvent être listées, séparées par des virgules — c'est ce qu'exige une
rotation interrompue.

### Où en est la rotation : `/actuator/encryption`

Un seul rapport, pour une session d'administrateur, liste chaque stockage que Vectispire garde
scellé et combien de ses valeurs sont sous la clé courante, sous une précédente, sous aucune
(`unreadable`), ou en clair parce qu'antérieures au chiffrement :

```bash
curl -s -H "Authorization: Bearer <session d'un administrateur>" https://vectispire.example.com/actuator/encryption
```

**La rotation est terminée quand il répond `"rotationFinished": true`** — aucun stockage n'a de
`previousKey` au-dessus de zéro. D'ici là, chaque démarrage journalise aussi un avertissement par
stockage qui dépend encore d'une clé précédente, en nommant ce qui le rescelle. Le rapport dit
combien de valeurs sont où, jamais ce qu'elles contiennent.

| Stockage | Ce qui rescelle une valeur encore sous une clé précédente |
|---|---|
| Clés de déploiement SSH | ajouter la clé à nouveau, y déplacer les dépôts, supprimer l'ancienne ligne (la page *Clés SSH* et `GET /api/v1/ssh-keys` montrent l'état de chaque ligne) |
| Jetons de clonage HTTPS ([0022](../architecture/fr/decisions/0022-https-clone-tokens-are-bound-to-a-host.md)) | ajouter le jeton à nouveau, y déplacer les dépôts, supprimer l'ancienne ligne (`GET /api/v1/git-tokens`) |
| Jetons des connexions de forge ([0037](../architecture/fr/decisions/0037-discovering-repositories-at-setup.md)) | enregistrer la connexion (`PATCH /api/v1/forge-connections/{id}` — un `{}` vide suffit) ou remplacer son jeton (`PUT …/token`) |
| Clé de signature des documents | le démarrage suivant, de lui-même |
| Secrets TOTP et codes de secours | la vérification suivante du second facteur du compte — une connexion, ou une désactivation —, d'elle-même ; ou un nouvel enrôlement |
| Jeton d'accès au tracker, secret du webhook entrant du tracker | le reposer dans les réglages de ticketing (et, pour le secret du webhook, dans le tracker) |
| Secret de signature du webhook de notification | le reposer dans les réglages de notification, et chez le destinataire |
| Clé d'API OpenAI | la reposer dans les réglages de la revue par modèle |
| En-tête d'autorisation SIEM | le reposer dans les réglages SIEM |

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

# Faire tourner la clé de signature des documents

La **clé de signature des documents** est une autre clé, et faire tourner `ENCRYPTION_KEY` ne la
touche pas. Elle signe ce que Vectispire remet à des personnes extérieures — paquets de preuves,
exports VEX, CSAF et CycloneDX, approbations de checklist, exports de projet et provenance des
documents de rapport — et ces destinataires les vérifient contre la moitié publique que Vectispire
publie. La faire tourner change ce qu'ils doivent croire : la procédure les concerne surtout eux.

Elle vient de l'un de deux endroits : `vectispire.signing.key` (un PEM PKCS#8 P-256 :
`VECTISPIRE_SIGNING_KEY` dans le `.env` de la composition, `secrets.signingKey` dans le chart) ou,
quand il est vide, une clé que Vectispire a générée au premier usage et garde dans `t_setting`,
scellée sous `ENCRYPTION_KEY`.

## Ce que deviennent les documents signés avant

**Ils restent vérifiables.** Chaque clé publique avec laquelle ce déploiement a signé est
enregistrée — les moitiés publiques seulement, en clair, dans `t_setting`
(`internal.document_signing_keys`) — et publiée :

| Route (sans compte) | Répond |
|---|---|
| `GET /api/v1/crypto/public-key.pub` | la clé **active**, comme avant |
| `GET /api/v1/crypto/public-keys` | toutes les clés : `keyId`, `status` (`ACTIVE`, `RETIRED`, `REVOKED`), `publicKey` (PEM), `activeFrom`, `retiredAt` |
| `GET /api/v1/crypto/public-keys/<keyId>.pub` | l'une d'elles, dans le PEM que lit `cosign verify-blob --key` |

L'identifiant d'une clé est le SHA-256 de son encodage DER, en hexadécimal. Un document nomme la clé
qui l'a signé : le `keyid` d'une enveloppe DSSE, la clé jointe à un paquet de preuves (par commodité
seulement — calculez son identifiant, puis demandez cet identifiant à l'instance), le
`signing_key_id` qu'enregistrent un document de checklist et une exécution de rapport.
`POST /api/v1/crypto/verify` essaie la clé active, puis les clés retirées, et dit laquelle
correspond (`keyId`, `keyStatus`).

**L'enregistrement commence au premier démarrage d'une version qui l'a (1.0.0).** Une clé remplacée
avant n'y figure pas. Démarrez une fois en 1.0.0 avec la clé que vous avez, vérifiez qu'elle est
listée `ACTIVE`, et seulement ensuite faites la rotation.

## La rotation

Exécutée chaque nuit, telle qu'écrite ici, par `scripts/signing-key-rotation-drill.sh` contre l'image
livrée : un dossier de preuves signé avant la rotation est vérifié avec openssl contre la clé publiée
sous son identifiant, et un dossier signé après contre la clé active.

**1. Générez la nouvelle clé**, là où elle sera gardée :

```bash
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out vectispire-signing-key.pem
```

**2. Notez la clé en usage**, pour la reconnaître ensuite :

```bash
curl -s https://vectispire.example.com/api/v1/crypto/public-keys
```

**3. Configurez la nouvelle clé et redémarrez.** Avec la composition, mettez le PEM dans `.env` en
`VECTISPIRE_SIGNING_KEY` (il arrive dans le conteneur comme un fichier) ; avec le chart,
`secrets.signingKey` ; sinon `vectispire.signing.key`, ou un fichier de ce nom dans le répertoire
que lit `SPRING_CONFIG_IMPORT=configtree:`. Une clé configurée l'emporte toujours sur la clé
stockée. Avec plusieurs instances, redémarrez-les toutes : jusqu'à ce que la dernière ait
redémarré, les anciennes signent encore avec l'ancienne clé, et ces signatures se vérifient comme
celles d'une clé retirée.

**4. Vérifiez.** La même requête liste maintenant la nouvelle clé `ACTIVE` et la précédente
`RETIRED`, avec la date de son remplacement. Quand la précédente était la clé générée, elle est
listée aussi : c'est celle qui a signé tous les documents jusqu'ici.

**5. Prévenez les destinataires.** Quiconque a épinglé `public-key.pub` doit la récupérer à
nouveau ; quiconque vérifie un document plus ancien récupère la clé qu'il nomme sur
`public-keys/<keyId>.pub`. La liste sert mieux les destinataires qu'une clé unique : c'est elle qui
leur permet de vérifier un document d'avant une rotation sans vous demander de quelle clé il
s'agissait.

**6. L'ancienne clé privée.** La vérification n'a besoin que de la moitié publique, que Vectispire
garde. Le fichier d'une clé configurée peut être détruit dès que vous ne reviendrez plus en
arrière ; retirer à nouveau `vectispire.signing.key` rend active la clé stockée — ou une clé
nouvellement générée s'il n'y en avait pas — et la clé qu'elle remplace est retirée à son tour. Une
clé générée reste scellée dans `t_setting` et continue d'apparaître dans `/actuator/encryption` ;
elle ne signe rien tant qu'une clé est configurée.

## Quand la clé est compromise

Faites la rotation comme ci-dessus, et listez l'identifiant de la clé compromise dans
`vectispire.signing.revoked-keys` (`VECTISPIRE_SIGNING_REVOKED_KEYS`, séparés par des virgules) sur
chaque instance :

- elle reste publiée, `status: REVOKED`, pour qu'un destinataire apprenne pourquoi un document ne se
  vérifie plus ;
- `POST /api/v1/crypto/verify` répond `valid: false` pour une signature qu'elle a faite, même si
  elle correspond : qui la détient peut tout signer ;
- une instance configurée pour signer avec une clé révoquée refuse de démarrer.

Réémettez ensuite les documents qui comptent encore — exportez-les à nouveau — et dites à leurs
destinataires lesquels remplacent lesquels. Une révocation ne vaut que par les destinataires qui
consultent la liste : raison de plus pour les y renvoyer plutôt qu'à un fichier unique.

## Avec `ENCRYPTION_KEY`

Les deux rotations sont indépendantes ; faites-les l'une après l'autre, pour que le rapport de
chacune dise de quoi il parle.

- **Faire tourner `ENCRYPTION_KEY`** rescelle la clé de signature générée au démarrage suivant, et
  `/actuator/encryption` la compte comme *Document signing key*. La clé de signature elle-même ne
  change pas, et aucun destinataire ne le remarque.
- **Perdre `ENCRYPTION_KEY`** rend illisible une clé de signature générée : la signature est
  refusée plutôt qu'une nouvelle clé improvisée. Configurez une nouvelle clé de signature : c'est
  une rotation. Les clés publiées ne sont pas scellées, donc les documents signés avant restent
  vérifiables bien que la clé qui les a signés soit perdue.
- **L'enregistrement des clés publiques n'est pas un secret** et n'est pas dans
  `/actuator/encryption`. Il est dans la base, donc dans chaque sauvegarde : une restauration
  ramène les clés publiées au moment où elle a été prise.
