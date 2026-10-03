# Connexions de forge

Une connexion en lecture seule à un GitHub ou un GitLab, depuis laquelle Vectispire découvrira vos dépôts
et vous laissera choisir ceux à importer ([décision 0037](https://github.com/asmolabs/vectispire/blob/main/docs/architecture/fr/decisions/0037-discovering-repositories-at-setup.md)).
Cette version livre les connexions et la **découverte** des dépôts d'un GitLab : une connexion liste ce
que son jeton peut voir et le garde comme un instantané, comparé d'une exécution à l'autre. Le choix des
dépôts et leur import comme cibles viennent dans les lots suivants, de même que la découverte d'un GitHub.

Administrateurs seulement, par `/api/v1/forge-connections` ([référence de l'API](https://github.com/asmolabs/vectispire/blob/main/docs/fr/api/rest_api_reference.md)).
Il n'y a pas encore d'écran.

## Ce qu'est une connexion

Un nom, une forge (`github` ou `gitlab`), son **adresse web** — celle de la barre d'adresse du
navigateur, `https` seulement — et un jeton. Laissez l'adresse vide pour github.com ou gitlab.com. Pour
GitHub, aussi le **propriétaire** : l'organisation ou l'utilisateur pour qui le jeton a été émis.

| Vous utilisez | Adresse à saisir | API atteinte |
|---|---|---|
| gitlab.com | *(vide)* | `https://gitlab.com/api/v4` |
| GitLab autogéré ou Dedicated | `https://gitlab.example.org` (un préfixe comme `/gitlab` est gardé) | `…/api/v4` |
| github.com | *(vide)* | `https://api.github.com` |
| GitHub Enterprise Cloud avec résidence des données | `https://acme.ghe.com` | `https://api.acme.ghe.com` |
| GitHub Enterprise Server | `https://github.example.org` | `…/api/v3` |

Ne saisissez pas l'adresse de l'API : `…/api/v4` est refusée avec l'adresse à saisir à la place.

**Le jeton de la connexion ne clone jamais.** Les identifiants de clonage restent les
[clés SSH](ssh-keys.fr.md) et jetons HTTPS que vous gérez déjà, choisis par hôte à l'import : le jeton de
découverte est en lecture seule, reste dans le plan de contrôle et n'est jamais envoyé à un agent.

## Le jeton à créer

| Forge | Créer | Accorder |
|---|---|---|
| GitLab | un **jeton d'accès de groupe** — un membre robot qui survit à la personne qui l'a créé — ou un jeton d'accès personnel ; rôle **Reporter** sur les groupes à découvrir | **`read_api`** seulement |
| GitHub (github.com, ghe.com, les Enterprise Server qui les proposent) | un jeton d'accès personnel **fine-grained**, propriétaire de ressource = celui de la connexion, accès *All repositories* ou une sélection | **Metadata: read**, et rien d'autre |
| GitHub Enterprise Server sans jetons *fine-grained* | un jeton d'accès personnel classique | `repo` (pour lister les dépôts privés) et `read:org` |

**GitLab : `read_api`, et seulement des portées de lecture.** Le jeton est accepté avec `read_api` plus,
au plus, `read_repository`, `read_registry` ou `read_user`. Toute autre — `api`, `write_repository`,
`sudo`, `admin_mode`, les portées runner et Kubernetes, et toute portée que GitLab ajoutera — refuse la
connexion : la liste est une liste d'autorisation. La connexion indique si le jeton est un jeton de groupe
ou de projet (`gitlab_bot`) ou celui d'une personne (`gitlab_personal`) ; préférez le premier.

**Jetons GitHub *fine-grained* : Vectispire ne peut pas vérifier leurs permissions.** GitHub ne les
déclare pas par son API. La connexion montre `scopes: null` et `canWrite: null` — *inconnu*, pas *lecture
seule*. N'accordez que **Metadata: read** ; c'est une phrase, pas une vérification.

**Les jetons GitHub classiques ne sont acceptés que sur Enterprise Server, et signalés.** Sur github.com
et ghe.com un jeton classique est refusé : la seule portée classique qui liste les dépôts privés, `repo`,
peut aussi écrire dans chacun d'eux, et un jeton *fine-grained* y est toujours disponible. Sur Enterprise
Server un jeton classique portant `repo` ou `public_repo` est accepté et affiché **`canWrite: true`** —
dans la liste, l'entrée d'audit et l'événement SIEM. Les portées d'administration (`admin:org`,
`delete_repo`, `workflow`, les portées de paquets…) sont refusées.

**Ce qui reste, écrit plutôt que caché.** Un jeton classique `repo` de GitHub Enterprise Server peut
écrire. Le `read_api` de GitLab peut aussi lire des fichiers par l'API. La connexion est un accès
permanent en lecture à la liste des dépôts d'une organisation, détenu par le plan de contrôle.

## Sondé avant d'être gardé

À la création, et chaque fois que le jeton ou la façon de le présenter change, Vectispire présente le
jeton une fois à la forge et lit ce qu'elle en dit :

- **GitLab** : `GET /api/v4/personal_access_tokens/self` (portées, expiration, révocation),
  `GET /api/v4/version` (**GitLab 16 ou ultérieur**), `GET /api/v4/user` (robot ou personne). Un jeton
  portant une portée refusée n'est pas présenté une deuxième fois.
- **GitHub** : `GET /users/{owner}` — les portées d'un jeton classique, l'expiration du jeton et, sur
  Enterprise Server, sa version (**3.12 ou ultérieure**) arrivent en en-têtes. Un 404 signifie que le
  propriétaire n'existe pas ou est caché à ce jeton.

Un refus dit pourquoi en mots : jeton rejeté ou expiré, `read_api` absente, une portée refusée, un serveur
trop ancien, un propriétaire inconnu, ou une adresse injoignable.

## Sur votre réseau interne, derrière votre propre AC

Un GitLab autogéré ou un GitHub Enterprise Server sur le réseau interne est le cas courant.

- **Dites-le : cochez *réseau interne*** (`internalNetwork: true`). Sans cela l'adresse doit être
  publique : une adresse qui se résout dans une plage privée ou locale est refusée **avant que rien ne
  soit envoyé**, et le refus est journalisé et signalé au SIEM (`VECTI-SEC-036`) — une URL de base
  pointée vers l'intérieur est l'allure qu'aurait une falsification de requête côté serveur par ce
  formulaire. Avec, les adresses privées sont acceptées ; le lien local (le point de métadonnées du
  cloud), la base de Vectispire et son démon Docker restent refusés quoi que vous cochiez. L'adresse est
  revérifiée à chaque requête, car un nom peut se résoudre ailleurs demain.
- **Épinglez votre AC** (`caPem`) : collez l'AC qui a émis le certificat du serveur, en PEM. Ce doit être
  une AC (le certificat propre du serveur est refusé), valide aujourd'hui, et huit certificats au plus.
  Elle est approuvée **pour cette seule connexion, à la place des AC publiques**, et le certificat du
  serveur doit toujours nommer l'hôte saisi. Il n'y a **pas d'interrupteur « ignorer la vérification »**
  et il n'y en aura pas : le jeton partirait vers le premier qui répond sur le chemin.
- Ni l'un ni l'autre ne s'appliquent à github.com, ghe.com ou gitlab.com : leurs hôtes sont publics et
  vérifiés contre les AC publiques, et les deux leur sont refusés.

Une AC qui expire arrête la connexion ; remplacez-la par un `PATCH`, qui sonde à nouveau le jeton stocké
à travers la nouvelle AC avant de la garder.

## Rotation, modifications et suppression

- **Remplacer le jeton sur place** (`PUT …/token`) : il est sondé comme un nouveau, et la connexion garde
  son identité et tout ce qui s'y rattachera. Un remplaçant que la forge refuse laisse le jeton stocké
  intact. L'expiration déclarée par la forge est affichée (`tokenExpiresAt`).
- **Renommer, changer la déclaration de réseau ou l'AC** (`PATCH`). L'adresse ne change pas : un autre
  serveur est une autre connexion.
- **Supprimer** (`DELETE`) : aucune cible ne part avec elle — un dépôt importé est une cible comme une
  autre. Ses découvertes et son instantané partent avec elle.

## Découvrir les dépôts

`POST /api/v1/forge-connections/{id}/discoveries` demande une découverte et répond aussitôt, **202**, avec
l'exécution — `pending`. Une instance du plan de contrôle la prend en quelques secondes et liste la forge en
arrière-plan ; interrogez `GET …/discoveries/{discoveryId}` pour suivre sa progression. GitLab seulement
dans cette version : une connexion GitHub répond 409 `forge-discovery-unsupported` jusqu'à l'arrivée de son
listage.

**Ce qui est listé (GitLab).** Les groupes dont le jeton est membre (`GET /groups?min_access_level=10`),
puis chaque projet dont il est membre (`GET /projects?membership=true&min_access_level=10&statistics=true`,
pages *keyset* par identifiant), puis le langage principal de chaque projet nouveau ou actif depuis sa
dernière lecture (`GET /projects/:id/languages`). Les deux paramètres ne sont pas optionnels : sans eux,
gitlab.com liste tous les projets publics du service. Un jeton voit ce que son rôle lui laisse voir —
donnez-lui **Reporter** sur les groupes à découvrir ; les projets d'un Guest sont listés quand même, sans
leur taille ni, pour les privés, leur langage.

**Ce qui est gardé par dépôt** : l'identifiant GitLab (stable aux renommages et aux déplacements), le chemin
complet, l'espace de noms, le nom, la branche par défaut, archivé, fork, visibilité, dernière activité,
langage principal, taille, et les URL HTTPS, SSH et web. **Une valeur que GitLab n'a pas donnée reste vide —
*inconnue*, jamais zéro** : pas de taille sans Reporter, pas de langage quand sa requête est refusée, pas de
branche par défaut pour un dépôt vide, et *fork* seulement quand GitLab nomme le projet source (il ne le
nomme que si le jeton peut le lire). Un dépôt dans l'espace personnel d'un utilisateur est listé et marqué
`personal` : la sélection le proposera décoché.

**Ses états.**

| État | Signification |
|---|---|
| `pending` | en attente d'une instance — ou reprise après l'arrêt de l'instance qui l'exécutait |
| `running` | en cours de listage ; les compteurs avancent : espaces de noms et dépôts vus, requêtes faites, secondes d'attente sur les limites de débit |
| `completed` | toutes les pages ont été lues ; les dépôts qui ne sont plus listés sont marqués **disparus** |
| `partial` | une borne l'a arrêtée (ci-dessous) ; ce qui a été lu est gardé et comparé, **rien n'est marqué disparu** |
| `failed` | `token_rejected` (401 : remplacez le jeton), `forge_refused` (un listage a répondu 403 ou 404 : le jeton doit avoir `read_api`), `forge_unavailable` (pas de réponse après trois essais), `destination_blocked`, `cross_origin_page`, `connection_unusable` (le jeton ne se déchiffre plus, ou l'AC épinglée a expiré), `executor_lost`, `internal_error` |

**Une découverte par connexion à la fois** : une seconde demande répond 409
`forge-discovery-in-progress`, avec le `discoveryId` de celle en cours.

**Bornes.** Trente minutes et vingt mille dépôts par exécution ; au-delà de l'une ou l'autre, l'exécution
finit `partial` (`time_bound`, `repository_bound`). Une limite de débit est respectée, jamais devancée : une
attente d'au plus une minute (`Retry-After`, `RateLimit-Reset`) est passée dans l'exécution ; une plus longue
la termine `partial`, `rate_limited`, `rateLimitResetAt` disant quand la relancer. Un serveur qui ne répond
pas est réessayé trois fois avec un délai croissant, dix secondes par requête, puis l'exécution échoue.

**La comparaison.** Chaque exécution est comparée à l'instantané laissé par les précédentes. Une fois
terminée, `newCount`, `changedCount` et `goneCount` disent comment il a bougé, et
`GET …/discoveries/{discoveryId}/repositories` liste les dépôts (`change=all`), les nouveaux (`new`), ceux
renommés ou déplacés, changés de branche par défaut, archivés, désarchivés ou revenus après avoir disparu
(`changed`, avec `changeSummary`), et ceux qui ne sont plus listés (`gone`). **Seule une exécution complète
marque un dépôt disparu** — un listage partiel ne prouve rien de ce qu'il n'a pas atteint : son `goneCount`
est vide et `change=gone` est refusé. **Rien n'est jamais supprimé de l'instantané**, sauf avec la
connexion : un dépôt disparu ou archivé reste, et une cible importée depuis lui garde son historique.

**La même porte que la sonde.** Chaque requête passe par la garde sortante — l'adresse revérifiée à chaque
requête, privée seulement si vous avez déclaré le serveur interne — et par l'AC que vous avez épinglée. **La
page suivante n'est suivie que sur le schéma, l'hôte et le port de la connexion** : une page pointant
ailleurs fait échouer l'exécution avant que rien n'y soit envoyé, journalisé `FORGE_CONNECTION_REFUSED` et
signalé `VECTI-SEC-036` ; de même pour une adresse que la garde refuse désormais. Le jeton est déchiffré
pour l'exécution et ne quitte jamais le plan de contrôle — une découverte tourne sur le plan de contrôle, sur
chaque instance, quel que soit l'interrupteur du worker intégré, jamais sur un agent. Un redémarrage en cours
reprend l'exécution depuis sa première page ; après trois tentatives perdues, elle échoue `executor_lost`.

**Administrateurs seulement**, comme la connexion : une découverte nomme des dépôts qu'aucun droit ne couvre
encore.

## Chiffrement

Le jeton est chiffré sous `ENCRYPTION_KEY` avec la ligne pour contexte, si bien qu'un chiffré copié dans
une autre ligne ne se déchiffre pas. Il n'est jamais renvoyé par une route, écrit dans la piste d'audit ni
journalisé. `encryptionState` vaut `previous_key` tant qu'une [rotation de clé](maintenance.fr.md) n'a pas
atteint la ligne : **enregistrer la connexion** (tout `PATCH`) ou remplacer son jeton le rescelle sous
la clé courante.

## Audit et SIEM

| Geste | Audit | SIEM |
|---|---|---|
| Créée, jeton remplacé, déclaration de réseau ou AC changée, supprimée | `FORGE_CONNECTION_CHANGED` | `VECTI-SEC-034` (6) |
| Renommée | `FORGE_CONNECTION_CHANGED` | — |
| Refusée pour une adresse bloquée ou une portée refusée | `FORGE_CONNECTION_REFUSED` | `VECTI-SEC-036` (5, échec) |
| Refusée pour autre chose — un jeton mal saisi, un serveur ancien | — | — |
| Une découverte arrêtée par une page suivante sur une autre origine, ou une adresse que la garde refuse | `FORGE_CONNECTION_REFUSED` | `VECTI-SEC-036` (5, échec) |

Les entrées nomment la forge, l'adresse, le propriétaire, le type de jeton, ses portées et s'il peut
écrire ; jamais le jeton. Voir le [catalogue SIEM](../integrations/siem.fr.md#catalogue-des-evenements).
