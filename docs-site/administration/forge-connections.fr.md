# Connexions de forge

Une connexion en lecture seule à un GitHub ou un GitLab, depuis laquelle Vectispire découvrira vos dépôts
et vous laissera choisir ceux à importer ([décision 0037](https://github.com/asmolabs/vectispire/blob/main/docs/architecture/fr/decisions/0037-discovering-repositories-at-setup.md)).
Cette version livre les connexions, la **découverte** des dépôts d'un GitLab — une connexion liste ce que
son jeton peut voir et le garde comme un instantané, comparé d'une exécution à l'autre — puis la
**sélection et l'import** de ces dépôts comme cibles ordinaires. La découverte d'un GitHub vient dans un lot
ultérieur.

Administrateurs seulement : à l'écran sous **Administration → Connexions de forge** ([ci-dessous](#a-lecran)),
et par `/api/v1/forge-connections` ([référence de l'API](https://github.com/asmolabs/vectispire/blob/main/docs/fr/api/rest_api_reference.md)).

## À l'écran

**Administration → Connexions de forge** présente chaque connexion sur une carte : la forge et son adresse,
le type de jeton et les portées que la forge a communiquées, **s'il peut écrire** — *Lecture seule*, *Peut
écrire* (un jeton classique de GitHub Enterprise Server), ou *Non communiqué* pour un jeton GitHub à
granularité fine, ce qui veut dire *inconnu*, pas lecture seule —, l'expiration du jeton (annoncée
**quatorze jours à l'avance**, puis *Expiré*), la déclaration de réseau, l'AC épinglée et sa fin de
validité, l'état de chiffrement, la dernière découverte et le nombre de cibles importées par elle.

- **Ajouter une connexion** : la forge, un nom, l'adresse web (vide pour gitlab.com ou github.com), le
  propriétaire pour GitHub, le jeton. Pour un serveur auto-hébergé, cochez *Ce serveur est sur le réseau
  interne* et collez votre AC en PEM : le formulaire lit le collage avant de l'envoyer et dit en mots ce qui
  ne va pas — une clé privée, pas un certificat, un certificat tronqué, plus de huit — puis le serveur
  vérifie qu'il s'agit d'une AC encore valide. Pour une adresse cloud, aucune des deux options n'est
  proposée. *Vérifier et enregistrer* présente le jeton à la forge ; **un refus s'affiche tel que le
  serveur le formule** — jeton rejeté ou expiré, portée hors des portées de lecture, serveur antérieur à
  GitLab 16 ou GitHub Enterprise Server 3.12, propriétaire inconnu, adresse bloquée par la garde sortante —,
  le reste du formulaire conservé et le jeton effacé.
- **Remplacer le jeton** (la flèche circulaire) : vérifié comme un nouveau ; refusé, le jeton conservé ne
  change pas.
- **Modifier** (le crayon) : le nom, la déclaration de réseau et l'AC — la garder, en épingler une autre ou
  la désépingler. L'adresse ne change pas.
- **Supprimer** (la corbeille) : la confirmation dit combien de cibles importées perdent leur provenance,
  et que **les cibles restent**.

**Découvrir et importer** ouvre la page de la connexion, en trois étapes.

1. **Découvrir.** *Découvrir* met une exécution en file ; la page la suit d'elle-même — toutes les deux
   secondes, puis deux fois plus longtemps chaque fois que rien n'a bougé, jusqu'à trente, et plus du tout
   une fois terminée ou la page quittée — avec ses compteurs : espaces de noms, dépôts, requêtes, secondes
   d'attente des limites de débit, dépôts non conservés. Si une exécution est déjà en cours, la page la nomme
   et propose de la suivre. Une exécution **partielle** dit pourquoi (trente minutes, vingt mille dépôts,
   une limite de débit — avec l'heure où elle est levée) et que rien n'a été marqué disparu ; une exécution
   **échouée** dit pourquoi en mots, avec le détail du serveur en dessous. Une fois terminée, les chiffres
   de la comparaison — *nouveaux*, *modifiés*, *disparus* (exécution terminée seulement), *tous les dépôts
   listés* — ouvrent chacun la liste qu'ils comptent. Les exécutions précédentes sont listées en dessous.
2. **Choisir.** La table de la dernière découverte terminée complète ou partielle, filtrée et paginée par
   le serveur : archivés, forks, espaces personnels, dépôts déjà cibles (chacun masqué, affiché, ou seul
   affiché), visibilité, inactivité en jours, langage, espace de noms et motif de chemin. Sous les filtres,
   ce que chaque filtre **n'a pas pu juger** est compté — GitLab ne nomme la source d'un fork que si le jeton
   peut la lire — avec la règle : un filtre qui masque garde ce qu'il ne peut pas juger, un filtre qui exige
   l'écarte. La sélection part de la proposition, qui laisse **les espaces personnels décochés** ;
   *Proposition*, *Tous ceux retenus*, *Aucun* et *Inverser* s'appliquent à tout ce que les filtres
   retiennent, sur toutes les pages ; une ligne coche un dépôt ; on peut coller des identifiants de forge. Un
   dépôt déjà cible, déjà importé ou vide est grisé avec la raison, et **un identifiant que le serveur n'a
   pas pu cocher est nommé**.
3. **Classer et importer.** Où chaque espace de noms est classé — la proposition, modifiable par espace de
   noms ou, en cochant *Modifier dépôt par dépôt*, par dépôt : une autre solution, un autre projet, ou
   *Aucun projet* ; les noms existants sont suggérés. L'identifiant de clonage par hôte — la proposition,
   aucun, un jeton HTTPS lié à cet hôte ou une clé SSH. *Analyser chaque nouvelle cible une fois maintenant*
   (désactivé par défaut) et les secondes entre deux premières analyses (10 à 600). Puis **Aperçu** : cibles
   créées, dépôts ignorés et pourquoi, dépôts refusés avec la raison du formulaire (l'import est refusé en
   entier tant qu'il y en a un), solutions et projets réutilisés ou créés, l'identifiant et **qui verra
   chaque cible** — les administrateurs, plus les comptes et équipes ayant accès à un projet réutilisé ; les
   cibles d'un nouveau projet ne sont visibles que des administrateurs. Toute modification après l'aperçu en
   demande un nouveau avant que *Importer* ne soit proposé : **ce qui est importé est ce qui a été
   prévisualisé**. Un import en prend au plus mille ; les autres restent cochés pour le suivant.

Le **résultat** liste les cibles créées — chacune liée à ses problèmes et, si elle est en file, à sa
première analyse — et celles ignorées, et renvoie au journal d'audit, où l'import est résumé une fois sous
*Dépôts importés depuis une forge* (`FORGE_IMPORT_APPLIED`).

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
  autre. Ses découvertes, son instantané et la provenance des cibles importées par elle partent avec elle ;
  les cibles restent, et cessent seulement de dire d'où elles viennent.

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
encore. Chaque découverte mise en file est journalisée `FORGE_DISCOVERY_REQUESTED` au nom du demandeur ;
elle n'est pas signalée au SIEM — l'accès permanent est la connexion, signalée `VECTI-SEC-034`.

## Sélectionner et importer

Une fois une découverte terminée **`completed` ou `partial`**, ses dépôts peuvent être sélectionnés et importés
comme des cibles ordinaires. La sélection lit **la dernière découverte de ce genre de la connexion** : une
découverte en attente, en cours ou en échec répond 409 `forge-discovery-not-selectable`, une plus ancienne 409
`forge-discovery-superseded` avec `latestDiscoveryId` — l'instantané décrit désormais l'exécution plus récente.
Une exécution partielle est sélectionnable : ce qu'elle a listé, elle l'a listé entier, et rien n'est déduit de ce
qu'elle n'a pas atteint.

**Le tableau** — `GET …/discoveries/{discoveryId}/selection` — liste les dépôts par chemin complet, 100 par page
(`limit` jusqu'à 500), chacun avec :

- `presentAs` : les cibles qui le déposent déjà. Un dépôt **est déjà présent** quand l'identité de son URL de
  clonage HTTPS *ou* SSH — hôte et chemin, en minuscules, sans schéma, utilisateur, port ni `.git` — égale celle de
  l'URL d'une cible existante, **quels que soient la branche et le sous-chemin de cette cible** : la règle par
  laquelle le formulaire de dépôt refuse un doublon. `git@git.example.org:Acme/API.git` et
  `https://git.example.org/acme/api` sont un seul dépôt, et un monorepo découpé en trois cibles de sous-chemin
  montre trois identifiants.
- `importedAs` : la cible qu'un import précédent depuis cette connexion en a faite — reconnue par l'identifiant de
  GitLab, si bien qu'un dépôt renommé sur la forge reste cette cible.
- `selectable`, et `notSelectable` quand il ne l'est pas : `already_imported`, `already_present`,
  `no_default_branch` (un dépôt vide : rien à cloner encore), `no_clone_url`.
- `offered` : si la sélection le propose coché — sélectionnable, ni archivé, ni fork, et **pas dans un espace de
  noms personnel**, proposé décoché.
- `proposedSolution` et `proposedProject`, ci-dessous.

**Filtres** : `archived` et `forks` (`hide` par défaut, `show`, `only`), `inactiveDays` (masque une dernière
activité plus ancienne), `language`, `visibility`, `namespace` (ce groupe et tout ce qui est en dessous), `path` (un
motif — `acme/payments/*`, `*` une suite quelconque de caractères, `?` un seul — ou, sans l'un ni l'autre, une
recherche), `personal` et `present` (`show` par défaut, `hide`, `only`). **Un filtre ne juge jamais ce que GitLab
n'a pas dit** : celui qui masque garde un dépôt qu'il ne peut juger, celui qui exige l'écarte, et `unjudged` les
compte par filtre — GitLab ne nomme la source d'un fork que si le jeton peut la lire, si bien que la plupart des
dépôts n'ont aucune indication de fork, et les masquer masquerait l'essentiel du parc.

**La sélection** est un ensemble d'identifiants GitLab que l'écran garde ; ce qui est importé est ce qui a été coché,
jamais ce qu'un filtre retient au moment de l'import. `POST …/discoveries/{discoveryId}/selection` applique une
opération à ce que les filtres retiennent — `proposed`, `all`, `none`, `invert`, ou `add` et `remove` avec
`forgeIds` — et répond la sélection, en retirant (et en nommant dans `dropped`) tout identifiant qui ne peut être
coché.

**Où chaque dépôt est rangé — proposé, montré, modifiable.** GitLab : le groupe de premier niveau est la solution,
et le groupe parent du dépôt sous lui le projet (`acme/backend/payments/api` → solution `acme`, projet
`backend/payments`) ; un dépôt directement sous le groupe de premier niveau va dans un projet nommé d'après ce
groupe. Un espace de noms personnel : aucun projet. Une solution ou un projet **du même nom** (casse mise à part)
est réutilisé, jamais renommé ni déplacé. Une règle `mapping` change la proposition pour un espace de noms et tout ce
qui est en dessous, ou pour un dépôt par son `forgeId` : une autre `solution`, un autre `project`, ou `noProject`.
La règle la plus précise l'emporte sur chaque champ, si bien que renommer la solution d'`acme` garde le projet de
chaque sous-groupe.

**L'aperçu** — `POST …/imports/preview`, rien n'est écrit — dit ce que l'import ferait : les cibles avec leur URL,
leur branche par défaut, leur identifiant de clonage, leur solution et leur projet, et **qui les verra**
(`visibleTo`) : les administrateurs, plus les comptes et équipes ayant un droit sur un projet réutilisé, comptés ;
un nouveau projet n'a encore aucun droit, ses cibles sont donc *visibles des seuls administrateurs* jusqu'à ce que
quelqu'un en accorde un — ou, quand la visibilité n'est pas restreinte sur votre installation, de chaque compte
connecté. Il liste les dépôts écartés et pourquoi, ceux que l'import refuserait avec la raison du formulaire, les
solutions et projets réutilisés (`existingId`) ou créés, l'identifiant de clonage par hôte, la planification par
défaut et les premiers scans.

**L'import** — `POST …/imports`, le corps de l'aperçu :

- **Au plus 1 000 dépôts, en une transaction** : tout est créé ou rien. Une sélection plus grande fait plusieurs
  imports.
- **Par les gestes mêmes des formulaires** : les mêmes refus (un hôte hors de la liste autorisée, un jeton présenté
  à un autre hôte…) et les mêmes entrées d'audit qu'un dépôt, une solution ou un projet ajouté à la main. Un dépôt
  que le formulaire refuserait fait refuser l'import — 400 nommant les premiers ; l'aperçu les liste tous.
- **Replanifié dans sa transaction.** Ce qui est devenu une cible depuis l'aperçu est écarté (`already_present`,
  `already_imported`) ; **rejouer un import ne crée rien**. Deux administrateurs important la même sélection en même
  temps créent chaque cible une fois : le second import attend la clé du premier, puis écarte ce qu'il a créé.
- **L'identifiant de clonage, par hôte** (`credentials` : `host`, puis `sshKeyId` ou `httpsTokenId`). Une clé SSH
  clone par l'URL SSH de GitLab ; un [jeton HTTPS](../guide/repositories.fr.md) — lié à cet hôte — par son URL HTTPS ;
  aucun, par l'URL HTTPS, pour les dépôts publics. Un hôte que vous ne nommez pas prend la proposition : **l'unique
  jeton HTTPS lié à cet hôte quand il y en a exactement un**, aucun sinon. Un dépôt privé importé sans identifiant
  est permis et signalé — ses scans échoueront avec *requires authentication*. **Le jeton de la connexion ne clone
  jamais** : il peut lister l'organisation, il n'est pas envoyé aux agents.
- **Branche** : la branche par défaut de GitLab à la découverte. Un changement ultérieur de branche par défaut
  apparaît comme *changed* à la découverte suivante ; la cible n'est pas modifiée.
- **Planification** : aucune qui lui soit propre, la planification par défaut de l'installation s'applique donc — et
  chaque nouvelle cible la prend **à son propre créneau dans la semaine qui vient**, pas toutes au tic suivant.
- **Premier scan** : désactivé par défaut. Avec `firstScan`, le premier scan de chaque nouvelle cible est mis en file
  et retenu pour qu'ils atteignent GitLab un par un : le *k*-ième attend *k* × `spacingSeconds` (60 par défaut, de 10
  à 600). Trois cents dépôts au défaut font cinq heures de clonages.
- **Aucun droit.** Les nouvelles cibles sont visibles des administrateurs et de quiconque détient un droit sur le
  projet où elles sont rangées. Accorder reste l'affaire de son propre écran.

Le résultat liste ce qui a été créé — l'identifiant, l'URL, la solution, le projet et le premier scan de chaque
cible — et ce qui a été écarté. `importedTargets` de la connexion compte les cibles importées par elle qui
existent encore.

**Provenance.** Chaque cible importée est liée à sa connexion et à l'identifiant de GitLab. Supprimer la cible
supprime le lien — le dépôt est de nouveau proposé ; supprimer la connexion supprime chaque lien et aucune cible.

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
| Une découverte mise en file — jamais une demande refusée parce qu'une autre tourne déjà | `FORGE_DISCOVERY_REQUESTED` (la connexion, l'identifiant de la découverte, le demandeur) | — |
| Une découverte arrêtée par une page suivante sur une autre origine, ou une adresse que la garde refuse | `FORGE_CONNECTION_REFUSED` | `VECTI-SEC-036` (5, échec) |
| Un import : chaque cible, solution et projet créé | `SETTING_UPDATED` (*Repository added: … — imported from connection …*), `SOLUTION_UPDATED`, `PROJECT_UPDATED` | — |
| Un import, une fois, résumé : comptes, dépôts écartés, premiers scans, identifiants par hôte | `FORGE_IMPORT_APPLIED` | `VECTI-SEC-035` (5) quand il a créé quelque chose |

Les entrées nomment la forge, l'adresse, le propriétaire, le type de jeton, ses portées et s'il peut
écrire ; jamais le jeton. Voir le [catalogue SIEM](../integrations/siem.fr.md#catalogue-des-evenements).
