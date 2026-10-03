# 0037 — Les dépôts sont découverts par une connexion de forge en lecture seule, choisis par une personne, et importés comme des cibles ordinaires

**Date :** 2026-10-03 · **Statut :** acceptée · **S'appuie sur :** [0002](0002-the-database-carries-the-queue.md), [0022](0022-https-clone-tokens-are-bound-to-a-host.md), [0023](0023-solutions-projects-and-repositories.md), [0025](0025-siem-events-leave-through-the-outbox.md), [0030](0030-modulith-verifies-the-module-boundaries.md) · **Décideur :** Laurent Boucher

*Acceptée le 2026-10-03 par le responsable produit, chaque question ouverte tranchée comme recommandé —
les réponses sont à la fin, sous « Tranché le 2026-10-03 », et le corps ci-dessous est écrit tel que
décidé. Bitbucket est le lot qui suit le premier (D8) ; la v1 est GitHub et GitLab.*

## Contexte

La demande du responsable produit, le 2026-10-03 : *initialiser l'outil en trouvant les projets dans
GitLab, GitHub et Bitbucket, et me laisser choisir ceux que je veux.*

Aujourd'hui, un dépôt devient une cible d'une seule manière : un administrateur remplit un formulaire —
URL, branche, identifiant, planification — et `RepositoryAdministrationService` crée une ligne
(`@RequiresAdministrator` sur `POST /api/v1/repositories`). Un parc de trois cents dépôts, c'est trois
cents formulaires, et rien ne dit à l'administrateur quels dépôts il n'a pas encore ajoutés. La première
semaine d'une installation se passe à taper des URL, et la couverture obtenue est ce dont la personne
s'est souvenue. Un outil de posture qui ne voit que ce que quelqu'un a pensé à déclarer mesure la
déclaration, pas le parc.

Ce qui existe déjà, et sur quoi cette décision s'appuie :

- **Les identifiants de clonage** sont gérés : clés de déploiement SSH, et jetons HTTPS liés à un hôte
  ([0022](0022-https-clone-tokens-are-bound-to-a-host.md), `t_git_token`), chiffrés tous deux sous
  `ENCRYPTION_KEY` avec la ligne comme contexte (`SecretCipher`), jamais renvoyés par une route, remis
  seulement à un exécuteur en mode `delegated`, scellés pour sa clé.
- **Une seule porte vers l'extérieur** : `OutboundUrlGuard` résout la destination et la refuse selon une
  politique (`PUBLIC_ONLY`, `INTERNAL_ALLOWED`, `INTERNAL_REQUIRED` ; le lien local et les points
  d'accès réservés de Vectispire sous toutes les politiques) ; `PinnedHttpSender` se connecte à l'adresse
  vérifiée et à aucune autre ; `OutboundJson` refuse les redirections et borne chaque appel à dix
  secondes.
- **Une API de forge est déjà appelée** avec un jeton chiffré : l'intégration de ticketing
  (`TicketService`) ouvre des tickets sur GitLab et GitHub, nettoie l'URL de base et choisit sa politique
  d'après un réglage d'administrateur (`TICKET_ALLOW_PRIVATE_URL` : destinations internes permises ou
  non). C'est le précédent pour l'URL de base et pour la politique.
- **Une solution contient des projets, un projet référence des dépôts**, un droit peut viser un projet
  et il est résolu à chaque requête ([0023](0023-solutions-projects-and-repositories.md)). Un dépôt peut
  n'être dans aucun projet ; rien n'y est jamais classé par inférence sans une personne.
- **La file des analyses est une table** ([0002](0002-the-database-carries-the-queue.md)), et une analyse
  porte un `not_before` (V48) que la prise en charge respecte déjà.
- **Une planification hebdomadaire par défaut** est ajoutée en parallèle : une cible sans planification
  propre est analysée chaque semaine, son créneau étalé selon son identifiant pour qu'un parc ne démarre
  pas à la même minute.
- **`TargetDeleted`** est publié par `targets` vers chaque module qui détient des lignes sur une cible.

Ce qui **n'existe pas** : une règle pour *« le même dépôt »*. `RepositoryUrl.normalizeHost` compare des
hôtes, pour la liaison de 0022 ; rien ne compare des dépôts, et rien n'empêche aujourd'hui deux cibles de
nommer la même URL. Un import en masse sans cette règle dupliquerait chaque dépôt qu'un administrateur
avait déjà saisi. Cette décision doit l'introduire (§4).

## Décision

### 1. Forges, éditions et API

**REST partout, un adaptateur par forge derrière une seule interface** (`ForgeClient` : sonder le jeton,
lister les espaces de noms, lister les dépôts, page par page). Chaque adaptateur fait quelques centaines
de lignes de correspondance ; la tâche, l'instantané, la sélection et l'import sont écrits une fois.

| Forge | Édition | API | URL de base | Dans |
|---|---|---|---|---|
| GitHub | github.com | REST, `X-GitHub-Api-Version: 2022-11-28` | fixe : `https://api.github.com`, hôte de clonage `github.com` | v1 |
| GitHub | Enterprise Cloud avec résidence des données | idem | `https://api.<sous-domaine>.ghe.com`, d'après le sous-domaine saisi | v1 |
| GitHub | Enterprise Server | idem, sous `/api/v3` | saisie : l'adresse web que les utilisateurs consultent, p. ex. `https://git.example.org` | v1 |
| GitLab | gitlab.com | REST v4, `/api/v4` | fixe : `https://gitlab.com` | v1 |
| GitLab | Autogéré et Dedicated | idem | saisie, préfixe de chemin conservé : `https://example.org/gitlab` | v1 |
| Bitbucket | Cloud | REST 2.0 | fixe : `https://api.bitbucket.org/2.0`, hôte de clonage `bitbucket.org` | v1.1 (lot D8) |
| Bitbucket | Data Center | REST 1.0, `/rest/api/latest` | saisie | v1.1 (lot D8) |

- **L'URL de base est l'adresse web, pas celle de l'API**, et l'adaptateur en déduit le chemin de l'API.
  Un administrateur copie ce qui est dans la barre d'adresse ; lui demander `…/api/v4` serait la première
  chose qu'il se tromperait à saisir. Les barres obliques finales sont retirées (comme le fait
  `TicketService`), une URL portant des identifiants est refusée (`RepositoryUrl.carriesCredential`), et
  **`https` seulement** : un jeton envoyé en `http` sur un réseau interne reste un jeton en clair sur le
  fil.
- **Les versions prises en charge sont celles que l'éditeur supporte encore** au moment où le lot arrive —
  les adaptateurs n'utilisent aucun point d'accès plus récent que GitLab 16, GHES 3.12 ou Bitbucket Data
  Center 8. Une création qui trouve un serveur plus ancien (`GET /version` de GitLab, l'en-tête
  `X-GitHub-Enterprise-Version` de GHES, `application-properties` de Bitbucket) refuse en citant la
  version trouvée plutôt que d'échouer plus tard sur un champ manquant.
- **GitLab et GitHub en v1, Bitbucket au lot suivant.** Les deux premiers sont déjà parlés par
  l'intégration de ticketing, et couvrent à eux deux les parcs montrés au produit. Bitbucket est dans
  cette décision, pas reporté hors d'elle : ses deux éditions ne partagent qu'un nom — l'authentification
  de Cloud a changé sous ses pieds en 2025–2026 (mots de passe d'application retirés au profit de jetons
  d'API à portées), et Data Center ne renvoie la branche par défaut que par un appel par dépôt — et il
  arrive comme un lot à part (D8) sur la même interface plutôt que de retarder les deux autres.

*Écartées :* **GraphQL** (GitHub v4, celui de GitLab). Il ramènerait les dépôts et leurs langages en une
requête, et c'est son seul avantage ici. GitHub facture GraphQL par coût calculé, plus difficile à borner
qu'un nombre de requêtes ; GHES et GitLab autogéré suivent le schéma du cloud avec un retard de versions
qu'une installation ne maîtrise pas ; Bitbucket n'en a pas, si bien qu'une voie GraphQL serait une
seconde implémentation du même listage. **Une bibliothèque générique d'hébergement Git** (un client pour
toutes les forges) : elle apporterait sa propre pile HTTP, exactement ce qui ne doit pas exister à côté
de `PinnedHttpSender` (§3).

### 2. Une connexion de forge : un identifiant en lecture seule, gardé comme les autres

Une **connexion de forge** est un nom, un type de forge, une URL de base, **pour GitHub le propriétaire**
(organisation ou utilisateur) pour lequel le jeton a été émis, un nom d'utilisateur facultatif
(Bitbucket Cloud authentifie un jeton d'API avec l'adresse du compte), et un jeton. Elle vit dans une
nouvelle table, `t_forge_connection`.

**Les portées, par forge — les plus étroites que chacune offre :**

| Forge | Identifiant | Portées requises | Refusées |
|---|---|---|---|
| GitHub (cloud, résidence des données, GHES qui les proposent) | jeton d'accès personnel *fine-grained*, propriétaire de ressource = celui de la connexion, accès « All repositories » ou une sélection | **Metadata: read** — et rien d'autre | — (les permissions *fine-grained* ne se lisent pas par l'API ; voir ci-dessous) |
| GHES sans jetons *fine-grained* | jeton d'accès personnel classique | `repo` est la seule portée classique qui liste les dépôts privés, et elle écrit | acceptée seulement là, **signalée comme capable d'écrire** — dans la liste, l'entrée d'audit et les détails de `VECTI-SEC-034` |
| GitLab | **jeton d'accès de groupe** (préféré : un membre robot qui survit à la personne qui l'a créé) ou jeton d'accès personnel, rôle Reporter sur les groupes à découvrir | **`read_api`** | toute portée hors de `read_api`, `read_repository`, `read_registry`, `read_user` — `api`, `write_repository`, `sudo`, `admin_mode`, les portées runner et Kubernetes |
| Bitbucket Cloud | jeton d'API Atlassian à portées, ou jeton d'accès d'espace de travail | `read:workspace:bitbucket`, `read:project:bitbucket`, `read:repository:bitbucket` (noms vérifiés sur la liste d'Atlassian au début du lot D8) | toute portée `write:`, `admin:` ou `delete:` quand la réponse les indique |
| Bitbucket Data Center | jeton d'accès HTTP (projet ou personnel) | permission **Project read** / **Repository read** | permissions d'écriture et d'administration |

- **Sondé à la création et à chaque remplacement.** L'adaptateur appelle la forge une fois avec le jeton
  et lit ce que la forge en dit : `GET /personal_access_tokens/self` de GitLab (portées et expiration),
  les en-têtes `X-OAuth-Scopes` (classique) et `github-authentication-token-expiration` de GitHub, les
  en-têtes de portées de Bitbucket. **Une portée que la forge indique et que le tableau refuse fait
  refuser la connexion** ; une liste d'autorisation, pas une liste d'interdiction, si bien qu'une portée
  qu'une forge ajoutera l'an prochain est refusée jusqu'à ce que quelqu'un l'ait lue. Là où la forge ne
  dit rien — les jetons *fine-grained* de GitHub — l'écran dit *« GitHub n'indique pas les permissions de
  ce jeton ; ne lui accordez que Metadata: read »*, ce qui est une phrase et non une vérification, et est
  écrit comme telle.
- **Conservé comme tout autre secret** : chiffré sous `ENCRYPTION_KEY`, la ligne comme contexte
  (`forge_connection:<id>:token`), si bien qu'un chiffré copié dans une autre ligne ne se déchiffre pas ;
  **jamais renvoyé par aucune route**. La liste montre le nom, le type, l'URL de base, le propriétaire,
  les portées et l'expiration que la forge a indiquées, l'`encryptionState` (comme le montrent les clés
  SSH et les jetons, si bien qu'une rotation d'`ENCRYPTION_KEY` signale la ligne *à faire tourner* — voir
  [`KEY_ROTATION.fr.md`](../../../fr/KEY_ROTATION.fr.md)), la dernière découverte et le nombre de cibles
  importées par elle.
- **La rotation remplace le jeton sur place** (`PUT …/token`), sondé à nouveau, la ligne et ses liens
  conservés. 0022 fait tourner par suppression puis ajout parce que rien ne pointe vers un jeton que des
  dépôts ; ici l'instantané de découverte et la provenance des cibles importées dépendent de la ligne, et
  la supprimer les rendrait orphelins pour un geste de routine. Une expiration indiquée par la forge est
  affichée, et annoncée quatorze jours avant.
- **Supprimer une connexion supprime son instantané et ses liens de provenance, et aucune cible.** Un
  dépôt importé est une cible comme une autre dès sa création (§5).
- **Qui : les administrateurs**, comme pour les clés SSH, les jetons HTTPS et les dépôts. Une connexion
  révèle le nom de chaque dépôt d'une organisation, et un import crée des cibles — les deux relèvent
  aujourd'hui d'un administrateur. Les clés API d'intégration
  ([0024](0024-integration-api-keys-act-for-an-account.md)) ne sont pas acceptées sur ces routes en v1.
- **Journalisé** sous une nouvelle opération, `FORGE_CONNECTION_CHANGED` (créée, jeton remplacé,
  renommée, supprimée), plutôt que le `SETTING_UPDATED` qu'utilisent les clés SSH et les jetons : une
  connexion est un accès en lecture permanent à toute une organisation, et un auditeur qui la cherche ne
  devrait pas avoir à lire chaque changement de réglage pour la trouver.
- **Signalé au SIEM** ([0025](0025-siem-events-leave-through-the-outbox.md)). L'identifiant le plus haut
  en usage est `VECTI-SEC-033` (réservé par la 0035 ; `SecurityEventType` déclare jusqu'à `032`). Cette
  décision réserve les trois suivants — revérifiés contre `SecurityEventType` et les ADR ouvertes au
  début du lot D1, puisqu'une autre proposition peut les avoir pris entre-temps :

| Id | Événement | Sévérité | Pourquoi le SOC le veut |
|---|---|---|---|
| `VECTI-SEC-034` | Connexion de forge créée, son jeton remplacé, ou supprimée | 6 | un accès en lecture permanent à la liste complète des dépôts d'une organisation est apparu, a changé de mains ou a disparu |
| `VECTI-SEC-035` | Dépôts importés depuis une forge | 5 | de nombreuses cibles — et les identifiants de clonage qui leur sont attachés — créées en un geste ; une fois par import, avec son nombre, jamais une fois par cible |
| `VECTI-SEC-036` | Connexion de forge refusée : destination bloquée, portée d'écriture, ou identifiant présenté à un autre hôte | 5 (`failure`) | une URL de base visant le réseau interne ou le point d'accès de métadonnées, ou un jeton plus large que déclaré, est la forme que prend une tentative de SSRF ou de collecte d'identifiants |

**Le jeton de la connexion ne clone pas.** Les identifiants de clonage restent ce que 0022 et les clés SSH
en ont fait, choisis par hôte à l'import (§5). Quatre raisons, chacune suffisante :

- **Les portées diffèrent.** Sur GitHub, le jeton de découverte peut se limiter à *Metadata: read* — il ne
  peut lire aucune ligne de code. Un jeton qui clone a besoin de *Contents: read*. N'en utiliser qu'un
  élargit le jeton de découverte à la lecture de chaque dépôt de l'organisation, pour s'épargner d'en
  créer un second.
- **Les lieux diffèrent.** Le jeton de découverte ne quitte jamais le plan de contrôle. Un jeton de
  clonage voyage, scellé, vers chaque agent `delegated` qui prend une analyse d'un dépôt qui l'utilise. Un
  identifiant unique mettrait le jeton de listage de toute l'organisation sur chaque agent.
- **Les hôtes diffèrent.** L'API de GitHub répond sur `api.github.com` et clone sur `github.com` ; 0022 lie
  un jeton de clonage à l'hôte auquel il est présenté, et un identifiant partagé exigerait deux liaisons,
  ce que la règle de 0022 existe pour empêcher.
- **Les cycles de vie diffèrent.** Faire tourner le jeton de découverte ne doit pas casser les analyses de
  la nuit.

*Écartées :* **réutiliser le jeton de la connexion comme identifiant de clonage** (ci-dessus) ; **une
GitHub App ou une application OAuth GitLab** — le meilleur identifiant à terme (jetons d'installation
de courte durée, approuvés par l'organisation, non liés à une personne), et un parcours d'enregistrement,
une clé privée à garder et une route de rappel à exposer : une suite (§6), pas la v1 ; **ranger le jeton
dans la table des réglages comme le jeton de ticketing** — une connexion par installation, alors qu'un
parc couvre couramment une organisation dans le cloud et une instance autohébergée.

### 3. La découverte est une tâche, et son résultat un instantané

**Une découverte est une ligne, exécutée en arrière-plan, interrogée par l'écran.** `POST
/api/v1/forge-connections/{id}/discoveries` répond `202` avec l'identifiant de l'exécution ; l'exécution
est prise dans la table par une instance du plan de contrôle sous bail, comme les analyses (0002), si bien
qu'un redémarrage la reprend au lieu de la perdre. Ses états sont `pending`, `running`, `completed`,
`partial` et `failed`, avec des compteurs que l'écran affiche pendant qu'elle tourne : espaces de noms
vus, dépôts vus, requêtes faites, temps passé à attendre une limite de débit. Une seule découverte par
connexion à la fois ; une seconde demande répond `409` avec l'identifiant de celle en cours.

*Écartée :* **la découverte synchrone dans la requête.** Une instance GitLab de trois mille projets, c'est
trente pages, plus un appel de langages par projet : des minutes. Une requête tenue aussi longtemps est
coupée par le premier proxy devant le plan de contrôle, et un redémarrage au milieu ne laisse aucune trace
de ce qui a été vu.

**Ce qui est listé.** Les espaces de noms d'abord, puis leurs dépôts :

| Forge | Espaces de noms | Dépôts |
|---|---|---|
| GitHub | le propriétaire de la connexion — un jeton *fine-grained* est émis pour exactement un | `GET /orgs/{owner}/repos?type=all&per_page=100` (ou `GET /user/repos` pour un utilisateur) |
| GitLab | `GET /groups?min_access_level=10&per_page=100` | `GET /projects?membership=true&pagination=keyset&order_by=id&sort=asc&per_page=100` |
| Bitbucket Cloud | `GET /2.0/user/permissions/workspaces` | `GET /2.0/repositories/{workspace}?pagelen=100` |
| Bitbucket Data Center | `GET /rest/api/latest/projects?limit=100` | `GET /rest/api/latest/projects/{key}/repos?limit=100`, puis la branche par défaut par dépôt |

**`membership=true` et `min_access_level` ne sont pas facultatifs sur gitlab.com** : sans eux l'API liste
chaque projet et groupe public du service — des millions — et une découverte parcourrait les dépôts des
autres jusqu'à sa limite. Les tests de l'adaptateur vérifient les paramètres, pas seulement le résultat.

**Ce qui est gardé par dépôt** : l'**identifiant stable** de la forge, le chemin complet, le chemin de
l'espace de noms, le nom, la branche par défaut, archivé, fork, visibilité, dernière activité (GitHub
`pushed_at`, GitLab `last_activity_at`, Bitbucket `updated_on`), langage principal, taille, les URL de
clonage HTTPS et SSH et l'URL web. **Inconnu n'est pas zéro** — la règle de la
[0007](0007-none-is-not-an-empty-list.md) appliquée aux métadonnées : GitLab ne donne la taille qu'à un
Reporter (`statistics=true`) et les langages que par un appel par projet ; Bitbucket Cloud n'a pas du tout
d'indicateur d'archivage. Une valeur que la forge n'a pas donnée est stockée `null` et affichée
*inconnue*, et un filtre sur elle dit combien de dépôts il n'a pas pu juger, au lieu de les traiter comme
petits, sans langage ou actifs.

**Pages, limites, attentes.**

- Les pages suivent le mécanisme propre à chaque forge (le `Link` de GitHub, le `Link` en pagination par
  clé de GitLab, le `next` de Bitbucket Cloud, le `nextPageStart` de Data Center). **Une URL de page
  suivante n'est suivie que si son schéma, son hôte et son port sont ceux de la connexion** ; toute autre
  fait échouer la découverte avec `VECTI-SEC-036`. Le garde vérifierait la nouvelle destination, mais le
  jeton serait déjà en route vers elle.
- **Les limites de débit sont respectées, jamais doublées** : `Retry-After`, `X-RateLimit-Reset` (GitHub)
  et `RateLimit-Reset` (GitLab) fixent l'attente. Une attente jusqu'à soixante secondes se passe dans
  l'exécution ; une plus longue termine l'exécution en `partial`, ses compteurs disant quand la limite se
  réinitialise, et l'exécution suivante recommence. Un `5xx` ou un délai dépassé est réessayé trois fois
  avec recul, puis fait échouer la page.
- **Bornes** : dix secondes par requête (celles d'`OutboundJson`), trente minutes et vingt mille dépôts par
  exécution ; au-delà de l'une ou l'autre, l'exécution se termine en `partial`. Un parc plus grand se
  découvre par groupe, ce que l'écran propose.
- **Un `401` fait échouer l'exécution** — « jeton refusé ou expiré ». **Un `403` sur un espace de noms**
  marque cet espace *illisible avec ce jeton* et l'exécution continue : un groupe que le jeton ne peut lire
  n'est pas une raison de ne rien montrer des autres, ni de prétendre qu'il était vide.

**Le garde sortant, réutilisé — pas un second client HTTP.** Chaque appel passe par `OutboundJson` et
`PinnedHttpSender` : l'adresse vérifiée est l'adresse atteinte, les redirections sont refusées, les points
d'accès réservés de Vectispire sont refusés sous toutes les politiques. La politique est choisie par
connexion, comme l'intégration de ticketing la choisit : **`PUBLIC_ONLY` pour les éditions cloud**, dont
les hôtes sont fixes et ne peuvent être saisis, et pour une URL de base saisie, sauf si l'administrateur
coche *« ce serveur est sur le réseau interne »*, qui sélectionne **`INTERNAL_ALLOWED`** — un GitHub
Enterprise Server ou un GitLab autogéré sur le réseau interne est le cas courant, pas l'exception, et le
lien local y reste refusé. L'URL de base est validée à l'enregistrement et **revalidée à chaque
exécution**, puisque le nom peut entre-temps résoudre ailleurs. L'en-tête `Authorization` n'est joint qu'à
une requête dont l'hôte est celui de la connexion — la règle que 0022 applique aux jetons de clonage,
appliquée à celui-ci. `OutboundJson` renvoie aujourd'hui un corps et aucun en-tête ; le lot D2 lui donne
un appel paginé qui renvoie les en-têtes dont les adaptateurs ont besoin (`Link`, `Retry-After`, les
en-têtes de limite de débit et de portées), pour que la porte reste la seule porte.

**L'instantané.** Une exécution écrit dans `t_forge_repository` : une ligne par dépôt que la connexion a
jamais vu, identifiée par connexion et identifiant de forge, avec ses métadonnées, l'exécution qui l'a vu
en premier et celle qui l'a vu en dernier. Relancer une découverte est donc une **comparaison** :

- **nouveau** — vu pour la première fois par cette exécution ;
- **modifié** — renommé ou déplacé (même identifiant de forge, autre chemin), branche par défaut changée,
  archivé ;
- **disparu** — vu auparavant, absent de cette exécution. **Seule une exécution `completed` marque un
  dépôt disparu** : un listage partiel ne prouve rien de ce qu'il n'a pas atteint, et en déduire une
  suppression serait exactement le défaut de la 0007.

Un dépôt disparu ou archivé sur la forge **n'est pas supprimé de Vectispire** : sa cible, s'il a été
importé, est signalée sur l'écran de découverte et garde son historique ; la retirer reste le geste d'une
personne.

**Qui voit une découverte : les administrateurs**, comme pour la connexion. Une découverte liste des dépôts
qu'aucun droit ne couvre encore — un lecteur titulaire d'un droit sur un projet apprendrait les noms de
toute l'organisation.

### 4. Sélection : ce qu'une personne choisit, et comment un dépôt est reconnu

L'écran de découverte est un tableau de l'instantané avec des **filtres** — archivés (masqués par
défaut), forks (masqués par défaut), dernière activité plus ancienne que N jours, langage, visibilité,
espace de noms, un motif sur le chemin complet (`acme/payments/*`), *déjà une cible* (affiché, grisé, non
sélectionnable) — et **tout sélectionner parmi les résultats / rien / inverser**. La sélection est un
ensemble d'identifiants de forge ; ce qui est importé est ce qui a été coché, jamais ce qu'un filtre
retient au moment de l'import.

**Reconnaître un dépôt déjà présent.** Une nouvelle règle à côté de `normalizeHost`,
`RepositoryUrl.identity` (apportée par le refus des doublons du formulaire de dépôt, réponse 6, et
réutilisée ici) : l'hôte tel que `normalizeHost` l'écrit, puis le chemin — sans `.git`, sans
barre oblique finale, en minuscules — et rien du schéma, de l'utilisateur ni du port, la forme scp
`git@host:group/repo.git` lue comme son chemin. Un dépôt découvert **est déjà présent** quand l'identité de
son URL de clonage HTTPS *ou* SSH est égale à l'identité de l'URL d'une cible existante, **quel que soit le
sous-chemin de cette cible** : un monodépôt déjà découpé en cibles par sous-chemin est affiché *présent
(3 cibles)*, pas proposé à nouveau. Une fois importé, le **lien de provenance** (§5) le reconnaît par
identifiant de forge, si bien qu'un dépôt renommé sur la forge reste la même cible.

- Mettre le chemin en minuscules accepte que deux dépôts ne différant que par la casse sur un serveur
  sensible à la casse soient pris pour un seul. Aucune des trois forges ne le permet, et le coût du
  contraire — un doublon pour chaque `Acme/API` saisi `acme/api` — est le défaut que cette règle existe
  pour empêcher.
- Une URL de clonage dont l'hôte SSH diffère de l'hôte HTTPS (`ssh.example.org`, variantes sur le port
  443) est reconnue par les deux URL de la forge elle-même, raison pour laquelle l'instantané garde les
  deux.
- L'import revérifie l'identité **dans sa transaction** (§5) ; le verdict de l'aperçu est un conseil.

**Correspondance avec les solutions et les projets — proposée, montrée, modifiable.** La 0023 n'infère
rien ; ici la proposition est montrée et une personne la confirme, ce qui fait la différence entre inférer
et suggérer :

| Forge | Solution proposée | Projet proposé |
|---|---|---|
| GitLab | le groupe de premier niveau | le groupe parent du dépôt sous celui-ci (`acme/backend/payments/api` → projet `backend/payments`) ; un dépôt directement sous le groupe de premier niveau → un projet nommé d'après ce groupe |
| GitHub | l'organisation | un projet par dépôt, nommé d'après lui — GitHub n'a pas de niveau entre les deux ; modifiable comme toute proposition |
| Bitbucket Cloud | l'espace de travail | le projet Bitbucket |
| Bitbucket Data Center | une solution nommée d'après la connexion | le projet Bitbucket |
| toutes | espaces de noms personnels : aucune — listés, **non cochés** | aucun — le dépôt est importé dans aucun projet |

- Une solution ou un projet existant **du même nom** (tel que `SolutionAdministrationService` compare les
  noms) est **réutilisé**, marqué *existant*, jamais renommé ni déplacé.
- Chaque proposition est modifiable par espace de noms et par dépôt : renommer la solution ou le projet
  proposé, en choisir un existant, ou *aucun projet*.
- **L'aperçu** (`POST …/imports/preview`, rien n'est écrit) dit ce que l'import ferait : solutions et
  projets à créer et à réutiliser, cibles à créer, dépôts écartés et pourquoi (déjà présent, dépôt vide,
  pas de branche par défaut), l'identifiant de clonage par hôte, la planification, les premières analyses
  et leur étalement — et **qui verra les nouvelles cibles** : les administrateurs, plus les titulaires d'un
  droit sur chaque projet réutilisé, en nombre ; un nouveau projet n'a aucun droit, et l'aperçu dit
  *visible des seuls administrateurs* jusqu'à ce que quelqu'un en accorde un.

*Écartées :* **une correspondance automatique appliquée sans aperçu** — la règle de la 0023 contre
l'inférence vaut pour tout ce qu'une personne n'a pas vu ; **aplatir l'imbrication de GitLab en solutions
imbriquées** — la 0023 a deux niveaux à dessein, et un troisième changerait chaque agrégat et chaque
droit ; **comparer par chaîne d'URL** — `https://github.com/Acme/api` et `git@github.com:acme/api.git` sont
un seul dépôt.

### 5. Import : des cibles ordinaires, une planification par défaut, des premières analyses étalées

`POST /api/v1/forge-connections/{id}/imports` prend la sélection, la correspondance modifiée,
l'identifiant par hôte, l'option de première analyse et un label d'agent requis facultatif. **Jusqu'à
1 000 dépôts par import, en une transaction** : il crée tout ou rien, si bien qu'un échec à mi-chemin ne
laisse aucun parc à moitié classé à nettoyer à la main. Une sélection plus grande fait plusieurs imports.

- **Par les services existants.** Chaque cible est créée par `RepositoryAdministrationService` et chaque
  solution et projet par `SolutionAdministrationService` — les mêmes refus que les formulaires (un
  identifiant dans une URL, un jeton HTTPS sur un autre hôte, un nom de projet en double), les mêmes lignes
  d'audit. L'import est une boucle sur des gestes qui existent déjà, pas une seconde manière de créer une
  cible.
- **L'identifiant de clonage est choisi par hôte.** Une clé SSH → l'URL SSH de la forge ; un jeton HTTPS
  (0022, lié à cet hôte) → l'URL HTTPS ; aucun → l'URL HTTPS, pour les dépôts publics. Quand exactement un
  jeton HTTPS est lié à l'hôte de clonage de la forge, il est proposé. Un dépôt privé importé sans
  identifiant est permis et signalé dans l'aperçu : sa première analyse échouera avec *requires
  authentication*, visiblement.
- **Branche** : la branche par défaut au moment de la découverte. Un changement ultérieur de branche par
  défaut est montré *modifié* par la découverte suivante ; la cible n'est pas changée dans le dos de son
  responsable.
- **Planification** : aucune qui lui soit propre, donc **la planification hebdomadaire par défaut
  s'applique, étalée selon l'identifiant** — trois cents cibles importées ne se réanalysent pas toutes le
  même lundi matin. Le lot D6 dépend de l'arrivée de ce défaut ; sans lui une cible importée n'aurait
  aucune planification, l'état que le défaut a été fait pour supprimer.
- **Première analyse : facultative, désactivée par défaut, étalée.** Sur demande, chaque nouvelle cible est
  mise en file par `TargetScans.queue` avec `not_before` = maintenant + *k* × espacement (soixante secondes
  par défaut, modifiable à l'import entre dix secondes et dix minutes ; trois cents dépôts sur cinq heures
  au défaut). Une cible déjà en attente est sautée, comme le bouton
  d'analyse la saute.
- **Idempotent par construction.** Un dépôt déjà lié à la connexion, ou déjà présent par identité, est
  sauté et signalé *déjà importé* ; rejouer la même requête ne crée rien.
- **Visibilité.** L'import ne crée **aucun droit**. Les nouvelles cibles sont visibles des administrateurs
  et, par la 0023, de qui détient un droit sur le projet où elles sont classées. L'attribution de droits
  reste sur son propre écran, journalisée `TEAM_ACCESS_CHANGED` et signalée `VECTI-SEC-011` — noyé dans
  un import en masse, un droit serait facile à manquer en revue.
- **Audit et SIEM.** Chaque cible reçoit l'entrée qu'écrit le formulaire (*Repository added: …*, masquée),
  avec *importé par la connexion N, découverte M* ; chaque solution et projet créé reçoit son entrée
  habituelle ; une entrée `FORGE_IMPORT_APPLIED` résume l'import (nombres, connexion, découverte, acteur) ;
  et `VECTI-SEC-035` est signalé **une fois par import** — un SOC veut un événement pour un geste, pas trois
  cents.
- **Provenance.** `t_forge_import_link` (identifiant de dépôt, de connexion, de forge) enregistre d'où vient
  une cible. Il vit dans le nouveau module, **sans clé étrangère** entre modules : le module écoute
  `TargetDeleted` et supprime son lien, comme les tables de la 0035 écoutent `ProjectDeleted`. Supprimer une
  cible, la modifier, la déplacer dans un autre projet — tout se passe exactement comme pour une cible
  saisie à la main.

*Écartées :* **mettre en file toutes les premières analyses d'un coup** — les agents videraient la file
dans l'ordre de toute façon, mais les clonages frapperaient la forge en une rafale (détection d'abus sur
github.com, limitations d'un GitLab autogéré), et les analyses manuelles et les gates de CI derrière eux
attendraient des heures ; **aucune première analyse** — la demande est de voir le parc, et le défaut
hebdomadaire montrerait les premiers chiffres jusqu'à sept jours plus tard ; **reproduire l'appartenance
de la forge en droits** — les droits de Vectispire seraient alors décidés par qui administre la forge, un
jeton capable de lire les membres demande une portée plus large, et une personne retirée d'un groupe
GitLab garderait son accès à Vectispire jusqu'à la synchronisation suivante, ou le perdrait sans que
personne dans Vectispire en décide ; **une tâche d'import comme la découverte** — créer mille lignes prend
quelques secondes, et une transaction est la manière la plus simple de promettre tout ou rien.

### 6. Où cela se place, et ce qui est hors périmètre

**Un nouveau module vertical, `core/forges/`** (`web`, `internal`, `persistence`), dont le `package-info`
déclare `targets` (création de cibles, de solutions et de projets, `TargetScans`, `TargetDeleted`) et
`access::security` (les marqueurs de ses routes), chacun avec sa raison. `targets` n'en dépend pas : la
dépendance va dans un seul sens, et une cible ne sait jamais qu'elle a été importée.
`ArchitectureTest.MODULES` et `ModularityTest.MODULES` l'ajoutent.

**Hors périmètre en v1, et les suites dans l'ordre proposé :**

1. **Une redécouverte planifiée avec notification** des nouveaux dépôts — la relance manuelle et sa
   comparaison d'abord ; une planification est un cron sur la même tâche.
2. **Des webhooks ou system hooks pour l'intégration automatique** d'un dépôt créé sur la forge — une
   route entrante par forge, son secret, et une décision sur le fait qu'un dépôt devienne une cible sans
   une personne.
3. **La synchronisation continue** (renommages, archivage et suppression appliqués aux cibles).
4. **Les identifiants GitHub App et application OAuth GitLab** (§2).
5. **La découverte des registres de conteneurs** — GHCR, le registre GitLab, Docker Hub, Harbor — pour les
   cibles d'image.
6. **D'autres forges** : Azure DevOps, Gitea et Forgejo.
7. **La découverte par un agent**, pour une forge que le plan de contrôle ne peut atteindre : le jeton de
   la connexion devrait être scellé pour un agent désigné, comme la 0035 le prévoit pour ses exports.
8. **Des droits à l'import** (une équipe nommée sur les projets créés) — refusés pour la v1 (tranché le
   2026-10-03, réponse 5) ; rouverts seulement par une décision propre.
9. **Les clés API d'intégration** sur les routes de découverte et d'import, pour une intégration scriptée.

## Alternatives envisagées

Chaque section consigne ses propres rejets ; les plus importants, ensemble :

- **Un téléversement CSV ou YAML de dépôts** au lieu d'une API de forge. Aucun identifiant à garder et
  aucun appel sortant ; et l'administrateur doit toujours connaître la liste, ce qui est le problème.
  Gardé comme format d'import possible plus tard, pas comme la réponse.
- **Le jeton clone aussi** (§2) : un identifiant au lieu de deux, élargi à la lecture du code de chaque
  dépôt, porté sur chaque agent, lié à deux hôtes.
- **La découverte synchrone** (§3) : bien sur vingt dépôts, coupée par le premier proxy sur trois mille.
- **GraphQL** (§1) : moins de requêtes, un modèle de coût plus difficile à borner, un décalage de versions
  sur les éditions autohébergées, et rien pour Bitbucket.
- **Une correspondance automatique sans aperçu, ou la reproduction des permissions de la forge** (§4,
  §5) : les deux font de la forge l'autorité sur ce que Vectispire montre, et à qui.
- **Un type de cible « dépôt découvert » à part**, analysé sans être importé : un second modèle de cible
  que chaque requête, chaque droit et chaque score devrait connaître.

## Conséquences

- Un nouveau module, `forges`, avec quatre tables — `t_forge_connection`, `t_forge_discovery`,
  `t_forge_repository`, `t_forge_import_link` — écrites une fois sous `db/migration/common` avec les
  placeholders de type, à partir de la prochaine version libre quand le lot D1 arrive ; aucune clé
  étrangère ne sort du module, donc aucun répertoire par moteur n'est nécessaire (0027).
  `integrationTestAll` tourne sur le lot, comme pour toute migration.
- Un stockage chiffré de plus, que la procédure de rotation d'`ENCRYPTION_KEY` doit lister à côté des clés
  SSH et des jetons.
- Une nouvelle règle d'identité des dépôts, `RepositoryUrl.identity`. **Le formulaire de dépôt refuse
  lui aussi un doublon selon cette règle** (tranché le 2026-10-03, réponse 6), par un changement séparé
  construit sur sa propre branche : la règle arrive là, et les lots d'ici la réutilisent au lieu d'en
  écrire une seconde.
- `OutboundJson` gagne un appel paginé qui renvoie les en-têtes ; chaque adaptateur passe par lui.
- Deux opérations d'audit (`FORGE_CONNECTION_CHANGED`, `FORGE_IMPORT_APPLIED`), trois identifiants SIEM et
  une entrée de catalogue pour chacun, dans les deux langues.
- De nouvelles routes et leur contrat OpenAPI ; l'interface gagne un écran des connexions, un écran de
  découverte avec sa progression, un tableau de sélection et un aperçu.
- **Le jeton de la connexion est un nouvel accès permanent** à la liste des dépôts d'une organisation,
  détenu par le plan de contrôle. Il est en lecture seule là où la forge le permet et déclaré comme tel là
  où elle ne le permet pas ; ce résidu — un jeton classique `repo` sur GHES, le `read_api` de GitLab qui
  peut aussi lire des fichiers par l'API — est écrit dans le guide d'administration, pas caché.
- Une forge que le plan de contrôle ne peut atteindre (un GitLab interne joignable seulement depuis le
  réseau d'un agent) ne peut être découverte en v1.

## Tranché le 2026-10-03

Le responsable produit a tranché les huit questions que la proposition laissait ouvertes, chacune comme
recommandé :

1. **Bitbucket au lot suivant** (D8) ; la v1 est GitHub et GitLab. Si les premiers parcs se révèlent être
   sur Bitbucket, D8 passe avant D4.
2. **Les jetons GitHub classiques sur un GHES sans jetons *fine-grained* sont acceptés, signalés comme
   capables d'écrire** — dans la liste, l'entrée d'audit et les détails de `VECTI-SEC-034`. Les refuser
   exclurait entièrement ces serveurs.
3. **GitHub : un projet par dépôt**, nommé d'après lui, modifiable comme toute proposition.
4. **La première analyse à l'import est désactivée par défaut** ; sur demande, les analyses sont espacées
   de **soixante secondes** par défaut, modifiable entre **dix secondes et dix minutes**.
5. **Pas de droits d'équipe à l'import en v1.** Un droit reste un geste séparé, journalisé, avec son
   propre événement SIEM.
6. **Le formulaire de dépôt manuel refuse lui aussi un doublon selon la règle d'identité**, par un
   changement séparé construit en parallèle. `RepositoryUrl.identity` arrive avec lui ; ces lots la
   réutilisent.
7. **Les espaces de noms personnels sont proposés, non cochés.**
8. **Les bornes tiennent** : 1 000 dépôts par import, 20 000 par découverte, trente minutes par
   découverte.

## Construit en D1

Le lot D1 — les connexions — a été livré le 2026-10-03 comme le décrit le §2, avec ces choix que le texte
ci-dessus ne faisait pas, chacun consigné ici plutôt que laissé au code :

- **Une AC par connexion, jamais un interrupteur qui ignore la vérification.** Le parc du responsable
  produit est un GitLab autogéré sur un réseau interne, où un certificat de l'AC propre de l'organisation
  est la règle. Une connexion peut épingler cette AC (`caPem`) : ce doit être une AC, valide aujourd'hui,
  huit certificats au plus, et elle est approuvée pour cette seule connexion, *à la place* des AC
  publiques ; la vérification du nom d'hôte est inchangée. La règle est celle du collecteur SIEM
  (`CollectorCa`), extraite en `PinnedCa` pour que les deux partagent une seule lecture, et
  `PinnedHttpSender` la prend pour une requête. Une édition cloud refuse l'AC comme la déclaration de
  réseau interne.
- **`OutboundJson.answer`** : une requête qui renvoie le statut et les en-têtes — GitHub déclare les
  portées d'un jeton, son expiration et sa version en en-têtes. L'appel paginé de D2 avec les en-têtes de
  limite de débit reste celui de D2.
- **La sonde.** GitLab : `GET /personal_access_tokens/self` (portées, expiration, révocation — les jetons
  de groupe et de projet sont des jetons personnels d'un robot), jugé avant que le jeton ne soit présenté
  à nouveau ; `GET /version` (16 ou ultérieur) ; `GET /user` (`bot` distingue un jeton de groupe ou de
  projet de celui d'une personne, affichés `gitlab_bot` ou `gitlab_personal`). GitHub : un seul
  `GET /users/{owner}`, dont le 401 est la vérification du jeton et le 404 celle du propriétaire. Un jeton
  GitHub classique sur github.com ou ghe.com est une portée refusée (`VECTI-SEC-036`) : un jeton
  *fine-grained* y est toujours disponible.
- **Inconnu n'est pas « non ».** `canWrite` vaut `null` pour un jeton GitHub *fine-grained*, dont GitHub
  ne déclare pas les permissions, plutôt que `false`.
- **Une troisième opération d'audit, `FORGE_CONNECTION_REFUSED`**, porte `VECTI-SEC-036` ; les refus
  qu'un administrateur corrige simplement (un jeton mal saisi, un serveur ancien) ne sont ni journalisés ni
  signalés. `VECTI-SEC-034` est nommé par son auteur à la création, au remplacement du jeton, au
  changement d'AC ou de déclaration de réseau, et à la suppression ; un renommage est seulement
  journalisé.
- **`PATCH` renomme, ou change l'AC ou la déclaration de réseau** (sondé à nouveau avec le jeton
  stocké) ; l'adresse ne change jamais — un autre serveur est une autre connexion. L'enregistrement
  rescelle le jeton sous l'`ENCRYPTION_KEY` courante, et c'est ainsi qu'une rotation de clé atteint ce
  stockage.
- Reportés à leurs lots : le nom d'utilisateur de Bitbucket (D8) ; la dernière découverte et le nombre de
  cibles importées dans la liste (D3, D6) ; l'annonce de l'expiration quatorze jours avant (D7 —
  l'expiration est stockée et renvoyée dès maintenant). `forges` ne liste qu'`access::security` ;
  `targets` arrive avec l'import (D6).

## Mise en œuvre, par lots

| Lot | Contenu | Taille |
|---|---|---|
| D1 | Le module `forges` : `t_forge_connection`, chiffrement avec la ligne comme contexte, la sonde et la liste d'autorisation des portées par forge, les routes (administrateurs), `FORGE_CONNECTION_CHANGED`, `VECTI-SEC-034` et `036`, `encryptionState` ; `integrationTestAll` | M |
| D2 | L'appel paginé d'`OutboundJson` avec en-têtes ; pages suivantes de même origine ; attentes sur `Retry-After` et les limites de débit ; le jeton joint à son seul hôte | S |
| D3 | La tâche de découverte (`t_forge_discovery`, prise et bail, progression, `partial`), l'instantané et sa comparaison ; l'adaptateur GitLab, avec des tests sur réponses enregistrées qui vérifient `membership=true` et `min_access_level` | L |
| D4 | L'adaptateur GitHub (cloud, résidence des données, GHES), tests sur réponses enregistrées | M |
| D5 | Les routes de sélection (qui réutilisent `RepositoryUrl.identity`, qu'apporte le refus des doublons du formulaire de dépôt), filtres, proposition de correspondance, aperçu | M |
| D6 | L'import par les services existants, identifiants par hôte, premières analyses étalées sur `not_before`, liens de provenance et leur écouteur de `TargetDeleted`, `FORGE_IMPORT_APPLIED`, `VECTI-SEC-035` — après l'arrivée de la planification hebdomadaire par défaut | M |
| D7 | L'interface : connexions, découverte avec progression et comparaison, tableau de sélection, éditeur de correspondance, aperçu, résultat de l'import | L |
| D8 | Les adaptateurs Bitbucket Cloud et Data Center | M |
| D9 | Documentation en anglais et en français : administration (connexions, portées par forge, les résidus), guide utilisateur (découverte et import), catalogue SIEM, référence de l'API, rotation des clés | S |

D1 à D3 et D5 à D7 font la fonctionnalité pour GitLab ; D4 ajoute GitHub sans les toucher. D1 seul n'est
utile que comme sonde, il part donc avec D3.
