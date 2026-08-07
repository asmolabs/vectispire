# ADR-002 — Exécution multi-instance et agents

**Statut :** **étapes 0, 1 et 3 implémentées ; étape 2 (rôles) écartée, étape 4 non faite**
**Date :** 2026-08-06
**Contexte :** suite d'ADR-001 §9decies (la base de données est devenue configurable, donc PostgreSQL et MySQL sont possibles)

> **Où en est ce document.** L'étape 0 (outbox), l'étape 3 (agents distants, §10) et
> l'étape 1 (plan de contrôle multi-instance, §11) sont faites. L'ordre a été inversé
> par rapport à la recommandation de §9 : le besoin exprimé était de **déporter
> l'exécution**, et les agents fonctionnent sur SQLite (conséquence heureuse de D3),
> donc rien de l'étape 1 n'était un préalable. Elle a suivi.
>
> Les points §2.1 à §2.6 sont désormais traités ou refusés au démarrage. **Deux
> instances web sont donc supportées, sous conditions** : PostgreSQL ou MySQL, Redis, et
> `ZANSHIN_AUTO_MIGRATE=false`. L'application refuse ou avertit quand elles ne sont pas
> réunies (§11.3).

---

## 1. Pourquoi ce document

Rendre la base de données configurable a ouvert une porte que le reste de l'application
ne peut pas encore franchir : **on ne met pas PostgreSQL derrière une seule instance**,
et lancer deux instances de Zanshin aujourd'hui produit des dégâts silencieux plutôt
qu'une erreur.

Ce document inventorie précisément ce qui l'empêche, tranche les décisions de
conception, et découpe le travail en étapes dont chacune est utile seule.

Il traite aussi la question des **agents** — des exécutants de scan séparés du plan de
contrôle — parce que la réponse aux deux questions partage la même première étape, et
parce que faire les agents d'abord ne résoudrait rien.

---

## 2. Ce qui casse aujourd'hui avec deux instances

Chacun de ces points est vérifié dans le code actuel, pas supposé.

### 2.1 La file d'attente est dans le processus qui a reçu la requête *(corrigé — 2026-08-06)*

> Traité : la file est passée en base (`zanshin/services/scan_queue.py`), et
> `claim_next` est désormais transactionnelle sur PostgreSQL et MySQL
> (`FOR UPDATE SKIP LOCKED`), avec un repli explicite sur SQLite qui ne prétend rien de
> plus que ce que SQLite offre. Éprouvé par des réclamants concurrents contre de vrais
> serveurs — voir §11.1, y compris la différence entre les deux moteurs que ces tests
> ont révélée.


[`repository_service.py`](../../zanshin/services/repository_service.py) crée un
`ThreadPoolExecutor` de module (`ZANSHIN_SCAN_WORKERS`, 5 par défaut) et
`executor.submit(...)` y dépose le travail. `container_service.py` partage le même
exécuteur. Conséquence directe : le travail appartient au processus qui l'a accepté.
Avec deux instances, il n'y a pas une file de dix travailleurs, il y a deux files de
cinq qui s'ignorent — et une instance qui redémarre emporte les scans qu'elle tenait.

### 2.2 L'ordonnanceur déclencherait chaque scan deux fois *(corrigé — 2026-08-07)*

> Corrigé par un bail d'élection (§11.2) : la partie du tick dont l'effet est « une fois
> par période » n'est exécutée que par le porteur du bail. Ce qui est per-instance par
> nature — réclamer du travail pour son propre agent intégré, se déclarer vivant — reste
> exécuté partout, sans quoi une flotte resterait inactive derrière son leader.

[`scheduler.py`](../../zanshin/services/scheduler.py) est un thread démon par
processus. Il estampille `last_scheduled_scan_at` *avant* de dispatcher, ce qui protège
contre un double déclenchement par le même processus, pas contre deux processus qui
tiquent en même temps. Deux instances = deux scans par échéance, donc le double de
conteneurs de scan, de trafic registre et d'appels d'API d'enrichissement.

Le tick héberge aussi la reprise des scans bloqués, la purge des charges brutes et
l'expiration des triages : trois travaux qui doivent avoir **un seul** propriétaire.

### 2.3 Le démarrage d'une instance tue les scans de l'autre *(corrigé — 2026-08-06)*

> Corrigé avec les agents, parce qu'un agent distant rendait le défaut immédiatement
> destructeur : démarrer l'instance web faisait échouer les scans qu'un agent était en
> train d'exécuter. `reconcile_interrupted_scans` ne reprend plus qu'un scan **dont
> personne ne détient le bail**, ou dont le bail appartient à l'agent intégré de cet
> hôte (c'est-à-dire au processus qui vient de redémarrer).
>
> Un second défaut a été trouvé au même endroit : la fonction échouait aussi les scans
> `pending`, ce qui annulait la propriété pour laquelle la file est passée en base —
> qu'une demande survive au processus qui l'a acceptée. Un scan en file est désormais
> laissé tranquille, et un scan repris **retourne en file** au lieu d'échouer : le
> travail n'a pas été fait, et la ligne *est* l'entrée de file.

`recover_interrupted_scans()` s'exécute à l'import dans
[`zanshin.py`](../../zanshin/zanshin.py) et marque en échec tout scan encore « en
vol », en partant du principe qu'il appartient à un processus disparu. C'est vrai
aujourd'hui — tous les imports ont lieu au démarrage, avant qu'un scan ne tourne. Avec
deux instances, **la seconde qui démarre fait échouer les scans en cours de la
première.** C'est le même piège que la migration concurrente corrigée en §9decies :
du code d'initialisation qui suppose être seul.

### 2.4 L'état Reflex est sur le disque local *(signalé au démarrage — 2026-08-07)*

> Inchangé sur le fond : c'est une propriété de Reflex, pas de ce code. Mais une
> instance qui en voit une autre et ne trouve pas d'état partagé configuré le dit
> maintenant à voix haute au démarrage (§11.3), au lieu de laisser découvrir le
> problème par des utilisateurs déconnectés au hasard.

`state_manager_mode` vaut `disk` par défaut dans Reflex 0.9.6 (les autres valeurs sont
`memory` et `redis`). L'état serveur d'un client vit donc sur l'instance qui a accepté
sa connexion. Sans état partagé, un client qui atterrit sur l'autre instance se
retrouve déconnecté et sans contexte, de façon intermittente et impossible à
diagnostiquer depuis les journaux.

C'est le blocage le plus dur, parce qu'il ne se contourne pas par du code applicatif :
il faut soit des sessions collantes au niveau du répartiteur, soit
`state_manager_mode = "redis"` avec `redis_url`. **Redis n'est donc pas optionnel pour
un étage web réparti** — ce qui change la réponse au point suivant.

### 2.5 Deux garde-fous de sécurité sont en mémoire, par processus *(corrigé — 2026-08-07)*

> Corrigé : les deux comptent à travers `zanshin/services/counter_store.py`, partagé via
> Redis quand `REDIS_URL` est réglé et en mémoire sinon (§11.4). Le repli n'est pas un
> mode dégradé : c'est l'implémentation correcte pour une instance seule.

- [`rate_limit.py`](../../zanshin/api/rate_limit.py) : fenêtre fixe par clé API, dans un
  dictionnaire. Avec deux instances, le quota double.
- [`login_throttle.py`](../../zanshin/services/login_throttle.py) : même structure.
  L'anti-bourrage se contourne en alternant les instances.

Les deux dégradent une propriété de sécurité, silencieusement, sans qu'aucun test
existant ne le voie.

### 2.6 Le verrou de migration ne couvre qu'un hôte *(signalé au démarrage — 2026-08-07)*

> Inchangé sur le fond — un verrou de fichier ne coordonnera jamais deux hôtes — mais
> l'application avertit maintenant quand elle voit une autre instance vivante alors que
> `ZANSHIN_AUTO_MIGRATE` est actif (§11.3).

Le verrou `fcntl` d'ADR-001 §9decies sérialise les processus **d'un hôte**. Deux hôtes
qui démarrent ensemble ne sont pas coordonnés. `ZANSHIN_AUTO_MIGRATE=false` existe déjà
pour ça : c'est la réponse, il faut la rendre obligatoire dans ce mode de déploiement.

---

## 3. Décisions

### D1 — La base de données est la source de vérité de la file

Les scans sont déjà des lignes avec un statut. Il manque la **réclamation
transactionnelle** : `SELECT ... FOR UPDATE SKIP LOCKED`, puis `status = 'running'`
dans la même transaction. Soit une instance a le travail et la ligne le dit, soit ni
l'un ni l'autre.

Pas de broker. Un broker introduirait une double écriture entre la ligne de scan et le
message — message publié puis transaction annulée, ou transaction validée et
publication échouée — dont la correction standard (*transactional outbox*) est **plus
de machinerie que la file qu'on remplace**. Un broker ne dispense pas non plus du bail
et du battement de cœur : un consommateur qui meurt en tenant un message demande un
*visibility timeout*, c'est-à-dire le même travail sous un autre nom.

`SKIP LOCKED` existe sur PostgreSQL et MySQL 8, pas sur SQLite — voir D6.

### D2 — Redis porte l'état Reflex, et donc aussi les compteurs

Puisque §2.4 impose Redis pour un étage web réparti, les compteurs de quota et
d'anti-bourrage y vont aussi, et non en base : ce sont des compteurs à fenêtre, écrits
à chaque requête, dont la perte au redémarrage est acceptable — exactement le profil
que Redis sert bien et qu'une table sert mal (une écriture par requête amplifierait le
trafic que le quota est censé limiter).

À noter : Redis comme magasin d'état n'est pas Redis comme broker de messages. D1 reste
valable.

### D3 — Le transport des agents est du long-polling HTTP

`GET /api/v1/agents/jobs?wait=30` renvoie une tâche ou 204. Raisons, par ordre
d'importance :

1. **L'agent n'a pas besoin d'accès à la base.** Un agent qui aurait une connexion
   PostgreSQL au plan de contrôle aurait aussi besoin des identifiants de la base et de
   `ENCRYPTION_KEY` — donc de quoi déchiffrer *toutes* les clés SSH. En HTTP il ne parle
   qu'à l'API, avec une clé à portée `agent`, et il réutilise l'authentification, les
   portées, le quota et l'audit qui existent.
2. **Le contrôle de flux se fait tout seul.** L'agent demande du travail quand il a de
   la capacité. Un broker qui pousse ne sait pas ce que l'agent fait.
3. **La latence n'est pas un enjeu.** Les scans durent une à deux minutes ; un long-poll
   de 30 secondes coûte quelques pourcents.
4. **Conséquence utile :** comme seul le plan de contrôle touche la base, **les agents
   fonctionnent même sur SQLite.**

### D4 — Outbox pour ce qui sort, inbox pour ce qui entre

- **Outbox** là où il existe vraiment un second système : les notifications
  ([`notification_service.py`](../../zanshin/services/notification_service.py)) et, plus
  tard, la création de tickets. Aujourd'hui le webhook part *après* la validation de la
  transaction : si le processus meurt entre les deux, la notification est perdue en
  silence. Une ligne d'outbox écrite dans la même transaction, relayée par le tick,
  corrige une perte de message réelle.
- **Inbox avec déduplication** sur le chemin des résultats d'agents. Un agent qui
  réessaie ne doit pas insérer deux fois 421 findings. La déduplication ne peut pas se
  contenter de `Issue.fingerprint` : il rend le rapprochement idempotent mais
  `sync_from_scan` incrémente `times_seen` à chaque appel, donc un rapport rejoué
  fausserait l'historique sans créer de doublon visible. Il faut un identifiant de
  message, une table des messages traités avec contrainte d'unicité, et l'insertion de
  cet identifiant **dans la transaction qui applique l'effet**.
- **Pas d'outbox pour la file des scans** : pas de second système, D1 suffit.

### D5 — Un seul artefact, un rôle

`ZANSHIN_ROLE=all|web|agent`, défaut `all`. Le déploiement mono-processus reste
identique — c'est une qualité de ce projet, pas une limitation, et la majorité des
installations n'aura jamais besoin d'autre chose.

| Rôle | Sert l'UI/API | Réclame des scans | Tient le tick |
|---|---|---|---|
| `all` (défaut) | oui | oui | oui |
| `web` | oui | non | une seule instance, élue |
| `agent` | non | oui | non |

### D6 — SQLite reste mono-instance, et c'est documenté comme tel

Pas de `SKIP LOCKED`, un seul écrivain. Le démarrage doit **refuser** un rôle réparti
sur SQLite avec un message qui nomme la raison, plutôt que de laisser découvrir le
problème en production.

---

## 4. Étapes

### Étape 0 — Outbox des notifications *(faite — 2026-08-06)*

Corrige un bug existant et valide le pattern sur un cas réel avant de l'appliquer là où
il compte.

- Table `outbox_message` (id, type, charge JSON, créé le, tentatives, envoyé le, dernière erreur).
- Écriture dans la transaction qui produit le résultat de scan.
- Relais sur le tick de l'ordonnanceur, à côté de la rétention et de l'expiration des triages.
- Réessai avec recul exponentiel, plafonné ; échec définitif journalisé et visible.

**Vérification :** faite. Le message est écrit dans la transaction du scan via un
paramètre `before_commit` sur `sync_from_scan` — la seule façon d'obtenir une réelle
atomicité, puisque cette méthode valide elle-même. Réessais espacés (60 s, 120 s, 240 s,
plafonnés à une heure), abandon après 8 tentatives avec entrée d'audit, messages livrés
purgés sur le même tick que les charges brutes. Vérifié en réel contre un puits qui
refuse les deux premiers appels : deux échecs enregistrés avec leur date de réessai, puis
livraison, `message_id` présent dans la charge pour qu'un récepteur puisse dédupliquer
une livraison au-moins-une-fois.

Un défaut trouvé en écrivant les tests : `NotificationService.__init__` prend
`http_post=httpx.post` en argument par défaut, donc lié à l'import — patcher `httpx`
ensuite n'a aucun effet, et le test doit injecter. Vrai aussi pour `EnrichmentService`,
`EolService` et `TicketService`.

### Étape 1 — Plan de contrôle multi-instance *(sans aucun agent)*

C'est l'étape qui répond à la demande. Elle est utile seule et préalable à tout le reste.

1. **Colonnes de bail sur `scan`** : `claimed_by`, `claimed_at`, `lease_expires_at`, `attempts`.
2. **`claim_next_scan()`** en `FOR UPDATE SKIP LOCKED`, avec repli explicite sur SQLite
   (pas de réclamation concurrente, donc mono-instance — D6).
3. **`trigger_scan` n'exécute plus** : il insère une ligne `pending` et rend la main.
   Une boucle de travailleurs réclame et exécute. Le `ThreadPoolExecutor` de module
   disparaît en tant que file ; il reste éventuellement comme parallélisme *local* d'un
   travailleur.
4. **Battement de cœur** pendant l'exécution ; **reprise des baux expirés** au lieu de
   `recover_interrupted_scans()` tel quel — sinon §2.3 se déclenche.
5. **Ordonnanceur à propriétaire unique.** Une table de bail d'élection (`leader`, un
   titulaire, une expiration) plutôt qu'un verrou consultatif spécifique à un moteur :
   c'est portable, ça marche aussi en mono-instance sans cas particulier, et l'état est
   observable en SQL quand quelque chose cloche.
6. **Compteurs dans Redis** (D2) avec repli en mémoire quand `redis_url` est absent —
   c'est-à-dire en mono-instance, où le comportement actuel est correct.
7. **`state_manager_mode = "redis"`** dès que plus d'une instance sert l'UI.
8. **Refus au démarrage** des combinaisons impossibles : rôle réparti sur SQLite, étage
   web multiple sans `redis_url`, `ZANSHIN_AUTO_MIGRATE` actif sur plusieurs hôtes.

**Vérification :** deux instances contre le même PostgreSQL — un scan est exécuté
exactement une fois, une échéance d'ordonnanceur produit un scan et non deux, tuer
l'instance qui exécute fait reprendre le scan par l'autre après expiration du bail, et
le quota comme l'anti-bourrage comptent globalement.

### Étape 2 — Rôles

`ZANSHIN_ROLE` (D5) et le découpage des tâches de démarrage : migration, bootstrap,
reprise et tick n'ont plus tous le même déclencheur. La séparation de privilèges
commence ici : un rôle `web` n'a plus besoin du socket Docker.

**Vérification :** un `web` seul sert l'UI et l'API et n'exécute aucun scan ; un `agent`
seul n'écoute sur aucun port applicatif.

### Étape 3 — Agents distants

1. Enregistrement : `POST /api/v1/agents/register` — identité, capacités déclarées
   (types d'analyse, architecture, zone réseau), `max_concurrent`.
2. Réclamation par long-poll (D3), battement de cœur, remontée des résultats.
3. **Inbox avec déduplication** (D4) sur la remontée.
4. Portée `agent` sur les clés API, et audit des actions d'agent.
5. Envoi **découpé** des grosses charges : 421 findings et un SBOM de 18 Mo ne passent
   pas dans une requête confortable. C'est un besoin de fractionnement, pas de
   regroupement par lots.

**Vérification :** un agent dans un réseau sans accès à la base exécute un scan de bout
en bout ; une remontée rejouée ne duplique rien et ne gonfle pas `times_seen` ; un agent
qui meurt en cours voit sa tâche reprise.

### Étape 4 — Routage par capacité

Quand il y aura deux agents différents à départager, et pas avant.

---

## 5. La décision à prendre avant d'écrire l'étape 3

**Comment un agent obtient la clé de déploiement.** Aujourd'hui elle est déchiffrée en
processus depuis la base avec `ENCRYPTION_KEY`. Deux modèles :

| Modèle | Coût | Conséquence |
|---|---|---|
| L'agent détient `ENCRYPTION_KEY` et lit la base | faible | **tout agent peut déchiffrer toutes les clés SSH** |
| Le plan de contrôle remet un identifiant de courte durée par tâche | élevé | un agent compromis reste circonscrit à ce qu'il a scanné |

Le second est cohérent avec D3, qui prive déjà l'agent d'accès à la base. À trancher
explicitement, parce que revenir en arrière après coup signifie faire tourner tous les
secrets.

Point connexe : **un agent compromis peut supprimer des findings**, donc influencer le
verdict du gate. Cela plaide aussi pour le second modèle, et pour auditer les remontées
d'agents comme on audite un triage.

---

## 6. Ce qu'on ne fait pas, et pourquoi

- **Un broker de messages** (RabbitMQ, Kafka, NATS). Voir D1. Le jour où il devient
  justifié — une tâche consommée par plusieurs abonnés aux préoccupations différentes,
  un débit de plusieurs milliers de messages par seconde, ou le rejeu d'un historique
  d'événements — la file en base reste la source de vérité et le broker se greffe à
  côté. Commencer par la base ne ferme aucune porte ; commencer par le broker engage
  tout de suite dans l'outbox.
- **Le chiffrement des charges de messages**, tant qu'elles restent dans le périmètre :
  TLS couvre le transit, et la base est déjà l'endroit où ces données vivent. Cela
  change si des messages transitent par un broker tiers — et ce n'est pas théorique
  ici, la charge brute d'un scanner **contient des secrets en clair** (le rapport
  gitleaks ; le `Finding` normalisé, lui, ne garde que la règle, le fichier et la
  ligne). Messages hors périmètre ⇒ chiffrement obligatoire, pas optionnel.
- **Le regroupement par lots.** Quelques scans par heure et une poignée de webhooks :
  regrouper n'achète rien de mesurable et retarde la seule chose que quelqu'un attend.
- **Un SDK de plugins pour les agents.** Le point d'extension existe déjà et il est au
  bon niveau : [`ScannerEngine`](../../zanshin/services/scanners/base.py). Un agent est
  un *transport* pour cette interface, pas une abstraction supplémentaire. `scan-api/`
  en est le prototype.

---

## 7. Stratégie de test

La logique de réclamation **ne peut pas** être testée sur SQLite : `SKIP LOCKED` n'y
existe pas, et c'est précisément la concurrence qu'on veut éprouver. Elle relève donc de
la suite multi-backends introduite en §9decies (`pytest -m backends`, PostgreSQL 16 et
MySQL 8.4 via testcontainers), avec des tests qui lancent plusieurs réclamants
concurrents et vérifient qu'une tâche est attribuée une seule fois.

Le reste — élection, expiration de bail, déduplication d'inbox, relais d'outbox — se
teste sur SQLite comme le reste de la suite, la concurrence étant simulée par des appels
séquentiels sur des identités distinctes.

Le précédent à garder en tête : les six défauts de portabilité d'ADR-001 §9decies
étaient tous invisibles depuis SQLite et à la lecture. Une garantie de concurrence non
exécutée contre un vrai serveur n'est pas une garantie.

---

## 8. Découpage du code en paquets

**Verdict : oui, mais trois paquets et non quatre, et au moment de l'étape 2/3 — pas
avant.** Le découpage n'est pas un rangement : c'est la formalisation du contrat de
l'agent, et il force à trancher §5.

### 8.1 Ce qu'il achète réellement

Un seul bénéfice compte, et il est concret : **des artefacts de déploiement
différents.** Un agent qui ne peut pas importer l'UI ne dépend pas de Reflex, n'embarque
pas le frontend compilé, et son image devient une fraction de l'actuelle. Symétriquement,
un rôle `web` cesse de porter le client Docker — c'est-à-dire que le processus exposé sur
le réseau perd une capacité équivalente à root sur l'hôte. La séparation de privilèges de
D5 devient vérifiable par la liste des dépendances installées, pas par une convention.

### 8.2 Pourquoi trois et pas quatre

Séparer `ui` de `backend` n'achète pas d'artefact : les deux sont toujours déployés
ensemble dans le rôle `web`. Cela n'achèterait que de la discipline — et la discipline
est déjà là : rien dans `models/`, `repositories/`, `services/`, `api/` ni `container.py`
n'importe `zanshin.ui`. Un paquet supplémentaire ne corrigerait donc rien d'existant. Si
l'on veut garantir que ça reste vrai, une règle de *linter* d'imports coûte une ligne de
configuration au lieu d'un paquet.

### 8.3 Le vrai travail que le découpage révèle

[`scan_processor.py`](../../zanshin/services/scan_processor.py) fait deux métiers et ne
peut aller dans aucun des deux paquets tel quel. Il importe à la fois :

- de l'**exécution** — `scanners.base`, `git_url`, `ssh_key_service` ;
- du **plan de contrôle** — `issue_service`, `enrichment_service`,
  `license_compliance_service`, `notification_service`, `remediation`,
  `dependency_graph`, et une session de base de données.

La coupure a une bonne réponse, et elle découle de D3 et D4 : **l'agent exécute les
scanners et renvoie la charge brute ; le plan de contrôle normalise, enrichit, rapproche
les problèmes et notifie.** Soit deux objets là où il y en a un :

| Aujourd'hui | Devient | Où |
|---|---|---|
| `ScanProcessor.process_scan` | `ScanRunner` — clone, exécute syft/grype/gitleaks/checkov, renvoie les charges brutes | agent |
| idem | `ScanIngestor` — normalise en `Finding`, enrichit (EPSS/KEV), rapproche via `IssueService`, notifie | serveur |

Conséquence heureuse : l'agent n'a alors besoin ni de la base, ni de `ENCRYPTION_KEY`,
ni des services d'enrichissement. Ce qui converge exactement avec D3.

### 8.4 La forme

Un *workspace* uv à trois membres :

| Paquet | Contenu | Dépendances lourdes |
|---|---|---|
| `zanshin-common` | contrat de tâche et de résultat (pydantic), `clock`, `url_guard`, `git_url`, exceptions partagées | aucune — ni SQLAlchemy, ni Reflex |
| `zanshin-agent` | `ScannerEngine` et ses implémentations, `ScanRunner`, remontée HTTP | `docker`, `httpx` |
| `zanshin-server` | `models`, `migrations`, `repositories`, services de plan de contrôle, `api`, `ui` | SQLAlchemy, Alembic, Reflex |

Un déploiement mono-processus (`ZANSHIN_ROLE=all`) installe simplement les deux.

Deux points à noter :

- **Les modèles SQLAlchemy ne sont pas communs.** C'est contre-intuitif, mais si l'agent
  n'accède pas à la base (D3), il n'a pas besoin de `models/` : il a besoin de la *forme*
  d'une tâche et d'un résultat, c'est-à-dire de schémas pydantic. Mettre les modèles dans
  `common` traînerait SQLAlchemy dans l'agent pour rien et rouvrirait la porte à un agent
  qui parle à la base.
- **`scan-api/` devient redondant.** Ce sidecar est le prototype de l'agent : une fois
  `zanshin-agent` en place, il n'y a plus de raison d'entretenir deux implémentations du
  même rôle. Le backend `local_api` peut rester le temps d'une transition, puis
  disparaître.

### 8.5 Le coût, et la décision que ça force

Le coût réel n'est pas le déplacement de fichiers : c'est le **versionnement du
contrat**. Deux artefacts se déploient séparément, donc un agent d'une version peut
parler à un serveur d'une autre. Il faut que l'agent déclare sa version du contrat à
l'enregistrement et que le serveur refuse ce qu'il ne sait pas traiter, avec un message
lisible.

Et surtout : **ce découpage n'existe proprement que dans le second modèle de secrets de
§5.** Si l'agent détient `ENCRYPTION_KEY` et lit la base pour récupérer une clé de
déploiement, il lui faut SQLAlchemy, les modèles, le service de chiffrement — et les
trois paquets s'effondrent en deux. Choisir le découpage, c'est donc choisir les
identifiants de courte durée. Les deux décisions n'en font qu'une, ce qui est un argument
de plus pour le modèle le plus sûr.

---

## 9. Recommandation

Faire l'**étape 0** puis l'**étape 1**, et s'arrêter là jusqu'à ce qu'un besoin concret
d'agent apparaisse — un segment réseau injoignable, une architecture différente, ou le
besoin de sortir le socket Docker du processus exposé. L'étape 1 livre le multi-instance
demandé, ne dépend d'aucune décision ouverte, et aucune de ses pièces n'est à jeter si
les agents viennent ensuite.

Le découpage en paquets (§8) appartient à l'étape 2/3 et **pas** à l'étape 1 : fait
maintenant, il déplacerait des fichiers sans changer un seul artefact déployé, et il
figerait la coupure de `ScanProcessor` avant que le contrat de l'agent ne soit écrit.
Fait au bon moment, c'est le même travail que l'étape 3, pas un travail en plus.

### Ordre de dépendance des décisions

```
Étape 0 (outbox notifications)  ── indépendante, livrable seule
        │
Étape 1 (multi-instance)        ── répond à la demande, aucune décision ouverte
        │
        ├── D2 impose Redis dès que l'UI est répartie
        └── D6 impose PostgreSQL ou MySQL
        │
Décision §5 (secrets de l'agent) ── à trancher AVANT les étapes 2/3
        │
        └── détermine §8 : trois paquets seulement si identifiants de courte durée
        │
Étapes 2 et 3 (rôles, agents, découpage)
        │
Étape 4 (routage par capacité)  ── quand il y aura deux agents à départager
```

---

## 10. Statut d'implémentation — agents (étape 3), 2026-08-06

L'étape 3 a été faite avant l'étape 1, à la demande : le besoin exprimé était de
**déporter l'exécution des scans**, pas de répartir l'étage web. C'était possible parce
que D3 prive l'agent d'accès à la base — donc les agents fonctionnent sur SQLite, et
aucune pièce de l'étape 1 n'était un préalable.

### 10.1 La coupure de `ScanProcessor` (§8.3)

Faite telle qu'écrite, aux noms près :

| Prévu | Livré | Où |
|---|---|---|
| `ScanRunner` | `zanshin/services/scan_runner.py` | agent **et** contrôleur |
| `ScanIngestor` | `zanshin/services/scan_ingestor.py` | contrôleur seul |

Le contrat qu'ils échangent est dans `zanshin/scan_contract.py` (`ScanTask`,
`ScanArtifacts`, `CONTRACT_VERSION`) — un module qui n'importe **rien** de Zanshin,
c'est-à-dire le futur paquet `zanshin-common` de §8.4 sans le packaging.
`ScanProcessor` compose les deux et garde sa signature, donc la file, l'ordonnanceur et
la suite de tests existante n'ont pas bougé.

Le découpage en trois paquets uv (§8.4) n'est **pas** fait : il déplacerait des fichiers
sans changer d'artefact déployé. Ce qu'il achetait vraiment — un agent qui ne peut pas
importer la base — est obtenu autrement, par un test qui vérifie le graphe d'imports
dans un interpréteur neuf (`tests/test_agent_worker.py`,
`tests/test_scan_runner.py`). `Dockerfile.agent` n'installe d'ailleurs ni Reflex ni
SQLAlchemy, ce qui rend la promesse vérifiable à l'inspection.

Défaut trouvé en écrivant ce test : `zanshin/services/scanners/__init__.py` importait la
factory au chargement, donc importer la seule classe abstraite `ScannerEngine` tirait
settings → repositories → models → SQLAlchemy. Passé en imports paresseux (PEP 562).
L'absence de base côté agent est une propriété de sécurité, pas une optimisation, et ce
fichier l'aurait annulée en silence.

### 10.2 Propriété et bail (une partie de l'étape 1)

Quatre colonnes sur `scan` (migration `0010`) : `claimed_by`, `claimed_at`,
`lease_expires_at`, `attempts`. Ce n'est pas tout l'étape 1 — la réclamation reste un
`UPDATE ... WHERE status='pending'` conditionnel, **pas** `FOR UPDATE SKIP LOCKED` — mais
c'est ce qui donne un propriétaire à un scan, sans quoi les agents étaient impossibles.

Un bail expiré ne tue rien (rien ici ne peut tuer un thread sur une autre machine) : il
rend la ligne réclamable, et `still_owned` refuse ensuite les résultats de l'exécutant
qui l'a perdue. Après `MAX_ATTEMPTS` (3) le scan échoue au lieu d'être remis en file,
sinon une cible qui bloque tout exécutant qu'elle touche occuperait la flotte
indéfiniment.

Conséquence à noter : **la limite de simultanéité est devenue par exécutant.** Elle
devait : compter tous les scans en cours aurait fait qu'ajouter un agent *réduisait* ce
que l'hôte s'autorisait à faire.

### 10.3 L'agent intégré — ce qui n'était pas prévu, et qui compte

L'ajout demandé en cours de route, et le plus utile : le processus web est lui-même une
ligne de la table `agent` (`kind=builtin`, créée au démarrage, une par hôte). C'est le
*Built-In Node* de Jenkins, et ça change deux choses :

- **le déploiement mono-processus reste identique** — un seul lancement, aucune
  configuration, l'agent intégré réclame et exécute comme avant ;
- **le désactiver est le geste qui déporte l'exécution.** Sans lui, « ne plus rien
  exécuter ici » n'était pas exprimable ; il aurait fallu un réglage de plus, qui aurait
  décrit la même chose que l'agent sans être visible sur le même écran.

Ses exécuteurs réutilisent le réglage existant `scan_max_concurrent` plutôt qu'un
second nombre : deux valeurs pour « combien de scans cet hôte lance à la fois »
finiraient par se contredire, et l'opérateur n'aurait aucun moyen de savoir laquelle
gagne.

### 10.4 Authentification des agents — la question tranchée

D3 disait « une clé à portée `agent` » ; c'est ce qui est livré : `SCOPE_AGENT` sur les
clés API existantes, donc l'authentification, le quota et l'audit sont ceux qui
existaient déjà. Deux points méritent d'être écrits :

- la portée est **absente de `DEFAULT_SCOPES`**, contrairement aux trois autres. Élargir
  en silence une clé émise avant les agents lui offrirait le droit de soumettre des
  résultats de scan, que personne ne lui a accordé ;
- elle n'est **pas** un surensemble des autres. Un agent reçoit du travail ; il ne lit
  pas l'historique des problèmes et n'exporte pas le document VEX d'un client.

Un jeton d'agent maison a été envisagé puis écarté : il aurait fallu réimplémenter le
quota, l'audit et la rotation qui existent sur les clés API.

### 10.5 La décision de §5 — comment un agent obtient la clé de déploiement

**Tranchée par un troisième modèle, qui ne figurait pas dans §5 : le mode
d'identifiants est une propriété de l'agent, et le défaut est qu'aucun secret ne quitte
le contrôleur.** Colonne `credentials_mode` :

| Mode | Ce que le contrôleur envoie | Conséquence |
|---|---|---|
| `local` (**défaut**) | rien | un agent compromis ne donne que ce que l'opérateur a accordé à *cette* machine, et la révocation est locale et immédiate |
| `delegated` (opt-in, par agent) | la clé de déploiement, par tâche | pour une machine de confiance ; un agent compromis conserve la clé jusqu'à rotation |

Garde-fous du mode `delegated`, obligatoires et non configurables :

1. **refus si le transport n'est pas TLS** (`ZANSHIN_ALLOW_INSECURE_AGENT_CREDENTIALS`
   existe pour un essai local et n'a pas d'autre usage). Le scan est alors remis en file
   avec un message explicite — scanner sans la clé produirait un échec de clone
   ressemblant à un problème réseau, et l'opérateur ne saurait jamais que le mode choisi
   n'était pas en vigueur ;
2. **la clé n'est jamais persistée sur l'agent** : mémoire → fichier temporaire `0600` →
   supprimé après le clone ;
3. **une entrée d'audit par remise** (`AGENT_CREDENTIAL_SENT`). Si un agent est trouvé
   compromis, la seule question à laquelle on peut répondre est *quelles* clés il a
   reçues et quand.

Le champ `ssh_credential_expires_at` est présent dans le contrat, inutilisé : c'est le
modèle 2 de §5 (identifiants de courte durée), le seul réellement sûr là où le
fournisseur sait les émettre (GitHub App, GitLab). Y passer ne changera pas la forme du
message. **La dette est nommée, pas masquée.**

Le second risque de §5 — un agent compromis qui fabrique des résultats et influence
donc le verdict du gate — est traité par trois choses : un agent ne peut remonter que
sur une tâche qu'il a lui-même réclamée sous bail valide, la provenance est enregistrée
(`scan.claimed_by`), et toute remontée produit une entrée d'audit
(`AGENT_RESULT_SUBMITTED`), comme un triage.

Défaut trouvé en écrivant les tests : `still_owned` accepte une ligne sans propriétaire,
tolérance raisonnable pour l'agent intégré (c'est lui qui a réclamé les lignes d'avant
la migration) mais trou béant pour un agent distant — n'importe lequel aurait pu remonter
des résultats pour n'importe quel scan en file, sans jamais avoir reçu le travail. La
vérification côté API exige désormais une réclamation explicite.

### 10.6 Inbox de déduplication (D4)

Table `processed_message` (migration `0011`), `message_id` unique, écrite **dans la
transaction qui applique l'effet**. La contrainte d'unicité est le mécanisme, pas un
filet : deux réessais simultanés passeraient tous deux une vérification applicative, et
seule la base peut arbitrer.

Le dégât qu'un rejeu aurait causé est exactement celui que D4 décrivait : pas des
findings en double (`Issue.fingerprint` les empêche) mais un `times_seen` gonflé sur
chaque problème du rapport — c'est-à-dire le chiffre sur lequel un analyste juge si un
problème est chronique. Vérifié en réel : un rejeu identique répond `duplicate` et
`times_seen` reste à 1.

### 10.7 Envoi fractionné (étape 3.5)

Fait, sur le JSON sérialisé plutôt que sur la structure : l'agent découpe une chaîne et
n'a pas à comprendre ce qu'il découpe. Le réassemblage est **en mémoire, par processus**
— même choix, pour la même raison, que le quota d'API et l'anti-bourrage : ce plan de
contrôle est mono-processus. Un envoi interrompu est donc perdu au redémarrage, ce qui
est correct : l'agent détient encore le bail et rejoue tout le rapport.

### 10.8 Ce qui n'est pas fait

- **Étape 1 complète** : pas de `FOR UPDATE SKIP LOCKED`, pas d'élection
  d'ordonnanceur, pas de compteurs Redis. **Deux instances web restent non
  supportées** — §2.2, §2.4, §2.5 et §2.6 décrivent toujours des défauts réels.
- **`ZANSHIN_ROLE`** (D5, étape 2) : non implémenté. Un agent n'écoute déjà sur aucun
  port applicatif et n'a pas besoin de la base, donc la séparation de privilèges
  attendue de l'étape 2 est en partie acquise par construction ; mais le rôle `web`
  (qui n'exécuterait rien) s'obtient aujourd'hui en désactivant l'agent intégré, pas par
  une variable d'environnement.
- **Étape 4 (routage par capacité)** : les labels existent sur les agents et le
  filtrage existe dans la signature de `claim_next`, mais aucune cible ne porte encore
  de label requis — donc le routage ne fait rien. Assumé : il n'y a pas encore deux
  agents à départager.
- **Annulation coopérative** : annuler côté contrôleur libère la file, l'agent qui
  exécute continue et verra sa remontée refusée. Il faudrait que l'agent interroge un
  drapeau, ce qui coûte un aller-retour par scan pour une action exceptionnelle.
- **`scan-api/`** (§8.4 : « devient redondant ») : toujours là. Le backend `local_api`
  reste utilisable, y compris *depuis* un agent
  (`--scanner-engine local_api`), ce qui en fait le chemin de migration ; sa suppression
  n'est pas dans ce lot.

### 10.9 Vérification

Faite en réel, contre un contrôleur servi par granian et un agent lancé dans un autre
processus avec `python -m zanshin.agent` :

- un dépôt public a été scanné **de bout en bout par l'agent distant** (clone, Syft,
  Grype, gitleaks, checkov dans de vrais conteneurs Docker), 21 findings normalisés
  côté contrôleur, 21 problèmes créés, SBOM et sortie Grype brutes stockées ;
- l'agent intégré désactivé, le scan est resté `pending` jusqu'à ce que l'agent distant
  le réclame — c'est-à-dire que le geste « ne rien exécuter ici » a l'effet annoncé ;
- rejeu d'un rapport avec le même `message_id` : `duplicate`, `times_seen` inchangé ;
- bail forcé à échéance : scan remis en file aux tentatives 1 et 2, échoué à la 3ᵉ ;
- aucune clé de déploiement dans la charge d'un agent en mode `local` ; refus `412` et
  scan remis en file pour un agent `delegated` en HTTP.

Non vérifié en réel, et à savoir : le `Dockerfile.agent` n'a pas été construit (même
limite que `scan-api/Dockerfile`), et rien n'a été essayé contre PostgreSQL ou MySQL —
la suite multi-backends (`pytest -m backends`) couvre le schéma, pas le protocole
d'agent.

---

## 11. Statut d'implémentation — plan de contrôle multi-instance (étape 1), 2026-08-07

L'étape 1 après l'étape 3, donc, et sans que l'inversion coûte quoi que ce soit : les
baux et la propriété des scans posés pour les agents (§10.2) étaient précisément la
moitié du travail que cette étape demandait.

### 11.1 Réclamation transactionnelle (D1)

`claim_next` fait maintenant `SELECT … FOR UPDATE SKIP LOCKED` puis le changement de
statut **dans la même transaction** sur PostgreSQL et MySQL. SQLite garde l'`UPDATE`
conditionnel, qui suffit aux threads d'un processus.

Le contrôle de dialecte est explicite, et c'est important : le dialecte SQLite de
SQLAlchemy **laisse tomber `FOR UPDATE` en silence** au lieu de le refuser. Demander
sans vérifier aurait produit une réclamation d'apparence transactionnelle, verte sur la
machine du développeur, distribuant le même scan à deux processus en production.

**Ce que les tests réels ont trouvé.** Dix réclamants concurrents, connexions
distinctes, contre PostgreSQL 16 et MySQL 8.4 : aucun scan jamais réclamé deux fois —
la sûreté tenait dès la première version — mais six réclamants sur dix repartaient les
mains vides alors que vingt scans attendaient. MySQL compte les lignes verrouillées
dans `LIMIT` au lieu de les sauter ; PostgreSQL continue à parcourir. Un problème de
débit, pas de sûreté, dont la forme en production est un agent qui interroge la file
trente secondes pendant que du travail attend. Exactement la classe de défaut que §7
annonçait : invisible sur SQLite et à la lecture.

Deux corrections évidentes essayées et écartées, notées dans le code parce qu'elles
reviendront à l'esprit du prochain lecteur :

1. **élargir la fenêtre de sélection** puis la tronquer — fait échouer PostgreSQL sur
   les tests que MySQL échouait, parce qu'un réclamant qui verrouille des lignes qu'il
   ne prendra pas affame les autres tant qu'il les tient ;
2. **une fenêtre réservée à MySQL** — fonctionne, puis devient inutile dès que le budget
   de réessais est correct.

Reste le plus simple : demander exactement ce dont on a besoin, et réessayer. Budget
mesuré (4 tentatives laissaient trois réclamants à vide, 12 aucun), pas choisi au goût.

### 11.2 Ordonnanceur à propriétaire unique (§2.2)

Table `leader_lease` (migration `0012`), une ligne par travail devant avoir exactement
un propriétaire. Le tick se coupe selon ce qu'est chaque travail :

| Travail | Portée | Pourquoi |
|---|---|---|
| Rafraîchir son agent intégré, réclamer des scans | **chaque instance** | une flotte dont les instances n'attrapent du travail qu'en détenant le bail resterait inactive derrière son leader |
| Scans planifiés, rétention, expiration des triages, relais outbox, tickets, reprise des baux | **le porteur du bail** | leur effet est « une fois par période » |

Un bail en table plutôt qu'un verrou consultatif (`pg_advisory_lock`, `GET_LOCK`) :
ceux-ci sont nommés et portés différemment selon le moteur et n'existent pas sur SQLite,
donc le mono-processus devrait se traiter à part. Une ligne fonctionne pareil sur les
trois, et — l'argument qui a tranché — elle est **observable** : quand quelque chose a
cessé de se produire, la table dit qui était censé le faire et jusqu'à quand. La page
Agents l'affiche.

L'acquisition échoue **fermée** : une instance qui ne peut pas joindre la table ne
s'autorise pas à supposer qu'elle est seule. Sauter un tick coûte une minute de
latence ; se croire leader à tort coûte un scan dupliqué de chaque cible due.

### 11.3 Refus et avertissements au démarrage (D6, §2.4, §2.6)

`zanshin/startup_guard.py`. La détection ne demande rien à l'opérateur — un drapeau de
configuration serait faux précisément quand ça compte, parce que personne ne le règle.
Chaque instance enregistre déjà un agent intégré par hôte et le rafraîchit à chaque
tick : une autre instance vivante, c'est la ligne d'un autre hôte vue récemment.

- **deux instances sur SQLite : refus**, avec l'autre hôte, la raison et la sortie
  nommés. Un seul écrivain, et pas de `SKIP LOCKED` pour rendre la réclamation sûre ;
- **plusieurs instances sans état Reflex partagé** ou **avec `ZANSHIN_AUTO_MIGRATE`
  actif** : avertissements. Ça dégrade, ça ne corrompt pas.

Deux limites assumées : deux instances sur le **même hôte** partagent une ligne et sont
invisibles ici (ce déploiement n'achète rien qu'une limite de simultanéité plus haute ne
donnerait), et une instance arrêtée depuis moins de deux minutes paraît encore vivante —
ce qui peut refuser un redémarrage sous un nouveau nom d'hôte, comme en fait un rolling
restart Kubernetes. D'où `ZANSHIN_ALLOW_MULTI_INSTANCE_SQLITE`, dont c'est le seul usage.

### 11.4 Compteurs partagés (D2, §2.5)

`zanshin/services/counter_store.py` : Redis quand `REDIS_URL` est réglé, mémoire sinon.
La même variable que Reflex utilise pour son état, délibérément — un opérateur en flotte
doit de toute façon la régler, et demander une seconde URL vers le même serveur serait un
moyen de les désynchroniser.

Deux formes, parce que les deux appelants comptent différemment et qu'aucun ne doit
changer de sémantique pour partager un magasin : fenêtre fixe (le quota dit *quand*
réessayer) et fenêtre glissante (un verrouillage ne doit pas devenir indulgent à la
frontière d'une fenêtre).

**Redis injoignable autorise au lieu de refuser.** Choix délibéré : ces garde-fous
protègent d'un abus, et une panne Redis qui transformerait chaque login et chaque appel
d'API en refus convertirait une panne de dépendance en panne totale.

### 11.5 L'étape 2 (rôles) est écartée, pas oubliée

`ZANSHIN_ROLE=all|web|agent` (D5) n'est pas implémenté, et ne devrait pas l'être tel
quel : les deux rôles qu'il décrit existent déjà autrement. Le rôle `agent` est un point
d'entrée séparé (`python -m zanshin.agent`) qui n'écoute sur aucun port applicatif et
n'a pas de base ; le rôle `web` s'obtient en désactivant l'agent intégré depuis la page
Agents, ce qui est visible là où un opérateur regarde déjà. Une troisième façon de dire
la même chose finirait par contredire les deux autres — c'est le même raisonnement qui a
fait réutiliser `scan_max_concurrent` pour l'agent intégré plutôt que d'inventer un
second nombre (§10.3).

Ce que l'étape 2 promettait vraiment — la séparation de privilèges — est acquis par
construction : un agent n'a ni socket ouvert, ni base, ni `ENCRYPTION_KEY`.

### 11.6 Ce qui reste

- **Étape 4 (routage par capacité)** : les labels existent sur les agents et le
  filtrage est dans la signature de `claim_next`, mais aucune cible ne porte de label
  requis. Assumé : il n'y a pas encore deux agents à départager.
- **Un répartiteur de charge réel n'a pas été essayé.** Deux processus contre un même
  PostgreSQL et un même Redis, si (§11.7) — ce qui couvre l'élection et les compteurs.
  Ce qui reste non éprouvé est la couche au-dessus : sessions collantes ou
  `state_manager_mode = "redis"` sous un vrai trafic navigateur, c'est-à-dire §2.4, dont
  la cause appartient à Reflex et pas à ce code.
- **`scan_cron`** reste ignoré par l'ordonnanceur (limite antérieure, inchangée).

### 11.7 Vérification

- `pytest -m backends`, qui tourne désormais **en CI** dans un job dédié — il n'en
  existait aucun, donc la suite PostgreSQL/MySQL écrite en §9decies n'avait jamais été
  exécutée automatiquement. Les tests qui exigent un serveur y sont marqués, y compris
  la moitié Redis des tests de compteurs (le paramètre est marqué, pas le test, pour que
  chaque cas reste écrit une seule fois pour les deux implémentations) ;
- réclamation : dix réclamants concurrents sur PostgreSQL 16 et MySQL 8.4, trois
  exécutions consécutives, chaque scan attribué exactement une fois ;
- élection : un seul des deux ordonnanceurs dispatche une cible due, le suiveur continue
  de réclamer du travail, le bail passe quand le porteur cesse de le renouveler, et une
  table injoignable ne fait pas croire à une instance qu'elle est seule ;
- garde-fou : vérifié dans les deux sens sur une vraie base — une instance seule démarre,
  une seconde est refusée avec le message attendu ;
- **deux processus réels contre un même PostgreSQL 16 et un même Redis** :
  - trois cibles dues, deux ordonnanceurs qui tiquent six fois chacun en parallèle →
    **trois scans créés, pas six**. C'est §2.2 clos entre processus, pas seulement entre
    identités simulées ;
  - le bail forcé à échéance est repris par une troisième instance au tick suivant ;
  - compteurs partagés : la seconde instance n'obtient que 2 requêtes sur 8 (le quota
    commun de 10 était déjà entamé) et voit les 6 échecs de connexion, donc le compte se
    verrouille. **Sans `REDIS_URL`, le même scénario donne 8 sur 8 des deux côtés et
    aucun verrouillage** — le défaut de §2.5 reproduit, puis corrigé.
