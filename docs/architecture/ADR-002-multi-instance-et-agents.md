# ADR-002 — Exécution multi-instance et agents

**Statut :** proposé, non implémenté
**Date :** 2026-08-06
**Contexte :** suite d'ADR-001 §9decies (la base de données est devenue configurable, donc PostgreSQL et MySQL sont possibles)

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

### 2.1 La file d'attente est dans le processus qui a reçu la requête

[`repository_service.py`](../../zanshin/services/repository_service.py) crée un
`ThreadPoolExecutor` de module (`ZANSHIN_SCAN_WORKERS`, 5 par défaut) et
`executor.submit(...)` y dépose le travail. `container_service.py` partage le même
exécuteur. Conséquence directe : le travail appartient au processus qui l'a accepté.
Avec deux instances, il n'y a pas une file de dix travailleurs, il y a deux files de
cinq qui s'ignorent — et une instance qui redémarre emporte les scans qu'elle tenait.

### 2.2 L'ordonnanceur déclencherait chaque scan deux fois

[`scheduler.py`](../../zanshin/services/scheduler.py) est un thread démon par
processus. Il estampille `last_scheduled_scan_at` *avant* de dispatcher, ce qui protège
contre un double déclenchement par le même processus, pas contre deux processus qui
tiquent en même temps. Deux instances = deux scans par échéance, donc le double de
conteneurs de scan, de trafic registre et d'appels d'API d'enrichissement.

Le tick héberge aussi la reprise des scans bloqués, la purge des charges brutes et
l'expiration des triages : trois travaux qui doivent avoir **un seul** propriétaire.

### 2.3 Le démarrage d'une instance tue les scans de l'autre

`recover_interrupted_scans()` s'exécute à l'import dans
[`zanshin.py`](../../zanshin/zanshin.py) et marque en échec tout scan encore « en
vol », en partant du principe qu'il appartient à un processus disparu. C'est vrai
aujourd'hui — tous les imports ont lieu au démarrage, avant qu'un scan ne tourne. Avec
deux instances, **la seconde qui démarre fait échouer les scans en cours de la
première.** C'est le même piège que la migration concurrente corrigée en §9decies :
du code d'initialisation qui suppose être seul.

### 2.4 L'état Reflex est sur le disque local

`state_manager_mode` vaut `disk` par défaut dans Reflex 0.9.6 (les autres valeurs sont
`memory` et `redis`). L'état serveur d'un client vit donc sur l'instance qui a accepté
sa connexion. Sans état partagé, un client qui atterrit sur l'autre instance se
retrouve déconnecté et sans contexte, de façon intermittente et impossible à
diagnostiquer depuis les journaux.

C'est le blocage le plus dur, parce qu'il ne se contourne pas par du code applicatif :
il faut soit des sessions collantes au niveau du répartiteur, soit
`state_manager_mode = "redis"` avec `redis_url`. **Redis n'est donc pas optionnel pour
un étage web réparti** — ce qui change la réponse au point suivant.

### 2.5 Deux garde-fous de sécurité sont en mémoire, par processus

- [`rate_limit.py`](../../zanshin/api/rate_limit.py) : fenêtre fixe par clé API, dans un
  dictionnaire. Avec deux instances, le quota double.
- [`login_throttle.py`](../../zanshin/services/login_throttle.py) : même structure.
  L'anti-bourrage se contourne en alternant les instances.

Les deux dégradent une propriété de sécurité, silencieusement, sans qu'aucun test
existant ne le voie.

### 2.6 Le verrou de migration ne couvre qu'un hôte

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

### Étape 0 — Outbox des notifications *(indépendante, livrable seule)*

Corrige un bug existant et valide le pattern sur un cas réel avant de l'appliquer là où
il compte.

- Table `outbox_message` (id, type, charge JSON, créé le, tentatives, envoyé le, dernière erreur).
- Écriture dans la transaction qui produit le résultat de scan.
- Relais sur le tick de l'ordonnanceur, à côté de la rétention et de l'expiration des triages.
- Réessai avec recul exponentiel, plafonné ; échec définitif journalisé et visible.

**Vérification :** une notification survit à un arrêt brutal entre la validation et
l'envoi ; un envoi rejoué ne duplique pas ; un point d'arrivée en panne n'empêche pas le
scan de se terminer.

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
