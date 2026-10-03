# 0038 — Sur Kubernetes, le plan de contrôle tourne sans point d'accès aux conteneurs, les scans tournent sur des agents sur un hôte Docker, la base est externe, et les plugins de rapport attendent un exécuteur capable de joindre un démon distant

**Date :** 2026-10-03 · **Statut :** proposée · **S'appuie sur :** [0002](0002-the-database-carries-the-queue.md), [0003](0003-long-polling-for-agents.md), [0013](0013-flyway-multi-dialect-migrations.md), [0018](0018-the-docker-socket-is-never-mounted.md), [0035](0035-report-plugins.md) · **Décideur :** Laurent Boucher

*Proposée. La forme du déploiement (§1–§7) est écrite telle qu'elle serait décidée. Une question
reste ouverte, sous « À trancher » : où tournent les plugins de rapport. L'examen qui la fonde (§3) a
montré qu'ils ne peuvent pas tourner sur un démon Docker distant sans modification du code ; aucune
chart n'est donc écrite : une chart qui installe une fonction qui ne peut pas marcher n'est pas une
chart à livrer.*

## Contexte

La première installation de production est attendue pour fin octobre 2026, **sur Kubernetes**, un
cluster construit par son propriétaire. MySQL est installé à part, pas par Vectispire. Le dépôt ne
contient aucun matériel Kubernetes : la seule composition livrée est `docker-compose.yml`, qui
s'appuie sur trois choses qu'un pod standard n'a pas.

- **Un démon Docker.** Le worker intégré, les plugins et les plugins de rapport lancent tous leurs
  conteneurs par `ContainerRunner`, qui parle à `DOCKER_HOST` — dans la composition, un proxy de
  socket sur le même hôte ([0018](0018-the-docker-socket-is-never-mounted.md)). Un pod n'a pas de
  socket, et ne doit pas en recevoir.
- **Le même chemin des deux côtés.** L'espace de travail d'un scan, la base du matcher et l'entrée
  d'un rapport sont créés sous `java.io.tmpdir` puis confiés au démon en **bind mounts**, que le démon
  résout sur *son* hôte. La composition fait coïncider les deux systèmes de fichiers en montant
  `VECTISPIRE_WORK_DIR` au même chemin absolu (guide d'installation, « Espaces de travail des scans »).
- **Des volumes sur un hôte.** Le miroir d'audit et le répertoire de travail sont des répertoires de
  l'hôte.

Ce qui tient déjà sans hôte : la file est dans la base ([0002](0002-the-database-carries-the-queue.md)),
les agents interrogent en HTTPS et n'ont besoin d'aucune connexion entrante
([0003](0003-long-polling-for-agents.md)), les secrets se lisent comme des fichiers
(`spring.config.import: optional:configtree:/run/secrets/`, `ENCRYPTION_KEY_FILE`), et le point de
santé publie les sondes Kubernetes (`management.endpoint.health.probes.enabled: true` ;
`/actuator/health/liveness` et `/readiness` sont ouverts sans session, `PlatformMetricsTest`).

## Décision

### 1. Ce qui tourne dans le cluster

- **Le plan de contrôle, en Deployment**, depuis l'image publiée **par empreinte** (Jib, utilisateur
  `1000:1000`, port 3180). Il sert l'interface depuis le même jar et la même origine — pas de second
  workload pour le front, et `connect-src 'self'` reste vrai.
- **Un Ingress avec TLS** devant, pour les personnes comme pour les agents. Trois réglages découlent
  de ce que fait l'application, pas du goût :
  - un **délai de lecture d'au moins 60 s** : le long polling d'un agent tient sa requête jusqu'à
    30 s (`AgentJobPoller.MAX_WAIT`) ;
  - une **taille de corps d'au moins 256 Mo** : le résultat d'un agent porte le SBOM
    (`VECTISPIRE_MAX_BODY_AGENT_RESULT`) ; un jeu de règles fait 64 Mo ;
  - **`VECTISPIRE_TRUSTED_PROXIES` réglé sur les adresses du contrôleur d'Ingress**, sinon le
    limiteur de débit et chaque entrée d'audit nomment le contrôleur (`TrustedProxies`), et
    `X-Forwarded-Proto` est ignoré : le TLS terminé à l'Ingress se lit alors comme du HTTP en clair
    côté pod, et le cookie de passage de l'authentification unique part sans `Secure`.
- **`VECTISPIRE_EMBEDDED_WORKER=false`.** Le plan de contrôle ne lance aucun conteneur : il n'a pas
  de démon où le faire (§3).
- **Rien d'autre.** Pas de base, pas de démon, pas de sidecar.

**Réplicas : un au démarrage, deux pris en charge une fois les deux conditions ci-dessous réunies.**
Le code a été écrit pour plusieurs instances, et chaque mécanisme a un nom :

| État partagé | Comment deux instances s'accordent |
|---|---|
| La file de scans | prise conditionnelle sur la ligne, baux repris à expiration (0002, `ScanQueue`) |
| Planification, purge, expiration du triage, reprise | un bail de leader par `UPDATE` conditionnel (`LeaderElection`, `SchedulerService`) |
| Tâches de maintenance | exécutées sur chaque instance par contrat, écrites pour le supporter (`MaintenanceTask`) ; le relais réclame chaque message (`OutboxService.relay`) |
| Sessions, défis MFA, fenêtres de débit | des lignes, pas des maps (`SessionEntity`, `MfaChallengeEntity`, `RateWindows`, V44) |
| Long polling des agents | chacun relit la file chaque seconde, quelle que soit l'instance qui tient la requête (`AgentJobPoller`) |
| La chaîne d'audit | sa tête est une ligne verrouillée (V66, `AuditChainConcurrencyIntegrationTest`) |
| La clé de signature des documents | générée une fois, insérée si absente, relue (`SigningKeyService`) |

Chacun est testé sur les vrais moteurs par deux sessions ou deux fils ; **aucun par deux
applications en marche**, d'où un réplica au démarrage. Deux réplicas demandent :

- **l'affinité de session pour l'authentification unique.** Le flux OIDC par code garde son état et
  son nonce dans la session servlet (`OidcConfiguration`, `SessionCreationPolicy.IF_REQUIRED`) ; un
  retour qui arrive sur l'autre pod ne trouve aucune demande d'autorisation et la connexion échoue.
  L'affinité par cookie sur l'Ingress règle le cas. La connexion par mot de passe et la MFA n'en ont
  pas besoin — ce sont des lignes ;
- **un fichier de miroir d'audit par pod** (§5), jamais un seul fichier alimenté par deux processus.

La concurrence des rapports et des découvertes est par instance (`VECTISPIRE_REPORT_CONCURRENCY`,
`VECTISPIRE_DISCOVERY_CONCURRENCY`) : deux réplicas la doublent.

### 2. Les scans tournent sur des agents, sur un hôte Docker dédié

Les scans, les plugins de scan et les vérifications produisant du SARIF tournent sur **des agents
sur une VM Docker hors du cluster**, exactement la forme du profil `with-agent` de la composition :
l'agent, son propre proxy de socket, son répertoire de travail monté au même chemin absolu, son home
dessous ([Agents](../../../../docs-site/administration/agents.fr.md)). L'agent joint le plan de
contrôle par l'Ingress en HTTPS, tout ce que 0003 lui demande ; sa JVM doit faire confiance au
certificat de l'Ingress. Rien ne change pour l'agent : les bind mounts de ses scanners sont des
chemins de son propre hôte, qui est l'hôte de son démon.

C'est aussi la frontière que 0018 désigne comme la vraie — l'exécution sur une autre machine que le
processus qui détient `ENCRYPTION_KEY` — atteinte par construction plutôt que par un profil qu'il
faut penser à choisir.

### 3. Où les conteneurs ne peuvent pas tourner, aujourd'hui : les plugins de rapport

0035 §2 exécute les plugins de rapport sur **le point d'accès aux conteneurs du plan de contrôle**,
sous l'interrupteur du worker intégré. Sur Kubernetes, ce point d'accès devrait être un **démon
distant**, joint en TCP avec TLS. L'exécuteur a été lu pour ce que cela donnerait (`ContainerRunner`,
`ContainerRun`, `ReportPluginRenderer`, `ImageSignatureVerifier`, `ReportExecutorConfiguration`, les
sources de docker-java 3.7.1). **Cela ne marche pas aujourd'hui, pour trois raisons indépendantes :**

1. **Le TLS est lu et pas utilisé.** `ContainerRunner.clientAt` construit sa configuration par
   `DefaultDockerClientConfig.createDefaultConfigBuilder()`, qui lit bien `DOCKER_TLS_VERIFY` et
   `DOCKER_CERT_PATH` dans `getSSLConfig()` — puis construit le transport par
   `new ApacheDockerHttpClient.Builder().dockerHost(…)` seul, jamais `.sslConfig(…)`.
   `ApacheDockerHttpClientImpl` ne choisit `https` pour un hôte `tcp://` que si on lui a donné un
   contexte SSL. `DOCKER_HOST=tcp://hôte:2376` parle donc HTTP en clair à un port TLS, et chaque appel
   échoue.
2. **Les entrées sont des bind mounts, et un bind est un chemin de l'hôte du démon.** Trois : le
   répertoire d'entrée du rapport qui contient `export.json` (`ReportPluginRenderer.writeInput`, monté
   en lecture seule sur `/input`), la clé publique cosign d'un signataire par clé
   (`ImageSignatureVerifier`), et le login de registre écrit pour un registre privé
   (`ContainerRunner.run`, `REGISTRY_LOGIN_MOUNT`). Tous passent par `HostConfig.withBinds`, et un
   démon à qui l'on donne un bind dont il n'a pas la source **la crée, vide**. Un démon distant
   donnerait donc au plugin un `/input` vide (le run échoue en `exit_code`, consigné comme ayant pu
   lire l'export), à cosign un répertoire à la place de la clé (`signature_unverified`), et aucun
   login (`registry_authentication_required`). Chaque échec est sûr — rien de non vérifié ne tourne,
   rien n'est signé — et aucun n'est un rapport. *La sortie, elle, marcherait* : c'est un volume tmpfs
   tenu par un conteneur gardien et relu par l'API d'archive (`copyArchiveFromContainerCmd`), qui ne
   nomme jamais un chemin de l'hôte. Un signataire sans clé (keyless) sur un registre public se
   vérifierait aussi : il ne monte rien.
3. **L'exécuteur n'existe qu'avec le worker intégré.** `ReportExecutorConfiguration` est
   `@ConditionalOnProperty("vectispire.worker.enabled")`. Éteint, pas d'exécuteur, et une demande de
   rapport répond 409 `report-executor-unavailable`. Allumé, le worker intégré réclame aussi des scans
   et les lance sur le même démon distant — dont les espaces de travail sont des binds eux aussi, donc
   chaque scan échouerait — et le plan de contrôle clonerait de nouveau avec les clés de déploiement,
   la concentration que 0003 et 0018 ont défaite.

Et une hypothèse de la composition serait perdue même une fois les trois corrigées : **le proxy de
socket est le filtre de l'API.** Le port TCP propre d'un démon, avec TLS, n'en a aucun : qui détient
le certificat client a `exec`, les volumes, Swarm et le reste. Un hôte de rapports distant devrait
garder le proxy livré derrière un terminateur TLS mutuel sur cet hôte, pour que le certificat ouvre
les appels qu'ouvre le proxy de la composition, et rien de plus.

**Ce qui marche sur Kubernetes aujourd'hui, donc :** tout le produit sauf les plugins de rapport —
scans et plugins de scan sur agents, imports SARIF, triage, la barrière, les rapports et exports
intégrés (rendus dans la JVM, pas dans un conteneur), la découverte, le SIEM, les tickets. Les
plugins de rapport répondent 409, comme 0035 le dit d'une installation tout-agent.

### 4. La base est externe

- **MySQL, un seul hôte dans l'URL** — `jdbc:mysql://db.example.org:3306/vectispire`. Une URL dont
  les hôtes viennent du DNS (`mysql+srv`) ou qui en nomme plusieurs est refusée au démarrage par
  `ReservedEndpoints`, qui doit connaître l'adresse de la base pour en écarter les webhooks.
- **TLS vers MySQL** par les propriétés de Connector/J : `sslMode=VERIFY_IDENTITY`, et l'autorité du
  serveur dans un truststore monté depuis un Secret (`trustCertificateKeyStoreUrl=file:…`).
- **`max_allowed_packet` d'au moins `160M`** sur le serveur. Un export et un paquet de rapport signé
  sont bornés à 64 Mio et voyagent en hexadécimal, au double de leur taille (`ReportExportCeiling`) ;
  au défaut de 64 Mio la borne tombe à environ 32 Mio. Sans effet tant que les plugins de rapport ne
  tournent pas, réglé dès maintenant pour ne pas être la prochaine surprise.
- **UTC.** La JVM est en UTC — l'image ne fixe aucun fuseau, et la chart ne doit pas fixer `TZ` — et
  le `default_time_zone` du serveur devrait être `'+00:00'` : les migrations MySQL donnent à certaines
  colonnes un défaut `CURRENT_TIMESTAMP` (V10, V12, V13), que le serveur évalue dans le fuseau de la
  session.
- **Migrations au démarrage, comme aujourd'hui.** Flyway prend un verrou nommé MySQL pendant qu'il
  migre (`GET_LOCK`, `MySQLNamedLockTemplate` de flyway-mysql 12.4.0) : deux pods qui démarrent
  ensemble ne migrent pas tous les deux, l'un migre, l'autre attend. Les sauvegardes et l'exercice de
  restauration (`scripts/restore-drill.sh`) relèvent du propriétaire de la base.

### 5. Les secrets, et ce qui doit survivre à un redémarrage

**Les secrets sont des fichiers, venus de Secrets Kubernetes, montés sous `/run/secrets/`** — l'arbre
de configuration que l'application importe déjà, et que Spring Boot lit tel que Kubernetes le
dispose :

| Fichier | Contient | Pourquoi |
|---|---|---|
| `encryption_key`, lu par `ENCRYPTION_KEY_FILE` | la clé qui déchiffre chaque clé de déploiement et chaque jeton | pas nommé `ENCRYPTION_KEY`, sinon l'arbre fixe aussi la variable et les deux ensemble sont refusés |
| `VECTISPIRE_DB_PASSWORD` | le mot de passe de la base | — |
| `VECTISPIRE_BOOTSTRAP_PASSWORD` | le mot de passe du premier administrateur | lu seulement tant que la table des comptes est vide |
| `vectispire.signing.key` | la clé de signature des documents, PEM | facultative ; à fixer avec deux réplicas, et à garder : une clé remplacée rend invérifiable chaque document déjà signé |
| `vectispire.oidc.client-secret` | le secret du client OIDC | avec l'authentification unique |
| `VECTISPIRE_PREVIOUS_ENCRYPTION_KEYS_FILE` | les clés précédentes, pendant une rotation | pendant une rotation seulement |

**Rien sur le disque du plan de contrôle ne doit survivre à un redémarrage, sauf le miroir
d'audit.** Worker éteint, il ne clone rien : il n'enregistre aucune clé d'hôte SSH et ne garde aucune
base du matcher ; la clé de signature, quand elle est générée, est stockée chiffrée en base. Le
miroir (`VECTISPIRE_AUDIT_MIRROR`) est ce qui fait de la suppression de la dernière entrée d'audit une
seconde modification sur un second support ; sur Kubernetes c'est un **volume persistant**, et **un
fichier par pod** — le nom du pod dans le chemin — car deux processus qui ajoutent au même fichier sur
un volume partagé entremêlent leurs lignes. `/audit-log/verify` compare alors la table au fichier du
pod qui répond : les entrées écrites par l'autre pod sont « absentes du miroir », ce qui est signalé
sans rompre l'intégrité ; une entrée présente dans un fichier et absente de la table la rompt
toujours.

### 6. La forme du pod

- **Contexte de sécurité** : `runAsNonRoot`, utilisateur et groupe 1000,
  `allowPrivilegeEscalation: false`, toutes les capacités retirées, `seccompProfile: RuntimeDefault`,
  et un **système de fichiers racine en lecture seule** avec des volumes `emptyDir` pour
  `java.io.tmpdir` et le home (`/home/vectispire`). La lecture seule est l'intention, à confirmer en
  démarrant l'image ainsi avant que la chart ne l'affirme.
- **Sondes** : une **sonde de démarrage** sur `/actuator/health/liveness` assez longue pour les
  migrations (la composition accorde 120 s), puis la vivacité sur `/actuator/health/liveness` et la
  disponibilité sur `/actuator/health/readiness`, avec
  `management.endpoint.health.group.readiness.include` réglé sur `readinessState,db` pour qu'un pod qui
  a perdu sa base cesse de recevoir du trafic plutôt que de répondre 500.
- **Ressources** : l'image dimensionne déjà le tas à 75 % de la mémoire du conteneur
  (`-XX:MaxRAMPercentage=75`). Commencer à 1 Gio demandé et 2 Gio de limite, 0,5 CPU demandé, et
  mesurer : les rapports intégrés se rendent en mémoire.
- **NetworkPolicy, facultative et grossière.** En entrée, le 3180 depuis le contrôleur d'Ingress
  seulement. En sortie, le DNS, la base, les forges (la découverte lit leur API ; l'autorité interne
  est épinglée sur la connexion de forge, pas dans la JVM), l'émetteur OIDC, le collecteur SIEM, les
  outils de tickets et les flux de menace ou leurs miroirs. Une politique nomme des adresses, pas des
  hôtes : c'est un plancher, et le contrôle par destination reste `OutboundUrlGuard` →
  `PinnedHttpSender`.

### 7. Les mises à jour

**`strategy: Recreate`, pas de mise à jour progressive.** Le verrou de Flyway empêche deux
migrations de se heurter, mais une mise à jour progressive garde aussi la version *précédente* en
service sur le schéma *migré*, et rien dans les règles de migration (0013, 0027) ne demande à une
migration de laisser fonctionner la version précédente. Une mise à jour arrête donc tous les pods,
démarre la nouvelle image, qui migre, puis sert. Il n'y a pas de migration descendante : revenir en
arrière, c'est restaurer la sauvegarde de la base prise avant la mise à jour, avec l'empreinte de
l'image précédente.

## À trancher : où tournent les plugins de rapport sur Kubernetes

| | Ce qu'il faut | Ce que cela coûte |
|---|---|---|
| **A. Un exécuteur qui copie les entrées, sur un démon distant** | (1) `clientAt` passe au transport les réglages SSL de la configuration — quelques lignes ; (2) des entrées copiées plutôt que montées : un second gardien qui tient un volume tmpfs, rempli par l'API d'archive (`copyArchiveToContainerCmd` ; le démon refuse une archive écrite sur une racine en lecture seule, pas sur un chemin de volume — les tests doivent le confirmer), monté en lecture seule dans le plugin ; utilisé pour l'export, la clé cosign et le login de registre — quelque deux cents lignes dans `ContainerRunner`/`ContainerRun` ; (3) un interrupteur propre à l'exécuteur de rapports, qui vaut par défaut celui du worker. Des tests contre un démon qui ne voit pas les fichiers du processus. **Environ deux à trois jours.** | Le plan de contrôle détient un certificat client vers un hôte Docker : root sur cet hôte. Un hôte réservé aux rapports, son proxy derrière du TLS mutuel, ramène cela à ce dont les rapports ont besoin. 0035 §2 tient tel quel. |
| **B. Les plugins de rapport sur les agents** — le lot ultérieur de 0035 | L'export scellé pour un agent désigné avec les clés de 0031, un nouveau type de travail d'agent, le rendu sur l'agent, la sortie renvoyée et vérifiée avant d'être signée. | Le plus gros. L'export confidentiel quitte le plan de contrôle pour un hôte dont l'exploitant n'est peut-être pas un lecteur du projet — la raison pour laquelle 0035 l'a différé. Le cluster ne détient alors plus aucun accès Docker. |
| **C. Un système de fichiers partagé au même chemin** sur le pod et l'hôte de rapports (NFS) | Pas de code pour les binds ; le TLS par un sidecar ; le worker allumé pour avoir l'exécuteur. | Écarté : allumer le worker ramène scans et clones sur le plan de contrôle, et l'export comme chaque espace de travail traversent le réseau sur un partage. |
| **D. Démarrer sans plugins de rapport** | Rien. | Les plugins de rapport répondent 409 jusqu'à ce que A ou B arrive ; tout le reste marche. |

**Recommandation : D pour fin octobre, puis A.** L'échéance est tenue avec la forme testée
aujourd'hui, et A est petit, garde intact le raisonnement de 0035, et sera redemandé par toute
installation sans démon local. La chart s'écrit une fois ceci tranché — pour D elle n'a besoin
d'aucun réglage Docker ; pour A elle gagne l'hôte distant et son certificat en Secret.

## Alternatives écartées

- **Un sidecar Docker-in-Docker.** Il exige un conteneur privilégié, root sur le nœud à peu de chose
  près, dans le pod qui détient `ENCRYPTION_KEY` — la concentration de 0018, en pire.
- **Monter le socket Docker ou containerd du nœud.** Root sur le nœud, pour chaque workload qu'il
  porte ; et un socket containerd ne parle de toute façon pas l'API Docker qu'utilise
  `ContainerRunner`.
- **Lancer les scanners comme des Jobs Kubernetes** — un backend Kubernetes pour `ContainerRunner`.
  La forme fermée ne se transpose pas terme à terme : la limite de taille d'un `emptyDir` s'applique
  par éviction, pas par le noyau comme le tmpfs de la sortie bornée ; le pod qui les crée a besoin du
  droit RBAC de créer des pods, depuis le processus qui détient la clé. Une réécriture de l'exécuteur,
  pas un choix de déploiement ; pas pour octobre.
- **Le worker intégré sur un démon distant.** Chaque espace de travail est un bind (§3), et le plan
  de contrôle clonerait de nouveau.
- **MySQL dans la chart** (une sous-chart de base). La base est installée et sauvegardée par son
  propriétaire ; une chart qui en livre aussi une invite à en avoir deux.
- **Une mise à jour progressive.** Voir §7.
- **Plusieurs réplicas dès le premier jour.** Voir §1 : les mécanismes existent, deux applications
  en marche n'ont pas été essayées, et l'authentification unique demande l'affinité.

## Conséquences

- Une installation Kubernetes est une installation tout-agent : au moins un agent sur un hôte Docker
  est nécessaire avant le premier scan.
- Les plugins de rapport sont indisponibles sur Kubernetes jusqu'à ce que la question ci-dessus soit
  tranchée et construite.
- Le miroir d'audit demande un volume persistant et un fichier par pod.
- Le guide d'installation gagne une section Kubernetes, et la chart vit sous
  `deploy/helm/vectispire/`, vérifiée et rendue en CI — une fois la chart écrite.
