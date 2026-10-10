# Installation

Vectispire, c'est deux processus et une base de données : un plan de contrôle Spring Boot qui
sert l'API et l'interface compilée, et — facultativement — un ou plusieurs agents distants. Une
installation sur une seule machine n'a besoin ni de l'agent ni d'aucune configuration d'agent.

## Prérequis

| Prérequis | Pourquoi |
|---|---|
| **Docker**, démarré et joignable | Chaque scanner s'exécute comme un conteneur éphémère que Vectispire demande à un démon Docker de démarrer — à travers un proxy de socket dans la composition, voir ci-dessous. Ce n'est pas facultatif : il y a un seul moteur de scan, et c'est Docker. |
| **MySQL 8** (défaut) ou **PostgreSQL** | Les deux sont supportés et exercés par la campagne d'intégration ; MySQL est le défaut et le moteur que livre la composition. Le moteur est lu depuis l'URL JDBC ; il n'y a pas de réglage de dialecte séparé. |
| **Git** | Vectispire clone ce qu'il analyse. |
| **Node 24 (LTS)**, **JDK 25** | Uniquement si vous construisez depuis les sources plutôt que d'exécuter les images publiées. Node est épinglé par `.nvmrc` ; Angular 22 refuse Node 25. |

!!! warning "Accès à un démon Docker"
    Vectispire exécute ses scanners en conteneurs, il lui faut donc joindre un démon — mais
    **il ne monte pas le socket**. La composition place un `docker-socket-proxy` devant, sur un
    réseau interne, et pointe le plan de contrôle dessus via `DOCKER_HOST`. Rien à configurer
    de votre côté, aucun groupe `docker` à rejoindre.

    Hors compose, directement contre un démon ? Là, l'utilisateur doit bien avoir accès à
    `/var/run/docker.sock`, et sous Linux cela signifie généralement le groupe `docker`. Sans
    cela, chaque scan échoue au premier conteneur.

    Le démon désigné par `DOCKER_HOST` et chaque hôte de l'URL JDBC sont **réservés** : aucun
    webhook, serveur d'IA, collecteur SIEM ou connexion forge ne peut les viser, quelle que soit la
    politique. Dans un pod Kubernetes, le service d'API du cluster l'est aussi
    (`KUBERNETES_SERVICE_HOST` et `KUBERNETES_SERVICE_PORT`, donnés à chaque pod). Le
    plan de contrôle **refuse donc de démarrer** s'il ne sait pas lire ces hôtes — un
    `DOCKER_HOST` qui n'est ni `unix://`, ni `npipe://`, ni `tcp://`, `http://` ou `https://`, ou
    une URL JDBC dont les hôtes ne figurent pas dans la chaîne (`jdbc:mysql+srv://`). Les URL à
    plusieurs hôtes ou de réplication, la forme MySQL `address=(host=…)` et les noms d'hôte avec
    un tiret bas sont lus ; pour MySQL, le port 33060 du protocole X est réservé à côté du port
    classique.

!!! danger "Un seul hôte, un seul rayon d'impact"
    Avec le worker intégré actif — le défaut — le processus qui peut créer des conteneurs est
    celui qui détient `ENCRYPTION_KEY`, et l'accès au démon vaut root sur cet hôte. Le proxy
    réduit ce que l'on peut demander au démon ; il ne sépare pas les deux. Au-delà d'une
    installation mono-équipe, faites tourner un **agent distant** et posez
    `VECTISPIRE_EMBEDDED_WORKER=false` sur le plan de contrôle. Voir la
    [décision 0018](https://github.com/asmolabs/vectispire/blob/main/docs/architecture/fr/decisions/0018-the-docker-socket-is-never-mounted.md).

## Le chemin le plus court : Docker Compose

```bash
cp .env.example .env      # puis éditez-le — voir ci-dessous
docker compose up -d
```

Cela démarre MySQL et le plan de contrôle sur `http://localhost:3180`. Pour lancer aussi
un agent distant dédié :

```bash
docker compose --profile with-agent up -d
```

!!! info "Ce que la composition tient à part"
    - **Les secrets arrivent en fichiers.** `MYSQL_PASSWORD`, `MYSQL_ROOT_PASSWORD`,
      `ENCRYPTION_KEY`, `VECTISPIRE_BOOTSTRAP_PASSWORD`, `VECTISPIRE_SIGNING_KEY` et
      `VECTISPIRE_OIDC_CLIENT_SECRET` se lisent toujours dans `.env`, mais Compose les remet aux
      conteneurs en fichiers sous `/run/secrets/`, pas en environnement : l'environnement d'un
      conteneur est ce que `docker inspect` rend à quiconque parle au démon. Les deux derniers sont
      facultatifs et restent déclarés dans `.env` quand ils ne servent pas — vides, et aucun fichier
      n'est monté ; un `.env` qui ne les déclare pas arrête `docker compose up` avec un message qui
      nomme la variable. **À la mise à jour :** ajoutez les deux lignes, et sortez le secret du
      client OIDC de `.env.oidc`, dont les valeurs arrivent toujours dans l'environnement.
    - **La base ne répond qu'au plan de contrôle.** Elle vit sur un réseau interne avec le seul
      plan de contrôle et ne publie aucun port — un port lié à `127.0.0.1` reste joignable depuis
      tous les autres conteneurs de l'hôte. Pour une session SQL :
      `docker compose exec db mysql -u vectispire -p vectispire`.
    - **L'agent atteint l'API et son propre proxy du démon, rien d'autre** — ni la base, ni le
      proxy du plan de contrôle.
    - **Aucun réglage ne peut viser le proxy du démon ni la base.** Une URL d'Ollama, de webhook,
      de SIEM ou de tracker qui nomme l'un d'eux est refusée, quelle que soit la politique de
      destination.

!!! warning "Les analyses vivent dans un répertoire de l'hôte, au même chemin dans le conteneur"
    Chaque analyseur est un conteneur que lance le **démon**, et le démon résout les répertoires
    qu'il y monte **sur son propre hôte** — pas dans le conteneur du plan de contrôle. L'espace de
    travail d'une analyse (le clone, le SBOM, le rapport de secrets le temps qu'elle tourne) et la
    base de vulnérabilités sont donc créés dans `VECTISPIRE_WORK_DIR` — `/var/lib/vectispire/work`
    par défaut — que la composition monte dans le plan de contrôle **au même chemin absolu** et
    remet à l'utilisateur de l'image (1000:1000, mode 0700) par le service ponctuel `work-dir` avant
    que le plan de contrôle démarre. Le profil `with-agent` fait de même pour l'agent avec
    `VECTISPIRE_AGENT_WORK_DIR` (`/var/lib/vectispire/agent-work`).

    - Le disque qui le porte contient la base du rapprocheur, quelque 3 Go, et le clone de chaque
      analyse en cours.
    - Changez le chemin dans `.env` si vous le souhaitez, jamais à un seul des deux endroits : le
      montage est `chemin:chemin` à dessein.
    - **Hors de cette composition** — votre propre fichier Compose, Kubernetes, `docker run` —
      montez un répertoire de l'hôte au même chemin et faites-y pointer le répertoire temporaire de
      la JVM (`JDK_JAVA_OPTIONS=-Djava.io.tmpdir=<chemin>`). Laissé au `/tmp` du conteneur, chaque
      analyseur reçoit un répertoire vide et chaque analyse échoue.
    - **Le même répertoire porte le home du processus**, `home/` en dessous (`-Duser.home`). C'est
      là que les clés d'hôte des forges sont inscrites, `home/.ssh/known_hosts`, et conservées d'un
      redémarrage à l'autre ; l'agent a le sien sous `VECTISPIRE_AGENT_WORK_DIR`. Pour les épingler
      à l'avance, voir [En SSH : la clé d'hôte de la forge](../guide/repositories.md#ssh-host-keys).
      Les images tournent en 1000 sans compte de ce numéro et portent `HOME=/home/vectispire`, si
      bien qu'un simple `docker run` a lui aussi un home inscriptible — mais dans la couche propre
      du conteneur, perdue avec lui : un hôte qui y est inscrit est rencontré à nouveau comme
      nouveau après une recréation, et sous `--read-only` le home ne peut pas être écrit du tout.
      Hors de cette composition, ajoutez aussi `-Duser.home=<chemin>/home` à `JDK_JAVA_OPTIONS`,
      ou montez un volume sur `/home/vectispire` ; l'option l'emporte sur le `HOME` de l'image.
    - **Votre propre `~/.ssh` n'est pas monté**, et `VECTISPIRE_HOST_SSH` vaut `false` ici :
      attachez une clé de déploiement à chaque dépôt privé. La composition le montait en lecture
      seule, là où le processus ne le lisait jamais — et l'eût-il lu, il aurait remis toutes vos
      clés au processus qui détient `ENCRYPTION_KEY`.
    - Sous Docker Desktop, le chemin est dans sa machine virtuelle, pas sur votre Mac ou votre PC,
      et c'est ce qu'il faut : les deux côtés du montage s'y trouvent.

La composition tire deux images publiées : rien ici ne demande de JDK ni de cache Gradle.

```
ghcr.io/asmolabs/vectispire:0.10.0
ghcr.io/asmolabs/vectispire-agent:0.10.0
```

Elles sont publiques — ni identifiant, ni jeton. Pour en tirer une seule,
`docker pull ghcr.io/asmolabs/vectispire:0.10.0` ; et lisez
[Vérifier une release](#verifier-une-release) avant de l'exécuter.

## Avant le premier démarrage

La plupart des réglages vivent dans la base de données et s'éditent depuis **Réglages** une
fois l'application lancée. Quatre choses doivent être justes *avant* le premier démarrage,
parce qu'elles sont nécessaires pour atteindre cet écran.

### La base de données

```bash
VECTISPIRE_DB_URL=jdbc:mysql://localhost:3306/vectispire
VECTISPIRE_DB_USER=vectispire
VECTISPIRE_DB_PASSWORD=…
```

Cette URL est aussi la valeur par défaut. Pour PostgreSQL, pointez la même variable dessus —
`jdbc:postgresql://localhost:5432/vectispire` — et ne changez rien d'autre. Un réglage du serveur MySQL compte si vous utilisez des [plugins de rapport](../administration/report-plugins.fr.md)
sur de grands projets : au `max_allowed_packet` par défaut (64 Mio), l'export d'un rapport est gardé jusqu'à
environ 32 Mio, et `--max-allowed-packet=160M` rétablit toute la borne de 64 Mio.

Le schéma appartient aux **migrations Flyway**, appliquées au démarrage. Il n'y a pas de
commande de migration séparée à lancer, et `ddl-auto` est à `validate` délibérément : un schéma
synthétisé depuis les entités n'est pas celui que la production reçoit, donc tester contre lui
laisserait passer une migration fautive.

### La clé de chiffrement

Vectispire chiffre les secrets qu'il détient — les clés de déploiement avant tout.
**L'enregistrement d'un secret est refusé tant qu'aucune clé n'est posée.**

```bash
ENCRYPTION_KEY_FILE=/run/secrets/vectispire-encryption-key
```

Préférez `ENCRYPTION_KEY_FILE` à `ENCRYPTION_KEY` en production : un fichier est ce qu'un
secret Docker ou Kubernetes monte, et il garde la valeur hors de `/proc/<pid>/environ`, de
`docker inspect` et des journaux de votre orchestrateur. Poser les deux est refusé. Un chemin
qui ne résout pas arrête l'application plutôt que de la démarrer sans clé.

Voir [Rotation et purge](../administration/maintenance.md) pour la changer plus tard.

### Le premier compte {#the-first-account}

Il n'y a pas de page d'inscription. Le premier compte vient de variables d'amorçage, et le
SUPERUSER est créé quand la table des utilisateurs est vide :

```bash
VECTISPIRE_BOOTSTRAP_USERNAME=admin
VECTISPIRE_BOOTSTRAP_PASSWORD=<au moins 12 caractères>
```

Dès qu'un compte existe, les deux variables sont ignorées. Changez ce mot de passe à la
première connexion.

## Où l'exécuter

**Vectispire est conçu pour un réseau interne, pas pour l'Internet public.** C'est une console
d'exploitation destinée à une équipe qui a déjà accès au code qu'elle analyse, et sa conception
suppose que quiconque peut atteindre la page de connexion est quelqu'un à qui vous auriez donné
un compte de toute façon.

Cette hypothèse est portante, donc autant l'énoncer clairement plutôt que de la laisser déduire
des valeurs par défaut :

- Le plan de contrôle publie le port `3180` sur **toutes les interfaces** de son hôte. C'est
  délibéré — il faut bien atteindre l'interface — mais cela signifie qu'un hôte doté d'une
  adresse publique sert Vectispire à Internet dès qu'il démarre. La base de données, elle, ne
  publie aucun port — pas même en loopback, que les autres conteneurs de l'hôte joindraient encore ;
  la différence est volontaire et visible dans `docker-compose.yml`.
- Un utilisateur connecté capable d'enregistrer un dépôt peut faire cloner au plan de contrôle
  une URL qu'il a choisie. C'est le produit qui fonctionne comme prévu, et c'est aussi pourquoi
  *qui peut se connecter* est la frontière qui compte le plus.

Si l'hôte est joignable depuis l'extérieur de votre réseau, mettez-le derrière quelque chose —
un VPN, un proxy qui authentifie, ou une règle de pare-feu — avant toute autre chose. Si vous
terminez TLS devant lui, nommez le proxy dans `VECTISPIRE_TRUSTED_PROXIES` (`vectispire.security.trusted-proxies`) ; laissée
vide, la limitation de débit compte l'adresse du proxy plutôt que celle de l'appelant, et cesse
de protéger qui que ce soit.

### Deux réglages qui changent avec la taille de l'installation

| Réglage | Défaut | Le changer quand |
|---|---|---|
| `VECTISPIRE_HOST_SSH` | `true` | **Plus d'une équipe partage l'installation.** Avec le repli actif, un dépôt sans clé propre est cloné avec l'identité `~/.ssh` de l'hôte — donc ajouter une URL suffit à faire cloner Vectispire sous cette identité. Sur une installation mono-équipe, la clé de l'hôte atteint déjà toutes les cibles et le repli ne coûte rien ; sur une installation partagée, mettez-le à `false` et attachez une clé de déploiement par dépôt. Le `docker-compose.yml` livré le met à `false` et ne monte aucun `~/.ssh` : dans son conteneur, il n'y a pas de clé d'hôte sur laquelle se replier. |
| Secret du webhook entrant (`ticket_webhook_secret`) | vide | **Vous branchez un webhook de tracker.** Celui-ci n'est pas une variable d'environnement : c'est un réglage en base, posé dans **Paramètres → Tickets → Secret du webhook entrant** et stocké chiffré. Tant qu'il est vide, la route de webhook refuse chaque appel par un `403` qui dit que le webhook n'est pas configuré, ce que le tracker affiche dans son journal de livraison — la route ne peut pas porter de session, le secret est donc toute son authentification. Posez la même valeur dans le tracker. Une livraison n'est traitée qu'une fois sur trente jours, et la décision qu'elle porte est mise en file pour approbation au lieu d'être appliquée ; voir [Tickets](../integrations/ticketing.md#inbound-webhook). |

Les deux sont consignés avec leur raisonnement dans le modèle de menaces du projet.

## Kubernetes {#kubernetes}

Une chart Helm est livrée dans [`deploy/helm/vectispire/`](https://github.com/asmolabs/vectispire/tree/main/deploy/helm/vectispire).
Elle suit la [décision 0038](https://github.com/asmolabs/vectispire/blob/main/docs/architecture/fr/decisions/0038-deploying-on-kubernetes.md).
Elle déploie :

- le plan de contrôle, qui sert aussi l'interface ;
- son Ingress ;
- le volume du miroir d'audit.

Elle ne déploie **ni** la base **ni** les Secrets, qui sont les vôtres. Elle ne lance elle-même aucun
conteneur : **chaque scan tourne sur un agent**. Les agents tournent sur un hôte Docker hors du
cluster (recommandé), ou dans le cluster, en pods, sur option.

!!! warning "Les plugins de rapport ne sont pas encore disponibles sur Kubernetes"
    Un [plugin de rapport](../administration/report-plugins.fr.md) tourne sur le point d'accès Docker
    du plan de contrôle lui-même, et un pod n'en a pas. Les demandes répondent
    `409 report-executor-unavailable` jusqu'à ce qu'une version ultérieure sache joindre un démon
    distant. Les rapports et exports intégrés ne sont pas concernés : l'application les produit
    elle-même.

### Le serveur MySQL

Installé et sauvegardé à part. La chart pointe vers lui :

- **Un seul hôte dans l'URL.** `jdbc:mysql://mysql.example.org:3306/vectispire`. Une URL qui liste
  plusieurs hôtes, ou `mysql+srv`, est refusée au démarrage : Vectispire doit connaître l'adresse de
  la base pour empêcher les webhooks de l'atteindre.
- **TLS.** Ajoutez `sslMode=VERIFY_IDENTITY` à l'URL. Si le certificat du serveur vient d'une
  autorité privée, mettez cette autorité dans un truststore PKCS12, rangé dans un Secret nommé par
  `database.trustStore`. Ajoutez ensuite
  `trustCertificateKeyStoreUrl=file:/etc/vectispire/mysql/truststore.p12&trustCertificateKeyStoreType=PKCS12`
  à l'URL.
- **`max_allowed_packet` d'au moins `160M`.** Les exports de rapport voyagent en hexadécimal, au double
  de leur taille.
- **UTC** : `default_time_zone = '+00:00'`. Certaines colonnes ont `CURRENT_TIMESTAMP` pour défaut, que
  le serveur évalue dans le fuseau de la session. Ne fixez pas `TZ` sur le pod.
- **Sauvegardez avant chaque mise à jour.** Les migrations tournent au démarrage et n'ont pas de retour
  arrière. Revenir en arrière, c'est restaurer la sauvegarde et l'empreinte de l'image précédente.

### Installer

```bash
kubectl create namespace vectispire
kubectl -n vectispire create secret generic vectispire-database \
  --from-literal=password='<le mot de passe de la base>'   # gitleaks:allow
kubectl -n vectispire create secret generic vectispire-keys \
  --from-literal=encryption-key="$(openssl rand -base64 32)" \
  --from-literal=bootstrap-password="$(openssl rand -base64 24)"   # gitleaks:allow
kubectl -n vectispire create secret tls vectispire-tls --cert=tls.crt --key=tls.key

cp deploy/helm/vectispire/values.example.yaml mes-valeurs.yaml   # à adapter
helm install vectispire deploy/helm/vectispire -n vectispire -f mes-valeurs.yaml
```

**Dans un namespace qui vous est attribué.** Quand vous ne pouvez écrire que dans un namespace, sautez
`kubectl create namespace` et installez-y avec `-n <votre namespace>` : la chart ne crée rien à
l'échelle du cluster et, sans agents, tout ce qu'elle produit y atterrit. Des agents dans le cluster
demandent deux valeurs de plus, voir plus bas.

**Sauvegardez la clé de chiffrement** hors du cluster. Elle déchiffre chaque clé de déploiement et
chaque jeton que Vectispire détient ; un cluster reconstruit sans elle détient des secrets que
personne ne peut lire.

Fixez aussi une **clé de signature** (`secrets.signingKey`, PEM PKCS#8 P-256) : en 0.10.0, une
installation qui n'en a pas répond 500 à son premier dossier de preuves (corrigé dans la version
suivante). Gardez-la : la remplacer rend invérifiable chaque document déjà signé.

La chart refuse de se rendre sans ses valeurs obligatoires, et dit laquelle manque. La liste complète
est dans le [README](https://github.com/asmolabs/vectispire/blob/main/deploy/helm/vectispire/README.md)
de la chart.

**Forme du déploiement :**

- un réplica ;
- `strategy: Recreate`, pour qu'un ancien pod ne serve jamais un schéma migré ;
- l'image épinglée par empreinte ;
- le pod : uid 1000, système de fichiers racine en lecture seule, toutes capacités retirées, aucun
  jeton de compte de service ;
- des sondes sur `/actuator/health/liveness` et `/actuator/health/readiness` ; la disponibilité inclut
  la base.

### L'Ingress

Les annotations par défaut sont celles d'ingress-nginx. Avec un autre contrôleur, réglez les trois
mêmes choses dans ses propres termes :

| Réglage | Pourquoi |
|---|---|
| délai de lecture ≥ 60 s | le long polling d'un agent tient sa requête 30 s |
| taille de corps ≥ 256 Mo | le résultat d'un agent porte le SBOM |
| TLS | l'interface connecte des personnes |

Réglez `trustedProxies` sur la plage d'adresses du contrôleur d'Ingress. Laissé vide, chaque entrée
d'audit et chaque limite de débit nomme le contrôleur au lieu de l'appelant. Le TLS terminé à
l'Ingress se lirait aussi comme du HTTP en clair côté application.

**Et activez `networkPolicy`, que la chart exige alors.** Un pair de cette plage est cru sur l'adresse
du client. Les pods du contrôleur n'ont pas d'adresse fixe, la plage est donc souvent celle des pods :
sans politique qui réserve le port 3180 au contrôleur, n'importe quel pod pourrait l'appeler en direct
et annoncer n'importe quelle adresse — un nouveau compteur de débit à chaque requête, une entrée d'audit
au nom de quelqu'un d'autre. La politique ne tient qu'avec un CNI qui applique les NetworkPolicy.
`trustedProxiesWithoutNetworkPolicy` rend la chart malgré tout, pour une plage qui ne contient que le
contrôleur.

**Derrière un répartiteur de charge, gardez l'adresse du client jusqu'au contrôleur.** `trustedProxies`
fait croire à l'application ce que le contrôleur écrit dans `X-Forwarded-For`, c'est-à-dire seulement ce
que le contrôleur a vu. Avec son Service en `externalTrafficPolicy: Cluster`, la valeur par défaut, un
nœud traduit la source à l'entrée et le contrôleur voit l'adresse d'un nœud : tous les clients partagent
alors le compteur de débit de ce nœud, et chaque entrée d'audit nomme un nœud. Posez
`externalTrafficPolicy: Local` sur le Service du contrôleur, ou le protocole PROXY entre le répartiteur et
le contrôleur.

**Deux réplicas** sont possibles, mais pas par défaut. Ils demandent :

- l'affinité par cookie (`ingress.stickySessions`) : l'authentification unique garde son état dans la
  session du pod qui a envoyé la personne vers le fournisseur ;
- un volume ReadWriteMany pour le miroir d'audit (`auditMirror.accessMode`) : chaque pod y écrit son
  propre fichier.

### Des agents sur un hôte Docker (recommandé)

Une VM Linux avec Docker, hors du cluster, qui joint l'Ingress en HTTPS. Créez l'agent sur l'écran
**Agents**, puis lancez-le comme le fait le profil `with-agent` de la composition :

- son propre proxy de socket ;
- son répertoire de travail monté **au même chemin** des deux côtés — le démon résout le bind d'un
  scanner sur son propre hôte.

```yaml
# docker-compose.yml sur l'hôte de l'agent
services:
  agent:
    image: ghcr.io/asmolabs/vectispire-agent:0.10.0@sha256:121ec47d0db949946b55ec034b72fdaff909470c92353efda434bbbbb428d72e
    environment:
      VECTISPIRE_URL: https://vectispire.example.org
      DOCKER_HOST: tcp://agent-docker-proxy:2375
      # La clé en fichier, lue par l'arbre de configuration, pas en variable.
      SPRING_CONFIG_IMPORT: optional:configtree:/run/secrets/
      JDK_JAVA_OPTIONS: >-
        -Djava.io.tmpdir=/var/lib/vectispire/agent-work
        -Duser.home=/var/lib/vectispire/agent-work/home
    secrets:
      - source: agent_token
        target: VECTISPIRE_AGENT_TOKEN
    volumes:
      - /var/lib/vectispire/agent-work:/var/lib/vectispire/agent-work
    depends_on: [agent-docker-proxy]
    restart: unless-stopped
    networks: [outside, docker]
  agent-docker-proxy:
    image: tecnativa/docker-socket-proxy:0.3.0@sha256:9e4b9e7517a6b660f2cc903a19b257b1852d5b3344794e3ea334ff00ae677ac2
    # Ce qu'appelle ContainerRunner, et rien d'autre ; toute autre section garde sa valeur par
    # défaut, 0. docker-compose.yml les liste toutes, chacune avec sa raison.
    environment: {PING: 1, VERSION: 1, INFO: 1, CONTAINERS: 1, IMAGES: 1, POST: 1, EXEC: 0}
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    restart: unless-stopped
    networks: [docker]
secrets:
  agent_token:
    file: ./agent-token   # la clé affichée une fois sur l'écran Agents, mode 0600
networks:
  outside: {}
  docker: {internal: true}
```

Avant le premier démarrage, donnez le répertoire de travail à l'utilisateur de l'agent :

```bash
sudo install -d -m 0700 -o 1000 -g 1000 /var/lib/vectispire/agent-work
```

**Confiance.** Si le certificat de l'Ingress vient d'une autorité privée, donnez un truststore à la JVM
de l'agent par `JDK_JAVA_OPTIONS` :

```
-Djavax.net.ssl.trustStore=… -Djavax.net.ssl.trustStoreType=PKCS12
```

Le truststore remplace celui de la JVM : incluez-y chaque autorité à laquelle l'agent doit se fier.

Voir [Agents](../administration/agents.fr.md) pour :

- les modes d'identifiants ;
- l'épinglage d'une clé de signature ;
- la concurrence.

### Des agents dans le cluster (sur option)

`agents.enabled: true` déploie un pod d'agent par release. Le pod a deux conteneurs :

- l'agent, en lecture seule, en uid 1000 ;
- un démon Docker à lui (`docker:dind`), sur un socket Unix partagé par un `emptyDir`. Il n'écoute
  jamais en TCP : le point d'entrée de l'image ouvrirait sinon le port 2375 à tout le cluster, sans
  authentification.

Le répertoire de travail est un second `emptyDir`, monté au même chemin dans les deux conteneurs.

**Le démon tourne dans un conteneur privilégié, qui est root sur son nœud.** Un scanner qui s'échappe
de son propre conteneur atteint ce démon, et par lui le nœud. Donnez à ces pods :

- **leur propre namespace** : la chart crée `vectispire-agents` au niveau `privileged` de Pod
  Security Admission. Dans un seul namespace qui vous est attribué, posez `agents.namespace: ""` et
  `agents.createNamespace: false` : les agents vont à côté du control plane, et le pod n'est admis que
  si le propriétaire de ce namespace l'a mis au niveau `privileged` — pour tous les pods qu'il contient.
  `kubectl get namespace <votre namespace> --show-labels` vous le dit ; `restricted` ou `baseline`
  signifie un hôte Docker ;
- **leurs propres nœuds** : `agents.nodeSelector` (ou une affinité de nœud obligatoire), et
  `agents.tolerations` accordé à une taint qu'eux seuls tolèrent. La chart refuse de se rendre sans les
  deux (`agents.acknowledgeSharedNodes` passe outre). Quoi que vous posiez, elle tient le control plane à
  l'écart du nœud de **tout** agent — de n'importe quelle release, dans n'importe quel namespace — par une
  anti-affinité obligatoire : le control plane détient `ENCRYPTION_KEY`. Sur un seul nœud, il reste
  Pending plutôt que de le partager ;
- **la NetworkPolicy** : active par défaut. Elle refuse toute entrée. Listez dans
  `agents.networkPolicy.excludeCidrs` ce qu'un scanner échappé ne doit pas atteindre : les plages de
  pods, de services **et de nœuds** du cluster (les kubelets, et l'adresse réelle du serveur d'API), et
  le sous-réseau de la base s'il est en dehors, comme l'est d'ordinaire un MySQL managé. La sortie
  n'atteint alors que le monde extérieur et l'Ingress. La chart refuse une liste vide
  (`agents.networkPolicy.acknowledgeClusterReachable` passe outre), et exclut `169.254.0.0/16` — le
  point de métadonnées du cloud — ainsi que les adresses de métadonnées hors de cette plage
  (`100.100.100.200`, `192.0.0.192`, `168.63.129.16`), quoi qu'elle contienne ;
- **une clé de signature épinglée** (`agents.signingKey.secretName`), que la chart exige : sans elle le
  control plane accepte les résultats de l'agent sans attestation.

Là où le cluster interdit les pods privilégiés, utilisez un hôte Docker.

La **variante rootless** (`agents.dind.variant: rootless`, `docker:dind-rootless`) **ne scanne pas avec
l'agent de cette version** :

- sous l'espace de noms utilisateur du démon rootless, l'espace de travail que l'agent possède en
  uid 1000 apparaît au scanner comme appartenant à root ;
- le scanner, lancé lui aussi en uid 1000, ne peut pas le lire, et chaque scanner finit absent ;
- sur la plupart des clusters, elle demande en outre un conteneur privilégié malgré tout, ou seccomp
  et AppArmor non confinés.

La chart ne la rend qu'avec `agents.dind.rootless.acknowledgeUnreadableWorkspaces: true`.

Chaque redémarrage du pod télécharge de nouveau les images des scanners et la base de
vulnérabilités — environ 3 Go. `agents.dind.imageCache` garde les images sur un volume.

## Exécuter depuis les sources

```bash
git clone https://github.com/asmolabs/vectispire.git
cd vectispire
npm ci

cd vectispire-java && ./gradlew :vectispire-core:bootRun --args='--server.port=3180'
npm --workspace @vectispire/frontend start    # interface sur :4280, /api relayé vers :3180
```

`npm` ne couvre que l'interface. Le plan de contrôle est une construction Gradle dans
`vectispire-java/` et ne partage rien avec elle que le contrat HTTP.

## Vérifier une release

Chaque release porte le jar, son SBOM, le [script de barrière CI](../integrations/ci-gate.md) et —
à partir de la version qui suit la 0.10.0 — la CLI `vectispire-cli.sh`, chacun avec un paquet Sigstore
vérifié comme le jar ci-dessous. Vérifiez avant d'exécuter quoi que ce soit — un outil de sécurité que vous avez pris sur
parole est une contradiction.

```bash
cosign verify-blob \
  --bundle vectispire-0.10.0.jar.cosign.bundle \
  --certificate-identity "https://github.com/asmolabs/vectispire/.github/workflows/release.yml@refs/tags/v0.10.0" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  vectispire-0.10.0.jar
```

Chaque option épingle quelque chose, et en retirer une seule rend l'essentiel de ce pour quoi
la signature existait. `--certificate-identity` nomme le **fichier de workflow et le tag**, pas
le dépôt : ne faire correspondre que le dépôt accepterait une signature émise par n'importe
quel workflow que n'importe qui peut y ajouter, y compris un workflow ajouté dans une demande
de fusion. `--certificate-oidc-issuer` dit que l'identité vient du service de jetons de
GitHub — sans lui, une chaîne qui *ressemble* simplement à l'identité ci-dessus suffit.
Remplacez le tag aux deux endroits pour une autre version ; l'identité est par tag, par
conception.

### Vérifier une image

Les images sont signées de la même façon, **par empreinte plutôt que par tag** — un tag peut être
déplacé vers une autre image, pas une empreinte. Vérifiez donc l'empreinte, et déployez cette même
empreinte : vérifier le tag puis le tirer de nouveau vérifie une image que vous ne faites peut-être
pas tourner. Résolvez le tag une fois, avec la commande qu'utilise le workflow de release lui-même :

```bash
DIGEST="$(docker buildx imagetools inspect ghcr.io/asmolabs/vectispire:0.10.0 --format '{{.Manifest.Digest}}')"
echo "$DIGEST"   # sha256:…

cosign verify \
  --certificate-identity "https://github.com/asmolabs/vectispire/.github/workflows/release.yml@refs/tags/v0.10.0" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "ghcr.io/asmolabs/vectispire@${DIGEST}"
```

Désignez ensuite l'image par `ghcr.io/asmolabs/vectispire@sha256:<empreinte>` dans votre fichier
Compose ou votre chart plutôt que par son tag.

Chaque image porte aussi son SBOM en attestation plutôt qu'en fichier posé à côté, parce qu'un
fichier posé à côté d'une image est un fichier que n'importe qui peut remplacer :

```bash
cosign verify-attestation --type cyclonedx \
  --certificate-identity "https://github.com/asmolabs/vectispire/.github/workflows/release.yml@refs/tags/v0.10.0" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "ghcr.io/asmolabs/vectispire@${DIGEST}"
```

Il n'y a pas de clé de signature. Sigstore *keyless* signe avec l'identité OIDC du workflow
lui-même, donc il n'y a rien sous la garde de quiconque à voler ou à faire tourner.

Lancez la même commande sur les noms de fichiers du SBOM. Cela vaut la peine : un SBOM est ce
que quelqu'un donne à manger à son propre scanner, et un SBOM non signé est une liste de
dépendances que n'importe qui peut réécrire avant que vous ne la lisiez.

### Vérifier la provenance de construction

Une signature dit *quel workflow* a produit un fichier. Chaque release postérieure à v0.9.0 porte
aussi une attestation de [provenance de construction SLSA](https://slsa.dev/spec/v1.0/provenance),
pour le jar et pour chaque image, qui dit *comment* : le dépôt, le **commit** vers lequel
pointait le tag au moment de la release, le workflow et l'exécuteur. Un tag peut être déplacé
après coup ; le commit consigné dans la provenance ne le peut pas, et c'est lui qu'il faut
extraire pour lire ou reconstruire le code qui a été livré.

La CLI de GitHub la vérifie, sans fichier à télécharger à côté de l'artefact :

```bash
gh attestation verify vectispire-<version>.jar \
  --repo asmolabs/vectispire \
  --signer-workflow asmolabs/vectispire/.github/workflows/release.yml \
  --source-ref refs/tags/v<version>

gh attestation verify oci://ghcr.io/asmolabs/vectispire@sha256:<empreinte> \
  --repo asmolabs/vectispire \
  --signer-workflow asmolabs/vectispire/.github/workflows/release.yml \
  --source-ref refs/tags/v<version>
```

L'image est désignée **par empreinte** — celle qu'indiquent les notes de release, ou celle que
renvoie `docker buildx imagetools inspect ghcr.io/asmolabs/vectispire:<version> --format '{{.Manifest.Digest}}'`
— pour la même raison que la signature. L'image de l'agent se vérifie de la même façon sous
`ghcr.io/asmolabs/vectispire-agent`. À partir de la version qui suit la 0.10.0, une troisième image
est publiée, `ghcr.io/asmolabs/vectispire-report-demo` — le [plugin de rapport](../administration/report-plugins.fr.md)
de démonstration, que la composition ne tire pas — et elle se vérifie de la même façon sous son propre nom.

`--repo` seul est la commande que GitHub documente, et elle ne suffit pas : elle accepte une
attestation produite par *n'importe quel* workflow du dépôt, sur n'importe quelle branche.
`--signer-workflow` la restreint au workflow de release et `--source-ref` au tag que vous
vouliez installer — les deux choses que `--certificate-identity` épingle dans les commandes
`cosign` ci-dessus. Ajoutez `--format json` pour lire la déclaration elle-même ; le commit se
trouve sous `buildDefinition.resolvedDependencies`.

La provenance s'ajoute à la signature et ne la remplace pas : v0.9.0 et les releases qui l'ont
précédée ont une signature et pas de provenance, et les commandes `cosign` ci-dessus restent le contrôle
que toutes les releases permettent.

## Suite

[Enregistrer un dépôt et lancer votre premier scan →](first-scan.md)
