# 0018 — Le socket Docker n'est jamais monté dans le plan de contrôle

**Date :** 2026-09-08 · **Statut :** accepté · **Décideur :** Laurent Boucher

## Contexte

Le `docker-compose.yml` livré montait `/var/run/docker.sock` dans le plan de contrôle, et
`VECTISPIRE_EMBEDDED_WORKER` vaut `true` par défaut : c'était donc le déploiement de tout le monde.

**L'API du démon Docker n'a pas de notion de privilège partiel.** Qui l'atteint peut créer un
conteneur avec `HostConfig.Binds: ["/:/host"]` et lire ou écrire le système de fichiers de l'hôte en
root. Aucune capability n'est requise, `no-new-privileges` ne s'applique pas, et rien du
confinement que construit `ContainerRunner` — `cap_drop: ALL`, racine en lecture seule, scratch
`noexec`, réseau coupé — n'est pertinent : ce confinement protège l'hôte *du scanner*, pas du
processus qui détient le socket.

**Or le processus qui détient le socket est celui qui détient tout le reste.** Le plan de contrôle
porte `ENCRYPTION_KEY` dans son environnement — la clé qui déchiffre toutes les clés de déploiement
SSH et tous les jetons d'intégration du parc — plus les identifiants de la base. Root sur cet hôte,
c'est le parc entier.

**C'est la concentration que l'architecture avait déjà démontée.**
[0003](0003-long-polling-for-agents.md) existe pour que l'exécution des scans et la clé de
chiffrement ne soient jamais au même endroit, et `vectispire-agent` ne peut pas compiler contre un
driver JDBC — une propriété du graphe de build, pas une règle que quelqu'un fait respecter. Le
fichier compose les remettait ensemble.

[0017](0017-custom-checks-as-container-images.md) refuse les JAR téléversés et en donne la raison
en ces termes : un plugin « obtiendrait ce que le processus a : le pool de connexions, la clé qui
chiffre les clés de déploiement et les jetons de tracker, le socket Docker ». Ce raisonnement est
juste, et il s'applique tel quel au processus lui-même. Cinq images tierces — Syft, Grype, Gitleaks,
Checkov, Semgrep — sont tirées et exécutées par ce démon sur une entrée que personne ne contrôle.

### Pourquoi ne pas simplement refuser d'exécuter des conteneurs ici

Parce que c'est exactement ce qu'est l'agent distant, et que c'est déjà la recommandation. Ce qui
manquait, c'est que le déploiement *par défaut* la contredisait, et qu'une installation mono-hôte —
qui est une façon légitime de faire tourner Vectispire — n'avait aucun moyen terme entre « socket
monté » et « pas de scan ».

## Décision

**Aucun conteneur Vectispire ne monte `/var/run/docker.sock`.** Un service `docker-proxy` le monte,
en lecture seule, et le plan de contrôle atteint le démon à travers lui via `DOCKER_HOST`. Ce proxy
vit sur un réseau `internal: true` partagé avec le plan de contrôle et rien d'autre : il n'est ni
joignable depuis le reste de la composition, ni capable d'appeler à l'extérieur. L'agent, quand le
profil `with-agent` tourne, a son propre proxy sur son propre réseau — voir l'amendement plus bas.

`ContainerRunner` n'a rien demandé : il honorait déjà `DOCKER_HOST` et `VECTISPIRE_DOCKER_HOST`
avant toute autodétection de socket.

Le proxy est épinglé par le digest de son index multi-architecture, comme les images de scanners, et
pour la même raison : un conteneur qui parle au démon n'est pas un endroit pour un tag mutable.

### Ce qui passe, et c'est la liste de ce que Vectispire appelle

`PING`, `VERSION`, `INFO`, `CONTAINERS`, `IMAGES`, `POST`. Tout le reste est refusé, et les refus
qui comptent sont nommés explicitement dans le fichier compose plutôt que laissés au défaut :
`EXEC`, `SECRETS`, `VOLUMES`, `NETWORKS`, `SWARM`, `BUILD`, `COMMIT`, `SYSTEM`.

**Mesuré contre un proxy qui tourne plutôt que lu dans la documentation**, parce que l'un d'eux ne
se comporte pas comme le nom de la variable le laisse croire :

```
GET  /_ping /version /info /containers/json /images/json   → 200
GET  /secrets /volumes /networks /swarm /system/df         → 403
POST /containers/{id}/exec                                 → 201   ← autorisé
POST /exec/{id}/start                                      → 403   ← et inerte
POST /containers/create  {"Binds":["/:/host"]}             → 201
```

`EXEC=0` gouverne les points d'entrée `/exec/*`, pas le `/containers/{id}/exec` qui crée
l'instance — ce chemin-là est couvert par `CONTAINERS`. Une instance d'exec peut donc être **créée**
et ne peut jamais être **démarrée** : la capacité est fermée, mais pas là où le nom de la variable
la place. Bon à savoir avant que quelqu'un ne lise un 201 dans un journal et n'en conclue que la
liste blanche ne s'applique pas.

## Ce que cela ne fait pas, dit plutôt que sous-entendu

**Cela ne rend pas le démon sûr à joindre.** `POST /containers/create` est dans la liste autorisée,
parce que c'est l'appel dont Vectispire vit, et il accepte des `Binds`. Un attaquant qui obtient
l'exécution de code dans le plan de contrôle peut encore demander au proxy de créer un conteneur qui
monte l'hôte. **Le proxy réduit la surface, il ne pose pas de frontière.**

Cette dernière phrase n'est pas une déduction : `POST /containers/create` avec
`Binds: ["/:/host"]` a été envoyé à travers le proxy et a répondu 201.

Ce qu'il achète est réel et vaut la peine : le fichier socket a disparu du système de fichiers du
conteneur, donc une primitive de traversée de chemin ou d'écriture de fichier ne l'atteint plus ;
un `exec` dans le plan de contrôle ou la base qui tournent ne peut pas être démarré ; secrets,
volumes et réseaux sont refusés ; et la liste blanche est un énoncé écrit et relisible de ce que ce
système demande à un démon, ce qu'aucun déploiement n'avait jusqu'ici.

**La frontière, c'est une deuxième machine.** Un parc qui en a besoin fait tourner l'agent distant
avec `VECTISPIRE_EMBEDDED_WORKER=false` sur le plan de contrôle. L'hôte que l'on peut faire exécuter
des conteneurs n'est alors plus l'hôte qui détient `ENCRYPTION_KEY`, et c'est une propriété qu'aucune
configuration de proxy ne donne. La documentation le dit à l'endroit où un opérateur choisit.

## Amendement du 25 septembre 2026 : un proxy par client, et plus rien à inspecter

Une revue de sécurité a trouvé la composition en train de défaire une partie de ce que cette
décision avait mis en place ; chaque point a été vérifié sur une pile en marche avant d'être changé :

- **L'agent partageait le proxy du plan de contrôle, et vivait sur le réseau de la base.** Grâce à
  `CONTAINERS: 1`, `GET /containers/vectispire-control-plane/json` rendait l'environnement du plan de
  contrôle — `ENCRYPTION_KEY`, le mot de passe de la base, celui du premier administrateur — et
  l'agent pouvait ouvrir `db:3306` directement. C'est exactement l'association clé plus base que la
  [décision 0003](0003-long-polling-for-agents.md) interdit à l'agent dès la compilation. L'agent a
  désormais son propre proxy (`agent-docker-proxy`, sur `vectispire-agent-docker`) et n'atteint que
  l'API, sur `vectispire-agent` ; la base vit sur `vectispire-db`, `internal: true`, avec le seul
  plan de contrôle.
- **Les secrets étaient des variables d'environnement**, et l'environnement fait partie de chaque
  inspect. La composition les remet désormais en `secrets:` copiés dans `/run/secrets/` :
  `ENCRYPTION_KEY_FILE` pour la clé, un config tree (`spring.config.import:
  optional:configtree:/run/secrets/`) pour les mots de passe, et les variables `_FILE` de MySQL pour
  les siens. `docker inspect` n'en montre plus aucun.
- **Le port de la base en boucle locale ne l'était pas.** `127.0.0.1:3306:3306` semblait réservé à
  l'hôte, mais Docker accepte le trafic vers un port publié depuis n'importe quel autre réseau de
  l'hôte avant d'appliquer son isolation entre réseaux : un conteneur neuf sur le réseau de l'agent
  ouvrait la base sur son adresse de conteneur. Le port a disparu ; `docker compose exec db mysql` le
  remplace.
- **On pouvait faire écrire le plan de contrôle à son propre proxy.** Les URL d'Ollama, du webhook,
  du SIEM et du tracker peuvent viser des hôtes internes — un serveur Ollama y vit — et le proxy est
  interne lui aussi. Un responsable sécurité qui en réglait une sur
  `http://docker-proxy:2375/containers/create` faisait appeler le démon par le plan de contrôle.
  `OutboundUrlGuard` refuse désormais, sous toutes les politiques, l'extrémité que nomme
  `DOCKER_HOST` et celle de la base, par nom et par adresse résolue, sur leur port.
- **Le profil `with-agent` ne démarrait pas** : l'agent attendait que le plan de contrôle soit sain,
  et l'image publiée, construite par Jib, n'a pas de healthcheck. La composition en déclare un.

Ce que cela ne change *pas*, c'est le paragraphe ci-dessus : les deux proxys atteignent l'unique
démon de l'hôte, et `POST /containers/create` avec un montage de `/` y reste root — là où vivent
aussi les fichiers de la base et les secrets. Sur une seule machine, le profil agent évalue le
protocole, pas l'isolation.

## Conséquences

- `group_add: docker` disparaît de la composition. C'était une valeur propre à l'hôte — un nom de
  groupe ici, un GID numérique là — que chaque opérateur devait découvrir.
- Un conteneur de plus dans la composition par défaut, et une image de plus à tenir à jour.
- Un opérateur qui fait tourner Vectispire hors compose, directement contre un démon, n'est pas
  affecté : rien ici ne l'interdit, et `DOCKER_HOST` est le même bouton.
- L'affirmation de [`04_vue_infrastructure`](../../bflorat/fr/04_vue_infrastructure.md) selon
  laquelle « seul le plan de contrôle interagit avec le démon Docker via le socket de l'hôte » est
  désormais fausse à la lettre et vraie dans l'esprit : elle a été réécrite.
