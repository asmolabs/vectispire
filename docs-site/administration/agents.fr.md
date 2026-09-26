# Agents

Un scan est exécuté par un **agent**. Il en existe deux sortes, toutes deux étant des lignes de
la même table, listées ensemble sur la page **Agents**.

**L'agent intégré** est le processus web lui-même. Créé automatiquement au démarrage, sans
configuration — ce qui est pourquoi une installation mono-machine fonctionne d'emblée.

**Les agents distants** sont des processus de travail séparés sur d'autres machines, parlant un
protocole court : `hello`, `sealing-key` (pour un agent `delegated`), `jobs`, `rules`, `heartbeat`, `result`.

Deux durées le traversent, sous deux formes différentes, pour qui écrit un client d'après le
contrat publié. `GET /api/v1/agent/jobs?wait=30` prend l'attente du long-poll en **secondes
entières** — 0 par défaut, qui répond aussitôt, et tenue 30 au plus. Le `duration` du résultat
est un **texte ISO-8601** (`"PT12.345S"`), le `format: duration` que déclare le contrat ; un nombre
de secondes venant d'un agent plus ancien est encore accepté. Dans le résultat, `[]` signifie
qu'une étape a tourné sans rien trouver, et `null` ou un champ absent qu'elle n'a pas tourné — d'où
l'importance de la différence : seul le premier résout le stock de cette étape.

Les deux exécutent le même code et renvoient tous deux la sortie brute des scanners pour que le
plan de contrôle la normalise. Un résultat produit sur une autre machine est donc
**indiscernable** d'un résultat local : mêmes lignes, même enrichissement, même politique de
licences, même réconciliation.

## Quand en ajouter un

- Garder le socket Docker hors de l'hôte qui sert l'interface.
- Atteindre un dépôt ou un registre routable seulement depuis un autre segment réseau.
- Ajouter de la capacité.

## En exécuter un

```bash
# Sur la machine de l'agent — la clé vient de /agents, affichée une seule fois
VECTISPIRE_URL=https://vectispire.internal \
VECTISPIRE_AGENT_TOKEN=zsk_... \
java -jar vectispire-agent.jar      # produit par ./gradlew :vectispire-agent:bootJar, JDK 25
```

Ou en conteneur, ce qui est la façon prévue de le déployer :

```bash
docker compose --profile with-agent up -d
```

Un agent **interroge en HTTP**, il n'a donc besoin d'aucun port entrant. Sa clé porte la portée
`agent` et **aucun accès à la base de données** — c'est une propriété de sécurité et non un
détail. Un agent disposant d'une connexion à la base aurait aussi besoin d'`ENCRYPTION_KEY`,
c'est-à-dire de la capacité à déchiffrer toutes les clés de déploiement que Vectispire détient.

Dans la composition fournie, l'agent n'atteint que l'API et un proxy du démon qui lui est propre ;
la base et le proxy du plan de contrôle sont sur des réseaux auxquels il n'est pas rattaché. Cela
l'empêche de *demander* la clé — cela ne fait pas deux hôtes d'un seul : les deux proxys atteignent
le même démon, et l'accès au démon y est root. Le profil sert à évaluer le protocole. Pour
l'isolation, faites tourner l'agent sur une autre machine et réglez `VECTISPIRE_EMBEDDED_WORKER=false`
sur le plan de contrôle.

## Mener plusieurs analyses en parallèle {#running-several-scans-at-once}

**Analyses simultanées** (`max_concurrent`) est le nombre d'analyses qu'un agent mène en parallèle :
**de 1 à 16**, 1 quand rien n'est précisé. Réglez-le en déclarant l'agent, ou plus tard avec l'icône
de curseurs sur sa ligne — ou `PATCH /api/v1/admin/agents/{id}` avec `{"max_concurrent": 4}`. Une
valeur hors de 1–16 est refusée par un 400 plutôt qu'arrondie en silence. La ligne l'affiche sous la
forme *en cours / autorisées*, et un changement est inscrit au journal d'audit.

La limite est appliquée des deux côtés. Le plan de contrôle ne confie une nouvelle analyse à un
agent que tant que celles qu'il détient — prises en charge, pas encore rendues, bail encore vivant —
sont moins nombreuses que la limite, et il les compte dans la base : deux interrogations du même
agent ne peuvent pas la dépasser ensemble. L'agent, lui, cesse d'interroger dès qu'il est plein.

**La limite appartient à la ligne de l'agent, pas à un processus.** Deux processus démarrés avec la
même clé se partagent une seule limite — et, en mode `delegated`, seul celui qui s'est annoncé en
dernier peut ouvrir une clé scellée. Pour davantage de machines, déclarez davantage d'agents.

### Le dimensionner

Chaque analyse lance jusqu'à cinq conteneurs de scanners l'un après l'autre, chacun plafonné à 2 Go
de mémoire et à tous les cœurs de l'hôte Docker sauf un, et le rapprochement des vulnérabilités
télécharge sa base — environ 2 Go — dans l'espace de travail propre à cette analyse. Par analyse
simultanée, comptez environ :

| | par analyse |
|---|---|
| CPU | un cœur |
| Mémoire | 2 Go, en plus de la JVM de l'agent |
| Disque (répertoire temporaire) | 3 Go — le clone, le SBOM et la base de vulnérabilités |

Les analyses au-delà de ce que la machine peut tenir n'attendent pas leur tour : elles se disputent
les mêmes cœurs et expirent ensemble, à 15 minutes par scanner. Restez en deçà de la machine ; plus
de capacité, c'est un autre agent.

### La modifier, et arrêter un agent

**Une limite abaissée s'applique à la prochaine prise en charge.** Aucune nouvelle analyse ne
démarre tant que celles en cours ne sont pas repassées sous la limite, et rien de ce qui tourne n'est
interrompu. L'agent apprend la nouvelle valeur dans la réponse à sa prochaine interrogation —
relevée ou abaissée, sans redémarrage.

**Arrêter un agent attend ses analyses.** Sur `SIGTERM` — `docker stop`, une mise à jour progressive
— il cesse de prendre du travail et attend que les analyses en cours soient rendues. Les abandonner
coûterait plus cher qu'attendre : le protocole n'a pas d'appel pour rendre une analyse, donc une
analyse abandonnée garde son bail jusqu'à ce qu'il expire (20 minutes après son dernier signe de
vie), puis revient dans la file en ayant consommé l'une de ses trois tentatives, et son travail est
perdu. Donnez au conteneur un délai d'arrêt aussi long que votre analyse la plus longue —
`stop_grace_period: 30m` dans compose ; le défaut de Docker est de 10 secondes.

Si le processus est tué avant — ou si la machine tombe —, c'est exactement cette expiration qui se
produit. Jusque-là ses analyses comptent encore dans sa limite, si bien qu'un agent redémarré aussitôt
ne prend que ce qui reste ; une fois expirées, elles ne comptent plus, avant même que la file les
ait remises en attente.

## Modes d'identifiants {#credentials-modes}

| Mode | Ce que le contrôleur envoie | Quand |
|---|---|---|
| `local` (défaut) | rien | la machine de l'agent a son propre accès git — en SSH : un dépôt privé en HTTPS ne peut pas être cloné dans ce mode. Un agent compromis ne livre que ce qui avait été accordé à cette machine. |
| `delegated` | la clé de déploiement ou le jeton HTTPS, par travail | une machine de confiance seulement. |

En mode `delegated`, la clé ou le jeton **ne part jamais que scellé** pour le processus de l'agent
lui-même, et jamais en clair — en HTTPS ou non. Il n'est jamais écrit sur le disque de l'agent — il
est lu en mémoire et remis au transport — et chaque remise est auditée.

### Avant de déléguer des identifiants : épingler la clé de signature {#before-delegating-credentials-pin-the-signing-key}

**Un agent `delegated` ne reçoit rien tant qu'aucune clé de signature des résultats n'est épinglée
pour lui** — voir [Attester les résultats d'un agent](#attesting-an-agents-results) — et que sa
moitié privée n'est pas dans la configuration de l'agent. La raison tient à l'origine de la clé de
scellement. L'agent fabrique une paire X25519 neuve à chaque démarrage et en annonce la moitié
publique ; le plan de contrôle scelle les identifiants pour elle. Cette annonce emprunte le même
chemin réseau que les identifiants, si bien qu'un proxy qui termine TLS sur ce chemin pourrait
autrement la modifier. L'agent **signe donc sa clé de scellement avec sa clé de signature
épinglée**, et le plan de contrôle n'accepte qu'une clé de scellement dont la signature se vérifie
contre la clé qu'un administrateur a épinglée ([décision 0031](https://github.com/asmolabs/vectispire/blob/main/docs/architecture/fr/decisions/0031-a-sealing-key-is-believed-only-on-the-pinned-key.md)).
**Le scellement sort un proxy qui termine TLS de la frontière de confiance, pourvu qu'une clé de
signature soit épinglée.**

Donc, pour chaque agent `delegated` :

1. Épinglez une clé de signature sur sa ligne (l'icône de cadenas sur `/agents`), et posez la
   moitié privée affichée une seule fois dans `VECTISPIRE_AGENT_SIGNING_KEY`, dans la configuration
   de l'agent.
2. Faites tourner un agent de cette version et redémarrez-le. Après son `hello`, il annonce sa clé
   de scellement, signée ; son journal dit `Sealing key verified by the control plane`.
3. La ligne indique alors *Scellé de bout en bout*. Jusque-là elle indique *Aucune clé de scellement
   vérifiée : identifiants retenus*, et chaque prise en charge d'une analyse qui demande une clé ou
   un jeton reçoit un **412** qui nomme l'étape manquante — l'analyse retourne dans la file, rien
   n'est envoyé. Les analyses d'images, qui ne demandent aucun identifiant, tournent en attendant.

**La rotation est automatique.** Chaque démarrage fabrique une paire neuve, datée de sa création ;
le plan de contrôle garde la plus récente signée par la clé épinglée et refuse une plus ancienne
(**409**, audité). Un `hello` sans clé, ou avec une clé que personne n'a signée, ne remplace ni
n'efface jamais la clé acceptée.

**La réinitialiser est un acte d'administrateur.** `DELETE /api/v1/admin/agents/{id}/sealing-key`
oublie la clé — pour un hôte d'agent dont l'horloge a reculé, si bien que toutes ses nouvelles clés
paraissent plus anciennes, ou soupçonné d'avoir laissé fuir la sienne. Épingler, remplacer ou
retirer la clé de signature l'oublie aussi. Les deux sont audités, et l'agent annonce une nouvelle
clé à son prochain démarrage, ou à sa prochaine prise en charge.

Une signature qui ne se vérifie pas est refusée en **403**, écrite au journal d'audit sous
`AGENT_SEALING_KEY_REFUSED` et envoyée au SIEM sous `ZAN-SEC-020` : la clé configurée sur l'agent
n'est pas celle qui est épinglée, ou la clé de scellement n'a pas été fabriquée par l'agent.

**Mise à niveau.** Un agent plus ancien que cette version ne sait pas signer sa clé : un plan de
contrôle à jour ne lui remet aucun identifiant délégué (412, dans le journal de l'agent), tandis que
son `hello`, le mode `local` et les analyses d'images continuent de fonctionner. Un agent de cette
version face à un plan de contrôle plus ancien fonctionne comme avant — son `hello` porte la clé
non signée pour laquelle ce plan de contrôle scelle.

Préférez `local`. Cela borne les dégâts qu'un agent compromis peut faire à l'accès propre de
cette machine, ce qui est toute la raison d'exécuter des scans sur un hôte séparé.

## Attester les résultats d'un agent {#attesting-an-agents-results}

**C'est le contrôle qui mérite d'être activé avant les autres.** Rendre le résultat d'un scan est
l'opération la plus lourde du produit : des artefacts présents et vides signifient « analysé, rien
trouvé », ce qui résout tout le backlog de la cible pour ce type — en silence, et correctement. Qui
peut poster un résultat peut donc faire disparaître les vulnérabilités d'une cible de tous les
écrans, de tous les exports et de tous les verdicts de gate, en ne laissant qu'un scan qui a l'air
d'avoir tourné.

Tant qu'aucune clé n'est épinglée, la seule chose entre cela et un `VECTISPIRE_AGENT_TOKEN` volé
est le jeton lui-même — et un jeton vit dans un fichier compose, une variable d'environnement et un
coffre de secrets de CI, et voyage à chaque poll.

Sur `/agents`, l'icône de cadenas d'une ligne épingle une clé. Le plan de contrôle génère une paire
Ed25519, garde la moitié publique sur la ligne de l'agent et vous montre la moitié privée **une
fois** :

```bash
VECTISPIRE_AGENT_SIGNING_KEY=<la valeur affichée une seule fois>
```

Posez-la dans la configuration de l'agent et redémarrez-le. Tant qu'il ne l'a pas, ses résultats
sont refusés en 403 et le refus est écrit au journal d'audit sous `AGENT_RESULT_REFUSED`.

Préférez générer la paire vous-même si vous tenez à ce que la moitié privée n'ait jamais existé
ici : `PUT /api/v1/admin/agents/{id}/signing-key` accepte une clé publique en base64 à la place du
mot `generate`.

**La clé n'est jamais annoncée par l'agent**, et cette asymétrie avec la clé de scellement est tout
l'intérêt. Une signature vérifiée contre une clé que son signataire a publiée sur le même canal ne
prouve que ce que le jeton porteur prouvait déjà. Celle-ci doit venir de quelqu'un qui n'est pas
l'agent.

La même clé se porte garante de la clé de scellement de l'agent : c'est pourquoi un agent
`delegated` ne reçoit aucun identifiant sans elle — voir [Avant de déléguer des identifiants](#before-delegating-credentials-pin-the-signing-key).

La ligne dit dans quel état est chaque agent — *Results attested* ou *Results unsigned* — parce
qu'un opérateur qui croit son parc attesté n'a aucun autre moyen d'apprendre qu'il ne l'est pas.

## Désactiver l'agent intégré

C'est ainsi qu'on dit « n'exécute rien ici ». Les scans en file attendent alors un agent
distant au lieu d'utiliser discrètement l'instance web.

Cela vaut la peine sur tout déploiement où l'hôte de l'interface ne devrait pas avoir de socket
Docker du tout.

## Épingler une cible à un agent

Posez **Agent requis** sur le dépôt ou l'image. Servez-vous-en pour les cibles routables depuis
un seul segment — pas comme outil de répartition de charge, puisqu'une cible épinglée cesse
d'être analysée quand cet unique agent est indisponible.

## Lire la page

Chaque agent affiche ses analyses en cours face à sa limite — voir
[Mener plusieurs analyses en parallèle](#running-several-scans-at-once) — et la date de sa dernière annonce. Un
agent qui **ne s'est jamais annoncé** n'a pas atteint le plan de contrôle du tout : vérifiez
l'URL, le jeton, et que le HTTPS sortant est autorisé.

![Les agents enregistrés : l'agent intégré sur clés locales, un agent distant scellé et attestant ses résultats, et un troisième délégué en clair, non signé et silencieux depuis 12:41.](../assets/screens/fr/agents.png)
